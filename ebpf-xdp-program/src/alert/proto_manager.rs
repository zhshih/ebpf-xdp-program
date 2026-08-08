use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use ebpf_xdp_program_common::ProtoIndex;

use crate::{
    alert::{
        model::{Alert, AlertEvent, AlertKind, AlertSignal},
        state::{AlertLifecycle, AlertState},
        view::AlertMetricsSnapshot,
    },
    anomaly::AnomalyLevel,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AlertKey {
    proto: ProtoIndex,
    kind: AlertKind,
}

/// Configuration for a single alert rule applied by the [`AlertLifecycleManager`].
///
/// Each rule governs one `AlertKind` and specifies the conditions under which
/// signals escalate through the FSM and fire alerts.
pub struct AlertRule {
    pub kind: AlertKind,
    /// Minimum anomaly severity required for a signal to be eligible.
    pub min_level: AnomalyLevel,
    /// Minimum detector confidence [0, 1] required for a signal to be eligible.
    pub min_confidence: f64,
    /// Duration after firing during which re-firing is suppressed.
    pub cooldown: Duration,
    /// Number of consecutive eligible ticks required to fire.
    pub consecutive_threshold: u32,
    /// Number of consecutive normal ticks required to resolve.
    pub resolve_consecutive_threshold: u32,
    /// If true, the protocol's EWMA baseline is frozen while the alert is hot.
    pub freezes_baseline: bool,
}

/// Drives per-`(proto, kind)` alert FSMs for all configured rules.
pub struct AlertLifecycleManager {
    rules: Vec<AlertRule>,
    states: HashMap<AlertKey, AlertState>,
}

impl AlertLifecycleManager {
    /// Creates a manager with the given rules. An empty rule set disables all alerting.
    pub fn new(rules: Vec<AlertRule>) -> Self {
        if rules.is_empty() {
            tracing::warn!("AlertLifecycleManager initialized with no rules; alerting disabled");
        }

        Self {
            rules,
            states: HashMap::new(),
        }
    }

    pub fn snapshot(&self) -> Vec<AlertMetricsSnapshot> {
        self.states
            .iter()
            .map(|(key, state)| AlertMetricsSnapshot {
                proto: key.proto,
                kind: key.kind,
                phase_value: state.phase_value(),
                phase_label: state.phase_label(),
                consecutive_count: state.consecutive_count,
            })
            .collect()
    }

    /// Advances every FSM against `signals` and returns this tick's alerts.
    ///
    /// The first vec is this tick's `Fired`/`Resolved` transitions
    /// (`signals` are filtered by rule criteria before advancing). The
    /// second is a re-affirmation [`Alert`] for every `(proto, kind)` slot
    /// that's still `Firing` with an active signal but didn't transition
    /// this tick — `state.advance()` only emits on a transition, not every
    /// tick, and external sinks with their own auto-expiry (e.g.
    /// Alertmanager's `resolve_timeout`) need a periodic re-send of
    /// still-active alerts between transitions.
    pub fn tick(&mut self, signals: &[AlertSignal], now: Instant) -> (Vec<AlertEvent>, Vec<Alert>) {
        let active = self.collect_active(signals);
        self.advance_states(&active, now)
    }

    /// Returns the set of protocols whose baselines should be frozen.
    ///
    /// A protocol is frozen when any of its alert states is "hot" (Pending, Firing,
    /// or within cooldown) for a rule with `freezes_baseline = true`.
    pub fn frozen_protos(&self, now: Instant) -> HashSet<ProtoIndex> {
        self.states
            .iter()
            .filter_map(|(key, state)| {
                self.rules
                    .iter()
                    .find(|r| r.kind == key.kind)
                    .filter(|rule| rule.freezes_baseline && state.is_hot(now, rule.cooldown))
                    .map(|_| key.proto)
            })
            .collect()
    }

    fn collect_active(&self, signals: &[AlertSignal]) -> HashMap<AlertKey, AlertSignal> {
        let mut active = HashMap::new();

        for rule in &self.rules {
            for signal in signals {
                if signal.kind != rule.kind {
                    tracing::info!(
                        "skipping signal for proto {:?} kind {:?} due to rule kind {:?}",
                        signal.proto,
                        signal.kind,
                        rule.kind
                    );
                    continue;
                }
                if signal.level < rule.min_level {
                    tracing::info!(
                        "skipping signal for proto {:?} level {:?} below rule min level {:?}",
                        signal.proto,
                        signal.level,
                        rule.min_level
                    );
                    continue;
                }
                if signal.confidence < rule.min_confidence {
                    tracing::info!(
                        "skipping signal for proto {:?} confidence {} below rule min confidence {}",
                        signal.proto,
                        signal.confidence,
                        rule.min_confidence
                    );
                    continue;
                }

                let key = AlertKey {
                    proto: signal.proto,
                    kind: signal.kind,
                };

                active.insert(key, signal.clone());
            }
        }

        active
    }

    fn advance_states(
        &mut self,
        active: &HashMap<AlertKey, AlertSignal>,
        now: Instant,
    ) -> (Vec<AlertEvent>, Vec<Alert>) {
        let mut events = Vec::new();
        let mut heartbeats = Vec::new();

        for rule in &self.rules {
            let mut keys: HashSet<AlertKey> = self
                .states
                .keys()
                .filter(|k| k.kind == rule.kind)
                .cloned()
                .collect();
            keys.extend(active.keys().filter(|k| k.kind == rule.kind).cloned());

            tracing::debug!(
                rule_kind = ?rule.kind,
                active_signal_count = active.len(),
                tracked_states_count = self.states.len(),
                unique_keys = keys.len(),
                "advancing alert states for rule"
            );

            for key in keys {
                let state = self.states.entry(key).or_insert_with(AlertState::new);

                let signal = active.get(&key);
                let is_active = signal.is_some();

                tracing::trace!(
                    proto = ?key.proto,
                    kind = ?key.kind,
                    state = ?state,
                    signal_active = is_active,
                    "processing alert state for key"
                );

                match state.advance(
                    is_active,
                    now,
                    rule.cooldown,
                    rule.consecutive_threshold,
                    rule.resolve_consecutive_threshold,
                ) {
                    Some(lifecycle @ AlertLifecycle::Fired) => {
                        let s = signal.expect("signal present when alert fired");
                        tracing::info!(
                            proto = ?s.proto,
                            kind = ?s.kind,
                            "firing alert"
                        );
                        events.push(AlertEvent {
                            alert: Alert {
                                proto: s.proto,
                                kind: s.kind,
                                level: s.level,
                                confidence: s.confidence,
                            },
                            lifecycle,
                        });
                    }

                    Some(lifecycle @ AlertLifecycle::Resolved) => {
                        tracing::info!(
                            proto = ?key.proto,
                            kind = ?key.kind,
                            "resolving alert"
                        );
                        events.push(AlertEvent {
                            alert: Alert {
                                proto: key.proto,
                                kind: key.kind,
                                level: rule.min_level,
                                confidence: 0.0,
                            },
                            lifecycle,
                        });
                    }

                    None if state.is_firing() => {
                        if let Some(s) = signal {
                            heartbeats.push(Alert {
                                proto: s.proto,
                                kind: s.kind,
                                level: s.level,
                                confidence: s.confidence,
                            });
                        }
                    }

                    None => {}
                }
            }
        }

        (events, heartbeats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anomaly::AnomalyLevel;

    fn spike_signal(proto: ProtoIndex, level: AnomalyLevel, confidence: f64) -> AlertSignal {
        AlertSignal {
            proto,
            level,
            kind: AlertKind::Spike,
            confidence,
        }
    }

    fn spike_rule(min_level: AnomalyLevel, min_confidence: f64, threshold: u32) -> AlertRule {
        AlertRule {
            kind: AlertKind::Spike,
            min_level,
            min_confidence,
            cooldown: Duration::ZERO,
            consecutive_threshold: threshold,
            resolve_consecutive_threshold: 1,
            freezes_baseline: false,
        }
    }

    fn spike_rule_freezing(threshold: u32) -> AlertRule {
        AlertRule {
            kind: AlertKind::Spike,
            min_level: AnomalyLevel::Suspicious,
            min_confidence: 0.0,
            cooldown: Duration::ZERO,
            consecutive_threshold: threshold,
            resolve_consecutive_threshold: 1,
            freezes_baseline: true,
        }
    }

    #[test]
    fn manager_no_rules_no_events() {
        let mut mgr = AlertLifecycleManager::new(vec![]);
        let (events, _) = mgr.tick(
            &[spike_signal(ProtoIndex::Tcp, AnomalyLevel::Severe, 1.0)],
            Instant::now(),
        );
        assert!(events.is_empty());
    }

    #[test]
    fn manager_signal_below_min_level() {
        let mut mgr =
            AlertLifecycleManager::new(vec![spike_rule(AnomalyLevel::Suspicious, 0.0, 1)]);
        // Normal level signal — below Suspicious threshold
        let (events, _) = mgr.tick(
            &[spike_signal(ProtoIndex::Tcp, AnomalyLevel::Normal, 1.0)],
            Instant::now(),
        );
        assert!(events.is_empty());
    }

    #[test]
    fn manager_signal_below_confidence() {
        let mut mgr =
            AlertLifecycleManager::new(vec![spike_rule(AnomalyLevel::Suspicious, 0.6, 1)]);
        let (events, _) = mgr.tick(
            &[spike_signal(ProtoIndex::Tcp, AnomalyLevel::Suspicious, 0.3)],
            Instant::now(),
        );
        assert!(events.is_empty());
    }

    #[test]
    fn manager_fires_after_consecutive() {
        let mut mgr =
            AlertLifecycleManager::new(vec![spike_rule(AnomalyLevel::Suspicious, 0.0, 3)]);
        let signal = || spike_signal(ProtoIndex::Tcp, AnomalyLevel::Suspicious, 1.0);
        let now = Instant::now();

        let (e1, _) = mgr.tick(&[signal()], now);
        let (e2, _) = mgr.tick(&[signal()], now);
        let (e3, _) = mgr.tick(&[signal()], now);

        assert!(e1.is_empty(), "should not fire on tick 1");
        assert!(e2.is_empty(), "should not fire on tick 2");
        assert_eq!(e3.len(), 1, "should fire on tick 3");
        assert!(matches!(e3[0].lifecycle, AlertLifecycle::Fired));
    }

    #[test]
    fn manager_resolves_after_quiet() {
        let mut mgr =
            AlertLifecycleManager::new(vec![spike_rule(AnomalyLevel::Suspicious, 0.0, 1)]);
        let signal = || spike_signal(ProtoIndex::Tcp, AnomalyLevel::Suspicious, 1.0);
        let now = Instant::now();

        // Fire
        let (fired, _) = mgr.tick(&[signal()], now);
        assert_eq!(fired.len(), 1);
        assert!(matches!(fired[0].lifecycle, AlertLifecycle::Fired));

        // Quiet tick → resolve (resolve_threshold=1)
        let (resolved, _) = mgr.tick(&[], now);
        assert_eq!(resolved.len(), 1);
        assert!(matches!(resolved[0].lifecycle, AlertLifecycle::Resolved));
    }

    #[test]
    fn manager_kind_mismatch_signal_ignored() {
        // Rule is Spike-only; a Drop signal should be filtered out entirely.
        let mut mgr =
            AlertLifecycleManager::new(vec![spike_rule(AnomalyLevel::Suspicious, 0.0, 1)]);
        let drop_signal = AlertSignal {
            proto: ProtoIndex::Tcp,
            level: AnomalyLevel::Suspicious,
            kind: AlertKind::Drop,
            confidence: 1.0,
        };
        let (events, _) = mgr.tick(&[drop_signal], Instant::now());
        assert!(
            events.is_empty(),
            "Drop signal should be ignored by Spike-only rule"
        );
    }

    #[test]
    fn manager_frozen_protos_during_hot() {
        let mut mgr = AlertLifecycleManager::new(vec![spike_rule_freezing(1)]);
        let signal = spike_signal(ProtoIndex::Tcp, AnomalyLevel::Suspicious, 1.0);
        let now = Instant::now();

        mgr.tick(&[signal], now);

        let frozen = mgr.frozen_protos(now);
        assert!(
            frozen.contains(&ProtoIndex::Tcp),
            "TCP should be frozen after firing"
        );
    }

    #[test]
    fn manager_snapshot_reflects_fired_state() {
        let mut mgr =
            AlertLifecycleManager::new(vec![spike_rule(AnomalyLevel::Suspicious, 0.0, 1)]);
        mgr.tick(
            &[spike_signal(ProtoIndex::Tcp, AnomalyLevel::Suspicious, 1.0)],
            Instant::now(),
        );

        let snaps = mgr.snapshot();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].proto, ProtoIndex::Tcp);
        assert_eq!(snaps[0].kind, AlertKind::Spike);
        assert_eq!(snaps[0].phase_value, 2, "Firing should be phase_value 2");
        assert_eq!(snaps[0].phase_label, "firing");
        assert_eq!(snaps[0].consecutive_count, 1);
    }

    #[test]
    fn heartbeats_empty_before_threshold() {
        let mut mgr =
            AlertLifecycleManager::new(vec![spike_rule(AnomalyLevel::Suspicious, 0.0, 3)]);
        let signal = spike_signal(ProtoIndex::Tcp, AnomalyLevel::Suspicious, 1.0);
        let now = Instant::now();

        // Pending, not yet Firing
        let (_, heartbeats) = mgr.tick(std::slice::from_ref(&signal), now);
        assert!(heartbeats.is_empty(), "should not heartbeat while Pending");
    }

    #[test]
    fn heartbeats_returns_alert_on_subsequent_tick_while_firing() {
        let mut mgr =
            AlertLifecycleManager::new(vec![spike_rule(AnomalyLevel::Suspicious, 0.0, 1)]);
        let signal = spike_signal(ProtoIndex::Tcp, AnomalyLevel::Suspicious, 0.9);
        let now = Instant::now();

        let (fired, _) = mgr.tick(std::slice::from_ref(&signal), now);
        assert_eq!(fired.len(), 1);

        // Next tick: still firing, no new transition.
        let (events, heartbeats) = mgr.tick(std::slice::from_ref(&signal), now);
        assert!(events.is_empty());

        assert_eq!(heartbeats.len(), 1);
        assert_eq!(heartbeats[0].proto, ProtoIndex::Tcp);
        assert_eq!(heartbeats[0].kind, AlertKind::Spike);
        assert_eq!(heartbeats[0].level, AnomalyLevel::Suspicious);
        assert_eq!(heartbeats[0].confidence, 0.9);
    }

    #[test]
    fn heartbeats_excludes_key_that_just_transitioned() {
        let mut mgr =
            AlertLifecycleManager::new(vec![spike_rule(AnomalyLevel::Suspicious, 0.0, 1)]);
        let signal = spike_signal(ProtoIndex::Tcp, AnomalyLevel::Suspicious, 1.0);
        let now = Instant::now();

        let (fired, heartbeats) = mgr.tick(std::slice::from_ref(&signal), now);
        assert_eq!(fired.len(), 1);
        assert!(
            heartbeats.is_empty(),
            "should not double-send an alert that fired this same tick"
        );
    }

    #[test]
    fn heartbeats_empty_once_signal_drops() {
        // resolve_consecutive_threshold=2, so one quiet tick keeps it Firing
        // (not yet Resolved) with no active signal to source heartbeat data from.
        let rule = AlertRule {
            kind: AlertKind::Spike,
            min_level: AnomalyLevel::Suspicious,
            min_confidence: 0.0,
            cooldown: Duration::ZERO,
            consecutive_threshold: 1,
            resolve_consecutive_threshold: 2,
            freezes_baseline: false,
        };
        let mut mgr = AlertLifecycleManager::new(vec![rule]);
        let signal = spike_signal(ProtoIndex::Tcp, AnomalyLevel::Suspicious, 1.0);
        let now = Instant::now();

        mgr.tick(&[signal], now); // Fired
        let (events, heartbeats) = mgr.tick(&[], now); // still Firing, resolve threshold not yet met
        assert!(events.is_empty());
        assert!(
            heartbeats.is_empty(),
            "no active signal this tick means no fresh data to heartbeat with"
        );
    }
}
