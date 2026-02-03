use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::{
    alert::{
        model::{Alert, AlertKind, AlertSignal},
        state::{AlertLifecycle, AlertState},
    },
    anomaly::AnomalyLevel,
};
use ebpf_xdp_program_common::ProtoIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AlertKey {
    proto: ProtoIndex,
    kind: AlertKind,
}

pub struct AlertRule {
    pub kind: AlertKind,
    pub min_level: AnomalyLevel,
    pub min_confidence: f64,
    pub cooldown: Duration,
    pub consecutive_threshold: u32,
    pub resolve_consecutive_threshold: u32,
    pub freezes_baseline: bool,
}
pub struct AlertEvent {
    pub alert: Alert,
    pub lifecycle: AlertLifecycle,
}

pub struct AlertManager {
    rules: Vec<AlertRule>,
    states: HashMap<AlertKey, AlertState>,
}

impl AlertManager {
    pub fn new(rules: Vec<AlertRule>) -> Self {
        if rules.is_empty() {
            tracing::warn!("AlertManager initialized with no rules; alerting disabled");
        }

        Self {
            rules,
            states: HashMap::new(),
        }
    }

    pub fn evaluate(&mut self, signals: &[AlertSignal], now: Instant) -> Vec<AlertEvent> {
        let active = self.collect_active(signals);
        self.advance_states(&active, now)
    }

    pub fn is_baseline_frozen(&self, now: Instant) -> bool {
        self.states.iter().any(|(key, state)| {
            self.rules
                .iter()
                .find(|r| r.kind == key.kind)
                .is_some_and(|rule| rule.freezes_baseline && state.is_hot(now, rule.cooldown))
        })
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
    ) -> Vec<AlertEvent> {
        let mut events = Vec::new();

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

                if let Some(lifecycle) = state.advance(
                    is_active,
                    now,
                    rule.cooldown,
                    rule.consecutive_threshold,
                    rule.resolve_consecutive_threshold,
                )
                {
                    match lifecycle {
                        AlertLifecycle::Fired => {
                            let s = signal.unwrap();
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
                                    timestamp: now,
                                },
                                lifecycle,
                            });
                        }

                        AlertLifecycle::Resolved => {
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
                                    timestamp: now,
                                },
                                lifecycle,
                            });
                        }
                    }
                }
            }
        }

        events
    }
}
