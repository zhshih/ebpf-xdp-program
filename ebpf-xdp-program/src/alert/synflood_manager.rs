//! Per-source-IP SYN-flood alerting.
//!
//! Deliberately parallel to, not folded into, [`crate::alert::AlertManager`]:
//! `AlertManager`'s `AlertKey { proto: ProtoIndex, kind: AlertKind }` has
//! nowhere to put an `Ipv4Addr` without either widening `AlertKey` (which
//! ripples into `frozen_protos()`, `AlertMetricsSnapshot`, and every
//! existing Spike/Drop/Emergency test) or collapsing all attacker IPs into
//! one bucket (destroying the "which IP" information this exists to
//! surface). [`SynFloodAlertManager`] reuses [`AlertState`] — the FSM
//! primitive itself — but keeps its own small, separately-bounded map.
//!
//! `SynFloodSignal`/`SynFloodAlert`/`SynFloodAlertEvent` live in
//! `crate::alert::model`; [`SynFloodAlertSlotSnapshot`] lives in
//! `crate::alert::view` (see `crate::alert`'s module doc for why). This file
//! keeps only what's private to `SynFloodAlertManager` itself: its FSM/GC
//! logic.
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use crate::alert::{
    model::{SynFloodAlert, SynFloodAlertEvent, SynFloodSignal},
    state::AlertState,
    view::SynFloodAlertSlotSnapshot,
};

/// Drives per-source-IP SYN-flood alert FSMs.
///
/// Bounded memory: an entry is only ever created for an IP present in the
/// current tick's (already-bounded, top-N) signal list, and `evaluate()`
/// garbage-collects any entry that is neither in this tick's signals nor
/// still "hot" (Pending/Firing/within cooldown) — so live state is bounded
/// by roughly `top_n + (IPs still cooling down)`, both attacker-independent
/// config knobs, independent of how many distinct source IPs an attacker
/// rotates through over time.
pub struct SynFloodAlertManager {
    cooldown: Duration,
    consecutive_threshold: u32,
    resolve_consecutive_threshold: u32,
    states: HashMap<Ipv4Addr, AlertState>,
}

impl SynFloodAlertManager {
    pub fn new(
        cooldown: Duration,
        consecutive_threshold: u32,
        resolve_consecutive_threshold: u32,
    ) -> Self {
        Self {
            cooldown,
            consecutive_threshold,
            resolve_consecutive_threshold,
            states: HashMap::new(),
        }
    }

    /// Filters/advances FSMs against `signals`, then garbage-collects any
    /// entry that's neither in `signals` nor still hot.
    pub fn evaluate(
        &mut self,
        signals: &[SynFloodSignal],
        now: Instant,
    ) -> Vec<SynFloodAlertEvent> {
        let active: HashMap<Ipv4Addr, &SynFloodSignal> =
            signals.iter().map(|s| (s.src_ip, s)).collect();

        let mut keys: HashSet<Ipv4Addr> = self.states.keys().copied().collect();
        keys.extend(active.keys().copied());

        let mut events = Vec::new();
        for ip in keys {
            let state = self.states.entry(ip).or_insert_with(AlertState::new);
            let signal = active.get(&ip);
            if let Some(lifecycle) = state.advance(
                signal.is_some(),
                now,
                self.cooldown,
                self.consecutive_threshold,
                self.resolve_consecutive_threshold,
            ) {
                events.push(SynFloodAlertEvent {
                    alert: SynFloodAlert {
                        src_ip: ip,
                        pps: signal.map_or(0.0, |s| s.pps),
                        confidence: signal.map_or(0.0, |s| s.confidence),
                    },
                    lifecycle,
                });
            }
        }

        let cooldown = self.cooldown;
        self.states
            .retain(|ip, state| active.contains_key(ip) || state.is_hot(now, cooldown));

        events
    }

    /// Returns a re-affirmation [`SynFloodAlert`] for every currently-`Firing`
    /// source IP that has an active signal this tick, excluding any IP
    /// already represented in `just_transitioned` (this tick's `evaluate()`
    /// events). See [`crate::alert::AlertManager::heartbeats`] for the full
    /// rationale (external sinks like Alertmanager need periodic re-sends
    /// between `Fired`/`Resolved` transitions).
    pub fn heartbeats(
        &self,
        signals: &[SynFloodSignal],
        just_transitioned: &HashSet<Ipv4Addr>,
    ) -> Vec<SynFloodAlert> {
        let active: HashMap<Ipv4Addr, &SynFloodSignal> =
            signals.iter().map(|s| (s.src_ip, s)).collect();

        self.states
            .iter()
            .filter_map(|(ip, state)| {
                if !state.is_firing() || just_transitioned.contains(ip) {
                    return None;
                }
                let signal = active.get(ip)?;
                Some(SynFloodAlert {
                    src_ip: *ip,
                    pps: signal.pps,
                    confidence: signal.confidence,
                })
            })
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.states.len()
    }

    pub fn snapshot(&self) -> Vec<SynFloodAlertSlotSnapshot> {
        self.states
            .iter()
            .map(|(ip, s)| SynFloodAlertSlotSnapshot {
                src_ip: *ip,
                phase_label: s.phase_label(),
                consecutive_count: s.consecutive_count,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::AlertLifecycle;

    const NO_COOLDOWN: Duration = Duration::ZERO;

    fn signal(ip: u32, pps: f64) -> SynFloodSignal {
        SynFloodSignal {
            src_ip: Ipv4Addr::from(ip),
            pps,
            confidence: 1.0,
        }
    }

    #[test]
    fn synflood_manager_fires_after_consecutive() {
        let mut mgr = SynFloodAlertManager::new(NO_COOLDOWN, 3, 1);
        let now = Instant::now();

        let e1 = mgr.evaluate(&[signal(1, 200.0)], now);
        let e2 = mgr.evaluate(&[signal(1, 200.0)], now);
        let e3 = mgr.evaluate(&[signal(1, 200.0)], now);

        assert!(e1.is_empty());
        assert!(e2.is_empty());
        assert_eq!(e3.len(), 1);
        assert!(matches!(e3[0].lifecycle, AlertLifecycle::Fired));
        assert_eq!(e3[0].alert.src_ip, Ipv4Addr::from(1));
    }

    #[test]
    fn synflood_manager_resolves_after_quiet() {
        let mut mgr = SynFloodAlertManager::new(NO_COOLDOWN, 1, 1);
        let now = Instant::now();

        let fired = mgr.evaluate(&[signal(1, 200.0)], now);
        assert_eq!(fired.len(), 1);
        assert!(matches!(fired[0].lifecycle, AlertLifecycle::Fired));

        let resolved = mgr.evaluate(&[], now);
        assert_eq!(resolved.len(), 1);
        assert!(matches!(resolved[0].lifecycle, AlertLifecycle::Resolved));
    }

    #[test]
    fn synflood_manager_cooldown_blocks_refire() {
        let long_cooldown = Duration::from_secs(3600);
        let mut mgr = SynFloodAlertManager::new(long_cooldown, 1, 1);
        let now = Instant::now();

        mgr.evaluate(&[signal(1, 200.0)], now); // fires
        mgr.evaluate(&[], now); // resolves, still within cooldown

        let refire = mgr.evaluate(&[signal(1, 200.0)], now);
        assert!(refire.is_empty(), "cooldown should block refire");
    }

    #[test]
    fn synflood_manager_gc_drops_inactive_non_signaled_ip() {
        let mut mgr = SynFloodAlertManager::new(NO_COOLDOWN, 5, 1);
        let now = Instant::now();

        // One quiet tick for an IP that never signaled at all shouldn't even
        // create a state; a signal that stops before firing should still be
        // dropped by GC once it's no longer hot.
        mgr.evaluate(&[signal(1, 200.0)], now); // count=1, Pending
        assert_eq!(mgr.active_count(), 1);
        mgr.evaluate(&[], now); // signal gone, not hot -> GC'd
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn synflood_manager_bounded_state_does_not_grow_with_ip_churn() {
        let top_n = 5;
        let mut mgr = SynFloodAlertManager::new(NO_COOLDOWN, 3, 1);
        let now = Instant::now();

        // Feed many distinct one-shot IPs across many ticks, each appearing
        // only in a single tick's (already top-N-bounded) signal list.
        for tick in 0..100u32 {
            let ips: Vec<SynFloodSignal> = (0..top_n)
                .map(|i| signal(tick * top_n as u32 + i as u32, 200.0))
                .collect();
            mgr.evaluate(&ips, now);
        }

        assert!(
            mgr.active_count() <= top_n,
            "active_count should stay bounded by top_n, got {}",
            mgr.active_count()
        );
    }

    #[test]
    fn heartbeats_empty_before_firing() {
        let mut mgr = SynFloodAlertManager::new(NO_COOLDOWN, 3, 1);
        let now = Instant::now();

        mgr.evaluate(&[signal(1, 200.0)], now); // Pending, not yet Firing
        let heartbeats = mgr.heartbeats(&[signal(1, 200.0)], &HashSet::new());
        assert!(heartbeats.is_empty(), "should not heartbeat while Pending");
    }

    #[test]
    fn heartbeats_returns_alert_on_subsequent_tick_while_firing() {
        let mut mgr = SynFloodAlertManager::new(NO_COOLDOWN, 1, 1);
        let now = Instant::now();

        let fired = mgr.evaluate(&[signal(1, 200.0)], now);
        assert_eq!(fired.len(), 1);

        let events = mgr.evaluate(&[signal(1, 250.0)], now); // still firing
        assert!(events.is_empty());

        let heartbeats = mgr.heartbeats(&[signal(1, 250.0)], &HashSet::new());
        assert_eq!(heartbeats.len(), 1);
        assert_eq!(heartbeats[0].src_ip, Ipv4Addr::from(1));
        assert_eq!(heartbeats[0].pps, 250.0);
    }

    #[test]
    fn heartbeats_excludes_ip_that_just_transitioned() {
        let mut mgr = SynFloodAlertManager::new(NO_COOLDOWN, 1, 1);
        let now = Instant::now();

        let fired = mgr.evaluate(&[signal(1, 200.0)], now);
        assert_eq!(fired.len(), 1);
        let just_transitioned: HashSet<_> = fired.iter().map(|e| e.alert.src_ip).collect();

        let heartbeats = mgr.heartbeats(&[signal(1, 200.0)], &just_transitioned);
        assert!(
            heartbeats.is_empty(),
            "should not double-send an alert that fired this same tick"
        );
    }

    #[test]
    fn heartbeats_empty_once_signal_drops() {
        // resolve_consecutive_threshold=2, so one quiet tick keeps it Firing
        // with no active signal to source heartbeat data from.
        let mut mgr = SynFloodAlertManager::new(NO_COOLDOWN, 1, 2);
        let now = Instant::now();

        mgr.evaluate(&[signal(1, 200.0)], now); // fires
        let events = mgr.evaluate(&[], now); // still firing, resolve threshold not yet met
        assert!(events.is_empty());

        let heartbeats = mgr.heartbeats(&[], &HashSet::new());
        assert!(
            heartbeats.is_empty(),
            "no active signal this tick means no fresh data to heartbeat with"
        );
    }
}
