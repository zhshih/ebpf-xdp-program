//! Per-source-IP port-scan alerting.
//!
//! Deliberately parallel to, not folded into, [`crate::alert::AlertManager`]
//! — same rationale as [`crate::alert::SynFloodAlertManager`] (see its own
//! doc comment). [`PortScanAlertManager`] reuses [`AlertState`] but keeps
//! its own small, separately-bounded map.
//!
//! `PortScanSignal`/`PortScanAlert`/`PortScanAlertEvent` live in
//! `crate::alert::model`; [`PortScanAlertSlotSnapshot`] lives in
//! `crate::alert::view` (see `crate::alert`'s module doc for why). This file
//! keeps only what's private to `PortScanAlertManager` itself: its FSM/GC
//! logic.
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use crate::alert::{
    model::{PortScanAlert, PortScanAlertEvent, PortScanSignal},
    state::AlertState,
    view::PortScanAlertSlotSnapshot,
};

/// Drives per-source-IP port-scan alert FSMs. Same bounded-memory rationale
/// as [`crate::alert::SynFloodAlertManager`] (see its own doc comment).
pub struct PortScanAlertManager {
    cooldown: Duration,
    consecutive_threshold: u32,
    resolve_consecutive_threshold: u32,
    states: HashMap<Ipv4Addr, AlertState>,
}

impl PortScanAlertManager {
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
        signals: &[PortScanSignal],
        now: Instant,
    ) -> Vec<PortScanAlertEvent> {
        let active: HashMap<Ipv4Addr, &PortScanSignal> =
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
                events.push(PortScanAlertEvent {
                    alert: PortScanAlert {
                        src_ip: ip,
                        distinct_ports: signal.map_or(0, |s| s.distinct_ports),
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

    pub fn active_count(&self) -> usize {
        self.states.len()
    }

    pub fn snapshot(&self) -> Vec<PortScanAlertSlotSnapshot> {
        self.states
            .iter()
            .map(|(ip, s)| PortScanAlertSlotSnapshot {
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

    fn signal(ip: u32, distinct_ports: u32) -> PortScanSignal {
        PortScanSignal {
            src_ip: Ipv4Addr::from(ip),
            distinct_ports,
            confidence: 1.0,
        }
    }

    #[test]
    fn port_scan_manager_fires_after_consecutive() {
        let mut mgr = PortScanAlertManager::new(NO_COOLDOWN, 3, 1);
        let now = Instant::now();

        let e1 = mgr.evaluate(&[signal(1, 30)], now);
        let e2 = mgr.evaluate(&[signal(1, 30)], now);
        let e3 = mgr.evaluate(&[signal(1, 30)], now);

        assert!(e1.is_empty());
        assert!(e2.is_empty());
        assert_eq!(e3.len(), 1);
        assert!(matches!(e3[0].lifecycle, AlertLifecycle::Fired));
        assert_eq!(e3[0].alert.src_ip, Ipv4Addr::from(1));
    }

    #[test]
    fn port_scan_manager_resolves_after_quiet() {
        let mut mgr = PortScanAlertManager::new(NO_COOLDOWN, 1, 1);
        let now = Instant::now();

        let fired = mgr.evaluate(&[signal(1, 30)], now);
        assert_eq!(fired.len(), 1);
        assert!(matches!(fired[0].lifecycle, AlertLifecycle::Fired));

        let resolved = mgr.evaluate(&[], now);
        assert_eq!(resolved.len(), 1);
        assert!(matches!(resolved[0].lifecycle, AlertLifecycle::Resolved));
    }

    #[test]
    fn port_scan_manager_cooldown_blocks_refire() {
        let long_cooldown = Duration::from_secs(3600);
        let mut mgr = PortScanAlertManager::new(long_cooldown, 1, 1);
        let now = Instant::now();

        mgr.evaluate(&[signal(1, 30)], now); // fires
        mgr.evaluate(&[], now); // resolves, still within cooldown

        let refire = mgr.evaluate(&[signal(1, 30)], now);
        assert!(refire.is_empty(), "cooldown should block refire");
    }

    #[test]
    fn port_scan_manager_gc_drops_inactive_non_signaled_ip() {
        let mut mgr = PortScanAlertManager::new(NO_COOLDOWN, 5, 1);
        let now = Instant::now();

        mgr.evaluate(&[signal(1, 30)], now); // count=1, Pending
        assert_eq!(mgr.active_count(), 1);
        mgr.evaluate(&[], now); // signal gone, not hot -> GC'd
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn port_scan_manager_bounded_state_does_not_grow_with_ip_churn() {
        let top_n = 5;
        let mut mgr = PortScanAlertManager::new(NO_COOLDOWN, 3, 1);
        let now = Instant::now();

        for tick in 0..100u32 {
            let ips: Vec<PortScanSignal> = (0..top_n)
                .map(|i| signal(tick * top_n as u32 + i as u32, 30))
                .collect();
            mgr.evaluate(&ips, now);
        }

        assert!(
            mgr.active_count() <= top_n,
            "active_count should stay bounded by top_n, got {}",
            mgr.active_count()
        );
    }
}
