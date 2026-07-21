//! Type alias instantiating the generic FSM manager for SYN-flood alerting.
//! See `crate::alert::ip_manager` for the shared FSM/GC logic and
//! `crate::alert`'s module doc for why this file still exists separately
//! from `port_scan_manager.rs`.
use crate::alert::{
    ip_manager::IpAlertLifecycleManager,
    model::{SynFloodAlert, SynFloodSignal},
};

pub type SynFloodAlertLifecycleManager = IpAlertLifecycleManager<SynFloodSignal, SynFloodAlert>;

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::Ipv4Addr,
        time::{Duration, Instant},
    };

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
        let mut mgr = SynFloodAlertLifecycleManager::new(NO_COOLDOWN, 3, 1);
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
        let mut mgr = SynFloodAlertLifecycleManager::new(NO_COOLDOWN, 1, 1);
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
        let mut mgr = SynFloodAlertLifecycleManager::new(long_cooldown, 1, 1);
        let now = Instant::now();

        mgr.evaluate(&[signal(1, 200.0)], now); // fires
        mgr.evaluate(&[], now); // resolves, still within cooldown

        let refire = mgr.evaluate(&[signal(1, 200.0)], now);
        assert!(refire.is_empty(), "cooldown should block refire");
    }

    #[test]
    fn synflood_manager_gc_drops_inactive_non_signaled_ip() {
        let mut mgr = SynFloodAlertLifecycleManager::new(NO_COOLDOWN, 5, 1);
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
        let mut mgr = SynFloodAlertLifecycleManager::new(NO_COOLDOWN, 3, 1);
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
        let mut mgr = SynFloodAlertLifecycleManager::new(NO_COOLDOWN, 3, 1);
        let now = Instant::now();

        mgr.evaluate(&[signal(1, 200.0)], now); // Pending, not yet Firing
        let heartbeats = mgr.heartbeats(&[signal(1, 200.0)], &HashSet::new());
        assert!(heartbeats.is_empty(), "should not heartbeat while Pending");
    }

    #[test]
    fn heartbeats_returns_alert_on_subsequent_tick_while_firing() {
        let mut mgr = SynFloodAlertLifecycleManager::new(NO_COOLDOWN, 1, 1);
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
        let mut mgr = SynFloodAlertLifecycleManager::new(NO_COOLDOWN, 1, 1);
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
        let mut mgr = SynFloodAlertLifecycleManager::new(NO_COOLDOWN, 1, 2);
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
