use std::time::Instant;

use crate::{
    alert::{PortScanAlert, PortScanAlertEvent, PortScanAlertLifecycleManager},
    anomaly::PortScanDetector,
    metrics::MetricsHandle,
    pipeline::{TickAlerts, view::PortScanSnapshot},
    rate::{PortScanCountersSnapshot, PortScanIpBreadth, compute_port_scan_breadth},
};

/// Coordinates per-source-IP port-scan detection, mirroring
/// [`crate::pipeline::SynFloodRunner`]'s tick/snapshot shape but with no
/// `prime_or_diff` step: [`compute_port_scan_breadth`] is a pure function of
/// a single fresh snapshot (a windowed gauge, not a rate), so every tick
/// with data produces a real result, including the first.
pub struct PortScanRunner {
    detector: PortScanDetector,
    alert_lifecycle_manager: PortScanAlertLifecycleManager,
    /// Top scanners from the most recently processed tick; empty until the
    /// first successful tick. Read by [`Self::snapshot`] for the API.
    last_top_n: Vec<PortScanIpBreadth>,
}

impl PortScanRunner {
    pub fn new(
        detector: PortScanDetector,
        alert_lifecycle_manager: PortScanAlertLifecycleManager,
    ) -> Self {
        Self {
            detector,
            alert_lifecycle_manager,
            last_top_n: Vec::new(),
        }
    }

    pub fn tick(
        &mut self,
        current: &Option<PortScanCountersSnapshot>,
        metrics: &MetricsHandle,
    ) -> TickAlerts<PortScanAlertEvent, PortScanAlert> {
        let Some(curr) = current else {
            return TickAlerts {
                transitions: Vec::new(),
                heartbeats: Vec::new(),
            };
        };

        let top_n =
            compute_port_scan_breadth(curr, self.detector.window_ns(), self.detector.top_n());
        let signals = self.detector.detect(&top_n);
        let (transitions, heartbeats) = self.alert_lifecycle_manager.tick(&signals, Instant::now());

        for event in &transitions {
            tracing::warn!(
                src_ip = %event.alert.src_ip,
                distinct_ports = event.alert.distinct_ports,
                confidence = event.alert.confidence,
                lifecycle = ?event.lifecycle,
                "port-scan alert event"
            );
        }

        metrics.update_port_scan(&top_n, self.alert_lifecycle_manager.active_count());
        for event in &transitions {
            metrics.record_port_scan_event(event.lifecycle);
        }

        self.last_top_n = top_n;

        TickAlerts {
            transitions,
            heartbeats,
        }
    }

    /// Assembles a point-in-time view of port-scan state for the `/portscan`
    /// API endpoint. Pure read — does not mutate any FSM.
    pub fn snapshot(&self) -> PortScanSnapshot {
        PortScanSnapshot {
            top_scanners: self.last_top_n.clone(),
            alerts: self.alert_lifecycle_manager.snapshot(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use ebpf_xdp_program_common::{PortScanKey, PortTouch};

    use super::*;

    fn snap(now_ns: u64, entries: &[(u32, u16, u64)]) -> PortScanCountersSnapshot {
        let touches = entries
            .iter()
            .map(|&(ip, port, last_seen_ns)| {
                (PortScanKey::new(ip, port), PortTouch { last_seen_ns })
            })
            .collect();
        PortScanCountersSnapshot { now_ns, touches }
    }

    fn make_runner(max_distinct_ports: u32, top_n: usize) -> PortScanRunner {
        PortScanRunner::new(
            PortScanDetector::new(max_distinct_ports, top_n, 30_000_000_000),
            PortScanAlertLifecycleManager::new(Duration::ZERO, 1, 1),
        )
    }

    #[test]
    fn port_scan_runner_tick_none_input_is_noop() {
        let mut runner = make_runner(20, 10);
        runner.tick(&None, &MetricsHandle);
        assert!(runner.snapshot().top_scanners.is_empty());
    }

    #[test]
    fn port_scan_runner_snapshot_before_any_tick_is_empty() {
        let runner = make_runner(20, 10);
        let snapshot = runner.snapshot();
        assert!(snapshot.top_scanners.is_empty());
        assert!(snapshot.alerts.is_empty());
    }

    #[test]
    fn port_scan_runner_single_tick_detects_over_threshold() {
        // Unlike SynFloodRunner, no priming tick is needed: a single tick
        // with data is enough to detect, since this is a live gauge.
        let mut runner = make_runner(2, 10);
        let s = snap(
            1_000_000_000,
            &[
                (1, 80, 999_000_000),
                (1, 443, 999_000_000),
                (1, 22, 999_000_000),
            ],
        );
        runner.tick(&Some(s), &MetricsHandle);

        let snapshot = runner.snapshot();
        assert_eq!(snapshot.top_scanners.len(), 1);
        assert_eq!(snapshot.top_scanners[0].src_ip, Ipv4Addr::from(1));
        assert_eq!(snapshot.top_scanners[0].distinct_ports, 3);
    }

    #[test]
    fn port_scan_runner_window_excludes_stale_touches() {
        let mut runner = make_runner(1, 10);
        // Only one touch falls within the 30s window; the other is 40s stale.
        let s = snap(
            50_000_000_000,
            &[(1, 80, 49_000_000_000), (1, 443, 5_000_000_000)],
        );
        runner.tick(&Some(s), &MetricsHandle);

        let snapshot = runner.snapshot();
        assert_eq!(snapshot.top_scanners.len(), 1);
        assert_eq!(snapshot.top_scanners[0].distinct_ports, 1);
    }

    #[test]
    fn port_scan_runner_fires_after_consecutive_ticks_over_threshold() {
        // consecutive_threshold=1 (see make_runner), so a single over-threshold
        // tick is enough to reach Firing — no baseline warmup needed.
        let mut runner = make_runner(2, 10);
        let s = snap(
            1_000_000_000,
            &[
                (1, 80, 999_000_000),
                (1, 443, 999_000_000),
                (1, 22, 999_000_000),
            ],
        );
        runner.tick(&Some(s), &MetricsHandle);

        let snapshot = runner.snapshot();
        assert_eq!(snapshot.alerts.len(), 1);
        assert_eq!(snapshot.alerts[0].phase_label, "firing");
        assert_eq!(snapshot.alerts[0].consecutive_count, 1);
        assert_eq!(snapshot.alerts[0].src_ip, Ipv4Addr::from(1));
    }

    #[test]
    fn port_scan_runner_tick_heartbeats_still_firing_alert() {
        let mut runner = make_runner(2, 10);
        let s = snap(
            1_000_000_000,
            &[
                (1, 80, 999_000_000),
                (1, 443, 999_000_000),
                (1, 22, 999_000_000),
            ],
        );
        let fired = runner.tick(&Some(s), &MetricsHandle);
        assert_eq!(fired.transitions.len(), 1);
        assert!(
            fired.heartbeats.is_empty(),
            "should not double-send an alert that just fired this tick"
        );

        // Same offending IP, still over threshold, later timestamp: still Firing.
        let s2 = snap(
            2_000_000_000,
            &[
                (1, 80, 1_999_000_000),
                (1, 443, 1_999_000_000),
                (1, 22, 1_999_000_000),
            ],
        );
        let alerts = runner.tick(&Some(s2), &MetricsHandle);
        assert!(
            alerts.transitions.is_empty(),
            "still firing, no new transition"
        );
        assert_eq!(alerts.heartbeats.len(), 1);
        assert_eq!(alerts.heartbeats[0].src_ip, Ipv4Addr::from(1));
    }
}
