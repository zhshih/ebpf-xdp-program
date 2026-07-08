use std::time::Instant;

use crate::{
    alert::{SynFloodAlertEvent, SynFloodAlertManager, SynFloodAlertSlotSnapshot},
    anomaly::SynFloodDetector,
    metrics::MetricsHandle,
    rate::{SynCountersSnapshot, SynIpRate, compute_syn_rates_top_n},
};

/// Point-in-time view of SYN-flood state, for the `/synflood` API endpoint.
pub struct SynFloodSnapshot {
    pub top_offenders: Vec<SynIpRate>,
    pub alerts: Vec<SynFloodAlertSlotSnapshot>,
}

/// Coordinates per-source-IP SYN-flood detection, mirroring
/// [`crate::pipeline::AnomalyRunner`]'s tick/prime/snapshot shape but with
/// no baseline — [`SynFloodDetector`] is stateless and threshold-based, so
/// there's no warmup gate to track.
pub struct SynFloodRunner {
    prev_snapshot: Option<SynCountersSnapshot>,
    detector: SynFloodDetector,
    alert_manager: SynFloodAlertManager,
    /// Top offenders from the most recently processed tick; empty until the
    /// second successful tick. Read by [`Self::snapshot`] for the API.
    last_top_n: Vec<SynIpRate>,
}

impl SynFloodRunner {
    pub fn new(detector: SynFloodDetector, alert_manager: SynFloodAlertManager) -> Self {
        Self {
            prev_snapshot: None,
            detector,
            alert_manager,
            last_top_n: Vec::new(),
        }
    }

    pub fn tick(&mut self, current: &Option<SynCountersSnapshot>, metrics: &MetricsHandle) {
        let Some(curr) = current else { return };
        let prev = match &self.prev_snapshot {
            Some(p) => p.clone(),
            None => {
                self.prev_snapshot = Some(curr.clone());
                return;
            }
        };

        let top_n = compute_syn_rates_top_n(&prev, curr, self.detector.top_n());
        let signals = self.detector.detect(&top_n);
        let events = self.alert_manager.evaluate(&signals, Instant::now());

        for event in &events {
            tracing::warn!(
                src_ip = %event.src_ip,
                pps = event.pps,
                confidence = event.confidence,
                lifecycle = ?event.lifecycle,
                "syn-flood alert event"
            );
        }

        metrics.update_synflood(&top_n, self.alert_manager.active_count());
        for event in &events {
            metrics.record_synflood_event(event.lifecycle);
        }

        self.last_top_n = top_n;
        self.prev_snapshot = Some(curr.clone());
    }

    /// Assembles a point-in-time view of SYN-flood state for the `/synflood`
    /// API endpoint. Pure read — does not mutate any FSM.
    pub fn snapshot(&self) -> SynFloodSnapshot {
        SynFloodSnapshot {
            top_offenders: self.last_top_n.clone(),
            alerts: self.alert_manager.snapshot(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use super::*;
    use ebpf_xdp_program_common::SynCounter;

    fn snap(t: Instant, entries: &[(u32, u64)]) -> SynCountersSnapshot {
        let counters = entries
            .iter()
            .map(|&(ip, packets)| (ip, SynCounter { packets, bytes: packets * 60 }))
            .collect();
        SynCountersSnapshot {
            timestamp: t,
            counters,
        }
    }

    fn make_runner(max_syn_pps: f64, top_n: usize) -> SynFloodRunner {
        SynFloodRunner::new(
            SynFloodDetector::new(max_syn_pps, top_n),
            SynFloodAlertManager::new(Duration::ZERO, 1, 1),
        )
    }

    #[test]
    fn synflood_runner_tick_none_input_is_noop() {
        let mut runner = make_runner(100.0, 10);
        runner.tick(&None, &MetricsHandle);
        assert!(runner.snapshot().top_offenders.is_empty());
    }

    #[test]
    fn synflood_runner_first_snapshot_primes_prev() {
        let mut runner = make_runner(100.0, 10);
        let s = snap(Instant::now(), &[(1, 10)]);
        runner.tick(&Some(s), &MetricsHandle);
        assert!(runner.snapshot().top_offenders.is_empty());
    }

    #[test]
    fn synflood_runner_second_snapshot_detects_over_threshold() {
        let mut runner = make_runner(100.0, 10);
        let t1 = Instant::now();
        let t2 = t1 + Duration::from_secs(1);
        runner.tick(&Some(snap(t1, &[(1, 0)])), &MetricsHandle);
        runner.tick(&Some(snap(t2, &[(1, 200)])), &MetricsHandle);

        let snapshot = runner.snapshot();
        assert_eq!(snapshot.top_offenders.len(), 1);
        assert_eq!(snapshot.top_offenders[0].src_ip, Ipv4Addr::from(1));
        assert!((snapshot.top_offenders[0].pps - 200.0).abs() < 1.0);
    }

    #[test]
    fn synflood_runner_snapshot_before_any_tick_is_empty() {
        let runner = make_runner(100.0, 10);
        let snapshot = runner.snapshot();
        assert!(snapshot.top_offenders.is_empty());
        assert!(snapshot.alerts.is_empty());
    }

    #[test]
    fn synflood_runner_fires_after_consecutive_ticks_over_threshold() {
        // consecutive_threshold=1 (see make_runner), so a single over-threshold
        // tick is enough to reach Firing — no baseline warmup needed, unlike
        // AnomalyRunner's EWMA equivalent.
        let mut runner = make_runner(100.0, 10);
        let mut t = Instant::now();
        runner.tick(&Some(snap(t, &[(1, 0)])), &MetricsHandle); // prime

        t += Duration::from_secs(1);
        runner.tick(&Some(snap(t, &[(1, 500)])), &MetricsHandle);

        let snapshot = runner.snapshot();
        assert_eq!(snapshot.alerts.len(), 1);
        assert_eq!(snapshot.alerts[0].phase_label, "firing");
    }
}
