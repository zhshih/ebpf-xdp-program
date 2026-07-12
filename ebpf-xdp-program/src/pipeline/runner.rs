use std::time::Instant;

use ebpf_xdp_program_common::ProtoIndex;

use crate::{
    alert::{AlertEvent, AlertKind, AlertManager},
    anomaly::{
        AnomalyDetector, AnomalyView, EmergencyDetector, EwmaDetector, compute_anomaly_view,
    },
    baseline::{BaselineState, EwmaEstimator},
    metrics::MetricsHandle,
    rate::{ProtoRate, TrafficCountersSnapshot, compute_rates},
};

/// Point-in-time view of one protocol's alert FSM slot, for the `/anomalies` API.
#[derive(Debug)]
pub struct AlertSlotSnapshot {
    pub kind: AlertKind,
    pub phase_label: &'static str,
    pub consecutive_count: u32,
}

/// Point-in-time view of one protocol's full anomaly/alert state.
///
/// `rate`/`anomaly` are `None` until the runner has processed at least two
/// counter snapshots (the first tick only primes `prev_counters`).
#[derive(Debug)]
pub struct ProtoSnapshot {
    pub proto: ProtoIndex,
    pub rate: Option<ProtoRate>,
    pub baseline: BaselineState,
    pub anomaly: Option<AnomalyView>,
    pub alerts: Vec<AlertSlotSnapshot>,
    pub frozen: bool,
}

/// Point-in-time view of all per-protocol anomaly/alert state, assembled by
/// [`AnomalyRunner::snapshot`] for the `/anomalies` API endpoint.
#[derive(Debug)]
pub struct RunnerSnapshot {
    pub protos: Vec<ProtoSnapshot>,
}

pub struct AnomalyRunner {
    prev_counters: Option<TrafficCountersSnapshot>,
    baseline: EwmaEstimator,
    emergency_detector: EmergencyDetector,
    alert_manager: AlertManager,
    warmed_up: bool,
    /// Rates from the most recently processed tick; empty until the second
    /// successful tick. Read by [`Self::snapshot`] for the `/anomalies` API.
    last_rates: Vec<ProtoRate>,
}

impl AnomalyRunner {
    pub fn new(
        baseline: EwmaEstimator,
        emergency_detector: EmergencyDetector,
        alert_manager: AlertManager,
    ) -> Self {
        Self {
            prev_counters: None,
            baseline,
            emergency_detector,
            alert_manager,
            warmed_up: false,
            last_rates: Vec::new(),
        }
    }

    pub fn tick(&mut self, current: &Option<TrafficCountersSnapshot>, metrics: &MetricsHandle) {
        // Advances the baseline's wall-clock gate unconditionally: this is called once
        // per real ANOMALY_EVAL_INTERVAL tick regardless of data availability, so time
        // must keep advancing even when there's nothing to process yet.
        self.baseline.advance();

        let Some(curr) = current else { return };
        let Some(prev) = super::prime_or_diff(&mut self.prev_counters, current) else {
            return;
        };

        let rates = compute_rates(&prev, curr);

        let any_ready = rates
            .iter()
            .any(|r| matches!(self.baseline.snapshot(r.proto), BaselineState::Ready { .. }));
        if !self.warmed_up && any_ready {
            self.warmed_up = true;
            tracing::info!("baseline ready");
        }

        let ewma_detector = EwmaDetector::new(&self.baseline);
        let events = run_anomaly_pipeline(
            &rates,
            &ewma_detector,
            &self.emergency_detector,
            &mut self.alert_manager,
        );

        let frozen = self.alert_manager.frozen_protos(curr.timestamp);
        let unfrozen: Vec<_> = rates
            .iter()
            .filter(|r| !frozen.contains(&r.proto))
            .cloned()
            .collect();
        if !unfrozen.is_empty() {
            tracing::info!(frozen_protos = ?frozen, "updating traffic baseline");
            self.baseline.update(&unfrozen);
        }

        if events.is_empty() {
            tracing::info!(
                baseline_ready = any_ready,
                "no alert events generated during anomaly evaluation"
            );
        }

        for event in &events {
            tracing::warn!(
                proto = ?event.alert.proto,
                level = ?event.alert.level,
                kind = ?event.alert.kind,
                state = ?event.lifecycle,
                confidence = event.alert.confidence,
                "alert event"
            );
        }

        metrics.update_rates(&rates);
        metrics.update_baseline(&self.baseline);
        metrics.update_anomaly(&rates, &self.baseline);
        metrics.update_alerts(&self.alert_manager.metrics_snapshot(), &frozen);
        for event in &events {
            metrics.record_alert_event(event.alert.proto, event.alert.kind, event.lifecycle);
        }

        self.last_rates = rates;
    }

    /// Whether the EWMA baseline has produced at least one non-warming tick.
    pub fn warmed_up(&self) -> bool {
        self.warmed_up
    }

    /// Assembles a point-in-time view of all per-protocol anomaly/alert state
    /// for the `/anomalies` API endpoint. Pure read — does not mutate any FSM
    /// or baseline, and is safe to call from a different task than `tick()`.
    pub fn snapshot(&self, now: Instant) -> RunnerSnapshot {
        let frozen = self.alert_manager.frozen_protos(now);
        let alert_snapshots = self.alert_manager.metrics_snapshot();

        let protos = (0..ProtoIndex::COUNT as usize)
            .filter_map(ProtoIndex::from_index)
            .map(|proto| {
                let rate = self.last_rates.iter().find(|r| r.proto == proto).cloned();
                let baseline = self.baseline.snapshot(proto);
                let anomaly = rate
                    .as_ref()
                    .map(|r| compute_anomaly_view(&baseline, r.pps, r.bps));
                let alerts = alert_snapshots
                    .iter()
                    .filter(|s| s.proto == proto)
                    .map(|s| AlertSlotSnapshot {
                        kind: s.kind,
                        phase_label: s.phase_label,
                        consecutive_count: s.consecutive_count,
                    })
                    .collect();

                ProtoSnapshot {
                    proto,
                    rate,
                    baseline,
                    anomaly,
                    alerts,
                    frozen: frozen.contains(&proto),
                }
            })
            .collect();

        RunnerSnapshot { protos }
    }
}

fn run_anomaly_pipeline<E: AnomalyDetector, Em: AnomalyDetector>(
    rates: &[ProtoRate],
    ewma: &E,
    emergency: &Em,
    alert_manager: &mut AlertManager,
) -> Vec<AlertEvent> {
    let mut all_signals = ewma.detect(rates);
    all_signals.extend(emergency.detect(rates));

    if !all_signals.is_empty() {
        tracing::info!("generated {} total signals", all_signals.len());
    }

    alert_manager.evaluate(&all_signals, Instant::now())
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ebpf_xdp_program_common::ProtoIndex;

    use super::*;
    use crate::{
        alert::{AlertKind, AlertRule, AlertSignal},
        anomaly::{AnomalyDetector, AnomalyLevel},
        rate::ProtoRate,
    };

    struct SignalDetector(Vec<AlertSignal>);
    impl AnomalyDetector for SignalDetector {
        fn detect(&self, _: &[ProtoRate]) -> Vec<AlertSignal> {
            self.0.clone()
        }
    }

    fn make_rates() -> Vec<ProtoRate> {
        vec![ProtoRate {
            proto: ProtoIndex::Tcp,
            pps: 100.0,
            bps: 10_000.0,
        }]
    }

    fn immediate_spike_rule() -> AlertRule {
        AlertRule {
            kind: AlertKind::Spike,
            min_level: AnomalyLevel::Suspicious,
            min_confidence: 0.0,
            cooldown: std::time::Duration::ZERO,
            consecutive_threshold: 1,
            resolve_consecutive_threshold: 1,
            freezes_baseline: false,
        }
    }

    use std::time::Duration;

    use crate::{
        config::{default_alert_rules, default_baseline_estimator, default_emergency_detector},
        metrics::MetricsHandle,
        rate::{TrafficCountersSnapshot, model::TrafficCounters},
    };

    fn make_runner() -> AnomalyRunner {
        AnomalyRunner::new(
            default_baseline_estimator(),
            default_emergency_detector(),
            AlertManager::new(default_alert_rules()),
        )
    }

    fn make_counter_snapshot(t: Instant, pkts: u64, bytes: u64) -> TrafficCountersSnapshot {
        let stats = (0..ProtoIndex::COUNT as usize)
            .map(|_| TrafficCounters {
                packets: pkts,
                bytes,
            })
            .collect();
        TrafficCountersSnapshot {
            timestamp: t,
            stats,
        }
    }

    #[test]
    fn runner_tick_none_input_is_noop() {
        let mut runner = make_runner();
        runner.tick(&None, &MetricsHandle); // should return immediately without panic
    }

    #[test]
    fn runner_tick_first_snapshot_primes_prev_counters() {
        let mut runner = make_runner();
        let snap = make_counter_snapshot(Instant::now(), 100, 10_000);
        runner.tick(&Some(snap), &MetricsHandle); // stores prev and returns early
    }

    #[test]
    fn runner_tick_second_snapshot_runs_full_pipeline() {
        let mut runner = make_runner();
        let t1 = Instant::now();
        let t2 = t1 + Duration::from_secs(1);
        let snap1 = make_counter_snapshot(t1, 100, 10_000);
        let snap2 = make_counter_snapshot(t2, 200, 20_000);
        runner.tick(&Some(snap1), &MetricsHandle); // prime prev_counters
        runner.tick(&Some(snap2), &MetricsHandle); // runs compute_rates → pipeline → baseline.update
        // baseline is Warming after 1 sample → no signals, no panic
    }

    /// `warmed_up()` flips `true` once any polled protocol's EWMA baseline
    /// reports `Ready` — exercised through real `tick()` calls rather than
    /// checking the internal `any_ready` computation directly.
    #[test]
    fn runner_warms_up_after_enough_ticks() {
        use crate::baseline::EwmaEstimator;

        // min_samples=3, min_elapsed_ticks=0 so only the sample-count gate matters.
        let estimator = EwmaEstimator::new(0.4, 3, 1e-3, 0);
        let mut runner = AnomalyRunner::new(
            estimator,
            default_emergency_detector(),
            AlertManager::new(default_alert_rules()),
        );

        let mut t = Instant::now();
        let mut pkts = 100u64;
        let mut bytes = 10_000u64;
        runner.tick(&Some(make_counter_snapshot(t, pkts, bytes)), &MetricsHandle); // prime

        assert!(!runner.warmed_up(), "should still be warming after priming");

        // Alternating deltas build variance above min_stddev quickly.
        for i in 0..6 {
            t += Duration::from_secs(1);
            if i % 2 == 0 {
                pkts += 100;
                bytes += 10_000;
            } else {
                pkts += 50;
                bytes += 5_000;
            }
            runner.tick(&Some(make_counter_snapshot(t, pkts, bytes)), &MetricsHandle);
        }

        assert!(
            runner.warmed_up(),
            "expected baseline to warm up after 6 ticks with min_samples=3"
        );
    }

    /// Regression: `warmed_up` must reflect the EWMA baseline's own
    /// readiness, not "did any alert event fire." A prior implementation
    /// derived `warmed_up` from whether `run_anomaly_pipeline` returned any
    /// events, so an emergency-only firing (baseline still `Warming`) would
    /// incorrectly flip it `true`.
    #[test]
    fn runner_warmed_up_stays_false_when_only_emergency_fires_during_warmup() {
        use crate::anomaly::{EmergencyDetector, EmergencyThreshold};

        // min_samples so high the baseline never becomes Ready within this test.
        let estimator = EwmaEstimator::new(0.4, 1000, 1e-3, 0);
        let emergency = EmergencyDetector::new(vec![EmergencyThreshold {
            proto: ProtoIndex::Tcp,
            max_pps: Some(1.0),
            max_bps: None,
        }]);
        let emergency_rule = AlertRule {
            kind: AlertKind::Emergency,
            min_level: AnomalyLevel::Suspicious,
            min_confidence: 0.0,
            cooldown: Duration::ZERO,
            consecutive_threshold: 1,
            resolve_consecutive_threshold: 1,
            freezes_baseline: false,
        };
        let mut runner = AnomalyRunner::new(
            estimator,
            emergency,
            AlertManager::new(vec![emergency_rule]),
        );

        let t1 = Instant::now();
        let t2 = t1 + Duration::from_secs(1);
        runner.tick(
            &Some(make_counter_snapshot(t1, 100, 10_000)),
            &MetricsHandle,
        ); // prime
        runner.tick(
            &Some(make_counter_snapshot(t2, 200, 20_000)),
            &MetricsHandle,
        ); // 100 pps > threshold, fires

        assert!(
            !runner.warmed_up(),
            "only the emergency detector fired; the EWMA baseline is still Warming"
        );
    }

    #[test]
    fn snapshot_before_any_tick_has_no_rates() {
        let runner = make_runner();
        let snapshot = runner.snapshot(Instant::now());
        assert_eq!(snapshot.protos.len(), ProtoIndex::COUNT as usize);
        assert!(snapshot.protos.iter().all(|p| p.rate.is_none()));
        assert!(!runner.warmed_up());
    }

    #[test]
    fn snapshot_after_second_tick_has_rates_for_every_proto() {
        let mut runner = make_runner();
        let t1 = Instant::now();
        let t2 = t1 + Duration::from_secs(1);
        let snap1 = make_counter_snapshot(t1, 100, 10_000);
        let snap2 = make_counter_snapshot(t2, 200, 20_000);
        runner.tick(&Some(snap1), &MetricsHandle);
        runner.tick(&Some(snap2), &MetricsHandle);

        let snapshot = runner.snapshot(t2);
        assert_eq!(snapshot.protos.len(), ProtoIndex::COUNT as usize);
        let tcp = snapshot
            .protos
            .iter()
            .find(|p| p.proto == ProtoIndex::Tcp)
            .expect("TCP entry present");
        assert!(
            tcp.rate.is_some(),
            "rate should be populated after a full tick"
        );
        assert!(
            matches!(tcp.baseline, crate::baseline::BaselineState::Warming),
            "single sample isn't enough to leave Warming"
        );
        // Baseline is still warming, so the anomaly view is the zeroed/Normal default.
        let anomaly = tcp
            .anomaly
            .expect("anomaly view computed whenever a rate is present");
        assert_eq!(anomaly.z_pps, 0.0);
        assert!(matches!(
            anomaly.level,
            crate::anomaly::AnomalyLevel::Normal
        ));
    }

    #[test]
    fn pipeline_no_signals_when_ready() {
        let det = SignalDetector(vec![]);
        let mut mgr = AlertManager::new(vec![immediate_spike_rule()]);
        let events = run_anomaly_pipeline(&make_rates(), &det, &det, &mut mgr);
        assert!(events.is_empty());
    }

    #[test]
    fn pipeline_events_when_signal_matches_rule() {
        let signal = AlertSignal {
            proto: ProtoIndex::Tcp,
            level: AnomalyLevel::Suspicious,
            kind: AlertKind::Spike,
            confidence: 1.0,
        };
        let det = SignalDetector(vec![signal]);
        let empty = SignalDetector(vec![]);
        let mut mgr = AlertManager::new(vec![immediate_spike_rule()]);
        let events = run_anomaly_pipeline(&make_rates(), &det, &empty, &mut mgr);
        assert!(!events.is_empty());
    }

    /// End-to-end: warm up a real EWMA baseline, then inject a massive traffic spike.
    ///
    /// This exercises the full path: `EwmaEstimator` → `EwmaDetector` → Z-score
    /// computation → `AlertManager` FSM → `AlertEvent::Fired`. No mocked detectors.
    #[test]
    fn end_to_end_spike_fires_after_baseline_warms_up() {
        use crate::{
            alert::AlertLifecycle,
            anomaly::{EmergencyDetector, EwmaDetector},
            baseline::{BaselineState, EwmaEstimator},
        };

        // No time gate so the test doesn't have to advance ticks.
        let mut estimator = EwmaEstimator::new(0.4, 10, 1e-3, 0);

        // Alternating 100/200 pps builds stddev above min_stddev quickly.
        for i in 0..20 {
            let pps = if i % 2 == 0 { 100.0_f64 } else { 200.0 };
            estimator.update(&[ProtoRate {
                proto: ProtoIndex::Tcp,
                pps,
                bps: pps * 100.0,
            }]);
        }
        assert!(
            matches!(
                estimator.snapshot(ProtoIndex::Tcp),
                BaselineState::Ready { .. }
            ),
            "baseline must be ready before the end-to-end test can proceed"
        );

        let ewma_detector = EwmaDetector::new(&estimator);
        let emergency = EmergencyDetector::new(vec![]);
        let mut alert_manager = AlertManager::new(vec![AlertRule {
            kind: AlertKind::Spike,
            min_level: AnomalyLevel::Suspicious,
            min_confidence: 0.0,
            cooldown: Duration::ZERO,
            consecutive_threshold: 1,
            resolve_consecutive_threshold: 1,
            freezes_baseline: false,
        }]);

        // 100 000 pps is >> 6σ above a ~150 pps baseline → Severe spike.
        let spike = vec![ProtoRate {
            proto: ProtoIndex::Tcp,
            pps: 100_000.0,
            bps: 10_000_000.0,
        }];

        let events = run_anomaly_pipeline(&spike, &ewma_detector, &emergency, &mut alert_manager);

        assert!(!events.is_empty(), "expected at least one alert event");
        assert!(matches!(events[0].lifecycle, AlertLifecycle::Fired));
        assert_eq!(events[0].alert.proto, ProtoIndex::Tcp);
        assert!(matches!(events[0].alert.level, AnomalyLevel::Severe));
    }
}
