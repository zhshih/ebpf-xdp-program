use std::time::Instant;

use crate::{
    alert::{AlertEvent, AlertManager, AlertSignal},
    anomaly::{AnomalyDetector, DetectResult, EmergencyDetector, EwmaDetector},
    baseline::EwmaEstimator,
    metrics::MetricsHandle,
    rate::{ProtoRateSnapshot, TrafficCountersSnapshot, compute_rates},
};

enum PipelineOutcome {
    WarmingUp,
    NoSignals,
    Events { events: Vec<AlertEvent> },
}

pub struct AnomalyRunner {
    prev_counters: Option<TrafficCountersSnapshot>,
    baseline: EwmaEstimator,
    emergency_detector: EmergencyDetector,
    alert_manager: AlertManager,
    warmed_up: bool,
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
        }
    }

    pub fn tick(&mut self, current: &Option<TrafficCountersSnapshot>, metrics: &MetricsHandle) {
        let Some(curr) = current else { return };
        let prev = match &self.prev_counters {
            Some(p) => p.clone(),
            None => {
                self.prev_counters = Some(curr.clone());
                return;
            }
        };

        let rates = compute_rates(&prev, curr);
        let rate_snapshot = ProtoRateSnapshot { rates };

        let ewma_detector = EwmaDetector::new(&self.baseline);
        let outcome = run_anomaly_pipeline(
            &rate_snapshot,
            &ewma_detector,
            &self.emergency_detector,
            &mut self.alert_manager,
        );

        let frozen = self.alert_manager.frozen_protos(curr.timestamp);
        let unfrozen: Vec<_> = rate_snapshot
            .rates
            .iter()
            .filter(|r| !frozen.contains(&r.proto))
            .cloned()
            .collect();
        if !unfrozen.is_empty() {
            tracing::info!(frozen_protos = ?frozen, "updating traffic baseline");
            self.baseline.update(&unfrozen);
        }

        if !self.warmed_up && !matches!(outcome, PipelineOutcome::WarmingUp) {
            self.warmed_up = true;
            tracing::info!("baseline ready");
        }

        let events = match outcome {
            PipelineOutcome::WarmingUp => {
                tracing::info!("baseline warming up");
                vec![]
            }
            PipelineOutcome::NoSignals => {
                tracing::info!("no alert signals generated during anomaly evaluation");
                vec![]
            }
            PipelineOutcome::Events { events } => events,
        };

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

        metrics.update_rates(&rate_snapshot.rates);
        metrics.update_baseline(&self.baseline);
        metrics.update_anomaly(&rate_snapshot.rates, &self.baseline);
        metrics.update_alerts(&self.alert_manager.metrics_snapshot(), &frozen);
        for event in &events {
            metrics.record_alert_event(event.alert.proto, event.alert.kind, event.lifecycle);
        }

        self.prev_counters = Some(curr.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ebpf_xdp_program_common::ProtoIndex;

    use super::*;
    use crate::{
        alert::{AlertKind, AlertRule, AlertSignal},
        anomaly::{AnomalyDetector, AnomalyLevel, DetectResult},
        rate::{ProtoRate, ProtoRateSnapshot},
    };

    struct WarmingDetector;
    impl AnomalyDetector for WarmingDetector {
        fn detect(&self, _: &ProtoRateSnapshot) -> DetectResult {
            DetectResult::WarmingUp
        }
    }

    struct SignalDetector(Vec<AlertSignal>);
    impl AnomalyDetector for SignalDetector {
        fn detect(&self, _: &ProtoRateSnapshot) -> DetectResult {
            DetectResult::Signals(self.0.clone())
        }
    }

    fn make_snapshot() -> ProtoRateSnapshot {
        ProtoRateSnapshot {
            rates: vec![ProtoRate {
                proto: ProtoIndex::Tcp,
                pps: 100.0,
                bps: 10_000.0,
            }],
        }
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
                bytes: bytes,
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
        // baseline is Warming after 1 sample → WarmingUp outcome, no panic
    }

    #[test]
    fn pipeline_warming_up() {
        let det = WarmingDetector;
        let mut mgr = AlertManager::new(vec![immediate_spike_rule()]);
        let outcome = run_anomaly_pipeline(&make_snapshot(), &det, &det, &mut mgr);
        assert!(matches!(outcome, PipelineOutcome::WarmingUp));
    }

    #[test]
    fn pipeline_no_signals_when_ready() {
        let det = SignalDetector(vec![]);
        let mut mgr = AlertManager::new(vec![immediate_spike_rule()]);
        let outcome = run_anomaly_pipeline(&make_snapshot(), &det, &det, &mut mgr);
        assert!(matches!(outcome, PipelineOutcome::NoSignals));
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
        let outcome = run_anomaly_pipeline(&make_snapshot(), &det, &empty, &mut mgr);
        assert!(matches!(outcome, PipelineOutcome::Events { .. }));
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

        // No time gate so the test doesn't have to sleep.
        let mut estimator = EwmaEstimator::new(0.4, 10, 1e-3, Duration::ZERO);

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
        let spike = ProtoRateSnapshot {
            rates: vec![ProtoRate {
                proto: ProtoIndex::Tcp,
                pps: 100_000.0,
                bps: 10_000_000.0,
            }],
        };

        let outcome = run_anomaly_pipeline(&spike, &ewma_detector, &emergency, &mut alert_manager);

        let PipelineOutcome::Events { events } = outcome else {
            panic!("expected PipelineOutcome::Events, got a non-event outcome");
        };
        assert!(!events.is_empty(), "expected at least one alert event");
        assert!(matches!(events[0].lifecycle, AlertLifecycle::Fired));
        assert_eq!(events[0].alert.proto, ProtoIndex::Tcp);
        assert!(matches!(events[0].alert.level, AnomalyLevel::Severe));
    }
}

fn run_anomaly_pipeline(
    snapshot: &ProtoRateSnapshot,
    ewma: &dyn AnomalyDetector,
    emergency: &dyn AnomalyDetector,
    alert_manager: &mut AlertManager,
) -> PipelineOutcome {
    let results = [ewma.detect(snapshot), emergency.detect(snapshot)];

    let any_warming = results.iter().any(|r| matches!(r, DetectResult::WarmingUp));
    let all_signals: Vec<AlertSignal> = results
        .into_iter()
        .flat_map(|r| match r {
            DetectResult::WarmingUp => vec![],
            DetectResult::Signals(s) => s,
        })
        .collect();

    if !all_signals.is_empty() {
        tracing::info!("generated {} total signals", all_signals.len());
    }

    let events = alert_manager.evaluate(&all_signals, Instant::now());

    if events.is_empty() {
        if any_warming {
            PipelineOutcome::WarmingUp
        } else {
            PipelineOutcome::NoSignals
        }
    } else {
        PipelineOutcome::Events { events }
    }
}
