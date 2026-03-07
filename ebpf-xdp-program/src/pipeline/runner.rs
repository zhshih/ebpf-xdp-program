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
        Self { prev_counters: None, baseline, emergency_detector, alert_manager, warmed_up: false }
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
        let rate_snapshot = ProtoRateSnapshot { timestamp: curr.timestamp, rates };

        let ewma_detector = EwmaDetector::new(&self.baseline);
        let outcome = run_anomaly_pipeline(
            &rate_snapshot,
            &ewma_detector,
            &self.emergency_detector,
            &mut self.alert_manager,
        );

        let frozen = self.alert_manager.frozen_protos(curr.timestamp);
        let unfrozen: Vec<_> = rate_snapshot.rates.iter()
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

    let events = alert_manager.evaluate(&all_signals, snapshot.timestamp);

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