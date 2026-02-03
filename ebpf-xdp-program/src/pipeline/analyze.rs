use crate::{
    alert::{AlertEvent, AlertManager, AlertSignal},
    anomaly::{AnomalyDetector, DetectResult},
    rate::ProtoRateSnapshot,
};

pub enum PipelineOutcome {
    WarmingUp,
    NoSignals,
    Events { events: Vec<AlertEvent> },
}

pub fn run_anomaly_pipeline(
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
