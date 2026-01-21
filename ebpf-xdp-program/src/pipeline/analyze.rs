use crate::{
    alert::{AlertEvent, AlertKind, AlertManager, AlertSignal},
    anomaly::{self, AnalyzeResult, AnomalyObservation},
    baseline::AnomalyBaseline,
    rate::ProtoRateSnapshot,
};

pub enum PipelineOutcome {
    WarmingUp,
    NoSignals,
    Events { events: Vec<AlertEvent> },
}

pub fn run_anomaly_pipeline<B: AnomalyBaseline>(
    snapshot: &ProtoRateSnapshot,
    baseline: &mut B,
    alert_manager: &mut AlertManager,
) -> PipelineOutcome {
    let result = anomaly::observe_anomaly(snapshot, baseline);

    match result {
        AnalyzeResult::WarmingUp => PipelineOutcome::WarmingUp,

        AnalyzeResult::Normal(obs) => {
            let signals: Vec<_> = obs.iter().filter_map(observation_to_signal).collect();

            if signals.is_empty() {
                return PipelineOutcome::NoSignals;
            }

            tracing::info!("generated {:?} signals", signals);
            let events = alert_manager.evaluate(&signals, snapshot.timestamp);

            PipelineOutcome::Events { events }
        }
    }
}

fn observation_to_signal(observation: &AnomalyObservation) -> Option<AlertSignal> {
    tracing::info!(
        "classifying anomaly observation for proto {:?}: level={:?}, z_pps={:?}, z_bps={:?}, confidence={}",
        observation.proto,
        observation.anomaly_level,
        observation.z_pps,
        observation.z_bps,
        observation.confidence()
    );
    if observation.anomaly_level.is_normal() {
        return None;
    }

    let kind = match observation.dominant_z() {
        Some(z) => {
            if z >= 0.0 {
                AlertKind::Spike
            } else {
                AlertKind::Drop
            }
        }
        None => AlertKind::Spike,
    };

    tracing::info!(
        "generated alert signal for proto {:?}: level={:?}, z={:?}, confidence={}",
        observation.proto,
        observation.anomaly_level,
        observation.dominant_z(),
        observation.confidence()
    );
    Some(AlertSignal {
        proto: observation.proto,
        level: observation.anomaly_level,
        kind,
        confidence: observation.confidence(),
    })
}
