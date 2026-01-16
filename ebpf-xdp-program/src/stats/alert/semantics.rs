use crate::stats::alert::model::{Alert, AlertKind};
use crate::stats::anomaly::classifier::AnomalyDecision;

pub fn decision_to_alert(decision: &AnomalyDecision) -> Option<Alert> {
    if decision.anomaly_level.is_normal() {
        return None;
    }

    let z = decision.dominant_z()?;
    let kind = if z >= 0.0 {
        AlertKind::TrafficSpike
    } else {
        AlertKind::TrafficDrop
    };

    Some(Alert {
        proto: decision.proto,
        level: decision.anomaly_level,
        kind,
        confidence: decision.confidence(),
    })
}

pub fn emit_alert(alert: Alert) {
    tracing::warn!(
        proto = ?alert.proto,
        level = ?alert.level,
        kind = ?alert.kind,
        confidence = alert.confidence,
        "traffic anomaly detected"
    );
}
