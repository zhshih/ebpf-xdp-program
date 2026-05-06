use ebpf_xdp_program_common::ProtoIndex;

use crate::anomaly::AnomalyLevel;

/// Classification of what kind of anomaly was detected.
///
/// - `Spike`: traffic rate significantly above the baseline (positive z-score)
/// - `Drop`: traffic rate significantly below the baseline (negative z-score)
/// - `Emergency`: absolute threshold breached, regardless of baseline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertKind {
    Spike,
    Drop,
    Emergency,
}

impl AlertKind {
    /// Short lowercase label used in Prometheus metric labels and log output.
    pub fn label(self) -> &'static str {
        match self {
            AlertKind::Spike => "spike",
            AlertKind::Drop => "drop",
            AlertKind::Emergency => "emergency",
        }
    }
}

/// An intermediate anomaly signal produced by a detector, before FSM evaluation.
///
/// Signals are filtered by [`AlertRule`](crate::alert::AlertRule) criteria
/// (min_level, min_confidence) before advancing the alert state machine.
#[derive(Debug, Clone)]
pub struct AlertSignal {
    pub proto: ProtoIndex,
    pub level: AnomalyLevel,
    pub kind: AlertKind,
    /// Normalized confidence in [0, 1]; higher means the anomaly is more pronounced.
    pub confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_kind_label_all_variants() {
        assert_eq!(AlertKind::Spike.label(), "spike");
        assert_eq!(AlertKind::Drop.label(), "drop");
        assert_eq!(AlertKind::Emergency.label(), "emergency");
    }
}

/// A finalized alert emitted by the alert manager on a `Fired` or `Resolved` transition.
#[derive(Debug, Clone)]
pub struct Alert {
    pub proto: ProtoIndex,
    pub kind: AlertKind,
    pub level: AnomalyLevel,
    pub confidence: f64,
}
