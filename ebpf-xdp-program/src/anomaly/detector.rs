use crate::{alert::AlertSignal, rate::ProtoRateSnapshot};

/// Outcome of a single anomaly detection pass.
///
/// `WarmingUp` means the baseline is not yet ready and no detection was performed.
/// `Signals` contains zero or more anomaly signals (an empty vec means normal traffic).
pub enum DetectResult {
    WarmingUp,
    Signals(Vec<AlertSignal>),
}

/// Abstraction over anomaly detection strategies.
///
/// Implementors examine a rate snapshot and return signals for any protocols
/// whose traffic deviates from the expected pattern.
pub trait AnomalyDetector {
    fn detect(&self, snapshot: &ProtoRateSnapshot) -> DetectResult;
}

/// Severity classification for a detected anomaly.
///
/// Variants are ordered: `Normal < Suspicious < Severe`, enabling comparison
/// against [`AlertRule::min_level`](crate::alert::AlertRule).
///
/// Z-score thresholds: Normal < 3σ, Suspicious 3–6σ, Severe ≥ 6σ.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq)]
pub enum AnomalyLevel {
    Normal,
    Suspicious,
    Severe,
}

impl AnomalyLevel {
    /// Returns `true` only for `Normal`; used to filter out non-anomalous signals.
    pub fn is_normal(&self) -> bool {
        matches!(self, AnomalyLevel::Normal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anomaly_level_ordering() {
        assert!(AnomalyLevel::Normal < AnomalyLevel::Suspicious);
        assert!(AnomalyLevel::Suspicious < AnomalyLevel::Severe);
        assert!(AnomalyLevel::Normal < AnomalyLevel::Severe);
    }

    #[test]
    fn anomaly_level_is_normal() {
        assert!(AnomalyLevel::Normal.is_normal());
    }

    #[test]
    fn anomaly_level_is_not_normal() {
        assert!(!AnomalyLevel::Suspicious.is_normal());
        assert!(!AnomalyLevel::Severe.is_normal());
    }
}
