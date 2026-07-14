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

    /// Short lowercase label, mirroring `AlertKind::label()` / `ProtoIndex::label()`.
    pub fn label(self) -> &'static str {
        match self {
            AnomalyLevel::Normal => "normal",
            AnomalyLevel::Suspicious => "suspicious",
            AnomalyLevel::Severe => "severe",
        }
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

    #[test]
    fn anomaly_level_label_all_variants() {
        assert_eq!(AnomalyLevel::Normal.label(), "normal");
        assert_eq!(AnomalyLevel::Suspicious.label(), "suspicious");
        assert_eq!(AnomalyLevel::Severe.label(), "severe");
    }
}
