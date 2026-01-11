use crate::{ProtoIndex, stats::baseline::proto::Baseline};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyLevel {
    Normal,
    Suspicious,
    Severe,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct AnomalyDecision {
    pub proto: ProtoIndex,
    pub pps: f64,
    pub bps: f64,
    pub pps_baseline: Baseline,
    pub bps_baseline: Baseline,
    pub z_pps: Option<f64>,
    pub z_bps: Option<f64>,
    pub anomaly_level: AnomalyLevel,
}

pub fn classify(z: Option<f64>) -> Option<AnomalyLevel> {
    z.map(|v| {
        let a = v.abs();
        if a < 3.0 {
            AnomalyLevel::Normal
        } else if a < 6.0 {
            AnomalyLevel::Suspicious
        } else {
            AnomalyLevel::Severe
        }
    })
}
