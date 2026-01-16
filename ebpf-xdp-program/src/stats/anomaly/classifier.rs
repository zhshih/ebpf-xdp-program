use crate::{ProtoIndex, stats::baseline::proto::Baseline};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyLevel {
    Normal,
    Suspicious,
    Severe,
}

impl AnomalyLevel {
    pub fn is_normal(&self) -> bool {
        matches!(self, AnomalyLevel::Normal)
    }
}

pub enum AnalyzeResult {
    WarmingUp,
    Normal(Vec<AnomalyDecision>),
}

impl AnalyzeResult {
    pub fn decisions(&self) -> &[AnomalyDecision] {
        match self {
            AnalyzeResult::Normal(d) => d,
            AnalyzeResult::WarmingUp => &[],
        }
    }

    pub fn is_warming_up(&self) -> bool {
        matches!(self, AnalyzeResult::WarmingUp)
    }
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

impl AnomalyDecision {
    pub fn confidence(&self) -> f64 {
        let pps = self.z_pps.map(f64::abs).unwrap_or(0.0);
        let bps = self.z_bps.map(f64::abs).unwrap_or(0.0);
        pps.max(bps)
    }

    pub fn dominant_z(&self) -> Option<f64> {
        match (self.z_pps, self.z_bps) {
            (Some(zp), Some(zb)) => Some(if zp.abs() >= zb.abs() { zp } else { zb }),
            (Some(z), None) | (None, Some(z)) => Some(z),
            _ => None,
        }
    }
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
