use crate::{
    ProtoIndex,
    anomaly::zscore::compute_proto_z_scores,
    baseline::{AnomalyBaseline, BaselineState, ProtoBaseline, Readiness},
    rate::{ProtoRate, ProtoRateSnapshot},
};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq)]
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

#[derive(Debug)]
pub enum AnalyzeResult {
    WarmingUp,
    Normal(Vec<AnomalyObservation>),
}

#[allow(dead_code)]
impl AnalyzeResult {
    pub fn observations(&self) -> &[AnomalyObservation] {
        match self {
            AnalyzeResult::Normal(d) => d,
            AnalyzeResult::WarmingUp => &[],
        }
    }

    pub fn is_warming_up(&self) -> bool {
        matches!(self, AnalyzeResult::WarmingUp)
    }
}

#[derive(Debug)]
pub struct AnomalyObservation {
    pub proto: ProtoIndex,
    #[allow(dead_code)]
    pub observed_pps: f64,
    #[allow(dead_code)]
    pub observed_bps: f64,
    #[allow(dead_code)]
    pub baseline: ProtoBaseline,
    pub z_pps: Option<f64>,
    pub z_bps: Option<f64>,
    pub anomaly_level: AnomalyLevel,
}

impl AnomalyObservation {
    pub fn confidence(&self) -> f64 {
        if self.z_pps.is_none() && self.z_bps.is_none() {
            1.0
        } else {
            let pps = self.z_pps.map(f64::abs).unwrap_or(0.0);
            let bps = self.z_bps.map(f64::abs).unwrap_or(0.0);
            let max_z = pps.max(bps);
            (max_z / 10.0).min(1.0)
        }
    }

    pub fn dominant_z(&self) -> Option<f64> {
        match (self.z_pps, self.z_bps) {
            (Some(zp), Some(zb)) => Some(if zp.abs() >= zb.abs() { zp } else { zb }),
            (Some(z), None) | (None, Some(z)) => Some(z),
            _ => None,
        }
    }
}

pub fn observe_anomaly<B: AnomalyBaseline>(
    snapshot: &ProtoRateSnapshot,
    baseline: &B,
) -> AnalyzeResult {
    let mut observations = Vec::new();
    let mut any_ready = false;

    let emergence_epsilon = 1.0;

    for rate in &snapshot.rates {
        let baseline_state = baseline.snapshot(rate.proto);

        match baseline_state {
            BaselineState::Ready {
                baseline: proto_baseline,
            } => {
                any_ready = true;

                let (z_pps, z_bps) = compute_proto_z_scores(&proto_baseline, rate.pps, rate.bps);

                let pps_level = anomaly_level_from_z(z_pps);
                let bps_level = anomaly_level_from_z(z_bps);

                let anomaly_level = match (pps_level, bps_level) {
                    (AnomalyLevel::Severe, _) | (_, AnomalyLevel::Severe) => AnomalyLevel::Severe,
                    (AnomalyLevel::Suspicious, _) | (_, AnomalyLevel::Suspicious) => {
                        AnomalyLevel::Suspicious
                    }
                    _ => AnomalyLevel::Normal,
                };

                observations.push(AnomalyObservation {
                    proto: rate.proto,
                    observed_pps: rate.pps,
                    observed_bps: rate.bps,
                    baseline: proto_baseline,
                    z_pps: Some(z_pps),
                    z_bps: Some(z_bps),
                    anomaly_level,
                });
            }

            BaselineState::Warming {
                reason: Readiness::LowVariance,
            } => {
                if is_emergence_anomaly(rate, emergence_epsilon) {
                    observations.push(AnomalyObservation {
                        proto: rate.proto,
                        observed_pps: rate.pps,
                        observed_bps: rate.bps,
                        baseline: ProtoBaseline::zero(),
                        z_pps: None,
                        z_bps: None,
                        anomaly_level: AnomalyLevel::Suspicious,
                    });
                }
            }
            _ => {
                continue;
            }
        }
    }

    if any_ready {
        AnalyzeResult::Normal(observations)
    } else {
        AnalyzeResult::WarmingUp
    }
}

fn anomaly_level_from_z(z: f64) -> AnomalyLevel {
    let a = z.abs();
    if a < 3.0 {
        AnomalyLevel::Normal
    } else if a < 6.0 {
        AnomalyLevel::Suspicious
    } else {
        AnomalyLevel::Severe
    }
}

fn is_emergence_anomaly(rate: &ProtoRate, epsilon: f64) -> bool {
    rate.pps > epsilon || rate.bps > epsilon
}
