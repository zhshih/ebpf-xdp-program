use crate::{
    alert::{AlertKind, AlertSignal},
    anomaly::detector::{AnomalyDetector, AnomalyLevel, DetectResult},
    baseline::{Baseline, BaselineState},
    rate::ProtoRateSnapshot,
};

use super::zscore::compute_proto_z_scores;

pub struct EwmaDetector<'a, B: Baseline> {
    baseline: &'a B,
}

impl<'a, B: Baseline> EwmaDetector<'a, B> {
    pub fn new(baseline: &'a B) -> Self {
        Self { baseline }
    }
}

impl<'a, B: Baseline> AnomalyDetector for EwmaDetector<'a, B> {
    fn detect(&self, snapshot: &ProtoRateSnapshot) -> DetectResult {
        let mut signals = Vec::new();
        let mut any_ready = false;

        for rate in &snapshot.rates {
            let baseline_state = self.baseline.snapshot(rate.proto);

            let (anomaly_level, z_pps, z_bps) = match baseline_state {
                BaselineState::Ready {
                    baseline: proto_baseline,
                } => {
                    any_ready = true;
                    let (z_pps, z_bps) =
                        compute_proto_z_scores(&proto_baseline, rate.pps, rate.bps);
                    let level = match (anomaly_level_from_z(z_pps), anomaly_level_from_z(z_bps)) {
                        (AnomalyLevel::Severe, _) | (_, AnomalyLevel::Severe) => {
                            AnomalyLevel::Severe
                        }
                        (AnomalyLevel::Suspicious, _) | (_, AnomalyLevel::Suspicious) => {
                            AnomalyLevel::Suspicious
                        }
                        _ => AnomalyLevel::Normal,
                    };
                    (level, Some(z_pps), Some(z_bps))
                }
                BaselineState::Warming => (AnomalyLevel::Normal, None, None),
            };

            if anomaly_level.is_normal() {
                continue;
            }

            tracing::info!(
                "detecting anomaly for proto {:?}: level={:?}, z_pps={:?}, z_bps={:?}",
                rate.proto,
                anomaly_level,
                z_pps,
                z_bps,
            );

            let dominant_z = match (z_pps, z_bps) {
                (Some(zp), Some(zb)) => Some(if zp.abs() >= zb.abs() { zp } else { zb }),
                (Some(z), None) | (None, Some(z)) => Some(z),
                _ => None,
            };
            let confidence = {
                let pps = z_pps.map(f64::abs).unwrap_or(0.0);
                let bps = z_bps.map(f64::abs).unwrap_or(0.0);
                (pps.max(bps) / 10.0).min(1.0)
            };
            let kind = match dominant_z {
                Some(z) if z >= 0.0 => AlertKind::Spike,
                Some(_) => AlertKind::Drop,
                None => AlertKind::Spike,
            };

            tracing::info!(
                "generated alert signal for proto {:?}: level={:?}, z={:?}, confidence={}",
                rate.proto,
                anomaly_level,
                dominant_z,
                confidence,
            );

            signals.push(AlertSignal {
                proto: rate.proto,
                level: anomaly_level,
                kind,
                confidence,
            });
        }

        if any_ready {
            DetectResult::Signals(signals)
        } else {
            DetectResult::WarmingUp
        }
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
