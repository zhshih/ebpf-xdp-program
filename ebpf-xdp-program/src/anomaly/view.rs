//! `BaselineState`-to-view rendering, decoupled from the `AnomalyDetector`
//! trait system.
//!
//! [`compute_anomaly_view`] is not called by any detector's `detect()` — it's
//! used externally by `pipeline/runner.rs` (per-protocol snapshot assembly),
//! `api/anomalies.rs`, and `metrics.rs` to independently derive a z-score
//! view straight from a protocol's baseline. That's why it lives in its own
//! file rather than alongside the `AnomalyDetector` trait: it has no
//! producer/consumer relationship with `EwmaDetector`/`EmergencyDetector` at all.
use ewma_detector::compute_proto_z_scores;

use crate::{anomaly::AnomalyLevel, baseline::BaselineState};

/// Computed anomaly view for one protocol's rate sample: z-scores, discrete
/// level, and a [0, 1] confidence derived from the worse of the two z-scores.
#[derive(Debug, Clone, Copy)]
pub struct AnomalyView {
    pub z_pps: f64,
    pub z_bps: f64,
    pub level: AnomalyLevel,
    pub confidence: f64,
}

/// Classifies a single protocol's current rate against its baseline.
///
/// Returns all-zero/`Normal` while the baseline is still warming, matching the
/// behavior previously inlined in `MetricsHandle::update_anomaly`.
pub fn compute_anomaly_view(baseline: &BaselineState, pps: f64, bps: f64) -> AnomalyView {
    match baseline {
        BaselineState::Ready { baseline } => {
            let (z_pps, z_bps) = compute_proto_z_scores(baseline, pps, bps);
            let abs_z = z_pps.abs().max(z_bps.abs());
            let level = if abs_z >= 6.0 {
                AnomalyLevel::Severe
            } else if abs_z >= 3.0 {
                AnomalyLevel::Suspicious
            } else {
                AnomalyLevel::Normal
            };
            AnomalyView {
                z_pps,
                z_bps,
                level,
                confidence: (abs_z / 10.0).min(1.0),
            }
        }
        BaselineState::Warming => AnomalyView {
            z_pps: 0.0,
            z_bps: 0.0,
            level: AnomalyLevel::Normal,
            confidence: 0.0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_baseline(
        pps_mean: f64,
        pps_stddev: f64,
        bps_mean: f64,
        bps_stddev: f64,
    ) -> BaselineState {
        use crate::baseline::{BaselineStats, ProtoBaseline};

        BaselineState::Ready {
            baseline: ProtoBaseline {
                pps: BaselineStats {
                    mean: pps_mean,
                    stddev: pps_stddev,
                },
                bps: BaselineStats {
                    mean: bps_mean,
                    stddev: bps_stddev,
                },
            },
        }
    }

    #[test]
    fn compute_anomaly_view_warming_returns_zeros() {
        let view = compute_anomaly_view(&BaselineState::Warming, 1000.0, 100_000.0);
        assert_eq!(view.z_pps, 0.0);
        assert_eq!(view.z_bps, 0.0);
        assert!(matches!(view.level, AnomalyLevel::Normal));
        assert_eq!(view.confidence, 0.0);
    }

    #[test]
    fn compute_anomaly_view_low_z_is_normal() {
        let baseline = ready_baseline(100.0, 10.0, 10_000.0, 1_000.0);
        let view = compute_anomaly_view(&baseline, 105.0, 10_500.0);
        assert!(matches!(view.level, AnomalyLevel::Normal));
    }

    #[test]
    fn compute_anomaly_view_mid_z_is_suspicious() {
        let baseline = ready_baseline(100.0, 10.0, 10_000.0, 1_000.0);
        // 4 stddev above mean -> |z| = 4, within [3, 6).
        let view = compute_anomaly_view(&baseline, 140.0, 10_000.0);
        assert!(matches!(view.level, AnomalyLevel::Suspicious));
    }

    #[test]
    fn compute_anomaly_view_high_z_is_severe() {
        let baseline = ready_baseline(100.0, 10.0, 10_000.0, 1_000.0);
        // 10 stddev above mean -> |z| = 10, >= 6.
        let view = compute_anomaly_view(&baseline, 200.0, 10_000.0);
        assert!(matches!(view.level, AnomalyLevel::Severe));
    }

    #[test]
    fn compute_anomaly_view_confidence_clamped_at_one() {
        let baseline = ready_baseline(100.0, 10.0, 10_000.0, 1_000.0);
        // 50 stddev above mean -> |z| = 50, confidence = (50/10).min(1.0) = 1.0.
        let view = compute_anomaly_view(&baseline, 600.0, 10_000.0);
        assert_eq!(view.confidence, 1.0);
    }
}
