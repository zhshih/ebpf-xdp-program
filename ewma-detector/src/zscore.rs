// NOTE:
// These functions are pure math utilities.
// They must NOT be used directly for anomaly decisions.
// Use Ewma::robust_z_score instead.
use crate::estimator::ProtoBaseline;

const EPSILON: f64 = 1e-9;

/// Computes `(z_pps, z_bps)` for an observed rate against a protocol baseline.
///
/// Returns `(0.0, 0.0)` when either stddev is too small — a safe default
/// that prevents false anomaly signals during the warmup period.
pub fn compute_proto_z_scores(
    baseline: &ProtoBaseline,
    observed_pps: f64,
    observed_bps: f64,
) -> (f64, f64) {
    let z_pps = z_score(observed_pps, baseline.pps.mean, baseline.pps.stddev).unwrap_or(0.0);

    let z_bps = z_score(observed_bps, baseline.bps.mean, baseline.bps.stddev).unwrap_or(0.0);

    (z_pps, z_bps)
}

fn z_score_raw(value: f64, mean: f64, stddev: f64) -> f64 {
    (value - mean) / stddev
}

fn z_score(value: f64, mean: f64, stddev: f64) -> Option<f64> {
    if stddev <= EPSILON {
        None
    } else {
        Some(z_score_raw(value, mean, stddev))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::estimator::BaselineStats;

    const Z_CLIP: f64 = 10.0;

    /// Computes a z-score clipped to `[-Z_CLIP, Z_CLIP]`.
    ///
    /// Returns `None` when `stddev <= EPSILON` to signal that the distribution is
    /// too narrow to produce meaningful scores (e.g., no data yet).
    fn robust_z_score_clipped(value: f64, mean: f64, stddev: f64) -> Option<f64> {
        if stddev <= EPSILON {
            return None;
        }
        let z = (value - mean) / stddev;
        Some(z.clamp(-Z_CLIP, Z_CLIP))
    }

    fn make_baseline(
        pps_mean: f64,
        pps_stddev: f64,
        bps_mean: f64,
        bps_stddev: f64,
    ) -> ProtoBaseline {
        ProtoBaseline {
            pps: BaselineStats {
                mean: pps_mean,
                stddev: pps_stddev,
            },
            bps: BaselineStats {
                mean: bps_mean,
                stddev: bps_stddev,
            },
        }
    }

    #[test]
    fn z_score_zero_stddev_returns_zero() {
        // EPSILON stddev is considered too small → falls back to 0.0
        let baseline = make_baseline(100.0, EPSILON, 10_000.0, EPSILON);
        let (z_pps, z_bps) = compute_proto_z_scores(&baseline, 200.0, 20_000.0);
        assert_eq!(z_pps, 0.0);
        assert_eq!(z_bps, 0.0);
    }

    #[test]
    fn z_score_exact_mean_is_zero() {
        let baseline = make_baseline(100.0, 10.0, 10_000.0, 1_000.0);
        let (z_pps, z_bps) = compute_proto_z_scores(&baseline, 100.0, 10_000.0);
        assert!(
            (z_pps).abs() < 1e-9,
            "value == mean should give z=0, got {}",
            z_pps
        );
        assert!(
            (z_bps).abs() < 1e-9,
            "value == mean should give z=0, got {}",
            z_bps
        );
    }

    #[test]
    fn z_score_above_mean() {
        let baseline = make_baseline(100.0, 10.0, 0.0, 1.0);
        let (z_pps, _) = compute_proto_z_scores(&baseline, 130.0, 0.0);
        assert!((z_pps - 3.0).abs() < 1e-9, "expected z=3.0, got {}", z_pps);
    }

    #[test]
    fn z_score_below_mean() {
        let baseline = make_baseline(100.0, 10.0, 0.0, 1.0);
        let (z_pps, _) = compute_proto_z_scores(&baseline, 70.0, 0.0);
        assert!(
            (z_pps - (-3.0)).abs() < 1e-9,
            "expected z=-3.0, got {}",
            z_pps
        );
    }

    #[test]
    fn robust_z_clipped_returns_none_low_stddev() {
        assert_eq!(robust_z_score_clipped(100.0, 50.0, 0.0), None);
        assert_eq!(robust_z_score_clipped(100.0, 50.0, EPSILON), None);
    }

    #[test]
    fn robust_z_clipped_clamps_at_10() {
        // z = (10000 - 0) / 1 = 10000, should be clamped to 10
        let result = robust_z_score_clipped(10_000.0, 0.0, 1.0).unwrap();
        assert!(
            (result - 10.0).abs() < 1e-9,
            "should be clamped to 10, got {}",
            result
        );
    }
}
