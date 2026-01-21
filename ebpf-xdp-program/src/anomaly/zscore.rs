// NOTE:
// These functions are pure math utilities.
// They must NOT be used directly for anomaly decisions.
// Use Ewma::robust_z_score instead.
use crate::baseline::ProtoBaseline;

const EPSILON: f64 = 1e-9;

#[allow(dead_code)]
const Z_CLIP: f64 = 10.0;

#[allow(dead_code)]
pub fn robust_z_score_clipped(value: f64, mean: f64, stddev: f64) -> Option<f64> {
    if stddev <= EPSILON {
        return None;
    }

    let z = z_score_raw(value, mean, stddev);
    Some(z.clamp(-Z_CLIP, Z_CLIP))
}

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
