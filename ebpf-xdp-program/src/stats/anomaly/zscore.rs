// NOTE:
// These functions are pure math utilities.
// They must NOT be used directly for anomaly decisions.
// Use Ewma::robust_z_score instead.

const Z_CLIP: f64 = 10.0;

#[allow(dead_code)]
pub fn z_score(value: f64, mean: f64, stddev: f64) -> Option<f64> {
    if stddev <= 0.0 {
        None
    } else {
        Some(z_score_raw(value, mean, stddev))
    }
}

pub fn robust_z_score_clipped(value: f64, mean: f64, stddev: f64) -> Option<f64> {
    if stddev <= 0.0 {
        return None;
    }

    let z = z_score_raw(value, mean, stddev);
    Some(z.clamp(-Z_CLIP, Z_CLIP))
}

fn z_score_raw(value: f64, mean: f64, stddev: f64) -> f64 {
    (value - mean) / stddev
}
