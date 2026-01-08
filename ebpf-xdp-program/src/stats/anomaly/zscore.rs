pub fn z_score(value: f64, mean: f64, stddev: f64) -> Option<f64> {
    if stddev <= 0.0 {
        None
    } else {
        Some((value - mean) / stddev)
    }
}
