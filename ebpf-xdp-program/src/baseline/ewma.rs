/// Online Exponential Weighted Moving Average estimator with robust variance tracking.
///
/// Tracks mean, variance (EWMA of squared deviations), and MAD (mean absolute deviation)
/// simultaneously. Updates are Huber-clipped (k=3) to resist outlier contamination of
/// the baseline, which is critical for accurate anomaly detection.
#[derive(Debug, Clone)]
pub struct Ewma {
    pub alpha: f64,
    pub mean: f64,
    pub variance: f64,
    pub mad: f64,
    pub samples: u64,
}

#[allow(dead_code)]
impl Ewma {
    const EPSILON: f64 = 1e-9;

    /// Creates a new EWMA with the given smoothing factor.
    ///
    /// `alpha` controls adaptation speed: values in (0, 1], higher = faster.
    /// Typical values: 0.1 (slow/stable) to 0.4 (fast/reactive).
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha,
            mean: 0.0,
            variance: 0.0,
            mad: 0.0,
            samples: 0,
        }
    }

    /// Incorporates a new observation into the running estimates.
    ///
    /// The update is Huber-clipped: deviations beyond `3 * robust_stddev` are clamped,
    /// preventing a single large spike from permanently skewing the baseline mean.
    pub fn update(&mut self, sample: f64) {
        self.samples += 1;

        let prev_mean = self.mean;
        let delta = sample - prev_mean;

        let scale = self.robust_stddev();
        let bounded_delta = huber(delta, scale, 3.0);

        self.mean = prev_mean + self.alpha * bounded_delta;

        self.variance =
            (1.0 - self.alpha) * self.variance + self.alpha * bounded_delta * bounded_delta;

        let abs_dev = (sample - prev_mean).abs();
        self.mad = (1.0 - self.alpha) * self.mad + self.alpha * abs_dev;
    }

    /// Current EWMA mean estimate.
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Standard deviation derived from EWMA variance. Floor is `EPSILON` to avoid division by zero.
    pub fn stddev(&self) -> f64 {
        self.variance.sqrt().max(Self::EPSILON)
    }

    /// Robust standard deviation: `max(1.4826 * MAD, 0.25 * σ, EPSILON)`.
    ///
    /// The MAD-based estimate is more resistant to outliers than pure variance.
    /// Used internally to scale the Huber clipping window.
    pub fn robust_stddev(&self) -> f64 {
        let mad_sigma = 1.4826 * self.mad;
        let var_sigma = self.variance.sqrt();
        mad_sigma.max(var_sigma * 0.25).max(Self::EPSILON)
    }
}

fn huber(delta: f64, scale: f64, k: f64) -> f64 {
    let limit = k * scale;
    delta.clamp(-limit, limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPSILON: f64 = 1e-9;

    #[test]
    fn ewma_new_is_zero() {
        let e = Ewma::new(0.4);
        assert_eq!(e.mean, 0.0);
        assert_eq!(e.variance, 0.0);
        assert_eq!(e.mad, 0.0);
        assert_eq!(e.samples, 0);
    }

    #[test]
    fn ewma_single_update_moves_mean() {
        let mut e = Ewma::new(0.4);
        e.update(100.0);
        // After one update from 0, mean should move toward 100
        assert!(e.mean > 0.0, "mean should shift toward sample");
        assert!(e.mean < 100.0, "mean should not jump to sample in one step");
        assert_eq!(e.samples, 1);
    }

    #[test]
    fn ewma_mean_converges() {
        let mut e = Ewma::new(0.4);
        for _ in 0..100 {
            e.update(50.0);
        }
        assert!(
            (e.mean - 50.0).abs() < 0.01,
            "mean should converge to 50.0, got {}",
            e.mean
        );
    }

    #[test]
    fn ewma_stddev_floor() {
        let e = Ewma::new(0.4);
        assert!(e.stddev() >= EPSILON, "stddev must have a floor of EPSILON");
    }

    #[test]
    fn ewma_robust_stddev_floor() {
        let e = Ewma::new(0.4);
        assert!(
            e.robust_stddev() >= EPSILON,
            "robust_stddev must have a floor of EPSILON"
        );
    }

    #[test]
    fn ewma_huber_clips_outlier() {
        let mut e = Ewma::new(0.4);
        // Establish a stable baseline around 1.0
        for _ in 0..100 {
            e.update(1.0);
        }
        let mean_before = e.mean;
        // Inject a massive outlier
        e.update(10_000.0);
        let mean_after = e.mean;
        // Huber clipping should keep the mean from jumping far from 1.0
        assert!(
            (mean_after - mean_before).abs() < 5.0,
            "Huber clipping should resist outlier; mean jumped from {} to {}",
            mean_before,
            mean_after
        );
    }

    #[test]
    fn ewma_variance_increases_with_spread() {
        let mut e_const = Ewma::new(0.4);
        let mut e_spread = Ewma::new(0.4);

        for i in 0..50 {
            e_const.update(10.0);
            e_spread.update(if i % 2 == 0 { 1.0 } else { 100.0 });
        }

        assert!(
            e_spread.variance > e_const.variance,
            "spread input should produce higher variance than constant input"
        );
    }
}
