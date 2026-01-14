use crate::stats::anomaly::zscore::robust_z_score_clipped;
use std::time::{Duration, Instant};

const MIN_SAMPLES: u64 = 5;
const MIN_ELAPSED: Duration = Duration::from_secs(10);
const MIN_STDDEV: f64 = 1e-6;

#[derive(Debug, Clone)]
pub struct Ewma {
    pub alpha: f64,
    pub mean: f64,
    pub variance: f64,
    pub mad: f64,
    pub initialized: bool,
    pub sample_count: u64,
    pub start_time: Option<Instant>,
}

impl Ewma {
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha,
            mean: 0.0,
            variance: 0.0,
            mad: 0.0,
            initialized: false,
            sample_count: 0,
            start_time: None,
        }
    }

    pub fn update(&mut self, sample: f64) {
        let now = Instant::now();

        if !self.initialized {
            self.mean = sample;
            self.variance = 0.0;
            self.mad = 0.0;
            self.initialized = true;
            self.sample_count = 1;
            self.start_time = Some(now);
            return;
        }

        self.sample_count += 1;

        let delta = sample - self.mean;

        let scale = self.robust_stddev().unwrap_or(1.0);
        let bounded_delta = huber(delta, scale, 3.0);

        self.mean += self.alpha * bounded_delta;
        self.variance =
            (1.0 - self.alpha) * self.variance + self.alpha * bounded_delta * bounded_delta;

        let abs_dev = (sample - self.mean).abs();
        self.mad = (1.0 - self.alpha) * self.mad + self.alpha * abs_dev;
    }

    pub fn is_ready(&self) -> bool {
        if !self.initialized {
            return false;
        }

        if self.sample_count < MIN_SAMPLES {
            return false;
        }

        let elapsed_ok = self
            .start_time
            .map(|t| t.elapsed() >= MIN_ELAPSED)
            .unwrap_or(false);

        if !elapsed_ok {
            return false;
        }

        if self.variance < MIN_STDDEV {
            return true;
        }

        self.variance.sqrt() > MIN_STDDEV
    }

    pub fn mean(&self) -> Option<f64> {
        self.is_ready().then_some(self.mean)
    }

    pub fn stddev(&self) -> Option<f64> {
        self.is_ready().then_some(self.variance.sqrt())
    }

    pub fn robust_stddev(&self) -> Option<f64> {
        if !self.is_ready() {
            return None;
        }

        let mad_sigma = 1.4826 * self.mad;
        let var_sigma = self.variance.sqrt();

        let sigma = mad_sigma.max(var_sigma * 0.25);

        (sigma > MIN_STDDEV).then_some(sigma)
    }

    // This is the ONLY entry point for anomaly z-scores.
    // All robustness, gating, and clipping is enforced here.
    pub fn robust_z_score(&self, value: f64) -> Option<f64> {
        let mean = self.mean()?;
        let stddev = self.robust_stddev()?;
        robust_z_score_clipped(value, mean, stddev)
    }
}

fn huber(delta: f64, scale: f64, k: f64) -> f64 {
    let limit = k * scale;
    delta.clamp(-limit, limit)
}
