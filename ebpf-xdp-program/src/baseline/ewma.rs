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

    pub fn new(alpha: f64) -> Self {
        Self {
            alpha,
            mean: 0.0,
            variance: 0.0,
            mad: 0.0,
            samples: 0,
        }
    }

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

    pub fn mean(&self) -> f64 {
        self.mean
    }

    pub fn stddev(&self) -> f64 {
        self.variance.sqrt().max(Self::EPSILON)
    }

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
