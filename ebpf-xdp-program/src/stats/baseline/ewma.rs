#[derive(Debug, Clone)]
pub struct Ewma {
    pub alpha: f64,
    pub mean: f64,
    pub variance: f64,
    pub initialized: bool,
}

impl Ewma {
    pub fn new(alpha: f64) -> Self {
        Self {
            alpha,
            mean: 0.0,
            variance: 0.0,
            initialized: false,
        }
    }

    pub fn update(&mut self, sample: f64) {
        if !self.initialized {
            self.mean = sample;
            self.variance = 0.0;
            self.initialized = true;
            return;
        }

        let delta = sample - self.mean;
        self.mean += self.alpha * delta;
        self.variance = (1.0 - self.alpha) * self.variance + self.alpha * delta * delta;
    }

    pub fn mean(&self) -> Option<f64> {
        self.initialized.then_some(self.mean)
    }

    pub fn stddev(&self) -> Option<f64> {
        self.initialized.then_some(self.variance.sqrt())
    }
}
