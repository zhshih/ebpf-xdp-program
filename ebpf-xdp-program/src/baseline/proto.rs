use crate::{baseline::Ewma, rate::ProtoRate};
use ebpf_xdp_program_common::ProtoIndex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    NotEnoughSamples,
    LowVariance,
    WarmupTime,
    Ready,
}

#[derive(Debug)]
pub enum BaselineState {
    Ready { baseline: ProtoBaseline },
    Warming { reason: Readiness },
}

#[derive(Debug, Clone)]
pub struct BaselineStats {
    pub mean: f64,
    pub stddev: f64,
}

#[derive(Debug, Clone)]
pub struct ProtoBaseline {
    pub pps: BaselineStats,
    pub bps: BaselineStats,
}

impl ProtoBaseline {
    pub fn zero() -> Self {
        Self {
            pps: BaselineStats {
                mean: 0.0,
                stddev: 0.0,
            },
            bps: BaselineStats {
                mean: 0.0,
                stddev: 0.0,
            },
        }
    }
}

#[derive(Debug)]
pub struct ProtoEwmaBaselineEstimator {
    pps_ewma: HashMap<ProtoIndex, Ewma>,
    bps_ewma: HashMap<ProtoIndex, Ewma>,
    min_samples: u64,
    min_stddev: f64,
    min_elapsed: Duration,
    start_time: Instant,
}

impl ProtoEwmaBaselineEstimator {
    pub fn new(alpha: f64, min_samples: u64, min_stddev: f64, min_elapsed: Duration) -> Self {
        let mut pps = HashMap::new();
        let mut bps = HashMap::new();

        for idx in 0..ProtoIndex::COUNT {
            let proto = ProtoIndex::from_index(idx as usize).unwrap();
            pps.insert(proto, Ewma::new(alpha));
            bps.insert(proto, Ewma::new(alpha));
        }

        Self {
            pps_ewma: pps,
            bps_ewma: bps,
            min_samples,
            min_stddev,
            min_elapsed,
            start_time: Instant::now(),
        }
    }

    pub fn snapshot(&self, proto: ProtoIndex) -> BaselineState {
        let pps = self.pps_ewma.get(&proto).unwrap();
        let bps = self.bps_ewma.get(&proto).unwrap();

        let samples = pps.samples.min(bps.samples);
        let elapsed = self.start_time.elapsed();

        let baseline = ProtoBaseline {
            pps: BaselineStats {
                mean: pps.mean(),
                stddev: pps.stddev(),
            },
            bps: BaselineStats {
                mean: bps.mean(),
                stddev: bps.stddev(),
            },
        };

        if samples < self.min_samples {
            return BaselineState::Warming {
                reason: Readiness::NotEnoughSamples,
            };
        }

        if baseline.pps.stddev < self.min_stddev || baseline.bps.stddev < self.min_stddev {
            return BaselineState::Warming {
                reason: Readiness::LowVariance,
            };
        }

        if elapsed < self.min_elapsed {
            return BaselineState::Warming {
                reason: Readiness::WarmupTime,
            };
        }

        BaselineState::Ready { baseline }
    }

    pub fn update(&mut self, observed_rates: &[ProtoRate]) {
        for rate in observed_rates {
            if let Some(ewma_pps) = self.pps_ewma.get_mut(&rate.proto) {
                ewma_pps.update(rate.pps);
            }
            if let Some(ewma_bps) = self.bps_ewma.get_mut(&rate.proto) {
                ewma_bps.update(rate.bps);
            }
        }
    }

    pub fn readiness(&self, proto: ProtoIndex) -> Readiness {
        if self.start_time.elapsed() < self.min_elapsed {
            return Readiness::WarmupTime;
        }

        let pps = match self.pps_ewma.get(&proto) {
            Some(e) => e,
            None => return Readiness::NotEnoughSamples,
        };

        let bps = match self.bps_ewma.get(&proto) {
            Some(e) => e,
            None => return Readiness::NotEnoughSamples,
        };

        if pps.samples < self.min_samples || bps.samples < self.min_samples {
            return Readiness::NotEnoughSamples;
        }

        Readiness::Ready
    }
}

pub trait AnomalyBaseline {
    #[allow(dead_code)]
    fn readiness(&self, proto: ProtoIndex) -> Readiness;
    fn snapshot(&self, proto: ProtoIndex) -> BaselineState;
}

impl AnomalyBaseline for ProtoEwmaBaselineEstimator {
    fn readiness(&self, proto: ProtoIndex) -> Readiness {
        self.readiness(proto)
    }

    fn snapshot(&self, proto: ProtoIndex) -> BaselineState {
        self.snapshot(proto)
    }
}
