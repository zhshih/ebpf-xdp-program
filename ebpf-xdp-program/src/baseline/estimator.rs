use crate::{baseline::Ewma, rate::ProtoRate};
use ebpf_xdp_program_common::ProtoIndex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum BaselineState {
    Ready { baseline: ProtoBaseline },
    Warming,
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

#[derive(Debug)]
pub struct EwmaEstimator {
    pps_ewma: HashMap<ProtoIndex, Ewma>,
    bps_ewma: HashMap<ProtoIndex, Ewma>,
    min_samples: u64,
    min_stddev: f64,
    min_elapsed: Duration,
    start_time: Instant,
}

impl EwmaEstimator {
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

        if samples < self.min_samples
            || baseline.pps.stddev < self.min_stddev
            || baseline.bps.stddev < self.min_stddev
            || elapsed < self.min_elapsed
        {
            tracing::trace!(
                proto = ?proto,
                samples = samples,
                min_samples = self.min_samples,
                pps_stddev = baseline.pps.stddev,
                bps_stddev = baseline.bps.stddev,
                min_stddev = self.min_stddev,
                elapsed_secs = elapsed.as_secs(),
                min_elapsed_secs = self.min_elapsed.as_secs(),
                "baseline warming"
            );
            return BaselineState::Warming;
        }

        tracing::debug!(
            proto = ?proto,
            pps_mean = baseline.pps.mean,
            pps_stddev = baseline.pps.stddev,
            bps_mean = baseline.bps.mean,
            bps_stddev = baseline.bps.stddev,
            samples = samples,
            "baseline ready"
        );
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
}

pub trait Baseline {
    fn snapshot(&self, proto: ProtoIndex) -> BaselineState;
}

impl Baseline for EwmaEstimator {
    fn snapshot(&self, proto: ProtoIndex) -> BaselineState {
        self.snapshot(proto)
    }
}
