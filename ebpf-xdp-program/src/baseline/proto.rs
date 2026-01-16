use crate::{baseline::Ewma, rate::ProtoRate};
use ebpf_xdp_program_common::ProtoIndex;
use std::collections::HashMap;

#[allow(dead_code)]
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
pub struct ProtoEwmaBaselineEstimator {
    pps_ewma: HashMap<ProtoIndex, Ewma>,
    bps_ewma: HashMap<ProtoIndex, Ewma>,
}

impl ProtoEwmaBaselineEstimator {
    pub fn new(alpha: f64) -> Self {
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
        }
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

    pub fn is_ready(&self) -> bool {
        self.pps_ewma.values().all(|ewma| ewma.is_ready())
            && self.bps_ewma.values().all(|ewma| ewma.is_ready())
    }

    pub fn baseline(&self, proto: ProtoIndex) -> Option<ProtoBaseline> {
        let pps_ewma = self.pps_ewma.get(&proto)?;
        let bps_ewma = self.bps_ewma.get(&proto)?;

        Some(ProtoBaseline {
            pps: BaselineStats {
                mean: pps_ewma.mean()?,
                stddev: pps_ewma.stddev()?,
            },
            bps: BaselineStats {
                mean: bps_ewma.mean()?,
                stddev: bps_ewma.stddev()?,
            },
        })
    }

    pub fn z_scores(
        &self,
        proto: ProtoIndex,
        observed_pps: f64,
        observed_bps: f64,
    ) -> Option<(Option<f64>, Option<f64>)> {
        let pps_ewma = self.pps_ewma.get(&proto)?;
        let bps_ewma = self.bps_ewma.get(&proto)?;

        let z_pps = pps_ewma.robust_z_score(observed_pps);
        let z_bps = bps_ewma.robust_z_score(observed_bps);

        Some((z_pps, z_bps))
    }
}
