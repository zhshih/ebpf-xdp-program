use super::super::{anomaly::zscore, rate::model::ProtoRate};
use super::ewma::Ewma;
use ebpf_xdp_program_common::ProtoIndex;
use std::collections::HashMap;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Baseline {
    pub mean: f64,
    pub stddev: f64,
}

#[derive(Debug, Clone)]
pub struct ProtoBaseline {
    pub pps: Baseline,
    pub bps: Baseline,
}

#[derive(Debug)]
pub struct ProtoEwmaBaseline {
    pps: HashMap<ProtoIndex, Ewma>,
    bps: HashMap<ProtoIndex, Ewma>,
}

impl ProtoEwmaBaseline {
    pub fn new(alpha: f64) -> Self {
        let mut pps = HashMap::new();
        let mut bps = HashMap::new();

        for idx in 0..ProtoIndex::COUNT {
            let proto = ProtoIndex::from_index(idx as usize).unwrap();
            pps.insert(proto, Ewma::new(alpha));
            bps.insert(proto, Ewma::new(alpha));
        }

        Self { pps, bps }
    }

    pub fn update(&mut self, rates: &[ProtoRate]) {
        for rate in rates {
            if let Some(ewma_pps) = self.pps.get_mut(&rate.proto) {
                ewma_pps.update(rate.pps);
            }
            if let Some(ewma_bps) = self.bps.get_mut(&rate.proto) {
                ewma_bps.update(rate.bps);
            }
        }
    }

    pub fn baseline(&self, proto: ProtoIndex) -> Option<ProtoBaseline> {
        let pps = self.pps.get(&proto)?;
        let bps = self.bps.get(&proto)?;

        Some(ProtoBaseline {
            pps: Baseline {
                mean: pps.mean()?,
                stddev: pps.stddev()?,
            },
            bps: Baseline {
                mean: bps.mean()?,
                stddev: bps.stddev()?,
            },
        })
    }

    pub fn z_scores(
        &self,
        proto: ProtoIndex,
        pps: f64,
        bps: f64,
    ) -> Option<(Option<f64>, Option<f64>)> {
        let pps_ewma = self.pps.get(&proto)?;
        let bps_ewma = self.bps.get(&proto)?;

        let z_pps = zscore::z_score(pps, pps_ewma.mean()?, pps_ewma.stddev()?);
        let z_bps = zscore::z_score(bps, bps_ewma.mean()?, bps_ewma.stddev()?);

        Some((z_pps, z_bps))
    }
}
