#![no_std]

mod estimator;
mod ewma;
mod rate;
mod zscore;

pub use estimator::{Baseline, BaselineState, BaselineStats, EwmaEstimator, ProtoBaseline};
pub use ewma::Ewma;
pub use rate::ProtoRate;
pub use zscore::compute_proto_z_scores;
