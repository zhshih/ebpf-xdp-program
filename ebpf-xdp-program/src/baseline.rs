pub mod ewma;
pub mod proto;

pub use ewma::Ewma;
pub use proto::{ProtoBaseline, ProtoEwmaBaselineEstimator};
