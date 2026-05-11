//! Anomaly detection — Z-score analysis and emergency threshold checks.
//!
//! Two independent detectors feed the pipeline:
//! - [`EwmaDetector`]: computes per-protocol Z-scores against the EWMA baseline.
//!   Returns [`DetectResult::WarmingUp`] until the baseline is ready.
//! - [`EmergencyDetector`]: fires immediately when an absolute rate threshold is
//!   exceeded, regardless of baseline state.
//!
//! Both implement [`AnomalyDetector`] and produce [`AlertSignal`]s consumed by
//! the alert manager.
pub mod detector;
pub mod emergency;
pub mod ewma;
mod zscore;

pub use detector::{AnomalyDetector, AnomalyLevel, DetectResult};
pub use emergency::{EmergencyDetector, EmergencyThreshold};
pub use ewma::EwmaDetector;
pub use zscore::compute_proto_z_scores;
