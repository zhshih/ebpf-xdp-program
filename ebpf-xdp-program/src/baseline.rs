//! EWMA-based traffic baseline estimation.
//!
//! [`EwmaEstimator`] maintains one EWMA per `(protocol, dimension)` pair and
//! gatekeeps readiness: a protocol's baseline is [`BaselineState::Ready`] only when
//! it has accumulated enough samples, sufficient variance, and enough wall-clock time.
//! Until then, anomaly detection is suppressed for that protocol.
pub use ewma_detector::{Baseline, BaselineState, BaselineStats, EwmaEstimator, ProtoBaseline};
