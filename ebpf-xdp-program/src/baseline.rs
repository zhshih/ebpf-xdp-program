//! EWMA-based traffic baseline estimation.
//!
//! [`EwmaEstimator`] maintains one EWMA per `(protocol, dimension)` pair and
//! gatekeeps readiness: a protocol's baseline is [`BaselineState::Ready`] only when
//! it has accumulated enough samples, sufficient variance, and enough wall-clock time.
//! Until then, anomaly detection is suppressed for that protocol.
pub use ewma_detector::{Baseline, BaselineState, EwmaEstimator};
// Only consumed by `anomaly/ewma.rs`'s test module today (mock baseline construction);
// re-exported here for API symmetry with `Baseline`/`BaselineState` above. Not unused in
// spirit, just not yet reached by any non-test code path.
#[cfg_attr(not(test), allow(unused_imports))]
pub use ewma_detector::{BaselineStats, ProtoBaseline};
