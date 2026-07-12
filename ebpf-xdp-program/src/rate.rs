//! Per-protocol traffic rate computation and snapshot management.
//!
//! [`TrafficCountersSnapshot`] captures raw cumulative packet/byte counters read
//! from the BPF map. [`diff_stats`] converts two consecutive snapshots into
//! per-protocol deltas; [`compute_rates`] then normalises them into
//! [`ProtoRate`] (pps/bps) values for use by the anomaly pipeline.
//!
//! File layout follows the same boundary-crossing rule as `crate::alert`/
//! `crate::anomaly`/`crate::api`: a type belongs in `model.rs` only if it
//! crosses a producer/consumer or module boundary. `model.rs` holds
//! [`TrafficCounters`]/[`TrafficCountersSnapshot`]/[`ProtoRate`] and
//! [`SynCountersSnapshot`]/[`SynIpRate`] — every one of them is produced
//! here and consumed by a genuinely different component (`pipeline`,
//! `anomaly`, `metrics`, `api`; `ProtoRate` even crosses into the sibling
//! `ewma-detector` crate). `compute.rs`/`synflood_compute.rs` hold only the
//! logic that produces them, split by which BPF map shape they read: a
//! fixed 5-entry `ProtoIndex` array (`compute.rs`) vs. an unbounded
//! per-source-IP map (`synflood_compute.rs`, see its own doc comment).
pub mod compute;
pub mod model;
pub mod synflood_compute;

pub use compute::{compute_mix, compute_rates, diff_stats, read_snapshot};
pub use model::{ProtoRate, SynCountersSnapshot, SynIpRate, TrafficCountersSnapshot};
pub use synflood_compute::{compute_syn_rates_top_n, read_syn_snapshot};

/// Elapsed time between two snapshot timestamps, in seconds. `None` for a
/// non-positive interval (e.g. a clock adjustment), so callers can bail out
/// rather than dividing by ~0.
pub(super) fn dt_secs(prev: std::time::Instant, curr: std::time::Instant) -> Option<f64> {
    let dt = curr.duration_since(prev).as_secs_f64();
    (dt > 0.0).then_some(dt)
}

/// Saturating counter delta converted to a per-second rate.
pub(super) fn rate(curr: u64, prev: u64, dt: f64) -> f64 {
    curr.saturating_sub(prev) as f64 / dt
}
