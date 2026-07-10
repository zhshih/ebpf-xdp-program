//! Per-protocol traffic rate computation and snapshot management.
//!
//! [`TrafficCountersSnapshot`] captures raw cumulative packet/byte counters read
//! from the BPF map. [`diff_stats`] converts two consecutive snapshots into
//! per-protocol deltas; [`compute_rates`] then normalises them into
//! [`ProtoRate`] (pps/bps) values for use by the anomaly pipeline.
pub mod compute;
pub mod model;
pub mod synflood;

pub use compute::{compute_mix, compute_rates, diff_stats, read_snapshot};
pub use model::{ProtoRate, TrafficCountersSnapshot};
pub use synflood::{SynCountersSnapshot, SynIpRate, compute_syn_rates_top_n, read_syn_snapshot};

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
