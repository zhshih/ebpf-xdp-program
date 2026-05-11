//! Per-protocol traffic rate computation and snapshot management.
//!
//! [`TrafficCountersSnapshot`] captures raw cumulative packet/byte counters read
//! from the BPF map. [`diff_stats`] converts two consecutive snapshots into
//! per-protocol deltas; [`compute_rates`] then normalises them into
//! [`ProtoRate`] (pps/bps) values for use by the anomaly pipeline.
pub mod compute;
pub mod model;

pub use compute::{compute_mix, compute_rates, diff_stats, read_snapshot};
pub use model::{ProtoRate, ProtoRateSnapshot, TrafficCountersSnapshot};
