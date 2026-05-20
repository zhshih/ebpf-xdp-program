use std::time::Instant;

use ebpf_xdp_program_common::ProtoIndex;

/// Raw cumulative packet and byte counters for one protocol bucket.
///
/// These are monotonically increasing totals read from the BPF map
/// after summing across all CPU cores.
#[derive(Default, Clone)]
pub struct TrafficCounters {
    pub packets: u64,
    pub bytes: u64,
}

/// A timestamped snapshot of cumulative counters for all five protocol buckets.
///
/// Consecutive snapshots are diffed to compute per-interval deltas.
#[derive(Clone)]
pub struct TrafficCountersSnapshot {
    pub timestamp: Instant,
    pub stats: Vec<TrafficCounters>,
}

/// Per-protocol traffic rates derived from two consecutive counter snapshots.
#[derive(Debug, Clone)]
pub struct ProtoRate {
    pub proto: ProtoIndex,
    /// Packets per second observed in the last interval.
    pub pps: f64,
    /// Bytes per second observed in the last interval.
    pub bps: f64,
}
