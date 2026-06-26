use std::time::Instant;

pub use ewma_detector::ProtoRate;

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
