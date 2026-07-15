use std::{collections::HashMap, net::Ipv4Addr, time::Instant};

use ebpf_xdp_program_common::{PortScanKey, PortTouch, SynCounter};
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

/// A full read of the live `SYN_TRACKER` map's contents at one point in time.
#[derive(Clone)]
pub struct SynCountersSnapshot {
    pub timestamp: Instant,
    pub counters: HashMap<u32, SynCounter>,
}

/// One source IP's SYN rate for the interval between two snapshots.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynIpRate {
    pub src_ip: Ipv4Addr,
    pub pps: f64,
}

/// A full read of the live `PORT_SCAN_TRACKER` map's contents at one point
/// in time, plus the `CLOCK_MONOTONIC` timestamp it was read at — see
/// `rate::port_scan_compute`'s module doc for why the two are comparable.
#[derive(Clone)]
pub struct PortScanCountersSnapshot {
    pub now_ns: u64,
    pub touches: HashMap<PortScanKey, PortTouch>,
}

/// One source IP's distinct-destination-port count within the current
/// detection window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortScanIpBreadth {
    pub src_ip: Ipv4Addr,
    pub distinct_ports: u32,
}
