use ebpf_xdp_program_common::ProtoIndex;
use std::time::Instant;

#[derive(Default, Clone)]
pub struct TrafficCounters {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone)]
pub struct TrafficCountersSnapshot {
    pub timestamp: Instant,
    pub stats: Vec<TrafficCounters>,
}

#[derive(Debug, Clone)]
pub struct ProtoRate {
    pub proto: ProtoIndex,
    pub pps: f64,
    pub bps: f64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProtoRateSnapshot {
    pub timestamp: Instant,
    pub rates: Vec<ProtoRate>,
}
