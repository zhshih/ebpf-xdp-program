use ebpf_xdp_program_common::ProtoIndex;

/// Per-protocol traffic rates derived from two consecutive counter snapshots.
#[derive(Debug, Clone)]
pub struct ProtoRate {
    pub proto: ProtoIndex,
    /// Packets per second observed in the last interval.
    pub pps: f64,
    /// Bytes per second observed in the last interval.
    pub bps: f64,
}
