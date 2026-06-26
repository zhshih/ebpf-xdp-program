/// Mean and standard deviation for a single metric dimension (pps or bps).
#[derive(Debug, Clone)]
pub struct BaselineStats {
    pub mean: f64,
    pub stddev: f64,
}

/// EWMA-based baseline statistics for a single protocol, covering both
/// packet rate (pps) and bit rate (bps) dimensions independently.
#[derive(Debug, Clone)]
pub struct ProtoBaseline {
    pub pps: BaselineStats,
    pub bps: BaselineStats,
}
