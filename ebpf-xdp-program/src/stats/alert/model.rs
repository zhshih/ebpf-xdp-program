use crate::stats::anomaly::classifier::AnomalyLevel;
use ebpf_xdp_program_common::ProtoIndex;

#[derive(Debug, Clone)]
pub enum AlertKind {
    TrafficSpike,
    TrafficDrop,
    TrafficAnomaly,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub proto: ProtoIndex,
    pub level: AnomalyLevel,
    pub kind: AlertKind,
    pub confidence: f64,
}
