use std::time::Instant;

use crate::anomaly::AnomalyLevel;
use ebpf_xdp_program_common::ProtoIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertKind {
    Spike,
    Drop,
    Emergency,
}

impl AlertKind {
    pub fn label(self) -> &'static str {
        match self {
            AlertKind::Spike => "spike",
            AlertKind::Drop => "drop",
            AlertKind::Emergency => "emergency",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AlertSignal {
    pub proto: ProtoIndex,
    pub level: AnomalyLevel,
    pub kind: AlertKind,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub proto: ProtoIndex,
    pub kind: AlertKind,
    pub level: AnomalyLevel,
    pub confidence: f64,

    #[allow(dead_code)]
    pub timestamp: Instant,
}
