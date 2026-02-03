use crate::{alert::AlertSignal, rate::ProtoRateSnapshot};

pub enum DetectResult {
    WarmingUp,
    Signals(Vec<AlertSignal>),
}

pub trait AnomalyDetector {
    fn detect(&self, snapshot: &ProtoRateSnapshot) -> DetectResult;
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq)]
pub enum AnomalyLevel {
    Normal,
    Suspicious,
    Severe,
}

impl AnomalyLevel {
    pub fn is_normal(&self) -> bool {
        matches!(self, AnomalyLevel::Normal)
    }
}
