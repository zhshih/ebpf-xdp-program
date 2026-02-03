use crate::{
    alert::{AlertKind, AlertSignal},
    anomaly::{AnomalyDetector, AnomalyLevel, DetectResult},
    rate::ProtoRateSnapshot,
};
use ebpf_xdp_program_common::ProtoIndex;

/// Per-protocol absolute rate thresholds for emergency detection.
pub struct EmergencyThreshold {
    pub proto: ProtoIndex,
    pub max_pps: Option<f64>,
    pub max_bps: Option<f64>,
}

/// Stateless emergency detector. No warmup, no EWMA state, no baseline freeze.
/// Fires `AlertKind::Emergency` immediately when any threshold is exceeded.
pub struct EmergencyDetector {
    thresholds: Vec<EmergencyThreshold>,
}

impl EmergencyDetector {
    pub fn new(thresholds: Vec<EmergencyThreshold>) -> Self {
        Self { thresholds }
    }
}

impl AnomalyDetector for EmergencyDetector {
    fn detect(&self, snapshot: &ProtoRateSnapshot) -> DetectResult {
        let mut signals = Vec::new();

        for rate in &snapshot.rates {
            let Some(t) = self.thresholds.iter().find(|t| t.proto == rate.proto) else {
                continue;
            };

            let pps_exceeded = t.max_pps.is_some_and(|l| rate.pps > l);
            let bps_exceeded = t.max_bps.is_some_and(|l| rate.bps > l);

            if pps_exceeded || bps_exceeded {
                let pps_ratio = t
                    .max_pps
                    .filter(|&l| l > 0.0)
                    .map(|l| rate.pps / l)
                    .unwrap_or(0.0);
                let bps_ratio = t
                    .max_bps
                    .filter(|&l| l > 0.0)
                    .map(|l| rate.bps / l)
                    .unwrap_or(0.0);
                let confidence = (pps_ratio.max(bps_ratio) - 1.0).clamp(0.0, 1.0);

                tracing::info!(
                    proto = ?rate.proto,
                    pps = rate.pps,
                    bps = rate.bps,
                    pps_threshold = ?t.max_pps,
                    bps_threshold = ?t.max_bps,
                    confidence,
                    "emergency threshold exceeded"
                );

                signals.push(AlertSignal {
                    proto: rate.proto,
                    level: AnomalyLevel::Severe,
                    kind: AlertKind::Emergency,
                    confidence,
                });
            }
        }

        DetectResult::Signals(signals)
    }
}
