use ebpf_xdp_program_common::ProtoIndex;

use crate::{
    alert::{AlertKind, AlertSignal},
    anomaly::{AnomalyDetector, AnomalyLevel, DetectResult},
    rate::ProtoRateSnapshot,
};

/// Per-protocol absolute rate thresholds for emergency detection.
///
/// Either `max_pps` or `max_bps` (or both) may be set. Protocols without
/// a matching threshold entry in [`EmergencyDetector`] are silently skipped.
pub struct EmergencyThreshold {
    pub proto: ProtoIndex,
    pub max_pps: Option<f64>,
    pub max_bps: Option<f64>,
}

/// Stateless emergency detector. No warmup, no EWMA state, no baseline freeze.
/// Fires `AlertKind::Emergency` immediately when any threshold is exceeded.
///
/// Confidence is computed as `(max(pps_ratio, bps_ratio) - 1.0).clamp(0, 1)`
/// where `ratio = observed / threshold`, so 2× the threshold yields confidence 1.0.
pub struct EmergencyDetector {
    thresholds: Vec<EmergencyThreshold>,
}

impl EmergencyDetector {
    /// Creates a detector with the given per-protocol thresholds.
    ///
    /// Protocols not represented in `thresholds` are never flagged.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate::{ProtoRate, ProtoRateSnapshot};

    fn snapshot(rates: Vec<ProtoRate>) -> ProtoRateSnapshot {
        ProtoRateSnapshot { rates }
    }

    fn rate(proto: ProtoIndex, pps: f64, bps: f64) -> ProtoRate {
        ProtoRate { proto, pps, bps }
    }

    #[test]
    fn emergency_no_threshold_no_signal() {
        let det = EmergencyDetector::new(vec![]);
        let result = det.detect(&snapshot(vec![rate(ProtoIndex::Tcp, 1_000_000.0, 1e12)]));
        assert!(matches!(result, DetectResult::Signals(ref s) if s.is_empty()));
    }

    #[test]
    fn emergency_under_threshold_no_signal() {
        let det = EmergencyDetector::new(vec![EmergencyThreshold {
            proto: ProtoIndex::Tcp,
            max_pps: Some(1000.0),
            max_bps: Some(100_000.0),
        }]);
        let result = det.detect(&snapshot(vec![rate(ProtoIndex::Tcp, 999.0, 99_999.0)]));
        assert!(matches!(result, DetectResult::Signals(ref s) if s.is_empty()));
    }

    #[test]
    fn emergency_pps_exceeded_fires() {
        let det = EmergencyDetector::new(vec![EmergencyThreshold {
            proto: ProtoIndex::Tcp,
            max_pps: Some(1000.0),
            max_bps: None,
        }]);
        let result = det.detect(&snapshot(vec![rate(ProtoIndex::Tcp, 1001.0, 0.0)]));
        let DetectResult::Signals(signals) = result else {
            panic!("expected DetectResult::Signals");
        };
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].proto, ProtoIndex::Tcp);
        assert_eq!(signals[0].kind, AlertKind::Emergency);
        assert_eq!(signals[0].level, AnomalyLevel::Severe);
    }

    #[test]
    fn emergency_bps_exceeded_fires() {
        let det = EmergencyDetector::new(vec![EmergencyThreshold {
            proto: ProtoIndex::Udp,
            max_pps: None,
            max_bps: Some(100_000.0),
        }]);
        let result = det.detect(&snapshot(vec![rate(ProtoIndex::Udp, 0.0, 100_001.0)]));
        let DetectResult::Signals(signals) = result else {
            panic!("expected DetectResult::Signals");
        };
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].proto, ProtoIndex::Udp);
    }

    #[test]
    fn emergency_confidence_proportional() {
        // 2× threshold → ratio = 2.0 → confidence = (2.0 - 1.0).clamp(0,1) = 1.0
        let det = EmergencyDetector::new(vec![EmergencyThreshold {
            proto: ProtoIndex::Icmp,
            max_pps: Some(500.0),
            max_bps: None,
        }]);
        let result = det.detect(&snapshot(vec![rate(ProtoIndex::Icmp, 1000.0, 0.0)]));
        let DetectResult::Signals(signals) = result else {
            panic!("expected DetectResult::Signals");
        };
        assert!(
            (signals[0].confidence - 1.0).abs() < 1e-9,
            "confidence should be 1.0 at 2× threshold"
        );
    }
}
