use ewma_detector::compute_proto_z_scores;

use crate::{
    alert::{AlertKind, AlertSignal},
    anomaly::{AnomalyDetector, AnomalyLevel, DetectResult},
    baseline::{Baseline, BaselineState},
    rate::ProtoRate,
};

/// EWMA-backed anomaly detector that computes per-protocol z-scores against a live baseline.
///
/// Borrows a [`Baseline`] implementation to keep the detector stateless and
/// the lifetime explicit — the baseline must outlive the detector.
pub struct EwmaDetector<'a, B: Baseline> {
    baseline: &'a B,
}

impl<'a, B: Baseline> EwmaDetector<'a, B> {
    /// Creates a detector backed by the provided baseline reference.
    pub fn new(baseline: &'a B) -> Self {
        Self { baseline }
    }
}

impl<'a, B: Baseline> AnomalyDetector for EwmaDetector<'a, B> {
    fn detect(&self, rates: &[ProtoRate]) -> DetectResult {
        let mut signals = Vec::new();
        let mut any_ready = false;

        for rate in rates {
            let baseline_state = self.baseline.snapshot(rate.proto);

            let (anomaly_level, z_pps, z_bps) = match baseline_state {
                BaselineState::Ready {
                    baseline: proto_baseline,
                } => {
                    any_ready = true;
                    let (z_pps, z_bps) =
                        compute_proto_z_scores(&proto_baseline, rate.pps, rate.bps);
                    let level = match (anomaly_level_from_z(z_pps), anomaly_level_from_z(z_bps)) {
                        (AnomalyLevel::Severe, _) | (_, AnomalyLevel::Severe) => {
                            AnomalyLevel::Severe
                        }
                        (AnomalyLevel::Suspicious, _) | (_, AnomalyLevel::Suspicious) => {
                            AnomalyLevel::Suspicious
                        }
                        _ => AnomalyLevel::Normal,
                    };
                    (level, Some(z_pps), Some(z_bps))
                }
                BaselineState::Warming => (AnomalyLevel::Normal, None, None),
            };

            if anomaly_level.is_normal() {
                continue;
            }

            tracing::info!(
                "detecting anomaly for proto {:?}: level={:?}, z_pps={:?}, z_bps={:?}",
                rate.proto,
                anomaly_level,
                z_pps,
                z_bps,
            );

            let dominant_z = match (z_pps, z_bps) {
                (Some(zp), Some(zb)) => Some(if zp.abs() >= zb.abs() { zp } else { zb }),
                (Some(z), None) | (None, Some(z)) => Some(z),
                _ => None,
            };
            let confidence = {
                let pps = z_pps.map(f64::abs).unwrap_or(0.0);
                let bps = z_bps.map(f64::abs).unwrap_or(0.0);
                (pps.max(bps) / 10.0).min(1.0)
            };
            let kind = match dominant_z {
                Some(z) if z >= 0.0 => AlertKind::Spike,
                Some(_) => AlertKind::Drop,
                None => AlertKind::Spike,
            };

            tracing::info!(
                "generated alert signal for proto {:?}: level={:?}, z={:?}, confidence={}",
                rate.proto,
                anomaly_level,
                dominant_z,
                confidence,
            );

            signals.push(AlertSignal {
                proto: rate.proto,
                level: anomaly_level,
                kind,
                confidence,
            });
        }

        if any_ready {
            DetectResult::Signals(signals)
        } else {
            DetectResult::WarmingUp
        }
    }
}

fn anomaly_level_from_z(z: f64) -> AnomalyLevel {
    let a = z.abs();
    if a < 3.0 {
        AnomalyLevel::Normal
    } else if a < 6.0 {
        AnomalyLevel::Suspicious
    } else {
        AnomalyLevel::Severe
    }
}

#[cfg(test)]
mod tests {
    use ebpf_xdp_program_common::ProtoIndex;

    use super::*;
    use crate::{
        baseline::{Baseline, BaselineState, BaselineStats, ProtoBaseline},
        rate::ProtoRate,
    };

    // ── Test doubles ─────────────────────────────────────────────────────────

    struct MockBaseline {
        mean_pps: f64,
        stddev_pps: f64,
        mean_bps: f64,
        stddev_bps: f64,
    }

    impl Baseline for MockBaseline {
        fn snapshot(&self, _proto: ProtoIndex) -> BaselineState {
            BaselineState::Ready {
                baseline: ProtoBaseline {
                    pps: BaselineStats {
                        mean: self.mean_pps,
                        stddev: self.stddev_pps,
                    },
                    bps: BaselineStats {
                        mean: self.mean_bps,
                        stddev: self.stddev_bps,
                    },
                },
            }
        }
    }

    struct WarmingBaseline;

    impl Baseline for WarmingBaseline {
        fn snapshot(&self, _proto: ProtoIndex) -> BaselineState {
            BaselineState::Warming
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn rates(rates: Vec<ProtoRate>) -> Vec<ProtoRate> {
        rates
    }

    fn rate(proto: ProtoIndex, pps: f64, bps: f64) -> ProtoRate {
        ProtoRate { proto, pps, bps }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn warming_up_returns_warming_up() {
        let baseline = WarmingBaseline;
        let det = EwmaDetector::new(&baseline);
        let result = det.detect(&rates(vec![rate(ProtoIndex::Tcp, 100.0, 10_000.0)]));
        assert!(matches!(result, DetectResult::WarmingUp));
    }

    #[test]
    fn drop_suspicious_signal() {
        // mean=100, stddev=10, observed_pps=60  →  z_pps = (60-100)/10 = -4.0  →  Suspicious Drop
        let baseline = MockBaseline {
            mean_pps: 100.0,
            stddev_pps: 10.0,
            mean_bps: 0.0,
            stddev_bps: 1e-10,
        };
        let det = EwmaDetector::new(&baseline);
        let result = det.detect(&rates(vec![rate(ProtoIndex::Tcp, 60.0, 0.0)]));
        let DetectResult::Signals(signals) = result else {
            panic!("expected DetectResult::Signals");
        };
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].proto, ProtoIndex::Tcp);
        assert!(matches!(signals[0].kind, AlertKind::Drop));
        assert!(matches!(signals[0].level, AnomalyLevel::Suspicious));
        // confidence = |z_pps| / 10.0 = 4.0 / 10.0 = 0.4
        assert!(
            (signals[0].confidence - 0.4).abs() < 1e-9,
            "expected confidence=0.4, got {}",
            signals[0].confidence
        );
    }

    #[test]
    fn drop_severe_signal() {
        // mean=100, stddev=10, observed_pps=0  →  z_pps = (0-100)/10 = -10.0  →  Severe Drop
        let baseline = MockBaseline {
            mean_pps: 100.0,
            stddev_pps: 10.0,
            mean_bps: 0.0,
            stddev_bps: 1e-10,
        };
        let det = EwmaDetector::new(&baseline);
        let result = det.detect(&rates(vec![rate(ProtoIndex::Icmp, 0.0, 0.0)]));
        let DetectResult::Signals(signals) = result else {
            panic!("expected DetectResult::Signals");
        };
        assert_eq!(signals.len(), 1);
        assert!(matches!(signals[0].kind, AlertKind::Drop));
        assert!(matches!(signals[0].level, AnomalyLevel::Severe));
        // confidence = min(10.0 / 10.0, 1.0) = 1.0
        assert!(
            (signals[0].confidence - 1.0).abs() < 1e-9,
            "expected confidence=1.0, got {}",
            signals[0].confidence
        );
    }

    #[test]
    fn spike_positive_z_emits_spike() {
        // mean=100, stddev=10, observed_pps=150  →  z_pps = +5.0  →  Suspicious Spike
        let baseline = MockBaseline {
            mean_pps: 100.0,
            stddev_pps: 10.0,
            mean_bps: 0.0,
            stddev_bps: 1e-10,
        };
        let det = EwmaDetector::new(&baseline);
        let result = det.detect(&rates(vec![rate(ProtoIndex::Udp, 150.0, 0.0)]));
        let DetectResult::Signals(signals) = result else {
            panic!("expected DetectResult::Signals");
        };
        assert_eq!(signals.len(), 1);
        assert!(matches!(signals[0].kind, AlertKind::Spike));
        assert!(matches!(signals[0].level, AnomalyLevel::Suspicious));
    }

    #[test]
    fn bps_dominates_pps_in_dominant_z() {
        // z_pps = (130-100)/10 = +3.0 (Suspicious), z_bps = (200-100)/5 = +20.0 (Severe)
        // |z_bps| > |z_pps|, so dominant_z = z_bps (positive) → Spike, Severe
        let baseline = MockBaseline {
            mean_pps: 100.0,
            stddev_pps: 10.0,
            mean_bps: 100.0,
            stddev_bps: 5.0,
        };
        let det = EwmaDetector::new(&baseline);
        let result = det.detect(&rates(vec![rate(ProtoIndex::Tcp, 130.0, 200.0)]));
        let DetectResult::Signals(signals) = result else {
            panic!("expected DetectResult::Signals");
        };
        assert_eq!(signals.len(), 1);
        assert!(matches!(signals[0].kind, AlertKind::Spike));
        assert!(matches!(signals[0].level, AnomalyLevel::Severe));
        // confidence = (max(|3.0|, |20.0|) / 10.0).min(1.0) = 1.0
        assert!(
            (signals[0].confidence - 1.0).abs() < 1e-9,
            "expected confidence=1.0, got {}",
            signals[0].confidence
        );
    }

    #[test]
    fn normal_z_emits_no_signal() {
        // mean=100, stddev=10, observed_pps=101  →  z_pps ≈ 0.1  →  Normal, no signal
        let baseline = MockBaseline {
            mean_pps: 100.0,
            stddev_pps: 10.0,
            mean_bps: 100.0,
            stddev_bps: 10.0,
        };
        let det = EwmaDetector::new(&baseline);
        let result = det.detect(&rates(vec![rate(ProtoIndex::Tcp, 101.0, 101.0)]));
        assert!(matches!(result, DetectResult::Signals(ref s) if s.is_empty()));
    }
}
