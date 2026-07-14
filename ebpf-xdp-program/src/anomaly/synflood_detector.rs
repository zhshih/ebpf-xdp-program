use crate::{alert::SynFloodSignal, anomaly::ratio_confidence, rate::SynIpRate};

/// Stateless, threshold-based SYN-flood detector — mirrors
/// [`crate::anomaly::EmergencyDetector`]'s shape (no warmup, no persistent
/// baseline) rather than adaptive EWMA baselining. Adaptive per-IP
/// baselining would need state that outlives eviction from the bounded
/// `SYN_TRACKER`/top-N pipeline, which is fine for "is this IP over an
/// absolute rate right now" but wrong for "learn this IP's normal
/// behavior" — most attacking IPs have no prior baseline anyway.
///
/// Deliberately does not implement [`crate::anomaly::AnomalyDetector`]:
/// that trait's signature is hard-coded to `&[ProtoRate]`.
pub struct SynFloodDetector {
    max_syn_pps: f64,
    top_n: usize,
}

impl SynFloodDetector {
    pub fn new(max_syn_pps: f64, top_n: usize) -> Self {
        Self { max_syn_pps, top_n }
    }

    pub fn top_n(&self) -> usize {
        self.top_n
    }

    /// Confidence is `(pps / max_syn_pps - 1.0).clamp(0, 1)`, sharing
    /// `EmergencyDetector`'s ratio-based confidence formula — 2x threshold = 1.0.
    pub fn detect(&self, rates: &[SynIpRate]) -> Vec<SynFloodSignal> {
        rates
            .iter()
            .filter(|r| r.pps > self.max_syn_pps)
            .map(|r| SynFloodSignal {
                src_ip: r.src_ip,
                pps: r.pps,
                confidence: ratio_confidence(r.pps, self.max_syn_pps),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn rate(ip: u32, pps: f64) -> SynIpRate {
        SynIpRate {
            src_ip: Ipv4Addr::from(ip),
            pps,
        }
    }

    #[test]
    fn synflood_under_threshold_no_signal() {
        let det = SynFloodDetector::new(100.0, 10);
        let signals = det.detect(&[rate(1, 99.0)]);
        assert!(signals.is_empty());
    }

    #[test]
    fn synflood_over_threshold_fires() {
        let det = SynFloodDetector::new(100.0, 10);
        let signals = det.detect(&[rate(1, 101.0)]);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].src_ip, Ipv4Addr::from(1));
    }

    #[test]
    fn synflood_confidence_proportional() {
        // 2x threshold -> ratio = 2.0 -> confidence = (2.0 - 1.0).clamp(0,1) = 1.0
        let det = SynFloodDetector::new(500.0, 10);
        let signals = det.detect(&[rate(1, 1000.0)]);
        assert!(
            (signals[0].confidence - 1.0).abs() < 1e-9,
            "confidence should be 1.0 at 2x threshold"
        );
    }

    #[test]
    fn synflood_confidence_matches_ratio_confidence_at_sub_one_threshold() {
        // Regression pin: confidence must track the true ratio against the
        // configured threshold, not an artificially floored denominator.
        let det = SynFloodDetector::new(0.5, 10);
        let signals = det.detect(&[rate(1, 1.0)]);
        assert_eq!(signals.len(), 1);
        assert!(
            (signals[0].confidence - ratio_confidence(1.0, 0.5)).abs() < 1e-9,
            "confidence should equal ratio_confidence(1.0, 0.5), got {}",
            signals[0].confidence
        );
        assert!(
            (signals[0].confidence - 1.0).abs() < 1e-9,
            "1.0 pps against a 0.5 threshold is a 2x breach, confidence should be 1.0"
        );
    }

    #[test]
    fn synflood_multiple_ips_each_signaled() {
        let det = SynFloodDetector::new(100.0, 10);
        let signals = det.detect(&[rate(1, 150.0), rate(2, 50.0), rate(3, 200.0)]);
        assert_eq!(signals.len(), 2);
        assert!(signals.iter().any(|s| s.src_ip == Ipv4Addr::from(1)));
        assert!(signals.iter().any(|s| s.src_ip == Ipv4Addr::from(3)));
    }
}
