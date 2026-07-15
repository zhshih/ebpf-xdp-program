use crate::{alert::PortScanSignal, anomaly::ratio_confidence, rate::PortScanIpBreadth};

/// Stateless, threshold-based port-scan detector — same shape as
/// [`crate::anomaly::SynFloodDetector`]: fires when a source IP's distinct
/// destination-port count exceeds `max_distinct_ports`.
///
/// Deliberately does not implement [`crate::anomaly::AnomalyDetector`]:
/// that trait's signature is hard-coded to `&[ProtoRate]`.
pub struct PortScanDetector {
    max_distinct_ports: u32,
    top_n: usize,
    window_ns: u64,
}

impl PortScanDetector {
    pub fn new(max_distinct_ports: u32, top_n: usize, window_ns: u64) -> Self {
        Self {
            max_distinct_ports,
            top_n,
            window_ns,
        }
    }

    pub fn top_n(&self) -> usize {
        self.top_n
    }

    pub fn window_ns(&self) -> u64 {
        self.window_ns
    }

    /// Confidence is `(distinct_ports / max_distinct_ports - 1.0).clamp(0, 1)`,
    /// sharing `EmergencyDetector`/`SynFloodDetector`'s ratio-based formula.
    pub fn detect(&self, breadths: &[PortScanIpBreadth]) -> Vec<PortScanSignal> {
        breadths
            .iter()
            .filter(|b| b.distinct_ports > self.max_distinct_ports)
            .map(|b| PortScanSignal {
                src_ip: b.src_ip,
                distinct_ports: b.distinct_ports,
                confidence: ratio_confidence(
                    b.distinct_ports as f64,
                    self.max_distinct_ports as f64,
                ),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn breadth(ip: u32, distinct_ports: u32) -> PortScanIpBreadth {
        PortScanIpBreadth {
            src_ip: Ipv4Addr::from(ip),
            distinct_ports,
        }
    }

    #[test]
    fn port_scan_under_threshold_no_signal() {
        let det = PortScanDetector::new(20, 10, 30_000_000_000);
        let signals = det.detect(&[breadth(1, 19)]);
        assert!(signals.is_empty());
    }

    #[test]
    fn port_scan_over_threshold_fires() {
        let det = PortScanDetector::new(20, 10, 30_000_000_000);
        let signals = det.detect(&[breadth(1, 21)]);
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].src_ip, Ipv4Addr::from(1));
    }

    #[test]
    fn port_scan_confidence_proportional() {
        // 2x threshold -> ratio = 2.0 -> confidence = (2.0 - 1.0).clamp(0,1) = 1.0
        let det = PortScanDetector::new(50, 10, 30_000_000_000);
        let signals = det.detect(&[breadth(1, 100)]);
        assert!(
            (signals[0].confidence - 1.0).abs() < 1e-9,
            "confidence should be 1.0 at 2x threshold"
        );
    }

    #[test]
    fn port_scan_confidence_matches_ratio_confidence_at_sub_one_threshold() {
        let det = PortScanDetector::new(1, 10, 30_000_000_000);
        let signals = det.detect(&[breadth(1, 2)]);
        assert_eq!(signals.len(), 1);
        assert!(
            (signals[0].confidence - ratio_confidence(2.0, 1.0)).abs() < 1e-9,
            "confidence should equal ratio_confidence(2.0, 1.0), got {}",
            signals[0].confidence
        );
    }

    #[test]
    fn port_scan_multiple_ips_each_signaled() {
        let det = PortScanDetector::new(20, 10, 30_000_000_000);
        let signals = det.detect(&[breadth(1, 30), breadth(2, 10), breadth(3, 40)]);
        assert_eq!(signals.len(), 2);
        assert!(signals.iter().any(|s| s.src_ip == Ipv4Addr::from(1)));
        assert!(signals.iter().any(|s| s.src_ip == Ipv4Addr::from(3)));
    }
}
