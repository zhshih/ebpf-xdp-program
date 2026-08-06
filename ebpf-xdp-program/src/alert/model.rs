use std::net::Ipv4Addr;

use ebpf_xdp_program_common::ProtoIndex;

use crate::{
    alert::{
        ip_manager::{FromIpSignal, IpKeyed},
        state::AlertLifecycle,
    },
    anomaly::AnomalyLevel,
};

/// Classification of what kind of anomaly was detected.
///
/// - `Spike`: traffic rate significantly above the baseline (positive z-score)
/// - `Drop`: traffic rate significantly below the baseline (negative z-score)
/// - `Emergency`: absolute threshold breached, regardless of baseline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertKind {
    Spike,
    Drop,
    Emergency,
}

impl AlertKind {
    /// Short lowercase label used in Prometheus metric labels and log output.
    pub fn label(self) -> &'static str {
        match self {
            AlertKind::Spike => "spike",
            AlertKind::Drop => "drop",
            AlertKind::Emergency => "emergency",
        }
    }
}

/// An intermediate anomaly signal produced by a detector, before FSM evaluation.
///
/// Signals are filtered by [`AlertRule`](crate::alert::AlertRule) criteria
/// (min_level, min_confidence) before advancing the alert state machine.
#[derive(Debug, Clone)]
pub struct AlertSignal {
    pub proto: ProtoIndex,
    pub level: AnomalyLevel,
    pub kind: AlertKind,
    /// Normalized confidence in [0, 1]; higher means the anomaly is more pronounced.
    pub confidence: f64,
}

/// A finalized alert emitted by the alert manager on a `Fired` or `Resolved` transition.
#[derive(Debug, Clone)]
pub struct Alert {
    pub proto: ProtoIndex,
    pub kind: AlertKind,
    pub level: AnomalyLevel,
    pub confidence: f64,
}

/// An alert that has undergone a lifecycle transition (fired or resolved).
pub struct AlertEvent {
    pub alert: Alert,
    pub lifecycle: AlertLifecycle,
}

/// An alert lifecycle transition for one source IP, generic over the
/// finalized alert payload `A`. `SynFloodAlertEvent`/`PortScanAlertEvent`
/// below are its two instantiations.
pub struct IpAlertEvent<A> {
    pub alert: A,
    pub lifecycle: AlertLifecycle,
}

/// A per-source-IP SYN-flood signal.
///
/// Deliberately not [`AlertSignal`]: that type is keyed by `ProtoIndex`,
/// which has nowhere to put an `Ipv4Addr` without collapsing distinct
/// attacker IPs into one bucket.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynFloodSignal {
    pub src_ip: Ipv4Addr,
    pub pps: f64,
    pub confidence: f64,
}

/// A finalized SYN-flood alert payload, mirroring [`Alert`] (minus
/// `kind`/`level`, which have no SynFlood equivalent — this pipeline has no
/// rule-based classification, just an absolute threshold).
pub struct SynFloodAlert {
    pub src_ip: Ipv4Addr,
    pub pps: f64,
    pub confidence: f64,
}

impl IpKeyed for SynFloodSignal {
    fn src_ip(&self) -> Ipv4Addr {
        self.src_ip
    }
}

impl IpKeyed for SynFloodAlert {
    fn src_ip(&self) -> Ipv4Addr {
        self.src_ip
    }
}

impl FromIpSignal<SynFloodSignal> for SynFloodAlert {
    fn from_signal(src_ip: Ipv4Addr, signal: Option<&SynFloodSignal>) -> Self {
        SynFloodAlert {
            src_ip,
            pps: signal.map_or(0.0, |s| s.pps),
            confidence: signal.map_or(0.0, |s| s.confidence),
        }
    }
}

/// A SYN-flood alert lifecycle transition for one source IP.
pub type SynFloodAlertEvent = IpAlertEvent<SynFloodAlert>;

/// A per-source-IP port-scan signal.
///
/// Deliberately not [`AlertSignal`], for the same reason [`SynFloodSignal`]
/// isn't: keyed by `Ipv4Addr`, which `ProtoIndex` has nowhere to put.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PortScanSignal {
    pub src_ip: Ipv4Addr,
    pub distinct_ports: u32,
    pub confidence: f64,
}

/// A finalized port-scan alert payload, mirroring [`SynFloodAlert`].
pub struct PortScanAlert {
    pub src_ip: Ipv4Addr,
    pub distinct_ports: u32,
    pub confidence: f64,
}

impl IpKeyed for PortScanSignal {
    fn src_ip(&self) -> Ipv4Addr {
        self.src_ip
    }
}

impl IpKeyed for PortScanAlert {
    fn src_ip(&self) -> Ipv4Addr {
        self.src_ip
    }
}

impl FromIpSignal<PortScanSignal> for PortScanAlert {
    fn from_signal(src_ip: Ipv4Addr, signal: Option<&PortScanSignal>) -> Self {
        PortScanAlert {
            src_ip,
            distinct_ports: signal.map_or(0, |s| s.distinct_ports),
            confidence: signal.map_or(0.0, |s| s.confidence),
        }
    }
}

/// A port-scan alert lifecycle transition for one source IP.
pub type PortScanAlertEvent = IpAlertEvent<PortScanAlert>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_kind_label_all_variants() {
        assert_eq!(AlertKind::Spike.label(), "spike");
        assert_eq!(AlertKind::Drop.label(), "drop");
        assert_eq!(AlertKind::Emergency.label(), "emergency");
    }
}
