use std::time::Duration;

use ebpf_xdp_program_common::ProtoIndex;

use crate::{
    alert::{AlertKind, AlertRule},
    anomaly::{AnomalyLevel, EmergencyDetector, EmergencyThreshold},
    baseline::EwmaEstimator,
};

pub fn default_baseline_estimator() -> EwmaEstimator {
    EwmaEstimator::new(0.4, 5, 1e-3, Duration::from_secs(120))
}

pub fn default_alert_rules() -> Vec<AlertRule> {
    vec![
        AlertRule {
            kind: AlertKind::Spike,
            min_level: AnomalyLevel::Suspicious,
            min_confidence: 0.6,
            cooldown: Duration::from_secs(120),
            consecutive_threshold: 5,
            resolve_consecutive_threshold: 3,
            freezes_baseline: true,
        },
        AlertRule {
            kind: AlertKind::Emergency,
            min_level: AnomalyLevel::Severe,
            min_confidence: 0.0,
            cooldown: Duration::from_secs(60),
            consecutive_threshold: 1,
            resolve_consecutive_threshold: 1,
            freezes_baseline: false,
        },
    ]
}

pub fn default_emergency_detector() -> EmergencyDetector {
    EmergencyDetector::new(vec![EmergencyThreshold {
        proto: ProtoIndex::Icmp,
        max_pps: Some(3.0),
        max_bps: None,
    }])
}
