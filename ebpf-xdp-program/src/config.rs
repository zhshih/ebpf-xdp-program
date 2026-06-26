use std::time::Duration;

use anyhow::Context as _;
use ebpf_xdp_program_common::ProtoIndex;

use crate::{
    alert::{AlertKind, AlertRule},
    anomaly::{AnomalyLevel, EmergencyDetector, EmergencyThreshold},
    baseline::EwmaEstimator,
};

// ─── Config DTOs ─────────────────────────────────────────────────────────────

/// Top-level TOML configuration.
///
/// All sections are optional. Fields omitted from the file fall back to the
/// compiled-in defaults returned by the `default_*` functions below.
#[derive(serde::Deserialize, Default)]
pub struct Config {
    pub baseline: Option<BaselineConfig>,
    #[serde(default)]
    pub alert_rules: Vec<AlertRuleConfig>,
    #[serde(default)]
    pub emergency_thresholds: Vec<EmergencyThresholdConfig>,
}

/// Overrides for the EWMA baseline estimator parameters.
#[derive(serde::Deserialize)]
pub struct BaselineConfig {
    /// EWMA smoothing factor in (0, 1]. Higher = faster adaptation.
    pub alpha: Option<f64>,
    /// Minimum number of samples before the baseline is considered ready.
    pub min_samples: Option<u64>,
    /// Minimum standard deviation required for the baseline to be ready.
    pub min_stddev: Option<f64>,
    /// Minimum elapsed seconds from start before the baseline is ready.
    pub min_elapsed_secs: Option<u64>,
}

/// Serialisable representation of a single alert rule.
#[derive(serde::Deserialize)]
pub struct AlertRuleConfig {
    /// Alert kind: `"spike"`, `"drop"`, or `"emergency"`.
    pub kind: String,
    /// Minimum anomaly level: `"normal"`, `"suspicious"`, or `"severe"`.
    pub min_level: String,
    /// Minimum detector confidence in [0, 1].
    pub min_confidence: f64,
    /// Re-fire suppression window in seconds.
    pub cooldown_secs: u64,
    /// Consecutive anomalous ticks required to fire.
    pub consecutive_threshold: u32,
    /// Consecutive normal ticks required to resolve.
    pub resolve_consecutive_threshold: u32,
    /// Whether to freeze the protocol's EWMA baseline while the alert is hot.
    pub freezes_baseline: bool,
}

/// Serialisable representation of a per-protocol emergency threshold.
#[derive(serde::Deserialize)]
pub struct EmergencyThresholdConfig {
    /// Protocol bucket: `"icmp"`, `"tcp"`, `"udp"`, `"ipv6"`, or `"other"`.
    pub proto: String,
    /// Maximum allowed packets-per-second before an emergency signal fires.
    pub max_pps: Option<f64>,
    /// Maximum allowed bytes-per-second before an emergency signal fires.
    pub max_bps: Option<f64>,
}

// ─── String → domain type parsers ────────────────────────────────────────────

fn parse_anomaly_level(s: &str) -> anyhow::Result<AnomalyLevel> {
    match s.to_ascii_lowercase().as_str() {
        "normal" => Ok(AnomalyLevel::Normal),
        "suspicious" => Ok(AnomalyLevel::Suspicious),
        "severe" => Ok(AnomalyLevel::Severe),
        other => anyhow::bail!("unknown anomaly level: {:?}", other),
    }
}

fn parse_alert_kind(s: &str) -> anyhow::Result<AlertKind> {
    match s.to_ascii_lowercase().as_str() {
        "spike" => Ok(AlertKind::Spike),
        "drop" => Ok(AlertKind::Drop),
        "emergency" => Ok(AlertKind::Emergency),
        other => anyhow::bail!("unknown alert kind: {:?}", other),
    }
}

fn parse_proto_index(s: &str) -> anyhow::Result<ProtoIndex> {
    match s.to_ascii_lowercase().as_str() {
        "icmp" => Ok(ProtoIndex::Icmp),
        "tcp" => Ok(ProtoIndex::Tcp),
        "udp" => Ok(ProtoIndex::Udp),
        "ipv6" => Ok(ProtoIndex::Ipv6),
        "other" => Ok(ProtoIndex::Other),
        other => anyhow::bail!("unknown protocol: {:?}", other),
    }
}

// ─── Builders ────────────────────────────────────────────────────────────────

fn build_estimator(baseline: Option<BaselineConfig>) -> EwmaEstimator {
    let defaults = default_baseline_estimator();
    let Some(b) = baseline else { return defaults };

    // Decompose defaults to extract their individual parameters.
    // We re-create with overrides applied on top.
    EwmaEstimator::new(
        b.alpha.unwrap_or(0.4),
        b.min_samples.unwrap_or(5),
        b.min_stddev.unwrap_or(1e-3),
        b.min_elapsed_secs
            .unwrap_or(120)
            .div_ceil(crate::ANOMALY_EVAL_INTERVAL.as_secs()),
    )
}

fn build_alert_rules(rules: Vec<AlertRuleConfig>) -> anyhow::Result<Vec<AlertRule>> {
    rules
        .into_iter()
        .enumerate()
        .map(|(i, r)| {
            Ok(AlertRule {
                kind: parse_alert_kind(&r.kind)
                    .with_context(|| format!("alert_rules[{i}].kind"))?,
                min_level: parse_anomaly_level(&r.min_level)
                    .with_context(|| format!("alert_rules[{i}].min_level"))?,
                min_confidence: r.min_confidence,
                cooldown: Duration::from_secs(r.cooldown_secs),
                consecutive_threshold: r.consecutive_threshold,
                resolve_consecutive_threshold: r.resolve_consecutive_threshold,
                freezes_baseline: r.freezes_baseline,
            })
        })
        .collect()
}

fn build_emergency_detector(
    thresholds: Vec<EmergencyThresholdConfig>,
) -> anyhow::Result<EmergencyDetector> {
    let ts: anyhow::Result<Vec<EmergencyThreshold>> = thresholds
        .into_iter()
        .enumerate()
        .map(|(i, t)| {
            Ok(EmergencyThreshold {
                proto: parse_proto_index(&t.proto)
                    .with_context(|| format!("emergency_thresholds[{i}].proto"))?,
                max_pps: t.max_pps,
                max_bps: t.max_bps,
            })
        })
        .collect();
    Ok(EmergencyDetector::new(ts?))
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Loads and parses a TOML configuration file, returning domain objects.
///
/// Any section or field omitted from the file falls back to the compiled-in
/// defaults. Returns an error if the file cannot be read or the TOML is invalid.
pub fn load_config(
    path: &std::path::Path,
) -> anyhow::Result<(EwmaEstimator, EmergencyDetector, Vec<AlertRule>)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    let cfg: Config = toml::from_str(&text)
        .with_context(|| format!("failed to parse config file: {}", path.display()))?;

    let estimator = build_estimator(cfg.baseline);
    let emergency = if cfg.emergency_thresholds.is_empty() {
        default_emergency_detector()
    } else {
        build_emergency_detector(cfg.emergency_thresholds)?
    };
    let rules = if cfg.alert_rules.is_empty() {
        default_alert_rules()
    } else {
        build_alert_rules(cfg.alert_rules)?
    };

    Ok((estimator, emergency, rules))
}

pub fn default_baseline_estimator() -> EwmaEstimator {
    EwmaEstimator::new(
        0.4,
        5,
        1e-3,
        120u64.div_ceil(crate::ANOMALY_EVAL_INTERVAL.as_secs()),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_anomaly_level ───────────────────────────────────────────────────

    #[test]
    fn parse_anomaly_level_valid() {
        assert!(matches!(
            parse_anomaly_level("normal"),
            Ok(AnomalyLevel::Normal)
        ));
        assert!(matches!(
            parse_anomaly_level("suspicious"),
            Ok(AnomalyLevel::Suspicious)
        ));
        assert!(matches!(
            parse_anomaly_level("severe"),
            Ok(AnomalyLevel::Severe)
        ));
    }

    #[test]
    fn parse_anomaly_level_case_insensitive() {
        assert!(matches!(
            parse_anomaly_level("NORMAL"),
            Ok(AnomalyLevel::Normal)
        ));
        assert!(matches!(
            parse_anomaly_level("Suspicious"),
            Ok(AnomalyLevel::Suspicious)
        ));
    }

    #[test]
    fn parse_anomaly_level_invalid_returns_err() {
        assert!(parse_anomaly_level("critical").is_err());
        assert!(parse_anomaly_level("").is_err());
    }

    // ── parse_alert_kind ─────────────────────────────────────────────────────

    #[test]
    fn parse_alert_kind_valid() {
        assert!(matches!(parse_alert_kind("spike"), Ok(AlertKind::Spike)));
        assert!(matches!(parse_alert_kind("drop"), Ok(AlertKind::Drop)));
        assert!(matches!(
            parse_alert_kind("emergency"),
            Ok(AlertKind::Emergency)
        ));
    }

    #[test]
    fn parse_alert_kind_invalid_returns_err() {
        assert!(parse_alert_kind("flood").is_err());
        assert!(parse_alert_kind("").is_err());
    }

    // ── parse_proto_index ────────────────────────────────────────────────────

    #[test]
    fn parse_proto_index_valid() {
        assert!(matches!(parse_proto_index("icmp"), Ok(ProtoIndex::Icmp)));
        assert!(matches!(parse_proto_index("tcp"), Ok(ProtoIndex::Tcp)));
        assert!(matches!(parse_proto_index("udp"), Ok(ProtoIndex::Udp)));
        assert!(matches!(parse_proto_index("ipv6"), Ok(ProtoIndex::Ipv6)));
        assert!(matches!(parse_proto_index("other"), Ok(ProtoIndex::Other)));
    }

    #[test]
    fn parse_proto_index_invalid_returns_err() {
        assert!(parse_proto_index("sctp").is_err());
        assert!(parse_proto_index("").is_err());
    }

    // ── build_estimator ──────────────────────────────────────────────────────

    #[test]
    fn build_estimator_none_uses_defaults() {
        use crate::baseline::BaselineState;
        let est = build_estimator(None);
        // No samples fed — must still be in Warming state.
        assert!(matches!(
            est.snapshot(ProtoIndex::Tcp),
            BaselineState::Warming
        ));
    }

    // ── build_alert_rules ────────────────────────────────────────────────────

    #[test]
    fn build_alert_rules_valid_rule() {
        let cfg = vec![AlertRuleConfig {
            kind: "spike".to_string(),
            min_level: "suspicious".to_string(),
            min_confidence: 0.5,
            cooldown_secs: 60,
            consecutive_threshold: 3,
            resolve_consecutive_threshold: 2,
            freezes_baseline: true,
        }];
        let rules = build_alert_rules(cfg).expect("should parse");
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].kind, AlertKind::Spike));
        assert!(matches!(rules[0].min_level, AnomalyLevel::Suspicious));
        assert!((rules[0].min_confidence - 0.5).abs() < 1e-9);
        assert_eq!(rules[0].consecutive_threshold, 3);
        assert!(rules[0].freezes_baseline);
    }

    #[test]
    fn build_alert_rules_invalid_kind_returns_err() {
        let cfg = vec![AlertRuleConfig {
            kind: "unknown_kind".to_string(),
            min_level: "suspicious".to_string(),
            min_confidence: 0.5,
            cooldown_secs: 60,
            consecutive_threshold: 3,
            resolve_consecutive_threshold: 2,
            freezes_baseline: false,
        }];
        assert!(build_alert_rules(cfg).is_err());
    }

    #[test]
    fn build_alert_rules_invalid_level_returns_err() {
        let cfg = vec![AlertRuleConfig {
            kind: "spike".to_string(),
            min_level: "critical".to_string(),
            min_confidence: 0.5,
            cooldown_secs: 60,
            consecutive_threshold: 3,
            resolve_consecutive_threshold: 2,
            freezes_baseline: false,
        }];
        assert!(build_alert_rules(cfg).is_err());
    }

    // ── build_emergency_detector ─────────────────────────────────────────────

    #[test]
    fn build_emergency_detector_valid_threshold() {
        let cfg = vec![EmergencyThresholdConfig {
            proto: "tcp".to_string(),
            max_pps: Some(1000.0),
            max_bps: None,
        }];
        assert!(build_emergency_detector(cfg).is_ok());
    }

    #[test]
    fn build_emergency_detector_invalid_proto_returns_err() {
        let cfg = vec![EmergencyThresholdConfig {
            proto: "sctp".to_string(),
            max_pps: Some(1000.0),
            max_bps: None,
        }];
        assert!(build_emergency_detector(cfg).is_err());
    }

    // ── load_config ──────────────────────────────────────────────────────────

    #[test]
    fn load_config_empty_toml_returns_defaults() {
        let path = std::env::temp_dir().join("test_config_empty.toml");
        std::fs::write(&path, "").unwrap();
        assert!(
            load_config(&path).is_ok(),
            "empty TOML should fall back to defaults"
        );
    }

    #[test]
    fn load_config_with_overrides() {
        let path = std::env::temp_dir().join("test_config_overrides.toml");
        std::fs::write(
            &path,
            r#"
[baseline]
alpha = 0.2
min_samples = 10

[[alert_rules]]
kind = "drop"
min_level = "severe"
min_confidence = 0.8
cooldown_secs = 30
consecutive_threshold = 2
resolve_consecutive_threshold = 1
freezes_baseline = false
"#,
        )
        .unwrap();
        let (_, _, rules) = load_config(&path).expect("should parse");
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].kind, AlertKind::Drop));
        assert!(matches!(rules[0].min_level, AnomalyLevel::Severe));
    }

    #[test]
    fn load_config_invalid_toml_returns_err() {
        let path = std::env::temp_dir().join("test_config_invalid.toml");
        std::fs::write(&path, "not valid toml !!!").unwrap();
        assert!(load_config(&path).is_err());
    }

    #[test]
    fn load_config_unknown_proto_in_thresholds_returns_err() {
        let path = std::env::temp_dir().join("test_config_bad_proto.toml");
        std::fs::write(
            &path,
            r#"
[[emergency_thresholds]]
proto = "sctp"
max_pps = 1000.0
"#,
        )
        .unwrap();
        assert!(load_config(&path).is_err());
    }
}
