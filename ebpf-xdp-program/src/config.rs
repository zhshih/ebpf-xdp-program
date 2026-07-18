use std::time::Duration;

use anyhow::Context as _;
use ebpf_xdp_program_common::ProtoIndex;

use crate::{
    alert::{AlertKind, AlertRule, PortScanAlertManager, SynFloodAlertManager},
    anomaly::{
        AnomalyLevel, EmergencyDetector, EmergencyThreshold, PortScanDetector, SynFloodDetector,
    },
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
    pub syn_flood: Option<SynFloodConfig>,
    pub port_scan: Option<PortScanConfig>,
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

/// Overrides for per-source-IP SYN-flood detection.
#[derive(serde::Deserialize)]
pub struct SynFloodConfig {
    /// Maximum allowed SYN packets-per-second from a single source IP.
    pub max_syn_pps: Option<f64>,
    /// Number of top-offending source IPs tracked/alerted on per tick.
    pub top_n: Option<usize>,
    /// Re-fire suppression window in seconds.
    pub cooldown_secs: Option<u64>,
    /// Consecutive over-threshold ticks required to fire.
    pub consecutive_threshold: Option<u32>,
    /// Consecutive under-threshold ticks required to resolve.
    pub resolve_consecutive_threshold: Option<u32>,
}

/// Overrides for per-source-IP port-scan detection.
#[derive(serde::Deserialize)]
pub struct PortScanConfig {
    /// Maximum distinct destination ports one source IP may touch within `window_secs`.
    pub max_distinct_ports: Option<u32>,
    /// Detection window, in seconds, over which distinct ports are counted.
    pub window_secs: Option<u64>,
    /// Number of top-scanning source IPs tracked/alerted on per tick.
    pub top_n: Option<usize>,
    /// Re-fire suppression window in seconds.
    pub cooldown_secs: Option<u64>,
    /// Consecutive over-threshold ticks required to fire.
    pub consecutive_threshold: Option<u32>,
    /// Consecutive under-threshold ticks required to resolve.
    pub resolve_consecutive_threshold: Option<u32>,
}

// ─── Resolved config (actually-in-effect values, for the `/config` API) ──────

/// Resolved EWMA baseline parameters, after defaults have been merged in.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedBaselineConfig {
    pub alpha: f64,
    pub min_samples: u64,
    pub min_stddev: f64,
    /// Stored in human-facing seconds (not the derived tick count), so the
    /// value stays meaningful regardless of `ANOMALY_EVAL_INTERVAL`.
    pub min_elapsed_secs: u64,
}

/// Resolved view of a single alert rule, with enum fields rendered as labels.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedAlertRuleConfig {
    pub kind: &'static str,
    pub min_level: &'static str,
    pub min_confidence: f64,
    pub cooldown_secs: u64,
    pub consecutive_threshold: u32,
    pub resolve_consecutive_threshold: u32,
    pub freezes_baseline: bool,
}

/// Resolved view of a single per-protocol emergency threshold.
///
/// `proto` is lowercased from `ProtoIndex::label()` (which returns `"ICMP"`,
/// `"TCP"`, etc. for Prometheus label compatibility) so the JSON view stays
/// consistent with the lowercase `kind`/`min_level` labels above — this is a
/// JSON-boundary-only adjustment; `ProtoIndex::label()` itself is left
/// untouched since it backs live Prometheus label values.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedEmergencyThresholdConfig {
    pub proto: String,
    pub max_pps: Option<f64>,
    pub max_bps: Option<f64>,
}

/// Resolved per-source-IP SYN-flood detection parameters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedSynFloodConfig {
    pub max_syn_pps: f64,
    pub top_n: usize,
    pub cooldown_secs: u64,
    pub consecutive_threshold: u32,
    pub resolve_consecutive_threshold: u32,
}

/// Resolved per-source-IP port-scan detection parameters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedPortScanConfig {
    pub max_distinct_ports: u32,
    pub window_secs: u64,
    pub top_n: usize,
    pub cooldown_secs: u64,
    pub consecutive_threshold: u32,
    pub resolve_consecutive_threshold: u32,
}

/// The actually-in-effect configuration, resolved from either a TOML file or
/// compiled-in defaults. Serialised as-is by the `/config` API endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedConfig {
    pub baseline: ResolvedBaselineConfig,
    pub alert_rules: Vec<ResolvedAlertRuleConfig>,
    pub emergency_thresholds: Vec<ResolvedEmergencyThresholdConfig>,
    pub syn_flood: ResolvedSynFloodConfig,
    pub port_scan: ResolvedPortScanConfig,
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

/// Builds the EWMA estimator from optional overrides, returning both the
/// domain object and the resolved scalars used to build it. `EwmaEstimator`
/// has no getters, so this is the only point where those scalars are
/// observable — captured here once, with no separate/divergent default path.
fn build_estimator(baseline: Option<BaselineConfig>) -> (EwmaEstimator, ResolvedBaselineConfig) {
    let alpha = baseline.as_ref().and_then(|b| b.alpha).unwrap_or(0.4);
    let min_samples = baseline.as_ref().and_then(|b| b.min_samples).unwrap_or(5);
    let min_stddev = baseline.as_ref().and_then(|b| b.min_stddev).unwrap_or(1e-3);
    let min_elapsed_secs = baseline.and_then(|b| b.min_elapsed_secs).unwrap_or(120);
    let min_elapsed_ticks = min_elapsed_secs.div_ceil(crate::ANOMALY_EVAL_INTERVAL.as_secs());

    let estimator = EwmaEstimator::new(alpha, min_samples, min_stddev, min_elapsed_ticks);
    let resolved = ResolvedBaselineConfig {
        alpha,
        min_samples,
        min_stddev,
        min_elapsed_secs,
    };
    (estimator, resolved)
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

/// Projects a constructed [`AlertRule`] into its resolved JSON view.
/// `AlertRule`'s fields are all public, so this can run on any `Vec<AlertRule>`
/// (built from a TOML override or a compiled-in default) after the fact —
/// there's exactly one place where an `AlertRule`'s values exist, and this is
/// a pure projection of it, so the rendered view can't drift from what's
/// actually loaded into the `AlertManager`.
fn resolve_alert_rule(rule: &AlertRule) -> ResolvedAlertRuleConfig {
    ResolvedAlertRuleConfig {
        kind: rule.kind.label(),
        min_level: rule.min_level.label(),
        min_confidence: rule.min_confidence,
        cooldown_secs: rule.cooldown.as_secs(),
        consecutive_threshold: rule.consecutive_threshold,
        resolve_consecutive_threshold: rule.resolve_consecutive_threshold,
        freezes_baseline: rule.freezes_baseline,
    }
}

/// Builds the emergency detector from TOML overrides, returning both the
/// domain object and the resolved per-protocol thresholds used to build it.
/// `EmergencyDetector` has no getter for its thresholds, so (like
/// `build_estimator`) this is the only point where they're observable.
fn build_emergency_detector(
    thresholds: Vec<EmergencyThresholdConfig>,
) -> anyhow::Result<(EmergencyDetector, Vec<ResolvedEmergencyThresholdConfig>)> {
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
    let ts = ts?;
    let resolved = resolve_emergency_thresholds(&ts);
    Ok((EmergencyDetector::new(ts), resolved))
}

fn resolve_emergency_thresholds(
    ts: &[EmergencyThreshold],
) -> Vec<ResolvedEmergencyThresholdConfig> {
    ts.iter()
        .map(|t| ResolvedEmergencyThresholdConfig {
            proto: t.proto.label().to_ascii_lowercase(),
            max_pps: t.max_pps,
            max_bps: t.max_bps,
        })
        .collect()
}

/// Builds the SYN-flood detector and alert manager from optional overrides,
/// returning both domain objects and the resolved scalars used to build
/// them — same rationale as `build_estimator` (see there).
fn build_synflood(
    cfg: Option<SynFloodConfig>,
) -> (
    SynFloodDetector,
    SynFloodAlertManager,
    ResolvedSynFloodConfig,
) {
    let max_syn_pps = cfg.as_ref().and_then(|c| c.max_syn_pps).unwrap_or(100.0);
    let top_n = cfg.as_ref().and_then(|c| c.top_n).unwrap_or(10);
    let cooldown_secs = cfg.as_ref().and_then(|c| c.cooldown_secs).unwrap_or(60);
    let consecutive_threshold = cfg
        .as_ref()
        .and_then(|c| c.consecutive_threshold)
        .unwrap_or(3);
    let resolve_consecutive_threshold = cfg
        .and_then(|c| c.resolve_consecutive_threshold)
        .unwrap_or(3);

    let detector = SynFloodDetector::new(max_syn_pps, top_n);
    let alert_manager = SynFloodAlertManager::new(
        Duration::from_secs(cooldown_secs),
        consecutive_threshold,
        resolve_consecutive_threshold,
    );
    let resolved = ResolvedSynFloodConfig {
        max_syn_pps,
        top_n,
        cooldown_secs,
        consecutive_threshold,
        resolve_consecutive_threshold,
    };
    (detector, alert_manager, resolved)
}

/// Builds the port-scan detector and alert manager from optional overrides,
/// returning both domain objects and the resolved scalars used to build
/// them — same rationale as `build_synflood` (see there).
fn build_port_scan(
    cfg: Option<PortScanConfig>,
) -> (
    PortScanDetector,
    PortScanAlertManager,
    ResolvedPortScanConfig,
) {
    let max_distinct_ports = cfg
        .as_ref()
        .and_then(|c| c.max_distinct_ports)
        .unwrap_or(20);
    let window_secs = cfg.as_ref().and_then(|c| c.window_secs).unwrap_or(30);
    let top_n = cfg.as_ref().and_then(|c| c.top_n).unwrap_or(10);
    let cooldown_secs = cfg.as_ref().and_then(|c| c.cooldown_secs).unwrap_or(60);
    let consecutive_threshold = cfg
        .as_ref()
        .and_then(|c| c.consecutive_threshold)
        .unwrap_or(3);
    let resolve_consecutive_threshold = cfg
        .and_then(|c| c.resolve_consecutive_threshold)
        .unwrap_or(3);

    let window_ns = Duration::from_secs(window_secs).as_nanos() as u64;
    let detector = PortScanDetector::new(max_distinct_ports, top_n, window_ns);
    let alert_manager = PortScanAlertManager::new(
        Duration::from_secs(cooldown_secs),
        consecutive_threshold,
        resolve_consecutive_threshold,
    );
    let resolved = ResolvedPortScanConfig {
        max_distinct_ports,
        window_secs,
        top_n,
        cooldown_secs,
        consecutive_threshold,
        resolve_consecutive_threshold,
    };
    (detector, alert_manager, resolved)
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Bundle of all constructed detector/alerting domain objects, returned
/// alongside [`ResolvedConfig`] by [`load_config`]/[`resolve_all`].
///
/// A named struct rather than a growing tuple — cheaper to extend as new
/// detectors are added, and self-documenting at call sites.
pub struct ResolvedDetectors {
    pub baseline: EwmaEstimator,
    pub emergency: EmergencyDetector,
    pub alert_rules: Vec<AlertRule>,
    pub synflood_detector: SynFloodDetector,
    pub synflood_alert_manager: SynFloodAlertManager,
    pub port_scan_detector: PortScanDetector,
    pub port_scan_alert_manager: PortScanAlertManager,
}

/// Loads and parses a TOML configuration file, returning domain objects plus
/// the resolved configuration view used by the `/config` API endpoint.
///
/// Any section or field omitted from the file falls back to the compiled-in
/// defaults. Returns an error if the file cannot be read or the TOML is invalid.
pub fn load_config(path: &std::path::Path) -> anyhow::Result<(ResolvedDetectors, ResolvedConfig)> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;
    let cfg: Config = toml::from_str(&text)
        .with_context(|| format!("failed to parse config file: {}", path.display()))?;

    let (estimator, resolved_baseline) = build_estimator(cfg.baseline);

    let (emergency, resolved_emergency_thresholds) = if cfg.emergency_thresholds.is_empty() {
        (
            default_emergency_detector(),
            resolve_emergency_thresholds(&default_emergency_thresholds()),
        )
    } else {
        build_emergency_detector(cfg.emergency_thresholds)?
    };

    let rules = if cfg.alert_rules.is_empty() {
        default_alert_rules()
    } else {
        build_alert_rules(cfg.alert_rules)?
    };
    let resolved_alert_rules = rules.iter().map(resolve_alert_rule).collect();

    let (synflood_detector, synflood_alert_manager, resolved_synflood) =
        build_synflood(cfg.syn_flood);
    let (port_scan_detector, port_scan_alert_manager, resolved_port_scan) =
        build_port_scan(cfg.port_scan);

    let resolved = ResolvedConfig {
        baseline: resolved_baseline,
        alert_rules: resolved_alert_rules,
        emergency_thresholds: resolved_emergency_thresholds,
        syn_flood: resolved_synflood,
        port_scan: resolved_port_scan,
    };

    let detectors = ResolvedDetectors {
        baseline: estimator,
        emergency,
        alert_rules: rules,
        synflood_detector,
        synflood_alert_manager,
        port_scan_detector,
        port_scan_alert_manager,
    };

    Ok((detectors, resolved))
}

/// Resolves the effective configuration from an optional TOML file path,
/// falling back to compiled-in defaults when `config_path` is `None`.
///
/// Single entry point so callers (just `main.rs`) don't need to know about
/// the TOML-vs-defaults branching.
pub fn resolve_all(
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<(ResolvedDetectors, ResolvedConfig)> {
    match config_path {
        Some(path) => load_config(path),
        None => Ok((
            ResolvedDetectors {
                baseline: default_baseline_estimator(),
                emergency: default_emergency_detector(),
                alert_rules: default_alert_rules(),
                synflood_detector: default_synflood_detector(),
                synflood_alert_manager: default_synflood_alert_manager(),
                port_scan_detector: default_port_scan_detector(),
                port_scan_alert_manager: default_port_scan_alert_manager(),
            },
            default_resolved_config(),
        )),
    }
}

pub fn default_baseline_estimator() -> EwmaEstimator {
    build_estimator(None).0
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

fn default_emergency_thresholds() -> Vec<EmergencyThreshold> {
    vec![EmergencyThreshold {
        proto: ProtoIndex::Icmp,
        max_pps: Some(3.0),
        max_bps: None,
    }]
}

pub fn default_emergency_detector() -> EmergencyDetector {
    EmergencyDetector::new(default_emergency_thresholds())
}

pub fn default_synflood_detector() -> SynFloodDetector {
    build_synflood(None).0
}

pub fn default_synflood_alert_manager() -> SynFloodAlertManager {
    build_synflood(None).1
}

pub fn default_port_scan_detector() -> PortScanDetector {
    build_port_scan(None).0
}

pub fn default_port_scan_alert_manager() -> PortScanAlertManager {
    build_port_scan(None).1
}

/// Resolved view of [`default_baseline_estimator`] + [`default_alert_rules`] +
/// [`default_emergency_detector`] + [`default_synflood_detector`] +
/// [`default_port_scan_detector`], for the no-config-file startup path.
pub fn default_resolved_config() -> ResolvedConfig {
    ResolvedConfig {
        baseline: build_estimator(None).1,
        alert_rules: default_alert_rules()
            .iter()
            .map(resolve_alert_rule)
            .collect(),
        emergency_thresholds: resolve_emergency_thresholds(&default_emergency_thresholds()),
        syn_flood: build_synflood(None).2,
        port_scan: build_port_scan(None).2,
    }
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
        let (est, resolved) = build_estimator(None);
        // No samples fed — must still be in Warming state.
        assert!(matches!(
            est.snapshot(ProtoIndex::Tcp),
            BaselineState::Warming
        ));
        assert_eq!(resolved.alpha, 0.4);
        assert_eq!(resolved.min_samples, 5);
        assert_eq!(resolved.min_stddev, 1e-3);
        assert_eq!(resolved.min_elapsed_secs, 120);
    }

    #[test]
    fn build_estimator_applies_overrides_to_resolved_view() {
        let (_, resolved) = build_estimator(Some(BaselineConfig {
            alpha: Some(0.2),
            min_samples: Some(10),
            min_stddev: None,
            min_elapsed_secs: None,
        }));
        assert_eq!(resolved.alpha, 0.2);
        assert_eq!(resolved.min_samples, 10);
        // Omitted fields still fall back to defaults.
        assert_eq!(resolved.min_stddev, 1e-3);
        assert_eq!(resolved.min_elapsed_secs, 120);
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

    // ── build_synflood ───────────────────────────────────────────────────────

    #[test]
    fn build_synflood_none_uses_defaults() {
        let (_, _, resolved) = build_synflood(None);
        assert_eq!(resolved.max_syn_pps, 100.0);
        assert_eq!(resolved.top_n, 10);
        assert_eq!(resolved.cooldown_secs, 60);
        assert_eq!(resolved.consecutive_threshold, 3);
        assert_eq!(resolved.resolve_consecutive_threshold, 3);
    }

    #[test]
    fn build_synflood_applies_overrides() {
        let (_, _, resolved) = build_synflood(Some(SynFloodConfig {
            max_syn_pps: Some(50.0),
            top_n: Some(5),
            cooldown_secs: None,
            consecutive_threshold: None,
            resolve_consecutive_threshold: None,
        }));
        assert_eq!(resolved.max_syn_pps, 50.0);
        assert_eq!(resolved.top_n, 5);
        // Omitted fields still fall back to defaults.
        assert_eq!(resolved.cooldown_secs, 60);
        assert_eq!(resolved.consecutive_threshold, 3);
    }

    // ── build_port_scan ──────────────────────────────────────────────────────

    #[test]
    fn build_port_scan_none_uses_defaults() {
        let (_, _, resolved) = build_port_scan(None);
        assert_eq!(resolved.max_distinct_ports, 20);
        assert_eq!(resolved.window_secs, 30);
        assert_eq!(resolved.top_n, 10);
        assert_eq!(resolved.cooldown_secs, 60);
        assert_eq!(resolved.consecutive_threshold, 3);
        assert_eq!(resolved.resolve_consecutive_threshold, 3);
    }

    #[test]
    fn build_port_scan_applies_overrides() {
        let (_, _, resolved) = build_port_scan(Some(PortScanConfig {
            max_distinct_ports: Some(50),
            window_secs: Some(10),
            top_n: Some(5),
            cooldown_secs: None,
            consecutive_threshold: None,
            resolve_consecutive_threshold: None,
        }));
        assert_eq!(resolved.max_distinct_ports, 50);
        assert_eq!(resolved.window_secs, 10);
        assert_eq!(resolved.top_n, 5);
        // Omitted fields still fall back to defaults.
        assert_eq!(resolved.cooldown_secs, 60);
        assert_eq!(resolved.consecutive_threshold, 3);
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
        let (detectors, resolved) = load_config(&path).expect("should parse");
        let rules = detectors.alert_rules;
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].kind, AlertKind::Drop));
        assert!(matches!(rules[0].min_level, AnomalyLevel::Severe));

        assert_eq!(resolved.baseline.alpha, 0.2);
        assert_eq!(resolved.baseline.min_samples, 10);
        assert_eq!(resolved.alert_rules.len(), 1);
        assert_eq!(resolved.alert_rules[0].kind, "drop");
        assert_eq!(resolved.alert_rules[0].min_level, "severe");
    }

    #[test]
    fn load_config_with_synflood_overrides() {
        let path = std::env::temp_dir().join("test_config_synflood_overrides.toml");
        std::fs::write(
            &path,
            r#"
[syn_flood]
max_syn_pps = 250.0
top_n = 3
"#,
        )
        .unwrap();
        let (_, resolved) = load_config(&path).expect("should parse");
        assert_eq!(resolved.syn_flood.max_syn_pps, 250.0);
        assert_eq!(resolved.syn_flood.top_n, 3);
        // Omitted fields still fall back to defaults.
        assert_eq!(resolved.syn_flood.cooldown_secs, 60);
    }

    #[test]
    fn load_config_with_port_scan_overrides() {
        let path = std::env::temp_dir().join("test_config_port_scan_overrides.toml");
        std::fs::write(
            &path,
            r#"
[port_scan]
max_distinct_ports = 40
window_secs = 15
"#,
        )
        .unwrap();
        let (_, resolved) = load_config(&path).expect("should parse");
        assert_eq!(resolved.port_scan.max_distinct_ports, 40);
        assert_eq!(resolved.port_scan.window_secs, 15);
        // Omitted fields still fall back to defaults.
        assert_eq!(resolved.port_scan.top_n, 10);
    }

    // ── resolved config ──────────────────────────────────────────────────────

    #[test]
    fn default_resolved_config_matches_compiled_in_defaults() {
        let resolved = default_resolved_config();
        assert_eq!(resolved.baseline.alpha, 0.4);
        assert_eq!(resolved.baseline.min_samples, 5);
        assert_eq!(resolved.alert_rules.len(), default_alert_rules().len());
        assert_eq!(resolved.alert_rules[0].kind, "spike");
        assert_eq!(resolved.alert_rules[1].kind, "emergency");
        assert_eq!(resolved.emergency_thresholds.len(), 1);
        assert_eq!(resolved.emergency_thresholds[0].proto, "icmp");
        assert_eq!(resolved.emergency_thresholds[0].max_pps, Some(3.0));
    }

    #[test]
    fn default_resolved_config_includes_synflood_defaults() {
        let resolved = default_resolved_config();
        assert_eq!(resolved.syn_flood.max_syn_pps, 100.0);
        assert_eq!(resolved.syn_flood.top_n, 10);
    }

    #[test]
    fn default_resolved_config_includes_port_scan_defaults() {
        let resolved = default_resolved_config();
        assert_eq!(resolved.port_scan.max_distinct_ports, 20);
        assert_eq!(resolved.port_scan.window_secs, 30);
    }

    #[test]
    fn resolve_all_none_matches_defaults() {
        let (detectors, resolved) = resolve_all(None).expect("should resolve defaults");
        assert_eq!(detectors.alert_rules.len(), default_alert_rules().len());
        assert_eq!(resolved.baseline.alpha, 0.4);
    }

    #[test]
    fn resolve_all_some_path_loads_file() {
        let path = std::env::temp_dir().join("test_resolve_all_path.toml");
        std::fs::write(&path, "[baseline]\nalpha = 0.7\n").unwrap();
        let (_, resolved) = resolve_all(Some(&path)).expect("should resolve from file");
        assert_eq!(resolved.baseline.alpha, 0.7);
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
