//! Pushes fired/resolved/heartbeat alerts to a Prometheus Alertmanager
//! instance via its `POST /api/v2/alerts` HTTP API.
//!
//! This is the first outbound network client in the codebase — everything
//! else here is either kernel-ingress (XDP) or a server accepting inbound
//! connections (the Axum API, the Prometheus exporter). It's also the first
//! use of a channel: `tick()` stays synchronous (an `.await` inside
//! `main.rs`'s `select!` loop would change its blocking characteristics), so
//! [`AlertmanagerSink::push`] enqueues onto a bounded channel and a
//! separately-spawned background task owns the actual async HTTP POSTs.
use std::{collections::BTreeMap, time::SystemTime};

use crate::alert::{Alert, PortScanAlert, SynFloodAlert};

fn rfc3339(t: SystemTime) -> String {
    humantime::format_rfc3339(t).to_string()
}

/// Wire format for one entry of Alertmanager's `POST /api/v2/alerts` array.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AlertmanagerAlert {
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    #[serde(rename = "startsAt")]
    pub starts_at: String,
    #[serde(rename = "endsAt", skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<String>,
    #[serde(rename = "generatorURL", skip_serializing_if = "Option::is_none")]
    pub generator_url: Option<String>,
}

/// Converts a proto+kind [`Alert`] to Alertmanager's wire format.
///
/// `ends_at = None` covers both a `Fired` transition and a heartbeat
/// re-affirmation of a still-active alert — both leave the alert open in
/// Alertmanager. `ends_at = Some(now)` marks a `Resolved` transition.
///
/// `level`/`confidence` go in `annotations`, never `labels`: they can differ
/// between the `Fired` and `Resolved` event for the *same* underlying alert
/// (`alert::proto_manager`'s `advance_states` sources a `Resolved` event's
/// `level`/`confidence` from the rule's `min_level`/`0.0`, not the original
/// firing signal) — putting them in `labels` would give Alertmanager two
/// different fingerprints for what should be one alert, so it would never
/// actually resolve.
pub fn alert_to_wire(
    alert: &Alert,
    now: SystemTime,
    ends_at: Option<SystemTime>,
    generator_url: Option<&str>,
) -> AlertmanagerAlert {
    let labels = BTreeMap::from([
        ("alertname".to_string(), "XdpTrafficAnomaly".to_string()),
        ("proto".to_string(), alert.proto.label().to_string()),
        ("kind".to_string(), alert.kind.label().to_string()),
    ]);
    let annotations = BTreeMap::from([
        ("level".to_string(), alert.level.label().to_string()),
        ("confidence".to_string(), format!("{:.3}", alert.confidence)),
        (
            "summary".to_string(),
            format!(
                "{} {} anomaly on {} traffic",
                alert.level.label(),
                alert.kind.label(),
                alert.proto.label()
            ),
        ),
    ]);

    AlertmanagerAlert {
        labels,
        annotations,
        starts_at: rfc3339(now),
        ends_at: ends_at.map(rfc3339),
        generator_url: generator_url.map(str::to_string),
    }
}

/// Converts a [`SynFloodAlert`] to Alertmanager's wire format. See
/// [`alert_to_wire`] for the `ends_at` and label/annotation split rationale
/// — `pps`/`confidence` are annotations only, `src_ip` is the only label
/// stable across an alert's full Fired-to-Resolved lifetime.
pub fn synflood_alert_to_wire(
    alert: &SynFloodAlert,
    now: SystemTime,
    ends_at: Option<SystemTime>,
    generator_url: Option<&str>,
) -> AlertmanagerAlert {
    let labels = BTreeMap::from([
        ("alertname".to_string(), "XdpSynFlood".to_string()),
        ("src_ip".to_string(), alert.src_ip.to_string()),
    ]);
    let annotations = BTreeMap::from([
        ("pps".to_string(), format!("{:.1}", alert.pps)),
        ("confidence".to_string(), format!("{:.3}", alert.confidence)),
        (
            "summary".to_string(),
            format!("SYN-flood from {}", alert.src_ip),
        ),
    ]);

    AlertmanagerAlert {
        labels,
        annotations,
        starts_at: rfc3339(now),
        ends_at: ends_at.map(rfc3339),
        generator_url: generator_url.map(str::to_string),
    }
}

/// Converts a [`PortScanAlert`] to Alertmanager's wire format. Same
/// rationale as [`synflood_alert_to_wire`].
pub fn port_scan_alert_to_wire(
    alert: &PortScanAlert,
    now: SystemTime,
    ends_at: Option<SystemTime>,
    generator_url: Option<&str>,
) -> AlertmanagerAlert {
    let labels = BTreeMap::from([
        ("alertname".to_string(), "XdpPortScan".to_string()),
        ("src_ip".to_string(), alert.src_ip.to_string()),
    ]);
    let annotations = BTreeMap::from([
        (
            "distinct_ports".to_string(),
            alert.distinct_ports.to_string(),
        ),
        ("confidence".to_string(), format!("{:.3}", alert.confidence)),
        (
            "summary".to_string(),
            format!("Port scan from {}", alert.src_ip),
        ),
    ]);

    AlertmanagerAlert {
        labels,
        annotations,
        starts_at: rfc3339(now),
        ends_at: ends_at.map(rfc3339),
        generator_url: generator_url.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ebpf_xdp_program_common::ProtoIndex;

    use super::*;
    use crate::{alert::AlertKind, anomaly::AnomalyLevel};

    #[test]
    fn alert_to_wire_fired_has_no_ends_at() {
        let alert = Alert {
            proto: ProtoIndex::Tcp,
            kind: AlertKind::Spike,
            level: AnomalyLevel::Severe,
            confidence: 1.0,
        };
        let wire = alert_to_wire(&alert, SystemTime::now(), None, None);
        assert_eq!(wire.ends_at, None);
        assert_eq!(wire.labels["alertname"], "XdpTrafficAnomaly");
        assert_eq!(wire.labels["proto"], "TCP");
        assert_eq!(wire.labels["kind"], "spike");
    }

    #[test]
    fn alert_to_wire_resolved_has_ends_at() {
        let alert = Alert {
            proto: ProtoIndex::Tcp,
            kind: AlertKind::Spike,
            level: AnomalyLevel::Suspicious,
            confidence: 0.0,
        };
        let now = SystemTime::now();
        let wire = alert_to_wire(&alert, now, Some(now), None);
        assert!(wire.ends_at.is_some());
    }

    /// Alertmanager correlates Fired<->Resolved purely by exact label-set
    /// equality. A `Resolved` event's `level`/`confidence` come from the
    /// rule's `min_level`/`0.0` (see `alert::proto_manager::advance_states`),
    /// not the original firing signal, so if these fields leaked into
    /// labels, Fired and Resolved would get different fingerprints and
    /// Alertmanager would never actually resolve the alert.
    #[test]
    fn alert_to_wire_labels_stable_across_fired_and_resolved() {
        let fired = Alert {
            proto: ProtoIndex::Tcp,
            kind: AlertKind::Spike,
            level: AnomalyLevel::Severe,
            confidence: 1.0,
        };
        let resolved = Alert {
            proto: ProtoIndex::Tcp,
            kind: AlertKind::Spike,
            level: AnomalyLevel::Suspicious, // rule.min_level placeholder
            confidence: 0.0,
        };
        let now = SystemTime::now();
        let fired_wire = alert_to_wire(&fired, now, None, None);
        let resolved_wire = alert_to_wire(&resolved, now, Some(now), None);
        assert_eq!(fired_wire.labels, resolved_wire.labels);
    }

    #[test]
    fn synflood_alert_to_wire_labels_stable_across_pps_change() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let a = SynFloodAlert {
            src_ip: ip,
            pps: 5000.0,
            confidence: 1.0,
        };
        let b = SynFloodAlert {
            src_ip: ip,
            pps: 0.0,
            confidence: 0.0,
        };
        let now = SystemTime::now();
        let wire_a = synflood_alert_to_wire(&a, now, None, None);
        let wire_b = synflood_alert_to_wire(&b, now, Some(now), None);
        assert_eq!(wire_a.labels, wire_b.labels);
        assert_eq!(wire_a.labels["src_ip"], "10.0.0.1");
    }

    #[test]
    fn port_scan_alert_to_wire_labels_stable_across_distinct_ports_change() {
        let ip = Ipv4Addr::new(10, 0, 0, 2);
        let a = PortScanAlert {
            src_ip: ip,
            distinct_ports: 50,
            confidence: 1.0,
        };
        let b = PortScanAlert {
            src_ip: ip,
            distinct_ports: 0,
            confidence: 0.0,
        };
        let now = SystemTime::now();
        let wire_a = port_scan_alert_to_wire(&a, now, None, None);
        let wire_b = port_scan_alert_to_wire(&b, now, Some(now), None);
        assert_eq!(wire_a.labels, wire_b.labels);
    }

    #[test]
    fn generator_url_none_omits_field_from_json() {
        let alert = Alert {
            proto: ProtoIndex::Tcp,
            kind: AlertKind::Emergency,
            level: AnomalyLevel::Severe,
            confidence: 1.0,
        };
        let wire = alert_to_wire(&alert, SystemTime::now(), None, None);
        let json = serde_json::to_value(&wire).unwrap();
        assert!(json.get("generatorURL").is_none());
        assert!(json.get("endsAt").is_none());
    }

    #[test]
    fn generator_url_some_is_included_in_json() {
        let alert = Alert {
            proto: ProtoIndex::Tcp,
            kind: AlertKind::Emergency,
            level: AnomalyLevel::Severe,
            confidence: 1.0,
        };
        let wire = alert_to_wire(
            &alert,
            SystemTime::now(),
            None,
            Some("http://localhost:8080/anomalies"),
        );
        let json = serde_json::to_value(&wire).unwrap();
        assert_eq!(json["generatorURL"], "http://localhost:8080/anomalies");
    }
}
