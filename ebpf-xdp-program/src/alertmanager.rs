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
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};

use tokio::{
    sync::mpsc::{self, error::TrySendError},
    task::JoinHandle,
};

use crate::{
    alert::{Alert, AlertLifecycle, PortScanAlert, SynFloodAlert},
    config::ResolvedAlertmanagerConfig,
    metrics::MetricsHandle,
};

/// Capacity of the channel from `tick()`'s synchronous `push()` calls to the
/// background dispatcher task. Bounded (not unbounded): the risk isn't a
/// dead receiver (that already fails fast via `TrySendError::Closed`) but a
/// slow-but-alive one stuck retrying during an Alertmanager outage, which
/// would otherwise grow memory without limit for the outage's duration.
const DISPATCH_CHANNEL_CAPACITY: usize = 256;
/// Caps how many queued alerts one dispatcher iteration batches into a
/// single POST, so a large backlog doesn't produce one unbounded request.
const MAX_BATCH: usize = 64;
const RETRY_ATTEMPTS: u32 = 3;
const RETRY_BASE_DELAY: Duration = Duration::from_millis(300);

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

/// Converts and pushes one tick's alert transitions and heartbeats onto
/// `sink` via `to_wire`; a no-op if `sink` is `None`.
///
/// `to_wire` is a plain fn pointer generic over `T`, not a trait bound:
/// `alert_to_wire`/`synflood_alert_to_wire`/`port_scan_alert_to_wire`
/// already share this exact signature, so no new trait is needed to make
/// them pluggable here.
pub fn dispatch_tick_alerts<'a, T: 'a>(
    sink: Option<&AlertmanagerSink>,
    generator_url: Option<&str>,
    transitions: impl IntoIterator<Item = (&'a T, AlertLifecycle)>,
    heartbeats: impl IntoIterator<Item = &'a T>,
    to_wire: fn(&T, SystemTime, Option<SystemTime>, Option<&str>) -> AlertmanagerAlert,
) {
    let Some(sink) = sink else { return };
    let now = SystemTime::now();
    for (alert, lifecycle) in transitions {
        let ends_at = matches!(lifecycle, AlertLifecycle::Resolved).then_some(now);
        sink.push(to_wire(alert, now, ends_at, generator_url));
    }
    for hb in heartbeats {
        sink.push(to_wire(hb, now, None, generator_url));
    }
}

/// Non-blocking handle for enqueuing alerts to the background dispatcher
/// task. Cheap to clone (wraps a `tokio::sync::mpsc::Sender`).
#[derive(Clone)]
pub struct AlertmanagerSink {
    tx: mpsc::Sender<AlertmanagerAlert>,
}

impl AlertmanagerSink {
    /// Enqueues `alert` for delivery. Never blocks the caller — called from
    /// `tick()`'s synchronous path — so a full queue or a dead dispatcher
    /// task just drops the alert (counted/logged) rather than waiting.
    pub fn push(&self, alert: AlertmanagerAlert) {
        match self.tx.try_send(alert) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                MetricsHandle.record_alertmanager_dropped();
                tracing::warn!("Alertmanager dispatch queue full; dropping alert");
            }
            Err(TrySendError::Closed(_)) => {
                tracing::debug!("Alertmanager dispatcher task not running; dropping alert");
            }
        }
    }
}

/// Builds the HTTP client and spawns the background dispatcher task if
/// Alertmanager pushing is enabled. Returns `None` (a no-op) otherwise.
///
/// Relies on [`crate::config::build_alertmanager`]'s invariant that `url` is
/// always `Some` when `cfg.enabled` — that's validated at config-load time,
/// not here.
///
/// The `JoinHandle` resolves once every `AlertmanagerSink` clone is dropped
/// and [`run_dispatcher`] has drained its queue.
pub fn maybe_spawn(cfg: &ResolvedAlertmanagerConfig) -> Option<(AlertmanagerSink, JoinHandle<()>)> {
    if !cfg.enabled {
        return None;
    }
    let url = cfg
        .url
        .clone()
        .expect("ResolvedAlertmanagerConfig::enabled implies url is Some");

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_secs))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            tracing::error!(
                error = %e,
                "failed to build Alertmanager HTTP client; alerts will not be pushed"
            );
            return None;
        }
    };

    let (tx, rx) = mpsc::channel(DISPATCH_CHANNEL_CAPACITY);
    let task = tokio::task::spawn(run_dispatcher(rx, client, url));
    Some((AlertmanagerSink { tx }, task))
}

/// Drains the channel, batching bursts into single POSTs, until the sink
/// (and every clone of it) is dropped.
async fn run_dispatcher(
    mut rx: mpsc::Receiver<AlertmanagerAlert>,
    client: reqwest::Client,
    url: String,
) {
    while let Some(first) = rx.recv().await {
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(next) => batch.push(next),
                Err(_) => break,
            }
        }

        match post_with_retry(&client, &url, &batch).await {
            Ok(()) => MetricsHandle.record_alertmanager_push(true),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    count = batch.len(),
                    "failed to push alert batch to Alertmanager after retries; dropping"
                );
                MetricsHandle.record_alertmanager_push(false);
            }
        }
    }
    tracing::info!("Alertmanager dispatcher exiting: all senders dropped");
}

/// POSTs `batch` to Alertmanager, retrying transport errors and 5xx
/// responses with exponential backoff. Does not retry 4xx responses — a
/// rejected payload is a bug, not a transient failure, so retrying just
/// wastes time and delays surfacing the error.
async fn post_with_retry(
    client: &reqwest::Client,
    url: &str,
    batch: &[AlertmanagerAlert],
) -> anyhow::Result<()> {
    let mut last_err = anyhow::anyhow!("post_with_retry called with RETRY_ATTEMPTS == 0");

    for attempt in 0..RETRY_ATTEMPTS {
        match client.post(url).json(batch).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) if resp.status().is_client_error() => {
                return Err(anyhow::anyhow!(
                    "alertmanager rejected the payload: {}",
                    resp.status()
                ));
            }
            Ok(resp) => {
                last_err = anyhow::anyhow!("alertmanager returned {}", resp.status());
            }
            Err(e) => last_err = anyhow::Error::from(e),
        }

        if attempt + 1 < RETRY_ATTEMPTS {
            tokio::time::sleep(RETRY_BASE_DELAY * 2u32.pow(attempt)).await;
        }
    }

    Err(last_err)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ebpf_xdp_program_common::ProtoIndex;

    use super::*;
    use crate::{
        alert::{AlertKind, AlertRule},
        anomaly::AnomalyLevel,
    };

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

    fn sample_alert() -> AlertmanagerAlert {
        alert_to_wire(
            &Alert {
                proto: ProtoIndex::Tcp,
                kind: AlertKind::Spike,
                level: AnomalyLevel::Severe,
                confidence: 1.0,
            },
            SystemTime::now(),
            None,
            None,
        )
    }

    #[test]
    fn dispatch_tick_alerts_is_noop_when_sink_none() {
        let alert = Alert {
            proto: ProtoIndex::Tcp,
            kind: AlertKind::Spike,
            level: AnomalyLevel::Severe,
            confidence: 1.0,
        };
        // Non-empty transitions/heartbeats: would panic if the `sink.is_none()`
        // short-circuit were ever replaced with a force-unwrap.
        dispatch_tick_alerts(
            None,
            None,
            [(&alert, AlertLifecycle::Fired)],
            [&alert],
            alert_to_wire,
        );
    }

    #[test]
    fn dispatch_tick_alerts_marks_only_resolved_transitions_with_ends_at() {
        let (tx, mut rx) = mpsc::channel(4);
        let sink = AlertmanagerSink { tx };
        let fired = Alert {
            proto: ProtoIndex::Tcp,
            kind: AlertKind::Spike,
            level: AnomalyLevel::Severe,
            confidence: 1.0,
        };
        let resolved = Alert {
            proto: ProtoIndex::Udp,
            kind: AlertKind::Drop,
            level: AnomalyLevel::Suspicious,
            confidence: 0.0,
        };

        dispatch_tick_alerts(
            Some(&sink),
            None,
            [
                (&fired, AlertLifecycle::Fired),
                (&resolved, AlertLifecycle::Resolved),
            ],
            std::iter::empty(),
            alert_to_wire,
        );

        assert_eq!(rx.try_recv().unwrap().ends_at, None);
        assert!(rx.try_recv().unwrap().ends_at.is_some());
        assert!(rx.try_recv().is_err(), "no further alerts expected");
    }

    #[test]
    fn dispatch_tick_alerts_heartbeats_never_have_ends_at() {
        let (tx, mut rx) = mpsc::channel(4);
        let sink = AlertmanagerSink { tx };
        let alert = Alert {
            proto: ProtoIndex::Tcp,
            kind: AlertKind::Spike,
            level: AnomalyLevel::Severe,
            confidence: 1.0,
        };

        dispatch_tick_alerts(
            Some(&sink),
            None,
            std::iter::empty(),
            [&alert],
            alert_to_wire,
        );

        assert_eq!(rx.try_recv().unwrap().ends_at, None);
        assert!(rx.try_recv().is_err(), "no further alerts expected");
    }

    #[test]
    fn push_drops_when_channel_full_without_blocking() {
        let (tx, mut rx) = mpsc::channel(1);
        let sink = AlertmanagerSink { tx };

        sink.push(sample_alert()); // fills the one slot
        sink.push(sample_alert()); // channel full: dropped, not blocked/panicked

        assert!(rx.try_recv().is_ok(), "first push should have gone through");
        assert!(
            rx.try_recv().is_err(),
            "second push should have been dropped, not queued"
        );
    }

    #[test]
    fn push_after_receiver_dropped_does_not_panic() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let sink = AlertmanagerSink { tx };
        sink.push(sample_alert()); // dispatcher gone: should log and return, not panic
    }

    /// Spins up a throwaway Axum server bound to an ephemeral localhost port
    /// that records every POSTed JSON body into the returned `Arc<Mutex<_>>`,
    /// mirroring `api::serve`'s own bind pattern. Used as a stand-in
    /// Alertmanager for dispatcher tests, avoiding a new mock-server
    /// dev-dependency since axum is already in the dependency tree.
    async fn spawn_recording_server() -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let received_for_handler = received.clone();
        let app = axum::Router::new().route(
            "/api/v2/alerts",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let received = received_for_handler.clone();
                async move {
                    received.lock().unwrap().push(body);
                    axum::http::StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/api/v2/alerts"), received)
    }

    /// Spins up a server that always responds 500, counting requests it saw.
    async fn spawn_always_failing_server() -> (String, std::sync::Arc<std::sync::atomic::AtomicU32>)
    {
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let attempts_for_handler = attempts.clone();
        let app = axum::Router::new().route(
            "/api/v2/alerts",
            axum::routing::post(move || {
                let attempts = attempts_for_handler.clone();
                async move {
                    attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/api/v2/alerts"), attempts)
    }

    #[tokio::test]
    async fn post_with_retry_delivers_batch_on_success() {
        let (url, received) = spawn_recording_server().await;
        let client = reqwest::Client::new();
        let batch = vec![sample_alert()];

        post_with_retry(&client, &url, &batch)
            .await
            .expect("mock server returns 200");

        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1, "expected exactly one POST");
        assert_eq!(got[0][0]["labels"]["alertname"], "XdpTrafficAnomaly");
    }

    #[tokio::test]
    async fn post_with_retry_gives_up_after_max_attempts_on_500() {
        let (url, attempts) = spawn_always_failing_server().await;
        let client = reqwest::Client::new();
        let batch = vec![sample_alert()];

        let result = post_with_retry(&client, &url, &batch).await;

        assert!(result.is_err(), "should give up after exhausting retries");
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            RETRY_ATTEMPTS,
            "should have attempted exactly RETRY_ATTEMPTS times, no more no less"
        );
    }

    #[tokio::test]
    async fn dispatcher_delivers_pushed_alerts_end_to_end() {
        let (url, received) = spawn_recording_server().await;
        let client = reqwest::Client::new();
        let (tx, rx) = mpsc::channel(DISPATCH_CHANNEL_CAPACITY);
        tokio::spawn(run_dispatcher(rx, client, url));
        let sink = AlertmanagerSink { tx };

        sink.push(sample_alert());

        // The dispatcher task runs on its own schedule; poll briefly rather
        // than assume a fixed delay is enough.
        for _ in 0..100 {
            if !received.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(received.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn dispatcher_task_exits_after_draining_queue_once_sink_dropped() {
        let (url, received) = spawn_recording_server().await;
        let client = reqwest::Client::new();
        let (tx, rx) = mpsc::channel(DISPATCH_CHANNEL_CAPACITY);
        let task = tokio::spawn(run_dispatcher(rx, client, url));
        let sink = AlertmanagerSink { tx };

        sink.push(sample_alert());
        drop(sink);

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("dispatcher should exit promptly once all senders are dropped")
            .expect("dispatcher task should not panic");
        assert_eq!(received.lock().unwrap().len(), 1);
    }

    /// End-to-end: a real `AnomalyRunner` warms up its baseline and fires on
    /// an injected spike, then `dispatch_tick_alerts` carries that transition
    /// through a real dispatcher task to a mock Alertmanager HTTP endpoint.
    #[tokio::test]
    async fn pipeline_to_alertmanager_end_to_end() {
        use std::time::Instant;

        use crate::{
            alert::AlertLifecycleManager,
            baseline::EwmaEstimator,
            config::default_emergency_detector,
            metrics::MetricsHandle,
            pipeline::AnomalyRunner,
            rate::{TrafficCountersSnapshot, model::TrafficCounters},
        };

        fn snapshot(
            t: Instant,
            other_pkts: u64,
            other_bytes: u64,
            tcp_pkts: u64,
            tcp_bytes: u64,
        ) -> TrafficCountersSnapshot {
            let stats = (0..ProtoIndex::COUNT as usize)
                .map(|i| {
                    if ProtoIndex::from_index(i) == Some(ProtoIndex::Tcp) {
                        TrafficCounters {
                            packets: tcp_pkts,
                            bytes: tcp_bytes,
                        }
                    } else {
                        TrafficCounters {
                            packets: other_pkts,
                            bytes: other_bytes,
                        }
                    }
                })
                .collect();
            TrafficCountersSnapshot {
                timestamp: t,
                stats,
            }
        }

        let (url, received) = spawn_recording_server().await;
        let client = reqwest::Client::new();
        let (tx, rx) = mpsc::channel(DISPATCH_CHANNEL_CAPACITY);
        tokio::spawn(run_dispatcher(rx, client, url));
        let sink = AlertmanagerSink { tx };

        // min_samples=10, no time gate, so a handful of ticks is enough to warm up.
        let estimator = EwmaEstimator::new(0.4, 10, 1e-3, 0);
        let mut runner = AnomalyRunner::new(
            estimator,
            default_emergency_detector(),
            AlertLifecycleManager::new(vec![AlertRule {
                kind: AlertKind::Spike,
                min_level: AnomalyLevel::Suspicious,
                min_confidence: 0.0,
                cooldown: Duration::ZERO,
                consecutive_threshold: 1,
                resolve_consecutive_threshold: 1,
                freezes_baseline: false,
            }]),
        );

        let mut t = Instant::now();
        let mut pkts = 100u64;
        let mut bytes = 10_000u64;
        runner.tick(&Some(snapshot(t, pkts, bytes, pkts, bytes)), &MetricsHandle); // prime

        // Alternating deltas build variance above min_stddev quickly.
        for i in 0..20 {
            t += Duration::from_secs(1);
            if i % 2 == 0 {
                pkts += 100;
                bytes += 10_000;
            } else {
                pkts += 50;
                bytes += 5_000;
            }
            runner.tick(&Some(snapshot(t, pkts, bytes, pkts, bytes)), &MetricsHandle);
        }
        assert!(runner.warmed_up(), "baseline should be ready by now");

        // TCP jumps >> 6σ above baseline; other protocols keep oscillating so only TCP fires.
        t += Duration::from_secs(1);
        let tcp_pkts = pkts + 10_000_000;
        let tcp_bytes = bytes + 1_000_000_000;
        pkts += 100;
        bytes += 10_000;
        let alerts = runner.tick(
            &Some(snapshot(t, pkts, bytes, tcp_pkts, tcp_bytes)),
            &MetricsHandle,
        );
        assert!(
            !alerts.transitions.is_empty(),
            "expected the injected spike to fire an alert"
        );

        dispatch_tick_alerts(
            Some(&sink),
            Some("http://test-host:8080/anomalies"),
            alerts.transitions.iter().map(|e| (&e.alert, e.lifecycle)),
            alerts.heartbeats.iter(),
            alert_to_wire,
        );

        for _ in 0..100 {
            if !received.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let got = received.lock().unwrap();
        assert_eq!(got.len(), 1, "expected exactly one batched POST");
        let posted_alert = &got[0][0];
        assert_eq!(posted_alert["labels"]["alertname"], "XdpTrafficAnomaly");
        assert_eq!(posted_alert["labels"]["proto"], "TCP");
        assert_eq!(posted_alert["labels"]["kind"], "spike");
        assert_eq!(
            posted_alert["generatorURL"], "http://test-host:8080/anomalies",
            "generator_url passed to dispatch_tick_alerts should reach the wire payload"
        );
        assert!(
            posted_alert.get("endsAt").is_none(),
            "a Fired transition must not carry endsAt"
        );
    }
}
