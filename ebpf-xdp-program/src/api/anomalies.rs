use axum::{Json, extract::State};
use serde::Serialize;

use crate::{
    api::ApiContext,
    baseline::BaselineState,
    pipeline::{AlertSlotSnapshot, ProtoSnapshot, RunnerSnapshot},
};

#[derive(Debug, Serialize)]
pub struct AnomaliesResponse {
    pub protocols: Vec<ProtoAnomalyView>,
}

/// JSON view of one protocol's anomaly/alert state.
///
/// `pps`/`bps`/`z_score_*`/`level`/`confidence` are `None` until the runner
/// has processed at least two counter snapshots; the baseline-related fields
/// are `None` while still warming.
#[derive(Debug, Serialize)]
pub struct ProtoAnomalyView {
    /// Lowercased from `ProtoIndex::label()` for consistency with the
    /// lowercase `kind`/`level` labels below (see the note on
    /// `config::ResolvedEmergencyThresholdConfig`).
    pub proto: String,
    pub pps: Option<f64>,
    pub bps: Option<f64>,
    pub baseline_ready: bool,
    pub baseline_pps_mean: Option<f64>,
    pub baseline_pps_stddev: Option<f64>,
    pub baseline_bps_mean: Option<f64>,
    pub baseline_bps_stddev: Option<f64>,
    pub z_score_pps: Option<f64>,
    pub z_score_bps: Option<f64>,
    pub level: Option<&'static str>,
    pub confidence: Option<f64>,
    pub frozen: bool,
    pub alerts: Vec<AlertSlotView>,
}

#[derive(Debug, Serialize)]
pub struct AlertSlotView {
    pub kind: &'static str,
    pub phase: &'static str,
    pub consecutive_count: u32,
}

pub async fn handler(State(ctx): State<ApiContext>) -> Json<AnomaliesResponse> {
    let state = ctx.dynamic.read().await;
    let protocols = match &state.runner_snapshot {
        Some(snapshot) => to_view(snapshot),
        // No anomaly-eval tick has run yet.
        None => vec![],
    };
    Json(AnomaliesResponse { protocols })
}

fn to_view(snapshot: &RunnerSnapshot) -> Vec<ProtoAnomalyView> {
    snapshot.protos.iter().map(proto_view).collect()
}

fn proto_view(p: &ProtoSnapshot) -> ProtoAnomalyView {
    let (baseline_ready, pps_mean, pps_stddev, bps_mean, bps_stddev) = match &p.baseline {
        BaselineState::Ready { baseline } => (
            true,
            Some(baseline.pps.mean),
            Some(baseline.pps.stddev),
            Some(baseline.bps.mean),
            Some(baseline.bps.stddev),
        ),
        BaselineState::Warming => (false, None, None, None, None),
    };

    ProtoAnomalyView {
        proto: p.proto.label().to_ascii_lowercase(),
        pps: p.rate.as_ref().map(|r| r.pps),
        bps: p.rate.as_ref().map(|r| r.bps),
        baseline_ready,
        baseline_pps_mean: pps_mean,
        baseline_pps_stddev: pps_stddev,
        baseline_bps_mean: bps_mean,
        baseline_bps_stddev: bps_stddev,
        z_score_pps: p.anomaly.map(|a| a.z_pps),
        z_score_bps: p.anomaly.map(|a| a.z_bps),
        level: p.anomaly.map(|a| a.level.label()),
        confidence: p.anomaly.map(|a| a.confidence),
        frozen: p.frozen,
        alerts: p.alerts.iter().map(alert_slot_view).collect(),
    }
}

fn alert_slot_view(a: &AlertSlotSnapshot) -> AlertSlotView {
    AlertSlotView {
        kind: a.kind.label(),
        phase: a.phase_label,
        consecutive_count: a.consecutive_count,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ebpf_xdp_program_common::ProtoIndex;
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        alert::{AlertKind, AlertLifecycleManager},
        api::{self, make_ctx},
        config::{default_alert_rules, default_baseline_estimator, default_emergency_detector},
        pipeline::AnomalyRunner,
    };

    #[tokio::test]
    async fn anomalies_empty_before_any_tick() {
        let ctx = make_ctx();
        let router = api::router(ctx);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/anomalies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["protocols"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn anomalies_reflects_runner_snapshot_after_a_tick() {
        let mut runner = AnomalyRunner::new(
            default_baseline_estimator(),
            default_emergency_detector(),
            AlertLifecycleManager::new(default_alert_rules()),
        );
        let t1 = std::time::Instant::now();
        let t2 = t1 + Duration::from_secs(1);
        let snap1 = crate::rate::TrafficCountersSnapshot {
            timestamp: t1,
            stats: (0..ProtoIndex::COUNT as usize)
                .map(|_| crate::rate::model::TrafficCounters {
                    packets: 100,
                    bytes: 10_000,
                })
                .collect(),
        };
        let snap2 = crate::rate::TrafficCountersSnapshot {
            timestamp: t2,
            stats: (0..ProtoIndex::COUNT as usize)
                .map(|_| crate::rate::model::TrafficCounters {
                    packets: 200,
                    bytes: 20_000,
                })
                .collect(),
        };
        runner.tick(&Some(snap1), &crate::metrics::MetricsHandle);
        runner.tick(&Some(snap2), &crate::metrics::MetricsHandle);

        let ctx = make_ctx();
        {
            let mut state = ctx.dynamic.write().await;
            state.runner_snapshot = Some(runner.snapshot(t2));
        }
        let router = api::router(ctx);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/anomalies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let protocols = parsed["protocols"].as_array().unwrap();
        assert_eq!(protocols.len(), ProtoIndex::COUNT as usize);
        let tcp = protocols
            .iter()
            .find(|p| p["proto"] == "tcp")
            .expect("tcp entry present");
        assert!(tcp["pps"].is_number(), "rate should be populated");
        assert_eq!(tcp["baseline_ready"], false);
    }

    #[test]
    fn alert_slot_view_maps_fields() {
        let slot = AlertSlotSnapshot {
            kind: AlertKind::Spike,
            phase_label: "firing",
            consecutive_count: 5,
        };
        let view = alert_slot_view(&slot);
        assert_eq!(view.kind, "spike");
        assert_eq!(view.phase, "firing");
        assert_eq!(view.consecutive_count, 5);
    }

    #[test]
    fn proto_view_warming_has_no_anomaly_when_rate_absent() {
        let snapshot = ProtoSnapshot {
            proto: ProtoIndex::Tcp,
            rate: None,
            baseline: BaselineState::Warming,
            anomaly: None,
            alerts: vec![],
            frozen: false,
        };
        let view = proto_view(&snapshot);
        assert_eq!(view.proto, "tcp");
        assert!(view.pps.is_none());
        assert!(!view.baseline_ready);
        assert!(view.level.is_none());
    }
}
