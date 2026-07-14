use axum::{Json, extract::State};
use serde::Serialize;

use crate::{api::ApiContext, pipeline::SynFloodSnapshot};

/// Bounded top-N view of current SYN-flood state — never an unbounded dump,
/// since source-IP cardinality is attacker-controlled.
#[derive(Debug, Serialize)]
pub struct SynFloodResponse {
    pub top_offenders: Vec<SynFloodOffenderView>,
    pub active_alert_count: usize,
}

#[derive(Debug, Serialize)]
pub struct SynFloodOffenderView {
    pub src_ip: String,
    pub pps: f64,
    pub alert_phase: Option<&'static str>,
    pub alert_consecutive_count: Option<u32>,
}

pub async fn handler(State(ctx): State<ApiContext>) -> Json<SynFloodResponse> {
    let state = ctx.dynamic.read().await;
    let response = match &state.synflood_snapshot {
        Some(snapshot) => to_view(snapshot),
        // No SYN-flood eval tick has run yet.
        None => SynFloodResponse {
            top_offenders: vec![],
            active_alert_count: 0,
        },
    };
    Json(response)
}

fn to_view(snapshot: &SynFloodSnapshot) -> SynFloodResponse {
    let top_offenders = snapshot
        .top_offenders
        .iter()
        .map(|r| {
            let alert = snapshot.alerts.iter().find(|a| a.src_ip == r.src_ip);
            SynFloodOffenderView {
                src_ip: r.src_ip.to_string(),
                pps: r.pps,
                alert_phase: alert.map(|a| a.phase_label),
                alert_consecutive_count: alert.map(|a| a.consecutive_count),
            }
        })
        .collect();
    SynFloodResponse {
        top_offenders,
        active_alert_count: snapshot.alerts.len(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        alert::SynFloodAlertSlotSnapshot,
        api::{self, make_ctx},
        rate::SynIpRate,
    };

    #[tokio::test]
    async fn synflood_empty_before_any_tick() {
        let ctx = make_ctx();
        let router = api::router(ctx);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/synflood")
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
        assert!(parsed["top_offenders"].as_array().unwrap().is_empty());
        assert_eq!(parsed["active_alert_count"], 0);
    }

    #[tokio::test]
    async fn synflood_reflects_runner_snapshot_after_a_tick() {
        let ctx = make_ctx();
        {
            let mut state = ctx.dynamic.write().await;
            state.synflood_snapshot = Some(SynFloodSnapshot {
                top_offenders: vec![SynIpRate {
                    src_ip: Ipv4Addr::from(1),
                    pps: 250.0,
                }],
                alerts: vec![SynFloodAlertSlotSnapshot {
                    src_ip: Ipv4Addr::from(1),
                    phase_label: "firing",
                    consecutive_count: 3,
                }],
            });
        }
        let router = api::router(ctx);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/synflood")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let offenders = parsed["top_offenders"].as_array().unwrap();
        assert_eq!(offenders.len(), 1);
        assert_eq!(offenders[0]["src_ip"], "0.0.0.1");
        assert_eq!(offenders[0]["pps"], 250.0);
        assert_eq!(offenders[0]["alert_phase"], "firing");
        assert_eq!(offenders[0]["alert_consecutive_count"], 3);
        assert_eq!(parsed["active_alert_count"], 1);
    }

    #[test]
    fn synflood_offender_view_maps_alert_phase_when_present() {
        let snapshot = SynFloodSnapshot {
            top_offenders: vec![
                SynIpRate {
                    src_ip: Ipv4Addr::from(1),
                    pps: 50.0,
                },
                SynIpRate {
                    src_ip: Ipv4Addr::from(2),
                    pps: 300.0,
                },
            ],
            alerts: vec![SynFloodAlertSlotSnapshot {
                src_ip: Ipv4Addr::from(2),
                phase_label: "pending",
                consecutive_count: 1,
            }],
        };
        let view = to_view(&snapshot);
        assert_eq!(view.active_alert_count, 1);
        let ip1 = view
            .top_offenders
            .iter()
            .find(|o| o.src_ip == "0.0.0.1")
            .unwrap();
        assert!(ip1.alert_phase.is_none());
        assert!(ip1.alert_consecutive_count.is_none());
        let ip2 = view
            .top_offenders
            .iter()
            .find(|o| o.src_ip == "0.0.0.2")
            .unwrap();
        assert_eq!(ip2.alert_phase, Some("pending"));
        assert_eq!(ip2.alert_consecutive_count, Some(1));
    }
}
