use axum::{Json, extract::State};
use serde::Serialize;

use crate::{api::ApiContext, pipeline::PortScanSnapshot};

/// Bounded top-N view of current port-scan state — never an unbounded dump,
/// since source-IP cardinality is attacker-controlled.
#[derive(Debug, Serialize)]
pub struct PortScanResponse {
    pub top_scanners: Vec<PortScanOffenderView>,
    pub active_alert_count: usize,
}

#[derive(Debug, Serialize)]
pub struct PortScanOffenderView {
    pub src_ip: String,
    pub distinct_ports: u32,
    pub alert_phase: Option<&'static str>,
    pub alert_consecutive_count: Option<u32>,
}

pub async fn handler(State(ctx): State<ApiContext>) -> Json<PortScanResponse> {
    let state = ctx.dynamic.read().await;
    let response = match &state.port_scan_snapshot {
        Some(snapshot) => to_view(snapshot),
        // No port-scan eval tick has run yet.
        None => PortScanResponse {
            top_scanners: vec![],
            active_alert_count: 0,
        },
    };
    Json(response)
}

fn to_view(snapshot: &PortScanSnapshot) -> PortScanResponse {
    let top_scanners = snapshot
        .top_scanners
        .iter()
        .map(|b| {
            let alert = snapshot.alerts.iter().find(|a| a.src_ip == b.src_ip);
            PortScanOffenderView {
                src_ip: b.src_ip.to_string(),
                distinct_ports: b.distinct_ports,
                alert_phase: alert.map(|a| a.phase_label),
                alert_consecutive_count: alert.map(|a| a.consecutive_count),
            }
        })
        .collect();
    PortScanResponse {
        top_scanners,
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
        alert::PortScanAlertSlotSnapshot,
        api::{self, make_ctx},
        rate::PortScanIpBreadth,
    };

    #[tokio::test]
    async fn port_scan_empty_before_any_tick() {
        let ctx = make_ctx();
        let router = api::router(ctx);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/portscan")
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
        assert!(parsed["top_scanners"].as_array().unwrap().is_empty());
        assert_eq!(parsed["active_alert_count"], 0);
    }

    #[tokio::test]
    async fn port_scan_reflects_runner_snapshot_after_a_tick() {
        let ctx = make_ctx();
        {
            let mut state = ctx.dynamic.write().await;
            state.port_scan_snapshot = Some(PortScanSnapshot {
                top_scanners: vec![PortScanIpBreadth {
                    src_ip: Ipv4Addr::from(1),
                    distinct_ports: 42,
                }],
                alerts: vec![PortScanAlertSlotSnapshot {
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
                    .uri("/portscan")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let scanners = parsed["top_scanners"].as_array().unwrap();
        assert_eq!(scanners.len(), 1);
        assert_eq!(scanners[0]["src_ip"], "0.0.0.1");
        assert_eq!(scanners[0]["distinct_ports"], 42);
        assert_eq!(scanners[0]["alert_phase"], "firing");
        assert_eq!(scanners[0]["alert_consecutive_count"], 3);
        assert_eq!(parsed["active_alert_count"], 1);
    }

    #[test]
    fn port_scan_offender_view_maps_alert_phase_when_present() {
        let snapshot = PortScanSnapshot {
            top_scanners: vec![
                PortScanIpBreadth {
                    src_ip: Ipv4Addr::from(1),
                    distinct_ports: 5,
                },
                PortScanIpBreadth {
                    src_ip: Ipv4Addr::from(2),
                    distinct_ports: 30,
                },
            ],
            alerts: vec![PortScanAlertSlotSnapshot {
                src_ip: Ipv4Addr::from(2),
                phase_label: "pending",
                consecutive_count: 1,
            }],
        };
        let view = to_view(&snapshot);
        assert_eq!(view.active_alert_count, 1);
        let ip1 = view
            .top_scanners
            .iter()
            .find(|o| o.src_ip == "0.0.0.1")
            .unwrap();
        assert!(ip1.alert_phase.is_none());
        assert!(ip1.alert_consecutive_count.is_none());
        let ip2 = view
            .top_scanners
            .iter()
            .find(|o| o.src_ip == "0.0.0.2")
            .unwrap();
        assert_eq!(ip2.alert_phase, Some("pending"));
        assert_eq!(ip2.alert_consecutive_count, Some(1));
    }
}
