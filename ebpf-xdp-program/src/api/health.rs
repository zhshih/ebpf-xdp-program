use axum::{Json, extract::State};
use serde::Serialize;

use crate::api::ApiContext;

/// Minimal liveness payload. Per-protocol detail lives in `/anomalies`, not here.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Always `"ok"` for now — there's no failure mode today that leaves the
    /// process running in a degraded-but-alive state worth surfacing.
    pub status: &'static str,
    pub uptime_secs: u64,
    pub baseline_warmed_up: bool,
    /// `None` until the first stats-poll tick has succeeded.
    pub last_stats_age_secs: Option<f64>,
}

pub async fn handler(State(ctx): State<ApiContext>) -> Json<HealthResponse> {
    let state = ctx.dynamic.read().await;
    let now = std::time::Instant::now();
    Json(HealthResponse {
        status: "ok",
        uptime_secs: now.duration_since(state.started_at).as_secs(),
        baseline_warmed_up: state.warmed_up,
        last_stats_age_secs: state
            .last_stats_at
            .map(|t| now.duration_since(t).as_secs_f64()),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tokio::sync::RwLock;
    use tower::ServiceExt as _;

    use super::*;
    use crate::{
        api::{self, ApiState},
        config::default_resolved_config,
    };

    fn make_ctx() -> ApiContext {
        ApiContext {
            resolved_config: Arc::new(default_resolved_config()),
            dynamic: Arc::new(RwLock::new(ApiState::new())),
        }
    }

    #[tokio::test]
    async fn health_reports_ok_with_no_ticks_yet() {
        let ctx = make_ctx();
        let router = api::router(ctx);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/health")
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
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["baseline_warmed_up"], false);
        assert!(parsed["last_stats_age_secs"].is_null());
    }

    #[tokio::test]
    async fn health_reflects_warmed_up_and_stats_freshness() {
        let ctx = make_ctx();
        {
            let mut state = ctx.dynamic.write().await;
            state.warmed_up = true;
            state.last_stats_at = Some(std::time::Instant::now());
        }
        let router = api::router(ctx);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["baseline_warmed_up"], true);
        assert!(!parsed["last_stats_age_secs"].is_null());
    }
}
