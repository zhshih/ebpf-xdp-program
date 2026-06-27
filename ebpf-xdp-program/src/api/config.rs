use axum::{Json, extract::State};

use crate::{api::ApiContext, config::ResolvedConfig};

/// Read-only dump of the actually-in-effect configuration. GET-only for now —
/// hot-reload (POST) would need real design work (validation, atomic swap of
/// the running `EwmaEstimator`/`AlertManager`, races with in-flight ticks)
/// that's out of scope here.
pub async fn handler(State(ctx): State<ApiContext>) -> Json<ResolvedConfig> {
    Json((*ctx.resolved_config).clone())
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
    use crate::api::{self, ApiState};

    #[tokio::test]
    async fn config_returns_resolved_defaults() {
        let resolved = crate::config::default_resolved_config();
        let expected_alpha = resolved.baseline.alpha;
        let ctx = ApiContext {
            resolved_config: Arc::new(resolved),
            dynamic: Arc::new(RwLock::new(ApiState::new())),
        };
        let router = api::router(ctx);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/config")
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
        assert_eq!(parsed["baseline"]["alpha"], expected_alpha);
        assert!(!parsed["alert_rules"].as_array().unwrap().is_empty());
    }
}
