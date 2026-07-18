//! Axum-based read-only REST API exposing process health, resolved
//! configuration, and live per-protocol anomaly/alert state.
//!
//! Runs concurrently with the main eBPF-stats/anomaly-eval loop as a separate
//! tokio task. Never touches the eBPF/aya maps directly — it only reads
//! shared, lock-protected state written by the main loop once per tick.
//!
//! File layout follows the same boundary-crossing rule as `crate::alert`/
//! `crate::anomaly`: a type only needs a shared `model.rs` if a genuinely
//! different component consumes it as an independently meaningful value.
//! Every response/view type here ([`health::HealthResponse`],
//! [`anomalies::AnomaliesResponse`]/`ProtoAnomalyView`/`AlertSlotView`,
//! [`synflood::SynFloodResponse`]/`SynFloodOffenderView`,
//! [`port_scan::PortScanResponse`]/`PortScanOffenderView`) is a JSON-shaped,
//! second-order rendering built and consumed by exactly one handler in its
//! own file — none of them are read by anything else, so none of them cross
//! a boundary. The types that *do* cross into this module
//! ([`RunnerSnapshot`], [`SynFloodSnapshot`], [`PortScanSnapshot`],
//! [`ResolvedConfig`]) already live in their producing modules rather than
//! being duplicated here — that's why `api` has no `model.rs` of its own.
mod anomalies;
mod config;
mod health;
mod port_scan;
mod synflood;

use std::{net::SocketAddr, sync::Arc, time::Instant};

use anyhow::Context as _;
use axum::Router;
use tokio::sync::RwLock;

use crate::{
    config::ResolvedConfig,
    pipeline::{PortScanSnapshot, RunnerSnapshot, SynFloodSnapshot},
};

/// Mutable state written by the main loop, read by API handlers.
///
/// `last_stats_at` is updated once per 1s stats-poll tick; `warmed_up` and
/// `runner_snapshot` are updated once per 30s anomaly-eval tick;
/// `synflood_snapshot`/`port_scan_snapshot` are updated once per their own
/// eval ticks.
pub struct ApiState {
    pub started_at: Instant,
    pub last_stats_at: Option<Instant>,
    pub warmed_up: bool,
    pub runner_snapshot: Option<RunnerSnapshot>,
    pub synflood_snapshot: Option<SynFloodSnapshot>,
    pub port_scan_snapshot: Option<PortScanSnapshot>,
}

impl ApiState {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            last_stats_at: None,
            warmed_up: false,
            runner_snapshot: None,
            synflood_snapshot: None,
            port_scan_snapshot: None,
        }
    }
}

/// Shared, cloneable Axum router state.
///
/// `resolved_config` is immutable after startup, so it needs no lock.
/// `dynamic` is updated every tick by the main loop and read by handlers.
#[derive(Clone)]
pub struct ApiContext {
    pub resolved_config: Arc<ResolvedConfig>,
    pub dynamic: Arc<RwLock<ApiState>>,
}

/// Builds the full router: `GET /health`, `GET /config`, `GET /anomalies`,
/// `GET /synflood`, `GET /portscan`.
pub fn router(ctx: ApiContext) -> Router {
    Router::new()
        .route("/health", axum::routing::get(health::handler))
        .route("/config", axum::routing::get(config::handler))
        .route("/anomalies", axum::routing::get(anomalies::handler))
        .route("/synflood", axum::routing::get(synflood::handler))
        .route("/portscan", axum::routing::get(port_scan::handler))
        .with_state(ctx)
}

/// Binds and serves the router on `addr` until the process exits. Intended to
/// be driven by a dedicated `tokio::spawn`-ed task.
pub async fn serve(addr: SocketAddr, ctx: ApiContext) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind API listener on {addr}"))?;
    axum::serve(listener, router(ctx))
        .await
        .context("API server error")
}

/// Builds a fresh, all-default `ApiContext` for handler tests. Shared by
/// every `api/*.rs` test module so each doesn't redefine it.
#[cfg(test)]
pub(crate) fn make_ctx() -> ApiContext {
    ApiContext {
        resolved_config: Arc::new(crate::config::default_resolved_config()),
        dynamic: Arc::new(RwLock::new(ApiState::new())),
    }
}
