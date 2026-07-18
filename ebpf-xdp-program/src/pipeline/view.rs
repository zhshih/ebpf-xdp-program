//! Read-only renderings of runner state for the
//! `/anomalies`/`/synflood`/`/portscan` API endpoints, decoupled from the
//! runners that produce them. See `crate::alert`'s module doc for the full
//! model.rs/view.rs/logic rule.
//!
//! All five types here are `snapshot()`'s output — each runner's *secondary*
//! method, explicitly documented as safe to call from a different task than
//! `tick()` (the primary method, which returns `()`) — assembled once per
//! call, stored in `ApiState`, and read later by an independent
//! HTTP-handling task. Mirrors `anomaly::view`'s `AnomalyView` and
//! `alert::view`'s `AlertMetricsSnapshot`.
use ebpf_xdp_program_common::ProtoIndex;

use crate::{
    alert::{AlertKind, IpAlertSlotSnapshot},
    anomaly::AnomalyView,
    baseline::BaselineState,
    rate::{PortScanIpBreadth, ProtoRate, SynIpRate},
};

/// Point-in-time view of one protocol's alert FSM slot, for the `/anomalies` API.
#[derive(Debug)]
pub struct AlertSlotSnapshot {
    pub kind: AlertKind,
    pub phase_label: &'static str,
    pub consecutive_count: u32,
}

/// Point-in-time view of one protocol's full anomaly/alert state.
///
/// `rate`/`anomaly` are `None` until the runner has processed at least two
/// counter snapshots (the first tick only primes `prev_counters`).
#[derive(Debug)]
pub struct ProtoSnapshot {
    pub proto: ProtoIndex,
    pub rate: Option<ProtoRate>,
    pub baseline: BaselineState,
    pub anomaly: Option<AnomalyView>,
    pub alerts: Vec<AlertSlotSnapshot>,
    pub frozen: bool,
}

/// Point-in-time view of all per-protocol anomaly/alert state, assembled by
/// [`crate::pipeline::AnomalyRunner::snapshot`] for the `/anomalies` API endpoint.
#[derive(Debug)]
pub struct RunnerSnapshot {
    pub protos: Vec<ProtoSnapshot>,
}

/// Point-in-time view of SYN-flood state, for the `/synflood` API endpoint.
pub struct SynFloodSnapshot {
    pub top_offenders: Vec<SynIpRate>,
    pub alerts: Vec<IpAlertSlotSnapshot>,
}

/// Point-in-time view of port-scan state, for the `/portscan` API endpoint.
pub struct PortScanSnapshot {
    pub top_scanners: Vec<PortScanIpBreadth>,
    pub alerts: Vec<IpAlertSlotSnapshot>,
}
