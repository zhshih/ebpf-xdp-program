//! Read-only renderings of FSM state for external display, decoupled from
//! the managers that produce them. See `crate::alert`'s module doc for the
//! full model.rs/view.rs/logic rule this file follows.
//!
//! Both types here are the return value of a *secondary* introspection
//! method, not a manager's primary one: [`AlertMetricsSnapshot`] comes from
//! `AlertManager::snapshot()` (not `evaluate()`) and is a direct
//! read of `AlertState`'s own private fields (`phase_value()`,
//! `phase_label()`, `consecutive_count`) — it exists for no reason other
//! than to expose them. [`SynFloodAlertSlotSnapshot`] comes from
//! `SynFloodAlertManager::snapshot()` (not `evaluate()`) for the same
//! reason. Mirrors `anomaly::view`'s `AnomalyView`.
use std::net::Ipv4Addr;

use ebpf_xdp_program_common::ProtoIndex;

use crate::alert::AlertKind;

/// Snapshot of a single alert slot for metrics export.
pub struct AlertMetricsSnapshot {
    pub proto: ProtoIndex,
    pub kind: AlertKind,
    pub phase_value: u8,
    pub phase_label: &'static str,
    pub consecutive_count: u32,
}

/// Point-in-time view of one IP's SYN-flood FSM slot, for the `/synflood` API.
pub struct SynFloodAlertSlotSnapshot {
    pub src_ip: Ipv4Addr,
    pub phase_label: &'static str,
    pub consecutive_count: u32,
}
