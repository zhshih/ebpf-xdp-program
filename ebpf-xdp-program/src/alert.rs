//! Alert lifecycle management.
//!
//! Each `(protocol, kind)` pair is tracked by an FSM with three phases:
//! `Inactive → Pending → Firing`. An [`AlertRule`] controls the thresholds
//! and cooldowns that govern phase transitions. [`AlertManager`] drives all
//! FSMs and emits [`AlertEvent`]s when alerts fire or resolve.
//!
//! File layout follows one rule: a type belongs in `model.rs` only if it's
//! shared domain vocabulary that crosses a producer/consumer or module
//! boundary — one component produces it and a genuinely different
//! component (a different manager, or an external layer like
//! `pipeline`/`api`/`metrics`) consumes it as an independently meaningful
//! value. A type that exists purely to configure or expose the internal
//! state of *one* specific manager — rule/threshold config fed into its
//! constructor, or a bespoke snapshot shaped by that manager's own FSM
//! fields — is manager-scaffolding and stays colocated with that manager's
//! logic instead. Crossing a boundary is what earns a type a place in
//! `model.rs`; how many components sit on either side of that boundary
//! does not matter — a single-producer/single-consumer pipeline still
//! crosses one.
//!
//! - `model.rs` holds [`AlertKind`]/[`AlertSignal`] (produced by
//!   `EwmaDetector`/`EmergencyDetector` in `crate::anomaly`, consumed by
//!   [`AlertManager`] here), [`AlertEvent`] (produced by [`AlertManager`],
//!   consumed by `pipeline`/`metrics` outside this module), and the
//!   SynFlood equivalents `SynFloodSignal`/`SynFloodAlert`/
//!   `SynFloodAlertEvent`, which cross the same
//!   `SynFloodDetector`→`SynFloodAlertManager` boundary.
//! - `proto_manager.rs` holds what's private to the Proto+`AlertKind`-keyed
//!   FSM: the private `AlertKey`, [`AlertRule`] (constructor config, never
//!   observed by anything but the manager it configures),
//!   [`AlertMetricsSnapshot`] (a metrics-export view shaped by this
//!   manager's own state), and [`AlertManager`] itself. Its name stays as
//!   `proto_manager.rs` rather than folding into a `manager.rs` — it's
//!   accurately scoped to this one generic, Proto-keyed manager, distinct
//!   from the IP-keyed SynFlood manager below.
//! - `synflood_manager.rs` holds what's private to the IP-keyed FSM:
//!   [`SynFloodAlertSlotSnapshot`] and [`SynFloodAlertManager`]. Kept in
//!   its own file rather than folded into `proto_manager.rs` because
//!   `AlertKey`'s `ProtoIndex` has nowhere to put an `Ipv4Addr` without
//!   widening it and rippling into `frozen_protos()`,
//!   `AlertMetricsSnapshot`, and every existing Spike/Drop/Emergency test.
//! - `state.rs` holds `AlertLifecycle`/`AlertState`, the FSM primitive
//!   shared by both managers.
pub mod model;
pub mod proto_manager;
mod state;
pub mod synflood_manager;

pub use model::{AlertEvent, AlertKind, AlertSignal, SynFloodSignal};
pub use proto_manager::{AlertManager, AlertMetricsSnapshot, AlertRule};
pub use state::AlertLifecycle;
pub use synflood_manager::{SynFloodAlertManager, SynFloodAlertSlotSnapshot};
