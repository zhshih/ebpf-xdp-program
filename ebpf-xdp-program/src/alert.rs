//! Alert lifecycle management.
//!
//! Each `(protocol, kind)` pair is tracked by an FSM with three phases:
//! `Inactive → Pending → Firing`. An [`AlertRule`] controls the thresholds
//! and cooldowns that govern phase transitions. [`AlertManager`] drives all
//! FSMs and emits [`AlertEvent`]s when alerts fire or resolve.
//!
//! File layout follows one rule, in three categories — canonical statement
//! here; `crate::anomaly`/`crate::pipeline`/`crate::rate` point back to this
//! doc rather than restating it.
//! - `model.rs`: the return value of a component's *primary* method — the
//!   one whose job defines why it exists (`evaluate()`, `detect()`,
//!   `tick()`) — consumed by a genuinely different component as an
//!   independently meaningful value.
//! - `view.rs`: the return value of a *secondary*, on-demand introspection
//!   method (`snapshot()`) that exists solely to expose current state for
//!   display. Classify by *which method produced
//!   it*, not by how it's consumed today — e.g. `AlertEvent` and
//!   `AlertMetricsSnapshot` are, right now, both only logged/exported, but
//!   only the latter is a direct read of `AlertState`'s own fields via a
//!   method that exists for no other reason.
//! - manager/logic files: the primary method's own implementation, plus
//!   config fed into a constructor and observed by nothing else (e.g.
//!   `AlertRule`).
//!
//! - `model.rs` holds [`AlertKind`]/[`AlertSignal`] (produced by
//!   `EwmaDetector`/`EmergencyDetector` in `crate::anomaly`, consumed by
//!   [`AlertManager`] here), [`AlertEvent`] (produced by [`AlertManager`],
//!   consumed by `pipeline`/`metrics` outside this module), and the
//!   SynFlood/PortScan equivalents `SynFloodSignal`/`SynFloodAlert`/
//!   `SynFloodAlertEvent` and `PortScanSignal`/`PortScanAlert`/
//!   `PortScanAlertEvent`, which cross the analogous detector→manager
//!   boundaries.
//! - `view.rs` holds [`AlertMetricsSnapshot`], [`SynFloodAlertSlotSnapshot`],
//!   and [`PortScanAlertSlotSnapshot`] — see `view.rs`'s own doc comment for
//!   which method produces each and why.
//! - `proto_manager.rs` holds what's private to the Proto+`AlertKind`-keyed
//!   FSM: the private `AlertKey`, [`AlertRule`] (constructor config, never
//!   observed by anything but the manager it configures), and
//!   [`AlertManager`] itself. Its name stays as `proto_manager.rs` rather
//!   than folding into a `manager.rs` — it's accurately scoped to this one
//!   generic, Proto-keyed manager, distinct from the IP-keyed SynFlood/
//!   PortScan managers below.
//! - `synflood_manager.rs` holds what's private to the IP-keyed FSM:
//!   [`SynFloodAlertManager`] itself. Kept in its own file rather than
//!   folded into `proto_manager.rs` because `AlertKey`'s `ProtoIndex` has
//!   nowhere to put an `Ipv4Addr` without widening it and rippling into
//!   `frozen_protos()` and every existing Spike/Drop/Emergency test.
//! - `port_scan_manager.rs` holds [`PortScanAlertManager`], for the same
//!   reason `synflood_manager.rs` stays separate (see above).
//! - `state.rs` holds `AlertLifecycle`/`AlertState`, the FSM primitive
//!   shared by all three managers.
pub mod model;
pub mod port_scan_manager;
pub mod proto_manager;
mod state;
pub mod synflood_manager;
pub mod view;

pub use model::{AlertEvent, AlertKind, AlertSignal, PortScanSignal, SynFloodSignal};
pub use port_scan_manager::PortScanAlertManager;
pub use proto_manager::{AlertManager, AlertRule};
pub use state::AlertLifecycle;
pub use synflood_manager::SynFloodAlertManager;
pub use view::{AlertMetricsSnapshot, PortScanAlertSlotSnapshot, SynFloodAlertSlotSnapshot};
