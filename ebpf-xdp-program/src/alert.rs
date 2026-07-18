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
//!   `PortScanAlertEvent` (the latter two are type aliases of
//!   [`model::IpAlertEvent`]), which cross the analogous detector→manager
//!   boundaries. It also holds the
//!   [`ip_manager::IpKeyed`]/[`ip_manager::FromIpSignal`] impls tying those
//!   SynFlood/PortScan types to the generic manager below, co-located with
//!   the concrete types rather than in `ip_manager.rs` so that file stays
//!   decoupled from any specific detector's vocabulary.
//! - `view.rs` holds [`AlertMetricsSnapshot`] and [`IpAlertSlotSnapshot`]
//!   (shared by both the `/synflood` and `/portscan` APIs, since both
//!   managers' `snapshot()` is one generic method) — see `view.rs`'s own
//!   doc comment for which method produces each and why.
//! - `proto_manager.rs` holds what's private to the Proto+`AlertKind`-keyed
//!   FSM: the private `AlertKey`, [`AlertRule`] (constructor config, never
//!   observed by anything but the manager it configures), and
//!   [`AlertManager`] itself. Its name stays as `proto_manager.rs` rather
//!   than folding into a `manager.rs` — it's accurately scoped to this one
//!   generic, Proto-keyed manager, distinct from the IP-keyed SynFlood/
//!   PortScan manager below (a real modeling difference: `AlertKey` has
//!   nowhere to put an `Ipv4Addr`).
//! - `ip_manager.rs` holds [`ip_manager::IpAlertManager`], the single
//!   generic FSM/GC implementation shared by SynFlood and PortScan
//!   alerting. Kept separate from `proto_manager.rs` for the key-type
//!   reason above. Unlike that split, SynFlood and PortScan are both
//!   `Ipv4Addr`-keyed — same key, same FSM logic — so there's no modeling
//!   reason for them to have separate manager implementations;
//!   `synflood_manager.rs`/`port_scan_manager.rs` below are just aliases
//!   onto this one.
//! - `synflood_manager.rs`/`port_scan_manager.rs` each hold a single
//!   `pub type ... = IpAlertManager<...>;` alias, plus their own unit
//!   tests, so external code keeps referring to `SynFloodAlertManager`/
//!   `PortScanAlertManager` by their domain-meaningful names — the two
//!   files differ only in which concrete types the alias names, not in any
//!   logic.
//! - `state.rs` holds `AlertLifecycle`/`AlertState`, the FSM primitive
//!   shared by all three managers.
pub mod ip_manager;
pub mod model;
pub mod port_scan_manager;
pub mod proto_manager;
mod state;
pub mod synflood_manager;
pub mod view;

pub use model::{
    Alert, AlertEvent, AlertKind, AlertSignal, PortScanAlert, PortScanAlertEvent, PortScanSignal,
    SynFloodAlert, SynFloodAlertEvent, SynFloodSignal,
};
pub use port_scan_manager::PortScanAlertManager;
pub use proto_manager::{AlertManager, AlertRule};
pub use state::AlertLifecycle;
pub use synflood_manager::SynFloodAlertManager;
pub use view::{AlertMetricsSnapshot, IpAlertSlotSnapshot};
