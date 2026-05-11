//! Alert lifecycle management.
//!
//! Each `(protocol, kind)` pair is tracked by an FSM with three phases:
//! `Inactive → Pending → Firing`. An [`AlertRule`] controls the thresholds
//! and cooldowns that govern phase transitions. [`AlertManager`] drives all
//! FSMs and emits [`AlertEvent`]s when alerts fire or resolve.
pub mod manager;
pub mod model;
mod state;

pub use manager::{AlertEvent, AlertManager, AlertMetricsSnapshot, AlertRule};
pub use model::{AlertKind, AlertSignal};
pub use state::AlertLifecycle;
