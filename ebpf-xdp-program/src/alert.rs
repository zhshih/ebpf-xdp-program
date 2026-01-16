pub mod model;
pub mod semantics;

pub use model::{Alert, AlertKind};
pub use semantics::{decision_to_alert, emit_alert};
