//! Anomaly detection pipeline orchestration.
//!
//! [`AnomalyRunner`] is the top-level coordinator. On each call to [`AnomalyRunner::tick`]
//! it computes per-protocol rates from raw counter deltas, runs both detectors
//! (EWMA Z-score and emergency thresholds), advances alert FSMs, updates the
//! EWMA baseline (skipping protocols currently frozen by a hot alert), and
//! emits Prometheus metrics.
//!
//! File layout follows the model.rs/view.rs/logic rule documented in
//! `crate::alert`'s module doc. `pipeline` doesn't originate its own domain
//! vocabulary — it only orchestrates types already defined in
//! `alert`/`anomaly`/`rate`, so it has no `model.rs`. It does have one
//! `view.rs`: [`AlertSlotSnapshot`]/[`ProtoSnapshot`]/[`RunnerSnapshot`]/
//! [`SynFloodSnapshot`]/[`PortScanSnapshot`] — see `view.rs`'s own doc
//! comment for why — kept out of `runner.rs`/`synflood_runner.rs`/
//! `port_scan_runner.rs`, which hold only the managers themselves.
//!
//! `AnomalyRunner::tick()`/`SynFloodRunner::tick()`/`PortScanRunner::tick()`,
//! the *primary* methods, return [`TickAlerts`]: the Fired/Resolved
//! transitions for this tick (also logged and recorded to metrics, as
//! before) plus a heartbeat re-affirmation of every still-Firing alert (see
//! `crate::alert::AlertLifecycleManager::heartbeats`) — consumed by `main.rs` to
//! dispatch to the Alertmanager sink. `TickAlerts` is a plain return-value
//! bundle, not new domain vocabulary, so it lives here rather than in a
//! `model.rs`.
mod port_scan_runner;
mod runner;
mod synflood_runner;
mod view;

pub use port_scan_runner::PortScanRunner;
pub use runner::AnomalyRunner;
pub use synflood_runner::SynFloodRunner;
pub use view::{
    AlertSlotSnapshot, PortScanSnapshot, ProtoSnapshot, RunnerSnapshot, SynFloodSnapshot,
};

/// Alerts produced by one `tick()` call, for dispatch to external sinks
/// (e.g. Alertmanager).
///
/// `transitions` are Fired/Resolved lifecycle events — emitted once per
/// phase change, the same values already logged and fed to
/// `MetricsHandle::record_alert_event`. `heartbeats` are currently-Firing
/// alerts re-affirmed every tick, since transitions alone leave a gap an
/// external sink with its own auto-expiry (e.g. Alertmanager's
/// `resolve_timeout`) would otherwise time out on.
pub struct TickAlerts<Event, Alert> {
    pub transitions: Vec<Event>,
    pub heartbeats: Vec<Alert>,
}

/// Shared "prime or diff" step at the top of a runner's `tick()`.
///
/// On the first call after construction (or after any gap with no data),
/// `*prev` is `None`: this primes it from `current` and returns `None` so
/// the caller skips processing for one tick. On every call after that, it
/// returns the previous snapshot to diff against and rotates `*prev` to
/// `current`.
pub(crate) fn prime_or_diff<T: Clone>(prev: &mut Option<T>, current: &Option<T>) -> Option<T> {
    let curr = current.as_ref()?;
    match prev.take() {
        Some(p) => {
            *prev = Some(curr.clone());
            Some(p)
        }
        None => {
            *prev = Some(curr.clone());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prime_or_diff_no_current_is_noop() {
        let mut prev: Option<i32> = None;
        assert_eq!(prime_or_diff(&mut prev, &None), None);
        assert_eq!(prev, None);

        // Also a no-op when prev was already primed.
        let mut prev = Some(1);
        assert_eq!(prime_or_diff(&mut prev, &None), None);
        assert_eq!(prev, Some(1));
    }

    #[test]
    fn prime_or_diff_first_call_primes_and_returns_none() {
        let mut prev: Option<i32> = None;
        let result = prime_or_diff(&mut prev, &Some(5));
        assert_eq!(result, None);
        assert_eq!(prev, Some(5));
    }

    #[test]
    fn prime_or_diff_second_call_returns_old_and_rotates() {
        let mut prev = Some(5);
        let result = prime_or_diff(&mut prev, &Some(9));
        assert_eq!(result, Some(5));
        assert_eq!(prev, Some(9));
    }
}
