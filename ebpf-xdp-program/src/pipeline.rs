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
//! vocabulary — `AnomalyRunner::tick()`/`SynFloodRunner::tick()`/
//! `PortScanRunner::tick()`, the *primary* methods, return `()` and only
//! have side effects — it only orchestrates types already defined in
//! `alert`/`anomaly`/`rate`, so it has no `model.rs`. It does have one
//! `view.rs`: [`AlertSlotSnapshot`]/[`ProtoSnapshot`]/[`RunnerSnapshot`]/
//! [`SynFloodSnapshot`]/[`PortScanSnapshot`] — see `view.rs`'s own doc
//! comment for why — kept out of `runner.rs`/`synflood_runner.rs`/
//! `port_scan_runner.rs`, which hold only the managers themselves.
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
