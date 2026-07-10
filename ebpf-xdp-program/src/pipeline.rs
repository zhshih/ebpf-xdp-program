//! Anomaly detection pipeline orchestration.
//!
//! [`AnomalyRunner`] is the top-level coordinator. On each call to [`AnomalyRunner::tick`]
//! it computes per-protocol rates from raw counter deltas, runs both detectors
//! (EWMA Z-score and emergency thresholds), advances alert FSMs, updates the
//! EWMA baseline (skipping protocols currently frozen by a hot alert), and
//! emits Prometheus metrics.
mod runner;
mod synflood_runner;

pub use runner::{AlertSlotSnapshot, AnomalyRunner, ProtoSnapshot, RunnerSnapshot};
pub use synflood_runner::{SynFloodRunner, SynFloodSnapshot};

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
