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
