use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlertPhase {
    Inactive,
    Pending,
    Firing,
}

/// Edge event emitted by [`AlertState::advance`] on a phase transition.
///
/// Only emitted on transitions, not on every tick — callers can treat
/// this as a stream of discrete alert lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLifecycle {
    Fired,
    Resolved,
}

/// Single-slot FSM tracking the alert lifecycle for one `(proto, kind)` pair.
///
/// State machine: `Inactive → Pending → Firing → Inactive`.
///
/// - **Inactive**: no anomaly signal seen (or signal has resolved and cooldown expired)
/// - **Pending**: anomaly seen, accumulating consecutive hits before firing
/// - **Firing**: alert is active; waits for consecutive normal ticks to resolve
#[derive(Debug)]
pub struct AlertState {
    phase: AlertPhase,
    pub(crate) consecutive_count: u32,
    resolve_consecutive_count: u32,
    last_fired: Option<Instant>,
}

impl AlertState {
    /// Creates a new state machine in the `Inactive` phase.
    pub fn new() -> Self {
        Self {
            phase: AlertPhase::Inactive,
            consecutive_count: 0,
            resolve_consecutive_count: 0,
            last_fired: None,
        }
    }

    /// Advances the FSM by one tick.
    ///
    /// - `signal_active`: whether a qualifying anomaly signal is present this tick
    /// - Returns `Some(Fired)` when the consecutive threshold is reached and the alert fires
    /// - Returns `Some(Resolved)` when the resolve threshold of quiet ticks is met
    /// - Returns `None` on all other ticks (no phase transition)
    pub fn advance(
        &mut self,
        signal_active: bool,
        now: Instant,
        cooldown: Duration,
        consecutive_threshold: u32,
        resolve_consecutive_threshold: u32,
    ) -> Option<AlertLifecycle> {
        match self.phase {
            AlertPhase::Inactive => {
                if signal_active {
                    self.consecutive_count = 1;
                    if self.try_fire(now, cooldown, consecutive_threshold) {
                        tracing::debug!(
                            consecutive_count = self.consecutive_count,
                            threshold = consecutive_threshold,
                            "alert state transition: Inactive -> Firing (threshold reached immediately)"
                        );
                        return Some(AlertLifecycle::Fired);
                    }
                    self.phase = AlertPhase::Pending;
                    tracing::debug!(
                        consecutive_count = self.consecutive_count,
                        "alert state transition: Inactive -> Pending"
                    );
                }
                None
            }

            AlertPhase::Pending => {
                if !signal_active {
                    self.reset();
                    tracing::debug!("alert state transition: Pending -> Inactive (signal lost)");
                    None
                } else {
                    self.consecutive_count += 1;
                    tracing::debug!(
                        consecutive_count = self.consecutive_count,
                        "alert pending, consecutive anomalous sample"
                    );
                    if self.try_fire(now, cooldown, consecutive_threshold) {
                        tracing::debug!(
                            consecutive_count = self.consecutive_count,
                            threshold = consecutive_threshold,
                            "alert state transition: Pending -> Firing (threshold reached)"
                        );
                        Some(AlertLifecycle::Fired)
                    } else {
                        tracing::debug!(
                            consecutive_count = self.consecutive_count,
                            threshold = consecutive_threshold,
                            meets_count = self.consecutive_count >= consecutive_threshold,
                            cooldown_passed = self.cooldown_passed(now, cooldown),
                            "alert still pending, not ready to fire"
                        );
                        None
                    }
                }
            }

            AlertPhase::Firing => {
                if signal_active {
                    self.resolve_consecutive_count = 0;
                    None
                } else {
                    self.resolve_consecutive_count += 1;
                    tracing::debug!(
                        resolve_consecutive_count = self.resolve_consecutive_count,
                        threshold = resolve_consecutive_threshold,
                        "alert firing, consecutive normal sample"
                    );
                    if self.resolve_consecutive_count >= resolve_consecutive_threshold {
                        self.reset();
                        tracing::debug!(
                            resolve_consecutive_count = self.resolve_consecutive_count,
                            threshold = resolve_consecutive_threshold,
                            "alert state transition: Firing -> Inactive (resolve threshold reached)"
                        );
                        Some(AlertLifecycle::Resolved)
                    } else {
                        None
                    }
                }
            }
        }
    }

    /// Returns 0=Inactive, 1=Pending, 2=Firing — for metrics export only.
    pub(crate) fn phase_value(&self) -> u8 {
        match self.phase {
            AlertPhase::Inactive => 0,
            AlertPhase::Pending => 1,
            AlertPhase::Firing => 2,
        }
    }

    /// Returns `true` if the alert is in `Pending`, `Firing`, or within cooldown of last fire.
    ///
    /// Used by the alert manager to determine which protocols should have
    /// their baselines frozen during and shortly after an active alert.
    pub fn is_hot(&self, now: Instant, cooldown: Duration) -> bool {
        match self.phase {
            AlertPhase::Pending | AlertPhase::Firing => true,
            AlertPhase::Inactive => match self.last_fired {
                None => false,
                Some(t) => now.duration_since(t) < cooldown,
            },
        }
    }

    fn try_fire(&mut self, now: Instant, cooldown: Duration, consecutive_threshold: u32) -> bool {
        if self.consecutive_count >= consecutive_threshold && self.cooldown_passed(now, cooldown) {
            self.phase = AlertPhase::Firing;
            self.last_fired = Some(now);
            true
        } else {
            false
        }
    }

    fn reset(&mut self) {
        tracing::trace!(
            old_status = ?self.phase,
            old_consecutive_count = self.consecutive_count,
            "alert state reset"
        );
        self.phase = AlertPhase::Inactive;
        self.consecutive_count = 0;
        self.resolve_consecutive_count = 0;
    }

    fn cooldown_passed(&self, now: Instant, cooldown: Duration) -> bool {
        match self.last_fired {
            None => true,
            Some(t) => now.duration_since(t) >= cooldown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_COOLDOWN: Duration = Duration::ZERO;

    // Helper: advance with threshold=3, resolve_threshold=2, no cooldown
    fn advance(state: &mut AlertState, signal: bool) -> Option<AlertLifecycle> {
        state.advance(signal, Instant::now(), NO_COOLDOWN, 3, 2)
    }

    #[test]
    fn state_inactive_no_signal_stays_inactive() {
        let mut s = AlertState::new();
        let result = advance(&mut s, false);
        assert!(result.is_none());
        assert_eq!(s.phase_value(), 0); // Inactive
    }

    #[test]
    fn state_inactive_signal_goes_pending() {
        let mut s = AlertState::new();
        // threshold=3, one signal → Pending (not enough to fire)
        let result = advance(&mut s, true);
        assert!(result.is_none());
        assert_eq!(s.phase_value(), 1); // Pending
    }

    #[test]
    fn state_inactive_threshold_1_fires_directly() {
        let mut s = AlertState::new();
        let result = s.advance(true, Instant::now(), NO_COOLDOWN, 1, 2);
        assert_eq!(result, Some(AlertLifecycle::Fired));
        assert_eq!(s.phase_value(), 2); // Firing
    }

    #[test]
    fn state_pending_lost_signal_resets() {
        let mut s = AlertState::new();
        advance(&mut s, true); // → Pending
        let result = advance(&mut s, false); // signal lost
        assert!(result.is_none());
        assert_eq!(s.phase_value(), 0); // back to Inactive
    }

    #[test]
    fn state_pending_accumulates_consecutive() {
        let mut s = AlertState::new();
        advance(&mut s, true); // count=1, Pending
        let result = advance(&mut s, true); // count=2, still Pending (need 3)
        assert!(result.is_none());
        assert_eq!(s.phase_value(), 1); // Pending
        assert_eq!(s.consecutive_count, 2);
    }

    #[test]
    fn state_pending_reaches_threshold_fires() {
        let mut s = AlertState::new();
        advance(&mut s, true); // count=1
        advance(&mut s, true); // count=2
        let result = advance(&mut s, true); // count=3 → Fired
        assert_eq!(result, Some(AlertLifecycle::Fired));
        assert_eq!(s.phase_value(), 2); // Firing
    }

    #[test]
    fn state_firing_signal_stays_firing() {
        let mut s = AlertState::new();
        // Fire it first (threshold=1)
        s.advance(true, Instant::now(), NO_COOLDOWN, 1, 2);
        assert_eq!(s.phase_value(), 2);
        // Signal still present → stays Firing, no event
        let result = advance(&mut s, true);
        assert!(result.is_none());
        assert_eq!(s.phase_value(), 2);
    }

    #[test]
    fn state_firing_resolves_after_threshold() {
        let mut s = AlertState::new();
        s.advance(true, Instant::now(), NO_COOLDOWN, 1, 2);
        // resolve_threshold=2 → need 2 consecutive quiet ticks
        let r1 = advance(&mut s, false);
        assert!(r1.is_none(), "first quiet tick should not resolve");
        let r2 = advance(&mut s, false);
        assert_eq!(r2, Some(AlertLifecycle::Resolved));
        assert_eq!(s.phase_value(), 0); // back to Inactive
    }

    #[test]
    fn state_is_hot_inactive_within_cooldown() {
        let mut s = AlertState::new();
        let now = Instant::now();
        // Fire (threshold=1), then resolve (resolve_threshold=1)
        s.advance(true, now, Duration::ZERO, 1, 1); // → Firing, last_fired=Some(now)
        s.advance(false, now, Duration::ZERO, 1, 1); // → Inactive, last_fired preserved
        // is_hot() with large cooldown should return true
        assert!(
            s.is_hot(now, Duration::from_secs(120)),
            "should be hot within cooldown window"
        );
        // is_hot() after cooldown expires should return false
        let after_cooldown = now + Duration::from_secs(121);
        assert!(
            !s.is_hot(after_cooldown, Duration::from_secs(120)),
            "should not be hot after cooldown"
        );
    }

    #[test]
    fn state_cooldown_blocks_refire() {
        let long_cooldown = Duration::from_secs(3600);
        let mut s = AlertState::new();
        // Fire with threshold=1
        s.advance(true, Instant::now(), long_cooldown, 1, 1);
        assert_eq!(s.phase_value(), 2); // Firing
        // Resolve (resolve_threshold=1, one quiet tick)
        s.advance(false, Instant::now(), long_cooldown, 1, 1);
        assert_eq!(s.phase_value(), 0); // Inactive but within cooldown
        // Try to fire again — cooldown blocks it
        let result = s.advance(true, Instant::now(), long_cooldown, 1, 1);
        assert!(result.is_none(), "cooldown should block refire");
        // Still in Pending (count=1, cooldown not passed)
        assert_eq!(s.phase_value(), 1);
    }
}
