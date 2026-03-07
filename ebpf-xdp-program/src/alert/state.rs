use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlertPhase {
    Inactive,
    Pending,
    Firing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLifecycle {
    Fired,
    Resolved,
}

#[derive(Debug)]
pub struct AlertState {
    phase: AlertPhase,
    pub(crate) consecutive_count: u32,
    resolve_consecutive_count: u32,
    last_fired: Option<Instant>,
}

impl AlertState {
    pub fn new() -> Self {
        Self {
            phase: AlertPhase::Inactive,
            consecutive_count: 0,
            resolve_consecutive_count: 0,
            last_fired: None,
        }
    }

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
