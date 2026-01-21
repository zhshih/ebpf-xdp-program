use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertStatus {
    Inactive,
    Pending,
    Firing,
}

pub enum AlertEmission {
    None,
    Fired,
    Resolved,
}

#[derive(Debug)]
pub struct AlertState {
    pub status: AlertStatus,
    first_seen: Option<Instant>,
    last_fired: Option<Instant>,
}

impl AlertState {
    pub fn new() -> Self {
        Self {
            status: AlertStatus::Inactive,
            first_seen: None,
            last_fired: None,
        }
    }

    pub fn advance(
        &mut self,
        signal_active: bool,
        now: Instant,
        for_duration: Duration,
        cooldown: Duration,
    ) -> AlertEmission {
        match self.status {
            AlertStatus::Inactive => {
                if signal_active {
                    self.status = AlertStatus::Pending;
                    self.first_seen = Some(now);
                }
                AlertEmission::None
            }

            AlertStatus::Pending => {
                if !signal_active {
                    self.reset();
                    AlertEmission::None
                } else if now.duration_since(self.first_seen.unwrap()) >= for_duration {
                    if self.cooldown_passed(now, cooldown) {
                        self.status = AlertStatus::Firing;
                        self.last_fired = Some(now);
                        AlertEmission::Fired
                    } else {
                        AlertEmission::None
                    }
                } else {
                    AlertEmission::None
                }
            }

            AlertStatus::Firing => {
                if !signal_active {
                    self.reset();
                    AlertEmission::Resolved
                } else {
                    AlertEmission::None
                }
            }
        }
    }

    fn reset(&mut self) {
        self.status = AlertStatus::Inactive;
        self.first_seen = None;
    }

    fn cooldown_passed(&self, now: Instant, cooldown: Duration) -> bool {
        match self.last_fired {
            None => true,
            Some(t) => now.duration_since(t) >= cooldown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertStateKind {
    Firing,
    Resolved,
}
