use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::{
    alert::{
        model::{Alert, AlertKind, AlertSignal},
        state::{AlertEmission, AlertState, AlertStateKind},
    },
    anomaly::AnomalyLevel,
};
use ebpf_xdp_program_common::ProtoIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AlertKey {
    proto: ProtoIndex,
    kind: AlertKind,
}

pub struct AlertRule {
    pub kind: AlertKind,
    pub min_level: AnomalyLevel,
    pub min_confidence: f64,
    pub for_duration: Duration,
    pub cooldown: Duration,
}
pub struct AlertEvent {
    pub alert: Alert,
    pub state: AlertStateKind,
}

pub struct AlertManager {
    rules: Vec<AlertRule>,
    states: HashMap<AlertKey, AlertState>,
}

impl AlertManager {
    pub fn new(rules: Vec<AlertRule>) -> Self {
        if rules.is_empty() {
            tracing::warn!("AlertManager initialized with no rules; alerting disabled");
        }

        Self {
            rules,
            states: HashMap::new(),
        }
    }

    pub fn evaluate(&mut self, signals: &[AlertSignal], now: Instant) -> Vec<AlertEvent> {
        let active = self.collect_active(signals);
        tracing::info!("active alerts: {:?}", active.keys().collect::<Vec<_>>());
        self.advance_states(&active, now)
    }

    fn collect_active(&self, signals: &[AlertSignal]) -> HashMap<AlertKey, AlertSignal> {
        let mut active = HashMap::new();

        for rule in &self.rules {
            for signal in signals {
                if signal.kind != rule.kind {
                    tracing::info!(
                        "skipping signal for proto {:?} kind {:?} due to rule kind {:?}",
                        signal.proto,
                        signal.kind,
                        rule.kind
                    );
                    continue;
                }
                if signal.level < rule.min_level {
                    tracing::info!(
                        "skipping signal for proto {:?} level {:?} below rule min level {:?}",
                        signal.proto,
                        signal.level,
                        rule.min_level
                    );
                    continue;
                }
                if signal.confidence < rule.min_confidence {
                    tracing::info!(
                        "skipping signal for proto {:?} confidence {} below rule min confidence {}",
                        signal.proto,
                        signal.confidence,
                        rule.min_confidence
                    );
                    continue;
                }

                let key = AlertKey {
                    proto: signal.proto,
                    kind: signal.kind,
                };

                active.insert(key, signal.clone());
            }
        }

        active
    }

    fn advance_states(
        &mut self,
        active: &HashMap<AlertKey, AlertSignal>,
        now: Instant,
    ) -> Vec<AlertEvent> {
        let mut events = Vec::new();

        for rule in &self.rules {
            let keys: Vec<AlertKey> = self
                .states
                .keys()
                .cloned()
                .chain(active.keys().cloned())
                .collect();

            for key in keys {
                let state = self.states.entry(key).or_insert_with(AlertState::new);

                let signal = active.get(&key);
                let is_active = signal.is_some();
                tracing::info!(
                    "advancing alert state for proto {:?} kind {:?}: is_active={}",
                    key.proto,
                    key.kind,
                    is_active
                );

                let emission = state.advance(is_active, now, rule.for_duration, rule.cooldown);

                match emission {
                    AlertEmission::Fired => {
                        let s = signal.unwrap();
                        events.push(AlertEvent {
                            alert: Alert {
                                proto: s.proto,
                                kind: s.kind,
                                level: s.level,
                                confidence: s.confidence,
                                timestamp: now,
                            },
                            state: AlertStateKind::Firing,
                        });
                    }

                    AlertEmission::Resolved => {
                        events.push(AlertEvent {
                            alert: Alert {
                                proto: key.proto,
                                kind: key.kind,
                                level: rule.min_level,
                                confidence: 0.0,
                                timestamp: now,
                            },
                            state: AlertStateKind::Resolved,
                        });
                    }

                    AlertEmission::None => {}
                }
            }
        }

        events
    }
}
