//! Generic per-source-IP alert FSM manager, shared by SynFlood and
//! PortScan alerting. See `crate::alert`'s module doc for why this stays
//! separate from `proto_manager.rs`'s `AlertKey`-based manager.
//!
//! `S`/`A` are the concrete signal/alert types (`SynFloodSignal`/
//! `SynFloodAlert`, `PortScanSignal`/`PortScanAlert`), plugged in via the
//! [`IpKeyed`]/[`FromIpSignal`] traits below — implemented in
//! `crate::alert::model` next to those types, so this file stays decoupled
//! from any specific detector's vocabulary. `SynFloodAlertManager`/
//! `PortScanAlertManager` are type aliases of `IpAlertManager<...>`, defined
//! in `synflood_manager.rs`/`port_scan_manager.rs`.
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use crate::alert::{model::IpAlertEvent, state::AlertState, view::IpAlertSlotSnapshot};

/// Implemented by a per-IP signal type so `IpAlertManager` can key its FSM
/// map without needing to know the signal's other (metric) fields.
pub trait IpKeyed {
    fn src_ip(&self) -> Ipv4Addr;
}

/// Builds a finalized alert for `src_ip` from an optional signal — `None`
/// on a `Resolved` transition where no signal is active for `src_ip` this
/// tick, in which case implementations fall back to a zero-value metric.
pub trait FromIpSignal<S> {
    fn from_signal(src_ip: Ipv4Addr, signal: Option<&S>) -> Self;
}

/// Drives per-source-IP alert FSMs.
///
/// Bounded memory: an entry is only ever created for an IP present in the
/// current tick's (already-bounded, top-N) signal list, and `evaluate()`
/// garbage-collects any entry that is neither in this tick's signals nor
/// still "hot" (Pending/Firing/within cooldown) — so live state is bounded
/// by roughly `top_n + (IPs still cooling down)`, both attacker-independent
/// config knobs.
pub struct IpAlertManager<S, A> {
    cooldown: Duration,
    consecutive_threshold: u32,
    resolve_consecutive_threshold: u32,
    states: HashMap<Ipv4Addr, AlertState>,
    _marker: PhantomData<(S, A)>,
}

impl<S, A> IpAlertManager<S, A>
where
    S: IpKeyed,
    A: FromIpSignal<S>,
{
    pub fn new(
        cooldown: Duration,
        consecutive_threshold: u32,
        resolve_consecutive_threshold: u32,
    ) -> Self {
        Self {
            cooldown,
            consecutive_threshold,
            resolve_consecutive_threshold,
            states: HashMap::new(),
            _marker: PhantomData,
        }
    }

    /// Filters/advances FSMs against `signals`, then garbage-collects any
    /// entry that's neither in `signals` nor still hot.
    pub fn evaluate(&mut self, signals: &[S], now: Instant) -> Vec<IpAlertEvent<A>> {
        let active: HashMap<Ipv4Addr, &S> = signals.iter().map(|s| (s.src_ip(), s)).collect();

        let mut keys: HashSet<Ipv4Addr> = self.states.keys().copied().collect();
        keys.extend(active.keys().copied());

        let mut events = Vec::new();
        for ip in keys {
            let state = self.states.entry(ip).or_insert_with(AlertState::new);
            let signal = active.get(&ip).copied();
            if let Some(lifecycle) = state.advance(
                signal.is_some(),
                now,
                self.cooldown,
                self.consecutive_threshold,
                self.resolve_consecutive_threshold,
            ) {
                events.push(IpAlertEvent {
                    alert: A::from_signal(ip, signal),
                    lifecycle,
                });
            }
        }

        let cooldown = self.cooldown;
        self.states
            .retain(|ip, state| active.contains_key(ip) || state.is_hot(now, cooldown));

        events
    }

    /// Returns a re-affirmation alert for every currently-`Firing` source IP
    /// that has an active signal this tick, excluding any IP already
    /// represented in `just_transitioned` (this tick's `evaluate()` events).
    /// See [`crate::alert::AlertManager::heartbeats`] for the full rationale
    /// (external sinks like Alertmanager need periodic re-sends between
    /// `Fired`/`Resolved` transitions).
    pub fn heartbeats(&self, signals: &[S], just_transitioned: &HashSet<Ipv4Addr>) -> Vec<A> {
        let active: HashMap<Ipv4Addr, &S> = signals.iter().map(|s| (s.src_ip(), s)).collect();

        self.states
            .iter()
            .filter_map(|(ip, state)| {
                if !state.is_firing() || just_transitioned.contains(ip) {
                    return None;
                }
                let signal = active.get(ip).copied()?;
                Some(A::from_signal(*ip, Some(signal)))
            })
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.states.len()
    }

    pub fn snapshot(&self) -> Vec<IpAlertSlotSnapshot> {
        self.states
            .iter()
            .map(|(ip, s)| IpAlertSlotSnapshot {
                src_ip: *ip,
                phase_label: s.phase_label(),
                consecutive_count: s.consecutive_count,
            })
            .collect()
    }
}
