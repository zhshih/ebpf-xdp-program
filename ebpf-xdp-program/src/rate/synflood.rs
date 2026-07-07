//! Per-source-IP SYN rate computation.
//!
//! Unlike [`super::compute`]'s fixed 5-entry `ProtoIndex` array, the
//! `SYN_TRACKER` BPF map has unbounded key cardinality (one entry per
//! distinct source IP the kernel has recently seen). [`read_syn_snapshot`]
//! does a fresh full read of the live map every call rather than
//! maintaining an accumulator, so user-space memory for this tracker stays
//! bounded by twice the kernel map's own (LRU-bounded) capacity at all
//! times — no separate user-space eviction/TTL sweep is needed.
use std::{collections::HashMap, net::Ipv4Addr, time::Instant};

use aya::maps::{HashMap as BpfHashMap, MapData};
use ebpf_xdp_program_common::SynCounter;

/// A full read of the live `SYN_TRACKER` map's contents at one point in time.
#[derive(Clone)]
pub struct SynCountersSnapshot {
    pub timestamp: Instant,
    pub counters: HashMap<u32, SynCounter>,
}

pub fn read_syn_snapshot(
    map: &BpfHashMap<&MapData, u32, SynCounter>,
) -> anyhow::Result<SynCountersSnapshot> {
    let mut counters = HashMap::new();
    for entry in map.iter() {
        let (key, counter) = entry?;
        counters.insert(key, counter);
    }
    Ok(SynCountersSnapshot {
        timestamp: Instant::now(),
        counters,
    })
}

/// One source IP's SYN rate for the interval between two snapshots.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SynIpRate {
    pub src_ip: Ipv4Addr,
    pub pps: f64,
}

/// Diffs two consecutive full snapshots and returns the `top_n` source IPs
/// by SYN pps, descending.
///
/// IPs present only in `curr` (first seen this tick, or re-created after
/// kernel-LRU eviction) are treated as fresh from zero, so the very first
/// tick of a flood isn't missed waiting for a "previous" sample to diff
/// against. IPs present only in `prev` (evicted, or simply stopped sending)
/// are dropped — they're not "current" and shouldn't appear in this tick's
/// top-N.
pub fn compute_syn_rates_top_n(
    prev: &SynCountersSnapshot,
    curr: &SynCountersSnapshot,
    top_n: usize,
) -> Vec<SynIpRate> {
    let dt = curr.timestamp.duration_since(prev.timestamp).as_secs_f64();
    if dt <= 0.0 {
        return vec![];
    }

    let mut rates: Vec<SynIpRate> = curr
        .counters
        .iter()
        .map(|(&key, c)| {
            let prev_packets = prev.counters.get(&key).map_or(0, |p| p.packets);
            let delta = c.packets.saturating_sub(prev_packets);
            SynIpRate {
                src_ip: Ipv4Addr::from(key),
                pps: delta as f64 / dt,
            }
        })
        .filter(|r| r.pps > 0.0)
        .collect();

    rates.sort_by(|a, b| b.pps.partial_cmp(&a.pps).unwrap_or(std::cmp::Ordering::Equal));
    rates.truncate(top_n);
    rates
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn snapshot(t: Instant, entries: &[(u32, u64)]) -> SynCountersSnapshot {
        let counters = entries
            .iter()
            .map(|&(ip, packets)| (ip, SynCounter { packets, bytes: packets * 60 }))
            .collect();
        SynCountersSnapshot {
            timestamp: t,
            counters,
        }
    }

    #[test]
    fn compute_syn_rates_top_n_basic() {
        let t0 = Instant::now();
        let prev = snapshot(t0, &[(1, 10)]);
        let curr = snapshot(t0 + Duration::from_secs(1), &[(1, 110)]);

        let rates = compute_syn_rates_top_n(&prev, &curr, 10);
        assert_eq!(rates.len(), 1);
        assert_eq!(rates[0].src_ip, Ipv4Addr::from(1));
        assert!((rates[0].pps - 100.0).abs() < 1.0, "got {}", rates[0].pps);
    }

    #[test]
    fn compute_syn_rates_top_n_truncates_to_top_n() {
        let t0 = Instant::now();
        let prev = snapshot(t0, &[]);
        let curr = snapshot(t0 + Duration::from_secs(1), &[(1, 300), (2, 100), (3, 200)]);

        let rates = compute_syn_rates_top_n(&prev, &curr, 2);
        assert_eq!(rates.len(), 2);
        assert_eq!(rates[0].src_ip, Ipv4Addr::from(1));
        assert_eq!(rates[1].src_ip, Ipv4Addr::from(3));
    }

    #[test]
    fn compute_syn_rates_top_n_treats_new_ip_as_fresh() {
        let t0 = Instant::now();
        let prev = snapshot(t0, &[]);
        let curr = snapshot(t0 + Duration::from_secs(1), &[(7, 50)]);

        let rates = compute_syn_rates_top_n(&prev, &curr, 10);
        assert_eq!(rates.len(), 1);
        assert!((rates[0].pps - 50.0).abs() < 1.0, "got {}", rates[0].pps);
    }

    #[test]
    fn compute_syn_rates_top_n_drops_ip_only_in_prev() {
        let t0 = Instant::now();
        let prev = snapshot(t0, &[(1, 10), (2, 20)]);
        let curr = snapshot(t0 + Duration::from_secs(1), &[(1, 20)]);

        let rates = compute_syn_rates_top_n(&prev, &curr, 10);
        assert_eq!(rates.len(), 1);
        assert_eq!(rates[0].src_ip, Ipv4Addr::from(1));
    }

    #[test]
    fn compute_syn_rates_top_n_zero_dt_returns_empty() {
        let t0 = Instant::now();
        let prev = snapshot(t0, &[(1, 10)]);
        let curr = snapshot(t0, &[(1, 20)]);

        let rates = compute_syn_rates_top_n(&prev, &curr, 10);
        assert!(rates.is_empty());
    }
}
