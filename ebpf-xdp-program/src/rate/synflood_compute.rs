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

use aya::maps::{MapData, PerCpuHashMap};
use ebpf_xdp_program_common::SynCounter;

use super::model::{SynCountersSnapshot, SynIpRate};

/// Reads every key's `SynCounter` and sums it across CPUs — `SYN_TRACKER` is
/// per-CPU (see the kernel-side map doc) so concurrent updates from
/// different RX queues never race on the same counter.
pub fn read_syn_snapshot(
    map: &PerCpuHashMap<&MapData, u32, SynCounter>,
) -> anyhow::Result<SynCountersSnapshot> {
    let mut counters = HashMap::new();
    for entry in map.iter() {
        let (key, per_cpu) = entry?;
        let summed = per_cpu.iter().fold(
            SynCounter {
                packets: 0,
                bytes: 0,
            },
            |acc, c| SynCounter {
                packets: acc.packets + c.packets,
                bytes: acc.bytes + c.bytes,
            },
        );
        counters.insert(key, summed);
    }
    Ok(SynCountersSnapshot {
        timestamp: Instant::now(),
        counters,
    })
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
    let Some(dt) = super::dt_secs(prev.timestamp, curr.timestamp) else {
        return vec![];
    };

    let mut rates: Vec<SynIpRate> = curr
        .counters
        .iter()
        .map(|(&key, c)| {
            let prev_packets = prev.counters.get(&key).map_or(0, |p| p.packets);
            SynIpRate {
                src_ip: Ipv4Addr::from(key),
                pps: super::rate(c.packets, prev_packets, dt),
            }
        })
        .filter(|r| r.pps > 0.0)
        .collect();

    rates.sort_by(|a, b| {
        b.pps
            .partial_cmp(&a.pps)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
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
            .map(|&(ip, packets)| {
                (
                    ip,
                    SynCounter {
                        packets,
                        bytes: packets * 60,
                    },
                )
            })
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
