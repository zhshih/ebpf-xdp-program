//! Per-source-IP port-scan breadth computation.
//!
//! Unlike [`super::synflood_compute`]'s diffed-rate shape, "how many
//! distinct destination ports has this source IP touched recently" is a
//! live gauge computed from a single fresh snapshot — there's no
//! `prev`/`curr` diff here, and no per-CPU fold on read since
//! `PORT_SCAN_TRACKER` is a plain (non-per-CPU) map.
//!
//! The kernel writes `PortTouch::last_seen_ns` via `bpf_ktime_get_ns()`, a
//! `CLOCK_MONOTONIC`-equivalent clock (nanoseconds since boot, not
//! wall-clock). [`now_ktime_ns`] reads the same clock from user-space via
//! `libc::clock_gettime` — `libc` is already a direct dependency of this
//! crate (see `main.rs`'s `setrlimit` call) — so the two are directly
//! comparable.
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

use aya::maps::{HashMap as BpfHashMap, MapData};
use ebpf_xdp_program_common::{PortScanKey, PortTouch};

use super::model::{PortScanCountersSnapshot, PortScanIpBreadth};

fn now_ktime_ns() -> u64 {
    let mut ts = unsafe { std::mem::zeroed::<libc::timespec>() };
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(ret, 0, "clock_gettime(CLOCK_MONOTONIC) failed");
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Reads every `(src_ip, dst_port)` key's last-touch timestamp.
/// `PORT_SCAN_TRACKER` is a plain map, so unlike `read_syn_snapshot` there's
/// no per-CPU summing.
pub fn read_port_scan_snapshot(
    map: &BpfHashMap<&MapData, PortScanKey, PortTouch>,
) -> anyhow::Result<PortScanCountersSnapshot> {
    let mut touches = HashMap::new();
    for entry in map.iter() {
        let (key, touch) = entry?;
        touches.insert(key, touch);
    }
    Ok(PortScanCountersSnapshot {
        now_ns: now_ktime_ns(),
        touches,
    })
}

/// Filters to touches within `window_ns` of the snapshot's own `now_ns`,
/// groups survivors by source IP, and returns the `top_n` IPs by distinct
/// destination-port count, descending.
pub fn compute_port_scan_breadth(
    snapshot: &PortScanCountersSnapshot,
    window_ns: u64,
    top_n: usize,
) -> Vec<PortScanIpBreadth> {
    let mut ports_by_ip: HashMap<u32, HashSet<u16>> = HashMap::new();
    for (key, touch) in &snapshot.touches {
        if snapshot.now_ns.saturating_sub(touch.last_seen_ns) <= window_ns {
            ports_by_ip
                .entry(key.src_addr)
                .or_default()
                .insert(key.dst_port);
        }
    }

    let mut breadths: Vec<PortScanIpBreadth> = ports_by_ip
        .into_iter()
        .map(|(ip, ports)| PortScanIpBreadth {
            src_ip: Ipv4Addr::from(ip),
            distinct_ports: ports.len() as u32,
        })
        .collect();

    breadths.sort_by_key(|b| std::cmp::Reverse(b.distinct_ports));
    breadths.truncate(top_n);
    breadths
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(now_ns: u64, entries: &[(u32, u16, u64)]) -> PortScanCountersSnapshot {
        let touches = entries
            .iter()
            .map(|&(ip, port, last_seen_ns)| {
                (PortScanKey::new(ip, port), PortTouch { last_seen_ns })
            })
            .collect();
        PortScanCountersSnapshot { now_ns, touches }
    }

    #[test]
    fn compute_port_scan_breadth_basic() {
        let snap = snapshot(1_000, &[(1, 80, 900), (1, 443, 950), (1, 22, 990)]);
        let breadths = compute_port_scan_breadth(&snap, 1_000, 10);
        assert_eq!(breadths.len(), 1);
        assert_eq!(breadths[0].src_ip, Ipv4Addr::from(1));
        assert_eq!(breadths[0].distinct_ports, 3);
    }

    #[test]
    fn compute_port_scan_breadth_counts_distinct_ports_only() {
        let snap = snapshot(1_000, &[(1, 80, 900), (1, 80, 950)]);
        let breadths = compute_port_scan_breadth(&snap, 1_000, 10);
        assert_eq!(breadths[0].distinct_ports, 1);
    }

    #[test]
    fn compute_port_scan_breadth_excludes_stale_touches_outside_window() {
        let snap = snapshot(10_000, &[(1, 80, 9_000), (1, 443, 1_000)]);
        let breadths = compute_port_scan_breadth(&snap, 2_000, 10);
        assert_eq!(breadths.len(), 1);
        assert_eq!(breadths[0].distinct_ports, 1);
    }

    #[test]
    fn compute_port_scan_breadth_empty_when_all_stale() {
        let snap = snapshot(10_000, &[(1, 80, 1_000)]);
        let breadths = compute_port_scan_breadth(&snap, 2_000, 10);
        assert!(breadths.is_empty());
    }

    #[test]
    fn compute_port_scan_breadth_truncates_to_top_n() {
        let snap = snapshot(
            1_000,
            &[
                (1, 80, 1_000),
                (2, 80, 1_000),
                (2, 443, 1_000),
                (3, 80, 1_000),
                (3, 443, 1_000),
                (3, 22, 1_000),
            ],
        );
        let breadths = compute_port_scan_breadth(&snap, 1_000, 2);
        assert_eq!(breadths.len(), 2);
        assert_eq!(breadths[0].src_ip, Ipv4Addr::from(3));
        assert_eq!(breadths[0].distinct_ports, 3);
        assert_eq!(breadths[1].src_ip, Ipv4Addr::from(2));
        assert_eq!(breadths[1].distinct_ports, 2);
    }

    #[test]
    fn now_ktime_ns_is_monotonic_non_decreasing() {
        let a = now_ktime_ns();
        let b = now_ktime_ns();
        assert!(b >= a);
    }
}
