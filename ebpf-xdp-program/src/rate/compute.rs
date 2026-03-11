use aya::maps::{MapData, PerCpuArray};
use std::time::Instant;

use ebpf_xdp_program_common::{ProtoIndex, ProtoStats};

use super::model::{ProtoRate, TrafficCounters, TrafficCountersSnapshot};

pub fn read_snapshot(
    proto_stats: &PerCpuArray<&MapData, ProtoStats>,
) -> anyhow::Result<TrafficCountersSnapshot> {
    Ok(TrafficCountersSnapshot {
        timestamp: Instant::now(),
        stats: read_current_stats(proto_stats)?,
    })
}

/// Computes the per-protocol counter delta between two consecutive snapshots.
///
/// Uses saturating subtraction to handle the unlikely case of counter wraps
/// or out-of-order reads without panicking.
pub fn diff_stats(cur: &[TrafficCounters], prev: &[TrafficCounters]) -> Vec<TrafficCounters> {
    cur.iter()
        .zip(prev.iter())
        .map(|(c, p)| TrafficCounters {
            packets: c.packets.saturating_sub(p.packets),
            bytes: c.bytes.saturating_sub(p.bytes),
        })
        .collect()
}

/// Computes per-protocol packet and byte rates (pps/bps) from two snapshots.
///
/// Divides counter deltas by the elapsed time between snapshot timestamps.
/// At BPF poll intervals (1s), `dt` is always positive; a near-zero `dt`
/// would produce very large (but not NaN) values.
pub fn compute_rates(
    prev: &TrafficCountersSnapshot,
    curr: &TrafficCountersSnapshot,
) -> Vec<ProtoRate> {
    let dt = curr.timestamp.duration_since(prev.timestamp).as_secs_f64();

    curr.stats
        .iter()
        .zip(prev.stats.iter())
        .enumerate()
        .filter_map(|(idx, (curr, prev))| {
            let proto = ProtoIndex::from_index(idx)?;

            Some(ProtoRate {
                proto,
                pps: curr.packets.saturating_sub(prev.packets) as f64 / dt,
                bps: curr.bytes.saturating_sub(prev.bytes) as f64 / dt,
            })
        })
        .collect()
}

/// Returns per-protocol packet share as a percentage of total packets in `delta`.
/// Returns an empty vec if total packets is zero.
pub fn compute_mix(delta: &[TrafficCounters]) -> Vec<(ProtoIndex, f64)> {
    let total = delta.iter().map(|s| s.packets).sum::<u64>();
    if total == 0 {
        return vec![];
    }
    let total = total as f64;
    (0..delta.len())
        .filter_map(|idx| {
            let proto = ProtoIndex::from_index(idx)?;
            Some((proto, delta[idx].packets as f64 * 100.0 / total))
        })
        .collect()
}

fn read_current_stats(
    proto_stats: &PerCpuArray<&MapData, ProtoStats>,
) -> anyhow::Result<Vec<TrafficCounters>> {
    let mut stats = vec![TrafficCounters::default(); ProtoIndex::COUNT as usize];

    for idx in 0..ProtoIndex::COUNT {
        let values = proto_stats.get(&idx, 0)?;
        for v in values.iter() {
            stats[idx as usize].packets += v.packets;
            stats[idx as usize].bytes += v.bytes;
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn counters(packets: u64, bytes: u64) -> TrafficCounters {
        TrafficCounters { packets, bytes }
    }

    #[test]
    fn diff_stats_basic() {
        let cur = vec![counters(10, 200), counters(20, 500)];
        let prev = vec![counters(3, 50), counters(5, 100)];
        let diff = diff_stats(&cur, &prev);
        assert_eq!(diff[0].packets, 7);
        assert_eq!(diff[0].bytes, 150);
        assert_eq!(diff[1].packets, 15);
        assert_eq!(diff[1].bytes, 400);
    }

    #[test]
    fn diff_stats_saturates_underflow() {
        let cur = vec![counters(3, 10)];
        let prev = vec![counters(10, 50)];
        let diff = diff_stats(&cur, &prev);
        assert_eq!(diff[0].packets, 0, "saturating_sub should clamp to 0");
        assert_eq!(diff[0].bytes, 0, "saturating_sub should clamp to 0");
    }

    #[test]
    fn compute_rates_correct_pps_bps() {
        // 5 protocol slots, TCP has 1000 packets and 100k bytes in 2 seconds
        let prev_stats = vec![counters(0, 0); ProtoIndex::COUNT as usize];
        let mut curr_stats = vec![counters(0, 0); ProtoIndex::COUNT as usize];
        curr_stats[ProtoIndex::Tcp as usize] = counters(1000, 100_000);

        let t0 = Instant::now();
        let prev = TrafficCountersSnapshot { timestamp: t0, stats: prev_stats };
        let curr = TrafficCountersSnapshot {
            timestamp: t0 + Duration::from_secs(2),
            stats: curr_stats,
        };

        let rates = compute_rates(&prev, &curr);
        let tcp = rates.iter().find(|r| r.proto == ProtoIndex::Tcp).unwrap();

        assert!((tcp.pps - 500.0).abs() < 1.0, "expected 500 pps, got {}", tcp.pps);
        assert!(
            (tcp.bps - 50_000.0).abs() < 1.0,
            "expected 50000 bps, got {}",
            tcp.bps
        );
    }

    #[test]
    fn compute_mix_empty_on_zero_traffic() {
        let delta = vec![counters(0, 0); ProtoIndex::COUNT as usize];
        let mix = compute_mix(&delta);
        assert!(mix.is_empty(), "zero traffic should yield empty mix");
    }

    #[test]
    fn compute_mix_single_proto_100pct() {
        let mut delta = vec![counters(0, 0); ProtoIndex::COUNT as usize];
        delta[ProtoIndex::Tcp as usize] = counters(500, 0);
        let mix = compute_mix(&delta);
        // compute_mix returns all protocols (including 0%), so check TCP's share specifically
        let tcp = mix.iter().find(|(p, _)| *p == ProtoIndex::Tcp).expect("TCP should be in mix");
        assert!((tcp.1 - 100.0).abs() < 0.001, "TCP should have 100% share, got {}", tcp.1);
    }

    #[test]
    fn compute_mix_sums_to_100() {
        let mut delta = vec![counters(0, 0); ProtoIndex::COUNT as usize];
        delta[ProtoIndex::Tcp as usize] = counters(600, 0);
        delta[ProtoIndex::Udp as usize] = counters(300, 0);
        delta[ProtoIndex::Icmp as usize] = counters(100, 0);
        let mix = compute_mix(&delta);
        let sum: f64 = mix.iter().map(|(_, pct)| pct).sum();
        assert!((sum - 100.0).abs() < 0.001, "mix should sum to 100, got {}", sum);
    }
}
