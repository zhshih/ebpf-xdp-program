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

pub fn diff_stats(cur: &[TrafficCounters], prev: &[TrafficCounters]) -> Vec<TrafficCounters> {
    cur.iter()
        .zip(prev.iter())
        .map(|(c, p)| TrafficCounters {
            packets: c.packets.saturating_sub(p.packets),
            bytes: c.bytes.saturating_sub(p.bytes),
        })
        .collect()
}

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

/// Returns per-protocol packet share as a percentage of total packets.
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
