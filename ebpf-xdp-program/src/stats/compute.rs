use aya::maps::{MapData, PerCpuArray};
use std::time::Instant;

use ebpf_xdp_program_common::{ProtoIndex, ProtoStats};

use super::model::{AccumulatedStats, ProtoRate, ProtoSnapshot};

pub fn read_snapshot(
    proto_stats: &PerCpuArray<&MapData, ProtoStats>,
) -> anyhow::Result<ProtoSnapshot> {
    Ok(ProtoSnapshot {
        timestamp: Instant::now(),
        stats: read_current_stats(proto_stats)?,
    })
}

pub fn diff_stats(cur: &[AccumulatedStats], prev: &[AccumulatedStats]) -> Vec<AccumulatedStats> {
    cur.iter()
        .zip(prev.iter())
        .map(|(c, p)| AccumulatedStats {
            packets: c.packets.saturating_sub(p.packets),
            bytes: c.bytes.saturating_sub(p.bytes),
        })
        .collect()
}

pub fn compute_rates(prev: &ProtoSnapshot, curr: &ProtoSnapshot) -> Vec<ProtoRate> {
    let dt = curr.timestamp.duration_since(prev.timestamp).as_secs_f64();

    curr.stats
        .iter()
        .zip(prev.stats.iter())
        .enumerate()
        .map(|(idx, (curr, prev))| {
            let pkt_delta = curr.packets.saturating_sub(prev.packets);
            let byte_delta = curr.bytes.saturating_sub(prev.bytes);

            ProtoRate {
                proto: unsafe {
                    core::mem::transmute::<u32, ebpf_xdp_program_common::ProtoIndex>(idx as u32)
                },
                pps: pkt_delta as f64 / dt,
                bps: byte_delta as f64 / dt,
            }
        })
        .collect()
}

fn read_current_stats(
    proto_stats: &PerCpuArray<&MapData, ProtoStats>,
) -> anyhow::Result<Vec<AccumulatedStats>> {
    let mut stats = vec![AccumulatedStats::default(); ProtoIndex::COUNT as usize];

    for idx in 0..ProtoIndex::COUNT {
        let values = proto_stats.get(&idx, 0)?;
        for v in values.iter() {
            stats[idx as usize].packets += v.packets;
            stats[idx as usize].bytes += v.bytes;
        }
    }

    Ok(stats)
}
