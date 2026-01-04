use anyhow::Context as _;
use aya::{
    maps::{MapData, PerCpuArray},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use ebpf_xdp_program_common::{ProtoIndex, ProtoStats};
use std::time::Duration;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlo1")]
    iface: String,
}

#[derive(Default, Clone)]
struct AccumulatedStats {
    packets: u64,
    bytes: u64,
}

#[derive(Clone, Default)]
struct Snapshot {
    stats: Vec<AccumulatedStats>,
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

fn diff_stats(cur: &[AccumulatedStats], prev: &[AccumulatedStats]) -> Vec<AccumulatedStats> {
    cur.iter()
        .zip(prev.iter())
        .map(|(c, p)| AccumulatedStats {
            packets: c.packets.saturating_sub(p.packets),
            bytes: c.bytes.saturating_sub(p.bytes),
        })
        .collect()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opt = Opt::parse();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-xdp-program"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("ebpf_xdp_program").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let proto_stats: PerCpuArray<_, ProtoStats> = PerCpuArray::try_from(
        ebpf.map("PROTO_STATS")
            .context("PROTO_STATS map not found")?,
    )?;

    let mut poll = tokio::time::interval(Duration::from_secs(1));
    let mut report = tokio::time::interval(Duration::from_secs(5));

    let mut last_report_snapshot = Snapshot {
        stats: vec![AccumulatedStats::default(); ProtoIndex::COUNT as usize],
    };
    loop {
        tokio::select! {
            _ = poll.tick() => {
                let current = read_current_stats(&proto_stats)?;
                for (idx, s) in current.iter().enumerate() {
                    let proto = unsafe { core::mem::transmute::<u32, ProtoIndex>(idx as u32) };

                    tracing::info!(
                        "proto {} -> packets={}, bytes={}",
                        proto.label(),
                        s.packets,
                        s.bytes
                    );
                }
            }
            _ = report.tick() => {
                let current = read_current_stats(&proto_stats)?;

                let delta = diff_stats(&current, &last_report_snapshot.stats);
                last_report_snapshot.stats = current.clone();

                let total_packets: u64 = delta.iter().map(|s| s.packets).sum();
                let total_bytes: u64 = delta.iter().map(|s| s.bytes).sum();

                if total_packets == 0 || total_bytes == 0 {
                    tracing::info!("no traffic observed in this interval");
                    continue;
                }

                // --- 1) TCP vs UDP (packet ratio) ---
                let tcp_packets = delta[ProtoIndex::Tcp as usize].packets;
                let udp_packets = delta[ProtoIndex::Udp as usize].packets;

                let tcp_pct = tcp_packets as f64 * 100.0 / total_packets as f64;
                let udp_pct = udp_packets as f64 * 100.0 / total_packets as f64;

                tracing::info!(
                    "traffic mix (packets): TCP={:.1}%, UDP={:.1}%",
                    tcp_pct,
                    udp_pct
                );


                // --- 2) IPv6 vs IPv4 (byte ratio) ---
                let ipv6_bytes = delta[ProtoIndex::Ipv6 as usize].bytes;
                let ipv6_pct = ipv6_bytes as f64 * 100.0 / total_bytes as f64;

                tracing::info!(
                    "traffic mix (bytes): IPv6={:.1}%, IPv4={:.1}%",
                    ipv6_pct,
                    100.0 - ipv6_pct
                );

                // --- 3) Control-plane vs Data-plane (byte ratio) ---
                // Control-plane: ICMP
                // Data-plane: TCP + UDP
                let control_plane_bytes =
                    delta[ProtoIndex::Icmp as usize].bytes;

                let data_plane_bytes =
                    delta[ProtoIndex::Tcp as usize].bytes +
                    delta[ProtoIndex::Udp as usize].bytes;

                let control_pct = control_plane_bytes as f64 * 100.0 / total_bytes as f64;
                let data_pct = data_plane_bytes as f64 * 100.0 / total_bytes as f64;

                tracing::info!(
                    "traffic role (bytes): control-plane={:.1}%, data-plane={:.1}%",
                    control_pct,
                    data_pct
                );
            }
            _ = signal::ctrl_c() => {
                tracing::info!("Exiting...");
                break;
            }
        }
    }

    Ok(())
}
