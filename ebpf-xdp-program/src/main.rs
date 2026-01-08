mod stats;

use anyhow::Context as _;
use aya::{
    maps::PerCpuArray,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use crate::stats::{
    baseline::proto::{ProtoBaseline, ProtoEwmaBaseline},
    rate::{
        compute::{compute_rates, diff_stats, read_snapshot},
        model::ProtoSnapshot,
    },
};
use ebpf_xdp_program_common::{ProtoIndex, ProtoStats};
use std::time::Duration;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlo1")]
    iface: String,
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

    let mut poll_1s = tokio::time::interval(Duration::from_secs(1));
    let mut report_5s = tokio::time::interval(Duration::from_secs(5));
    let mut rate_60s = tokio::time::interval(Duration::from_secs(60));

    let mut last_mix_snapshot: Option<ProtoSnapshot> = None;
    let mut last_rate_snapshot: Option<ProtoSnapshot> = None;
    let mut latest_snapshot: Option<ProtoSnapshot> = None;

    let mut ewma = ProtoEwmaBaseline::new(0.2);
    loop {
        tokio::select! {
            _ = poll_1s.tick() => {
                let curr = read_snapshot(&proto_stats)?;
                latest_snapshot = Some(curr.clone());

                for (idx, s) in curr.stats.iter().enumerate() {
                    let proto = unsafe { core::mem::transmute::<u32, ProtoIndex>(idx as u32) };

                    tracing::debug!(
                        "proto {} -> packets={}, bytes={}",
                        proto.label(),
                        s.packets,
                        s.bytes
                    );
                }
            }
            _ = report_5s.tick() => {
                let Some(curr) = &latest_snapshot else { continue };

                if let Some(prev) = &last_mix_snapshot {
                    let delta = diff_stats(&curr.stats, &prev.stats);

                    let total_packets: u64 = delta.iter().map(|s| s.packets).sum();
                    let total_bytes: u64 = delta.iter().map(|s| s.bytes).sum();

                    if total_packets > 0 {
                        let tcp = delta[ProtoIndex::Tcp as usize].packets;
                        let udp = delta[ProtoIndex::Udp as usize].packets;

                        tracing::info!(
                            "mix(5s packets): TCP={:.1}%, UDP={:.1}%",
                            tcp as f64 * 100.0 / total_packets as f64,
                            udp as f64 * 100.0 / total_packets as f64,
                        );
                    }

                    if total_bytes > 0 {
                        let ipv6 = delta[ProtoIndex::Ipv6 as usize].bytes;
                        tracing::info!(
                            "mix(5s bytes): IPv6={:.1}%, IPv4={:.1}%",
                            ipv6 as f64 * 100.0 / total_bytes as f64,
                            100.0 - ipv6 as f64 * 100.0 / total_bytes as f64,
                        );
                    }
                }

                last_mix_snapshot = Some(curr.clone());
            }
            _ = rate_60s.tick() => {
                let Some(curr) = &latest_snapshot else { continue };

                if let Some(prev) = &last_rate_snapshot {
                    let rates = compute_rates(prev, curr);

                    ewma.update(&rates);

                    for r in &rates {
                        if let Some(ProtoBaseline { pps, bps }) = ewma.baseline(r.proto) {
                            let (z_pps, z_bps) = ewma.z_scores(r.proto, r.pps, r.bps).unwrap_or((None, None));

                            tracing::info!(
                                "rate(60s) proto={:?} \
                                pps={:.1} (ewma={:.1}, σ={:.1}, z-score={}) \
                                bps={:.1} (ewma={:.1}, σ={:.1}, z-score={})",
                                r.proto,
                                r.pps,
                                pps.mean,
                                pps.stddev,
                                z_pps.map_or_else(|| "N/A".to_string(), |z| format!("{:.1}", z)),
                                r.bps,
                                bps.mean,
                                bps.stddev,
                                z_bps.map_or_else(|| "N/A".to_string(), |z| format!("{:.1}", z)),
                            );
                        }
                    }
                }

                last_rate_snapshot = Some(curr.clone());
            }
            _ = signal::ctrl_c() => {
                tracing::info!("Exiting...");
                break;
            }
        }
    }

    Ok(())
}
