mod alert;
mod anomaly;
mod baseline;
mod pipeline;
mod rate;

use anyhow::Context as _;
use aya::{
    maps::PerCpuArray,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use crate::{
    alert::{decision_to_alert, emit_alert},
    anomaly::AnalyzeResult,
    baseline::ProtoEwmaBaselineEstimator,
    pipeline::analyze_snapshot,
    rate::{
        {ProtoRate, ProtoRateSnapshot, TrafficCountersSnapshot},
        {compute_rates, diff_stats, read_snapshot},
    },
};
use ebpf_xdp_program_common::{ProtoIndex, ProtoStats};
use std::time::Duration;
use tokio::signal;

const STATS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MIX_AGG_INTERVAL: Duration = Duration::from_secs(5);
const ANOMALY_EVAL_INTERVAL: Duration = Duration::from_secs(60);

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

    let mut stats_poll_tick = tokio::time::interval(STATS_POLL_INTERVAL);
    let mut mix_aggregation_tick = tokio::time::interval(MIX_AGG_INTERVAL);
    let mut anomaly_eval_tick = tokio::time::interval(ANOMALY_EVAL_INTERVAL);

    let mut current_counters: Option<TrafficCountersSnapshot> = None;
    let mut prev_mix_counters: Option<TrafficCountersSnapshot> = None;
    let mut prev_anomaly_counters: Option<TrafficCountersSnapshot> = None;

    let mut traffic_baseline = ProtoEwmaBaselineEstimator::new(0.2);
    loop {
        tokio::select! {
            _ = stats_poll_tick.tick() => {
                let curr = read_snapshot(&proto_stats)?;
                current_counters = Some(curr.clone());

                for (idx, s) in curr.stats.iter().enumerate() {
                    let Some(proto) = ProtoIndex::from_index(idx) else { continue };

                    tracing::debug!(
                        "proto {} -> packets={}, bytes={}",
                        proto.label(),
                        s.packets,
                        s.bytes
                    );
                }
            }
            _ = mix_aggregation_tick.tick() => {
                let Some(curr) = &current_counters else { continue };
                let Some(prev) = &prev_mix_counters else {
                    prev_mix_counters = Some(curr.clone());
                    continue;
                };

                let mix_delta = diff_stats(&curr.stats, &prev.stats);
                let window_secs = MIX_AGG_INTERVAL.as_secs_f64();

                let mix_rate_snapshot = ProtoRateSnapshot {
                    timestamp: curr.timestamp,
                    rates: mix_delta
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, d)| -> Option<ProtoRate> {
                            let proto = ProtoIndex::from_index(idx)?;
                            Some(ProtoRate {
                                proto,
                                pps: d.packets as f64 / window_secs,
                                bps: d.bytes as f64 * 8.0 / window_secs,
                            })
                        })
                        .collect(),
                };

                traffic_baseline.update(&mix_rate_snapshot.rates);

                let total_packets: u64 = mix_delta.iter().map(|s| s.packets).sum();
                let total_bytes: u64 = mix_delta.iter().map(|s| s.bytes).sum();

                if total_packets > 0 {
                    let icmp = mix_delta[ProtoIndex::Icmp as usize].packets;
                    let tcp = mix_delta[ProtoIndex::Tcp as usize].packets;
                    let udp = mix_delta[ProtoIndex::Udp as usize].packets;

                    tracing::info!(
                        "mix(5s packets): ICMP={:.1}%, TCP={:.1}%, UDP={:.1}%",
                        icmp as f64 * 100.0 / total_packets as f64,
                        tcp as f64 * 100.0 / total_packets as f64,
                        udp as f64 * 100.0 / total_packets as f64,

                    );
                }

                if total_bytes > 0 {
                    let ipv6 = mix_delta[ProtoIndex::Ipv6 as usize].bytes;
                    tracing::info!(
                        "mix(5s bytes): IPv6={:.1}%, IPv4={:.1}%",
                        ipv6 as f64 * 100.0 / total_bytes as f64,
                        100.0 - ipv6 as f64 * 100.0 / total_bytes as f64,
                    );
                }

                prev_mix_counters = Some(curr.clone());
            }
            _ = anomaly_eval_tick.tick() => {
                let Some(curr) = &current_counters else { continue };
                let Some(prev) = &prev_anomaly_counters else {
                    prev_anomaly_counters = Some(curr.clone());
                    continue;
                };

                let rates = compute_rates(prev, curr);

                let anomaly_rate_snapshot = ProtoRateSnapshot {
                    timestamp: curr.timestamp,
                    rates,
                };

                match analyze_snapshot(&anomaly_rate_snapshot, &mut traffic_baseline) {
                    AnalyzeResult::WarmingUp => {
                        tracing::info!("baseline warming up");
                    }

                    AnalyzeResult::Normal(decisions) => {
                        for decision in decisions {
                            tracing::info!(
                                "analyze proto {} -> pps={:.1}, bps={:.1}, z_pps={:?}, z_bps={:?}, level={:?}, confidence={:.2}",
                                decision.proto.label(),
                                decision.observed_pps,
                                decision.observed_bps,
                                decision.z_pps,
                                decision.z_bps,
                                decision.anomaly_level,
                                decision.confidence(),
                            );
                            if let Some(alert) = decision_to_alert(&decision) {
                                emit_alert(alert);
                            }
                        }
                    }
                }

                prev_anomaly_counters = Some(curr.clone());
            }
            _ = signal::ctrl_c() => {
                tracing::info!("Exiting...");
                break;
            }
        }
    }

    Ok(())
}
