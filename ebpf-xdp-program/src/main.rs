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
    alert::{AlertKind, AlertManager, AlertRule},
    anomaly::{AnomalyLevel, EmergencyDetector, EmergencyThreshold, EwmaDetector},
    baseline::EwmaEstimator,
    pipeline::{PipelineOutcome, run_anomaly_pipeline},
    rate::{ProtoRateSnapshot, TrafficCountersSnapshot, compute_rates, diff_stats, read_snapshot},
};
use ebpf_xdp_program_common::{ProtoIndex, ProtoStats};
use std::time::Duration;
use tokio::signal;

const STATS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MIX_AGG_INTERVAL: Duration = Duration::from_secs(5);
const ANOMALY_EVAL_INTERVAL: Duration = Duration::from_secs(30);

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

    let mut traffic_baseline = EwmaEstimator::new(0.4, 5, 1e-3, Duration::from_secs(120));

    let rules = vec![
        AlertRule {
            kind: AlertKind::Spike,
            min_level: AnomalyLevel::Suspicious,
            min_confidence: 0.6,
            cooldown: Duration::from_secs(120),
            consecutive_threshold: 5,
            resolve_consecutive_threshold: 3,
            freezes_baseline: true,
        },
        AlertRule {
            kind: AlertKind::Emergency,
            min_level: AnomalyLevel::Severe,
            min_confidence: 0.0,
            cooldown: Duration::from_secs(60),
            consecutive_threshold: 1,
            resolve_consecutive_threshold: 1,
            freezes_baseline: false,
        },
    ];
    let mut alert_manager = AlertManager::new(rules);

    let emergency_detector = EmergencyDetector::new(vec![EmergencyThreshold {
        proto: ProtoIndex::Icmp,
        max_pps: Some(3.0),
        max_bps: None,
    }]);
    let mut baseline_warmed_up = false;

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
                    tracing::debug!(
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

                let rate_snapshot = ProtoRateSnapshot {
                    timestamp: curr.timestamp,
                    rates,
                };

                let ewma_detector = EwmaDetector::new(&traffic_baseline);
                let outcome = run_anomaly_pipeline(
                    &rate_snapshot,
                    &ewma_detector,
                    &emergency_detector,
                    &mut alert_manager,
                );

                if !alert_manager.is_baseline_frozen(curr.timestamp) {
                    tracing::info!("updating traffic baseline");
                    traffic_baseline.update(&rate_snapshot.rates);
                }

                if !baseline_warmed_up && !matches!(outcome, PipelineOutcome::WarmingUp) {
                    baseline_warmed_up = true;
                    tracing::info!("baseline ready");
                }

                match outcome {
                    PipelineOutcome::WarmingUp => {
                        tracing::info!("baseline warming up");
                    }

                    PipelineOutcome::NoSignals => {
                        tracing::info!("no alert signals generated during anomaly evaluation");
                    }

                    PipelineOutcome::Events {
                        events,
                    } => {
                        for event in events {
                            tracing::warn!(
                                proto = ?event.alert.proto,
                                level = ?event.alert.level,
                                kind = ?event.alert.kind,
                                state = ?event.lifecycle,
                                confidence = event.alert.confidence,
                                "alert event"
                            );
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
