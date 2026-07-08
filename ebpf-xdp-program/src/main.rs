mod alert;
mod anomaly;
mod api;
mod baseline;
mod config;
mod metrics;
mod pipeline;
mod rate;

use anyhow::Context as _;
use aya::{
    maps::{HashMap as BpfHashMap, PerCpuArray},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::warn;
use std::time::Duration;

use ebpf_xdp_program_common::{ProtoIndex, ProtoStats, SynCounter};
use tokio::signal;

use crate::{
    alert::AlertManager,
    pipeline::{AnomalyRunner, SynFloodRunner},
    rate::{
        SynCountersSnapshot, TrafficCountersSnapshot, compute_mix, diff_stats, read_snapshot,
        read_syn_snapshot,
    },
};

const STATS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MIX_AGG_INTERVAL: Duration = Duration::from_secs(5);
const ANOMALY_EVAL_INTERVAL: Duration = Duration::from_secs(30);
// Its own cadence rather than the 1s stats-poll interval: a near-full
// SYN_TRACKER map read costs ~2x max_entries syscalls, which is wasteful at
// 1s. Not the 30s anomaly-eval interval either — that's tuned for EWMA
// baseline warmup, which SynFloodDetector (stateless/threshold-based) has
// no use for.
const SYN_FLOOD_EVAL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, env = "XDP_IFACE")]
    iface: String,

    #[clap(long, default_value = "9091")]
    metrics_port: u16,

    /// Port for the read-only JSON API (`/health`, `/config`, `/anomalies`).
    #[clap(long, default_value = "8080")]
    api_port: u16,

    /// Optional path to a TOML configuration file.
    /// If omitted, compiled-in defaults are used.
    #[clap(long, value_name = "FILE")]
    config: Option<std::path::PathBuf>,
}

/// Builds the shared API context and spawns the Axum server as an independent
/// task (fire-and-forget, like the eBPF-logger task above). Returns the
/// context so the main loop can write tick-derived state into it.
fn spawn_api_server(port: u16, resolved_config: config::ResolvedConfig) -> api::ApiContext {
    let ctx = api::ApiContext {
        resolved_config: std::sync::Arc::new(resolved_config),
        dynamic: std::sync::Arc::new(tokio::sync::RwLock::new(api::ApiState::new())),
    };
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let ctx_for_task = ctx.clone();
    tokio::task::spawn(async move {
        if let Err(e) = api::serve(addr, ctx_for_task).await {
            tracing::error!(error = %e, "API server task exited with error");
        }
    });
    tracing::info!(port, "Axum API listening");
    ctx
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let opt = Opt::parse();
    let metrics_handle = metrics::init(opt.metrics_port)?;
    tracing::info!(port = opt.metrics_port, "Prometheus metrics listening");

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {ret}");
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
                    let mut guard = logger.readable_mut().await.expect("eBPF logger fd error");
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt {
        iface,
        config: config_path,
        api_port,
        ..
    } = opt;
    let program: &mut Xdp = ebpf
        .program_mut("ebpf_xdp_program")
        .context("eBPF program 'ebpf_xdp_program' not found in object file")?
        .try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let proto_stats: PerCpuArray<_, ProtoStats> = PerCpuArray::try_from(
        ebpf.map("PROTO_STATS")
            .context("PROTO_STATS map not found")?,
    )?;

    // The kernel side declares this as an `LruHashMap`, but aya's user-space
    // `HashMap` wrapper reads back both `HashMap` and `LruHashMap` kernel
    // map variants — there is no separate user-space `LruHashMap` type.
    let syn_tracker: BpfHashMap<_, u32, SynCounter> = BpfHashMap::try_from(
        ebpf.map("SYN_TRACKER")
            .context("SYN_TRACKER map not found")?,
    )?;

    let mut stats_poll_tick = tokio::time::interval(STATS_POLL_INTERVAL);
    let mut mix_aggregation_tick = tokio::time::interval(MIX_AGG_INTERVAL);
    let mut anomaly_eval_tick = tokio::time::interval(ANOMALY_EVAL_INTERVAL);
    let mut syn_flood_eval_tick = tokio::time::interval(SYN_FLOOD_EVAL_INTERVAL);

    let mut current_counters: Option<TrafficCountersSnapshot> = None;
    let mut prev_mix_counters: Option<TrafficCountersSnapshot> = None;
    let (detectors, resolved_config) = config::resolve_all(config_path.as_deref())?;
    let mut anomaly_runner = AnomalyRunner::new(
        detectors.baseline,
        detectors.emergency,
        AlertManager::new(detectors.alert_rules),
    );
    let mut syn_flood_runner = SynFloodRunner::new(
        detectors.synflood_detector,
        detectors.synflood_alert_manager,
    );

    let api_ctx = spawn_api_server(api_port, resolved_config);

    loop {
        tokio::select! {
            _ = stats_poll_tick.tick() => {
                let curr = match read_snapshot(&proto_stats) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to read eBPF stats snapshot; skipping tick");
                        continue;
                    }
                };
                current_counters = Some(curr.clone());
                {
                    let mut state = api_ctx.dynamic.write().await;
                    state.last_stats_at = Some(std::time::Instant::now());
                }

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
                let mix = compute_mix(&mix_delta);

                if !mix.is_empty() {
                    let get = |p: ProtoIndex| mix.iter().find(|(k, _)| *k == p).map(|(_, v)| *v).unwrap_or(0.0);
                    tracing::info!(
                        "mix(5s packets): ICMP={:.1}%, TCP={:.1}%, UDP={:.1}%",
                        get(ProtoIndex::Icmp),
                        get(ProtoIndex::Tcp),
                        get(ProtoIndex::Udp),
                    );
                    metrics_handle.update_mix(&mix);
                }

                let total_bytes: u64 = mix_delta.iter().map(|s| s.bytes).sum();
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
                anomaly_runner.tick(&current_counters, &metrics_handle);
                let mut state = api_ctx.dynamic.write().await;
                state.warmed_up = anomaly_runner.warmed_up();
                state.runner_snapshot = Some(anomaly_runner.snapshot(std::time::Instant::now()));
            }
            _ = syn_flood_eval_tick.tick() => {
                let curr: Option<SynCountersSnapshot> = match read_syn_snapshot(&syn_tracker) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to read SYN_TRACKER snapshot; skipping tick");
                        continue;
                    }
                };
                syn_flood_runner.tick(&curr, &metrics_handle);
                let mut state = api_ctx.dynamic.write().await;
                state.synflood_snapshot = Some(syn_flood_runner.snapshot());
            }
            _ = signal::ctrl_c() => {
                tracing::info!("Exiting...");
                break;
            }
        }
    }

    Ok(())
}
