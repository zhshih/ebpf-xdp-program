mod alert;
mod alertmanager;
mod anomaly;
mod api;
mod baseline;
mod config;
mod metrics;
mod pipeline;
mod rate;

use anyhow::Context as _;
use aya::{
    maps::{HashMap as BpfHashMap, PerCpuArray, PerCpuHashMap},
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::warn;
use std::time::Duration;

use ebpf_xdp_program_common::{PortScanKey, PortTouch, ProtoIndex, ProtoStats, SynCounter};
use tokio::{signal, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::{
    alert::AlertLifecycleManager,
    pipeline::{AnomalyRunner, PortScanRunner, SynFloodRunner},
    rate::{
        TrafficCountersSnapshot, compute_mix, diff_stats, read_port_scan_snapshot, read_snapshot,
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
const SYNFLOOD_EVAL_INTERVAL: Duration = Duration::from_secs(5);
// Same cadence reasoning as SYNFLOOD_EVAL_INTERVAL: PORT_SCAN_TRACKER's
// full-map read is comparably costly (in fact larger — 16384 vs 8192
// max_entries), and 30s is still tuned for EWMA warmup, irrelevant here.
const PORTSCAN_EVAL_INTERVAL: Duration = Duration::from_secs(5);
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, env = "XDP_IFACE")]
    iface: String,

    #[clap(long, default_value = "9091")]
    metrics_port: u16,

    /// Port for the read-only JSON API (`/health`, `/config`, `/anomalies`,
    /// `/synflood`, `/portscan`).
    #[clap(long, default_value = "8080")]
    api_port: u16,

    /// Optional path to a TOML configuration file.
    /// If omitted, compiled-in defaults are used.
    #[clap(long, value_name = "FILE")]
    config: Option<std::path::PathBuf>,
}

/// Builds the shared API context and spawns the Axum server as an
/// independent task. Returns the context so the main loop can write
/// tick-derived state into it, and the task's `JoinHandle` so an unexpected
/// exit can be detected.
fn spawn_api_server(
    port: u16,
    resolved_config: config::ResolvedConfig,
    shutdown: CancellationToken,
) -> (api::ApiContext, JoinHandle<anyhow::Result<()>>) {
    let ctx = api::ApiContext {
        resolved_config: std::sync::Arc::new(resolved_config),
        dynamic: std::sync::Arc::new(tokio::sync::RwLock::new(api::ApiState::new())),
    };
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let ctx_for_task = ctx.clone();
    let task = tokio::task::spawn(api::serve(addr, ctx_for_task, shutdown));
    tracing::info!(port, "Axum API listening");
    (ctx, task)
}

fn log_api_exit(res: Result<anyhow::Result<()>, tokio::task::JoinError>, when: &str) {
    match res {
        Ok(Ok(())) => tracing::info!("API server exited{when}"),
        Ok(Err(e)) => tracing::error!(error = %e, "API server exited with error{when}"),
        Err(e) => tracing::error!(error = %e, "API server task panicked{when}"),
    }
}

/// Unwraps a BPF map read, logging and returning `None` on error so the
/// caller's tick arm can `continue` instead of processing stale/absent data.
fn read_or_skip<T>(result: anyhow::Result<T>, what: &str) -> Option<T> {
    match result {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, "failed to read {what}; skipping tick");
            None
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let shutdown = CancellationToken::new();

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
    let logger_task: Option<JoinHandle<()>> = match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
            None
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            let shutdown = shutdown.clone();
            Some(tokio::task::spawn(async move {
                loop {
                    tokio::select! {
                        guard = logger.readable_mut() => {
                            let mut guard = guard.expect("eBPF logger fd error");
                            guard.get_inner_mut().flush();
                            guard.clear_ready();
                        }
                        _ = shutdown.cancelled() => break,
                    }
                }
            }))
        }
    };
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

    // The kernel side declares this as an `LruPerCpuHashMap`, but aya's
    // user-space `PerCpuHashMap` wrapper reads back both `PerCpuHashMap` and
    // `LruPerCpuHashMap` kernel map variants — there is no separate
    // user-space `LruPerCpuHashMap` type.
    let syn_tracker: PerCpuHashMap<_, u32, SynCounter> = PerCpuHashMap::try_from(
        ebpf.map("SYN_TRACKER")
            .context("SYN_TRACKER map not found")?,
    )?;

    // PORT_SCAN_TRACKER is a plain (non-per-CPU) map — record_port_touch
    // only overwrites a timestamp, never increments a counter, so there's
    // no cross-CPU race to guard against (see the kernel-side map doc).
    let port_scan_tracker: BpfHashMap<_, PortScanKey, PortTouch> = BpfHashMap::try_from(
        ebpf.map("PORT_SCAN_TRACKER")
            .context("PORT_SCAN_TRACKER map not found")?,
    )?;

    let mut stats_poll_tick = tokio::time::interval(STATS_POLL_INTERVAL);
    let mut mix_aggregation_tick = tokio::time::interval(MIX_AGG_INTERVAL);
    let mut anomaly_eval_tick = tokio::time::interval(ANOMALY_EVAL_INTERVAL);
    let mut synflood_eval_tick = tokio::time::interval(SYNFLOOD_EVAL_INTERVAL);
    let mut port_scan_eval_tick = tokio::time::interval(PORTSCAN_EVAL_INTERVAL);

    let mut current_counters: Option<TrafficCountersSnapshot> = None;
    let mut prev_mix_counters: Option<TrafficCountersSnapshot> = None;
    let (detectors, resolved_config) = config::resolve_all(config_path.as_deref())?;
    let mut anomaly_runner = AnomalyRunner::new(
        detectors.baseline,
        detectors.emergency,
        AlertLifecycleManager::new(detectors.alert_rules),
    );
    let mut synflood_runner = SynFloodRunner::new(
        detectors.synflood_detector,
        detectors.synflood_alert_lifecycle_manager,
    );
    let mut port_scan_runner = PortScanRunner::new(
        detectors.port_scan_detector,
        detectors.port_scan_alert_lifecycle_manager,
    );

    // Must read out of `resolved_config` before it's moved by value into
    // `spawn_api_server` below.
    let (am_sink, am_task) = match alertmanager::maybe_spawn(&resolved_config.alertmanager) {
        Some((sink, task)) => (Some(sink), Some(task)),
        None => (None, None),
    };
    let am_generator_url = resolved_config.alertmanager.generator_url.clone();

    let (api_ctx, mut api_task) = spawn_api_server(api_port, resolved_config, shutdown.clone());
    let mut api_task_done = false;

    loop {
        tokio::select! {
            _ = stats_poll_tick.tick() => {
                let Some(curr) = read_or_skip(read_snapshot(&proto_stats), "eBPF stats snapshot") else {
                    continue;
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
                let Some(prev) = pipeline::prime_or_diff(&mut prev_mix_counters, &current_counters) else {
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
            }
            _ = anomaly_eval_tick.tick() => {
                let alerts = anomaly_runner.tick(&current_counters, &metrics_handle);
                alertmanager::dispatch_tick_alerts(
                    am_sink.as_ref(),
                    am_generator_url.as_deref(),
                    alerts.transitions.iter().map(|e| (&e.alert, e.lifecycle)),
                    alerts.heartbeats.iter(),
                    alertmanager::alert_to_wire,
                );
                let mut state = api_ctx.dynamic.write().await;
                state.warmed_up = anomaly_runner.warmed_up();
                state.runner_snapshot = Some(anomaly_runner.snapshot(std::time::Instant::now()));
            }
            _ = synflood_eval_tick.tick() => {
                let Some(curr) = read_or_skip(read_syn_snapshot(&syn_tracker), "SYN_TRACKER snapshot") else {
                    continue;
                };
                let alerts = synflood_runner.tick(&Some(curr), &metrics_handle);
                alertmanager::dispatch_tick_alerts(
                    am_sink.as_ref(),
                    am_generator_url.as_deref(),
                    alerts.transitions.iter().map(|e| (&e.alert, e.lifecycle)),
                    alerts.heartbeats.iter(),
                    alertmanager::synflood_alert_to_wire,
                );
                let mut state = api_ctx.dynamic.write().await;
                state.synflood_snapshot = Some(synflood_runner.snapshot());
            }
            _ = port_scan_eval_tick.tick() => {
                let Some(curr) = read_or_skip(read_port_scan_snapshot(&port_scan_tracker), "PORT_SCAN_TRACKER snapshot") else {
                    continue;
                };
                let alerts = port_scan_runner.tick(&Some(curr), &metrics_handle);
                alertmanager::dispatch_tick_alerts(
                    am_sink.as_ref(),
                    am_generator_url.as_deref(),
                    alerts.transitions.iter().map(|e| (&e.alert, e.lifecycle)),
                    alerts.heartbeats.iter(),
                    alertmanager::port_scan_alert_to_wire,
                );
                let mut state = api_ctx.dynamic.write().await;
                state.port_scan_snapshot = Some(port_scan_runner.snapshot());
            }
            res = &mut api_task, if !api_task_done => {
                api_task_done = true;
                log_api_exit(res, "");
            }
            _ = signal::ctrl_c() => {
                tracing::info!("Shutdown signal received, draining background tasks...");
                shutdown.cancel();
                break;
            }
        }
    }

    drop(am_sink);

    // Run concurrently: a hung task can't extend total shutdown wait past
    // SHUTDOWN_GRACE_PERIOD.
    let api_drain = async move {
        if api_task_done {
            return;
        }
        let Ok(res) = tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, api_task).await else {
            tracing::warn!("API server did not shut down within grace period");
            return;
        };
        log_api_exit(res, " during shutdown");
    };
    let logger_drain = async move {
        let Some(logger_task) = logger_task else {
            return;
        };
        if tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, logger_task)
            .await
            .is_err()
        {
            tracing::warn!("eBPF logger task did not shut down within grace period");
        }
    };
    let am_drain = async move {
        let Some(am_task) = am_task else {
            return;
        };
        if tokio::time::timeout(SHUTDOWN_GRACE_PERIOD, am_task)
            .await
            .is_err()
        {
            tracing::warn!("Alertmanager dispatcher did not shut down within grace period");
        }
    };
    tokio::join!(api_drain, logger_drain, am_drain);

    Ok(())
}
