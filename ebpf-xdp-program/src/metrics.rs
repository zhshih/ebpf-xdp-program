use std::{collections::HashSet, net::SocketAddr};

use anyhow::Context as _;
use ebpf_xdp_program_common::ProtoIndex;
use metrics::{Unit, describe_counter, describe_gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

use crate::{
    alert::{AlertKind, AlertLifecycle, AlertMetricsSnapshot},
    anomaly::{AnomalyLevel, compute_anomaly_view},
    baseline::{BaselineState, EwmaEstimator},
    rate::{ProtoRate, SynIpRate},
};

/// Zero-size handle. All metric state lives in the global `metrics` registry.
pub struct MetricsHandle;

pub fn init(port: u16) -> anyhow::Result<MetricsHandle> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .with_context(|| format!("failed to bind Prometheus metrics listener on port {port}"))?;

    register_descriptions();
    Ok(MetricsHandle)
}

fn register_descriptions() {
    describe_gauge!(
        "xdp_traffic_pps",
        Unit::CountPerSecond,
        "Packets per second per protocol"
    );
    describe_gauge!(
        "xdp_traffic_bps",
        Unit::Bytes,
        "Bytes per second per protocol"
    );
    describe_gauge!(
        "xdp_traffic_mix_pct",
        Unit::Percent,
        "% of total packets per protocol (5s window)"
    );
    describe_gauge!(
        "xdp_baseline_pps_mean",
        Unit::CountPerSecond,
        "EWMA baseline PPS mean"
    );
    describe_gauge!(
        "xdp_baseline_pps_stddev",
        Unit::CountPerSecond,
        "EWMA baseline PPS stddev"
    );
    describe_gauge!(
        "xdp_baseline_bps_mean",
        Unit::Bytes,
        "EWMA baseline BPS mean"
    );
    describe_gauge!(
        "xdp_baseline_bps_stddev",
        Unit::Bytes,
        "EWMA baseline BPS stddev"
    );
    describe_gauge!(
        "xdp_baseline_ready",
        Unit::Count,
        "1 if baseline ready, 0 if warming"
    );
    describe_gauge!(
        "xdp_anomaly_z_score_pps",
        Unit::Count,
        "Z-score for PPS (0 if warming)"
    );
    describe_gauge!(
        "xdp_anomaly_z_score_bps",
        Unit::Count,
        "Z-score for BPS (0 if warming)"
    );
    describe_gauge!(
        "xdp_anomaly_level",
        Unit::Count,
        "0=Normal 1=Suspicious 2=Severe"
    );
    describe_gauge!(
        "xdp_anomaly_confidence",
        Unit::Count,
        "Anomaly confidence 0.0-1.0"
    );
    describe_gauge!(
        "xdp_alert_phase",
        Unit::Count,
        "0=Inactive 1=Pending 2=Firing per proto+kind"
    );
    describe_gauge!(
        "xdp_alert_consecutive_count",
        Unit::Count,
        "Consecutive anomalous samples per proto+kind"
    );
    describe_gauge!(
        "xdp_alert_baseline_frozen",
        Unit::Count,
        "1 if EWMA baseline updates are frozen per protocol"
    );
    describe_counter!(
        "xdp_alert_events_total",
        Unit::Count,
        "Alert lifecycle events (fired|resolved)"
    );
    // Deliberately no per-source-IP label on any SYN-flood metric below:
    // putting attacker-controlled IPs into a Prometheus label value is a
    // cardinality-explosion vector (rotate source IPs -> blow up the
    // registry). Per-IP detail is only ever exposed via the bounded
    // `/synflood` JSON endpoint.
    describe_gauge!(
        "xdp_synflood_top_offender_pps",
        Unit::CountPerSecond,
        "SYN pps of the single hottest source IP this tick; see /synflood for the bounded top-N breakdown"
    );
    describe_gauge!(
        "xdp_synflood_active_alerts",
        Unit::Count,
        "Number of source IPs currently in a Pending/Firing SYN-flood alert state"
    );
    describe_counter!(
        "xdp_synflood_alert_events_total",
        Unit::Count,
        "SYN-flood alert lifecycle events (fired|resolved), aggregate only"
    );
}

impl MetricsHandle {
    /// Called at the 5s tick with the computed per-protocol packet percentages.
    pub fn update_mix(&self, mix_pcts: &[(ProtoIndex, f64)]) {
        for (proto, pct) in mix_pcts {
            metrics::gauge!("xdp_traffic_mix_pct", "proto" => proto.label()).set(*pct);
        }
    }

    /// Called at the 30s tick with current rate snapshot.
    pub fn update_rates(&self, rates: &[ProtoRate]) {
        for r in rates {
            metrics::gauge!("xdp_traffic_pps", "proto" => r.proto.label()).set(r.pps);
            metrics::gauge!("xdp_traffic_bps", "proto" => r.proto.label()).set(r.bps);
        }
    }

    /// Called at the 30s tick to expose baseline mean/stddev per protocol.
    pub fn update_baseline(&self, estimator: &EwmaEstimator) {
        for idx in 0..ProtoIndex::COUNT {
            let proto =
                ProtoIndex::from_index(idx as usize).expect("idx in range 0..ProtoIndex::COUNT");
            let label = proto.label();
            match estimator.snapshot(proto) {
                BaselineState::Ready { baseline } => {
                    metrics::gauge!("xdp_baseline_ready",      "proto" => label).set(1.0);
                    metrics::gauge!("xdp_baseline_pps_mean",   "proto" => label)
                        .set(baseline.pps.mean);
                    metrics::gauge!("xdp_baseline_pps_stddev", "proto" => label)
                        .set(baseline.pps.stddev);
                    metrics::gauge!("xdp_baseline_bps_mean",   "proto" => label)
                        .set(baseline.bps.mean);
                    metrics::gauge!("xdp_baseline_bps_stddev", "proto" => label)
                        .set(baseline.bps.stddev);
                }
                BaselineState::Warming => {
                    metrics::gauge!("xdp_baseline_ready", "proto" => label).set(0.0);
                }
            }
        }
    }

    /// Called at the 30s tick with current rates and EWMA estimator.
    /// Recomputes z-scores from the baseline and emits anomaly metrics.
    pub fn update_anomaly(&self, rates: &[ProtoRate], estimator: &EwmaEstimator) {
        for r in rates {
            let label = r.proto.label();
            let view = compute_anomaly_view(&estimator.snapshot(r.proto), r.pps, r.bps);
            let level_val = match view.level {
                AnomalyLevel::Normal => 0.0,
                AnomalyLevel::Suspicious => 1.0,
                AnomalyLevel::Severe => 2.0,
            };
            metrics::gauge!("xdp_anomaly_z_score_pps", "proto" => label).set(view.z_pps);
            metrics::gauge!("xdp_anomaly_z_score_bps", "proto" => label).set(view.z_bps);
            metrics::gauge!("xdp_anomaly_level",       "proto" => label).set(level_val);
            metrics::gauge!("xdp_anomaly_confidence",  "proto" => label).set(view.confidence);
        }
    }

    /// Called at the 30s tick with alert FSM state snapshots.
    pub fn update_alerts(
        &self,
        snaps: &[AlertMetricsSnapshot],
        frozen_protos: &HashSet<ProtoIndex>,
    ) {
        for idx in 0..ProtoIndex::COUNT {
            let proto =
                ProtoIndex::from_index(idx as usize).expect("idx in range 0..ProtoIndex::COUNT");
            metrics::gauge!("xdp_alert_baseline_frozen", "proto" => proto.label()).set(
                if frozen_protos.contains(&proto) {
                    1.0
                } else {
                    0.0
                },
            );
        }
        for snap in snaps {
            let proto = snap.proto.label();
            let kind = snap.kind.label();
            metrics::gauge!("xdp_alert_phase",
                "proto" => proto, "kind" => kind)
            .set(snap.phase_value as f64);
            metrics::gauge!("xdp_alert_consecutive_count",
                "proto" => proto, "kind" => kind)
            .set(snap.consecutive_count as f64);
        }
    }

    /// Called once per AlertEvent emitted by the pipeline runner.
    pub fn record_alert_event(
        &self,
        proto: ProtoIndex,
        kind: AlertKind,
        lifecycle: AlertLifecycle,
    ) {
        metrics::counter!("xdp_alert_events_total",
            "proto" => proto.label(),
            "kind"  => kind.label(),
            "lifecycle" => lifecycle.label())
        .increment(1);
    }

    /// Called at the SYN-flood eval tick with the current top-N offenders
    /// and count of active alert-manager entries. Aggregate only — no
    /// per-IP label (see the cardinality note on metric registration above).
    pub fn update_synflood(&self, top_n: &[SynIpRate], active_alerts: usize) {
        let top_pps = top_n.first().map_or(0.0, |r| r.pps);
        metrics::gauge!("xdp_synflood_top_offender_pps").set(top_pps);
        metrics::gauge!("xdp_synflood_active_alerts").set(active_alerts as f64);
    }

    /// Called once per SYN-flood `AlertLifecycle` event. Aggregate only.
    pub fn record_synflood_event(&self, lifecycle: AlertLifecycle) {
        metrics::counter!("xdp_synflood_alert_events_total", "lifecycle" => lifecycle.label())
            .increment(1);
    }
}
