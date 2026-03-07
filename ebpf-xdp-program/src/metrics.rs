use crate::{
    alert::{AlertKind, AlertLifecycle, AlertMetricsSnapshot},
    anomaly::compute_proto_z_scores,
    baseline::{BaselineState, EwmaEstimator},
    rate::ProtoRate,
};
use ebpf_xdp_program_common::ProtoIndex;
use std::collections::HashSet;
use anyhow::Context as _;
use metrics::{describe_counter, describe_gauge, Unit};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

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
    describe_gauge!("xdp_traffic_pps", Unit::CountPerSecond, "Packets per second per protocol");
    describe_gauge!("xdp_traffic_bps", Unit::Bytes, "Bytes per second per protocol");
    describe_gauge!("xdp_traffic_mix_pct", Unit::Percent, "% of total packets per protocol (5s window)");
    describe_gauge!("xdp_baseline_pps_mean", Unit::CountPerSecond, "EWMA baseline PPS mean");
    describe_gauge!("xdp_baseline_pps_stddev", Unit::CountPerSecond, "EWMA baseline PPS stddev");
    describe_gauge!("xdp_baseline_bps_mean", Unit::Bytes, "EWMA baseline BPS mean");
    describe_gauge!("xdp_baseline_bps_stddev", Unit::Bytes, "EWMA baseline BPS stddev");
    describe_gauge!("xdp_baseline_ready", Unit::Count, "1 if baseline ready, 0 if warming");
    describe_gauge!("xdp_anomaly_z_score_pps", Unit::Count, "Z-score for PPS (0 if warming)");
    describe_gauge!("xdp_anomaly_z_score_bps", Unit::Count, "Z-score for BPS (0 if warming)");
    describe_gauge!("xdp_anomaly_level", Unit::Count, "0=Normal 1=Suspicious 2=Severe");
    describe_gauge!("xdp_anomaly_confidence", Unit::Count, "Anomaly confidence 0.0-1.0");
    describe_gauge!("xdp_alert_phase", Unit::Count, "0=Inactive 1=Pending 2=Firing per proto+kind");
    describe_gauge!("xdp_alert_consecutive_count", Unit::Count, "Consecutive anomalous samples per proto+kind");
    describe_gauge!("xdp_alert_baseline_frozen", Unit::Count, "1 if EWMA baseline updates are frozen per protocol");
    describe_counter!("xdp_alert_events_total", Unit::Count, "Alert lifecycle events (fired|resolved)");
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
            let proto = ProtoIndex::from_index(idx as usize).unwrap();
            let label = proto.label();
            match estimator.snapshot(proto) {
                BaselineState::Ready { baseline } => {
                    metrics::gauge!("xdp_baseline_ready",      "proto" => label).set(1.0);
                    metrics::gauge!("xdp_baseline_pps_mean",   "proto" => label).set(baseline.pps.mean);
                    metrics::gauge!("xdp_baseline_pps_stddev", "proto" => label).set(baseline.pps.stddev);
                    metrics::gauge!("xdp_baseline_bps_mean",   "proto" => label).set(baseline.bps.mean);
                    metrics::gauge!("xdp_baseline_bps_stddev", "proto" => label).set(baseline.bps.stddev);
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
            let (z_pps, z_bps, level_val, confidence) = match estimator.snapshot(r.proto) {
                BaselineState::Ready { baseline } => {
                    let (z_pps, z_bps) = compute_proto_z_scores(&baseline, r.pps, r.bps);
                    let abs_z = z_pps.abs().max(z_bps.abs());
                    let level_val = if abs_z >= 6.0 { 2.0 } else if abs_z >= 3.0 { 1.0 } else { 0.0 };
                    (z_pps, z_bps, level_val, (abs_z / 10.0).min(1.0))
                }
                BaselineState::Warming => (0.0, 0.0, 0.0, 0.0),
            };
            metrics::gauge!("xdp_anomaly_z_score_pps", "proto" => label).set(z_pps);
            metrics::gauge!("xdp_anomaly_z_score_bps", "proto" => label).set(z_bps);
            metrics::gauge!("xdp_anomaly_level",       "proto" => label).set(level_val);
            metrics::gauge!("xdp_anomaly_confidence",  "proto" => label).set(confidence);
        }
    }

    /// Called at the 30s tick with alert FSM state snapshots.
    pub fn update_alerts(&self, snaps: &[AlertMetricsSnapshot], frozen_protos: &HashSet<ProtoIndex>) {
        for idx in 0..ProtoIndex::COUNT {
            let proto = ProtoIndex::from_index(idx as usize).unwrap();
            metrics::gauge!("xdp_alert_baseline_frozen", "proto" => proto.label())
                .set(if frozen_protos.contains(&proto) { 1.0 } else { 0.0 });
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
        let lc_label = match lifecycle {
            AlertLifecycle::Fired => "fired",
            AlertLifecycle::Resolved => "resolved",
        };
        metrics::counter!("xdp_alert_events_total",
            "proto" => proto.label(),
            "kind"  => kind.label(),
            "lifecycle" => lc_label)
            .increment(1);
    }
}
