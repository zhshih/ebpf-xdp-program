use crate::{
    anomaly::{AnalyzeResult, AnomalyDecision, AnomalyLevel, anomaly_level_from_z},
    baseline::{ProtoBaseline, ProtoEwmaBaselineEstimator},
    rate::ProtoRateSnapshot,
};

pub fn analyze_snapshot(
    snapshot: &ProtoRateSnapshot,
    baseline: &mut ProtoEwmaBaselineEstimator,
) -> AnalyzeResult {
    let mut decisions = Vec::new();

    for rate in &snapshot.rates {
        let (z_pps, z_bps) = match baseline.z_scores(rate.proto, rate.pps, rate.bps) {
            Some(z) => z,
            None => continue,
        };

        let pps_level = anomaly_level_from_z(z_pps);
        let bps_level = anomaly_level_from_z(z_bps);

        let anomaly_level = match (pps_level, bps_level) {
            (Some(AnomalyLevel::Severe), _) | (_, Some(AnomalyLevel::Severe)) => {
                AnomalyLevel::Severe
            }

            (Some(AnomalyLevel::Suspicious), _) | (_, Some(AnomalyLevel::Suspicious)) => {
                AnomalyLevel::Suspicious
            }

            _ => AnomalyLevel::Normal,
        };

        let base = match baseline.baseline(rate.proto) {
            Some(b) => b,
            None => continue,
        };

        let decision = AnomalyDecision {
            proto: rate.proto,
            observed_pps: rate.pps,
            observed_bps: rate.bps,
            baseline: ProtoBaseline {
                pps: base.pps,
                bps: base.bps,
            },
            z_pps,
            z_bps,
            anomaly_level,
        };

        decisions.push(decision);
    }

    if !baseline.is_ready() {
        AnalyzeResult::WarmingUp
    } else {
        AnalyzeResult::Normal(decisions)
    }
}
