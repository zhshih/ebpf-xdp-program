use crate::stats::{
    anomaly::classifier::{AnalyzeResult, AnomalyDecision, AnomalyLevel, classify},
    baseline::proto::ProtoEwmaBaseline,
    rate::model::ProtoRateSnapshot,
};

pub fn analyze_snapshot(
    snapshot: &ProtoRateSnapshot,
    baseline: &mut ProtoEwmaBaseline,
) -> AnalyzeResult {
    let mut decisions = Vec::new();

    for rate in &snapshot.rates {
        let (z_pps, z_bps) = match baseline.z_scores(rate.proto, rate.pps, rate.bps) {
            Some(z) => z,
            None => continue,
        };

        let pps_level = classify(z_pps);
        let bps_level = classify(z_bps);

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
            pps: rate.pps,
            bps: rate.bps,
            pps_baseline: base.pps,
            bps_baseline: base.bps,
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
