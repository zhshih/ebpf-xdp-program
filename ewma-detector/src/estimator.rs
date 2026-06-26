use ebpf_xdp_program_common::ProtoIndex;

use crate::{ewma::Ewma, rate::ProtoRate};

const PROTO_COUNT: usize = ProtoIndex::COUNT as usize;

/// Mean and standard deviation for a single metric dimension (pps or bps).
#[derive(Debug, Clone)]
pub struct BaselineStats {
    pub mean: f64,
    pub stddev: f64,
}

/// EWMA-based baseline statistics for a single protocol, covering both
/// packet rate (pps) and bit rate (bps) dimensions independently.
#[derive(Debug, Clone)]
pub struct ProtoBaseline {
    pub pps: BaselineStats,
    pub bps: BaselineStats,
}

/// Whether a protocol's baseline is ready for anomaly detection.
///
/// `Warming` means not enough data has been collected yet; anomaly detection
/// is skipped for that protocol. `Ready` carries the current baseline estimates.
#[derive(Debug)]
pub enum BaselineState {
    Ready { baseline: ProtoBaseline },
    Warming,
}

/// Manages one [`Ewma`] per (protocol, dimension) pair and gatekeeps readiness.
///
/// A protocol transitions from `Warming` to `Ready` only when all three conditions hold:
/// - At least `min_samples` observations have been fed via [`update`](Self::update)
/// - Both pps and bps stddev exceed `min_stddev` (filters out flat/idle protocols)
/// - At least `min_elapsed_ticks` calls to [`advance`](Self::advance) have happened since construction
#[derive(Debug)]
pub struct EwmaEstimator {
    pps_ewma: [Ewma; PROTO_COUNT],
    bps_ewma: [Ewma; PROTO_COUNT],
    min_samples: u64,
    min_stddev: f64,
    min_elapsed_ticks: u64,
    elapsed_ticks: u64,
}

impl EwmaEstimator {
    /// Creates a new estimator tracking all five protocol buckets.
    ///
    /// - `alpha`: EWMA smoothing factor (0, 1]
    /// - `min_samples`: minimum observations before readiness
    /// - `min_stddev`: minimum standard deviation required (filters constant-rate protocols)
    /// - `min_elapsed_ticks`: minimum number of [`advance`](Self::advance) calls before readiness
    pub fn new(alpha: f64, min_samples: u64, min_stddev: f64, min_elapsed_ticks: u64) -> Self {
        Self {
            pps_ewma: [Ewma::new(alpha); PROTO_COUNT],
            bps_ewma: [Ewma::new(alpha); PROTO_COUNT],
            min_samples,
            min_stddev,
            min_elapsed_ticks,
            elapsed_ticks: 0,
        }
    }

    /// Advances the wall-clock gate by one tick.
    ///
    /// Call once per pipeline tick, independent of [`update`](Self::update), so the
    /// gate keeps advancing even when every protocol is momentarily frozen.
    pub fn advance(&mut self) {
        self.elapsed_ticks += 1;
    }

    /// Returns the current baseline state for `proto`.
    ///
    /// Returns `Warming` if any readiness condition is unmet; `Ready` otherwise.
    pub fn snapshot(&self, proto: ProtoIndex) -> BaselineState {
        let pps = &self.pps_ewma[proto as usize];
        let bps = &self.bps_ewma[proto as usize];

        let samples = pps.samples.min(bps.samples);

        let baseline = ProtoBaseline {
            pps: BaselineStats {
                mean: pps.mean(),
                stddev: pps.stddev(),
            },
            bps: BaselineStats {
                mean: bps.mean(),
                stddev: bps.stddev(),
            },
        };

        if samples < self.min_samples
            || baseline.pps.stddev < self.min_stddev
            || baseline.bps.stddev < self.min_stddev
            || self.elapsed_ticks < self.min_elapsed_ticks
        {
            return BaselineState::Warming;
        }

        BaselineState::Ready { baseline }
    }

    /// Feeds observed per-protocol rates into the EWMA estimators.
    ///
    /// Should be called once per anomaly evaluation tick. Protocols not present
    /// in `observed_rates` are silently skipped (their EWMAs are not updated).
    pub fn update(&mut self, observed_rates: &[ProtoRate]) {
        for rate in observed_rates {
            self.pps_ewma[rate.proto as usize].update(rate.pps);
            self.bps_ewma[rate.proto as usize].update(rate.bps);
        }
    }
}

/// Abstraction over baseline providers, enabling mock baselines in tests.
pub trait Baseline {
    fn snapshot(&self, proto: ProtoIndex) -> BaselineState;
}

impl Baseline for EwmaEstimator {
    fn snapshot(&self, proto: ProtoIndex) -> BaselineState {
        self.snapshot(proto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_estimator(min_samples: u64, min_stddev: f64) -> EwmaEstimator {
        // min_elapsed_ticks = 0 so the time gate never blocks tests
        EwmaEstimator::new(0.4, min_samples, min_stddev, 0)
    }

    fn make_rate(proto: ProtoIndex, pps: f64, bps: f64) -> ProtoRate {
        ProtoRate { proto, pps, bps }
    }

    #[test]
    fn estimator_warming_at_start() {
        let est = make_estimator(5, 1e-3);
        assert!(
            matches!(est.snapshot(ProtoIndex::Tcp), BaselineState::Warming),
            "should be Warming with zero samples"
        );
    }

    #[test]
    fn estimator_warming_below_min_samples() {
        let mut est = make_estimator(5, 1e-3);
        for i in 0..4 {
            est.update(&[make_rate(
                ProtoIndex::Tcp,
                i as f64 * 10.0,
                i as f64 * 1000.0,
            )]);
        }
        assert!(
            matches!(est.snapshot(ProtoIndex::Tcp), BaselineState::Warming),
            "should still be Warming with only 4 samples (need 5)"
        );
    }

    #[test]
    fn estimator_warming_low_stddev() {
        let mut est = make_estimator(3, 1.0); // min_stddev = 1.0 (high)
        // Constant traffic: EWMA mean converges to 100 and variance decays to near-zero.
        // After ~50 samples the EWMA stddev drops well below 1.0, keeping the baseline Warming.
        for _ in 0..50 {
            est.update(&[make_rate(ProtoIndex::Tcp, 100.0, 10000.0)]);
        }
        assert!(
            matches!(est.snapshot(ProtoIndex::Tcp), BaselineState::Warming),
            "constant-rate traffic should not reach Ready (stddev too low)"
        );
    }

    #[test]
    fn estimator_ready_after_sufficient_data() {
        let mut est = make_estimator(5, 1e-3);
        // Varying traffic builds up stddev
        for i in 0..20 {
            let v = if i % 2 == 0 { 10.0 } else { 200.0 };
            est.update(&[make_rate(ProtoIndex::Tcp, v, v * 100.0)]);
        }
        assert!(
            matches!(est.snapshot(ProtoIndex::Tcp), BaselineState::Ready { .. }),
            "should be Ready after 20 varying samples"
        );
    }

    #[test]
    fn estimator_update_feeds_both_dimensions() {
        let mut est = make_estimator(1, 0.0);
        est.update(&[make_rate(ProtoIndex::Udp, 50.0, 5000.0)]);
        let pps_samples = est.pps_ewma[ProtoIndex::Udp as usize].samples;
        let bps_samples = est.bps_ewma[ProtoIndex::Udp as usize].samples;
        assert_eq!(pps_samples, 1, "pps EWMA should have 1 sample");
        assert_eq!(bps_samples, 1, "bps EWMA should have 1 sample");
    }

    #[test]
    fn baseline_trait_dispatch() {
        // Call snapshot() via the Baseline trait object to exercise the trait impl.
        let est = make_estimator(5, 1e-3);
        let b: &dyn Baseline = &est;
        assert!(matches!(
            b.snapshot(ProtoIndex::Tcp),
            BaselineState::Warming
        ));
    }

    #[test]
    fn estimator_all_protocols_tracked() {
        let est = make_estimator(5, 1e-3);
        // All 5 protocols should be snapshotable without panic
        for i in 0..ProtoIndex::COUNT as usize {
            let proto = ProtoIndex::from_index(i).unwrap();
            let _ = est.snapshot(proto);
        }
    }

    #[test]
    fn advance_alone_satisfies_elapsed_gate() {
        // Time gate should be satisfiable purely via advance(), independent of update().
        let mut est = EwmaEstimator::new(0.4, 0, 0.0, 3);
        for _ in 0..3 {
            est.advance();
        }
        assert!(
            matches!(est.snapshot(ProtoIndex::Tcp), BaselineState::Ready { .. }),
            "elapsed_ticks should reach min_elapsed_ticks via advance() alone"
        );
    }
}
