//! Anomaly detection — Z-score analysis and emergency threshold checks.
//!
//! Two independent detectors feed the rule-based pipeline, both returning
//! `Vec<AlertSignal>` (empty means "nothing to report" — an empty result
//! does not distinguish "not enough data yet" from "no anomaly found";
//! baseline readiness is a question callers ask directly, not something
//! smuggled through the return type — see `AnomalyRunner::tick`):
//! - [`EwmaDetector`]: computes per-protocol Z-scores against the EWMA
//!   baseline. Silently skips protocols whose baseline is still `Warming`.
//! - [`EmergencyDetector`]: fires immediately when an absolute rate threshold is
//!   exceeded, regardless of baseline state.
//!
//! File layout follows the model.rs/view.rs/logic rule documented in
//! `crate::alert`'s module doc (a type belongs in `model.rs` only if it's
//! the output of a component's *primary* method, consumed by a genuinely
//! different component; `view.rs` is for a *secondary* introspection
//! method's output; this module doesn't restate the rule, only its own
//! specifics):
//!
//! - `model.rs` holds [`AnomalyLevel`]: it's a field on `AlertSignal`
//!   (produced by both [`EwmaDetector`] and [`EmergencyDetector`], consumed
//!   by [`AlertManager`] in `crate::alert`), and `pipeline`/`api`/`metrics`
//!   independently read it as a rendered view — it doesn't belong to just
//!   one detector, so it doesn't stay colocated with one.
//! - The [`AnomalyDetector`] trait — the shared contract implemented by both
//!   `EwmaDetector` and `EmergencyDetector` — lives right here rather than
//!   in its own file: it isn't a value either one produces or consumes, and
//!   a dedicated file for one trait signature would be disproportionate —
//!   the same reasoning that keeps `ratio_confidence` here instead of its
//!   own file.
//! - `emergency_detector.rs` keeps [`EmergencyThreshold`] colocated with
//!   [`EmergencyDetector`]: it's constructor config fed into `new()`, never
//!   observed by anything else — the same category as `AlertRule` in
//!   `crate::alert::proto_manager`.
//!
//! [`SynFloodDetector`]/[`PortScanDetector`] are two further independent
//! detectors with no relationship to the two above: neither implements
//! `AnomalyDetector` (different input type, no baseline/warmup concept —
//! see each one's own doc comment), so each lives entirely in its own file
//! (`synflood_detector.rs`/`port_scan_detector.rs`).
//!
//! [`AnomalyView`]/[`compute_anomaly_view`] live in `view.rs` instead — see
//! that file's own doc comment for why. `ratio_confidence` is defined right
//! here rather than in any one detector's file, for the same reason
//! `crate::pipeline::prime_or_diff` is defined in `pipeline.rs`: it's shared
//! by `EmergencyDetector`/`SynFloodDetector`/`PortScanDetector` — a
//! different set than `model.rs`'s — and is small enough that a dedicated
//! file for one function would be disproportionate.
pub mod emergency_detector;
pub mod ewma_detector;
pub mod model;
pub mod port_scan_detector;
pub mod synflood_detector;
pub mod view;

pub use emergency_detector::{EmergencyDetector, EmergencyThreshold};
pub use ewma_detector::EwmaDetector;
pub use model::AnomalyLevel;
pub use port_scan_detector::PortScanDetector;
pub use synflood_detector::SynFloodDetector;
pub use view::{AnomalyView, compute_anomaly_view};

use crate::{alert::AlertSignal, rate::ProtoRate};

/// Abstraction over anomaly detection strategies.
///
/// Implementors examine a rate snapshot and return signals for any protocols
/// whose traffic deviates from the expected pattern. An empty vec means no
/// anomaly was found; it does not distinguish that from "not enough data
/// yet" — callers that care about baseline readiness ask the baseline
/// directly (see `AnomalyRunner::tick`) rather than inferring it here.
pub trait AnomalyDetector {
    fn detect(&self, rates: &[ProtoRate]) -> Vec<AlertSignal>;
}

/// Ratio-based confidence: `(observed / threshold - 1.0).clamp(0, 1)`, so
/// 2x the threshold yields confidence 1.0. Caller must ensure `threshold > 0`.
pub(crate) fn ratio_confidence(observed: f64, threshold: f64) -> f64 {
    (observed / threshold - 1.0).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_confidence_at_threshold_is_zero() {
        assert_eq!(ratio_confidence(100.0, 100.0), 0.0);
    }

    #[test]
    fn ratio_confidence_below_threshold_clamped_to_zero() {
        assert_eq!(ratio_confidence(50.0, 100.0), 0.0);
    }

    #[test]
    fn ratio_confidence_at_double_threshold_is_one() {
        assert_eq!(ratio_confidence(200.0, 100.0), 1.0);
    }

    #[test]
    fn ratio_confidence_above_double_threshold_clamped_to_one() {
        assert_eq!(ratio_confidence(1_000_000.0, 100.0), 1.0);
    }

    #[test]
    fn ratio_confidence_scales_linearly_between_bounds() {
        // 1.5x threshold -> ratio 1.5 -> (1.5 - 1.0).clamp(0,1) = 0.5
        assert!((ratio_confidence(150.0, 100.0) - 0.5).abs() < 1e-9);
    }
}
