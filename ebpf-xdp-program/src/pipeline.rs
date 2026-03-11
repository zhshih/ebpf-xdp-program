//! Anomaly detection pipeline orchestration.
//!
//! [`AnomalyRunner`] is the top-level coordinator. On each call to [`AnomalyRunner::tick`]
//! it computes per-protocol rates from raw counter deltas, runs both detectors
//! (EWMA Z-score and emergency thresholds), advances alert FSMs, updates the
//! EWMA baseline (skipping protocols currently frozen by a hot alert), and
//! emits Prometheus metrics.
mod runner;

pub use runner::AnomalyRunner;
