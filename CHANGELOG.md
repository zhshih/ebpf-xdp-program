# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-05-10

### Added

- XDP kernel program that tracks per-protocol (ICMP, TCP, UDP, IPv6, Other) packet and byte counters via a `PerCpuArray` BPF map
- EWMA-based baseline estimator with Huber-clipped robust standard deviation; becomes ready after ≥5 samples, stddev > 1e-3, and ≥120 s elapsed
- Z-score anomaly classifier with three severity levels: Normal (< 3σ), Suspicious (3–6σ), Severe (≥ 6σ)
- Emergency threshold detector for absolute rate spikes independent of baseline
- FSM-based alert engine (`Inactive → Pending → Firing`) with configurable consecutive-hit thresholds, cooldowns, and baseline freezing
- Prometheus metrics endpoint (default port 9091)
- TOML configuration file support for all thresholds and alert rules (`config.example.toml` included)
- GitHub Actions CI pipeline: formatting, `cargo check`, Clippy, and unit tests
- 88 unit tests covering baseline estimation, anomaly detection, alert state machine, rate computation, and configuration parsing
