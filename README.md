# ebpf-xdp-program

[![CI](https://github.com/zhshih/ebpf-xdp-program/actions/workflows/ci.yml/badge.svg)](https://github.com/zhshih/ebpf-xdp-program/actions/workflows/ci.yml)
[![License: MIT / Apache-2.0](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](LICENSE-MIT)

A Rust eBPF/XDP network traffic anomaly detector. It attaches to a network interface at the kernel level, tracks per-protocol packet and byte rates, and uses statistical analysis (EWMA baseline + Z-score) to detect traffic spikes and anomalies in real time.

## Features

- **Kernel-space packet counting** via XDP — zero-copy, pre-routing interception
- **Per-protocol tracking**: ICMP, TCP, UDP, IPv6, and Other
- **EWMA-based adaptive baseline** with Huber-clipped robust statistics (ready after ≥5 samples and ≥120s)
- **Z-score anomaly classification**: Normal (< 3σ), Suspicious (3–6σ), Severe (≥ 6σ)
- **FSM-based alert engine** with configurable rules, cooldowns, and baseline freezing
- **SYN-flood detection**: per-source-IP SYN rate against a configurable threshold, tracked in a bounded kernel-side LRU map
- **Port-scan detection**: per-source-IP distinct destination ports touched within a sliding window
- **Read-only REST API** for health, resolved config, and live anomaly/offender state
- **Optional Alertmanager integration**: pushes fired/resolved/heartbeat alerts to a Prometheus Alertmanager instance
- **Prometheus metrics** exported on a configurable port
- **TOML configuration** for thresholds, alert rules, and timing

## Prerequisites

1. Linux kernel **≥ 4.8** (XDP support). Native-mode XDP requires ≥ 5.x and a supported NIC driver; SKB mode works on any kernel ≥ 4.8.
2. Stable + nightly Rust toolchains:
   ```shell
   rustup toolchain install stable
   rustup toolchain install nightly --component rust-src
   ```
3. bpf-linker: `cargo install bpf-linker`
4. Root privileges at runtime (configured automatically via `.cargo/config.toml`)

## Build & Run

```shell
cargo build --release

# Attach to a network interface (default: wlo1)
cargo run --release -- --iface eth0

# With custom metrics port and config file
cargo run --release -- --iface eth0 --metrics-port 9091 --config config.example.toml
```

Copy `config.example.toml` to get started with custom thresholds and alert rules.

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --iface` | `$XDP_IFACE` (required) | Network interface to attach XDP program to (run `ip link` to list yours) |
| `--metrics-port` | `9091` | Port for Prometheus metrics HTTP endpoint |
| `--api-port` | `8080` | Port for the read-only JSON API (see [REST API](#rest-api)) |
| `--config` | _(built-in defaults)_ | Path to TOML configuration file |

## How It Works

Three independent detection pipelines, each reading its own kernel-side BPF map, feed a shared FSM alert engine (`Inactive → Pending → Firing`):

- **Per-protocol** (`PROTO_STATS`): 1s aggregation → 30s EWMA baseline → Z-score classification
- **SYN-flood** (`SYN_TRACKER`): every 5s, ranks source IPs by SYN pps against a fixed threshold
- **Port-scan** (`PORT_SCAN_TRACKER`): every 5s, ranks source IPs by distinct destination ports touched against a fixed threshold

```
detection pipeline → FSM alert engine → Prometheus metrics / tracing logs
                                       → Alertmanager (optional, see below)
```

Two alert rules govern the per-protocol pipeline by default:
- **Spike**: Suspicious level (≥ 3σ), 5 consecutive detections required, 120s cooldown, freezes baseline while firing
- **Emergency**: Severe level (≥ 6σ), fires immediately, 60s cooldown

SYN-flood and port-scan detection each use a single absolute-threshold rule (configurable via `[syn_flood]`/`[port_scan]` in the TOML config — see `config.example.toml`) rather than baseline/Z-score classification, since they track per-source-IP behavior rather than aggregate traffic mix.

## REST API

A read-only JSON API is served on `--api-port` (default `8080`):

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness, plus whether the baseline has warmed up and stats are still fresh |
| `GET /config` | The fully-resolved configuration (compiled-in defaults + any TOML overrides) |
| `GET /anomalies` | Per-protocol baseline, rate, and alert FSM state |
| `GET /synflood` | Current top SYN-flood offender IPs and their alert FSM state |
| `GET /portscan` | Current top port-scan offender IPs and their alert FSM state |

## Alertmanager Integration

Fired, resolved, and periodic heartbeat alerts (for every still-`Firing` alert, so long-running alerts aren't auto-expired by Alertmanager between transitions) can be pushed to a [Prometheus Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/) instance's `POST /api/v2/alerts` endpoint. Disabled by default — enable via a `[alertmanager]` section in your TOML config:

```toml
[alertmanager]
enabled = true
url = "http://localhost:9093/api/v2/alerts"
timeout_secs = 5              # optional, HTTP request timeout
generator_url = "http://localhost:8080/anomalies"  # optional, included on every pushed alert
```

Set Alertmanager's own `resolve_timeout` comfortably longer than this program's heartbeat interval (worst case 30s, the per-protocol anomaly-evaluation cadence) so a long-`Firing` alert isn't auto-resolved by Alertmanager between heartbeats.

## Sample Output

```
2025-05-01T12:00:00Z INFO  ebpf_xdp_program: Prometheus metrics listening port=9091
2025-05-01T12:00:30Z INFO  ebpf_xdp_program::pipeline: baseline warming up proto=TCP samples=1/5
2025-05-01T12:02:30Z INFO  ebpf_xdp_program::pipeline: baseline ready proto=TCP mean_pps=142.3 stddev_pps=8.1
2025-05-01T12:05:00Z WARN  ebpf_xdp_program::alert: alert fired rule=Spike proto=TCP level=Suspicious pps=427.0 z_score=35.1
2025-05-01T12:07:02Z INFO  ebpf_xdp_program::alert: alert resolved rule=Spike proto=TCP
```

Metrics are exported at `http://localhost:9091/metrics` in Prometheus format.

## Troubleshooting

**`failed to attach the XDP program with default flags`**  
Not all NIC drivers support native XDP. Try SKB mode by changing `XdpFlags::default()` to `XdpFlags::SKB_MODE` in `main.rs`, or use a virtual interface (`lo`, `veth`).

**`Operation not permitted` on startup**  
The program requires root to load eBPF programs. The `.cargo/config.toml` runner is set to `sudo -E`, so `cargo run` will prompt for your password.

**`PROTO_STATS map not found` or eBPF verifier error**  
Rebuild the eBPF program (`cargo build`) to ensure the embedded object is up to date. Verifier errors often indicate a kernel too old for the BPF helpers used.

**Metrics endpoint not reachable**  
Check that port 9091 (or your `--metrics-port`) is not already in use. The Prometheus endpoint starts before XDP attachment, so metrics are available even if attachment fails.

## Cross-compiling on macOS

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package ebpf-xdp-program --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled binary can be copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, ebpf-xdp-program is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
