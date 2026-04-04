# ebpf-xdp-program

A Rust eBPF/XDP network traffic anomaly detector. It attaches to a network interface at the kernel level, tracks per-protocol packet and byte rates, and uses statistical analysis (EWMA baseline + Z-score) to detect traffic spikes and anomalies in real time.

## Features

- **Kernel-space packet counting** via XDP — zero-copy, pre-routing interception
- **Per-protocol tracking**: ICMP, TCP, UDP, IPv6, and Other
- **EWMA-based adaptive baseline** with Huber-clipped robust statistics (ready after ≥5 samples and ≥120s)
- **Z-score anomaly classification**: Normal (< 3σ), Suspicious (3–6σ), Severe (≥ 6σ)
- **FSM-based alert engine** with configurable rules, cooldowns, and baseline freezing
- **Prometheus metrics** exported on a configurable port
- **TOML configuration** for thresholds, alert rules, and timing

## Prerequisites

1. Stable + nightly Rust toolchains:
   ```shell
   rustup toolchain install stable
   rustup toolchain install nightly --component rust-src
   ```
2. bpf-linker: `cargo install bpf-linker`
3. Root privileges at runtime (configured automatically via `.cargo/config.toml`)

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
| `-i, --iface` | `wlo1` | Network interface to attach XDP program to |
| `--metrics-port` | `9091` | Port for Prometheus metrics HTTP endpoint |
| `--config` | _(built-in defaults)_ | Path to TOML configuration file |

## How It Works

```
XDP hook (kernel) → per-CPU BPF map → user-space aggregation (1s)
  → EWMA baseline (30s)
  → Z-score classification
  → FSM alert engine (Inactive → Pending → Firing)
  → Prometheus metrics / tracing logs
```

Two alert rules are configured by default:
- **Spike**: Suspicious level (≥ 3σ), 5 consecutive detections required, 120s cooldown, freezes baseline while firing
- **Emergency**: Severe level (≥ 6σ), fires immediately, 60s cooldown

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
