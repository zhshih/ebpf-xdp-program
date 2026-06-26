#!/usr/bin/env bash
# Cargo invokes this as: cargo-runner.sh <executable> [args...]
#
# Only the real ebpf-xdp-program binary needs root, to attach the XDP
# program. Everything else Cargo might run this way (unit/integration test
# binaries under target/<profile>/deps/..., doctests under a /tmp/rustdoctest*
# directory, future benches/examples) runs as the invoking user.
set -euo pipefail

bin="$1"
shift

if [[ "$(basename "$bin")" == "ebpf-xdp-program" ]]; then
  exec sudo -E "$bin" "$@"
else
  exec "$bin" "$@"
fi
