#!/usr/bin/env bash
# Copy the workspace-built daemon binary to ui/binaries/ with the correct
# target-triple suffix required by Tauri's externalBin feature.
#
# Usage:
#   ./ui/scripts/copy-sidecar.sh                              # auto-detect host triple, release
#   ./ui/scripts/copy-sidecar.sh aarch64-unknown-linux-gnu     # explicit triple, release
#   ./ui/scripts/copy-sidecar.sh x86_64-pc-windows-msvc debug  # explicit triple + profile
set -euo pipefail

TRIPLE="${1:-$(rustc -vV | grep '^host:' | cut -d' ' -f2)}"
PROFILE="${2:-release}"
EXT=""
[[ "$TRIPLE" == *windows* ]] && EXT=".exe"

SRC="target/${PROFILE}/tor-vpn${EXT}"
# Cross-compiled binaries live under target/<triple>/<profile>/
if [[ ! -f "$SRC" ]]; then
    SRC="target/${TRIPLE}/${PROFILE}/tor-vpn${EXT}"
fi

DST="ui/binaries/tor-vpn-${TRIPLE}${EXT}"

if [[ ! -f "$SRC" ]]; then
    echo "Error: daemon binary not found at target/${PROFILE}/tor-vpn${EXT} or target/${TRIPLE}/${PROFILE}/tor-vpn${EXT}" >&2
    echo "Build it first: cargo build --release -p tor-vpn" >&2
    exit 1
fi

mkdir -p ui/binaries
cp "$SRC" "$DST"
echo "Copied $SRC -> $DST"
echo ""
echo "Now build the app with the bundled sidecar:"
echo "  cd ui && cargo tauri build --config '{\"bundle\":{\"externalBin\":[\"binaries/tor-vpn\"]}}'"
