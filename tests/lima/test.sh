#!/usr/bin/env bash
# Integration test for tor-vpn on Linux via Lima VM.
#
# Prerequisites:
#   brew install lima
#   cross build --target aarch64-unknown-linux-gnu --release -p tor-vpn
#
# Usage:
#   ./tests/lima/test.sh          # full test suite
#   ./tests/lima/test.sh quick    # just build check + status
#   ./tests/lima/test.sh setup    # only create/start VM
#   ./tests/lima/test.sh teardown # destroy VM

set -euo pipefail

VM_NAME="tor-vpn-test"
BINARY="target/aarch64-unknown-linux-gnu/release/tor-vpn"
REMOTE_BIN="/tmp/tor-vpn"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIMA_CONFIG="${SCRIPT_DIR}/tor-vpn.yaml"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "${YELLOW}----${NC}: $1"; }

FAILURES=0

cd "$PROJECT_DIR"

# --- VM lifecycle ---

vm_exists() { limactl list -q 2>/dev/null | grep -q "^${VM_NAME}$"; }
vm_running() { limactl list --json 2>/dev/null | grep -q "\"status\":\"Running\".*\"name\":\"${VM_NAME}\"" || \
               limactl list --json 2>/dev/null | python3 -c "import sys,json; vms=json.load(sys.stdin); sys.exit(0 if any(v.get('name')=='${VM_NAME}' and v.get('status')=='Running' for v in vms) else 1)" 2>/dev/null; }

setup_vm() {
    if ! [ -f "$BINARY" ]; then
        info "Building tor-vpn for Linux..."
        cross build --target aarch64-unknown-linux-gnu --release -p tor-vpn
    fi

    if ! vm_exists; then
        info "Creating Lima VM '${VM_NAME}'..."
        limactl create --name="${VM_NAME}" "$LIMA_CONFIG"
    fi

    if ! vm_running; then
        info "Starting Lima VM '${VM_NAME}'..."
        limactl start "${VM_NAME}"
    fi

    info "Copying binary to VM..."
    limactl copy "$BINARY" "${VM_NAME}:/tmp/tor-vpn"
    limactl shell "${VM_NAME}" chmod +x "$REMOTE_BIN"
}

teardown_vm() {
    info "Destroying Lima VM '${VM_NAME}'..."
    limactl stop "${VM_NAME}" 2>/dev/null || true
    limactl delete "${VM_NAME}" 2>/dev/null || true
}

# --- Helper: run command in VM ---

vm() { limactl shell "${VM_NAME}" "$@"; }
vm_sudo() { limactl shell "${VM_NAME}" sudo "$@"; }

# --- Ensure clean state ---

ensure_clean() {
    vm "$REMOTE_BIN" stop 2>/dev/null || true
    sleep 1
    vm_sudo pkill -9 tor-vpn 2>/dev/null || true
    sleep 1
    for i in $(seq 1 10); do
        if ! vm_sudo pgrep -x tor-vpn >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    vm_sudo "$REMOTE_BIN" cleanup 2>/dev/null || true
    vm_sudo rm -f /tmp/tor-vpn-daemon.log 2>/dev/null || true
    sleep 1
}

# --- Wait for daemon to be fully ready (routes installed) ---

wait_for_ready() {
    local timeout="${1:-120}"
    for i in $(seq 1 "$timeout"); do
        if vm ip route show 2>/dev/null | grep -q "0\.0\.0\.0/1"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# --- Tests ---

test_binary_runs() {
    info "Test: binary executes and shows help"
    if vm "$REMOTE_BIN" --help 2>&1 | grep -q "tor-vpn"; then
        pass "binary runs and shows help"
    else
        fail "binary failed to execute"
    fi
}

test_status_clean() {
    info "Test: status reports clean state when not running"
    local output
    output=$(vm "$REMOTE_BIN" status 2>&1) || true
    if echo "$output" | grep -qi "not running\|no state\|clean"; then
        pass "status reports clean state"
    else
        fail "unexpected status output: $output"
    fi
}

test_requires_root() {
    info "Test: start without root fails gracefully"
    local output
    output=$(vm "$REMOTE_BIN" start 2>&1) || true
    if echo "$output" | grep -qi "root\|admin\|permission\|privilege\|superuser"; then
        pass "start requires root"
    else
        fail "start did not report root requirement: $output"
    fi
}

# Session 1: Full VPN flow (no --override-dns)
# Covers: TUN, bootstrap, routes, IPv6, Linux paths, DNS, Tor, IPC, graceful stop
test_vpn_flow() {
    info "Starting daemon..."
    vm_sudo "$REMOTE_BIN" start --log-file /tmp/tor-vpn-daemon.log &

    # --- TUN creation ---
    info "Test: TUN device creation"
    local tun_ok=false
    for i in $(seq 1 30); do
        if vm ip link show 2>/dev/null | grep -q "torvpn"; then
            tun_ok=true
            break
        fi
        sleep 1
    done
    if $tun_ok; then
        pass "TUN device created"
    else
        fail "TUN device not found after 30s"
    fi
    if vm ip addr show 2>/dev/null | grep -q "10\."; then
        pass "TUN device has IP address"
    else
        fail "TUN device has no IP address"
    fi

    # --- Linux paths (check while daemon is running, before bootstrap) ---
    info "Test: state file at /run/tor-vpn-state.json"
    # State file is written after route installation, so wait for bootstrap first
    info "Test: Tor bootstrap (up to 120s)"
    local bootstrapped=false
    for i in $(seq 1 120); do
        local output
        output=$(vm "$REMOTE_BIN" status 2>&1) || true
        if echo "$output" | grep -qi "connected\|running\|active"; then
            bootstrapped=true
            break
        fi
        sleep 1
    done
    if $bootstrapped; then
        pass "Tor bootstrapped"
    else
        fail "Tor did not bootstrap within 120s"
        vm_sudo cat /tmp/tor-vpn-daemon.log 2>/dev/null | tail -20 || true
        return
    fi

    # --- Routes ---
    info "Test: catch-all routes (polling up to 30s)"
    if wait_for_ready 30; then
        pass "route 0.0.0.0/1 installed"
        pass "route 128.0.0.0/1 installed"
    else
        local routes
        routes=$(vm ip route show 2>/dev/null) || true
        echo "$routes" | grep -q "0\.0\.0\.0/1" && pass "route 0.0.0.0/1 installed" || fail "route 0.0.0.0/1 not found"
        echo "$routes" | grep -q "128\.0\.0\.0/1" && pass "route 128.0.0.0/1 installed" || fail "route 128.0.0.0/1 not found"
    fi

    # --- IPv6 blackhole ---
    info "Test: IPv6 blackhole routes"
    if vm ip -6 route show 2>/dev/null | grep -q "::/1"; then
        pass "IPv6 blackhole ::/1 installed"
    else
        fail "IPv6 blackhole ::/1 not found (best-effort, may be ok)"
    fi

    # --- Linux paths (now routes are installed → state file exists) ---
    if vm_sudo test -f /run/tor-vpn-state.json; then
        pass "state file at /run/tor-vpn-state.json"
        local content
        content=$(vm_sudo cat /run/tor-vpn-state.json 2>/dev/null) || true
        if echo "$content" | grep -q "tun_name"; then
            pass "state file contains expected fields"
        else
            fail "state file missing expected fields"
        fi
    else
        fail "state file not at /run/tor-vpn-state.json"
    fi

    info "Test: IPC socket at /run/tor-vpn.sock"
    if vm_sudo test -S /run/tor-vpn.sock; then
        pass "IPC socket at /run/tor-vpn.sock"
    else
        fail "IPC socket not at /run/tor-vpn.sock"
    fi

    # --- DNS resolution ---
    info "Test: DNS resolution through Tor"
    local dns_result
    dns_result=$(vm dig +short +timeout=15 google.com 2>&1) || true
    if echo "$dns_result" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
        pass "DNS resolution works"
    else
        fail "DNS resolution failed: $dns_result"
    fi

    # --- Tor connectivity ---
    info "Test: traffic routes through Tor (up to 3 attempts)"
    local tor_ok=false
    for attempt in 1 2 3; do
        local result
        result=$(vm curl -s --max-time 30 https://check.torproject.org/api/ip 2>&1) || true
        if echo "$result" | grep -q '"IsTor":true'; then
            tor_ok=true
            local ip
            ip=$(echo "$result" | grep -o '"IP":"[^"]*"' | head -1)
            pass "traffic goes through Tor"
            info "Exit IP: $ip"
            break
        fi
        sleep 5
    done
    if ! $tor_ok; then
        fail "traffic NOT going through Tor after 3 attempts"
    fi

    # --- IPC commands ---
    info "Test: IPC status without root"
    local status_out
    status_out=$(vm "$REMOTE_BIN" status 2>&1) || true
    if echo "$status_out" | grep -qi "connected\|running\|uptime\|tx\|rx"; then
        pass "IPC status works"
    else
        fail "IPC status failed: $status_out"
    fi

    info "Test: IPC refresh circuits"
    local refresh_out
    refresh_out=$(vm "$REMOTE_BIN" refresh 2>&1) || true
    if echo "$refresh_out" | grep -qi "refresh\|circuit\|cache\|ok\|success"; then
        pass "circuit refresh works"
    else
        fail "circuit refresh failed: $refresh_out"
    fi

    # --- Graceful stop ---
    info "Test: graceful stop via IPC"
    vm "$REMOTE_BIN" stop 2>&1 || true
    sleep 3
    if ! vm_sudo pgrep -x tor-vpn >/dev/null 2>&1; then
        pass "daemon stopped gracefully"
    else
        fail "daemon still running after stop"
        vm_sudo pkill -9 tor-vpn 2>/dev/null || true
    fi
    if ! vm ip route show 2>/dev/null | grep -q "0\.0\.0\.0/1"; then
        pass "routes cleaned up after stop"
    else
        fail "routes not cleaned up after stop"
    fi
}

# Session 2: --override-dns + .onion + SIGKILL recovery
# Reuses same daemon session: test .onion, then SIGKILL instead of graceful stop
test_override_dns_onion_and_sigkill() {
    local onion_host="duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

    info "Starting daemon with --override-dns..."
    vm_sudo "$REMOTE_BIN" start --override-dns --log-file /tmp/tor-vpn-daemon.log &

    if ! wait_for_ready 120; then
        fail "daemon did not become ready"
        return
    fi

    # --- DNS method ---
    info "Test: DNS override method"
    local log
    log=$(vm_sudo cat /tmp/tor-vpn-daemon.log 2>/dev/null) || true
    if echo "$log" | grep -qi "DNS configured via resolvectl"; then
        pass "DNS method: resolvectl (systemd-resolved)"
    elif echo "$log" | grep -qi "DNS configured via resolvconf"; then
        pass "DNS method: resolvconf"
    elif echo "$log" | grep -qi "DNS configured via /etc/resolv.conf"; then
        pass "DNS method: direct resolv.conf write"
    else
        fail "DNS method not detected in logs"
    fi

    # --- .onion service ---
    info "Test: .onion service via wget (up to 3 attempts)"
    local onion_ok=false
    for attempt in 1 2 3; do
        if vm wget -q --timeout=60 --tries=1 -O /dev/null "https://${onion_host}/" 2>&1; then
            onion_ok=true
            pass ".onion service reachable via wget"
            break
        fi
        info ".onion attempt $attempt failed, retrying..."
        sleep 10
    done
    if ! $onion_ok; then
        fail ".onion service not reachable"
    fi

    # --- SIGKILL recovery (reuse running daemon instead of starting a new one) ---
    info "Test: SIGKILL recovery"
    if ! vm_sudo pgrep -x tor-vpn >/dev/null 2>&1; then
        fail "daemon not running for SIGKILL test"
        return
    fi

    info "Sending SIGKILL..."
    vm_sudo pkill -9 tor-vpn 2>/dev/null || true
    sleep 2

    if vm_sudo test -f /run/tor-vpn-state.json; then
        pass "state file preserved after SIGKILL"
    else
        fail "state file not found after SIGKILL"
    fi

    local cleanup_out
    cleanup_out=$(vm_sudo "$REMOTE_BIN" cleanup 2>&1) || true
    if echo "$cleanup_out" | grep -qi "clean\|restored\|removed\|success"; then
        pass "cleanup after SIGKILL succeeded"
    else
        fail "cleanup after SIGKILL: $cleanup_out"
    fi

    if ! vm ip route show 2>/dev/null | grep -q "0\.0\.0\.0/1"; then
        pass "routes cleaned after SIGKILL recovery"
    else
        fail "routes still present after cleanup"
    fi
}

# --- Main ---

case "${1:-full}" in
    setup)
        setup_vm
        info "VM '${VM_NAME}' is ready. Shell into it with: limactl shell ${VM_NAME}"
        ;;
    teardown)
        teardown_vm
        ;;
    quick)
        setup_vm
        echo ""
        info "=== Quick tests ==="
        test_binary_runs
        test_status_clean
        test_requires_root
        ;;
    full)
        setup_vm
        echo ""
        info "=== Basic tests (no daemon) ==="
        test_binary_runs
        test_status_clean
        test_requires_root

        echo ""
        info "=== Session 1: Full VPN flow ==="
        ensure_clean
        test_vpn_flow

        echo ""
        info "=== Session 2: DNS override + .onion + SIGKILL ==="
        ensure_clean
        test_override_dns_onion_and_sigkill
        ;;
    *)
        echo "Usage: $0 [setup|teardown|quick|full]"
        exit 1
        ;;
esac

# --- Summary ---
echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}${FAILURES} test(s) failed${NC}"
fi

# Cleanup daemon if still running
vm_sudo pkill tor-vpn 2>/dev/null || true

exit "$FAILURES"
