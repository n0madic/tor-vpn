# tor-vpn

Transparent Tor VPN that routes **all** machine traffic through the Tor network. No SOCKS proxy configuration needed — every application on the system automatically goes through Tor.

Works by creating a TUN virtual network interface, capturing all outgoing packets with a userspace TCP/IP stack, and forwarding them through Tor using [Arti](https://gitlab.torproject.org/tpo/core/arti) (the official Rust Tor implementation).

Includes a **GUI application** (Tauri v2 + Svelte) for managing the daemon with a system tray, live bandwidth stats, and a settings panel.

## How It Works

```
┌───────────────┐
│  Applications │
└──────┬────────┘
       │ normal TCP/UDP traffic
       ▼
┌──────────────┐     ┌──────────────────┐
│  OS Routing  │────▶│  TUN Device      │
│  Table       │     │  (tun-rs)        │
└──────────────┘     └──────┬───────────┘
                            │ raw IP packets
                            ▼
                     ┌───────────────────┐
                     │  Userspace Stack  │
                     │ (netstack-smoltcp)│
                     └───┬──────────┬────┘
                         │          │
                    TCP  │          │ UDP (port 53)
                         ▼          ▼
                  ┌───────────┐ ┌───────────┐
                  │TCP Handler│ │DNS Handler│
                  │(+DNS:53)  │ │(UDP DNS)  │
                  └─────┬─────┘ └─────┬─────┘
                        │             │
                        ▼             ▼
                  ┌──────────────────────┐
                  │   Arti (Tor Client)  │
                  └──────────┬───────────┘
                             │
                             ▼
                       Tor Network
```

**Key:** Tor connects to guard relays through the *original* network before routes are installed. Guard relay IPs get `/32` bypass routes through the original gateway, preventing a routing loop.

## Features

- **Transparent proxying** — all TCP traffic goes through Tor, no per-app configuration
- **DNS leak protection** — all DNS queries (UDP and TCP) are intercepted and resolved through Tor
- **`.onion` support** — access onion services from any application, e.g. `curl http://example.onion` (macOS/Linux only — [blocked by Windows DNS Client](https://datatracker.ietf.org/doc/html/rfc7686))
- **Stream isolation** — configurable per-connection, per-destination, or session-wide Tor circuit isolation
- **Exit country selection** — choose which country your traffic appears to come from (`--exit-country DE`)
- **Bridge support** — connect through Tor bridges for censorship circumvention (`--bridge`)
- **Pluggable transports** — use obfs4, snowflake, etc. to disguise Tor traffic (`--pt-path`)
- **Bandwidth stats** — live upload/download traffic monitoring (in GUI or periodic logging)
- **Circuit refresh** — `tor-vpn refresh` or `SIGUSR1` to get a new Tor identity without restarting
- **Route safety** — routes are automatically restored on exit, Ctrl+C, panic, or after SIGKILL (via `cleanup` subcommand or auto-recovery on next start)
- **Dynamic guard monitoring** — automatically detects new Tor guard relays and adds bypass routes on the fly
- **DNS resilience** — retries with fresh Tor circuit on timeout, caches responses (configurable TTL)
- **Backpressure** — configurable limit on concurrent TCP connections (`--max-connections`)
- **IPC control socket** — manage the running daemon without root (`status`, `refresh`, `stop`) via Unix socket / Windows named pipe
- **GUI application** — Tauri-based desktop app with system tray, live bandwidth graph, log viewer, and settings
- **Cross-platform** — macOS, Linux, and Windows

## Requirements

- **Root/sudo/Administrator** — required only for `start` and `cleanup` (TUN device creation and route manipulation). Other commands (`status`, `refresh`, `stop`) work without privileges via IPC
- **Rust 1.70+** — for building from source
- **Node.js 18+** — for building the GUI frontend (optional)
- **Windows only:** [wintun.dll](https://www.wintun.net/) — place next to the executable, in System32, or anywhere on PATH

## Installation

### CLI Daemon

```bash
git clone https://github.com/n0madic/tor-vpn.git
cd tor-vpn
cargo build --release
```

The binary will be at `./target/release/tor-vpn`.

### GUI Application

```bash
# Install frontend dependencies (first time only)
cd ui/frontend && npm install && cd ../..

# Development mode (hot-reload)
cd ui && cargo tauri dev

# Production build
cd ui && cargo tauri build
```

The GUI launches the daemon with privilege escalation (native password dialog). Once running, the GUI communicates with the daemon via IPC — disconnect, refresh, and status queries work without entering the password again.

## Usage

### GUI

Launch the GUI application:

```bash
./target/release/tor-vpn-ui
# Or in development:
cd ui && cargo tauri dev
```

The GUI provides:
- **Dashboard** — connect/disconnect with one click, live bandwidth stats and speed graph, connection details (TUN, gateway, guard IPs, DNS, PID, exit country)
- **Logs** — real-time daemon log viewer with auto-scroll
- **Settings** — all daemon options as a form (exit country, isolation, DNS override, bridges, bypass CIDRs, etc.)
- **System tray** — background operation with tray icon and context menu

The daemon is launched with root privileges via the native OS password dialog (macOS: Authorization Services, Linux: PolicyKit, Windows: UAC).

### CLI (macOS / Linux)

```bash
# Start with defaults (all traffic through Tor)
sudo tor-vpn start

# Custom TUN address and MTU
sudo tor-vpn start --tun-address 10.10.0.1 --tun-mtu 1400

# Per-connection isolation (new Tor circuit for every TCP connection)
sudo tor-vpn start --isolation per-connection

# Bypass specific subnets (e.g. local network)
sudo tor-vpn start --bypass-cidr 192.168.1.0/24 --bypass-cidr 10.0.0.0/8

# Override system DNS (required for .onion support in browsers with DoH)
sudo tor-vpn start --override-dns

# Route traffic through a specific country's exit nodes
sudo tor-vpn start --exit-country DE

# Use bridges for censorship circumvention
sudo tor-vpn start \
  --bridge "obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0" \
  --pt-path "obfs4=/usr/bin/obfs4proxy"

# Write logs to file instead of stderr
sudo tor-vpn start --log-file /tmp/tor-vpn.log

# Refresh Tor circuits without restarting (new identity)
tor-vpn refresh

# Gracefully stop the daemon (no root required)
tor-vpn stop

# Verbose logging
sudo tor-vpn --log-level debug start
```

Press **Ctrl+C** to stop. Routes and DNS are automatically restored.

### Status & Control (No Root Required)

```bash
# Show live VPN status (via IPC when daemon is running, fallback to state file)
tor-vpn status

# Refresh Tor circuits (new identity)
tor-vpn refresh

# Gracefully stop the daemon
tor-vpn stop
```

### Recovery After Force-Kill

```bash
# Automatic: simply start tor-vpn again — it detects and cleans up orphaned state
sudo tor-vpn start

# Manual: restore routes/DNS without starting the VPN
sudo tor-vpn cleanup
```

### CLI (Windows)

Run from an **Administrator** command prompt:

```powershell
tor-vpn.exe start
tor-vpn.exe start --exit-country DE
tor-vpn.exe status     # no admin required
tor-vpn.exe refresh    # no admin required
tor-vpn.exe stop       # no admin required
tor-vpn.exe cleanup    # admin required (only after crash)
```

### Environment Variables

All options can be set via environment variables with the `TOR_VPN_` prefix. CLI flags take precedence.

```bash
export TOR_VPN_LOG_LEVEL=debug
export TOR_VPN_ISOLATION=per-connection
export TOR_VPN_OVERRIDE_DNS=true
export TOR_VPN_EXIT_COUNTRY=DE
export TOR_VPN_BYPASS_CIDR="192.168.1.0/24,10.0.0.0/8"
sudo -E tor-vpn start
```

### Config File

Use `--config` to load settings from a torrc-compatible config file:

```bash
sudo tor-vpn start --config /etc/tor-vpn.conf
```

Example config file:

```apacheconf
# Bridges — copy directly from torrc
Bridge obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0
ClientTransportPlugin obfs4 exec /usr/bin/lyrebird
UseBridges 1

# Exit country (torrc format)
ExitNodes {de}

# Logging — stderr (default), stdout, or file
Log info stderr
Log notice file /var/log/tor-vpn.log

# tor-vpn specific settings
Isolation per-destination
OverrideDNS 0
BypassCIDR 10.0.0.0/8
MaxConnections 256
DNSCacheTTL 900
ControlSocket /tmp/tor-vpn.sock
```

**Precedence** (lowest to highest): config file < environment variables < CLI arguments.

## Subcommands

| Subcommand | Root Required | Description |
|------------|:---:|-------------|
| `start` | Yes | Start the VPN — route all traffic through Tor |
| `status` | No | Show VPN status and diagnostic information (via IPC) |
| `refresh` | No | Refresh Tor circuits — new identity (via IPC, fallback to SIGUSR1) |
| `stop` | No | Gracefully stop the running daemon (via IPC) |
| `cleanup` | Yes | Restore orphaned routes/DNS from a previous crash or SIGKILL |

## Global Options

| Option | Env Variable | Default | Description |
|--------|-------------|---------|-------------|
| `--config` | `TOR_VPN_CONFIG` | *(none)* | Path to a torrc-style config file |
| `--log-level` | `TOR_VPN_LOG_LEVEL` | `info` | Log level (`error`, `warn`, `info`, `debug`, `trace`) |
| `--log-file` | `TOR_VPN_LOG_FILE` | *(stderr)* | Write logs to file instead of stderr (no ANSI colors) |
| `--state-file` | `TOR_VPN_STATE_FILE` | *(platform tmpdir)* | Path to state file for SIGKILL recovery |
| `--socket-path` | `TOR_VPN_SOCKET_PATH` | *(platform default)* | Path to IPC control socket for daemon management |

## Start Options

| Option | Env Variable | Default | Description |
|--------|-------------|---------|-------------|
| `--tun-name` | `TOR_VPN_TUN_NAME` | `torvpn0` | TUN device name (auto-assigned on macOS) |
| `--tun-address` | `TOR_VPN_TUN_ADDRESS` | `10.200.0.1` | TUN interface IPv4 address |
| `--tun-netmask` | `TOR_VPN_TUN_NETMASK` | `24` | TUN netmask prefix length |
| `--tun-mtu` | `TOR_VPN_TUN_MTU` | `1500` | TUN MTU |
| `--isolation` | `TOR_VPN_ISOLATION` | `per-destination` | `per-connection`, `per-destination`, or `session` |
| `--cache-dir` | `TOR_VPN_CACHE_DIR` | `/tmp/tor-vpn-cache` | Tor cache/state directory |
| `--bypass-cidr` | `TOR_VPN_BYPASS_CIDR` | *(none)* | CIDRs to route through original gateway (repeatable, comma-separated via env) |
| `--max-connections` | `TOR_VPN_MAX_CONNECTIONS` | `256` | Maximum concurrent TCP connections through Tor |
| `--max-dns-queries` | `TOR_VPN_MAX_DNS_QUERIES` | `256` | Maximum concurrent DNS queries |
| `--dns-cache-ttl` | `TOR_VPN_DNS_CACHE_TTL` | `900` | DNS cache TTL in seconds |
| `--override-dns` | `TOR_VPN_OVERRIDE_DNS` | `false` | Override system DNS to prevent browser DoH (macOS/Linux only) |
| `--exit-country` | `TOR_VPN_EXIT_COUNTRY` | *(any)* | ISO 3166-1 alpha-2 country code for exit relay (e.g., `US`, `DE`) |
| `--bridge` | `TOR_VPN_BRIDGE` | *(none)* | Tor bridge line(s) (repeatable, comma-separated via env) |
| `--pt-path` | `TOR_VPN_PT_PATH` | *(none)* | Pluggable transport path: `TRANSPORT=PATH` (repeatable) |
| `--state-write-interval` | `TOR_VPN_STATE_WRITE_INTERVAL` | `60` | State file write interval in seconds (for SIGKILL recovery) |

## Stream Isolation Policies

| Policy | Behavior |
|--------|----------|
| `per-connection` | Every TCP connection uses a new Tor circuit. Maximum privacy, slower. |
| `per-destination` | Connections to the same (IP, port) share a circuit. Good balance. **(default)** |
| `session` | All connections share one circuit. Fastest, least private. |

## Circuit Refresh (New Identity)

```bash
# Via the refresh subcommand (uses IPC — no root required)
tor-vpn refresh

# Or directly via signal (Unix only, may need root)
sudo kill -USR1 $(pgrep tor-vpn)
```

This invalidates all cached isolation tokens and clears the DNS cache. New connections will use fresh Tor circuits. Existing connections are unaffected.

In the GUI, click **New Identity** on the Dashboard (no password prompt needed).

## Limitations

- **TCP only** — Tor does not support arbitrary UDP. Non-DNS UDP packets are dropped.
- **IPv4 only** — IPv6 traffic is blocked (blackhole routes) to prevent leaks.
- **No `.onion` on Windows** — Windows blocks `.onion` DNS queries at the OS level (RFC 7686). `.onion` works on macOS and Linux.
- **No transparent authentication** — services that block Tor exit nodes will still block you.
- **Performance** — traffic goes through the Tor network (3 relays), expect higher latency.

### Windows-Specific Notes

- Routes via native Windows routing API (`route_manager` crate with `InterfaceIndex`), guard detection via `netstat2` crate
- IPC uses a named pipe (`\\.\pipe\tor-vpn`) — `stop`, `refresh`, and `status` work without Administrator
- **`.onion` domains are not supported** — Windows DNS Client (`dnsapi.dll`) blocks `.onion` queries at the API level per [RFC 7686](https://datatracker.ietf.org/doc/html/rfc7686). This is a Windows OS limitation that cannot be worked around. Regular domains work fine through Tor
- **`--override-dns` is disabled** — since `.onion` is blocked at the OS level, DNS override provides no benefit on Windows and is silently ignored. The UI disables the checkbox
- State file stored in `%TEMP%\tor-vpn-state.json`
- Requires [wintun.dll](https://www.wintun.net/) — place next to the executable, in System32, or anywhere on PATH

## Project Structure

```
tor-vpn/
├── src/main.rs             # CLI dispatch, session loop, IPC handler, wake detector
├── crates/                 # Internal library crates
│   ├── config/             # CLI args (clap), Config, torrc-style config file parser
│   ├── state/              # VpnState persistence, SIGKILL recovery
│   ├── bandwidth/          # Atomic tx/rx counters, CountingIo wrapper
│   ├── shutdown/           # Signal handling (SIGINT/SIGTERM/SIGUSR1)
│   ├── tun/                # TUN device creation (tun-rs)
│   ├── netstack/           # Userspace TCP/IP stack packet pump (netstack-smoltcp)
│   ├── tor/                # Arti Tor client, bootstrap watcher, bridge/PT config
│   ├── routing/            # Route management, DNS config, guard relay detection
│   ├── dns/                # DNS handler, .onion→synthetic IP mapping, DNS cache
│   ├── tcp/                # TCP proxy through Tor, DNS-over-TCP interception
│   └── ipc/                # IPC control socket (Unix socket / named pipe)
├── ui/                     # GUI application (Tauri v2 + Svelte 5)
│   ├── src/                # Rust backend (commands, IPC client, privilege escalation, tray)
│   ├── frontend/           # Svelte frontend (dashboard, settings, log viewer)
│   └── Cargo.toml          # UI crate dependencies
├── Cargo.toml              # Workspace root
└── README.md
```

## Tech Stack

| Component | Crate/Framework | Role |
|-----------|----------------|------|
| TUN interface | `tun-rs` v2 | Cross-platform async TUN device |
| Userspace TCP/IP | `netstack-smoltcp` | TUN packets → TCP streams / UDP datagrams |
| Tor client | `arti-client` v0.40 | Official Rust Tor implementation |
| GeoIP | `tor-geoip` v0.40 | Country-code exit relay selection |
| DNS parsing | `simple-dns` | Parse and build DNS packets |
| Route management | `route_manager` | Cross-platform native OS routing APIs |
| Guard detection | `netstat2` | Cross-platform socket enumeration |
| CLI | `clap` v4 | Command-line argument parsing |
| Async runtime | `tokio` | Async I/O and task scheduling |
| GUI framework | Tauri v2 | Lightweight desktop app (~10 MB, native WebView) |
| GUI frontend | Svelte 5 + TypeScript | Reactive UI with minimal bundle size |
| Concurrent state | `dashmap`, `moka` | Lock-free maps, TTL/LRU caches |

## License

MIT
