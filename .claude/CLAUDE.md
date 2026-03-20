# tor-vpn

Rust TUN-based transparent Tor VPN. Routes all machine traffic through Tor without SOCKS proxy. macOS + Linux + Windows.

## Build & Test

```bash
cargo check --workspace   # fast type check (all crates)
cargo test --workspace    # unit tests (all crates)
cargo build --release
sudo ./target/release/tor-vpn start    # requires root for TUN + routes
./target/release/tor-vpn status        # show tunnel status (no root via IPC)
./target/release/tor-vpn refresh       # refresh Tor circuits (no root via IPC)
./target/release/tor-vpn stop          # gracefully stop daemon (no root via IPC)
sudo ./target/release/tor-vpn cleanup  # manually restore routes/DNS after crash

# GUI (Tauri v2 + Svelte)
cd ui/frontend && npm install          # first time only
cd ui && cargo tauri dev               # development mode with hot-reload (falls back to PATH)

# GUI production build with bundled daemon sidecar
cargo build --release -p tor-vpn       # build daemon first
./ui/scripts/copy-sidecar.sh           # copy to ui/binaries/ with target-triple suffix
cd ui && cargo tauri build --config '{"bundle":{"externalBin":["binaries/tor-vpn"]}}'

# Cross-compile for Linux (aarch64)
cross build --target aarch64-unknown-linux-gnu --release -p tor-vpn
cross test --target aarch64-unknown-linux-gnu --workspace --exclude tor-vpn-ui

# Linux integration tests via Lima VM (requires: brew install lima, cross)
./tests/lima/test.sh quick     # binary + status checks (~1 min)
./tests/lima/test.sh full      # full VPN flow + .onion + SIGKILL recovery (~3 min)
./tests/lima/test.sh setup     # create/start VM for manual testing
./tests/lima/test.sh teardown  # destroy VM
```

## Architecture

```
App → OS Routes → TUN (tun-rs) → netstack-smoltcp → TCP handler → Arti → Tor
                                                   → DNS handler (port 53) → Arti resolve
```

Startup order matters: Tor bootstraps BEFORE routes install (direct network access needed).

## Source Map

The codebase is organized as a Cargo workspace with internal crates under `crates/`:

| Crate / File | Purpose |
|------|---------|
| `src/main.rs` | Thin CLI dispatch (`start` / `cleanup` / `status` / `refresh` / `stop`), `run_start()` session loop, `run_vpn_session()` (TUN → Tor → routes → netstack → handlers → IPC server), `run_status()` IPC-first diagnostics, `run_refresh()` IPC-first circuit refresh, `run_stop()` IPC shutdown, wake-from-sleep detector |
| `crates/state/` | `VpnState` struct (includes `original_if_index: u32` for Windows route cleanup), `VpnStatus` enum, `is_tor_vpn_process()`, state file persistence (`load`/`save`/`delete_file`), `get_status()`, `uptime_from_state()`, platform defaults (`default_state_file()`, `default_socket_path()`, `default_tor_cache_dir()`) |
| `crates/config/` | `Cli`, `Command`, `StartArgs`, `Config`, `IsolationPolicy`, CIDR/country-code parsers. `file` submodule: torrc-style config file parser (`ConfigFile`, `parse_config_file`), merge logic (`merge_into_config`, `ResolvedConfig`) |
| `crates/bandwidth/` | `BandwidthStats` — atomic tx/rx byte counters, `CountingIo<T>` inline byte counting wrapper, `log_summary()`, `format_bytes()` |
| `crates/shutdown/` | SIGINT/SIGTERM signal handling, SIGUSR1 stream, CancellationToken panic hook |
| `crates/tun/` | `create_tun_device()` — DeviceBuilder, platform-specific naming, Windows wintun.dll loading |
| `crates/netstack/` | `start_netstack()` — StackBuilder, bidirectional packet pump TUN↔Stack via DeviceFramed |
| `crates/tor/` | `TorManager` — bootstrap, `connect_tcp`, `connect_onion`, `resolve_dns`, isolation policy, `run_bootstrap_watcher`, `PROBE_DOMAINS` |
| `crates/routing/` | `NetworkController` — route management via `route_manager` crate (native OS APIs), default gateway detection (IP + interface name + index), guard IP bypass (/32 IPv4, /128 IPv6), catch-all (0/1+128/1), DNS config (macOS/Linux only — disabled on Windows). Submodules: `dns` (platform DNS config), `guard` (guard relay detection via netstat2, `run_guard_monitor`), `cleanup` (`cleanup_orphaned()`, `restore_dns_if_ours()` for SIGKILL recovery) |
| `crates/dns/` | DNS handler, `OnionState` (.onion→synthetic IP mapping with embedded counter, 10.254.0.0/16), `HandlerCtx`, `DnsCache`/`OnionMap` type aliases, DNS response construction via simple-dns Packet API |
| `crates/tcp/` | TCP accept loop, .onion lookup, DNS-over-TCP interception (port 53), `copy_bidirectional` netstack↔Arti DataStream |
| `crates/ipc/` | IPC control socket for unprivileged daemon management. `protocol.rs`: `Request`/`Response` (serde JSON). `server.rs`: async Unix socket / Windows named pipe server, `IpcCommand` dispatch. `client.rs`: blocking client (`send`, `try_status`, `try_refresh`, `try_shutdown`). `lib.rs`: `default_socket_path()` |

### UI Source Map (`ui/`)

| File | Purpose |
|------|---------|
| `ui/src/main.rs` | Tauri app entry point, registers commands, starts poller and tray |
| `ui/src/config.rs` | `VpnState` deserialization (mirrors daemon), `UiConfig` assembled from two sources: `config.json` (daemon_path only) + `daemon.conf` (torrc-style daemon settings). `save_config()` splits back, `load_daemon_config()` parses daemon.conf |
| `ui/src/daemon.rs` | Daemon lifecycle: `connect` (privilege escalation), `disconnect` (SIGTERM), `refresh_circuits` (SIGUSR1), `cleanup`, `get_status` |
| `ui/src/state_poller.rs` | Background thread: reads state file every 2s, computes bandwidth rates from deltas, emits `vpn-status` events |
| `ui/src/tray.rs` | System tray icon + context menu (Open Dashboard / Quit) |
| `ui/frontend/src/lib/types.ts` | TypeScript types mirroring Rust structs, `formatBytes()`, `formatRate()`, `formatDuration()` |
| `ui/frontend/src/lib/api.ts` | Tauri `invoke()` wrappers for all backend commands |
| `ui/frontend/src/lib/stores/vpn.ts` | Svelte writable store for VPN status, subscribes to `vpn-status` events |
| `ui/frontend/src/lib/stores/config.ts` | Svelte writable store for UiConfig, load/save functions |
| `ui/frontend/src/components/Dashboard.svelte` | Main screen: status indicator, bandwidth, connect/disconnect/refresh/cleanup buttons |
| `ui/frontend/src/components/ConfigPanel.svelte` | Settings panel: all StartArgs as form fields, save/reset |
| `ui/frontend/src/components/StatusIndicator.svelte` | Color-coded status dot + label (green/gray/yellow/red) |
| `ui/frontend/src/components/BandwidthChart.svelte` | Upload/download totals + rates + SVG sparkline |

| `ui/scripts/copy-sidecar.sh` | Copies daemon binary to `ui/binaries/` with target-triple suffix for Tauri `externalBin` bundling |

### Test Infrastructure (`tests/`)

| File | Purpose |
|------|---------|
| `tests/lima/tor-vpn.yaml` | Lima VM config (Ubuntu 24.04 ARM64, 2 CPU, 2GB RAM) for Linux integration testing |
| `tests/lima/test.sh` | Integration test suite: 2 daemon sessions covering TUN, routes, DNS, Tor connectivity, .onion, IPC, graceful stop, SIGKILL recovery |

## Key Crate Integration Notes

- **tun-rs**: `Arc<AsyncDevice>` + `DeviceFramed<BytesCodec>` for `Stream<BytesMut>` / `Sink<BytesMut>`
- **netstack-smoltcp**: `Stack` is `Stream<Vec<u8>>` / `Sink<Vec<u8>>` — packet pump converts between BytesMut↔Vec
- **arti-client**: `DataStream` is futures AsyncRead — needs `tokio_util::compat::FuturesAsyncReadCompatExt` for tokio IO. Features: `onion-service-client`, `geoip`, `pt-client` (implies `bridge-client`)
- **netstack TcpListener**: `Stream<Item=(TcpStream, local_addr, remote_addr)>` — `remote_addr` is the destination app wants to reach
- **netstat2**: `get_sockets_info(AddressFamilyFlags, ProtocolFlags) -> Result<Vec<SocketInfo>>` — cross-platform socket enumeration via native OS APIs (proc_pidfdinfo on macOS, NETLINK on Linux, iphlpapi on Windows). Used for guard relay IP detection instead of CLI tools (lsof/ss/netstat). `SocketInfo.associated_pids: Vec<u32>`, `ProtocolSocketInfo::Tcp(TcpSocketInfo { remote_addr, state, .. })`, `TcpState::Established`
- **netdev**: `get_default_interface() -> Result<Interface>` — cross-platform network interface/gateway detection via native OS APIs (sysctl on macOS, netlink on Linux, GetAdaptersAddresses on Windows). `Interface { name, gateway: Option<NetworkDevice>, dns_servers: Vec<IpAddr>, ipv4: Vec<Ipv4Net>, ... }`. `get_interfaces()` enumerates all interfaces. Replaces CLI tools (route/ip route/route print for gateway, networksetup/netsh for DNS query, netsh for TUN IP)
- **objc2-system-configuration** (macOS only): `SCPreferences::new(None, &name, None)`, `SCNetworkService::all(&prefs)` → `CFRetained<CFArray>`, `service.interface()` → `SCNetworkInterface`, `interface.bsd_name()` → `CFString`, `service.name()` → `CFString`, `service.enabled()` → `bool`, `service.protocol(&kSCNetworkProtocolTypeDNS)` → `SCNetworkProtocol`, `protocol.configuration()` / `set_configuration()` → `CFDictionary`, `dict[kSCPropNetDNSServerAddresses]` → `CFArray<CFString>`, `prefs.commit_changes()` + `prefs.apply_changes()`. Replaces ALL `networksetup` calls (`-listallhardwareports`, `-listallnetworkservices`, `-getdnsservers`, `-setdnsservers`) for interface→service mapping, DNS query, and DNS set/restore
- **route_manager**: `RouteManager::new()`, `.add(&Route)`, `.delete(&Route)` — cross-platform route management via native OS APIs (PF_ROUTE socket on macOS/BSD, netlink on Linux, Windows routing API). `Route::new(IpAddr, u8)` with builder methods `.with_gateway(IpAddr)`, `.with_if_name(String)`, `.with_if_index(u32)`. Windows requires `.with_if_index()` on all gateway-based routes — `CreateIpForwardEntry2` fails with ERROR_FILE_NOT_FOUND (os error 2) if `InterfaceIndex` is 0. Replaces CLI tools (`route`/`ip route`/`route.exe`) for IPv4 route add/delete. IPv6 blackhole routes remain as CLI (crate doesn't support reject/blackhole route types)

## Design Decisions

- `.onion` → `OnionState` struct wrapping `DashMap<String, Ipv4Addr>` + `AtomicU32` counter (hostname → synthetic IP from 10.254.0.0/16). `get_or_allocate()` uses entry API for race-free allocation. `lookup_by_ip()` for TCP handler reverse lookup. Each VPN session creates a fresh `OnionState` (no global counter)
- Per-destination isolation default: moka::sync::Cache<SocketAddr, IsolationToken> for TCP (max 4096, 30min TTL), moka::sync::Cache<String, IsolationToken> for .onion (max 1024, 30min TTL, key = "hostname:port")
- Route-based loop prevention: host routes for Tor guard IPs via original gateway (/32 for IPv4, /128 for IPv6)
- DNS responses built via simple-dns Packet API (parse query → `into_reply()` → add records → serialize), EDNS OPT records stripped by clearing `additional_records`
- System DNS override opt-in via `--override-dns`: sets DNS to TUN-derived IP (tun_addr+1) to prevent browser DoH upgrades (required for .onion interception). Off by default. **Disabled on Windows** — Windows DNS Client (`dnsapi.dll`) blocks `.onion` queries at the API level per RFC 7686 (before any network request), making DNS override ineffective for .onion. Regular DNS queries go through TUN → Tor without needing system DNS changes. The flag is silently ignored on Windows; the UI disables the checkbox
- Linux DNS configuration fallback chain: resolvectl (systemd-resolved, per-interface, SIGKILL-safe) → resolvconf (managed DNS) → direct /etc/resolv.conf write. Method stored in state file for correct restoration
- NetworkController implements Drop for cleanup on panic/unexpected exit
- Dynamic guard relay monitoring with fast/slow polling phases (5s first 2min, then 30s)
- DNS-over-TCP (port 53) intercepted in TCP handler, resolved via Tor (same as UDP DNS). 30s read timeout on length prefix prevents idle connections from holding semaphore permits indefinitely
- DNS retry with fresh Tor circuit on timeout + DNS cache via `moka` (`--dns-cache-ttl`, default 900s/15min, 4096 max LRU entries, shared between UDP and TCP DNS). Cache entries store insertion `Instant` — cached responses report accurate remaining TTL (not max TTL) to prevent clients from using stale IPs after daemon cache expires
- Semaphore-based TCP connection limit (`--max-connections`, default 256) — permit acquired before `tokio::spawn` for proper backpressure
- smoltcp patched via `[patch.crates-io]` to git main (TCP sequence number underflow fix)
- netstack-smoltcp patched via `[patch.crates-io]` to git main (premature `socket.close()` before `send_buffer` drain fix merged upstream but not yet released)
- DNS resolution: 5s timeout + retry with fresh circuit (5s) = 10s max, always SERVFAIL on failure
- Microdescriptor download schedule tuned for fresh bootstrap: 16 attempts (default 3), 8 parallel (default 4). Arti hardcodes 10s per-request read timeout in tor-dirclient — larger batches (~9800 MDs) exceed this → "Partial response" errors. More retries + higher parallelism = smaller batches per request
- Arti log noise suppressed: `tor_guardmgr=error,tor_chanmgr=error,tor_circmgr=error,tor_proto=error,tor_netdir=error`
- DNS returns SERVFAIL (not NXDOMAIN) when Tor resolution fails — prevents negative caching by clients
- Session restart loop: `main()` creates a fresh tokio runtime per session; `drop(rt)` force-cancels arti's internal background tasks, releasing the state lock. Wake detector and bootstrap watcher signal `Notify` → full session teardown + fresh restart (new TUN, new TorClient, new routes). `CachedSession` carries gateway + guard IPs between restarts — on restart with cache, routes install immediately with cached guard IPs (Phase 5 before Phase 4), traffic flows through Tor while guard detection runs concurrently. Stale guard /32 routes are harmless (unused bypass routes for old IPs)
- Wake-from-sleep detection via wall-clock vs monotonic clock divergence (>15s threshold, 5s polling) → signals restart
- Bootstrap watcher: verifies Tor with real DNS probe (not just `ready_for_traffic()` — arti can report ready while circuits are dead). Rotates probe domains (google, wikipedia, cloudflare) for resilience. First check at 30s (circuits need time to stabilize after route changes), then 30s. 3 consecutive probe failures (10s timeout each, 10s recovery interval) → signals restart
- Circuit warmup: after bootstrap, a DNS resolve fires in the background (via `tokio::spawn`) to force guard connection establishment. Guard IP polling runs concurrently at 1s intervals for up to 30s — guard TCP connections appear as ESTABLISHED before full circuit completion. Periodic "kick" resolves every 5s stimulate additional circuit building. Post-route verification (Phase 5b) fires all PROBE_DOMAINS in parallel with 5s overall timeout
- Full restart instead of incremental recovery: fresh `TorClient` fixes .onion after wake (hidden service state goes stale). ~10-15s restart (arti caches consensus on disk) vs ~2s incremental, but more reliable
- Country-code exit selection via `--exit-country` (ISO 3166-1 alpha-2). Uses arti-client `geoip` feature + `tor-geoip` crate. Applied to TCP `StreamPrefs` via `exit_country()`. NOT applied to .onion (no exit relay) or DNS resolution (same IPs regardless of exit country, and constraining country causes "Protocol error" on RESOLVE streams). Validated at parse time (2 ASCII letters, case-insensitive → uppercase)
- Epoch-based circuit refresh via SIGUSR1 (Unix only) or IPC `refresh`: invalidates per-destination/per-onion isolation token caches (moka `invalidate_all()`), forcing fresh circuits for new connections. Existing connections unaffected. DNS cache also cleared. Session-mode token unchanged by design — `refresh_circuits()` returns a distinct message for Session policy ("DNS cache cleared, session isolation unchanged") so the CLI/UI accurately reflects what was refreshed. Signal stream persists across multiple SIGUSR1 deliveries in same session
- Panic hook uses `Arc<Mutex<CancellationToken>>` — installed once, token swapped each session
- SIGKILL recovery: `VpnState` JSON written to `/tmp/tor-vpn-state.json` (macOS), `/run/tor-vpn-state.json` (Linux), or `%TEMP%\tor-vpn-state.json` (Windows) after route installation. On next startup, `cleanup_orphaned()` checks for stale state file → if PID is dead, restores routes/DNS. `sudo tor-vpn cleanup` for manual recovery. State file is on tmpfs — cleared on reboot (when routes reset anyway)
- Windows: TUN via wintun.dll (standard DLL search: exe dir, System32, PATH), routes via `route_manager` crate (native Windows routing API, requires `InterfaceIndex` — `netdev::Interface::index` captured and passed via `.with_if_index()`), gateway detection via `netdev` (native GetAdaptersAddresses), guard detection via `netstat2` crate, process check via `sysinfo` crate, admin check via `is-admin` crate (`IsUserAnAdmin` shell32). DNS override disabled (see `--override-dns` above). `.onion` domains not supported on Windows (blocked by `dnsapi.dll` per RFC 7686)
- `.onion` reverse lookup O(n) — acceptable since the map is small (typically <100 entries), lookup is per-connection
- IPv6 leak prevention: blackhole routes (`::/1` + `8000::/1`) installed alongside IPv4 catch-all routes. macOS uses `-reject` via `::1`, Linux uses `blackhole`, Windows uses loopback `interface=1`. Combined with AAAA → empty response in DNS handler for defense-in-depth. Best-effort install (warning on failure, never aborts VPN startup). Tor exit nodes have unstable IPv6 support — AAAA queries return empty before cache check to prevent type mismatch
- `derive_dns_ip()` validates DNS IP against subnet boundaries (same subnet, not broadcast)
- `cleanup_orphaned()` collects both DNS restore errors and route removal errors; state file preserved on partial failure for retry. Returns `Err` on partial failure (not `Ok(true)`) so callers can distinguish full success from partial cleanup. `run_start()` aborts on partial cleanup failure (prevents layering a new session on top of stale routes/DNS). `restore_dns_if_ours()` returns `Result<(), String>` so DNS failures are not silently swallowed
- SIGKILL DNS recovery uses `configured_dns_ip` guard (not `original_dns`) — resolvectl/resolvconf don't save original_dns
- macOS DNS: fully native via `objc2-system-configuration` — service detection (`SCNetworkServiceCopyAll` + `SCNetworkInterfaceGetBSDName`), DNS read (`SCNetworkProtocolGetConfiguration` + `kSCPropNetDNSServerAddresses`), DNS write (`SCNetworkProtocolSetConfiguration` + `SCPreferencesCommitChanges/ApplyChanges`). Zero `networksetup` CLI calls
- `.onion` connections respect isolation policy (PerConnection/PerDestination/Session) same as TCP
- Semaphore-based DNS query limit (`--max-dns-queries`, default 256) — permit acquired before `tokio::spawn` for proper backpressure
- `--bypass-cidr` validated at parse time (clap value_parser) — rejects invalid CIDR before reaching route commands
- All CLI arguments mirrored by `TOR_VPN_*` environment variables (clap `env` feature). CLI flags take precedence. `--bypass-cidr` uses comma-separated values via env (`TOR_VPN_BYPASS_CIDR="10.0.0.0/8,172.16.0.0/12"`)
- State file permissions 0o644 (world-readable — contains only routing metadata, no secrets). macOS uses hardcoded `/tmp/` (not `std::env::temp_dir()` which is per-user for root), same as the IPC socket path
- PID reuse mitigation: `cleanup_orphaned()` verifies process name matches `tor-vpn` before treating PID as alive — cross-platform via `sysinfo` crate (`System::refresh_processes_specifics` with single-PID lookup)
- Bandwidth accounting: `BandwidthStats` with two `AtomicU64` counters (tx/rx). TCP uses `CountingIo` wrapper around Tor stream for inline byte counting in `poll_read`/`poll_write` (captures bytes even when `copy_bidirectional` returns `Err`). DNS handler counts query/response sizes directly. Logged every 60s, on SIGUSR1, and at session shutdown. Counters persisted to state file (`VpnState.tx_bytes`/`rx_bytes`) for `status` subcommand. Human-readable formatting (B/KB/MB/GB)
- Bridge/PT support: `--bridge` accepts standard Tor bridge lines (parsed via `BridgeConfigBuilder::from_str()`), `--pt-path` maps transport names to binaries (e.g. `obfs4=/usr/bin/obfs4proxy`). Transport requirements auto-detected from bridge lines via `get_transport()`. Direct bridges (no PT) don't require `--pt-path`. When `--pt-path` not provided, PT binaries are auto-detected from system PATH via `which`/`where`. Resolved paths stored in `TorManager::resolved_pt_paths` for guard detection. Enabled via arti-client `pt-client` feature flag. `BoolOrAuto::Explicit(true)` set when bridges configured. Bridge lines with transport `Some("")` treated as direct (no PT needed)
- PT guard detection: when bridges with PTs are configured (determined by `TorManager::resolved_pt_paths()` being non-empty), `detect_pt_external_ips()` finds the PT binary's real external connections via `sysinfo` crate (PID discovery by exe path) + `netstat2` crate (socket enumeration), instead of `detect_guard_ips()` which would only find arti's localhost connection to the PT SOCKS proxy. Guard monitor also uses PT detection when bridges are configured
- PT bridge warmup + guard state reset: arti's guard manager marks bridges as "down" after ~10s timeout and persists to `{cache_dir}/state/` — won't retry for 30+ minutes. PT bridges (especially webtunnel) take 15-30s to connect, exceeding this timeout. Fix: `TorManager::new()` deletes `{cache_dir}/state/` (keeping `cache/`) when bridges configured, ensuring fresh bridge evaluation. Warmup is a single `resolve_dns` attempt; on failure returns `SessionOutcome::WarmupFailed` → session loop retries with fresh TorClient (up to 8 attempts, 10s apart). Non-PT warmup is warn-only (not fatal)
- Bridge IP fallback: `parse_bridge_ips()` extracts relay IPv4 addresses from bridge lines as last-resort bypass routes when guard detection returns empty. Bridge line format: `[transport] host:port [fingerprint] [key=value...]`. For obfs4/direct bridges, the relay IP is the actual connection target. For webtunnel/snowflake, the relay IP differs from the CDN endpoint but an extra bypass route is harmless
- DNS/TCP handler context: `HandlerCtx` struct groups shared parameters (tor, onion_map, dns_cache, dns_cache_ttl, stats, cancel) passed to `run_dns_handler` and `run_tcp_handler` — reduces argument count from 8 to 3
- Config file: `--config /path/to/config` loads torrc-style config file. Precedence: config file (lowest) < env vars < CLI args (highest). torrc-compatible directives: `Bridge`, `ClientTransportPlugin` (exec form), `ExitNodes {CC}`, `UseBridges 0/1`, `Log <severity> stdout|stderr|file /path`, `CacheDirectory`, `ControlSocket`. tor-vpn directives: `TunName`, `TunAddress`, `TunNetmask`, `TunMTU`, `Isolation`, `CacheDir` (alias), `BypassCIDR`, `MaxConnections`, `MaxDNSQueries`, `DNSCacheTTL`, `OverrideDNS`, `StateFile`, `ControlSocket`, `StateWriteInterval` (1-3600). All directive names case-insensitive. Unknown directives ignored with stderr warning (forward-compatible). `UseBridges 0` disables bridges from config file (CLI `--bridge` still overrides). Two-phase clap parse (`get_matches()` + `from_arg_matches()`) to check `value_source()` for merge precedence
- `status` subcommand: reads state file + checks PID liveness to detect 3 states: clean (not running), running (PID alive), dirty (needs cleanup). Uptime derived from state file mtime. Traffic stats (tx/rx bytes) read from state file — daemon writes `BandwidthStats` counters every 60s, on SIGUSR1, and at shutdown. Output via `println!` (not tracing)
- `refresh` subcommand: reads state file for running PID, sends SIGUSR1 via `nix::sys::signal::kill()`. Unix-only (SIGUSR1 doesn't exist on Windows). No root required — only needs permission to signal the target process
- Arti log noise: `tor_ptmgr=error` added to suppress `PT <not yet launched> quit: ChildGone` warnings at shutdown
- UI architecture: Tauri v2 (Rust backend + system WebView) + Svelte 5 (TypeScript frontend). Daemon communication via 3 channels: subprocess (start with privilege escalation), state file polling (2s interval for live stats), signals (SIGTERM/SIGUSR1 for stop/refresh). Config split: `config.json` stores only `daemon_path` (UI setting), `daemon.conf` is single source of truth for all daemon settings (torrc-style). `get_config()` assembles from both, `save_config()` splits back. `connect(daemon_path)` launches with `tor-vpn start --config <daemon.conf>` — bridge lines never touch a shell
- `--state-write-interval <SECS>` (default: 60, env: `TOR_VPN_STATE_WRITE_INTERVAL`): configurable bandwidth flush interval. UI sets 2s for near-real-time stats. Write-on-change optimization: skips disk write when bandwidth counters are unchanged (idle VPN)
- `--log-file <PATH>` (global, env: `TOR_VPN_LOG_FILE`): write logs to file instead of stderr, with ANSI colors disabled. Used by UI to capture daemon output without shell redirection
- `reset_signal_state()` called at start of `run_start()`: clears signal mask and resets SIGTERM/SIGUSR1 to SIG_DFL. Fixes signal delivery when launched via macOS `do shell script ... with administrator privileges` where the parent shell may leave signals as SIG_IGN
- UI privilege escalation: platform-native — macOS: `osascript` "do shell script ... with administrator privileges", Linux: `pkexec` (PolicyKit), Windows: `Start-Process -Verb RunAs -WindowStyle Hidden` (UAC, no console window). Daemon launched detached with stdout/stderr redirected to log file
- UI config split across two files in platform-specific config dir (macOS `~/Library/Application Support/com.tor-vpn.ui/`, Linux `~/.config/tor-vpn-ui/`, Windows `%APPDATA%\tor-vpn-ui\`): `config.json` (only `daemon_path`), `daemon.conf` (torrc-style daemon settings — single source of truth, parsed on load via `config::parse_config_file`)
- Bandwidth rates computed in UI from state file byte counter deltas between poll cycles: `rate = (current_bytes - prev_bytes) / elapsed_secs`
- IPC control socket: daemon creates Unix domain socket (`/tmp/tor-vpn.sock` macOS, `/run/tor-vpn.sock` Linux) / named pipe (`\\.\pipe\tor-vpn` Windows) in Phase 7e. Configurable via `--socket-path` CLI flag, `TOR_VPN_SOCKET_PATH` env var, or `ControlSocket` config file directive (torrc-compatible). Accepts `status`/`refresh`/`shutdown` commands via newline-delimited JSON. Socket permissions 0o666 (any local user can query status), but control commands (`shutdown`, `refresh`) require peer credential authorization via `getpeereid`/`SO_PEERCRED`: root (UID 0) or the daemon owner. Owner detection via `SUDO_UID` env (sudo + macOS UI osascript injection) or `PKEXEC_UID` env (PolicyKit). macOS UI injects `SUDO_UID=<libc::getuid()>` into the osascript shell command. No heuristic fallbacks — daemon started directly as root without env vars is controllable only by root. Request payloads capped at 4KB (`MAX_REQUEST_SIZE`) to prevent memory exhaustion. Client response reads bounded at 64KB (`MAX_RESPONSE_SIZE`) to prevent DoS via fake socket. Stale socket cleanup validates file type via `symlink_metadata().is_socket()` before removal — refuses to delete non-socket paths (prevents file-deletion primitive when path is user-configurable). CLI `status`/`refresh`/`stop` try IPC at the resolved socket path with SIGUSR1/state-file fallback. UI reads `ControlSocket` from `daemon.conf` for IPC. Socket lifecycle: created on session start, deleted on shutdown/cancel, stale sockets cleaned up via connect-probe on next start. With IPC providing live bandwidth data, UI `state_write_interval` defaults to 60s (was 2s), reducing FS overhead
- Symlink-safe file writes: `state::safe_create_file()` and `state::save()` use `O_CREAT | O_EXCL` (via `create_new(true)`) on Unix — prevents symlink-following attacks where a local attacker places a symlink at a predictable temp path (`/tmp/tor-vpn-state.json.tmp`, `/tmp/tor-vpn-daemon.log`) to clobber arbitrary files when the root daemon writes. Log file creation in `init_logging` also uses `safe_create_file()`
- Kill-switch blackhole routes on restart (`--kill-switch`, default true): when a VPN session restarts (wake-from-sleep or Tor failure), `transition_to_blackhole()` replaces TUN catch-all routes with IPv4 blackhole/reject routes (0.0.0.0/1 + 128.0.0.0/1) instead of removing all routes. Guard /32 bypass routes stay so Tor can reconnect. All other traffic is dropped (not leaked through clearnet). The blackhole routes are removed by the next session's `install_routes()` or by `cleanup_orphaned()`. `--kill-switch=false` disables this behavior (falls back to `remove_routes()` which briefly exposes traffic during re-bootstrap). macOS: `-reject` via route, Linux: `blackhole` via ip, Windows: loopback interface via netsh. Gateway detection under blackhole: `new_with_hint()` first tries normal detection (blackhole /1 routes shadow but don't delete the /0 default route — some OSes/tools still see it), then briefly removes blackhole → detects real gateway → reinstalls blackhole (handles network change after wake), then falls back to cached hint if network is genuinely unavailable
- Graceful shutdown route cleanup: `remove_routes()` collects errors from each operation and only deletes the state file if all succeeded. On partial failure (e.g., DNS restore fails), the state file is preserved for `sudo tor-vpn cleanup` retry — consistent with `cleanup_orphaned()` behavior
- Config file injection prevention: `to_config_content()` sanitizes ALL string values with `sanitize_line()` (truncates at first `\n`/`\r`) — including `ControlSocket` path, `StateFile` path, and `Log` path — to prevent directive injection in the torrc-style config file via values containing newlines from the renderer. `StateFile` emitted when non-default to preserve custom paths through UI save/load roundtrip
- DNS-over-TCP payload timeout: both the 2-byte length prefix AND the message payload reads have 30s timeouts, preventing slow-loris attacks that would hold TCP semaphore permits indefinitely. Total connection lifetime capped at 120s to prevent semaphore hogging (was unbounded: 64 queries * 30s = 32min). Response length validated against u16::MAX before framing (SERVFAIL fallback on overflow)
- UI daemon_path validation: `validate_daemon_path()` canonicalizes the path first (resolves all symlinks), then checks: (1) absolute, (2) existing regular file, (3) filename exactly `tor-vpn`/`tor-vpn.exe`. Returns the canonical `PathBuf` — callers execute the canonical path (not the original) to prevent TOCTOU symlink-swap attacks. Unix `validate_unix_trust_chain`: binary file must not be group/world-writable (mode & 0o022 == 0), ancestor directories must not be world-writable (mode & 0o002 == 0). Windows `validate_windows_trust_chain`: rejects paths under `%USERPROFILE%` or `%TEMP%`. Applied to both `connect()` and `cleanup()`
- UI CSP: `tauri.conf.json` sets `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'` to restrict renderer capabilities
- UI state file resolution: `load_vpn_state()` reads `StateFile` from `daemon.conf` (same as `socket_path()` reads `ControlSocket`), ensuring consistent behavior with custom state file paths
- IPC uptime: `build_ipc_status()` computes uptime from `Instant::now()` captured at session start, not from state file mtime (which resets on each bandwidth flush write). `VpnState.started_at` (Unix timestamp, `#[serde(default)]` for backward compat) persisted to state file for CLI and UI fallback uptime. Both `print_uptime_from_state()` (CLI) and `uptime_from_state()` (UI) compute uptime as `now - started_at`
- Windows IPC authorization: `is_authorized()` defaults to deny (fail-closed) when peer credentials are unavailable. On Windows, `handle_pipe_connection` calls `GetNamedPipeClientProcessId` (kernel32 FFI) to verify the peer — if the PID is valid, the client passed the named pipe ACL and is treated as root-equivalent (`Some(0)`). If PID cannot be obtained, destructive commands are denied. `status` queries bypass authorization and work for all local users
- Daemon sidecar bundling: `find_daemon_path()` checks for bundled sidecar (`current_exe().parent().join("tor-vpn")`) before falling back to `which("tor-vpn")`. Tauri `externalBin` config NOT in committed `tauri.conf.json` (would break `cargo check --workspace`) — passed at build time via `cargo tauri build --config '{"bundle":{"externalBin":["binaries/tor-vpn"]}}'`. `ui/scripts/copy-sidecar.sh` copies daemon binary to `ui/binaries/tor-vpn-{TARGET_TRIPLE}`. Sidecar location: macOS `App.app/Contents/MacOS/tor-vpn`, Linux `/usr/bin/tor-vpn`, Windows install dir. `daemon_path` config field still works as user override
- Cross-compilation: arti-client uses `rustls` TLS backend (not `native-tls`/OpenSSL) — pure Rust, no C dependencies for TLS. `libsqlite3-sys` uses `bundled` feature (builds SQLite from source). This enables `cross build --target aarch64-unknown-linux-gnu` without system libraries. UI crate (`tor-vpn-ui`) excluded from cross builds/tests (depends on GTK/glib on Linux): `cross test --workspace --exclude tor-vpn-ui`
- Linux integration tests: Lima VM (Ubuntu 24.04 ARM64) runs the cross-compiled binary. `tests/lima/test.sh` covers full VPN flow in 2 daemon sessions — session 1 (no --override-dns): TUN, bootstrap, routes, IPv6 blackhole, Linux paths (/run/), DNS, Tor connectivity, IPC, graceful stop; session 2 (--override-dns): DNS method detection (resolvectl), .onion via wget, SIGKILL recovery + cleanup
