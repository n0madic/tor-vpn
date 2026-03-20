use std::sync::{Arc, Mutex};
use std::time::Duration;

use config::{CommandFactory, FromArgMatches};
use tokio_util::sync::CancellationToken;

use config::{Cli, Command, Config};
use dns::{DnsCache, OnionMap};
use ipc::IpcCommand;

/// Result of a single VPN session.
enum SessionOutcome {
    /// Clean shutdown (Ctrl+C / SIGTERM).
    Shutdown,
    /// Session should be restarted (wake from sleep or Tor failure).
    Restart,
    /// PT bridge warmup failed — retry with fresh TorClient (clears guard state).
    WarmupFailed,
}

/// Cached state from a previous session, reused on restart to skip
/// gateway detection and install guard routes immediately.
struct CachedSession {
    gateway_ip: std::net::IpAddr,
    interface: String,
    if_index: u32,
    guard_ips: Vec<std::net::IpAddr>,
}

fn main() -> anyhow::Result<()> {
    // Two-phase clap parse: get raw ArgMatches to check value_source() for config file merge
    let matches = Cli::command().get_matches();
    let cli = Cli::from_arg_matches(&matches).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Parse config file first (lowest priority)
    let file_config = cli
        .config
        .as_ref()
        .map(|path| config::parse_config_file(path))
        .transpose()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    match cli.command {
        Command::Start(_) => {
            // Merge: config file < env < CLI
            let resolved = config::merge_into_config(cli, &matches, file_config);
            init_logging(&resolved.log_targets);
            run_start(resolved.config)
        }
        Command::Cleanup => {
            let log_targets = config::resolve_log_targets(&cli, &matches, file_config.as_ref());
            let state_file = config::resolve_state_file(&cli, &matches, file_config.as_ref());
            init_logging(&log_targets);
            run_cleanup(&state_file)
        }
        Command::Status => {
            let state_file = config::resolve_state_file(&cli, &matches, file_config.as_ref());
            let socket_path = config::resolve_socket_path(&cli, &matches, file_config.as_ref());
            run_status(&state_file, &socket_path)
        }
        Command::Refresh => {
            let state_file = config::resolve_state_file(&cli, &matches, file_config.as_ref());
            let socket_path = config::resolve_socket_path(&cli, &matches, file_config.as_ref());
            run_refresh(&state_file, &socket_path)
        }
        Command::Stop => {
            let socket_path = config::resolve_socket_path(&cli, &matches, file_config.as_ref());
            run_stop(&socket_path)
        }
    }
}

/// Initialize tracing with one or more log targets, each with its own level.
/// Supports simultaneous logging to stderr, stdout, and/or files.
fn init_logging(targets: &[config::LogTarget]) {
    use time::macros::format_description;
    use tracing_subscriber::fmt::time::UtcTime;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;

    // Short HH:MM:SS timestamp — log lives one session, date is unnecessary
    let make_timer = || UtcTime::new(format_description!("[hour]:[minute]:[second]"));

    let make_filter = |level: &str| {
        let s = format!(
            "{level},tor_guardmgr=error,tor_chanmgr=error,tor_circmgr=error,\
             tor_proto=error,tor_netdir=error,tor_ptmgr=error"
        );
        tracing_subscriber::EnvFilter::try_new(&s)
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };

    let mut layers: Vec<Box<dyn Layer<tracing_subscriber::Registry> + Send + Sync>> = Vec::new();

    for target in targets {
        let filter = make_filter(&target.level);
        match &target.destination {
            config::LogDestination::Stderr => {
                layers.push(Box::new(
                    tracing_subscriber::fmt::layer()
                        .with_timer(make_timer())
                        .with_writer(std::io::stderr)
                        .with_filter(filter),
                ));
            }
            config::LogDestination::Stdout => {
                layers.push(Box::new(
                    tracing_subscriber::fmt::layer()
                        .with_timer(make_timer())
                        .with_writer(std::io::stdout)
                        .with_filter(filter),
                ));
            }
            config::LogDestination::File(path) => {
                // Use safe_create_file to prevent symlink-following attacks:
                // the log path is predictable (/tmp/tor-vpn-daemon.log) and the
                // daemon runs as root, so a symlink would clobber arbitrary files.
                match state::safe_create_file(path) {
                    Ok(file) => {
                        layers.push(Box::new(
                            tracing_subscriber::fmt::layer()
                                .with_timer(make_timer())
                                .with_writer(std::sync::Mutex::new(file))
                                .with_ansi(false)
                                .with_filter(filter),
                        ));
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to open log file {}: {e}", path.display());
                    }
                }
            }
        }
    }

    // Fallback if all targets failed (e.g., all file opens failed)
    if layers.is_empty() {
        layers.push(Box::new(
            tracing_subscriber::fmt::layer()
                .with_timer(make_timer())
                .with_writer(std::io::stderr)
                .with_filter(make_filter("info")),
        ));
    }

    tracing_subscriber::registry().with(layers).init();
}

/// Verify the process is running with elevated privileges (root on Unix, Administrator on Windows).
fn ensure_elevated(context: &str) -> anyhow::Result<()> {
    if !is_admin::is_admin() {
        #[cfg(unix)]
        anyhow::bail!("tor-vpn {context} must run as root (sudo).");
        #[cfg(windows)]
        anyhow::bail!("tor-vpn {context} must run as Administrator.");
    }
    Ok(())
}

fn run_cleanup(state_file: &std::path::Path) -> anyhow::Result<()> {
    ensure_elevated("cleanup")?;

    match routing::cleanup_orphaned(state_file) {
        Ok(true) => tracing::info!("Cleanup complete — orphaned routes and DNS restored"),
        Ok(false) => tracing::info!("No orphaned state found — system appears clean"),
        Err(e) => return Err(e),
    }
    Ok(())
}

fn run_status(state_file: &std::path::Path, socket_path: &std::path::Path) -> anyhow::Result<()> {
    // Try IPC first — live data directly from daemon memory
    if let Some(ipc::Response::Status { state, uptime_secs }) = ipc::try_status(socket_path) {
        println!("Status: running");
        println!("PID: {}", state.pid);
        println!(
            "Uptime: {}",
            format_duration(Duration::from_secs(uptime_secs))
        );
        println!();
        print_state_details(&state, state_file);
        return Ok(());
    }

    // Fallback — state file (daemon unreachable or not running)
    match state::get_status(state_file)? {
        state::VpnStatus::Clean => {
            println!("Status: not running");
            println!("State file: {} (not found)", state_file.display());
        }
        state::VpnStatus::Running(s) => {
            println!("Status: running");
            println!("PID: {}", s.pid);
            let uptime = state::uptime_from_state(&s);
            if uptime > 0 {
                println!("Uptime: {}", format_duration(Duration::from_secs(uptime)));
            } else {
                println!("Uptime: (unknown)");
            }
            println!();
            print_state_details(&s, state_file);
        }
        state::VpnStatus::Dirty(s) => {
            println!("Status: dirty (needs cleanup)");
            println!("PID: {} (dead)", s.pid);
            println!();
            print_state_details(&s, state_file);
            println!();
            println!("Run `sudo tor-vpn cleanup` to restore routes and DNS.");
        }
    }
    Ok(())
}

fn run_refresh(state_file: &std::path::Path, socket_path: &std::path::Path) -> anyhow::Result<()> {
    // Try IPC first — cross-platform, no privileges needed
    if let Ok(msg) = ipc::try_refresh(socket_path) {
        println!("{msg}");
        return Ok(());
    }

    // Fallback — SIGUSR1 (Unix only, may need root)
    #[cfg(not(unix))]
    {
        _ = state_file;
        anyhow::bail!("Cannot reach daemon via IPC and SIGUSR1 is Unix-only");
    }

    #[cfg(unix)]
    {
        match state::get_status(state_file)? {
            state::VpnStatus::Clean => {
                anyhow::bail!("tor-vpn is not running (no state file found)");
            }
            state::VpnStatus::Dirty(s) => {
                anyhow::bail!(
                    "tor-vpn (PID {}) is not running (stale state). Run `sudo tor-vpn cleanup` first.",
                    s.pid
                );
            }
            state::VpnStatus::Running(s) => {
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(s.pid as i32),
                    nix::sys::signal::Signal::SIGUSR1,
                )
                .map_err(|e| anyhow::anyhow!("Failed to send SIGUSR1 to PID {}: {e}", s.pid))?;
                println!(
                    "Sent SIGUSR1 to tor-vpn (PID {}) — circuits will refresh",
                    s.pid
                );
                Ok(())
            }
        }
    }
}

fn run_stop(socket_path: &std::path::Path) -> anyhow::Result<()> {
    ipc::try_shutdown(socket_path)
        .map_err(|e| anyhow::anyhow!("Failed to stop daemon: {e}. Is it running?"))?;
    println!("Shutdown signal sent — daemon will clean up and exit");
    Ok(())
}

/// Build an IPC Status response from the current daemon state.
fn build_ipc_status(
    net_ctrl: &Arc<Mutex<routing::NetworkController>>,
    bw: &Arc<bandwidth::BandwidthStats>,
    session_start: std::time::Instant,
) -> ipc::Response {
    let mgr = net_ctrl.lock().unwrap_or_else(|p| p.into_inner());

    let uptime_secs = session_start.elapsed().as_secs();

    let state = state::VpnState {
        pid: std::process::id(),
        tun_name: mgr.tun_name().to_string(),
        original_gateway: mgr.original_gateway().to_string(),
        original_interface: mgr.original_interface().to_string(),
        original_if_index: mgr.original_if_index(),
        guard_ips: mgr.guard_ips().to_vec(),
        bypass_cidrs: mgr.bypass_cidrs().to_vec(),
        dns_service_name: mgr.dns_service_name().map(|s| s.to_string()),
        original_dns: mgr.original_dns().map(|s| s.to_string()),
        configured_dns_ip: mgr.configured_dns_ip().map(|s| s.to_string()),
        dns_method: mgr.dns_method().map(|s| s.to_string()),
        exit_country: mgr.exit_country().map(|s| s.to_string()),
        tx_bytes: bw.tx(),
        rx_bytes: bw.rx(),
        started_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(uptime_secs),
    };

    ipc::Response::Status {
        state: Box::new(state),
        uptime_secs,
    }
}

fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {minutes}m {seconds}s")
    } else if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

fn print_state_details(state: &state::VpnState, state_file: &std::path::Path) {
    println!("TUN device: {}", state.tun_name);
    println!(
        "Original gateway: {} ({})",
        state.original_gateway, state.original_interface
    );

    if state.guard_ips.is_empty() {
        println!("Guard IPs: (none)");
    } else {
        println!(
            "Guard IPs: {}",
            state
                .guard_ips
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if !state.bypass_cidrs.is_empty() {
        println!("Bypass CIDRs: {}", state.bypass_cidrs.join(", "));
    }

    if let Some(ref dns_ip) = state.configured_dns_ip {
        println!("DNS override: {dns_ip}");
        if let Some(ref method) = state.dns_method {
            println!("DNS method: {method}");
        }
        if let Some(ref service) = state.dns_service_name {
            println!("DNS service: {service}");
        }
        if let Some(ref original) = state.original_dns {
            println!(
                "Original DNS: {}",
                original.lines().collect::<Vec<_>>().join(", ")
            );
        }
    } else {
        println!("DNS override: disabled");
    }

    if state.tx_bytes > 0 || state.rx_bytes > 0 {
        println!(
            "Traffic: {} received, {} sent",
            bandwidth::format_bytes(state.rx_bytes),
            bandwidth::format_bytes(state.tx_bytes),
        );
    }

    println!("State file: {}", state_file.display());
}

/// Reset signal dispositions and mask inherited from the parent process.
///
/// When launched via macOS `do shell script ... with administrator privileges`,
/// the parent shell (`/bin/sh` = zsh) may set SIGTERM to `SIG_IGN` before exec.
/// Signal dispositions persist across `exec()`, so tokio's signal handler
/// registration sees `SIG_IGN` and the signal is never delivered. Resetting
/// to `SIG_DFL` before tokio registers its handlers fixes this.
#[cfg(unix)]
fn reset_signal_state() {
    use nix::sys::signal::{self, SigAction, SigHandler, SigSet, SigmaskHow, Signal};

    // Clear signal mask — unblock all signals
    let empty = SigSet::empty();
    let _ = signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&empty), None);

    // Reset SIGTERM and SIGUSR1 to default disposition (overrides inherited SIG_IGN)
    let default_action = SigAction::new(
        SigHandler::SigDfl,
        signal::SaFlags::empty(),
        SigSet::empty(),
    );
    unsafe {
        let _ = signal::sigaction(Signal::SIGTERM, &default_action);
        let _ = signal::sigaction(Signal::SIGUSR1, &default_action);
    }
}

fn run_start(config: Config) -> anyhow::Result<()> {
    // Reset signal state inherited from parent process. When launched via macOS
    // `do shell script ... with administrator privileges`, the parent shell (zsh)
    // may leave SIGTERM/SIGUSR1 as SIG_IGN or blocked. Signal dispositions and
    // masks persist across exec(), preventing tokio handlers from firing.
    #[cfg(unix)]
    reset_signal_state();

    ensure_elevated("start")?;

    // Prevent running two instances simultaneously — second instance would
    // overwrite routes and state file, breaking the first one.
    if let Some(existing) = state::load(&config.state_file)? {
        if state::is_tor_vpn_process(existing.pid) {
            anyhow::bail!(
                "tor-vpn is already running (PID {}). Stop it first or use `tor-vpn refresh` to refresh circuits.",
                existing.pid
            );
        }
    }

    // Auto-recover from previous SIGKILL before starting new session.
    // Abort on partial cleanup failure — starting on top of stale routes/DNS
    // would overwrite the only recovery state, making manual cleanup impossible.
    match routing::cleanup_orphaned(&config.state_file) {
        Ok(true) => {
            tracing::warn!("Cleaned up orphaned routes from a previous crash");
            std::thread::sleep(Duration::from_secs(1));
        }
        Ok(false) => {}
        Err(e) => {
            anyhow::bail!(
                "Cannot start: {e}. Run `sudo tor-vpn cleanup` to resolve, then try again."
            );
        }
    }

    // Install panic hook once — token is swapped each session
    let panic_cancel: Arc<Mutex<CancellationToken>> =
        Arc::new(Mutex::new(CancellationToken::new()));
    shutdown::install_panic_hook_shared(Arc::clone(&panic_cancel));

    tracing::info!("Starting tor-vpn...");

    let has_bridges = !config.bridges.is_empty();
    let mut warmup_failures = 0u32;
    let mut cached_session: Option<CachedSession> = None;

    loop {
        // Fresh runtime per session: dropping it force-cancels arti's internal
        // background tasks, releasing the state/directory lock for the next session.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let result = rt.block_on(run_vpn_session(
            &config,
            &panic_cancel,
            cached_session.as_ref(),
        ));

        // Drop runtime — kills ALL spawned tasks (including arti internals),
        // which closes their file descriptors and releases the state lock.
        drop(rt);

        match result {
            Ok((SessionOutcome::Shutdown, _)) => break,
            Ok((SessionOutcome::Restart, cache)) => {
                // Non-warmup restart (wake-from-sleep, bootstrap watcher)
                cached_session = cache;
                warmup_failures = 0;
                tracing::info!("Restarting VPN session...");
                // Brief pause for macOS WiFi re-establishment after wake
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            Ok((SessionOutcome::WarmupFailed, _)) => {
                cached_session = None;
                if !has_bridges {
                    // Should not happen, but handle gracefully
                    tracing::warn!("Unexpected warmup failure without bridges");
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
                warmup_failures += 1;
                if warmup_failures > 8 {
                    anyhow::bail!(
                        "Bridge connection failed after {warmup_failures} attempts. \
                         Check bridge configuration and connectivity."
                    );
                }
                // Jitter: 8-12s to avoid thundering herd on concurrent retries
                let jitter_secs = 8
                    + (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_millis() as u64
                        % 5);
                tracing::warn!(
                    "Bridge warmup failed (attempt {warmup_failures}/8), retrying in {jitter_secs}s..."
                );
                std::thread::sleep(Duration::from_secs(jitter_secs));
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "VPN session failed");
                return Err(e);
            }
        }
    }

    tracing::info!("tor-vpn stopped. Routes restored.");
    Ok(())
}

/// Run a single VPN session (TUN → Tor → routes → handlers → wait → cleanup).
///
/// Returns `Shutdown`/`Restart`/`WarmupFailed` along with cached session state
/// that can be reused on the next restart to skip gateway detection and
/// install guard routes immediately.
async fn run_vpn_session(
    config: &Config,
    panic_cancel: &Arc<Mutex<CancellationToken>>,
    cached: Option<&CachedSession>,
) -> anyhow::Result<(SessionOutcome, Option<CachedSession>)> {
    let session_start = std::time::Instant::now();

    // --- Phase 1: Create NetworkController (detect original gateway before any changes) ---
    let tun_name_for_routes = config.tun_name.clone();
    let bypass_cidrs = config.bypass_cidrs.clone();
    let mut net_ctrl = if let Some(cache) = cached {
        routing::NetworkController::new_with_hint(
            tun_name_for_routes,
            bypass_cidrs,
            config.state_file.clone(),
            cache.gateway_ip,
            &cache.interface,
            cache.if_index,
        )?
    } else {
        routing::NetworkController::new(
            tun_name_for_routes,
            bypass_cidrs,
            config.state_file.clone(),
        )?
    };

    // --- Phase 2: Create TUN device ---
    let device = tun::create_tun_device(config)?;
    let actual_tun_name = device.name().unwrap_or_else(|_| config.tun_name.clone());

    // Update route manager with actual TUN name (important on macOS where it's auto-assigned)
    if actual_tun_name != config.tun_name {
        tracing::info!(
            requested = %config.tun_name,
            actual = %actual_tun_name,
            "TUN name differs from requested — updating route manager"
        );
        net_ctrl.set_tun_name(actual_tun_name.clone());
    }

    net_ctrl.set_exit_country(config.exit_country.clone());

    // --- Phase 3: Bootstrap Tor (BEFORE installing routes, so Tor connects directly) ---
    let tor_manager = Arc::new(
        tor::TorManager::new(
            config.isolation.clone(),
            &config.cache_dir,
            config.exit_country.as_deref(),
            &config.bridges,
            &config.pt_paths,
        )
        .await?,
    );

    let has_pt_bridges = !tor_manager.resolved_pt_paths().is_empty();

    // --- Phase 4+5: Warmup, detect guards, install routes ---
    // Windows: DNS override disabled — Windows DNS Client blocks .onion at the API
    // level (RFC 7686) regardless of system DNS settings, and netsh DNS changes are
    // fragile (don't auto-revert on crash). Regular DNS queries go through the TUN
    // device and are resolved via Tor without needing system DNS changes.
    #[cfg(target_os = "windows")]
    let dns_ip: Option<std::net::Ipv4Addr> = None;
    #[cfg(not(target_os = "windows"))]
    let dns_ip = if config.override_dns {
        Some(derive_dns_ip(config.tun_address, config.tun_netmask)?)
    } else {
        None
    };
    let dns_ip_str = dns_ip
        .as_ref()
        .map(|ip: &std::net::Ipv4Addr| ip.to_string());

    if let Some(cache) = cached {
        if !cache.guard_ips.is_empty() {
            // Install routes immediately with cached guard IPs
            net_ctrl.set_guard_ips(cache.guard_ips.clone());
            net_ctrl.install_routes(dns_ip_str.as_deref())?;
        }
    }
    let routes_pre_installed = net_ctrl.routes_installed();

    // Fire warmup resolve in background — don't block guard IP polling.
    if has_pt_bridges {
        tracing::info!("Warming up Tor circuits through PT bridge...");
    } else {
        tracing::debug!("Warming up Tor circuits...");
    }
    let warmup_tor = Arc::clone(&tor_manager);
    let warmup_handle =
        tokio::spawn(async move { warmup_tor.resolve_dns("www.gstatic.com").await });

    // Poll for guard IPs concurrently with warmup (1s intervals, 30s window).
    let guard_ips = {
        let mut detected = Vec::new();
        for attempt in 1..=30u32 {
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Every 5s, fire another resolve to stimulate circuit building
            if attempt % 5 == 0 && attempt < 25 {
                let tor_clone = Arc::clone(&tor_manager);
                let domain = tor::PROBE_DOMAINS[attempt as usize / 5 % tor::PROBE_DOMAINS.len()];
                tokio::spawn(async move {
                    let _ = tor_clone.resolve_dns(domain).await;
                });
            }

            let detection = if has_pt_bridges {
                let pt_paths = tor_manager.resolved_pt_paths().to_vec();
                tokio::task::spawn_blocking(move || routing::detect_pt_external_ips(&pt_paths))
                    .await
            } else {
                tokio::task::spawn_blocking(routing::detect_guard_ips).await
            };

            match detection {
                Ok(Ok(ips)) if !ips.is_empty() => {
                    detected = ips;
                    break;
                }
                Ok(Ok(_)) => {
                    if attempt % 5 == 0 {
                        tracing::debug!(attempt, "No guard connections yet, continuing...");
                    }
                }
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "Guard IP detection failed");
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Guard IP detection task panicked");
                    break;
                }
            }
        }

        // Fallback: extract relay IPs from bridge lines when detection returns empty.
        if detected.is_empty() && !config.bridges.is_empty() {
            detected = parse_bridge_ips(&config.bridges);
            if !detected.is_empty() {
                tracing::info!(
                    "Using bridge relay IPs as fallback bypass routes: {:?}",
                    detected
                );
            }
        }

        detected
    };

    // Check warmup result for PT bridge failure detection
    match warmup_handle.await {
        Ok(Ok(_)) if has_pt_bridges => tracing::info!("PT bridge circuit established"),
        Ok(Ok(_)) => tracing::debug!("Tor circuit warmup successful"),
        Ok(Err(e)) if has_pt_bridges => {
            tracing::warn!(error = %e, "PT bridge circuit warmup failed");
            return Ok((SessionOutcome::WarmupFailed, None));
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "Tor circuit warmup failed — guard detection may be incomplete");
        }
        Err(e) => {
            tracing::warn!(error = %e, "Warmup task panicked");
        }
    }

    if guard_ips.is_empty() {
        tracing::warn!("No guard IPs detected — guard traffic may be tunneled through itself");
    }

    // Install or update routes with detected guard IPs
    if routes_pre_installed {
        for ip in &guard_ips {
            if let Err(e) = net_ctrl.add_guard_ip(*ip) {
                tracing::warn!(ip = %ip, error = %e, "Failed to add new guard bypass route");
            }
        }
    } else {
        net_ctrl.set_guard_ips(guard_ips);
        net_ctrl.install_routes(dns_ip_str.as_deref())?;
    }

    // --- Phase 5b: Verify Tor circuits work through new routes ---
    {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<&str>(1);

        for domain in tor::PROBE_DOMAINS {
            let tor_clone = Arc::clone(&tor_manager);
            let tx = tx.clone();
            tokio::spawn(async move {
                if tor_clone
                    .resolve_quick(domain, Duration::from_secs(5))
                    .await
                    .is_ok()
                {
                    let _ = tx.send(domain).await;
                }
            });
        }
        drop(tx);

        match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
            Ok(Some(domain)) => {
                tracing::debug!(domain, "Post-route circuit verification succeeded");
            }
            _ => {
                tracing::warn!(
                    "Post-route circuit verification failed — first few DNS queries may fail"
                );
            }
        }
    }

    // Wrap in Arc<Mutex> for sharing with the guard monitor task
    let net_ctrl = Arc::new(Mutex::new(net_ctrl));

    // --- Phase 6: Start netstack ---
    let cancel = CancellationToken::new();

    // Update panic hook to cancel this session's token
    {
        let mut guard = panic_cancel.lock().unwrap_or_else(|p| p.into_inner());
        *guard = cancel.clone();
    }

    let netstack_handle = netstack::start_netstack(device, cancel.clone())?;

    // --- Phase 7: Start handlers ---
    let onion_map: OnionMap = dns::new_onion_map();
    let dns_cache: DnsCache = dns::new_dns_cache(config.dns_cache_ttl);
    let bw = Arc::new(bandwidth::BandwidthStats::new());

    #[cfg(target_os = "windows")]
    if config.override_dns {
        tracing::warn!(
            "--override-dns has no effect on Windows — \
             the Windows DNS Client blocks .onion queries per RFC 7686 at the API level"
        );
    }

    let restart_notify = Arc::new(tokio::sync::Notify::new());

    let handler_ctx = dns::HandlerCtx {
        tor: Arc::clone(&tor_manager),
        onion_map: Arc::clone(&onion_map),
        dns_cache: Arc::clone(&dns_cache),
        dns_cache_ttl: config.dns_cache_ttl,
        stats: Arc::clone(&bw),
        cancel: cancel.clone(),
    };

    let tcp_ctx = handler_ctx.clone();
    let max_connections = config.max_connections;
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp_handler(netstack_handle.tcp_listener, tcp_ctx, max_connections).await;
    });

    let dns_ctx = handler_ctx;
    let max_dns_queries = config.max_dns_queries;
    let dns_handle = tokio::spawn(async move {
        dns::run_dns_handler(netstack_handle.udp_socket, dns_ctx, max_dns_queries).await;
    });

    // --- Phase 7b: Start guard relay monitor ---
    let monitor_cancel = cancel.clone();
    let monitor_rm = Arc::clone(&net_ctrl);
    let monitor_pt_paths = if has_pt_bridges {
        Some(tor_manager.resolved_pt_paths().to_vec())
    } else {
        None
    };
    let monitor_handle = tokio::spawn(routing::run_guard_monitor(
        monitor_rm,
        monitor_pt_paths,
        monitor_cancel,
    ));

    // --- Phase 7c: Start Tor bootstrap watcher ---
    let health_cancel = cancel.clone();
    let health_tor = Arc::clone(&tor_manager);
    let health_dns_cache = Arc::clone(&dns_cache);
    let health_restart = Arc::clone(&restart_notify);
    let health_handle = tokio::spawn(tor::run_bootstrap_watcher(
        health_tor,
        health_dns_cache,
        health_restart,
        health_cancel,
    ));

    // --- Phase 7d: Start wake-from-sleep detector ---
    let wake_cancel = cancel.clone();
    let wake_restart = Arc::clone(&restart_notify);
    let wake_handle = tokio::spawn(run_wake_detector(wake_restart, wake_cancel));

    // --- Phase 7e: IPC control server ---
    let (ipc_tx, mut ipc_rx) = tokio::sync::mpsc::channel::<IpcCommand>(8);
    let ipc_socket = config.socket_path.clone();
    let ipc_cancel = cancel.clone();
    let ipc_path = ipc_socket.clone();
    let owner_uid = ipc::detect_owner_uid();
    let ipc_handle = tokio::spawn(ipc::run_ipc_server(ipc_path, ipc_tx, ipc_cancel, owner_uid));
    tracing::info!(path = %ipc_socket.display(), "IPC control socket created");

    tracing::info!(
        tun = %actual_tun_name,
        "tor-vpn is running — all traffic is routed through Tor"
    );
    tracing::info!(
        "Press Ctrl+C to stop. Use `tor-vpn stop/status/refresh` or SIGUSR1 to refresh circuits."
    );

    // --- Phase 8: Wait for shutdown signal, restart request, or circuit refresh ---
    #[cfg(unix)]
    let mut sigusr1 = shutdown::sigusr1_stream();
    let mut shutdown = std::pin::pin!(shutdown::shutdown_signal());
    let mut stats_interval =
        tokio::time::interval(Duration::from_secs(config.state_write_interval as u64));
    stats_interval.tick().await; // consume the first immediate tick

    // Track last-written bandwidth to skip redundant state file writes
    let mut last_written_tx: u64 = 0;
    let mut last_written_rx: u64 = 0;

    let flush_bandwidth = |last_tx: &mut u64, last_rx: &mut u64, force: bool| {
        let tx = bw.tx();
        let rx = bw.rx();
        if force {
            bw.log_summary();
        }
        if !force && tx == *last_tx && rx == *last_rx {
            return;
        }
        *last_tx = tx;
        *last_rx = rx;
        tokio::task::block_in_place(|| {
            if let Ok(mut mgr) = net_ctrl.lock() {
                mgr.update_bandwidth(tx, rx);
            }
        });
    };

    let outcome = loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                tracing::info!("Shutting down...");
                break SessionOutcome::Shutdown;
            }
            _ = restart_notify.notified() => {
                tracing::info!("Restart requested — tearing down session...");
                break SessionOutcome::Restart;
            }
            _ = async {
                #[cfg(unix)]
                {
                    if let Some(ref mut sig) = sigusr1 {
                        sig.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                }
                #[cfg(not(unix))]
                {
                    std::future::pending::<()>().await;
                }
            } => {
                let _ = tor_manager.refresh_circuits();
                dns_cache.invalidate_all();
                flush_bandwidth(&mut last_written_tx, &mut last_written_rx, true);
            }
            Some(cmd) = ipc_rx.recv() => {
                match cmd.request {
                    ipc::Request::Status => {
                        let s = build_ipc_status(&net_ctrl, &bw, session_start);
                        let _ = cmd.reply.send(s);
                    }
                    ipc::Request::Refresh => {
                        let msg = tor_manager.refresh_circuits();
                        dns_cache.invalidate_all();
                        flush_bandwidth(&mut last_written_tx, &mut last_written_rx, true);
                        let _ = cmd.reply.send(ipc::Response::Ok {
                            message: Some(msg.into()),
                        });
                    }
                    ipc::Request::Shutdown => {
                        let _ = cmd.reply.send(ipc::Response::Ok {
                            message: Some("Shutting down".into()),
                        });
                        // Yield to let IPC server flush the response to the client
                        tokio::task::yield_now().await;
                        break SessionOutcome::Shutdown;
                    }
                }
            }
            _ = stats_interval.tick() => {
                flush_bandwidth(&mut last_written_tx, &mut last_written_rx, false);
            }
        }
    };

    // Log final bandwidth stats and persist to state file before cleanup
    flush_bandwidth(&mut last_written_tx, &mut last_written_rx, true);

    // --- Phase 9: Cancel all tasks and cleanup ---
    cancel.cancel();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let _ = std::fs::remove_file(&ipc_socket);
    tcp_handle.abort();
    dns_handle.abort();
    monitor_handle.abort();
    health_handle.abort();
    wake_handle.abort();
    ipc_handle.abort();

    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = tcp_handle.await;
        let _ = dns_handle.await;
        let _ = monitor_handle.await;
        let _ = health_handle.await;
        let _ = wake_handle.await;
        let _ = ipc_handle.await;
    })
    .await;

    // Capture session state for caching before cleanup
    let session_cache = {
        let mgr = net_ctrl.lock().unwrap_or_else(|p| p.into_inner());
        Some(CachedSession {
            gateway_ip: mgr.original_gateway(),
            interface: mgr.original_interface().to_string(),
            if_index: mgr.original_if_index(),
            guard_ips: mgr.guard_ips().to_vec(),
        })
    };

    // Kill-switch: on restart, install blackhole routes instead of removing all routes.
    // This prevents traffic leaking through clearnet while Tor re-bootstraps.
    // On clean shutdown, remove everything as usual.
    let use_kill_switch = config.kill_switch && !matches!(outcome, SessionOutcome::Shutdown);
    let mut mgr = net_ctrl.lock().unwrap_or_else(|p| p.into_inner());

    if use_kill_switch {
        if let Err(e) = mgr.transition_to_blackhole() {
            tracing::warn!(error = %e, "Kill-switch failed, falling back to full cleanup");
            let _ = mgr.remove_routes();
        }
    } else {
        mgr.remove_routes()?;
    }

    Ok((outcome, session_cache))
}

/// Detect system wake-from-sleep by monitoring for large jumps
/// between monotonic and wall-clock time.
async fn run_wake_detector(restart_notify: Arc<tokio::sync::Notify>, cancel: CancellationToken) {
    const CHECK_INTERVAL: Duration = Duration::from_secs(5);
    const JUMP_THRESHOLD: Duration = Duration::from_secs(15);

    let mut last_wall = std::time::SystemTime::now();
    let mut last_mono = std::time::Instant::now();

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(CHECK_INTERVAL) => {}
        }

        let now_wall = std::time::SystemTime::now();
        let now_mono = std::time::Instant::now();

        let mono_elapsed = now_mono.duration_since(last_mono);
        let wall_elapsed = now_wall.duration_since(last_wall).unwrap_or(Duration::ZERO);

        if let Some(sleep_duration) = detect_time_jump(wall_elapsed, mono_elapsed, JUMP_THRESHOLD) {
            tracing::warn!(
                sleep_secs = sleep_duration.as_secs(),
                "System wake detected — requesting full restart"
            );
            restart_notify.notify_one();
            break;
        }

        last_wall = now_wall;
        last_mono = now_mono;
    }
    tracing::debug!("Wake detector stopped");
}

/// Check if wall-clock time advanced significantly more than monotonic time.
fn detect_time_jump(
    wall_elapsed: Duration,
    mono_elapsed: Duration,
    threshold: Duration,
) -> Option<Duration> {
    if wall_elapsed > mono_elapsed + threshold {
        Some(wall_elapsed.saturating_sub(mono_elapsed))
    } else {
        None
    }
}

/// Derive the DNS intercept IP from the TUN address (next IP in subnet).
#[cfg(not(target_os = "windows"))]
fn derive_dns_ip(
    tun_addr: std::net::Ipv4Addr,
    prefix_len: u8,
) -> anyhow::Result<std::net::Ipv4Addr> {
    let octets = tun_addr.octets();
    if octets[3] == 255 {
        anyhow::bail!(
            "Cannot derive DNS IP from TUN address {tun_addr}: last octet is 255 (would produce .0 network address). \
             Use a TUN address with last octet < 255."
        );
    }
    let dns_ip = std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3] + 1);

    let tun_u32 = u32::from(tun_addr);
    let dns_u32 = u32::from(dns_ip);
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };

    if (tun_u32 & mask) != (dns_u32 & mask) {
        anyhow::bail!("DNS IP {dns_ip} is outside the TUN subnet (/{prefix_len}) of {tun_addr}");
    }

    let broadcast = (tun_u32 & mask) | !mask;
    if dns_u32 == broadcast {
        anyhow::bail!("DNS IP {dns_ip} is the broadcast address for {tun_addr}/{prefix_len}");
    }

    Ok(dns_ip)
}

/// Extract relay IPv4 addresses from bridge lines for use as fallback bypass routes.
fn parse_bridge_ips(bridges: &[String]) -> Vec<std::net::IpAddr> {
    let mut ips = Vec::new();
    for line in bridges {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let host_port = if parts[0].contains(':') && !parts[0].contains('=') {
            parts[0]
        } else if parts.len() >= 2 {
            parts[1]
        } else {
            continue;
        };

        if let Some((host, _)) = host_port.rsplit_once(':') {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_time_jump_no_sleep() {
        let wall = Duration::from_secs(5);
        let mono = Duration::from_secs(5);
        let threshold = Duration::from_secs(15);
        assert!(detect_time_jump(wall, mono, threshold).is_none());
    }

    #[test]
    fn test_detect_time_jump_after_sleep() {
        let wall = Duration::from_secs(305);
        let mono = Duration::from_secs(5);
        let threshold = Duration::from_secs(15);
        let result = detect_time_jump(wall, mono, threshold);
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_secs(), 300);
    }

    #[test]
    fn test_detect_time_jump_within_threshold() {
        let wall = Duration::from_secs(6);
        let mono = Duration::from_secs(5);
        let threshold = Duration::from_secs(15);
        assert!(detect_time_jump(wall, mono, threshold).is_none());
    }

    #[test]
    fn test_detect_time_jump_exactly_at_threshold() {
        let wall = Duration::from_secs(20);
        let mono = Duration::from_secs(5);
        let threshold = Duration::from_secs(15);
        assert!(detect_time_jump(wall, mono, threshold).is_none());
    }

    #[test]
    fn test_detect_time_jump_just_over_threshold() {
        let wall = Duration::from_secs(21);
        let mono = Duration::from_secs(5);
        let threshold = Duration::from_secs(15);
        let result = detect_time_jump(wall, mono, threshold);
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_secs(), 16);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_derive_dns_ip_normal() {
        let ip = derive_dns_ip("10.200.0.1".parse().unwrap(), 24).unwrap();
        assert_eq!(ip, "10.200.0.2".parse::<std::net::Ipv4Addr>().unwrap());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_derive_dns_ip_zero() {
        let ip = derive_dns_ip("10.200.0.0".parse().unwrap(), 24).unwrap();
        assert_eq!(ip, "10.200.0.1".parse::<std::net::Ipv4Addr>().unwrap());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_derive_dns_ip_255_fails() {
        assert!(derive_dns_ip("10.200.0.255".parse().unwrap(), 24).is_err());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_derive_dns_ip_broadcast_detection() {
        assert!(derive_dns_ip("10.200.0.254".parse().unwrap(), 24).is_err());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_derive_dns_ip_slash30_valid() {
        let ip = derive_dns_ip("10.200.0.1".parse().unwrap(), 30).unwrap();
        assert_eq!(ip, "10.200.0.2".parse::<std::net::Ipv4Addr>().unwrap());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_derive_dns_ip_slash30_broadcast() {
        assert!(derive_dns_ip("10.200.0.2".parse().unwrap(), 30).is_err());
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_derive_dns_ip_crosses_subnet() {
        assert!(derive_dns_ip("10.200.0.255".parse().unwrap(), 25).is_err());
        assert!(derive_dns_ip("10.200.1.127".parse().unwrap(), 25).is_err());
    }

    #[test]
    fn test_parse_bridge_ips_obfs4() {
        let bridges = vec!["obfs4 192.0.2.1:443 AAAA cert=bbb iat-mode=0".to_string()];
        let ips = parse_bridge_ips(&bridges);
        assert_eq!(ips, vec!["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]);
    }

    #[test]
    fn test_parse_bridge_ips_direct() {
        let bridges = vec!["192.0.2.1:443 AAAA".to_string()];
        let ips = parse_bridge_ips(&bridges);
        assert_eq!(ips, vec!["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]);
    }

    #[test]
    fn test_parse_bridge_ips_multiple() {
        let bridges = vec![
            "obfs4 192.0.2.1:443 AAAA cert=bbb".to_string(),
            "webtunnel 198.51.100.5:443 BBBB url=https://cdn.example.com".to_string(),
        ];
        let ips = parse_bridge_ips(&bridges);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"192.0.2.1".parse().unwrap()));
        assert!(ips.contains(&"198.51.100.5".parse().unwrap()));
    }

    #[test]
    fn test_parse_bridge_ips_deduplicates() {
        let bridges = vec![
            "obfs4 192.0.2.1:443 AAAA cert=bbb".to_string(),
            "obfs4 192.0.2.1:9001 CCCC cert=ddd".to_string(),
        ];
        let ips = parse_bridge_ips(&bridges);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_parse_bridge_ips_empty() {
        let ips = parse_bridge_ips(&[]);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_parse_bridge_ips_ipv6_skipped_gracefully() {
        let bridges = vec!["obfs4 [2001:db8::1]:443 AAAA cert=bbb".to_string()];
        let ips = parse_bridge_ips(&bridges);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(45)), "45s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(Duration::from_secs(125)), "2m 5s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }

    #[test]
    fn test_format_duration_days() {
        assert_eq!(format_duration(Duration::from_secs(90061)), "1d 1h 1m 1s");
    }

    #[test]
    fn test_format_duration_zero() {
        assert_eq!(format_duration(Duration::from_secs(0)), "0s");
    }
}
