mod cleanup;
mod dns;
mod guard;

pub use cleanup::*;
#[cfg(target_os = "macos")]
pub use dns::get_current_dns;
pub use dns::restore_dns_settings;
pub use guard::*;

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use route_manager::Route;

/// High-level network controller: manages OS routes (via `route_manager` crate),
/// DNS configuration, and SIGKILL recovery state.
pub struct NetworkController {
    route_mgr: route_manager::RouteManager,
    original_gateway: IpAddr,
    original_interface: String,
    tun_name: String,
    guard_ips: Vec<IpAddr>,
    bypass_cidrs: Vec<String>,
    routes_installed: bool,
    original_dns: Option<String>,
    dns_service_name: Option<String>,
    /// DNS IP we configured (stored for re-application after wake).
    configured_dns_ip: Option<String>,
    /// DNS configuration method used (e.g. "resolvectl", "resolvconf", "resolv.conf").
    /// Determines how to restore DNS on cleanup.
    dns_method: Option<String>,
    /// Exit country code for UI display (not used for routing).
    exit_country: Option<String>,
    /// Path to the state file for SIGKILL recovery.
    state_file: PathBuf,
    /// Last-saved bandwidth counters (tx/rx bytes through Tor).
    tx_bytes: u64,
    rx_bytes: u64,
    /// Unix timestamp when the session started (for uptime calculation).
    started_at: u64,
}

impl NetworkController {
    /// Create a new NetworkController, detecting the current default gateway.
    /// Retries gateway detection up to 5 times (1s apart) to handle transient
    /// routing table gaps after a session restart.
    pub fn new(
        tun_name: String,
        bypass_cidrs: Vec<String>,
        state_file: PathBuf,
    ) -> anyhow::Result<Self> {
        let (gateway, interface) = detect_default_gateway_with_retry()?;
        tracing::info!(
            gateway = %gateway,
            interface = %interface,
            "Detected original default gateway"
        );

        let route_mgr = route_manager::RouteManager::new()
            .map_err(|e| anyhow::anyhow!("Failed to create route manager: {e}"))?;

        let started_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            route_mgr,
            original_gateway: gateway,
            original_interface: interface,
            tun_name,
            guard_ips: Vec::new(),
            bypass_cidrs,
            routes_installed: false,
            original_dns: None,
            dns_service_name: None,
            configured_dns_ip: None,
            dns_method: None,
            exit_country: None,
            state_file,
            tx_bytes: 0,
            rx_bytes: 0,
            started_at,
        })
    }

    /// Set the exit country code for display in the state file.
    pub fn set_exit_country(&mut self, cc: Option<String>) {
        self.exit_country = cc;
    }

    /// Create a NetworkController using a cached gateway hint.
    ///
    /// Validates the cached gateway with a single `detect_default_gateway()` call.
    /// On mismatch or failure, falls back to `detect_default_gateway_with_retry()`.
    pub fn new_with_hint(
        tun_name: String,
        bypass_cidrs: Vec<String>,
        state_file: PathBuf,
        hint_gateway: IpAddr,
        hint_interface: &str,
    ) -> anyhow::Result<Self> {
        let (gateway, interface) = match detect_default_gateway() {
            Ok((gw, iface)) if gw == hint_gateway && iface == hint_interface => {
                tracing::info!(
                    gateway = %gw,
                    interface = %iface,
                    "Reusing cached gateway (validated)"
                );
                (gw, iface)
            }
            Ok((gw, iface)) => {
                tracing::info!(
                    old_gw = %hint_gateway, old_iface = %hint_interface,
                    new_gw = %gw, new_iface = %iface,
                    "Gateway changed since last session"
                );
                (gw, iface)
            }
            Err(e) => {
                tracing::debug!(error = %e, "Gateway hint validation failed, retrying...");
                match detect_default_gateway_with_retry() {
                    Ok(result) => {
                        tracing::info!(
                            gateway = %result.0,
                            interface = %result.1,
                            "Detected original default gateway (hint validation failed)"
                        );
                        result
                    }
                    Err(_) => {
                        // Gateway undetectable — likely kill-switch blackhole routes
                        // are shadowing the default route. Temporarily remove them
                        // so we can detect the real gateway (important if the laptop
                        // woke up on a different network with a new gateway).
                        tracing::info!("Removing kill-switch routes for gateway detection...");
                        remove_ipv4_blackhole_routes_cli();

                        let detected = detect_default_gateway_with_retry();

                        // Reinstall blackhole immediately — keep traffic blocked
                        // while Tor re-bootstraps. Best-effort: if this fails the
                        // new session's install_routes() will clean up anyway.
                        let _ = add_ipv4_blackhole_routes_cli();

                        match detected {
                            Ok(result) => {
                                tracing::info!(
                                    gateway = %result.0,
                                    interface = %result.1,
                                    "Detected gateway after removing kill-switch routes"
                                );
                                result
                            }
                            Err(retry_err) => {
                                // Network genuinely unavailable (WiFi not ready yet).
                                // Trust the cached hint — the next bootstrap watcher
                                // restart will re-detect once the network is up.
                                tracing::info!(
                                    gateway = %hint_gateway,
                                    interface = %hint_interface,
                                    error = %retry_err,
                                    "Network unavailable, trusting cached gateway hint"
                                );
                                (hint_gateway, hint_interface.to_string())
                            }
                        }
                    }
                }
            }
        };

        let route_mgr = route_manager::RouteManager::new()
            .map_err(|e| anyhow::anyhow!("Failed to create route manager: {e}"))?;

        let started_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            route_mgr,
            original_gateway: gateway,
            original_interface: interface,
            tun_name,
            guard_ips: Vec::new(),
            bypass_cidrs,
            routes_installed: false,
            original_dns: None,
            dns_service_name: None,
            configured_dns_ip: None,
            dns_method: None,
            exit_country: None,
            state_file,
            tx_bytes: 0,
            rx_bytes: 0,
            started_at,
        })
    }

    /// Persist current route state to disk for recovery after SIGKILL.
    /// Best-effort: logs a warning on failure but does not propagate the error.
    fn save_state(&self) {
        state::save(
            &state::VpnState {
                pid: std::process::id(),
                tun_name: self.tun_name.clone(),
                original_gateway: self.original_gateway.to_string(),
                original_interface: self.original_interface.clone(),
                guard_ips: self.guard_ips.clone(),
                bypass_cidrs: self.bypass_cidrs.clone(),
                dns_service_name: self.dns_service_name.clone(),
                original_dns: self.original_dns.clone(),
                configured_dns_ip: self.configured_dns_ip.clone(),
                dns_method: self.dns_method.clone(),
                exit_country: self.exit_country.clone(),
                tx_bytes: self.tx_bytes,
                rx_bytes: self.rx_bytes,
                started_at: self.started_at,
            },
            &self.state_file,
        );
    }

    /// Remove the state file after successful route cleanup.
    fn delete_state_file(&self) {
        state::delete_file(&self.state_file);
    }

    /// Update bandwidth counters in the state file (called periodically by the daemon).
    pub fn update_bandwidth(&mut self, tx: u64, rx: u64) {
        self.tx_bytes = tx;
        self.rx_bytes = rx;
        self.save_state();
    }

    /// Set guard relay IPs (must be called after Tor bootstrap).
    pub fn set_guard_ips(&mut self, ips: Vec<IpAddr>) {
        tracing::info!(count = ips.len(), "Guard relay IPs detected");
        for ip in &ips {
            tracing::debug!(ip = %ip, "Guard relay");
        }
        self.guard_ips = ips;
    }

    /// Get the original gateway IP (for caching across sessions).
    pub fn original_gateway(&self) -> IpAddr {
        self.original_gateway
    }

    /// Get the original interface name (for caching across sessions).
    pub fn original_interface(&self) -> &str {
        &self.original_interface
    }

    /// Get the current guard IPs (for caching across sessions).
    pub fn guard_ips(&self) -> &[IpAddr] {
        &self.guard_ips
    }

    /// Whether routes are currently installed.
    pub fn routes_installed(&self) -> bool {
        self.routes_installed
    }

    /// Get the TUN device name.
    pub fn tun_name(&self) -> &str {
        &self.tun_name
    }

    /// Get the bypass CIDRs.
    pub fn bypass_cidrs(&self) -> &[String] {
        &self.bypass_cidrs
    }

    /// Get the DNS service name (macOS).
    pub fn dns_service_name(&self) -> Option<&str> {
        self.dns_service_name.as_deref()
    }

    /// Get the original DNS configuration.
    pub fn original_dns(&self) -> Option<&str> {
        self.original_dns.as_deref()
    }

    /// Get the configured DNS IP.
    pub fn configured_dns_ip(&self) -> Option<&str> {
        self.configured_dns_ip.as_deref()
    }

    /// Get the DNS method used.
    pub fn dns_method(&self) -> Option<&str> {
        self.dns_method.as_deref()
    }

    /// Get the exit country code.
    pub fn exit_country(&self) -> Option<&str> {
        self.exit_country.as_deref()
    }

    /// Update the TUN device name (e.g. when macOS auto-assigns a different utun).
    pub fn set_tun_name(&mut self, name: String) {
        self.tun_name = name;
    }

    /// Add a new guard IP bypass route if not already tracked.
    /// Returns `true` if the IP was new and a route was added.
    pub fn add_guard_ip(&mut self, ip: IpAddr) -> anyhow::Result<bool> {
        if self.guard_ips.contains(&ip) {
            return Ok(false);
        }
        if self.routes_installed {
            self.add_host_route(&ip)?;
        }
        self.guard_ips.push(ip);
        if self.routes_installed {
            self.save_state();
        }
        Ok(true)
    }

    /// Install all routes: guard bypasses, catch-all through TUN, optional DNS configuration.
    ///
    /// Idempotent — safe to call again (e.g., after wake from sleep wipes routes).
    /// On first call, `dns_ip` controls DNS setup. On subsequent calls the stored
    /// `configured_dns_ip` is used automatically.
    ///
    /// Sets `routes_installed = true` before starting so that `Drop` will clean up
    /// any partially-installed routes if an error occurs mid-way.
    pub fn install_routes(&mut self, dns_ip: Option<&str>) -> anyhow::Result<()> {
        tracing::info!("Installing routes...");

        // Mark early so Drop cleans up partial routes on error
        self.routes_installed = true;

        // Store dns_ip on first call for future reinstalls
        if let Some(ip) = dns_ip {
            if self.configured_dns_ip.is_none() {
                self.configured_dns_ip = Some(ip.to_string());
            }
        }

        // 1. Add /32 host routes for guard IPs through original gateway
        // Clone to avoid borrow conflict with &mut self
        let guard_ips = self.guard_ips.clone();
        for ip in &guard_ips {
            self.add_host_route(ip)?;
        }

        // 2. Add bypass CIDRs through original gateway
        let bypass_cidrs = self.bypass_cidrs.clone();
        for cidr in &bypass_cidrs {
            self.add_cidr_route(cidr)?;
        }

        // 3. Remove any lingering IPv4 blackhole routes from a previous session restart.
        //    Must happen before installing TUN catch-all (same prefix, different target).
        remove_ipv4_blackhole_routes_cli();

        // 4. Add catch-all routes through TUN (more specific than default but less than /32)
        self.add_catchall_routes()?;

        // 4. Block IPv6 to prevent traffic leaks outside Tor
        // Best-effort: if IPv6 is disabled at kernel level, this is a harmless no-op
        if let Err(e) = add_ipv6_blackhole_routes_cli() {
            tracing::warn!(error = %e, "Failed to install IPv6 blackhole routes (IPv6 may be disabled)");
        }

        // 5. Configure system DNS to force plain DNS (prevents browser DoH upgrades)
        if let Some(ip) = dns_ip {
            self.configure_dns(ip)?;
        } else if self.configured_dns_ip.is_none() {
            tracing::info!(
                "System DNS unchanged (use --override-dns for .onion support in browsers)"
            );
        }

        self.save_state();
        tracing::info!("Routes installed successfully");
        Ok(())
    }

    /// Remove all installed routes and restore DNS.
    ///
    /// Collects errors from each operation and only deletes the state file
    /// if all operations succeeded. On partial failure, the state file is
    /// preserved so `sudo tor-vpn cleanup` can retry.
    pub fn remove_routes(&mut self) -> anyhow::Result<()> {
        if !self.routes_installed {
            return Ok(());
        }

        tracing::info!("Removing routes...");
        let mut errors = Vec::new();

        // Restore DNS first
        if let Err(e) = self.restore_dns() {
            errors.push(format!("DNS restore: {e}"));
        }

        // Remove catch-all routes (best-effort — may already be gone if TUN was destroyed)
        self.remove_catchall_routes();

        // Remove IPv6 blackhole routes
        if let Err(e) = remove_ipv6_blackhole_routes_cli() {
            errors.push(format!("IPv6 blackhole routes: {e}"));
        }

        // Remove IPv4 blackhole routes (may be present from kill-switch transition)
        remove_ipv4_blackhole_routes_cli();

        // Remove bypass CIDRs
        let bypass_cidrs = self.bypass_cidrs.clone();
        for cidr in &bypass_cidrs {
            if let Err(e) = self.remove_cidr_route(cidr) {
                errors.push(format!("bypass CIDR {cidr}: {e}"));
            }
        }

        // Remove guard IP routes
        let guard_ips = self.guard_ips.clone();
        for ip in &guard_ips {
            if let Err(e) = self.remove_host_route(ip) {
                errors.push(format!("guard route {ip}: {e}"));
            }
        }

        self.routes_installed = false;

        if errors.is_empty() {
            self.delete_state_file();
            tracing::info!("Routes removed");
            Ok(())
        } else {
            for err in &errors {
                tracing::warn!("Cleanup error: {err}");
            }
            tracing::warn!("Partial cleanup — state file preserved for `sudo tor-vpn cleanup`");
            Err(anyhow::anyhow!(
                "Partial cleanup: {} operation(s) failed — state file preserved",
                errors.len()
            ))
        }
    }

    /// Switch from TUN catch-all routes to blackhole kill-switch routes.
    ///
    /// Called on session restart instead of `remove_routes()` to prevent traffic
    /// leaking through the original default route while Tor re-bootstraps.
    ///
    /// Keeps guard /32 routes (Tor can reconnect), bypass CIDRs, and IPv6 blackhole.
    /// Replaces TUN catch-all with IPv4 blackhole/reject. Restores DNS (Tor needs
    /// system DNS for bootstrap, and our TUN-based DNS is about to be destroyed).
    ///
    /// Sets `routes_installed = false` so `Drop` won't double-clean.
    /// The next session's `install_routes()` removes the blackhole before installing TUN routes.
    pub fn transition_to_blackhole(&mut self) -> anyhow::Result<()> {
        if !self.routes_installed {
            return Ok(());
        }

        tracing::info!("Installing kill-switch routes for session restart...");

        // 1. Remove TUN catch-all (will die anyway when TUN is destroyed, but
        //    remove explicitly to avoid conflicting with blackhole routes)
        self.remove_catchall_routes();

        // 2. Install blackhole catch-all — all non-guard traffic is now dropped
        add_ipv4_blackhole_routes_cli()?;

        // 3. Restore DNS — Tor needs working DNS for bootstrap, and our
        //    TUN-based DNS intercept is about to be destroyed with the TUN device
        if let Err(e) = self.restore_dns() {
            tracing::warn!(error = %e, "Failed to restore DNS during kill-switch transition");
        }

        // 4. Guard /32 routes stay — Tor can reach guard relays
        // 5. Bypass CIDR routes stay — user's bypass traffic still works
        // 6. IPv6 blackhole stays — no IPv6 leaks

        // Mark as not installed so Drop won't try to clean up.
        // Stale guard/bypass routes are harmless (unused bypass routes for old IPs).
        // The new session's install_routes() will set up fresh routes.
        self.routes_installed = false;

        tracing::info!("Kill-switch active — only Tor guard traffic allowed until reconnect");
        Ok(())
    }

    /// Configure system DNS to use our intercept IP.
    /// Required so browsers use plain DNS (port 53) instead of DoH,
    /// which ensures .onion queries reach our DNS handler.
    /// Idempotent: only saves original DNS on first call so reinstalls don't
    /// overwrite it with our own configured value.
    fn configure_dns(&mut self, dns_ip: &str) -> anyhow::Result<()> {
        #[cfg(target_os = "macos")]
        {
            let service = if let Some(s) = &self.dns_service_name {
                s.clone()
            } else {
                // Try interface-based lookup first (exact match), fall back to heuristic
                let s = dns::detect_network_service_for_interface(&self.original_interface)
                    .ok_or(())
                    .or_else(|()| dns::detect_network_service().map_err(|_| ()))
                    .map_err(|()| anyhow::anyhow!("No network service found"))?;
                self.dns_service_name = Some(s.clone());
                s
            };

            // Only save original DNS on first call
            if self.original_dns.is_none() {
                self.original_dns = Some(dns::get_current_dns(&service)?);
            }

            dns::set_dns_via_sc(&service, Some(&[dns_ip]))?;
            tracing::info!(service = %service, dns = dns_ip, "DNS configured");
        }

        #[cfg(target_os = "linux")]
        {
            // Try resolvectl (systemd-resolved) — per-interface DNS,
            // auto-reverts when TUN interface is destroyed (SIGKILL-safe).
            if dns::configure_resolvectl_dns(&self.tun_name, dns_ip) {
                self.dns_method = Some("resolvectl".to_string());
                tracing::info!(
                    dns = dns_ip,
                    "DNS configured via resolvectl (systemd-resolved)"
                );
                return Ok(());
            }

            // Try resolvconf — managed DNS, cleanly removes our entry on cleanup.
            if dns::configure_resolvconf_dns(&self.tun_name, dns_ip) {
                self.dns_method = Some("resolvconf".to_string());
                tracing::info!(dns = dns_ip, "DNS configured via resolvconf");
                return Ok(());
            }

            // Fallback: direct /etc/resolv.conf write
            if self.original_dns.is_none() {
                self.original_dns =
                    Some(std::fs::read_to_string("/etc/resolv.conf").map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to backup /etc/resolv.conf (cannot safely override DNS): {e}"
                        )
                    })?);
            }
            let content = format!("nameserver {dns_ip}\n");
            std::fs::write("/etc/resolv.conf", content)
                .map_err(|e| anyhow::anyhow!("Failed to write /etc/resolv.conf: {e}"))?;
            self.dns_method = Some("resolv.conf".to_string());
            tracing::info!(
                dns = dns_ip,
                "DNS configured via /etc/resolv.conf (direct write)"
            );
        }

        #[cfg(target_os = "windows")]
        {
            // Save original DNS on first call
            if self.original_dns.is_none() {
                self.original_dns = Some(dns::get_current_dns_windows(&self.tun_name)?);
            }

            run_cmd(
                "netsh",
                &[
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    &format!("name={}", self.tun_name),
                    "static",
                    dns_ip,
                ],
            )?;
            self.dns_method = Some("netsh".to_string());
            tracing::info!(
                tun = %self.tun_name,
                dns = dns_ip,
                "DNS configured via netsh"
            );
        }

        Ok(())
    }

    /// Restore original DNS configuration.
    fn restore_dns(&self) -> anyhow::Result<()> {
        dns::restore_dns_settings(
            self.dns_service_name.as_deref(),
            self.original_dns.as_deref(),
            self.dns_method.as_deref(),
            &self.tun_name,
        )
    }
}

impl Drop for NetworkController {
    fn drop(&mut self) {
        if self.routes_installed {
            tracing::warn!("NetworkController dropped with routes still installed — cleaning up");
            let _ = self.remove_routes();
        }
    }
}

// --- Platform-specific route operations ---

/// Detect the default gateway with retries.
/// After route removal during session restart, the OS routing table may be
/// momentarily empty. Retries up to 5 times with 1s delay.
fn detect_default_gateway_with_retry() -> anyhow::Result<(IpAddr, String)> {
    let mut last_err = None;
    for attempt in 1..=5 {
        match detect_default_gateway() {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt < 5 {
                    tracing::debug!(attempt, error = %e, "Gateway detection failed, retrying...");
                    std::thread::sleep(Duration::from_secs(1));
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap())
}

/// Detect the current default gateway and interface via `netdev` crate.
/// Uses native OS APIs (sysctl on macOS, netlink on Linux, IP Helper on Windows).
fn detect_default_gateway() -> anyhow::Result<(IpAddr, String)> {
    let iface = netdev::interface::get_default_interface()
        .map_err(|e| anyhow::anyhow!("Failed to detect default interface: {e}"))?;

    let gateway_ip = iface
        .gateway
        .as_ref()
        .and_then(|gw| gw.ipv4.first())
        .ok_or_else(|| anyhow::anyhow!("Could not detect default gateway"))?;

    Ok((IpAddr::V4(*gateway_ip), iface.name))
}

// --- Route operations via route_manager crate (native OS APIs) ---

impl NetworkController {
    /// Add a host route for a guard IP through the original gateway.
    /// Uses /32 for IPv4, /128 for IPv6 (single-host prefix for each address family).
    /// Idempotent: removes any existing route first (handles kill-switch leftovers
    /// from a previous session where guard /32 routes were intentionally preserved).
    fn add_host_route(&mut self, ip: &IpAddr) -> anyhow::Result<()> {
        let route = Route::new(*ip, host_prefix(ip)).with_gateway(self.original_gateway);
        // Best-effort delete — may not exist (normal case) or may point to a
        // different gateway (network changed after wake). Either way, ignore errors.
        let _ = self.route_mgr.delete(&route);
        self.route_mgr
            .add(&route)
            .map_err(|e| anyhow::anyhow!("Failed to add host route for {ip}: {e}"))?;
        tracing::debug!(ip = %ip, gateway = %self.original_gateway, "Added host route for guard relay");
        Ok(())
    }

    /// Remove a host route (/32 for IPv4, /128 for IPv6).
    fn remove_host_route(&mut self, ip: &IpAddr) -> anyhow::Result<()> {
        let route = Route::new(*ip, host_prefix(ip)).with_gateway(self.original_gateway);
        self.route_mgr
            .delete(&route)
            .map_err(|e| anyhow::anyhow!("Failed to remove host route for {ip}: {e}"))?;
        Ok(())
    }

    /// Add a CIDR route through the original gateway.
    /// Idempotent: removes any existing route first (handles kill-switch leftovers).
    fn add_cidr_route(&mut self, cidr: &str) -> anyhow::Result<()> {
        let parsed: cidr::IpCidr = cidr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid CIDR '{cidr}': {e}"))?;
        let route = Route::new(parsed.first_address(), parsed.network_length())
            .with_gateway(self.original_gateway);
        let _ = self.route_mgr.delete(&route);
        self.route_mgr
            .add(&route)
            .map_err(|e| anyhow::anyhow!("Failed to add CIDR route {cidr}: {e}"))?;
        tracing::debug!(cidr = cidr, "Added bypass route");
        Ok(())
    }

    /// Remove a CIDR route.
    fn remove_cidr_route(&mut self, cidr: &str) -> anyhow::Result<()> {
        let parsed: cidr::IpCidr = cidr
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid CIDR '{cidr}': {e}"))?;
        let route = Route::new(parsed.first_address(), parsed.network_length())
            .with_gateway(self.original_gateway);
        self.route_mgr
            .delete(&route)
            .map_err(|e| anyhow::anyhow!("Failed to remove CIDR route {cidr}: {e}"))?;
        Ok(())
    }

    /// Add catch-all routes through the TUN device.
    /// Uses 0.0.0.0/1 and 128.0.0.0/1 which together cover all IPv4 space
    /// but are less specific than /32 guard routes.
    fn add_catchall_routes(&mut self) -> anyhow::Result<()> {
        let r1 = Route::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 1)
            .with_if_name(self.tun_name.clone());
        let r2 = Route::new(IpAddr::V4(std::net::Ipv4Addr::new(128, 0, 0, 0)), 1)
            .with_if_name(self.tun_name.clone());
        self.route_mgr
            .add(&r1)
            .map_err(|e| anyhow::anyhow!("Failed to add catch-all route 0.0.0.0/1: {e}"))?;
        self.route_mgr
            .add(&r2)
            .map_err(|e| anyhow::anyhow!("Failed to add catch-all route 128.0.0.0/1: {e}"))?;
        tracing::debug!(tun = %self.tun_name, "Catch-all routes installed");
        Ok(())
    }

    /// Remove catch-all routes (best-effort — routes may already be gone if TUN was destroyed).
    fn remove_catchall_routes(&mut self) {
        let r1 = Route::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 1)
            .with_if_name(self.tun_name.clone());
        let r2 = Route::new(IpAddr::V4(std::net::Ipv4Addr::new(128, 0, 0, 0)), 1)
            .with_if_name(self.tun_name.clone());
        let _ = self.route_mgr.delete(&r1);
        let _ = self.route_mgr.delete(&r2);
    }
}

/// Install IPv6 blackhole/reject routes to prevent IPv6 traffic leaking outside Tor.
/// Uses ::/1 + 8000::/1 (same split-route pattern as IPv4) to avoid overriding the default route.
/// Remains as CLI because `route_manager` doesn't support reject/blackhole route types.
fn add_ipv6_blackhole_routes_cli() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_cmd("route", &["-n", "add", "-inet6", "::/1", "::1", "-reject"])?;
        run_cmd(
            "route",
            &["-n", "add", "-inet6", "8000::/1", "::1", "-reject"],
        )?;
    }

    #[cfg(target_os = "linux")]
    {
        run_cmd("ip", &["-6", "route", "add", "blackhole", "::/1"])?;
        run_cmd("ip", &["-6", "route", "add", "blackhole", "8000::/1"])?;
    }

    #[cfg(target_os = "windows")]
    {
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "route",
                "::/1",
                "interface=1",
                "store=active",
            ],
        )?;
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "route",
                "8000::/1",
                "interface=1",
                "store=active",
            ],
        )?;
    }

    tracing::debug!("IPv6 blackhole routes installed");
    Ok(())
}

/// Install IPv4 blackhole/reject routes as a kill switch during session restart.
/// Uses 0.0.0.0/1 + 128.0.0.0/1 (same split-route pattern as catch-all and IPv6 blackhole).
/// Guard /32 host routes remain active, allowing Tor to reconnect through the original gateway.
fn add_ipv4_blackhole_routes_cli() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        run_cmd(
            "route",
            &[
                "-n",
                "add",
                "-net",
                "0.0.0.0",
                "-netmask",
                "128.0.0.0",
                "127.0.0.1",
                "-reject",
            ],
        )?;
        run_cmd(
            "route",
            &[
                "-n",
                "add",
                "-net",
                "128.0.0.0",
                "-netmask",
                "128.0.0.0",
                "127.0.0.1",
                "-reject",
            ],
        )?;
    }

    #[cfg(target_os = "linux")]
    {
        run_cmd("ip", &["route", "add", "blackhole", "0.0.0.0/1"])?;
        run_cmd("ip", &["route", "add", "blackhole", "128.0.0.0/1"])?;
    }

    #[cfg(target_os = "windows")]
    {
        run_cmd(
            "netsh",
            &[
                "interface",
                "ip",
                "add",
                "route",
                "0.0.0.0/1",
                "interface=1",
                "store=active",
            ],
        )?;
        run_cmd(
            "netsh",
            &[
                "interface",
                "ip",
                "add",
                "route",
                "128.0.0.0/1",
                "interface=1",
                "store=active",
            ],
        )?;
    }

    tracing::debug!("IPv4 blackhole routes installed (kill switch)");
    Ok(())
}

/// Remove IPv4 blackhole/reject routes (best-effort, ignores errors).
fn remove_ipv4_blackhole_routes_cli() {
    #[cfg(target_os = "macos")]
    {
        let _ = run_cmd(
            "route",
            &["-n", "delete", "-net", "0.0.0.0", "-netmask", "128.0.0.0"],
        );
        let _ = run_cmd(
            "route",
            &["-n", "delete", "-net", "128.0.0.0", "-netmask", "128.0.0.0"],
        );
    }

    #[cfg(target_os = "linux")]
    {
        let _ = run_cmd("ip", &["route", "del", "blackhole", "0.0.0.0/1"]);
        let _ = run_cmd("ip", &["route", "del", "blackhole", "128.0.0.0/1"]);
    }

    #[cfg(target_os = "windows")]
    {
        let _ = run_cmd(
            "netsh",
            &[
                "interface",
                "ip",
                "delete",
                "route",
                "0.0.0.0/1",
                "interface=1",
            ],
        );
        let _ = run_cmd(
            "netsh",
            &[
                "interface",
                "ip",
                "delete",
                "route",
                "128.0.0.0/1",
                "interface=1",
            ],
        );
    }
}

/// Remove IPv6 blackhole/reject routes (best-effort, ignores errors).
/// Remains as CLI because `route_manager` doesn't support reject/blackhole route types.
fn remove_ipv6_blackhole_routes_cli() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = run_cmd("route", &["-n", "delete", "-inet6", "::/1"]);
        let _ = run_cmd("route", &["-n", "delete", "-inet6", "8000::/1"]);
    }

    #[cfg(target_os = "linux")]
    {
        let _ = run_cmd("ip", &["-6", "route", "del", "blackhole", "::/1"]);
        let _ = run_cmd("ip", &["-6", "route", "del", "blackhole", "8000::/1"]);
    }

    #[cfg(target_os = "windows")]
    {
        let _ = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "delete",
                "route",
                "::/1",
                "interface=1",
            ],
        );
        let _ = run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "delete",
                "route",
                "8000::/1",
                "interface=1",
            ],
        );
    }

    Ok(())
}

/// Create a temporary `route_manager::RouteManager` and clean up routes for orphaned state.
/// Used by `cleanup::cleanup_orphaned()` when the original `NetworkController` is gone.
/// Returns a list of error descriptions for any failed removals.
pub fn cleanup_routes(
    tun_name: &str,
    guard_ips: &[IpAddr],
    bypass_cidrs: &[String],
    original_gateway: IpAddr,
) -> Vec<String> {
    let mut errors = Vec::new();

    let mut route_mgr = match route_manager::RouteManager::new() {
        Ok(mgr) => mgr,
        Err(e) => {
            errors.push(format!("Failed to create route manager: {e}"));
            return errors;
        }
    };

    // Remove catch-all routes (best-effort — typically already gone after TUN destruction)
    let r1 = Route::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 1)
        .with_if_name(tun_name.to_string());
    let r2 = Route::new(IpAddr::V4(std::net::Ipv4Addr::new(128, 0, 0, 0)), 1)
        .with_if_name(tun_name.to_string());
    let _ = route_mgr.delete(&r1);
    let _ = route_mgr.delete(&r2);

    // Remove IPv6 blackhole routes (still CLI)
    if let Err(e) = remove_ipv6_blackhole_routes_cli() {
        errors.push(format!("IPv6 blackhole routes: {e}"));
    }

    // Remove IPv4 blackhole routes (may be present from kill-switch transition)
    remove_ipv4_blackhole_routes_cli();

    // Remove bypass CIDRs
    for cidr in bypass_cidrs {
        if let Ok(parsed) = cidr.parse::<cidr::IpCidr>() {
            let route = Route::new(parsed.first_address(), parsed.network_length())
                .with_gateway(original_gateway);
            if let Err(e) = route_mgr.delete(&route) {
                errors.push(format!("bypass CIDR {cidr}: {e}"));
            }
        } else {
            errors.push(format!("bypass CIDR {cidr}: invalid CIDR"));
        }
    }

    // Remove guard IP routes (/32 for IPv4, /128 for IPv6)
    for ip in guard_ips {
        let route = Route::new(*ip, host_prefix(ip)).with_gateway(original_gateway);
        if let Err(e) = route_mgr.delete(&route) {
            errors.push(format!("guard route {ip}: {e}"));
        }
    }

    errors
}

/// Return the host route prefix length for an IP address: /32 for IPv4, /128 for IPv6.
fn host_prefix(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// Run a command and return an error if it fails.
pub fn run_cmd(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run {cmd}: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("{cmd} {} failed: {stderr}", args.join(" ")));
    }

    Ok(())
}
