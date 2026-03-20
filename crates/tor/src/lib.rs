use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arti_client::{
    config::pt::TransportConfigBuilder,
    config::{BoolOrAuto, BridgeConfigBuilder, CfgPath, PtTransportName, TorClientConfigBuilder},
    DataStream, IsolationToken, StreamPrefs, TorClient,
};
use tokio_util::sync::CancellationToken;
use tor_geoip::CountryCode;
use tor_rtcompat::PreferredRuntime;

use config::IsolationPolicy;

/// Type alias for the DNS cache, breaking the circular dependency between tor and dns crates.
/// The dns crate has its own identical type alias.
pub type DnsCache = Arc<moka::sync::Cache<String, (Vec<Ipv4Addr>, Instant)>>;

/// Max entries for per-destination isolation token caches.
const DEST_TOKEN_MAX: u64 = 4096;
const ONION_TOKEN_MAX: u64 = 1024;
/// TTL for isolation tokens — after expiry, a new circuit will be used for the destination.
const TOKEN_TTL: Duration = Duration::from_secs(30 * 60);
/// Timeout for TCP connection establishment through Tor (circuit building + connect).
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

pub struct TorManager {
    client: TorClient<PreferredRuntime>,
    policy: IsolationPolicy,
    /// Per-destination isolation tokens (used when policy == PerDestination)
    dest_tokens: moka::sync::Cache<SocketAddr, IsolationToken>,
    /// Per-.onion isolation tokens (used when policy == PerDestination, key = "hostname:port")
    onion_tokens: moka::sync::Cache<String, IsolationToken>,
    /// Session-wide token (used when policy == Session)
    session_token: IsolationToken,
    /// Optional exit relay country preference (ISO 3166-1 alpha-2)
    exit_country: Option<CountryCode>,
    /// Resolved PT binary paths (from --pt-path or auto-detected from PATH).
    /// Used for guard IP detection — empty when no bridges/PTs are configured.
    resolved_pt_paths: Vec<(String, String)>,
}

impl TorManager {
    /// Bootstrap a new Tor client.
    ///
    /// Must be called BEFORE routes are installed so that Tor can connect
    /// to the network through the original default gateway.
    pub async fn new(
        policy: IsolationPolicy,
        cache_dir: &str,
        exit_country: Option<&str>,
        bridges: &[String],
        pt_paths: &[(String, String)],
    ) -> anyhow::Result<Self> {
        // Install the default rustls CryptoProvider (ring) before any TLS usage.
        // Ignore error if already installed (e.g. across session restarts).
        let _ = rustls::crypto::ring::default_provider().install_default();

        tracing::info!(cache_dir = %cache_dir, "Bootstrapping Tor client...");

        let state_dir = format!("{cache_dir}/state");
        let cache_path = format!("{cache_dir}/cache");

        // Ensure directories exist with correct permissions
        for dir in [&state_dir, &cache_path] {
            std::fs::create_dir_all(dir)
                .map_err(|e| anyhow::anyhow!("Failed to create directory {dir}: {e}"))?;
        }

        // When bridges are configured, clear stale guard state before bootstrap.
        // Arti's guard manager marks bridges as "down" after a timeout (~10s) and
        // persists this to {cache_dir}/state/. PT bridges (especially webtunnel) can
        // take 15-30s to connect, exceeding this timeout. Once marked "down", arti
        // refuses to retry for 30+ minutes. Deleting state/ forces fresh evaluation
        // while keeping cache/ (consensus, descriptors) intact.
        if !bridges.is_empty() {
            let state_path = std::path::Path::new(&state_dir);
            if state_path.exists() {
                if let Err(e) = std::fs::remove_dir_all(state_path) {
                    tracing::warn!(error = %e, "Failed to clear guard state");
                } else {
                    std::fs::create_dir_all(&state_dir)
                        .map_err(|e| anyhow::anyhow!("Failed to recreate state dir: {e}"))?;
                    tracing::debug!("Cleared guard state for fresh bridge evaluation");
                }
            }
        }

        let mut config_builder = TorClientConfigBuilder::from_directories(state_dir, cache_path);

        // Trust parent directories of the cache dir (e.g. /tmp which is world-writable
        // with sticky bit on macOS). Without this, Arti's fs-mistrust rejects paths
        // under /tmp when launched as root via osascript privilege escalation.
        config_builder
            .storage()
            .permissions()
            .ignore_prefix(cache_dir);

        // Arti hardcodes a 10s per-request read timeout in tor-dirclient.
        // On fresh bootstrap (~9800 microdescriptors), large batches often
        // exceed this timeout → "Partial response" / "line truncated" errors.
        // Mitigate by: more retries (each fetches only remaining missing MDs)
        // and higher parallelism (smaller batches per request).
        config_builder
            .download_schedule()
            .retry_microdescs()
            .attempts(16_u32)
            .parallelism(8_u8);

        // Configure bridges and pluggable transports (if provided)
        let mut resolved_pt_paths = Vec::new();
        if !bridges.is_empty() {
            let mut bridge_builders = Vec::new();
            let mut required_transports = std::collections::HashSet::new();

            for line in bridges {
                let bridge: BridgeConfigBuilder = line
                    .parse()
                    .map_err(|e| anyhow::anyhow!("Invalid bridge line '{line}': {e}"))?;
                if let Some(transport) = bridge.get_transport() {
                    if !transport.is_empty() {
                        required_transports.insert(transport.to_string());
                    }
                }
                bridge_builders.push(bridge);
            }

            // Configure PT binaries for required transports
            for transport_name in &required_transports {
                let path = pt_paths
                    .iter()
                    .find(|(t, _)| t == transport_name)
                    .map(|(_, p)| p.clone())
                    .or_else(|| find_in_path(transport_name))
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Bridge requires transport '{transport_name}' but no --pt-path was provided \
                             and '{transport_name}' was not found in PATH. \
                             Use --pt-path \"{transport_name}=/path/to/binary\""
                        )
                    })?;

                let pt_name: PtTransportName = transport_name.parse().map_err(|e| {
                    anyhow::anyhow!("Invalid transport name '{transport_name}': {e}")
                })?;

                tracing::info!(transport = %transport_name, path = %path, "Using PT binary");

                resolved_pt_paths.push((transport_name.clone(), path.clone()));

                let mut transport = TransportConfigBuilder::default();
                transport
                    .protocols(vec![pt_name])
                    .path(CfgPath::new_literal(&path));
                config_builder.bridges().transports().push(transport);
            }

            *config_builder.bridges().bridges() = bridge_builders;
            config_builder.bridges().enabled(BoolOrAuto::Explicit(true));

            tracing::info!(
                bridges = bridges.len(),
                transports = required_transports.len(),
                "Bridge configuration applied"
            );
        }

        let config = config_builder
            .build()
            .map_err(|e| anyhow::anyhow!("Tor config build failed: {e}"))?;

        let client = TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| anyhow::anyhow!("Tor bootstrap failed: {}", e))?;

        let exit_country = exit_country
            .map(|cc| {
                cc.parse::<CountryCode>()
                    .map_err(|e| anyhow::anyhow!("invalid exit country code '{cc}': {e}"))
            })
            .transpose()?;

        if let Some(cc) = &exit_country {
            tracing::info!(country = %cc, "Exit relay country preference set");
        }

        tracing::info!("Tor client bootstrapped successfully");

        Ok(Self {
            client,
            policy,
            dest_tokens: moka::sync::Cache::builder()
                .max_capacity(DEST_TOKEN_MAX)
                .time_to_live(TOKEN_TTL)
                .build(),
            onion_tokens: moka::sync::Cache::builder()
                .max_capacity(ONION_TOKEN_MAX)
                .time_to_live(TOKEN_TTL)
                .build(),
            session_token: IsolationToken::new(),
            exit_country,
            resolved_pt_paths,
        })
    }

    /// Apply exit country preference to StreamPrefs (if configured).
    fn apply_exit_country(&self, prefs: &mut StreamPrefs) {
        if let Some(cc) = self.exit_country {
            prefs.exit_country(cc);
        }
    }

    /// Build StreamPrefs with isolation policy applied.
    fn prefs_for_tcp(&self, dest: SocketAddr) -> StreamPrefs {
        let mut prefs = StreamPrefs::new();
        match &self.policy {
            IsolationPolicy::PerConnection => {
                prefs.new_isolation_group();
            }
            IsolationPolicy::PerDestination => {
                let token = self.dest_tokens.get_with(dest, IsolationToken::new);
                prefs.set_isolation(token);
            }
            IsolationPolicy::Session => {
                prefs.set_isolation(self.session_token);
            }
        }
        self.apply_exit_country(&mut prefs);
        prefs
    }

    /// Build StreamPrefs with isolation policy applied for .onion connections.
    fn prefs_for_onion(&self, hostname: &str, port: u16) -> StreamPrefs {
        let mut prefs = StreamPrefs::new();
        match &self.policy {
            IsolationPolicy::PerConnection => {
                prefs.new_isolation_group();
            }
            IsolationPolicy::PerDestination => {
                let key = format!("{hostname}:{port}");
                let token = self.onion_tokens.get_with(key, IsolationToken::new);
                prefs.set_isolation(token);
            }
            IsolationPolicy::Session => {
                prefs.set_isolation(self.session_token);
            }
        }
        // No exit_country for .onion — exit relay is not used
        prefs
    }

    /// Connect to a TCP destination through Tor with the configured isolation policy.
    ///
    /// Times out after 60s to prevent indefinite hangs on dead circuits,
    /// which would hold a semaphore permit and eventually exhaust the connection pool.
    pub async fn connect_tcp(&self, dest: SocketAddr) -> anyhow::Result<DataStream> {
        let host = dest.ip().to_string();
        let port = dest.port();
        let prefs = self.prefs_for_tcp(dest);

        match tokio::time::timeout(
            TCP_CONNECT_TIMEOUT,
            self.client.connect_with_prefs((&*host, port), &prefs),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(anyhow::anyhow!("Tor connect failed: {}", e)),
            Err(_) => Err(anyhow::anyhow!(
                "Tor connect to {dest} timed out after {}s",
                TCP_CONNECT_TIMEOUT.as_secs()
            )),
        }
    }

    /// Connect to an .onion hostname through Tor with the configured isolation policy.
    ///
    /// Times out after 60s to prevent indefinite hangs on dead circuits.
    pub async fn connect_onion(&self, hostname: &str, port: u16) -> anyhow::Result<DataStream> {
        tracing::debug!(hostname, port, "Connecting to .onion service");
        let prefs = self.prefs_for_onion(hostname, port);

        match tokio::time::timeout(
            TCP_CONNECT_TIMEOUT,
            self.client.connect_with_prefs((hostname, port), &prefs),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(e)) => Err(anyhow::anyhow!("Tor .onion connect failed: {}", e)),
            Err(_) => Err(anyhow::anyhow!(
                "Tor .onion connect to {hostname}:{port} timed out after {}s",
                TCP_CONNECT_TIMEOUT.as_secs()
            )),
        }
    }

    /// Quick DNS resolve with custom timeout, no automatic retry.
    /// Used for health checks where the caller manages retries or parallel attempts.
    pub async fn resolve_quick(
        &self,
        hostname: &str,
        timeout: Duration,
    ) -> anyhow::Result<Vec<IpAddr>> {
        match tokio::time::timeout(timeout, self.client.resolve(hostname)).await {
            Ok(Ok(addrs)) => Ok(addrs),
            Ok(Err(e)) => Err(anyhow::anyhow!("DNS resolve failed: {}", e)),
            Err(_) => Err(anyhow::anyhow!(
                "DNS resolve timed out after {}ms",
                timeout.as_millis()
            )),
        }
    }

    /// Resolve a DNS name through Tor.
    ///
    /// 5s timeout per attempt. On failure, retries once with a fresh circuit (5s).
    /// Total worst case: 10s, then SERVFAIL → client retries on its own schedule.
    ///
    /// Note: exit_country is NOT applied here — DNS resolution returns the same
    /// IPs regardless of exit country, and constraining to a specific country
    /// reduces the exit relay pool causing "Protocol error" failures.
    pub async fn resolve_dns(&self, hostname: &str) -> anyhow::Result<Vec<IpAddr>> {
        const DNS_TIMEOUT: Duration = Duration::from_secs(5);

        // First attempt
        match tokio::time::timeout(DNS_TIMEOUT, self.client.resolve(hostname)).await {
            Ok(Ok(addrs)) => return Ok(addrs),
            Ok(Err(e)) => {
                tracing::debug!(
                    name = %hostname, error = %e,
                    "DNS resolve failed, retrying with fresh circuit"
                );
            }
            Err(_) => {
                tracing::debug!(name = %hostname, "DNS resolve timed out, retrying with fresh circuit");
            }
        }

        // Retry with fresh circuit
        let mut prefs = StreamPrefs::new();
        prefs.new_isolation_group();
        match tokio::time::timeout(
            DNS_TIMEOUT,
            self.client.resolve_with_prefs(hostname, &prefs),
        )
        .await
        {
            Ok(Ok(addrs)) => Ok(addrs),
            Ok(Err(e)) => Err(anyhow::anyhow!("Tor DNS resolve failed: {}", e)),
            Err(_) => Err(anyhow::anyhow!("Tor DNS resolve timed out after retry")),
        }
    }

    /// Invalidate all isolation token caches, forcing new circuits for subsequent connections.
    ///
    /// Triggered by SIGUSR1 or IPC `refresh`. Existing connections are unaffected.
    /// Under `Session` policy the session token is static by design — only DNS cache
    /// is cleared (handled by the caller). Returns a user-facing message describing
    /// what was actually refreshed.
    pub fn refresh_circuits(&self) -> &'static str {
        self.dest_tokens.invalidate_all();
        self.onion_tokens.invalidate_all();
        match self.policy {
            IsolationPolicy::Session => {
                tracing::info!(
                    "Circuit refresh: DNS cache will be cleared, but session isolation \
                     token is unchanged (use restart for a new circuit identity)"
                );
                "DNS cache cleared (session isolation unchanged — restart for new identity)"
            }
            _ => {
                tracing::info!(
                    "Circuit refresh: isolation tokens invalidated — \
                     new connections will use fresh circuits"
                );
                "Circuits refreshed"
            }
        }
    }

    /// Get a reference to the underlying TorClient (for guard IP detection).
    pub fn client(&self) -> &TorClient<PreferredRuntime> {
        &self.client
    }

    /// Get the resolved PT binary paths (transport_name, path).
    /// Non-empty when bridges with pluggable transports are configured.
    /// Includes both explicit `--pt-path` values and auto-detected binaries from PATH.
    pub fn resolved_pt_paths(&self) -> &[(String, String)] {
        &self.resolved_pt_paths
    }
}

/// Domains used for DNS health probes (circuit verification, bootstrap watcher).
/// Rotated to avoid hitting a single provider and to survive individual outages.
pub const PROBE_DOMAINS: &[&str] = &[
    "www.google.com",
    "www.wikipedia.org",
    "www.cloudflare.com",
    "www.apple.com",
    "www.amazon.com",
];

/// Background task that verifies Tor actually works by probing with real DNS.
///
/// `ready_for_traffic()` alone is unreliable — arti can report "ready" while
/// circuits are actually dead. The probe catches this discrepancy.
///
/// Flow:
/// - First check at 30s after startup (circuits need time to stabilize after route changes).
/// - Every 30s: probe DNS. If fails → switch to 10s polling.
/// - 3 consecutive probe failures → signal full VPN session restart.
pub async fn run_bootstrap_watcher(
    tor: Arc<TorManager>,
    dns_cache: DnsCache,
    restart_notify: Arc<tokio::sync::Notify>,
    cancel: CancellationToken,
) {
    const NORMAL_POLL: Duration = Duration::from_secs(30);
    const RECOVERY_POLL: Duration = Duration::from_secs(10);
    const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

    // Allow circuits to stabilize after route installation before first probe.
    // Route changes can temporarily disrupt existing guard connections.
    let mut poll_interval = Duration::from_secs(30);
    let mut probe_failures: u32 = 0;
    let mut probe_count: usize = 0;

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(poll_interval) => {}
        }

        let status = tor.client().bootstrap_status();
        let ready = status.ready_for_traffic();

        // Only probe when arti reports ready — if not ready, it'll definitely fail
        let domain = PROBE_DOMAINS[probe_count % PROBE_DOMAINS.len()];
        probe_count += 1;
        let working = if ready {
            matches!(
                tokio::time::timeout(PROBE_TIMEOUT, tor.client().resolve(domain)).await,
                Ok(Ok(_))
            )
        } else {
            false
        };

        if working {
            probe_failures = 0;
            poll_interval = NORMAL_POLL;
        } else {
            probe_failures += 1;

            if probe_failures >= 3 {
                tracing::warn!(
                    status = %status,
                    ready,
                    failures = probe_failures,
                    "Tor not working — requesting full restart"
                );
                dns_cache.invalidate_all();
                restart_notify.notify_one();
                break;
            }

            tracing::debug!(
                status = %status,
                ready,
                failures = probe_failures,
                "DNS probe failed — will verify on next check"
            );
            poll_interval = RECOVERY_POLL;
        }
    }
    tracing::debug!("Bootstrap watcher stopped");
}

/// Try to find a binary by name in the system PATH.
fn find_in_path(name: &str) -> Option<String> {
    which::which(name)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_line_parsing() {
        // Standard bridge line should parse successfully
        let line = "192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let result: Result<BridgeConfigBuilder, _> = line.parse();
        assert!(
            result.is_ok(),
            "direct bridge line should parse: {result:?}"
        );
    }

    #[test]
    fn test_bridge_line_with_transport() {
        // Bridge line with transport prefix
        let line =
            "obfs4 192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA cert=AAAA iat-mode=0";
        let bridge: BridgeConfigBuilder = line.parse().expect("should parse obfs4 bridge line");
        let transport = bridge.get_transport();
        assert_eq!(transport, Some("obfs4"));
    }

    #[test]
    fn test_direct_bridge_no_transport() {
        let line = "192.0.2.1:443 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let bridge: BridgeConfigBuilder = line.parse().expect("should parse direct bridge");
        // Direct bridges return Some("") — empty string means no PT needed
        let transport = bridge.get_transport();
        assert!(
            transport.is_none() || transport == Some(""),
            "direct bridge should have no transport, got: {transport:?}"
        );
    }

    #[test]
    fn test_pt_transport_name_parsing() {
        let name: Result<PtTransportName, _> = "obfs4".parse();
        assert!(name.is_ok());
        let name: Result<PtTransportName, _> = "snowflake".parse();
        assert!(name.is_ok());
    }

    #[test]
    fn test_invalid_bridge_line() {
        let result: Result<BridgeConfigBuilder, _> = "not a valid bridge line".parse();
        assert!(result.is_err());
    }
}
