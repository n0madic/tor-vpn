use std::fmt::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use cidr::Ipv4Cidr;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

pub use clap::{ArgMatches, CommandFactory, FromArgMatches};

mod file;
pub use file::*;

#[derive(Debug, Clone, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationPolicy {
    /// New Tor circuit for every TCP connection
    PerConnection,
    /// Same circuit for connections to the same (ip, port) — default
    PerDestination,
    /// Single shared circuit for the entire session
    Session,
}

#[derive(Debug, Parser)]
#[command(name = "tor-vpn", about = "TUN-based transparent Tor VPN")]
pub struct Cli {
    /// Path to a torrc-style config file
    #[arg(long, global = true, env = "TOR_VPN_CONFIG")]
    pub config: Option<PathBuf>,

    /// Log level
    #[arg(long, default_value = "info", global = true, env = "TOR_VPN_LOG_LEVEL")]
    pub log_level: String,

    /// Path to the state file used for SIGKILL recovery
    #[arg(long, global = true, default_value_os_t = state::default_state_file(), env = "TOR_VPN_STATE_FILE")]
    pub state_file: PathBuf,

    /// Write logs to a file instead of stderr (disables ANSI colors)
    #[arg(long, global = true, env = "TOR_VPN_LOG_FILE")]
    pub log_file: Option<PathBuf>,

    /// Path to the IPC control socket for daemon management
    #[arg(long, global = true, default_value_os_t = state::default_socket_path(), env = "TOR_VPN_SOCKET_PATH")]
    pub socket_path: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the VPN — route all traffic through Tor
    Start(StartArgs),
    /// Clean up orphaned routes and DNS from a previously killed tor-vpn instance
    Cleanup,
    /// Show VPN status and diagnostic information
    Status,
    /// Refresh Tor circuits by sending SIGUSR1 to the running instance (Unix only)
    Refresh,
    /// Gracefully stop the running VPN daemon (no root required)
    Stop,
}

#[derive(Debug, Args)]
pub struct StartArgs {
    /// TUN device name (auto-assigned on macOS)
    #[arg(long, default_value = "torvpn0", env = "TOR_VPN_TUN_NAME")]
    pub tun_name: String,

    /// TUN interface IPv4 address
    #[arg(long, default_value = "10.200.0.1", env = "TOR_VPN_TUN_ADDRESS")]
    pub tun_address: Ipv4Addr,

    /// TUN interface netmask prefix length (1-30)
    #[arg(long, default_value_t = 24, value_parser = clap::value_parser!(u8).range(1..=30), env = "TOR_VPN_TUN_NETMASK")]
    pub tun_netmask: u8,

    /// TUN MTU (68-65535)
    #[arg(long, default_value_t = 1500, value_parser = clap::value_parser!(u16).range(68..=65535), env = "TOR_VPN_TUN_MTU")]
    pub tun_mtu: u16,

    /// Stream isolation policy
    #[arg(
        long,
        value_enum,
        default_value = "per-destination",
        env = "TOR_VPN_ISOLATION"
    )]
    pub isolation: IsolationPolicy,

    /// Tor cache/state directory
    #[arg(long, default_value_t = state::default_tor_cache_dir(), env = "TOR_VPN_CACHE_DIR")]
    pub cache_dir: String,

    /// CIDRs to bypass TUN (routed through original gateway)
    #[arg(long, value_parser = parse_cidr, env = "TOR_VPN_BYPASS_CIDR", value_delimiter = ',')]
    pub bypass_cidr: Vec<String>,

    /// Maximum concurrent TCP connections proxied through Tor
    #[arg(long, default_value_t = 256, env = "TOR_VPN_MAX_CONNECTIONS")]
    pub max_connections: usize,

    /// Maximum concurrent DNS queries
    #[arg(long, default_value_t = 256, env = "TOR_VPN_MAX_DNS_QUERIES")]
    pub max_dns_queries: usize,

    /// DNS cache TTL in seconds
    #[arg(long, default_value_t = 900, env = "TOR_VPN_DNS_CACHE_TTL")]
    pub dns_cache_ttl: u32,

    /// Override system DNS to prevent browser DoH (required for .onion in browsers)
    #[arg(long, default_value_t = false, env = "TOR_VPN_OVERRIDE_DNS")]
    pub override_dns: bool,

    /// ISO 3166-1 alpha-2 country code for exit relay selection (e.g., "US", "DE")
    #[arg(long, value_parser = parse_country_code, env = "TOR_VPN_EXIT_COUNTRY")]
    pub exit_country: Option<String>,

    /// Tor bridge line(s) in standard format (repeatable)
    /// Example: "obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0"
    #[arg(long, env = "TOR_VPN_BRIDGE", value_delimiter = ',')]
    pub bridge: Vec<String>,

    /// Pluggable transport binary paths: TRANSPORT=PATH (repeatable)
    /// Example: "obfs4=/usr/bin/obfs4proxy"
    #[arg(long, value_parser = parse_pt_path, env = "TOR_VPN_PT_PATH", value_delimiter = ',')]
    pub pt_path: Vec<(String, String)>,

    /// Interval in seconds between state file writes (bandwidth stats).
    /// Lower values (2-5) give near-real-time stats for UI monitoring.
    #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u32).range(1..=3600), env = "TOR_VPN_STATE_WRITE_INTERVAL")]
    pub state_write_interval: u32,

    /// Install blackhole routes during session restart to prevent traffic leaks.
    /// Disable with --kill-switch=false if it causes connectivity issues.
    #[arg(long, default_value_t = true, num_args = 0..=1, default_missing_value = "true", env = "TOR_VPN_KILL_SWITCH")]
    pub kill_switch: bool,
}

/// Resolved daemon configuration — used by the daemon and (via serde) by the UI.
///
/// Strong types (`Ipv4Addr`, `IsolationPolicy`) for daemon code; serde handles
/// JSON serialization for Tauri IPC automatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub tun_name: String,
    pub tun_address: Ipv4Addr,
    pub tun_netmask: u8,
    pub tun_mtu: u16,
    pub isolation: IsolationPolicy,
    pub cache_dir: String,
    pub bypass_cidrs: Vec<String>,
    pub max_connections: usize,
    pub max_dns_queries: usize,
    pub dns_cache_ttl: u32,
    pub override_dns: bool,
    pub exit_country: Option<String>,
    pub bridges: Vec<String>,
    #[serde(
        serialize_with = "serialize_pt_paths",
        deserialize_with = "deserialize_pt_paths"
    )]
    pub pt_paths: Vec<(String, String)>,
    #[serde(skip, default = "state::default_state_file")]
    pub state_file: PathBuf,
    #[serde(default = "state::default_socket_path")]
    pub socket_path: PathBuf,
    pub state_write_interval: u32,
    #[serde(default = "default_true")]
    pub kill_switch: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tun_name: "torvpn0".to_string(),
            tun_address: "10.200.0.1".parse().unwrap(),
            tun_netmask: 24,
            tun_mtu: 1500,
            isolation: IsolationPolicy::PerDestination,
            cache_dir: state::default_tor_cache_dir(),
            bypass_cidrs: vec![],
            max_connections: 256,
            max_dns_queries: 256,
            dns_cache_ttl: 900,
            override_dns: false,
            exit_country: None,
            bridges: vec![],
            pt_paths: vec![],
            state_file: state::default_state_file(),
            socket_path: state::default_socket_path(),
            state_write_interval: 60,
            kill_switch: true,
        }
    }
}

impl From<ConfigFile> for Config {
    fn from(file: ConfigFile) -> Self {
        let mut c = Self::default();

        if let Some(v) = file.tun_name {
            c.tun_name = v;
        }
        if let Some(v) = file.tun_address {
            c.tun_address = v;
        }
        if let Some(v) = file.tun_netmask {
            c.tun_netmask = v;
        }
        if let Some(v) = file.tun_mtu {
            c.tun_mtu = v;
        }
        if let Some(v) = file.isolation {
            c.isolation = v;
        }
        if let Some(v) = file.cache_dir {
            c.cache_dir = v;
        }
        if !file.bypass_cidrs.is_empty() {
            c.bypass_cidrs = file.bypass_cidrs;
        }
        if let Some(v) = file.max_connections {
            c.max_connections = v;
        }
        if let Some(v) = file.max_dns_queries {
            c.max_dns_queries = v;
        }
        if let Some(v) = file.dns_cache_ttl {
            c.dns_cache_ttl = v;
        }
        if let Some(v) = file.override_dns {
            c.override_dns = v;
        }
        if let Some(v) = file.state_write_interval {
            c.state_write_interval = v;
        }
        if let Some(v) = file.kill_switch {
            c.kill_switch = v;
        }
        if let Some(v) = file.state_file {
            c.state_file = v;
        }
        if let Some(v) = file.socket_path {
            c.socket_path = v;
        }

        c.exit_country = file.exit_country;

        // UseBridges 0 disables bridges from config file
        if file.use_bridges == Some(false) {
            c.bridges.clear();
            c.pt_paths.clear();
        } else {
            if !file.bridges.is_empty() {
                c.bridges = file.bridges;
            }
            if !file.pt_paths.is_empty() {
                c.pt_paths = file.pt_paths;
            }
        }

        c
    }
}

impl Config {
    #[cfg(test)]
    pub fn new(args: StartArgs, state_file: PathBuf) -> Self {
        Self {
            tun_name: args.tun_name,
            tun_address: args.tun_address,
            tun_netmask: args.tun_netmask,
            tun_mtu: args.tun_mtu,
            isolation: args.isolation,
            cache_dir: args.cache_dir,
            bypass_cidrs: args.bypass_cidr,
            max_connections: args.max_connections,
            max_dns_queries: args.max_dns_queries,
            dns_cache_ttl: args.dns_cache_ttl,
            override_dns: args.override_dns,
            exit_country: args.exit_country,
            bridges: args.bridge,
            pt_paths: args.pt_path,
            state_file,
            socket_path: state::default_socket_path(),
            state_write_interval: args.state_write_interval,
            kill_switch: args.kill_switch,
        }
    }

    /// Build torrc-style config file content for this config.
    ///
    /// String values are sanitized to strip newlines/carriage returns,
    /// preventing directive injection when the renderer provides values
    /// containing `\n` (which would be interpreted as new directives).
    pub fn to_config_content(&self, log_path: &Path) -> String {
        let mut out = String::with_capacity(512);
        writeln!(out, "# Generated by tor-vpn UI").unwrap();

        writeln!(out, "TunName {}", sanitize_line(&self.tun_name)).unwrap();
        writeln!(out, "TunAddress {}", self.tun_address).unwrap();
        writeln!(out, "TunNetmask {}", self.tun_netmask).unwrap();
        writeln!(out, "TunMTU {}", self.tun_mtu).unwrap();

        writeln!(out, "Isolation {}", isolation_to_str(&self.isolation)).unwrap();
        writeln!(out, "OverrideDNS {}", if self.override_dns { 1 } else { 0 }).unwrap();

        if let Some(ref cc) = self.exit_country {
            if !cc.is_empty() {
                writeln!(out, "ExitNodes {{{}}}", sanitize_line(cc)).unwrap();
            }
        }

        writeln!(out, "MaxConnections {}", self.max_connections).unwrap();
        writeln!(out, "MaxDNSQueries {}", self.max_dns_queries).unwrap();
        writeln!(out, "DNSCacheTTL {}", self.dns_cache_ttl).unwrap();
        writeln!(out, "StateWriteInterval {}", self.state_write_interval).unwrap();

        if !self.kill_switch {
            writeln!(out, "KillSwitch 0").unwrap();
        }

        if self.cache_dir != state::default_tor_cache_dir() {
            writeln!(out, "CacheDir {}", sanitize_line(&self.cache_dir)).unwrap();
        }
        if self.state_file != state::default_state_file() {
            let sf = self.state_file.display().to_string();
            writeln!(out, "StateFile {}", sanitize_line(&sf)).unwrap();
        }
        if self.socket_path != state::default_socket_path() {
            let sp = self.socket_path.display().to_string();
            writeln!(out, "ControlSocket {}", sanitize_line(&sp)).unwrap();
        }
        {
            let lp = log_path.display().to_string();
            writeln!(out, "Log info file {}", sanitize_line(&lp)).unwrap();
        }

        for cidr in &self.bypass_cidrs {
            writeln!(out, "BypassCIDR {}", sanitize_line(cidr)).unwrap();
        }

        if !self.bridges.is_empty() {
            writeln!(out, "UseBridges 1").unwrap();
            for bridge in &self.bridges {
                writeln!(out, "Bridge {}", sanitize_line(bridge)).unwrap();
            }
        }

        for (transport, path) in &self.pt_paths {
            writeln!(
                out,
                "ClientTransportPlugin {} exec {}",
                sanitize_line(transport),
                sanitize_line(path)
            )
            .unwrap();
        }

        out
    }
}

fn default_true() -> bool {
    true
}

fn isolation_to_str(policy: &IsolationPolicy) -> &'static str {
    match policy {
        IsolationPolicy::PerConnection => "per-connection",
        IsolationPolicy::PerDestination => "per-destination",
        IsolationPolicy::Session => "session",
    }
}

/// Truncate a string at the first newline or carriage return.
///
/// Prevents directive injection in torrc-style config files: a value
/// containing `\n` would otherwise be interpreted as a new directive
/// by the line-oriented parser.
fn sanitize_line(s: &str) -> &str {
    match s.find(['\n', '\r']) {
        Some(pos) => &s[..pos],
        None => s,
    }
}

/// Serialize `Vec<(String, String)>` as `["transport=path", ...]` for JSON.
fn serialize_pt_paths<S>(paths: &[(String, String)], s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(paths.len()))?;
    for (transport, path) in paths {
        seq.serialize_element(&format!("{transport}={path}"))?;
    }
    seq.end()
}

/// Deserialize `["transport=path", ...]` into `Vec<(String, String)>`.
fn deserialize_pt_paths<'de, D>(d: D) -> Result<Vec<(String, String)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let strings: Vec<String> = Vec::deserialize(d)?;
    Ok(strings
        .iter()
        .filter_map(|s| {
            let (t, p) = s.split_once('=')?;
            Some((t.to_string(), p.to_string()))
        })
        .collect())
}

/// Validate CIDR notation using the `cidr` crate.
/// Ensures the string is a valid IPv4 network address with host bits zeroed
/// (e.g. `10.0.0.0/8` is valid, `10.0.0.1/8` is rejected).
pub fn parse_cidr(s: &str) -> Result<String, String> {
    s.parse::<Ipv4Cidr>()
        .map_err(|e| format!("invalid CIDR '{s}': {e}"))?;
    Ok(s.to_string())
}

/// Validate pluggable transport path specification: "TRANSPORT=PATH".
pub fn parse_pt_path(s: &str) -> Result<(String, String), String> {
    let (transport, path) = s
        .split_once('=')
        .ok_or_else(|| format!("invalid PT path '{s}': expected TRANSPORT=PATH format"))?;
    if transport.is_empty() {
        return Err(format!("invalid PT path '{s}': transport name is empty"));
    }
    let path_buf = std::path::Path::new(path);
    if !path_buf.exists() {
        return Err(format!(
            "PT binary not found: '{path}' (for transport '{transport}')"
        ));
    }
    if !path_buf.is_file() {
        return Err(format!(
            "PT path is not a file: '{path}' (for transport '{transport}')"
        ));
    }
    Ok((transport.to_string(), path.to_string()))
}

/// Validate ISO 3166-1 alpha-2 country code (2 ASCII letters, case-insensitive).
pub fn parse_country_code(s: &str) -> Result<String, String> {
    let upper = s.to_uppercase();
    if upper.len() != 2 || !upper.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(format!(
            "invalid country code '{s}': must be 2 ASCII letters (ISO 3166-1 alpha-2)"
        ));
    }
    Ok(upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_args() -> StartArgs {
        StartArgs {
            tun_name: "torvpn0".to_string(),
            tun_address: "10.200.0.1".parse().unwrap(),
            tun_netmask: 24,
            tun_mtu: 1500,
            isolation: IsolationPolicy::PerDestination,
            cache_dir: state::default_tor_cache_dir(),
            bypass_cidr: vec![],
            max_connections: 256,
            max_dns_queries: 256,
            dns_cache_ttl: 900,
            override_dns: false,
            exit_country: None,
            bridge: vec![],
            pt_path: vec![],
            state_write_interval: 60,
            kill_switch: true,
        }
    }

    // --- Config::from(StartArgs) conversion ---

    #[test]
    fn test_config_from_start_args_defaults() {
        let config = Config::new(default_args(), state::default_state_file());

        assert_eq!(config.tun_name, "torvpn0");
        assert_eq!(
            config.tun_address,
            "10.200.0.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(config.tun_netmask, 24);
        assert_eq!(config.tun_mtu, 1500);
        assert_eq!(config.cache_dir, state::default_tor_cache_dir());
        assert!(config.bypass_cidrs.is_empty());
        assert_eq!(config.max_connections, 256);
        assert_eq!(config.max_dns_queries, 256);
        assert_eq!(config.dns_cache_ttl, 900);
        assert!(!config.override_dns);
    }

    #[test]
    fn test_config_from_start_args_custom_values() {
        let args = StartArgs {
            tun_name: "utun9".to_string(),
            tun_address: "192.168.100.1".parse().unwrap(),
            tun_netmask: 16,
            tun_mtu: 9000,
            isolation: IsolationPolicy::PerConnection,
            cache_dir: "/var/lib/tor".to_string(),
            bypass_cidr: vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()],
            max_connections: 512,
            max_dns_queries: 128,
            dns_cache_ttl: 300,
            override_dns: true,
            exit_country: Some("US".to_string()),
            bridge: vec![],
            pt_path: vec![],
            state_write_interval: 5,
            kill_switch: true,
        };
        let config = Config::new(args, "/custom/state.json".into());

        assert_eq!(config.tun_name, "utun9");
        assert_eq!(
            config.tun_address,
            "192.168.100.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(config.tun_netmask, 16);
        assert_eq!(config.tun_mtu, 9000);
        assert_eq!(config.cache_dir, "/var/lib/tor");
        assert_eq!(config.bypass_cidrs, ["10.0.0.0/8", "172.16.0.0/12"]);
        assert_eq!(config.max_connections, 512);
        assert_eq!(config.max_dns_queries, 128);
        assert_eq!(config.dns_cache_ttl, 300);
        assert!(config.override_dns);
        assert_eq!(config.state_file, PathBuf::from("/custom/state.json"));
    }

    /// `bypass_cidr` in `StartArgs` maps to `bypass_cidrs` in `Config`.
    #[test]
    fn test_config_from_start_args_bypass_cidrs_renamed() {
        let mut args = default_args();
        args.bypass_cidr = vec!["1.2.3.0/24".to_string()];
        let config = Config::new(args, state::default_state_file());
        assert_eq!(config.bypass_cidrs, ["1.2.3.0/24"]);
    }

    // --- IsolationPolicy variants ---

    #[test]
    fn test_isolation_policy_per_connection() {
        let args = StartArgs {
            isolation: IsolationPolicy::PerConnection,
            ..default_args()
        };
        let config = Config::new(args, state::default_state_file());
        assert!(matches!(config.isolation, IsolationPolicy::PerConnection));
    }

    #[test]
    fn test_isolation_policy_per_destination() {
        let args = StartArgs {
            isolation: IsolationPolicy::PerDestination,
            ..default_args()
        };
        let config = Config::new(args, state::default_state_file());
        assert!(matches!(config.isolation, IsolationPolicy::PerDestination));
    }

    #[test]
    fn test_isolation_policy_session() {
        let args = StartArgs {
            isolation: IsolationPolicy::Session,
            ..default_args()
        };
        let config = Config::new(args, state::default_state_file());
        assert!(matches!(config.isolation, IsolationPolicy::Session));
    }

    /// Verify that `IsolationPolicy` is `Clone`, which is required by the rest of the codebase.
    #[test]
    fn test_isolation_policy_clone() {
        let policy = IsolationPolicy::PerConnection;
        let cloned = policy.clone();
        assert!(matches!(cloned, IsolationPolicy::PerConnection));
    }

    /// Verify `Debug` formatting is available (used in tracing).
    #[test]
    fn test_isolation_policy_debug() {
        assert!(format!("{:?}", IsolationPolicy::PerConnection).contains("PerConnection"));
        assert!(format!("{:?}", IsolationPolicy::PerDestination).contains("PerDestination"));
        assert!(format!("{:?}", IsolationPolicy::Session).contains("Session"));
    }

    // --- IsolationPolicy serde ---

    #[test]
    fn test_isolation_policy_serde() {
        let json = serde_json::to_string(&IsolationPolicy::PerConnection).unwrap();
        assert_eq!(json, "\"per-connection\"");
        let json = serde_json::to_string(&IsolationPolicy::PerDestination).unwrap();
        assert_eq!(json, "\"per-destination\"");
        let json = serde_json::to_string(&IsolationPolicy::Session).unwrap();
        assert_eq!(json, "\"session\"");

        let policy: IsolationPolicy = serde_json::from_str("\"per-connection\"").unwrap();
        assert!(matches!(policy, IsolationPolicy::PerConnection));
    }

    // --- Config serde ---

    #[test]
    fn test_config_serde_pt_paths() {
        let config = Config {
            pt_paths: vec![("obfs4".to_string(), "/usr/bin/obfs4proxy".to_string())],
            ..Config::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"obfs4=/usr/bin/obfs4proxy\""));
        assert!(!json.contains("state_file")); // skipped

        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.pt_paths[0].0, "obfs4");
        assert_eq!(parsed.pt_paths[0].1, "/usr/bin/obfs4proxy");
    }

    #[test]
    fn test_config_serde_state_file_skipped() {
        let config = Config {
            state_file: PathBuf::from("/custom/path"),
            ..Config::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("state_file"));
        assert!(!json.contains("/custom/path"));
    }

    #[test]
    fn test_config_serde_socket_path_included() {
        let config = Config {
            socket_path: PathBuf::from("/tmp/custom.sock"),
            ..Config::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("socket_path"));
        assert!(json.contains("/tmp/custom.sock"));

        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.socket_path, PathBuf::from("/tmp/custom.sock"));
    }

    // --- Config::from(ConfigFile) ---

    #[test]
    fn test_config_from_config_file_partial() {
        let file = ConfigFile {
            tun_name: Some("mytun0".to_string()),
            tun_mtu: Some(1400),
            override_dns: Some(true),
            exit_country: Some("DE".to_string()),
            ..Default::default()
        };
        let c = Config::from(file);
        assert_eq!(c.tun_name, "mytun0");
        assert_eq!(c.tun_mtu, 1400);
        assert!(c.override_dns);
        assert_eq!(c.exit_country.as_deref(), Some("DE"));
        assert_eq!(c.tun_address.to_string(), "10.200.0.1");
        assert_eq!(c.max_connections, 256);
    }

    #[test]
    fn test_config_from_config_file_socket_path() {
        let file = ConfigFile {
            socket_path: Some(PathBuf::from("/run/custom.sock")),
            ..Default::default()
        };
        let c = Config::from(file);
        assert_eq!(c.socket_path, PathBuf::from("/run/custom.sock"));
    }

    #[test]
    fn test_config_from_config_file_use_bridges_false() {
        let file = ConfigFile {
            bridges: vec!["obfs4 192.0.2.1:443 AAAA".to_string()],
            pt_paths: vec![("obfs4".to_string(), "/usr/bin/obfs4proxy".to_string())],
            use_bridges: Some(false),
            ..Default::default()
        };
        let c = Config::from(file);
        assert!(c.bridges.is_empty());
        assert!(c.pt_paths.is_empty());
    }

    // --- Config::to_config_content roundtrip ---

    #[test]
    fn test_config_to_config_content_roundtrip() {
        let original = Config {
            tun_name: "mytun0".to_string(),
            tun_address: "10.100.0.1".parse().unwrap(),
            tun_netmask: 16,
            tun_mtu: 1400,
            isolation: IsolationPolicy::PerConnection,
            override_dns: true,
            exit_country: Some("US".to_string()),
            max_connections: 512,
            max_dns_queries: 128,
            dns_cache_ttl: 300,
            state_write_interval: 5,
            cache_dir: "/tmp/test-cache".to_string(),
            bypass_cidrs: vec!["10.0.0.0/8".to_string()],
            bridges: vec!["obfs4 192.0.2.1:443 AAAA cert=bbb iat-mode=0".to_string()],
            pt_paths: vec![("obfs4".to_string(), "/usr/bin/obfs4proxy".to_string())],
            state_file: state::default_state_file(),
            socket_path: state::default_socket_path(),
            kill_switch: true,
        };
        let content = original.to_config_content(Path::new("/tmp/roundtrip.log"));
        let parsed = parse_config_content(&content, Path::new("<test>")).unwrap();

        // Verify Log directive roundtrip
        assert_eq!(parsed.log_targets.len(), 1);
        assert_eq!(parsed.log_targets[0].level, "info");
        assert!(matches!(
            parsed.log_targets[0].destination,
            LogDestination::File(_)
        ));

        let restored = Config::from(parsed);

        assert_eq!(restored.tun_name, original.tun_name);
        assert_eq!(restored.tun_address, original.tun_address);
        assert_eq!(restored.tun_netmask, original.tun_netmask);
        assert_eq!(restored.tun_mtu, original.tun_mtu);
        assert!(matches!(restored.isolation, IsolationPolicy::PerConnection));
        assert_eq!(restored.override_dns, original.override_dns);
        assert_eq!(restored.exit_country, original.exit_country);
        assert_eq!(restored.max_connections, original.max_connections);
        assert_eq!(restored.dns_cache_ttl, original.dns_cache_ttl);
        assert_eq!(restored.state_write_interval, original.state_write_interval);
        assert_eq!(restored.bypass_cidrs, original.bypass_cidrs);
        assert_eq!(restored.bridges, original.bridges);
        assert_eq!(restored.pt_paths, original.pt_paths);
    }

    // --- parse_cidr validation ---

    #[test]
    fn test_parse_cidr_valid() {
        assert!(parse_cidr("10.0.0.0/8").is_ok());
        assert!(parse_cidr("0.0.0.0/0").is_ok());
        assert!(parse_cidr("192.168.1.0/24").is_ok());
        assert!(parse_cidr("255.255.255.255/32").is_ok());
    }

    #[test]
    fn test_parse_cidr_bare_ip_treated_as_host() {
        // cidr crate accepts bare IP as /32 host route — valid for route commands
        assert!(parse_cidr("10.0.0.0").is_ok());
    }

    #[test]
    fn test_parse_cidr_invalid_prefix_too_large() {
        assert!(parse_cidr("10.0.0.0/33").is_err());
    }

    #[test]
    fn test_parse_cidr_invalid_not_ip() {
        assert!(parse_cidr("foobar/8").is_err());
    }

    #[test]
    fn test_parse_cidr_invalid_garbage() {
        assert!(parse_cidr("foobar").is_err());
    }

    #[test]
    fn test_parse_cidr_rejects_host_bits() {
        // 10.0.0.1/8 has non-zero host bits — invalid network address
        assert!(parse_cidr("10.0.0.1/8").is_err());
        assert!(parse_cidr("192.168.1.1/24").is_err());
    }

    // --- parse_country_code validation ---

    #[test]
    fn test_parse_country_code_valid() {
        assert_eq!(parse_country_code("US").unwrap(), "US");
        assert_eq!(parse_country_code("de").unwrap(), "DE");
        assert_eq!(parse_country_code("Jp").unwrap(), "JP");
    }

    #[test]
    fn test_parse_country_code_invalid_length() {
        assert!(parse_country_code("USA").is_err());
        assert!(parse_country_code("U").is_err());
        assert!(parse_country_code("").is_err());
    }

    #[test]
    fn test_parse_country_code_invalid_chars() {
        assert!(parse_country_code("1A").is_err());
        assert!(parse_country_code("A1").is_err());
        assert!(parse_country_code("!!").is_err());
    }

    // --- exit_country config propagation ---

    #[test]
    fn test_config_exit_country_none_by_default() {
        let config = Config::new(default_args(), state::default_state_file());
        assert!(config.exit_country.is_none());
    }

    #[test]
    fn test_config_exit_country_propagation() {
        let mut args = default_args();
        args.exit_country = Some("DE".to_string());
        let config = Config::new(args, state::default_state_file());
        assert_eq!(config.exit_country.as_deref(), Some("DE"));
    }

    // --- parse_pt_path validation ---

    #[test]
    fn test_parse_pt_path_missing_equals() {
        assert!(parse_pt_path("obfs4/usr/bin/obfs4proxy").is_err());
    }

    #[test]
    fn test_parse_pt_path_empty_transport() {
        assert!(parse_pt_path("=/usr/bin/obfs4proxy").is_err());
    }

    #[test]
    fn test_parse_pt_path_nonexistent_file() {
        assert!(parse_pt_path("obfs4=/nonexistent/path/obfs4proxy").is_err());
    }

    #[test]
    fn test_parse_pt_path_valid_file() {
        // Use the cargo binary itself as a known-existing file
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let cargo_path = which_cargo(&cargo);
        if let Some(path) = cargo_path {
            let input = format!("obfs4={path}");
            let result = parse_pt_path(&input);
            assert!(result.is_ok(), "should accept existing file: {result:?}");
            let (transport, p) = result.unwrap();
            assert_eq!(transport, "obfs4");
            assert_eq!(p, path);
        }
    }

    /// Helper to find a binary path for testing.
    fn which_cargo(name: &str) -> Option<String> {
        which::which(name)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    // --- bridge / PT config propagation ---

    #[test]
    fn test_config_bridges_empty_by_default() {
        let config = Config::new(default_args(), state::default_state_file());
        assert!(config.bridges.is_empty());
        assert!(config.pt_paths.is_empty());
    }

    #[test]
    fn test_config_bridges_propagation() {
        let mut args = default_args();
        args.bridge = vec!["obfs4 192.0.2.1:443 AAAA cert=bbb iat-mode=0".to_string()];
        args.pt_path = vec![("obfs4".to_string(), "/usr/bin/obfs4proxy".to_string())];
        let config = Config::new(args, state::default_state_file());
        assert_eq!(config.bridges.len(), 1);
        assert_eq!(config.pt_paths.len(), 1);
        assert_eq!(config.pt_paths[0].0, "obfs4");
    }
}
