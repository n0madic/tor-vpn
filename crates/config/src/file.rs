use std::fmt;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use clap::parser::ValueSource;
use clap::ArgMatches;

use crate::{parse_cidr, parse_country_code, Cli, Command, Config, IsolationPolicy};

/// Where a `Log` directive sends output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogDestination {
    Stderr,
    Stdout,
    File(PathBuf),
}

/// A single `Log` directive: severity + destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogTarget {
    pub level: String,
    pub destination: LogDestination,
}

/// Error from parsing a config file, with file path and line number.
#[derive(Debug)]
pub struct ConfigFileError {
    pub path: PathBuf,
    pub line_number: usize,
    pub message: String,
}

impl fmt::Display for ConfigFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line_number == 0 {
            write!(f, "{}: {}", self.path.display(), self.message)
        } else {
            write!(
                f,
                "{}:{}: {}",
                self.path.display(),
                self.line_number,
                self.message
            )
        }
    }
}

impl std::error::Error for ConfigFileError {}

/// Intermediate representation of a parsed config file.
/// All fields are `Option` — absent means "not specified in config file".
#[derive(Debug, Default)]
pub struct ConfigFile {
    // Global
    pub log_targets: Vec<LogTarget>,
    pub state_file: Option<PathBuf>,
    pub socket_path: Option<PathBuf>,
    pub state_write_interval: Option<u32>,
    // Start-specific
    pub tun_name: Option<String>,
    pub tun_address: Option<Ipv4Addr>,
    pub tun_netmask: Option<u8>,
    pub tun_mtu: Option<u16>,
    pub isolation: Option<IsolationPolicy>,
    pub cache_dir: Option<String>,
    pub bypass_cidrs: Vec<String>,
    pub max_connections: Option<usize>,
    pub max_dns_queries: Option<usize>,
    pub dns_cache_ttl: Option<u32>,
    pub override_dns: Option<bool>,
    pub exit_country: Option<String>,
    pub bridges: Vec<String>,
    pub pt_paths: Vec<(String, String)>,
    /// UseBridges 0/1 — if 0, Bridge lines are ignored during merge.
    pub use_bridges: Option<bool>,
    pub kill_switch: Option<bool>,
}

/// Result of merging CLI args with config file values.
pub struct ResolvedConfig {
    pub log_targets: Vec<LogTarget>,
    pub config: Config,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Read and parse a torrc-style config file.
pub fn parse_config_file(path: &Path) -> Result<ConfigFile, ConfigFileError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigFileError {
        path: path.to_path_buf(),
        line_number: 0,
        message: format!("cannot read config file: {e}"),
    })?;
    parse_config_content(&content, path)
}

/// Parse config file content (separated from I/O for testability).
pub fn parse_config_content(content: &str, path: &Path) -> Result<ConfigFile, ConfigFileError> {
    let mut config = ConfigFile::default();

    for (line_idx, raw_line) in content.lines().enumerate() {
        let line_number = line_idx + 1;
        let line = raw_line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split into directive and value at first whitespace
        let (directive, value) = match line.split_once(char::is_whitespace) {
            Some((d, v)) => (d, v.trim()),
            None => (line, ""),
        };

        match directive.to_lowercase().as_str() {
            // --- torrc-compatible directives ---
            "bridge" => {
                require_value(value, directive, path, line_number)?;
                config.bridges.push(value.to_string());
            }
            "clienttransportplugin" => {
                require_value(value, directive, path, line_number)?;
                parse_client_transport_plugin(value, &mut config.pt_paths, path, line_number)?;
            }
            "exitnodes" => {
                require_value(value, directive, path, line_number)?;
                let cc = value.trim_start_matches('{').trim_end_matches('}').trim();
                let upper = parse_country_code(cc).map_err(|e| err(path, line_number, &e))?;
                config.exit_country = Some(upper);
            }
            "usebridges" => {
                config.use_bridges = Some(parse_bool_01(value, directive, path, line_number)?);
            }
            "log" => {
                require_value(value, directive, path, line_number)?;
                parse_log_directive(value, &mut config, path, line_number)?;
            }
            "cachedirectory" | "cachedir" => {
                require_value(value, directive, path, line_number)?;
                config.cache_dir = Some(value.to_string());
            }

            // --- tor-vpn specific directives ---
            "tunname" => {
                require_value(value, directive, path, line_number)?;
                config.tun_name = Some(value.to_string());
            }
            "tunaddress" => {
                require_value(value, directive, path, line_number)?;
                config.tun_address =
                    Some(value.parse::<Ipv4Addr>().map_err(|e| {
                        err(path, line_number, &format!("invalid IP address: {e}"))
                    })?);
            }
            "tunnetmask" => {
                let n: u8 = parse_num(value, directive, path, line_number)?;
                if !(1..=30).contains(&n) {
                    return Err(err(path, line_number, "TunNetmask must be 1-30"));
                }
                config.tun_netmask = Some(n);
            }
            "tunmtu" => {
                let n: u16 = parse_num(value, directive, path, line_number)?;
                if n < 68 {
                    return Err(err(path, line_number, "TunMTU must be at least 68"));
                }
                config.tun_mtu = Some(n);
            }
            "isolation" => {
                require_value(value, directive, path, line_number)?;
                config.isolation = Some(match value.to_lowercase().as_str() {
                    "per-connection" => IsolationPolicy::PerConnection,
                    "per-destination" => IsolationPolicy::PerDestination,
                    "session" => IsolationPolicy::Session,
                    _ => {
                        return Err(err(
                            path,
                            line_number,
                            "Isolation must be per-connection, per-destination, or session",
                        ))
                    }
                });
            }
            "bypasscidr" => {
                require_value(value, directive, path, line_number)?;
                parse_cidr(value).map_err(|e| err(path, line_number, &e))?;
                config.bypass_cidrs.push(value.to_string());
            }
            "maxconnections" => {
                config.max_connections = Some(parse_num(value, directive, path, line_number)?);
            }
            "maxdnsqueries" => {
                config.max_dns_queries = Some(parse_num(value, directive, path, line_number)?);
            }
            "dnscachettl" => {
                config.dns_cache_ttl = Some(parse_num(value, directive, path, line_number)?);
            }
            "overridedns" => {
                config.override_dns = Some(parse_bool_01(value, directive, path, line_number)?);
            }
            "statefile" => {
                require_value(value, directive, path, line_number)?;
                config.state_file = Some(PathBuf::from(value));
            }
            "controlsocket" => {
                require_value(value, directive, path, line_number)?;
                config.socket_path = Some(PathBuf::from(value));
            }
            "statewriteinterval" => {
                let n: u32 = parse_num(value, directive, path, line_number)?;
                if !(1..=3600).contains(&n) {
                    return Err(err(path, line_number, "StateWriteInterval must be 1-3600"));
                }
                config.state_write_interval = Some(n);
            }
            "killswitch" => {
                config.kill_switch = Some(parse_bool_01(value, directive, path, line_number)?);
            }

            _ => {
                // Warn and continue for forward compatibility with newer config files.
                // Strict parsing would catch typos but break when new directives are added.
                eprintln!(
                    "Warning: {}:{}: unknown directive '{}' (ignored)",
                    path.display(),
                    line_number,
                    directive
                );
            }
        }
    }

    Ok(config)
}

/// Parse `Log <severity> [stdout|stderr|file /path]` directive.
fn parse_log_directive(
    value: &str,
    config: &mut ConfigFile,
    path: &Path,
    line_number: usize,
) -> Result<(), ConfigFileError> {
    // Format: Log <severity> [destination]
    // destination: "stderr", "stdout", or "file /path/to/log"
    let (severity, destination) = match value.split_once(char::is_whitespace) {
        Some((s, d)) => (s.trim(), d.trim()),
        None => (value, "stderr"),
    };

    let log_dest = if destination.starts_with("file ") || destination.starts_with("file\t") {
        let file_path = destination["file".len()..].trim();
        if file_path.is_empty() {
            return Err(err(
                path,
                line_number,
                "Log file destination requires a path: Log <severity> file /path/to/log",
            ));
        }
        LogDestination::File(PathBuf::from(file_path))
    } else {
        match destination {
            "stderr" => LogDestination::Stderr,
            "stdout" => LogDestination::Stdout,
            _ => {
                return Err(err(
                    path,
                    line_number,
                    &format!(
                        "unsupported Log destination '{destination}': use 'stderr', 'stdout', or 'file /path'"
                    ),
                ));
            }
        }
    };

    // Map torrc severity names to tracing levels
    // torrc: debug, info, notice, warn, err
    // tracing: trace, debug, info, warn, error
    let mapped = match severity.to_lowercase().as_str() {
        "err" => "error",
        "notice" => "info",
        _ => severity, // debug, info, warn pass through as-is
    };

    config.log_targets.push(LogTarget {
        level: mapped.to_string(),
        destination: log_dest,
    });
    Ok(())
}

/// Parse `ClientTransportPlugin <transports> exec <path> [args...]`.
fn parse_client_transport_plugin(
    value: &str,
    pt_paths: &mut Vec<(String, String)>,
    path: &Path,
    line_number: usize,
) -> Result<(), ConfigFileError> {
    let parts: Vec<&str> = value.splitn(3, char::is_whitespace).collect();
    if parts.len() < 3 {
        return Err(err(
            path,
            line_number,
            "ClientTransportPlugin requires: <transports> exec <path>",
        ));
    }

    let transports_str = parts[0];
    let keyword = parts[1].trim();
    let binary_and_args = parts[2].trim();

    if keyword != "exec" {
        return Err(err(
            path,
            line_number,
            &format!("expected 'exec' keyword in ClientTransportPlugin, got '{keyword}'"),
        ));
    }

    let binary_path = binary_and_args
        .split_whitespace()
        .next()
        .ok_or_else(|| err(path, line_number, "missing binary path after 'exec'"))?;

    for transport in transports_str.split(',') {
        let transport = transport.trim();
        if transport.is_empty() {
            continue;
        }
        pt_paths.push((transport.to_string(), binary_path.to_string()));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn err(path: &Path, line_number: usize, message: &str) -> ConfigFileError {
    ConfigFileError {
        path: path.to_path_buf(),
        line_number,
        message: message.to_string(),
    }
}

fn require_value(
    value: &str,
    directive: &str,
    path: &Path,
    ln: usize,
) -> Result<(), ConfigFileError> {
    if value.is_empty() {
        Err(err(path, ln, &format!("{directive} requires a value")))
    } else {
        Ok(())
    }
}

fn parse_num<T: std::str::FromStr>(
    value: &str,
    directive: &str,
    path: &Path,
    ln: usize,
) -> Result<T, ConfigFileError>
where
    T::Err: fmt::Display,
{
    require_value(value, directive, path, ln)?;
    value
        .parse::<T>()
        .map_err(|e| err(path, ln, &format!("invalid {directive} value: {e}")))
}

fn parse_bool_01(
    value: &str,
    directive: &str,
    path: &Path,
    ln: usize,
) -> Result<bool, ConfigFileError> {
    match value {
        "1" => Ok(true),
        "0" => Ok(false),
        _ => Err(err(path, ln, &format!("{directive} must be 0 or 1"))),
    }
}

// ---------------------------------------------------------------------------
// Merge: config file < env < CLI
// ---------------------------------------------------------------------------

/// Check if a CLI arg was explicitly provided (by command line or env var).
fn was_set(matches: &ArgMatches, id: &str) -> bool {
    matches!(
        matches.value_source(id),
        Some(ValueSource::CommandLine) | Some(ValueSource::EnvVariable)
    )
}

/// Merge CLI args with config file values. Precedence: CLI/env > config file > defaults.
pub fn merge_into_config(
    cli: Cli,
    matches: &ArgMatches,
    file_config: Option<ConfigFile>,
) -> ResolvedConfig {
    let file = file_config.unwrap_or_default();

    let sub_matches = matches.subcommand_matches("start");

    // Helper closures for checking explicit values
    let global_set = |id: &str| -> bool { was_set(matches, id) };
    let start_set = |id: &str| -> bool { sub_matches.is_some_and(|m| was_set(m, id)) };

    // Resolve log targets: CLI --log-level/--log-file override config file Log directives
    let log_targets = if global_set("log_level") || global_set("log_file") {
        let level = cli.log_level;
        let dest = match cli.log_file {
            Some(path) => LogDestination::File(path),
            None => LogDestination::Stderr,
        };
        vec![LogTarget {
            level,
            destination: dest,
        }]
    } else if !file.log_targets.is_empty() {
        file.log_targets
    } else {
        vec![LogTarget {
            level: cli.log_level,
            destination: LogDestination::Stderr,
        }]
    };

    // Resolve global fields
    let state_file = if global_set("state_file") {
        cli.state_file
    } else {
        file.state_file.unwrap_or(cli.state_file)
    };
    let socket_path = if global_set("socket_path") {
        cli.socket_path
    } else {
        file.socket_path.unwrap_or(cli.socket_path)
    };

    let Command::Start(args) = cli.command else {
        unreachable!("merge_into_config called for non-Start command");
    };

    // Scalar fields: CLI/env wins, then config file, then default
    macro_rules! pick {
        ($cli_val:expr, $file_val:expr, $id:expr) => {
            if start_set($id) {
                $cli_val
            } else {
                $file_val.unwrap_or($cli_val)
            }
        };
    }

    // Vec fields: CLI/env wins, then non-empty config file, then CLI default (empty)
    macro_rules! pick_vec {
        ($cli_val:expr, $file_val:expr, $id:expr) => {
            if start_set($id) {
                $cli_val
            } else if !$file_val.is_empty() {
                $file_val
            } else {
                $cli_val
            }
        };
    }

    // Option fields: CLI/env wins, then config file, then CLI default (None)
    macro_rules! pick_opt {
        ($cli_val:expr, $file_val:expr, $id:expr) => {
            if start_set($id) {
                $cli_val
            } else {
                $file_val.or($cli_val)
            }
        };
    }

    let mut bridges = pick_vec!(args.bridge, file.bridges, "bridge");
    let mut pt_paths = pick_vec!(args.pt_path, file.pt_paths, "pt_path");

    // UseBridges 0 disables bridges (only when bridges came from config file, not CLI)
    if file.use_bridges == Some(false) && !start_set("bridge") {
        bridges.clear();
        pt_paths.clear();
    }

    let config = Config {
        tun_name: pick!(args.tun_name, file.tun_name, "tun_name"),
        tun_address: pick!(args.tun_address, file.tun_address, "tun_address"),
        tun_netmask: pick!(args.tun_netmask, file.tun_netmask, "tun_netmask"),
        tun_mtu: pick!(args.tun_mtu, file.tun_mtu, "tun_mtu"),
        isolation: pick!(args.isolation, file.isolation, "isolation"),
        cache_dir: pick!(args.cache_dir, file.cache_dir, "cache_dir"),
        bypass_cidrs: pick_vec!(args.bypass_cidr, file.bypass_cidrs, "bypass_cidr"),
        max_connections: pick!(
            args.max_connections,
            file.max_connections,
            "max_connections"
        ),
        max_dns_queries: pick!(
            args.max_dns_queries,
            file.max_dns_queries,
            "max_dns_queries"
        ),
        dns_cache_ttl: pick!(args.dns_cache_ttl, file.dns_cache_ttl, "dns_cache_ttl"),
        override_dns: pick!(args.override_dns, file.override_dns, "override_dns"),
        exit_country: pick_opt!(args.exit_country, file.exit_country, "exit_country"),
        bridges,
        pt_paths,
        state_file,
        socket_path,
        state_write_interval: pick!(
            args.state_write_interval,
            file.state_write_interval,
            "state_write_interval"
        ),
        kill_switch: pick!(args.kill_switch, file.kill_switch, "kill_switch"),
    };

    ResolvedConfig {
        log_targets,
        config,
    }
}

/// Resolve log targets for non-Start paths (Cleanup).
pub fn resolve_log_targets(
    cli: &Cli,
    matches: &ArgMatches,
    file: Option<&ConfigFile>,
) -> Vec<LogTarget> {
    if was_set(matches, "log_level") || was_set(matches, "log_file") {
        let level = cli.log_level.clone();
        let dest = match &cli.log_file {
            Some(p) => LogDestination::File(p.clone()),
            None => LogDestination::Stderr,
        };
        vec![LogTarget {
            level,
            destination: dest,
        }]
    } else if let Some(targets) = file.map(|f| &f.log_targets).filter(|t| !t.is_empty()) {
        targets.clone()
    } else {
        vec![LogTarget {
            level: cli.log_level.clone(),
            destination: LogDestination::Stderr,
        }]
    }
}

/// Resolve state_file for the Cleanup path (no StartArgs available).
pub fn resolve_state_file(cli: &Cli, matches: &ArgMatches, file: Option<&ConfigFile>) -> PathBuf {
    if was_set(matches, "state_file") {
        cli.state_file.clone()
    } else {
        file.and_then(|f| f.state_file.clone())
            .unwrap_or_else(|| cli.state_file.clone())
    }
}

/// Resolve socket_path for non-Start paths (Status, Refresh, Stop).
pub fn resolve_socket_path(cli: &Cli, matches: &ArgMatches, file: Option<&ConfigFile>) -> PathBuf {
    if was_set(matches, "socket_path") {
        cli.socket_path.clone()
    } else {
        file.and_then(|f| f.socket_path.clone())
            .unwrap_or_else(|| cli.socket_path.clone())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};

    fn parse(content: &str) -> Result<ConfigFile, ConfigFileError> {
        parse_config_content(content, Path::new("<test>"))
    }

    // --- Parser tests ---

    #[test]
    fn test_empty_file() {
        let config = parse("").unwrap();
        assert!(config.log_targets.is_empty());
        assert!(config.bridges.is_empty());
    }

    #[test]
    fn test_comments_only() {
        let config = parse("# comment\n# another\n\n").unwrap();
        assert!(config.tun_name.is_none());
    }

    #[test]
    fn test_tun_name() {
        let config = parse("TunName mytun0").unwrap();
        assert_eq!(config.tun_name.as_deref(), Some("mytun0"));
    }

    #[test]
    fn test_tun_address() {
        let config = parse("TunAddress 10.100.0.1").unwrap();
        assert_eq!(
            config.tun_address,
            Some("10.100.0.1".parse::<Ipv4Addr>().unwrap())
        );
    }

    #[test]
    fn test_tun_netmask() {
        let config = parse("TunNetmask 16").unwrap();
        assert_eq!(config.tun_netmask, Some(16));
    }

    #[test]
    fn test_tun_netmask_out_of_range() {
        assert!(parse("TunNetmask 0").is_err());
        assert!(parse("TunNetmask 31").is_err());
        assert!(parse("TunNetmask 99").is_err());
    }

    #[test]
    fn test_tun_mtu() {
        let config = parse("TunMTU 1400").unwrap();
        assert_eq!(config.tun_mtu, Some(1400));
    }

    #[test]
    fn test_tun_mtu_too_small() {
        assert!(parse("TunMTU 67").is_err());
        assert!(parse("TunMTU 0").is_err());
    }

    #[test]
    fn test_tun_mtu_minimum_valid() {
        let config = parse("TunMTU 68").unwrap();
        assert_eq!(config.tun_mtu, Some(68));
    }

    #[test]
    fn test_isolation() {
        let config = parse("Isolation per-connection").unwrap();
        assert!(matches!(
            config.isolation,
            Some(IsolationPolicy::PerConnection)
        ));

        let config = parse("Isolation per-destination").unwrap();
        assert!(matches!(
            config.isolation,
            Some(IsolationPolicy::PerDestination)
        ));

        let config = parse("Isolation session").unwrap();
        assert!(matches!(config.isolation, Some(IsolationPolicy::Session)));
    }

    #[test]
    fn test_isolation_invalid() {
        assert!(parse("Isolation foobar").is_err());
    }

    #[test]
    fn test_cache_directory() {
        let config = parse("CacheDirectory /tmp/mytor").unwrap();
        assert_eq!(config.cache_dir.as_deref(), Some("/tmp/mytor"));
    }

    #[test]
    fn test_cache_dir_alias() {
        let config = parse("CacheDir /tmp/mytor").unwrap();
        assert_eq!(config.cache_dir.as_deref(), Some("/tmp/mytor"));
    }

    #[test]
    fn test_bypass_cidr_multiple() {
        let config = parse("BypassCIDR 10.0.0.0/8\nBypassCIDR 172.16.0.0/12").unwrap();
        assert_eq!(config.bypass_cidrs, vec!["10.0.0.0/8", "172.16.0.0/12"]);
    }

    #[test]
    fn test_bypass_cidr_invalid() {
        assert!(parse("BypassCIDR foobar").is_err());
    }

    #[test]
    fn test_max_connections() {
        let config = parse("MaxConnections 512").unwrap();
        assert_eq!(config.max_connections, Some(512));
    }

    #[test]
    fn test_max_dns_queries() {
        let config = parse("MaxDNSQueries 128").unwrap();
        assert_eq!(config.max_dns_queries, Some(128));
    }

    #[test]
    fn test_dns_cache_ttl() {
        let config = parse("DNSCacheTTL 300").unwrap();
        assert_eq!(config.dns_cache_ttl, Some(300));
    }

    #[test]
    fn test_override_dns() {
        let config = parse("OverrideDNS 1").unwrap();
        assert_eq!(config.override_dns, Some(true));

        let config = parse("OverrideDNS 0").unwrap();
        assert_eq!(config.override_dns, Some(false));
    }

    #[test]
    fn test_override_dns_invalid() {
        assert!(parse("OverrideDNS true").is_err());
        assert!(parse("OverrideDNS yes").is_err());
    }

    #[test]
    fn test_state_file() {
        let config = parse("StateFile /tmp/state.json").unwrap();
        assert_eq!(config.state_file, Some(PathBuf::from("/tmp/state.json")));
    }

    #[test]
    fn test_control_socket() {
        let config = parse("ControlSocket /tmp/my-vpn.sock").unwrap();
        assert_eq!(config.socket_path, Some(PathBuf::from("/tmp/my-vpn.sock")));
    }

    #[test]
    fn test_control_socket_missing_value() {
        assert!(parse("ControlSocket").is_err());
    }

    #[test]
    fn test_log_with_destination() {
        let config = parse("Log debug stderr").unwrap();
        assert_eq!(config.log_targets.len(), 1);
        assert_eq!(config.log_targets[0].level, "debug");
        assert_eq!(config.log_targets[0].destination, LogDestination::Stderr);
    }

    #[test]
    fn test_log_stdout() {
        let config = parse("Log info stdout").unwrap();
        assert_eq!(config.log_targets.len(), 1);
        assert_eq!(config.log_targets[0].level, "info");
        assert_eq!(config.log_targets[0].destination, LogDestination::Stdout);
    }

    #[test]
    fn test_log_without_destination() {
        let config = parse("Log warn").unwrap();
        assert_eq!(config.log_targets.len(), 1);
        assert_eq!(config.log_targets[0].level, "warn");
        assert_eq!(config.log_targets[0].destination, LogDestination::Stderr);
    }

    #[test]
    fn test_log_file_destination() {
        let config = parse("Log notice file /var/log/tor-vpn.log").unwrap();
        assert_eq!(config.log_targets.len(), 1);
        assert_eq!(config.log_targets[0].level, "info"); // notice -> info
        assert_eq!(
            config.log_targets[0].destination,
            LogDestination::File(PathBuf::from("/var/log/tor-vpn.log"))
        );
    }

    #[test]
    fn test_log_file_no_path() {
        // "Log info file" without a path after "file" should fail
        assert!(parse("Log info file").is_err());
    }

    #[test]
    fn test_log_torrc_severity_mapping() {
        // notice -> info
        let config = parse("Log notice stderr").unwrap();
        assert_eq!(config.log_targets[0].level, "info");
        // err -> error
        let config = parse("Log err stderr").unwrap();
        assert_eq!(config.log_targets[0].level, "error");
        // debug, info, warn pass through
        assert_eq!(
            parse("Log debug stderr").unwrap().log_targets[0].level,
            "debug"
        );
    }

    #[test]
    fn test_log_file_does_not_set_log_file_for_stderr() {
        let config = parse("Log debug stderr").unwrap();
        assert_eq!(config.log_targets[0].destination, LogDestination::Stderr);
    }

    #[test]
    fn test_log_invalid_destination() {
        assert!(parse("Log info /var/log/tor.log").is_err());
    }

    #[test]
    fn test_log_multiple_targets() {
        let config = parse("Log info stderr\nLog debug file /var/log/tor-vpn.log").unwrap();
        assert_eq!(config.log_targets.len(), 2);
        assert_eq!(
            config.log_targets[0],
            LogTarget {
                level: "info".into(),
                destination: LogDestination::Stderr,
            }
        );
        assert_eq!(
            config.log_targets[1],
            LogTarget {
                level: "debug".into(),
                destination: LogDestination::File("/var/log/tor-vpn.log".into()),
            }
        );
    }

    #[test]
    fn test_bridge_lines() {
        let config = parse(
            "Bridge obfs4 192.0.2.1:443 AAAA cert=bbb iat-mode=0\n\
             Bridge obfs4 192.0.2.2:443 BBBB cert=ccc iat-mode=0",
        )
        .unwrap();
        assert_eq!(config.bridges.len(), 2);
        assert!(config.bridges[0].starts_with("obfs4 192.0.2.1:443"));
        assert!(config.bridges[1].starts_with("obfs4 192.0.2.2:443"));
    }

    #[test]
    fn test_client_transport_plugin_single() {
        let config = parse("ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy").unwrap();
        assert_eq!(config.pt_paths.len(), 1);
        assert_eq!(config.pt_paths[0].0, "obfs4");
        assert_eq!(config.pt_paths[0].1, "/usr/bin/obfs4proxy");
    }

    #[test]
    fn test_client_transport_plugin_multiple_transports() {
        let config = parse("ClientTransportPlugin obfs4,webtunnel exec /usr/bin/lyrebird").unwrap();
        assert_eq!(config.pt_paths.len(), 2);
        assert_eq!(config.pt_paths[0].0, "obfs4");
        assert_eq!(config.pt_paths[1].0, "webtunnel");
        assert_eq!(config.pt_paths[0].1, "/usr/bin/lyrebird");
        assert_eq!(config.pt_paths[1].1, "/usr/bin/lyrebird");
    }

    #[test]
    fn test_client_transport_plugin_with_args() {
        let config =
            parse("ClientTransportPlugin snowflake exec /usr/bin/snowflake-client -url https://example.com").unwrap();
        assert_eq!(config.pt_paths.len(), 1);
        assert_eq!(config.pt_paths[0].0, "snowflake");
        assert_eq!(config.pt_paths[0].1, "/usr/bin/snowflake-client");
    }

    #[test]
    fn test_client_transport_plugin_missing_exec() {
        assert!(parse("ClientTransportPlugin obfs4 socks5 127.0.0.1:9050").is_err());
    }

    #[test]
    fn test_client_transport_plugin_too_few_parts() {
        assert!(parse("ClientTransportPlugin obfs4").is_err());
    }

    #[test]
    fn test_exit_nodes() {
        let config = parse("ExitNodes {us}").unwrap();
        assert_eq!(config.exit_country.as_deref(), Some("US"));
    }

    #[test]
    fn test_exit_nodes_uppercase() {
        let config = parse("ExitNodes {DE}").unwrap();
        assert_eq!(config.exit_country.as_deref(), Some("DE"));
    }

    #[test]
    fn test_exit_nodes_invalid() {
        assert!(parse("ExitNodes {USA}").is_err());
    }

    #[test]
    fn test_use_bridges_enabled() {
        let config = parse("UseBridges 1").unwrap();
        assert_eq!(config.use_bridges, Some(true));
    }

    #[test]
    fn test_use_bridges_disabled() {
        let config = parse("UseBridges 0").unwrap();
        assert_eq!(config.use_bridges, Some(false));
    }

    #[test]
    fn test_use_bridges_invalid() {
        assert!(parse("UseBridges yes").is_err());
    }

    #[test]
    fn test_state_write_interval() {
        let config = parse("StateWriteInterval 5").unwrap();
        assert_eq!(config.state_write_interval, Some(5));

        let config = parse("StateWriteInterval 3600").unwrap();
        assert_eq!(config.state_write_interval, Some(3600));
    }

    #[test]
    fn test_state_write_interval_out_of_range() {
        assert!(parse("StateWriteInterval 0").is_err());
        assert!(parse("StateWriteInterval 3601").is_err());
    }

    #[test]
    fn test_state_write_interval_invalid() {
        assert!(parse("StateWriteInterval abc").is_err());
        assert!(parse("StateWriteInterval").is_err());
    }

    #[test]
    fn test_unknown_directive_ignored() {
        // Unknown directives are ignored with a stderr warning (forward-compatible)
        let config = parse("FooBar baz").unwrap();
        assert!(config.tun_name.is_none());
    }

    #[test]
    fn test_missing_value() {
        assert!(parse("TunName").is_err());
        assert!(parse("Bridge").is_err());
    }

    #[test]
    fn test_case_insensitive() {
        let config = parse("tunname foo").unwrap();
        assert_eq!(config.tun_name.as_deref(), Some("foo"));

        let config = parse("TUNNAME bar").unwrap();
        assert_eq!(config.tun_name.as_deref(), Some("bar"));
    }

    #[test]
    fn test_scalar_last_wins() {
        let config = parse("TunName first\nTunName second").unwrap();
        assert_eq!(config.tun_name.as_deref(), Some("second"));
    }

    #[test]
    fn test_full_config() {
        let content = "\
# Full config example
TunName mytun0
TunAddress 10.100.0.1
TunNetmask 16
TunMTU 1400
Isolation per-connection
CacheDirectory /tmp/mytor
BypassCIDR 10.0.0.0/8
BypassCIDR 172.16.0.0/12
MaxConnections 512
MaxDNSQueries 128
DNSCacheTTL 300
OverrideDNS 1
ExitNodes {de}
Log debug stderr
StateFile /tmp/state.json
ControlSocket /tmp/custom-vpn.sock
StateWriteInterval 5
Bridge obfs4 192.0.2.1:443 AAAA cert=bbb iat-mode=0
Bridge obfs4 192.0.2.2:443 BBBB cert=ccc iat-mode=0
UseBridges 1
";
        let config = parse(content).unwrap();
        assert_eq!(config.tun_name.as_deref(), Some("mytun0"));
        assert_eq!(
            config.tun_address,
            Some("10.100.0.1".parse::<Ipv4Addr>().unwrap())
        );
        assert_eq!(config.tun_netmask, Some(16));
        assert_eq!(config.tun_mtu, Some(1400));
        assert!(matches!(
            config.isolation,
            Some(IsolationPolicy::PerConnection)
        ));
        assert_eq!(config.cache_dir.as_deref(), Some("/tmp/mytor"));
        assert_eq!(config.bypass_cidrs, vec!["10.0.0.0/8", "172.16.0.0/12"]);
        assert_eq!(config.max_connections, Some(512));
        assert_eq!(config.max_dns_queries, Some(128));
        assert_eq!(config.dns_cache_ttl, Some(300));
        assert_eq!(config.override_dns, Some(true));
        assert_eq!(config.exit_country.as_deref(), Some("DE"));
        assert_eq!(config.log_targets.len(), 1);
        assert_eq!(config.log_targets[0].level, "debug");
        assert_eq!(config.state_file, Some(PathBuf::from("/tmp/state.json")));
        assert_eq!(
            config.socket_path,
            Some(PathBuf::from("/tmp/custom-vpn.sock"))
        );
        assert_eq!(config.state_write_interval, Some(5));
        assert_eq!(config.bridges.len(), 2);
        assert_eq!(config.use_bridges, Some(true));
    }

    #[test]
    fn test_error_line_number() {
        let content = "TunName foo\n# comment\nTunNetmask abc";
        let e = parse(content).unwrap_err();
        assert_eq!(e.line_number, 3);
    }

    // --- Merge tests ---

    fn get_matches(args: &[&str]) -> ArgMatches {
        Cli::command().get_matches_from(args)
    }

    #[test]
    fn test_merge_cli_overrides_config_file() {
        let matches = get_matches(&[
            "tor-vpn",
            "--log-level",
            "debug",
            "start",
            "--tun-mtu",
            "9000",
        ]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            tun_mtu: Some(1400),
            log_targets: vec![LogTarget {
                level: "warn".into(),
                destination: LogDestination::Stderr,
            }],
            max_connections: Some(512),
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert_eq!(resolved.config.tun_mtu, 9000); // CLI wins
        assert_eq!(resolved.log_targets[0].level, "debug"); // CLI wins
        assert_eq!(resolved.config.max_connections, 512); // config file wins over default
    }

    #[test]
    fn test_merge_config_file_overrides_defaults() {
        let matches = get_matches(&["tor-vpn", "start"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            tun_name: Some("mytun".to_string()),
            dns_cache_ttl: Some(600),
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert_eq!(resolved.config.tun_name, "mytun");
        assert_eq!(resolved.config.dns_cache_ttl, 600);
    }

    #[test]
    fn test_merge_no_config_file() {
        let matches = get_matches(&["tor-vpn", "start"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();

        let resolved = merge_into_config(cli, &matches, None);
        assert_eq!(resolved.config.tun_name, "torvpn0");
        assert_eq!(resolved.config.tun_mtu, 1500);
    }

    #[test]
    fn test_merge_vec_cli_overrides() {
        let matches = get_matches(&["tor-vpn", "start", "--bypass-cidr", "10.0.0.0/8"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            bypass_cidrs: vec!["192.168.0.0/16".to_string()],
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert_eq!(resolved.config.bypass_cidrs, vec!["10.0.0.0/8"]);
    }

    #[test]
    fn test_merge_vec_config_file_used() {
        let matches = get_matches(&["tor-vpn", "start"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            bypass_cidrs: vec!["192.168.0.0/16".to_string()],
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert_eq!(resolved.config.bypass_cidrs, vec!["192.168.0.0/16"]);
    }

    #[test]
    fn test_merge_use_bridges_disabled() {
        let matches = get_matches(&["tor-vpn", "start"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            bridges: vec!["obfs4 192.0.2.1:443 AAAA".to_string()],
            pt_paths: vec![("obfs4".to_string(), "/usr/bin/obfs4proxy".to_string())],
            use_bridges: Some(false),
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert!(resolved.config.bridges.is_empty());
        assert!(resolved.config.pt_paths.is_empty());
    }

    #[test]
    fn test_merge_use_bridges_disabled_but_cli_bridge() {
        let matches = get_matches(&["tor-vpn", "start", "--bridge", "obfs4 192.0.2.1:443 BBBB"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            use_bridges: Some(false),
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        // CLI --bridge overrides UseBridges 0
        assert_eq!(resolved.config.bridges.len(), 1);
    }

    #[test]
    fn test_merge_exit_country_from_config() {
        let matches = get_matches(&["tor-vpn", "start"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            exit_country: Some("DE".to_string()),
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert_eq!(resolved.config.exit_country.as_deref(), Some("DE"));
    }

    #[test]
    fn test_merge_state_write_interval_from_config() {
        let matches = get_matches(&["tor-vpn", "start"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            state_write_interval: Some(5),
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert_eq!(resolved.config.state_write_interval, 5);
    }

    #[test]
    fn test_merge_state_write_interval_cli_overrides() {
        let matches = get_matches(&["tor-vpn", "start", "--state-write-interval", "2"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            state_write_interval: Some(30),
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert_eq!(resolved.config.state_write_interval, 2);
    }

    #[test]
    fn test_merge_exit_country_cli_overrides() {
        let matches = get_matches(&["tor-vpn", "start", "--exit-country", "US"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            exit_country: Some("DE".to_string()),
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert_eq!(resolved.config.exit_country.as_deref(), Some("US"));
    }

    #[test]
    fn test_merge_socket_path_from_config() {
        let matches = get_matches(&["tor-vpn", "start"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            socket_path: Some(PathBuf::from("/tmp/custom.sock")),
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert_eq!(
            resolved.config.socket_path,
            PathBuf::from("/tmp/custom.sock")
        );
    }

    #[test]
    fn test_merge_socket_path_cli_overrides() {
        let matches = get_matches(&["tor-vpn", "--socket-path", "/tmp/cli.sock", "start"]);
        let cli = Cli::from_arg_matches(&matches).unwrap();
        let file = ConfigFile {
            socket_path: Some(PathBuf::from("/tmp/config.sock")),
            ..Default::default()
        };

        let resolved = merge_into_config(cli, &matches, Some(file));
        assert_eq!(resolved.config.socket_path, PathBuf::from("/tmp/cli.sock"));
    }
}
