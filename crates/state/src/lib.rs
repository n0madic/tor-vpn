use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Persisted state for recovering routes/DNS after SIGKILL or force-stop.
/// Written to a tmpfs-backed path so it is automatically cleared on reboot
/// (when routes are also cleared by the kernel).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VpnState {
    pub pid: u32,
    pub tun_name: String,
    pub original_gateway: String,
    pub original_interface: String,
    pub guard_ips: Vec<IpAddr>,
    pub bypass_cidrs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_service_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_dns: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_dns_ip: Option<String>,
    /// DNS configuration method used on Linux ("resolvectl", "resolvconf", or "resolv.conf").
    /// Determines how to restore DNS on cleanup. None for macOS or pre-upgrade state files.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dns_method: Option<String>,
    /// Exit country code (ISO 3166-1 alpha-2) if configured.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub exit_country: Option<String>,
    /// Cumulative bytes sent through Tor (upload). Updated periodically by the daemon.
    #[serde(default)]
    pub tx_bytes: u64,
    /// Cumulative bytes received from Tor (download). Updated periodically by the daemon.
    #[serde(default)]
    pub rx_bytes: u64,
    /// Unix timestamp (seconds since epoch) when the VPN session started.
    /// Used by the UI to compute uptime without IPC (state-file fallback).
    #[serde(default)]
    pub started_at: u64,
}

/// Check if a PID belongs to a still-running tor-vpn process.
///
/// Uses `sysinfo` for cross-platform process lookup: checks both existence and
/// command name in a single call. Mitigates PID reuse race — after SIGKILL, the
/// PID may be recycled by another process.
pub fn is_tor_vpn_process(pid: u32) -> bool {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[Pid::from_u32(pid)]),
        false,
        ProcessRefreshKind::nothing(),
    );

    sys.process(Pid::from_u32(pid))
        .is_some_and(|p| p.name().to_string_lossy().contains("tor-vpn"))
}

/// The operational status of the VPN as determined from the state file.
pub enum VpnStatus {
    /// No state file exists — VPN is not running and system is clean.
    Clean,
    /// State file exists and the process is alive — VPN is running.
    Running(VpnState),
    /// State file exists but the process is dead — orphaned routes need cleanup.
    Dirty(VpnState),
}

/// Load the VPN state from the state file.
/// Returns `Ok(None)` if the file does not exist.
/// Returns `Err` if the file exists but cannot be read or parsed.
pub fn load(path: &Path) -> anyhow::Result<Option<VpnState>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read state file {}: {e}", path.display()))?;
    let state: VpnState = serde_json::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Corrupt state file {}: {e}", path.display()))?;
    Ok(Some(state))
}

/// Determine the current VPN status by reading the state file and checking PID liveness.
pub fn get_status(path: &Path) -> anyhow::Result<VpnStatus> {
    match load(path)? {
        None => Ok(VpnStatus::Clean),
        Some(state) => {
            if is_tor_vpn_process(state.pid) {
                Ok(VpnStatus::Running(state))
            } else {
                Ok(VpnStatus::Dirty(state))
            }
        }
    }
}

/// Atomically write the VPN state to disk for SIGKILL recovery.
/// Best-effort: logs a warning on failure.
///
/// Uses exclusive file creation (`O_CREAT | O_EXCL`) on Unix to prevent
/// symlink-following attacks: a local attacker could place a symlink at
/// the predictable temp path, causing the root daemon to overwrite an
/// arbitrary file. `create_new(true)` refuses to open symlinks.
pub fn save(state: &VpnState, path: &Path) {
    let tmp_path = path.with_extension("json.tmp");
    match serde_json::to_string_pretty(state) {
        Ok(json) => {
            let result = safe_write_new(&tmp_path, json.as_bytes())
                .and_then(|()| std::fs::rename(&tmp_path, path));
            if let Err(e) = result {
                tracing::warn!(error = %e, "Failed to save state file — SIGKILL recovery unavailable");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to serialize state — SIGKILL recovery unavailable");
        }
    }
}

/// Create a file at `path` and open it safely, without following symlinks.
///
/// On Unix: removes the path first, then creates with `O_CREAT | O_EXCL`
/// (via `create_new`). This prevents a TOCTOU symlink race — if an attacker
/// places a symlink between remove and create, `O_EXCL` will fail because
/// the symlink itself exists. File mode is set to 0o644.
///
/// On non-Unix: falls back to normal `File::create`.
pub fn safe_create_file(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::remove_file(path);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::File::create(path)
    }
}

/// Write content to a file path without following symlinks.
///
/// Removes the old file, then creates exclusively (`O_CREAT | O_EXCL` on Unix)
/// to prevent local symlink attacks when the daemon runs as root with
/// predictable temp file paths.
fn safe_write_new(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = safe_create_file(path)?;
    file.write_all(content)
}

/// Compute uptime in seconds from `VpnState.started_at` (Unix timestamp).
/// Returns 0 if `started_at` is not set (old state files written before this field was added).
pub fn uptime_from_state(state: &VpnState) -> u64 {
    if state.started_at == 0 {
        return 0;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now.saturating_sub(state.started_at)
}

/// Remove the state file after successful route cleanup.
pub fn delete_file(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Return the platform-specific default path for the state file.
///
/// Uses hardcoded `/tmp/` on macOS (not `std::env::temp_dir()` which is per-user
/// for root — the daemon runs as root but clients read the state file as regular users).
/// Prefers `/run` on Linux (tmpfs, cleared on reboot). Falls back to
/// `std::env::temp_dir()` which maps to `%TEMP%` on Windows.
pub fn default_state_file() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        return PathBuf::from("/tmp/tor-vpn-state.json");
    }
    #[cfg(target_os = "linux")]
    {
        let run = PathBuf::from("/run");
        if run.exists() {
            return run.join("tor-vpn-state.json");
        }
    }
    #[allow(unreachable_code)]
    std::env::temp_dir().join("tor-vpn-state.json")
}

/// Return the platform-specific default path for the IPC control socket.
///
/// Uses hardcoded `/tmp/` on macOS (not `std::env::temp_dir()` which is per-user
/// for root — the daemon runs as root but clients connect as regular users).
pub fn default_socket_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/tmp/tor-vpn.sock")
    }
    #[cfg(target_os = "linux")]
    {
        let run = PathBuf::from("/run");
        if run.exists() {
            return run.join("tor-vpn.sock");
        }
        PathBuf::from("/tmp/tor-vpn.sock")
    }
    #[cfg(target_os = "windows")]
    {
        PathBuf::from(r"\\.\pipe\tor-vpn")
    }
}

/// Return the platform-specific default path for the Tor cache directory.
///
/// Uses hardcoded `/tmp/` on macOS (not `std::env::temp_dir()` which is per-user —
/// the daemon runs as root but the UI resolves defaults as a regular user).
/// Uses `/tmp` on Linux, `%TEMP%` on Windows.
pub fn default_tor_cache_dir() -> String {
    #[cfg(target_os = "macos")]
    {
        return "/tmp/tor-vpn-cache".to_string();
    }
    #[allow(unreachable_code)]
    std::env::temp_dir()
        .join("tor-vpn-cache")
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_vpn_state_round_trip() {
        let state = VpnState {
            pid: 12345,
            tun_name: "utun7".to_string(),
            original_gateway: "192.168.1.1".to_string(),
            original_interface: "en0".to_string(),
            guard_ips: vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()],
            bypass_cidrs: vec!["10.0.0.0/8".to_string()],
            dns_service_name: Some("Wi-Fi".to_string()),
            original_dns: Some("8.8.8.8\n8.8.4.4".to_string()),
            configured_dns_ip: Some("10.200.0.2".to_string()),
            dns_method: None,
            exit_country: None,
            tx_bytes: 0,
            rx_bytes: 0,
            started_at: 0,
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let restored: VpnState = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.pid, 12345);
        assert_eq!(restored.tun_name, "utun7");
        assert_eq!(restored.original_gateway, "192.168.1.1");
        assert_eq!(restored.original_interface, "en0");
        assert_eq!(restored.guard_ips.len(), 2);
        assert_eq!(restored.bypass_cidrs, ["10.0.0.0/8"]);
        assert_eq!(restored.dns_service_name.as_deref(), Some("Wi-Fi"));
        assert_eq!(restored.original_dns.as_deref(), Some("8.8.8.8\n8.8.4.4"));
        assert_eq!(restored.configured_dns_ip.as_deref(), Some("10.200.0.2"));
        assert!(restored.dns_method.is_none());
    }

    #[test]
    fn test_vpn_state_optional_fields_none() {
        let state = VpnState {
            pid: 1,
            tun_name: "tun0".to_string(),
            original_gateway: "10.0.0.1".to_string(),
            original_interface: "eth0".to_string(),
            guard_ips: vec![],
            bypass_cidrs: vec![],
            dns_service_name: None,
            original_dns: None,
            configured_dns_ip: None,
            dns_method: None,
            exit_country: None,
            tx_bytes: 0,
            rx_bytes: 0,
            started_at: 0,
        };

        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains("dns_service_name"));
        assert!(!json.contains("original_dns"));
        assert!(!json.contains("configured_dns_ip"));
        assert!(!json.contains("dns_method"));

        let restored: VpnState = serde_json::from_str(&json).unwrap();
        assert!(restored.dns_service_name.is_none());
        assert!(restored.original_dns.is_none());
        assert!(restored.configured_dns_ip.is_none());
        assert!(restored.dns_method.is_none());
    }

    #[test]
    fn test_vpn_state_backward_compat_no_dns_method() {
        let json = r#"{"pid":1,"tun_name":"tun0","original_gateway":"10.0.0.1","original_interface":"eth0","guard_ips":[],"bypass_cidrs":[],"configured_dns_ip":"10.200.0.2","original_dns":"nameserver 8.8.8.8\n"}"#;
        let state: VpnState = serde_json::from_str(json).unwrap();
        assert!(state.dns_method.is_none());
        assert_eq!(state.configured_dns_ip.as_deref(), Some("10.200.0.2"));
    }

    #[test]
    fn test_vpn_state_dns_method_round_trip() {
        let state = VpnState {
            pid: 1,
            tun_name: "tun0".to_string(),
            original_gateway: "10.0.0.1".to_string(),
            original_interface: "eth0".to_string(),
            guard_ips: vec![],
            bypass_cidrs: vec![],
            dns_service_name: None,
            original_dns: None,
            configured_dns_ip: Some("10.200.0.2".to_string()),
            dns_method: Some("resolvectl".to_string()),
            exit_country: None,
            tx_bytes: 0,
            rx_bytes: 0,
            started_at: 0,
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("resolvectl"));
        let restored: VpnState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.dns_method.as_deref(), Some("resolvectl"));
    }

    #[test]
    fn test_is_tor_vpn_process_nonexistent_pid() {
        assert!(!is_tor_vpn_process(u32::MAX - 1));
    }

    #[test]
    fn test_is_tor_vpn_process_current_pid_is_not_tor_vpn() {
        assert!(!is_tor_vpn_process(std::process::id()));
    }

    #[test]
    fn test_default_state_file_is_in_temp() {
        let path = default_state_file();
        let path_str = path.to_string_lossy();

        assert!(
            path_str.starts_with("/tmp/") || path_str.starts_with("/run/") || {
                let temp_dir = std::env::temp_dir().to_string_lossy().to_string();
                path_str.starts_with(&temp_dir)
            },
            "state file should be in /tmp, /run, or temp dir: {path_str}"
        );
        assert!(path_str.ends_with("tor-vpn-state.json"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_default_state_file_macos() {
        assert_eq!(
            default_state_file(),
            PathBuf::from("/tmp/tor-vpn-state.json")
        );
    }

    #[test]
    fn test_load_nonexistent() {
        let path = PathBuf::from("/tmp/tor-vpn-test-load-nonexistent.json");
        assert!(load(&path).unwrap().is_none());
    }

    #[test]
    fn test_load_corrupt_json() {
        let path = std::env::temp_dir().join("tor-vpn-test-load-corrupt.json");
        std::fs::write(&path, "not valid json").unwrap();
        let result = load(&path);
        std::fs::remove_file(&path).ok();
        assert!(result.is_err());
    }

    #[test]
    fn test_load_valid_state() {
        let path = std::env::temp_dir().join("tor-vpn-test-load-valid.json");
        let state = VpnState {
            pid: 99999,
            tun_name: "utun7".to_string(),
            original_gateway: "192.168.1.1".to_string(),
            original_interface: "en0".to_string(),
            guard_ips: vec!["1.2.3.4".parse().unwrap()],
            bypass_cidrs: vec![],
            dns_service_name: None,
            original_dns: None,
            configured_dns_ip: None,
            dns_method: None,
            exit_country: None,
            tx_bytes: 0,
            rx_bytes: 0,
            started_at: 0,
        };
        let json = serde_json::to_string_pretty(&state).unwrap();
        std::fs::write(&path, &json).unwrap();
        let loaded = load(&path).unwrap().unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(loaded.pid, 99999);
        assert_eq!(loaded.tun_name, "utun7");
    }

    #[test]
    fn test_get_status_clean() {
        let path = PathBuf::from("/tmp/tor-vpn-test-status-clean.json");
        assert!(matches!(get_status(&path).unwrap(), VpnStatus::Clean));
    }

    #[test]
    fn test_get_status_dirty() {
        let path = std::env::temp_dir().join("tor-vpn-test-status-dirty.json");
        let state = VpnState {
            pid: u32::MAX - 1,
            tun_name: "tun0".to_string(),
            original_gateway: "10.0.0.1".to_string(),
            original_interface: "eth0".to_string(),
            guard_ips: vec![],
            bypass_cidrs: vec![],
            dns_service_name: None,
            original_dns: None,
            configured_dns_ip: None,
            dns_method: None,
            exit_country: None,
            tx_bytes: 0,
            rx_bytes: 0,
            started_at: 0,
        };
        let json = serde_json::to_string_pretty(&state).unwrap();
        std::fs::write(&path, &json).unwrap();
        let status = get_status(&path).unwrap();
        std::fs::remove_file(&path).ok();
        assert!(matches!(status, VpnStatus::Dirty(_)));
    }
}
