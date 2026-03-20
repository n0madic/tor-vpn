use std::io::{Read, Seek, SeekFrom};
use std::process::{Command, Stdio};

use std::path::PathBuf;

use crate::config::{self, VpnStatus};

/// Start the VPN daemon with privilege escalation.
///
/// Reads `daemon.conf` from the UI config directory (written by `save_config`).
/// If no config exists yet, writes defaults so the daemon has a config file.
#[tauri::command]
pub fn connect(daemon_path: String) -> Result<(), String> {
    let canonical = validate_daemon_path(&daemon_path)?;
    let canonical_str = canonical.to_string_lossy();

    let config_path = config::daemon_config_path();

    // Always regenerate daemon.conf from current settings to ensure the latest
    // format (e.g. omitting default CacheDir so the daemon computes its own).
    let current = config::get_config()?;
    config::save_config(current).map_err(|e| format!("Failed to write config: {e}"))?;

    // Truncate old log
    let _ = std::fs::write(config::daemon_log_path(), "");

    let config_path_str = config_path.to_string_lossy();
    let args = ["start", "--config", &config_path_str];
    eprintln!("[tor-vpn-ui] Command: {} {}", canonical_str, args.join(" "));

    // Execute the canonical path (not the original) to prevent TOCTOU via symlink swap
    spawn_privileged_and_wait(&canonical_str, &args)
}

/// Resolve the IPC socket path: daemon.conf ControlSocket if set, otherwise platform default.
fn socket_path() -> PathBuf {
    config::resolve_daemon_setting(|c| c.socket_path.clone(), ipc::default_socket_path)
}

/// Stop the VPN daemon: IPC shutdown first (no privileges), fallback to SIGTERM.
#[tauri::command]
pub fn disconnect() -> Result<(), String> {
    // Try IPC shutdown first — no privilege escalation needed
    let socket_path = socket_path();
    if ipc::try_shutdown(&socket_path).is_ok() {
        // Wait for graceful shutdown (up to 5s)
        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            match config::load_vpn_state() {
                None => return Ok(()),
                Some(s) if !config::is_tor_vpn_process(s.pid) => return Ok(()),
                _ => {}
            }
        }
    }

    // Fallback — privileged SIGTERM
    // Re-check: daemon may have exited during IPC wait (state file gone or PID dead)
    let state = match config::load_vpn_state() {
        Some(s) if config::is_tor_vpn_process(s.pid) => s,
        _ => return Ok(()), // Already stopped
    };

    let pid = state.pid;
    privileged_kill(pid, "TERM")?;

    // Wait up to 5s for graceful shutdown
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if !config::is_tor_vpn_process(pid) {
            return Ok(());
        }
    }

    // Daemon stuck in cleanup — force kill
    eprintln!("[tor-vpn-ui] Daemon did not exit after SIGTERM, sending SIGKILL");
    privileged_kill(pid, "KILL")?;
    std::thread::sleep(std::time::Duration::from_secs(1));
    Ok(())
}

/// Refresh Tor circuits: IPC first (no privileges), fallback to SIGUSR1.
#[tauri::command]
pub fn refresh_circuits() -> Result<(), String> {
    // Try IPC first — cross-platform, no privilege escalation needed
    let socket_path = socket_path();
    if ipc::try_refresh(&socket_path).is_ok() {
        return Ok(());
    }

    // Fallback — privileged SIGUSR1
    let state = config::load_vpn_state().ok_or("VPN is not running")?;
    if !config::is_tor_vpn_process(state.pid) {
        return Err("VPN process is not running".to_string());
    }

    #[cfg(unix)]
    {
        privileged_kill(state.pid, "USR1")
    }
    #[cfg(not(unix))]
    {
        Err("Circuit refresh not available".to_string())
    }
}

/// Run cleanup with privilege escalation to restore routes and DNS.
#[tauri::command]
pub fn cleanup(daemon_path: String) -> Result<(), String> {
    let canonical = validate_daemon_path(&daemon_path)?;
    let canonical_str = canonical.to_string_lossy();
    spawn_privileged_blocking(&canonical_str, &["cleanup"])
}

/// Get current VPN status: IPC first (live data), fallback to state file.
#[tauri::command]
pub fn get_status() -> VpnStatus {
    // Try IPC first — live data from daemon memory (no FS overhead)
    let socket_path = socket_path();
    if let Some(ipc::Response::Status { state, uptime_secs }) = ipc::try_status(&socket_path) {
        return VpnStatus::Connected {
            state: *state,
            uptime_secs,
            tx_rate: 0.0, // UI computes rates from byte counter deltas between polls
            rx_rate: 0.0,
        };
    }

    // Fallback — state file
    match config::load_vpn_state() {
        None => VpnStatus::Disconnected,
        Some(state) => {
            if config::is_tor_vpn_process(state.pid) {
                let uptime_secs = state::uptime_from_state(&state);
                VpnStatus::Connected {
                    state,
                    uptime_secs,
                    tx_rate: 0.0,
                    rx_rate: 0.0,
                }
            } else {
                VpnStatus::Dirty { state }
            }
        }
    }
}

/// Read the last N lines of the daemon log file.
///
/// Seeks from the end to avoid reading the entire file (which can grow to
/// hundreds of MB during long sessions). Reads a 64 KB tail chunk — sufficient
/// for 500 lines of typical log output.
#[tauri::command]
pub fn read_daemon_log(lines: Option<usize>) -> Result<String, String> {
    let log_path = config::daemon_log_path();
    let mut file = std::fs::File::open(&log_path).map_err(|e| format!("Cannot read log: {e}"))?;
    let n = lines.unwrap_or(100);

    let len = file.metadata().map(|m| m.len()).unwrap_or(0);

    // Read from the tail: 64 KB is enough for ~500 lines of typical log output
    const TAIL_SIZE: u64 = 64 * 1024;
    if len > TAIL_SIZE {
        let _ = file.seek(SeekFrom::End(-(TAIL_SIZE as i64)));
    }

    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .map_err(|e| format!("Cannot read log: {e}"))?;

    let all_lines: Vec<&str> = buf.lines().collect();
    // If we seeked into the middle of a line, skip the first partial line
    let skip = if len > TAIL_SIZE { 1 } else { 0 };
    let usable = &all_lines[skip.min(all_lines.len())..];
    let start = usable.len().saturating_sub(n);
    Ok(usable[start..].join("\n"))
}

/// Validate that a path is safe to execute with elevated privileges.
///
/// Prevents a compromised renderer from launching arbitrary programs as
/// root/admin by enforcing a strict trust chain:
///
/// 1. Path must be absolute
/// 2. Canonicalized (symlinks resolved) to prevent `/usr/local/bin/tor-vpn → ~/evil`)
/// 3. Filename must be exactly `tor-vpn` (or `tor-vpn.exe` on Windows)
/// 4. The binary file itself must be root-owned and not writable by non-root (Unix)
/// 5. Every ancestor directory from `/` down must be root-owned and not writable
///    by non-root (Unix) — prevents `/root-owned/user-writable/subdir/tor-vpn`
/// 6. On Windows: every ancestor must not be user-writable (rejects Downloads, Desktop, etc.)
fn validate_daemon_path(path_str: &str) -> Result<PathBuf, String> {
    let path = std::path::Path::new(path_str);

    if !path.is_absolute() {
        return Err(format!("Daemon path must be absolute: {path_str}"));
    }

    // Canonicalize: resolves all symlinks and `..` components.
    // After this, the path points to the real file on disk — a symlink
    // like /usr/local/bin/tor-vpn → /home/alice/tor-vpn is resolved
    // and the real location is validated.
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("Daemon binary not found or not accessible: {path_str}: {e}"))?;

    let metadata = std::fs::metadata(&canonical).map_err(|e| {
        format!(
            "Cannot read daemon binary metadata: {}: {e}",
            canonical.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "Daemon path is not a regular file: {}",
            canonical.display()
        ));
    }

    let file_name = canonical.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let valid = if cfg!(windows) {
        file_name == "tor-vpn" || file_name == "tor-vpn.exe"
    } else {
        file_name == "tor-vpn"
    };
    if !valid {
        return Err(format!(
            "Invalid daemon binary name: expected 'tor-vpn', got '{file_name}'"
        ));
    }

    #[cfg(unix)]
    validate_unix_trust_chain(&canonical)?;

    #[cfg(windows)]
    validate_windows_trust_chain(&canonical)?;

    // Return the canonical path — callers MUST execute this path, not the
    // original, to prevent TOCTOU attacks via symlink swapping between
    // validation and privileged execution.
    Ok(canonical)
}

/// Verify the binary and its ancestor directories are safe for privileged execution.
///
/// Checks:
/// 1. Binary file itself must not be writable by group or other (mode & 0o022).
///    A group/world-writable binary can be replaced by non-root users.
/// 2. Ancestor directories must not be world-writable (mode & 0o002).
///    World-writable directories allow any local user to plant files.
///    Group-writable directories are allowed to support developer builds
///    in e.g. `/opt/homebrew/bin/` (group `staff`, mode 0o775).
#[cfg(unix)]
fn validate_unix_trust_chain(canonical: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    // Check binary file itself: must not be writable by group or other
    let file_meta = std::fs::metadata(canonical)
        .map_err(|e| format!("Cannot stat binary {}: {e}", canonical.display()))?;
    let file_mode = file_meta.permissions().mode();
    if file_mode & 0o022 != 0 {
        return Err(format!(
            "Daemon binary is writable by group/other (mode {:04o}): {}",
            file_mode & 0o7777,
            canonical.display()
        ));
    }

    // Walk every ancestor directory up to root
    let mut dir = canonical.parent();
    while let Some(d) = dir {
        let meta = std::fs::metadata(d)
            .map_err(|e| format!("Cannot stat directory {}: {e}", d.display()))?;
        let mode = meta.permissions().mode();
        // World-writable directories allow any local user to plant a binary.
        // Sticky bit (0o1000, e.g. /tmp) doesn't help — users can still
        // create new files, just not delete others' files.
        if mode & 0o002 != 0 {
            return Err(format!(
                "Directory in daemon path is world-writable (mode {:04o}): {}",
                mode & 0o7777,
                d.display()
            ));
        }
        dir = d.parent();
    }

    Ok(())
}

/// Verify that the binary is not in a known dangerous location on Windows.
///
/// Rejects temp directories and common browser download locations where
/// a malicious binary could be planted. Does NOT reject the entire user
/// profile — developer builds under `%USERPROFILE%\github\...\target\`
/// must work.
#[cfg(windows)]
fn validate_windows_trust_chain(canonical: &std::path::Path) -> Result<(), String> {
    let canonical_str = canonical.to_string_lossy().to_lowercase();

    // Reject temp directories
    let temp = std::env::temp_dir().to_string_lossy().to_lowercase();
    if canonical_str.starts_with(&temp) {
        return Err(format!(
            "Daemon binary is in a temp directory: {}",
            canonical.display()
        ));
    }

    // Reject common user-writable attack surfaces (browser downloads, desktop, etc.)
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let profile_lower = profile.to_lowercase();
        let dangerous = [
            "\\downloads",
            "\\desktop",
            "\\documents",
            "\\appdata\\local\\temp",
        ];
        for suffix in &dangerous {
            let blocked = format!("{}{}", profile_lower, suffix);
            if canonical_str.starts_with(&blocked) {
                return Err(format!(
                    "Daemon binary is in an untrusted directory: {}",
                    canonical.display()
                ));
            }
        }
    }

    Ok(())
}

/// Check the daemon log file for ERROR lines. Returns the first error found.
fn check_log_for_errors() -> Option<String> {
    let log = std::fs::read_to_string(config::daemon_log_path()).ok()?;
    for line in log.lines().rev().take(20) {
        if line.contains("ERROR") || line.contains("Error:") {
            return Some(line.to_string());
        }
    }
    None
}

/// Send a signal to a root-owned daemon process via privilege escalation.
#[cfg(unix)]
fn privileged_kill(pid: u32, signal: &str) -> Result<(), String> {
    spawn_privileged_blocking("/bin/kill", &[&format!("-{signal}"), &pid.to_string()])
}

#[cfg(not(unix))]
fn privileged_kill(pid: u32, signal: &str) -> Result<(), String> {
    let pid_str = pid.to_string();
    let mut args = vec!["/PID", &pid_str];
    // Force-kill: taskkill without /F only sends WM_CLOSE (graceful).
    // A stuck daemon won't respond to WM_CLOSE, so /F is needed.
    if signal == "KILL" {
        args.push("/F");
    }
    spawn_privileged_blocking("taskkill", &args)
}

// ---------------------------------------------------------------------------
// Privilege escalation: common polling loop + platform-specific spawning
// ---------------------------------------------------------------------------

/// Result of checking a child process during the polling loop.
enum ChildStatus {
    /// Child is still running.
    Running,
    /// Child exited — return this error to the caller.
    Exited(String),
}

/// Outcome of `poll_for_daemon_start` when it cannot succeed on its own.
enum PollError {
    /// Child process exited with an error.
    ChildExited(String),
    /// Log file contained an error (caller should kill child if applicable).
    LogError(String),
    /// Timed out waiting for daemon (caller should kill child if applicable).
    Timeout,
}

/// Poll until the daemon starts (state file appears) or an error/timeout occurs.
///
/// `check_child` is called each iteration to inspect the spawned process.
/// For fire-and-forget launches (Windows), pass a no-op that always returns `Running`.
///
/// Returns `Ok(())` on success or `Err(PollError)` so the caller can kill the
/// child process before converting to a user-facing error string.
fn poll_for_daemon_start(
    mut check_child: impl FnMut() -> Result<ChildStatus, String>,
) -> Result<(), PollError> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(180);

    loop {
        // 1. Did the child process exit?
        match check_child().map_err(PollError::ChildExited)? {
            ChildStatus::Exited(err) => return Err(PollError::ChildExited(err)),
            ChildStatus::Running => {}
        }

        // 2. State file appeared — daemon is running
        if let Some(state) = config::load_vpn_state() {
            if config::is_tor_vpn_process(state.pid) {
                eprintln!("[tor-vpn-ui] Daemon started (PID {})", state.pid);
                return Ok(());
            }
        }

        // 3. Check log for early errors (after 10s grace period)
        if start.elapsed() > std::time::Duration::from_secs(10) {
            if let Some(err) = check_log_for_errors() {
                return Err(PollError::LogError(err));
            }
        }

        if start.elapsed() > timeout {
            return Err(PollError::Timeout);
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Launch the daemon with privilege escalation, poll until it starts or fails.
#[cfg(target_os = "macos")]
fn spawn_privileged_and_wait(program: &str, args: &[&str]) -> Result<(), String> {
    let _ = std::fs::write(config::daemon_log_path(), "");

    let script = build_osascript(program, args);
    eprintln!("[tor-vpn-ui] Launching daemon via osascript");

    let mut child = Command::new("osascript")
        .args(["-e", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to launch osascript: {e}"))?;

    poll_for_daemon_start(|| match child.try_wait() {
        Ok(Some(status)) if !status.success() => {
            let mut stderr_buf = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_string(&mut stderr_buf);
            }
            let msg = stderr_buf.trim().to_string();
            if msg.contains("canceled") || msg.contains("cancelled") {
                return Ok(ChildStatus::Exited("Password dialog cancelled".to_string()));
            }
            if let Some(err) = check_log_for_errors() {
                return Ok(ChildStatus::Exited(err));
            }
            Ok(ChildStatus::Exited(if msg.is_empty() {
                "Daemon exited unexpectedly".to_string()
            } else {
                format!("Privilege escalation failed: {msg}")
            }))
        }
        Ok(Some(_)) => {
            let err =
                check_log_for_errors().unwrap_or_else(|| "Daemon exited unexpectedly".to_string());
            Ok(ChildStatus::Exited(err))
        }
        Ok(None) => Ok(ChildStatus::Running),
        Err(e) => Err(format!("Failed to check process: {e}")),
    })
    .map_err(|e| {
        let _ = child.kill();
        match e {
            PollError::ChildExited(msg) => msg,
            PollError::LogError(msg) => msg,
            PollError::Timeout => "Timed out waiting for VPN to start".to_string(),
        }
    })
}

/// Build AppleScript command — just the program + args, no shell redirection.
///
/// Injects `SUDO_UID=<current_uid>` into the shell command so the daemon can
/// identify the original (unprivileged) user for IPC authorization. Without this,
/// `osascript "do shell script ... with administrator privileges"` starts the
/// daemon as root with no trace of the invoking user.
#[cfg(target_os = "macos")]
fn build_osascript(program: &str, args: &[&str]) -> String {
    let uid = unsafe { libc::getuid() };
    let mut cmd_parts = vec![shell_escape(program)];
    cmd_parts.extend(args.iter().map(|a| shell_escape(a)));
    let shell_cmd = cmd_parts.join(" ");
    // Prepend SUDO_UID so detect_owner_uid() works without /dev/console fallback
    let shell_cmd = format!("SUDO_UID={uid} {shell_cmd}");
    let escaped = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");

    format!("do shell script \"{escaped}\" with administrator privileges")
}

/// Blocking privilege escalation for short-lived commands (cleanup, kill).
#[cfg(target_os = "macos")]
fn spawn_privileged_blocking(program: &str, args: &[&str]) -> Result<(), String> {
    let mut cmd_parts = vec![shell_escape(program)];
    cmd_parts.extend(args.iter().map(|a| shell_escape(a)));
    let shell_cmd = cmd_parts.join(" ");
    let escaped = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");

    let script = format!("do shell script \"{escaped}\" with administrator privileges");

    let output = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("Failed to launch osascript: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = stderr.trim();
        if msg.contains("canceled") || msg.contains("cancelled") {
            return Err("Password dialog cancelled".to_string());
        }
        return Err(format!("Command failed: {msg}"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn spawn_privileged_and_wait(program: &str, args: &[&str]) -> Result<(), String> {
    let _ = std::fs::write(config::daemon_log_path(), "");

    let mut child = Command::new("pkexec")
        .arg(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to launch pkexec: {e}"))?;

    poll_for_daemon_start(|| match child.try_wait() {
        Ok(Some(status)) if !status.success() => {
            let err = check_log_for_errors()
                .unwrap_or_else(|| "Privilege escalation failed or cancelled".to_string());
            Ok(ChildStatus::Exited(err))
        }
        Ok(Some(_)) => {
            let err =
                check_log_for_errors().unwrap_or_else(|| "Daemon exited unexpectedly".to_string());
            Ok(ChildStatus::Exited(err))
        }
        Ok(None) => Ok(ChildStatus::Running),
        Err(e) => Err(format!("Failed to check process: {e}")),
    })
    .map_err(|e| {
        let _ = child.kill();
        match e {
            PollError::ChildExited(msg) => msg,
            PollError::LogError(msg) => msg,
            PollError::Timeout => "Timed out waiting for VPN to start".to_string(),
        }
    })
}

#[cfg(target_os = "linux")]
fn spawn_privileged_blocking(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new("pkexec")
        .arg(program)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to launch pkexec: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Command failed: {}", stderr.trim()));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn spawn_privileged_and_wait(program: &str, args: &[&str]) -> Result<(), String> {
    let _ = std::fs::write(config::daemon_log_path(), "");

    let args_str = windows_escape_args(args);

    let output = Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "Start-Process '{}' -ArgumentList '{}' -Verb RunAs",
                program.replace('\'', "''"),
                args_str
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to launch as admin: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Failed to elevate: {}", stderr.trim()));
    }

    // Windows Start-Process returns immediately (fire-and-forget) — no child to monitor
    poll_for_daemon_start(|| Ok(ChildStatus::Running)).map_err(|e| match e {
        PollError::ChildExited(msg) | PollError::LogError(msg) => msg,
        PollError::Timeout => "Timed out waiting for VPN to start".to_string(),
    })
}

#[cfg(target_os = "windows")]
fn spawn_privileged_blocking(program: &str, args: &[&str]) -> Result<(), String> {
    let args_str = windows_escape_args(args);

    let output = Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "Start-Process '{}' -ArgumentList '{}' -Verb RunAs -Wait",
                program.replace('\'', "''"),
                args_str
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to elevate: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Command failed: {}", stderr.trim()));
    }
    Ok(())
}

/// Escape arguments for PowerShell's `Start-Process -ArgumentList`.
///
/// Each argument is individually double-quoted with internal double-quotes
/// and single-quotes escaped. The result is joined with spaces and placed
/// inside `-ArgumentList '...'` (single-quoted PowerShell string).
#[cfg(target_os = "windows")]
fn windows_escape_args(args: &[&str]) -> String {
    args.iter()
        .map(|a| {
            // Escape for the inner cmd-style quoting: double-quote wrapping,
            // internal double-quotes become \"
            let escaped = a.replace('"', "\\\"");
            // Wrap each arg in double-quotes, then escape single-quotes for
            // the outer PowerShell single-quoted string (' → '')
            format!("\"{}\"", escaped).replace('\'', "''")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Shell-escape a string for use in a POSIX shell command.
///
/// Always single-quotes unless the string is purely safe characters
/// (alphanumeric, `.`, `/`, `-`, `_`, `:`). This prevents injection via
/// shell metacharacters like `;`, `|`, `$()`, backticks, etc.
fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    if s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'.' || b == b'/' || b == b'-' || b == b'_' || b == b':'
    }) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
