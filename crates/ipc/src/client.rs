use std::io::Read;
use std::path::Path;
use std::time::Duration;

use crate::protocol::{Request, Response};

/// Default timeout for IPC client operations.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum response payload size in bytes. Prevents memory exhaustion if the
/// daemon (or a fake socket planted before the real daemon starts) sends an
/// unbounded stream of data without a newline terminator.
const MAX_RESPONSE_SIZE: u64 = 65536;

/// Send a request to the daemon via IPC and return the response.
///
/// Blocking (no tokio runtime required) — suitable for CLI and UI tauri commands.
#[cfg(unix)]
pub fn send(socket_path: &Path, request: &Request, timeout: Duration) -> anyhow::Result<Response> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path)
        .map_err(|e| anyhow::anyhow!("cannot connect to daemon: {e}"))?;

    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut json = serde_json::to_string(request)?;
    json.push('\n');

    let mut writer = stream.try_clone()?;
    writer.write_all(json.as_bytes())?;
    writer.flush()?;
    // Shutdown write half to signal end of request
    writer.shutdown(std::net::Shutdown::Write)?;

    let reader = BufReader::new(stream);
    let mut line = String::new();
    // Bound the read to prevent memory exhaustion from a malicious socket
    // planted at the default path before the real daemon starts.
    reader.take(MAX_RESPONSE_SIZE).read_line(&mut line)?;

    if line.trim().is_empty() {
        anyhow::bail!("empty response from daemon");
    }

    let response: Response = serde_json::from_str(line.trim())?;
    Ok(response)
}

/// Send a request to the daemon via named pipe (Windows).
///
/// Uses a background thread + channel for the blocking read so the caller
/// gets a proper timeout instead of hanging indefinitely.
#[cfg(windows)]
pub fn send(pipe_path: &Path, request: &Request, timeout: Duration) -> anyhow::Result<Response> {
    use std::fs::OpenOptions;
    use std::io::{BufRead, BufReader, Write};

    let pipe_name = pipe_path.to_string_lossy().to_string();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pipe_name)
        .map_err(|e| anyhow::anyhow!("cannot connect to daemon: {e}"))?;

    let mut json = serde_json::to_string(request)?;
    json.push('\n');

    let mut writer = file.try_clone()?;
    writer.write_all(json.as_bytes())?;
    writer.flush()?;

    // Read response with timeout via a background thread — Windows named
    // pipes don't support set_read_timeout on File handles.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(file);
        let mut line = String::new();
        // Bound the read to prevent memory exhaustion from a malicious pipe
        let result = reader
            .take(MAX_RESPONSE_SIZE)
            .read_line(&mut line)
            .map(|_| line);
        let _ = tx.send(result);
    });

    let line = rx
        .recv_timeout(timeout)
        .map_err(|_| anyhow::anyhow!("response timeout after {}s", timeout.as_secs()))?
        .map_err(|e| anyhow::anyhow!("read error: {e}"))?;

    if line.trim().is_empty() {
        anyhow::bail!("empty response from daemon");
    }

    let response: Response = serde_json::from_str(line.trim())?;
    Ok(response)
}

/// Try to get status from the daemon. Returns `None` if daemon is unreachable.
pub fn try_status(socket_path: &Path) -> Option<Response> {
    send(socket_path, &Request::Status, DEFAULT_TIMEOUT).ok()
}

/// Try to refresh circuits via IPC. Returns the daemon's message describing
/// what was actually refreshed (differs for session vs per-destination isolation).
pub fn try_refresh(socket_path: &Path) -> anyhow::Result<String> {
    let resp = send(socket_path, &Request::Refresh, DEFAULT_TIMEOUT)?;
    match resp {
        Response::Ok { message } => Ok(message.unwrap_or_else(|| "Circuits refreshed".into())),
        Response::Error { message } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

/// Try to shut down the daemon via IPC.
pub fn try_shutdown(socket_path: &Path) -> anyhow::Result<()> {
    let resp = send(socket_path, &Request::Shutdown, DEFAULT_TIMEOUT)?;
    match resp {
        Response::Ok { .. } => Ok(()),
        Response::Error { message } => anyhow::bail!("{message}"),
        _ => anyhow::bail!("unexpected response"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_try_status_nonexistent_socket() {
        let path = PathBuf::from("/tmp/tor-vpn-test-nonexistent.sock");
        assert!(try_status(&path).is_none());
    }

    #[test]
    fn test_try_refresh_nonexistent_socket() {
        let path = PathBuf::from("/tmp/tor-vpn-test-nonexistent.sock");
        assert!(try_refresh(&path).is_err());
    }

    #[test]
    fn test_try_shutdown_nonexistent_socket() {
        let path = PathBuf::from("/tmp/tor-vpn-test-nonexistent.sock");
        assert!(try_shutdown(&path).is_err());
    }
}
