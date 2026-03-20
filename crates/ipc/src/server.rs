use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::protocol::{Request, Response};

/// Maximum request payload size in bytes. Prevents memory exhaustion from
/// oversized single-line payloads sent by malicious or buggy clients.
const MAX_REQUEST_SIZE: usize = 4096;

/// A command received over IPC with a channel to send the response back.
pub struct IpcCommand {
    pub request: Request,
    pub reply: tokio::sync::oneshot::Sender<Response>,
}

/// Run the IPC server on a Unix domain socket.
///
/// Accepts connections, reads one JSON-line request per connection, dispatches
/// via `cmd_tx`, and writes the response back. Cleans up the socket file on
/// cancellation.
///
/// `owner_uid` is the UID of the user who launched the daemon (from `SUDO_UID`
/// or `PKEXEC_UID`). Destructive commands (Shutdown) require the peer to be
/// root (UID 0) or the owner. `None` means only root is allowed.
#[cfg(unix)]
pub async fn run_ipc_server(
    socket_path: PathBuf,
    cmd_tx: mpsc::Sender<IpcCommand>,
    cancel: CancellationToken,
    owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    // Remove stale socket file (left over from crash/SIGKILL)
    cleanup_stale_socket(&socket_path);

    let listener = tokio::net::UnixListener::bind(&socket_path)?;

    // Make socket world-accessible so unprivileged users can query status.
    // Destructive commands are gated by peer credential checks.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o666);
        std::fs::set_permissions(&socket_path, perms)?;
    }

    tracing::debug!(path = %socket_path.display(), "IPC server listening");

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let tx = cmd_tx.clone();
                        let cancel = cancel.clone();
                        tokio::spawn(handle_unix_connection(stream, tx, cancel, owner_uid));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "IPC accept failed");
                    }
                }
            }
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    tracing::debug!("IPC server stopped");
    Ok(())
}

/// Handle a single Unix domain socket connection.
#[cfg(unix)]
async fn handle_unix_connection(
    stream: tokio::net::UnixStream,
    cmd_tx: mpsc::Sender<IpcCommand>,
    cancel: CancellationToken,
    owner_uid: Option<u32>,
) {
    // Get peer credentials before splitting the stream
    let peer_uid = stream.peer_cred().ok().map(|c| c.uid());

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let response = match handle_request(&mut reader, &cmd_tx, &cancel, peer_uid, owner_uid).await {
        Ok(resp) => resp,
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    };

    if let Ok(mut json) = serde_json::to_string(&response) {
        json.push('\n');
        let _ = writer.write_all(json.as_bytes()).await;
        let _ = writer.shutdown().await;
    }
}

/// Read one bounded JSON-line request, authorize it, dispatch, and return the response.
///
/// The read is capped at [`MAX_REQUEST_SIZE`] bytes to prevent memory exhaustion.
/// Destructive commands (Shutdown) require peer authorization.
async fn handle_request<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    cmd_tx: &mpsc::Sender<IpcCommand>,
    cancel: &CancellationToken,
    peer_uid: Option<u32>,
    owner_uid: Option<u32>,
) -> anyhow::Result<Response> {
    // Read one line with bounded buffer and timeout (5s)
    let line = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(Response::Error { message: "shutting down".into() }),
        result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_bounded_line(reader),
        ) => match result {
            Ok(Ok(line)) => line,
            Ok(Err(e)) => anyhow::bail!("{e}"),
            Err(_) => anyhow::bail!("request timeout"),
        },
    };

    let request: Request =
        serde_json::from_str(line.trim()).map_err(|e| anyhow::anyhow!("invalid request: {e}"))?;

    // Authorization: Shutdown and Refresh require root or daemon owner.
    // Status is read-only and allowed for all local users.
    if matches!(request, Request::Shutdown | Request::Refresh)
        && !is_authorized(peer_uid, owner_uid)
    {
        return Ok(Response::Error {
            message: "permission denied: only root or the daemon owner can perform this action"
                .into(),
        });
    }

    // Dispatch to the main event loop and wait for response
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let cmd = IpcCommand {
        request,
        reply: reply_tx,
    };

    cmd_tx
        .send(cmd)
        .await
        .map_err(|_| anyhow::anyhow!("daemon busy"))?;

    // Wait for response with timeout (10s)
    match tokio::time::timeout(std::time::Duration::from_secs(10), reply_rx).await {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(_)) => Ok(Response::Error {
            message: "handler dropped".into(),
        }),
        Err(_) => Ok(Response::Error {
            message: "response timeout".into(),
        }),
    }
}

/// Read a single newline-terminated line from `reader`, up to [`MAX_REQUEST_SIZE`] bytes.
/// Returns an error if the payload exceeds the limit or if no data is received.
async fn read_bounded_line<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<String> {
    let mut buf = vec![0u8; MAX_REQUEST_SIZE];
    let mut pos = 0;

    loop {
        if pos >= MAX_REQUEST_SIZE {
            anyhow::bail!("request too large (max {MAX_REQUEST_SIZE} bytes)");
        }
        let n = reader.read(&mut buf[pos..]).await?;
        if n == 0 {
            // EOF
            break;
        }
        // Check for newline in the newly read bytes
        if let Some(nl) = buf[pos..pos + n].iter().position(|&b| b == b'\n') {
            pos += nl + 1;
            break;
        }
        pos += n;
    }

    if pos == 0 {
        anyhow::bail!("empty request");
    }

    Ok(String::from_utf8_lossy(&buf[..pos]).into_owned())
}

/// Check if a peer is authorized for destructive commands.
///
/// Authorized if: peer UID is root (0), or matches the daemon owner UID
/// (the user who `sudo`'d / `pkexec`'d to start the daemon).
///
/// When peer credentials are unavailable (Windows named pipes), defaults to
/// deny. This prevents any local user from shutting down or refreshing the
/// VPN through the named pipe. On Windows, the UI falls back to privileged
/// `taskkill` for disconnect, and `tor-vpn stop` requires running as the
/// same user or admin.
fn is_authorized(peer_uid: Option<u32>, owner_uid: Option<u32>) -> bool {
    let Some(uid) = peer_uid else {
        return false; // Peer info unavailable — deny (fail-closed)
    };
    if uid == 0 {
        return true; // root
    }
    if let Some(owner) = owner_uid {
        if uid == owner {
            return true; // daemon owner
        }
    }
    false
}

/// Remove a stale socket file from a previous crash.
///
/// Only removes the path if it is actually a Unix domain socket (not a regular
/// file, symlink, directory, etc.) to prevent use as an arbitrary file-deletion
/// primitive when the socket path is user-configurable.
#[cfg(unix)]
fn cleanup_stale_socket(path: &Path) {
    use std::os::unix::fs::FileTypeExt;

    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return, // doesn't exist or inaccessible — nothing to clean
    };

    // Only proceed if the path is a Unix socket — refuse to delete anything else
    if !meta.file_type().is_socket() {
        tracing::warn!(
            path = %path.display(),
            "IPC socket path exists but is not a Unix socket — refusing to remove"
        );
        return;
    }

    // Try to connect — if it succeeds, another daemon is running
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => {
            tracing::warn!(
                path = %path.display(),
                "IPC socket is live — another daemon may be running"
            );
        }
        Err(_) => {
            // Dead socket — safe to remove
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Detect the UID of the user who launched the daemon via privilege escalation.
///
/// Checks `SUDO_UID` (set by sudo; also injected by the UI's `build_osascript`
/// on macOS) and `PKEXEC_UID` (set by PolicyKit on Linux).
///
/// Returns `None` if the daemon was started directly as root without any
/// detectable privilege escalation (only root can then control via IPC).
pub fn detect_owner_uid() -> Option<u32> {
    for var in ["SUDO_UID", "PKEXEC_UID"] {
        if let Ok(val) = std::env::var(var) {
            if let Ok(uid) = val.parse::<u32>() {
                return Some(uid);
            }
        }
    }
    None
}

/// Run the IPC server on a Windows named pipe.
#[cfg(windows)]
pub async fn run_ipc_server(
    pipe_path: PathBuf,
    cmd_tx: mpsc::Sender<IpcCommand>,
    cancel: CancellationToken,
    _owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name = pipe_path.to_string_lossy().to_string();

    tracing::debug!(path = %pipe_name, "IPC server listening (named pipe)");

    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(&pipe_name)?;

        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = server.connect() => {
                if let Err(e) = result {
                    tracing::warn!(error = %e, "Named pipe connect failed");
                    continue;
                }
                let tx = cmd_tx.clone();
                let cancel = cancel.clone();
                tokio::spawn(handle_pipe_connection(server, tx, cancel));
            }
        }
    }

    tracing::debug!("IPC server stopped");
    Ok(())
}

/// Handle a single named pipe connection (Windows).
///
/// Uses `GetNamedPipeClientProcessId` to verify the peer. The named pipe's
/// default ACL restricts connections to the creator's user, SYSTEM, and
/// Administrators — so a verified PID means the client passed OS-level
/// access control. We treat this as root-equivalent for `is_authorized`.
#[cfg(windows)]
async fn handle_pipe_connection(
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    cmd_tx: mpsc::Sender<IpcCommand>,
    cancel: CancellationToken,
) {
    // Verify peer via PID before splitting the pipe.
    // If the OS confirms a real client process, treat it as authorized
    // (the pipe ACL already gated who can connect).
    let peer_uid = if get_pipe_client_pid(&pipe).is_some() {
        Some(0) // ACL-verified → root-equivalent
    } else {
        None // Can't verify → is_authorized will deny
    };

    let (reader, mut writer) = tokio::io::split(pipe);
    let mut reader = BufReader::new(reader);

    let response = match handle_request(&mut reader, &cmd_tx, &cancel, peer_uid, None).await {
        Ok(resp) => resp,
        Err(e) => Response::Error {
            message: e.to_string(),
        },
    };

    if let Ok(mut json) = serde_json::to_string(&response) {
        json.push('\n');
        let _ = writer.write_all(json.as_bytes()).await;
        let _ = writer.shutdown().await;
    }
}

/// Get the client process ID from a named pipe connection.
///
/// Calls `GetNamedPipeClientProcessId` from kernel32.dll to identify the
/// peer process. Returns `None` if the call fails (shouldn't happen for
/// a connected pipe).
#[cfg(windows)]
fn get_pipe_client_pid(pipe: &tokio::net::windows::named_pipe::NamedPipeServer) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;

    extern "system" {
        fn GetNamedPipeClientProcessId(
            pipe: *mut std::ffi::c_void,
            client_process_id: *mut u32,
        ) -> i32;
    }

    let mut pid: u32 = 0;
    let handle = pipe.as_raw_handle();
    // SAFETY: handle is a valid named pipe server handle from an accepted connection,
    // and pid is a valid aligned pointer to a u32.
    let ok = unsafe { GetNamedPipeClientProcessId(handle, &mut pid) };
    if ok != 0 && pid > 0 {
        Some(pid)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handle_request_valid_status() {
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<IpcCommand>(1);
        let cancel = CancellationToken::new();

        let input = b"{\"command\":\"status\"}\n";
        let mut reader = &input[..];

        // Spawn handler that responds to the command
        let handle = tokio::spawn(async move {
            if let Some(cmd) = cmd_rx.recv().await {
                assert!(matches!(cmd.request, Request::Status));
                let _ = cmd.reply.send(Response::Ok { message: None });
            }
        });

        let resp = handle_request(&mut reader, &cmd_tx, &cancel, None, None)
            .await
            .unwrap();
        assert!(matches!(resp, Response::Ok { .. }));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_handle_request_invalid_json() {
        let (cmd_tx, _cmd_rx) = mpsc::channel::<IpcCommand>(1);
        let cancel = CancellationToken::new();

        let input = b"not json\n";
        let mut reader = &input[..];

        let resp = handle_request(&mut reader, &cmd_tx, &cancel, None, None).await;
        assert!(resp.is_err());
    }

    #[tokio::test]
    async fn test_handle_request_empty() {
        let (cmd_tx, _cmd_rx) = mpsc::channel::<IpcCommand>(1);
        let cancel = CancellationToken::new();

        let input = b"";
        let mut reader = &input[..];

        let resp = handle_request(&mut reader, &cmd_tx, &cancel, None, None).await;
        assert!(resp.is_err());
    }

    #[tokio::test]
    async fn test_handle_request_cancelled() {
        let (cmd_tx, _cmd_rx) = mpsc::channel::<IpcCommand>(1);
        let cancel = CancellationToken::new();
        cancel.cancel();

        // Reader that would block forever
        let (_, rx) = tokio::io::duplex(64);
        let mut reader = rx;

        let resp = handle_request(&mut reader, &cmd_tx, &cancel, None, None)
            .await
            .unwrap();
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[tokio::test]
    async fn test_handle_request_oversized_rejected() {
        let (cmd_tx, _cmd_rx) = mpsc::channel::<IpcCommand>(1);
        let cancel = CancellationToken::new();

        // Create a payload larger than MAX_REQUEST_SIZE without a newline
        let input = vec![b'A'; MAX_REQUEST_SIZE + 1];
        let mut reader = &input[..];

        let resp = handle_request(&mut reader, &cmd_tx, &cancel, None, None).await;
        assert!(resp.is_err());
        assert!(resp.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_is_authorized_root() {
        assert!(is_authorized(Some(0), None));
        assert!(is_authorized(Some(0), Some(501)));
    }

    #[test]
    fn test_is_authorized_owner() {
        assert!(is_authorized(Some(501), Some(501)));
    }

    #[test]
    fn test_is_authorized_other_user_denied() {
        assert!(!is_authorized(Some(502), Some(501)));
        assert!(!is_authorized(Some(502), None));
    }

    #[test]
    fn test_is_authorized_no_peer_info() {
        // No peer info (e.g., Windows) — deny (fail-closed)
        assert!(!is_authorized(None, None));
        assert!(!is_authorized(None, Some(501)));
    }

    #[test]
    fn test_detect_owner_uid_from_env() {
        // When neither SUDO_UID nor PKEXEC_UID is set, returns None
        // (actual env-dependent test would be flaky, just verify logic)
        let result = detect_owner_uid();
        // Result depends on environment — just ensure it doesn't panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_read_bounded_line_normal() {
        let input = b"{\"command\":\"status\"}\n";
        let mut reader = &input[..];
        let line = read_bounded_line(&mut reader).await.unwrap();
        assert_eq!(line.trim(), "{\"command\":\"status\"}");
    }

    #[tokio::test]
    async fn test_read_bounded_line_empty() {
        let input = b"";
        let mut reader = &input[..];
        assert!(read_bounded_line(&mut reader).await.is_err());
    }
}
