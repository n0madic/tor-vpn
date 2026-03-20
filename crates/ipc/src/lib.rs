mod client;
mod protocol;
mod server;

pub use client::{send, try_refresh, try_shutdown, try_status};
pub use protocol::{Request, Response};
pub use server::{detect_owner_uid, run_ipc_server, IpcCommand};

use std::path::PathBuf;

/// Return the platform-specific default IPC socket path.
///
/// Delegates to [`state::default_socket_path()`] — kept here for API compatibility.
pub fn default_socket_path() -> PathBuf {
    state::default_socket_path()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_socket_path_not_empty() {
        let path = default_socket_path();
        assert!(!path.as_os_str().is_empty());
    }

    #[test]
    fn test_default_socket_path_contains_tor_vpn() {
        let path = default_socket_path();
        let s = path.to_string_lossy();
        assert!(s.contains("tor-vpn"), "path should contain 'tor-vpn': {s}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_default_socket_path_macos() {
        assert_eq!(default_socket_path(), PathBuf::from("/tmp/tor-vpn.sock"));
    }
}
