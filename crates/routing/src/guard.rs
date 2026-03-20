use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, TcpState,
};
use tokio_util::sync::CancellationToken;

use super::NetworkController;

// --- IP extraction helpers ---

/// Push an IP onto the list if it's not loopback, unspecified, or already present.
fn push_unique_non_local(ips: &mut Vec<IpAddr>, ip: IpAddr) {
    if !ip.is_loopback() && !ip.is_unspecified() && !ips.contains(&ip) {
        ips.push(ip);
    }
}

// --- Guard relay detection (via netstat2) ---

/// Extract remote IPs from ESTABLISHED TCP sockets matching any of the given PIDs.
///
/// Pure function (no OS calls) — extracted for testability.
fn filter_established_tcp_ips(sockets: &[SocketInfo], pids: &[u32]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for si in sockets {
        if !si.associated_pids.iter().any(|p| pids.contains(p)) {
            continue;
        }
        if let ProtocolSocketInfo::Tcp(ref tcp) = si.protocol_socket_info {
            if tcp.state == TcpState::Established {
                push_unique_non_local(&mut ips, tcp.remote_addr);
            }
        }
    }
    ips
}

/// Query OS for ESTABLISHED TCP connections belonging to the given PIDs.
fn get_established_tcp_for_pids(pids: &[u32]) -> anyhow::Result<Vec<IpAddr>> {
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let sockets = get_sockets_info(af, ProtocolFlags::TCP)
        .map_err(|e| anyhow::anyhow!("Failed to enumerate sockets: {e}"))?;
    Ok(filter_established_tcp_ips(&sockets, pids))
}

/// Detect Tor guard relay IPs by inspecting our process's TCP connections.
pub fn detect_guard_ips() -> anyhow::Result<Vec<IpAddr>> {
    let pid = std::process::id();
    get_established_tcp_for_pids(&[pid])
}

/// Find PIDs for a pluggable transport binary.
///
/// Matches by exact executable path (`exe()`) or falls back to binary name
/// (`processes_by_exact_name`) when exe is unavailable (permission denied on some platforms).
fn find_pt_pids(binary_path: &str, binary_name: &str) -> Vec<u32> {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};

    let binary_path = std::path::Path::new(binary_path);
    let sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_processes(ProcessRefreshKind::nothing().with_exe(UpdateKind::Always)),
    );

    let mut pids: Vec<u32> = sys
        .processes()
        .values()
        .filter(|p| p.exe().is_some_and(|exe| exe == binary_path))
        .map(|p| p.pid().as_u32())
        .collect();

    // Fallback: match by binary name if exe() returned None for all processes
    // (e.g. insufficient permissions on Linux without CAP_SYS_PTRACE).
    if pids.is_empty() {
        let name = std::ffi::OsStr::new(binary_name);
        pids = sys
            .processes_by_exact_name(name)
            .map(|p| p.pid().as_u32())
            .collect();
    }

    pids
}

/// Detect external IPs used by pluggable transport binaries.
///
/// When bridges with PTs are configured, arti connects to 127.0.0.1 (the PT's local SOCKS proxy).
/// The PT binary makes the real external connection (e.g., to a CDN fronting the bridge).
/// We need bypass routes for these external IPs, not for localhost.
///
/// Finds PT processes by their binary path (from `--pt-path`), then extracts their
/// outgoing TCP connections, filtering loopback and unspecified addresses.
pub fn detect_pt_external_ips(pt_paths: &[(String, String)]) -> anyhow::Result<Vec<IpAddr>> {
    let mut all_pids = Vec::new();

    for (_transport, binary_path) in pt_paths {
        let binary_name = std::path::Path::new(binary_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        if binary_name.is_empty() {
            continue;
        }

        for pid in find_pt_pids(binary_path, binary_name) {
            if !all_pids.contains(&pid) {
                all_pids.push(pid);
            }
        }
    }

    let all_ips = if all_pids.is_empty() {
        Vec::new()
    } else {
        get_established_tcp_for_pids(&all_pids)?
    };

    if all_ips.is_empty() {
        tracing::debug!("No PT external connections found");
    } else {
        tracing::debug!(count = all_ips.len(), "PT external IPs detected");
        for ip in &all_ips {
            tracing::debug!(ip = %ip, "PT external connection");
        }
    }

    Ok(all_ips)
}

/// Periodically detect new Tor guard relay IPs and add bypass routes on the fly.
///
/// Runs every 30 seconds, compares against already-tracked IPs in the RouteManager,
/// and adds `/32` host routes for any new guard connections.
pub async fn run_guard_monitor(
    route_manager: Arc<Mutex<NetworkController>>,
    pt_paths: Option<Vec<(String, String)>>,
    cancel: CancellationToken,
) {
    // Fast polling (every 5s) during the first 2 minutes to catch guard connections
    // that appear right after route installation. Then slow down to 30s.
    const FAST_INTERVAL: Duration = Duration::from_secs(5);
    const SLOW_INTERVAL: Duration = Duration::from_secs(30);
    const FAST_PHASE: Duration = Duration::from_secs(120);

    let start = tokio::time::Instant::now();
    let mut interval = tokio::time::interval(FAST_INTERVAL);
    let mut fast_phase = true;
    // Skip the immediate first tick — initial guards are already handled at startup.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("Guard monitor stopping");
                break;
            }
            _ = interval.tick() => {
                // Switch to slow polling after the initial fast phase
                if fast_phase && start.elapsed() > FAST_PHASE {
                    fast_phase = false;
                    interval = tokio::time::interval(SLOW_INTERVAL);
                    interval.tick().await; // consume immediate first tick
                    tracing::debug!("Guard monitor switching to slow polling (30s)");
                }

                let result = if let Some(ref paths) = pt_paths {
                    let paths = paths.clone();
                    tokio::task::spawn_blocking(move || detect_pt_external_ips(&paths)).await
                } else {
                    tokio::task::spawn_blocking(detect_guard_ips).await
                };
                match result {
                    Ok(Ok(ips)) => {
                        // block_in_place: lock + route syscalls are sync I/O
                        tokio::task::block_in_place(|| {
                            let mut mgr = route_manager.lock().expect("NetworkController lock poisoned");
                            for ip in ips {
                                match mgr.add_guard_ip(ip) {
                                    Ok(true) => {
                                        tracing::debug!(ip = %ip, "New guard relay detected — bypass route added");
                                    }
                                    Ok(false) => {} // already tracked
                                    Err(e) => {
                                        tracing::warn!(ip = %ip, error = %e, "Failed to add guard bypass route");
                                    }
                                }
                            }
                        });
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "Guard IP detection failed");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Guard IP detection task panicked");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests_helpers {
    use super::*;

    #[test]
    fn test_push_unique_non_local_filters_loopback() {
        let mut ips = Vec::new();
        push_unique_non_local(&mut ips, "127.0.0.1".parse().unwrap());
        push_unique_non_local(&mut ips, "::1".parse().unwrap());
        assert!(ips.is_empty());
    }

    #[test]
    fn test_push_unique_non_local_filters_unspecified() {
        let mut ips = Vec::new();
        push_unique_non_local(&mut ips, "0.0.0.0".parse().unwrap());
        push_unique_non_local(&mut ips, "::".parse().unwrap());
        assert!(ips.is_empty());
    }

    #[test]
    fn test_push_unique_non_local_deduplicates() {
        let mut ips = Vec::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        push_unique_non_local(&mut ips, ip);
        push_unique_non_local(&mut ips, ip);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_push_unique_non_local_accepts_public_ip() {
        let mut ips = Vec::new();
        push_unique_non_local(&mut ips, "8.8.8.8".parse().unwrap());
        push_unique_non_local(&mut ips, "2001:db8::1".parse().unwrap());
        assert_eq!(ips.len(), 2);
    }
}

#[cfg(test)]
mod tests_guard_detection {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// Build a SocketInfo with TCP ESTABLISHED state for testing.
    fn tcp_socket(remote_ip: IpAddr, pid: u32, state: TcpState) -> SocketInfo {
        SocketInfo {
            protocol_socket_info: ProtocolSocketInfo::Tcp(netstat2::TcpSocketInfo {
                local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                local_port: 54321,
                remote_addr: remote_ip,
                remote_port: 9001,
                state,
            }),
            associated_pids: vec![pid],
            #[cfg(any(target_os = "linux", target_os = "android"))]
            inode: 0,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            uid: 0,
        }
    }

    #[test]
    fn test_matching_pid_established_collected() {
        let sockets = vec![tcp_socket(
            "1.2.3.4".parse().unwrap(),
            42,
            TcpState::Established,
        )];
        let ips = filter_established_tcp_ips(&sockets, &[42]);
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_non_matching_pid_excluded() {
        let sockets = vec![tcp_socket(
            "1.2.3.4".parse().unwrap(),
            999,
            TcpState::Established,
        )];
        let ips = filter_established_tcp_ips(&sockets, &[42]);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_non_established_state_excluded() {
        let sockets = vec![
            tcp_socket("1.2.3.4".parse().unwrap(), 42, TcpState::Listen),
            tcp_socket("5.6.7.8".parse().unwrap(), 42, TcpState::TimeWait),
            tcp_socket("9.9.9.9".parse().unwrap(), 42, TcpState::SynSent),
        ];
        let ips = filter_established_tcp_ips(&sockets, &[42]);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_loopback_and_unspecified_filtered() {
        let sockets = vec![
            tcp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 42, TcpState::Established),
            tcp_socket(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 42, TcpState::Established),
            tcp_socket(IpAddr::V6(Ipv6Addr::LOCALHOST), 42, TcpState::Established),
            tcp_socket("1.2.3.4".parse().unwrap(), 42, TcpState::Established),
        ];
        let ips = filter_established_tcp_ips(&sockets, &[42]);
        assert_eq!(ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_deduplication() {
        let sockets = vec![
            tcp_socket("1.2.3.4".parse().unwrap(), 42, TcpState::Established),
            tcp_socket("1.2.3.4".parse().unwrap(), 42, TcpState::Established),
        ];
        let ips = filter_established_tcp_ips(&sockets, &[42]);
        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn test_multiple_pids() {
        let sockets = vec![
            tcp_socket("1.2.3.4".parse().unwrap(), 42, TcpState::Established),
            tcp_socket("5.6.7.8".parse().unwrap(), 99, TcpState::Established),
            tcp_socket("9.9.9.9".parse().unwrap(), 777, TcpState::Established),
        ];
        let ips = filter_established_tcp_ips(&sockets, &[42, 99]);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"5.6.7.8".parse::<IpAddr>().unwrap()));
        assert!(!ips.contains(&"9.9.9.9".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_empty_input() {
        let ips = filter_established_tcp_ips(&[], &[42]);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_ipv6_address() {
        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();
        let sockets = vec![tcp_socket(ipv6, 42, TcpState::Established)];
        let ips = filter_established_tcp_ips(&sockets, &[42]);
        assert_eq!(ips, vec![ipv6]);
    }
}
