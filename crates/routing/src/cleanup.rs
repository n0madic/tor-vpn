//! SIGKILL recovery: clean up orphaned routes and DNS left behind by a killed tor-vpn instance.
//!
//! Moved from `state.rs` — these functions depend on routing operations
//! (`cleanup_routes`, `restore_dns_settings`, `get_current_dns`) which live
//! in this crate, while the state types/persistence remain in the `state` crate.

use std::path::Path;

use state::VpnState;

/// Clean up orphaned routes and DNS left behind by a previously killed tor-vpn instance.
///
/// Returns `Ok(true)` if orphaned state was found and cleaned up,
/// `Ok(false)` if no orphaned state exists.
pub fn cleanup_orphaned(path: &Path) -> anyhow::Result<bool> {
    let state = match state::load(path)? {
        Some(s) => s,
        None => return Ok(false),
    };

    // Don't clean up routes of a still-running tor-vpn instance
    if state::is_tor_vpn_process(state.pid) {
        anyhow::bail!(
            "tor-vpn (PID {}) is still running — stop it first (SIGTERM) before cleanup",
            state.pid
        );
    }

    tracing::info!(
        pid = state.pid,
        "Found orphaned state — cleaning up routes and DNS"
    );

    // 1. Restore DNS (only if DNS was configured — resolvectl/resolvconf don't save
    // original_dns since cleanup is label/interface-based, but configured_dns_ip is always set)
    let mut errors = Vec::new();
    if state.configured_dns_ip.is_some() {
        if let Err(e) = restore_dns_if_ours(&state) {
            errors.push(format!("DNS restore: {e}"));
        }
    }

    // 2. Remove routes, collecting errors
    let original_gateway: std::net::IpAddr = state
        .original_gateway
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid gateway IP in state file: {e}"))?;
    let route_errors = crate::cleanup_routes(
        &state.tun_name,
        &state.guard_ips,
        &state.bypass_cidrs,
        original_gateway,
    );

    errors.extend(route_errors);

    // 3. Only delete state file if all operations succeeded
    if errors.is_empty() {
        let _ = std::fs::remove_file(path);
        tracing::info!("Orphaned routes and DNS restored successfully");
        Ok(true)
    } else {
        for err in &errors {
            tracing::warn!("Cleanup error: {err}");
        }
        tracing::warn!(
            "Partial cleanup failure — state file kept for retry with `sudo tor-vpn cleanup`"
        );
        Err(anyhow::anyhow!(
            "Partial cleanup: {} operation(s) failed — state file preserved for retry",
            errors.len()
        ))
    }
}

/// Restore DNS only if the current system DNS still matches what we configured.
/// Prevents overwriting intentional user changes made after the crash.
/// Delegates the actual restoration to `crate::restore_dns_settings`.
///
/// Returns `Ok(())` on success or if DNS was never configured (--keep-dns).
/// Returns `Err` with a description if DNS restoration fails.
pub fn restore_dns_if_ours(state: &VpnState) -> Result<(), String> {
    let configured_ip = match &state.configured_dns_ip {
        Some(ip) => ip,
        None => return Ok(()), // --keep-dns was used, DNS was never modified
    };

    let do_restore = |service: Option<&str>, original: Option<&str>| -> Result<(), String> {
        crate::restore_dns_settings(
            service,
            original,
            state.dns_method.as_deref(),
            &state.tun_name,
        )
        .map_err(|e| format!("failed to restore DNS: {e}"))
    };

    #[cfg(target_os = "macos")]
    {
        let service = match &state.dns_service_name {
            Some(s) => s,
            None => return Ok(()),
        };
        match crate::get_current_dns(service) {
            Ok(current)
                if current
                    .trim()
                    .lines()
                    .any(|l| l.trim() == configured_ip.as_str()) =>
            {
                return do_restore(
                    state.dns_service_name.as_deref(),
                    state.original_dns.as_deref(),
                );
            }
            Ok(_) => {
                tracing::info!("DNS was changed since crash — skipping DNS restoration");
                return Ok(());
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to check current DNS — skipping restoration");
                return Ok(());
            }
        }
    }

    #[cfg(target_os = "linux")]
    match state.dns_method.as_deref() {
        Some("resolvectl") | Some("resolvconf") => {
            // resolvectl: auto-reverts when TUN interface is destroyed (SIGKILL-safe).
            // resolvconf: entry persists — remove it explicitly.
            // Both are safe to call unconditionally (no-op if already clean).
            return do_restore(None, None);
        }
        _ => {
            // Direct /etc/resolv.conf — verify our DNS is still active before overwriting
            let current = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
            let expected_line = format!("nameserver {configured_ip}");
            if current.trim().lines().any(|l| l.trim() == expected_line) {
                return do_restore(None, state.original_dns.as_deref());
            } else {
                tracing::info!("DNS was changed since crash — skipping DNS restoration");
                return Ok(());
            }
        }
    }

    // Windows: netsh does NOT auto-revert DNS when interface is removed.
    // Always try to restore DNS during SIGKILL recovery.
    #[cfg(target_os = "windows")]
    if state.dns_method.as_deref() == Some("netsh") {
        return do_restore(None, state.original_dns.as_deref());
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// With --keep-dns, DNS fields are all None — cleanup must skip DNS.
    #[test]
    fn test_vpn_state_keep_dns_no_dns_fields() {
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

        // restore_dns_if_ours should return Ok(()) without doing anything
        // (no configured_dns_ip means --keep-dns was used)
        restore_dns_if_ours(&state).unwrap(); // should not panic or fail
    }

    #[test]
    fn test_cleanup_orphaned_no_state_file() {
        let path = PathBuf::from("/tmp/tor-vpn-test-nonexistent-state.json");
        assert!(!cleanup_orphaned(&path).unwrap());
    }
}
