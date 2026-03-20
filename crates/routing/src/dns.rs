//! Platform-specific DNS configuration and restoration.
//!
//! - macOS: native SystemConfiguration API (service detection, DNS get/set)
//! - Linux: resolvectl → resolvconf → /etc/resolv.conf fallback chain
//! - Windows: DNS override disabled (.onion blocked at dnsapi.dll level)

// Command is used on Linux (resolvconf) but not macOS or Windows.
#[cfg(target_os = "linux")]
use std::process::Command;

// --- Linux DNS configuration helpers ---

/// Check if systemd-resolved is active on this system.
#[cfg(target_os = "linux")]
pub(super) fn is_systemd_resolved_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "systemd-resolved"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Try to configure DNS via resolvectl (systemd-resolved).
/// Sets per-interface DNS on the TUN device and makes it the default DNS route.
/// Returns `true` on success.
#[cfg(target_os = "linux")]
pub(super) fn configure_resolvectl_dns(tun_name: &str, dns_ip: &str) -> bool {
    if !is_systemd_resolved_active() {
        return false;
    }
    if super::run_cmd("resolvectl", &["dns", tun_name, dns_ip]).is_err() {
        return false;
    }
    if super::run_cmd("resolvectl", &["default-route", tun_name, "true"]).is_err() {
        // DNS was set but default-route failed — revert
        let _ = super::run_cmd("resolvectl", &["revert", tun_name]);
        return false;
    }
    true
}

/// Try to configure DNS via resolvconf (openresolv or systemd shim).
/// Adds a nameserver entry under a label tied to our TUN interface.
/// Returns `true` on success.
#[cfg(target_os = "linux")]
pub(super) fn configure_resolvconf_dns(tun_name: &str, dns_ip: &str) -> bool {
    use std::io::Write;

    let label = format!("{tun_name}.tor-vpn");
    let input = format!("nameserver {dns_ip}\n");

    Command::new("resolvconf")
        .args(["-a", &label])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(input.as_bytes())?;
            }
            child.wait()
        })
        .map(|s| s.success())
        .unwrap_or(false)
}

// --- macOS network service detection ---

/// Detect the network service name for a specific interface (e.g. "en0" → "Wi-Fi").
///
/// Uses native SystemConfiguration API (`SCNetworkServiceCopyAll` +
/// `SCNetworkInterfaceGetBSDName`) instead of parsing `networksetup` CLI output.
/// Returns `None` if the interface is not found.
#[cfg(target_os = "macos")]
pub(super) fn detect_network_service_for_interface(interface: &str) -> Option<String> {
    use objc2_core_foundation::CFString;
    use objc2_system_configuration::{SCNetworkService, SCPreferences};

    let name = CFString::from_str("tor-vpn");
    let prefs = SCPreferences::new(None, &name, None)?;
    let services = SCNetworkService::all(&prefs)?;
    // SAFETY: SCNetworkServiceCopyAll returns a CFArray of SCNetworkService objects.
    let typed = unsafe { services.cast_unchecked::<SCNetworkService>() };

    for i in 0..typed.len() {
        let Some(service) = typed.get(i) else {
            continue;
        };
        let Some(iface) = service.interface() else {
            continue;
        };
        let Some(bsd) = iface.bsd_name() else {
            continue;
        };
        if bsd.to_string() == interface {
            return service.name().map(|n| n.to_string());
        }
    }
    None
}

/// Detect the active network service by name heuristic.
///
/// Uses native SystemConfiguration API to enumerate services.
/// Tries well-known service names first, then falls back to the first
/// enabled service in the list.
#[cfg(target_os = "macos")]
pub(super) fn detect_network_service() -> anyhow::Result<String> {
    use objc2_core_foundation::CFString;
    use objc2_system_configuration::{SCNetworkService, SCPreferences};

    let label = CFString::from_str("tor-vpn");
    let prefs = SCPreferences::new(None, &label, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to create SCPreferences"))?;
    let services = SCNetworkService::all(&prefs)
        .ok_or_else(|| anyhow::anyhow!("Failed to enumerate network services"))?;
    // SAFETY: SCNetworkServiceCopyAll returns a CFArray of SCNetworkService objects.
    let typed = unsafe { services.cast_unchecked::<SCNetworkService>() };

    // Collect service names for preferred-name lookup
    let service_names: Vec<String> = (0..typed.len())
        .filter_map(|i| typed.get(i))
        .filter_map(|s| s.name().map(|n| n.to_string()))
        .collect();

    for preferred in &["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"] {
        if service_names.iter().any(|n| n == *preferred) {
            return Ok(preferred.to_string());
        }
    }

    // Fall back to first enabled service
    for i in 0..typed.len() {
        let Some(service) = typed.get(i) else {
            continue;
        };
        if service.enabled() {
            if let Some(svc_name) = service.name() {
                return Ok(svc_name.to_string());
            }
        }
    }

    Err(anyhow::anyhow!("No network service found"))
}

/// Get the current DNS servers for a network service on macOS.
///
/// Uses `netdev` to query the default interface's DNS servers.
/// Falls back to native SystemConfiguration API (`SCNetworkServiceCopyProtocol` +
/// `SCNetworkProtocolGetConfiguration`) if netdev returns empty
/// (some configurations only expose DNS at the service level).
#[cfg(target_os = "macos")]
pub fn get_current_dns(service: &str) -> anyhow::Result<String> {
    // Try netdev first — native API, no CLI
    if let Ok(iface) = netdev::interface::get_default_interface() {
        if !iface.dns_servers.is_empty() {
            return Ok(iface
                .dns_servers
                .iter()
                .map(|ip| ip.to_string())
                .collect::<Vec<_>>()
                .join("\n"));
        }
    }

    // Fallback: SystemConfiguration native API — read DNS config for the service
    get_current_dns_via_sc(service)
}

/// Read manually configured DNS servers for a network service via SystemConfiguration.
///
/// Returns "There aren't any DNS Servers" when no manual DNS is configured
/// (i.e. using DHCP-provided DNS), matching `networksetup -getdnsservers` behavior.
#[cfg(target_os = "macos")]
fn get_current_dns_via_sc(service: &str) -> anyhow::Result<String> {
    use objc2_core_foundation::{CFArray, CFString};
    use objc2_system_configuration::{
        kSCNetworkProtocolTypeDNS, kSCPropNetDNSServerAddresses, SCNetworkService, SCPreferences,
    };

    let no_dns = "There aren't any DNS Servers";

    let label = CFString::from_str("tor-vpn");
    let Some(prefs) = SCPreferences::new(None, &label, None) else {
        return Ok(no_dns.to_string());
    };
    let Some(services) = SCNetworkService::all(&prefs) else {
        return Ok(no_dns.to_string());
    };
    // SAFETY: SCNetworkServiceCopyAll returns a CFArray of SCNetworkService objects.
    let typed = unsafe { services.cast_unchecked::<SCNetworkService>() };

    // Find service by name
    let target = (0..typed.len())
        .filter_map(|i| typed.get(i))
        .find(|s| s.name().map(|n| n.to_string()).as_deref() == Some(service));
    let Some(svc) = target else {
        return Ok(no_dns.to_string());
    };

    // Get DNS protocol configuration for this service
    // SAFETY: kSCNetworkProtocolTypeDNS is a valid static CFString constant.
    let dns_proto_type = unsafe { kSCNetworkProtocolTypeDNS };
    let Some(dns_protocol) = svc.protocol(dns_proto_type) else {
        return Ok(no_dns.to_string());
    };
    let Some(dns_config) = dns_protocol.configuration() else {
        return Ok(no_dns.to_string());
    };

    // Get ServerAddresses from the config dictionary
    // SAFETY: kSCPropNetDNSServerAddresses is a valid static CFString constant.
    // DNS config dictionary has CFString keys; ServerAddresses value is CFArray<CFString>.
    let dns_key = unsafe { kSCPropNetDNSServerAddresses };
    let typed_dict = unsafe { dns_config.cast_unchecked::<CFString, CFArray<CFString>>() };
    let Some(servers) = (unsafe { typed_dict.get_unchecked(dns_key) }) else {
        return Ok(no_dns.to_string());
    };

    let result: Vec<String> = (0..servers.len())
        .filter_map(|i| servers.get(i).map(|s| s.to_string()))
        .collect();

    if result.is_empty() {
        Ok(no_dns.to_string())
    } else {
        Ok(result.join("\n"))
    }
}

/// Set or clear DNS servers for a network service via SystemConfiguration.
///
/// - `servers = Some(&["8.8.8.8"])` → sets manual DNS to the given addresses
/// - `servers = None` → clears manual DNS (reverts to DHCP)
///
/// Equivalent to `networksetup -setdnsservers <service> <ip...>` / `Empty`.
#[cfg(target_os = "macos")]
pub(super) fn set_dns_via_sc(service: &str, servers: Option<&[&str]>) -> anyhow::Result<()> {
    use objc2_core_foundation::{CFArray, CFDictionary, CFString};
    use objc2_system_configuration::{
        kSCNetworkProtocolTypeDNS, kSCPropNetDNSServerAddresses, SCNetworkService, SCPreferences,
    };

    let label = CFString::from_str("tor-vpn");
    let prefs = SCPreferences::new(None, &label, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to create SCPreferences"))?;
    let all = SCNetworkService::all(&prefs)
        .ok_or_else(|| anyhow::anyhow!("Failed to enumerate network services"))?;
    // SAFETY: SCNetworkServiceCopyAll returns a CFArray of SCNetworkService objects.
    let typed = unsafe { all.cast_unchecked::<SCNetworkService>() };

    let target = (0..typed.len())
        .filter_map(|i| typed.get(i))
        .find(|s| s.name().map(|n| n.to_string()).as_deref() == Some(service));
    let svc = target.ok_or_else(|| anyhow::anyhow!("Network service '{service}' not found"))?;

    // SAFETY: kSCNetworkProtocolTypeDNS is a valid static CFString constant.
    let dns_proto_type = unsafe { kSCNetworkProtocolTypeDNS };

    // Get or create DNS protocol for this service
    let dns_protocol = if let Some(p) = svc.protocol(dns_proto_type) {
        p
    } else {
        svc.add_protocol_type(dns_proto_type);
        svc.protocol(dns_proto_type)
            .ok_or_else(|| anyhow::anyhow!("Failed to add DNS protocol to service"))?
    };

    let config = match servers {
        Some(addrs) if !addrs.is_empty() => {
            let cf_addrs: Vec<_> = addrs.iter().map(|s| CFString::from_str(s)).collect();
            let cf_refs: Vec<&CFString> = cf_addrs.iter().map(|s| &**s).collect();
            let arr = CFArray::<CFString>::from_objects(&cf_refs);
            // SAFETY: kSCPropNetDNSServerAddresses is a valid static CFString constant.
            let dns_key = unsafe { kSCPropNetDNSServerAddresses };
            let dict =
                CFDictionary::<CFString, CFArray<CFString>>::from_slices(&[dns_key], &[&*arr]);
            Some(dict)
        }
        _ => None,
    };

    // SAFETY: config (if Some) is a valid CFDictionary with correct key/value types.
    let ok = unsafe { dns_protocol.set_configuration(config.as_ref().map(|d| d.as_opaque())) };
    if !ok {
        return Err(anyhow::anyhow!("SCNetworkProtocolSetConfiguration failed"));
    }

    if !prefs.commit_changes() {
        return Err(anyhow::anyhow!("SCPreferencesCommitChanges failed"));
    }
    if !prefs.apply_changes() {
        return Err(anyhow::anyhow!("SCPreferencesApplyChanges failed"));
    }

    Ok(())
}

/// Restore DNS to its original settings.
/// Shared between `NetworkController::restore_dns` (graceful shutdown)
/// and `cleanup::cleanup_orphaned` (SIGKILL recovery).
#[allow(unused_variables)]
pub fn restore_dns_settings(
    dns_service_name: Option<&str>,
    original_dns: Option<&str>,
    dns_method: Option<&str>,
    tun_name: &str,
) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    if let (Some(service), Some(original)) = (dns_service_name, original_dns) {
        if original.contains("There aren't any DNS Servers") {
            set_dns_via_sc(service, None)?;
        } else {
            let servers: Vec<&str> = original
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();
            set_dns_via_sc(service, Some(&servers))?;
        }
        tracing::info!(service = %service, "DNS restored");
    }

    #[cfg(target_os = "linux")]
    match dns_method {
        Some("resolvectl") => {
            // resolvectl revert — no-op if interface already gone (SIGKILL case)
            let _ = super::run_cmd("resolvectl", &["revert", tun_name]);
            tracing::info!("DNS restored via resolvectl");
        }
        Some("resolvconf") => {
            let label = format!("{tun_name}.tor-vpn");
            let _ = super::run_cmd("resolvconf", &["-d", &label]);
            tracing::info!("DNS restored via resolvconf");
        }
        _ => {
            if let Some(original) = original_dns {
                std::fs::write("/etc/resolv.conf", original)
                    .map_err(|e| anyhow::anyhow!("Failed to restore /etc/resolv.conf: {e}"))?;
                tracing::info!("DNS restored via /etc/resolv.conf");
            }
        }
    }

    // Windows: DNS override not used, nothing to restore.
    #[cfg(target_os = "windows")]
    {
        let _ = (dns_method, tun_name);
    }

    Ok(())
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod tests_macos {
    use super::*;

    #[test]
    fn test_detect_network_service_for_interface_en0() {
        // This test requires a real macOS system with en0 (Wi-Fi).
        // It validates the native SystemConfiguration API integration.
        let result = detect_network_service_for_interface("en0");
        // en0 typically exists on macOS; service name varies (e.g. "Wi-Fi")
        if let Some(ref name) = result {
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn test_detect_network_service_for_interface_nonexistent() {
        assert_eq!(detect_network_service_for_interface("en999"), None);
    }

    #[test]
    fn test_detect_network_service_finds_something() {
        // Should find at least one service on any macOS system
        let result = detect_network_service();
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }
}
