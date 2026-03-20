use tun_rs::{AsyncDevice, DeviceBuilder};

use config::Config;

/// Create and configure the TUN device.
///
/// - macOS: name auto-assigned (utunX)
/// - Linux: uses the configured name
/// - Windows: uses wintun.dll loaded via standard Windows DLL search order
///   (exe directory, System32, PATH, etc.). Sets a named device and low route
///   metric so catch-all routes prefer TUN.
pub fn create_tun_device(config: &Config) -> anyhow::Result<AsyncDevice> {
    let builder = DeviceBuilder::new();

    // On macOS, utun names are auto-assigned; on Linux we set the requested name.
    #[cfg(target_os = "linux")]
    let builder = builder.name(&config.tun_name);

    // Windows: set device name and metric. wintun.dll is loaded by tun-rs via
    // LoadLibrary("wintun.dll") — standard search order covers exe dir, System32, PATH.
    #[cfg(target_os = "windows")]
    let builder = builder.name(&config.tun_name).with(|opt| {
        opt.metric(0); // lowest metric so catch-all routes prefer TUN
    });

    let device = builder
        .ipv4(config.tun_address, config.tun_netmask, None)
        .mtu(config.tun_mtu)
        .build_async()
        .map_err(|e| {
            #[cfg(target_os = "windows")]
            {
                let msg = e.to_string();
                if msg.contains("wintun") || msg.contains("DLL") || msg.contains("library") {
                    return anyhow::anyhow!(
                        "TUN creation failed: {e}. \
                         Ensure wintun.dll is available (exe directory, System32, or PATH). \
                         Download from https://www.wintun.net/"
                    );
                }
            }
            anyhow::anyhow!("TUN creation failed: {e}")
        })?;

    let name = device.name().unwrap_or_default();
    tracing::info!(name = %name, address = %config.tun_address, mtu = config.tun_mtu, "TUN device created");

    Ok(device)
}
