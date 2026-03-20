/** Mirrors VpnState from the daemon's state.rs */
export interface VpnState {
  pid: number;
  tun_name: string;
  original_gateway: string;
  original_interface: string;
  guard_ips: string[];
  bypass_cidrs: string[];
  dns_service_name?: string;
  original_dns?: string;
  configured_dns_ip?: string;
  dns_method?: string;
  exit_country?: string;
  tx_bytes: number;
  rx_bytes: number;
}

/** Tagged union for VPN status (matches Rust VpnStatus serde output) */
export type VpnStatus =
  | { status: "disconnected" }
  | {
      status: "connected";
      state: VpnState;
      uptime_secs: number;
      tx_rate: number;
      rx_rate: number;
    }
  | { status: "dirty"; state: VpnState };

/** UI configuration persisted between sessions */
export interface UiConfig {
  daemon_path: string;
  minimize_to_tray: boolean;
  disconnect_on_quit: boolean;
  tun_name: string;
  tun_address: string;
  tun_netmask: number;
  tun_mtu: number;
  isolation: string;
  cache_dir: string;
  bypass_cidrs: string[];
  max_connections: number;
  max_dns_queries: number;
  dns_cache_ttl: number;
  override_dns: boolean;
  exit_country: string | null;
  bridges: string[];
  pt_paths: string[];
  socket_path: string;
  state_write_interval: number;
  kill_switch: boolean;
}

/** Format byte count as human-readable string (matches daemon's format_bytes) */
export function formatBytes(n: number): string {
  const KB = 1024;
  const MB = 1024 * KB;
  const GB = 1024 * MB;

  if (n >= GB) return `${(n / GB).toFixed(2)} GB`;
  if (n >= MB) return `${(n / MB).toFixed(2)} MB`;
  if (n >= KB) return `${(n / KB).toFixed(2)} KB`;
  return `${Math.round(n)} B`;
}

/** Format bytes/sec as human-readable rate */
export function formatRate(bytesPerSec: number): string {
  return `${formatBytes(Math.round(bytesPerSec))}/s`;
}

/** Format seconds as human-readable duration */
export function formatDuration(totalSecs: number): string {
  totalSecs = Math.floor(totalSecs);
  const days = Math.floor(totalSecs / 86400);
  const hours = Math.floor((totalSecs % 86400) / 3600);
  const minutes = Math.floor((totalSecs % 3600) / 60);
  const seconds = totalSecs % 60;

  if (days > 0) return `${days}d ${hours}h ${minutes}m ${seconds}s`;
  if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}
