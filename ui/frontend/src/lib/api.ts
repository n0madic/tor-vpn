import { invoke } from "@tauri-apps/api/core";
import type { VpnStatus, UiConfig } from "./types";

/** Start the VPN daemon using daemon.conf already on disk. */
export async function connect(daemonPath: string): Promise<void> {
  return invoke("connect", { daemonPath });
}

/** Stop the running VPN daemon. */
export async function disconnect(): Promise<void> {
  return invoke("disconnect");
}

/** Refresh Tor circuits (SIGUSR1). */
export async function refreshCircuits(): Promise<void> {
  return invoke("refresh_circuits");
}

/** Run cleanup to restore routes and DNS from a crashed daemon. */
export async function cleanup(daemonPath: string): Promise<void> {
  return invoke("cleanup", { daemonPath });
}

/** Get current VPN status (one-shot, for initial load). */
export async function getStatus(): Promise<VpnStatus> {
  return invoke("get_status");
}

/** Load persisted UI configuration. */
export async function getConfig(): Promise<UiConfig> {
  return invoke("get_config");
}

/** Save UI configuration to disk. */
export async function saveConfig(config: UiConfig): Promise<void> {
  return invoke("save_config", { config });
}

/** Get the detected path to the tor-vpn daemon binary. */
export async function getDaemonPath(): Promise<string> {
  return invoke("get_daemon_path");
}

/** Read the last N lines of the daemon log file. */
export async function readDaemonLog(lines?: number): Promise<string> {
  return invoke("read_daemon_log", { lines });
}

/** Check and clear pending tray action (connect/disconnect/connect_error). */
export async function takeTrayAction(): Promise<string> {
  return invoke("take_tray_action");
}

