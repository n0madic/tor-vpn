import { writable } from "svelte/store";

/** Whether a connect/disconnect action is in progress. */
export const actionPending = writable(false);

/** Error message from the last failed action, or null. */
export const lastError = writable<string | null>(null);

/** Whether the VPN is currently connected (updated by Dashboard poller). */
export const vpnConnected = writable(false);

