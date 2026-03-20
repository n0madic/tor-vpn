import { writable } from "svelte/store";
import type { UiConfig } from "../types";
import { getConfig, saveConfig as saveConfigApi } from "../api";

/** Reactive store for the UI configuration. */
export const uiConfig = writable<UiConfig | null>(null);

/** Load configuration from disk. */
export async function loadConfig(): Promise<void> {
  const config = await getConfig();
  uiConfig.set(config);
}

/** Save configuration to disk and update the store. */
export async function saveConfig(config: UiConfig): Promise<void> {
  await saveConfigApi(config);
  uiConfig.set(config);
}
