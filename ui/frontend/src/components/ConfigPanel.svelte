<script lang="ts">
  import { uiConfig, saveConfig, loadConfig } from "../lib/stores/config";
  import { vpnConnected } from "../lib/stores/vpn";
  import type { UiConfig } from "../lib/types";

  const isMacOS = navigator.platform.startsWith("Mac") || navigator.userAgent.includes("Mac OS");
  const isWindows = navigator.platform.startsWith("Win") || navigator.userAgent.includes("Windows");

  let saving = $state(false);
  let saveMessage = $state("");

  // Local copy for editing (avoid mutating store directly)
  let local: UiConfig | null = $state(null);

  // Snapshot of saved state for dirty detection
  let savedSnapshot = $state("");

  $effect(() => {
    if ($uiConfig && !local) {
      local = { ...$uiConfig };
      savedSnapshot = JSON.stringify($uiConfig);
    }
  });

  let hasChanges = $derived.by(() => {
    if (!local || !savedSnapshot) return false;
    return JSON.stringify(local) !== savedSnapshot;
  });

  async function handleSave() {
    if (!local) return;
    saving = true;
    saveMessage = "";
    try {
      await saveConfig(local);
      savedSnapshot = JSON.stringify(local);
      saveMessage = "Saved";
      setTimeout(() => (saveMessage = ""), 2000);
    } catch (e) {
      saveMessage = `Error: ${e}`;
    } finally {
      saving = false;
    }
  }

  async function handleReset() {
    await loadConfig();
    if ($uiConfig) {
      local = { ...$uiConfig };
      savedSnapshot = JSON.stringify($uiConfig);
    }
  }
</script>

{#if local}
  <div class="config-panel">
    {#if $vpnConnected}
      <div class="connected-notice">
        Settings are read-only while VPN is connected. Disconnect to make changes.
      </div>
    {/if}
    <fieldset disabled={$vpnConnected} class:disabled-fieldset={$vpnConnected}>
    <section class="surface-box">
      <h3>General</h3>

      <label>
        <span>Daemon path</span>
        <input type="text" bind:value={local.daemon_path} />
      </label>

      <label>
        <span>Exit country (ISO alpha-2)</span>
        <input
          type="text"
          value={local.exit_country ?? ""}
          oninput={(e) => {
            const v = (e.target as HTMLInputElement).value.trim();
            local!.exit_country = v.length > 0 ? v : null;
          }}
          placeholder="e.g. US, DE"
          maxlength="2"
        />
      </label>

      <label>
        <span>Isolation policy</span>
        <select bind:value={local.isolation}>
          <option value="per-connection">Per Connection</option>
          <option value="per-destination">Per Destination</option>
          <option value="session">Session</option>
        </select>
      </label>

      <label class="checkbox" title={isWindows ? "Not available on Windows — .onion is blocked at the OS level" : ""}>
        <input type="checkbox" bind:checked={local.override_dns} disabled={isWindows} />
        <span>{isWindows ? "Override DNS (not available on Windows)" : "Override system DNS (prevents DoH bypass)"}</span>
      </label>

      <label class="checkbox">
        <input type="checkbox" bind:checked={local.kill_switch} />
        <span>Kill switch (block traffic during reconnect)</span>
      </label>
    </section>

    <section class="surface-box">
      <h3>Network</h3>

      <div class="row">
        <label>
          <span>TUN address</span>
          <input type="text" bind:value={local.tun_address} />
        </label>
        <label>
          <span>Netmask</span>
          <input type="number" bind:value={local.tun_netmask} min="1" max="30" />
        </label>
      </div>

      <div class="row">
        <label>
          <span>MTU</span>
          <input type="number" bind:value={local.tun_mtu} min="68" max="65535" />
        </label>
        <label>
          <span>TUN name</span>
          <input
            type="text"
            bind:value={local.tun_name}
            disabled={isMacOS}
            title={isMacOS ? "macOS assigns interface names automatically (utunN)" : ""}
          />
        </label>
      </div>

      <div class="row">
        <label>
          <span>Max connections</span>
          <input type="number" bind:value={local.max_connections} min="1" />
        </label>
        <label>
          <span>Max DNS queries</span>
          <input type="number" bind:value={local.max_dns_queries} min="1" />
        </label>
      </div>

      <label>
        <span>DNS cache TTL (seconds)</span>
        <input type="number" bind:value={local.dns_cache_ttl} min="0" />
      </label>

      <label>
        <span>Bypass CIDRs (comma-separated)</span>
        <input
          type="text"
          value={local.bypass_cidrs.join(", ")}
          oninput={(e) => {
            const target = e.target as HTMLInputElement;
            local!.bypass_cidrs = target.value
              .split(",")
              .map((s) => s.trim())
              .filter((s) => s.length > 0);
          }}
          placeholder="e.g. 10.0.0.0/8, 172.16.0.0/12"
        />
      </label>
    </section>

    <section class="surface-box">
      <h3>Bridges</h3>

      <label>
        <span>Bridge lines (one per line)</span>
        <textarea
          rows="4"
          value={local.bridges.join("\n")}
          oninput={(e) => {
            const target = e.target as HTMLTextAreaElement;
            local!.bridges = target.value.split("\n").filter((s) => s.trim().length > 0);
          }}
          placeholder="obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0"
        ></textarea>
      </label>

      <label>
        <span>PT paths (one per line, TRANSPORT=PATH)</span>
        <textarea
          rows="2"
          value={local.pt_paths.join("\n")}
          oninput={(e) => {
            const target = e.target as HTMLTextAreaElement;
            local!.pt_paths = target.value.split("\n").filter((s) => s.trim().length > 0);
          }}
          placeholder="obfs4=/usr/bin/obfs4proxy"
        ></textarea>
      </label>

    </section>

    <section class="surface-box">
      <h3>Advanced</h3>

      <label>
        <span>Cache directory</span>
        <input type="text" bind:value={local.cache_dir} />
      </label>

      <label>
        <span>Control socket path</span>
        <input type="text" bind:value={local.socket_path} placeholder="/tmp/tor-vpn.sock" />
      </label>

      <label>
        <span>State write interval (seconds)</span>
        <input type="number" bind:value={local.state_write_interval} min="1" max="3600" />
      </label>
    </section>

    </fieldset>

    <section class="surface-box">
      <h3>UI</h3>

      <label class="checkbox">
        <input type="checkbox" bind:checked={local.minimize_to_tray} />
        <span>Minimize to tray instead of taskbar</span>
      </label>

      <label class="checkbox">
        <input type="checkbox" bind:checked={local.disconnect_on_quit} />
        <span>Disconnect VPN when app quits</span>
      </label>
    </section>

    <div class="button-row">
      <button class="btn-primary" onclick={handleSave} disabled={saving || !hasChanges}>
        {saving ? "Saving..." : "Save"}
      </button>
      <button class="btn-secondary" onclick={handleReset} disabled={!hasChanges}>Reset</button>
      {#if saveMessage}
        <span class="save-msg">{saveMessage}</span>
      {/if}
    </div>
  </div>
{:else}
  <p class="loading">Loading configuration...</p>
{/if}

<style>
  .config-panel {
    display: flex;
    flex-direction: column;
    gap: 20px;
    padding-bottom: 60px;
  }

  section {
    padding: 16px;
  }

  h3 {
    font-size: 14px;
    font-weight: 600;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 12px;
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 10px;
  }

  label span {
    font-size: 12px;
    color: var(--color-text-muted);
  }

  label.checkbox {
    flex-direction: row;
    align-items: center;
    gap: 8px;
  }

  label.checkbox span {
    font-size: 13px;
    color: var(--color-text);
  }

  input[type="text"],
  input[type="number"],
  select,
  textarea {
    background: var(--color-bg);
    border: 1px solid var(--color-border);
    border-radius: 4px;
    color: var(--color-text);
    padding: 8px 10px;
    font-size: 13px;
    font-family: var(--font-mono);
    width: 100%;
  }

  input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  input:focus,
  select:focus,
  textarea:focus {
    outline: none;
    border-color: var(--color-accent);
  }

  select {
    appearance: none;
    -webkit-appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%238a8a9a' d='M2 4l4 4 4-4'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 10px center;
    padding-right: 30px;
    cursor: pointer;
    height: 38px;
  }

  textarea {
    resize: vertical;
    font-family: var(--font-mono);
  }

  .row {
    display: flex;
    gap: 10px;
  }

  .row label {
    flex: 1;
  }

  .button-row {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    background: var(--color-surface);
    border-top: 1px solid var(--color-border);
    z-index: 10;
  }

  .save-msg {
    font-size: 13px;
    color: var(--color-green);
  }

  fieldset {
    border: none;
    padding: 0;
    margin: 0;
    min-inline-size: 0;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .disabled-fieldset {
    opacity: 0.6;
  }

  .connected-notice {
    background: rgba(255, 183, 77, 0.12);
    border: 1px solid var(--color-yellow);
    color: var(--color-yellow);
    padding: 10px 14px;
    border-radius: var(--radius);
    font-size: 13px;
    text-align: center;
  }

  .loading {
    color: var(--color-text-muted);
    text-align: center;
    padding: 40px;
  }
</style>
