<script lang="ts">
  import { onMount } from "svelte";
  import { vpnConnected } from "../lib/stores/vpn";
  import { uiConfig, loadConfig, saveConfig } from "../lib/stores/config";
  import {
    connect,
    disconnect,
    refreshCircuits,
    cleanup,
    getStatus,
    takeTrayAction,
  } from "../lib/api";
  import { formatDuration, formatBytes, formatRate } from "../lib/types";
  import type { VpnStatus } from "../lib/types";
  import StatusIndicator from "./StatusIndicator.svelte";

  // Direct local state — no stores, guaranteed reactivity
  let status: VpnStatus = $state({ status: "disconnected" });
  let actionPending = $state(false);
  let lastError: string | null = $state(null);
  let toast: string | null = $state(null);
  let toastTimer: ReturnType<typeof setTimeout> | null = null;
  let refreshing = $state(false);
  let txRate = $state(0);
  let rxRate = $state(0);
  let pollCount = $state(0);

  // Rate computation
  let prevTx = 0;
  let prevRx = 0;
  let prevTime = Date.now();

  // Sparkline: rolling 60 samples (2 min at 2s interval)
  const SPARK_LEN = 60;
  let txHistory: number[] = $state(new Array(SPARK_LEN).fill(0));
  let rxHistory: number[] = $state(new Array(SPARK_LEN).fill(0));
  let sparkMax = $derived(Math.max(...txHistory, ...rxHistory, 1));

  let guardIpsDisplay = $derived.by(() => {
    if (status.status !== "connected") return "";
    const ips = status.state.guard_ips;
    if (ips.length === 0) return "none";
    if (ips.length <= 3) return ips.join(", ");
    return ips.slice(-3).join(", ");
  });
  let guardIpsExtra = $derived.by(() => {
    if (status.status !== "connected") return 0;
    return status.state.guard_ips.length > 3 ? status.state.guard_ips.length : 0;
  });

  async function checkTrayAction() {
    try {
      const action = await takeTrayAction();
      if (action === "connect" && !actionPending) {
        // Tray started the daemon in background — just show "Connecting..." UI.
        // Don't set connectAttempted yet (password dialog + bootstrap can take minutes).
        actionPending = true;
        lastError = null;
        connectAttempted = false;
      } else if (action === "connect_done") {
        // Tray confirmed daemon is running — enable crash detection
        if (!actionPending) {
          // "connect" action was consumed before this poll — set pending now
          actionPending = true;
          lastError = null;
        }
        connectAttempted = true;
        connectPollSnapshot = pollCount;
      } else if (action === "disconnect") {
        // Tray sent disconnect — clear any pending connect state
        actionPending = false;
        connectAttempted = false;
      } else if (action === "connect_error") {
        actionPending = false;
        lastError = "Failed to start VPN daemon";
      }
    } catch {
      // ignore — command not yet registered during startup
    }
  }

  async function poll() {
    try {
      await checkTrayAction();
      const raw = await getStatus();
      pollCount++;

      if (raw.status === "connected") {
        const now = Date.now();
        const elapsed = (now - prevTime) / 1000;

        // Skip rate computation on first sample after connect (prevTx/prevRx are 0)
        // to avoid an artificial spike from accumulated warmup bytes
        if (prevTx > 0 && elapsed > 0.5) {
          txRate = Math.max(0, raw.state.tx_bytes - prevTx) / elapsed;
          rxRate = Math.max(0, raw.state.rx_bytes - prevRx) / elapsed;
        }

        prevTx = raw.state.tx_bytes;
        prevRx = raw.state.rx_bytes;
        prevTime = now;

        // Push to sparkline history (shift left, append new)
        txHistory = [...txHistory.slice(1), txRate];
        rxHistory = [...rxHistory.slice(1), rxRate];
      } else {
        prevTx = 0;
        prevRx = 0;
        prevTime = Date.now();
        txRate = 0;
        rxRate = 0;
        txHistory = new Array(SPARK_LEN).fill(0);
        rxHistory = new Array(SPARK_LEN).fill(0);
      }

      status = raw;
    } catch (e) {
      console.error("Poll failed:", e);
    }
  }

  onMount(() => {
    poll();
    const statusInterval = setInterval(poll, 2000);
    // Check tray actions at 200ms for near-instant UI response
    const trayInterval = setInterval(checkTrayAction, 400);
    return () => {
      clearInterval(statusInterval);
      clearInterval(trayInterval);
    };
  });

  let displayStatus: "disconnected" | "connected" | "connecting" | "dirty" =
    $derived.by(() => {
      if (actionPending) return "connecting";
      return status.status;
    });

  // pollCount snapshot taken when connect() succeeds — used to detect daemon crash
  let connectPollSnapshot = $state(0);
  let connectAttempted = $state(false);

  async function handleConnect() {
    // actionPending and lastError are set by the inline onclick handler
    // (Svelte 5 event delegation doesn't reliably call async function refs directly)
    connectAttempted = false;

    try {
      if (!$uiConfig) await loadConfig();
      if (!$uiConfig) {
        lastError = "Configuration not available";
        actionPending = false;
        return;
      }

      await saveConfig($uiConfig);
      await connect($uiConfig.daemon_path);
      connectAttempted = true;
      connectPollSnapshot = pollCount;
    } catch (e) {
      lastError = String(e);
      actionPending = false;
    }
  }

  // Clear actionPending when poller detects a state change
  $effect(() => {
    if (status.status !== "disconnected" && actionPending) {
      // Daemon started successfully — clear pending state and any stale error
      actionPending = false;
      lastError = null;
    } else if (
      status.status === "disconnected" &&
      actionPending &&
      connectAttempted &&
      pollCount >= connectPollSnapshot + 3 // wait for 3 polls (~6s) after connect before declaring crash
    ) {
      // Daemon started but crashed — unstick the UI
      actionPending = false;
      lastError = "Daemon exited unexpectedly after starting";
    }
  });

  // Keep shared vpnConnected store in sync
  $effect(() => {
    $vpnConnected = status.status === "connected";
  });

  async function withErrorHandling(fn: () => Promise<void>) {
    lastError = null;
    try {
      await fn();
    } catch (e) {
      lastError = String(e);
    }
  }

  async function handleDisconnect() {
    await withErrorHandling(async () => {
      await disconnect();
      await poll();
    });
  }

  function showToast(msg: string, durationMs = 3000) {
    if (toastTimer) clearTimeout(toastTimer);
    toast = msg;
    toastTimer = setTimeout(() => { toast = null; toastTimer = null; }, durationMs);
  }

  async function handleRefresh() {
    refreshing = true;
    lastError = null;
    try {
      await refreshCircuits();
      showToast("Identity refreshed — new circuits active");
    } catch (e) {
      lastError = String(e);
    } finally {
      refreshing = false;
    }
  }

  async function handleCleanup() {
    const daemonPath = $uiConfig?.daemon_path ?? "tor-vpn";
    await withErrorHandling(async () => {
      await cleanup(daemonPath);
      await poll();
    });
  }
</script>

<div class="dashboard" class:centered={displayStatus !== 'connected'}>
  <div class="status-section">
    {#if status.status !== "connected"}
      <div class="app-icon">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
          <defs>
            <linearGradient id="shieldGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#7B4FBF"/>
              <stop offset="100%" stop-color="#4A2D7A"/>
            </linearGradient>
            <linearGradient id="shieldBorder" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#A87FE0"/>
              <stop offset="100%" stop-color="#6B3FA0"/>
            </linearGradient>
            <linearGradient id="onionGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#E0D0F5"/>
              <stop offset="100%" stop-color="#C8B0E8"/>
            </linearGradient>
            <filter id="iconShadow" x="-10%" y="-10%" width="120%" height="130%">
              <feDropShadow dx="0" dy="4" stdDeviation="12" flood-color="#1a0a2e" flood-opacity="0.5"/>
            </filter>
          </defs>
          <path d="M256 28 C256 28 440 70 440 70 C440 70 440 260 440 260 C440 380 340 460 256 492 C172 460 72 380 72 260 C72 260 72 70 72 70 C72 70 256 28 256 28Z" fill="url(#shieldBorder)" filter="url(#iconShadow)"/>
          <path d="M256 48 C256 48 420 86 420 86 C420 86 420 256 420 256 C420 368 328 442 256 472 C184 442 92 368 92 256 C92 256 92 86 92 86 C92 86 256 48 256 48Z" fill="url(#shieldGrad)"/>
          <ellipse cx="256" cy="290" rx="120" ry="140" fill="none" stroke="url(#onionGrad)" stroke-width="8" opacity="0.4" stroke-dasharray="0 140 440"/>
          <path d="M256 150 C310 150 356 210 356 290 C356 360 310 400 256 400 C202 400 156 360 156 290 C156 210 202 150 256 150Z" fill="none" stroke="url(#onionGrad)" stroke-width="6" opacity="0.35"/>
          <path d="M256 180 C298 180 328 226 328 290 C328 346 298 378 256 378 C214 378 184 346 184 290 C184 226 214 180 256 180Z" fill="none" stroke="url(#onionGrad)" stroke-width="6" opacity="0.55"/>
          <path d="M256 210 C284 210 304 242 304 290 C304 332 284 356 256 356 C228 356 208 332 208 290 C208 242 228 210 256 210Z" fill="none" stroke="url(#onionGrad)" stroke-width="6" opacity="0.75"/>
          <ellipse cx="256" cy="290" rx="28" ry="36" fill="url(#onionGrad)" opacity="0.9"/>
          <path d="M256 150 C256 150 248 120 256 100 C264 120 256 150 256 150Z" fill="url(#onionGrad)" opacity="0.8"/>
          <path d="M252 148 C244 128 240 110 248 90" fill="none" stroke="url(#onionGrad)" stroke-width="3" opacity="0.5"/>
          <path d="M260 148 C268 128 272 110 264 90" fill="none" stroke="url(#onionGrad)" stroke-width="3" opacity="0.5"/>
          <circle cx="160" cy="200" r="5" fill="#E0D0F5" opacity="0.6"/>
          <circle cx="352" cy="200" r="5" fill="#E0D0F5" opacity="0.6"/>
          <circle cx="140" cy="300" r="5" fill="#E0D0F5" opacity="0.6"/>
          <circle cx="372" cy="300" r="5" fill="#E0D0F5" opacity="0.6"/>
          <circle cx="175" cy="380" r="5" fill="#E0D0F5" opacity="0.6"/>
          <circle cx="337" cy="380" r="5" fill="#E0D0F5" opacity="0.6"/>
          <line x1="160" y1="200" x2="184" y2="230" stroke="#E0D0F5" stroke-width="1.5" opacity="0.25"/>
          <line x1="352" y1="200" x2="328" y2="230" stroke="#E0D0F5" stroke-width="1.5" opacity="0.25"/>
          <line x1="140" y1="300" x2="172" y2="290" stroke="#E0D0F5" stroke-width="1.5" opacity="0.25"/>
          <line x1="372" y1="300" x2="340" y2="290" stroke="#E0D0F5" stroke-width="1.5" opacity="0.25"/>
        </svg>
      </div>
    {/if}

    <StatusIndicator status={displayStatus} />

    {#if status.status === "connected"}
      <div class="details">
        <span class="detail">Uptime: {formatDuration(status.uptime_secs)}{#if $uiConfig && $uiConfig.bridges.length > 0} &middot; Bridge{/if}{#if status.state.exit_country} &middot; Exit: {status.state.exit_country}{/if}</span>
      </div>

      <div class="bandwidth">
        <div class="stats">
          <div class="stat">
            <span class="arrow up">&uarr;</span>
            <span class="value">{formatBytes(status.state.tx_bytes)}</span>
            <span class="rate">{formatRate(txRate)}</span>
          </div>
          <div class="stat">
            <span class="arrow down">&darr;</span>
            <span class="value">{formatBytes(status.state.rx_bytes)}</span>
            <span class="rate">{formatRate(rxRate)}</span>
          </div>
        </div>

        <div class="sparkline">
          <svg viewBox="0 0 {SPARK_LEN - 1} 50" preserveAspectRatio="none">
            <path
              d={rxHistory.map((v, i) => `${i === 0 ? 'M' : 'L'}${i},${50 - (v / sparkMax) * 48}`).join(' ')}
              fill="none" stroke="var(--color-green)" stroke-width="1.5" vector-effect="non-scaling-stroke"
            />
            <path
              d={txHistory.map((v, i) => `${i === 0 ? 'M' : 'L'}${i},${50 - (v / sparkMax) * 48}`).join(' ')}
              fill="none" stroke="var(--color-blue)" stroke-width="1.5" stroke-opacity="0.5" vector-effect="non-scaling-stroke"
            />
          </svg>
          <div class="sparkline-legend">
            <span class="legend-item" style="color: var(--color-green)">&darr; download</span>
            <span class="legend-item" style="color: var(--color-blue)">&uarr; upload</span>
          </div>
        </div>
      </div>
    {/if}
  </div>

  {#if status.status === "connected"}
    <div class="info-panel surface-box">
      <div class="info-row">
        <span class="info-label">TUN</span>
        <span class="info-value">{status.state.tun_name}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Gateway</span>
        <span class="info-value">{status.state.original_gateway} ({status.state.original_interface})</span>
      </div>
      <div class="info-row">
        <span class="info-label">Guard IPs</span>
        <span class="info-value">{guardIpsDisplay}{#if guardIpsExtra > 0} <span class="info-muted">+{guardIpsExtra - 3} more ({guardIpsExtra} total)</span>{/if}</span>
      </div>
      {#if status.state.configured_dns_ip}
        <div class="info-row">
          <span class="info-label">VPN DNS</span>
          <span class="info-value">{status.state.configured_dns_ip}{status.state.dns_method ? ` (${status.state.dns_method})` : ''}</span>
        </div>
      {/if}
      {#if status.state.bypass_cidrs.length > 0}
        <div class="info-row">
          <span class="info-label">Bypass</span>
          <span class="info-value">{status.state.bypass_cidrs.join(', ')}</span>
        </div>
      {/if}
      <div class="info-row">
        <span class="info-label">Daemon PID</span>
        <span class="info-value">{status.state.pid}</span>
      </div>
    </div>
  {/if}

  {#if lastError}
    <div class="error">{lastError}</div>
  {/if}

  <div class="actions">
    {#if status.status === "disconnected"}
      <button
        class="action-btn {actionPending ? 'btn-connecting' : 'btn-primary'}"
        onclick={() => { actionPending = true; lastError = null; setTimeout(() => handleConnect(), 50); }}
        disabled={actionPending}
      >
Connect
      </button>
    {:else if status.status === "connected"}
      <button class="btn-danger action-btn" onclick={handleDisconnect}>
        Disconnect
      </button>
      <button class="btn-secondary action-btn" onclick={handleRefresh} disabled={refreshing}>
        {refreshing ? "Refreshing..." : "New Identity"}
      </button>
    {:else if status.status === "dirty"}
      <div class="dirty-notice">
        Orphaned routes detected. Run cleanup to restore network.
      </div>
      <button class="btn-warning action-btn" onclick={handleCleanup}>
        Cleanup
      </button>
    {/if}
  </div>

  {#if toast}
    <div class="toast">{toast}</div>
  {/if}
</div>

<style>
  .dashboard {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 24px;
    padding-top: 32px;
    height: 100%;
  }

  .dashboard.centered {
    justify-content: center;
    padding-top: 0;
  }

  .status-section {
    text-align: center;
    width: 100%;
  }

  .app-icon {
    width: 160px;
    height: 160px;
    margin: -120px auto 12px;
    opacity: 0.85;
  }

  .app-icon svg {
    width: 100%;
    height: 100%;
  }

  .details {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    margin-top: 12px;
  }

  .detail {
    font-size: 13px;
    color: var(--color-text-muted);
    font-family: var(--font-mono);
  }

  .bandwidth {
    margin-top: 16px;
    width: 100%;
  }

  .stats {
    display: flex;
    justify-content: center;
    gap: 32px;
  }

  .stat {
    display: flex;
    align-items: baseline;
    gap: 6px;
    min-width: 150px;
  }

  .arrow {
    font-size: 16px;
    font-weight: 700;
    width: 16px;
    text-align: center;
    flex-shrink: 0;
  }

  .arrow.up {
    color: var(--color-blue);
  }

  .arrow.down {
    color: var(--color-green);
  }

  .value {
    font-size: 16px;
    font-weight: 600;
    font-family: var(--font-mono);
    white-space: nowrap;
  }

  .rate {
    font-size: 12px;
    color: var(--color-text-muted);
    font-family: var(--font-mono);
    white-space: nowrap;
  }

  .sparkline {
    margin-top: 12px;
    width: 100%;
    background: var(--color-surface);
    border-radius: var(--radius);
    padding: 8px 12px 4px;
  }

  .sparkline svg {
    width: 100%;
    height: 60px;
    display: block;
  }

  .sparkline-legend {
    display: flex;
    justify-content: center;
    gap: 16px;
    margin-top: 4px;
  }

  .legend-item {
    font-size: 10px;
    font-family: var(--font-mono);
    opacity: 0.7;
  }

  .info-panel {
    width: 100%;
    max-width: 380px;
    padding: 10px 14px;
  }

  .info-row {
    display: flex;
    justify-content: space-between;
    padding: 4px 0;
    font-size: 12px;
    font-family: var(--font-mono);
  }

  .info-row + .info-row {
    border-top: 1px solid var(--color-border);
  }

  .info-label {
    color: var(--color-text-muted);
    flex-shrink: 0;
    margin-right: 12px;
  }

  .info-value {
    color: var(--color-text);
    text-align: right;
    word-break: break-all;
  }

  .info-muted {
    color: var(--color-text-muted);
  }

  .error {
    background: rgba(239, 83, 80, 0.15);
    border: 1px solid var(--color-red-dim);
    color: var(--color-red);
    padding: 10px 14px;
    border-radius: var(--radius);
    font-size: 13px;
    width: 100%;
    max-width: 360px;
    word-break: break-word;
  }

  .actions {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 10px;
    width: 100%;
    max-width: 300px;
  }

  .action-btn {
    width: 100%;
    padding: 12px 24px;
    font-size: 15px;
  }

  .dirty-notice {
    font-size: 13px;
    color: var(--color-yellow);
    text-align: center;
    padding: 8px;
  }

  .toast {
    position: fixed;
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%);
    background: var(--color-green);
    color: #fff;
    padding: 10px 20px;
    border-radius: var(--radius);
    font-size: 13px;
    font-weight: 600;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    animation: toast-in 0.25s ease-out;
    z-index: 100;
    white-space: nowrap;
  }

  @keyframes toast-in {
    from { opacity: 0; transform: translateX(-50%) translateY(8px); }
    to { opacity: 1; transform: translateX(-50%) translateY(0); }
  }
</style>
