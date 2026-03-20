<script lang="ts">
  import { onMount } from "svelte";
  import { readDaemonLog, getStatus } from "../lib/api";

  let log = $state("");
  let active = $state(false);
  let autoScroll = $state(true);
  let container = $state<HTMLPreElement | null>(null);

  async function fetchLog() {
    try {
      // Activate on first detection of running daemon (covers UI restart)
      if (!active) {
        const status = await getStatus();
        if (status.status === "connected") {
          active = true;
        } else {
          return;
        }
      }

      const text = await readDaemonLog(500);
      // Don't replace existing log with empty content (file truncated or unreadable after shutdown)
      if (text && text !== log) {
        log = text;
        if (autoScroll) {
          requestAnimationFrame(() => {
            if (container) {
              container.scrollTop = container.scrollHeight;
            }
          });
        }
      }
    } catch {
      // Log file doesn't exist yet
    }
  }

  function handleScroll() {
    if (!container) return;
    const atBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight < 30;
    autoScroll = atBottom;
  }

  // Scroll to bottom when tab becomes visible (container transitions from display:none)
  $effect(() => {
    if (!container) return;
    const observer = new IntersectionObserver((entries) => {
      if (entries[0]?.isIntersecting && autoScroll && container) {
        container.scrollTop = container.scrollHeight;
      }
    });
    observer.observe(container);
    return () => observer.disconnect();
  });

  onMount(() => {
    fetchLog();
    const id = setInterval(fetchLog, 2000);
    return () => clearInterval(id);
  });
</script>

<div class="log-viewer">
  <div class="log-header">
    <span class="log-title">Daemon Log</span>
    <label class="auto-scroll-toggle">
      <input type="checkbox" bind:checked={autoScroll} />
      Auto-scroll
    </label>
  </div>

  {#if !active}
    <div class="log-placeholder surface-box">
      Daemon is not running.<br />
      Logs will appear here after connecting.
    </div>
  {:else}
    <pre class="log-content surface-box" bind:this={container} onscroll={handleScroll}>{log || "Waiting for log output..."}</pre>
  {/if}
</div>

<style>
  .log-viewer {
    display: flex;
    flex-direction: column;
    height: calc(100vh - 100px);
  }

  .log-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
    flex-shrink: 0;
  }

  .log-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .auto-scroll-toggle {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--color-text-muted);
    cursor: pointer;
    flex-direction: row;
    margin-bottom: 0;
  }

  .auto-scroll-toggle input {
    width: auto;
  }

  .log-content {
    flex: 1;
    overflow-y: auto;
    padding: 12px;
    font-family: var(--font-mono);
    font-size: 11px;
    line-height: 1.5;
    color: var(--color-text);
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0;
    user-select: text;
    -webkit-user-select: text;
  }

  .log-placeholder {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--color-text-muted);
    font-size: 13px;
    text-align: center;
    line-height: 1.8;
  }
</style>
