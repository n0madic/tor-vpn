<script lang="ts">
  interface Props {
    status: "disconnected" | "connected" | "connecting" | "dirty";
  }

  let { status }: Props = $props();

  const labels: Record<string, string> = {
    disconnected: "Disconnected",
    connected: "Connected",
    connecting: "Connecting...",
    dirty: "Needs Cleanup",
  };
</script>

<div class="indicator">
  <div class="dot {status}"></div>
  <span class="label">{labels[status]}</span>
</div>

<style>
  .indicator {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
  }

  .dot {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .dot.disconnected {
    background: var(--color-text-muted);
  }

  .dot.connected {
    background: var(--color-green);
    box-shadow: 0 0 8px var(--color-green);
  }

  .dot.connecting {
    background: var(--color-yellow);
    animation: pulse 1.5s ease-in-out infinite;
  }

  .dot.dirty {
    background: var(--color-red);
    box-shadow: 0 0 8px var(--color-red);
  }

  .label {
    font-size: 22px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.3;
    }
  }
</style>
