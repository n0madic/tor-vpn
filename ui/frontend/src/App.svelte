<script lang="ts">
  import Dashboard from "./components/Dashboard.svelte";
  import ConfigPanel from "./components/ConfigPanel.svelte";
  import LogViewer from "./components/LogViewer.svelte";
  import { loadConfig } from "./lib/stores/config";

  let view: "dashboard" | "settings" | "logs" = $state("dashboard");

  // Load saved config on startup
  loadConfig();
</script>

<div class="app">
  <header class="titlebar">
    <span class="title">Tor VPN</span>
    <nav>
      <button
        class="nav-btn"
        class:active={view === "dashboard"}
        onclick={() => (view = "dashboard")}
      >
        Dashboard
      </button>
      <button
        class="nav-btn"
        class:active={view === "logs"}
        onclick={() => (view = "logs")}
      >
        Logs
      </button>
      <button
        class="nav-btn"
        class:active={view === "settings"}
        onclick={() => (view = "settings")}
      >
        Settings
      </button>
    </nav>
  </header>

  <main>
    <div class="tab-content" class:hidden={view !== "dashboard"}>
      <Dashboard />
    </div>
    <div class="tab-content" class:hidden={view !== "settings"}>
      <ConfigPanel />
    </div>
    <div class="tab-content" class:hidden={view !== "logs"}>
      <LogViewer />
    </div>
  </main>
</div>

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
  }

  .titlebar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    background: var(--color-surface);
    border-bottom: 1px solid var(--color-border);
    -webkit-app-region: drag;
  }

  .title {
    font-size: 16px;
    font-weight: 700;
    letter-spacing: -0.3px;
  }

  nav {
    display: flex;
    gap: 4px;
    -webkit-app-region: no-drag;
  }

  .nav-btn {
    background: transparent;
    color: var(--color-text-muted);
    padding: 6px 12px;
    font-size: 13px;
    font-weight: 500;
    border-radius: 6px;
  }

  .nav-btn.active {
    background: var(--color-border);
    color: var(--color-text);
  }

  main {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
  }

  .tab-content {
    height: 100%;
  }

  .hidden {
    display: none;
  }
</style>
