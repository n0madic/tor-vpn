#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod daemon;
mod tray;

#[cfg(target_os = "macos")]
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            tray::setup(app)?;
            Ok(())
        })
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                if config::should_minimize_to_tray() {
                    api.prevent_close();
                    hide_to_tray(window);
                } else if config::should_disconnect_on_quit() {
                    disconnect_if_running();
                }
            }
            tauri::WindowEvent::Focused(false) if config::should_minimize_to_tray() => {
                if window.is_minimized().unwrap_or(false) {
                    let _ = window.unminimize();
                    hide_to_tray(window);
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            daemon::connect,
            daemon::disconnect,
            daemon::refresh_circuits,
            daemon::cleanup,
            daemon::get_status,
            daemon::read_daemon_log,
            config::get_config,
            config::save_config,
            config::get_daemon_path,
            take_tray_action,
        ])
        .run(tauri::generate_context!())
        .expect("error running tor-vpn UI");
}

/// Hide window and remove from Dock (macOS) so only tray icon remains.
fn hide_to_tray(window: &tauri::Window) {
    let _ = window.hide();
    #[cfg(target_os = "macos")]
    let _ = window
        .app_handle()
        .set_activation_policy(tauri::ActivationPolicy::Accessory);
}

/// Check and clear pending tray action.
/// Called by the frontend during each poll cycle.
#[tauri::command]
fn take_tray_action() -> String {
    match tray::take_action() {
        1 => "connect".into(),
        2 => "disconnect".into(),
        3 => "connect_error".into(),
        4 => "connect_done".into(),
        _ => String::new(),
    }
}

/// Disconnect VPN if the daemon is currently running.
pub fn disconnect_if_running() {
    if matches!(daemon::get_status(), config::VpnStatus::Connected { .. }) {
        let _ = daemon::disconnect();
    }
}
