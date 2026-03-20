use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

use tauri::{
    image::Image,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    App, AppHandle, Manager,
};

use crate::{config, daemon};

/// Global tray icon handle for menu rebuilds from any context.
static TRAY_APP: OnceLock<AppHandle> = OnceLock::new();

/// Pending tray action for the frontend to pick up during polling.
static TRAY_ACTION: AtomicU8 = AtomicU8::new(0);
const ACTION_NONE: u8 = 0;
const ACTION_CONNECT: u8 = 1;
const ACTION_DISCONNECT: u8 = 2;
const ACTION_CONNECT_ERROR: u8 = 3;
const ACTION_CONNECT_DONE: u8 = 4;

/// Atomically read and clear the pending tray action.
/// Called by the `take_tray_action` Tauri command.
pub fn take_action() -> u8 {
    TRAY_ACTION.swap(ACTION_NONE, Ordering::Relaxed)
}

/// Set up the system tray icon with a context menu.
pub fn setup(app: &App) -> Result<(), Box<dyn std::error::Error>> {
    TRAY_APP.set(app.handle().clone()).ok();

    let icon = Image::from_bytes(include_bytes!("../icons/tray-icon.png"))?;

    let tray = TrayIconBuilder::with_id("main-tray")
        .icon(icon)
        .icon_as_template(true)
        .menu(&build_menu(app.handle())?)
        .tooltip("Tor VPN")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "toggle" => {
                if is_vpn_connected() {
                    TRAY_ACTION.store(ACTION_DISCONNECT, Ordering::Relaxed);
                    std::thread::spawn(|| {
                        if let Err(e) = daemon::disconnect() {
                            eprintln!("[tor-vpn-ui] Tray disconnect failed: {e}");
                        }
                        rebuild_tray_menu();
                    });
                } else {
                    TRAY_ACTION.store(ACTION_CONNECT, Ordering::Relaxed);
                    // Use saved daemon_path from config.json (same as button flow)
                    let daemon_path = config::saved_daemon_path();
                    std::thread::spawn(move || {
                        match daemon::connect(daemon_path) {
                            Ok(()) => {
                                TRAY_ACTION.store(ACTION_CONNECT_DONE, Ordering::Relaxed);
                            }
                            Err(e) => {
                                eprintln!("[tor-vpn-ui] Tray connect failed: {e}");
                                TRAY_ACTION.store(ACTION_CONNECT_ERROR, Ordering::Relaxed);
                            }
                        }
                        rebuild_tray_menu();
                    });
                }
                // Show window so user sees the state change
                show_main_window(app);
            }
            "show" => {
                show_main_window(app);
            }
            "quit" => {
                if config::should_disconnect_on_quit() {
                    crate::disconnect_if_running();
                }
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    // Background poller: rebuild menu when VPN state changes
    std::thread::spawn(move || {
        let mut was_connected = is_vpn_connected();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let connected = is_vpn_connected();
            if connected != was_connected {
                rebuild_tray_menu();
                was_connected = connected;
            }
        }
    });

    // Keep tray icon alive for the lifetime of the app
    // (dropping it removes the icon from the menu bar)
    std::mem::forget(tray);

    Ok(())
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        #[cfg(target_os = "macos")]
        let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Build a fresh tray menu reflecting current VPN state.
fn build_menu(app: &AppHandle) -> Result<Menu<tauri::Wry>, Box<dyn std::error::Error>> {
    let label = if is_vpn_connected() {
        "Disconnect"
    } else {
        "Connect"
    };
    let toggle = MenuItem::with_id(app, "toggle", label, true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let show = MenuItem::with_id(app, "show", "Open Dashboard", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    Ok(Menu::with_items(app, &[&toggle, &separator, &show, &quit])?)
}

/// Rebuild the tray menu from any thread via GCD main queue dispatch (macOS)
/// or direct call (other platforms).
fn rebuild_tray_menu() {
    let Some(app) = TRAY_APP.get() else {
        return;
    };
    let app = app.clone();
    dispatch_main(move || {
        if let Ok(menu) = build_menu(&app) {
            if let Some(tray) = app.tray_by_id("main-tray") {
                let _ = tray.set_menu(Some(menu));
            }
        }
    });
}

/// Check if the VPN daemon is currently running.
/// Uses the same logic as `daemon::get_status()`: IPC first, state file fallback.
fn is_vpn_connected() -> bool {
    matches!(daemon::get_status(), config::VpnStatus::Connected { .. })
}

/// Dispatch a closure to the main thread via GCD (macOS) or direct call (other platforms).
#[cfg(target_os = "macos")]
fn dispatch_main(f: impl FnOnce() + Send + 'static) {
    use std::ffi::c_void;

    unsafe extern "C" fn trampoline(ctx: *mut c_void) {
        let closure = unsafe { Box::from_raw(ctx as *mut Box<dyn FnOnce()>) };
        closure();
    }

    extern "C" {
        static _dispatch_main_q: c_void;
        fn dispatch_async_f(
            queue: *const c_void,
            context: *mut c_void,
            work: unsafe extern "C" fn(*mut c_void),
        );
    }

    let boxed: Box<Box<dyn FnOnce()>> = Box::new(Box::new(f));
    unsafe {
        dispatch_async_f(
            &raw const _dispatch_main_q,
            Box::into_raw(boxed) as *mut c_void,
            trampoline,
        );
    }
}

#[cfg(not(target_os = "macos"))]
fn dispatch_main(f: impl FnOnce() + Send + 'static) {
    f();
}
