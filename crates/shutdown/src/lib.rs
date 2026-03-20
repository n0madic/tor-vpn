use std::sync::{Arc, Mutex};

use tokio_util::sync::CancellationToken;

/// Wait for SIGINT (Ctrl+C) or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = ctrl_c => {
                        tracing::info!("Received SIGINT (Ctrl+C)");
                    }
                    _ = sigterm.recv() => {
                        tracing::info!("Received SIGTERM");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to register SIGTERM handler, using SIGINT only");
                let _ = ctrl_c.await;
                tracing::info!("Received SIGINT (Ctrl+C)");
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("Failed to listen for Ctrl+C");
        tracing::info!("Received Ctrl+C");
    }
}

/// Create a SIGUSR1 signal stream for circuit refresh. Unix only.
///
/// Returns `None` if the signal handler cannot be registered.
#[cfg(unix)]
pub fn sigusr1_stream() -> Option<tokio::signal::unix::Signal> {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()) {
        Ok(sig) => Some(sig),
        Err(e) => {
            tracing::warn!(error = %e, "Failed to register SIGUSR1 handler");
            None
        }
    }
}

/// Install a panic hook that cancels the current session's token.
///
/// Uses `Arc<Mutex<CancellationToken>>` so the token can be swapped each
/// session while the hook itself is installed only once.
pub fn install_panic_hook_shared(cancel: Arc<Mutex<CancellationToken>>) {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!("PANIC: {info}");
        if let Ok(token) = cancel.lock() {
            token.cancel();
        }
        default_hook(info);
    }));
}
