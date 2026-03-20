use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Lightweight global bandwidth counters for traffic visibility.
///
/// Records bytes sent to Tor (upload) and received from Tor (download)
/// across all TCP and DNS connections in a session.
pub struct BandwidthStats {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

impl BandwidthStats {
    pub fn new() -> Self {
        Self {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        }
    }

    /// Record bytes sent to Tor (upload).
    pub fn add_tx(&self, n: u64) {
        self.tx_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Record bytes received from Tor (download).
    pub fn add_rx(&self, n: u64) {
        self.rx_bytes.fetch_add(n, Ordering::Relaxed);
    }

    /// Total bytes sent to Tor.
    pub fn tx(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    /// Total bytes received from Tor.
    pub fn rx(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }

    /// Log a human-readable summary of bandwidth usage.
    pub fn log_summary(&self) {
        let tx = self.tx();
        let rx = self.rx();
        tracing::info!(
            upload = %format_bytes(tx),
            download = %format_bytes(rx),
            total = %format_bytes(tx + rx),
            "Bandwidth stats"
        );
    }
}

impl Default for BandwidthStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Wraps an `AsyncRead + AsyncWrite` stream and counts bytes inline.
///
/// Reading from the inner stream counts as download (rx).
/// Writing to the inner stream counts as upload (tx).
/// Bytes are recorded atomically as they pass through `poll_read`/`poll_write`,
/// so they're counted even when `copy_bidirectional` returns `Err`.
pub struct CountingIo<T> {
    inner: T,
    stats: Arc<BandwidthStats>,
}

impl<T> CountingIo<T> {
    pub fn new(inner: T, stats: Arc<BandwidthStats>) -> Self {
        Self { inner, stats }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountingIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            this.stats.add_rx(n as u64);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountingIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            this.stats.add_tx(*n as u64);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Format a byte count as a human-readable string (B/KB/MB/GB).
pub fn format_bytes(n: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if n >= GB {
        format!("{:.2} GB", n as f64 / GB as f64)
    } else if n >= MB {
        format!("{:.2} MB", n as f64 / MB as f64)
    } else if n >= KB {
        format!("{:.2} KB", n as f64 / KB as f64)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_counters_are_zero() {
        let stats = BandwidthStats::new();
        assert_eq!(stats.tx(), 0);
        assert_eq!(stats.rx(), 0);
    }

    #[test]
    fn test_add_tx() {
        let stats = BandwidthStats::new();
        stats.add_tx(100);
        stats.add_tx(200);
        assert_eq!(stats.tx(), 300);
    }

    #[test]
    fn test_add_rx() {
        let stats = BandwidthStats::new();
        stats.add_rx(500);
        stats.add_rx(1500);
        assert_eq!(stats.rx(), 2000);
    }

    #[test]
    fn test_tx_and_rx_independent() {
        let stats = BandwidthStats::new();
        stats.add_tx(100);
        stats.add_rx(200);
        assert_eq!(stats.tx(), 100);
        assert_eq!(stats.rx(), 200);
    }

    #[test]
    fn test_format_bytes_zero() {
        assert_eq!(format_bytes(0), "0 B");
    }

    #[test]
    fn test_format_bytes_bytes() {
        assert_eq!(format_bytes(1), "1 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_kilobytes() {
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
    }

    #[test]
    fn test_format_bytes_megabytes() {
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(5 * 1024 * 1024 + 512 * 1024), "5.50 MB");
    }

    #[test]
    fn test_format_bytes_gigabytes() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
        assert_eq!(
            format_bytes(2 * 1024 * 1024 * 1024 + 512 * 1024 * 1024),
            "2.50 GB"
        );
    }
}
