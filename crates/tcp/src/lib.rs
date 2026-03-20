use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use futures::StreamExt;
use netstack_smoltcp::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use bandwidth::CountingIo;
use dns::{self, is_onion_ip, HandlerCtx};

/// Run the TCP accept loop.
///
/// For each incoming connection from the netstack, determine the destination
/// and proxy the traffic through Tor. Limits concurrency to prevent resource exhaustion.
pub async fn run_tcp_handler(
    mut tcp_listener: TcpListener,
    ctx: HandlerCtx,
    max_connections: usize,
) {
    let semaphore = Arc::new(Semaphore::new(max_connections));

    loop {
        tokio::select! {
            biased;
            _ = ctx.cancel.cancelled() => break,
            conn = tcp_listener.next() => {
                let Some((stream, local_addr, remote_addr)) = conn else {
                    break;
                };

                tracing::debug!(
                    src = %local_addr,
                    dst = %remote_addr,
                    "New TCP connection"
                );

                let ctx = ctx.clone();

                // Acquire permit before spawn to apply backpressure to the accept loop
                let permit: OwnedSemaphorePermit = tokio::select! {
                    biased;
                    _ = ctx.cancel.cancelled() => break,
                    permit = semaphore.clone().acquire_owned() => {
                        match permit {
                            Ok(p) => p,
                            Err(_) => break, // semaphore closed
                        }
                    }
                };

                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = handle_tcp_connection(stream, remote_addr, &ctx).await {
                        tracing::debug!(
                            dst = %remote_addr,
                            error = %e,
                            "TCP connection ended"
                        );
                    }
                });
            }
        }
    }

    tracing::debug!("TCP handler stopped");
}

/// Handle a single TCP connection: connect to the destination through Tor
/// and bidirectionally copy data. DNS-over-TCP (port 53) is intercepted and
/// resolved via Tor rather than proxied as raw TCP.
async fn handle_tcp_connection(
    mut netstack_stream: netstack_smoltcp::TcpStream,
    dest: SocketAddr,
    ctx: &HandlerCtx,
) -> anyhow::Result<()> {
    // Intercept DNS-over-TCP (port 53) — resolve via Tor like UDP DNS.
    // Total connection lifetime capped to prevent a single slow client from
    // holding a TCP semaphore permit indefinitely (64 queries * 30s = 32min worst case).
    if dest.port() == 53 {
        const DNS_TCP_CONN_LIFETIME: std::time::Duration = std::time::Duration::from_secs(120);
        return match tokio::time::timeout(
            DNS_TCP_CONN_LIFETIME,
            handle_dns_tcp_connection(netstack_stream, ctx),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                tracing::debug!("DNS-over-TCP connection lifetime exceeded (120s)");
                Ok(())
            }
        };
    }

    // Check if destination is a synthetic .onion IP
    let tor_stream = if let IpAddr::V4(v4) = dest.ip() {
        if is_onion_ip(v4) {
            // Look up the .onion hostname by synthetic IP value
            let hostname = ctx
                .onion_map
                .lookup_by_ip(v4)
                .ok_or_else(|| anyhow::anyhow!("No .onion mapping for {v4}"))?;

            tracing::debug!(hostname = %hostname, port = dest.port(), "Connecting to .onion");
            ctx.tor.connect_onion(&hostname, dest.port()).await?
        } else {
            ctx.tor.connect_tcp(dest).await?
        }
    } else {
        ctx.tor.connect_tcp(dest).await?
    };

    // Arti DataStream implements futures::AsyncRead/AsyncWrite.
    // Netstack TcpStream implements tokio::AsyncRead/AsyncWrite.
    // Bridge them using tokio_util::compat, wrapped in CountingIo to track
    // bytes inline — copy_bidirectional loses byte counts on Err.
    let mut tor_stream = CountingIo::new(tor_stream.compat(), Arc::clone(&ctx.stats));

    match tokio::io::copy_bidirectional(&mut netstack_stream, &mut tor_stream).await {
        Ok((to_tor, from_tor)) => {
            tracing::trace!(
                dst = %dest,
                to_tor_bytes = to_tor,
                from_tor_bytes = from_tor,
                "TCP connection completed"
            );
        }
        Err(e) => {
            // Connection reset / broken pipe is normal for short-lived connections
            if e.kind() != std::io::ErrorKind::BrokenPipe
                && e.kind() != std::io::ErrorKind::ConnectionReset
            {
                return Err(e.into());
            }
        }
    }

    Ok(())
}

/// Handle a DNS-over-TCP connection (RFC 1035 §4.2.2).
///
/// DNS over TCP uses length-prefixed framing: each message is preceded by a
/// 2-byte big-endian length. We read queries in a loop (TCP DNS connections
/// may carry multiple queries), resolve each via Tor, and send back the
/// length-prefixed response.
///
/// Limited to 64 queries per connection to prevent abuse from a single client
/// holding a connection open and sending unlimited queries.
async fn handle_dns_tcp_connection(
    mut stream: netstack_smoltcp::TcpStream,
    ctx: &HandlerCtx,
) -> anyhow::Result<()> {
    const MAX_QUERIES_PER_CONN: usize = 64;
    /// Timeout for reading the 2-byte length prefix of a DNS-over-TCP message.
    /// Prevents idle connections from holding semaphore permits indefinitely.
    const DNS_TCP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    let mut query_count: usize = 0;

    loop {
        if query_count >= MAX_QUERIES_PER_CONN {
            tracing::debug!("DNS-over-TCP query limit reached, closing connection");
            return Ok(());
        }
        // Read 2-byte length prefix with timeout to prevent idle connections
        // from holding semaphore permits indefinitely
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(DNS_TCP_READ_TIMEOUT, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                tracing::debug!("DNS-over-TCP read timeout — closing idle connection");
                return Ok(());
            }
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            continue;
        }

        // Read the DNS message body with timeout — prevents a slow-loris attack
        // where an attacker sends the 2-byte length prefix but hangs on the payload,
        // holding a TCP semaphore permit indefinitely.
        let mut query = vec![0u8; msg_len];
        match tokio::time::timeout(DNS_TCP_READ_TIMEOUT, stream.read_exact(&mut query)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                tracing::debug!("DNS-over-TCP payload read timeout — closing connection");
                return Ok(());
            }
        }
        query_count += 1;
        // Bandwidth: counts local DNS query/response sizes, not Tor resolve traffic.
        ctx.stats.add_tx(msg_len as u64);

        // Resolve using the same logic as UDP DNS handler
        let response = match dns::handle_dns_query(
            &query,
            &ctx.tor,
            &ctx.onion_map,
            &ctx.dns_cache,
            ctx.dns_cache_ttl,
        )
        .await
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(error = %e, "DNS-over-TCP query handling failed");
                match dns::build_servfail(&query) {
                    Some(resp) => resp,
                    None => continue,
                }
            }
        };

        // Write length-prefixed response (DNS-over-TCP framing: 2-byte big-endian length)
        ctx.stats.add_rx(response.len() as u64);
        if response.len() > u16::MAX as usize {
            tracing::warn!(
                len = response.len(),
                "DNS-over-TCP response too large for u16 length prefix, sending SERVFAIL"
            );
            let fallback = dns::build_servfail(&query).unwrap_or_default();
            let resp_len = (fallback.len() as u16).to_be_bytes();
            stream.write_all(&resp_len).await?;
            stream.write_all(&fallback).await?;
            continue;
        }
        let resp_len = (response.len() as u16).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&response).await?;
    }
}
