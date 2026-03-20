use std::sync::Arc;

use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tun_rs::async_framed::{BytesCodec, DeviceFramed};
use tun_rs::AsyncDevice;

pub struct NetstackHandle {
    pub tcp_listener: TcpListener,
    pub udp_socket: UdpSocket,
    _tasks: Vec<JoinHandle<()>>,
}

/// Set up the userspace TCP/IP stack and bidirectional packet pump between TUN and stack.
pub fn start_netstack(
    device: AsyncDevice,
    cancel: CancellationToken,
) -> anyhow::Result<NetstackHandle> {
    // Wrap device in Arc for the framed split
    let dev = Arc::new(device);
    let (tun_reader, tun_writer) = DeviceFramed::new(dev, BytesCodec::new()).split();

    // Build netstack
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .build()?;

    let tcp_listener = tcp_listener.expect("TCP was enabled");
    let udp_socket = udp_socket.expect("UDP was enabled");

    let mut tasks = Vec::new();

    // Spawn the TCP/ICMP runner
    if let Some(runner) = runner {
        tasks.push(tokio::spawn(async move {
            if let Err(e) = runner.await {
                tracing::error!(error = %e, "Netstack runner error");
            }
        }));
    }

    // Split stack into separate sink (write) and stream (read) halves
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Packet pump: TUN → Stack
    let cancel_tun = cancel.clone();
    tasks.push(tokio::spawn(async move {
        let mut tun_stream = tun_reader;
        loop {
            tokio::select! {
                biased;
                _ = cancel_tun.cancelled() => break,
                pkt = tun_stream.next() => {
                    match pkt {
                        Some(Ok(pkt)) => {
                            if let Err(e) = stack_sink.send(pkt.to_vec()).await {
                                tracing::warn!(error = %e, "TUN→Stack send error");
                            }
                        }
                        Some(Err(e)) => tracing::warn!(error = %e, "TUN recv error"),
                        None => break,
                    }
                }
            }
        }
        tracing::debug!("TUN→Stack pump stopped");
    }));

    // Packet pump: Stack → TUN
    tasks.push(tokio::spawn(async move {
        let mut tun_sink = tun_writer;
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                pkt = stack_stream.next() => {
                    match pkt {
                        Some(Ok(pkt)) => {
                            if let Err(e) = tun_sink.send(BytesMut::from(pkt.as_slice())).await {
                                tracing::warn!(error = %e, "Stack→TUN send error");
                            }
                        }
                        Some(Err(e)) => tracing::warn!(error = %e, "Stack recv error"),
                        None => break,
                    }
                }
            }
        }
        tracing::debug!("Stack→TUN pump stopped");
    }));

    tracing::info!("Netstack started with bidirectional packet pump");

    Ok(NetstackHandle {
        tcp_listener,
        udp_socket,
        _tasks: tasks,
    })
}
