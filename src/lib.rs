//! strait: a Layer 4 load balancer.
//!
//! Current stage: a TCP proxy that forwards every connection to a single backend.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

/// Accepts connections on `listener` forever and forwards each one to `backend`.
///
/// Takes an already bound listener so callers (and tests) can bind to port 0.
pub async fn run(listener: TcpListener, backend: SocketAddr) -> Result<()> {
    info!(listen = %listener.local_addr()?, %backend, "strait is up");

    loop {
        let (client, peer) = listener.accept().await?;

        // One task per connection, so a slow or failing peer never blocks the accept loop.
        tokio::spawn(async move {
            if let Err(err) = handle(client, backend).await {
                warn!(%peer, error = %err, "connection failed");
            }
        });
    }
}

/// Connects `client` to `backend` and relays bytes in both directions until either side closes.
async fn handle(mut client: TcpStream, backend: SocketAddr) -> Result<()> {
    let peer = client.peer_addr()?;

    let mut upstream = TcpStream::connect(backend)
        .await
        .with_context(|| format!("could not connect to backend {backend}"))?;

    info!(%peer, %backend, "connection opened");

    let (sent, received) = copy_bidirectional(&mut client, &mut upstream).await?;

    info!(%peer, sent, received, "connection closed");
    Ok(())
}
