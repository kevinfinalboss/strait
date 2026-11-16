//! strait: a Layer 4 load balancer.
//!
//! Current stage: TCP load balancing across multiple backends with
//! round-robin or least-connections.

mod balancer;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

pub use balancer::{Algorithm, Backend, Lease, Pool, Strategy};

/// Accepts connections on `listener` forever and forwards each one to a backend from `pool`.
///
/// Takes an already bound listener so callers (and tests) can bind to port 0.
pub async fn run(listener: TcpListener, pool: Arc<Pool>) -> Result<()> {
    info!(
        listen = %listener.local_addr()?,
        backends = pool.backends().len(),
        "strait is up"
    );

    loop {
        let (client, peer) = listener.accept().await?;
        let lease = pool.lease();

        // One task per connection, so a slow or failing peer never blocks the accept loop.
        tokio::spawn(async move {
            let backend = lease.addr();
            if let Err(err) = handle(client, lease).await {
                warn!(%peer, %backend, error = %err, "connection failed");
            }
        });
    }
}

/// Connects `client` to the leased backend and relays bytes in both directions
/// until either side closes. The lease is released when this function returns.
async fn handle(mut client: TcpStream, lease: Lease) -> Result<()> {
    let peer = client.peer_addr()?;
    let backend = lease.addr();

    let mut upstream = TcpStream::connect(backend)
        .await
        .with_context(|| format!("could not connect to backend {backend}"))?;

    info!(%peer, %backend, "connection opened");

    let (sent, received) = copy_bidirectional(&mut client, &mut upstream).await?;

    info!(%peer, %backend, sent, received, "connection closed");
    Ok(())
}
