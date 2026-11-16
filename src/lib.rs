//! strait: a Layer 4 load balancer.
//!
//! Current stage: TCP load balancing across multiple backends with active
//! health checks, connection retries, timeouts and client IP affinity.

mod balancer;
mod health;
mod relay;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{info, warn};

pub use balancer::{
    Algorithm, Backend, IpHash, Lease, LeastConnections, Pool, RoundRobin, Strategy,
};
pub use health::{HealthCheck, spawn as spawn_health_checks};
pub use relay::{Transferred, relay};

/// Per-connection behavior of the proxy.
#[derive(Debug, Clone, Copy)]
pub struct ProxyConfig {
    /// Maximum time to establish a connection to a backend.
    pub connect_timeout: Duration,
    /// Close a connection when no byte moves in either direction for this long.
    pub idle_timeout: Duration,
    /// Extra backends to try when connecting to the chosen one fails.
    pub retries: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(300),
            retries: 2,
        }
    }
}

/// Accepts connections on `listener` forever and forwards each one to a backend from `pool`.
///
/// Takes an already bound listener so callers (and tests) can bind to port 0.
pub async fn run(listener: TcpListener, pool: Arc<Pool>, config: ProxyConfig) -> Result<()> {
    info!(
        listen = %listener.local_addr()?,
        backends = pool.backends().len(),
        "strait is up"
    );

    loop {
        let (client, peer) = listener.accept().await?;
        let pool = Arc::clone(&pool);

        // One task per connection, so a slow or failing peer never blocks the accept loop.
        tokio::spawn(async move {
            if let Err(err) = handle(client, peer, &pool, config).await {
                warn!(%peer, error = %err, "connection failed");
            }
        });
    }
}

/// Connects `client` to a backend, retrying on others if needed, then relays bytes
/// until both sides close. The lease is released when this function returns.
async fn handle(
    mut client: TcpStream,
    peer: SocketAddr,
    pool: &Pool,
    config: ProxyConfig,
) -> Result<()> {
    let (lease, mut upstream) = connect(pool, peer, config).await?;
    let backend = lease.addr();

    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;

    info!(%peer, %backend, "connection opened");

    let transferred = relay(&mut client, &mut upstream, config.idle_timeout)
        .await
        .with_context(|| format!("relay to {backend} stopped"))?;

    info!(
        %peer,
        %backend,
        sent = transferred.sent,
        received = transferred.received,
        "connection closed"
    );
    Ok(())
}

/// Tries up to `1 + retries` different backends and returns the first that accepts.
async fn connect(
    pool: &Pool,
    client: SocketAddr,
    config: ProxyConfig,
) -> Result<(Lease, TcpStream)> {
    let mut tried: Vec<SocketAddr> = Vec::new();

    for _ in 0..=config.retries {
        let Some(lease) = pool.lease(client, &tried) else {
            break;
        };
        let backend = lease.addr();

        match timeout(config.connect_timeout, TcpStream::connect(backend)).await {
            Ok(Ok(upstream)) => return Ok((lease, upstream)),
            Ok(Err(err)) => warn!(%backend, error = %err, "backend refused connection"),
            Err(_) => warn!(%backend, "backend connect timed out"),
        }
        tried.push(backend);
    }

    bail!("no backend accepted the connection (tried {})", tried.len())
}
