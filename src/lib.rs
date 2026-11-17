//! strait: a Layer 4 load balancer.
//!
//! TCP and UDP load balancing across multiple backends with active health
//! checks, connection retries, timeouts, client IP affinity and a YAML config
//! that can be reloaded without dropping connections.

mod balancer;
mod config;
mod discovery;
mod health;
pub mod maglev;
mod metrics;
mod proxy_protocol;
mod relay;
mod server;
mod stun;
mod udp;
#[cfg(feature = "xdp")]
pub mod xdp;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_util::task::TaskTracker;
use tracing::{Instrument, debug, info, info_span, warn};

pub use balancer::{
    Algorithm, Backend, Candidates, IpHash, Lease, LeastConnections, Pool, RoundRobin, Strategy,
};
pub use config::{
    Config, Dataplane, HealthCheckConfig, KubernetesBackends, ListenerConfig, MacAddr,
    MetricsConfig, Protocol, ServicePort, XdpConfig, XdpMode,
};
pub use health::{HealthCheck, HealthChecks, spawn as spawn_health_checks};
pub use metrics::{
    BackendMetrics, BackendState, ListenerMetrics, Metrics, ReloadResult, TransferCounters,
    serve_metrics,
};
pub use proxy_protocol::{ProxyProtocol, header_v2 as proxy_protocol_v2};
pub use relay::{Transferred, relay};
pub use server::{ReloadSummary, Server};
pub use stun::{StunUsername, Template as StunTemplate};
pub use udp::{DEFAULT_UDP_IDLE_TIMEOUT, UdpSettings, serve as serve_udp};

/// Per-connection behavior of the proxy.
#[derive(Debug, Clone, Copy)]
pub struct ProxyConfig {
    /// Maximum time to establish a connection to a backend.
    pub connect_timeout: Duration,
    /// Close a connection when no byte moves in either direction for this long.
    pub idle_timeout: Duration,
    /// Extra backends to try when connecting to the chosen one fails.
    pub retries: usize,
    /// Header sent to the backend before any client byte, carrying the
    /// client's address.
    pub proxy_protocol: Option<ProxyProtocol>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            idle_timeout: Duration::from_secs(300),
            retries: 2,
            proxy_protocol: None,
        }
    }
}

/// Where a listener sends its connections. Swapped atomically on a config reload.
pub struct Route {
    /// Listener name, attached to every connection log.
    pub name: Arc<str>,
    pub pool: Arc<Pool>,
    pub proxy: ProxyConfig,
    pub metrics: Arc<Metrics>,
    listener_metrics: Arc<ListenerMetrics>,
    /// Metric handles of every backend in `pool`, so connections never build labels.
    backend_metrics: HashMap<SocketAddr, Arc<BackendMetrics>>,
    /// Every connection task of the listener, so shutdown can wait for them.
    connections: TaskTracker,
    /// Set on the routes of UDP listeners.
    udp: Option<udp::UdpRoute>,
}

impl Route {
    pub fn new(
        name: impl Into<Arc<str>>,
        pool: Arc<Pool>,
        proxy: ProxyConfig,
        metrics: Arc<Metrics>,
        connections: TaskTracker,
    ) -> Self {
        let name = name.into();
        let backend_metrics = pool
            .backends()
            .iter()
            .map(|backend| (backend.addr(), metrics.backend(&name, backend.addr())))
            .collect();
        Self {
            listener_metrics: metrics.listener(&name),
            backend_metrics,
            name,
            pool,
            proxy,
            metrics,
            connections,
            udp: None,
        }
    }

    /// Makes this the route of a UDP listener. `pods` maps pod names to
    /// backends of `pool`, for `stun-username`.
    pub fn with_udp(mut self, settings: UdpSettings, pods: BTreeMap<String, SocketAddr>) -> Self {
        let backends = self
            .pool
            .backends()
            .iter()
            .map(|backend| {
                let addr = backend.addr();
                (addr, self.metrics.udp_backend(&self.name, addr))
            })
            .collect();
        self.udp = Some(udp::UdpRoute {
            settings,
            pods,
            metrics: self.metrics.udp_listener(&self.name),
            backends,
        });
        self
    }

    fn backend_metrics(&self, backend: SocketAddr) -> Arc<BackendMetrics> {
        match self.backend_metrics.get(&backend) {
            Some(handles) => Arc::clone(handles),
            // Unreachable while leases come from `pool`; kept as a safe fallback.
            None => self.metrics.backend(&self.name, backend),
        }
    }
}

/// Accepts connections on `listener` forever and forwards each one to a backend from `pool`.
///
/// Takes an already bound listener so callers (and tests) can bind to port 0.
pub async fn run(listener: TcpListener, pool: Arc<Pool>, config: ProxyConfig) -> Result<()> {
    let route = Arc::new(ArcSwap::from_pointee(Route::new(
        "default",
        pool,
        config,
        Arc::new(Metrics::default()),
        TaskTracker::new(),
    )));
    serve(listener, route).await
}

/// Like [`run`], but reads the route again for every connection, so a reload can
/// replace it while the listener keeps running.
pub async fn serve(listener: TcpListener, route: Arc<ArcSwap<Route>>) -> Result<()> {
    info!(
        listen = %listener.local_addr()?,
        backends = route.load().pool.backends().len(),
        "listening"
    );

    loop {
        let (client, peer) = listener.accept().await?;

        // Each connection keeps the route that was current when it arrived, so a
        // reload never changes the backend pool under an open connection.
        let route = route.load_full();
        route.listener_metrics.accepted.inc();

        // One task per connection, so a slow or failing peer never blocks the accept loop.
        let span = info_span!("conn", listener = %route.name);
        let connections = route.connections.clone();
        connections.spawn(
            async move {
                if let Err(err) = handle(client, peer, &route).await {
                    warn!(%peer, error = %err, "connection failed");
                }
            }
            .instrument(span),
        );
    }
}

/// Connects `client` to a backend, retrying on others if needed, then relays bytes
/// until both sides close. The lease is released when this function returns.
async fn handle(mut client: TcpStream, peer: SocketAddr, route: &Route) -> Result<()> {
    let Ok((lease, mut upstream, metrics)) = connect(route, peer).await.inspect_err(|_| {
        route.listener_metrics.no_backend.inc();
    }) else {
        bail!("no backend accepted the connection");
    };
    let backend = lease.addr();
    metrics.connections.inc();
    let started = Instant::now();

    client.set_nodelay(true)?;
    upstream.set_nodelay(true)?;

    if let Some(ProxyProtocol::V2) = route.proxy.proxy_protocol {
        // The address the client connected to, which a wildcard listener
        // only knows per connection.
        let header = proxy_protocol::header_v2(peer, client.local_addr()?);
        upstream
            .write_all(&header)
            .await
            .inspect_err(|_| {
                route.listener_metrics.relay_errors.inc();
            })
            .with_context(|| format!("could not send the PROXY header to {backend}"))?;
    }

    // Per-connection logs are debug: at info they would cost more than the
    // proxying itself under load. Metrics cover the totals; failures are warn.
    debug!(%peer, %backend, "connection opened");

    let result = relay(
        &mut client,
        &mut upstream,
        route.proxy.idle_timeout,
        &metrics.transfer,
    )
    .await;
    metrics
        .connection_duration
        .observe(started.elapsed().as_secs_f64());
    let transferred = result
        .inspect_err(|_| {
            route.listener_metrics.relay_errors.inc();
        })
        .with_context(|| format!("relay to {backend} stopped"))?;

    debug!(
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
    route: &Route,
    client: SocketAddr,
) -> Result<(Lease, TcpStream, Arc<BackendMetrics>)> {
    let config = route.proxy;
    let mut tried: Vec<SocketAddr> = Vec::new();

    for _ in 0..=config.retries {
        let Some(lease) = route.pool.lease(client, &tried) else {
            break;
        };
        let backend = lease.addr();
        let metrics = route.backend_metrics(backend);
        let started = Instant::now();

        let failure = match timeout(config.connect_timeout, TcpStream::connect(backend)).await {
            Ok(Ok(upstream)) => {
                metrics
                    .connect_duration
                    .observe(started.elapsed().as_secs_f64());
                return Ok((lease, upstream, metrics));
            }
            Ok(Err(err)) => {
                warn!(%backend, error = %err, "backend refused connection");
                metrics::ConnectFailure::Refused
            }
            Err(_) => {
                warn!(%backend, "backend connect timed out");
                metrics::ConnectFailure::Timeout
            }
        };
        metrics.connect_failure(failure).inc();
        tried.push(backend);
    }

    bail!("no backend accepted the connection (tried {})", tried.len())
}
