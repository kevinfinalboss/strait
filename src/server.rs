//! Runs every listener from a [`Config`] and applies new configs without a restart.

use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use kube::Client;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::task::TaskTracker;
use tracing::{Instrument, error, info, info_span};

use crate::balancer::Pool;
use crate::config::{Config, Dataplane, ListenerConfig};
use crate::discovery;
use crate::health::{self, HealthChecks};
use crate::metrics::{BackendState, Metrics};
use crate::{Route, serve};

/// All running listeners.
///
/// Listeners are identified by their `listen` address and data plane: a reload
/// that keeps both updates that listener in place, even if its name changes.
pub struct Server {
    listeners: Vec<Running>,
    metrics: Arc<Metrics>,
    state: BackendState,
    /// Created on the first config that discovers backends from Kubernetes.
    kube: Option<Client>,
    /// Connection tasks of every listener, including removed ones.
    connections: TaskTracker,
    /// Attached on the first config with an XDP listener; stays until shutdown.
    #[cfg(feature = "xdp")]
    xdp: Option<Arc<crate::xdp::DataPlane>>,
    #[cfg(feature = "xdp")]
    xdp_stats: crate::xdp::XdpStats,
}

struct Running {
    config: ListenerConfig,
    local_addr: SocketAddr,
    upstream: Arc<Upstream>,
    /// Accept loop of a proxy listener.
    accept: Option<JoinHandle<()>>,
    discovery: Option<JoinHandle<()>>,
    /// VIP of an XDP listener; dropping it removes the VIP from the data plane.
    #[cfg(feature = "xdp")]
    _xdp: Option<crate::xdp::Binding>,
}

/// What receives a new listener's traffic.
enum Frontend {
    /// A bound socket and its actual address, for a proxy listener.
    Socket(TcpListener, SocketAddr),
    #[cfg(feature = "xdp")]
    Xdp(Arc<crate::xdp::DataPlane>),
}

/// Whether `running` can be updated in place to `config`.
fn same_listener(running: &ListenerConfig, config: &ListenerConfig) -> bool {
    running.listen == config.listen
        && running.dataplane == config.dataplane
        && running.protocol == config.protocol
}

/// The parts of a listener that a reload or a discovery update can change.
///
/// Both go through [`Upstream::apply`], under one lock, so a config reload and
/// an endpoint change never overwrite each other.
struct Upstream {
    route: Arc<ArcSwap<Route>>,
    metrics: Arc<Metrics>,
    connections: TaskTracker,
    state: Mutex<UpstreamState>,
}

struct UpstreamState {
    config: ListenerConfig,
    backends: Vec<SocketAddr>,
    health: HealthChecks,
}

/// Names of the listeners touched by a reload, by what happened to them.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReloadSummary {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub unchanged: Vec<String>,
    pub removed: Vec<String>,
}

impl Server {
    pub async fn start(config: &Config) -> Result<Self> {
        Self::with_metrics(config, Arc::new(Metrics::default())).await
    }

    /// Like [`start`](Self::start), recording into `metrics`.
    pub async fn with_metrics(config: &Config, metrics: Arc<Metrics>) -> Result<Self> {
        let mut server = Self {
            listeners: Vec::new(),
            metrics,
            state: BackendState::default(),
            kube: None,
            connections: TaskTracker::new(),
            #[cfg(feature = "xdp")]
            xdp: None,
            #[cfg(feature = "xdp")]
            xdp_stats: crate::xdp::XdpStats::default(),
        };
        server.reload(config).await?;
        Ok(server)
    }

    /// Live per-backend gauges for a Prometheus registry; follows every reload.
    pub fn backend_state(&self) -> BackendState {
        self.state.clone()
    }

    /// Prometheus counters of the XDP data plane; empty until it is attached.
    #[cfg(feature = "xdp")]
    pub fn xdp_stats(&self) -> crate::xdp::XdpStats {
        self.xdp_stats.clone()
    }

    /// Name and bound address of every running listener (the VIP for XDP ones).
    pub fn local_addrs(&self) -> Vec<(String, SocketAddr)> {
        self.listeners
            .iter()
            .map(|running| (running.config.name.clone(), running.local_addr))
            .collect()
    }

    /// Applies `config`. On error nothing changes and the previous config keeps running.
    ///
    /// Open connections are never interrupted: they keep the route they started
    /// with, including on listeners that the new config removes.
    pub async fn reload(&mut self, config: &Config) -> Result<ReloadSummary> {
        config.validate()?;

        if self.kube.is_none() && config.listeners.iter().any(|l| l.kubernetes.is_some()) {
            let client = Client::try_default()
                .await
                .context("could not connect to the Kubernetes API")?;
            self.kube = Some(client);
        }
        let uses_xdp = config
            .listeners
            .iter()
            .any(|l| l.dataplane == Dataplane::Xdp);
        #[cfg(feature = "xdp")]
        if uses_xdp {
            let wanted = config
                .xdp
                .as_ref()
                .expect("validated: xdp listeners need it");
            match &self.xdp {
                None => {
                    let dataplane = crate::xdp::DataPlane::attach(wanted)?;
                    let dataplane = Arc::new(dataplane);
                    self.xdp_stats.set(Arc::clone(&dataplane));
                    self.xdp = Some(dataplane);
                }
                Some(running) if running.config() != wanted => {
                    tracing::warn!("xdp settings changed; restart strait to apply them");
                }
                Some(_) => {}
            }
        }
        #[cfg(not(feature = "xdp"))]
        debug_assert!(
            !uses_xdp,
            "validate rejects xdp listeners without the feature"
        );

        // Bind every new address before touching anything, so a port that is
        // already taken aborts the reload with the old listeners still running.
        // Past this loop nothing can fail, so a reload applies fully or not at all.
        let mut bound = Vec::new();
        for listener in &config.listeners {
            let kept = self
                .listeners
                .iter()
                .any(|r| same_listener(&r.config, listener));
            if !kept && listener.dataplane == Dataplane::Proxy {
                let socket = TcpListener::bind(listener.listen).await.with_context(|| {
                    format!(
                        "listener {:?}: could not bind {}",
                        listener.name, listener.listen
                    )
                })?;
                let local_addr = socket.local_addr().with_context(|| {
                    format!("listener {:?}: bound address unknown", listener.name)
                })?;
                bound.push((listener.listen, socket, local_addr));
            }
        }

        let mut summary = ReloadSummary::default();
        let mut previous = std::mem::take(&mut self.listeners);

        for listener in &config.listeners {
            let name = listener.name.clone();
            match previous
                .iter()
                .position(|r| same_listener(&r.config, listener))
            {
                Some(index) => {
                    let mut running = previous.swap_remove(index);
                    if running.config == *listener {
                        summary.unchanged.push(name);
                    } else {
                        running.update(listener.clone(), self.kube.as_ref());
                        summary.updated.push(name);
                    }
                    self.listeners.push(running);
                }
                None => {
                    let frontend = match listener.dataplane {
                        Dataplane::Proxy => {
                            let index = bound
                                .iter()
                                .position(|(addr, _, _)| *addr == listener.listen)
                                .expect("every new proxy address was bound above");
                            let (_, socket, local_addr) = bound.swap_remove(index);
                            Frontend::Socket(socket, local_addr)
                        }
                        #[cfg(feature = "xdp")]
                        Dataplane::Xdp => {
                            Frontend::Xdp(Arc::clone(self.xdp.as_ref().expect("attached above")))
                        }
                        #[cfg(not(feature = "xdp"))]
                        Dataplane::Xdp => unreachable!("validate rejects xdp listeners"),
                    };
                    self.listeners.push(Running::start(
                        listener.clone(),
                        frontend,
                        &self.metrics,
                        &self.connections,
                        self.kube.as_ref(),
                    ));
                    summary.added.push(name);
                }
            }
        }

        // Dropping a listener stops its accept loop, discovery and health checks.
        summary.removed = previous.iter().map(|r| r.config.name.clone()).collect();
        self.state.set(
            self.listeners
                .iter()
                .map(|r| Arc::clone(&r.upstream.route))
                .collect(),
        );
        Ok(summary)
    }

    /// Stops accepting connections, then waits up to `grace` for the open ones
    /// to finish. Returns how many were still open when `grace` ran out; they
    /// are cut when the runtime shuts down.
    pub async fn shutdown(self, grace: Duration) -> usize {
        // Dropping the listeners closes their sockets and stops discovery.
        drop(self.listeners);
        self.connections.close();

        let open = self.connections.len();
        if open == 0 {
            return 0;
        }
        info!(connections = open, grace = %humantime::format_duration(grace), "draining connections");
        match timeout(grace, self.connections.wait()).await {
            Ok(()) => 0,
            Err(_) => self.connections.len(),
        }
    }
}

impl Running {
    fn start(
        config: ListenerConfig,
        frontend: Frontend,
        metrics: &Arc<Metrics>,
        connections: &TaskTracker,
        kube: Option<&Client>,
    ) -> Self {
        let upstream = Arc::new(Upstream::new(
            config.clone(),
            Arc::clone(metrics),
            connections.clone(),
        ));
        let span = info_span!("listener", name = %config.name);

        let mut running = Self {
            local_addr: config.listen,
            discovery: start_discovery(&config, &upstream, kube),
            upstream,
            accept: None,
            #[cfg(feature = "xdp")]
            _xdp: None,
            config,
        };
        match frontend {
            Frontend::Socket(socket, local_addr) => {
                let route = Arc::clone(&running.upstream.route);
                running.local_addr = local_addr;
                running.accept = Some(tokio::spawn(
                    async move {
                        if let Err(err) = serve(socket, route).await {
                            error!(error = %err, "listener stopped");
                        }
                    }
                    .instrument(span),
                ));
            }
            #[cfg(feature = "xdp")]
            Frontend::Xdp(dataplane) => {
                running._xdp = Some(crate::xdp::Binding::start(
                    dataplane,
                    running.config.listen,
                    running.config.protocol,
                    Arc::clone(&running.upstream.route),
                    span,
                ));
            }
        }
        running
    }

    /// Applies new settings in place. Backends that stay keep their state.
    fn update(&mut self, config: ListenerConfig, kube: Option<&Client>) {
        // A different Kubernetes source needs a new watch. Until it reports, the
        // listener keeps the backends it already had instead of dropping to none.
        if config.kubernetes != self.config.kubernetes {
            if let Some(task) = self.discovery.take() {
                task.abort();
            }
            self.discovery = start_discovery(&config, &self.upstream, kube);
        }
        self.upstream.reconfigure(config.clone());
        self.config = config;
    }
}

fn start_discovery(
    config: &ListenerConfig,
    upstream: &Arc<Upstream>,
    kube: Option<&Client>,
) -> Option<JoinHandle<()>> {
    let source = config.kubernetes.clone()?;
    let client = kube.expect("a Kubernetes client exists whenever a listener needs one");
    let upstream = Arc::clone(upstream);
    let span = info_span!("listener", name = %config.name);
    Some(discovery::spawn(
        client.clone(),
        source,
        span,
        move |backends| {
            upstream.set_backends(backends);
        },
    ))
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(task) = &self.accept {
            task.abort();
        }
        if let Some(task) = &self.discovery {
            task.abort();
        }
    }
}

impl Upstream {
    fn new(config: ListenerConfig, metrics: Arc<Metrics>, connections: TaskTracker) -> Self {
        // Kubernetes listeners start empty and fill in on the first endpoint list.
        let backends = config.backends.clone();
        let pool = Arc::new(Pool::new(backends.iter().copied(), config.strategy));
        let health = health::spawn(&pool, config.health());
        let route = Arc::new(ArcSwap::from_pointee(Route::new(
            config.name.as_str(),
            pool,
            config.proxy(),
            Arc::clone(&metrics),
            connections.clone(),
        )));
        Self {
            route,
            metrics,
            connections,
            state: Mutex::new(UpstreamState {
                config,
                backends,
                health,
            }),
        }
    }

    /// New listener settings from a reload. Static listeners also take their
    /// backends from the config; Kubernetes ones keep what discovery found.
    fn reconfigure(&self, config: ListenerConfig) {
        let mut state = self.state.lock().expect("upstream lock poisoned");
        if config.kubernetes.is_none() {
            state.backends = config.backends.clone();
        }
        state.config = config;
        self.apply(&mut state);
    }

    /// New backend list from discovery.
    fn set_backends(&self, backends: Vec<SocketAddr>) {
        let mut state = self.state.lock().expect("upstream lock poisoned");
        state.backends = backends;
        self.apply(&mut state);
    }

    fn apply(&self, state: &mut UpstreamState) {
        let config = &state.config;
        let current = self.route.load();
        let pool = Arc::new(Pool::rebuild(
            Some(&current.pool),
            state.backends.iter().copied(),
            config.strategy,
        ));

        // Backends that stay keep their running check; see `HealthChecks::update`.
        let health = config.health();
        state.health.update(&pool, health);
        self.route.store(Arc::new(Route::new(
            config.name.as_str(),
            pool,
            config.proxy(),
            Arc::clone(&self.metrics),
            self.connections.clone(),
        )));
    }
}

impl fmt::Display for ReloadSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let groups = [
            ("added", &self.added),
            ("updated", &self.updated),
            ("unchanged", &self.unchanged),
            ("removed", &self.removed),
        ];
        let parts: Vec<String> = groups
            .iter()
            .filter(|(_, names)| !names.is_empty())
            .map(|(label, names)| format!("{label}: {}", names.join(", ")))
            .collect();
        f.write_str(&parts.join("; "))
    }
}
