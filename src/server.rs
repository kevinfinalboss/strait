//! Runs every listener from a [`Config`] and applies new configs without a restart.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{Instrument, error, info_span};

use crate::balancer::Pool;
use crate::config::{Config, ListenerConfig};
use crate::health::{self, HealthChecks};
use crate::metrics::{BackendState, Metrics};
use crate::{Route, serve};

/// All running listeners.
///
/// Listeners are identified by their `listen` address: a reload that keeps an
/// address updates that listener in place, even if its name changes.
pub struct Server {
    listeners: Vec<Running>,
    metrics: Arc<Metrics>,
    state: BackendState,
}

struct Running {
    config: ListenerConfig,
    local_addr: SocketAddr,
    route: Arc<ArcSwap<Route>>,
    accept: JoinHandle<()>,
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
        };
        server.reload(config).await?;
        Ok(server)
    }

    /// Live per-backend gauges for a Prometheus registry; follows every reload.
    pub fn backend_state(&self) -> BackendState {
        self.state.clone()
    }

    /// Name and bound address of every running listener.
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

        // Bind every new address before touching anything, so a port that is
        // already taken aborts the reload with the old listeners still running.
        let mut bound = Vec::new();
        for listener in &config.listeners {
            if !self
                .listeners
                .iter()
                .any(|r| r.config.listen == listener.listen)
            {
                let socket = TcpListener::bind(listener.listen).await.with_context(|| {
                    format!(
                        "listener {:?}: could not bind {}",
                        listener.name, listener.listen
                    )
                })?;
                bound.push((listener.listen, socket));
            }
        }

        let mut summary = ReloadSummary::default();
        let mut previous = std::mem::take(&mut self.listeners);

        for listener in &config.listeners {
            let name = listener.name.clone();
            match previous
                .iter()
                .position(|r| r.config.listen == listener.listen)
            {
                Some(index) => {
                    let mut running = previous.swap_remove(index);
                    if running.config == *listener {
                        summary.unchanged.push(name);
                    } else {
                        running.update(listener.clone(), &self.metrics)?;
                        summary.updated.push(name);
                    }
                    self.listeners.push(running);
                }
                None => {
                    let index = bound
                        .iter()
                        .position(|(addr, _)| *addr == listener.listen)
                        .expect("every new address was bound above");
                    let (_, socket) = bound.swap_remove(index);
                    self.listeners
                        .push(Running::start(listener.clone(), socket, &self.metrics)?);
                    summary.added.push(name);
                }
            }
        }

        // Dropping a listener stops its accept loop and health checks.
        summary.removed = previous.iter().map(|r| r.config.name.clone()).collect();
        self.state.set(
            self.listeners
                .iter()
                .map(|r| Arc::clone(&r.route))
                .collect(),
        );
        Ok(summary)
    }
}

impl Running {
    fn start(config: ListenerConfig, socket: TcpListener, metrics: &Arc<Metrics>) -> Result<Self> {
        let local_addr = socket.local_addr()?;
        let pool = Arc::new(Pool::new(config.backends.iter().copied(), config.strategy)?);
        let health = health::spawn(&pool, config.health());
        let route = Arc::new(ArcSwap::from_pointee(Route {
            name: config.name.as_str().into(),
            pool,
            proxy: config.proxy(),
            metrics: Arc::clone(metrics),
        }));

        let accept = tokio::spawn({
            let route = Arc::clone(&route);
            let span = info_span!("listener", name = %config.name);
            async move {
                if let Err(err) = serve(socket, route).await {
                    error!(error = %err, "listener stopped");
                }
            }
            .instrument(span)
        });

        Ok(Self {
            config,
            local_addr,
            route,
            accept,
            health,
        })
    }

    /// Swaps in a new pool and settings. Backends that stay keep their state.
    fn update(&mut self, config: ListenerConfig, metrics: &Arc<Metrics>) -> Result<()> {
        let current = self.route.load();
        let pool = Arc::new(Pool::rebuild(
            Some(&current.pool),
            config.backends.iter().copied(),
            config.strategy,
        )?);

        // Replacing the guard stops the health checks of the previous pool.
        self.health = health::spawn(&pool, config.health());
        self.route.store(Arc::new(Route {
            name: config.name.as_str().into(),
            pool,
            proxy: config.proxy(),
            metrics: Arc::clone(metrics),
        }));
        self.config = config;
        Ok(())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.accept.abort();
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
