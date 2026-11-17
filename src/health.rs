//! Active health checks: periodically open a TCP connection to every backend.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, timeout};
use tracing::{info, warn};

use crate::balancer::{Backend, Pool};

/// How backends are probed and how many results it takes to change their state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthCheck {
    /// Off means no probes: every backend stays healthy.
    pub enabled: bool,
    /// Port to probe instead of the backend's own.
    pub port: Option<u16>,
    /// Time between two probes of the same backend.
    pub interval: Duration,
    /// How long a probe may take before it counts as a failure.
    pub timeout: Duration,
    /// Consecutive failures before a healthy backend is taken out of rotation.
    pub unhealthy_threshold: u32,
    /// Consecutive successes before an unhealthy backend is put back.
    pub healthy_threshold: u32,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            enabled: true,
            port: None,
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(1),
            unhealthy_threshold: 2,
            healthy_threshold: 2,
        }
    }
}

/// The running health check tasks of one pool, one per backend. Dropping it stops them.
#[must_use = "health checks stop as soon as this is dropped"]
#[derive(Debug)]
pub struct HealthChecks {
    config: HealthCheck,
    tasks: HashMap<SocketAddr, Probing>,
}

/// The health check task of one backend.
#[derive(Debug)]
struct Probing {
    backend: Arc<Backend>,
    task: JoinHandle<()>,
}

impl Drop for Probing {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl HealthChecks {
    /// Follows a rebuilt pool: backends that stay keep their running check, with
    /// its schedule and its count of consecutive results; only backends that
    /// joined get a new one, and backends that left stop being probed.
    ///
    /// A different `config` restarts every check, since the thresholds and the
    /// interval of a running check cannot change.
    pub fn update(&mut self, pool: &Pool, config: HealthCheck) {
        if config != self.config {
            self.tasks.clear();
            self.config = config;
        }

        if !config.enabled {
            // Without checks nothing would ever mark a backend healthy again.
            self.tasks.clear();
            for backend in pool.backends() {
                backend.set_healthy(true);
            }
            return;
        }

        let mut previous = std::mem::take(&mut self.tasks);
        for backend in pool.backends() {
            let probing = match previous.remove(&backend.addr()) {
                // Same `Backend`, so the same health flag the task is updating.
                Some(probing) if Arc::ptr_eq(&probing.backend, backend) => probing,
                _ => Probing {
                    backend: Arc::clone(backend),
                    task: tokio::spawn(watch(Arc::clone(backend), config)),
                },
            };
            self.tasks.insert(backend.addr(), probing);
        }
        // Whatever is left in `previous` is dropped here, which stops it.
    }
}

/// Starts one background task per backend that keeps its health flag up to date.
pub fn spawn(pool: &Pool, config: HealthCheck) -> HealthChecks {
    let mut checks = HealthChecks {
        config,
        tasks: HashMap::new(),
    };
    checks.update(pool, config);
    checks
}

async fn watch(backend: Arc<Backend>, config: HealthCheck) {
    let mut ticker = interval(config.interval);
    // After a slow probe, wait a full interval instead of firing a burst of probes.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    // Consecutive results in the same direction; reset whenever the result flips.
    let mut successes = 0;
    let mut failures = 0;

    loop {
        ticker.tick().await;

        if probe(&backend, config.port, config.timeout).await {
            successes += 1;
            failures = 0;
            if successes >= config.healthy_threshold && !backend.set_healthy(true) {
                info!(backend = %backend.addr(), "backend is healthy again");
            }
        } else {
            failures += 1;
            successes = 0;
            if failures >= config.unhealthy_threshold && backend.set_healthy(false) {
                warn!(backend = %backend.addr(), "backend is unhealthy, removed from rotation");
            }
        }
    }
}

/// A backend passes when a TCP connection to it (or to `port` on its
/// address) succeeds within `limit`.
async fn probe(backend: &Backend, port: Option<u16>, limit: Duration) -> bool {
    let mut addr = backend.addr();
    if let Some(port) = port {
        addr.set_port(port);
    }
    matches!(timeout(limit, TcpStream::connect(addr)).await, Ok(Ok(_)))
}
