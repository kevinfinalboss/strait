//! Active health checks: periodically open a TCP connection to every backend.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, timeout};
use tracing::{info, warn};

use crate::balancer::{Backend, Pool};

/// How backends are probed and how many results it takes to change their state.
#[derive(Debug, Clone, Copy)]
pub struct HealthCheck {
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
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(1),
            unhealthy_threshold: 2,
            healthy_threshold: 2,
        }
    }
}

/// The running health check tasks of one pool. Dropping it stops them.
#[must_use = "health checks stop as soon as this is dropped"]
#[derive(Debug)]
pub struct HealthChecks {
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for HealthChecks {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Starts one background task per backend that keeps its health flag up to date.
pub fn spawn(pool: &Pool, config: HealthCheck) -> HealthChecks {
    let tasks = pool
        .backends()
        .iter()
        .map(|backend| tokio::spawn(watch(Arc::clone(backend), config)))
        .collect();
    HealthChecks { tasks }
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

        if probe(&backend, config.timeout).await {
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

/// A backend passes when a TCP connection to it succeeds within `limit`.
async fn probe(backend: &Backend, limit: Duration) -> bool {
    matches!(
        timeout(limit, TcpStream::connect(backend.addr())).await,
        Ok(Ok(_))
    )
}
