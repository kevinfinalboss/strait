//! Backend pool and load balancing strategies.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::{Result, bail};
use clap::ValueEnum;

/// A backend server, its health and the number of connections currently proxied to it.
#[derive(Debug)]
pub struct Backend {
    addr: SocketAddr,
    active: AtomicUsize,
    healthy: AtomicBool,
}

impl Backend {
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            active: AtomicUsize::new(0),
            healthy: AtomicBool::new(true),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Updates the health flag and returns the previous value.
    pub fn set_healthy(&self, healthy: bool) -> bool {
        self.healthy.swap(healthy, Ordering::Relaxed)
    }
}

/// Marks one connection as active on a backend for as long as it is alive.
///
/// The counter is decremented in `Drop`, so it stays correct even when the
/// connection ends with an error.
#[derive(Debug)]
pub struct Lease {
    backend: Arc<Backend>,
}

impl Lease {
    fn new(backend: Arc<Backend>) -> Self {
        backend.active.fetch_add(1, Ordering::Relaxed);
        Self { backend }
    }

    pub fn addr(&self) -> SocketAddr {
        self.backend.addr
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.backend.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Decides which backend receives the next connection.
///
/// `Send + Sync` is required because one strategy is shared by every connection task.
pub trait Strategy: Send + Sync {
    /// Returns the index of the chosen backend. `backends` is never empty.
    fn choose(&self, backends: &[Arc<Backend>]) -> usize;
}

/// Cycles through the backends in order.
#[derive(Debug, Default)]
pub struct RoundRobin {
    next: AtomicUsize,
}

impl Strategy for RoundRobin {
    fn choose(&self, backends: &[Arc<Backend>]) -> usize {
        self.next.fetch_add(1, Ordering::Relaxed) % backends.len()
    }
}

/// Picks the backend with the fewest active connections; ties go to the first one.
#[derive(Debug, Default)]
pub struct LeastConnections;

impl Strategy for LeastConnections {
    fn choose(&self, backends: &[Arc<Backend>]) -> usize {
        backends
            .iter()
            .enumerate()
            .min_by_key(|(_, backend)| backend.active_connections())
            .map(|(index, _)| index)
            .expect("backends is never empty")
    }
}

/// Strategy names accepted on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Algorithm {
    RoundRobin,
    LeastConn,
}

impl Algorithm {
    fn strategy(self) -> Box<dyn Strategy> {
        match self {
            Algorithm::RoundRobin => Box::new(RoundRobin::default()),
            Algorithm::LeastConn => Box::new(LeastConnections),
        }
    }
}

/// The set of backends plus the strategy used to pick between them.
pub struct Pool {
    backends: Vec<Arc<Backend>>,
    strategy: Box<dyn Strategy>,
}

impl Pool {
    pub fn new(addrs: impl IntoIterator<Item = SocketAddr>, algorithm: Algorithm) -> Result<Self> {
        let backends: Vec<_> = addrs
            .into_iter()
            .map(|addr| Arc::new(Backend::new(addr)))
            .collect();

        if backends.is_empty() {
            bail!("at least one backend is required");
        }

        Ok(Self {
            backends,
            strategy: algorithm.strategy(),
        })
    }

    /// Chooses a backend for a new connection and marks it as active.
    ///
    /// Backends in `exclude` are skipped, so a retry never hits the same backend twice.
    /// Only healthy backends are considered; if none is healthy, every remaining
    /// backend is tried instead (fail open), since health checks can be wrong.
    /// Returns `None` when every backend is excluded.
    pub fn lease(&self, exclude: &[SocketAddr]) -> Option<Lease> {
        let remaining: Vec<_> = self
            .backends
            .iter()
            .filter(|backend| !exclude.contains(&backend.addr))
            .cloned()
            .collect();

        let healthy: Vec<_> = remaining
            .iter()
            .filter(|backend| backend.is_healthy())
            .cloned()
            .collect();

        let candidates = if healthy.is_empty() {
            remaining
        } else {
            healthy
        };
        if candidates.is_empty() {
            return None;
        }

        let index = self.strategy.choose(&candidates);
        Some(Lease::new(Arc::clone(&candidates[index])))
    }

    pub fn backends(&self) -> &[Arc<Backend>] {
        &self.backends
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(pool: &Pool) -> Lease {
        pool.lease(&[]).unwrap()
    }

    fn addrs(count: u16) -> Vec<SocketAddr> {
        (1..=count)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
            .collect()
    }

    #[test]
    fn rejects_empty_pool() {
        assert!(Pool::new([], Algorithm::RoundRobin).is_err());
    }

    #[test]
    fn round_robin_cycles_through_backends() {
        let pool = Pool::new(addrs(3), Algorithm::RoundRobin).unwrap();

        let ports: Vec<u16> = (0..6).map(|_| lease(&pool).addr().port()).collect();

        assert_eq!(ports, [1, 2, 3, 1, 2, 3]);
    }

    #[test]
    fn least_connections_prefers_idle_backend() {
        let pool = Pool::new(addrs(3), Algorithm::LeastConn).unwrap();

        let first = lease(&pool);
        let second = lease(&pool);
        assert_eq!(first.addr().port(), 1);
        assert_eq!(second.addr().port(), 2);

        drop(first);
        assert_eq!(lease(&pool).addr().port(), 1);
    }

    #[test]
    fn dropping_lease_releases_connection() {
        let pool = Pool::new(addrs(1), Algorithm::RoundRobin).unwrap();
        let backend = &pool.backends()[0];

        let leased = lease(&pool);
        assert_eq!(backend.active_connections(), 1);

        drop(leased);
        assert_eq!(backend.active_connections(), 0);
    }

    #[test]
    fn skips_unhealthy_backends() {
        let pool = Pool::new(addrs(3), Algorithm::RoundRobin).unwrap();
        pool.backends()[1].set_healthy(false);

        let ports: Vec<u16> = (0..4).map(|_| lease(&pool).addr().port()).collect();

        assert_eq!(ports, [1, 3, 1, 3]);
    }

    #[test]
    fn fails_open_when_no_backend_is_healthy() {
        let pool = Pool::new(addrs(2), Algorithm::RoundRobin).unwrap();
        for backend in pool.backends() {
            backend.set_healthy(false);
        }

        assert!(pool.lease(&[]).is_some());
    }

    #[test]
    fn excludes_already_tried_backends() {
        let pool = Pool::new(addrs(2), Algorithm::RoundRobin).unwrap();
        let first = pool.backends()[0].addr();
        let second = pool.backends()[1].addr();

        assert_eq!(pool.lease(&[first]).unwrap().addr(), second);
        assert!(pool.lease(&[first, second]).is_none());
    }
}
