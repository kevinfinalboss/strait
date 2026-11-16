//! Backend pool and load balancing strategies.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, bail};
use clap::ValueEnum;

/// A backend server and the number of connections currently proxied to it.
#[derive(Debug)]
pub struct Backend {
    addr: SocketAddr,
    active: AtomicUsize,
}

impl Backend {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Relaxed)
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
            .map(|addr| {
                Arc::new(Backend {
                    addr,
                    active: AtomicUsize::new(0),
                })
            })
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
    pub fn lease(&self) -> Lease {
        let index = self.strategy.choose(&self.backends);
        Lease::new(Arc::clone(&self.backends[index]))
    }

    pub fn backends(&self) -> &[Arc<Backend>] {
        &self.backends
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let ports: Vec<u16> = (0..6).map(|_| pool.lease().addr().port()).collect();

        assert_eq!(ports, [1, 2, 3, 1, 2, 3]);
    }

    #[test]
    fn least_connections_prefers_idle_backend() {
        let pool = Pool::new(addrs(3), Algorithm::LeastConn).unwrap();

        let first = pool.lease();
        let second = pool.lease();
        assert_eq!(first.addr().port(), 1);
        assert_eq!(second.addr().port(), 2);

        drop(first);
        assert_eq!(pool.lease().addr().port(), 1);
    }

    #[test]
    fn dropping_lease_releases_connection() {
        let pool = Pool::new(addrs(1), Algorithm::RoundRobin).unwrap();
        let backend = &pool.backends()[0];

        let lease = pool.lease();
        assert_eq!(backend.active_connections(), 1);

        drop(lease);
        assert_eq!(backend.active_connections(), 0);
    }
}
