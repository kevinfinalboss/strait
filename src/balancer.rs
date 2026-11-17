//! Backend pool and load balancing strategies.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use clap::ValueEnum;
use serde::Deserialize;

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

/// The backends a strategy may pick from for one connection.
///
/// A filtered view of the pool rather than a list, so choosing a backend does not
/// allocate. Health flags can change while a strategy looks at them, so the view
/// may shrink between two passes.
#[derive(Debug, Clone, Copy)]
pub struct Candidates<'a> {
    backends: &'a [Arc<Backend>],
    exclude: &'a [SocketAddr],
    healthy_only: bool,
}

impl<'a> Candidates<'a> {
    pub fn iter(self) -> impl Iterator<Item = &'a Arc<Backend>> + Clone {
        let Self {
            backends,
            exclude,
            healthy_only,
        } = self;
        backends.iter().filter(move |backend| {
            !exclude.contains(&backend.addr) && (!healthy_only || backend.is_healthy())
        })
    }
}

/// Decides which backend receives the next connection.
///
/// `Send + Sync` is required because one strategy is shared by every connection task.
pub trait Strategy: Send + Sync {
    /// Returns the chosen backend for a connection from `client`, or `None` if
    /// `candidates` turned out to be empty.
    fn choose<'a>(
        &self,
        candidates: Candidates<'a>,
        client: SocketAddr,
    ) -> Option<&'a Arc<Backend>>;
}

/// Cycles through the backends in order.
#[derive(Debug, Default)]
pub struct RoundRobin {
    next: AtomicUsize,
}

impl Strategy for RoundRobin {
    fn choose<'a>(
        &self,
        candidates: Candidates<'a>,
        _client: SocketAddr,
    ) -> Option<&'a Arc<Backend>> {
        let count = candidates.iter().count();
        if count == 0 {
            return None;
        }
        let turn = self.next.fetch_add(1, Ordering::Relaxed) % count;
        candidates
            .iter()
            .nth(turn)
            .or_else(|| candidates.iter().next())
    }
}

/// Picks the backend with the fewest active connections; ties go to the first one.
#[derive(Debug, Default)]
pub struct LeastConnections;

impl Strategy for LeastConnections {
    fn choose<'a>(
        &self,
        candidates: Candidates<'a>,
        _client: SocketAddr,
    ) -> Option<&'a Arc<Backend>> {
        candidates
            .iter()
            .min_by_key(|backend| backend.active_connections())
    }
}

/// Keeps every connection from the same client IP on the same backend.
///
/// Uses rendezvous (highest random weight) hashing: each backend gets a score
/// from `hash(client ip, backend addr)` and the highest score wins. When a
/// backend leaves the candidate list, only the clients it was winning move;
/// everyone else keeps their backend.
///
/// The client port is ignored, so reconnects from the same host stick.
#[derive(Debug, Default)]
pub struct IpHash;

impl IpHash {
    fn score(client: IpAddr, backend: SocketAddr) -> u64 {
        let mut hasher = DefaultHasher::new();
        client.hash(&mut hasher);
        backend.hash(&mut hasher);
        hasher.finish()
    }
}

impl Strategy for IpHash {
    fn choose<'a>(
        &self,
        candidates: Candidates<'a>,
        client: SocketAddr,
    ) -> Option<&'a Arc<Backend>> {
        candidates
            .iter()
            .max_by_key(|backend| Self::score(client.ip(), backend.addr()))
    }
}

/// Strategy names accepted on the command line and in the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Algorithm {
    RoundRobin,
    LeastConn,
    IpHash,
}

impl Algorithm {
    fn strategy(self) -> Box<dyn Strategy> {
        match self {
            Algorithm::RoundRobin => Box::new(RoundRobin::default()),
            Algorithm::LeastConn => Box::new(LeastConnections),
            Algorithm::IpHash => Box::new(IpHash),
        }
    }
}

/// The set of backends plus the strategy used to pick between them.
pub struct Pool {
    backends: Vec<Arc<Backend>>,
    strategy: Box<dyn Strategy>,
}

impl Pool {
    /// An empty pool is valid: every lease returns `None` until backends appear,
    /// which happens when a Kubernetes service has no ready pods.
    pub fn new(addrs: impl IntoIterator<Item = SocketAddr>, algorithm: Algorithm) -> Self {
        Self::rebuild(None, addrs, algorithm)
    }

    /// Builds a pool, reusing the `Backend` of every address that `previous` already had.
    ///
    /// On a config reload this keeps the health state and the active connection
    /// count of backends that stay, so least-conn and health checks carry on
    /// instead of starting from scratch.
    pub fn rebuild(
        previous: Option<&Pool>,
        addrs: impl IntoIterator<Item = SocketAddr>,
        algorithm: Algorithm,
    ) -> Self {
        // Indexed by address so a rebuild is linear in the pool size, which
        // matters for Services with many pods that change often.
        let existing: HashMap<SocketAddr, &Arc<Backend>> = previous
            .map(|pool| {
                pool.backends
                    .iter()
                    .map(|backend| (backend.addr, backend))
                    .collect()
            })
            .unwrap_or_default();
        let backends: Vec<_> = addrs
            .into_iter()
            .map(|addr| match existing.get(&addr) {
                Some(backend) => Arc::clone(backend),
                None => Arc::new(Backend::new(addr)),
            })
            .collect();

        Self {
            backends,
            strategy: algorithm.strategy(),
        }
    }

    /// Chooses a backend for a new connection from `client` and marks it as active.
    ///
    /// Backends in `exclude` are skipped, so a retry never hits the same backend twice.
    /// Only healthy backends are considered; if none is healthy, every remaining
    /// backend is tried instead (fail open), since health checks can be wrong.
    /// Returns `None` when every backend is excluded.
    pub fn lease(&self, client: SocketAddr, exclude: &[SocketAddr]) -> Option<Lease> {
        let remaining = Candidates {
            backends: &self.backends,
            exclude,
            healthy_only: false,
        };
        let healthy = Candidates {
            healthy_only: true,
            ..remaining
        };

        let any_healthy = healthy.iter().next().is_some();
        let candidates = if any_healthy { healthy } else { remaining };

        // A backend can turn unhealthy while the strategy is choosing; fall back
        // to any remaining backend rather than failing the connection.
        let backend = self
            .strategy
            .choose(candidates, client)
            .or_else(|| remaining.iter().next())?;
        Some(Lease::new(Arc::clone(backend)))
    }

    pub fn backends(&self) -> &[Arc<Backend>] {
        &self.backends
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 50000);

    fn lease(pool: &Pool) -> Lease {
        pool.lease(CLIENT, &[]).unwrap()
    }

    fn client(index: u32) -> SocketAddr {
        SocketAddr::from((std::net::Ipv4Addr::from(0x0a00_0000 + index), 40000))
    }

    /// Returns the backend port each of `clients` is sent to.
    fn assignments(pool: &Pool, clients: u32) -> Vec<u16> {
        (0..clients)
            .map(|i| pool.lease(client(i), &[]).unwrap().addr().port())
            .collect()
    }

    fn addrs(count: u16) -> Vec<SocketAddr> {
        (1..=count)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], port)))
            .collect()
    }

    #[test]
    fn rebuild_keeps_state_of_backends_that_stay() {
        let old = Pool::new(addrs(2), Algorithm::RoundRobin);
        let held = old.lease(CLIENT, &[old.backends()[0].addr()]).unwrap();
        old.backends()[0].set_healthy(false);

        let new_addrs = [
            old.backends()[1].addr(),
            SocketAddr::from(([127, 0, 0, 1], 9)),
        ];
        let new = Pool::rebuild(Some(&old), new_addrs, Algorithm::LeastConn);

        assert!(Arc::ptr_eq(&new.backends()[0], &old.backends()[1]));
        assert_eq!(new.backends()[0].active_connections(), 1);
        assert_eq!(new.backends()[1].active_connections(), 0);
        assert!(new.backends()[1].is_healthy());

        drop(held);
        assert_eq!(new.backends()[0].active_connections(), 0);
    }

    #[test]
    fn empty_pool_has_nothing_to_lease() {
        let pool = Pool::new([], Algorithm::RoundRobin);
        assert!(pool.lease(CLIENT, &[]).is_none());
    }

    #[test]
    fn round_robin_cycles_through_backends() {
        let pool = Pool::new(addrs(3), Algorithm::RoundRobin);

        let ports: Vec<u16> = (0..6).map(|_| lease(&pool).addr().port()).collect();

        assert_eq!(ports, [1, 2, 3, 1, 2, 3]);
    }

    #[test]
    fn least_connections_prefers_idle_backend() {
        let pool = Pool::new(addrs(3), Algorithm::LeastConn);

        let first = lease(&pool);
        let second = lease(&pool);
        assert_eq!(first.addr().port(), 1);
        assert_eq!(second.addr().port(), 2);

        drop(first);
        assert_eq!(lease(&pool).addr().port(), 1);
    }

    #[test]
    fn dropping_lease_releases_connection() {
        let pool = Pool::new(addrs(1), Algorithm::RoundRobin);
        let backend = &pool.backends()[0];

        let leased = lease(&pool);
        assert_eq!(backend.active_connections(), 1);

        drop(leased);
        assert_eq!(backend.active_connections(), 0);
    }

    #[test]
    fn skips_unhealthy_backends() {
        let pool = Pool::new(addrs(3), Algorithm::RoundRobin);
        pool.backends()[1].set_healthy(false);

        let ports: Vec<u16> = (0..4).map(|_| lease(&pool).addr().port()).collect();

        assert_eq!(ports, [1, 3, 1, 3]);
    }

    #[test]
    fn fails_open_when_no_backend_is_healthy() {
        let pool = Pool::new(addrs(2), Algorithm::RoundRobin);
        for backend in pool.backends() {
            backend.set_healthy(false);
        }

        assert!(pool.lease(CLIENT, &[]).is_some());
    }

    #[test]
    fn excludes_already_tried_backends() {
        let pool = Pool::new(addrs(2), Algorithm::RoundRobin);
        let first = pool.backends()[0].addr();
        let second = pool.backends()[1].addr();

        assert_eq!(pool.lease(CLIENT, &[first]).unwrap().addr(), second);
        assert!(pool.lease(CLIENT, &[first, second]).is_none());
    }

    #[test]
    fn ip_hash_keeps_a_client_on_one_backend() {
        let pool = Pool::new(addrs(4), Algorithm::IpHash);
        let host = client(7);

        let first = pool.lease(host, &[]).unwrap().addr();
        for port in [40001, 40002, 51234] {
            let reconnect = SocketAddr::new(host.ip(), port);
            assert_eq!(pool.lease(reconnect, &[]).unwrap().addr(), first);
        }
    }

    #[test]
    fn ip_hash_spreads_clients_across_backends() {
        let pool = Pool::new(addrs(4), Algorithm::IpHash);

        let ports = assignments(&pool, 4000);

        for backend in 1..=4 {
            let share = ports.iter().filter(|&&port| port == backend).count();
            assert!(
                (800..=1200).contains(&share),
                "backend {backend} got {share}"
            );
        }
    }

    #[test]
    fn ip_hash_only_moves_clients_of_a_removed_backend() {
        let pool = Pool::new(addrs(4), Algorithm::IpHash);
        let before = assignments(&pool, 4000);

        pool.backends()[2].set_healthy(false);
        let after = assignments(&pool, 4000);

        for (old, new) in before.iter().zip(&after) {
            if *old == 3 {
                assert_ne!(*new, 3);
            } else {
                assert_eq!(old, new);
            }
        }
    }
}
