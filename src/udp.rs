//! UDP proxy: relays datagrams between clients and backends.
//!
//! Every client address (IP and port) is a flow. Its first datagram picks a
//! backend; strait then opens a socket of its own towards that backend, so
//! replies come back to that socket and can be sent to the right client from
//! the listener's address. A flow ends after `idle_timeout` without a datagram
//! in either direction, or when its backend leaves the listener: it is dropped
//! rather than moved, since the backend may hold state for it.
//!
//! Like TCP connections, flows keep the backend they started with across
//! reloads, and a removed listener (or a shutdown) stops taking new flows but
//! keeps relaying the open ones until they end.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use arc_swap::ArcSwap;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{Instrument, debug, info, info_span, warn};

use crate::Route;
use crate::balancer::Lease;
use crate::metrics::{BackendMetrics, FlowEnd, UdpBackendMetrics, UdpDrop, UdpListenerMetrics};
use crate::stun::{StunUsername, Unroutable};

/// Default `idle_timeout` of UDP listeners. ICE keeps a WebRTC flow busy with
/// consent checks every few seconds, and DNS-like traffic needs far less.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default `max_flows`.
pub const DEFAULT_MAX_FLOWS: usize = 65_536;

/// Largest UDP payload.
const MAX_DATAGRAM: usize = 65_535;

/// How often an idle flow checks whether its backend left.
const CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// Settings of a UDP proxy listener; see the fields of the same name in
/// [`ListenerConfig`](crate::ListenerConfig).
#[derive(Debug, Clone, PartialEq)]
pub struct UdpSettings {
    pub max_flows: usize,
    pub max_flows_per_backend: Option<usize>,
    pub stun_username: Option<Arc<StunUsername>>,
}

impl Default for UdpSettings {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            max_flows_per_backend: None,
            stun_username: None,
        }
    }
}

/// The UDP part of a [`Route`].
pub(crate) struct UdpRoute {
    pub settings: UdpSettings,
    /// Pod names of the backends, for `stun-username`.
    pub pods: BTreeMap<String, SocketAddr>,
    pub metrics: Arc<UdpListenerMetrics>,
    /// UDP metric handles of every backend in the pool.
    pub backends: HashMap<SocketAddr, Arc<UdpBackendMetrics>>,
}

/// One client's flow, owned by the listener's task.
struct Flow {
    id: u64,
    upstream: Arc<UdpSocket>,
    shared: Arc<FlowShared>,
    /// Relays the backend's datagrams to the client; aborted with the flow.
    replies: JoinHandle<()>,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.replies.abort();
    }
}

/// What both directions of a flow use.
struct FlowShared {
    /// Counts the flow on its backend, for least-conn, the active connections
    /// gauge and `max_flows_per_backend`.
    lease: Lease,
    started: Instant,
    /// Milliseconds from `started` to the last datagram in either direction.
    last_seen: AtomicU64,
    backend: Arc<BackendMetrics>,
    packets: Arc<UdpBackendMetrics>,
    listener: Arc<UdpListenerMetrics>,
}

impl FlowShared {
    fn touch(&self) {
        let now = self.started.elapsed().as_millis() as u64;
        self.last_seen.store(now, Ordering::Relaxed);
    }

    fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_seen.load(Ordering::Relaxed));
        self.started.elapsed().saturating_sub(last)
    }
}

/// A reply task telling the listener that its flow is over.
struct Ended {
    client: SocketAddr,
    id: u64,
    reason: FlowEnd,
}

/// Relays datagrams on `socket` to the backends of `route` until `stop`
/// fires (or its sender is dropped), then until the open flows have ended.
pub async fn serve(
    socket: UdpSocket,
    route: Arc<ArcSwap<Route>>,
    mut stop: watch::Receiver<()>,
) -> Result<()> {
    let socket = Arc::new(socket);
    info!(
        listen = %socket.local_addr()?,
        backends = route.load().pool.backends().len(),
        "listening (udp)"
    );

    let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<Ended>();
    let mut flows: HashMap<SocketAddr, Flow> = HashMap::new();
    let mut next_id: u64 = 0;
    let mut draining = false;
    let mut buf = vec![0u8; MAX_DATAGRAM];

    loop {
        if draining && flows.is_empty() {
            return Ok(());
        }
        tokio::select! {
            // Fires on a send or when the sender is dropped; either way, drain.
            _ = stop.changed(), if !draining => {
                draining = true;
                if !flows.is_empty() {
                    info!(flows = flows.len(), "listener closed; relaying open flows until they end");
                }
            }
            Some(ended) = ended_rx.recv() => {
                // A newer flow from the same client may have taken the slot.
                if flows.get(&ended.client).is_some_and(|flow| flow.id == ended.id) {
                    let flow = flows.remove(&ended.client).expect("checked above");
                    end(flow, ended.reason);
                }
            }
            received = socket.recv_from(&mut buf) => {
                let (len, client) = match received {
                    Ok(received) => received,
                    Err(err) => {
                        debug!(error = %err, "udp receive failed");
                        continue;
                    }
                };
                let packet = &buf[..len];

                if let Some(flow) = flows.get(&client) {
                    if !flow.shared.lease.backend().is_retired() {
                        forward(flow, packet);
                        continue;
                    }
                    // The backend left and this flow has not noticed yet.
                    let flow = flows.remove(&client).expect("found above");
                    end(flow, FlowEnd::BackendGone);
                }
                if draining {
                    continue;
                }

                let route = route.load_full();
                match open(&route, &socket, client, packet, flows.len(), &ended_tx, next_id).await {
                    Ok(flow) => {
                        next_id += 1;
                        forward(&flow, packet);
                        flows.insert(client, flow);
                    }
                    Err(reason) => {
                        debug!(%client, ?reason, "udp datagram dropped");
                        if let Some(udp) = &route.udp {
                            udp.metrics.dropped(reason).inc();
                        }
                    }
                }
            }
        }
    }
}

/// Sends a client's datagram to the flow's backend.
fn forward(flow: &Flow, packet: &[u8]) {
    let shared = &flow.shared;
    // Never waits: a full socket buffer drops the datagram, as the network
    // would, instead of holding up every other flow of the listener.
    match flow.upstream.try_send(packet) {
        Ok(_) => {
            shared.touch();
            shared.packets.packets.sent.inc();
            shared.backend.transfer.sent.inc_by(packet.len() as u64);
        }
        Err(err) => {
            debug!(backend = %shared.lease.addr(), error = %err, "udp send failed");
            shared.listener.dropped(UdpDrop::SendFailed).inc();
        }
    }
}

fn end(flow: Flow, reason: FlowEnd) {
    let shared = &flow.shared;
    shared.listener.ended(reason).inc();
    shared
        .backend
        .connection_duration
        .observe(shared.started.elapsed().as_secs_f64());
    debug!(backend = %shared.lease.addr(), ?reason, "udp flow ended");
}

/// Starts a flow for `client`, whose first datagram is `packet`.
async fn open(
    route: &Route,
    socket: &Arc<UdpSocket>,
    client: SocketAddr,
    packet: &[u8],
    open_flows: usize,
    ended: &mpsc::UnboundedSender<Ended>,
    id: u64,
) -> Result<Flow, UdpDrop> {
    let udp = route
        .udp
        .as_ref()
        .expect("UDP listeners always get a UDP route");
    if open_flows >= udp.settings.max_flows {
        return Err(UdpDrop::TableFull);
    }

    let lease = match &udp.settings.stun_username {
        Some(stun) => {
            let pod = stun.pod(packet).map_err(|reason| match reason {
                Unroutable::NotStun => UdpDrop::NotStun,
                Unroutable::UnknownUfrag => UdpDrop::UnknownUfrag,
            })?;
            udp.pods
                .get(&pod)
                .and_then(|addr| route.pool.lease_addr(*addr))
        }
        None => route.pool.lease(client, &[]),
    }
    .ok_or(UdpDrop::NoBackend)?;
    // The lease already counts this flow.
    if udp
        .settings
        .max_flows_per_backend
        .is_some_and(|max| lease.backend().active_connections() > max)
    {
        return Err(UdpDrop::BackendFull);
    }

    let backend = lease.addr();
    let upstream = match connect(backend).await {
        Ok(upstream) => Arc::new(upstream),
        Err(err) => {
            warn!(%backend, error = %err, "could not open a udp socket to the backend");
            return Err(UdpDrop::NoBackend);
        }
    };

    route.listener_metrics.accepted.inc();
    let backend_metrics = route.backend_metrics(backend);
    backend_metrics.connections.inc();
    let shared = Arc::new(FlowShared {
        lease,
        started: Instant::now(),
        last_seen: AtomicU64::new(0),
        backend: backend_metrics,
        packets: udp
            .backends
            .get(&backend)
            .cloned()
            .unwrap_or_else(|| route.metrics.udp_backend(&route.name, backend)),
        listener: Arc::clone(&udp.metrics),
    });
    debug!(%client, %backend, "udp flow opened");

    let span = info_span!("flow", listener = %route.name, %client, %backend);
    let replies = tokio::spawn(
        relay_replies(
            Arc::clone(socket),
            Arc::clone(&upstream),
            client,
            Arc::clone(&shared),
            route.proxy.idle_timeout,
            ended.clone(),
            id,
        )
        .instrument(span),
    );
    Ok(Flow {
        id,
        upstream,
        shared,
        replies,
    })
}

/// A socket of strait's own, connected to `backend` so that it only receives
/// that backend's datagrams.
async fn connect(backend: SocketAddr) -> io::Result<UdpSocket> {
    let any = match backend.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let socket = UdpSocket::bind(SocketAddr::new(any, 0)).await?;
    socket.connect(backend).await?;
    // `try_send` only uses readiness the runtime has seen; until it has seen
    // this socket writable, every `try_send` would fail with WouldBlock.
    socket.writable().await?;
    Ok(socket)
}

/// Sends the backend's datagrams to `client` from the listener's socket, and
/// watches the flow: reports it over when it has been idle for `idle` or its
/// backend left.
async fn relay_replies(
    listener: Arc<UdpSocket>,
    upstream: Arc<UdpSocket>,
    client: SocketAddr,
    shared: Arc<FlowShared>,
    idle: Duration,
    ended: mpsc::UnboundedSender<Ended>,
    id: u64,
) {
    // Capacity only: pages are touched as datagrams fill them, so a flow costs
    // memory for the largest datagram it has seen, not for MAX_DATAGRAM.
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_DATAGRAM);
    let reason = loop {
        let idle_for = shared.idle_for();
        if idle_for >= idle {
            break FlowEnd::Idle;
        }
        if shared.lease.backend().is_retired() {
            break FlowEnd::BackendGone;
        }
        tokio::select! {
            received = upstream.recv_buf(&mut buf) => match received {
                Ok(len) => {
                    shared.touch();
                    shared.packets.packets.received.inc();
                    shared.backend.transfer.received.inc_by(len as u64);
                    if let Err(err) = listener.send_to(&buf, client).await {
                        debug!(error = %err, "udp send to client failed");
                    }
                    buf.clear();
                }
                // Typically an ICMP port unreachable from the backend, reported
                // on the next call. The flow stays until it goes idle.
                Err(err) => debug!(error = %err, "udp receive from backend failed"),
            },
            _ = sleep((idle - idle_for).min(CHECK_INTERVAL)) => {}
        }
    };
    // The listener may already be gone, along with the flow.
    let _ = ended.send(Ended { client, id, reason });
}
