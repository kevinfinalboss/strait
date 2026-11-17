//! Prometheus metrics and the HTTP endpoint that serves them.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwap;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{
    DescriptorEncoder, EncodeLabelSet, EncodeLabelValue, EncodeMetric, LabelValueEncoder,
};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::ConstGauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{info, warn};

use crate::Route;

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ListenerLabels {
    pub listener: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BackendLabels {
    pub listener: String,
    pub backend: String,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum Direction {
    /// Client to backend.
    Sent,
    /// Backend to client.
    Received,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TransferLabels {
    pub listener: String,
    pub backend: String,
    pub direction: Direction,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum ConnectFailure {
    Refused,
    Timeout,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ConnectFailureLabels {
    pub listener: String,
    pub backend: String,
    pub reason: ConnectFailure,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum ConnectionError {
    /// No backend accepted the connection, retries included.
    NoBackend,
    /// The relay stopped with an error, such as a reset or the idle timeout.
    Relay,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ConnectionErrorLabels {
    pub listener: String,
    pub reason: ConnectionError,
}

/// Why a UDP flow ended.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum FlowEnd {
    /// No packet in either direction for the idle timeout.
    Idle,
    /// Its backend left the listener. The flow is dropped rather than moved,
    /// since the backend may hold state for it.
    BackendGone,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct FlowEndLabels {
    pub listener: String,
    pub reason: FlowEnd,
}

/// Why a UDP packet from a client was dropped.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum UdpDrop {
    /// No backend to start a flow with: none in the pool, or (with
    /// `stun-username`) the named pod is not ready.
    NoBackend,
    /// `stun-username`: the first packet of a flow is not a STUN Binding
    /// Request with a USERNAME.
    NotStun,
    /// `stun-username`: the ufrag does not match the template.
    UnknownUfrag,
    /// The listener has `max_flows` flows already.
    TableFull,
    /// The backend has `max_flows_per_backend` flows already.
    BackendFull,
    /// The packet could not be handed to the kernel, usually a full socket
    /// buffer.
    SendFailed,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct UdpDropLabels {
    pub listener: String,
    pub reason: UdpDrop,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum ReloadResult {
    Success,
    Failure,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReloadLabels {
    pub result: ReloadResult,
}

/// Implements `EncodeLabelValue` with the given lowercase names, following the
/// Prometheus convention (the derive would use the variant names as written).
macro_rules! label_values {
    ($type:ty { $($variant:path => $name:literal),+ $(,)? }) => {
        impl EncodeLabelValue for $type {
            fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
                use std::fmt::Write;
                encoder.write_str(match self {
                    $($variant => $name),+
                })
            }
        }
    };
}

label_values!(Direction { Direction::Sent => "sent", Direction::Received => "received" });
label_values!(ConnectFailure { ConnectFailure::Refused => "refused", ConnectFailure::Timeout => "timeout" });
label_values!(ConnectionError {
    ConnectionError::NoBackend => "no_backend",
    ConnectionError::Relay => "relay",
});
label_values!(FlowEnd { FlowEnd::Idle => "idle", FlowEnd::BackendGone => "backend_gone" });
label_values!(UdpDrop {
    UdpDrop::NoBackend => "no_backend",
    UdpDrop::NotStun => "not_stun",
    UdpDrop::UnknownUfrag => "unknown_ufrag",
    UdpDrop::TableFull => "table_full",
    UdpDrop::BackendFull => "backend_full",
    UdpDrop::SendFailed => "send_failed",
});
label_values!(ReloadResult { ReloadResult::Success => "success", ReloadResult::Failure => "failure" });

type HistogramFamily<L> = Family<L, Histogram, fn() -> Histogram>;

/// Counters and histograms updated on the connection path.
///
/// Counter names are registered without the `_total` suffix; the encoder adds it.
#[derive(Debug, Clone)]
pub struct Metrics {
    /// Live [`BackendMetrics`] by label set, so every route that uses a backend
    /// shares one handle and its series can be removed when the last one goes.
    live: Arc<Mutex<HashMap<BackendLabels, Weak<BackendMetrics>>>>,
    /// Same as `live`, for listeners.
    live_listeners: Arc<Mutex<HashMap<String, Weak<ListenerMetrics>>>>,
    /// Same as `live`, for the UDP series of listeners and backends.
    live_udp: Arc<Mutex<HashMap<String, Weak<UdpListenerMetrics>>>>,
    live_udp_backends: Arc<Mutex<HashMap<BackendLabels, Weak<UdpBackendMetrics>>>>,
    pub accepted: Family<ListenerLabels, Counter>,
    pub backend_connections: Family<BackendLabels, Counter>,
    pub connect_failures: Family<ConnectFailureLabels, Counter>,
    pub connection_errors: Family<ConnectionErrorLabels, Counter>,
    pub bytes: Family<TransferLabels, Counter>,
    pub connect_duration: HistogramFamily<BackendLabels>,
    pub connection_duration: HistogramFamily<BackendLabels>,
    pub reloads: Family<ReloadLabels, Counter>,
    pub udp_packets: Family<TransferLabels, Counter>,
    pub udp_flows_ended: Family<FlowEndLabels, Counter>,
    pub udp_dropped: Family<UdpDropLabels, Counter>,
}

fn connect_buckets() -> Histogram {
    // 100µs to about 3.3s.
    Histogram::new(exponential_buckets(0.0001, 2.0, 16))
}

fn connection_buckets() -> Histogram {
    // 1ms to about 9 hours.
    Histogram::new(exponential_buckets(0.001, 4.0, 13))
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            live: Arc::default(),
            live_listeners: Arc::default(),
            live_udp: Arc::default(),
            live_udp_backends: Arc::default(),
            accepted: Family::default(),
            backend_connections: Family::default(),
            connect_failures: Family::default(),
            connection_errors: Family::default(),
            bytes: Family::default(),
            connect_duration: Family::new_with_constructor(connect_buckets),
            connection_duration: Family::new_with_constructor(connection_buckets),
            reloads: Family::default(),
            udp_packets: Family::default(),
            udp_flows_ended: Family::default(),
            udp_dropped: Family::default(),
        }
    }
}

impl Metrics {
    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "strait_connections_accepted",
            "Client connections accepted by a listener",
            self.accepted.clone(),
        );
        registry.register(
            "strait_backend_connections",
            "Connections established to a backend",
            self.backend_connections.clone(),
        );
        registry.register(
            "strait_backend_connect_failures",
            "Failed attempts to connect to a backend, retried ones included",
            self.connect_failures.clone(),
        );
        registry.register(
            "strait_connection_errors",
            "Client connections that ended with an error",
            self.connection_errors.clone(),
        );
        registry.register(
            "strait_bytes",
            "Bytes relayed; sent is client to backend, received is backend to client",
            self.bytes.clone(),
        );
        registry.register(
            "strait_backend_connect_duration_seconds",
            "Time to establish a TCP connection to a backend",
            self.connect_duration.clone(),
        );
        registry.register(
            "strait_connection_duration_seconds",
            "Lifetime of relayed connections",
            self.connection_duration.clone(),
        );
        registry.register(
            "strait_udp_packets",
            "UDP datagrams relayed; sent is client to backend, received is backend to client",
            self.udp_packets.clone(),
        );
        registry.register(
            "strait_udp_flows_ended",
            "UDP flows that ended, by reason",
            self.udp_flows_ended.clone(),
        );
        registry.register(
            "strait_udp_dropped",
            "UDP datagrams from clients that were dropped, by reason",
            self.udp_dropped.clone(),
        );
        registry.register(
            "strait_config_reloads",
            "Config reloads by result",
            self.reloads.clone(),
        );
    }

    pub fn record_reload(&self, result: ReloadResult) {
        self.reloads.get_or_create(&ReloadLabels { result }).inc();
    }

    /// Handles for the per-listener series.
    ///
    /// Like [`backend`](Self::backend), returns the existing handles while
    /// anything holds them, and the series leave the registry with the last one,
    /// so a listener removed or renamed by a reload stops being exported.
    pub fn listener(&self, listener: &str) -> Arc<ListenerMetrics> {
        let mut live = self.live_listeners.lock().expect("metrics lock poisoned");
        if let Some(existing) = live.get(listener).and_then(Weak::upgrade) {
            return existing;
        }

        let error = |reason| {
            self.connection_errors
                .get_or_create(&ConnectionErrorLabels {
                    listener: listener.to_owned(),
                    reason,
                })
                .clone()
        };
        let handles = Arc::new(ListenerMetrics {
            accepted: self
                .accepted
                .get_or_create(&ListenerLabels {
                    listener: listener.to_owned(),
                })
                .clone(),
            no_backend: error(ConnectionError::NoBackend),
            relay_errors: error(ConnectionError::Relay),
            listener: listener.to_owned(),
            metrics: self.clone(),
        });
        live.insert(listener.to_owned(), Arc::downgrade(&handles));
        handles
    }

    /// Removes the series of `listener`; see [`forget`](Self::forget).
    fn forget_listener(&self, listener: &str) {
        let mut live = self.live_listeners.lock().expect("metrics lock poisoned");
        if live
            .get(listener)
            .is_some_and(|weak| weak.strong_count() > 0)
        {
            return;
        }
        live.remove(listener);

        self.accepted.remove(&ListenerLabels {
            listener: listener.to_owned(),
        });
        for reason in [ConnectionError::NoBackend, ConnectionError::Relay] {
            self.connection_errors.remove(&ConnectionErrorLabels {
                listener: listener.to_owned(),
                reason,
            });
        }
    }

    /// Handles for the series of `backend` on `listener`.
    ///
    /// Returns the existing handles while anything still holds them. When the
    /// last holder drops them, the series leave the registry, so backends that
    /// come and go (pods in Kubernetes) do not pile up.
    pub fn backend(&self, listener: &str, backend: SocketAddr) -> Arc<BackendMetrics> {
        let labels = BackendLabels {
            listener: listener.to_owned(),
            backend: backend.to_string(),
        };
        let mut live = self.live.lock().expect("metrics lock poisoned");
        if let Some(existing) = live.get(&labels).and_then(Weak::upgrade) {
            return existing;
        }

        let failure = |reason| {
            self.connect_failures
                .get_or_create(&ConnectFailureLabels {
                    listener: labels.listener.clone(),
                    backend: labels.backend.clone(),
                    reason,
                })
                .clone()
        };
        let handles = Arc::new(BackendMetrics {
            connections: self.backend_connections.get_or_create(&labels).clone(),
            connect_duration: self.connect_duration.get_or_create(&labels).clone(),
            connection_duration: self.connection_duration.get_or_create(&labels).clone(),
            connect_refused: failure(ConnectFailure::Refused),
            connect_timeout: failure(ConnectFailure::Timeout),
            transfer: TransferCounters::new(self, &labels.listener, &labels.backend),
            labels: labels.clone(),
            metrics: self.clone(),
        });
        live.insert(labels, Arc::downgrade(&handles));
        handles
    }

    /// Handles for the UDP series of `listener`. Like
    /// [`listener`](Self::listener), shared while held and removed with the
    /// last holder.
    pub fn udp_listener(&self, listener: &str) -> Arc<UdpListenerMetrics> {
        let mut live = self.live_udp.lock().expect("metrics lock poisoned");
        if let Some(existing) = live.get(listener).and_then(Weak::upgrade) {
            return existing;
        }
        let ended = |reason| {
            self.udp_flows_ended
                .get_or_create(&FlowEndLabels {
                    listener: listener.to_owned(),
                    reason,
                })
                .clone()
        };
        let dropped = UDP_DROPS.map(|reason| {
            self.udp_dropped
                .get_or_create(&UdpDropLabels {
                    listener: listener.to_owned(),
                    reason,
                })
                .clone()
        });
        let handles = Arc::new(UdpListenerMetrics {
            ended_idle: ended(FlowEnd::Idle),
            ended_backend_gone: ended(FlowEnd::BackendGone),
            dropped,
            listener: listener.to_owned(),
            metrics: self.clone(),
        });
        live.insert(listener.to_owned(), Arc::downgrade(&handles));
        handles
    }

    fn forget_udp_listener(&self, listener: &str) {
        let mut live = self.live_udp.lock().expect("metrics lock poisoned");
        if live
            .get(listener)
            .is_some_and(|weak| weak.strong_count() > 0)
        {
            return;
        }
        live.remove(listener);
        for reason in [FlowEnd::Idle, FlowEnd::BackendGone] {
            self.udp_flows_ended.remove(&FlowEndLabels {
                listener: listener.to_owned(),
                reason,
            });
        }
        for reason in UDP_DROPS {
            self.udp_dropped.remove(&UdpDropLabels {
                listener: listener.to_owned(),
                reason,
            });
        }
    }

    /// Handles for the UDP series of `backend` on `listener`; see
    /// [`backend`](Self::backend).
    pub fn udp_backend(&self, listener: &str, backend: SocketAddr) -> Arc<UdpBackendMetrics> {
        let labels = BackendLabels {
            listener: listener.to_owned(),
            backend: backend.to_string(),
        };
        let mut live = self.live_udp_backends.lock().expect("metrics lock poisoned");
        if let Some(existing) = live.get(&labels).and_then(Weak::upgrade) {
            return existing;
        }
        let handles = Arc::new(UdpBackendMetrics {
            packets: TransferCounters::in_family(
                &self.udp_packets,
                &labels.listener,
                &labels.backend,
            ),
            labels: labels.clone(),
            metrics: self.clone(),
        });
        live.insert(labels, Arc::downgrade(&handles));
        handles
    }

    fn forget_udp_backend(&self, labels: &BackendLabels) {
        let mut live = self.live_udp_backends.lock().expect("metrics lock poisoned");
        if live.get(labels).is_some_and(|weak| weak.strong_count() > 0) {
            return;
        }
        live.remove(labels);
        for direction in [Direction::Sent, Direction::Received] {
            self.udp_packets.remove(&TransferLabels {
                listener: labels.listener.clone(),
                backend: labels.backend.clone(),
                direction,
            });
        }
    }

    /// Removes the series of `labels`, unless new handles for them were created
    /// after the old ones started dropping.
    fn forget(&self, labels: &BackendLabels) {
        let mut live = self.live.lock().expect("metrics lock poisoned");
        if live.get(labels).is_some_and(|weak| weak.strong_count() > 0) {
            return;
        }
        live.remove(labels);

        self.backend_connections.remove(labels);
        self.connect_duration.remove(labels);
        self.connection_duration.remove(labels);
        for reason in [ConnectFailure::Refused, ConnectFailure::Timeout] {
            self.connect_failures.remove(&ConnectFailureLabels {
                listener: labels.listener.clone(),
                backend: labels.backend.clone(),
                reason,
            });
        }
        for direction in [Direction::Sent, Direction::Received] {
            self.bytes.remove(&TransferLabels {
                listener: labels.listener.clone(),
                backend: labels.backend.clone(),
                direction,
            });
        }
    }
}

/// Series of one listener, looked up once so a connection only does atomic adds.
/// Created by [`Metrics::listener`]; the series are removed when the last
/// handle is dropped.
#[derive(Debug)]
pub struct ListenerMetrics {
    pub accepted: Counter,
    pub no_backend: Counter,
    pub relay_errors: Counter,
    listener: String,
    metrics: Metrics,
}

impl Drop for ListenerMetrics {
    fn drop(&mut self) {
        self.metrics.forget_listener(&self.listener);
    }
}

/// Series of one backend of one listener, looked up once so a connection only
/// does atomic adds. Created by [`Metrics::backend`]; the series are removed when
/// the last handle is dropped.
#[derive(Debug)]
pub struct BackendMetrics {
    pub connections: Counter,
    pub connect_duration: Histogram,
    pub connection_duration: Histogram,
    pub connect_refused: Counter,
    pub connect_timeout: Counter,
    pub transfer: TransferCounters,
    labels: BackendLabels,
    metrics: Metrics,
}

impl BackendMetrics {
    pub fn connect_failure(&self, reason: ConnectFailure) -> &Counter {
        match reason {
            ConnectFailure::Refused => &self.connect_refused,
            ConnectFailure::Timeout => &self.connect_timeout,
        }
    }
}

impl Drop for BackendMetrics {
    fn drop(&mut self) {
        self.metrics.forget(&self.labels);
    }
}

const UDP_DROPS: [UdpDrop; 6] = [
    UdpDrop::NoBackend,
    UdpDrop::NotStun,
    UdpDrop::UnknownUfrag,
    UdpDrop::TableFull,
    UdpDrop::BackendFull,
    UdpDrop::SendFailed,
];

/// UDP series of one listener. Created by [`Metrics::udp_listener`]; the
/// series are removed when the last handle is dropped.
#[derive(Debug)]
pub struct UdpListenerMetrics {
    pub ended_idle: Counter,
    pub ended_backend_gone: Counter,
    /// One counter per [`UdpDrop`], in the order of `UDP_DROPS`.
    dropped: [Counter; 6],
    listener: String,
    metrics: Metrics,
}

impl UdpListenerMetrics {
    pub fn dropped(&self, reason: UdpDrop) -> &Counter {
        let index = UDP_DROPS
            .iter()
            .position(|r| *r == reason)
            .expect("every reason is listed");
        &self.dropped[index]
    }

    pub fn ended(&self, reason: FlowEnd) -> &Counter {
        match reason {
            FlowEnd::Idle => &self.ended_idle,
            FlowEnd::BackendGone => &self.ended_backend_gone,
        }
    }
}

impl Drop for UdpListenerMetrics {
    fn drop(&mut self) {
        self.metrics.forget_udp_listener(&self.listener);
    }
}

/// UDP series of one backend of one listener. Created by
/// [`Metrics::udp_backend`]; removed when the last handle is dropped.
#[derive(Debug)]
pub struct UdpBackendMetrics {
    pub packets: TransferCounters,
    labels: BackendLabels,
    metrics: Metrics,
}

impl Drop for UdpBackendMetrics {
    fn drop(&mut self) {
        self.metrics.forget_udp_backend(&self.labels);
    }
}

/// Byte counters for one connection, looked up once so the relay only does atomic adds.
#[derive(Debug, Clone, Default)]
pub struct TransferCounters {
    pub sent: Counter,
    pub received: Counter,
}

impl TransferCounters {
    pub fn new(metrics: &Metrics, listener: &str, backend: &str) -> Self {
        Self::in_family(&metrics.bytes, listener, backend)
    }

    /// Counters of `family`, which has a series per direction.
    pub fn in_family(
        family: &Family<TransferLabels, Counter>,
        listener: &str,
        backend: &str,
    ) -> Self {
        let counter = |direction| {
            family
                .get_or_create(&TransferLabels {
                    listener: listener.to_owned(),
                    backend: backend.to_owned(),
                    direction,
                })
                .clone()
        };
        Self {
            sent: counter(Direction::Sent),
            received: counter(Direction::Received),
        }
    }
}

/// Reports per-backend state read live at scrape time, so backends removed by a
/// reload disappear instead of keeping their last value.
#[derive(Clone, Default)]
pub struct BackendState {
    routes: Arc<ArcSwap<Vec<Arc<ArcSwap<Route>>>>>,
}

impl std::fmt::Debug for BackendState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendState")
            .field("listeners", &self.routes.load().len())
            .finish()
    }
}

impl BackendState {
    /// Replaces the set of listeners to report on.
    pub fn set(&self, routes: Vec<Arc<ArcSwap<Route>>>) {
        self.routes.store(Arc::new(routes));
    }

    fn backends(&self) -> Vec<(BackendLabels, usize, bool)> {
        let mut rows = Vec::new();
        for route in self.routes.load().iter() {
            let route = route.load();
            for backend in route.pool.backends() {
                let labels = BackendLabels {
                    listener: route.name.to_string(),
                    backend: backend.addr().to_string(),
                };
                rows.push((labels, backend.active_connections(), backend.is_healthy()));
            }
        }
        rows
    }
}

impl Collector for BackendState {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let rows = self.backends();

        let mut active = encoder.encode_descriptor(
            "strait_backend_active_connections",
            "Connections currently relayed to a backend",
            None,
            MetricType::Gauge,
        )?;
        for (labels, connections, _) in &rows {
            ConstGauge::new(*connections as i64).encode(active.encode_family(labels)?)?;
        }

        let mut up = encoder.encode_descriptor(
            "strait_backend_up",
            "1 if the backend passes health checks, 0 otherwise",
            None,
            MetricType::Gauge,
        )?;
        for (labels, _, healthy) in &rows {
            ConstGauge::new(i64::from(*healthy)).encode(up.encode_family(labels)?)?;
        }
        Ok(())
    }
}

/// Serves `GET /metrics` in the Prometheus text format and `GET /healthz`.
pub async fn serve_metrics(listener: TcpListener, registry: Arc<Registry>) -> Result<()> {
    info!(listen = %listener.local_addr()?, "metrics endpoint is up");
    loop {
        let (socket, peer) = listener.accept().await?;
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            if let Err(err) = respond(socket, &registry).await {
                warn!(%peer, error = %err, "metrics request failed");
            }
        });
    }
}

async fn respond(mut socket: TcpStream, registry: &Registry) -> Result<()> {
    let head = timeout(Duration::from_secs(5), read_head(&mut socket)).await??;
    let path = head
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("GET "))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or("");

    let (status, content_type, body) = match path {
        "/metrics" => {
            let mut body = String::new();
            prometheus_client::encoding::prometheus_text::encode(&mut body, registry)?;
            ("200 OK", "text/plain; version=0.0.4; charset=utf-8", body)
        }
        "/healthz" => ("200 OK", "text/plain", "ok\n".to_owned()),
        _ => ("404 Not Found", "text/plain", "not found\n".to_owned()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    socket.write_all(response.as_bytes()).await?;
    let _ = socket.shutdown().await;
    Ok(())
}

/// Reads up to the end of the request head, which is all a GET needs.
async fn read_head(socket: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = socket.read(&mut chunk).await?;
        if n == 0 || buf.len() + n > 8192 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
