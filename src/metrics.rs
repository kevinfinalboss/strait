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
    pub accepted: Family<ListenerLabels, Counter>,
    pub backend_connections: Family<BackendLabels, Counter>,
    pub connect_failures: Family<ConnectFailureLabels, Counter>,
    pub connection_errors: Family<ConnectionErrorLabels, Counter>,
    pub bytes: Family<TransferLabels, Counter>,
    pub connect_duration: HistogramFamily<BackendLabels>,
    pub connection_duration: HistogramFamily<BackendLabels>,
    pub reloads: Family<ReloadLabels, Counter>,
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
            accepted: Family::default(),
            backend_connections: Family::default(),
            connect_failures: Family::default(),
            connection_errors: Family::default(),
            bytes: Family::default(),
            connect_duration: Family::new_with_constructor(connect_buckets),
            connection_duration: Family::new_with_constructor(connection_buckets),
            reloads: Family::default(),
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
            "strait_config_reloads",
            "Config reloads by result",
            self.reloads.clone(),
        );
    }

    pub fn record_reload(&self, result: ReloadResult) {
        self.reloads.get_or_create(&ReloadLabels { result }).inc();
    }

    /// Handles for the per-listener series.
    pub fn listener(&self, listener: &str) -> ListenerMetrics {
        let error = |reason| {
            self.connection_errors
                .get_or_create(&ConnectionErrorLabels {
                    listener: listener.to_owned(),
                    reason,
                })
                .clone()
        };
        ListenerMetrics {
            accepted: self
                .accepted
                .get_or_create(&ListenerLabels {
                    listener: listener.to_owned(),
                })
                .clone(),
            no_backend: error(ConnectionError::NoBackend),
            relay_errors: error(ConnectionError::Relay),
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
#[derive(Debug, Clone)]
pub struct ListenerMetrics {
    pub accepted: Counter,
    pub no_backend: Counter,
    pub relay_errors: Counter,
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

/// Byte counters for one connection, looked up once so the relay only does atomic adds.
#[derive(Debug, Clone, Default)]
pub struct TransferCounters {
    pub sent: Counter,
    pub received: Counter,
}

impl TransferCounters {
    pub fn new(metrics: &Metrics, listener: &str, backend: &str) -> Self {
        let counter = |direction| {
            metrics
                .bytes
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
