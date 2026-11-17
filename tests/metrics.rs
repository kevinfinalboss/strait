//! Integration tests for the Prometheus endpoint.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use prometheus_client::registry::Registry;
use strait::{Config, Metrics, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

async fn spawn_echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut reader, mut writer) = socket.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

async fn dead_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn config(backends: &[SocketAddr]) -> Config {
    let list: Vec<String> = backends.iter().map(ToString::to_string).collect();
    Config::parse(&format!(
        "listeners:\n  - name: api\n    listen: 127.0.0.1:0\n    backends: [{}]\n",
        list.join(", ")
    ))
    .unwrap()
}

/// A running server plus its metrics endpoint.
struct Harness {
    server: Server,
    proxy: SocketAddr,
    metrics: SocketAddr,
}

async fn start(backends: &[SocketAddr]) -> Harness {
    let metrics = Arc::new(Metrics::default());
    let server = Server::with_metrics(&config(backends), Arc::clone(&metrics))
        .await
        .unwrap();

    let mut registry = Registry::default();
    metrics.register(&mut registry);
    registry.register_collector(Box::new(server.backend_state()));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(strait::serve_metrics(listener, Arc::new(registry)));

    let proxy = server.local_addrs()[0].1;
    Harness {
        server,
        proxy,
        metrics: addr,
    }
}

/// Sends `GET path` and returns the status line and the body.
async fn get(addr: SocketAddr, path: &str) -> (String, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (head.lines().next().unwrap().to_owned(), body.to_owned())
}

/// Returns the value of the sample whose name and labels are exactly `series`.
fn value(body: &str, series: &str) -> Option<f64> {
    body.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' '))
        .map(|v| v.parse().unwrap())
}

async fn scrape(harness: &Harness) -> String {
    get(harness.metrics, "/metrics").await.1
}

/// Scrapes until `series` has `expected`, failing after two seconds.
async fn eventually(harness: &Harness, series: &str, expected: f64) {
    let result = timeout(Duration::from_secs(2), async {
        loop {
            if value(&scrape(harness).await, series) == Some(expected) {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(result.is_ok(), "{series} never reached {expected}");
}

#[tokio::test]
async fn counts_connections_bytes_and_live_state() {
    let backend = spawn_echo_backend().await;
    let harness = start(&[backend]).await;
    let labels = format!(r#"{{listener="api",backend="{backend}"}}"#);

    let mut client = TcpStream::connect(harness.proxy).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();

    let body = scrape(&harness).await;
    assert_eq!(
        value(
            &body,
            r#"strait_connections_accepted_total{listener="api"}"#
        ),
        Some(1.0)
    );
    assert_eq!(
        value(&body, &format!("strait_backend_connections_total{labels}")),
        Some(1.0)
    );
    assert_eq!(
        value(&body, &format!("strait_backend_active_connections{labels}")),
        Some(1.0)
    );
    assert_eq!(
        value(&body, &format!("strait_backend_up{labels}")),
        Some(1.0)
    );

    // Bytes are counted while the connection is still open.
    let sent =
        format!(r#"strait_bytes_total{{listener="api",backend="{backend}",direction="sent"}}"#);
    let received =
        format!(r#"strait_bytes_total{{listener="api",backend="{backend}",direction="received"}}"#);
    assert_eq!(value(&body, &sent), Some(4.0));
    assert_eq!(value(&body, &received), Some(4.0));

    drop(client);
    eventually(
        &harness,
        &format!("strait_backend_active_connections{labels}"),
        0.0,
    )
    .await;
    eventually(
        &harness,
        &format!("strait_connection_duration_seconds_count{labels}"),
        1.0,
    )
    .await;
}

#[tokio::test]
async fn counts_failed_connects_with_their_reason() {
    let dead = dead_addr().await;
    let alive = spawn_echo_backend().await;
    let harness = start(&[dead, alive]).await;

    // Round-robin sends the first connection to the dead backend, then retries.
    let _client = TcpStream::connect(harness.proxy).await.unwrap();

    eventually(
        &harness,
        &format!(r#"strait_backend_connect_failures_total{{listener="api",backend="{dead}",reason="refused"}}"#),
        1.0,
    )
    .await;
}

#[tokio::test]
async fn backends_removed_by_a_reload_leave_the_gauges() {
    let old = spawn_echo_backend().await;
    let new = spawn_echo_backend().await;
    let mut harness = start(&[old]).await;

    let up =
        |backend: SocketAddr| format!(r#"strait_backend_up{{listener="api",backend="{backend}"}}"#);
    assert_eq!(value(&scrape(&harness).await, &up(old)), Some(1.0));

    harness.server.reload(&config(&[new])).await.unwrap();

    let body = scrape(&harness).await;
    assert_eq!(value(&body, &up(old)), None);
    assert_eq!(value(&body, &up(new)), Some(1.0));
}

#[tokio::test]
async fn backends_removed_by_a_reload_leave_every_series_once_their_connections_close() {
    let old = spawn_echo_backend().await;
    let new = spawn_echo_backend().await;
    let mut harness = start(&[old]).await;
    let connections =
        format!(r#"strait_backend_connections_total{{listener="api",backend="{old}"}}"#);

    let mut client = TcpStream::connect(harness.proxy).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    client.read_exact(&mut reply).await.unwrap();
    eventually(&harness, &connections, 1.0).await;

    harness.server.reload(&config(&[new])).await.unwrap();

    // The connection is still open, so its series keep counting.
    assert_eq!(value(&scrape(&harness).await, &connections), Some(1.0));

    drop(client);
    let label = format!(r#"backend="{old}""#);
    let gone = timeout(Duration::from_secs(2), async {
        while scrape(&harness).await.contains(&label) {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(gone.is_ok(), "series of {old} are still exported");
}

#[tokio::test]
async fn serves_health_and_rejects_other_paths() {
    let harness = start(&[spawn_echo_backend().await]).await;

    let (status, body) = get(harness.metrics, "/healthz").await;
    assert_eq!(
        (status.as_str(), body.as_str()),
        ("HTTP/1.1 200 OK", "ok\n")
    );

    let (status, _) = get(harness.metrics, "/admin").await;
    assert_eq!(status, "HTTP/1.1 404 Not Found");
}
