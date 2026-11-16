//! Integration tests for retries, health checks and idle timeouts.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use strait::{Algorithm, HealthCheck, Pool, ProxyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

/// Starts a backend on `listener` that sends `name` to every client and holds the connection open.
fn serve_named(listener: TcpListener, name: &'static str) {
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = socket.write_all(name.as_bytes()).await;
                let mut sink = Vec::new();
                let _ = socket.read_to_end(&mut sink).await;
            });
        }
    });
}

async fn spawn_named_backend(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    serve_named(listener, name);
    addr
}

/// Returns an address on which nothing is listening.
async fn dead_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

async fn spawn_strait(pool: Arc<Pool>, config: ProxyConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(strait::run(listener, pool, config));
    addr
}

async fn read_name(stream: &mut TcpStream) -> String {
    let mut name = [0u8; 1];
    stream.read_exact(&mut name).await.unwrap();
    String::from_utf8(name.to_vec()).unwrap()
}

/// Polls `condition` until it holds, failing the test after two seconds.
async fn eventually(condition: impl Fn() -> bool) {
    timeout(Duration::from_secs(2), async {
        while !condition() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("condition not met within 2s");
}

fn fast_health_checks() -> HealthCheck {
    HealthCheck {
        interval: Duration::from_millis(20),
        timeout: Duration::from_millis(100),
        ..HealthCheck::default()
    }
}

#[tokio::test]
async fn retries_on_another_backend_when_connect_fails() {
    let backends = [dead_addr().await, spawn_named_backend("b").await];
    let pool = Arc::new(Pool::new(backends, Algorithm::RoundRobin).unwrap());
    let proxy = spawn_strait(pool, ProxyConfig::default()).await;

    // Round-robin sends every other connection to the dead backend first.
    for _ in 0..4 {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        assert_eq!(read_name(&mut client).await, "b");
    }
}

#[tokio::test]
async fn health_checks_remove_and_restore_a_backend() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let pool = Arc::new(Pool::new([addr], Algorithm::RoundRobin).unwrap());
    let _checks = strait::spawn_health_checks(&pool, fast_health_checks());
    let backend = Arc::clone(&pool.backends()[0]);

    eventually(|| !backend.is_healthy()).await;

    serve_named(TcpListener::bind(addr).await.unwrap(), "a");

    eventually(|| backend.is_healthy()).await;
}

#[tokio::test]
async fn unhealthy_backend_gets_no_traffic() {
    let backends = [dead_addr().await, spawn_named_backend("b").await];
    let pool = Arc::new(Pool::new(backends, Algorithm::RoundRobin).unwrap());
    let _checks = strait::spawn_health_checks(&pool, fast_health_checks());

    let dead = Arc::clone(&pool.backends()[0]);
    eventually(|| !dead.is_healthy()).await;

    // With retries disabled, a connection to the dead backend would fail.
    let config = ProxyConfig {
        retries: 0,
        ..ProxyConfig::default()
    };
    let proxy = spawn_strait(pool, config).await;

    for _ in 0..4 {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        assert_eq!(read_name(&mut client).await, "b");
    }
}

#[tokio::test]
async fn idle_connections_are_closed() {
    let backend = spawn_named_backend("a").await;
    let pool = Arc::new(Pool::new([backend], Algorithm::RoundRobin).unwrap());
    let config = ProxyConfig {
        idle_timeout: Duration::from_millis(100),
        ..ProxyConfig::default()
    };
    let proxy = spawn_strait(pool, config).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    assert_eq!(read_name(&mut client).await, "a");

    // The backend sends nothing else, so the proxy should close the connection.
    let mut rest = Vec::new();
    timeout(Duration::from_secs(2), client.read_to_end(&mut rest))
        .await
        .expect("connection was not closed by the idle timeout")
        .unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn active_connections_are_not_closed() {
    let backend = spawn_named_backend("a").await;
    let pool = Arc::new(Pool::new([backend], Algorithm::RoundRobin).unwrap());
    let config = ProxyConfig {
        idle_timeout: Duration::from_millis(200),
        ..ProxyConfig::default()
    };
    let proxy = spawn_strait(pool, config).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    assert_eq!(read_name(&mut client).await, "a");

    // Keep sending for longer than the idle timeout; each write resets it.
    for _ in 0..6 {
        sleep(Duration::from_millis(80)).await;
        client.write_all(b"ping").await.unwrap();
    }

    // Still open: a read must time out on our side instead of returning EOF.
    let mut buf = [0u8; 1];
    let read = timeout(Duration::from_millis(50), client.read(&mut buf)).await;
    assert!(read.is_err(), "connection was closed while active");
}
