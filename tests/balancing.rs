//! Integration tests for spreading connections across several backends.

use std::net::SocketAddr;
use std::sync::Arc;

use strait::{Algorithm, Pool, ProxyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

/// Starts a backend that sends `name` to every client and then holds the connection open.
async fn spawn_named_backend(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                socket.write_all(name.as_bytes()).await.unwrap();
                // Keep the connection open until the client closes it.
                let mut sink = Vec::new();
                let _ = socket.read_to_end(&mut sink).await;
            });
        }
    });

    addr
}

async fn spawn_strait(backends: Vec<SocketAddr>, algorithm: Algorithm) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pool = Pool::new(backends, algorithm);
    tokio::spawn(strait::run(
        listener,
        Arc::new(pool),
        ProxyConfig::default(),
    ));
    addr
}

/// Opens a connection through the proxy and returns it with the name of the backend it reached.
async fn connect(proxy: SocketAddr) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let mut name = [0u8; 1];
    stream.read_exact(&mut name).await.unwrap();
    (stream, String::from_utf8(name.to_vec()).unwrap())
}

#[tokio::test]
async fn round_robin_spreads_connections_evenly() {
    let backends = vec![
        spawn_named_backend("a").await,
        spawn_named_backend("b").await,
        spawn_named_backend("c").await,
    ];
    let proxy = spawn_strait(backends, Algorithm::RoundRobin).await;

    let mut seen = Vec::new();
    for _ in 0..6 {
        let (_stream, name) = connect(proxy).await;
        seen.push(name);
    }

    assert_eq!(seen, ["a", "b", "c", "a", "b", "c"]);
}

#[tokio::test]
async fn least_connections_skips_busy_backends() {
    let backends = vec![
        spawn_named_backend("a").await,
        spawn_named_backend("b").await,
        spawn_named_backend("c").await,
    ];
    let proxy = spawn_strait(backends, Algorithm::LeastConn).await;

    // Hold every connection open so each backend stays busy.
    let (_first, a) = connect(proxy).await;
    let (_second, b) = connect(proxy).await;
    let (_third, c) = connect(proxy).await;

    assert_eq!([a, b, c], ["a", "b", "c"]);
}

/// Connects through the proxy from `source` (any 127.x.y.z address works on Linux loopback).
async fn connect_from(source: [u8; 4], proxy: SocketAddr) -> String {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::from((source, 0))).unwrap();
    let mut stream = socket.connect(proxy).await.unwrap();
    let mut name = [0u8; 1];
    stream.read_exact(&mut name).await.unwrap();
    String::from_utf8(name.to_vec()).unwrap()
}

#[tokio::test]
async fn ip_hash_pins_each_client_to_one_backend() {
    let backends = vec![
        spawn_named_backend("a").await,
        spawn_named_backend("b").await,
        spawn_named_backend("c").await,
    ];
    let proxy = spawn_strait(backends, Algorithm::IpHash).await;

    let mut used = std::collections::HashSet::new();
    for host in 2..22u8 {
        let first = connect_from([127, 0, 0, host], proxy).await;
        for _ in 0..3 {
            assert_eq!(connect_from([127, 0, 0, host], proxy).await, first);
        }
        used.insert(first);
    }

    // 20 different clients should not all land on the same backend.
    assert!(used.len() > 1, "every client went to {used:?}");
}
