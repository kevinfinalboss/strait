//! Integration tests: run strait in front of an echo backend on random ports.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Starts a backend that writes back everything it receives.
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

/// Starts strait in front of `backend` and returns the address it listens on.
async fn spawn_strait(backend: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(strait::run(listener, backend));
    addr
}

#[tokio::test]
async fn relays_bytes_both_ways() {
    let backend = spawn_echo_backend().await;
    let proxy = spawn_strait(backend).await;

    let mut client = TcpStream::connect(proxy).await.unwrap();
    client.write_all(b"hello, strait").await.unwrap();
    client.shutdown().await.unwrap();

    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();

    assert_eq!(response, b"hello, strait");
}

#[tokio::test]
async fn handles_concurrent_clients() {
    let backend = spawn_echo_backend().await;
    let proxy = spawn_strait(backend).await;

    let mut clients = Vec::new();
    for i in 0..50 {
        clients.push(tokio::spawn(async move {
            let message = format!("client {i}");
            let mut client = TcpStream::connect(proxy).await.unwrap();
            client.write_all(message.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();

            let mut response = String::new();
            client.read_to_string(&mut response).await.unwrap();
            assert_eq!(response, message);
        }));
    }

    for client in clients {
        client.await.unwrap();
    }
}

#[tokio::test]
async fn survives_unreachable_backend() {
    // Bind and immediately drop a listener to get a port nobody listens on.
    let dead_backend = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let proxy = spawn_strait(dead_backend).await;

    // Each connection fails at the backend, but the proxy keeps accepting new ones.
    for _ in 0..3 {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf).await;
        assert!(buf.is_empty());
    }
}
