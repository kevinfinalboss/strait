//! Integration tests: run strait in front of an echo backend on random ports.

use std::net::SocketAddr;
use std::sync::Arc;

use strait::{Algorithm, Pool, ProxyConfig};
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
    let pool = Pool::new([backend], Algorithm::RoundRobin);
    tokio::spawn(strait::run(
        listener,
        Arc::new(pool),
        ProxyConfig::default(),
    ));
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

/// Starts a keep-alive backend that answers every request with its headers and
/// body in two separate writes, like many real HTTP servers do.
async fn spawn_split_write_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();
            tokio::spawn(async move {
                let mut request = [0u8; 1];
                while socket.read_exact(&mut request).await.is_ok() {
                    socket.write_all(b"head").await.unwrap();
                    // A short gap so strait reads the two writes separately.
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    socket.write_all(b"body").await.unwrap();
                }
            });
        }
    });

    addr
}

#[tokio::test]
async fn does_not_delay_responses_split_over_several_writes() {
    let backend = spawn_split_write_backend().await;
    let proxy = spawn_strait(backend).await;
    let mut client = TcpStream::connect(proxy).await.unwrap();

    // Without TCP_NODELAY, Nagle holds back "body" until "head" is acknowledged,
    // and the client's delayed ACK turns that into stalls of about 40ms.
    let mut stalled = 0;
    for _ in 0..200 {
        let started = std::time::Instant::now();
        client.write_all(b"?").await.unwrap();
        let mut response = [0u8; 8];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"headbody");
        if started.elapsed() > std::time::Duration::from_millis(30) {
            stalled += 1;
        }
    }

    assert_eq!(
        stalled, 0,
        "{stalled} of 200 responses stalled for over 30ms"
    );
}
