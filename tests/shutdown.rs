//! Integration tests for graceful shutdown.

use std::net::SocketAddr;
use std::time::Duration;

use strait::{Config, Server};
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

async fn start() -> (Server, SocketAddr) {
    let backend = spawn_echo_backend().await;
    let config = Config::parse(&format!(
        "listeners:\n  - name: api\n    listen: 127.0.0.1:0\n    backends: [{backend}]\n"
    ))
    .unwrap();
    let server = Server::start(&config).await.unwrap();
    let proxy = server.local_addrs()[0].1;
    (server, proxy)
}

async fn echo(stream: &mut TcpStream, message: &[u8]) {
    stream.write_all(message).await.unwrap();
    let mut reply = vec![0u8; message.len()];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, message);
}

#[tokio::test]
async fn stops_accepting_and_waits_for_open_connections() {
    let (server, proxy) = start().await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    echo(&mut client, b"before").await;

    let shutdown = tokio::spawn(server.shutdown(Duration::from_secs(10)));

    let refused = timeout(Duration::from_secs(2), async {
        while TcpStream::connect(proxy).await.is_ok() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(refused.is_ok(), "the listener still accepts connections");

    // The open connection keeps working while the server drains.
    echo(&mut client, b"during").await;
    assert!(!shutdown.is_finished());

    drop(client);
    let cut = timeout(Duration::from_secs(2), shutdown)
        .await
        .expect("shutdown did not finish after the last connection closed")
        .unwrap();
    assert_eq!(cut, 0);
}

#[tokio::test]
async fn gives_up_on_open_connections_after_the_grace_period() {
    let (server, proxy) = start().await;
    let mut client = TcpStream::connect(proxy).await.unwrap();
    echo(&mut client, b"hello").await;

    let cut = timeout(
        Duration::from_secs(2),
        server.shutdown(Duration::from_millis(100)),
    )
    .await
    .expect("shutdown ignored its grace period");
    assert_eq!(cut, 1);
}
