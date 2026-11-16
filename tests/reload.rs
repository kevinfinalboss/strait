//! Integration tests for multiple listeners and config reloads.

use std::net::SocketAddr;
use std::time::Duration;

use strait::{Config, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

/// Starts a backend that sends `name`, then echoes everything it receives.
async fn spawn_named_backend(name: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                socket.write_all(name.as_bytes()).await.unwrap();
                let (mut reader, mut writer) = socket.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });

    addr
}

/// Builds a config with one listener per `(name, listen, backend)`.
fn config(listeners: &[(&str, &str, SocketAddr)]) -> Config {
    let mut yaml = String::from("listeners:\n");
    for (name, listen, backend) in listeners {
        yaml.push_str(&format!(
            "  - name: {name}\n    listen: {listen}\n    backends: [{backend}]\n"
        ));
    }
    Config::parse(&yaml).unwrap()
}

fn addr_of(server: &Server, name: &str) -> SocketAddr {
    server
        .local_addrs()
        .into_iter()
        .find(|(listener, _)| listener == name)
        .map(|(_, addr)| addr)
        .unwrap_or_else(|| panic!("no listener named {name}"))
}

/// Connects to `addr` and returns the stream with the name of the backend behind it.
async fn connect(addr: SocketAddr) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut name = [0u8; 1];
    stream.read_exact(&mut name).await.unwrap();
    (stream, String::from_utf8(name.to_vec()).unwrap())
}

async fn assert_echo(stream: &mut TcpStream) {
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
}

#[tokio::test]
async fn each_listener_has_its_own_backends() {
    let a = spawn_named_backend("a").await;
    let b = spawn_named_backend("b").await;
    let server = Server::start(&config(&[
        ("api", "127.0.0.1:0", a),
        ("db", "127.0.0.2:0", b),
    ]))
    .await
    .unwrap();

    assert_eq!(connect(addr_of(&server, "api")).await.1, "a");
    assert_eq!(connect(addr_of(&server, "db")).await.1, "b");
}

#[tokio::test]
async fn reload_switches_backends_without_dropping_open_connections() {
    let a = spawn_named_backend("a").await;
    let b = spawn_named_backend("b").await;
    let mut server = Server::start(&config(&[("api", "127.0.0.1:0", a)]))
        .await
        .unwrap();
    let listen = addr_of(&server, "api");

    let (mut open, name) = connect(listen).await;
    assert_eq!(name, "a");

    let summary = server
        .reload(&config(&[("api", "127.0.0.1:0", b)]))
        .await
        .unwrap();
    assert_eq!(summary.updated, ["api"]);

    // Same port, new backend for new connections.
    assert_eq!(addr_of(&server, "api"), listen);
    assert_eq!(connect(listen).await.1, "b");

    // The connection opened before the reload still reaches backend a.
    assert_echo(&mut open).await;
}

#[tokio::test]
async fn reload_adds_and_removes_listeners() {
    let a = spawn_named_backend("a").await;
    let b = spawn_named_backend("b").await;
    let mut server = Server::start(&config(&[("old", "127.0.0.1:0", a)]))
        .await
        .unwrap();
    let old_addr = addr_of(&server, "old");
    let (mut open, _) = connect(old_addr).await;

    let summary = server
        .reload(&config(&[("new", "127.0.0.3:0", b)]))
        .await
        .unwrap();
    assert_eq!(summary.added, ["new"]);
    assert_eq!(summary.removed, ["old"]);

    assert_eq!(connect(addr_of(&server, "new")).await.1, "b");

    // The removed listener stops accepting, but its open connection keeps working.
    timeout(Duration::from_secs(2), async {
        while TcpStream::connect(old_addr).await.is_ok() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("removed listener still accepts connections");
    assert_echo(&mut open).await;
}

#[tokio::test]
async fn failed_reload_keeps_the_previous_config() {
    let a = spawn_named_backend("a").await;
    let b = spawn_named_backend("b").await;
    let mut server = Server::start(&config(&[("api", "127.0.0.1:0", a)]))
        .await
        .unwrap();
    let listen = addr_of(&server, "api");

    // Hold a port so the new listener cannot bind it.
    let taken = TcpListener::bind("127.0.0.4:0").await.unwrap();
    let taken_addr = taken.local_addr().unwrap().to_string();

    let result = server
        .reload(&config(&[
            ("api", "127.0.0.1:0", b),
            ("extra", &taken_addr, b),
        ]))
        .await;

    let message = format!("{:#}", result.unwrap_err());
    assert!(message.contains("could not bind"), "{message}");

    // Nothing changed: still one listener, still routing to backend a.
    assert_eq!(server.local_addrs().len(), 1);
    assert_eq!(connect(listen).await.1, "a");
}

#[tokio::test]
async fn reloading_the_same_config_changes_nothing() {
    let a = spawn_named_backend("a").await;
    let cfg = config(&[("api", "127.0.0.1:0", a)]);
    let mut server = Server::start(&cfg).await.unwrap();
    let listen = addr_of(&server, "api");

    let summary = server.reload(&cfg).await.unwrap();

    assert_eq!(summary.unchanged, ["api"]);
    assert!(summary.updated.is_empty() && summary.added.is_empty() && summary.removed.is_empty());
    assert_eq!(addr_of(&server, "api"), listen);
}
