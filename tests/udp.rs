//! Integration tests of the UDP proxy: real sockets on random local ports.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use prometheus_client::registry::Registry;
use strait::{Algorithm, Metrics, Pool, ProxyConfig, Route, StunUsername, UdpSettings};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::task::TaskTracker;

/// A backend that answers every datagram with `<name>:<datagram>`.
async fn spawn_backend(name: &'static str) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0; 65_535];
        loop {
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let mut reply = format!("{name}:").into_bytes();
            reply.extend_from_slice(&buf[..len]);
            socket.send_to(&reply, peer).await.unwrap();
        }
    });
    addr
}

struct Proxy {
    addr: SocketAddr,
    route: Arc<ArcSwap<Route>>,
    metrics: Arc<Metrics>,
    stop: Option<watch::Sender<()>>,
    task: JoinHandle<anyhow::Result<()>>,
}

fn route(
    pool: Pool,
    idle: Duration,
    settings: UdpSettings,
    pods: &[(&str, SocketAddr)],
    metrics: &Arc<Metrics>,
) -> Route {
    let proxy = ProxyConfig {
        idle_timeout: idle,
        ..ProxyConfig::default()
    };
    let pods: BTreeMap<String, SocketAddr> =
        pods.iter().map(|(name, addr)| ((*name).to_owned(), *addr)).collect();
    Route::new(
        "rtc",
        Arc::new(pool),
        proxy,
        Arc::clone(metrics),
        TaskTracker::new(),
    )
    .with_udp(settings, pods)
}

async fn spawn_proxy(route_for: impl FnOnce(&Arc<Metrics>) -> Route) -> Proxy {
    let metrics = Arc::new(Metrics::default());
    let route = Arc::new(ArcSwap::from_pointee(route_for(&metrics)));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (stop, stopped) = watch::channel(());
    let task = tokio::spawn(strait::serve_udp(socket, Arc::clone(&route), stopped));
    Proxy {
        addr,
        route,
        metrics,
        stop: Some(stop),
        task,
    }
}

async fn client(proxy: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(proxy).await.unwrap();
    socket
}

/// Sends `message` and returns the answer, or `None` after 300ms.
async fn ask(socket: &UdpSocket, message: &[u8]) -> Option<String> {
    socket.send(message).await.unwrap();
    let mut buf = vec![0; 65_535];
    let len = timeout(Duration::from_millis(300), socket.recv(&mut buf))
        .await
        .ok()?
        .unwrap();
    Some(String::from_utf8_lossy(&buf[..len]).into_owned())
}

fn scrape(metrics: &Metrics) -> String {
    let mut registry = Registry::default();
    metrics.register(&mut registry);
    let mut text = String::new();
    prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
    text
}

/// The value of the series of `scrape` whose line starts with `series`.
fn value(text: &str, series: &str) -> u64 {
    text.lines()
        .find(|line| line.starts_with(series))
        .and_then(|line| line.rsplit(' ').next())
        .map_or(0, |value| value.parse().unwrap())
}

/// A STUN Binding Request with `username`, padded as the RFC wants.
fn binding_request(username: &str) -> Vec<u8> {
    let mut value = username.as_bytes().to_vec();
    let len = value.len() as u16;
    value.resize(value.len().div_ceil(4) * 4, 0);
    let mut packet = vec![0x00, 0x01];
    packet.extend_from_slice(&((4 + value.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
    packet.extend_from_slice(&[1; 12]);
    packet.extend_from_slice(&[0x00, 0x06]);
    packet.extend_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(&value);
    packet
}

const IDLE: Duration = Duration::from_secs(30);

#[tokio::test]
async fn relays_datagrams_both_ways_and_keeps_a_client_on_its_backend() {
    let (a, b) = (spawn_backend("a").await, spawn_backend("b").await);
    let proxy = spawn_proxy(|metrics| {
        route(
            Pool::new([a, b], Algorithm::RoundRobin),
            IDLE,
            UdpSettings::default(),
            &[],
            metrics,
        )
    })
    .await;

    let first = client(proxy.addr).await;
    let second = client(proxy.addr).await;
    let one = ask(&first, b"1").await.unwrap();
    let two = ask(&second, b"2").await.unwrap();
    // Round-robin spread the two flows; each flow then stays put.
    assert_ne!(one[..1], two[..1]);
    for _ in 0..5 {
        assert_eq!(ask(&first, b"1").await.unwrap(), one);
        assert_eq!(ask(&second, b"2").await.unwrap(), two);
    }

    let text = scrape(&proxy.metrics);
    assert_eq!(value(&text, "strait_connections_accepted_total{listener=\"rtc\"}"), 2);
    let sent = format!("strait_udp_packets_total{{listener=\"rtc\",backend=\"{a}\",direction=\"sent\"}}");
    assert_eq!(value(&text, &sent), 6);
    // Every flow holds a lease, so the active gauge counts flows.
    let pool = &proxy.route.load().pool;
    assert!(pool.backends().iter().all(|b| b.active_connections() == 1));
}

#[tokio::test]
async fn an_idle_flow_ends_and_releases_its_backend() {
    let a = spawn_backend("a").await;
    let proxy = spawn_proxy(|metrics| {
        route(
            Pool::new([a], Algorithm::RoundRobin),
            Duration::from_millis(200),
            UdpSettings::default(),
            &[],
            metrics,
        )
    })
    .await;

    let socket = client(proxy.addr).await;
    assert_eq!(ask(&socket, b"x").await.as_deref(), Some("a:x"));
    let backend = Arc::clone(&proxy.route.load().pool.backends()[0]);
    assert_eq!(backend.active_connections(), 1);

    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(backend.active_connections(), 0);
    let text = scrape(&proxy.metrics);
    assert_eq!(value(&text, "strait_udp_flows_ended_total{listener=\"rtc\",reason=\"idle\"}"), 1);

    // The next datagram starts a new flow.
    assert_eq!(ask(&socket, b"y").await.as_deref(), Some("a:y"));
}

#[tokio::test]
async fn routes_each_flow_to_the_pod_named_by_its_stun_username() {
    let (a, b) = (spawn_backend("a").await, spawn_backend("b").await);
    let stun: StunUsername =
        serde_yaml_ng::from_str("ufrag: \"nsp{id}\"\npod: \"nes-session-{id}\"").unwrap();
    let settings = UdpSettings {
        stun_username: Some(Arc::new(stun)),
        ..UdpSettings::default()
    };
    let proxy = spawn_proxy(|metrics| {
        route(
            Pool::new([a, b], Algorithm::StunUsername),
            IDLE,
            settings,
            &[("nes-session-aaaaa", a), ("nes-session-bbbbb", b)],
            metrics,
        )
    })
    .await;

    // A flow that does not start with STUN goes nowhere.
    let stray = client(proxy.addr).await;
    assert_eq!(ask(&stray, b"\x16\xfe\xfd hello").await, None);

    // Each player reaches its own pod, many times over and from any port.
    for _ in 0..3 {
        let to_b = client(proxy.addr).await;
        let reply = ask(&to_b, &binding_request("nspbbbbb:cl1e")).await.unwrap();
        assert!(reply.starts_with("b:"));
        // Later datagrams (DTLS, SRTP) follow the flow.
        assert_eq!(ask(&to_b, b"media").await.as_deref(), Some("b:media"));

        let to_a = client(proxy.addr).await;
        assert!(ask(&to_a, &binding_request("nspaaaaa:cl2e")).await.unwrap().starts_with("a:"));
    }

    // Unknown ufrags and pods that are not ready are dropped.
    let lost = client(proxy.addr).await;
    assert_eq!(ask(&lost, &binding_request("other:cl1e")).await, None);
    assert_eq!(ask(&lost, &binding_request("nspzzzzz:cl1e")).await, None);

    let text = scrape(&proxy.metrics);
    let dropped = |reason: &str| {
        value(&text, &format!("strait_udp_dropped_total{{listener=\"rtc\",reason=\"{reason}\"}}"))
    };
    assert_eq!(dropped("not_stun"), 1);
    assert_eq!(dropped("unknown_ufrag"), 1);
    assert_eq!(dropped("no_backend"), 1);
}

#[tokio::test]
async fn a_flow_whose_backend_leaves_is_dropped_not_moved() {
    let (a, b) = (spawn_backend("a").await, spawn_backend("b").await);
    let stun: StunUsername = serde_yaml_ng::from_str("ufrag: \"nsp{id}\"").unwrap();
    let settings = UdpSettings {
        stun_username: Some(Arc::new(stun)),
        ..UdpSettings::default()
    };
    let proxy = spawn_proxy(|metrics| {
        route(
            Pool::new([a, b], Algorithm::StunUsername),
            IDLE,
            settings.clone(),
            &[("one", a), ("two", b)],
            metrics,
        )
    })
    .await;

    let player = client(proxy.addr).await;
    assert!(ask(&player, &binding_request("nspone:x")).await.unwrap().starts_with("a:"));

    // Pod "one" goes away: the listener's pool is rebuilt without it.
    let current = proxy.route.load_full();
    let pool = Pool::rebuild(Some(&current.pool), [b], Algorithm::StunUsername);
    proxy
        .route
        .store(Arc::new(route(pool, IDLE, settings, &[("two", b)], &proxy.metrics)));

    // Its game state is gone with it: the flow ends instead of moving to "two",
    // and the media that follows has no STUN to route it.
    assert_eq!(ask(&player, b"media").await, None);
    let text = scrape(&proxy.metrics);
    assert_eq!(
        value(&text, "strait_udp_flows_ended_total{listener=\"rtc\",reason=\"backend_gone\"}"),
        1
    );
    assert_eq!(value(&text, "strait_udp_dropped_total{listener=\"rtc\",reason=\"not_stun\"}"), 1);
}

#[tokio::test]
async fn limits_flows_per_listener_and_per_backend() {
    let (a, b) = (spawn_backend("a").await, spawn_backend("b").await);
    let settings = UdpSettings {
        max_flows: 3,
        max_flows_per_backend: Some(1),
        ..UdpSettings::default()
    };
    let proxy = spawn_proxy(|metrics| {
        route(
            Pool::new([a, b], Algorithm::LeastConn),
            IDLE,
            settings,
            &[],
            metrics,
        )
    })
    .await;

    let mut clients = Vec::new();
    for _ in 0..2 {
        let socket = client(proxy.addr).await;
        assert!(ask(&socket, b"x").await.is_some());
        clients.push(socket);
    }
    // Both backends have their one flow.
    let third = client(proxy.addr).await;
    assert_eq!(ask(&third, b"x").await, None);
    let text = scrape(&proxy.metrics);
    assert_eq!(
        value(&text, "strait_udp_dropped_total{listener=\"rtc\",reason=\"backend_full\"}"),
        1
    );

    // With room per backend, the listener-wide limit is next.
    let settings = UdpSettings {
        max_flows: 2,
        ..UdpSettings::default()
    };
    let current = proxy.route.load_full();
    let pool = Pool::rebuild(Some(&current.pool), [a, b], Algorithm::LeastConn);
    proxy
        .route
        .store(Arc::new(route(pool, IDLE, settings, &[], &proxy.metrics)));
    assert_eq!(ask(&third, b"x").await, None);
    let text = scrape(&proxy.metrics);
    assert_eq!(
        value(&text, "strait_udp_dropped_total{listener=\"rtc\",reason=\"table_full\"}"),
        1
    );
}

#[tokio::test]
async fn a_closed_listener_relays_open_flows_until_they_end() {
    let a = spawn_backend("a").await;
    let mut proxy = spawn_proxy(|metrics| {
        route(
            Pool::new([a], Algorithm::RoundRobin),
            Duration::from_millis(400),
            UdpSettings::default(),
            &[],
            metrics,
        )
    })
    .await;

    let open = client(proxy.addr).await;
    assert_eq!(ask(&open, b"x").await.as_deref(), Some("a:x"));

    // The listener is removed (a reload) or strait shuts down.
    drop(proxy.stop.take());
    assert_eq!(ask(&open, b"y").await.as_deref(), Some("a:y"));
    let late = client(proxy.addr).await;
    assert_eq!(ask(&late, b"z").await, None);

    // Once the open flow goes idle, the listener's task is done.
    timeout(Duration::from_secs(2), &mut proxy.task)
        .await
        .expect("the listener finished draining")
        .unwrap()
        .unwrap();
}
