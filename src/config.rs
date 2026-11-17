//! YAML configuration: one or more listeners, each with its own backends and settings.

use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::ProxyConfig;
use crate::ProxyProtocol;
use crate::stun::StunUsername;
use crate::udp::{DEFAULT_MAX_FLOWS, DEFAULT_UDP_IDLE_TIMEOUT, UdpSettings};
use crate::balancer::Algorithm;
use crate::health::HealthCheck;

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listeners: Vec<ListenerConfig>,
    /// Prometheus endpoint; off when absent.
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    /// XDP data plane, used by listeners with `dataplane: xdp`.
    #[serde(default)]
    pub xdp: Option<XdpConfig>,
}

/// Where the XDP program runs and where it sends encapsulated packets.
/// Read once, when the first XDP listener starts; changing it needs a restart.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdpConfig {
    /// Interface that receives the VIP traffic.
    pub interface: String,
    /// Outer source address for IPv4 backends. Defaults to the interface's
    /// first IPv4 address.
    #[serde(default)]
    pub source: Option<Ipv4Addr>,
    /// Outer source address for IPv6 backends. Defaults to the interface's
    /// first global IPv6 address; needed only by IPv6 listeners.
    #[serde(default)]
    pub source_v6: Option<Ipv6Addr>,
    /// MAC address of the next hop that routes encapsulated packets to
    /// backends. Defaults to the MAC of the interface's IPv4 default gateway.
    #[serde(default)]
    pub gateway_mac: Option<MacAddr>,
    /// Largest IP packet the path from this interface to the backends
    /// carries. Packets that would not fit once encapsulated are answered with
    /// ICMP "too big". Defaults to the interface's MTU.
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub mode: XdpMode,
}

/// Smallest `xdp.mtu`: every IPv4 host takes 576-byte packets (RFC 791), so a
/// lower value would ask clients for packets they may not be able to send.
pub const MIN_XDP_MTU: u16 = 576;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XdpMode {
    /// Native if the driver supports it, generic otherwise.
    #[default]
    Auto,
    /// In the driver, before the kernel allocates anything. Fastest.
    Native,
    /// In the kernel network stack. Works on any interface, much slower.
    Generic,
}

/// A MAC address written as `aa:bb:cc:dd:ee:ff`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

impl std::str::FromStr for MacAddr {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let mut bytes = [0u8; 6];
        let mut parts = text.split(':');
        for byte in &mut bytes {
            let part = parts.next().filter(|p| p.len() == 2);
            *byte = part
                .and_then(|p| u8::from_str_radix(p, 16).ok())
                .with_context(|| format!("invalid MAC address {text:?}"))?;
        }
        if parts.next().is_some() {
            bail!("invalid MAC address {text:?}");
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Transport protocol of a listener.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    #[default]
    Tcp,
    /// Only with `dataplane: xdp`.
    Udp,
}

/// How a listener moves traffic to its backends.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Dataplane {
    /// strait accepts each TCP connection and relays it to a backend.
    #[default]
    Proxy,
    /// An XDP program forwards packets to backends with IP-in-IP, and backends
    /// answer clients directly (direct server return).
    Xdp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Address that serves `/metrics` and `/healthz`.
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    /// Identifies the listener in logs and across reloads.
    pub name: String,
    pub listen: SocketAddr,
    #[serde(default)]
    pub dataplane: Dataplane,
    #[serde(default)]
    pub protocol: Protocol,
    /// Fixed backend addresses. Exactly one of `backends` and `kubernetes` is set.
    #[serde(default)]
    pub backends: Vec<SocketAddr>,
    /// Discover backends from the EndpointSlices of a Kubernetes Service.
    #[serde(default)]
    pub kubernetes: Option<KubernetesBackends>,
    #[serde(default = "default_strategy")]
    pub strategy: Algorithm,
    #[serde(default = "default_connect_timeout", with = "humantime_serde")]
    pub connect_timeout: Duration,
    /// Close a connection, or end a UDP flow, after this long without traffic.
    /// Defaults to 5m for TCP and 30s for UDP; see [`Self::idle_timeout`].
    #[serde(default, with = "humantime_serde")]
    pub idle_timeout: Option<Duration>,
    #[serde(default = "default_retries")]
    pub retries: usize,
    #[serde(default)]
    pub health_check: HealthCheckConfig,
    /// PROXY protocol header sent to backends, so they see the client's
    /// address. Proxy listeners only.
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProtocol>,
    /// UDP proxy: most flows open at once; a new client beyond it is dropped.
    #[serde(default)]
    pub max_flows: Option<usize>,
    /// UDP proxy: most flows to one backend; unlimited by default.
    #[serde(default)]
    pub max_flows_per_backend: Option<usize>,
    /// With `strategy: stun-username`, how a flow's first packet names its pod.
    #[serde(default)]
    pub stun_username: Option<StunUsername>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesBackends {
    /// Name of the Service whose ready pods become backends.
    pub service: String,
    /// Namespace of the Service; defaults to the namespace strait runs in.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Port name from the Service, or the container port number.
    pub port: ServicePort,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ServicePort {
    Number(u16),
    Name(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HealthCheckConfig {
    /// Off means every backend is always considered healthy.
    pub enabled: bool,
    /// TCP port to probe instead of the backend's own, for example a health
    /// endpoint next to a UDP service.
    pub port: Option<u16>,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    pub unhealthy_threshold: u32,
    pub healthy_threshold: u32,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        let defaults = HealthCheck::default();
        Self {
            enabled: defaults.enabled,
            port: defaults.port,
            interval: defaults.interval,
            timeout: defaults.timeout,
            unhealthy_threshold: defaults.unhealthy_threshold,
            healthy_threshold: defaults.healthy_threshold,
        }
    }
}

fn default_strategy() -> Algorithm {
    Algorithm::RoundRobin
}

fn default_connect_timeout() -> Duration {
    ProxyConfig::default().connect_timeout
}

fn default_retries() -> usize {
    ProxyConfig::default().retries
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid config {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = serde_yaml_ng::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks rules that the YAML structure alone cannot express.
    pub fn validate(&self) -> Result<()> {
        if self.listeners.is_empty() {
            bail!("at least one listener is required");
        }

        let mut names = HashSet::new();
        let mut addrs = HashSet::new();
        if let Some(metrics) = self.metrics {
            addrs.insert((metrics.listen, Protocol::Tcp));
        }
        for listener in &self.listeners {
            let name = &listener.name;
            if name.is_empty() {
                bail!("listener name cannot be empty");
            }
            if !names.insert(name) {
                bail!("listener name {name:?} is used more than once");
            }
            // XDP listeners on the same address can differ by protocol (DNS over
            // TCP and UDP, say); the metrics endpoint and proxies are TCP.
            if !addrs.insert((listener.listen, listener.protocol)) {
                bail!(
                    "listener {name:?}: address {} is used by another listener or the metrics endpoint",
                    listener.listen
                );
            }
            listener
                .validate()
                .with_context(|| format!("listener {name:?}"))?;
            if listener.dataplane == Dataplane::Xdp {
                if !cfg!(feature = "xdp") {
                    bail!(
                        "listener {name:?} uses dataplane: xdp, but strait was built without the xdp feature"
                    );
                }
                if self.xdp.is_none() {
                    bail!(
                        "listener {name:?} uses dataplane: xdp, which needs the top-level xdp section"
                    );
                }
            }
        }
        if let Some(mtu) = self.xdp.as_ref().and_then(|xdp| xdp.mtu)
            && mtu < MIN_XDP_MTU
        {
            bail!("xdp.mtu must be at least {MIN_XDP_MTU}, got {mtu}");
        }
        Ok(())
    }
}

impl ListenerConfig {
    fn validate(&self) -> Result<()> {
        match (&self.kubernetes, self.backends.is_empty()) {
            (Some(_), false) => bail!("set either backends or kubernetes, not both"),
            (None, true) => bail!("at least one backend is required, or a kubernetes service"),
            (Some(kubernetes), true) if kubernetes.service.is_empty() => {
                bail!("kubernetes.service cannot be empty")
            }
            _ => {}
        }
        let mut seen = HashSet::new();
        for backend in &self.backends {
            if !seen.insert(backend) {
                bail!("backend {backend} is listed more than once");
            }
        }

        let durations = [
            ("connect_timeout", self.connect_timeout),
            ("idle_timeout", self.idle_timeout()),
            ("health_check.interval", self.health_check.interval),
            ("health_check.timeout", self.health_check.timeout),
        ];
        for (field, value) in durations {
            if value.is_zero() {
                bail!("{field} must be greater than zero");
            }
        }

        if self.health_check.unhealthy_threshold == 0 || self.health_check.healthy_threshold == 0 {
            bail!("health_check thresholds must be at least 1");
        }

        let udp_proxy = self.protocol == Protocol::Udp && self.dataplane == Dataplane::Proxy;
        if !udp_proxy {
            for (field, set) in [
                ("max_flows", self.max_flows.is_some()),
                ("max_flows_per_backend", self.max_flows_per_backend.is_some()),
            ] {
                if set {
                    bail!("{field} is for protocol udp listeners with dataplane proxy");
                }
            }
        }
        if self.max_flows == Some(0) || self.max_flows_per_backend == Some(0) {
            bail!("max_flows and max_flows_per_backend must be at least 1");
        }
        if self.protocol == Protocol::Udp && self.proxy_protocol.is_some() {
            bail!("proxy_protocol is for TCP listeners");
        }
        match (self.strategy == Algorithm::StunUsername, &self.stun_username) {
            (true, None) => bail!("strategy stun-username needs the stun_username section"),
            (false, Some(_)) => bail!("stun_username is only used by strategy stun-username"),
            (true, Some(_)) if !udp_proxy => {
                bail!("strategy stun-username is for protocol udp listeners with dataplane proxy")
            }
            (true, Some(_)) if self.kubernetes.is_none() => {
                bail!(
                    "strategy stun-username finds pods by name, so its backends must come from kubernetes"
                )
            }
            _ => {}
        }
        if self.protocol == Protocol::Udp
            && self.health_check.enabled
            && self.health_check.port.is_none()
        {
            bail!(
                "health checks are TCP connects: a udp listener needs health_check.port (a TCP port on the backends) or health_check.enabled: false"
            );
        }
        if self.proxy_protocol.is_some() && self.dataplane == Dataplane::Xdp {
            // Packets go to the backends as they are, with the client's own
            // address: there is no connection of strait's to put a header on.
            bail!(
                "proxy_protocol is for proxy listeners; with dataplane xdp, backends already see the client's address"
            );
        }
        if self.dataplane == Dataplane::Xdp {
            // The VIP is not bound to a socket: packets to it are caught on the
            // wire, so it needs a real address and port.
            if self.listen.ip().is_unspecified() || self.listen.port() == 0 {
                bail!(
                    "dataplane xdp needs a specific listen address and port (the VIP), got {}",
                    self.listen
                );
            }
            for backend in &self.backends {
                if backend.is_ipv4() != self.listen.is_ipv4() {
                    bail!(
                        "backend {backend}: with dataplane xdp, backends must have the VIP's address family"
                    );
                }
                // Packets keep their destination port: backends get them on the
                // VIP's port, and the backend port is only used by health checks.
                if backend.port() != self.listen.port() {
                    bail!(
                        "backend {backend}: with dataplane xdp, backends receive traffic on the VIP port {}",
                        self.listen.port()
                    );
                }
            }
        }
        Ok(())
    }

    /// `idle_timeout`, or the default for the listener's protocol.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout.unwrap_or(match self.protocol {
            Protocol::Tcp => ProxyConfig::default().idle_timeout,
            Protocol::Udp => DEFAULT_UDP_IDLE_TIMEOUT,
        })
    }

    pub fn udp(&self) -> UdpSettings {
        UdpSettings {
            max_flows: self.max_flows.unwrap_or(DEFAULT_MAX_FLOWS),
            max_flows_per_backend: self.max_flows_per_backend,
            stun_username: self.stun_username.clone().map(std::sync::Arc::new),
        }
    }

    pub fn proxy(&self) -> ProxyConfig {
        ProxyConfig {
            connect_timeout: self.connect_timeout,
            idle_timeout: self.idle_timeout(),
            retries: self.retries,
            proxy_protocol: self.proxy_protocol,
        }
    }

    pub fn health(&self) -> HealthCheck {
        HealthCheck {
            enabled: self.health_check.enabled,
            port: self.health_check.port,
            interval: self.health_check.interval,
            timeout: self.health_check.timeout,
            unhealthy_threshold: self.health_check.unhealthy_threshold,
            healthy_threshold: self.health_check.healthy_threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"
listeners:
  - name: api
    listen: 0.0.0.0:8080
    strategy: least-conn
    backends:
      - 10.0.0.1:9001
      - 10.0.0.2:9001
    connect_timeout: 500ms
    idle_timeout: 1m
    retries: 1
    health_check:
      interval: 2s
      timeout: 300ms
      unhealthy_threshold: 3
      healthy_threshold: 1
  - name: postgres
    listen: 0.0.0.0:5432
    backends: [10.0.1.1:5432]
"#;

    fn error(text: &str) -> String {
        format!("{:#}", Config::parse(text).unwrap_err())
    }

    #[test]
    fn parses_every_field() {
        let config = Config::parse(FULL).unwrap();
        let api = &config.listeners[0];

        assert_eq!(api.name, "api");
        assert_eq!(api.listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(api.strategy, Algorithm::LeastConn);
        assert_eq!(api.backends.len(), 2);
        assert_eq!(api.connect_timeout, Duration::from_millis(500));
        assert_eq!(api.idle_timeout(), Duration::from_secs(60));
        assert_eq!(api.retries, 1);
        assert_eq!(api.health_check.interval, Duration::from_secs(2));
        assert_eq!(api.health_check.unhealthy_threshold, 3);
    }

    #[test]
    fn fills_in_defaults() {
        let config = Config::parse(FULL).unwrap();
        let postgres = &config.listeners[1];

        assert_eq!(postgres.strategy, Algorithm::RoundRobin);
        assert_eq!(postgres.proxy().retries, ProxyConfig::default().retries);
        assert_eq!(postgres.health_check, HealthCheckConfig::default());
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = "listeners:\n  - name: a\n    listen: 127.0.0.1:1\n    backends: [127.0.0.1:2]\n    retires: 3\n";
        assert!(error(text).contains("unknown field `retires`"));
    }

    #[test]
    fn reports_the_line_of_a_bad_value() {
        let text =
            "listeners:\n  - name: a\n    listen: not-an-address\n    backends: [127.0.0.1:2]\n";
        let message = error(text);
        assert!(message.contains("line 3"), "{message}");
    }

    #[test]
    fn rejects_empty_backends() {
        let text = "listeners:\n  - name: a\n    listen: 127.0.0.1:1\n    backends: []\n";
        assert!(error(text).contains("at least one backend"));
    }

    #[test]
    fn rejects_duplicate_listeners() {
        let text = "listeners:\n  - {name: a, listen: 127.0.0.1:1, backends: [127.0.0.1:9]}\n  - {name: a, listen: 127.0.0.1:2, backends: [127.0.0.1:9]}\n";
        assert!(error(text).contains("used more than once"));

        let text = "listeners:\n  - {name: a, listen: 127.0.0.1:1, backends: [127.0.0.1:9]}\n  - {name: b, listen: 127.0.0.1:1, backends: [127.0.0.1:9]}\n";
        assert!(error(text).contains("used by another listener"));
    }

    #[test]
    fn parses_metrics_endpoint() {
        let text = "metrics:\n  listen: 127.0.0.1:9090\nlisteners:\n  - {name: a, listen: 127.0.0.1:1, backends: [127.0.0.1:2]}\n";
        let config = Config::parse(text).unwrap();
        assert_eq!(
            config.metrics.unwrap().listen,
            "127.0.0.1:9090".parse().unwrap()
        );

        assert_eq!(Config::parse(FULL).unwrap().metrics, None);
    }

    #[test]
    fn rejects_metrics_on_a_listener_address() {
        let text = "metrics: {listen: 127.0.0.1:1}\nlisteners:\n  - {name: a, listen: 127.0.0.1:1, backends: [127.0.0.1:2]}\n";
        assert!(error(text).contains("metrics endpoint"));
    }

    #[test]
    fn parses_kubernetes_backends() {
        let text = "listeners:\n  - name: a\n    listen: 127.0.0.1:1\n    kubernetes:\n      service: web\n      namespace: shop\n      port: http\n  - name: b\n    listen: 127.0.0.1:2\n    kubernetes: {service: db, port: 5432}\n";
        let config = Config::parse(text).unwrap();

        let web = config.listeners[0].kubernetes.as_ref().unwrap();
        assert_eq!(web.service, "web");
        assert_eq!(web.namespace.as_deref(), Some("shop"));
        assert_eq!(web.port, ServicePort::Name("http".into()));

        let db = config.listeners[1].kubernetes.as_ref().unwrap();
        assert_eq!(db.namespace, None);
        assert_eq!(db.port, ServicePort::Number(5432));
    }

    #[test]
    fn requires_exactly_one_backend_source() {
        let both = "listeners:\n  - name: a\n    listen: 127.0.0.1:1\n    backends: [127.0.0.1:2]\n    kubernetes: {service: web, port: 80}\n";
        assert!(error(both).contains("either backends or kubernetes"));

        let neither = "listeners:\n  - name: a\n    listen: 127.0.0.1:1\n";
        assert!(error(neither).contains("or a kubernetes service"));
    }

    const XDP: &str = r#"
xdp:
  interface: eth0
  source: 10.0.2.2
  gateway_mac: AA:bb:cc:00:11:22
listeners:
  - name: web
    listen: 10.0.0.10:80
    dataplane: xdp
    backends: [10.0.3.2:80, 10.0.3.3:80]
"#;

    #[test]
    fn parses_xdp_listeners() {
        if !cfg!(feature = "xdp") {
            assert!(error(XDP).contains("built without the xdp feature"));
            return;
        }
        let config = Config::parse(XDP).unwrap();
        let xdp = config.xdp.unwrap();
        let mac = xdp.gateway_mac.unwrap();
        assert_eq!(mac.0, [0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22]);
        assert_eq!(mac.to_string(), "aa:bb:cc:00:11:22");
        assert_eq!(xdp.source, Some("10.0.2.2".parse().unwrap()));
        assert_eq!(config.listeners[0].protocol, Protocol::Tcp);
        assert_eq!(xdp.mode, XdpMode::Auto);
        assert_eq!(config.listeners[0].dataplane, Dataplane::Xdp);
    }

    #[test]
    fn checks_xdp_listeners() {
        let without_section = XDP.replace(
            "xdp:\n  interface: eth0\n  source: 10.0.2.2\n  gateway_mac: AA:bb:cc:00:11:22\n",
            "",
        );
        assert!(error(&without_section).contains("xdp"));
        assert!(error(&XDP.replace("AA:bb", "AA:zz")).contains("invalid MAC address"));
        assert!(
            error(&XDP.replace("AA:bb:cc:00:11:22", "aa:bb:cc:00:11"))
                .contains("invalid MAC address")
        );
        if cfg!(feature = "xdp") {
            assert!(error(&XDP.replace("10.0.3.3:80", "10.0.3.3:8080")).contains("VIP port 80"));
            assert!(
                error(&XDP.replace("listen: 10.0.0.10:80", "listen: 0.0.0.0:80"))
                    .contains("specific listen address")
            );
            assert!(
                error(&XDP.replace("10.0.3.3:80", "\"[fd00::3]:80\""))
                    .contains("VIP's address family")
            );
            let mtu = |value: &str| {
                XDP.replace(
                    "  interface: eth0\n",
                    &format!("  interface: eth0\n  mtu: {value}\n"),
                )
            };
            assert_eq!(
                Config::parse(&mtu("1500")).unwrap().xdp.unwrap().mtu,
                Some(1500)
            );
            assert!(error(&mtu("500")).contains("at least 576"));
        }
    }

    #[test]
    fn parses_proxy_protocol() {
        let text = "listeners:\n  - name: a\n    listen: 127.0.0.1:1\n    backends: [127.0.0.1:2]\n    proxy_protocol: v2\n";
        let config = Config::parse(text).unwrap();
        assert_eq!(
            config.listeners[0].proxy().proxy_protocol,
            Some(ProxyProtocol::V2)
        );
        assert!(error(&text.replace("v2", "v1")).contains("unknown variant"));
        if cfg!(feature = "xdp") {
            let xdp = XDP.replace("dataplane: xdp", "dataplane: xdp\n    proxy_protocol: v2");
            assert!(error(&xdp).contains("proxy_protocol is for proxy listeners"));
        }
    }

    #[test]
    fn checks_stun_username_listeners() {
        let base = "listeners:\n  - name: rtc\n    listen: 0.0.0.0:3478\n    protocol: udp\n    kubernetes: { service: nes-session, port: 5000 }\n    health_check: { enabled: false }\n";
        let stun = format!(
            "{base}    strategy: stun-username\n    stun_username:\n      ufrag: \"nsp{{id}}\"\n      pod: \"nes-session-{{id}}\"\n"
        );
        let config = Config::parse(&stun).unwrap();
        let routing = config.listeners[0].udp().stun_username.unwrap();
        assert_eq!(routing.ufrag.to_string(), "nsp{id}");
        assert_eq!(routing.pod.to_string(), "nes-session-{id}");

        assert!(error(&stun.replace("nsp{id}", "nsp-{id}")).contains("not allowed in an ICE ufrag"));
        assert!(
            error(&format!("{base}    strategy: stun-username\n")).contains("needs the stun_username")
        );
        let without_strategy = stun.replace("    strategy: stun-username\n", "");
        assert!(error(&without_strategy).contains("only used by strategy stun-username"));
        let tcp = stun.replace("    protocol: udp\n", "");
        assert!(error(&tcp).contains("for protocol udp listeners"));
        let fixed = stun.replace(
            "kubernetes: { service: nes-session, port: 5000 }",
            "backends: [127.0.0.1:5000]",
        );
        assert!(error(&fixed).contains("must come from kubernetes"));
    }

    #[test]
    fn checks_udp_listeners() {
        let proxy_udp = "listeners:\n  - name: dns\n    listen: 127.0.0.1:53\n    protocol: udp\n    backends: [127.0.0.1:5353]\n";
        // The UDP proxy has TCP health checks too, so it needs a TCP port.
        assert!(error(proxy_udp).contains("health_check.port"));
        let unchecked = format!("{proxy_udp}    health_check:\n      enabled: false\n");
        let config = Config::parse(&unchecked).unwrap();
        let listener = &config.listeners[0];
        assert_eq!(listener.idle_timeout(), crate::DEFAULT_UDP_IDLE_TIMEOUT);
        assert_eq!(listener.udp().max_flows, crate::udp::DEFAULT_MAX_FLOWS);

        let limited = format!("{unchecked}    max_flows: 10\n    max_flows_per_backend: 2\n");
        let udp = Config::parse(&limited).unwrap().listeners[0].udp();
        assert_eq!((udp.max_flows, udp.max_flows_per_backend), (10, Some(2)));
        assert!(error(&limited.replace("max_flows: 10", "max_flows: 0")).contains("at least 1"));
        let tcp_limited = "listeners:\n  - name: a\n    listen: 127.0.0.1:1\n    backends: [127.0.0.1:2]\n    max_flows: 5\n";
        assert!(error(tcp_limited).contains("max_flows is for protocol udp"));
        assert!(
            error(&format!("{unchecked}    proxy_protocol: v2\n")).contains("for TCP listeners")
        );

        // TCP and UDP listeners can share an address.
        let both = format!(
            "{unchecked}  - name: dns-tcp\n    listen: 127.0.0.1:53\n    backends: [127.0.0.1:5353]\n"
        );
        assert_eq!(Config::parse(&both).unwrap().listeners.len(), 2);
        if !cfg!(feature = "xdp") {
            return;
        }
        let udp = XDP.replace("dataplane: xdp", "dataplane: xdp\n    protocol: udp");
        assert!(error(&udp).contains("health_check.port"));
        let probed = format!("{udp}    health_check:\n      port: 8080\n");
        let config = Config::parse(&probed).unwrap();
        assert_eq!(config.listeners[0].health().port, Some(8080));
        assert!(Config::parse(&format!("{udp}    health_check:\n      enabled: false\n")).is_ok());

        // The same VIP over TCP and UDP is two listeners.
        let both = format!(
            "{XDP}  - name: web-udp\n    listen: 10.0.0.10:80\n    dataplane: xdp\n    protocol: udp\n    backends: [10.0.3.2:80]\n    health_check:\n      enabled: false\n"
        );
        assert_eq!(Config::parse(&both).unwrap().listeners.len(), 2);
    }

    #[test]
    fn rejects_zero_durations() {
        let text = "listeners:\n  - name: a\n    listen: 127.0.0.1:1\n    backends: [127.0.0.1:2]\n    idle_timeout: 0s\n";
        assert!(error(text).contains("idle_timeout must be greater than zero"));
    }
}
