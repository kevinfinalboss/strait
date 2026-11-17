//! YAML configuration: one or more listeners, each with its own backends and settings.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::ProxyConfig;
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
    /// Source address of the outer IP-in-IP header, usually the interface's own.
    pub source: Ipv4Addr,
    /// MAC address of the next hop that routes encapsulated packets to backends.
    pub gateway_mac: MacAddr,
    #[serde(default)]
    pub mode: XdpMode,
}

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
    #[serde(default = "default_idle_timeout", with = "humantime_serde")]
    pub idle_timeout: Duration,
    #[serde(default = "default_retries")]
    pub retries: usize,
    #[serde(default)]
    pub health_check: HealthCheckConfig,
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

fn default_idle_timeout() -> Duration {
    ProxyConfig::default().idle_timeout
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
            addrs.insert(metrics.listen);
        }
        for listener in &self.listeners {
            let name = &listener.name;
            if name.is_empty() {
                bail!("listener name cannot be empty");
            }
            if !names.insert(name) {
                bail!("listener name {name:?} is used more than once");
            }
            if !addrs.insert(listener.listen) {
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
            ("idle_timeout", self.idle_timeout),
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

        if self.dataplane == Dataplane::Xdp {
            // The VIP is not bound to a socket: packets to it are caught on the
            // wire, so it needs a real address and port.
            if !matches!(self.listen.ip(), IpAddr::V4(ip) if !ip.is_unspecified())
                || self.listen.port() == 0
            {
                bail!(
                    "dataplane xdp needs an IPv4 listen address and port (the VIP), got {}",
                    self.listen
                );
            }
            for backend in &self.backends {
                if !backend.is_ipv4() {
                    bail!("dataplane xdp supports IPv4 backends only, got {backend}");
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

    pub fn proxy(&self) -> ProxyConfig {
        ProxyConfig {
            connect_timeout: self.connect_timeout,
            idle_timeout: self.idle_timeout,
            retries: self.retries,
        }
    }

    pub fn health(&self) -> HealthCheck {
        HealthCheck {
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
        assert_eq!(api.idle_timeout, Duration::from_secs(60));
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
        assert_eq!(xdp.gateway_mac.0, [0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22]);
        assert_eq!(xdp.gateway_mac.to_string(), "aa:bb:cc:00:11:22");
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
                    .contains("IPv4 listen address")
            );
        }
    }

    #[test]
    fn rejects_zero_durations() {
        let text = "listeners:\n  - name: a\n    listen: 127.0.0.1:1\n    backends: [127.0.0.1:2]\n    idle_timeout: 0s\n";
        assert!(error(text).contains("idle_timeout must be greater than zero"));
    }
}
