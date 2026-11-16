//! YAML configuration: one or more listeners, each with its own backends and settings.

use std::collections::HashSet;
use std::net::SocketAddr;
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
    pub backends: Vec<SocketAddr>,
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
        }
        Ok(())
    }
}

impl ListenerConfig {
    fn validate(&self) -> Result<()> {
        if self.backends.is_empty() {
            bail!("at least one backend is required");
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
    fn rejects_zero_durations() {
        let text = "listeners:\n  - name: a\n    listen: 127.0.0.1:1\n    backends: [127.0.0.1:2]\n    idle_timeout: 0s\n";
        assert!(error(text).contains("idle_timeout must be greater than zero"));
    }
}
