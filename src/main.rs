use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use prometheus_client::registry::Registry;
use strait::{
    Algorithm, Config, HealthCheckConfig, ListenerConfig, Metrics, MetricsConfig, ReloadResult,
    Server,
};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// A Layer 4 load balancer written in Rust.
///
/// Configure it with a YAML file (--config), or with flags for a single listener.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// YAML config file; send SIGHUP to reload it without dropping connections
    #[arg(short, long, conflicts_with = "backends")]
    config: Option<PathBuf>,

    /// Address to listen on
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Backend that receives connections (repeat for more backends)
    #[arg(short = 'b', long = "backend", required_unless_present = "config")]
    backends: Vec<SocketAddr>,

    /// Load balancing strategy
    #[arg(short, long, value_enum, default_value_t = Algorithm::RoundRobin)]
    strategy: Algorithm,

    /// Maximum time to connect to a backend
    #[arg(long, default_value = "3s", value_parser = humantime::parse_duration)]
    connect_timeout: Duration,

    /// Close connections with no traffic for this long
    #[arg(long, default_value = "5m", value_parser = humantime::parse_duration)]
    idle_timeout: Duration,

    /// Other backends to try when a connection to the chosen one fails
    #[arg(long, default_value_t = 2)]
    retries: usize,

    /// Time between health checks of each backend
    #[arg(long, default_value = "5s", value_parser = humantime::parse_duration)]
    health_interval: Duration,

    /// Maximum time a health check may take
    #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
    health_timeout: Duration,

    /// Serve Prometheus metrics on this address (overrides `metrics.listen` in the config)
    #[arg(long, value_name = "ADDR")]
    metrics: Option<SocketAddr>,
}

impl Args {
    fn load_config(&self) -> Result<Config> {
        let mut config = self.config_without_overrides()?;
        if let Some(listen) = self.metrics {
            config.metrics = Some(MetricsConfig { listen });
            config.validate()?;
        }
        Ok(config)
    }

    fn config_without_overrides(&self) -> Result<Config> {
        if let Some(path) = &self.config {
            return Config::load(path);
        }

        let config = Config {
            listeners: vec![ListenerConfig {
                name: "default".into(),
                listen: self.listen,
                backends: self.backends.clone(),
                strategy: self.strategy,
                connect_timeout: self.connect_timeout,
                idle_timeout: self.idle_timeout,
                retries: self.retries,
                health_check: HealthCheckConfig {
                    interval: self.health_interval,
                    timeout: self.health_timeout,
                    ..HealthCheckConfig::default()
                },
            }],
            metrics: None,
        };
        config.validate()?;
        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let config = args.load_config()?;
    let metrics = Arc::new(Metrics::default());
    let mut server = Server::with_metrics(&config, Arc::clone(&metrics)).await?;
    for (name, addr) in server.local_addrs() {
        info!(listener = %name, %addr, "strait is up");
    }

    // The metrics address is read once at startup; changing it needs a restart.
    let metrics_listen = config.metrics.map(|m| m.listen);
    if let Some(listen) = metrics_listen {
        let mut registry = Registry::default();
        metrics.register(&mut registry);
        registry.register_collector(Box::new(server.backend_state()));
        let socket = TcpListener::bind(listen)
            .await
            .with_context(|| format!("could not bind metrics endpoint {listen}"))?;
        tokio::spawn(async move {
            if let Err(err) = strait::serve_metrics(socket, Arc::new(registry)).await {
                error!(error = %err, "metrics endpoint stopped");
            }
        });
    }

    let mut hangup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = hangup.recv() => {
                if args.config.is_none() {
                    warn!("SIGHUP ignored: reloading needs --config");
                    continue;
                }
                let reloaded = match args.load_config() {
                    Ok(config) => {
                        if config.metrics.map(|m| m.listen) != metrics_listen {
                            warn!("metrics.listen changed; restart strait to apply it");
                        }
                        server.reload(&config).await
                    }
                    Err(err) => Err(err),
                };
                match reloaded {
                    Ok(summary) => {
                        metrics.record_reload(ReloadResult::Success);
                        info!(%summary, "config reloaded");
                    }
                    Err(err) => {
                        metrics.record_reload(ReloadResult::Failure);
                        error!(error = format!("{err:#}"), "reload failed, keeping previous config");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                return Ok(());
            }
        }
    }
}
