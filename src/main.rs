use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use strait::{Algorithm, Config, HealthCheckConfig, ListenerConfig, Server};
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
}

impl Args {
    fn load_config(&self) -> Result<Config> {
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
    let mut server = Server::start(&args.load_config()?).await?;
    for (name, addr) in server.local_addrs() {
        info!(listener = %name, %addr, "strait is up");
    }

    let mut hangup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = hangup.recv() => {
                if args.config.is_none() {
                    warn!("SIGHUP ignored: reloading needs --config");
                    continue;
                }
                match args.load_config() {
                    Ok(config) => match server.reload(&config).await {
                        Ok(summary) => info!(%summary, "config reloaded"),
                        Err(err) => error!(error = format!("{err:#}"), "reload failed, keeping previous config"),
                    },
                    Err(err) => error!(error = format!("{err:#}"), "reload failed, keeping previous config"),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                return Ok(());
            }
        }
    }
}
