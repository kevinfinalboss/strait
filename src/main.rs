use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use strait::{Algorithm, HealthCheck, Pool, ProxyConfig};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

/// A Layer 4 load balancer written in Rust.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Address to listen on
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Backend that receives connections (repeat for more backends)
    #[arg(short = 'b', long = "backend", required = true)]
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let pool = Arc::new(Pool::new(args.backends, args.strategy)?);
    let listener = TcpListener::bind(args.listen).await?;

    strait::spawn_health_checks(
        &pool,
        HealthCheck {
            interval: args.health_interval,
            timeout: args.health_timeout,
            ..HealthCheck::default()
        },
    );

    let config = ProxyConfig {
        connect_timeout: args.connect_timeout,
        idle_timeout: args.idle_timeout,
        retries: args.retries,
    };

    tracing::info!(strategy = ?args.strategy, "load balancing");

    tokio::select! {
        result = strait::run(listener, pool, config) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
}
