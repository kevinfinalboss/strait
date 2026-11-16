use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use strait::{Algorithm, Pool};
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let pool = Arc::new(Pool::new(args.backends, args.strategy)?);
    let listener = TcpListener::bind(args.listen).await?;

    tracing::info!(strategy = ?args.strategy, "load balancing");

    tokio::select! {
        result = strait::run(listener, pool) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
}
