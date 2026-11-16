use std::net::SocketAddr;

use anyhow::Result;
use clap::Parser;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

/// A Layer 4 load balancer written in Rust.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Address to listen on
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Backend that receives the connections
    #[arg(short, long)]
    backend: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let listener = TcpListener::bind(args.listen).await?;

    tokio::select! {
        result = strait::run(listener, args.backend) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
}
