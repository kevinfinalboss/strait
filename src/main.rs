use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use notify::{RecursiveMode, Watcher};
use prometheus_client::registry::Registry;
use strait::{
    Algorithm, Config, HealthCheckConfig, ListenerConfig, Metrics, MetricsConfig, ReloadResult,
    Server,
};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
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

    /// Reload automatically when the config file changes, including a Kubernetes
    /// ConfigMap mounted as a directory
    #[arg(long, requires = "config", conflicts_with = "backends")]
    watch_config: bool,

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

    /// Send backends a PROXY protocol header with the client's address
    #[arg(long, value_enum, value_name = "VERSION")]
    proxy_protocol: Option<strait::ProxyProtocol>,

    /// Time between health checks of each backend
    #[arg(long, default_value = "5s", value_parser = humantime::parse_duration)]
    health_interval: Duration,

    /// Maximum time a health check may take
    #[arg(long, default_value = "1s", value_parser = humantime::parse_duration)]
    health_timeout: Duration,

    /// Serve Prometheus metrics on this address (overrides `metrics.listen` in the config)
    #[arg(long, value_name = "ADDR")]
    metrics: Option<SocketAddr>,

    /// On SIGTERM or Ctrl-C, how long open connections get to finish before they
    /// are cut; keep it below the pod's terminationGracePeriodSeconds
    #[arg(long, default_value = "20s", value_parser = humantime::parse_duration)]
    shutdown_timeout: Duration,
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
                dataplane: strait::Dataplane::Proxy,
                protocol: strait::Protocol::Tcp,
                backends: self.backends.clone(),
                kubernetes: None,
                strategy: self.strategy,
                connect_timeout: self.connect_timeout,
                idle_timeout: Some(self.idle_timeout),
                retries: self.retries,
                health_check: HealthCheckConfig {
                    interval: self.health_interval,
                    timeout: self.health_timeout,
                    ..HealthCheckConfig::default()
                },
                proxy_protocol: self.proxy_protocol,
                max_flows: None,
                max_flows_per_backend: None,
                stun_username: None,
            }],
            metrics: None,
            xdp: None,
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
        #[cfg(feature = "xdp")]
        registry.register_collector(Box::new(server.xdp_stats()));
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
    // Kubernetes stops pods with SIGTERM. As PID 1 in a container, a signal
    // without a handler is ignored, so without this every stop would wait for
    // the grace period and end in SIGKILL.
    let mut terminate = signal(SignalKind::terminate())?;
    let (changes, mut changed) = mpsc::unbounded_channel();
    let _watcher = match (&args.config, args.watch_config) {
        (Some(path), true) => Some(watch(path, changes)?),
        _ => None,
    };

    loop {
        tokio::select! {
            _ = hangup.recv() => {
                if args.config.is_none() {
                    warn!("SIGHUP ignored: reloading needs --config");
                    continue;
                }
                reload(&args, &mut server, &metrics, metrics_listen).await;
            }
            Some(()) = changed.recv() => {
                // One save often fires several events; wait for them to settle.
                tokio::time::sleep(Duration::from_millis(500)).await;
                while changed.try_recv().is_ok() {}
                info!("config file changed");
                reload(&args, &mut server, &metrics, metrics_listen).await;
            }
            _ = terminate.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }

    info!("shutting down, no longer accepting connections");
    tokio::select! {
        cut = server.shutdown(args.shutdown_timeout) => {
            if cut == 0 {
                info!("all connections finished");
            } else {
                warn!(connections = cut, "shutdown timeout reached, closing open connections");
            }
        }
        // A second signal skips the wait.
        _ = terminate.recv() => warn!("second signal, closing open connections"),
        _ = tokio::signal::ctrl_c() => warn!("second signal, closing open connections"),
    }
    Ok(())
}

async fn reload(
    args: &Args,
    server: &mut Server,
    metrics: &Metrics,
    metrics_listen: Option<SocketAddr>,
) {
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
            error!(
                error = format!("{err:#}"),
                "reload failed, keeping previous config"
            );
        }
    }
}

/// Watches the directory that holds `path` and sends a message on every change.
///
/// The directory is watched rather than the file because Kubernetes updates a
/// mounted ConfigMap by swapping a symlink, which a watch on the file would miss.
fn watch(path: &std::path::Path, changes: mpsc::UnboundedSender<()>) -> Result<impl Watcher> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."))
        .to_owned();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        if event.is_ok_and(|event| !event.kind.is_access()) {
            let _ = changes.send(());
        }
    })?;
    watcher
        .watch(&dir, RecursiveMode::NonRecursive)
        .with_context(|| format!("could not watch {}", dir.display()))?;
    info!(dir = %dir.display(), "watching config for changes");
    Ok(watcher)
}
