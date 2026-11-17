//! Userspace control plane of the XDP data plane (feature `xdp`).
//!
//! strait loads the XDP program from `strait-ebpf` onto one interface, then
//! keeps one Maglev table per XDP listener (a VIP) in sync with the listener's
//! healthy backends. The kernel side does the per-packet work; see
//! `strait-ebpf/src/main.rs`.

use std::collections::HashMap;
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwap;
use aya::Ebpf;
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray, PerCpuValues};
use aya::programs::Xdp;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::ConstCounter;
use strait_common::{MAX_VIPS, PROTO_TCP, Settings, TABLE_SIZE, VipKey, VipStats};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{Instrument, Span, info, warn};

use crate::Route;
use crate::config::{XdpConfig, XdpMode};
use crate::maglev::Maglev;
use crate::metrics::ListenerLabels;

/// How often each XDP listener compares its healthy backends with its table.
const SYNC_INTERVAL: Duration = Duration::from_millis(500);

/// The XDP program attached to an interface, and its maps. Dropping it detaches
/// the program.
pub struct DataPlane {
    config: XdpConfig,
    inner: Mutex<Inner>,
}

struct Inner {
    /// Owns the program; its link detaches when this is dropped.
    _ebpf: Ebpf,
    vips: BpfHashMap<MapData, VipKey, u32>,
    tables: Array<MapData, u32>,
    stats: PerCpuArray<MapData, VipStats>,
    active: HashMap<VipKey, Vip>,
}

struct Vip {
    slot: u32,
    listener: String,
    /// What the kernel table holds, so an update only writes slots that changed.
    table: Vec<u32>,
}

impl DataPlane {
    /// Loads the program and attaches it to `config.interface`. Needs root, or
    /// `CAP_BPF` and `CAP_NET_ADMIN`.
    pub fn attach(config: &XdpConfig) -> Result<Self> {
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/strait-xdp"
        )))
        .context("could not load the XDP program (strait needs root or CAP_BPF)")?;

        let program: &mut Xdp = ebpf
            .program_mut("strait_xdp")
            .context("XDP program missing from the object")?
            .try_into()?;
        program
            .load()
            .context("the kernel rejected the XDP program")?;
        let interface = CString::new(config.interface.as_str())?;
        let mode = match config.mode {
            XdpMode::Auto => aya::programs::XdpMode::Default,
            XdpMode::Native => aya::programs::XdpMode::Driver,
            XdpMode::Generic => aya::programs::XdpMode::Skb,
        };
        program.attach(&interface, mode).with_context(|| {
            format!(
                "could not attach XDP to {} in {:?} mode",
                config.interface, config.mode
            )
        })?;

        let mut settings: Array<MapData, Settings> = take_map(&mut ebpf, "SETTINGS")?;
        settings.set(
            0,
            &Settings {
                source: u32::from(config.source),
                gateway_mac: config.gateway_mac.0,
                _pad: [0; 2],
            },
            0,
        )?;

        let inner = Inner {
            vips: take_map(&mut ebpf, "VIPS")?,
            tables: take_map(&mut ebpf, "TABLES")?,
            stats: take_map(&mut ebpf, "STATS")?,
            _ebpf: ebpf,
            active: HashMap::new(),
        };
        info!(
            interface = %config.interface,
            mode = ?config.mode,
            source = %config.source,
            gateway = %config.gateway_mac,
            "XDP data plane attached"
        );
        Ok(Self {
            config: config.clone(),
            inner: Mutex::new(inner),
        })
    }

    pub fn config(&self) -> &XdpConfig {
        &self.config
    }

    /// Points `vip` at `backends`, adding the VIP if it is new.
    ///
    /// The table is written before the VIP is published, so the program never
    /// sees a new VIP with an empty table. On an update, flows on slots that
    /// changed move to their new backend as their slot is written.
    pub fn set(&self, listener: &str, vip: SocketAddrV4, backends: &[Ipv4Addr]) -> Result<()> {
        let key = vip_key(vip);
        let maglev = Maglev::new(backends.iter().copied().map(IpAddr::V4), TABLE_SIZE);
        let table: Vec<u32> = if maglev.table().is_empty() {
            vec![0; TABLE_SIZE as usize]
        } else {
            maglev
                .table()
                .iter()
                .map(|&index| match maglev.backends()[index as usize] {
                    IpAddr::V4(ip) => u32::from(ip),
                    IpAddr::V6(_) => unreachable!("only IPv4 backends are passed in"),
                })
                .collect()
        };

        let mut inner = self.inner.lock().expect("data plane lock poisoned");
        let inner = &mut *inner;
        let (slot, previous, is_new) = match inner.active.get_mut(&key) {
            Some(existing) => (existing.slot, std::mem::take(&mut existing.table), false),
            None => {
                let used: Vec<u32> = inner.active.values().map(|v| v.slot).collect();
                let Some(slot) = (0..MAX_VIPS).find(|slot| !used.contains(slot)) else {
                    bail!("the XDP data plane supports at most {MAX_VIPS} listeners");
                };
                (slot, Vec::new(), true)
            }
        };

        let base = slot * TABLE_SIZE;
        for (index, &backend) in table.iter().enumerate() {
            if previous.get(index) != Some(&backend) {
                inner.tables.set(base + index as u32, &backend, 0)?;
            }
        }

        if is_new {
            // A reused slot must not carry the counters of its previous VIP.
            let cpus = aya::util::nr_cpus()
                .map_err(|(path, err)| anyhow::anyhow!("{path}: {err}"))?
                .get() as usize;
            inner.stats.set(
                slot,
                PerCpuValues::try_from(vec![VipStats::default(); cpus])?,
                0,
            )?;
            inner.vips.insert(&key, &slot, 0)?;
        }
        inner.active.insert(
            key,
            Vip {
                slot,
                listener: listener.to_owned(),
                table,
            },
        );
        Ok(())
    }

    /// Stops balancing `vip`; its packets go back to the kernel.
    pub fn remove(&self, vip: SocketAddrV4) {
        let key = vip_key(vip);
        let mut inner = self.inner.lock().expect("data plane lock poisoned");
        if inner.active.remove(&key).is_some()
            && let Err(err) = inner.vips.remove(&key)
        {
            warn!(%vip, error = %err, "could not remove VIP from the XDP data plane");
        }
    }

    /// Counters of every VIP, summed over CPUs.
    fn stats(&self) -> Vec<(String, VipStats)> {
        let inner = self.inner.lock().expect("data plane lock poisoned");
        inner
            .active
            .values()
            .map(|vip| {
                let total = inner
                    .stats
                    .get(&vip.slot, 0)
                    .map(|per_cpu| {
                        per_cpu
                            .iter()
                            .fold(VipStats::default(), |sum, cpu| VipStats {
                                packets: sum.packets + cpu.packets,
                                bytes: sum.bytes + cpu.bytes,
                                no_backend: sum.no_backend + cpu.no_backend,
                            })
                    })
                    .unwrap_or_default();
                (vip.listener.clone(), total)
            })
            .collect()
    }
}

fn take_map<T: TryFrom<aya::maps::Map, Error = aya::maps::MapError>>(
    ebpf: &mut Ebpf,
    name: &str,
) -> Result<T> {
    let map = ebpf
        .take_map(name)
        .with_context(|| format!("map {name} missing from the XDP object"))?;
    Ok(T::try_from(map)?)
}

fn vip_key(vip: SocketAddrV4) -> VipKey {
    VipKey {
        addr: u32::from(*vip.ip()),
        port: vip.port(),
        proto: PROTO_TCP,
        _pad: 0,
    }
}

/// One XDP listener's VIP in the data plane. Dropping it stops the sync and
/// removes the VIP.
pub struct Binding {
    dataplane: Arc<DataPlane>,
    vip: SocketAddrV4,
    sync: JoinHandle<()>,
}

impl Binding {
    /// Publishes `vip` and keeps its table in sync with the healthy backends of
    /// the listener's current route.
    pub fn start(
        dataplane: Arc<DataPlane>,
        vip: SocketAddrV4,
        route: Arc<ArcSwap<Route>>,
        span: Span,
    ) -> Self {
        let sync = tokio::spawn(sync(Arc::clone(&dataplane), vip, route).instrument(span));
        Self {
            dataplane,
            vip,
            sync,
        }
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        self.sync.abort();
        self.dataplane.remove(self.vip);
    }
}

/// Health checks only flip flags on backends, so the sync polls for changes.
async fn sync(dataplane: Arc<DataPlane>, vip: SocketAddrV4, route: Arc<ArcSwap<Route>>) {
    let mut ticker = interval(SYNC_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut applied: Option<(String, Vec<Ipv4Addr>)> = None;

    loop {
        ticker.tick().await;
        let route = route.load();
        let wanted = (route.name.to_string(), serving(&route));
        if applied.as_ref() == Some(&wanted) {
            continue;
        }

        let dp = Arc::clone(&dataplane);
        let (name, backends) = wanted.clone();
        // Writing a table is up to TABLE_SIZE syscalls: keep it off the runtime.
        let result = tokio::task::spawn_blocking(move || dp.set(&name, vip, &backends)).await;
        match result {
            Ok(Ok(())) => {
                info!(%vip, backends = wanted.1.len(), "XDP backends updated");
                applied = Some(wanted);
            }
            Ok(Err(err)) => {
                warn!(%vip, error = format!("{err:#}"), "could not update XDP backends")
            }
            Err(err) => warn!(%vip, error = %err, "XDP update task failed"),
        }
    }
}

/// Backends that should get traffic: the healthy ones, or every one if none is
/// healthy (fail open, like the proxy).
fn serving(route: &Route) -> Vec<Ipv4Addr> {
    let ipv4 = |addr: SocketAddr| match addr.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    };
    let backends = route.pool.backends();
    let healthy: Vec<_> = backends
        .iter()
        .filter(|b| b.is_healthy())
        .filter_map(|b| ipv4(b.addr()))
        .collect();
    let mut chosen = if healthy.is_empty() {
        backends.iter().filter_map(|b| ipv4(b.addr())).collect()
    } else {
        healthy
    };
    chosen.sort_unstable();
    chosen
}

/// Name, help and value of one counter family.
type Series = (&'static str, &'static str, fn(&VipStats) -> u64);

/// Prometheus counters of the XDP data plane, read at scrape time.
#[derive(Clone, Default)]
pub struct XdpStats {
    dataplane: Arc<Mutex<Option<Arc<DataPlane>>>>,
}

impl std::fmt::Debug for XdpStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpStats").finish_non_exhaustive()
    }
}

impl XdpStats {
    pub(crate) fn set(&self, dataplane: Arc<DataPlane>) {
        *self.dataplane.lock().expect("stats lock poisoned") = Some(dataplane);
    }
}

impl Collector for XdpStats {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let dataplane = self.dataplane.lock().expect("stats lock poisoned").clone();
        let rows = dataplane.map(|dp| dp.stats()).unwrap_or_default();

        let series: [Series; 3] = [
            (
                "strait_xdp_packets",
                "Packets sent to a backend by the XDP data plane",
                |s| s.packets,
            ),
            (
                "strait_xdp_bytes",
                "Bytes of packets sent to a backend by the XDP data plane, before encapsulation",
                |s| s.bytes,
            ),
            (
                "strait_xdp_no_backend",
                "Packets the XDP data plane dropped because the listener had no backend",
                |s| s.no_backend,
            ),
        ];
        for (name, help, value) in series {
            let mut family = encoder.encode_descriptor(name, help, None, MetricType::Counter)?;
            for (listener, stats) in &rows {
                let labels = ListenerLabels {
                    listener: listener.clone(),
                };
                ConstCounter::new(value(stats)).encode(family.encode_family(&labels)?)?;
            }
        }
        Ok(())
    }
}
