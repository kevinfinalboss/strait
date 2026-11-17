//! Userspace control plane of the XDP data plane (feature `xdp`).
//!
//! strait loads the XDP program from `strait-ebpf` onto one interface, then
//! keeps, for every XDP listener (a VIP), its backends and Maglev table in sync
//! with the listener's healthy backends. The kernel side does the per-packet
//! work; see `strait-ebpf/src/main.rs`.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use aya::Ebpf;
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray, PerCpuValues};
use aya::programs::Xdp;
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::ConstCounter;
use strait_common::{
    Backend, FAMILY_V4, FAMILY_V6, MAX_BACKENDS, MAX_VIPS, PROTO_TCP, PROTO_UDP, Settings,
    TABLE_SIZE, VipKey, VipStats,
};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};
use tracing::{Instrument, Span, info, warn};

use crate::Route;
use crate::config::{MacAddr, Protocol, XdpConfig, XdpMode};
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
    backends: Array<MapData, Backend>,
    stats: PerCpuArray<MapData, VipStats>,
    active: HashMap<VipKey, Vip>,
    /// Whether an IPv6 outer source is configured.
    has_source_v6: bool,
    /// Bumped every time a backend index is (re)assigned.
    generation: u32,
}

struct Vip {
    slot: u32,
    listener: String,
    /// Backend address to its stable index within the VIP.
    indices: HashMap<IpAddr, u32>,
    /// What the kernel table holds, so an update only writes slots that changed.
    table: Vec<u32>,
    /// Whether the VIP is in the kernel's `VIPS` map. A first `set` that fails
    /// halfway leaves it out, and the next `set` publishes it.
    published: bool,
}

/// The settings the program runs with, after filling in what the config left
/// to detection.
#[derive(Debug, Clone, Copy)]
struct Resolved {
    source_v4: Ipv4Addr,
    source_v6: Option<Ipv6Addr>,
    gateway_mac: MacAddr,
}

impl DataPlane {
    /// Loads the program and attaches it to `config.interface`. Needs root, or
    /// `CAP_BPF` and `CAP_NET_ADMIN`.
    pub fn attach(config: &XdpConfig) -> Result<Self> {
        let resolved = resolve(config)?;

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
                source_v4: resolved.source_v4.octets(),
                source_v6: resolved.source_v6.map_or([0; 16], |ip| ip.octets()),
                gateway_mac: resolved.gateway_mac.0,
                _pad: [0; 2],
            },
            0,
        )?;

        let inner = Inner {
            vips: take_map(&mut ebpf, "VIPS")?,
            tables: take_map(&mut ebpf, "TABLES")?,
            backends: take_map(&mut ebpf, "BACKENDS")?,
            stats: take_map(&mut ebpf, "STATS")?,
            _ebpf: ebpf,
            active: HashMap::new(),
            has_source_v6: resolved.source_v6.is_some(),
            generation: 0,
        };
        info!(
            interface = %config.interface,
            mode = ?config.mode,
            source = %resolved.source_v4,
            source_v6 = %resolved.source_v6.map_or("none".to_owned(), |ip| ip.to_string()),
            gateway = %resolved.gateway_mac,
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
    /// Writes happen in an order that never sends a packet nowhere: new
    /// backends are published first, then the table entries that change, then
    /// backends that left are marked inactive (which also rebalances the flows
    /// remembered for them). The VIP itself is published last, once a `set` of
    /// it gets that far.
    pub fn set(
        &self,
        listener: &str,
        vip: SocketAddr,
        protocol: Protocol,
        backends: &[IpAddr],
    ) -> Result<()> {
        let key = vip_key(vip, protocol);
        let mut inner = self.inner.lock().expect("data plane lock poisoned");
        let inner = &mut *inner;
        if vip.is_ipv6() && !inner.has_source_v6 {
            bail!(
                "IPv6 VIP {vip} needs an IPv6 outer source: set xdp.source_v6, or give the interface a global IPv6 address"
            );
        }

        if !inner.active.contains_key(&key) {
            let used: Vec<u32> = inner.active.values().map(|v| v.slot).collect();
            let Some(slot) = (0..MAX_VIPS).find(|slot| !used.contains(slot)) else {
                bail!("the XDP data plane supports at most {MAX_VIPS} listeners");
            };
            inner.active.insert(
                key,
                Vip {
                    slot,
                    listener: listener.to_owned(),
                    indices: HashMap::new(),
                    table: Vec::new(),
                    published: false,
                },
            );
        }
        let vip_state = inner.active.get_mut(&key).expect("inserted above");
        vip_state.listener = listener.to_owned();
        let slot = vip_state.slot;
        let base = slot * MAX_BACKENDS;

        // 1. Give new backends a free index and publish them.
        let leaving: Vec<(IpAddr, u32)> = vip_state
            .indices
            .iter()
            .filter(|(addr, _)| !backends.contains(addr))
            .map(|(addr, index)| (*addr, *index))
            .collect();
        for addr in backends {
            if vip_state.indices.contains_key(addr) {
                continue;
            }
            // Indices of leaving backends stay taken until step 3.
            let used: Vec<u32> = vip_state.indices.values().copied().collect();
            let Some(index) = (0..MAX_BACKENDS).find(|i| !used.contains(i)) else {
                bail!("{vip}: at most {MAX_BACKENDS} backends per XDP listener");
            };
            inner.generation = inner.generation.wrapping_add(1);
            inner
                .backends
                .set(base + index, &backend_entry(*addr, inner.generation), 0)?;
            vip_state.indices.insert(*addr, index);
        }

        // 2. Point the table at the current backends.
        let maglev = Maglev::new(backends.iter().copied(), TABLE_SIZE);
        let table: Vec<u32> = if maglev.table().is_empty() {
            vec![0; TABLE_SIZE as usize]
        } else {
            maglev
                .table()
                .iter()
                .map(|&i| vip_state.indices[&maglev.backends()[i as usize]] + 1)
                .collect()
        };
        let table_base = slot * TABLE_SIZE;
        for (index, &entry) in table.iter().enumerate() {
            if vip_state.table.get(index) != Some(&entry) {
                inner.tables.set(table_base + index as u32, &entry, 0)?;
            }
        }
        vip_state.table = table;

        // 3. Retire backends that left; their index can be reused later.
        for (addr, index) in leaving {
            let mut entry = inner.backends.get(&(base + index), 0)?;
            entry.active = 0;
            inner.backends.set(base + index, &entry, 0)?;
            vip_state.indices.remove(&addr);
        }

        if !vip_state.published {
            // A reused slot must not carry the counters of its previous VIP.
            let cpus = aya::util::nr_cpus()
                .map_err(|(path, err)| anyhow!("{path}: {err}"))?
                .get() as usize;
            inner.stats.set(
                slot,
                PerCpuValues::try_from(vec![VipStats::default(); cpus])?,
                0,
            )?;
            inner.vips.insert(&key, &slot, 0)?;
            vip_state.published = true;
        }
        Ok(())
    }

    /// Stops balancing `vip`; its packets go back to the kernel.
    pub fn remove(&self, vip: SocketAddr, protocol: Protocol) {
        let key = vip_key(vip, protocol);
        let mut inner = self.inner.lock().expect("data plane lock poisoned");
        let Some(state) = inner.active.remove(&key) else {
            return;
        };
        if state.published
            && let Err(err) = inner.vips.remove(&key)
        {
            warn!(%vip, error = %err, "could not remove VIP from the XDP data plane");
        }
        // Flows remembered for this VIP must not survive into the slot's next VIP.
        for index in state.indices.values() {
            let at = state.slot * MAX_BACKENDS + index;
            if let Ok(mut entry) = inner.backends.get(&at, 0) {
                entry.active = 0;
                let _ = inner.backends.set(at, &entry, 0);
            }
        }
    }

    /// Counters of every VIP, summed over CPUs.
    fn stats(&self) -> Vec<(String, VipStats)> {
        let inner = self.inner.lock().expect("data plane lock poisoned");
        inner
            .active
            .values()
            .filter(|vip| vip.published)
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
                                new_flows: sum.new_flows + cpu.new_flows,
                                dropped: sum.dropped + cpu.dropped,
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

fn addr_bytes(addr: IpAddr) -> ([u8; 16], u8) {
    match addr {
        IpAddr::V4(ip) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&ip.octets());
            (bytes, FAMILY_V4)
        }
        IpAddr::V6(ip) => (ip.octets(), FAMILY_V6),
    }
}

fn vip_key(vip: SocketAddr, protocol: Protocol) -> VipKey {
    let (addr, family) = addr_bytes(vip.ip());
    VipKey {
        addr,
        port: vip.port(),
        proto: match protocol {
            Protocol::Tcp => PROTO_TCP,
            Protocol::Udp => PROTO_UDP,
        },
        family,
    }
}

fn backend_entry(addr: IpAddr, generation: u32) -> Backend {
    let (addr, family) = addr_bytes(addr);
    Backend {
        addr,
        generation,
        family,
        active: 1,
        _pad: [0; 2],
    }
}

/// Fills in the settings the config leaves out, from the interface.
fn resolve(config: &XdpConfig) -> Result<Resolved> {
    let (ipv4, ipv6) = interface_addresses(&config.interface)?;
    let source_v4 = match config.source {
        Some(ip) => ip,
        None => ipv4
            .with_context(|| format!("{} has no IPv4 address; set xdp.source", config.interface))?,
    };
    let gateway_mac = match config.gateway_mac {
        Some(mac) => mac,
        None => gateway_mac(&config.interface).with_context(|| {
            format!(
                "could not find the gateway MAC of {}; set xdp.gateway_mac",
                config.interface
            )
        })?,
    };
    Ok(Resolved {
        source_v4,
        source_v6: config.source_v6.or(ipv6),
        gateway_mac,
    })
}

/// The first IPv4 address and the first non-link-local IPv6 address of
/// `interface`.
fn interface_addresses(interface: &str) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `list` with a linked list freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Err(std::io::Error::last_os_error()).context("getifaddrs");
    }
    let mut ipv4 = None;
    let mut ipv6 = None;
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: `entry` is a node of the list returned by `getifaddrs`, and
        // every pointer in it stays valid until `freeifaddrs`.
        unsafe {
            let ifa = &*entry;
            entry = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || CStr::from_ptr(ifa.ifa_name).to_str() != Ok(interface) {
                continue;
            }
            match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET if ipv4.is_none() => {
                    let addr = &*ifa.ifa_addr.cast::<libc::sockaddr_in>();
                    ipv4 = Some(Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)));
                }
                libc::AF_INET6 if ipv6.is_none() => {
                    let addr = &*ifa.ifa_addr.cast::<libc::sockaddr_in6>();
                    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
                    // The outer source must be routable to the backends.
                    if !ip.is_unicast_link_local() && !ip.is_loopback() {
                        ipv6 = Some(ip);
                    }
                }
                _ => {}
            }
        }
    }
    // SAFETY: `list` came from `getifaddrs` and is freed once.
    unsafe { libc::freeifaddrs(list) };
    Ok((ipv4, ipv6))
}

/// MAC address of the IPv4 default gateway reachable through `interface`.
///
/// The gateway comes from the routing table and its MAC from the neighbour
/// table. If the neighbour is not known yet, a datagram to the gateway makes
/// the kernel resolve it.
fn gateway_mac(interface: &str) -> Result<MacAddr> {
    let routes = std::fs::read_to_string("/proc/net/route").context("/proc/net/route")?;
    let gateway = default_gateway(&routes, interface)
        .with_context(|| format!("no IPv4 default route through {interface}"))?;

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut nudged = false;
    loop {
        let neighbours = std::fs::read_to_string("/proc/net/arp").context("/proc/net/arp")?;
        if let Some(mac) = neighbour_mac(&neighbours, gateway, interface) {
            return Ok(mac);
        }
        if Instant::now() >= deadline {
            bail!("gateway {gateway} did not answer ARP on {interface}");
        }
        if !nudged {
            // The discard port: nothing has to listen there, the datagram only
            // makes the kernel look the gateway up.
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            let _ = socket.send_to(&[0], (gateway, 9));
            nudged = true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The gateway of the default route through `interface`, from the text of
/// `/proc/net/route` (addresses are little-endian hex).
fn default_gateway(routes: &str, interface: &str) -> Option<Ipv4Addr> {
    routes.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (iface, destination, gateway, mask) = (
            fields.first()?,
            fields.get(1)?,
            fields.get(2)?,
            fields.get(7)?,
        );
        if *iface != interface || *destination != "00000000" || *mask != "00000000" {
            return None;
        }
        let gateway = u32::from_str_radix(gateway, 16).ok()?;
        (gateway != 0).then(|| Ipv4Addr::from(gateway.swap_bytes()))
    })
}

/// The MAC of `ip` on `interface`, from the text of `/proc/net/arp`, if the
/// entry is complete.
fn neighbour_mac(neighbours: &str, ip: Ipv4Addr, interface: &str) -> Option<MacAddr> {
    neighbours.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (addr, flags, mac, device) = (
            fields.first()?,
            fields.get(2)?,
            fields.get(3)?,
            fields.get(5)?,
        );
        let flags = u32::from_str_radix(flags.trim_start_matches("0x"), 16).ok()?;
        if *addr != ip.to_string() || *device != interface || flags & 0x2 == 0 {
            return None;
        }
        mac.parse().ok()
    })
}

/// One XDP listener's VIP in the data plane. Dropping it stops the sync and
/// removes the VIP.
pub struct Binding {
    dataplane: Arc<DataPlane>,
    vip: SocketAddr,
    protocol: Protocol,
    sync: JoinHandle<()>,
}

impl Binding {
    /// Publishes `vip` and keeps its backends in sync with the healthy
    /// backends of the listener's current route.
    pub fn start(
        dataplane: Arc<DataPlane>,
        vip: SocketAddr,
        protocol: Protocol,
        route: Arc<ArcSwap<Route>>,
        span: Span,
    ) -> Self {
        let task = sync(Arc::clone(&dataplane), vip, protocol, route);
        Self {
            dataplane,
            vip,
            protocol,
            sync: tokio::spawn(task.instrument(span)),
        }
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        self.sync.abort();
        self.dataplane.remove(self.vip, self.protocol);
    }
}

/// Health checks only flip flags on backends, so the sync polls for changes.
async fn sync(
    dataplane: Arc<DataPlane>,
    vip: SocketAddr,
    protocol: Protocol,
    route: Arc<ArcSwap<Route>>,
) {
    let mut ticker = interval(SYNC_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut applied: Option<(String, Vec<IpAddr>)> = None;
    let mut unusable: Vec<SocketAddr> = Vec::new();

    loop {
        ticker.tick().await;
        let route = route.load();
        let serving = serving(&route, vip);
        if serving.unusable != unusable {
            if !serving.unusable.is_empty() {
                // Static backends are checked by the config; these come from
                // Kubernetes, where a dual-stack Service or a targetPort that
                // differs from the VIP port produces them.
                warn!(
                    %vip,
                    skipped = ?serving.unusable,
                    "skipping backends the XDP data plane cannot reach: they need the VIP's address family and port"
                );
            }
            unusable = serving.unusable;
        }
        let wanted = (route.name.to_string(), serving.backends);
        if applied.as_ref() == Some(&wanted) {
            continue;
        }

        let dp = Arc::clone(&dataplane);
        let (name, backends) = wanted.clone();
        // Writing a table is up to TABLE_SIZE syscalls: keep it off the runtime.
        let result =
            tokio::task::spawn_blocking(move || dp.set(&name, vip, protocol, &backends)).await;
        match result {
            Ok(Ok(())) => {
                info!(%vip, ?protocol, backends = wanted.1.len(), "XDP backends updated");
                applied = Some(wanted);
            }
            Ok(Err(err)) => {
                warn!(%vip, error = format!("{err:#}"), "could not update XDP backends");
            }
            Err(err) => warn!(%vip, error = %err, "XDP update task failed"),
        }
    }
}

/// The backends of a route as the XDP data plane sees them.
#[derive(Debug, PartialEq, Eq)]
struct Serving {
    /// Addresses that should get traffic.
    backends: Vec<IpAddr>,
    /// Backends left out because packets cannot reach them as they are.
    unusable: Vec<SocketAddr>,
}

/// Backends that should get traffic: the healthy ones, or every one if none is
/// healthy (fail open, like the proxy).
///
/// Packets are forwarded with their own destination port and inside a header
/// of their own family, so a backend with another family or port than `vip`
/// could never get them: it is left out, whatever its health.
fn serving(route: &Route, vip: SocketAddr) -> Serving {
    let (usable, mut unusable): (Vec<_>, Vec<_>) = route
        .pool
        .backends()
        .iter()
        .partition(|b| b.addr().is_ipv4() == vip.is_ipv4() && b.addr().port() == vip.port());
    let healthy: Vec<IpAddr> = usable
        .iter()
        .filter(|b| b.is_healthy())
        .map(|b| b.addr().ip())
        .collect();
    let mut backends = if healthy.is_empty() {
        usable.iter().map(|b| b.addr().ip()).collect()
    } else {
        healthy
    };
    backends.sort_unstable();
    backends.dedup();
    let mut unusable: Vec<SocketAddr> = unusable.drain(..).map(|b| b.addr()).collect();
    unusable.sort_unstable();
    Serving { backends, unusable }
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

        let series: [Series; 5] = [
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
            (
                "strait_xdp_new_flows",
                "Packets whose flow was not in the flow table and was placed by Maglev",
                |s| s.new_flows,
            ),
            (
                "strait_xdp_dropped",
                "Packets the XDP data plane dropped for another reason: a backend of the wrong address family, or no headroom for the outer header",
                |s| s.dropped,
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

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTES: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0102000A\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t0002000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
eth1\t00000000\t01030A0A\t0003\t0\t0\t100\t00000000\t0\t0\t0
";

    const ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
10.0.2.1         0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0
10.10.3.1        0x1         0x0         00:00:00:00:00:00     *        eth1
";

    #[test]
    fn finds_the_default_gateway_of_an_interface() {
        assert_eq!(
            default_gateway(ROUTES, "eth0"),
            Some(Ipv4Addr::new(10, 0, 2, 1))
        );
        assert_eq!(
            default_gateway(ROUTES, "eth1"),
            Some(Ipv4Addr::new(10, 10, 3, 1))
        );
        assert_eq!(default_gateway(ROUTES, "eth2"), None);
    }

    #[test]
    fn reads_only_complete_neighbour_entries() {
        assert_eq!(
            neighbour_mac(ARP, Ipv4Addr::new(10, 0, 2, 1), "eth0").map(|m| m.to_string()),
            Some("aa:bb:cc:dd:ee:01".to_owned())
        );
        // Incomplete entry (flags 0x0): still resolving.
        assert_eq!(
            neighbour_mac(ARP, Ipv4Addr::new(10, 10, 3, 1), "eth1"),
            None
        );
        // Right address, wrong interface.
        assert_eq!(neighbour_mac(ARP, Ipv4Addr::new(10, 0, 2, 1), "eth1"), None);
    }

    fn route(backends: &[&str]) -> Route {
        let pool = crate::Pool::new(
            backends.iter().map(|b| b.parse().unwrap()),
            crate::Algorithm::RoundRobin,
        );
        Route::new(
            "web",
            Arc::new(pool),
            crate::ProxyConfig::default(),
            Arc::new(crate::Metrics::default()),
            tokio_util::task::TaskTracker::new(),
        )
    }

    fn ips(addrs: &[&str]) -> Vec<IpAddr> {
        addrs.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn serves_healthy_backends_and_fails_open() {
        let vip = "10.0.0.10:80".parse().unwrap();
        let route = route(&["10.0.3.3:80", "10.0.3.2:80"]);
        assert_eq!(
            serving(&route, vip).backends,
            ips(&["10.0.3.2", "10.0.3.3"])
        );

        route.pool.backends()[0].set_healthy(false);
        assert_eq!(serving(&route, vip).backends, ips(&["10.0.3.2"]));

        route.pool.backends()[1].set_healthy(false);
        assert_eq!(
            serving(&route, vip).backends,
            ips(&["10.0.3.2", "10.0.3.3"])
        );
    }

    #[test]
    fn leaves_out_backends_of_another_family_or_port() {
        // What discovery hands over for a dual-stack Service, or one whose
        // targetPort is not the VIP port.
        let route = route(&["10.0.3.2:80", "[fd00::2]:80", "10.0.3.3:8080"]);

        let v4 = serving(&route, "10.0.0.10:80".parse().unwrap());
        assert_eq!(v4.backends, ips(&["10.0.3.2"]));
        assert_eq!(
            v4.unusable,
            vec![
                "10.0.3.3:8080".parse().unwrap(),
                "[fd00::2]:80".parse().unwrap()
            ]
        );

        let v6 = serving(&route, "[fd00::10]:80".parse().unwrap());
        assert_eq!(v6.backends, ips(&["fd00::2"]));
        assert_eq!(v6.unusable.len(), 2);

        // Failing open never brings an unusable backend back.
        route.pool.backends()[0].set_healthy(false);
        assert_eq!(
            serving(&route, "10.0.0.10:80".parse().unwrap()).backends,
            ips(&["10.0.3.2"])
        );
    }

    #[test]
    fn keys_carry_the_family_and_protocol() {
        let v4 = vip_key("10.0.0.10:53".parse().unwrap(), Protocol::Udp);
        assert_eq!(&v4.addr[..4], &[10, 0, 0, 10]);
        assert_eq!(&v4.addr[4..], &[0; 12]);
        assert_eq!((v4.family, v4.proto, v4.port), (FAMILY_V4, PROTO_UDP, 53));

        let v6 = vip_key("[fd00::10]:80".parse().unwrap(), Protocol::Tcp);
        assert_eq!(v6.addr, "fd00::10".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!((v6.family, v6.proto), (FAMILY_V6, PROTO_TCP));
    }
}
