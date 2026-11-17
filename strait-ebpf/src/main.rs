//! strait's XDP data plane: Maglev load balancing with direct server return.
//!
//! For every TCP or UDP packet addressed to a VIP, the program picks a backend,
//! wraps the packet in an outer header addressed to it (IP-in-IP for IPv4,
//! IPv6-in-IPv6 for IPv6) and sends it back out of the interface it came in
//! on, towards the gateway. The backend decapsulates it and answers the client
//! directly, so replies never come back through the load balancer. Everything
//! else is passed to the kernel untouched.
//!
//! A flow's first packet picks its backend from the VIP's Maglev table; the
//! choice is remembered in an LRU flow table, so later packets of the flow stay
//! on that backend even when the table changes. A remembered backend that left
//! the VIP is not used: the flow goes back to the table.

#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS, XDP_TX};
use aya_ebpf::helpers::generated::bpf_xdp_adjust_head;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{Array, HashMap, LruHashMap, PerCpuArray};
use aya_ebpf::programs::XdpContext;
use strait_common::{
    Backend, FAMILY_V4, FAMILY_V6, Flow, FlowKey, MAX_BACKENDS, MAX_FLOWS, MAX_VIPS, PROTO_TCP,
    PROTO_UDP, Settings, TABLE_SIZE, VipKey, VipStats, flow_hash,
};

/// VIP to its slot in `0..MAX_VIPS`.
#[map]
static VIPS: HashMap<VipKey, u32> = HashMap::with_max_entries(MAX_VIPS, 0);

/// One Maglev table of `TABLE_SIZE` entries per VIP slot, back to back. An
/// entry is a backend index within the VIP plus one; 0 means no backend.
#[map]
static TABLES: Array<u32> = Array::with_max_entries(MAX_VIPS * TABLE_SIZE, 0);

/// `MAX_BACKENDS` backends per VIP slot, back to back.
#[map]
static BACKENDS: Array<Backend> = Array::with_max_entries(MAX_VIPS * MAX_BACKENDS, 0);

/// Backend chosen for each recent flow.
#[map]
static FLOWS: LruHashMap<FlowKey, Flow> = LruHashMap::with_max_entries(MAX_FLOWS, 0);

#[map]
static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);

#[map]
static STATS: PerCpuArray<VipStats> = PerCpuArray::with_max_entries(MAX_VIPS, 0);

const ETH_LEN: usize = mem::size_of::<EthHdr>();
const IPV4_LEN: usize = mem::size_of::<Ipv4Hdr>();
const IPV6_LEN: usize = mem::size_of::<Ipv6Hdr>();
const ETH_P_IP: [u8; 2] = [0x08, 0x00];
const ETH_P_IPV6: [u8; 2] = [0x86, 0xdd];
const IPPROTO_IPIP: u8 = 4;
const IPPROTO_IPV6: u8 = 41;

#[repr(C)]
#[derive(Clone, Copy)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    ether_type: [u8; 2],
}

/// IPv4 header without options. Multi-byte fields are big-endian bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    tot_len: [u8; 2],
    id: [u8; 2],
    frag: [u8; 2],
    ttl: u8,
    proto: u8,
    check: [u8; 2],
    src: [u8; 4],
    dst: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ipv6Hdr {
    /// Version, traffic class and flow label.
    vtc_flow: [u8; 4],
    payload_len: [u8; 2],
    next_header: u8,
    hop_limit: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

/// What the program needs from a packet it may balance.
struct Packet {
    family: u8,
    flow: FlowKey,
    /// Length of the IP packet, headers included.
    ip_len: u16,
    /// First two bytes of the IP header, to carry the TOS / traffic class over.
    head: [u8; 2],
    /// Destination MAC of the packet, which is this interface's.
    our_mac: [u8; 6],
}

#[xdp]
pub fn strait_xdp(ctx: XdpContext) -> u32 {
    balance(&ctx)
}

/// Passes every packet. Only for test topologies built from veth pairs: a veth
/// hands frames sent with `XDP_TX` to its peer only if the peer runs an XDP
/// program. Physical NICs have no such requirement.
#[xdp]
pub fn strait_pass(_ctx: XdpContext) -> u32 {
    XDP_PASS
}

/// A pointer to a `T` at `offset`, if the packet is long enough. The bounds
/// check is what lets the verifier accept the access.
#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let start = ctx.data();
    if start + offset + mem::size_of::<T>() > ctx.data_end() {
        return None;
    }
    Some((start + offset) as *mut T)
}

#[inline(always)]
fn v4_addr(addr: [u8; 4]) -> [u8; 16] {
    let [a, b, c, d] = addr;
    [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// Source and destination ports at `offset`; TCP and UDP both start with them.
#[inline(always)]
fn ports(ctx: &XdpContext, offset: usize) -> Option<(u16, u16)> {
    let ports = ptr_at::<[u8; 4]>(ctx, offset)?;
    // SAFETY: `ptr_at` checked that the bytes are inside the packet.
    let ports = unsafe { *ports };
    Some((
        u16::from_be_bytes([ports[0], ports[1]]),
        u16::from_be_bytes([ports[2], ports[3]]),
    ))
}

/// Parses an IPv4 or IPv6 TCP or UDP packet. `None` for anything else, which
/// the kernel handles as usual.
#[inline(always)]
fn parse(ctx: &XdpContext) -> Option<Packet> {
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    // SAFETY: `ptr_at` checked that the header is inside the packet.
    let eth = unsafe { *eth };

    if eth.ether_type == ETH_P_IP {
        let ip = ptr_at::<Ipv4Hdr>(ctx, ETH_LEN)?;
        // SAFETY: as above.
        let ip = unsafe { *ip };
        // Only IPv4 without options, so the ports are at a fixed offset.
        // Fragments other than the first have no ports, and the first one
        // alone would hash differently from the rest: leave all to the kernel.
        if ip.version_ihl != 0x45 || u16::from_be_bytes(ip.frag) & 0x3fff != 0 {
            return None;
        }
        if ip.proto != PROTO_TCP && ip.proto != PROTO_UDP {
            return None;
        }
        let (src_port, dst_port) = ports(ctx, ETH_LEN + IPV4_LEN)?;
        return Some(Packet {
            family: FAMILY_V4,
            flow: FlowKey {
                src: v4_addr(ip.src),
                dst: v4_addr(ip.dst),
                src_port,
                dst_port,
                proto: ip.proto,
                _pad: [0; 3],
            },
            ip_len: u16::from_be_bytes(ip.tot_len),
            head: [ip.version_ihl, ip.tos],
            our_mac: eth.dst,
        });
    }

    if eth.ether_type == ETH_P_IPV6 {
        let ip = ptr_at::<Ipv6Hdr>(ctx, ETH_LEN)?;
        // SAFETY: as above.
        let ip = unsafe { *ip };
        // Extension headers would move the ports; leave such packets alone.
        if ip.next_header != PROTO_TCP && ip.next_header != PROTO_UDP {
            return None;
        }
        let (src_port, dst_port) = ports(ctx, ETH_LEN + IPV6_LEN)?;
        return Some(Packet {
            family: FAMILY_V6,
            flow: FlowKey {
                src: ip.src,
                dst: ip.dst,
                src_port,
                dst_port,
                proto: ip.next_header,
                _pad: [0; 3],
            },
            ip_len: u16::from_be_bytes(ip.payload_len).wrapping_add(IPV6_LEN as u16),
            head: [ip.vtc_flow[0], ip.vtc_flow[1]],
            our_mac: eth.dst,
        });
    }
    None
}

/// The backend for `flow` on VIP `slot`: the remembered one if it is still a
/// backend of the VIP, otherwise a new pick from the Maglev table.
#[inline(always)]
fn choose(slot: u32, flow: &FlowKey, stats: *mut VipStats) -> Option<Backend> {
    // SAFETY: the value is copied out right away.
    if let Some(&known) = unsafe { FLOWS.get(flow) }
        && known.backend / MAX_BACKENDS == slot
        && let Some(&backend) = BACKENDS.get(known.backend)
        && backend.active == 1
        && backend.generation == known.generation
    {
        return Some(backend);
    }

    // SAFETY: per-CPU value, so nothing else writes it concurrently.
    unsafe { (*stats).new_flows += 1 };
    let entry = *TABLES.get(slot * TABLE_SIZE + flow_hash(flow) % TABLE_SIZE)?;
    if entry == 0 || entry > MAX_BACKENDS {
        return None;
    }
    let index = slot * MAX_BACKENDS + (entry - 1);
    let backend = *BACKENDS.get(index)?;
    if backend.active != 1 {
        return None;
    }
    let remembered = Flow {
        backend: index,
        generation: backend.generation,
    };
    // A full table evicts the least recently used flow; a failed insert only
    // means this flow is looked up in the Maglev table again next time.
    let _ = FLOWS.insert(flow, &remembered, 0);
    Some(backend)
}

#[inline(always)]
fn balance(ctx: &XdpContext) -> u32 {
    let Some(packet) = parse(ctx) else {
        return XDP_PASS;
    };
    let key = VipKey {
        addr: packet.flow.dst,
        port: packet.flow.dst_port,
        proto: packet.flow.proto,
        family: packet.family,
    };
    // SAFETY: the value is a plain u32 that is copied out right away.
    let Some(&slot) = (unsafe { VIPS.get(&key) }) else {
        return XDP_PASS;
    };
    if slot >= MAX_VIPS {
        return XDP_PASS;
    }
    let Some(stats) = STATS.get_ptr_mut(slot) else {
        return XDP_PASS;
    };
    let Some(backend) = choose(slot, &packet.flow, stats) else {
        // SAFETY: per-CPU value, so nothing else writes it concurrently.
        unsafe { (*stats).no_backend += 1 };
        return XDP_DROP;
    };
    if backend.family != packet.family {
        // Userspace never puts such a backend in a VIP's table; count it all
        // the same, so a drop here never goes unseen.
        // SAFETY: per-CPU value, so nothing else writes it concurrently.
        unsafe { (*stats).dropped += 1 };
        return XDP_DROP;
    }
    let Some(&settings) = SETTINGS.get(0) else {
        return XDP_PASS;
    };

    let received = (ctx.data_end() - ctx.data()) as u64;
    let sent = if packet.family == FAMILY_V4 {
        encap_v4(ctx, &packet, &backend, &settings)
    } else {
        encap_v6(ctx, &packet, &backend, &settings)
    };
    if !sent {
        // SAFETY: per-CPU value, so nothing else writes it concurrently.
        unsafe { (*stats).dropped += 1 };
        return XDP_DROP;
    }
    // SAFETY: per-CPU value, so nothing else writes it concurrently.
    unsafe {
        (*stats).packets += 1;
        (*stats).bytes += received;
    }
    XDP_TX
}

/// Grows the packet by one `T` at the front and writes a fresh Ethernet header
/// there, addressed to the gateway. Returns where the outer IP header goes,
/// already bounds-checked.
#[inline(always)]
fn make_room<T>(
    ctx: &XdpContext,
    packet: &Packet,
    settings: &Settings,
    ether_type: [u8; 2],
) -> Option<*mut T> {
    // SAFETY: plain helper call on the program's own context.
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(mem::size_of::<T>() as i32)) } != 0 {
        return None;
    }
    // The packet moved: every pointer has to be checked again.
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    let outer = ptr_at::<T>(ctx, ETH_LEN)?;
    // SAFETY: bounds-checked just above.
    unsafe {
        *eth = EthHdr {
            dst: settings.gateway_mac,
            src: packet.our_mac,
            ether_type,
        };
    }
    Some(outer)
}

#[inline(always)]
fn encap_v4(ctx: &XdpContext, packet: &Packet, backend: &Backend, settings: &Settings) -> bool {
    let Some(outer) = make_room::<Ipv4Hdr>(ctx, packet, settings, ETH_P_IP) else {
        return false;
    };
    let mut header = Ipv4Hdr {
        version_ihl: 0x45,
        tos: packet.head[1],
        tot_len: packet.ip_len.wrapping_add(IPV4_LEN as u16).to_be_bytes(),
        id: [0, 0],
        frag: [0, 0],
        ttl: 64,
        proto: IPPROTO_IPIP,
        check: [0, 0],
        src: settings.source_v4,
        dst: [
            backend.addr[0],
            backend.addr[1],
            backend.addr[2],
            backend.addr[3],
        ],
    };
    header.check = checksum(&header).to_be_bytes();
    // SAFETY: bounds-checked by `make_room`.
    unsafe { *outer = header };
    true
}

#[inline(always)]
fn encap_v6(ctx: &XdpContext, packet: &Packet, backend: &Backend, settings: &Settings) -> bool {
    let Some(outer) = make_room::<Ipv6Hdr>(ctx, packet, settings, ETH_P_IPV6) else {
        return false;
    };
    // SAFETY: bounds-checked by `make_room`.
    unsafe {
        *outer = Ipv6Hdr {
            // Version 6 and the inner traffic class; no flow label.
            vtc_flow: [packet.head[0], packet.head[1] & 0xf0, 0, 0],
            payload_len: packet.ip_len.to_be_bytes(),
            next_header: IPPROTO_IPV6,
            hop_limit: 64,
            src: settings.source_v6,
            dst: backend.addr,
        };
    }
    true
}

/// Internet checksum of an IPv4 header whose checksum field is zero.
#[inline(always)]
fn checksum(header: &Ipv4Hdr) -> u16 {
    // SAFETY: `Ipv4Hdr` is 20 bytes of `u8`s with no padding.
    let bytes: &[u8; IPV4_LEN] = unsafe { &*(header as *const Ipv4Hdr).cast() };
    let mut sum = 0u32;
    let mut i = 0;
    while i < IPV4_LEN {
        sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
        i += 2;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
