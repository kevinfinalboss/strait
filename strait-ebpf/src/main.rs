//! strait's XDP data plane: Maglev load balancing with direct server return.
//!
//! For every IPv4 TCP or UDP packet addressed to a VIP, the program picks a
//! backend from the VIP's Maglev table by the flow's 5-tuple, wraps the packet
//! in an outer IPv4 header addressed to that backend (IP-in-IP) and sends it
//! back out of the interface it came in on, towards the gateway. The backend
//! decapsulates it and answers the client directly, so replies never come
//! back through the load balancer. Everything else is passed to the kernel
//! untouched.
//!
//! There is no connection tracking: a flow stays on its backend because its
//! hash and the table stay the same. Userspace keeps the tables up to date.

#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::bindings::xdp_action::{XDP_DROP, XDP_PASS, XDP_TX};
use aya_ebpf::helpers::generated::bpf_xdp_adjust_head;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use aya_ebpf::programs::XdpContext;
use strait_common::{
    MAX_VIPS, PROTO_TCP, PROTO_UDP, Settings, TABLE_SIZE, VipKey, VipStats, flow_hash,
};

/// VIP to its slot in `0..MAX_VIPS`.
#[map]
static VIPS: HashMap<VipKey, u32> = HashMap::with_max_entries(MAX_VIPS, 0);

/// One Maglev table of `TABLE_SIZE` backend addresses per VIP slot, back to
/// back. 0 means the VIP has no backend.
#[map]
static TABLES: Array<u32> = Array::with_max_entries(MAX_VIPS * TABLE_SIZE, 0);

#[map]
static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);

#[map]
static STATS: PerCpuArray<VipStats> = PerCpuArray::with_max_entries(MAX_VIPS, 0);

const ETH_LEN: usize = mem::size_of::<EthHdr>();
const IP_LEN: usize = mem::size_of::<Ipv4Hdr>();
const ETH_P_IP: [u8; 2] = [0x08, 0x00];
const IPPROTO_IPIP: u8 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    ether_type: [u8; 2],
}

/// IPv4 header without options. Multi-byte fields are kept as big-endian bytes.
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
fn balance(ctx: &XdpContext) -> u32 {
    let Some(eth) = ptr_at::<EthHdr>(ctx, 0) else {
        return XDP_PASS;
    };
    // SAFETY: `ptr_at` checked that the header is inside the packet.
    let eth = unsafe { *eth };
    if eth.ether_type != ETH_P_IP {
        return XDP_PASS;
    }

    let Some(ip) = ptr_at::<Ipv4Hdr>(ctx, ETH_LEN) else {
        return XDP_PASS;
    };
    // SAFETY: as above.
    let ip = unsafe { *ip };
    // Only IPv4 without options, so the ports are at a fixed offset. Fragments
    // other than the first have no ports, and the first one alone would hash
    // differently from the rest: leave all of them to the kernel.
    if ip.version_ihl != 0x45 || u16::from_be_bytes(ip.frag) & 0x3fff != 0 {
        return XDP_PASS;
    }
    if ip.proto != PROTO_TCP && ip.proto != PROTO_UDP {
        return XDP_PASS;
    }

    // TCP and UDP both start with the source and destination ports.
    let Some(ports) = ptr_at::<[u8; 4]>(ctx, ETH_LEN + IP_LEN) else {
        return XDP_PASS;
    };
    // SAFETY: as above.
    let ports = unsafe { *ports };
    let src_port = u16::from_be_bytes([ports[0], ports[1]]);
    let dst_port = u16::from_be_bytes([ports[2], ports[3]]);
    let src = u32::from_be_bytes(ip.src);
    let dst = u32::from_be_bytes(ip.dst);

    let key = VipKey {
        addr: dst,
        port: dst_port,
        proto: ip.proto,
        _pad: 0,
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

    let hash = flow_hash(src, dst, src_port, dst_port, ip.proto);
    let backend = match TABLES.get(slot * TABLE_SIZE + hash % TABLE_SIZE) {
        Some(&backend) if backend != 0 => backend,
        _ => {
            // SAFETY: per-CPU value, so nothing else writes it concurrently.
            unsafe { (*stats).no_backend += 1 };
            return XDP_DROP;
        }
    };
    let Some(&settings) = SETTINGS.get(0) else {
        return XDP_PASS;
    };

    let received = (ctx.data_end() - ctx.data()) as u64;
    let inner_len = u16::from_be_bytes(ip.tot_len);

    // Make room for the outer IP header in front of the packet.
    // SAFETY: plain helper call on the program's own context.
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(IP_LEN as i32)) } != 0 {
        return XDP_DROP;
    }
    // The packet moved: every pointer has to be checked again.
    let (Some(new_eth), Some(outer)) = (ptr_at::<EthHdr>(ctx, 0), ptr_at::<Ipv4Hdr>(ctx, ETH_LEN))
    else {
        return XDP_DROP;
    };

    let mut header = Ipv4Hdr {
        version_ihl: 0x45,
        tos: ip.tos,
        tot_len: inner_len.wrapping_add(IP_LEN as u16).to_be_bytes(),
        id: [0, 0],
        frag: [0, 0],
        ttl: 64,
        proto: IPPROTO_IPIP,
        check: [0, 0],
        src: settings.source.to_be_bytes(),
        dst: backend.to_be_bytes(),
    };
    header.check = checksum(&header).to_be_bytes();

    // SAFETY: both pointers were bounds-checked after the head moved, and the
    // per-CPU stats value is ours alone.
    unsafe {
        *new_eth = EthHdr {
            dst: settings.gateway_mac,
            // The packet was addressed to this interface, so its destination
            // MAC is ours.
            src: eth.dst,
            ether_type: ETH_P_IP,
        };
        *outer = header;
        (*stats).packets += 1;
        (*stats).bytes += received;
    }
    XDP_TX
}

/// Internet checksum of an IPv4 header whose checksum field is zero.
#[inline(always)]
fn checksum(header: &Ipv4Hdr) -> u16 {
    // SAFETY: `Ipv4Hdr` is 20 bytes of `u8`s with no padding.
    let bytes: &[u8; IP_LEN] = unsafe { &*(header as *const Ipv4Hdr).cast() };
    let mut sum = 0u32;
    let mut i = 0;
    while i < IP_LEN {
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
