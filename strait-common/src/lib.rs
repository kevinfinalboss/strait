//! Types shared by the XDP program (`strait-ebpf`) and the userspace control
//! plane (`strait`, feature `xdp`). Both sides must agree on these layouts
//! byte for byte, hence `#[repr(C)]` and explicit padding.
//!
//! Addresses are stored as 16 bytes in network order: IPv6 as is, IPv4 in the
//! first 4 bytes with the rest zero. Ports are in host order.

#![no_std]

/// Slots in each VIP's Maglev table. Prime, as Maglev requires.
pub const TABLE_SIZE: u32 = 65_537;

/// Most VIPs one data plane serves; each gets a `TABLE_SIZE` region in `TABLES`
/// (256 KiB each) and a `MAX_BACKENDS` region in `BACKENDS`.
pub const MAX_VIPS: u32 = 16;

/// Most backends behind one VIP.
pub const MAX_BACKENDS: u32 = 256;

/// Flows remembered by the LRU flow table. When it is full, the least recently
/// used flow is forgotten and goes back to the Maglev table on its next packet.
pub const MAX_FLOWS: u32 = 262_144;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const FAMILY_V4: u8 = 4;
pub const FAMILY_V6: u8 = 6;

/// A virtual service: packets to this address, port and protocol are balanced.
/// Key of the `VIPS` map, whose value is the VIP's slot in `0..MAX_VIPS`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VipKey {
    pub addr: [u8; 16],
    pub port: u16,
    pub proto: u8,
    pub family: u8,
}

/// One backend of a VIP, at `BACKENDS[slot * MAX_BACKENDS + index]`.
///
/// Indices are stable while a backend stays, so the Maglev table and the flow
/// table can refer to them. `generation` changes whenever an index is given to
/// a new backend, so a remembered flow never follows a reused index to the
/// wrong backend.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Backend {
    pub addr: [u8; 16],
    pub generation: u32,
    pub family: u8,
    /// 0 once the backend left the VIP: remembered flows to it are rebalanced.
    pub active: u8,
    pub _pad: [u8; 2],
}

/// A flow's 5-tuple, key of the `FLOWS` LRU map.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

/// Where a flow was sent: a `BACKENDS` index and the generation it had.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flow {
    pub backend: u32,
    pub generation: u32,
}

/// Data plane settings, the only entry of the `SETTINGS` map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Outer source address for IPv4 backends (IP-in-IP).
    pub source_v4: [u8; 4],
    /// Outer source address for IPv6 backends (IPv6-in-IPv6). Zero if unset.
    pub source_v6: [u8; 16],
    /// Next hop for encapsulated packets, which leave through the interface
    /// they arrived on.
    pub gateway_mac: [u8; 6],
    pub _pad: [u8; 2],
}

/// Counters of one VIP, in the per-CPU `STATS` map indexed by VIP slot.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VipStats {
    /// Packets encapsulated and sent to a backend.
    pub packets: u64,
    /// Bytes of those packets as received, before encapsulation.
    pub bytes: u64,
    /// Packets dropped because the VIP had no backend.
    pub no_backend: u64,
    /// Packets whose flow was not in the flow table and went through Maglev.
    pub new_flows: u64,
    /// Packets dropped for another reason: the backend has another address
    /// family than the packet, or there was no headroom for the outer header.
    pub dropped: u64,
}

#[cfg(feature = "user")]
mod pod {
    // SAFETY: plain `#[repr(C)]` integers and arrays with explicit padding, so
    // every bit pattern is valid and there are no uninitialized bytes.
    unsafe impl aya::Pod for super::VipKey {}
    unsafe impl aya::Pod for super::Backend {}
    unsafe impl aya::Pod for super::FlowKey {}
    unsafe impl aya::Pod for super::Flow {}
    unsafe impl aya::Pod for super::Settings {}
    unsafe impl aya::Pod for super::VipStats {}
}

/// Hash of a flow, from which its Maglev slot is `flow_hash % TABLE_SIZE`.
/// Every packet of a flow hashes the same.
#[inline(always)]
pub fn flow_hash(flow: &FlowKey) -> u32 {
    let mut h: u32 = 0x9e37_79b9;
    let mut i = 0;
    while i < 16 {
        let src = u32::from_ne_bytes([
            flow.src[i],
            flow.src[i + 1],
            flow.src[i + 2],
            flow.src[i + 3],
        ]);
        let dst = u32::from_ne_bytes([
            flow.dst[i],
            flow.dst[i + 1],
            flow.dst[i + 2],
            flow.dst[i + 3],
        ]);
        h = mix(h, src);
        h = mix(h, dst);
        i += 4;
    }
    let ports = (u32::from(flow.src_port) << 16) | u32::from(flow.dst_port);
    h = mix(h, ports);
    h = mix(h, u32::from(flow.proto));
    // murmur3's finalizer, so every input bit affects every output bit.
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}

#[inline(always)]
fn mix(h: u32, value: u32) -> u32 {
    (h ^ value
        .wrapping_mul(0xcc9e_2d51)
        .rotate_left(15)
        .wrapping_mul(0x1b87_3593))
    .rotate_left(13)
    .wrapping_mul(5)
    .wrapping_add(0xe654_6b64)
}
