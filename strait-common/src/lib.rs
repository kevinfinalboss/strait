//! Types shared by the XDP program (`strait-ebpf`) and the userspace control
//! plane (`strait`, feature `xdp`). Both sides must agree on these layouts
//! byte for byte, hence `#[repr(C)]` and explicit padding.
//!
//! Addresses and ports are stored in host byte order: userspace writes
//! `u32::from(Ipv4Addr)`, and the XDP program converts from the wire once.

#![no_std]

/// Slots in each VIP's Maglev table. Prime, as Maglev requires.
pub const TABLE_SIZE: u32 = 65_537;

/// Most VIPs one data plane serves; each gets a `TABLE_SIZE` region in `TABLES`
/// (256 KiB each).
pub const MAX_VIPS: u32 = 16;

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// A virtual service: packets to this address, port and protocol are balanced.
/// Key of the `VIPS` map, whose value is the VIP's slot in `0..MAX_VIPS`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VipKey {
    pub addr: u32,
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// Data plane settings, the only entry of the `SETTINGS` map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Source address of the outer IP-in-IP header.
    pub source: u32,
    /// Next hop for encapsulated packets, which are sent back out of the
    /// interface they arrived on.
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
}

#[cfg(feature = "user")]
mod pod {
    // SAFETY: plain `#[repr(C)]` integers and arrays with explicit padding, so
    // every bit pattern is valid and there are no uninitialized bytes.
    unsafe impl aya::Pod for super::VipKey {}
    unsafe impl aya::Pod for super::Settings {}
    unsafe impl aya::Pod for super::VipStats {}
}

/// Hash of a flow's 5-tuple, from which the Maglev slot is
/// `flow_hash % TABLE_SIZE`. Every packet of a flow hashes the same, so a flow
/// stays on one backend while the table does not change.
#[inline(always)]
pub fn flow_hash(src: u32, dst: u32, src_port: u16, dst_port: u16, proto: u8) -> u32 {
    let ports = (u32::from(src_port) << 16) | u32::from(dst_port);
    let mut h = src.wrapping_mul(0x9e37_79b1);
    h ^= dst.rotate_left(13).wrapping_mul(0x85eb_ca77);
    h ^= ports.wrapping_mul(0xc2b2_ae3d);
    h ^= u32::from(proto);
    // murmur3's finalizer, so every input bit affects every output bit.
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^ (h >> 16)
}
