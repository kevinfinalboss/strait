//! Attaches an XDP program that passes every packet to an interface, and keeps
//! it attached until killed.
//!
//! Test topologies built from veth pairs need it on the peer of the interface
//! strait runs on: a veth only delivers frames sent with `XDP_TX` when its peer
//! has an XDP program. See demo/xdp.sh.
//!
//!     sudo target/release/examples/xdp_pass <interface>

use std::ffi::CString;

use anyhow::{Context, Result};
use aya::Ebpf;
use aya::programs::{Xdp, XdpMode};

fn main() -> Result<()> {
    let interface = std::env::args()
        .nth(1)
        .context("usage: xdp_pass <interface>")?;
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/strait-xdp"
    )))?;
    let program: &mut Xdp = ebpf
        .program_mut("strait_pass")
        .context("strait_pass missing from the object")?
        .try_into()?;
    program.load()?;
    program
        .attach(&CString::new(interface.as_str())?, XdpMode::Driver)
        .with_context(|| format!("could not attach to {interface}"))?;
    println!("XDP_PASS attached to {interface}");

    // The program stays attached while `ebpf` is alive.
    loop {
        std::thread::park();
    }
}
