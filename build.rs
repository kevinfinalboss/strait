//! With the `xdp` feature, compiles `strait-ebpf` for the BPF target so the
//! binary can embed it. Set `AYA_BUILD_SKIP=1` to skip that, for example to
//! run clippy on a machine without the BPF toolchain.

fn main() {
    #[cfg(feature = "xdp")]
    {
        let package = aya_build::Package {
            name: "strait-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/strait-ebpf"),
            ..Default::default()
        };
        if let Err(err) = aya_build::build_ebpf([package], aya_build::Toolchain::default()) {
            panic!("could not build the XDP program: {err:#}");
        }
    }
}
