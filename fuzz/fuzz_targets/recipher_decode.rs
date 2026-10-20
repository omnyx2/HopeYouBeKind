#![no_main]
//! Fuzz the CTRL_RECIPHER payload parser (🔴 on-wire, network-reachable). Must never
//! panic on arbitrary input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lattice_meshrun::decode_recipher(data);
});
