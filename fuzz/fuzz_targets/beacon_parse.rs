#![no_main]
//! Fuzz the LAN multicast beacon parser (network-reachable from the local segment).
//! Must never panic on arbitrary input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lattice_meshrun::lan::beacon_parse(data);
});
