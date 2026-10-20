#![no_main]
//! Fuzz the CTRL_GOSSIP payload parser (🔴 on-wire, network-reachable). Mixed-version
//! meshes depend on it tolerating old/garbage lines — it must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lattice_meshrun::decode_gossip(data);
});
