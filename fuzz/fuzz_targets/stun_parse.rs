#![no_main]
//! Fuzz the STUN response parser against arbitrary bytes from the network.
//! Must never panic, slice out of bounds, or loop forever.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lattice_net::nat::parse_mapped_address(data);
});
