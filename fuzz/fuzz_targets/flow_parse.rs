#![no_main]
//! Fuzz the overlay IPv4 5-tuple parser feeding the traffic monitor. Must never panic
//! on arbitrary (decrypted but attacker-shaped) packet bytes.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lattice_meshrun::parse_flow(data);
});
