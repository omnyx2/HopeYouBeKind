#![no_main]
//! Fuzz the datagram header parser. Must never panic on arbitrary input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = lattice_proto::wire::decode(data);
});
