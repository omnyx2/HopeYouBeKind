//! Kademlia's XOR distance metric over 256-bit keys.
//!
//! A key is a node id (32 bytes). The "distance" between two keys is their
//! bitwise XOR, interpreted as a 256-bit big-endian number; closeness in this
//! metric is what the whole routing structure is organized around.

use std::cmp::Ordering;

/// A 256-bit Kademlia key (a node id, or the hash a value is stored under).
pub type Key = [u8; 32];

/// XOR of two keys — their distance, as a byte array comparable big-endian.
pub fn xor(a: &Key, b: &Key) -> Key {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i];
    }
    d
}

/// Order two keys by their distance to `target` (closest first).
pub fn by_distance(target: &Key, a: &Key, b: &Key) -> Ordering {
    // Lexicographic byte comparison of the XOR == big-endian numeric comparison.
    xor(a, target).cmp(&xor(b, target))
}

/// The bucket index for `other` relative to `self_id`: the number of leading
/// zero bits in their XOR distance (0..=255). Closer ids share a longer prefix
/// and land in higher-index buckets.
pub fn bucket_index(self_id: &Key, other: &Key) -> usize {
    let d = xor(self_id, other);
    let mut zeros = 0usize;
    for &byte in d.iter() {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros() as usize;
            break;
        }
    }
    zeros.min(255)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Key {
        [byte; 32]
    }

    #[test]
    fn distance_to_self_is_zero_and_minimal() {
        let k = key(0xAB);
        assert_eq!(xor(&k, &k), [0u8; 32]);
        // self is closer to itself than any other node
        assert_eq!(by_distance(&k, &k, &key(0x01)), Ordering::Less);
    }

    #[test]
    fn orders_by_xor_distance() {
        let target = [0u8; 32];
        let near = {
            let mut k = [0u8; 32];
            k[31] = 1;
            k
        }; // distance 1
        let far = {
            let mut k = [0u8; 32];
            k[0] = 1;
            k
        }; // distance 2^248
        assert_eq!(by_distance(&target, &near, &far), Ordering::Less);
    }

    #[test]
    fn bucket_index_reflects_shared_prefix() {
        let me = [0u8; 32];
        // Differs in the very first bit → distance has 0 leading zeros.
        let mut far = [0u8; 32];
        far[0] = 0x80;
        assert_eq!(bucket_index(&me, &far), 0);
        // Differs only in the last bit → 255 leading zero bits.
        let mut near = [0u8; 32];
        near[31] = 0x01;
        assert_eq!(bucket_index(&me, &near), 255);
    }
}
