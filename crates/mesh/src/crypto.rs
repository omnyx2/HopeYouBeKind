//! v2 per-mesh symmetric crypto (docs/MESH_V2.md §4–§5).
//!
//! Each mesh encrypts its frames under an **epoch key** derived from that epoch's
//! shared secret + the monotonic epoch number (§5). The default suite is
//! ChaCha20-Poly1305 AEAD; the research **manifold / time-window** cipher will be a
//! second suite, selected by the charter's `initial_cipher`.
//!
//! The epoch is mixed into key derivation, so a re-cipher (new epoch with a fresh
//! secret) yields an unrelated key: an expelled node's old-epoch key can't read the
//! new traffic. Replay protection and the nonce counter live in the data plane; the
//! header is passed here as AEAD associated data so tampering is detected.

use std::time::{SystemTime, UNIX_EPOCH};

use blake2::{Blake2s256, Digest};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

/// Bytes the AEAD appends (Poly1305 tag).
pub const TAG_LEN: usize = 16;

/// A mesh's AEAD bound to one epoch.
pub struct MeshCipher {
    epoch: u64,
    cipher: ChaCha20Poly1305,
}

impl MeshCipher {
    /// Build the cipher for `epoch` from that epoch's shared `secret`.
    pub fn new(secret: &[u8; 32], epoch: u64) -> Self {
        let key = epoch_key(secret, epoch);
        Self {
            epoch,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Seal `plaintext` under `nonce` (a per-epoch counter), authenticating `aad`
    /// (the v2 header). Returns `ciphertext || tag`.
    pub fn seal(&self, nonce: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        self.cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes(nonce)),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("chacha20poly1305 seal")
    }

    /// Open `ciphertext`; `None` if authentication fails (wrong key/epoch/aad or
    /// tampering).
    pub fn open(&self, nonce: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes(nonce)),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .ok()
    }
}

/// The **cipher seam** — a mesh's symmetric suite, kept deliberately separate so the
/// data plane is suite-agnostic. [`suite`] dispatches on `charter.initial_cipher`
/// (P-C1); the default is [`MeshCipher`] and the research time-window cipher is the
/// second registered suite [`TimeWindowSuite`], dropped in without touching any caller.
pub trait MeshSuite: Send + Sync {
    /// Suite name (logged / matched against `charter.initial_cipher`).
    fn name(&self) -> &'static str;
    /// Seal `plaintext` under per-message `seq`, authenticating `aad` (the header).
    fn seal(&self, seq: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8>;
    /// Open; `None` on auth failure (or, for forward-secure suites, once the key for
    /// `seq` has been erased).
    fn open(&self, seq: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>>;
}

impl MeshSuite for MeshCipher {
    fn name(&self) -> &'static str {
        "chachapoly-epoch"
    }
    fn seal(&self, seq: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        MeshCipher::seal(self, seq, plaintext, aad)
    }
    fn open(&self, seq: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        MeshCipher::open(self, seq, ciphertext, aad)
    }
}

/// The default cipher (the proven epoch-keyed ChaCha20-Poly1305).
pub const DEFAULT_CIPHER: &str = "chachapoly-epoch";

/// The registered cipher suites, by name — populates the GUI cipher dropbox (P-C1)
/// and validates `charter.initial_cipher`. A mesh's cipher is **fixed at creation**;
/// changing it later is a re-cipher (≥60% quorum, docs/PROTOCOL_DESIGN.md §5-4).
pub fn available_ciphers() -> &'static [&'static str] {
    &[DEFAULT_CIPHER, TimeWindowSuite::NAME]
}

/// Can we build a suite for `name`? (`"default"` aliases [`DEFAULT_CIPHER`].)
pub fn is_known_cipher(name: &str) -> bool {
    name == "default" || available_ciphers().contains(&name)
}

/// Build a mesh's cipher suite by name (from `charter.initial_cipher`). Dispatches
/// on the registered name; any legacy/unknown name falls back to the proven default
/// (so an older mesh keeps working — all its nodes share the same name anyway).
pub fn suite(name: &str, secret: &[u8; 32], epoch: u64) -> Box<dyn MeshSuite> {
    match name {
        TimeWindowSuite::NAME => Box::new(TimeWindowSuite::new(secret, epoch)),
        // "default", DEFAULT_CIPHER, or anything legacy/unknown → the default.
        _ => Box::new(MeshCipher::new(secret, epoch)),
    }
}

// ============================================================================
//  RESEARCH CIPHER DROP-IN — time-window / manifold suite
//  --------------------------------------------------------------------------
//  The second registered MeshSuite and the HOME of the research cipher
//  (docs/PROTOCOL_DESIGN.md, docs/CIPHER_TIMEWINDOW.md). Select it per mesh with
//  charter.initial_cipher = "timewindow".
//
//  P-C1 state: a WORKING PLACEHOLDER — an *independent* epoch key (distinct KDF
//  domain so it can't open chachapoly-epoch's frames) over ChaCha20-Poly1305. This
//  makes the seam real, selectable, and testable. Replace the two marked blocks in
//  `seal`/`open` with the manifold + forward-secure time-window construction; P-C4
//  wires the wall-clock window + key-erasure ratchet (and adds a time input to the
//  trait), so `open` returns None once a window has passed = data unrecoverable.
// ============================================================================

/// Research time-window suite (placeholder cipher — see banner above).
pub struct TimeWindowSuite {
    cipher: ChaCha20Poly1305,
}

impl TimeWindowSuite {
    /// The charter name that selects this suite.
    pub const NAME: &'static str = "timewindow";

    pub fn new(secret: &[u8; 32], epoch: u64) -> Self {
        // Distinct KDF domain ⇒ keys independent from `chachapoly-epoch`.
        let mut h = Blake2s256::new();
        h.update(b"lattice-mesh-timewindow-v1");
        h.update(secret);
        h.update(epoch.to_be_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&h.finalize());
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
        }
    }
}

impl MeshSuite for TimeWindowSuite {
    fn name(&self) -> &'static str {
        Self::NAME
    }
    fn seal(&self, seq: u64, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        // ▼▼▼ RESEARCH: replace with the manifold / time-window encrypt ▼▼▼
        self.cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes(seq)),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("timewindow seal")
        // ▲▲▲
    }
    fn open(&self, seq: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        // ▼▼▼ RESEARCH: replace with the time-window decrypt — return None once the
        //     window has passed (key erased) so the data is unrecoverable. ▼▼▼
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes(seq)),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .ok()
        // ▲▲▲
    }
}

/// Header-cipher window length (seconds). The header key rotates each window; on
/// decrypt we also try the adjacent windows (the §5-3 *overlapping slide*) so a frame
/// that crosses a window boundary — or arrives under ±1 window of clock skew — still
/// opens.
const HEADER_WINDOW_SECS: u64 = 60;

/// Encrypts the 5-byte wire header (P-C2) under a key derived from **(mesh secret,
/// mesh id, time window)** — so the routing metadata (version/src/dst/type) is hidden
/// from non-members and the frame carries **no constant cleartext bytes** to
/// fingerprint Lattice by (docs/PROTOCOL_DESIGN.md §5-3, §6). Deliberately separate
/// from the body cipher: the header is time-windowed, the body is the per-mesh dropbox
/// [`MeshSuite`]. A relay (a member) can still open just the header to read `dst` and
/// forward without touching the body.
pub struct HeaderCrypto {
    secret: [u8; 32],
    mesh_id: u8,
}

impl HeaderCrypto {
    pub fn new(secret: &[u8; 32], mesh_id: u8) -> Self {
        Self {
            secret: *secret,
            mesh_id,
        }
    }

    fn current_window() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / HEADER_WINDOW_SECS)
            .unwrap_or(0)
    }

    fn cipher_for(&self, window: u64) -> ChaCha20Poly1305 {
        let mut h = Blake2s256::new();
        h.update(b"lattice-mesh-header-v1");
        h.update(self.secret);
        h.update([self.mesh_id]);
        h.update(window.to_be_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&h.finalize());
        ChaCha20Poly1305::new(Key::from_slice(&key))
    }

    /// Seal the header bytes under the current window; `seq` is the AEAD nonce.
    pub fn seal(&self, seq: u64, header: &[u8]) -> Vec<u8> {
        self.cipher_for(Self::current_window())
            .encrypt(Nonce::from_slice(&nonce_bytes(seq)), header)
            .expect("header seal")
    }

    /// Open header bytes, trying the current and adjacent windows (overlapping slide,
    /// tolerant of ±1 window of skew). `None` if none open (wrong key / not a member).
    pub fn open(&self, seq: u64, sealed: &[u8]) -> Option<Vec<u8>> {
        let w = Self::current_window();
        for win in [w, w.wrapping_sub(1), w.wrapping_add(1)] {
            if let Ok(pt) = self
                .cipher_for(win)
                .decrypt(Nonce::from_slice(&nonce_bytes(seq)), sealed)
            {
                return Some(pt);
            }
        }
        None
    }
}

/// Per-mesh frame **scramble** (P-C5, docs/PROTOCOL_DESIGN.md §6): a secret-derived
/// transform that (a) XOR-masks the cleartext `seq` so it doesn't look like a counter
/// starting at 0, and (b) floats the 21-byte sealed header to a **per-frame** position
/// inside the body. With nothing constant at a fixed offset, traffic carries no
/// signature to fingerprint Lattice by — even knowing the program exists. The scheme
/// is fixed at mesh creation (it's a pure function of the secret); the position varies
/// per frame (it depends on `seq`).
pub struct Scramble {
    secret: [u8; 32],
    seq_mask: [u8; 8],
}

impl Scramble {
    pub fn new(secret: &[u8; 32]) -> Self {
        let mut h = Blake2s256::new();
        h.update(b"lattice-seq-mask-v1");
        h.update(secret);
        let d = h.finalize();
        let mut seq_mask = [0u8; 8];
        seq_mask.copy_from_slice(&d[..8]);
        Self {
            secret: *secret,
            seq_mask,
        }
    }

    /// XOR the 8 seq bytes with the per-mesh mask (its own inverse — the receiver
    /// calls it again to recover the real seq).
    pub fn mask_seq(&self, mut b: [u8; 8]) -> [u8; 8] {
        for (x, m) in b.iter_mut().zip(self.seq_mask.iter()) {
            *x ^= m;
        }
        b
    }

    /// Where to splice the sealed header into the body: a per-mesh, per-frame offset
    /// in `0..=body_len` (so the header can land before, inside, or after the body).
    pub fn header_offset(&self, seq: u64, body_len: usize) -> usize {
        let mut h = Blake2s256::new();
        h.update(b"lattice-scramble-off-v1");
        h.update(self.secret);
        h.update(seq.to_be_bytes());
        let d = h.finalize();
        let v = u64::from_be_bytes(d[..8].try_into().unwrap());
        (v % (body_len as u64 + 1)) as usize
    }
}

/// An opaque per-mesh LAN-discovery tag (docs/DISCOVERY.md P-D4): a domain-separated
/// hash of the mesh secret, truncated to 8 bytes. Broadcast in the LAN beacon so
/// same-mesh peers recognise each other without revealing the mesh id or any pubkey;
/// a non-member sees only random-looking bytes. Derived from the secret (not an epoch
/// key) so it survives re-ciphering — discovery shouldn't break on a rekey.
pub fn lan_tag(secret: &[u8; 32]) -> [u8; 8] {
    let mut h = Blake2s256::new();
    h.update(b"lattice-mesh-lan-tag-v1");
    h.update(secret);
    let digest = h.finalize();
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&digest[..8]);
    tag
}

fn epoch_key(secret: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut h = Blake2s256::new();
    h.update(b"lattice-mesh-epoch-v2");
    h.update(secret);
    h.update(epoch.to_be_bytes());
    let mut k = [0u8; 32];
    k.copy_from_slice(&h.finalize());
    k
}

/// 96-bit nonce: the low 64 bits hold the per-epoch counter (the high 32 stay 0).
fn nonce_bytes(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [9u8; 32];
    const AAD: &[u8] = b"\x02\x07\x01\x09\x03"; // a stand-in v2 header

    #[test]
    fn seal_open_round_trip() {
        let c = MeshCipher::new(&SECRET, 0);
        let ct = c.seal(1, b"hello mesh", AAD);
        assert_ne!(ct, b"hello mesh"); // actually encrypted
        assert_eq!(c.open(1, &ct, AAD).unwrap(), b"hello mesh");
    }

    #[test]
    fn wrong_aad_fails() {
        let c = MeshCipher::new(&SECRET, 0);
        let ct = c.seal(1, b"hi", AAD);
        assert!(c.open(1, &ct, b"different header").is_none());
    }

    #[test]
    fn wrong_nonce_fails() {
        let c = MeshCipher::new(&SECRET, 0);
        let ct = c.seal(1, b"hi", AAD);
        assert!(c.open(2, &ct, AAD).is_none());
    }

    #[test]
    fn different_epoch_cannot_open() {
        let e0 = MeshCipher::new(&SECRET, 0);
        let e1 = MeshCipher::new(&SECRET, 1);
        let ct = e0.seal(1, b"epoch-0 only", AAD);
        assert!(e1.open(1, &ct, AAD).is_none()); // epoch is in the key derivation
        assert_eq!(e0.open(1, &ct, AAD).unwrap(), b"epoch-0 only");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let c = MeshCipher::new(&SECRET, 0);
        let mut ct = c.seal(1, b"hi", AAD);
        ct[0] ^= 0xff;
        assert!(c.open(1, &ct, AAD).is_none());
    }

    #[test]
    fn distinct_nonces_give_distinct_ciphertext() {
        let c = MeshCipher::new(&SECRET, 0);
        assert_ne!(c.seal(1, b"same", AAD), c.seal(2, b"same", AAD));
    }

    #[test]
    fn suite_seam_round_trips() {
        let s = suite("noise-ik-chachapoly", &SECRET, 0);
        assert_eq!(s.name(), "chachapoly-epoch");
        let ct = s.seal(1, b"via the seam", AAD);
        assert_eq!(s.open(1, &ct, AAD).unwrap(), b"via the seam");
        assert!(s.open(2, &ct, AAD).is_none());
    }

    #[test]
    fn suite_dispatches_by_name() {
        assert_eq!(suite("default", &SECRET, 0).name(), "chachapoly-epoch");
        assert_eq!(
            suite("chachapoly-epoch", &SECRET, 0).name(),
            "chachapoly-epoch"
        );
        assert_eq!(suite("timewindow", &SECRET, 0).name(), "timewindow");
        // Unknown names fall back to the default (legacy meshes keep working).
        assert_eq!(suite("who-knows", &SECRET, 0).name(), "chachapoly-epoch");
    }

    #[test]
    fn registered_ciphers_are_known() {
        assert!(is_known_cipher("default"));
        for name in available_ciphers() {
            assert!(is_known_cipher(name));
        }
        assert!(!is_known_cipher("not-a-cipher"));
    }

    #[test]
    fn timewindow_round_trips_but_is_independent_of_default() {
        let tw = suite("timewindow", &SECRET, 0);
        let def = suite("chachapoly-epoch", &SECRET, 0);
        let ct = tw.seal(1, b"window payload", AAD);
        // Round-trips under its own suite...
        assert_eq!(tw.open(1, &ct, AAD).unwrap(), b"window payload");
        // ...but the default suite can't open it (distinct KDF domain ⇒ distinct key).
        assert!(def.open(1, &ct, AAD).is_none());
    }

    #[test]
    fn header_crypto_round_trips_and_gates() {
        let hc = HeaderCrypto::new(&SECRET, 3);
        let header: &[u8] = b"\x02\x03\x01\x09\x03"; // a 5-byte v2 header
        let sealed = hc.seal(7, header);
        assert_ne!(&sealed[..], header); // encrypted
        assert_eq!(sealed.len(), 5 + TAG_LEN); // header + tag
        assert_eq!(hc.open(7, &sealed).unwrap(), header);
        assert!(hc.open(8, &sealed).is_none()); // wrong seq (nonce)
        assert!(HeaderCrypto::new(&SECRET, 4).open(7, &sealed).is_none()); // wrong mesh id
        assert!(HeaderCrypto::new(&[1u8; 32], 3).open(7, &sealed).is_none()); // non-member
    }

    #[test]
    fn scramble_seq_mask_round_trips() {
        let s = Scramble::new(&SECRET);
        let seq = 42u64.to_be_bytes();
        let masked = s.mask_seq(seq);
        assert_ne!(masked, seq); // actually masked
        assert_eq!(s.mask_seq(masked), seq); // XOR is its own inverse
    }

    #[test]
    fn scramble_offset_in_range_and_deterministic() {
        let s = Scramble::new(&SECRET);
        for (seq, blen) in [(0u64, 0usize), (1, 10), (1000, 100), (5, 21)] {
            let off = s.header_offset(seq, blen);
            assert!(off <= blen);
            assert_eq!(off, s.header_offset(seq, blen)); // deterministic
        }
    }
}
