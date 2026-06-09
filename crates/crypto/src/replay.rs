//! Sliding-window replay protection over a monotonic per-packet counter.
//!
//! Each transport packet carries a strictly increasing 64-bit counter. This
//! window accepts each counter at most once, rejects duplicates, and rejects
//! counters older than the window — the IPsec/WireGuard anti-replay approach.
//! Out-of-order delivery within the window is allowed (UDP reorders packets).
//!
//! Integration note: meaningful replay protection requires the counter to be
//! bound to the AEAD (used as the nonce). That lands together with the move off
//! snow's in-order stateful transport to a counter-as-nonce cipher (see
//! PROTOCOL.md); this component is the algorithm that guards it, tested here.

/// Bits of history kept. 64 fits a single word; widen to `[u64; N]` for a larger
/// window if needed (the algorithm is identical per word).
const WINDOW: u64 = 64;

/// Anti-replay sliding window. `latest` is the highest counter accepted so far;
/// `bitmap` bit *i* records whether `latest - i` has been seen (bit 0 = latest).
#[derive(Default)]
pub struct ReplayWindow {
    latest: u64,
    bitmap: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check a counter and record it. Returns `true` if it is fresh (accept),
    /// `false` if it is a replay or too old to verify (reject). Counters are
    /// 1-based; `0` is never valid.
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.latest {
            // Advance the window forward by the gap.
            let shift = seq - self.latest;
            self.bitmap = if shift >= WINDOW {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.latest = seq;
            true
        } else {
            let diff = self.latest - seq;
            if diff >= WINDOW {
                return false; // too old to prove non-replay
            }
            let mask = 1u64 << diff;
            if self.bitmap & mask != 0 {
                false // already seen
            } else {
                self.bitmap |= mask;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_in_order_rejects_duplicates() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(2));
        assert!(w.check_and_update(3));
        assert!(!w.check_and_update(2), "duplicate rejected");
        assert!(!w.check_and_update(3), "duplicate rejected");
        assert!(!w.check_and_update(0), "zero never valid");
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(10));
        assert!(w.check_and_update(8), "older but unseen, within window");
        assert!(w.check_and_update(9));
        assert!(!w.check_and_update(8), "now a replay");
    }

    #[test]
    fn rejects_counters_older_than_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(1000));
        assert!(!w.check_and_update(1), "far outside the 64-wide window");
        assert!(w.check_and_update(1000 - 63), "just inside the window");
        assert!(!w.check_and_update(1000 - 64), "just outside the window");
    }

    #[test]
    fn large_forward_jump_resets_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(5));
        assert!(w.check_and_update(5_000_000));
        assert!(
            !w.check_and_update(5),
            "old counter rejected after big jump"
        );
        assert!(w.check_and_update(5_000_001));
    }
}
