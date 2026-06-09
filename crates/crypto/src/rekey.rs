//! Rekey policy: when a session has carried enough messages or lived long
//! enough, it should renegotiate keys (forward secrecy, nonce-exhaustion
//! avoidance). See PROTOCOL.md for the chosen parameters.

use std::time::Duration;

/// Default message ceiling before rekeying (2^60 — far below nonce exhaustion).
pub const DEFAULT_MAX_MESSAGES: u64 = 1 << 60;
/// Default session age before rekeying.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(120);

/// Tracks how much a session has been used and decides when to rekey. The age
/// is passed in (caller owns the clock) so this is deterministic and testable.
pub struct RekeyPolicy {
    messages: u64,
    max_messages: u64,
    max_age: Duration,
}

impl Default for RekeyPolicy {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_MESSAGES, DEFAULT_MAX_AGE)
    }
}

impl RekeyPolicy {
    pub fn with_limits(max_messages: u64, max_age: Duration) -> Self {
        Self {
            messages: 0,
            max_messages,
            max_age,
        }
    }

    /// Count one transport message.
    pub fn record(&mut self) {
        self.messages = self.messages.saturating_add(1);
    }

    /// Whether a rekey is due, given the session's current age.
    pub fn due(&self, age: Duration) -> bool {
        self.messages >= self.max_messages || age >= self.max_age
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rekeys_after_message_ceiling() {
        let mut p = RekeyPolicy::with_limits(3, Duration::from_secs(120));
        p.record();
        p.record();
        assert!(!p.due(Duration::ZERO));
        p.record();
        assert!(p.due(Duration::ZERO), "hit the message ceiling");
    }

    #[test]
    fn rekeys_after_max_age() {
        let p = RekeyPolicy::with_limits(u64::MAX, Duration::from_secs(120));
        assert!(!p.due(Duration::from_secs(119)));
        assert!(p.due(Duration::from_secs(120)));
    }
}
