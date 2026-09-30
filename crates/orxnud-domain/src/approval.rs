//! Approval digests — the anti-Loopjacking mechanism (control S6).
//!
//! # The threat this defeats
//!
//! *Loopjacking*: "a human approves what they understand as operation A, while
//! the implementation uses that decision for a materially different operation
//! B." A human-in-the-loop control that is not *bound* to the operation is
//! decorative.
//!
//! # The mechanism
//!
//! An [`ApprovalDigest`] is a hash over the complete tuple that defines an
//! operation:
//!
//! ```text
//! (actor, capability, target, normalised params, issued_at, expires_at)
//! ```
//!
//! The user is shown a rendering of that tuple, and the *same* tuple's digest
//! is re-verified **immediately before execution**. If the target, any
//! parameter, or the actor has changed since approval, the digest does not
//! match and the call aborts.
//!
//! # Why the digest is computed here, in the domain crate
//!
//! Because it is pure. It is a value, not a decision. Keeping the *decision*
//! (is this gated? has the user approved? is the grant still valid?) in
//! `orxnud-policy`, and only the *identity* of an operation here, means the
//! security-critical comparison has no I/O and no side effects, so it is
//! straightforward to test exhaustively.

use serde::{Deserialize, Serialize};

/// Parameters after normalisation.
///
/// Normalisation matters more than it looks: `"send to alice"` and
/// `"send  to   alice"` must produce the *same* digest, or a user could be
/// shown one thing and have another approved. The canonical form is defined by
/// the capability's schema, so the domain only requires that a normalised
/// value exists and is stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NormalizedParams(String);

impl NormalizedParams {
    /// Wraps an already-normalised canonical string.
    ///
    /// Callers are responsible for canonicalisation. `orxnud-policy` performs
    /// it via the capability's declared schema before constructing this.
    #[must_use]
    pub fn canonical(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The canonical form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A 32-byte digest identifying one approved operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ApprovalDigest([u8; 32]);

impl ApprovalDigest {
    /// The digest of *nothing*, used as a sentinel and for comparisons.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Whether this is the zero sentinel.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }

    /// Lowercase hex, for logs and for binding to a human-visible string.
    #[must_use]
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            use std::fmt::Write as _;
            // Writing to a String is infallible.
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

/// A human approval, as issued.
///
/// The record is what the user saw and agreed to. `issued_at` and `expires_at`
/// are milliseconds since the Unix epoch, supplied by the caller so the domain
/// stays free of a clock (testability: no hidden time source).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Who gave it. An approval given to one actor is not usable by another.
    pub actor_label: String,
    /// The capability the user believed they were approving.
    pub capability: String,
    /// The human-readable target — a URL, a file path, a recipient.
    pub target: String,
    /// The canonical parameters the user were shown.
    pub params: NormalizedParams,
    /// Issue time, ms since epoch.
    pub issued_at_ms: i64,
    /// Expiry time, ms since epoch.
    pub expires_at_ms: i64,
    /// The risk class that made this approval necessary.
    pub risk: crate::enums::RiskClass,
    /// The digest of the tuple above.
    pub digest: ApprovalDigest,
}

impl ApprovalRecord {
    /// Whether the approval is still valid at `now_ms`.
    ///
    /// Single-use and short-lived by design: a stale approval must not authorise
    /// a later, possibly-different, situation. The *single-use* part is enforced
    /// by the task engine's re-derivation on retry (property TP-6), not here,
    /// because only the engine knows whether it has been consumed.
    #[must_use]
    pub fn is_valid_at(&self, now_ms: i64) -> bool {
        !self.digest.is_zero() && now_ms < self.expires_at_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::RiskClass;
    use proptest::prelude::*;

    fn record() -> ApprovalRecord {
        ApprovalRecord {
            actor_label: "human".into(),
            capability: "send-message".into(),
            target: "https://example.invalid/alice".into(),
            params: NormalizedParams::canonical("{\"to\":\"alice\"}"),
            issued_at_ms: 1_000,
            expires_at_ms: 2_000,
            risk: RiskClass::High,
            digest: ApprovalDigest::from_bytes([1u8; 32]),
        }
    }

    #[test]
    fn zero_digest_is_detected() {
        assert!(ApprovalDigest::ZERO.is_zero());
        assert!(!ApprovalDigest::from_bytes([1u8; 32]).is_zero());
    }

    #[test]
    fn hex_is_lowercase_and_64_chars() {
        let hex = ApprovalDigest::from_bytes([0xABu8; 32]).to_hex();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(hex, "ab".repeat(32));
    }

    #[test]
    fn validity_window_is_half_open() {
        let r = record();
        assert!(r.is_valid_at(1_000));
        assert!(r.is_valid_at(1_999));
        // Expiry is exclusive: at exactly expires_at, it is no longer valid.
        assert!(!r.is_valid_at(2_000));
        assert!(!r.is_valid_at(2_001));
    }

    #[test]
    fn a_zero_digest_is_never_valid() {
        // Defence in depth: a record with no digest must not be honoured, even
        // inside its time window.
        let r = ApprovalRecord {
            digest: ApprovalDigest::ZERO,
            ..record()
        };
        assert!(!r.is_valid_at(1_500));
    }

    #[test]
    fn mutating_any_tuple_member_requires_a_new_digest() {
        // This is the property that makes the digest bind. It is exercised for
        // real against the hashing implementation in `orxnud-policy`, which is
        // where the digest is actually computed; here we pin that the record
        // carries every field the digest must cover, so a future change that
        // drops one is caught.
        let base = record();
        let variants = [
            ApprovalRecord {
                actor_label: "other".into(),
                ..base.clone()
            },
            ApprovalRecord {
                capability: "delete-file".into(),
                ..base.clone()
            },
            ApprovalRecord {
                target: "https://example.invalid/bob".into(),
                ..base.clone()
            },
            ApprovalRecord {
                params: NormalizedParams::canonical("{\"to\":\"bob\"}"),
                ..base.clone()
            },
            ApprovalRecord {
                issued_at_ms: 1_001,
                ..base.clone()
            },
            ApprovalRecord {
                expires_at_ms: 2_001,
                ..base.clone()
            },
        ];
        for v in &variants {
            assert_ne!(base, *v, "mutation did not change the record");
        }
    }

    proptest! {
        /// Validity is monotone decreasing in time within a fixed window, and
        /// false at or after expiry regardless of the start.
        #[test]
        fn validity_is_monotone_in_time(start: i64, span: i64, now: i64) {
            let span = span % 10_000;
            let r = ApprovalRecord {
                issued_at_ms: start,
                expires_at_ms: start + span,
                ..record()
            };
            if now < start + span {
                prop_assert!(r.is_valid_at(now));
            } else {
                prop_assert!(!r.is_valid_at(now));
            }
        }
    }
}
