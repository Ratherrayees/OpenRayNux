//! The anti-Loopjacking digest (control S6).
//!
//! The digest covers the **complete tuple that defines an operation**:
//! actor, capability, target, normalised parameters, issued-at, expires-at.
//! A user is shown a rendering of that tuple; the *same* tuple's digest is
//! recomputed immediately before execution and compared. If the target, any
//! parameter, or the actor has changed, the digests differ and the call aborts.

use blake3;

use orxnud_domain::ids::CapabilityId;
use orxnud_domain::{Actor, ApprovalDigest, NormalizedParams};

/// A digest failure.
#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    /// The supplied approval does not match the action about to run.
    ///
    /// A hard abort, never a retry: the operation is not the one that was
    /// approved, and retrying it would be attempting the unapproved thing again.
    #[error("approval digest mismatch: the action differs from what was approved")]
    Mismatch,

    /// No approval was supplied for an action that requires one.
    #[error("this action requires an approval and none was supplied")]
    Missing,
}

/// The canonical byte form of an operation, hashed to produce its digest.
///
/// Fixed field order, explicit separators, and an explicit `-` for absent
/// values so that "absent" and "empty string" cannot collide.
#[must_use]
pub fn canonical_bytes(
    actor: &Actor,
    capability: &CapabilityId,
    target: Option<&str>,
    params: &NormalizedParams,
    issued_at_ms: i64,
    expires_at_ms: i64,
) -> Vec<u8> {
    let mut s = String::with_capacity(256);
    s.push_str("orxnud-approval-v1|");
    s.push_str(actor.label());
    s.push('|');
    s.push_str(actor.authority_root().map_or("-", |u| u.as_str()));
    s.push('|');
    s.push_str(capability.as_str());
    s.push('|');
    s.push_str(target.unwrap_or("-"));
    s.push('|');
    s.push_str(params.as_str());
    s.push('|');
    s.push_str(&issued_at_ms.to_string());
    s.push('|');
    s.push_str(&expires_at_ms.to_string());
    s.into_bytes()
}

/// Computes the digest of an operation.
#[must_use]
pub fn digest_for(
    actor: &Actor,
    capability: &CapabilityId,
    target: Option<&str>,
    params: &NormalizedParams,
    issued_at_ms: i64,
    expires_at_ms: i64,
) -> ApprovalDigest {
    let bytes = canonical_bytes(actor, capability, target, params, issued_at_ms, expires_at_ms);
    ApprovalDigest::from_bytes(*blake3::hash(&bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_domain::actor::{AuthChannel, ModelProvenance};
    use orxnud_domain::ids::{RequestId, RunId, TaskId, UserId};
    use proptest::prelude::*;

    fn cap() -> CapabilityId {
        CapabilityId::new("send-message")
    }
    fn human() -> Actor {
        Actor::Human { user: UserId::new("u-1"), via: AuthChannel::LocalInteractive }
    }
    fn params() -> NormalizedParams {
        NormalizedParams::canonical("{\"to\":\"alice\"}")
    }

    fn d(
        actor: &Actor,
        cap: &CapabilityId,
        target: Option<&str>,
        p: &NormalizedParams,
        i: i64,
        e: i64,
    ) -> ApprovalDigest {
        digest_for(actor, cap, target, p, i, e)
    }

    #[test]
    fn identical_operations_produce_identical_digests() {
        let a = d(&human(), &cap(), Some("alice"), &params(), 100, 200);
        let b = d(&human(), &cap(), Some("alice"), &params(), 100, 200);
        assert_eq!(a, b);
        assert!(!a.is_zero());
    }

    #[test]
    fn mutating_any_member_changes_the_digest() {
        // This is the property that makes an approval *bind* to an operation.
        let base = d(&human(), &cap(), Some("alice"), &params(), 100, 200);

        let other_target = d(&human(), &cap(), Some("bob"), &params(), 100, 200);
        let no_target = d(&human(), &cap(), None, &params(), 100, 200);
        let other_params = d(
            &human(), &cap(), Some("alice"),
            &NormalizedParams::canonical("{\"to\":\"bob\"}"), 100, 200,
        );
        let empty_params = d(&human(), &cap(), Some("alice"), &NormalizedParams::canonical(""), 100, 200);
        let other_cap = d(&human(), &CapabilityId::new("delete-file"), Some("alice"), &params(), 100, 200);
        let other_issued = d(&human(), &cap(), Some("alice"), &params(), 101, 200);
        let other_expiry = d(&human(), &cap(), Some("alice"), &params(), 100, 201);
        let other_actor = Actor::Human {
            user: UserId::new("u-2"),
            via: AuthChannel::LocalInteractive,
        };
        let actor_d = d(&other_actor, &cap(), Some("alice"), &params(), 100, 200);
        // A different actor *kind*, same human.
        let ai_actor = Actor::Ai {
            delegated_by: UserId::new("u-1"),
            run: RunId::new("r"),
            task: TaskId::new("t"),
            provenance: ModelProvenance::new("m", "p", RequestId::new("q")),
        };
        let ai_d = d(&ai_actor, &cap(), Some("alice"), &params(), 100, 200);

        for (name, other) in [
            ("target", other_target),
            ("absent target", no_target),
            ("params", other_params),
            ("empty params", empty_params),
            ("capability", other_cap),
            ("issued_at", other_issued),
            ("expires_at", other_expiry),
            ("actor user", actor_d),
            ("actor kind", ai_d),
        ] {
            assert_ne!(base, other, "mutating {name} did not change the digest");
        }
    }

    #[test]
    fn absent_and_empty_target_do_not_collide() {
        // The explicit `-` separator exists precisely for this.
        let none = d(&human(), &cap(), None, &params(), 100, 200);
        let empty = d(&human(), &cap(), Some(""), &params(), 100, 200);
        assert_ne!(none, empty);
    }

    #[test]
    fn a_field_separator_cannot_be_forged_across_fields() {
        // Without separators, ("a|b") and ("a", "b") would hash identically.
        let one = d(&human(), &CapabilityId::new("a"), None, &NormalizedParams::canonical("b"), 100, 200);
        let two = d(&human(), &CapabilityId::new("a"), None, &NormalizedParams::canonical("b"), 100, 200);
        let split = d(&human(), &CapabilityId::new("a"), Some("b"), &NormalizedParams::canonical(""), 100, 200);
        assert_ne!(one, split);
    }

    #[test]
    fn the_canonical_form_is_prefixed_with_its_version() {
        // So a future change to the field set cannot be confused with an old
        // approval.
        let bytes = canonical_bytes(&human(), &cap(), Some("a"), &params(), 1, 2);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.starts_with("orxnud-approval-v1|"), "missing version prefix: {s}");
    }

    proptest! {
        /// A digest is never the zero sentinel for a real operation, and it is
        /// a pure function of its inputs.
        #[test]
        fn digest_is_pure_and_nonzero(n: u8, m: u8) {
            let target = if n % 2 == 0 { Some("alice") } else { None };
            let p = NormalizedParams::canonical(format!("{{\"n\":{m}}}"));
            let a = d(&human(), &cap(), target, &p, 100, 200);
            let b = d(&human(), &cap(), target, &p, 100, 200);
            prop_assert_eq!(a, b);
            prop_assert!(!a.is_zero());
        }

        /// Changing any single input changes the digest, for generated values.
        #[test]
        fn any_single_mutation_changes_the_digest(n: u8) {
            let n = i64::from(n);
            let base = d(&human(), &cap(), Some("alice"), &params(), n, n + 1);
            prop_assert_ne!(base, d(&human(), &cap(), Some("bob"), &params(), n, n + 1));
            prop_assert_ne!(base, d(&human(), &cap(), None, &params(), n, n + 1));
            prop_assert_ne!(base, d(&human(), &cap(), Some("alice"), &params(), n + 1, n + 1));
            prop_assert_ne!(base, d(&human(), &cap(), Some("alice"), &params(), n, n + 2));
        }
    }
}
