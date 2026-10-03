//! The anti-Loopjacking digest (control S6).
//!
//! The digest covers the **complete tuple that defines an operation**:
//! actor, capability, target, normalised parameters, issued-at, expires-at.
//! A user is shown a rendering of that tuple; the *same* tuple's digest is
//! recomputed immediately before execution and compared. If the target, any
//! parameter, or the actor has changed, the digests differ and the call aborts.

use blake3;

use orxnud_domain::ids::CapabilityId;
use orxnud_domain::{Actor, ApprovalDigest, ApprovalRecord, NormalizedParams};

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
    let bytes = canonical_bytes(
        actor,
        capability,
        target,
        params,
        issued_at_ms,
        expires_at_ms,
    );
    ApprovalDigest::from_bytes(*blake3::hash(&bytes).as_bytes())
}

/// Canonicalises raw parameters into the form an approval commits to.
///
/// [`NormalizedParams::canonical`] is deliberately a dumb wrapper: it trusts its
/// caller. That trust is the whole problem, because a caller that passes a
/// placeholder gets an approval digest computed over the placeholder while the
/// adapter runs the real parameters — the user approves one operation and a
/// different one executes. So the derivation lives here, once, next to the digest
/// that consumes it, rather than being re-derived (or forgotten) per call site.
///
/// Two properties, and both are security properties:
///
/// 1. **It changes with the parameters.** Different values are different
///    operations and must not share a digest.
/// 2. **It does not change with the *writing* of the parameters.** `{"a":1,"b":2}`
///    and `{"b":2,"a":1}` are the same operation, and an approval shown to the
///    user in one spelling must verify in the other — otherwise key order becomes
///    an accidental approval bypass, or a spurious refusal.
///
/// Property 2 is why this sorts keys itself instead of calling
/// [`serde_json::to_string`] directly. serde_json is currently built without the
/// `preserve_order` feature, so its `Map` is a `BTreeMap` and plain serialisation
/// would already sort. Relying on that would make approval digests depend on a
/// feature flag in a `Cargo.toml` nobody reading `digest.rs` would think to look
/// for; enabling it upstream would silently change every digest. The sort is
/// therefore explicit, so the guarantee holds regardless of how serde_json is
/// compiled.
#[must_use]
pub fn canonical_params(value: &serde_json::Value) -> NormalizedParams {
    NormalizedParams::canonical(canonical_json(value))
}

/// The canonical text of a parameter value.
fn canonical_json(value: &serde_json::Value) -> String {
    fn sorted(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort_unstable();
                let mut out = serde_json::Map::with_capacity(map.len());
                for key in keys {
                    if let Some(v) = map.get(key) {
                        out.insert(key.clone(), sorted(v));
                    }
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(sorted).collect())
            }
            other => other.clone(),
        }
    }

    // Serialising a `serde_json::Value` cannot fail: there is no I/O, no
    // non-string map key, and no custom `Serialize` impl to reject. A panic here
    // would therefore be unreachable, whereas a fallback would be reachable and
    // wrong — collapsing two different parameter sets onto one digest, which is
    // the exact failure this function exists to prevent.
    serde_json::to_string(&sorted(value)).expect("serialising a serde_json::Value cannot fail")
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
        Actor::Human {
            user: UserId::new("u-1"),
            via: AuthChannel::LocalInteractive,
        }
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

    // ---------------------------------------------------------------------
    // Canonicalisation: the two properties an approval depends on.
    // ---------------------------------------------------------------------

    /// Property 1: different parameters are different operations.
    ///
    /// This is the test that would have failed against the placeholder that
    /// motivated [`canonical_params`] — a constant `{}` made every parameter set
    /// of a given capability hash identically, so one approval would have covered
    /// every possible invocation of it.
    #[test]
    fn the_digest_changes_when_the_parameters_change() {
        let base = canonical_params(&serde_json::json!({"text": "hello world"}));
        let other = canonical_params(&serde_json::json!({"text": "goodbye world"}));

        assert_ne!(base.as_str(), other.as_str());
        assert_ne!(
            d(&human(), &cap(), None, &base, 100, 200),
            d(&human(), &cap(), None, &other, 100, 200),
        );
    }

    /// A real parameter set must not collide with the empty placeholder that the
    /// runtime used to pass.
    #[test]
    fn real_parameters_do_not_collide_with_the_empty_placeholder() {
        let real = canonical_params(&serde_json::json!({"text": "hello world"}));
        let placeholder = NormalizedParams::canonical("{}");
        assert_ne!(real.as_str(), placeholder.as_str());
        assert_ne!(
            d(&human(), &cap(), None, &real, 100, 200),
            d(&human(), &cap(), None, &placeholder, 100, 200),
        );
    }

    /// Property 2: key *order* is not part of the operation.
    ///
    /// An approval is shown to a human as rendered text and verified against
    /// whatever the caller happens to send later. If spelling changed the digest,
    /// the same approved operation would be refused (or, inverted, a different
    /// one accepted) purely because of object key ordering.
    #[test]
    fn key_order_does_not_change_the_canonical_form_or_the_digest() {
        let forward: serde_json::Value =
            serde_json::from_str(r#"{"to":"alice","body":"hi","n":1}"#).expect("json");
        let reversed: serde_json::Value =
            serde_json::from_str(r#"{"n":1,"body":"hi","to":"alice"}"#).expect("json");

        assert_eq!(
            canonical_params(&forward).as_str(),
            canonical_params(&reversed).as_str(),
        );
        assert_eq!(
            d(
                &human(),
                &cap(),
                None,
                &canonical_params(&forward),
                100,
                200
            ),
            d(
                &human(),
                &cap(),
                None,
                &canonical_params(&reversed),
                100,
                200
            ),
        );
    }

    /// The same, nested — which is the case plain `to_string` would only have got
    /// right by accident of serde_json's `BTreeMap` map, and so the case worth
    /// pinning explicitly.
    #[test]
    fn nested_key_order_is_also_canonicalised() {
        let forward: serde_json::Value =
            serde_json::from_str(r#"{"a":{"x":1,"y":[{"p":true,"q":null}]},"b":{"m":2,"n":3}}"#)
                .expect("json");
        let reversed: serde_json::Value =
            serde_json::from_str(r#"{"b":{"n":3,"m":2},"a":{"y":[{"q":null,"p":true}],"x":1}}"#)
                .expect("json");

        assert_eq!(
            canonical_params(&forward).as_str(),
            canonical_params(&reversed).as_str(),
        );
        // Canonical form is sorted and compact, which is what makes it a stable
        // thing to hash rather than merely a stable thing.
        assert_eq!(
            canonical_params(&forward).as_str(),
            r#"{"a":{"x":1,"y":[{"p":true,"q":null}]},"b":{"m":2,"n":3}}"#
        );
    }

    /// Array order is *not* canonicalised away: `["a","b"]` and `["b","a"]` are
    /// genuinely different arguments to most capabilities, so sorting them would
    /// merge two operations rather than two spellings of one.
    #[test]
    fn array_order_is_preserved_because_it_is_meaningful() {
        let forward = canonical_params(&serde_json::json!({"xs": ["a", "b"]}));
        let reversed = canonical_params(&serde_json::json!({"xs": ["b", "a"]}));
        assert_ne!(forward.as_str(), reversed.as_str());
    }

    /// Non-object parameters canonicalise to themselves rather than to a
    /// placeholder, so `null` and `""` stay distinguishable. This matters because
    /// the digest is built by concatenating fields with `|` separators, where two
    /// empty strings would otherwise render identically.
    #[test]
    fn non_object_parameters_stay_distinguishable() {
        let null = canonical_params(&serde_json::Value::Null);
        let empty = canonical_params(&serde_json::json!(""));
        let zero = canonical_params(&serde_json::json!(0));
        assert_eq!(null.as_str(), "null");
        assert_eq!(empty.as_str(), "\"\"");
        assert_eq!(zero.as_str(), "0");
        assert_ne!(null.as_str(), empty.as_str());
    }

    /// The canonical form is a pure function of the value, so it is safe to
    /// recompute it at verification time from a separately-parsed copy.
    #[test]
    fn canonicalisation_is_deterministic_across_repeated_derivations() {
        let value = serde_json::json!({"to": "alice", "n": 3, "tags": ["x", "y"]});
        let first = canonical_params(&value).as_str().to_owned();
        for _ in 0..16 {
            assert_eq!(canonical_params(&value).as_str(), first);
        }
        // Round-tripping through text must not change it either.
        let reparsed: serde_json::Value = serde_json::from_str(&first).expect("json");
        assert_eq!(canonical_params(&reparsed).as_str(), first);
    }

    #[test]
    fn mutating_any_member_changes_the_digest() {
        // This is the property that makes an approval *bind* to an operation.
        let base = d(&human(), &cap(), Some("alice"), &params(), 100, 200);

        let other_target = d(&human(), &cap(), Some("bob"), &params(), 100, 200);
        let no_target = d(&human(), &cap(), None, &params(), 100, 200);
        let other_params = d(
            &human(),
            &cap(),
            Some("alice"),
            &NormalizedParams::canonical("{\"to\":\"bob\"}"),
            100,
            200,
        );
        let empty_params = d(
            &human(),
            &cap(),
            Some("alice"),
            &NormalizedParams::canonical(""),
            100,
            200,
        );
        let other_cap = d(
            &human(),
            &CapabilityId::new("delete-file"),
            Some("alice"),
            &params(),
            100,
            200,
        );
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
        let whole = d(
            &human(),
            &CapabilityId::new("a"),
            None,
            &NormalizedParams::canonical("b"),
            100,
            200,
        );
        let same = d(
            &human(),
            &CapabilityId::new("a"),
            None,
            &NormalizedParams::canonical("b"),
            100,
            200,
        );
        let split = d(
            &human(),
            &CapabilityId::new("a"),
            Some("b"),
            &NormalizedParams::canonical(""),
            100,
            200,
        );
        // Sanity: identical inputs are identical, so the difference below is
        // caused by the field split and not by hashing being nondeterministic.
        assert_eq!(whole, same);
        assert_ne!(whole, split);
    }

    #[test]
    fn the_canonical_form_is_prefixed_with_its_version() {
        // So a future change to the field set cannot be confused with an old
        // approval.
        let bytes = canonical_bytes(&human(), &cap(), Some("a"), &params(), 1, 2);
        let s = String::from_utf8_lossy(&bytes);
        assert!(
            s.starts_with("orxnud-approval-v1|"),
            "missing version prefix: {s}"
        );
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

        /// Canonicalisation is invariant under object key order, for generated
        /// objects, including nested ones.
        ///
        /// The two spellings are built as text in opposite orders and then parsed,
        /// so this exercises the same path a real caller takes: JSON arrives as
        /// bytes, not as an ordered map we control.
        #[test]
        fn canonical_form_is_invariant_under_key_order(
            keys in prop::collection::vec("[a-z]{1,4}", 1..6),
            nums in prop::collection::vec(any::<i64>(), 1..6),
        ) {
            // The index makes each key unique. Duplicate keys would collapse
            // during parsing, and then the two spellings would not be the same
            // object at all — which would test nothing about key order.
            let pairs: Vec<(String, i64)> = keys
                .iter()
                .enumerate()
                .zip(nums.iter())
                .map(|((i, k), n)| (format!("k{i}{k}"), *n))
                .collect();

            let mut forward = String::from("{");
            for (i, (k, n)) in pairs.iter().enumerate() {
                if i > 0 {
                    forward.push(',');
                }
                forward.push_str(&format!("\"{k}\":{{\"a\":{n},\"b\":{n}}}"));
            }
            forward.push('}');

            // The same pairs, opposite order, with the nested keys also swapped.
            let mut reversed = String::from("{");
            for (i, (k, n)) in pairs.iter().rev().enumerate() {
                if i > 0 {
                    reversed.push(',');
                }
                reversed.push_str(&format!("\"{k}\":{{\"b\":{n},\"a\":{n}}}"));
            }
            reversed.push('}');

            let a: serde_json::Value = serde_json::from_str(&forward).expect("json");
            let b: serde_json::Value = serde_json::from_str(&reversed).expect("json");
            let ca = canonical_params(&a);
            let cb = canonical_params(&b);
            prop_assert_eq!(ca.as_str(), cb.as_str());
            prop_assert_eq!(
                d(&human(), &cap(), None, &ca, 100, 200),
                d(&human(), &cap(), None, &cb, 100, 200)
            );
        }
    }
}

/// Issues an approval for one operation.
///
/// # Why this exists
///
/// [`ApprovalRecord`] has public fields, so it can be built with any digest at all —
/// the tests in this crate do exactly that. Nothing checks a record's digest against
/// its own fields when it is constructed; `authorise` checks it against the *action*
/// about to run. That is the correct place for the check and the wrong place for the
/// construction, because it means a caller can hold a record that is internally
/// inconsistent and only discovers it at dispatch.
///
/// So issuance goes here, beside [`digest_for`]: the digest is computed from the same
/// tuple in the same function, and there is no way to produce a record whose digest
/// does not describe it. A caller that wants a different digest does not use this — it
/// wants a different approval.
///
/// The canonicalisation requirement is inherited from [`canonical_params`]: an approval
/// whose `params` were canonicalised differently from the ones dispatch will canonicalise
/// would never verify, so callers must pass [`canonical_params`] output rather than
/// hand-built text.
#[must_use]
pub fn issue_approval(
    actor: &Actor,
    capability: &CapabilityId,
    target: Option<&str>,
    params: &NormalizedParams,
    issued_at_ms: i64,
    expires_at_ms: i64,
    risk: orxnud_domain::enums::RiskClass,
) -> ApprovalRecord {
    ApprovalRecord {
        actor_label: actor.label().to_owned(),
        capability: capability.as_str().to_owned(),
        target: target.unwrap_or("-").to_owned(),
        params: params.clone(),
        issued_at_ms,
        expires_at_ms,
        risk,
        digest: digest_for(
            actor,
            capability,
            target,
            params,
            issued_at_ms,
            expires_at_ms,
        ),
    }
}

#[cfg(test)]
mod issue_tests {
    use super::*;
    use orxnud_domain::actor::AuthChannel;
    use orxnud_domain::enums::RiskClass;
    use orxnud_domain::ids::UserId;

    /// The one actor this crate's tests share, so a digest computed against a different
    /// actor cannot accidentally agree.
    fn local_human() -> Actor {
        Actor::Human {
            user: UserId::new("local"),
            via: AuthChannel::LocalInteractive,
        }
    }

    #[test]
    fn an_issued_approval_verifies_against_the_tuple_it_was_issued_for() {
        let actor = local_human();
        let capability = CapabilityId::new("filesystem/write-text");
        let params = canonical_params(&serde_json::json!({"path": "a.txt", "contents": "alpha"}));

        let record = issue_approval(
            &actor,
            &capability,
            Some("a.txt"),
            &params,
            1_000,
            2_000,
            RiskClass::High,
        );

        assert!(record.is_valid_at(1_500), "must be valid inside its window");
        assert!(!record.is_valid_at(2_000), "expiry is exclusive");
        // The digest must be the one dispatch recomputes for the same tuple.
        assert_eq!(
            record.digest,
            digest_for(&actor, &capability, Some("a.txt"), &params, 1_000, 2_000)
        );
        assert_eq!(record.capability, "filesystem/write-text");
        assert_eq!(record.params.as_str(), params.as_str());
    }

    #[test]
    fn changing_any_field_after_issuance_breaks_the_digest() {
        let actor = local_human();
        let capability = CapabilityId::new("filesystem/write-text");
        let params = canonical_params(&serde_json::json!({"path": "a.txt", "contents": "alpha"}));
        let issued = issue_approval(
            &actor,
            &capability,
            Some("a.txt"),
            &params,
            1_000,
            2_000,
            RiskClass::High,
        );

        // Different contents: the same capability, the same target, a different
        // operation. This is the substitution V-63 exists to prevent.
        let other = canonical_params(&serde_json::json!({"path": "a.txt", "contents": "beta"}));
        assert_ne!(
            issued.digest,
            digest_for(&actor, &capability, Some("a.txt"), &other, 1_000, 2_000)
        );
        // Reordered keys: the same operation, so it must still verify.
        let reordered =
            canonical_params(&serde_json::json!({"contents": "alpha", "path": "a.txt"}));
        assert_eq!(reordered.as_str(), params.as_str());
        assert_eq!(
            issued.digest,
            digest_for(&actor, &capability, Some("a.txt"), &reordered, 1_000, 2_000)
        );
    }
}
