//! The policy engine: the deterministic, **non-bypassable** choke point.
//!
//! # What makes this a choke point rather than a layer
//!
//! docs-03 §1: policy is not a stage in a chain that a code path could route
//! around. It is the *only* producer of
//! `AuthorisationProof`(orxnud_domain::AuthorisationProof), and that is the
//! only way to obtain a
//! `CapabilityInvocation`(orxnud_domain::CapabilityInvocation) — whose fields
//! are private and which has no other public constructor. A compile-fail test
//! (`orxnud-domain/tests/compile_fail/invocation_is_policy_sealed.rs`) proves
//! the seal holds from outside that crate.
//!
//! So the flow is: intent produces a `Proposal` → validation produces an
//! `ActionRequest` → **this crate** decides → a `CapabilityInvocation` exists.
//! There is no other route to an adapter.
//!
//! # Fails closed
//!
//! Every failure path denies. Not "denies and warns", not "denies in strict
//! mode". If the policy set cannot be read, if the audit journal cannot be
//! written, if a grant has expired, if the risk cannot be classified — the
//! answer is no. A policy engine that can fail open is not a policy engine.
//!
//! # What policy decides, in order
//!
//! 0. **Authority** — may this *actor* do this, under its delegation?
//! 1. Registration and version
//! 2. Parameter schema conformance
//! 3. Data class within the task's envelope
//! 4. Grant present, unexpired, unrevoked
//! 5. Risk classification (unknown ⇒ High)
//! 6. Approval present, valid, and **digest-bound to this exact action**
//! 7. Egress consent for the data class
//! 8. Budget
//! 9. **Audit — which must succeed, or the action is denied**
//!
//! Step 0 is new relative to the original design and is the reason
//! `orxnud-domain` grew an `Actor` type. Step 6 is the anti-Loopjacking check
//! (control S6): the digest is recomputed here, from the action about to run,
//! and compared with the one the user approved.
//!
//! # Scope
//!
//! Phase 1 has **no capabilities registered**, so every decision here denies in
//! practice. That is correct, not a stub: "zero capabilities enabled" is a
//! Phase 1 exit criterion.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod authority;
pub mod budget;
pub mod decision;
pub mod digest;
pub mod engine;
pub mod policy_set;

pub use authority::{AuthorisationProof, CapabilityInvocation, DispatchView};
pub use budget::{BudgetError, BudgetLedger, Ceiling};
pub use decision::{Decision, DenialReason, PolicyError};
pub use digest::{DigestError, canonical_params, digest_for, issue_approval};
pub use engine::{AuthorisedInvocation, CapabilityDeclaration, PolicyEngine, SettlementReport};
pub use policy_set::{Grant, PolicySet};

// `PolicySeal` and `seal()` used to live here. They are gone, and
// `scripts/ci-gates.sh` G2d's token list has an entry for each that now matches
// nothing.
//
// The seal was a `pub struct` in `orxnud-domain` whose only field was a `&'static str`
// the *holder* wrote about itself. `AuthorisationProof::issue` and
// `CapabilityInvocation::authorise` both took it and bound it to `_`; nothing
// anywhere compared `issued_by` with `"orxnud-policy"`. So the "proof of policy"
// was a value the caller supplied, and the only thing standing between a caller and
// authority was gate G2d -- a lexical CI scan that the third audit showed reporting
// `ok` on a tree that forges authority three separate ways.
//
// Now that the authority types live in this crate, their constructors can be
// `pub(crate)` and `rustc` enforces the boundary. The seal existed to bridge two
// crates; with no bridge left, it is not a weakened control but a deleted fiction.
// See `authority.rs`.
