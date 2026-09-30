//! A `CapabilityInvocation` must not be constructible from parts.
//!
//! Both `CapabilityInvocation` and `AuthorisationProof` have private fields, so
//! neither can be assembled with a struct literal from outside `orxnud-domain`.
//! This test proves that from the outside, which is the only vantage point that
//! counts: the enforcement is worthless if it is only true from inside.
//!
//! # What is and is not proved here
//!
//! Proved by the type system: neither type can be **built from parts**.
//!
//! **Not** proved by the type system: that only `orxnud-policy` may call
//! [`CapabilityInvocation::authorise`]. Rust has no friend crates, so a `pub`
//! constructor is callable by every crate in the workspace. That half of the
//! guarantee is enforced by gate G2 in `scripts/ci-gates.sh`, which fails the
//! build if any crate other than `orxnud-policy` names `PolicySeal`,
//! `AuthorisationProof`, or `authorise`.
//!
//! Recording that split matters: a single compile-fail test claiming to prove
//! "only policy can authorise" would be overstating what the compiler checks.

use orxnud_domain::actor::{Actor, AuthChannel};
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, RunId, TaskId, UserId};
use orxnud_domain::{
    ActionRequest, AuthorisationProof, CapabilityInvocation, InvocationContext, PolicySeal,
};

fn main() {
    // --- Escape 1: build the invocation from fields. All are private. ---
    let _invocation = CapabilityInvocation {
        task: TaskId::from("t-1"),
        step: 0,
        actor: Actor::Human { user: UserId::from("u"), via: AuthChannel::LocalInteractive },
        capability: CapabilityId::from("c"),
        params: orxnud_domain::json!({}),
        data_class: DataClass::Public,
        context: InvocationContext::new("k", 1, "c"),
        assessed_risk: RiskClass::Low,
        policy_version: "forged".to_owned(),
    };

    // --- Escape 2: forge the authorisation proof. Also private fields. ---
    //
    // Before the seal was tightened these fields were `pub`, which meant anyone
    // could mint a "policy approval" and hand it to `authorise`. That is exactly
    // the failure the choke point exists to prevent, so the test pins the fixed
    // shape as well as the intended one.
    let forged = AuthorisationProof {
        policy_version: "forged".to_owned(),
        approval: None,
        assessed_risk: RiskClass::Low,
    };

    // --- Escape 3: mutate a proof obtained legitimately. Also private. ---
    let mut obtained = AuthorisationProof::issue(
        &PolicySeal::attest("a-crate-that-should-not-be-here"),
        "v1",
        None,
        RiskClass::Low,
    );
    obtained.assessed_risk = RiskClass::Critical;
    obtained.policy_version = "escalated".to_owned();

    // --- Escape 4: an invocation with the wrong argument count, to prove the
    // seal is a required parameter rather than an optional one. ---
    let request = ActionRequest::new(
        TaskId::from("t-1"),
        RunId::from("r-1"),
        0,
        CapabilityId::from("c"),
        orxnud_domain::json!({}),
        DataClass::Public,
        DataClass::Public,
    );
    let _ = CapabilityInvocation::authorise(
        request,
        Actor::Human { user: UserId::from("u"), via: AuthChannel::LocalInteractive },
        InvocationContext::new("k", 1, "c"),
        forged,
    );
}
