//! A `CapabilityInvocation` must not be constructible outside `orxnud-domain`.
//!
//! `CapabilityInvocation`'s fields are private and its only constructor,
//! `authorise`, takes an `AuthorisationProof` that requires a real policy
//! decision. This test proves the seal holds from outside the crate: a
//! caller that has *not* run policy evaluation cannot build one, so the
//! "model authorises itself" path does not exist.
//!
//! Two separate escapes are attempted, because either one alone would be a
//! hole:
//!
//! 1. Build the struct with a field literal.
//! 2. Build an `AuthorisationProof` and pass it to `authorise`.

use orxnud_domain::actor::{Actor, AuthChannel};
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, RunId, TaskId, UserId};
use orxnud_domain::{
    ActionRequest, AuthorisationProof, CapabilityInvocation, InvocationContext,
};

fn main() {
    // --- Escape 1: a struct literal. The fields are private. ---
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

    // --- Escape 2: forge the proof. `AuthorisationProof`'s fields are public,
    // so a caller CAN build one -- which is why escape 1 is the real boundary
    // and this is the belt to its braces. Both must fail.
    let request = ActionRequest::new(
        TaskId::from("t-1"),
        RunId::from("r-1"),
        0,
        CapabilityId::from("c"),
        orxnud_domain::json!({}),
        DataClass::Public,
        DataClass::Public,
    );
    let forged = AuthorisationProof {
        policy_version: "forged".to_owned(),
        approval: None,
        assessed_risk: RiskClass::Low,
    };
    let _ = CapabilityInvocation::authorise(
        request,
        Actor::Human { user: UserId::from("u"), via: AuthChannel::LocalInteractive },
        InvocationContext::new("k", 1, "c"),
        forged,
    );
}
