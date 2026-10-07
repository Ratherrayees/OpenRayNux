//! The authority types cannot be assembled field by field.
//!
//! `CapabilityInvocation` and `AuthorisationProof` have private fields and no public
//! field-setter, so the only way to obtain either is through `orxnud-policy`'s
//! `pub(crate)` constructors. A struct literal is the other way, and it is closed.
//!
//! This file deliberately contains nothing else. When several escapes share one
//! fixture, `rustc` reports the resolution failures first and drops the later
//! type-check diagnostics, so the recorded `.stderr` would not mention these private
//! fields at all and the fixture would pass without ever proving them. One escape per
//! file keeps each `.stderr` pinned to the diagnostic that proves it.

use orxnud_domain::actor::{Actor, AuthChannel};
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, TaskId, UserId};
use orxnud_domain::InvocationContext;
use orxnud_policy::authority::{AuthorisationProof, CapabilityInvocation};

fn main() {
    let _invocation = CapabilityInvocation {
        task: TaskId::new("t-1"),
        step: 0,
        actor: Actor::Human { user: UserId::new("u"), via: AuthChannel::LocalInteractive },
        capability: CapabilityId::new("c"),
        params: orxnud_domain::json!({}),
        data_class: DataClass::Public,
        context: InvocationContext::new("k", 1, "c"),
        assessed_risk: RiskClass::Low,
        policy_version: "forged".to_owned(),
    };

    let _proof = AuthorisationProof {
        policy_version: "forged".to_owned(),
        approval: None,
        assessed_risk: RiskClass::Low,
    };
}
