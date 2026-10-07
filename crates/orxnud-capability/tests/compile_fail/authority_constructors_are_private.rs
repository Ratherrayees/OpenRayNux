//! `issue` and `authorise` are `pub(crate)`, so only `orxnud-policy` can call them.
//!
//! Before this change both were `pub`, and the third audit chained them from a
//! standalone crate into a usable invocation:
//!
//! ```text
//! PolicySeal::attest("anything")                    -> a seal
//! AuthorisationProof::issue(&seal, "v1", None, Low) -> a proof
//! CapabilityInvocation::authorise(&seal, .., proof) -> an authorised invocation
//!     capability = filesystem/write-text
//!     params     = {"path":"~/.ssh/authorized_keys","contents":"attacker"}
//! ```
//!
//! No policy evaluation, no human approval, no approval digest. The seal was meant to
//! prevent exactly this and its `issued_by` was compared against nothing.
//!
//! Rust cannot express "callable by exactly one crate" for a `pub` item, which is why
//! the type had to live in the crate that is allowed to call the constructor. Moving it
//! there is what turns this from a lexical CI scan into something `rustc` decides.

use orxnud_domain::actor::{Actor, AuthChannel};
use orxnud_domain::enums::{RiskClass};
use orxnud_domain::ids::{CapabilityId, RunId, TaskId, UserId};
use orxnud_domain::{ActionRequest, InvocationContext};
use orxnud_policy::authority::{AuthorisationProof, CapabilityInvocation};

fn main() {
    let _proof = AuthorisationProof::issue("v1", None, RiskClass::Low);

    // Even with a caller-chosen approval digest and a caller-chosen risk class.
    let _proof = AuthorisationProof::issue(
        "v1",
        Some(orxnud_domain::ApprovalDigest::from_bytes([7u8; 32])),
        RiskClass::Critical,
    );

    let request = ActionRequest::new(
        TaskId::new("t-1"),
        RunId::new("r-1"),
        0,
        CapabilityId::new("filesystem/write-text"),
        orxnud_domain::json!({}),
        orxnud_domain::DataClass::Public,
        orxnud_domain::DataClass::Public,
    );
    let _invocation = CapabilityInvocation::authorise(
        request,
        Actor::Human { user: UserId::new("u"), via: AuthChannel::LocalInteractive },
        InvocationContext::new("k", 1, "c"),
        AuthorisationProof::issue("v1", None, RiskClass::Low),
    );
}
