//! `orxnud-domain` must not export an authority-bearing type at all.
//!
//! The authority types moved to `orxnud-policy`, which is the crate that owns
//! authority and the only place its constructors can be `pub(crate)`. Rust cannot
//! express "only this crate may construct this" across a crate boundary: if the type
//! lives in a crate `orxnud-policy` depends on, any `pub` constructor on it is callable
//! by everything downstream. So the types had to move, and this file pins the
//! consequence from the outside.
//!
//! It fails to compile if any of these names is ever re-exported from the domain crate
//! — which would re-create the exact escape the third audit reproduced:
//!
//! ```text
//! PolicySeal::attest("anything")                    -> a seal
//! AuthorisationProof::issue(&seal, "v1", ..)        -> a proof
//! CapabilityInvocation::authorise(&seal, .., proof)  -> an authorised invocation
//! ```
//!
//! What is proved here is the *absence of the export*. That only the policy crate can
//! construct the types is proved separately, in
//! `crates/orxnud-capability/tests/compile_fail/`.

use orxnud_domain::{
    ActionRequest, AuthorisationProof, CapabilityInvocation, DispatchView, PolicySeal,
};

fn main() {
    // Each of these names is unresolvable, and that is the assertion.
    let _ = PolicySeal::attest("x");
    let _ = AuthorisationProof::issue("v1", None, orxnud_domain::enums::RiskClass::Low);
    let _ = std::mem::size_of::<CapabilityInvocation>();
    let _ = std::mem::size_of::<DispatchView<'static>>();
    // And the domain's own untrusted request type is still nameable, so this file is
    // not failing merely because the imports are wrong.
    let _ = ActionRequest::new(
        orxnud_domain::ids::TaskId::new("t"),
        orxnud_domain::ids::RunId::new("r"),
        0,
        orxnud_domain::ids::CapabilityId::new("c"),
        orxnud_domain::json!({}),
        orxnud_domain::DataClass::Public,
        orxnud_domain::DataClass::Public,
    );
}
