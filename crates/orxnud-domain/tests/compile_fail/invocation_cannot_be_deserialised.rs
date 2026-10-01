//! A `CapabilityInvocation` must not be constructible from external data.
//!
//! # Why this test exists
//!
//! `CapabilityInvocation` has private fields and one constructor,
//! `authorise`, which requires a `PolicySeal` and an `AuthorisationProof`. For a
//! long time that read as a complete authority boundary — and ADR-0012 leaned on it:
//! *"It is not possible to do this without going through policy."*
//!
//! It was not true. `CapabilityInvocation` also derived `Deserialize`, and a derived
//! `Deserialize` writes private fields without calling any constructor. So the seal
//! guarded a door that had a second, unguarded entrance.
//!
//! The proof that this was exploitable, not merely untidy, is recorded in
//! `orxnud-domain/src/invocation.rs`: a standalone crate outside the workspace built
//! an invocation from a JSON literal and printed
//!
//! ```text
//! FORGED OK -> CapabilityId("send-email") risk=Low policy_version=forged
//! ```
//!
//! with no policy evaluation, no proof, and no seal.
//!
//! # What this pins
//!
//! Inbound data must use `CapabilityRequest`, which carries no authority to forge.
//! This file fails to compile if `Deserialize` is ever re-derived on the invocation,
//! whatever the reason.

use orxnud_domain::CapabilityInvocation;

fn main() {
    // The exploit that motivated removing the derive.
    let json = r#"{
        "task": "t", "step": 0,
        "actor": {"kind": "human", "detail": {"user": "u", "via": "local-interactive"}},
        "capability": "send-email",
        "params": {"to": "attacker@evil.test"},
        "data_class": "regulated",
        "context": {"idempotency_key": "k", "deadline_ms": 1, "cancellation": "c"},
        "assessed_risk": "low",
        "policy_version": "forged"
    }"#;

    // The caller asserts its own risk assessment and policy version. If this
    // compiles, the authority boundary is gone.
    let forged: CapabilityInvocation = serde_json::from_str(json).expect("forged");
    let _ = forged;
}
