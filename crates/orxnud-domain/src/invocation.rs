//! Action requests: what a caller asks for, before anything has been authorised.
//!
//! # There are no authorised invocations in this crate
//!
//! `CapabilityInvocation`, `AuthorisationProof` and `DispatchView` used to
//! live here, and this module documented a two-part enforcement story: private
//! fields, plus gate G2's lexical scan to stop other crates naming the minting
//! verbs. The second half is the part that was not true.
//!
//! Gate G2 reported `ok` on a tree that forged authority three separate ways
//! from a standalone crate, because a lexical scan cannot see what a token
//! *means* -- and a third of the escapes named none of the symbols it looked
//! for. A checker that cannot fail is worse than no checker, because it reports
//! `ok` on the trees it exists to catch.
//!
//! So the types moved to `orxnud-policy`, next to the constructors that mint
//! them, and those constructors are `pub(crate)`. Rust cannot say "callable by
//! exactly one crate" about a `pub` item, which is the whole reason the seal was
//! needed; it can say it about a `pub(crate)` one. The boundary is now decided
//! by `rustc` rather than by a pattern match over source text.
//!
//! What is left here is deliberately untrusted: a caller must be able to
//! describe the action it wants. `CapabilityRequest` and [`ActionRequest`]
//! carry no authority to forge, and neither can be promoted into something that
//! does -- there is no `From`/`Into` from a request to an invocation.
//!
//! See ADR-0012 and ADR-0027.

use serde::{Deserialize, Serialize};

use crate::enums::{DataClass, RiskClass};
use crate::ids::{CapabilityId, RequestId, RunId, TaskId};

/// A validated request to perform an action, before policy evaluation.
///
/// Produced by deterministic validation from a `Proposal`. Still inert: this
/// has not been authorised and cannot reach an adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionRequest {
    /// The task this belongs to.
    pub task: TaskId,
    /// The run that produced it.
    pub run: RunId,
    /// The step index within the plan.
    pub step: u32,
    /// The capability to invoke.
    pub capability: CapabilityId,
    /// Validated parameters, matching the capability's declared schema.
    pub params: serde_json::Value,
    /// The highest data class of everything this action may read.
    pub input_class: DataClass,
    /// The highest data class of anything this action may emit.
    pub output_class: DataClass,
}

impl ActionRequest {
    /// Builds a validated request with the most sensitive of the two classes as
    /// the effective class, so a caller cannot understate it.
    #[must_use]
    pub fn new(
        task: TaskId,
        run: RunId,
        step: u32,
        capability: CapabilityId,
        params: serde_json::Value,
        input_class: DataClass,
        output_class: DataClass,
    ) -> Self {
        Self {
            task,
            run,
            step,
            capability,
            params,
            input_class,
            output_class,
        }
    }

    /// The single effective data class for this action.
    #[must_use]
    pub fn effective_class(&self) -> DataClass {
        self.input_class.combine(self.output_class)
    }

    /// The risk class implied by the capability's declared risk and this
    /// action's effective data class.
    ///
    /// Deliberately *escalating*: a low-risk capability handling regulated data
    /// is not a low-risk action.
    #[must_use]
    pub fn effective_risk(&self, declared: RiskClass) -> RiskClass {
        if self.effective_class() >= DataClass::Regulated && declared < RiskClass::High {
            RiskClass::High
        } else {
            declared
        }
    }
}

/// Ambient context every invocation carries: deadlines, cancellation,
/// idempotency.
///
/// A separate struct because these are the *execution* concerns, as opposed to
/// the *identity and authority* concerns on the invocation itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationContext {
    /// Idempotency key. Deterministic from `(task, step, attempt_class)` so a
    /// retry reuses it and a *different* action gets a different one (S7).
    pub idempotency_key: String,
    /// Deadline for the whole invocation, in milliseconds.
    pub deadline_ms: u64,
    /// An opaque cancellation token handle, resolved by the dispatcher.
    pub cancellation: String,
}

impl InvocationContext {
    /// Builds a context with an explicit deadline and cancellation handle.
    #[must_use]
    pub fn new(
        idempotency_key: impl Into<String>,
        deadline_ms: u64,
        cancellation: impl Into<String>,
    ) -> Self {
        Self {
            idempotency_key: idempotency_key.into(),
            deadline_ms,
            cancellation: cancellation.into(),
        }
    }
}

// ---- moved to `orxnud-policy::authority` (AuthorisationProof) ----

// ---- moved to `orxnud-policy::authority` (PolicySeal, deleted) ----

/// An **untrusted inbound request** to invoke a capability.
///
/// # What this type means
///
/// > "Someone asked for this."
///
/// It is the only capability-shaped type that is allowed to come *in* from outside
/// the process: JSON-RPC frames, the CLI, a GUI, a TUI, a voice transcript, a DM, an
/// API call, a scheduled event, an external integration. Every one of those ingress
/// paths converges here, and every one of them is untrusted.
///
/// # What it deliberately does not carry
///
/// No `assessed_risk`, no `policy_version`, no approval digest, no credential
/// handle, no `PolicySeal`, no `AuthorisationProof`. Those are *derived by trusted
/// deterministic code* during authorisation. A field here that a caller could set
/// would be a field the caller could lie about.
///
/// # The distinction this type exists to make
///
/// ```text
/// CapabilityRequest  == "someone asked for this"
/// ActionRequest      == "validated against the capability's schema"
/// CapabilityInvocation == "OpenRayNux authorised this exact action to execute"
/// ```
///
/// Only the last one can reach an adapter. Getting these confused is how a
/// system ends up treating a *request* as an *authorisation*, which is the confused
/// deputy of ADR-0027 (TH-04) wearing a different hat.
///
/// Note the deliberate difference from [`ActionRequest`]: that type is bound to a
/// specific task and run, because it comes from *deterministic validation of a plan*
/// inside the daemon. This type knows nothing about tasks — it is what arrives before
/// any plan exists. Converting one into the other is a step of the authorisation
/// pipeline, not a field copy.
///
/// `orxnud_policy::CapabilityInvocation::authorise` is not a method on this
/// type precisely because authorisation needs an actor, a policy evaluation and a
/// proof, none of which exist at ingress.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// Which capability the caller wants.
    pub capability: CapabilityId,
    /// The thing being acted on, as an opaque string.
    ///
    /// Opaque here on purpose: normalisation against a capability's schema happens in
    /// validation, so the digest that an approval binds to is computed from *validated*
    /// parameters and not from whatever the caller happened to send.
    pub target: String,
    /// The parameters, as sent. Unvalidated and unnormalised.
    pub parameters: serde_json::Value,
    /// A caller-supplied correlation handle, for logging and rate-limiting.
    ///
    /// Not an idempotency key. Idempotency keys are *derived* from
    /// `(task, step, attempt_class)` so a retry reuses one and a different action
    /// cannot collide with it; a caller-supplied key would let a caller choose to
    /// collide.
    pub request_id: RequestId,
}

// ---- moved to `orxnud-policy::authority` (CapabilityInvocation) ----

// ---- moved to `orxnud-policy::authority` (DispatchView) ----

/// A correlation id for a single dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DispatchId(pub RequestId);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::RunId;
    use proptest::prelude::*;

    fn request(a: DataClass, b: DataClass) -> ActionRequest {
        ActionRequest::new(
            TaskId::new("t"),
            RunId::new("r"),
            0,
            CapabilityId::new("c"),
            serde_json::json!({"x": 1}),
            a,
            b,
        )
    }

    fn request_dto() -> CapabilityRequest {
        CapabilityRequest {
            capability: CapabilityId::new("send-email"),
            target: "user@example.test".to_string(),
            parameters: serde_json::json!({"subject": "hi"}),
            request_id: RequestId::new("req-1"),
        }
    }

    /// The inbound DTO is a *request*, and deserialising one is not an escape.
    ///
    /// The counterpart to `invocation_cannot_be_deserialised`: this type is
    /// *supposed* to come in from outside, so `Deserialize` here is the feature
    /// working rather than a hole. Stating it explicitly is what makes the
    /// asymmetry legible -- one of the two capability-shaped types accepts
    /// external data, and the one that carries authority does not.
    #[test]
    fn an_untrusted_request_deserialises_because_it_carries_no_authority() {
        let json = serde_json::to_string(&request_dto()).expect("serialise");
        let back: CapabilityRequest = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, request_dto());
        // The point is what it does NOT carry: no risk, no policy version, no digest,
        // no actor. There is no field for any of them, so there is nothing to forge.
        let rendered = serde_json::to_string(&back).expect("serialise again");
        for forbidden in ["risk", "policy", "digest", "actor", "seal"] {
            assert!(
                !rendered.contains(forbidden),
                "the inbound DTO grew a `{forbidden}` field: {rendered}"
            );
        }
    }

    #[test]
    fn effective_class_is_the_more_sensitive_side() {
        assert_eq!(
            request(DataClass::Public, DataClass::Regulated).effective_class(),
            DataClass::Regulated
        );
        assert_eq!(
            request(DataClass::Sensitive, DataClass::Personal).effective_class(),
            DataClass::Sensitive
        );
    }

    #[test]
    fn regulated_data_escalates_a_low_risk_capability() {
        // A "read" capability over regulated data is not a low-risk action.
        let req = request(DataClass::Regulated, DataClass::Regulated);
        assert_eq!(req.effective_risk(RiskClass::Low), RiskClass::High);
        assert!(req.effective_risk(RiskClass::Low).requires_approval());
    }

    #[test]
    fn regulated_data_does_not_escalate_an_already_high_risk_capability() {
        let req = request(DataClass::Regulated, DataClass::Regulated);
        assert_eq!(req.effective_risk(RiskClass::Critical), RiskClass::Critical);
    }

    #[test]
    fn public_data_leaves_risk_untouched() {
        let req = request(DataClass::Public, DataClass::Public);
        assert_eq!(req.effective_risk(RiskClass::Medium), RiskClass::Medium);
    }

    proptest! {
        /// The effective class is never less sensitive than either input, and
        /// risk never decreases.
        #[test]
        fn effective_class_and_risk_never_degrade(a: u8, b: u8, r: u8) {
            let classes = [
                DataClass::Public,
                DataClass::Personal,
                DataClass::Sensitive,
                DataClass::Regulated,
            ];
            let risks = [
                RiskClass::Low,
                RiskClass::Medium,
                RiskClass::High,
                RiskClass::Critical,
            ];
            let req = request(classes[(a % 4) as usize], classes[(b % 4) as usize]);
            let declared = risks[(r % 4) as usize];
            let eff = req.effective_class();
            prop_assert!(eff >= req.input_class);
            prop_assert!(eff >= req.output_class);
            prop_assert!(req.effective_risk(declared) >= declared);
        }
    }
}
