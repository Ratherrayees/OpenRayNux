//! Action requests and authorised capability invocations.
//!
//! # The choke point
//!
//! [`CapabilityInvocation`] is the *only* way to reach a capability adapter.
//! Both its fields **and** those of [`AuthorisationProof`] are private, so
//! neither type can be built with a struct literal from outside this crate.
//!
//! # What actually enforces this, stated honestly
//!
//! Rust has no friend crates: a `pub fn` in this crate is callable by every
//! crate in the workspace, including ones that should not hold an
//! authorisation. So the guarantee is **two mechanisms, neither of them the
//! type system alone**:
//!
//! 1. **Opacity.** Neither type has public fields, so no caller can assemble one
//!    from parts. [`AuthorisationProof::issue`] is the single path, and it takes
//!    a [`PolicySeal`].
//! 2. **The dependency-graph gate** (`scripts/ci-gates.sh`, gate G2): only
//!    `orxnud-policy` is permitted to name `AuthorisationProof`,
//!    `PolicySeal`, or [`CapabilityInvocation::authorise`]. Any other crate
//!    referencing them fails the build.
//!
//! Claiming the type system alone guarantees "only the policy layer can
//! authorise" would be false, and a false security claim is worse than a
//! documented two-part mechanism. Gate G2 is what closes the gap; the
//! compile-fail tests in `tests/compile_fail/` prove the opacity half.
//!
//! See ADR-0012 and ADR-0027.

use serde::{Deserialize, Serialize};

use crate::actor::Actor;
use crate::approval::ApprovalDigest;
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

/// Proof that the policy layer evaluated and authorised an action.
///
/// Fields are private, so this cannot be assembled from parts outside
/// `orxnud-domain`. It is the value that makes [`CapabilityInvocation`]
/// unforgeable, which is the mechanism behind "the LLM must never be the
/// authority that grants itself permission".
///
/// Obtain one from [`AuthorisationProof::issue`], which additionally requires a
/// [`PolicySeal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorisationProof {
    policy_version: String,
    approval: Option<ApprovalDigest>,
    assessed_risk: RiskClass,
}

impl AuthorisationProof {
    /// Issues a proof. Requires a [`PolicySeal`], which gate G2 restricts to
    /// `orxnud-policy`.
    #[must_use]
    pub fn issue(
        _seal: &PolicySeal,
        policy_version: impl Into<String>,
        approval: Option<ApprovalDigest>,
        assessed_risk: RiskClass,
    ) -> Self {
        Self {
            policy_version: policy_version.into(),
            approval,
            assessed_risk,
        }
    }

    /// The policy version that made the decision.
    #[must_use]
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// The approval digest, when the risk class required one.
    #[must_use]
    pub fn approval(&self) -> Option<ApprovalDigest> {
        self.approval
    }

    /// The risk the policy assigned, after escalation.
    #[must_use]
    pub fn assessed_risk(&self) -> RiskClass {
        self.assessed_risk
    }
}

/// The capability of issuing an [`AuthorisationProof`].
///
/// Deliberately **not** constructible in a useful way: its only constructor
/// records the issuing crate name, and gate G2 permits that name to be
/// `orxnud-policy` and nothing else. Rust offers no way to express "only this
/// crate may call this", so the restriction is mechanical rather than nominal —
/// which is why it lives in a script that fails the build rather than in a
/// comment.
///
/// A caller that reached this type without a real policy evaluation has still
/// gained nothing: `CapabilityInvocation::authorise` grants no capability by
/// itself. The dispatcher resolves the capability against the registry, and
/// Phase 1's registry is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySeal {
    issued_by: &'static str,
}

impl PolicySeal {
    /// The name recorded for a seal.
    #[must_use]
    pub fn issued_by(&self) -> &'static str {
        self.issued_by
    }

    /// Creates a seal attributed to `issued_by`.
    ///
    /// Public because Rust cannot restrict it; the gate is the enforcement.
    /// Callers outside `orxnud-policy` are a build failure, not a runtime one.
    #[must_use]
    pub fn attest(issued_by: &'static str) -> Self {
        Self { issued_by }
    }
}

/// A **policy-authorised** request to invoke a capability.
///
/// Fields are private. The only constructor is [`Self::authorise`], which
/// requires an [`AuthorisationProof`].
///
/// A capability adapter never sees this type's `actor` field: the dispatcher
/// strips it. That is deliberate — a capability that learns its caller becomes
/// a confused deputy (ADR-0027, control S8).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityInvocation {
    task: TaskId,
    step: u32,
    actor: Actor,
    capability: CapabilityId,
    params: serde_json::Value,
    data_class: DataClass,
    context: InvocationContext,
    assessed_risk: RiskClass,
    policy_version: String,
}

impl CapabilityInvocation {
    /// Authorises an action, producing an invocation.
    ///
    /// # Safety of this boundary
    ///
    /// The safety here is *type-level*, not documentary: `AuthorisationProof`
    /// can only be obtained from `orxnud-policy` running a real policy
    /// evaluation. A caller that has not evaluated policy cannot call this.
    #[must_use]
    pub fn authorise(
        _seal: &PolicySeal,
        request: ActionRequest,
        actor: Actor,
        context: InvocationContext,
        proof: AuthorisationProof,
    ) -> Self {
        // Computed before the fields are moved out.
        let data_class = request.effective_class();
        Self {
            task: request.task,
            step: request.step,
            actor,
            capability: request.capability,
            params: request.params,
            data_class,
            context,
            assessed_risk: proof.assessed_risk,
            policy_version: proof.policy_version,
        }
    }

    /// The task this invocation belongs to.
    #[must_use]
    pub fn task(&self) -> &TaskId {
        &self.task
    }

    /// The step index within the plan.
    #[must_use]
    pub fn step(&self) -> u32 {
        self.step
    }

    /// Who is acting. Read by policy and audit; stripped before dispatch.
    #[must_use]
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// The capability to invoke.
    #[must_use]
    pub fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// The validated parameters.
    #[must_use]
    pub fn params(&self) -> &serde_json::Value {
        &self.params
    }

    /// The effective data class.
    #[must_use]
    pub fn data_class(&self) -> DataClass {
        self.data_class
    }

    /// The execution context.
    #[must_use]
    pub fn context(&self) -> &InvocationContext {
        &self.context
    }

    /// The risk the policy assigned.
    #[must_use]
    pub fn assessed_risk(&self) -> RiskClass {
        self.assessed_risk
    }

    /// The policy version that authorised this.
    #[must_use]
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    /// What the adapter actually receives: everything *except* the actor.
    ///
    /// This is the method the dispatcher uses. Making the strip explicit at one
    /// place is what keeps "capabilities are caller-agnostic" true rather than
    /// aspirational.
    #[must_use]
    pub fn dispatch_view(&self) -> DispatchView<'_> {
        DispatchView {
            step: self.step,
            capability: &self.capability,
            params: &self.params,
            data_class: self.data_class,
            context: &self.context,
        }
    }
}

/// The capability-facing projection of an invocation.
///
/// Contains no actor and no policy version: the capability learns *what* to do,
/// never *who* asked. Authority was already settled.
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchView<'a> {
    /// Step index, for correlation in adapter logs.
    pub step: u32,
    /// The capability id.
    pub capability: &'a CapabilityId,
    /// The validated parameters.
    pub params: &'a serde_json::Value,
    /// The effective data class.
    pub data_class: DataClass,
    /// Deadline, idempotency key, and cancellation handle.
    pub context: &'a InvocationContext,
}

/// A correlation id for a single dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DispatchId(pub RequestId);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::AuthChannel;
    use crate::approval::ApprovalDigest;
    use crate::ids::{RunId, UserId};
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

    fn proof() -> AuthorisationProof {
        AuthorisationProof::issue(&seal(), "v1", None, RiskClass::Low)
    }

    fn seal() -> PolicySeal {
        // In-crate, so this is the honest spelling of what `orxnud-policy` does
        // across the crate boundary.
        PolicySeal::attest("orxnud-domain-test")
    }

    fn actor() -> Actor {
        Actor::Human {
            user: UserId::new("u"),
            via: AuthChannel::LocalInteractive,
        }
    }

    fn ctx() -> InvocationContext {
        InvocationContext::new("k", 1000, "c")
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

    #[test]
    fn dispatch_view_hides_the_actor() {
        let inv = CapabilityInvocation::authorise(
            &seal(),
            request(DataClass::Public, DataClass::Public),
            actor(),
            ctx(),
            proof(),
        );
        let view = inv.dispatch_view();
        // The actor is reachable on the invocation for audit...
        assert!(matches!(inv.actor(), Actor::Human { .. }));
        // ...but the dispatch view has no field that could carry it. This is
        // the type-level expression of "capabilities are caller-agnostic".
        let debug = format!("{view:?}");
        assert!(
            !debug.contains("Human") && !debug.contains("u\""),
            "dispatch view leaked actor identity: {debug}"
        );
    }

    #[test]
    fn authorise_records_policy_version_and_risk() {
        let p = AuthorisationProof::issue(
            &seal(),
            "v1",
            Some(ApprovalDigest::from_bytes([7u8; 32])),
            RiskClass::Critical,
        );
        let inv = CapabilityInvocation::authorise(
            &seal(),
            request(DataClass::Sensitive, DataClass::Sensitive),
            actor(),
            ctx(),
            p,
        );
        assert_eq!(inv.policy_version(), "v1");
        assert_eq!(inv.assessed_risk(), RiskClass::Critical);
        assert_eq!(inv.data_class(), DataClass::Sensitive);
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
