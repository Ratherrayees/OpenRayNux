//! The authority-bearing types, and the crate that owns them.
//!
//! # Why these types live here and not in `orxnud-domain`
//!
//! Because ownership is the only thing that decides this. `AuthorisationProof::issue`
//! and `CapabilityInvocation::authorise` used to be `pub` in `orxnud-domain`, and the
//! boundary was a `PolicySeal` that any crate could construct:
//!
//! ```text
//! let seal  = PolicySeal::attest("anything");            // pub
//! let proof = AuthorisationProof::issue(&seal, "v1", None, RiskClass::Low);  // pub
//! let inv   = CapabilityInvocation::authorise(&seal, req, actor, ctx, proof); // pub
//! ```
//!
//! `_seal` was bound to `_` in both constructors and never read, so the "proof" was a
//! value the caller supplied. `issued_by` was compared with nothing. What actually
//! prevented forgery was gate G2 — a lexical CI scan for four identifiers — and the
//! audit showed that scan reporting `ok` on a tree that forges authority three ways.
//!
//! Rust has no friend crates, so "only `orxnud-policy` may construct this" is not
//! expressible while the type lives in a crate `orxnud-policy` depends on. It *is*
//! expressible once the type lives here, because then the constructor can be
//! `pub(crate)` and `rustc` enforces it. No scan, no token, no self-attestation.
//!
//! So the seal is deleted rather than made stronger. A string the holder writes about
//! itself is not provenance, and keeping the type would keep implying that it was.
//!
//! # What this module does not claim
//!
//! `CapabilityInvocation` derives `Serialize`, for audit records and for hashing.
//! Serialising authority *out* is a disclosure risk the caller owns; deserialising it
//! *in* would be an authorisation bypass. Only the first is possible here — there is
//! no `Deserialize`, and no `From`/`TryFrom`/`Default`, and every field is private.
//! A `compile_fail` fixture asserts each of those.

use orxnud_domain::DataClass;
use orxnud_domain::actor::Actor;
use orxnud_domain::approval::ApprovalDigest;
use orxnud_domain::enums::RiskClass;
use orxnud_domain::ids::{CapabilityId, TaskId};
use orxnud_domain::invocation::{ActionRequest, InvocationContext};
use serde::Serialize;

/// Proof that the policy layer evaluated and authorised an action.
///
/// Fields are private, so this cannot be assembled from parts outside
/// `orxnud-domain`. It is the value that makes `CapabilityInvocation`
/// unforgeable, which is the mechanism behind "the LLM must never be the
/// authority that grants itself permission".
///
/// Obtain one from `AuthorisationProof::issue`, which additionally requires a
/// `PolicySeal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorisationProof {
    policy_version: String,
    approval: Option<ApprovalDigest>,
    assessed_risk: RiskClass,
}

impl AuthorisationProof {
    /// Issues a proof.
    ///
    /// Crate-private, and that is the entire authority boundary for this type. It was
    /// `pub` with a `PolicySeal` parameter that was bound to `_` and never read, so
    /// any crate could mint a proof by naming any string.
    #[must_use]
    pub(crate) fn issue(
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

/// Fields are private. The only constructor is `Self::authorise`, which requires
/// an `AuthorisationProof`, and both are `pub(crate)` in this crate.
///
/// A capability adapter never sees this type's `actor` field: the dispatcher
/// strips it. That is deliberate — a capability that learns its caller becomes
/// a confused deputy (ADR-0027, control S8).
///
/// # This type is NOT `Deserialize`, and that is load-bearing
///
/// A derived `Deserialize` is a *second, unrestricted constructor*. It writes the
/// private fields without going through `Self::authorise`, so it bypasses
/// `PolicySeal`, `AuthorisationProof`, and policy evaluation entirely — which is
/// exactly what the private fields were there to prevent.
///
/// This was not theoretical. Before Phase 3, this type derived both `Serialize` and
/// `Deserialize`, and a standalone crate could mint an authorised invocation from a
/// JSON literal, asserting its own `assessed_risk: low` and `policy_version`:
///
/// ```text
/// FORGED OK -> CapabilityId("send-email") risk=Low policy_version=forged
///            params={"to":"attacker@evil.test"}
/// ```
///
/// No policy. No proof. No seal. No human.
///
/// `serde` is a mechanism for constructing a value from external data, and private
/// fields do not make a derived deserializer an authority boundary. The architectural
/// claim in ADR-0012 — "it is not *possible* to do this without going through policy" —
/// was false for this type until the derive was removed.
///
/// Inbound data uses `CapabilityRequest`, which is a *request* and carries no
/// authority to lose. See ADR-0034.
///
/// `Serialize` remains, for audit records and for hashing: serialising an
/// authority-bearing value *out* is a disclosure risk the caller must own, whereas
/// deserialising one *in* is an authorisation bypass. Those are not symmetric.
#[derive(Debug, Clone, PartialEq, Serialize)]
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
    /// The safety here is *type-level*, not documentary: both this method and
    /// `AuthorisationProof::issue` are `pub(crate)`, so the only code in the
    /// workspace that can call either is in this crate — and the only call sites are
    /// inside [`PolicyEngine::authorise`], after a policy evaluation has returned.
    /// A caller that has not evaluated policy cannot call this, and `rustc` is what
    /// says so.
    #[must_use]
    pub(crate) fn authorise(
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
///
/// Fields are private. This type is the argument to `CapabilityAdapter::invoke`,
/// which is `pub(crate)` in `orxnud-capability`; while its fields were public, any
/// crate could build one by hand and call an adapter with it, skipping policy, the
/// approval, and the audit record.
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchView<'a> {
    /// Step index, for correlation in adapter logs.
    step: u32,
    /// The capability id.
    capability: &'a CapabilityId,
    /// The validated parameters.
    params: &'a serde_json::Value,
    /// The effective data class.
    data_class: DataClass,
    /// Deadline, idempotency key, and cancellation handle.
    context: &'a InvocationContext,
}

impl<'a> DispatchView<'a> {
    /// Step index, for correlation in adapter logs.
    #[must_use]
    pub fn step(&self) -> u32 {
        self.step
    }

    /// The capability id.
    #[must_use]
    pub fn capability(&self) -> &'a CapabilityId {
        self.capability
    }

    /// The validated parameters.
    #[must_use]
    pub fn params(&self) -> &'a serde_json::Value {
        self.params
    }

    /// The effective data class.
    #[must_use]
    pub fn data_class(&self) -> DataClass {
        self.data_class
    }

    /// Deadline, idempotency key, and cancellation handle.
    #[must_use]
    pub fn context(&self) -> &'a InvocationContext {
        self.context
    }
}
