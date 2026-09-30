//! The decision type: allow, gate, or deny. Never anything else.

use serde::{Deserialize, Serialize};

use orxnud_domain::{Actor, ApprovalDigest, DataClass, RiskClass};

/// Why an action was refused.
///
/// Every variant is a *specific* reason. A policy engine that returns a single
/// "denied" is unauditable and un-debuggable, and a user who cannot tell why
/// something was refused cannot correct it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "reason", content = "detail")]
pub enum DenialReason {
    /// The actor has no authority root, so it cannot borrow anyone's authority.
    NoAuthorityRoot {
        /// Which kind of actor.
        actor: String,
    },

    /// Only a human may grant authority, and this actor tried.
    ActorMayNotGrant {
        /// Which kind of actor.
        actor: String,
    },

    /// No capability with this id is registered.
    UnknownCapability {
        /// The id that was not found.
        capability: String,
    },

    /// Parameters did not match the capability's declared schema.
    InvalidParams {
        /// The capability whose schema was violated.
        capability: String,
        /// The validation failure.
        detail: String,
    },

    /// The data class exceeds what the task is permitted to touch.
    DataClassExceeded {
        /// What the action needed.
        required: DataClass,
        /// The maximum permitted.
        permitted: DataClass,
    },

    /// Data of this class may not leave the machine without explicit consent.
    EgressNotConsented {
        /// The class that needed consent.
        data_class: DataClass,
    },

    /// No valid grant for this actor and capability.
    NoGrant {
        /// The capability.
        capability: String,
    },

    /// The grant existed but had expired.
    GrantExpired {
        /// The capability.
        capability: String,
        /// Expiry, ms since epoch.
        expired_at_ms: i64,
        /// Now, ms since epoch.
        now_ms: i64,
    },

    /// The action needs an approval and none was supplied.
    ApprovalRequired {
        /// The risk that made it necessary.
        risk: RiskClass,
    },

    /// The supplied approval is outside its validity window.
    ApprovalExpired {
        /// Expiry, ms since epoch.
        expired_at_ms: i64,
        /// Now, ms since epoch.
        now_ms: i64,
    },

    /// **The approval does not match the action about to run.**
    ///
    /// The anti-Loopjacking check (control S6). A hard abort: the operation is
    /// not the one that was approved.
    ApprovalDigestMismatch,

    /// A spend ceiling would be exceeded.
    BudgetExceeded {
        /// Which ceiling.
        scope: String,
        /// The ceiling, in the ceiling's unit.
        limit: u64,
        /// What was already spent.
        spent: u64,
    },

    /// The policy set could not be read. **Fails closed.**
    PolicyUnavailable {
        /// The underlying reason.
        detail: String,
    },

    /// The audit journal could not be written. **Fails closed.**
    ///
    /// An action that cannot be recorded must not run, or the journal is not a
    /// record of anything.
    AuditUnavailable {
        /// The underlying reason.
        detail: String,
    },
}

impl DenialReason {
    /// A stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoAuthorityRoot { .. } => "no_authority_root",
            Self::ActorMayNotGrant { .. } => "actor_may_not_grant",
            Self::UnknownCapability { .. } => "unknown_capability",
            Self::InvalidParams { .. } => "invalid_params",
            Self::DataClassExceeded { .. } => "data_class_exceeded",
            Self::EgressNotConsented { .. } => "egress_not_consented",
            Self::NoGrant { .. } => "no_grant",
            Self::GrantExpired { .. } => "grant_expired",
            Self::ApprovalRequired { .. } => "approval_required",
            Self::ApprovalExpired { .. } => "approval_expired",
            Self::ApprovalDigestMismatch => "approval_digest_mismatch",
            Self::BudgetExceeded { .. } => "budget_exceeded",
            Self::PolicyUnavailable { .. } => "policy_unavailable",
            Self::AuditUnavailable { .. } => "audit_unavailable",
        }
    }

    /// Whether this refusal is the user's fault or ours.
    ///
    /// Useful in the UI: "you have not granted this" and "our policy engine is
    /// broken" call for very different messages.
    #[must_use]
    pub fn is_user_actionable(&self) -> bool {
        !matches!(
            self,
            Self::PolicyUnavailable { .. } | Self::AuditUnavailable { .. } | Self::NoAuthorityRoot { .. }
        )
    }
}

/// The policy engine's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "outcome", content = "detail")]
pub enum Decision {
    /// Permitted, no approval needed.
    Allow {
        /// The risk assigned.
        risk: RiskClass,
    },
    /// Requires an explicit, digest-bound, single-use human approval.
    Gate {
        /// The risk that made it necessary.
        risk: RiskClass,
        /// The digest the approval must match.
        required_digest: ApprovalDigest,
        /// The actor the approval must come from.
        approver: Actor,
    },
    /// Refused.
    Deny {
        /// Why.
        reason: DenialReason,
    },
}

impl Decision {
    /// Whether the action may proceed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow { .. })
    }

    /// Whether the action needs an approval first.
    #[must_use]
    pub fn is_gated(&self) -> bool {
        matches!(self, Self::Gate { .. })
    }

    /// Whether the action was refused.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }

    /// The denial reason, if denied.
    #[must_use]
    pub fn denial(&self) -> Option<&DenialReason> {
        match self {
            Self::Deny { reason } => Some(reason),
            _ => None,
        }
    }
}

/// A policy failure distinct from a denial.
///
/// A denial is a *decision*. A failure is the engine being unable to decide. Both
/// result in no action, but they are logged differently, because "we refused"
/// and "we could not tell" have different causes.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The policy set could not be loaded.
    #[error("policy set unavailable: {0}")]
    Unavailable(String),

    /// The audit journal could not be written.
    #[error("audit journal unavailable: {0}")]
    AuditUnavailable(String),

    /// A capability's declared schema could not be evaluated.
    #[error("capability schema invalid: {0}")]
    InvalidSchema(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn all_reasons() -> Vec<DenialReason> {
        vec![
            DenialReason::NoAuthorityRoot { actor: "external".into() },
            DenialReason::ActorMayNotGrant { actor: "ai".into() },
            DenialReason::UnknownCapability { capability: "c".into() },
            DenialReason::InvalidParams { capability: "c".into(), detail: "x".into() },
            DenialReason::DataClassExceeded {
                required: DataClass::Regulated,
                permitted: DataClass::Public,
            },
            DenialReason::EgressNotConsented { data_class: DataClass::Sensitive },
            DenialReason::NoGrant { capability: "c".into() },
            DenialReason::GrantExpired {
                capability: "c".into(),
                expired_at_ms: 1,
                now_ms: 2,
            },
            DenialReason::ApprovalRequired { risk: RiskClass::High },
            DenialReason::ApprovalExpired { expired_at_ms: 1, now_ms: 2 },
            DenialReason::ApprovalDigestMismatch,
            DenialReason::BudgetExceeded {
                scope: "daily".into(),
                limit: 10,
                spent: 11,
            },
            DenialReason::PolicyUnavailable { detail: "x".into() },
            DenialReason::AuditUnavailable { detail: "x".into() },
        ]
    }

    #[test]
    fn denial_codes_are_distinct() {
        let mut codes: BTreeSet<&str> = BTreeSet::new();
        for r in all_reasons() {
            assert!(codes.insert(r.code()), "duplicate code: {}", r.code());
        }
        assert_eq!(codes.len(), 14);
    }

    #[test]
    fn our_own_failures_are_not_the_users_fault() {
        for r in [
            DenialReason::PolicyUnavailable { detail: "x".into() },
            DenialReason::AuditUnavailable { detail: "x".into() },
            DenialReason::NoAuthorityRoot { actor: "external".into() },
        ] {
            assert!(!r.is_user_actionable(), "{} should not be user-actionable", r.code());
        }
        assert!(DenialReason::NoGrant { capability: "c".into() }.is_user_actionable());
    }

    #[test]
    fn decision_predicates_are_exclusive() {
        let allow = Decision::Allow { risk: RiskClass::Low };
        let deny = Decision::Deny { reason: DenialReason::ApprovalDigestMismatch };
        let gate = Decision::Gate {
            risk: RiskClass::High,
            required_digest: ApprovalDigest::from_bytes([1u8; 32]),
            approver: Actor::System { component: orxnud_domain::actor::SystemComponent::Backup },
        };
        for d in [&allow, &gate, &deny] {
            let n = [d.is_allowed(), d.is_gated(), d.is_denied()].iter().filter(|b| **b).count();
            assert_eq!(n, 1, "a decision must be exactly one of allow/gate/deny");
        }
        assert!(deny.denial().is_some());
        assert!(allow.denial().is_none());
    }

    #[test]
    fn a_denial_always_carries_a_reason() {
        // A bare "denied" is unauditable.
        for r in all_reasons() {
            let d = Decision::Deny { reason: r };
            assert!(d.denial().is_some());
        }
    }
}
