//! Domain errors.
//!
//! Every variant carries a machine-readable code alongside the human message,
//! because "something went wrong" is a bug (docs-08 §9) and because the
//! dispatcher needs to distinguish "denied" from "malformed" from "timed out"
//! without string matching.

use crate::ids::CapabilityId;

/// A domain-layer failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    /// An identifier was empty or otherwise structurally invalid.
    #[error("invalid {kind} identifier: {reason}")]
    InvalidId {
        /// Which identifier kind.
        kind: &'static str,
        /// Why it was rejected.
        reason: String,
    },

    /// A capability id was referenced that is not in the registry.
    #[error("unknown capability: {0}")]
    UnknownCapability(CapabilityId),

    /// A state transition that the state machine does not permit.
    #[error("illegal task transition: {from:?} -> {to:?}")]
    IllegalTransition {
        /// Origin state.
        from: crate::task_state::TaskState,
        /// Target state.
        to: crate::task_state::TaskState,
    },

    /// An approval digest did not match the operation about to run.
    ///
    /// The anti-Loopjacking check (control S6). This is a hard abort, never a
    /// retry: the operation is not the one that was approved.
    #[error("approval digest mismatch: the operation changed since it was approved")]
    ApprovalDigestMismatch,

    /// An approval was outside its validity window.
    #[error("approval expired at {expires_at_ms} (now {now_ms})")]
    ApprovalExpired {
        /// Expiry, ms since epoch.
        expires_at_ms: i64,
        /// Current time, ms since epoch.
        now_ms: i64,
    },

    /// An actor attempted something only a human may do.
    #[error("actor {label} may not grant authority")]
    ActorMayNotGrant {
        /// The actor's short label.
        label: &'static str,
    },

    /// Parameters failed schema validation.
    #[error("parameters rejected for {capability}: {reason}")]
    InvalidParams {
        /// The capability whose schema was violated.
        capability: CapabilityId,
        /// Why validation failed.
        reason: String,
    },

    /// A data class was used that the action is not permitted to touch.
    #[error("data class {required:?} exceeds the permitted maximum {permitted:?}")]
    DataClassExceeded {
        /// What was required.
        required: crate::enums::DataClass,
        /// The maximum permitted.
        permitted: crate::enums::DataClass,
    },
}

impl DomainError {
    /// A stable, machine-readable code. Used by the protocol layer so clients
    /// branch on a code rather than on prose.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidId { .. } => "invalid_id",
            Self::UnknownCapability(_) => "unknown_capability",
            Self::IllegalTransition { .. } => "illegal_transition",
            Self::ApprovalDigestMismatch => "approval_digest_mismatch",
            Self::ApprovalExpired { .. } => "approval_expired",
            Self::ActorMayNotGrant { .. } => "actor_may_not_grant",
            Self::InvalidParams { .. } => "invalid_params",
            Self::DataClassExceeded { .. } => "data_class_exceeded",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enums::DataClass;
    use crate::task_state::TaskState;

    #[test]
    fn codes_are_distinct() {
        let all = [
            DomainError::InvalidId {
                kind: "task",
                reason: "empty".into(),
            },
            DomainError::UnknownCapability(CapabilityId::new("c")),
            DomainError::IllegalTransition {
                from: TaskState::Completed,
                to: TaskState::Running,
            },
            DomainError::ApprovalDigestMismatch,
            DomainError::ApprovalExpired {
                expires_at_ms: 1,
                now_ms: 2,
            },
            DomainError::ActorMayNotGrant { label: "ai" },
            DomainError::InvalidParams {
                capability: CapabilityId::new("c"),
                reason: "x".into(),
            },
            DomainError::DataClassExceeded {
                required: DataClass::Regulated,
                permitted: DataClass::Public,
            },
        ];
        let mut codes: Vec<&str> = all.iter().map(DomainError::code).collect();
        let before = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), before, "error codes collided");
    }

    #[test]
    fn messages_carry_useful_context() {
        let e = DomainError::IllegalTransition {
            from: TaskState::Completed,
            to: TaskState::Running,
        };
        let msg = e.to_string();
        assert!(msg.contains("Completed"), "message lost context: {msg}");
        assert!(msg.contains("Running"), "message lost context: {msg}");
    }
}
