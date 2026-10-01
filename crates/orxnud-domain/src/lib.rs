//! `OpenRayNux` domain types and invariants.
//!
//! # What this crate is
//!
//! Pure, dependency-light *types* and the invariants that constrain them. There
//! is no I/O, no async, no storage, and no platform knowledge here. That is not
//! stylistic: the portable-core CI gate (G9) builds this crate for
//! `wasm32-unknown-unknown`, so any dependency or construct that assumes an OS
//! would fail the gate.
//!
//! # The two load-bearing ideas
//!
//! 1. **The model proposes; a deterministic engine disposes** (ADR-0012).
//!    [`Proposal`] is *inert data*. It has no method that reaches an adapter,
//!    and a compile-fail test (`tests/compile_fail/proposal_is_inert.rs`)
//!    proves that. Writing the unsafe path requires deliberately constructing an
//!    authorised [`CapabilityInvocation`], which only `orxnud-policy` can do.
//!
//! 2. **Who is acting is a first-class value** (ADR-0027). [`Actor`] is carried
//!    on every invocation and carries its own *delegation chain*, so authority
//!    can never be inferred from context.
//!
//! # What is deliberately absent
//!
//! There is no task engine, no scheduler, no capability, no policy evaluation,
//! and no memory here. This crate is the vocabulary; behaviour lives elsewhere.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

pub mod actor;
pub mod approval;
pub mod enums;
pub mod error;
pub mod ids;
pub mod intent;
pub mod invocation;
pub mod platform;
pub mod task_state;

pub use actor::{Actor, AuthChannel, ModelProvenance, SystemComponent};
pub use approval::{ApprovalDigest, ApprovalRecord, NormalizedParams};
pub use enums::{
    ApprovalLevel, CapabilityHealth, DataClass, IsolationTier, RiskClass, StateClass,
    StateConsistency,
};
pub use error::DomainError;
pub use ids::{
    CapabilityId, ExternalSource, GrantId, RequestId, RunId, ScheduleId, TaskId, UserId, WorkflowId,
};
pub use intent::{IntentKind, Proposal, ProposedStep};
pub use invocation::{
    ActionRequest, AuthorisationProof, CapabilityInvocation, CapabilityRequest, DispatchView,
    InvocationContext, PolicySeal,
};
pub use platform::{FsContract, NotificationRequest, NotifyContract, SecretRef, SecretsContract};
pub use task_state::{MisfirePolicy, ScheduleFire, ScheduleSpec, TaskKind, TaskState, TaskStatus};

/// Re-export of [`serde_json::json!`] so downstream crates and compile-fail
/// cases can build untrusted parameter payloads without declaring their own
/// `serde_json` dependency.
pub use serde_json::json;
