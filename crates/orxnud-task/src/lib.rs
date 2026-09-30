//! Task lifecycle types and the **ADR-0029 conformance harness**.
//!
//! # The real engine is not in this crate yet
//!
//! Phase 2 writes it. Phase 1 writes the **contract** it must satisfy and a
//! deliberately trivial in-test fixture to make that contract executable.
//!
//! This ordering is the whole point. docs-13 §7:
//!
//! > The harness is the deliverable; the queue is not. … the real queue arrives
//! > in Phase 2, and must pass the same suite **unchanged**.
//!
//! If the tests were written against the implementation, they would describe the
//! implementation. Written against properties, they describe the *contract*,
//! and swapping engines is an implementation change rather than a rewrite.
//!
//! # What the harness is not
//!
//! It is not a scheduler, not a queue, and not a partial engine. The fixture
//! used to exercise it lives in `tests/support/`, is never compiled into the
//! library, and exists only to make the properties runnable. See
//! [`conformance::TaskEngineContract`] for what an implementation must provide.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod conformance;

pub use orxnud_domain::task_state::{
    MisfirePolicy, ScheduleFire, ScheduleSpec, TaskKind, TaskState, TaskStatus, is_legal_transition,
};
pub use orxnud_domain::{Actor, CapabilityId, DataClass, RiskClass, TaskId};

/// The version of the conformance suite.
///
/// A Phase 2 engine records the suite version it was validated against, so a
/// later change to the properties cannot silently invalidate a pass.
pub const CONFORMANCE_SUITE_VERSION: &str = "1.0.0";
