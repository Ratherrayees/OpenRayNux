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
//! library, and exists only to make the properties runnable.
//!
//! # Phase 2
//!
//! [`engine::DurableEngine`] is the production engine, and it implements
//! [`conformance::properties::TaskEngine`] — the trait Phase 1 defined — against
//! the SQLite store. The conformance suite is **unchanged**: it is the
//! acceptance criterion, not a description of the implementation. Running it
//! against a second engine is
//! `tests/conformance_production.rs`.
//!
//! What is deliberately still absent, and why:
//!
//! * **No capability invocation.** The dispatcher is Phase 4. An invocation
//!   requires `orxnud-policy` to construct it, and this crate may not enable a
//!   capability (docs-13 §8).
//! * **No actor on a task row.** Actor attribution belongs to the capability
//!   dispatch, not to the queue. Where a human *authorised* something — a
//!   schedule — that is recorded as a user id.
//! * **No hidden background thread.** Every operation is a method with an
//!   explicit clock argument. A task engine that wakes itself is a task engine
//!   whose behaviour cannot be tested at the interesting moments.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod clock;
pub mod conformance;
pub mod engine;
pub mod error;
pub mod limits;
pub mod scheduler;

pub use engine::DurableEngine;
pub use error::{EngineError, EngineErrorKind, TaskCause};
pub use limits::EngineLimits;
pub use scheduler::{PassReport, SchedulePass, Scheduler};

pub use orxnud_domain::task_state::{
    MisfirePolicy, ScheduleFire, ScheduleSpec, TaskKind, TaskState, TaskStatus, is_legal_transition,
};
pub use orxnud_domain::{Actor, CapabilityId, DataClass, RiskClass, TaskId};

/// The version of the conformance suite.
///
/// A Phase 2 engine records the suite version it was validated against, so a
/// later change to the properties cannot silently invalidate a pass.
pub const CONFORMANCE_SUITE_VERSION: &str = "1.0.0";
