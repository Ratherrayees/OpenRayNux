//! The ADR-0029 conformance harness.
//!
//! # The twelve properties
//!
//! The contract is [`TaskEngine`]. Any implementation that provides
//! that trait and passes [`run_suite`] conforms, regardless of how it stores
//! or schedules anything. That is what makes ADR-0007's engine replaceable.
//!
//! | Property | Statement |
//! |---|---|
//! | TP-1 | No task silently disappears. |
//! | TP-2 | Exactly-once where required, at-least-once otherwise. |
//! | TP-3 | Cancellation is observable. |
//! | TP-4 | Restart recovers durable work. |
//! | TP-5 | **Expired leases cannot execute.** |
//! | TP-6 | Retries never inherit approvals. |
//! | TP-7 | Power loss cannot corrupt task state. |
//! | TP-8 | Scheduling is deterministic under time manipulation. |
//! | TP-9 | Catch-up is bounded and explicit. |
//! | TP-10 | Bounded resources. |
//! | TP-11 | Dead-lettering is terminal and visible. |
//! | TP-12 | Every side effect is accounted for. |
//!
//! # Determinism
//!
//! Failure injection needs randomness, and this suite's randomness is a **fixed
//! seed** recorded in every report. Re-running with the same seed reproduces the
//! same interruption points, so a failure is a bug report rather than a ghost.
//!
//! The real power-loss test (TP-7) kills a *child process*, so it cannot run
//! inside the test binary that is already running. It is exposed as
//! [`power_loss::victim_main`] and driven by [`power_loss::kill_at_points`].

pub mod clock;
pub mod power_loss;
pub mod properties;
pub mod report;
pub mod schedule;

pub use clock::{FixedClock, TestClock};
pub use properties::{Claim, EngineFactory, Rng, TaskEngine, TaskRecord};
pub use report::{ConformanceReport, PropertyOutcome, PropertyResult, Verdict};
pub use schedule::{CatchUpPlan, MisfireOutcome, catch_up_plan};

/// The twelve properties, in canonical order.
pub const PROPERTIES: [&str; 12] = [
    "TP-1", "TP-2", "TP-3", "TP-4", "TP-5", "TP-6", "TP-7", "TP-8", "TP-9", "TP-10", "TP-11",
    "TP-12",
];

/// A one-line statement of each property, used in reports.
pub const PROPERTY_DESCRIPTIONS: [(&str, &str); 12] = [
    ("TP-1", "no task silently disappears"),
    (
        "TP-2",
        "exactly-once where required, at-least-once otherwise",
    ),
    ("TP-3", "cancellation is observable"),
    ("TP-4", "restart recovers durable work"),
    ("TP-5", "expired leases cannot execute"),
    ("TP-6", "retries never inherit approvals"),
    ("TP-7", "power loss cannot corrupt task state"),
    (
        "TP-8",
        "scheduling is deterministic under time manipulation",
    ),
    ("TP-9", "catch-up is bounded and explicit"),
    ("TP-10", "bounded resources"),
    ("TP-11", "dead-lettering is terminal and visible"),
    ("TP-12", "every side effect is accounted for"),
];

/// Runs the whole suite against an engine.
///
/// Returns a [`ConformanceReport`] listing all twelve properties. The caller
/// decides what to do with it; the suite never reports success itself, because a
/// harness that declares its own tests passing is not a harness.
#[must_use]
pub fn run_suite(factory: EngineFactory, seed: u64) -> ConformanceReport {
    properties::run_all(factory, seed)
}
