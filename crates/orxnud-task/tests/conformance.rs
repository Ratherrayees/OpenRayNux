//! The ADR-0029 conformance suite, run against the trivial fixture.
//!
//! # What this file is
//!
//! The Phase 1 deliverable. It runs all twelve properties against
//! `tests/support::TrivialEngine` and **fails if any property is violated or
//! unsupported**.
//!
//! # What it deliberately is not
//!
//! The task engine. There is no queue, no scheduler, no persistence here — the
//! fixture has none of those, and the suite does not pretend otherwise. Phase 2
//! writes the engine; **this file must pass unchanged** against it. That is the
//! whole value of specifying properties rather than an implementation: the
//! contract is fixed, and swapping the engine is an implementation change.
//!
//! # Determinism
//!
//! The seed below is fixed and recorded in the report. Re-running reproduces the
//! same interruption points, so a failure here is a bug report rather than a
//! ghost.

mod support;

/// The recorded seed for the randomised injection. Changing it changes which
/// points are exercised, so it is a constant rather than a default.
const SEED: u64 = 0x0F0E_D100;

use orxnud_task::conformance::EngineFactory;
use orxnud_task::conformance::clock::FixedClock;
use orxnud_task::conformance::report::Verdict;
use orxnud_task::conformance::run_suite;
use support::TrivialEngine;

/// A factory for the conforming fixture.
fn conforming() -> EngineFactory {
    Box::new(|| Box::new(TrivialEngine::new()))
}

/// A factory for the same fixture with lease fencing removed, to prove TP-5
/// reports a gap rather than a pass.
fn unfenced() -> EngineFactory {
    Box::new(|| Box::new(TrivialEngine::without_fencing()))
}

/// A factory for an engine whose every operation fails.
fn broken() -> EngineFactory {
    Box::new(|| Box::new(TrivialEngine::broken()))
}

/// The whole suite, against a working engine. All twelve must hold.
#[test]
fn all_twelve_properties_hold_for_a_conforming_engine() {
    let report = run_suite(conforming(), SEED);

    // Always render the report, so a failure is diagnosable from the log alone.
    println!("{}", report.render());

    let violations = report.violations();
    assert!(violations.is_empty(), "properties violated: {violations:?}");
    let gaps = report.gaps();
    assert!(gaps.is_empty(), "properties unsupported: {gaps:?}");
    assert_eq!(report.verdict(), Verdict::Conforms);
    assert!(report.fully_conforms());
    assert_eq!(report.results.len(), 12, "every property must be reported");
}

/// The suite is deterministic: the same seed must produce the same verdicts.
#[test]
fn the_suite_is_reproducible() {
    let r1 = run_suite(conforming(), SEED);
    let r2 = run_suite(conforming(), SEED);
    assert_eq!(r1, r2, "the same seed must produce an identical report");
}

/// An engine with no lease fencing must report TP-5 as a **gap**, never as a
/// pass. "We chose not to implement it" is not "it works".
#[test]
fn an_engine_without_fencing_reports_tp5_as_unsupported() {
    let report = run_suite(unfenced(), SEED);
    assert_eq!(report.gaps(), vec!["TP-5"], "TP-5 should be the only gap");
    assert_eq!(report.verdict(), Verdict::ConformsWithGaps);
    assert!(
        !report.fully_conforms(),
        "a gap must not be reported as full conformance"
    );
}

/// A **fencing engine that does it wrong** must be caught. This is the test that
/// proves the suite has teeth: without it, TP-5 could be passing for the wrong
/// reason.
#[test]
fn a_engine_that_checks_identity_but_not_liveness_fails_tp5() {
    use orxnud_domain::task_state::TaskState;
    use orxnud_domain::{TaskId, TaskKind};
    use orxnud_task::conformance::properties::{
        Claim, TaskEngine, TaskRecord, tp5_expired_leases_cannot_execute,
    };
    use orxnud_task::conformance::report::PropertyOutcome;

    /// The classic bug: `complete` verifies *who* holds the task but never
    /// *when* they held it. This passes the "re-claimed" case and fails the
    /// "expired but unclaimed" one.
    #[derive(Default)]
    struct IdentityOnlyEngine {
        rec: Option<TaskRecord>,
    }

    impl TaskEngine for IdentityOnlyEngine {
        fn name(&self) -> &'static str {
            "identity-only-buggy"
        }
        fn enqueue(&mut self, task: TaskRecord) -> Result<(), String> {
            self.rec = Some(task);
            Ok(())
        }
        fn claim(&mut self, worker: &str, now_ms: i64) -> Result<Claim, String> {
            let Some(r) = self.rec.as_mut() else {
                return Ok(Claim::Empty);
            };
            if !r.state.is_claimable() {
                return Ok(Claim::Empty);
            }
            r.state = TaskState::Running;
            r.attempts += 1;
            r.lease_expires_at_ms = Some(now_ms + 1_000);
            r.lease_holder = Some(worker.to_owned());
            Ok(Claim::Claimed(r.clone()))
        }
        fn complete(
            &mut self,
            id: &TaskId,
            worker: &str,
            _now_ms: i64,
            state: TaskState,
            effect_observed: bool,
            error: Option<String>,
        ) -> Result<(), String> {
            let r = self.rec.as_mut().ok_or("no such task")?;
            // The bug: identity only. The lease's expiry is never consulted.
            if r.lease_holder.as_deref() != Some(worker) {
                return Err("not the holder".into());
            }
            let _ = id;
            r.state = state;
            r.effect_observed = effect_observed;
            r.last_error = error;
            r.lease_holder = None;
            r.lease_expires_at_ms = None;
            Ok(())
        }
        fn request_cancel(&mut self, _id: &TaskId) -> Result<(), String> {
            Ok(())
        }
        fn recover(&mut self, _now_ms: i64) -> Result<(), String> {
            Ok(())
        }
        fn all(&self) -> Vec<TaskRecord> {
            self.rec.iter().cloned().collect()
        }
        fn get(&self, _id: &TaskId) -> Option<TaskRecord> {
            self.rec.clone()
        }
    }

    let mut e = IdentityOnlyEngine::default();
    let mut c = FixedClock::default();
    let outcome = tp5_expired_leases_cannot_execute(&mut e, &mut c);
    match outcome {
        PropertyOutcome::Violated { detail } => {
            assert!(
                detail.contains("expired lease"),
                "TP-5 failed for the wrong reason: {detail}"
            );
        }
        other => panic!("TP-5 must catch an identity-only fence; it reported {other}"),
    }
    let _ = (TaskKind::Workflow, "compiling");
}

/// A broken engine must not be able to pass anything: every property that needs
/// it must report a violation rather than an empty success.
#[test]
fn a_broken_engine_violates_rather_than_silently_passing() {
    let report = run_suite(broken(), SEED);
    let violations = report.violations();
    assert!(
        !violations.is_empty(),
        "a broken engine must not produce a clean report"
    );
    assert_eq!(report.verdict(), Verdict::NonConforming);
}

/// The engine-killed power-loss harness. Runs the real SIGKILL rig.
#[test]
fn power_loss_never_yields_an_impossible_state() {
    use orxnud_task::conformance::power_loss::tp7_power_loss_cannot_corrupt;
    use orxnud_task::conformance::report::PropertyOutcome;

    let mut engine = TrivialEngine::new();
    let mut clock = FixedClock::default();
    let outcome = tp7_power_loss_cannot_corrupt(&mut engine, &mut clock, SEED);
    match outcome {
        PropertyOutcome::Holds { cases } => {
            assert!(cases >= 1, "TP-7 reported no cases");
        }
        PropertyOutcome::Unsupported { detail } => {
            // The rig could not run in this environment. That is a legitimate
            // environment limitation, but it must be *visible*, never silently
            // reported as a pass.
            panic!("TP-7 could not be exercised here: {detail}");
        }
        PropertyOutcome::Violated { detail } => panic!("TP-7 violated: {detail}"),
    }
}

/// The TP-7 victim, as a test.
///
/// `#[ignore]`d because it is not a test: it is a **child process entry point**.
/// It does nothing unless the environment names a database, so invoking the
/// binary with no arguments is harmless. The name must match the `--exact`
/// filter in `power_loss::spawn_victim`.
///
/// The library function is imported under a different name on purpose. A bare
/// `victim_entry_point()` inside a function of the same name resolves to
/// *itself*, and because the call is in tail position it compiles to an infinite
/// loop rather than crashing — which presents as the victim silently hanging.
#[test]
#[ignore = "child-process entry point for TP-7, not a test"]
fn victim_entry_point() {
    orxnud_task::conformance::power_loss::victim_entry_point();
}
