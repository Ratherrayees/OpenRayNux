//! Deterministic crash injection *inside* a transaction.
//!
//! # Why this module exists at all
//!
//! Phase 2's first failure-injection suite killed a child process at named points
//! **between** repository calls, and one of those points was labelled
//! `during-complete`. That label was a lie. The child did this:
//!
//! ```ignore
//! if stop_here("during-complete") { /* die */ }
//! engine.complete(task, ...);   // never reached
//! ```
//!
//! So the process died *before* the transaction began. That proves the pre-crash
//! state survives — which the other five points already prove — and proves nothing
//! about atomicity. The interesting failure is a process that dies with a write
//! transaction **open and partly applied**, and it cannot be reached by a timer or
//! from the outside: the window is microseconds wide and inside someone else's
//! function.
//!
//! The only deterministic way in is to be *called* from inside the transaction.
//!
//! # Why this is feature-gated
//!
//! The hook is compiled out unless the `fault-injection` feature is on, which is
//! not a default feature and is not enabled by any release profile. It is the same
//! trade every database library makes (`sqlx`, `tokio-test`, `fault-inject`).
//! `no_table_outside_the_task_layer_exists` and gate G2 both run without it.
//!
//! # Why `abort()` and not `SIGKILL`
//!
//! `abort()` raises `SIGABRT` and terminates immediately: **no unwinding, no
//! destructors, no `Drop`, no flushing**. `std::process::exit` would run
//! at-exit handlers and could flush buffers — precisely the behaviour this is
//! supposed to bypass. Self-signalling is used so the hook needs no `unsafe` and
//! no `libc` dependency, keeping G4 (`#![forbid(unsafe_code)]`) intact.
//!
//! [`maybe_crash`] is a no-op unless `ORXNUD_FAULT` names the fault point, so
//! enabling the feature alone changes no behaviour.
//!
//! # Why the tests live in this crate
//!
//! The mid-transaction crash tests spawn a child process that dies with a write
//! transaction open, so they have to run somewhere the hook is compiled in. They
//! run here, as unit tests of [`crate::task_repo`], for two reasons:
//!
//! * a repository transaction is a *storage* invariant, and the storage crate is
//!   where a reader will look for it;
//! * `#[cfg(test)]` is enough. Putting these tests in `orxnud-task` would have
//!   required `orxnud-store/fault-injection` as a dev-dependency, and Cargo rejects
//!   naming the same crate twice under different names — so that route needed the
//!   hook live in a library build for the sake of a test, which is a much larger
//!   blast radius than this module has.

/// A point inside a repository transaction where the process can be killed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FaultPoint {
    /// Inside `claim`'s transaction, after the `UPDATE ... RETURNING` has claimed a
    /// task but before the attempt row is inserted and the transaction commits.
    ClaimAfterTakeBeforeAttempt,
    /// Inside `complete_with`'s transaction, after the tasks row has been updated
    /// but before the attempt row is closed and the transaction commits.
    ///
    /// This is the interesting one: the task row and the attempt row disagree at
    /// this instant. Atomicity means neither half is visible afterwards.
    CompleteAfterUpdateBeforeAttempt,
    /// Inside the post-verification step-advancement transaction, after the step result has
    /// been written and before `steps_completed` has been moved.
    ///
    /// The window that matters: the result and the counter disagree for exactly as long as
    /// the transaction is open, so this is the only moment at which a crash could leave a
    /// verified step recorded against a task that has not counted it.
    AdvanceStepAfterResultBeforeCounter,
    /// Inside `cancel`'s first transaction, between marking the tasks row and
    /// recording the cancellation event.
    CancelBeforeEvent,
}

impl FaultPoint {
    /// The value `ORXNUD_FAULT` uses to select this point.
    fn slug(self) -> &'static str {
        match self {
            Self::ClaimAfterTakeBeforeAttempt => "claim-after-take-before-attempt",
            Self::CompleteAfterUpdateBeforeAttempt => "complete-after-update-before-attempt",
            Self::AdvanceStepAfterResultBeforeCounter => "advance-step-after-result-before-counter",
            Self::CancelBeforeEvent => "cancel-before-event",
        }
    }
}

/// Every fault point, for tests that iterate all of them.
pub fn all() -> Vec<FaultPoint> {
    vec![
        FaultPoint::ClaimAfterTakeBeforeAttempt,
        FaultPoint::CompleteAfterUpdateBeforeAttempt,
        FaultPoint::AdvanceStepAfterResultBeforeCounter,
        FaultPoint::CancelBeforeEvent,
    ]
}

/// Whether `wanted` (the value of `ORXNUD_FAULT`) selects `point`.
///
/// Pure and total, so the selection logic is unit-testable without a child process
/// and without `env::set_var` — which is `unsafe` on this edition, and this crate
/// forbids unsafe.
pub fn selects(point: FaultPoint, wanted: &str) -> bool {
    wanted == point.slug()
}

/// Kills the process if `ORXNUD_FAULT` selects `point`; otherwise returns.
///
/// # Why the gate is on the body and not on this function
///
/// [`crate::task_repo`] calls `maybe_crash` unconditionally. A call site that only
/// existed under `cfg` would mean `#[cfg]` attributes scattered through the
/// repository's transaction logic -- and a call site that vanishes in a release
/// build is a call site nobody reviews. So the function always exists, and
/// everything except the signature is compiled out unless the feature (or a test
/// build) is on.
///
/// A side effect worth noting: because the body is still *type-checked* by
/// `cargo check` in an ordinary build, a mistake in the hook cannot hide behind the
/// gate. What the gate removes is the [`std::process::abort`] call, which is the
/// only part that must not ship.
///
/// # Panics
///
/// Never. An unknown name in the environment variable leaves the process alone:
/// silently aborting on a typo would take down an entire test run.
///
/// # Non-local control flow
///
/// This function does not return when it fires. The caller is mid-transaction, so
/// there is no unwinding, no `Drop`, and no flushing -- which is the point.
#[allow(unused_variables)]
pub fn maybe_crash(point: FaultPoint) {
    #[cfg(not(any(test, feature = "fault-injection")))]
    return;

    #[cfg(any(test, feature = "fault-injection"))]
    {
        let Ok(wanted) = std::env::var("ORXNUD_FAULT") else {
            return;
        };
        if !selects(point, &wanted) {
            return;
        }
        // Tell the parent *before* dying: the parent distinguishes "died at the
        // fault point" from "died somewhere unexpected", and stdout is only flushed
        // if the write completed, so this must be unbuffered.
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = out.write_all(format!("FAULT-HIT {}\n", point.slug()).as_bytes());
        let _ = out.flush();

        eprintln!("fault injection: aborting at {}", point.slug());
        std::process::abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_point_is_selected_only_by_its_own_slug() {
        assert!(selects(
            FaultPoint::CompleteAfterUpdateBeforeAttempt,
            "complete-after-update-before-attempt"
        ));
        // Each point must ignore every *other* point's name, or a run could die at
        // two places at once.
        for other in all() {
            if other != FaultPoint::CompleteAfterUpdateBeforeAttempt {
                assert!(!selects(
                    FaultPoint::CompleteAfterUpdateBeforeAttempt,
                    other.slug()
                ));
            }
        }
    }

    #[test]
    fn an_unknown_fault_name_selects_nothing() {
        // A typo must not abort: that would take down the whole test run.
        for point in all() {
            assert!(!selects(point, "no-such-point"));
            assert!(!selects(point, ""));
        }
    }

    #[test]
    fn an_unset_variable_selects_nothing() {
        // What `maybe_crash` does when the variable is absent, which is why
        // enabling the feature changes no behaviour by itself.
        assert!(std::env::var("ORXNUD_FAULT").map_or(true, |v| v.is_empty()));
    }

    #[test]
    fn every_point_has_a_distinct_slug() {
        let mut slugs: Vec<_> = all().iter().map(|p| p.slug()).collect();
        let count = slugs.len();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), count, "two fault points share a slug");
    }

    #[test]
    fn the_slugs_are_the_documented_ones() {
        // A rename here must break the test binary that selects them by name.
        let names: Vec<_> = all().iter().map(|p| p.slug()).collect();
        assert_eq!(
            names,
            vec![
                "claim-after-take-before-attempt",
                "complete-after-update-before-attempt",
                "advance-step-after-result-before-counter",
                "cancel-before-event",
            ]
        );
    }
}

/// Mid-transaction crash atomicity.
///
/// Each test spawns a real child process against a real file database and kills it
/// from *inside* an open write transaction, then asserts the transaction's partial
/// work left nothing behind. That is the property SQLite's `BEGIN IMMEDIATE` plus
/// the rollback journal is supposed to give, and it is the one property a
/// kill-from-the-outside suite cannot check: the window is microseconds wide and
/// inside someone else's function, so the only way in is to be called from there.
#[cfg(test)]
mod atomicity {
    use super::*;
    use crate::migration::MigrationRunner;
    use crate::pragma::Pragma;
    use crate::task_repo::{
        ClaimOutcome, NewTask, StepStatus, TargetedClaimOutcome, TaskRepository, VerifiedStep,
    };
    use orxnud_domain::ids::TaskId;
    use orxnud_domain::task_state::{TaskKind, TaskState};
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const NOW: i64 = 1_767_225_600_000;
    const LEASE: i64 = 5_000;
    const ENV_SCENARIO: &str = "ORXNUD_FAULT_SCENARIO";
    const ENV_DB: &str = "ORXNUD_FAULT_DB";
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

    /// Every (scenario, fault point, what the crash must undo) triple.
    const CASES: &[(&str, FaultPoint, &str)] = &[
        (
            "claim",
            FaultPoint::ClaimAfterTakeBeforeAttempt,
            "the claim",
        ),
        (
            "complete",
            FaultPoint::CompleteAfterUpdateBeforeAttempt,
            "the completion",
        ),
        ("cancel", FaultPoint::CancelBeforeEvent, "the cancellation"),
    ];

    fn db_path(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "orxnud-fault-atomicity-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d.join("t.db")
    }

    fn open(path: &Path) -> rusqlite::Connection {
        let c = rusqlite::Connection::open(path).expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        let r = MigrationRunner::new(&c);
        if r.applied_version().expect("version") == 0 {
            r.run(true).expect("migrate");
        }
        c
    }

    /// A fresh database holding one pending task.
    fn seeded(tag: &str) -> PathBuf {
        let p = db_path(tag);
        let mut c = open(&p);
        TaskRepository::new(&mut c)
            .insert(&NewTask::new(TaskId::new("t"), TaskKind::Query, NOW), NOW)
            .expect("seed");
        p
    }

    /// A database holding one task already running step 1 of a two-step composition, with
    /// an approved proposal for that step.
    ///
    /// `TaskKind::Workflow` because a workflow is the kind that carries composition, and
    /// `max_steps = 2` because a single-step task would complete rather than stop at the
    /// boundary, which is the case already covered by the `complete` scenario.
    fn seeded_running_step(tag: &str) -> PathBuf {
        let p = db_path(tag);
        let mut c = open(&p);
        {
            let mut repo = TaskRepository::new(&mut c);
            repo.insert(
                &NewTask::new(TaskId::new("t"), TaskKind::Workflow, NOW),
                NOW,
            )
            .expect("seed");
        }
        c.execute("UPDATE tasks SET max_steps = 2 WHERE id = 't';", [])
            .expect("bounds");
        let mut repo = TaskRepository::new(&mut c);
        assert!(matches!(
            repo.claim_specific(&TaskId::new("t"), "w", NOW, LEASE),
            Ok(TargetedClaimOutcome::Claimed(_))
        ));
        repo.propose_action(
            "p1",
            &TaskId::new("t"),
            "w",
            "filesystem/write-text",
            Some("a.txt"),
            "{}",
            "{}",
            None,
            1,
            NOW,
        )
        .expect("propose");
        repo.decide_proposal("p1", "approved", NOW)
            .expect("approve");
        repo.begin_approved_execution("p1", "w", NOW, LEASE)
            .expect("resume");
        p
    }

    /// Runs `scenario` in a child that will be aborted from inside a transaction.
    ///
    /// Polls with `try_wait` rather than calling `output()`, because a child whose
    /// hook never fires sleeps forever *while still holding stdout open*: `output()`
    /// would block until the CI job was killed. Found the hard way — moving the
    /// `complete` hook to just after its commit should have produced a clean
    /// assertion failure and instead hung the suite for twenty minutes. A test that
    /// cannot fail is worse than a missing test; one that hangs is worse still.
    fn run(scenario: &str, point: FaultPoint, db: &Path) -> std::process::Output {
        let mut child = Command::new(std::env::current_exe().expect("current_exe"))
            .args([
                "--exact",
                "faults::atomicity::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env(ENV_DB, db)
            .env(ENV_SCENARIO, scenario)
            // This is what makes the store abort *itself*, mid-transaction.
            .env("ORXNUD_FAULT", point.slug())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn");

        let deadline = std::time::Instant::now() + TIMEOUT;
        let status = loop {
            if let Some(s) = child.try_wait().expect("try_wait") {
                break s;
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "the {scenario} child outlived {TIMEOUT:?}: the hook never fired, so no \
                     transaction was interrupted and this test would have asserted nothing."
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        let mut out = child.wait_with_output().expect("wait_with_output");
        out.status = status;
        out
    }

    /// The re-executed child. Never returns on the paths that matter.
    #[test]
    #[ignore = "entry point for run(); not a test"]
    fn crash_child() {
        let Ok(db) = std::env::var(ENV_DB) else {
            return; // Harmless when a person runs the binary directly.
        };
        let scenario = std::env::var(ENV_SCENARIO).expect("scenario");
        let mut conn = open(Path::new(&db));
        let mut repo = TaskRepository::new(&mut conn);

        match scenario.as_str() {
            "claim" => {
                // Aborted inside the claim transaction, with the task taken but no
                // attempt row written.
                let _ = repo.claim("w", NOW, LEASE);
            }
            "complete" => {
                assert!(matches!(
                    repo.claim("w", NOW, LEASE),
                    Ok(ClaimOutcome::Claimed(_))
                ));
                // Aborted after the tasks row was updated, before the attempt row was
                // closed: the two rows disagree at the instant of the crash.
                let _ = repo.complete_with(
                    &TaskId::new("t"),
                    "w",
                    NOW,
                    TaskState::Completed,
                    true,
                    None,
                    0,
                );
            }
            "cancel" => {
                assert!(matches!(
                    repo.claim("w", NOW, LEASE),
                    Ok(ClaimOutcome::Claimed(_))
                ));
                // Aborted after the state flipped to `cancelled`, before the event.
                let _ = repo.request_cancel(&TaskId::new("t"), NOW);
            }
            "advance-step" => {
                // Aborted after the verified step result was written and before
                // `steps_completed` moved: the two disagree for exactly as long as the
                // transaction is open, which is the window this scenario exists to test.
                let _ = repo.complete_verified_step(&VerifiedStep {
                    task_id: TaskId::new("t"),
                    worker: "w",
                    step_no: 1,
                    proposal_id: "p1",
                    status: StepStatus::Verified,
                    verification: Some("evidence".into()),
                    structured_output: None,
                    artifacts: None,
                    recorded_at_ms: NOW,
                });
            }
            other => panic!("unknown scenario {other}"),
        }

        // Reached only if the hook did not fire. The parent asserts on
        // `FAULT-HIT`, so this branch turns a silent pass into a failure.
        eprintln!("FAULT-MISSED {scenario}");
        loop {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    fn assert_died_at_the_fault_point(
        out: &std::process::Output,
        scenario: &str,
        point: FaultPoint,
    ) {
        assert!(
            out.status.code().is_none(),
            "{scenario}: expected an abnormal death, got exit {:?}\nstdout: {}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(&format!("FAULT-HIT {}", point.slug())),
            "{scenario}: the hook never fired, so no transaction was interrupted:\n{stdout}"
        );
        assert!(
            !stdout.contains("FAULT-MISSED"),
            "{scenario}: the store survived its own hook"
        );
    }

    fn state_of(db: &Path) -> (String, Option<String>, Option<i64>) {
        let c = rusqlite::Connection::open(db).expect("reopen");
        c.query_row(
            "SELECT state, lease_holder, completed_at_ms FROM tasks WHERE id = 't';",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("read the task")
    }

    /// The step counters and the step results of task `t`, read together.
    ///
    /// Read as a pair because the property is about them agreeing: a counter that moved
    /// without its result, or a result without its counter, is the contradiction this
    /// scenario is looking for.
    fn step_coherence(db: &Path) -> (String, i64, i64, i64) {
        let c = rusqlite::Connection::open(db).expect("reopen");
        c.query_row(
            "SELECT t.state, t.steps_completed, t.max_steps,
                    (SELECT COUNT(*) FROM task_step_results r WHERE r.task_id = t.id)
               FROM tasks t WHERE t.id = 't';",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("read the task")
    }

    fn attempts(db: &Path) -> i64 {
        let c = rusqlite::Connection::open(db).expect("reopen");
        c.query_row("SELECT COUNT(*) FROM task_attempts;", [], |r| r.get(0))
            .expect("count attempts")
    }

    /// The step-advancement transaction is all-or-nothing.
    ///
    /// The crash lands in the one window where the step result and the counter disagree --
    /// after the result row is written, before `steps_completed` moves. Both are
    /// uncommitted at that point, so recovery must find neither. The two states this rules
    /// out are precisely the ones nothing else would complain about:
    ///
    /// ```text
    /// result present + counter not advanced + terminal state
    /// counter advanced + result absent
    /// ```
    #[test]
    fn a_crash_inside_the_step_advancement_transaction_undoes_the_whole_step() {
        let db = seeded_running_step("advance-step");
        let out = run(
            "advance-step",
            FaultPoint::AdvanceStepAfterResultBeforeCounter,
            &db,
        );
        assert_died_at_the_fault_point(
            &out,
            "advance-step",
            FaultPoint::AdvanceStepAfterResultBeforeCounter,
        );

        let (state, steps_completed, max_steps, results) = step_coherence(&db);
        assert_eq!(
            results, 0,
            "the verified result was written but rolled back, so it must not survive"
        );
        assert_eq!(steps_completed, 0, "the counter must not have moved either");
        assert_eq!(max_steps, 2, "the bounds are untouched by a rollback");
        assert_eq!(
            state, "running",
            "the task is still executing the step it had not finished"
        );

        // Not terminal, and not counting a step it has no result for.
        assert!(
            !matches!(state.as_str(), "completed" | "dead-lettered"),
            "a rolled-back advancement must not leave a terminal task: {state}"
        );
        assert_eq!(results, steps_completed);
    }

    /// The complement: after recovery the step can be completed for real, exactly once.
    ///
    /// Worth stating separately because "the rollback was clean" and "the work can still be
    /// finished" are different claims, and a transaction that rolled back but left the task
    /// unclaimable would satisfy the first and fail this.
    #[test]
    fn a_step_rolled_back_by_a_crash_can_still_be_completed_once() {
        let db = seeded_running_step("advance-retry");
        let _ = run(
            "advance-step",
            FaultPoint::AdvanceStepAfterResultBeforeCounter,
            &db,
        );

        let mut c = open(&db);
        let advance = TaskRepository::new(&mut c).complete_verified_step(&VerifiedStep {
            task_id: TaskId::new("t"),
            worker: "w",
            step_no: 1,
            proposal_id: "p1",
            status: StepStatus::Verified,
            verification: Some("evidence".into()),
            structured_output: None,
            artifacts: None,
            recorded_at_ms: NOW,
        });
        assert!(
            advance.is_ok(),
            "the step must still be completable: {advance:?}"
        );
        drop(c);

        let (state, steps_completed, _, results) = step_coherence(&db);
        assert_eq!(state, "awaiting-next-step");
        assert_eq!(steps_completed, 1);
        assert_eq!(results, 1, "one verified step, one result, one count");
    }

    #[test]
    fn a_crash_inside_the_claim_transaction_undoes_the_claim() {
        let db = seeded("claim");
        let out = run("claim", FaultPoint::ClaimAfterTakeBeforeAttempt, &db);
        assert_died_at_the_fault_point(&out, "claim", FaultPoint::ClaimAfterTakeBeforeAttempt);

        let (state, holder, _) = state_of(&db);
        assert_eq!(
            state, "pending",
            "a rolled-back claim must leave the task pending"
        );
        assert_eq!(holder, None, "no lease may survive a rolled-back claim");
        assert_eq!(attempts(&db), 0, "no attempt row may survive either");
    }

    #[test]
    fn a_crash_inside_the_completion_transaction_undoes_the_completion() {
        let db = seeded("complete");
        let out = run(
            "complete",
            FaultPoint::CompleteAfterUpdateBeforeAttempt,
            &db,
        );
        assert_died_at_the_fault_point(
            &out,
            "complete",
            FaultPoint::CompleteAfterUpdateBeforeAttempt,
        );

        let (state, holder, completed_at) = state_of(&db);
        assert_eq!(
            state, "running",
            "the tasks row update must have rolled back with the rest of the transaction"
        );
        assert_eq!(
            completed_at, None,
            "a rolled-back completion leaves no timestamp"
        );
        assert_eq!(
            holder.as_deref(),
            Some("w"),
            "the lease clear must have rolled back too"
        );
        // And the attempt row: the update that would have closed it never committed.
        assert_eq!(
            attempts(&db),
            1,
            "the claim's attempt survives; only the close is undone"
        );

        // The database is still usable, which is the point: the crash cost the work,
        // it did not corrupt it.
        let mut c = open(&db);
        assert_eq!(
            TaskRepository::new(&mut c)
                .recover(NOW + LEASE + 1)
                .expect("recover"),
            1,
            "the orphaned lease must be reclaimable"
        );
    }

    #[test]
    fn a_crash_inside_the_cancellation_transaction_cannot_silently_cancel() {
        let db = seeded("cancel");
        let out = run("cancel", FaultPoint::CancelBeforeEvent, &db);
        assert_died_at_the_fault_point(&out, "cancel", FaultPoint::CancelBeforeEvent);

        let (state, _, _) = state_of(&db);
        assert_ne!(
            state, "cancelled",
            "a cancellation with no event must not survive: that is the silent-cancellation case"
        );
    }

    #[test]
    fn every_fault_point_rolls_back_and_leaves_a_readable_database() {
        for (scenario, point, what) in CASES {
            let db = seeded(&format!("all-{scenario}"));
            let out = run(scenario, *point, &db);
            assert_died_at_the_fault_point(&out, scenario, *point);

            let c = rusqlite::Connection::open(&db).expect("reopen");
            let integrity: String = c
                .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
                .expect("integrity");
            assert_eq!(
                integrity, "ok",
                "{scenario}: integrity_check said {integrity}"
            );

            // The generalised claim: whatever the state, it is one the engine's own
            // state machine allows -- never something only the dead process knew.
            let (state, _, _) = state_of(&db);
            let parsed = TaskState::from_wire_str(&state).expect("a state from the closed set");
            assert!(
                !matches!(parsed, TaskState::Completed | TaskState::Cancelled),
                "{scenario}: {what} survived the rollback as {parsed:?}"
            );
        }
    }

    /// The guard, in both directions, in one place.
    ///
    /// A claim that rolled back must be claimable again, and a completion that rolled
    /// back must be completable again -- otherwise "atomic" would only mean "nothing
    /// happened", which is a weaker and less useful claim.
    #[test]
    fn rolled_back_work_can_be_redone() {
        let db = seeded("redo-complete");
        let out = run(
            "complete",
            FaultPoint::CompleteAfterUpdateBeforeAttempt,
            &db,
        );
        assert_died_at_the_fault_point(
            &out,
            "complete",
            FaultPoint::CompleteAfterUpdateBeforeAttempt,
        );

        let mut c = open(&db);
        let mut repo = TaskRepository::new(&mut c);
        assert_eq!(repo.recover(NOW + LEASE + 1).expect("recover"), 1);
        assert!(
            matches!(
                repo.claim("w2", NOW + LEASE + 1, LEASE).expect("claim"),
                ClaimOutcome::Claimed(_)
            ),
            "a task whose claim rolled back must be claimable again"
        );
        assert!(
            repo.complete_with(
                &TaskId::new("t"),
                "w2",
                NOW + LEASE + 2,
                TaskState::Completed,
                true,
                None,
                0,
            )
            .expect("complete"),
            "a task whose completion rolled back must be completable again"
        );
        assert_eq!(state_of(&db).0, "completed");
        let _ = std::fs::remove_dir_all(db.parent().expect("parent"));
    }
}
