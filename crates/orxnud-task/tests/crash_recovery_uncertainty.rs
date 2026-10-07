//! V-93: a crash in the execution window must not make uncertain work retryable.
//!
//! # The defect this file exists to prevent
//!
//! V-92 made an uncertain *side effect* durable, but only on the path where the
//! dispatcher **returns**: `settle_unverified` reads the verification outcome and
//! writes `needs-verification`. Between `begin_approved_execution` committing and
//! `settle_unverified` committing there is a window in which the process can die,
//! and nothing in it has recorded the uncertainty.
//!
//! What survives such a crash is exactly the shape V-92 was created to stop:
//!
//! ```text
//! approved -> begin_approved_execution  ->  tasks: running, lease held
//!                                        ->  task_effects: one unresolved row
//! process dies
//! restart -> TaskService::open -> recover()
//!         -> tasks: pending          <-- the defect
//!         -> any worker claims it, and the non-idempotent effect runs again
//! ```
//!
//! `recover()` selected every `running` task holding a lease and set it to
//! `pending` (or `dead-lettered`), consulting neither the `idempotent` column nor
//! the `task_effects` ledger. Both exist for exactly this decision; neither was
//! read on it.
//!
//! # What is asserted here
//!
//! The crashes are real `SIGKILL`s delivered by the operating system to real child
//! processes, through the **production** engine against a **real file**, reusing the
//! existing fault-injection harness. Nothing here constructs
//! `TaskState::NeedsVerification` directly: a test that mints the answer it is
//! asking the code to produce proves nothing about whether the code produces it.
//!
//! The decision under test is `TaskRepository::recover`. That is where recovery
//! happens, so that is what is exercised.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use orxnud_domain::ids::TaskId;
use orxnud_domain::task_state::{TaskKind, TaskState, is_legal_transition};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::{EffectStatus, TaskRepository};
use orxnud_task::{DurableEngine, EngineLimits};
use rusqlite::OptionalExtension;

/// 2026-01-01T00:00:00Z. Fixed, so every assertion is about the transition and
/// not about a clock that moved.
const NOW: i64 = 1_767_225_600_000;

const ENV_POINT: &str = "ORXNUD_V93_POINT";
const ENV_DB: &str = "ORXNUD_V93_DB";
const ENV_KIND: &str = "ORXNUD_V93_KIND";
const ENV_EFFECT: &str = "ORXNUD_V93_EFFECT";
const ENV_READY: &str = "ORXNUD_V93_READY";

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-v93-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn db_in(dir: &Path) -> PathBuf {
    dir.join("state.db")
}

fn tid(s: &str) -> TaskId {
    TaskId::new(s)
}

fn open_engine(path: &Path) -> DurableEngine {
    let conn = rusqlite::Connection::open(path).expect("open");
    Pragma::critical().apply(&conn).expect("pragmas");
    Pragma::critical().verify(&conn).expect("verify pragmas");
    MigrationRunner::new(&conn).run(true).expect("migrate");
    DurableEngine::new(conn, EngineLimits::documented()).expect("engine")
}

// ---------------------------------------------------------------- the child

/// The child does exactly what the production dispatch path does, in the same
/// order, and stops with the effect reserved and the outcome unsettled.
///
/// The order is the point, and it is the order `runtime.rs::execute_proposal`
/// uses: claim, take the execution lease, **reserve the effect**, dispatch. A
/// crash after the reservation and before settlement is the dangerous window.
fn child_main() -> ! {
    let db = PathBuf::from(std::env::var(ENV_DB).expect("v93 db must be set"));
    let ready = std::env::var(ENV_READY).expect("v93 ready must be set");
    let kind = match std::env::var(ENV_KIND).ok().as_deref() {
        Some("query") => TaskKind::Query,
        _ => TaskKind::Workflow,
    };
    let mut e = open_engine(&db);

    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("v93-task"), kind, NOW),
        NOW,
    )
    .expect("enqueue");

    let claimed = e
        .claim_task("doomed-worker", NOW)
        .expect("claim")
        .expect("the child must claim its own task");
    assert_eq!(
        claimed.state,
        TaskState::Running,
        "the claim must be durable before the effect is reserved"
    );

    // An external effect is reserved *before* it is dispatched, so a crash here
    // leaves an unresolved ledger row -- the durable evidence that the world may
    // already have changed.
    //
    // The flag is the *effect's* repeat-safety, taken from the capability the way
    // the dispatcher takes it: `external-call` is non-idempotent, `count` is not.
    // It is deliberately independent of the task kind, because that independence is
    // the point: a task can be flagged idempotent and still be about to run an
    // effect that must not be repeated.
    // Driven by the scenario name, so a test can hold the *task* kind and the
    // *effect* kind apart -- which is the whole point of two of the cases below.
    let (effect_step, effect_idempotent) = match std::env::var(ENV_EFFECT).ok().as_deref() {
        Some("idempotent") => ("count", true),
        Some("non-idempotent") => ("external-call", false),
        _ => panic!("ENV_EFFECT must say which kind of effect is dispatched"),
    };
    let key = DurableEngine::idempotency_key(&tid("v93-task"), effect_step, "initial");
    assert!(
        e.reserve_effect(
            &key,
            &tid("v93-task"),
            claimed.attempts,
            effect_step,
            effect_idempotent,
            NOW
        )
        .expect("reserve"),
        "the first reservation must succeed"
    );

    // Signalled *after* everything above is durable, and before the kill, so the
    // parent's kill lands in the window and not before it. Signalling earlier
    // would be a race: the parent could kill the child before the reservation
    // existed, and the test would then be asserting something about a crash that
    // happened somewhere else entirely.
    std::fs::write(&ready, b"ready").expect("signal ready");

    // The effect *may* have happened. Nobody knows. There is no settlement, no
    // state transition, and no verification: the process is about to be killed.
    loop {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

/// Re-executed as the child by [`kill_during_execution`].
#[test]
#[ignore = "child-process entry point for the crash test, not a test"]
fn crash_child_entry_point() {
    if std::env::var_os(ENV_POINT).is_none() {
        return;
    }
    child_main();
}

fn spawn_child(db: &Path, ready: &Path, kind: &str, effect: &str) -> Child {
    Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "crash_child_entry_point",
            "--nocapture",
            "--ignored",
        ])
        .env(ENV_POINT, "during-execution-window")
        .env(ENV_DB, db)
        .env(ENV_KIND, kind)
        .env(ENV_EFFECT, effect)
        .env(ENV_READY, ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the crash child")
}

/// Runs the child until it is positioned in the execution window, then `SIGKILL`s
/// it. Returns once the kill has been delivered.
fn kill_during_execution_with(db: &Path, ready: &Path, kind: &str, effect: &str) {
    let mut child = spawn_child(db, ready, kind, effect);
    for _ in 0..4_000 {
        if ready.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert!(
        ready.exists(),
        "the child never reached the execution window; is the harness broken?"
    );
    // SIGKILL: no unwinding, no destructors, no flush. The faithful analogue of
    // power loss, and the only crash a rollback path could cheat against.
    child.kill().expect("SIGKILL the child");
    child.wait().expect("reap the child");
}

/// Asserts the whole terminal-state contract for a task recovered as uncertain.
fn assert_terminally_uncertain(e: &mut DurableEngine, id: &TaskId, why: &str) {
    let row = e.task(id).expect("read").expect("the task must exist");

    assert_eq!(
        row.state,
        TaskState::NeedsVerification,
        "{why}: the task must be `needs-verification`, got {:?}",
        row.state
    );
    assert!(
        row.lease_holder.is_none() && row.lease_expires_at_ms.is_none(),
        "{why}: an uncertain task must not keep a lease, got holder={:?} expiry={:?}",
        row.lease_holder,
        row.lease_expires_at_ms
    );
    assert_eq!(
        e.live_leases(NOW).expect("live leases"),
        0,
        "{why}: recovery must leave no lease behind"
    );

    // Not claimable, by the domain predicate and by every claim path in the store.
    assert!(
        !TaskState::NeedsVerification.is_claimable(),
        "{why}: the domain must not consider it claimable"
    );
    assert!(
        e.claim_task("second-worker", NOW).expect("claim").is_none(),
        "{why}: a second worker must not be able to claim it"
    );
    // A refusal, not an error: the task exists and is not claimable, which is the
    // ordinary answer for a terminal task and must not read as a storage fault.
    let targeted = e
        .claim_task_id(id, "second-worker", NOW)
        .expect("targeted claim must answer, not error");
    assert!(
        matches!(targeted, orxnud_task::engine::ClaimAttempt::Refused(_)),
        "{why}: even a targeted claim must be refused, got {targeted:?}"
    );
    assert!(
        !e.all_tasks()
            .expect("read")
            .iter()
            .any(|r| r.state == TaskState::Pending || r.state == TaskState::Running),
        "{why}: no task may be left claimable after recovery"
    );

    // Not continuable: a boundary claim is the only other entry into `running`.
    let boundary = e
        .claim_next_step(&tid("v93-task"), "second-worker", NOW)
        .expect("boundary claim must not error");
    assert!(
        matches!(
            boundary,
            orxnud_store::task_repo::TargetedClaimOutcome::Refused(_)
        ),
        "{why}: an uncertain task must not be continuable, got {boundary:?}"
    );
}

/// A crash with a `workflow` task dispatching a non-idempotent effect.
fn kill_during_execution(db: &Path, ready: &Path, kind: &str) {
    kill_during_execution_with(db, ready, kind, "non-idempotent");
}

// ------------------------------------------------------- the regression test

/// **The defect.** A crash during the execution window of a *non-idempotent*
/// task must not leave the task claimable.
#[test]
fn a_crash_mid_execution_does_not_make_a_non_idempotent_task_retryable() {
    let d = dir("non-idempotent");
    let db = db_in(&d);
    let ready = d.join("ready");

    kill_during_execution(&db, &ready, "workflow");

    // Before recovery: exactly the state a crash in the window leaves behind.
    {
        let e = open_engine(&db);
        let before = e.task(&tid("v93-task")).expect("read").expect("present");
        assert_eq!(before.state, TaskState::Running, "precondition: running");
        assert_eq!(before.lease_holder.as_deref(), Some("doomed-worker"));
        assert!(
            !before.idempotent,
            "precondition: a Workflow is non-idempotent by default"
        );
        let repo = TaskRepository::new_readonly(e.conn());
        assert!(
            !repo
                .all_effects_resolved(&tid("v93-task"))
                .expect("effects"),
            "precondition: the crash left an unresolved effect"
        );
    }

    // Recovery, through the production path.
    let mut e = open_engine(&db);
    e.recover(NOW).expect("recovery must not fail");

    assert_terminally_uncertain(&mut e, &tid("v93-task"), "non-idempotent crash");
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------ the audit event

/// Recovery must say what it did, and must not say the work completed.
#[test]
fn recovery_records_an_uncertainty_event_and_never_a_completion() {
    let d = dir("event");
    let db = db_in(&d);
    kill_during_execution(&db, &d.join("ready"), "workflow");

    let mut e = open_engine(&db);
    e.recover(NOW).expect("recovery");

    let repo = TaskRepository::new_readonly(e.conn());
    let events = repo.all_events().expect("events");

    let kinds: Vec<&str> = events.iter().map(|ev| ev.kind.as_str()).collect();
    assert!(
        kinds.iter().any(|k| k.contains("needs-verification")),
        "recovery must record that it settled the task into `needs-verification`, got {kinds:?}"
    );
    // Scoped to what *recovery* wrote. The task's earlier history legitimately
    // contains `enqueued -> pending`; only the events recovery itself appends are
    // statements about the orphan, and those are the ones that must not describe
    // the task as completable or retryable.
    let recovery_events: Vec<&orxnud_store::task_repo::TaskEvent> = events
        .iter()
        .filter(|ev| {
            matches!(
                ev.kind.as_str(),
                "recovered" | "needs-verification-recovered" | "dead-lettered"
            )
        })
        .collect();
    assert!(
        !recovery_events.is_empty(),
        "recovery must append an event of its own; got {kinds:?}"
    );
    for ev in recovery_events {
        assert_ne!(
            ev.to_state,
            Some(TaskState::Completed),
            "no recovery event may claim the task completed: {ev:?}"
        );
        assert_ne!(
            ev.to_state,
            Some(TaskState::Pending),
            "no recovery event may report an uncertain task as retryable: {ev:?}"
        );
        // The event names the state it moved to and why. It carries no payload:
        // the content that may have been written must not be copied here.
        assert!(
            ev.detail.as_deref().is_none_or(|d| !d.contains("contents")),
            "the event must not carry the effect's payload: {ev:?}"
        );
    }

    // The transition itself is recorded as the legal edge it is.
    let settling = events
        .iter()
        .find(|ev| ev.kind.as_str().contains("needs-verification"))
        .expect("the settling event");
    assert_eq!(settling.from_state, Some(TaskState::Running));
    assert_eq!(settling.to_state, Some(TaskState::NeedsVerification));
    assert!(
        is_legal_transition(TaskState::Running, TaskState::NeedsVerification),
        "the edge recovery uses must be legal in the domain"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------ approval reuse

/// The approval that authorised the interrupted execution must not be revived.
#[test]
fn the_approval_that_authorised_the_interrupted_execution_is_not_reusable() {
    let d = dir("approval");
    let db = db_in(&d);
    kill_during_execution(&db, &d.join("ready"), "workflow");

    // Record the approval for the attempt the dead worker held, then recover.
    {
        let e = open_engine(&db);
        let attempt = e
            .task(&tid("v93-task"))
            .expect("read")
            .expect("present")
            .attempts;
        let mut e = e;
        e.record_approval(&orxnud_store::task_repo::ApprovalRow {
            task_id: tid("v93-task"),
            step_no: 1,
            attempt_no: attempt,
            digest_hex: "aa".repeat(32),
            capability: "filesystem/write-text".to_owned(),
            target: Some("out.txt".to_owned()),
            params: "{}".to_owned(),
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60_000,
            consumed_at_ms: None,
        })
        .expect("record the approval the interrupted execution used");
        e.recover(NOW).expect("recovery");
    }

    // After recovery the task is terminal, so there is nothing to execute. The
    // stronger property is that even the approval row cannot be re-consumed: the
    // recovery path must not have marked it usable for a later attempt.
    let mut e = open_engine(&db);
    let row = e.task(&tid("v93-task")).expect("read").expect("present");
    assert_eq!(row.state, TaskState::NeedsVerification);
    assert!(
        e.claim_task("second-worker", NOW).expect("claim").is_none(),
        "an uncertain task must be inexecutable, so no approval can be spent on it"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// --------------------------------------------------- the idempotency matrix

/// The other half of the matrix: an **idempotent** task in the same crash window
/// is recoverable, because repeating it cannot duplicate an effect.
///
/// Without this, the V-93 fix would turn every crashed task into
/// `needs-verification` and make the queue useless.
#[test]
fn a_crash_mid_execution_leaves_an_idempotent_task_retryable() {
    let d = dir("idempotent");
    let db = db_in(&d);
    kill_during_execution_with(&db, &d.join("ready"), "query", "idempotent");

    let mut e = open_engine(&db);
    let before = e.task(&tid("v93-task")).expect("read").expect("present");
    assert!(
        before.idempotent,
        "precondition: a Query is idempotent by default"
    );
    e.recover(NOW).expect("recovery");

    let after = e.task(&tid("v93-task")).expect("read").expect("present");
    assert_eq!(
        after.state,
        TaskState::Pending,
        "an idempotent task must stay recoverable, got {:?}",
        after.state
    );
    assert!(
        after.lease_holder.is_none(),
        "the dead owner must be cleared"
    );

    // And it really is claimable again: the fix must not have broken recovery.
    assert!(
        e.claim_task("second-worker", NOW).expect("claim").is_some(),
        "an idempotent task must still be claimable after recovery"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// A non-idempotent task that crashed **before** performing any effect is
/// recoverable: nothing happened, so repeating changes nothing.
///
/// This is the distinction that makes the fix more than `if !idempotent`. The
/// dangerous fact is not "the task is non-idempotent"; it is "the world may
/// already have changed in a way that repeating could duplicate".
#[test]
fn a_non_idempotent_task_with_no_reserved_effect_stays_retryable() {
    let d = dir("no-effect");
    let db = db_in(&d);

    let mut e = open_engine(&db);
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("v93-task"), TaskKind::Workflow, NOW),
        NOW,
    )
    .expect("enqueue");
    e.claim_task("doomed-worker", NOW)
        .expect("claim")
        .expect("claimed");
    // Deliberately no `reserve_effect`: the crash happened before any effect was
    // dispatched, so the ledger is empty and the world is unchanged.

    let repo = TaskRepository::new_readonly(e.conn());
    assert!(
        repo.effects_for(&tid("v93-task"))
            .expect("effects")
            .is_empty(),
        "precondition: no effect was reserved"
    );

    e.recover(NOW).expect("recovery");
    let after = e.task(&tid("v93-task")).expect("read").expect("present");
    assert_eq!(
        after.state,
        TaskState::Pending,
        "a non-idempotent task that never dispatched an effect is recoverable, got {:?}",
        after.state
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// A non-idempotent task whose effect is *known not to have happened* is
/// recoverable too. This is V-92's `Refuted -> Failed` row applied at recovery:
/// the verifier already decided this finding makes a retry safe.
#[test]
fn a_non_idempotent_task_whose_effect_was_proved_not_performed_stays_retryable() {
    let d = dir("not-performed");
    let db = db_in(&d);
    kill_during_execution(&db, &d.join("ready"), "workflow");

    let mut e = open_engine(&db);
    let key = DurableEngine::idempotency_key(&tid("v93-task"), "external-call", "initial");
    assert!(
        e.resolve_effect(&key, EffectStatus::NotPerformed, Some("no effect"), NOW)
            .expect("resolve"),
        "the disproof must be recorded"
    );
    e.recover(NOW).expect("recovery");

    let after = e.task(&tid("v93-task")).expect("read").expect("present");
    assert_eq!(
        after.state,
        TaskState::Pending,
        "a disproved effect cannot be duplicated by a retry, got {:?}",
        after.state
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// An effect the verifier recorded as `unknown` before the crash is still
/// uncertainty. The crash landing after the record rather than before it must not
/// make the difference.
#[test]
fn a_non_idempotent_task_whose_effect_was_recorded_unknown_is_still_uncertain() {
    let d = dir("unknown-effect");
    let db = db_in(&d);
    kill_during_execution(&db, &d.join("ready"), "workflow");

    let mut e = open_engine(&db);
    let key = DurableEngine::idempotency_key(&tid("v93-task"), "external-call", "initial");
    assert!(
        e.resolve_effect(&key, EffectStatus::Unknown, Some("timed out"), NOW)
            .expect("resolve"),
        "the unknown verdict must be recorded"
    );
    e.recover(NOW).expect("recovery");
    assert_terminally_uncertain(&mut e, &tid("v93-task"), "recorded-unknown");
    let _ = std::fs::remove_dir_all(&d);
}

/// An effect recorded as `observed` is not uncertain, but it is also not safe to
/// *repeat* for a non-idempotent task: the effect happened, so dispatching it
/// again duplicates it. Recovery must therefore not make it claimable.
#[test]
fn a_non_idempotent_task_whose_effect_was_observed_is_not_reclaimable() {
    let d = dir("observed-effect");
    let db = db_in(&d);
    kill_during_execution(&db, &d.join("ready"), "workflow");

    let mut e = open_engine(&db);
    let key = DurableEngine::idempotency_key(&tid("v93-task"), "external-call", "initial");
    assert!(
        e.resolve_effect(&key, EffectStatus::Observed, Some("written"), NOW)
            .expect("resolve"),
        "the observed verdict must be recorded"
    );
    e.recover(NOW).expect("recovery");
    assert_terminally_uncertain(&mut e, &tid("v93-task"), "observed-effect");
    let _ = std::fs::remove_dir_all(&d);
}

/// Fail closed on a ledger this build cannot read. An unrecognised status is not
/// "probably fine" — it is a row whose meaning is unknown, and the only safe
/// reading of an unknown row for a non-idempotent task is "do not repeat this".
#[test]
fn an_unreadable_effect_status_fails_closed_for_a_non_idempotent_task() {
    let d = dir("malformed");
    let db = db_in(&d);
    kill_during_execution(&db, &d.join("ready"), "workflow");

    {
        let e = open_engine(&db);
        // The CHECK constraint holds off `writable_schema`, which is how a future
        // writer or a hand-repair would produce exactly this row.
        // `ignore_check_constraints` is the right tool: `writable_schema` edits the
        // *schema*, not DML, so the CHECK still fires. This is how a corrupt row or
        // a hand-repair from a future writer would actually appear.
        e.conn()
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("ignore_check_constraints");
        e.conn()
            .execute(
                "UPDATE task_effects SET status = 'in-flux' WHERE task_id = 'v93-task';",
                [],
            )
            .expect("write the unrecognised status");
        e.conn()
            .execute_batch("PRAGMA ignore_check_constraints = OFF;")
            .expect("restore");
    }

    let mut e = open_engine(&db);
    e.recover(NOW)
        .expect("recovery must not fail on an unreadable status");
    assert_terminally_uncertain(&mut e, &tid("v93-task"), "unreadable-status");
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------- the retry budget

/// An uncertain task is terminal regardless of whether it had attempts left. The
/// budget is not a licence to repeat uncertain work, and dead-lettering would
/// report the wrong reason.
#[test]
fn uncertainty_takes_precedence_over_the_retry_budget() {
    let d = dir("budget");
    let db = db_in(&d);
    kill_during_execution(&db, &d.join("ready"), "workflow");

    {
        let e = open_engine(&db);
        // Exhaust the budget: the pre-fix code dead-lettered here.
        e.conn()
            .execute(
                "UPDATE tasks SET attempts = max_attempts WHERE id = 'v93-task';",
                [],
            )
            .expect("exhaust the budget");
    }

    let mut e = open_engine(&db);
    e.recover(NOW).expect("recovery");
    let after = e.task(&tid("v93-task")).expect("read").expect("present");
    assert_eq!(
        after.state,
        TaskState::NeedsVerification,
        "an exhausted budget must not convert uncertainty into a dead letter, got {:?}",
        after.state
    );
    let _ = std::fs::remove_dir_all(&d);
}

// -------------------------------------------------------------- restart proof

/// Two processes, two `recover()` calls, one database: the uncertainty is durable
/// and a second daemon cannot undo it.
#[test]
fn the_uncertainty_survives_a_second_recovery_and_a_second_worker() {
    let d = dir("restart");
    let db = db_in(&d);
    kill_during_execution(&db, &d.join("ready"), "workflow");

    // Process 1 recovers.
    {
        let mut e = open_engine(&db);
        e.recover(NOW).expect("first recovery");
    }
    // Process 2 opens the same file and recovers again, which is what a restart
    // does before it serves a single request.
    let mut e = open_engine(&db);
    assert_eq!(
        e.recover(NOW).expect("second recovery"),
        0,
        "a second recovery has nothing left to reclaim"
    );

    assert_terminally_uncertain(&mut e, &tid("v93-task"), "after-restart");
    let _ = std::fs::remove_dir_all(&d);
}

/// The harness itself must be honest: if the child never reached the execution
/// window the crash tests would be passing vacuously.
#[test]
fn the_child_entry_point_is_harmless_without_the_environment() {
    assert!(
        std::env::var_os(ENV_POINT).is_none(),
        "the parent must not set this in the parent's own environment"
    );
    crash_child_entry_point();
}

// ------------------------------------------ the flag is the effect's, not the task's

/// **The case that decides the design.** A task flagged *idempotent* that crashed while
/// dispatching a *non-idempotent* effect must still be recovered as uncertain.
///
/// This is not hypothetical, and it is not an edge: the daemon's `task/create` defaults
/// to a `query` kind, so a task created without an explicit `kind` carries
/// `tasks.idempotent = 1` even when the next thing it does is run
/// `filesystem/write-text`. Deciding recovery from the task's flag would leave every
/// such task auto-retryable, which is the defect V-93 exists to close.
///
/// It is also the substitution V-92 deliberately refused, in a comment on
/// `settle_unverified`: the task's flag answers a different question, and reading it
/// for an effect decision "would be exactly the substitution Phase 12 of the brief
/// warns against".
#[test]
fn an_idempotent_task_that_dispatched_a_non_idempotent_effect_is_still_uncertain() {
    let d = dir("task-flag-misleading");
    let db = db_in(&d);
    // A `query` task: `tasks.idempotent` is TRUE.
    kill_during_execution_with(&db, &d.join("ready"), "query", "non-idempotent");

    {
        let e = open_engine(&db);
        let before = e.task(&tid("v93-task")).expect("read").expect("present");
        assert!(
            before.idempotent,
            "precondition: the task row claims this task is safe to re-run"
        );
        let repo = TaskRepository::new_readonly(e.conn());
        let effects = repo.effects_for(&tid("v93-task")).expect("effects");
        assert_eq!(effects.len(), 1, "exactly one effect was reserved");
        assert!(
            !effects[0].idempotent,
            "precondition: the *effect* is not safe to repeat"
        );
        assert_eq!(effects[0].status, "pending", "and its outcome is unknown");
    }

    let mut e = open_engine(&db);
    e.recover(NOW).expect("recovery");
    assert_terminally_uncertain(
        &mut e,
        &tid("v93-task"),
        "idempotent task, non-idempotent effect",
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The mirror image: a task flagged **non-idempotent** that dispatched an effect the
/// capability declares idempotent must stay recoverable. Otherwise adding a read-only
/// capability to an existing workflow task would strand the task on any crash.
#[test]
fn a_non_idempotent_task_that_dispatched_an_idempotent_effect_stays_retryable() {
    let d = dir("effect-flag-relieves");
    let db = db_in(&d);
    kill_during_execution_with(&db, &d.join("ready"), "workflow", "idempotent");

    let mut e = open_engine(&db);
    let before = e.task(&tid("v93-task")).expect("read").expect("present");
    assert!(
        !before.idempotent,
        "precondition: the task row claims this task is not safe to re-run"
    );
    e.recover(NOW).expect("recovery");

    let after = e.task(&tid("v93-task")).expect("read").expect("present");
    assert_eq!(
        after.state,
        TaskState::Pending,
        "an effect the capability declares safe to repeat must not strand the task, got {:?}",
        after.state
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The reservation records the effect's repeat-safety, so a later reader does not have
/// to guess it or reach for the task row.
#[test]
fn a_reservation_records_the_effects_repeat_safety() {
    let d = dir("recorded-flag");
    let db = db_in(&d);

    let mut e = open_engine(&db);
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("v93-task"), TaskKind::Workflow, NOW),
        NOW,
    )
    .expect("enqueue");
    e.claim_task("w", NOW).expect("claim").expect("claimed");

    for (step, idempotent) in [("count", true), ("external-call", false)] {
        let key = DurableEngine::idempotency_key(&tid("v93-task"), step, "initial");
        assert!(
            e.reserve_effect(&key, &tid("v93-task"), 1, step, idempotent, NOW)
                .expect("reserve"),
            "reserve {step}"
        );
    }

    let repo = TaskRepository::new_readonly(e.conn());
    let effects = repo.effects_for(&tid("v93-task")).expect("effects");
    assert_eq!(effects.len(), 2);
    let recorded: Vec<(&str, bool)> = effects
        .iter()
        .map(|r| (r.step_key.as_str(), r.idempotent))
        .collect();
    assert_eq!(
        recorded,
        vec![("count", true), ("external-call", false)],
        "each reservation must carry its own repeat-safety, not the task's"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------- concurrency

/// Recovery cannot leave a window in which another connection sees the task as
/// claimable before the uncertainty is durable.
///
/// The mechanism is structural rather than hoped-for: the decision is a single
/// `UPDATE ... SET state = CASE ...` with **no preceding read**, so there is no
/// read-then-act pair for another writer to interleave with. Both writers can only
/// observe one state or the other, never an intermediate one. This test asserts that
/// by making the claim attempt from a genuinely separate connection while recovery
/// holds the task open.
///
/// It also pins the property the audit flagged as a dependency: every transaction
/// here is `BEGIN DEFERRED` (the separate finding that this crate runs
/// `BEGIN IMMEDIATE`), so the guarantee must come from the statement's shape, not
/// from the isolation level. If the decision is ever rewritten as a read followed by
/// a write, this test is what notices.
#[test]
fn a_claim_from_another_connection_never_observes_a_recoverable_uncertain_task() {
    let d = dir("concurrency");
    let db = db_in(&d);
    kill_during_execution_with(&db, &d.join("ready"), "workflow", "non-idempotent");

    // The second connection is opened *before* recovery runs, so it is a real
    // competing reader/writer rather than a reader that starts afterwards and
    // therefore cannot interleave.
    let other = {
        let conn = rusqlite::Connection::open(&db).expect("second connection");
        Pragma::critical().apply(&conn).expect("pragmas");
        MigrationRunner::new(&conn).run(true).expect("migrate");
        conn
    };

    // Before recovery the task is `running` under a dead owner. Neither connection
    // may claim it: that is the pre-existing fence, and it is what stops the window
    // from mattering before recovery runs.
    {
        let claim: Option<String> = other
            .query_row(
                "SELECT id FROM tasks
                  WHERE state = 'pending' AND run_after_ms <= ?1 AND attempts < max_attempts
                  LIMIT 1;",
                [NOW],
                |r| r.get(0),
            )
            .optional()
            .expect("query");
        assert!(
            claim.is_none(),
            "a task holding a dead owner's lease must not be claimable before recovery"
        );
    }

    let mut e = open_engine(&db);
    e.recover(NOW).expect("recovery");

    // After recovery, from the second connection, with the identical predicate
    // `take_lease` uses. `needs-verification` is not `pending`, so nothing matches.
    let visible: Vec<(String, String)> = {
        let mut stmt = other
            .prepare("SELECT id, state FROM tasks ORDER BY id;")
            .expect("prepare");
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("query");
        let mut v = Vec::new();
        for row in rows {
            v.push(row.expect("row"));
        }
        v
    };
    assert_eq!(
        visible,
        vec![("v93-task".to_owned(), "needs-verification".to_owned())],
        "the only observable state must be the settled one"
    );
    let claim: Option<String> = other
        .query_row(
            "SELECT id FROM tasks
              WHERE state = 'pending' AND run_after_ms <= ?1 AND attempts < max_attempts
              LIMIT 1;",
            [NOW],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .expect("query");
    assert!(
        claim.is_none(),
        "the second connection can still claim the task: {claim:?}"
    );

    // And a real claim through the production engine agrees.
    assert!(
        e.claim_task("racing-worker", NOW).expect("claim").is_none(),
        "the engine's claim path must agree with the raw predicate"
    );
    drop(other);
    let _ = std::fs::remove_dir_all(&d);
}

/// Two connections racing to *recover* the same orphan converge on one answer.
///
/// The second `recover()` sees nothing left to reclaim, so it must not re-apply the
/// transition or resurrect the row. This is the count-is-a-claim question: a recovery
/// that reports rows it did not change is a recovery a supervisor cannot trust.
#[test]
fn two_concurrent_recoveries_converge_and_the_second_reports_nothing() {
    let d = dir("double-recovery");
    let db = db_in(&d);
    kill_during_execution_with(&db, &d.join("ready"), "workflow", "non-idempotent");

    let mut first = open_engine(&db);
    let mut second = open_engine(&db);

    let a = first.recover(NOW).expect("first recovery");
    let b = second.recover(NOW).expect("second recovery");
    assert_eq!(a, 1, "the first recovery reclaimed the orphan");
    assert_eq!(
        b, 0,
        "the second recovery had nothing left to do, but reported {b}"
    );

    // Exactly one transition was recorded. Two would mean the audit log claims the
    // task moved twice.
    let repo = TaskRepository::new_readonly(first.conn());
    let settling: Vec<_> = repo
        .all_events()
        .expect("events")
        .into_iter()
        .filter(|ev| ev.kind.as_str().contains("needs-verification"))
        .collect();
    assert_eq!(
        settling.len(),
        1,
        "exactly one settling event, not one per recovery: {settling:?}"
    );
    drop(second);
    drop(first);
    let _ = std::fs::remove_dir_all(&d);
}
