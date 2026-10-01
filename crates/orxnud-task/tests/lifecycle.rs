//! Cancellation, shutdown, idempotency, and retries across real restarts.
//!
//! docs-08 §4.6's row *"Cancellation must not leave state falsely marked as
//! completed"* and *"Shutdown must not silently abandon durable work"* are the two
//! properties this file exists to check. Both are easy to satisfy by accident and
//! easy to break on a restart, so every case here reopens the database rather than
//! trusting an in-memory view.

use std::path::{Path, PathBuf};

use orxnud_domain::ids::TaskId;
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::EffectStatus;
use orxnud_task::{DurableEngine, EngineLimits};

const NOW: i64 = 1_767_225_600_000;
const HOUR: i64 = 3_600_000;

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-cancel-{}-{tag}", std::process::id()));
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
    MigrationRunner::new(&conn).run(true).expect("migrate");
    DurableEngine::new(conn, EngineLimits::documented()).expect("engine")
}

// ------------------------------------------------------------- cancellation

#[test]
fn a_cancellation_is_durable_before_it_is_acted_on() {
    // TP-3: "a cancellation request is durably recorded *before* it is acted upon".
    // Two writes, two log entries, in that order -- observable, not asserted in
    // prose.
    let d = dir("cancel-order");
    let db = db_in(&d);
    let mut e = open_engine(&db);
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
        NOW,
    )
    .expect("enqueue");
    e.cancel_task(&tid("t"), NOW).expect("cancel");

    let repo = orxnud_store::task_repo::TaskRepository::new_readonly(e.conn());
    let kinds: Vec<String> = repo
        .events_for(&tid("t"))
        .expect("events")
        .into_iter()
        .map(|x| x.kind)
        .collect();
    let req = kinds.iter().position(|k| k == "cancel-requested");
    let act = kinds.iter().position(|k| k == "cancelled");
    assert!(req.is_some() && act.is_some(), "{kinds:?}");
    assert!(
        req.expect("req") < act.expect("act"),
        "the request must be durable first: {kinds:?}"
    );

    let row = repo.get(&tid("t")).expect("read").expect("present");
    assert!(
        row.cancel_requested_at_ms == Some(NOW),
        "the request instant must be recorded"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_cancellation_survives_a_restart() {
    let d = dir("cancel-restart");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        e.enqueue_new(
            &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
            NOW,
        )
        .expect("enqueue");
        e.cancel_task(&tid("t"), NOW).expect("cancel");
    }
    let mut e = open_engine(&db);
    assert_eq!(
        e.task(&tid("t")).expect("read").expect("present").state,
        TaskState::Cancelled
    );
    // Recovery must not resurrect it.
    e.recover(NOW).expect("recover");
    assert_eq!(
        e.task(&tid("t")).expect("read").expect("present").state,
        TaskState::Cancelled
    );
    assert!(
        e.claim_task("w", NOW).expect("claim").is_none(),
        "a cancelled task is not claimable"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn cancelling_an_in_flight_task_does_not_let_it_report_completion() {
    // The specific failure docs-08 §4.6 names: the work was already running, the
    // user cancelled, and the worker finishes and reports success. The fence must
    // refuse, or the cancellation was a lie.
    let d = dir("cancel-inflight");
    let db = db_in(&d);
    let mut e = open_engine(&db);
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
        NOW,
    )
    .expect("enqueue");
    let claimed = e.claim_task("w", NOW).expect("claim").expect("claimed");

    e.cancel_task(&tid("t"), NOW + 1).expect("cancel");
    assert_eq!(
        e.task(&tid("t")).expect("read").expect("present").state,
        TaskState::Cancelled
    );

    // The worker, unaware, tries to commit success.
    assert!(
        !e.complete_task(&tid("t"), "w", NOW + 2, TaskState::Completed, true, None)
            .expect("complete"),
        "a cancelled task must not be marked completed by its ex-worker"
    );
    assert_eq!(
        e.task(&tid("t")).expect("read").expect("present").state,
        TaskState::Cancelled,
        "the task must still be cancelled, not completed"
    );
    assert_eq!(
        claimed.state,
        TaskState::Running,
        "the worker's own view is stale"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn cancelling_a_terminal_task_does_not_resurrect_it() {
    let d = dir("cancel-terminal");
    let db = db_in(&d);
    let mut e = open_engine(&db);
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Query, NOW),
        NOW,
    )
    .expect("enqueue");
    let _ = e.claim_task("w", NOW).expect("claim");
    let _ = e.complete_task(&tid("t"), "w", NOW, TaskState::Completed, true, None);
    e.cancel_task(&tid("t"), NOW + 10)
        .expect("cancel is a no-op");
    assert_eq!(
        e.task(&tid("t")).expect("read").expect("present").state,
        TaskState::Completed
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------------ shutdown

#[test]
fn a_shutdown_that_recovers_does_not_lose_accepted_work() {
    // "Shutdown must not silently abandon durable work": every accepted task is
    // either finished or back in the queue, with nothing stranded.
    let d = dir("shutdown");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        for i in 0..6 {
            e.enqueue_new(
                &orxnud_store::task_repo::NewTask::new(tid(&format!("t{i}")), TaskKind::Query, NOW),
                NOW,
            )
            .expect("enqueue");
        }
        // Finish one, leave three running, leave two pending.
        let _ = e.claim_task("w", NOW).expect("claim");
        for _ in 0..3 {
            let _ = e.claim_task("w", NOW).expect("claim");
        }
        e.complete_task(&tid("t0"), "w", NOW, TaskState::Completed, true, None)
            .expect("complete");
    }

    let mut e = open_engine(&db);
    assert_eq!(
        e.recover(NOW + 1).expect("recover"),
        3,
        "three leases were orphaned"
    );

    let all = e.all_tasks().expect("tasks");
    assert_eq!(all.len(), 6, "TP-1: nothing may be lost across a shutdown");
    for row in &all {
        match row.state {
            TaskState::Completed | TaskState::Pending => {}
            other => panic!(
                "{other:?} is neither finished nor requeued for {:?}",
                row.id
            ),
        }
        if row.state == TaskState::Running {
            panic!("{:?} was left running after recovery", row.id);
        }
    }
    // And the five survivors are claimable again.
    let mut claimed = 0;
    for _ in 0..10 {
        if e.claim_task("next", NOW + 1).expect("claim").is_some() {
            claimed += 1;
        }
    }
    assert_eq!(claimed, 5, "five tasks should have been requeued");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn shutdown_and_restart_twice_is_still_coherent() {
    // Two crashes in a row must not compound into a lost task.
    let d = dir("double-shutdown");
    let db = db_in(&d);
    for round in 0..2 {
        {
            let mut e = open_engine(&db);
            e.enqueue_new(
                &orxnud_store::task_repo::NewTask::new(
                    tid(&format!("t{round}")),
                    TaskKind::Query,
                    NOW,
                ),
                NOW,
            )
            .expect("enqueue");
            let _ = e.claim_task("w", NOW).expect("claim");
        }
        let mut e = open_engine(&db);
        e.recover(NOW + round + 1).expect("recover");
    }
    let mut e = open_engine(&db);
    assert_eq!(e.all_tasks().expect("tasks").len(), 2);
    assert_eq!(
        e.recover(NOW + 10).expect("recover"),
        0,
        "nothing is left leased"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// -------------------------------------------------------------- idempotency

#[test]
fn an_idempotency_key_survives_a_restart_and_still_deduplicates() {
    // The claim we make: at-most-once dispatch *attempt* per key, durably. Not
    // exactly-once for a remote system -- see the test below for why that is not
    // claimed.
    let d = dir("idem-restart");
    let db = db_in(&d);
    let key = {
        let mut e = open_engine(&db);
        e.enqueue_new(
            &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
            NOW,
        )
        .expect("enqueue");
        let _ = e.claim_task("w", NOW).expect("claim");
        let k = DurableEngine::idempotency_key(&tid("t"), "charge-card", "initial");
        assert!(
            e.reserve_effect(&k, &tid("t"), 1, "charge-card", NOW)
                .expect("reserve")
        );
        k
    };
    for _ in 0..2 {
        let mut e = open_engine(&db);
        assert!(
            !e.reserve_effect(&key, &tid("t"), 1, "charge-card", NOW)
                .expect("reserve"),
            "a reservation must survive any number of restarts"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_different_step_gets_a_different_key_across_a_restart() {
    let d = dir("idem-steps");
    let db = db_in(&d);
    let mut e = open_engine(&db);
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
        NOW,
    )
    .expect("enqueue");
    let _ = e.claim_task("w", NOW).expect("claim");
    assert!(
        e.reserve_effect(
            &DurableEngine::idempotency_key(&tid("t"), "a", "initial"),
            &tid("t"),
            1,
            "a",
            NOW
        )
        .expect("a")
    );
    drop(e);
    let mut e = open_engine(&db);
    assert!(
        e.reserve_effect(
            &DurableEngine::idempotency_key(&tid("t"), "b", "initial"),
            &tid("t"),
            1,
            "b",
            NOW
        )
        .expect("b"),
        "a different step must not be suppressed by another step's reservation"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_effect_recorded_as_unknown_is_not_reported_as_a_success() {
    // The honest-answer half of TP-12: an unresolved effect is not a completed one.
    let d = dir("unknown-effect");
    let db = db_in(&d);
    let mut e = open_engine(&db);
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
        NOW,
    )
    .expect("enqueue");
    let claimed = e.claim_task("w", NOW).expect("claim").expect("claimed");
    let key = DurableEngine::idempotency_key(&tid("t"), "remote-call", "initial");
    assert!(
        e.reserve_effect(&key, &tid("t"), claimed.attempts, "remote-call", NOW)
            .expect("reserve")
    );
    assert!(
        e.resolve_effect(&key, EffectStatus::Unknown, Some("timeout"), NOW + 1)
            .expect("resolve")
    );

    let row = e.task(&tid("t")).expect("read").expect("present");
    assert_ne!(
        row.state,
        TaskState::Completed,
        "an unknown effect is not a success"
    );
    assert!(
        !e.complete_task(&tid("t"), "w", NOW + 1, TaskState::Completed, false, None)
            .is_ok()
            || row.state != TaskState::Completed,
        "an unresolved-effect task must not be completable as a clean success"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_uncertain_effect_is_recorded_before_the_verification_state() {
    // Ordering: the ledger records what happened, *then* the task moves to
    // `needs-verification`. Doing it the other way round leaves a task awaiting a
    // human with no record of why.
    let d = dir("uncertain-order");
    let db = db_in(&d);
    let mut e = open_engine(&db);
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
        NOW,
    )
    .expect("enqueue");
    let claimed = e.claim_task("w", NOW).expect("claim").expect("claimed");
    let key = DurableEngine::idempotency_key(&tid("t"), "remote", "initial");
    assert!(
        e.reserve_effect(&key, &tid("t"), claimed.attempts, "remote", NOW)
            .expect("reserve")
    );
    assert!(
        e.resolve_effect(&key, EffectStatus::Unknown, None, NOW + 1)
            .expect("resolve")
    );
    let _ = e.complete_task(
        &tid("t"),
        "w",
        NOW + 1,
        TaskState::NeedsVerification,
        true,
        Some("unknown"),
    );
    let row = e.task(&tid("t")).expect("read").expect("present");
    assert_eq!(row.state, TaskState::NeedsVerification);
    assert!(
        row.state.is_terminal(),
        "and terminal, so it is not auto-retried"
    );
    assert!(
        e.all_effects_resolved(&tid("t")).expect("resolved"),
        "with the ledger accounted for"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------------- retries

#[test]
fn a_retry_after_a_restart_gets_a_new_attempt_and_nothing_carried_over() {
    // TP-6's operational half, across the boundary where it is easiest to break.
    let d = dir("retry-restart");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        e.enqueue_new(
            &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
            NOW,
        )
        .expect("enqueue");
        let claimed = e.claim_task("w", NOW).expect("claim").expect("claimed");
        assert_eq!(claimed.attempts, 1);
        // A retry delay, so the task is not immediately claimable before the crash.
        let _ = e.complete_task_with(
            &tid("t"),
            "w",
            NOW,
            TaskState::Failed,
            false,
            Some("boom"),
            Some(HOUR),
        );
    }
    let mut e = open_engine(&db);
    // Before the delay: not claimable.
    assert!(
        e.claim_task("w", NOW + 1).expect("claim").is_none(),
        "a backoff must be honoured"
    );
    // After it: a new attempt.
    let retry = e
        .claim_task("w", NOW + HOUR)
        .expect("claim")
        .expect("claimed");
    assert_eq!(retry.attempts, 2);
    assert_eq!(retry.lease_holder.as_deref(), Some("w"));

    // And the attempt history shows two distinct attempts, the first closed with
    // its error.
    let repo = orxnud_store::task_repo::TaskRepository::new_readonly(e.conn());
    let attempts = repo.attempts_for(&tid("t")).expect("attempts");
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].outcome.as_deref(), Some("failed"));
    assert_eq!(attempts[0].error.as_deref(), Some("boom"));
    assert!(
        attempts[1].finished_at_ms.is_none(),
        "the second attempt is still open"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_task_that_keeps_failing_dies_at_exactly_its_retry_budget() {
    // TP-11 + TP-10: bounded retries, then terminal, and never handed out again.
    let d = dir("retry-budget");
    let db = db_in(&d);
    let mut e = open_engine(&db);
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
        NOW,
    )
    .expect("enqueue");

    let budget = EngineLimits::documented().max_attempts_default;
    for attempt in 1..=budget {
        let claimed = e
            .claim_task("w", NOW + i64::from(attempt) * 1_000)
            .expect("claim")
            .expect("a retry must be available until the budget is spent");
        assert_eq!(claimed.attempts, attempt);
        let _ = e.complete_task_with(
            &tid("t"),
            "w",
            NOW + i64::from(attempt) * 1_000,
            TaskState::Failed,
            false,
            Some("always fails"),
            Some(0),
        );
    }
    let row = e.task(&tid("t")).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::DeadLettered,
        "TP-11: out of retries must be terminal"
    );
    assert_eq!(
        row.last_error.as_deref(),
        Some("always fails"),
        "and carry its last error"
    );
    assert!(row.dead_lettered_at_ms.is_some());
    // And it is never handed out again, however many passes run.
    for i in 100..110 {
        assert!(e.claim_task("w", NOW + i).expect("claim").is_none());
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_dead_lettered_task_is_reported_to_the_user_not_silently_dropped() {
    // TP-11: "is surfaced to the user, and is never silently retried". The engine's
    // report here is `count_in_state`, which is what `doctor` would show.
    let d = dir("dlq-visible");
    let db = db_in(&d);
    let mut e = open_engine(&db);
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
        NOW,
    )
    .expect("enqueue");
    for attempt in 1..=3 {
        let _ = e.claim_task("w", NOW + attempt).expect("claim");
        let _ = e.complete_task_with(
            &tid("t"),
            "w",
            NOW + attempt,
            TaskState::Failed,
            false,
            Some("e"),
            Some(0),
        );
    }
    let repo = orxnud_store::task_repo::TaskRepository::new_readonly(e.conn());
    assert_eq!(
        repo.count_in_state(TaskState::DeadLettered).expect("count"),
        1
    );
    let events = repo.events_for(&tid("t")).expect("events");
    let kinds: Vec<&str> = events.iter().map(|x| x.kind.as_str()).collect();
    assert!(
        kinds.contains(&"dead-lettered"),
        "the dead-letter must be in the log, not just the row: {kinds:?}"
    );
    // And it must not be logged as a plain completion -- a support request reading
    // the event log would otherwise be told the task succeeded.
    let last = events.last().expect("an event");
    assert_eq!(last.kind, "dead-lettered");
    assert_eq!(last.to_state, Some(TaskState::DeadLettered));
    assert_eq!(last.from_state, Some(TaskState::Running));
    let _ = std::fs::remove_dir_all(&d);
}
