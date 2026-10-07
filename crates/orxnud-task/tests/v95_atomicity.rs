//! V-95 Phase 11: the atomicity boundary, proved by what survives a failure.
//!
//! # Why this file is separate from the concurrency tests
//!
//! `v95_concurrency.rs` asks what happens when two writers meet. This file asks what
//! survives when a single writer *dies* partway through — and the requirement is the
//! same in both: **do not claim atomicity because a Rust `Transaction` object exists.**
//! The object is a promise; this file checks the promise.
//!
//! # How the failure is injected
//!
//! The window between "the state row is written" and "the event is written" inside one
//! transaction is far too short to hit from outside with a signal. So it is hit from
//! *inside*, with a SQLite trigger that aborts the statement at a chosen point. That is
//! not a simulation: the abort propagates as a real statement error and the transaction
//! rolls back exactly as it would if the process had been killed between two statements.
//!
//! The real `SIGKILL` windows are not simulated and not simulated here either — they are
//! covered by real child processes in `crash_recovery_uncertainty.rs`, which kills at the
//! points a signal *can* reach: after the effect is reserved and before it is settled.
//!
//! # What "proved" means for each window
//!
//! For every case the same four things are checked, because a partial answer hides the
//! interesting failure:
//!
//! * **durable state** — what a restart would read.
//! * **authority state** — whether an approval was spent, since that is the one thing
//!   here that cannot be taken back.
//! * **audit state** — whether an event was committed that describes a mutation which
//!   did not happen.
//! * **recoverability** — whether the task can still make progress.

use std::path::{Path, PathBuf};

use orxnud_domain::ids::TaskId;
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::{ApprovalRow, NewTask, TaskRepository};
use orxnud_task::{DurableEngine, EngineLimits};
use rusqlite::Connection;

/// 2026-01-01T00:00:00Z. Fixed, so every assertion is about the transition and not about
/// a clock that moved.
const NOW: i64 = 1_767_225_600_000;
const LEASE_MS: i64 = 30_000;

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-v95-atomicity-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn db_in(d: &Path) -> PathBuf {
    d.join("state.db")
}

fn tid(s: &str) -> TaskId {
    TaskId::new(s)
}

fn open_engine(path: &Path) -> DurableEngine {
    let conn = Connection::open(path).expect("open");
    Pragma::critical().apply(&conn).expect("pragmas");
    Pragma::critical().verify(&conn).expect("verify pragmas");
    MigrationRunner::new(&conn).run(true).expect("migrate");
    DurableEngine::new(conn, EngineLimits::documented()).expect("engine")
}

/// A task parked at `waiting-for-user` with an approved proposal and an unspent approval.
fn approved_waiting_task(path: &Path, id: &str, digest_hex: &str) {
    let mut e = open_engine(path);
    e.enqueue_new(&NewTask::new(tid(id), TaskKind::Workflow, NOW), NOW)
        .expect("enqueue");
    let attempt = e
        .claim_task("preparer", NOW)
        .expect("claim")
        .expect("a task to claim")
        .attempts;

    let mut repo = TaskRepository::new(e.conn_mut());
    repo.record_approval(&ApprovalRow {
        task_id: tid(id),
        step_no: 1,
        attempt_no: attempt,
        digest_hex: digest_hex.to_owned(),
        capability: "filesystem/write-text".to_owned(),
        target: Some("out.txt".to_owned()),
        params: r#"{"path":"out.txt","contents":"x"}"#.to_owned(),
        issued_at_ms: NOW,
        expires_at_ms: NOW + 60_000,
        consumed_at_ms: None,
    })
    .expect("record approval");

    let proposal = repo
        .propose_action(
            "proposal-under-test",
            &tid(id),
            "preparer",
            "filesystem/write-text",
            Some("out.txt"),
            r#"{"path":"out.txt","contents":"x"}"#,
            r#"{"kind":"human"}"#,
            None,
            1,
            NOW,
        )
        .expect("propose")
        .proposal_id;
    repo.decide_proposal(&proposal, "approved", NOW)
        .expect("approve");
}

/// The four answers, gathered once so no case can quietly skip one.
struct Snapshot {
    state: String,
    lease_holder: Option<String>,
    approval_spent: bool,
    execution_begun_events: usize,
}

fn snapshot(path: &Path, id: &str) -> Snapshot {
    let e = open_engine(path);
    let row = e.task(&tid(id)).expect("read").expect("present");
    let approval_spent: bool = e
        .conn()
        .query_row(
            "SELECT consumed_at_ms IS NOT NULL FROM task_approvals WHERE task_id = ?1;",
            [id],
            |r| r.get(0),
        )
        .expect("read approval");
    let repo = TaskRepository::new_readonly(e.conn());
    let execution_begun_events = repo
        .all_events()
        .expect("events")
        .iter()
        .filter(|ev| ev.kind == "approved-execution-begun")
        .count();
    Snapshot {
        state: row.state.as_wire_str().to_owned(),
        lease_holder: row.lease_holder.clone(),
        approval_spent,
        execution_begun_events,
    }
}

impl std::fmt::Display for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "state={} lease={:?} approval_spent={} execution_begun_events={}",
            self.state, self.lease_holder, self.approval_spent, self.execution_begun_events
        )
    }
}

// ========================================================= the failure windows

/// The baseline: with no injected failure the operation does what it claims, so the
/// assertions in the other cases are compared against a known-good outcome rather than
/// against an assumption.
#[test]
fn the_window_baseline_commits_state_authority_and_event_together() {
    let d = dir("baseline");
    let db = db_in(&d);
    approved_waiting_task(&db, "t", &"ab".repeat(32));

    {
        let mut e = open_engine(&db);
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.begin_execution_spending_approval("proposal-under-test", "w", NOW, LEASE_MS)
            .expect("begin execution");
    }

    let s = snapshot(&db, "t");
    assert_eq!(s.state, "running");
    assert_eq!(s.lease_holder.as_deref(), Some("w"));
    assert!(s.approval_spent, "the authority spend must be recorded");
    assert_eq!(
        s.execution_begun_events, 1,
        "exactly one event, and it matches the state that was committed"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// Window: **after the state mutation's first write, before the event.** The abort
/// happens at the approval spend, which is the first write in
/// `begin_execution_spending_approval`.
///
/// If the approval spend and the lease were separate operations, this would leave an
/// approval spent for an execution that never began. One transaction means neither
/// survives.
#[test]
fn a_failure_at_the_first_write_rolls_back_the_whole_operation() {
    let d = dir("abort-first-write");
    let db = db_in(&d);
    approved_waiting_task(&db, "t", &"ab".repeat(32));
    {
        let e = open_engine(&db);
        e.conn()
            .execute_batch(
                "CREATE TRIGGER abort_the_spend BEFORE UPDATE OF consumed_at_ms ON task_approvals
                   BEGIN SELECT RAISE(ABORT, 'injected: writer died at the first write'); END;",
            )
            .expect("trigger");
    }

    let err = {
        let mut e = open_engine(&db);
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.begin_execution_spending_approval("proposal-under-test", "w", NOW, LEASE_MS)
            .expect_err("the injected abort must propagate")
    };
    assert!(
        format!("{err}").contains("injected"),
        "the injected failure must be the one that surfaces, not something it masked: {err}"
    );

    let s = snapshot(&db, "t");
    assert_eq!(
        s.state, "waiting-for-user",
        "the task must be exactly as it was: {s}"
    );
    assert_eq!(s.lease_holder, None, "no lease may survive: {s}");
    assert!(
        !s.approval_spent,
        "an approval spent for an execution that never began is unrecoverable, and is \
         the specific thing this transaction exists to prevent: {s}"
    );
    assert_eq!(s.execution_begun_events, 0, "no event may describe it: {s}");
    let _ = std::fs::remove_dir_all(&d);
}

/// Window: **after the state mutation, before the event.** The lease write succeeds; the
/// event append is what fails.
///
/// This is the window that most directly tests whether the mutation and its log share one
/// boundary. Without a shared boundary the task would be `running` with a lease and the
/// audit log would be silent about it — which is a false negative in the audit trail,
/// recoverable in principle but undetectable in fact.
#[test]
fn a_failure_after_the_state_mutation_leaves_no_mutation_and_no_event() {
    let d = dir("abort-before-event");
    let db = db_in(&d);
    approved_waiting_task(&db, "t", &"ab".repeat(32));
    {
        let e = open_engine(&db);
        e.conn()
            .execute_batch(
                "CREATE TRIGGER abort_the_event BEFORE INSERT ON task_events
                   BEGIN SELECT RAISE(ABORT, 'injected: writer died before the event'); END;",
            )
            .expect("trigger");
    }

    {
        let mut e = open_engine(&db);
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.begin_execution_spending_approval("proposal-under-test", "w", NOW, LEASE_MS)
            .expect_err("the injected abort must propagate");
    }

    let s = snapshot(&db, "t");
    assert_eq!(
        s.state, "waiting-for-user",
        "the lease write must have rolled back with the event write: {s}"
    );
    assert_eq!(s.lease_holder, None, "{s}");
    assert!(!s.approval_spent, "and so must the approval spend: {s}");
    assert_eq!(
        s.execution_begun_events, 0,
        "no event may claim a mutation that did not commit: {s}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// Window: **after the event, before COMMIT.** The event row has been written inside the
/// transaction; the commit is what fails.
///
/// This is the mirror of the previous window and it matters just as much: the event is
/// the last thing written, so if the commit failed and the event survived, the audit log
/// would claim a transition that the task table contradicts. The two windows together
/// are what "one atomicity boundary" means, and neither alone would be evidence of it.
#[test]
fn a_failure_after_the_event_leaves_no_event_and_no_mutation() {
    let d = dir("abort-after-event");
    let db = db_in(&d);
    approved_waiting_task(&db, "t", &"ab".repeat(32));
    {
        let e = open_engine(&db);
        // `AFTER INSERT` runs after the row is written into the transaction, so this
        // aborts with the event already staged and only the COMMIT left.
        e.conn()
            .execute_batch(
                "CREATE TRIGGER abort_after_the_event AFTER INSERT ON task_events
                   BEGIN SELECT RAISE(ABORT, 'injected: writer died after the event'); END;",
            )
            .expect("trigger");
    }

    {
        let mut e = open_engine(&db);
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.begin_execution_spending_approval("proposal-under-test", "w", NOW, LEASE_MS)
            .expect_err("the injected abort must propagate");
    }

    let s = snapshot(&db, "t");
    assert_eq!(s.state, "waiting-for-user", "{s}");
    assert_eq!(s.lease_holder, None, "{s}");
    assert!(!s.approval_spent, "{s}");
    assert_eq!(
        s.execution_begun_events, 0,
        "an event describing a transition the task table contradicts is worse than no \
         event at all: the log would assert something false: {s}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// Recoverability, stated positively: after any of those failures the task is not stuck.
/// It is still claimable and its approval is still usable, which is what makes a refusal
/// retryable rather than terminal.
#[test]
fn a_task_refused_by_a_failed_attempt_is_still_fully_retryable() {
    let d = dir("recoverable");
    let db = db_in(&d);
    approved_waiting_task(&db, "t", &"ab".repeat(32));
    {
        let e = open_engine(&db);
        e.conn()
            .execute_batch(
                "CREATE TRIGGER abort_the_event BEFORE INSERT ON task_events
                   BEGIN SELECT RAISE(ABORT, 'injected'); END;",
            )
            .expect("trigger");
    }
    {
        let mut e = open_engine(&db);
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.begin_execution_spending_approval("proposal-under-test", "w", NOW, LEASE_MS)
            .expect_err("injected");
    }

    // Remove the fault and try again, as a later attempt would.
    {
        let e = open_engine(&db);
        e.conn()
            .execute_batch("DROP TRIGGER abort_the_event;")
            .expect("drop trigger");
    }
    {
        let mut e = open_engine(&db);
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.begin_execution_spending_approval("proposal-under-test", "w2", NOW, LEASE_MS)
            .expect("the retry must succeed: nothing durable blocked it");
    }

    let s = snapshot(&db, "t");
    assert_eq!(s.state, "running", "{s}");
    assert_eq!(
        s.lease_holder.as_deref(),
        Some("w2"),
        "and the lease belongs to the retry: {s}"
    );
    assert!(s.approval_spent, "{s}");
    assert_eq!(
        s.execution_begun_events, 1,
        "exactly one event, from the attempt that actually committed: {s}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The same four questions, asked of `propose_action` — the other P1-16 site — because
/// a transaction that is correct for one operation is no evidence about the next.
#[test]
fn a_failure_inside_propose_action_leaves_neither_proposal_nor_state_change() {
    let d = dir("propose-atomicity");
    let db = db_in(&d);
    approved_waiting_task(&db, "t", &"ab".repeat(32));
    let before = snapshot(&db, "t");
    {
        let e = open_engine(&db);
        e.conn()
            .execute_batch(
                "CREATE TRIGGER abort_proposal_insert BEFORE INSERT ON task_proposals
                   BEGIN SELECT RAISE(ABORT, 'injected: writer died at the proposal'); END;",
            )
            .expect("trigger");
    }

    {
        let mut e = open_engine(&db);
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.propose_action(
            "second-proposal",
            &tid("t"),
            "w",
            "filesystem/write-text",
            Some("out.txt"),
            r#"{"path":"out.txt","contents":"x"}"#,
            r#"{"kind":"human"}"#,
            None,
            1,
            NOW,
        )
        .expect_err("the injected abort must propagate");
    }

    let e = open_engine(&db);
    let proposals: i64 = e
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM task_proposals WHERE proposal_id = 'second-proposal';",
            [],
            |r| r.get(0),
        )
        .expect("count proposals");
    assert_eq!(proposals, 0, "a proposal may not survive its own failure");
    let after = snapshot(&db, "t");
    assert_eq!(
        (after.state.clone(), after.lease_holder.clone()),
        (before.state.clone(), before.lease_holder.clone()),
        "the task must be untouched: {before} -> {after}"
    );
    drop(e);
    let _ = std::fs::remove_dir_all(&d);
}

/// The task's state must not be left `waiting-for-user` *because* the proposal insert
/// failed — the read that decided the task was parkable and the write that parked it are
/// in the same transaction, so a failure between them must undo the decision too.
#[test]
fn a_failure_after_the_proposal_row_leaves_the_task_unparked() {
    let d = dir("propose-atomicity-2");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        e.claim_task("w1", NOW).expect("claim").expect("claimed");
    }
    {
        let e = open_engine(&db);
        // The proposal row is inserted, then the task is parked. Abort the parking.
        e.conn()
            .execute_batch(
                "CREATE TRIGGER abort_the_parking BEFORE UPDATE OF state ON tasks
                   WHEN NEW.state = 'waiting-for-user'
                 BEGIN SELECT RAISE(ABORT, 'injected: writer died before parking'); END;",
            )
            .expect("trigger");
    }

    {
        let mut e = open_engine(&db);
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.propose_action(
            "p",
            &tid("t"),
            "w1",
            "filesystem/write-text",
            Some("out.txt"),
            r#"{"path":"out.txt","contents":"x"}"#,
            r#"{"kind":"human"}"#,
            None,
            1,
            NOW,
        )
        .expect_err("the injected abort must propagate");
    }

    let e = open_engine(&db);
    let row = e.task(&tid("t")).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::Running,
        "the proposal was rolled back, so parking the task must have been too: {row:?}"
    );
    let proposals: i64 = e
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM task_proposals WHERE proposal_id = 'p';",
            [],
            |r| r.get(0),
        )
        .expect("count proposals");
    assert_eq!(
        proposals, 0,
        "and no proposal may exist that nobody was ever asked about"
    );
    drop(e);
    let _ = std::fs::remove_dir_all(&d);
}
