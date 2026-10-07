//! V-97: one execution identity, one proposal, one approval.
//!
//! # The defect this file exists to prevent
//!
//! `task_proposals` carried **no** uniqueness on `(task_id, step_no, attempt_no)`. Its only
//! key was the surrogate `proposal_id`, minted as `p-{task_id}-{milliseconds}`, so two
//! proposals could occupy one execution identity and differ from each other by the
//! millisecond they happened to be minted in.
//!
//! That is worse than a missing constraint on its own, because `task_approvals` is keyed on
//! the identity and **not** on `proposal_id`. So an approval recorded for the first
//! proposal was found by the second one, and nothing in the digest bound the two together:
//! `canonical_bytes` names `(approver, actor, capability, target, params, issued, expires,
//! step_no)` and no proposal. The only thing standing between "approve A, execute B" and a
//! dispatched effect was a byte-string comparison in the daemon.
//!
//! # How the duplicate was reachable
//!
//! Not by a race — `authority_transaction` serialises writers and `propose_action` guards
//! on state, so concurrent workers produce exactly one row. It was reachable *sequentially*,
//! because `begin_execution_spending_approval` re-enters `running` **without** advancing
//! `attempts` or `steps_completed`. A worker whose dispatch failed held a live lease on a
//! task that was again `running` at the same `(step, attempt)`, and `propose_action`
//! accepted a second proposal.
//!
//! Migration 14 therefore enforces the identity in the database, reconciles the duplicates
//! that already exist, and refuses to migrate at all when they disagree about the action.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

use orxnud_domain::{TaskId, TaskKind};
use orxnud_store::migration::{MIGRATIONS, MigrationRunner};
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::{
    ApprovalRow, NewTask, TargetedClaimOutcome, TaskRepoError, TaskRepository,
};
use rusqlite::Connection;

const NOW: i64 = 1_767_225_600_000;
const LEASE: i64 = 60_000;

fn tid(s: &str) -> TaskId {
    TaskId::new(s)
}

fn db(tag: &str) -> (PathBuf, Connection) {
    let d = std::env::temp_dir().join(format!("v97id-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    let p = d.join("state.db");
    let c = Connection::open(&p).expect("open");
    Pragma::critical().apply(&c).expect("pragmas");
    MigrationRunner::new(&c).run(true).expect("migrate");
    (p, c)
}

fn cleanup(p: &Path) {
    let _ = std::fs::remove_dir_all(p.parent().unwrap_or(p));
}

/// A database at the last version before this branch's migrations, with two tasks.
fn schema10() -> Connection {
    let c = Connection::open_in_memory().expect("open");
    Pragma::critical().apply(&c).expect("pragmas");
    c.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_meta
           (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL);",
    )
    .expect("schema_meta");
    for m in MIGRATIONS.iter().filter(|m| m.version <= 10) {
        let tx = rusqlite::Transaction::new_unchecked(&c, rusqlite::TransactionBehavior::Immediate)
            .expect("begin");
        tx.execute_batch(m.sql)
            .unwrap_or_else(|e| panic!("v{}: {e}", m.version));
        tx.execute(
            "INSERT OR REPLACE INTO schema_meta VALUES (?1,?2,?3);",
            rusqlite::params![m.version, m.name, NOW],
        )
        .expect("record");
        tx.commit().expect("commit");
    }
    c.execute_batch(
        "INSERT INTO tasks (id,kind,state,idempotent,attempts,max_attempts,created_at_ms,updated_at_ms)
           VALUES ('t1','query','completed',1,1,3,1,1),
                  ('t2','workflow','completed',1,2,5,1,1);
         UPDATE tasks SET steps_completed = 2 WHERE id = 't2';",
    )
    .expect("seed");
    c
}

/// Insert a proposal through SQL, which is the only way to *build* a duplicate: the fixed
/// `propose_action` refuses at the first one.
#[allow(clippy::too_many_arguments)] // a fixture: every parameter is a distinct column value
fn seed_proposal(
    c: &Connection,
    id: &str,
    task: &str,
    step: i64,
    attempt: i64,
    target: &str,
    created_at: i64,
    status: &str,
) {
    let r = c.execute(
        "INSERT INTO task_proposals
           (proposal_id,task_id,attempt_no,step_no,capability,target,params,proposer,
            created_at_ms,status)
         VALUES (?1,?2,?3,?4,'filesystem/write-text',?5,'{}','{}',?6,?7);",
        rusqlite::params![id, task, attempt, step, target, created_at, status],
    );
    assert!(
        r.is_ok(),
        "this fixture relies on duplicates being *insertable* at schema 10; {id} -> {r:?}"
    );
}

fn count_identity(c: &Connection, task: &str, step: i64, attempt: i64) -> i64 {
    c.query_row(
        "SELECT COUNT(*) FROM task_proposals
          WHERE task_id = ?1 AND step_no = ?2 AND attempt_no = ?3;",
        rusqlite::params![task, step, attempt],
        |r| r.get(0),
    )
    .expect("count")
}

// ---------------------------------------------------------------------------
// A. the constraint
// ---------------------------------------------------------------------------

/// Requirement: the database refuses a second proposal for one execution identity.
#[test]
fn a_second_proposal_for_the_same_execution_identity_is_refused_by_the_database() {
    let (p, mut c) = db("identity");
    let mut repo = TaskRepository::new(&mut c);
    repo.insert(&NewTask::new(tid("t"), TaskKind::Query, NOW), NOW)
        .expect("insert");
    let TargetedClaimOutcome::Claimed(_) = repo
        .claim_specific(&tid("t"), "w1", NOW, LEASE)
        .expect("claim")
    else {
        panic!("claimable")
    };
    repo.propose_action(
        "p1",
        &tid("t"),
        "w1",
        "filesystem/write-text",
        Some("out.txt"),
        "{}",
        "{}",
        None,
        1,
        NOW + 1,
    )
    .expect("first proposal");

    // Raw SQL, deliberately: the point is that the *schema* refuses it, not that a guard
    // happens to be in the way above it.
    let err = c.execute(
        "INSERT INTO task_proposals
           (proposal_id,task_id,attempt_no,step_no,capability,target,params,proposer,created_at_ms,status)
         VALUES ('p2','t',1,1,'filesystem/write-text','out.txt','{}','{}',2,'pending');",
        [],
    );
    let msg = format!("{err:?}");
    assert!(
        err.is_err(),
        "a duplicate (task_id, step_no, attempt_no) must be unrepresentable"
    );
    assert!(
        msg.contains("task_proposals.task_id") && msg.contains("task_proposals.step_no"),
        "the refusal must name the identity, not just say UNIQUE: {msg}"
    );
    assert_eq!(count_identity(&c, "t", 1, 1), 1);
    cleanup(&p);
}

/// The constraint is on the *triple*, so a retry on a new attempt is still representable.
/// Migration 7's `UNIQUE (task_id, step_no)` could not do this; that is why migration 8
/// dropped it, and why a triple is the key that was needed.
#[test]
fn a_retry_of_the_same_step_on_a_new_attempt_is_still_representable() {
    let (p, mut c) = db("retry");
    TaskRepository::new(&mut c)
        .insert(&NewTask::new(tid("t"), TaskKind::Query, NOW), NOW)
        .expect("insert the parent task");
    for (id, attempt) in [("p1", 1), ("p2", 2), ("p3", 3)] {
        c.execute(
            "INSERT INTO task_proposals
               (proposal_id,task_id,attempt_no,step_no,capability,target,params,proposer,created_at_ms,status)
             VALUES (?1,'t',?2,1,'filesystem/write-text','out.txt','{}','{}',?3,'pending');",
            rusqlite::params![id, attempt, attempt as i64],
        )
        .expect("a retried step must accept a new proposal");
    }
    assert_eq!(count_identity(&c, "t", 1, 1), 1);
    assert_eq!(count_identity(&c, "t", 1, 2), 1);
    assert_eq!(count_identity(&c, "t", 1, 3), 1);
    cleanup(&p);
}

/// Requirement: the *classified* error, so a caller can tell the two unique keys apart.
///
/// The two cases have to be driven from **different execution identities** on purpose. An
/// insert that violates both unique constraints at once reports only one of them, so a
/// test that tried to provoke both from a single identity would silently stop testing the
/// distinction it claims to test.
#[test]
fn the_two_unique_keys_produce_two_different_refusals() {
    let (p, mut c) = db("classify");
    {
        let mut repo = TaskRepository::new(&mut c);
        repo.insert(&NewTask::new(tid("t"), TaskKind::Query, NOW), NOW)
            .expect("insert");
        repo.insert(&NewTask::new(tid("other"), TaskKind::Query, NOW), NOW)
            .expect("insert");
        repo.insert(&NewTask::new(tid("holder"), TaskKind::Query, NOW), NOW)
            .expect("insert");
        let TargetedClaimOutcome::Claimed(_) = repo
            .claim_specific(&tid("t"), "w1", NOW, LEASE)
            .expect("claim")
        else {
            panic!("claimable")
        };
        repo.propose_action(
            "p1",
            &tid("t"),
            "w1",
            "filesystem/write-text",
            Some("out.txt"),
            "{}",
            "{}",
            None,
            1,
            NOW + 1,
        )
        .expect("first proposal");
        repo.record_approval(&ApprovalRow {
            task_id: tid("t"),
            attempt_no: 1,
            step_no: 1,
            digest_hex: "00".repeat(32),
            capability: "filesystem/write-text".to_owned(),
            target: Some("out.txt".to_owned()),
            params: "{}".to_owned(),
            issued_at_ms: NOW + 2,
            expires_at_ms: NOW + 200_000,
            consumed_at_ms: None,
        })
        .expect("record approval");
        repo.decide_proposal("p1", "approved", NOW + 3)
            .expect("decide");
        // Re-enters `running` under a fresh lease WITHOUT advancing `attempts` or
        // `steps_completed` -- the property that made a second proposal reachable at all.
        repo.begin_execution_spending_approval("p1", "w1", NOW + 4, LEASE)
            .expect("re-enter running");
    }

    // (1) The identity is taken. Reached the way production reached it: a worker whose
    // dispatch failed still held a lease on a task that was `running` again at the same
    // `(step, attempt)`.
    {
        let mut repo = TaskRepository::new(&mut c);
        let second = repo.propose_action(
            "p2",
            &tid("t"),
            "w1",
            "filesystem/write-text",
            Some("out.txt"),
            "{}",
            "{}",
            None,
            1,
            NOW + 5,
        );
        assert!(
            matches!(
                second,
                Err(TaskRepoError::ExecutionIdentityTaken {
                    step_no: 1,
                    attempt_no: 1,
                    ref existing_id,
                    ..
                }) if existing_id == "p1"
            ),
            "a taken identity must be its own refusal, naming the proposal that holds it, \
             got {second:?}"
        );
    }

    // (2) The *identifier* is taken, while the identity is free.
    //
    // Planted on a THIRD task, because `proposal_id` is a global primary key and SQLite
    // reports only one constraint when two are violated. Holding `q1` on the same identity
    // the next call will ask for would violate both at once, and the test would stop
    // testing the distinction it claims to test. A third task is the only way to hold the
    // identifier while leaving the identity free.
    //
    // This is also the shape production produces for real: `proposal_id` is minted as
    // `p-{task_id}-{milliseconds}`, so two proposals minted inside one millisecond collide
    // on the identifier while their identities are perfectly distinct.
    c.execute(
        "INSERT INTO task_proposals
           (proposal_id,task_id,attempt_no,step_no,capability,target,params,proposer,
            created_at_ms,status)
         VALUES ('q1','holder',1,1,'filesystem/write-text','out.txt','{}','{}',1,'pending');",
        [],
    )
    .expect("plant the identifier collision on a free identity");
    {
        let mut repo = TaskRepository::new(&mut c);
        let TargetedClaimOutcome::Claimed(_) = repo
            .claim_specific(&tid("other"), "w2", NOW + 6, LEASE)
            .expect("claim the second task")
        else {
            panic!("claimable")
        };
        let other = repo.propose_action(
            "q1", // deliberately the id now in use, on the other task
            &tid("other"),
            "w2",
            "filesystem/write-text",
            Some("out.txt"),
            "{}",
            "{}",
            None,
            1,
            NOW + 7,
        );
        assert!(
            matches!(other, Err(TaskRepoError::AlreadyExists(ref m)) if m.contains("q1")),
            "an identifier collision must be `AlreadyExists` naming the colliding id, got {other:?}"
        );
    }
    assert_eq!(
        count_identity(&c, "other", 1, 1),
        0,
        "the refused proposal must leave no row behind: a refusal that wrote a proposal \
         would be a worse outcome than either refusal"
    );
    assert_eq!(
        count_identity(&c, "holder", 1, 1),
        1,
        "and the identity that legitimately holds the identifier must be untouched"
    );
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// D. concurrency
// ---------------------------------------------------------------------------

/// Requirement: many workers, one execution identity, simultaneous proposals. Exactly one
/// wins and every loser receives a classified refusal.
///
/// Real threads, real connections to the same **file**, and a barrier so the writes are
/// genuinely concurrent rather than serialised by the scheduler. `authority_transaction`
/// takes the write lock up front, so the losers block and then match zero rows — but the
/// assertion that matters is that they are *refused with a class*, not that they happen to
/// fail.
#[test]
fn concurrent_proposals_for_one_identity_produce_exactly_one_winner() {
    let (p, _c) = db("concurrent");
    const WORKERS: usize = 8;

    {
        let mut c = Connection::open(&p).expect("open");
        let mut repo = TaskRepository::new(&mut c);
        repo.insert(&NewTask::new(tid("t"), TaskKind::Query, NOW), NOW)
            .expect("insert");
        let TargetedClaimOutcome::Claimed(_) = repo
            .claim_specific(&tid("t"), "w1", NOW, LEASE)
            .expect("claim")
        else {
            panic!("claimable")
        };
    }

    let barrier = Arc::new(Barrier::new(WORKERS));
    let handles: Vec<_> = (0..WORKERS)
        .map(|i| {
            let p = p.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut c = Connection::open(&p).expect("open in thread");
                Pragma::critical().apply(&c).expect("pragmas");
                let mut repo = TaskRepository::new(&mut c);
                barrier.wait();
                let id = format!("p-{i}");
                match repo.propose_action(
                    &id,
                    &tid("t"),
                    "w1",
                    "filesystem/write-text",
                    Some("out.txt"),
                    "{}",
                    "{}",
                    None,
                    1,
                    NOW + 10,
                ) {
                    Ok(_) => format!("winner:{id}"),
                    // Two refusals are legitimate here, and which one fires is a
                    // consequence of ordering rather than of the race: the winner has
                    // already moved the task to `waiting-for-user`, so the *state* guard
                    // refuses the losers before the insert is attempted. That is the
                    // stronger refusal -- it holds even for a task with no effect row at
                    // all. The identity constraint is the backstop for the case the state
                    // guard misses (a task re-entered into `running` without advancing
                    // its attempt), which `the_two_unique_keys_produce_two_different_
                    // refusals` drives directly.
                    Err(TaskRepoError::ProposalNotInState { .. })
                    | Err(TaskRepoError::ExecutionIdentityTaken { .. }) => {
                        format!("refused:{id}")
                    }
                    Err(e) => format!("unexpected:{id}:{e}"),
                }
            })
        })
        .collect();
    let outcomes: Vec<String> = handles
        .into_iter()
        .map(|h| h.join().expect("thread"))
        .collect();

    let winners: Vec<&String> = outcomes
        .iter()
        .filter(|o| o.starts_with("winner:"))
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one proposal may occupy the execution identity; got {outcomes:?}"
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| o.starts_with("refused:"))
            .count(),
        WORKERS - 1,
        "every other worker must receive a classified refusal; got {outcomes:?}"
    );
    for o in &outcomes {
        assert!(
            !o.starts_with("unexpected:"),
            "every refusal must be a typed store error, never a raw SQLite failure, got {o}"
        );
    }
    assert_eq!(
        count_identity(&Connection::open(&p).expect("open"), "t", 1, 1),
        1,
        "and exactly one row may exist"
    );
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// E. approval interaction
// ---------------------------------------------------------------------------

/// Requirement: one proposal ↔ one execution identity ↔ one approval.
///
/// With the identity enforced, the scenario the audit found — two proposals on one
/// identity, where the second silently inherited the first's approval — is unrepresentable
/// rather than merely guarded. Both the identical-content and different-content forms are
/// attempted through raw SQL, which is the only way to reach them at all.
#[test]
fn one_identity_cannot_hold_two_proposals_for_an_approval_to_choose_between() {
    let (p, mut c) = db("approval");
    {
        let mut repo = TaskRepository::new(&mut c);
        repo.insert(&NewTask::new(tid("t"), TaskKind::Query, NOW), NOW)
            .expect("insert");
        let TargetedClaimOutcome::Claimed(_) = repo
            .claim_specific(&tid("t"), "w1", NOW, LEASE)
            .expect("claim")
        else {
            panic!("claimable")
        };
        repo.propose_action(
            "p1",
            &tid("t"),
            "w1",
            "filesystem/write-text",
            Some("out.txt"),
            "{}",
            "{}",
            None,
            1,
            NOW + 1,
        )
        .expect("propose");
        repo.record_approval(&ApprovalRow {
            task_id: tid("t"),
            attempt_no: 1,
            step_no: 1,
            digest_hex: "00".repeat(32),
            capability: "filesystem/write-text".to_owned(),
            target: Some("out.txt".to_owned()),
            params: "{}".to_owned(),
            issued_at_ms: NOW + 2,
            expires_at_ms: NOW + 200_000,
            consumed_at_ms: None,
        })
        .expect("record approval");
        repo.decide_proposal("p1", "approved", NOW + 3)
            .expect("decide");
    }

    // A second proposal with the SAME content: would have silently shared p1's approval.
    let same = c.execute(
        "INSERT INTO task_proposals
           (proposal_id,task_id,attempt_no,step_no,capability,target,params,proposer,created_at_ms,status)
         VALUES ('p-same','t',1,1,'filesystem/write-text','out.txt','{}','{}',9,'pending');",
        [],
    );
    assert!(
        same.is_err(),
        "identical content must still be one proposal"
    );

    // A second proposal with DIFFERENT content: would have been a different action for the
    // same approval, which is the escalation shape.
    let different = c.execute(
        "INSERT INTO task_proposals
           (proposal_id,task_id,attempt_no,step_no,capability,target,params,proposer,created_at_ms,status)
         VALUES ('p-diff','t',1,1,'filesystem/write-text','OTHER.txt','{}','{}',9,'pending');",
        [],
    );
    assert!(
        different.is_err(),
        "a different action for the same identity must be unrepresentable"
    );

    assert_eq!(count_identity(&c, "t", 1, 1), 1);
    // The approval is therefore unambiguous: exactly one proposal can be executed under it.
    let row = TaskRepository::new(&mut c)
        .approval_for_attempt(&tid("t"), 1, 1)
        .expect("read approval")
        .expect("an approval exists");
    assert_eq!(row.capability, "filesystem/write-text");
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// A. existing duplicates: classification
// ---------------------------------------------------------------------------

/// Requirement: an equivalent duplicate is reconciled deterministically, and the discarded
/// row is recorded rather than silently deleted.
#[test]
fn equivalent_existing_duplicates_reconcile_to_one_and_are_recorded() {
    let c = schema10();
    seed_proposal(&c, "p-a", "t1", 1, 1, "out.txt", 100, "approved");
    seed_proposal(&c, "p-b", "t1", 1, 1, "out.txt", 200, "approved");
    seed_proposal(&c, "p-c", "t1", 1, 1, "out.txt", 300, "pending");
    assert_eq!(
        count_identity(&c, "t1", 1, 1),
        3,
        "duplicates are reachable"
    );

    MigrationRunner::new(&c).run(true).expect("migrate");

    assert_eq!(
        count_identity(&c, "t1", 1, 1),
        1,
        "one identity, one proposal"
    );
    let survivors: Vec<String> = {
        let mut st = c
            .prepare(
                "SELECT proposal_id FROM task_proposals WHERE task_id='t1' ORDER BY proposal_id;",
            )
            .expect("prepare");
        st.query_map([], |r| r.get(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    };
    assert_eq!(
        survivors,
        vec!["p-a".to_owned()],
        "the survivor is the earliest `created_at_ms`, a total order, so every host agrees"
    );

    let logged: Vec<String> = {
        let mut st = c
            .prepare(
                "SELECT detail FROM task_events
                  WHERE kind = 'proposal-identity-reconciled' ORDER BY seq;",
            )
            .expect("prepare");
        st.query_map([], |r| r.get(0))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    };
    assert_eq!(
        logged.len(),
        2,
        "every discarded row must be recorded, so the deletion is not silent: {logged:?}"
    );
    assert!(
        logged.iter().all(|d| d.contains("p-a")),
        "and each record must name the survivor: {logged:?}"
    );
}

/// Requirement: a *conflicting* duplicate stops the migration, and leaves the data alone.
#[test]
fn conflicting_existing_duplicates_stop_the_migration_without_touching_anything() {
    let c = schema10();
    seed_proposal(&c, "p-a", "t1", 1, 1, "out.txt", 100, "approved");
    seed_proposal(&c, "p-b", "t1", 1, 1, "OTHER.txt", 200, "approved");

    let err = MigrationRunner::new(&c).run(true).expect_err("must refuse");
    let text = err.to_string();
    assert!(
        text.contains("authority decision"),
        "the refusal must say why, and say what an operator has to do: {text}"
    );
    assert_eq!(
        count_identity(&c, "t1", 1, 1),
        2,
        "nothing may be deleted when the data cannot be reconciled"
    );
    let version: i64 = c
        .query_row(
            "SELECT COALESCE(MAX(version),0) FROM schema_meta;",
            [],
            |r| r.get(0),
        )
        .expect("read");
    assert_eq!(version, 13, "the failed migration must have rolled back");
}

/// A duplicate on a *different* identity is not a duplicate, and must not stop anything.
#[test]
fn proposals_on_distinct_identities_are_never_conflicts() {
    let c = schema10();
    seed_proposal(&c, "p-1", "t1", 1, 1, "a.txt", 100, "approved");
    seed_proposal(&c, "p-2", "t1", 1, 2, "b.txt", 100, "pending");
    seed_proposal(&c, "p-3", "t2", 2, 1, "c.txt", 100, "pending");
    MigrationRunner::new(&c)
        .run(true)
        .expect("three distinct identities must migrate");
    let total: i64 = c
        .query_row("SELECT COUNT(*) FROM task_proposals;", [], |r| r.get(0))
        .expect("count");
    assert_eq!(total, 3, "nothing may be discarded here");
}
