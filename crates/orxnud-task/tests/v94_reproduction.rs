//! V-94 Phase 0: reproduction of the five audited findings, against unmodified code.
//!
//! Every assertion here is about **observable durable state** — a row that exists, a
//! blob's length, a timestamp's value, an event that was or was not written — rather
//! than about a specific error variant. That is deliberate: it means each test
//! compiles and *fails* against the defective implementation, and still means the same
//! thing once the fix lands.
//!
//! The file is kept rather than deleted. A defect that has been fixed once is a defect
//! that will be reintroduced: the digest parser, the row-count check, the constraint
//! classification, the timestamp and the consume failure are all places where a later
//! refactor can plausibly "simplify" the safety back out.
//!
//! Nothing here constructs an impossible state. Every scenario is reached through the
//! production API or through a legitimate state transition that invalidates a
//! precondition.

use std::path::{Path, PathBuf};

use orxnud_domain::ids::TaskId;
use orxnud_domain::security_state::{ApprovalLedger, AuditJournal};
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::security_state::{SqliteApprovalLedger, SqliteAuditJournal};
use orxnud_store::task_repo::{ApprovalRow, NewTask, TaskRepoError, TaskRepository};
use orxnud_task::{DurableEngine, EngineLimits};

const NOW: i64 = 1_767_225_600_000;
const LEASE: i64 = 5_000;

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-v94-{}-{tag}", std::process::id()));
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

fn engine(path: &Path) -> DurableEngine {
    let conn = rusqlite::Connection::open(path).expect("open");
    Pragma::critical().apply(&conn).expect("pragmas");
    Pragma::critical().verify(&conn).expect("verify pragmas");
    MigrationRunner::new(&conn).run(true).expect("migrate");
    DurableEngine::new(conn, EngineLimits::documented()).expect("engine")
}

/// A running task with a live lease, which both P1-16 reproductions need.
fn claimed_task(e: &mut DurableEngine, id: &str) -> u32 {
    e.enqueue_new(&NewTask::new(tid(id), TaskKind::Workflow, NOW), NOW)
        .expect("enqueue");
    e.claim_task("w1", NOW)
        .expect("claim")
        .expect("claimed")
        .attempts
}

/// The sequence number of the newest event, so a test can assert only about the
/// events its own operation appended rather than about the task's whole history.
fn highest_seq(e: &DurableEngine) -> i64 {
    e.conn()
        .query_row("SELECT COALESCE(MAX(seq), 0) FROM task_events;", [], |r| {
            r.get(0)
        })
        .expect("max seq")
}

fn count(e: &DurableEngine, sql: &str) -> i64 {
    e.conn().query_row(sql, [], |r| r.get(0)).expect("count")
}

fn approval_row(task: &str, attempt_no: u32, digest_hex: String) -> ApprovalRow {
    ApprovalRow {
        task_id: tid(task),
        step_no: 1,
        attempt_no,
        digest_hex,
        capability: "filesystem/write-text".to_owned(),
        target: Some("out.txt".to_owned()),
        params: r#"{"path":"out.txt","contents":"x"}"#.to_owned(),
        issued_at_ms: NOW,
        expires_at_ms: NOW + 60_000,
        consumed_at_ms: None,
    }
}

/// Creates a proposal through the production path, returning its id.
fn propose(e: &mut DurableEngine, task: &str, id: &str) -> String {
    let mut repo = TaskRepository::new(e.conn_mut());
    repo.propose_action(
        id,
        &tid(task),
        "w1",
        "filesystem/write-text",
        Some("out.txt"),
        r#"{"path":"out.txt","contents":"x"}"#,
        r#"{"kind":"human"}"#,
        None,
        1,
        NOW,
    )
    .expect("propose")
    .proposal_id
}

// ===========================================================================
// P1-15 — a malformed approval digest was accepted as a durable value
// ===========================================================================
//
// `hex_to_bytes` returned `Vec::new()` for non-hex input and silently dropped a
// trailing nibble for odd-length input. `task_approvals.digest` is `BLOB NOT NULL`
// with no length CHECK, so both results were accepted and persisted: an empty blob, or
// — worse — a *different, valid-looking 32-byte digest* built from a truncated string.
// The second case is authority substitution: the stored value no longer matches what
// the caller believes it issued, and nothing says so.

/// Every malformed digest must leave **no row at all**. On the defective code a
/// non-hex digest produced a zero-length BLOB, which `BLOB NOT NULL` accepts.
#[test]
fn p1_15_malformed_digests_leave_no_durable_approval() {
    // 63 hex characters: the defective parser dropped the trailing nibble and stored
    // a plausible 32-byte digest that is not the caller's digest.
    let odd = {
        let s = "ab".repeat(32);
        s[..63].to_owned()
    };
    let cases: [(&str, String); 6] = [
        ("non-hex", "zz".repeat(32)),
        ("odd length", odd),
        ("empty", String::new()),
        ("too short", "ab".repeat(16)),
        ("too long", "ab".repeat(64)),
        ("mixed", format!("{}{}", "ab".repeat(31), "zz")),
    ];

    for (label, digest) in cases {
        let d = dir(&format!("p1-15-{}", label.replace(' ', "-")));
        let mut e = engine(&db_in(&d));
        let attempts = claimed_task(&mut e, "t");
        let mut repo = TaskRepository::new(e.conn_mut());

        let _ = repo.record_approval(&approval_row("t", attempts, digest));

        let rows = count(&e, "SELECT COUNT(*) FROM task_approvals;");
        assert_eq!(
            rows, 0,
            "{label}: a malformed digest was persisted as a durable approval \
             (absent of the expected mutation must never read as success)"
        );

        // And if a row somehow exists, its blob must be exactly 32 bytes -- never a
        // truncated digest that looks valid.
        let stored: Vec<i64> = {
            let mut stmt = e
                .conn()
                .prepare("SELECT length(digest) FROM task_approvals;")
                .expect("prepare");
            let rows = stmt.query_map([], |r| r.get::<_, i64>(0)).expect("query");
            let mut v = Vec::new();
            for row in rows {
                v.push(row.expect("row"));
            }
            v
        };
        for len in stored {
            assert_eq!(
                len, 32,
                "{label}: a {len}-byte digest is not an authority digest"
            );
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// The schema must refuse an arbitrary-length authority blob, so no other write path
/// can produce one either. `spent_approvals` and `audit_log` already carry length
/// CHECKs; `task_approvals.digest` did not.
#[test]
fn p1_15_the_digest_column_itself_refuses_a_wrong_length() {
    let d = dir("p1-15-schema");
    let mut e = engine(&db_in(&d));
    claimed_task(&mut e, "t");

    for (label, blob) in [
        ("31 bytes", vec![7u8; 31]),
        ("33 bytes", vec![7u8; 33]),
        ("0 bytes", Vec::new()),
        ("1 byte", vec![7u8; 1]),
    ] {
        let r = e.conn().execute(
            "INSERT INTO task_approvals
                (task_id, step_no, attempt_no, digest, capability, params,
                 issued_at_ms, expires_at_ms)
             VALUES ('t', 1, 1, ?1, 'c', '{}', 0, 1);",
            rusqlite::params![blob],
        );
        assert!(
            r.is_err(),
            "{label}: the durable layer accepted a digest that is not 32 bytes"
        );
    }
    // The one legitimate length is accepted, or the fix has simply broken approvals.
    e.conn()
        .execute(
            "INSERT INTO task_approvals
                (task_id, step_no, attempt_no, digest, capability, params,
                 issued_at_ms, expires_at_ms)
             VALUES ('t', 1, 1, ?1, 'c', '{}', 0, 1);",
            rusqlite::params![vec![7u8; 32]],
        )
        .expect("a 32-byte digest is the legitimate case");
    let _ = std::fs::remove_dir_all(&d);
}

/// A well-formed digest must keep working and must round-trip unchanged. The point of
/// the fix is not to refuse valid approvals.
#[test]
fn p1_15_a_valid_digest_is_accepted_and_round_trips() {
    let d = dir("p1-15-valid");
    let mut e = engine(&db_in(&d));
    let attempts = claimed_task(&mut e, "t");
    let hex = "ab".repeat(32);
    let mut repo = TaskRepository::new(e.conn_mut());
    repo.record_approval(&approval_row("t", attempts, hex.clone()))
        .expect("a valid digest must be accepted");

    let stored: Vec<u8> = e
        .conn()
        .query_row("SELECT digest FROM task_approvals;", [], |r| r.get(0))
        .expect("read");
    assert_eq!(stored.len(), 32);
    assert_eq!(
        stored
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        hex,
        "the stored digest must be the one that was supplied"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// P1-16 — a zero-row conditional UPDATE reported success
// ===========================================================================

/// `begin_approved_execution` issued `UPDATE ... WHERE id = ? AND state =
/// 'waiting-for-user'`, discarded `rows_affected`, wrote an
/// `approved-execution-begun` event claiming `to_state = running`, committed, and
/// returned `Ok`. Its fence sibling `complete_verified_step` checks exactly this, so
/// the omission is an oversight rather than a decision.
///
/// Reproduced with a `RAISE(IGNORE)` trigger on the conditional UPDATE. That gives a
/// *genuine* zero-row affected count with no SQLite error and no state change -- the
/// exact situation the missing check exists for -- without contriving an impossible
/// row or racing another thread. `RAISE(IGNORE)` is SQLite's own mechanism for
/// declining a row operation, so this is real database behaviour rather than a mock.
///
/// Uses the deprecated lease-without-spending operation on purpose. That is the function
/// whose zero-row result was read as success, and it has no production caller any more, so
/// this reproduction is the only thing left that keeps its check honest.
#[test]
#[allow(deprecated)]
fn p1_16_begin_approved_execution_does_not_report_success_for_a_zero_row_update() {
    let d = dir("p1-16-begin");
    let mut e = engine(&db_in(&d));
    claimed_task(&mut e, "t");
    let proposal = propose(&mut e, "t", "p-zero-row");

    {
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.decide_proposal(&proposal, "approved", NOW)
            .expect("approve");
    }
    // The task is now `waiting-for-user`, which is exactly the state the UPDATE's
    // predicate requires -- so only the row count can reveal the problem.
    assert_eq!(
        e.task(&tid("t")).expect("read").expect("present").state,
        TaskState::WaitingForUser
    );
    let before_seq = highest_seq(&e);
    e.conn()
        .execute_batch(
            "CREATE TRIGGER decline_the_begin BEFORE UPDATE ON tasks
               WHEN OLD.state = 'waiting-for-user'
             BEGIN SELECT RAISE(IGNORE); END;",
        )
        .expect("trigger");

    let mut repo = TaskRepository::new(e.conn_mut());
    let result = repo.begin_approved_execution(&proposal, "w1", NOW, LEASE);

    assert!(
        result.is_err(),
        "a zero-row mutation reported success: the caller was told it holds a lease it \
         does not hold. Got {result:?}"
    );
    let err = result.expect_err("refused");
    assert!(
        matches!(err, TaskRepoError::ProposalNotInState { .. }),
        "expected a typed state refusal naming the actual state, got {err:?}"
    );

    // Events written *by this operation* -- the task's earlier history legitimately
    // contains `claimed -> running`, which is a different transition entirely.
    let events: Vec<_> = repo
        .all_events()
        .expect("events")
        .into_iter()
        .filter(|ev| ev.seq > before_seq)
        .collect();
    for ev in &events {
        assert_ne!(
            ev.kind, "approved-execution-begun",
            "a zero-row mutation emitted a success event: {ev:?}"
        );
        assert!(
            ev.to_state != Some(TaskState::Running),
            "a zero-row mutation claimed the task was running: {ev:?}"
        );
    }
    // The repository borrow must end before the engine is used again.
    let row = e.task(&tid("t")).expect("read").expect("present");
    assert_eq!(row.state, TaskState::WaitingForUser);
    assert!(
        row.lease_holder.is_none(),
        "no lease may have been granted for a transition that did not happen: {row:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The same shape in `propose_action`. A proposal row plus a `running ->
/// waiting-for-user` event could commit while the task stayed `running` **and kept
/// its lease** -- the exact interleaving the adjacent comment claims is impossible.
#[test]
fn p1_16_propose_action_does_not_report_success_for_a_zero_row_update() {
    let d = dir("p1-16-propose");
    let mut e = engine(&db_in(&d));
    claimed_task(&mut e, "t");
    let before_seq = highest_seq(&e);
    e.conn()
        .execute_batch(
            "CREATE TRIGGER decline_the_propose BEFORE UPDATE ON tasks
               WHEN OLD.state = 'running'
             BEGIN SELECT RAISE(IGNORE); END;",
        )
        .expect("trigger");

    let mut repo = TaskRepository::new(e.conn_mut());
    let result = repo.propose_action(
        "p-ghost",
        &tid("t"),
        "w1",
        "filesystem/write-text",
        Some("out.txt"),
        r#"{"path":"out.txt","contents":"x"}"#,
        r#"{"kind":"human"}"#,
        None,
        1,
        NOW,
    );
    assert!(
        result.is_err(),
        "a zero-row mutation reported success: the caller was told a proposal was \
         accepted when the task never became waitable. Got {result:?}"
    );
    assert!(
        matches!(result, Err(TaskRepoError::ProposalNotInState { .. })),
        "expected a typed state refusal, got {result:?}"
    );

    let events: Vec<_> = repo
        .all_events()
        .expect("events")
        .into_iter()
        .filter(|ev| ev.seq > before_seq)
        .collect();
    for ev in &events {
        assert_ne!(
            ev.kind, "action-proposed",
            "success event on a zero row: {ev:?}"
        );
        assert!(
            ev.to_state != Some(TaskState::WaitingForUser),
            "a zero-row mutation claimed the task was waiting: {ev:?}"
        );
    }
    assert_eq!(
        count(&e, "SELECT COUNT(*) FROM task_proposals;"),
        0,
        "the whole operation is one transaction: a zero-row state change must roll the \
         proposal row back with it, or a durable proposal exists for a task that never \
         became waitable"
    );
    let row = e.task(&tid("t")).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::Running,
        "the state must be exactly as it was"
    );
    assert!(
        row.lease_holder.is_some(),
        "the lease must not have been released for a transition that did not happen"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// P1-17 — INSERT OR IGNORE reported a rejected insert as a duplicate
// ===========================================================================
//
// SQLite's `OR IGNORE` covers NOT NULL, CHECK, UNIQUE and PRIMARY KEY. The zero-row
// result was read as "this key already exists", so an *invalid* insert and a *storage*
// failure were indistinguishable from an expected duplicate.

/// `reserve_effect`'s documented contract is "`false` is the caller's signal not to
/// dispatch". If an invalid insert also returns `false`, a rejected reservation reads
/// as a duplicate and the caller either skips real work or moves on believing the
/// effect was handled.
#[test]
fn p1_17_reserve_effect_distinguishes_a_duplicate_from_an_invalid_insert() {
    let d = dir("p1-17-effect");
    let mut e = engine(&db_in(&d));
    claimed_task(&mut e, "t");

    assert!(
        e.reserve_effect("k", &tid("t"), 1, 1, "step", false, NOW)
            .expect("first"),
        "the first reservation must succeed"
    );
    assert!(
        !e.reserve_effect("k", &tid("t"), 1, 1, "step", false, NOW)
            .expect("duplicate"),
        "a genuine duplicate is `false`, and that is the documented meaning"
    );

    // An effect for a task that does not exist: an invalid insert, not a duplicate.
    let ghost = e.reserve_effect("other", &tid("ghost"), 1, 1, "step", false, NOW);
    assert!(
        ghost.is_err(),
        "an effect for a non-existent task is invalid, not a duplicate: {ghost:?}"
    );
    assert_eq!(
        count(&e, "SELECT COUNT(*) FROM task_effects;"),
        1,
        "the invalid reservation must not leave a row"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// `record_approval` has the same shape, and `AlreadyExists` is a *caller* error the
/// daemon maps to a specific wire code. Reporting a CHECK failure as "already exists"
/// sends the reader to fix the wrong thing.
#[test]
fn p1_17_record_approval_distinguishes_a_duplicate_from_an_invalid_insert() {
    let d = dir("p1-17-approval");
    let mut e = engine(&db_in(&d));
    let attempts = claimed_task(&mut e, "t");

    e.record_approval(&approval_row("t", attempts, "ab".repeat(32)))
        .expect("first approval");

    let dup = e.record_approval(&approval_row("t", attempts, "ab".repeat(32)));
    assert!(
        matches!(dup, Err(orxnud_task::EngineError { .. })),
        "the duplicate must be refused, got {dup:?}"
    );

    // An invalid one: `step_no = 0` violates the table's CHECK.
    let mut bad = approval_row("t", attempts, "cd".repeat(32));
    bad.step_no = 0;
    let invalid = e.record_approval(&bad);
    assert!(
        invalid.is_err(),
        "a CHECK violation must be refused: {invalid:?}"
    );
    assert_eq!(
        count(&e, "SELECT COUNT(*) FROM task_approvals;"),
        1,
        "the invalid insert must not have been counted as a stored approval"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// A schedule fire that was *rejected* must not be reported as "already recorded", or
/// the scheduler treats a lost occurrence as a dedup and advances past it.
#[test]
fn p1_17_a_rejected_fire_is_not_reported_as_an_already_present_fire() {
    let d = dir("p1-17-fire");
    let path = db_in(&d);
    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        Pragma::critical().apply(&conn).expect("pragmas");
        MigrationRunner::new(&conn).run(true).expect("migrate");
    }
    let mut e = engine(&path);
    {
        let mut repo = orxnud_store::schedule_repo::ScheduleRepository::new(e.conn_mut());
        repo.insert(
            &orxnud_domain::task_state::ScheduleSpec {
                id: orxnud_domain::ids::ScheduleId::new("s1"),
                cron: "* * * * *".to_owned(),
                timezone: "UTC".to_owned(),
                misfire: orxnud_domain::task_state::MisfirePolicy::FireOnce,
                catch_up_cap: 10,
                enabled: true,
                authorised_by: orxnud_domain::ids::UserId::new("u1"),
            },
            NOW,
        )
        .expect("schedule");

        let fire = orxnud_domain::task_state::ScheduleFire {
            schedule: orxnud_domain::ids::ScheduleId::new("s1"),
            fire_time_ms: NOW,
            catch_up: false,
        };
        assert_eq!(
            repo.insert_fire(&fire, NOW).expect("first fire"),
            orxnud_store::schedule_repo::FireInsert::Inserted,
            "the first fire must be inserted"
        );
        assert_eq!(
            repo.insert_fire(&fire, NOW).expect("duplicate"),
            orxnud_store::schedule_repo::FireInsert::AlreadyPresent,
            "a genuine duplicate is the documented answer"
        );

        // A fire for a schedule that does not exist. `OR IGNORE` does not swallow FK
        // violations, but the sibling NOT NULL and CHECK paths are, and none of them
        // may read as a duplicate.
        let ghost = orxnud_domain::task_state::ScheduleFire {
            schedule: orxnud_domain::ids::ScheduleId::new("no-such-schedule"),
            fire_time_ms: NOW + 1,
            catch_up: false,
        };
        let res = repo.insert_fire(&ghost, NOW);
        assert!(
            res.is_err(),
            "a fire for a non-existent schedule must fail, not read as a duplicate: {res:?}"
        );
        assert_eq!(
            repo.fire_count(&orxnud_domain::ids::ScheduleId::new("s1"))
                .expect("count"),
            1,
            "a rejected fire must not be recorded"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// P1-18 — the durable ledger wrote consumed_at_ms = 0
// ===========================================================================

/// The ledger records *the time it was given*, and a refused replay does not overwrite
/// the winner's.
///
/// V-94. `spent_approvals.consumed_at_ms` was hardcoded to `0` — the epoch — so the
/// ledger could answer *whether* a digest had been spent and never *when*. A sentinel is
/// not a weaker timestamp, it is a missing one: zero is indistinguishable from "never
/// recorded".
#[test]
fn p1_18_the_spent_approval_ledger_records_the_time_it_was_given() {
    let d = dir("p1-18");
    let path = db_in(&d);
    let digest = orxnud_domain::ApprovalDigest::from_bytes([9u8; 32]);
    let consumed_at = NOW;

    {
        let mut ledger = SqliteApprovalLedger::open(&path).expect("ledger");
        ledger
            .consume_at(&digest, consumed_at)
            .expect("first consume must succeed");
    }

    // Read through an independent connection, so the assertion depends on the durable
    // row rather than on any accessor.
    let reader = rusqlite::Connection::open(&path).expect("open for reading");
    let stored: i64 = reader
        .query_row(
            "SELECT consumed_at_ms FROM spent_approvals WHERE digest = ?1;",
            rusqlite::params![digest.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .expect("read the stored timestamp");
    assert_eq!(
        stored, consumed_at,
        "the ledger must record when the approval was spent, not a sentinel"
    );
    assert_ne!(
        stored, 0,
        "a zero timestamp is indistinguishable from 'never recorded'"
    );

    // A refused replay must not overwrite the winner's timestamp: the column records
    // when the approval was *first* spent, which is the fact an incident review needs.
    {
        let mut ledger = SqliteApprovalLedger::open(&path).expect("ledger");
        let replay = ledger
            .consume_at(&digest, NOW + 60_000)
            .expect_err("a replay must be refused");
        assert!(matches!(
            replay,
            orxnud_domain::security_state::LedgerError::AlreadyConsumed
        ));
    }
    let after: i64 = reader
        .query_row(
            "SELECT consumed_at_ms FROM spent_approvals WHERE digest = ?1;",
            rusqlite::params![digest.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .expect("read");
    assert_eq!(
        after, consumed_at,
        "a refused replay must not overwrite the winner's timestamp"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// Two concurrent consumes must yield exactly one winner and one refusal, on a real
/// file with real contention -- the property the single-use guarantee rests on, and the
/// property that must survive adding a timestamp to the same statement.
#[test]
fn p1_18_two_concurrent_consumes_yield_exactly_one_winner() {
    let d = dir("p1-18-race");
    let path = db_in(&d);
    let digest = orxnud_domain::ApprovalDigest::from_bytes([4u8; 32]);

    let handles: Vec<_> = (0..4i64)
        .map(|t| {
            let p = path.clone();
            std::thread::spawn(move || {
                let mut l = SqliteApprovalLedger::open(&p).expect("ledger");
                l.consume_at(&digest, NOW + t).is_ok()
            })
        })
        .collect();
    let outcomes: Vec<bool> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();
    assert_eq!(
        outcomes.iter().filter(|w| **w).count(),
        1,
        "single-use must have exactly one winner, got {outcomes:?}"
    );

    let reader = rusqlite::Connection::open(&path).expect("open for reading");
    let n: i64 = reader
        .query_row("SELECT COUNT(*) FROM spent_approvals;", [], |r| r.get(0))
        .expect("count");
    assert_eq!(n, 1, "one winner, one row");
    let _ = std::fs::remove_dir_all(&d);
}

/// The audit ledger shares the same file and must be untouched by the change.
#[test]
fn p1_18_the_audit_journal_still_works_alongside_the_approval_ledger() {
    let d = dir("p1-18-audit");
    let path = db_in(&d);
    {
        let mut ledger = SqliteApprovalLedger::open(&path).expect("ledger");
        ledger
            .consume_at(&orxnud_domain::ApprovalDigest::from_bytes([1u8; 32]), NOW)
            .expect("consume");
    }
    // Opened on the same file the approval ledger migrated: the two must coexist.
    let journal = SqliteAuditJournal::open(&path).expect("journal");
    assert!(
        journal
            .is_empty()
            .expect("the audit journal is still readable"),
        "a fresh audit journal is empty; this asserts only that opening it alongside \
         the approval ledger works and left no stray records"
    );
    assert_eq!(
        journal.len().expect("len"),
        0,
        "the approval ledger must not write to the audit journal"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// The negative space: absence of the expected durable mutation, never success
// ===========================================================================
//
// Phase 11's question, stated as tests. Each one is a place the system is tempted to
// conclude "nothing is wrong" from the absence of a row, an event, or a write.

// A proposal for a task that does not exist: not a proposal.
#[test]
fn absence_of_a_task_is_a_refusal_not_an_empty_proposal() {
    let d = dir("neg-no-task");
    let mut e = engine(&db_in(&d));
    let mut repo = TaskRepository::new(e.conn_mut());
    let err = repo.propose_action(
        "p",
        &tid("ghost"),
        "w1",
        "filesystem/write-text",
        Some("out.txt"),
        "{}",
        r#"{"kind":"human"}"#,
        None,
        1,
        NOW,
    );
    assert!(
        err.is_err(),
        "a proposal for a missing task must be refused: {err:?}"
    );
    assert_eq!(count(&e, "SELECT COUNT(*) FROM task_proposals;"), 0);
    let _ = std::fs::remove_dir_all(&d);
}

// Beginning an execution for a proposal that was never approved.
#[test]
fn absence_of_an_approval_is_a_refusal_not_an_execution() {
    let d = dir("neg-no-approval");
    let mut e = engine(&db_in(&d));
    claimed_task(&mut e, "t");
    let proposal = propose(&mut e, "t", "p-unapproved");
    let mut repo = TaskRepository::new(e.conn_mut());
    // Deliberately not approved, and deliberately no approval row.
    let err = repo
        .begin_execution_spending_approval(&proposal, "w1", NOW, LEASE)
        .expect_err("an unapproved proposal must not begin an execution");
    assert!(
        matches!(err, TaskRepoError::ProposalNotInState { .. }),
        "{err:?}"
    );

    let row = e.task(&tid("t")).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::WaitingForUser,
        "the task must be untouched"
    );
    assert!(row.lease_holder.is_none(), "no lease may exist");
    let _ = std::fs::remove_dir_all(&d);
}

// An approval already spent for this attempt: not a second execution.
#[test]
fn an_already_spent_approval_is_a_refusal_not_a_second_execution() {
    let d = dir("neg-already-spent");
    let mut e = engine(&db_in(&d));
    let attempts = claimed_task(&mut e, "t");
    let proposal = propose(&mut e, "t", "p-once");
    {
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.record_approval(&approval_row("t", attempts, "ab".repeat(32)))
            .expect("approval");
        repo.decide_proposal(&proposal, "approved", NOW)
            .expect("approve");
        repo.begin_execution_spending_approval(&proposal, "w1", NOW, LEASE)
            .expect("first execution");
        assert!(
            repo.begin_execution_spending_approval(&proposal, "w2", NOW, LEASE)
                .is_err(),
            "a spent approval must not authorise a second execution"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

// A duplicate reservation is a duplicate; an invalid one is an error. Both are proven
// above; this pins that the *pair* of answers is what callers get, so a later change
// that collapses them has one place to fail.
#[test]
fn the_reservation_outcomes_are_exactly_two_and_neither_is_an_error() {
    let d = dir("neg-two-outcomes");
    let mut e = engine(&db_in(&d));
    claimed_task(&mut e, "t");

    // `DurableEngine::reserve_effect` collapses the row to a bool; this asserts the two
    // answers it is allowed to give are "reserved" and "already reserved", and that the
    // second is not an error.
    let first = e.reserve_effect("k", &tid("t"), 1, 1, "step", false, NOW);
    let second = e.reserve_effect("k", &tid("t"), 1, 1, "step", false, NOW);
    assert!(first.expect("the first reservation is not an error"));
    assert!(
        !second.expect("a duplicate is an answer, not an error"),
        "the second reservation is a duplicate"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// A zero-row update on the *combined* operation, which is the production path now.
#[test]
fn the_production_operation_refuses_a_zero_row_state_change_too() {
    let d = dir("neg-combined-zero-row");
    let mut e = engine(&db_in(&d));
    let attempts = claimed_task(&mut e, "t");
    let proposal = propose(&mut e, "t", "p-zero");
    {
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.record_approval(&approval_row("t", attempts, "ab".repeat(32)))
            .expect("approval");
        repo.decide_proposal(&proposal, "approved", NOW)
            .expect("approve");
    }
    e.conn()
        .execute_batch(
            "CREATE TRIGGER decline_the_combined BEFORE UPDATE OF state ON tasks
               WHEN OLD.state = 'waiting-for-user'
             BEGIN SELECT RAISE(IGNORE); END;",
        )
        .expect("trigger");

    let mut repo = TaskRepository::new(e.conn_mut());
    let err = repo
        .begin_execution_spending_approval(&proposal, "w1", NOW, LEASE)
        .expect_err("a zero-row state change must not report success");
    assert!(
        matches!(err, TaskRepoError::ProposalNotInState { .. }),
        "{err:?}"
    );

    // And because it is one transaction, the approval spend rolled back with it.
    let row = repo
        .approval_for_attempt(&tid("t"), 1, attempts)
        .expect("read")
        .expect("present");
    assert!(
        row.consumed_at_ms.is_none(),
        "a refused execution must not leave the approval spent: {row:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// A storage failure reading the ledger is an error, not "not consumed".
#[test]
fn an_unreadable_approval_row_is_an_error_not_an_absent_approval() {
    let d = dir("neg-unreadable");
    let mut e = engine(&db_in(&d));
    let attempts = claimed_task(&mut e, "t");
    {
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.record_approval(&approval_row("t", attempts, "ab".repeat(32)))
            .expect("approval");
    }
    // Drop the table out from under the reader.
    e.conn()
        .execute_batch("ALTER TABLE task_approvals RENAME TO task_approvals_gone;")
        .expect("rename");
    let repo = TaskRepository::new_readonly(e.conn());
    let res = repo.approval_for_attempt(&tid("t"), 1, attempts);
    assert!(
        res.is_err(),
        "a missing table is a storage failure, not an absent approval: {res:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ===========================================================================
// Phase 10: an event may never claim a transition the row did not make
// ===========================================================================
//
// The property is stated as a correspondence rather than as a list of cases, because
// the list is what drifts: a future event kind would not be covered by an enumeration,
// but it is covered by "for every event of this kind, the durable consequence holds".

/// Every `approved-execution-begun` event corresponds to a lease and a spent approval.
#[test]
fn every_execution_begun_event_has_the_durable_state_it_claims() {
    let d = dir("evt-begun");
    let mut e = engine(&db_in(&d));
    let attempts = claimed_task(&mut e, "t");
    let proposal = propose(&mut e, "t", "p-evt");
    {
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.record_approval(&approval_row("t", attempts, "ab".repeat(32)))
            .expect("approval");
        repo.decide_proposal(&proposal, "approved", NOW)
            .expect("approve");
        repo.begin_execution_spending_approval(&proposal, "w1", NOW, LEASE)
            .expect("begin");
    }

    let repo = TaskRepository::new_readonly(e.conn());
    let begins: Vec<_> = repo
        .all_events()
        .expect("events")
        .into_iter()
        .filter(|ev| ev.kind == "approved-execution-begun")
        .collect();
    assert_eq!(begins.len(), 1, "exactly one such event: {begins:?}");

    // The event's own claims.
    assert_eq!(begins[0].from_state, Some(TaskState::WaitingForUser));
    assert_eq!(begins[0].to_state, Some(TaskState::Running));
    assert_eq!(begins[0].worker.as_deref(), Some("w1"));

    // And the durable consequences it asserts.
    let row = repo.get(&tid("t")).expect("read").expect("present");
    assert_eq!(row.state, TaskState::Running);
    assert_eq!(row.lease_holder.as_deref(), Some("w1"));
    assert!(row.lease_expires_at_ms.is_some());
    let approval = repo
        .approval_for_attempt(&tid("t"), 1, attempts)
        .expect("read")
        .expect("present");
    assert!(
        approval.consumed_at_ms.is_some(),
        "the event claims an execution began, so the approval must be spent: {approval:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// Every `action-proposed` event corresponds to a task that is waiting, unleased.
#[test]
fn every_action_proposed_event_has_the_durable_state_it_claims() {
    let d = dir("evt-proposed");
    let mut e = engine(&db_in(&d));
    claimed_task(&mut e, "t");
    propose(&mut e, "t", "p-evt2");

    let repo = TaskRepository::new_readonly(e.conn());
    let proposed: Vec<_> = repo
        .all_events()
        .expect("events")
        .into_iter()
        .filter(|ev| ev.kind == "action-proposed")
        .collect();
    assert_eq!(proposed.len(), 1, "{proposed:?}");
    assert_eq!(proposed[0].to_state, Some(TaskState::WaitingForUser));

    let row = repo.get(&tid("t")).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::WaitingForUser,
        "the event claims the task is waiting, so it must be: {row:?}"
    );
    assert!(
        row.lease_holder.is_none() && row.lease_expires_at_ms.is_none(),
        "the event claims the lease was released with the transition: {row:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}
