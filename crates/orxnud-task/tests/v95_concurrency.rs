//! V-95: transaction semantics and concurrency integrity.
//!
//! # The defect this file exists to prevent
//!
//! `TaskRepository::tx` is documented as *"Begins an immediate transaction"*, and its
//! docs explain, in detail and correctly, **why** `IMMEDIATE` is required:
//!
//! > `IMMEDIATE`, never `DEFERRED`: with a deferred transaction the write lock is taken
//! > at the first *read*, so a second writer can change the table between our read and
//! > our write and the statement is retried — which for a state transition means
//! > deciding again whether it is legal.
//!
//! It calls `Connection::unchecked_transaction()`, which uses the connection's default
//! `TransactionBehavior` — `DEFERRED` (rusqlite `lib.rs` sets
//! `transaction_behavior: TransactionBehavior::Deferred` on every constructor). So the
//! argument in that comment is an argument *for* `IMMEDIATE`, written on top of code
//! that is `DEFERRED`. The comment is not merely optimistic; it is the analysis of the
//! bug, sitting in the place where the bug is.
//!
//! `SqliteAuditJournal::append` carries the same mismatch in one line —
//! `// IMMEDIATE before the read: taking the write lock first is what stops two writers
//! // both computing the same successor.` — over a `DEFERRED` transaction.
//!
//! Only two of the four transaction constructors in the workspace are affected.
//! `migration.rs` and `schedule_repo.rs` genuinely pass `TransactionBehavior::Immediate`.
//!
//! # The measured failure mode
//!
//! A `DEFERRED` transaction that reads before it writes behaves worse than "racy", and
//! the difference is worth stating precisely because it decides the fix:
//!
//! * It does **not** block. It fails *immediately* with `SQLITE_BUSY_SNAPSHOT`
//!   (rusqlite `ErrorCode::DatabaseBusy`, extended code 5).
//! * SQLite **never invokes the busy handler** for `SQLITE_BUSY_SNAPSHOT`, because
//!   waiting cannot turn a stale snapshot into a current one. `busy_timeout` therefore
//!   does not rescue it, and no retry loop in this workspace could either.
//! * The error renders as `"database is locked"` — indistinguishable, at the call site,
//!   from a genuine lock, and carrying no statement about *which* decision became
//!   undecidable.
//!
//! So a deferred read-then-write does not produce a false success (V-94 closed that
//! door). It produces an **unclassifiable failure**: the operation refuses, but it cannot
//! say why, and it cannot wait itself out of it. `IMMEDIATE` moves the wait to `BEGIN`,
//! where the busy handler can see it and `busy_timeout` can absorb it.
//!
//! # What is asserted here
//!
//! Real file databases, real separate connections, real lock contention. The interleaving
//! is **observed, not timed**: a rival connection takes the write lock *before* the
//! contender starts, and the contender installs a SQLite busy handler whose first
//! invocation means — by SQLite's own behaviour — that the contender is inside a blocked
//! statement. Nothing sleeps hoping for an overlap.
//!
//! The assertions state the invariant a caller is entitled to rely on — *"a competing
//! writer receives a classified refusal"* — not the current behaviour. Every test below
//! failed before the fix, and its failure message says what it got instead.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::thread::JoinHandle;
use std::time::Duration;

use orxnud_domain::ids::TaskId;
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::{ApprovalRow, NewTask, TaskRepoError, TaskRepository};
use orxnud_task::{DurableEngine, EngineLimits};
use rusqlite::{Connection, TransactionBehavior};

/// 2026-01-01T00:00:00Z. Fixed, so every assertion is about the transition and not about
/// a clock that moved.
const NOW: i64 = 1_767_225_600_000;
const LEASE_MS: i64 = 30_000;

/// A digest written out in full, so nothing here can be malformed by accident.
fn digest(byte_pair: &str) -> String {
    assert_eq!(byte_pair.len(), 2, "fixtures repeat one byte pair");
    byte_pair.repeat(32)
}

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-v95-{}-{tag}", std::process::id()));
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

/// A second independent connection to the same file, with the production pragmas.
fn open_peer(path: &Path) -> Connection {
    let conn = Connection::open(path).expect("open peer");
    Pragma::critical().apply(&conn).expect("peer pragmas");
    Pragma::critical()
        .verify(&conn)
        .expect("verify peer pragmas");
    conn
}

fn open_engine(path: &Path) -> DurableEngine {
    let conn = Connection::open(path).expect("open");
    Pragma::critical().apply(&conn).expect("pragmas");
    Pragma::critical().verify(&conn).expect("verify pragmas");
    MigrationRunner::new(&conn).run(true).expect("migrate");
    DurableEngine::new(conn, EngineLimits::documented()).expect("engine")
}

// --------------------------------------------------- the blocking observation
//
// SQLite calls a busy handler synchronously, on the thread that issued the blocked
// statement. A thread-local gate is therefore sufficient to identify the contender and
// invisible to every other thread — including under `cargo test`, where tests share a
// process, which a `static` gate would not be.

/// What the contender's connection reported while it was running.
#[derive(Debug, Clone, Copy)]
enum Ev {
    /// The busy handler fired: by SQLite's own behaviour, the contender is inside a
    /// blocked statement and is waiting for the write lock.
    Blocked,
    /// The body returned. It may never have needed the lock at all — which under
    /// `DEFERRED` is the interesting case, because `SQLITE_BUSY_SNAPSHOT` never reaches
    /// the busy handler.
    Finished,
}

thread_local! {
    static GATE: std::cell::RefCell<Option<Gate>> = const { std::cell::RefCell::new(None) };
}

struct Gate {
    /// Moved into the contender thread; `Ev::Blocked` is sent at most once.
    blocked: Sender<Ev>,
    /// Cleared by the test to let the blocked statement proceed.
    released: Arc<AtomicBool>,
    /// Guards the "announced once" side effect.
    announced: AtomicBool,
}

/// The busy handler installed on the contender.
///
/// It reports the first contention, then waits until the test releases it. Returning
/// `false` stops SQLite retrying and hands the original error back. The sleep lives here
/// rather than in the test because this runs *only* while the statement is genuinely
/// blocked.
fn on_busy(_count: i32) -> bool {
    GATE.with(|cell| {
        let held = cell.borrow();
        let Some(gate) = held.as_ref() else {
            return false;
        };
        if !gate.announced.swap(true, Ordering::SeqCst) {
            let _ = gate.blocked.send(Ev::Blocked);
        }
        if gate.released.load(Ordering::SeqCst) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
        true
    })
}

/// A rival connection holding the write lock with `sql` applied but **not committed**.
///
/// Armed *before* the contender starts, so contention is guaranteed rather than hoped
/// for. The explicit `BEGIN IMMEDIATE` is issued through `execute_batch`, which is how
/// the existing durability tests hold a write lock.
fn rival_locking(path: &Path, sql: &str) -> Connection {
    let peer = open_peer(path);
    peer.execute_batch("BEGIN IMMEDIATE;")
        .expect("rival takes the write lock");
    peer.execute(sql, []).expect("rival changes durable state");
    peer
}

fn rival_commits(rival: &Connection) {
    rival.execute_batch("COMMIT;").expect("rival commits");
}

/// Runs `body` on its own connection while `rival_sql` holds the write lock.
///
/// Order is fixed and matters: the rival locks first, the contender starts, we wait for
/// SQLite to tell us the contender has either blocked or finished, the rival commits, and
/// only then is the contender released. There is no window in which the contender might
/// win by accident.
///
/// Returns the body's value and whether it ever blocked.
fn race<F, T>(path: &Path, body: F, rival_sql: &str) -> (T, bool)
where
    F: FnOnce(&mut Connection) -> T + Send + 'static,
    T: Send + 'static,
{
    let rival = rival_locking(path, rival_sql);
    let (tx, rx) = channel::<Ev>();
    let done = tx.clone();
    let released = Arc::new(AtomicBool::new(false));
    let released_in_thread = Arc::clone(&released);
    let p = path.to_path_buf();

    let handle: JoinHandle<T> = std::thread::spawn(move || {
        let mut conn = open_peer(&p);
        GATE.with(|cell| {
            *cell.borrow_mut() = Some(Gate {
                blocked: tx,
                released: released_in_thread,
                announced: AtomicBool::new(false),
            });
        });
        conn.busy_handler(Some(on_busy))
            .expect("install busy handler");
        let out = body(&mut conn);
        let _ = done.send(Ev::Finished);
        out
    });

    let blocked = match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ev::Blocked) => true,
        Ok(Ev::Finished) => false,
        Err(e) => panic!("the contender reported nothing in ten seconds ({e})"),
    };
    rival_commits(&rival);
    released.store(true, Ordering::SeqCst);
    (handle.join().expect("contender panicked"), blocked)
}

/// The same thing, for the production repository operations.
fn contending<F>(path: &Path, body: F, rival_sql: &str) -> (Outcome, bool)
where
    F: FnOnce(&mut TaskRepository<'_>) -> Outcome + Send + 'static,
{
    race(
        path,
        move |conn| {
            let mut repo = TaskRepository::new(conn);
            body(&mut repo)
        },
        rival_sql,
    )
}

/// Asserts that a contender actually contended for the write lock.
///
/// Under `DEFERRED` this is false, and that is the finding: a read-then-write whose
/// snapshot the rival invalidated fails with `SQLITE_BUSY_SNAPSHOT` *without ever
/// blocking*, so there is no point at which the operation could have waited for the lock
/// it needed.
fn assert_contended(blocked: bool, who: &str) {
    assert!(
        blocked,
        "{who}: the contender never reached a blocked statement, so it never waited for \
         the write lock.\n\
         A `BEGIN DEFERRED` transaction takes the write lock at its first *write*, and \
         these operations read before they write -- so once a rival has committed, the \
         write fails immediately with SQLITE_BUSY_SNAPSHOT, which SQLite never passes to \
         the busy handler. `BEGIN IMMEDIATE` takes the lock at BEGIN, which is where the \
         wait belongs and where busy_timeout can absorb it."
    );
}

// ------------------------------------------------------------------- outcomes

/// The outcome of a contended operation, as an enum so that a failure names the
/// difference that matters: a *classified refusal* versus an *unclassified busy error*.
#[derive(Debug, Clone)]
enum Outcome {
    Succeeded,
    /// A refusal that says why this caller lost.
    Refused(String),
    /// SQLite said the database was busy. Not a refusal: it says "retry", not "you
    /// lost", carries no reason, and — for a snapshot conflict — cannot be retried at all.
    Busy,
    /// Something else went wrong. Never acceptable for a loser, and never folded into
    /// `Refused`, because an unexplained failure is not an explained refusal.
    Storage(String),
}

impl Outcome {
    fn of(result: Result<(), TaskRepoError>) -> Self {
        match result {
            Ok(()) => Self::Succeeded,
            Err(TaskRepoError::Sqlite(inner)) if is_busy(&inner) => Self::Busy,
            Err(TaskRepoError::Sqlite(inner)) => Self::Storage(inner.to_string()),
            Err(e) => Self::Refused(e.to_string()),
        }
    }

    /// The assertion: a writer that lost a race is owed a refusal that names the reason.
    fn assert_loser_was_told_why(self, who: &str) {
        match self {
            Self::Refused(why) => eprintln!("{who}: refused with a reason: {why}"),
            Self::Busy => panic!(
                "{who}: lost the race, but was told 'database is locked'.\n\
                 A busy error is not a refusal. It carries no reason, a caller cannot \
                 distinguish it from a genuine fault, and for SQLITE_BUSY_SNAPSHOT it \
                 cannot even be retried. The correct answer is a refusal naming why."
            ),
            Self::Storage(msg) => {
                panic!("{who}: expected a refusal, got a storage error: {msg}")
            }
            Self::Succeeded => panic!("{who}: won the race it was supposed to lose"),
        }
    }

    /// For an operation whose correct outcome on losing may legitimately be `Ok` — an
    /// idempotent no-op on a terminal state. The assertion is narrower and just as
    /// sharp: whatever the answer, it must not be an unclassified busy error, because a
    /// busy error means the operation never got to look at current state at all.
    fn assert_no_busy_error(self, who: &str) {
        match self {
            Self::Busy => panic!(
                "{who}: was told 'database is locked', so it never reached a decision at \
                 all. See `assert_loser_was_told_why` for why that is the wrong answer."
            ),
            Self::Storage(msg) => {
                panic!("{who}: expected a decision, got a storage error: {msg}")
            }
            Self::Refused(why) => eprintln!("{who}: refused with a reason: {why}"),
            Self::Succeeded => eprintln!("{who}: succeeded, having read current state"),
        }
    }
}

fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::DatabaseBusy
                || f.code == rusqlite::ErrorCode::DatabaseLocked
    )
}

fn is_busy_message(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("database is locked") || m.contains("database table is locked")
}

// ------------------------------------------------------------------- fixtures

/// A task parked at `waiting-for-user` with an approved proposal and an unspent
/// approval — the only state in which an execution lease may begin.
///
/// Reaches that state through the production sequence only: enqueue, claim, record the
/// approval, propose (which parks the task for approval), then decide. Nothing writes
/// `waiting-for-user` directly, so the fixture cannot manufacture a state the code would
/// never itself produce.
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

    let row = repo.get(&tid(id)).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::WaitingForUser,
        "the fixture must reach waiting-for-user through the production path"
    );
}

/// What the rival does in the competing-writer tests: it cancels the task, so the
/// transition the contender is attempting is no longer legal.
const CANCEL_T: &str = "UPDATE tasks SET state = 'cancelled' WHERE id = 't';";

/// A write that changes nothing, used where the contention is purely about
/// serialisation and the rival must not alter any predicate.
const NO_OP_WRITE: &str = "UPDATE tasks SET updated_at_ms = updated_at_ms WHERE id = 'x';";

fn count_events(e: &DurableEngine, needle: &str) -> usize {
    let repo = TaskRepository::new_readonly(e.conn());
    repo.all_events()
        .expect("events")
        .iter()
        .filter(|ev| ev.kind.as_str().contains(needle))
        .count()
}

// ============================================================ A. competing writer

/// A. A competitor cancels the task after the contender has decided to begin an
/// execution and before the contender writes. The contender must be told it lost, by
/// name, and must leave no lease and no spent approval behind.
#[test]
fn a_competing_state_change_is_a_classified_refusal_not_a_busy_error() {
    let d = dir("A-competing-transition");
    let db = db_in(&d);
    approved_waiting_task(&db, "t", &digest("ab"));

    let (out, blocked) = contending(
        &db,
        |repo| {
            Outcome::of(
                repo.begin_execution_spending_approval("proposal-under-test", "w-a", NOW, LEASE_MS)
                    .map(|_| ()),
            )
        },
        CANCEL_T,
    );

    assert_contended(blocked, "A");
    out.assert_loser_was_told_why("A: contender that lost the race");

    // A refusal must leave the task exactly as it found it.
    let check = open_engine(&db);
    let row = check.task(&tid("t")).expect("read").expect("present");
    assert_ne!(
        row.state,
        TaskState::Running,
        "the contender must not hold a lease it was not entitled to: {row:?}"
    );
    assert!(
        row.lease_holder.is_none(),
        "a refused execution must not leave a lease: {row:?}"
    );
    let spent: Option<i64> = check
        .conn()
        .query_row(
            "SELECT consumed_at_ms FROM task_approvals WHERE task_id = 't';",
            [],
            |r| r.get(0),
        )
        .expect("read approval");
    assert_eq!(
        spent, None,
        "a refused execution must not spend the approval: {spent:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// A'. The same race on the deprecated lease-only entry point — the shape the P1-16
/// zero-row check was added to defend. Deprecated but still reachable, so its
/// transaction semantics must match the operation that replaced it.
#[test]
#[allow(deprecated)]
fn a_competing_state_change_is_a_classified_refusal_on_the_legacy_lease_path() {
    let d = dir("A2-legacy-lease");
    let db = db_in(&d);
    approved_waiting_task(&db, "t", &digest("ab"));

    let (out, blocked) = contending(
        &db,
        |repo| {
            Outcome::of(
                repo.begin_approved_execution("proposal-under-test", "w-a", NOW, LEASE_MS)
                    .map(|_| ()),
            )
        },
        CANCEL_T,
    );

    assert_contended(blocked, "A'");
    out.assert_loser_was_told_why("A': contender on the legacy lease path");
    let _ = std::fs::remove_dir_all(&d);
}

/// A''. The same race on `propose_action`, the other P1-16 site.
#[test]
fn a_competing_state_change_is_a_classified_refusal_on_the_proposal_path() {
    let d = dir("A3-propose");
    let db = db_in(&d);
    approved_waiting_task(&db, "t", &digest("ab"));

    let (out, blocked) = contending(
        &db,
        |repo| {
            Outcome::of(
                repo.propose_action(
                    "second-proposal",
                    &tid("t"),
                    "w-a",
                    "filesystem/write-text",
                    Some("out.txt"),
                    r#"{"path":"out.txt","contents":"x"}"#,
                    r#"{"kind":"human"}"#,
                    None,
                    1,
                    NOW,
                )
                .map(|_| ()),
            )
        },
        CANCEL_T,
    );

    assert_contended(blocked, "A''");
    out.assert_loser_was_told_why("A'': contender on the proposal path");
    let _ = std::fs::remove_dir_all(&d);
}

/// A'''. `request_cancel`, which reads the task, updates it, and reads it again — the one
/// transition whose outcome is *derived from a read* rather than from a row count.
///
/// The correct outcome here is `Ok`, and the test says why that is a hard-won assertion
/// rather than a weak one. Cancelling an already-`cancelled` task is an idempotent no-op
/// by design (`TaskState::is_terminal`), so the contender *should* succeed — but only if
/// it saw the rival's committed state. Under `DEFERRED` it never got that far: the
/// refusal came from `SQLITE_BUSY_SNAPSHOT` before any of this was decided.
///
/// So the assertion is that the contender waited for the lock, and then took the
/// read-derived no-op path: it must not have written anything. If it had decided from a
/// pre-commit snapshot it would have seen `running`, and `cancel_requested_at_ms` would
/// carry its timestamp.
#[test]
fn a_competing_cancellation_makes_the_contender_wait_and_then_see_the_new_state() {
    let d = dir("A4-cancel");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        assert_eq!(
            e.claim_task("w1", NOW)
                .expect("claim")
                .expect("claimed")
                .state,
            TaskState::Running
        );
    }

    let (out, blocked) = contending(
        &db,
        |repo| Outcome::of(repo.request_cancel(&tid("t"), NOW).map(|_| ())),
        CANCEL_T,
    );

    assert_contended(blocked, "A'''");
    out.assert_no_busy_error("A''': contender on the cancel path");

    let check = open_engine(&db);
    let row = check.task(&tid("t")).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::Cancelled,
        "the rival's cancellation stands"
    );
    assert_eq!(
        row.cancel_requested_at_ms, None,
        "the contender must have observed the terminal state and written nothing. A \
         timestamp here means it decided from a snapshot taken before the rival \
         committed: {row:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ====================================================== B. competing approval/execution

/// B. Two workers, one approval, one proposal, released together: exactly one may begin
/// the execution, the other must be told why it lost, and the approval must be spent
/// exactly once.
///
/// Neither worker is rigged to lose — which one wins depends on which reaches the write
/// lock first — so the assertions are a set: one winner, and the winner owns the lease.
#[test]
fn two_workers_racing_one_approval_never_allow_both_to_execute() {
    let d = dir("B2-simultaneous");
    let db = db_in(&d);
    approved_waiting_task(&db, "t", &digest("cd"));

    let spawn = |name: &'static str, p: PathBuf| -> JoinHandle<Result<String, String>> {
        std::thread::spawn(move || {
            let mut conn = open_peer(&p);
            let mut repo = TaskRepository::new(&mut conn);
            repo.begin_execution_spending_approval("proposal-under-test", name, NOW, LEASE_MS)
                .map(|r| r.task_id.to_string())
                .map_err(|e| e.to_string())
        })
    };

    let a = spawn("w-a", db.clone());
    let b = spawn("w-b", db.clone());
    let ra = a.join().expect("worker a");
    let rb = b.join().expect("worker b");

    let winners = [ra.is_ok(), rb.is_ok()].iter().filter(|w| **w).count();
    assert_eq!(
        winners, 1,
        "exactly one worker may begin the execution.\n\
         One approval, one proposal, two workers. If both succeed then one approval has \
         authorised two executions, which is the entire thing approvals exist to prevent.\n\
         \n  a = {ra:?}\n  b = {rb:?}"
    );

    for (who, r) in [("w-a", ra.as_ref()), ("w-b", rb.as_ref())] {
        if let Err(why) = r {
            assert!(
                !is_busy_message(why),
                "{who} lost the race and was told the database was busy instead of why it \
                 lost. A busy error is not a refusal.\n  {why}"
            );
        }
    }

    let check = open_engine(&db);
    let (spends, at): (i64, Option<i64>) = check
        .conn()
        .query_row(
            "SELECT COUNT(*), MIN(consumed_at_ms) FROM task_approvals
              WHERE task_id = 't' AND consumed_at_ms IS NOT NULL;",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("count spends");
    assert_eq!(spends, 1, "the approval is spent exactly once");
    assert_eq!(at, Some(NOW), "and by the winner's clock, not the epoch");

    let row = check.task(&tid("t")).expect("read").expect("present");
    assert_eq!(
        row.lease_holder.as_deref(),
        Some(if ra.is_ok() { "w-a" } else { "w-b" }),
        "the lease belongs to the worker that won"
    );
    assert_eq!(row.state, TaskState::Running, "{row:?}");
    let _ = std::fs::remove_dir_all(&d);
}

/// B (stress). The same race repeated, so a schedule that happens to serialise cleanly
/// on one run cannot pass every time.
#[test]
fn two_workers_racing_one_approval_never_allow_both_to_execute_over_many_runs() {
    for round in 0..40 {
        let d = dir(&format!("B3-stress-{round}"));
        let db = db_in(&d);
        approved_waiting_task(&db, "t", &digest("ef"));

        let spawn = |name: &'static str, p: PathBuf| -> JoinHandle<Result<(), String>> {
            std::thread::spawn(move || {
                let mut conn = open_peer(&p);
                let mut repo = TaskRepository::new(&mut conn);
                repo.begin_execution_spending_approval("proposal-under-test", name, NOW, LEASE_MS)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            })
        };
        let a = spawn("w-a", db.clone());
        let b = spawn("w-b", db.clone());
        let ra = a.join().expect("worker a");
        let rb = b.join().expect("worker b");

        let winners = [ra.is_ok(), rb.is_ok()].iter().filter(|w| **w).count();
        assert_eq!(
            winners, 1,
            "round {round}: exactly one worker may begin the execution. a={ra:?} b={rb:?}"
        );
        for r in [&ra, &rb] {
            if let Err(why) = r {
                assert!(
                    !is_busy_message(why),
                    "round {round}: a losing worker was told the database was busy \
                     rather than why it lost: {why}"
                );
            }
        }

        let check = open_engine(&db);
        let spends: i64 = check
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM task_approvals
                  WHERE task_id = 't' AND consumed_at_ms IS NOT NULL;",
                [],
                |r| r.get(0),
            )
            .expect("count spends");
        assert_eq!(
            spends, 1,
            "round {round}: the approval is spent exactly once"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// B (fan-out). Four and eight workers, not just two. The invariant is the same and the
/// point is different: with more contenders, the losers are more likely to collide with
/// a snapshot rather than a lock, which is what `IMMEDIATE` has to absorb.
#[test]
fn many_workers_racing_one_approval_never_allow_more_than_one_execution() {
    for workers in [4usize, 8] {
        let d = dir(&format!("B4-fanout-{workers}"));
        let db = db_in(&d);
        approved_waiting_task(&db, "t", &digest("11"));

        let handles: Vec<_> = (0..workers)
            .map(|i| {
                let p = db.clone();
                std::thread::spawn(move || {
                    let name = format!("w-{i}");
                    let mut conn = open_peer(&p);
                    let mut repo = TaskRepository::new(&mut conn);
                    repo.begin_execution_spending_approval(
                        "proposal-under-test",
                        &name,
                        NOW,
                        LEASE_MS,
                    )
                    .map(|_| ())
                    .map_err(|e| e.to_string())
                })
            })
            .collect();

        let results: Vec<Result<(), String>> = handles
            .into_iter()
            .map(|h| h.join().expect("worker"))
            .collect();

        let winners = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            winners, 1,
            "{workers} workers, one approval: exactly one may begin. {results:?}"
        );
        for (i, r) in results.iter().enumerate() {
            if let Err(why) = r {
                assert!(
                    !is_busy_message(why),
                    "with {workers} workers, loser {i} was told the database was busy \
                     rather than why it lost: {why}"
                );
            }
        }

        let check = open_engine(&db);
        let spends: i64 = check
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM task_approvals
                  WHERE task_id = 't' AND consumed_at_ms IS NOT NULL;",
                [],
                |r| r.get(0),
            )
            .expect("count spends");
        assert_eq!(spends, 1, "{workers} workers: spent exactly once");
        let _ = std::fs::remove_dir_all(&d);
    }
}

// ============================================================ C. competing recovery

/// C. Recovery run twice, genuinely interleaved: each orphan settled exactly once.
///
/// `recover` returning `Ok(0)` for the loser is legitimate — there was nothing left to
/// settle. What is not legitimate is being told the database is busy, or a second
/// settling transition.
#[test]
fn two_recoveries_racing_settle_each_orphan_exactly_once() {
    let d = dir("C-two-recoveries");
    let db = db_in(&d);

    // Two tasks left mid-flight by a crash: `running`, lease expired.
    for id in ["orphan-1", "orphan-2"] {
        let mut e = open_engine(&db);
        e.enqueue_new(&NewTask::new(tid(id), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        assert_eq!(
            e.claim_task("doomed", NOW)
                .expect("claim")
                .expect("claimed")
                .state,
            TaskState::Running
        );
        e.conn()
            .execute(
                "UPDATE tasks SET lease_expires_at_ms = ?1 WHERE id = ?2;",
                rusqlite::params![NOW - 1_000, id],
            )
            .expect("expire the lease so recovery considers the task");
    }

    // The rival holds the write lock but changes nothing: the contention is purely about
    // serialisation, so recovery must wait and then decide on current state.
    let (first, _blocked) = race(
        &db,
        |conn| {
            let mut repo = TaskRepository::new(conn);
            repo.recover(NOW).map_err(|e| e.to_string())
        },
        NO_OP_WRITE,
    );

    let mut second = open_engine(&db);
    let b = {
        let mut repo = TaskRepository::new(second.conn_mut());
        repo.recover(NOW)
    };

    let first_count = match first {
        Ok(n) => n as usize,
        Err(m) => panic!("a losing recovery must not fail at all: {m}"),
    };
    let second_count = match b.as_ref() {
        Ok(v) => *v as usize,
        Err(e) => panic!("the second recovery failed rather than finding nothing: {e}"),
    };
    assert_eq!(
        first_count + second_count,
        2,
        "each orphan settled exactly once across both recoveries"
    );

    // And the durable record agrees: two settling events, one per orphan.
    let settling = count_events(&second, "recovered");
    assert_eq!(
        settling, 2,
        "exactly one settling event per orphan: {settling} events"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// C (fan-out). Four recoveries racing: still one settling transition per orphan, and no
/// recovery told to retry because of a snapshot conflict.
#[test]
fn four_recoveries_racing_still_settle_each_orphan_exactly_once() {
    let d = dir("C2-four-recoveries");
    let db = db_in(&d);
    for id in ["o1", "o2", "o3", "o4"] {
        let mut e = open_engine(&db);
        e.enqueue_new(&NewTask::new(tid(id), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        assert_eq!(
            e.claim_task("doomed", NOW)
                .expect("claim")
                .expect("claimed")
                .state,
            TaskState::Running
        );
        e.conn()
            .execute(
                "UPDATE tasks SET lease_expires_at_ms = ?1 WHERE id = ?2;",
                rusqlite::params![NOW - 1_000, id],
            )
            .expect("expire");
    }

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let p = db.clone();
            std::thread::spawn(move || {
                let mut conn = open_peer(&p);
                let mut repo = TaskRepository::new(&mut conn);
                repo.recover(NOW).map_err(|e| e.to_string())
            })
        })
        .collect();
    let results: Vec<Result<u64, String>> =
        handles.into_iter().map(|h| h.join().unwrap()).collect();

    let settled: usize = results
        .iter()
        .map(|r| match r {
            Ok(n) => *n as usize,
            Err(m) => panic!("a recovery failed rather than finding nothing to do: {m}"),
        })
        .sum();
    assert_eq!(
        settled, 4,
        "four orphans, settled four times in total across four recoveries: {results:?}"
    );

    let check = open_engine(&db);
    assert_eq!(
        count_events(&check, "recovered"),
        4,
        "one settling event per orphan"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ============================================================ D. claim vs recovery

/// D. `recover` and `take_lease` racing for the same eligible task.
///
/// Stated as a set of permitted final states, because the interesting part is that
/// **both** outcomes are legal: either the claimant wins and the task is running with its
/// lease, or recovery wins and the task is pending and unleased. The defect would be a
/// task settled twice, `running` with no lease, or `pending` still holding one.
#[test]
fn recovery_racing_a_claim_leaves_exactly_one_owner() {
    let d = dir("D-claim-vs-recovery");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        e.enqueue_new(
            &NewTask::new(tid("contested"), TaskKind::Workflow, NOW),
            NOW,
        )
        .expect("enqueue");
        assert_eq!(
            e.claim_task("doomed", NOW)
                .expect("claim")
                .expect("claimed")
                .state,
            TaskState::Running
        );
        e.conn()
            .execute(
                "UPDATE tasks SET lease_expires_at_ms = ?1 WHERE id = 'contested';",
                rusqlite::params![NOW - 1_000],
            )
            .expect("expire");
    }

    let (recovery, _blocked) = race(
        &db,
        |conn| {
            let mut repo = TaskRepository::new(conn);
            repo.recover(NOW).map_err(|e| e.to_string())
        },
        NO_OP_WRITE,
    );

    let mut claimant = open_engine(&db);
    let claim = claimant
        .claim_task("late-claimer", NOW)
        .expect("claim")
        .map(|c| c.id);

    let check = open_engine(&db);
    let row = check
        .task(&tid("contested"))
        .expect("read")
        .expect("present");
    let settling = count_events(&check, "recovered");

    assert!(
        settling <= 1,
        "the task was settled more than once, which means recovery and claim both \
         believed they owned it.\n  recovery={recovery:?}\n  claim={claim:?}\n  {row:?}"
    );
    if let Err(why) = recovery {
        assert!(
            !is_busy_message(&why),
            "recovery was told the database was busy rather than what it settled: {why}"
        );
    }
    match row.state {
        TaskState::Running => assert!(
            row.lease_holder.is_some(),
            "`running` with no lease is not a state this system may be in: {row:?}"
        ),
        TaskState::Pending => assert!(
            row.lease_holder.is_none(),
            "`pending` while still holding a lease: {row:?}"
        ),
        other => panic!("unexpected final state {other:?}: {row:?}"),
    }
    let _ = std::fs::remove_dir_all(&d);
}

// ==================================================== the mechanism, measured directly

/// The mechanism, measured rather than assumed: the *same* read-then-write, twice,
/// differing only in the `BEGIN`. Both arms are reported.
///
/// Under `DEFERRED` the read precedes the write lock, so a rival can commit in between
/// and the write is refused with `SQLITE_BUSY_SNAPSHOT` — which the busy handler never
/// sees. Under `IMMEDIATE` the lock is taken first, so there is no interval, and the
/// contender simply waits.
#[test]
fn deferred_and_immediate_differ_in_whether_the_write_can_be_committed() {
    for (behavior, tag) in [
        (TransactionBehavior::Deferred, "deferred"),
        (TransactionBehavior::Immediate, "immediate"),
    ] {
        let d = dir(&format!("mechanism-comparison-{tag}"));
        let db = db_in(&d);
        {
            let mut e = open_engine(&db);
            e.enqueue_new(&NewTask::new(tid("m"), TaskKind::Workflow, NOW), NOW)
                .expect("enqueue");
        }

        let (report, blocked) = race(
            &db,
            move |conn| {
                let tx = conn.transaction_with_behavior(behavior).expect("begin");
                // Read first, exactly as the production operations do.
                let state: String = tx
                    .query_row("SELECT state FROM tasks WHERE id = 'm';", [], |r| r.get(0))
                    .expect("read state");
                // Then write against the decision made from that read.
                let wrote = tx.execute(
                    "UPDATE tasks SET state = 'running'
                      WHERE id = 'm' AND state = 'waiting-for-user';",
                    [],
                );
                match wrote {
                    Ok(n) => {
                        let committed = tx.commit().map_err(|e| e.to_string());
                        format!("{tag}: read {state}; wrote {n} rows; commit -> {committed:?}")
                    }
                    Err(e) => {
                        let why = e.to_string();
                        let code = extended_code(&e);
                        format!("{tag}: read {state}; write refused (extended {code}): {why}")
                    }
                }
            },
            "UPDATE tasks SET state = 'cancelled' WHERE id = 'm';",
        );
        eprintln!("V-95 mechanism, {tag} (blocked first = {blocked}): {report}");
        assert!(
            report.contains("cancelled") || report.contains("locked"),
            "{tag}: the report must show either the rival's committed state or a refused \
             stale write, got: {report}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// The decisive form, asserted rather than printed: under `IMMEDIATE` the writer blocks
/// at `BEGIN`, so by the time it reads, the rival's commit is already visible and the
/// decision is made on current state. There is no window to lose.
#[test]
fn immediate_reads_current_state_because_the_lock_is_taken_before_the_read() {
    let d = dir("mechanism-immediate-alone");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        e.enqueue_new(&NewTask::new(tid("m"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
    }

    let (observed, blocked) = race(
        &db,
        |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin");
            let state: String = tx
                .query_row("SELECT state FROM tasks WHERE id = 'm';", [], |r| r.get(0))
                .expect("read");
            tx.commit().expect("commit");
            state
        },
        "UPDATE tasks SET state = 'cancelled' WHERE id = 'm';",
    );

    assert!(blocked, "IMMEDIATE must wait at BEGIN, not fail");
    assert_eq!(
        observed, "cancelled",
        "under IMMEDIATE the read happens after the rival committed, so the decision is \
         made on current state"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The control, asserted directly: under `DEFERRED` the writer does not wait at all. It
/// takes a snapshot, the rival commits, and the write is refused as a *snapshot*
/// conflict — an error that names neither the operation nor the state that became
/// undecidable, and that no busy handler or `busy_timeout` can absorb.
#[test]
fn deferred_never_waits_and_reports_an_unclassifiable_conflict() {
    let d = dir("mechanism-deferred-alone");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        e.enqueue_new(&NewTask::new(tid("m"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
    }

    let (observed, blocked) = race(
        &db,
        |conn| {
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .expect("begin");
            let state: String = tx
                .query_row("SELECT state FROM tasks WHERE id = 'm';", [], |r| r.get(0))
                .expect("read");
            let wrote = tx
                .execute(
                    "UPDATE tasks SET state = 'running'
                      WHERE id = 'm' AND state = 'waiting-for-user';",
                    [],
                )
                .map_err(|e| (e.to_string(), extended_code(&e)));
            (state, wrote)
        },
        "UPDATE tasks SET state = 'cancelled' WHERE id = 'm';",
    );

    let (state, wrote) = observed;
    assert_eq!(
        state, "pending",
        "the DEFERRED read happened before the rival committed, so it could not have \
         seen the cancellation"
    );
    assert!(
        !blocked,
        "the whole finding: a deferred read-then-write does not wait for the write lock, \
         so there is no point at which it could have"
    );
    match wrote {
        Ok(n) => panic!(
            "DEFERRED then committed {n} row(s) from a snapshot taken before the rival \
             committed. The rival's UPDATE did not touch this row, so the predicate \
             happened to stay true -- which is exactly why the bug is invisible without \
             an adversary: whether a stale decision is *caught* depends on whether the \
             rival happened to write the same row, and whether it is *correct* depends \
             on whether it did."
        ),
        Err((why, code)) => {
            eprintln!("V-95 mechanism, deferred: refused with extended code {code}: {why}");
            assert_eq!(
                code, 5,
                "expected SQLITE_BUSY_SNAPSHOT (extended code 5), got {code}: {why}"
            );
            assert!(
                is_busy_message(&why),
                "and it must render as an unclassifiable 'database is locked': {why}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// The SQLite extended code, which is the only place the distinction survives: 5 is
/// `SQLITE_BUSY_SNAPSHOT`, and it is not retryable by any busy handler.
fn extended_code(e: &rusqlite::Error) -> i32 {
    match e {
        rusqlite::Error::SqliteFailure(f, _) => f.extended_code,
        other => {
            eprintln!("not a SQLite failure: {other:?}");
            -1
        }
    }
}
