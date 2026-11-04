//! V-102 / A-023 (CONC-006): the fenced heartbeat is the function that keeps a
//! continuation's claim alive across a provider call, and it cannot be used to revive
//! work that is no longer that worker's.
//!
//! # The defect this file exists to prevent
//!
//! The daemon's `task/continue` route released the governed mutex while the model was
//! being asked (the correction itself), and then a follow-up made the claim survive a
//! model call that outlives the lease: while the model waits, the continuation calls
//! `DurableEngine::heartbeat` — the store's own fenced renewal — every third of the
//! lease. That is safe **only** if the heartbeat's predicate is exactly what it says it
//! is, because a renewal write is a write with nobody else's consent check behind it:
//!
//! ```sql
//! UPDATE tasks SET lease_expires_at_ms = ?4, updated_at_ms = ?3
//!   WHERE id = ?1 AND lease_holder = ?2
//!     AND lease_expires_at_ms IS NOT NULL AND lease_expires_at_ms > ?3;
//! ```
//!
//! The four clauses each refuse a way a dead claim could be revived:
//!
//! * `lease_holder = ?` — the lease was retaken by another worker;
//! * `lease_expires_at_ms IS NOT NULL` — cancellation, a step boundary or a human
//!   proposal cleared the lease entirely (a cancelled task's lease is gone, so there is
//!   nothing to extend);
//! * `lease_expires_at_ms > ?` — the lease lapsed and is someone else's decision now.
//!
//! So this file pins each clause on the engine's own production path (`DurableEngine`
//! over a real migrated store): a renewal extends only a lease *this worker* holds and
//! that has not yet lapsed, and every other attempt is `Ok(false)` — a refusal, not an
//! error, so the caller cannot mistake a lost claim for a lost database. Nothing here
//! waits on a clock: every timestamp is a harness constant passed in explicitly, which
//! is why the 30 s lease is exercised in milliseconds.
//!
//! The same file pins the **persistence clock** half of the A-023 follow-up. A
//! `task/continue` or `task/ai-propose` call can spend longer than the lease between
//! gathering its proposal and writing it, so the final lease fence must sample the
//! clock inside the store's `IMMEDIATE` transaction rather than accept a timestamp
//! captured before the wait. The last two tests below drive
//! `propose_action_at_write` and `complete_task_with_at_write` with an expired clock
//! and a live one, and assert both the refusal and the timestamp the accepted row
//! carries.

use orxnud_domain::actor::{Actor, AuthChannel};
use orxnud_domain::ids::{CapabilityId, TaskId, UserId};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::NewTask;
use orxnud_task::engine::ClaimAttempt;
use orxnud_task::{EngineErrorKind, EngineLimits, TaskCause, TaskKind, TaskState};
use std::path::{Path, PathBuf};

/// 2026-01-01T00:00:00Z. Fixed, so every assertion is about the predicate and not about
/// a clock that moved.
const NOW: i64 = 1_767_225_600_000;

/// The documented lease. Used by name rather than read off the limits, so a change to
/// the documented lease is a change *here* too, and the tests that depend on its
/// arithmetic cannot drift silently.
const LEASE_MS: i64 = 30_000;

fn tid(s: &str) -> TaskId {
    TaskId::new(s)
}

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-v102-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn db_in(d: &Path) -> PathBuf {
    d.join("state.db")
}

/// The documented limits. Nothing here needs them shorter: the clock is supplied
/// explicitly, so a 30 s lease lapses between two statement calls, not between two
/// wall-clock waits.
fn documented_limits() -> EngineLimits {
    EngineLimits::documented()
}

/// Opens, applies the production pragmas, migrates, and wraps for the engine.
fn engine_on(path: &Path) -> orxnud_task::DurableEngine {
    let conn = rusqlite::Connection::open(path).expect("open");
    Pragma::critical().apply(&conn).expect("pragmas");
    Pragma::critical().verify(&conn).expect("verify pragmas");
    MigrationRunner::new(&conn)
        .migrate(path, &orxnud_platform_fs::OsIdentity)
        .expect("migrate");
    orxnud_task::DurableEngine::new(conn, documented_limits()).expect("engine")
}

/// A second connection to the same already-migrated file, opened **read-only**.
///
/// Production disables nothing to make this work: it is the ordinary SQLite read-only
/// mode, used here because a storage failure has to come from *somewhere* deterministic,
/// and "the file the store would write to refuses writes" is the smallest honest fixture
/// available without adding a fault point to the store.
fn read_only_engine(path: &Path) -> orxnud_task::DurableEngine {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only");
    orxnud_task::DurableEngine::new(conn, documented_limits()).expect("read-only engine")
}

/// A task in `pending`, then claimed by `w1` at `NOW`, so the row holds a live lease to
/// `NOW + LEASE_MS`.
fn claimed_by_w1(e: &mut orxnud_task::DurableEngine) {
    e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
        .expect("enqueue");
    match e.claim_task_id(&tid("t"), "w1", NOW).expect("claim") {
        ClaimAttempt::Claimed(_) => {}
        ClaimAttempt::Refused(r) => panic!("the fixture task must claim cleanly: {r:?}"),
    }
}

/// A heartbeat that succeeded is observable in the row: extended from *this* moment,
/// not from the claim's.
#[test]
fn a_heartbeat_extends_a_lease_its_worker_still_holds() {
    let d = dir("extends");
    let mut e = engine_on(&db_in(&d));
    claimed_by_w1(&mut e);

    let renewed = e
        .heartbeat(
            &tid("t"),
            "w1",
            e.task(&tid("t")).unwrap().unwrap().claim_generation,
            NOW + 1_000,
        )
        .expect("the renewal write must not fail");
    assert!(renewed, "a live, held lease must renew");

    let row = e.task(&tid("t")).expect("read").expect("row");
    assert_eq!(row.state, TaskState::Running, "renewal must not move state");
    assert_eq!(row.lease_holder.as_deref(), Some("w1"));
    // Extended from the renewal's own `now`, not the claim's: the caller learns
    // nothing it did not already rely on, but the arithmetic says which moment the
    // write measured time from.
    assert_eq!(row.lease_expires_at_ms, Some(NOW + 1_000 + LEASE_MS));
}

/// The lapsed-lease clause: once the expiry instant has passed, the claim is gone, and a
/// renewal from the worker who had it is refused **as a value, not as an error** — and
/// the row is left untouched, because what owns the task next is nobody but the budget
/// and recovery's to decide.
#[test]
fn a_heartbeat_cannot_extend_a_lease_that_has_lapsed() {
    let d = dir("lapsed");
    let mut e = engine_on(&db_in(&d));
    claimed_by_w1(&mut e);

    // Exactly at the boundary is lapsed: the predicate is strictly `>`, so an expiry
    // instant itself is not a live lease.
    let at_expiry = e
        .heartbeat(
            &tid("t"),
            "w1",
            e.task(&tid("t")).unwrap().unwrap().claim_generation,
            NOW + LEASE_MS,
        )
        .expect("the attempt must be a value, not a write failure");
    let past = e
        .heartbeat(
            &tid("t"),
            "w1",
            e.task(&tid("t")).unwrap().unwrap().claim_generation,
            NOW + LEASE_MS + 1,
        )
        .expect("the attempt must be a value, not a write failure");

    assert!(!at_expiry, "an expiry instant is not a live lease");
    assert!(!past, "a lapsed lease cannot be extended by its own worker");

    let row = e.task(&tid("t")).expect("read").expect("row");
    assert_eq!(row.lease_expires_at_ms, Some(NOW + LEASE_MS));
    assert_eq!(row.lease_holder.as_deref(), Some("w1"));
}

/// The holder clause: another worker's renewal is refused even while the lease is live.
#[test]
fn a_heartbeat_cannot_extend_another_workers_lease() {
    let d = dir("foreign");
    let mut e = engine_on(&db_in(&d));
    claimed_by_w1(&mut e);

    let renewed = e
        .heartbeat(
            &tid("t"),
            "w2",
            e.task(&tid("t")).unwrap().unwrap().claim_generation,
            NOW + 1_000,
        )
        .expect("the attempt must be a value, not a write failure");

    assert!(
        !renewed,
        "a worker who does not hold the lease cannot renew it"
    );

    let row = e.task(&tid("t")).expect("read").expect("row");
    assert_eq!(row.lease_expires_at_ms, Some(NOW + LEASE_MS));
    assert_eq!(row.lease_holder.as_deref(), Some("w1"));
}

/// Cancellation clears the lease, and a cleared lease is not an extendable one: a
/// renewal cannot resurrect work a human cancelled while the model was still thinking.
#[test]
fn a_heartbeat_cannot_revive_a_cancelled_task() {
    let d = dir("cancelled");
    let mut e = engine_on(&db_in(&d));
    claimed_by_w1(&mut e);
    e.cancel_task(&tid("t"), NOW + 1_000).expect("cancel");

    let renewed = e
        .heartbeat(
            &tid("t"),
            "w1",
            e.task(&tid("t")).unwrap().unwrap().claim_generation,
            NOW + 2_000,
        )
        .expect("the attempt must be a value, not a write failure");

    assert!(!renewed, "a renewal must not revive a cancelled task");

    let row = e.task(&tid("t")).expect("read").expect("row");
    assert_eq!(row.state, TaskState::Cancelled);
    assert_eq!(row.lease_holder, None, "the lease stays cleared");
    assert_eq!(row.lease_expires_at_ms, None, "the lease stays cleared");
}

/// A renewal failure is a **failure**, not a reported success.
///
/// The engine's storage layer reports the write that could not be performed, and the row
/// keeps the lease it had — so a caller that treats an error as "renewed" is wrong twice,
/// and this test is the place that turns that into a failing run.
#[test]
fn a_heartbeat_reports_a_storage_failure_as_a_failure() {
    let d = dir("storage-failure");
    let path = db_in(&d);
    // Same file, same worker, same claim: only the connection the renewal goes out on
    // can refuse to perform the write.
    {
        let mut e = engine_on(&path);
        claimed_by_w1(&mut e);
        // `e` owns its connection; dropping it closes it and leaves the file with the
        // claimed row and its live lease.
        e.task(&tid("t")).expect("read").expect("row");
    }
    let mut ro = read_only_engine(&path);

    let outcome = ro.heartbeat(
        &tid("t"),
        "w1",
        ro.task(&tid("t")).unwrap().unwrap().claim_generation,
        NOW + 1_000,
    );

    let err = outcome.expect_err("a storage failure on a renewal is a failure");
    assert_eq!(
        err.kind,
        EngineErrorKind::Storage,
        "a write that could not be performed is a storage fault, not success"
    );

    // The failed renewal is also a no-renewal: the row still holds the lease it had.
    let row = ro.task(&tid("t")).expect("read").expect("row");
    assert_eq!(row.lease_expires_at_ms, Some(NOW + LEASE_MS));
    assert_eq!(row.lease_holder.as_deref(), Some("w1"));
}

/// The proposal's lease fence is judged by the clock *at the write*, not the clock the
/// caller captured before the provider call.
///
/// This is the store-level half of the CONC-006 correction. `task/continue` holds the
/// model call outside the governed lock; when the answer arrives, the proposal is
/// written with `propose_action_at_write`, whose clock is read inside the `IMMEDIATE`
/// transaction. The same worker, the same row and the same pre-wait constant `NOW` are
/// used twice below: the first call reads the clock at expiry and is refused, the second
/// reads it while live and is accepted. If the fence were still using a caller-supplied
/// pre-wait timestamp, both calls would have the same answer.
#[test]
fn a_proposal_at_write_is_judged_by_the_write_clock_not_the_claim_clock() {
    let d = dir("proposal-at-write");
    let mut e = engine_on(&db_in(&d));
    claimed_by_w1(&mut e);

    let proposer = Actor::Human {
        user: UserId::new("local"),
        via: AuthChannel::LocalInteractive,
    };
    let capability = CapabilityId::new("text/word-count");

    // The write clock reads exactly at expiry, which is already lapsed (strict `>`).
    let refused = e.propose_action_at_write(
        "p-expired",
        &tid("t"),
        "w1",
        e.task(&tid("t")).unwrap().unwrap().claim_generation,
        &capability,
        None,
        r#"{"text":"one two three"}"#,
        &proposer,
        || NOW + LEASE_MS,
    );
    let err = refused.expect_err("an expired lease must refuse the proposal at the write");
    assert_eq!(
        err.cause,
        TaskCause::Conflict,
        "a stale lease is a conflict, not malformed input: {err}"
    );

    // The refusal left the claim exactly as it was: still running, still held, still
    // at its original expiry. A refused write is not a partial completion.
    let row = e.task(&tid("t")).expect("read").expect("row");
    assert_eq!(row.state, TaskState::Running);
    assert_eq!(row.lease_holder.as_deref(), Some("w1"));
    assert_eq!(row.lease_expires_at_ms, Some(NOW + LEASE_MS));

    // The same call, with the write clock reading a live instant, is accepted — and
    // the proposal carries that clock, not the claim-time constant.
    let accepted = e
        .propose_action_at_write(
            "p-live",
            &tid("t"),
            "w1",
            e.task(&tid("t")).unwrap().unwrap().claim_generation,
            &capability,
            None,
            r#"{"text":"one two three"}"#,
            &proposer,
            || NOW + 1_000,
        )
        .expect("a live lease must accept the proposal");
    assert_eq!(
        accepted.created_at_ms,
        NOW + 1_000,
        "the proposal must be stamped with the persistence clock"
    );
}

/// The completion path's lease fence is judged by the clock *at the write*.
///
/// A `done` answer from the model completes the task through the same at-write path as
/// a proposal. The pre-wait value would say the claim was live; the write clock is what
/// decides, so an expired claim is refused as a value and the row is untouched.
#[test]
fn a_completion_at_write_is_judged_by_the_write_clock_not_the_claim_clock() {
    let d = dir("completion-at-write");
    let mut e = engine_on(&db_in(&d));
    claimed_by_w1(&mut e);

    let refused = e
        .complete_task_with_at_write(
            &tid("t"),
            "w1",
            e.task(&tid("t")).unwrap().unwrap().claim_generation,
            TaskState::Completed,
            false,
            None,
            None,
            || NOW + LEASE_MS,
        )
        .expect("a fenced completion is a value, not a write failure");
    assert!(!refused, "an expired lease must refuse the completion");

    let row = e.task(&tid("t")).expect("read").expect("row");
    assert_eq!(row.state, TaskState::Running);
    assert_eq!(row.lease_holder.as_deref(), Some("w1"));
    assert_eq!(row.terminal_at_ms, None, "no terminal stamp was written");

    let accepted = e
        .complete_task_with_at_write(
            &tid("t"),
            "w1",
            e.task(&tid("t")).unwrap().unwrap().claim_generation,
            TaskState::Completed,
            false,
            Some("no work required"),
            None,
            || NOW + 1_000,
        )
        .expect("a live lease must accept the completion");
    assert!(accepted);

    let row = e.task(&tid("t")).expect("read").expect("row");
    assert_eq!(row.state, TaskState::Completed);
    assert_eq!(
        row.terminal_at_ms,
        Some(NOW + 1_000),
        "the terminal stamp is the write clock"
    );
}
