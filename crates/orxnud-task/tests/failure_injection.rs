//! Failure injection at realistic interruption points (docs-08 §4.6).
//!
//! # Real processes, not simulated ones
//!
//! Every crash here is an actual `SIGKILL` delivered by the operating system to a
//! real child process. That is the only faithful analogue of power loss: no
//! unwinding, no destructors, no flush, no chance for the child to tidy up. A
//! "crash" simulated by dropping a value or by calling a rollback path tests the
//! test's own imagination about what a crash does.
//!
//! The child writes through the **production engine** against a **real file**, so
//! what is being killed is the code that ships.
//!
//! # The interruption points
//!
//! | Point | What is true when the child dies |
//! |---|---|
//! | `before-write` | Nothing was attempted |
//! | `after-enqueue` | The task is durable, unclaimed |
//! | `after-claim` | The lease is durable and orphaned |
//! | `after-complete-before-ack` | The task is terminal; the *caller* never learned |
//! | `after-effect-reserved` | The dedupe row is durable and unresolved |
//!
//! The last two are the ones a naive implementation gets wrong. `after-complete-
//! before-ack` is the reason TP-12 exists: the effect happened, the database says
//! so, and the worker that was about to report success does not exist.
//!
//! # How a point is reached, and why it is the only way
//!
//! Every point below is announced by the child **at the statement that establishes
//! it**, and the parent kills on that announcement. There is no sleep anywhere in
//! the protocol.
//!
//! This was not always so, and the reason is worth recording because the old version
//! looked reasonable and was wrong. The child used to signal a single `ready` file as
//! soon as it had opened the database, and the parent waited for that file and then
//! slept a fixed 25 ms before killing. That synchronises nothing: the child is
//! "ready" *before* it has enqueued, claimed or reserved anything, so the 25 ms was a
//! guess that the remaining three transactions would commit in time. On a fast machine
//! they take about 0.8 ms, so the guess holds with a 30x margin and the test passes. On
//! a loaded CI runner they can take longer than 25 ms, and then the kill lands *before*
//! the reservation, `effects_for` returns nothing, and the test fails having tested
//! nothing at all.
//!
//! Demonstrated rather than asserted: with the 25 ms reduced to 0 ms on this machine,
//! `a_crash_after_the_effect_reserves_leaves_the_outcome_explicitly_unknown` fails 4
//! runs out of 10. The margin was the only thing holding the test up.
//!
//! So the invariant now is: if the parent kills because a point was announced, the
//! state that point names is already durable. That is a property of the protocol
//! rather than of how fast the machine is.
//!
//! # Why `during-complete` is not in this file
//!
//! It used to be, and it never interrupted anything. There is no statement inside the
//! completion transaction this crate can observe, because the transaction belongs to
//! [`orxnud_store::task_repo`] -- and `child_main()` never even had a `stop_here` for
//! it, so the point silently ran to the end of the child and the kill landed wherever
//! the 25 ms guess happened to fall. The test asserted "wholly before or wholly
//! after" while being unable to produce "during".
//!
//! A real mid-transaction interruption is possible and is tested, but not from here.
//! `orxnud-store` has a feature-gated fault hook (`faults::maybe_crash`) that aborts
//! the process from inside the transaction, and
//! `faults::atomicity::a_crash_inside_the_completion_transaction_undoes_the_completion`
//! drives exactly this point: the tasks row updated, the lease cleared, the attempt
//! row still open, then SIGABRT. It asserts the rollback of all three.
//!
//! That hook is deliberately unreachable from `orxnud-task`. It is gated on
//! `#[cfg(any(test, feature = "fault-injection"))]`, and `cfg(test)` applies only to
//! `orxnud-store`'s own test target -- so in a dependent crate's test binary the hook
//! is compiled out, which was confirmed here rather than assumed. The other route,
//! enabling `orxnud-store/fault-injection` from this crate's manifest, is blocked on
//! purpose: `orxnud-store`'s own `fault_feature_is_not_shipped` test fails any manifest
//! that enables it, because the hook calls `std::process::abort` and an environment
//! carrying `ORXNUD_FAULT` must never be able to kill a shipped daemon.
//!
//! So the honest position is that this file does not cover the interior of the
//! terminal transition, `orxnud-store` covers it properly, and claiming otherwise here
//! would have been the defect all over again. The point is removed rather than
//! reimplemented as a timing approximation.
//!
//! # Every case is checked for the master property
//!
//! *"No failure injection ever produces silent data loss or an unauthorised side
//! effect."* So each case asserts: no lost task, no task in an impossible state, no
//! task stuck `running` with a dead owner after recovery, and `integrity_check` ok.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use orxnud_domain::ids::TaskId;
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_task::conformance::properties::{Claim, TaskEngine, TaskRecord};
use orxnud_task::{DurableEngine, EngineLimits};

const NOW: i64 = 1_767_225_600_000;

/// Where the child should stop, and what it must leave behind on the way.
const ENV_POINT: &str = "ORXNUD_FAULT_POINT";
const ENV_DB: &str = "ORXNUD_FAULT_DB";
const ENV_READY: &str = "ORXNUD_FAULT_READY";

/// The interruption points, as data so the parent and child cannot disagree.
///
/// Every one of these is announced by [`announce`] at the statement that establishes
/// it. `during-complete` was in this list and never was: nothing in this crate can
/// observe the interior of a transaction that `orxnud-store` owns, so the child had no
/// `stop_here` for it and the point meant nothing. It is covered for real in
/// `orxnud-store`'s `faults::atomicity` tests, which can abort from inside the
/// transaction; the module docs explain why that hook cannot be reached from here.
const POINTS: &[&str] = &[
    "before-write",
    "after-enqueue",
    "after-claim",
    "after-complete-before-ack",
    "after-effect-reserved",
];

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-fault-{}-{tag}", std::process::id()));
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

/// Announces that `point` has been reached, in a way the parent can observe.
///
/// This is the whole synchronisation mechanism. It is called at the statement that
/// makes the point *true* -- after `enqueue` has returned, after `claim` has returned,
/// after `reserve_effect` has returned -- so the parent's observation of the file is
/// evidence that the corresponding transaction has already committed. There is
/// deliberately no delay between the work and this call.
///
/// The write is to a temporary file and then renamed, so the parent can never observe
/// the name before the contents are there. That matters because the alternative -- a
/// plain `write` -- leaves a window in which the file exists but is empty, which on a
/// loaded runner is exactly the kind of window that produces a flaky test instead of a
/// clear one.
fn announce(ready: &Path, point: &str) {
    let staging = ready.with_extension("staging");
    std::fs::write(&staging, point.as_bytes()).expect("announce staging");
    std::fs::rename(&staging, ready).expect("announce point");
}

/// The point at which the child should stop.
fn stop_here(point: &str) -> bool {
    std::env::var(ENV_POINT).ok().as_deref() == Some(point)
}

/// Parks forever, so the parent can kill the process at the announced point.
///
/// Returning here would let the child run on into work the parent believes has not
/// happened, which is how a point stops meaning anything. The loop is unreachable from
/// the tests' point of view; the parent always kills before this is observed.
fn park() -> ! {
    loop {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Runs the child's work, announcing each point as it is genuinely established.
///
/// Never returns: the parent kills the process at the announced point.
fn child_main() -> ! {
    let db = std::env::var(ENV_DB).expect("fault db must be set");
    let ready = std::env::var(ENV_READY).expect("fault ready must be set");
    let db = PathBuf::from(db);
    let ready = PathBuf::from(ready);
    let mut e = open_engine(&db);

    if stop_here("before-write") {
        // Announced here, which is genuinely "nothing was attempted": the engine is
        // open and migrated, and not one task write has been issued.
        announce(&ready, "before-write");
        park();
    }

    let t = tid("fault-task");
    // Re-submission is idempotent here: a worker resuming after a crash must not
    // fail on a task it legitimately created last time. The production engine
    // refuses a duplicate id (TP-1's "silently disappears", in the other
    // direction), so the child checks first -- which is what a caller has to do.
    if e.all().iter().all(|r| r.id != t) {
        e.enqueue(TaskRecord::pending(t.clone(), TaskKind::Workflow))
            .expect("enqueue");
    }

    if stop_here("after-enqueue") {
        // `enqueue` returned, so the task is committed and unclaimed. Announcing
        // after the call is what makes that true rather than probable.
        announce(&ready, "after-enqueue");
        park();
    }

    let Claim::Claimed(claimed) = e
        .claim("victim", NOW)
        .expect("the child must claim its own task")
    else {
        panic!("the child must claim its own task");
    };
    assert_eq!(
        claimed.state,
        TaskState::Running,
        "the claim must be durable"
    );

    if stop_here("after-claim") {
        announce(&ready, "after-claim");
        park();
    }

    // An external effect is reserved *before* it is dispatched, so a crash here
    // leaves an unresolved ledger row -- TP-12's "outcome unknown".
    let key = DurableEngine::idempotency_key(&t, "external-call", "initial");
    let reserved = e.reserve_effect(&key, &t, 1, claimed.attempts, "external-call", false, NOW);
    assert!(
        reserved.expect("reserve"),
        "the first reservation must succeed"
    );

    if stop_here("after-effect-reserved") {
        // This is the point whose synchronisation was wrong, and it failed on CI.
        // `reserve_effect` commits (`tx.commit()` inside the repository) before it
        // returns, so announcing after the call means the reservation is durable --
        // which is exactly what `the reservation must be durable` asserts, and
        // previously it could be read before the commit had happened.
        announce(&ready, "after-effect-reserved");
        park();
    }

    e.complete(&t, "victim", NOW, TaskState::Completed, true, None)
        .expect("complete");

    if stop_here("after-complete-before-ack") {
        // The task is terminal and the effect happened. The process that was about
        // to tell the caller is about to be killed.
        announce(&ready, "after-complete-before-ack");
        park();
    }

    // Not a stop point: the child finished cleanly. The parent kills it anyway.
    park()
}

/// Re-executed as the child by [`spawn_child`].
#[test]
#[ignore = "child-process entry point for failure injection, not a test"]
fn fault_child_entry_point() {
    if std::env::var_os(ENV_POINT).is_none() {
        return;
    }
    child_main();
}

fn spawn_child(point: &str, db: &Path, ready: &Path) -> std::io::Result<Child> {
    Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "fault_child_entry_point",
            "--nocapture",
            "--ignored",
        ])
        .env(ENV_POINT, point)
        .env(ENV_DB, db)
        .env(ENV_READY, ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// Kills a child at `point` with SIGKILL and returns once it is dead.
///
/// The wait is for the child to announce *this* point, not for it to start up. The
/// announcement is written by [`announce`] at the statement that makes the point true,
/// so observing it means the state the point names is already committed and the
/// `SIGKILL` lands strictly after it.
///
/// There is no sleep between the announcement and the kill, and that is the whole fix.
/// The previous version waited for a start-up `ready` file and then slept a fixed
/// 25 ms, which meant the kill position depended on how quickly three transactions
/// committed on the runner. See the module docs for what that cost.
///
/// # Panics
///
/// If the child exits before announcing, or never announces. Both are failures: the
/// first means the point was never established, and the second means the child cannot
/// reach it. Returning early instead would let a parent assertion report a confusing
/// consequence of the wrong cause.
fn kill_at(point: &str, db: &Path, ready: &Path) {
    let mut child = spawn_child(point, db, ready).expect("spawn the fault child");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Ok(announced) = std::fs::read_to_string(ready) {
            assert_eq!(
                announced, point,
                "the child announced {announced:?} but {point:?} was requested"
            );
            break;
        }
        // A child that died early cannot announce anything, and a 30s wait for it
        // would turn that into a hung test.
        if let Some(status) = child.try_wait().expect("poll the fault child") {
            panic!("the child exited ({status}) before announcing {point}");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the child never announced {point}: it would report a spurious pass"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    // No unwinding, no destructors, no flush -- the closest available analogue of
    // power loss, delivered at a point whose durable state is already established.
    child.kill().expect("SIGKILL");
    let _ = child.wait();
}

// ------------------------------------------------------------ the assertions

/// The master property, applied after a crash at any point.
///
/// Checked with a fresh connection, because that is what the next process gets.
#[track_caller]
fn assert_coherent_after_crash(db: &Path, point: &str) {
    assert!(db.exists(), "{point}: the database file is missing");

    let conn = rusqlite::Connection::open(db).expect("reopen after the crash");
    let integrity: String = conn
        .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
        .expect("check");
    assert_eq!(
        integrity, "ok",
        "{point}: integrity_check reported {integrity}"
    );

    // The schema survived, so a previous binary can still open this database.
    assert_eq!(
        MigrationRunner::new(&conn)
            .applied_version()
            .expect("version"),
        orxnud_store::migration::CURRENT_VERSION,
        "{point}: the schema version did not survive"
    );

    // No task in an impossible state, and none left running with a dead owner.
    let mut stmt = conn
        .prepare("SELECT id, state, lease_holder FROM tasks;")
        .expect("prepare");
    let rows: Vec<(String, String, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("query")
        .filter_map(Result::ok)
        .collect();
    for (id, state, holder) in &rows {
        assert!(
            matches!(
                state.as_str(),
                "pending"
                    | "running"
                    | "waiting-for-user"
                    | "waiting-for-external"
                    | "paused"
                    | "cancelled"
                    | "completed"
                    | "failed"
                    | "dead-lettered"
                    | "needs-verification"
            ),
            "{point}: task {id} is in the impossible state {state:?}"
        );
        if state == "running" {
            assert!(
                holder.is_some(),
                "{point}: task {id} is running with no owner"
            );
        }
    }

    // An effect may legitimately be unresolved -- that is TP-12's honest answer --
    // but it must never be silently absent while the task claims success.
    let unaccounted: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tasks t
              WHERE t.state = 'completed'
                AND EXISTS (SELECT 1 FROM task_attempts a WHERE a.task_id = t.id)
                AND NOT EXISTS (SELECT 1 FROM task_effects e WHERE e.task_id = t.id);",
            [],
            |r| r.get(0),
        )
        .expect("query");
    assert_eq!(
        unaccounted, 0,
        "{point}: a completed task with an attempt and no effect record"
    );
}

// -------------------------------------------------------------- the test cases

#[test]
fn a_crash_before_any_write_leaves_a_usable_database() {
    let d = dir("before-write");
    let db = db_in(&d);
    let ready = d.join("ready");
    kill_at("before-write", &db, &ready);
    assert_coherent_after_crash(&db, "before-write");
    // Nothing was written, so there is nothing to recover.
    let mut e = open_engine(&db);
    assert_eq!(e.all_tasks().expect("tasks").len(), 0);
    assert_eq!(e.recover(NOW).expect("recover"), 0);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_crash_after_enqueue_leaves_the_task_durable_and_reclaimable() {
    // TP-1: an accepted task must never vanish, however the process died.
    let d = dir("after-enqueue");
    let db = db_in(&d);
    kill_at("after-enqueue", &db, &d.join("ready"));
    assert_coherent_after_crash(&db, "after-enqueue");

    let mut e = open_engine(&db);
    let t = e
        .task(&tid("fault-task"))
        .expect("read")
        .expect("the task must exist");
    assert_eq!(t.state, TaskState::Pending);
    assert_eq!(t.attempts, 0);
    // And it is immediately claimable by the next process.
    let Claim::Claimed(claimed) = e.claim("next", NOW).expect("claim") else {
        panic!("the task must be reclaimable after the crash");
    };
    assert_eq!(claimed.id, tid("fault-task"));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_crash_after_claim_leaves_an_orphaned_lease_that_recovery_reclaims() {
    // TP-4: after an unclean shutdown, no task may be left `running` with a dead
    // owner. The lease had *not* expired -- the crash is what orphaned it.
    let d = dir("after-claim");
    let db = db_in(&d);
    kill_at("after-claim", &db, &d.join("ready"));

    let mut e = open_engine(&db);
    let before = e.task(&tid("fault-task")).expect("read").expect("present");
    assert_eq!(before.state, TaskState::Running, "the claim was durable");
    assert_eq!(before.lease_holder.as_deref(), Some("victim"));
    let lease_ms = before
        .lease_expires_at_ms
        .expect("a claimed task has a lease");
    assert!(
        lease_ms > NOW,
        "the lease had not expired when the process died"
    );

    // Recovery immediately, without waiting for expiry.
    assert_eq!(e.recover(NOW).expect("recover"), 1);
    let after = e.task(&tid("fault-task")).expect("read").expect("present");
    assert_eq!(after.state, TaskState::Pending);
    assert!(
        after.lease_holder.is_none(),
        "the dead owner must be cleared"
    );
    assert_eq!(e.live_leases(NOW).expect("live"), 0);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_crash_after_the_effect_reserves_leaves_the_outcome_explicitly_unknown() {
    // TP-12. The remote call may or may not have happened; the ledger row says
    // "unresolved", which is the honest state. What must not happen is the row
    // disappearing and the task claiming a clean success.
    let d = dir("after-effect");
    let db = db_in(&d);
    kill_at("after-effect-reserved", &db, &d.join("ready"));
    assert_coherent_after_crash(&db, "after-effect-reserved");

    let e = open_engine(&db);
    let repo = orxnud_store::task_repo::TaskRepository::new_readonly(e.conn());
    let effects = repo.effects_for(&tid("fault-task")).expect("effects");
    assert_eq!(effects.len(), 1, "the reservation must be durable");
    assert_eq!(
        effects[0].status, "pending",
        "and unresolved, not fabricated as a result"
    );
    assert!(
        !repo
            .all_effects_resolved(&tid("fault-task"))
            .expect("resolved?")
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_crash_after_the_commit_but_before_the_ack_leaves_a_terminal_task() {
    // The case that makes TP-12 necessary. The effect happened and the database
    // says so; the process that was about to report it does not exist. Recovery
    // must not retry it, because the row is terminal.
    let d = dir("after-complete");
    let db = db_in(&d);
    kill_at("after-complete-before-ack", &db, &d.join("ready"));
    assert_coherent_after_crash(&db, "after-complete-before-ack");

    let mut e = open_engine(&db);
    let t = e.task(&tid("fault-task")).expect("read").expect("present");
    assert_eq!(
        t.state,
        TaskState::Completed,
        "the committed transition survived"
    );
    assert!(t.effect_observed, "and the effect is recorded");
    // Recovery must not hand it out again: retrying would duplicate the effect.
    assert_eq!(e.recover(NOW).expect("recover"), 0);
    assert_eq!(
        e.claim("next", NOW).expect("claim"),
        Claim::Empty,
        "a terminal task must not be re-claimed"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn every_interruption_point_leaves_the_database_coherent() {
    // The table-driven version, so adding a point to `POINTS` cannot skip the
    // coherence assertions.
    for point in POINTS {
        let d = dir(&format!("table-{point}"));
        let db = db_in(&d);
        kill_at(point, &db, &d.join("ready"));
        assert_coherent_after_crash(&db, point);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[test]
fn repeated_crashes_at_the_same_point_never_lose_a_task() {
    // Run the same interruption several times against one database. A durability
    // property that holds once is not a durability property.
    let d = dir("repeat");
    let db = db_in(&d);
    for round in 0..3 {
        let ready = d.join(format!("ready-{round}"));
        kill_at("after-claim", &db, &ready);
        assert_coherent_after_crash(&db, "after-claim");
        let mut e = open_engine(&db);
        assert!(
            e.task(&tid("fault-task")).expect("read").is_some(),
            "round {round}: the task was lost"
        );
        e.recover(NOW).expect("recover");
    }
    // And the attempt history shows the retries, so nothing was silently dropped.
    let e = open_engine(&db);
    let repo = orxnud_store::task_repo::TaskRepository::new_readonly(e.conn());
    let attempts = repo.attempts_for(&tid("fault-task")).expect("attempts");
    assert!(
        attempts.len() >= 3,
        "each crash should leave an attempt: {attempts:?}"
    );
    for a in &attempts {
        assert!(
            a.finished_at_ms.is_some(),
            "an interrupted attempt must be closed: {a:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_crash_never_produces_a_duplicate_side_effect() {
    // The master property's second half: no unauthorised *or* duplicated effect.
    // The dedupe ledger is what makes this hold, and it must hold across crashes.
    let d = dir("dup-effect");
    let db = db_in(&d);
    kill_at("after-effect-reserved", &db, &d.join("ready"));

    let key = DurableEngine::idempotency_key(&tid("fault-task"), "external-call", "initial");
    {
        let mut e = open_engine(&db);
        assert!(
            !e.reserve_effect(&key, &tid("fault-task"), 1, 2, "external-call", false, NOW)
                .expect("reserve"),
            "the reservation from the killed process must still block a re-dispatch"
        );
        // Which is why the retry must go to verification rather than retrying.
        assert!(
            !e.all_effects_resolved(&tid("fault-task"))
                .expect("unresolved")
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_child_entry_point_is_harmless_without_the_environment() {
    // `#[ignore]`d but must still be safe to run: no env means no work, so invoking
    // the binary by hand does nothing surprising.
    assert!(
        std::env::var_os(ENV_POINT).is_none(),
        "the parent must not set this"
    );
    fault_child_entry_point();
}
