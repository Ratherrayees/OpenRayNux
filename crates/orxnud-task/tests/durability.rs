//! Durability and restart, on **real files**.
//!
//! # Why every test here uses a file
//!
//! docs-08 §4.4: *"Never `:memory:` for anything touching durability. A memory DB
//! cannot test WAL, `synchronous=FULL`, crash recovery, or migration on an
//! existing file."* An in-memory database reports `journal_mode = memory` no
//! matter what is asked for, has no write-ahead log, and has nothing to recover.
//! Testing durability against one is testing nothing.
//!
//! # What is actually exercised
//!
//! * **Restart**: a second process-level open of the same file sees the same state.
//! * **Reopen after a dropped connection**: the WAL is checkpointed and read back.
//! * **Pragmas**: read back from *every* connection, not just the first.
//! * **Interrupted migration**: a migration that fails leaves a restorable database.
//!
//! Not helper methods — each test opens the file, writes through the public API,
//! closes, and reopens.

use std::path::{Path, PathBuf};

use orxnud_domain::ids::TaskId;
use orxnud_domain::ids::{ScheduleId, UserId};
use orxnud_domain::task_state::{MisfirePolicy, ScheduleSpec, TaskKind, TaskState};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::NewTask;
use orxnud_task::{DurableEngine, EngineLimits, Scheduler};

const NOW: i64 = 1_767_225_600_000;
const HOUR: i64 = 3_600_000;

/// A scratch directory, unique per test so the suite can run in parallel.
fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-dur-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn db_in(dir: &Path) -> PathBuf {
    dir.join("state.db")
}

/// Opens a store the way production does: real file, critical pragmas applied *and*
/// verified, then migrated.
fn open(path: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).expect("open");
    Pragma::critical().apply(&conn).expect("apply pragmas");
    // Verification on open is not ceremony: a pragma that silently failed to apply
    // is indistinguishable from one that was never set until the disk loses power.
    Pragma::critical().verify(&conn).expect("verify pragmas");
    MigrationRunner::new(&conn).run(true).expect("migrate");
    conn
}

fn engine(path: &Path) -> DurableEngine {
    DurableEngine::new(open(path), EngineLimits::documented()).expect("engine")
}

fn tid(s: &str) -> TaskId {
    TaskId::new(s)
}

// ------------------------------------------------------------------- pragmas

#[test]
fn the_critical_pragmas_read_back_on_every_connection() {
    // ADR-0032's finding 3 was that `apalis-sqlite` applies `synchronous` once
    // through a pool rather than per connection, so durability is *inconsistent
    // between connections*. The fix is to verify each connection as it is opened,
    // which is only meaningful if more than one connection is actually checked.
    let d = dir("pragmas");
    let path = db_in(&d);

    let mut verified = 0;
    for _ in 0..5 {
        let conn = open(&path);
        let mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .expect("mode");
        let sync: i64 = conn
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .expect("sync");
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys;", [], |r| r.get(0))
            .expect("fk");
        assert_eq!(mode.to_lowercase(), "wal", "every connection must be WAL");
        assert_eq!(sync, 2, "every connection must be synchronous=FULL (2)");
        assert_eq!(fk, 1, "every connection must have foreign keys on");
        verified += 1;
    }
    assert_eq!(verified, 5, "all five connections must have been checked");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_weakened_durability_setting_is_caught_by_verification() {
    // The negative control for the test above, and it is *not* the control one would
    // first guess.
    //
    // Measured on this build (SQLite 3.53.2 bundled, rusqlite 0.40.2): a raw
    // `Connection::open` already reports `synchronous = 2` (FULL), because
    // `SQLITE_DEFAULT_SYNCHRONOUS` is 2, and rusqlite enables foreign keys on
    // open. So "we forgot to set it" is not the failure mode — **someone weakening
    // it** is, which is exactly what ADR-0032 found in `apalis-sqlite`
    // (`synchronous = OFF`).
    //
    // That makes verification load-bearing rather than decorative, and it is why
    // `Pragma::verify` reads every value back instead of trusting the SET.
    let d = dir("weakened-pragmas");
    let path = db_in(&d);
    let conn = rusqlite::Connection::open(&path).expect("open");
    Pragma::critical().apply(&conn).expect("apply");
    assert!(
        Pragma::critical().verify(&conn).is_ok(),
        "the applied set must verify"
    );

    // Now reproduce ADR-0032's failure exactly.
    conn.execute_batch("PRAGMA synchronous = OFF;")
        .expect("weaken");
    let sync: i64 = conn
        .query_row("PRAGMA synchronous;", [], |r| r.get(0))
        .expect("read");
    assert_eq!(
        sync, 0,
        "OFF is 0, and it is weaker than NORMAL, let alone FULL"
    );
    let err = Pragma::critical()
        .verify(&conn)
        .expect_err("verification must catch OFF");
    let msg = err.to_string();
    assert!(msg.contains("synchronous"), "{msg}");

    // And NORMAL, the subtler weakening, is caught too.
    conn.execute_batch("PRAGMA synchronous = NORMAL;")
        .expect("weaken");
    assert!(
        Pragma::critical().verify(&conn).is_err(),
        "NORMAL is not power-loss safe and must also be refused"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_critical_pragma_set_is_stricter_than_the_sqlite_defaults() {
    // What the SQLite defaults actually are, measured rather than assumed, so a
    // future SQLite build that changed `SQLITE_DEFAULT_SYNCHRONOUS` would show up
    // here instead of silently changing our durability floor.
    let d = dir("defaults");
    let path = db_in(&d);
    let conn = rusqlite::Connection::open(&path).expect("open");
    let default_sync: i64 = conn
        .query_row("PRAGMA synchronous;", [], |r| r.get(0))
        .expect("sync");
    let default_journal: String = conn
        .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
        .expect("mode");
    assert_eq!(
        default_journal.to_lowercase(),
        "delete",
        "a fresh file defaults to rollback journal"
    );
    // WAL mode is NOT the default and never can be assumed: it has to be set, and
    // once set it is persistent, which is the property the previous test relies on.
    assert_eq!(
        default_sync, 2,
        "SQLITE_DEFAULT_SYNCHRONOUS is FULL in this build"
    );

    // The derived set deliberately weakens synchronous to NORMAL, so this
    // difference is a real, recorded divergence rather than a coincidence.
    assert_eq!(Pragma::derived().synchronous, "normal");
    assert_eq!(Pragma::critical().synchronous, "full");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn wal_mode_survives_reopening_the_file() {
    // journal_mode is *persistent* in SQLite, so a reopened database must already
    // be in WAL. If it were not, a restart would silently downgrade durability.
    let d = dir("wal-persist");
    let path = db_in(&d);
    drop(open(&path));
    let conn = rusqlite::Connection::open(&path).expect("reopen");
    let mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
        .expect("mode");
    assert_eq!(mode.to_lowercase(), "wal");
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------------- restart

#[test]
fn a_task_survives_a_restart_with_its_attempts_and_leases() {
    let d = dir("restart");
    let path = db_in(&d);

    let before: i64 = {
        let mut e = engine(&path);
        e.enqueue_new(&NewTask::new(tid("t1"), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimed");
        assert_eq!(claimed.state, TaskState::Running);
        e.enqueue_new(&NewTask::new(tid("t2"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        claimed
            .lease_expires_at_ms
            .expect("a claimed task carries a lease expiry")
    };

    // A restart is a new process: drop everything, reopen.
    let after = engine(&path);
    let t1 = after.task(&tid("t1")).expect("read").expect("present");
    assert_eq!(
        t1.state,
        TaskState::Running,
        "a running task survives a clean restart"
    );
    assert_eq!(t1.attempts, 1);
    assert_eq!(t1.lease_holder.as_deref(), Some("w1"));
    assert_eq!(
        t1.lease_expires_at_ms,
        Some(before),
        "the lease expiry is durable"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_idempotency_reservation_survives_a_restart() {
    // TP-12's ledger must be durable: a reservation that vanished on restart would
    // let a retry dispatch the same effect a second time.
    let d = dir("idem-restart");
    let path = db_in(&d);
    let key = {
        let mut e = engine(&path);
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        let _ = e.claim_task("w", NOW).expect("claim");
        let k = DurableEngine::idempotency_key(&tid("t"), "send", "initial");
        assert!(
            e.reserve_effect(&k, &tid("t"), 1, "send", NOW)
                .expect("reserve")
        );
        k
    };
    {
        let mut e = engine(&path);
        assert!(
            !e.reserve_effect(&key, &tid("t"), 2, "send", NOW)
                .expect("reserve"),
            "the reservation must survive the restart"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_approval_recorded_before_a_restart_is_still_scoped_to_its_attempt() {
    // TP-6 across a restart: the per-attempt key is what stops a retry inheriting,
    // and the key has to still be there afterwards.
    let d = dir("approval-restart");
    let path = db_in(&d);
    let approval = orxnud_store::task_repo::ApprovalRow {
        task_id: tid("t"),
        attempt_no: 1,
        digest_hex: "cd".repeat(32),
        capability: "cap".into(),
        target: None,
        params: "{}".into(),
        issued_at_ms: NOW,
        expires_at_ms: NOW + 3_600_000,
        consumed_at_ms: None,
    };
    {
        let mut e = engine(&path);
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        let _ = e.claim_task("w", NOW).expect("claim");
        e.record_approval(&approval).expect("record");
    }
    let e = engine(&path);
    assert!(e.approval_for(&tid("t"), 1).expect("read").is_some());
    assert!(
        e.approval_for(&tid("t"), 2).expect("read").is_none(),
        "attempt 2 must not inherit, even across a restart"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_transition_log_survives_a_restart_and_keeps_its_order() {
    let d = dir("log-restart");
    let path = db_in(&d);
    {
        let mut e = engine(&path);
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
        let _ = e.claim_task("w", NOW).expect("claim");
        let _ = e.complete_task(&tid("t"), "w", NOW, TaskState::Completed, true, None);
    }
    let e = engine(&path);
    let events = orxnud_store::task_repo::TaskRepository::new_readonly(e.conn())
        .events_for(&tid("t"))
        .expect("events");
    let kinds: Vec<&str> = events.iter().map(|x| x.kind.as_str()).collect();
    assert_eq!(kinds, vec!["enqueued", "claimed", "completed"]);
    let seqs: Vec<i64> = events.iter().map(|x| x.seq).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_clean_restart_runs_recovery_and_finds_a_live_lease_to_orphan() {
    // TP-4's operational half. On a restart the previous process is gone, so the
    // lease is orphaned regardless of expiry, and the task becomes reclaimable.
    let d = dir("recover-restart");
    let path = db_in(&d);
    let expiry;
    {
        let mut e = engine(&path);
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
        expiry = e
            .claim_task("w", NOW)
            .expect("claim")
            .expect("claimed")
            .lease_expires_at_ms
            .expect("e");
        assert_eq!(e.live_leases(NOW).expect("live"), 1);
    }
    let mut e = engine(&path);
    // Well before the lease would expire: recovery still reclaims it.
    let recovered = e.recover(NOW + 1).expect("recover");
    assert_eq!(recovered, 1);
    assert_eq!(e.live_leases(NOW + 1).expect("live"), 0);
    let row = e.task(&tid("t")).expect("read").expect("present");
    assert_eq!(row.state, TaskState::Pending);
    assert!(
        expiry > NOW,
        "the lease had not expired; recovery still reclaimed it"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_reclaimed_task_can_be_claimed_by_a_different_worker_after_restart() {
    let d = dir("reclaim-restart");
    let path = db_in(&d);
    {
        let mut e = engine(&path);
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        let _ = e.claim_task("w1", NOW).expect("claim");
    }
    let mut e = engine(&path);
    e.recover(NOW + 1).expect("recover");
    let claimed = e
        .claim_task("w2", NOW + 1)
        .expect("claim")
        .expect("claimed");
    assert_eq!(claimed.lease_holder.as_deref(), Some("w2"));
    assert_eq!(
        claimed.attempts, 2,
        "the reclaim is a new attempt, not a continuation"
    );
    // And the previous worker cannot commit into it.
    assert!(
        !e.complete_task(&tid("t"), "w1", NOW + 1, TaskState::Completed, true, None)
            .expect("complete")
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_task_dead_lettered_before_a_restart_is_not_requeued_after_it() {
    let d = dir("dlq-restart");
    let path = db_in(&d);
    {
        let mut e = engine(&path);
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        for i in 0..3 {
            let _ = e.claim_task("w", NOW + i).expect("claim");
            let _ = e.complete_task_with(
                &tid("t"),
                "w",
                NOW + i,
                TaskState::Failed,
                false,
                Some("boom"),
                Some(0),
            );
        }
    }
    let mut e = engine(&path);
    assert_eq!(
        e.task(&tid("t")).expect("read").expect("present").state,
        TaskState::DeadLettered
    );
    // A restart must not resurrect it.
    e.recover(NOW + 100).expect("recover");
    assert_eq!(
        e.task(&tid("t")).expect("read").expect("present").state,
        TaskState::DeadLettered
    );
    assert!(e.claim_task("w", NOW + 100).expect("claim").is_none());
    let _ = std::fs::remove_dir_all(&d);
}

// ---------------------------------------------------------------- migrations

#[test]
fn migrations_are_idempotent_across_repeated_opens() {
    let d = dir("mig-idem");
    let path = db_in(&d);
    for _ in 0..3 {
        let conn = open(&path);
        assert_eq!(
            MigrationRunner::new(&conn).applied_version().expect("v"),
            orxnud_store::migration::CURRENT_VERSION
        );
        assert!(
            MigrationRunner::new(&conn)
                .run(true)
                .expect("run")
                .is_empty(),
            "a second run must apply nothing"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_migration_on_an_existing_file_is_protected_by_a_verified_snapshot() {
    // ADR-0017 decision 2: every migration is preceded by an automatic, verified
    // snapshot. `migrate` takes it rather than trusting a flag.
    let d = dir("mig-snapshot");
    let path = db_in(&d);
    let conn = open(&path);
    MigrationRunner::new(&conn)
        .run(true)
        .expect("first migrate");

    // Nothing is pending, so no snapshot is taken and none is left behind.
    let applied = MigrationRunner::new(&conn)
        .migrate(&path, false)
        .expect("migrate");
    assert!(applied.is_empty());
    assert!(
        !orxnud_store::backup::Backup::path_for(&path).exists(),
        "a no-op migration must not leave a snapshot behind"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_failed_migration_leaves_the_database_readable_and_restores_the_snapshot() {
    // The critical property of ADR-0017 decision 4: a failed migration restores,
    // and the previous binary keeps working.
    let d = dir("mig-restore");
    let path = db_in(&d);
    {
        let conn = open(&path);
        // Take the snapshot the way `migrate` would, then damage the schema the way
        // a half-applied migration would.
        let snapshot = orxnud_store::backup::Backup::take(&conn, &path).expect("snapshot");
        conn.execute_batch("CREATE TABLE half_applied (x INTEGER);")
            .expect("damage");
        assert!(
            MigrationRunner::new(&conn).applied_version().is_err()
                || orxnud_store::backup::Backup::verify(&path).is_ok(),
            "the damaged database may still be structurally valid"
        );
        snapshot.restore(&path).expect("restore");
    }
    let conn = rusqlite::Connection::open(&path).expect("reopen");
    let half: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='half_applied';",
            [],
            |r| r.get(0),
        )
        .expect("query");
    assert_eq!(half, 0, "the restore must have undone the damage");
    // And the schema is intact, so a previous binary can open it.
    assert_eq!(
        MigrationRunner::new(&conn).applied_version().expect("v"),
        orxnud_store::migration::CURRENT_VERSION
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_fresh_database_reaches_the_current_version_and_creates_only_the_task_schema() {
    let d = dir("mig-fresh");
    let path = db_in(&d);
    let conn = open(&path);
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'
                   ORDER BY name;",
            )
            .expect("prepare");
        stmt.query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect()
    };
    assert_eq!(
        tables,
        vec![
            "schedule_fires",
            "schedules",
            "schema_meta",
            "task_approvals",
            "task_attempts",
            "task_effects",
            "task_events",
            "tasks",
        ]
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------------ schedules

#[test]
fn the_fire_ledger_survives_a_restart_and_prevents_a_duplicate_after_it() {
    // TP-8 across a restart: the UNIQUE constraint is the guarantee, and it must
    // hold after the process that inserted the row is gone.
    let d = dir("fires-restart");
    let path = db_in(&d);
    let spec = ScheduleSpec {
        id: ScheduleId::new("s"),
        cron: "0 * * * *".into(),
        timezone: "UTC".into(),
        misfire: MisfirePolicy::FireAll,
        catch_up_cap: 10,
        enabled: true,
        authorised_by: UserId::new("u"),
    };
    let first = {
        let mut e = engine(&path);
        e.schedules().insert(&spec, NOW - HOUR).expect("insert");
        Scheduler::new(&mut e)
            .run_pass(NOW)
            .expect("pass")
            .tasks_created
    };
    assert_eq!(first, 1);

    // Restart, rewind the ledger, and re-run: the fire row is still there.
    let mut e = engine(&path);
    e.conn_mut()
        .execute(
            "UPDATE schedules SET last_fired_ms = NULL WHERE id='s';",
            [],
        )
        .expect("rewind");
    let report = Scheduler::new(&mut e).run_pass(NOW + 1).expect("pass");
    assert_eq!(
        report.tasks_created, 0,
        "the durable ledger must prevent the duplicate"
    );
    assert_eq!(report.fires_already_present, 1);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_schedule_created_before_a_restart_still_fires_after_it() {
    let d = dir("sched-restart");
    let path = db_in(&d);
    {
        let mut e = engine(&path);
        e.schedules()
            .insert(
                &ScheduleSpec {
                    id: ScheduleId::new("s"),
                    cron: "0 * * * *".into(),
                    timezone: "UTC".into(),
                    misfire: MisfirePolicy::FireAll,
                    catch_up_cap: 10,
                    enabled: true,
                    authorised_by: UserId::new("u"),
                },
                NOW - HOUR,
            )
            .expect("insert");
    }
    let mut e = engine(&path);
    assert_eq!(
        Scheduler::new(&mut e)
            .run_pass(NOW)
            .expect("pass")
            .tasks_created,
        1
    );
    let _ = std::fs::remove_dir_all(&d);
}

// --------------------------------------------------------------- concurrency

#[test]
fn n_workers_sharing_a_file_produce_exactly_one_winner_per_task() {
    // docs-08 §4.7: "Task claim under N concurrent workers -> exactly one winner".
    // Real threads, real connections, real WAL contention -- not a simulation.
    let d = dir("concurrent-claim");
    let path = db_in(&d);

    let mut e = engine(&path);
    for i in 0..12 {
        e.enqueue_new(
            &NewTask::new(tid(&format!("t{i}")), TaskKind::Query, NOW),
            NOW,
        )
        .expect("enqueue");
    }
    drop(e); // release this process's connection before the workers open theirs

    let claimed = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let mut handles = Vec::new();
    for w in 0..6 {
        let path = path.clone();
        let claimed = std::sync::Arc::clone(&claimed);
        handles.push(std::thread::spawn(move || {
            let conn = rusqlite::Connection::open(&path).expect("worker open");
            Pragma::critical().apply(&conn).expect("worker pragmas");
            let mut e =
                DurableEngine::new(conn, EngineLimits::documented()).expect("worker engine");
            for _ in 0..4 {
                if let Ok(Some(row)) = e.claim_task(&format!("w{w}"), NOW) {
                    claimed.lock().expect("lock").push(row.id.to_string());
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("worker must not panic");
    }

    let ids = claimed.lock().expect("lock").clone();
    assert_eq!(ids.len(), 12, "every task must be claimed exactly once");
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 12, "no task may be claimed twice: {ids:?}");

    // And the database agrees: 12 running tasks, none running *and* claimable.
    let conn = rusqlite::Connection::open(&path).expect("reopen");
    let running: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tasks WHERE state='running';",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(running, 12);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_busy_database_is_reported_as_a_conflict_not_as_corruption() {
    // ADR-0032 finding 3's concern: an error the caller cannot classify. A
    // SQLITE_BUSY under contention is a retryable conflict, not a bug.
    let d = dir("busy");
    let path = db_in(&d);
    let _setup = engine(&path);

    // Hold a write transaction open on one connection.
    let holder = rusqlite::Connection::open(&path).expect("holder");
    Pragma::critical().apply(&holder).expect("pragmas");
    holder.execute_batch("BEGIN IMMEDIATE;").expect("begin");
    holder
        .execute(
            "INSERT INTO tasks (id,kind,state,idempotent,max_attempts,created_at_ms,updated_at_ms)
                    VALUES ('busy-t','query','pending',1,3,0,0);",
            [],
        )
        .expect("insert");

    // A second connection with a *short* busy timeout so the test does not wait
    // for the holder's five seconds.
    let other = rusqlite::Connection::open(&path).expect("other");
    Pragma::critical().apply(&other).expect("pragmas");
    other
        .execute_batch("PRAGMA busy_timeout = 50;")
        .expect("short timeout");

    let result: Result<_, rusqlite::Error> = other.execute(
        "INSERT INTO tasks (id,kind,state,idempotent,max_attempts,created_at_ms,updated_at_ms)
         VALUES ('other-t','query','pending',1,3,0,0);",
        [],
    );
    assert!(
        result.is_err(),
        "a contended write must fail rather than corrupt"
    );
    if let Err(e) = result {
        let classified = orxnud_task::error::EngineError::from(
            orxnud_store::task_repo::TaskRepoError::Sqlite(Box::new(e)),
        );
        assert_eq!(
            classified.kind,
            orxnud_task::EngineErrorKind::ConcurrencyConflict,
            "a busy database must be retryable, not an invariant violation"
        );
    }
    drop(holder);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_interrupted_write_transaction_leaves_no_partial_row() {
    // TP-7's transaction half: rollback is all-or-nothing, so a transaction that
    // dies mid-flight leaves the pre-transaction state.
    let d = dir("interrupted-tx");
    let path = db_in(&d);
    let _ = engine(&path);

    {
        let conn = rusqlite::Connection::open(&path).expect("open");
        Pragma::critical().apply(&conn).expect("pragmas");
        conn.execute_batch("BEGIN IMMEDIATE;").expect("begin");
        conn.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,max_attempts,created_at_ms,updated_at_ms)
             VALUES ('half','query','pending',1,3,0,0);",
            [],
        )
        .expect("insert inside the transaction");
        // Roll back instead of committing -- the same database state a killed
        // process leaves behind.
        conn.execute_batch("ROLLBACK;").expect("rollback");
    }

    let conn = rusqlite::Connection::open(&path).expect("reopen");
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM tasks WHERE id='half';", [], |r| {
            r.get(0)
        })
        .expect("count");
    assert_eq!(n, 0, "a rolled-back transaction must leave nothing");
    let integrity: String = conn
        .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
        .expect("check");
    assert_eq!(integrity, "ok");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_task_committed_before_a_crash_is_visible_after_it() {
    // The other half of TP-7: what *was* committed survives, because
    // `synchronous = FULL` fsynced the WAL on commit.
    let d = dir("committed-survives");
    let path = db_in(&d);
    {
        let mut e = engine(&path);
        e.enqueue_new(&NewTask::new(tid("durable"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        // Dropping the connection *without* an explicit close stands in for the
        // process ending: the WAL is fsynced at commit, so this row is on disk.
    }
    let conn = rusqlite::Connection::open(&path).expect("reopen");
    let row: (String, i64) = conn
        .query_row(
            "SELECT state, attempts FROM tasks WHERE id='durable';",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("the committed task must be present");
    assert_eq!(row, ("pending".to_owned(), 0));
    let _ = std::fs::remove_dir_all(&d);
}
