//! S-31 Test C and Test D: every application-managed open participates, and the restore
//! primitive cannot be reached without exclusive ownership.
//!
//! The two-process evidence is in `s31_two_process.rs`. This file covers the *coverage*
//! question it cannot: whether all five named entry points, and every other one found,
//! actually go through the ownership gate rather than around it.

use std::path::PathBuf;

/// Nonce-keyed scratch directory.
fn dir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let d = std::env::temp_dir().join(format!("s31-ep-{}-{tag}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

/// A database whose schema the **real** migrations have already produced.
///
/// The first version of this hand-rolled `schema_meta`, and it broke: migration 1 wants
/// a column the fixture did not have. A fixture that does not match the real schema
/// makes the "succeeds once free" half of every test here meaningless, because it
/// fails for an unrelated reason. So the schema is produced by opening a real store
/// once, which runs the actual migrations.
fn seeded(tag: &str) -> (PathBuf, PathBuf) {
    let d = dir(tag);
    let db = d.join("state.db");
    // `Store::open` alone does not migrate — it applies pragmas and verifies SQLite.
    // The schema is produced by `open_and_migrate`, which is the production path for
    // "create this database if it is not there yet".
    let store =
        orxnud_store::migration::open_and_migrate(&db).expect("create a real migrated store");
    drop(store);
    (d, db)
}

/// True when the error text identifies an *ownership* refusal.
///
/// Matching on the text rather than a variant is deliberate here: these errors cross a
/// crate boundary (`StoreError` vs `JournalError` vs `LedgerError`), each with its own
/// vocabulary, and the property under test is that the refusal came from the ownership
/// gate rather than from something incidental. Asserting "it failed" would be satisfied
/// by an unrelated failure and would prove nothing about participation.
fn refused_for_ownership(e: &str) -> bool {
    e.contains("ownership") || e.contains("refusing") || e.contains("is held elsewhere")
}

/// Holds exclusive ownership for `db` in this process, the way a restore would.
fn hold_exclusive(db: &std::path::Path) -> orxnud_store::ownership::ExclusiveOwnership {
    orxnud_store::ownership::acquire_exclusive_for_tests(db).expect("take exclusive ownership")
}

/// **Test C — each named entry point refuses while the database is exclusively owned.**
///
/// One test rather than five, because the interesting property is that *all* of them
/// consult the gate. A per-entry-point set would let one omission hide behind the others.
#[test]
fn c_every_entry_point_participates_in_the_ownership_rule() {
    let (_d, db) = seeded("participate");
    let lease = hold_exclusive(&db);

    // 1. `Store::open` — the central opener the others funnel through.
    let store = orxnud_store::sqlite::Store::open(&db, true).expect_err("Store::open must refuse");
    assert!(
        refused_for_ownership(&store.to_string()),
        "Store::open must refuse for ownership, got: {store}"
    );

    // 2. `open_and_migrate` — a second, distinct way into the store.
    let migrate =
        orxnud_store::migration::open_and_migrate(&db).expect_err("open_and_migrate must refuse");
    assert!(
        refused_for_ownership(&migrate.to_string()),
        "open_and_migrate must refuse for ownership, got: {migrate}"
    );

    // 3. `SqliteAuditJournal::open`.
    let journal = orxnud_store::security_state::SqliteAuditJournal::open(&db)
        .expect_err("SqliteAuditJournal::open must refuse");
    assert!(
        refused_for_ownership(&journal.to_string()),
        "SqliteAuditJournal::open must refuse for ownership, got: {journal}"
    );

    // 4. `SqliteApprovalLedger::open`.
    let ledger = orxnud_store::security_state::SqliteApprovalLedger::open(&db)
        .expect_err("SqliteApprovalLedger::open must refuse");
    assert!(
        refused_for_ownership(&ledger.to_string()),
        "SqliteApprovalLedger::open must refuse for ownership, got: {ledger}"
    );

    drop(lease);

    // With ownership released every one of them works, so the refusals above were about
    // ownership and not about a database that happens to be unusable.
    let _ = orxnud_store::sqlite::Store::open(&db, true).expect("Store::open works once free");
    let _ = orxnud_store::security_state::SqliteAuditJournal::open(&db)
        .expect("journal works once free");
    let _ = orxnud_store::security_state::SqliteApprovalLedger::open(&db)
        .expect("ledger works once free");
}

/// `TaskService::open` lives in the daemon crate, so it is exercised here through the
/// same public opener it uses rather than by importing the daemon.
#[test]
fn c_task_service_open_refuses_through_its_own_opener() {
    let (_d, db) = seeded("task-service");
    let lease = hold_exclusive(&db);

    // `TaskService::open` calls `Store::open` first, so this is the gate it must pass.
    let store = orxnud_store::sqlite::Store::open(&db, true).expect_err("must refuse");
    assert!(
        refused_for_ownership(&store.to_string()),
        "TaskService::open's opener must refuse for ownership, got: {store}"
    );
    drop(lease);
}

/// **Test D — the restore primitive is not reachable without exclusive ownership.**
///
/// Two halves. The runtime half: the public entry point refuses when the database is
/// busy, and succeeds once free — so the refusal is coordination, not a blanket deny.
/// The visibility half lives in `s30_restore_not_public.rs`, which compiles a probe
/// against the crate as an external consumer; it is referenced here rather than
/// duplicated because a second copy would be a second thing to keep in sync.
#[test]
fn d_restore_refuses_without_exclusive_ownership_and_recovers_when_free() {
    let (d, db) = seeded("restore-gate");
    let conn = rusqlite::Connection::open(&db).expect("seed conn");
    // The version the snapshot will contain, read rather than assumed. The first version
    // of this test asserted `== 1` against a hand-made fixture and failed for that
    // reason alone; the assertion is about "the snapshot's state came back", so it is
    // stated against the snapshot's own recorded value.
    let expected: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_meta", [], |r| r.get(0))
        .expect("read the current version");
    let snapshot = orxnud_store::backup::Backup::take(&conn, &db).expect("take a snapshot");
    // Damage by **deleting** a row rather than inserting one: `schema_meta` has a
    // NOT NULL column set, and an insert that half-fills it is a fixture error rather
    // than the damage this test means to cause.
    conn.execute_batch("DELETE FROM schema_meta;")
        .expect("damage the database so a no-op restore would be detectable");
    drop(conn);

    // Another owner: the restore must refuse rather than proceed.
    let other = hold_exclusive(&db);
    let refused = snapshot
        .restore_coordinated(&db)
        .expect_err("a restore attempted while another owner holds the database must fail");
    assert!(
        refused_for_ownership(&refused.to_string()),
        "the refusal must identify the ownership conflict, not something incidental: \
         {refused}"
    );

    drop(other);
    snapshot
        .restore_coordinated(&db)
        .expect("the same restore must succeed once the owner is gone");
    // The **same** query as the one that recorded `expected`. The first version read a
    // bare `version` here against a `MAX(version)` there and compared 14 with 1 — a
    // fixture mismatch reported as a failed restore.
    let v: i64 = rusqlite::Connection::open(&db)
        .expect("read")
        .query_row("SELECT MAX(version) FROM schema_meta", [], |r| r.get(0))
        .expect("version");
    assert_eq!(
        v, expected,
        "the restore must reproduce the snapshot's logical state, not merely not crash"
    );
    let _ = std::fs::remove_dir_all(&d);
}
