//! DATA-004: a pre-migration snapshot must be bound to the database it protects.
//!
//! # The defect
//!
//! `MigrationRunner::migrate` reuses a file already at the canonical pre-migration
//! path (`<db>.pre-migration.bak`) instead of taking a new one, because it may be
//! the only good copy of a database whose last migration failed. It adopts that
//! file on the strength of [`orxnud_store::backup::Backup::verify`] alone, and
//! `verify` establishes only that the file **is a database**: it opens, it passes
//! `integrity_check`, it has a `schema_meta` and that table has rows.
//!
//! None of that says the file is a snapshot *of this database*. A file that is a
//! perfectly good SQLite database belonging to something else — a different
//! installation, a database restored from elsewhere, a template state directory
//! copied onto a machine — passes every one of those checks.
//!
//! Measured before this change, end to end: the foreign file was adopted as the
//! recovery obligation, the migration failed, and the recovery the caller then
//! performed installed the **foreign** database's rows over the live database.
//! The live database's own row was gone, replaced by the other database's, and
//! the store reported success throughout.
//!
//! # What these tests drive
//!
//! The production path: [`orxnud_store::migration::MigrationRunner::migrate`],
//! with a database whose next migration **fails** so that the reuse branch is
//! the one under test, and with the recovery the caller performs on the
//! obligation the migration hands back.
//!
//! The assertions are about **observable durable state** — which rows the live
//! database holds afterwards — and not about an error variant, so each one
//! compiles and **fails** against the defective implementation rather than
//! failing to build.

use std::path::{Path, PathBuf};

use orxnud_platform_fs::OsIdentity;
use orxnud_store::backup::Backup;
use orxnud_store::migration::{MigrationError, MigrationRunner};

/// A scratch directory, unique per test name and per call.
fn dir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let d = std::env::temp_dir().join(format!(
        "orxnud-snapshot-provenance-{}-{tag}-{nonce}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

/// A **version-1** database whose next migration fails, holding one row of its own.
///
/// The store's own failed-migration fixture: migration 2 creates the `tasks`
/// table, and a `tasks` table that is already there makes it fail. A failure is
/// what keeps a snapshot *retained* rather than discarded, and a retained
/// snapshot is the only thing a caller can be handed as a recovery obligation.
fn stage_a_database_with_a_row_of_its_own(path: &Path) {
    let c = rusqlite::Connection::open(path).expect("open");
    c.execute_batch(
        "CREATE TABLE schema_meta (
             version INTEGER PRIMARY KEY,
             name TEXT NOT NULL,
             applied_at INTEGER NOT NULL);
         INSERT INTO schema_meta (version, name, applied_at) VALUES (1, 'schema_meta', 0);
         CREATE TABLE tasks (id TEXT PRIMARY KEY);
         INSERT INTO tasks (id) VALUES ('live-1');",
    )
    .expect("stage a version-1 database whose next migration must fail");
}

/// A **different** database: fully migrated, with a row of its own.
///
/// This is the file that ends up at the canonical snapshot path. It is a
/// complete, valid, healthy SQLite database — nothing about it is corrupt, and
/// `Backup::verify` accepts it. What it is not is a snapshot of the live
/// database.
fn build_a_foreign_database(path: &Path) {
    let c = rusqlite::Connection::open(path).expect("open");
    MigrationRunner::new(&c)
        .migrate(path, &OsIdentity)
        .expect("migrate the other database to the current schema");
    c.execute(
        "INSERT INTO tasks (id, kind, state, idempotent, max_attempts, created_at_ms, updated_at_ms)
         VALUES ('foreign-1', 'foreign', 'pending', 0, 1, 0, 0);",
        [],
    )
    .expect("give the other database a row of its own");
}

/// The ids in the `tasks` table, comma-separated.
fn task_ids(path: &Path) -> String {
    let c = rusqlite::Connection::open(path).expect("open");
    c.query_row(
        "SELECT COALESCE(GROUP_CONCAT(id), '<none>') FROM tasks;",
        [],
        |r| r.get(0),
    )
    .expect("read the tasks table")
}

/// Plants a snapshot of `other` at the canonical pre-migration path of `db`.
///
/// Through the production snapshot path, so the planted file is a real,
/// transactionally consistent copy — the same shape a snapshot left behind by an
/// earlier build would have.
fn plant_a_snapshot_of_another_database_at(db: &Path, other: &Path) -> PathBuf {
    let canonical = Backup::path_for(db);
    let c = rusqlite::Connection::open(other).expect("open the other database");
    let snapshot = Backup::take(&c, other, &OsIdentity).expect("snapshot the other database");
    std::fs::copy(snapshot.path(), &canonical).expect("plant the snapshot");
    canonical
}

/// **A snapshot of another database is not adopted as this database's recovery
/// point, and the live database keeps its own row.**
///
/// The whole finding, end to end. The foreign file is a valid database, so every
/// structural check passes; what it fails is the one check that matters — that
/// the snapshot belongs to *this* database.
///
/// The recovery is performed here exactly as a caller would perform it, because
/// the damage is done by the recovery and not by the migration: the migration
/// hands back an obligation, and the caller restores it.
#[test]
fn a_snapshot_of_another_database_is_not_adopted_as_the_recovery_point() {
    let d = dir("foreign");
    let db = d.join("state.db");
    stage_a_database_with_a_row_of_its_own(&db);

    let other = d.join("other.db");
    build_a_foreign_database(&other);
    let canonical = plant_a_snapshot_of_another_database_at(&db, &other);
    assert!(
        canonical.exists(),
        "precondition: the foreign file must be at the canonical path"
    );

    let c = rusqlite::Connection::open(&db).expect("reopen");
    let err = MigrationRunner::new(&c)
        .migrate(&db, &OsIdentity)
        .expect_err("the staged migration must fail");
    drop(c);

    // If the migration hands back an obligation, the caller restores it. That
    // restore is what installs the other database's content over this one.
    let obligation = match &err {
        MigrationError::RecoveryRequired { snapshot, .. } => Some(snapshot.clone()),
        _ => None,
    };
    if let Some(snapshot) = &obligation {
        orxnud_store::migration::recover_from_snapshot(&db, snapshot, &OsIdentity)
            .expect("the caller performs the recovery it was handed");
    }

    assert_eq!(
        task_ids(&db),
        "live-1",
        "the live database must still hold its own row: a snapshot of another database was \
         adopted as the recovery point and the recovery installed the other database's rows \
         over this one"
    );
    assert_ne!(
        obligation.as_deref(),
        Some(canonical.as_path()),
        "a file that is not a snapshot of this database must not be handed back as its \
         recovery obligation"
    );
    assert!(
        canonical.exists(),
        "the refused file must be left where it was: it is not this store's to delete"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// **A snapshot of this database is adopted.** The control for the test above.
///
/// Without this, "the migration refuses" would be indistinguishable from "the
/// migration refuses everything", and a blanket refusal would be a different
/// defect rather than a fix. The snapshot here is the one the production path
/// itself took, so it is the recovery point for the very migration that failed.
#[test]
fn a_snapshot_of_this_database_is_still_adopted() {
    let d = dir("own");
    let db = d.join("state.db");
    stage_a_database_with_a_row_of_its_own(&db);

    // The first migration fails and leaves the snapshot it took behind.
    {
        let c = rusqlite::Connection::open(&db).expect("reopen");
        let err = MigrationRunner::new(&c)
            .migrate(&db, &OsIdentity)
            .expect_err("the staged migration must fail");
        drop(c);
        assert!(
            matches!(err, MigrationError::RecoveryRequired { .. }),
            "precondition: the first migration must leave a recovery obligation, got {err:?}"
        );
    }
    let canonical = Backup::path_for(&db);
    assert!(
        canonical.exists(),
        "precondition: the failed migration must have left its snapshot behind"
    );

    // The second attempt finds that snapshot at the canonical path and reuses
    // it: it may be the only good copy of the pre-migration state.
    let c = rusqlite::Connection::open(&db).expect("reopen");
    let err = MigrationRunner::new(&c)
        .migrate(&db, &OsIdentity)
        .expect_err("the staged migration must fail again");
    drop(c);

    match &err {
        MigrationError::RecoveryRequired { snapshot, .. } => assert_eq!(
            snapshot, &canonical,
            "the snapshot of this database must be the one handed back as the recovery obligation"
        ),
        other => panic!("expected RecoveryRequired, got {other:?}"),
    }
    assert_eq!(
        task_ids(&db),
        "live-1",
        "the live database must be untouched by a refused migration"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// The provenance identity a database carries, read straight from its table.
fn identity_of(path: &Path) -> Option<String> {
    let c = rusqlite::Connection::open(path).expect("open");
    c.query_row(
        "SELECT id FROM database_identity WHERE singleton = 1;",
        [],
        |r| r.get::<_, String>(0),
    )
    .ok()
}

/// **The refusal is classified, and it names both identities.**
///
/// The classification is part of the contract: the caller has to be able to tell
/// "the file at the canonical path belongs to another installation" from "the
/// platform could not make the file private" and from "the file is reachable
/// through a second name". They are three different facts with three different
/// remedies, and an operator sent to the wrong one is being sent to the wrong
/// place.
#[test]
fn a_foreign_snapshot_is_refused_as_a_provenance_mismatch() {
    let d = dir("mismatch");
    let db = d.join("state.db");
    stage_a_database_with_a_row_of_its_own(&db);

    let other = d.join("other.db");
    build_a_foreign_database(&other);
    let canonical = plant_a_snapshot_of_another_database_at(&db, &other);

    let c = rusqlite::Connection::open(&db).expect("reopen");
    let err = MigrationRunner::new(&c)
        .migrate(&db, &OsIdentity)
        .expect_err("the staged migration must fail");
    drop(c);

    let (expected, found) = match &err {
        MigrationError::SnapshotProvenanceMismatch {
            path,
            expected,
            found,
        } => {
            assert_eq!(
                path, &canonical,
                "the refusal must name the file it left in place"
            );
            (expected.clone(), found.clone())
        }
        other => panic!("expected a provenance mismatch, got {other:?}"),
    };
    assert_eq!(
        expected,
        identity_of(&db).expect("this database must carry an identity"),
        "the refusal must name this database's identity"
    );
    assert_eq!(
        found,
        identity_of(&other).expect("the other database must carry an identity"),
        "the refusal must name the identity the file actually carries"
    );
    assert_ne!(expected, found, "the two identities must be different");
    assert!(
        canonical.exists(),
        "the refused file must be left where it was: it is not this store's to delete"
    );
    assert_eq!(
        task_ids(&db),
        "live-1",
        "the live database must be untouched by a refused migration"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// **A snapshot that carries no identity at all is refused.**
///
/// The file was written by a build that predates the provenance table, or it is
/// a foreign database. The file alone cannot tell those apart, and neither can
/// this code, so the file is refused and left where it is.
#[test]
fn a_snapshot_with_no_identity_is_refused() {
    let d = dir("legacy");
    let db = d.join("state.db");
    stage_a_database_with_a_row_of_its_own(&db);

    // A snapshot of this database taken before it was ever given an identity:
    // the shape a build that predates the provenance table leaves behind.
    let canonical = {
        let c = rusqlite::Connection::open(&db).expect("open");
        let snapshot = Backup::take(&c, &db, &OsIdentity).expect("take a snapshot");
        snapshot.path().to_path_buf()
    };
    assert_eq!(
        identity_of(&canonical),
        None,
        "precondition: the planted file must carry no identity"
    );

    let c = rusqlite::Connection::open(&db).expect("reopen");
    let err = MigrationRunner::new(&c)
        .migrate(&db, &OsIdentity)
        .expect_err("the staged migration must fail");
    drop(c);

    match &err {
        MigrationError::SnapshotProvenanceMissing { path } => assert_eq!(
            path, &canonical,
            "the refusal must name the file it left in place"
        ),
        other => panic!("expected a missing-provenance refusal, got {other:?}"),
    }
    assert!(
        canonical.exists(),
        "the refused file must be left where it was: it may be the only good copy"
    );
    assert_eq!(
        task_ids(&db),
        "live-1",
        "the live database must be untouched by a refused migration"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// **A database keeps its identity, and two databases do not share one.**
///
/// The identity is what a snapshot is bound to, so it has to survive the
/// migrations that follow it — and it has to be *different* for different
/// databases, or the binding says nothing.
#[test]
fn an_identity_is_stable_for_a_database_and_distinct_between_databases() {
    let d = dir("identity");
    let first = d.join("first.db");
    let second = d.join("second.db");

    for path in [&first, &second] {
        let c = rusqlite::Connection::open(path).expect("open");
        MigrationRunner::new(&c)
            .migrate(path, &OsIdentity)
            .expect("migrate");
    }
    let first_id = identity_of(&first).expect("the first database must carry an identity");
    let second_id = identity_of(&second).expect("the second database must carry an identity");
    assert_ne!(
        first_id, second_id,
        "two databases must not share an identity, or a snapshot of one could be adopted \
         as the other's"
    );

    // A second migration attempt must not change it. The identity is created
    // once and then carried: a database whose identity changed would make every
    // snapshot it had ever taken unbindable.
    let c = rusqlite::Connection::open(&first).expect("reopen");
    MigrationRunner::new(&c)
        .migrate(&first, &OsIdentity)
        .expect("a second migration attempt");
    drop(c);
    assert_eq!(
        identity_of(&first).as_deref(),
        Some(first_id.as_str()),
        "the identity must not change when the database is migrated again"
    );

    let _ = std::fs::remove_dir_all(&d);
}
