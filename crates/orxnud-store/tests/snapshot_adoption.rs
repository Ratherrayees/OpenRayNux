//! SEC-003 F-1: an **adopted** pre-migration snapshot is made private before it is
//! accepted as the recovery point.
//!
//! # The defect
//!
//! A snapshot *taken* by this code is restricted to `0600` before it is published, so
//! it is born private. A snapshot left behind by an **earlier** build is not: it is
//! whatever the platform created, which under the common `022` is `0644` —
//! world-readable.
//!
//! `MigrationRunner::migrate` reuses a snapshot already at the conventional path,
//! because it may be the only good copy of a database whose previous migration
//! failed. Before this change the reuse **adopted that file unchanged**, so the
//! upgrade population kept a world-readable copy of every task, every proposed
//! action, the approval ledger and the audit journal in the one place the operator
//! is told to keep as their recovery point.
//!
//! # What these tests drive
//!
//! The production path: [`orxnud_store::migration::MigrationRunner::migrate`] with a
//! database whose next migration **fails**, so the adopted snapshot is *retained*
//! and its mode can be observed. The store already has a deterministic
//! failed-migration fixture — a version-1 database whose migration 2 collides — and
//! this file uses the same shape.
//!
//! Not the permission helper in isolation: the property is about what an *adoption*
//! leaves on disk.

use std::path::{Path, PathBuf};

use orxnud_domain::platform::{
    FileFacts, FilesystemIdentity, FilesystemPrivacy, PrivacyError, PrivacyOutcome,
    SqliteMainDatabase, SqliteMainFacts,
};
use orxnud_platform_fs::OsIdentity;
use orxnud_store::backup::Backup;
use orxnud_store::migration::{MigrationError, MigrationRunner};

/// The mode of `path`, in octal, or `None` where the platform has no mode bits.
#[cfg(unix)]
fn mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).ok()?;
    Some(meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn mode(_path: &Path) -> Option<u32> {
    None
}

/// Sets `path`'s mode. A no-op where the platform has no mode bits.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// A scratch directory, unique per test name and per call.
fn dir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let d = std::env::temp_dir().join(format!(
        "orxnud-snapshot-privacy-{}-{tag}-{nonce}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

/// A **version-1** database whose migration 2 fails, because the `tasks` table it
/// creates is already there.
///
/// The store's own failed-migration fixture. A failure is what keeps the snapshot
/// *retained* rather than discarded, and a retained snapshot is the only thing a
/// caller can be handed as a recovery obligation.
fn stage_a_database_whose_next_migration_fails(path: &Path) {
    let c = rusqlite::Connection::open(path).expect("open");
    c.execute_batch(
        "CREATE TABLE schema_meta (
             version INTEGER PRIMARY KEY,
             name TEXT NOT NULL,
             applied_at INTEGER NOT NULL);
         INSERT INTO schema_meta (version, name, applied_at) VALUES (1, 'schema_meta', 0);
         CREATE TABLE tasks (id TEXT PRIMARY KEY);",
    )
    .expect("stage a version-1 database whose migration 2 must fail");
}

/// Stages a version-1 database whose next migration fails, **and runs the
/// production migration once** so that the database carries its provenance
/// identity and a snapshot of it is left at the canonical path.
///
/// # Why the first run is part of the fixture
///
/// The adoption now refuses a snapshot that cannot be shown to belong to *this*
/// database, and a snapshot taken with [`Backup::take`] directly from a
/// database that has never been migrated carries no identity at all — so it is
/// refused for that reason before the privacy and alias rules are ever reached.
/// That refusal is a different finding and it is proved in
/// `tests/snapshot_provenance.rs`.
///
/// Running the production migration once produces the shape this file is about:
/// a snapshot left at the canonical path by a build that had already given the
/// database its identity. Everything this file asserts is about what the
/// *adoption* then does with that file.
fn stage_a_failed_migration_with_its_snapshot(path: &Path) -> PathBuf {
    stage_a_database_whose_next_migration_fails(path);
    let c = rusqlite::Connection::open(path).expect("open");
    let err = MigrationRunner::new(&c)
        .migrate(path, &OsIdentity)
        .expect_err("the staged migration must fail");
    drop(c);
    match &err {
        MigrationError::RecoveryRequired { snapshot, .. } => snapshot.clone(),
        other => panic!("expected RecoveryRequired, got {other:?}"),
    }
}

/// **An adopted `0644` snapshot is restricted to `0600` before it is retained.**
///
/// The upgrade path: a snapshot left behind by a build that did not restrict it is
/// world-readable, and adopting it unchanged kept it that way. The adoption must
/// make it private, and the file that is handed back as the recovery obligation
/// must be the private one.
#[cfg(unix)]
#[test]
fn an_adopted_world_readable_snapshot_is_made_private_before_it_is_retained() {
    let d = dir("adopted");
    let db = d.join("state.db");
    // The production path leaves a snapshot of this database at the canonical
    // path, which is the shape the reuse branch finds.
    let canonical = stage_a_failed_migration_with_its_snapshot(&db);
    set_mode(&canonical, 0o644);
    assert_eq!(
        mode(&canonical),
        Some(0o644),
        "precondition: the snapshot must start world-readable, or this test proves nothing"
    );
    assert!(
        Backup::verify(&canonical).is_ok(),
        "precondition: the snapshot must verify, or the reuse branch is not the one under test"
    );

    // The production path. The migration fails, so the snapshot is retained.
    let c = rusqlite::Connection::open(&db).expect("reopen");
    let err = MigrationRunner::new(&c)
        .migrate(&db, &OsIdentity)
        .expect_err("the staged migration must fail");
    drop(c);

    let retained = match &err {
        MigrationError::RecoveryRequired { snapshot, .. } => snapshot.clone(),
        other => panic!("expected RecoveryRequired, got {other:?}"),
    };
    assert_eq!(
        retained, canonical,
        "the adopted snapshot must be the one handed back as the recovery obligation"
    );
    assert!(
        retained.exists(),
        "and it must still exist: the only copy of the old state is at {}",
        retained.display()
    );
    assert_eq!(
        mode(&retained),
        Some(0o600),
        "an adopted snapshot must be made private to its owner before it is accepted as \
         the recovery point; a snapshot left by an earlier build is world-readable, and \
         adopting it unchanged keeps a world-readable copy of every task, every proposed \
         action, the approval ledger and the audit journal"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// **A privacy failure refuses the adoption, and is classified as a privacy failure.**
///
/// Two things are pinned. The snapshot is **not** accepted as though it had been
/// secured, and the migration does not proceed. And the failure is **not** reported
/// as an ownership or alias failure: nobody else holds this snapshot, and an
/// operator sent to look for a competing process is being sent to the wrong place.
///
/// The snapshot is also **left exactly where it was**, at its original mode: it may
/// be the only good copy of the database, and overwriting it to work around a
/// permission failure would destroy the recovery point the refusal protects.
#[test]
fn a_privacy_failure_refuses_the_adoption_and_preserves_the_snapshot() {
    let d = dir("privacy-refusal");
    let db = d.join("state.db");
    let canonical = stage_a_failed_migration_with_its_snapshot(&db);
    #[cfg(unix)]
    set_mode(&canonical, 0o644);
    let before = canonical.exists();

    let c = rusqlite::Connection::open(&db).expect("reopen");
    let err = MigrationRunner::new(&c)
        .migrate(&db, &CannotRestrict)
        .expect_err("a snapshot that cannot be made private must not be adopted");
    drop(c);

    match &err {
        MigrationError::SnapshotPrivacy { path, .. } => {
            assert_eq!(
                path, &canonical,
                "the refusal must name the snapshot it left in place"
            );
        }
        MigrationError::SnapshotAliasUnsafe { .. } => panic!(
            "a privacy refusal was reported as an alias refusal: {err}. The snapshot has one \
             name and nobody else holds it; what failed is that it could not be made private."
        ),
        MigrationError::RecoveryRequired { .. } => panic!(
            "the migration proceeded past a failed restriction: {err}. The snapshot was \
             accepted as though it had been secured."
        ),
        other => panic!("expected a privacy refusal, got {other:?}"),
    }
    assert!(
        before && canonical.exists(),
        "the snapshot must be left exactly where it was: it may be the only good copy"
    );
    #[cfg(unix)]
    assert_eq!(
        mode(&canonical),
        Some(0o644),
        "the refusal must not have rewritten the snapshot it was protecting"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// **A snapshot reachable through a second name is refused, and is not modified.**
///
/// The restriction changes the mode of an *inode*. An inode reachable under a
/// second name would have that other name's object changed as well, so the store's
/// own link-count rule refuses it — the same rule that protects the database
/// protects the copy of it.
#[cfg(unix)]
#[test]
fn a_snapshot_reachable_through_a_second_name_is_refused_and_left_alone() {
    let d = dir("two-names");
    let db = d.join("state.db");
    let canonical = stage_a_failed_migration_with_its_snapshot(&db);
    let alias = d.join("snapshot-alias.db");
    std::fs::hard_link(&canonical, &alias).expect("hard link the snapshot");
    set_mode(&canonical, 0o644);
    assert_eq!(mode(&canonical), Some(0o644), "precondition");

    let c = rusqlite::Connection::open(&db).expect("reopen");
    let err = MigrationRunner::new(&c)
        .migrate(&db, &OsIdentity)
        .expect_err("a snapshot with a second name must not be adopted");
    drop(c);

    match &err {
        MigrationError::SnapshotAliasUnsafe { path, .. } => {
            assert_eq!(
                path, &canonical,
                "the refusal must name the snapshot it left in place"
            );
        }
        other => panic!("expected an alias-safety refusal, got {other:?}"),
    }
    assert_eq!(
        mode(&canonical),
        Some(0o644),
        "the refused snapshot must not have been modified: restricting an inode with two \
         names would have changed the mode of the object under the other name too"
    );
    assert!(
        canonical.exists(),
        "and it must still exist: the refusal protects it"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// **A snapshot that disappears while it is being secured is taken afresh.**
///
/// The canonical snapshot path is shared by every process migrating the same
/// database: one of them finishing successfully removes the file the others are
/// looking at. An open that failed on that would be failing over a file that is
/// no longer there, and reporting it as a *privacy* failure would send an
/// operator to look for a permission problem that does not exist.
///
/// The capability below removes the file and *then* refuses to restrict it,
/// which is the race in one deterministic step.
#[test]
fn a_snapshot_that_disappears_while_it_is_being_secured_is_taken_afresh() {
    let d = dir("vanished");
    let db = d.join("state.db");
    let canonical = stage_a_failed_migration_with_its_snapshot(&db);

    let c = rusqlite::Connection::open(&db).expect("reopen");
    let err = MigrationRunner::new(&c)
        .migrate(&db, &RemovesThenRefuses)
        .expect_err("the staged migration must fail");
    drop(c);

    match &err {
        MigrationError::RecoveryRequired { snapshot, .. } => assert_eq!(
            snapshot, &canonical,
            "the fresh snapshot must be the one handed back as the recovery obligation"
        ),
        other => panic!("expected RecoveryRequired, got {other:?}"),
    }
    assert!(
        canonical.exists(),
        "a fresh snapshot must have been published in place of the one that vanished"
    );
    let c = rusqlite::Connection::open(&db).expect("reopen");
    assert_eq!(
        MigrationRunner::new(&c).applied_version().expect("version"),
        1,
        "the migration must have failed without applying anything"
    );
    drop(c);

    let _ = std::fs::remove_dir_all(&d);
}

/// A capability that **removes** the canonical snapshot and then refuses to
/// restrict it.
///
/// The removal is what makes the case deterministic: the file is gone by the
/// time the store looks, which is exactly the state a competing migrator leaves
/// behind when it finishes and discards the snapshot it took. Every other
/// restriction — the snapshot's staging copy, the database itself — is answered
/// by the real platform, so the store reaches the adoption and only the
/// adoption fails.
struct RemovesThenRefuses;

impl RemovesThenRefuses {
    /// Whether `path` is the canonical pre-migration snapshot path.
    ///
    /// The staging copy the backup path creates has a different name, and it
    /// must not be removed: the case under test is about the file at the
    /// canonical path, not about the copy being made.
    fn is_the_canonical_snapshot(path: &Path) -> bool {
        path.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".pre-migration.bak"))
    }
}

impl FilesystemIdentity for RemovesThenRefuses {
    fn observe(&self, path: &Path) -> FileFacts {
        OsIdentity.observe(path)
    }

    fn observe_sqlite_main(&self, connection: SqliteMainDatabase<'_>) -> SqliteMainFacts {
        OsIdentity.observe_sqlite_main(connection)
    }
}

impl FilesystemPrivacy for RemovesThenRefuses {
    fn restrict_file_to_owner(&self, path: &Path) -> Result<PrivacyOutcome, PrivacyError> {
        if Self::is_the_canonical_snapshot(path) {
            let _ = std::fs::remove_file(path);
            return Err(PrivacyError::Unavailable {
                path: path.display().to_string(),
                reason: "the file was removed by a competing migrator".to_owned(),
            });
        }
        OsIdentity.restrict_file_to_owner(path)
    }

    fn restrict_dir_to_owner(&self, path: &Path) -> Result<PrivacyOutcome, PrivacyError> {
        OsIdentity.restrict_dir_to_owner(path)
    }
}

/// **A capability that answers identity normally and **refuses** the restriction.
///
/// The real platform cannot be made to fail on demand, so the case that needs a
/// failing restriction uses a local double. It answers the identity questions by
/// delegating to the real platform, so the store reaches the restriction step and
/// only that step fails.
struct CannotRestrict;

impl FilesystemIdentity for CannotRestrict {
    fn observe(&self, path: &Path) -> FileFacts {
        OsIdentity.observe(path)
    }

    fn observe_sqlite_main(&self, connection: SqliteMainDatabase<'_>) -> SqliteMainFacts {
        OsIdentity.observe_sqlite_main(connection)
    }
}

impl FilesystemPrivacy for CannotRestrict {
    fn restrict_file_to_owner(&self, path: &Path) -> Result<PrivacyOutcome, PrivacyError> {
        Err(PrivacyError::Unavailable {
            path: path.display().to_string(),
            reason: "this capability cannot restrict anything".to_owned(),
        })
    }

    fn restrict_dir_to_owner(&self, path: &Path) -> Result<PrivacyOutcome, PrivacyError> {
        Err(PrivacyError::Unavailable {
            path: path.display().to_string(),
            reason: "this capability cannot restrict anything".to_owned(),
        })
    }
}
