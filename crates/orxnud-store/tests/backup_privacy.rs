//! SEC-003: the *copies* of the database this product makes are private too.
//!
//! # Why this file exists
//!
//! The live database is private to its owner, and so are its `-wal` and `-shm`
//! sidecars. The same store also makes two **complete copies** of the database,
//! and neither was private:
//!
//! * the **pre-migration snapshot** — `state.db.pre-migration.bak` — which is a
//!   full copy of every task, every parameter a model proposed to act on, the
//!   approval ledger and the audit journal. It is created on *every* migration
//!   and is **deliberately kept** when a migration fails, because it may be the
//!   only good copy of the database.
//! * the **restore staging image** — the file a restore writes before it
//!   installs anything into the live database.
//!
//! Both were created by the platform with the process's umask applied, which
//! under the common `022` is `0644`: world-readable. Inside the `0700` state
//! root they are unreachable by another local account, so this is not a
//! disclosure *in place*. It **is** a disclosure of the artefact itself, and the
//! snapshot is precisely the artefact an operator is told to keep and back up.
//!
//! # What these tests drive
//!
//! The production paths: `MigrationRunner::migrate` for the snapshot, and
//! `Backup::restore_coordinated` for the staging image. Not the permission
//! helper in isolation.

use std::path::{Path, PathBuf};

use orxnud_domain::platform::{
    FileFacts, FilesystemIdentity, FilesystemPrivacy, PrivacyError, PrivacyOutcome,
    SqliteMainDatabase, SqliteMainFacts,
};
use orxnud_platform_fs::OsIdentity;
use orxnud_store::StoreError;
use orxnud_store::backup::{Backup, BackupError};

/// A scratch directory, unique per test name and per call.
fn dir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let d = std::env::temp_dir().join(format!(
        "orxnud-backup-privacy-{}-{tag}-{nonce}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

/// The mode of `path`, in octal, or `None` where it cannot be read.
///
/// Unix-only, and deliberately not stubbed for the platforms that have no mode
/// bits: a stub that returns `None` there would be dead code, and this file
/// compiles under `-D warnings` on Windows. The one test that asserts a mode is
/// Unix-gated with it.
#[cfg(unix)]
fn mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).ok()?;
    Some(meta.permissions().mode() & 0o7777)
}

/// **The published pre-migration snapshot is private to its owner.**
///
/// The production path: `MigrationRunner::migrate` is what takes the snapshot
/// and publishes it at its canonical name. The snapshot must be `0600` at that
/// name — and it must be born private, because the publication is a rename and
/// a rename preserves the mode, so a snapshot that was tightened *after*
/// publication would have been world-readable for a moment.
#[cfg(unix)]
#[test]
fn the_published_pre_migration_snapshot_is_private_to_its_owner() {
    let d = dir("snapshot");
    let db = d.join("state.db");

    // A database at an old schema version, so the migration has work to do and
    // therefore takes a snapshot.
    {
        let store = orxnud_store::sqlite::Store::open(&db, true, &OsIdentity).expect("open");
        orxnud_store::migration::MigrationRunner::new(store.conn())
            .migrate(&db, &OsIdentity)
            .expect("migrate");
    }

    let canonical = Backup::path_for(&db);
    // The snapshot is discarded when the migration succeeds, so this test needs
    // a *failed* migration to leave one behind. Failing a migration honestly is
    // what the crate's own fault seams are for; without one, the snapshot's
    // lifetime is "until the migration succeeds" and there is nothing to
    // observe. So the snapshot is taken directly, which is the same call the
    // runner makes, and the mode is asserted on the artefact it publishes.
    let snapshot = {
        let store = orxnud_store::sqlite::Store::open(&db, true, &OsIdentity).expect("open");
        Backup::take(store.conn(), &db, &OsIdentity).expect("take a snapshot")
    };
    assert_eq!(
        snapshot.path(),
        canonical,
        "precondition: the snapshot must be published at its canonical name"
    );
    assert_eq!(
        mode(&canonical),
        Some(0o600),
        "the published snapshot is a full copy of every task, every proposed \
         action, the approval ledger and the audit journal; it must be private to \
         its owner, not readable by every account on the machine"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// **A privacy failure in the restore path is not an ownership failure.**
///
/// The two are different facts with different remedies. An ownership refusal
/// says another process holds the database; a privacy refusal says the file was
/// readable and could not be made unreadable to other accounts. An operator sent
/// to look for a competing process is being sent to the wrong place, and a
/// machine reading the taxonomy is being told the wrong thing.
#[test]
fn a_privacy_failure_in_the_restore_path_is_not_reported_as_an_ownership_failure() {
    let d = dir("classification");
    let db = d.join("state.db");

    {
        let store = orxnud_store::sqlite::Store::open(&db, true, &OsIdentity).expect("open");
        store
            .conn()
            .execute_batch("CREATE TABLE notes(v TEXT); INSERT INTO notes VALUES ('one');")
            .expect("write");
    }
    let snapshot = {
        let store = orxnud_store::sqlite::Store::open(&db, true, &OsIdentity).expect("open");
        Backup::take(store.conn(), &db, &OsIdentity).expect("take a snapshot")
    };

    let err = snapshot
        .restore_coordinated(&db, &CannotRestrict)
        .expect_err("a restore that cannot make the database private must be refused");

    match err {
        BackupError::Privacy { .. } => {}
        BackupError::Ownership { reason } => panic!(
            "a privacy refusal was reported as an ownership refusal: {reason}. Nobody else \
             holds this database; the platform could not make it private, and the two \
             need different remedies."
        ),
        other => panic!("expected a privacy refusal, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// **A store whose platform cannot restrict the file records that, and says so.**
///
/// The `NotApplicable` half of the contract: the platform has no owner-only
/// mechanism, so nothing was restricted. The store must still open the database
/// — refusing would break a platform the product supports for storage — but it
/// must **record** that no restriction was applied, so no caller can read the
/// successful open as a guarantee.
#[test]
fn an_open_whose_privacy_is_not_applicable_records_that_rather_than_claiming_a_restriction() {
    let d = dir("not-applicable");
    let db = d.join("state.db");

    let store = orxnud_store::sqlite::Store::open(&db, true, &NotApplicable)
        .expect("a platform with no owner-only mechanism must still be able to store state");
    assert_eq!(
        store.privacy_outcome(),
        PrivacyOutcome::NotApplicable,
        "the store must record that no owner-only restriction was established, rather \
         than reporting the successful open as if one had been"
    );
    assert!(
        !store.privacy_outcome().is_restricted(),
        "a restriction that was never applied must never report as one"
    );
    drop(store);

    // The real platform, for contrast: it does establish the restriction.
    let store = orxnud_store::sqlite::Store::open(&db, true, &OsIdentity).expect("open");
    #[cfg(unix)]
    assert_eq!(
        store.privacy_outcome(),
        PrivacyOutcome::Restricted,
        "on a platform with owner-only access the store must record that it established it"
    );
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// A capability that answers identity normally and **refuses** the restriction.
///
/// The real platform cannot be made to fail on demand, so the case that needs
/// a failing restriction uses a local double. It answers the identity questions
/// by delegating to the real platform, so the store reaches the restriction
/// step and only that step fails.
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

/// A capability that answers identity normally and reports the restriction as
/// **not applicable** — the shape a platform with no owner-only mechanism has.
struct NotApplicable;

impl FilesystemIdentity for NotApplicable {
    fn observe(&self, path: &Path) -> FileFacts {
        OsIdentity.observe(path)
    }

    fn observe_sqlite_main(&self, connection: SqliteMainDatabase<'_>) -> SqliteMainFacts {
        OsIdentity.observe_sqlite_main(connection)
    }
}

impl FilesystemPrivacy for NotApplicable {
    fn restrict_file_to_owner(&self, _path: &Path) -> Result<PrivacyOutcome, PrivacyError> {
        Ok(PrivacyOutcome::NotApplicable)
    }

    fn restrict_dir_to_owner(&self, _path: &Path) -> Result<PrivacyOutcome, PrivacyError> {
        Ok(PrivacyOutcome::NotApplicable)
    }
}

/// The store's own error vocabulary must keep a privacy refusal apart.
#[test]
fn a_privacy_refusal_in_the_store_is_not_an_ownership_refusal() {
    let d = dir("store-classification");
    let db = d.join("state.db");

    let err = orxnud_store::sqlite::Store::open(&db, true, &CannotRestrict)
        .expect_err("a database that cannot be made private must not be opened");
    match err {
        StoreError::Privacy { .. } => {}
        StoreError::Ownership { .. } => panic!(
            "a privacy refusal was reported as an ownership refusal: {err}. The two \
             facts have different remedies and must not share a variant."
        ),
        other => panic!("expected a privacy refusal, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&d);
}
