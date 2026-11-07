//! SEC-003: a database the store opens is private to its owner.
//!
//! # The defect this closes
//!
//! The platform creates a SQLite database with the process's umask applied. Under
//! the common `022` that is `0644`: **world-readable**. The database holds the
//! user's task text, the parameters a model proposed to act on, the approval
//! ledger and the hash-chained audit journal. The store created it, so the
//! store is the component that has to notice and correct it — and it did not.
//!
//! The correction is not "chmod the file". It is:
//!
//! * the file is restricted **through a descriptor**, so the object whose mode
//!   changes is the object that was opened, rather than whatever a name
//!   resolves to a moment later; and
//! * the open is **refused** when the restriction cannot be made, because a
//!   store that opened a world-readable database and carried on would hold the
//!   user's data in a file every other account on the machine can read.
//!
//! # What these tests drive
//!
//! The **production** open path — [`orxnud_store::Store::open`] with the real
//! [`orxnud_platform_fs::OsIdentity`] — against real files in a temporary
//! directory. Not the permission helper in isolation: the property is about
//! what an open leaves on disk, so the test has to open a database and then
//! look at the file.
//!
//! The one case that cannot be produced by a real filesystem — a platform that
//! can observe a file but cannot restrict it — uses a local capability that
//! refuses, and asserts that the open fails.
//!
//! # What these tests do not prove
//!
//! On Unix the mode bits are the guarantee; on Windows there are none, and the
//! restriction is a no-op that records the limit rather than pretending to have
//! happened (see `orxnud_platform_fs::restrict_file_to_owner`). The
//! directory-level guarantee — the state root at `0700` — is a **daemon**
//! property and is proved in `orxnud-daemon`'s `state_privacy` suite.

use std::path::{Path, PathBuf};

use orxnud_domain::platform::{
    FileFacts, FilesystemIdentity, FilesystemPrivacy, PrivacyError, PrivacyOutcome,
    SqliteMainDatabase, SqliteMainFacts,
};
use orxnud_platform_fs::OsIdentity;
use orxnud_store::sqlite::Store;

/// A scratch directory, unique per test name and per call.
fn dir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let d = std::env::temp_dir().join(format!(
        "orxnud-privacy-{}-{tag}-{nonce}",
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
/// compiles under `-D warnings` on Windows. Every test that asserts a mode is
/// Unix-gated with it.
#[cfg(unix)]
fn mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).ok()?;
    Some(meta.permissions().mode() & 0o7777)
}

/// Sets `path`'s mode. Unix-only, and not stubbed, for the reason `mode` is not.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
}

/// **A newly opened database is private to its owner.**
///
/// The database does not exist before the open — the platform creates it — so
/// this is the *creation* case, and it is the one a fresh install hits.
#[cfg(unix)]
#[test]
fn a_newly_opened_database_is_private_to_its_owner() {
    let d = dir("fresh");
    let db = d.join("state.db");

    {
        let store = Store::open(&db, true, &OsIdentity).expect("open");
        assert!(
            db.exists(),
            "the open must have created the database, or this test proves nothing"
        );
        assert_eq!(
            mode(&db),
            Some(0o600),
            "a database the platform just created must be restricted to its owner before \
             the open returns; the platform creates it at the umask's mode, which is \
             world-readable under the common 022"
        );
        drop(store);
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// **The sidecars are private too.**
///
/// `-wal` and `-shm` are created by the platform when WAL mode is applied, with
/// the same umask-derived mode as the database. A `-wal` file holds the user's
/// rows, so a private database beside a world-readable log is half private.
///
/// SQLite materialises them on the first **write**, not on the mode change, so
/// the test writes before it looks.
#[cfg(unix)]
#[test]
fn the_sidecars_of_an_open_database_are_private_too() {
    let d = dir("sidecars");
    let db = d.join("state.db");

    {
        let store = Store::open(&db, true, &OsIdentity).expect("open");
        store
            .conn()
            .execute_batch("CREATE TABLE notes(v TEXT); INSERT INTO notes VALUES ('one');")
            .expect("a write, so the sidecars are materialised");
        for suffix in ["-wal", "-shm"] {
            let sidecar = d.join(format!("state.db{suffix}"));
            assert!(
                sidecar.exists(),
                "precondition: {suffix} must exist once the database has been written to"
            );
            assert_eq!(
                mode(&sidecar),
                Some(0o600),
                "{suffix} holds the user's rows and must be restricted to its owner"
            );
        }
        drop(store);
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// **An existing world-readable database is tightened when it is opened.**
///
/// The upgrade case: a database created by an earlier build, or by any other
/// program, arrives world-readable. Opening it must correct that, because
/// "the file was already there" is not a reason to leave it readable.
#[cfg(unix)]
#[test]
fn an_existing_world_readable_database_is_tightened_on_open() {
    let d = dir("existing");
    let db = d.join("state.db");

    // A database that exists, and is readable by everyone.
    {
        let store = Store::open(&db, true, &OsIdentity).expect("open");
        drop(store);
    }
    set_mode(&db, 0o644);
    assert_eq!(
        mode(&db),
        Some(0o644),
        "precondition: the database must start world-readable, or this test proves nothing"
    );

    {
        let store = Store::open(&db, true, &OsIdentity).expect("open");
        assert_eq!(
            mode(&db),
            Some(0o600),
            "opening a world-readable database must tighten it; the file was already there \
             and that is not a reason to leave it readable"
        );
        drop(store);
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// **An existing world-readable sidecar is tightened too.**
///
/// The sidecar is only present while a connection is open, so the tightening is
/// observed by a second open of the same database while the first is still
/// holding it — a shared lease, which the store supports.
#[cfg(unix)]
#[test]
fn an_existing_world_readable_sidecar_is_tightened_on_open() {
    let d = dir("existing-sidecar");
    let db = d.join("state.db");
    let wal = d.join("state.db-wal");

    let first = Store::open(&db, true, &OsIdentity).expect("open");
    first
        .conn()
        .execute_batch("CREATE TABLE notes(v TEXT); INSERT INTO notes VALUES ('one');")
        .expect("a write, so the sidecars are materialised");
    assert!(wal.exists(), "precondition: the -wal must exist");
    set_mode(&wal, 0o644);
    assert_eq!(
        mode(&wal),
        Some(0o644),
        "precondition: it must start readable"
    );

    // A second open of the same database, with the first still holding it.
    let second = Store::open(&db, true, &OsIdentity).expect("second open");
    assert_eq!(
        mode(&wal),
        Some(0o600),
        "a world-readable sidecar must be tightened when the database is opened again"
    );

    drop(first);
    drop(second);
    let _ = std::fs::remove_dir_all(&d);
}

/// **The restriction holds whatever the ambient umask is.**
///
/// The creation mode a platform applies is the requested mode **masked by the
/// umask**, so a `0700` request can arrive as `0000` — stricter than asked
/// for, and useless. The mode is therefore set explicitly rather than
/// inherited, and this test proves it by running the same open under a
/// permissive umask in a child process.
///
/// The umask is changed in the **child**, not in this process: it is
/// process-global state, and a test that changed it in-process would race
/// every other test in the binary.
#[cfg(unix)]
#[test]
fn the_restriction_holds_under_a_permissive_umask() {
    const MARKER: &str = "ORXNUD_PRIVACY_UMASK_CHILD";
    if std::env::var_os(MARKER).is_none() {
        // Re-run this test in a child whose umask is `000`.
        let exe = std::env::current_exe().expect("the test binary");
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("umask 000; exec \"$@\"")
            .arg("sh")
            .arg(&exe)
            .args(std::env::args().skip(1))
            .env(MARKER, "1")
            .status()
            .expect("run the child");
        assert!(
            status.success(),
            "the child, which opened the database under umask 000, must have passed; \
             it did not: {status}"
        );
        return;
    }

    // The child. Everything below runs under umask `000`, which is the most
    // permissive setting there is: without an explicit restriction, the
    // platform would create the database at `0666`.
    let d = dir("umask");
    let db = d.join("state.db");
    {
        let store = Store::open(&db, true, &OsIdentity).expect("open");
        assert_eq!(
            mode(&db),
            Some(0o600),
            "the restriction must be explicit, not inherited from the umask: under umask \
             000 the platform creates the file at 0666"
        );
        drop(store);
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// **A capability that cannot restrict the file refuses the open.**
///
/// The failure mode this pins: a store that opened the database anyway and
/// recorded that the mode was not what was wanted. That is a disclosure with a
/// note attached, and it is the outcome the refusal exists to prevent.
#[test]
fn an_open_that_cannot_restrict_the_database_is_refused() {
    let d = dir("refuses");
    let db = d.join("state.db");

    let err = Store::open(&db, true, &CannotRestrict)
        .expect_err("a database that cannot be made private must not be opened");
    let text = err.to_string();
    assert!(
        text.contains("privacy") || text.contains("owner"),
        "the refusal must say the database could not be made private; got: {text}"
    );
    assert!(
        !text.contains("another process") && !text.contains("second name"),
        "a privacy refusal must not be reported as an ownership or alias refusal: nobody \
         else has this database, and sending an operator looking for a second name is \
         the wrong diagnosis. Got: {text}"
    );

    // The refusal released the lease: the real capability can open the file the
    // failed attempt created.
    let store = Store::open(&db, true, &OsIdentity).expect("the refusal must release the lease");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// **The alias protections still hold after the restriction.**
///
/// The permission change must not have weakened the check that a database
/// reachable through a second name is refused. This is the production open
/// path, with a real hard link.
#[cfg(unix)]
#[test]
fn a_database_reachable_through_a_second_name_is_still_refused() {
    let d = dir("alias");
    let db = d.join("state.db");
    {
        let store = Store::open(&db, true, &OsIdentity).expect("open");
        drop(store);
    }
    let alias = d.join("alias.db");
    std::fs::hard_link(&db, &alias).expect("hard link the database");

    let err = Store::open(&db, true, &OsIdentity)
        .expect_err("a database reachable through two names must still be refused");
    let text = err.to_string();
    assert!(
        text.contains("names") || text.contains("alias") || text.contains("ownership"),
        "the alias refusal must still be the one that fires; got: {text}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// A capability that answers identity normally and **refuses** the restriction.
///
/// The real platform cannot be made to fail on demand, so the one case that
/// needs a failing restriction uses a local double. It answers the identity
/// questions by delegating to the real platform, so the store reaches the
/// restriction step and only the restriction fails.
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
