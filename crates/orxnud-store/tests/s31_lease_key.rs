//! S-31: the ownership lease key must be **stable**.
//!
//! # The bypass these tests close
//!
//! The ownership lease is keyed by a path-derived lock file. The key used to be
//! derived by canonicalising the configured path and, when that failed, falling
//! back to the canonicalised *parent* plus the file name. A database that does not
//! exist yet is the normal state of a database about to be created, and
//! `canonicalize` fails on it — so the fallback decided the lock name from the
//! *name* rather than from the *target*.
//!
//! When the configured path is a symlink whose target does not exist yet, the two
//! answers disagree, and the lease splits:
//!
//! ```text
//! state.db -> victim.db        (victim.db does not exist yet)
//!
//! first process   canonicalize fails    ->  state.db.lock
//! (the open creates victim.db)
//! second process  canonicalize succeeds ->  victim.db.lock
//! ```
//!
//! Two lock files for one database, so the second process participates in
//! nothing: the same class of bypass as the hard-link alias ADR-0058 refuses,
//! reached through a symlink instead of a link.
//!
//! The correction resolves the **target** rather than the name, so the key is
//! the same before and after the database is created.
//!
//! # What these tests do and do not establish
//!
//! They establish that the *lease key* is stable, and that the ownership
//! boundary holds across it. They establish **nothing** about whether SQLite
//! opened the file the checks looked at: that is the separate pathname-to-
//! connection race, it remains open, and it is stated in
//! `docs/12-verification-register.md`.

use std::path::{Path, PathBuf};

use orxnud_store::StoreError;
use orxnud_store::ownership::{OwnershipError, acquire_exclusive_for_tests};
use orxnud_store::sqlite::Store;

/// A scratch directory, unique per test name.
fn dir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let d = std::env::temp_dir().join(format!("s31-key-{}-{tag}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

/// The lease key for `path`, or a panic naming the path.
fn key(path: &Path) -> PathBuf {
    orxnud_store::ownership::lock_path_for(path)
        .unwrap_or_else(|e| panic!("a resolvable path must yield a lease key: {path:?}: {e}"))
}

/// Put a **real** SQLite database at `path`.
///
/// A file of arbitrary bytes would not do: SQLite refuses to open it, and the
/// refusal that follows must be about ownership, not about a file that is not a
/// database.
fn plant_database(dir: &Path, path: &Path) {
    let seed = dir.join(format!(
        "seed-{}.db",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    {
        let conn = rusqlite::Connection::open(&seed).expect("create the seed database");
        conn.execute_batch("CREATE TABLE t(x);").expect("schema");
    }
    std::fs::copy(&seed, path).expect("plant the database");
    let _ = std::fs::remove_file(&seed);
}

/// Create a symlink at `link` pointing at `target`.
///
/// Unix-only: the repository's Windows lane does not run `orxnud-store`'s tests
/// (see `.github/workflows/ci.yml`, the `windows-portability` job), and the
/// store's own inode test is already `#[cfg(unix)]`.
#[cfg(unix)]
fn symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).expect("create the symlink");
}

/// **Case 1 — the exact reproduction: one key across the absent-to-present
/// transition.**
///
/// The configured path is a symlink to a target that does not exist yet. The key
/// derived before the target exists must be the key derived after it does, and
/// the same as the key derived from the target's own path.
#[cfg(unix)]
#[test]
fn a_dangling_symlink_target_keeps_one_lease_key() {
    let d = dir("dangling");
    let configured = d.join("state.db");
    let target = d.join("victim.db");
    symlink(&target, &configured);

    // The target does not exist yet.
    assert!(!target.exists(), "the target must start absent");

    let before = key(&configured);
    assert_eq!(
        before.file_name().unwrap().to_string_lossy(),
        "victim.db.lock",
        "the key must be derived from the symlink's *target*, not from the name the \
         caller happened to configure"
    );

    // The database is created — by the first process's open, or by anything else.
    plant_database(&d, &target);

    let after = key(&configured);
    let direct = key(&target);

    assert_eq!(
        before, after,
        "the key must not change when the target appears; a key that changes splits \
         the lease and lets a second process bypass the first"
    );
    assert_eq!(
        after, direct,
        "the configured path and the target it names must land on the same lease"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// **Case 2 — actual exclusion across the symlink.**
///
/// While the exclusive lease is held through the configured (symlink) path, a
/// competing open through the **direct target path** must be refused. The lease
/// is what refuses it: the alias check sees a single-name file and permits it.
#[cfg(unix)]
#[test]
fn an_exclusive_lease_through_a_dangling_symlink_excludes_the_direct_target() {
    let d = dir("exclude");
    let configured = d.join("state.db");
    let target = d.join("victim.db");
    symlink(&target, &configured);

    // The first process takes the exclusive lease through the configured path,
    // while the target does not yet exist.
    let lease = acquire_exclusive_for_tests(&configured).expect("take the exclusive lease");

    // The database now exists — a real one, so the refusal that follows is
    // about ownership and not about a file that is not a database.
    plant_database(&d, &target);

    // A competing open through the *direct* target path must not bypass it.
    let err = Store::open(&target, true, &orxnud_platform_fs::OsIdentity)
        .expect_err("the exclusive lease must exclude a competing open");
    match err {
        StoreError::Ownership { source } => assert!(
            matches!(source.as_ref(), OwnershipError::Conflicted { .. }),
            "the refusal must be the ownership conflict, not something else: {source:?}"
        ),
        other => panic!("expected an ownership refusal, got {other:?}"),
    }

    // And the same through the configured path.
    let err = Store::open(&configured, true, &orxnud_platform_fs::OsIdentity)
        .expect_err("the exclusive lease must exclude a competing open");
    assert!(
        matches!(err, StoreError::Ownership { .. }),
        "expected an ownership refusal, got {err:?}"
    );

    drop(lease);
    // Once the lease is released, the same open succeeds: the refusal was about
    // ownership, not about a broken database.
    Store::open(&target, true, &orxnud_platform_fs::OsIdentity)
        .expect("the open must succeed once the lease is released");

    let _ = std::fs::remove_dir_all(&d);
}

/// **Case 3 — an existing symlink still shares the lease.**
///
/// This is the semantics that already existed and must not regress: two paths
/// that resolve to the same existing database must land on one lock, so a
/// process opening through the alias is excluded by a lease held through the
/// real path.
#[cfg(unix)]
#[test]
fn a_symlink_to_an_existing_database_shares_the_lease() {
    let d = dir("existing-alias");
    let real = d.join("state.db");
    let alias = d.join("alias.db");
    plant_database(&d, &real);
    symlink(&real, &alias);

    assert_eq!(
        key(&real),
        key(&alias),
        "an alias of an existing database must resolve to the same lease"
    );

    // And the exclusion holds across the alias.
    let lease = acquire_exclusive_for_tests(&real).expect("take the exclusive lease");
    let err = Store::open(&alias, true, &orxnud_platform_fs::OsIdentity)
        .expect_err("the alias must not bypass the exclusive lease");
    assert!(
        matches!(err, StoreError::Ownership { .. }),
        "expected an ownership refusal, got {err:?}"
    );
    drop(lease);

    let _ = std::fs::remove_dir_all(&d);
}

/// **Case 4 — an ordinary missing database keeps one key.**
///
/// The common case the fallback existed for: a database that has not been
/// created yet, at a path that is not a symlink. The key must be absolute, and
/// it must not change when the database appears.
#[test]
fn a_missing_database_in_an_existing_directory_keeps_one_lease_key() {
    let d = dir("missing");
    let db = d.join("not-created-yet.db");
    assert!(!db.exists(), "the database must start absent");

    let before = key(&db);
    assert!(
        before.is_absolute(),
        "a key derived from the caller's string would be relative, and therefore \
         ambient to the working directory"
    );
    assert_eq!(
        before.file_name().unwrap().to_string_lossy(),
        "not-created-yet.db.lock",
        "the key is derived from the database name, not from whether the database \
         exists"
    );

    plant_database(&d, &db);
    assert_eq!(
        before,
        key(&db),
        "creating the database must not move the lease"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// **Case 5 — an unresolvable path is refused, not guessed.**
///
/// Two realistic unresolvable cases:
///
/// * a symlink loop — the target can never be settled;
/// * a symlink whose destination's *directory* does not exist — the file it
///   names cannot be placed, so there is no stable identity to derive.
///
/// Neither may fall back to the caller's own string: a key derived from an
/// unresolved path is not a stable identity, and two processes would not meet
/// on it. The refusal must be an ownership refusal, so the caller is told the
/// database cannot be opened rather than being allowed to proceed unprotected.
#[cfg(unix)]
#[test]
fn an_unresolvable_database_path_is_refused_rather_than_guessed() {
    let d = dir("unresolvable");

    // A symlink that points at itself.
    let loop_link = d.join("loop.db");
    symlink(&loop_link, &loop_link);
    assert!(
        orxnud_store::ownership::lock_path_for(&loop_link).is_err(),
        "a symlink loop has no stable target, so it must not yield a lease key"
    );
    let err = acquire_exclusive_for_tests(&loop_link)
        .expect_err("a loop must be refused, not given a key");
    assert!(
        matches!(err, OwnershipError::Unavailable { .. }),
        "expected an unavailable refusal, got {err:?}"
    );

    // A symlink whose destination's directory does not exist.
    let bad = d.join("bad.db");
    symlink(&d.join("missing-dir").join("db"), &bad);
    assert!(
        orxnud_store::ownership::lock_path_for(&bad).is_err(),
        "a destination whose directory does not exist has no stable target"
    );

    // And the refusal names the path, so an operator can act on it.
    let err = acquire_exclusive_for_tests(&bad).expect_err("must be refused");
    match err {
        OwnershipError::Unavailable { path, .. } => assert_eq!(
            path, bad,
            "the refusal must name the database it could not open"
        ),
        other => panic!("expected an unavailable refusal, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// **Case 6 — the hard-link case is unchanged, and is still refused.**
///
/// A hard link is *not* a symlink, so it produces two lease keys — that is the
/// bypass the alias check exists to close, and this test pins the pairing: the
/// lease alone would not have protected the database, and the refusal comes
/// from the alias check.
#[cfg(unix)]
#[test]
fn a_hard_linked_database_gets_two_lease_keys_and_is_refused() {
    let d = dir("hard-link");
    let db = d.join("state.db");
    let alias = d.join("alias.db");
    {
        let store =
            Store::open(&db, true, &orxnud_platform_fs::OsIdentity).expect("create the database");
        drop(store);
    }
    std::fs::hard_link(&db, &alias).expect("hard link the database");

    assert_ne!(
        key(&db),
        key(&alias),
        "a hard link is not a symlink, so the two names keep two lease keys: that is \
         why the alias check, and not the lease, is what refuses the alias"
    );

    let err = Store::open(&alias, true, &orxnud_platform_fs::OsIdentity)
        .expect_err("a database reachable through two names must be refused");
    assert!(
        matches!(err, StoreError::Ownership { .. }),
        "expected an ownership refusal, got {err:?}"
    );

    let _ = std::fs::remove_dir_all(&d);
}
