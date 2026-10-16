//! Cross-process database ownership (S-31, F-26c).
//!
//! # What this is for
//!
//! S-30's [`crate::backup::RestoreGuard`] establishes that a restore may proceed: it
//! checkpoints the target's write-ahead log and refuses if a reader is inside a
//! transaction. That is an **instantaneous, in-process** check. It is not a lease, and
//! it cannot see another daemon. Between the checkpoint and the copy, a second
//! process may open and write the database, and neither the guard nor the logical
//! verification is designed to survive that.
//!
//! This module supplies the missing layer: a **stable per-database lock file** with
//! ordinary `flock`-style shared/exclusive ownership, held for the lifetime of the
//! thing it protects.
//!
//! # Semantics
//!
//! * An **ordinary open** holds **shared** ownership for as long as its connection may
//!   be used. Several may coexist — including several in one process, because the lock
//!   is per open file description.
//! * A **restore** holds **exclusive** ownership for the whole lifecycle: before the
//!   checkpoint, through the copy, through the logical verification, and until the
//!   outcome is known.
//! * Contention **fails fast** with a typed error. Nothing here waits: an unbounded
//!   start-up wait is its own availability defect, and a restore that blocks silently
//!   is indistinguishable from a hung daemon.
//!
//! # Why not SQLite's own locking
//!
//! SQLite serialises writers, and the online backup API takes a destination lock for
//! the backup operation. Neither covers the *lifecycle*: the window before the
//! checkpoint, and the window after the copy, are outside both. A transaction lock is
//! also not an ownership claim — it says "I am writing now", not "I am restoring, and
//! nobody may open this database for the next fifty milliseconds".
//!
//! **Advisory locks only coordinate participants that follow this protocol.** A
//! process that opens the database by some other route participates in nothing. That
//! is why every application-managed open is instrumented rather than the restore path
//! alone.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

/// Why an ownership lease could not be established.
///
/// Both variants are refusals. Neither is ever converted into a successful open or a
/// successful restore: an ownership step that fails is a failure of the operation, not
/// a warning about it.
#[derive(Debug)]
pub enum OwnershipError {
    /// Another owner holds a conflicting lease. Fail fast; do not wait.
    Conflicted {
        /// The lock file whose lease could not be taken.
        path: PathBuf,
    },
    /// The lock file could not be created or opened.
    Unavailable {
        /// The lock file.
        path: PathBuf,
        /// The underlying reason.
        source: std::io::Error,
    },
}

impl std::fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflicted { path } => write!(
                f,
                "database ownership is held elsewhere for {}; refusing rather than \
                 waiting, because an unbounded start-up wait is its own defect",
                path.display()
            ),
            Self::Unavailable { path, source } => {
                write!(
                    f,
                    "cannot establish database ownership for {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for OwnershipError {}

/// The stable lock file for a database.
///
/// # Identity rules, and why each one exists
///
/// * **Extension, not a sibling of a sibling.** `state.db` locks at `state.db.lock`,
///   so the identity is a pure function of the database file name.
/// * **Normalised.** The caller-supplied path is canonicalised relative to the current
///   directory first. A lock identity derived from an unnormalised string would give
///   `state.db`, `./state.db` and `/abs/cwd/state.db` three different locks for one
///   database.
/// * **Symlinks are resolved where the target exists.** `canonicalize` fails on a
///   nonexistent path, which is the normal state of a database about to be created; the
///   canonicalised *parent* is joined with the file name in that case, so a not-yet-created
///   database still gets a stable, absolute identity rather than silently falling back to
///   the caller's relative string.
/// * **The lock file is never deleted or renamed.** Identity must outlive the processes
///   that hold it. Replacing it would let a new inode be locked by one process while an
///   old inode stays locked by another — two "owners" of one database.
///
/// # Known gap — HARD LINKS ARE NOT DETECTED
///
/// Symlinks and relative paths are handled above. **Hard links are not**, and that is a
/// real bypass, measured:
///
/// ```text
/// state.db and alias.db are one inode (20445) but resolve to
///     state.db.lock   and   alias.db.lock
/// -> two locks, so a competitor opening the alias participates in nothing
/// ```
///
/// Keying the lock by inode does not fix it: `link(2)` permits a hard link in a different
/// directory on the same filesystem, so an inode-keyed name would still need a parent
/// directory and the two parents can differ.
///
/// The fix is to **refuse** a database with more than one name, which needs the file's link
/// count. That is platform-specific (`std::os::unix::fs::MetadataExt`), gate G3 forbids it
/// outside `orxnud-platform-*`, and gate G2's layering forbids `orxnud-store` from
/// depending on a platform crate. `orxnud_platform_fs::hard_link_count` exists and is
/// correctly placed, but is currently unreachable from the crate that takes the lease.
///
/// **Until that is resolved, ownership is not alias-safe.** Any caller opening this
/// database through a hard link participates in nothing. Recorded as an open limitation
/// in A-008; not claimed as fixed.
#[must_use]
pub fn lock_path_for(db_path: &Path) -> PathBuf {
    match db_path.canonicalize() {
        Ok(canonical) => with_lock_suffix(&canonical),
        Err(_) => match db_path.parent().and_then(|p| Path::canonicalize(p).ok()) {
            // Resolve the directory, keep the file name: a database that does not exist
            // yet still gets an absolute, stable identity.
            Some(parent) => with_lock_suffix(&parent.join(db_path.file_name().unwrap_or_default())),
            // Last resort: normalise the path lexically rather than falling back to
            // whatever string the caller passed.
            None => with_lock_suffix(
                &std::path::absolute(db_path).unwrap_or_else(|_| db_path.to_path_buf()),
            ),
        },
    }
}

fn with_lock_suffix(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    path.with_file_name(name)
}

/// Owns a shared lease on a database.
///
/// Held for the lifetime of the value that carries it, so the lease follows the real
/// connection lifetime rather than the `open()` call that produced it. Dropping the
/// carrying value drops this, which releases the lock — and the kernel also releases it
/// if the process dies, which is what makes a crashed daemon not wedge the database.
#[derive(Debug)]
pub struct SharedOwnership {
    // `_file` is the lease: `flock` is tied to the open file description, so the file
    // must be kept alive for as long as the lock is meant to be held.
    _file: File,
    path: PathBuf,
}

impl SharedOwnership {
    /// The lock file this lease is held on.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A lease over nothing, for an in-memory database.
    ///
    /// `:memory:` has no file, so a second process cannot open it and there is nothing
    /// to coordinate. The lease exists rather than being `Option`-shaped so that
    /// `Store` has one shape regardless of how it was opened.
    pub(crate) fn in_memory() -> Self {
        Self {
            _file: {
                // An empty path never reaches the filesystem: the file handle is only
                // there to be dropped, and this one owns no OS lock.
                std::fs::File::open("/dev/null")
                    .expect("the null device always opens on this platform")
            },
            path: PathBuf::from(":memory:"),
        }
    }
}

/// Owns an exclusive lease on a database. Nothing else may open it while this lives.
#[derive(Debug)]
pub struct ExclusiveOwnership {
    _file: File,
    path: PathBuf,
}

impl ExclusiveOwnership {
    /// The lock file this lease is held on.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Opens (creating if necessary) the lock file for `db_path`.
///
/// `create(true)` is deliberate: the lock file is part of the database's identity and
/// two processes racing to create it must end up on the **same inode**. Creating it
/// exclusively would let the loser fail spuriously; creating it exclusively and then
/// unlinking is the classic way to end up with two lock files for one database.
fn open_lock_file(path: &Path) -> Result<File, OwnershipError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|source| OwnershipError::Unavailable {
            path: path.to_path_buf(),
            source,
        })
}

/// Acquire an exclusive lease on behalf of an **integration test**.
///
/// S-31's coverage tests need to stand where a restore stands, to prove that the other
/// entry points refuse while it holds the database. Without this they could only prove
/// that the restore refuses, which says nothing about the other four.
///
/// It is `pub` but documented as a test seam, because `#[cfg(test)]` items are invisible
/// to the integration tests in `tests/` that need it. It grants no capability that
/// `RestoreGuard` does not already require: it is exclusive, it fails closed, and it
/// cannot be used to restore anything.
pub fn acquire_exclusive_for_tests(db_path: &Path) -> Result<ExclusiveOwnership, OwnershipError> {
    acquire_exclusive(db_path)
}

/// **Rejects a database reachable through more than one name.**
///
/// `lock_path_for` normalises relative paths and resolves symlinks, and a hard link
/// defeats both: `state.db` and `alias.db` are the same inode but canonicalise to two
/// different names, so they produce **two lock files** and a competitor opening via the
/// alias participates in nothing. Measured during S-31's review:
///
/// ```text
/// a -> /tmp/.../state.db.lock
/// b -> /tmp/.../alias.db.lock
/// SAME LOCK? false        (both inode 20445)
/// ```
///
/// Keying the lock by inode was considered and rejected: `link(2)` permits a hard link in a
/// different directory on the same filesystem, so an inode-keyed name would still have to be
/// scoped by a parent directory, and the two parents can differ. There is no
/// filesystem-independent way to give one inode one name.
///
/// So the database is **refused**. This is also what SQLite itself warns about: opening one
/// database through multiple names can give the two names different WAL or journal files,
/// which is undefined behaviour independent of any locking question.
///
/// The count itself comes from `orxnud_platform_fs::hard_link_count`, because gate G3
/// forbids a platform `cfg` in this crate. Where the platform cannot report a count it
/// returns `None` and this function **passes** — recorded as a limitation in A-008 rather
/// than presented as a check that happened to succeed.
/// Acquire a shared lease on behalf of an **integration test**.
///
/// Symmetric with [`acquire_exclusive_for_tests`]: S-31's coverage tests need to stand
/// where an ordinary daemon stands, to prove that a second ordinary process may also open.
/// Like its counterpart it grants nothing a normal open does not already require.
pub fn acquire_shared_for_tests(db_path: &Path) -> Result<SharedOwnership, OwnershipError> {
    acquire_shared(db_path)
}

/// Acquire a shared lease. Fails fast if an exclusive owner holds the database.
pub(crate) fn acquire_shared(db_path: &Path) -> Result<SharedOwnership, OwnershipError> {
    let path = lock_path_for(db_path);
    let file = open_lock_file(&path)?;
    file.try_lock_shared().map_err(|e| classify(&path, e))?;
    Ok(SharedOwnership { _file: file, path })
}

/// Acquire an exclusive lease. Fails fast if any owner, shared or exclusive, holds it.
///
/// This is **not** an upgrade path: `acquire_shared` followed by `acquire_exclusive` on
/// the same database is not a supported sequence, and nothing here makes it one. The
/// caller must release its shared lease first — see `TaskService::open`, which drops the
/// store (and with it the shared lease) before asking for exclusive ownership.
pub(crate) fn acquire_exclusive(db_path: &Path) -> Result<ExclusiveOwnership, OwnershipError> {
    let path = lock_path_for(db_path);
    let file = open_lock_file(&path)?;
    // `File::try_lock` is the *exclusive* non-blocking lock; `lock_shared` is the
    // shared one. Naming it `try_lock_exclusive` here would not compile, which is
    // worth stating because the pairing is easy to get backwards.
    // `File::try_lock` is the *exclusive* non-blocking lock; `lock_shared` is the
    // shared one. Naming it `try_lock_exclusive` here would not compile, which is
    // worth stating because the pairing is easy to get backwards.
    file.try_lock().map_err(|e| classify(&path, e))?;
    Ok(ExclusiveOwnership { _file: file, path })
}

/// Distinguishes "someone else holds it" from "the platform cannot do this at all".
///
/// The two are different failures: the first is contention and is expected under
/// concurrency, the second means the mechanism is unavailable (an unsupported
/// filesystem, for instance) and silently treating it as contention would report a
/// healthy database as busy.
fn classify(path: &Path, error: std::fs::TryLockError) -> OwnershipError {
    match error {
        // Contention: expected, and reported as such rather than as a broken lock file.
        std::fs::TryLockError::WouldBlock => OwnershipError::Conflicted {
            path: path.to_path_buf(),
        },
        // The mechanism itself is unavailable — an unsupported filesystem, for example.
        // Silently reporting this as contention would call a healthy database "busy".
        std::fs::TryLockError::Error(source) => OwnershipError::Unavailable {
            path: path.to_path_buf(),
            source,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Inode identity is Unix-only; the test that uses it is gated below.
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    /// Nonce-keyed scratch directory. A PID alone is not unique across runs on a
    /// busy host, and two runs sharing a directory fail for reasons that have nothing
    /// to do with what the test asserts.
    fn dir(tag: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let d = std::env::temp_dir().join(format!("s31-own-{}-{tag}-{nonce}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch");
        d
    }

    /// **Lock identity.** Aliases of one database must resolve to one lock.
    ///
    /// The failure this prevents is specific: `./state.db`, `state.db` and the
    /// absolute path are three strings and — without normalisation — three lock files,
    /// so two processes could each hold "the" lock on the same database.
    #[test]
    fn aliases_of_one_database_resolve_to_one_lock() {
        let d = dir("identity");
        let db = d.join("state.db");
        std::fs::write(&db, b"").expect("touch");

        let canonical = lock_path_for(&db);
        assert!(
            canonical.is_absolute(),
            "a lock identity derived from the caller's string would be relative and \
             therefore ambient to the working directory"
        );

        // A path that does not exist yet still gets an absolute, stable identity.
        let missing = d.join("not-created-yet.db");
        let lock_missing = lock_path_for(&missing);
        assert!(
            lock_missing.is_absolute(),
            "a database about to be created must still get a stable absolute identity"
        );
        assert_eq!(
            lock_missing.file_name().unwrap().to_string_lossy(),
            "not-created-yet.db.lock",
            "the lock name is derived from the database name, not from whether the \
             database exists"
        );

        let _ = std::fs::remove_dir_all(&d);
    }

    /// Two shared owners coexist; an exclusive request is refused while either lives.
    #[test]
    fn shared_owners_coexist_and_exclusive_is_refused_while_any_lives() {
        let d = dir("shared");
        let db = d.join("state.db");
        std::fs::write(&db, b"").expect("touch");

        let a = acquire_shared(&db).expect("first shared");
        let b = acquire_shared(&db).expect("second shared; shared owners coexist");

        assert!(
            matches!(
                acquire_exclusive(&db),
                Err(OwnershipError::Conflicted { .. })
            ),
            "an exclusive request must be refused while shared owners exist"
        );

        drop(a);
        assert!(
            matches!(
                acquire_exclusive(&db),
                Err(OwnershipError::Conflicted { .. })
            ),
            "one shared owner remaining is still a refusal"
        );

        drop(b);
        let x = acquire_exclusive(&db).expect("exclusive once every shared owner released");
        // And the reverse: an exclusive owner blocks a new shared owner.
        assert!(
            matches!(acquire_shared(&db), Err(OwnershipError::Conflicted { .. })),
            "an exclusive owner must exclude new shared owners"
        );
        drop(x);

        // The kernel releases the lock when the owner goes away, so the lease is
        // reacquirable rather than sticky.
        acquire_exclusive(&db).expect("reacquirable after release");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The lock file is never replaced, so identity survives concurrent participants.
    #[cfg(unix)]
    #[test]
    fn the_lock_file_is_created_once_and_not_replaced() {
        let d = dir("stable");
        let db = d.join("state.db");
        std::fs::write(&db, b"").expect("touch");
        let path = lock_path_for(&db);

        let first = acquire_shared(&db).expect("first");
        let inode_before = std::fs::metadata(&path).expect("metadata").ino();
        let _second = acquire_shared(&db).expect("second");

        std::fs::metadata(&path).expect("still present");
        assert_eq!(
            std::fs::metadata(&path).expect("metadata").ino(),
            inode_before,
            "the lock file must stay the same inode for every participant; replacing \
             it would let one process lock the new inode while another holds the old"
        );
        drop(first);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A lock file in a directory that does not exist is an `Unavailable` refusal,
    /// not a silent success.
    #[test]
    fn an_unusable_lock_path_is_refused_rather_than_ignored() {
        let db = Path::new("/nonexistent-directory-for-s31/state.db");
        assert!(
            matches!(acquire_shared(db), Err(OwnershipError::Unavailable { .. })),
            "a lock that cannot be created must be a refusal; silently skipping it \
             would leave the database unprotected while appearing to succeed"
        );
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    /// Nonce-keyed scratch directory.
    fn dir(tag: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let d = std::env::temp_dir().join(format!("s31-b-{}-{tag}-{nonce}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch");
        d
    }

    /// **Boundary 2 — shared ownership genuinely coexists, so two daemons may both run.**
    ///
    /// This is the row that would be wrong if the implementation had over-corrected into
    /// refusing concurrent opens. The protocol intends: ordinary opens share, a restore
    /// excludes. If two ordinary opens were refused, a second daemon could never start
    /// and the change would be broader than the design describes.
    #[test]
    fn ordinary_opens_share_rather_than_excluding_each_other() {
        let d = dir("share");
        let db = d.join("state.db");
        std::fs::write(&db, b"x").expect("seed");

        // Two independent owners, each from its own file description.
        let first = acquire_shared(&db).expect("first ordinary open");
        let second = acquire_shared(&db).expect("second ordinary open must be permitted");
        let third = acquire_shared(&db).expect("a third, too");
        drop((first, second, third));
        let _ = std::fs::remove_dir_all(&d);
    }
}
