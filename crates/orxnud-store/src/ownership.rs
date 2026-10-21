//! Cross-process database ownership (S-31, F-26c).
//!
//! # What this is for
//!
//! S-30's crate-private restore guard establishes that a restore may proceed: it
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

use crate::alias::AliasRefusal;

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
    /// The ownership lock could not be established.
    ///
    /// Either the lock file could not be created or opened, or the **lease key
    /// could not be derived** — the configured path could not be resolved to a
    /// stable target. The latter is a refusal rather than a fallback: a lock
    /// name derived from an unresolved path is not a stable identity, and two
    /// processes would not meet on it.
    Unavailable {
        /// The path the refusal concerns: the lock file, or the database whose
        /// key could not be derived.
        path: PathBuf,
        /// The underlying reason.
        source: std::io::Error,
    },
    /// The database could not be shown to be alias-safe (ADR-0058, F-26c).
    ///
    /// # Why this is an ownership refusal and not a separate error
    ///
    /// Because it is the same fact. Ownership of a database is keyed by path, so a
    /// database reachable through a second name is one whose ownership cannot be
    /// expressed — a second process may already hold it under a name this process
    /// never sees. Reporting it through the ownership channel means every caller
    /// that already handles "this database is not safely openable" handles this
    /// too, and no route has to learn a second vocabulary for it.
    ///
    /// It is deliberately **not** [`OwnershipError::Unavailable`]: that one means the
    /// lock file could not be created, and an operator's response to it is different
    /// from their response to "somebody has a second name for your database".
    AliasUnsafe {
        /// The database path.
        path: PathBuf,
        /// Why it could not be shown to be safe.
        reason: AliasRefusal,
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
            Self::AliasUnsafe { path, reason } => {
                write!(f, "refusing to open {}: {reason}", path.display())
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
/// * **Normalised.** The caller-supplied path is resolved to an absolute path
///   before the lock name is derived, so `state.db`, `./state.db` and
///   `/abs/cwd/state.db` cannot be three different locks for one database.
/// * **The target is resolved, not just the name.** A configured path that is a
///   **symlink** is followed to the file it names — *even when that file does
///   not exist yet*. This is what makes the lock name stable across the
///   database's creation, and it is not a refinement: see "The failure this
///   fixes" below.
/// * **The lock file is never deleted or renamed.** Identity must outlive the processes
///   that hold it. Replacing it would let a new inode be locked by one process while an
///   old inode stays locked by another — two "owners" of one database.
///
/// # The failure this fixes
///
/// The key used to be derived by canonicalising the configured path and, when
/// that failed, falling back to the canonicalised **parent** plus the file name.
/// A database that does not exist yet is the normal state of a database about to
/// be created, and `canonicalize` fails on it — so the fallback decided the lock
/// name from the *name* rather than from the *target*.
///
/// When the configured path is a symlink whose target does not exist yet, the two
/// answers disagree, and the lease splits:
///
/// ```text
/// state.db -> victim.db        (victim.db does not exist yet)
///
/// first process   canonicalize fails    ->  state.db.lock
/// (the open creates victim.db)
/// second process  canonicalize succeeds ->  victim.db.lock
/// ```
///
/// Two lock files for one database, so the second process participates in
/// nothing: the same class of bypass as the hard-link alias below, reached
/// through a symlink instead of a link.
///
/// Resolving the **target** instead of the name gives one answer before and
/// after the database is created, and the same answer as the target's own path.
/// The resolver follows the final component's symlink chain, refuses a path it
/// cannot settle, and never falls back to the caller's own string.
///
/// # Hard links — detected, not tolerated
///
/// Symlinks and relative paths are handled above. **Hard links are not**, and that
/// was a real bypass, measured:
///
/// ```text
/// state.db and alias.db are one inode (20445) but resolve to
///     state.db.lock   and   alias.db.lock
/// -> two locks, so a competitor opening the alias participates in nothing
/// ```
///
/// Keying the lock by inode does not fix it: `link(2)` permits a hard link in a different
/// directory on the same filesystem, so an inode-keyed name would still need a parent
/// directory, and the two parents can differ.
///
/// So the database is **refused**: a database reachable through more than one name
/// cannot be owned by a path-keyed rule, and the check that refuses it lives in
/// [`crate::alias`], where the filesystem-identity capability ADR-0058 requires is
/// applied on both sides of the open.
///
/// What that check establishes is stated in [`crate::alias`], and it is deliberately
/// narrower than "ownership is alias-safe": the observations are of a **path**, and
/// SQLite resolves the path itself, so a path changed and changed back inside the
/// window is not detected. ADR-0058 Decision 2 approved that limitation rather than
/// claiming it away.
///
/// # Errors
///
/// [`OwnershipError::Unavailable`] when the lease key cannot be derived. The
/// derivation is deliberately fallible: a key that cannot be established must
/// not become permission to continue without the intended ownership protection.
pub fn lock_path_for(db_path: &Path) -> Result<PathBuf, OwnershipError> {
    let target = resolve_lease_target(db_path).map_err(|source| OwnershipError::Unavailable {
        path: db_path.to_path_buf(),
        source,
    })?;
    Ok(with_lock_suffix(&target))
}

/// How many symbolic links may be followed while resolving the lease target.
///
/// The same order of magnitude as the operating system's own limit
/// (`SYMLOOP_MAX` is 40 on Linux), so a path the kernel would accept is not
/// rejected here — and a loop is caught rather than spun on.
const MAX_SYMLINK_DEPTH: usize = 40;

/// The database a configured path is *intended* to name, resolved as far as the
/// filesystem allows.
///
/// # Why this exists
///
/// [`lock_path_for`] used to canonicalise the configured path and, when that
/// failed, fall back to the canonicalised **parent** plus the file name. That
/// fallback is unstable in exactly the case it exists to cover. A database that
/// does not exist yet is the normal state of a database about to be created, and
/// `canonicalize` fails on it — so the fallback decided the lock name from the
/// *name* rather than from the *target*.
///
/// When the configured path is a symlink whose target does not exist yet, the
/// two answers disagree:
///
/// ```text
/// state.db -> victim.db        (victim.db does not exist yet)
///
/// first process   canonicalize fails    ->  state.db.lock
/// (the open creates victim.db)
/// second process  canonicalize succeeds ->  victim.db.lock
/// ```
///
/// Two lock files for one database, so the second process participates in
/// nothing — the same class of bypass as the hard-link alias ADR-0058 refuses,
/// reached through a symlink instead of a link.
///
/// This resolves the **target** instead: a symlink is followed even when its
/// destination does not exist, so the name is derived from the file the path
/// will name once the database is there. The answer is the same before and after
/// the database is created.
///
/// # What it resolves
///
/// * The parent directory is canonicalised, so `.`, `..` and symlinked parent
///   directories are settled once and for all.
/// * The final component is followed if it is a symlink, repeatedly, so a chain
///   of symlinks settles on the file at the end of it.
/// * A final component that is not a symlink keeps its name, whether or not it
///   exists.
///
/// # What it refuses
///
/// * A parent that cannot be resolved.
/// * A symlink whose destination cannot be read, or whose destination's parent
///   directory does not exist.
/// * A symlink loop, or a chain longer than [`MAX_SYMLINK_DEPTH`].
///
/// Every refusal is an error. The caller must not fall back to the caller's own
/// string: a lock name derived from an unresolved path is not a stable identity,
/// and two processes would not meet on it.
fn resolve_lease_target(db_path: &Path) -> Result<PathBuf, std::io::Error> {
    if db_path.as_os_str().is_empty() {
        return Err(std::io::Error::other("the database path is empty"));
    }
    // Absolute first, so the parent can be resolved: a relative path with no
    // directory component has no parent to canonicalise.
    let absolute = std::path::absolute(db_path)?;
    let mut parent = absolute
        .parent()
        .ok_or_else(|| std::io::Error::other("the database path has no parent directory"))?
        .canonicalize()?;
    let mut name = absolute
        .file_name()
        .ok_or_else(|| std::io::Error::other("the database path has no file name"))?
        .to_os_string();

    for _ in 0..MAX_SYMLINK_DEPTH {
        let current = parent.join(&name);
        let meta = match std::fs::symlink_metadata(&current) {
            Ok(meta) => meta,
            // A database that does not exist yet: the name stands, and the answer
            // is the one it will have once the file is there.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(current),
            // Anything else — a permission problem, an I/O error — is not
            // "absent". Treating it as absent would let the caller proceed with a
            // key derived from an unreadable path.
            Err(e) => return Err(e),
        };
        if !meta.file_type().is_symlink() {
            return Ok(current);
        }
        let target = std::fs::read_link(&current)?;
        // A relative destination is relative to the symlink's own directory.
        let resolved = if target.is_absolute() {
            target
        } else {
            parent.join(target)
        };
        let target_parent = resolved.parent().ok_or_else(|| {
            std::io::Error::other("the symlink destination has no parent directory")
        })?;
        let target_name = resolved
            .file_name()
            .ok_or_else(|| std::io::Error::other("the symlink destination has no file name"))?;
        // The destination's parent must exist. A symlink to a path whose
        // directory is absent names a file that cannot be placed, and there is no
        // stable identity to derive for it.
        parent = target_parent.canonicalize()?;
        name = target_name.to_os_string();
    }
    Err(std::io::Error::other(
        "too many levels of symbolic links while resolving the database path",
    ))
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

/// Acquire a shared lease on behalf of an **integration test**.
///
/// Symmetric with [`acquire_exclusive_for_tests`]: S-31's coverage tests need to stand
/// where an ordinary daemon stands, to prove that a second ordinary process may also open.
/// Like its counterpart it grants nothing a normal open does not already require.
///
/// It takes no filesystem-identity capability, because it does not open the database:
/// it takes the lease only. The alias check belongs to the open itself, and a lease
/// without a database behind it has nothing to be unsafe about.
pub fn acquire_shared_for_tests(db_path: &Path) -> Result<SharedOwnership, OwnershipError> {
    acquire_shared(db_path)
}

/// Test-only: a hook that fires **after** the shared lease is taken and **before** the
/// recovery state is read.
///
/// It exists so the ordering can be proven rather than asserted in a comment: a test
/// that installs a hook here can attempt to take the exclusive lease, and must fail,
/// which is only true if the shared lease is already held.
#[cfg(test)]
pub(crate) mod seams {
    use std::cell::RefCell;

    std::thread_local! {
        static AFTER_SHARED_LEASE: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
    }

    /// Install `f` to run on this thread once the next shared lease has been taken.
    pub(crate) fn after_shared_lease(f: impl Fn() + 'static) {
        AFTER_SHARED_LEASE.with(|s| *s.borrow_mut() = Some(Box::new(f)));
    }

    pub(crate) fn fire_after_shared_lease() {
        let f = AFTER_SHARED_LEASE.with(|s| s.borrow_mut().take());
        if let Some(f) = f {
            f();
        }
    }
}

/// Surfaces a recovery failure as an ownership refusal.
///
/// Typed rather than a panic or a silent pass: a caller that cannot restore must be told it
/// cannot open, and the message must name recovery so the refusal is not misread as a lock
/// contention.
///
/// `path` is the path the refusal is about. It used to be a lock name derived from an
/// **empty** path, which named nothing the caller could act on; the caller now passes the
/// path it was actually working on.
fn ownership_error(path: &Path, e: crate::recovery::RecoveryError) -> OwnershipError {
    OwnershipError::Unavailable {
        path: path.to_path_buf(),
        source: std::io::Error::other(format!(
            "an outstanding restore could not be completed: {e}"
        )),
    }
}

/// Acquire a shared lease. Fails fast if an exclusive owner holds the database.
///
/// # This is the recovery-aware boundary (F-26b)
///
/// **Both** entry points to a live database funnel through here or through
/// [`acquire_exclusive`]: `Store::open`, `SqliteAuditJournal::open` and
/// `SqliteApprovalLedger::open` each call `acquire_shared` before opening their own
/// `Connection`, and `RestoreGuard::acquire_with` calls `acquire_exclusive`. `Store::open`
/// alone is **not** the choke point — the audit that established that is recorded in
/// `docs/12-verification-register.md` A-011.
///
/// So the outstanding-restore check lives here rather than in `Store::open`, and it runs
/// **before** the lease is taken, so a database with an outstanding intent is never handed
/// out usable.
///
/// Recursion is avoided by [`crate::recovery::complete_outstanding_restore`] taking its
/// lease through the `_unchecked` variants below, which perform no recovery check. An
/// outstanding intent therefore does not make recovery unable to run.
pub(crate) fn acquire_shared(db_path: &Path) -> Result<SharedOwnership, OwnershipError> {
    // **The lease is taken before the recovery state is read.** The two used to be
    // separate operations, in the other order, and that was a race: a reader could
    // check "no intent", and a restore could then publish an intent and crash before
    // the reader took its lease, leaving the reader holding a lease on a database
    // whose restore was outstanding.
    //
    // A restore publishes its intent while holding the **exclusive** lease, so a
    // held shared lease means no new intent can appear. The read below is therefore
    // not a stale observation that has to be re-taken afterwards.
    //
    // Two rounds, never more. The second round covers the case where an intent *was*
    // outstanding: the shared lease is dropped, recovery completes under the exclusive
    // lease, and the lease is taken again and the state re-read. If something is still
    // outstanding after that, the caller is refused rather than served -- this fails
    // fast and never retries indefinitely.
    for _ in 0..2 {
        let lease = acquire_shared_unchecked(db_path)?;
        // The seam fires with the shared lease held, so a test can prove the ordering
        // rather than infer it.
        #[cfg(test)]
        seams::fire_after_shared_lease();
        if crate::recovery::restore_state(db_path) == crate::recovery::RestoreState::Idle {
            return Ok(lease);
        }
        // Something is outstanding: an intent, a staging file, or an intent that will
        // not parse. Release the shared lease so recovery can take the exclusive one,
        // and let the recovery decide -- including refusing, if the intent is malformed.
        drop(lease);
        crate::recovery::complete_outstanding_restore(db_path)
            .map_err(|e| ownership_error(db_path, e))?;
    }
    Err(ownership_error(
        db_path,
        crate::recovery::RecoveryError::Io {
            what: "the database did not settle: a restore is still outstanding".into(),
            source: std::io::Error::other("outstanding restore"),
        },
    ))
}

/// The shared lease **without** the recovery check.
///
/// The lease only. It grants no authority a checked acquisition would refuse.
pub(crate) fn acquire_shared_unchecked(db_path: &Path) -> Result<SharedOwnership, OwnershipError> {
    let path = lock_path_for(db_path)?;
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
    // The exclusive lease is taken **first**, and the recovery state is read under it.
    // Reading first and locking second was the same race as on the shared path: a
    // restore could publish an intent in between.
    let lease = acquire_exclusive_unchecked(db_path)?;
    // Under the exclusive lease, no other process can publish, complete or remove an
    // intent, so this read is authoritative and the recovery that follows can install
    // without re-taking the lease.
    crate::recovery::complete_outstanding_restore_under_lease(db_path)
        .map_err(|e| ownership_error(db_path, e))?;
    Ok(lease)
}

/// The exclusive lease **without** the recovery check.
///
/// Only recovery itself uses this, so that completing a restore does not recursively
/// demand that it complete a restore. It grants no authority a checked acquisition would
/// refuse; the only difference is which caller may ask without the check.
pub(crate) fn acquire_exclusive_unchecked(
    db_path: &Path,
) -> Result<ExclusiveOwnership, OwnershipError> {
    let path = lock_path_for(db_path)?;
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

        let canonical = lock_path_for(&db).expect("a resolvable path yields a lease key");
        assert!(
            canonical.is_absolute(),
            "a lock identity derived from the caller's string would be relative and \
             therefore ambient to the working directory"
        );

        // A path that does not exist yet still gets an absolute, stable identity.
        let missing = d.join("not-created-yet.db");
        let lock_missing = lock_path_for(&missing).expect("a missing file still has a key");
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
        let path = lock_path_for(&db).expect("a resolvable path yields a lease key");

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
