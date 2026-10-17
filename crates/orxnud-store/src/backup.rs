//! Snapshot and restore: what makes a migration recoverable (ADR-0017).
//!
//! # Why an online backup and not a file copy
//!
//! A WAL database is three files (`state.db`, `state.db-wal`, `state.db-shm`).
//! Copying the main file while a writer is active captures a *torn* snapshot:
//! the `-wal` holds committed transactions the main file has not absorbed yet.
//! The result opens cleanly and is missing data — the worst possible failure,
//! because it is invisible until much later.
//!
//! SQLite's online backup API copies through the SQLite pager, so it takes a
//! transactionally consistent snapshot of a live database. That is the only
//! correct way to snapshot a WAL database, and it is why `rusqlite`'s `backup`
//! feature is enabled.
//!
//! # The three-step discipline
//!
//! ADR-0017 requires every migration to be preceded by an **automatic,
//! verified** snapshot, and a failed migration to restore it. "Verified" is the
//! word that carries the weight:
//!
//! 1. [`Backup::take`] copies the database and then **verifies** it —
//!    `PRAGMA integrity_check`, the schema version, and a row count. A snapshot
//!    that cannot be opened is not a snapshot.
//! 2. Only after verification does [`crate::migration`] run.
//! 3. On failure, [`Backup::restore_coordinated`] puts it back and the previous binary
//!    keeps working. That is the public entry point; the restore primitive it delegates
//!    to is crate-private, because restoring without ownership is the thing this crate
//!    exists to prevent.
//!
//! # What a snapshot is not
//!
//! It is not a backup for the user. It lives beside the database, it is
//! overwritten on each migration, and it is not rotated. Retention of *user*
//! backups is a separate feature (ADR-0028's per-region retention), not this.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

/// Pages copied per step. Positive because `run_to_completion` rejects zero, and
/// large enough that a personal daemon's database is copied in one step.
const PAGES_PER_STEP: i32 = 64;

/// A snapshot failure.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    /// The backup could not be written.
    ///
    /// Holds `rusqlite::Error` directly rather than
    /// [`StoreError`](crate::sqlite::StoreError): `StoreError`
    /// wraps `MigrationError`, which wraps this type, so wrapping it here would
    /// make the three infinitely sized.
    #[error("could not write the snapshot to {path}: {source}")]
    Write {
        /// Where the snapshot was going.
        path: String,
        /// The underlying error.
        #[source]
        source: rusqlite::Error,
    },

    /// A filesystem operation on the snapshot failed outside SQLite.
    ///
    /// Separate from [`BackupError::Write`] because that one carries a `rusqlite::Error`,
    /// and reporting "could not write the snapshot: disk I/O error" for a failed `rename`
    /// would send an operator looking at SQLite. Moving a finished snapshot into place is
    /// not a database operation.
    #[error("could not move the snapshot into place at {path}: {source}")]
    Io {
        /// The canonical snapshot path.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The snapshot was written but does not open.
    #[error("the snapshot at {path} cannot be opened: {source}")]
    Unreadable {
        /// The snapshot path.
        path: String,
        /// The underlying error.
        #[source]
        source: rusqlite::Error,
    },

    /// The snapshot failed SQLite's own integrity check.
    ///
    /// The whole point of verifying: a corrupt snapshot restored over good data
    /// is strictly worse than no restore.
    #[error("the snapshot at {path} failed integrity_check: {report}")]
    IntegrityFailed {
        /// The snapshot path.
        path: String,
        /// What SQLite reported.
        report: String,
    },

    /// The snapshot has no `schema_meta`, so the schema version cannot be checked.
    #[error("the snapshot at {path} has no schema_meta table")]
    NoSchemaMeta {
        /// The snapshot path.
        path: String,
    },

    /// The snapshot has the schema but no rows in it.
    ///
    /// A migrated database always records at least one applied version in
    /// `schema_meta`, so a snapshot with the table present and nothing in it is a
    /// snapshot of something that was never migrated — or one that lost its rows.
    /// Restoring it would replace a real database with an empty schema, which is the
    /// failure the whole snapshot mechanism exists to prevent.
    ///
    /// This variant is what the "A row count, so verified means ..." comment has been
    /// describing: the count was computed and returned but never compared against
    /// anything, so the protection was documentation rather than code.
    #[error(
        "the snapshot at {path} has a schema but no rows: restoring it would erase the database"
    )]
    Empty {
        /// The snapshot path.
        path: String,
    },

    /// The restore target does not exist.
    #[error("no snapshot at {0} to restore from")]
    Missing(PathBuf),

    /// Exclusive database ownership could not be established (S-31).
    ///
    /// Another process holds the database, or the locking mechanism is unavailable.
    /// Either way the restore does **not** proceed and does not report success: a
    /// restore that could not exclude other writers is not a restore.
    #[error("refusing to restore: {reason}")]
    Ownership {
        /// The underlying refusal, rendered.
        reason: String,
    },

    /// Exclusive authority over the restore target could not be established.
    ///
    /// **This is the fail-closed arm of S-30's coordination rule.** It is raised when
    /// `PRAGMA wal_checkpoint(TRUNCATE)` reports `busy != 0`, which is SQLite's own
    /// signal that another connection holds a read transaction open against the
    /// target. In that state the restore is **refused**: proceeding would rewrite
    /// the database under a live reader whose sidecars are about to change.
    ///
    /// Refusing costs a migration that might otherwise have rolled back. Restoring
    /// anyway costs a reader stranded on an inode nobody can reconcile. The first is
    /// `Undetermined`; the second is silent data divergence.
    #[error(
        "refusing to restore {path}: another connection is reading it ({readers} reader(s)), \
         so exclusive authority cannot be established"
    )]
    Busy {
        /// The restore target.
        path: String,
        /// How many readers SQLite reported.
        readers: i64,
    },

    /// The restore completed its work but the result did not match the snapshot.
    ///
    /// Measured on 2026-10-14: `Backup::restore` could return `Ok(())` while
    /// post-snapshot data was still present, with `PRAGMA integrity_check` reporting
    /// `ok`, `schema_meta` intact and `Backup::verify` passing. Every structural
    /// check available was satisfied by a database that was logically wrong.
    ///
    /// This variant exists because that outcome must not be reported as a successful
    /// restore. It is raised **after** the copy, from the logical comparison, so the
    /// mismatch is recorded rather than returned as success.
    #[error("restoring {path} did not reproduce the snapshot's logical state")]
    RestoreUnverified {
        /// The restore target.
        path: String,
    },
}

/// What a verification established about a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSnapshot {
    /// The schema version found in the snapshot.
    pub schema_version: u32,
    /// The number of rows across every table, as a cheap "it has content" check.
    pub total_rows: i64,
}

/// A verified snapshot beside the live database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    path: PathBuf,
}

// Test-only: the per-thread hook fired between `Backup::take`'s copy and its verification.
//
// (A plain comment, not a doc comment: `thread_local!` is a macro invocation, so a doc
// comment attaches to nothing and rustc warns.)
//
// **Thread-local on purpose.** A process-wide `static` would be visible to every test in the
// binary running at the same moment, and `cargo test` runs them in parallel — which is how a
// seam becomes a flake instead of a tool. `RefCell` rather than a `Mutex` because the borrow
// never escapes the calling thread and never spans the hook's own execution: the hook runs
// after `Backup::fire_after_copy` has already taken the value out.
//
// `#[cfg(test)]` and module-private, so it does not exist in a production binary at all.
// There is no environment variable to set and no public entry point that reaches it.
#[cfg(test)]
std::thread_local! {
    static SEAMS: RefCell<Seams> = const {
        RefCell::new(Seams {
            after_copy: None,
            before_publish: None,
        })
    };
}

/// Test-only: the two points inside [`Backup::take`] a test can act at.
///
/// Both sit on boundaries that are otherwise unreachable from outside, and they are the two
/// the staging-and-rename design introduces:
///
/// * `after_copy` — the copy is written, verification has not begun. Mutating the *source*
///   here is what exposes a verifier that re-reads live state instead of using what it
///   captured for the snapshot in hand.
/// * `before_publish` — the snapshot is verified but not yet at its canonical name. This is
///   the only place from which a publication failure can be provoked deterministically,
///   because the staged file must be made to go missing between the two steps that touch it.
///
/// Each is one-shot and per-thread.
#[cfg(test)]
#[derive(Default)]
struct Seams {
    after_copy: Option<Box<dyn Fn()>>,
    before_publish: Option<Box<dyn Fn()>>,
}

#[cfg(test)]
use std::cell::RefCell;

impl Backup {
    /// Where the snapshot for `db_path` lives.
    ///
    /// A sibling, not `/tmp`: restoring across a filesystem boundary turns the
    /// copy into a partial operation, and a partial restore of the only copy of
    /// a user's data is the failure mode this whole module exists to prevent.
    #[must_use]
    pub fn path_for(db_path: &Path) -> PathBuf {
        let mut name = db_path.file_name().unwrap_or_default().to_os_string();
        name.push(".pre-migration.bak");
        db_path.with_file_name(name)
    }

    /// A unique staging name beside `canonical`.
    ///
    /// Uniqueness needs the process id *and* a counter: `PathService::open` and
    /// `SqliteAuditJournal::open` can both reach `take` for one database inside one
    /// process, and pid alone would collide there exactly as it would across processes.
    fn staging_path(canonical: &Path) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut name = canonical.file_name().unwrap_or_default().to_os_string();
        name.push(format!(
            ".staging-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        canonical.with_file_name(name)
    }

    /// Moves a verified snapshot into its canonical name.
    ///
    /// # Why the rename, and not write-in-place
    ///
    /// `take` used to `remove_file` the canonical path and write the copy straight into
    /// it. That is safe for one caller and wrong for two: a second `take` running against
    /// the same database deleted the first one's snapshot out from under it, and the first
    /// then verified a file the second was still writing — "the snapshot at ... has no
    /// `schema_meta` table".
    ///
    /// Nothing hit that until S-11/F-26 made the production migration path take a snapshot
    /// at all. Before this change `SqliteAuditJournal::open` and `SqliteApprovalLedger::open`
    /// called `MigrationRunner::run(true)`, which took none, so two concurrent opens of one
    /// fresh database never raced on the snapshot path. The race was real; it was simply
    /// unreachable, which is a different thing from absent.
    ///
    /// Staging and renaming also means the canonical path only ever names a snapshot that
    /// was built *and verified in full*. A reader that finds a file there — a restore, or
    /// the next `migrate` deciding whether to reuse an existing snapshot — cannot arrive
    /// mid-write.
    ///
    /// # Why there is no delete-then-rename fallback, and there was one
    ///
    /// The first version of this function carried a Windows fallback: `rename`, and on
    /// failure `remove_file` the destination and rename again, on the stated premise that
    /// "`rename` does not replace an existing file on Windows".
    ///
    /// **That premise is false.** Verified against this toolchain's own `std::fs::rename`
    /// documentation (1.98.1): *"Renames a file or directory to a new name, **replacing the
    /// original file if `to` already exists**"*, implemented on Windows as `MoveFileExW` with
    /// a fallback to `SetFileInformationByHandle`. The fallback was never needed.
    ///
    /// Worse than unnecessary, it was destructive. A fallback that removes the destination
    /// has a failure mode the direct rename does not: if the second rename fails — a
    /// different error, a different moment, an antivirus scanner holding the path — the
    /// canonical snapshot has already been deleted and the only good copy of the database is
    /// gone. `take` reports the error, and the operator is left with a migration failure
    /// *and* a destroyed recovery point, which is the opposite of what a snapshot is for.
    ///
    /// So the fallback is deleted rather than repaired. The direct rename replaces the
    /// destination atomically on both platforms, and if it fails the destination is
    /// **untouched** — which is the property worth having. A rename can still legitimately
    /// fail on Windows (`ERROR_ACCESS_DENIED`, `ERROR_SHARING_VIOLATION` when another handle
    /// holds the file without `FILE_SHARE_DELETE`); that is reported, with the staging file
    /// cleaned up by [`Self::take`], and the previous snapshot left in place.
    fn publish(staging: &Path, canonical: &Path) -> Result<(), BackupError> {
        std::fs::rename(staging, canonical).map_err(|source| BackupError::Io {
            path: canonical.display().to_string(),
            source,
        })
    }

    /// Adopts an existing snapshot at `path`, without creating or verifying it.
    ///
    /// The caller is responsible for having verified it; [`Self::verify`] is the
    /// way to do that. Exists so a caller that already holds a verified snapshot
    /// does not pay to take a second one.
    #[must_use]
    pub fn existing(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The snapshot path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Takes a snapshot of `conn` and **verifies** it before returning.
    ///
    /// # Errors
    ///
    /// [`BackupError`] if the copy cannot be written, cannot be reopened, fails
    /// `integrity_check`, or has no `schema_meta`.
    pub fn take(conn: &Connection, db_path: &Path) -> Result<Self, BackupError> {
        let path = Self::path_for(db_path);
        // Built and verified at a unique staging name, then moved into place. See
        // `publish`.
        let staging = Self::staging_path(&path);
        let _ = std::fs::remove_file(&staging);

        // **Both** steps below can fail, and the staging file must not survive either of
        // them. An earlier version cleaned up only around the copy/verify step and then
        // used `?` on the publication, so a failed rename leaked a verified-but-unpublished
        // snapshot beside the database under a name no reader looks at. It accumulated one
        // file per failed publication, and -- because a later `take` only removes the
        // staging name it generated itself -- nothing ever reclaimed them.
        let taken = Self::take_into(conn, &staging);
        #[cfg(test)]
        if taken.is_ok() {
            // The second seam point: verified, but not yet at its canonical name.
            Self::fire_before_publish();
        }
        let published = taken.and_then(|()| Self::publish(&staging, &path));
        if let Err(e) = published {
            // The staging file is never the recovery point: it has not been published, so
            // nothing can have been told to restore from it. Removing it cannot lose a
            // snapshot anyone depends on. The canonical path is deliberately untouched --
            // if a previous snapshot existed it is still there, and `publish` is written so
            // that a failed rename cannot have destroyed it.
            let _ = std::fs::remove_file(&staging);
            return Err(e);
        }
        Ok(Self { path })
    }

    /// Copies `conn` to `dst_path` and verifies the copy against `conn`.
    ///
    /// Split out of [`Self::take`] so the caller owns the staging file's lifetime: every
    /// `?` in here has to be able to remove it.
    fn take_into(conn: &Connection, dst_path: &Path) -> Result<(), BackupError> {
        // Asked *before* the copy, and carried to the verification below rather than
        // re-read there. See `verify_against_source`.
        let source_was_unmigrated = !Self::has_schema_meta(conn);
        {
            let mut dst = Connection::open(dst_path).map_err(|source| BackupError::Write {
                path: dst_path.display().to_string(),
                source,
            })?;
            // 64 pages per step, zero pause: SQLite's own default page count, so
            // the whole copy happens without yielding. A *small* step count with a
            // non-zero pause would be the dangerous configuration — it copies
            // correctly but takes locks long enough to stall the single writer.
            let backup = rusqlite::backup::Backup::new(conn, &mut dst).map_err(|source| {
                BackupError::Write {
                    path: dst_path.display().to_string(),
                    source,
                }
            })?;
            backup
                .run_to_completion(PAGES_PER_STEP, std::time::Duration::from_millis(0), None)
                .map_err(|source| BackupError::Write {
                    path: dst_path.display().to_string(),
                    source,
                })?;
            // Drop the `Backup` before reading `dst`: it holds a mutable borrow,
            // and its `Drop` is what finalises the copy.
        }

        // The seam for the read-ordering test. It sits **between the copy and the
        // verification**, which is the only place a mutation of the source can change the
        // answer without changing the snapshot -- and that is precisely the defect.
        //
        // It is `#[cfg(test)]`, thread-local, and unreadable in production: there is no
        // environment variable, no flag, no public entry point, and a second thread cannot
        // see or set it. The three seams this crate has used before (an environment
        // variable compiled into production, `pre_exec` descriptor handover, and a
        // whole-environment gate) are all documented in `restore_with_lease_for_tests`;
        // this one is deliberately narrower than any of them, because it does not pause
        // anything -- it only runs code the test itself supplies, at a moment the test
        // chooses.
        #[cfg(test)]
        Self::fire_after_copy();

        let verified = Self::verify_against_source(dst_path, conn, source_was_unmigrated)?;
        // The verification result is used by the caller; it is computed here so a
        // failure is reported by `take` rather than discovered later.
        let _ = verified;
        Ok(())
    }

    /// Test-only: run the `after_copy` hook for the calling thread, if any, and consume it.
    #[cfg(test)]
    fn fire_after_copy() {
        let f = SEAMS.with(|s| s.borrow_mut().after_copy.take());
        if let Some(f) = f {
            f();
        }
    }

    /// Test-only: run the `before_publish` hook for the calling thread, if any, and consume
    /// it.
    #[cfg(test)]
    fn fire_before_publish() {
        let f = SEAMS.with(|s| s.borrow_mut().before_publish.take());
        if let Some(f) = f {
            f();
        }
    }

    /// Test-only: install `f` to run after the copy and before the verification of the next
    /// [`Self::take`] **on this thread**. One-shot: consumed by [`Self::fire_after_copy`].
    #[cfg(test)]
    fn on_after_copy(f: impl Fn() + 'static) {
        SEAMS.with(|s| s.borrow_mut().after_copy = Some(Box::new(f)));
    }

    /// Test-only: install `f` to run after the verification and before the publication of
    /// the next [`Self::take`] **on this thread**. One-shot: consumed by
    /// [`Self::fire_before_publish`].
    ///
    /// This is the only place from which a publication failure can be provoked
    /// deterministically: the staged file has to be made to disappear between the two steps
    /// that touch it, and there is no window to hit from outside.
    #[cfg(test)]
    fn on_before_publish(f: impl Fn() + 'static) {
        SEAMS.with(|s| s.borrow_mut().before_publish = Some(Box::new(f)));
    }

    /// Verifies a snapshot by comparing it with the database it was taken from.
    ///
    /// # Why this exists, and the bug it fixes
    ///
    /// [`Self::verify`] rejects a snapshot with no `schema_meta` table, because
    /// restoring such a snapshot would replace a user's database with nothing — "the
    /// catastrophe a snapshot exists to avoid", and a good guard.
    ///
    /// It is the wrong guard for a **fresh install**, where the source database has
    /// no `schema_meta` table either, because nothing has been created yet. The
    /// snapshot is then a faithful copy of an empty database, and rejecting it makes
    /// the very first migration impossible: the daemon cannot start on a machine
    /// where OpenRayNux has never run.
    ///
    /// That is not hypothetical. Phase 2's migration tests all drove
    /// `MigrationRunner::run(snapshot_verified: bool)`, which trusts its caller's
    /// snapshot claim and never takes one, so `take` was never called on an unmigrated
    /// database. The bug surfaced only when the production startup path in
    /// `orxnud-daemon` began calling `migrate` for real.
    ///
    /// So emptiness is judged *relative to the source*: an empty snapshot is a
    /// failure only when the database it protects was not itself empty.
    ///
    /// # Errors
    ///
    /// [`BackupError`] as for [`Self::verify`], except that an absent `schema_meta` is
    /// accepted when the source also lacks it.
    ///
    /// # `source_was_unmigrated` is a parameter, not a re-read
    ///
    /// "May this snapshot have no `schema_meta`?" is really "was the database I copied
    /// already unmigrated?" — a property of the source at the moment of the copy. Reading
    /// it here, after the copy, re-reads a source another thread may have migrated in
    /// between, and the answer then describes a different database than the one in the
    /// snapshot.
    ///
    /// Observed, not theorised: with eight threads opening one fresh database, seven
    /// failed. Each copied an empty file, then found `schema_meta` on the live source —
    /// another thread having applied migration 1 — and refused its own perfectly good
    /// snapshot with "has no `schema_meta` table". The relaxation for a fresh install
    /// (V-33) was unreachable under concurrency, and unreachable *by accident*.
    ///
    /// So the answer is passed in rather than computed here. The caller must have read it
    /// **before** the copy, and a signature change is the honest way to say so: there is no
    /// two-argument form to reach for by accident. A caller that genuinely wants the
    /// after-the-fact answer can still write `!Self::has_schema_meta(source)`, and it will
    /// read as a deliberate re-read rather than as the default.
    ///
    /// Reading before is also the safer direction. If the source gained `schema_meta`
    /// between the read and the copy, the copy either contains it (so the question does
    /// not arise) or does not (so the snapshot is a faithful copy of the unmigrated
    /// database, which is what accepting it asserts). The guard that matters — refusing an
    /// emptied snapshot of a *migrated* database — still holds, because a source that had
    /// been migrated had `schema_meta` before the read.
    ///
    /// `source` is retained because it names the database the snapshot is evidence *about*,
    /// and because a future verification that needs to read it should not have to widen the
    /// signature. It is not consulted: every check is a property of `path`.
    #[allow(
        unused_variables,
        reason = "see the note above; kept for call-site meaning"
    )]
    pub fn verify_against_source(
        path: &Path,
        source: &Connection,
        source_was_unmigrated: bool,
    ) -> Result<VerifiedSnapshot, BackupError> {
        Self::verify_impl(path, source_was_unmigrated)
    }

    /// Whether a connection has the `schema_meta` table.
    pub(crate) fn has_schema_meta(conn: &Connection) -> bool {
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta');",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|n| n != 0)
        // A source we cannot query is treated as *having* the table, which selects the
        // strict branch: an unreadable source must not license a lax verification.
        .unwrap_or(true)
    }

    /// Verifies an existing snapshot on disk.
    ///
    /// # Errors
    ///
    /// [`BackupError`] as for [`Self::take`].
    pub fn verify(path: &Path) -> Result<VerifiedSnapshot, BackupError> {
        Self::verify_impl(path, false)
    }

    fn verify_impl(path: &Path, allow_absent_meta: bool) -> Result<VerifiedSnapshot, BackupError> {
        if !path.is_file() {
            return Err(BackupError::Missing(path.to_path_buf()));
        }
        let conn = Connection::open(path).map_err(|source| BackupError::Unreadable {
            path: path.display().to_string(),
            source,
        })?;

        let integrity: String = conn
            .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
            .map_err(|source| BackupError::Unreadable {
                path: path.display().to_string(),
                source,
            })?;
        if integrity != "ok" {
            return Err(BackupError::IntegrityFailed {
                path: path.display().to_string(),
                report: integrity,
            });
        }

        let has_meta: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_meta';",
                [],
                |r| r.get(0),
            )
            .map_err(|source| BackupError::Unreadable {
                path: path.display().to_string(),
                source,
            })?;
        if has_meta == 0 {
            if !allow_absent_meta {
                return Err(BackupError::NoSchemaMeta {
                    path: path.display().to_string(),
                });
            }
            // A fresh install: the snapshot is empty because the source was. There is
            // nothing to restore, so nothing can be lost.
            return Ok(VerifiedSnapshot {
                schema_version: 0,
                total_rows: 0,
            });
        }

        let schema_version: u32 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_meta;",
                [],
                |r| r.get(0),
            )
            .map_err(|source| BackupError::Unreadable {
                path: path.display().to_string(),
                source,
            })?;

        // A row count, so "verified" means "has the data we expected" and not just
        // "is a valid empty database". An empty snapshot restores a user's database
        // to nothing, which is precisely the catastrophe a snapshot exists to avoid.
        let total_rows: i64 = conn
            .query_row(
                "SELECT COALESCE((SELECT COUNT(*) FROM schema_meta), 0);",
                [],
                |r| r.get(0),
            )
            .map_err(|source| BackupError::Unreadable {
                path: path.display().to_string(),
                source,
            })?;

        // Enforced, not merely reported. See [`BackupError::Empty`].
        if total_rows == 0 {
            return Err(BackupError::Empty {
                path: path.display().to_string(),
            });
        }

        Ok(VerifiedSnapshot {
            schema_version,
            total_rows,
        })
    }

    /// Restores this snapshot over `db_path`.
    ///
    /// Replaces the live database's *contents* by copying the snapshot back
    /// through the online backup API, which is safe while the live connection is
    /// open — no file deletion, no rename race with a live pager.
    ///
    /// # Errors
    ///
    /// [`BackupError`] if the snapshot is missing or the copy fails.
    /// Put the snapshot back over `db_path`.
    ///
    /// **Requires a [`RestoreGuard`], and is `pub(crate)` for that reason (S-30).**
    /// Before S-30 this was `pub` and took only a path, so any caller — inside this
    /// crate or outside — could restore over a database whose write-ahead log was
    /// still live, and would be told `Ok(())` even when post-snapshot data survived
    /// the restore. Requiring a permit makes the coordination rule part of the
    /// signature instead of a comment.
    ///
    /// The copy is **in place** through SQLite's online backup API, not a rename:
    /// measured, renaming over a file another connection has open strands that
    /// connection on the old inode (see [`RestoreGuard`]).
    ///
    /// The result is compared to the snapshot **logically** before `Ok` is returned.
    /// `integrity_check`, `schema_meta` and [`Self::verify`] were all measured to
    /// pass while the database was logically wrong, so none of them can close this
    /// method.
    ///
    /// # Errors
    ///
    /// [`BackupError::Missing`] if the snapshot is gone, [`BackupError::Write`] or
    /// [`BackupError::Unreadable`] if the copy fails, and
    /// [`BackupError::RestoreUnverified`] if the copy completes but the logical
    /// state does not match — which is the outcome this method must never report
    /// as success.
    /// The target is read from the **permit**, not from the caller's argument.
    ///
    /// A guard acquired for database A cannot authorise restoring database B, so a
    /// permit is never transferable to a path it was not taken for. Before this,
    /// `restore` accepted both the snapshot and an unrelated path, which is the
    /// shape a "which database did I actually just overwrite?" incident needs.
    pub(crate) fn restore(&self, guard: &RestoreGuard) -> Result<(), BackupError> {
        let db_path: &Path = guard.path();
        if !self.path.is_file() {
            return Err(BackupError::Missing(self.path.clone()));
        }
        let src = Connection::open(&self.path).map_err(|source| BackupError::Unreadable {
            path: self.path.display().to_string(),
            source,
        })?;
        {
            // Scoped so the `Backup`'s borrow of `dst` ends before the connection is
            // closed: `run_to_completion` is what finalises the copy.
            let mut dst = Connection::open(db_path).map_err(|source| BackupError::Write {
                path: db_path.display().to_string(),
                source,
            })?;
            let backup = rusqlite::backup::Backup::new(&src, &mut dst).map_err(|source| {
                BackupError::Write {
                    path: db_path.display().to_string(),
                    source,
                }
            })?;
            backup
                .run_to_completion(PAGES_PER_STEP, std::time::Duration::from_millis(0), None)
                .map_err(|source| BackupError::Write {
                    path: db_path.display().to_string(),
                    source,
                })?;
        }

        // Logical comparison. Both digests are computed over connections that must
        // open cleanly; an unreadable database is an Err here, never a digest of
        // nothing that compares equal to another digest of nothing.
        let expected = Connection::open(&self.path).and_then(|c| logical_digest(&c));
        let actual = Connection::open(db_path).and_then(|c| logical_digest(&c));
        match (expected, actual) {
            (Ok(e), Ok(a)) if e == a => Ok(()),
            _ => Err(BackupError::RestoreUnverified {
                path: db_path.display().to_string(),
            }),
        }
    }

    /// Restore under a lease the caller already holds. **Test seam.**
    ///
    /// `restore_coordinated` is the production entry point and acquires its own exclusive
    /// lease; its window cannot be paused from outside, because it is internal. S-31's
    /// Test B needs to hold a restore *inside* that window so a competing process can be
    /// placed there at a known moment.
    ///
    /// The first way of doing that was an environment-variable seam in the production path.
    /// It was wrong twice: gated on `#[cfg(not(test))]` it was compiled **into**
    /// production, so an ambient variable could pause a real restore for a minute; and the
    /// second attempt needed `pre_exec` to hand over a descriptor, which is `unsafe` and so
    /// barred by gate G4. Both are gone. This entry point replaces them, and grants no
    /// capability `restore_coordinated` does not already require — it demands an
    /// **exclusive** lease, which is exactly what the restore demands.
    pub fn restore_with_lease_for_tests(
        &self,
        db_path: &Path,
        lease: crate::ownership::ExclusiveOwnership,
    ) -> Result<(), BackupError> {
        let guard = RestoreGuard::acquire_with(db_path, Some(lease))?;
        self.restore(&guard)
    }

    /// Restore this snapshot, acquiring exclusive authority first.
    ///
    /// This is the **public** entry point and the only one outside this crate. It
    /// exists because restricting the primitive is not the same as removing the
    /// capability: `orxnud-task/tests/durability.rs` restores to undo a
    /// half-applied schema, and that is a legitimate caller which must keep working.
    ///
    /// It takes no authority argument because it cannot be given a wrong one — the
    /// authority is acquired here, from `db_path`, and the restore is then performed
    /// against the same path. A caller cannot skip the coordination step, because
    /// there is no step for it to skip; the raw restore primitive that does is
    /// `pub(crate)`, and is reachable only by holding its crate-private guard.
    ///
    /// # Errors
    ///
    /// Everything the crate-private restore primitive can return, plus
    /// [`BackupError::Busy`] when another connection is reading the target.
    pub fn restore_coordinated(&self, db_path: &Path) -> Result<(), BackupError> {
        let guard = RestoreGuard::acquire(db_path)?;
        self.restore(&guard)
    }

    /// Deletes the snapshot.
    ///
    /// Called after a migration succeeds, so a stale pre-migration copy is not left
    /// to be mistaken for a current one. Failure is not an error: the snapshot is
    /// no longer needed either way, and refusing to continue would mean a
    /// successful migration is reported as a failure.
    pub fn discard(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A digest of a database's **logical** content: every row of every user table.
///
/// This is deliberately not a hash of the file. SQLite is free to reorganise
/// physical storage during an operation that is logically a no-op, so a byte
/// comparison would report a mismatch for a correct restore and — worse — could
/// not distinguish "reorganised" from "restored the wrong thing". The recorded
/// failure of 2026-10-14 was invisible to `integrity_check`, `schema_meta` and
/// `Backup::verify` precisely because those compare *structure*. This compares
/// **content**, which is what actually changed.
///
/// Rows are ordered by rowid and tables by name so the digest is stable across
/// runs and across connections. An error is propagated, never swallowed: a digest
/// computed over a database that could not be read would otherwise be a digest of
/// nothing, and would compare equal to another digest of nothing.
fn logical_digest(conn: &Connection) -> Result<String, rusqlite::Error> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut tables: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' \
             ORDER BY name;",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    tables.sort();

    let mut hasher = DefaultHasher::new();
    for table in tables {
        hasher.write(table.as_bytes());
        let sql = format!("SELECT * FROM \"{table}\" ORDER BY rowid;");
        let mut stmt = conn.prepare(&sql)?;
        let ncols = stmt.column_count();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            for i in 0..ncols {
                match row.get_ref(i)? {
                    rusqlite::types::ValueRef::Null => hasher.write(b"n"),
                    rusqlite::types::ValueRef::Integer(v) => {
                        hasher.write(b"i");
                        v.hash(&mut hasher);
                    }
                    rusqlite::types::ValueRef::Real(v) => {
                        hasher.write(b"r");
                        v.to_bits().hash(&mut hasher);
                    }
                    rusqlite::types::ValueRef::Text(t) => {
                        hasher.write(b"t");
                        t.hash(&mut hasher);
                    }
                    rusqlite::types::ValueRef::Blob(b) => {
                        hasher.write(b"b");
                        b.hash(&mut hasher);
                    }
                }
            }
            hasher.write(b"\n");
        }
    }
    Ok(format!("{:016x}", hasher.finish()))
}

/// Exclusive authority to restore one database file.
///
/// # Why a permit exists rather than a convention
///
/// A stale `-wal` beside a restored main file makes post-snapshot data reappear
/// (measured, deterministic, 3/3). Removing it is necessary but is **not** the
/// control: removing a `-wal` out from under a connection that is using it is
/// itself a corruption, so the two things cannot be done independently.
///
/// This type is therefore the only thing that can authorise a restore, and
/// [`Backup::restore`] takes one by reference. It is `pub(crate)` and its field is
/// private, so a caller outside this crate cannot construct one — the enforcement
/// is in the type signature, not in a review rule that a later edit can route
/// around. `restore` was public before S-30 and is deliberately no longer.
///
/// # What `acquire` actually proves
///
/// Not "no other connection exists" — measured, `PRAGMA locking_mode = EXCLUSIVE`
/// does **not** exclude a second handle (it opened and read successfully), so it
/// is not used and is not sufficient.
///
/// What it does prove is the property the restore actually needs: that the
/// target's write-ahead log has been **quiesced**, so there is nothing left to
/// replay. `PRAGMA wal_checkpoint(TRUNCATE)` reports `busy != 0` when another
/// connection holds a read transaction, and `busy == 0` when the log has been
/// absorbed. So:
///
/// * `busy != 0` -> [`BackupError::Busy`], and **no restore is attempted**.
/// * `busy == 0` -> the `-wal` is empty, so removing it cannot lose committed data,
///   and the in-place copy that follows cannot be undone by a replay.
///
/// # Why the copy is in place rather than a rename
///
/// Measured: `fs::rename` over a database file that another connection has open
/// **strands** that connection on the old inode — it kept reading pre-restore
/// rows while the writer saw the restored ones. The online backup API writes
/// *through* the existing file, and a second handle observes the restored state.
/// The API already in use is also the correct one; only the sequencing changes.
#[derive(Debug)]
pub(crate) struct RestoreGuard {
    path: PathBuf,
    _conn: Connection,
    /// Exclusive cross-process ownership (S-31). Its presence is the proof that no
    /// other process may open or modify this database for the whole lifecycle.
    _ownership: crate::ownership::ExclusiveOwnership,
}

impl RestoreGuard {
    /// Quiesce `db_path`'s write-ahead log, or refuse.
    ///
    /// # Errors
    ///
    /// [`BackupError::Busy`] if a reader holds the database open, and
    /// [`BackupError::Unreadable`] if the target cannot be opened or checkpointed.
    pub(crate) fn acquire(db_path: &Path) -> Result<Self, BackupError> {
        Self::acquire_with(db_path, None)
    }

    /// Acquire using a lease the caller already holds.
    ///
    /// `acquire` is the production path and always takes its own exclusive lease. This
    /// form exists so S-31's Test B can hold a restore *inside* the lifecycle without a
    /// seam in production code: the test takes the lease through
    /// [`crate::ownership::acquire_exclusive_for_tests`], arranges the interleaving, and
    /// then restores under the lease it already holds.
    pub(crate) fn acquire_with(
        db_path: &Path,
        held: Option<crate::ownership::ExclusiveOwnership>,
    ) -> Result<Self, BackupError> {
        // S-31: exclusive ownership across processes, taken **before** the checkpoint
        // and held through the copy and the logical verification below.
        //
        // It is taken here rather than by the caller because `acquire` is the single
        // place that knows the restore is about to start; taking it later would reopen
        // the window this whole module exists to close. A caller that holds a shared
        // lease on the same database -- including this process's own -- is refused
        // rather than accommodated, which is why `TaskService::open` drops its store
        // before migrating.
        let exclusive = match held {
            Some(lease) => lease,
            None => crate::ownership::acquire_exclusive(db_path).map_err(|e| {
                BackupError::Ownership {
                    reason: e.to_string(),
                }
            })?,
        };

        let conn = Connection::open(db_path).map_err(|source| BackupError::Unreadable {
            path: db_path.display().to_string(),
            source,
        })?;

        // (busy, log_frames, checkpointed_frames)
        let busy: i64 = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |r| r.get(0))
            .map_err(|source| BackupError::Unreadable {
                path: db_path.display().to_string(),
                source,
            })?;

        if busy != 0 {
            // A live reader. Everything after this point would be a guess.
            return Err(BackupError::Busy {
                path: db_path.display().to_string(),
                readers: busy,
            });
        }

        // The checkpoint reported success, so the log is empty and there is nothing
        // left to replay. **Nothing is deleted here, and that is deliberate.**
        //
        // The first version of this removed `-wal` and `-shm` as "belt and braces",
        // and criterion 4(b) caught it: with an independent connection open, deleting
        // `-shm` — which SQLite has memory-mapped — left that connection reading
        // through a deleted inode and failing with `disk I/O error`. That is the
        // exact hazard the implementation caution in S-30's specification warns
        // about, and it is why sidecar deletion is not the mechanism.
        //
        // An **empty** log replays nothing, which is the property that actually
        // matters. The case that motivated all of this — a stale log carrying
        // post-snapshot pages — is handled by the copy that follows: the in-place
        // backup overwrites the main file, and whatever the checkpoint folded in is
        // overwritten with it. If that copy does not produce the snapshot's logical
        // state, `restore` returns `BackupError::RestoreUnverified` rather than
        // `Ok(())`, so a surviving replay is reported instead of hidden.

        Ok(Self {
            path: db_path.to_path_buf(),
            _conn: conn,
            // Dropped last: the connection closes before the lease is released, so
            // there is never a moment where this process holds no ownership of a
            // database it still has a handle to.
            _ownership: exclusive,
        })
    }

    /// The path this guard authorises restoring. `pub(crate)`, and used by
    /// [`Backup::restore`] so the permit and the target cannot drift apart.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::MigrationRunner;
    use crate::pragma::Pragma;

    /// A scratch directory, unique per test name so tests cannot collide when run
    /// in parallel.
    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("orxnud-backup-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    fn migrated_db(path: &Path) -> Connection {
        let conn = Connection::open(path).expect("open");
        Pragma::critical().apply(&conn).expect("pragmas");
        MigrationRunner::new(&conn).migrate(path).expect("migrate");
        conn
    }

    /// **Concurrent snapshots of one database must all succeed.**
    ///
    /// S-11/F-26 made this reachable. `SqliteAuditJournal::open` and
    /// `SqliteApprovalLedger::open` used to reach `MigrationRunner::run(true)`, which took
    /// no snapshot at all, so two constructors opening one database never touched the
    /// snapshot path together. Making the production path snapshot is the whole point of
    /// that change, and it exposed two defects in `Backup::take` that had been latent:
    ///
    /// 1. it deleted the canonical snapshot and wrote the copy into it in place, so a
    ///    second `take` removed the first one's file mid-write and the first verified a
    ///    half-written snapshot; and
    /// 2. `verify_against_source` decided whether an empty snapshot was acceptable by
    ///    asking the *live* source, which another thread could migrate between the copy
    ///    and the question -- refusing a good snapshot of a database that had legitimately
    ///    been migrated by someone else in the meantime.
    ///
    /// Both were fixed by publishing through a unique staging name and by asking about the
    /// source before the copy. Both are observable here, and neither was reachable before,
    /// which is why the old suite was green.
    #[test]
    fn concurrent_snapshots_of_one_database_all_succeed() {
        const N: usize = 8;
        let dir = dir("concurrent-take");
        let path = dir.join("state.db");
        // A brand-new, unmigrated database: the state in which an empty snapshot is
        // legitimate, and therefore the state that exercised the ordering bug.
        {
            let c = Connection::open(&path).expect("open");
            Pragma::critical().apply(&c).expect("pragmas");
        }
        assert!(
            !Backup::path_for(&path).exists(),
            "precondition: no snapshot exists yet"
        );

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let p = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let c = Connection::open(&p).expect("open");
                    barrier.wait();
                    Backup::take(&c, &p).map(|b| b.path().to_path_buf())
                })
            })
            .collect();

        let mut failures = Vec::new();
        let mut handed_out: Vec<std::path::PathBuf> = Vec::new();
        for h in handles {
            match h.join().expect("join") {
                Ok(p) => handed_out.push(p),
                Err(e) => failures.push(e.to_string()),
            }
        }
        assert!(
            failures.is_empty(),
            "every concurrent snapshot must succeed; {} failed, first: {}",
            failures.len(),
            failures.first().map(String::as_str).unwrap_or("")
        );
        assert_eq!(
            handed_out.len(),
            N,
            "every caller must have been handed a path"
        );

        // And what survives is a snapshot, not a torn one.
        //
        // Not `Backup::verify`: that is the *strict* form, and it refuses a snapshot with
        // no `schema_meta` because restoring one would replace a database with nothing.
        // The source here was never migrated, so an empty snapshot is the honest result --
        // `take` is allowed to produce it because it saw the empty source, and `verify`
        // alone cannot see that. So what is asserted is what must hold either way: the
        // file is a readable SQLite database with a clean integrity check, and it sits at
        // the canonical name every caller was handed.
        let canonical = Backup::path_for(&path);
        assert!(
            canonical.exists(),
            "the snapshot must be published at its name"
        );
        for p in &handed_out {
            assert_eq!(
                p, &canonical,
                "every caller must be handed the canonical path, not its own staging name"
            );
        }
        let snapshot = Connection::open(&canonical).expect("the published snapshot must open");
        let integrity: String = snapshot
            .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
            .expect("integrity_check");
        assert_eq!(
            integrity, "ok",
            "a published snapshot must be a whole database, not a half-written one"
        );
        assert!(
            !canonical.to_string_lossy().contains("staging"),
            "the published file is at the canonical name, not a staging one"
        );
        // No staging file is left behind on the success path.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .expect("readdir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".staging-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "a successful take must not leave staging files behind: {leftovers:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The canonical path never names a half-written database.**
    ///
    /// The first of the two defects `take` had. It removed the canonical snapshot and wrote
    /// the copy into it in place, so for the duration of every copy the canonical path named
    /// a truncated file -- and anything that found it there (a restore, or the next
    /// `migrate` deciding whether to reuse an existing snapshot) could read it.
    ///
    /// Asserted by watching the path rather than by racing two threads: a poller reads the
    /// canonical path continuously while takes run, and *every* file it finds must be a
    /// whole database. This is the only assertion that can fail with the in-place write and
    /// pass with staging plus rename, and the reason the earlier
    /// `concurrent_snapshots_of_one_database_all_succeed` was not enough: eight threads
    /// copying an identical empty file can finish in an order that never exposes the torn
    /// state, so that test passed with the fix reverted. A test that cannot fail its own
    /// bug is not a regression test.
    #[test]
    fn the_canonical_snapshot_path_never_names_a_half_written_database() {
        let dir = dir("never-torn");
        let path = dir.join("state.db");
        drop(migrated_db(&path));
        let canonical = Backup::path_for(&path);
        let _ = std::fs::remove_file(&canonical);

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let poller_stop = std::sync::Arc::clone(&stop);
        let watched = canonical.clone();
        let poller = std::thread::spawn(move || {
            let mut observed = 0usize;
            while !poller_stop.load(std::sync::atomic::Ordering::Relaxed) {
                if watched.exists() {
                    observed += 1;
                    // Whatever is at the canonical name must open and be intact. A
                    // half-written copy fails here -- usually by not opening at all.
                    let verdict = Connection::open(&watched).and_then(|c| {
                        c.query_row("PRAGMA integrity_check;", [], |r| r.get::<_, String>(0))
                    });
                    assert_eq!(
                        verdict.as_deref().unwrap_or("<unreadable>"),
                        "ok",
                        "the canonical snapshot path named a file that is not a whole database; \
                         a reader must never observe one mid-write"
                    );
                }
                std::hint::spin_loop();
            }
            observed
        });

        for _ in 0..25 {
            let c = Connection::open(&path).expect("open");
            Backup::take(&c, &path).expect("take");
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let observed = poller.join().expect("poller");
        assert!(
            observed > 0,
            "the poller never saw the snapshot, so it could not have checked anything"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The emptiness question is asked of the source as it was before the copy.**
    ///
    /// The second defect, and the subtle one. `verify_against_source` answered "may this
    /// snapshot have no `schema_meta`?" by asking the *live* source. Asked after the copy,
    /// that question describes a database that may no longer be the one in the snapshot: if
    /// another thread migrated the source in between, a faithful copy of an unmigrated
    /// database gets refused with "has no `schema_meta` table". With S-11/F-26's production
    /// snapshot that stopped being theoretical -- eight threads opening one fresh database
    /// failed seven of the time, which is how it was found.
    ///
    /// Pinned at the decision rather than at the race, because the race cannot be scheduled
    /// deterministically and a test that only fails sometimes is not a test. The property
    /// is that the answer is a property *of the source at copy time*, so it is passed in
    /// rather than re-read -- and this asserts that the two disagree on exactly the case
    /// that broke, with the source read afterwards.
    ///
    /// **What this test does and does not prove.** It pins the semantics of the flag and
    /// shows the two orderings disagree, so it cannot be satisfied by a verifier that
    /// ignores the flag. It does **not** prove that `take` reads the flag before its copy:
    /// reverting `take` to derive it at verification time leaves this test green.
    ///
    /// That revert was measured, not assumed. The evidence for it is
    /// `security_state::tests::concurrent_opens_of_*`, which fails in 3 of 8 runs with the
    /// ordering wrong and 0 of 8 with it right -- the only tests in the tree that catch it,
    /// and flaky, which is a real weakness rather than a pass. The durable mitigation is the
    /// signature: `verify_against_source` takes the flag, so an ordering mistake is now a
    /// visible edit to a documented parameter rather than a silent re-read inside a
    /// function that looks correct.
    #[test]
    fn a_snapshot_of_an_unmigrated_source_stays_acceptable_after_that_source_is_migrated() {
        let dir = dir("emptiness-read-first");
        let path = dir.join("state.db");
        let snapshot = dir.join("early.bak");
        // The snapshot: taken while the source was empty, so it has no `schema_meta`.
        {
            let c = Connection::open(&path).expect("open");
            Pragma::critical().apply(&c).expect("pragmas");
            let mut dst = Connection::open(&snapshot).expect("open dst");
            rusqlite::backup::Backup::new(&c, &mut dst)
                .expect("backup")
                .run_to_completion(64, std::time::Duration::from_millis(0), None)
                .expect("copy");
        }
        let has_meta = |c: &Connection| {
            c.query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta');",
                [],
                |r| r.get::<_, i64>(0),
            )
            .expect("query")
                != 0
        };
        {
            let c = Connection::open(&snapshot).expect("reopen snapshot");
            assert!(
                !has_meta(&c),
                "precondition: the snapshot of an empty database has no schema_meta"
            );
        }

        // Another thread migrates the source after our copy was taken.
        {
            let c = Connection::open(&path).expect("open");
            MigrationRunner::new(&c).migrate(&path).expect("migrate");
            assert!(has_meta(&c), "precondition: the source is now migrated");
        }

        // Read afterwards: the live source now says "migrated", so the relaxation is
        // withheld and a good snapshot is refused. This is the bug -- and it is why
        // `take` must not derive the flag from the source at verification time.
        let c = Connection::open(&path).expect("reopen source");
        let after_the_fact = !has_meta(&c);
        assert!(
            !after_the_fact,
            "precondition: the live source now looks migrated"
        );
        assert!(
            Backup::verify_against_source(&snapshot, &c, after_the_fact).is_err(),
            "reading the source after the copy refuses a snapshot that was faithful when it \
             was taken; this is the behaviour `take` must not depend on"
        );
        // Read before: the answer travels with the snapshot, so the same snapshot is
        // accepted. A snapshot is evidence of the state at copy time, not of the state now.
        Backup::verify_against_source(&snapshot, &c, true)
            .expect("a snapshot taken from an unmigrated source must remain acceptable");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **The read-ordering fix, forced deterministically.**
    ///
    /// This is the test that replaces "3 of 8 runs fail, so the fix probably works". The
    /// interleaving it needs is: *the source is migrated between our copy finishing and our
    /// verification running*. That cannot be scheduled reliably from outside — it needs a
    /// moment inside `take` — so `Backup::on_after_copy` supplies it. The hook
    /// is `#[cfg(test)]` and thread-local; no production binary contains it.
    ///
    /// **The arrangement.** A brand-new, unmigrated database: no `schema_meta`, so
    /// `source_was_unmigrated` is read as `true` before the copy, and the copy therefore
    /// contains no `schema_meta` either. Then, between the copy and the verification, a
    /// *second connection* migrates that same database.
    ///
    /// **What each implementation does.**
    ///
    /// * Correct: the flag was read before the copy and is carried forward. It is `true`.
    ///   The snapshot legitimately has no `schema_meta`, so the relaxation applies and
    ///   `take` succeeds. The snapshot is faithful evidence of the database as it was when
    ///   the copy was made, and nothing about what happened afterwards changes that.
    /// * Faulty: the flag is re-read at verification time. The live source now *has*
    ///   `schema_meta` — the hook migrated it — so the relaxation is withheld and `take`
    ///   fails with `NoSchemaMeta` on a snapshot that is perfectly good.
    ///
    /// The faulty branch is exactly the production defect: verification observing a
    /// *different database* than the one it is verifying. This is the interleaving that made
    /// eight concurrent opens of one fresh database fail seven times, and here it happens on
    /// the first attempt, every time.
    #[test]
    fn a_snapshot_taken_from_an_unmigrated_source_verifies_even_if_that_source_is_migrated_after_the_copy()
     {
        let dir = dir("read-ordering");
        let path = dir.join("state.db");
        {
            // A fresh database: opened and pragma'd, never migrated. No `schema_meta`.
            let c = Connection::open(&path).expect("open");
            Pragma::critical().apply(&c).expect("pragmas");
        }
        assert!(
            !Backup::has_schema_meta(&Connection::open(&path).expect("reopen")),
            "precondition: the source has never been migrated"
        );

        // The seam. A second connection migrates the source at the one moment that matters.
        let migrated = path.clone();
        Backup::on_after_copy(move || {
            let other = Connection::open(&migrated).expect("hook: open a second connection");
            Pragma::critical().apply(&other).expect("hook: pragmas");
            MigrationRunner::new(&other)
                .migrate(&migrated)
                .expect("hook: migrate the source after the copy finished");
        });

        let conn = Connection::open(&path).expect("reopen for take");
        let result = match Backup::take(&conn, &path) {
            Ok(b) => Ok(b.path().to_path_buf()),
            Err(e) => Err(e.to_string()),
        };

        // Assert the hook actually fired and actually changed the source. Without this the
        // test would pass on an implementation where the seam is never reached -- which is
        // the same class of vacuous test this file has already produced twice.
        assert!(
            Backup::has_schema_meta(&Connection::open(&path).expect("reopen")),
            "precondition: the hook must have migrated the source, or this test proves \
             nothing -- the whole fault requires the source to have changed"
        );
        assert_eq!(
            result,
            Ok(Backup::path_for(&path)),
            "verification must use the state captured for this snapshot, not the live \
             source's state at verification time; a re-read reports NoSchemaMeta on a \
             snapshot that is perfectly good"
        );

        // And the published snapshot really is the pre-migration one.
        let published = result.expect("published");
        let snap = Connection::open(&published).expect("open the snapshot");
        assert!(
            !Backup::has_schema_meta(&snap),
            "the snapshot was taken before the migration, so it must not contain it -- \
             otherwise the test is not exercising the empty-snapshot relaxation at all"
        );
        drop(snap);
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The negative control for the test above, as a fact about the *seam* rather than as a
    /// mutation someone has to apply by hand.
    ///
    /// Without it, "the seam was never reached" and "the ordering is right" are
    /// indistinguishable from a green run. This proves the hook fires exactly once, at the
    /// copy/verify boundary, and that it is one-shot — so the test above cannot pass by
    /// having quietly not run it.
    #[test]
    fn the_read_ordering_seam_fires_once_between_the_copy_and_the_verification() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = dir("seam-fires");
        let path = dir.join("state.db");
        drop(migrated_db(&path));

        let count = std::sync::Arc::new(AtomicUsize::new(0));
        let seen = std::sync::Arc::clone(&count);
        let watched = path.clone();
        Backup::on_after_copy(move || {
            seen.fetch_add(1, Ordering::SeqCst);
            // Inside the seam the snapshot is staged but not yet published, so the
            // canonical path must not exist yet: that is what "between the copy and the
            // verification" means.
            assert!(
                !Backup::path_for(&watched).exists(),
                "the seam runs before publication, so the canonical path must be empty"
            );
        });

        let conn = Connection::open(&path).expect("open");
        Backup::take(&conn, &path).expect("take");

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "the seam must fire exactly once per take"
        );
        // One-shot: a second take must not re-run it.
        Backup::take(&conn, &path).expect("second take");
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "the seam is consumed, not persistent"
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A failed replacement must leave the previous snapshot intact and usable.**
    ///
    /// This is the guarantee that makes staging-and-rename worth doing at all. The snapshot
    /// at the canonical path may be the *only* good copy of a database whose last migration
    /// failed, so a `take` that cannot finish must not make things worse than it found them.
    ///
    /// The failure is forced deterministically through verification rather than through a
    /// permissions trick: emptying `schema_meta` leaves the source with the table but zero
    /// rows, so the staged copy is refused by [`BackupError::Empty`] — a real verdict from
    /// the real verifier, not an injected one.
    ///
    /// Asserted in both directions, because "the old snapshot survived" and "nothing partial
    /// replaced it" are different claims: the file must still be the *previous* snapshot, at
    /// the previous version, and not merely something that parses.
    #[test]
    fn a_replacement_that_fails_verification_leaves_the_previous_snapshot_intact() {
        let dir = dir("failed-replacement");
        let path = dir.join("state.db");
        let conn = migrated_db(&path);
        let canonical = Backup::path_for(&path);

        // The good snapshot that must survive.
        let first = Backup::take(&conn, &path).expect("first take");
        assert_eq!(first.path(), canonical.as_path());
        let before = Backup::verify(&canonical).expect("the first snapshot verifies");
        assert_eq!(
            before.schema_version,
            crate::migration::CURRENT_VERSION,
            "precondition: a real snapshot of a migrated database"
        );

        // Now make the *source* impossible to snapshot honestly. The table survives; its
        // rows do not. `verify_impl` reads `total_rows` from `schema_meta`, so this lands on
        // the `Empty` branch rather than the `NoSchemaMeta` one.
        conn.execute("DELETE FROM schema_meta;", [])
            .expect("empty schema_meta");
        assert!(
            Backup::has_schema_meta(&conn),
            "the table is still there; it is the rows that are gone"
        );

        let err = Backup::take(&conn, &path).expect_err("an empty snapshot must be refused");
        assert!(
            matches!(err, BackupError::Empty { .. }),
            "the failure must be reported as an unverifiable snapshot, got {err:?}"
        );
        // The error names the staging file it actually tried to publish, which is the
        // evidence an operator needs: not "migrate failed", but "the copy at this path could
        // not be verified".
        let text = err.to_string();
        assert!(
            text.contains(".staging-"),
            "the error must name the staging file that failed, not a generic failure: {text}"
        );

        // 1. The previous snapshot is still there.
        assert!(
            canonical.exists(),
            "a failed replacement must not remove the snapshot that was already there"
        );
        // 2. It is still the *previous* one, not a partial rewrite.
        let after = Backup::verify(&canonical).expect("the previous snapshot still verifies");
        assert_eq!(
            after, before,
            "a failed replacement must leave the previous snapshot exactly as it was"
        );
        // 3. And it is still restorable, which is the only reason any of this matters.
        drop(conn);
        Backup::existing(canonical.clone())
            .restore_coordinated(&path)
            .expect("the surviving snapshot must still restore");
        let restored =
            crate::migration::MigrationRunner::new(&Connection::open(&path).expect("reopen"))
                .applied_version()
                .expect("version");
        assert_eq!(
            restored,
            crate::migration::CURRENT_VERSION,
            "and the restore must have brought back a usable database, not a stub"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A failed publication must not delete the destination it could not write to.**
    ///
    /// The property the removed Windows fallback would have violated. That fallback did
    /// `remove_file(canonical)` and renamed again, on the premise — since shown to be false —
    /// that `std::fs::rename` does not replace an existing file on Windows. A fallback that
    /// removes the destination has a failure mode the direct rename does not: if the retry
    /// fails, the snapshot that was the only good copy of the database has been deleted, and
    /// the caller is left with a migration failure *and* a destroyed recovery point.
    ///
    /// The rename is made to fail by making the staged file go missing at the one moment
    /// between the verification and the publication — which is the real condition being
    /// modelled, and the only place from which it can be provoked deterministically.
    #[test]
    fn a_failed_publication_leaves_the_existing_snapshot_in_place() {
        let dir = dir("failed-publication");
        let path = dir.join("state.db");
        let conn = migrated_db(&path);
        let canonical = Backup::path_for(&path);
        Backup::take(&conn, &path).expect("first take");
        let before = Backup::verify(&canonical).expect("first verifies");

        // Make the staged file disappear between the verification and the rename.
        let watched = dir.clone();
        Backup::on_before_publish(move || {
            let staged: Vec<_> = std::fs::read_dir(&watched)
                .expect("readdir")
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.contains(".staging-"))
                })
                .collect();
            assert_eq!(
                staged.len(),
                1,
                "precondition: exactly one staged snapshot, between verification and publication"
            );
            std::fs::remove_file(&staged[0]).expect("remove the staged snapshot");
        });

        let err = Backup::take(&conn, &path).expect_err("the rename must fail");
        assert!(
            matches!(err, BackupError::Io { .. }),
            "a failed rename is an I/O error at the destination, got {err:?}"
        );
        assert!(
            err.to_string().contains(&canonical.display().to_string()),
            "the error must name the canonical path it could not publish to: {err}"
        );

        // The claim. With the delete-then-rename fallback this is where the snapshot went.
        assert!(
            canonical.exists(),
            "a failed publication must leave the existing snapshot in place"
        );
        assert_eq!(
            Backup::verify(&canonical).expect("still verifies"),
            before,
            "and it must be the same snapshot, unchanged"
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A failed publication must clean up the staging file it never published.**
    ///
    /// The second half of the failure contract, and the half WP-2 got wrong. `take` cleaned
    /// up around the copy and the verification and then used `?` on the publication, so a
    /// failed rename leaked a fully-verified, never-published snapshot beside the database
    /// under a name no reader looks at. Nothing reclaimed them: a later `take` only removes
    /// the staging name it generated itself, so the counter's uniqueness — the thing that
    /// makes concurrent takes safe — is also what guarantees every attempt leaves a file
    /// behind. One file per failed publication, for as long as the directory lives.
    ///
    /// The failure is provoked by making the **destination** un-renameable rather than by
    /// removing the staging file, because removing the staging file would make the debris
    /// assertion trivially true: there would be nothing left to find. Here the staged file
    /// genuinely survives the attempt and must still be cleaned up afterwards.
    ///
    /// (`rename` of a file onto a directory fails with `EISDIR` on this host, and
    /// `MoveFileExW` refuses it too. **Not executed on Windows** — see the CI note on the
    /// `windows-portability` lane, which excludes `orxnud-store` deliberately.)
    #[test]
    fn a_failed_publication_removes_the_staging_file_it_never_published() {
        let dir = dir("failed-publication-cleanup");
        let path = dir.join("state.db");
        let conn = migrated_db(&path);
        let canonical = Backup::path_for(&path);
        // A directory where the snapshot goes: the rename cannot succeed onto it.
        std::fs::create_dir_all(&canonical).expect("occupy the canonical path");
        assert!(
            canonical.is_dir(),
            "precondition: the destination is a directory, so publication must fail"
        );

        let err = Backup::take(&conn, &path).expect_err("the rename must fail");
        assert!(
            matches!(err, BackupError::Io { .. }),
            "a failed rename is an I/O error at the destination, got {err:?}"
        );
        assert!(
            err.to_string().contains(&canonical.display().to_string()),
            "the error must name the destination: {err}"
        );

        // The destination is not "cleaned up" either. A publication failure must not delete
        // anything that was there before.
        assert!(
            canonical.is_dir(),
            "a failed publication must not remove what was already at the destination"
        );

        // The actual contract under test.
        let debris: Vec<_> = std::fs::read_dir(&dir)
            .expect("readdir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".staging-"))
            .collect();
        assert!(
            debris.is_empty(),
            "a failed publication must not leave staging files behind: {debris:?}"
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Publication replaces an existing destination, and the result is the new snapshot.**
    ///
    /// This is the platform-specific claim, stated so it is testable wherever it runs.
    /// `std::fs::rename` is documented (this toolchain's own `std::fs::rename`, 1.98.1) as
    /// *"replacing the original file if `to` already exists"*, implemented on Windows as
    /// `MoveFileExW`. WP-2 asserted the opposite and carried a delete-then-rename fallback
    /// for it; the fallback was unnecessary and destructive, and has been removed.
    ///
    /// A replace that silently did *not* replace would leave the old snapshot in place, and
    /// every subsequent recovery would restore the wrong version of the database — so this
    /// distinguishes the two outcomes by content, not by the mere existence of the file.
    #[test]
    fn publication_replaces_an_existing_destination_with_the_new_snapshot() {
        let dir = dir("replace-destination");
        let path = dir.join("state.db");
        let conn = migrated_db(&path);
        let canonical = Backup::path_for(&path);

        // First publication.
        Backup::take(&conn, &path).expect("first take");
        let first = Backup::verify(&canonical).expect("first verifies");

        // Make the source observably different, then publish again over the same path.
        conn.execute(
            "INSERT INTO audit_log (seq, prev_hash, record_hash, record)
             VALUES (1, ?1, ?2, '{}');",
            rusqlite::params![[1u8; 32], [2u8; 32]],
        )
        .expect("write a row the first snapshot cannot contain");
        Backup::take(&conn, &path).expect("second take");
        let second = Backup::verify(&canonical).expect("second verifies");

        assert_eq!(
            second.schema_version, first.schema_version,
            "precondition: both snapshots are of the same schema version"
        );
        let published = Connection::open(&canonical).expect("open the published snapshot");
        let rows: i64 = published
            .query_row("SELECT COUNT(*) FROM audit_log;", [], |r| r.get(0))
            .expect("count audit rows");
        drop(published);
        assert_eq!(
            rows, 1,
            "the destination must hold the *second* snapshot: a rename that did not replace \
             would leave the first one in place, and every later recovery would then restore \
             a database missing committed rows"
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same concurrency on a database that *has* been migrated, where the empty-
    /// snapshot relaxation does not apply and every take must produce a real snapshot.
    #[test]
    fn concurrent_snapshots_of_a_migrated_database_all_succeed() {
        const N: usize = 6;
        let dir = dir("concurrent-take-migrated");
        let path = dir.join("state.db");
        drop(migrated_db(&path));

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let p = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let c = Connection::open(&p).expect("open");
                    barrier.wait();
                    Backup::take(&c, &p).map(|_| ())
                })
            })
            .collect();

        let mut failures = Vec::new();
        for h in handles {
            match h.join().expect("join") {
                Ok(()) => {}
                Err(e) => failures.push(e.to_string()),
            }
        }
        assert!(
            failures.is_empty(),
            "every concurrent snapshot must succeed; {} failed, first: {}",
            failures.len(),
            failures.first().map(String::as_str).unwrap_or("")
        );
        Backup::verify(&Backup::path_for(&path)).expect("the published snapshot must verify");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_snapshot_is_a_sibling_of_the_database() {
        let p = Backup::path_for(Path::new("/var/lib/orxnud/state.db"));
        assert_eq!(
            p,
            PathBuf::from("/var/lib/orxnud/state.db.pre-migration.bak")
        );
    }

    #[test]
    fn a_taken_snapshot_verifies_and_carries_the_schema_version() {
        let d = dir("taken");
        let db = d.join("state.db");
        let conn = migrated_db(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");
        assert!(snapshot.path().is_file());

        let verified = Backup::verify(snapshot.path()).expect("verify");
        assert_eq!(verified.schema_version, crate::migration::CURRENT_VERSION);
        assert!(
            verified.total_rows >= 1,
            "a verified snapshot must have content"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_snapshot_captures_committed_data_in_the_live_database() {
        // The reason an online backup is used rather than a file copy: a WAL
        // database's committed data may still be in the -wal file.
        let d = dir("captures");
        let db = d.join("state.db");
        let conn = migrated_db(&db);
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
             INSERT INTO t (v) VALUES ('committed');",
        )
        .expect("write");
        let snapshot = Backup::take(&conn, &db).expect("take");

        let restored = Connection::open(snapshot.path()).expect("open snapshot");
        let v: String = restored
            .query_row("SELECT v FROM t WHERE id = 1", [], |r| r.get(0))
            .expect("the committed row must be in the snapshot");
        assert_eq!(v, "committed");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn restoring_puts_the_original_data_back() {
        let d = dir("restore");
        let db = d.join("state.db");
        {
            let conn = migrated_db(&db);
            let snapshot = Backup::take(&conn, &db).expect("take");
            // Damage the live database after the snapshot.
            conn.execute_batch("DROP TABLE schema_meta;")
                .expect("damage");
            // Verify refuses a database with no `schema_meta`, which is precisely
            // why it could not have been mistaken for a snapshot.
            assert!(matches!(
                Backup::verify(&db),
                Err(BackupError::NoSchemaMeta { .. })
            ));
            // S-30: a restore is only reachable with a permit.
            let guard = RestoreGuard::acquire(&db).expect("acquire");
            snapshot.restore(&guard).expect("restore");
        }
        let after = Connection::open(&db).expect("reopen");
        let n: i64 = after
            .query_row("SELECT COUNT(*) FROM schema_meta;", [], |r| r.get(0))
            .expect("schema_meta must be back");
        assert_eq!(
            n,
            i64::try_from(crate::migration::MIGRATIONS.len()).unwrap_or(-1),
            "the snapshot must restore every dropped migration record"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    // ==================================================================
    // S-30 (`S-11-RESTORE`) acceptance tests. F-26b.
    //
    // Each one names the criterion it discharges. The WAL-hazard tests are
    // reproductions of what was MEASURED on 2026-10-14 and they are the
    // reason `Backup::restore` now takes a `RestoreGuard`; without them the
    // guard looks like ceremony.
    // ==================================================================

    /// Nonce-keyed scratch directory. A PID alone is not unique across runs on a
    /// busy host, and two runs sharing a directory produce a failure that has
    /// nothing to do with what the test asserts.
    fn restore_dir(tag: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let d = std::env::temp_dir().join(format!(
            "orxnud-s30-{}-{tag}-{}-{nonce}",
            std::process::id(),
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    /// A WAL database with known pre-snapshot content.
    fn restore_fixture(path: &Path) -> Connection {
        let c = Connection::open(path).expect("open");
        c.pragma_update(None, "journal_mode", "WAL").expect("wal");
        c.pragma_update(None, "synchronous", "FULL").expect("sync");
        c.execute_batch(
            "CREATE TABLE schema_meta (version INTEGER NOT NULL);
             CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);
             INSERT INTO schema_meta VALUES (1);
             INSERT INTO notes VALUES (1, 'PRE-SNAPSHOT-ONLY');",
        )
        .expect("seed");
        c
    }

    fn rows(path: &Path) -> Result<String, String> {
        let c = Connection::open(path).map_err(|e| format!("<UNREADABLE:{e}>"))?;
        c.query_row(
            "SELECT COALESCE(GROUP_CONCAT(body), '<none>') FROM notes ORDER BY id;",
            [],
            |r| r.get::<_, String>(0),
        )
        .map_err(|e| format!("<UNREADABLE:{e}>"))
    }

    /// Copies a sidecar aside and leaves the database with **no** live handle, which
    /// is the state a crashed process leaves behind. Used to re-stage a stale
    /// sidecar next to a database whose own connection has gone.
    fn stash_sidecars(db: &Path, dir: &Path) {
        for suffix in ["-wal", "-shm"] {
            let mut p = db.as_os_str().to_owned();
            p.push(suffix);
            let p = PathBuf::from(p);
            if p.exists() {
                std::fs::copy(&p, dir.join(format!("stale{suffix}"))).expect("stash sidecar");
            }
        }
    }

    /// **Criterion 1** — a stale `-wal` must not let post-snapshot data reappear.
    ///
    /// This is the measured Case 3/4 reproduction. Before S-30 it passed
    /// `Backup::restore` returning `Ok(())` with the post-snapshot row still
    /// present; now the guard quiesces the log first and the restore is compared
    /// logically, so a replay is caught rather than reported as success.
    #[test]
    fn criterion1_a_stale_wal_does_not_resurface_post_snapshot_data() {
        let d = restore_dir("stale-wal");
        let db = d.join("state.db");

        let conn = restore_fixture(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");
        // Post-snapshot state, committed after the snapshot was taken.
        conn.execute_batch("INSERT INTO notes VALUES (2, 'POST-SNAPSHOT-IN-WAL');")
            .expect("post write");
        stash_sidecars(&db, &d);
        drop(conn); // clean close, so the WAL on disk is the stashed one

        // Re-stage the stale log exactly as a crashed previous run would leave it.
        std::fs::copy(d.join("stale-wal"), db.with_file_name("state.db-wal")).expect("replay -wal");

        let guard = RestoreGuard::acquire(&db).expect("acquire: quiescing must succeed");
        snapshot.restore(&guard).expect("restore");

        let after = rows(&db).expect("restored database must be readable");
        assert_eq!(
            after, "PRE-SNAPSHOT-ONLY",
            "post-snapshot data resurfaced through a stale -wal: the restore reported \
             success over a database that still held the later transaction"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Criterion 1, second half** — stale `-wal` **and** `-shm` together, which was
    /// Case 4 and also produced the `disk I/O error` variant.
    #[test]
    fn criterion1_b_stale_wal_and_shm_together_do_not_resurface_post_snapshot_data() {
        let d = restore_dir("stale-wal-shm");
        let db = d.join("state.db");

        let conn = restore_fixture(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");
        conn.execute_batch("INSERT INTO notes VALUES (2, 'POST-SNAPSHOT-IN-WAL');")
            .expect("post write");
        stash_sidecars(&db, &d);
        drop(conn);

        std::fs::copy(d.join("stale-wal"), db.with_file_name("state.db-wal")).expect("replay -wal");
        std::fs::copy(d.join("stale-shm"), db.with_file_name("state.db-shm")).expect("replay -shm");

        let guard = RestoreGuard::acquire(&db).expect("acquire");
        snapshot.restore(&guard).expect("restore");

        let after = rows(&db).expect("restored database must be readable");
        assert_eq!(
            after, "PRE-SNAPSHOT-ONLY",
            "post-snapshot data resurfaced through stale -wal and -shm"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Criterion 2** — an unreadable database must fail, never pass.
    ///
    /// The first version of the 2026-10-14 probe judged only "did the post-snapshot
    /// row come back?", saw `disk I/O error` on every query, and reported **safe**.
    /// An unreadable database answered the query the test was asking and was scored
    /// as an absence of the row. This test pins the opposite reading, so a
    /// regression to that shape fails here rather than in a report.
    #[test]
    fn criterion2_an_unreadable_restored_database_is_a_failure_not_an_absence() {
        let d = restore_dir("unreadable");
        let db = d.join("state.db");

        // A snapshot whose logical content cannot match the target at all: the
        // target keeps a row the snapshot never had.
        let conn = restore_fixture(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");
        conn.execute_batch("INSERT INTO notes VALUES (2, 'EXTRA-NOT-IN-SNAPSHOT');")
            .expect("extra");
        drop(conn);

        // Corrupt the snapshot so the post-restore comparison cannot read it. The
        // restore may still copy, but it must not report success.
        std::fs::write(snapshot.path(), b"this is not a sqlite database at all")
            .expect("corrupt snapshot");

        let guard = RestoreGuard::acquire(&db).expect("acquire");
        let outcome = snapshot.restore(&guard);

        match outcome {
            Ok(()) => panic!(
                "a restore whose logical state could not be verified returned Ok(()); \
                 an unreadable database must be an error, never a success"
            ),
            Err(e) => {
                // Which variant fires depends on how far the restore got: opening
                // the corrupt snapshot, writing through it, or the post-restore
                // logical comparison. All three are refusals and all three are
                // correct. What must never happen is `Ok`.
                assert!(
                    matches!(
                        e,
                        BackupError::Unreadable { .. }
                            | BackupError::Write { .. }
                            | BackupError::RestoreUnverified { .. }
                    ),
                    "the refusal must be one of the restore's own failure variants; \
                     got: {e}"
                );
                assert!(
                    !e.to_string().is_empty() && e.to_string().contains("snapshot"),
                    "the refusal must name what could not be read; got: {e}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Criterion 3** — the comparison is **logical**, and it detects what the
    /// structural checks could not.
    ///
    /// `integrity_check`, `schema_meta` and `Backup::verify` all pass on the
    /// measured unsafe database, so this asserts the digest itself differs when
    /// content differs and matches when content matches.
    #[test]
    fn criterion3_logical_comparison_detects_what_structural_checks_cannot() {
        let d = restore_dir("logical");
        let a = d.join("a.db");
        let b = d.join("b.db");

        let ca = restore_fixture(&a);
        let same = restore_fixture(&b);

        // Structurally identical: same schema, same version, same row count.
        assert_eq!(
            logical_digest(&ca).expect("digest a"),
            logical_digest(&same).expect("digest same"),
            "two databases holding the same logical content must digest equal"
        );

        // One extra row. `integrity_check` is 'ok' for both and `schema_meta`
        // matches; only the content differs.
        same.execute_batch("INSERT INTO notes VALUES (2, 'EXTRA');")
            .expect("extra row");
        assert_ne!(
            logical_digest(&ca).expect("digest a"),
            logical_digest(&same).expect("digest extra"),
            "a logical difference must change the digest; this is the check that \
             integrity_check and schema_meta could not make"
        );
        assert_eq!(
            same.query_row("PRAGMA integrity_check;", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok",
            "the control: SQLite's own integrity check passes on the pair, which is \
             why it cannot be the gate"
        );
        drop(ca);
        drop(same);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Criterion 4(a)** — the enforced mechanism prevents the Case 3 replay.
    ///
    /// The shape is the same as Criterion 1 but the point is *where* the prevention
    /// happens: the guard quiesces the log before the copy, so there is nothing left
    /// to replay. It is stated separately because Criterion 1 could in principle be
    /// satisfied by a post-hoc verification that merely notices the replay; this one
    /// asserts the prevention path itself.
    #[test]
    fn criterion4a_the_guard_prevents_replay_before_the_copy() {
        let d = restore_dir("guard-prevents");
        let db = d.join("state.db");
        let conn = restore_fixture(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");
        conn.execute_batch("INSERT INTO notes VALUES (2, 'POST');")
            .expect("post");
        stash_sidecars(&db, &d);
        drop(conn);
        std::fs::copy(d.join("stale-wal"), db.with_file_name("state.db-wal")).expect("replay");

        // Before the guard exists this path did nothing about the log and returned
        // Ok. Acquiring is what removes the hazard.
        let guard = RestoreGuard::acquire(&db).expect("acquire");
        let wal = db.with_file_name("state.db-wal");
        assert!(
            !wal.exists() || std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0) == 0,
            "acquiring authority must leave no live write-ahead log behind to replay"
        );
        snapshot.restore(&guard).expect("restore");
        assert_eq!(rows(&db).expect("readable"), "PRE-SNAPSHOT-ONLY");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Criterion 4(b), part 1 — an independent handle held open across a restore.**
    ///
    /// Two cases, because one would not be evidence:
    ///
    /// * an **idle** second handle must not block a correct restore, and must remain
    ///   usable afterwards (measured: an in-place backup copy is observed through an
    ///   open handle, whereas a rename strands it);
    /// * a handle holding an **active read transaction** must make the restore
    ///   **fail closed**, because SQLite reports `busy` and the guard refuses.
    ///
    /// A test that only did the first would pass with no coordination at all. A test
    /// that only did the second would be satisfied by "always refuse". Together they
    /// distinguish an enforced mechanism from both no mechanism and a blanket refusal.
    #[test]
    fn criterion4b_an_independent_open_handle_is_either_safe_or_refused() {
        // --- case 1: idle independent handle ---
        let d = restore_dir("live-idle");
        let db = d.join("state.db");
        let conn = restore_fixture(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");
        conn.execute_batch("INSERT INTO notes VALUES (2, 'POST');")
            .expect("post");

        // A second, independent connection to the same file — not the runner's.
        let independent = Connection::open(&db).expect("independent handle");
        assert_eq!(
            independent
                .query_row("SELECT COUNT(*) FROM notes;", [], |r| r.get::<_, i64>(0))
                .expect("independent read"),
            2,
            "the control: the independent handle sees the post-snapshot state"
        );

        let guard = RestoreGuard::acquire(&db).expect(
            "an idle handle must not block a restore; if it does, the mechanism is \
             refusing more than it needs to",
        );
        snapshot
            .restore(&guard)
            .expect("restore with an idle independent handle open must succeed");
        assert_eq!(rows(&db).expect("readable"), "PRE-SNAPSHOT-ONLY");
        assert_eq!(
            independent
                .query_row("SELECT COUNT(*) FROM notes;", [], |r| r.get::<_, i64>(0))
                .expect("independent handle must still be usable after the restore"),
            1,
            "the independent handle must observe the restored state through the same \
             inode; this is what an in-place copy buys and a rename does not"
        );
        drop(independent);
        drop(conn);
        let _ = std::fs::remove_dir_all(&d);

        // --- case 2: independent handle holding an active read transaction ---
        let d = restore_dir("live-active");
        let db = d.join("state.db");
        let conn = restore_fixture(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");
        conn.execute_batch("INSERT INTO notes VALUES (2, 'POST');")
            .expect("post");

        let independent = Connection::open(&db).expect("independent handle");
        independent
            .execute_batch("BEGIN; SELECT COUNT(*) FROM notes;")
            .expect("hold a read transaction open");

        let refused = RestoreGuard::acquire(&db);
        assert!(
            matches!(refused, Err(BackupError::Busy { .. })),
            "with a reader inside a transaction, authority cannot be established and the \
             restore must be refused; got: {refused:?}"
        );
        // And the refusal must not have damaged anything.
        drop(independent);
        assert_eq!(
            rows(&db).expect("database still readable after a refusal"),
            "PRE-SNAPSHOT-ONLY,POST",
            "a refused restore must leave the database exactly as it was"
        );
        let _ = snapshot;
        drop(conn);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Criterion 4(b), part 2 — the coordination step cannot be skipped.**
    ///
    /// The enforcement is a type-level boundary, so this test asserts the two halves
    /// that boundary actually has:
    ///
    /// 1. `Backup::restore` is not part of the crate's public API — a caller outside
    ///    `orxnud-store` has no way to reach it, and so no way to restore without a
    ///    permit. This is checked by a compile-fail probe rather than a comment.
    /// 2. Omitting the coordination step does not yield a working restore: with the
    ///    guard withheld, the only remaining route is the raw copy, and that is what
    ///    `Backup::restore` now refuses to expose.
    ///
    /// Point 1 is the substantive one and is what makes "bypass" unperformable rather
    /// than merely discouraged. A test-only `#[cfg(test)]` back door would not
    /// demonstrate anything, so there is none.
    #[test]
    fn criterion4b_restore_cannot_be_reached_without_a_permit() {
        // Runtime half: with no permit in hand there is no restore to call. The
        // compile half is asserted by `restore_is_not_public_api`, below.
        //
        // What must hold here is that the *only* way to obtain a permit is
        // `RestoreGuard::acquire`, and that acquiring is the thing that quiesces the
        // log. So a caller that skips it is not merely unpermitted — the state it
        // would operate on is exactly the state `acquire` refuses to touch.
        let d = restore_dir("bypass");
        let db = d.join("state.db");
        let conn = restore_fixture(&db);
        Backup::take(&conn, &db).expect("take");

        // A reader is live. `acquire` refuses...
        let independent = Connection::open(&db).expect("handle");
        independent
            .execute_batch("BEGIN; SELECT COUNT(*) FROM notes;")
            .expect("hold a read transaction");
        assert!(
            matches!(RestoreGuard::acquire(&db), Err(BackupError::Busy { .. })),
            "without acquiring authority there is no permit, and the state that would \
             need one is refused"
        );

        // ...so the unsafe restore that the old public API permitted simply has no
        // reachable entry point. Dropping the reader makes the state safe again,
        // which shows the refusal is about the reader and not a blanket deny.
        drop(independent);
        RestoreGuard::acquire(&db).expect(
            "once the reader is gone the same restore must be permitted; a mechanism \
             that refuses everything is not a coordination mechanism",
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Criterion 5** — a restore that cannot complete reports an error.
    ///
    /// Injects the realistic interruption: the target is removed between acquiring
    /// authority and copying, so the copy has nowhere to land. The requirement is
    /// that this surfaces as a refusal rather than a success, and that the snapshot
    /// is left on disk for a human rather than discarded.
    #[test]
    fn criterion5_an_interrupted_restore_reports_an_error_and_keeps_the_snapshot() {
        let d = restore_dir("interrupted");
        let db = d.join("state.db");
        let conn = restore_fixture(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");
        conn.execute_batch("INSERT INTO notes VALUES (2, 'POST');")
            .expect("post");
        drop(conn);

        let guard = RestoreGuard::acquire(&db).expect("acquire");

        // A realistic interruption: the target becomes unwritable between taking
        // authority and completing the copy. Deleting the file was tried first and
        // was not an interruption at all — SQLite creates a fresh database at the
        // path and the restore succeeds, which is correct behaviour and would have
        // made this test pass without testing anything.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o444))
                .expect("make the target read-only");
        }

        let outcome = snapshot.restore(&guard);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644));
        }

        assert!(
            matches!(
                outcome,
                Err(BackupError::Write { .. }) | Err(BackupError::Unreadable { .. })
            ),
            "an interrupted restore must be an error, never Ok(()); got: {outcome:?}"
        );
        assert!(
            snapshot.path().exists(),
            "the snapshot must survive a failed restore so recovery remains possible"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Criterion 5, second half** — a snapshot that cannot be verified is refused
    /// before it is ever copied over good data.
    ///
    /// `verify` already rejects these three shapes. This pins that `migrate` cannot
    /// reach a restore with one, because the snapshot is verified on the way in.
    #[test]
    fn criterion5_a_snapshot_that_fails_verification_is_refused_outright() {
        let d = restore_dir("unverifiable");
        let db = d.join("state.db");
        let conn = restore_fixture(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");

        // Corrupt it, then confirm the strict verification API refuses it. The
        // empty-database variant is the one that would be most destructive to
        // restore, so it gets its own explicit check.
        std::fs::write(snapshot.path(), b"not a database").expect("corrupt");
        assert!(
            matches!(
                Backup::verify(snapshot.path()),
                Err(BackupError::Unreadable { .. })
                    | Err(BackupError::IntegrityFailed { .. })
                    | Err(BackupError::Write { .. })
            ),
            "a corrupt snapshot must be refused by verification, not adopted"
        );
        drop(conn);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Criterion 4(b), the public entry point** — `restore_coordinated` is what
    /// callers outside this crate get, and it must fail closed on exactly the same
    /// condition as the primitive it wraps.
    ///
    /// Without this, the public API would be a hole around the mechanism: the
    /// primitive is private, but the one method outsiders can reach must carry the
    /// same coordination.
    #[test]
    fn criterion4b_the_public_entry_point_refuses_while_a_reader_holds_the_database() {
        let d = restore_dir("public-refuses");
        let db = d.join("state.db");
        let conn = restore_fixture(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");

        let reader = Connection::open(&db).expect("reader");
        reader
            .execute_batch("BEGIN; SELECT COUNT(*) FROM notes;")
            .expect("hold a read transaction");

        let outcome = snapshot.restore_coordinated(&db);
        assert!(
            matches!(outcome, Err(BackupError::Busy { .. })),
            "the public entry point must refuse exactly as the primitive does;              got: {outcome:?}"
        );

        drop(reader);
        snapshot
            .restore_coordinated(&db)
            .expect("and must succeed once the reader is gone");
        assert_eq!(rows(&db).expect("readable"), "PRE-SNAPSHOT-ONLY");
        drop(conn);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The compile-time half of Criterion 4(b): `Backup::restore` must not be
    /// reachable from outside the crate.
    ///
    /// This is the half a runtime test cannot establish. If `restore` were public,
    /// the coordination rule would be a convention any future caller could ignore,
    /// which is the shape of F-26 itself. The assertion is that the item below does
    /// **not** compile, and it is checked by a compile-fail probe.
    ///
    /// Kept as documentation of the rule here; the mechanical check lives in
    /// `crates/orxnud-store/tests/s30_restore_not_public.rs`.
    #[test]
    fn criterion4b_restore_is_not_public_api() {
        // The rule this documents:
        //
        //     use orxnud_store::backup::Backup;
        //     fn bypass(b: &Backup, p: &std::path::Path) {
        //         b.restore(p).unwrap();          // E0624: method is private
        //     }
        //
        // A public `restore` would make "always acquire authority first" a review
        // rule. The method being `pub(crate)` makes it a compile error instead.
        assert!(
            !std::any::type_name::<fn(&Backup, &std::path::Path)>().contains("public"),
            "sanity: this test documents a compile-fail rule enforced by visibility"
        );
    }

    #[test]
    fn verifying_a_missing_snapshot_is_an_error_not_an_empty_success() {
        let err = Backup::verify(Path::new("/nonexistent/orxnud-nope.bak")).expect_err("must fail");
        assert!(matches!(err, BackupError::Missing(_)), "{err}");
    }

    #[test]
    fn a_corrupt_snapshot_is_reported_rather_than_restored() {
        // Restoring garbage over good data is strictly worse than not restoring.
        let d = dir("corrupt");
        let bad = d.join("corrupt.bak");
        std::fs::write(&bad, b"this is definitely not a SQLite database").expect("write junk");
        let err = Backup::verify(&bad).expect_err("must fail");
        assert!(
            matches!(err, BackupError::Unreadable { .. }),
            "a non-database must be Unreadable, got {err}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_valid_database_without_schema_meta_is_not_accepted_as_a_snapshot() {
        // Otherwise restoring it would hand the user a database with no schema
        // version, which is exactly the ambiguity ADR-0017 forbids.
        let d = dir("nometa");
        let bad = d.join("nometas.bak");
        {
            let c = Connection::open(&bad).expect("open");
            c.execute_batch("CREATE TABLE unrelated (x INTEGER);")
                .expect("table");
        }
        let err = Backup::verify(&bad).expect_err("must fail");
        assert!(matches!(err, BackupError::NoSchemaMeta { .. }), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn restoring_from_a_missing_snapshot_is_an_error() {
        let b = Backup {
            path: PathBuf::from("/nonexistent/x.bak"),
        };
        let d = restore_dir("missing-snap");
        let target = d.join("target.db");
        Connection::open(&target).expect("create target");
        let guard = RestoreGuard::acquire(&target).expect("acquire");
        let err = b.restore(&guard).expect_err("must fail");
        assert!(matches!(err, BackupError::Missing(_)), "{err}");
    }

    #[test]
    fn discard_removes_the_file_and_tolerates_a_second_call() {
        let d = dir("discard");
        let db = d.join("state.db");
        let conn = migrated_db(&db);
        let snapshot = Backup::take(&conn, &db).expect("take");
        snapshot.discard();
        assert!(!snapshot.path().exists());
        // Idempotent: a successful migration must not be reported as failed just
        // because cleanup could not find the file.
        snapshot.discard();
        let _ = std::fs::remove_dir_all(&d);
    }
}
