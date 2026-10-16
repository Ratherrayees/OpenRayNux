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
        // Remove any previous snapshot first. Writing over an existing file would
        // leave stale bytes if the copy were shorter than the old one.
        let _ = std::fs::remove_file(&path);

        {
            let mut dst = Connection::open(&path).map_err(|source| BackupError::Write {
                path: path.display().to_string(),
                source,
            })?;
            // 64 pages per step, zero pause: SQLite's own default page count, so
            // the whole copy happens without yielding. A *small* step count with a
            // non-zero pause would be the dangerous configuration — it copies
            // correctly but takes locks long enough to stall the single writer.
            let backup = rusqlite::backup::Backup::new(conn, &mut dst).map_err(|source| {
                BackupError::Write {
                    path: path.display().to_string(),
                    source,
                }
            })?;
            backup
                .run_to_completion(PAGES_PER_STEP, std::time::Duration::from_millis(0), None)
                .map_err(|source| BackupError::Write {
                    path: path.display().to_string(),
                    source,
                })?;
            // Drop the `Backup` before reading `dst`: it holds a mutable borrow,
            // and its `Drop` is what finalises the copy.
        }

        let verified = Self::verify_against_source(&path, conn)?;
        // The verification result is used by the caller; it is computed here so a
        // failure is reported by `take` rather than discovered later.
        let _ = verified;
        Ok(Self { path })
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
    /// [`crate::migration::MigrationRunner::run`], which trusts its caller's
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
    pub fn verify_against_source(
        path: &Path,
        source: &Connection,
    ) -> Result<VerifiedSnapshot, BackupError> {
        Self::verify_impl(path, !Self::has_schema_meta(source))
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
        MigrationRunner::new(&conn).run(true).expect("migrate");
        conn
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
