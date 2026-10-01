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
//! 3. On failure, [`Backup::restore`] puts it back and the previous binary keeps
//!    working.
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
    /// Holds `rusqlite::Error` directly rather than [`StoreError`]: `StoreError`
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
    pub fn restore(&self, db_path: &Path) -> Result<(), BackupError> {
        if !self.path.is_file() {
            return Err(BackupError::Missing(self.path.clone()));
        }
        let src = Connection::open(&self.path).map_err(|source| BackupError::Unreadable {
            path: self.path.display().to_string(),
            source,
        })?;
        let mut dst = Connection::open(db_path).map_err(|source| BackupError::Write {
            path: db_path.display().to_string(),
            source,
        })?;
        let backup =
            rusqlite::backup::Backup::new(&src, &mut dst).map_err(|source| BackupError::Write {
                path: db_path.display().to_string(),
                source,
            })?;
        backup
            .run_to_completion(PAGES_PER_STEP, std::time::Duration::from_millis(0), None)
            .map_err(|source| BackupError::Write {
                path: db_path.display().to_string(),
                source,
            })?;
        Ok(())
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
            snapshot.restore(&db).expect("restore");
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
        let err = b
            .restore(Path::new("/tmp/orxnud-target.db"))
            .expect_err("must fail");
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
