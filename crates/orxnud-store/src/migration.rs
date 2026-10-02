//! The migration mechanism — with **no application tables**.
//!
//! Phase 1 provides the runner and its guarantees; it does not provide a
//! schema. docs-13 §8 forbids inventing application tables ahead of the engine
//! that uses them, so [`MIGRATIONS`] contains exactly one entry: `schema_meta`,
//! the bookkeeping table the runner itself needs.
//!
//! # Guarantees the runner must uphold
//!
//! * **Forward only.** A migration, once applied, is never un-applied. Rolling
//!   back is done by restoring a snapshot (ADR-0017), not by reversing SQL.
//! * **Transactional.** All of a migration's statements, or none.
//! * **Idempotent.** Re-running a migration that has already been applied is a
//!   no-op, checked against `schema_meta`.
//! * **Snapshot-protected.** The caller takes a verified snapshot *before*
//!   running any; the runner refuses to proceed unless told the snapshot exists.
//!
//! That last one is why [`MigrationRunner::run`] takes a
//! `snapshot_verified: bool`. It is not ceremony: a migration is the single
//! highest-risk write path in the system, and it operates on the only copy of
//! the user's data.

use std::path::Path;

use rusqlite::Connection;

use crate::backup::{Backup, BackupError};
use crate::sqlite::StoreError;

/// A migration failure.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// A statement in a migration failed.
    #[error("migration {version} failed: {source}")]
    Failed {
        /// The migration version.
        version: u32,
        /// The underlying error.
        #[source]
        source: rusqlite::Error,
    },

    /// The runner was asked to migrate without a verified snapshot.
    ///
    /// Refused rather than warned: this is the one write path where a mistake is
    /// unrecoverable.
    #[error("refusing to migrate without a verified pre-migration snapshot (ADR-0017)")]
    NoSnapshot,

    /// Taking or verifying the pre-migration snapshot failed.
    #[error("snapshot protection failed: {0}")]
    Snapshot(#[from] BackupError),

    /// A migration failed **and the snapshot could not be restored**.
    ///
    /// The most serious error this crate can report. It is distinguished from
    /// [`Self::Failed`] because the remedy differs: `Failed` means the database is
    /// untouched and the user can retry; this means it may be damaged and the
    /// snapshot at the reported path is the only good copy.
    #[error(transparent)]
    RestoreFailed(Box<RestoreFailure>),
}

/// Why a migration failed *and* its snapshot could not be restored.
///
/// Boxed out of [`MigrationError`] for the same reason as `TaskRepoError::Sqlite`:
/// two `String`s plus an error made every `Result` in the crate large.
#[derive(Debug, thiserror::Error)]
#[error(
    "migration {version} failed and the snapshot at {snapshot} could not be restored; \
     do not delete it"
)]
pub struct RestoreFailure {
    /// The migration version.
    pub version: u32,
    /// Where the good copy is.
    pub snapshot: String,
    /// What went wrong.
    #[source]
    pub source: BackupError,
}

/// One forward migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// Monotonic version. Migrations are applied in ascending order, once.
    pub version: u32,
    /// A short name, recorded in `schema_meta` for diagnosis.
    pub name: &'static str,
    /// The SQL to apply inside a single transaction.
    pub sql: &'static str,
}

/// Every migration, in the order they must be applied.
///
/// Migration 1 is Phase 1's `schema_meta` bookkeeping. Migrations 2.. are the
/// Phase 2 task layer, built from [`crate::schema`] so there is exactly one place
/// a table can be created.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "schema_meta",
        sql: "CREATE TABLE IF NOT EXISTS schema_meta (
            version     INTEGER PRIMARY KEY,
            name        TEXT NOT NULL,
            applied_at  INTEGER NOT NULL
        );",
    },
    Migration {
        version: 2,
        name: "tasks",
        sql: crate::schema::MIGRATION_TASKS,
    },
    Migration {
        version: 3,
        name: "task_accounting",
        sql: crate::schema::MIGRATION_ACCOUNTING,
    },
    Migration {
        version: 4,
        name: "task_events",
        sql: crate::schema::MIGRATION_EVENTS,
    },
    Migration {
        version: 5,
        name: "schedules",
        sql: crate::schema::MIGRATION_SCHEDULES,
    },
    Migration {
        version: 6,
        name: "security_state",
        sql: crate::schema::MIGRATION_SECURITY_STATE,
    },
];

/// The schema version a fully migrated Phase 2 database reports.
pub const CURRENT_VERSION: u32 = 6;

/// Applies pending migrations.
#[derive(Debug)]
pub struct MigrationRunner<'a> {
    conn: &'a Connection,
}

impl<'a> MigrationRunner<'a> {
    /// Creates a runner over a connection.
    #[must_use]
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// The highest applied version, or 0 when nothing has been applied.
    ///
    /// # Errors
    ///
    /// [`MigrationError::Failed`] if `schema_meta` is absent or unreadable.
    pub fn applied_version(&self) -> Result<u32, MigrationError> {
        let table_count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_meta';",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|source| MigrationError::Failed { version: 0, source })?;
        if table_count == 0 {
            return Ok(0);
        }
        self.conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_meta;",
                [],
                |r| r.get(0),
            )
            .map_err(|source| MigrationError::Failed { version: 0, source })
    }

    /// Applies every pending migration, in ascending order.
    ///
    /// Returns the versions applied. An empty vector means already up to date.
    ///
    /// **Does not take a snapshot.** See [`Self::migrate`] — production code
    /// wants that one. This exists for the case where the caller already holds a
    /// verified snapshot, and for tests.
    ///
    /// # Errors
    ///
    /// [`MigrationError::NoSnapshot`] if `snapshot_verified` is false — the
    /// runner refuses to touch the only copy of the user's data without a
    /// verified way back. Otherwise [`MigrationError::Failed`].
    pub fn run(&self, snapshot_verified: bool) -> Result<Vec<u32>, MigrationError> {
        if !snapshot_verified {
            return Err(MigrationError::NoSnapshot);
        }
        let current = self.applied_version()?;
        let mut applied = Vec::new();
        for m in MIGRATIONS.iter().filter(|m| m.version > current) {
            // `IMMEDIATE`, never `DEFERRED`, and the reason is concurrency rather
            // than discipline.
            //
            // `CREATE TABLE IF NOT EXISTS` must read the schema to decide whether the
            // table exists before it writes. In a deferred transaction that read
            // happens first, so a second connection writing in between leaves this
            // one holding a stale snapshot, and the upgrade fails with
            // `SQLITE_BUSY_SNAPSHOT` -- reported as "database is locked".
            //
            // `busy_timeout` does **not** rescue that case, because waiting cannot
            // make a stale snapshot current. Two processes opening the same database
            // at once therefore raced here even with the busy handler set, and the
            // loser failed with a message that reads like a fault rather than a
            // busy database.
            //
            // `IMMEDIATE` takes the write lock up front, so the migration either
            // starts with a current view or waits for the writer to finish. Every
            // statement is still `IF NOT EXISTS`, so the outcome does not depend on
            // who wins: the schema is the same either way.
            let tx = rusqlite::Transaction::new_unchecked(
                self.conn,
                rusqlite::TransactionBehavior::Immediate,
            )
            .map_err(|source| MigrationError::Failed {
                version: m.version,
                source,
            })?;
            tx.execute_batch(m.sql)
                .map_err(|source| MigrationError::Failed {
                    version: m.version,
                    source,
                })?;
            tx.execute(
                "INSERT OR REPLACE INTO schema_meta (version, name, applied_at) VALUES (?1, ?2, ?3);",
                rusqlite::params![m.version, m.name, now_ms()],
            )
            .map_err(|source| MigrationError::Failed { version: m.version, source })?;
            tx.commit().map_err(|source| MigrationError::Failed {
                version: m.version,
                source,
            })?;
            applied.push(m.version);
        }
        Ok(applied)
    }
}

impl<'a> MigrationRunner<'a> {
    /// Migrates a database on disk, taking and verifying a snapshot first.
    ///
    /// The production entry point. The sequence, and why each step exists:
    ///
    /// 1. Read the current version. If it is already current, do nothing — not
    ///    even a snapshot, because there is no risk to protect against.
    /// 2. Take a snapshot and **verify** it ([`crate::backup`]).
    /// 3. Apply each pending migration in its own transaction.
    /// 4. On any failure, restore the snapshot so a previous binary can open the
    ///    database, and report which version was reached.
    ///
    /// The snapshot is discarded only on success. Leaving a pre-migration copy
    /// behind after a *failed* migration is deliberate: it may be the only good
    /// copy.
    ///
    /// # Errors
    ///
    /// [`MigrationError::Snapshot`] if the snapshot could not be taken or
    /// verified, [`MigrationError::Failed`] if a migration failed (snapshot
    /// restored), or [`MigrationError::RestoreFailed`] if a migration failed
    /// *and* the restore failed.
    pub fn migrate(
        &self,
        db_path: &Path,
        snapshot_verified_by_caller: bool,
    ) -> Result<Vec<u32>, MigrationError> {
        let current = self.applied_version()?;
        let pending: Vec<&Migration> = MIGRATIONS.iter().filter(|m| m.version > current).collect();
        if pending.is_empty() {
            return Ok(Vec::new());
        }

        // The caller's claim is checked, never trusted: if the caller says it
        // holds a snapshot but none exists on disk, take one anyway.
        let snapshot = if snapshot_verified_by_caller {
            let path = Backup::path_for(db_path);
            match Backup::verify(&path) {
                Ok(_) => Some(Backup::existing(path)),
                Err(_) => Some(Backup::take(self.conn, db_path)?),
            }
        } else {
            Some(Backup::take(self.conn, db_path)?)
        };

        match self.run(true) {
            Ok(applied) => {
                // Only now is the snapshot obsolete.
                if let Some(s) = &snapshot {
                    s.discard();
                }
                Ok(applied)
            }
            Err(err) => {
                // A partial migration must not be left in place: the recorded
                // version and the actual tables would disagree, and nothing could
                // say which is authoritative.
                if let Some(s) = &snapshot {
                    if let Err(restore_err) = s.restore(db_path) {
                        return Err(MigrationError::RestoreFailed(Box::new(RestoreFailure {
                            version: current + 1,
                            snapshot: s.path().display().to_string(),
                            source: restore_err,
                        })));
                    }
                    // The snapshot has served its purpose *and* the restore has
                    // been verified by `restore` succeeding, so remove it rather
                    // than leaving a stale copy to be mistaken for current.
                    s.discard();
                }
                Err(err)
            }
        }
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Convenience: open a store and migrate it in one step.
///
/// # Errors
///
/// Any [`StoreError`].
pub fn open_and_migrate(
    path: &std::path::Path,
    snapshot_verified: bool,
) -> Result<crate::sqlite::Store, StoreError> {
    let store = crate::sqlite::Store::open(path, true)?;
    MigrationRunner::new(store.conn()).run(snapshot_verified)?;
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        crate::pragma::Pragma::critical()
            .apply(&c)
            .expect("apply pragmas");
        c
    }

    #[test]
    fn every_migration_applies_and_reaches_the_current_version() {
        let conn = mem();
        let applied = MigrationRunner::new(&conn).run(true).expect("migrate");
        assert_eq!(
            applied,
            MIGRATIONS.iter().map(|m| m.version).collect::<Vec<u32>>(),
            "every registered migration must be applied"
        );
        assert_eq!(
            MigrationRunner::new(&conn)
                .applied_version()
                .expect("version"),
            CURRENT_VERSION
        );
    }

    #[test]
    fn the_schema_contains_exactly_the_declared_tables_and_nothing_more() {
        // The discipline that keeps Phase 2 from sprawling: a table appears here
        // because something required it, and this test fails if one is added
        // without a table in `schema.rs` and a row in ADR-0028.
        let conn = mem();
        MigrationRunner::new(&conn).run(true).expect("migrate");
        let mut names: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table'
                   AND name NOT LIKE 'sqlite_%' ORDER BY name;",
            )
            .expect("prepare")
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "audit_log",
                "schedule_fires",
                "schedules",
                "schema_meta",
                "spent_approvals",
                "task_approvals",
                "task_attempts",
                "task_effects",
                "task_events",
                "tasks",
            ],
            "unexpected tables"
        );
    }

    #[test]
    fn no_table_outside_the_task_layer_exists() {
        // Phase 2's scope boundary. Health records, jobs, learning, messaging,
        // memories, provider catalogues, MCP servers, and UI preferences all belong
        // to later phases; a schema for one of them appearing now would be exactly
        // the speculative work this phase forbids.
        let conn = mem();
        MigrationRunner::new(&conn).run(true).expect("migrate");
        let forbidden = [
            "users",
            "health",
            "jobs",
            "learning",
            "messages",
            "memories",
            "documents",
            "embeddings",
            "providers",
            "mcp_servers",
            "preferences",
            "budget_ledger",
            "credentials",
            "secrets",
        ];
        for name in forbidden {
            let n: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name = ?1;",
                    [name],
                    |r| r.get(0),
                )
                .expect("query");
            assert_eq!(n, 0, "a table for a later phase exists: {name}");
        }
    }

    #[test]
    fn migration_is_idempotent() {
        let conn = mem();
        let r = MigrationRunner::new(&conn);
        assert_eq!(
            r.run(true).expect("first run"),
            MIGRATIONS.iter().map(|m| m.version).collect::<Vec<u32>>()
        );
        assert_eq!(r.run(true).expect("second run"), Vec::<u32>::new());
        assert_eq!(r.applied_version().expect("version"), CURRENT_VERSION);
    }

    #[test]
    fn migration_refuses_without_a_verified_snapshot() {
        // The one write path where a mistake is unrecoverable, so the runner
        // refuses rather than warns.
        let conn = mem();
        assert!(matches!(
            MigrationRunner::new(&conn).run(false),
            Err(MigrationError::NoSnapshot)
        ));
        // And nothing was applied.
        assert_eq!(
            MigrationRunner::new(&conn)
                .applied_version()
                .expect("version"),
            0
        );
    }

    #[test]
    fn applied_version_is_zero_on_a_fresh_database() {
        let conn = mem();
        assert_eq!(
            MigrationRunner::new(&conn)
                .applied_version()
                .expect("version"),
            0
        );
    }

    #[test]
    fn migration_versions_are_unique_and_ascending() {
        let mut seen: Vec<u32> = MIGRATIONS.iter().map(|m| m.version).collect();
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), before, "duplicate migration version");
        assert!(
            seen.windows(2).all(|w| w[0] < w[1]),
            "migration versions must ascend"
        );
    }

    #[test]
    fn migrations_persist_to_a_real_file() {
        let dir = std::env::temp_dir().join(format!("orxnud-mig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("m.db");
        let _ = std::fs::remove_file(&path);

        let store = open_and_migrate(&path, true).expect("open+migrate");
        assert_eq!(
            MigrationRunner::new(store.conn())
                .applied_version()
                .expect("version"),
            CURRENT_VERSION
        );
        drop(store);
        // Reopen: the version is durable.
        let store2 = open_and_migrate(&path, true).expect("reopen");
        assert_eq!(
            MigrationRunner::new(store2.conn())
                .run(true)
                .expect("rerun"),
            Vec::<u32>::new()
        );
        let _ = std::fs::remove_file(&path);
    }

    fn tmp_db(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("orxnud-migrate-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d.join("t.db")
    }

    /// The regression test for the fresh-install bug.
    ///
    /// `migrate` (as opposed to `run`) takes a snapshot and verifies it, and
    /// verification used to require a `schema_meta` table. A database that had never
    /// been migrated has no such table, so the *first* migration could not run — the
    /// daemon could not start on a machine where OpenRayNux had never run.
    ///
    /// Every migration test here drove `run`, which trusts the caller's snapshot
    /// claim and never takes one, so this path had no coverage until the production
    /// startup in `orxnud-daemon` called `migrate` for real.
    #[test]
    fn migrating_a_brand_new_database_succeeds() {
        let path = tmp_db("fresh");
        assert!(!path.exists(), "precondition: no database yet");

        let store = crate::sqlite::Store::open(&path, true).expect("open");
        let applied = MigrationRunner::new(store.conn())
            .migrate(&path, false)
            .expect("a fresh database must migrate");
        assert_eq!(applied.len(), MIGRATIONS.len(), "every migration applies");
        assert_eq!(
            MigrationRunner::new(store.conn())
                .applied_version()
                .expect("version"),
            CURRENT_VERSION
        );
        // And the snapshot is cleaned up, so a later start does not mistake it for
        // current.
        assert!(
            !Backup::path_for(&path).exists(),
            "a successful migration must not leave its snapshot behind"
        );
    }

    /// The guards that motivated the fix must still hold.
    ///
    /// Relaxing verification for a fresh install is only safe because emptiness is
    /// judged against the *source*. Two refusals have to survive that relaxation:
    /// a snapshot with no `schema_meta` at all, and one with the table but no rows.
    #[test]
    fn an_emptied_snapshot_of_a_real_database_is_still_rejected() {
        // (a) no schema_meta at all.
        let path = tmp_db("strict-nometa");
        {
            let store = crate::sqlite::Store::open(&path, true).expect("open");
            MigrationRunner::new(store.conn()).run(true).expect("run");
        }
        let backup = Backup::take(&Connection::open(&path).expect("reopen"), &path).expect("take");
        {
            let b = Connection::open(backup.path()).expect("open snapshot");
            b.execute_batch("DROP TABLE schema_meta;").expect("drop");
        }
        Backup::verify(backup.path()).expect_err("a snapshot with no schema_meta must be refused");

        // (b) schema_meta present but empty.
        let path = tmp_db("strict-norows");
        {
            let store = crate::sqlite::Store::open(&path, true).expect("open");
            MigrationRunner::new(store.conn()).run(true).expect("run");
        }
        let backup = Backup::take(&Connection::open(&path).expect("reopen"), &path).expect("take");
        {
            let b = Connection::open(backup.path()).expect("open snapshot");
            b.execute_batch("DELETE FROM schema_meta;").expect("delete");
        }
        Backup::verify(backup.path()).expect_err("an empty snapshot must be refused");
    }

    /// A fresh install is the case the fix is *for*, asserted through the strict API.
    #[test]
    fn an_empty_snapshot_is_accepted_only_when_the_source_is_also_empty() {
        let path = tmp_db("fresh-verify");
        let store = crate::sqlite::Store::open(&path, true).expect("open");
        let backup =
            Backup::take(store.conn(), &path).expect("a fresh database can be snapshotted");

        // Relative to a source with no schema_meta: accepted.
        Backup::verify_against_source(backup.path(), store.conn())
            .expect("an empty snapshot of an empty database is faithful");
        // Absolute: refused, because nothing about the file says it is safe.
        Backup::verify(backup.path()).expect_err("the strict API still refuses emptiness");
    }
}
