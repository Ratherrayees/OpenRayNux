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
    Migration {
        // Representation only. Nothing reads these columns until stage 3, and a task
        // created after this migration still takes exactly one action because
        // `max_steps` defaults to 1.
        version: 7,
        name: "task_composition",
        sql: crate::schema::MIGRATION_COMPOSITION,
    },
    Migration {
        // Corrects stage 2's reading of `attempt_no` as a step number. Forward, because a
        // database already at version 7 holds the bad index and the wrong numbering.
        version: 8,
        name: "task_composition_correction",
        sql: crate::schema::MIGRATION_COMPOSITION_CORRECTION,
    },
    Migration {
        // Widens `task_attempts`' primary key to include the logical step, because the
        // attempt counter is per-step. Forward, because a database already at version 8
        // holds the narrower key and every step after the first would collide on it.
        version: 9,
        name: "task_attempt_step_scope",
        sql: crate::schema::MIGRATION_ATTEMPT_STEP_SCOPE,
    },
    Migration {
        // The same widening `task_approvals` was owed and did not get in version 9. Every
        // logical step starts its attempt counter again, so a second step's approval
        // collided with the first step's on `(task_id, attempt_no)` and was silently
        // dropped by an `INSERT OR IGNORE`. Forward, for the same reason as version 9.
        version: 10,
        name: "task_approval_step_scope",
        sql: crate::schema::MIGRATION_APPROVAL_STEP_SCOPE,
    },
    Migration {
        // V-93. Records, per side effect, whether repeating *that effect* is safe.
        // `tasks.idempotent` cannot answer it: a task is created before the capability
        // that will run on it is chosen, and the daemon's default task kind is `query`,
        // so most tasks are flagged idempotent at the task level regardless of what
        // they are about to do. Recovery needs the capability's own declaration, and
        // the dispatcher is the only place that knows it -- so it is written into the
        // ledger where recovery can read it. Forward, for the same reason as 9 and 10:
        // a database already at version 10 holds effects with no repeat-safety recorded,
        // and the column defaults those to `0`, which is the fail-closed reading.
        version: 11,
        name: "task_effect_idempotency",
        sql: crate::schema::MIGRATION_EFFECT_IDEMPOTENCY,
    },
];

/// The schema version a fully migrated Phase 2 database reports.
pub const CURRENT_VERSION: u32 = 11;

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
        Self::applied_version_on(self.conn)
    }

    /// Whether one specific version has already been recorded, read through a
    /// transaction that is about to write.
    ///
    /// Separate from [`Self::applied_version`] because the check has to happen **inside**
    /// the `IMMEDIATE` transaction that applies the migration; reading it before the lock
    /// is what let two processes both decide to apply the same non-idempotent statement.
    fn applied_version_on(conn: &Connection) -> Result<u32, MigrationError> {
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_meta';",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|source| MigrationError::Failed { version: 0, source })?;
        if table_count == 0 {
            return Ok(0);
        }
        conn.query_row(
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
        let mut applied = Vec::new();
        for m in MIGRATIONS {
            // Re-checked **inside** the transaction, per migration, rather than filtered
            // once against a version read before the loop.
            //
            // The lock makes execution serial, but it does not make a pre-loop read
            // current: two processes can both observe version 6, both queue on the
            // `IMMEDIATE` lock, and the loser then runs a migration the winner has already
            // applied. With `IF NOT EXISTS` statements that was invisible -- the loser
            // simply re-created what existed. The first migration that is *not*
            // idempotent (`ALTER TABLE ... ADD COLUMN`, which SQLite has no
            // `IF NOT EXISTS` form of) turns that latent race into a hard failure:
            // "duplicate column name".
            //
            // Reading the version under the same transaction that records it makes
            // "has this been applied?" and "apply it" one atomic decision, which is the
            // property the loop was already assuming.
            //
            // Done as a cheap pre-filter on the in-transaction value so the common
            // up-to-date case still opens no write transaction per migration.
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
            if Self::applied_version_on(&tx)? >= m.version {
                // Another process applied it while this one waited for the lock.
                continue;
            }
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

    /// Brings a connection up to exactly `version`, as if it had been migrated by an
    /// older build. Used to prove the correction applies to a database that is already at
    /// the stage-2 version, which is the case that actually matters.
    fn migrate_to(conn: &Connection, version: u32) {
        // Skipping what is already recorded is what makes this a faithful simulation of an
        // older build rather than a second full run: a real runner would not re-apply
        // migration 7, and a helper that did would fail on its own non-idempotent ALTERs.
        let applied: u32 = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_meta;",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        for m in MIGRATIONS
            .iter()
            .filter(|m| m.version <= version && m.version > applied)
        {
            conn.execute_batch(m.sql).expect("migration sql");
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta (version, name, applied_at) VALUES (?1, ?2, 0);",
                rusqlite::params![m.version, m.name],
            )
            .expect("record");
        }
    }

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

    /// The columns stage 2 added, and the guarantee each one is supposed to carry.
    ///
    /// Written as a table rather than three separate tests because the interesting claim
    /// is the *set*: a migration that added `max_steps` but not `steps_completed` would
    /// pass a test that only checked the first.
    #[test]
    fn composition_columns_exist_on_a_fresh_database_with_their_defaults() {
        let conn = mem();
        MigrationRunner::new(&conn).run(true).expect("migrate");

        for (table, column, default) in [
            ("tasks", "max_steps", 1),
            ("tasks", "steps_completed", 0),
            ("task_proposals", "step_no", 1),
            ("task_approvals", "step_no", 1),
        ] {
            let sql = format!("SELECT {column} FROM {table} LIMIT 0");
            conn.prepare(&sql)
                .unwrap_or_else(|e| panic!("{table}.{column} must exist: {e}"));
            // NOT NULL with a default: `PRAGMA table_info` reports `notnull`, and the
            // default is what a not-yet-written row reads as.
            // PRAGMA table_info: 0 cid, 1 name, 2 type, 3 notnull, 4 dflt_value, 5 pk.
            let info: Vec<(String, i64, Option<String>)> = conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .expect("pragma")
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                })
                .expect("query")
                .filter_map(Result::ok)
                .collect();
            let row = info
                .iter()
                .find(|c| c.0 == column)
                .unwrap_or_else(|| panic!("{table}.{column} is missing: {info:?}"));
            assert_eq!(row.1, 1, "{table}.{column} must be NOT NULL");
            assert_eq!(
                row.2.as_deref(),
                Some(default.to_string().as_str()),
                "{table}.{column} must default to {default}"
            );
        }
    }

    /// A step may hold several attempts, so proposals cannot be unique per step.
    ///
    /// `step_no` is the logical step and `attempt_no` is the retry within it, so a failed
    /// step that is retried legitimately produces two proposals on the *same* step. A
    /// `UNIQUE (task_id, step_no)` cannot represent that: it would refuse the retry. The
    /// lookup index is therefore over the triple, and is not unique.
    #[test]
    fn a_logical_step_may_hold_several_attempted_proposals() {
        let conn = mem();
        MigrationRunner::new(&conn).run(true).expect("migrate");
        conn.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,max_attempts,created_at_ms,updated_at_ms)
             VALUES ('rt','query','pending',0,5,1,1);",
            [],
        )
        .expect("task");
        for attempt in 1..=2 {
            conn.execute(
                "INSERT INTO task_proposals (proposal_id,task_id,attempt_no,step_no,capability,
                                             target,params,proposer,created_at_ms,status)
                 VALUES (?1,'rt',?2,1,'filesystem/write-text','t','{}','{}',1,'approved');",
                rusqlite::params![format!("p{attempt}"), attempt],
            )
            .expect("a retried step proposes again on the same step_no");
        }
        let rows: Vec<(i64, i64)> = conn
            .prepare("SELECT step_no, attempt_no FROM task_proposals WHERE task_id='rt' ORDER BY attempt_no;")
            .expect("prepare")
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("query")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(rows, vec![(1, 1), (1, 2)], "same step, two attempts");

        // And the stage-2 unique index must be gone, while a usable lookup index exists.
        let indexes: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='task_proposals';",
            )
            .expect("prepare")
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();
        assert!(
            !indexes.iter().any(|i| i == "idx_task_proposals_step"),
            "the per-step unique index must have been dropped: {indexes:?}"
        );
        assert!(
            indexes
                .iter()
                .any(|i| i == "idx_task_proposals_step_attempt"),
            "a (task, step, attempt) lookup index is expected: {indexes:?}"
        );
    }

    /// A legacy task was one logical step, whatever its retry count.
    ///
    /// Its proposals are *retries of step 1*, not steps 1, 2 and 3. Reading historical
    /// `attempt_no` as a step number would invent a multi-step history that never existed,
    /// and would leave `steps_completed` disagreeing with a task that finished on its first
    /// try after two retries.
    #[test]
    fn legacy_rows_all_map_to_logical_step_one() {
        let conn = mem();
        migrate_to(&conn, 6);
        let seed = |id: &str, state: &str, attempts: i64| {
            conn.execute(
                "INSERT INTO tasks (id,kind,state,idempotent,attempts,max_attempts,
                                   created_at_ms,updated_at_ms)
                 VALUES (?1,'query',?2,0,?3,9,1,1);",
                rusqlite::params![id, state, attempts],
            )
            .expect("task");
            for attempt in 1..=attempts {
                conn.execute(
                    "INSERT INTO task_proposals (proposal_id,task_id,attempt_no,capability,
                                                 target,params,proposer,created_at_ms,status)
                     VALUES (?1,?2,?3,'filesystem/write-text','t','{}','{}',1,'approved');",
                    rusqlite::params![format!("p-{id}-{attempt}"), id, attempt],
                )
                .expect("proposal");
                conn.execute(
                    "INSERT INTO task_approvals (task_id,attempt_no,digest,capability,target,
                                                 params,issued_at_ms,expires_at_ms)
                     VALUES (?1,?2,?3,'filesystem/write-text','t','{}',1,2);",
                    rusqlite::params![id, attempt, vec![attempt as u8; 8]],
                )
                .expect("approval");
            }
        };
        seed("retried", "completed", 3);
        seed("single", "completed", 1);
        seed("open", "running", 2);

        migrate_to(&conn, CURRENT_VERSION);

        let counters = |id: &str| -> (i64, i64) {
            conn.query_row(
                "SELECT max_steps, steps_completed FROM tasks WHERE id = ?1;",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("row")
        };
        // Every legacy task is a one-step task, whatever its retries.
        assert_eq!(
            counters("retried"),
            (1, 1),
            "a finished legacy task is 1 of 1"
        );
        assert_eq!(counters("single"), (1, 1));
        assert_eq!(
            counters("open"),
            (1, 0),
            "an unfinished legacy task has done nothing"
        );

        // And every historical proposal and approval belongs to logical step 1.
        let proposal_steps: Vec<i64> = conn
            .prepare("SELECT DISTINCT step_no FROM task_proposals;")
            .expect("prepare")
            .query_map([], |r| r.get::<_, i64>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(proposal_steps, vec![1], "legacy proposals are all step 1");
        let approval_steps: Vec<i64> = conn
            .prepare("SELECT DISTINCT step_no FROM task_approvals;")
            .expect("prepare")
            .query_map([], |r| r.get::<_, i64>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(approval_steps, vec![1], "legacy approvals are all step 1");

        // The retries themselves are untouched: `attempt_no` still distinguishes them.
        let attempts: Vec<i64> = conn
            .prepare("SELECT attempt_no FROM task_proposals WHERE task_id='retried' ORDER BY attempt_no;")
            .expect("prepare")
            .query_map([], |r| r.get::<_, i64>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(
            attempts,
            vec![1, 2, 3],
            "history is preserved, not rewritten"
        );
    }

    /// Nothing is discarded: the counts before and after the correction are identical.
    #[test]
    fn the_correction_discards_no_proposal_approval_or_task() {
        let conn = mem();
        migrate_to(&conn, 7);
        conn.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,attempts,max_attempts,
                               created_at_ms,updated_at_ms)
             VALUES ('keep','query','completed',0,2,9,1,1);",
            [],
        )
        .expect("task");
        conn.execute(
            "INSERT INTO task_proposals (proposal_id,task_id,attempt_no,step_no,capability,
                                         target,params,proposer,created_at_ms,status)
             VALUES ('k1','keep',1,1,'filesystem/write-text','t','{}','{}',1,'approved');",
            [],
        )
        .expect("proposal");
        let before = {
            let t: i64 = conn
                .query_row("SELECT COUNT(*) FROM tasks;", [], |r| r.get(0))
                .unwrap();
            let p: i64 = conn
                .query_row("SELECT COUNT(*) FROM task_proposals;", [], |r| r.get(0))
                .unwrap();
            (t, p)
        };
        migrate_to(&conn, CURRENT_VERSION);
        let after = {
            let t: i64 = conn
                .query_row("SELECT COUNT(*) FROM tasks;", [], |r| r.get(0))
                .unwrap();
            let p: i64 = conn
                .query_row("SELECT COUNT(*) FROM task_proposals;", [], |r| r.get(0))
                .unwrap();
            (t, p)
        };
        assert_eq!(before, after, "a schema correction must not delete rows");
    }

    /// A fresh database and one migrated from the previous release end up identical.
    #[test]
    fn fresh_and_migrated_schemas_converge() {
        let shape = |c: &Connection| -> Vec<String> {
            let mut out: Vec<String> = c
                .prepare(
                    "SELECT type || ':' || name FROM sqlite_master
                     WHERE tbl_name IN ('tasks','task_proposals','task_approvals','task_step_results')
                       OR name LIKE 'idx_task_proposals%'
                     ORDER BY name;",
                )
                .expect("prepare")
                .query_map([], |r| r.get::<_, String>(0))
                .expect("query")
                .filter_map(Result::ok)
                .collect();
            let cols: Vec<String> = c
                .prepare(
                    "SELECT 'col:' || m.name FROM sqlite_master s
                     JOIN pragma_table_info(s.name) m
                     WHERE s.type='table'
                       AND s.name IN ('tasks','task_proposals','task_approvals','task_step_results')
                     ORDER BY m.name;",
                )
                .expect("prepare cols")
                .query_map([], |r| r.get::<_, String>(0))
                .expect("query cols")
                .filter_map(Result::ok)
                .collect();
            out.extend(cols);
            out.sort();
            out
        };

        let fresh = mem();
        MigrationRunner::new(&fresh)
            .run(true)
            .expect("fresh migrate");
        let migrated = mem();
        migrate_to(&migrated, CURRENT_VERSION);
        assert_eq!(
            shape(&fresh),
            shape(&migrated),
            "a new install and an upgraded one must not differ"
        );
    }

    /// Re-running is a no-op, and specifically does not re-run the non-idempotent
    /// `ALTER TABLE`s -- which is the failure mode that motivated re-checking the version
    /// inside the transaction.
    #[test]
    fn rerunning_the_migrations_changes_nothing() {
        let conn = mem();
        let first = MigrationRunner::new(&conn).run(true).expect("migrate");
        assert_eq!(
            first,
            MIGRATIONS.iter().map(|m| m.version).collect::<Vec<u32>>()
        );
        let second = MigrationRunner::new(&conn)
            .run(true)
            .expect("re-run is a no-op");
        assert!(
            second.is_empty(),
            "nothing should be applied twice: {second:?}"
        );
    }

    /// Composition state is representable, and carries no authority.
    ///
    /// `task_step_results` deliberately has no worker, lease, digest or approval column:
    /// it records what happened, and authorising remains the proposal/approval/dispatcher
    /// path's job. A second copy of any of those here would be a second thing to keep in
    /// step, and the most likely route to a step result being mistaken for permission.
    #[test]
    fn a_step_result_records_an_outcome_and_authorises_nothing() {
        let conn = mem();
        MigrationRunner::new(&conn).run(true).expect("migrate");
        conn.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,max_attempts,created_at_ms,updated_at_ms)
             VALUES ('sr','query','pending',0,3,1,1);",
            [],
        )
        .expect("task");

        let columns: Vec<String> = conn
            .prepare("PRAGMA table_info(task_step_results)")
            .expect("pragma")
            .query_map([], |r| r.get::<_, String>(1))
            .expect("query")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(
            columns,
            vec![
                "task_id",
                "step_no",
                "status",
                "verification",
                "structured_output",
                "artifacts",
                "recorded_at_ms"
            ]
        );
        for forbidden in [
            "worker",
            "lease",
            "digest",
            "approval",
            "authority_root",
            "actor",
        ] {
            assert!(
                !columns.iter().any(|c| c.contains(forbidden)),
                "a step result must not carry {forbidden:?}: {columns:?}"
            );
        }

        conn.execute(
            "INSERT INTO task_step_results (task_id,step_no,status,verification,recorded_at_ms)
             VALUES ('sr',1,'verified','the verifier agreed',99);",
            [],
        )
        .expect("a verified step records");
        // 1-based, and one row per step.
        conn.execute(
            "INSERT INTO task_step_results (task_id,step_no,status,recorded_at_ms)
             VALUES ('sr',1,'verified',1);",
            [],
        )
        .expect_err("one result per step");
        conn.execute(
            "INSERT INTO task_step_results (task_id,step_no,status,recorded_at_ms)
             VALUES ('sr',0,'verified',1);",
            [],
        )
        .expect_err("step numbers are 1-based");
        conn.execute(
            "INSERT INTO task_step_results (task_id,step_no,status,recorded_at_ms)
             VALUES ('sr',2,'invented',1);",
            [],
        )
        .expect_err("the status vocabulary is closed");
    }

    /// Two processes opening the same fresh database both succeed.
    ///
    /// This is the test that caught migration 7's shape: `ALTER TABLE ... ADD COLUMN` has
    /// no `IF NOT EXISTS` form, so a loser that queued on the `IMMEDIATE` lock and then
    /// applied an already-applied version failed with "duplicate column name".
    #[test]
    fn concurrent_applicators_of_a_non_idempotent_migration_both_succeed() {
        let dir = std::env::temp_dir().join(format!("orxnud-mig-conc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("state.db");

        let mut handles = Vec::new();
        for _ in 0..4 {
            let p = path.clone();
            handles.push(std::thread::spawn(move || {
                let conn = rusqlite::Connection::open(&p).expect("open");
                conn.busy_timeout(std::time::Duration::from_secs(10))
                    .expect("busy timeout");
                // Either this thread applied the migrations or found them already applied;
                // both are success. What must never happen is a hard failure.
                MigrationRunner::new(&conn)
                    .run(true)
                    .map(|_| ())
                    .unwrap_or_else(|e| {
                        // A `SQLITE_BUSY` that outlives the busy timeout is a lock
                        // configuration problem, not a migration-logic one, and is reported
                        // as such rather than being counted as a duplicate-apply failure.
                        panic!("concurrent migration failed: {e}");
                    });
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }

        let conn = rusqlite::Connection::open(&path).expect("reopen");
        assert_eq!(
            MigrationRunner::new(&conn).run(true).expect("read version"),
            Vec::<u32>::new(),
            "everything is applied exactly once"
        );
        let _ = std::fs::remove_dir_all(&dir);
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
                "task_proposals",
                "task_step_results",
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
