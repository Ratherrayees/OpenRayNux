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
//! * **Snapshot-protected.** Production code reaches the schema only through
//!   [`MigrationRunner::migrate`], which takes and verifies its own snapshot
//!   before running anything and hands back a recovery obligation on failure.
//!
//! That last one used to be a boolean, and it was the defect this module was
//! audited for (S-11 / F-26). `MigrationRunner::run(snapshot_verified: bool)` took a
//! `snapshot_verified: bool`, checked it, and then applied every migration — it
//! took no snapshot and restored nothing, so the boolean was the whole of its
//! safety. A caller that passed `true` without holding anything got no refusal
//! and no rollback. The two production call sites that did this were the audit
//! journal and the approval ledger, which between them hold the only tamper
//! evidence the system produces.
//!
//! There is now no parameter to get wrong. `migrate` decides for itself, and the
//! alternative — [`MigrationRunner::migrate_ephemeral`] — is named for the only
//! case where deciding differently is honest: a database with no durable copy,
//! such as an in-memory fixture. A source-level check keeps production code off
//! that path, because no behavioural test can observe which function a caller
//! chose.

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

    /// The migration failed and a snapshot is waiting to be restored (S-31).
    ///
    /// A distinct variant rather than `Failed` because the required response is
    /// different and doing the wrong thing is silent. The caller must **drop every
    /// connection and shared lease on this database first**, then restore under
    /// exclusive ownership via [`crate::backup::Backup::restore_coordinated`].
    ///
    /// Restoring from inside [`MigrationRunner::migrate`] is no longer possible: this
    /// type borrows a connection whose owning `Store` holds a shared lease, and
    /// exclusive ownership conflicts with a shared lease even in the same process,
    /// because the lock is per open file description. Recovering here would mean
    /// either deadlocking against our own lease or releasing it through a `&self`
    /// borrow, which Rust does not permit.
    #[error(
        "migration failed; a snapshot at {snapshot} must be restored after releasing the database"
    )]
    RecoveryRequired {
        /// The migration failure that caused this.
        source: Box<MigrationError>,
        /// The verified snapshot to restore.
        snapshot: std::path::PathBuf,
    },

    /// The runner was asked to migrate without a verified snapshot.
    ///
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
    Migration {
        // V-94. `task_approvals.digest` had no length CHECK, so the durable layer would
        // store a blob of any length under the column that binds an approval to the
        // operation it authorises -- including the zero-length blob the previous parser
        // produced from unparseable input. Requires recreating the table, because SQLite
        // cannot add a CHECK to an existing one.
        //
        // Forward, and deliberately lossy: the copy below keeps only rows whose digest is
        // already 32 bytes. A database carrying a malformed approval has an authority
        // record that never was one; discarding it is the fail-closed reading, and the
        // alternative -- keeping it -- would preserve exactly the state this migration
        // exists to remove. Such a row is un-recoverable authority, and an operator who
        // needs it can re-approve.
        version: 12,
        name: "task_approval_digest_length",
        sql: crate::schema::MIGRATION_APPROVAL_DIGEST_LENGTH,
    },
    Migration {
        // V-93 follow-up. The effect ledger recorded `task_id` and `attempt_no` but not
        // the logical step, and `attempt_no` restarts at every step boundary -- so two
        // steps' effects were indistinguishable and `recover()` could only reason about
        // the whole task. It therefore let a completed earlier step's effect decide
        // whether a later step could ever be retried, which is permanent, because
        // `needs-verification` is terminal.
        //
        // Nullable rather than defaulted: a row written before this migration has no
        // recorded step, and `step_no = 1` would assert one. `NULL` says the evidence is
        // absent, and `recover()` reads it as "might be the execution I am recovering",
        // which fails safe.
        version: 13,
        name: "task_effect_step_scope",
        sql: crate::schema::MIGRATION_EFFECT_STEP_SCOPE,
    },
    Migration {
        // V-97. `task_proposals` had no uniqueness on `(task_id, step_no, attempt_no)` --
        // only the surrogate `proposal_id` primary key, and the non-unique lookup index
        // migration 8 deliberately created. The constraint is *stated* in `schema.rs` and
        // *assumed* by the approval path, and it was never enforced, so a second proposal
        // for one execution identity could exist and could be approved in its own right.
        //
        // Forward rather than an edit to migration 7 or 8, for the reason migration 8
        // gives: a database that already applied those versions holds the shape they
        // created, and rewriting them would leave it in place while claiming it never
        // existed.
        //
        // Duplicates are reconciled rather than assumed absent, because they are
        // reachable: `propose_action` only refused a second proposal through the task's
        // state, and `begin_execution_spending_approval` re-enters `running` without
        // advancing `attempts` or `steps_completed`, so a worker whose dispatch failed
        // could propose again for the same identity. See `MIGRATION_PROPOSAL_IDENTITY`.
        version: 14,
        name: "task_proposal_identity",
        sql: crate::schema::MIGRATION_PROPOSAL_IDENTITY,
    },
];

/// The schema version a fully migrated Phase 2 database reports.
pub const CURRENT_VERSION: u32 = 14;

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

    /// Applies every pending migration to a database with **no durable copy**.
    ///
    /// # This is not the production entry point
    ///
    /// Production code must use [`Self::migrate`], which takes and verifies its
    /// own snapshot and can restore it. This method does neither, and it says so
    /// in its name rather than leaving a flag for the caller to set.
    ///
    /// It exists because a snapshot of a database that does not survive the
    /// process would be meaningless. The legitimate callers are an in-memory
    /// fixture, a file-scoped test fixture that is about to be deleted, and a
    /// child process about to be killed on purpose — in all of them there is no
    /// previous state to protect, so "take a snapshot first" would be theatre.
    ///
    /// # Why the unsafe form was removed rather than flagged
    ///
    /// The previous shape was `run(snapshot_verified: bool)`: it took no
    /// snapshot, restored nothing, and refused only when the boolean was false.
    /// The four production call sites that passed `true` therefore had no
    /// snapshot and no rollback, and the two that ran in production were the
    /// audit journal and the approval ledger.
    ///
    /// A boolean that names its own safety is not a safety mechanism; it is a
    /// claim, and a claim is exactly what S-11 recorded as being asserted rather
    /// than established. Removing the parameter leaves one production meaning,
    /// and this method — whose name is a warning — leaves one other meaning.
    ///
    /// `migrate_ephemeral` is refused in production code by gate **G16**
    /// (`scripts/gate_policy.py g16`, run by `scripts/ci-gates.sh`), which reads
    /// every crate's production source. A behavioural test cannot tell which of
    /// two methods a caller invoked -- both end in the same migrations and the
    /// same `schema_meta` -- so the check that keeps this off the production path
    /// has to be a check on the code. G13 exercises that gate against injected
    /// violations in both directions, so it is known to be able to fail.
    ///
    /// # Errors
    ///
    /// [`MigrationError::Failed`] if a statement fails.
    ///
    /// There is no "refusing to migrate without a snapshot" variant, and there used to
    /// be one. `MigrationError::NoSnapshot` existed to answer `run(false)`; it is gone
    /// because the boolean is gone. Keeping it would have been worse than dead code: a
    /// variant named for a refusal that can no longer happen advertises a guarantee the
    /// type no longer has.
    pub fn migrate_ephemeral(&self) -> Result<Vec<u32>, MigrationError> {
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
    pub fn migrate(&self, db_path: &Path) -> Result<Vec<u32>, MigrationError> {
        let current = self.applied_version()?;
        let pending: Vec<&Migration> = MIGRATIONS.iter().filter(|m| m.version > current).collect();
        if pending.is_empty() {
            return Ok(Vec::new());
        }

        // The snapshot decision is made here, and there is no longer a parameter for a
        // caller to get wrong. The previous shape took
        // `snapshot_verified_by_caller: bool` and, when it was `true`, reused a snapshot
        // from disk after checking it. The check made the flag harmless — `false`, which
        // is what every production caller passed, could not produce an unprotected
        // migration — but a parameter whose two values mean "take a snapshot" and "do not
        // take a snapshot" is a parameter a future caller can read backwards. Removing it
        // leaves exactly one behaviour, and it is the safe one.
        //
        // A pre-existing snapshot file at the conventional path is still reused rather
        // than overwritten, because it may be the only good copy of a database whose last
        // migration failed. It is used only if it verifies against this database.
        let snapshot = match Backup::verify(&Backup::path_for(db_path)) {
            Ok(_) => Some(Backup::existing(Backup::path_for(db_path))),
            Err(_) => Some(Backup::take(self.conn, db_path)?),
        };

        match self.migrate_ephemeral() {
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
                //
                // S-31: the restore itself **cannot happen here**. It needs exclusive
                // ownership of the database across processes, and this runner holds a
                // borrow of a connection whose owning `Store` holds a *shared* lease --
                // which `flock` treats as conflicting even within one process, because
                // the lock is per open file description. Restoring from here would
                // either deadlock against our own lease or require releasing it, which
                // a `&self` borrow cannot do.
                //
                // So the recovery is handed back to the caller, which must drop its
                // store first. See `MigrationError::RecoveryRequired`.
                match snapshot {
                    Some(s) => Err(MigrationError::RecoveryRequired {
                        source: Box::new(err),
                        snapshot: s.path().to_path_buf(),
                    }),
                    None => Err(err),
                }
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
pub fn open_and_migrate(path: &std::path::Path) -> Result<crate::sqlite::Store, StoreError> {
    // Whether the file already exists is read *before* opening it, because a failed
    // first migration must not leave a half-built file behind for the next start to
    // inherit. See `discard_failed_initialisation`.
    let pre_existing = path.exists();
    let store = crate::sqlite::Store::open(path, true)?;
    match MigrationRunner::new(store.conn()).migrate(path) {
        Ok(_) => Ok(store),
        Err(MigrationError::RecoveryRequired { source, snapshot }) => {
            // S-31: the store holds shared ownership for as long as it lives, so a restore
            // on this path could not take exclusive ownership. Drop it first, which
            // closes the connection and releases the lease, then recover.
            drop(store);
            recover_from_snapshot(path, &snapshot)?;
            Err(StoreError::Migration(source))
        }
        Err(e) => {
            drop(store);
            discard_failed_initialisation(path, pre_existing);
            Err(StoreError::Migration(Box::new(e)))
        }
    }
}

/// Recovers `db_path` from `snapshot` under exclusive ownership.
///
/// The one implementation of the sequence every migration caller needs, so it exists once
/// rather than three times and cannot drift between them:
///
/// 1. every connection and shared lease on `db_path` must already be dropped;
/// 2. exclusive ownership is taken (S-31), failing fast if another process holds it;
/// 3. the snapshot is restored, which verifies the restored *logical* content (S-30).
///
/// # Errors
///
/// [`MigrationError::RestoreFailed`] if the restore does not produce a database whose
/// logical content matches the snapshot. The original migration error is the caller's to
/// keep: this reports that recovery itself failed, which is a different and more urgent
/// fact.
pub fn recover_from_snapshot(db_path: &Path, snapshot: &Path) -> Result<(), StoreError> {
    crate::backup::Backup::existing(snapshot.to_path_buf())
        .restore_coordinated(db_path)
        .map_err(|source| {
            StoreError::Migration(Box::new(MigrationError::RestoreFailed(Box::new(
                RestoreFailure {
                    version: 0,
                    snapshot: snapshot.display().to_string(),
                    source,
                },
            ))))
        })
}

/// Removes a database this call created, after its first migration failed.
///
/// # Why a first migration failure is different from any other
///
/// Every other migration failure has a snapshot to roll back to, and the caller restores
/// it. A failure on a **brand-new** database may have no usable snapshot — V-33 records the
/// case where the very first migration cannot take one at all — and even when it can, the
/// thing being rolled back to is empty. What is left behind is a file that exists, holds
/// some of the schema, and will be opened by the next start as though it were a database to
/// migrate rather than one to create.
///
/// So the file is removed, and the next start begins clean. That is strictly better than
/// inheriting a half-built schema, and it cannot lose data: a file this call *created*
/// contained nothing but what the migrations put there.
///
/// # The guard, and why it is not optional
///
/// `pre_existing` is read **before** the store is opened. Only a file this call created is
/// ever removed. A pre-existing database with no `schema_meta` is a real case — a foreign
/// file, or one whose first migration failed under an older build — and deleting that would
/// destroy a user's data on the strength of a version check. Absence of `schema_meta` is not
/// evidence of emptiness.
pub(crate) fn discard_failed_initialisation(db_path: &Path, pre_existing: bool) {
    if pre_existing {
        return;
    }
    // The sidecars too. A `-wal` without its database is not inert: SQLite may recreate
    // the database from it on the next open, which is precisely the stale-data problem
    // S-30 exists to prevent, one step removed.
    // The snapshot goes too. `Backup::take` does not clean up after itself: if the copy or
    // the verification fails partway, the file it created stays on disk. On this path there
    // is nothing to recover from, so that file is debris -- and debris with a snapshot's
    // name is worse than none, because the *next* start's `migrate` adopts any existing
    // file at this path that verifies, and an empty database's snapshot can verify.
    for path in [
        db_path.to_path_buf(),
        wal_sidecar(db_path),
        shm_sidecar(db_path),
        Backup::path_for(db_path),
    ] {
        let _ = std::fs::remove_file(path);
    }
}

/// The `-wal` path SQLite derives from a database path.
fn wal_sidecar(db_path: &Path) -> std::path::PathBuf {
    suffix(db_path, "-wal")
}

/// The `-shm` path SQLite derives from a database path.
fn shm_sidecar(db_path: &Path) -> std::path::PathBuf {
    suffix(db_path, "-shm")
}

fn suffix(db_path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = db_path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    db_path.with_file_name(name)
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
        let applied = MigrationRunner::new(&conn)
            .migrate_ephemeral()
            .expect("migrate");
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
        MigrationRunner::new(&conn)
            .migrate_ephemeral()
            .expect("migrate");

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
        MigrationRunner::new(&conn)
            .migrate_ephemeral()
            .expect("migrate");
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
                    // A real digest is 32 bytes. Migration 12 refuses anything else, so a
                    // shorter seed would be discarded rather than migrated -- which is the point.
                    rusqlite::params![id, attempt, vec![attempt as u8; 32]],
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
            .migrate_ephemeral()
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
        let first = MigrationRunner::new(&conn)
            .migrate_ephemeral()
            .expect("migrate");
        assert_eq!(
            first,
            MIGRATIONS.iter().map(|m| m.version).collect::<Vec<u32>>()
        );
        let second = MigrationRunner::new(&conn)
            .migrate_ephemeral()
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
        MigrationRunner::new(&conn)
            .migrate_ephemeral()
            .expect("migrate");
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
                //
                // Ephemeral on purpose. All four threads share one database path, so
                // `migrate` would have them race for the single snapshot at
                // `Backup::path_for`, and the test would fail on snapshot contention
                // instead of on the lock behaviour it exists to pin. The snapshot path has
                // its own coverage (`migrate` takes and verifies one before touching a
                // file); this test is about `IMMEDIATE` transactions.
                MigrationRunner::new(&conn)
                    .migrate_ephemeral()
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
            MigrationRunner::new(&conn)
                .migrate(&path)
                .expect("read version"),
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
        MigrationRunner::new(&conn)
            .migrate_ephemeral()
            .expect("migrate");
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
        MigrationRunner::new(&conn)
            .migrate_ephemeral()
            .expect("migrate");
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
            r.migrate_ephemeral().expect("first run"),
            MIGRATIONS.iter().map(|m| m.version).collect::<Vec<u32>>()
        );
        assert_eq!(
            r.migrate_ephemeral().expect("second run"),
            Vec::<u32>::new()
        );
        assert_eq!(r.applied_version().expect("version"), CURRENT_VERSION);
    }

    /// S-11 / F-26. The guarantee this module now has to keep, stated as something
    /// observable rather than as an argument.
    ///
    /// The previous shape was `run(snapshot_verified: bool)`. Its refusal was real but
    /// weak: `run(false)` returned a `NoSnapshot` refusal, so a test could observe that
    /// the runner declined an unprotected migration, while `run(true)` took no snapshot and
    /// restored nothing. The refusal proved the runner could say no; it did not make the yes safe,
    /// and production answered yes.
    ///
    /// What replaces it cannot be a refusal, because there is nothing left to refuse.
    /// `migrate` has no boolean, so the only way to reach an unprotected migration is to
    /// name it: `migrate_ephemeral`. The property to pin is therefore the positive one --
    /// **`migrate` on a real database has taken and verified a snapshot by the time a
    /// migration fails**, and hands that snapshot back as a recovery obligation.
    ///
    /// Observed on a genuine mid-migration failure rather than on a mock, because the
    /// failure has to be a real one for "the snapshot was already there" to mean anything.
    #[test]
    fn a_failing_file_backed_migration_hands_back_a_snapshot_that_exists_and_verifies() {
        // A database at version 1 with a `tasks` table that is *not* migration 2's: the
        // name collides, so `MIGRATION_TASKS` fails with "table tasks already exists".
        // A real statement failure, produced by real schema conflict, not by a flag.
        let path = tmp_db("fail-midway");
        {
            let c = Connection::open(&path).expect("open");
            c.execute_batch(
                "CREATE TABLE schema_meta (
                     version INTEGER PRIMARY KEY,
                     name TEXT NOT NULL,
                     applied_at INTEGER NOT NULL);
                 INSERT INTO schema_meta (version, name, applied_at) VALUES (1, 'schema_meta', 0);
                 CREATE TABLE tasks (id TEXT PRIMARY KEY);",
            )
            .expect("stage a version-1 database");
        }

        let c = Connection::open(&path).expect("reopen");
        let err = MigrationRunner::new(&c)
            .migrate(&path)
            .expect_err("migration 2 must fail against the colliding table");

        // The obligation, not a warning: this is the only copy of the old state, and the
        // caller is told where it is.
        let snapshot = match &err {
            MigrationError::RecoveryRequired { snapshot, .. } => snapshot.clone(),
            other => panic!("expected RecoveryRequired, got {other:?}"),
        };
        assert!(
            snapshot.exists(),
            "a failed migration must leave a snapshot behind at {}",
            snapshot.display()
        );
        Backup::verify(&snapshot).expect("the snapshot handed back must verify");

        // And the failure is reported as itself, not swallowed into the recovery story.
        let MigrationError::RecoveryRequired { source, .. } = &err else {
            unreachable!()
        };
        assert!(
            matches!(**source, MigrationError::Failed { .. }),
            "the original failure must survive as the cause, got {source:?}"
        );

        // The database is untouched: no half-applied migration 2 is visible.
        assert_eq!(
            MigrationRunner::new(&c).applied_version().expect("version"),
            1,
            "a failed migration must not record a version"
        );
        let cols: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('tasks') WHERE name = 'kind';",
                [],
                |r| r.get(0),
            )
            .expect("probe");
        assert_eq!(
            cols, 0,
            "the colliding table must be left exactly as it was: migration 2 added no columns"
        );
        drop(c);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// A pre-existing snapshot that fails verification is **replaced, not adopted**.
    ///
    /// `migrate` reuses a snapshot already at the conventional path, because it may be the
    /// only good copy of a database whose previous migration failed. Reuse is only safe if
    /// the file is checked, and this is the check.
    ///
    /// This is the branch the old `snapshot_verified_by_caller: bool` decided between, and
    /// it is only observable now because the decision lives in one place with no parameter.
    /// A caller that passed `true` got this reuse unconditionally — it was told the snapshot
    /// was verified, and it believed the caller.
    ///
    /// The arrangement makes adoption and replacement distinguishable. If `migrate` trusted
    /// the file, the failure below would hand back the planted garbage as the recovery
    /// obligation. It has to hand back something that verifies against the source.
    #[test]
    fn a_failed_migration_replaces_a_snapshot_that_does_not_verify() {
        let path = tmp_db("bad-preexisting-snapshot");
        {
            let c = Connection::open(&path).expect("open");
            c.execute_batch(
                "CREATE TABLE schema_meta (
                     version INTEGER PRIMARY KEY,
                     name TEXT NOT NULL,
                     applied_at INTEGER NOT NULL);
                 INSERT INTO schema_meta (version, name, applied_at) VALUES (1, 'schema_meta', 0);
                 CREATE TABLE tasks (id TEXT PRIMARY KEY);",
            )
            .expect("stage a version-1 database whose migration 2 must fail");
        }

        // Garbage at the snapshot path: not a database at all.
        let planted = Backup::path_for(&path);
        std::fs::write(&planted, b"this is not a snapshot of anything").expect("plant garbage");
        assert!(planted.exists(), "precondition: the garbage is in place");

        let c = Connection::open(&path).expect("reopen");
        let err = MigrationRunner::new(&c)
            .migrate(&path)
            .expect_err("migration 2 must still fail against the colliding table");
        drop(c);

        let snapshot = match &err {
            MigrationError::RecoveryRequired { snapshot, .. } => snapshot.clone(),
            other => panic!("expected RecoveryRequired, got {other:?}"),
        };
        // Not a path comparison. `Backup::take` builds at a unique staging name and
        // renames into the canonical one, so the obligation is *at* the canonical path by
        // design; what distinguishes replacement from adoption is what is written there.
        let published = std::fs::read(&snapshot).expect("the published snapshot is readable");
        assert_ne!(
            published, b"this is not a snapshot of anything",
            "the bytes at the snapshot path must be the snapshot this call took, not the \
             planted file it was supposed to reject"
        );
        assert!(
            snapshot.exists(),
            "and it must exist: the only copy of the old state is at {}",
            snapshot.display()
        );
        // The real test: it verifies against the source, under the *strict* branch. The
        // staged database does have `schema_meta` -- it is a version-1 database -- so the
        // snapshot must too, and the planted bytes could not possibly satisfy this.
        let source = Connection::open(&path).expect("reopen source");
        assert!(
            Backup::has_schema_meta(&source),
            "precondition: the staged database is a version-1 database, so the strict \
             branch applies and no relaxation is being relied on"
        );
        Backup::verify_against_source(&snapshot, &source, false)
            .expect("the replacement snapshot must verify against the source");
        drop(source);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// A first initialisation that cannot even take its snapshot leaves nothing behind.
    ///
    /// The case the other failure paths cannot cover. V-33 records that a brand-new
    /// database used to be refused by snapshot *verification*, because there was no
    /// `schema_meta` to compare against -- so the very first migration could not run at
    /// all. Verification is now relaxed for an empty source, which means `Backup::take`
    /// is what can fail, and when it does there is no snapshot to restore from. What would
    /// otherwise be left on disk is a file that exists, holds part of the schema, and will
    /// be opened by the next start as a database to *migrate* rather than one to create.
    ///
    /// So it is removed. Forcing the failure by occupying the snapshot path with a
    /// directory makes `Backup::take` fail for a real, uninteresting reason.
    #[test]
    fn a_failed_first_initialisation_leaves_no_database_file_and_no_sidecars() {
        let path = tmp_db("fresh-init-fail");
        // The snapshot path is a directory, so creating the snapshot file there cannot
        // succeed. Nothing else about this database is unusual.
        std::fs::create_dir_all(Backup::path_for(&path)).expect("occupy the snapshot path");
        assert!(
            !path.exists(),
            "precondition: the database file must not exist before the call"
        );

        let Err(err) = open_and_migrate(&path) else {
            panic!("the snapshot path is a directory, so the migration cannot proceed");
        };
        // The failure is reported, not swallowed by the cleanup: a silent success here
        // would leave a daemon believing it has a database it does not have.
        assert!(
            matches!(err, crate::sqlite::StoreError::Migration(_)),
            "a failed first migration must surface as a migration error, got {err:?}"
        );

        assert!(
            !path.exists(),
            "a database this call created and could not migrate must not be left behind: the \
             next start would inherit a half-built schema and treat it as one to migrate"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// The sidecars, tested where they can actually exist.
    ///
    /// An earlier version of the test above asserted that no `-wal`/`-shm` survived, and
    /// **passed with the sidecar removal deleted**. Nothing wrote to the database before
    /// the snapshot was attempted, so SQLite had not created them and the assertion could
    /// not fail. That is the failure mode AGENTS.md §3 warns about: a green test reading as
    /// coverage of something it never touched.
    ///
    /// So the claim is tested directly, against a directory that really does contain the
    /// sidecars. It is still the same guarantee — a `-wal` whose database has been deleted
    /// is not inert, because SQLite may rebuild the database from it on the next open.
    #[test]
    fn discarding_a_failed_initialisation_removes_the_sidecars_and_the_snapshot() {
        let path = tmp_db("sidecars");
        // Built by hand, because nothing on this path writes before the failure.
        std::fs::write(&path, b"sqlite-format-3\0").expect("db");
        std::fs::write(wal_sidecar(&path), b"wal").expect("wal");
        std::fs::write(shm_sidecar(&path), b"shm").expect("shm");
        std::fs::write(Backup::path_for(&path), b"snapshot").expect("snapshot");
        for p in [
            path.clone(),
            wal_sidecar(&path),
            shm_sidecar(&path),
            Backup::path_for(&path),
        ] {
            assert!(p.exists(), "precondition: {} must exist", p.display());
        }

        discard_failed_initialisation(&path, false);

        for p in [
            path.clone(),
            wal_sidecar(&path),
            shm_sidecar(&path),
            Backup::path_for(&path),
        ] {
            assert!(
                !p.exists(),
                "{} must be removed with the database it belonged to",
                p.display()
            );
        }
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// **A live independent connection when a failed initialisation is discarded.**
    ///
    /// The sidecars are removed with the database, and S-30's criterion 4(b) measured that
    /// removing `-shm` while a connection has it memory-mapped makes **that** connection
    /// fail with `disk I/O error`. S-30 drew the lesson that sidecar deletion must not be the
    /// restore mechanism; this is a different call site, and it deletes them too.
    ///
    /// In-process ordering is already handled — both callers drop their own connection and
    /// their shared lease first — but S-31 *shared* ownership exists precisely so a second
    /// process may hold the same database open. So the question is not hypothetical: a
    /// failed first initialisation can run its cleanup while another process is reading.
    ///
    /// Measured rather than assumed, and the measurement is the point: this records what
    /// actually happens instead of what it was hoped would happen.
    #[test]
    fn discarding_a_failed_initialisation_while_another_connection_has_it_open() {
        let path = tmp_db("live-reader");
        // A live reader, as another process would be: its own connection, WAL mode, the
        // sidecars created and mapped.
        let reader = Connection::open(&path).expect("open as the other process would");
        crate::pragma::Pragma::critical()
            .apply(&reader)
            .expect("pragmas, which create the WAL sidecars");
        reader
            .execute_batch("CREATE TABLE someone_elses (id TEXT PRIMARY KEY);")
            .expect("write, so there is real state and a real mapped -shm");
        let shm = shm_sidecar(&path);
        let wal = wal_sidecar(&path);
        assert!(
            shm.exists() && wal.exists(),
            "precondition: WAL mode must have produced both sidecars, got shm={} wal={}",
            shm.exists(),
            wal.exists()
        );
        let before: i64 = reader
            .query_row("SELECT COUNT(*) FROM someone_elses;", [], |r| r.get(0))
            .expect("the reader can read before the cleanup");

        // The cleanup runs. `pre_existing = false` says "this call created the file", which
        // is the branch that deletes.
        discard_failed_initialisation(&path, false);

        // Not vacuous: confirm the sidecars really were removed. If they were already gone
        // the cleanup would have had nothing to do and the measurement below would be of
        // nothing -- which is how this file has already produced two green tests that
        // covered no code.
        assert!(
            !shm.exists() && !wal.exists(),
            "precondition: the cleanup must actually have deleted the sidecars, or this              test measures nothing (shm={} wal={})",
            shm.exists(),
            wal.exists()
        );

        // --- case 2: the reader holds an ACTIVE read transaction across the cleanup ---
        //
        // This is the shape S-30's criterion 4(b) used, and it is stronger than an idle
        // handle: the `-shm` index is genuinely in use, so removing it is removing something
        // mapped and live rather than something merely present.
        let d2 = tmp_db("live-reader-active");
        {
            let active = Connection::open(&d2).expect("open");
            crate::pragma::Pragma::critical()
                .apply(&active)
                .expect("pragmas");
            active
                .execute_batch("CREATE TABLE someone_elses (id TEXT PRIMARY KEY);")
                .expect("write");
            let shm2 = shm_sidecar(&d2);
            assert!(shm2.exists(), "precondition: the -shm must exist");
            active
                .execute_batch("BEGIN; SELECT COUNT(*) FROM someone_elses;")
                .expect("take a live read transaction");

            discard_failed_initialisation(&d2, false);
            assert!(
                !shm2.exists(),
                "precondition: the -shm must really have been removed, or this case                  measures nothing"
            );

            let after_active: rusqlite::Result<i64> =
                active.query_row("SELECT COUNT(*) FROM someone_elses;", [], |r| r.get(0));
            active.execute_batch("COMMIT;").ok();
            assert!(
                after_active.is_ok(),
                "a connection holding a live read transaction is broken by the cleanup: \
                 {after_active:?}. This is S-30 criterion 4(b)'s failure exactly: the -shm \
                 index is mapped and in use, and it has been removed underneath it."
            );
            drop(active);
        }
        let _ = std::fs::remove_dir_all(d2.parent().expect("dir"));

        // --- case 1 (continued): the idle reader. This is the measurement.
        let after: rusqlite::Result<i64> =
            reader.query_row("SELECT COUNT(*) FROM someone_elses;", [], |r| r.get(0));
        assert!(
            after.is_ok(),
            "an independent connection that had the database open is broken by the cleanup: \
             {after:?}. S-30 criterion 4(b) measured this exact failure -- deleting a \
             memory-mapped -shm -- and here it is reachable because S-31 shared ownership \
             deliberately lets a second process hold the database."
        );
        assert_eq!(
            after.expect("readable"),
            before,
            "and its data must be intact"
        );
        drop(reader);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// **The guard, in both directions, on the same code path as above.**
    ///
    /// `pre_existing` is the only thing between "this is debris from a failed first
    /// migration" and "this is a user's file". Deleting the wrong one loses data
    /// irrecoverably and invisibly, so both branches are pinned: created files and every
    /// sidecar go, and a pre-existing file and all of its sidecars stay.
    #[test]
    fn discarding_is_refused_for_a_file_that_predates_the_call() {
        let path = tmp_db("sidecars-kept");
        std::fs::write(&path, b"a real database").expect("db");
        std::fs::write(wal_sidecar(&path), b"wal").expect("wal");
        std::fs::write(shm_sidecar(&path), b"shm").expect("shm");
        std::fs::write(Backup::path_for(&path), b"the only good copy").expect("snapshot");

        discard_failed_initialisation(&path, true);

        for p in [
            path.clone(),
            wal_sidecar(&path),
            shm_sidecar(&path),
            Backup::path_for(&path),
        ] {
            assert!(
                p.exists(),
                "{} must survive: it existed before this call, and nothing here is entitled \
                 to decide it was debris",
                p.display()
            );
        }
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// **The guard on that deletion, in both directions.**
    ///
    /// Deleting a database because its first migration failed is only safe when this call
    /// created it. A file that was already there and carries no `schema_meta` is a real
    /// case -- a foreign file, or one an older build left half-built -- and "no
    /// `schema_meta`" is not evidence that there is nothing to lose. This test plants a
    /// pre-existing file, fails the same way, and requires it to survive with its rows.
    ///
    /// Without the second half, `discard_failed_initialisation` would be a rule that is only
    /// ever safe when it is right, and nothing would say which times those are.
    #[test]
    fn a_failed_migration_never_removes_a_file_that_was_already_there() {
        let path = tmp_db("preexisting-kept");
        {
            let c = Connection::open(&path).expect("open");
            c.execute_batch(
                "CREATE TABLE somebody_elses_table (id TEXT PRIMARY KEY, payload TEXT NOT NULL);\
                 INSERT INTO somebody_elses_table (id, payload) VALUES ('x', 'user data');",
            )
            .expect("seed a pre-existing file");
        }
        // Same obstacle as the test above, against a file that now already exists.
        std::fs::create_dir_all(Backup::path_for(&path)).expect("occupy the snapshot path");
        assert!(path.exists(), "precondition: the file is already there");

        assert!(
            open_and_migrate(&path).is_err(),
            "the snapshot cannot be taken, so the migration cannot proceed"
        );

        assert!(
            path.exists(),
            "a pre-existing file must never be removed, however its migration failed: \
             absence of schema_meta is not evidence of emptiness"
        );
        let c = Connection::open(&path).expect("reopen");
        let payload: String = c
            .query_row(
                "SELECT payload FROM somebody_elses_table WHERE id = 'x';",
                [],
                |r| r.get(0),
            )
            .expect("the row must still be there");
        assert_eq!(
            payload, "user data",
            "user data must survive a failed migration"
        );
        drop(c);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// The same failure on a database that never had a `schema_meta` at all.
    ///
    /// The case above starts from a real version-1 database, so the snapshot has something
    /// to record. This one starts from a file with no bookkeeping whatsoever, which is what
    /// `discard_failed_initialisation` exists for -- and it pins that the *error* is still
    /// reported rather than turned into a silent success by the cleanup.
    #[test]
    fn a_failed_first_migration_on_a_foreign_file_still_reports_and_leaves_it_alone() {
        let path = tmp_db("foreign-file");
        {
            let c = Connection::open(&path).expect("open");
            // A file that is not ours: no `schema_meta`, and a `tasks` table we must not
            // destroy. This is the case where absence of `schema_meta` is *not* evidence
            // of emptiness.
            c.execute_batch("CREATE TABLE tasks (id TEXT PRIMARY KEY, mine TEXT NOT NULL);")
                .expect("seed a foreign file");
            c.execute("INSERT INTO tasks (id, mine) VALUES ('u1', 'keep me');", [])
                .expect("seed a row");
        }

        let c = Connection::open(&path).expect("reopen");
        let err = MigrationRunner::new(&c)
            .migrate(&path)
            .expect_err("migration 2 must fail against the colliding table");
        drop(c);

        // `migrate` itself never deletes: cleanup is the caller's decision, and it is
        // guarded by whether the file pre-existed. This test is the reason that guard
        // exists, so it asserts the file is still there.
        assert!(
            path.exists(),
            "a pre-existing file must never be removed by a failed migration"
        );
        let c = Connection::open(&path).expect("reopen");
        let kept: String = c
            .query_row("SELECT mine FROM tasks WHERE id = 'u1';", [], |r| r.get(0))
            .expect("the row must still be there");
        assert_eq!(kept, "keep me", "user data must survive a failed migration");
        assert!(
            matches!(err, MigrationError::RecoveryRequired { .. }),
            "the caller must still be told a snapshot exists to recover from, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
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

        let store = open_and_migrate(&path).expect("open+migrate");
        assert_eq!(
            MigrationRunner::new(store.conn())
                .applied_version()
                .expect("version"),
            CURRENT_VERSION
        );
        drop(store);
        // Reopen: the version is durable.
        let store2 = open_and_migrate(&path).expect("reopen");
        assert_eq!(
            MigrationRunner::new(store2.conn())
                .migrate(&path)
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
            .migrate(&path)
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
            MigrationRunner::new(store.conn())
                .migrate(&path)
                .expect("run");
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
            MigrationRunner::new(store.conn())
                .migrate(&path)
                .expect("run");
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

        // Relative to a source with no schema_meta: accepted. The answer is passed in,
        // read before the copy; see `Backup::verify_against_source`.
        assert!(
            !Backup::has_schema_meta(store.conn()),
            "precondition: a freshly opened store has not been migrated"
        );
        Backup::verify_against_source(backup.path(), store.conn(), true)
            .expect("an empty snapshot of an empty database is faithful");
        // Absolute: refused, because nothing about the file says it is safe.
        Backup::verify(backup.path()).expect_err("the strict API still refuses emptiness");
    }
    // ---------------------------------------------------------------- V-97: migration 12
    //
    // Migration 12 rebuilds `task_approvals` to add `CHECK (length(digest) = 32)`. Two
    // things about that rebuild were wrong and are asserted here.
    //
    // The first: the copy wrote `NULL` into `consumed_at_ms`, justified by a claim that a
    // consumed row "cannot be re-inserted under this primary key". It can — the row *is*
    // re-inserted, under a key identical to the one it came from — so the consumption
    // record of every already-executed approval was erased, and
    // `record_approval_replacing_expired` reads that column to decide whether a
    // replacement is allowed.
    //
    // The second: the filter was `length(digest) = 32` alone, which is not a type check.
    // SQLite is dynamically typed, so a 32-character TEXT value satisfies it and was
    // carried into the new table as a digest.

    /// An approval, inserted at schema 10 with a caller-chosen digest and consumption.
    ///
    /// `digest_sql` is interpolated into the statement rather than bound, because that is
    /// the only way to produce a value of a chosen *storage class*. A bound `"x'ff..'"`
    /// is the 68-character TEXT spelling of a blob, not a blob — which is precisely the
    /// distinction migration 12's filter exists to draw, and binding it would have made
    /// every fixture a malformed row.
    fn seed_approval(
        conn: &Connection,
        task: &str,
        attempt: i64,
        digest_sql: &str,
        issued: i64,
        expires: i64,
        consumed: Option<i64>,
    ) {
        let consumed = consumed.map_or_else(|| "NULL".to_owned(), |v| v.to_string());
        conn.execute_batch(&format!(
            "INSERT INTO task_approvals
               (task_id,attempt_no,step_no,digest,capability,target,params,
                issued_at_ms,expires_at_ms,consumed_at_ms)
             VALUES ('{task}',{attempt},1,{digest_sql},'filesystem/write-text','out.txt',
                     '{{}}',{issued},{expires},{consumed});"
        ))
        .expect("seed an approval");
    }

    fn approvals(conn: &Connection) -> Vec<(i64, Option<i64>, String, i64)> {
        let mut st = conn
            .prepare(
                "SELECT attempt_no, consumed_at_ms, hex(digest), expires_at_ms
                   FROM task_approvals ORDER BY attempt_no;",
            )
            .expect("prepare");
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    }

    /// Requirement: `consumed_at_ms` is preserved, for every valid row, consumed or not.
    #[test]
    fn migration_12_preserves_which_approvals_had_been_consumed() {
        let conn = mem();
        migrate_to(&conn, 10);
        conn.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,attempts,max_attempts,
                               created_at_ms,updated_at_ms)
             VALUES ('t','query','completed',0,1,9,1,1);",
            [],
        )
        .expect("task");

        seed_approval(
            &conn,
            "t",
            1,
            &format!("x'{}'", "11".repeat(32)),
            10,
            9_000,
            None,
        );
        seed_approval(
            &conn,
            "t",
            2,
            &format!("x'{}'", "22".repeat(32)),
            20,
            9_000,
            Some(1_700_000_000_123_i64),
        );
        // Consumed *and* expired: the combination that must survive most faithfully,
        // because both are facts an operator reads.
        seed_approval(
            &conn,
            "t",
            3,
            &format!("x'{}'", "33".repeat(32)),
            30,
            40,
            Some(1_700_000_000_456_i64),
        );
        seed_approval(
            &conn,
            "t",
            4,
            &format!("x'{}'", "44".repeat(32)),
            40,
            50,
            Some(1_700_000_000_789_i64),
        );

        let before = approvals(&conn);
        assert_eq!(before.len(), 4, "four rows seeded");

        migrate_to(&conn, CURRENT_VERSION);
        let after = approvals(&conn);

        assert_eq!(
            after.len(),
            before.len(),
            "every valid row must survive: {before:?} -> {after:?}"
        );
        for (b, a) in before.iter().zip(after.iter()) {
            assert_eq!(
                a.0, b.0,
                "attempt order must be unchanged: {before:?} -> {after:?}"
            );
            assert_eq!(
                a.1, b.1,
                "consumed_at_ms(attempt {}) must be identical across the migration: \
                 {:?} -> {:?}",
                b.0, b.1, a.1
            );
            assert_eq!(a.2, b.2, "the digest must be carried verbatim");
            assert_eq!(a.3, b.3, "expires_at_ms must be carried verbatim");
        }
        assert_eq!(
            after.iter().filter(|r| r.1.is_some()).count(),
            3,
            "three of the four were consumed, and all three must still read as consumed"
        );
    }

    /// The inverse: an *unconsumed* approval must not come out looking consumed. A blanket
    /// copy of a sentinel would satisfy the test above and break this one.
    #[test]
    fn migration_12_does_not_invent_a_consumption_that_did_not_happen() {
        let conn = mem();
        migrate_to(&conn, 10);
        conn.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,attempts,max_attempts,
                               created_at_ms,updated_at_ms)
             VALUES ('t','query','waiting-for-user',0,1,9,1,1);",
            [],
        )
        .expect("task");
        seed_approval(
            &conn,
            "t",
            1,
            &format!("x'{}'", "aa".repeat(32)),
            10,
            9_000,
            None,
        );

        migrate_to(&conn, CURRENT_VERSION);
        let after = approvals(&conn);
        assert_eq!(
            after[0].1, None,
            "an approval nobody spent must not come out spent"
        );
    }

    /// Requirement: a malformed digest is still discarded. Preserving consumption state
    /// must not mean preserving rows the CHECK refuses.
    #[test]
    fn migration_12_still_discards_a_malformed_digest() {
        let conn = mem();
        migrate_to(&conn, 10);
        conn.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,attempts,max_attempts,
                               created_at_ms,updated_at_ms)
             VALUES ('t','query','completed',0,1,9,1,1);",
            [],
        )
        .expect("task");

        seed_approval(
            &conn,
            "t",
            1,
            &format!("x'{}'", "ff".repeat(32)),
            10,
            9_000,
            None,
        );
        // 31 bytes.
        seed_approval(
            &conn,
            "t",
            2,
            &format!("x'{}'", "ee".repeat(31)),
            10,
            9_000,
            None,
        );
        // 33 bytes.
        seed_approval(
            &conn,
            "t",
            3,
            &format!("x'{}'", "dd".repeat(33)),
            10,
            9_000,
            None,
        );
        // Zero bytes.
        seed_approval(&conn, "t", 4, "zeroblob(0)", 10, 9_000, None);
        // 32 characters, and not one of them a hex digit: `length()` alone would accept it.
        seed_approval(
            &conn,
            "t",
            5,
            &format!("'{}'", "zz".repeat(16)),
            10,
            9_000,
            None,
        );
        // 32 characters that *are* hex, stored as TEXT rather than BLOB.
        seed_approval(
            &conn,
            "t",
            6,
            &format!("'{}'", "ab".repeat(16)),
            10,
            9_000,
            None,
        );
        // An INTEGER cannot be 32 bytes long.
        seed_approval(&conn, "t", 7, "32", 10, 9_000, None);
        // And one that must survive, to prove the filter is not simply "drop everything".
        seed_approval(
            &conn,
            "t",
            8,
            &format!("x'{}'", "01".repeat(32)),
            10,
            9_000,
            None,
        );

        assert_eq!(
            approvals(&conn).len(),
            8,
            "all eight are insertable at schema 10"
        );

        migrate_to(&conn, CURRENT_VERSION);
        let after = approvals(&conn);
        // Attempts 1 and 8 are the two well-formed 32-byte blobs; every other attempt is a
        // value whose length or storage class makes it unusable as a digest.
        let survivors: Vec<i64> = after.iter().map(|r| r.0).collect();
        assert_eq!(
            survivors,
            vec![1, 8],
            "only the well-formed 32-byte blobs may survive, and a TEXT value of length 32 \
             is not one of them; got {after:?}"
        );
    }

    /// Requirement: post-migration consumption still works — a database that survives the
    /// rebuild must still enforce single use.
    #[test]
    fn a_migrated_approval_can_still_be_consumed_exactly_once() {
        let conn = mem();
        migrate_to(&conn, 10);
        conn.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,attempts,max_attempts,
                               created_at_ms,updated_at_ms)
             VALUES ('t','query','waiting-for-user',0,1,9,1,1);",
            [],
        )
        .expect("task");
        seed_approval(
            &conn,
            "t",
            1,
            &format!("x'{}'", "7f".repeat(32)),
            10,
            9_000,
            None,
        );

        migrate_to(&conn, CURRENT_VERSION);
        let spent = conn
            .execute(
                "UPDATE task_approvals SET consumed_at_ms = 555 WHERE task_id = 't';",
                [],
            )
            .expect("consume");
        assert_eq!(spent, 1, "the first consumption lands");
        let again = conn
            .execute(
                "UPDATE task_approvals SET consumed_at_ms = 556 WHERE task_id = 't'
                   AND consumed_at_ms IS NULL;",
                [],
            )
            .expect("second consumption");
        assert_eq!(
            again, 0,
            "and the conditional form still reports 'no row', so single use holds"
        );
    }
}
