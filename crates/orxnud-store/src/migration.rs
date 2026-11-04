//! The migration mechanism — with **no application tables**.
//!
//! Phase 1 provides the runner and its guarantees; it does not provide a
//! schema. docs-13 §8 forbids inventing application tables ahead of the engine
//! that uses them, so the migration list contains exactly one entry: `schema_meta`,
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

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use orxnud_domain::platform::{FileFacts, FilesystemIdentity, PrivacyError};

use crate::alias::{AliasRefusal, PreObservation};
use crate::backup::{Backup, BackupError, VerifiedSnapshot};
use crate::sqlite::StoreError;

/// What securing an adopted snapshot produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Secured {
    /// The file is private to its owner, and it is still the file that was
    /// verified. The adoption may proceed.
    Ready,
    /// The file is **gone**.
    ///
    /// A competing migrator finished first and discarded the snapshot it took.
    /// There is nothing left to make private, nothing to protect and nothing to
    /// adopt, so the caller takes a fresh snapshot instead.
    Gone,
}

/// Serialises the snapshot decision, publication, migration and discard for one database.
///
/// The database lease is **shared** on the migration path, so it does not exclude a
/// second migrator. The snapshot pathname is not covered by any SQLite transaction, and
/// publication replaces that pathname atomically. Two migrators can therefore overwrite
/// or discard each other's recovery point. This lock is taken only when a migration is
/// pending, held until the result (including any recovery obligation) is returned, and
/// released by the operating system if the process dies.
///
/// It is a separate zero-byte sidecar beside the canonical snapshot path. It holds no
/// user data; its only purpose is mutual exclusion.
struct SnapshotLock {
    _file: std::fs::File,
}

impl SnapshotLock {
    fn path_for(db_path: &Path) -> PathBuf {
        let mut path = Backup::path_for(db_path).into_os_string();
        path.push(".lock");
        PathBuf::from(path)
    }

    fn acquire(db_path: &Path) -> Result<Self, MigrationError> {
        let path = Self::path_for(db_path);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|source| MigrationError::SnapshotLock {
                path: path.clone(),
                source,
            })?;
        file.lock()
            .map_err(|source| MigrationError::SnapshotLock { path, source })?;
        Ok(Self { _file: file })
    }
}

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

    /// The recorded schema history is not a contiguous sequence starting at 1.
    ///
    /// `applied_version` used to return the **maximum** recorded version, which made a
    /// history like `1, 2, 14` indistinguishable from an intact `1..=14`: the runner
    /// saw "current" and did nothing, leaving the database without the tables that
    /// versions 3..13 were supposed to create. A gap is corruption or tampering, not a
    /// migration state, and there is no safe version at which to start forward work.
    #[error("database schema history is incomplete: {detail}")]
    IncompleteHistory {
        /// What was actually recorded.
        detail: String,
    },

    /// The database was written by a newer schema than this binary knows.
    ///
    /// Treating the unknown maximum as "already current" silently opens a database
    /// whose tables and constraints this build does not understand. The refusal is
    /// deliberate and happens before a snapshot is taken or a statement is run.
    #[error(
        "database schema version {found} is newer than this binary supports (maximum {supported})"
    )]
    UnsupportedVersion {
        /// The version found on disk.
        found: u32,
        /// The highest version this binary implements.
        supported: u32,
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

    /// The exclusive snapshot-path lock could not be acquired.
    ///
    /// Migrations of one database are serialised from the snapshot decision through
    /// publication and discard. Without that lock, one migrator's successful `discard`
    /// could remove a competing migrator's recovery point, because the snapshot pathname
    /// is shared while the database lease is only shared. A lock failure means the
    /// migration did not run and no snapshot was disturbed.
    #[error("could not lock the pre-migration snapshot path at {path}: {source}")]
    SnapshotLock {
        /// The lock path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// An existing snapshot could not be **made private** to its owner, so it was
    /// **not** adopted as the recovery point and the migration did not proceed.
    ///
    /// A distinct variant rather than a `Snapshot` failure because the two demand
    /// opposite responses. A `Snapshot` failure means "no usable copy exists" and
    /// the remedy is to take a new one. This one means **a usable copy exists and
    /// was left exactly where it was**: overwriting it to work around a permission
    /// failure would destroy the only good copy of the database, so the file is
    /// preserved and the migration refuses.
    ///
    /// It is also deliberately **not** an ownership failure. Nobody else holds this
    /// snapshot; the platform simply could not make it private, and an operator
    /// sent to look for a competing process is being sent to the wrong place.
    #[error("snapshot at {path} could not be made private to its owner: {reason}")]
    SnapshotPrivacy {
        /// The snapshot that was left in place.
        path: std::path::PathBuf,
        /// Why it could not be made private.
        reason: PrivacyError,
    },
    /// An existing snapshot could not be **shown to be safe** — it was reachable
    /// through more than one name, or the path was replaced while it was being
    /// secured — so it was **not** adopted and the migration did not proceed.
    ///
    /// The snapshot is left exactly where it was, for the same reason as
    /// [`Self::SnapshotPrivacy`]: it may be the only good copy of the database.
    #[error("snapshot at {path} could not be shown to be safe: {reason}")]
    SnapshotAliasUnsafe {
        /// The snapshot that was left in place.
        path: std::path::PathBuf,
        /// Why it could not be shown to be safe.
        reason: AliasRefusal,
    },

    /// An existing snapshot carries **no provenance**, so it cannot be shown to
    /// be a snapshot of *this* database, and it was **not** adopted.
    ///
    /// A distinct variant rather than a `Snapshot` failure because the two
    /// demand opposite responses. A `Snapshot` failure means "no usable copy
    /// exists" and the remedy is to take a new one. This one means **a file that
    /// verifies sits at the canonical path and cannot be tied to this database**:
    /// it was left by a build that predates the provenance table, or it is a
    /// database that belongs to something else, and there is no way to tell those
    /// apart from the file alone.
    ///
    /// The file is **left exactly where it was**. Overwriting it to work around
    /// the missing provenance would destroy the only good copy of the database —
    /// and the replacement would be a snapshot of the database as it is *now*,
    /// which is not the pre-migration state the recovery point is for.
    #[error(
        "the snapshot at {path} carries no database identity, so it cannot be shown to be a \
         snapshot of this database; it was left in place. Move it aside and retry"
    )]
    SnapshotProvenanceMissing {
        /// The snapshot that was left in place.
        path: std::path::PathBuf,
    },

    /// An existing snapshot carries **another database's** identity, so it is
    /// not a snapshot of this one, and it was **not** adopted.
    ///
    /// This is the cross-database case: the file at the canonical path is a
    /// complete, healthy database that belongs to a different installation — a
    /// state directory copied from another machine, a template, a database
    /// restored from elsewhere. Every structural check it passes; the one check
    /// it fails is the one that matters.
    ///
    /// Adopting it would make the recovery obligation point at the other
    /// installation's data, and the restore that follows would install that data
    /// over this database — this database's rows replaced by another
    /// installation's, with the store reporting success throughout.
    #[error(
        "the snapshot at {path} was taken from a different database (its identity is {found}, \
         this database's is {expected}); it was left in place. Move it aside and retry"
    )]
    SnapshotProvenanceMismatch {
        /// The snapshot that was left in place.
        path: std::path::PathBuf,
        /// The identity of the database being migrated.
        expected: String,
        /// The identity the snapshot carries.
        found: String,
    },

    /// The database could not be given a **provenance identity**, so the
    /// migration did not proceed.
    ///
    /// The identity is what binds a pre-migration snapshot to the database it
    /// protects. Without it a snapshot cannot be shown to belong to this
    /// database, so the migration refuses rather than adopt one it cannot vouch
    /// for — and the refusal here is *earlier* than that: the identity could not
    /// be written at all.
    ///
    /// Nothing was migrated and no snapshot was taken. The database is otherwise
    /// unchanged.
    #[error("the database could not be given a provenance identity: {source}")]
    ProvenanceUnavailable {
        /// The underlying error.
        #[source]
        source: rusqlite::Error,
    },

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
///
/// **Crate-private**, and that is the whole point of the S-11 change: its `sql`
/// field is a ready-to-run DDL string, so a public `Migration` is a public
/// schema. Nothing outside this crate needs the type; the only caller that did
/// was a test, and it is served by [`crate::test_support`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Migration {
    /// Monotonic version. Migrations are applied in ascending order, once.
    pub version: u32,
    /// A short name, recorded in `schema_meta` for diagnosis.
    pub name: &'static str,
    /// The SQL to apply inside a single transaction.
    pub sql: &'static str,
}

/// Every migration, in the order they must be applied.
///
/// **Not exported at all.** `pub(crate)`, in every build, because this hands out every
/// `CREATE TABLE` and
/// `ALTER TABLE` in the schema as a plain `&str`. A caller with one of these and
/// a `Connection` — and `Store::conn()` is public — can apply any schema change
/// with no pre-migration snapshot, no verification and no recovery, which is the
/// whole of F-26.
///
/// The gate is the *visibility* rather than a feature: the list is `pub(crate)` in
/// every build, so no build -- production or test -- can obtain it from outside this
/// crate. Integration tests in *other* crates need to stage a database at a chosen
/// version and cannot see `#[cfg(test)]`, so they are served by
/// [`crate::test_support::stage_schema`], which offers the operation rather than the
/// SQL.
///
/// This is the *accident* route closed. `MigrationRunner::migrate` remains the
/// production entry point, and gate **G16** is what stops the *deliberate* one.
///
/// # What replaced the public export
///
/// Integration tests in *other* crates need to stage a database at a chosen
/// schema version, and `#[cfg(test)]` does not cross a crate boundary. Rather
/// than re-export the SQL under a feature -- which would put the strings back in
/// a shipped build the moment anything enabled it -- [`crate::test_support`]
/// offers a **function** that performs the staging, gated on the same feature.
/// A caller gets "put this connection at version N", which is what they wanted,
/// and cannot get the DDL itself.
///
/// Migration 1 is Phase 1's `schema_meta` bookkeeping. Migrations 2.. are the
/// Phase 2 task layer, built from [`crate::schema`] so there is exactly one place
/// a table can be created.
pub(crate) const MIGRATIONS: &[Migration] = &[
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
    Migration {
        // CONC-002. `attempts` is deliberately per-step and is reset at a completed
        // boundary, so it cannot distinguish every lease acquisition. This separate,
        // durable counter is incremented in the same UPDATE that grants a claim.
        version: 15,
        name: "task_claim_generation",
        sql: crate::schema::MIGRATION_CLAIM_GENERATION,
    },
];

/// The schema version a fully migrated Phase 2 database reports.
pub const CURRENT_VERSION: u32 = 15;

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
    /// [`MigrationError::Failed`] if `schema_meta` is absent or unreadable,
    /// [`MigrationError::IncompleteHistory`] if its versions are not contiguous
    /// `1..=max`, or [`MigrationError::UnsupportedVersion`] if the maximum is newer
    /// than [`CURRENT_VERSION`].
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
        let (recorded, lowest, highest): (i64, i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(MIN(version), 0), COALESCE(MAX(version), 0) \
                 FROM schema_meta;",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|source| MigrationError::Failed { version: 0, source })?;
        if recorded == 0 {
            return Ok(0);
        }
        // A history is only trustworthy if it is exactly `1..=highest`. Counting
        // rows rather than trusting `MAX` is what makes the `1, 2, 14` case visible:
        // three recorded versions cannot describe the fourteen-step history the
        // maximum claims. A negative or zero version is equally not a history this
        // runner wrote.
        if lowest != 1 || recorded != highest || highest < 1 {
            return Err(MigrationError::IncompleteHistory {
                detail: format!(
                    "schema_meta records {recorded} versions from {lowest} to {highest}; \
                     expected the contiguous sequence 1..={highest}"
                ),
            });
        }
        let highest = u32::try_from(highest).map_err(|_| MigrationError::IncompleteHistory {
            detail: format!("schema_meta records an out-of-range version {highest}"),
        })?;
        if highest > CURRENT_VERSION {
            return Err(MigrationError::UnsupportedVersion {
                found: highest,
                supported: CURRENT_VERSION,
            });
        }
        Ok(highest)
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
        // Refuse a corrupt or newer history before writing anything, including the
        // provenance identity. The per-migration check below runs inside a transaction,
        // but by then the identity has already been written; a history that cannot be
        // trusted is not a reason to mutate the database first.
        self.applied_version()?;

        // The provenance identity is part of the shape of a database this store
        // owns, so it is created here as well as on the snapshotting path.
        //
        // The reason is convergence: an ephemeral database and a migrated one
        // must have the **same tables**, or "the schema contains exactly the
        // declared tables" would be true of one and false of the other, and the
        // test that says so would be describing a schema that does not ship.
        //
        // On the snapshotting path the identity is created *earlier* — before the
        // snapshot is taken, so that the snapshot carries it — and this call
        // finds it already there.
        Self::ensure_database_identity(self.conn)?;
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
    ///
    /// # The snapshot is private to its owner
    ///
    /// The pre-migration snapshot is a full copy of the database, and the platform
    /// creates it with the process's umask applied. `identity` is therefore
    /// **required**: it is how the snapshot is made owner-only before it is
    /// published, and a migration that cannot take a private snapshot refuses.
    pub fn migrate(
        &self,
        db_path: &Path,
        identity: &dyn FilesystemIdentity,
    ) -> Result<Vec<u32>, MigrationError> {
        let current = self.applied_version()?;
        if MIGRATIONS.iter().all(|m| m.version <= current) {
            return Ok(Vec::new());
        }

        // From here through the recovery obligation, no other migrator of this database
        // may publish or discard the shared snapshot pathname. The version is re-read
        // under the lock: another migrator may have completed between the check above
        // and this acquisition.
        let _snapshot_lock = SnapshotLock::acquire(db_path)?;
        let current = self.applied_version()?;
        if MIGRATIONS.iter().all(|m| m.version <= current) {
            return Ok(Vec::new());
        }

        // The database is given its **provenance identity** before anything else
        // happens, and that order is the whole of the mechanism.
        //
        // The identity is what a pre-migration snapshot carries, and a snapshot
        // can only carry it if the identity is already in the database when the
        // copy is taken. So the identity is written first, and the snapshot —
        // taken or adopted — is bound to it.
        //
        // It is written even though the migration may then refuse: the refusal
        // is about the file at the canonical path, and this database is not that
        // file. What it does *not* do is touch the file at the canonical path,
        // which is the one thing the refusal is protecting.
        let live_identity = Self::ensure_database_identity(self.conn)?;

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
        let canonical = Backup::path_for(db_path);
        // The path is observed **before** the verification, so the identity the
        // verification saw is the identity that is confirmed afterwards. An
        // observation error is not fatal here: it only matters in the adoption
        // branch below, and the take branch replaces the file at this name anyway.
        let pre = crate::alias::observe_before_open(&canonical, identity);
        let snapshot = match Backup::verify(&canonical) {
            Ok(verified) => {
                // The file exists and verified, so it is about to be **adopted** as
                // the recovery point. A snapshot left behind by a build that did
                // not restrict it is a world-readable copy of the user's entire
                // durable state, and adopting it unchanged keeps it that way — so it
                // is made private **first**, and the migration does not proceed if
                // that cannot be done.
                //
                // The **provenance** check comes before that, and before anything
                // else touches the file. "Verifies" says the file is a database;
                // it does not say the file is a snapshot *of this database*, and a
                // database belonging to something else verifies just as well. A
                // file that cannot be shown to be ours is not modified, is not
                // adopted, and is left where it is.
                Self::require_snapshot_of_this_database(&canonical, &verified, &live_identity)?;
                let pre = pre.map_err(|reason| MigrationError::SnapshotAliasUnsafe {
                    path: canonical.clone(),
                    reason,
                })?;
                match Self::secure_adopted_snapshot(&canonical, pre, identity)? {
                    Secured::Ready => Some(Backup::existing(canonical)),
                    // The snapshot was removed under us — most likely by a
                    // competing migrator that finished and discarded the one it
                    // took. There is nothing to adopt and nothing to protect, so
                    // a fresh snapshot is taken rather than the open failing
                    // over a file that is no longer there.
                    Secured::Gone => Some(Backup::take(self.conn, db_path, identity)?),
                }
            }
            Err(_) => Some(Backup::take(self.conn, db_path, identity)?),
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

    /// Makes an existing, verified snapshot private to its owner before it is adopted.
    ///
    /// # Why an adopted snapshot needs this
    ///
    /// A snapshot taken by this code is restricted before it is published, so it is
    /// born `0600`. A snapshot left behind by an **earlier** build is not: it is
    /// whatever the platform created, which under the common `022` is `0644` —
    /// world-readable. Adopting it unchanged would keep a world-readable copy of
    /// every task, every proposed action, the approval ledger and the audit journal
    /// in the one place the operator is told to keep as their recovery point.
    ///
    /// # The order, and why each step is there
    ///
    /// 1. **The path must name a file with exactly one name.** The restriction
    ///    changes the mode of an *inode*, so an inode reachable through a second
    ///    name would have that other name's object changed as well. The store's own
    ///    link-count rule refuses that, and reusing it here is the point: the same
    ///    check that protects the database protects the copy of it.
    /// 2. **The restriction goes through a descriptor.** `restrict_file_to_owner`
    ///    opens the file once and `fchmod`s that descriptor, so the object whose mode
    ///    changes is the object that was opened.
    /// 3. **The path must still name the same file afterwards.** A path replaced
    ///    between the observation and the restriction would otherwise be adopted
    ///    without ever having been checked.
    ///
    /// # What it refuses, and what it preserves
    ///
    /// A refusal **leaves the snapshot exactly where it was**. It may be the only
    /// good copy of a database whose last migration failed, and overwriting it to
    /// work around a permission failure would destroy the recovery point the
    /// refusal is protecting.
    ///
    /// # The platform without a mechanism
    ///
    /// A platform with no owner-only mechanism answers
    /// [`orxnud_domain::platform::PrivacyOutcome::NotApplicable`], and the adoption
    /// **proceeds** — there is no restriction to make, and refusing would break a
    /// platform the product supports for storage. `NotApplicable` is never converted
    /// into `Restricted`: the file is not private, and nothing here says that it is.
    ///
    /// # The file that is **gone**
    ///
    /// Two things can remove the file between the verification and here: a
    /// competing migrator that finished and discarded the snapshot it took, and
    /// an operator. There is then nothing to make private, nothing to protect and
    /// nothing to adopt — and reporting that as a *privacy* failure would fail an
    /// open that has lost nothing. So it is reported as what it is, and the
    /// caller takes a fresh snapshot instead.
    ///
    /// This is not a rare interleaving. The canonical snapshot path is shared by
    /// every process migrating the same database, and one of them finishing
    /// successfully removes the file the others are looking at.
    fn secure_adopted_snapshot(
        path: &Path,
        pre: PreObservation,
        identity: &dyn FilesystemIdentity,
    ) -> Result<Secured, MigrationError> {
        if let Err(reason) = identity.restrict_file_to_owner(path) {
            if Self::is_gone(path, identity) {
                return Ok(Secured::Gone);
            }
            return Err(MigrationError::SnapshotPrivacy {
                path: path.to_path_buf(),
                reason,
            });
        }
        // The identity must be unchanged: a path replaced while it was being secured
        // is not the file that was verified.
        if let Err(reason) = crate::alias::observe_after_open(path, identity, pre) {
            if matches!(reason, AliasRefusal::Disappeared) {
                return Ok(Secured::Gone);
            }
            return Err(MigrationError::SnapshotAliasUnsafe {
                path: path.to_path_buf(),
                reason,
            });
        }
        Ok(Secured::Ready)
    }

    /// Whether `path` no longer names a file at all.
    ///
    /// The platform is asked rather than the filesystem being probed, because the
    /// platform's answer is the one the rest of this module trusts: it is the
    /// same observation that establishes the link count and the identity. A
    /// platform that cannot answer says so, and a file that is still there is
    /// treated as still there.
    fn is_gone(path: &Path, identity: &dyn FilesystemIdentity) -> bool {
        matches!(identity.observe(path), FileFacts::Absent)
    }

    /// Gives the database its provenance identity, if it does not have one yet, and
    /// returns it.
    ///
    /// # Why this happens **before** the snapshot
    ///
    /// The identity is what binds a snapshot to the database it protects, and a
    /// snapshot can only carry it if the identity is already in the database when
    /// the copy is taken. So it is written first, and every snapshot this build
    /// takes afterwards carries it.
    ///
    /// # Why it is written even when the migration may then refuse
    ///
    /// Because the refusal is about the file at the canonical path, and this
    /// database is not that file. The identity is written to *this* database; the
    /// refused file is not touched at all.
    ///
    /// # The race
    ///
    /// Two processes can open the same database and both reach this. The write
    /// lock is taken up front (`IMMEDIATE`), the row is keyed by a constant, and
    /// the insert is `ON CONFLICT DO NOTHING` — so the second process waits, then
    /// finds the row the first one wrote, and reads *that* value back. The
    /// identity is therefore the same for both, and there is exactly one.
    ///
    /// # Why there is no "it already has one" shortcut
    ///
    /// There was one, and it made the property untestable: it read the identity
    /// and returned it without touching the row, so the insert's own semantics —
    /// which are what decide whether an existing identity is *kept* — were never
    /// exercised on a database that already had one. Replacing the insert with
    /// one that overwrites was then a mutation no test could see.
    ///
    /// The shortcut saved one small write transaction on a path that only runs
    /// when there is a migration to apply, and it cost the only thing that
    /// matters here: the evidence that the identity is stable.
    ///
    /// # Errors
    ///
    /// [`MigrationError::ProvenanceUnavailable`] if the identity cannot be
    /// written or read back.
    fn ensure_database_identity(conn: &Connection) -> Result<String, MigrationError> {
        let unavailable = |source| MigrationError::ProvenanceUnavailable { source };
        let tx = crate::tx::authority_transaction(conn).map_err(unavailable)?;
        tx.execute_batch(crate::schema::DATABASE_IDENTITY_DDL)
            .map_err(unavailable)?;
        tx.execute(
            "INSERT INTO database_identity (singleton, id, created_at_ms) VALUES (1, ?1, ?2)
             ON CONFLICT(singleton) DO NOTHING;",
            rusqlite::params![new_database_identity(), now_ms()],
        )
        .map_err(unavailable)?;
        let id: String = tx
            .query_row(
                "SELECT id FROM database_identity WHERE singleton = 1;",
                [],
                |r| r.get(0),
            )
            .map_err(unavailable)?;
        tx.commit().map_err(unavailable)?;
        Ok(id)
    }

    /// Requires that `verified` is a snapshot of the database whose identity is
    /// `live_identity`.
    ///
    /// # What "verifies" does and does not say
    ///
    /// [`Backup::verify`] establishes that the file is a **database**: it opens,
    /// it passes `integrity_check`, it has a `schema_meta` and that table has
    /// rows. Every one of those is a statement about the file's *shape*. None of
    /// them is a statement about *whose* it is, and a complete, healthy database
    /// belonging to another installation passes all of them.
    ///
    /// That is not a hypothetical. The file at the canonical path is adopted
    /// rather than replaced precisely because it may be the only good copy of a
    /// database whose last migration failed — so it is also the file most likely
    /// to be *stale*, and a state directory copied from another machine brings
    /// its own `.pre-migration.bak` with it.
    ///
    /// # The two refusals
    ///
    /// * **No provenance at all** (`SnapshotProvenanceMissing`): the file was
    ///   written by a build that predates the identity, or it is a foreign
    ///   database. The file alone cannot tell those apart, and neither can this
    ///   code, so the file is refused.
    /// * **Another database's identity** (`SnapshotProvenanceMismatch`): the file
    ///   says what it is, and it is not this.
    ///
    /// Both **leave the file exactly where it was**. It is not this store's to
    /// delete, and it may be the only good copy of something.
    fn require_snapshot_of_this_database(
        path: &Path,
        verified: &VerifiedSnapshot,
        live_identity: &str,
    ) -> Result<(), MigrationError> {
        match &verified.identity {
            None => Err(MigrationError::SnapshotProvenanceMissing {
                path: path.to_path_buf(),
            }),
            Some(found) if found != live_identity => {
                Err(MigrationError::SnapshotProvenanceMismatch {
                    path: path.to_path_buf(),
                    expected: live_identity.to_owned(),
                    found: found.clone(),
                })
            }
            Some(_) => Ok(()),
        }
    }
}

/// The identity of the database `conn` is connected to, if it has one.
///
/// `None` for a database that has never been given one: one written by a build
/// that did not have the provenance table, or one this store has never migrated.
///
/// The absence is reported as an absence rather than as an error, because "this
/// database has no identity" and "this database is not a database" are different
/// facts and only one of them is a failure.
pub(crate) fn read_database_identity(conn: &Connection) -> Result<Option<String>, rusqlite::Error> {
    use rusqlite::OptionalExtension;

    let has_table: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'database_identity';",
        [],
        |r| r.get(0),
    )?;
    if has_table == 0 {
        return Ok(None);
    }
    let id = conn
        .query_row(
            "SELECT id FROM database_identity WHERE singleton = 1;",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    Ok(id)
}

/// A fresh identity for a database.
///
/// 128 bits, hex.
///
/// # Where the entropy comes from
///
/// `RandomState`'s keys are seeded by the operating system and incremented per
/// instance, so two databases in one process get different values and neither
/// is derivable from the other. Nothing in this crate needed a randomness
/// dependency for it, and adding one for a discriminator would be a poor trade.
///
/// # What it is and is not
///
/// It is a **discriminator**, not a secret: it is stored in the database in the
/// clear, and anyone who can read the database can read it. What it has to be
/// is **unique per database instance** and **stable for the life of that
/// instance**, because it is what says "this snapshot is a snapshot of that
/// database".
fn new_database_identity() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut first = RandomState::new().build_hasher();
    let second = RandomState::new().build_hasher();
    let entropy = second.finish();
    first.write_u64(entropy);
    first.write_u64(now_nanos());
    first.write_u32(std::process::id());
    format!("{:016x}{:016x}", first.finish(), entropy)
}

fn now_nanos() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
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
/// # The filesystem-identity capability is required
///
/// As [`crate::sqlite::Store::open`]: ADR-0058 Decision 2 requires every open of a
/// database to present the capability that can say how many names reach it, and
/// requires a platform that cannot answer to be a refusal.
///
/// # Errors
///
/// Any [`StoreError`].
pub fn open_and_migrate(
    path: &std::path::Path,
    identity: &dyn FilesystemIdentity,
) -> Result<crate::sqlite::Store, StoreError> {
    // Whether the file already exists is read *before* opening it, because a failed
    // first migration must not leave a half-built file behind for the next start to
    // inherit. See `discard_failed_initialisation`.
    let pre_existing = path.exists();
    let store = crate::sqlite::Store::open(path, true, identity)?;
    match MigrationRunner::new(store.conn()).migrate(path, identity) {
        Ok(_) => Ok(store),
        Err(MigrationError::RecoveryRequired { source, snapshot }) => {
            // S-31: the store holds shared ownership for as long as it lives, so a restore
            // on this path could not take exclusive ownership. Drop it first, which
            // closes the connection and releases the lease, then recover.
            drop(store);
            recover_from_snapshot(path, &snapshot, identity)?;
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
/// # The filesystem-identity capability is required
///
/// As [`crate::sqlite::Store::open`]: the restore writes **through** the existing
/// database file, so a database reachable through a second name is one whose two
/// names would end up holding different content. ADR-0058 Decision 2 requires the
/// capability on every open and requires "the platform cannot say" to be a refusal.
///
/// # Errors
///
/// [`MigrationError::RestoreFailed`] if the restore does not produce a database whose
/// logical content matches the snapshot. The original migration error is the caller's to
/// keep: this reports that recovery itself failed, which is a different and more urgent
/// fact.
pub fn recover_from_snapshot(
    db_path: &Path,
    snapshot: &Path,
    identity: &dyn FilesystemIdentity,
) -> Result<(), StoreError> {
    crate::backup::Backup::existing(snapshot.to_path_buf())
        .restore_coordinated(db_path, identity)
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
///
/// # The canonical snapshot, and why it is never removed here
///
/// The snapshot path (`<db>.pre-migration.bak`) is **not** removed by this cleanup,
/// whatever is at it.
///
/// The reason is the rule the whole cleanup is built on: **it removes what this call
/// created.** The file at the snapshot path is not this call's. This call publishes a
/// snapshot there only on the paths that end in a recovery obligation — the paths where
/// the caller restores it — so on every path that reaches this cleanup the file there is
/// one that was **already** on disk before the call.
///
/// That file is not this store's to delete. It may be the only good copy of a pre-migration
/// state, and it may be the file a refusal has just declined to adopt: a snapshot whose
/// provenance is missing or belongs to another database is **refused** and **left in
/// place**, and the refusal's message tells the operator to move it aside. A cleanup that
/// then deletes it makes that message false and destroys the only recovery copy.
///
/// # Why there is no "it is only debris" exception
///
/// There was one, and it was wrong in a way no amount of care in the classification
/// could fix. The exception classified the file at the path — by reading its first
/// sixteen bytes — and then removed **the path**. Between those two steps the file at
/// the path can change: another process migrating the same database publishes its own
/// snapshot there, and the removal then deletes *that* snapshot, which is a valid
/// recovery point of the same database.
///
/// Nothing prevents that interleaving. The lease is keyed on the **database** path, not
/// the snapshot path; the migration path holds only a **shared** lease, which does not
/// exclude another migrator; and this cleanup runs after the connection and the lease
/// have been dropped, so it holds no ownership lock at all. Publication is a
/// `rename` over the canonical path, which is atomic as a replacement and takes no lock
/// this cleanup honours. SQLite's own locking covers the database file, not the
/// snapshot path.
///
/// A `dev`/`inode` comparison immediately before the unlink does not close the window
/// either — it narrows it to the instructions between the comparison and the unlink —
/// and a same-directory rename would move whatever occupies the path at that instant,
/// which is the same harm under a different name. On POSIX there is no unlink-by-descriptor,
/// so the only way to remove *that* file is to unlink a name that is known to refer to it,
/// and the canonical path is not such a name.
///
/// So the cleanup does not touch the canonical path at all, and the check-then-remove
/// sequence is gone rather than narrowed.
///
/// # What is left at the canonical path, and who replaces it
///
/// A stale **non-database** file may sit at the canonical path until the next
/// successful migration publishes a fresh snapshot over it. That is safe, and it needs
/// no special handling: `Backup::verify` refuses a file that is not a database, so the
/// next migration takes the **take** branch, and `Backup::publish` renames the staged
/// copy over the canonical path — an atomic replacement, staged, verified, restricted and
/// alias-checked exactly as any other published snapshot is. The stale file is replaced
/// by that publication, not by the cleanup.
pub(crate) fn discard_failed_initialisation(db_path: &Path, pre_existing: bool) {
    if pre_existing {
        return;
    }
    // The sidecars too. A `-wal` without its database is not inert: SQLite may recreate
    // the database from it on the next open, which is precisely the stale-data problem
    // S-30 exists to prevent, one step removed.
    //
    // The canonical snapshot path is deliberately **not** in this list. See above: it is
    // not this call's file, and no pathname-based classification can bind a removal to
    // the file it classified.
    for path in [
        db_path.to_path_buf(),
        wal_sidecar(db_path),
        shm_sidecar(db_path),
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

    /// A history like `1, 2, 14` used to look "current" because only `MAX(version)`
    /// was read, so the runner skipped versions 3..13 and opened a database with none
    /// of their tables. The maximum is not a history; the gap is a refusal.
    #[test]
    fn a_gapped_schema_history_is_refused_rather_than_treated_as_current() {
        let conn = mem();
        conn.execute_batch(
            "CREATE TABLE schema_meta (
                 version INTEGER PRIMARY KEY,
                 name TEXT NOT NULL,
                 applied_at INTEGER NOT NULL
             );
             INSERT INTO schema_meta VALUES (1, 'schema_meta', 0);
             INSERT INTO schema_meta VALUES (2, 'tasks', 0);
             INSERT INTO schema_meta VALUES (14, 'task_proposal_identity', 0);",
        )
        .expect("stage a gapped history");

        let err = MigrationRunner::new(&conn)
            .migrate_ephemeral()
            .expect_err("a gap must not be treated as a current schema");
        assert!(
            err.to_string().contains("schema history"),
            "the refusal must name the history, not a generic SQL failure: {err}"
        );
        let recorded: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_meta;", [], |r| r.get(0))
            .expect("count");
        assert_eq!(
            recorded, 3,
            "a refused migration must not rewrite the history"
        );
    }

    /// A newer database is not "already current"; it is a schema this binary cannot
    /// understand. The old maximum-only read returned `Ok([])` and opened it.
    #[test]
    fn a_newer_schema_version_is_refused_rather_than_silently_accepted() {
        let conn = mem();
        conn.execute_batch(
            "CREATE TABLE schema_meta (
                 version INTEGER PRIMARY KEY,
                 name TEXT NOT NULL,
                 applied_at INTEGER NOT NULL
             );",
        )
        .expect("stage schema_meta");
        for version in 1..=CURRENT_VERSION + 1 {
            conn.execute(
                "INSERT INTO schema_meta VALUES (?1, 'future', 0);",
                [i64::from(version)],
            )
            .expect("record");
        }

        let err = MigrationRunner::new(&conn)
            .migrate_ephemeral()
            .expect_err("a newer schema must not be accepted");
        assert!(
            err.to_string().contains("newer than this binary"),
            "the refusal must say the database is newer: {err}"
        );
        let recorded: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_meta;", [], |r| r.get(0))
            .expect("count");
        assert_eq!(
            recorded,
            i64::from(CURRENT_VERSION) + 1,
            "a refused migration must not rewrite the future history"
        );
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
                // both are success. What must never happen is a hard failure. This now
                // drives the production `migrate` path, so the snapshot lock is part of
                // what the four concurrent callers exercise.
                MigrationRunner::new(&conn)
                    .migrate(&p, &orxnud_platform_fs::OsIdentity)
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
                .migrate(&path, &orxnud_platform_fs::OsIdentity)
                .expect("read version"),
            Vec::<u32>::new(),
            "everything is applied exactly once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The snapshot lock is genuinely exclusive, not an advisory name.
    ///
    /// The concurrent migration test above exercises the production path, but its
    /// success alone would not distinguish a working lock from a fast race. This
    /// observes the exclusion directly: a second open file description cannot take
    /// the lock while the guard is alive, and can take it as soon as the guard drops.
    #[test]
    fn the_snapshot_lock_excludes_a_second_holder() {
        let path = tmp_db("snapshot-lock");
        let held = SnapshotLock::acquire(&path).expect("first holder");
        let other = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(SnapshotLock::path_for(&path))
            .expect("open the lock path");
        assert!(
            other.try_lock().is_err(),
            "a second holder must not acquire the snapshot lock while the first is alive"
        );
        drop(held);
        other
            .try_lock()
            .expect("the lock must be released when the guard drops");
        drop(other);
        let _ = std::fs::remove_dir_all(path.parent().expect("temp dir"));
    }

    /// A final-component symlink is one database with two path spellings, but two
    /// **snapshot** paths.
    ///
    /// V-101's lost-recovery interleaving needs two migrators to publish and discard the
    /// same snapshot pathname. A final-component alias cannot produce that: its snapshot
    /// is a sibling of the alias (`alias.db.pre-migration.bak`), not of the target
    /// (`state.db.pre-migration.bak`), so `discard` by one spelling cannot remove the
    /// other's recovery point. The lock is deliberately keyed by the snapshot pathname it
    /// protects, so each of those paths is serialised independently. Directory-level
    /// aliases are different: they resolve to the same snapshot file and therefore the
    /// same lock file, which is the case the OS lock covers.
    #[cfg(unix)]
    #[test]
    fn a_final_component_symlink_spelling_gets_its_own_snapshot_path() {
        let db = tmp_db("snapshot-alias");
        std::fs::write(&db, b"database bytes").expect("write the target");
        let alias = db.with_file_name("alias.db");
        std::os::unix::fs::symlink(&db, &alias).expect("symlink the target");

        assert_eq!(
            std::fs::canonicalize(&alias).expect("canonicalize the alias"),
            std::fs::canonicalize(&db).expect("canonicalize the target"),
            "the two spellings must name one database"
        );
        assert_ne!(
            Backup::path_for(&db),
            Backup::path_for(&alias),
            "two spellings must not share a snapshot path, or one discard could remove \
             the other's recovery point"
        );
        assert_ne!(
            SnapshotLock::path_for(&db),
            SnapshotLock::path_for(&alias),
            "the snapshot lock is keyed by the pathname it protects"
        );

        let _ = std::fs::remove_dir_all(db.parent().expect("temp dir"));
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
                "database_identity",
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
            .migrate(&path, &orxnud_platform_fs::OsIdentity)
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
            .migrate(&path, &orxnud_platform_fs::OsIdentity)
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

        let Err(err) = open_and_migrate(&path, &orxnud_platform_fs::OsIdentity) else {
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

    /// **A failed initialisation removes the database it created and its sidecars —
    /// and nothing else.**
    ///
    /// The sidecars are tested where they can actually exist. An earlier version of this
    /// test asserted that no `-wal`/`-shm` survived, and **passed with the sidecar removal
    /// deleted**: nothing wrote to the database before the snapshot was attempted, so
    /// SQLite had not created them and the assertion could not fail. That is the failure
    /// mode AGENTS.md §3 warns about — a green test reading as coverage of something it
    /// never touched — so the sidecars are created here by hand.
    ///
    /// The cleanup removes what *this call* created. The file at the canonical
    /// snapshot path is not this call's: this call publishes a snapshot there only on
    /// the paths that end in a recovery obligation, which the caller restores instead
    /// of cleaning up. So on every path that reaches this cleanup, the file there was
    /// already on disk before the call — and it is not the store's to delete.
    ///
    /// The file here is deliberately **not** a database: it is what a stale
    /// non-database file at that path looks like. It is left where it is, and the
    /// next successful migration replaces it by publishing a fresh snapshot over it
    /// (see `a_successful_migration_replaces_stale_non_database_debris`).
    ///
    /// # Why the snapshot is not removed here at all
    ///
    /// A version of this test required the snapshot to be removed with the database.
    /// That was the rule that made the cleanup a **check-then-delete** sequence: the
    /// file at the path was classified (a header read), and then the *path* was
    /// deleted — and between the two, another process migrating the same database
    /// could publish its own snapshot there. The removal then deleted a valid
    /// recovery point of the same database.
    ///
    /// Nothing prevents that interleaving: the lease is keyed on the database path,
    /// the migration path holds only a shared lease, and this cleanup runs with no
    /// lease at all. So the rule is now the simpler one — the cleanup does not touch
    /// the canonical path — and the check-then-delete sequence is gone rather than
    /// narrowed.
    #[test]
    fn discarding_a_failed_initialisation_removes_the_database_and_its_sidecars() {
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

        for p in [path.clone(), wal_sidecar(&path), shm_sidecar(&path)] {
            assert!(
                !p.exists(),
                "{} must be removed with the database it belonged to",
                p.display()
            );
        }
        assert!(
            Backup::path_for(&path).exists(),
            "the file at the canonical snapshot path is not this call's: it must survive the \
             cleanup, whatever it is. It may be the only good copy of a pre-migration state, \
             and it may be the file a refusal has just declined to adopt."
        );
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

    /// **A candidate recovery snapshot at the canonical path survives the cleanup.**
    ///
    /// The cleanup removes what *this call* created. The file at the snapshot path is
    /// not this call's: this call publishes a snapshot there only on the paths that end
    /// in a recovery obligation, which the caller restores instead of cleaning up. So a
    /// database sitting at that path may be the only good copy of a pre-migration state,
    /// and it is not the store's to delete.
    ///
    /// This is the complement of the test above. There, the *database* predated the call
    /// and everything survived; here the database was created by the call and is removed,
    /// while the candidate beside it is not.
    #[test]
    fn a_candidate_recovery_snapshot_survives_the_failed_initialisation_cleanup() {
        let path = tmp_db("candidate-kept");
        let canonical = Backup::path_for(&path);
        {
            let c = Connection::open(&canonical).expect("open the candidate");
            c.execute_batch("CREATE TABLE somebody_elses (id TEXT PRIMARY KEY);")
                .expect("seed the candidate");
        }
        let before = std::fs::read(&canonical).expect("read the candidate");

        discard_failed_initialisation(&path, false);

        assert!(
            canonical.exists(),
            "a candidate recovery snapshot must survive the cleanup: it is not this call's \
             file, and it may be the only good copy of a pre-migration state"
        );
        assert_eq!(
            std::fs::read(&canonical).expect("re-read the candidate"),
            before,
            "the candidate must be byte-identical after the cleanup"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// A **version-1** database, written before the provenance table existed, so it
    /// carries no identity at all.
    ///
    /// This is the shape a build that predates the provenance table leaves behind — and
    /// the shape the refusal tells the operator to move aside. It is also the shape
    /// whose next migration **fails** (migration 2 creates the `tasks` table, and it is
    /// already there), which is what keeps a snapshot of it retained as a recovery
    /// obligation.
    fn write_a_version_1_database(path: &std::path::Path) {
        let c = Connection::open(path).expect("open the version-1 database");
        c.execute_batch(
            "CREATE TABLE schema_meta (
                 version INTEGER PRIMARY KEY,
                 name TEXT NOT NULL,
                 applied_at INTEGER NOT NULL);
             INSERT INTO schema_meta (version, name, applied_at) VALUES (1, 'schema_meta', 0);
             CREATE TABLE tasks (id TEXT PRIMARY KEY);
             INSERT INTO tasks (id) VALUES ('legacy-1');",
        )
        .expect("seed the version-1 database");
    }

    /// A **legacy** candidate at the canonical path: a version-1 database, written
    /// before the provenance table existed, so it carries no identity at all.
    ///
    /// This is the shape a build that predates the provenance table leaves behind — and
    /// the shape the refusal tells the operator to move aside.
    fn plant_a_legacy_candidate(canonical: &std::path::Path) {
        write_a_version_1_database(canonical);
    }

    /// **A successful migration replaces stale non-database debris at the canonical
    /// snapshot path.**
    ///
    /// The cleanup does not remove the canonical path, so a file that is not a database
    /// can sit there after a failed initialisation. The next migration must replace it —
    /// and must replace it *safely*: the published snapshot is staged, verified,
    /// restricted and alias-checked like any other, and it reaches the canonical path by
    /// an atomic rename.
    ///
    /// The migration here **fails** on purpose, after the snapshot is published: a
    /// successful migration discards the snapshot it took, so the canonical path would be
    /// empty again and the replacement would not be observable. A failed migration keeps
    /// the published snapshot as the recovery obligation, which is what makes the
    /// replacement visible.
    #[test]
    fn a_successful_migration_replaces_stale_non_database_debris() {
        let path = tmp_db("debris-replaced");
        // A version-1 database whose next migration fails, so the published snapshot is
        // retained rather than discarded.
        write_a_version_1_database(&path);

        // The debris: a file at the canonical path that is not a database at all.
        let canonical = Backup::path_for(&path);
        std::fs::write(&canonical, b"not a database at all").expect("debris");
        let before = std::fs::read(&canonical).expect("read the debris");

        let c = Connection::open(&path).expect("open");
        let err = MigrationRunner::new(&c)
            .migrate(&path, &orxnud_platform_fs::OsIdentity)
            .expect_err("migration 2 must fail against the colliding table");
        drop(c);
        assert!(
            matches!(err, MigrationError::RecoveryRequired { .. }),
            "precondition: the migration must fail and hand back a recovery obligation, \
             got {err:?}"
        );

        // The path now holds the published snapshot, not the debris.
        let after = std::fs::read(&canonical).expect("read the published snapshot");
        assert_ne!(
            after, before,
            "the stale file must have been replaced by the published snapshot, not left in \
             place and not deleted by the cleanup"
        );
        assert!(
            Backup::verify(&canonical).is_ok(),
            "the published snapshot must verify: the replacement is a real snapshot, not a \
             file that merely occupies the path"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// A **foreign** candidate at the canonical path: a complete, healthy database
    /// belonging to another database, so it carries an identity that is not ours.
    ///
    /// Taken through the production snapshot path, so the planted file is a real,
    /// transactionally consistent copy.
    fn plant_a_foreign_candidate(canonical: &std::path::Path, other: &std::path::Path) {
        {
            let c = Connection::open(other).expect("open the other database");
            MigrationRunner::new(&c)
                .migrate(other, &orxnud_platform_fs::OsIdentity)
                .expect("migrate the other database");
        }
        let c = Connection::open(other).expect("reopen the other database");
        let snapshot = Backup::take(&c, other, &orxnud_platform_fs::OsIdentity)
            .expect("snapshot the other database");
        std::fs::copy(snapshot.path(), canonical).expect("plant the foreign candidate");
    }

    /// The assertions every refused-snapshot case shares.
    ///
    /// The file must still be there and byte-identical; and the live database must be
    /// in the state the caller intended — the half-built file this call created is
    /// removed, so the next start begins clean and the refused snapshot's content is
    /// nowhere in it.
    fn assert_a_refused_snapshot_survived(
        canonical: &std::path::Path,
        live: &std::path::Path,
        before: &[u8],
        context: &str,
    ) {
        assert!(
            canonical.exists(),
            "the refused snapshot must still be there: the refusal tells the operator to move \
             it aside, so the store may not have deleted it ({context})"
        );
        assert_eq!(
            std::fs::read(canonical).expect("re-read the refused snapshot"),
            before,
            "the refused snapshot must be byte-identical after the refusal ({context})"
        );
        assert!(
            !live.exists(),
            "the half-built database this call created must still be removed, so the next \
             start begins clean ({context})"
        );
    }

    /// **A refused snapshot survives the audit journal's constructor.**
    ///
    /// The journal is opened by the daemon at startup, so this is a path an operator
    /// meets: the daemon refuses to start, and the file the refusal names must still be
    /// there to be moved aside.
    #[test]
    fn the_audit_journal_preserves_a_refused_snapshot_with_no_provenance() {
        let path = tmp_db("journal-legacy");
        let canonical = Backup::path_for(&path);
        plant_a_legacy_candidate(&canonical);
        let before = std::fs::read(&canonical).expect("read the candidate");
        assert!(
            !path.exists(),
            "precondition: the journal database is absent"
        );

        let err = match crate::security_state::SqliteAuditJournal::open(
            &path,
            &orxnud_platform_fs::OsIdentity,
        ) {
            Ok(_) => panic!("the journal must refuse the candidate"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("carries no database identity"),
            "the refusal must be the provenance refusal, got: {err}"
        );
        assert!(
            !err.contains("could not be made private"),
            "a provenance refusal must not be reported as a privacy failure: {err}"
        );
        assert!(
            !err.contains("could not be shown to be safe"),
            "a provenance refusal must not be reported as an alias failure: {err}"
        );
        assert_a_refused_snapshot_survived(
            &canonical,
            &path,
            &before,
            "the snapshot carries no database identity",
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// **A refused snapshot survives the approval ledger's constructor.**
    ///
    /// The ledger is opened by the daemon at startup too, and it is the store of which
    /// approvals were spent — so its pre-migration copy is evidence, not debris.
    #[test]
    fn the_approval_ledger_preserves_a_refused_snapshot_with_no_provenance() {
        let path = tmp_db("ledger-legacy");
        let canonical = Backup::path_for(&path);
        plant_a_legacy_candidate(&canonical);
        let before = std::fs::read(&canonical).expect("read the candidate");
        assert!(
            !path.exists(),
            "precondition: the ledger database is absent"
        );

        let err = match crate::security_state::SqliteApprovalLedger::open(
            &path,
            &orxnud_platform_fs::OsIdentity,
        ) {
            Ok(_) => panic!("the ledger must refuse the candidate"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("carries no database identity"),
            "the refusal must be the provenance refusal, got: {err}"
        );
        assert!(
            !err.contains("could not be made private"),
            "a provenance refusal must not be reported as a privacy failure: {err}"
        );
        assert!(
            !err.contains("could not be shown to be safe"),
            "a provenance refusal must not be reported as an alias failure: {err}"
        );
        assert_a_refused_snapshot_survived(
            &canonical,
            &path,
            &before,
            "the snapshot carries no database identity",
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// **A refused snapshot with no provenance survives `open_and_migrate`.**
    ///
    /// The refusal says the file is left in place and tells the operator to move it
    /// aside. Before this correction the caller's cleanup deleted it: the guard was on
    /// whether the *live database* existed before the call, and a file at the snapshot
    /// path that was already there is not that call's to delete.
    ///
    /// The case is the first-start one, and it is the one that loses data: the database
    /// does not exist, so the cleanup removes it — and used to remove the snapshot
    /// beside it, which may have been the only good copy of a pre-migration state.
    #[test]
    fn open_and_migrate_preserves_a_refused_snapshot_with_no_provenance() {
        let path = tmp_db("open-and-migrate-legacy");
        let canonical = Backup::path_for(&path);
        plant_a_legacy_candidate(&canonical);
        let before = std::fs::read(&canonical).expect("read the candidate");
        assert!(!path.exists(), "precondition: the live database is absent");

        let err = open_and_migrate(&path, &orxnud_platform_fs::OsIdentity)
            .expect_err("the migration must refuse the candidate");

        match err {
            StoreError::Migration(inner) => assert!(
                matches!(*inner, MigrationError::SnapshotProvenanceMissing { .. }),
                "the caller must receive a missing-provenance refusal, got {inner:?}"
            ),
            other => panic!("expected a migration refusal, got {other:?}"),
        }
        assert_a_refused_snapshot_survived(
            &canonical,
            &path,
            &before,
            "the snapshot carries no database identity",
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// **A refused snapshot with another database's provenance survives
    /// `open_and_migrate`.**
    ///
    /// The same case with the other refusal: the candidate is a complete, healthy
    /// database that belongs to somebody else, so it verifies and is refused on its
    /// provenance rather than on its shape.
    #[test]
    fn open_and_migrate_preserves_a_refused_snapshot_with_another_identity() {
        let path = tmp_db("open-and-migrate-foreign");
        let canonical = Backup::path_for(&path);
        let other = path.with_file_name("other.db");
        plant_a_foreign_candidate(&canonical, &other);
        let before = std::fs::read(&canonical).expect("read the candidate");
        assert!(!path.exists(), "precondition: the live database is absent");

        let err = open_and_migrate(&path, &orxnud_platform_fs::OsIdentity)
            .expect_err("the migration must refuse the candidate");

        match err {
            StoreError::Migration(inner) => assert!(
                matches!(*inner, MigrationError::SnapshotProvenanceMismatch { .. }),
                "the caller must receive a provenance-mismatch refusal, got {inner:?}"
            ),
            other => panic!("expected a migration refusal, got {other:?}"),
        }
        assert_a_refused_snapshot_survived(
            &canonical,
            &path,
            &before,
            "the snapshot was taken from a different database",
        );
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
            open_and_migrate(&path, &orxnud_platform_fs::OsIdentity).is_err(),
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
            .migrate(&path, &orxnud_platform_fs::OsIdentity)
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

        let store = open_and_migrate(&path, &orxnud_platform_fs::OsIdentity).expect("open+migrate");
        assert_eq!(
            MigrationRunner::new(store.conn())
                .applied_version()
                .expect("version"),
            CURRENT_VERSION
        );
        drop(store);
        // Reopen: the version is durable.
        let store2 = open_and_migrate(&path, &orxnud_platform_fs::OsIdentity).expect("reopen");
        assert_eq!(
            MigrationRunner::new(store2.conn())
                .migrate(&path, &orxnud_platform_fs::OsIdentity)
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

        let store =
            crate::sqlite::Store::open(&path, true, &orxnud_platform_fs::OsIdentity).expect("open");
        let applied = MigrationRunner::new(store.conn())
            .migrate(&path, &orxnud_platform_fs::OsIdentity)
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
            let store = crate::sqlite::Store::open(&path, true, &orxnud_platform_fs::OsIdentity)
                .expect("open");
            MigrationRunner::new(store.conn())
                .migrate(&path, &orxnud_platform_fs::OsIdentity)
                .expect("run");
        }
        let backup = Backup::take(
            &Connection::open(&path).expect("reopen"),
            &path,
            &orxnud_platform_fs::OsIdentity,
        )
        .expect("take");
        {
            let b = Connection::open(backup.path()).expect("open snapshot");
            b.execute_batch("DROP TABLE schema_meta;").expect("drop");
        }
        Backup::verify(backup.path()).expect_err("a snapshot with no schema_meta must be refused");

        // (b) schema_meta present but empty.
        let path = tmp_db("strict-norows");
        {
            let store = crate::sqlite::Store::open(&path, true, &orxnud_platform_fs::OsIdentity)
                .expect("open");
            MigrationRunner::new(store.conn())
                .migrate(&path, &orxnud_platform_fs::OsIdentity)
                .expect("run");
        }
        let backup = Backup::take(
            &Connection::open(&path).expect("reopen"),
            &path,
            &orxnud_platform_fs::OsIdentity,
        )
        .expect("take");
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
        let store =
            crate::sqlite::Store::open(&path, true, &orxnud_platform_fs::OsIdentity).expect("open");
        let backup = Backup::take(store.conn(), &path, &orxnud_platform_fs::OsIdentity)
            .expect("a fresh database can be snapshotted");

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
