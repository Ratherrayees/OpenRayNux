//! OpenRayNux SQLite persistence.
//!
//! # Two hard requirements
//!
//! ## 1. The bundled SQLite is at least 3.51.3
//!
//! SQLite 3.51.3 (2026-03-13) fixed the **WAL-reset database corruption bug**,
//! documented as present in every version from 3.7.0 through 3.51.2. It
//! requires two or more connections writing and checkpointing concurrently with
//! tight timing — which is *precisely* the workload a durable task queue
//! creates.
//!
//! This is why we **bundle** SQLite (`libsqlite3-sys` with the `bundled`
//! feature) rather than linking the system library. The development machine
//! runs Fedora 44, which ships 3.51.2 — *below the fix*. Linking the system
//! library would mean shipping a data-corruption bug in the state most
//! developers, and many users, would run.
//!
//! The requirement is enforced **at compile time**: `build.rs` parses
//! `SQLITE_VERSION_NUMBER` out of the header `libsqlite3-sys` actually compiles,
//! and [`sqlite`] const-asserts on the result. Asserting against a constant we
//! wrote ourselves would prove nothing. See ADR-0006 and V-02.
//!
//! ## 2. `critical` state is written with `synchronous = FULL`
//!
//! `sqlite.org/wal.html` is explicit that in WAL mode `synchronous = NORMAL`
//! means *"syncing the content to the disk is not required, as long as the
//! application is willing to sacrifice durability following a power loss or
//! hard reboot."* OpenRayNux requires surviving power loss, so every connection
//! to critical state uses `FULL`.
//!
//! Pragmas are **verified by reading them back** ([`Pragma::verify`]), because a
//! pragma that silently failed to apply is indistinguishable from one that was
//! never set until the day the disk loses power.
//!
//! # What this crate owns
//!
//! `orxnud-store` is the **only** crate that speaks SQL (ADR-0006 decision 2).
//! Everything above it works in domain operations:
//!
//! * [`schema`] — the Phase 2 tables, and why each one is required.
//! * [`task_repo`] — tasks, leases, attempts, effects, approvals, events.
//! * [`schedule_repo`] — schedules and the fire ledger.
//! * [`migration`] — forward-only, transactional, snapshot-protected.
//! * [`backup`] — the online snapshot and restore that make a migration
//!   recoverable (ADR-0017).
//! * [`region`] — the declared state regions (ADR-0028).
//!
//! # The transaction discipline
//!
//! Every state transition is one `BEGIN IMMEDIATE` transaction, opened through
//! [`tx::authority_transaction`]. `IMMEDIATE` rather than the default `DEFERRED`
//! because `sqlite.org/lang_transaction.html` says: *"If the BEGIN IMMEDIATE
//! operation succeeds, then no subsequent operations in that transaction will
//! ever fail with a SQLITE_BUSY error."*
//!
//! The clause that matters is the first half of that sentence. `DEFERRED` takes
//! the write lock at the transaction's first **write**, not its first read — and a
//! task transition reads before it writes, because the read is what answers "is
//! this still legal?". So the lock arrives one statement too late: a competing
//! writer can commit in between, and the write is then refused outright with
//! `SQLITE_BUSY_SNAPSHOT`, which SQLite never passes to the busy handler because
//! waiting cannot make a stale snapshot current. `busy_timeout` does not rescue it.
//!
//! That was not a theoretical gap. `TaskRepository::tx` was documented here as
//! taking the lock before the read while calling `unchecked_transaction()`, which
//! is `DEFERRED` — so the crate asserted a property it did not have. See
//! [`tx`] for the measurement and `crates/orxnud-task/tests/v95_concurrency.rs`
//! for the reproduction.
//!
//! Every mutation here takes `&mut Connection`, so the compiler enforces that a
//! caller cannot hold a shared borrow across a transaction.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backup;
pub mod faults;
pub mod migration;
pub mod ownership;
pub mod pragma;
pub mod recovery;
pub mod region;
pub mod repository;
pub mod schedule_repo;
pub mod schema;
pub mod security_state;
pub mod sqlite;
pub mod task_repo;
pub mod tx;

pub use migration::{MigrationError, MigrationRunner};
pub use pragma::{Pragma, PragmaError};
pub use region::{RegionRegistry, StateRegion, task_layer_regions};
pub use repository::{Repository, RepositoryError, SchemaMeta};
pub use security_state::{SqliteApprovalLedger, SqliteAuditJournal};
pub use sqlite::{
    MIN_SQLITE_VERSION, SqliteVersion, Store, StoreError, open, verify_sqlite_version,
};

/// Staging a database at a chosen schema version, for tests in other crates.
///
/// # Why this exists rather than a re-exported `MIGRATIONS`
///
/// S-11/F-26 required `MIGRATIONS` — and every `schema::MIGRATION_*` DDL string —
/// to stop being public, because a `Connection` plus a `CREATE TABLE` is a schema
/// change with no pre-migration snapshot, no verification and no recovery. But
/// `orxnud-task`'s integration tests genuinely need to build a database at
/// version 10 to test the version 11–14 migrations, and `#[cfg(test)]` does not
/// cross a crate boundary.
///
/// Two shapes were available. Re-exporting the SQL behind a feature puts the
/// strings back into any build that enables it, which is the accident route
/// reopened. Offering a **function** gives a caller the only thing they actually
/// wanted — "put this connection at version N" — and hands them no DDL to carry
/// anywhere else.
///
/// Resolver 3 does not unify a dev-dependency's features into a normal build, so
/// `orxnud-task` enables this from `[dev-dependencies]` and no shipped binary
/// contains it. `tests/test_support_feature_is_not_shipped.rs` is what holds that,
/// by the same manifest-reading argument as the `fault-injection` test.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use crate::migration::{MIGRATIONS, Migration};
    use rusqlite::{Connection, Transaction, TransactionBehavior};

    /// Applies migrations 1..=`version` and records them, as an older build would
    /// have left the database.
    ///
    /// # Errors
    ///
    /// The underlying SQLite error, with the migration's name in the message where
    /// one is known.
    pub fn stage_schema(conn: &Connection, version: u32) -> Result<(), String> {
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
            let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
                .map_err(|e| format!("begin: {e}"))?;
            tx.execute_batch(m.sql)
                .map_err(|e| format!("{}: {e}", m.name))?;
            tx.execute(
                "INSERT OR REPLACE INTO schema_meta (version, name, applied_at) VALUES (?1,?2,0);",
                rusqlite::params![m.version, m.name],
            )
            .map_err(|e| format!("{}: {e}", m.name))?;
            tx.commit().map_err(|e| format!("{}: {e}", m.name))?;
        }
        Ok(())
    }

    /// The migration list, for a test that needs to assert on versions or names.
    ///
    /// Returns only `(version, name)`. The `sql` is deliberately not reachable
    /// through this module: a caller that can stage a database at a version is
    /// doing what it came to do, and one that can *read the DDL* can do it with a
    /// connection the guard never saw.
    #[must_use]
    pub fn migration_versions() -> Vec<(u32, &'static str)> {
        MIGRATIONS
            .iter()
            .map(|m: &Migration| (m.version, m.name))
            .collect()
    }
}
