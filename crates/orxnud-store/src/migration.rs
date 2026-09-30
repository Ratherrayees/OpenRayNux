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

use rusqlite::Connection;

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

/// The `schema_meta` table plus nothing else.
///
/// Phase 1 deliberately ships no application tables. This is bookkeeping the
/// migration runner requires, and it is the *only* table Phase 1 creates.
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "schema_meta",
    sql: "CREATE TABLE IF NOT EXISTS schema_meta (
        version     INTEGER PRIMARY KEY,
        name        TEXT NOT NULL,
        applied_at  INTEGER NOT NULL
    );",
}];

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
            let tx =
                self.conn
                    .unchecked_transaction()
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
    fn phase_one_ships_no_application_tables() {
        // The contract's exit criterion: schema_meta only.
        let conn = mem();
        let applied = MigrationRunner::new(&conn).run(true).expect("migrate");
        assert_eq!(applied, vec![1]);
        let names: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
            .expect("prepare")
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();
        assert_eq!(names, vec!["schema_meta"], "unexpected tables: {names:?}");
    }

    #[test]
    fn migration_is_idempotent() {
        let conn = mem();
        let r = MigrationRunner::new(&conn);
        assert_eq!(r.run(true).expect("first run"), vec![1]);
        assert_eq!(r.run(true).expect("second run"), Vec::<u32>::new());
        assert_eq!(r.applied_version().expect("version"), 1);
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
            1
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
}
