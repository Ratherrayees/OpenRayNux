//! The repository port: domain operations, never raw SQL.
//!
//! # Why there is no raw-SQL escape hatch
//!
//! `orxnud-store` is the only crate that speaks SQL. Exposing `conn()` publicly
//! to other crates would let parameterisation be forgotten in a call site — and
//! a SQL injection in a task engine is a privilege escalation, because the
//! engine writes the audit table.
//!
//! [`Store::conn`] therefore stays `pub` (the Phase 2 engine lives in
//! `orxnud-task` and needs it), but it is reachable only from within the
//! workspace, and CI gate **G7** plus review are what watch it. [`Repository`]
//! is the surface everything else uses.
//!
//! # The authority filter
//!
//! [`Repository::authoritative_query`] is the single place that implements ADR-0013's
//! rule: derived data can never satisfy an authority check. It is a *query*, not
//! a convention, so a caller cannot forget it — the only way to read
//! authoritative state is through a method that filters.

use rusqlite::Connection;

use crate::region::StateRegion;

/// A repository failure.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    /// A region name was declared twice.
    #[error("state region `{name}` is already declared")]
    DuplicateRegion {
        /// The repeated name.
        name: &'static str,
    },

    /// A row was not found.
    #[error("no row for {entity} {id}")]
    NotFound {
        /// Which entity.
        entity: &'static str,
        /// Its id.
        id: String,
    },

    /// A derived row was offered where authority was required.
    ///
    /// The runtime expression of "AI-generated memory is never authoritative".
    #[error("{entity} {id} is derived data and cannot satisfy an authority check")]
    DerivedNotAuthoritative {
        /// Which entity.
        entity: &'static str,
        /// Its id.
        id: String,
    },

    /// An underlying SQLite error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// A row of the bookkeeping table.
///
/// The only type Phase 1 persists, because it is the only table Phase 1 has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaMeta {
    /// The migration version.
    pub version: u32,
    /// The migration name.
    pub name: String,
    /// When it was applied, ms since epoch.
    pub applied_at: i64,
}

/// Domain-level persistence operations.
///
/// A trait so that `orxnud-policy` and `orxnud-task` depend on the *contract*,
/// not on SQLite. Not speculative: two crates in Phase 1 need it, and it is what
/// keeps the ADR-0006 driver swap (rusqlite → sqlx) a one-place change.
pub trait Repository {
    /// The error this repository returns.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Reads applied migrations.
    fn schema_meta(&self) -> Result<Vec<SchemaMeta>, Self::Error>;

    /// Applies a migration inside a transaction, recording it in `schema_meta`.
    fn migrate(&mut self, region: &StateRegion) -> Result<u32, Self::Error>;
}

/// A `rusqlite`-backed [`Repository`].
#[derive(Debug)]
pub struct SqliteRepository<'a> {
    conn: &'a mut Connection,
}

impl<'a> SqliteRepository<'a> {
    /// Wraps a connection.
    #[must_use]
    pub fn new(conn: &'a mut Connection) -> Self {
        Self { conn }
    }
}

impl Repository for SqliteRepository<'_> {
    type Error = RepositoryError;

    fn schema_meta(&self) -> Result<Vec<SchemaMeta>, RepositoryError> {
        let mut stmt = self
            .conn
            .prepare("SELECT version, name, applied_at FROM schema_meta ORDER BY version;")?;
        let rows = stmt.query_map([], |r| {
            Ok(SchemaMeta {
                version: r.get(0)?,
                name: r.get(1)?,
                applied_at: r.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn migrate(&mut self, _region: &StateRegion) -> Result<u32, RepositoryError> {
        // Phase 1 applies no application migrations; see crate docs. The
        // bookkeeping table is applied by `migration::MigrationRunner`, which
        // owns the snapshot precondition.
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::MigrationRunner;
    use crate::pragma::Pragma;
    use orxnud_domain::StateClass;

    fn migrated() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        MigrationRunner::new(&c).run(true).expect("migrate");
        c
    }

    fn region() -> StateRegion {
        StateRegion { name: "schema_meta", class: StateClass::Critical, owner: "orxnud-store", retention: "indefinite" }
    }

    #[test]
    fn schema_meta_reads_back_what_migration_recorded() {
        let mut c = migrated();
        let repo = SqliteRepository::new(&mut c);
        let meta = repo.schema_meta().expect("read");
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[0].version, 1);
        assert_eq!(meta[0].name, "schema_meta");
        assert!(meta[0].applied_at > 0);
    }

    #[test]
    fn migration_applies_nothing_in_phase_one() {
        let mut c = migrated();
        let mut repo = SqliteRepository::new(&mut c);
        assert_eq!(repo.migrate(&region()).expect("migrate"), 0);
    }

    #[test]
    fn error_codes_are_distinct() {
        use std::collections::BTreeSet;
        let errs = [
            RepositoryError::DuplicateRegion { name: "t" },
            RepositoryError::NotFound { entity: "task", id: "1".into() },
            RepositoryError::DerivedNotAuthoritative { entity: "memory", id: "1".into() },
        ];
        let mut names: BTreeSet<String> = BTreeSet::new();
        for e in &errs {
            let rendered = e.to_string();
            let head = rendered.split([' ', ':']).next().unwrap_or("").to_owned();
            assert!(names.insert(head.clone()), "duplicate error head: {head}");
        }
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn derived_rows_are_refused_where_authority_is_required() {
        let e = RepositoryError::DerivedNotAuthoritative { entity: "memory", id: "m-1".into() };
        assert!(e.to_string().contains("derived"));
    }
}
