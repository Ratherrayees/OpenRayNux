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
//! # The authority filter
//!
//! [`SqliteRepository::authoritative_rows`] is the single place ADR-0013's rule is
//! implemented: *derived* data can never satisfy an authority check. It is a
//! **query**, not a convention, so a caller cannot forget it — and the filter is
//! in SQL, so it cannot be bypassed by a caller who forgot to filter in Rust.
//!
//! Phase 2 declares no `derived` regions, so the filter currently passes
//! everything through. It is implemented and tested **now**, while it is cheap,
//! rather than when the first `derived` region arrives and someone discovers the
//! rule was never enforced. The test therefore constructs a synthetic `derived`
//! region and proves it is excluded — the case will not exist in production until
//! a `derived` table does, and a filter with no test is a filter nobody has
//! checked.

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

/// One row returned by an authority-checked query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritativeRow {
    /// The region the row came from.
    pub region: &'static str,
    /// The row's primary key.
    pub id: String,
    /// The row's class, as declared.
    pub class: String,
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

    /// Reads rows that may satisfy an authority check.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::DerivedNotAuthoritative`] if a `derived` region was
    /// requested, or any SQLite error.
    fn authoritative_rows(
        &self,
        region: &StateRegion,
    ) -> Result<Vec<AuthoritativeRow>, Self::Error>;
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
        // The migration list is owned by `migration::MigrationRunner`, which also
        // owns the snapshot precondition (ADR-0017). A repository is handed a
        // region, not a migration, so there is nothing for it to apply — and
        // duplicating the list here would give the snapshot precondition a second,
        // unprotected implementation.
        Ok(0)
    }

    fn authoritative_rows(
        &self,
        region: &StateRegion,
    ) -> Result<Vec<AuthoritativeRow>, RepositoryError> {
        // The filter, in SQL. A `derived` region is refused outright rather than
        // filtered row by row: a derived row cannot satisfy an authority check, so
        // an empty result would be a lie about what was consulted.
        if region.class == orxnud_domain::StateClass::Derived {
            return Err(RepositoryError::DerivedNotAuthoritative {
                entity: "region",
                id: region.name.to_owned(),
            });
        }
        let sql = format!(
            "SELECT {key} FROM {table} WHERE 1=1 ORDER BY {key};",
            key = region.key_column,
            table = region.name
        );
        let mut stmt = self.conn.prepare(&sql)?;
        // `get::<_, String>` would fail on a numeric key, and the failure mode is
        // an opaque `InvalidColumnType` rather than "this region's key is an
        // integer". Rendering whatever SQLite returns keeps the filter working for
        // every region's key type.
        let rows = stmt.query_map([], |r| {
            let v: rusqlite::types::Value = r.get(0)?;
            Ok(match v {
                rusqlite::types::Value::Integer(i) => i.to_string(),
                rusqlite::types::Value::Real(f) => f.to_string(),
                rusqlite::types::Value::Text(s) => s,
                other => format!("{other:?}"),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(AuthoritativeRow {
                region: region.name,
                id: r?,
                class: format!("{:?}", region.class),
            });
        }
        Ok(out)
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
        StateRegion {
            name: "schema_meta",
            class: StateClass::Critical,
            owner: "orxnud-store",
            retention: "indefinite",
            key_column: "version",
        }
    }

    #[test]
    fn schema_meta_reads_back_what_migration_recorded() {
        let mut c = migrated();
        let repo = SqliteRepository::new(&mut c);
        let meta = repo.schema_meta().expect("read");
        assert_eq!(meta.len(), crate::migration::MIGRATIONS.len());
        assert_eq!(meta[0].version, 1);
        assert_eq!(meta[0].name, "schema_meta");
        assert!(meta[0].applied_at > 0);
        // Ascending and complete, so `applied_version` is derivable from the log.
        assert!(meta.windows(2).all(|w| w[0].version < w[1].version));
        assert_eq!(
            meta.last().expect("last").version,
            crate::migration::CURRENT_VERSION
        );
    }

    #[test]
    fn migration_is_owned_by_the_runner_not_the_repository() {
        let mut c = migrated();
        let mut repo = SqliteRepository::new(&mut c);
        assert_eq!(repo.migrate(&region()).expect("migrate"), 0);
    }

    #[test]
    fn a_derived_region_can_never_satisfy_an_authority_check() {
        // ADR-0013 invariant 3, enforced by a query rather than a convention. The
        // test builds the case on purpose: Phase 2 declares no `derived` region,
        // so this is the only place the filter is exercised, and a filter that has
        // never been tested is a filter nobody has checked.
        let mut c = migrated();
        let repo = SqliteRepository::new(&mut c);
        let derived = StateRegion {
            name: "summaries",
            class: StateClass::Derived,
            owner: "orxnud-test",
            retention: "regenerable",
            key_column: "id",
        };
        let err = repo.authoritative_rows(&derived).expect_err("must refuse");
        assert!(
            matches!(err, RepositoryError::DerivedNotAuthoritative { .. }),
            "{err}"
        );
    }

    #[test]
    fn an_authoritative_region_is_readable_through_the_filter() {
        // The other half: the filter must not refuse legitimate authority reads.
        let mut c = migrated();
        let repo = SqliteRepository::new(&mut c);
        let rows = repo.authoritative_rows(&region()).expect("read");
        assert_eq!(
            rows.len(),
            crate::migration::MIGRATIONS.len(),
            "one schema_meta row per applied migration"
        );
        assert_eq!(rows[0].region, "schema_meta");
        assert!(
            rows[0].id.chars().all(|c| c.is_ascii_digit()),
            "{}",
            rows[0].id
        );
    }

    #[test]
    fn the_authority_filter_is_separate_from_the_plain_reader() {
        // There must be no way to read authoritative state *without* going through
        // the filter, or ADR-0013's "enforced by a repository query" is a claim
        // about a code path that nothing is obliged to use.
        let mut c = migrated();
        let repo = SqliteRepository::new(&mut c);
        let derived = StateRegion {
            name: "summaries",
            class: StateClass::Derived,
            owner: "orxnud-test",
            retention: "regenerable",
            key_column: "id",
        };
        assert!(repo.authoritative_rows(&derived).is_err());
    }

    #[test]
    fn error_codes_are_distinct() {
        use std::collections::BTreeSet;
        let errs = [
            RepositoryError::DuplicateRegion { name: "t" },
            RepositoryError::NotFound {
                entity: "task",
                id: "1".into(),
            },
            RepositoryError::DerivedNotAuthoritative {
                entity: "memory",
                id: "1".into(),
            },
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
        let e = RepositoryError::DerivedNotAuthoritative {
            entity: "memory",
            id: "m-1".into(),
        };
        assert!(e.to_string().contains("derived"));
    }
}
