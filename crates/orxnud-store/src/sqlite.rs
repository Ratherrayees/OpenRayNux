//! The bundled-SQLite version contract.
//!
//! This module exists to make one number impossible to get wrong by accident.

use std::fmt;

use rusqlite::Connection;

use orxnud_domain::platform::FilesystemIdentity;

use crate::pragma::{Pragma, PragmaError};

/// The minimum acceptable bundled SQLite version.
///
/// SQLite **3.51.3** (2026-03-13) fixed the WAL-reset database corruption bug.
/// From `sqlite.org/wal.html`:
///
/// > "The bug is likely present in all version of SQLite from 3.7.0
/// > (2010-07-21) through 3.51.2 (2026-01-09). It is fixed in version 3.51.3
/// > (2026-03-13) and later. Backports … 3.44.6 and 3.50.7."
///
/// 3.51.0 also hardened *"resistance to database corruption caused by an
/// application breaking Posix advisory locks using close()"* — a second fix in
/// the same area, which is why we track SQLite actively rather than pinning once
/// (Verification Register, V-02).
///
/// The encoded form of "3.51.3" is `3 * 1_000_000 + 51 * 1_000 + 3`.
///
/// `const_assert_min_sqlite` is what turns this into a build failure rather
/// than a runtime surprise.
pub const MIN_SQLITE_VERSION: i32 = 3 * 1_000_000 + 51 * 1_000 + 3;

/// A SQLite library version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SqliteVersion {
    /// Major component.
    pub major: u32,
    /// Minor component.
    pub minor: u32,
    /// Patch component.
    pub patch: u32,
}

impl SqliteVersion {
    /// The version SQLite reports as compiled in.
    #[must_use]
    pub fn compiled() -> Self {
        // `rusqlite::version()` returns a `&str` like "3.51.2"; parse it rather
        // than adding a dependency for three integers.
        parse_version(rusqlite::version()).unwrap_or(SqliteVersion {
            major: 0,
            minor: 0,
            patch: 0,
        })
    }

    /// The version encoded in SQLite's single-integer form.
    #[must_use]
    pub fn encoded(self) -> i32 {
        i32::try_from(self.major).unwrap_or(i32::MAX) * 1_000_000
            + i32::try_from(self.minor).unwrap_or(i32::MAX) * 1_000
            + i32::try_from(self.patch).unwrap_or(i32::MAX)
    }

    /// Whether this version meets [`MIN_SQLITE_VERSION`].
    #[must_use]
    pub fn satisfies_minimum(self) -> bool {
        self.encoded() >= MIN_SQLITE_VERSION
    }
}

impl fmt::Display for SqliteVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Parses a `major.minor.patch` version string.
fn parse_version(s: &str) -> Option<SqliteVersion> {
    let mut it = s.split('.');
    Some(SqliteVersion {
        major: it.next()?.parse().ok()?,
        minor: it.next()?.parse().ok()?,
        patch: it.next()?.parse().ok()?,
    })
}

/// A build-time failure to meet the SQLite version floor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "bundled SQLite {found} is below the required minimum {required}.\n\
     OpenRayNux refuses to run: 3.51.3 fixed the WAL-reset database corruption\n\
     bug, which a durable task queue is structurally likely to trigger.\n\
     Check the `rusqlite` `bundled` feature is enabled and that the pinned\n\
     amalgamation is at least 3.51.3 (ADR-0006, Verification Register V-02)."
)]
pub struct SqliteTooOld {
    /// What is compiled in.
    pub found: SqliteVersion,
    /// What is required.
    pub required: SqliteVersion,
}

impl SqliteTooOld {
    /// Builds the error for a too-old version.
    #[must_use]
    pub fn new(found: SqliteVersion) -> Self {
        Self {
            found,
            required: min_version(),
        }
    }
}

fn min_version() -> SqliteVersion {
    SqliteVersion {
        major: u32::try_from(MIN_SQLITE_VERSION / 1_000_000).unwrap_or(0),
        minor: u32::try_from((MIN_SQLITE_VERSION % 1_000_000) / 1_000).unwrap_or(0),
        patch: u32::try_from(MIN_SQLITE_VERSION % 1_000).unwrap_or(0),
    }
}

/// A store failure.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The compiled SQLite is too old to be safe.
    #[error(transparent)]
    SqliteTooOld(#[from] SqliteTooOld),

    /// Database ownership could not be established (S-31).
    ///
    /// Distinct from [`StoreError::Io`] on purpose: this means another process holds
    /// the database, which is expected under concurrency, whereas `Io` means the file
    /// could not be used at all. They must not be flattened.
    #[error("database ownership: {source}")]
    Ownership {
        /// The underlying refusal.
        source: Box<crate::ownership::OwnershipError>,
    },

    /// A pragma could not be applied or verified.
    #[error(transparent)]
    Pragma(#[from] PragmaError),

    /// A migration failed. Boxed for the same reason as `TaskRepoError::Sqlite`.
    #[error(transparent)]
    Migration(Box<crate::migration::MigrationError>),

    /// An underlying SQLite error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A repository-level failure. Boxed for the same reason as `Migration`.
    #[error(transparent)]
    Repository(Box<crate::repository::RepositoryError>),

    /// Filesystem failure.
    #[error("i/o error at {path}: {source}")]
    Io {
        /// The path involved.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// Verifies the compiled SQLite meets the minimum.
///
/// The compile-time assertion in `const_assert_min_sqlite` already guarantees
/// this cannot fail for a binary built from this tree. It stays because a store
/// may be opened by code linked against a *different* SQLite — and a runtime
/// check costs nothing next to silently running on a corrupting library.
///
/// # Errors
///
/// [`SqliteTooOld`] when the bundled version is below 3.51.3.
pub fn verify_sqlite_version() -> Result<SqliteVersion, SqliteTooOld> {
    let found = SqliteVersion::compiled();
    if found.satisfies_minimum() {
        Ok(found)
    } else {
        Err(SqliteTooOld::new(found))
    }
}

/// The SQLite version actually linked, as reported by `build.rs`.
///
/// `build.rs` parses `SQLITE_VERSION_NUMBER` out of the very header that
/// `libsqlite3-sys` compiles, so this is the version that will be in the binary.
/// It cannot be forged by editing a constant here.
const LINKED_SQLITE_VERSION: i64 = parse_decimal(env!("ORXNUD_LINKED_SQLITE_VERSION"));

/// Parses an ASCII decimal integer in a `const` context.
///
/// `str::parse` is not const-callable, so `build.rs`'s output has to be converted
/// by hand. Returns 0 for anything unparseable, which makes the assertion below
/// fail rather than silently pass.
const fn parse_decimal(s: &str) -> i64 {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    let mut acc: i64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < b'0' || b > b'9' {
            return 0;
        }
        acc = acc * 10 + (b - b'0') as i64;
        i += 1;
    }
    acc
}

/// Compile-time assertion that the linked SQLite is new enough.
///
/// Evaluated in a `const` context, so violating it is a **build error**, not a
/// runtime one. This is the checkable form of Verification Register V-02: there
/// is no way to produce a release binary that links a known-corrupting SQLite.
///
/// It asserts against [`LINKED_SQLITE_VERSION`] rather than a constant written by
/// hand, because a self-comparison proves nothing — it would still pass if the
/// amalgamation were downgraded underneath it.
// Clippy reads `LINKED_SQLITE_VERSION >= 3_051_003` as a constant comparison
// because in this crate the left side *is* a constant. That is the entire point:
// the assertion must be evaluated by the compiler, not at run time, so that
// downgrading the amalgamation is a build failure.
#[allow(clippy::assertions_on_constants)]
const fn const_assert_min_sqlite() {
    assert!(
        LINKED_SQLITE_VERSION >= 3_051_003,
        "OpenRayNux requires SQLite >= 3.51.3 for the WAL-reset corruption fix"
    );
}

const _: () = const_assert_min_sqlite();

/// An open store: a connection plus the pragma set it was opened with.
///
/// Deliberately not a pool. SQLite has exactly one writer (docs-06 / ADR-0006),
/// so a pool would add contention without adding throughput; the Phase 2 engine
/// introduces a single-writer thread with a bounded read pool.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
    version: SqliteVersion,
    /// Shared ownership of this database's lock file, held for as long as `conn` is
    /// usable (S-31).
    ///
    /// It is a field rather than something `open` acquires and drops: the lease must
    /// follow the **connection lifetime**, and a lease released when `open` returned
    /// would protect nothing. Dropping the `Store` drops both, in that order, so the
    /// connection is closed before the lock is released — the order matters, because a
    /// released lock with a live connection is exactly the window S-31 exists to close.
    _ownership: crate::ownership::SharedOwnership,
}

/// Maps an ownership refusal into the store's error vocabulary.
///
/// It gets its own variant rather than becoming `StoreError::Io`, because "another
/// process owns this database" and "the file could not be read" call for different
/// responses, and a caller that cannot tell them apart will eventually retry the
/// second as if it were the first.
pub(crate) fn ownership_error(e: crate::ownership::OwnershipError) -> StoreError {
    StoreError::Ownership {
        source: Box::new(e),
    }
}

impl From<crate::alias::OpenFailure> for StoreError {
    /// An alias refusal is an **ownership** refusal.
    ///
    /// Ownership of a database is keyed by path, so a database that is reachable
    /// through a second name is one whose ownership cannot be expressed: another
    /// process may already be using it under a name this process never sees.
    /// Reporting it through the ownership channel means every caller that
    /// already handles "this database is not safely openable" handles this too.
    fn from(e: crate::alias::OpenFailure) -> Self {
        match e {
            crate::alias::OpenFailure::Ownership(source) => StoreError::Ownership {
                source: Box::new(source),
            },
            crate::alias::OpenFailure::Alias { path, reason } => StoreError::Ownership {
                source: Box::new(crate::ownership::OwnershipError::AliasUnsafe { path, reason }),
            },
            crate::alias::OpenFailure::Sqlite { source, .. } => StoreError::Sqlite(source),
        }
    }
}

impl From<crate::migration::MigrationError> for StoreError {
    fn from(e: crate::migration::MigrationError) -> Self {
        Self::Migration(Box::new(e))
    }
}

impl From<crate::repository::RepositoryError> for StoreError {
    fn from(e: crate::repository::RepositoryError) -> Self {
        Self::Repository(Box::new(e))
    }
}

impl Store {
    /// Opens a store at `path`, applying and then **verifying** its pragmas.
    ///
    /// # The filesystem-identity capability is required
    ///
    /// `identity` is not optional and has no default. ADR-0058 Decision 2 requires
    /// that every open of a database presents the capability that can say how many
    /// names reach it, and that a platform which cannot answer is a **refusal**
    /// rather than a pass. A convenience constructor that supplied a permissive
    /// answer would be the bypass reached through a different door, so there is
    /// none: the production implementation comes from `orxnud-platform-fs`, and
    /// the tests supply one that answers for themselves.
    ///
    /// # Errors
    ///
    /// Fails if the SQLite version is too old, if a pragma cannot be applied or
    /// read back, if the file cannot be opened, or if the database cannot be shown
    /// to be alias-safe.
    pub fn open(
        path: &std::path::Path,
        critical: bool,
        identity: &dyn FilesystemIdentity,
    ) -> Result<Self, StoreError> {
        let version = verify_sqlite_version().map_err(StoreError::SqliteTooOld)?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| StoreError::Io {
                path: parent.display().to_string(),
                source,
            })?;
        }
        // Ownership and the open are one operation. A connection opened without
        // a lease is one that participates in nothing and can be modified behind
        // a restore's back, so the lease and the guarded open cannot be two
        // steps a caller has to remember.
        //
        // The open is guarded: the database's link count and identity are checked
        // before SQLite is asked to open anything, and again afterwards. A
        // database reachable through a second name is refused here rather than
        // opened and left to participate in nothing.
        let (conn, ownership, sidecars) = crate::alias::open_shared(path, identity)?;
        let pragma = if critical {
            Pragma::critical()
        } else {
            Pragma::derived()
        };
        // On any failure after this point the connection is dropped here and the
        // lease with it. No path returns a connection without its lease.
        pragma.apply(&conn)?;
        pragma.verify(&conn)?;
        // The sidecars are verified **after** WAL mode has been applied, because
        // that is when SQLite materialises them. Verifying only before the open
        // would look at a directory that did not have them yet.
        sidecars.verify_after_open(identity).map_err(|f| {
            ownership_error(crate::ownership::OwnershipError::AliasUnsafe {
                path: f.path,
                reason: f.reason,
            })
        })?;
        Ok(Self {
            conn,
            version,
            _ownership: ownership,
        })
    }

    /// Opens an in-memory store. **Tests only.**
    ///
    /// An in-memory database has no write-ahead log and no crash recovery, so it
    /// cannot exercise the durability properties (TP-1, TP-4, TP-7). Use
    /// [`Self::open`] on a real file for anything about durability.
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let version = verify_sqlite_version().map_err(StoreError::SqliteTooOld)?;
        let conn = Connection::open_in_memory()?;
        let pragma = Pragma::in_memory();
        pragma.apply(&conn)?;
        pragma.verify(&conn)?;
        Ok(Self {
            conn,
            version,
            // An in-memory database has no file, so there is nothing for a second
            // process to open and nothing to coordinate. The lease is a no-op rather
            // than absent, so the type of `Store` does not change between the two.
            _ownership: crate::ownership::SharedOwnership::in_memory(),
        })
    }

    /// The database path this store holds shared ownership of.
    #[must_use]
    pub fn ownership_path(&self) -> &std::path::Path {
        self._ownership.path()
    }

    /// The SQLite version this store is running on.
    #[must_use]
    pub fn sqlite_version(&self) -> SqliteVersion {
        self.version
    }

    /// Borrows the connection.
    #[must_use]
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Mutably borrows the connection.
    #[must_use]
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Consumes the store, returning the connection.
    #[must_use]
    pub fn into_connection(self) -> Connection {
        self.conn
    }

    /// The ownership lease, taken back from the store.
    ///
    /// Added by S-31 so a caller can hand a bare connection to another component
    /// while **keeping** the database's shared lease alive. `into_connection` drops the
    /// `Store` and with it the lease, which would silently unprotect a connection that
    /// is still in use -- the exact "lease does not follow the connection lifetime"
    /// failure S-31 exists to prevent. The `Store` cannot implement `Drop` to retain it,
    /// so ownership is returned explicitly and the caller is required to carry it.
    #[must_use]
    pub fn into_parts(self) -> (Connection, crate::ownership::SharedOwnership) {
        (self.conn, self._ownership)
    }
}

/// Opens a store. A convenience alias for [`Store::open`].
///
/// # Errors
///
/// As [`Store::open`].
pub fn open(
    path: &std::path::Path,
    critical: bool,
    identity: &dyn FilesystemIdentity,
) -> Result<Store, StoreError> {
    Store::open(path, critical, identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_const_decimal_parser_handles_what_build_rs_emits() {
        assert_eq!(parse_decimal("3053002"), 3_053_002);
        assert_eq!(parse_decimal("0"), 0);
        // Anything unparseable becomes 0, which must trip the minimum assertion
        // rather than be read as "version 0 passes".
        for bad in ["", "abc", "3.53.2", "3053002 ", "-1", "3_0"] {
            assert_eq!(parse_decimal(bad), 0, "{bad:?} should not parse");
        }
    }

    #[test]
    fn the_compile_time_and_runtime_versions_agree() {
        // If these drift, the build-time assertion is asserting about a different
        // SQLite than the one that actually runs.
        assert_eq!(
            LINKED_SQLITE_VERSION,
            i64::from(SqliteVersion::compiled().encoded()),
            "build.rs and rusqlite disagree about the linked SQLite version"
        );
    }

    #[test]
    // Constant by construction; the runtime half is what this test is really for.
    #[allow(clippy::assertions_on_constants)]
    fn the_linked_sqlite_satisfies_the_minimum() {
        assert!(SqliteVersion::compiled().satisfies_minimum());
        assert!(LINKED_SQLITE_VERSION >= 3_051_003);
    }
    use rusqlite::Connection;

    #[test]
    fn the_bundled_sqlite_meets_the_minimum() {
        // The assertion the whole crate exists to make. If this fails, the
        // `bundled` feature is off or the amalgamation is too old.
        let v = verify_sqlite_version().expect("bundled SQLite must be >= 3.51.3");
        assert!(
            v.satisfies_minimum(),
            "compiled SQLite {v} is below the floor"
        );
        assert!(
            v.encoded() >= 3_051_003,
            "compiled SQLite {v} is below 3.51.3"
        );
    }

    #[test]
    fn the_development_machine_would_have_been_rejected() {
        // Documents *why* we bundle. Fedora 44 ships 3.51.2, which this check
        // rejects. If a future Fedora moves past the floor, this test's comment
        // is what needs revisiting -- not the assertion above.
        let fedora = SqliteVersion {
            major: 3,
            minor: 51,
            patch: 2,
        };
        assert!(!fedora.satisfies_minimum(), "3.51.2 must be rejected");
        assert_eq!(fedora.encoded(), 3_051_002);
        let err = SqliteTooOld::new(fedora);
        assert!(err.to_string().contains("3.51.3"));
    }

    #[test]
    fn version_encoding_and_comparison_agree() {
        let v = SqliteVersion {
            major: 3,
            minor: 51,
            patch: 3,
        };
        assert_eq!(v.encoded(), MIN_SQLITE_VERSION);
        assert!(v.satisfies_minimum());
        assert!(
            !SqliteVersion {
                major: 3,
                minor: 51,
                patch: 2
            }
            .satisfies_minimum()
        );
        assert!(
            SqliteVersion {
                major: 3,
                minor: 52,
                patch: 0
            }
            .satisfies_minimum()
        );
        assert!(
            !SqliteVersion {
                major: 2,
                minor: 99,
                patch: 99
            }
            .satisfies_minimum()
        );
    }

    #[test]
    fn version_strings_parse() {
        assert_eq!(
            parse_version("3.51.3"),
            Some(SqliteVersion {
                major: 3,
                minor: 51,
                patch: 3
            })
        );
        assert_eq!(
            parse_version("3.51.2"),
            Some(SqliteVersion {
                major: 3,
                minor: 51,
                patch: 2
            })
        );
        assert_eq!(parse_version("garbage"), None);
        assert_eq!(parse_version("3.51"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn compiled_version_parses() {
        // If this is zero, the parse failed and the minimum check would be
        // silently vacuous -- so assert the parse actually produced something.
        let v = SqliteVersion::compiled();
        assert!(v.major > 0, "compiled version did not parse: {v}");
    }

    #[test]
    fn min_version_decodes_correctly() {
        assert_eq!(
            min_version(),
            SqliteVersion {
                major: 3,
                minor: 51,
                patch: 3
            }
        );
    }

    #[test]
    fn store_opens_and_reports_its_version() {
        let store = Store::open_in_memory().expect("open in-memory");
        assert!(store.sqlite_version().satisfies_minimum());
    }

    #[test]
    fn store_opens_on_a_real_file_and_verifies_its_pragmas() {
        let dir = std::env::temp_dir().join(format!("orxnud-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("s.db");
        let _ = std::fs::remove_file(&path);
        let store = Store::open(&path, true, &orxnud_platform_fs::OsIdentity).expect("open");
        assert!(store.sqlite_version().satisfies_minimum());
        drop(store);
        // The file exists and WAL is on it.
        assert!(path.exists());
        let conn = Connection::open(&path).expect("reopen");
        let mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .expect("read");
        assert_eq!(mode.to_lowercase(), "wal", "journal_mode is persistent");
        let _ = std::fs::remove_file(&path);
    }
}
