//! Alias safety for database opens (ADR-0058, F-26c).
//!
//! # The bypass this closes
//!
//! Ownership of a database is keyed by **path**: `state.db` owns `state.db.lock`,
//! and a process that opens the same file through a second name owns
//! `alias.db.lock` instead. Two locks, one database, and the second process
//! participates in nothing — so it may write while a restore is installing a
//! staged image. Measured during S-31's review:
//!
//! ```text
//! state.db and alias.db are one inode (20445) but resolve to
//!     state.db.lock   and   alias.db.lock
//! -> two locks, so a competitor opening the alias participates in nothing
//! ```
//!
//! The fix is not to give one inode one name — `link(2)` permits a hard link in
//! a different directory on the same filesystem, so an inode-keyed name would
//! still need a parent directory and the two parents can differ. The fix is to
//! **refuse** a database that is reachable through more than one name.
//!
//! # What this module establishes, and what it does not
//!
//! The check is two-sided (ADR-0058 Decision 3): the file is observed before
//! SQLite is asked to open it and again afterwards, and the two observations
//! must agree. On Windows there is a third observation: immediately after the
//! open, the file behind SQLite's **actual** main-database handle is inspected
//! and must match both path observations.
//!
//! **What is established.** A database reachable through more than one name is
//! refused, at the open, with a typed error naming the count. A file that is
//! replaced between the two observations is refused. A platform that cannot
//! answer the question is refused rather than assumed safe. On Windows the file
//! SQLite actually opened is the file that was checked, so a path swapped
//! between the pre-check and `sqlite3_open_v2` is refused rather than missed.
//!
//! **What is not established.** On Unix the connection's own descriptor is not
//! observable through SQLite's public API; `SQLITE_FCNTL_WIN32_GET_HANDLE` is a
//! Windows VFS opcode. The two observations there are observations of a
//! **path**, so a path changed and changed back inside the window is not
//! detected. ADR-0058 Decision 2 approved exactly that limitation rather than
//! claiming it away, and the guarantees here are stated against the bypass, not
//! against a detector. On every platform the sidecars remain path observations:
//! the main handle says nothing about which `-wal` or `-shm` SQLite opened.
//!
//! The residual Unix window is named rather than assumed away, and the *bypass*
//! — a second name reaching a database that is being restored — is what this
//! work removes.

use std::path::{Path, PathBuf};

use orxnud_domain::platform::{
    FileFacts, FileId, FilesystemIdentity, SqliteMainDatabase, SqliteMainFacts,
};

use crate::ownership::{ExclusiveOwnership, OwnershipError, SharedOwnership};

/// Why a database could not be shown to be alias-safe.
///
/// Every variant is a **refusal**. None of them is ever converted into a
/// successful open: ADR-0058 Decision 2 requires that "the platform cannot
/// say" and "the platform checked and it is fine" produce opposite outcomes,
/// and a permissive default that read them alike would be the bypass reached
/// through a different door.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasRefusal {
    /// The platform could not establish the file's link count or its identity.
    ///
    /// The platform is named so the refusal can say *why* it cannot answer,
    /// because "we could not tell" and "we checked" demand different responses
    /// from an operator.
    Unknown {
        /// The platform that could not answer.
        platform: &'static str,
    },
    /// The file is reachable through more than one name.
    ///
    /// A link count is a property of the **inode**, not of the name, so this
    /// refusal applies to *every* name for the file — including the legitimate
    /// one. Introducing a single alias makes the database unopenable through all
    /// of its names. That is safe, and it is an availability consequence an
    /// operator has to be told about rather than discover.
    MultipleNames {
        /// How many names reach the file.
        name_count: u64,
    },
    /// The platform reported a link count but no stable identity.
    ///
    /// The count is usable and the continuity check is not, so the open is
    /// refused rather than performed without the second half of the check.
    IdentityUnavailable,
    /// The file's identity changed between the two observations.
    ///
    /// The file at the path is not the file that was checked.
    IdentityChanged,
    /// The file was present before the open and is absent after it.
    Disappeared,
    /// The file was absent before the open and is still absent after it.
    ///
    /// The open was supposed to create it. A path that does not resolve to a
    /// file is not a database, whatever SQLite reported about the open.
    NotCreated,
    /// The platform could not establish the identity of the file SQLite opened.
    ///
    /// Distinct from [`AliasRefusal::Unknown`], which is about the path: this
    /// one means the path observations succeeded but the handle behind the live
    /// connection could not be inspected. On Windows that is a refusal, never a
    /// fallback to the path check.
    MainDatabaseUnknown {
        /// The platform that could not answer.
        platform: &'static str,
    },
    /// The file SQLite opened is not the file the path observations checked.
    ///
    /// The path resolved to one file before and after the open, but the live
    /// connection holds a different file. This is the window the handle check
    /// exists to close.
    MainDatabaseIdentityChanged,
    /// The file SQLite opened is reachable through more than one name.
    ///
    /// The path observations said one name; the handle says otherwise. The
    /// handle is the authority, because it is the file that will be written.
    MainDatabaseMultipleNames {
        /// How many names reach the opened file.
        name_count: u64,
    },
}

impl std::fmt::Display for AliasRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown { platform } => write!(
                f,
                "the {platform} platform cannot report this database's link count or \
                 identity, so its alias-safety cannot be established; refusing rather \
                 than assuming it is safe"
            ),
            Self::MultipleNames { name_count } => write!(
                f,
                "the file is reachable through {name_count} names, so a path-keyed \
                 ownership rule can be bypassed through the others; refusing every \
                 name for it"
            ),
            Self::IdentityUnavailable => write!(
                f,
                "the platform reported a link count but no stable identity, so the \
                 file's continuity across the open cannot be checked; refusing"
            ),
            Self::IdentityChanged => write!(
                f,
                "the file's identity changed between the check before the open and \
                 the check after it; refusing"
            ),
            Self::Disappeared => write!(
                f,
                "the database was present before the open and is gone after it; refusing"
            ),
            Self::NotCreated => write!(
                f,
                "the database was absent before the open and is still absent after it; \
                 refusing"
            ),
            Self::MainDatabaseUnknown { platform } => write!(
                f,
                "the {platform} platform could not establish the identity of the file \
                 SQLite actually opened, so the connection cannot be shown to refer to \
                 the checked database; refusing"
            ),
            Self::MainDatabaseIdentityChanged => write!(
                f,
                "the file SQLite actually opened is not the file the path checks \
                 observed; refusing"
            ),
            Self::MainDatabaseMultipleNames { name_count } => write!(
                f,
                "the file SQLite actually opened is reachable through {name_count} \
                 names, so a path-keyed ownership rule can be bypassed through the \
                 others; refusing every name for it"
            ),
        }
    }
}

/// Why a database open did not produce a usable connection.
///
/// Three causes, kept apart because they demand opposite responses: the ownership
/// lease could not be taken, the file was refused on its own terms (alias
/// safety), or SQLite refused to open it.
#[derive(Debug)]
pub enum OpenFailure {
    /// The ownership lease could not be established.
    ///
    /// Another process holds the database, or the locking mechanism is
    /// unavailable. Never converted into a successful open.
    Ownership(OwnershipError),
    /// The database could not be shown to be alias-safe.
    Alias {
        /// The database path.
        path: std::path::PathBuf,
        /// Why it could not be shown to be safe.
        reason: AliasRefusal,
    },
    /// SQLite refused the open.
    Sqlite {
        /// The database path.
        path: std::path::PathBuf,
        /// The underlying error.
        source: rusqlite::Error,
    },
}

impl std::fmt::Display for OpenFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ownership(e) => write!(f, "{e}"),
            Self::Alias { path, reason } => {
                write!(f, "refusing to open {}: {reason}", path.display())
            }
            Self::Sqlite { path, source } => {
                write!(f, "cannot open {}: sqlite error: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for OpenFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ownership(e) => Some(e),
            Self::Alias { .. } => None,
            Self::Sqlite { source, .. } => Some(source),
        }
    }
}

/// The SQLite sidecars that sit beside a database file.
///
/// `-wal` is the write-ahead log and `-shm` is the shared-memory index that
/// tracks it. SQLite derives both names by **string concatenation** from the
/// database's name (`zWal = sqlite3_mprintf("%s-wal", zMove)`), so they live in
/// the database's own directory and are reachable by a second name exactly as
/// the database is.
///
/// `-journal` is the rollback journal. A file-backed database in this crate is
/// always in WAL mode — `Pragma::apply` **fails the open** if WAL cannot be
/// set — so the live database never has one. It is listed anyway: a database
/// that somehow carries one must not be aliased either, and the check costs
/// nothing when the file is absent.
const SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// A sidecar that could not be shown to be safe: which file, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SidecarFailure {
    /// The offending sidecar path.
    pub(crate) path: PathBuf,
    /// Why it could not be shown to be safe.
    pub(crate) reason: AliasRefusal,
}

/// The sidecars of a database, observed before an open and verified after it.
///
/// # Why the sidecars need their own check
///
/// The main database's link-count check does not cover them, and cannot: a hard
/// link to the live `-shm` gives a **second database** a valid wal-index. The
/// two databases then share one index over one log, and the demonstrated
/// consequence is that the protected database's contents disappear — while
/// `PRAGMA integrity_check` still answers `ok`:
///
/// ```text
/// hard link  state.db-shm -> evil.db-shm
/// open evil.db; write to it
/// -> state.db's rows are gone, and integrity_check says ok
/// ```
///
/// The same is true of the write-ahead log, and of the rollback journal in a
/// database that has one.
///
/// # What the check is, and is not
///
/// It is a **path** check, in the same sense as the main database's: the
/// sidecar is observed by name, and nothing here proves which descriptor SQLite
/// used. It rejects a hard link that exists **before** the second database is
/// opened, which is the demonstrated attack. A link created *inside* the
/// window between the observation and SQLite's use of the sidecar is not
/// detected, and that window is the same one ADR-0058 Decision 2 approved as
/// named-but-not-closed.
#[derive(Debug, Clone)]
pub(crate) struct SidecarGuard {
    paths: Vec<PathBuf>,
}

impl SidecarGuard {
    /// Observe the sidecars of `db_path` before the database is opened.
    ///
    /// # Errors
    ///
    /// A [`SidecarFailure`] when a sidecar that exists is reachable through more
    /// than one name, or when the platform cannot establish its link count or
    /// identity. **A sidecar that does not exist is not a failure**: SQLite
    /// creates and removes them around a connection's life, and refusing every
    /// first open because `-wal` is not there yet would refuse every database.
    pub(crate) fn observe_before_open(
        db_path: &Path,
        identity: &dyn FilesystemIdentity,
    ) -> Result<Self, SidecarFailure> {
        let mut observed = Vec::new();
        for suffix in SIDECARS {
            let path = sidecar_path(db_path, suffix);
            match identity.observe(&path) {
                // Not there: the normal state of a database that has not been
                // opened yet, or of one whose last connection has closed.
                FileFacts::Absent => observed.push(path),
                FileFacts::Known { name_count, .. } => {
                    if name_count != 1 {
                        return Err(SidecarFailure {
                            path,
                            reason: AliasRefusal::MultipleNames { name_count },
                        });
                    }
                    observed.push(path);
                }
                // The platform could not answer. That is not "one name"; it is
                // "we do not know", and it refuses.
                FileFacts::Unknown { platform } => {
                    return Err(SidecarFailure {
                        path,
                        reason: AliasRefusal::Unknown { platform },
                    });
                }
            }
        }
        Ok(Self { paths: observed })
    }

    /// Verify the sidecars after the database has been opened, and — for an
    /// ordinary open — after SQLite has been told to use WAL mode and has
    /// materialised the sidecars this connection needs.
    ///
    /// # What is checked, and what is deliberately not
    ///
    /// The **link count**. That is the property that matters: a sidecar with
    /// more than one name is a sidecar another database can adopt, and that is
    /// the demonstrated attack.
    ///
    /// The sidecar's *identity* is **not** compared across the two observations,
    /// and the reason is not a preference. **SQLite manages the sidecars'
    /// lifetimes**, not this crate: a hot write-ahead log recovered at open time
    /// is checkpointed, and the log is then deleted and recreated, so the file at
    /// `state.db-wal` after an open is routinely a *different* file from the one
    /// there before. Comparing the two would refuse every crash recovery — the
    /// daemon's own `a_crash_after_expiry_and_before_reapproval_still_recovers`
    /// is exactly that case. A recreation and an attack are not distinguishable
    /// by identity alone, so identity is not used as a signal here; the link
    /// count is, and it is the one that catches the attack.
    ///
    /// The **main database's** identity continuity is unaffected: that file is
    /// not recreated by SQLite, and the check above still applies to it.
    ///
    /// # Errors
    ///
    /// A [`SidecarFailure`] when a sidecar that now exists is reachable through
    /// more than one name, or when the platform cannot establish its link count.
    pub(crate) fn verify_after_open(
        &self,
        identity: &dyn FilesystemIdentity,
    ) -> Result<(), SidecarFailure> {
        for path in &self.paths {
            match identity.observe(path) {
                // Gone. SQLite removes a sidecar when the last connection
                // closes, so its absence afterwards is not an anomaly.
                FileFacts::Absent => continue,
                FileFacts::Known { name_count, .. } => {
                    if name_count != 1 {
                        return Err(SidecarFailure {
                            path: path.clone(),
                            reason: AliasRefusal::MultipleNames { name_count },
                        });
                    }
                }
                FileFacts::Unknown { platform } => {
                    return Err(SidecarFailure {
                        path: path.clone(),
                        reason: AliasRefusal::Unknown { platform },
                    });
                }
            }
        }
        Ok(())
    }
}

/// The path of the sidecar `db_path` derives for `suffix`.
fn sidecar_path(db_path: &Path, suffix: &str) -> PathBuf {
    let mut name = db_path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    db_path.with_file_name(name)
}

/// What the check established **before** the open.
///
/// Carried into the post-open observation so the two can be compared. The
/// comparison is the point of the two-sided check: a single observation says
/// what the file was, and two observations say whether it still is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreObservation {
    /// The path did not exist when the open began.
    ///
    /// Nothing could be checked, because there was nothing to check. The
    /// post-open observation is then the first one with anything to say, and it
    /// must find a file with exactly one name.
    Absent,
    /// The path existed, reachable by exactly one name, with this identity.
    Present(FileId),
}

/// Observes `path` before the open.
///
/// # Errors
///
/// [`AliasRefusal`] when the file is reachable through more than one name, when
/// the platform cannot answer, or when it answers the link count but not the
/// identity.
pub(crate) fn observe_before_open(
    path: &Path,
    identity: &dyn FilesystemIdentity,
) -> Result<PreObservation, AliasRefusal> {
    match identity.observe(path) {
        FileFacts::Absent => Ok(PreObservation::Absent),
        FileFacts::Known {
            name_count,
            identity: file_id,
        } => {
            if name_count != 1 {
                return Err(AliasRefusal::MultipleNames { name_count });
            }
            let Some(file_id) = file_id else {
                return Err(AliasRefusal::IdentityUnavailable);
            };
            Ok(PreObservation::Present(file_id))
        }
        FileFacts::Unknown { platform } => Err(AliasRefusal::Unknown { platform }),
    }
}

/// Observes `path` after the open, compares it with `pre`, and returns the
/// identity of the file the path now names.
///
/// The returned identity is what the main-database handle must also have. On a
/// freshly created database there is no pre-open identity, so the post-open
/// observation is the only path evidence and its identity becomes the expected
/// one.
///
/// # Errors
///
/// [`AliasRefusal`] when the file now has more than one name, when the platform
/// cannot answer, when the identity differs from the one recorded before the
/// open, or when the file is not there at all.
pub(crate) fn observe_after_open(
    path: &Path,
    identity: &dyn FilesystemIdentity,
    pre: PreObservation,
) -> Result<FileId, AliasRefusal> {
    match (pre, identity.observe(path)) {
        (PreObservation::Present(_), FileFacts::Absent) => Err(AliasRefusal::Disappeared),
        (
            PreObservation::Absent,
            FileFacts::Known {
                name_count,
                identity: file_id,
            },
        ) => {
            if name_count != 1 {
                return Err(AliasRefusal::MultipleNames { name_count });
            }
            let Some(file_id) = file_id else {
                return Err(AliasRefusal::IdentityUnavailable);
            };
            Ok(file_id)
        }
        (PreObservation::Absent, FileFacts::Absent) => Err(AliasRefusal::NotCreated),
        (
            PreObservation::Present(before),
            FileFacts::Known {
                name_count,
                identity,
            },
        ) => {
            if name_count != 1 {
                return Err(AliasRefusal::MultipleNames { name_count });
            }
            let Some(after) = identity else {
                return Err(AliasRefusal::IdentityUnavailable);
            };
            if after != before {
                return Err(AliasRefusal::IdentityChanged);
            }
            Ok(after)
        }
        (PreObservation::Absent, FileFacts::Unknown { platform })
        | (PreObservation::Present(_), FileFacts::Unknown { platform }) => {
            Err(AliasRefusal::Unknown { platform })
        }
    }
}

/// Opens `db_path` under the alias-safety contract, holding a **shared** lease.
///
/// This is the only way an **ordinary** production live-database connection is
/// opened in this crate. Every route that opens one — `Store::open`, the audit
/// journal, the approval ledger, the restore guard — comes through here, so a
/// route that forgot to check would be a route with no alias protection at all.
///
/// The recovery path opens the live database three times of its own
/// (`install_staged`, `finalize_log`, `live_digest`). Those opens are made by
/// the **restorer**, under the **exclusive** lease, and they are the only
/// live-database opens this crate makes without the check. The reasoning is
/// recorded in the Verification Register (F-26c): the install is in place, so
/// it preserves the inode and cannot split two names apart, and the restore's
/// logical verification is the control that catches a concurrent writer.
///
/// The lease is taken **here** rather than by the caller, and that is the point:
/// "own the database, then open it" and "check it is safe to own, then open it"
/// are two properties that must hold for *every* open, and a caller that had to
/// remember both would eventually forget one. Gate **G17** encodes the same
/// requirement lexically: a file-backed open is only legitimate immediately
/// after an ownership acquisition.
///
/// # The order, and why it is that order
///
/// 1. Take the shared lease. It also completes any outstanding restore, under
///    the lease, so no half-restored database is ever handed out.
/// 2. Observe the path. A file with more than one name is refused **before**
///    SQLite is asked to open anything, so the file is never opened at all.
/// 3. Open the database.
/// 4. Immediately observe the file behind the connection's **actual**
///    main-database handle, before any `PRAGMA` or WAL work. On Windows this is
///    the file SQLite will write; a handle that cannot be inspected is refused.
/// 5. Observe the path again. A file replaced underneath the open, or given a
///    second name while it was being opened, is refused here.
/// 6. Compare the handle's identity with both path observations. The connection
///    is dropped on every refusal, so a refused open leaves no handle behind.
///
/// The path observations are separated by the open and by nothing else, because
/// the lease is already held: a cooperating process cannot publish a restore
/// intent or install an image between them.
///
/// # What the check does not establish
///
/// On Unix the observations are of a **path**. SQLite opens by filename, and no
/// public API exposes the connection's descriptor, so this cannot show that the
/// connection refers to the inode the checks saw. A path changed and changed
/// back inside the window is not detected, and ADR-0058 Decision 2 approved that
/// limitation rather than claiming it away. On every platform the sidecars are
/// path observations; the main handle says nothing about which `-wal` or `-shm`
/// SQLite opened.
///
/// # Errors
///
/// [`OpenFailure::Ownership`] when the lease cannot be taken,
/// [`OpenFailure::Alias`] when the database cannot be shown to be alias-safe,
/// and [`OpenFailure::Sqlite`] when SQLite refuses the open. All three are
/// refusals; none yields a connection.
pub(crate) fn open_shared(
    db_path: &Path,
    identity: &dyn FilesystemIdentity,
) -> Result<(rusqlite::Connection, SharedOwnership, SidecarGuard), OpenFailure> {
    // The sidecars are observed **before** the lease is taken, and therefore
    // before any roll-forward install the lease acquisition may perform. An
    // aliased sidecar must be refused before *any* destructive work, not only
    // before the open.
    let sidecars =
        SidecarGuard::observe_before_open(db_path, identity).map_err(|f| OpenFailure::Alias {
            path: f.path,
            reason: f.reason,
        })?;
    let ownership = crate::ownership::acquire_shared(db_path).map_err(OpenFailure::Ownership)?;
    let pre = pre_check(db_path, identity)?;
    let conn = rusqlite::Connection::open(db_path).map_err(|source| OpenFailure::Sqlite {
        path: db_path.to_path_buf(),
        source,
    })?;
    // The handle is observed before the post-open path check and before any
    // `PRAGMA`: it is the file this connection will use, and it must be the
    // file the path checks describe.
    let main = identity.observe_sqlite_main(SqliteMainDatabase::new(&conn));
    let post = post_check(db_path, identity, pre)?;
    main_check(db_path, main, pre, post)?;
    Ok((conn, ownership, sidecars))
}

/// Opens `db_path` under the alias-safety contract, holding an **exclusive**
/// lease.
///
/// The restore path. Exclusive ownership excludes every other process for the
/// whole restore lifecycle, and the alias check runs inside it, so a database
/// that is reachable through a second name is refused before the checkpoint and
/// before anything is staged. The main-database handle is inspected here too:
/// exclusive ownership says who may open the database, not which file SQLite
/// opened.
///
/// `held` carries a lease the caller already took. It is how the S-31
/// interleaving test stands inside the restore window without a production
/// seam; the lease is exclusive either way, and this function opens nothing
/// without one.
pub(crate) fn open_exclusive(
    db_path: &Path,
    held: Option<ExclusiveOwnership>,
    identity: &dyn FilesystemIdentity,
) -> Result<(rusqlite::Connection, ExclusiveOwnership, SidecarGuard), OpenFailure> {
    // As in `open_shared`: the sidecars are observed before the lease, so an
    // aliased one is refused before the restore's checkpoint or its install.
    let sidecars =
        SidecarGuard::observe_before_open(db_path, identity).map_err(|f| OpenFailure::Alias {
            path: f.path,
            reason: f.reason,
        })?;
    let ownership = match held {
        Some(lease) => lease,
        None => crate::ownership::acquire_exclusive(db_path).map_err(OpenFailure::Ownership)?,
    };
    let pre = pre_check(db_path, identity)?;
    let conn = rusqlite::Connection::open(db_path).map_err(|source| OpenFailure::Sqlite {
        path: db_path.to_path_buf(),
        source,
    })?;
    let main = identity.observe_sqlite_main(SqliteMainDatabase::new(&conn));
    let post = post_check(db_path, identity, pre)?;
    main_check(db_path, main, pre, post)?;
    Ok((conn, ownership, sidecars))
}

/// The pre-open observation, reported as an open failure.
fn pre_check(
    db_path: &Path,
    identity: &dyn FilesystemIdentity,
) -> Result<PreObservation, OpenFailure> {
    observe_before_open(db_path, identity).map_err(|reason| OpenFailure::Alias {
        path: db_path.to_path_buf(),
        reason,
    })
}

/// The post-open observation and its comparison, reported as an open failure.
///
/// The returned identity is the one the main-database handle must also have.
fn post_check(
    db_path: &Path,
    identity: &dyn FilesystemIdentity,
    pre: PreObservation,
) -> Result<FileId, OpenFailure> {
    observe_after_open(db_path, identity, pre).map_err(|reason| OpenFailure::Alias {
        path: db_path.to_path_buf(),
        reason,
    })
}

/// Compares the file SQLite actually opened with the path observations.
///
/// # What each answer means
///
/// * `NotApplicable` — the platform has no API for the handle, so the path
///   observations remain the only evidence. This is the Unix case, and it is
///   named rather than silently skipped.
/// * `Unknown` — the platform has the API and could not use it. Refuse.
/// * `Known` — the handle is the authority. It must have exactly one name, and
///   its identity must equal the pre-open identity when there was one and the
///   post-open identity always.
///
/// The pre-open comparison is not redundant with the post-open one: the file can
/// be replaced between the path checks, and the handle is the only observation
/// that sees what SQLite opened in that window.
fn verify_sqlite_main(
    main: SqliteMainFacts,
    pre: PreObservation,
    post: FileId,
) -> Result<(), AliasRefusal> {
    match main {
        SqliteMainFacts::NotApplicable => Ok(()),
        SqliteMainFacts::Unknown { platform } => {
            Err(AliasRefusal::MainDatabaseUnknown { platform })
        }
        SqliteMainFacts::Known {
            name_count,
            identity,
        } => {
            if name_count != 1 {
                return Err(AliasRefusal::MainDatabaseMultipleNames { name_count });
            }
            if let PreObservation::Present(before) = pre
                && identity != before
            {
                return Err(AliasRefusal::MainDatabaseIdentityChanged);
            }
            if identity != post {
                return Err(AliasRefusal::MainDatabaseIdentityChanged);
            }
            Ok(())
        }
    }
}

/// The main-handle comparison, reported as an open failure.
fn main_check(
    db_path: &Path,
    main: SqliteMainFacts,
    pre: PreObservation,
    post: FileId,
) -> Result<(), OpenFailure> {
    verify_sqlite_main(main, pre, post).map_err(|reason| OpenFailure::Alias {
        path: db_path.to_path_buf(),
        reason,
    })
}
