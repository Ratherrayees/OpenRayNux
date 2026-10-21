//! F-26c: the SQLite sidecars are part of the ownership boundary.
//!
//! # The bypass these tests close
//!
//! The main database's link-count check does not cover the sidecars, and cannot:
//! a hard link to the live `-shm` gives a **second database** a valid wal-index.
//! The two databases then share one index over one log, and the demonstrated
//! consequence is that the protected database's contents disappear — while
//! `PRAGMA integrity_check` still answers `ok`:
//!
//! ```text
//! hard link  state.db-shm -> evil.db-shm
//! open evil.db; write to it
//! -> state.db's rows are gone, and integrity_check says ok
//! ```
//!
//! SQLite does not help here: its own Unix VFS applies the main database's
//! link-count check only to the main database. Every other file — the write-ahead
//! log, the shared-memory index, the rollback journal — is opened with
//! `SQLITE_OPEN_NOLOCK`, and `verifyDbFile` returns immediately for those.
//!
//! # What these tests do and do not establish
//!
//! They establish that a sidecar reachable through more than one name is refused
//! through the **real** store and restore paths, and that a legitimate WAL
//! lifecycle is not.
//!
//! They establish **nothing** about whether a sidecar could be replaced or
//! relinked between the observation and SQLite's use of it. The check is a
//! **path** check, in the same sense as the main database's, and the residual
//! pathname-to-connection race stays open.

use std::path::{Path, PathBuf};

use orxnud_domain::platform::{
    FileFacts, FileId, FilesystemIdentity, SqliteMainDatabase, SqliteMainFacts,
};
use orxnud_platform_fs::OsIdentity;
use orxnud_store::StoreError;
use orxnud_store::alias::AliasRefusal;
use orxnud_store::ownership::OwnershipError;
use orxnud_store::sqlite::Store;

/// A scratch directory, unique per test name.
fn dir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let d = std::env::temp_dir().join(format!("f26c-side-{}-{tag}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

/// The path of the sidecar `db` derives for `suffix`.
fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    db.with_file_name(name)
}

/// The number of names reaching `path`.
#[cfg(unix)]
fn link_count(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .map(|m| m.nlink())
        .unwrap_or(0)
}

/// The rows of the `notes` table, as one string.
fn notes(conn: &rusqlite::Connection) -> String {
    conn.query_row(
        "SELECT COALESCE(group_concat(v), '<none>') FROM notes;",
        [],
        |r| r.get::<_, String>(0),
    )
    .unwrap_or_else(|e| format!("<{e}>"))
}

/// Open `db` through the production path and give it known content.
///
/// The connection stays open, so the WAL sidecars are materialised and alive.
///
/// Unix-only: every caller of this helper is a hard-link case, and a hard link
/// is a Unix-only way to reach one file through two names. The Windows lane
/// compiles this file (`cargo check --workspace --all-targets`) but runs the
/// portable alias suite instead, so the helper is gated rather than silenced.
#[cfg(unix)]
fn open_with_content(db: &Path) -> Store {
    let store = Store::open(db, true, &OsIdentity).expect("open the database");
    store
        .conn()
        .execute_batch("CREATE TABLE notes(v TEXT); INSERT INTO notes VALUES ('kept');")
        .expect("write");
    store
}

/// The alias refusal inside a store error, if that is what the error is.
fn alias_refusal(err: &StoreError) -> Option<&AliasRefusal> {
    match err {
        StoreError::Ownership { source } => match source.as_ref() {
            OwnershipError::AliasUnsafe { reason, .. } => Some(reason),
            _ => None,
        },
        _ => None,
    }
}

/// **Required test A — an aliased `-shm` is refused through the real store path.**
///
/// The protected database is opened through the production path, the live `-shm`
/// is hard-linked to a second database's expected `-shm`, and the second database
/// is then opened through the same production path. The refusal must name the
/// sidecar, the protected rows must survive, and the refused open must leave no
/// ownership state behind.
#[cfg(unix)]
#[test]
fn an_aliased_shm_sidecar_is_refused_by_the_store() {
    let d = dir("shm");
    let db = d.join("state.db");
    let evil = d.join("evil.db");
    let store = open_with_content(&db);

    let shm = sidecar(&db, "-shm");
    assert!(
        shm.exists(),
        "precondition: WAL mode must have produced the -shm"
    );
    assert_eq!(
        link_count(&shm),
        1,
        "precondition: the -shm must start unaliased"
    );

    // The alias: the second database's expected -shm path is the live one.
    std::fs::hard_link(&shm, sidecar(&evil, "-shm")).expect("hard link the -shm");
    assert_eq!(link_count(&shm), 2, "the link must really be a second name");

    // Opening the second database through the real store path must be refused.
    let err = Store::open(&evil, true, &OsIdentity)
        .expect_err("an aliased -shm must be refused, not opened");
    match alias_refusal(&err) {
        Some(AliasRefusal::MultipleNames { name_count }) => {
            assert_eq!(
                *name_count, 2,
                "the refusal must name the count it observed, so an operator can see \
                 that a second name exists"
            );
        }
        other => panic!("expected a multiple-names refusal, got {other:?}"),
    }
    assert!(
        err.to_string().contains("-shm"),
        "the refusal must name the offending sidecar: {err}"
    );

    // The protected database's rows are intact.
    assert_eq!(
        notes(store.conn()),
        "kept",
        "the protected database must not have been affected by the refusal"
    );

    // The protected database's own -shm is aliased too, so *it* is now refused as
    // well: the guard is not a special case for the second database.
    let err = Store::open(&db, true, &OsIdentity)
        .expect_err("the protected database's own aliased -shm must be refused too");
    assert!(
        alias_refusal(&err).is_some(),
        "expected an alias refusal, got {err:?}"
    );
    assert_eq!(
        notes(store.conn()),
        "kept",
        "the protected rows must survive"
    );

    // No ownership state was left behind: once the alias is gone, the same path
    // opens.
    drop(store);
    std::fs::remove_file(sidecar(&evil, "-shm")).expect("remove the alias");
    Store::open(&db, true, &OsIdentity).expect("the open must succeed once the alias is gone");

    let _ = std::fs::remove_dir_all(&d);
}

/// A snapshot of one sidecar file.
///
/// The identity and the link count come from the **production** identity
/// abstraction (`OsIdentity`), so the snapshot is the same view the guard takes
/// and the test cannot drift away from it. The bytes are read directly,
/// because the question this answers is whether the refused open changed the
/// file *at all* — a digest would be a weaker form of the same question.
#[cfg(unix)]
struct SidecarSnapshot {
    /// The file's stable identity, when the platform established one.
    identity: Option<FileId>,
    /// How many names reach the file.
    name_count: u64,
    /// The file's length in bytes.
    len: u64,
    /// The file's bytes.
    bytes: Vec<u8>,
}

/// Snapshot `path` through the production identity abstraction.
///
/// A missing file is a snapshot with no identity, which is how a *replaced* or
/// *unlinked* pathname would show up: the identity would become `None` rather
/// than merely change.
#[cfg(unix)]
fn snapshot(path: &Path) -> SidecarSnapshot {
    match OsIdentity.observe(path) {
        FileFacts::Absent => SidecarSnapshot {
            identity: None,
            name_count: 0,
            len: 0,
            bytes: Vec::new(),
        },
        FileFacts::Known {
            name_count,
            identity,
        } => SidecarSnapshot {
            identity,
            name_count,
            len: std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            bytes: std::fs::read(path).unwrap_or_default(),
        },
        FileFacts::Unknown { platform } => {
            panic!(
                "the platform could not answer for {}: {platform}",
                path.display()
            )
        }
    }
}

/// The result of `PRAGMA integrity_check` on `conn`.
#[cfg(unix)]
fn integrity(conn: &rusqlite::Connection) -> String {
    conn.query_row("PRAGMA integrity_check;", [], |r| r.get::<_, String>(0))
        .unwrap_or_else(|e| format!("<{e}>"))
}

/// **Required test B — an aliased `-wal` is refused through the real store path.**
///
/// The same shape as the `-shm` case, against the write-ahead log. The refusal
/// must not disturb the protected database, and the store's existing WAL
/// initialisation must still work.
///
/// # What the pre/post snapshots add
///
/// The refusal is proved twice over. The *typed error* proves the store refused;
/// the snapshots prove that **the protected write-ahead log was not touched** by
/// the refusal — same identity, same link count, same length, same bytes — and
/// that the **aliased pathname still identifies the same log object**, so the
/// refused open neither unlinked it nor replaced it.
///
/// That last point is the one a reader of the earlier crash/recovery
/// investigation needs: a *raw* SQLite second database opened through the alias
/// makes SQLite replace the log at the aliased name, which breaks the hard link
/// and leaves the protected database's log alone. This test pins the supported
/// path's behaviour, which is stronger: the store refuses **before** SQLite is
/// handed the second database at all, so no replacement and no write happens.
#[cfg(unix)]
#[test]
fn an_aliased_wal_sidecar_is_refused_by_the_store() {
    let d = dir("wal");
    let db = d.join("state.db");
    let evil = d.join("evil.db");
    let store = open_with_content(&db);

    let wal = sidecar(&db, "-wal");
    assert!(
        wal.exists(),
        "precondition: WAL mode must have produced the -wal"
    );
    assert_eq!(
        link_count(&wal),
        1,
        "precondition: the -wal must start unaliased"
    );

    std::fs::hard_link(&wal, sidecar(&evil, "-wal")).expect("hard link the -wal");
    assert_eq!(link_count(&wal), 2, "the link must really be a second name");

    // The state the refused open must leave alone. The protected connection is
    // open and idle here, so nothing else is writing the log.
    let wal_before = snapshot(&wal);
    let alias_before = snapshot(&sidecar(&evil, "-wal"));
    let evil_lock = orxnud_store::ownership::lock_path_for(&evil)
        .expect("the second database's lease key is derivable");

    let err = Store::open(&evil, true, &OsIdentity)
        .expect_err("an aliased -wal must be refused, not opened");
    match alias_refusal(&err) {
        Some(AliasRefusal::MultipleNames { name_count }) => {
            assert_eq!(
                *name_count, 2,
                "the refusal must name the count it observed"
            );
        }
        other => panic!("expected a multiple-names refusal, got {other:?}"),
    }
    assert!(
        err.to_string().contains("-wal"),
        "the refusal must name the offending sidecar: {err}"
    );

    // ---- the protected log must be exactly as it was ----
    let wal_after = snapshot(&wal);
    let alias_after = snapshot(&sidecar(&evil, "-wal"));
    assert_eq!(
        wal_before.identity, wal_after.identity,
        "the refused open must not have replaced the protected write-ahead log"
    );
    assert_eq!(
        wal_before.name_count, wal_after.name_count,
        "the refused open must not have changed how many names reach the log"
    );
    assert_eq!(
        wal_before.len, wal_after.len,
        "the refused open must not have changed the log's length"
    );
    assert_eq!(
        wal_before.bytes, wal_after.bytes,
        "the refused open must not have written a single byte to the protected log"
    );
    assert_eq!(
        alias_before.identity, alias_after.identity,
        "the aliased pathname must still identify the same log object: the refused open \
         must not have unlinked and replaced it"
    );
    assert_eq!(
        wal_before.identity, alias_before.identity,
        "the alias and the protected path must still be the same file"
    );
    assert_eq!(
        alias_before.bytes, alias_after.bytes,
        "the aliased log must not have been written through either"
    );

    // ---- no connection and no ownership state may have been left behind ----
    assert!(
        !evil.exists(),
        "the refused open must not have created the second database"
    );
    assert!(
        !evil_lock.exists(),
        "the refusal must have happened before the lease was taken, so no lock file \
         may exist for the second database"
    );

    // The protected database's rows are intact and the file is sound.
    assert_eq!(
        notes(store.conn()),
        "kept",
        "the protected rows must survive"
    );
    assert_eq!(
        integrity(store.conn()),
        "ok",
        "the protected database must still pass its own integrity check"
    );

    // The protected database's own -wal is aliased, so it is refused too.
    let err = Store::open(&db, true, &OsIdentity)
        .expect_err("the protected database's own aliased -wal must be refused too");
    assert!(
        alias_refusal(&err).is_some(),
        "expected an alias refusal, got {err:?}"
    );
    let wal_after_own = snapshot(&wal);
    assert_eq!(
        wal_before.identity, wal_after_own.identity,
        "refusing the protected database's own aliased log must not have replaced it"
    );
    assert_eq!(
        wal_before.bytes, wal_after_own.bytes,
        "refusing the protected database's own aliased log must not have written to it"
    );
    assert_eq!(
        notes(store.conn()),
        "kept",
        "the protected rows must survive"
    );
    assert_eq!(
        integrity(store.conn()),
        "ok",
        "the protected database must still pass its own integrity check"
    );

    drop(store);
    std::fs::remove_file(sidecar(&evil, "-wal")).expect("remove the alias");
    Store::open(&db, true, &OsIdentity).expect("the open must succeed once the alias is gone");

    let _ = std::fs::remove_dir_all(&d);
}

/// **Required test C — the restore path refuses an aliased sidecar.**
///
/// The restore checkpoints the live database, installs a staged image in place
/// and removes the sidecars. With a sidecar aliased, the restore must refuse
/// **before** any of that, and the protected database must be left as it was.
#[cfg(unix)]
#[test]
fn the_restore_path_refuses_an_aliased_sidecar() {
    use orxnud_store::backup::Backup;

    let d = dir("restore");
    let db = d.join("state.db");
    let evil = d.join("evil.db");

    // A real database, a real snapshot, and known content.
    let snapshot = {
        let store = open_with_content(&db);
        let snapshot = Backup::take(store.conn(), &db).expect("take the snapshot");
        drop(store);
        snapshot
    };

    // The alias. A second, *raw* connection keeps the sidecars alive, because
    // SQLite removes them when the last connection closes -- and the restore
    // needs the exclusive lease, which the store's shared lease would block.
    let holder = rusqlite::Connection::open(&db).expect("a raw connection");
    holder
        .execute_batch("PRAGMA journal_mode=wal;")
        .expect("wal mode");
    let shm = sidecar(&db, "-shm");
    assert!(shm.exists(), "precondition: the -shm must exist");
    std::fs::hard_link(&shm, sidecar(&evil, "-shm")).expect("hard link the -shm");

    // The real restore path.
    let err = snapshot
        .restore_coordinated(&db, &OsIdentity)
        .expect_err("a restore against an aliased sidecar must be refused");
    assert!(
        err.to_string().contains("-shm"),
        "the refusal must name the offending sidecar: {err}"
    );

    // The protected database is untouched and still readable.
    let c = rusqlite::Connection::open(&db).expect("reopen");
    assert_eq!(
        notes(&c),
        "kept",
        "the protected rows must survive a refused restore"
    );
    assert_eq!(
        c.query_row("PRAGMA integrity_check;", [], |r| r.get::<_, String>(0))
            .unwrap_or_default(),
        "ok",
        "the protected database must still be intact"
    );

    // And the restore still works once the alias is gone.
    drop(c);
    drop(holder);
    std::fs::remove_file(sidecar(&evil, "-shm")).expect("remove the alias");
    snapshot
        .restore_coordinated(&db, &OsIdentity)
        .expect("the restore must succeed once the alias is gone");

    let _ = std::fs::remove_dir_all(&d);
}

/// **Required test D — the ordinary WAL lifecycle is not disturbed.**
///
/// SQLite creates and removes the sidecars around a connection's life, so a
/// first open sees no sidecar at all and a later open may see a different one.
/// None of that may be reported as an alias.
#[test]
fn the_ordinary_wal_lifecycle_is_accepted() {
    let d = dir("lifecycle");
    let db = d.join("state.db");

    // First open: no sidecar exists yet, and that is not an error.
    assert!(
        !sidecar(&db, "-wal").exists(),
        "precondition: no sidecar may exist before the first open"
    );
    let store = Store::open(&db, true, &OsIdentity).expect("the first open must succeed");
    store
        .conn()
        .execute_batch("CREATE TABLE notes(v TEXT); INSERT INTO notes VALUES ('one');")
        .expect("write");
    assert!(
        sidecar(&db, "-shm").exists(),
        "precondition: WAL mode must have produced the -shm"
    );

    // A checkpoint and a write: legitimate, and the sidecars stay singly named.
    store
        .conn()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint");
    store
        .conn()
        .execute_batch("INSERT INTO notes VALUES ('two');")
        .expect("write");
    #[cfg(unix)]
    {
        assert_eq!(
            link_count(&sidecar(&db, "-wal")),
            1,
            "the -wal must stay singly named"
        );
        assert_eq!(
            link_count(&sidecar(&db, "-shm")),
            1,
            "the -shm must stay singly named"
        );
    }

    // Close: SQLite removes the sidecars. A later open must not see that as an
    // anomaly, and the removed-and-recreated sidecar must be accepted.
    drop(store);
    let store = Store::open(&db, true, &OsIdentity).expect("the reopen must succeed");
    assert_eq!(
        notes(store.conn()),
        "one,two",
        "the rows must survive the reopen"
    );
    store
        .conn()
        .execute_batch("INSERT INTO notes VALUES ('three');")
        .expect("write after the reopen");
    assert_eq!(
        notes(store.conn()),
        "one,two,three",
        "the rows must survive the second write"
    );
    drop(store);

    // And a third open, after another close, must also be fine.
    let store = Store::open(&db, true, &OsIdentity).expect("the third open must succeed");
    assert_eq!(notes(store.conn()), "one,two,three");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// A capability that answers `Unknown` for one path and normally for the rest.
///
/// The store's identity contract is a trait, so a test can inject a platform
/// that cannot answer. The guard must refuse rather than treat "we cannot tell"
/// as "one name". The main-database handle is not the subject here; this fake
/// answers `NotApplicable` so the sidecar refusal is the one under test.
struct UnknownFor {
    unknown: PathBuf,
    identity: FileId,
}

impl FilesystemIdentity for UnknownFor {
    fn observe(&self, path: &Path) -> FileFacts {
        if path == self.unknown {
            return FileFacts::Unknown {
                platform: "a-platform-that-cannot-answer",
            };
        }
        FileFacts::Known {
            name_count: 1,
            identity: Some(self.identity),
        }
    }

    fn observe_sqlite_main(&self, _connection: SqliteMainDatabase<'_>) -> SqliteMainFacts {
        SqliteMainFacts::NotApplicable
    }
}

/// **Required test E — unknown sidecar metadata fails closed.**
///
/// The link count of a sidecar that the platform cannot report is not "one
/// name"; it is "we do not know", and it must be refused.
#[test]
fn unknown_sidecar_metadata_fails_closed() {
    let d = dir("unknown");
    let db = d.join("state.db");
    // A raw connection, kept open: SQLite removes the sidecars when the last
    // connection closes, and the guard is about sidecars that *exist*.
    let holder = rusqlite::Connection::open(&db).expect("open the database");
    holder
        .execute_batch(
            "PRAGMA journal_mode=wal; CREATE TABLE notes(v TEXT); \
             INSERT INTO notes VALUES ('one');",
        )
        .expect("schema and write");
    let shm = sidecar(&db, "-shm");
    assert!(shm.exists(), "precondition: the -shm must exist");

    let capability = UnknownFor {
        unknown: shm.clone(),
        identity: FileId::Unix { dev: 1, ino: 1 },
    };
    let err = Store::open(&db, true, &capability)
        .expect_err("an unknown sidecar must be refused, not assumed safe");
    match alias_refusal(&err) {
        Some(AliasRefusal::Unknown { platform }) => {
            assert_eq!(
                *platform, "a-platform-that-cannot-answer",
                "the refusal must name the platform that could not answer"
            );
        }
        other => panic!("expected an unknown-platform refusal, got {other:?}"),
    }
    assert!(
        err.to_string().contains("-shm"),
        "the refusal must name the offending sidecar: {err}"
    );
    drop(holder);

    let _ = std::fs::remove_dir_all(&d);
}
