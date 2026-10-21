//! Windows-only integration tests for native identity and the actual database
//! handle.
//!
//! # Why these are separate from the portable suite
//!
//! `s31_alias_safety` runs everywhere. Its filesystem cases use the real
//! `OsIdentity`; its ordering and main-handle cases use local scripted
//! capabilities to control the answers. This file proves the part that only
//! Windows can measure: `orxnud-platform-fs` opens the path with `CreateFileW`,
//! reads the full 128-bit identifier and link count, and `Store::open` asks the
//! live `rusqlite::Connection` which file SQLite actually opened. The portable
//! suite cannot establish any of that.
//!
//! # What is still not proven here
//!
//! The sidecars remain path observations. This file does not claim a hard link
//! to `-wal` or `-shm` created *after* the pre-open observation is detected; the
//! store module documents that residual window. It also does not prove anything
//! on a filesystem that cannot create hard links: such a filesystem makes the
//! hard-link test fail loudly rather than pass without measuring the property.

#![cfg(windows)]

use std::path::{Path, PathBuf};

use orxnud_domain::platform::{
    FileFacts, FileId, FilesystemIdentity, SqliteMainDatabase, SqliteMainFacts,
};
use orxnud_platform_fs::OsIdentity;
use orxnud_store::StoreError;
use orxnud_store::alias::AliasRefusal;
use orxnud_store::ownership::OwnershipError;
use orxnud_store::sqlite::Store;

fn dir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let d = std::env::temp_dir().join(format!("f26c-win-{}-{tag}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

fn alias_refusal(err: &StoreError) -> &AliasRefusal {
    match err {
        StoreError::Ownership { source } => match source.as_ref() {
            OwnershipError::AliasUnsafe { reason, .. } => reason,
            other => panic!("expected an alias refusal, got {other:?}"),
        },
        other => panic!("expected an ownership refusal, got {other:?}"),
    }
}

fn known(facts: FileFacts) -> (u64, FileId) {
    match facts {
        FileFacts::Known {
            name_count,
            identity: Some(identity),
        } => (name_count, identity),
        other => panic!("expected known facts with an identity, got {other:?}"),
    }
}

/// **A real store open succeeds, and the live handle is the file on disk.**
///
/// This is the end-to-end version of the platform unit test: the production
/// `Store::open` path observes the created database, inspects the actual SQLite
/// handle, and returns a store only because the two agree.
#[test]
fn a_real_store_open_validates_the_actual_handle() {
    let d = dir("open");
    let db = d.join("state.db");

    let store = Store::open(&db, true, &OsIdentity).expect("a new database must open");
    assert!(db.exists(), "the open must have created the database");

    let (path_count, path_identity) = known(OsIdentity.observe(&db));
    assert_eq!(
        path_count, 1,
        "a freshly created database must have one name"
    );

    match OsIdentity.observe_sqlite_main(SqliteMainDatabase::new(store.conn())) {
        SqliteMainFacts::Known {
            name_count,
            identity,
        } => {
            assert_eq!(
                name_count, path_count,
                "the live connection and the path must report the same link count"
            );
            assert_eq!(
                identity, path_identity,
                "the live connection must hold the file the path names"
            );
        }
        other => panic!("the live main handle must be inspectable, got {other:?}"),
    }

    drop(store);
    let _ = std::fs::remove_dir_all(&d);
}

/// **A hard-linked database is refused through both names.**
///
/// The Windows implementation must report the real link count, not a
/// platform-specific "unknown". If this filesystem cannot create a hard link,
/// the test fails with that reason rather than passing without measuring it.
#[test]
fn a_hard_linked_database_is_refused() {
    let d = dir("hard-link");
    let db = d.join("state.db");
    let alias = d.join("alias.db");

    {
        let store = Store::open(&db, true, &OsIdentity).expect("create the database");
        drop(store);
    }
    std::fs::hard_link(&db, &alias).expect(
        "the scratch filesystem must support hard links; if it does not, the \
         hard-link property cannot be established here and this test must fail \
         rather than pass without measuring it",
    );

    let (count, _) = known(OsIdentity.observe(&db));
    assert_eq!(count, 2, "the hard link must raise the native link count");

    for path in [&db, &alias] {
        let err = Store::open(path, true, &OsIdentity)
            .expect_err("a database with two names must be refused");
        match alias_refusal(&err) {
            AliasRefusal::MultipleNames { name_count } => {
                assert_eq!(*name_count, 2, "the refusal must name the count");
            }
            other => panic!("expected a multiple-names refusal, got {other:?}"),
        }
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// Delegates path facts to the real Windows backend and scripts only the
/// main-database handle answer.
struct MainAnswer {
    main: SqliteMainFacts,
}

impl FilesystemIdentity for MainAnswer {
    fn observe(&self, path: &Path) -> FileFacts {
        OsIdentity.observe(path)
    }

    fn observe_sqlite_main(&self, _connection: SqliteMainDatabase<'_>) -> SqliteMainFacts {
        self.main
    }
}

/// **An unverifiable main handle is refused, not skipped.**
#[test]
fn an_unverifiable_main_handle_is_refused() {
    let d = dir("main-unknown");
    let db = d.join("state.db");
    let identity = MainAnswer {
        main: SqliteMainFacts::Unknown {
            platform: "windows",
        },
    };

    let err =
        Store::open(&db, true, &identity).expect_err("an unverifiable main handle must be refused");
    match alias_refusal(&err) {
        AliasRefusal::MainDatabaseUnknown { platform } => {
            assert_eq!(*platform, "windows", "the refusal must name the platform");
        }
        other => panic!("expected a main-handle unknown refusal, got {other:?}"),
    }

    // The lease was released: the real capability can open the file the failed
    // attempt created.
    let store = Store::open(&db, true, &OsIdentity).expect("the refusal must release the lease");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// **A main handle reachable through two names is refused.**
#[test]
fn a_main_handle_with_two_names_is_refused() {
    let d = dir("main-two-names");
    let db = d.join("state.db");

    {
        let store = Store::open(&db, true, &OsIdentity).expect("create the database");
        drop(store);
    }
    let (_, identity) = known(OsIdentity.observe(&db));
    let identity = MainAnswer {
        main: SqliteMainFacts::Known {
            name_count: 2,
            identity,
        },
    };

    let err = Store::open(&db, true, &identity)
        .expect_err("a main handle with two names must be refused");
    match alias_refusal(&err) {
        AliasRefusal::MainDatabaseMultipleNames { name_count } => {
            assert_eq!(*name_count, 2, "the refusal must name the handle's count");
        }
        other => panic!("expected a main-handle multiple-names refusal, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// **A main handle that holds a different file is refused.**
#[test]
fn a_mismatched_main_handle_identity_is_refused() {
    let d = dir("main-mismatch");
    let db = d.join("state.db");

    {
        let store = Store::open(&db, true, &OsIdentity).expect("create the database");
        drop(store);
    }
    let identity = MainAnswer {
        main: SqliteMainFacts::Known {
            name_count: 1,
            // The real path observation on Windows returns a `Windows`
            // identity, so a `Unix` variant is guaranteed to differ. This is a
            // scripted mismatch, not a claim that such an identity can exist on
            // Windows.
            identity: FileId::Unix { dev: 0, ino: 0 },
        },
    };

    let err =
        Store::open(&db, true, &identity).expect_err("a mismatched main handle must be refused");
    assert!(
        matches!(
            alias_refusal(&err),
            AliasRefusal::MainDatabaseIdentityChanged
        ),
        "expected a main-handle identity refusal, got {err}"
    );

    let _ = std::fs::remove_dir_all(&d);
}
