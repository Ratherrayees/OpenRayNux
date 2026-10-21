//! F-26c / ADR-0058: alias safety for database opens.
//!
//! # The bypass these tests close
//!
//! Ownership of a database is keyed by **path**. `state.db` owns `state.db.lock`;
//! a process that opens the same file through a second name owns
//! `alias.db.lock` instead. Two locks, one database, and the second process
//! participates in nothing — so it may write while a restore installs a staged
//! image. Measured during S-31's review:
//!
//! ```text
//! state.db and alias.db are one inode (20445) but resolve to
//!     state.db.lock   and   alias.db.lock
//! ```
//!
//! ADR-0058 approved the remedy: **refuse** a database reachable through more
//! than one name, with the link count read through a filesystem-identity
//! capability that `orxnud-store` depends on as a trait and the platform layer
//! implements.
//!
//! # Test inventory: fourteen cases in four groups
//!
//! ADR-0058's test plan has six rows, but this file now holds more than the five
//! planned cases. Its fourteen `#[test]` functions are:
//!
//! | Group | Tests |
//! |---|---|
//! | ADR-0058's five planned path cases | 1–5 in the table below |
//! | Ordering and creation additions | `a_database_aliased_when_the_open_begins_is_refused_before_it_is_opened`, `a_second_name_that_appears_during_the_open_is_refused`, `an_unanswerable_platform_is_refused_on_either_side_of_the_open`, `a_database_created_by_the_open_must_have_exactly_one_name` |
//! | Main-database handle | `a_main_handle_with_a_different_identity_is_refused`, `a_main_handle_with_two_names_is_refused`, `an_unverifiable_main_handle_is_refused`, `a_matching_main_handle_is_accepted` |
//! | Typed refusal | `the_refusal_is_typed_rather_than_a_message` |
//!
//! The five planned cases, named exactly as the ADR names them:
//!
//! | # | Test | What it proves |
//! |---|---|---|
//! | 1 | `an_ordinary_single_name_database_opens_normally` | The check does not break the common path, including a database that does not exist yet. |
//! | 2 | `a_database_reachable_through_two_names_is_refused` | Two names for one inode; **both** refuse, with a typed ownership error naming the count. |
//! | 3 | `the_two_names_would_have_had_two_locks` | The bypass being closed is real: the two names had two lock files. |
//! | 4 | `an_unknowable_filesystem_is_refused_not_assumed_safe` | A capability that cannot answer refuses. |
//! | 5 | `a_file_replaced_during_the_open_is_detected` | A detectable change between the two observations is refused. |
//!
//! The sixth ADR row is a preservation requirement: the two-process and
//! controlled-interleaving tests in `s31_two_process.rs` and `s31_entry_points.rs`
//! must keep passing **unchanged**, because they are the evidence for the
//! ownership protocol this work narrows rather than replaces.
//!
//! # Which implementation these use
//!
//! The **real** one — `orxnud_platform_fs::OsIdentity` — for the cases that are
//! about the filesystem (1, 2, 3 and the typed refusal). A store test that used a
//! fake would prove the store's logic and nothing about the implementation that
//! ships, and the whole point of cases 1 and 2 is that the shipped
//! implementation answers about a real hard link.
//!
//! The ordering, creation and main-handle cases use local scripted capabilities.
//! Planned cases 4 and 5 need capabilities that **cannot** exist on a real
//! filesystem — one that cannot answer at all, and one whose answer changes
//! between calls. The fakes are local to this file and cannot leak into
//! production.
//!
//! The four main-handle cases exercise the store's comparison decision through
//! `SqliteMainFacts`. On Unix `observe_sqlite_main` is `NotApplicable`, so this
//! file cannot exercise the native Windows handle; `s31_windows_identity.rs` does
//! that on Windows.
//!
//! # What these tests do not prove
//!
//! On Unix, the observations are of a **path**. SQLite opens by filename, so
//! these tests cannot show that the connection refers to the inode the path
//! checks saw. The main-handle cases prove the store's decision logic, not that a
//! real Unix connection handle was inspected. Every sidecar remains a path
//! observation, a hard link created after the handle observation is not detected,
//! and native Windows runtime behavior is not compiled or run here. ADR-0058
//! Decision 2 approved the path limitation rather than claiming it away, and the
//! guarantee these tests establish is stated in [`orxnud_store::alias`].

use std::cell::Cell;
use std::path::{Path, PathBuf};

use orxnud_domain::platform::{
    FileFacts, FileId, FilesystemIdentity, SqliteMainDatabase, SqliteMainFacts,
};
use orxnud_platform_fs::OsIdentity;
use orxnud_store::StoreError;
use orxnud_store::alias::AliasRefusal;
use orxnud_store::ownership::OwnershipError;
use orxnud_store::sqlite::Store;

/// A scratch directory, unique per test name and per call.
fn dir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let d = std::env::temp_dir().join(format!("f26c-{}-{tag}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

/// The typed refusal an alias-unsafe open must produce.
fn alias_refusal(err: &StoreError) -> &AliasRefusal {
    match err {
        StoreError::Ownership { source } => match source.as_ref() {
            OwnershipError::AliasUnsafe { reason, .. } => reason,
            other => panic!("expected an alias refusal, got {other:?}"),
        },
        other => panic!("expected an ownership refusal, got {other:?}"),
    }
}

/// **Case 1 — the common path still works, including creating the database.**
///
/// The check must not cost the ordinary case anything. It must also cover the
/// *creation* path: a database that does not exist yet has nothing to check
/// before the open, so the post-open observation is the first one with anything
/// to say, and it must find a file with exactly one name.
#[test]
fn an_ordinary_single_name_database_opens_normally() {
    let d = dir("ordinary");
    let db = d.join("state.db");
    assert!(!db.exists(), "the database must not exist before the open");

    let store = Store::open(&db, true, &OsIdentity).expect("an ordinary open must succeed");
    assert!(
        db.exists(),
        "the open must have created the database it was asked for"
    );
    drop(store);

    // And again, now that the file exists: the pre-open observation has a real
    // link count and a real identity to work with.
    let store = Store::open(&db, true, &OsIdentity).expect("a second ordinary open must succeed");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// **Case 2 — two names for one inode: both refuse, with the count named.**
///
/// The link count is a property of the **inode**, not of the name, so the
/// refusal applies to every name for the file — including the legitimate one.
/// That is the safe direction, and it is an availability consequence an operator
/// has to be told about, which is why the error names the count.
///
/// This is one of the two tests a permissive default would fail. A default that
/// read "two names" as "fine" would let the alias straight through, and the whole
/// finding would still be open.
#[test]
fn a_database_reachable_through_two_names_is_refused() {
    let d = dir("two-names");
    let db = d.join("state.db");
    let alias = d.join("alias.db");

    // A real database, created through the real open.
    {
        let store = Store::open(&db, true, &OsIdentity).expect("create the database");
        drop(store);
    }
    std::fs::hard_link(&db, &alias).expect("hard link the database");

    // Both names now reach one inode through two directory entries.
    for path in [&db, &alias] {
        let err = Store::open(path, true, &OsIdentity)
            .expect_err("a database reachable through two names must be refused");
        match alias_refusal(&err) {
            AliasRefusal::MultipleNames { name_count } => {
                assert_eq!(
                    *name_count, 2,
                    "the refusal must name the count it observed, so an operator can \
                     see that a second name exists rather than guessing"
                );
            }
            other => panic!("expected a multiple-names refusal, got {other:?}"),
        }
    }

    // The refusal must not leave ownership state behind: once the second name is
    // gone, the very same path opens again. A refusal that leaked the lease
    // would refuse the database for ever.
    std::fs::remove_file(&alias).expect("remove the alias");
    let store =
        Store::open(&db, true, &OsIdentity).expect("the refusal must have released the lease");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// **Case 3 — the bypass being closed is real: the two names had two locks.**
///
/// Without this, case 2 could be passing for the wrong reason — for instance
/// because the two names had been made to share one lock by something else. The
/// measurement is the one from S-31's review: one inode, two lock files.
#[test]
fn the_two_names_would_have_had_two_locks() {
    let d = dir("two-locks");
    let db = d.join("state.db");
    let alias = d.join("alias.db");

    {
        let store = Store::open(&db, true, &OsIdentity).expect("create the database");
        drop(store);
    }
    std::fs::hard_link(&db, &alias).expect("hard link the database");

    let lock_a = orxnud_store::ownership::lock_path_for(&db).expect("a resolvable path");
    let lock_b = orxnud_store::ownership::lock_path_for(&alias).expect("a resolvable path");
    assert_ne!(
        lock_a, lock_b,
        "the two names must resolve to two different lock files; that is the bypass, \
         and the refusal in case 2 is the only thing standing between it and an \
         unguarded database"
    );

    // And the refusal is what closes it, for both names.
    for path in [&db, &alias] {
        assert!(
            Store::open(path, true, &OsIdentity).is_err(),
            "with two lock files for one inode, the open must be refused — otherwise a \
             competitor opening the alias would participate in nothing"
        );
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// A capability that cannot answer.
///
/// Stands for both ways the platform can fail to answer: a platform that does
/// not expose the count, and a metadata error on a platform that does. Both
/// must produce the same outcome, because an operator's response to "we could
/// not tell" and to "we checked" must be opposite.
struct Unknowable;

impl FilesystemIdentity for Unknowable {
    fn observe(&self, _path: &Path) -> FileFacts {
        FileFacts::Unknown {
            platform: "a-platform-that-cannot-answer",
        }
    }

    fn observe_sqlite_main(&self, _connection: SqliteMainDatabase<'_>) -> SqliteMainFacts {
        SqliteMainFacts::Unknown {
            platform: "a-platform-that-cannot-answer",
        }
    }
}

/// **Case 4 — "the platform cannot say" is a refusal, not a pass.**
///
/// This is the second of the two tests a permissive default would fail. A
/// default that treated an unanswerable question as "one name, therefore safe"
/// would let every database on such a platform through unguarded — which is the
/// bypass reached through a different door. ADR-0058 Decision 2 requires the
/// refusal and names the platform as the reason.
#[test]
fn an_unknowable_filesystem_is_refused_not_assumed_safe() {
    let d = dir("unknowable");
    let db = d.join("state.db");

    // Even for a database that does not exist yet: the open would create it, and
    // the file it created could not be shown to have one name either.
    let err = Store::open(&db, true, &Unknowable)
        .expect_err("an unanswerable filesystem must be refused, not assumed safe");
    match alias_refusal(&err) {
        AliasRefusal::Unknown { platform } => {
            assert_eq!(
                *platform, "a-platform-that-cannot-answer",
                "the refusal must name the platform, because 'we could not tell' and \
                 'we checked and it is fine' call for opposite responses"
            );
        }
        other => panic!("expected an unknown-platform refusal, got {other:?}"),
    }

    // And for an existing database.
    {
        let store = Store::open(&db, true, &OsIdentity).expect("create the database");
        drop(store);
    }
    let err = Store::open(&db, true, &Unknowable)
        .expect_err("an unanswerable filesystem must be refused for an existing database too");
    assert!(
        matches!(alias_refusal(&err), AliasRefusal::Unknown { .. }),
        "expected an unknown-platform refusal, got {err}"
    );

    // The refusal must leave no handle and no lease behind.
    let store = Store::open(&db, true, &OsIdentity)
        .expect("the real platform must still be able to open the database");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// A capability whose answers are **scripted**, one per observation.
///
/// The store's check asks exactly twice — once before SQLite is handed the path
/// and once after — so a two-answer script covers every ordering case without a
/// race and without a sleep. The last answer repeats if the store asks again,
/// so an extra question cannot make the script run out.
struct Scripted {
    target: PathBuf,
    answers: Vec<FileFacts>,
    calls: Cell<u32>,
    main: SqliteMainFacts,
}

impl Scripted {
    /// Script the answers **for `target`**.
    ///
    /// Every other path — the sidecars — is reported absent, which is the
    /// ordinary state of a database that has not been opened.
    ///
    /// The answers are keyed by *path* and not by "the Nth observation of
    /// anything". The store observes the database before and after the open, and
    /// each sidecar before and after, so a fake keyed by observation count
    /// would answer a different question as soon as the number of observations
    /// changed. Keying by path is also what each of these tests means.
    fn new(target: impl Into<PathBuf>, answers: Vec<FileFacts>) -> Self {
        assert!(!answers.is_empty(), "a scripted capability needs an answer");
        Self {
            target: target.into(),
            answers,
            calls: Cell::new(0),
            // The path-only tests are about the path checks; the main-handle
            // question is answered explicitly by `with_main` where it matters.
            main: SqliteMainFacts::NotApplicable,
        }
    }

    /// Script the answer to the main-database handle question.
    fn with_main(mut self, main: SqliteMainFacts) -> Self {
        self.main = main;
        self
    }

    /// One name, one identity.
    fn one_name(id: u64) -> FileFacts {
        FileFacts::Known {
            name_count: 1,
            identity: Some(FileId::Unix { dev: 1, ino: id }),
        }
    }

    /// Two names, one identity.
    fn two_names(id: u64) -> FileFacts {
        FileFacts::Known {
            name_count: 2,
            identity: Some(FileId::Unix { dev: 1, ino: id }),
        }
    }

    /// The platform cannot answer.
    fn unknown() -> FileFacts {
        FileFacts::Unknown {
            platform: "a-platform-that-cannot-answer",
        }
    }
}

impl FilesystemIdentity for Scripted {
    fn observe(&self, path: &Path) -> FileFacts {
        if path != self.target {
            return FileFacts::Absent;
        }
        let n = self.calls.get() as usize;
        self.calls.set(self.calls.get() + 1);
        self.answers[n.min(self.answers.len() - 1)]
    }

    fn observe_sqlite_main(&self, _connection: SqliteMainDatabase<'_>) -> SqliteMainFacts {
        self.main
    }
}

/// **Case 5 — a file replaced during the open is detected.**
///
/// **What it proves:** that a *detectable* change between the two observations
/// is refused, and that the refusal happens after SQLite opened the file, so
/// the connection has to be dropped rather than returned.
///
/// **What it does not prove:** that every possible replacement during SQLite's
/// own open is impossible. It cannot, and it must not be described as if it did
/// — SQLite opens by filename and `orxnud-store` cannot hand it a descriptor
/// (ADR-0058 Decision 2).
#[test]
fn a_file_replaced_during_the_open_is_detected() {
    let d = dir("replaced");
    let db = d.join("state.db");

    let swapping = Scripted::new(&db, vec![Scripted::one_name(1), Scripted::one_name(2)]);
    let err = Store::open(&db, true, &swapping)
        .expect_err("a file whose identity changed during the open must be refused");
    assert!(
        matches!(alias_refusal(&err), AliasRefusal::IdentityChanged),
        "expected an identity-changed refusal, got {err}"
    );

    // The open really did reach SQLite: the file exists. So the refusal came
    // from the *post*-open comparison, and the connection opened to make that
    // comparison was dropped rather than handed back.
    assert!(
        db.exists(),
        "the refusal must come from the post-open comparison, after SQLite opened \
         the file"
    );

    // And the lease was released: the same path opens with a capability that
    // answers consistently.
    let store =
        Store::open(&db, true, &OsIdentity).expect("the refusal must have released the lease");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// The handle's answer when it is the file the path checks saw.
fn main_matches(id: u64) -> SqliteMainFacts {
    SqliteMainFacts::Known {
        name_count: 1,
        identity: FileId::Unix { dev: 1, ino: id },
    }
}

/// **A main handle that holds a different file from the path is refused.**
///
/// This is the window the path checks cannot close on their own: the path
/// resolves consistently, but SQLite opened something else. The handle is the
/// authority, so the open is refused even though both path observations agree.
#[test]
fn a_main_handle_with_a_different_identity_is_refused() {
    let d = dir("main-different");
    let db = d.join("state.db");

    let script =
        Scripted::new(&db, vec![Scripted::one_name(1)]).with_main(SqliteMainFacts::Known {
            name_count: 1,
            identity: FileId::Unix { dev: 9, ino: 9 },
        });
    let err = Store::open(&db, true, &script)
        .expect_err("a handle that holds a different file must be refused");
    assert!(
        matches!(
            alias_refusal(&err),
            AliasRefusal::MainDatabaseIdentityChanged
        ),
        "expected a main-handle identity refusal, got {err}"
    );

    // The lease was released: the ordinary path opens again.
    let store =
        Store::open(&db, true, &OsIdentity).expect("the refusal must have released the lease");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// **A main handle with more than one name is refused.**
///
/// The path observations said one name; the handle says two. The handle wins,
/// because the handle is the file that will be written.
#[test]
fn a_main_handle_with_two_names_is_refused() {
    let d = dir("main-two-names");
    let db = d.join("state.db");

    let script =
        Scripted::new(&db, vec![Scripted::one_name(1)]).with_main(SqliteMainFacts::Known {
            name_count: 2,
            identity: FileId::Unix { dev: 1, ino: 1 },
        });
    let err = Store::open(&db, true, &script)
        .expect_err("a handle reachable through two names must be refused");
    match alias_refusal(&err) {
        AliasRefusal::MainDatabaseMultipleNames { name_count } => {
            assert_eq!(*name_count, 2, "the refusal must name the handle's count");
        }
        other => panic!("expected a main-handle multiple-names refusal, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// **A main handle that cannot be inspected is refused, not skipped.**
///
/// `Unknown` from the handle check is not a licence to fall back to the path
/// observations. On Windows that answer means the live connection could not be
/// shown to refer to the checked file, and the open must fail.
#[test]
fn an_unverifiable_main_handle_is_refused() {
    let d = dir("main-unknown");
    let db = d.join("state.db");

    let script =
        Scripted::new(&db, vec![Scripted::one_name(1)]).with_main(SqliteMainFacts::Unknown {
            platform: "a-platform-that-cannot-answer",
        });
    let err =
        Store::open(&db, true, &script).expect_err("an unverifiable main handle must be refused");
    match alias_refusal(&err) {
        AliasRefusal::MainDatabaseUnknown { platform } => {
            assert_eq!(
                *platform, "a-platform-that-cannot-answer",
                "the refusal must name the platform that could not answer"
            );
        }
        other => panic!("expected a main-handle unknown refusal, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// **A main handle that agrees with the path is accepted.**
///
/// The negative cases above must not be passing because every main-handle answer
/// is refused. When the handle holds the same file as the path checks, the open
/// succeeds.
#[test]
fn a_matching_main_handle_is_accepted() {
    let d = dir("main-matches");
    let db = d.join("state.db");

    let script = Scripted::new(&db, vec![Scripted::one_name(1)]).with_main(main_matches(1));
    let store = Store::open(&db, true, &script)
        .expect("a handle that agrees with the path must be accepted");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// Two names before the open, one name after it.
///
/// The file itself is untouched: the *answers* differ, not the filesystem. That
/// is what makes the ordering observable without a race — the store takes one
/// observation before SQLite is handed the path and one after, and this
/// capability answers differently to each.
fn aliased_then_clean(db: &Path) -> Scripted {
    Scripted::new(db, vec![Scripted::two_names(1), Scripted::one_name(1)])
}

/// **The observation taken *before* the open is acted upon.**
///
/// ADR-0058 Decision 3 requires two observations — one before SQLite is asked
/// to open anything, one after — and requires the *first* one to refuse a
/// database with more than one name. If only the second observation were
/// consulted, the file would be opened first and the alias noticed afterwards.
///
/// This is an addition to the ADR's five new cases, not one of them, and it
/// exists because the other cases do not distinguish "refused before the open"
/// from "refused after it": with a real hard link the outcome is the same
/// either way, and only the file's existence on disk tells them apart.
#[test]
fn a_database_aliased_when_the_open_begins_is_refused_before_it_is_opened() {
    let d = dir("aliased-then-clean");
    let db = d.join("state.db");

    let err = Store::open(&db, true, &aliased_then_clean(&db))
        .expect_err("the observation taken before the open must decide the open");
    match alias_refusal(&err) {
        AliasRefusal::MultipleNames { name_count } => {
            assert_eq!(
                *name_count, 2,
                "the refusal must be the one the *pre-open* observation produced"
            );
        }
        other => panic!("expected a multiple-names refusal, got {other:?}"),
    }

    assert!(
        !db.exists(),
        "the database must not exist: the refusal came before SQLite was handed the \
         path, so the file was never opened"
    );

    // The lease was released too: a real open of the same path works afterwards.
    let store =
        Store::open(&db, true, &OsIdentity).expect("the refusal must have released the lease");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// One name before the open, two names after it.
///
/// The mirror of [`aliased_then_clean`]: a second name appears while the
/// database is being opened.
fn clean_then_aliased(db: &Path) -> Scripted {
    Scripted::new(db, vec![Scripted::one_name(1), Scripted::two_names(1)])
}

/// **A second name that appears while the database is being opened is refused.**
///
/// ADR-0058 Decision 3, step 3: after the open, `name_count(path)` must still be
/// one. This is the observation that catches a link created *during* the open,
/// which the pre-open observation cannot see.
///
/// It is an addition to the ADR's five new cases, not one of them, and it exists
/// because nothing else distinguishes the post-open link count from the pre-open
/// one: with a real hard link the two names exist before the open begins.
#[test]
fn a_second_name_that_appears_during_the_open_is_refused() {
    let d = dir("clean-then-aliased");
    let db = d.join("state.db");

    let err = Store::open(&db, true, &clean_then_aliased(&db))
        .expect_err("a second name appearing during the open must be refused");
    match alias_refusal(&err) {
        AliasRefusal::MultipleNames { name_count } => {
            assert_eq!(
                *name_count, 2,
                "the refusal must be the one the *post-open* observation produced"
            );
        }
        other => panic!("expected a multiple-names refusal, got {other:?}"),
    }

    // The lease was released: the same path opens once the capability answers
    // consistently.
    let store =
        Store::open(&db, true, &OsIdentity).expect("the refusal must have released the lease");
    drop(store);

    let _ = std::fs::remove_dir_all(&d);
}

/// **An unanswerable platform is refused on *either* side of the open.**
///
/// ADR-0058 Decision 2: "`None` from `name_count` or `identity` means refuse".
/// It does not say *which* observation has to be able to answer — so neither
/// side may be treated as the one that can be lenient. Two cases, one per side:
///
/// * the platform cannot answer **before** the open, and can after: the open is
///   still refused, because the answer that mattered was the one it did not get;
/// * the platform can answer before the open, and cannot answer **after** it: the
///   open is still refused, because the answer that mattered was the one it did
///   not get.
///
/// Both are the same rule. Together they are what stops "unknown means safe"
/// from creeping back in on one side of the check.
#[test]
fn an_unanswerable_platform_is_refused_on_either_side_of_the_open() {
    let d = dir("unknown-either-side");

    // Unknown before the open, answerable after.
    let db = d.join("before.db");
    let err = Store::open(
        &db,
        true,
        &Scripted::new(&db, vec![Scripted::unknown(), Scripted::one_name(1)]),
    )
    .expect_err("an unanswerable platform must be refused before the open");
    assert!(
        matches!(alias_refusal(&err), AliasRefusal::Unknown { .. }),
        "expected an unknown-platform refusal, got {err}"
    );
    assert!(
        !db.exists(),
        "the refusal must come before SQLite was handed the path, so the file was \
         never opened"
    );

    // Answerable before the open, unknown after.
    let db = d.join("after.db");
    let err = Store::open(
        &db,
        true,
        &Scripted::new(&db, vec![Scripted::one_name(1), Scripted::unknown()]),
    )
    .expect_err("an unanswerable platform must be refused after the open too");
    assert!(
        matches!(alias_refusal(&err), AliasRefusal::Unknown { .. }),
        "expected an unknown-platform refusal, got {err}"
    );

    let _ = std::fs::remove_dir_all(&d);
}

/// **A database created by the open must have exactly one name afterwards.**
///
/// The other half of the creation path: the pre-open observation had nothing to
/// say, because the file did not exist, so the post-open observation is the
/// first one that has anything to say about it — and a file the open created
/// must not have acquired a second name in the meantime.
#[test]
fn a_database_created_by_the_open_must_have_exactly_one_name() {
    let d = dir("created-then-aliased");
    let db = d.join("state.db");

    let err = Store::open(
        &db,
        true,
        &Scripted::new(&db, vec![FileFacts::Absent, Scripted::two_names(1)]),
    )
    .expect_err("a database that acquired a second name during its own open must be refused");
    match alias_refusal(&err) {
        AliasRefusal::MultipleNames { name_count } => {
            assert_eq!(
                *name_count, 2,
                "the refusal must be the one the *post-open* observation produced"
            );
        }
        other => panic!("expected a multiple-names refusal, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&d);
}

/// The refusal is **typed**, so a caller can tell it from a broken database.
///
/// A refusal reported only as a message would be indistinguishable from an I/O
/// error, and a caller that cannot tell them apart will eventually retry the
/// second as if it were the first.
#[test]
fn the_refusal_is_typed_rather_than_a_message() {
    let d = dir("typed");
    let db = d.join("state.db");
    {
        let store = Store::open(&db, true, &OsIdentity).expect("create the database");
        drop(store);
    }
    let alias = d.join("alias.db");
    std::fs::hard_link(&db, &alias).expect("hard link");

    let err = Store::open(&db, true, &OsIdentity).expect_err("must refuse");
    match err {
        StoreError::Ownership { source } => match source.as_ref() {
            OwnershipError::AliasUnsafe { path, reason } => {
                assert_eq!(path, &db, "the refusal must name the database it refused");
                assert!(
                    matches!(reason, AliasRefusal::MultipleNames { name_count: 2 }),
                    "expected a two-names refusal, got {reason:?}"
                );
            }
            other => panic!("expected an alias refusal, got {other:?}"),
        },
        other => panic!("expected an ownership refusal, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&d);
}
