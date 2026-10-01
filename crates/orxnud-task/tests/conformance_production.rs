//! The ADR-0029 conformance suite, run against the **production** engine.
//!
//! # What this file is
//!
//! Phase 2's acceptance criterion. It calls the *same*
//! [`run_suite`](orxnud_task::conformance::run_suite) the Phase 1 fixture uses,
//! with the only difference being which engine the factory builds. Nothing here
//! re-implements a property, weakens an assertion, skips a case, or forks the
//! harness — if this file needed any of those, the engine would be wrong.
//!
//! It lives in `tests/` rather than in the library so the conformance machinery is
//! reachable from both the trivial fixture and the real engine without either
//! engine depending on the other.
//!
//! # The failure that matters
//!
//! If a property reports `Unsupported`, the suite does **not** pass. A durability
//! or fencing property that silently did not run is worse than one that admits it
//! could not, which is why [`run_suite`] treats `Unsupported` as a failure here.
//!
//! # Durability tests use real files
//!
//! docs-08 §4.4: never `:memory:` for anything touching durability. An in-memory
//! database has no WAL, no `synchronous = FULL`, and no crash recovery, so it
//! cannot test TP-1, TP-4 or TP-7 at all. Every engine here is built on a real
//! file under a per-test temporary directory.

mod support_production;

use std::path::PathBuf;

use orxnud_task::conformance::report::Verdict;
use orxnud_task::conformance::run_suite;

use support_production::{production, production_broken};

/// The recorded seed, matching the trivial fixture's, so a failure in either
/// engine is reproducible and the two reports are comparable.
const SEED: u64 = 0x0F0E_D100;

#[test]
fn all_twelve_properties_hold_for_the_production_engine() {
    let report = run_suite(production(), SEED);
    println!("{}", report.render());

    let violations = report.violations();
    assert!(violations.is_empty(), "properties violated: {violations:?}");
    let gaps = report.gaps();
    assert!(gaps.is_empty(), "properties unsupported: {gaps:?}");
    assert_eq!(report.verdict(), Verdict::Conforms);
    assert!(report.fully_conforms());
    assert_eq!(report.results.len(), 12, "every property must be reported");
    // The engine under test must be named, so a report cannot be mistaken for one
    // produced by the trivial fixture.
    assert_eq!(report.engine, "sqlite-durable");
}

#[test]
fn the_production_report_names_all_twelve_properties() {
    // A property silently dropped from the report is as bad as one that failed.
    let report = run_suite(production(), SEED);
    let ids: Vec<&str> = report.results.iter().map(|r| r.id).collect();
    let expected = [
        "TP-1", "TP-2", "TP-3", "TP-4", "TP-5", "TP-6", "TP-7", "TP-8", "TP-9", "TP-10", "TP-11",
        "TP-12",
    ];
    for id in expected {
        assert!(ids.contains(&id), "{id} missing from the report: {ids:?}");
    }
}

#[test]
fn the_production_suite_is_reproducible() {
    // The same seed must produce the same verdicts. A conformance report that
    // varies run to run is not evidence of anything.
    let a = run_suite(production(), SEED);
    let b = run_suite(production(), SEED);
    assert_eq!(a, b);
}

#[test]
fn a_broken_production_store_violates_rather_than_silently_passing() {
    // The suite must have teeth against *this* engine. If a store that rejects
    // every write still produced a clean report, the report would be meaningless.
    let report = run_suite(production_broken(), SEED);
    assert!(
        !report.violations().is_empty(),
        "an engine whose store rejects everything must not produce a clean report"
    );
    assert_eq!(report.verdict(), Verdict::NonConforming);
}

#[test]
fn the_engine_names_itself_and_declares_its_fencing() {
    // Sanity on the declaration TP-5's visibility depends on: an engine that did not
    // support fencing would report `Unsupported` rather than silently passing.
    let e = production_engine();
    assert_eq!(
        orxnud_task::conformance::properties::TaskEngine::name(&e),
        "sqlite-durable"
    );
    assert!(orxnud_task::conformance::properties::TaskEngine::supports_lease_fencing(&e));
}

/// A production engine on a fresh real-file database.
fn production_engine() -> orxnud_task::DurableEngine {
    let conn = open_migrated(&database_in(scratch("direct")));
    orxnud_task::DurableEngine::new(conn, orxnud_task::EngineLimits::documented())
        .expect("documented limits are valid")
}

/// A unique temporary directory for a test, removed by the caller.
///
/// Per-test rather than per-process: the conformance properties are isolated from
/// each other but a *test binary* runs several suites, and sharing one directory
/// would let one suite's rows be visible to another's.
pub fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orxnud-conf-prod-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// The database file inside a scratch directory.
///
/// A *file* inside a directory, deliberately: opening the directory as a database
/// looks like it works on Linux and fails only on the first write, which is a
/// confusing way to discover the difference.
pub fn database_in(dir: PathBuf) -> PathBuf {
    dir.join("state.db")
}

/// Opens a migrated store on a real file, with critical pragmas.
pub fn open_migrated(path: &std::path::Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).expect("open");
    orxnud_store::pragma::Pragma::critical()
        .apply(&conn)
        .expect("apply pragmas");
    orxnud_store::pragma::Pragma::critical()
        .verify(&conn)
        .expect("verify pragmas");
    orxnud_store::MigrationRunner::new(&conn)
        .run(true)
        .expect("migrate");
    conn
}

/// The TP-7 victim, as a test in **this** binary.
///
/// # Why this file needs its own copy
///
/// `power_loss::spawn_victim` re-executes the *current test binary* with
/// `--exact victim_entry_point --ignored`. The entry point is therefore a
/// per-binary requirement, not a library function: a second binary that runs the
/// conformance suite must expose it or TP-7's process-kill half reports
/// "victim never signalled readiness" — which is exactly what happened on the first
/// run of this file, and why it is written down rather than worked around.
///
/// This is **not** a fork of the harness. `run_suite`, the twelve properties, and
/// every assertion are the Phase 1 code, untouched. What is duplicated here is a
/// three-line shim; the victim itself lives once, in
/// `orxnud_task::conformance::power_loss::victim_entry_point`.
///
/// # Why the qualification is there
///
/// `#[ignore]`d because it is not a test — it is an entry point. Running it
/// directly with no environment set is a no-op, so invoking the binary by hand is
/// harmless.
#[test]
#[ignore = "child-process entry point for TP-7, not a test"]
fn victim_entry_point() {
    orxnud_task::conformance::power_loss::victim_entry_point();
}

/// The Phase 1 fixture's binary must expose the same entry point.
///
/// Asserted rather than assumed: the two shims are textually identical, and if one
/// is renamed or removed the only symptom would be a 30-second timeout inside
/// TP-7, which is a poor way to learn about a rename.
#[test]
fn the_phase_one_fixture_binary_also_provides_the_victim_entry_point() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(manifest_dir.join("tests/conformance.rs"))
        .expect("the Phase 1 fixture file must still exist");
    assert!(
        src.contains("fn victim_entry_point()"),
        "tests/conformance.rs no longer defines the TP-7 entry point; \
         power_loss::spawn_victim filters on it and TP-7 would time out"
    );
}
