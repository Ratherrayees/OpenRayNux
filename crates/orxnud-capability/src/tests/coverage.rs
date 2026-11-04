//! Machine-readable TEST-001 coverage records.
//!
//! A test that returns before its assertions must say so; the gate consumes these
//! records rather than inferring success from an exit status. When the environment is
//! absent (a developer running one test) recording is a no-op.
//!
//! A record is bound to the identity nextest assigns to the test process, not to a
//! caller-supplied thread name. When recording is enabled, the complete identity is
//! `NEXTEST_BINARY_ID` plus `NEXTEST_TEST_NAME`; both are required and the producer
//! requires an exact full-identity match. A worker that enters [`scope`] inherits that
//! process identity, so it cannot rename itself into another test's identity. A thread
//! that was not entered through [`scope`] has no provenance and cannot create a record.
//!
//! Without `ORXNUD_TEST_COVERAGE`, ordinary local `cargo test` runs retain the old
//! thread-name compatibility path so the test suite still works without nextest. That
//! path never writes a record and is not provenance.

use std::cell::RefCell;
use std::io::Write;
use std::marker::PhantomData;
use std::thread::ThreadId;

/// The suite, the module prefix the harness prepends, and grouping modules that are
/// not part of the registered identity. `v46` groups the four governed-path tests but
/// is not in the checker's stable ID, so it is normalised away here.
const ALLOWED_SUITES: &[(&str, &str, &[&str])] = &[
    (
        "orxnud-capability::suites::write_text",
        "suites::write_text",
        &[],
    ),
    (
        "orxnud-capability::suites::governed_path",
        "suites::governed_path",
        &["v46"],
    ),
];

thread_local! {
    static ACTIVE_SCOPE: RefCell<Option<ProducerScope>> = const { RefCell::new(None) };
}

struct ProducerScope {
    full_test: String,
    thread: ThreadId,
}

/// The provenance a test must hold while it emits coverage records.
///
/// The guard is deliberately not `Send` or `Sync`: a worker spawned by the test cannot
/// be handed the test's scope, and a worker that has not called [`scope`] itself has no
/// provenance.
#[must_use = "the coverage scope must be held for the duration of the test"]
pub(crate) struct Scope {
    full_test: String,
    thread: ThreadId,
    _not_send: PhantomData<*const ()>,
}

impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE_SCOPE.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_ref().is_some_and(|active| {
                active.full_test == self.full_test && active.thread == self.thread
            }) {
                *slot = None;
            }
        });
    }
}

/// Enter a tracked test's producer scope.
///
/// With coverage enabled the identity comes from nextest's per-process environment:
/// `NEXTEST_BINARY_ID` and `NEXTEST_TEST_NAME`. A missing or partial pair fails closed;
/// there is no thread-name fallback while recording. Without coverage, a local
/// `cargo test` run may use the harness thread name only to keep the source-level
/// regressions runnable; [`record`] writes nothing in that mode.
pub(crate) fn scope(suite: &'static str) -> Scope {
    let Some((_, harness_prefix, grouping_modules)) = ALLOWED_SUITES
        .iter()
        .find(|(allowed, _, _)| *allowed == suite)
    else {
        panic!("coverage producer suite is not allowed: {suite:?}");
    };

    let thread = std::thread::current();
    let harness_identity = nextest_identity();
    let using_nextest = harness_identity.is_some();
    let actual = match harness_identity {
        Some(identity) => identity,
        None if coverage_recording_enabled() => panic!(
            "coverage producer requires the nextest identity: set NEXTEST_BINARY_ID and \
             NEXTEST_TEST_NAME, or unset ORXNUD_TEST_COVERAGE (suite {suite:?})"
        ),
        None => thread
            .name()
            .unwrap_or_else(|| {
                panic!("coverage producer scope has no harness test name: {suite:?}")
            })
            .to_owned(),
    };

    let mut test_path = if using_nextest {
        actual
            .strip_prefix(suite)
            .and_then(|rest| rest.strip_prefix("::"))
            .unwrap_or_else(|| {
                panic!(
                    "coverage producer scope mismatch: the harness identity is {actual:?}, \
                     not in suite {suite:?}"
                )
            })
            .to_owned()
    } else if harness_prefix.is_empty() {
        actual.to_owned()
    } else {
        actual
            .strip_prefix(*harness_prefix)
            .and_then(|rest| rest.strip_prefix("::"))
            .unwrap_or_else(|| {
                panic!(
                    "coverage producer scope mismatch: the executing test is {actual:?}, \
                     not in suite {suite:?}"
                )
            })
            .to_owned()
    };

    for grouping in *grouping_modules {
        if let Some(rest) = test_path
            .strip_prefix(grouping)
            .and_then(|rest| rest.strip_prefix("::"))
        {
            test_path = rest.to_owned();
            break;
        }
    }
    if test_path.is_empty() {
        panic!("coverage producer scope has an empty test name: {actual:?}");
    }

    let full_test = format!("{suite}::{test_path}");
    let thread_id = thread.id();
    let previous = ACTIVE_SCOPE.with(|slot| {
        slot.borrow_mut().replace(ProducerScope {
            full_test: full_test.clone(),
            thread: thread_id,
        })
    });
    assert!(
        previous.is_none(),
        "coverage producer scope is already active on this thread"
    );

    Scope {
        full_test,
        thread: thread_id,
        _not_send: PhantomData,
    }
}

/// Return nextest's full test identity, if the harness supplied one.
///
/// `NEXTEST_TEST_NAME` is only the module/test path; `NEXTEST_BINARY_ID` is the binary
/// the harness selected. The coverage ID is their exact concatenation, which differs by
/// test target: a lib target reports `orxnud-capability` while an integration target
/// reports the binary-qualified id, for example `orxnud-daemon::uncertain_outcome`.
fn nextest_identity() -> Option<String> {
    match (
        std::env::var("NEXTEST_BINARY_ID"),
        std::env::var("NEXTEST_TEST_NAME"),
    ) {
        (Ok(binary), Ok(test)) if !binary.is_empty() && !test.is_empty() => {
            Some(format!("{binary}::{test}"))
        }
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => None,
        (binary, test) => panic!(
            "coverage producer identity is incomplete or invalid: \
             NEXTEST_BINARY_ID={binary:?}, NEXTEST_TEST_NAME={test:?}"
        ),
    }
}

fn coverage_recording_enabled() -> bool {
    std::env::var_os("ORXNUD_TEST_COVERAGE").is_some()
}

pub(crate) fn verified(test: &str) {
    record("verified", test, None);
}

pub(crate) fn reduced(test: &str, reason: &str) {
    record("reduced", test, Some(reason));
}

fn record(outcome: &str, test: &str, reason: Option<&str>) {
    validate_producer(test);
    let Some(path) = std::env::var_os("ORXNUD_TEST_COVERAGE") else {
        return;
    };
    let run = std::env::var("ORXNUD_COVERAGE_RUN").unwrap_or_else(|_| "missing-run".to_owned());
    let reason = reason
        .map(|r| format!(",\"reason\":\"{}\"", escape(r)))
        .unwrap_or_default();
    let line = format!(
        "{{\"run\":\"{}\",\"test\":\"{}\",\"outcome\":\"{}\"{reason}}}\n",
        escape(&run),
        escape(test),
        outcome
    );
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap_or_else(|e| {
            panic!(
                "cannot open test coverage artifact {}: {e}",
                path.to_string_lossy()
            )
        });
    file.write_all(line.as_bytes()).unwrap_or_else(|e| {
        panic!(
            "cannot append test coverage artifact {}: {e}",
            path.to_string_lossy()
        )
    });
}

/// Split a claimed ID at the registered suite boundary, preserving any module path in
/// the test component. A nested module is still part of the identity; it is not a new
/// suite.
fn claimed_test(claimed: &str) -> (&'static str, &str) {
    for (suite, _, _) in ALLOWED_SUITES {
        if let Some(test) = claimed
            .strip_prefix(suite)
            .and_then(|rest| rest.strip_prefix("::"))
            .filter(|test| !test.is_empty())
        {
            return (suite, test);
        }
    }

    let Some((suite, test)) = claimed.rsplit_once("::") else {
        panic!("coverage producer identity is malformed: {claimed:?}");
    };
    if suite.is_empty() || test.is_empty() {
        panic!("coverage producer identity is malformed: {claimed:?}");
    }
    panic!("coverage producer suite is not allowed: {suite:?}");
}

/// Refuse a record whose claimed full test identity is not the scope's identity.
///
/// The claimed suite and test are checked before the scope is consulted, so an
/// out-of-binary suite and a malformed ID fail with their own diagnostics. A thread
/// without a scope fails closed rather than falling back to its name.
fn validate_producer(claimed: &str) {
    let _ = claimed_test(claimed);

    let actual = ACTIVE_SCOPE.with(|slot| slot.borrow().as_ref().map(|s| s.full_test.clone()));
    let Some(actual) = actual else {
        panic!(
            "coverage producer has no test provenance: the record claims {claimed:?}; \
             the test did not enter a producer scope"
        );
    };
    if actual != claimed {
        panic!(
            "coverage producer identity mismatch: the executing test is {actual:?}, but \
             the record claims {claimed:?}"
        );
    }
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
