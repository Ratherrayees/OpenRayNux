//! SEC-003 F-2: `--doctor` reports the privacy it **observed**, not the privacy the
//! platform could provide.
//!
//! # The defect
//!
//! The report used to say
//!
//! ```text
//! state root privacy: owner-only (0700 directory, 0600 database) -- Unix mode bits
//! ```
//!
//! on the strength of a **compile-time capability check** — "this build has Unix mode
//! bits". That is a statement about the *platform*, printed where an operator reads a
//! statement about their *installation*.
//!
//! Reproduced against the shipped binary: a state root at `0755` and a database at
//! `0644` — both world-readable — were reported as "owner-only".
//!
//! That is a false assurance about a security property, on the surface an operator uses
//! to check one. The same shape as V-91's finding, that "every audit record claiming a
//! human approved something was a claim about a file mode".
//!
//! # What these tests pin
//!
//! * a non-compliant installation is reported as **not** owner-only, with the mode
//!   that was seen;
//! * a compliant installation is reported as owner-only;
//! * an absent installation is reported as absent;
//! * and the report never claims owner-only protection it did not observe.
//!
//! # Diagnosis stays diagnosis
//!
//! `--doctor` creates nothing and changes nothing. A report that repaired what it
//! diagnosed could not be re-read to check the repair, and a diagnostic with a side
//! effect is not a diagnostic.

use std::path::PathBuf;
use std::process::Command;

/// Runs `--doctor` and returns its stdout.
fn doctor(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_orxnud"))
        .args(args)
        .output()
        .expect("the daemon binary must run");
    assert!(
        out.status.success(),
        "--doctor must succeed: args={args:?} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A scratch installation root.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "orxnud-doctor-privacy-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// The line of the report that speaks about the state root's privacy.
fn root_privacy_line(report: &str) -> String {
    report
        .lines()
        .find(|l| l.starts_with("state root privacy:"))
        .unwrap_or_else(|| panic!("the report must have a state root privacy line: {report}"))
        .to_owned()
}

/// **A world-readable installation is not reported as owner-only.**
///
/// The reviewed case, reproduced exactly: a state root at `0755` and a database at
/// `0644`. The report must say the state root is **not** owner-only, name the mode
/// it observed, and must not claim the database is private either.
#[cfg(unix)]
#[test]
fn a_world_readable_installation_is_not_reported_as_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let root = scratch("permissive");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).expect("chmod root");
    let database = root.join("state.db");
    std::fs::write(&database, b"not really a database").expect("write");
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644)).expect("chmod db");

    let report = doctor(&["--doctor", "--state-root", root.to_str().expect("utf-8")]);

    let line = root_privacy_line(&report);
    assert!(
        line.contains("NOT owner-only"),
        "a state root at 0755 must not be reported as owner-only: {line}"
    );
    assert!(
        line.contains("0755"),
        "the report must name the mode it observed, or it is not reporting anything: {line}"
    );
    assert!(
        !line.contains("owner-only (0700"),
        "the report must not carry the old capability-based claim: {line}"
    );

    // And the same for the database, which was 0644.
    let db_line = report
        .lines()
        .find(|l| l.starts_with("database privacy:"))
        .unwrap_or_else(|| panic!("the report must have a database privacy line: {report}"));
    assert!(
        db_line.contains("NOT owner-only") && db_line.contains("0644"),
        "a database at 0644 must not be reported as owner-only: {db_line}"
    );

    // And the diagnosis changed nothing.
    assert_eq!(
        std::fs::metadata(&root)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0),
        0o755,
        "--doctor must not repair what it diagnoses: a diagnostic with a side effect cannot \
         be re-read to check the repair"
    );
    assert_eq!(
        std::fs::metadata(&database)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0),
        0o644,
        "--doctor must not repair what it diagnoses"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **A compliant installation is reported as owner-only.**
///
/// The other direction: the report must be able to say "this one is fine", or an
/// operator cannot act on it.
#[cfg(unix)]
#[test]
fn a_compliant_installation_is_reported_as_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let root = scratch("compliant");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod root");
    let database = root.join("state.db");
    std::fs::write(&database, b"not really a database").expect("write");
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).expect("chmod db");

    let report = doctor(&["--doctor", "--state-root", root.to_str().expect("utf-8")]);

    let line = root_privacy_line(&report);
    assert!(
        line.contains("owner-only") && !line.contains("NOT owner-only"),
        "a state root at 0700 must be reported as owner-only: {line}"
    );
    let db_line = report
        .lines()
        .find(|l| l.starts_with("database privacy:"))
        .unwrap_or_else(|| panic!("the report must have a database privacy line: {report}"));
    assert!(
        db_line.contains("owner-only") && !db_line.contains("NOT owner-only"),
        "a database at 0600 must be reported as owner-only: {db_line}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **An installation that does not exist is reported as absent.**
///
/// Not "owner-only" and not "not owner-only": there is nothing to be private, and
/// saying either would be a claim about a path nobody has.
#[test]
fn an_absent_installation_is_reported_as_absent() {
    let root = scratch("absent");
    let missing = root.join("not-created");
    assert!(!missing.exists(), "precondition: the root must not exist");

    let report = doctor(&["--doctor", "--state-root", missing.to_str().expect("utf-8")]);

    let line = root_privacy_line(&report);
    assert!(
        line.contains("absent"),
        "an installation that does not exist must be reported as absent: {line}"
    );
    assert!(
        !line.contains("owner-only"),
        "and it must not claim owner-only protection for a path that is not there: {line}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **The report never claims a protection it did not observe.**
///
/// The general form of the defect, asserted without depending on the platform: the
/// report must not contain the old capability-based claim anywhere.
#[test]
fn the_report_never_claims_owner_only_from_a_capability_check() {
    let root = scratch("never-claims");
    let report = doctor(&["--doctor", "--state-root", root.to_str().expect("utf-8")]);

    assert!(
        !report.contains("owner-only (0700 directory, 0600 database)"),
        "the capability-based claim must be gone from the report entirely: {report}"
    );
    assert!(
        report.contains("state root privacy:"),
        "the report must still speak about the state root's privacy: {report}"
    );
    assert!(
        report.contains("database privacy:"),
        "and about the database's: {report}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
