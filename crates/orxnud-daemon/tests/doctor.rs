//! `orxnud --doctor` reports the state root it was asked about, and only what exists.
//!
//! # Why a binary-level test
//!
//! Because the bugs were in argument handling and output formatting, and neither is
//! reachable from the library: `--doctor` was a separate `Action` variant that carried
//! no root, so the value parsed from `--state-root` was dropped on the floor, and the
//! report printed the *default* root's paths. A library test calling `doctor(&paths)`
//! directly would have passed on the broken code, because the bug was in what reached
//! `doctor`, not in what it did.
//!
//! Two defects are pinned here:
//!
//! * `--state-root` was accepted, validated, and then ignored — and only when it
//!   appeared *before* `--doctor`, because the flag returned from inside the argument
//!   loop. An operator auditing one state root on a host with several was reading a
//!   confident diagnosis of a different installation.
//! * The report listed five paths with no indication of which existed. Three of the
//!   five are never created by anything: there is no `audit.log` (the journal is a
//!   table inside `state.db`), no `daemon.lock` (`InstanceLock` is an in-memory record
//!   and the endpoint is what enforces one instance), and no `daemon.log` (logs go to
//!   stderr).

use std::path::Path;
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

/// A path no installation uses, so a report naming it can only have come from the flag.
fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("orxnud-doctor-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// `--state-root` is honoured, in either argument position.
///
/// The position case is the one that makes this a real regression: `--doctor` returned
/// from inside the parse loop, so `--state-root` after it was never even read, and before
/// it was read and then discarded because the `Action::Doctor` variant had nowhere to put
/// it. A silent no-op that still prints a plausible report is worse than a rejection.
#[test]
fn doctor_reports_the_state_root_it_was_given_in_either_position() {
    let root = scratch("alt");

    let after = doctor(&["--doctor", "--state-root", root.to_str().expect("utf-8")]);
    assert!(
        after.contains(root.to_str().expect("utf-8")),
        "--state-root after --doctor must be honoured; got:\n{after}"
    );

    let before = doctor(&["--state-root", root.to_str().expect("utf-8"), "--doctor"]);
    assert!(
        before.contains(root.to_str().expect("utf-8")),
        "--state-root before --doctor must be honoured; got:\n{before}"
    );

    let equals = doctor(&[
        &format!("--state-root={}", root.to_str().expect("utf-8")),
        "--doctor",
    ]);
    assert!(
        equals.contains(root.to_str().expect("utf-8")),
        "--state-root=<DIR> must be honoured; got:\n{equals}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The report does not mention the default root when another one was asked for.
///
/// The stronger form of the test above. Asserting only that the requested path appears
/// would pass even if the report listed *both* roots, which is what an operator would
/// read as ambiguous and have to guess about.
#[test]
fn doctor_does_not_also_report_the_default_root() {
    let root = scratch("notdefault");
    let out = doctor(&["--doctor", "--state-root", root.to_str().expect("utf-8")]);
    let default = orxnud_platform_ipc::default_state_root();
    assert!(
        !out.contains(default.to_str().expect("utf-8")),
        "the default root must not appear when another was requested; got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Without the flag, the default root is reported.
#[test]
fn doctor_without_a_state_root_reports_the_default() {
    let out = doctor(&["--doctor"]);
    let default = orxnud_platform_ipc::default_state_root();
    assert!(
        out.contains(default.to_str().expect("utf-8")),
        "no flag must mean the default root; got:\n{out}"
    );
}

/// Output stays line-separated.
///
/// `HostCapability::report` returned no trailing newline and `doctor` printed it with
/// `print!`, so the sandbox verdict and the next line ran together:
/// `tier1_executable: yesdurable security state:`. Trivially fixable, and it made the
/// whole report hard to read past that point.
#[test]
fn doctor_output_stays_line_separated() {
    let root = scratch("lines");
    let out = doctor(&["--doctor", "--state-root", root.to_str().expect("utf-8")]);

    for line in out.lines() {
        assert!(
            line.len() < 200,
            "a report line this long suggests two fields ran together: {line}"
        );
        assert!(
            !line.contains("yesdurable") && !line.contains("nonestate"),
            "two fields ran together: {line}"
        );
    }
    // The verdict that was previously glued to its neighbour, on its own line.
    let verdict = out
        .lines()
        .find(|l| l.starts_with("tier1_executable:"))
        .unwrap_or_else(|| panic!("no tier1 verdict line in:\n{out}"));
    assert!(
        verdict.trim_end().ends_with("yes") || verdict.contains("(no"),
        "the verdict line must carry only the verdict: {verdict}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The report names only artefacts that exist or are part of the contract.
#[test]
fn doctor_names_only_real_artifacts() {
    let root = scratch("artifacts");
    let out = doctor(&["--doctor", "--state-root", root.to_str().expect("utf-8")]);

    // Real: the database file and the endpoint are both part of the daemon's contract.
    assert!(
        out.contains("state.db"),
        "the database must be reported: {out}"
    );
    assert!(
        out.contains("orxnud.sock"),
        "the endpoint must be reported: {out}"
    );

    // Not real. Each is named only to say plainly that it is *not* created, so an
    // operator does not go looking for a file the daemon has never written.
    assert!(
        out.contains("there is no separate audit.log file"),
        "audit storage must be described truthfully: {out}"
    );
    assert!(
        out.contains("no daemon.lock is created"),
        "the single-instance mechanism must be described truthfully: {out}"
    );
    assert!(
        out.contains("no daemon.log is created"),
        "log destination must be described truthfully: {out}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Presence is reported, so "this file exists" is distinguishable from "this is a name
/// this daemon has always had".
#[test]
fn doctor_says_whether_each_path_exists() {
    let root = scratch("presence");
    let out = doctor(&["--doctor", "--state-root", root.to_str().expect("utf-8")]);

    // The scratch root exists but holds no daemon state, so everything in it is absent.
    assert!(
        out.contains("absent"),
        "an unused root must report its artefacts as absent: {out}"
    );
    assert!(
        Path::new(&root).exists(),
        "the scratch root itself must exist for this to mean anything"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// `--doctor` creates nothing.
///
/// The banner promises this, and it matters: a diagnosis that materialises the paths it
/// diagnoses turns a read-only inspection into a side effect on the user's machine.
#[test]
fn doctor_creates_no_paths() {
    let root = scratch("readonly");
    let before: Vec<_> = std::fs::read_dir(&root)
        .expect("readable")
        .filter_map(Result::ok)
        .collect();
    assert!(before.is_empty(), "the scratch root must start empty");

    let _ = doctor(&["--doctor", "--state-root", root.to_str().expect("utf-8")]);

    let after: Vec<_> = std::fs::read_dir(&root)
        .expect("readable")
        .filter_map(Result::ok)
        .collect();
    assert!(
        after.is_empty(),
        "--doctor must not create anything; found {after:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
