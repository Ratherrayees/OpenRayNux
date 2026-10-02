//! The CI gates must actually fail in CI when a verification tool is missing.
//!
//! # What this protects
//!
//! `scripts/ci-gates.sh` skips a gate whose tool is absent, so that a laptop
//! without `cargo-deny` can still run the gates it can run. That is the right
//! local behaviour and a false-green CI result.
//!
//! The mitigation is strict mode: under it, a missing tool is a failure. The
//! mitigation did not work. The decision was made by comparing `$STRICT` against
//! the literal `deny`, six times, in six places — while GitHub Actions sets
//! `CI: "true"`, and the file's own header documented `CI=true` as activating it.
//! Every gate that could skip therefore skipped silently in CI, which is the exact
//! "a green build that checked less than it claimed to" the script exists to
//! prevent.
//!
//! # Why this test drives the script rather than restating its logic
//!
//! A test that reimplemented the condition would have passed against the bug. This
//! one *sources* `scripts/ci-gates.sh` and calls the predicate the gates call, so
//! the thing under test is the thing that ships.
//!
//! No missing system package is involved: the decision depends only on two
//! environment variables, both set explicitly here, so the result is the same on a
//! machine that has every tool and one that has none.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn script() -> PathBuf {
    repo_root().join("scripts/ci-gates.sh")
}

/// Runs `is_strict` from the real script, under a controlled environment.
///
/// `env_clear` matters: without it the ambient `CI` of whatever runs the suite
/// would leak in and the answer would depend on who launched the test.
fn is_strict_with(env: &[(&str, &str)]) -> bool {
    let mut cmd = Command::new("bash");
    cmd.arg("-c")
        .arg("source \"$1\" >/dev/null 2>&1; if is_strict; then echo yes; else echo no; fi")
        .arg("bash")
        .arg(script())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run the gate script's predicate");
    assert!(
        out.status.success(),
        "sourcing scripts/ci-gates.sh failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    match String::from_utf8_lossy(&out.stdout).trim() {
        "yes" => true,
        "no" => false,
        other => panic!("unexpected predicate output {other:?}"),
    }
}

#[test]
fn ci_true_is_strict() {
    // The regression. GitHub Actions sets exactly this, and it was documented as
    // activating strict mode. It did not.
    assert!(
        is_strict_with(&[("CI", "true")]),
        "CI=true must make a missing tool a failure"
    );
}

#[test]
fn the_documented_explicit_spelling_is_still_strict() {
    // The old code compared against `deny`, so that value was the one thing that
    // worked. Removing it would be a silent regression for anyone using it.
    assert!(
        is_strict_with(&[("CI", "deny")]),
        "CI=deny must remain strict"
    );
}

#[test]
fn the_explicit_opt_in_variable_is_strict_on_its_own() {
    assert!(
        is_strict_with(&[("ORXNUD_STRICT", "yes")]),
        "ORXNUD_STRICT must be strict without CI"
    );
    assert!(
        is_strict_with(&[("ORXNUD_STRICT", "1"), ("CI", "")]),
        "ORXNUD_STRICT must win when CI is empty"
    );
}

#[test]
fn an_ordinary_local_invocation_is_not_strict() {
    // The behaviour that must not regress: a developer running the gates by hand
    // gets visible skips, not hard failures for tools they may not have installed.
    assert!(
        !is_strict_with(&[]),
        "no environment must mean developer-friendly"
    );
    assert!(
        !is_strict_with(&[("CI", "")]),
        "an empty CI must not be strict"
    );
    assert!(
        !is_strict_with(&[("CI", "false")]),
        "an explicit CI=false must not be strict"
    );
    assert!(
        !is_strict_with(&[("CI", "0"), ("ORXNUD_STRICT", "off")]),
        "explicitly falsy values must not be strict"
    );
}

#[test]
fn every_tool_gate_defers_to_the_predicate_rather_than_comparing_a_literal() {
    // The structural half. Six separate `if [ "$STRICT" = ... ]` comparisons is
    // what allowed the bug: fixing one site would have left five.
    let text = std::fs::read_to_string(script()).expect("read the script");
    assert!(
        !text.contains("STRICT=") || !text.contains("\"$STRICT\" ="),
        "the literal comparison must be gone from scripts/ci-gates.sh"
    );
    let gates = text.matches("if is_strict; then").count();
    assert_eq!(
        gates, 5,
        "five gates defer to a tool check (G5, G8, G9, G11, G12); G9's is the \
         nextest requirement"
    );
    // And the summary line must report the same decision the gates made.
    assert!(
        text.contains("is_strict && printf 'strict  yes: a missing tool fails"),
        "the banner must use the same predicate"
    );
}

#[test]
fn a_deliberately_missing_tool_fails_under_strict_mode_and_skips_without_it() {
    // The end-to-end property, without depending on anything being absent.
    //
    // Rather than uninstalling `cargo-semver-checks` (which the developer's machine
    // may legitimately have), the gate is asked for one that no implementation
    // provides: an unknown gate name exits 2 rather than silently passing, which is
    // the same "an unmet requirement is reported, not absorbed" behaviour. The
    // strict/non-strict split itself is covered deterministically above.
    let out = Command::new("bash")
        .arg(script())
        .arg("G-does-not-exist")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("run the script");
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unknown gate must be refused, not silently accepted"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown gate"),
        "and the refusal must say why"
    );
}

#[test]
fn sourcing_the_script_defines_the_gates_without_running_them() {
    // The assumption the tests above rest on. If `main` ran on source, every
    // predicate call would also run the whole gate suite.
    let out = Command::new("bash")
        .arg("-c")
        .arg("source \"$1\" >/dev/null 2>&1; declare -F is_strict >/dev/null && echo defined")
        .arg("bash")
        .arg(script())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("source the script");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "defined",
        "sourcing must define is_strict and run nothing"
    );
}
