//! Test support: locating the hostile helper and running it under the sandbox.

#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;

use orxnud_platform_sandbox::SandboxRunner;
use orxnud_platform_sandbox::contract::{ExecutionResult, SandboxSpec};
use orxnud_platform_sandbox::linux::BwrapRunner;

/// Why a test failed, in words rather than a bare assert.
///
/// An isolation test that fails with "assertion failed" costs an hour of debugging;
/// one that says "the helper reached the network" costs a minute.
pub struct Failure;

impl Failure {
    /// A reminder for whoever debugs a red isolation test.
    #[must_use]
    pub fn explain() -> &'static str {
        "isolation failures report the helper's own PASS/FAIL line on stdout"
    }
}

/// The hostile helper binary: this test binary, re-executed.
///
/// Cargo places every integration test binary in `target/<profile>/deps/`, so the
/// helper sits next to this executable.
#[must_use]
pub fn helper_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let name = exe
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_owned();
    assert!(
        name.starts_with("isolation"),
        "this helper only works from the isolation test binary, got {name}"
    );
    // Cargo gives each test binary a *different* metadata hash, so deriving the
    // helper's filename from this one does not work. Scan the directory instead.
    let dir = exe.parent().expect("deps directory");
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read deps directory")
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("hostile_helper-") && n != name)
        })
        .collect();
    found.sort();
    assert!(
        !found.is_empty(),
        "no hostile_helper-* binary in {}; run `cargo test --no-run` first",
        dir.display()
    );
    found.remove(0)
}

/// The harness flags that re-execute one ignored test as a plain program.
#[must_use]
pub fn harness_argv(program: &str, args: &[&str]) -> Vec<String> {
    let mut v = vec![
        "--exact".to_owned(),
        "hostile_helper_entry_point".to_owned(),
        "--ignored".to_owned(),
        "--nocapture".to_owned(),
        "--".to_owned(),
        program.to_owned(),
    ];
    v.extend(args.iter().map(|s| (*s).to_owned()));
    v
}

/// Runs the helper under the sandbox.
///
/// The deadline is raised to a floor so a test that did not set one still terminates,
/// but a test that *did* set a short deadline keeps it.
pub fn run_helper(spec: &SandboxSpec) -> ExecutionResult {
    run_helper_with(spec, None)
}

/// Runs the helper, optionally overriding the deadline.
///
/// # Why the override is explicit
///
/// An earlier version raised any deadline below 20 s to a 20 s floor, "for safety".
/// That silently overrode a test that deliberately asked for 1.5 s, so the timeout test
/// took 20 s and then failed while looking like a hang bug in the runner. A floor must
/// never be applied to an explicit request.
pub fn run_helper_with(spec: &SandboxSpec, deadline: Option<Duration>) -> ExecutionResult {
    let mut spec = with_helper_visible(spec);
    if let Some(d) = deadline {
        spec.limits.wall_clock = d;
    }
    BwrapRunner::new()
        .run(&spec)
        .expect("the runner must not fail closed for a spec that demands nothing unavailable")
}

/// Grants read access to the helper binary itself.
///
/// Without this the sandbox cannot exec the program at all: the helper lives in the
/// build output, which nothing else in the spec would expose. A real capability would
/// be installed somewhere the sandbox is expected to see.
pub fn with_helper_visible(spec: &SandboxSpec) -> SandboxSpec {
    let helper = helper_path();
    let dir = helper.parent().expect("helper directory").to_path_buf();
    let mut spec = spec.clone();
    if !spec.fs.read_only.contains(&dir) {
        spec = spec.grant_ro(dir);
    }
    spec
}

/// Runs the helper with synthetic markers in the *supervisor's* environment.
///
/// `std::env::set_var` is `unsafe` on this edition and the crate forbids unsafe, so
/// the markers are placed by re-executing through a shell that exports them. That is
/// also the more honest test: the markers really are in the parent environment of the
/// process that spawns `bwrap`, which is exactly the leak being tested for.
pub fn run_with_parent_env(spec: &SandboxSpec, markers: &[&str]) -> ExecutionResult {
    let mut exported = String::new();
    for m in markers {
        exported.push_str(m);
        exported.push(' ');
    }

    // Exec **bwrap** under the poisoned environment, not the helper: the property
    // under test is that the sandbox strips the environment, so the process holding
    // the markers must be `bwrap`'s parent.
    let spec = with_helper_visible(spec);
    let argv = BwrapRunner::argv_for(&spec).expect("argv");
    let script = format!(
        "{} exec /usr/bin/bwrap {}",
        exported.trim(),
        argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
    );

    let raw = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .expect("spawn poisoned-env bwrap");

    let text = String::from_utf8_lossy(&raw.stdout);
    ExecutionResult {
        status: orxnud_platform_sandbox::contract::ExecutionStatus::Exited(
            raw.status.code().unwrap_or(-1),
        ),
        stdout: orxnud_platform_sandbox::contract::CapturedStream {
            bytes: text.as_bytes().to_vec(),
            truncated: false,
            dropped: 0,
        },
        stderr: orxnud_platform_sandbox::contract::CapturedStream {
            bytes: raw.stderr.clone(),
            truncated: false,
            dropped: 0,
        },
        elapsed: Duration::ZERO,
        unproven: Vec::new(),
    }
}

/// Single-quotes a path for `/bin/sh`.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The extra-descriptor count for the helper run *without* a sandbox.
pub fn fd_count_unsandboxed() -> usize {
    let out = std::process::Command::new(helper_path())
        .args([
            "--exact",
            "hostile_helper_entry_point",
            "--ignored",
            "--nocapture",
        ])
        .env("ORXNUD_HOSTILE_HELPER", "fd-scan")
        .output()
        .expect("spawn helper");
    extras_from(&String::from_utf8_lossy(&out.stdout))
}

/// Extracts `extras=[..]` from the helper's report.
pub fn extras_from(stdout: &str) -> usize {
    stdout
        .split("extras=[")
        .nth(1)
        .and_then(|s| s.split(']').next())
        .map(|s| s.split(',').filter(|part| !part.trim().is_empty()).count())
        .unwrap_or(0)
}
