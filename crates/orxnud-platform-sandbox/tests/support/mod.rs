//! Test support: locating the hostile helper and running it under the sandbox.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
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

    // Why the executable check is load-bearing: cargo writes *several* files per test
    // binary into `deps/` under that binary's own hash -- the executable, a `.d`
    // dep-info file, and for a crate with a lib target an `.rmeta`. A name-prefix
    // filter matches all of them, so the "binary" this function returned could be a
    // 369-byte text file. bwrap then refuses to execute it and every test that needs
    // the helper fails with no output at all:
    //
    //     bwrap: execvp .../deps/hostile_helper-1c609b67bc4a3424.d: Permission denied
    //
    // Which reads like a sandbox failure and is not one. Only a file the kernel would
    // actually execute can be the helper, so that -- not its name -- is the filter.
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read deps directory")
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("hostile_helper-") && n != name)
        })
        .filter(|p| is_executable(p))
        .collect();
    assert!(
        !candidates.is_empty(),
        "no hostile_helper-* executable in {}; run `cargo test --no-run` first",
        dir.display()
    );

    // Newest first, rather than the lexicographically first *name*. More than one
    // helper can be present after a rebuild, and the stale ones are the earlier build
    // of the same source; picking by name has no relationship to which binary is
    // current, so it could silently test old behaviour. Modification time is what
    // distinguishes them, and sorting by name as a tie-break keeps the choice
    // reproducible when two files share a timestamp.
    candidates.sort_by(|a, b| modified(b).cmp(&modified(a)).then_with(|| a.cmp(b)));
    candidates.remove(0)
}

/// Whether `path` is a regular file this process may execute.
///
/// The executable bit, because that is precisely the property `bwrap` needs and the
/// one a name filter was approximating badly. Cargo's sidecar files are readable
/// text, which is exactly why they slipped through.
fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|meta| {
        if !meta.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            meta.permissions().mode() & 0o111 != 0
        }
        // Not a Unix target, so there is no mode bit to read and
        // `PermissionsExt` does not exist. The property is still decidable: what
        // separates the helper from cargo's sidecars here is the extension, since the
        // binary is `hostile_helper-<hash>.exe` and the sidecars are `.d` and
        // `.rmeta`.
        //
        // This module is Linux evidence either way -- it locates a `bwrap` helper and
        // runs it under `/bin/sh` -- so this arm only has to be *correct enough to
        // compile*, which is what the MSVC `--all-targets` check in `windows-check`
        // requires. The `windows-portability` lane runs `--lib`, never this
        // integration test, so nothing asserts against this answer at runtime.
        #[cfg(not(unix))]
        {
            let _ = meta;
            path.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
        }
    })
}

/// When `path` was last modified, or the epoch if that cannot be read.
///
/// The epoch keeps an unreadable candidate at the bottom of the ordering instead of
/// panicking a test over a file's timestamp.
fn modified(path: &Path) -> std::time::SystemTime {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .unwrap_or(std::time::UNIX_EPOCH)
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
