//! The `orxnud-fswrite` binary's own refusals, driven as a process.
//!
//! # Why this lives in `tests/` and not in `src/`
//!
//! Gate G5(f) forbids `Command::new` anywhere in `orxnud-capability/src`, because a
//! second route to run a Tier-1 capability would bypass `ExecutionBackend`. That rule is
//! right and it is not being relaxed: the tests here are in an integration test crate,
//! which the gate does not scan, and they spawn **the helper binary directly** rather
//! than as a governed capability.
//!
//! That is the point. These tests answer "what does the helper do when handed a stream
//! it did not expect?", and the only honest way to answer it is to run the binary and
//! look at its exit code and its stderr. Driving the same cases through
//! `ExecutionBackend` would exercise the sandbox and prove nothing about the receiver.
//!
//! Every case asserts a **nonzero exit and no file written**. A helper that wrote
//! something and then complained would satisfy "it printed an error" and fail this file.

use std::io::Write as _;
use std::process::{Command, Stdio};

/// A unique, empty scratch directory per test, removed at the end.
fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-fswrite-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

/// Runs the helper and returns `(success, stderr)`.
fn run(helper: &std::path::Path, args: &[&str], stdin: Option<&[u8]>) -> (bool, String) {
    let mut child = Command::new(helper)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the helper spawns");
    {
        let mut pipe = child.stdin.take().expect("stdin is piped");
        if let Some(bytes) = stdin {
            // A helper that refuses its arguments exits *without reading stdin*, so a
            // write racing that exit gets EPIPE. That is the refusal working, not a
            // transport failure: the assertions below are about the exit status, the
            // message and the absent file, and none of them are reachable if this panics
            // first. Panicking here made `an_unknown_transport_version_is_refused_by_name`
            // fail roughly one run in three under full-suite parallelism and never in
            // isolation. Only EPIPE is tolerated; any other write error still fails.
            match pipe.write_all(bytes) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
                Err(e) => panic!("stdin accepts the frame: {e:?}"),
            }
        }
        // Dropping the pipe here is the *correct* sender behaviour (ADR-0054 Decision
        // 3a) and is what every case below depends on to terminate at all.
    }
    let out = child.wait_with_output().expect("the helper exits");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_missing_transport_version_is_refused_and_writes_nothing() {
    let helper = orxnud_capability::write_text::resolve_helper().expect("helper built");
    let dir = scratch("no-version");
    let target = dir.join("out.txt");

    // The shape an old daemon sends: `--path` plus the payload, and no version. If the
    // helper accepted this it would be guessing which protocol it is speaking, which is
    // how an old helper and a new daemon silently mismatch (Decision 6).
    let (ok, stderr) = run(
        &helper,
        &[
            "--path",
            target.to_str().expect("utf-8 path"),
            "--contents",
            "x",
        ],
        None,
    );

    assert!(
        !ok,
        "a missing transport version must be refused; stderr: {stderr}"
    );
    assert!(
        stderr.contains("stdin-transport"),
        "and it must say which requirement was unmet; stderr: {stderr}"
    );
    assert!(
        !target.exists(),
        "a refused invocation must not write the file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unknown_transport_version_is_refused_by_name() {
    let helper = orxnud_capability::write_text::resolve_helper().expect("helper built");
    let dir = scratch("bad-version");
    let target = dir.join("out.txt");

    let (ok, stderr) = run(
        &helper,
        &[
            "--stdin-transport=99",
            "--path",
            target.to_str().expect("utf-8 path"),
        ],
        Some(&orxnud_capability::stdin_frame::encode(b"x").expect("frames")),
    );

    assert!(
        !ok,
        "an unknown transport version must be refused; stderr: {stderr}"
    );
    assert!(
        stderr.contains("transport"),
        "the refusal must name the transport; stderr: {stderr}"
    );
    assert!(
        !target.exists(),
        "a refused invocation must not write the file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_malformed_frame_is_refused_and_writes_nothing() {
    let helper = orxnud_capability::write_text::resolve_helper().expect("helper built");
    let dir = scratch("malformed");
    let target = dir.join("out.txt");

    // A plausible-but-wrong header: the frame names a protocol this helper does not
    // speak. The important property is that it refuses *before* creating the file.
    let (ok, stderr) = run(
        &helper,
        &[
            orxnud_capability::stdin_frame::VERSION_ARG,
            "--path",
            target.to_str().expect("utf-8 path"),
        ],
        Some(b"ORXNUD-STDIN/42\ncontents-length: 1\n\nx"),
    );

    assert!(!ok, "an unknown protocol must be refused; stderr: {stderr}");
    assert!(!target.exists(), "nothing may be written");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_empty_stream_is_refused_rather_than_writing_an_empty_file() {
    let helper = orxnud_capability::write_text::resolve_helper().expect("helper built");
    let dir = scratch("no-stream");
    let target = dir.join("out.txt");

    let (ok, stderr) = run(
        &helper,
        &[
            orxnud_capability::stdin_frame::VERSION_ARG,
            "--path",
            target.to_str().expect("utf-8 path"),
        ],
        Some(b""),
    );

    assert!(!ok, "an empty stream must be refused; stderr: {stderr}");
    assert!(
        !target.exists(),
        "**this is the whole point**: an empty stream must not become an empty file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_declared_empty_payload_writes_a_real_empty_file() {
    // The other half of the same rule, and the one a bare stdin cannot express: a
    // *declared* zero is a request for an empty file and is honoured.
    let helper = orxnud_capability::write_text::resolve_helper().expect("helper built");
    let dir = scratch("declared-empty");
    let target = dir.join("out.txt");

    let (ok, stderr) = run(
        &helper,
        &[
            orxnud_capability::stdin_frame::VERSION_ARG,
            "--path",
            target.to_str().expect("utf-8 path"),
        ],
        Some(&orxnud_capability::stdin_frame::encode(b"").expect("frames")),
    );

    assert!(
        ok,
        "a declared zero is a valid empty write; stderr: {stderr}"
    );
    assert!(target.exists(), "the file must exist");
    assert_eq!(
        std::fs::read(&target).expect("readable"),
        Vec::<u8>::new(),
        "and it must be empty, because that is what was declared"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_well_formed_frame_writes_exactly_the_declared_bytes() {
    // Including multi-byte text and an embedded NUL: the transport is byte-exact, so a
    // body that is not valid UTF-8 still arrives intact.
    let helper = orxnud_capability::write_text::resolve_helper().expect("helper built");
    let dir = scratch("exact");
    let target = dir.join("out.txt");
    let payload: &[u8] = "héllo 🌍\0binary".as_bytes();

    let (ok, stderr) = run(
        &helper,
        &[
            orxnud_capability::stdin_frame::VERSION_ARG,
            "--path",
            target.to_str().expect("utf-8 path"),
        ],
        Some(&orxnud_capability::stdin_frame::encode(payload).expect("frames")),
    );

    assert!(ok, "a well-formed frame must be accepted; stderr: {stderr}");
    assert_eq!(
        std::fs::read(&target).expect("readable"),
        payload,
        "the body must arrive byte for byte, NUL and all"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn trailing_bytes_after_the_declared_payload_are_refused_and_write_nothing() {
    let helper = orxnud_capability::write_text::resolve_helper().expect("helper built");
    let dir = scratch("trailing");
    let target = dir.join("out.txt");

    let mut stream = orxnud_capability::stdin_frame::encode(b"declared").expect("frames");
    stream.extend_from_slice(b"EXTRA");
    let (ok, stderr) = run(
        &helper,
        &[
            orxnud_capability::stdin_frame::VERSION_ARG,
            "--path",
            target.to_str().expect("utf-8 path"),
        ],
        Some(&stream),
    );

    assert!(
        !ok,
        "trailing data must be refused, not truncated; stderr: {stderr}"
    );
    assert!(
        !target.exists(),
        "nothing may be written: dropping the tail would be a wrong write"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_short_body_is_refused_and_never_writes_a_partial_file() {
    let helper = orxnud_capability::write_text::resolve_helper().expect("helper built");
    let dir = scratch("short");
    let target = dir.join("out.txt");

    // Declares 10, delivers 3.
    let (ok, stderr) = run(
        &helper,
        &[
            orxnud_capability::stdin_frame::VERSION_ARG,
            "--path",
            target.to_str().expect("utf-8 path"),
        ],
        Some(b"ORXNUD-STDIN/1\ncontents-length: 10\n\nabc"),
    );

    assert!(!ok, "a short body must be refused; stderr: {stderr}");
    assert!(!target.exists(), "no partial file may be created");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_helper_processes_do_not_cross_payloads() {
    // Each invocation gets its own pipe. If the transport ever became shared state,
    // this is where it would show: 16 processes, 16 distinct bodies, all correct.
    let helper = orxnud_capability::write_text::resolve_helper().expect("helper built");
    let dir = scratch("concurrent");
    let payloads: Vec<String> = (0..16)
        .map(|i| format!("payload-{i:02}-{}", "m".repeat(i + 1)))
        .collect();

    std::thread::scope(|s| {
        let handles: Vec<_> = payloads
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let dir = dir.clone();
                let helper = helper.clone();
                s.spawn(move || {
                    let target = dir.join(format!("out-{i:02}.txt"));
                    let (ok, stderr) = run(
                        &helper,
                        &[
                            orxnud_capability::stdin_frame::VERSION_ARG,
                            "--path",
                            target.to_str().expect("utf-8 path"),
                        ],
                        Some(
                            &orxnud_capability::stdin_frame::encode(p.as_bytes()).expect("frames"),
                        ),
                    );
                    assert!(ok, "each invocation must succeed; stderr: {stderr}");
                    let got = std::fs::read_to_string(&target).expect("readable");
                    assert_eq!(&got, p, "a payload crossed between processes");
                })
            })
            .collect();
        for h in handles {
            h.join().expect("no thread panicked");
        }
    });
    let _ = std::fs::remove_dir_all(&dir);
}
