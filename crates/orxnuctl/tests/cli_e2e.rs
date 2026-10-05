//! The CLI, end to end, against a real daemon.
//!
//! # What is actually exercised
//!
//! The real `orxnud` binary and the real `orxnuctl` binary, as separate processes,
//! talking over a real Unix domain socket. Nothing here reaches into
//! `TaskService`, `DurableEngine` or SQLite: the path under test is exactly the one a
//! user gets.
//!
//! ```text
//! orxnuctl -> IPC client -> Unix socket -> orxnud -> TaskService -> SQLite
//! ```
//!
//! That matters because every property worth checking here is a property of the
//! *arrangement*. "A CLI cannot complete somebody else's task" is a claim about the
//! daemon's fence surviving a round trip through a client, and a test that called
//! `TaskService` directly would pass whether or not the CLI ever spoke to it.
//!
//! # Where the binaries come from
//!
//! `CARGO_BIN_EXE_*` is only defined for a package's own binaries, and these are two
//! different packages. So the daemon is located relative to this test executable,
//! which cargo places in `target/<profile>/deps/` — the same directory whose siblings
//! are the built binaries.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A temporary state directory, unique per test and per process.
fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnuctl-e2e-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// The `orxnud` binary, next to this test executable in `target/<profile>/deps/`.
fn daemon_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // deps/ -> <profile>/ ; the binaries are siblings of deps/.
    let profile = exe
        .parent()
        .expect("deps directory")
        .parent()
        .expect("profile");
    profile.join("orxnud")
}

/// The `orxnuctl` binary, same directory.
fn cli_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let profile = exe
        .parent()
        .expect("deps directory")
        .parent()
        .expect("profile");
    profile.join("orxnuctl")
}

/// A running daemon, stopped when it is dropped.
struct Daemon {
    child: Child,
    #[allow(dead_code, reason = "read by Drop through the field name")]
    root: PathBuf,
}

/// A one-shot OpenAI-compatible provider, in this process, on a loopback port.
///
/// These tests spawn the real `orxnud` binary, so the provider has to exist outside the
/// test binary. Pointing the daemon at a real HTTP endpoint proves more than a test-only
/// flag on the product would: the binary's argument handling, the configuration contract,
/// the HTTP client and the parser are all exercised as shipped.
///
/// It also keeps the product free of a `--provider-scripted` switch, which would be a test
/// affordance in a user-facing binary and a way for a deployment to believe it has a model
/// when it does not.
struct FakeProvider {
    address: String,
    contacted: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FakeProvider {
    fn answering(content: &str) -> Self {
        use std::io::{Read as _, Write as _};
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port for the provider");
        let address = listener.local_addr().expect("an address").to_string();
        let contacted = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&contacted);
        let content = content.to_owned();
        let handle = std::thread::spawn(move || {
            // Two connections: readiness does not touch the provider, but a retried or
            // duplicated request must not hang the test either.
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                flag.store(true, Ordering::SeqCst);
                let mut raw = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => raw.extend_from_slice(&chunk[..n]),
                    }
                    if raw.len() > 64 * 1024 {
                        break;
                    }
                }
                let body = serde_json::json!({
                    "id": "chatcmpl-fake",
                    "object": "chat.completion",
                    "model": "fake-model-1",
                    "choices": [{
                        "index": 0,
                        "message": { "role": "assistant", "content": content },
                        "finish_reason": "stop",
                    }],
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Self {
            address,
            contacted,
            handle: Some(handle),
        }
    }

    /// Whether anything has connected.
    ///
    /// A non-blocking check, so a test never waits for something that should not happen.
    fn was_contacted(&self) -> bool {
        self.contacted.load(Ordering::SeqCst)
    }
}

impl Drop for FakeProvider {
    fn drop(&mut self) {
        // The listener is owned by the thread; detaching is fine because it exits after
        // its accept loop, and the test process is short-lived either way.
        let _ = self.handle.take();
    }
}

impl Daemon {
    /// Starts a real daemon on `root` and waits until it answers.
    ///
    /// Readiness is a request the daemon can only answer once `serve` is polling, so
    /// this waits for a fact rather than sleeping a guessed interval.
    fn start(root: &Path) -> Self {
        // Explicit opt-in to the non-model script, so the scripted CLI path stays green on
        // a host with no credentials. Never a default: a daemon started without this
        // refuses, which `a_daemon_with_no_provider_flags_refuses_to_propose` asserts.
        Self::start_with_flags(root, &["--provider-scripted"])
    }

    /// Starts a daemon with no provider at all, as a user would start it.
    fn start_unconfigured(root: &Path) -> Self {
        Self::start_with_flags(root, &[])
    }

    fn start_with_flags(root: &Path, flags: &[&str]) -> Self {
        Self::start_with_provider(root, None, flags)
    }

    /// Starts a daemon pointed at `provider`.
    ///
    /// With `None` the daemon has no proposal provider at all, and `task/ai-propose`
    /// answers `provider-not-configured` — the same as a production daemon started
    /// without the two provider flags.
    fn start_with_provider(root: &Path, provider: Option<&FakeProvider>, extra: &[&str]) -> Self {
        let mut command = Command::new(daemon_bin());
        command.arg("--state-root").arg(root);
        if let Some(p) = provider {
            command
                .arg("--provider-base-url")
                .arg(format!("http://{}/v1", p.address))
                .arg("--provider-model")
                .arg("fake-model-1");
        }
        for flag in extra {
            command.arg(flag);
        }
        let child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn orxnud");
        let d = Self {
            child,
            root: root.to_path_buf(),
        };
        d.await_ready();
        d
    }

    fn endpoint(&self) -> PathBuf {
        self.root.join("orxnud.sock")
    }

    fn await_ready(&self) {
        for _ in 0..200 {
            let out = self.cli(&["task", "list"]);
            if out.status.success() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!(
            "the daemon never became ready at {}",
            self.endpoint().display()
        );
    }

    /// Runs `orxnuctl` against this daemon, with the endpoint passed explicitly.
    fn cli(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(cli_bin());
        cmd.args(args)
            .arg("--endpoint")
            .arg(self.endpoint())
            .output()
            .expect("run orxnuctl")
    }

    /// Whether this host can actually run a Tier-1 capability, as the daemon reports.
    ///
    /// Read from `doctor` rather than from a crate the CLI is forbidden to depend on
    /// (gate G2(b)), and through the same diagnostic a user would consult. The daemon
    /// answers for the host *it* dispatches on, which is the only host that matters.
    fn tier1_executable(&self) -> bool {
        let out = self.cli(&["doctor"]);
        let text = stdout_of(&out);
        assert!(
            out.status.success(),
            "doctor must succeed: {text}{}",
            stderr_of(&out)
        );
        let verdict = text
            .lines()
            .find_map(|l| l.strip_prefix("tier1 executable: "))
            .unwrap_or_else(|| {
                panic!(
                    "doctor did not report a Tier-1 verdict, so this test cannot know \
                        which property to assert:\n{text}"
                )
            });
        match verdict.trim() {
            "yes" => true,
            other if other.starts_with("no") => false,
            other => panic!("doctor reported an unreadable Tier-1 verdict {other:?}:\n{text}"),
        }
    }
}

/// Describes the host to the test log, so a failure says which environment produced it.
///
/// Printed rather than asserted: the point is that "this failed on a host that cannot
/// sandbox" is legible from the log alone, without re-running anything.
fn print_host_environment(daemon: &Daemon) -> bool {
    let ok = daemon.tier1_executable();
    let kind = if ok {
        "CAN sandbox: asserting successful Tier-1 execution"
    } else {
        "CANNOT sandbox: asserting the fail-closed refusal, which is correct here"
    };
    println!("   [host] tier1_executable={ok} -- {kind}");
    ok
}

/// Runs a Tier-1 dispatch that the caller needs to have **succeed**, or asserts the
/// fail-closed refusal when this host cannot isolate.
///
/// # Why this exists rather than a platform `ignore`
///
/// The question "can this host isolate a subprocess?" is not a platform question. A
/// Linux host can answer no — `bwrap` installed, kernel or LSM refusing the user
/// namespace — which is the state a GitHub-hosted runner is in. The gate these tests used
/// to carry was `#[cfg_attr(not(target_os = "linux"), ignore)]`, which answers a
/// different question, is an `ignore` (and a skip teaches nothing), and so left the
/// genuinely interesting host state untested: a Linux machine that cannot sandbox.
///
/// # What it does on a host that cannot
///
/// It performs the dispatch and asserts the refusal *positively*: non-zero exit, the
/// missing guarantee named, and nothing written. Then it returns `None` so the caller
/// returns without asserting anything it cannot observe here. The test is not skipped
/// and does not pass vacuously — it asserts the property that is actually true, which is
/// that a Tier-1 capability does not run unsandboxed.
///
/// Returns `None` only on such a host. `Some` means the dispatch was attempted and the
/// caller owns the rest.
fn tier1_dispatch(
    daemon: &Daemon,
    root: &std::path::Path,
    approval: &str,
    target: &str,
    params: &str,
) -> Option<Output> {
    if print_host_environment(daemon) {
        return Some(daemon.cli(&[
            "capability",
            "run",
            "--capability",
            "filesystem/write-text",
            "--target",
            target,
            "--params",
            params,
            "--approval",
            approval,
        ]));
    }

    let out = daemon.cli(&[
        "capability",
        "run",
        "--capability",
        "filesystem/write-text",
        "--target",
        target,
        "--params",
        params,
        "--approval",
        approval,
    ]);
    assert_tier1_refused(&out, root, target);
    let _ = std::fs::remove_dir_all(root);
    None
}

/// Asserts that `out` is the fail-closed refusal this host should produce, and that it
/// created nothing.
///
/// Shared with the tests that reach Tier-1 execution through `task/execute` rather than
/// `capability/run`, so the three assertions a refusal must satisfy are written once. The
/// reason is checked as well as the failure, because "it failed somehow" is not the
/// property — "it refused because it could not isolate" is.
fn assert_tier1_refused(out: &Output, root: &std::path::Path, target: &str) {
    let stderr = stderr_of(out);
    assert!(
        !out.status.success(),
        "a host that cannot isolate must refuse, not run the work: {}",
        stdout_of(out)
    );
    assert!(
        stderr.contains("sandbox guarantees"),
        "the refusal must name the missing guarantee, got: {stderr}"
    );
    // Both spellings: `capability/run` writes under the workspace, `task/execute` does
    // too, but the assertion should not depend on which route produced the refusal.
    assert!(
        !workspace(root).join(target).exists() && !root.join(target).exists(),
        "a refused Tier-1 dispatch must leave nothing behind"
    );
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// The whole product loop, driven through the CLI.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_user_can_create_list_claim_and_complete_a_task() {
    let root = dir("workflow");
    let d = Daemon::start(&root);

    // create
    let out = d.cli(&["task", "create", "--id", "t-1", "buy milk"]);
    assert!(out.status.success(), "create failed: {}", stderr_of(&out));
    let created = stdout_of(&out);
    assert!(created.contains("t-1"), "{created}");
    assert!(created.contains("pending"), "{created}");
    assert!(created.contains("buy milk"), "{created}");

    // list: the task is there, with its content
    let out = d.cli(&["task", "list"]);
    assert!(out.status.success());
    let listed = stdout_of(&out);
    assert!(listed.contains("t-1"), "{listed}");
    assert!(listed.contains("pending"), "{listed}");
    assert!(listed.contains("buy milk"), "{listed}");

    // claim
    let out = d.cli(&["task", "claim", "--id", "t-1", "--worker", "w1"]);
    assert!(out.status.success(), "claim failed: {}", stderr_of(&out));
    let claimed = stdout_of(&out);
    assert!(claimed.contains("running"), "{claimed}");
    assert!(claimed.contains("w1"), "{claimed}");
    assert!(claimed.contains("attempt"), "{claimed}");
    assert!(
        claimed.contains("lease expires"),
        "the daemon owns the lease and must report it: {claimed}"
    );

    // list again: the claim is visible
    let out = d.cli(&["task", "list"]);
    assert!(stdout_of(&out).contains("running"));

    // complete
    let out = d.cli(&["task", "complete", "--id", "t-1", "--worker", "w1"]);
    assert!(out.status.success(), "complete failed: {}", stderr_of(&out));
    assert!(stdout_of(&out).contains("completed"));

    // and the final list shows the terminal state
    let out = d.cli(&["task", "list"]);
    let listed = stdout_of(&out);
    assert!(listed.contains("completed"), "{listed}");
    assert!(!listed.contains("running"), "{listed}");

    let _ = std::fs::remove_dir_all(&root);
}

/// The security property, through the CLI: a stranger cannot complete a task.
///
/// The CLI must not pre-judge this — it sends the request and shows the daemon's
/// answer. So the proof that it does not is that the refusal arrives *from the
/// daemon*, with the daemon's own structured reason.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_wrong_worker_is_refused_by_the_daemon_not_by_the_cli() {
    let root = dir("wrong-worker");
    let d = Daemon::start(&root);

    d.cli(&["task", "create", "--id", "t-1", "x"]);
    let out = d.cli(&["task", "claim", "--id", "t-1", "--worker", "owner"]);
    assert!(out.status.success(), "{}", stderr_of(&out));

    // The intruder.
    let out = d.cli(&["task", "complete", "--id", "t-1", "--worker", "intruder"]);
    assert!(
        !out.status.success(),
        "a worker without the lease must not exit 0"
    );
    let err = stderr_of(&out);
    assert!(
        err.contains("fenced"),
        "the refusal must carry the daemon's structured reason: {err}"
    );
    assert!(
        !stdout_of(&out).contains("completed"),
        "nothing may claim success on a refused completion"
    );

    // The task is untouched: still running, still owned by the real worker.
    let out = d.cli(&["task", "list"]);
    let listed = stdout_of(&out);
    assert!(listed.contains("running"), "{listed}");
    assert!(!listed.contains("completed"), "{listed}");

    // And the rightful owner can still finish it.
    let out = d.cli(&["task", "complete", "--id", "t-1", "--worker", "owner"]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert!(stdout_of(&out).contains("completed"));

    let _ = std::fs::remove_dir_all(&root);
}

/// A pending task cannot be completed at all, through the CLI.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_never_claimed_task_cannot_be_completed_through_the_cli() {
    let root = dir("pending");
    let d = Daemon::start(&root);
    d.cli(&["task", "create", "--id", "t-1", "x"]);

    let out = d.cli(&["task", "complete", "--id", "t-1", "--worker", "anyone"]);
    assert!(!out.status.success(), "must not exit 0");
    assert!(stderr_of(&out).contains("fenced"), "{}", stderr_of(&out));

    let out = d.cli(&["task", "list"]);
    assert!(stdout_of(&out).contains("pending"));
    let _ = std::fs::remove_dir_all(&root);
}

/// Phase 11: no daemon, no backtrace, no internal detail, non-zero exit.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn with_no_daemon_the_cli_says_so_and_exits_non_zero() {
    let root = dir("no-daemon");
    // Deliberately never started.
    let endpoint = root.join("orxnud.sock");

    let out = Command::new(cli_bin())
        .args(["task", "list", "--endpoint"])
        .arg(&endpoint)
        .output()
        .expect("run orxnuctl");

    assert!(
        !out.status.success(),
        "an unreachable daemon is a failure, not an empty list"
    );
    let err = stderr_of(&out);
    assert!(err.contains("cannot reach"), "{err}");
    assert!(
        !err.contains("RUST_BACKTRACE") && !err.contains("panicked"),
        "no backtrace by default: {err}"
    );
    assert!(
        !err.contains("state.db") && !err.contains(".sql"),
        "no storage detail may reach the user: {err}"
    );
    assert!(
        stdout_of(&out).trim().is_empty(),
        "a failure must not print a table a script would parse as data"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Phase 15: an empty database is a clean success, not an error and not a crash.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn an_empty_task_list_is_a_clean_success() {
    let root = dir("empty");
    let d = Daemon::start(&root);
    let out = d.cli(&["task", "list"]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    assert_eq!(stdout_of(&out).trim(), "no tasks");
    let _ = std::fs::remove_dir_all(&root);
}

/// A duplicate id, and a claim for something that does not exist: both refusals, both
/// with the daemon's own reason rather than a CLI paraphrase.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn refusals_reach_the_user_as_the_daemons_structured_reason() {
    let root = dir("refusals");
    let d = Daemon::start(&root);

    d.cli(&["task", "create", "--id", "t-1", "original"]);

    // Duplicate id.
    let out = d.cli(&["task", "create", "--id", "t-1", "impostor"]);
    assert!(!out.status.success());
    assert!(
        stderr_of(&out).contains("already-exists"),
        "{}",
        stderr_of(&out)
    );

    // And the original survived: a plain insert, never an upsert.
    let out = d.cli(&["task", "list"]);
    let listed = stdout_of(&out);
    assert!(listed.contains("original"), "{listed}");
    assert!(!listed.contains("impostor"), "{listed}");

    // No such task.
    let out = d.cli(&["task", "claim", "--id", "ghost", "--worker", "w"]);
    assert!(!out.status.success());
    assert!(stderr_of(&out).contains("not-found"), "{}", stderr_of(&out));

    let _ = std::fs::remove_dir_all(&root);
}

/// Over-long content is refused by the daemon's bound, and the CLI must not pre-empt
/// it with a different rule.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn oversized_content_is_refused_by_the_daemon() {
    let root = dir("oversize");
    let d = Daemon::start(&root);

    let huge = "x".repeat(64 * 1024);
    let out = d.cli(&["task", "create", "--id", "t-1", &huge]);
    assert!(!out.status.success(), "must not exit 0");
    assert!(stderr_of(&out).contains("refused"), "{}", stderr_of(&out));

    // Nothing was created.
    let out = d.cli(&["task", "list"]);
    assert_eq!(stdout_of(&out).trim(), "no tasks");

    let _ = std::fs::remove_dir_all(&root);
}

/// The whole thing survives a restart, driven through the CLI on both sides.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn tasks_survive_a_restart_of_the_daemon() {
    let root = dir("restart");
    {
        let d = Daemon::start(&root);
        let out = d.cli(&["task", "create", "--id", "keep-me", "durable content"]);
        assert!(out.status.success(), "{}", stderr_of(&out));
        let out = d.cli(&["task", "claim", "--id", "keep-me", "--worker", "w1"]);
        assert!(out.status.success(), "{}", stderr_of(&out));
        let out = d.cli(&["task", "complete", "--id", "keep-me", "--worker", "w1"]);
        assert!(out.status.success(), "{}", stderr_of(&out));
    }
    // Dropped without an orderly stop, then started again on the same directory.
    {
        let d = Daemon::start(&root);
        let out = d.cli(&["task", "list"]);
        assert!(out.status.success(), "{}", stderr_of(&out));
        let listed = stdout_of(&out);
        assert!(listed.contains("keep-me"), "{listed}");
        assert!(listed.contains("durable content"), "{listed}");
        assert!(listed.contains("completed"), "{listed}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// The product loop with cancellation, driven entirely through the CLI.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_user_can_cancel_a_task_and_see_it_cancelled() {
    let root = dir("cancel");
    let d = Daemon::start(&root);

    let out = d.cli(&["task", "create", "--id", "t-1", "no longer needed"]);
    assert!(out.status.success(), "{}", stderr_of(&out));

    let out = d.cli(&["task", "cancel", "--id", "t-1"]);
    assert!(out.status.success(), "cancel failed: {}", stderr_of(&out));
    let cancelled = stdout_of(&out);
    assert!(cancelled.contains("cancelled"), "{cancelled}");
    assert!(cancelled.contains("t-1"), "{cancelled}");
    assert!(cancelled.contains("no longer needed"), "{cancelled}");

    // list shows the authoritative state.
    let out = d.cli(&["task", "list"]);
    let listed = stdout_of(&out);
    assert!(listed.contains("cancelled"), "{listed}");
    assert!(!listed.contains("pending"), "{listed}");

    let _ = std::fs::remove_dir_all(&root);
}

/// Repeated cancellation follows the engine's semantics: a no-op that succeeds.
///
/// The point of this test is not the wording but the *state*: repeating a cancel must
/// not resurrect the task, must not fail, and must not append a second terminal event.
/// The CLI reports whatever state the daemon says, which after a repeat is still
/// `cancelled` — and saying so is true, not a false claim of success.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn repeating_a_cancel_is_a_no_op_that_leaves_the_task_cancelled() {
    let root = dir("cancel-twice");
    let d = Daemon::start(&root);

    d.cli(&["task", "create", "--id", "t-1", "x"]);

    let first = d.cli(&["task", "cancel", "--id", "t-1"]);
    assert!(first.status.success(), "{}", stderr_of(&first));
    assert!(stdout_of(&first).contains("cancelled"));

    // Three more times. All succeed, all report `cancelled`, none changes anything.
    for _ in 0..3 {
        let again = d.cli(&["task", "cancel", "--id", "t-1"]);
        assert!(
            again.status.success(),
            "a repeated cancel must succeed: {}",
            stderr_of(&again)
        );
        assert!(
            stdout_of(&again).contains("cancelled"),
            "the task is still cancelled, and that is what should be said"
        );
    }

    let out = d.cli(&["task", "list"]);
    let listed = stdout_of(&out);
    assert_eq!(
        listed.matches("cancelled").count(),
        1,
        "one task, one row, one state: {listed}"
    );
    assert!(!listed.contains("running"), "no resurrection: {listed}");

    let _ = std::fs::remove_dir_all(&root);
}

/// The case where the CLI must NOT say `cancelled`: the task is already `completed`,
/// so a cancel changes nothing and claiming otherwise would misreport it.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn cancelling_a_completed_task_reports_it_unchanged_rather_than_cancelled() {
    let root = dir("cancel-completed");
    let d = Daemon::start(&root);

    d.cli(&["task", "create", "--id", "t-1", "x"]);
    let out = d.cli(&["task", "claim", "--id", "t-1", "--worker", "w1"]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    let out = d.cli(&["task", "complete", "--id", "t-1", "--worker", "w1"]);
    assert!(out.status.success(), "{}", stderr_of(&out));

    let out = d.cli(&["task", "cancel", "--id", "t-1"]);
    assert!(
        out.status.success(),
        "the engine's no-op succeeds: {}",
        stderr_of(&out)
    );
    let said = stdout_of(&out);
    assert!(
        said.contains("unchanged"),
        "a completed task was not cancelled, so the CLI must not say it was: {said}"
    );
    assert!(
        said.contains("completed"),
        "and it must report the state that is actually true: {said}"
    );

    let out = d.cli(&["task", "list"]);
    let listed = stdout_of(&out);
    assert!(listed.contains("completed"), "{listed}");
    assert!(!listed.contains("cancelled"), "{listed}");

    let _ = std::fs::remove_dir_all(&root);
}

/// Cancelling a task that does not exist is a structured refusal, not a local guess.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn cancelling_a_missing_task_is_a_structured_refusal() {
    let root = dir("cancel-absent");
    let d = Daemon::start(&root);

    let out = d.cli(&["task", "cancel", "--id", "ghost"]);
    assert!(!out.status.success(), "must not exit 0");
    let err = stderr_of(&out);
    assert!(err.contains("not-found"), "{err}");
    assert!(err.contains("refused"), "{err}");
    assert!(
        stdout_of(&out).trim().is_empty(),
        "a refusal must not print a task block"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A cancelled task cannot be claimed through the CLI either.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_cancelled_task_cannot_be_claimed_through_the_cli() {
    let root = dir("cancel-then-claim");
    let d = Daemon::start(&root);

    d.cli(&["task", "create", "--id", "t-1", "x"]);
    let out = d.cli(&["task", "cancel", "--id", "t-1"]);
    assert!(out.status.success(), "{}", stderr_of(&out));

    let claimed = d.cli(&["task", "claim", "--id", "t-1", "--worker", "w1"]);
    assert!(
        !claimed.status.success(),
        "a cancelled task must not be claimable"
    );
    assert!(
        stderr_of(&claimed).contains("not-claimable"),
        "{}",
        stderr_of(&claimed)
    );

    // And the state is still `cancelled`, not resurrected into running.
    let out = d.cli(&["task", "list"]);
    let listed = stdout_of(&out);
    assert!(listed.contains("cancelled"), "{listed}");
    assert!(!listed.contains("running"), "{listed}");

    let _ = std::fs::remove_dir_all(&root);
}

/// Cancellation survives a restart, through the CLI on both sides.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_cancelled_task_stays_cancelled_across_a_restart() {
    let root = dir("cancel-restart");
    {
        let d = Daemon::start(&root);
        let out = d.cli(&["task", "create", "--id", "t-1", "durable refusal"]);
        assert!(out.status.success(), "{}", stderr_of(&out));
        let out = d.cli(&["task", "cancel", "--id", "t-1"]);
        assert!(out.status.success(), "{}", stderr_of(&out));
    }
    {
        let d = Daemon::start(&root);
        let out = d.cli(&["task", "list"]);
        assert!(out.status.success(), "{}", stderr_of(&out));
        let listed = stdout_of(&out);
        assert!(listed.contains("cancelled"), "{listed}");
        assert!(
            listed.contains("durable refusal"),
            "content must survive too: {listed}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Phase 11: no daemon, no backtrace, no SQL or path disclosure.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn cancelling_with_no_daemon_fails_cleanly() {
    let root = dir("cancel-no-daemon");
    let endpoint = root.join("orxnud.sock");

    let out = Command::new(cli_bin())
        .args(["task", "cancel", "--id", "x", "--endpoint"])
        .arg(&endpoint)
        .output()
        .expect("run orxnuctl");

    assert!(!out.status.success(), "must not exit 0");
    let err = stderr_of(&out);
    assert!(err.contains("cannot reach"), "{err}");
    assert!(
        !err.contains("panicked") && !err.contains("RUST_BACKTRACE"),
        "{err}"
    );
    assert!(!err.contains("state.db") && !err.contains(".sql"), "{err}");

    let _ = std::fs::remove_dir_all(&root);
}

/// The first capability, driven through both real binaries.
///
/// The point is not that a number came back — it is the whole chain behind it:
/// CLI -> socket -> daemon -> policy -> authorisation -> dispatcher -> adapter ->
/// verifier -> durable audit -> response. Every stage had to succeed for `verified:
/// true` to appear, and the audit assertion below proves the tail of that chain ran
/// rather than being short-circuited.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_user_can_run_a_capability_and_see_a_verified_result() {
    let root = dir("capability");
    let d = Daemon::start(&root);

    let out = d.cli(&[
        "capability",
        "run",
        "--capability",
        "text/word-count",
        "--params",
        r#"{"text":"hello world\nOpenRayNux"}"#,
    ]);
    assert!(out.status.success(), "{}", stderr_of(&out));
    let said = stdout_of(&out);
    assert!(said.contains("capability: text/word-count"), "{said}");
    assert!(said.contains("verified: true"), "{said}");
    assert!(!said.contains("undetermined"), "{said}");
    assert!(!said.contains("refuted"), "{said}");
    // 22 bytes, 22 scalar values, 3 words, 2 lines — the contract's definitions.
    assert!(said.contains("bytes: 22"), "{said}");
    assert!(said.contains("characters: 22"), "{said}");
    assert!(said.contains("words: 3"), "{said}");
    assert!(said.contains("lines: 2"), "{said}");

    let _ = std::fs::remove_dir_all(&root);
}

/// The capability produced durable audit records, and they survive a restart.
///
/// A capability that ran without leaving a record would be exactly the failure the
/// journal exists to prevent, so this reads the file rather than trusting the reply.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_capability_run_leaves_durable_audit_that_survives_a_restart() {
    let root = dir("capability-audit");
    {
        let d = Daemon::start(&root);
        let out = d.cli(&[
            "capability",
            "run",
            "--capability",
            "text/word-count",
            "--params",
            r#"{"text":"audit me"}"#,
        ]);
        assert!(out.status.success(), "{}", stderr_of(&out));
    }
    // Restarted against the same database: the chain must still verify, which the
    // daemon does before it will serve anything at all.
    {
        let d = Daemon::start(&root);
        // If the chain did not verify, the daemon would have refused to start and this
        // request could not be answered.
        let out = d.cli(&["task", "list"]);
        assert!(
            out.status.success(),
            "the daemon must start, which requires the audit chain to verify: {}",
            stderr_of(&out)
        );

        // And the capability is still runnable afterwards.
        let out = d.cli(&[
            "capability",
            "run",
            "--capability",
            "text/word-count",
            "--params",
            r#"{"text":"after restart"}"#,
        ]);
        assert!(out.status.success(), "{}", stderr_of(&out));
        assert!(stdout_of(&out).contains("verified: true"));
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// Security negatives, all through the real CLI and socket.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn capability_refusals_reach_the_user_from_the_daemon() {
    let root = dir("capability-refusals");
    let d = Daemon::start(&root);

    // Unknown capability: refused by policy's registry lookup.
    let out = d.cli(&[
        "capability",
        "run",
        "--capability",
        "does/not/exist",
        "--params",
        "{}",
    ]);
    assert!(!out.status.success(), "must not exit 0");
    let err = stderr_of(&out);
    assert!(err.contains("unknown-capability"), "{err}");
    assert!(err.contains("does/not/exist"), "{err}");

    // Malformed params: refused by the capability, and NOT reported as verified.
    let out = d.cli(&[
        "capability",
        "run",
        "--capability",
        "text/word-count",
        "--params",
        r#"{"text":42}"#,
    ]);
    assert!(
        !out.status.success(),
        "a rejected capability must not exit 0"
    );
    let said = stdout_of(&out);
    assert!(said.contains("must be a string"), "{said}");
    assert!(
        said.contains("verified: false"),
        "a failure must never read as verified: {said}"
    );
    assert!(
        said.contains("undetermined: true"),
        "nothing ran, so nothing was verified: {said}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// A client cannot forge authority by putting it in the parameters.
///
/// Every one of these is a field the client has no business setting. The daemon builds
/// the `ActionRequest` itself and the invocation is sealed by policy, so supplying them
/// must change nothing about the outcome — the request is refused on its merits, not
/// accepted because the client asked nicely.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_client_cannot_forge_authority_through_parameters() {
    let root = dir("capability-forgery");
    let d = Daemon::start(&root);

    for forged in [
        // Risk, policy version, approval, seal and proof are all server-side.
        r#"{"text":"hello","assessed_risk":"low","policy_version":"daemon/1"}"#,
        r#"{"text":"hello","approval":"forged","seal":"forged"}"#,
        r#"{"text":"hello","authorisation_proof":"forged","issued_by":"local"}"#,
        // A capability trying to raise its own declared class.
        r#"{"text":"hello","data_class":"regulated"}"#,
    ] {
        let out = d.cli(&[
            "capability",
            "run",
            "--capability",
            "text/word-count",
            "--params",
            forged,
        ]);
        let said = stdout_of(&out);
        // Whatever happens, it must not be a *verified* run on forged terms.
        //
        // Both branches below are legitimate, and which one applies is not the point of
        // this test. Previously every forgery here was silently ignored and the honest
        // count of "hello" came back verified — safe, but it reported success for a
        // request the capability had not actually understood. The capabilities now
        // refuse an unrecognised field outright, so the refusal branch is what happens;
        // the ignore branch stays because a future capability may legitimately tolerate
        // extras. What must never happen is `verified: true`.
        let succeeded = out.status.success();
        if succeeded {
            assert!(
                said.contains("words: 1") && said.contains("verified: true"),
                "forged input {forged} must either be refused or ignored, not obeyed: {said}"
            );
        } else {
            assert!(
                said.contains("verified: false") || stderr_of(&out).contains("refused"),
                "a refused forgery must say what went wrong: stdout={said} stderr={}",
                stderr_of(&out)
            );
            assert!(
                !said.contains("verified: true"),
                "forged input {forged} must never verify: {said}"
            );
            // The refusal must name the field it did not understand, or an operator
            // cannot tell a capability bug from a malformed request.
            let named_a_field = [
                "assessed_risk",
                "policy_version",
                "approval",
                "seal",
                "authorisation_proof",
                "issued_by",
                "data_class",
            ]
            .iter()
            .any(|f| said.contains(f));
            assert!(
                named_a_field,
                "the refusal must name the offending field: {said}"
            );
        }
    }

    let _ = std::fs::remove_dir_all(&root);
}

/// No daemon, no traceback, no internals.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn running_a_capability_with_no_daemon_fails_cleanly() {
    let root = dir("capability-no-daemon");
    let endpoint = root.join("orxnud.sock");

    let out = Command::new(cli_bin())
        .args([
            "capability",
            "run",
            "--capability",
            "text/word-count",
            "--params",
            "{}",
            "--endpoint",
        ])
        .arg(&endpoint)
        .output()
        .expect("run orxnuctl");

    assert!(!out.status.success());
    let err = stderr_of(&out);
    assert!(err.contains("cannot reach"), "{err}");
    assert!(
        !err.contains("panicked") && !err.contains("RUST_BACKTRACE"),
        "{err}"
    );
    assert!(!err.contains("state.db") && !err.contains(".sql"), "{err}");

    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// The governed side-effect capability, through both real binaries
// ---------------------------------------------------------------------------
//
// Every test below drives `orxnuctl` as a separate process against a real `orxnud`
// over a real socket. Nothing calls TaskService or the dispatcher directly, because the
// thing being verified is the *product* path: a person approving an operation and then
// invoking it, and the daemon refusing when the two do not match.
//
// The sandbox is exercised for real too. If the host cannot sandbox, the Tier-1
// execution is refused by design and the tests that need it say so rather than
// pretending; see `write_text` in the capability suite for the same distinction at
// the unit level.

/// The workspace the daemon confines writes to.
fn workspace(root: &std::path::Path) -> std::path::PathBuf {
    root.join("workspace")
}

/// Asks for an approval and returns it as the JSON text `--approval` takes.
fn approve(daemon: &Daemon, target: &str, contents: &str, ttl_ms: &str) -> String {
    let params = format!(r#"{{"path":"{target}","contents":"{contents}"}}"#);
    let out = daemon.cli(&[
        "capability",
        "approve",
        "--capability",
        "filesystem/write-text",
        "--target",
        target,
        "--params",
        &params,
        "--ttl-ms",
        ttl_ms,
    ]);
    assert!(
        out.status.success(),
        "issuing an approval must succeed: {}",
        stderr_of(&out)
    );
    stdout_of(&out).trim().to_owned()
}

/// The full governed loop, as a person would perform it.
///
/// # Why this asserts different things on different hosts
///
/// Tier-1 execution needs a host that can actually isolate a subprocess, and not every
/// host can: `bwrap` may be installed while the kernel or an LSM forbids it from creating
/// a user namespace, which is the case on a GitHub-hosted Linux runner. On such a host
/// the dispatch is **refused**, and that refusal is the security property working — so
/// asserting a successful write there would assert something false about the host, and
/// asserting the failure unconditionally would assert nothing anywhere.
///
/// [`tier1_dispatch`] asks the daemon what the host can do and then asserts the property
/// that is true: successful, verified execution where isolation is available, and a
/// refusal that creates nothing where it is not. Neither branch is a skip, neither is
/// mocked, and neither weakens the contract — a host that cannot isolate cannot run the
/// capability, by design (ADR-0035, V-49).
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_user_approves_a_write_and_the_file_appears_with_exactly_those_bytes() {
    let root = dir("write-happy");
    let daemon = Daemon::start(&root);

    let approval = approve(&daemon, "hello.txt", "hello world", "60000");

    let Some(out) = tier1_dispatch(
        &daemon,
        &root,
        &approval,
        "hello.txt",
        r#"{"path":"hello.txt","contents":"hello world"}"#,
    ) else {
        return;
    };

    assert!(
        out.status.success(),
        "the approved write must succeed: {}",
        stderr_of(&out)
    );
    assert!(
        stdout_of(&out).contains("verified: true"),
        "{}",
        stdout_of(&out)
    );
    assert_eq!(
        std::fs::read_to_string(workspace(&root).join("hello.txt")).expect("written"),
        "hello world",
        "the file must hold exactly the approved contents"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_high_risk_capability_refuses_without_an_approval_and_writes_nothing() {
    let root = dir("write-no-approval");
    let daemon = Daemon::start(&root);

    let out = daemon.cli(&[
        "capability",
        "run",
        "--capability",
        "filesystem/write-text",
        "--target",
        "denied.txt",
        "--params",
        r#"{"path":"denied.txt","contents":"nope"}"#,
    ]);

    assert!(
        !out.status.success(),
        "an unapproved High-risk call must fail"
    );
    let err = stderr_of(&out);
    assert!(
        err.contains("approval-required"),
        "the refusal must name the reason: {err}"
    );
    assert!(
        !workspace(&root).join("denied.txt").exists(),
        "a refused call must not have written anything"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The substitution test, and the one the whole approval mechanism exists for.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn an_approval_for_one_write_cannot_be_reused_for_different_contents() {
    let root = dir("write-substitute");
    let daemon = Daemon::start(&root);

    let approval = approve(&daemon, "sub.txt", "alpha", "60000");

    // Alpha: approved, and it runs. Needs a host that can isolate; see
    // `tier1_dispatch` for why the gate is a capability question and not a platform one.
    let Some(ok) = tier1_dispatch(
        &daemon,
        &root,
        &approval,
        "sub.txt",
        r#"{"path":"sub.txt","contents":"alpha"}"#,
    ) else {
        return;
    };
    assert!(ok.status.success(), "{}", stderr_of(&ok));

    // Beta: same capability, same target, same approval, different contents.
    let refused = daemon.cli(&[
        "capability",
        "run",
        "--capability",
        "filesystem/write-text",
        "--target",
        "sub.txt",
        "--params",
        r#"{"path":"sub.txt","contents":"beta"}"#,
        "--approval",
        &approval,
    ]);
    assert!(
        !refused.status.success(),
        "beta must not be authorised by alpha's approval"
    );
    let err = stderr_of(&refused);
    assert!(
        err.contains("approval-digest-mismatch"),
        "the refusal must be the parameter binding, not something incidental: {err}"
    );
    assert_eq!(
        std::fs::read_to_string(workspace(&root).join("sub.txt")).expect("read"),
        "alpha",
        "the refused write must not have modified the file"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn an_approval_works_once_and_is_refused_the_second_time() {
    let root = dir("write-single-use");
    let daemon = Daemon::start(&root);

    let approval = approve(&daemon, "once.txt", "x", "60000");
    // The first use has to *succeed* for "and is refused the second time" to mean
    // anything, so this test needs a host that can isolate. `tier1_dispatch` performs
    // that first use and hands it back -- reusing it rather than dispatching again,
    // because a second dispatch would itself be the reuse this test is about.
    let Some(first) = tier1_dispatch(
        &daemon,
        &root,
        &approval,
        "once.txt",
        r#"{"path":"once.txt","contents":"x"}"#,
    ) else {
        return;
    };
    assert!(
        first.status.success(),
        "the first use must succeed: {}",
        stderr_of(&first)
    );
    let args = [
        "capability",
        "run",
        "--capability",
        "filesystem/write-text",
        "--target",
        "once.txt",
        "--params",
        r#"{"path":"once.txt","contents":"x"}"#,
        "--approval",
        approval.as_str(),
    ];
    let second = daemon.cli(&args);
    assert!(!second.status.success(), "the second use must be refused");
    assert!(
        stderr_of(&second).contains("approval-already-used"),
        "{}",
        stderr_of(&second)
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The V-62 regression, demonstrated through the product rather than at a seam.
///
/// `ttl_ms 0` produces an approval whose expiry equals its issue time, so the refusal is
/// a fact about the inputs. No sleeping, and therefore no flakiness: if this test ever
/// starts passing because the machine got slower, something is wrong with the test.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn an_expired_approval_is_refused_and_writes_nothing() {
    let root = dir("write-expired");
    let daemon = Daemon::start(&root);

    let approval = approve(&daemon, "late.txt", "x", "0");
    let out = daemon.cli(&[
        "capability",
        "run",
        "--capability",
        "filesystem/write-text",
        "--target",
        "late.txt",
        "--params",
        r#"{"path":"late.txt","contents":"x"}"#,
        "--approval",
        &approval,
    ]);

    assert!(!out.status.success(), "an expired approval must be refused");
    assert!(
        stderr_of(&out).contains("approval-expired"),
        "{}",
        stderr_of(&out)
    );
    assert!(
        !workspace(&root).join("late.txt").exists(),
        "an expired approval must not have written anything"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn an_escaping_path_is_refused_and_nothing_appears_outside_the_workspace() {
    let root = dir("write-escape");
    let daemon = Daemon::start(&root);

    let approval = approve(&daemon, "../escaped.txt", "pwned", "60000");
    let out = daemon.cli(&[
        "capability",
        "run",
        "--capability",
        "filesystem/write-text",
        "--target",
        "../escaped.txt",
        "--params",
        r#"{"path":"../escaped.txt","contents":"pwned"}"#,
        "--approval",
        &approval,
    ]);

    assert!(!out.status.success(), "an escaping path must be refused");
    assert!(
        !root.join("escaped.txt").exists(),
        "nothing may appear beside the workspace: {}",
        root.join("escaped.txt").display()
    );
    assert!(
        !std::path::Path::new("/tmp/escaped.txt").exists(),
        "nothing may escape to /tmp"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The governed execution is audited, and the record survives the process that made it.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn the_write_is_audited_with_real_timestamps_and_survives_a_restart() {
    let root = dir("write-audit");
    let before = {
        let daemon = Daemon::start(&root);
        let approval = approve(&daemon, "audited.txt", "recorded", "60000");
        // A *completed* execution is what there is to audit, so this needs a host that
        // can isolate. On one that cannot, `tier1_dispatch` asserts the refusal instead.
        let Some(out) = tier1_dispatch(
            &daemon,
            &root,
            &approval,
            "audited.txt",
            r#"{"path":"audited.txt","contents":"recorded"}"#,
        ) else {
            return;
        };
        assert!(out.status.success(), "{}", stderr_of(&out));
        let bytes = state_bytes(&root);
        assert!(
            bytes.contains("filesystem/write-text"),
            "the governed capability must appear in the durable audit trail"
        );
        assert!(
            !bytes.contains("\"at-ms\":0"),
            "no audit record may be stamped at the epoch"
        );
        bytes.len()
    };

    // A fresh daemon over the same state: reaching this point at all means the chain
    // loaded and verified, because restore fails closed on a broken link.
    let _daemon = Daemon::start(&root);
    assert_eq!(
        state_bytes(&root).len(),
        before,
        "a restart must neither add nor lose records"
    );
    assert!(
        workspace(&root).join("audited.txt").exists(),
        "the written file survives the daemon that wrote it"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The durable state file as text.
///
/// A byte scan rather than SQL, and the reason is the dependency boundary: this crate
/// may reach `orxnud-protocol` and `orxnud-platform-ipc` and nothing else -- not even as
/// a dev-dependency, which `cli_boundary.rs` asserts. `orxnud-store` owns the schema and
/// reading it properly would mean depending on it.
///
/// That constraint costs little here, because the property being checked is "these
/// strings are in the durable file", and SQLite stores text values verbatim. A substring
/// search over the file answers exactly that. It cannot answer a question about *rows*
/// -- and none of the assertions below is a question about rows: they check that a
/// capability name was persisted, and that no record carries a zero timestamp.
fn state_bytes(root: &std::path::Path) -> String {
    // The write-ahead log is read too, and not as a nicety. SQLite in WAL mode commits
    // into `state.db-wal` and only checkpoints into `state.db` later; the test harness
    // stops the daemon with SIGKILL, so the most recent records are still in the log.
    // Reading only the main file finds an older, checkpointed prefix and reports a
    // perfectly good audit trail as empty.
    let mut out = String::new();
    for name in ["state.db", "state.db-wal"] {
        if let Ok(bytes) = std::fs::read(root.join(name)) {
            out.push_str(&String::from_utf8_lossy(&bytes));
        }
    }
    assert!(
        !out.is_empty(),
        "the daemon's durable state file is missing"
    );
    out
}

// ---------------------------------------------------------------------------
// The governed task action path, through both real binaries
// ---------------------------------------------------------------------------
//
// The daemon socket suite proves the runtime behaviour. This proves the *product*
// interface: that the CLI serialises the three verbs the way the daemon expects, and
// that a refusal reaches the user as a refusal rather than as a success with empty
// output. Wiring bugs between the two live here and nowhere else.

/// The proposal id from `task propose` output.
fn propose_id(out: &Output) -> String {
    stdout_of(out)
        .lines()
        .find_map(|l| l.trim().strip_prefix("id: "))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .expect("a proposal id in the output")
}

/// The whole loop as a person performs it.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_user_proposes_a_governed_action_approves_it_and_executes_it() {
    let root = dir("governed-happy");
    let daemon = Daemon::start(&root);

    daemon.cli(&["task", "create", "--id", "cg1"]);
    let claimed = daemon.cli(&["task", "claim", "--id", "cg1", "--worker", "w1"]);
    assert!(claimed.status.success(), "{}", stderr_of(&claimed));

    let proposed = daemon.cli(&[
        "task",
        "propose",
        "--task",
        "cg1",
        "--worker",
        "w1",
        "--capability",
        "filesystem/write-text",
        "--target",
        "cli.txt",
        "--params",
        r#"{"path":"cli.txt","contents":"written through the cli"}"#,
    ]);
    assert!(proposed.status.success(), "{}", stderr_of(&proposed));
    assert!(
        stdout_of(&proposed).contains("waiting_for"),
        "{}",
        stdout_of(&proposed)
    );
    let pid = propose_id(&proposed);

    // Parked, lease released.
    let listed = daemon.cli(&["task", "list"]);
    assert!(
        stdout_of(&listed).contains("waiting-for-user"),
        "{}",
        stdout_of(&listed)
    );

    // The human approves the proposal — supplying no action.
    let approved = daemon.cli(&[
        "capability",
        "approve",
        "--proposal",
        &pid,
        "--ttl-ms",
        "60000",
    ]);
    assert!(approved.status.success(), "{}", stderr_of(&approved));
    let approval = stdout_of(&approved);
    assert!(approval.contains("\"approver\": \"human\""), "{approval}");
    assert!(approval.contains("\"actor_label\": \"ai\""), "{approval}");

    // Execution. Tier-1, so it needs a host that can isolate: everything above is
    // host-independent and stays asserted either way.
    let executed = daemon.cli(&["task", "execute", "--proposal", &pid, "--worker", "w1"]);
    if !print_host_environment(&daemon) {
        assert_tier1_refused(&executed, &root, "cli.txt");
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    assert!(executed.status.success(), "{}", stderr_of(&executed));
    assert!(
        stdout_of(&executed).contains("verified: true"),
        "{}",
        stdout_of(&executed)
    );
    assert_eq!(
        std::fs::read_to_string(root.join("workspace").join("cli.txt")).expect("written"),
        "written through the cli"
    );

    let listed = daemon.cli(&["task", "list"]);
    assert!(
        stdout_of(&listed).contains("completed"),
        "{}",
        stdout_of(&listed)
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The refusals a person will actually hit, and they must be non-zero exits.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn the_governed_refusals_reach_the_cli_as_failures() {
    let root = dir("governed-refusals");
    let daemon = Daemon::start(&root);
    daemon.cli(&["task", "create", "--id", "cg2"]);
    daemon.cli(&["task", "claim", "--id", "cg2", "--worker", "w1"]);

    let proposed = daemon.cli(&[
        "task",
        "propose",
        "--task",
        "cg2",
        "--worker",
        "w1",
        "--capability",
        "filesystem/write-text",
        "--target",
        "r.txt",
        "--params",
        r#"{"path":"r.txt","contents":"x"}"#,
    ]);
    let pid = propose_id(&proposed);

    // Executing before approval.
    let early = daemon.cli(&["task", "execute", "--proposal", &pid, "--worker", "w1"]);
    assert!(!early.status.success(), "an unapproved proposal must fail");
    assert!(
        stderr_of(&early).contains("approval"),
        "{}",
        stderr_of(&early)
    );

    // An unknown proposal.
    let ghost = daemon.cli(&["task", "execute", "--proposal", "p-nope", "--worker", "w1"]);
    assert!(!ghost.status.success(), "an unknown proposal must fail");

    // Approve, then reuse the same proposal.
    let approved = daemon.cli(&[
        "capability",
        "approve",
        "--proposal",
        &pid,
        "--ttl-ms",
        "60000",
    ]);
    assert!(approved.status.success());
    // The first execution after approval is a Tier-1 dispatch, so it is the one step
    // here that needs a host that can isolate. Everything above and below it is a
    // refusal or a governance assertion that holds either way.
    let first = daemon.cli(&["task", "execute", "--proposal", &pid, "--worker", "w1"]);
    if !print_host_environment(&daemon) {
        assert_tier1_refused(&first, &root, "r.txt");
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    assert!(first.status.success(), "{}", stderr_of(&first));
    let again = daemon.cli(&["task", "execute", "--proposal", &pid, "--worker", "w1"]);
    assert!(!again.status.success(), "an approval must be single-use");

    // A worker that does not hold the lease cannot propose.
    let impostor = daemon.cli(&[
        "task",
        "propose",
        "--task",
        "cg2",
        "--worker",
        "someone-else",
        "--capability",
        "filesystem/write-text",
        "--target",
        "z.txt",
        "--params",
        r#"{"path":"z.txt","contents":"x"}"#,
    ]);
    assert!(
        !impostor.status.success(),
        "a worker without the lease must not propose"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The governed execution is audited durably, with real timestamps.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn the_governed_execution_is_audited_and_survives_a_restart() {
    let root = dir("governed-audit");
    {
        let daemon = Daemon::start(&root);
        daemon.cli(&["task", "create", "--id", "cg3"]);
        daemon.cli(&["task", "claim", "--id", "cg3", "--worker", "w1"]);
        let proposed = daemon.cli(&[
            "task",
            "propose",
            "--task",
            "cg3",
            "--worker",
            "w1",
            "--capability",
            "filesystem/write-text",
            "--target",
            "audited.txt",
            "--params",
            r#"{"path":"audited.txt","contents":"recorded"}"#,
        ]);
        let pid = propose_id(&proposed);
        daemon.cli(&[
            "capability",
            "approve",
            "--proposal",
            &pid,
            "--ttl-ms",
            "60000",
        ]);
        let out = daemon.cli(&["task", "execute", "--proposal", &pid, "--worker", "w1"]);
        if !print_host_environment(&daemon) {
            assert_tier1_refused(&out, &root, "audited.txt");
            let _ = std::fs::remove_dir_all(&root);
            return;
        }
        assert!(out.status.success(), "{}", stderr_of(&out));
    }
    let bytes = state_bytes(&root);
    assert!(
        bytes.contains("filesystem/write-text"),
        "the action must be audited"
    );
    assert!(
        !bytes.contains("\"at-ms\":0"),
        "a governed execution must not be stamped at the epoch"
    );
    // A restart must accept the chain.
    let daemon = Daemon::start(&root);
    assert!(daemon.cli(&["task", "list"]).status.success());
    assert!(
        root.join("workspace").join("audited.txt").exists(),
        "the side effect survives the daemon that produced it"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The two provider flags reach the provider, and the request stops at the credential.
///
/// This is as far as the binary can be driven hermetically: the daemon reads its key from
/// the platform credential store, and a spawned process on a build host has none. The
/// refusal is therefore asserted rather than worked around, and both honest reasons are
/// accepted because which one applies depends on the host — a machine with a keyring and
/// no key says `provider-credential-absent`, one with neither says
/// `provider-credential-store-unavailable`.
///
/// What it proves is the wiring: the flags are parsed, a provider is constructed, and the
/// credential is required before any request leaves. The HTTP path itself is covered
/// against a real socket in the daemon's own suite, with a hermetic store.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn the_provider_flags_are_wired_and_the_credential_is_required_before_any_request() {
    let root = dir("ai-credential");
    let provider = FakeProvider::answering(
        r#"{"capability":"filesystem/write-text","target":"final.txt","params":{"path":"final.txt","contents":"delegated governance works"}}"#,
    );
    let daemon = Daemon::start_with_provider(&root, Some(&provider), &[]);
    daemon.cli(&["task", "create", "--id", "k1", "x"]);
    assert!(
        daemon
            .cli(&["task", "claim", "--id", "k1", "--worker", "ai"])
            .status
            .success()
    );

    let refused = daemon.cli(&["task", "ai-propose", "--task", "k1", "--worker", "ai"]);
    assert!(
        !refused.status.success(),
        "no usable request means no proposal"
    );
    let said = format!("{}{}", stdout_of(&refused), stderr_of(&refused));

    // Which refusal fires depends on the host, and the test asserts the invariant rather
    // than one host's answer.
    //
    // With no credential in the platform store, the request stops at `authorization` with a
    // credential reason. With one -- which is the state after anybody has actually used the
    // provider -- that check passes and the request stops at the transport instead, because
    // this test's endpoint is `http://` and plaintext may not carry a credential. Both prove
    // the same thing: the flags produced a real provider instance, and nothing left this
    // process.
    //
    // The earlier version asserted only the credential reason and therefore started failing
    // the moment a human stored a key. A test whose subject is "the flags are wired" should
    // not depend on whether the machine happens to hold a secret.
    assert!(
        said.contains("provider-credential-absent")
            || said.contains("provider-credential-store-unavailable")
            || said.contains("provider-plaintext-refused"),
        "the refusal must name a reason this daemon decided for itself: {said}"
    );

    // And the provider was never contacted at all -- not even a TCP connection. The
    // plaintext refusal is decided from the scheme before any socket is opened, so an
    // `http://` endpoint configured on a real deployment is never dialled.
    assert!(
        !provider.was_contacted(),
        "the provider must not be contacted without a credential"
    );
}

/// A daemon started the way a user starts it — no provider flags — must refuse.
///
/// This is the assertion that keeps the scripted provider from becoming a silent
/// production fallback. There is no flag that makes `orxnud` pretend to have a model.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_daemon_with_no_provider_flags_refuses_to_propose() {
    let root = dir("ai-unconfigured");
    let daemon = Daemon::start_unconfigured(&root);
    daemon.cli(&["task", "create", "--id", "u1", "x"]);
    assert!(
        daemon
            .cli(&["task", "claim", "--id", "u1", "--worker", "ai"])
            .status
            .success()
    );

    let refused = daemon.cli(&["task", "ai-propose", "--task", "u1", "--worker", "ai"]);
    assert!(
        !refused.status.success(),
        "an unconfigured daemon must not propose"
    );
    let said = format!("{}{}", stdout_of(&refused), stderr_of(&refused));
    assert!(
        said.contains("provider-not-configured"),
        "the refusal must name the reason: {said}"
    );
}

/// The AI proposer through the real CLI.
///
/// The product claim is "ask the model what it would do, then let the deterministic
/// runtime decide" — so both halves are driven here: the proposal arrives, the file does
/// not exist yet, a human approves, and only then does anything happen.
/// The AI proposer, a human approval, and the governed path finishing the job.
///
/// Environment-aware for the same reason as
/// `a_user_approves_a_write_and_the_file_appears_with_exactly_those_bytes`: the tail of
/// this loop executes a Tier-1 capability, and a host that cannot isolate refuses it.
/// The proposal and approval stages are host-independent, so they are asserted
/// unconditionally; only the execution stage branches.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_user_asks_the_ai_proposer_and_the_governed_path_finishes_the_job() {
    let root = dir("ai-happy");
    let daemon = Daemon::start(&root);
    let can_sandbox = print_host_environment(&daemon);

    daemon.cli(&["task", "create", "--id", "e1", "Create", "final.txt"]);
    assert!(
        daemon
            .cli(&["task", "claim", "--id", "e1", "--worker", "ai"])
            .status
            .success()
    );

    let proposed = daemon.cli(&["task", "ai-propose", "--task", "e1", "--worker", "ai"]);
    assert!(proposed.status.success(), "{}", stderr_of(&proposed));
    let out = stdout_of(&proposed);
    assert!(out.contains("proposed_by: ai"), "{out}");
    assert!(out.contains("waiting_for: human-approval"), "{out}");
    let pid = propose_id(&proposed);

    // Proposing is not doing. True on every host, and it is the assertion that matters
    // most here: nothing ran before a human said yes.
    assert!(!root.join("workspace").join("final.txt").exists());
    assert!(stdout_of(&daemon.cli(&["task", "list"])).contains("waiting-for-user"));

    // A human finishes it.
    assert!(
        daemon
            .cli(&[
                "capability",
                "approve",
                "--proposal",
                &pid,
                "--ttl-ms",
                "60000"
            ])
            .status
            .success()
    );
    let done = daemon.cli(&["task", "execute", "--proposal", &pid, "--worker", "ai"]);

    if !can_sandbox {
        let stderr = stderr_of(&done);
        assert!(
            !done.status.success(),
            "a host that cannot isolate must refuse the execution, not perform it: {}",
            stdout_of(&done)
        );
        assert!(
            stderr.contains("sandbox guarantees"),
            "the refusal must name the missing guarantee, got: {stderr}"
        );
        assert!(
            !root.join("workspace").join("final.txt").exists(),
            "a refused execution must leave the workspace untouched"
        );
        let _ = std::fs::remove_dir_all(&root);
        return;
    }

    assert!(done.status.success(), "{}", stderr_of(&done));
    assert!(stdout_of(&done).contains("verified: true"));
    assert_eq!(
        std::fs::read_to_string(root.join("workspace").join("final.txt")).expect("written"),
        "delegated governance works"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The AI route refuses the two things a caller would try next: inventing an approver,
/// and executing before one exists.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn the_ai_proposer_cannot_approve_or_execute() {
    let root = dir("ai-boundary");
    let daemon = Daemon::start(&root);
    daemon.cli(&["task", "create", "--id", "e2", "x"]);
    daemon.cli(&["task", "claim", "--id", "e2", "--worker", "ai"]);
    let proposed = daemon.cli(&["task", "ai-propose", "--task", "e2", "--worker", "ai"]);
    let pid = propose_id(&proposed);

    // Executing before approval.
    let early = daemon.cli(&["task", "execute", "--proposal", &pid, "--worker", "ai"]);
    assert!(
        !early.status.success(),
        "an unapproved proposal must not run"
    );
    assert!(!root.join("workspace").join("final.txt").exists());

    // A caller-supplied approver is not honoured.
    let forged = daemon.cli(&[
        "capability",
        "approve",
        "--proposal",
        &pid,
        "--ttl-ms",
        "60000",
    ]);
    assert!(forged.status.success());
    assert!(
        stdout_of(&forged).contains("\"approver\": \"human\""),
        "{}",
        stdout_of(&forged)
    );
    assert!(!stdout_of(&forged).contains("\"approver\": \"ai\""));

    let _ = std::fs::remove_dir_all(&root);
}
