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
///
/// The binary belongs to another package, so `cargo test -p orxnuctl` does **not**
/// rebuild it: the suite would otherwise run against whatever was last built,
/// and a stale daemon would quietly become the thing under test. The check below
/// refuses that, rather than letting a green suite certify the wrong binary.
fn daemon_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    // deps/ -> <profile>/ ; the binaries are siblings of deps/.
    let profile = exe
        .parent()
        .expect("deps directory")
        .parent()
        .expect("profile");
    let binary = profile.join("orxnud");
    assert_the_daemon_binary_is_current(&binary);
    binary
}

/// Whether the daemon binary is at least as new as the daemon's own source.
///
/// Skipped when the daemon crate cannot be found, which is the case in a
/// packaged build; there is nothing to compare against.
fn assert_the_daemon_binary_is_current(binary: &std::path::Path) {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("orxnud-daemon").join("src"));
    let Some(source) = source else { return };
    if !source.is_dir() {
        return;
    }
    let newest = |dir: &std::path::Path| -> Option<std::time::SystemTime> {
        let mut newest = None;
        let mut stack = vec![dir.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(modified) = entry.metadata().and_then(|m| m.modified()) {
                    newest =
                        Some(newest.map_or(modified, |n: std::time::SystemTime| n.max(modified)));
                }
            }
        }
        newest
    };
    let (Ok(binary_time), Some(source_time)) = (
        std::fs::metadata(binary).and_then(|m| m.modified()),
        newest(&source),
    ) else {
        return;
    };
    assert!(
        binary_time >= source_time,
        "the daemon binary at {} is older than the daemon's source: run \
         `cargo build -p orxnud-daemon --bin orxnud` before this suite, or the \
         tests will certify a stale daemon",
        binary.display()
    );
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
        Self::start_with_env(root, &[], provider, extra)
    }

    /// Starts a daemon with extra environment variables.
    ///
    /// The variables belong to this child process only. Nothing global is changed,
    /// so a developer's own session, credential store and bus are untouched.
    fn start_with_env(
        root: &Path,
        env: &[(&str, &str)],
        provider: Option<&FakeProvider>,
        extra: &[&str],
    ) -> Self {
        let mut command = Command::new(daemon_bin());
        command.arg("--state-root").arg(root);
        for (name, value) in env {
            command.env(name, value);
        }
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
            // R-1's exception, granted to the daemon this harness spawns.
            //
            // There is no configuration key and no environment variable for this -- see `Daemon`
            // in `lib.rs` -- so the route is a flag that exists only in a debug build. A shipped
            // release binary has no way to permit an argv payload at all. These suites measure the
            // governed path (approval, single use, expiry, settlement, audit across restart) and
            // need a capability that actually executes; this is how they get one.
            //
            // It does NOT satisfy R-1 option 2 (owner, bounded period, review date). See the open
            // owner decision in `docs/18` section 12.
            .arg("--permit-argv-payload-exposure-for-tests")
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

    /// Starts a daemon pointed at a TLS provider.
    ///
    /// The provider's certificate is handed to the daemon through `SSL_CERT_FILE`,
    /// which is where the platform keeps the roots it already trusts. The daemon's
    /// own transport rules are untouched.
    fn start_with_tls_provider(
        root: &Path,
        provider: &TlsProvider,
        credential_file: &Path,
    ) -> Self {
        Self::start_with_tls_provider_at(root, provider, credential_file, "/v1", false).0
    }

    /// Starts a daemon pointed at a TLS provider, at `path` after the authority.
    ///
    /// `path` is the provider's path prefix, so a scenario can configure an
    /// endpoint the safe-label projection refuses without touching the transport.
    /// With `capture_stderr`, the daemon's own standard error is collected.
    fn start_with_tls_provider_at(
        root: &Path,
        provider: &TlsProvider,
        credential_file: &Path,
        path: &str,
        capture_stderr: bool,
    ) -> (Self, Option<CapturedStderr>) {
        Self::start_with_tls_provider_base(
            root,
            provider,
            credential_file,
            &format!("https://{}{path}", provider.address),
            capture_stderr,
        )
    }

    /// Starts a daemon pointed at `base_url`, exactly as configured.
    ///
    /// The URL is used as given: the daemon's configuration is not the thing under
    /// test here, only what the daemon says about it.
    fn start_with_tls_provider_base(
        root: &Path,
        provider: &TlsProvider,
        credential_file: &Path,
        base_url: &str,
        capture_stderr: bool,
    ) -> (Self, Option<CapturedStderr>) {
        let mut command = Command::new(daemon_bin());
        command
            .arg("--state-root")
            .arg(root)
            .arg("--provider-base-url")
            .arg(base_url)
            .arg("--provider-model")
            .arg("fake-model-1")
            .arg("--provider-credential-file")
            .arg(credential_file)
            .arg("--permit-argv-payload-exposure-for-tests")
            .env("SSL_CERT_FILE", &provider.cert_file)
            // The ambient credential store is made unreachable for this process, so
            // the test does not depend on the machine holding a usable secret. The
            // variable belongs to this child alone.
            .env("DBUS_SESSION_BUS_ADDRESS", BROKEN_SESSION_BUS)
            .stdout(Stdio::null());
        if capture_stderr {
            command.stderr(Stdio::piped());
        } else {
            command.stderr(Stdio::null());
        }
        let mut child = command.spawn().expect("spawn orxnud");
        let captured = if capture_stderr {
            child.stderr.take().map(CapturedStderr::collect)
        } else {
            None
        };
        let d = Self {
            child,
            root: root.to_path_buf(),
        };
        d.await_ready();
        (d, captured)
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

/// The whole loop as a person performs it.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_person_can_run_a_two_step_task_through_continue_and_the_capability_approve_gate() {
    let root = dir("multi-step");
    let daemon = Daemon::start(&root);

    // A task is single-step unless it asks for more, so asking is the first thing that
    // makes a boundary reachable at all.
    let created = daemon.cli(&[
        "task",
        "create",
        "--id",
        "ms1",
        "--max-steps",
        "2",
        "write",
        "cli.txt",
    ]);
    assert!(created.status.success(), "{}", stderr_of(&created));
    assert!(
        stdout_of(&created).contains("max_steps: 2"),
        "{}",
        stdout_of(&created)
    );

    let claimed = daemon.cli(&["task", "claim", "--id", "ms1", "--worker", "w1"]);
    assert!(claimed.status.success(), "{}", stderr_of(&claimed));

    // Step 1, proposed by the model.
    let first = daemon.cli(&["task", "ai-propose", "--task", "ms1", "--worker", "w1"]);
    assert!(first.status.success(), "{}", stderr_of(&first));
    let p1 = propose_id(&first);

    let a1 = daemon.cli(&[
        "capability",
        "approve",
        "--proposal",
        &p1,
        "--ttl-ms",
        "60000",
    ]);
    assert!(a1.status.success(), "{}", stderr_of(&a1));

    let x1 = daemon.cli(&["task", "execute", "--proposal", &p1, "--worker", "w1"]);
    if !print_host_environment(&daemon) {
        // Everything above is host-independent. A host that cannot isolate is asserted as
        // the fail-closed refusal rather than skipped, per the same rule as the other
        // Tier-1 tests.
        assert_tier1_refused(&x1, &root, "cli.txt");
        let _ = std::fs::remove_dir_all(&root);
        return;
    }
    assert!(x1.status.success(), "{}", stderr_of(&x1));
    assert!(
        stdout_of(&x1).contains("verified: true"),
        "{}",
        stdout_of(&x1)
    );

    // The verified step parked the task at a boundary rather than finishing it.
    let listed = daemon.cli(&["task", "list"]);
    assert!(
        stdout_of(&listed).contains("awaiting-next-step"),
        "{}",
        stdout_of(&listed)
    );
    assert!(
        !stdout_of(&listed).contains("completed"),
        "a two-step task must not finish on its first step: {}",
        stdout_of(&listed)
    );

    // One `continue`: crosses the boundary and proposes step 2, ending in approval.
    let next = daemon.cli(&["task", "continue", "--task", "ms1", "--worker", "w1"]);
    assert!(next.status.success(), "{}", stderr_of(&next));
    let out = stdout_of(&next);
    assert!(out.contains("step: 2"), "{out}");
    assert!(out.contains("waiting_for: human-approval"), "{out}");
    assert!(out.contains("proposed_by: ai"), "{out}");
    let p2 = propose_id(&next);
    assert_ne!(p2, p1, "the second step needs its own proposal");

    // Continuing is not a way around the approval gate.
    let early = daemon.cli(&["task", "execute", "--proposal", &p2, "--worker", "w1"]);
    assert!(
        !early.status.success(),
        "an unapproved continuation must fail"
    );

    let a2 = daemon.cli(&[
        "capability",
        "approve",
        "--proposal",
        &p2,
        "--ttl-ms",
        "60000",
    ]);
    assert!(a2.status.success(), "{}", stderr_of(&a2));
    let x2 = daemon.cli(&["task", "execute", "--proposal", &p2, "--worker", "w1"]);
    assert!(x2.status.success(), "{}", stderr_of(&x2));
    assert!(
        stdout_of(&x2).contains("verified: true"),
        "{}",
        stdout_of(&x2)
    );

    // Both steps done, and `max_steps` finished the task without a `done` answer.
    // `task list` renders a table, so the state is read as a word in the row.
    let listed = daemon.cli(&["task", "list"]);
    let text = stdout_of(&listed);
    assert!(text.contains("ms1"), "{text}");
    assert!(
        text.contains("completed"),
        "the task must be completed: {text}"
    );
    assert!(
        !text.contains("awaiting-next-step"),
        "the task must not still be at a boundary: {text}"
    );

    // And there is no third step, because `max_steps` is the bound.
    let over = daemon.cli(&["task", "continue", "--task", "ms1", "--worker", "w1"]);
    assert!(!over.status.success(), "a finished task cannot continue");
    assert!(
        stderr_of(&over).contains("not-at-boundary"),
        "{}",
        stderr_of(&over)
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// An impossible `--max-steps` is refused by the daemon, not clamped by the CLI.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_impossible_max_steps_is_refused_rather_than_clamped() {
    let root = dir("max-steps-bounds");
    let daemon = Daemon::start(&root);

    // Nonsense syntax is the CLI's to refuse, naming the flag the user typed.
    let nonsense = daemon.cli(&[
        "task",
        "create",
        "--id",
        "bad",
        "--max-steps",
        "abc",
        "do",
        "it",
    ]);
    assert!(!nonsense.status.success(), "abc is not a step count");
    assert!(
        stderr_of(&nonsense).contains("--max-steps"),
        "{}",
        stderr_of(&nonsense)
    );

    // Impossible values are the daemon's to refuse: it owns the invariant, so the CLI
    // cannot become the place where a bound is quietly enforced twice.
    for bad in ["0", "1000"] {
        let out = daemon.cli(&[
            "task",
            "create",
            "--id",
            "bad",
            "--max-steps",
            bad,
            "do",
            "it",
        ]);
        assert!(
            !out.status.success(),
            "--max-steps {bad} must be refused, not stored: {}",
            stdout_of(&out)
        );
        assert!(
            stderr_of(&out).contains("max_steps"),
            "the daemon's refusal must name the field: {}",
            stderr_of(&out)
        );
    }

    // Nothing was created, so the task list has no such row.
    let listed = daemon.cli(&["task", "list"]);
    assert!(
        !stdout_of(&listed).contains("bad"),
        "{}",
        stdout_of(&listed)
    );

    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// A pseudo-terminal, so the CLI's own terminal check runs unchanged.
//
// The CLI refuses to take a disclosure confirmation unless `stdin.is_terminal()`.
// A pipe is not a terminal, so the interactive path cannot be reached without one --
// and the production check must not be weakened to reach it. `script(1)` is not
// available everywhere, so the pair is allocated here.
// ---------------------------------------------------------------------------

/// What a CLI run under a pseudo-terminal printed, and how it ended.
struct PtyRun {
    /// Everything the child wrote to the terminal.
    output: String,
    /// The child's exit code, when it exited normally.
    code: Option<i32>,
}

/// Runs `command` with its standard streams attached to a pseudo-terminal.
///
/// Waits until `prompt` appears, writes `answer`, and returns everything printed.
///
/// # Descriptors
///
/// The master is allocated by `rustix` and owned by a `File`, so it is closed exactly
/// once when this function returns. The slave is opened by path and handed to the
/// child as its standard streams, so the child owns those descriptors from the moment
/// it is spawned and this function never touches them again.
///
/// # Timeouts
///
/// A broken prompt or a stalled child cannot hang the suite: the wait is bounded, and a
/// child that has not exited by the deadline is killed.
fn run_under_pty(
    command: &mut std::process::Command,
    prompt: &str,
    answer: &str,
    timeout: std::time::Duration,
) -> PtyRun {
    use rustix::pty::{OpenptFlags, openpt, ptsname, unlockpt};
    use std::io::{Read as _, Write as _};

    // --- the master/slave pair -------------------------------------------
    // `rustix` offers the whole pseudo-terminal through safe calls, so this
    // helper contains no `unsafe` at all: the repository's rule is that `unsafe`
    // lives in the platform crates and nowhere else, and there is no reason for
    // a test helper to break it.
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).expect("a pty master");
    unlockpt(&master).expect("unlock the pty");
    // The master is owned by this `File`, so it is closed exactly once, when
    // this helper returns.
    let master = std::fs::File::from(master);
    let slave_path = ptsname(&master, Vec::new()).expect("the pty slave name");
    let slave = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(std::path::PathBuf::from(
            slave_path.to_string_lossy().into_owned(),
        ))
        .expect("open the pty slave");
    // The child owns the slave as its three standard streams from the moment it is
    // spawned; these clones are only to hand one descriptor to each stream.
    command.stdin(std::process::Stdio::from(
        slave.try_clone().expect("clone slave"),
    ));
    command.stdout(std::process::Stdio::from(
        slave.try_clone().expect("clone slave"),
    ));
    command.stderr(std::process::Stdio::from(slave));

    let mut child = command.spawn().expect("spawn the CLI under a pty");
    let mut writer = master
        .try_clone()
        .expect("clone the pty master for writing");

    // --- read until the prompt, answer, read the rest --------------------
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut reader = master
        .try_clone()
        .expect("clone the pty master for reading");
    std::thread::spawn(move || {
        let mut buf = [0_u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let deadline = std::time::Instant::now() + timeout;
    let mut seen = String::new();
    let mut answered = false;
    let mut exited = false;
    // A short tick, so a child that ends is noticed at once rather than when the
    // whole deadline expires.
    let tick = std::time::Duration::from_millis(100);
    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        match rx.recv_timeout(tick) {
            Ok(chunk) => {
                seen.push_str(&String::from_utf8_lossy(&chunk));
                if !answered && seen.contains(prompt) {
                    answered = true;
                    writer
                        .write_all(answer.as_bytes())
                        .expect("write the confirmation");
                    writer.flush().expect("flush the confirmation");
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if let Ok(Some(_)) = child.try_wait() {
            exited = true;
            // Drain what the child left in the terminal before it ended.
            while let Ok(chunk) = rx.recv_timeout(std::time::Duration::from_millis(100)) {
                seen.push_str(&String::from_utf8_lossy(&chunk));
            }
            break;
        }
    }
    if !exited {
        let _ = child.kill();
    }
    let status = child.wait().expect("wait for the CLI");
    PtyRun {
        output: seen,
        code: status.code(),
    }
}

/// A session bus that does not exist.
///
/// Set on the daemon this test spawns, so the platform credential store cannot be
/// reached from it. It is a per-process variable: nothing outside the test's own
/// child processes is affected, and the developer's credential store is neither
/// read nor modified.
const BROKEN_SESSION_BUS: &str = "unix:path=/nonexistent-orxnud-e2e-session-bus";

/// A credential generated for this test.
///
/// Random, synthetic, and never a real secret: it is written to a file under the
/// test's own temporary directory, it is never stored anywhere a user would find
/// it, and it is worthless outside this run.
fn synthetic_credential() -> String {
    use std::io::Read as _;
    let mut bytes = [0_u8; 24];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("the kernel's random source");
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("orxnud-e2e-synthetic-{hex}")
}

/// Writes the synthetic credential where the daemon can read it, and nowhere else.
fn write_credential_file(path: &std::path::Path, credential: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, credential).expect("write the synthetic credential");
    let mut permissions = std::fs::metadata(path).expect("stat").permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions).expect("restrict the credential file");
}

/// Sends one request to the provider **without** a credential, and returns the
/// response head.
///
/// The provider is supposed to refuse this. A provider that answered it would
/// prove nothing about the daemon's credential handling.
fn probe_without_credential(provider: &TlsProvider) -> String {
    use std::io::{Read as _, Write as _};
    let config = provider.client_config();
    let address = provider
        .address
        .parse::<std::net::SocketAddr>()
        .expect("the provider address");
    let socket = std::net::TcpStream::connect(address).expect("connect to the provider");
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1").expect("a server name");
    let connection = rustls::ClientConnection::new(config, name).expect("a TLS client");
    let mut tls = rustls::StreamOwned::new(connection, socket);
    tls.write_all(
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
    )
    .expect("write the probe request");
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 1024];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > 16 {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&raw).into_owned()
}

/// A daemon pointed at a credential file that is not there must refuse to start.
///
/// This is the proof that the file is the *only* source: there is no fallback to
/// the platform store, so a test that cannot establish isolation fails loudly
/// instead of quietly using the machine's own secret.
fn a_daemon_with_an_unusable_credential_file_refuses_to_start(root: &std::path::Path) {
    use std::io::Read as _;
    let mut command = std::process::Command::new(daemon_bin());
    command
        .arg("--state-root")
        .arg(root.join("refused-state"))
        .arg("--provider-base-url")
        .arg("https://127.0.0.1:1/v1")
        .arg("--provider-model")
        .arg("fake-model-1")
        .arg("--provider-credential-file")
        .arg(root.join("absent-credential"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("spawn the daemon");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut status = None;
    while std::time::Instant::now() < deadline {
        if let Ok(Some(s)) = child.try_wait() {
            status = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let Some(status) = status else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("the daemon neither started nor refused");
    };
    assert!(
        !status.success(),
        "a daemon with no usable credential file must not start"
    );
    let mut stderr = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut stderr);
    }
    assert!(
        stderr.contains("refusing to start"),
        "the refusal must be loud: {stderr}"
    );
}

/// The model-proposal the synthetic provider answers with.
///
/// The same shape the daemon's proposal parser reads from a model's answer, and the
/// same shape the daemon's own disclosure tests use for a read.
const READ_PROPOSAL_JSON: &str =
    r#"{"capability":"filesystem/read-text","target":"a.txt","params":{"path":"a.txt"}}"#;

/// The proposal id in a `task ai-propose` reply.
fn model_proposal_id(out: &Output) -> String {
    let text = stdout_of(out);
    text.lines()
        .find_map(|l| l.trim().strip_prefix("id: "))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .or_else(|| {
            let marker = "\"proposal_id\": \"";
            let start = text.find(marker)? + marker.len();
            let rest = &text[start..];
            let end = rest.find('"')?;
            Some(rest[..end].to_owned())
        })
        .unwrap_or_else(|| panic!("a proposal id in the output: {text}"))
}

/// A model-initiated file read, approved through the real interactive confirmation.
///
/// The real `orxnuctl` binary, the real daemon binary, the real Unix socket, and a
/// synthetic HTTP provider on loopback. The CLI's own `stdin.is_terminal()` check runs
/// unchanged, because the confirmation is typed into a real pseudo-terminal.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket daemon evidence: starts a real orxnud and talks to it over a Unix domain socket; the local IPC transport refuses on Windows rather than binding a named pipe"
)]
#[test]
fn a_model_initiated_read_is_approved_through_an_interactive_confirmation() {
    use std::time::Duration;

    let root = dir("read-pty");
    let ws = workspace(&root);
    std::fs::create_dir_all(&ws).expect("mkdir the workspace");
    let sentinel = "PTY-READ-SENTINEL-4b7e2a";
    std::fs::write(ws.join("a.txt"), sentinel).expect("seed the file");

    // An isolated, synthetic credential, written under this test's own temporary
    // directory. The daemon reads it from there and nowhere else.
    let credential = synthetic_credential();
    let credential_file = root.join("provider-credential");
    write_credential_file(&credential_file, &credential);

    // The synthetic provider, answering with a model-initiated read proposal. It
    // requires the credential, so a daemon that used anything else would be refused.
    let provider = TlsProvider::answering(READ_PROPOSAL_JSON, &credential);
    let daemon = Daemon::start_with_tls_provider(&root, &provider, &credential_file);

    // The provider refuses an unauthenticated request.
    let refused = probe_without_credential(&provider);
    assert!(
        refused.starts_with("HTTP/1.1 401"),
        "the provider must refuse a request without the credential: {refused}"
    );
    assert_eq!(
        provider.rejected(),
        vec!["<none>".to_owned()],
        "the refusal must be recorded"
    );

    // A daemon that cannot establish the credential refuses to start, rather than
    // falling back to whatever the machine's own credential store holds.
    a_daemon_with_an_unusable_credential_file_refuses_to_start(&root);

    // The other half of the isolation claim. A daemon with **no** credential file,
    // in a process where the ambient credential store is unreachable, cannot
    // authenticate at all -- so the daemon above succeeded because of the
    // synthetic credential, and not because the machine happened to hold a usable
    // secret.
    let ambient_root = root.join("ambient");
    std::fs::create_dir_all(&ambient_root).expect("mkdir the ambient daemon's root");
    let ambient = Daemon::start_with_env(
        &ambient_root,
        &[("DBUS_SESSION_BUS_ADDRESS", BROKEN_SESSION_BUS)],
        None,
        &[
            "--provider-base-url",
            "https://127.0.0.1:1/v1",
            "--provider-model",
            "fake-model-1",
        ],
    );
    ambient.cli(&["task", "create", "--id", "ambient-1"]);
    ambient.cli(&["task", "claim", "--id", "ambient-1", "--worker", "w1"]);
    let refused = ambient.cli(&[
        "task",
        "ai-propose",
        "--task",
        "ambient-1",
        "--worker",
        "w1",
    ]);
    assert!(
        !refused.status.success(),
        "a daemon with no credential and no ambient store must not propose"
    );
    let said = format!("{}{}", stdout_of(&refused), stderr_of(&refused));
    assert!(
        said.contains("credential"),
        "the refusal must name the credential: {said}"
    );

    // Create and claim a task, then ask the model for a proposal.
    let created = daemon.cli(&["task", "create", "--id", "pty-1"]);
    assert!(created.status.success(), "{}", stderr_of(&created));
    let claimed = daemon.cli(&["task", "claim", "--id", "pty-1", "--worker", "w1"]);
    assert!(claimed.status.success(), "{}", stderr_of(&claimed));
    let proposed = daemon.cli(&["task", "ai-propose", "--task", "pty-1", "--worker", "w1"]);
    assert!(
        proposed.status.success(),
        "the model must propose: {}\n{}",
        stdout_of(&proposed),
        stderr_of(&proposed)
    );
    let proposal_id = model_proposal_id(&proposed);
    eprintln!("proposal id: {proposal_id}");

    // The interactive leg, on a real pseudo-terminal.
    let mut command = std::process::Command::new(cli_bin());
    command
        .args(["capability", "approve", "--proposal", &proposal_id])
        .arg("--endpoint")
        .arg(daemon.endpoint());
    let run = run_under_pty(&mut command, "[y/N]", "yes\n", Duration::from_secs(60));
    eprintln!("--- the approval on the terminal ---\n{}", run.output);
    assert_eq!(run.code, Some(0), "the CLI must succeed: {}", run.output);
    let out = run.output;

    // The rendered preview, from the fresh challenge-bearing response.
    assert!(
        out.contains(&proposal_id),
        "the proposal id must be shown: {out}"
    );
    assert!(
        out.contains("filesystem/read-text"),
        "the capability must be shown: {out}"
    );
    assert!(
        out.contains("path:       a.txt"),
        "the exact path must be shown: {out}"
    );
    assert!(
        out.contains("this READS a file; it does not write one."),
        "the read-versus-write distinction must be shown: {out}"
    );
    assert!(
        out.contains("MAY BE DISCLOSED"),
        "the disclosure consequence must be shown: {out}"
    );
    assert!(
        out.contains("recipient:"),
        "the recipient must be shown: {out}"
    );
    assert!(
        out.contains("at most 65536 bytes"),
        "the 64 KiB read ceiling must be shown: {out}"
    );
    assert!(
        out.contains("at most 32768 bytes"),
        "the 32 KiB observation ceiling must be shown: {out}"
    );
    assert!(
        out.contains("at most 8 entries"),
        "the eight-entry maximum must be shown: {out}"
    );
    assert!(
        out.contains("skipped entirely, not truncated"),
        "the whole-observation skip rule must be shown: {out}"
    );
    assert!(
        out.contains("one too large for the budget is skipped whole"),
        "the whole-observation rule must be shown: {out}"
    );
    assert!(
        out.contains(
            "eligible content is available only to the immediately following logical step"
        ),
        "the next-step limitation must be shown: {out}"
    );
    assert!(
        out.contains("Eligibility is limited to the immediately following logical step"),
        "the server's timing statement must be shown: {out}"
    );
    // The recipient is the safe label the daemon produced: the origin of the
    // provider, with no userinfo, no query and no fragment in it.
    let recipient = out
        .lines()
        .find_map(|l| l.trim().strip_prefix("recipient:"))
        .expect("the recipient line");
    for forbidden in ['@', '?', '#'] {
        assert!(
            !recipient.contains(forbidden),
            "the recipient label must not carry {forbidden:?}: {recipient}"
        );
    }
    for canary in ["query_token", "fragment"] {
        assert!(
            !out.contains(canary),
            "a canary reached the terminal: {out}"
        );
    }
    // The human's affirmative is on the record, and nothing else was typed.
    assert!(
        out.contains("yes"),
        "the typed confirmation must be shown: {out}"
    );
    // The approval was issued to a human, for an AI originator.
    assert!(out.contains("\"approver\": \"human\""), "{out}");
    assert!(out.contains("\"actor_label\": \"ai\""), "{out}");
    // No file contents on the terminal, and no raw endpoint.
    assert!(
        !out.contains(sentinel),
        "the file's contents reached the terminal: {out}"
    );
    for canary in ["userinfo", "query_token", "fragment"] {
        assert!(
            !out.contains(canary),
            "a canary reached the terminal: {out}"
        );
    }

    // Execute the approved read through the supported command.
    let executed = daemon.cli(&[
        "task",
        "execute",
        "--proposal",
        &proposal_id,
        "--worker",
        "w1",
    ]);
    eprintln!(
        "--- the execution ---\n{}\n{}",
        stdout_of(&executed),
        stderr_of(&executed)
    );
    assert!(
        executed.status.success(),
        "the approved read must execute: {}\n{}",
        stdout_of(&executed),
        stderr_of(&executed)
    );

    // The approval is single-use: a second approval of the same proposal must be
    // refused, so exactly one approval can exist for it.
    let again = daemon.cli(&["capability", "approve", "--proposal", &proposal_id]);
    assert!(
        !again.status.success(),
        "a second approval must be refused: {}\n{}",
        stdout_of(&again),
        stderr_of(&again)
    );
    assert!(
        !format!("{}{}", stdout_of(&again), stderr_of(&again)).contains("\"approver\": \"human\""),
        "a second approval must not be issued"
    );

    // The proposal reached a decided state.
    let listed = daemon.cli(&["task", "list"]);
    assert!(
        stdout_of(&listed).contains("completed"),
        "the task must be completed: {}",
        stdout_of(&listed)
    );

    // Durable state: the approval is there, and the file's contents are not.
    let state = state_bytes(&root);
    assert!(
        state.contains(&proposal_id),
        "the proposal must be in the durable state"
    );
    assert!(
        !state.contains(sentinel),
        "the file's contents must not be in the durable state"
    );
    // The provider was really contacted: this was a model-originated proposal, and
    // it went over the ordinary OpenAI-compatible request the product makes.
    assert!(
        provider.was_contacted(),
        "the synthetic provider must have been asked"
    );
    let requests = provider.requests();
    assert_eq!(requests.len(), 1, "one provider request: {requests:?}");
    let request = &requests[0];
    assert!(
        request.contains("POST /v1/chat/completions"),
        "the ordinary provider path must be used: {request}"
    );
    assert!(
        request.contains("fake-model-1"),
        "the configured model must be asked for: {request}"
    );
    assert!(
        !request.contains(sentinel),
        "the model must not have been given the file's contents: {request}"
    );
    // The daemon authenticated with the synthetic credential, and only that one.
    assert!(
        request.contains(&format!("Authorization: Bearer {credential}")),
        "the daemon must have authenticated with the synthetic credential: {request}"
    );
    assert_eq!(
        provider.rejected(),
        vec!["<none>".to_owned()],
        "nothing else may have been refused: {:?}",
        provider.rejected()
    );

    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// A synthetic provider that speaks TLS.
//
// The shipped daemon refuses a plaintext provider, and it has no opt-in: a flag
// that turns off a transport guarantee is not a test affordance, it is a hole.
// So the fake provider serves HTTPS with a certificate it generates itself, and
// the daemon is told to trust it the way the platform already tells it to trust
// roots -- through the host trust store, which `rustls-native-certs` reads from
// `SSL_CERT_FILE` on Linux. Nothing in the product changes, and no test-only
// switch is added to it.
// ---------------------------------------------------------------------------

/// A synthetic OpenAI-compatible provider on a loopback TLS port.
struct TlsProvider {
    /// `host:port` of the loopback listener.
    address: String,
    /// The certificate, in PEM, for the daemon to trust.
    cert_file: std::path::PathBuf,
    /// Whether anything has connected.
    contacted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Every request the provider received, verbatim.
    requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// Every credential the provider was offered and refused.
    rejected: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// The provider's certificate, for a client that has to trust it.
    certificate_der: Vec<u8>,
    /// The accept loop.
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TlsProvider {
    /// Starts a provider that answers every request with `content`.
    ///
    /// The provider **requires** the credential: a request that does not carry
    /// `Authorization: Bearer {credential}` is answered `401` and recorded as
    /// rejected. A provider that answered an unauthenticated request would prove
    /// nothing about the daemon's credential handling.
    fn answering(content: &str, credential: &str) -> Self {
        use rcgen::{CertificateParams, KeyPair, SanType};
        use std::io::{Read as _, Write as _};

        let mut params = CertificateParams::new(Vec::new()).expect("certificate parameters");
        // The daemon dials an IP, so the certificate must carry an IP subject
        // alternative name: a DNS name would not verify for `127.0.0.1`.
        params.subject_alt_names = vec![SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        ))];
        let key = KeyPair::generate().expect("a key pair");
        let certificate = params.self_signed(&key).expect("a self-signed certificate");

        let certificate_der = certificate.der().to_vec();
        let certs = vec![rustls::pki_types::CertificateDer::from(
            certificate_der.clone(),
        )];
        let signing_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        );
        let config = std::sync::Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, signing_key)
                .expect("a TLS server configuration"),
        );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = listener.local_addr().expect("an address").to_string();
        // Unique per provider: the tests run in parallel in one process, and two
        // providers sharing one certificate file would trust each other's.
        let cert_file = std::env::temp_dir().join(format!(
            "orxnuctl-e2e-{}-provider-{}.pem",
            std::process::id(),
            address.rsplit(':').next().expect("a port")
        ));
        std::fs::write(&cert_file, certificate.pem()).expect("write the provider certificate");

        let contacted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&contacted);
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&requests);
        let rejected = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let refusals = std::sync::Arc::clone(&rejected);
        let content = content.to_owned();
        let expected = format!("Bearer {credential}");
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let Ok(connection) = rustls::ServerConnection::new(std::sync::Arc::clone(&config))
                else {
                    continue;
                };
                let mut tls = rustls::StreamOwned::new(connection, stream);
                let mut raw = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => raw.extend_from_slice(&chunk[..n]),
                    }
                    if raw.len() > 64 * 1024 {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&raw).into_owned();
                let presented = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.trim()
                            .eq_ignore_ascii_case("authorization")
                            .then(|| value.trim().to_owned())
                    })
                    .unwrap_or_default();
                if presented != expected {
                    // No credential, or the wrong one: refuse it, and say so in the
                    // log rather than answering a request nobody authenticated.
                    refusals
                        .lock()
                        .expect("the rejection log")
                        .push(if presented.is_empty() {
                            "<none>".to_owned()
                        } else {
                            presented
                        });
                    let response = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\
                                    Connection: close\r\n\r\n";
                    let _ = tls.write_all(response.as_bytes());
                    let _ = tls.flush();
                    let _ = tls.sock.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                recorded.lock().expect("the request log").push(head);
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
                let _ = tls.write_all(response.as_bytes());
                let _ = tls.flush();
                // The client asked for a close; end the session rather than
                // holding the connection open against a one-shot provider.
                let _ = tls.sock.shutdown(std::net::Shutdown::Both);
            }
        });

        Self {
            address,
            cert_file,
            certificate_der,
            contacted,
            requests,
            rejected,
            handle: Some(handle),
        }
    }

    /// Whether anything has connected.
    fn was_contacted(&self) -> bool {
        self.contacted.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Every request the provider received, verbatim.
    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("the request log").clone()
    }

    /// The literal request line of every request the provider received.
    ///
    /// The first line of an HTTP request is the request line, and it carries the
    /// request-target: the bytes the client actually put on the wire. Reading it
    /// here is how a test states what was sent, rather than what was configured.
    fn request_lines(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|head| head.lines().next().unwrap_or_default().to_owned())
            .collect()
    }

    /// Every credential the provider was offered and refused.
    fn rejected(&self) -> Vec<String> {
        self.rejected.lock().expect("the rejection log").clone()
    }

    /// A client configuration that trusts this provider's certificate.
    fn client_config(&self) -> std::sync::Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                self.certificate_der.clone(),
            ))
            .expect("the provider certificate is a certificate");
        std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }
}

impl Drop for TlsProvider {
    fn drop(&mut self) {
        let _ = self.handle.take();
        let _ = std::fs::remove_file(&self.cert_file);
    }
}

// ---------------------------------------------------------------------------
// The refusal paths, through the real CLI and the real daemon.
//
// Each scenario is independent: its own state root, its own workspace, its own
// synthetic credential, its own certificate, its own proposal and its own
// challenge. A challenge minted by one scenario can never be mistaken for
// another's, and a refusal in one is never evidence about another.
// ---------------------------------------------------------------------------

/// The daemon's standard error, collected while it runs.
///
/// A pipe nobody reads would fill and block the daemon, so it is drained by a
/// thread for as long as the daemon lives.
struct CapturedStderr {
    text: std::sync::Arc<std::sync::Mutex<String>>,
    /// Held so the draining thread outlives the daemon's standard error.
    _handle: Option<std::thread::JoinHandle<()>>,
}

impl CapturedStderr {
    fn collect(mut stderr: std::process::ChildStderr) -> Self {
        use std::io::Read as _;
        let text = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let sink = std::sync::Arc::clone(&text);
        let handle = std::thread::spawn(move || {
            let mut buf = [0_u8; 4096];
            loop {
                match stderr.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => sink
                        .lock()
                        .expect("the stderr log")
                        .push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
        Self {
            text,
            _handle: Some(handle),
        }
    }

    /// Everything the daemon has said so far.
    fn text(&self) -> String {
        self.text.lock().expect("the stderr log").clone()
    }
}

/// A recording proxy in front of the daemon's socket.
///
/// The CLI connects here. Every byte is forwarded to the real daemon unchanged,
/// and the method of each request and the value of each reply are recorded on
/// the way past.
///
/// This is how a scenario proves a request was **not** sent, and what the daemon
/// actually answered. An error message says what the client concluded; this says
/// what crossed the wire.
struct RecordingProxy {
    path: std::path::PathBuf,
    methods: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    replies: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl RecordingProxy {
    /// Starts a proxy in front of `target`.
    fn start(target: &std::path::Path, tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("orxnuctl-e2e-{}-{tag}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener =
            std::os::unix::net::UnixListener::bind(&path).expect("bind the proxy socket");
        let methods = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let replies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded_methods = std::sync::Arc::clone(&methods);
        let recorded_replies = std::sync::Arc::clone(&replies);
        let target = target.to_path_buf();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(client) = stream else { break };
                let Ok(server) = std::os::unix::net::UnixStream::connect(&target) else {
                    continue;
                };
                let mut server_write = server.try_clone().expect("clone the server socket");
                let mut server_read = server;
                let mut client_write = client.try_clone().expect("clone the client socket");
                let mut client_read = client;
                let up_methods = std::sync::Arc::clone(&recorded_methods);
                // Client to server: the request, recorded on the way past.
                let up = std::thread::spawn(move || {
                    use std::io::{Read as _, Write as _};
                    let mut buf = [0_u8; 8192];
                    let mut pending: Vec<u8> = Vec::new();
                    loop {
                        match client_read.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                pending.extend_from_slice(&buf[..n]);
                                // The local transport frames one JSON value per line.
                                while let Some(i) = pending.iter().position(|b| *b == b'\n') {
                                    let line: Vec<u8> = pending.drain(..=i).collect();
                                    let Ok(value) =
                                        serde_json::from_slice::<serde_json::Value>(&line)
                                    else {
                                        continue;
                                    };
                                    let Some(method) = value.get("method").and_then(|m| m.as_str())
                                    else {
                                        continue;
                                    };
                                    up_methods
                                        .lock()
                                        .expect("the method log")
                                        .push(method.to_owned());
                                }
                                if server_write.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
                // Server to client: the reply, recorded and passed on untouched.
                let down_replies = std::sync::Arc::clone(&recorded_replies);
                let down = std::thread::spawn(move || {
                    use std::io::{Read as _, Write as _};
                    let mut buf = [0_u8; 8192];
                    let mut pending: Vec<u8> = Vec::new();
                    loop {
                        match server_read.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                pending.extend_from_slice(&buf[..n]);
                                while let Some(i) = pending.iter().position(|b| *b == b'\n') {
                                    let line: Vec<u8> = pending.drain(..=i).collect();
                                    if let Ok(value) =
                                        serde_json::from_slice::<serde_json::Value>(&line)
                                    {
                                        down_replies.lock().expect("the reply log").push(value);
                                    }
                                }
                                if client_write.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
                let _ = up.join();
                let _ = down.join();
            }
        });
        Self {
            path,
            methods,
            replies,
            handle: Some(handle),
        }
    }

    /// The method of every request that crossed the wire.
    fn methods(&self) -> Vec<String> {
        self.methods.lock().expect("the method log").clone()
    }

    /// Every reply the daemon gave.
    fn replies(&self) -> Vec<serde_json::Value> {
        self.replies.lock().expect("the reply log").clone()
    }

    /// Every reply that carried a preview.
    fn previews(&self) -> Vec<serde_json::Value> {
        self.replies()
            .into_iter()
            .filter(|reply| reply.pointer("/result/preview").is_some())
            .map(|reply| {
                reply
                    .pointer("/result/preview")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)
            })
            .collect()
    }
}

impl Drop for RecordingProxy {
    fn drop(&mut self) {
        let _ = self.handle.take();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A daemon, a task, and a genuine model-initiated read proposal.
struct RefusalScenario {
    root: std::path::PathBuf,
    /// Held so the daemon outlives the scenario.
    _daemon: Daemon,
    provider: TlsProvider,
    proxy: RecordingProxy,
    task_id: String,
    proposal_id: String,
    sentinel: String,
    credential: String,
    stderr: Option<CapturedStderr>,
}

impl RefusalScenario {
    /// Starts an isolated daemon and produces a model-initiated read proposal.
    fn start(tag: &str, provider_path: &str) -> Self {
        Self::start_with(tag, provider_path, false)
    }

    fn start_with(tag: &str, provider_path: &str, capture_stderr: bool) -> Self {
        let root = dir(tag);
        let workspace = workspace(&root);
        std::fs::create_dir_all(&workspace).expect("mkdir the workspace");
        let sentinel = format!("REFUSAL-SENTINEL-{tag}-a91c");
        std::fs::write(workspace.join("a.txt"), &sentinel).expect("seed the file");
        let credential = synthetic_credential();
        let credential_file = root.join("provider-credential");
        write_credential_file(&credential_file, &credential);
        let provider = TlsProvider::answering(READ_PROPOSAL_JSON, &credential);
        let (daemon, stderr) = Daemon::start_with_tls_provider_at(
            &root,
            &provider,
            &credential_file,
            provider_path,
            capture_stderr,
        );
        let proxy = RecordingProxy::start(&daemon.endpoint(), tag);
        let task_id = format!("task-{tag}");
        daemon.cli(&["task", "create", "--id", &task_id]);
        let claimed = daemon.cli(&["task", "claim", "--id", &task_id, "--worker", "w1"]);
        assert!(claimed.status.success(), "{}", stderr_of(&claimed));
        let proposed = daemon.cli(&["task", "ai-propose", "--task", &task_id, "--worker", "w1"]);
        assert!(
            proposed.status.success(),
            "the model must propose: {}\n{}",
            stdout_of(&proposed),
            stderr_of(&proposed)
        );
        let proposal_id = model_proposal_id(&proposed);
        Self {
            root,
            _daemon: daemon,
            provider,
            proxy,
            task_id,
            proposal_id,
            sentinel,
            credential,
            stderr,
        }
    }

    /// The durable state, opened against the daemon's own database.
    fn state(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.root.join("state.db")).expect("open the state database")
    }

    /// The proposal's status in the durable state.
    fn proposal_status(&self) -> String {
        self.state()
            .query_row(
                "SELECT status FROM task_proposals WHERE proposal_id = ?1",
                [&self.proposal_id],
                |row| row.get(0),
            )
            .expect("the proposal must be in the durable state")
    }

    /// How many approvals exist for this scenario's task.
    fn approval_count(&self) -> i64 {
        self.state()
            .query_row(
                "SELECT COUNT(*) FROM task_approvals WHERE task_id = ?1",
                [&self.task_id],
                |row| row.get(0),
            )
            .expect("count the approvals")
    }

    /// How many effect records exist for this scenario's task.
    ///
    /// The effect ledger is where a performed read is recorded, so this is the
    /// marker that the read helper did not run.
    fn effect_count(&self) -> i64 {
        self.state()
            .query_row(
                "SELECT COUNT(*) FROM task_effects WHERE task_id = ?1",
                [&self.task_id],
                |row| row.get(0),
            )
            .expect("count the effects")
    }

    /// The task's state in the durable state.
    fn task_state(&self) -> String {
        self.state()
            .query_row(
                "SELECT state FROM tasks WHERE id = ?1",
                [&self.task_id],
                |row| row.get(0),
            )
            .expect("the task must be in the durable state")
    }

    /// The method of every request the CLI sent.
    fn methods(&self) -> Vec<String> {
        self.proxy.methods()
    }

    /// Every reply the daemon gave.
    fn replies(&self) -> Vec<serde_json::Value> {
        self.proxy.replies()
    }

    /// Every reply that carried a preview.
    fn previews(&self) -> Vec<serde_json::Value> {
        self.proxy.previews()
    }

    /// Whether an approval was submitted.
    fn approval_was_sent(&self) -> bool {
        self.methods().iter().any(|m| m == "capability/approve")
    }

    /// Everything the daemon said, if it was captured.
    fn daemon_stderr(&self) -> String {
        self.stderr
            .as_ref()
            .map_or_else(String::new, CapturedStderr::text)
    }
}

/// The operator declines. Nothing is approved, and nothing is read.
#[test]
fn an_operator_who_declines_leaves_the_read_unapproved() {
    let scenario = RefusalScenario::start("decline", "/v1");
    let mut command = std::process::Command::new(cli_bin());
    command
        .args(["capability", "approve", "--proposal", &scenario.proposal_id])
        .arg("--endpoint")
        .arg(scenario.proxy.path.clone());
    let run = run_under_pty(
        &mut command,
        "[y/N]",
        "n\n",
        std::time::Duration::from_secs(60),
    );
    assert_eq!(
        run.code,
        Some(0),
        "declining is a choice, not a failure: {}",
        run.output
    );
    assert!(
        run.output.contains("Declined"),
        "the decline must be reported: {}",
        run.output
    );
    // The disclosure really was shown before the question was asked.
    assert!(
        run.output.contains("MAY BE DISCLOSED"),
        "the preview must be rendered: {}",
        run.output
    );
    // The wire: no approval was submitted.
    assert!(
        !scenario.approval_was_sent(),
        "no approval may be sent: {:?}",
        scenario.methods()
    );
    // And the durable state agrees.
    assert_eq!(scenario.proposal_status(), "pending");
    assert_eq!(scenario.approval_count(), 0);
    assert_eq!(scenario.effect_count(), 0);
    assert_ne!(scenario.task_state(), "completed");
    // Nothing was disclosed to the provider beyond the proposal request itself.
    assert_eq!(scenario.provider.requests().len(), 1);
    // No secret and no file content on the terminal.
    assert!(!run.output.contains(&scenario.credential));
    assert!(!run.output.contains(&scenario.sentinel));
    let _ = std::fs::remove_dir_all(&scenario.root);
}

/// The operator's input reaches end-of-file. The CLI declines, and nothing is
/// approved.
#[test]
fn end_of_input_at_the_prompt_declines_without_approving_anything() {
    let scenario = RefusalScenario::start("eof", "/v1");
    let mut command = std::process::Command::new(cli_bin());
    command
        .args(["capability", "approve", "--proposal", &scenario.proposal_id])
        .arg("--endpoint")
        .arg(scenario.proxy.path.clone());
    // Ctrl-D is the terminal's end-of-input character. On a canonical terminal it
    // makes the line discipline deliver a zero-length read to the waiting process,
    // which is what `read_line` reports as end-of-file -- not a line, and not a
    // closed process.
    let run = run_under_pty(
        &mut command,
        "[y/N]",
        "\u{4}",
        std::time::Duration::from_secs(60),
    );
    assert_eq!(
        run.code,
        Some(0),
        "end of input declines, it does not fail: {}",
        run.output
    );
    assert!(
        run.output.contains("Declined"),
        "the decline must be reported: {}",
        run.output
    );
    // The prompt was really reached, and nothing was typed.
    assert!(run.output.contains("[y/N]"), "{}", run.output);
    assert!(
        !run.output.contains("[y/N] yes"),
        "nothing was typed: {}",
        run.output
    );
    // The wire: no approval was submitted.
    assert!(
        !scenario.approval_was_sent(),
        "no approval may be sent: {:?}",
        scenario.methods()
    );
    assert_eq!(scenario.proposal_status(), "pending");
    assert_eq!(scenario.approval_count(), 0);
    assert_eq!(scenario.effect_count(), 0);
    assert_ne!(scenario.task_state(), "completed");
    assert_eq!(scenario.provider.requests().len(), 1);
    assert!(!run.output.contains(&scenario.credential));
    assert!(!run.output.contains(&scenario.sentinel));
    let _ = std::fs::remove_dir_all(&scenario.root);
}

/// A caller with no terminal is refused, and it is refused **before** a
/// challenge-bearing preview is asked for.
#[test]
fn a_non_interactive_caller_is_refused_before_a_challenge_is_asked_for() {
    let scenario = RefusalScenario::start("non-interactive", "/v1");
    let mut command = std::process::Command::new(cli_bin());
    command
        .args(["capability", "approve", "--proposal", &scenario.proposal_id])
        .arg("--endpoint")
        .arg(scenario.proxy.path.clone())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = command.output().expect("run the CLI");
    assert!(
        !out.status.success(),
        "a non-interactive approval must fail"
    );
    let said = format!("{}{}", stdout_of(&out), stderr_of(&out));
    assert!(
        said.contains("interactive confirmation"),
        "the refusal must be explicit: {said}"
    );
    // The wire: exactly one preview, and it was the inspection. No
    // challenge-bearing preview was asked for, and no approval was sent.
    let methods = scenario.methods();
    assert_eq!(
        methods
            .iter()
            .filter(|m| *m == "capability/preview")
            .count(),
        1,
        "only the inspection may be requested: {methods:?}"
    );
    assert!(
        !scenario.approval_was_sent(),
        "no approval may be sent: {methods:?}"
    );
    assert_eq!(scenario.proposal_status(), "pending");
    assert_eq!(scenario.approval_count(), 0);
    assert_eq!(scenario.effect_count(), 0);
    assert_ne!(scenario.task_state(), "completed");
    assert_eq!(scenario.provider.requests().len(), 1);
    assert!(!said.contains(&scenario.credential));
    assert!(!said.contains(&scenario.sentinel));
    let _ = std::fs::remove_dir_all(&scenario.root);
}

/// A recipient that cannot be safely identified blocks the approval.
#[test]
fn a_recipient_that_cannot_be_identified_blocks_the_approval() {
    const CANARY: &str = "UNSAFE-DESTINATION-CANARY-4d19";
    // The transport is untouched: the provider is still local, still TLS, still
    // authenticated. Only the *path* of the endpoint is one the safe-label
    // projection refuses to show, because a query string is not something a URL
    // we are willing to display may carry.
    let scenario = RefusalScenario::start_with("blocked-recipient", &format!("/v1?{CANARY}"), true);

    // The proposal was produced: the transport and the credential are intact.
    assert!(!scenario.proposal_id.is_empty());

    // The CLI refuses, and it refuses without asking the operator anything.
    let mut command = std::process::Command::new(cli_bin());
    command
        .args(["capability", "approve", "--proposal", &scenario.proposal_id])
        .arg("--endpoint")
        .arg(scenario.proxy.path.clone());
    let run = run_under_pty(
        &mut command,
        "[y/N]",
        "yes\n",
        std::time::Duration::from_secs(60),
    );

    // The daemon's own answers, as they crossed the wire.
    let previews = scenario.previews();
    assert!(
        !previews.is_empty(),
        "the proposal must have been previewed: {:?}",
        scenario.replies()
    );
    let inspection = &previews[0];
    assert_eq!(
        inspection.get("proposal_kind").and_then(|k| k.as_str()),
        Some("model-initiated-file-read"),
        "the classification must not change: {inspection}"
    );
    assert_eq!(
        inspection
            .get("requires_confirmation")
            .and_then(|r| r.as_bool()),
        Some(true),
        "a model-originated read must still require a confirmation: {inspection}"
    );
    assert_eq!(
        inspection.get("approval_allowed").and_then(|a| a.as_bool()),
        Some(false),
        "the proposal must be blocked: {inspection}"
    );
    let blocked = inspection
        .get("blocked_reason")
        .and_then(|b| b.as_str())
        .expect("a blocked reason");
    // The reason says the recipient cannot be identified, and it does not say it
    // by quoting the endpoint it could not identify.
    assert!(
        !blocked.is_empty(),
        "a blocked proposal must say why: {inspection}"
    );
    assert!(
        blocked.contains("recipient") || blocked.contains("cannot be displayed safely"),
        "the reason must name what is wrong: {blocked}"
    );
    assert!(
        !blocked.contains(CANARY),
        "the reason must not quote the unsafe destination: {blocked}"
    );
    // No recipient was shown, because none could be shown safely.
    assert!(
        !inspection
            .get("recipient")
            .and_then(|r| r.as_str())
            .unwrap_or_default()
            .contains(CANARY),
        "the unsafe destination must not be shown: {inspection}"
    );
    // The fresh preview, if one was asked for, carried no challenge: a blocked
    // proposal mints none.
    for preview in previews.iter().skip(1) {
        assert!(
            preview.get("challenge").is_none(),
            "a blocked proposal must not mint a challenge: {preview}"
        );
    }

    assert!(
        !run.output.contains("[y/N]"),
        "a blocked proposal must not be put to the operator: {}",
        run.output
    );
    assert!(
        run.output.contains(blocked),
        "the reason must reach the operator: {}",
        run.output
    );
    assert!(
        !scenario.approval_was_sent(),
        "no approval may be sent: {:?}",
        scenario.methods()
    );
    assert_eq!(scenario.proposal_status(), "pending");
    assert_eq!(scenario.approval_count(), 0);
    assert_eq!(scenario.effect_count(), 0);
    assert_ne!(scenario.task_state(), "completed");
    assert_eq!(scenario.provider.requests().len(), 1);

    // The canary appears nowhere it must not: not on the operator's console, not
    // in the durable state, and not in any daemon error.
    assert!(
        !run.output.contains(CANARY),
        "the canary reached the console: {}",
        run.output
    );
    let state = std::fs::read(scenario.root.join("state.db")).unwrap_or_default();
    let state = String::from_utf8_lossy(&state).into_owned();
    assert!(
        !state.contains(CANARY),
        "the canary reached the durable state"
    );
    let said = scenario.daemon_stderr();
    assert!(
        !said.contains(CANARY),
        "the canary must not appear in the daemon's output: {said}"
    );
    assert!(
        said.contains("destination withheld (unsafe to display)"),
        "the daemon must withhold a destination it cannot show: {said}"
    );
    let _ = std::fs::remove_dir_all(&scenario.root);
}

/// The daemon's startup output never carries a destination it cannot show.
///
/// A configured provider URL may carry user information, a query string or a
/// fragment. The daemon's own startup banner is read by whoever is watching the
/// machine, so the destination it prints is the safe projection -- and a
/// destination the projection refuses is withheld whole, not partly shown.
#[test]
fn the_daemons_startup_output_never_carries_a_destination_it_cannot_show() {
    const USERINFO: &str = "USERINFO-CANARY-7c1";
    const QUERY: &str = "QUERY-CANARY-4d19";
    const FRAGMENT: &str = "FRAGMENT-CANARY-2b8";
    const WITHHELD: &str = "destination withheld (unsafe to display)";

    // A destination with user information in it.
    let root = dir("startup-userinfo");
    let credential = synthetic_credential();
    let credential_file = root.join("provider-credential");
    write_credential_file(&credential_file, &credential);
    let provider = TlsProvider::answering(READ_PROPOSAL_JSON, &credential);
    let base = format!("https://{USERINFO}@{}/v1", provider.address);
    let (daemon, stderr) =
        Daemon::start_with_tls_provider_base(&root, &provider, &credential_file, &base, true);
    // The daemon starts: the configuration is accepted.
    assert!(daemon.cli(&["task", "list"]).status.success());
    let said = stderr
        .expect("the daemon's standard error was captured")
        .text();
    assert!(
        !said.contains(USERINFO),
        "the user information reached the startup output: {said}"
    );
    assert!(
        said.contains(WITHHELD),
        "the destination must be withheld: {said}"
    );
    drop(daemon);
    let _ = std::fs::remove_dir_all(&root);

    // A destination with a query string and a fragment. The daemon starts, the
    // banner withholds the destination, and the configured request is still made
    // exactly as configured: the query and the fragment are not removed from it.
    let root = dir("startup-query");
    let credential = synthetic_credential();
    let credential_file = root.join("provider-credential");
    write_credential_file(&credential_file, &credential);
    let provider = TlsProvider::answering(READ_PROPOSAL_JSON, &credential);
    let base = format!("https://{}/v1?{QUERY}#{FRAGMENT}", provider.address);
    let (daemon, stderr) =
        Daemon::start_with_tls_provider_base(&root, &provider, &credential_file, &base, true);
    let said = stderr
        .expect("the daemon's standard error was captured")
        .text();
    for canary in [QUERY, FRAGMENT] {
        assert!(
            !said.contains(canary),
            "the canary reached the startup output: {said}"
        );
    }
    assert!(
        said.contains(WITHHELD),
        "the destination must be withheld: {said}"
    );

    // The request still happens, and it carries the configured path, query and
    // fragment: the configuration was not changed to make it printable.
    daemon.cli(&["task", "create", "--id", "s1"]);
    assert!(
        daemon
            .cli(&["task", "claim", "--id", "s1", "--worker", "w1"])
            .status
            .success()
    );
    let proposed = daemon.cli(&["task", "ai-propose", "--task", "s1", "--worker", "w1"]);
    assert!(
        proposed.status.success(),
        "the model must be asked: {}\n{}",
        stdout_of(&proposed),
        stderr_of(&proposed)
    );
    let requests = provider.requests();
    assert_eq!(requests.len(), 1, "one provider request: {requests:?}");

    // What was actually put on the wire. The request-target is the configured
    // path and the configured query, and the fragment is not transmitted: a
    // fragment identifies a secondary resource in the representation the server
    // returns, and it is not part of the request-target (RFC 9110 section 7.1).
    let lines = provider.request_lines();
    assert_eq!(lines.len(), 1, "one request line: {lines:?}");
    let line = &lines[0];
    assert!(
        line.starts_with("POST /v1/chat/completions?"),
        "the request-target must be the configured path and query: {line}"
    );
    assert!(
        line.contains(QUERY),
        "the configured query must be sent: {line}"
    );
    assert!(
        !line.contains(FRAGMENT),
        "the fragment must not be transmitted: {line}"
    );
    assert!(
        !requests[0].contains(FRAGMENT),
        "the fragment must not appear anywhere in the request: {requests:?}"
    );
    // The request is still an authenticated TLS request with the synthetic
    // credential: nothing about the transport was relaxed.
    assert!(
        requests[0].contains(&format!("Authorization: Bearer {credential}")),
        "the synthetic credential must still be sent: {requests:?}"
    );
    drop(daemon);
    let _ = std::fs::remove_dir_all(&root);
}
