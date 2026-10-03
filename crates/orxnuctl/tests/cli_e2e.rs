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

impl Daemon {
    /// Starts a real daemon on `root` and waits until it answers.
    ///
    /// Readiness is a request the daemon can only answer once `serve` is polling, so
    /// this waits for a fact rather than sleeping a guessed interval.
    fn start(root: &Path) -> Self {
        let child = Command::new(daemon_bin())
            .arg("--state-root")
            .arg(root)
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
