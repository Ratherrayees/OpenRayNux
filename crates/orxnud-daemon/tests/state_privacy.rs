//! SEC-003: the state root is private to its owner.
//!
//! # Why this is a daemon property and not a store one
//!
//! The **database** is the store's artefact: it is the store that opens it, and
//! the store is the component that notices the platform created it
//! world-readable and corrects it. That is proved in `orxnud-store`'s
//! `database_privacy` suite, against the production open path.
//!
//! The **state root** is the daemon's artefact. It is the one directory this
//! product owns, and it is the boundary: the database, the audit journal, the
//! approval ledger, the capability workspace and the IPC socket all live inside
//! it, and the platform creates each of them with the process's umask applied.
//! A root that is `0755` makes every one of them reachable by another local
//! account, whatever mode the files themselves carry.
//!
//! So the daemon restricts the root to `0700` **before** anything is created
//! inside it, and the mode is set exactly rather than inherited from the umask:
//! `mkdir` masks the requested mode, so a `0700` request can arrive as `0000`
//! under a permissive umask.
//!
//! # What this does not prove
//!
//! The Unix mode bits are the guarantee. On Windows there are none, and the
//! restriction is a no-op that records the limit rather than pretending to have
//! happened — so the assertions here are Unix-gated, and the Windows limit is
//! stated rather than papered over.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use orxnud_daemon::{Paths, prepare_state_paths};

/// A state root unique to this process and this call.
fn root(tag: &str) -> PathBuf {
    use std::sync::atomic::AtomicU32;
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "orxnud-daemon-privacy-{}-{tag}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

/// The mode of `path`, in octal, or `None` where the platform has no mode bits.
#[cfg(unix)]
fn mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).ok()?;
    Some(meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn mode(_path: &Path) -> Option<u32> {
    None
}

/// Sets `path`'s mode. A no-op where the platform has no mode bits.
#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) {}

/// **A state root the daemon creates is private to its owner.**
///
/// The daemon's own start-up path: the root is restricted, and the database
/// inside it is private too. The second assertion is the store's guarantee,
/// observed through the daemon, because a root that is `0700` and a database
/// that is `0600` are two different properties and both have to hold.
#[cfg(unix)]
#[test]
fn a_state_root_the_daemon_creates_is_private_to_its_owner() {
    let root = root("fresh");
    let paths = Paths::under(&root);

    // A root that does not exist yet, as a fresh install has it.
    let _ = std::fs::remove_dir_all(&root);
    assert!(!root.exists(), "precondition: the root must not exist yet");

    paths.ensure_state_root().expect("create the state root");

    assert_eq!(
        mode(&root),
        Some(0o700),
        "the state root holds the database, the audit journal, the approval ledger and the \
         socket; it must be private to its owner"
    );

    // And the database inside it, through the daemon's own durable-state path.
    {
        let mut daemon = orxnud_daemon::Daemon::compose(
            prepare_state_paths(paths.clone())
                .unwrap_or_else(|e| panic!("the test's state root must validate: {e}")),
        );
        daemon
            .attach_durable_security_state(&paths.database)
            .expect("attach the durable security state");
    }
    assert_eq!(
        mode(&paths.database),
        Some(0o600),
        "the database inside the root must be private to its owner as well"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **An existing world-readable state root is tightened.**
///
/// The upgrade case: a root created by an earlier build arrives `0755`, and
/// every file in it is readable by every other account on the machine. The
/// daemon must correct that when it opens the root, not leave it because "the
/// directory was already there".
#[cfg(unix)]
#[test]
fn an_existing_world_readable_state_root_is_tightened() {
    let root = root("existing");
    let paths = Paths::under(&root);

    set_mode(&root, 0o755);
    assert_eq!(
        mode(&root),
        Some(0o755),
        "precondition: the root must start world-readable, or this test proves nothing"
    );

    paths.ensure_state_root().expect("open the state root");

    assert_eq!(
        mode(&root),
        Some(0o700),
        "opening a world-readable state root must tighten it; the directory was already \
         there and that is not a reason to leave it readable"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **The capability workspace is private too.**
///
/// The workspace holds the output of a High-risk capability — the text a
/// sandboxed write produced — so it is restricted the same way.
#[cfg(unix)]
#[test]
fn the_capability_workspace_is_private_to_its_owner() {
    let root = root("workspace");
    let paths = Paths::under(&root);

    paths.ensure_state_root().expect("create the state root");
    paths.ensure_workspace().expect("create the workspace");

    assert_eq!(
        mode(&paths.workspace()),
        Some(0o700),
        "the workspace holds a High-risk capability's output and must be private to its owner"
    );

    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// umask: the creation mode is masked by the process's umask, so the exact mode
// has to be set rather than inherited. These cases run the **shipped binary** in
// a child process, because the umask is process-global state and changing it in
// this process would race every other test in the binary.
// ---------------------------------------------------------------------------

/// Runs the shipped daemon under `umask`, and reports what it left behind.
///
/// Returns the child's exit status (`None` when it was still serving and had to
/// be stopped) and its stderr.
///
/// The stderr goes to a **file**, not a pipe, and that is not a convenience.
/// The daemon starts a sandbox probe, and a probe that is still running holds
/// the write end of an inherited stderr pipe — so reading a pipe to EOF after
/// the daemon has exited blocks for as long as that probe lives. A file has no
/// such reader, and the text is on disk the moment the child is reaped.
fn run_daemon_under_umask(root: &Path, umask: &str) -> (Option<i32>, String) {
    let stderr_path = root.with_extension("stderr.txt");
    let _ = std::fs::remove_file(&stderr_path);
    let stderr_file = std::fs::File::create(&stderr_path).expect("create the stderr file");

    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("umask {umask}; exec \"$@\""))
        .arg("sh")
        .arg(env!("CARGO_BIN_EXE_orxnud"))
        .arg("--state-root")
        .arg(root)
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .expect("spawn the daemon under the umask");

    // Two outcomes, and they are told apart by **whether the process exited**:
    //
    // * the daemon refused to start and exited on its own -- its status and its
    //   stderr are the answer;
    // * the daemon started and is serving -- the socket appears, and the daemon
    //   is stopped by this harness.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut exited: Option<i32> = None;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                exited = status.code();
                break;
            }
            Ok(None) => {}
            Err(_) => break,
        }
        if root.join("orxnud.sock").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if exited.is_none() {
        // Still serving: stop it, and report "it started" by returning no exit
        // status.
        let _ = child.kill();
        // `wait` in every path, so the child is never left unreaped: the lint
        // that says so is right, and an unreaped daemon would keep serving.
        let _ = child.wait();
    } else {
        // Already exited and reaped by `try_wait`; `wait` again so the child is
        // collected on this path too.
        let _ = child.wait();
    }

    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    let _ = std::fs::remove_file(&stderr_path);
    (exited, stderr)
}

/// **The state root is exactly `0700` under a permissive umask.**
///
/// `mkdir` takes the requested mode **masked by the umask**, so a `0700`
/// request can arrive as something else. The implementation therefore sets the
/// mode exactly, after creating the directory, and this test proves it by
/// running the shipped binary where the umask cannot help: under `umask 000`
/// the platform would create the directory at `0777`, and a database inside it
/// at `0666`.
///
/// A directory created at `0777` is the failure this guards: world-readable and
/// world-writable, so another account could replace the database inside it.
#[cfg(unix)]
#[test]
fn the_state_root_is_exactly_owner_only_under_a_permissive_umask() {
    let root = root("umask-000");
    let _ = std::fs::remove_dir_all(&root);

    let (status, stderr) = run_daemon_under_umask(&root, "000");
    assert!(
        status.is_none_or(|c| c == 0),
        "the daemon must start under a permissive umask; it exited with {status:?}: {stderr}"
    );

    assert_eq!(
        mode(&root),
        Some(0o700),
        "under umask 000 the platform would create the state root at 0777; the mode must \
         be set exactly, not inherited from the umask"
    );
    let database = root.join("state.db");
    assert!(
        database.exists(),
        "precondition: the daemon must have created the database"
    );
    assert_eq!(
        mode(&database),
        Some(0o600),
        "under umask 000 the platform would create the database at 0666; the mode must be \
         set exactly, not inherited from the umask"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **A state root that cannot be secured is refused, and nothing is written.**
///
/// `umask 0777` is the one setting under which the implementation cannot
/// complete: `mkdir(0o700)` is masked to `0000`, and a directory at `0000` cannot
/// be **opened**, so the descriptor-based restriction cannot be performed on the
/// object the implementation just created.
///
/// The required behaviour is a **secure refusal**, not a startup: the directory
/// is at `0000` — *more* restrictive than asked for, so nothing is exposed — and
/// the daemon must not create a database inside it or serve anything.
///
/// This is deliberately **not** "make it work at any umask". Doing that would
/// need a pathname-based `chmod` after the fact, which is the time-of-check /
/// time-of-use shape the descriptor-based design exists to avoid.
#[cfg(unix)]
#[test]
fn a_state_root_that_cannot_be_secured_is_refused_and_nothing_is_written() {
    let root = root("umask-0777");
    let _ = std::fs::remove_dir_all(&root);

    let (status, stderr) = run_daemon_under_umask(&root, "0777");
    let code = status.expect("the daemon must have exited rather than served");
    assert_ne!(
        code, 0,
        "a state root that could not be secured must not be served; the daemon exited \
         with {code}: {stderr}"
    );
    assert!(
        stderr.contains("state root"),
        "the refusal must say which step failed, or an operator cannot act on it: {stderr}"
    );

    let database = root.join("state.db");
    assert!(
        !database.exists(),
        "no durable state may be written under a state root that could not be secured"
    );
    assert!(
        !root.join("orxnud.sock").exists(),
        "the endpoint must never be bound under a state root that could not be secured"
    );
    let root_mode = mode(&root);
    assert!(
        root_mode.is_none_or(|m| m & 0o077 == 0),
        "the state root must never be more permissive than owner-only, whatever the umask \
         did to it; it is at {root_mode:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// **The artefact a refused umask leaves behind is recoverable.**
///
/// A `0000` directory is unusable but not unrecoverable: the owner may `chmod`
/// it, because `chmod` is governed by ownership rather than by the mode. So the
/// operator's route out is one command, and the daemon works normally
/// afterwards.
///
/// This is recorded as a **property of the refusal**, not as a promise that the
/// implementation could have avoided the artefact: it could not, and the
/// alternative was a pathname-based `chmod` on a path another account might be
/// able to replace.
#[cfg(unix)]
#[test]
fn the_artefact_a_refused_umask_leaves_behind_is_recoverable() {
    use std::os::unix::fs::PermissionsExt;

    let root = root("umask-0777-recover");
    let _ = std::fs::remove_dir_all(&root);

    let (status, _stderr) = run_daemon_under_umask(&root, "0777");
    assert!(
        status.is_some_and(|c| c != 0),
        "precondition: the daemon must have refused under umask 0777"
    );
    assert!(
        root.exists(),
        "precondition: the refused attempt must have left the root"
    );

    // The owner's route out.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    assert_eq!(
        mode(&root),
        Some(0o700),
        "the owner must be able to recover the root"
    );

    // And the daemon works normally once the directory is usable.
    let (status, stderr) = run_daemon_under_umask(&root, "022");
    assert!(
        status.is_none_or(|c| c == 0),
        "the daemon must start once the state root is usable; it exited with {status:?}: {stderr}"
    );
    assert_eq!(
        mode(&root),
        Some(0o700),
        "the recovered root must be owner-only"
    );
    assert_eq!(
        mode(&root.join("state.db")),
        Some(0o600),
        "the recovered root's database must be owner-only"
    );

    let _ = std::fs::remove_dir_all(&root);
}
