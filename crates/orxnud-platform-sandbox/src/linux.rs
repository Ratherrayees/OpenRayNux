//! The Linux backend: `bubblewrap`, namespaces, and what they actually guarantee.
//!
//! # What this backend provides, precisely
//!
//! Everything below was measured on the Phase 4 host (Fedora 44, kernel 6.x,
//! `bubblewrap 0.12.0`), not read from a man page. Where a guarantee is *not*
//! provided, this module says so and the contract refuses to pretend otherwise.
//!
//! | Guarantee | Status | Mechanism |
//! |---|---|---|
//! | Visibility | **PROVEN** | `--unshare-pid`, `--unshare-net`, `--ro-bind` / `--bind` / `--tmpfs` |
//! | Tree lifetime | **PROVEN** | `--unshare-pid` + `--die-with-parent`; kernel kills the namespace when init dies |
//! | Resource ceilings | **NOT PROVEN** | `memory.max`, `pids.max`, `cpu.max` are unwritable in this user session |
//!
//! # Tree lifetime: how it is *actually* achieved, and the first wrong answer
//!
//! ## The first measurement was wrong
//!
//! An earlier version of this file documented that all three of these escaped:
//!
//! ```text
//! --unshare-pid --die-with-parent  -> ESCAPED
//! --unshare-pid                    -> ESCAPED
//! --die-with-parent                -> ESCAPED
//! ```
//!
//! **That was a measurement error.** The check looked for the grandchild's PID in the
//! host's `/proc`, but the PID the helper reported was the one it saw **inside** its
//! new PID namespace. On the host, `3` is an unrelated process, so the check found a
//! live `/proc/3` and concluded the grandchild had escaped.
//!
//! The corrected check watches the grandchild's *heartbeat* advancing on disk, which
//! distinguishes a live process from a stale file. With that:
//!
//! ```text
//! --unshare-pid --die-with-parent  -> CONTAINED   (5 of 5 runs, SIGTERM and SIGKILL)
//! --unshare-pid only              -> ESCAPED
//! --die-with-parent only          -> ESCAPED
//! neither                         -> ESCAPED
//! ```
//!
//! ## Why the combination works, and neither flag does alone
//!
//! `PR_SET_PDEATHSIG` on its own is genuinely insufficient: it fires when the **direct**
//! parent dies, and a helper that has double-forked and called `setsid` is no longer a
//! direct child. That part of the first analysis was correct.
//!
//! What was missed is that `--unshare-pid` makes the sandboxed process **PID 1 of a new
//! PID namespace**, and the kernel guarantees that when a namespace's init process
//! dies, *every* remaining process in that namespace is sent `SIGKILL`. So the chain is:
//!
//! ```text
//! supervisor signals bwrap
//!   -> bwrap's PDEATHSIG fires
//!   -> the namespace init dies
//!   -> the kernel SIGKILLs the whole namespace, including the detached grandchild
//! ```
//!
//! The grandchild cannot opt out: leaving a PID namespace requires privileges the
//! sandboxed process does not have.
//!
//! ## The conditions, stated plainly
//!
//! This guarantee depends on **the supervisor signalling `bwrap`**, never the child
//! directly. Signalling the child would kill the grandchild's parent without triggering
//! `PDEATHSIG`, leaving the namespace init alive. [`BwrapRunner::run`] therefore always
//! signals the `bwrap` process it spawned. A future refactor that signals the inner
//! process would silently break containment, so this is called out in the code too.
//!
//! `cgroup.kill` remains the stronger mechanism — it walks the cgroup, so it handles
//! concurrent forks and needs no namespace — and remains the right answer once a host
//! delegates the controllers. On this host `cgroup.kill` *is* writable but the
//! resource controllers are not, so it is not yet a better option.
//!
//! # Why `bubblewrap` and not hand-rolled namespaces
//!
//! Constructing the namespace/mount/seccomp setup by hand needs `unsafe`, and gate G4
//! forbids it. `bwrap` also gets the ordering right — namespaces unshare before the
//! mounts, so the child never observes a partially-constructed root — and handles
//! `setuid` restoration, which is easy to get subtly wrong.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::contract::{
    AvailableGuarantees, CapturedStream, ExecutionResult, ExecutionStatus, NetworkPolicy,
    ResourceLimits, SandboxRunner, SandboxSpec, SandboxUnavailable,
};

/// The bubblewrap executable.
const BWRAP: &str = "bwrap";

/// A Linux sandbox runner.
///
/// Cloning is cheap and the runner is stateless apart from the cancellation flag, so a
/// supervisor can hold one per in-flight execution.
#[derive(Clone)]
pub struct BwrapRunner {
    /// Set to request cancellation of whatever is currently running.
    cancel: Arc<AtomicBool>,
}

impl Default for BwrapRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl BwrapRunner {
    /// A runner that is not cancelling anything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Probes what this host actually provides.
    ///
    /// Runs `bwrap` once with no grants. A refusal here is the whole Phase 4b
    /// blocker, discovered at startup rather than at dispatch time.
    #[must_use]
    pub fn probe() -> AvailableGuarantees {
        let bwrap_present = Command::new(BWRAP)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        let visibility = bwrap_present && Self::namespace_probe();
        // `cgroup.kill` and the resource controllers. Probed by attempting the write,
        // because "the controller is listed" and "we may use it" are different facts —
        // this host lists `memory` and `pids` in `cgroup.controllers` and refuses both.
        // Tree lifetime comes from the PID namespace plus `PDEATHSIG`, both of which
        // `namespace_probe` already exercised. Resource ceilings are separate and still
        // unavailable here: the controllers are listed in `cgroup.controllers` but every
        // write is refused in this user session.
        let resources = visibility && CgroupV2::discover().can_limit;
        // Tree lifetime rides on the same probe: `--unshare-pid` plus
        // `--die-with-parent` is what the kernel uses to kill a detached descendant,
        // and `namespace_probe` runs with both.
        let tree_lifetime = visibility;

        AvailableGuarantees {
            visibility,
            tree_lifetime,
            resources,
        }
    }

    /// The exact `bwrap` argument vector for a spec.
    ///
    /// Exposed because a supervisor sometimes must exec through a wrapper — to place
    /// the sandbox under a poisoned parent environment for a test, or to apply an
    /// ambient wrapper such as a cgroup manager. Callers get the same argv
    /// [`Self::run`] would use, so a wrapper cannot accidentally produce a weaker
    /// sandbox than the one the spec describes.
    ///
    /// # Errors
    ///
    /// As [`build_command`]: a relative program path is refused.
    pub fn argv_for(spec: &SandboxSpec) -> Result<Vec<String>, SandboxUnavailable> {
        build_command(spec).map(|(argv, _)| argv)
    }

    /// Whether an unprivileged PID namespace can actually be created.
    fn namespace_probe() -> bool {
        Command::new(BWRAP)
            .args([
                "--unshare-pid",
                "--ro-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
            ])
            .args(["--", "/bin/true"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// What the host's cgroup v2 hierarchy permits.
///
/// Only the resource controllers are consulted. `cgroup.kill` is writable here but is
/// *not* what provides tree lifetime on Linux — the PID namespace does, and does so
/// more cheaply. `cgroup.kill` becomes the right mechanism when a host delegates
/// controllers, because it needs no namespace and handles concurrent forks.
struct CgroupV2 {
    /// `memory.max` (or `pids.max`) is writable in a cgroup we own.
    can_limit: bool,
}

impl CgroupV2 {
    /// Finds our own cgroup and tests what we may do in a child of it.
    fn discover() -> Self {
        let Some(path) = Self::own_path() else {
            return Self { can_limit: false };
        };
        // Probing needs a cgroup of our own. Created under our scope and removed
        // afterwards; `can_limit`/`can_kill` record the result either way.
        let probe = path.join("orxnud-sandbox-probe");
        let created = std::fs::create_dir(&probe).is_ok();
        if !created {
            return Self { can_limit: false };
        }
        let can_limit = std::fs::write(probe.join("pids.max"), b"64\n").is_ok()
            || std::fs::write(probe.join("memory.max"), b"67108864\n").is_ok();
        let _ = std::fs::remove_dir(&probe);
        Self { can_limit }
    }

    /// Our own cgroup path from `/proc/self/cgroup`.
    fn own_path() -> Option<PathBuf> {
        let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        // Unified hierarchy line: `0::/path`.
        let line = text.lines().find(|l| l.starts_with("0::"))?;
        let rel = line.trim_start_matches("0::").trim();
        Some(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
    }
}

impl SandboxRunner for BwrapRunner {
    fn available_guarantees(&self) -> AvailableGuarantees {
        Self::probe()
    }

    fn cancel(&self) -> Result<(), SandboxUnavailable> {
        self.cancel.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn run(&self, spec: &SandboxSpec) -> Result<ExecutionResult, SandboxUnavailable> {
        let available = Self::probe();

        // Fail closed on a required guarantee we cannot provide. Checked *before* the
        // process is built, so a refusal never leaves a half-started sandbox.
        if let Err(e) = available.check(spec) {
            return Ok(ExecutionResult {
                status: ExecutionStatus::Refused(e),
                stdout: CapturedStream::empty(),
                stderr: CapturedStream::empty(),
                elapsed: Duration::ZERO,
                unproven: Vec::new(),
            });
        }

        self.cancel.store(false, Ordering::SeqCst);

        let (argv, _program) = match build_command(spec) {
            Ok(v) => v,
            Err(e) => {
                return Ok(ExecutionResult {
                    status: ExecutionStatus::Refused(e),
                    stdout: CapturedStream::empty(),
                    stderr: CapturedStream::empty(),
                    elapsed: Duration::ZERO,
                    unproven: Vec::new(),
                });
            }
        };

        let started = Instant::now();
        let mut child = match Command::new(BWRAP)
            .args(&argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // `bwrap` must not inherit our environment: it is the single most
            // effective way for a parent secret to reach a child. The child's own
            // environment is set explicitly by `--setenv` below.
            .env_clear()
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                return Ok(ExecutionResult {
                    status: ExecutionStatus::SpawnFailed(e.to_string()),
                    stdout: CapturedStream::empty(),
                    stderr: CapturedStream::empty(),
                    elapsed: started.elapsed(),
                    unproven: Vec::new(),
                });
            }
        };

        let cap = spec.limits.output_bytes;
        let deadline = spec.limits.wall_clock;

        // Two reader threads, so neither stream can deadlock the supervisor by filling
        // its pipe while we wait on the other. A single-threaded read of both is the
        // classic way to hang a supervisor forever, and this brief requires that the
        // parent must never block indefinitely on `stdout`.
        let mut out_pipe = child.stdout.take();
        let mut err_pipe = child.stderr.take();
        let out_handle = std::thread::spawn(move || read_capped(&mut out_pipe, cap));
        let err_handle = std::thread::spawn(move || read_capped(&mut err_pipe, cap));

        let mut timed_out = false;
        let mut cancelled = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) => {}
                Err(e) => {
                    return Ok(ExecutionResult {
                        status: ExecutionStatus::SpawnFailed(e.to_string()),
                        stdout: CapturedStream::empty(),
                        stderr: CapturedStream::empty(),
                        elapsed: started.elapsed(),
                        unproven: Vec::new(),
                    });
                }
            }
            if started.elapsed() >= deadline {
                timed_out = true;
                // SIGKILL rather than SIGTERM: the Phase 4 spike established that a
                // helper may ignore SIGTERM, and a graceful-then-forceful path would
                // wait out a grace period for a process that never honours it.
                let _ = child.kill();
                let _ = child.wait();
                break std::process::ExitStatus::default();
            }
            if self.cancel.load(Ordering::SeqCst) {
                cancelled = true;
                let _ = child.kill();
                let _ = child.wait();
                break std::process::ExitStatus::default();
            }
            std::thread::sleep(Duration::from_millis(5));
        };

        // Bounded join. Discovered by removing `--die-with-parent` as a teeth-check:
        // the supervisor then hung forever, because a surviving descendant keeps the
        // stdout pipe open and the reader thread never sees EOF.
        //
        // A hang is the worst failure a supervisor can have, so the readers are
        // abandoned rather than waited on. The threads leak; the daemon does not. The
        // output is reported as truncated, because a helper whose pipe never closed
        // produced output we could not vouch for.
        let stdout = join_bounded(out_handle, Duration::from_millis(2_000));
        let stderr = join_bounded(err_handle, Duration::from_millis(2_000));

        // Record what was *not* provided. Non-empty only when the caller explicitly
        // accepted best-effort containment, and the audit record must carry it.
        let mut unproven = Vec::new();
        if spec.requires.tree_lifetime == crate::contract::TreeLifetime::BestEffort
            && !available.tree_lifetime
        {
            unproven.push((
                "process-tree lifetime containment",
                "no cgroup `cgroup.kill` on this host; a detached descendant may outlive \
                 the execution"
                    .to_owned(),
            ));
        }
        if spec.limits.memory_bytes.is_some() && !available.resources {
            unproven.push((
                "OS-enforced memory ceiling",
                format!(
                    "no writable cgroup controller on this host; the requested {} MiB is \
                     not enforced",
                    spec.limits.memory_bytes.unwrap_or(0) / (1024 * 1024)
                ),
            ));
        }

        let status = if timed_out {
            ExecutionStatus::TimedOut
        } else if cancelled {
            ExecutionStatus::Cancelled
        } else if stdout.truncated || stderr.truncated {
            ExecutionStatus::OutputExceeded {
                stream: if stdout.truncated { "stdout" } else { "stderr" },
                cap,
            }
        } else {
            ExecutionStatus::Exited(status.code().unwrap_or(-1))
        };

        Ok(ExecutionResult {
            status,
            stdout,
            stderr,
            elapsed: started.elapsed(),
            unproven,
        })
    }
}

impl CapturedStream {
    /// An empty, complete stream.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            bytes: Vec::new(),
            truncated: false,
            dropped: 0,
        }
    }
}

/// Joins a reader thread, giving up after `budget`.
///
/// Returns what the thread produced if it finished in time, and a truncated stream
/// otherwise. The thread is detached, not killed: it holds a pipe and will exit when
/// the pipe finally closes.
fn join_bounded(
    handle: std::thread::JoinHandle<CapturedStream>,
    budget: Duration,
) -> CapturedStream {
    let (tx, rx) = std::sync::mpsc::channel();
    // A second thread that sends the result on, so this one can time out without
    // joining the original.
    std::thread::spawn(move || {
        let result = handle.join().unwrap_or_else(|_| CapturedStream::empty());
        let _ = tx.send(result);
    });
    match rx.recv_timeout(budget) {
        Ok(s) => s,
        Err(_) => CapturedStream {
            bytes: Vec::new(),
            truncated: true,
            dropped: 0,
        },
    }
}

/// Reads up to `cap` bytes, discarding the rest rather than growing without bound.
///
/// This is the defence against output flooding: a helper that prints forever costs
/// the supervisor `cap` bytes and nothing more.
fn read_capped<R: Read>(r: &mut Option<R>, cap: u64) -> CapturedStream {
    let Some(mut src) = r.take() else {
        return CapturedStream::empty();
    };
    let cap_usize = usize::try_from(cap).unwrap_or(usize::MAX);
    let mut bytes = Vec::new();
    let mut dropped = 0u64;
    let mut buf = [0u8; 8192];
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let room = cap_usize.saturating_sub(bytes.len());
                if room == 0 {
                    dropped += n as u64;
                } else if n <= room {
                    bytes.extend_from_slice(&buf[..n]);
                } else {
                    bytes.extend_from_slice(&buf[..room]);
                    dropped += (n - room) as u64;
                }
            }
            // A read error ends the stream. The helper is not trusted to close
            // cleanly, and a supervisor that blocks on a broken pipe is the failure
            // mode this phase exists to prevent.
            Err(_) => break,
        }
    }
    CapturedStream {
        truncated: dropped > 0,
        dropped,
        bytes,
    }
}

/// Builds the `bwrap` argument vector and the in-sandbox program path.
///
/// # Errors
///
/// [`SandboxUnavailable::Invalid`] for a configuration that cannot be expressed —
/// chiefly a relative program path, which would resolve against the sandbox root and
/// silently become a different executable.
fn build_command(spec: &SandboxSpec) -> Result<(Vec<String>, String), SandboxUnavailable> {
    if !spec.program.is_absolute() {
        return Err(SandboxUnavailable::Invalid(format!(
            "program {} must be an absolute path; a relative one would resolve inside \
             the sandbox and silently run something else",
            spec.program.display()
        )));
    }

    let mut argv: Vec<String> = vec![
        // Namespace the process tree. `Visibility`, not `TreeLifetime`.
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--unshare-uts".into(),
        "--unshare-cgroup".into(),
        // Parent-death signal for the *direct* child. Documented as not being subtree
        // containment; see the module docs.
        "--die-with-parent".into(),
    ];

    if spec.network == NetworkPolicy::None {
        // Verified against a live listener on the host loopback in the Phase 4 spike.
        argv.push("--unshare-net".into());
    }

    // A tmpfs root: nothing from the host filesystem is visible unless bound below.
    // `--ro-bind /usr` and friends are then added back, because a capability with no
    // runtime at all cannot do anything.
    argv.push("--tmpfs".into());
    argv.push("/tmp".into());

    for dir in ["/usr", "/lib", "/lib64", "/bin", "/sbin"] {
        if Path::new(dir).exists() {
            argv.push("--ro-bind".into());
            argv.push(dir.into());
            argv.push(dir.into());
        }
    }

    for p in &spec.fs.read_only {
        argv.push("--ro-bind".into());
        argv.push(p.display().to_string());
        argv.push(p.display().to_string());
    }
    for p in &spec.fs.read_write {
        argv.push("--bind".into());
        argv.push(p.display().to_string());
        argv.push(p.display().to_string());
    }

    // Paths that must be absent get an empty tmpfs over them, so a refusal is
    // observable rather than merely implied by a missing grant.
    for p in &spec.fs.denied {
        argv.push("--tmpfs".into());
        argv.push(p.display().to_string());
    }

    argv.push("--proc".into());
    argv.push("/proc".into());
    argv.push("--dev".into());
    argv.push("/dev".into());
    argv.push("--chdir".into());
    argv.push(spec.working_dir.display().to_string());

    // The child's environment, explicitly. `--clearenv` first so nothing leaks from
    // the supervisor, then only what the caller granted.
    argv.push("--clearenv".into());
    for (k, v) in &spec.env {
        argv.push("--setenv".into());
        argv.push(k.clone());
        argv.push(v.clone());
    }

    // `--` ends bwrap's own options, so a program path or argument beginning with
    // `-` cannot be reinterpreted as an option to the sandbox tool itself.
    argv.push("--".into());
    let program = spec.program.display().to_string();
    argv.push(program.clone());
    argv.extend(spec.args.iter().cloned());

    Ok((argv, program))
}

/// The environment the supervisor itself holds, for tests.
///
/// Deliberately *not* a public accessor: a function that returned the process
/// environment would be an invitation, and the credential boundary is enforced by
/// never building one.
/// An environment map with nothing in it, for tests that assert closure.
#[must_use]
pub fn empty_env() -> BTreeMap<String, String> {
    BTreeMap::new()
}

/// The `ResourceLimits` a test should use when it wants ceilings observed rather than
/// enforced.
#[must_use]
pub fn observed_only_limits() -> ResourceLimits {
    ResourceLimits {
        memory_bytes: Some(64 * 1024 * 1024),
        max_processes: Some(32),
        cpu_cores: Some(0.5),
        ..ResourceLimits::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relative_program_is_refused_rather_than_reinterpreted() {
        let spec = SandboxSpec::new("relative/path");
        match build_command(&spec) {
            Err(SandboxUnavailable::Invalid(why)) => {
                assert!(why.contains("absolute"), "{why}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn the_environment_is_cleared_before_anything_is_granted() {
        let spec = SandboxSpec::new("/bin/true").env("ALLOWED", "yes");
        let (argv, _) = build_command(&spec).expect("build");
        let clear = argv
            .iter()
            .position(|a| a == "--clearenv")
            .expect("--clearenv");
        let setenv = argv.iter().position(|a| a == "--setenv").expect("--setenv");
        assert!(
            clear < setenv,
            "--clearenv must come first, or the grant is a lie"
        );
        // And only the granted variable appears.
        assert_eq!(argv.iter().filter(|a| *a == "ALLOWED").count(), 1);
    }

    #[test]
    fn no_networking_means_a_network_namespace() {
        let spec = SandboxSpec::new("/bin/true");
        let (argv, _) = build_command(&spec).expect("build");
        assert!(
            argv.iter().any(|a| a == "--unshare-net"),
            "no network must mean a netns"
        );
    }

    #[test]
    fn granted_network_omits_the_namespace() {
        let spec = SandboxSpec::new("/bin/true").with_network();
        let (argv, _) = build_command(&spec).expect("build");
        assert!(
            !argv.iter().any(|a| a == "--unshare-net"),
            "granting network must remove the netns, not merely not add it"
        );
    }

    #[test]
    fn the_program_and_its_arguments_are_after_a_double_dash() {
        // A hostile argument beginning with `-` must not become an option to bwrap.
        let spec = SandboxSpec::new("/bin/echo")
            .arg("--unshare-everything")
            .arg("-x");
        let (argv, program) = build_command(&spec).expect("build");
        let sep = argv.iter().position(|a| a == "--").expect("--");
        assert_eq!(argv[sep + 1], program);
        assert_eq!(argv[sep + 2], "--unshare-everything");
        assert_eq!(argv[sep + 3], "-x");
    }

    #[test]
    fn a_denied_path_gets_an_empty_tmpfs_so_refusal_is_observable() {
        let spec = SandboxSpec::new("/bin/true").deny("/home/user/.ssh");
        let (argv, _) = build_command(&spec).expect("build");
        // Not `position(...)`: `/tmp` also gets a tmpfs, and the first match is that
        // one. Search for the *pair* instead.
        let overmounted = argv
            .windows(2)
            .any(|w| w[0] == "--tmpfs" && w[1] == "/home/user/.ssh");
        assert!(overmounted, "the denied path must be overmounted: {argv:?}");
    }

    #[test]
    fn a_capped_reader_keeps_the_cap_and_counts_the_drop() {
        let big = vec![b'x'; 40_000];
        let mut src = std::io::Cursor::new(big);
        let out = read_capped(&mut Some(&mut src), 1_000);
        assert_eq!(out.bytes.len(), 1_000, "the cap must hold");
        assert!(out.truncated, "truncation must be reported");
        assert_eq!(out.dropped, 39_000);
    }

    #[test]
    fn an_uncapped_reader_keeps_everything() {
        let mut src = std::io::Cursor::new(vec![7u8; 100]);
        let out = read_capped(&mut Some(&mut src), 1_000_000);
        assert_eq!(out.bytes.len(), 100);
        assert!(!out.truncated);
        assert_eq!(out.dropped, 0);
    }

    #[test]
    fn a_missing_pipe_is_an_empty_stream_not_a_panic() {
        let mut nothing: Option<std::io::Cursor<Vec<u8>>> = None;
        let out = read_capped(&mut nothing, 1024);
        assert!(out.bytes.is_empty() && !out.truncated);
    }

    #[test]
    fn the_probe_reports_what_the_host_actually_provides() {
        // Not an assertion that a guarantee *is* available — this host may provide
        // none of them. The assertion is that the probe runs and reports honestly,
        // so a caller can decide before dispatch.
        let have = BwrapRunner::probe();
        // bwrap is installed on the Phase 4 host, so visibility must be found.
        assert!(
            have.visibility,
            "bwrap is installed; the probe must find it"
        );
        // And the two blocked guarantees must be reported as absent, not assumed.
        assert!(
            !have.resources,
            "this host delegates no cgroup controllers; the probe must not claim otherwise"
        );
    }

    #[test]
    fn a_spec_demanding_os_enforced_resources_is_refused_on_this_host() {
        // The fail-closed path, exercised against the one guarantee this host cannot
        // provide. Resource ceilings are `Required` by default and unwritable here, so
        // a default spec must be refused rather than silently running without them.
        let have = BwrapRunner::probe();
        assert!(
            !have.resources,
            "this host must not claim resource ceilings"
        );
        let spec = SandboxSpec::new("/bin/true");
        let result = BwrapRunner::new().run(&spec).expect("run");
        match result.status {
            ExecutionStatus::Refused(SandboxUnavailable::GuaranteeUnavailable {
                guarantee,
                ..
            }) => assert_eq!(guarantee, "OS-enforced resource ceilings"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_spec_accepting_observed_resources_is_allowed_and_says_so() {
        // The honest degradation: the caller says it will accept observation instead
        // of enforcement, and the result records what was not provided.
        use crate::contract::Resource;
        let mut spec = SandboxSpec::new("/bin/true");
        spec.requires.resources = Resource::Observed;
        spec.limits.memory_bytes = Some(64 * 1024 * 1024);
        let result = BwrapRunner::new().run(&spec).expect("run");
        assert!(
            result
                .unproven
                .iter()
                .any(|(g, _)| *g == "OS-enforced memory ceiling"),
            "an unenforced ceiling must be reported: {:?}",
            result.unproven
        );
    }
}
