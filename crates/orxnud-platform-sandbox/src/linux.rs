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
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::cgroup::{CgroupV2, ResourceControl};
use crate::contract::{
    AvailableGuarantees, CapturedStream, ExecutionResult, ExecutionStatus, NetworkPolicy, Resource,
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
        let av = CgroupV2::discover().availability;
        let resources = visibility && (av.memory || av.processes || av.cpu);
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
    /// As `build_command`: a relative program path is refused.
    pub fn argv_for(spec: &SandboxSpec) -> Result<Vec<String>, SandboxUnavailable> {
        build_command(spec).map(|(argv, _)| argv)
    }

    /// Whether an unprivileged PID namespace can actually be created.
    fn namespace_probe() -> bool {
        Self::namespace_probe_command()
            .args(["--", "/bin/true"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// The probe's command, before the program is supplied.
    ///
    /// Extracted so [`Self::namespace_probe`] and [`Self::probe_identity`] run the *same*
    /// namespaces. A diagnostic that built its own would be measuring a different
    /// configuration from the one that decides whether a capability runs.
    fn namespace_probe_command() -> Command {
        let mut c = Command::new(BWRAP);
        c.args([
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]);
        c
    }

    /// The identity observed **inside** the probe sandbox: `(uid_map, CapEff)`.
    ///
    /// # Why this exists
    ///
    /// "Can this host sandbox a Tier-1 capability?" is one question. "Is the sandbox that
    /// just answered it the sandbox users run?" is a different one, and the answer
    /// distinguishes two environments that both report success:
    ///
    /// * **Production.** The caller is unprivileged, so `bwrap` has to create a nested
    ///   user namespace to gain any capability. Inside, `uid_map` is a single-entry map
    ///   such as `1000 0 1` and `CapEff` is zero.
    /// * **Not production.** The caller already holds `CAP_SYS_ADMIN` (a `--privileged`
    ///   or `--cap-add=SYS_ADMIN` container). `bwrap` then runs *without* nesting:
    ///   `uid_map` is the full identity map `0 0 4294967295` and the sandbox inherits the
    ///   caller's capabilities.
    ///
    /// The second is a materially weaker claim about the security boundary, so a test run
    /// in it is not evidence that the production path works. Measured on both, rather
    /// than assumed.
    ///
    /// `None` when the probe cannot run at all, which is the incapable-host case.
    #[must_use]
    pub fn probe_identity() -> Option<(String, String)> {
        let out = Self::namespace_probe_command()
            .args([
                "--",
                "/bin/sh",
                "-c",
                "cat /proc/self/uid_map; grep CapEff /proc/self/status",
            ])
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let uid_map = text
            .lines()
            // `uid_map` lines are right-aligned and begin with padding, so a line has to
            // be trimmed before it can be recognised as three numbers.
            .map(str::trim)
            .find(|l| {
                let f: Vec<_> = l.split_whitespace().collect();
                f.len() == 3
                    && f.iter()
                        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
            })
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .unwrap_or_else(|| "unreadable".to_owned());
        let cap_eff = text
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .map(|v| v.trim().to_owned())
            .unwrap_or_else(|| "unreadable".to_owned());
        Some((uid_map, cap_eff))
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

        // --- resource setup, before a process exists ---------------------
        //
        // The dedicated child is created and its ceilings written *before* the
        // supervisor is spawned, so there is no window in which a payload could be
        // running without the limits that were required for it. Creation succeeding
        // and a later control write failing is treated as total failure: a partially
        // configured cgroup is not a weaker sandbox, it is a broken one.
        //
        // The translation from the spec's portable limits to cgroup controls happens
        // first, and it is fallible. An inexpressible limit is a refusal, not a shorter
        // control list -- a dropped control would be an unestablished required guarantee
        // with nothing to show for it.
        let controls = match controls_for(spec) {
            Ok(v) => v,
            Err(e) => {
                // Before any cgroup is created and before any process exists.
                return Ok(ExecutionResult {
                    status: ExecutionStatus::Refused(e),
                    stdout: CapturedStream::empty(),
                    stderr: CapturedStream::empty(),
                    elapsed: Duration::ZERO,
                    unproven: Vec::new(),
                });
            }
        };
        // `Resource::Required` with nothing to enforce is not a satisfiable request.
        //
        // This is a fail-open that measurement found: a spec that *requires* OS-enforced
        // ceilings but names none passed `available.check` (which asks whether the host
        // *can* enforce, not whether anything was asked for), created no cgroup, ran the
        // payload unbounded, and reported `unproven: []` -- a required guarantee
        // silently absent, with no record anywhere that it was missing.
        //
        // Which of the two is wrong depends on intent, and the honest reading of
        // "required" is that it demands *something*. So it is refused as incoherent
        // rather than executed unbounded. A caller who means "no particular ceiling,
        // just make sure you could" asks for [`Resource::Observed`], which is what that
        // value is for.
        if controls.is_empty() && spec.requires.resources == Resource::Required {
            return Ok(ExecutionResult {
                status: ExecutionStatus::Refused(SandboxUnavailable::Invalid(
                    "OS-enforced resource ceilings are required but no ceiling was named; \
                     a required guarantee with nothing to enforce would run the payload \
                     unbounded"
                        .to_owned(),
                )),
                stdout: CapturedStream::empty(),
                stderr: CapturedStream::empty(),
                elapsed: Duration::ZERO,
                unproven: Vec::new(),
            });
        }
        let mut owned: Option<CgroupV2> = None;
        if !controls.is_empty() {
            match CgroupV2::discover().create("exec", &controls) {
                Ok(cg) => owned = Some(cg),
                Err(e) if spec.requires.resources == Resource::Required => {
                    // Fail closed: refuse *before* spawning, so no process is created
                    // and no credential-bearing environment is ever bound.
                    return Ok(ExecutionResult {
                        status: ExecutionStatus::Refused(
                            SandboxUnavailable::GuaranteeUnavailable {
                                guarantee: "OS-enforced resource ceilings",
                                detail: format!(
                                    "a required ceiling could not be established: {}",
                                    e.reason
                                ),
                            },
                        ),
                        stdout: CapturedStream::empty(),
                        stderr: CapturedStream::empty(),
                        elapsed: Duration::ZERO,
                        unproven: Vec::new(),
                    });
                }
                Err(_) => {
                    // Not required: the honest degradation is to proceed and record the
                    // gap below. Never to silently run with no ceiling at all.
                }
            }
        }

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
        let mut child = match spawn_supervisor(&argv, owned.as_ref()) {
            Ok(c) => c,
            Err(e) => {
                // `owned` drops here, removing the dedicated child. A spawn failure must
                // not leave a cgroup behind, and must never fall back to running without
                // the required ceilings.
                drop(owned);
                return Ok(ExecutionResult {
                    status: ExecutionStatus::SpawnFailed(e.to_string()),
                    stdout: CapturedStream::empty(),
                    stderr: CapturedStream::empty(),
                    elapsed: started.elapsed(),
                    unproven: Vec::new(),
                });
            }
        };

        // Membership is verified, not assumed. Writing limits to a cgroup says nothing
        // about who is inside it, so the only admissible evidence that this execution is
        // resource-controlled is our own supervisor appearing in `cgroup.procs`.
        let joined = match &owned {
            None => true,
            Some(cg) => {
                // Awaited, not sampled. `spawn` returns as soon as the child is forked,
                // which is before it has executed anything -- including the write that
                // puts it in the cgroup. A single immediate read therefore sees an empty
                // `cgroup.procs` for a supervisor that is about to join, and would reject
                // a perfectly good execution. The wait is bounded so a child that never
                // joins fails closed rather than hanging.
                let deadline = Instant::now() + Duration::from_millis(2_000);
                loop {
                    if cg.contains(child.id()) {
                        break true;
                    }
                    // A child that has already been reaped will never join.
                    if matches!(child.try_wait(), Ok(Some(_))) {
                        break false;
                    }
                    if Instant::now() >= deadline {
                        break false;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        };
        if !joined {
            let detail = match &owned {
                Some(cg) => format!(
                    "the supervisor did not join the dedicated cgroup (members: {}, \
                     reaped: {:?}); the requested ceilings would not have applied",
                    cg.member_count(),
                    child.try_wait().ok()
                ),
                None => "no dedicated cgroup was established".to_owned(),
            };
            if let Some(cg) = &owned {
                let _ = cg.kill_all();
            }
            let _ = child.kill();
            let _ = child.wait();
            drop(owned);
            return Ok(ExecutionResult {
                status: ExecutionStatus::Refused(SandboxUnavailable::GuaranteeUnavailable {
                    guarantee: "OS-enforced resource ceilings",
                    detail,
                }),
                stdout: CapturedStream::empty(),
                stderr: CapturedStream::empty(),
                elapsed: started.elapsed(),
                unproven: Vec::new(),
            });
        }

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
                // `cgroup.kill` first, then the signal. The signal alone reaches only the
                // supervisor; a descendant that has forked and detached from the pipe
                // would survive it. The cgroup kill is the only mechanism that terminates
                // every member, including one forked concurrently with this loop.
                if let Some(cg) = &owned {
                    let _ = cg.kill_all();
                }
                // SIGKILL rather than SIGTERM: the Phase 4 spike established that a
                // helper may ignore SIGTERM, and a graceful-then-forceful path would
                // wait out a grace period for a process that never honours it.
                let _ = child.kill();
                let _ = child.wait();
                break std::process::ExitStatus::default();
            }
            if self.cancel.load(Ordering::SeqCst) {
                cancelled = true;
                if let Some(cg) = &owned {
                    let _ = cg.kill_all();
                }
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
        // Only reachable when the caller did *not* require enforcement: a required
        // ceiling either got established or the execution was refused above.
        if owned.is_none() && spec.requires.resources == Resource::Observed {
            if spec.limits.memory_bytes.is_some() {
                unproven.push((
                    "OS-enforced memory ceiling",
                    format!(
                        "no usable cgroup controller on this host; the requested {} MiB is \
                         not enforced",
                        spec.limits.memory_bytes.unwrap_or(0) / (1024 * 1024)
                    ),
                ));
            }
            if spec.limits.max_processes.is_some() {
                unproven.push((
                    "OS-enforced process ceiling",
                    "no usable pids controller on this host; the requested ceiling is not \
                     enforced"
                        .to_owned(),
                ));
            }
            if spec.limits.cpu_cores.is_some() {
                unproven.push((
                    "OS-enforced CPU ceiling",
                    "no usable cpu controller on this host; the requested ceiling is not \
                     enforced"
                        .to_owned(),
                ));
            }
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

        // Members are swept before removal so a descendant holding stdout open cannot
        // keep the cgroup alive, and removal stays bounded.
        if let Some(cg) = &owned {
            let _ = cg.kill_all();
        }
        drop(owned);

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
/// The cgroup controls a spec's *portable* limits translate to.
/// This is the whole of the platform-specific knowledge the runner needs, and it
/// lives here rather than in the capability layer: a contract says "64 MiB", never
/// "memory.max" or a cgroup path.
/// Spawns the sandbox supervisor, placing it in the dedicated cgroup first.
///
/// # Why a shell wrapper rather than adopt-after-spawn
///
/// The obvious sequence is spawn, then write the child's pid to `cgroup.procs`. That is
/// a race: cgroup membership is inherited at `fork`, so anything the supervisor forked
/// before the write keeps the *parent's* limits forever, with no error anywhere. The
/// window is `bwrap`'s own startup -- several namespace setups and a `/proc` mount -- and
/// a payload started inside it would be unconstrained.
///
/// Writing the pid from a shell before `exec` closes the window without `unsafe`:
/// `sh` writes `$$` to `cgroup.procs` and then `exec`s `bwrap`, which preserves the pid.
/// `bwrap` is therefore already a member before it can fork anything, and every
/// descendant inherits membership.
///
/// `std::process::Command` has no pre-exec hook without `unsafe`, so this is the
/// standard no-`unsafe` way to do it. The `|| exit` is load-bearing: if the join fails the
/// supervisor must never start, because a running unconstrained process is exactly the
/// failure this design exists to prevent.
fn spawn_supervisor(
    argv: &[String],
    cgroup: Option<&CgroupV2>,
) -> std::io::Result<std::process::Child> {
    let Some(cg) = cgroup else {
        return Command::new(BWRAP)
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // `bwrap` must not inherit our environment: it is the single most
            // effective way for a parent secret to reach a child. The child's own
            // environment is set explicitly by `--setenv` below.
            .env_clear()
            .spawn();
    };

    let procs = cg.path.join("cgroup.procs");
    Command::new("/bin/sh")
        .arg("-c")
        .arg("printf %s \"$$\" > \"$1\" || exit 97; shift; exec \"$@\"")
        .arg("orxnud-join-cgroup")
        .arg(&procs)
        .arg(BWRAP)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .spawn()
}

/// The cgroup v2 control file that expresses each limit this module can enforce.
///
/// # No control is optional
///
/// The brief's rule — *a requested control is established or the execution is refused* —
/// means this returns an error rather than a shorter list. The previous version pushed
/// whatever it could and dropped the rest, which is how a `cpu_cores` of `NaN` produced a
/// cgroup with no `cpu.max` at all while the contract said CPU was required: `NaN > 0.0`
/// is false, the `if let` never fired, and the omission was invisible. A silently dropped
/// control is a required guarantee quietly not provided.
///
/// # `cpu_cores` is converted here, and only here
///
/// The portable contract speaks in fractional cores; `cpu.max` speaks in a quota of
/// microseconds per period. Nothing else in the crate performs that conversion, so there
/// is exactly one place where the two units can be confused.
///
/// # Errors
///
/// [`SandboxUnavailable::Invalid`] naming the limit that could not be expressed. The
/// [`crate::cgroup::LimitInvalid`] detail is carried through so the caller sees the
/// offending number and the range the kernel accepts.
fn controls_for(spec: &SandboxSpec) -> Result<Vec<ResourceControl>, SandboxUnavailable> {
    let mut v = Vec::new();
    if let Some(b) = spec.limits.memory_bytes {
        // Validate before pushing, so a `u64::MAX` budget is refused here -- where the
        // caller can still be told which number was wrong -- rather than becoming a
        // `memory.max` of `max`, which is how a memory ceiling quietly becomes no ceiling.
        ResourceControl::Memory { bytes: b }
            .validate()
            .map_err(|e| SandboxUnavailable::Invalid(e.to_string()))?;
        v.push(ResourceControl::Memory { bytes: b });
        // A memory ceiling evaded by swapping is not a memory ceiling, so the budget is
        // pinned to zero alongside it. `0` is a valid, meaningful `memory.swap.max`, so
        // this one is not a validation concern -- only a policy one.
        ResourceControl::Swap { bytes: 0 }
            .validate()
            .map_err(|e| SandboxUnavailable::Invalid(e.to_string()))?;
        v.push(ResourceControl::Swap { bytes: 0 });
    }
    if let Some(p) = spec.limits.max_processes {
        ResourceControl::Processes { max: p }
            .validate()
            .map_err(|e| SandboxUnavailable::Invalid(e.to_string()))?;
        v.push(ResourceControl::Processes { max: p });
    }
    if let Some(c) = spec.limits.cpu_cores {
        // An explicit conversion, with the rounding stated rather than inherited from
        // `as u64`'s truncation-toward-zero.
        //
        // `as u64` on an `f64` saturates, which is why the `f64::INFINITY` and `1e300`
        // cases used to produce a quota of `u64::MAX` -- a value the kernel stores as
        // `max`, i.e. *unlimited*, so an absurd request silently became no request at all.
        // Converting through a checked helper and letting [`ResourceControl::validate`]
        // judge the result means every one of `NaN`, `inf`, a negative value, zero and a
        // saturating magnitude is refused with a message naming it.
        //
        // The period is the CFS default of 100 ms, inside the kernel's accepted
        // `1000..=1000000` us range (verified). The quota is rounded to the nearest
        // microsecond and then floored at one period-millisecond, which is the CFS
        // bandwidth granularity: anything finer is not expressible, and rounding it to
        // the nearest representable value would *widen* a very small budget by up to
        // 1000x -- a ceiling quietly becoming a looser one.
        const PERIOD_US: u64 = 100_000;
        let scaled = c * PERIOD_US as f64;
        let quota_us = if scaled.is_finite() && scaled >= 0.0 {
            scaled.round() as u64
        } else {
            // Non-finite or negative cannot be ordered against the kernel's range at all,
            // so it is refused by validation rather than coerced here.
            u64::MAX
        };
        let cpu = ResourceControl::Cpu {
            quota_us,
            period_us: PERIOD_US,
        };
        cpu.validate()
            .map_err(|e| SandboxUnavailable::Invalid(e.to_string()))?;
        v.push(cpu);
    }
    Ok(v)
}

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
        // Resources are reported against ground truth rather than a hardcoded `false`.
        //
        // These tests used to assert "this host delegates nothing", which was true when
        // they were written and stopped being true when delegation was found. A test that
        // encodes a host property as a constant reports the wrong problem the moment the
        // host changes -- it is a change detector, not a check of the probe.
        let av = CgroupV2::discover().availability;
        assert_eq!(
            have.resources,
            av.memory || av.processes || av.cpu,
            "the probe must report exactly what the cgroup hierarchy allows"
        );
        if !have.resources {
            assert!(!av.memory && !av.processes && !av.cpu);
        }
    }

    #[test]
    fn a_required_resource_control_that_cannot_be_written_is_refused() {
        // The fail-closed rule, exercised against the availability the host actually
        // reports rather than against an assumption about which host that is.
        //
        // When this host *can* limit, the honest assertion is that a required spec runs;
        // when it cannot, the honest assertion is a refusal. Either way the rule is the
        // same: never run a required ceiling without one.
        let have = BwrapRunner::probe();
        let mut spec = SandboxSpec::new("/bin/true");
        spec.requires.resources = crate::contract::Resource::Required;
        spec.limits.memory_bytes = Some(64 * 1024 * 1024);
        let result = BwrapRunner::new().run(&spec).expect("run");
        if have.resources {
            assert!(
                !matches!(result.status, ExecutionStatus::Refused(_)),
                "a required ceiling this host can enforce must not be refused: {:?}",
                result.status
            );
        } else {
            match result.status {
                ExecutionStatus::Refused(SandboxUnavailable::GuaranteeUnavailable {
                    guarantee,
                    ..
                }) => assert_eq!(guarantee, "OS-enforced resource ceilings"),
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_observed_ceiling_is_either_enforced_or_reported_as_unproven() {
        // The honest degradation, both branches: with `Observed`, a ceiling the platform
        // provides is enforced, and one it cannot provide is recorded as a gap. Never a
        // silent run with no ceiling and no record.
        use crate::contract::Resource;
        let have = BwrapRunner::probe();
        let mut spec = SandboxSpec::new("/bin/true");
        spec.requires.resources = Resource::Observed;
        spec.limits.memory_bytes = Some(64 * 1024 * 1024);
        let result = BwrapRunner::new().run(&spec).expect("run");
        if have.resources {
            assert!(
                !result
                    .unproven
                    .iter()
                    .any(|(g, _)| *g == "OS-enforced memory ceiling"),
                "an enforced ceiling must not be reported as unproven"
            );
        } else {
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

    // ------------------------------------------------------- V-46: limit validation

    #[test]
    fn required_ceilings_with_nothing_to_enforce_are_refused_not_run_unbounded() {
        // The fail-open that measurement found, and the worst of the set.
        //
        // Before this, `spec.requires.resources = Required` with every limit unset
        // produced a cgroup-free run that reported `Exited(0)` and `unproven: []`. A
        // required guarantee was silently absent with nothing recorded anywhere that it
        // was missing -- the run looked clean while enforcing nothing at all.
        //
        // Refused as incoherent, and refused *before* any process exists.
        let mut spec = SandboxSpec::new("/bin/true");
        spec.requires.resources = Resource::Required;
        let result = BwrapRunner::new().run(&spec).expect("run returns a result");
        match result.status {
            ExecutionStatus::Refused(SandboxUnavailable::Invalid(why)) => {
                assert!(
                    why.contains("no ceiling was named"),
                    "the refusal must name the incoherence: {why}"
                );
            }
            other => panic!(
                "a required guarantee with nothing to enforce must be refused, got {other:?} \
                 -- an unbounded run reporting success is the fail-open this closes"
            ),
        }
        assert_eq!(
            result.elapsed,
            Duration::ZERO,
            "the refusal must not have waited"
        );
        assert!(result.stdout.bytes.is_empty(), "nothing may have run");
    }

    #[test]
    fn an_observed_request_with_no_ceilings_is_permitted() {
        // The other side of the same rule, so the refusal cannot be a blanket ban.
        //
        // `Observed` means "make sure you could enforce these, and I accept best effort" --
        // with no ceiling named there is nothing to enforce and nothing to report.
        let mut spec = SandboxSpec::new("/bin/true");
        spec.requires.resources = Resource::Observed;
        let result = BwrapRunner::new().run(&spec).expect("run");
        assert!(
            !matches!(result.status, ExecutionStatus::Refused(_)),
            "an observed request with no ceilings is coherent: {:?}",
            result.status
        );
    }

    #[test]
    fn a_nan_or_infinite_cpu_budget_is_refused_rather_than_dropped_or_widened() {
        // The silent-drop defect, pinned.
        //
        // `NaN > 0.0` is false, so the old `if let ... && c > 0.0` never fired and the CPU
        // control vanished: a *required* CPU ceiling ran with no CPU ceiling, silently.
        // `f64::INFINITY` was worse in the other direction -- `as u64` saturates, so the
        // quota became `u64::MAX`, which the kernel stores as `max`, i.e. *unlimited*.
        // Both now refuse, and both refuse before a cgroup exists.
        for cores in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 0.0] {
            let mut spec = SandboxSpec::new("/bin/true");
            spec.requires.resources = Resource::Required;
            spec.limits.cpu_cores = Some(cores);
            let err = controls_for(&spec).expect_err(&format!(
                "cpu_cores={cores} must be refused, not silently dropped"
            ));
            assert!(
                matches!(err, SandboxUnavailable::Invalid(_)),
                "an unusable budget is an invalid configuration, got {err:?}"
            );
            let result = BwrapRunner::new().run(&spec).expect("run returns a result");
            assert!(
                matches!(result.status, ExecutionStatus::Refused(_)),
                "cpu_cores={cores} must not run: {:?}",
                result.status
            );
            assert_eq!(
                result.elapsed,
                Duration::ZERO,
                "cpu_cores={cores} must be refused before any process exists"
            );
        }
    }

    #[test]
    fn an_unlimited_memory_budget_is_refused_rather_than_becoming_no_limit() {
        // `memory.max` is signed in the kernel, so `u64::MAX` is stored as the literal
        // `max`: verified by write-then-read on this host. A capability asking for an
        // enormous memory budget would otherwise get an uncapped workload while believing
        // it was bounded.
        let mut spec = SandboxSpec::new("/bin/true");
        spec.requires.resources = Resource::Required;
        spec.limits.memory_bytes = Some(u64::MAX);
        let err = controls_for(&spec).expect_err("u64::MAX is not a memory ceiling");
        assert!(err.to_string().contains("memory"), "{err}");

        let result = BwrapRunner::new().run(&spec).expect("run returns a result");
        assert!(
            matches!(result.status, ExecutionStatus::Refused(_)),
            "an uncapped memory request must not run as though it were capped: {:?}",
            result.status
        );
    }

    #[test]
    fn a_zero_process_budget_is_refused_before_a_cgroup_is_created() {
        // `pids.max = 0` is accepted by the kernel and admits no process at all,
        // including the payload. Honouring it would surface much later, as a supervisor
        // that failed to join, with no mention of the number responsible.
        let mut spec = SandboxSpec::new("/bin/true");
        spec.requires.resources = Resource::Required;
        spec.limits.max_processes = Some(0);
        let err = controls_for(&spec).expect_err("0 processes admits no payload");
        assert!(err.to_string().contains("processes"), "{err}");
        let result = BwrapRunner::new().run(&spec).expect("run returns a result");
        assert!(
            matches!(result.status, ExecutionStatus::Refused(_)),
            "{:?}",
            result.status
        );
    }

    #[test]
    fn fractional_cores_convert_to_the_exact_microsecond_quota() {
        // The unit conversion, stated and tested.
        //
        // The portable contract speaks fractional cores; `cpu.max` speaks a quota of
        // microseconds per period. Half a core at the 100 ms CFS period is 50 000 us.
        // Asserting the rendered value is what makes the conversion auditable: a change
        // of period, or a switch to `round` vs truncation, moves these numbers.
        let quota = |cores: f64| -> String {
            let mut spec = SandboxSpec::new("/bin/true");
            spec.limits.cpu_cores = Some(cores);
            controls_for(&spec)
                .expect("expressible")
                .into_iter()
                .find(|c| c.file() == "cpu.max")
                .expect("a cpu control")
                .value()
        };
        assert_eq!(quota(0.5), "50000 100000");
        assert_eq!(quota(1.0), "100000 100000");
        assert_eq!(quota(0.25), "25000 100000");
        assert_eq!(quota(2.0), "200000 100000");
        // A value too fine to express is refused rather than rounded *up* to the
        // granularity, which would widen a very small budget by up to 1000x.
        assert!(
            controls_for(&{
                let mut s = SandboxSpec::new("/bin/true");
                s.limits.cpu_cores = Some(0.000001);
                s
            })
            .is_err(),
            "a millionth of a core is below the CFS granularity and must be refused, not \
             rounded up to something looser"
        );
    }

    #[test]
    fn a_memory_ceiling_implies_no_swap() {
        // A memory ceiling evaded by swapping is not a memory ceiling, so swap is pinned
        // to zero alongside it. Asserted because it is a policy the platform adds on the
        // caller's behalf: a capability that asked only for memory gets a swap decision
        // too, and that should be visible rather than incidental.
        let mut spec = SandboxSpec::new("/bin/true");
        spec.limits.memory_bytes = Some(32 * 1024 * 1024);
        let controls = controls_for(&spec).expect("memory is expressible");
        let files: Vec<&str> = controls.iter().map(|c| c.file()).collect();
        assert!(
            files.contains(&"memory.max") && files.contains(&"memory.swap.max"),
            "a memory ceiling must pin swap as well: {files:?}"
        );
        let swap = controls
            .iter()
            .find(|c| c.file() == "memory.swap.max")
            .unwrap();
        assert_eq!(
            swap.value(),
            "0",
            "swap must be forbidden, not merely bounded"
        );
    }

    #[test]
    fn a_request_with_no_limits_at_all_produces_no_controls() {
        // The distinction the refusal above depends on: "no ceilings named" must be
        // distinguishable from "ceilings named", or the refusal would be unfalsifiable.
        let spec = SandboxSpec::new("/bin/true");
        assert!(
            controls_for(&spec)
                .expect("an empty set is not an error")
                .is_empty(),
            "a spec that names no ceiling must yield no control"
        );
    }
}
