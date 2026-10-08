//! The portable execution contract: **what** isolation is required, never **how**.
//!
//! # Three independent guarantees, deliberately not conflated
//!
//! The Phase 4 research spike found that the original single property — *"no
//! undeclared access, and no residue"* — collapsed three separate things that Linux
//! provides by completely different mechanisms, at three different levels of kernel
//! support. Treating them as one property is what made the phase unachievable rather
//! than merely unfinished, so this module names them separately and never lets one
//! stand in for another.
//!
//! | Guarantee | Linux mechanism | Windows mechanism |
//! |---|---|---|
//! | [`Visibility`] — which processes and files exist | PID + mount namespaces | Job Object / AppContainer file view |
//! | [`TreeLifetime`] — a detached descendant cannot outlive the execution | **cgroup `cgroup.kill`** | **Job Object kill-on-close** |
//! | [`Resource`] — hard memory/CPU/PID ceilings | cgroup v2 controllers | Job Object limits |
//!
//! The spike's finding, recorded because it is the kind of claim that gets written
//! down wrongly and then trusted:
//!
//! - `--die-with-parent` sets `PR_SET_PDEATHSIG`, which fires **only when the direct
//!   parent dies**. A process that has double-forked and called `setsid` is no longer
//!   a direct child, so it survives. Verified: three containment options
//!   (`--unshare-pid --die-with-parent`, `--unshare-pid` alone, `--die-with-parent`
//!   alone) and a grandchild that ignored `SIGTERM`/`SIGINT`/`SIGHUP` **escaped all
//!   three.**
//! - A PID namespace gives *visibility* control (the helper saw four PIDs, all its
//!   own) but not *lifetime* control: killing the namespace's init does not
//!   terminate its remaining members.
//!
//! ## What Phase 4a proved, and what it did not
//!
//! | Guarantee | Status | Evidence |
//! |---|---|---|
//! | Environment isolation | **PROVEN** | `tests/isolation.rs`; a synthetic marker in the supervisor's environment does not reach the child |
//! | Filesystem isolation | **PROVEN** | same file; a file outside the grant is unreadable |
//! | Network isolation | **PROVEN** | same file; proved against a live listener on the host loopback |
//! | Output bounds | **PROVEN** | same file; a 50 MB flood is capped |
//! | Timeout | **PROVEN** | same file; a hang is killed at the deadline and the supervisor returns |
//! | Descriptor hygiene | **PROVEN (weak)** | same file; compared against an unsandboxed baseline. The teeth-check is inconclusive on this host — see V-47 |
//! | Visibility | **PROVEN** | PID namespace: the helper sees only its own processes |
//! | [`TreeLifetime`] | **PROVEN** | a detached, `SIGTERM`-ignoring grandchild is killed; 5 of 5 runs. The first measurement said otherwise and was wrong — see V-45 |
//! | [`Resource`] ceilings | **NOT PROVEN** | `memory.max`, `pids.max`, `cpu.max` are unwritable in this user session. Requested by default and **refused**, never downgraded |
//!
//! Windows is **NOT_PROVEN** for everything. No Windows code is written and none can
//! be validated on this host; V-29 already carries that caveat and this phase extends
//! rather than relaxes it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Network access a sandboxed process is granted.
///
/// A closed enum rather than a list of hosts, because "allow these domains" and "no
/// network" are very different requests and an allow-list in the portable core would
/// leak the assumption that network filtering is expressible as hostnames — it is not;
/// it is a namespace, a firewall, or a proxy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NetworkPolicy {
    /// No network interfaces except a down loopback. The default.
    ///
    /// `Default` because "assume the capability can reach the network" is the
    /// optimistic default, and an optimistic default on a security boundary is a bug
    /// waiting for a caller who forgets.
    #[default]
    None,
    /// Full network access. Requested explicitly, never inferred.
    Full,
}

/// Filesystem access a sandboxed process is granted.
///
/// Grants are **exact paths**, and the default is a *closed* sandbox: nothing is
/// readable or writable unless named.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FsPolicy {
    /// Paths readable (and writable) inside the sandbox. Empty means the sandbox
    /// root only.
    pub read_write: Vec<PathBuf>,
    /// Paths readable but not writable.
    pub read_only: Vec<PathBuf>,
    /// Paths deliberately absent, so a test can assert an *active* denial rather
    /// than the absence of a grant.
    ///
    /// Exists because "no undeclared filesystem access" is otherwise untestable:
    /// without a named forbidden path, a test can only observe that something
    /// happened, not that the right thing was refused.
    pub denied: Vec<PathBuf>,
}

/// A hard ceiling on a resource, or `None` for "not requested".
///
/// `Option` rather than a zero value because zero is a meaningful limit for `pids`
/// and an invalid one for a duration, and a type that cannot represent "unset"
/// invites a silent default.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResourceLimits {
    /// Wall-clock ceiling. Enforced by the supervisor, so it always applies.
    pub wall_clock: Duration,
    /// Maximum captured bytes per stream. Enforced by the supervisor.
    pub output_bytes: u64,
    /// Memory ceiling, in bytes.
    ///
    /// `None` when the platform cannot enforce one. The contract reports this as
    /// `NOT_PROVEN` rather than pretending a counter is a limit.
    pub memory_bytes: Option<u64>,
    /// Maximum concurrent processes inside the sandbox.
    pub max_processes: Option<u64>,
    /// CPU ceiling, in fractional cores (e.g. `0.5` for half a core).
    pub cpu_cores: Option<f64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            // Generous, because this is a *ceiling* and a tighter one would surprise
            // a legitimate capability. The dispatcher sets tighter values per call.
            wall_clock: Duration::from_secs(300),
            // 1 MiB per stream. A capability that needs more should say so; a helper
            // that floods output should be cut off rather than allowed to exhaust the
            // daemon's memory.
            output_bytes: 1024 * 1024,
            memory_bytes: None,
            max_processes: None,
            cpu_cores: None,
        }
    }
}

/// Which independent guarantees an execution is asking for.
///
/// Separate fields rather than a bitmask of one "isolation" flag, because they are
/// provided by different kernel facilities and a single flag would let a caller
/// believe it had containment when it had only visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IsolationRequirements {
    /// Which processes and files the process can see at all.
    pub visibility: Visibility,
    /// Whether a detached descendant must be unable to outlive the execution.
    pub tree_lifetime: TreeLifetime,
    /// Whether hard resource ceilings must be enforced by the OS.
    pub resources: Resource,
}

/// See the module docs: namespaces and AppContainer file views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Visibility {
    /// PID and mount namespaces, or the platform equivalent. Requested by default,
    /// because it is available everywhere and costs nothing.
    #[default]
    Namespaced,
    /// No namespace isolation. Explicitly weaker, and recorded as such.
    None,
}

/// See the module docs: `cgroup.kill` and Job Objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TreeLifetime {
    /// The execution must be able to terminate a detached descendant. **Not
    /// available on the Phase 4a host**, so requests for it are refused rather than
    /// downgraded.
    #[default]
    Required,
    /// The caller accepts that a detached descendant may survive, and has been told
    /// what that means.
    ///
    /// `Default` is `Required`, not `BestEffort`: the safe default for a security
    /// property is to demand it and fail when it is unavailable, because a capability
    /// that cannot contain its children should not start.
    BestEffort,
}

/// See the module docs: cgroup controllers and Job Object limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Resource {
    /// Hard ceilings are required. Refused when the platform cannot provide them.
    #[default]
    Required,
    /// The caller accepts supervisor-side observation instead of OS enforcement.
    ///
    /// Named `Observed` rather than `Enforced` because that is the honest word:
    /// counting a child's memory is not limiting it.
    Observed,
}

/// How hard the sandbox refuses a request it cannot satisfy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxUnavailable {
    /// The sandbox mechanism is not installed or not permitted.
    ///
    /// The message is surfaced to the user, because "the sandbox is missing" and "the
    /// capability failed" need different responses.
    MechanismMissing(String),
    /// A guarantee was required and cannot be provided.
    ///
    /// This is the fail-closed path. The brief's rule — *a requested isolation mode
    /// that cannot be established must fail closed* — is why this is an error rather
    /// than a logged warning.
    GuaranteeUnavailable {
        /// Which guarantee.
        guarantee: &'static str,
        /// Why it is unavailable.
        detail: String,
    },
    /// The requested configuration is incoherent.
    Invalid(String),
}

impl std::fmt::Display for SandboxUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MechanismMissing(what) => write!(
                f,
                "the sandbox mechanism is unavailable ({what}). No capability will run \
                 without it: an unsandboxed capability has no isolation at all, which is \
                 worse than no capability"
            ),
            Self::GuaranteeUnavailable { guarantee, detail } => write!(
                f,
                "required guarantee `{guarantee}` cannot be provided: {detail}. Refusing \
                 rather than running with weaker isolation than was asked for"
            ),
            Self::Invalid(why) => write!(f, "invalid sandbox configuration: {why}"),
        }
    }
}

impl std::error::Error for SandboxUnavailable {}

/// Everything a sandboxed execution is given.
///
/// No defaults that grant access. An empty `env` is a closed environment, not "the
/// parent's" — the Phase 4 spike proved that inheriting the parent environment is
/// how a credential leaks into a child that has no credential handle in the API.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxSpec {
    /// The executable to run. Absolute; resolved by the caller, never by the sandbox.
    pub program: PathBuf,
    /// Arguments. Passed as a vector, never a shell string.
    pub args: Vec<String>,
    /// The complete environment. **Empty means no environment**, not the parent's.
    pub env: BTreeMap<String, String>,
    /// Working directory inside the sandbox.
    pub working_dir: PathBuf,
    /// Filesystem grants.
    pub fs: FsPolicy,
    /// Network grant.
    pub network: NetworkPolicy,
    /// Resource ceilings.
    pub limits: ResourceLimits,
    /// Which guarantees are required.
    pub requires: IsolationRequirements,
    /// Whether the process must die when the supervisor dies.
    ///
    /// Distinct from [`TreeLifetime::Required`] on purpose. Parent-death signalling is
    /// cheap and available; subtree kill is neither. Conflating them is how a design
    /// ends up claiming containment it has.
    pub die_with_supervisor: bool,
}

impl SandboxSpec {
    /// A spec with no grants whatsoever.
    ///
    /// The builder methods only ever *add* explicit grants, so a forgotten setting
    /// produces a more restricted capability rather than a less restricted one.
    ///
    /// `working_dir` defaults to the platform's root separator — `/` on Linux, `\` on
    /// Windows. Not a hard-coded `"/"`: this module is the *portable* half of the
    /// boundary and is compiled for every target, so a literal POSIX root would be a
    /// Linux assumption in the one file that must not contain one (gate G3). On Linux
    /// the value is byte-identical to the previous literal.
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            working_dir: PathBuf::from(std::path::MAIN_SEPARATOR_STR),
            fs: FsPolicy::default(),
            network: NetworkPolicy::None,
            limits: ResourceLimits::default(),
            requires: IsolationRequirements::default(),
            die_with_supervisor: true,
        }
    }

    /// Adds an argument.
    #[must_use]
    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    /// Grants one environment variable. The only way to add one.
    #[must_use]
    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    /// Grants a read-write path.
    #[must_use]
    pub fn grant_rw(mut self, p: impl Into<PathBuf>) -> Self {
        self.fs.read_write.push(p.into());
        self
    }

    /// Grants a read-only path.
    #[must_use]
    pub fn grant_ro(mut self, p: impl Into<PathBuf>) -> Self {
        self.fs.read_only.push(p.into());
        self
    }

    /// Names a path that must be denied, so a test can assert an *active* refusal.
    #[must_use]
    pub fn deny(mut self, p: impl Into<PathBuf>) -> Self {
        self.fs.denied.push(p.into());
        self
    }

    /// Grants full network access. Never inferred.
    #[must_use]
    pub fn with_network(mut self) -> Self {
        self.network = NetworkPolicy::Full;
        self
    }

    /// Sets the wall-clock ceiling.
    #[must_use]
    pub fn with_deadline(mut self, d: Duration) -> Self {
        self.limits.wall_clock = d;
        self
    }

    /// Sets the per-stream output cap.
    #[must_use]
    pub fn with_output_cap(mut self, bytes: u64) -> Self {
        self.limits.output_bytes = bytes;
        self
    }

    /// Accepts a best-effort tree lifetime instead of requiring it.
    ///
    /// The only way to relax [`TreeLifetime`], and named so that a caller reaching for
    /// it is visible in a diff.
    #[must_use]
    pub fn accepting_best_effort_containment(mut self) -> Self {
        self.requires.tree_lifetime = TreeLifetime::BestEffort;
        self
    }

    /// Whether this spec asks for anything the environment may not be able to give.
    #[must_use]
    pub fn demands(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.requires.tree_lifetime == TreeLifetime::Required {
            v.push("process-tree lifetime containment");
        }
        if self.requires.resources == Resource::Required {
            v.push("OS-enforced resource ceilings");
        }
        v
    }
}

/// How a sandboxed execution ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// The process exited with this code on its own.
    Exited(i32),
    /// The supervisor stopped it at the deadline.
    TimedOut,
    /// The supervisor stopped it because cancellation was requested.
    Cancelled,
    /// The process was killed after exceeding the output cap.
    OutputExceeded {
        /// Which stream.
        stream: &'static str,
        /// The cap that was hit.
        cap: u64,
    },
    /// The supervisor could not establish the requested sandbox, **before starting
    /// anything**.
    ///
    /// The phase is part of the value, not a convention the caller has to know. There is
    /// a second way for a runner to fail to establish a sandbox — see
    /// [`Self::Abandoned`] — and a caller that cannot tell them apart has to guess, and
    /// the optimistic guess turns a capability that ran into one that provably did not.
    Refused(SandboxUnavailable),
    /// The runner started the process and **then** could not establish a required
    /// guarantee, so it stopped the execution and is reporting on something that existed.
    ///
    /// # Why this is not `Refused`
    ///
    /// The concrete case is the Linux backend's cgroup-membership check: it waits for the
    /// supervisor to appear in the dedicated cgroup, and if it never does it kills what it
    /// started and gives up. By then a payload may have run to completion — the check can
    /// fail *because* the supervisor came and went faster than the poll — and the runner
    /// has no way to tell that case from the one where the supervisor never got started at
    /// all.
    ///
    /// Reporting both as [`Self::Refused`] makes "nothing ran" unrepresentable-but-claimed.
    /// A caller reading `Refused` as a disproof then records *"definitely did not happen"*
    /// for an execution whose defining property is that nobody can say, and that verdict is
    /// what authorises an automatic retry of a side effect that may already exist.
    ///
    /// The security-relevant question is not "did it succeed?" but "did anything run?", and
    /// this is the value that answers it.
    Abandoned(SandboxUnavailable),
    /// The process could not be started at all.
    ///
    /// Distinct from a process that was killed: **nothing ran**. A caller retrying a
    /// spawn failure is retrying something that never began.
    ///
    /// The phase is load-bearing here too, for the same reason as [`Self::Refused`]: a
    /// runner may only report this when no process was created. Losing track of a process
    /// that already exists is [`Self::Killed`].
    SpawnFailed(String),
    /// The process was terminated by a signal.
    ///
    /// Phase 4b addition. `Exited(n)` already covers a normal exit, but a capability
    /// killed by `SIGKILL` — including one killed by the kernel for exceeding a
    /// resource ceiling — has no exit code, and folding that into `SpawnFailed` would
    /// claim nothing ran when something did.
    ///
    /// Also the value a runner must use when it has started a process and can no longer
    /// account for it. There is no separate status for that, because the fact both share
    /// is the one that matters: a process existed and its outcome is not established.
    Killed,
}

/// Whether a stream was complete, or truncated at the cap.
///
/// Truncation is reported rather than hidden: a caller reading `stdout` must be able
/// to tell "the helper said this" from "the helper said more than we kept".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedStream {
    /// What was captured, up to the cap.
    pub bytes: Vec<u8>,
    /// Whether the cap was reached and output was discarded.
    pub truncated: bool,
    /// How many bytes were discarded.
    pub dropped: u64,
}

/// The result of a sandboxed execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    /// How it ended.
    pub status: ExecutionStatus,
    /// Captured standard output.
    pub stdout: CapturedStream,
    /// Captured standard error.
    pub stderr: CapturedStream,
    /// Wall-clock duration actually spent.
    pub elapsed: Duration,
    /// Guarantees that were **not** provided, with the reason.
    ///
    /// The mechanism by which a caller learns that its sandbox was weaker than it
    /// asked for. A spec that demanded a guarantee and did not get it must fail closed,
    /// so this is normally empty — and when it is not empty, it is because the caller
    /// explicitly accepted [`TreeLifetime::BestEffort`].
    pub unproven: Vec<(&'static str, String)>,
}

impl ExecutionResult {
    /// Whether the process exited cleanly on its own.
    #[must_use]
    pub fn is_clean_exit(&self) -> bool {
        matches!(self.status, ExecutionStatus::Exited(0))
    }

    /// Whether a process was started at all.
    ///
    /// False for a refusal and for a spawn failure. The security-relevant question:
    /// "did anything run?" is not the same as "did it succeed?".
    ///
    /// This is the whole reason [`ExecutionStatus::Abandoned`] exists rather than being
    /// folded into [`ExecutionStatus::Refused`]: a refusal and an abandonment look alike
    /// from the outside, and this predicate is the one place that has to tell them apart.
    #[must_use]
    pub fn did_start(&self) -> bool {
        !matches!(
            self.status,
            ExecutionStatus::SpawnFailed(_) | ExecutionStatus::Refused(_)
        )
    }

    /// Whether the process ran but did not report success.
    ///
    /// True for every terminal state that is not a clean exit and not "never started",
    /// which is what a caller needs in order to decide the effect's truth is unknown
    /// rather than negative (TP-12).
    #[must_use]
    pub fn is_indeterminate(&self) -> bool {
        matches!(
            self.status,
            ExecutionStatus::TimedOut
                | ExecutionStatus::Cancelled
                | ExecutionStatus::OutputExceeded { .. }
                | ExecutionStatus::Abandoned(_)
                | ExecutionStatus::Killed
        )
    }

    /// A short, redacted summary suitable for an audit record.
    #[must_use]
    pub fn summary(&self) -> String {
        let status = match &self.status {
            ExecutionStatus::Exited(c) => format!("exit {c}"),
            ExecutionStatus::TimedOut => "timed out".to_owned(),
            ExecutionStatus::Cancelled => "cancelled".to_owned(),
            ExecutionStatus::OutputExceeded { stream, cap } => {
                format!("output cap on {stream} at {cap} bytes")
            }
            ExecutionStatus::Refused(e) => format!("refused: {e}"),
            ExecutionStatus::Abandoned(e) => format!("abandoned after starting: {e}"),
            ExecutionStatus::SpawnFailed(e) => format!("spawn failed: {e}"),
            ExecutionStatus::Killed => "killed by a signal".to_owned(),
        };
        format!(
            "{status} in {}ms, stdout {}B{}, stderr {}B{}",
            self.elapsed.as_millis(),
            self.stdout.bytes.len(),
            if self.stdout.truncated {
                " (truncated)"
            } else {
                ""
            },
            self.stderr.bytes.len(),
            if self.stderr.truncated {
                " (truncated)"
            } else {
                ""
            },
        )
    }
}

/// Launches a sandboxed process.
///
/// The portable half of the execution boundary. Every method is a *requirement*; the
/// platform backend either satisfies it or returns [`SandboxUnavailable`].
///
/// `Send + Sync` because a supervisor is shared: one daemon runs dispatches from a
/// worker pool, and a runner that could only be owned by one thread would force a
/// supervisor per thread — which is how supervisor state ends up duplicated.
pub trait SandboxRunner: Send + Sync {
    /// Runs `spec` to completion, honouring its deadline and output caps.
    ///
    /// # Errors
    ///
    /// [`SandboxUnavailable`] only when the sandbox could not be established. A
    /// *helper* that fails is an [`ExecutionStatus`], not an error: the sandbox
    /// worked, the helper did not.
    ///
    /// # The phase is part of the error contract
    ///
    /// `Err` means **no process was created**, exactly as
    /// [`ExecutionStatus::SpawnFailed`] does. There is no way to report "I gave up on a
    /// process I had already started" as an error, and the reason is deliberate: a
    /// caller holding an `Err` has nothing that could indicate whether anything ran, so
    /// it has to record "nothing ran", and a runner that could return `Err` after
    /// spawning would make that recording false.
    ///
    /// A runner that has started something reports [`ExecutionStatus::Abandoned`] or
    /// [`ExecutionStatus::Killed`] instead — never `Err`.
    ///
    /// # Panics
    ///
    /// Never. A runner that panics would take the daemon with it, and ADR-0009's
    /// whole premise is that a faulty integration cannot do that.
    fn run(&self, spec: &SandboxSpec) -> Result<ExecutionResult, SandboxUnavailable>;

    /// Requests cancellation of a running execution.
    ///
    /// Separate from [`Self::run`] so a supervisor can hold a handle while `run` is
    /// still blocked on a process that refuses to die.
    fn cancel(&self) -> Result<(), SandboxUnavailable>;

    /// Which guarantees this runner can actually provide on this host.
    ///
    /// Reported so a caller can decide *before* dispatch rather than discovering it as
    /// a refusal mid-flight.
    fn available_guarantees(&self) -> AvailableGuarantees;
}

/// What a specific runner can provide, on this host, right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvailableGuarantees {
    /// PID/mount namespaces are available.
    pub visibility: bool,
    /// `cgroup.kill` (or the platform equivalent) is available.
    pub tree_lifetime: bool,
    /// cgroup controllers (or the equivalent) are available.
    pub resources: bool,
}

impl AvailableGuarantees {
    /// A runner that provides nothing. Used to test the fail-closed path.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            visibility: false,
            tree_lifetime: false,
            resources: false,
        }
    }

    /// Checks a spec against what is available, and explains any shortfall.
    ///
    /// # Errors
    ///
    /// [`SandboxUnavailable::GuaranteeUnavailable`] naming the first missing
    /// guarantee. Fail-closed: the caller gets a refusal, not a weaker sandbox.
    pub fn check(&self, spec: &SandboxSpec) -> Result<(), SandboxUnavailable> {
        if spec.requires.tree_lifetime == TreeLifetime::Required && !self.tree_lifetime {
            return Err(SandboxUnavailable::GuaranteeUnavailable {
                guarantee: "process-tree lifetime containment",
                detail: "no cgroup `cgroup.kill` or Job Object available on this host".to_owned(),
            });
        }
        if spec.requires.resources == Resource::Required && !self.resources {
            return Err(SandboxUnavailable::GuaranteeUnavailable {
                guarantee: "OS-enforced resource ceilings",
                detail: "no cgroup controllers or Job Object limits available".to_owned(),
            });
        }
        if spec.requires.visibility == Visibility::Namespaced && !self.visibility {
            return Err(SandboxUnavailable::GuaranteeUnavailable {
                guarantee: "namespace isolation",
                detail: "no PID/mount namespace or AppContainer isolation available".to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_spec_grants_nothing() {
        let s = SandboxSpec::new("/bin/true");
        assert!(
            s.env.is_empty(),
            "the environment must be closed by default"
        );
        assert!(s.fs.read_write.is_empty() && s.fs.read_only.is_empty());
        assert_eq!(s.network, NetworkPolicy::None, "no network by default");
        assert!(s.die_with_supervisor);
    }

    #[test]
    fn the_default_tree_lifetime_is_required_not_best_effort() {
        // The asymmetry matters: a caller must opt *out* of containment, so the
        // refusal is visible in a diff.
        assert_eq!(TreeLifetime::default(), TreeLifetime::Required);
        assert_eq!(Resource::default(), Resource::Required);
        assert_eq!(NetworkPolicy::default(), NetworkPolicy::None);
    }

    #[test]
    fn a_required_guarantee_is_refused_when_unavailable() {
        let s = SandboxSpec::new("/bin/true");
        let have = AvailableGuarantees {
            visibility: true,
            tree_lifetime: false,
            resources: false,
        };
        let err = have.check(&s).expect_err("must refuse");
        assert!(matches!(
            err,
            SandboxUnavailable::GuaranteeUnavailable { guarantee, .. }
                if guarantee == "process-tree lifetime containment"
        ));
        // And the message must not read like a warning.
        assert!(err.to_string().contains("Refusing"), "{err}");
    }

    #[test]
    fn relaxing_containment_is_explicit_and_visible_in_demands() {
        let s = SandboxSpec::new("/bin/true");
        assert!(s.demands().contains(&"process-tree lifetime containment"));

        let relaxed = s.clone().accepting_best_effort_containment();
        assert!(
            !relaxed
                .demands()
                .contains(&"process-tree lifetime containment")
        );
        // Resource enforcement is still required: relaxing containment must not
        // silently relax anything else.
        assert!(relaxed.demands().contains(&"OS-enforced resource ceilings"));
    }

    #[test]
    fn a_runner_with_everything_satisfies_a_full_spec() {
        let have = AvailableGuarantees {
            visibility: true,
            tree_lifetime: true,
            resources: true,
        };
        have.check(&SandboxSpec::new("/bin/true"))
            .expect("all available");
    }

    #[test]
    fn grants_are_explicit_and_additive() {
        let s = SandboxSpec::new("/bin/true")
            .env("ALLOWED", "yes")
            .grant_ro("/etc/ssl")
            .grant_rw("/tmp/work")
            .deny("/home/user/.ssh");
        assert_eq!(s.env.len(), 1);
        assert_eq!(s.env.get("ALLOWED").map(String::as_str), Some("yes"));
        assert_eq!(s.fs.read_only, vec![PathBuf::from("/etc/ssl")]);
        assert_eq!(s.fs.read_write, vec![PathBuf::from("/tmp/work")]);
        assert_eq!(s.fs.denied, vec![PathBuf::from("/home/user/.ssh")]);
    }

    #[test]
    fn a_summary_reports_truncation() {
        let r = ExecutionResult {
            status: ExecutionStatus::OutputExceeded {
                stream: "stdout",
                cap: 1024,
            },
            stdout: CapturedStream {
                bytes: vec![0; 1024],
                truncated: true,
                dropped: 999_999,
            },
            stderr: CapturedStream {
                bytes: Vec::new(),
                truncated: false,
                dropped: 0,
            },
            elapsed: Duration::from_millis(42),
            unproven: Vec::new(),
        };
        let s = r.summary();
        assert!(s.contains("output cap on stdout at 1024 bytes"), "{s}");
        assert!(s.contains("(truncated)"), "{s}");
    }

    #[test]
    fn a_clean_exit_is_distinguishable_from_every_other_status() {
        let mk = |status| ExecutionResult {
            status,
            stdout: CapturedStream {
                bytes: vec![],
                truncated: false,
                dropped: 0,
            },
            stderr: CapturedStream {
                bytes: vec![],
                truncated: false,
                dropped: 0,
            },
            elapsed: Duration::ZERO,
            unproven: Vec::new(),
        };
        assert!(mk(ExecutionStatus::Exited(0)).is_clean_exit());
        for status in [
            ExecutionStatus::Exited(1),
            ExecutionStatus::TimedOut,
            ExecutionStatus::Cancelled,
            ExecutionStatus::SpawnFailed("x".into()),
        ] {
            assert!(
                !mk(status.clone()).is_clean_exit(),
                "{status:?} is not a clean exit"
            );
        }
    }
}
