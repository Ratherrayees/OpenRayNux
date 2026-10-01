//! Hard resource ceilings: cgroup v2, and what this host can and cannot do.
//!
//! # The host limitation, stated first
//!
//! The Phase 4a/4b host has **no delegated cgroup controllers**. `memory.max`,
//! `pids.max` and `cpu.max` all return `EPERM` in a cgroup created under our own
//! scope, while the controllers are *listed* in `cgroup.controllers`. Those are
//! different facts and only the second one matters, so [`CgroupV2::discover`] tests
//! the write rather than reading the list (V-46).
//!
//! Consequence, and it is deliberate: on such a host, a capability that **requires**
//! ceilings is **refused**, not run unbounded. Nothing here degrades a limit into an
//! observation without the caller opting in.
//!
//! # Where the ceilings are provable
//!
//! A container run with the cgroup filesystem mounted read-write *does* get
//! delegation — verified on this host — and is the environment in which the
//! enforcement tests are meant to run. [`CgroupV2::discover`] therefore reports what
//! is available, and the enforcement tests assert the *semantics* of each control
//! against whatever the host provides. On a host without delegation those tests
//! report `NOT_PROVEN` rather than passing vacuously; see
//! [`enforcement_environment`].
//!
//! # One dimension at a time
//!
//! `memory.max`, `pids.max` and `cpu.max` are separate controls with separate failure
//! modes: an allocation fails, a `fork` returns `EAGAIN`, a process is throttled. They
//! are exercised separately rather than as one "resources" knob, because they are.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Which cgroup v2 control a capability requires.
///
/// One variant per control. A single `Resources { .. }` bundle would let a caller ask
/// for memory and get throttling, which are unrelated guarantees with unrelated failure
/// modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceControl {
    /// `memory.max` — hard address-space ceiling; an allocation past it fails or the
    /// kernel kills the process.
    Memory {
        /// The ceiling in bytes.
        bytes: u64,
    },
    /// `memory.swap.max` — caps swap separately, so a memory ceiling cannot be
    /// evaded by swapping.
    Swap {
        /// The ceiling in bytes; `0` forbids swap entirely.
        bytes: u64,
    },
    /// `pids.max` — ceiling on process and thread count. `fork` returns `EAGAIN`
    /// past it.
    Processes {
        /// The maximum number of processes and threads.
        max: u64,
    },
    /// `cpu.max` — bandwidth cap as `<quota> <period>` in microseconds, or `max
    /// <period>` for no quota.
    Cpu {
        /// Bandwidth quota per period, in microseconds.
        quota_us: u64,
        /// Period length in microseconds.
        period_us: u64,
    },
}

impl ResourceControl {
    /// The cgroup file this control writes.
    #[must_use]
    pub fn file(self) -> &'static str {
        match self {
            Self::Memory { .. } => "memory.max",
            Self::Swap { .. } => "memory.swap.max",
            Self::Processes { .. } => "pids.max",
            Self::Cpu { .. } => "cpu.max",
        }
    }

    /// The value to write.
    #[must_use]
    pub fn value(self) -> String {
        match self {
            Self::Memory { bytes } | Self::Swap { bytes } => bytes.to_string(),
            Self::Processes { max } => max.to_string(),
            Self::Cpu {
                quota_us,
                period_us,
            } => format!("{quota_us} {period_us}"),
        }
    }

    /// A short name for logs and audit records.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Memory { .. } => "memory",
            Self::Swap { .. } => "swap",
            Self::Processes { .. } => "processes",
            Self::Cpu { .. } => "cpu",
        }
    }
}

/// What this host's cgroup v2 hierarchy actually permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CgroupAvailability {
    /// A cgroup could be created under our own scope.
    pub can_create: bool,
    /// `memory.max` is writable.
    pub memory: bool,
    /// `memory.swap.max` is writable.
    pub swap: bool,
    /// `pids.max` is writable.
    pub processes: bool,
    /// `cpu.max` is writable.
    pub cpu: bool,
    /// `cgroup.kill` is writable, which terminates every member including
    /// concurrently-forked children.
    pub group_kill: bool,
}

impl CgroupAvailability {
    /// Whether `control` can be enforced here.
    #[must_use]
    pub fn supports(self, control: ResourceControl) -> bool {
        match control {
            ResourceControl::Memory { .. } => self.memory,
            ResourceControl::Swap { .. } => self.swap,
            ResourceControl::Processes { .. } => self.processes,
            ResourceControl::Cpu { .. } => self.cpu,
        }
    }

    /// The controls that cannot be enforced here.
    #[must_use]
    pub fn missing(&self, wanted: &[ResourceControl]) -> Vec<&'static str> {
        wanted
            .iter()
            .copied()
            .filter(|c| !self.supports(*c))
            .map(|c| c.label())
            .collect()
    }
}

/// A cgroup v2 subtree this process may manage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupV2 {
    /// The directory this handle owns — always a **dedicated child**, never the base.
    pub path: PathBuf,
    /// The parent this handle was created under.
    ///
    /// Retained so "is the execution in a dedicated child?" is answerable from the
    /// handle rather than inferred. See [`CgroupV2::is_dedicated_child`].
    pub base: PathBuf,
    /// What the host permits.
    pub availability: CgroupAvailability,
    /// Whether this process created `path` and is therefore responsible for removing it.
    ///
    /// `discover()` also returns a handle, and *its* `path` is the base -- a directory
    /// this process must never touch. Cleanup is gated on this flag, because a `Drop`
    /// that ran on a discovered handle would write `cgroup.kill` to the whole session
    /// cgroup and then try to `rmdir` it.
    owns_path: bool,
}

impl CgroupV2 {
    /// Whether this handle's directory is strictly below its base.
    ///
    /// The mechanical form of the safety property: a limit written to `self.path` can
    /// only affect processes that were adopted into it, and never the base's other
    /// members.
    #[must_use]
    pub fn is_dedicated_child(&self) -> bool {
        self.path != self.base && self.path.starts_with(&self.base)
    }
}

impl CgroupV2 {
    /// Discovers what is available, by attempting the writes.
    ///
    /// Probing creates and removes a scratch cgroup. That is the only reliable test:
    /// reading `cgroup.controllers` reports what the *kernel* supports, and the
    /// failure mode that matters is whether *we* may write.
    #[must_use]
    pub fn discover() -> Self {
        let (base, availability) = Self::support();
        Self {
            path: PathBuf::new(),
            base,
            availability,
            owns_path: false,
        }
    }

    /// The environment's standing, without collapsing distinct failures.
    ///
    /// The brief's distinction matters operationally: "there is no cgroup v2" and
    /// "there is one but nothing is delegated to me" need different responses, and a
    /// single "unavailable" would hide a fixable misconfiguration.
    #[must_use]
    pub fn support() -> (PathBuf, CgroupAvailability) {
        // Distinguish "no cgroup v2 at all" from "one exists but is undelegated".
        if !Path::new("/sys/fs/cgroup")
            .join("cgroup.controllers")
            .exists()
        {
            return (PathBuf::new(), CgroupAvailability::default());
        }
        delegated_base().unwrap_or_else(|| (PathBuf::new(), CgroupAvailability::default()))
    }

    /// Creates a **dedicated child** cgroup, with `controls` applied.
    ///
    /// # "Dedicated child" is the whole safety property
    ///
    /// [`own_cgroup`] may resolve to the cgroup hierarchy root, when the process's own
    /// cgroup is not creatable in (a container scope, for instance). That fallback is
    /// safe **only** because this function never writes a control to the base: it always
    /// creates `base/orxnud-<name>` and puts the limits and the process in *that*.
    ///
    /// Putting an execution directly into the shared root would mean writing
    /// `memory.max` or `pids.max` where unrelated processes live, so a resource limit
    /// could throttle or kill something OpenRayNux does not own. That must never
    /// happen, and [`CgroupV2::create`] is the only place a cgroup is made.
    ///
    /// Asserted by `resources.rs::an_execution_lands_in_a_dedicated_child_cgroup`,
    /// which checks that the returned directory is strictly *below* the base.
    ///
    /// # Errors
    ///
    /// The controls this host cannot enforce, named. **Fail-closed**: a caller that
    /// asked for a memory ceiling is not handed a cgroup without one.
    pub fn create(&self, name: &str, controls: &[ResourceControl]) -> Result<Self, ResourceMiss> {
        let (base, _) = Self::support();
        if base.as_os_str().is_empty() {
            return Err(ResourceMiss {
                controls: controls.iter().copied().map(|c| c.label()).collect(),
                reason: "no cgroup v2 base is both creatable and delegated to this process"
                    .to_owned(),
            });
        }
        // Unique per invocation: see `unique_suffix`. Two concurrent executions must
        // never share a cgroup, or they would share limits and each would delete the
        // other's directory while the other was still running in it.
        let path = base.join(format!("orxnud-{name}-{}", unique_suffix()));
        // Deliberately `create_dir`, not `create_dir_all` over a `remove_dir`. Clearing
        // a pre-existing path first is what let a concurrent caller destroy a cgroup
        // that another process was still a member of.
        std::fs::create_dir(&path).map_err(|e| ResourceMiss {
            controls: controls.iter().copied().map(|c| c.label()).collect(),
            reason: format!("cannot create {}: {e}", path.display()),
        })?;

        let mut missing = Vec::new();
        for c in controls {
            if !self.availability.supports(*c) {
                missing.push(c.label());
                continue;
            }
            if let Err(e) = write_control(&path, *c) {
                return Err(ResourceMiss {
                    controls: vec![c.label()],
                    reason: format!("cannot write {}: {e}", c.file()),
                });
            }
        }
        if !missing.is_empty() {
            // Remove the half-configured cgroup: a partial limit set is worse than
            // none, because it looks enforced.
            let _ = std::fs::remove_dir(&path);
            return Err(ResourceMiss {
                controls: missing,
                reason: "this host does not delegate these cgroup controllers".to_owned(),
            });
        }

        Ok(Self {
            path,
            base,
            availability: self.availability,
            owns_path: true,
        })
    }

    /// Moves `pid` into this cgroup, so its limits apply.
    ///
    /// # Errors
    ///
    /// Whatever the kernel refused, with the file named.
    pub fn adopt(&self, pid: u32) -> Result<(), ResourceMiss> {
        std::fs::write(self.path.join("cgroup.procs"), pid.to_string()).map_err(|e| ResourceMiss {
            controls: Vec::new(),
            reason: format!("cannot move {pid} into the cgroup: {e}"),
        })
    }

    /// Writes `1` to `cgroup.kill`, terminating every member.
    ///
    /// The kernel walks the cgroup, so a member that forks *during* the kill is still
    /// caught — which is the property a signal cannot offer (ADR-0035).
    ///
    /// # Errors
    ///
    /// If `cgroup.kill` is not writable here.
    pub fn kill_all(&self) -> Result<(), ResourceMiss> {
        std::fs::write(self.path.join("cgroup.kill"), "1\n").map_err(|e| ResourceMiss {
            controls: vec!["group-kill"],
            reason: format!("cgroup.kill refused: {e}"),
        })
    }

    /// How many processes are in the cgroup.
    #[must_use]
    pub fn member_count(&self) -> usize {
        std::fs::read_to_string(self.path.join("cgroup.procs"))
            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0)
    }

    /// Whether a pid is still alive.
    #[must_use]
    pub fn pid_alive(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    /// Removes the cgroup. Best effort: a cgroup with live members cannot be removed,
    /// and forcing it would need `cgroup.kill` anyway.
    pub fn remove(mut self) {
        // The work happens here, and `owns_path` is cleared so `Drop` does not repeat it.
        // Forgetting the handle instead would have made `remove()` a silent no-op, which
        // is how 48 cgroups leaked in a 6-way concurrent run before it was caught.
        let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
        remove_cgroup_dir(&self.path);
        self.owns_path = false;
    }
}

/// Removes a cgroup directory, retrying while the kernel finishes releasing it.
///
/// # Why `remove_dir` and not `remove_dir_all`
///
/// A cgroup directory contains kernel-managed control files that **cannot be unlinked**,
/// so `remove_dir_all` fails on the first one and leaves the cgroup behind. The correct
/// call is `rmdir`, which succeeds once the cgroup is empty.
///
/// Empty is not immediate, though: a process that has been killed can take a moment to be
/// reaped from `cgroup.procs`. Hence the bounded retry. This is not a retry to paper over
/// a race -- the outcome is deterministic once the kernel catches up -- and it is bounded
/// so a genuinely stuck cgroup cannot hang a caller.
fn remove_cgroup_dir(path: &std::path::Path) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match std::fs::remove_dir(path) {
            Ok(()) => return true,
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => return false,
        }
    }
}

impl Drop for CgroupV2 {
    /// Guarantees cleanup on the failure path too.
    ///
    /// A test that panics between `create` and `remove` used to leave its cgroup behind
    /// permanently, and every later run inherited the pile. Members are killed first so a
    /// failed test cannot leave descendants running either.
    fn drop(&mut self) {
        if self.owns_path && !self.path.as_os_str().is_empty() {
            let _ = std::fs::write(self.path.join("cgroup.kill"), "1");
            remove_cgroup_dir(&self.path);
        }
    }
}

/// A required resource control this host cannot enforce.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("required resource controls unavailable: {controls:?} ({reason})")]
pub struct ResourceMiss {
    /// Which controls are missing.
    pub controls: Vec<&'static str>,
    /// Why.
    pub reason: String,
}

fn write_control(path: &Path, control: ResourceControl) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path.join(control.file()))?;
    f.write_all(control.value().as_bytes())?;
    f.sync_all()
}

/// Every directory that could serve as a cgroup base, nearest first.
///
/// Own cgroup, then each ancestor, then the hierarchy root. The root is a valid base
/// when delegation reaches it; it is only ever a **parent**, never the execution's home.
fn candidate_bases() -> Vec<PathBuf> {
    let root = Path::new("/sys/fs/cgroup").to_path_buf();
    let mut out: Vec<PathBuf> = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/proc/self/cgroup")
        && let Some(line) = text.lines().find(|l| l.starts_with("0::"))
    {
        let rel = line
            .trim_start_matches("0::")
            .trim()
            .trim_start_matches('/');
        let mut cur = root.clone();
        if !rel.is_empty() {
            for seg in rel.split('/') {
                if seg.is_empty() {
                    continue;
                }
                cur = cur.join(seg);
                out.push(cur.clone());
            }
        }
    }
    out.push(root);
    out.dedup();
    out
}

/// Probes one candidate base by creating a child cgroup and attempting each write.
///
/// # Creation alone is not delegation
///
/// A directory can be perfectly creatable and have **no controllers delegated to
/// it**. The container case is exactly that: `/sys/fs/cgroup/system.slice/docker-<id>.scope`
/// accepts `mkdir` and refuses `memory.max`, because the controllers sit at the root and
/// were never delegated down. Selecting a base on creatability alone therefore picks a
/// base where nothing can be enforced -- and reports "delegated" for an environment that
/// is not (V-57).
///
/// So the probe is the *write*. That is also the only probe that answers the question
/// that matters: "can I enforce a limit here?"
fn probe_base(base: &Path) -> (bool, CgroupAvailability) {
    let child = base.join(probe_dir_name());
    // A leftover from a previous run is not an error; it also means we already know
    // the base is creatable. With a name unique to this invocation, an existing
    // directory can only be our own stale one, so it is safe to keep writing into it.
    let created = std::fs::create_dir(&child).is_ok();
    if !created && !child.exists() {
        return (false, CgroupAvailability::default());
    }
    let write = |f: &str, v: &str| std::fs::write(child.join(f), v).is_ok();
    let availability = CgroupAvailability {
        can_create: true,
        memory: write("memory.max", "67108864"),
        swap: write("memory.swap.max", "0"),
        processes: write("pids.max", "64"),
        cpu: write("cpu.max", "50000 100000"),
        group_kill: write("cgroup.kill", "1"),
    };
    remove_cgroup_dir(&child);
    (true, availability)
}

/// A probe directory name unique to this invocation.
///
/// # Why the name must be unique
///
/// The probe directory used to be a fixed `.orxnud-probe`. `discover()` runs it against
/// every candidate base, and any number of callers may run concurrently -- which they do
/// by default under `cargo test`, where test binaries execute in parallel and each
/// binary discovers independently.
///
/// With a shared name the sequence is not atomic: caller **A** creates the directory,
/// caller **B** fails `create_dir` and proceeds because the directory *exists*, then
/// **A** finishes and removes it -- and **B**'s remaining writes now fail with `ENOENT`.
/// The symptom was an intermittent `ResourceMiss { controls: ["cpu"] }` on a host that
/// does delegate `cpu`, appearing only under parallel execution.
///
/// A per-invocation name removes the interleaving entirely: no two probes can ever hold
/// the same directory, so one caller can never delete another's. This is correct
/// regardless of test ordering, which is the property that matters -- a retry loop would
/// only have hidden it.
fn probe_dir_name() -> String {
    format!(".orxnud-probe-{}", unique_suffix())
}

/// A suffix unique to this process and this call.
///
/// Within a process the counter is exact. Across processes the pid makes it unique for
/// every concurrent run, and a pid can only be reused after its previous owner has
/// exited -- by which point its cgroups are gone. This is what makes discovery and
/// execution correct *independently of ordering*: nothing is shared, so nothing can be
/// deleted out from under a concurrent caller.
fn unique_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// The first base where a child cgroup can be created **and** controllers written.
fn delegated_base() -> Option<(PathBuf, CgroupAvailability)> {
    candidate_bases()
        .into_iter()
        .map(|base| {
            let (created, availability) = probe_base(&base);
            (base, created, availability)
        })
        .find(|(_, created, a)| *created && (a.memory || a.processes || a.cpu))
        .map(|(base, _, availability)| (base, availability))
}

/// What the enforcement tests should conclude on this host.
///
/// Deliberately a value rather than a skip: a caller can print it, assert on it, or
/// record it in a verification register entry. A test that silently skips teaches
/// nothing and reports nothing.
#[must_use]
pub fn enforcement_environment() -> EnforcementEnvironment {
    let a = CgroupV2::discover().availability;
    if a.memory && a.processes && a.cpu {
        EnforcementEnvironment::Delegated
    } else {
        EnforcementEnvironment::Undelegated {
            missing: [
                (!a.memory).then_some("memory"),
                (!a.swap).then_some("swap"),
                (!a.processes).then_some("processes"),
                (!a.cpu).then_some("cpu"),
            ]
            .into_iter()
            .flatten()
            .collect(),
        }
    }
}

/// Where resource enforcement stands on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementEnvironment {
    /// Every control is writable, so enforcement can be proven here.
    Delegated,
    /// Some controls are refused, so enforcement is **not** proven here.
    Undelegated {
        /// Which controls are missing.
        missing: Vec<&'static str>,
    },
}

impl EnforcementEnvironment {
    /// Whether enforcement tests can run here.
    #[must_use]
    pub fn can_enforce(&self) -> bool {
        matches!(self, Self::Delegated)
    }

    /// A one-line description for a test report or a register entry.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Delegated => {
                "cgroup v2 delegated: memory, swap, pids, cpu and cgroup.kill all writable"
                    .to_owned()
            }
            Self::Undelegated { missing } => format!(
                "cgroup v2 NOT delegated (missing: {}); resource enforcement is NOT_PROVEN \
                 here and a capability requiring a ceiling is refused",
                missing.join(", ")
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_control_maps_to_its_own_file_and_value() {
        // One dimension at a time: a bundled knob would let a caller ask for memory
        // and silently get throttling.
        assert_eq!(ResourceControl::Memory { bytes: 1024 }.file(), "memory.max");
        assert_eq!(ResourceControl::Memory { bytes: 1024 }.value(), "1024");
        assert_eq!(ResourceControl::Swap { bytes: 0 }.file(), "memory.swap.max");
        assert_eq!(ResourceControl::Processes { max: 8 }.file(), "pids.max");
        assert_eq!(
            ResourceControl::Cpu {
                quota_us: 50_000,
                period_us: 100_000
            }
            .value(),
            "50000 100000"
        );
        assert_ne!(
            ResourceControl::Memory { bytes: 1 }.label(),
            ResourceControl::Swap { bytes: 1 }.label(),
            "memory and swap are separate controls"
        );
    }

    #[test]
    fn availability_is_established_by_writing_not_by_listing() {
        // The distinction V-46 exists for: this host *lists* memory and pids in
        // `cgroup.controllers` and refuses both writes.
        let a = CgroupV2::discover().availability;
        if a.can_create {
            assert!(
                a.memory || !a.supports(ResourceControl::Memory { bytes: 1 }),
                "a control cannot be supported without being writable"
            );
        }
    }

    #[test]
    fn the_environment_description_states_what_is_proven() {
        let env = enforcement_environment();
        let text = env.describe();
        if env.can_enforce() {
            assert!(text.contains("delegated"), "{text}");
        } else {
            assert!(
                text.contains("NOT_PROVEN"),
                "an undelegated host must say so: {text}"
            );
        }
    }

    #[test]
    fn a_control_is_either_enforced_or_refused_and_never_silently_skipped() {
        // The invariant, stated so it holds on *every* host.
        //
        // This test used to assert the host refuses, on the strength of an earlier
        // probe nested under `app.slice/ptyxis-spawn-*.scope`. That scope accepts no
        // controllers; its **parent** `user@1000.service` does. Discovery now walks
        // ancestors and probes by writing, so the development host turns out to be
        // delegated after all (V-57).
        //
        // Asserting a fixed outcome would re-break on a host change; asserting the
        // *rule* tests the property that must never change.
        let cg = CgroupV2::discover();
        match cg.create(
            "fail-closed-test",
            &[ResourceControl::Memory {
                bytes: 64 * 1024 * 1024,
            }],
        ) {
            Ok(cgroup) => {
                assert!(
                    cg.availability.memory,
                    "a cgroup carrying a memory ceiling needs the controller"
                );
                let limit =
                    std::fs::read_to_string(cgroup.path.join("memory.max")).unwrap_or_default();
                assert_eq!(
                    limit.trim(),
                    (64 * 1024 * 1024).to_string(),
                    "a returned cgroup must actually carry the requested ceiling"
                );
                cgroup.remove();
            }
            Err(miss) => {
                assert!(
                    !miss.controls.is_empty(),
                    "a refusal must name the control it could not enforce"
                );
            }
        }
    }
}
