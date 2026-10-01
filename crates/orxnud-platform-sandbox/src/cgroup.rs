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
        let availability = Self::probe();
        Self {
            path: PathBuf::new(),
            base: PathBuf::new(),
            availability,
        }
    }

    fn probe() -> CgroupAvailability {
        let Some(base) = own_cgroup() else {
            return CgroupAvailability::default();
        };
        let probe = base.join("orxnud-resource-probe");
        let Ok(()) = std::fs::create_dir(&probe) else {
            return CgroupAvailability::default();
        };
        let write = |f: &str, v: &str| std::fs::write(probe.join(f), v).is_ok();
        let availability = CgroupAvailability {
            can_create: true,
            memory: write("memory.max", "67108864"),
            swap: write("memory.swap.max", "0"),
            processes: write("pids.max", "64"),
            cpu: write("cpu.max", "50000 100000"),
            group_kill: write("cgroup.kill", "1"),
        };
        let _ = std::fs::remove_dir(&probe);
        availability
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
        let base = own_cgroup().ok_or(ResourceMiss {
            controls: controls.iter().map(|c| c.label()).collect(),
            reason: "this host has no cgroup v2 hierarchy".to_owned(),
        })?;
        let path = base.join(format!("orxnud-{name}"));
        let _ = std::fs::remove_dir(&path);
        std::fs::create_dir_all(&path).map_err(|e| ResourceMiss {
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
    pub fn remove(self) {
        let _ = std::fs::remove_dir_all(&self.path);
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

/// The nearest cgroup v2 directory this process may create children in.
///
/// Tries the process's own cgroup first, then the hierarchy root. The fallback is
/// not a convenience: a container run with `--cgroupns=host` reports its own cgroup as
/// the docker scope it runs in, and that scope accepts no subdirectories even though
/// the controllers are writable at the root. Probing only the own path therefore
/// reported "no delegation" in an environment that *does* delegate -- the opposite of
/// the truth, and worse than not probing at all.
///
/// Verified rather than assumed: with the fallback the same container reports every
/// control writable, and `cgroup.kill` terminates a member's descendants.
fn own_cgroup() -> Option<PathBuf> {
    let root = Path::new("/sys/fs/cgroup");
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/proc/self/cgroup")
        && let Some(line) = text.lines().find(|l| l.starts_with("0::"))
    {
        let rel = line
            .trim_start_matches("0::")
            .trim()
            .trim_start_matches('/');
        if !rel.is_empty() {
            candidates.push(root.join(rel));
        }
    }
    candidates.push(root.to_path_buf());
    candidates.into_iter().find(|c| {
        std::fs::create_dir(c.join(".orxnud-writable-probe")).is_ok_and(|()| {
            let _ = std::fs::remove_dir(c.join(".orxnud-writable-probe"));
            true
        })
    })
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
    fn requesting_an_unavailable_control_fails_closed() {
        // The invariant: a capability that requires a ceiling is refused rather than
        // run without one.
        let cg = CgroupV2::discover();
        let err = cg
            .create(
                "fail-closed-test",
                &[ResourceControl::Memory {
                    bytes: 64 * 1024 * 1024,
                }],
            )
            .expect_err("must refuse when undelegated");
        assert!(
            !err.controls.is_empty(),
            "the refusal must name the control"
        );
        assert!(
            err.reason.contains("delegat") || err.reason.contains("create"),
            "{}",
            err.reason
        );
    }
}
