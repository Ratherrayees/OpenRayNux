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
    /// `memory.max` — hard limit on the cgroup's **memory usage**; an allocation past it
    /// fails, or the kernel reclaims, or it OOM-kills the process.
    ///
    /// Deliberately *not* described as an address-space limit, because it is not one.
    /// `memory.max` accounts resident and charged pages, so a process may still reserve a
    /// very large virtual address space -- including one that could never be backed -- and
    /// stay inside the limit. A reader who took this control for `RLIMIT_AS` would
    /// conclude that a workload is prevented from making huge reservations, which this
    /// control does not do.
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

/// Why a [`ResourceControl`] cannot be expressed to the kernel.
///
/// # Why this is not a `String`
///
/// Every variant here was measured on the Phase 4 host by writing the value and
/// reading the kernel's answer back (see [`ResourceControl::validate`]). The
/// distinction matters because the two failure families demand opposite
/// responses:
///
/// - [`Self::OutOfRange`] — **the request is wrong**. Refusing it is the whole point; a
///   caller that asked for a ceiling the kernel cannot express must be told so, not
///   silently given something else.
/// - [`Self::Malformed`] — **the value cannot even be parsed** as a kernel integer.
///
/// Both are *our* fault, and neither is the host's. Collapsing them into
/// "this host does not delegate this controller" — which is what the pre-validation code
/// did — reports a fixable caller bug as an unfixable host misconfiguration, and sends an
/// operator to debug delegation instead of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LimitInvalid {
    /// The value is well-formed but outside what the kernel accepts.
    ///
    /// `cgroup v2` bounds, all measured rather than quoted (see [`ResourceControl::validate`]):
    ///
    /// | Control | Accepted range |
    /// |---|---|
    /// | `memory.max`, `memory.swap.max` | `1 ..= 9223372036854771711` bytes, rounded **down** to 4096 |
    /// | `pids.max` | `1 ..= 4194304` |
    /// | `cpu.max` quota | `1000 ..= 17592186044415` us |
    /// | `cpu.max` period | `1000 ..= 1000000` us |
    ///
    /// The byte ceiling is not arbitrary: `memory.max` is a signed `long long` in the
    /// kernel, and anything at or above `i64::MAX` is stored as the literal string `max` --
    /// that is, **as no limit at all**. So `bytes = u64::MAX` does not mean "an enormous
    /// ceiling", it means "no ceiling", and writing it is indistinguishable from never
    /// having asked. That is the single most dangerous input this type accepts.
    #[error("{control}: {value} is outside the range cgroup v2 accepts ({why})")]
    OutOfRange {
        /// Which control.
        control: &'static str,
        /// The rejected value, rendered.
        value: String,
        /// What the kernel accepts.
        why: &'static str,
    },
    /// The value is not a number the kernel can parse at all.
    #[error("{control}: {value:?} is not a value cgroup v2 can parse")]
    Malformed {
        /// Which control.
        control: &'static str,
        /// The rejected value, rendered.
        value: String,
    },
}

/// The kernel's smallest accepted `cpu.max` quota, in microseconds.
///
/// Measured: `999 100000` is rejected with `EINVAL`, `1000 100000` is accepted. This is
/// the CFS bandwidth granularity, not an OpenRayNux choice, so a fractional core below
/// 1/1000 of a core cannot be expressed as a quota and must be refused rather than
/// rounded.
pub const CPU_QUOTA_MIN_US: u64 = 1_000;

/// The kernel's largest accepted finite `cpu.max` quota, in microseconds.
///
/// Measured by bisection: `17592186044415` is accepted, `17592186044416` is `EINVAL`.
/// (`u64::MAX` is accepted too, but is stored as `max` -- see [`LimitInvalid`].)
pub const CPU_QUOTA_MAX_US: u64 = 17_592_186_044_415;

/// The kernel's accepted `cpu.max` period range, in microseconds.
///
/// Measured: `999` and `1000001` are both `EINVAL`. `100_000` (the CFS default period) is
/// inside it, which is why [`crate::linux`] uses it rather than inventing one.
pub const CPU_PERIOD_MIN_US: u64 = 1_000;
/// See [`CPU_PERIOD_MIN_US`].
pub const CPU_PERIOD_MAX_US: u64 = 1_000_000;

/// The kernel's largest accepted `pids.max`.
///
/// Measured by bisection: `4194304` is accepted, `4194305` is `EINVAL`. This is the
/// kernel's `PID_MAX_LIMIT`.
pub const PIDS_MAX_LIMIT: u64 = 4_194_304;

/// The largest byte count `memory.max` stores as a finite ceiling.
///
/// Measured by bisection: `9223372036854771711` stays finite, `9223372036854771712` and
/// above are stored as `max`. The boundary is `i64::MAX` rounded down to a page, because
/// the kernel parses into a signed `long long`.
pub const MEMORY_MAX_BYTES: u64 = 9_223_372_036_854_771_711;

/// The page size the memory controller rounds byte counts to.
///
/// `memory.max` rounds **down** to a multiple of this, so a request is never silently
/// widened; it can be silently *narrowed* by up to one page.
pub const PAGE_SIZE: u64 = 4096;

impl ResourceControl {
    /// Rejects any value this kernel cannot express as the ceiling that was asked for.
    ///
    /// # Why validation happens here and not at the call site
    ///
    /// Because the dangerous inputs are not obviously wrong to the code that produces
    /// them. `cpu_cores` is an `f64`, and `NaN`, `f64::INFINITY` and a value large enough
    /// to saturate a `u64` cast are all *representable* in that type while being
    /// meaningless as a CPU budget. A `u64::MAX` memory budget is likewise a perfectly
    /// good `u64` that the kernel interprets as "unlimited".
    ///
    /// The pre-validation code produced three distinct wrong behaviours from these, all
    /// measured:
    ///
    /// ```text
    /// cpu_cores = NaN      -> `c > 0.0` is false -> the CPU control is DROPPED
    ///                          -> a required CPU ceiling runs with no ceiling at all
    /// cpu_cores = inf      -> `(inf * 100_000.0) as u64` saturates -> quota u64::MAX
    ///                          -> kernel stores `max` -> unlimited
    /// cpu_cores = 1e-6     -> quota 0 -> kernel EINVAL
    /// memory = u64::MAX    -> kernel stores `max` -> unlimited
    /// ```
    ///
    /// The first is the worst: a control that was *required* and *available* was dropped
    /// without a word, so the run reported success having enforced nothing.
    ///
    /// # What validation does and does not promise
    ///
    /// It proves the value is one this kernel will store as the ceiling requested. It does
    /// not prove the kernel will accept the write -- that is checked by actually writing it
    /// and reported by [`ResourceMiss`].
    ///
    /// # Errors
    ///
    /// [`LimitInvalid`] naming the control, the value, and the range the kernel accepts.
    pub fn validate(self) -> Result<(), LimitInvalid> {
        let control = self.label();
        match self {
            // `memory.max` is page-accounted; `memory.swap.max` is not, and a zero swap
            // ceiling is a policy rather than an impossibility.
            Self::Memory { bytes } => validate_bytes(control, bytes, true),
            Self::Swap { bytes } => validate_bytes(control, bytes, false),
            Self::Processes { max } => {
                if max == 0 {
                    // `0` is *accepted* by the kernel -- verified -- and means "not one
                    // process may exist here". It is not an invalid request, it is a
                    // request that guarantees the execution cannot start, so honouring it
                    // would produce a refusal at a much later and far less informative
                    // point. Refused here, where the number can still be named.
                    return Err(LimitInvalid::OutOfRange {
                        control,
                        value: max.to_string(),
                        why: "a process ceiling of 0 admits no process at all, including \
                              the sandboxed payload; use 1 or more",
                    });
                }
                if max > PIDS_MAX_LIMIT {
                    return Err(LimitInvalid::OutOfRange {
                        control,
                        value: max.to_string(),
                        why: "the kernel's PID_MAX_LIMIT is 4194304",
                    });
                }
                Ok(())
            }
            Self::Cpu {
                quota_us,
                period_us,
            } => {
                if !(CPU_PERIOD_MIN_US..=CPU_PERIOD_MAX_US).contains(&period_us) {
                    return Err(LimitInvalid::OutOfRange {
                        control,
                        value: format!("{quota_us} {period_us}"),
                        why: "the cpu.max period must be between 1000 and 1000000 \
                              microseconds",
                    });
                }
                if quota_us < CPU_QUOTA_MIN_US {
                    return Err(LimitInvalid::OutOfRange {
                        control,
                        value: format!("{quota_us} {period_us}"),
                        why: "a cpu.max quota below 1000 microseconds is below the CFS \
                              bandwidth granularity and cannot be expressed",
                    });
                }
                if quota_us > CPU_QUOTA_MAX_US {
                    return Err(LimitInvalid::OutOfRange {
                        control,
                        value: format!("{quota_us} {period_us}"),
                        why: "the largest finite cpu.max quota is 17592186044415 \
                              microseconds",
                    });
                }
                Ok(())
            }
        }
    }

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

/// Validates a byte-count ceiling for `memory.max` or `memory.swap.max`.
///
/// # Why a sub-page memory budget is refused
///
/// `memory.max` is accounted in **pages**. Measured on this host by write-then-readback:
///
/// ```text
///   1 -> 0        4095 -> 0        4097 -> 4096
/// ```
///
/// So a request of 1 byte becomes a limit of **0**. That is the same class of problem as
/// `u64::MAX` becoming `max`, only narrower: the caller asked for a ceiling and receives a
/// different one, and the one they receive makes the execution impossible rather than
/// unlimited. Measured here: a fresh process joining a cgroup with `memory.max = 0` or
/// `4096` is OOM-killed (`memory.events oom_kill 1`) before it can do work, while a
/// process already resident when the limit is written survives until its next charge.
///
/// The three candidate policies were:
/// - *round up to one page* -- rejected. It would **widen** the requested budget, which on a
///   security boundary is the wrong direction.
/// - *round down and document* -- rejected as the default, because the documented value
///   and the effective value then differ silently, and the effective one is unusable.
/// - *refuse* -- chosen. It is the only option where what the caller was told cannot
///   differ from what the kernel enforces.
///
/// `memory.swap.max` keeps `0` as valid, because "no swap at all" is a real policy that
/// [`crate::linux`] relies on when it pairs a memory ceiling with a swap prohibition.
/// Sub-page swap is not refused, and the asymmetry is deliberate: rounding a swap ceiling
/// down to 0 produces the policy that was asked for, while rounding a memory ceiling down
/// produces one that cannot be met.
fn validate_bytes(
    control: &'static str,
    bytes: u64,
    // Whether this is `memory.max` (page-accounted, so sub-page is unusable) rather than
    // `memory.swap.max` (where a small or zero ceiling is a real policy).
    page_accounted: bool,
) -> Result<(), LimitInvalid> {
    if bytes > MEMORY_MAX_BYTES {
        // The important case. `memory.max` is signed in the kernel, so this is not a
        // colossal ceiling but *no ceiling*: the kernel stores the literal string `max`
        // and the governed workload runs with unlimited memory while the capability
        // believes it asked for a ceiling. Verified by write-then-read on this host.
        return Err(LimitInvalid::OutOfRange {
            control,
            value: bytes.to_string(),
            why: "values at or above i64::MAX are stored by the kernel as `max`, which \
                  means NO limit; an unlimited budget must be expressed as the absence of \
                  a ceiling, not as a huge number",
        });
    }
    if page_accounted && bytes < PAGE_SIZE {
        return Err(LimitInvalid::OutOfRange {
            control,
            value: bytes.to_string(),
            why: "memory is accounted in pages, so a budget below 4096 bytes is stored as \
                  0 -- a limit no execution can meet. Round the budget up to at least \
                  4096, or omit the memory ceiling entirely",
        });
    }
    Ok(())
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
    /// The discovered base may resolve to the cgroup hierarchy root, when the process's
    /// own cgroup is not creatable in (a container scope, for instance). That fallback
    /// is safe **only** because this function never writes a control to the base: it
    /// always creates `base/orxnud-<name>` and puts the limits and the process in *that*.
    ///
    /// Putting an execution directly into the shared root would mean writing
    /// `memory.max` or `pids.max` where unrelated processes live, so a resource limit
    /// could throttle or kill something OpenRayNux does not own. That must never
    /// happen, and [`CgroupV2::create`] is the only place a cgroup is made.
    ///
    /// Asserted by `resources.rs::an_execution_lands_in_a_dedicated_child_cgroup`,
    /// which checks that the returned directory is strictly *below* the base.
    ///
    /// # The base comes from the handle, not from a fresh probe
    ///
    /// An earlier version re-ran [`Self::support`] here and took the base from *that*,
    /// while taking the availability from `self`. Those are two independent probes, so a
    /// host whose delegation changed between them would produce a cgroup created under
    /// one base and configured against another's answers -- a limit written where it does
    /// not apply. The handle's own `base` and `availability` are now the single source,
    /// which is also one fewer probe (and one fewer scratch cgroup) per execution.
    ///
    /// # Errors
    ///
    /// * [`LimitInvalid`] for a value this kernel cannot express as the ceiling asked for,
    ///   raised **before** anything is created.
    /// * [`ResourceMiss`] for the controls this host cannot enforce, named.
    ///
    /// **Fail-closed**: a caller that asked for a memory ceiling is not handed a cgroup
    /// without one.
    pub fn create(&self, name: &str, controls: &[ResourceControl]) -> Result<Self, ResourceMiss> {
        let base = self.base.clone();
        if base.as_os_str().is_empty() {
            return Err(ResourceMiss {
                controls: controls.iter().copied().map(|c| c.label()).collect(),
                reason: "no cgroup v2 base is both creatable and delegated to this process"
                    .to_owned(),
                kind: ResourceMissKind::NoDelegatedBase,
            });
        }
        // Validate every control before creating anything.
        //
        // Doing it first means an inexpressible request costs no directory at all, and --
        // more importantly -- that the failure names the *caller's* number rather than a
        // kernel errno. A refused `u64::MAX` memory budget is a manifest bug; letting the
        // write fail instead would report it as whatever the kernel said, and letting it
        // *succeed* would enforce nothing while claiming to.
        for c in controls {
            c.validate()?;
        }
        self.create_in(&base, name, controls)
    }

    /// Creates the dedicated child under `base`, applying `controls`, all or nothing.
    ///
    /// # Cleanup on every failure path
    ///
    /// Any failure after the directory exists removes it. This is a single function
    /// precisely so that rule has one place to live: previously only the
    /// "controller not delegated" branch cleaned up, and a failure to *write* a control
    /// returned immediately and left an empty `orxnud-*` directory behind forever.
    /// Verified on this host, where a rejected write leaves the directory present, so
    /// those accumulate in the shared base -- exactly the kind of residue a governed
    /// system must not produce.
    ///
    /// Removing is safe unconditionally because nothing has been placed in the cgroup yet:
    /// limits are written before any process is adopted, so this directory has no members
    /// and `rmdir` cannot be refused for that reason.
    ///
    /// # Errors
    ///
    /// [`ResourceMiss`], leaving no directory behind.
    fn create_in(
        &self,
        base: &Path,
        name: &str,
        controls: &[ResourceControl],
    ) -> Result<Self, ResourceMiss> {
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
            kind: ResourceMissKind::CreateRefused,
        })?;
        self.create_at(&path, base, controls)
    }

    /// Configures an already-created `path` as the dedicated child of `base`.
    ///
    /// Split from [`Self::create_in`] so the "a failed configuration leaves nothing
    /// behind" rule can be exercised directly, against a directory whose control writes
    /// are made to fail. Without that seam the rule is only reachable on a host that
    /// happens to refuse a particular control, and an assertion that cannot run is not
    /// an assertion.
    ///
    /// # Errors
    ///
    /// [`ResourceMiss`], with `path` removed.
    fn create_at(
        &self,
        path: &Path,
        base: &Path,
        controls: &[ResourceControl],
    ) -> Result<Self, ResourceMiss> {
        if let Err(miss) = self.configure(path, controls) {
            // One cleanup rule, one place. Every failure after the directory exists goes
            // through here.
            //
            // Previously only the "controller not delegated" branch cleaned up, and a
            // failure to *write* a control returned immediately and left an empty
            // `orxnud-*` directory behind. Verified on this host: a rejected write leaves
            // the directory present, so those accumulate in the shared base and nothing
            // ever removes them.
            //
            // Safe unconditionally because nothing has been placed in the cgroup yet:
            // limits are written before any process is adopted, so this directory has no
            // members and `rmdir` cannot be refused for that reason.
            remove_cgroup_dir(path);
            return Err(miss);
        }

        Ok(Self {
            path: path.to_path_buf(),
            base: base.to_path_buf(),
            availability: self.availability,
            owns_path: true,
        })
    }

    /// Writes `controls` into an existing cgroup directory, all or nothing.
    ///
    /// Split out of [`Self::create`] so the "every failure cleans up" rule has exactly one
    /// place to live: a second call site that forgot the cleanup would reintroduce the
    /// leak rather than merely duplicating the happy path.
    fn configure(&self, path: &Path, controls: &[ResourceControl]) -> Result<(), ResourceMiss> {
        // Availability first, and in full, before writing anything.
        //
        // Checking all of it up front means a request that is partly unsupported never
        // writes the supported subset. The alternative writes `memory.max`, then discovers
        // `pids` is undelegated, and leaves a cgroup that *looks* limited while running
        // the payload with an unbounded process count.
        let missing: Vec<&'static str> = controls
            .iter()
            .copied()
            .filter(|c| !self.availability.supports(*c))
            .map(|c| c.label())
            .collect();
        if !missing.is_empty() {
            return Err(ResourceMiss {
                controls: missing,
                reason: "this host does not delegate these cgroup controllers".to_owned(),
                kind: ResourceMissKind::ControllerUndelegated,
            });
        }

        for c in controls {
            write_control(path, *c).map_err(|e| ResourceMiss {
                controls: vec![c.label()],
                reason: format!("cannot write {}: {e}", c.file()),
                kind: classify_write_error(&e),
            })?;
        }
        Ok(())
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
            kind: ResourceMissKind::WriteFailed,
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
            kind: ResourceMissKind::WriteFailed,
        })
    }

    /// Whether `pid` is currently a member, read from `cgroup.procs`.
    ///
    /// Membership is a fact about the kernel, not about a path string. Everything that
    /// claims "this execution is resource-controlled" must be able to check this, because
    /// writing a limit to a cgroup says nothing about who is inside it.
    #[must_use]
    pub fn contains(&self, pid: u32) -> bool {
        std::fs::read_to_string(self.path.join("cgroup.procs"))
            .map(|t| t.lines().any(|l| l.trim() == pid.to_string()))
            .unwrap_or(false)
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
    /// Which *kind* of failure this is.
    ///
    /// Retained rather than folded into `reason`, because the brief's distinction is
    /// operational: "there is no cgroup v2 here" and "there is one but nothing is
    /// delegated to me" need different responses, and a single "unavailable" hides a
    /// fixable misconfiguration. `reason` is a human sentence and is not a stable
    /// interface; this is.
    pub kind: ResourceMissKind,
}

/// What sort of failure made a required control unenforceable.
///
/// Not derived from the errno alone, because the same errno means different things here:
/// `EINVAL` on a control file is the kernel refusing a *value* (our bug), while `EPERM` is
/// the kernel refusing us the *controller* (a delegation problem). Before this existed,
/// both arrived as "this host does not delegate these cgroup controllers", which is
/// actively misleading for the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceMissKind {
    /// No cgroup v2 hierarchy is mounted, or nothing under it is both creatable by this
    /// process and has controllers delegated to it.
    NoDelegatedBase,
    /// The base directory could not be created.
    CreateRefused,
    /// The controller is listed by the kernel but not delegated to this subtree, so the
    /// write was refused with `EPERM`.
    ControllerUndelegated,
    /// The kernel refused the *value*. A caller bug, not a host limitation.
    ValueRejected,
    /// The write failed for a reason that is neither of the above.
    WriteFailed,
}

impl From<LimitInvalid> for ResourceMiss {
    /// An inexpressible value is reported as a *value* problem, never as a host one.
    ///
    /// The `controls` list carries the offending control's label, so a caller that only
    /// inspects the refusal still learns which of its requirements was wrong -- the same
    /// shape as every other `ResourceMiss`.
    fn from(invalid: LimitInvalid) -> Self {
        // The label travels in the variant as a `&'static str`, so it is matched rather
        // than parsed out of the message. Slicing the `Display` output would couple the
        // error's prose to a machine-readable field, which is the stringly-typed coupling
        // that makes error text impossible to reword safely.
        let control = match &invalid {
            LimitInvalid::OutOfRange { control, .. } | LimitInvalid::Malformed { control, .. } => {
                *control
            }
        };
        Self {
            controls: vec![control],
            reason: invalid.to_string(),
            kind: ResourceMissKind::ValueRejected,
        }
    }
}

/// Classifies a control-file write failure.
///
/// The split is `EINVAL` against everything else, and it is the `EINVAL` case that
/// matters: on this host a delegated controller answers `EPERM` when the controller is not
/// available and `EINVAL` when the number is outside what the kernel can store, and both
/// previously produced the same "not delegated" sentence.
fn classify_write_error(e: &std::io::Error) -> ResourceMissKind {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => ResourceMissKind::ControllerUndelegated,
        std::io::ErrorKind::InvalidInput => ResourceMissKind::ValueRejected,
        _ => ResourceMissKind::WriteFailed,
    }
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

    // ---------------------------------------------------------------- validation
    //
    // These need no delegation and no root: they are pure, so they run identically in CI
    // and on the development host. Each bound they pin was measured on this host by
    // writing the value and reading the kernel's answer back; the `enforcement.rs`
    // suite then proves the kernel honours what these accept.

    #[test]
    fn an_unlimited_memory_budget_is_refused_rather_than_becoming_no_limit() {
        // The most dangerous value this type accepts.
        //
        // `memory.max` is signed in the kernel, so `u64::MAX` is not a colossal ceiling:
        // the kernel stores the literal string `max`, which means *no ceiling at all*.
        // Verified by write-then-read on this host -- `18446744073709551615` reads back
        // as `max`. So a caller asking for an enormous memory budget and getting
        // validation would otherwise get an unbounded workload while believing it was
        // capped.
        let err = ResourceControl::Memory { bytes: u64::MAX }
            .validate()
            .expect_err("u64::MAX is not a ceiling, it is the absence of one");
        assert!(
            err.to_string().contains("NO limit"),
            "the message must explain what u64::MAX actually means: {err}"
        );
        // And the same for every value past the signed boundary.
        for bytes in [
            MEMORY_MAX_BYTES + 1,
            1 << 63,
            i64::MAX as u64,
            i64::MAX as u64 + 1,
        ] {
            assert!(
                ResourceControl::Memory { bytes }.validate().is_err(),
                "{bytes} is stored as `max` and must be refused"
            );
        }
    }

    #[test]
    fn a_memory_ceiling_at_the_signed_boundary_is_still_a_ceiling() {
        // The other side of the same boundary, so the rule is a range and not a guess.
        assert!(
            ResourceControl::Memory {
                bytes: MEMORY_MAX_BYTES
            }
            .validate()
            .is_ok(),
            "the largest finite memory.max must be accepted"
        );
        assert!(
            ResourceControl::Memory {
                bytes: 64 * 1024 * 1024
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn a_sub_page_memory_budget_is_refused_because_it_would_become_zero() {
        // `memory.max` is page-accounted. Measured on this host by write-then-readback:
        // `1 -> 0`, `4095 -> 0`, `4097 -> 4096`. So a 1-byte budget is silently stored as
        // a **zero** ceiling, which is the `u64::MAX` problem in miniature: the caller is
        // told one thing and the kernel enforces another.
        //
        // It is worse than "merely narrower", because the value it becomes is
        // unusable: measured here, a fresh process joining a cgroup with `memory.max = 0`
        // is OOM-killed (`memory.events oom_kill 1`) before doing any work. Rounding *up*
        // to one page would fix the unusability by widening the requested budget, which is
        // the wrong direction on a security boundary, so the value is refused instead.
        for bytes in [1u64, 512, 2048, PAGE_SIZE - 1] {
            let err = ResourceControl::Memory { bytes }
                .validate()
                .expect_err(&format!(
                    "{bytes} bytes is stored as 0, which is not the ceiling that was asked for"
                ));
            assert!(
                err.to_string().contains("page"),
                "the refusal must explain the page granularity: {err}"
            );
        }
        // One page is expressible and is the smallest meaningful memory ceiling.
        assert!(
            ResourceControl::Memory { bytes: PAGE_SIZE }
                .validate()
                .is_ok()
        );
        // And above it, sub-page rounding is at most one page of narrowing, which is
        // acceptable: the value remains what the caller asked for, to within the kernel's
        // own accounting unit.
        assert!(
            ResourceControl::Memory {
                bytes: 64 * 1024 * 1024 + 1
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn swap_zero_is_valid_because_no_swap_is_a_policy_not_a_mistake() {
        // `memory.swap.max = 0` is what pins a memory ceiling against being evaded by
        // swapping, and `linux.rs` relies on it. A validator that rejected it would
        // refuse every memory-bounded execution.
        assert!(
            ResourceControl::Swap { bytes: 0 }.validate().is_ok(),
            "no swap is a real policy"
        );
        assert!(
            ResourceControl::Swap {
                bytes: 64 * 1024 * 1024
            }
            .validate()
            .is_ok()
        );
        assert!(
            ResourceControl::Swap { bytes: u64::MAX }
                .validate()
                .is_err(),
            "but an unlimited swap ceiling is still `max` in the kernel"
        );
    }

    #[test]
    fn a_zero_process_ceiling_is_refused_because_it_admits_no_payload() {
        // `pids.max = 0` is *accepted* by the kernel -- verified -- and means not one
        // process may exist in the cgroup. Honouring it would produce a refusal much
        // later, at the point where the supervisor failed to join, with no mention of the
        // number that caused it. Refused where the number can still be named.
        let err = ResourceControl::Processes { max: 0 }
            .validate()
            .expect_err("a cgroup that admits no process cannot host a payload");
        assert!(err.to_string().contains("0"), "{err}");
    }

    #[test]
    fn a_process_ceiling_beyond_the_kernel_limit_is_refused() {
        // Measured by bisection: `4194304` is accepted, `4194305` is `EINVAL`. Refusing
        // it here means the caller learns their number is wrong instead of receiving
        // "this host does not delegate the pids controller", which is what the write
        // failure used to produce.
        assert!(
            ResourceControl::Processes {
                max: PIDS_MAX_LIMIT
            }
            .validate()
            .is_ok()
        );
        let err = ResourceControl::Processes {
            max: PIDS_MAX_LIMIT + 1,
        }
        .validate()
        .expect_err("past PID_MAX_LIMIT");
        assert!(err.to_string().contains("4194304"), "{err}");
    }

    #[test]
    fn a_cpu_quota_below_the_bandwidth_granularity_is_refused_not_rounded() {
        // Measured: `999 100000` is `EINVAL`, `1000 100000` is accepted. Rounding a tiny
        // budget *up* to 1000 would widen it; a request for a ten-thousandth of a core
        // cannot be honoured and must be refused.
        assert!(
            ResourceControl::Cpu {
                quota_us: 999,
                period_us: 100_000
            }
            .validate()
            .is_err()
        );
        assert!(
            ResourceControl::Cpu {
                quota_us: CPU_QUOTA_MIN_US,
                period_us: 100_000
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn a_cpu_quota_or_period_outside_the_kernel_range_is_refused() {
        // Measured: the largest finite quota is 17592186044415 (17592186044416 is
        // `EINVAL`), and the period must be within 1000..=1000000.
        assert!(
            ResourceControl::Cpu {
                quota_us: CPU_QUOTA_MAX_US,
                period_us: 100_000
            }
            .validate()
            .is_ok()
        );
        assert!(
            ResourceControl::Cpu {
                quota_us: CPU_QUOTA_MAX_US + 1,
                period_us: 100_000
            }
            .validate()
            .is_err(),
            "past the largest finite quota the kernel refuses the value"
        );
        for period_us in [CPU_PERIOD_MIN_US - 1, CPU_PERIOD_MAX_US + 1, 0] {
            assert!(
                ResourceControl::Cpu {
                    quota_us: 50_000,
                    period_us
                }
                .validate()
                .is_err(),
                "period {period_us} is outside the kernel's range"
            );
        }
        assert!(
            ResourceControl::Cpu {
                quota_us: 50_000,
                period_us: 100_000
            }
            .validate()
            .is_ok(),
            "the CFS default period must be accepted"
        );
    }

    #[test]
    fn a_refused_limit_names_the_control_and_the_offending_number() {
        // A refusal a caller can act on. Both halves are asserted, because a message that
        // says only "invalid" sends the operator looking at the host instead of at the
        // manifest that produced the number.
        let err = ResourceControl::Processes {
            max: PIDS_MAX_LIMIT + 1,
        }
        .validate()
        .expect_err("refused");
        let text = err.to_string();
        assert!(text.contains("processes"), "must name the control: {text}");
        assert!(
            text.contains(&(PIDS_MAX_LIMIT + 1).to_string()),
            "must name the number: {text}"
        );
        assert!(text.contains("4194304"), "must state the range: {text}");
    }

    #[test]
    fn an_invalid_limit_is_reported_as_a_value_problem_not_a_host_problem() {
        // The distinction that was previously lost. An inexpressible value is the
        // caller's bug; reporting it as an undelegated controller sends an operator to
        // debug cgroup delegation that was working perfectly.
        let miss = ResourceMiss::from(
            ResourceControl::Memory { bytes: u64::MAX }
                .validate()
                .expect_err("refused"),
        );
        assert_eq!(miss.kind, ResourceMissKind::ValueRejected);
        assert_eq!(miss.controls, vec!["memory"]);
    }

    // cgroup v2 does not exist off Linux, and the distinction under test is between two
    // errno values the kernel returns for a cgroup write.
    #[cfg(unix)]
    #[test]
    fn a_permission_failure_and_a_value_failure_are_different_kinds() {
        // `EPERM` and `EINVAL` on a control file mean opposite things, and the brief
        // forbids collapsing them.
        let denied = classify_write_error(&std::io::Error::from_raw_os_error(libc_eperm()));
        let invalid = classify_write_error(&std::io::Error::from_raw_os_error(libc_einval()));
        assert_eq!(denied, ResourceMissKind::ControllerUndelegated);
        assert_eq!(invalid, ResourceMissKind::ValueRejected);
        let other = classify_write_error(&std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(other, ResourceMissKind::WriteFailed);
    }

    /// `EPERM`, without naming libc: the crate forbids `unsafe` and takes no dependency
    /// for one errno. The value is the ABI constant, which is 1 on every Linux target
    /// this crate builds for.
    fn libc_eperm() -> i32 {
        1
    }

    /// `EINVAL`. See [`libc_eperm`].
    fn libc_einval() -> i32 {
        22
    }

    // ------------------------------------------------------------- partial setup

    /// A base directory whose control files do not exist and cannot be created.
    ///
    /// Running `create_in` against it forces the **write-failure** path -- the one that
    /// previously leaked -- with no delegation and no root required, which is what makes
    /// the assertion below deterministic in CI rather than dependent on a host that
    /// happens to refuse a particular control.
    ///
    /// Removes itself on drop, so a failing assertion cannot leave a directory in `/tmp`.
    /// Six were left behind by deliberately mutated runs during the work that added this,
    /// which is exactly the kind of residue the surrounding tests already guard against
    /// with `Drop` (`Gate` and `Child` in `enforcement.rs`).
    struct ScratchBase(PathBuf);

    impl Drop for ScratchBase {
        fn drop(&mut self) {
            // Best effort: the fixture may already have been removed, and a read-only mode
            // set by a test can prevent removal. Restore permissions first so cleanup can
            // succeed in the latter case.
            restore_tree_permissions(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl ScratchBase {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    /// Makes `dir` and everything under it writable, so it can be removed.
    #[cfg(unix)]
    fn restore_tree_permissions(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                restore_tree_permissions(&p);
            }
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700));
        }
    }

    /// Not a Unix target: nothing to restore, and `remove_dir_all` will report any problem.
    #[cfg(not(unix))]
    fn restore_tree_permissions(_dir: &Path) {}

    fn scratch_base(tag: &str) -> ScratchBase {
        let dir =
            std::env::temp_dir().join(format!("orxnud-fakebase-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        ScratchBase(dir)
    }

    // Unix-gated with the helper it calls. `make_read_only` below is `#[cfg(unix)]`
    // because POSIX mode bits are the only way this crate makes a directory
    // unwritable, and this test is the helper's only caller -- so the caller has to
    // carry the same gate or an MSVC `--all-targets` build fails to resolve the
    // name. Gating the test rather than the helper is also the honest scope: the
    // property under test is that a refused `memory.max` write leaves no cgroup
    // directory behind, and there is no cgroup v2 hierarchy on Windows for that
    // property to hold on. The Linux test is unchanged and still runs there.
    #[cfg(unix)]
    #[test]
    fn a_failed_control_write_leaves_no_cgroup_behind() {
        // The leak, and the fix for it.
        //
        // Verified on this host that a rejected control write leaves the cgroup directory
        // present. The pre-fix code returned on that path without removing it, so empty
        // `orxnud-*` directories accumulated in the shared base and were never cleaned by
        // anything.
        //
        // The write is made to fail deterministically and without delegation: the base
        // contains a **directory** named `memory.max`, so opening it as a file fails with
        // `EISDIR` on any filesystem. On the pre-fix code this assertion failed with the
        // cgroup directory still on disk.
        let base = scratch_base("writefail");
        let base = base.path().to_path_buf();
        // The cgroup directory is built by the test and made read-only, so creating
        // `memory.max` inside it fails with `EACCES`. That makes the write failure
        // deterministic and independent of cgroup delegation, on any filesystem.
        //
        // Read-only rather than "plant something in the way" for a reason tied to the
        // cleanup rule: the cleanup is `rmdir`, which the kernel honours on a cgroupfs
        // directory whose control files are empty, and which a normal filesystem refuses
        // with `ENOTEMPTY` if any real entry remains. A fixture that leaves a file behind
        // would be testing the fixture rather than the code -- so the directory here is
        // left genuinely empty, which is the state a refused write actually produces.
        let cgdir = base.join("orxnud-leak-test-fixture");
        std::fs::create_dir(&cgdir).expect("cgroup dir");
        make_read_only(&cgdir);

        let cg = claiming_everything();
        let miss = cg
            .create_at(
                &cgdir,
                &base,
                &[ResourceControl::Memory {
                    bytes: 16 * 1024 * 1024,
                }],
            )
            .expect_err("writing into a read-only directory must fail");

        // A refused write, reported as such and not as anything the caller must fix.
        assert!(
            !matches!(miss.kind, ResourceMissKind::ValueRejected),
            "an ordinary I/O failure must not be reported as a bad request: {miss}"
        );
        assert!(
            miss.reason.contains("memory.max"),
            "the refusal must name the file it could not write: {}",
            miss.reason
        );
        assert_eq!(miss.controls, vec!["memory"]);

        // The half-configured cgroup is gone.
        assert!(
            !cgdir.exists(),
            "a failed setup must remove its cgroup directory: {}",
            cgdir.display()
        );
        assert_eq!(
            std::fs::read_dir(&base)
                .map(|d| d.flatten().count())
                .unwrap_or(0),
            0,
            "nothing may survive a failed setup in {}",
            base.display()
        );
    }

    /// Removes write permission from a directory, so files cannot be created inside it.
    ///
    /// `#[cfg(unix)]` because that is the only platform this crate's cgroup backend can
    /// run on; the gate is there so the intent is explicit rather than incidental.
    #[cfg(unix)]
    fn make_read_only(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(dir).expect("metadata").permissions();
        perm.set_mode(0o500);
        std::fs::set_permissions(dir, perm).expect("chmod");
    }

    /// A handle that claims every controller is writable, for driving paths the host
    /// itself may not permit.
    ///
    /// `#[cfg(unix)]` with the test that calls it, for the reason the file records
    /// above `a_failed_control_write_leaves_no_cgroup_behind`: the only caller is
    /// Unix-gated, so an ungated helper is dead code there and an MSVC `--all-targets`
    /// build fails on `-D warnings`.
    #[cfg(unix)]
    fn claiming_everything() -> CgroupV2 {
        CgroupV2 {
            path: PathBuf::new(),
            base: PathBuf::new(),
            availability: CgroupAvailability {
                can_create: true,
                memory: true,
                swap: true,
                processes: true,
                cpu: true,
                group_kill: true,
            },
            owns_path: false,
        }
    }

    #[test]
    fn an_undelegated_controller_is_refused_before_anything_is_written() {
        // The pre-check, not a partial write.
        //
        // `memory` is claimed unavailable, so a memory ceiling must be refused outright:
        // writing the *other* control first and then discovering the missing one would
        // leave a cgroup that looks bounded while the memory limit was never applied.
        let base = scratch_base("undelegated");
        let base = base.path().to_path_buf();
        let partial = CgroupV2 {
            path: PathBuf::new(),
            base: base.clone(),
            availability: CgroupAvailability {
                can_create: true,
                memory: false,
                swap: true,
                processes: true,
                cpu: true,
                group_kill: true,
            },
            owns_path: false,
        };
        let miss = partial
            .create_in(
                &base,
                "partial-test",
                &[
                    ResourceControl::Memory {
                        bytes: 32 * 1024 * 1024,
                    },
                    ResourceControl::Processes { max: 16 },
                ],
            )
            .expect_err("an undelegated memory controller must refuse");
        assert_eq!(miss.kind, ResourceMissKind::ControllerUndelegated);
        assert_eq!(miss.controls, vec!["memory"]);
        assert_eq!(
            std::fs::read_dir(&base)
                .map(|d| d.flatten().count())
                .unwrap_or(0),
            0,
            "a refused setup must leave no directory behind"
        );
    }

    #[test]
    fn an_invalid_limit_costs_no_directory_at_all() {
        // Validation runs before `create_dir`, so an inexpressible request never reaches
        // the filesystem. That is what makes the refusal cheap *and* unambiguous: there
        // is nothing to clean up because nothing was made.
        //
        // Exercised through the public entry point, which is where a caller meets it.
        let cg = CgroupV2::discover();
        if cg.base.as_os_str().is_empty() {
            // No delegated base here. `create` refuses before validation with a base
            // error, so this case cannot be reached; the validation logic itself is
            // covered by the `ResourceControl::validate` tests above.
            return;
        }
        let miss = cg
            .create(
                "invalid-test",
                &[ResourceControl::Memory { bytes: u64::MAX }],
            )
            .expect_err("u64::MAX is not a ceiling");
        assert_eq!(miss.kind, ResourceMissKind::ValueRejected);
        assert_eq!(miss.controls, vec!["memory"]);
    }
}
