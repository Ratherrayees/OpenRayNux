//! Subprocess execution boundary: the portable contract and its per-OS backends.
//!
//! # This crate is the sandbox boundary
//!
//! Gate G3 greps the workspace for platform branches and fails if one appears
//! outside a `platform-*` crate. So this is where every `cfg` for process
//! isolation lives, and the portable core asks a trait
//! ([`SandboxRunner`]) what it can guarantee rather than learning which OS it is on.
//!
//! The contract ([`contract`] module) expresses **what** isolation is required;
//! the backends express **how** a particular OS provides it. Nothing in
//! `orxnud-capability` knows that `bubblewrap` exists.
//!
//! # Phase 4 scope: what is proven and what is not
//!
//! The research spike established that three guarantees which are routinely
//! discussed together are in fact separate, and are provided by different kernel
//! facilities:
//!
//! 1. **Visibility** — PID and mount namespaces.
//! 2. **Tree lifetime** — `cgroup.kill`, or a Windows Job Object.
//! 3. **Resource ceilings** — cgroup controllers, or Job Object limits.
//!
//! `--die-with-parent` provides **none of the three**. It sets
//! `PR_SET_PDEATHSIG`, which fires only when the *direct* parent dies; a process
//! that has double-forked and called `setsid` is no longer a direct child. A PID
//! namespace hides processes but does not terminate them.
//!
//! Phase 4a proves 1, and proves environment/filesystem/network/output/timeout
//! isolation. Phase 4b then proves 3 (`Resource`) as well, on a host that delegates the
//! controllers — see [`cgroup`] and `tests/enforcement.rs`. Delegation is a property of
//! the *host*, not of the code, so the standing is measured rather than assumed: where the
//! controllers are unavailable, a capability that requires ceilings is **refused** at
//! runtime rather than quietly downgraded, and [`cgroup::enforcement_environment`]
//! reports which case this host is.
//!
//! Guarantee 2 (`TreeLifetime`) is provided by the PID namespace, with `cgroup.kill` as a
//! deliberate redundant backstop; see [`linux`].
//! See ADR-0035.
//!
//! # Windows: refused, not degraded
//!
//! No Windows sandbox exists. Job Objects and AppContainer are unimplemented
//! (verification register V-29), so [`platform::host_backend`] binds
//! [`platform::UnsupportedRunner`] off Linux, which reports
//! [`AvailableGuarantees::none`] and refuses every request.
//!
//! That is the honest outcome, and it is deliberate. A Windows runner that executed
//! with weaker isolation would be an unsandboxed third-party subprocess, which
//! ADR-0035 rules worse than no capability at all. So the portability work makes the
//! absence **explicit and deterministic** — a Tier-1 capability is refused on Windows,
//! visibly, rather than silently running without a sandbox.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cgroup;
pub mod contract;
pub mod linux;
pub mod platform;

pub use cgroup::{
    CgroupAvailability, CgroupV2, EnforcementEnvironment, LimitInvalid, ResourceControl,
    ResourceMiss, ResourceMissKind,
};
pub use contract::{
    AvailableGuarantees, CapturedStream, ExecutionResult, ExecutionStatus, FsPolicy,
    IsolationRequirements, NetworkPolicy, Resource, ResourceLimits, SandboxRunner, SandboxSpec,
    SandboxUnavailable, TreeLifetime, Visibility,
};
pub use platform::{UnsupportedRunner, host_backend, host_backend_mechanism, host_backend_name};
