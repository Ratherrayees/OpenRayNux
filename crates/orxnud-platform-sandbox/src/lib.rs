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
//! isolation. It does **not** prove 2 or 3, because this host delegates no cgroup
//! controllers (`cgroup.kill`, `memory.max`, and `pids.max` are all unwritable
//! in our user session). Those remain `NOT_PROVEN` and are refused at runtime when
//! a capability requires them, rather than being quietly downgraded.
//!
//! See ADR-0035.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod contract;
pub mod linux;

pub use contract::{
    AvailableGuarantees, CapturedStream, ExecutionResult, ExecutionStatus, FsPolicy,
    IsolationRequirements, NetworkPolicy, Resource, ResourceLimits, SandboxRunner, SandboxSpec,
    SandboxUnavailable, TreeLifetime, Visibility,
};
