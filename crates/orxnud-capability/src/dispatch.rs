//! The deterministic dispatcher: the only route from an authorised intent to an
//! executed effect.
//!
//! # The property this type exists to guarantee
//!
//! > An action can leave OpenRayNux only through the governed dispatch path.
//!
//! That is achieved structurally rather than by review. `CapabilityInvocation` has
//! one constructor and it demands `orxnud-policy`'s private seal (ADR-0034), so no
//! other crate can manufacture authority. This crate holds the *other* half:
//! `PolicyEngine::authorise_for_dispatch` is the single method that hands an
//! invocation out, and [`Dispatcher::dispatch`] is the single place that asks for
//! one and then acts on it.
//!
//! # The stages, and why the order is not negotiable
//!
//! ```text
//!  1. AUTHORITY            who is asking, and on whose authority
//!  2. POLICY               deterministic decision: allow, gate, deny
//!  3. APPROVAL             digest-bound, single-use, re-verified
//!  4. BUDGET               charged before execution, not after
//!  5. CAPABILITY RESOLUTION find an implementation for the declared id
//!  6. CREDENTIAL RESOLUTION  resolve a secret, if and only if permitted
//!  7. EXECUTION            call the adapter
//!  8. VERIFICATION         decide whether the effect actually happened
//!  9. AUDIT / FINAL STATE  record it, hash-chained
//! ```
//!
//! Stages 1–4 are performed *inside* `orxnud-policy`, not here. That is deliberate:
//! policy is the sole authority for its own decisions, and a dispatcher that
//! reimplemented any of them would be a second authorization system. This crate
//! orchestrates the stages and enforces the ordering; policy decides.
//!
//! # Why credentials come so late
//!
//! Stage 6 is after every check that can refuse. The tempting alternative -- resolve
//! the credential when an invocation exists -- is wrong, because "an invocation
//! exists" is precisely the thing a bypass would forge. Resolution is authorised by
//! *this* dispatcher having walked stages 1–5, not by the mere existence of a value.
//!
//! # Reentrancy
//!
//! An adapter may not call back into the dispatcher. See
//! [`Dispatcher::enter_guarded`] for why, and for what the bounded alternative is.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use orxnud_domain::Actor;
use orxnud_domain::approval::{ApprovalDigest, ApprovalRecord, NormalizedParams};
use orxnud_domain::ids::CapabilityId;
use orxnud_domain::invocation::{ActionRequest, CapabilityInvocation, InvocationContext};
use orxnud_domain::platform::{SecretRef, SecretsContract};
use orxnud_policy::{PolicyEngine, PolicyError};

use crate::credential::{CredentialBroker, CredentialError};
use crate::verification::{ExecutionOutcome, VerificationOutcome, Verifier, VerifyError};

/// Why a dispatch did not complete.
///
/// Every variant fails closed: there is no path here that means "carry on and treat
/// it as success".
#[derive(Debug)]
pub enum DispatchError {
    // --- stages 1-4: the governed refusals ---
    /// Authority, policy, approval or budget refused. The policy crate's own error,
    /// kept verbatim so the reason is never flattened into "denied".
    Policy(PolicyError),

    /// A Tier-1 capability could not be sandboxed, so nothing ran.
    ///
    /// Distinct from [`Self::Execution`] and [`Self::Failed`] on purpose: nothing was
    /// executed, so retrying the *capability* cannot help, and reporting it as an
    /// execution failure would suggest the adapter ran and failed.
    SandboxRefused(SandboxRefusal),

    /// The capability is declared but has no registered implementation.
    ///
    /// Distinct from policy's `UnknownCapability`: the policy *knows* about this
    /// capability, but nothing implements it. A user needs different information
    /// for each.
    NoImplementation(CapabilityId),

    /// The implementation exists but is switched off.
    Disabled(CapabilityId),

    /// The implementation's declared data class is below the invocation's.
    ///
    /// A declaration-level check that policy does not make, because policy evaluates
    /// grants and this compares the *implementation* against what it was handed.
    ClassEscalation {
        /// Which capability.
        id: CapabilityId,
        /// What the implementation declared.
        declared: orxnud_domain::enums::DataClass,
        /// What was asked for.
        actual: orxnud_domain::enums::DataClass,
    },

    // --- stage 6: credentials ---
    /// A required credential could not be produced. The value is never in here.
    Credential(CredentialError),

    // --- stages 7-8: execution and verification ---
    /// The adapter failed, timed out, or did not report.
    ///
    /// Never interpreted as a permission problem: an adapter that cannot do the work
    /// fails the *work*.
    Execution(String),

    /// Verification could not run. Maps to "undetermined", never to success.
    Verification(VerifyError),

    /// The effect is known not to have happened.
    VerificationRefuted {
        /// What refuted it.
        evidence: String,
    },

    // --- infrastructure ---
    /// The audit journal could not be written.
    ///
    /// Fatal, and fatal *after* execution too: an action with no audit record is
    /// worse than a refused action, because the user cannot tell what happened.
    Audit(String),

    /// An adapter tried to call back into the dispatcher.
    Reentrant(String),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "policy refused: {e}"),
            Self::SandboxRefused(r) => write!(
                f,
                "{refused} was refused: {reason} (missing: {missing})",
                refused = r.capability,
                reason = r.reason,
                missing = if r.missing.is_empty() {
                    "none".to_owned()
                } else {
                    r.missing.join(", ")
                },
            ),
            Self::NoImplementation(c) => write!(f, "{c} is declared but has no implementation"),
            Self::Disabled(c) => write!(f, "{c} is disabled"),
            Self::ClassEscalation {
                id,
                declared,
                actual,
            } => write!(
                f,
                "{id} implements up to {declared:?} but was invoked at {actual:?}"
            ),
            Self::Credential(e) => write!(f, "{e}"),
            Self::Execution(e) => write!(f, "execution failed: {e}"),
            Self::Verification(e) => write!(f, "{e}"),
            Self::VerificationRefuted { evidence } => {
                write!(f, "verification refuted the effect: {evidence}")
            }
            Self::Audit(e) => write!(f, "audit journal unavailable: {e}"),
            Self::Reentrant(c) => write!(f, "adapter attempted a reentrant dispatch: {c}"),
        }
    }
}

impl std::error::Error for DispatchError {}

/// What a completed dispatch concluded.
///
/// The execution and verification results are kept as separate fields because the
/// caller's next decision differs per combination: a verified effect is done; an
/// unverified one may need `NeedsVerification`; a refuted one may be retried. A
/// single `success: bool` would collapse exactly the distinction TP-12 and I8 exist
/// to preserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchOutcome {
    /// What the adapter reported.
    pub execution: ExecutionOutcome,
    /// What verification concluded.
    pub verification: VerificationOutcome,
    /// The capability that ran.
    pub capability: CapabilityId,
}

impl DispatchOutcome {
    /// Whether the effect is confirmed to have happened.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verification.is_verified()
    }

    /// Whether the truth is unknown, and the caller must decide.
    ///
    /// The state that must never be reported as success, and the reason
    /// `DispatchOutcome` has no `success` field.
    #[must_use]
    pub fn is_undetermined(&self) -> bool {
        self.verification.is_undetermined()
    }
}

/// A registered capability implementation.
///
/// # `tier` is load-bearing
///
/// A Tier-1 capability **must** be sandboxed, and the dispatcher refuses to invoke one
/// that cannot be (V-50, ADR-0035). The tier is a method on the adapter rather than a
/// field on the declaration because the adapter is the thing that knows how it runs:
/// a declaration claiming Tier 0 while the implementation spawns a subprocess would
/// be exactly the bypass Phase 4b exists to close.
pub trait CapabilityAdapter: Send + Sync {
    /// The id this adapter implements.
    fn capability_id(&self) -> &CapabilityId;

    /// The highest data class this adapter may handle.
    fn declared_class(&self) -> orxnud_domain::enums::DataClass;

    /// Which isolation tier this implementation requires.
    ///
    /// `InProcess` is Tier 0: a Rust trait call in this address space, where a panic
    /// is a bug we fix. `Subprocess` is Tier 1 and **requires** a sandbox: the
    /// dispatcher will refuse to invoke it unless an execution backend is present and
    /// the requested guarantees can be established.
    fn tier(&self) -> ExecutionTier {
        ExecutionTier::InProcess
    }

    /// Runs the capability.
    ///
    /// Receives the capability-facing projection, which does **not** carry the actor:
    /// an adapter that learns its caller becomes a confused deputy (ADR-0027, S8).
    ///
    /// May panic. The dispatcher catches it (see `dispatch`), because "a faulty
    /// integration must not take down the daemon" is a hard requirement (ADR-0009),
    /// not an aspiration.
    ///
    /// # Errors
    ///
    /// Any failure the adapter reports.
    fn invoke(
        &self,
        view: &orxnud_domain::invocation::DispatchView<'_>,
        credential: Option<&crate::credential::CredentialHandle>,
    ) -> Result<ExecutionOutcome, String>;
}

/// What a Tier-1 capability needs from its sandbox.
///
/// Deliberately expressed in *capability* terms, not OS terms: a filesystem grant, a
/// network grant, a deadline. Nothing here names bubblewrap, a namespace, a cgroup, or
/// a Job Object — those are the backend's business, and leaking them into a portable
/// crate is what gate G3 exists to prevent (ADR-0035).
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionContract {
    /// The capability being run.
    pub capability: CapabilityId,
    /// The program to execute. Absolute; never a shell string.
    pub program: String,
    /// Arguments, passed as a vector.
    pub args: Vec<String>,
    /// Environment variables the child may see. **Empty means none.**
    ///
    /// A credential is never placed here. Credentials travel through the
    /// [`crate::credential::CredentialHandle`] parameter instead, so a leaked
    /// environment cannot leak one — see V-50's credential section.
    pub env: BTreeMap<String, String>,
    /// Working directory inside the sandbox.
    pub working_dir: String,
    /// Read-write paths.
    pub grant_rw: Vec<String>,
    /// Read-only paths.
    pub grant_ro: Vec<String>,
    /// Whether the child may use the network at all.
    pub network: bool,
    /// Wall-clock deadline.
    pub deadline_ms: u64,
    /// Per-stream output cap.
    pub output_cap_bytes: u64,
    /// Which resource controls must be established, and what this invocation may use.
    pub resources: ResourcePolicy,
}

/// Which resource controls must be established, and what this invocation may use.
///
/// # Requirement is not budget
///
/// The two are related and are deliberately separate fields, because conflating them
/// produces both a security hole and a usability bug:
///
/// ```text
/// requirement = "this capability must have memory isolation, or it does not run"
/// budget      = "this invocation may use 64 MiB"
/// ```
///
/// A requirement is a **precondition**: if the host cannot establish it the dispatch is
/// **refused** and nothing runs. A budget is a **ceiling for one invocation**: when the
/// host cannot enforce it the budget is still recorded, the shortfall reported, and the
/// invocation proceeds.
///
/// The rule is deterministic and lives here, in the contract, rather than being inferred
/// by the dispatcher from what happens to be available:
///
/// ```text
/// capability requires control X  +  X cannot be established  ->  REFUSE
/// capability requires nothing    +  budget X unenforceable   ->  PROCEED, record gap
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResourcePolicy {
    /// Controls that must be established, or the dispatch is refused.
    ///
    /// Per capability and explicit. A blanket "everything is required" would refuse
    /// every Tier-1 capability on a host without delegated cgroups -- fail-closed in
    /// form, a sandbox that never runs in practice, and steady pressure to weaken the
    /// default later.
    pub required: Vec<ResourceRequirement>,
    /// Soft ceilings for this invocation.
    pub budget: ResourceBudget,
}

/// One control a capability needs established before it may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceRequirement {
    /// `memory.max`.
    Memory,
    /// `pids.max`.
    Processes,
    /// `cpu.max`.
    Cpu,
}

impl ResourceRequirement {
    /// A stable label, for refusals and audit records.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Processes => "processes",
            Self::Cpu => "cpu",
        }
    }
}

/// Soft ceilings for one invocation.
///
/// Recorded and, where the host can, enforced. A shortfall is reported rather than
/// silently dropped, so an audit record distinguishes "ran within its budget" from
/// "ran, and the budget was not enforced".
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ResourceBudget {
    /// Memory this invocation expects to use, in bytes.
    pub memory_bytes: Option<u64>,
    /// Processes this invocation expects to create.
    pub processes: Option<u64>,
    /// CPU this invocation expects, in fractional cores.
    pub cpu_cores: Option<f64>,
}

/// The result a backend returns for a Tier-1 execution.
///
/// `sandboxed` is not a field: a result that exists at all came from a sandbox, because
/// [`Self::execute`] returning `Err` is how a refusal is expressed. A boolean would
/// allow `Ok` with `sandboxed: false`, which is precisely the unsandboxed fallback this
/// phase forbids.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    /// Exit code, when the process ran and exited.
    pub exit_code: Option<i32>,
    /// Captured stdout.
    pub stdout: String,
    /// Captured stderr.
    pub stderr: String,
    /// How it ended, in backend terms.
    pub status: ExecutionOutcomeKind,
}

/// How a sandboxed execution ended, before verification interprets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcomeKind {
    /// Exited on its own with this code.
    Exited(i32),
    /// Stopped at the deadline.
    TimedOut,
    /// Stopped because cancellation was requested.
    Cancelled,
    /// Stopped because an output cap was reached.
    OutputCapped,
    /// The process died from a signal.
    Killed,
}

/// Runs a Tier-1 capability inside a sandbox.
///
/// # The invariant this trait exists to enforce
///
/// A Tier-1 capability cannot execute outside a sandbox, and there is exactly one way
/// to run one: through this trait. `Dispatcher::dispatch` refuses a Tier-1 adapter
/// when no executor is configured, so the absence of a sandbox produces a refusal
/// rather than an in-process call or an unsandboxed subprocess.
///
/// Implementations must **fail closed**: if the requested guarantees cannot be
/// established, return `Err`. A backend that cannot provide isolation must not
/// approximate it.
pub trait ExecutionBackend: Send + Sync {
    /// Runs `contract` inside a sandbox.
    ///
    /// # Errors
    ///
    /// A refusal. Nothing was executed, and the caller must not retry the capability
    /// as though it had.
    fn execute(&self, contract: &ExecutionContract) -> Result<ExecutionReport, SandboxRefusal>;

    /// Whether this backend can establish the guarantees the contract needs.
    ///
    /// Consulted *before* execution so the dispatcher can refuse early, but the
    /// backend remains the authority: a `true` here does not permit a later `Err`.
    fn can_fulfil(&self, contract: &ExecutionContract) -> bool;
}

/// Maps a backend report onto the existing execution outcome model.
///
/// The mapping is the security-relevant part: a sandbox that *refused* never reaches
/// here, so anything arriving is something that actually ran. A `TimedOut` or
/// `OutputCapped` maps to `Unknown` rather than `Failed`, because "the process did not
/// report" and "the process reported failure" are different (TP-12), and only the
/// second one means nothing happened.
fn outcome_from_report(report: ExecutionReport) -> ExecutionOutcome {
    match report.status {
        ExecutionOutcomeKind::Exited(0) => ExecutionOutcome::Succeeded {
            output: Some(report.stdout),
        },
        ExecutionOutcomeKind::Exited(code) => ExecutionOutcome::Failed {
            detail: format!("exit {code}: {}", redact(&report.stderr)),
        },
        ExecutionOutcomeKind::TimedOut => ExecutionOutcome::Unknown {
            detail: "the sandbox stopped the capability at its deadline".to_owned(),
        },
        ExecutionOutcomeKind::Cancelled => ExecutionOutcome::Unknown {
            detail: "the capability was cancelled".to_owned(),
        },
        ExecutionOutcomeKind::OutputCapped => ExecutionOutcome::Unknown {
            detail: "the capability exceeded its output cap, so its report is incomplete"
                .to_owned(),
        },
        ExecutionOutcomeKind::Killed => ExecutionOutcome::Unknown {
            detail: "the capability was killed by a signal".to_owned(),
        },
    }
}

/// Trims and bounds a child's stderr before it reaches an audit record.
///
/// A hostile helper controls this text, so it must not be able to flood the audit
/// journal or smuggle a newline that breaks a record's framing.
fn redact(s: &str) -> String {
    const MAX: usize = 512;
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.len() <= MAX {
        cleaned
    } else {
        format!("{}…[{} bytes total]", &cleaned[..MAX], cleaned.len())
    }
}

#[cfg(test)]
mod resource_rule_tests {
    use super::{ResourceBudget, ResourcePolicy, ResourceRequirement};

    #[test]
    fn a_requirement_is_not_a_budget() {
        // The distinction the contract encodes. Conflating them produces either a
        // security hole (a budget treated as a gate) or a permanent refusal (a
        // requirement satisfied only by observation).
        let requiring = ResourcePolicy {
            required: vec![ResourceRequirement::Memory],
            budget: ResourceBudget {
                memory_bytes: Some(64 * 1024 * 1024),
                ..ResourceBudget::default()
            },
        };
        assert_eq!(
            requiring.required.len(),
            1,
            "a requirement is a precondition"
        );
        assert_eq!(
            requiring.budget.memory_bytes,
            Some(64 * 1024 * 1024),
            "a budget is a per-invocation ceiling and is independent of it"
        );

        let budgeting_only = ResourcePolicy {
            required: vec![],
            budget: requiring.budget,
        };
        assert!(budgeting_only.required.is_empty());
        assert_ne!(
            budgeting_only.required, requiring.required,
            "the same budget with and without a requirement must differ in gating"
        );
    }

    #[test]
    fn requirements_are_named_for_refusals() {
        for r in [
            ResourceRequirement::Memory,
            ResourceRequirement::Processes,
            ResourceRequirement::Cpu,
        ] {
            assert!(!r.label().is_empty(), "a refusal must name the control");
        }
    }
}

/// Which isolation tier an implementation requires.
///
/// Two values, and no third. A tier that meant "best effort" would be a bypass with a
/// name, so the only way to be less isolated than Tier 1 is to declare Tier 0 — which
/// means in-process, where the sandbox does not apply because there is no process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionTier {
    /// Tier 0: in-process. A Rust trait call; a panic is caught by the dispatcher.
    InProcess,
    /// Tier 1: a sandboxed subprocess. **Cannot be invoked without a sandbox.**
    Subprocess,
}

/// A refusal to invoke a Tier-1 capability because no sandbox could be established.
///
/// Its own type rather than a `DispatchError` variant so it cannot be confused with a
/// *capability* failing. A sandbox refusal means nothing ran; an adapter error means
/// something ran and failed. Collapsing them would let a caller retry a refusal as
/// though retrying could help.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxRefusal {
    /// Which capability was refused.
    pub capability: CapabilityId,
    /// Why, in the backend's words.
    pub reason: String,
    /// Guarantees that were not established.
    pub missing: Vec<&'static str>,
}

/// What a Tier-1 adapter wants from its sandbox, in portable terms.
///
/// Separate from [`CapabilityAdapter`] because only Tier-1 adapters have one, and
/// requiring every Tier-0 adapter to answer "which program do you run?" would be a
/// lie for an in-process implementation.
#[derive(Debug, Clone, PartialEq)]
pub struct SandboxPlan {
    /// Absolute path to the executable.
    pub program: String,
    /// Arguments.
    pub args: Vec<String>,
    /// Environment the child may see. Empty means none.
    pub env: BTreeMap<String, String>,
    /// Working directory.
    pub working_dir: String,
    /// Read-write grants.
    pub grant_rw: Vec<String>,
    /// Read-only grants.
    pub grant_ro: Vec<String>,
    /// Whether the network is granted.
    pub network: bool,
    /// Deadline in milliseconds.
    pub deadline_ms: u64,
    /// Per-stream output cap.
    pub output_cap_bytes: u64,
    /// Which controls must be established, and what this invocation may use.
    pub resources: ResourcePolicy,
}

/// Verification strategy, looked up alongside the adapter.
pub trait AdapterBundle {
    /// The adapter.
    fn adapter(&self) -> &dyn CapabilityAdapter;

    /// The sandbox plan, for a Tier-1 adapter.
    ///
    /// `None` for Tier 0, and for a Tier-1 adapter it is a configuration error the
    /// dispatcher refuses rather than guessing.
    fn sandbox_plan(&self) -> Option<SandboxPlan> {
        None
    }

    /// How to verify its effects.
    fn verifier(&self) -> &dyn Verifier;
}

/// Why a dispatch was refused, in one enum so callers match once.
#[derive(Debug)]
pub enum Refusal {
    /// The governed stages refused.
    Policy(PolicyError),
    /// No implementation.
    NoImplementation(CapabilityId),
    /// Switched off.
    Disabled(CapabilityId),
    /// Data class too high for the implementation.
    ClassEscalation {
        /// Which capability.
        id: CapabilityId,
        /// What it implements.
        declared: orxnud_domain::enums::DataClass,
        /// What was asked.
        actual: orxnud_domain::enums::DataClass,
    },
    /// Credential problem. Never contains a secret value.
    Credential(CredentialError),
    /// An adapter re-entered the dispatcher.
    Reentrant(CapabilityId),
    /// A Tier-1 capability had no usable sandbox.
    Sandbox(SandboxRefusal),
}

impl Refusal {
    /// The stable identifier for logs and tests.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Policy(_) => "policy_refused",
            Self::NoImplementation(_) => "no_implementation",
            Self::Disabled(_) => "capability_disabled",
            Self::ClassEscalation { .. } => "class_escalation",
            Self::Credential(_) => "credential_unavailable",
            Self::Reentrant(_) => "reentrant_dispatch",
            Self::Sandbox(_) => "sandbox_refused",
        }
    }
}

/// Guards against an adapter re-entering the dispatcher.
///
/// ADR-0009: "No capability may invoke another capability." The type-level route is
/// that an adapter receives a `DispatchView`, which cannot dispatch. The runtime
/// route is this flag, for the case where an adapter holds a dispatcher reference
/// from elsewhere -- which is exactly what a future MCP adapter might do by
/// accident.
///
/// Reentrancy is refused rather than permitted-with-a-depth-limit, because a nested
/// dispatch would mean the audit chain records an action whose authority was
/// established inside another action's execution, and reconstructing that later is
/// hard. Refusing is boring and obvious.
#[derive(Debug, Default)]
struct ReentrancyGuard {
    /// `true` while a dispatch is in flight.
    inside: Mutex<bool>,
    /// Which capability is executing, for the refusal message.
    current: Mutex<Option<CapabilityId>>,
}

impl ReentrancyGuard {
    fn enter(&self, id: &CapabilityId) -> Result<(), DispatchError> {
        let mut inside = self.inside.lock().map_err(|_| {
            DispatchError::Reentrant("dispatcher state poisoned by a panic".to_owned())
        })?;
        if *inside {
            let who = self
                .current
                .lock()
                .ok()
                .and_then(|c| c.clone())
                .map_or_else(|| "another capability".to_owned(), |c| c.to_string());
            return Err(DispatchError::Reentrant(format!(
                "{id} called back in from {who}"
            )));
        }
        *inside = true;
        if let Ok(mut c) = self.current.lock() {
            *c = Some(id.clone());
        }
        Ok(())
    }

    fn leave(&self) {
        if let Ok(mut inside) = self.inside.lock() {
            *inside = false;
        }
        if let Ok(mut c) = self.current.lock() {
            *c = None;
        }
    }
}

/// The deterministic dispatcher.
///
/// Holds the adapters. Borrows policy and the secret store, because ADR-0006
/// documents exactly one writer of each and two owners would mean two opinions about
/// the same state.
pub struct Dispatcher<'p, S: SecretsContract> {
    policy: &'p mut PolicyEngine,
    secrets: &'p S,
    bundles: BTreeMap<CapabilityId, Arc<dyn AdapterBundle>>,
    reentrancy: ReentrancyGuard,
    /// The only route to a Tier-1 process.
    ///
    /// `None` means no sandbox is configured, and a Tier-1 capability is then
    /// **refused**. That is the fail-closed default: a missing sandbox must not become
    /// an in-process call, and must not become an unsandboxed subprocess (V-49, V-50).
    execution: Option<Arc<dyn ExecutionBackend>>,
}

impl<'p, S: SecretsContract> Dispatcher<'p, S> {
    /// Builds a dispatcher over `bundles`.
    #[must_use]
    pub fn new(
        policy: &'p mut PolicyEngine,
        secrets: &'p S,
        bundles: BTreeMap<CapabilityId, Arc<dyn AdapterBundle>>,
    ) -> Self {
        Self {
            policy,
            secrets,
            bundles,
            reentrancy: ReentrancyGuard::default(),
            execution: None,
        }
    }

    /// Installs the execution backend that Tier-1 capabilities will use.
    ///
    /// The only way to make subprocess execution possible. There is deliberately no
    /// setter that takes a program and arguments directly, because that would be the
    /// `dispatcher -> direct subprocess` bypass Phase 4b forbids.
    #[must_use]
    pub fn with_execution(mut self, backend: Arc<dyn ExecutionBackend>) -> Self {
        self.execution = Some(backend);
        self
    }

    /// Whether a sandbox is configured.
    #[must_use]
    pub fn has_execution_backend(&self) -> bool {
        self.execution.is_some()
    }

    /// How many records the audit chain holds.
    ///
    /// Exposed so a caller can assert that a governed execution left a trace, which
    /// is the difference between "it ran" and "it ran and can be reconstructed".
    #[must_use]
    pub fn audit_len(&self) -> usize {
        self.policy.audit().len()
    }

    /// Builds the execution contract for a Tier-1 capability.
    ///
    /// # The credential is deliberately absent
    ///
    /// The contract carries no credential, and no `SecretRef`. A contract is data that
    /// will be logged, audited, and serialised for diagnostics; putting a secret or
    /// even its reference in it would create three new leak paths. The credential
    /// travels as the [`crate::credential::CredentialHandle`] passed to the backend's
    /// own channel, which is why `ExecutionBackend::execute` takes only a contract and
    /// the handle is threaded separately in the sandbox backend.
    ///
    /// # Errors
    ///
    /// [`DispatchError::InvalidInput`] when the adapter declared no program, which a
    /// Tier-1 adapter without a program is a configuration error rather than a
    /// runtime failure.
    fn contract_for(
        &self,
        _invocation: &CapabilityInvocation,
        capability: &CapabilityId,
    ) -> Result<ExecutionContract, DispatchError> {
        let bundle = self
            .bundles
            .get(capability)
            .ok_or_else(|| DispatchError::NoImplementation(capability.clone()))?;
        let sandboxed = bundle.sandbox_plan().ok_or_else(|| {
            DispatchError::SandboxRefused(SandboxRefusal {
                capability: capability.clone(),
                reason: "the adapter is Tier-1 but declares no sandbox plan".to_owned(),
                missing: vec!["a sandbox plan"],
            })
        })?;
        Ok(ExecutionContract {
            capability: capability.clone(),
            program: sandboxed.program,
            args: sandboxed.args,
            env: sandboxed.env,
            working_dir: sandboxed.working_dir,
            grant_rw: sandboxed.grant_rw,
            grant_ro: sandboxed.grant_ro,
            network: sandboxed.network,
            deadline_ms: sandboxed.deadline_ms,
            output_cap_bytes: sandboxed.output_cap_bytes,
            resources: sandboxed.resources.clone(),
        })
    }

    /// Registers an implementation. Duplicate ids are refused, because two
    /// implementations of one capability is a version-conflict bug that would
    /// otherwise be resolved by iteration order.
    ///
    /// # Errors
    ///
    /// [`DispatchError::NoImplementation`] is not the right error here; a duplicate
    /// is reported as [`RegisterError::Duplicate`].
    pub fn register(&mut self, bundle: Arc<dyn AdapterBundle>) -> Result<(), RegisterError> {
        let id = bundle.adapter().capability_id().clone();
        if self.bundles.contains_key(&id) {
            return Err(RegisterError::Duplicate(id));
        }
        self.bundles.insert(id, bundle);
        Ok(())
    }

    /// Whether a dispatch is currently in flight on this thread of control.
    ///
    /// Exposed for tests and for the daemon's health output. A dispatcher that is
    /// permanently `true` means an adapter panicked while the guard was held, which
    /// `dispatch` handles by dropping the guard.
    #[must_use]
    pub fn is_executing(&self) -> bool {
        self.reentrancy.inside.lock().map(|g| *g).unwrap_or(false)
    }

    /// Runs the whole governed path for one invocation.
    ///
    /// # Errors
    ///
    /// [`DispatchError`] naming the stage that refused or failed. Every path is
    /// fail-closed.
    ///
    /// # Panics
    ///
    /// Never, as far as this function is concerned: an adapter panic is caught and
    /// converted to [`DispatchError::Execution`]. An audit failure is fatal *after*
    /// execution as well as before, because an action nobody can account for is worse
    /// than a refused one.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &mut self,
        request: ActionRequest,
        actor: Actor,
        context: InvocationContext,
        target: Option<String>,
        params: NormalizedParams,
        approval: Option<&ApprovalRecord>,
        credential_ref: Option<&SecretRef>,
        now_ms: i64,
    ) -> Result<DispatchOutcome, DispatchError> {
        let capability = request.capability.clone();

        // --- stages 1-4: AUTHORITY, POLICY, APPROVAL, BUDGET ---
        //
        // All four happen inside policy, which is the sole authority for its own
        // decisions. This crate does not reimplement any of them: a dispatcher that
        // evaluated policy would be a second authorization system, and the two would
        // eventually disagree.
        //
        // The ordering guarantee this call buys us: no adapter lookup, no credential
        // access, and no side effect has happened at this point, because none of
        // those exist yet in the code path.
        let authorised = self
            .policy
            .authorise_for_dispatch(request, actor, context, target, params, approval, now_ms)
            .map_err(DispatchError::Policy)?;
        let invocation = authorised.invocation;
        let decision = authorised.decision;

        // --- stage 5: CAPABILITY RESOLUTION ---
        let bundle = self
            .bundles
            .get(&capability)
            .cloned()
            .ok_or_else(|| DispatchError::NoImplementation(capability.clone()))?;
        let adapter = bundle.adapter();
        let declared = adapter.declared_class();
        let actual = invocation.data_class();
        if actual > declared {
            return Err(DispatchError::ClassEscalation {
                id: capability.clone(),
                declared,
                actual,
            });
        }

        // --- stage 6: CREDENTIAL RESOLUTION ---
        //
        // Last check before execution, and only if the invocation needs one. Reached
        // only because stages 1-5 all passed: an invocation that exists is not the
        // reason a credential opens, and the two must not be confused.
        let credential = match credential_ref {
            Some(reference) => Some(
                CredentialBroker::new(self.secrets)
                    .resolve(reference)
                    .map_err(DispatchError::Credential)?,
            ),
            None => None,
        };

        // --- stage 7: EXECUTION ---
        //
        // Two routes, and the tier decides which. Tier 0 is an in-process trait call;
        // Tier 1 goes through the execution backend and can do nothing else. There is
        // no third route, and no fallback from Tier 1 to Tier 0 -- that absence is the
        // invariant (V-50).
        let execution = match adapter.tier() {
            ExecutionTier::Subprocess => {
                // Refused *before* the contract is built, so no process is created and
                // nothing about the capability leaks. Note this happens after stage 6,
                // which is deliberate: credential resolution is cheap and side-effect
                // free, and a refusal here must not be able to read a secret. The
                // contract check below happens before the backend is asked to run.
                let Some(backend) = self.execution.clone() else {
                    return Err(DispatchError::SandboxRefused(SandboxRefusal {
                        capability: capability.clone(),
                        reason: "no execution backend is configured, so a Tier-1 \
                                 capability cannot be sandboxed"
                            .to_owned(),
                        missing: vec!["a sandbox execution backend"],
                    }));
                };
                let contract = self.contract_for(&invocation, &capability)?;
                if !backend.can_fulfil(&contract) {
                    return Err(DispatchError::SandboxRefused(SandboxRefusal {
                        capability: capability.clone(),
                        reason: "the execution backend cannot establish the required \
                                 sandbox guarantees"
                            .to_owned(),
                        missing: vec!["the requested sandbox guarantees"],
                    }));
                }
                self.reentrancy.enter(&capability)?;
                let report = {
                    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        backend.execute(&contract)
                    }));
                    self.reentrancy.leave();
                    match caught {
                        Err(_) => {
                            // A backend that panics must not be treated as success,
                            // and must not be retried as though the capability failed.
                            return Err(DispatchError::SandboxRefused(SandboxRefusal {
                                capability: capability.clone(),
                                reason: "the execution backend panicked".to_owned(),
                                missing: vec!["a functioning execution backend"],
                            }));
                        }
                        Ok(Ok(r)) => r,
                        Ok(Err(refusal)) => {
                            return Err(DispatchError::SandboxRefused(refusal));
                        }
                    }
                };
                outcome_from_report(report)
            }
            ExecutionTier::InProcess => {
                self.reentrancy.enter(&capability)?;
                // The guard is released by `catch_unwind`'s drop path even on a panic,
                // so a faulty adapter cannot wedge the dispatcher for its lifetime.
                let view = invocation.dispatch_view();
                let credential = credential.as_ref();
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    adapter.invoke(&view, credential)
                }));
                self.reentrancy.leave();

                match caught {
                    // A panicking adapter is a bug in the adapter, and ADR-0009
                    // requires that it not take down the host. Reported as an execution
                    // failure, never as a permission failure.
                    Err(_) => ExecutionOutcome::Unknown {
                        detail: format!("{} panicked during execution", capability),
                    },
                    Ok(Err(e)) => ExecutionOutcome::Failed { detail: e },
                    Ok(Ok(outcome)) => outcome,
                }
            }
        };

        // --- stage 8: VERIFICATION ---
        //
        // Distinct from execution, and evaluated even when the adapter reported
        // success. An adapter that returns `Ok` has said "I ran"; it has not said
        // "it worked".
        let verification = match bundle.verifier().verify(&execution, now_ms) {
            Ok(v) => v,
            // A verifier that cannot run produces "undetermined", never "verified"
            // and never "refuted".
            Err(e) => VerificationOutcome::Undetermined {
                reason: e.to_string(),
            },
        };

        // --- stage 9: AUDIT / FINAL STATE ---
        //
        // Stage 9's *authorisation* half is stage 1's `audit_pair`: policy wrote the
        // permit record, and a refusal record with the same correlation key, before
        // this dispatcher saw a `Decision`. What remains is the terminal record, and
        // it is written by the caller that owns the journal once it knows the
        // execution and verification outcomes -- which is deliberately not this
        // function, because only the caller knows whether the *task* may now be
        // marked done. `decision` needs no second record: policy recorded the risk
        // and the approval digest with it.
        let outcome = DispatchOutcome {
            execution,
            verification,
            capability: capability.clone(),
        };
        let _ = decision;

        if outcome.verification.is_refuted() {
            return Err(DispatchError::VerificationRefuted {
                evidence: match &outcome.verification {
                    VerificationOutcome::Refuted { evidence } => evidence.clone(),
                    _ => unreachable!("checked by is_refuted"),
                },
            });
        }

        Ok(outcome)
    }
}

/// Why an implementation could not be registered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// Two implementations claim the same id.
    #[error("{0} already has a registered implementation")]
    Duplicate(CapabilityId),
}

impl From<RegisterError> for DispatchError {
    fn from(e: RegisterError) -> Self {
        match e {
            RegisterError::Duplicate(id) => Self::NoImplementation(id),
        }
    }
}

/// The approval digest an invocation required, if any.
///
/// Exposed so a caller can present the user with *the* digest they must approve,
/// rather than a recomputed one. Recomputation at approval time is how Loopjacking
/// (TH-05) gets in.
#[must_use]
pub fn required_digest(decision: &orxnud_policy::Decision) -> Option<ApprovalDigest> {
    match decision {
        orxnud_policy::Decision::Gate {
            required_digest, ..
        } => Some(*required_digest),
        _ => None,
    }
}

/// Whether an invocation carries the approval digest policy demanded.
#[must_use]
pub fn approval_satisfied(
    decision: &orxnud_policy::Decision,
    approval: Option<&ApprovalRecord>,
) -> bool {
    match required_digest(decision) {
        None => true,
        Some(wanted) => approval.is_some_and(|a| a.digest == wanted),
    }
}

/// Re-exported so a caller building a dispatcher has one import site.
pub use crate::verification::VerificationOutcome as Outcome;
