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
//! An adapter may not call back into the dispatcher. `ReentrancyGuard` says why, and
//! says why the bounded alternative — permitting reentrancy under a depth limit — was
//! not taken. There is no `Dispatcher::enter_guarded` method in this crate.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use orxnud_domain::Actor;
use orxnud_domain::approval::{ApprovalDigest, ApprovalRecord, NormalizedParams};
use orxnud_domain::ids::CapabilityId;
use orxnud_domain::invocation::{ActionRequest, InvocationContext};
use orxnud_domain::platform::{SecretRef, SecretsContract};
use orxnud_policy::authority::CapabilityInvocation;
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
    /// Distinct from [`Self::Execution`] and from a `Failed` on purpose: nothing was
    /// executed, so retrying the *capability* cannot help, and reporting it as an
    /// execution failure would suggest the adapter ran and failed. `DispatchError` has
    /// no `Failed` variant; `Self::Execution` is the one that means the adapter ran and
    /// failed.
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

    /// The capability's own parameters were rejected.
    ///
    /// Distinct from [`Self::SandboxRefused`] because the cause is the request, not
    /// the host: a traversing path and a missing bubblewrap binary both end in "no
    /// plan", and conflating them told operators to go and inspect their kernel
    /// settings for a malformed argument. Also distinct from a capability that
    /// declares no plan at all ([`PlanError::NoPlanDeclared`]), which is a defect in
    /// this build and is reported as [`Self::SandboxRefused`] so it still surfaces as
    /// an environment fault.
    ///
    /// Nothing ran. The caller can fix the request and retry, so the terminal audit
    /// record for this authorisation is a `Denied`, not an `Uncertain`.
    InvalidInput {
        /// Which capability rejected the parameters.
        capability: CapabilityId,
        /// What was wrong, in the capability's words. Never a path outside the
        /// workspace and never parameter content.
        detail: String,
    },

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
            Self::InvalidInput { capability, detail } => {
                write!(f, "{capability} rejected the request: {detail}")
            }
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
    /// Whether `execution`'s output is ephemeral and must not be persisted.
    ///
    /// Taken from the bundle's declaration rather than recomputed here, so the answer is
    /// the same one the adapter was built from.
    pub output_is_ephemeral: bool,
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
///
/// # Why this trait is `pub(crate)`
///
/// Because a trait object of it is a capability execution primitive. Anyone who can
/// name this trait can do two things they must not be able to do: call `invoke`, and
/// implement the trait to supply their own adapter to a `Dispatcher`. Both are the
/// execution boundary, and both are now decided by `rustc` rather than by a reviewer
/// reading source.
///
/// A `pub trait` with a `pub(crate)` method would *also* have worked — an
/// unimplementable method makes the trait unimplementable — but a private method
/// inside a public trait reads as an oversight, and the whole trait being
/// unreachable is the statement that is actually true.
pub(crate) trait CapabilityAdapter: Send + Sync {
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
        view: &orxnud_policy::authority::DispatchView<'_>,
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

impl ResourcePolicy {
    /// Checks that every *required* control has a concrete ceiling.
    ///
    /// # Why this is validation and not a default
    ///
    /// V-56 separates a **requirement** (a prerequisite for safe execution) from a
    /// **budget** (a concrete per-invocation ceiling). Collapsing them is tempting and
    /// wrong: a requirement with no budget has nothing to enforce, so honouring it means
    /// inventing a number.
    ///
    /// The backend must enforce policy, not create it. An earlier version of this
    /// integration filled the gap with a `DEFAULT_*` in `subprocess.rs` -- 512 MiB, 64
    /// processes, 1 core -- which quietly moved a resource decision out of the capability
    /// and the policy engine and into the execution layer, with nothing recording that a
    /// default had been applied. A default resource *profile* may be a legitimate future
    /// decision, but it belongs in policy and configuration where it is visible, not
    /// hidden in a backend.
    ///
    /// So an incomplete policy is refused here, before a process exists. A budget for a
    /// control that is merely `budget` (not required) is unaffected: an unenforceable
    /// non-required budget still proceeds and records its gap (V-56).
    ///
    /// # Errors
    ///
    /// [`PolicyIncomplete`] naming every required control that has no budget.
    pub fn validate(&self) -> Result<(), PolicyIncomplete> {
        let b = self.budget;
        let mut missing = Vec::new();
        for r in &self.required {
            let absent = match r {
                ResourceRequirement::Memory => b.memory_bytes.is_none(),
                ResourceRequirement::Processes => b.processes.is_none(),
                ResourceRequirement::Cpu => b.cpu_cores.is_none(),
            };
            if absent {
                missing.push(r.label());
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(PolicyIncomplete { missing })
        }
    }
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

/// Why a [`ResourcePolicy`] cannot be executed as written.
///
/// Returned by [`ResourcePolicy::validate`] before anything is spawned, so an incomplete
/// policy is a refusal rather than a surprise at the platform layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIncomplete {
    /// Controls that were declared required but given no concrete ceiling.
    pub missing: Vec<&'static str>,
}

impl std::fmt::Display for PolicyIncomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "required control(s) {:?} declared with no budget, so there is no ceiling to \
             enforce",
            self.missing
        )
    }
}

impl std::error::Error for PolicyIncomplete {}

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
/// [`ExecutionBackend::execute`] returning `Err` is how a refusal is expressed. A
/// boolean would allow `Ok` with `sandboxed: false`, which is precisely the unsandboxed
/// fallback this phase forbids.
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
///
/// # The budget is bytes, not characters
///
/// [`MAX`] is a byte budget, deliberately: the audit record is bytes, and a budget
/// counted in characters would let a record grow by a factor of four if the child
/// emitted multi-byte text. The total reported in the suffix is therefore
/// `str::len()`, which is bytes, and must stay that way.
///
/// # Why the truncation walks backwards
///
/// Slicing at a fixed byte offset is only correct when that offset happens to fall
/// on a code-point boundary, and a hostile helper chooses its own output. A child
/// that emitted a multi-byte character straddling the boundary made this panic:
///
/// ```text
/// end byte index 512 is not a char boundary; it is inside '€' (bytes 511..514)
/// ```
///
/// It is reached from `outcome_from_report`, **outside** the `catch_unwind` that
/// wraps the backend, so it took the dispatcher down — which is exactly what
/// `CapabilityAdapter::invoke`'s contract says must not happen ("a faulty
/// integration must not take down the daemon"). The fix moves the cut back to the
/// nearest boundary rather than widening the budget or dropping the offending
/// bytes: at most three steps, because a code point is at most four bytes.
fn redact(s: &str) -> String {
    const MAX: usize = 512;
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if cleaned.len() <= MAX {
        return cleaned;
    }
    let mut end = MAX;
    while !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[{} bytes total]", &cleaned[..end], cleaned.len())
}

#[cfg(test)]
mod redact_tests {
    use super::redact;

    /// The byte budget `redact` enforces, restated so a test cannot quietly pass by
    /// agreeing with a changed constant.
    const MAX: usize = 512;

    /// Builds a string of `ascii` ASCII bytes followed by `tail`.
    fn ascii_then(ascii: usize, tail: &str) -> String {
        let mut s = "a".repeat(ascii);
        s.push_str(tail);
        s
    }

    /// The reported total, parsed out of the `…[N bytes total]` suffix.
    fn reported_total(out: &str) -> usize {
        let start = out.rfind('[').expect("suffix present") + 1;
        let end = out.rfind(" bytes total]").expect("suffix present");
        out[start..end].parse().expect("a number")
    }

    #[test]
    fn a_short_string_is_returned_exactly() {
        // "Exactly" means: unchanged by the *truncation*, which is a no-op below the
        // budget. The control-character scrub applies at every length, so it is
        // asserted separately below.
        for s in ["", "ok", "a clean line with no control characters"] {
            let out = redact(s);
            assert_eq!(out, s, "short clean input must be untouched");
            assert!(!out.contains('…'), "no truncation marker: {out}");
        }
    }

    #[test]
    fn control_characters_are_scrubbed_at_every_length() {
        // The scrubbing half of the contract, independent of the budget. A newline
        // or a tab is a framing character an audit record must not carry.
        for s in ["a\nb", "a\tb", "a\rb", "a\u{0}b"] {
            let out = redact(s);
            assert_eq!(out, "a b", "control characters become spaces: {out:?}");
            assert!(!out.contains('…'), "still short, still untruncated");
        }
    }

    #[test]
    fn ascii_behaviour_is_exact() {
        // ASCII is one byte per character, so the cut lands on a boundary and
        // nothing about the original path changes.
        let s = "b".repeat(MAX);
        assert_eq!(redact(&s), s, "exactly at the budget: untouched");

        let over = "b".repeat(MAX + 100);
        let out = redact(&over);
        assert_eq!(
            out,
            format!("{}…[{} bytes total]", "b".repeat(MAX), MAX + 100)
        );
        assert!(out.starts_with(&"b".repeat(MAX)), "the full budget is kept");
    }

    #[test]
    fn a_two_byte_character_straddling_the_boundary_does_not_panic() {
        // 511 ASCII bytes, then a 2-byte char: byte 512 lands inside it.
        let s = ascii_then(MAX - 1, "é");
        assert_eq!(s.len(), 513, "the input must straddle the boundary");
        let out = redact(&s);
        assert!(out.starts_with(&"a".repeat(MAX - 1)));
        assert!(out.ends_with(&format!("…[{} bytes total]", 513)));
    }

    #[test]
    fn a_three_byte_character_straddling_the_boundary_does_not_panic() {
        // The exact reproducer of the original panic: byte 512 inside '€'.
        let s = ascii_then(MAX - 1, "€");
        assert_eq!(s.len(), 514);
        let out = redact(&s);
        assert!(
            out.starts_with(&"a".repeat(MAX - 1)),
            "the cut moves back to the last boundary: {out}"
        );
        assert!(out.ends_with(&format!("…[{} bytes total]", 514)));
    }

    #[test]
    fn a_four_byte_character_straddling_the_boundary_does_not_panic() {
        // 509 ASCII bytes, then a 4-byte char starting at 509: every offset from
        // 510 to 512 is inside it, so the cut must walk back three times.
        let s = ascii_then(MAX - 3, "😀");
        assert_eq!(s.len(), 513);
        let out = redact(&s);
        assert!(
            out.starts_with(&"a".repeat(MAX - 3)),
            "a four-byte code point needs three steps back: {out}"
        );
        assert!(out.ends_with(&format!("…[{} bytes total]", 513)));
    }

    #[test]
    fn every_offset_inside_a_code_point_is_safe() {
        // Not a sample: for each leading width, place a code point so that the
        // 512th byte is *every* position inside it.
        for width in 2..=4usize {
            let cp = match width {
                2 => "é",
                3 => "€",
                _ => "😀",
            };
            for inside in 1..width {
                let lead = MAX - inside;
                let s = ascii_then(lead, cp);
                assert!(
                    s.len() > MAX,
                    "case must actually straddle: lead={lead} width={width}"
                );
                let out = redact(&s);
                // No panic, valid UTF-8, and the byte budget is respected.
                assert!(
                    out.len() < s.len() + "…[514 bytes total]".len(),
                    "output must be bounded"
                );
                assert_eq!(
                    reported_total(&out),
                    s.len(),
                    "the reported total is the true byte length, not the cut"
                );
                // Whatever we kept must end on a boundary, i.e. be a valid prefix.
                let kept = out.split('…').next().expect("a prefix");
                assert!(
                    s.starts_with(kept),
                    "kept text must be a true prefix of the input"
                );
            }
        }
    }

    #[test]
    fn the_truncated_prefix_is_never_a_partial_code_point() {
        // The property that matters for a downstream reader: what we emit is
        // decodable, so an audit record can never be written with a split rune.
        for cp in ["é", "€", "😀", "𝄞"] {
            for lead in MAX - 4..=MAX {
                let s = ascii_then(lead, cp);
                let out = redact(&s);
                let kept = out.split('…').next().expect("a prefix");
                assert!(
                    kept.is_char_boundary(kept.len()),
                    "{cp:?} at {lead} produced a split code point"
                );
                // Round-tripping through bytes is the real proof it is intact.
                assert_eq!(
                    kept,
                    String::from_utf8(kept.as_bytes().to_vec()).expect("valid UTF-8")
                );
            }
        }
    }

    #[test]
    fn mixed_ascii_and_multibyte_content_survives_the_cut() {
        let mut s = String::new();
        while s.len() < MAX {
            s.push_str("héllo wörld ✓ ");
        }
        let out = redact(&s);
        let kept = out.split('…').next().expect("a prefix");
        assert!(s.starts_with(kept));
        assert!(
            kept.len() <= MAX,
            "the kept prefix respects the byte budget"
        );
        assert_eq!(reported_total(&out), s.len());
    }

    #[test]
    fn control_characters_are_still_replaced_and_the_budget_still_applies() {
        // The original two responsibilities, unchanged: scrub framing characters,
        let mut s = "x".repeat(MAX - 4);
        // U+2028 is a 3-byte line separator and is **not** a control character, so
        // `is_control()` leaves it alone. That is the point: this input is 514 bytes,
        // truncation cuts at 512, and 512 falls *inside* that last character, so the
        // backwards boundary walk in `redact` is what keeps it from slicing a code
        // point in half. A plain space here would make the input exactly 512 bytes,
        // which returns early, never truncates, and leaves `reported_total` with no
        // suffix to parse.
        s.push_str("\n\r\u{0}\u{2028}");
        let out = redact(&s);
        assert!(
            !out.contains('\n') && !out.contains('\r') && !out.contains('\u{0}'),
            "control characters must be scrubbed: {out:?}"
        );
        assert!(out.contains(' '), "scrubbed positions become spaces");
        assert_eq!(reported_total(&out), s.len());
    }

    #[test]
    fn redaction_is_deterministic() {
        let s = ascii_then(MAX - 1, "€");
        let first = redact(&s);
        for _ in 0..8 {
            assert_eq!(redact(&s), first, "same input, same output");
        }
    }

    #[test]
    fn a_pathological_input_of_only_multibyte_characters_is_bounded() {
        // Every character is 3 bytes, so no boundary is ever hit at a round number.
        let s = "€".repeat(4_000);
        let out = redact(&s);
        assert_eq!(reported_total(&out), 12_000);
        let kept = out.split('…').next().expect("a prefix");
        assert!(kept.len() <= MAX);
        assert!(s.starts_with(kept));
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
/// *capability* failing. An adapter error means something ran and failed; a refusal that
/// carries [`ExecutionCertainty::NothingAttempted`] means nothing ran. Collapsing them
/// would let a caller retry a refusal as though retrying could help.
///
/// **A refusal is not automatically a disproof.** This type exists partly to say "nothing
/// ran", but a failure the backend cannot place in time reaches the same error type with no
/// such claim — `execute` is called inside a `catch_unwind`, so a backend that panicked may
/// have spawned its child before unwinding, and a backend that gives up on a containment
/// guarantee may have already run the payload before it noticed — so [`Self::certainty`] is
/// the field a consumer must read. Treating every `SandboxRefusal` as proof that nothing ran
/// is what previously let a non-idempotent side effect be re-dispatched after a backend
/// failure nobody could characterise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxRefusal {
    /// Which capability was refused.
    pub capability: CapabilityId,
    /// Why, in the backend's words.
    pub reason: String,
    /// Guarantees that were not established.
    pub missing: Vec<&'static str>,
    /// Whether this refusal establishes that nothing ran.
    ///
    /// A field rather than an assumption, because the two are not the same and the
    /// difference decides whether a retry is safe. `NothingAttempted` is set only where the
    /// refusal is decided before a process exists -- no backend configured, no plan,
    /// incomplete resource policy, guarantees the host cannot establish, or the backend
    /// declining to build a spec -- and the *status* the backend reports for a give-up
    /// carries the phase as well, so a refusal cannot be built for a phase that has passed.
    ///
    /// Two situations are `Unknown` and they are different in cause and identical in
    /// consequence. A backend that **panicked** may have spawned its child before
    /// unwinding, and a backend that **gave up** on a guarantee it had promised may have
    /// already run the payload. From the journal alone, "nothing ran" and "something ran"
    /// are indistinguishable in both.
    ///
    /// The journal records that difference rather than flattening both to "refused",
    /// because `OutcomeKind::Denied` asserts the capability did not execute and
    /// `OutcomeKind::Uncertain` declines to. Getting this wrong in the optimistic
    /// direction is what makes a task engine retry an effect that already happened.
    pub certainty: ExecutionCertainty,
}

/// What a refusal establishes about execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionCertainty {
    /// The refusal was decided before anything was spawned, so nothing ran.
    NothingAttempted,
    /// A process may have been started. The outcome is not established either way.
    Unknown,
}

impl SandboxRefusal {
    /// A refusal decided before anything was spawned.
    ///
    /// The constructor exists so that `NothingAttempted` is the *default* spelling at
    /// every pre-execution site. A site that genuinely ran has to say so out loud by
    /// passing [`ExecutionCertainty::Unknown`], which is the direction this wants to
    /// be wrong in: an extra `Unknown` costs a retry, a missing one costs correctness.
    #[must_use]
    pub fn nothing_attempted(
        capability: CapabilityId,
        reason: impl Into<String>,
        missing: Vec<&'static str>,
    ) -> Self {
        Self {
            capability,
            reason: reason.into(),
            missing,
            certainty: ExecutionCertainty::NothingAttempted,
        }
    }
}

/// Why a Tier-1 adapter could not produce a sandbox plan.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// The invocation's parameters are not acceptable to this capability.
    ///
    /// Caller's error, and the adapter's own words about why. Reported as invalid
    /// input, never as a missing sandbox.
    #[error("{0}")]
    InvalidParams(String),

    /// A Tier-1 adapter that declares no plan at all.
    ///
    /// A defect in the build rather than in the request. Nothing about the invocation
    /// was examined, so no caller edit can change the answer.
    #[error("the adapter is Tier-1 but declares no sandbox plan")]
    NoPlanDeclared,
}

/// What a Tier-1 adapter wants from its sandbox, in portable terms.
///
/// Separate from `CapabilityAdapter` because only Tier-1 adapters have one, and
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

/// The adapter implementations a [`Dispatcher`] can resolve against.
///
/// # Why this type exists
///
/// It exists so that `Dispatcher::new` can stay `pub` while the things it stores are
/// not. `AdapterBundle` is `pub(crate)` — the boundary that makes an adapter
/// uncallable and unimplementable from another crate — so a `pub fn new(…,
/// BTreeMap<CapabilityId, Arc<dyn AdapterBundle>>)` would leak a crate-private type
/// into a public signature. This is a `pub` wrapper with a private field and
/// crate-private construction, which gives the same reachability with none of the
/// leak.
///
/// It is deliberately *not* a general registration API: `insert` is `pub(crate)`, so
/// the only bundles a caller can ever obtain are the ones this crate builds. A public
/// `register` would be a way to add execution machinery from outside, which is exactly
/// what the sealed trait prevents.
///
/// Not to be confused with [`crate::CapabilityRegistry`], which holds capability
/// *declarations* (risk, class, enabled) rather than implementations. Both are real;
/// this one holds the code.
#[derive(Clone, Default)]
pub struct AdapterRegistry {
    bundles: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>>,
}

impl std::fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Counted rather than listed: an `Arc<dyn AdapterBundle>` cannot be
        // formatted, and the ids alone would be an inventory of what this
        // installation can execute.
        f.debug_struct("AdapterRegistry")
            .field("adapters", &self.bundles.len())
            .finish()
    }
}

impl AdapterRegistry {
    /// A registry with no adapters in it.
    ///
    /// Every dispatch against this is refused with [`DispatchError::NoImplementation`],
    /// which is the fail-closed result and not a gap.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// How many adapters are registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    /// Whether no adapter is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Whether `id` has an implementation here.
    #[must_use]
    pub fn contains(&self, id: &CapabilityId) -> bool {
        self.bundles.contains_key(id)
    }

    /// Registers an adapter under the id **the adapter itself reports**.
    ///
    /// Crate-private because that is the whole boundary: the only way an adapter
    /// enters the world is code in this crate.
    ///
    /// The id is read from the adapter rather than passed in. That makes it
    /// impossible to file a bundle under a different id than the one it answers to,
    /// which was a latent composition bug when the caller supplied both and the
    /// dispatcher later compared them.
    pub(crate) fn insert(
        &mut self,
        bundle: Arc<dyn AdapterBundle + Send + Sync>,
    ) -> Option<Arc<dyn AdapterBundle + Send + Sync>> {
        let id = bundle.adapter().capability_id().clone();
        self.bundles.insert(id, bundle)
    }

    /// The map the dispatcher holds.
    pub(crate) fn into_bundles(
        self,
    ) -> BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> {
        self.bundles
    }

    /// Adopts an already-built bundle map.
    ///
    /// Crate-private for the same reason `insert` is: it is a construction path, and
    /// every construction path for a registry is inside this crate.
    #[cfg(test)]
    pub(crate) fn from_bundles(
        bundles: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>>,
    ) -> Self {
        Self { bundles }
    }

    /// The adapters this crate ships.
    ///
    /// The single supported way for a caller to obtain a non-empty registry, and the
    /// reason composition of adapter code lives here rather than in the daemon: an
    /// adapter is capability code, so the set of them is the crate's business.
    ///
    /// `write-text` and `read-text` are included only when their helper binary can be
    /// located, which keeps the Tier-1 refusal (`NoImplementation`) at composition
    /// rather than turning it into a runtime failure further from the cause.
    #[must_use]
    pub fn shipped(workspace: &std::path::Path) -> Self {
        let mut registry = Self::empty();
        registry.insert(Arc::new(crate::text::WordCountBundle::default()));
        if let Some(helper) = crate::write_text::resolve_helper() {
            registry.insert(Arc::new(crate::write_text::WriteTextBundle::new(
                workspace, helper,
            )));
        }
        if let Some(helper) = crate::read_text::resolve_helper() {
            registry.insert(Arc::new(crate::read_text::ReadTextBundle::new(
                workspace, helper,
            )));
        }
        registry
    }
}

/// Verification strategy, looked up alongside the adapter.
///
/// Crate-private for the same reason as `CapabilityAdapter`: implementing it is
/// supplying an adapter, and `sandbox_plan` is how a Tier-1 capability's parameters
/// reach its child, so it is part of the execution surface rather than a description
/// of one.
pub(crate) trait AdapterBundle {
    /// The adapter.
    fn adapter(&self) -> &dyn CapabilityAdapter;

    /// The sandbox plan for this invocation, for a Tier-1 adapter.
    ///
    /// `Ok(None)` for Tier 0, and for a Tier-1 adapter it is a configuration error the
    /// dispatcher refuses rather than guessing.
    ///
    /// # Why this returns a `Result` and not an `Option`
    ///
    /// `Option<SandboxPlan>` cannot say *why* there is no plan, and the two reasons are
    /// not the same event:
    ///
    /// * `Err(PlanError::InvalidParams(..))` -- the caller supplied parameters this
    ///   capability will not accept (a traversing path, an absolute path, a missing
    ///   field). Nothing ran, the caller can fix the request, and the answer belongs
    ///   with invalid input.
    /// * `Err(PlanError::NoPlanDeclared)` -- a Tier-1 adapter that declares no plan.
    ///   That is a defect in this build, not in the request, and no caller edit fixes
    ///   it.
    ///
    /// Collapsing both to `None` made a caller-supplied bad path surface as
    /// *"the execution backend cannot establish the required sandbox guarantees
    /// (missing: a sandbox plan)"* -- on a host where the sandbox had just executed a
    /// neighbouring capability successfully. An operator's runbook sends them to check
    /// bubblewrap and user namespaces for what was actually a bad request. The
    /// diagnostic the adapter already had was discarded by `.ok()?` on the way.
    ///
    /// Takes the invocation because a Tier-1 adapter's `invoke` is **never called** —
    /// the dispatcher executes the contract built from this plan instead — so this is
    /// the only place a Tier-1 capability's parameters can reach its child. A plan
    /// that ignored them would make every parameterised Tier-1 capability
    /// unimplementable, or worse, implementable only by smuggling data through the
    /// credential environment variable, which is for credentials and is redacted
    /// accordingly.
    fn sandbox_plan(
        &self,
        _invocation: &CapabilityInvocation,
    ) -> Result<Option<SandboxPlan>, PlanError> {
        Ok(None)
    }

    /// How to verify its effects.
    fn verifier(&self) -> &dyn Verifier;

    /// Whether this capability's execution output is **not** durable.
    ///
    /// Defaults to `false`, which is the behaviour every capability had before this method
    /// existed: the output is whatever the sandboxed child wrote to stdout, and callers may
    /// keep it. A bundle that returns `true` is declaring that its output is *ephemeral
    /// execution output* — returned to the dispatcher, never written to durable task
    /// state.
    ///
    /// It lives on the bundle rather than on the declaration because the bundle is what the
    /// dispatcher has in hand when it assembles an outcome, and because this is a statement
    /// about how the effect is obtained rather than about what the capability is. A read of
    /// a workspace file is the case that needs it: the bytes are the point of the call, and
    /// persisting them would copy file contents into `task_step_results` as a side effect
    /// of nothing more than having read something.
    ///
    /// Defaulting to `false` is what makes this safe to add: a capability that says nothing
    /// keeps behaving exactly as it did.
    fn output_is_ephemeral(&self) -> bool {
        false
    }
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
    bundles: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>>,
    reentrancy: ReentrancyGuard,
    /// The only route to a Tier-1 process.
    ///
    /// `None` means no sandbox is configured, and a Tier-1 capability is then
    /// **refused**. That is the fail-closed default: a missing sandbox must not become
    /// an in-process call, and must not become an unsandboxed subprocess (V-49, V-50).
    execution: Option<Arc<dyn ExecutionBackend>>,
}

impl<'p, S: SecretsContract> Dispatcher<'p, S> {
    /// Builds a dispatcher over `registry`.
    ///
    /// Takes an [`AdapterRegistry`] rather than a raw bundle map because the bundle
    /// type is crate-private; see that type for why that is the boundary.
    #[must_use]
    pub fn new(policy: &'p mut PolicyEngine, secrets: &'p S, registry: AdapterRegistry) -> Self {
        Self {
            policy,
            secrets,
            bundles: registry.into_bundles(),
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
        invocation: &CapabilityInvocation,
        capability: &CapabilityId,
    ) -> Result<ExecutionContract, DispatchError> {
        let bundle = self
            .bundles
            .get(capability)
            .ok_or_else(|| DispatchError::NoImplementation(capability.clone()))?;
        let sandboxed = match plan_for(Some(bundle), invocation, capability)? {
            Some(plan) => plan,
            None => {
                return Err(DispatchError::SandboxRefused(
                    SandboxRefusal::nothing_attempted(
                        capability.clone(),
                        "the adapter is Tier-1 but declares no sandbox plan",
                        vec!["a sandbox plan"],
                    ),
                ));
            }
        };
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
        // Kept for the terminal record in stage 9. `authorise_for_dispatch` takes
        // them by value and returns only an invocation, so the journal would have
        // to reconstruct them otherwise — and a reconstructed record does not
        // correlate with the authorisation, which is the state TP-12 exists to
        // make detectable.
        let audit_subject = (request.clone(), actor.clone(), target.clone());

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
        // The authorisation's durable identity. Everything below is obliged to settle
        // exactly this record.
        let authorisation_seq = authorised.authorisation_seq;

        // --- stages 5-8, as a value: no exit may skip the settle below ---
        //
        // `authorisation_seq` is an obligation, not a label. Policy wrote an audit
        // record saying this action was permitted, and from this line on something owns
        // the duty to settle it with exactly one terminal record naming that `seq`.
        //
        // Stages 5-8 can refuse for reasons that have nothing to do with authority -- no
        // implementation, a data class above what the adapter declares, an unconfigured
        // credential, parameters the capability rejects, a sandbox the host cannot
        // establish -- and every one of those used to `return Err(..)` straight out of
        // this function, past the audit write at the bottom. A controlled run found
        // exactly that: two `write-text` authorisations whose parameters were rejected
        // by the plan builder, each with no terminal record at all.
        //
        // So the refusing part is a value, and the settle is unconditional.
        let settled = self.run_authorised(&invocation, &capability, credential_ref, now_ms);

        // --- stage 9: AUDIT / SETTLE ---
        //
        // Reached on every path out of `dispatch` after authorisation: success, every
        // refusal, and every failure. Written here by the one component that holds both
        // the policy engine and the adapter registry, because the record has to be
        // built from the same fields the authorisation was built from and because this
        // is the only place the authorisation's identity is known.
        //
        // It used to sit at the end of the success path only, which is what made every
        // early return above invisible from here.
        let risk = match &decision {
            orxnud_policy::Decision::Allow { risk }
            | orxnud_policy::Decision::Gate { risk, .. } => *risk,
            orxnud_policy::Decision::Deny { .. } => orxnud_domain::enums::RiskClass::UNKNOWN,
        };
        let (kind, detail) = match &settled {
            Ok(outcome) => terminal_outcome(outcome),
            Err(error) => terminal_outcome_for_failure(error),
        };
        // State the approval economics on the record when an approval was presented and
        // the action was then refused.
        //
        // The burn happens inside policy, before the dispatcher reaches stage 5, so a
        // capability that rejects its own parameters has already had the user's approval
        // consumed. That is a deliberate choice — burning after execution would reopen the
        // replay window single-use exists to close — and V-43 records the reservation
        // model as the better long-term answer. It is not free of consequence for anyone
        // reading the journal later, though: the record says an approval authorised a
        // write that was then refused, and the natural reading is that the approval is
        // still good for a retry. It is not. Saying so costs one clause and removes the
        // inference.
        //
        // Keyed on `approval.is_some()` rather than on the decision's `required_digest`,
        // because those are different questions. `required_digest` is `Some` only for a
        // `Gate` — an action that *demanded* an approval. Here the question is whether an
        // approval was *presented and consumed*, which is true for the ordinary case too:
        // a High-risk capability the user approved in advance reaches `Allow`, and its
        // digest is spent at policy's burn just the same. Keying on the gate would have
        // stated the economics only for the paths where it is least in doubt.
        let detail = match (detail, approval) {
            (Some(d), Some(_)) => Some(format!(
                "{d}; the approval presented for this action was already spent and \
                 remains spent, so it cannot be presented again"
            )),
            (other, _) => other,
        };
        let (audit_request, audit_actor, audit_target) = &audit_subject;
        self.policy
            .record_terminal(
                audit_request,
                audit_actor,
                risk,
                audit_target.as_deref(),
                required_digest(&decision),
                authorisation_seq,
                kind,
                detail,
                now_ms,
            )
            .map_err(|e| DispatchError::Audit(e.to_string()))?;

        match settled {
            // The verifier ran and disproved the effect. The terminal record above
            // already describes the execution honestly; this is only the wire error.
            Ok(outcome) if outcome.verification.is_refuted() => {
                Err(DispatchError::VerificationRefuted {
                    evidence: match &outcome.verification {
                        VerificationOutcome::Refuted { evidence } => evidence.clone(),
                        _ => unreachable!("checked by is_refuted"),
                    },
                })
            }
            Ok(outcome) => Ok(outcome),
            Err(error) => Err(error),
        }
    }

    /// Stages 5-8: everything that can happen between "authorised" and "ran".
    ///
    /// Split out of [`Self::dispatch`] for one reason: so that none of it can
    /// `return` out of `dispatch`. Each of these stages used to be an early `return
    /// Err(..)`, and an early return from `dispatch` after stage 1 left the
    /// authorisation record already written with nothing to settle it. As a value
    /// rather than a control-flow exit, "every exit settles its authorisation" becomes
    /// a property of the shape of the function instead of a rule that has to be
    /// remembered at each new refusal.
    ///
    /// Nothing here writes an audit record. That is deliberate: this method decides
    /// *what happened*, and exactly one place in `dispatch` decides *what to record
    /// about* it.
    fn run_authorised(
        &mut self,
        invocation: &CapabilityInvocation,
        capability: &CapabilityId,
        credential_ref: Option<&SecretRef>,
        now_ms: i64,
    ) -> Result<DispatchOutcome, DispatchError> {
        let capability = capability.clone();
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
                    return Err(DispatchError::SandboxRefused(
                        SandboxRefusal::nothing_attempted(
                            capability.clone(),
                            "no execution backend is configured, so a Tier-1 capability \
                             cannot be sandboxed",
                            vec!["a sandbox execution backend"],
                        ),
                    ));
                };
                // Policy completeness is checked here, ahead of the backend, so an
                // incomplete policy costs no subprocess and no execution side effect.
                // `contract_for` reads the same plan, so this cannot disagree with it.
                let plan_resources = {
                    let bundle = self.bundles.get(&capability);
                    match plan_for(bundle, invocation, &capability)? {
                        Some(plan) => plan.resources,
                        None => {
                            return Err(DispatchError::SandboxRefused(
                                SandboxRefusal::nothing_attempted(
                                    capability.clone(),
                                    "the adapter is Tier-1 but declares no sandbox plan",
                                    vec!["a sandbox plan"],
                                ),
                            ));
                        }
                    }
                };
                if let Err(incomplete) = plan_resources.validate() {
                    return Err(DispatchError::SandboxRefused(
                        SandboxRefusal::nothing_attempted(
                            capability.clone(),
                            format!("incomplete resource policy: {incomplete}"),
                            incomplete.missing,
                        ),
                    ));
                }
                let contract = self.contract_for(invocation, &capability)?;
                if !backend.can_fulfil(&contract) {
                    return Err(DispatchError::SandboxRefused(
                        SandboxRefusal::nothing_attempted(
                            capability.clone(),
                            "the execution backend cannot establish the required sandbox \
                             guarantees",
                            vec!["the requested sandbox guarantees"],
                        ),
                    ));
                }
                self.reentrancy.enter(&capability)?;
                let report = {
                    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        backend.execute(&contract)
                    }));
                    self.reentrancy.leave();
                    match caught {
                        Err(_) => {
                            // A backend that panics must not be treated as success, and
                            // must not be retried as though the capability failed.
                            //
                            // `Unknown` certainty, and this is the one site that says so:
                            // `execute` may have spawned its child before unwinding, so
                            // from here nothing ran and something ran are
                            // indistinguishable. Every other refusal is decided before a
                            // process exists and is `NothingAttempted`. Recording this as
                            // a plain refusal would let a later reader — or a retry —
                            // treat an effect that may have happened as one that
                            // definitely did not.
                            return Err(DispatchError::SandboxRefused(SandboxRefusal {
                                capability: capability.clone(),
                                reason: "the execution backend panicked".to_owned(),
                                missing: vec!["a functioning execution backend"],
                                certainty: ExecutionCertainty::Unknown,
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
        // The verifier gets the validated parameters, not just the adapter's output:
        // without the input it could only check the adapter against itself. See
        // `Verifier::verify`.
        //
        // **The one admission point for every verification answer in the system.**
        // Whatever comes back is passed through `admit_verification` before it can
        // reach a `DispatchOutcome`, and therefore before anything downstream -- the
        // terminal audit record, `EffectStatus`, `Certainty`, the task state, retry
        // eligibility -- can see it. Three things funnel through here and nothing else:
        // the verifier's answer, a verifier that could not run, and the admissibility
        // rule itself. That is deliberate: an invariant enforced at two of three exits
        // from a function is an invariant with a hole in it, and this is the exit every
        // governed execution takes.
        let verification = admit_verification(
            &execution,
            match bundle
                .verifier()
                .verify(&execution, invocation.params(), now_ms)
            {
                Ok(v) => v,
                // A verifier that cannot run produces "undetermined", never "verified"
                // and never "refuted". Already conservative, so admission is a no-op on
                // it; it goes through the same function anyway so that there is one
                // place where a verification answer becomes a claim.
                Err(e) => VerificationOutcome::Undetermined {
                    reason: e.to_string(),
                },
            },
        );

        Ok(DispatchOutcome {
            execution,
            verification,
            capability: capability.clone(),
            // Read from the same `bundle` the plan and verifier came from, so the flag
            // cannot disagree with the effect it describes.
            output_is_ephemeral: bundle.output_is_ephemeral(),
        })
    }
}

/// Decides what a verifier's finding is allowed to mean, given what the execution did.
///
/// # The invariant
///
/// ```text
/// Verified or Refuted is admissible only against a Succeeded execution.
/// ```
///
/// Everything else degrades to [`VerificationOutcome::Undetermined`].
///
/// # Why this is one function and not verifier policy
///
/// A verifier is asked for a *finding*; the dispatcher owns what the finding is allowed
/// to mean. That split is the whole point, because the two answers are not symmetric:
///
/// * `Undetermined` withholds a decision. Nothing downstream can act on it.
/// * `Refuted` is the single finding the effect ledger converts into `not-performed`,
///   and `not-performed` is the only status `recover()` reads as *"a repeat cannot
///   duplicate anything"*. A refutation is therefore a **retry permission**.
///
/// So the failure this guards is not a wrong observation, it is a right observation in an
/// inadmissible frame: "the target does not hold the requested bytes" is a true sentence
/// about the world after a capability that was killed mid-write, and acting on it re-runs
/// a non-idempotent effect that may already exist. `WriteTextVerifier` returned
/// `Undetermined` for an unknown execution, correctly, and nothing checked -- a mutation
/// flipping that one arm to `Refuted` reproduced the whole chain against a real daemon,
/// with a real file on disk, and left every test in the workspace green.
///
/// Three properties keep this a rule rather than a convention:
///
/// * **It is central.** One call site, immediately after [`Verifier::verify`] and before
///   the answer can reach `DispatchOutcome`. Every verifier and every capability is
///   covered, and no verifier needs to know the rule exists.
/// * **It is exhaustive, not advisory.** The match below names all nine
///   `ExecutionOutcome` x `VerificationOutcome` pairs with no wildcard, so adding a
///   variant to either enum breaks the build *here*, where somebody has to say whether a
///   new answer is admissible against a new execution. That is the same discipline the
///   cross-channel table in the daemon uses, and it is why this can honestly be called
///   enforced rather than documented.
/// * **It cannot lose the finding.** A refusal keeps the verifier's words, redacted, so
///   an operator can see what was claimed and why it was not accepted. The alternative
///   -- discarding the answer -- would make a systematically over-refusing verifier
///   indistinguishable from one that is merely unlucky.
///
/// # Admissible outcomes, exhaustively
///
/// | execution | `Verified` | `Refuted` | `Undetermined` |
/// |---|---|---|---|
/// | `Succeeded` | admissible | **admissible** -- the legitimate refutation | admissible |
/// | `Failed`    | refused | **refused** -- the capability may have written before failing | admissible |
/// | `Unknown`   | refused | **refused** -- the capability may have written before going silent | admissible |
///
/// `Cancelled` and every post-start sandbox status arrive here as
/// [`ExecutionOutcome::Unknown`] -- `outcome_from_report` collapses them -- so the
/// `Unknown` row covers the whole post-start family rather than a hypothetical fourth
/// execution state. That collapse is why the rule is written over `ExecutionOutcome` and
/// not over `ExecutionOutcomeKind`: the kind is an implementation detail of the sandbox
/// bridge and has already been resolved by the time anything here could use it.
#[must_use]
pub fn admit_verification(
    execution: &ExecutionOutcome,
    reported: VerificationOutcome,
) -> VerificationOutcome {
    use ExecutionOutcome as E;
    use VerificationOutcome as V;
    // All nine cells named, no wildcard. Written out rather than compressed with a `_`
    // so that adding a variant to *either* enum breaks the build right here, where
    // somebody has to say whether the new answer is admissible against the new execution.
    // A first draft that grouped the answers instead was rejected by rustc for leaving
    // two cells uncovered, which is the behaviour this shape is here to get.
    match (execution, &reported) {
        // A capability that ran and finished is the only case where there is a world to
        // look at, so every answer stands -- including the refutation, which is exactly
        // where `Succeeded + Refuted` earns its retry permission.
        (E::Succeeded { .. }, V::Verified { .. })
        | (E::Succeeded { .. }, V::Refuted { .. })
        | (E::Succeeded { .. }, V::Undetermined { .. }) => reported,

        // "Nobody can say" never over-claims, so it is admissible against anything.
        (E::Failed { .. }, V::Undetermined { .. })
        | (E::Unknown { .. }, V::Undetermined { .. }) => reported,

        // The four inadmissible cells, and only these: a finding about a capability that
        // failed or went silent.
        (E::Failed { .. }, V::Verified { .. })
        | (E::Failed { .. }, V::Refuted { .. })
        | (E::Unknown { .. }, V::Verified { .. })
        | (E::Unknown { .. }, V::Refuted { .. }) => refuse_claim(execution, &reported),
    }
}

/// Builds the conservative replacement for a finding that was not admissible.
///
/// Split out so [`admit_verification`] stays a table, and so the two matches over the
/// closed vocabulary are each exhaustive in their own right. Every `return reported` below
/// is unreachable given the caller and is written out anyway: a claim being refused is
/// the only thing this function does, and a caller reaching either arm by accident gets
/// the claim back rather than a panic.
fn refuse_claim(
    execution: &ExecutionOutcome,
    reported: &VerificationOutcome,
) -> VerificationOutcome {
    use ExecutionOutcome as E;
    use VerificationOutcome as V;
    let phase = match execution {
        E::Failed { detail } => format!("reported a failure ({})", redact(detail)),
        E::Unknown { detail } => format!("did not report ({})", redact(detail)),
        E::Succeeded { .. } => return reported.clone(),
    };
    let claimed = match reported {
        V::Verified { evidence } => {
            format!("claimed the effect happened ({})", redact(evidence))
        }
        V::Refuted { evidence } => {
            format!("claimed the effect is absent ({})", redact(evidence))
        }
        V::Undetermined { .. } => return reported.clone(),
    };
    V::Undetermined {
        reason: format!(
            "the capability {phase}, and verification {claimed}; the finding is not \
             admissible against an execution that did not report success, because a \
             capability that fails or goes silent may still have produced its effect"
        ),
    }
}

/// Asks a bundle for its sandbox plan, translating the adapter's refusal.
///
/// `Ok(None)` means "this bundle declares no plan" -- for Tier 0 that is ordinary, and
/// for Tier 1 it is a build defect, which the callers report as a sandbox refusal so it
/// still reads as an environment fault rather than a bad request.
///
/// `Err(PlanError::InvalidParams)` becomes [`DispatchError::InvalidInput`]. That
/// mapping is the entire point of retyping this: the capability had a precise reason and
/// a caller can act on it, and neither fact survives being flattened into "no plan".
fn plan_for(
    bundle: Option<&Arc<dyn AdapterBundle + Send + Sync>>,
    invocation: &CapabilityInvocation,
    capability: &CapabilityId,
) -> Result<Option<SandboxPlan>, DispatchError> {
    let Some(bundle) = bundle else {
        return Ok(None);
    };
    match bundle.sandbox_plan(invocation) {
        Ok(plan) => Ok(plan),
        Err(PlanError::InvalidParams(detail)) => Err(DispatchError::InvalidInput {
            capability: capability.clone(),
            detail,
        }),
        // A bundle that returns this *as an error* is saying something stronger than
        // `Ok(None)`: it looked, and there is nothing. Either way the answer is a
        // defect in this build, so it is reported as a sandbox refusal by the callers
        // and never as the caller's fault.
        Err(PlanError::NoPlanDeclared) => Ok(None),
    }
}

/// How a finished dispatch should be described in the journal.
///
/// # Why this is a function and not a field
///
/// The journal needs a decision that does not exist anywhere else: an execution
/// that succeeded but was not verified is **not** a completed action, and an
/// execution that never reported is **not** a failed one. Mapping those
/// correctly once, here, is what stops stage 8's distinction from being lost on
/// the way to the record.
fn terminal_outcome(outcome: &DispatchOutcome) -> (orxnud_audit::OutcomeKind, Option<String>) {
    use orxnud_audit::OutcomeKind;
    match (&outcome.execution, outcome.verification.is_verified()) {
        // Verified, or refused by policy after the fact.
        (ExecutionOutcome::Succeeded { .. }, true) => (OutcomeKind::Completed, None),
        // Succeeded but not verified: the effect may or may not have happened.
        // This is TP-12's answer and it must not be recorded as `Completed`.
        (ExecutionOutcome::Succeeded { .. }, false) => (
            OutcomeKind::Uncertain,
            Some("the adapter reported success but verification did not confirm it".to_owned()),
        ),
        (ExecutionOutcome::Failed { detail }, _) => (OutcomeKind::Failed, Some(redact(detail))),
        (ExecutionOutcome::Unknown { detail }, _) => (OutcomeKind::Uncertain, Some(redact(detail))),
    }
}

/// How a dispatch that returned `Err` should be described in the journal.
///
/// # Why this exists separately from `terminal_outcome`
///
/// `terminal_outcome` describes a dispatch that *ran*: it has an execution and a
/// verification to weigh. This one describes a dispatch that returned an error, and
/// the question it answers is different — **did the capability run?** That is not a
/// detail. `OutcomeKind::Denied` asserts the action did not execute, and
/// `OutcomeKind::Uncertain` declines to say, and the difference decides whether a
/// caller may safely retry.
///
/// Before this existed there was no mapping at all: an early return wrote no record
/// and the journal was left claiming an action had been authorised with no outcome.
/// Every arm is written out, so adding a `DispatchError` variant breaks the build here,
/// where somebody has to say whether it ran.
///
/// # Visibility
///
/// Public because this is the *audit channel's* authoritative mapping, and the daemon
/// holds the *effect channel's* mapping for the same input. The property worth holding is
/// that the two never contradict — "no component may represent a may-have-run execution
/// as definitely not-performed" — and that cannot be asserted from either side alone.
/// `runtime.rs` asserts it over every `DispatchError` variant in one table.
#[must_use]
pub fn terminal_outcome_for_failure(
    error: &DispatchError,
) -> (orxnud_audit::OutcomeKind, Option<String>) {
    use orxnud_audit::OutcomeKind;
    match error {
        // --- Demonstrably did not execute. A `Denied`, so a retry is offered. ---
        //
        // All of these are decided before a process exists, which is what makes the
        // distinction from the group below structural rather than a judgement call.
        DispatchError::Policy(_) => (OutcomeKind::Denied, Some("refused by policy".to_owned())),
        DispatchError::NoImplementation(c) => (
            OutcomeKind::Denied,
            Some(format!("no implementation is registered for {c}")),
        ),
        DispatchError::Disabled(c) => (OutcomeKind::Denied, Some(format!("{c} is disabled"))),
        DispatchError::ClassEscalation { .. } => (
            OutcomeKind::Denied,
            Some("the data class exceeds what the implementation declares".to_owned()),
        ),
        DispatchError::Credential(_) => (
            OutcomeKind::Denied,
            Some("a required credential could not be produced".to_owned()),
        ),
        DispatchError::InvalidInput { capability, .. } => (
            OutcomeKind::Denied,
            Some(format!("{capability} rejected the supplied parameters")),
        ),
        // A sandbox refusal is a `Denied` **only** where the refusal itself establishes
        // that nothing was spawned. A backend that panicked may have spawned its child
        // before unwinding, and there `Uncertain` is the honest answer.
        DispatchError::SandboxRefused(refusal) => match refusal.certainty {
            ExecutionCertainty::NothingAttempted => (
                OutcomeKind::Denied,
                Some(format!(
                    "no sandbox could be established: {}",
                    refusal.reason
                )),
            ),
            ExecutionCertainty::Unknown => (
                OutcomeKind::Uncertain,
                Some(format!(
                    "the execution backend could not establish what it had started, so a child \
                     may have run and its outcome is not settled: {}",
                    refusal.reason
                )),
            ),
        },

        // --- Reached the capability; it ran or may have run. ---
        //
        // `Failed` where the capability reported a failure, `Uncertain` where the
        // report itself is missing or the verifier could not settle it. Neither is
        // offered for retry, because neither establishes that repeating the call
        // cannot duplicate the effect.
        DispatchError::Execution(detail) => (OutcomeKind::Failed, Some(redact(detail))),
        DispatchError::Verification(e) => (
            OutcomeKind::Uncertain,
            Some(format!("verification did not settle the effect: {e}")),
        ),

        // The verifier disproved the effect. The capability ran and demonstrably did
        // not do what was asked, which is a stronger statement than "failed" and must
        // not be recorded as an ordinary failure.
        DispatchError::VerificationRefuted { .. } => (
            OutcomeKind::Failed,
            Some("verification refuted the reported effect".to_owned()),
        ),

        // An adapter called back into the dispatcher.
        //
        // `Denied`, because `ReentrancyGuard::enter` is called *before* `execute` (stage
        // 7, subprocess tier) and before `invoke` (stage 7, in-process tier). The
        // capability this dispatch was about to run therefore never ran, which is a fact
        // about the code's order rather than an inference, and it is what the effect
        // ledger already records.
        //
        // This said `Uncertain` on the reasoning that "the adapter's earlier work in this
        // call is not rewindable". That was the wrong subject: the adapter that did that
        // work belongs to an *outer* dispatch, which has its own record and its own
        // outcome. Here the claim on the table was simply `Unknown` while
        // `effect_status_for_dispatch_failure` said `NotPerformed`, and the two disagreed
        // about an event whose outcome is settled by the order of two statements.
        DispatchError::Reentrant(_) => (
            OutcomeKind::Denied,
            Some("a capability re-entered the dispatcher".to_owned()),
        ),

        // Reached here only if a future stage raised it before stage 9. Stage 9's own
        // audit failure returns without reaching this function, because there is no
        // journal left to record it in -- and that limitation is why `Audit` is
        // documented as fatal in both directions.
        DispatchError::Audit(detail) => (
            OutcomeKind::Uncertain,
            Some(format!(
                "the audit journal failed: {}",
                redact(&detail.to_owned())
            )),
        ),
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

// ---------------------------------------------------------------------------
// Admissibility: what a verification answer is allowed to mean
// ---------------------------------------------------------------------------

#[cfg(test)]
mod admit_verification_tests {
    use super::admit_verification;
    use crate::verification::{ExecutionOutcome as E, VerificationOutcome as V};

    /// Every `ExecutionOutcome`, so a new variant has to be added to the table below.
    fn executions() -> Vec<(&'static str, E)> {
        vec![
            ("succeeded", E::Succeeded { output: None }),
            (
                "failed",
                E::Failed {
                    detail: "exit 1".to_owned(),
                },
            ),
            (
                "unknown",
                E::Unknown {
                    detail: "killed".to_owned(),
                },
            ),
        ]
    }

    /// Every `VerificationOutcome`, likewise.
    fn verifications() -> Vec<(&'static str, V)> {
        vec![
            (
                "verified",
                V::Verified {
                    evidence: "e".to_owned(),
                },
            ),
            (
                "refuted",
                V::Refuted {
                    evidence: "e".to_owned(),
                },
            ),
            (
                "undetermined",
                V::Undetermined {
                    reason: "r".to_owned(),
                },
            ),
        ]
    }

    /// The whole cross-product, as the table the rule *is*.
    ///
    /// A: the invariant, over every pair. `Refuted` and `Verified` are a disproof and a
    /// confirmation respectively, and only a `Succeeded` execution has standing to issue
    /// either. Anything else arrives as `Undetermined`, which withholds a decision and so
    /// cannot become a retry permission downstream.
    ///
    /// The count is pinned so a variant added to either enum cannot join the product
    /// silently: the loop below iterates 3x3, and a fourth execution would make it 4x3
    /// without touching a single assertion.
    #[test]
    fn only_a_succeeded_execution_may_issue_a_finding() {
        let (execs, vers) = (executions(), verifications());
        assert_eq!(
            (execs.len(), vers.len()),
            (3, 3),
            "the table is the whole cross-product; extend it when either enum grows"
        );

        for (ename, execution) in &execs {
            for (vname, reported) in &vers {
                let admitted = admit_verification(execution, reported.clone());
                let label = format!("{ename} + {vname}");

                match *vname {
                    "verified" | "refuted" => {
                        if *ename == "succeeded" {
                            assert_eq!(
                                &admitted, reported,
                                "{label}: a capability that ran and finished is the only \
                                 execution with a world to look at, so the finding stands"
                            );
                        } else {
                            assert!(
                                admitted.is_undetermined(),
                                "{label}: `{vname}` is a claim about the world, and a \
                                 capability that {ename} may still have produced its \
                                 effect, so the claim is not admissible and must be \
                                 withheld. Got {admitted:?}"
                            );
                            assert_eq!(
                                admitted.to_string(),
                                "undetermined",
                                "{label}: and it must be withheld, not silently kept"
                            );
                        }
                    }
                    // `Undetermined` is admissible everywhere: "nobody can say" is not a
                    // claim, so there is nothing for it to over-claim.
                    _ => assert_eq!(
                        &admitted, reported,
                        "{label}: withholding a decision never over-claims, so it passes \
                         through untouched"
                    ),
                }
            }
        }
    }

    /// The property the runtime depends on, stated over the closed vocabulary alone.
    ///
    /// Downstream, `VerificationOutcome::Refuted` is the *only* finding
    /// `certainty_of` maps to `Certainty::Disproved`, and `Disproved` is the only
    /// verification-derived value that becomes `EffectStatus::NotPerformed` -- the status
    /// `recover()` excludes from its uncertainty predicate, and therefore the retry
    /// permission. So the whole chain reduces to this: a claim must never survive an
    /// execution that did not report success.
    #[test]
    fn a_claim_never_survives_an_execution_that_did_not_report_success() {
        for (ename, execution) in executions() {
            for claim in [
                V::Verified {
                    evidence: "confirmed".to_owned(),
                },
                V::Refuted {
                    evidence: "absent".to_owned(),
                },
            ] {
                let admitted = admit_verification(&execution, claim.clone());
                if ename != "succeeded" {
                    assert!(
                        !admitted.is_verified() && !admitted.is_refuted(),
                        "{ename} + {claim:?}: a claim leaked through as {admitted:?}, and \
                         that is the one conversion that would authorise repeating a \
                         non-idempotent effect"
                    );
                }
            }
        }
    }

    /// A refusal keeps the verifier's words, bounded.
    ///
    /// Two reasons this matters rather than being cosmetic. An operator has to be able to
    /// see *what was claimed* and *why it was refused*, or a systematically over-refusing
    /// verifier is indistinguishable from an unlucky one. And the claim's `evidence` is
    /// verifier-controlled text, so it goes through the same `redact` the rest of this
    /// module uses for untrusted output: control characters stripped, capped at 512 bytes
    /// with the total reported.
    #[test]
    fn a_refused_claim_keeps_bounded_evidence_and_says_why() {
        let long = "€".repeat(400); // three bytes each, so this overruns a byte budget
        let admitted = admit_verification(
            &E::Unknown {
                detail: "killed by a signal".to_owned(),
            },
            V::Refuted {
                evidence: format!("absent\n{long}"),
            },
        );
        let V::Undetermined { reason } = &admitted else {
            panic!("expected a withheld finding, got {admitted:?}")
        };
        assert!(
            reason.contains("claimed the effect is absent"),
            "the operator must see the claim that was refused: {reason}"
        );
        assert!(
            reason.contains("killed by a signal"),
            "and the execution phase it was refused against: {reason}"
        );
        assert!(
            reason.contains("may still have produced its effect"),
            "and the reason the refusal is the safe direction: {reason}"
        );
        assert!(
            !reason.contains('\n') && !reason.contains('\r'),
            "a newline here would be a framing hazard: {reason:?}"
        );
        // Bounded by construction rather than by a named constant: `redact` caps each
        // piece of untrusted text at 512 bytes, and this reason embeds two of them plus a
        // fixed frame, so 4096 is a ceiling no input can approach. The point of the
        // assertion is that the composition cannot grow without limit, not that it
        // matches a particular constant.
        assert!(
            reason.len() < 4096,
            "the reason must stay bounded whatever the verifier wrote, got {} bytes",
            reason.len()
        );
    }

    /// The refusals are not silent, and they are not panics either.
    ///
    /// Written out because the two inner matches in `refuse_claim` each carry an
    /// unreachable arm, and an unreachable arm that panics is a latent failure in a
    /// function that decides whether a non-idempotent effect may be repeated.
    #[test]
    fn a_refusal_degrades_rather_than_failing() {
        for execution in executions() {
            for reported in verifications() {
                // Total function: every pair returns something, nothing unwinds.
                let _ = admit_verification(&execution.1, reported.1);
            }
        }
    }
}
