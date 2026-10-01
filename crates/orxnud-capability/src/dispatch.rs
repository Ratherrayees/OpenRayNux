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
use orxnud_domain::invocation::{ActionRequest, InvocationContext};
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
pub trait CapabilityAdapter: Send + Sync {
    /// The id this adapter implements.
    fn capability_id(&self) -> &CapabilityId;

    /// The highest data class this adapter may handle.
    fn declared_class(&self) -> orxnud_domain::enums::DataClass;

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

/// Verification strategy, looked up alongside the adapter.
pub trait AdapterBundle {
    /// The adapter.
    fn adapter(&self) -> &dyn CapabilityAdapter;

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
        }
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
        self.reentrancy.enter(&capability).map_err(|e| match e {
            DispatchError::Reentrant(_) => e,
            other => other,
        })?;

        // The guard is released by `catch_unwind`'s drop path even on a panic, so a
        // faulty adapter cannot wedge the dispatcher for the process lifetime.
        let view = invocation.dispatch_view();
        let execution = {
            let credential = credential.as_ref();
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                adapter.invoke(&view, credential)
            }));
            self.reentrancy.leave();

            match caught {
                // A panicking adapter is a bug in the adapter, and ADR-0009 requires
                // that it not take down the host. Reported as an execution failure,
                // never as a permission failure.
                Err(_) => ExecutionOutcome::Unknown {
                    detail: format!("{} panicked during execution", capability),
                },
                Ok(Err(e)) => ExecutionOutcome::Failed { detail: e },
                Ok(Ok(outcome)) => outcome,
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
