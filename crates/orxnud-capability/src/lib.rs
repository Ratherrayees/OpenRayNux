//! Capability registry, contracts, and the dispatcher shell.
//!
//! # This crate contains no capabilities
//!
//! Phase 1 builds the *registry* and the *dispatcher*, and registers nothing.
//! An empty registry is the correct end state, not a stub to be filled in
//! later: it is what makes "zero capabilities enabled" a mechanical fact rather
//! than a claim. [`CapabilityRegistry::default`] is empty, and the dispatcher
//! refuses every invocation it is given.
//!
//! If a capability were registered here in Phase 1, the phase would have
//! overrun — see `docs/13-phase-1-contract.md` §8.
//!
//! # The three pieces
//!
//! * [`CapabilityContract`] — what a capability declares about itself: its risk,
//!   data classes, whether it is idempotent, whether it is enabled.
//! * [`CapabilityRegistry`] — the set of known capabilities. Lookup is by
//!   [`CapabilityId`]; registration is explicit and there is no dynamic discovery.
//! * [`Dispatcher`] — resolves an authorised [`CapabilityInvocation`] against the
//!   registry and refuses if the capability is absent, disabled, or mismatched.
//!
//! # Why the dispatcher checks again
//!
//! Policy already authorised the invocation, so is the dispatcher's check
//! redundant? No, and the redundancy is the point. Policy decides *whether this
//! action is permitted*; the registry decides *whether this capability exists and
//! is switched on right now*. A capability can be disabled between authorisation
//! and dispatch, and a stale authorisation must not resurrect it. Defence in
//! depth that costs one `Option` lookup is worth having on the one path that
//! reaches a side effect.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeMap;

use orxnud_domain::Actor;
use orxnud_domain::enums::{DataClass, IsolationTier, RiskClass};
use orxnud_domain::ids::CapabilityId;
use orxnud_domain::invocation::{CapabilityInvocation, DispatchView};
use serde::{Deserialize, Serialize};

/// What a capability declares about itself.
///
/// A declaration, not a behaviour: this says what calling the capability *means*,
/// never what it does. The `CapabilityContract` trait below is what a
/// *implementation* provides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDeclaration {
    /// The id it is registered under.
    pub id: CapabilityId,
    /// Human-readable name for `orxnuctl doctor`. Not a description of behaviour.
    pub display_name: String,
    /// The risk class the capability declares.
    pub risk: RiskClass,
    /// The highest data class it may read.
    pub reads: DataClass,
    /// The highest data class it may emit.
    pub writes: DataClass,
    /// The isolation it requires.
    pub isolation: IsolationTier,
    /// Whether repeating the same call with the same idempotency key is safe.
    ///
    /// `false` means at-least-once delivery would duplicate an effect, so the
    /// task layer must treat an uncertain outcome as `NeedsVerification` rather
    /// than retrying. See TP-2 and TP-12.
    pub idempotent: bool,
    /// Whether the capability is switched on.
    ///
    /// A disabled capability has **zero operational cost**: it is not started, it
    /// is not polled, and the dispatcher refuses it without touching the
    /// declaration's other fields.
    pub enabled: bool,
}

impl CapabilityDeclaration {
    /// A declaration with conservative defaults: medium risk, public data,
    /// non-idempotent, disabled.
    ///
    /// Non-idempotent and disabled are the defaults on purpose. Assuming a new
    /// capability is safe to retry or safe to run are both optimistic; assuming it
    /// is off means enabling it is a deliberate act.
    #[must_use]
    pub fn new(id: CapabilityId, display_name: impl Into<String>) -> Self {
        Self {
            id,
            display_name: display_name.into(),
            risk: RiskClass::Medium,
            reads: DataClass::Public,
            writes: DataClass::Public,
            isolation: IsolationTier::default(),
            idempotent: false,
            enabled: false,
        }
    }

    /// Sets the declared risk.
    #[must_use]
    pub fn with_risk(mut self, risk: RiskClass) -> Self {
        self.risk = risk;
        self
    }

    /// Sets the data classes it may read and write.
    #[must_use]
    pub fn with_data(mut self, reads: DataClass, writes: DataClass) -> Self {
        self.reads = reads;
        self.writes = writes;
        self
    }

    /// Sets the required isolation.
    #[must_use]
    pub fn with_isolation(mut self, isolation: IsolationTier) -> Self {
        self.isolation = isolation;
        self
    }

    /// Marks the capability idempotent.
    #[must_use]
    pub fn idempotent(mut self) -> Self {
        self.idempotent = true;
        self
    }

    /// Enables the capability.
    #[must_use]
    pub fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// The effective data class for a call that both reads and writes.
    #[must_use]
    pub fn effective_class(&self) -> DataClass {
        self.reads.combine(self.writes)
    }
}

/// What a capability implementation provides.
///
/// The contract is deliberately narrow: it receives a [`DispatchView`], which
/// **does not carry the actor**. A capability that learns who is calling it
/// becomes a confused deputy able to reuse one caller's authority for another's
/// request (ADR-0027, control S8).
///
/// # Errors
///
/// Any failure the capability reports, including one it invents. The dispatcher
/// does not interpret adapter failures as permission failures; a capability that
/// cannot do the work fails the *work*, not the *policy*.
pub trait CapabilityContract {
    /// Runs the capability.
    fn invoke(&self, view: &DispatchView<'_>) -> Result<CapabilityOutcome, CapabilityError>;
}

/// What a capability returns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityOutcome {
    /// The value produced. `None` for a capability with no result.
    pub value: Option<serde_json::Value>,
    /// Whether the caller should treat the effect as having happened.
    ///
    /// `false` means *unknown*, which is not the same as "did not happen". This
    /// distinction is what TP-12 exists to preserve: an unknown outcome must be
    /// recorded as unknown, never silently reported as success.
    pub effect_observed: bool,
    /// A short, redacted description for the audit trail. Never a secret.
    pub detail: Option<String>,
}

impl CapabilityOutcome {
    /// An outcome whose effect is known to have occurred.
    #[must_use]
    pub fn observed(value: serde_json::Value) -> Self {
        Self {
            value: Some(value),
            effect_observed: true,
            detail: None,
        }
    }

    /// An outcome whose effect is **unknown**.
    #[must_use]
    pub fn uncertain() -> Self {
        Self {
            value: None,
            effect_observed: false,
            detail: None,
        }
    }

    /// An outcome known *not* to have occurred.
    #[must_use]
    pub fn not_performed(detail: impl Into<String>) -> Self {
        Self {
            value: None,
            effect_observed: false,
            detail: Some(detail.into()),
        }
    }
}

/// Why a dispatch was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DispatchError {
    /// No capability is registered under this id.
    #[error("no capability is registered as {0}")]
    NotRegistered(CapabilityId),

    /// Registered, but switched off.
    ///
    /// Distinct from [`Self::NotRegistered`] on purpose: "you turned this off"
    /// and "this does not exist" need different messages in a bug report.
    #[error("capability {0} is disabled")]
    Disabled(CapabilityId),

    /// The invocation's data class exceeds what the capability declared.
    #[error("capability {id} declares at most {declared} but was invoked at {actual}")]
    ClassEscalation {
        /// The capability.
        id: CapabilityId,
        /// The maximum the declaration permits.
        declared: DataClass,
        /// The class the invocation actually carries.
        actual: DataClass,
    },

    /// The capability has no implementation registered.
    #[error("capability {0} is declared but has no implementation")]
    NoImplementation(CapabilityId),

    /// The capability itself failed. Not a permission failure.
    #[error("capability failed: {0}")]
    Failed(String),
}

/// A capability failure.
pub type CapabilityError = String;

/// The set of known capabilities.
///
/// A `BTreeMap`, not a `HashMap`: registry contents appear in `doctor` output and
/// in audit records, and a stable iteration order makes those comparable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityRegistry {
    entries: BTreeMap<CapabilityId, CapabilityDeclaration>,
}

impl CapabilityRegistry {
    /// An empty registry. This is the Phase 1 state.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Registers a declaration.
    ///
    /// # Errors
    ///
    /// Fails if the id is already registered. Silently replacing a declaration
    /// would let a later component change a capability's risk or data classes
    /// after something had already been authorised against the old values.
    pub fn register(&mut self, declaration: CapabilityDeclaration) -> Result<(), RegistryError> {
        if self.entries.contains_key(&declaration.id) {
            return Err(RegistryError::Duplicate(declaration.id));
        }
        self.entries.insert(declaration.id.clone(), declaration);
        Ok(())
    }

    /// Looks up a declaration.
    #[must_use]
    pub fn get(&self, id: &CapabilityId) -> Option<&CapabilityDeclaration> {
        self.entries.get(id)
    }

    /// Whether an id is registered, regardless of whether it is enabled.
    #[must_use]
    pub fn contains(&self, id: &CapabilityId) -> bool {
        self.entries.contains_key(id)
    }

    /// Every registered id, in stable order.
    #[must_use]
    pub fn ids(&self) -> Vec<CapabilityId> {
        self.entries.keys().cloned().collect()
    }

    /// Every declaration, in stable order.
    pub fn iter(&self) -> impl Iterator<Item = &CapabilityDeclaration> {
        self.entries.values()
    }

    /// The registered capabilities that are switched on.
    #[must_use]
    pub fn enabled(&self) -> Vec<&CapabilityDeclaration> {
        self.entries.values().filter(|d| d.enabled).collect()
    }

    /// How many capabilities are enabled.
    ///
    /// Phase 1's exit criterion is that this is zero, so the count is exposed
    /// rather than inferred.
    #[must_use]
    pub fn enabled_count(&self) -> usize {
        self.entries.values().filter(|d| d.enabled).count()
    }
}

/// A registry error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// Two declarations claimed the same id.
    #[error("capability {0} is already registered")]
    Duplicate(CapabilityId),
}

/// Resolves authorised invocations against the registry.
///
/// Holds no implementations in Phase 1, so every dispatch is refused. The
/// resolution *logic* — the part that decides whether an invocation is
/// admissible — is what Phase 2 and the capability phases depend on, so it is
/// implemented and tested now with an empty registry.
#[derive(Debug, Clone, Default)]
pub struct Dispatcher {
    registry: CapabilityRegistry,
}

impl Dispatcher {
    /// A dispatcher over an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A dispatcher over `registry`.
    #[must_use]
    pub fn with_registry(registry: CapabilityRegistry) -> Self {
        Self { registry }
    }

    /// The registry this dispatcher resolves against.
    #[must_use]
    pub fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }

    /// Decides whether an authorised invocation may proceed.
    ///
    /// This performs **no** I/O and calls **no** capability. It answers one
    /// question: is this invocation still admissible? In Phase 1 the answer is
    /// always no, because the registry is empty — but the checks are written and
    /// tested so that registering a capability in a later phase cannot skip them.
    ///
    /// # Errors
    ///
    /// A [`DispatchError`] naming the first failed check.
    pub fn resolve<'i>(
        &self,
        invocation: &'i CapabilityInvocation,
    ) -> Result<ResolvedDispatch<'i>, DispatchError> {
        let id = invocation.capability().clone();
        let declaration = self
            .registry
            .get(&id)
            .ok_or_else(|| DispatchError::NotRegistered(id.clone()))?;
        if !declaration.enabled {
            return Err(DispatchError::Disabled(id));
        }
        let declared = declaration.effective_class();
        let actual = invocation.data_class();
        if actual > declared {
            return Err(DispatchError::ClassEscalation {
                id,
                declared,
                actual,
            });
        }
        Ok(ResolvedDispatch {
            capability: id,
            actor: invocation.actor().clone(),
            view: invocation.dispatch_view(),
        })
    }

    /// The invocation projection an adapter would receive.
    #[must_use]
    pub fn view_for<'i>(&self, invocation: &'i CapabilityInvocation) -> DispatchView<'i> {
        invocation.dispatch_view()
    }
}

/// An invocation that passed every admissibility check.
///
/// Carries the actor for the *audit* record and the view for the adapter. The
/// two are deliberately separate fields so that handing `actor` to an adapter is
/// a visible act rather than an accident of destructuring.
#[derive(Debug, Clone)]
pub struct ResolvedDispatch<'a> {
    /// Which capability to run.
    pub capability: CapabilityId,
    /// Who is acting. For audit only.
    pub actor: Actor,
    /// What the adapter receives. Contains no actor.
    pub view: DispatchView<'a>,
}

impl ResolvedDispatch<'_> {
    /// Whether this dispatch may carry a given actor into an adapter.
    ///
    /// Always `false`. It exists as a single named predicate so the "no actor to
    /// adapters" rule has one place to be tested, rather than being a property
    /// inferred from the struct's shape.
    #[must_use]
    pub fn actor_reaches_adapter(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_domain::PolicySeal;
    use orxnud_domain::actor::{Actor, AuthChannel};
    use orxnud_domain::approval::ApprovalDigest;
    use orxnud_domain::ids::{RunId, TaskId, UserId};
    use orxnud_domain::invocation::{ActionRequest, InvocationContext};
    use proptest::prelude::*;

    fn cap(name: &str) -> CapabilityId {
        CapabilityId::new(name)
    }

    fn actor() -> Actor {
        Actor::Human {
            user: UserId::new("u"),
            via: AuthChannel::LocalInteractive,
        }
    }

    fn request(class: DataClass) -> ActionRequest {
        ActionRequest::new(
            TaskId::new("t"),
            RunId::new("r"),
            0,
            cap("c"),
            serde_json::json!({"x": 1}),
            class,
            class,
        )
    }

    /// Builds an invocation the way `orxnud-policy` does. This is test-only
    /// scaffolding: gate G2 forbids this spelling outside the policy crate.
    fn authorised(capability: &str, class: DataClass) -> CapabilityInvocation {
        let mut req = request(class);
        req.capability = cap(capability);
        let seal = PolicySeal::attest("orxnud-capability-test");
        let proof = orxnud_domain::AuthorisationProof::issue(
            &seal,
            "v1",
            Some(ApprovalDigest::from_bytes([1u8; 32])),
            RiskClass::Medium,
        );
        CapabilityInvocation::authorise(
            &seal,
            req,
            actor(),
            InvocationContext::new("k", 1_000, "c"),
            proof,
        )
    }

    #[test]
    fn phase_one_registers_nothing() {
        // The exit criterion, asserted rather than described.
        let r = CapabilityRegistry::empty();
        assert!(r.ids().is_empty());
        assert_eq!(r.enabled_count(), 0);
        assert_eq!(r.enabled().len(), 0);
    }

    #[test]
    fn an_empty_registry_refuses_every_dispatch() {
        let d = Dispatcher::new();
        let err = d
            .resolve(&authorised("anything", DataClass::Public))
            .expect_err("must refuse");
        assert_eq!(err, DispatchError::NotRegistered(cap("anything")));
    }

    #[test]
    fn a_registered_but_disabled_capability_is_refused_distinctly() {
        let mut r = CapabilityRegistry::empty();
        r.register(CapabilityDeclaration::new(cap("c"), "C"))
            .expect("register");
        let d = Dispatcher::with_registry(r);
        let invocation = authorised("c", DataClass::Public);
        let err = d.resolve(&invocation).expect_err("must refuse");
        assert_eq!(err, DispatchError::Disabled(cap("c")));
    }

    #[test]
    fn enabling_a_capability_lets_it_through_but_adds_no_implementation() {
        let mut r = CapabilityRegistry::empty();
        r.register(
            CapabilityDeclaration::new(cap("c"), "C")
                .with_data(DataClass::Public, DataClass::Public)
                .enabled(),
        )
        .expect("register");
        let d = Dispatcher::with_registry(r);
        assert_eq!(d.registry().enabled_count(), 1);

        // Resolution succeeds; there is still nothing to *run*, which is why
        // `resolve` returns a description rather than executing anything.
        let invocation = authorised("c", DataClass::Public);
        let resolved = d.resolve(&invocation).expect("resolve");
        assert_eq!(resolved.capability, cap("c"));
    }

    #[test]
    fn an_invocation_above_the_declared_class_is_refused() {
        let mut r = CapabilityRegistry::empty();
        r.register(
            CapabilityDeclaration::new(cap("c"), "C")
                .with_data(DataClass::Public, DataClass::Public)
                .enabled(),
        )
        .expect("register");
        let d = Dispatcher::with_registry(r);
        let invocation = authorised("c", DataClass::Regulated);
        let err = d.resolve(&invocation).expect_err("must refuse");
        assert_eq!(
            err,
            DispatchError::ClassEscalation {
                id: cap("c"),
                declared: DataClass::Public,
                actual: DataClass::Regulated,
            }
        );
    }

    #[test]
    fn registration_is_refused_twice_for_one_id() {
        let mut r = CapabilityRegistry::empty();
        r.register(CapabilityDeclaration::new(cap("c"), "first"))
            .expect("first");
        let err = r
            .register(CapabilityDeclaration::new(cap("c"), "second"))
            .expect_err("second");
        assert_eq!(err, RegistryError::Duplicate(cap("c")));
        // The original declaration is untouched: a silent replace would let a
        // risk class change after something was authorised against the old one.
        assert_eq!(r.get(&cap("c")).expect("present").display_name, "first");
    }

    #[test]
    fn the_registry_iterates_in_a_stable_order() {
        let mut r = CapabilityRegistry::empty();
        for n in ["zeta", "alpha", "mid"] {
            r.register(CapabilityDeclaration::new(cap(n), n))
                .expect("register");
        }
        assert_eq!(r.ids(), vec![cap("alpha"), cap("mid"), cap("zeta")]);
    }

    #[test]
    fn defaults_are_conservative() {
        let d = CapabilityDeclaration::new(cap("c"), "C");
        // Not safe to retry, not safe to run, no special data, medium risk.
        assert!(!d.idempotent);
        assert!(!d.enabled);
        assert_eq!(d.effective_class(), DataClass::Public);
        assert_eq!(d.risk, RiskClass::Medium);
    }

    #[test]
    fn an_uncertain_outcome_is_not_a_success() {
        let u = CapabilityOutcome::uncertain();
        assert!(!u.effect_observed);
        assert!(u.value.is_none());
        let n = CapabilityOutcome::not_performed("no such file");
        assert!(!n.effect_observed);
        assert!(n.detail.is_some(), "a non-effect should say why");
        let o = CapabilityOutcome::observed(serde_json::json!({"ok": true}));
        assert!(o.effect_observed);
    }

    #[test]
    fn a_resolved_dispatch_never_hands_the_actor_to_an_adapter() {
        let mut r = CapabilityRegistry::empty();
        r.register(
            CapabilityDeclaration::new(cap("c"), "C")
                .with_data(DataClass::Public, DataClass::Public)
                .enabled(),
        )
        .expect("register");
        let d = Dispatcher::with_registry(r);
        let invocation = authorised("c", DataClass::Public);
        let resolved = d.resolve(&invocation).expect("resolve");
        assert!(!resolved.actor_reaches_adapter());
        // And the view itself carries no identity.
        let debug = format!("{:?}", resolved.view);
        assert!(
            !debug.contains("Human"),
            "the dispatch view leaked an actor: {debug}"
        );
    }

    proptest! {
        /// No enabled capability means every dispatch is refused, whatever the
        /// invocation claims. This is the Phase 1 invariant, stated as a
        /// quantifier so it holds for any input rather than the few tried here.
        #[test]
        fn with_nothing_enabled_nothing_dispatches(i: u8, class_idx: u8) {
            let classes = [
                DataClass::Public,
                DataClass::Personal,
                DataClass::Sensitive,
                DataClass::Regulated,
            ];
            let names = ["a", "b", "", "unknown/cap"];
            let name = names[(i % names.len() as u8) as usize];
            let class = classes[(class_idx % 4) as usize];
            let d = Dispatcher::new();
            prop_assert!(d.resolve(&authorised(name, class)).is_err());
        }

        /// A capability's effective class is never less than either side.
        #[test]
        fn effective_class_never_degrades(r: u8, w: u8) {
            let classes = [
                DataClass::Public,
                DataClass::Personal,
                DataClass::Sensitive,
                DataClass::Regulated,
            ];
            let reads = classes[(r % 4) as usize];
            let writes = classes[(w % 4) as usize];
            let d = CapabilityDeclaration::new(cap("c"), "C").with_data(reads, writes);
            let eff = d.effective_class();
            prop_assert!(eff >= reads);
            prop_assert!(eff >= writes);
        }
    }
}
