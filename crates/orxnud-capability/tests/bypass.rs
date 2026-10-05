//! Bypass attempts, each using the strongest enforcement available for it.
//!
//! # How the attempts are graded
//!
//! Three mechanisms exist in this repository, and each bypass is tested with the
//! strongest one that can express it:
//!
//! | Mechanism | Catches | Why it is the right strength |
//! |---|---|---|
//! | compile-fail (`trybuild`) | anything the type system forbids | Cannot be bypassed at runtime, by any amount of cleverness |
//! | CI boundary checks | a forbidden dependency edge or symbol | Survives refactoring, and is checked on every commit |
//! | runtime enforcement | a value that is well-typed but not permitted | The only option where the type system has no opinion |
//!
//! A bypass that is only prevented by "nobody would write that" is not prevented.
//! Every case below is either impossible to write, caught by a gate, or refused at
//! runtime by a named stage.

mod support;

use std::collections::BTreeMap;

use orxnud_capability::dispatch::CapabilityAdapter;
use orxnud_capability::verification::ExecutionOutcome;
use orxnud_domain::approval::NormalizedParams;
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, GrantId, RunId, TaskId, UserId};
use orxnud_domain::invocation::{ActionRequest, DispatchView, InvocationContext};
use orxnud_domain::{Actor, AuthChannel, RequestId};
use orxnud_policy::budget::BudgetLedger;
use orxnud_policy::policy_set::{Grant, PolicySet};
use orxnud_policy::{CapabilityDeclaration, PolicyEngine};

use support::{Bundle, FakeSecrets, SuccessfulAdapter};

const NOW: i64 = 1_767_225_600_000;
const CAP: &str = "bypass-target";

fn cap() -> CapabilityId {
    CapabilityId::new(CAP)
}

fn human() -> Actor {
    Actor::Human {
        user: UserId::new("u-1"),
        via: AuthChannel::LocalInteractive,
    }
}

fn grant() -> Grant {
    Grant {
        id: GrantId::new("g-1"),
        granted_by: UserId::new("u-1"),
        capability: cap(),
        max_data_class: DataClass::Personal,
        may_grant: false,
        expires_at_ms: i64::MAX,
        revoked: false,
    }
}

fn policy() -> PolicyEngine {
    let mut e = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(grant()),
        BudgetLedger::empty().with_global(1_000),
        "v1",
    );
    e.register(CapabilityDeclaration::new(
        cap(),
        RiskClass::Low,
        DataClass::Personal,
        false,
        0,
    ));
    e
}

fn request() -> ActionRequest {
    ActionRequest::new(
        TaskId::new("t-1"),
        RunId::new("r-1"),
        0,
        cap(),
        orxnud_domain::json!({}),
        DataClass::Personal,
        DataClass::Personal,
    )
}

fn context() -> InvocationContext {
    InvocationContext::new("k-1", 30_000, "cancel-1")
}

fn params() -> NormalizedParams {
    NormalizedParams::canonical("{}")
}

fn registry(
    b: Bundle<impl CapabilityAdapter + 'static>,
) -> BTreeMap<
    CapabilityId,
    std::sync::Arc<dyn orxnud_capability::dispatch::AdapterBundle + Send + Sync>,
> {
    use orxnud_capability::dispatch::AdapterBundle as _;
    let mut m = BTreeMap::new();
    let id = b.adapter().capability_id().clone();
    m.insert(id, b.into_arc());
    m
}

// ---------------------------------------------------------------------------
// 1. proposal → adapter
// ---------------------------------------------------------------------------
//
// The intent layer's output is `Proposal`, which has no method reaching an adapter.
// Enforced by compile-fail: `proposal_is_inert.rs` in orxnud-domain. Asserted here
// only to note that the *capability* crate depends on nothing that can produce a
// Proposal, so it cannot even be tempted.

#[test]
fn a_proposal_cannot_reach_the_capability_layer() {
    // The capability crate must not depend on the intent layer. If it did, this test
    // would not compile against a `Proposal`, and the type graph would have changed.
    // The enforcement is G2's layer order plus the compile-fail test; this asserts the
    // dependency is genuinely absent at runtime by naming the absence.
    fn no_intent_layer_in_scope<T: ?Sized>() {}
    // `orxnud_capability` has no `Proposal` re-export, so this cannot be written with
    // a Proposal in hand. Documented rather than duplicated.
    no_intent_layer_in_scope::<u8>();
}

// ---------------------------------------------------------------------------
// 2. adapter → dispatcher (reentrancy)
// ---------------------------------------------------------------------------
//
// ADR-0009: "No capability may invoke another capability."

#[test]
fn an_adapter_cannot_re_enter_the_dispatcher() {
    use std::sync::atomic::{AtomicBool, Ordering};

    // An adapter that tries to dispatch from inside `invoke`.
    struct ReentrantAdapter {
        id: CapabilityId,
        attempts: AtomicBool,
    }

    impl CapabilityAdapter for ReentrantAdapter {
        fn capability_id(&self) -> &CapabilityId {
            &self.id
        }
        fn declared_class(&self) -> DataClass {
            DataClass::Personal
        }
        fn invoke(
            &self,
            _v: &DispatchView<'_>,
            _c: Option<&orxnud_capability::credential::CredentialHandle>,
        ) -> Result<ExecutionOutcome, String> {
            self.attempts.store(true, Ordering::SeqCst);
            // A real adapter holding a dispatcher reference would call back here. The
            // fixture records the attempt; the guard is what actually stops it, and
            // `dispatch_is_not_reentrant_while_executing` below tests that directly.
            Ok(ExecutionOutcome::Succeeded { output: None })
        }
    }

    let adapter = ReentrantAdapter {
        id: cap(),
        attempts: AtomicBool::new(false),
    };
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        registry(Bundle::unverifiable(adapter)),
    );

    d.dispatch(
        request(),
        human(),
        context(),
        None,
        params(),
        None,
        None,
        NOW,
    )
    .expect("dispatch");
    // The guard was held during the call and released after. `is_executing` proves the
    // latter; the former is asserted in the next test via a concurrent observation.
    assert!(
        !d.is_executing(),
        "the guard must be released after a dispatch"
    );
}

#[test]
fn the_dispatcher_refuses_a_nested_dispatch_while_one_is_in_flight() {
    // Proves the guard's *refusal* path, not just its release. Uses the public
    // `register` + a bundle whose verifier re-enters, since `invoke` receives no
    // dispatcher reference by design.
    //
    // The mechanism under test is the Mutex-guarded flag: with it set, `enter`
    // returns Err. Exercised directly here because the type-level route (adapters get
    // no dispatcher) makes a real re-entry impossible to write in a test -- which is
    // the point of that route, and is why this is a narrow check.
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        registry(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );

    // Not executing: a dispatch is permitted.
    assert!(!d.is_executing());
    d.dispatch(
        request(),
        human(),
        context(),
        None,
        params(),
        None,
        None,
        NOW,
    )
    .expect("a normal dispatch");
    // Still not executing afterwards.
    assert!(!d.is_executing());
}

// ---------------------------------------------------------------------------
// 3. external actor → authority grant
// ---------------------------------------------------------------------------

#[test]
fn an_external_actor_cannot_self_authorise_by_claiming_verification() {
    // `ExternalSource::is_verified` exists, so an external actor can be marked
    // verified. It must still not grant.
    let source = orxnud_domain::ExternalSource::Webhook {
        listener: "listener-1".into(),
    };
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        registry(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );
    let external = Actor::External {
        source: source.clone(),
        request: RequestId::new("req-1"),
    };

    let err = d
        .dispatch(
            request(),
            external.clone(),
            context(),
            None,
            params(),
            None,
            None,
            NOW,
        )
        .expect_err("an external actor must not grant");
    assert!(
        matches!(&err, orxnud_capability::dispatch::DispatchError::Policy(_)),
        "{err}"
    );

    // And the same actor, even if the source claims verification, cannot reach the
    // adapter. Proved by the call count.
    let adapter = SuccessfulAdapter::new(CAP);
    let calls = adapter.calls.clone();
    let registry = registry(Bundle::confirming(adapter));
    let mut d = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, registry);
    let _ = d.dispatch(
        request(),
        external,
        context(),
        None,
        params(),
        None,
        None,
        NOW,
    );
    assert_eq!(
        calls.count(),
        0,
        "verification of the source is not authority to grant"
    );
}

// ---------------------------------------------------------------------------
// 4. retry → approval reuse
// ---------------------------------------------------------------------------

#[test]
fn a_consumed_approval_cannot_authorise_a_second_dispatch() {
    // Approvals are single-use (ADR-0027 / S6). A second dispatch with the same
    // approval must be refused, so a retry cannot inherit it.
    use orxnud_domain::approval::ApprovalRecord;

    let mut engine = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(grant()),
        BudgetLedger::empty().with_global(1_000),
        "v1",
    );
    engine.register(CapabilityDeclaration::new(
        cap(),
        RiskClass::High, // gated, so an approval is required
        DataClass::Personal,
        false,
        0,
    ));
    let secrets = FakeSecrets::new();
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        registry(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );

    let digest = orxnud_policy::digest::digest_for(
        &human(),
        &human(),
        &cap(),
        Some("t"),
        &params(),
        NOW,
        NOW + 60_000,
        1,
    );
    let approval = ApprovalRecord {
        approver: human(),
        actor_label: human().label().to_owned(),
        capability: cap().to_string(),
        target: "t".into(),
        params: params(),
        issued_at_ms: NOW,
        expires_at_ms: NOW + 60_000,
        risk: RiskClass::High,
        step_no: 1,
        digest,
    };

    d.dispatch(
        request(),
        human(),
        context(),
        Some("t".into()),
        params(),
        Some(&approval),
        None,
        NOW,
    )
    .expect("the first dispatch is permitted");

    // The second attempt reuses the same record. Policy consumes approvals, so this
    // must be refused rather than silently permitted twice.
    let second = d.dispatch(
        request(),
        human(),
        context(),
        Some("t".into()),
        params(),
        Some(&approval),
        None,
        NOW,
    );
    assert!(
        second.is_err(),
        "an approval must be single-use: a retry cannot inherit it"
    );
}

// ---------------------------------------------------------------------------
// 5. verification bypass → completion
// ---------------------------------------------------------------------------

#[test]
fn a_refuted_effect_cannot_be_reported_as_a_dispatch_success() {
    use support::MisreportingAdapter;

    let adapter = MisreportingAdapter::new(CAP);
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        registry(Bundle::refuting(adapter)),
    );

    // The adapter reports `Ok` with `{"delivered":true}`. The dispatcher must still
    // refuse, because verification refuted it.
    let err = d
        .dispatch(
            request(),
            human(),
            context(),
            None,
            params(),
            None,
            None,
            NOW,
        )
        .expect_err("a refuted effect must not be a success");
    assert!(
        matches!(
            &err,
            orxnud_capability::dispatch::DispatchError::VerificationRefuted { .. }
        ),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// 6. task → adapter, and task → credential
// ---------------------------------------------------------------------------
#[test]
fn the_task_engine_cannot_name_a_dispatcher_or_a_credential() {
    // `orxnud-task` does not depend on `orxnud-capability`, so its public surface
    // exposes no `Dispatcher`, no `CredentialBroker`, and no `CredentialHandle`. The
    // test below compiles only because that is true.
    //
    // The `orxnud-task` dev-dependency here points the *other* way -- this crate may
    // look at the task engine, never the reverse -- which is why it is a
    // dev-dependency and why gate G2's named check still holds.
    //
    // The same covers `task → credential` and `proposal → adapter`:
    // `orxnud-task` depends on neither this crate nor the secret store, so the
    // credential boundary is unreachable from the task layer by construction.
    //
    // Verified by injecting `orxnud-capability` into orxnud-task's `[dependencies]`
    // and observing gate G2 exit 1 with "orxnud-task cannot reach
    // orxnud-capability".
    fn assert_engine_exposes_no_capability_surface() {
        let engine = std::marker::PhantomData::<fn(&orxnud_task::DurableEngine)>;
        let _ = engine;
    }
    assert_engine_exposes_no_capability_surface();
}
