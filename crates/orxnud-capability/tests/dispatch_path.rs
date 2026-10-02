//! The governed dispatch path, end to end, against deterministic fixtures.
//!
//! No real external system is contacted. The claim under test is that the *stages*
//! run in order and that each refusal is fail-closed — not that any adapter works.

mod support;

use std::collections::BTreeMap;

use orxnud_capability::dispatch::{DispatchError, Dispatcher};
use orxnud_domain::approval::{ApprovalRecord, NormalizedParams};
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, RunId, TaskId, UserId};
use orxnud_domain::invocation::{ActionRequest, InvocationContext};
use orxnud_domain::{Actor, AuthChannel, RequestId, SecretRef};
use orxnud_policy::budget::BudgetLedger;
use orxnud_policy::digest::digest_for;
use orxnud_policy::policy_set::{Grant, PolicySet};
use orxnud_policy::{CapabilityDeclaration, PolicyEngine};

use support::{
    Bundle, FailingAdapter, FakeSecrets, MisreportingAdapter, MutatingAdapter, PanickingAdapter,
    SuccessfulAdapter, VerifyMode,
};

const NOW: i64 = 1_767_225_600_000;
const CAP: &str = "test-capability";

fn cap() -> CapabilityId {
    CapabilityId::new(CAP)
}

fn human() -> Actor {
    Actor::Human {
        user: UserId::new("u-1"),
        via: AuthChannel::LocalInteractive,
    }
}

fn params() -> NormalizedParams {
    NormalizedParams::canonical("{\"to\":\"alice\"}")
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

fn decl() -> CapabilityDeclaration {
    CapabilityDeclaration::new(cap(), RiskClass::Low, DataClass::Personal, false, 0)
}

fn grant() -> Grant {
    Grant {
        id: orxnud_domain::ids::GrantId::new("g-1"),
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
    e.register(decl());
    e
}

fn context() -> InvocationContext {
    InvocationContext::new("k-1", 30_000, "cancel-1")
}

fn secret_ref() -> SecretRef {
    SecretRef::new("test-service", "default")
}

/// Wraps a fixture bundle into the dispatcher's registry.
///
/// Generic over the concrete adapter because every fixture is a different type; the
/// `'static` bound is what lets it become an `Arc<dyn AdapterBundle + Send + Sync>`.
fn bundles<A: orxnud_capability::dispatch::CapabilityAdapter + 'static>(
    b: Bundle<A>,
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

fn dispatcher<'a>(
    engine: &'a mut PolicyEngine,
    secrets: &'a FakeSecrets,
    bundles: BTreeMap<
        CapabilityId,
        std::sync::Arc<dyn orxnud_capability::dispatch::AdapterBundle + Send + Sync>,
    >,
) -> Dispatcher<'a, FakeSecrets> {
    Dispatcher::new(engine, secrets, bundles)
}

// ------------------------------------------------------------------ happy path

#[test]
fn a_permitted_invocation_is_executed_and_verified() {
    let adapter = SuccessfulAdapter::new(CAP);
    let calls = adapter.calls.clone();
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(&mut engine, &secrets, bundles(Bundle::confirming(adapter)));

    let outcome = d
        .dispatch(
            request(),
            human(),
            context(),
            Some("alice".into()),
            params(),
            None,
            None,
            NOW,
        )
        .expect("dispatch");

    assert_eq!(outcome.capability, cap());
    assert!(
        outcome.is_verified(),
        "the fixture confirms, so verification passed"
    );
    assert!(!outcome.is_undetermined());
    assert_eq!(calls.count(), 1, "the adapter ran exactly once");
}

#[test]
fn the_audit_chain_records_the_authorisation_and_the_terminal_outcome() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );
    d.dispatch(
        request(),
        human(),
        context(),
        Some("alice".into()),
        params(),
        None,
        None,
        NOW,
    )
    .expect("dispatch");

    // Policy writes the authorisation record before the adapter is reached, so the
    // chain is non-empty and links the actor to the capability.
    let chain = engine.audit();
    assert_eq!(
        chain.len(),
        2,
        "a permitted dispatch writes an authorisation record and a terminal record"
    );
    assert!(chain.verify().is_ok(), "the hash chain must verify");
    let first = &chain.entries()[0];
    assert_eq!(first.capability, CAP);
    assert!(matches!(first.actor, Actor::Human { .. }));

    // The terminal record is written by stage 9, before the outcome is returned, and
    // it must resolve the authorisation. It previously was not written at all --
    // deferred to "the caller that owns the journal", which did not exist -- so a
    // completed action left the journal reporting its outcome as unknown.
    let terminal = &chain.entries()[1];
    assert!(
        matches!(
            terminal.outcome,
            orxnud_audit::AuditOutcome::Finished { .. }
        ),
        "the second record is the terminal outcome"
    );
    assert_eq!(
        terminal.correlation_key(),
        first.correlation_key(),
        "the terminal record must correlate with its authorisation, or the \
         unresolved-authorisation detector will report a finished action as unknown"
    );
    assert!(
        chain.unresolved_authorisations().is_empty(),
        "a completed dispatch leaves nothing unresolved"
    );
}

#[test]
fn an_unverified_success_is_recorded_as_uncertain_rather_than_completed() {
    // TP-12: an effect that was not confirmed must not be recorded as done. This is
    // the case a `Ok(outcome)` return value alone would get wrong.
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::unverifiable(SuccessfulAdapter::new(CAP))),
    );
    d.dispatch(
        request(),
        human(),
        context(),
        Some("alice".into()),
        params(),
        None,
        None,
        NOW,
    )
    .expect("dispatch returned an outcome");

    let chain = engine.audit();
    let terminal = &chain.entries()[1];
    let orxnud_audit::AuditOutcome::Finished { kind, .. } = &terminal.outcome else {
        panic!("expected a terminal record, got {:?}", terminal.outcome);
    };
    assert_eq!(
        *kind,
        orxnud_audit::OutcomeKind::Uncertain,
        "an adapter that reported success without confirmation must be recorded as \
         uncertain, never as completed"
    );
}

// ------------------------------------------------- stage 1: authority, first

#[test]
fn an_external_actor_is_refused_before_the_adapter_is_resolved() {
    // ADR-0027: External can request, never grant. Stage 1 must refuse before
    // anything else is examined — including capability resolution.
    let adapter = SuccessfulAdapter::new(CAP);
    let calls = adapter.calls.clone();
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(&mut engine, &secrets, bundles(Bundle::confirming(adapter)));

    let external = Actor::External {
        source: orxnud_domain::ExternalSource::Webhook {
            listener: "unconfigured-listener".into(),
        },
        request: orxnud_domain::RequestId::new("req-ext"),
    };
    let err = d
        .dispatch(
            request(),
            external,
            context(),
            None,
            params(),
            None,
            None,
            NOW,
        )
        .expect_err("an external actor must be refused");

    assert!(matches!(&err, DispatchError::Policy(_)), "{err}");
    assert_eq!(calls.count(), 0, "the adapter must not have run");
}

#[test]
fn an_ai_actor_cannot_elevate_its_delegating_humans_authority() {
    // I6: an AI actor's authority is exactly its human's, never more. The grant
    // below allows `Personal`; the AI actor asks for `Regulated` and is refused.
    let adapter = SuccessfulAdapter::new(CAP);
    let calls = adapter.calls.clone();
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(&mut engine, &secrets, bundles(Bundle::confirming(adapter)));

    let ai = Actor::Ai {
        delegated_by: UserId::new("u-1"),
        run: orxnud_domain::RunId::new("r-9"),
        task: TaskId::new("t-9"),
        provenance: orxnud_domain::ModelProvenance {
            model: "fixture".into(),
            revision: None,
            prompt_hash: "fixture-prompt".into(),
            request_id: orxnud_domain::RequestId::new("req-ai"),
        },
    };
    let mut req = request();
    req.input_class = DataClass::Regulated;
    req.output_class = DataClass::Regulated;

    let err = d
        .dispatch(req, ai, context(), None, params(), None, None, NOW)
        .expect_err("an AI actor must not exceed its delegation");
    assert!(matches!(&err, DispatchError::Policy(_)), "{err}");
    assert_eq!(calls.count(), 0);
}

#[test]
fn an_unknown_capability_is_refused() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );
    let mut req = request();
    req.capability = CapabilityId::new("never-registered");

    let err = d
        .dispatch(req, human(), context(), None, params(), None, None, NOW)
        .expect_err("an unknown capability must be refused");
    assert!(matches!(&err, DispatchError::Policy(_)), "{err}");
}

#[test]
fn a_capability_with_no_implementation_is_refused_at_stage_five() {
    // Policy knows the capability; nothing implements it. A different error from an
    // unknown capability, because the user's remedy differs.
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(&mut engine, &secrets, BTreeMap::new());

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
        .expect_err("no implementation must be refused");
    assert!(
        matches!(&err, DispatchError::NoImplementation(id) if id == &cap()),
        "{err}"
    );
}

// ---------------------------------------------- stage 3: approval, digest-bound

/// Builds a valid approval for `request()`, gated at High risk.
fn gated_policy() -> PolicyEngine {
    let mut e = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(grant()),
        BudgetLedger::empty().with_global(1_000),
        "v1",
    );
    e.register(CapabilityDeclaration::new(
        cap(),
        RiskClass::High,
        DataClass::Personal,
        false,
        0,
    ));
    e
}

fn approval_for(actor: &Actor, target: &str, p: &NormalizedParams, now: i64) -> ApprovalRecord {
    let digest = digest_for(actor, &cap(), Some(target), p, now, now + 60_000);
    ApprovalRecord {
        actor_label: actor.label().to_owned(),
        capability: cap().to_string(),
        target: target.to_owned(),
        params: p.clone(),
        issued_at_ms: now,
        expires_at_ms: now + 60_000,
        risk: RiskClass::High,
        digest,
    }
}

#[test]
fn an_approval_for_a_different_target_is_refused() {
    // Loopjacking (TH-05) in its simplest form: approve A, execute B.
    let mut engine = gated_policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );
    let approval = approval_for(&human(), "alice", &params(), NOW);

    let err = d
        .dispatch(
            request(),
            human(),
            context(),
            Some("bob".into()), // different target
            params(),
            Some(&approval),
            None,
            NOW,
        )
        .expect_err("an approval must not transfer to another target");
    assert!(matches!(&err, DispatchError::Policy(_)), "{err}");
}

#[test]
fn an_approval_for_different_params_is_refused() {
    let mut engine = gated_policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );
    let approval = approval_for(&human(), "alice", &params(), NOW);

    let err = d
        .dispatch(
            request(),
            human(),
            context(),
            Some("alice".into()),
            NormalizedParams::canonical("{\"to\":\"mallory\"}"),
            Some(&approval),
            None,
            NOW,
        )
        .expect_err("an approval must not transfer to different params");
    assert!(matches!(&err, DispatchError::Policy(_)), "{err}");
}

#[test]
fn an_approval_by_one_actor_does_not_authorise_another() {
    // I5: the digest includes the actor.
    let other = Actor::Human {
        user: UserId::new("u-2"),
        via: AuthChannel::LocalInteractive,
    };
    let mut engine = gated_policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );
    let approval = approval_for(&other, "alice", &params(), NOW);

    let err = d
        .dispatch(
            request(),
            human(),
            context(),
            Some("alice".into()),
            params(),
            Some(&approval),
            None,
            NOW,
        )
        .expect_err("another actor's approval must not apply");
    assert!(matches!(&err, DispatchError::Policy(_)), "{err}");
}

#[test]
fn an_expired_approval_is_refused() {
    let mut engine = gated_policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );
    let approval = approval_for(&human(), "alice", &params(), NOW);

    let err = d
        .dispatch(
            request(),
            human(),
            context(),
            Some("alice".into()),
            params(),
            Some(&approval),
            None,
            NOW + 120_000, // past expires_at_ms
        )
        .expect_err("an expired approval must be refused");
    assert!(matches!(&err, DispatchError::Policy(_)), "{err}");
}

#[test]
fn a_matching_approval_is_accepted() {
    let mut engine = gated_policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );
    let approval = approval_for(&human(), "alice", &params(), NOW);

    d.dispatch(
        request(),
        human(),
        context(),
        Some("alice".into()),
        params(),
        Some(&approval),
        None,
        NOW,
    )
    .expect("a matching approval must be accepted");
}

// ------------------------------------------------------- stage 4: budget first

#[test]
fn an_invocation_over_budget_is_refused_before_execution() {
    let adapter = SuccessfulAdapter::new(CAP);
    let calls = adapter.calls.clone();
    // Zero budget: every non-zero cost is refused.
    let mut engine = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(grant()),
        BudgetLedger::empty().with_global(0),
        "v1",
    );
    engine.register(CapabilityDeclaration::new(
        cap(),
        RiskClass::Low,
        DataClass::Personal,
        false,
        10, // costs 10
    ));
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(&mut engine, &secrets, bundles(Bundle::confirming(adapter)));

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
        .expect_err("over budget must be refused");
    assert!(matches!(&err, DispatchError::Policy(_)), "{err}");
    assert_eq!(
        calls.count(),
        0,
        "budget must be checked before the adapter runs"
    );
}

#[test]
fn repeated_dispatch_cannot_exceed_the_ceiling() {
    // A retry must not bypass the ceiling: the charge happens on every permit.
    let mut engine = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(grant()),
        BudgetLedger::empty().with_global(25),
        "v1",
    );
    engine.register(CapabilityDeclaration::new(
        cap(),
        RiskClass::Low,
        DataClass::Personal,
        false,
        10,
    ));
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );

    let mut permitted = 0;
    let mut refused = 0;
    for _ in 0..5 {
        match d.dispatch(
            request(),
            human(),
            context(),
            None,
            params(),
            None,
            None,
            NOW,
        ) {
            Ok(_) => permitted += 1,
            Err(DispatchError::Policy(_)) => refused += 1,
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert_eq!(permitted, 2, "25 units of budget, 10 per call");
    assert_eq!(refused, 3);
}

// ------------------------------------------- stage 6: credentials, as late as possible

#[test]
fn an_unauthorised_invocation_never_opens_the_secret_store() {
    // The ordering claim: credential resolution happens after every check that can
    // refuse. Proven by using a *failing* store — if stage 6 ran early, the error
    // would be Credential rather than Policy.
    let mut engine = policy();
    let secrets = FakeSecrets::failing();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );
    // Unauthorised at stages 1-2: no authority root, and an unregistered capability.
    // Both are decided by policy, before any adapter lookup or credential access.
    let external = Actor::External {
        source: orxnud_domain::ExternalSource::Unknown,
        request: RequestId::new("req-ext-2"),
    };
    let mut req = request();
    req.capability = CapabilityId::new("never-registered");

    let err = d
        .dispatch(
            req,
            external,
            context(),
            None,
            params(),
            None,
            Some(&secret_ref()),
            NOW,
        )
        .expect_err("an unauthorised invocation must be refused");
    assert!(
        matches!(&err, DispatchError::Policy(_)),
        "the store must not have been consulted; got {err}"
    );
}

#[test]
fn an_authorised_invocation_may_resolve_a_credential() {
    let adapter = SuccessfulAdapter::new(CAP);
    let saw = adapter.saw_credential.clone();
    let mut engine = policy();
    let secrets = FakeSecrets::new().with("test-service", "default", "s3cr3t");
    let mut d = dispatcher(&mut engine, &secrets, bundles(Bundle::confirming(adapter)));

    d.dispatch(
        request(),
        human(),
        context(),
        None,
        params(),
        None,
        Some(&secret_ref()),
        NOW,
    )
    .expect("dispatch");
    assert!(
        saw.load(std::sync::atomic::Ordering::SeqCst),
        "stage 6 must run before stage 7"
    );
}

#[test]
fn a_missing_credential_fails_the_dispatch_and_leaks_nothing() {
    let mut engine = policy();
    let secrets = FakeSecrets::new(); // nothing configured
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );

    let err = d
        .dispatch(
            request(),
            human(),
            context(),
            None,
            params(),
            None,
            Some(&secret_ref()),
            NOW,
        )
        .expect_err("an absent credential must fail the dispatch");
    assert!(matches!(&err, DispatchError::Credential(_)), "{err}");
    assert!(
        err.to_string().contains("test-service"),
        "the reference should be named"
    );
}

#[test]
fn an_audit_record_never_carries_the_credential_value() {
    const SECRET_VALUE: &str = "s3cr3t-value-must-not-appear";
    let mut engine = policy();
    let secrets = FakeSecrets::new().with("test-service", "default", SECRET_VALUE);
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );
    d.dispatch(
        request(),
        human(),
        context(),
        None,
        params(),
        None,
        Some(&secret_ref()),
        NOW,
    )
    .expect("dispatch");

    let chain = engine.audit();
    for record in chain.records() {
        let debug = format!("{record:?}");
        assert!(
            !debug.contains(SECRET_VALUE),
            "the credential leaked into an audit record: {debug}"
        );
    }
    assert!(chain.verify().is_ok());
}

// ---------------------------------------- stage 8: verification is not execution

#[test]
fn a_misreporting_adapter_is_not_treated_as_success() {
    // The central distinction of I8. The adapter returns Ok and claims the effect
    // happened; verification refutes it.
    let adapter = MisreportingAdapter::new(CAP);
    let calls = adapter.calls.clone();
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(&mut engine, &secrets, bundles(Bundle::refuting(adapter)));

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
        .expect_err("a refuted effect must not be reported as success");
    assert!(
        matches!(err, DispatchError::VerificationRefuted { .. }),
        "{err}"
    );
    assert_eq!(
        calls.count(),
        1,
        "the adapter did run; only the claim was wrong"
    );
}

#[test]
fn an_unverifiable_effect_is_reported_as_undetermined_not_success() {
    let adapter = SuccessfulAdapter::new(CAP);
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::unverifiable(adapter)),
    );

    // A verifier that errors yields Undetermined, which is *not* an error from
    // dispatch: the caller decides what "unverified" means for its task.
    let outcome = d
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
        .expect("an undetermined effect is a result, not a dispatch failure");
    assert!(
        outcome.is_undetermined(),
        "must not be reported as verified"
    );
    assert!(!outcome.is_verified());
}

#[test]
fn a_partial_effect_is_undetermined_and_invites_no_clean_retry() {
    let adapter = MutatingAdapter::new(CAP);
    let mutated = adapter.mutated.clone();
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::unverifiable(adapter)),
    );

    let outcome = d
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
        .expect("dispatch");
    assert!(
        mutated.load(std::sync::atomic::Ordering::SeqCst),
        "the effect partly occurred"
    );
    assert!(
        outcome.is_undetermined(),
        "a partial effect must be unknown, not a clean failure"
    );
}

// ------------------------------------------------------ failure isolation

#[test]
fn a_panicking_adapter_does_not_take_down_the_dispatcher() {
    let adapter = PanickingAdapter::new(CAP);
    let calls = adapter.calls.clone();
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::unverifiable(adapter)),
    );

    // The panic is caught. The dispatch still returns.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {})); // silence the expected panic output
    let outcome = d.dispatch(
        request(),
        human(),
        context(),
        None,
        params(),
        None,
        None,
        NOW,
    );
    std::panic::set_hook(previous);

    let outcome = outcome.expect("a panicking adapter must not fail the dispatch");
    assert_eq!(calls.count(), 1);
    assert!(
        outcome.is_undetermined(),
        "a panic means we do not know whether the effect happened"
    );
}

#[test]
fn the_dispatcher_is_usable_again_after_a_panicking_adapter() {
    // The reentrancy guard must be released even when the adapter panics, or one
    // faulty capability would wedge every later dispatch.
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let registry = bundles(Bundle::unverifiable(PanickingAdapter::new(CAP)));

    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let _ = {
        let mut d = dispatcher(&mut engine, &secrets, registry);
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
    };
    std::panic::set_hook(previous);

    // Now a good adapter under the same capability id. A *new* dispatcher, since the
    // registry is owned by the first one.
    let bundles = bundles(Bundle::confirming(SuccessfulAdapter::new(CAP)));
    let mut d = dispatcher(&mut engine, &secrets, bundles);
    let outcome = d
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
        .expect("the dispatcher must still work");
    assert!(outcome.is_verified());
    assert!(!d.is_executing(), "the guard must have been released");
}

#[test]
fn a_failing_adapter_is_reported_as_an_execution_failure_not_a_permission_failure() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(FailingAdapter::new(
            CAP,
            "the peer refused",
        ))),
    );

    let outcome = d
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
        .expect("an adapter failure is not a dispatch refusal");
    assert!(
        matches!(
            outcome.execution,
            orxnud_capability::verification::ExecutionOutcome::Failed { .. }
        ),
        "got {:?}",
        outcome.execution
    );
    assert!(
        outcome.is_undetermined(),
        "a failed run has nothing to verify"
    );
}

// ------------------------------------------------------ stage 5 class checks

#[test]
fn an_implementation_declaring_too_little_is_refused() {
    // Policy grants Personal; the *implementation* only handles Public. Dispatching
    // Personal to it would be an escalation the declaration hides.
    struct NarrowAdapter;
    impl orxnud_capability::dispatch::CapabilityAdapter for NarrowAdapter {
        fn capability_id(&self) -> &CapabilityId {
            // Leaked deliberately: a static id, so the test can build the key.
            static ID: std::sync::OnceLock<CapabilityId> = std::sync::OnceLock::new();
            ID.get_or_init(|| CapabilityId::new(CAP))
        }
        fn declared_class(&self) -> DataClass {
            DataClass::Public
        }
        fn invoke(
            &self,
            _v: &orxnud_domain::invocation::DispatchView<'_>,
            _c: Option<&orxnud_capability::credential::CredentialHandle>,
        ) -> Result<orxnud_capability::verification::ExecutionOutcome, String> {
            Ok(orxnud_capability::verification::ExecutionOutcome::Succeeded { output: None })
        }
    }

    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(NarrowAdapter)),
    );

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
        .expect_err("a class escalation must be refused");
    match err {
        DispatchError::ClassEscalation {
            declared, actual, ..
        } => {
            assert_eq!(declared, DataClass::Public);
            assert_eq!(actual, DataClass::Personal);
        }
        other => panic!("expected ClassEscalation, got {other}"),
    }
}

// ---------------------------------------------------- verification-mode fixture

#[test]
fn every_verify_mode_is_distinguishable() {
    // Guards the fixture itself: if `VerifyMode` collapsed, the tests above would
    // silently stop testing different things.
    let run = |mode| {
        let mut engine = policy();
        let secrets = FakeSecrets::new();
        let adapter = SuccessfulAdapter::new(CAP);
        let mut d = dispatcher(&mut engine, &secrets, bundles(Bundle::new(adapter, mode)));
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
    };
    assert!(run(VerifyMode::Confirms).expect("dispatch").is_verified());
    assert!(
        run(VerifyMode::Unavailable)
            .expect("dispatch")
            .is_undetermined()
    );
    assert!(matches!(
        run(VerifyMode::Refutes),
        Err(DispatchError::VerificationRefuted { .. })
    ));
}
