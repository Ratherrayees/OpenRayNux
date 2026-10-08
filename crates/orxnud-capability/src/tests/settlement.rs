//! Every authorisation reaches exactly one terminal record.
//!
//! # What this file is
//!
//! The invariant, asserted against the real dispatcher rather than described in a
//! comment. A controlled run of the assembled application found that a dispatch
//! refused by a capability's own parameter validation returned from `dispatch` before
//! the audit write at the end, leaving an `authorised` record with nothing closing it.
//! Nothing detected it: the detector that should have runs only in tests, and it pairs
//! records by a label that is the constant `ipc#0` for every dispatch over the local
//! socket, so even when it ran it resolved the two real orphans against two unrelated
//! completions and reported two innocent operations as unresolved instead.
//!
//! So the property is asserted here from three sides:
//!
//! * **Every exit settles.** Each refusal is provoked and the chain checked, rather than
//!   trusting that the refusal list and the settle list agree.
//! * **The disposition is the right one.** `Denied` asserts nothing ran; `Uncertain`
//!   declines to. Which one an exit gets decides whether a retry is safe.
//! * **The identity is exact.** Concurrent dispatches settle themselves, and no pairing
//!   is inferred from ordering or from a label.

use super::{Registry, support};

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::dispatch::{
    AdapterBundle, CapabilityAdapter, DispatchError, Dispatcher, ExecutionCertainty, ExecutionTier,
    PlanError, SandboxPlan,
};
use orxnud_audit::{AuditOutcome, OutcomeKind};
use orxnud_domain::approval::{ApprovalRecord, NormalizedParams};
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, RunId, TaskId, UserId};
use orxnud_domain::invocation::{ActionRequest, InvocationContext};
use orxnud_domain::{Actor, AuthChannel, SecretRef};
use orxnud_policy::budget::BudgetLedger;
use orxnud_policy::digest::digest_for;
use orxnud_policy::policy_set::{Grant, PolicySet};
use orxnud_policy::{CapabilityDeclaration, PolicyEngine};

use support::{
    Bundle, FailingAdapter, FakeSecrets, MisreportingAdapter, PanickingAdapter, SuccessfulAdapter,
};

const NOW: i64 = 1_767_225_600_000;
const CAP: &str = "test-capability";
/// The label every ad-hoc socket dispatch carries. Deliberately constant: it is the
/// situation that made label-based pairing unsound, and these tests must keep working
/// when every record looks identical to any pairing that reads labels.
const IPC_LABEL: &str = "ipc#0";

fn cap() -> CapabilityId {
    CapabilityId::new(CAP)
}

fn human() -> Actor {
    Actor::Human {
        user: UserId::new("u-1"),
        via: AuthChannel::LocalInteractive,
    }
}

/// A request whose context carries the constant socket label.
fn request() -> ActionRequest {
    ActionRequest::new(
        TaskId::new("ipc"),
        RunId::new("ipc"),
        0,
        cap(),
        orxnud_domain::json!({}),
        DataClass::Public,
        DataClass::Public,
    )
}

fn context() -> InvocationContext {
    InvocationContext::new("k-1", 30_000, IPC_LABEL)
}

fn params() -> NormalizedParams {
    NormalizedParams::canonical("{\"to\":\"alice\"}")
}

/// The declaration policy evaluates against: permits `Personal`.
///
/// It has to be *wider* than the implementations most fixtures declare. Policy's
/// data-class check is a stage-1-4 decision, so a declaration limited to `Public` would
/// deny a `Personal` request before the dispatcher ever runs, and the stage-5
/// `ClassEscalation` check — a second, independent enforcement of the same property one
/// layer down — would be unreachable. This is also the honest shape: policy governs what
/// a *request* may ask for, and the dispatcher governs what an *implementation* can
/// honour, and conflating them hides one of the two.
fn decl() -> CapabilityDeclaration {
    CapabilityDeclaration::new(cap(), RiskClass::Low, DataClass::Personal, false, 0)
}

/// A grant that permits `Personal`.
///
/// Deliberately wider than the `Public` declarations most fixtures use. Policy's own
/// data-class check runs in stage 1-4, so a grant limited to `Public` would deny a
/// `Personal` request there and the test would never reach the stage-5
/// `ClassEscalation` it means to exercise. Two different layers enforce data class, and
/// this is how one of them is got out of the way so the other can be observed.
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

/// A policy whose capability is `High` risk, so an approval is genuinely required.
///
/// Needed because `evaluate` only reads the presented approval when
/// `risk.requires_approval()` — on a `Low`-risk declaration an approval is passed
/// straight over. That is correct policy (a low-risk action needs no approval), but it
/// makes the burn-and-replay behaviour unobservable, because the digest is consumed
/// without ever having been examined. `High` is also the realistic case: the capability
/// that motivated this work is `filesystem/write-text`, declared `High`.
fn high_risk_policy() -> PolicyEngine {
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

fn policy() -> PolicyEngine {
    let mut e = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(grant()),
        BudgetLedger::empty().with_global(1_000),
        "v1",
    );
    e.register(decl());
    e
}

fn bundles<A: CapabilityAdapter + 'static>(b: Bundle<A>) -> Registry {
    let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
    let id = b.adapter().capability_id().clone();
    m.insert(id, b.into_arc());
    Registry::from_bundles(m)
}

fn dispatcher<'a>(
    engine: &'a mut PolicyEngine,
    secrets: &'a FakeSecrets,
    registry: Registry,
) -> Dispatcher<'a, FakeSecrets> {
    Dispatcher::new(engine, secrets, registry)
}

/// An approval over `p`, minted the way policy mints one.
///
/// Built through `digest_for` rather than hand-assembled, because the whole claim under
/// test is about a digest the ledger and the policy engine agree on. A hand-written
/// digest would not be in the ledger and the burn assertion would prove nothing.
fn approval_for(p: &NormalizedParams, now: i64) -> ApprovalRecord {
    ApprovalRecord {
        digest: digest_for(&human(), &human(), &cap(), None, p, now, now + 60_000, 0),
        approver: human(),
        actor_label: human().label().to_owned(),
        capability: cap().to_string(),
        target: String::new(),
        params: p.clone(),
        issued_at_ms: now,
        expires_at_ms: now + 60_000,
        risk: RiskClass::High,
        step_no: 0,
    }
}

// ------------------------------------------------------------------ assertions

/// The terminal record's disposition, and the detail it carries.
fn terminal(engine: &PolicyEngine) -> (OutcomeKind, Option<String>) {
    let entries = engine.audit().entries();
    let last = entries.last().expect("a terminal record must exist");
    match &last.outcome {
        AuditOutcome::Finished { kind, detail, .. } => (*kind, detail.clone()),
        AuditOutcome::Authorised { .. } => {
            panic!("the last record is an authorisation, not a terminal outcome")
        }
    }
}

/// Every authorisation in the chain is settled, by name.
fn assert_settled(engine: &PolicyEngine) {
    let report = engine.settlement_report();
    assert!(
        report.is_settled(),
        "every authorisation must be settled; unresolved={:?} dangling={:?}",
        report.unresolved_authorisations,
        report.dangling_settlements
    );
    assert!(
        engine.audit().verify().is_ok(),
        "the chain must still verify"
    );
}

fn assert_authorization_was_written(engine: &PolicyEngine) -> u64 {
    let entries = engine.audit().entries();
    assert!(
        entries
            .iter()
            .any(|r| matches!(r.outcome, AuditOutcome::Authorised { .. })),
        "the authorisation record must exist before the refusal is asserted: \
         otherwise this test proved nothing about settling"
    );
    entries[0].seq
}

/// The terminal record names exactly this authorisation, and only this one.
fn assert_settles_exactly(engine: &PolicyEngine, authorisation_seq: u64) {
    let entries = engine.audit().entries();
    let settling: Vec<_> = entries
        .iter()
        .filter_map(|r| r.settles_authorisation().map(|s| (r.seq, s)))
        .collect();
    assert_eq!(
        settling,
        vec![(authorisation_seq + 1, authorisation_seq)],
        "exactly one terminal record, naming exactly the authorisation it closes"
    );
}

// ------------------------------------------------- every refusal settles, as denied

/// A dispatch refused *after* authorisation must still leave a terminal record.
///
/// This is the regression for the finding. Each case is a distinct way `dispatch` used
/// to `return Err(..)` past the audit write.
#[test]
fn a_refusal_after_authorisation_still_records_a_disposition() {
    // 1. no implementation registered for a declared capability
    {
        let mut engine = policy();
        let secrets = FakeSecrets::new();
        let mut d = dispatcher(
            &mut engine,
            &secrets,
            Registry::from_bundles(BTreeMap::new()),
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
            .expect_err("no implementation must refuse");
        assert!(matches!(err, DispatchError::NoImplementation(_)), "{err}");
        let seq = assert_authorization_was_written(&engine);
        assert_settles_exactly(&engine, seq);
        assert_eq!(terminal(&engine).0, OutcomeKind::Denied, "nothing ran");
        assert_settled(&engine);
    }

    // 2. the implementation is disabled
    {
        let mut engine = policy();
        let secrets = FakeSecrets::new();
        let mut d = dispatcher(
            &mut engine,
            &secrets,
            bundles(Bundle::confirming(PublicTier0 {
                id: CapabilityId::new(CAP),
            })),
        );
        // Policy permits `Personal` (see `grant`), and the implementation declares only
        // `Public`, so the refusal lands in *stage 5* — the dispatcher's own
        // declaration-level check — rather than in policy.
        let over = ActionRequest::new(
            TaskId::new("ipc"),
            RunId::new("ipc"),
            0,
            cap(),
            orxnud_domain::json!({}),
            DataClass::Personal,
            DataClass::Personal,
        );
        let err = d
            .dispatch(over, human(), context(), None, params(), None, None, NOW)
            .expect_err("class escalation must refuse");
        assert!(
            matches!(err, DispatchError::ClassEscalation { .. }),
            "{err}"
        );
        let seq = assert_authorization_was_written(&engine);
        assert_settles_exactly(&engine, seq);
        assert_eq!(terminal(&engine).0, OutcomeKind::Denied, "nothing ran");
        assert_settled(&engine);
    }

    // 3. a required credential is not configured
    {
        let mut engine = policy();
        let secrets = FakeSecrets::failing();
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
                Some(&SecretRef::new("svc", "acct")),
                NOW,
            )
            .expect_err("an unresolvable credential must refuse");
        assert!(matches!(err, DispatchError::Credential(_)), "{err}");
        let seq = assert_authorization_was_written(&engine);
        assert_settles_exactly(&engine, seq);
        assert_eq!(terminal(&engine).0, OutcomeKind::Denied, "nothing ran");
        assert_settled(&engine);
    }
}

/// A Tier-1 capability whose parameters it rejects is `InvalidInput` and `Denied`.
///
/// The classification, end to end. This reached the caller as `sandbox-unavailable` —
/// "the execution backend cannot establish the required sandbox guarantees" — on a host
/// whose sandbox was working, because `Option<SandboxPlan>` could not say *why* there
/// was no plan.
#[test]
fn a_tier1_capability_rejecting_its_own_parameters_is_invalid_input_not_a_sandbox_outage() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(&mut engine, &secrets, rejecting_bundle(CAP))
        // A backend is present but never reached: the plan builder refuses first. It has
        // to be present at all, because "no execution backend is configured" is itself a
        // stage-7 refusal and would mask the classification under test.
        .with_execution(Arc::new(support::StubBackend));

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
        .expect_err("rejected parameters must refuse");

    match &err {
        DispatchError::InvalidInput { capability, detail } => {
            assert_eq!(*capability, cap());
            assert!(
                detail.contains("traversing"),
                "the capability's own reason must survive to the caller: {detail}"
            );
        }
        other => panic!("expected InvalidInput, got {other}"),
    }

    let seq = assert_authorization_was_written(&engine);
    assert_settles_exactly(&engine, seq);
    assert_eq!(
        terminal(&engine).0,
        OutcomeKind::Denied,
        "parameters rejected before anything ran is a refusal, not an unknown"
    );
    assert_settled(&engine);
}

/// The mirror case: a Tier-1 adapter that declares *no* plan is still an environment
/// fault, not the caller's fault.
///
/// The retype must not have swung too far. `PlanError::NoPlanDeclared` is a defect in
/// this build; reporting it as invalid parameters would send an operator to edit a
/// request that could never succeed.
#[test]
fn a_tier1_adapter_with_no_plan_is_still_reported_as_a_sandbox_refusal() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(&mut engine, &secrets, no_plan_bundle(CAP))
        .with_execution(Arc::new(support::StubBackend));

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
        .expect_err("a Tier-1 adapter with no plan must refuse");

    assert!(
        matches!(err, DispatchError::SandboxRefused(_)),
        "a build defect is an environment fault, not invalid input: {err}"
    );
    let seq = assert_authorization_was_written(&engine);
    assert_settles_exactly(&engine, seq);
    assert_eq!(terminal(&engine).0, OutcomeKind::Denied);
    assert_settled(&engine);
}

// ------------------------------------------------------------ uncertain is distinct

/// An execution that ran but was not verified is `Uncertain`, and still settles.
///
/// The distinction that matters for a retry: `Denied` says a repeat cannot duplicate
/// anything; `Uncertain` says it might.
#[test]
fn an_unverified_execution_is_uncertain_and_still_settles() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::unverifiable(MisreportingAdapter::new(CAP))),
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
    assert_eq!(
        terminal(&engine).0,
        OutcomeKind::Uncertain,
        "succeeded-but-unverified must never be recorded as completed"
    );
    assert_settled(&engine);
}

/// An execution that reported failure is `Failed`, and settles.
#[test]
fn a_failing_execution_is_failed_and_settles() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(FailingAdapter::new(CAP, "no"))),
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
    .expect("dispatch reports, not errors");
    assert_eq!(terminal(&engine).0, OutcomeKind::Failed);
    assert_settled(&engine);
}

/// A panicking adapter is settled as `Uncertain`, never as a clean refusal.
///
/// The adapter may have done work before unwinding, so the journal must decline to claim
/// nothing ran. `dispatch` returns an error either way; the *record* is what differs.
#[test]
fn a_panicking_adapter_settles_as_uncertain_rather_than_denied() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(PanickingAdapter::new(CAP))),
    );
    let _ = d.dispatch(
        request(),
        human(),
        context(),
        None,
        params(),
        None,
        None,
        NOW,
    );

    let (kind, _) = terminal(&engine);
    assert_eq!(
        kind,
        OutcomeKind::Uncertain,
        "a panic cannot establish that the capability did nothing"
    );
    assert_settled(&engine);
}

/// Verification that disproves the effect is `Failed`, and settles *before* the error
/// is returned.
#[test]
fn a_refuted_verification_settles_before_its_error_reaches_the_caller() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::refuting(SuccessfulAdapter::new(CAP))),
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
        .expect_err("a refuted effect must not be reported as success");
    assert!(
        matches!(err, DispatchError::VerificationRefuted { .. }),
        "{err}"
    );
    assert_settled(&engine);
}

// ------------------------------------------------------------------- approval burn

/// An approval is consumed when the action is later refused for bad parameters, and the
/// record says so.
///
/// The burn is deliberate and predates this work: policy consumes the digest *before* the
/// dispatcher reaches stage 5, because burning after execution would reopen the replay
/// window single-use exists to close. V-43 records the reservation model as the better
/// long-term answer. What was missing was the record saying it — the journal read
/// "an approval authorised a write that was then refused", which invites the inference
/// that the approval is still good for a retry. It is not.
#[test]
fn an_approval_is_spent_by_a_refusal_and_the_record_states_it() {
    let mut engine = high_risk_policy();
    let approval = approval_for(&params(), NOW);
    let secrets = FakeSecrets::new();

    // Scoped so the dispatcher — which borrows the engine — is dropped before the chain
    // is read. Two dispatches rather than one, because the second is what proves the
    // burn actually happened.
    {
        let mut d = dispatcher(&mut engine, &secrets, rejecting_bundle(CAP))
            .with_execution(Arc::new(support::StubBackend));
        let err = d
            .dispatch(
                request(),
                human(),
                context(),
                None,
                params(),
                Some(&approval),
                None,
                NOW,
            )
            .expect_err("rejected parameters must refuse");
        assert!(matches!(err, DispatchError::InvalidInput { .. }), "{err}");
    }

    // Read *this* refusal's record before anything else appends, because the second
    // dispatch below writes its own authorisation-and-denial pair and would otherwise be
    // the last record in the chain.
    let (_, detail) = terminal(&engine);
    let detail = detail.expect("the refusal must carry a detail line");
    assert!(
        detail.contains("spent"),
        "the record must state the approval economics: {detail}"
    );
    assert_settled(&engine);
    assert_eq!(
        engine.audit().len(),
        2,
        "the refusal wrote an authorisation and exactly one terminal record"
    );

    // Spent: a second presentation of the same digest is refused by the ledger. That
    // refusal is itself a complete, settled authorisation — policy writes both halves —
    // so the chain ends fully settled with four records, not three.
    {
        let mut d = dispatcher(&mut engine, &secrets, rejecting_bundle(CAP))
            .with_execution(Arc::new(support::StubBackend));
        let second = d.dispatch(
            request(),
            human(),
            context(),
            None,
            params(),
            Some(&approval),
            None,
            NOW,
        );
        assert!(
            second.is_err(),
            "an approval consumed by a refusal must not be reusable"
        );
    }
    assert_settled(&engine);
    assert_eq!(
        engine.audit().len(),
        4,
        "each dispatch wrote an authorisation and exactly one terminal record"
    );
}

// -------------------------------------------------------------------- concurrency

/// Concurrent dispatches settle themselves, with no pairing by order or by label.
///
/// Every request here carries the same task, step and request label, so a FIFO over a
/// label would have six interchangeable open authorisations and six interchangeable
/// completions. The identity is what keeps them apart.
#[test]
fn concurrent_dispatches_each_settle_their_own_authorisation() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );

    const N: usize = 6;
    for _ in 0..N {
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
    }

    assert_settled(&engine);
    assert_eq!(
        engine.audit().len(),
        N * 2,
        "each dispatch writes exactly one authorisation and one terminal record"
    );

    // Every authorisation is named by exactly one terminal record, and every terminal
    // record names an authorisation that exists. Checked as sets, because the point is
    // that the correspondence is total and one-to-one rather than merely balanced.
    let entries = engine.audit().entries();
    let authorisations: Vec<u64> = entries
        .iter()
        .filter(|r| matches!(r.outcome, AuditOutcome::Authorised { .. }))
        .map(|r| r.seq)
        .collect();
    let mut settled: Vec<u64> = entries
        .iter()
        .filter_map(|r| r.settles_authorisation())
        .collect();
    settled.sort_unstable();
    let mut expected = authorisations.clone();
    expected.sort_unstable();

    assert_eq!(
        settled, expected,
        "the settled set must equal the authorised set exactly"
    );
    assert!(engine.settlement_report().dangling_settlements.is_empty());
}

/// Identical requests, many of them, each settled exactly once.
///
/// The same evidence at a larger N and with no distinction at all between the requests —
/// the situation in which any label-based scheme is at its weakest.
#[test]
fn many_identical_requests_each_settle_exactly_once() {
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(
        &mut engine,
        &secrets,
        bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
    );

    const N: usize = 12;
    for _ in 0..N {
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
    }
    assert_settled(&engine);

    let entries = engine.audit().entries();
    let terminal_records: Vec<_> = entries
        .iter()
        .filter(|r| matches!(r.outcome, AuditOutcome::Finished { .. }))
        .collect();
    assert_eq!(terminal_records.len(), N);
    for t in terminal_records {
        assert!(
            t.settles_authorisation().is_some(),
            "no terminal record may lack an identity"
        );
    }
}

// --------------------------------------------------------------- fixtures

/// A Tier-0 adapter that declares only `Public`.
///
/// Exists so the stage-5 `ClassEscalation` check can be reached at all. Policy permits
/// `Personal` (see `grant` and `decl`), and the shared `SuccessfulAdapter` fixture
/// declares `Personal`, so with it the two layers agree and nothing escalates.
struct PublicTier0 {
    id: CapabilityId,
}

impl CapabilityAdapter for PublicTier0 {
    fn capability_id(&self) -> &CapabilityId {
        &self.id
    }

    fn declared_class(&self) -> DataClass {
        DataClass::Public
    }

    fn tier(&self) -> ExecutionTier {
        ExecutionTier::InProcess
    }

    fn invoke(
        &self,
        _view: &orxnud_policy::authority::DispatchView<'_>,
        _credential: Option<&crate::credential::CredentialHandle>,
    ) -> Result<crate::verification::ExecutionOutcome, String> {
        Ok(crate::verification::ExecutionOutcome::Succeeded {
            output: Some("ran".to_owned()),
        })
    }
}

/// A Tier-1 adapter that does nothing but answer identity and class.
///
/// Its `invoke` is unreachable: the dispatcher executes the contract built from the
/// bundle's plan instead, and never calls a Tier-1 adapter's `invoke`. Asserted with
/// `unreachable!` rather than returning something, so a test that reached it would
/// fail loudly instead of quietly measuring the wrong thing.
struct Tier1Adapter {
    id: CapabilityId,
}

impl CapabilityAdapter for Tier1Adapter {
    fn capability_id(&self) -> &CapabilityId {
        &self.id
    }

    fn declared_class(&self) -> DataClass {
        DataClass::Public
    }

    fn tier(&self) -> ExecutionTier {
        ExecutionTier::Subprocess
    }

    fn invoke(
        &self,
        _view: &orxnud_policy::authority::DispatchView<'_>,
        _credential: Option<&crate::credential::CredentialHandle>,
    ) -> Result<crate::verification::ExecutionOutcome, String> {
        unreachable!("a Tier-1 adapter's invoke is never called by the dispatcher")
    }
}

/// A bundle whose plan builder rejects the invocation's parameters.
///
/// Stands in for `write-text`/`read-text` handed a traversing or absolute path, without
/// needing a real sandbox to observe the *classification* — which is the thing under
/// test. Wraps `Bundle` so the adapter and its verifier are the standard fixtures, and
/// overrides only the plan.
struct RejectingParams {
    inner: Bundle<Tier1Adapter>,
}

impl RejectingParams {
    fn new(id: &str) -> Self {
        Self {
            inner: Bundle::confirming(Tier1Adapter {
                id: CapabilityId::new(id),
            }),
        }
    }
}

impl AdapterBundle for RejectingParams {
    fn adapter(&self) -> &dyn CapabilityAdapter {
        self.inner.adapter()
    }

    fn sandbox_plan(
        &self,
        _invocation: &orxnud_policy::authority::CapabilityInvocation,
    ) -> Result<Option<SandboxPlan>, PlanError> {
        // Shaped exactly like what `write_text::parse` returns for a traversing path.
        Err(PlanError::InvalidParams(
            "`path` must be relative to the workspace; a traversing path is refused".to_owned(),
        ))
    }

    fn verifier(&self) -> &dyn crate::verification::Verifier {
        self.inner.verifier()
    }
}

/// A Tier-1 bundle that yields a real plan, so the dispatcher reaches the backend.
///
/// The counterpart to `RejectingParams`. Needed by the tests that assert on what a
/// backend *did* rather than on what an adapter refused: a bundle that rejects its
/// parameters never gets as far as `execute`, so the backend's behaviour would be
/// unobservable.
///
/// The plan is never executed as a program — the test backends ignore the contract — so it
/// only has to be well-formed enough for the dispatcher to build a contract from it.
struct WithValidPlan {
    inner: Bundle<Tier1Adapter>,
}

impl WithValidPlan {
    fn new(id: &str) -> Self {
        Self {
            inner: Bundle::confirming(Tier1Adapter {
                id: CapabilityId::new(id),
            }),
        }
    }
}

impl AdapterBundle for WithValidPlan {
    fn adapter(&self) -> &dyn CapabilityAdapter {
        self.inner.adapter()
    }

    fn sandbox_plan(
        &self,
        _invocation: &orxnud_policy::authority::CapabilityInvocation,
    ) -> Result<Option<SandboxPlan>, PlanError> {
        Ok(Some(SandboxPlan {
            program: "/nonexistent/test-helper".to_owned(),
            args: Vec::new(),
            env: Default::default(),
            working_dir: std::env::temp_dir().display().to_string(),
            grant_rw: Vec::new(),
            grant_ro: vec!["/nonexistent/test-helper".to_owned()],
            network: false,
            deadline_ms: 30_000,
            output_cap_bytes: 64 * 1024,
            resources: crate::dispatch::ResourcePolicy::default(),
        }))
    }

    fn verifier(&self) -> &dyn crate::verification::Verifier {
        self.inner.verifier()
    }
}

/// A registry whose bundle produces a valid plan, so the backend is reached.
fn backend_reached_bundle(id: &str) -> Registry {
    let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
    m.insert(CapabilityId::new(id), Arc::new(WithValidPlan::new(id)));
    Registry::from_bundles(m)
}

/// A Tier-1 bundle that declares no plan at all: a defect in this build.
///
/// The trait's default `sandbox_plan` is `Ok(None)`, so this is the plain fixture with
/// no override — which is precisely the case the retyped signature must not confuse with
/// rejected parameters.
fn no_plan_bundle(id: &str) -> Registry {
    bundles(Bundle::confirming(Tier1Adapter {
        id: CapabilityId::new(id),
    }))
}

fn rejecting_bundle(id: &str) -> Registry {
    let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
    m.insert(CapabilityId::new(id), Arc::new(RejectingParams::new(id)));
    Registry::from_bundles(m)
}

// ------------------------------------------- a real side effect, and an unknown result

/// A capability that writes a real file, whose backend then fails to report.
///
/// # The defect this was written for
///
/// The system recorded a backend failure as *"nothing ran"*, which is the one statement
/// that re-opens a duplicate side effect: `recover()` treats a `not-performed` effect as
/// proof that a repeat cannot duplicate anything. The proof that this is wrong needs a
/// capability that genuinely produced an effect, because no fixture that only returns an
/// error says anything about the world.
///
/// So the capability writes a real file into an isolated scratch directory, and the
/// backend then reports nothing. Asserted here: the file exists, the refusal carries
/// `Unknown`, and the journal records `Uncertain` rather than a disproof.
#[test]
fn a_capability_whose_effect_happened_is_never_recorded_as_not_run() {
    let dir = std::env::temp_dir().join(format!(
        "orxnud-effect-then-unknown-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch");
    let written = dir.join("effect.txt");
    let _ = std::fs::remove_file(&written);

    let mut engine = high_risk_policy();
    let approval = approval_for(&params(), NOW);
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(&mut engine, &secrets, backend_reached_bundle(CAP)).with_execution(
        Arc::new(support::EffectThenUnknownBackend {
            path: written.clone(),
            contents: "the side effect landed",
        }),
    );

    let err = d
        .dispatch(
            request(),
            human(),
            context(),
            None,
            params(),
            Some(&approval),
            None,
            NOW,
        )
        .expect_err("the backend reported nothing, so this must be an error");

    // The world changed.
    assert!(
        written.exists(),
        "the simulated side effect must actually have happened"
    );
    assert_eq!(
        std::fs::read_to_string(&written).expect("read back"),
        "the side effect landed"
    );

    // And the refusal says so rather than claiming the opposite.
    match &err {
        DispatchError::SandboxRefused(r) => assert_eq!(
            r.certainty,
            ExecutionCertainty::Unknown,
            "a backend that already produced an effect cannot report NothingAttempted"
        ),
        other => panic!("expected SandboxRefused, got {other}"),
    }

    // The journal must decline to call it a disproof.
    let (kind, detail) = terminal(&engine);
    assert_eq!(
        kind,
        OutcomeKind::Uncertain,
        "the journal must not record a denial for an effect that landed; detail: {detail:?}"
    );
    assert_settled(&engine);

    let _ = std::fs::remove_dir_all(&dir);
}

/// The counterpart: a refusal that carries `NothingAttempted` leaves no file and is
/// recorded as a denial.
///
/// Without this, the test above would pass for a backend that simply never ran — the
/// distinction the whole `certainty` field exists to carry has to be observable, and the
/// only way to observe it is to look at what each backend did to the world.
#[test]
fn a_refusal_that_reports_nothing_attempted_leaves_no_effect_and_is_a_denial() {
    let dir = std::env::temp_dir().join(format!(
        "orxnud-refuse-before-effect-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch");
    let written = dir.join("must-not-exist.txt");
    let _ = std::fs::remove_file(&written);

    let mut engine = high_risk_policy();
    let approval = approval_for(&params(), NOW);
    let secrets = FakeSecrets::new();
    let mut d = dispatcher(&mut engine, &secrets, backend_reached_bundle(CAP)).with_execution(
        Arc::new(support::RefuseBeforeEffectBackend {
            path: written.clone(),
        }),
    );

    let err = d
        .dispatch(
            request(),
            human(),
            context(),
            None,
            params(),
            Some(&approval),
            None,
            NOW,
        )
        .expect_err("a backend refusal must be an error");

    match &err {
        DispatchError::SandboxRefused(r) => {
            assert_eq!(r.certainty, ExecutionCertainty::NothingAttempted)
        }
        other => panic!("expected SandboxRefused, got {other}"),
    }
    assert!(
        !written.exists(),
        "a backend that reports NothingAttempted must not have produced an effect"
    );
    assert_eq!(
        terminal(&engine).0,
        OutcomeKind::Denied,
        "nothing ran, so the journal may say so"
    );
    assert_settled(&engine);

    let _ = std::fs::remove_dir_all(&dir);
}

/// An unknown execution still consumes the approval, and the approval cannot be reused.
///
/// The burn happens in policy, before stage 5, so it happens regardless of what stage 7
/// reports. That is the fail-closed direction and it is unchanged by this work — but it is
/// asserted here *for the unknown case specifically*, because the unknown case is the one
/// where a retry is most tempting and the temptation is what would replay the approval.
#[test]
fn an_unknown_execution_spends_the_approval_and_the_approval_stays_spent() {
    let dir = std::env::temp_dir().join(format!(
        "orxnud-unknown-approval-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch");
    let written = dir.join("approved.txt");
    let _ = std::fs::remove_file(&written);

    let mut engine = high_risk_policy();
    let approval = approval_for(&params(), NOW);
    let secrets = FakeSecrets::new();

    {
        let mut d = dispatcher(&mut engine, &secrets, backend_reached_bundle(CAP)).with_execution(
            Arc::new(support::EffectThenUnknownBackend {
                path: written.clone(),
                contents: "approved side effect",
            }),
        );
        let _ = d.dispatch(
            request(),
            human(),
            context(),
            None,
            params(),
            Some(&approval),
            None,
            NOW,
        );
    }
    assert!(
        written.exists(),
        "the effect landed, so the approval authorised something that happened"
    );

    // The record must say the approval is gone, so an operator does not read the refusal
    // as "still good for a retry".
    let (_, detail) = terminal(&engine);
    let detail = detail.expect("the terminal record must carry a detail");
    assert!(
        detail.contains("spent"),
        "the record must state the approval economics: {detail}"
    );

    // And a second presentation of the same digest is refused by the ledger.
    {
        let mut d = dispatcher(&mut engine, &secrets, backend_reached_bundle(CAP)).with_execution(
            Arc::new(support::RefuseBeforeEffectBackend {
                path: written.clone(),
            }),
        );
        let second = d.dispatch(
            request(),
            human(),
            context(),
            None,
            params(),
            Some(&approval),
            None,
            NOW,
        );
        assert!(
            second.is_err(),
            "an approval spent by an unknown execution must not be reusable"
        );
    }
    assert_settled(&engine);

    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------- the production detector runs

/// The detector is asked at startup, on a real durable journal, and reports what the
/// previous process left behind.
///
/// This is the test for the requirement that detection is not test-only. Before this,
/// `unresolved_authorisations` was reachable only from `#[cfg(test)]`: the production
/// daemon never asked, so a journal containing an unsettled authorisation was
/// indistinguishable from a healthy one to anyone running the software.
///
/// # Why the orphan is written by hand
///
/// It cannot be produced through the dispatch path any more, and that is the fix
/// working: every exit now settles, so no sequence of dispatches can leave one behind.
/// The states this detector exists to catch are therefore unreachable from production
/// code *on purpose*, and can only be constructed directly — which is exactly what a
/// journal written by an older build, or by a process killed between the two audit
/// writes, looks like.
///
/// Written against a real SQLite journal and a real `restore`, because what is asserted
/// is that the check happens *on the load path* — before anything is served, describing
/// what the previous process left — not that a function returns the right answer when
/// asked nicely.
#[test]
fn restoring_a_journal_reports_what_the_previous_process_left_unsettled() {
    let dir = std::env::temp_dir().join(format!(
        "orxnud-settlement-restore-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch");
    let db = dir.join("state.db");

    {
        let mut engine = policy();
        let journal = orxnud_store::SqliteAuditJournal::open(&db).expect("open journal");
        engine.restore(&journal).expect("load");
        let mut engine = engine.with_security_state(
            Box::new(journal),
            Box::new(orxnud_store::SqliteApprovalLedger::open(&db).expect("ledger")),
        );

        // A healthy dispatch first, so the journal is not *entirely* unhealthy. A
        // detector that reported everything would pass the test above without this.
        let secrets = FakeSecrets::new();
        {
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
                None,
                NOW,
            )
            .expect("dispatch");
        }

        // Now the orphan: an authorisation with nothing closing it, exactly as a process
        // killed between the two audit writes would leave.
        engine
            .append_audit_record(orxnud_audit::AuditRecord::authorised(
                human(),
                cap().to_string(),
                None,
                DataClass::Personal,
                RiskClass::High,
                "v1",
                None,
                None,
                Some(TaskId::new("ipc")),
                Some(orxnud_domain::ids::RequestId::new(IPC_LABEL)),
                NOW,
            ))
            .expect("the orphan authorisation must persist");
    }

    // A fresh process. This is the production boundary: `restore` runs while the journal
    // loads and before anything is served.
    let mut restored = policy();
    let journal = orxnud_store::SqliteAuditJournal::open(&db).expect("open journal again");
    restored
        .restore(&journal)
        .expect("the journal must load and verify");

    let report = restored
        .restored_settlement()
        .expect("a restored engine must carry the load-time report")
        .clone();

    assert!(
        !report.is_settled(),
        "a journal carrying an unsettled authorisation must be reported unsettled: \
         {report:?}"
    );
    assert_eq!(
        report.unresolved_authorisations.len(),
        1,
        "exactly the orphan: {report:?}"
    );
    assert!(
        report.dangling_settlements.is_empty(),
        "nothing claims a settlement that does not exist: {report:?}"
    );

    // And the live report agrees with the load-time one, so a caller polling mid-process
    // is not told something different from what startup found.
    assert_eq!(
        restored.settlement_report().unresolved_authorisations,
        report.unresolved_authorisations
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A journal with nothing wrong reports settled.
///
/// The other direction, and the one that matters for trust: a check that always fires is
/// a check nobody reads. This asserts the negative so the positive cannot be satisfied by
/// a detector that reports everything.
#[test]
fn a_clean_journal_reports_settled_on_restore() {
    let dir = std::env::temp_dir().join(format!(
        "orxnud-settlement-clean-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch");
    let db = dir.join("state.db");

    {
        let mut engine = policy();
        let secrets = FakeSecrets::new();
        {
            let mut d = dispatcher(
                &mut engine,
                &secrets,
                bundles(Bundle::confirming(SuccessfulAdapter::new(CAP))),
            );
            for _ in 0..3 {
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
            }
        }
        let journal = orxnud_store::SqliteAuditJournal::open(&db).expect("open journal");
        engine.restore(&journal).expect("load");
        let _ = engine.with_security_state(
            Box::new(journal),
            Box::new(orxnud_store::SqliteApprovalLedger::open(&db).expect("ledger")),
        );
    }

    let mut restored = policy();
    let journal = orxnud_store::SqliteAuditJournal::open(&db).expect("open again");
    restored.restore(&journal).expect("load");
    let report = restored
        .restored_settlement()
        .expect("a restored engine carries the report");
    assert!(
        report.is_settled(),
        "a journal in which every dispatch settled must report settled: {report:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
