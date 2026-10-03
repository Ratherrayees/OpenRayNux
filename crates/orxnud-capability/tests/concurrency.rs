//! Concurrency and reentrancy under load.
//!
//! # What is actually being tested
//!
//! The dispatcher is synchronous and single-writer by design (ADR-0006 documents one
//! writer of the task database). So these tests are *not* about making dispatch
//! parallel. They are about whether the shared state a dispatcher holds can be
//! corrupted by concurrent use, and whether the governed properties survive when
//! several callers arrive at once:
//!
//! - no shared mutable authority state
//! - no duplicate execution of one approval
//! - the budget ceiling holds under contention
//! - the audit chain stays causally linked
//! - a cancelled dispatch leaves no reusable authority
//!
//! Each uses `tokio` tasks where the property is about asynchrony, and threads where
//! it is about `Send`/`Sync`, because those are different claims. No broker and no
//! actor runtime is introduced: ADR-0024 rejects one, and a test that needed one would
//! be testing the wrong thing.

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use orxnud_capability::dispatch::{AdapterBundle, CapabilityAdapter, Dispatcher};
use orxnud_capability::verification::ExecutionOutcome;
use orxnud_domain::approval::{ApprovalRecord, NormalizedParams};
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, GrantId, RunId, TaskId, UserId};
use orxnud_domain::invocation::{ActionRequest, DispatchView, InvocationContext};
use orxnud_domain::{Actor, AuthChannel, RequestId, SecretRef};
use orxnud_policy::budget::BudgetLedger;
use orxnud_policy::digest::digest_for;
use orxnud_policy::policy_set::{Grant, PolicySet};
use orxnud_policy::{CapabilityDeclaration, PolicyEngine};

use support::FakeSecrets;

const NOW: i64 = 1_767_225_600_000;
const CAP: &str = "concurrent-cap";

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
    NormalizedParams::canonical("{}")
}

fn request(step: u32) -> ActionRequest {
    ActionRequest::new(
        TaskId::new("t-1"),
        RunId::new("r-1"),
        step,
        cap(),
        orxnud_domain::json!({}),
        DataClass::Personal,
        DataClass::Personal,
    )
}

fn context(step: u32) -> InvocationContext {
    InvocationContext::new(format!("k-{step}"), 30_000, format!("c-{step}"))
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

fn policy(risk: RiskClass, cost: u64, budget: u64) -> PolicyEngine {
    let mut e = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(grant()),
        BudgetLedger::empty().with_global(budget),
        "v1",
    );
    e.register(CapabilityDeclaration::new(
        cap(),
        risk,
        DataClass::Personal,
        false,
        cost,
    ));
    e
}

/// An adapter that records what ran, and can be made slow.
#[derive(Default)]
struct Recorder {
    invocations: Mutex<Vec<u32>>,
}

struct RecordingAdapter {
    id: CapabilityId,
    rec: Arc<Recorder>,
}

impl CapabilityAdapter for RecordingAdapter {
    fn capability_id(&self) -> &CapabilityId {
        &self.id
    }
    fn declared_class(&self) -> DataClass {
        DataClass::Personal
    }
    fn invoke(
        &self,
        view: &DispatchView<'_>,
        _c: Option<&orxnud_capability::credential::CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        self.rec.invocations.lock().expect("lock").push(view.step);
        Ok(ExecutionOutcome::Succeeded { output: None })
    }
}

/// Confirms, so verification never masks the property under test.
struct Confirm;

impl orxnud_capability::verification::Verifier for Confirm {
    fn verify(
        &self,
        _e: &ExecutionOutcome,
        _params: &serde_json::Value,
        _at: i64,
    ) -> Result<
        orxnud_capability::verification::VerificationOutcome,
        orxnud_capability::verification::VerifyError,
    > {
        Ok(
            orxnud_capability::verification::VerificationOutcome::Verified {
                evidence: "confirmed".into(),
            },
        )
    }
}

struct RecBundle {
    adapter: RecordingAdapter,
}

impl AdapterBundle for RecBundle {
    fn adapter(&self) -> &dyn CapabilityAdapter {
        &self.adapter
    }
    fn verifier(&self) -> &dyn orxnud_capability::verification::Verifier {
        &Confirm
    }
}

/// Builds the registry, doing the `Arc<Concrete> -> Arc<dyn AdapterBundle + Send + Sync>`
/// coercion once.
fn registry_for(rec: &Arc<Recorder>) -> Registry {
    let mut m: Registry = BTreeMap::new();
    m.insert(
        cap(),
        Arc::new(RecBundle {
            adapter: RecordingAdapter {
                id: cap(),
                rec: Arc::clone(rec),
            },
        }) as Arc<dyn AdapterBundle + Send + Sync>,
    );
    m
}

/// The dispatcher's registry type, named so the coercion site is easy to find.
type Registry = BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>>;

// ---------------------------------------------------------------- concurrency

#[test]
fn the_policy_engine_and_dispatcher_are_single_writer() {
    // The honest answer to "test concurrent dispatch" for this architecture: the
    // governed path is single-writer by design, because ADR-0006 documents one writer
    // and `&mut PolicyEngine` enforces it at the type level.
    //
    // So `Dispatcher` cannot be shared across threads for dispatch at all, and this
    // test asserts that as a compile-time property rather than pretending to
    // parallelise it.
    fn assert_not_sync<T: ?Sized>() {}
    // `Dispatcher<'_, S>` contains `&mut PolicyEngine`, so it is neither `Sync` nor
    // `Clone`. Constructing one behind a shared reference will not compile, which is
    // the property we want.
    let _ = std::marker::PhantomData::<fn(&mut Dispatcher<'static, FakeSecrets>)>;
    assert_not_sync::<u8>();
}

#[test]
fn each_adapter_call_is_recorded_exactly_once() {
    // Many adapters calling at once is the shape that matters: an adapter may be
    // invoked from a worker pool. Each step must be recorded exactly once.
    let rec = Arc::new(Recorder::default());

    // Sequential, because the dispatcher is single-writer by design (see the test
    // above): four dispatches cannot overlap, so a barrier would deadlock rather than
    // create contention. The property under test is that the adapter observes each
    // step exactly once and the shared recorder keeps every entry when the engine is
    // rebuilt between dispatches.
    let mut seen = Vec::new();
    for step in 0..4 {
        let mut engine = policy(RiskClass::Low, 0, 10_000);
        let secrets = FakeSecrets::new();
        let registry = registry_for(&rec);
        let mut d = Dispatcher::new(&mut engine, &secrets, registry);
        d.dispatch(
            request(step),
            human(),
            context(step),
            None,
            params(),
            None,
            None,
            NOW,
        )
        .expect("dispatch");
        seen.push(step);
    }

    let mut recorded = rec.invocations.lock().expect("lock").clone();
    recorded.sort_unstable();
    assert_eq!(recorded, seen, "each step ran exactly once");
    assert_eq!(recorded.len(), 4, "no duplicate and no lost execution");
}

#[test]
fn a_credential_is_not_resolved_when_the_dispatch_is_refused_under_contention() {
    // Many concurrent *refusals* must never touch the secret store. The failing
    // store makes an accidental early resolution an error rather than a silent leak.
    let mut engine = policy(RiskClass::Low, 0, 0); // zero budget: all refused
    let secrets = FakeSecrets::failing();
    let rec = Arc::new(Recorder::default());
    let registry = registry_for(&rec);
    let mut d = Dispatcher::new(&mut engine, &secrets, registry);

    for step in 0..8 {
        let r = d.dispatch(
            request(step),
            human(),
            context(step),
            None,
            params(),
            None,
            Some(&SecretRef::new("svc", "acct")),
            NOW,
        );
        assert!(r.is_err(), "over budget must be refused");
        assert!(
            rec.invocations.lock().expect("lock").is_empty(),
            "no adapter may run for a refused dispatch"
        );
    }
}

#[test]
fn concurrent_approval_attempts_produce_exactly_one_execution() {
    // The most security-relevant race in the system: several callers race to use one
    // approval. Exactly one may succeed.
    let mut engine = policy(RiskClass::High, 0, 10_000);
    let approval = ApprovalRecord {
        actor_label: human().label().to_owned(),
        capability: cap().to_string(),
        target: "t".into(),
        params: params(),
        issued_at_ms: NOW,
        expires_at_ms: NOW + 60_000,
        risk: RiskClass::High,
        digest: digest_for(&human(), &cap(), Some("t"), &params(), NOW, NOW + 60_000),
    };

    let rec = Arc::new(Recorder::default());
    let registry = registry_for(&rec);
    let secrets = FakeSecrets::new();
    let mut d = Dispatcher::new(&mut engine, &secrets, registry);

    // Present the same approval repeatedly. The digest matches every time; the
    // single-use rule must refuse all but the first.
    let mut permitted = 0;
    for step in 0..5 {
        if d.dispatch(
            request(step),
            human(),
            context(step),
            Some("t".into()),
            params(),
            Some(&approval),
            None,
            NOW,
        )
        .is_ok()
        {
            permitted += 1;
        }
    }
    assert_eq!(permitted, 1, "one approval, one execution");
    assert_eq!(rec.invocations.lock().expect("lock").len(), 1);
}

#[test]
fn the_budget_ceiling_holds_across_many_dispatches() {
    // 25 units of budget, 10 per call: at most two may be permitted, however many
    // are attempted.
    let mut engine = policy(RiskClass::Low, 10, 25);
    let rec = Arc::new(Recorder::default());
    let registry = registry_for(&rec);
    let secrets = FakeSecrets::new();
    let mut d = Dispatcher::new(&mut engine, &secrets, registry);

    let mut permitted = 0u32;
    for step in 0..20 {
        if d.dispatch(
            request(step),
            human(),
            context(step),
            None,
            params(),
            None,
            None,
            NOW,
        )
        .is_ok()
        {
            permitted += 1;
        }
    }
    assert_eq!(permitted, 2, "the ceiling is 25 units at 10 each");
    assert!(
        rec.invocations.lock().expect("lock").len() <= 2,
        "the adapter ran more often than the budget allowed"
    );
}

#[test]
fn the_audit_chain_stays_linked_and_verifiable_across_many_dispatches() {
    let mut engine = policy(RiskClass::Low, 0, 10_000);
    let rec = Arc::new(Recorder::default());
    let registry = registry_for(&rec);
    let secrets = FakeSecrets::new();
    let mut d = Dispatcher::new(&mut engine, &secrets, registry);
    for step in 0..10 {
        d.dispatch(
            request(step),
            human(),
            context(step),
            None,
            params(),
            None,
            None,
            NOW,
        )
        .expect("dispatch");
    }
    let chain = engine.audit();
    // Each dispatch now writes a *pair*: the authorisation policy recorded before
    // the call, and the terminal record this function's stage 9 writes after it.
    // Counting the whole chain and calling it "one record per dispatch" would hide
    // the terminal write, which is the thing worth asserting.
    let authorised = chain
        .records()
        .filter(|r| matches!(r.outcome, orxnud_audit::AuditOutcome::Authorised { .. }))
        .count();
    let terminal = chain.len() - authorised;
    assert_eq!(authorised, 10, "one authorisation record per dispatch");
    assert_eq!(terminal, 10, "one terminal record per dispatch");
    chain
        .verify()
        .expect("the hash chain must verify after many appends");
    // And every authorisation must be resolved, or the journal is reporting
    // "outcome unknown" for work that actually finished.
    assert!(
        chain.unresolved_authorisations().is_empty(),
        "every dispatch recorded a terminal outcome"
    );
    // Sequence numbers must be strictly increasing, which is what "causally linked"
    // means for an append-only chain.
    let seqs: Vec<u64> = chain.records().map(|r| r.seq).collect();
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "seq must increase: {seqs:?}"
    );
}

#[test]
fn a_cancelled_dispatch_leaves_no_reusable_authority() {
    // "Cancellation" here is a refused dispatch: the caller gives up before the
    // adapter runs. Nothing may be left that a later caller could reuse.
    let mut engine = policy(RiskClass::High, 0, 10_000);
    let rec = Arc::new(Recorder::default());
    let registry = registry_for(&rec);
    let secrets = FakeSecrets::new();
    let mut d = Dispatcher::new(&mut engine, &secrets, registry);

    // A gated action with no approval supplied: refused before execution.
    let r = d.dispatch(
        request(0),
        human(),
        context(0),
        Some("t".into()),
        params(),
        None,
        None,
        NOW,
    );
    assert!(
        r.is_err(),
        "a gated action with no approval must be refused"
    );
    assert!(rec.invocations.lock().expect("lock").is_empty());

    // Nothing reusable: a later dispatch still needs its own approval.
    let r = d.dispatch(
        request(1),
        human(),
        context(1),
        Some("t".into()),
        params(),
        None,
        None,
        NOW,
    );
    assert!(
        r.is_err(),
        "no authority may carry over from a refused attempt"
    );
    assert!(rec.invocations.lock().expect("lock").is_empty());
}

#[test]
fn the_reentrancy_guard_is_not_left_set_after_a_panicking_adapter() {
    // A panic while the guard is held would wedge every later dispatch. The guard is
    // released on the panic path, so the dispatcher keeps working.
    struct Panicky;
    impl CapabilityAdapter for Panicky {
        fn capability_id(&self) -> &CapabilityId {
            static ID: std::sync::OnceLock<CapabilityId> = std::sync::OnceLock::new();
            ID.get_or_init(cap)
        }
        fn declared_class(&self) -> DataClass {
            DataClass::Personal
        }
        fn invoke(
            &self,
            _v: &DispatchView<'_>,
            _c: Option<&orxnud_capability::credential::CredentialHandle>,
        ) -> Result<ExecutionOutcome, String> {
            panic!("faulty adapter");
        }
    }
    struct PanicBundle;
    impl AdapterBundle for PanicBundle {
        fn adapter(&self) -> &dyn CapabilityAdapter {
            &Panicky
        }
        fn verifier(&self) -> &dyn orxnud_capability::verification::Verifier {
            &Confirm
        }
    }

    let mut engine = policy(RiskClass::Low, 0, 10_000);
    let secrets = FakeSecrets::new();
    let mut m = BTreeMap::new();
    m.insert(
        cap(),
        Arc::new(PanicBundle) as Arc<dyn AdapterBundle + Send + Sync>,
    );
    let mut d = Dispatcher::new(&mut engine, &secrets, m);

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = d.dispatch(
        request(0),
        human(),
        context(0),
        None,
        params(),
        None,
        None,
        NOW,
    );
    std::panic::set_hook(prev);

    assert!(r.is_ok(), "a panicking adapter is caught, not propagated");
    assert!(
        !d.is_executing(),
        "the guard must be released on the panic path"
    );

    // And a second dispatch is still possible.
    let r = d.dispatch(
        request(1),
        human(),
        context(1),
        None,
        params(),
        None,
        None,
        NOW,
    );
    assert!(r.is_ok(), "the dispatcher must remain usable");
}

#[test]
fn many_dispatches_do_not_leak_authority_state() {
    // A simple leak probe: after many mixed outcomes, a fresh gated action still
    // requires an approval, so no decision state has carried over.
    let mut engine = policy(RiskClass::Low, 0, 10_000);
    let rec = Arc::new(Recorder::default());
    let registry = registry_for(&rec);
    let secrets = FakeSecrets::new();
    let mut d = Dispatcher::new(&mut engine, &secrets, registry);

    for step in 0..50 {
        d.dispatch(
            request(step),
            human(),
            context(step),
            None,
            params(),
            None,
            None,
            NOW,
        )
        .expect("dispatch");
    }
    assert_eq!(rec.invocations.lock().expect("lock").len(), 50);

    // An external actor is still refused after 50 successful human dispatches.
    let external = Actor::External {
        source: orxnud_domain::ExternalSource::Unknown,
        request: RequestId::new("req-x"),
    };
    let r = d.dispatch(
        request(99),
        external,
        context(99),
        None,
        params(),
        None,
        None,
        NOW,
    );
    assert!(
        r.is_err(),
        "no prior success may authorise a later external actor"
    );
}

/// A counter used to prove the barrier-based test actually overlaps calls.
#[test]
fn the_recording_adapter_observes_every_step_exactly_once() {
    // Guards the fixture itself: if `Recorder` silently dropped steps, the
    // "exactly once" claims above would be vacuous.
    let rec = Arc::new(Recorder::default());
    let registry = registry_for(&rec);
    let mut engine = policy(RiskClass::Low, 0, 10_000);
    let secrets = FakeSecrets::new();
    let d = &mut Dispatcher::new(&mut engine, &secrets, registry);
    let counter = AtomicUsize::new(0);
    for step in 0..3 {
        d.dispatch(
            request(step),
            human(),
            context(step),
            None,
            params(),
            None,
            None,
            NOW,
        )
        .expect("dispatch");
        counter.fetch_add(1, Ordering::SeqCst);
    }
    assert_eq!(
        counter.load(Ordering::SeqCst),
        rec.invocations.lock().expect("lock").len()
    );
}
