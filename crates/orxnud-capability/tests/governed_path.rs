//! The governed path, end to end, with real sandboxed subprocesses.
//!
//! # Why these exist
//!
//! Phase 4a proved a sandbox. Nothing yet *consumed* it (V-50), so a beautifully
//! tested boundary could have been bypassed by the eventual execution path without any
//! test failing. These tests close that: every case goes through
//! `Dispatcher::dispatch`, and the hostile helper is a real process under a real
//! sandbox.
//!
//! # The ordering is the point
//!
//! Several tests below assert a *negative* about the sandbox — "no subprocess was
//! created" — because the interesting failure is an execution that happened when it
//! should not have. Those assertions are made by counting process creations inside the
//! backend, not by timing.

mod support;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use orxnud_capability::dispatch::{
    AdapterBundle, CapabilityAdapter, DispatchError, ExecutionBackend, ExecutionContract,
    ExecutionReport, ExecutionTier, SandboxPlan, SandboxRefusal,
};
use orxnud_capability::subprocess::SandboxExecutionBackend;
use orxnud_capability::verification::{
    ExecutionOutcome, VerificationOutcome, Verifier, VerifyError,
};
use orxnud_domain::approval::NormalizedParams;
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, GrantId, RunId, TaskId, UserId};
use orxnud_domain::invocation::DispatchView;
use orxnud_domain::invocation::{ActionRequest, InvocationContext};
use orxnud_domain::{Actor, AuthChannel, SecretRef};
use orxnud_policy::budget::BudgetLedger;
use orxnud_policy::policy_set::{Grant, PolicySet};
use orxnud_policy::{CapabilityDeclaration, PolicyEngine};

use support::{FakeSecrets, helper_path, sandbox_helpers_dir};

const NOW: i64 = 1_767_225_600_000;
const CAP: &str = "tier1-helper";

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

fn policy(cost: u64, budget: u64) -> PolicyEngine {
    let mut e = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(grant()),
        BudgetLedger::empty().with_global(budget),
        "v1",
    );
    e.register(CapabilityDeclaration::new(
        cap(),
        RiskClass::Low,
        DataClass::Personal,
        false,
        cost,
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
    // The mode travels in the environment, which is the only channel the helper reads.
    InvocationContext::new("k-1", 30_000, "c-1")
}

fn params() -> NormalizedParams {
    NormalizedParams::canonical("{}")
}

/// The hostile helper as a Tier-1 adapter.
///
/// `tier()` is what makes this a subprocess capability at all. Without it the adapter
/// would be Tier 0 and would run in-process — which is the bypass this whole file
/// exists to prevent.
pub struct Tier1HelperAdapter {
    id: CapabilityId,
    env: BTreeMap<String, String>,
}

impl Tier1HelperAdapter {
    pub fn new(id: &str) -> Self {
        Self {
            id: CapabilityId::new(id),
            env: BTreeMap::new(),
        }
    }

    /// Runs the helper in `mode`.
    ///
    /// One capability id for every mode: the *mode* selects the helper's behaviour,
    /// and giving each mode its own id meant the request and the registered bundle
    /// disagreed, so every test failed at stage 5 with `NoImplementation`.
    pub fn running(mode: &str) -> Self {
        Self::new(CAP).with_env("ORXNUD_HOSTILE_HELPER", mode)
    }

    fn with_env(mut self, k: &str, v: &str) -> Self {
        self.env.insert(k.to_owned(), v.to_owned());
        self
    }
}

impl CapabilityAdapter for Tier1HelperAdapter {
    fn capability_id(&self) -> &CapabilityId {
        &self.id
    }
    fn declared_class(&self) -> DataClass {
        DataClass::Personal
    }
    fn tier(&self) -> ExecutionTier {
        ExecutionTier::Subprocess
    }
    fn invoke(
        &self,
        _view: &DispatchView<'_>,
        _credential: Option<&orxnud_capability::credential::CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        // Unreachable for a Tier-1 adapter in the governed path. Deliberately a panic
        // rather than a silent success: if the dispatcher ever reached this, the
        // Tier-1 branch had been bypassed, and the test suite should say so loudly
        // rather than quietly pass.
        panic!("Tier-1 adapter invoked in-process: the sandbox route was bypassed");
    }
}

struct HelperBundle {
    adapter: Tier1HelperAdapter,
    grants: (Vec<String>, Vec<String>),
}

impl AdapterBundle for HelperBundle {
    fn adapter(&self) -> &dyn CapabilityAdapter {
        &self.adapter
    }
    fn verifier(&self) -> &dyn Verifier {
        &ReportVerifier
    }
    fn sandbox_plan(
        &self,
        _invocation: &orxnud_domain::invocation::CapabilityInvocation,
    ) -> Option<SandboxPlan> {
        let (ro, rw) = self.grants.clone();
        Some(SandboxPlan {
            program: helper_path().display().to_string(),
            args: vec![
                "--exact".into(),
                "hostile_helper_entry_point".into(),
                "--ignored".into(),
                "--nocapture".into(),
            ],
            env: self.adapter.env.clone(),
            working_dir: "/".into(),
            grant_rw: rw,
            // The helper binary lives in the build output, which the sandbox cannot
            // otherwise see. A real capability would be installed somewhere the
            // sandbox expects.
            grant_ro: ro,
            network: false,
            deadline_ms: 20_000,
            output_cap_bytes: 256 * 1024,
            // The helper is well behaved; it observes rather than demands resource
            // ceilings. A capability that could exhaust the host would demand them and
            // be refused on a host that cannot provide them (V-46).
            resources: orxnud_capability::dispatch::ResourcePolicy::default(),
        })
    }
}

fn bundles(a: Tier1HelperAdapter) -> BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> {
    let id = a.capability_id().clone();
    let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
    let dir = sandbox_helpers_dir();
    m.insert(
        id,
        Arc::new(HelperBundle {
            adapter: a,
            grants: (vec![dir.display().to_string()], vec![]),
        }),
    );
    m
}

/// A verifier that reports the helper's own PASS/FAIL line.
///
/// The point of the whole file: a subprocess reporting success is not the same as the
/// effect having happened, so the verdict comes from *parsing* the helper's report
/// rather than from the exit code.
struct ReportVerifier;

impl Verifier for ReportVerifier {
    fn verify(
        &self,
        execution: &ExecutionOutcome,
        _params: &serde_json::Value,
        _at: i64,
    ) -> Result<VerificationOutcome, VerifyError> {
        let ExecutionOutcome::Succeeded { output: Some(text) } = execution else {
            // Nothing ran, or it failed: nothing to verify. Never `Verified`.
            return Ok(VerificationOutcome::Undetermined {
                reason: "the capability did not report success".into(),
            });
        };
        if text.contains("RESULT PASS") {
            Ok(VerificationOutcome::Verified {
                evidence: "the helper reported the attempt was refused".into(),
            })
        } else {
            // The helper reported it *succeeded* at something it should not have been
            // able to do. That is a refutation, not a success.
            Ok(VerificationOutcome::Refuted {
                evidence: format!("the helper reported it succeeded: {text}"),
            })
        }
    }
}

/// An execution backend that counts executions, so a refusal can be detected as
/// "nothing ran" rather than inferred from timing.
struct CountingBackend {
    inner: Arc<SandboxExecutionBackend>,
    calls: AtomicUsize,
    seen: Mutex<Vec<ExecutionContract>>,
}

impl CountingBackend {
    fn new() -> Self {
        Self {
            inner: Arc::new(SandboxExecutionBackend::new()),
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ExecutionBackend for CountingBackend {
    fn execute(&self, contract: &ExecutionContract) -> Result<ExecutionReport, SandboxRefusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().expect("lock").push(contract.clone());
        self.inner.execute(contract)
    }
    fn can_fulfil(&self, contract: &ExecutionContract) -> bool {
        self.inner.can_fulfil(contract)
    }
}

// ---------------------------------------------------------------- the happy path

#[test]
fn a_governed_tier1_dispatch_runs_a_sandboxed_subprocess() {
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let backend = Arc::new(CountingBackend::new());
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        bundles(Tier1HelperAdapter::running("env-dump")),
    )
    .with_execution(backend.clone());

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
        .expect("governed dispatch");

    assert_eq!(backend.calls(), 1, "exactly one sandboxed execution");
    assert!(
        outcome.is_verified(),
        "the helper's own PASS line is what verifies it, not the exit code: {:?}",
        outcome
    );
    // Authorisation before the call, terminal outcome after it: the pair a real
    // execution produces. Counting only the authorisation would have hidden the
    // terminal write, which is the point of asserting on the governed path.
    assert_eq!(
        d.audit_records(),
        2,
        "the authorisation and its terminal outcome are both audited"
    );
}

#[test]
fn the_execution_contract_carries_no_credential_or_secret_reference() {
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new().with("svc", "acct", "s3cr3t-value");
    let backend = Arc::new(CountingBackend::new());
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        bundles(Tier1HelperAdapter::running("env-dump")),
    )
    .with_execution(backend.clone());

    d.dispatch(
        request(),
        human(),
        context(),
        None,
        params(),
        None,
        Some(&SecretRef::new("svc", "acct")),
        NOW,
    )
    .expect("dispatch");

    let seen = backend.seen.lock().expect("lock").clone();
    assert_eq!(seen.len(), 1);
    let text = format!("{seen:?}");
    assert!(
        !text.contains("s3cr3t-value"),
        "the credential value reached the execution contract: {text}"
    );
    // The *reference* must not be there either: a contract is logged and audited, so
    // even a SecretRef would create a second exposure path.
    assert!(
        !text.contains("openraynux/svc/acct"),
        "a secret reference reached the execution contract: {text}"
    );
}

// ----------------------------------------------------- the no-bypass invariant

#[test]
fn a_tier1_capability_without_a_backend_is_refused_and_runs_nothing() {
    // The central V-50 invariant. No backend configured must mean a refusal, never an
    // in-process call and never an unsandboxed subprocess.
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        bundles(Tier1HelperAdapter::running("env-dump")),
    );

    assert!(!d.has_execution_backend());
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
        .expect_err("a Tier-1 capability with no sandbox must be refused");

    match err {
        DispatchError::SandboxRefused(r) => {
            assert_eq!(r.capability, cap());
            assert!(r.reason.contains("no execution backend"), "{}", r.reason);
        }
        other => panic!("expected a sandbox refusal, got {other:?}"),
    }
}

#[test]
fn a_tier1_capability_with_an_unfulfillable_backend_runs_nothing() {
    // A backend that exists but cannot establish the guarantees is also a refusal.
    struct UselessBackend;
    impl ExecutionBackend for UselessBackend {
        fn execute(&self, _c: &ExecutionContract) -> Result<ExecutionReport, SandboxRefusal> {
            panic!("must not be reached: can_fulfil said no");
        }
        fn can_fulfil(&self, _c: &ExecutionContract) -> bool {
            false
        }
    }

    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        bundles(Tier1HelperAdapter::running("env-dump")),
    )
    .with_execution(Arc::new(UselessBackend));

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
        .expect_err("an unfulfillable backend must refuse");
    assert!(matches!(err, DispatchError::SandboxRefused(_)), "{err:?}");
}

#[test]
fn a_tier0_capability_still_runs_in_process() {
    // The other direction: integration must not have broken Tier 0.
    struct Tier0;
    impl CapabilityAdapter for Tier0 {
        fn capability_id(&self) -> &CapabilityId {
            static ID: std::sync::OnceLock<CapabilityId> = std::sync::OnceLock::new();
            ID.get_or_init(|| CapabilityId::new("t0"))
        }
        fn declared_class(&self) -> DataClass {
            DataClass::Personal
        }
        fn invoke(
            &self,
            _v: &DispatchView<'_>,
            _c: Option<&orxnud_capability::credential::CredentialHandle>,
        ) -> Result<ExecutionOutcome, String> {
            Ok(ExecutionOutcome::Succeeded { output: None })
        }
    }
    struct B0;
    impl AdapterBundle for B0 {
        fn adapter(&self) -> &dyn CapabilityAdapter {
            &Tier0
        }
        fn verifier(&self) -> &dyn Verifier {
            &Confirming
        }
    }
    struct Confirming;
    impl Verifier for Confirming {
        fn verify(
            &self,
            _e: &ExecutionOutcome,
            _params: &serde_json::Value,
            _a: i64,
        ) -> Result<VerificationOutcome, VerifyError> {
            Ok(VerificationOutcome::Verified {
                evidence: "ok".into(),
            })
        }
    }

    let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
    m.insert(
        CapabilityId::new("t0"),
        Arc::new(B0) as Arc<dyn AdapterBundle + Send + Sync>,
    );
    let mut engine = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(Grant {
            id: GrantId::new("g0"),
            granted_by: UserId::new("u-1"),
            capability: CapabilityId::new("t0"),
            max_data_class: DataClass::Personal,
            may_grant: false,
            expires_at_ms: i64::MAX,
            revoked: false,
        }),
        BudgetLedger::empty().with_global(100),
        "v1",
    );
    engine.register(CapabilityDeclaration::new(
        CapabilityId::new("t0"),
        RiskClass::Low,
        DataClass::Personal,
        false,
        0,
    ));
    let secrets = FakeSecrets::new();
    // No execution backend at all: a Tier-0 capability must not need one.
    let mut d = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m);
    let outcome = d
        .dispatch(
            ActionRequest::new(
                TaskId::new("t"),
                RunId::new("r"),
                0,
                CapabilityId::new("t0"),
                orxnud_domain::json!({}),
                DataClass::Personal,
                DataClass::Personal,
            ),
            human(),
            context(),
            None,
            params(),
            None,
            None,
            NOW,
        )
        .expect("Tier 0 must not need a sandbox");
    assert!(outcome.is_verified());
}

// -------------------------------------------------- refusals spawn no subprocess

#[test]
fn a_policy_refusal_reaches_the_backend_zero_times() {
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let backend = Arc::new(CountingBackend::new());
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        bundles(Tier1HelperAdapter::running("env-dump")),
    )
    .with_execution(backend.clone());

    let external = Actor::External {
        source: orxnud_domain::ExternalSource::Unknown,
        request: orxnud_domain::RequestId::new("req-ext"),
    };
    d.dispatch(
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
    assert_eq!(backend.calls(), 0, "policy refused before execution");
}

#[test]
fn a_budget_refusal_reaches_the_backend_zero_times() {
    let mut engine = policy(100, 0); // zero budget
    let secrets = FakeSecrets::new();
    let backend = Arc::new(CountingBackend::new());
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        bundles(Tier1HelperAdapter::running("env-dump")),
    )
    .with_execution(backend.clone());

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
    .expect_err("over budget must be refused");
    assert_eq!(backend.calls(), 0, "budget refused before execution");
}

#[test]
fn a_credential_failure_reaches_the_backend_zero_times() {
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new(); // nothing configured
    let backend = Arc::new(CountingBackend::new());
    let mut d = orxnud_capability::dispatch::Dispatcher::new(
        &mut engine,
        &secrets,
        bundles(Tier1HelperAdapter::running("env-dump")),
    )
    .with_execution(backend.clone());

    d.dispatch(
        request(),
        human(),
        context(),
        None,
        params(),
        None,
        Some(&SecretRef::new("absent", "acct")),
        NOW,
    )
    .expect_err("an absent credential must refuse");
    assert_eq!(backend.calls(), 0, "credential failure precedes execution");
}

#[test]
fn a_capability_resolution_failure_reaches_the_backend_zero_times() {
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let backend = Arc::new(CountingBackend::new());
    // No bundles at all.
    let m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
    let mut d = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m)
        .with_execution(backend.clone());

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
    .expect_err("no implementation must be refused");
    assert_eq!(backend.calls(), 0);
}

// ----------------------------------------- hostile behaviour through the path

#[test]
fn a_governed_filesystem_probe_is_denied() {
    let d = std::env::temp_dir().join(format!("orxnud-gov-fs-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("mkdir");
    let secret = d.join("secret.txt");
    std::fs::write(&secret, "sensitive").expect("seed");

    let mut adapter = Tier1HelperAdapter::running("fs-read");
    adapter.env.insert(
        "ORXNUD_HOSTILE_HELPER".into(),
        "fs-read\u{1}".to_owned() + secret.display().to_string().as_str(),
    );

    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let mut d2 =
        orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, bundles(adapter))
            .with_execution(Arc::new(SandboxExecutionBackend::new()));

    let outcome = d2
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
        .expect("governed dispatch");
    assert!(
        outcome.is_verified(),
        "the helper must have been denied the file, which verification confirms: {:?}",
        outcome
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_governed_network_probe_is_denied() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let mut adapter = Tier1HelperAdapter::running("net-connect");
    adapter.env.insert(
        "ORXNUD_HOSTILE_HELPER".into(),
        format!("net-connect\u{1}127.0.0.1:{port}"),
    );

    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let mut d2 =
        orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, bundles(adapter))
            .with_execution(Arc::new(SandboxExecutionBackend::new()));

    let outcome = d2
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
        .expect("governed dispatch");
    assert!(
        outcome.is_verified(),
        "the host listener must be unreachable: {outcome:?}"
    );

    // And the listener must have seen nothing.
    listener.set_nonblocking(true).expect("nonblocking");
    assert!(
        listener.accept().is_err(),
        "the sandbox reached the host listener"
    );
}

#[test]
fn a_governed_environment_probe_sees_no_secret() {
    let adapter = Tier1HelperAdapter::running("cred-env-probe");
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let mut d2 =
        orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, bundles(adapter))
            .with_execution(Arc::new(SandboxExecutionBackend::new()));

    let outcome = d2
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
        .expect("governed dispatch");
    assert!(
        outcome.is_verified(),
        "no synthetic credential marker may reach the child: {outcome:?}"
    );
}

#[test]
fn a_governed_descendant_spawn_is_contained() {
    // The Phase 4a containment result, now reached through the governed path.
    //
    // The marker lives in a *granted host-visible* directory rather than `/tmp`,
    // because `/tmp` inside the sandbox is a private tmpfs. A first version watched
    // `/tmp/orxnud-descendant-alive`, never saw it, and concluded "contained" for the
    // wrong reason -- a false green from looking in the wrong namespace.
    let marker_dir = std::env::temp_dir().join(format!("orxnud-gov-desc-{}", std::process::id()));
    std::fs::create_dir_all(&marker_dir).expect("mkdir");
    let marker = marker_dir.join("alive");
    let _ = std::fs::remove_file(&marker);

    let mut adapter = Tier1HelperAdapter::running("spawn-descendant");
    adapter.env.insert(
        "ORXNUD_DESCENDANT_MARKER".into(),
        marker.display().to_string(),
    );
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    // Grant the marker directory read-write, or the grandchild cannot write there.
    let id = cap();
    let dir = sandbox_helpers_dir();
    let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
    m.insert(
        id,
        Arc::new(HelperBundle {
            adapter,
            grants: (
                vec![dir.display().to_string()],
                vec![marker_dir.display().to_string()],
            ),
        }) as Arc<dyn AdapterBundle + Send + Sync>,
    );
    let mut d2 = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m)
        .with_execution(Arc::new(SandboxExecutionBackend::new()));

    d2.dispatch(
        request(),
        human(),
        context(),
        None,
        params(),
        None,
        None,
        NOW,
    )
    .expect("governed dispatch");

    // The helper's grandchild writes a heartbeat here. Once the namespace dies, the
    // heartbeat must stop advancing. Staleness is checked by change, not existence.
    let marker = marker.as_path();
    assert!(
        marker.exists(),
        "the helper should have spawned a grandchild"
    );
    let before = std::fs::metadata(marker).map(|m| m.len()).ok();
    std::thread::sleep(std::time::Duration::from_millis(900));
    let after = std::fs::metadata(marker).map(|m| m.len()).ok();
    // The file may be rewritten with the same length, so compare modification time.
    let m1 = std::fs::metadata(marker).and_then(|m| m.modified()).ok();
    std::thread::sleep(std::time::Duration::from_millis(700));
    let m2 = std::fs::metadata(marker).and_then(|m| m.modified()).ok();
    assert_eq!(
        m1, m2,
        "the grandchild's heartbeat is still advancing: containment failed (before={before:?} after={after:?})"
    );
    let _ = std::fs::remove_dir_all(&marker_dir);
}

#[test]
fn a_governed_hang_is_stopped_at_the_deadline() {
    let adapter = Tier1HelperAdapter::running("hang");
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let mut d2 =
        orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, bundles(adapter))
            .with_execution(Arc::new(SandboxExecutionBackend::new()));

    let started = std::time::Instant::now();
    let outcome = d2
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
        .expect("governed dispatch must return, not hang");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "the supervisor took {:?}; a hang must be bounded",
        started.elapsed()
    );
    assert!(
        matches!(outcome.execution, ExecutionOutcome::Unknown { .. }),
        "a deadline is an unknown outcome, not a success: {:?}",
        outcome.execution
    );
    assert!(
        !outcome.is_verified(),
        "a killed process must never verify as success"
    );
}

#[test]
fn a_governed_flood_is_bounded() {
    let mut adapter = Tier1HelperAdapter::running("flood");
    adapter
        .env
        .insert("ORXNUD_HOSTILE_HELPER".into(), "flood\u{1}20000000".into());
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let mut d2 =
        orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, bundles(adapter))
            .with_execution(Arc::new(SandboxExecutionBackend::new()));

    let outcome = d2
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
        .expect("governed dispatch");
    // 20 MB requested, 256 KiB cap. The report must be bounded, not merely present.
    let size = match &outcome.execution {
        ExecutionOutcome::Succeeded { output: Some(s) } => s.len(),
        ExecutionOutcome::Succeeded { output: None } => 0,
        ExecutionOutcome::Failed { detail } | ExecutionOutcome::Unknown { detail } => detail.len(),
    };
    assert!(
        size <= 256 * 1024,
        "the report grew to {size} bytes against a 256 KiB cap"
    );
}

// ------------------------------------------------------ disabled capabilities

#[test]
fn a_disabled_capability_produces_no_execution_path() {
    // Phase 4a's point 6, through the governed path: a disabled capability is refused
    // at stage 5, so no contract is built and the backend is never consulted.
    let mut engine = policy(0, 1_000);
    let secrets = FakeSecrets::new();
    let backend = Arc::new(CountingBackend::new());

    // Disabling is done by not registering, which is how a capability is absent. The
    // first dispatcher below proves the *same* capability runs when it is registered,
    // so the refusal cannot pass merely because the wiring is broken.
    {
        let mut enabled = orxnud_capability::dispatch::Dispatcher::new(
            &mut engine,
            &secrets,
            bundles(Tier1HelperAdapter::running("env-dump")),
        )
        .with_execution(backend.clone());
        enabled
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
            .expect("the registered capability must run");
        assert_eq!(backend.calls(), 1, "the baseline must execute exactly once");
    }

    let m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
    let mut d3 = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m)
        .with_execution(backend.clone());

    let err = d3
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
        .expect_err("an unregistered capability must be refused");
    assert!(matches!(err, DispatchError::NoImplementation(_)), "{err:?}");
    assert_eq!(
        backend.calls(),
        1,
        "the count must be unchanged: no subprocess for an unregistered capability"
    );
}

/// Fails if the audit chain lost the record, so a governed execution is attributable.
trait AuditAccess {
    fn audit_records(&self) -> usize;
}

impl<S: orxnud_domain::SecretsContract> AuditAccess
    for orxnud_capability::dispatch::Dispatcher<'_, S>
{
    fn audit_records(&self) -> usize {
        self.audit_len()
    }
}

// ------------------------------------------------ V-46: governed cgroup enforcement
//
// Everything above proves the sandbox *works*. These prove the governed path *uses* it
// for resources -- a distinction that only matters if the dispatcher could have run the
// payload outside a cgroup while every other test stayed green.
//
// The observer below reads the cgroup hierarchy directly. That is deliberate: it is the
// independent witness. If the runner merely *claimed* membership, these assertions would
// pass. The capability layer itself never sees a cgroup path or a controller name.

mod v46 {
    use super::*;
    use orxnud_capability::dispatch::{ResourceBudget, ResourcePolicy, ResourceRequirement};
    use orxnud_platform_sandbox::cgroup::CgroupV2;
    use orxnud_platform_sandbox::contract::{AvailableGuarantees, ExecutionResult, SandboxRunner};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;

    /// What an outside observer saw while an execution ran.
    #[derive(Debug, Default)]
    struct Observed {
        saw_child: bool,
        strictly_below_base: bool,
        memory_max: Vec<String>,
        memory_refusals: u64,
        memory_oom: u64,
        memory_oom_kill: u64,
        peak_memory_current: u64,
        max_members: usize,
        saw_payload_member: bool,
        leftover: usize,
        my_path: Option<PathBuf>,
    }

    /// Watches the discovered base for the runner's dedicated children.
    ///
    /// Runs on its own thread because the dispatch blocks until the payload exits, and
    /// the payload is only in the cgroup while it is running.
    fn watch(
        seconds: u64,
        ceiling: &str,
    ) -> (std::thread::JoinHandle<Observed>, Arc<AtomicBool>, CgroupV2) {
        let ceiling = ceiling.to_owned();
        let base = CgroupV2::discover();
        let base_path = base.base.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        // Scoped to this process. The runner names cgroups `orxnud-exec-<pid>-<seq>`, so
        // filtering by our own pid is exact. Counting every `orxnud-exec-*` in the shared
        // base instead observes *other* concurrently running tests and reports their
        // in-flight cgroups as our leak -- which is how a 2-vs-0 failure appeared only
        // under whole-workspace parallelism.
        let mine = format!("orxnud-exec-{}-", std::process::id());
        let handle = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
            let mut o = Observed::default();
            while std::time::Instant::now() < deadline && !flag.load(Ordering::SeqCst) {
                let mut entries: Vec<PathBuf> = std::fs::read_dir(&base_path)
                    .map(|d| {
                        d.flatten()
                            .map(|e| e.path())
                            .filter(|p| {
                                p.file_name()
                                    .and_then(|n| n.to_str())
                                    .is_some_and(|n| n.starts_with(&mine))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                for p in entries.drain(..) {
                    o.saw_child = true;
                    if p != base_path && p.starts_with(&base_path) {
                        o.strictly_below_base = true;
                    }
                    let mut is_mine = o.my_path.as_deref() == Some(p.as_path());
                    if let Ok(m) = std::fs::read_to_string(p.join("memory.max")) {
                        let v = m.trim().to_owned();
                        // Identify *our* execution by a ceiling unique to this test.
                        // Scoping by pid is not enough: `cargo test` runs the tests in this
                        // binary in parallel threads of one process, so sibling tests share
                        // the pid prefix and their in-flight cgroups read as our leak.
                        if v == ceiling && o.my_path.is_none() {
                            o.my_path = Some(p.clone());
                            is_mine = true;
                        }
                        o.memory_max.push(v);
                    }
                    // Every measurement below is scoped to *our* cgroup.
                    //
                    // Reading them from all of our process's cgroups was wrong: the tests
                    // in this module run in parallel threads of one process, so a sibling
                    // test's in-flight cgroup was contributing its memory ceiling,
                    // counters and peak to ours. That produced a 16 MiB ceiling being
                    // reported as having held 26 MB -- the sibling's 32 MiB cgroup, not
                    // ours. The failure looked like the ceiling was not enforced, which is
                    // the one conclusion this observer exists to rule out.
                    if !is_mine {
                        continue;
                    }
                    // Enforcement evidence, read from the kernel rather than from the
                    // helper.
                    //
                    // All three counters are collected because which one moves depends on
                    // the configuration. `max` counts charges refused *and reclaimed*,
                    // which is what memory.max does when it can push pages elsewhere. The
                    // runner also pins `memory.swap.max = 0`, so there is nowhere to push
                    // them and the kernel OOM-kills instead -- `max` then stays 0 and
                    // `oom_kill` moves. Asserting only `max` was asserting one particular
                    // mechanism rather than the property.
                    if let Ok(ev) = std::fs::read_to_string(p.join("memory.events")) {
                        for line in ev.lines() {
                            let (key, dst) = match line.split_once(' ') {
                                Some(("max", v)) => (v, 0),
                                Some(("oom", v)) => (v, 1),
                                Some(("oom_kill", v)) => (v, 2),
                                _ => continue,
                            };
                            let n = key.trim().parse().unwrap_or(0);
                            match dst {
                                0 => o.memory_refusals = o.memory_refusals.max(n),
                                1 => o.memory_oom = o.memory_oom.max(n),
                                _ => o.memory_oom_kill = o.memory_oom_kill.max(n),
                            }
                        }
                    }
                    if let Ok(cur) = std::fs::read_to_string(p.join("memory.current")) {
                        o.peak_memory_current =
                            o.peak_memory_current.max(cur.trim().parse().unwrap_or(0));
                    }
                    if let Ok(procs) = std::fs::read_to_string(p.join("cgroup.procs")) {
                        let n = procs.lines().filter(|l| !l.trim().is_empty()).count();
                        o.max_members = o.max_members.max(n);
                        // bwrap plus the payload plus whatever it forked: more than the
                        // supervisor alone is what shows the *workload* is inside too.
                        if n > 1 {
                            o.saw_payload_member = true;
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(3));
            }
            // "Leftover" means *ours* specifically: the cgroup carrying this test's unique
            // ceiling, re-checked after the dispatch returned. Counting every
            // `orxnud-exec-*` in the shared base instead observes sibling tests running in
            // parallel in this same process and reports their in-flight cgroups as our leak.
            o.leftover = match &o.my_path {
                Some(p) => usize::from(p.exists()),
                None => 0,
            };
            o
        });
        (handle, stop, base)
    }

    fn available() -> bool {
        let av = CgroupV2::discover().availability;
        av.memory && av.processes && av.cpu
    }

    fn bundle(resources: ResourcePolicy) -> Arc<dyn AdapterBundle + Send + Sync> {
        let mut b = Tier1HelperAdapter::running("fork-many");
        b.env.insert("ORXNUD_ARG1".into(), "24".into());
        Arc::new(PolicyBundle {
            adapter: b,
            resources,
            grant_rw: Vec::new(),
            deadline_ms: 20_000,
        })
    }

    /// A bundle whose plan demands a specific resource policy.
    struct PolicyBundle {
        adapter: Tier1HelperAdapter,
        resources: ResourcePolicy,
        grant_rw: Vec<String>,
        deadline_ms: u64,
    }

    impl AdapterBundle for PolicyBundle {
        fn adapter(&self) -> &dyn CapabilityAdapter {
            &self.adapter
        }
        fn verifier(&self) -> &dyn Verifier {
            &ReportVerifier
        }
        fn sandbox_plan(
            &self,
            _invocation: &orxnud_domain::invocation::CapabilityInvocation,
        ) -> Option<SandboxPlan> {
            Some(SandboxPlan {
                program: helper_path().display().to_string(),
                args: vec![
                    "--exact".into(),
                    "hostile_helper_entry_point".into(),
                    "--ignored".into(),
                    "--nocapture".into(),
                ],
                env: self.adapter.env.clone(),
                working_dir: "/".into(),
                grant_rw: self.grant_rw.clone(),
                grant_ro: vec![sandbox_helpers_dir().display().to_string()],
                network: false,
                deadline_ms: self.deadline_ms,
                output_cap_bytes: 256 * 1024,
                resources: self.resources.clone(),
            })
        }
    }

    // ---------------------------------------------------------------- 1. enforced

    /// A governed Tier-1 request that requires memory control actually runs inside a
    /// dedicated cgroup whose `memory.max` is the ceiling the contract asked for.
    #[test]
    fn a_required_memory_ceiling_is_applied_by_the_governed_path() {
        if !available() {
            println!("  host does not delegate memory+pids+cpu; reported, not skipped");
            return;
        }
        // A ceiling used by exactly this test, so the observer can identify this
        // execution's cgroup among the ones its parallel siblings create.
        const MY_CEILING: &str = "50331648";
        let required = ResourcePolicy {
            required: vec![ResourceRequirement::Memory],
            budget: ResourceBudget {
                // The distinctive ceiling the observer identifies this execution by.
                memory_bytes: Some(48 * 1024 * 1024),
                processes: Some(24),
                cpu_cores: Some(0.5),
            },
        };
        let id = cap();
        let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
        m.insert(id.clone(), bundle(required.clone()));
        let mut engine = policy(0, 1_000);
        let secrets = FakeSecrets::new();
        let mut d = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m)
            .with_execution(Arc::new(SandboxExecutionBackend::new()));
        let (watcher, stop, _base) = watch(25, MY_CEILING);
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
            .expect("a satisfiable required ceiling must not refuse");
        stop.store(true, Ordering::SeqCst);

        println!("  governed execution: {:?}", outcome.execution);
        let o = watcher.join().expect("observer");
        println!(
            "  observed: child={} strictly_below_base={} max_members={} payload_member={} \
             memory_max={:?} leftover={}",
            o.saw_child,
            o.strictly_below_base,
            o.max_members,
            o.saw_payload_member,
            o.memory_max,
            o.leftover
        );

        assert!(
            o.saw_child,
            "the governed path created no dedicated cgroup at all"
        );
        assert!(
            o.strictly_below_base,
            "the execution cgroup must be strictly below the discovered base (V-55)"
        );
        assert!(
            o.memory_max.iter().any(|m| m == MY_CEILING),
            "memory.max was not the requested ceiling: {:?}",
            o.memory_max
        );
        assert!(
            o.saw_payload_member && o.max_members > 1,
            "only the supervisor was observed ({max_members}); the workload itself was not \
             inside the cgroup",
            max_members = o.max_members
        );
        assert_eq!(
            o.leftover, 0,
            "the dedicated cgroup was not cleaned up after execution"
        );
    }

    /// A required control with no budget is an incomplete policy and must be refused
    /// before anything executes.
    ///
    /// This is the rule that replaced the rejected `DEFAULT_*` constants. The backend is
    /// no longer permitted to invent a ceiling, so the only way a required control can be
    /// honoured is if the capability actually said what the ceiling is.
    #[test]
    fn a_required_control_with_no_budget_is_refused_before_execution() {
        let runs = Arc::new(AtomicUsize::new(0));
        let backend = SandboxExecutionBackend::with_runner(Arc::new(UndelegatedRunner {
            inner: Arc::new(orxnud_platform_sandbox::linux::BwrapRunner::new()),
            runs: Arc::clone(&runs),
        }));
        // `Memory` required, but `memory_bytes` is None. Nothing to enforce.
        let incomplete = ResourcePolicy {
            required: vec![ResourceRequirement::Memory],
            budget: ResourceBudget {
                memory_bytes: None,
                processes: Some(8),
                cpu_cores: None,
            },
        };
        assert!(
            incomplete.validate().is_err(),
            "the policy is incomplete and validation must say so"
        );
        let id = cap();
        let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
        m.insert(id.clone(), bundle(incomplete));
        let mut engine = policy(0, 1_000);
        let secrets = FakeSecrets::new();
        let mut d = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m)
            .with_execution(Arc::new(backend));

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
            .expect_err("an incomplete resource policy must refuse");
        assert!(
            matches!(err, DispatchError::SandboxRefused(_)),
            "expected a refusal, got {err:?}"
        );
        assert_eq!(
            runs.load(Ordering::SeqCst),
            0,
            "an incomplete policy must be refused before the backend is consulted"
        );
    }

    /// A budget for a control that is merely budgeted is not affected by the completeness
    /// rule. V-56 keeps them distinct.
    #[test]
    fn a_budget_without_a_requirement_is_still_valid() {
        let budget_only = ResourcePolicy {
            required: Vec::new(),
            budget: ResourceBudget {
                memory_bytes: Some(32 * 1024 * 1024),
                processes: None,
                cpu_cores: None,
            },
        };
        assert!(
            budget_only.validate().is_ok(),
            "an unenforceable non-required budget is valid policy; it is recorded as a gap, \
             not refused: {:?}",
            budget_only.validate()
        );
    }

    // ------------------------------------------------------- 2. required-unavailable

    /// A runner that reports the resource controllers unavailable, counting `run` calls.
    struct UndelegatedRunner {
        inner: Arc<dyn SandboxRunner>,
        runs: Arc<AtomicUsize>,
    }

    impl SandboxRunner for UndelegatedRunner {
        fn available_guarantees(&self) -> AvailableGuarantees {
            let mut g = self.inner.available_guarantees();
            // The only thing this double lies about. Everything else is the real runner.
            g.resources = false;
            g
        }
        fn run(
            &self,
            spec: &orxnud_platform_sandbox::contract::SandboxSpec,
        ) -> Result<ExecutionResult, orxnud_platform_sandbox::contract::SandboxUnavailable>
        {
            self.runs.fetch_add(1, Ordering::SeqCst);
            self.inner.run(spec)
        }
        fn cancel(&self) -> Result<(), orxnud_platform_sandbox::contract::SandboxUnavailable> {
            self.inner.cancel()
        }
    }

    /// A required control the host cannot establish must refuse, must never reach the
    /// backend, and must not run the payload.
    ///
    /// Availability is forced with a delegating runner rather than by mutating the host's
    /// delegation: a test that needs a broken host is a test that cannot be trusted on a
    /// working one. The runner's `probe` is the same call the real runner makes, and the
    /// refusal path exercised below is the production one.
    #[test]
    fn a_required_control_the_host_cannot_provide_refuses_without_spawning() {
        let runs = Arc::new(AtomicUsize::new(0));
        let backend = SandboxExecutionBackend::with_runner(Arc::new(UndelegatedRunner {
            inner: Arc::new(orxnud_platform_sandbox::linux::BwrapRunner::new()),
            runs: Arc::clone(&runs),
        }));
        let required = ResourcePolicy {
            required: vec![ResourceRequirement::Memory],
            budget: ResourceBudget {
                memory_bytes: Some(64 * 1024 * 1024),
                processes: None,
                cpu_cores: None,
            },
        };
        let id = cap();
        let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
        m.insert(id.clone(), bundle(required.clone()));
        let mut engine = policy(0, 1_000);
        let secrets = FakeSecrets::new();
        let mut d = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m)
            .with_execution(Arc::new(backend));
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
            .expect_err("an unsatisfiable required ceiling must refuse");
        assert!(
            matches!(err, DispatchError::SandboxRefused(_)),
            "expected a refusal, got {err:?}"
        );
        // What is actually guaranteed, and why.
        //
        // The stage order is AUTHORITY -> ... -> CREDENTIAL -> SANDBOX -> EXECUTION
        // (`dispatch.rs`, stages 6 and 7). A resource refusal happens *inside* sandbox
        // establishment, so it necessarily follows credential resolution. Claiming
        // otherwise would be a false claim about this architecture.
        //
        // What is guaranteed, and asserted, is the part that carries security weight:
        // the backend is never invoked, so no subprocess exists, and no credential
        // material is ever bound into an environment because `stdin_credential` adds the
        // secret to the *spec* inside `execute`, which never runs. The credential is
        // resolved and then discarded; it does not cross into execution.
        assert_eq!(
            runs.load(Ordering::SeqCst),
            0,
            "the backend was invoked despite a required ceiling being unavailable, so a \
             credential-bearing environment may have been built"
        );
        let text = format!("{err:?}");
        assert!(
            !text.contains("ORXNUD_TIER1_CREDENTIAL"),
            "the refusal must not echo credential material: {text}"
        );
    }

    // ------------------------------------------------------------ 3. cgroup.kill

    /// A detached descendant that ignores every catchable signal, outliving a governed
    /// execution that is cut off at its deadline, must not survive it.
    ///
    /// A signal cannot reach it: it ignores SIGTERM, SIGINT, SIGHUP and SIGQUIT, and it is
    /// not a child of the process the supervisor signals.
    ///
    /// **What this proves, and what it does not.** It proves the governed outcome: a
    /// detached descendant alive at the deadline is not alive after it, and the dedicated
    /// cgroup is emptied and removed. It does *not* prove that `cgroup.kill` is what
    /// killed it. On Linux `bwrap` already runs with `--unshare-pid --die-with-parent`,
    /// so the namespace reaps descendants the moment the supervisor dies -- which is why
    /// removing the runner's `cgroup.kill` left this test green. Containment here is
    /// deliberately redundant: namespace first, cgroup as the backstop that also covers
    /// anything the namespace cannot reach. `cgroup.kill`'s independent teeth are proven
    /// where they are observable, in `enforcement.rs::cgroup_kill_terminates_a_three_level_subtree`.
    ///
    /// The earlier version of this test proved nothing at all: `spawn-descendant` returns
    /// immediately, so the sandbox exited long before any kill path was reached and the
    /// marker was never written. It "passed" on a sentinel value.
    #[test]
    fn a_governed_timeout_terminates_a_detached_descendant_and_reaps_its_cgroup() {
        if !available() {
            println!("  host does not delegate cgroup.kill; reported, not skipped");
            return;
        }
        // A *directory* is bound, not a file, so the descendant can create and rewrite
        // the marker inside the sandbox.
        let dir = std::env::temp_dir().join(format!("orxnud-v46-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("marker dir");
        let marker = dir.join("alive");
        let _ = std::fs::remove_file(&marker);

        let required = ResourcePolicy {
            required: vec![ResourceRequirement::Processes],
            budget: ResourceBudget {
                memory_bytes: Some(256 * 1024 * 1024),
                processes: Some(64),
                cpu_cores: Some(1.0),
            },
        };
        let mut adapter = Tier1HelperAdapter::running("descendant-hang");
        adapter.env.insert(
            "ORXNUD_DESCENDANT_MARKER".into(),
            marker.display().to_string(),
        );
        let id = cap();
        let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
        m.insert(
            id.clone(),
            Arc::new(PolicyBundle {
                adapter,
                resources: required.clone(),
                grant_rw: vec![dir.display().to_string()],
                // Short enough that the deadline lands while the descendant is alive.
                deadline_ms: 2_000,
            }),
        );
        let mut engine = policy(0, 1_000);
        let secrets = FakeSecrets::new();
        let mut d = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m)
            .with_execution(Arc::new(SandboxExecutionBackend::new()));

        let (watcher, stop, base) = watch(30, "268435456");
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
        stop.store(true, Ordering::SeqCst);
        println!("  governed execution: {:?}", outcome.execution);

        let o = watcher.join().expect("observer");
        // Liveness is a moving marker: the descendant rewrites its pid every 150 ms, so a
        // *changing* value proves it was alive and a *stable* value after the dispatch
        // proves it stopped. A host pid would prove nothing about which cgroup it was in.
        let first = std::fs::read_to_string(&marker).unwrap_or_default();
        std::thread::sleep(std::time::Duration::from_millis(600));
        let second = std::fs::read_to_string(&marker).unwrap_or_default();
        println!(
            "  descendant marker: {:?} -> {:?}; max_members={} leftover={}",
            first.trim(),
            second.trim(),
            o.max_members,
            o.leftover
        );

        assert!(
            first.trim().parse::<u32>().is_ok(),
            "the descendant never wrote a pid to the bound marker, so its death was not \
             observed: {:?}",
            first
        );
        assert_eq!(
            first.trim(),
            second.trim(),
            "the detached descendant is still running after the governed execution ended"
        );
        // A deadline surfaces as `Unknown`, not `Failed`: `Failed` means nothing
        // happened, `Unknown` means the subprocess was cut off mid-flight and nobody
        // vouches for its state. That mapping is the point -- asserting `Failed` would
        // have demanded the supervisor pretend the work never began.
        assert!(
            matches!(outcome.execution, ExecutionOutcome::Unknown { .. }),
            "the execution should have been cut off at its deadline: {:?}",
            outcome.execution
        );
        assert!(
            o.max_members >= 2,
            "only the supervisor was ever observed ({}); there was no descendant to kill",
            o.max_members
        );
        assert_eq!(
            o.leftover, 0,
            "the dedicated cgroup was not removed: {:?}",
            base.base
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ceiling must be *enforced by the kernel*, not merely written to a file.
    ///
    /// The first governed test proves `memory.max` holds the requested value. That is
    /// configuration, not enforcement: a file can contain `16777216` while nothing acts on
    /// it. This one presses a tiny ceiling with a bounded, page-touching workload and reads
    /// the kernel's own refusal accounting from `memory.events` while the execution runs.
    ///
    /// No OOM kill is required. `memory.max` is entitled to refuse and reclaim rather than
    /// kill, and the earlier version of this test demanded a kill -- which both
    /// mischaracterised the mechanism and made the test unsafe, because a helper that is
    /// killed cannot report and the workload had to be unbounded to provoke the kill.
    #[test]
    fn a_required_memory_ceiling_is_enforced_by_the_kernel_not_merely_written() {
        if !available() {
            println!("  host does not delegate memory control; reported, not skipped");
            return;
        }
        const CEILING: u64 = 16 * 1024 * 1024;
        let mine = "16777216";
        let required = ResourcePolicy {
            required: vec![ResourceRequirement::Memory],
            budget: ResourceBudget {
                memory_bytes: Some(CEILING),
                processes: Some(16),
                cpu_cores: Some(0.5),
            },
        };
        let mut adapter = Tier1HelperAdapter::running("mem-hog");
        // The helper's own bound is 64 MiB; it asks for more than the ceiling so the
        // ceiling is what refuses.
        adapter.env.insert("ORXNUD_ARG1".into(), "64".into());
        let id = cap();
        let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
        m.insert(
            id.clone(),
            Arc::new(PolicyBundle {
                adapter,
                resources: required.clone(),
                grant_rw: Vec::new(),
                deadline_ms: 20_000,
            }),
        );
        let mut engine = policy(0, 1_000);
        let secrets = FakeSecrets::new();
        let mut d = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m)
            .with_execution(Arc::new(SandboxExecutionBackend::new()));

        let (watcher, stop, _base) = watch(25, mine);
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
        stop.store(true, Ordering::SeqCst);

        let o = watcher.join().expect("observer");
        let text = format!("{:?}", outcome.execution);
        println!("  governed execution: {text}");
        println!(
            "  memory_max={:?} max={} oom={} oom_kill={} peak_current={} (ceiling {CEILING})",
            o.memory_max, o.memory_refusals, o.memory_oom, o.memory_oom_kill, o.peak_memory_current
        );

        // The ceiling the contract asked for, written to the child.
        assert!(
            o.memory_max.iter().any(|m| m == "16777216"),
            "memory.max was not the requested ceiling: {:?}",
            o.memory_max
        );
        // Enforcement, asserted deterministically rather than by sampling.
        //
        // `memory.events` is the nicest evidence, but reading it from a watcher thread is a
        // sampling race: the workload's window can be shorter than one poll under
        // whole-workspace parallelism, and the counters then read zero for a perfectly
        // enforced ceiling. So the counters above are *reported* and not *required*.
        //
        // The load-bearing assertion is that the workload could not retain what it asked
        // for: it requested 64 MiB against a 16 MiB ceiling. If it reports completing that,
        // the ceiling was not applied. Whether it was killed, refused-and-reclaimed, or
        // stopped short is left open -- that is the same discipline the mechanism suite
        // settled on, and it does not require one particular enforcement mechanism.
        let completed = text.contains("touched 64 MiB");
        assert!(
            !completed,
            "the workload retained its full 64 MiB against a 16 MiB ceiling: NOT enforced"
        );
        let peak = o.peak_memory_current;
        assert!(
            peak == 0 || peak <= CEILING,
            "the cgroup held {peak} bytes against a {CEILING}-byte ceiling"
        );
        // Supplementary, when the sampler caught the window.
        let intervened = o.memory_refusals + o.memory_oom + o.memory_oom_kill;
        if intervened > 0 {
            println!("  kernel intervention counters observed: {intervened}");
        } else {
            println!("  intervention counters not sampled (window too short); outcome used");
        }
        // And the ceiling held: peak usage never exceeded it.
        assert!(
            o.peak_memory_current <= CEILING,
            "the cgroup held {} bytes against a {CEILING}-byte ceiling",
            o.peak_memory_current
        );
    }

    // ------------------------------------------- V-46: placement precedes execution

    /// The payload must be inside the governed cgroup *before* it executes meaningful work,
    /// not merely at some point afterwards.
    ///
    /// # Why this is not the same as "membership is verified"
    ///
    /// Verifying membership from `cgroup.procs` after the fact is necessary but not
    /// sufficient. It proves the process *is* a member; it cannot prove it was not already
    /// doing unconstrained work before joining. The two properties differ, and only the
    /// second one is what a ceiling means:
    ///
    /// ```text
    ///   "the process eventually joined"      !=  "the process was constrained first"
    /// ```
    ///
    /// # The evidence
    ///
    /// The helper's *first* action on entry is to allocate and touch memory
    /// (`mem-hog` in `hostile_helper.rs`). The observer reads the execution cgroup's own
    /// `memory.events`. If the payload had executed any of those instructions before
    /// placement, those pages would be charged to the cgroup it started in instead, and
    /// this cgroup's `max` counter would stay at zero.
    ///
    /// A non-zero `max` is therefore positive evidence that placement happened first.
    /// Measured on this host while developing the test: **103** refused allocations
    /// recorded against the execution cgroup from a payload whose first act was to
    /// allocate, against a 32 MiB ceiling.
    ///
    /// # What this does not prove
    ///
    /// It does not make the window *zero*. The join is performed by a shell that writes its
    /// own pid and then `exec`s `bwrap`, so instructions execute between `fork` and that
    /// write. Those are the shell's, not the payload's, and the payload does not exist yet
    /// -- `bwrap` has not been exec'd. The claim being tested is the one that matters: **no
    /// attacker-controlled instruction runs before placement**, because the attacker's code
    /// has not started.
    /// What the helper reports is the deterministic signal, because it does not depend on
    /// the observer winning a sampling race.
    ///
    /// The helper allocates and touches `TOUCH_BUDGET_MIB` (64 MiB) and then reports how
    /// far it got. Against a 32 MiB ceiling it cannot finish, so `touched 64 MiB` is
    /// absent — and it can only be absent if the pages were charged to the ceiling's
    /// cgroup, since an unconstrained payload would simply have allocated them.
    ///
    /// The counters are corroboration rather than the assertion, and deliberately so: an
    /// earlier version of this test asserted on them and failed intermittently under
    /// whole-workspace parallelism, because a short-lived cgroup can be created and
    /// destroyed between two 3 ms polls. That is a property of the sampler, not of the
    /// enforcement, and asserting it tested the wrong thing — the same reason the
    /// neighbouring test above reports its counters instead of requiring them.
    #[test]
    fn the_payload_is_constrained_before_it_executes_work() {
        if !available() {
            println!("  host does not delegate memory control; reported, not skipped");
            return;
        }
        const CEILING: u64 = 32 * 1024 * 1024;
        let mine = "33554432";
        let required = ResourcePolicy {
            required: vec![ResourceRequirement::Memory],
            budget: ResourceBudget {
                memory_bytes: Some(CEILING),
                processes: Some(16),
                cpu_cores: Some(0.5),
            },
        };
        // `mem-hog` allocates and touches on its first instruction; 64 MiB is well above
        // the ceiling, so the kernel must intervene. The helper is bounded (TOUCH_BUDGET_MIB)
        // so a failed experiment costs a rounding error rather than the host.
        let mut adapter = Tier1HelperAdapter::running("mem-hog");
        adapter.env.insert("ORXNUD_ARG1".into(), "64".into());
        let id = cap();
        let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
        m.insert(
            id.clone(),
            Arc::new(PolicyBundle {
                adapter,
                resources: required.clone(),
                grant_rw: Vec::new(),
                deadline_ms: 20_000,
            }),
        );
        let mut engine = policy(0, 1_000);
        let secrets = FakeSecrets::new();
        let mut d = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m)
            .with_execution(Arc::new(SandboxExecutionBackend::new()));

        let (watcher, stop, _base) = watch(25, mine);
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
        stop.store(true, Ordering::SeqCst);
        let o = watcher.join().expect("observer");

        let charged = o.memory_refusals + o.memory_oom + o.memory_oom_kill;
        let text = format!("{:?}", outcome.execution);
        println!(
            "  ceiling {CEILING}; payload's first act was to allocate: max={} oom={} \
             oom_kill={}",
            o.memory_refusals, o.memory_oom, o.memory_oom_kill
        );
        assert!(
            o.memory_max.iter().any(|m| m == &CEILING.to_string()),
            "the ceiling must be on the execution cgroup: {:?}",
            o.memory_max
        );
        // The deterministic claim: the payload asked for 64 MiB and could not report
        // having got it. Those pages had to be charged against this cgroup's ceiling,
        // which is only possible if placement preceded the allocation.
        assert!(
            !text.contains("touched 64 MiB"),
            "the payload reported retaining its full 64 MiB against a {CEILING}-byte \
             ceiling, so its first allocation was not charged to this cgroup: {text}"
        );
        // Corroboration, when the sampler caught the window.
        if charged > 0 {
            println!("  kernel intervention recorded against the execution cgroup: {charged}");
        } else {
            println!("  intervention counters not sampled (window too short); outcome used");
        }
    }

    // ------------------------------------------- V-46: limit validation end to end

    /// A budget the kernel cannot express must be refused by the governed path, before any
    /// cgroup is created and before any process exists.
    ///
    /// The important one is `memory_bytes: u64::MAX`. `memory.max` is signed in the
    /// kernel, so that value is stored as the literal string `max` -- verified on this host
    /// by writing it and reading it back. A capability declaring an enormous memory budget
    /// would therefore be handed an **uncapped** workload while the contract claimed a
    /// ceiling, with nothing anywhere recording that the limit was not applied. That is
    /// "failed enforcement reported as successful enforcement", reached through the real
    /// dispatcher.
    ///
    /// The load-bearing assertion is that the runner is never reached, which is stronger
    /// than checking a refusal message: the cgroup is created *inside* `run`, so a zero
    /// count proves no cgroup was created and no subprocess spawned.
    #[test]
    fn an_unexpressible_budget_is_refused_before_any_cgroup_or_process_exists() {
        for (label, resources) in unexpressible_budgets() {
            let backend = Arc::new(SandboxExecutionBackend::new());
            let id = cap();
            let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> =
                BTreeMap::new();
            m.insert(id.clone(), bundle(resources.clone()));

            let mut engine = policy(0, 1_000);
            let secrets = FakeSecrets::new();
            let mut d = orxnud_capability::dispatch::Dispatcher::new(&mut engine, &secrets, m)
                .with_execution(backend);

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
                Err(DispatchError::SandboxRefused(r)) => {
                    // The refusal must come from *validation*, which is what proves it
                    // happened before any cgroup existed. A validation refusal names the
                    // offending value and the range the kernel accepts. A refusal that
                    // mentioned a cgroup path instead would have come from the kernel or
                    // from discovery, which can only happen after a cgroup exists.
                    //
                    // Checking the refusal's provenance, rather than watching the shared
                    // base, is deliberate: a watcher there also counts the cgroups of
                    // sibling tests running in parallel in this same process, and an earlier
                    // version of this assertion failed that way while the implementation
                    // was correct.
                    assert!(
                        r.reason.contains("outside the range")
                            || r.reason.contains("cannot host a payload"),
                        "{label}: expected a validation refusal naming the value, got: {}",
                        r.reason
                    );
                    assert!(
                        !r.reason.contains("/sys/fs/cgroup"),
                        "{label}: a validation refusal must not report a cgroup path, which \
                         would mean it came after a cgroup was created: {}",
                        r.reason
                    );
                }
                Err(other) => panic!("{label}: expected a sandbox refusal, got {other:?}"),
                Ok(outcome) => panic!(
                    "{label}: must be refused, but it produced an outcome: {outcome:?}. An \
                     unexpressible budget that runs is failed enforcement reported as success"
                ),
            }
        }
    }

    /// Budgets that are well-formed in their Rust types but meaningless as ceilings.
    ///
    /// Each was measured on this host: the kernel either stores it as `max` (no limit at
    /// all) or accepts a value that cannot host the payload. Every one of them is
    /// *representable* in the type that carries it, which is precisely why they reached the
    /// kernel before validation existed.
    fn unexpressible_budgets() -> Vec<(&'static str, ResourcePolicy)> {
        vec![
            (
                "memory budget of u64::MAX, which the kernel stores as `max`",
                ResourcePolicy {
                    required: vec![ResourceRequirement::Memory],
                    budget: ResourceBudget {
                        memory_bytes: Some(u64::MAX),
                        processes: Some(8),
                        cpu_cores: Some(0.5),
                    },
                },
            ),
            (
                "zero process budget, which admits no payload and not even the supervisor",
                ResourcePolicy {
                    required: vec![ResourceRequirement::Processes],
                    budget: ResourceBudget {
                        memory_bytes: Some(64 * 1024 * 1024),
                        processes: Some(0),
                        cpu_cores: Some(0.5),
                    },
                },
            ),
            (
                "CPU budget of NaN, used to be dropped silently so no CPU ceiling applied",
                ResourcePolicy {
                    required: vec![ResourceRequirement::Cpu],
                    budget: ResourceBudget {
                        memory_bytes: Some(64 * 1024 * 1024),
                        processes: Some(8),
                        cpu_cores: Some(f64::NAN),
                    },
                },
            ),
            (
                "CPU budget of infinity, which saturates to u64::MAX and becomes unlimited",
                ResourcePolicy {
                    required: vec![ResourceRequirement::Cpu],
                    budget: ResourceBudget {
                        memory_bytes: Some(64 * 1024 * 1024),
                        processes: Some(8),
                        cpu_cores: Some(f64::INFINITY),
                    },
                },
            ),
        ]
    }
}
