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
    fn sandbox_plan(&self) -> Option<SandboxPlan> {
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

fn bundles(a: Tier1HelperAdapter) -> BTreeMap<CapabilityId, Arc<dyn AdapterBundle>> {
    let id = a.capability_id().clone();
    let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle>> = BTreeMap::new();
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
    assert_eq!(d.audit_records(), 1, "the authorisation is audited");
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
            _a: i64,
        ) -> Result<VerificationOutcome, VerifyError> {
            Ok(VerificationOutcome::Verified {
                evidence: "ok".into(),
            })
        }
    }

    let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle>> = BTreeMap::new();
    m.insert(
        CapabilityId::new("t0"),
        Arc::new(B0) as Arc<dyn AdapterBundle>,
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
    let m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle>> = BTreeMap::new();
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
    let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle>> = BTreeMap::new();
    m.insert(
        id,
        Arc::new(HelperBundle {
            adapter,
            grants: (
                vec![dir.display().to_string()],
                vec![marker_dir.display().to_string()],
            ),
        }) as Arc<dyn AdapterBundle>,
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

    let m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle>> = BTreeMap::new();
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
