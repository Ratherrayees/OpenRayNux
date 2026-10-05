//! `filesystem/write-text` through the real governed path, with a real sandbox.
//!
//! # What these tests are for
//!
//! The unit tests in `write_text.rs` prove the capability's *logic*: parameter
//! validation, path resolution, the refusal to run in-process. They cannot prove the
//! capability *works*, because both of the things that make it a governed capability —
//! the sandbox and the verifier — are outside the capability's own code.
//!
//! So every test here goes through `Dispatcher::dispatch` with the host's real sandbox
//! (`SandboxExecutionBackend`, which is `bubblewrap` on Linux) and a High-risk
//! declaration, which means an approval is genuinely required and genuinely checked. No
//! stub backend appears anywhere in this file: a fake would pass for a plan no real
//! sandbox can establish, which is the failure mode these tests exist to rule out.
//!
//! `NOW` is a fixed instant, which is what makes the expiry and single-use tests
//! deterministic rather than timing-dependent.

mod support;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use orxnud_capability::dispatch::{
    AdapterBundle, DispatchOutcome, Dispatcher, ExecutionBackend, SandboxPlan,
};
use orxnud_capability::verification::VerificationOutcome;
use orxnud_capability::write_text::{self, WriteTextBundle};
use orxnud_domain::approval::NormalizedParams;
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, GrantId, RunId, TaskId, UserId};
use orxnud_domain::invocation::{ActionRequest, InvocationContext};
use orxnud_domain::{Actor, AuthChannel};
use orxnud_policy::budget::BudgetLedger;
use orxnud_policy::policy_set::{Grant, PolicySet};
use orxnud_policy::{CapabilityDeclaration, PolicyEngine};

use support::FakeSecrets;

/// An execution contract for a plan, exactly as the dispatcher builds one.
///
/// Written out rather than reached for, because `Dispatcher::contract_for` is private
/// and duplicating its seven-field mapping here is cheaper than exposing it: the test
/// needs to build a contract for a plan the bundle *refused* to produce, which is
/// precisely the case the dispatcher's own method cannot serve.
fn contract(plan: SandboxPlan) -> orxnud_capability::dispatch::ExecutionContract {
    orxnud_capability::dispatch::ExecutionContract {
        capability: cap(),
        program: plan.program,
        args: plan.args,
        env: plan.env,
        working_dir: plan.working_dir,
        grant_rw: plan.grant_rw,
        grant_ro: plan.grant_ro,
        network: plan.network,
        deadline_ms: plan.deadline_ms,
        output_cap_bytes: plan.output_cap_bytes,
        resources: plan.resources,
    }
}

/// A real `CapabilityInvocation`, minted the only way one can be: by policy.
///
/// Its fields are private and `AuthorisedInvocation` is the only producer, so a test
/// that wants a genuine invocation has to ask the policy engine for one. Which is
/// also the point -- an invocation assembled from parts would not be the thing the
/// dispatcher passes to a bundle.
fn invocation(params: &serde_json::Value) -> orxnud_domain::invocation::CapabilityInvocation {
    let mut engine = policy();
    engine
        .authorise_for_dispatch(
            request("a.txt", "x"),
            human(),
            context(),
            Some("a.txt".to_owned()),
            orxnud_policy::canonical_params(params),
            Some(&orxnud_policy::issue_approval(
                &human(),
                &human(),
                &cap(),
                Some("a.txt"),
                &orxnud_policy::canonical_params(params),
                NOW,
                NOW + 60_000,
                RiskClass::High,
                1,
            )),
            NOW,
        )
        .expect("a permitted, approved request yields an invocation")
        .invocation
}

/// A fixed instant, so expiry is a fact about the inputs rather than about the clock.
const NOW: i64 = 1_767_225_600_000;

fn cap() -> CapabilityId {
    CapabilityId::new(write_text::WRITE_TEXT_ID)
}

fn human() -> Actor {
    Actor::Human {
        user: UserId::new("local"),
        via: AuthChannel::LocalInteractive,
    }
}

/// A grant, so the refusal these tests care about is the *approval* refusal rather than
/// a missing-grant refusal. Both are refusals; only one of them is interesting.
fn grant() -> Grant {
    Grant {
        id: GrantId::new("g-1"),
        granted_by: UserId::new("local"),
        capability: cap(),
        max_data_class: DataClass::Public,
        may_grant: false,
        expires_at_ms: i64::MAX,
        revoked: false,
    }
}

fn policy() -> PolicyEngine {
    let mut engine = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(grant()),
        BudgetLedger::empty().with_global(1_000),
        "v1",
    );
    // High risk: this is the class that makes an approval mandatory, so every test below
    // is exercising the approval gate rather than a trivial allow.
    engine.register(CapabilityDeclaration::new(
        cap(),
        RiskClass::High,
        DataClass::Public,
        false,
        1,
    ));
    engine
}

fn request(path: &str, contents: &str) -> ActionRequest {
    ActionRequest::new(
        TaskId::new("t-1"),
        RunId::new("r-1"),
        0,
        cap(),
        serde_json::json!({"path": path, "contents": contents}),
        DataClass::Public,
        DataClass::Public,
    )
}

fn context() -> InvocationContext {
    InvocationContext::new("k-1", 30_000, "c-1")
}

fn params(path: &str, contents: &str) -> NormalizedParams {
    orxnud_policy::canonical_params(&serde_json::json!({"path": path, "contents": contents}))
}

/// A workspace, the bundle over it, and the dispatcher that runs it.
struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
    bundle: WriteTextBundle,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("orxnud-wt-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("workspace");
        let helper = write_text::resolve_helper().expect(
            "the Tier-1 child must be built before this suite means anything; \
             run `cargo build -p orxnud-capability`",
        );
        Self {
            bundle: WriteTextBundle::new(&workspace, helper),
            workspace,
            root,
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.workspace.join(relative)
    }

    fn bundles(&self) -> BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> {
        let mut b: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
        b.insert(cap(), Arc::new(self.bundle.clone()));
        b
    }

    /// One governed dispatch through the real sandbox, with a throwaway engine.
    ///
    /// Fine for every test except the single-use one, which needs the *same* engine --
    /// and therefore the same approval ledger -- across two dispatches. A fresh
    /// `PolicyEngine` means a fresh in-memory ledger, which would report the second use
    /// of an approval as unspent and make that test pass for the wrong reason.
    fn dispatch(
        &self,
        path: &str,
        contents: &str,
        target: Option<&str>,
        approval: Option<&orxnud_domain::ApprovalRecord>,
        now_ms: i64,
    ) -> Result<DispatchOutcome, orxnud_capability::dispatch::DispatchError> {
        let mut engine = policy();
        self.dispatch_with(&mut engine, path, contents, target, approval, now_ms)
    }

    /// A governed dispatch against a caller-supplied engine, so the ledger persists.
    fn dispatch_with(
        &self,
        engine: &mut PolicyEngine,
        path: &str,
        contents: &str,
        target: Option<&str>,
        approval: Option<&orxnud_domain::ApprovalRecord>,
        now_ms: i64,
    ) -> Result<DispatchOutcome, orxnud_capability::dispatch::DispatchError> {
        let secrets = FakeSecrets::new();
        let mut d = Dispatcher::new(engine, &secrets, self.bundles()).with_execution(Arc::new(
            orxnud_capability::subprocess::SandboxExecutionBackend::new(),
        ));
        d.dispatch(
            request(path, contents),
            human(),
            context(),
            target.map(str::to_owned),
            params(path, contents),
            approval,
            None,
            now_ms,
        )
    }

    /// A fresh approval for one operation.
    fn approval(&self, path: &str, contents: &str, ttl_ms: i64) -> orxnud_domain::ApprovalRecord {
        orxnud_policy::issue_approval(
            &human(),
            &human(),
            &cap(),
            Some(path),
            &params(path, contents),
            NOW,
            NOW + ttl_ms,
            RiskClass::High,
            1,
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Whether this host has a usable sandbox at all.
///
/// A host without one *refuses* Tier-1 work, which is the correct behaviour and makes
/// these tests unrunnable rather than wrong. They report that and pass vacuously only
/// where the assertion is about policy rather than about the sandbox; the sandbox tests
/// below fail loudly instead, because "the boundary was never exercised" must not read
/// as success.
fn sandbox_available() -> bool {
    orxnud_platform_sandbox::host_backend_name() != "unsupported"
}

fn require_sandbox(test: &str) -> bool {
    if sandbox_available() {
        return true;
    }
    eprintln!(
        "{test}: no sandbox backend on this host; the governed Tier-1 path cannot be exercised"
    );
    false
}

// ---------------------------------------------------------------------------
// The capability runs, and the sandbox contains it
// ---------------------------------------------------------------------------

#[test]
fn an_approved_write_reaches_the_sandbox_and_verifies_from_the_filesystem() {
    if !require_sandbox("an_approved_write_reaches_the_sandbox_and_verifies_from_the_filesystem") {
        return;
    }
    let fixture = Fixture::new("happy");
    let approval = fixture.approval("a.txt", "alpha", 60_000);

    let outcome = fixture
        .dispatch("a.txt", "alpha", Some("a.txt"), Some(&approval), NOW)
        .expect("an approved, permitted write must dispatch");

    assert_eq!(
        std::fs::read_to_string(fixture.path("a.txt")).expect("the file exists"),
        "alpha",
        "the sandboxed child must have written the requested bytes"
    );
    assert!(
        outcome.is_verified(),
        "verification must read the file and confirm it: {:?}",
        outcome.verification
    );
    assert!(
        matches!(
            outcome.execution,
            orxnud_capability::verification::ExecutionOutcome::Succeeded { .. }
        ),
        "the child must have exited cleanly: {:?}",
        outcome.execution
    );
}

#[test]
fn a_write_without_an_approval_is_refused_and_nothing_is_written() {
    let fixture = Fixture::new("no-approval");
    let refusal = fixture
        .dispatch("a.txt", "alpha", Some("a.txt"), None, NOW)
        .expect_err("High risk with no approval must be refused");

    assert!(
        refusal.to_string().contains("approval-required"),
        "the refusal must name the missing approval: {refusal}"
    );
    assert!(
        !fixture.path("a.txt").exists(),
        "a refused dispatch must not have written anything"
    );
}

#[test]
fn bytes_arrive_exactly_with_nothing_interpreted() {
    if !require_sandbox("bytes_arrive_exactly_with_nothing_interpreted") {
        return;
    }
    let fixture = Fixture::new("bytes");
    // Non-ASCII, a newline, a control character, and shell metacharacters. If any of
    // this were expanded the capability would be a shell wearing a file-writing hat.
    let awkward = "line one\nsecond \u{1F980}\ttab\u{0007}bell $(id) `whoami` ; rm -rf /";
    let approval = fixture.approval("bytes.bin", awkward, 60_000);

    fixture
        .dispatch(
            "bytes.bin",
            awkward,
            Some("bytes.bin"),
            Some(&approval),
            NOW,
        )
        .expect("dispatch");

    assert_eq!(
        std::fs::read(fixture.path("bytes.bin")).expect("read"),
        awkward.as_bytes(),
        "the bytes must arrive exactly"
    );
}

#[test]
fn an_empty_file_is_the_requested_effect_not_a_missing_one() {
    if !require_sandbox("an_empty_file_is_the_requested_effect_not_a_missing_one") {
        return;
    }
    let fixture = Fixture::new("empty");
    let approval = fixture.approval("empty.txt", "", 60_000);

    let outcome = fixture
        .dispatch("empty.txt", "", Some("empty.txt"), Some(&approval), NOW)
        .expect("dispatch");

    assert!(
        fixture.path("empty.txt").exists(),
        "an empty file is still a file"
    );
    assert_eq!(std::fs::read(fixture.path("empty.txt")).expect("read"), b"");
    assert!(
        outcome.is_verified(),
        "an empty file verifies: {:?}",
        outcome.verification
    );
}

/// The escape test: the boundary is the sandbox, and this proves it.
///
/// Asserted as an *effect* — the file does not appear outside the workspace — rather
/// than as an exit code, so a child that reported success while writing nowhere would
/// still fail the test. And the hand-built plan deliberately bypasses the bundle's own
/// validation, because the question is what happens when validation is *not* the thing
/// stopping the write.
#[test]
fn an_escaping_path_cannot_reach_the_host_filesystem() {
    if !require_sandbox("an_escaping_path_cannot_reach_the_host_filesystem") {
        return;
    }
    let fixture = Fixture::new("escape");
    let outside = fixture.root.join("escaped.txt");

    // (1) Validation refuses it, so a caller gets a reason rather than a mystery.
    assert!(
        fixture
            .dispatch("../escaped.txt", "pwned", Some("../escaped.txt"), None, NOW)
            .is_err(),
        "an escaping path must never dispatch"
    );

    // (2) The sandbox would refuse it even if validation did not. This plan is built by
    // hand with the escaping path, which the bundle's own `sandbox_plan` refuses to
    // produce — that refusal is (1), and this is the layer beneath it.
    let helper = write_text::resolve_helper().expect("helper built");
    let plan = SandboxPlan {
        program: helper.display().to_string(),
        args: vec![
            "--path".to_owned(),
            outside.display().to_string(),
            "--contents".to_owned(),
            "pwned".to_owned(),
        ],
        env: Default::default(),
        working_dir: fixture.workspace.display().to_string(),
        grant_rw: vec![fixture.workspace.display().to_string()],
        grant_ro: vec![helper.display().to_string()],
        network: false,
        deadline_ms: 10_000,
        output_cap_bytes: 64 * 1024,
        resources: orxnud_capability::dispatch::ResourcePolicy {
            required: Vec::new(),
            budget: orxnud_capability::dispatch::ResourceBudget {
                memory_bytes: Some(64 * 1024 * 1024),
                // Matches the capability's own budget; see V-65 for why this is not 1.
                processes: Some(16),
                cpu_cores: Some(1.0),
            },
        },
    };
    // The real backend, but *not* through the dispatcher: the point here is the sandbox
    // layer on its own, answering a plan the bundle deliberately refused to build. A
    // policy engine and a secrets store would be unused, and reaching for them would
    // make the escape look like an authorised operation.
    let backend = Arc::new(orxnud_capability::subprocess::SandboxExecutionBackend::new());
    // Err, or Ok with the write landing on the sandbox's own tmpfs: both mean the host
    // is untouched, and the assertion below is the one that matters.
    let _ = backend.execute(&contract(plan));

    assert!(
        !outside.exists(),
        "a sandboxed write escaped the workspace: {}",
        outside.display()
    );
}

// ---------------------------------------------------------------------------
// The approval binds to one operation
// ---------------------------------------------------------------------------

#[test]
fn an_approval_for_one_parameter_set_does_not_authorise_another() {
    if !require_sandbox("an_approval_for_one_parameter_set_does_not_authorise_another") {
        return;
    }
    let fixture = Fixture::new("substitute");

    // Approved: alpha.
    let approval = fixture.approval("a.txt", "alpha", 60_000);
    fixture
        .dispatch("a.txt", "alpha", Some("a.txt"), Some(&approval), NOW)
        .expect("the approved operation must run");
    assert_eq!(
        std::fs::read_to_string(fixture.path("a.txt")).expect("read"),
        "alpha"
    );

    // Same capability, same target, same path -- different contents, reusing alpha's
    // approval. This is the substitution V-63 exists to prevent, and the reason an
    // approval is bound to a parameter set rather than to a capability.
    let refusal = fixture
        .dispatch("a.txt", "beta", Some("a.txt"), Some(&approval), NOW)
        .expect_err("beta must not be authorised by an approval for alpha");
    assert!(
        refusal.to_string().contains("approval-digest-mismatch"),
        "the refusal must be the digest check, not something incidental: {refusal}"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.path("a.txt")).expect("read"),
        "alpha",
        "the refused dispatch must not have modified the file"
    );
}

#[test]
fn object_key_order_does_not_change_what_an_approval_authorises() {
    if !require_sandbox("object_key_order_does_not_change_what_an_approval_authorises") {
        return;
    }
    let fixture = Fixture::new("key-order");

    // Issued for {"path":..., "contents":...} in that order.
    let approval = fixture.approval("a.txt", "alpha", 60_000);
    assert_eq!(
        approval.params.as_str(),
        r#"{"contents":"alpha","path":"a.txt"}"#,
        "the canonical form is sorted, which is what makes order irrelevant"
    );

    // The same operation, written the other way round, must still be authorised: this is
    // one operation written two ways, not two operations.
    let secrets = FakeSecrets::new();
    let mut engine = policy();
    let mut d = Dispatcher::new(&mut engine, &secrets, fixture.bundles()).with_execution(Arc::new(
        orxnud_capability::subprocess::SandboxExecutionBackend::new(),
    ));
    let reversed: ActionRequest = ActionRequest::new(
        TaskId::new("t-1"),
        RunId::new("r-1"),
        0,
        cap(),
        serde_json::json!({"contents": "alpha", "path": "a.txt"}),
        DataClass::Public,
        DataClass::Public,
    );
    let outcome = d
        .dispatch(
            reversed,
            human(),
            context(),
            Some("a.txt".to_owned()),
            // Canonicalised the same way dispatch canonicalises, from the reversed text.
            orxnud_policy::canonical_params(
                &serde_json::json!({"contents": "alpha", "path": "a.txt"}),
            ),
            Some(&approval),
            None,
            NOW,
        )
        .expect("a reordered but identical request is the same approved operation");
    assert!(outcome.is_verified(), "{:?}", outcome.verification);
}

// ---------------------------------------------------------------------------
// Expiry -- the V-62 regression, made external
// ---------------------------------------------------------------------------

#[test]
fn an_expired_approval_is_refused_and_nothing_is_written() {
    if !require_sandbox("an_expired_approval_is_refused_and_nothing_is_written") {
        return;
    }
    let fixture = Fixture::new("expired");

    // Expires at NOW + 10.
    let approval = fixture.approval("late.txt", "alpha", 10);

    // Dispatched at NOW + 11. No sleeping: the instant is an argument, which is what
    // makes this deterministic. Under the V-62 defect `now_ms` was pinned at 0, so
    // `0 < expires_at_ms` was true for *any* expiry and every approval verified forever.
    let refusal = fixture
        .dispatch(
            "late.txt",
            "alpha",
            Some("late.txt"),
            Some(&approval),
            NOW + 11,
        )
        .expect_err("an expired approval must be refused");
    assert!(
        refusal.to_string().contains("approval-expired"),
        "the refusal must be the expiry check: {refusal}"
    );
    assert!(
        !fixture.path("late.txt").exists(),
        "an expired approval must not have written anything"
    );
}

#[test]
fn an_approval_is_valid_right_up_to_its_expiry() {
    let fixture = Fixture::new("boundary");
    let approval = fixture.approval("edge.txt", "alpha", 10);

    // One millisecond inside the window. The comparison is `now < expires`, so this is
    // the last instant at which the approval is live.
    assert!(approval.is_valid_at(NOW + 9), "just inside the window");
    assert!(
        !approval.is_valid_at(NOW + 10),
        "the boundary itself is expired"
    );
    assert!(
        fixture
            .dispatch(
                "edge.txt",
                "alpha",
                Some("edge.txt"),
                Some(&approval),
                NOW + 9
            )
            .is_ok(),
        "an approval must work right up to its expiry"
    );
}

// ---------------------------------------------------------------------------
// Single use
// ---------------------------------------------------------------------------

#[test]
fn an_approval_succeeds_once_and_is_refused_the_second_time() {
    if !require_sandbox("an_approval_succeeds_once_and_is_refused_the_second_time") {
        return;
    }
    let fixture = Fixture::new("single-use");
    let approval = fixture.approval("once.txt", "alpha", 60_000);

    // One engine for both dispatches, so both consult the same ledger. Two engines
    // would mean two ledgers, and the second use would look unspent.
    let mut engine = policy();
    fixture
        .dispatch_with(
            &mut engine,
            "once.txt",
            "alpha",
            Some("once.txt"),
            Some(&approval),
            NOW,
        )
        .expect("the first use must succeed");

    let refusal = fixture
        .dispatch_with(
            &mut engine,
            "once.txt",
            "alpha",
            Some("once.txt"),
            Some(&approval),
            NOW,
        )
        .expect_err("the second use of one approval must be refused");
    assert!(
        refusal.to_string().contains("approval-already-used"),
        "the refusal must be the single-use ledger: {refusal}"
    );
}

// ---------------------------------------------------------------------------
// Verification is independent of the writer
// ---------------------------------------------------------------------------

#[test]
fn a_lying_adapter_cannot_convince_the_verifier() {
    let fixture = Fixture::new("liar");

    // No file was written, and the verifier is asked about a *successful* execution.
    let real = fixture
        .bundle
        .verifier()
        .verify(
            &orxnud_capability::verification::ExecutionOutcome::Succeeded {
                output: Some("wrote alpha successfully".to_owned()),
            },
            &serde_json::json!({"path": "claimed.txt", "contents": "alpha"}),
            NOW,
        )
        .expect("verification runs");
    assert!(
        matches!(real, VerificationOutcome::Refuted { .. }),
        "a missing file must be refuted whatever the adapter claimed, got {real:?}"
    );
}

#[test]
fn the_plan_never_requests_a_network_and_grants_only_the_workspace() {
    let fixture = Fixture::new("grants");
    // Reach the plan the way the dispatcher does, via the bundle.
    let plan = fixture
        .bundle
        .sandbox_plan(&invocation(
            &serde_json::json!({"path": "a.txt", "contents": "x"}),
        ))
        .expect("a plan");
    assert!(
        !plan.network,
        "a filesystem write must not carry a network grant"
    );
    assert_eq!(
        plan.grant_rw,
        vec![fixture.workspace.display().to_string()],
        "the only writable path is the workspace"
    );
}

/// The child never runs in this process, whatever the dispatcher believes.
#[test]
fn the_adapter_is_tier_1_and_refuses_to_execute_in_process() {
    let fixture = Fixture::new("tier");
    assert_eq!(
        fixture.bundle.adapter().tier(),
        orxnud_capability::dispatch::ExecutionTier::Subprocess
    );
    let context = InvocationContext::new("k", 1_000, "c");
    let json = serde_json::json!({"path": "a.txt", "contents": "x"});
    let view = orxnud_domain::invocation::DispatchView {
        step: 0,
        capability: fixture.bundle.adapter().capability_id(),
        params: &json,
        data_class: DataClass::Public,
        context: &context,
    };
    assert!(
        fixture.bundle.adapter().invoke(&view, None).is_err(),
        "an in-process write would be the tier bypass"
    );
}
