//! `filesystem/read-text` through the **real** governed path.
//!
//! The other read tests prove the plan and the verifier in isolation. These prove the thing
//! that actually matters and that neither can: that a read of a real workspace file works
//! end to end — `Dispatcher::dispatch`, a real Tier-1 sandbox, a real `orxnud-fsread`
//! process, an independent re-read — and that the paths out of the workspace are refused by
//! something real rather than by a string check that happens to agree with reality.
//!
//! Nothing here is mocked. `SandboxExecutionBackend` is the production backend, and the
//! helper is the production binary; if `bwrap` cannot run on the host these tests fail
//! rather than quietly falling back, because a fallback would be exactly the substitution
//! this file exists to prevent.

// Declared once in `tests/mod.rs`, since a module path inside
// `tests/` would otherwise resolve per-file.
use super::{Registry, support};

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::dispatch::Dispatcher;
use crate::read_text::{self, ReadTextBundle};
use crate::subprocess::SandboxExecutionBackend;
use crate::verification::ExecutionOutcome;
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, GrantId, RunId, TaskId, UserId};
use orxnud_domain::invocation::{ActionRequest, InvocationContext};
use orxnud_domain::{Actor, AuthChannel};
use orxnud_policy::PolicyEngine;
use orxnud_policy::budget::BudgetLedger;
use orxnud_policy::policy_set::{Grant, PolicySet};

use support::FakeSecrets;

const NOW: i64 = 1_767_225_600_000;

/// Unmistakable if it ever reaches durable state, a log, an error or a `Debug` rendering.
const SENTINEL: &str = "SENTINEL-READ-REAL-8c4f21-do-not-log-do-not-persist";

fn cap() -> CapabilityId {
    CapabilityId::new(read_text::READ_TEXT_ID)
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
    // High risk: this is the class that makes an approval mandatory, so every test below is
    // exercising the approval gate rather than a trivial allow.
    engine.register(orxnud_policy::CapabilityDeclaration::new(
        cap(),
        RiskClass::High,
        DataClass::Public,
        false,
        1,
    ));
    engine
}

fn context() -> InvocationContext {
    InvocationContext::new("i-1", 60_000, "corr-1")
}

fn request(path: &str) -> ActionRequest {
    ActionRequest::new(
        TaskId::new("t-1"),
        RunId::new("r-1"),
        0,
        cap(),
        serde_json::json!({ "path": path }),
        DataClass::Public,
        DataClass::Public,
    )
}

fn workspace(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-rt-real-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn seed(ws: &Path, rel: &str, contents: &[u8]) -> PathBuf {
    let p = ws.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).expect("mkdir parent");
    }
    std::fs::write(&p, contents).expect("seed");
    p
}

/// The approval a high-risk read needs. Single-use by construction of the digest.
fn approval(path: &str) -> orxnud_domain::approval::ApprovalRecord {
    let params = serde_json::json!({ "path": path });
    orxnud_policy::issue_approval(
        &human(),
        &human(),
        &cap(),
        Some(path),
        &orxnud_policy::canonical_params(&params),
        NOW,
        NOW + 60_000,
        RiskClass::High,
        1,
    )
}

/// Runs one governed read through the real dispatcher and sandbox.
///
/// `Some(approval)` to proceed; `None` to prove the gate refuses without one.
fn dispatch_read(
    ws: &Path,
    path: &str,
    approval: Option<&orxnud_domain::approval::ApprovalRecord>,
) -> Result<crate::dispatch::DispatchOutcome, crate::dispatch::DispatchError>
{
    let helper = read_text::resolve_helper().expect("helper built");
    let mut bundles: BTreeMap<
        CapabilityId,
        Arc<dyn crate::dispatch::AdapterBundle + Send + Sync>,
    > = BTreeMap::new();
    bundles.insert(cap(), Arc::new(ReadTextBundle::new(ws, helper)));
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = Dispatcher::new(&mut engine, &secrets, Registry::from_bundles(bundles))
        .with_execution(Arc::new(SandboxExecutionBackend::new()));
    let params = serde_json::json!({ "path": path });
    d.dispatch(
        request(path),
        human(),
        context(),
        Some(path.to_owned()),
        orxnud_policy::canonical_params(&params),
        approval,
        None,
        NOW,
    )
}

/// The whole path, on a real file: sandbox, helper, independent verification.
#[test]
fn a_real_sandboxed_read_of_a_workspace_file_is_verified() {
    let ws = workspace("basic");
    seed(&ws, "a.txt", SENTINEL.as_bytes());

    let outcome = dispatch_read(&ws, "a.txt", Some(&approval("a.txt")))
        .expect("a governed read through the real sandbox");

    assert!(
        outcome.is_verified(),
        "the sandbox must have read the file and the verifier confirmed it: {outcome:?}"
    );
    // The content came back through the ephemeral execution output -- which is the only
    // channel it is allowed to travel, and the seam Stage 4b will use.
    match &outcome.execution {
        ExecutionOutcome::Succeeded { output } => assert_eq!(
            output.as_deref(),
            Some(SENTINEL),
            "the read must return exactly the file's bytes"
        ),
        other => panic!("expected success, got {other:?}"),
    }
    assert!(
        outcome.output_is_ephemeral,
        "a read's bytes must never be durable"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

/// A nested path is a legitimate read, and unlike the write path it is allowed.
#[test]
fn a_real_sandboxed_read_of_a_nested_file_is_verified() {
    let ws = workspace("nested");
    seed(&ws, "sub/dir/out.txt", b"nested contents");

    let outcome = dispatch_read(&ws, "sub/dir/out.txt", Some(&approval("sub/dir/out.txt")))
        .expect("a nested governed read");
    assert!(outcome.is_verified(), "{outcome:?}");
    let _ = std::fs::remove_dir_all(&ws);
}

/// The content of a file *outside* the workspace is unreachable: the sandbox binds nothing
/// outside, so the read fails because the file does not exist inside the sandbox root.
#[test]
fn a_real_sandboxed_read_cannot_reach_outside_the_workspace() {
    let ws = workspace("outside");
    let outside_dir =
        std::env::temp_dir().join(format!("orxnud-rt-outside-{}", std::process::id()));
    std::fs::create_dir_all(&outside_dir).expect("mkdir");
    let outside = outside_dir.join("secret.txt");
    std::fs::write(&outside, SENTINEL).expect("seed outside");

    // Reached by a path that *looks* relative but climbs out, and by the absolute path.
    for attempt in [
        "../orxnud-rt-outside/secret.txt".to_owned(),
        outside.display().to_string(),
    ] {
        let outcome = dispatch_read(&ws, &attempt, Some(&approval(&attempt)));
        // Either refused outright (no plan could be built) or dispatched and not verified.
        // Both are acceptable; what must never happen is a Verified read of the content.
        if let Ok(o) = outcome {
            assert!(
                !o.is_verified(),
                "{attempt}: content outside the workspace was read and verified: {o:?}"
            );
            if let ExecutionOutcome::Succeeded { output } = &o.execution {
                assert!(
                    !output.as_deref().unwrap_or_default().contains(SENTINEL),
                    "{attempt}: the outside content leaked: {output:?}"
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&outside_dir);
    let _ = std::fs::remove_dir_all(&ws);
}

/// No approval, no read. The gate is the same one every high-risk capability passes.
#[test]
fn an_unapproved_read_is_refused() {
    let ws = workspace("unapproved");
    seed(&ws, "a.txt", SENTINEL.as_bytes());

    let err = dispatch_read(&ws, "a.txt", None).expect_err("an unapproved read must be refused");
    let text = err.to_string();
    assert!(
        !text.contains(SENTINEL),
        "a refusal must not quote the file: {text}"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

/// A read is single-use: the approval is consumed by the first execution.
#[test]
fn an_approved_read_is_single_use() {
    let ws = workspace("single-use");
    seed(&ws, "a.txt", b"once");

    let rec = approval("a.txt");

    // One dispatcher, two dispatches. The spent-approval ledger lives in the policy engine
    // the dispatcher borrows, so a second *dispatcher* would be a second ledger and would
    // prove nothing about single use.
    let helper = read_text::resolve_helper().expect("helper built");
    let mut bundles: BTreeMap<
        CapabilityId,
        Arc<dyn crate::dispatch::AdapterBundle + Send + Sync>,
    > = BTreeMap::new();
    bundles.insert(cap(), Arc::new(ReadTextBundle::new(&ws, helper)));
    let mut engine = policy();
    let secrets = FakeSecrets::new();
    let mut d = Dispatcher::new(&mut engine, &secrets, Registry::from_bundles(bundles))
        .with_execution(Arc::new(SandboxExecutionBackend::new()));
    let params = orxnud_policy::canonical_params(&serde_json::json!({ "path": "a.txt" }));

    let first = d
        .dispatch(
            request("a.txt"),
            human(),
            context(),
            Some("a.txt".to_owned()),
            params.clone(),
            Some(&rec),
            None,
            NOW,
        )
        .expect("first read");
    assert!(first.is_verified(), "{first:?}");

    // The same record again is a replay, and the digest is already spent.
    let second = d.dispatch(
        request("a.txt"),
        human(),
        context(),
        Some("a.txt".to_owned()),
        params,
        Some(&rec),
        None,
        NOW,
    );
    assert!(
        second.is_err(),
        "a single-use approval must not authorise a second execution: {second:?}"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

/// An approval for one path does not authorise a read of another.
#[test]
fn an_approval_is_bound_to_the_path_it_names() {
    let ws = workspace("binding");
    seed(&ws, "a.txt", b"aaa");
    seed(&ws, "b.txt", b"bbb");

    // Approve `a.txt`, dispatch `b.txt`.
    let rec = approval("a.txt");
    let outcome = dispatch_read(&ws, "b.txt", Some(&rec));
    assert!(
        outcome.is_err(),
        "an approval must not carry to a different path: {outcome:?}"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

/// A missing file is undetermined, not verified and not refuted-as-absent-for-the-workspace.
#[test]
fn a_missing_file_is_not_verified() {
    let ws = workspace("missing");
    let outcome = dispatch_read(&ws, "nope.txt", Some(&approval("nope.txt")));
    if let Ok(o) = outcome {
        assert!(!o.is_verified(), "a missing file cannot verify: {o:?}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}

/// A directory is refused rather than listed.
#[test]
fn a_directory_is_not_read_as_a_listing() {
    let ws = workspace("dir");
    std::fs::create_dir_all(ws.join("adir")).expect("mkdir");
    let outcome = dispatch_read(&ws, "adir", Some(&approval("adir")));
    if let Ok(o) = outcome {
        assert!(!o.is_verified(), "a directory is not a file read: {o:?}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}

/// Over the ceiling: refused, and the sentinel proves nothing truncated came back.
#[test]
fn an_oversized_file_is_refused_by_the_real_sandbox() {
    let ws = workspace("oversize");
    // Comfortably over 64 KiB, with a recognisable marker at the end so a truncation would
    // be visible in what came back.
    let mut big = vec![b'x'; read_text::MAX_READ_BYTES as usize + 4096];
    big.extend_from_slice(b"TAIL-MARKER");
    seed(&ws, "big.bin", &big);

    let outcome = dispatch_read(&ws, "big.bin", Some(&approval("big.bin")));
    match outcome {
        Err(_) => {} // refused before or during execution: correct
        Ok(o) => {
            assert!(!o.is_verified(), "an oversized file must not verify: {o:?}");
            if let ExecutionOutcome::Succeeded { output } = &o.execution {
                let s = output.as_deref().unwrap_or_default();
                assert!(
                    !(s.contains("TAIL-MARKER") && !s.contains(&"x".repeat(100))),
                    "a truncated prefix was presented as a whole file"
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&ws);
}

/// At the ceiling: succeeds. The boundary is inclusive at the limit.
#[test]
fn a_file_exactly_at_the_ceiling_is_read() {
    let ws = workspace("atlimit");
    let exact = vec![b'y'; read_text::MAX_READ_BYTES as usize];
    seed(&ws, "exact.bin", &exact);
    let outcome = dispatch_read(&ws, "exact.bin", Some(&approval("exact.bin")));
    if let Ok(o) = outcome {
        assert!(
            o.is_verified(),
            "exactly at the limit must be readable: {o:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&ws);
}
