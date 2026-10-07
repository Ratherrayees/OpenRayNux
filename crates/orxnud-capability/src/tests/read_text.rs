//! The sandbox contract for `filesystem/read-text`.
//!
//! The capability's own unit tests cover parsing, path rules, the size ceiling and the
//! verifier. What needs a *real* invocation is the plan -- the sandbox contract -- because a
//! `CapabilityInvocation` can only be minted through policy, and a plan assembled from parts
//! would not be the thing the dispatcher hands to the backend.
//!
//! The property under test is the one that makes this capability safe by construction rather
//! than by convention: **it is granted nothing writable.** `write-text` binds the workspace
//! read-write because it writes; a read that were granted the same could be talked into
//! writing, regardless of what the helper binary does.

use std::path::PathBuf;

use crate::dispatch::{AdapterBundle, SandboxPlan};
use crate::read_text::{self, ReadTextBundle};
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, GrantId, RunId, TaskId, UserId};
use orxnud_domain::invocation::{ActionRequest, CapabilityInvocation, InvocationContext};
use orxnud_domain::{Actor, AuthChannel};
use orxnud_policy::PolicyEngine;
use orxnud_policy::budget::BudgetLedger;
use orxnud_policy::policy_set::{Grant, PolicySet};

const NOW: i64 = 1_767_225_600_000;

fn cap() -> CapabilityId {
    CapabilityId::new(read_text::READ_TEXT_ID)
}

fn human() -> Actor {
    Actor::Human {
        user: UserId::new("local"),
        via: AuthChannel::LocalInteractive,
    }
}

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

/// A genuine invocation, minted the only way one can be.
fn invocation(path: &str) -> CapabilityInvocation {
    let params = serde_json::json!({ "path": path });
    let mut engine = policy();
    engine
        .authorise_for_dispatch(
            request(path),
            human(),
            context(),
            Some(path.to_owned()),
            orxnud_policy::canonical_params(&params),
            Some(&orxnud_policy::issue_approval(
                &human(),
                &human(),
                &cap(),
                Some(path),
                &orxnud_policy::canonical_params(&params),
                NOW,
                NOW + 60_000,
                RiskClass::High,
                1,
            )),
            NOW,
        )
        .expect("a permitted, approved read yields an invocation")
        .invocation
}

fn workspace(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orxnud-fsread-plan-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn plan_for(ws: &PathBuf, path: &str) -> Option<SandboxPlan> {
    let bundle = ReadTextBundle::new(ws, "/nonexistent/orxnud-fsread");
    bundle.sandbox_plan(&invocation(path))
}

/// The load-bearing one: a read capability is granted **nothing** writable.
///
/// Stated as a property of the plan rather than of the helper, because the helper is a
/// program that could be changed. The sandbox is the boundary, and this is the boundary's
/// configuration for a capability whose declared effect is disclosure and nothing else.
#[test]
fn a_read_plan_is_granted_nothing_writable() {
    let ws = workspace("rw");
    for path in ["a.txt", "sub/dir/a.txt"] {
        let plan = plan_for(&ws, path).unwrap_or_else(|| panic!("a plan for {path}"));
        assert!(
            plan.grant_rw.is_empty(),
            "{path}: a read must be granted nothing writable, got {:?}",
            plan.grant_rw
        );
        assert!(
            plan.grant_ro.iter().any(|g| g == &ws.display().to_string()),
            "{path}: the workspace must be readable, got {:?}",
            plan.grant_ro
        );
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_read_plan_has_no_network_and_no_environment() {
    let ws = workspace("net");
    let plan = plan_for(&ws, "a.txt").expect("a plan");
    assert!(!plan.network, "reading a local file needs no network");
    assert!(
        plan.env.is_empty(),
        "a child that needs nothing from the environment should be offered none: {:?}",
        plan.env
    );
    let _ = std::fs::remove_dir_all(&ws);
}

/// The helper is passed one flag. No shell, no second verb, no way to express "and then".
#[test]
fn the_helper_is_given_only_the_path() {
    let ws = workspace("argv");
    let plan = plan_for(&ws, "sub/a.txt").expect("a plan");
    assert_eq!(
        plan.args.len(),
        2,
        "argv is the whole vocabulary: {:?}",
        plan.args
    );
    assert_eq!(plan.args[0], "--path");
    assert!(
        plan.args[1].ends_with("sub/a.txt"),
        "an absolute workspace path: {:?}",
        plan.args[1]
    );
    let _ = std::fs::remove_dir_all(&ws);
}

/// Defence in depth, validator layer: no plan can even be built for a path outside the
/// workspace, so the sandbox is never handed a target it would have to refuse.
#[test]
fn no_plan_is_built_for_a_path_outside_the_workspace() {
    let ws = workspace("escape");
    for escape in [
        "/etc/passwd".to_owned(),
        "/etc/hostname".to_owned(),
        "../escape.txt".to_owned(),
        "a/../../escape.txt".to_owned(),
        "sub/../../../escape.txt".to_owned(),
    ] {
        assert!(
            plan_for(&ws, &escape).is_none(),
            "no plan may be built for {escape:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_nested_read_does_produce_a_plan() {
    let ws = workspace("nested");
    assert!(
        plan_for(&ws, "sub/dir/out.txt").is_some(),
        "a nested workspace read is legitimate and must be runnable"
    );
    let _ = std::fs::remove_dir_all(&ws);
}

/// The capability's declared governance, asserted where the registry sees it.
#[test]
fn the_read_capability_is_declared_for_approval_not_autonomy() {
    let d = read_text::declaration();
    assert_eq!(d.risk, RiskClass::High, "reading is disclosure");
    assert_eq!(d.reads, DataClass::Public);
    assert_eq!(d.writes, DataClass::Public);
    assert!(
        !d.idempotent,
        "no standing permission: idempotence would let a policy grant it once and forever"
    );
    assert!(d.enabled);
}
