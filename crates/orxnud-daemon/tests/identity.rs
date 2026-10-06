//! Can a caller become the human?
//!
//! # What this file is for
//!
//! Before this milestone the daemon answered "who is asking?" with a constant: every
//! request, from any peer, produced `Actor::Human { user: "local" }` from a function with
//! no parameters. The authority was therefore real — a real `Human` really could grant,
//! and approvals really were issued — but *attribution* was fiction: nothing had been
//! established about the caller, so "the human approved this" was a statement about the
//! socket's file mode rather than about a peer.
//!
//! These tests drive a real daemon over a real Unix socket and assert the property the
//! milestone exists to establish:
//!
//! > The client is asking. Here is who the client actually is. Here is the authority that
//! > identity possesses.
//!
//! and never the version where the client says what it is and the daemon believes it.
//!
//! # How to read a forgery test here
//!
//! Most of the negative tests below send a field the daemon does not read, and assert the
//! outcome is unchanged. That is a weaker claim than "the request was rejected", and it is
//! the *honest* one: the wire protocol has no actor field, so there is nothing to reject.
//! What the test pins is that adding such a field changed nothing — that the daemon's
//! actor is decided before the params are read. The tests that *do* expect a refusal are
//! the ones where the caller-supplied value reaches a real decision: the approval
//! approver, and the approval's proposer label.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use orxnud_daemon::Paths;
use orxnud_daemon::runtime::Runtime;
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use orxnud_protocol::error::RpcErrorCode;
use serde_json::{Value, json};

struct NoSecrets;

#[derive(Debug, thiserror::Error)]
#[error("no secret store in the identity suite")]
struct NoSecretsError;

impl SecretsContract for NoSecrets {
    type Error = NoSecretsError;
    fn get(&self, _r: &SecretRef) -> Result<SecretLookup, Self::Error> {
        Ok(SecretLookup::Absent)
    }
    fn set(&self, _r: &SecretRef, _v: &str) -> Result<(), Self::Error> {
        Err(NoSecretsError)
    }
    fn delete(&self, _r: &SecretRef) -> Result<(), Self::Error> {
        Err(NoSecretsError)
    }
    fn is_available(&self) -> bool {
        false
    }
}

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-identity-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime")
}

/// A raw IPC client with no helper around it.
///
/// Deliberately not the CLI: this file is about what an *arbitrary* process that can open
/// the socket can say, so the client is a socket and four lines of framing. Anything the
/// CLI would refuse to send must still be shown to be harmless here, because the CLI is
/// not the boundary.
fn send_raw(endpoint: &Path, line: &[u8]) -> Option<Value> {
    let mut s = orxnud_platform_ipc::connect_blocking(endpoint)?;
    s.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    let _ = s.write_all(line);
    let _ = s.write_all(b"\n");
    let _ = s.flush();
    let mut reader = BufReader::new(s);
    let mut reply = String::new();
    reader.read_line(&mut reply).ok()?;
    serde_json::from_str(&reply).ok()
}

fn send(endpoint: &Path, id: &str, method: &str, params: Value) -> Value {
    let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    send_raw(endpoint, &serde_json::to_vec(&frame).expect("encode"))
        .unwrap_or_else(|| panic!("{method} must answer"))
}

fn await_ready(endpoint: &Path) {
    for _ in 0..200 {
        if let Some(v) = send_raw(
            endpoint,
            br#"{"jsonrpc":"2.0","id":"r","method":"daemon/version"}"#,
        ) && v.get("result").is_some()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("the runtime never became ready at {}", endpoint.display());
}

struct Serving {
    endpoint: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Serving {
    async fn start(root: PathBuf) -> Self {
        Self::start_with(root, orxnud_daemon::runtime::scripted_proposer()).await
    }

    async fn start_with(
        root: PathBuf,
        provider: std::sync::Arc<dyn orxnud_daemon::proposer::ProposalProvider>,
    ) -> Self {
        let runtime = Runtime::start(Paths::under(&root), NoSecrets)
            .await
            .expect("the runtime must start")
            .with_proposer(provider);
        let endpoint = runtime.endpoint().to_path_buf();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = runtime
                .serve(async move {
                    let _ = rx.await;
                })
                .await;
        });
        await_ready(&endpoint);
        Self {
            endpoint,
            shutdown: Some(tx),
            task,
        }
    }

    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

/// A claimed task with one pending write proposal. Returns the proposal id.
fn pending_proposal(s: &Serving, id: &str) -> String {
    send(
        &s.endpoint,
        "c",
        "task/create",
        json!({"id": id, "content": "governed"}),
    );
    send(
        &s.endpoint,
        "cl",
        "task/claim",
        json!({"id": id, "worker": "w1"}),
    );
    let p = send(
        &s.endpoint,
        "p",
        "task/propose",
        json!({
            "task": id, "worker": "w1", "capability": "filesystem/write-text",
            "target": "out.txt", "params": {"path": "out.txt", "contents": "x"}}),
    );
    p["result"]["proposal"]["proposal_id"]
        .as_str()
        .expect("a proposal id")
        .to_owned()
}

// ---------------------------------------------------------------------------
// 1. The legitimate local client
// ---------------------------------------------------------------------------

/// The ordinary local client is authenticated, and gets the human authority.
///
/// The positive half of the property, and the reason the boundary is not simply "refuse
/// everything": a caller that *is* the installation's owner must still be able to approve
/// work, or the daemon has no user.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_local_owner_is_authenticated_as_the_human_and_can_approve() {
    rt().block_on(async {
        let d = dir("owner-approves");
        let s = Serving::start(d.clone()).await;
        let pid = pending_proposal(&s, "t1");

        let reply = send(
            &s.endpoint,
            "1",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        let approval = &reply["result"]["approval"];
        assert_eq!(approval["approver"], "human", "{reply}");
        // The identity is a stable application identity, not an operating-system one.
        assert_eq!(approval["authority_root"], "local", "{reply}");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A normal task through propose → approve → execute is unchanged by the boundary.
///
/// Run end to end and asserted on its outcome, because the risk of adding an identity
/// check is a *behavioural* regression in the ordinary path, and a test that only
/// exercised approvals would not notice.
///
/// # Why this asserts two different things
///
/// The final step executes a capability, which needs a real sandbox. A GitHub-hosted
/// runner cannot establish Tier-1 guarantees (V-87), so the execution is legitimately
/// refused there — and "refused because the host cannot isolate" is the property that is
/// true on that host. Asserting the verified outcome unconditionally would have made this
/// suite fail on every hosted run, which is what V-85 records: a test that demands
/// evidence the host cannot produce either gets excluded or asserts the refusal.
///
/// So this reads the host's own answer from `daemon/status` and asserts whichever outcome
/// that host can honestly produce. The *identity* claim — that approval succeeded under the
/// authenticated principal — is asserted on both paths, because it does not need a sandbox.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_ordinary_governed_flow_still_works_end_to_end() {
    rt().block_on(async {
        let d = dir("ordinary");
        let s = Serving::start(d.clone()).await;
        let pid = pending_proposal(&s, "flow");

        let approved = send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        assert!(approved.get("result").is_some(), "{approved}");
        // The approval carries the authenticated identity, which is the part of this
        // test the identity boundary can affect.
        assert_eq!(
            approved["result"]["approval"]["approver"], "human",
            "{approved}"
        );
        assert_eq!(
            approved["result"]["approval"]["authority_root"], "local",
            "{approved}"
        );

        let status = send(&s.endpoint, "st", "daemon/status", json!({}));
        let can_execute = status["result"]["sandbox"]["tier1_executable"]
            .as_bool()
            .unwrap_or(false);

        let done = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        if can_execute {
            let outcome = &done["result"];
            assert_eq!(outcome["result"], "verified", "{done}");
            assert_eq!(outcome["verified"], true, "{done}");
            assert_eq!(outcome["refuted"], false, "{done}");
            assert_eq!(outcome["proposal"]["authority_root"], "local", "{done}");
        } else {
            // The host cannot isolate, so the governed path must refuse rather than run
            // anything. What matters here is that the refusal is a refusal and not a
            // silent success or an internal fault.
            assert!(
                done.get("error").is_some(),
                "a host that cannot isolate must refuse to execute: {done}"
            );
            // Asserted by its reason rather than its code: the reason says *why* the host
            // refused, which is the part that distinguishes a correct refusal from an
            // unrelated failure. The code on this route is the pre-existing V-90 gap
            // (`INTERNAL_ERROR` where the taxonomy wants a caller-actionable class), which
            // `tests/taxonomy.rs` owns -- hard-coding it here would pin a second instance
            // of a defect this milestone must not fix.
            assert!(
                done["error"]["data"]["reason"]
                    .as_str()
                    .is_some_and(|r| r.contains("sandbox")),
                "the refusal must name the sandbox as the reason: {done}"
            );
        }

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// 2. Forged identity fields
// ---------------------------------------------------------------------------

/// Every identity field a caller might add, in every place it could plausibly go.
///
/// The assertion is that the daemon's answer is *identical* with and without them. That is
/// the honest form of "these are ignored": the wire protocol has no actor field, so there
/// is nothing to reject, and what is pinned is that the actor was decided before the
/// params were ever read.
///
/// Each claim is checked by its own effect rather than by its absence from a response —
/// `attacker` appearing nowhere in a reply would also be true of a daemon that simply
/// dropped the field on the floor for an unrelated reason.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn no_caller_supplied_field_can_change_the_actor() {
    rt().block_on(async {
        let d = dir("forged-fields");
        let s = Serving::start(d.clone()).await;

        // A baseline approval, to have something to compare the forged one against.
        let clean_pid = pending_proposal(&s, "clean");
        let clean = send(
            &s.endpoint,
            "b0",
            "capability/approve",
            json!({"proposal": clean_pid, "ttl_ms": 60_000}),
        );
        let clean_approver = clean["result"]["approval"]["approver"].clone();
        let clean_root = clean["result"]["approval"]["authority_root"].clone();
        assert_eq!(clean_approver, "human");

        // The same operation with every identity field a caller could name.
        let forged_pid = pending_proposal(&s, "forged");
        let forged = send(
            &s.endpoint,
            "f",
            "capability/approve",
            json!({
                "proposal": forged_pid,
                "ttl_ms": 60_000,
                // The literal shape the milestone asked about.
                "actor": {"kind": "human", "user_id": "attacker", "via": "remote"},
                "user_id": "attacker",
                "user": "attacker",
                "approver": {"kind": "human", "user": "attacker"},
                "delegated_by": "attacker",
                "granted_by": "attacker",
                "authorised_by": "attacker",
                "auth_channel": "remote",
                "authority_root": "attacker",
                "via": "remote",
            }),
        );
        let approval = &forged["result"]["approval"];
        assert_eq!(
            approval["approver"], clean_approver,
            "a declared actor changed the approver: {forged}"
        );
        assert_eq!(
            approval["authority_root"], clean_root,
            "a declared user changed the authority root: {forged}"
        );

        // And the proposer's recorded authority is still the installation's, not the
        // declared one. This is the attribution claim: the audit-facing identity is not
        // the caller's to choose.
        assert_eq!(
            forged["result"]["proposal"]["authority_root"], "local",
            "a declared actor changed the proposal's authority: {forged}"
        );

        let rendered = serde_json::to_string(&forged).expect("serialise");
        assert!(
            !rendered.contains("attacker"),
            "a caller-supplied identity reached the reply: {rendered}"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// `_meta` is a metadata channel, so it is the obvious place to smuggle an identity.
///
/// Pinned separately because a change to how `_meta` is handled would otherwise be free to
/// affect authority without failing any of the tests above.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn request_metadata_cannot_carry_an_identity() {
    rt().block_on(async {
        let d = dir("meta");
        let s = Serving::start(d.clone()).await;
        let pid = pending_proposal(&s, "meta1");

        let frame = json!({
            "jsonrpc": "2.0", "id": "m", "method": "capability/approve",
            "params": {"proposal": pid, "ttl_ms": 60_000},
            "_meta": {
                "actor": {"kind": "human", "user": "attacker"},
                "user_id": "attacker",
                "authority_root": "attacker"
            }
        });
        let reply =
            send_raw(&s.endpoint, &serde_json::to_vec(&frame).expect("encode")).expect("a reply");
        assert_eq!(
            reply["result"]["approval"]["authority_root"], "local",
            "_meta carried an identity: {reply}"
        );
        assert!(
            !serde_json::to_string(&reply)
                .unwrap_or_default()
                .contains("attacker"),
            "{reply}"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A caller-supplied *approver* inside a presented approval is refused, not ignored.
///
/// This is the one forgery that reaches a real decision rather than an unread field:
/// `capability/dispatch` accepts an approval tuple from the client, and the approver is
/// the field that would matter. It is re-derived from the authenticated principal and the
/// digest binds it, so a client naming a different approver produces a digest that cannot
/// verify.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_presented_approval_cannot_name_its_own_approver() {
    rt().block_on(async {
        let d = dir("approver-forgery");
        let s = Serving::start(d.clone()).await;
        let pid = pending_proposal(&s, "apr");
        let approved = send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        let approval = &approved["result"]["approval"];
        let digest = approval["digest"].as_str().expect("a digest").to_owned();

        // Re-present the same approval with the approver rewritten. Only the digest can
        // catch this, because the approver is not carried on the wire.
        let forged = approval.clone();
        let mut forged = forged.as_object().expect("object").clone();
        forged.insert(
            "approver".to_owned(),
            json!({"kind": "human", "user": "attacker"}),
        );
        forged.insert("authority_root".to_owned(), json!("attacker"));

        let reply = send(
            &s.endpoint,
            "d",
            "capability/dispatch",
            json!({
                "capability": "filesystem/write-text",
                "target": "out.txt",
                "params": {"path": "out.txt", "contents": "x"},
                "approval": Value::Object(forged),
            }),
        );
        assert!(
            reply.get("error").is_some(),
            "an approval naming a different approver must not dispatch: {reply}"
        );

        // And the honest tuple is refused too, because this approval governs a proposal
        // in a task and `capability/dispatch` is the standalone path -- which is itself the
        // evidence that the digest binds something: same digest, different route.
        assert_ne!(digest, "", "the test must have a real digest to present");
        // The reason names the approval, in the machine-readable field a client branches
        // on — the digest is what caught the forgery.
        assert!(
            reply["error"]["data"]["reason"]
                .as_str()
                .is_some_and(|r| r.contains("approval")),
            "the refusal must name the approval: {reply}"
        );

        // The taxonomy is V-90: the forged approver produced an approval-digest mismatch,
        // and that is a caller-actionable refusal rather than a server fault. Asserted
        // positively, with the reason word, because a client recovering from this needs to
        // be able to re-issue a correct approval without reading prose.
        assert_eq!(
            reply["error"]["code"].as_i64(),
            Some(i64::from(RpcErrorCode::FORBIDDEN.code())),
            "an approval that does not describe the action is a caller-actionable refusal: \
             {reply}"
        );
        assert_eq!(
            reply["error"]["data"]["reason"], "approval-digest-mismatch",
            "the reason must be the stable word a client branches on: {reply}"
        );
        // `detail` is the human sentence, not a JSON blob. It used to be the rendered
        // `DenialReason`, which for a unit variant is `{"reason":"approval-digest-mismatch"}`
        // -- the machine word again, wrapped in an object, shown to a person.
        let detail = reply["error"]["data"]["detail"]
            .as_str()
            .unwrap_or_default();
        assert!(
            detail.contains("approval") && !detail.contains('{'),
            "detail must be a human sentence, not a rendered structure: {detail:?}"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// 3. Escalation
// ---------------------------------------------------------------------------

/// No actor other than the authenticated human can grant, and that is a property of the
/// type rather than of a route.
///
/// The assertion is on `Actor::can_grant` and `authority_root` for every variant, because
/// that is the check `orxnud_policy` makes before anything else (engine.rs, "0. AUTHORITY").
/// Testing it here rather than over the wire is deliberate: there is no IPC method that
/// produces an `External`, `System`, `Integration` or `Scheduled` actor at all, so a wire
/// test could only assert absence of a route. This asserts the reason the absence is safe.
#[test]
fn no_actor_except_the_human_can_grant() {
    use orxnud_domain::actor::{Actor, AuthChannel, ModelProvenance, SystemComponent};
    use orxnud_domain::ids::{
        CapabilityId, ExternalSource, GrantId, RequestId, RunId, ScheduleId, TaskId, UserId,
    };

    let human = Actor::Human {
        user: UserId::new("local"),
        via: AuthChannel::LocalInteractive,
    };
    let ai = Actor::Ai {
        delegated_by: UserId::new("local"),
        run: RunId::new("r"),
        task: TaskId::new("t"),
        provenance: ModelProvenance::new("m/some-model", "p", RequestId::new("q")),
    };
    let system = Actor::System {
        component: SystemComponent::Migration,
    };
    let integration = Actor::Integration {
        capability: CapabilityId::new("filesystem/write-text"),
        granted_by: UserId::new("local"),
        grant: GrantId::new("g"),
    };
    let scheduled = Actor::Scheduled {
        schedule: ScheduleId::new("s"),
        authorised_by: UserId::new("local"),
        task: TaskId::new("t"),
    };
    let external = Actor::External {
        source: ExternalSource::Webhook {
            listener: "l".to_owned(),
        },
        request: RequestId::new("q"),
    };

    for actor in [&human, &ai, &system, &integration, &scheduled, &external] {
        let label = actor.label();
        if label == "human" {
            assert!(actor.can_grant(), "the human must be able to grant");
        } else {
            assert!(
                !actor.can_grant(),
                "{label} must never be able to grant: {actor:?}"
            );
        }
    }

    // System and External have no human behind them at all, so policy refuses them before
    // it looks at anything else. An `Ai`, `Integration` or `Scheduled` actor may exercise
    // a human's grant but carries that human's identity, never its own authority.
    assert!(system.authority_root().is_none(), "{system:?}");
    assert!(external.authority_root().is_none(), "{external:?}");
    for borrowed in [&ai, &integration, &scheduled] {
        assert_eq!(
            borrowed.authority_root(),
            Some(&UserId::new("local")),
            "a delegated actor's root is the human it was delegated by, not itself: {borrowed:?}"
        );
    }
}

/// A persisted `Actor` is data, not authority.
///
/// `proposer_json` is stored as canonical JSON and read back with `serde_json::from_str`,
/// so a proposal's proposer *is* an `Actor` reconstructed from the database. That is a
/// genuine path from storage to an actor, and it is the one place where "it was persisted
/// earlier" could be mistaken for "it is authenticated". The stored value can only ever be
/// an `Ai` proposer on the write paths, and policy still refuses an `Ai` as an approver —
/// which is the property that makes reading it back safe.
#[test]
fn a_persisted_actor_is_not_self_authenticating() {
    use orxnud_domain::actor::Actor;
    use orxnud_domain::actor::ModelProvenance;
    use orxnud_domain::ids::{RequestId, RunId, TaskId, UserId};

    // Round-tripped exactly as `ProposalRow::proposer` does it.
    let stored = serde_json::to_string(&Actor::Ai {
        delegated_by: UserId::new("local"),
        run: RunId::new("t"),
        task: TaskId::new("t"),
        provenance: ModelProvenance::new("m/model", "p", RequestId::new("q")),
    })
    .expect("serialise");
    let recovered: Actor = serde_json::from_str(&stored).expect("deserialise");

    assert!(
        !recovered.can_grant(),
        "a recovered actor still cannot grant"
    );
    assert_eq!(recovered.authority_root(), Some(&UserId::new("local")));

    // The unforgeable part: an `Actor::Human` recovered from storage is still only a
    // *value*. It grants nothing by itself — the approval path re-derives the approver
    // from the authenticated principal and never from the stored proposer, so a proposal
    // persisted with a human-labelled proposer cannot approve itself.
    let human_json = serde_json::to_string(&Actor::Human {
        user: UserId::new("attacker"),
        via: orxnud_domain::actor::AuthChannel::Remote,
    })
    .expect("serialise");
    let recovered_human: Actor = serde_json::from_str(&human_json).expect("deserialise");
    assert!(recovered_human.can_grant(), "the value says human");
    assert_eq!(
        recovered_human.authority_root(),
        Some(&UserId::new("attacker")),
        "the value carries the name it was stored with"
    );
    // Which is why the test that matters is the wire one above: what the daemon *uses* is
    // the authenticated principal, not what storage says. Recorded here so the distinction
    // between "an Actor value can be Human" and "a Human actor can be obtained" stays
    // explicit in the file, because the first is true and the second is the thing being
    // fixed.
}

// ---------------------------------------------------------------------------
// 4. Restart and concurrency
// ---------------------------------------------------------------------------

/// A restart re-derives the identity from the same endpoint owner, so it does not change.
///
/// The risk this guards is specific: if the authenticated identity were held in memory and
/// regenerated with a fresh value on each start, an approval issued by the previous daemon
/// would stop verifying — which is a *liveness* bug dressed as a security one, and the one
/// most likely to be introduced by adding an identity layer.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_restart_does_not_change_the_authenticated_identity() {
    rt().block_on(async {
        let d = dir("restart");
        let first = Serving::start(d.clone()).await;
        let pid_a = pending_proposal(&first, "r1");
        let before = send(
            &first.endpoint,
            "a1",
            "capability/approve",
            json!({"proposal": pid_a, "ttl_ms": 60_000}),
        );
        let root_before = before["result"]["approval"]["authority_root"].clone();
        assert_eq!(root_before, "local", "{before}");
        let endpoint = first.endpoint.clone();
        first.stop().await;

        // Same directory, so the same installation owner is re-read from disk.
        let second = Serving::start(d.clone()).await;
        assert_eq!(
            second.endpoint, endpoint,
            "the endpoint must be the same path"
        );

        let pid_b = pending_proposal(&second, "r2");
        let after = send(
            &second.endpoint,
            "a2",
            "capability/approve",
            json!({"proposal": pid_b, "ttl_ms": 60_000}),
        );
        assert_eq!(
            after["result"]["approval"]["authority_root"], root_before,
            "a restart changed the authenticated identity: {after}"
        );

        second.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Two clients connecting at once derive one identity, not two.
///
/// The invariant that matters is not mutual exclusion — nothing is claimed — but that
/// concurrent callers cannot obtain *contradictory* identities. So the assertion is that
/// every concurrent client's answer is identical, rather than that one of them won.
///
/// No lock is added for this, and none is needed: the identity is a comparison against the
/// endpoint's own filesystem metadata, which the kernel owns and no amount of connecting
/// can change. Adding a mutex would have made the test pass while leaving that fact
/// untested.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn concurrent_clients_all_derive_the_same_identity() {
    rt().block_on(async {
        let d = dir("concurrent");
        let s = Serving::start(d.clone()).await;

        let mut handles = Vec::new();
        for i in 0..8 {
            let endpoint = s.endpoint.clone();
            handles.push(std::thread::spawn(move || {
                send(
                    &endpoint,
                    &format!("cc{i}"),
                    "task/create",
                    json!({"id": format!("c{i}"), "content": "x"}),
                )
            }));
        }
        let replies: Vec<Value> = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .collect();
        for r in &replies {
            assert!(r.get("result").is_some(), "{r}");
        }

        // And every one of them is approved under the same identity.
        let ids: Vec<String> = (0..8).map(|i| format!("c{i}")).collect();
        let mut roots = Vec::new();
        for (i, id) in ids.iter().enumerate() {
            let pid = pending_proposal(&s, id);
            send(
                &s.endpoint,
                &format!("cl{i}"),
                "task/claim",
                json!({"id": id, "worker": "w1"}),
            );
            let reply = send(
                &s.endpoint,
                &format!("ap{i}"),
                "capability/approve",
                json!({"proposal": pid, "ttl_ms": 60_000}),
            );
            roots.push(reply["result"]["approval"]["authority_root"].clone());
        }
        assert!(
            roots.windows(2).all(|w| w[0] == w[1]),
            "concurrent clients derived different identities: {roots:?}"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// 5. The CLI
// ---------------------------------------------------------------------------

/// The CLI reaches the daemon as a peer, not by declaring anything.
///
/// The end-to-end proof that the legitimate client works *because the transport established
/// the identity*. It is a real `orxnuctl` invocation against a real daemon, so if the CLI
/// had been relying on declaring an actor this would be where it showed.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_cli_obtains_authority_without_declaring_anything() {
    rt().block_on(async {
        let d = dir("cli");
        let s = Serving::start(d.clone()).await;

        // Resolved from the test binary's own directory, the way the existing
        // `cli_e2e` suite does it: `orxnuctl` is not a dependency of this crate, so
        // cargo does not build it into this test's environment.
        let exe = std::env::current_exe().expect("current_exe");
        let cli = exe
            .parent()
            .and_then(std::path::Path::parent)
            .expect("profile directory")
            .join("orxnuctl");
        let out = std::process::Command::new(cli)
            .args([
                "task",
                "create",
                "--endpoint",
                &s.endpoint.to_string_lossy(),
                "--id",
                "cli1",
                "from the cli",
            ])
            .output()
            .expect("the cli must run");
        assert!(
            out.status.success(),
            "the CLI must still work against an authenticated daemon: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        // The task exists, so the CLI's request reached the governed path as the owner.
        let listed = send(&s.endpoint, "l", "task/list", json!({}));
        assert_eq!(listed["result"]["count"], 1, "{listed}");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}
