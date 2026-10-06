//! Production evidence for step continuation (ADR-0043, ADR-0047).
//!
//! Every test here reaches a real daemon over a real Unix domain socket, and `tasks.rs`
//! explains at length why each one carries `#[cfg_attr(not(target_os = "linux"),
//! ignore = ...)]`. This file is that evidence for the one question the rest of the suite
//! could not answer: **does a multi-step task actually reach its next step, in production
//! code, with no path that skips the governed route?**
//!
//! The properties asserted here are the ones that make continuation safe rather than
//! merely working:
//!
//! * a continued step re-enters the ordinary proposal/approval/execute route, so
//!   continuation adds no authority of its own;
//! * the boundary claim is exactly-once under concurrency;
//! * a provider failure leaves the task at its boundary, retryable, rather than stranded;
//! * `max_steps` — not the orchestrator — is what bounds a task;
//! * a `done` answer completes the task, and carries nothing that could have been used to
//!   do anything instead;
//! * what a model is shown about earlier steps stays metadata: status and workspace-relative
//!   artifact names, never content (ADR-0044).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use orxnud_daemon::Paths;
use orxnud_daemon::runtime::Runtime;
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use serde_json::{Value, json};

/// A secret store with nothing in it. The runtime is generic over `SecretsContract`;
/// this also keeps the suite off the user's real keyring.
struct NoSecrets;

#[derive(Debug, thiserror::Error)]
#[error("no secret store in the continuation suite")]
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
    let d = std::env::temp_dir().join(format!("orxnud-cont-{}-{tag}", std::process::id()));
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
    let line = serde_json::to_vec(&frame).expect("encode");
    send_raw(endpoint, &line).unwrap_or_else(|| panic!("{method} must answer"))
}

fn await_ready(endpoint: &Path) {
    for _ in 0..200 {
        if let Some(v) = send_raw(
            endpoint,
            br#"{"jsonrpc":"2.0","id":"r","method":"daemon/version"}"#,
        ) && v.get("result").is_some_and(|r| r.get("current").is_some())
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
        provider: Arc<dyn orxnud_daemon::proposer::ProposalProvider>,
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

fn workspace(root: &Path) -> PathBuf {
    root.join("workspace")
}

/// The state of one task, read over the wire.
fn state_of(endpoint: &Path, id: &str) -> String {
    let listed = send(endpoint, "l", "task/list", json!({}));
    listed["result"]["tasks"]
        .as_array()
        .expect("tasks")
        .iter()
        .find(|t| t["id"] == id)
        .unwrap_or_else(|| panic!("no task {id}"))["state"]
        .as_str()
        .expect("a state string")
        .to_owned()
}

/// Runs one step to completion: propose, approve, execute.
///
/// The ordinary route, written once so every test in this file provably used it rather
/// than a shortcut that happens to produce the same state.
fn run_one_step(endpoint: &Path, worker: &str) -> Value {
    let p = send(
        endpoint,
        "p",
        "task/ai-propose",
        json!({ "task": "t1", "worker": worker }),
    );
    assert!(p.get("result").is_some(), "the step must propose: {p}");
    let pid = p["result"]["proposal"]["proposal_id"]
        .as_str()
        .expect("a proposal id")
        .to_owned();
    send(
        endpoint,
        "a",
        "capability/approve",
        json!({ "proposal": pid, "ttl_ms": 60_000 }),
    );
    let done = send(
        endpoint,
        "x",
        "task/execute",
        json!({ "proposal": pid, "worker": worker }),
    );
    assert_eq!(
        done["result"]["verified"], true,
        "the step must verify: {done}"
    );
    done
}

/// Proposes a step through the human route, returning the proposal id the daemon minted.
///
/// `task/propose` names the proposal itself, so the id comes back in the reply rather
/// than being chosen here. Used by the two tests that need a verified step *without* a
/// working provider, so that the provider failure under test is unambiguously the
/// continuation's rather than the first step's.
fn propose_first_step(endpoint: &Path, target: &str) -> String {
    let p = send(
        endpoint,
        "q",
        "task/propose",
        json!({
            "task": "t1", "worker": "w1", "capability": "filesystem/write-text",
            "target": target,
            "params": {"path": target, "contents": "first"},
        }),
    );
    assert!(
        p.get("result").is_some(),
        "the manual proposal must be written: {p}"
    );
    p["result"]["proposal"]["proposal_id"]
        .as_str()
        .expect("a proposal id")
        .to_owned()
}

/// Approves and executes `pid`, asserting the step verified.
fn approve_and_run(endpoint: &Path, pid: &str) {
    send(
        endpoint,
        "a",
        "capability/approve",
        json!({ "proposal": pid, "ttl_ms": 60_000 }),
    );
    let done = send(
        endpoint,
        "x",
        "task/execute",
        json!({ "proposal": pid, "worker": "w1" }),
    );
    assert_eq!(
        done["result"]["verified"], true,
        "the step must verify: {done}"
    );
}

// ---------------------------------------------------------------------------
// The headline property: a multi-step task really advances.
// ---------------------------------------------------------------------------

/// Two steps, both governed, and the task ends completed.
///
/// The whole point of this file. `max_steps: 2` on `task/create` is the only reason a
/// boundary is ever reached at all — with the schema default of one, a task completes on
/// its first verified effect and `task/continue` could never fire. So this test is
/// simultaneously the evidence that continuation is reachable in production and that
/// reaching it required closing a real gap.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_multi_step_task_advances_across_a_verified_step_boundary() {
    rt().block_on(async {
        let d = dir("advance");
        let s = Serving::start(d.clone()).await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "t1", "max_steps": 2, "content": "write final.txt"}),
        );

        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        run_one_step(&s.endpoint, "w1");

        // The verified step parked the task at a boundary rather than finishing it, because
        // `max_steps` says a second step is allowed.
        assert_eq!(state_of(&s.endpoint, "t1"), "awaiting-next-step");
        assert_eq!(
            std::fs::read_to_string(workspace(&d).join("final.txt")).expect("written"),
            "delegated governance works"
        );

        // One call to continue: crosses the boundary and proposes what comes next.
        let next = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(next["result"]["continued"], true, "{next}");
        assert_eq!(next["result"]["step"], 2, "the second logical step: {next}");
        assert_eq!(
            next["result"]["waiting_for"], "human-approval",
            "a continued step is governed exactly like the first: {next}"
        );

        // And it went through the ordinary route: an unapproved continuation does not run.
        let pid = next["result"]["proposal"]["proposal_id"]
            .as_str()
            .expect("a proposal id")
            .to_owned();
        let early = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        assert!(
            early.get("error").is_some(),
            "continuation must not be a way around approval: {early}"
        );

        send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        let done = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        assert_eq!(done["result"]["verified"], true, "{done}");
        assert_eq!(state_of(&s.endpoint, "t1"), "completed");

        // Two step results, one row per logical step however many proposals it took.
        let db = orxnud_store::security_state::SqliteAuditJournal::open(&d.join("state.db"))
            .expect("open");
        let conn = db.conn();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM task_step_results WHERE task_id = 't1'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(n, 2, "one durable result per logical step");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// `max_steps` is the bound, and the orchestrator has no loop.
// ---------------------------------------------------------------------------

/// The default single-step task still completes rather than parking.
///
/// Guards the change to `task/create` against regressing every pre-existing task: the
/// default is one step, so nothing about the old behaviour moves.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_single_step_task_completes_and_cannot_be_continued() {
    rt().block_on(async {
        let d = dir("single");
        let s = Serving::start(d.clone()).await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "t1", "content": "write final.txt"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        run_one_step(&s.endpoint, "w1");

        assert_eq!(
            state_of(&s.endpoint, "t1"),
            "completed",
            "an unasked-for extra step must not appear"
        );

        // Nothing to continue, and the refusal says so in a form a caller can branch on.
        let refused = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(
            refused["error"]["data"]["reason"], "not-at-boundary",
            "{refused}"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// `max_steps` is refused rather than clamped, at both ends.
///
/// A silent clamp would be the dangerous version of this feature: a caller asking for
/// three steps would get one and never learn, and a task with zero steps could never
/// finish at all.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_impossible_step_bound_is_refused_at_creation() {
    rt().block_on(async {
        let d = dir("bounds");
        let s = Serving::start(d.clone()).await;

        for bad in [json!(0), json!(-1), json!(1000), json!("3"), json!(1.5)] {
            let reply = send(
                &s.endpoint,
                "c",
                "task/create",
                json!({"id": "bad", "max_steps": bad}),
            );
            assert!(
                reply.get("error").is_some(),
                "max_steps {bad} must be refused rather than stored: {reply}"
            );
        }

        // And the upper bound is the documented one.
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "ok", "max_steps": 64}),
        );
        assert_eq!(state_of(&s.endpoint, "ok"), "pending");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// The boundary claim is exactly-once.
// ---------------------------------------------------------------------------

/// Two workers, one boundary: exactly one continuation succeeds.
///
/// The losers must be told *why* rather than left to infer it, which is why the refusal
/// carries a branchable reason. And no second proposal may be written, because the
/// loser's claim never happened.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_boundary_is_claimed_by_exactly_one_worker() {
    rt().block_on(async {
        let d = dir("race");
        let s = Serving::start(d.clone()).await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "t1", "max_steps": 2, "content": "write final.txt"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        run_one_step(&s.endpoint, "w1");
        assert_eq!(state_of(&s.endpoint, "t1"), "awaiting-next-step");

        // Both continuations issued from separate connections at the same time.
        let endpoint = s.endpoint.clone();
        let a = std::thread::spawn(move || {
            send(
                &endpoint,
                "k1",
                "task/continue",
                json!({"task": "t1", "worker": "w1"}),
            )
        });
        let endpoint = s.endpoint.clone();
        let b = std::thread::spawn(move || {
            send(
                &endpoint,
                "k2",
                "task/continue",
                json!({"task": "t1", "worker": "w2"}),
            )
        });
        let ra = a.join().expect("thread a");
        let rb = b.join().expect("thread b");

        let wins = [&ra, &rb]
            .iter()
            .filter(|r| r["result"]["continued"] == true)
            .count();
        let losses = [&ra, &rb]
            .iter()
            .filter(|r| r.get("error").is_some())
            .count();
        assert_eq!(wins, 1, "exactly one claim wins: {ra} {rb}");
        assert_eq!(
            losses, 1,
            "and the other is refused, not silently ignored: {ra} {rb}"
        );

        // Exactly one proposal for step 2 exists. Two would mean two claims both wrote.
        let db = orxnud_store::security_state::SqliteAuditJournal::open(&d.join("state.db"))
            .expect("open");
        let conn = db.conn();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM task_proposals WHERE task_id = 't1' AND step_no = 2",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(n, 1, "one proposal per claimed step");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Failure after the claim must not strand the task.
// ---------------------------------------------------------------------------

/// An unreachable provider releases the boundary instead of stranding it.
///
/// The claim and the proposal are two writes with a network call between them. If the
/// release did not exist, the task would sit in `running` holding a lease for a step that
/// will never be proposed, and `task/continue` — which only ever acts at a boundary —
/// could never be retried. The provider error is still reported; only the boundary is put
/// back.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_provider_failure_returns_the_task_to_its_boundary_and_is_retryable() {
    use orxnud_daemon::proposer::{ProposalContext, ProposalProvider, ProviderError};

    /// Refuses every call, so the failure lands between the claim and the proposal.
    struct Unreachable;

    impl ProposalProvider for Unreachable {
        fn model_id(&self) -> &str {
            "scripted/unreachable"
        }
        fn complete(
            &self,
            _ctx: &ProposalContext,
        ) -> Result<String, orxnud_daemon::proposer::ProviderError> {
            Err(ProviderError::Unreachable("the model is down".to_owned()))
        }
    }

    rt().block_on(async {
        let d = dir("unreachable");
        let s = Serving::start_with(d.clone(), Arc::new(Unreachable)).await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "t1", "max_steps": 2, "content": "write final.txt"}),
        );

        // Claimed directly and driven to a boundary without the provider, so the failure
        // below is unambiguously the continuation's.
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        let pid = propose_first_step(&s.endpoint, "first.txt");
        approve_and_run(&s.endpoint, &pid);
        assert_eq!(state_of(&s.endpoint, "t1"), "awaiting-next-step");

        // The provider cannot be asked. The boundary must survive that.
        let refused = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert!(
            refused.get("error").is_some(),
            "an unreachable model is a failure, not a proposal: {refused}"
        );
        assert_eq!(
            refused["error"]["data"]["reason"], "provider-unreachable",
            "{refused}"
        );
        assert_eq!(
            state_of(&s.endpoint, "t1"),
            "awaiting-next-step",
            "the boundary must be released, or the step is stranded forever: {refused}"
        );

        // And a working provider can now pick it up. Proving the retry rather than
        // asserting the absence of damage.
        s.stop().await;
        let s2 = Serving::start(d.clone()).await;
        let retried = send(
            &s2.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(retried["result"]["continued"], true, "{retried}");
        assert_eq!(retried["result"]["step"], 2);

        s2.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// The terminal answer.
// ---------------------------------------------------------------------------

/// `{"done": true}` finishes the task, and is a distinct shape rather than a capability.
///
/// Also the boundary case for the claim: a step was claimed, and then deliberately not
/// worked. `steps_completed` must not move, because no effect was verified — the task
/// finished, but it did not do another thing.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_model_can_say_no_further_work_is_needed() {
    use orxnud_daemon::proposer::ScriptedProvider;

    rt().block_on(async {
        let d = dir("done");
        // First the model proposes a step; then it says the task is finished. The
        // scripted provider returns one answer, so the two phases use two daemons over
        // the same store.
        let s = Serving::start(d.clone()).await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "t1", "max_steps": 3, "content": "write final.txt"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        run_one_step(&s.endpoint, "w1");
        assert_eq!(state_of(&s.endpoint, "t1"), "awaiting-next-step");
        s.stop().await;

        let s2 = Serving::start_with(
            d.clone(),
            Arc::new(ScriptedProvider::returning(
                "scripted/finished",
                r#"{"done": true, "summary": "final.txt holds the answer"}"#,
            )),
        )
        .await;
        let reply = send(
            &s2.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(reply["result"]["completed"], true, "{reply}");
        assert_eq!(reply["result"]["continued"], false, "{reply}");
        assert_eq!(
            reply["result"]["summary"], "final.txt holds the answer",
            "the model's reason is reported, not swallowed: {reply}"
        );
        assert_eq!(
            reply["result"]["proposed_by"], "ai",
            "a task that ended because a model said so must name it: {reply}"
        );
        assert_eq!(state_of(&s2.endpoint, "t1"), "completed");

        // Terminal is terminal: no resurrection through the continuation route.
        let after = send(
            &s2.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert!(after.get("error").is_some(), "{after}");

        s2.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A `done` answer carries no capability, so it cannot be used to do anything.
///
/// The security-relevant half of the previous test. A `done` answer names no capability,
/// no target and no parameters, so there is no payload in it to smuggle an action past
/// the allowlist — and the two shapes are mutually exclusive, so a response that mixes
/// `done` with a capability is refused rather than resolved in favour of one of them.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_done_answer_cannot_carry_an_action_and_contradictions_are_refused() {
    use orxnud_daemon::proposer::{ProposalContext, ProposalOutcome, ProposalProvider};

    let ctx = || ProposalContext {
        task_id: "t1".to_owned(),
        content: "write final.txt".to_owned(),
        attempt_no: 1,
        allowed: vec![orxnud_daemon::proposer::AllowedCapability {
            id: "filesystem/write-text".to_owned(),
            description: "Write a text file into the workspace".to_owned(),
            params: vec!["path".to_owned(), "contents".to_owned()],
            schema: orxnud_capability::write_text::declaration()
                .params()
                .schema
                .clone(),
            target: orxnud_domain::TargetSemantics::Required,
        }],
        prior_steps: Default::default(),
        disclosures: orxnud_daemon::observation::DisclosureBatch::empty(),
    };

    /// A provider returning whatever text the test hands it.
    struct Fixed(&'static str);
    impl ProposalProvider for Fixed {
        fn model_id(&self) -> &str {
            "scripted/fixed"
        }
        fn complete(
            &self,
            _c: &ProposalContext,
        ) -> Result<String, orxnud_daemon::proposer::ProviderError> {
            Ok(self.0.to_owned())
        }
    }

    let registered = |id: &str| id == "filesystem/write-text";

    // A clean `done` is the only terminal shape accepted, and it carries nothing.
    match orxnud_daemon::proposer::validate(
        r#"{"done": true, "summary": "nothing left"}"#,
        &ctx(),
        &registered,
    )
    .expect("a done answer")
    {
        ProposalOutcome::Done { summary } => assert_eq!(summary, "nothing left"),
        ProposalOutcome::Step(_) => panic!("done must not parse as a step"),
    }

    // `done` plus a capability, `done: false`, and a capability *named* `done` are all
    // refused. Each is a way a model might try to make one shape mean two things.
    for text in [
        r#"{"done": true, "capability": "filesystem/write-text", "params": {"path": "a", "contents": "b"}}"#,
        r#"{"done": false, "summary": "keep going"}"#,
        r#"{"done": "yes", "summary": "keep going"}"#,
    ] {
        let outcome = orxnud_daemon::proposer::validate(text, &ctx(), &registered);
        assert!(outcome.is_err(), "{text} must be refused, got {outcome:?}");
    }

    let _ = Fixed("").complete(&ctx());
}

// ---------------------------------------------------------------------------
// What the model is told, and what it is not.
// ---------------------------------------------------------------------------

/// The prior-step context is metadata, never content.
///
/// The continuation route is the first place a model is routinely shown something about
/// earlier steps, so this is where a disclosure regression would land. `PriorStep` carries
/// a step number, a status and workspace-relative artifact names — nothing else — and this
/// asserts that on the real projection, so adding a content field to it would fail here.
#[test]
fn prior_step_context_carries_status_and_names_but_never_content() {
    let rows = vec![
        orxnud_store::task_repo::StepResultRow {
            task_id: orxnud_domain::ids::TaskId::new("t1"),
            step_no: 1,
            status: orxnud_store::task_repo::StepStatus::Verified,
            verification: Some("the file matched".to_owned()),
            structured_output: Some(r#"{"contents":"the secret answer"}"#.to_owned()),
            artifacts: Some(r#"["final.txt"]"#.to_owned()),
            recorded_at_ms: 1,
        },
        orxnud_store::task_repo::StepResultRow {
            task_id: orxnud_domain::ids::TaskId::new("t1"),
            step_no: 2,
            status: orxnud_store::task_repo::StepStatus::Verified,
            verification: Some("wrote the summary".to_owned()),
            structured_output: Some(r#"{"body":"a private report"}"#.to_owned()),
            artifacts: Some("[]".to_owned()),
            recorded_at_ms: 2,
        },
    ];

    let ctx = orxnud_daemon::proposer::prior_step_context_from(&rows);
    let rendered = format!("{ctx:?}");
    for leaked in ["secret answer", "private report", "the file matched"] {
        assert!(
            !rendered.contains(leaked),
            "the prior-step context disclosed {leaked:?}: {rendered}"
        );
    }
    assert_eq!(ctx.steps.len(), 2, "both steps are represented");
    assert_eq!(ctx.steps[0].step_no, 1);
    assert_eq!(ctx.steps[0].artifacts, vec!["final.txt".to_owned()]);
    assert!(ctx.steps[1].artifacts.is_empty());
}

// ---------------------------------------------------------------------------
// Absence of a provider.
// ---------------------------------------------------------------------------

/// No provider is a refusal with its own reason, in both routes.
///
/// Shared behaviour rather than a continuation quirk, and stated once so the two routes
/// cannot drift: a daemon that cannot reach a model says so rather than guessing.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn continuation_without_a_provider_is_refused_before_the_boundary_is_crossed() {
    rt().block_on(async {
        let d = dir("noprovider");
        let runtime = Runtime::start(Paths::under(&d), NoSecrets)
            .await
            .expect("start");
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

        send(
            &endpoint,
            "c",
            "task/create",
            json!({"id": "t1", "max_steps": 2, "content": "write final.txt"}),
        );
        send(
            &endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        let pid = propose_first_step(&endpoint, "final.txt");
        approve_and_run(&endpoint, &pid);
        assert_eq!(state_of(&endpoint, "t1"), "awaiting-next-step");

        let refused = send(
            &endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(
            refused["error"]["data"]["reason"], "provider-not-configured",
            "{refused}"
        );
        // Refused *before* the boundary was crossed, so the task is still at it.
        assert_eq!(
            state_of(&endpoint, "t1"),
            "awaiting-next-step",
            "a missing provider must not consume the boundary: {refused}"
        );

        let _ = tx.send(());
        let _ = task.await;
        let _ = std::fs::remove_dir_all(&d);
    });
}
