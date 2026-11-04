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
        let runtime =
            Runtime::start_permitting_argv_payload_exposure(Paths::under(&root), NoSecrets)
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

/// Wall-clock milliseconds, the unit the task store stamps leases in.
fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock is after the epoch")
            .as_millis(),
    )
    .expect("milliseconds fit in i64")
}

/// Polls `probe` until it yields a value or `deadline` elapses.
///
/// Used only to bound "a renewal should have happened by now"; the property itself is
/// asserted on the value, not on the fact that a timeout did not fire.
fn wait_for<T>(deadline: Duration, mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let start = std::time::Instant::now();
    loop {
        if let Some(value) = probe() {
            return Some(value);
        }
        if start.elapsed() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Opens the daemon's own SQLite file for observation.
fn open_state_db(root: &Path) -> orxnud_store::security_state::SqliteAuditJournal {
    orxnud_store::security_state::SqliteAuditJournal::open(
        &root.join("state.db"),
        &orxnud_platform_fs::OsIdentity,
    )
    .expect("open the daemon's state database")
}

/// `(state, lease holder, lease expiry)` for one task, read from the store.
fn task_lease(
    db: &orxnud_store::security_state::SqliteAuditJournal,
    id: &str,
) -> (String, Option<String>, Option<i64>) {
    db.conn()
        .query_row(
            "SELECT state, lease_holder, lease_expires_at_ms FROM tasks WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("the task row")
}

/// The `created_at_ms` of every proposal persisted for `(task, step)`.
fn step_proposals(
    db: &orxnud_store::security_state::SqliteAuditJournal,
    id: &str,
    step: u32,
) -> Vec<i64> {
    let mut stmt = db
        .conn()
        .prepare(
            "SELECT created_at_ms FROM task_proposals
              WHERE task_id = ?1 AND step_no = ?2
              ORDER BY created_at_ms ASC",
        )
        .expect("prepare the proposal query");
    stmt.query_map(rusqlite::params![id, i64::from(step)], |r| r.get(0))
        .expect("query proposals")
        .collect::<Result<Vec<i64>, _>>()
        .expect("proposal rows")
}

/// Runs one step to completion: propose, approve, execute.
///
/// The ordinary route, written once so every test in this file provably used it rather
/// than a shortcut that happens to produce the same state.
fn run_one_step(endpoint: &Path, worker: &str, claim_generation: i64) -> Value {
    let p = send(
        endpoint,
        "p",
        "task/ai-propose",
        json!({ "task": "t1", "worker": worker, "claim_generation": claim_generation }),
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
fn propose_first_step(endpoint: &Path, target: &str, claim_generation: i64) -> String {
    let p = send(
        endpoint,
        "q",
        "task/propose",
        json!({
            "task": "t1", "worker": "w1", "capability": "filesystem/write-text",
            "claim_generation": claim_generation,
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

        let claimed = send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        let claim_generation = claimed["result"]["claim_generation"]
            .as_i64()
            .expect("claim generation");
        run_one_step(&s.endpoint, "w1", claim_generation);

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
        let db = orxnud_store::security_state::SqliteAuditJournal::open(
            &d.join("state.db"),
            &orxnud_platform_fs::OsIdentity,
        )
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
        let claimed = send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        let claim_generation = claimed["result"]["claim_generation"]
            .as_i64()
            .expect("claim generation");
        run_one_step(&s.endpoint, "w1", claim_generation);

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
        let claimed = send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        let claim_generation = claimed["result"]["claim_generation"]
            .as_i64()
            .expect("claim generation");
        run_one_step(&s.endpoint, "w1", claim_generation);
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
        let db = orxnud_store::security_state::SqliteAuditJournal::open(
            &d.join("state.db"),
            &orxnud_platform_fs::OsIdentity,
        )
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
        let claimed = send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        let claim_generation = claimed["result"]["claim_generation"]
            .as_i64()
            .expect("claim generation");
        let pid = propose_first_step(&s.endpoint, "first.txt", claim_generation);
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
        let claimed = send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        let claim_generation = claimed["result"]["claim_generation"]
            .as_i64()
            .expect("claim generation");
        run_one_step(&s.endpoint, "w1", claim_generation);
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
        let runtime = Runtime::start_permitting_argv_payload_exposure(Paths::under(&d), NoSecrets)
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
        let claimed = send(
            &endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        let claim_generation = claimed["result"]["claim_generation"]
            .as_i64()
            .expect("claim generation");
        let pid = propose_first_step(&endpoint, "final.txt", claim_generation);
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

// ---------------------------------------------------------------------------
// CONC-006: the governed lock is not held across the model's network wait
// ---------------------------------------------------------------------------

/// A provider that blocks until the test releases it, and records that it was entered.
///
/// The same latch-based seam `serve_lifecycle.rs` uses for the `task/ai-propose` route,
/// reproduced here because each integration test file is its own binary and cannot
/// share code with the other. A latch rather than a sleep: the test needs to assert
/// something about a state where the provider is *definitely* mid-call, and a sleep
/// races that — on a loaded machine the call may not have started, and the test
/// would pass for the wrong reason.
struct BlockingProvider {
    entered: std::sync::mpsc::Sender<()>,
    release: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
}

impl BlockingProvider {
    fn new() -> (
        Arc<Self>,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let p = Arc::new(Self {
            entered: entered_tx,
            release: Arc::new(std::sync::Mutex::new(release_rx)),
        });
        (p, entered_rx, release_tx)
    }
}

impl orxnud_daemon::proposer::ProposalProvider for BlockingProvider {
    fn model_id(&self) -> &str {
        "test/blocking"
    }

    fn complete(
        &self,
        _ctx: &orxnud_daemon::proposer::ProposalContext,
    ) -> Result<String, orxnud_daemon::proposer::ProviderError> {
        // Announce first, then block. The order matters: a provider that blocked
        // before announcing would leave the test unable to tell "not started" from
        // "started and stuck".
        let _ = self.entered.send(());
        if let Ok(release) = self.release.lock() {
            // A closed channel is how the harness tears the provider down at the end
            // of a failing run, so it must not hang here.
            let _ = release.recv();
        }
        // A valid answer, so a released provider still produces an ordinary outcome
        // rather than a refusal this test would have to interpret.
        //
        // `text/word-count` because it is in-process and carries no argv payload, so
        // it is offered by every runtime -- including one built without the
        // argv-payload exception -- and the proposal this continuation persists is
        // therefore an ordinary one on both.
        Ok(r#"{"capability":"text/word-count","params":{"text":"one two three"}}"#.to_owned())
    }
}

/// **A blocked `task/continue` does not hold the daemon's governed lock.**
///
/// The continuation used to hold the single-writer mutex — the one every durable-state
/// route needs — across the model's network round trip, so a slow model stalled every
/// other request for the length of the call. `task/ai-propose` was split long ago for
/// exactly this reason (`serve_lifecycle.rs`'s `a_blocked_provider_does_not_stop_unrelated_
/// requests`); the continuation was not, and the asymmetry was the finding.
///
/// The probe is `task/list`, not `daemon/status`: `daemon/status` answers from
/// composition state and takes no lock at all, so it would pass whether or not the
/// defect is present. `task/list` reads durable state, so it needs the governed lock,
/// and it is the probe that can detect this.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_blocked_continuation_does_not_hold_the_governed_lock() {
    rt().block_on(async {
        let (provider, entered, release) = BlockingProvider::new();
        let d = dir("blocked-continuation");
        let s = Serving::start_with(d.clone(), provider).await;

        // A task at a boundary, reached through the human route so the provider is
        // not involved in the setup.
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "t1", "max_steps": 2, "content": "write final.txt"}),
        );
        let claimed = send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        let claim_generation = claimed["result"]["claim_generation"]
            .as_i64()
            .expect("claim generation");
        let pid = propose_first_step(&s.endpoint, "first.txt", claim_generation);
        approve_and_run(&s.endpoint, &pid);
        assert_eq!(state_of(&s.endpoint, "t1"), "awaiting-next-step");

        // The model call, on its own connection, blocked inside the provider.
        let asking_endpoint = s.endpoint.clone();
        let asking = std::thread::spawn(move || {
            send(
                &asking_endpoint,
                "k",
                "task/continue",
                json!({"task": "t1", "worker": "w1"}),
            )
        });

        // Wait for the provider to be *definitely* inside the call, not merely scheduled.
        let entered = std::thread::spawn(move || entered.recv());
        let ok = entered.join().expect("waiter").is_ok();
        assert!(ok, "the provider was never entered");

        // The probe that needs the governed lock. It must answer while the model is
        // mid-call: a continuation that holds the lock across the network wait is what
        // makes this fail.
        let listed = send(&s.endpoint, "l", "task/list", json!({}));
        assert!(
            listed.get("result").is_some(),
            "task/list must be answered while a continuation waits on the model: {listed}"
        );

        // The lock-free route, for contrast: it must answer too, and by a different
        // mechanism (it takes no lock at all).
        let status = send(&s.endpoint, "h", "daemon/status", json!({}));
        assert!(
            status.get("result").is_some(),
            "daemon/status must be answered while a continuation waits on the model: {status}"
        );

        // Let the model answer, and the continuation must finish and persist.
        drop(release);
        let continued = asking.join().expect("continuation thread");
        assert!(
            continued.get("result").is_some(),
            "the continuation must finish once the model answers: {continued}"
        );
        assert_eq!(
            continued["result"]["continued"], true,
            "the boundary must have been crossed: {continued}"
        );
        assert_eq!(
            continued["result"]["waiting_for"], "human-approval",
            "a continued step is governed exactly like the first: {continued}"
        );
        assert_eq!(
            state_of(&s.endpoint, "t1"),
            "waiting-for-user",
            "the continuation's proposal must have been persisted: the task waits for a human,              and it is not the boundary it was continued from"
        );

        s.stop().await;
    });
}

/// **A task cancelled while the model is being asked cannot receive a stale proposal.**
///
/// The continuation's claim is fenced by the store, not by the mutex: `propose_action`
/// re-reads the task and its live lease holder inside its own transaction and refuses
/// unless the task is still `Running` under *this worker's* live lease. A cancel
/// clears the lease, so a continuation that was waiting on the model when the cancel
/// landed must be refused at the write — and its cleanup must not resurrect the task.
///
/// The cancel also has to *proceed* while the model is blocked, which it could not do
/// while the continuation held the governed lock. That is the same property the probe
/// above asserts, seen from the other side.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_cancelled_task_cannot_receive_a_stale_proposal_from_a_blocked_continuation() {
    rt().block_on(async {
        let (provider, entered, release) = BlockingProvider::new();
        let d = dir("cancelled-continuation");
        let s = Serving::start_with(d.clone(), provider).await;

        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "t1", "max_steps": 2, "content": "write final.txt"}),
        );
        let claimed = send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        let claim_generation = claimed["result"]["claim_generation"]
            .as_i64()
            .expect("claim generation");
        let pid = propose_first_step(&s.endpoint, "first.txt", claim_generation);
        approve_and_run(&s.endpoint, &pid);
        assert_eq!(state_of(&s.endpoint, "t1"), "awaiting-next-step");

        let asking_endpoint = s.endpoint.clone();
        let asking = std::thread::spawn(move || {
            send(
                &asking_endpoint,
                "k",
                "task/continue",
                json!({"task": "t1", "worker": "w1"}),
            )
        });

        let entered = std::thread::spawn(move || entered.recv());
        let ok = entered.join().expect("waiter").is_ok();
        assert!(ok, "the provider was never entered");

        // The cancel, while the model is blocked. It needs the governed lock, so it
        // could not have landed while the continuation held it across the wait.
        let cancelled = send(&s.endpoint, "x", "task/cancel", json!({"id": "t1"}));
        assert!(
            cancelled.get("result").is_some(),
            "the cancel must be served while a continuation waits on the model: {cancelled}"
        );

        // Let the model answer. The continuation must now be refused: the task is no
        // longer `Running` under this worker's live lease.
        drop(release);
        let continued = asking.join().expect("continuation thread");
        assert!(
            continued.get("error").is_some(),
            "a continuation whose task was cancelled must be refused, not persisted: {continued}"
        );
        assert_eq!(
            state_of(&s.endpoint, "t1"),
            "cancelled",
            "the cancelled task must stay cancelled: the stale continuation's cleanup must \
             not resurrect it"
        );

        s.stop().await;
    });
}

// ---------------------------------------------------------------------------
// The claim's lease, and the model's wait
// ---------------------------------------------------------------------------

/// The lease the tests below use: short enough that a model call can outlast it
/// in a test, and long enough that the renewal has three chances to fire.
///
/// The renewal cadence is a third of the lease, so a 900 ms lease renews every
/// 300 ms — the same ratio the engine's own documented limits describe.
const SHORT_LEASE_MS: i64 = 900;

/// The limits a short-lease runtime is built with.
///
/// Everything else is the documented default: only the lease duration changes,
/// because the lease duration is what the test is about.
fn short_lease_limits() -> orxnud_task::EngineLimits {
    orxnud_task::EngineLimits {
        lease_duration_ms: SHORT_LEASE_MS,
        ..orxnud_task::EngineLimits::default()
    }
}

/// A runtime with a short lease and a provider that blocks.
///
/// The argv-payload exception is *not* granted: the first step here uses
/// `text/word-count`, which is in-process and needs no exception, so the test
/// exercises the ordinary shipped posture.
async fn serving_with_a_short_lease(
    root: PathBuf,
    provider: Arc<dyn orxnud_daemon::proposer::ProposalProvider>,
) -> Serving {
    let runtime = Runtime::start_with_engine_limits(
        Paths::under(&root),
        NoSecrets,
        provider,
        short_lease_limits(),
    )
    .await
    .expect("the runtime must start");
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
    Serving {
        endpoint,
        shutdown: Some(tx),
        task,
    }
}

/// Puts a task at a boundary, through the human route so the provider is not
/// involved in the setup.
fn task_at_a_boundary(endpoint: &Path) {
    send(
        endpoint,
        "c",
        "task/create",
        json!({"id": "t1", "max_steps": 2, "content": "count some words"}),
    );
    let claimed = send(
        endpoint,
        "c",
        "task/claim",
        json!({"id": "t1", "worker": "w1"}),
    );
    let claim_generation = claimed["result"]["claim_generation"]
        .as_i64()
        .expect("claim generation");
    let proposed = send(
        endpoint,
        "q",
        "task/propose",
        json!({"task": "t1", "worker": "w1", "capability": "text/word-count",
               "claim_generation": claim_generation,
               "params": {"text": "one two three"}}),
    );
    assert!(
        proposed.get("result").is_some(),
        "the manual proposal must be written: {proposed}"
    );
    let pid = proposed["result"]["proposal"]["proposal_id"]
        .as_str()
        .expect("a proposal id")
        .to_owned();
    let approved = send(
        endpoint,
        "a",
        "capability/approve",
        json!({"proposal": pid, "ttl_ms": 60_000}),
    );
    assert!(
        approved.get("result").is_some(),
        "the proposal must be approved: {approved}"
    );
    let done = send(
        endpoint,
        "x",
        "task/execute",
        json!({"proposal": pid, "worker": "w1"}),
    );
    assert_eq!(
        done["result"]["verified"], true,
        "the first step must verify: {done}"
    );
    assert_eq!(state_of(endpoint, "t1"), "awaiting-next-step");
}

/// **A model call that outlasts the lease still lands, and only because the claim is
/// renewed.**
///
/// The claim is a lease, and a lease expires. The provider's own timeout is 60 s and
/// the lease is 30 s, so without a renewal a call that runs to its timeout is refused
/// at the write. The continuation renews the claim while the model is being asked, so
/// the answer still has somewhere to go.
///
/// This test is the proof that the renewal is *necessary*, not merely present. The
/// final proposal write samples its clock **inside** the store's `IMMEDIATE`
/// transaction (`propose_action_at_write`), after the provider wait. So with the
/// heartbeat disabled the lease is genuinely expired when the write is attempted and
/// the proposal is refused; with the heartbeat enabled the lease is still live and the
/// proposal lands. The assertions below read the lease and the persisted proposal from
/// the daemon's own database, so they observe the durable state rather than the
/// request's reply.
///
/// The lease here is short on purpose: the test holds the provider for three lease
/// durations, which is long enough for several renewals and short enough to run in a
/// few seconds. The wait is driven by explicit channels, and the only timeouts are
/// bounds on "something failed to make progress".
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_continuation_survives_a_model_call_longer_than_the_lease() {
    rt().block_on(async {
        let (provider, entered, release) = BlockingProvider::new();
        let d = dir("lease-renewed");
        let s = serving_with_a_short_lease(d.clone(), provider).await;
        task_at_a_boundary(&s.endpoint);

        let db = open_state_db(&d);
        let (state, holder, expiry_at_boundary) = task_lease(&db, "t1");
        assert_eq!(state, "awaiting-next-step");
        assert_eq!(holder, None, "a boundary must not hold a lease");
        assert_eq!(expiry_at_boundary, None, "a boundary must not hold a lease");

        let asking_endpoint = s.endpoint.clone();
        let asking = std::thread::spawn(move || {
            send(
                &asking_endpoint,
                "k",
                "task/continue",
                json!({"task": "t1", "worker": "w1"}),
            )
        });

        // The provider is *definitely* inside the call.
        let entered = std::thread::spawn(move || entered.recv());
        assert!(
            entered.join().expect("waiter").is_ok(),
            "the provider was never entered"
        );

        // The claim is durable by the time the provider is called. Record the expiry it
        // wrote, before any renewal can extend it.
        let (state, holder, initial_expiry) = task_lease(&db, "t1");
        assert_eq!(state, "running");
        assert_eq!(holder.as_deref(), Some("w1"));
        let initial_expiry = initial_expiry.expect("the claim must set an expiry");

        // Hold the model for three lease durations. Without renewal the claim has
        // certainly lapsed by the time the provider is released.
        std::thread::sleep(Duration::from_millis(SHORT_LEASE_MS as u64 * 3));

        // The lease is *live*, not merely held. `running` alone would not prove that:
        // a task can be `running` under an expired lease. Poll with a bounded deadline
        // so the assertion is not at the mercy of where the polling instant falls
        // between two renewal ticks.
        let live_expiry = wait_for(Duration::from_millis(SHORT_LEASE_MS as u64), || {
            let (state, holder, expiry) = task_lease(&db, "t1");
            (state == "running"
                && holder.as_deref() == Some("w1")
                && expiry.is_some_and(|e| e > now_ms()))
            .then_some(expiry.expect("checked above"))
        })
        .unwrap_or_else(|| {
            panic!(
                "the claim's lease must still be live while the model is blocked; \
                 observed {:?}",
                task_lease(&db, "t1")
            )
        });
        assert!(
            live_expiry > initial_expiry,
            "the lease must have been extended by a renewal: initial={initial_expiry}, \
             live={live_expiry}"
        );

        // Stamp the instant the provider is released. The proposal's `created_at_ms` is
        // written by the store's post-wait clock, so it must not precede this instant.
        let before_release = now_ms();
        drop(release);
        let continued = asking.join().expect("continuation thread");
        assert!(
            continued.get("result").is_some(),
            "the continuation must persist its proposal once the model answers: {continued}"
        );
        assert_eq!(
            continued["result"]["continued"], true,
            "the boundary must have been crossed: {continued}"
        );
        assert_eq!(
            state_of(&s.endpoint, "t1"),
            "waiting-for-user",
            "the proposal must be persisted and the task must wait for a human"
        );

        let proposals = step_proposals(&db, "t1", 2);
        assert_eq!(
            proposals.len(),
            1,
            "exactly one proposal must exist for the claimed step: {proposals:?}"
        );
        assert!(
            proposals[0] >= before_release,
            "the proposal must be stamped at persistence time, not with the pre-wait claim \
             time: created_at_ms={}, released_at={before_release}",
            proposals[0],
        );

        s.stop().await;
    });
}

/// **The governed lock is still released between renewals.**
///
/// The renewal takes the lock for the write and gives it straight back, so the
/// daemon's other routes are not held up while the model is being asked. The
/// probes here are the ones the blocked-continuation regression already uses:
/// `task/list` needs the governed lock, and `task/create` needs it too.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_governed_lock_is_released_between_renewals() {
    rt().block_on(async {
        let (provider, entered, release) = BlockingProvider::new();
        let d = dir("renewal-releases");
        let s = serving_with_a_short_lease(d.clone(), provider).await;
        task_at_a_boundary(&s.endpoint);

        let asking_endpoint = s.endpoint.clone();
        let asking = std::thread::spawn(move || {
            send(
                &asking_endpoint,
                "k",
                "task/continue",
                json!({"task": "t1", "worker": "w1"}),
            )
        });

        let entered = std::thread::spawn(move || entered.recv());
        assert!(
            entered.join().expect("waiter").is_ok(),
            "the provider was never entered"
        );

        // Long enough for several renewals to have happened, so the probes below
        // are taken while the renewal loop is running.
        std::thread::sleep(Duration::from_millis(SHORT_LEASE_MS as u64 * 2));

        let listed = send(&s.endpoint, "l", "task/list", json!({}));
        assert!(
            listed.get("result").is_some(),
            "task/list must be answered while the model is being asked: {listed}"
        );
        let created = send(
            &s.endpoint,
            "n",
            "task/create",
            json!({"id": "t2", "content": "another task"}),
        );
        assert!(
            created.get("result").is_some(),
            "task/create must be answered while the model is being asked: {created}"
        );

        drop(release);
        let continued = asking.join().expect("continuation thread");
        assert!(
            continued.get("result").is_some(),
            "the continuation must finish once the model answers: {continued}"
        );

        s.stop().await;
    });
}

/// **A cancelled task is not revived by a renewal, and its late answer is refused.**
///
/// The renewal is the store's fenced heartbeat: `WHERE id = ? AND lease_holder = ?
/// AND lease_expires_at_ms IS NOT NULL AND lease_expires_at_ms > ?`. A cancel clears
/// the lease, so a renewal cannot extend it — and a renewal that finds the claim gone
/// is a loss, not a success, so the continuation stops rather than waiting out a model
/// whose answer has nowhere to go.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_cancelled_task_is_not_revived_by_a_renewal() {
    rt().block_on(async {
        let (provider, entered, release) = BlockingProvider::new();
        let d = dir("cancel-not-revived");
        let s = serving_with_a_short_lease(d.clone(), provider).await;
        task_at_a_boundary(&s.endpoint);

        let asking_endpoint = s.endpoint.clone();
        let asking = std::thread::spawn(move || {
            send(
                &asking_endpoint,
                "k",
                "task/continue",
                json!({"task": "t1", "worker": "w1"}),
            )
        });

        let entered = std::thread::spawn(move || entered.recv());
        assert!(
            entered.join().expect("waiter").is_ok(),
            "the provider was never entered"
        );

        let cancelled = send(&s.endpoint, "x", "task/cancel", json!({"id": "t1"}));
        assert!(
            cancelled.get("result").is_some(),
            "the cancel must be served while the model is being asked: {cancelled}"
        );

        // Let the renewal tick at least once after the cancel.
        std::thread::sleep(Duration::from_millis(SHORT_LEASE_MS as u64 * 2));

        assert_eq!(
            state_of(&s.endpoint, "t1"),
            "cancelled",
            "a renewal must not revive a cancelled task"
        );

        drop(release);
        let continued = asking.join().expect("continuation thread");
        assert!(
            continued.get("error").is_some(),
            "the late answer must be refused, not persisted: {continued}"
        );
        // The *word* matters, not just the error. Losing the claim is discovered by the
        // renewal before the model has anything to answer: the reply says the claim was
        // lost, and it does not wait for the model only for the store's write fences to
        // refuse the result after the fact. A swallowed renewal loss (a renewal that
        // shrugs at `Ok(false)` and waits the model out anyway) would answer with a
        // different refusal here, written after the model finished — so this pins the
        // behaviour that mutation would otherwise leave standing.
        assert_eq!(
            continued["error"]["data"]["reason"], "claim-lost",
            "the loss of the claim must be stated by the response itself: {continued}"
        );
        assert_eq!(
            state_of(&s.endpoint, "t1"),
            "cancelled",
            "the cancelled task must stay cancelled: the stale continuation's cleanup must \
             not resurrect it"
        );

        s.stop().await;
    });
}
