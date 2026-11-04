//! CONC-002 daemon-boundary evidence: a stale claim generation cannot mutate a task
//! through the daemon IPC interface after recovery and a same-name re-claim.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use orxnud_daemon::Paths;
use orxnud_daemon::runtime::Runtime;
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use orxnud_protocol::error::RpcErrorCode;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};

struct NoSecrets;

#[derive(Debug, thiserror::Error)]
#[error("no secret store in the CONC-002 IPC suite")]
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
    let d = std::env::temp_dir().join(format!("orxnud-conc002-ipc-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

fn send_raw(endpoint: &Path, line: &[u8]) -> Option<Value> {
    let mut s = orxnud_platform_ipc::connect_blocking(endpoint)?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
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
        let runtime =
            Runtime::start_permitting_argv_payload_exposure(Paths::under(&root), NoSecrets)
                .await
                .expect("the runtime must start")
                .with_proposer(orxnud_daemon::runtime::scripted_proposer());
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

/// One durable proposal row, without the proposer's JSON.
///
/// The fields chosen are the ones a refused proposal could plausibly have changed:
/// identity, attempt, capability, target, status and both timestamps. A response-only
/// assertion cannot see a duplicate proposal written under a second id, so the row
/// itself is compared before and after every rejected request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProposalRow {
    proposal_id: String,
    attempt_no: i64,
    capability: String,
    target: Option<String>,
    status: String,
    created_at_ms: i64,
    decided_at_ms: Option<i64>,
}

/// One durable task-event row, in transition-log order.
///
/// `seq` is included as well as the columns because a reused sequence number is itself
/// evidence that the append-only log changed, which is the property a fence has to leave
/// alone.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EventRow {
    seq: i64,
    kind: String,
    from_state: Option<String>,
    to_state: Option<String>,
    worker: Option<String>,
    attempt_no: Option<i64>,
    detail: Option<String>,
}

/// The durable state one rejected request must not change.
///
/// Read from a fresh read-only connection on every snapshot rather than retained across
/// requests: WAL means the daemon's commits are visible without taking a shared lock,
/// and a retained handle would make "the row after the refusal" a value captured before it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableTask {
    state: String,
    lease_holder: Option<String>,
    lease_expires_at_ms: Option<i64>,
    claim_generation: i64,
    attempts: i64,
    proposals: Vec<ProposalRow>,
    events: Vec<EventRow>,
}

/// Reads one task and its proposal/event rows read-only.
///
/// Nothing here writes: `SQLITE_OPEN_READ_ONLY` cannot insert, update, checkpoint or
/// migrate. The assertions are about observable durable state, so the query is against
/// the real file the daemon wrote.
fn read_durable_task(root: &Path, task_id: &str) -> DurableTask {
    let conn = Connection::open_with_flags(root.join("state.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open the durable state read-only");
    let (state, lease_holder, lease_expires_at_ms, claim_generation, attempts) = conn
        .query_row(
            "SELECT state, lease_holder, lease_expires_at_ms, claim_generation, attempts
               FROM tasks WHERE id = ?1;",
            [task_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )
        .expect("the durable task row");

    let proposals = {
        let mut stmt = conn
            .prepare(
                "SELECT proposal_id, attempt_no, capability, target, status, created_at_ms,
                        decided_at_ms
                   FROM task_proposals WHERE task_id = ?1 ORDER BY proposal_id;",
            )
            .expect("prepare the proposal query");
        let rows = stmt
            .query_map([task_id], |r| {
                Ok(ProposalRow {
                    proposal_id: r.get(0)?,
                    attempt_no: r.get(1)?,
                    capability: r.get(2)?,
                    target: r.get(3)?,
                    status: r.get(4)?,
                    created_at_ms: r.get(5)?,
                    decided_at_ms: r.get(6)?,
                })
            })
            .expect("query the proposal rows");
        rows.map(|row| row.expect("a proposal row")).collect()
    };

    let events = {
        let mut stmt = conn
            .prepare(
                "SELECT seq, kind, from_state, to_state, worker, attempt_no, detail
                   FROM task_events WHERE task_id = ?1 ORDER BY seq;",
            )
            .expect("prepare the event query");
        let rows = stmt
            .query_map([task_id], |r| {
                Ok(EventRow {
                    seq: r.get(0)?,
                    kind: r.get(1)?,
                    from_state: r.get(2)?,
                    to_state: r.get(3)?,
                    worker: r.get(4)?,
                    attempt_no: r.get(5)?,
                    detail: r.get(6)?,
                })
            })
            .expect("query the event rows");
        rows.map(|row| row.expect("an event row")).collect()
    };

    DurableTask {
        state,
        lease_holder,
        lease_expires_at_ms,
        claim_generation,
        attempts,
        proposals,
        events,
    }
}

/// Asserts the exact wire refusal, not merely that an error object exists.
///
/// The code says which kind of recovery applies; `data.reason` says which lease refusal
/// happened. A test that accepts either as "some error" passes if the request is refused
/// for a malformed reason, which is the wrong property for a fence.
fn assert_refusal(reply: &Value, code: RpcErrorCode, reason: &str, what: &str) {
    let error = reply.get("error").unwrap_or_else(|| {
        panic!("{what} must be refused: {reply}");
    });
    assert_eq!(
        error["code"].as_i64().expect("an error code"),
        i64::from(code.code()),
        "{what} must use the expected protocol code: {reply}"
    );
    assert_eq!(
        error["data"]["reason"].as_str().expect("a stable reason"),
        reason,
        "{what} must use the expected refusal reason: {reply}"
    );
}

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows"
)]
#[test]
fn conc002_ipc_same_name_claim_fencing() {
    rt().block_on(async {
        let root = dir("same-name");
        let worker = "same-worker";

        let first = Serving::start(root.clone()).await;
        for id in ["t-complete", "t-propose"] {
            send(
                &first.endpoint,
                "create",
                "task/create",
                json!({"id": id, "content": "conc002"}),
            );
        }

        let first_complete_claim = send(
            &first.endpoint,
            "claim-complete",
            "task/claim",
            json!({"id": "t-complete", "worker": worker}),
        );
        let g1_complete = first_complete_claim["result"]["claim_generation"]
            .as_i64()
            .expect("first complete generation");

        let first_propose_claim = send(
            &first.endpoint,
            "claim-propose",
            "task/claim",
            json!({"id": "t-propose", "worker": worker}),
        );
        let g1_propose = first_propose_claim["result"]["claim_generation"]
            .as_i64()
            .expect("first propose generation");

        // Stop the first daemon. Its startup-recovered successor will reclaim both tasks.
        first.stop().await;

        let second = Serving::start(root.clone()).await;

        let second_complete_claim = send(
            &second.endpoint,
            "claim-complete-2",
            "task/claim",
            json!({"id": "t-complete", "worker": worker}),
        );
        let g2_complete = second_complete_claim["result"]["claim_generation"]
            .as_i64()
            .expect("second complete generation");
        assert_ne!(
            g1_complete, g2_complete,
            "recovery must mint a new generation"
        );

        let second_propose_claim = send(
            &second.endpoint,
            "claim-propose-2",
            "task/claim",
            json!({"id": "t-propose", "worker": worker}),
        );
        let g2_propose = second_propose_claim["result"]["claim_generation"]
            .as_i64()
            .expect("second propose generation");
        assert_ne!(
            g1_propose, g2_propose,
            "recovery must mint a new generation"
        );

        // Missing generation is rejected by the daemon boundary, and the refusal is the
        // request-validation one rather than a lease conflict: the request is malformed
        // before the store is asked whether a lease exists.
        let before_missing_complete = read_durable_task(&root, "t-complete");
        let missing = send(
            &second.endpoint,
            "missing-complete",
            "task/complete",
            json!({"id": "t-complete", "worker": worker}),
        );
        assert_refusal(
            &missing,
            RpcErrorCode::INVALID_REQUEST,
            "invalid-request",
            "task/complete without a claim generation",
        );
        assert_eq!(
            read_durable_task(&root, "t-complete"),
            before_missing_complete,
            "a missing-generation completion must not change durable state"
        );

        // A stale generation cannot complete the task, and it cannot leave a partial
        // mutation behind while refusing. The snapshot covers the row, its lease, its
        // counter, its proposal rows and its transition log.
        let before_stale_complete = read_durable_task(&root, "t-complete");
        let stale_complete = send(
            &second.endpoint,
            "stale-complete",
            "task/complete",
            json!({
                "id": "t-complete",
                "worker": worker,
                "claim_generation": g1_complete,
            }),
        );
        assert_refusal(
            &stale_complete,
            RpcErrorCode::CONFLICT,
            "fenced",
            "task/complete with a stale claim generation",
        );
        assert_eq!(
            read_durable_task(&root, "t-complete"),
            before_stale_complete,
            "a stale completion must not change durable state"
        );

        // The current generation can complete the task.
        let current_complete = send(
            &second.endpoint,
            "current-complete",
            "task/complete",
            json!({
                "id": "t-complete",
                "worker": worker,
                "claim_generation": g2_complete,
            }),
        );
        assert_eq!(
            current_complete["result"]["task"]["state"], "completed",
            "the current claim must be able to complete: {current_complete}"
        );

        // A stale generation cannot propose. The snapshot catches a proposal row written
        // under a different id, and the event log catches a transition that the refusal
        // did not report.
        let before_stale_propose = read_durable_task(&root, "t-propose");
        let stale_propose = send(
            &second.endpoint,
            "stale-propose",
            "task/propose",
            json!({
                "task": "t-propose",
                "worker": worker,
                "capability": "filesystem/write-text",
                "claim_generation": g1_propose,
                "target": "out.txt",
                "params": {"path": "out.txt", "contents": "x"},
            }),
        );
        assert_refusal(
            &stale_propose,
            RpcErrorCode::CONFLICT,
            "conflict",
            "task/propose with a stale claim generation",
        );
        assert_eq!(
            read_durable_task(&root, "t-propose"),
            before_stale_propose,
            "a stale proposal must not change durable state"
        );

        // The current generation can propose.
        let current_propose = send(
            &second.endpoint,
            "current-propose",
            "task/propose",
            json!({
                "task": "t-propose",
                "worker": worker,
                "capability": "filesystem/write-text",
                "claim_generation": g2_propose,
                "target": "out.txt",
                "params": {"path": "out.txt", "contents": "x"},
            }),
        );
        assert!(
            current_propose["result"]["proposal"].is_object(),
            "the current claim must be able to propose: {current_propose}"
        );

        // Missing generation is refused on both proposal routes, and both refusals are
        // request-validation refusals: `task/propose` calls the same required-generation
        // reader before the fence, and `task/ai-propose` calls it before the provider is
        // gathered or asked, so no provider request and no durable row can result.
        send(
            &second.endpoint,
            "create-ai",
            "task/create",
            json!({"id": "t-ai", "content": "conc002"}),
        );
        let ai_claim = send(
            &second.endpoint,
            "claim-ai",
            "task/claim",
            json!({"id": "t-ai", "worker": worker}),
        );
        let g2_ai = ai_claim["result"]["claim_generation"]
            .as_i64()
            .expect("the AI route's current generation");

        let before_missing_propose = read_durable_task(&root, "t-ai");
        let missing_propose = send(
            &second.endpoint,
            "missing-propose",
            "task/propose",
            json!({
                "task": "t-ai",
                "worker": worker,
                "capability": "filesystem/write-text",
                "target": "out.txt",
                "params": {"path": "out.txt", "contents": "x"},
            }),
        );
        assert_refusal(
            &missing_propose,
            RpcErrorCode::INVALID_REQUEST,
            "invalid-request",
            "task/propose without a claim generation",
        );
        assert_eq!(
            read_durable_task(&root, "t-ai"),
            before_missing_propose,
            "a missing-generation proposal must not change durable state"
        );

        let before_missing_ai = read_durable_task(&root, "t-ai");
        let missing_ai = send(
            &second.endpoint,
            "missing-ai",
            "task/ai-propose",
            json!({"task": "t-ai", "worker": worker}),
        );
        assert_refusal(
            &missing_ai,
            RpcErrorCode::INVALID_REQUEST,
            "invalid-request",
            "task/ai-propose without a claim generation",
        );
        assert_eq!(
            read_durable_task(&root, "t-ai"),
            before_missing_ai,
            "a missing-generation AI proposal must not change durable state"
        );

        // The genuine generation still reaches the configured provider route, so the two
        // refusals above are not an accidentally broken provider path.
        let current_ai = send(
            &second.endpoint,
            "current-ai",
            "task/ai-propose",
            json!({"task": "t-ai", "worker": worker, "claim_generation": g2_ai}),
        );
        assert_eq!(
            current_ai["result"]["proposed_by"], "ai",
            "the current claim must reach the AI proposal route: {current_ai}"
        );

        // A generation from one task cannot mutate another task. This is the recovery-era
        // case: it is already stale for its own task as well, so it proves cross-task and
        // stale refusal but not live foreign-generation refusal. The dedicated
        // `conc002_ipc_live_cross_task_generation_fencing` test covers that case.
        let before_cross_task = read_durable_task(&root, "t-propose");
        let cross_task = send(
            &second.endpoint,
            "cross-task",
            "task/complete",
            json!({
                "id": "t-propose",
                "worker": worker,
                "claim_generation": g1_complete,
            }),
        );
        assert_refusal(
            &cross_task,
            RpcErrorCode::CONFLICT,
            "fenced",
            "task/complete with another task's stale claim generation",
        );
        assert_eq!(
            read_durable_task(&root, "t-propose"),
            before_cross_task,
            "a cross-task completion must not change the named task"
        );

        second.stop().await;
    });
}

/// A **live** generation from one task cannot mutate another task.
///
/// `claim_generation` is a per-task counter, not a globally unique token: two tasks can
/// legitimately hold the same value. This test therefore arranges B's counter to differ
/// from A's while both leases are live, so the refusal is attributable to task-specific
/// generation enforcement rather than to a stale, expired or absent lease.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows"
)]
#[test]
fn conc002_ipc_live_cross_task_generation_fencing() {
    rt().block_on(async {
        let root = dir("cross-live");
        let worker = "cross-worker";

        // B is claimed once, then production recovery reclaims it and the same worker
        // claims it again, so B's live counter is the post-recovery one and is not 1.
        let first = Serving::start(root.clone()).await;
        send(
            &first.endpoint,
            "create-b",
            "task/create",
            json!({"id": "cross-b", "content": "conc002"}),
        );
        let b_first = send(
            &first.endpoint,
            "claim-b-1",
            "task/claim",
            json!({"id": "cross-b", "worker": worker}),
        );
        let b_generation_before_recovery = b_first["result"]["claim_generation"]
            .as_i64()
            .expect("B's pre-recovery generation");
        first.stop().await;

        let second = Serving::start(root.clone()).await;
        let b_reclaimed = send(
            &second.endpoint,
            "claim-b-2",
            "task/claim",
            json!({"id": "cross-b", "worker": worker}),
        );
        let b_generation = b_reclaimed["result"]["claim_generation"]
            .as_i64()
            .expect("B's live post-recovery generation");
        assert_ne!(
            b_generation_before_recovery, b_generation,
            "B must hold a post-recovery generation for this case"
        );

        // A is claimed for the first time under the same daemon, so its live generation is
        // its own first claim and, by construction in this fixture, differs from B's.
        send(
            &second.endpoint,
            "create-a",
            "task/create",
            json!({"id": "cross-a", "content": "conc002"}),
        );
        let a_claim = send(
            &second.endpoint,
            "claim-a",
            "task/claim",
            json!({"id": "cross-a", "worker": worker}),
        );
        let a_generation = a_claim["result"]["claim_generation"]
            .as_i64()
            .expect("A's live generation");
        assert_ne!(
            a_generation, b_generation,
            "this case requires A and B to hold different live generations"
        );

        // Both generations are genuinely live before either is used against the other.
        let a_before = read_durable_task(&root, "cross-a");
        assert_eq!(a_before.state, "running", "{a_before:?}");
        assert_eq!(a_before.lease_holder.as_deref(), Some(worker));
        assert_eq!(a_before.claim_generation, a_generation);
        assert!(a_before.lease_expires_at_ms.is_some());

        let b_before = read_durable_task(&root, "cross-b");
        assert_eq!(b_before.state, "running", "{b_before:?}");
        assert_eq!(b_before.lease_holder.as_deref(), Some(worker));
        assert_eq!(b_before.claim_generation, b_generation);
        assert!(b_before.lease_expires_at_ms.is_some());

        // A's live generation cannot complete B. Snapshot B first: the durable row, its
        // proposal rows and its transition log must be byte-for-byte as they were.
        let cross_task = send(
            &second.endpoint,
            "cross-live",
            "task/complete",
            json!({
                "id": "cross-b",
                "worker": worker,
                "claim_generation": a_generation,
            }),
        );
        assert_refusal(
            &cross_task,
            RpcErrorCode::CONFLICT,
            "fenced",
            "task/complete with a live generation from another task",
        );
        assert_eq!(
            read_durable_task(&root, "cross-b"),
            b_before,
            "a live foreign generation must not change the target task"
        );

        // Both live generations remain successful after the refused cross-task write.
        let a_current = send(
            &second.endpoint,
            "current-a",
            "task/complete",
            json!({
                "id": "cross-a",
                "worker": worker,
                "claim_generation": a_generation,
            }),
        );
        assert_eq!(
            a_current["result"]["task"]["state"], "completed",
            "A's own live generation must still complete A: {a_current}"
        );

        let b_current = send(
            &second.endpoint,
            "current-b",
            "task/complete",
            json!({
                "id": "cross-b",
                "worker": worker,
                "claim_generation": b_generation,
            }),
        );
        assert_eq!(
            b_current["result"]["task"]["state"], "completed",
            "B's own live generation must still complete B: {b_current}"
        );

        second.stop().await;
    });
}
