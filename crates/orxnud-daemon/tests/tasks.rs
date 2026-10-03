//! The task workflow, end to end, over a real socket.
//!
//! # What is actually exercised
//!
//! An **external client** — a separate connection to a real Unix domain socket,
//! speaking JSON-RPC — against a real `Runtime` over a real SQLite file. Nothing in
//! this file calls `TaskService` or `DurableEngine` directly. That is the whole
//! point: the properties worth protecting here are arrangement properties (a task
//! survives a restart, a lease fences a stranger out, `pending` cannot jump to
//! `completed`), and none of them is observable from a test that skips the transport
//! and the daemon's routing.
//!
//! The one place this file reads the database directly is to *check durability*
//! after the runtime has gone — reading `task_events` and `tasks` back out of the
//! file is how "it was really written down" is distinguished from "the reply said
//! so". That is an assertion about storage, not a substitute for the request path.
//!
//! # Why there is no fixed sleep
//!
//! Readiness is established by asking the daemon a question it can only answer once
//! `serve` is polling, and by waiting for the socket to appear — never by sleeping a
//! guessed interval. A fixed sleep is either slower than it needs to be or flaky, and
//! usually both at once.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use orxnud_daemon::Paths;
use orxnud_daemon::runtime::Runtime;
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use orxnud_protocol::error::RpcErrorCode;
use serde_json::{Value, json};

/// A secret store with nothing in it.
///
/// Present because the runtime is generic over `SecretsContract`; it also keeps this
/// suite off the user's real keyring, which is what keeps it hermetic.
struct NoSecrets;

#[derive(Debug, thiserror::Error)]
#[error("no secret store in the task suite")]
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
    let d = std::env::temp_dir().join(format!("orxnud-tasks-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// Multi-threaded: these drive a blocking client while the runtime serves elsewhere.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

/// One request over a real connection, as a raw line.
///
/// Raw so a case can send bytes the protocol crate would refuse to build, which is
/// how the malformed cases are expressed. Every literal is one line: the transport is
/// newline-delimited, so a newline inside the JSON arrives as a truncated frame.
fn send_raw(endpoint: &Path, line: &[u8]) -> Option<Value> {
    let mut s = std::os::unix::net::UnixStream::connect(endpoint).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let _ = s.write_all(line);
    let _ = s.write_all(b"\n");
    let _ = s.flush();
    let mut reader = BufReader::new(s);
    let mut reply = String::new();
    reader.read_line(&mut reply).ok()?;
    serde_json::from_str(&reply).ok()
}

/// A well-formed request, built with the protocol types so the test cannot drift
/// from the wire vocabulary.
fn send(endpoint: &Path, id: &str, method: &str, params: Value) -> Value {
    let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let line = serde_json::to_vec(&frame).expect("encode");
    send_raw(endpoint, &line).unwrap_or_else(|| panic!("{method} must answer"))
}

/// Waits until the daemon answers, by asking it something only a serving daemon can do.
///
/// A readiness *probe*, not a sleep: `daemon/version` needs no arguments, touches no
/// durable state, and cannot be answered by a socket file that exists but has nothing
/// polling it. Bounded so a runtime that never comes up fails the test with a clear
/// message instead of hanging.
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

/// A started, serving runtime plus the directory it is serving from.
///
/// Returned rather than scoped so a test can stop it *the way it chooses* — an
/// orderly shutdown and a crash are different events, and the recovery test needs
/// the second one.
struct Serving {
    endpoint: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Serving {
    async fn start(root: PathBuf) -> Self {
        let runtime = Runtime::start(Paths::under(&root), NoSecrets)
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
        Self {
            endpoint,
            shutdown: Some(tx),
            task,
        }
    }

    /// Orderly stop: the serve loop returns and the endpoint is released.
    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }

    /// A crash: the serve task is dropped mid-flight, so nothing gets to run a
    /// graceful release. Whatever the in-memory owner was holding stays held in the
    /// database, which is the situation recovery exists for.
    async fn crash(self) {
        self.task.abort();
    }
}

/// The migrated, verified connection the runtime wrote to.
///
/// Opened through the store's own adapter rather than a bare `rusqlite::Connection`,
/// which is both the convention the rest of this suite follows and a check in its own
/// right: if the runtime had left the database unmigrated, this would refuse.
fn conn(root: &Path) -> orxnud_store::security_state::SqliteAuditJournal {
    orxnud_store::security_state::SqliteAuditJournal::open(&root.join("state.db"))
        .expect("open the store the runtime wrote")
}

/// Reads the durable task rows straight out of the file.
///
/// An assertion about storage, used only after the runtime is gone.
fn tasks_in_file(root: &Path) -> Vec<(String, String, Option<String>)> {
    let db = conn(root);
    let mut stmt = db
        .conn()
        .prepare("SELECT id, state, payload FROM tasks ORDER BY id;")
        .expect("prepare");
    let rows = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("query");
    rows.map(|r| r.expect("row")).collect()
}

/// Reads the task event log straight out of the file.
fn events_for(root: &Path, task_id: &str) -> Vec<String> {
    let db = conn(root);
    let mut stmt = db
        .conn()
        .prepare("SELECT kind FROM task_events WHERE task_id = ?1 ORDER BY seq;")
        .expect("prepare");
    let rows = stmt
        .query_map([task_id], |r| r.get::<_, String>(0))
        .expect("query");
    rows.map(|r| r.expect("row")).collect()
}

// ---------------------------------------------------------------------------
// The workflow
// ---------------------------------------------------------------------------

#[test]
fn create_list_claim_complete_runs_over_the_socket() {
    rt().block_on(async {
        let root = dir("workflow");
        let s = Serving::start(root.clone()).await;

        // create
        let created = send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "buy milk"}),
        );
        let task = &created["result"]["task"];
        assert_eq!(task["id"], "t-1");
        assert_eq!(task["state"], "pending", "a new task starts pending");
        assert_eq!(
            task["content"], "buy milk",
            "content must survive the round trip"
        );
        assert_eq!(task["attempts"], 0);

        // list: present, with the content intact
        let listed = send(&s.endpoint, "2", "task/list", json!({}));
        assert_eq!(listed["result"]["count"], 1);
        assert_eq!(listed["result"]["tasks"][0]["id"], "t-1");
        assert_eq!(listed["result"]["tasks"][0]["content"], "buy milk");

        // claim: running, with a lease
        let claimed = send(
            &s.endpoint,
            "3",
            "task/claim",
            json!({"id": "t-1", "worker": "w1"}),
        );
        assert_eq!(claimed["result"]["task"]["state"], "running");
        assert_eq!(claimed["result"]["attempt"], 1);
        assert_eq!(claimed["result"]["task"]["lease_holder"], "w1");
        assert!(
            claimed["result"]["lease_expires_at_ms"].is_i64(),
            "a claim must report the lease it granted"
        );

        // list again: the claim is visible through the durable read path
        let listed = send(&s.endpoint, "4", "task/list", json!({}));
        assert_eq!(listed["result"]["tasks"][0]["state"], "running");

        // complete with the worker that holds the lease
        let done = send(
            &s.endpoint,
            "5",
            "task/complete",
            json!({"id": "t-1", "worker": "w1"}),
        );
        assert_eq!(done["result"]["task"]["state"], "completed");
        assert_eq!(
            done["result"]["task"]["lease_holder"],
            Value::Null,
            "completing must release the lease"
        );

        // list again: the terminal state is what a fresh read sees
        let listed = send(&s.endpoint, "6", "task/list", json!({}));
        assert_eq!(listed["result"]["tasks"][0]["state"], "completed");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&root);
    });
}

#[test]
fn a_completed_task_and_its_events_survive_a_restart() {
    rt().block_on(async {
        let root = dir("durable");
        {
            let s = Serving::start(root.clone()).await;
            send(
                &s.endpoint,
                "1",
                "task/create",
                json!({"id": "t-1", "kind": "query", "content": "survive me"}),
            );
            send(
                &s.endpoint,
                "2",
                "task/claim",
                json!({"id": "t-1", "worker": "w1"}),
            );
            send(
                &s.endpoint,
                "3",
                "task/complete",
                json!({"id": "t-1", "worker": "w1"}),
            );
            s.stop().await;
        }

        // On disk, before any restart: the row and the whole event trail.
        let on_disk = tasks_in_file(&root);
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].1, "completed");
        assert_eq!(on_disk[0].2.as_deref(), Some("survive me"));
        assert_eq!(
            events_for(&root, "t-1"),
            vec!["enqueued", "claimed", "completed"],
            "every step of the workflow must leave its event"
        );

        // A brand new runtime over the same file.
        let s = Serving::start(root.clone()).await;
        let listed = send(&s.endpoint, "4", "task/list", json!({}));
        assert_eq!(listed["result"]["count"], 1, "the task must survive");
        assert_eq!(listed["result"]["tasks"][0]["state"], "completed");
        assert_eq!(
            listed["result"]["tasks"][0]["content"], "survive me",
            "content must survive the restart"
        );
        s.stop().await;

        // And the events are still there after the second run.
        assert_eq!(
            events_for(&root, "t-1"),
            vec!["enqueued", "claimed", "completed"],
            "the event log must survive the restart"
        );
        let _ = std::fs::remove_dir_all(&root);
    });
}

#[test]
fn a_crashed_run_leaves_a_lease_that_the_next_run_reclaims() {
    rt().block_on(async {
        let root = dir("recover");
        {
            let s = Serving::start(root.clone()).await;
            send(
                &s.endpoint,
                "1",
                "task/create",
                json!({"id": "t-1", "kind": "query", "content": "orphan me"}),
            );
            send(
                &s.endpoint,
                "2",
                "task/claim",
                json!({"id": "t-1", "worker": "doomed"}),
            );
            // No orderly stop: the lease `doomed` holds must still be held on disk.
            s.crash().await;
        }

        let orphaned = tasks_in_file(&root);
        assert_eq!(orphaned[0].1, "running", "the crash left it running");

        // The next runtime recovers it at startup, before serving anything.
        let s = Serving::start(root.clone()).await;
        let listed = send(&s.endpoint, "3", "task/list", json!({}));
        assert_eq!(
            listed["result"]["tasks"][0]["state"], "pending",
            "recovery must put an orphaned lease back in the queue"
        );

        // And the usual workflow continues from there.
        let claimed = send(
            &s.endpoint,
            "4",
            "task/claim",
            json!({"id": "t-1", "worker": "w2"}),
        );
        assert_eq!(claimed["result"]["task"]["state"], "running");
        assert_eq!(
            claimed["result"]["attempt"], 2,
            "recovery does not refund the attempt"
        );
        let done = send(
            &s.endpoint,
            "5",
            "task/complete",
            json!({"id": "t-1", "worker": "w2"}),
        );
        assert_eq!(done["result"]["task"]["state"], "completed");
        s.stop().await;
        let _ = std::fs::remove_dir_all(&root);
    });
}

// ---------------------------------------------------------------------------
// Security and negative cases
// ---------------------------------------------------------------------------

#[test]
fn a_pending_task_cannot_be_completed_without_being_claimed() {
    // The state machine's whole point, over the wire. `Pending -> Completed` is not
    // a legal transition, and there is no request that can talk the daemon into
    // pretending otherwise.
    rt().block_on(async {
        let s = Serving::start(dir("pending-complete")).await;
        send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "x"}),
        );

        let refused = send(
            &s.endpoint,
            "2",
            "task/complete",
            json!({"id": "t-1", "worker": "anyone"}),
        );
        assert_eq!(
            refused["error"]["code"],
            RpcErrorCode::INVALID_REQUEST.code()
        );
        assert_eq!(
            refused["error"]["data"]["reason"], "fenced",
            "a task with no lease is fenced out, not completed"
        );

        // Still pending: the refusal must not have moved it.
        let listed = send(&s.endpoint, "3", "task/list", json!({}));
        assert_eq!(listed["result"]["tasks"][0]["state"], "pending");
        s.stop().await;
    });
}

#[test]
fn a_worker_cannot_complete_a_task_it_does_not_hold() {
    rt().block_on(async {
        let s = Serving::start(dir("wrong-worker")).await;
        send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "x"}),
        );
        send(
            &s.endpoint,
            "2",
            "task/claim",
            json!({"id": "t-1", "worker": "owner"}),
        );

        let stolen = send(
            &s.endpoint,
            "3",
            "task/complete",
            json!({"id": "t-1", "worker": "intruder"}),
        );
        assert_eq!(
            stolen["error"]["code"],
            RpcErrorCode::INVALID_REQUEST.code()
        );
        assert_eq!(stolen["error"]["data"]["reason"], "fenced");

        // The rightful owner can still finish it: the intruder changed nothing.
        let done = send(
            &s.endpoint,
            "4",
            "task/complete",
            json!({"id": "t-1", "worker": "owner"}),
        );
        assert_eq!(done["result"]["task"]["state"], "completed");
        s.stop().await;
    });
}

#[test]
fn a_duplicate_task_id_is_refused_rather_than_overwriting() {
    rt().block_on(async {
        let s = Serving::start(dir("duplicate")).await;
        let first = send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "original"}),
        );
        assert_eq!(first["result"]["task"]["content"], "original");

        let second = send(
            &s.endpoint,
            "2",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "impostor"}),
        );
        assert_eq!(
            second["error"]["code"],
            RpcErrorCode::INVALID_REQUEST.code()
        );
        assert_eq!(second["error"]["data"]["reason"], "already-exists");

        // The original survived: a plain INSERT, never an upsert.
        let listed = send(&s.endpoint, "3", "task/list", json!({}));
        assert_eq!(listed["result"]["count"], 1);
        assert_eq!(listed["result"]["tasks"][0]["content"], "original");
        s.stop().await;
    });
}

#[test]
fn claiming_what_cannot_be_claimed_is_refused_with_a_reason() {
    rt().block_on(async {
        let s = Serving::start(dir("claim-refusals")).await;

        // No such task.
        let absent = send(
            &s.endpoint,
            "1",
            "task/claim",
            json!({"id": "nope", "worker": "w"}),
        );
        assert_eq!(absent["error"]["data"]["reason"], "not-claimable");
        assert_eq!(absent["error"]["data"]["detail"], "not-found");

        // A pending task is claimable; claim it, then ask again.
        send(
            &s.endpoint,
            "2",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "x"}),
        );
        send(
            &s.endpoint,
            "3",
            "task/claim",
            json!({"id": "t-1", "worker": "w1"}),
        );
        let twice = send(
            &s.endpoint,
            "4",
            "task/claim",
            json!({"id": "t-1", "worker": "w2"}),
        );
        assert_eq!(twice["error"]["data"]["reason"], "not-claimable");
        assert_eq!(
            twice["error"]["data"]["detail"], "not-claimable",
            "an already-running task is not-claimable, which is different from missing"
        );
        s.stop().await;
    });
}

#[test]
fn malformed_and_oversized_parameters_are_refused() {
    rt().block_on(async {
        let s = Serving::start(dir("malformed")).await;

        // Missing id.
        let no_id = send(&s.endpoint, "1", "task/create", json!({"content": "x"}));
        assert_eq!(no_id["error"]["code"], RpcErrorCode::INVALID_REQUEST.code());

        // Wrong type: never coerced.
        let wrong_type = send(&s.endpoint, "2", "task/create", json!({"id": 12}));
        assert_eq!(
            wrong_type["error"]["code"],
            RpcErrorCode::INVALID_REQUEST.code()
        );

        // A kind the domain does not have.
        let bad_kind = send(
            &s.endpoint,
            "3",
            "task/create",
            json!({"id": "t-1", "kind": "teleport"}),
        );
        assert_eq!(
            bad_kind["error"]["code"],
            RpcErrorCode::INVALID_REQUEST.code()
        );

        // Over-long content, refused by name and bound.
        let huge = "x".repeat(64 * 1024);
        let too_big = send(
            &s.endpoint,
            "4",
            "task/create",
            json!({"id": "t-1", "content": huge}),
        );
        assert_eq!(
            too_big["error"]["code"],
            RpcErrorCode::INVALID_REQUEST.code()
        );
        let reason = too_big["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default();
        assert!(
            reason.contains("content") && reason.contains("limit"),
            "the refusal must name the field and the bound: {reason}"
        );

        // An over-long id is refused the same way.
        let long_id = send(
            &s.endpoint,
            "5",
            "task/create",
            json!({"id": "y".repeat(4096), "content": "x"}),
        );
        assert_eq!(
            long_id["error"]["code"],
            RpcErrorCode::INVALID_REQUEST.code()
        );

        // Nothing was created by any of that.
        let listed = send(&s.endpoint, "6", "task/list", json!({}));
        assert_eq!(
            listed["result"]["count"], 0,
            "no refused request may leave a row"
        );

        // An unknown method is still a clean -32601, not a task error.
        let unknown = send_raw(
            &s.endpoint,
            br#"{"jsonrpc":"2.0","id":"7","method":"task/teleport","params":{}}"#,
        )
        .expect("an answer");
        assert_eq!(
            unknown["error"]["code"],
            RpcErrorCode::METHOD_NOT_FOUND.code()
        );

        s.stop().await;
    });
}

#[test]
fn listing_is_deterministic_and_starts_empty() {
    rt().block_on(async {
        let s = Serving::start(dir("ordering")).await;

        let empty = send(&s.endpoint, "1", "task/list", json!({}));
        assert_eq!(empty["result"]["count"], 0);
        assert_eq!(empty["result"]["tasks"].as_array().map(Vec::len), Some(0));

        for id in ["t-c", "t-a", "t-b"] {
            send(
                &s.endpoint,
                "2",
                "task/create",
                json!({"id": id, "kind": "query", "content": id}),
            );
        }

        // Two reads of the same database agree, and both are id-ordered rather than
        // insertion-ordered: the repository's ORDER BY, which is total.
        let first = send(&s.endpoint, "3", "task/list", json!({}));
        let second = send(&s.endpoint, "4", "task/list", json!({}));
        let ids: Vec<&str> = first["result"]["tasks"]
            .as_array()
            .expect("array")
            .iter()
            .map(|t| t["id"].as_str().expect("id"))
            .collect();
        assert_eq!(
            ids,
            vec!["t-a", "t-b", "t-c"],
            "ordered by id, not by arrival"
        );
        assert_eq!(first["result"], second["result"], "two reads must agree");

        s.stop().await;
    });
}

#[test]
fn task_management_is_not_a_capability_invocation() {
    // The architectural claim, asserted rather than asserted-in-prose: a task
    // operation must not need a registered capability, and asking the governed
    // dispatcher to run one must still refuse because nothing is registered.
    rt().block_on(async {
        let s = Serving::start(dir("not-a-capability")).await;
        send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "x"}),
        );

        // The task exists, with no capability anywhere in sight.
        let listed = send(&s.endpoint, "2", "task/list", json!({}));
        assert_eq!(listed["result"]["count"], 1);

        // And no *task* capability exists: task management must not have registered
        // itself as an adapter to get here.
        let caps = send(&s.endpoint, "3", "capability/list", json!({}));
        assert_eq!(
            caps["result"]["capabilities"].as_array().map(Vec::len),
            Some(0),
            "task management must not register a capability"
        );
        assert_eq!(caps["result"]["enabled"], 0);

        // The governed path is unchanged: still refuses, still for its own reason.
        let dispatched = send(
            &s.endpoint,
            "4",
            "capability/dispatch",
            json!({"capability": "send-message"}),
        );
        let reason = dispatched["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default();
        assert!(
            reason.contains("policy") && reason.contains("send-message"),
            "the governed refusal must still come from policy: {reason}"
        );
        s.stop().await;
    });
}

// ---------------------------------------------------------------------------
// Cancellation
//
// The semantics under test were read out of `TaskRepository::request_cancel`, not
// inferred from a comment: it is synchronous, it transitions
// pending/running/waiting-for-user/waiting-for-external to `cancelled`, it is a
// *silent no-op that succeeds* on an already-terminal task, and it is **not** fenced
// — it clears the lease rather than checking it. Those four facts are what the tests
// below pin, because they are what a caller has to be able to rely on.
// ---------------------------------------------------------------------------

#[test]
fn a_pending_task_can_be_cancelled() {
    rt().block_on(async {
        let s = Serving::start(dir("cancel-pending")).await;
        send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "not needed"}),
        );
        assert_eq!(
            state_of(&s, "t-1"),
            "pending",
            "precondition: a new task is pending"
        );

        let out = send(&s.endpoint, "2", "task/cancel", json!({"id": "t-1"}));
        assert_eq!(out["result"]["cancelled"], true, "{out}");
        assert_eq!(out["result"]["task"]["state"], "cancelled");
        assert_eq!(
            state_of(&s, "t-1"),
            "cancelled",
            "visible through task/list"
        );
        s.stop().await;
    });
}

#[test]
fn a_running_task_can_be_cancelled_and_its_lease_is_released() {
    rt().block_on(async {
        let s = Serving::start(dir("cancel-running")).await;
        send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "x"}),
        );
        let claimed = send(
            &s.endpoint,
            "2",
            "task/claim",
            json!({"id": "t-1", "worker": "w1"}),
        );
        assert_eq!(claimed["result"]["task"]["state"], "running");
        assert!(
            claimed["result"]["task"]["lease_holder"].is_string(),
            "precondition: the lease is held"
        );

        // No worker identity: cancel is a decision about the task, not a report from
        // the holder, so it does not have to name one.
        let out = send(&s.endpoint, "3", "task/cancel", json!({"id": "t-1"}));
        assert_eq!(out["result"]["cancelled"], true, "{out}");
        assert_eq!(
            out["result"]["task"]["lease_holder"],
            Value::Null,
            "cancelling must release the lease, not leave a dangling holder"
        );
        assert_eq!(out["result"]["task"]["state"], "cancelled");
        s.stop().await;
    });
}

#[test]
fn a_waiting_task_can_be_cancelled() {
    rt().block_on(async {
        // `waiting-for-user` and `waiting-for-external` are not terminal and are not in
        // step 2's exclusion list, so the engine cancels them. Reached here through the
        // durable file rather than a new transition, because there is no IPC verb that
        // puts a task into a waiting state and inventing one would be adding surface.
        let root = dir("cancel-waiting");
        {
            let s = Serving::start(root.clone()).await;
            send(
                &s.endpoint,
                "1",
                "task/create",
                json!({"id": "t-1", "kind": "query", "content": "x"}),
            );
            set_state(&root, "t-1", "waiting-for-user");

            let out = send(&s.endpoint, "2", "task/cancel", json!({"id": "t-1"}));
            assert_eq!(out["result"]["cancelled"], true, "{out}");
            assert_eq!(out["result"]["task"]["state"], "cancelled");
            s.stop().await;
        }
        let _ = std::fs::remove_dir_all(&root);
    });
}

#[test]
fn cancelling_a_terminal_task_is_a_no_op_that_succeeds_and_reports_the_truth() {
    // The engine returns `Ok(())` without writing an event for a terminal task. So
    // this is exit 0 — but it must NOT claim `cancelled`, because the task is
    // `completed`. Reporting the authoritative state is the whole contract here.
    rt().block_on(async {
        let root = dir("cancel-terminal");
        let s = Serving::start(root.clone()).await;
        send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "x"}),
        );
        send(
            &s.endpoint,
            "2",
            "task/claim",
            json!({"id": "t-1", "worker": "w1"}),
        );
        send(
            &s.endpoint,
            "3",
            "task/complete",
            json!({"id": "t-1", "worker": "w1"}),
        );
        let events_before = events_for(&root, "t-1").len();

        let out = send(&s.endpoint, "4", "task/cancel", json!({"id": "t-1"}));
        assert_eq!(
            out["result"]["cancelled"], false,
            "a completed task was not cancelled: {out}"
        );
        assert_eq!(
            out["result"]["task"]["state"], "completed",
            "the authoritative state must be reported, not assumed"
        );

        // And no second terminal event: a no-op must not manufacture one.
        let events_after = events_for(&root, "t-1").len();
        assert_eq!(
            events_before, events_after,
            "a refused cancel must leave the event log alone"
        );
        assert_eq!(
            events_for(&root, "t-1").last().map(String::as_str),
            Some("completed"),
            "the last event is still the real terminal transition"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&root);
    });
}

#[test]
fn repeated_cancellation_is_idempotent_with_no_duplicate_event() {
    rt().block_on(async {
        let root = dir("cancel-twice");
        let s = Serving::start(root.clone()).await;
        send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "x"}),
        );

        let first = send(&s.endpoint, "2", "task/cancel", json!({"id": "t-1"}));
        assert_eq!(first["result"]["cancelled"], true, "{first}");
        let after_first = events_for(&root, "t-1");
        assert_eq!(
            after_first.last().map(|e| e.as_str()),
            Some("cancelled"),
            "the first cancel is a real transition and says so"
        );

        // Three more, for good measure.
        for i in 0..3 {
            let again = send(
                &s.endpoint,
                &format!("{}", 10 + i),
                "task/cancel",
                json!({"id": "t-1"}),
            );
            assert!(
                again["result"]["cancelled"].is_boolean(),
                "each reply must still be well formed: {again}"
            );
        }

        let after_repeats = events_for(&root, "t-1");
        assert_eq!(
            after_repeats.len(),
            after_first.len(),
            "repeating a cancel must not append events: {after_repeats:?}"
        );
        assert_eq!(
            after_repeats.iter().filter(|e| *e == "cancelled").count(),
            1,
            "exactly one terminal transition, ever"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&root);
    });
}

#[test]
fn cancelling_a_task_that_does_not_exist_is_not_found() {
    rt().block_on(async {
        let s = Serving::start(dir("cancel-absent")).await;
        let out = send(&s.endpoint, "1", "task/cancel", json!({"id": "ghost"}));
        assert_eq!(out["error"]["code"], RpcErrorCode::INVALID_REQUEST.code());
        assert_eq!(out["error"]["data"]["reason"], "not-found");
        s.stop().await;
    });
}

#[test]
fn a_cancelled_task_cannot_be_resurrected_by_a_late_completion() {
    // The race that matters: a worker holding a lease, and a cancel that clears it.
    // Exactly one terminal transition may win, and a zombie must not be able to
    // commit after the fact.
    rt().block_on(async {
        let s = Serving::start(dir("cancel-vs-complete")).await;
        send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "x"}),
        );
        send(
            &s.endpoint,
            "2",
            "task/claim",
            json!({"id": "t-1", "worker": "w1"}),
        );

        // Cancel wins: the lease is gone.
        let cancelled = send(&s.endpoint, "3", "task/cancel", json!({"id": "t-1"}));
        assert_eq!(cancelled["result"]["cancelled"], true);

        // The lease holder now tries to report success. The fence must refuse,
        // because the lease it was relying on no longer exists.
        let late = send(
            &s.endpoint,
            "4",
            "task/complete",
            json!({"id": "t-1", "worker": "w1"}),
        );
        assert!(
            late.get("error").is_some(),
            "a completion after a cancel must be fenced out: {late}"
        );

        // And the state is still `cancelled` — not `completed`. No resurrection.
        assert_eq!(state_of(&s, "t-1"), "cancelled");
        s.stop().await;
    });
}

#[test]
fn a_cancelled_task_can_be_neither_claimed_nor_completed_afterwards() {
    rt().block_on(async {
        let s = Serving::start(dir("cancel-then-claim")).await;
        send(
            &s.endpoint,
            "1",
            "task/create",
            json!({"id": "t-1", "kind": "query", "content": "x"}),
        );
        send(&s.endpoint, "2", "task/cancel", json!({"id": "t-1"}));

        let claimed = send(
            &s.endpoint,
            "3",
            "task/claim",
            json!({"id": "t-1", "worker": "w1"}),
        );
        assert!(
            claimed.get("error").is_some(),
            "a cancelled task must not be claimable: {claimed}"
        );
        assert_eq!(state_of(&s, "t-1"), "cancelled");
        s.stop().await;
    });
}

#[test]
fn a_cancelled_task_and_its_events_survive_a_restart() {
    rt().block_on(async {
        let root = dir("cancel-restart");
        {
            let s = Serving::start(root.clone()).await;
            send(
                &s.endpoint,
                "1",
                "task/create",
                json!({"id": "t-1", "kind": "query", "content": "not needed"}),
            );
            let out = send(&s.endpoint, "2", "task/cancel", json!({"id": "t-1"}));
            assert_eq!(out["result"]["cancelled"], true);
            s.stop().await;
        }

        // On disk, before any restart.
        let kinds = events_for(&root, "t-1");
        assert_eq!(
            kinds,
            vec!["enqueued", "cancel-requested", "cancelled"],
            "the engine records both halves of a cancellation"
        );

        // A brand new runtime over the same file.
        let s = Serving::start(root.clone()).await;
        assert_eq!(
            state_of(&s, "t-1"),
            "cancelled",
            "cancellation must survive the restart, not be requeued by recovery"
        );
        s.stop().await;

        assert_eq!(
            events_for(&root, "t-1"),
            vec!["enqueued", "cancel-requested", "cancelled"],
            "the event history must survive too"
        );
        let _ = std::fs::remove_dir_all(&root);
    });
}

/// The task's state, as `task/list` reports it.
///
/// Read through the public `task/list` rather than the database: this asserts what a
/// client can see, which is the property that matters. A caller wanting the stored row
/// would use [`tasks_in_file`].
fn state_of(s: &Serving, id: &str) -> String {
    let listed = send(&s.endpoint, "999", "task/list", json!({}));
    listed["result"]["tasks"]
        .as_array()
        .expect("tasks array")
        .iter()
        .find(|t| t["id"] == id)
        .map(|t| t["state"].as_str().unwrap_or_default().to_owned())
        .unwrap_or_else(|| panic!("{id} is not listed"))
}

/// Forcibly sets a task's state, to reach states no IPC verb can produce.
///
/// A test fixture, not a production path: it writes through the store's own adapter
/// so the schema and pragmas are still verified, and it exists so cancellation can be
/// tested from every state the engine claims to handle without inventing an IPC verb
/// that would put a task there.
fn set_state(root: &Path, id: &str, state: &str) {
    let db = conn(root);
    let changed = db
        .conn()
        .execute("UPDATE tasks SET state = ?2 WHERE id = ?1;", [id, state])
        .expect("set the state");
    assert_eq!(changed, 1, "the fixture must have found exactly one row");
}
