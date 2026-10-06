//! Unix-socket evidence, recorded as such per test rather than per file.
//!
//! Every test here reaches the daemon through a real Unix domain socket, and
//! `std::os::unix::net::UnixStream` has no Windows equivalent -- the local IPC
//! transport *refuses* there rather than binding a named pipe
//! (`crates/orxnud-platform-ipc`, ADR-0035). So each test carries
//! `#[cfg_attr(not(target_os = "linux"), ignore = ...)]` naming that reason, and
//! this file still *compiles* for MSVC, which is what the `windows-check` lane's
//! `--all-targets` proves.
//!
//! Per test rather than a whole-file `#![cfg(unix)]`, and the reason is gate G3:
//! `cfg` may appear only inside a `orxnud-platform-*` crate, so a file-level gate
//! here would fail the boundary check that keeps the portable core portable. What
//! it proved stays Linux evidence either way -- V-29.
//!

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
        Self::start_with(root, orxnud_daemon::runtime::scripted_proposer()).await
    }

    /// A daemon that asks `provider`.
    ///
    /// The seam is per-daemon and constructor-supplied, so there is nothing to install,
    /// nothing to restore, and nothing for a concurrently running test to inherit.
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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
        // `CONFLICT`: valid request, wrong state. The task is not in a state where
        // completing it is legal, and the recovery is to claim it first.
        assert_eq!(refused["error"]["code"], RpcErrorCode::CONFLICT.code());
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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
        // `CONFLICT`: another worker holding the lease is a race that was lost, not a bad
        // request and not a fault in the daemon.
        assert_eq!(stolen["error"]["code"], RpcErrorCode::CONFLICT.code());
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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
        // `CONFLICT`, not `INVALID_REQUEST`: the request was well-formed and the name was
        // simply taken. `INVALID_REQUEST` tells a client to change what it sent, which would
        // have it inventing a different id — the opposite of the advice. The reason word is
        // unchanged, so nothing a client branched on moved.
        assert_eq!(second["error"]["code"], RpcErrorCode::CONFLICT.code());
        assert_eq!(second["error"]["data"]["reason"], "already-exists");

        // The original survived: a plain INSERT, never an upsert.
        let listed = send(&s.endpoint, "3", "task/list", json!({}));
        assert_eq!(listed["result"]["count"], 1);
        assert_eq!(listed["result"]["tasks"][0]["content"], "original");
        s.stop().await;
    });
}

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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
        // `data.reason` is the *specific* refusal, not the coarse variant name: "not-found"
        // tells the client the task is gone, where "not-claimable" would only say the claim
        // was refused. Both are CONFLICT -- see tests/taxonomy.rs.
        assert_eq!(absent["error"]["data"]["reason"], "not-found");
        assert_eq!(absent["error"]["code"], RpcErrorCode::CONFLICT.code());

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
        // The refusal is carried by `reason` alone: with no detail to repeat it, and with
        // the two refusals distinguishable -- an already-running task is "not-claimable",
        // a missing one is "not-found".
        assert_eq!(twice["error"]["data"]["reason"], "not-claimable");
        assert!(
            twice["error"]["data"].get("detail").is_none(),
            "reason already is the refusal: {twice}"
        );
        s.stop().await;
    });
}

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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
        // The prose lives in `data.detail`, never in the machine-readable `data.reason`:
        // which of forty fields is wrong has no stable word, so the class goes in `reason`
        // and the explanation in the human-facing field.
        assert_eq!(too_big["error"]["data"]["reason"], "invalid-request");
        let detail = too_big["error"]["data"]["detail"]
            .as_str()
            .unwrap_or_default();
        assert!(
            detail.contains("content") && detail.contains("limit"),
            "the refusal must name the field and the bound: {detail}"
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

        // And no *task* capability exists. The registry is no longer empty — this
        // build ships `text/word-count` — so the assertion is now the sharper one: the
        // capability set contains nothing whose name suggests tasks, and task
        // management did not smuggle itself in as an adapter.
        let caps = send(&s.endpoint, "3", "capability/list", json!({}));
        let mut ids: Vec<&str> = caps["result"]["capabilities"]
            .as_array()
            .expect("array")
            .iter()
            .map(|v| v.as_str().expect("id"))
            .collect();
        ids.sort_unstable();
        // Exactly the shipped set. The point of this test is that *no* capability id
        // mentions a task -- task methods are not capability invocations -- and that
        // holds whatever the set contains, so the assertion is the set rather than a
        // count.
        assert_eq!(
            ids,
            vec![
                "filesystem/read-text",
                "filesystem/write-text",
                "text/word-count"
            ],
            "only the shipped capabilities exist"
        );
        for id in &ids {
            assert!(
                !id.contains("task"),
                "task management must not register a capability: {id}"
            );
        }

        // The governed path is unchanged: still refuses, still for its own reason, and
        // still the policy engine's refusal rather than a task-layer shortcut. Under the
        // V-90 vocabulary that means `reason` is policy's stable word and `detail` names
        // the capability -- previously one English sentence sat in `reason` and a client
        // had to substring-match it to learn anything.
        let dispatched = send(
            &s.endpoint,
            "4",
            "capability/dispatch",
            json!({"capability": "send-message"}),
        );
        let reason = dispatched["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default();
        let detail = dispatched["error"]["data"]["detail"]
            .as_str()
            .unwrap_or_default();
        assert_eq!(
            reason, "unknown-capability",
            "the governed refusal must still come from policy: {dispatched}"
        );
        assert!(
            detail.contains("send-message"),
            "the detail must name the capability: {detail}"
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn cancelling_a_task_that_does_not_exist_is_not_found() {
    rt().block_on(async {
        let s = Serving::start(dir("cancel-absent")).await;
        let out = send(&s.endpoint, "1", "task/cancel", json!({"id": "ghost"}));
        // `RESOURCE_NOT_FOUND`: the request named a task that does not exist. `INVALID_REQUEST`
        // would have said "you asked wrongly", which sends a client looking at its own
        // request rather than refreshing its view of the daemon.
        assert_eq!(
            out["error"]["code"],
            RpcErrorCode::RESOURCE_NOT_FOUND.code()
        );
        assert_eq!(out["error"]["data"]["reason"], "not-found");
        s.stop().await;
    });
}

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
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

// ---------------------------------------------------------------------------
// ADR-0037 / ADR-0038 — the governed task action path
// ---------------------------------------------------------------------------
//
// Every test here drives the real runtime over a real socket. The properties under test
// are *arrangement* properties — a proposal and a waiting task committed together, a
// lease released and retaken, an approval bound to one action — and none of them is
// observable from a unit test that wires the pieces up itself.

/// The workspace the daemon confines governed writes to.
fn workspace(root: &Path) -> PathBuf {
    root.join("workspace")
}

/// How many proposals are stored for this daemon's state directory.
///
/// Counted through the store's own migrated connection, matching the rest of this suite:
/// a raw handle would accept an unmigrated file, which is the opposite of what a
/// durability assertion wants.
fn stored_proposal_count(root: &Path) -> usize {
    let db = conn(root);
    db.conn()
        .query_row("SELECT count(*) FROM task_proposals;", [], |r| {
            r.get::<_, i64>(0)
        })
        .expect("count proposals") as usize
}

/// Creates, claims and proposes in one step; returns the proposal id.
fn propose(s: &Serving, task: &str, worker: &str, file: &str, contents: &str) -> String {
    send(
        &s.endpoint,
        "c",
        "task/create",
        json!({"id": task, "content": "governed"}),
    );
    send(
        &s.endpoint,
        "c",
        "task/claim",
        json!({"id": task, "worker": worker}),
    );
    let reply = send(
        &s.endpoint,
        "p",
        "task/propose",
        json!({
            "task": task,
            "worker": worker,
            "capability": "filesystem/write-text",
            "target": file,
            "params": {"path": file, "contents": contents},
        }),
    );
    reply["result"]["proposal"]["proposal_id"]
        .as_str()
        .expect("a proposal id")
        .to_owned()
}

/// The governed path, end to end, through the governed dispatcher.
///
/// The load-bearing assertion is that the task reaches `completed` **only after** the
/// verifier confirmed the file. A refuted effect must leave the task running, because
/// "we do not know whether it happened" is not "it happened".
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_proposed_action_is_approved_executed_verified_and_completes_its_task() {
    rt().block_on(async {
        let d = dir("governed-happy");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "g1", "w1", "governed.txt", "written under approval");

        // Parked, and the lease released: a human wait is not a lease reservation.
        let listed = send(&s.endpoint, "l", "task/list", json!({}));
        assert_eq!(listed["result"]["tasks"][0]["state"], "waiting-for-user");
        assert!(
            listed["result"]["tasks"][0]["lease_holder"].is_null(),
            "the lease must be released while waiting: {}",
            listed["result"]["tasks"][0]
        );

        // The trusted human approves the *proposal*, supplying no action of its own.
        let approved = send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        let ap = &approved["result"]["approval"];
        assert_eq!(ap["approver"], "human", "the approver is the trusted human");
        assert_eq!(
            ap["actor_label"], "ai",
            "the proposer is the delegated model"
        );
        assert_eq!(ap["authority_root"], "local");

        let executed = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        assert_eq!(executed["result"]["verified"], true, "{executed}");
        assert_eq!(
            std::fs::read_to_string(workspace(&d).join("governed.txt")).expect("written"),
            "written under approval"
        );
        assert_eq!(
            executed["result"]["task"]["state"], "completed",
            "the task completes only after verification"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// The approval is single-use, and the second use is refused before any side effect.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_approval_cannot_be_executed_twice() {
    rt().block_on(async {
        let d = dir("governed-single-use");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "g2", "w1", "once.txt", "first");
        send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        assert_eq!(
            send(
                &s.endpoint,
                "x",
                "task/execute",
                json!({"proposal": pid, "worker": "w1"})
            )["result"]["verified"],
            true
        );
        let again = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        assert!(
            again.get("error").is_some(),
            "a second execution must be refused: {again}"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// An approval that would be expired on arrival is refused, and nothing is written.
///
/// The refusal has moved *earlier* than it used to be. This test previously approved with
/// `ttl_ms: 0`, let the already-expired approval be written, and asserted that
/// `task/execute` then refused it with `approval-expired`. That was correct about the
/// execution and wrong about the approval: minting an authority that can never be used, and
/// marking the proposal decided while doing it, is what turned an operator's mistyped TTL
/// into an unrecoverable task (V-82).
///
/// So the TTL is now checked before anything is written, and this asserts where the refusal
/// now happens as well as that every safety property it checked before still holds.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_expired_approval_is_refused_and_writes_nothing() {
    rt().block_on(async {
        let d = dir("governed-expired");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "g3", "w1", "late.txt", "expired");

        // Refused at the approval, before any row is written.
        let refused = send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 0}),
        );
        assert_eq!(
            refused["error"]["data"]["reason"], "approval-expired",
            "a TTL that leaves the approval already expired must be refused: {refused}"
        );

        // And a negative one, which is the same mistake written differently.
        let negative = send(
            &s.endpoint,
            "an",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": -1}),
        );
        assert_eq!(
            negative["error"]["data"]["reason"], "approval-expired",
            "{negative}"
        );

        // No approval exists, so there is nothing to execute.
        let out = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        assert!(
            out.get("error").is_some(),
            "nothing may execute on a refused approval: {out}"
        );
        assert!(
            !workspace(&d).join("late.txt").exists(),
            "an expired approval must not write"
        );

        // The proposal is still approvable, and still pending -- the liveness half.
        let db = conn(&d);
        let approvals: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM task_approvals", [], |r| r.get(0))
            .expect("count approvals");
        assert_eq!(approvals, 0, "a refused approval must leave no row");
        let status: String = db
            .conn()
            .query_row(
                "SELECT status FROM task_proposals WHERE proposal_id = ?1;",
                [&pid],
                |r| r.get(0),
            )
            .expect("proposal status");
        assert_eq!(
            status, "pending",
            "a refused approval must leave the proposal approvable, not decided"
        );

        // Which is the recovery: approve again with a usable TTL.
        let good = send(
            &s.endpoint,
            "a2",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        assert!(
            good.get("result").is_some(),
            "the proposal must still be approvable: {good}"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// V-71: the lease holder is not the proposer.
///
/// A worker that does not hold the live lease cannot propose at all — that is the
/// ownership check — and the proposal that results records a proposer derived from the
/// task, never from the worker. Changing which worker holds the lease must therefore
/// leave the proposer, its authority root, and the eventual approval untouched.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_lease_holder_does_not_become_the_proposer() {
    rt().block_on(async {
        let d = dir("governed-v71");
        let s = Serving::start(d.clone()).await;

        // A worker with no lease is refused outright.
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "g4", "content": "x"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "g4", "worker": "w1"}),
        );
        let impostor = send(
            &s.endpoint,
            "p",
            "task/propose",
            json!({
                "task": "g4", "worker": "not-the-lease-holder",
                "capability": "filesystem/write-text", "target": "a.txt",
                "params": {"path": "a.txt", "contents": "x"},
            }),
        );
        assert!(
            impostor.get("error").is_some(),
            "a worker without the live lease must not propose: {impostor}"
        );

        // The legitimate holder's proposal records a delegated actor, not itself.
        let reply = send(
            &s.endpoint,
            "p",
            "task/propose",
            json!({
                "task": "g4", "worker": "w1",
                "capability": "filesystem/write-text", "target": "a.txt",
                "params": {"path": "a.txt", "contents": "x"},
            }),
        );
        assert_eq!(
            reply["result"]["proposal"]["authority_root"], "local",
            "the proposer acts under the delegating human, not under the worker"
        );
        let pid = reply["result"]["proposal"]["proposal_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let approved = send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        assert_eq!(approved["result"]["approval"]["approver"], "human");
        assert_eq!(
            approved["result"]["approval"]["actor_label"], "ai",
            "the worker string must never appear as the actor"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A proposal is durable, and so is a waiting task: both survive a restart unchanged.
///
/// This is the property that makes `waiting-for-user` explainable rather than merely
/// empty. It also covers the accident the design had to avoid: `recover` reclaims leases
/// on `running` tasks, so if the proposal path had left the task `running` with a dead
/// lease, a restart would have silently reset it to `pending`.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_proposal_and_its_waiting_task_survive_a_restart_unchanged() {
    rt().block_on(async {
        let d = dir("governed-restart");
        let before = {
            let s = Serving::start(d.clone()).await;
            let pid = propose(&s, "g5", "w1", "keep.txt", "durable");
            let row = send(&s.endpoint, "l", "task/list", json!({}));
            let proposal = send(&s.endpoint, "q", "task/list", json!({}));
            let _ = proposal;
            let p = stored_proposal_count(&d);
            s.crash().await;
            (
                pid,
                p,
                row["result"]["tasks"][0]["state"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            )
        };

        let (pid, stored, state) = before;
        assert_eq!(state, "waiting-for-user");
        assert_eq!(stored, 1, "the proposal must be durable before the wait");

        // A fresh process over the same directory: reaching here means the journal loaded
        // and verified.
        let s = Serving::start(d.clone()).await;
        let listed = send(&s.endpoint, "l", "task/list", json!({}));
        assert_eq!(
            listed["result"]["tasks"][0]["state"], "waiting-for-user",
            "recovery must not reset a waiting task; it is not running"
        );

        // And it can still be approved and executed after the restart.
        send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 600_000}),
        );
        let out = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        assert_eq!(out["result"]["verified"], true, "{out}");
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// The attempt number does not advance across the human wait.
///
/// A wait is not a retry: TP-6 requires a fresh approval after a *retry*, so the attempt
/// that asked must be the attempt that executes. If this regressed, the approval and the
/// execution it authorises would sit on different attempt numbers.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_attempt_does_not_advance_across_the_approval_wait() {
    rt().block_on(async {
        let d = dir("governed-attempt");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "g6", "w1", "attempt.txt", "x");
        let at_propose =
            send(&s.endpoint, "q", "task/list", json!({}))["result"]["tasks"][0]["attempts"]
                .clone();
        send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        let at_approve =
            send(&s.endpoint, "q", "task/list", json!({}))["result"]["tasks"][0]["attempts"]
                .clone();
        assert_eq!(
            at_propose, at_approve,
            "approval must not start a new attempt"
        );
        send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        let at_execute =
            send(&s.endpoint, "q", "task/list", json!({}))["result"]["tasks"][0]["attempts"]
                .clone();
        assert_eq!(
            at_approve, at_execute,
            "execution resumes the same attempt; a human wait is not a retry"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// The proposal commits to the parameters that were actually asked for.
///
/// This is the test that makes parameter binding *externally* checkable. Without it,
/// replacing the canonical form with any other consistent value would pass every other
/// test in this file: the proposal stores what it is given, approval is computed over
/// the stored value, and execution replays the stored value — so a consistently-wrong
/// canonicalisation is self-consistent and invisible. What catches it is comparing the
/// stored canonical text against the request that produced it.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_proposal_commits_to_the_parameters_that_were_requested() {
    rt().block_on(async {
        let d = dir("governed-params");
        let s = Serving::start(d.clone()).await;
        // Deliberately written in the "wrong" key order, to show the stored form is
        // canonical rather than verbatim.
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "g8", "content": "x"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "g8", "worker": "w1"}),
        );
        let r = send(
            &s.endpoint,
            "p",
            "task/propose",
            json!({
                "task": "g8", "worker": "w1",
                "capability": "filesystem/write-text", "target": "p.txt",
                "params": {"contents": "alpha", "path": "p.txt"},
            }),
        );
        assert_eq!(
            r["result"]["proposal"]["params"], r#"{"contents":"alpha","path":"p.txt"}"#,
            "the stored parameters must be the canonical form of what was requested"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// An unapproved proposal cannot be executed, and a decided proposal cannot be re-approved.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_unapproved_or_already_decided_proposal_is_refused() {
    rt().block_on(async {
        let d = dir("governed-unapproved");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "g7", "w1", "no.txt", "x");

        let early = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        assert!(early.get("error").is_some(), "{early}");

        send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        let twice = send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        assert!(
            twice.get("error").is_some(),
            "a decided proposal must not be approvable again: {twice}"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Approve proposal A, then try to execute proposal B with A's approval.
///
/// The interface makes this hard by construction — `task/execute` accepts only a
/// proposal id and a worker, so there is no field through which "execute B using A's
/// approval" could be expressed. That is the right design, but "hard by construction" is
/// a claim about code, not a test, so the invariant is asserted here directly: B executes
/// only under B's own approval, and never against A's.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_approval_for_one_proposal_does_not_execute_another() {
    rt().block_on(async {
        let d = dir("governed-cross");
        let s = Serving::start(d.clone()).await;

        // Two proposals on two tasks, with different contents.
        let pid_a = propose(&s, "xa", "w1", "a.txt", "alpha");
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "xb", "content": "x"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "xb", "worker": "w1"}),
        );
        let pid_b = send(
            &s.endpoint,
            "p",
            "task/propose",
            json!({
                "task": "xb", "worker": "w1",
                "capability": "filesystem/write-text", "target": "b.txt",
                "params": {"path": "b.txt", "contents": "beta"},
            }),
        )["result"]["proposal"]["proposal_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(pid_a, pid_b);

        // Only A is approved.
        send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid_a, "ttl_ms": 60_000}),
        );

        // B is not, so B cannot execute — A's approval does not reach it.
        let b_first = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid_b, "worker": "w1"}),
        );
        assert!(
            b_first.get("error").is_some(),
            "B must not execute under A's approval: {b_first}"
        );
        assert!(
            !workspace(&d).join("b.txt").exists(),
            "the refused execution must have written nothing"
        );

        // A executes under its own approval, and only its own contents land.
        let a = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid_a, "worker": "w1"}),
        );
        assert_eq!(a["result"]["verified"], true, "{a}");
        assert_eq!(
            std::fs::read_to_string(workspace(&d).join("a.txt")).expect("written"),
            "alpha"
        );
        assert!(
            !workspace(&d).join("b.txt").exists(),
            "A's approval must never cause B's side effect"
        );

        // And once B is approved in its own right, it writes *its* contents.
        send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid_b, "ttl_ms": 60_000}),
        );
        let b = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid_b, "worker": "w1"}),
        );
        assert_eq!(b["result"]["verified"], true, "{b}");
        assert_eq!(
            std::fs::read_to_string(workspace(&d).join("b.txt")).expect("written"),
            "beta"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Object-key order is not part of the operation; array order is.
///
/// Two halves of one rule, and the second is the one that would be quietly broken by a
/// well-meaning "let's sort everything" later: `{"a":1,"b":2}` and `{"b":2,"a":1}` are the
/// same request written twice, while `["a","b"]` and `["b","a"]` are different arguments
/// to almost any capability.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn key_order_is_canonicalised_but_array_order_is_meaningful() {
    // The property is about the canonical form the approval commits to, so it is asserted
    // where that form is produced.
    let forward: serde_json::Value =
        serde_json::from_str(r#"{"path":"p.txt","contents":"alpha"}"#).expect("json");
    let reversed: serde_json::Value =
        serde_json::from_str(r#"{"contents":"alpha","path":"p.txt"}"#).expect("json");
    assert_eq!(
        orxnud_policy::canonical_params(&forward).as_str(),
        orxnud_policy::canonical_params(&reversed).as_str(),
        "two spellings of one request must produce one canonical form"
    );

    let arr_forward: serde_json::Value = serde_json::from_str(r#"{"xs":["a","b"]}"#).expect("json");
    let arr_reversed: serde_json::Value =
        serde_json::from_str(r#"{"xs":["b","a"]}"#).expect("json");
    assert_ne!(
        orxnud_policy::canonical_params(&arr_forward).as_str(),
        orxnud_policy::canonical_params(&arr_reversed).as_str(),
        "array order is meaning and must not be sorted away"
    );
}

/// Durable parameters that cannot be read are refused, never defaulted.
///
/// The regression for the fail-open this slice removed: the stored text is what the
/// digest is computed over, so defaulting a corrupt row to `{}` used to produce a
/// *verified* execution of parameters nobody approved.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn unreadable_stored_parameters_are_refused_rather_than_defaulted() {
    rt().block_on(async {
        let d = dir("governed-corrupt");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "gc", "w1", "c.txt", "x");
        send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        s.stop().await;

        // Corrupt the durable parameters behind the daemon's back — in **both** the
        // proposal and the approval row.
        //
        // Both, deliberately: corrupting only the proposal is caught earlier by the
        // action-mismatch pre-check (the approval's params no longer match), which is
        // fail-closed but would mask the guard under test. Corrupting both lets the
        // mismatch check pass, so the parse guard is what actually has to stop it.
        let db = conn(&d);
        db.conn()
            .execute(
                "UPDATE task_proposals SET params = '{not json' WHERE proposal_id = ?1;",
                [pid.as_str()],
            )
            .expect("corrupt the proposal params");
        db.conn()
            .execute("UPDATE task_approvals SET params = '{not json';", [])
            .expect("corrupt the approval params");

        let s = Serving::start(d.clone()).await;
        let out = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        // `durable-state-corrupt` is the one word for "a stored row does not parse",
        // shared with `approval-corrupt` so an operator sees one class; which row was
        // corrupt is in the detail. V-90 unified these because both are the same fault.
        let reason = out["error"]["data"]["reason"].as_str().unwrap_or_default();
        assert_eq!(reason, "durable-state-corrupt", "{out}");
        assert!(
            !workspace(&d).join("c.txt").exists(),
            "unreadable durable parameters must produce no side effect at all"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// The AI task proposer
// ---------------------------------------------------------------------------
//
// The milestone claim is narrow and worth stating exactly: **a model may propose an
// action and nothing else.** These tests pin both halves — that a proposal reaches the
// governed path, and that the model's route contains no path to approving, executing or
// dispatching.

/// The demonstration: a plain request becomes a proposal a human can approve.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_ai_proposal_becomes_a_governed_action() {
    rt().block_on(async {
        let d = dir("ai-happy");
        let s = Serving::start(d.clone()).await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "ai1", "content": "Create final.txt containing delegated governance works"}),
        );
        send(&s.endpoint, "c", "task/claim", json!({"id": "ai1", "worker": "ai"}));
        let p = send(
            &s.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "ai1", "worker": "ai"}),
        );
        assert_eq!(p["result"]["proposed_by"], "ai", "the proposer is the model actor");
        assert_eq!(p["result"]["proposal"]["capability"], "filesystem/write-text");
        assert_eq!(p["result"]["waiting_for"], "human-approval");

        // Parked, and the file is NOT written: proposing is not doing.
        let listed = send(&s.endpoint, "l", "task/list", json!({}));
        assert_eq!(listed["result"]["tasks"][0]["state"], "waiting-for-user");
        assert!(!workspace(&d).join("final.txt").exists());

        // Only a human can finish it.
        let pid = p["result"]["proposal"]["proposal_id"].as_str().unwrap().to_owned();
        let early = send(&s.endpoint, "x", "task/execute", json!({"proposal": pid, "worker": "ai"}));
        assert!(early.get("error").is_some(), "an unapproved proposal must not run");

        send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        let done = send(&s.endpoint, "x", "task/execute", json!({"proposal": pid, "worker": "ai"}));
        assert_eq!(done["result"]["verified"], true, "{done}");
        assert_eq!(
            std::fs::read_to_string(workspace(&d).join("final.txt")).expect("written"),
            "delegated governance works"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A malformed response is refused by the real daemon, and no proposal is written.
///
/// Reachable only because the proposer slot is scoped: under the old one-shot
/// installation this test would have poisoned every other proposer test in the process,
/// so the suite had exactly one provider scenario and this one could not exist. That is
/// the whole argument for the seam — not elegance, but being able to write the test.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_malformed_ai_response_is_refused_without_writing_a_proposal() {
    use orxnud_daemon::proposer::ScriptedProvider;

    rt().block_on(async {
        let d = dir("ai-malformed");
        let s = Serving::start_with(
            d.clone(),
            Arc::new(ScriptedProvider::returning(
                "scripted/malformed",
                r#"{"capability":"filesystem/write-text","target":"a.txt","params":{"path":"a.txt"}}"#,
            )),
        )
        .await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "m1", "content": "write something"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "m1", "worker": "ai"}),
        );

        // `path` with no `contents`: a shape the capability declares but this request
        // does not satisfy. The refusal must happen at propose time, before a durable
        // proposal exists and before anyone is asked to approve anything.
        let refused = send(
            &s.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "m1", "worker": "ai"}),
        );
        let reason = refused["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_else(|| panic!("expected a refusal, got {refused}"));
        assert_eq!(reason, "proposal-schema-mismatch", "{refused}");

        // The task is untouched and still claimable by the human path, because a
        // refused proposal is not a partial success.
        let listed = send(&s.endpoint, "l", "task/list", json!({}));
        assert_eq!(listed["result"]["tasks"][0]["state"], "running");
        assert!(!workspace(&d).join("a.txt").exists());

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A capability the model was never offered is refused, and the refusal names the
/// capability. The menu is walked from the registry, so this asserts the walk rather than
/// a list: `text/word-count` *is* enabled, so refusing it proves the menu is not
/// everything in the build.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_enabled_but_unoffered_capability_is_refused() {
    use orxnud_daemon::proposer::ScriptedProvider;

    rt().block_on(async {
        let d = dir("ai-unoffered");
        let s = Serving::start_with(
            d.clone(),
            Arc::new(ScriptedProvider::returning(
                "scripted/unoffered",
                r#"{"capability":"email/send","params":{"to":"a@b.test"}}"#,
            )),
        )
        .await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "u1", "content": "count"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "u1", "worker": "ai"}),
        );

        let refused = send(
            &s.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "u1", "worker": "ai"}),
        );
        assert_eq!(
            refused["error"]["data"]["reason"], "proposal-capability-unknown",
            "{refused}"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// The menu offered to a model is the registry, walked.
///
/// `text/word-count` is enabled in this build and has never been named in the proposer.
/// If it appears in the menu a provider is handed, then "register a capability and it
/// becomes proposable" is a fact about the code rather than a claim about it — and its
/// declared parameter name comes from its own declaration, since the string `text` was
/// never written in the daemon either.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn every_enabled_capability_is_offered_to_the_model_with_its_declared_parameters() {
    use orxnud_daemon::proposer::{ProposalContext, ProposalProvider, ProviderError};
    use std::sync::Mutex;

    /// Records the context it is handed, and answers with a proposal it cannot make — so
    /// the test is about what the model was *shown*, not about what came back.
    struct Recorder {
        seen: Arc<Mutex<Option<ProposalContext>>>,
    }
    impl ProposalProvider for Recorder {
        fn model_id(&self) -> &str {
            "recorder/none"
        }
        fn complete(&self, ctx: &ProposalContext) -> Result<String, ProviderError> {
            *self.seen.lock().expect("recorder poisoned") = Some(ctx.clone());
            Ok(r#"{"capability":"no/such","params":{}}"#.to_owned())
        }
    }

    rt().block_on(async {
        let d = dir("ai-menu");
        let seen: Arc<Mutex<Option<ProposalContext>>> = Arc::new(Mutex::new(None));
        let s = Serving::start_with(
            d.clone(),
            Arc::new(Recorder {
                seen: Arc::clone(&seen),
            }),
        )
        .await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "n1", "content": "count words"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "n1", "worker": "ai"}),
        );
        send(
            &s.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "n1", "worker": "ai"}),
        );

        let ctx = seen
            .lock()
            .expect("recorder poisoned")
            .clone()
            .expect("the provider ran");
        let menu: Vec<(&str, Vec<&str>)> = ctx
            .allowed
            .iter()
            .map(|c| (c.id.as_str(), c.params.iter().map(String::as_str).collect()))
            .collect();

        assert!(
            menu.contains(&("text/word-count", vec!["text"])),
            "word-count is enabled and must be offered with its own declared parameter: \
             {menu:?}"
        );
        assert!(
            menu.contains(&("filesystem/write-text", vec!["path", "contents"])),
            "{menu:?}"
        );

        // The declaration's prose reaches the model too, or the menu is a list of names
        // and a model still cannot tell what anything does.
        let write_text = ctx
            .allowed
            .iter()
            .find(|c| c.id == "filesystem/write-text")
            .expect("offered");
        assert!(
            write_text.description.contains("Write one text file"),
            "the declaration's own description must be shown: {:?}",
            write_text.description
        );
        assert!(
            write_text.description.to_lowercase().contains("high"),
            "the model must be able to see that this needs a human: {:?}",
            write_text.description
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Two daemons in one process, asking different providers, at the same time.
///
/// This is the test the process-global slot could not pass. It failed the suite the
/// moment it was written: a scoped install in one test changed the answer another test
/// was getting at the same moment, so scoping was necessary but not sufficient — the
/// value had to stop being global. Per-runtime configuration makes the interference
/// structurally impossible rather than merely unlikely, which is the only version of
/// this worth having.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn two_daemons_keep_separate_proposers() {
    use orxnud_daemon::proposer::ScriptedProvider;

    rt().block_on(async {
        let good_dir = dir("ai-two-good");
        let bad_dir = dir("ai-two-bad");
        let good = Serving::start_with(
            good_dir.clone(),
            Arc::new(ScriptedProvider::returning(
                "scripted/good",
                r#"{"capability":"filesystem/write-text","target":"ok.txt","params":{"path":"ok.txt","contents":"ok"}}"#,
            )),
        )
        .await;
        let bad = Serving::start_with(
            bad_dir.clone(),
            Arc::new(ScriptedProvider::returning(
                "scripted/bad",
                r#"{"capability":"filesystem/write-text","target":"no.txt","params":{"path":"no.txt"}}"#,
            )),
        )
        .await;

        for (id, endpoint) in [("g1", &good.endpoint), ("b1", &bad.endpoint)] {
            send(
                endpoint,
                "c",
                "task/create",
                json!({"id": id, "content": "write a file"}),
            );
            send(endpoint, "c", "task/claim", json!({"id": id, "worker": "ai"}));
        }

        // Interleaved on purpose: if there were shared state, this is where it would
        // show. Each daemon must answer with its own provider's verdict.
        let bad_reply = send(
            &bad.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "b1", "worker": "ai"}),
        );
        assert_eq!(
            bad_reply["error"]["data"]["reason"], "proposal-schema-mismatch",
            "{bad_reply}"
        );

        let good_reply = send(
            &good.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "g1", "worker": "ai"}),
        );
        assert_eq!(good_reply["result"]["proposed_by"], "ai", "{good_reply}");
        assert_eq!(good_reply["result"]["model"], "scripted/good");

        good.stop().await;
        bad.stop().await;
        let _ = std::fs::remove_dir_all(&good_dir);
        let _ = std::fs::remove_dir_all(&bad_dir);
    });
}

/// The hard boundary, asserted rather than described.
///
/// Each of these is a way the model might *ask* to act. None is answerable: the model
/// gets text in and text out, and the deterministic side decides. The refusals name
/// themselves, so a reader can see which guard stopped each attempt.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_ai_route_offers_no_authority_to_the_model() {
    rt().block_on(async {
        let d = dir("ai-boundary");
        let s = Serving::start(d.clone()).await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "ai2", "content": "x"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "ai2", "worker": "ai"}),
        );

        // (a) The model cannot approve. `capability/approve` derives its approver from
        //     the trusted human, so a caller asserting one is simply ignored; there is no
        //     field through which to supply a different one.
        // The daemon ignores an `approver` the caller supplies: the field is not read
        // from the request at all. Asserting the *absence* of a forged approver in the
        // reply is the observable form of that.
        let forged = send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({
                "capability": "filesystem/write-text",
                "target": "x.txt",
                "params": {"path": "x.txt", "contents": "x"},
                "approver": "ai",
            }),
        );
        let echoed = forged.to_string();
        assert!(
            !echoed.contains("\"ai\""),
            "a caller must not be able to name its own approver: {forged}"
        );

        // (b) The model cannot reach a capability without a proposal and a human approval.
        //     A direct dispatch of a High-risk capability is refused on approval alone.
        let direct = send(
            &s.endpoint,
            "d",
            "capability/dispatch",
            json!({
                "capability": "filesystem/write-text", "target": "x.txt",
                "params": {"path": "x.txt", "contents": "x"},
            }),
        );
        let reason = direct["error"]["data"]["reason"]
            .as_str()
            .unwrap_or_default();
        assert!(reason.contains("approval-required"), "{direct}");
        assert!(!workspace(&d).join("x.txt").exists());

        // (c) The model cannot mutate policy; there is no verb that could.
        assert!(
            !orxnud_protocol::method::all_method_names()
                .iter()
                .any(|m| m.contains("policy") || m.contains("grant")),
            "no protocol verb exposes policy mutation"
        );

        // (d) The proposal's authority comes from the delegating human, and the worker
        //     string that happens to be "ai" is nowhere in it.
        let p = send(
            &s.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "ai2", "worker": "ai"}),
        );
        assert_eq!(p["result"]["proposal"]["authority_root"], "local");
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A proposal cannot be conjured for a task nobody holds, and one attempt gets one
/// proposal — so a model cannot flood the approval queue.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_ai_proposal_requires_the_lease_and_is_once_per_attempt() {
    rt().block_on(async {
        let d = dir("ai-guard");
        let s = Serving::start(d.clone()).await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "ai3", "content": "x"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "ai3", "worker": "ai"}),
        );

        let impostor = send(
            &s.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "ai3", "worker": "not-the-lease-holder"}),
        );
        assert!(impostor.get("error").is_some(), "{impostor}");

        assert!(
            send(
                &s.endpoint,
                "p",
                "task/ai-propose",
                json!({"task": "ai3", "worker": "ai"})
            )
            .get("result")
            .is_some()
        );
        let second = send(
            &s.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "ai3", "worker": "ai"}),
        );
        assert!(
            second.get("error").is_some(),
            "one attempt gets one proposal: {second}"
        );
        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}
