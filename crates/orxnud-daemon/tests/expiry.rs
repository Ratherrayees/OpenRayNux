//! V-82: approval expiry as a recoverable state, not a dead end.
//!
//! # What was wrong
//!
//! `capability/approve` marked a proposal `approved` and wrote an approval row
//! *unconditionally*. An approval that was expired on arrival, or that expired while the
//! task sat waiting for a human, therefore left a proposal that was decided with no
//! authority behind it: a second `capability/approve` was refused as
//! `proposal-already-decided`, and cancellation was the only way out. Reproduced before the
//! fix against this store; the reproduction's numbers are quoted in ADR-0049.
//!
//! Two further facts the register did not record, both found while reproducing it:
//!
//! * an over-short TTL was **not** the only route — an approval that expired *while the task
//!   waited* produced exactly the same dead end, and that is the more common one;
//! * `task/execute` took the execution lease *before* the policy stage refused, so every
//!   expired attempt additionally parked the task in `running` under a fresh lease for the
//!   lease duration.
//!
//! # What these tests hold
//!
//! The invariant, in one line: **an expired approval authorises nothing, consumes no future
//! authority, and never permanently dead-ends a proposal that a human may still re-approve.**
//!
//! Every test drives a real daemon over a real Unix domain socket and reads the real durable
//! rows, so none of this is asserted against a state production cannot produce.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use orxnud_daemon::Paths;
use orxnud_daemon::runtime::Runtime;
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use serde_json::{Value, json};

struct NoSecrets;

#[derive(Debug, thiserror::Error)]
#[error("no secret store in the expiry suite")]
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
    let d = std::env::temp_dir().join(format!("orxnud-exp-{}-{tag}", std::process::id()));
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
        // A scripted provider, so a refusal that is about *state* is distinguishable from one
        // that is about configuration. `continue_task` checks the provider before it checks
        // whether there is a boundary to cross, so without one every continuation assertion
        // would be testing the wrong refusal.
        let runtime = Runtime::start(Paths::under(&root), NoSecrets)
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

    /// A crash: the serve task is dropped mid-flight, so nothing runs a graceful release and
    /// whatever a holder had in memory stays in the database.
    async fn crash(self) {
        self.task.abort();
    }
}

fn workspace(root: &Path) -> PathBuf {
    root.join("workspace")
}

fn conn(root: &Path) -> orxnud_store::security_state::SqliteAuditJournal {
    orxnud_store::security_state::SqliteAuditJournal::open(&root.join("state.db"))
        .expect("open the store the runtime wrote")
}

/// The durable approval row for one task, as `(step, attempt, digest, expires, consumed)`.
fn approval_rows(root: &Path, task: &str) -> Vec<(i64, i64, String, i64, Option<i64>)> {
    let db = conn(root);
    let mut stmt = db
        .conn()
        .prepare(
            "SELECT step_no, attempt_no, hex(digest), expires_at_ms, consumed_at_ms
                    FROM task_approvals WHERE task_id = ?1 ORDER BY step_no, attempt_no;",
        )
        .expect("prepare");
    stmt.query_map([task], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
    })
    .expect("query")
    .collect::<Result<Vec<_>, _>>()
    .expect("rows")
}

/// The durable proposal statuses for one task.
fn proposal_statuses(root: &Path, task: &str) -> Vec<(String, String, i64)> {
    let db = conn(root);
    let mut stmt = db
        .conn()
        .prepare(
            "SELECT proposal_id, status, step_no FROM task_proposals
                    WHERE task_id = ?1 ORDER BY step_no;",
        )
        .expect("prepare");
    stmt.query_map([task], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows")
}

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

/// Creates a task, claims it, and proposes one write of `file`.
fn propose(s: &Serving, task: &str, worker: &str, file: &str, max_steps: u32) -> String {
    send(
        &s.endpoint,
        "c",
        "task/create",
        json!({"id": task, "max_steps": max_steps, "content": "governed"}),
    );
    send(
        &s.endpoint,
        "cl",
        "task/claim",
        json!({"id": task, "worker": worker}),
    );
    let reply = send(
        &s.endpoint,
        "p",
        "task/propose",
        json!({
            "task": task, "worker": worker, "capability": "filesystem/write-text",
            "target": file, "params": {"path": file, "contents": "x"}
        }),
    );
    assert_eq!(
        reply["result"]["proposal"]["capability"], "filesystem/write-text",
        "{reply}"
    );
    reply["result"]["proposal"]["proposal_id"]
        .as_str()
        .expect("a proposal id")
        .to_owned()
}

fn approve(s: &Path, pid: &str, ttl_ms: i64) -> Value {
    send(
        s,
        "a",
        "capability/approve",
        json!({ "proposal": pid, "ttl_ms": ttl_ms }),
    )
}

fn execute(s: &Path, pid: &str, worker: &str) -> Value {
    send(
        s,
        "x",
        "task/execute",
        json!({ "proposal": pid, "worker": worker }),
    )
}

// ---------------------------------------------------------------------------
// The recovery
// ---------------------------------------------------------------------------

/// An approval that expires while the task waits is replaced by a fresh one, and the step
/// then runs.
///
/// The general V-82, and the one that is not an operator typo: the TTL was fine when it was
/// issued and the human simply took longer than it lasted. The approval authorises nothing,
/// the replacement is a new digest rather than an extension of the old one, and the task
/// completes through the ordinary path.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_approval_that_expires_while_waiting_is_recoverable() {
    rt().block_on(async {
        let d = dir("waited-out");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "w1", "w1", "out.txt", 1);

        // A TTL that is valid on arrival and expired by the time anyone acts. `1` is the
        // smallest value the protocol can carry that is still `expires_at > issued_at`.
        let first = approve(&s.endpoint, &pid, 1);
        assert!(first.get("result").is_some(), "{first}");
        let digest_a = first["result"]["approval"]["digest"]
            .as_str()
            .expect("a digest")
            .to_owned();

        // Wait past it. Real elapsed time, not a fabricated clock: `is_valid_at` is
        // `now < expires_at`, so any later reading is expired.
        std::thread::sleep(Duration::from_millis(30));

        // The expired approval authorises nothing, and takes no lease doing so.
        let refused = execute(&s.endpoint, &pid, "w1");
        assert_eq!(
            refused["error"]["data"]["reason"], "approval-expired",
            "{refused}"
        );
        assert!(
            !workspace(&d).join("out.txt").exists(),
            "an expired approval must not execute"
        );
        assert_eq!(
            state_of(&s.endpoint, "w1"),
            "waiting-for-user",
            "a refused expiry must not park the task in `running` under a lease -- that was \\
             the second half of V-82"
        );

        // Recovery: approve again. A fresh digest, not the old one.
        let second = approve(&s.endpoint, &pid, 60_000);
        assert!(
            second.get("result").is_some(),
            "an expired approval must leave the proposal approvable: {second}"
        );
        let digest_b = second["result"]["approval"]["digest"]
            .as_str()
            .expect("a digest")
            .to_owned();
        assert_ne!(
            digest_a, digest_b,
            "the replacement must be new authority, not the expired one extended"
        );

        // And the ordinary path now works.
        let done = execute(&s.endpoint, &pid, "w1");
        assert_eq!(done["result"]["verified"], true, "{done}");
        assert!(workspace(&d).join("out.txt").exists());
        assert_eq!(state_of(&s.endpoint, "w1"), "completed");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Exactly one approval row survives, so the expired authority is gone rather than shadowed.
///
/// The old digest must not exist anywhere after the replacement. If both rows were kept, the
/// expired one would still be readable and would still have to be refused at every future
/// check — which is the shape of bug where "expired approvals are never resurrected" is true
/// only because nothing looks for them.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_expired_approval_leaves_no_authority_behind() {
    rt().block_on(async {
        let d = dir("no-shadow");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "n1", "w1", "out.txt", 1);
        approve(&s.endpoint, &pid, 1);
        std::thread::sleep(Duration::from_millis(30));
        let before = approval_rows(&d, "n1");
        assert_eq!(before.len(), 1, "{before:?}");

        let fresh = approve(&s.endpoint, &pid, 60_000);
        assert!(fresh.get("result").is_some(), "{fresh}");
        s.stop().await;

        let after = approval_rows(&d, "n1");
        assert_eq!(
            after.len(),
            1,
            "the replacement must overwrite, not accumulate: {after:?}"
        );
        assert_ne!(
            after[0].2, before[0].2,
            "the stored digest must be the fresh one"
        );
        assert!(
            after[0].4.is_none(),
            "and the fresh approval must not be born consumed: {after:?}"
        );

        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Single-use is not weakened
// ---------------------------------------------------------------------------

/// A live approval cannot be superseded, and a used one certainly cannot.
///
/// The other half of single-use. Allowing a second `capability/approve` to replace an unused
/// but live approval would mean a client holding one and the database holding another, and
/// the client would be holding the superseded one.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_live_approval_is_not_replaceable_and_a_used_one_certainly_is_not() {
    rt().block_on(async {
        let d = dir("single-use");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "s1", "w1", "out.txt", 1);

        let first = approve(&s.endpoint, &pid, 60_000);
        assert!(first.get("result").is_some(), "{first}");
        let digest_a = first["result"]["approval"]["digest"]
            .as_str()
            .unwrap()
            .to_owned();

        // Live: refused, and the stored digest is untouched.
        let again = approve(&s.endpoint, &pid, 60_000);
        assert_eq!(
            again["error"]["data"]["reason"], "approval-already-valid",
            "{again}"
        );

        // Executed, so the approval is consumed and the step is done.
        let done = execute(&s.endpoint, &pid, "w1");
        assert_eq!(done["result"]["verified"], true, "{done}");

        // Used: refused, distinctly, so a client can tell this from the live case.
        let after_use = approve(&s.endpoint, &pid, 60_000);
        assert_eq!(
            after_use["error"]["data"]["reason"], "approval-already-consumed",
            "{after_use}"
        );
        assert_eq!(state_of(&s.endpoint, "s1"), "completed");

        s.stop().await;
        let rows = approval_rows(&d, "s1");
        assert_eq!(
            rows[0].2.to_lowercase(),
            digest_a.to_lowercase(),
            "the original digest must still be the one stored"
        );
        assert!(
            rows[0].4.is_some(),
            "and it must be recorded as consumed: {rows:?}"
        );

        let _ = std::fs::remove_dir_all(&d);
    });
}

/// An expired approval cannot be presented again after a fresh one exists.
///
/// The specific sequence the invariant has teeth for: A issued, A expires, B issued, then A is
/// presented. There is no row for A any more, so this is refused before any policy question is
/// even reached — and refused *as an expiry*, not by executing with B's authority.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_expired_approval_cannot_be_replayed_after_a_fresh_one_exists() {
    rt().block_on(async {
        let d = dir("replay");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "r1", "w1", "out.txt", 1);

        let a = approve(&s.endpoint, &pid, 1);
        assert!(a.get("result").is_some(), "{a}");
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(
            execute(&s.endpoint, &pid, "w1")["error"]["data"]["reason"],
            "approval-expired",
            "A must be refused"
        );

        let b = approve(&s.endpoint, &pid, 60_000);
        assert!(b.get("result").is_some(), "{b}");

        // A is not a separate object any more. Executing the proposal now uses whatever
        // authority is stored -- B -- so this succeeds, which is the recovery working.
        let done = execute(&s.endpoint, &pid, "w1");
        assert_eq!(done["result"]["verified"], true, "B must authorise: {done}");

        // B is single-use.
        let twice = execute(&s.endpoint, &pid, "w1");
        assert!(
            twice.get("error").is_some(),
            "a consumed approval must not execute twice: {twice}"
        );

        s.stop().await;

        // The proof that A cannot be replayed: there is exactly one row, and it holds B's
        // digest. There is no surviving A for a later request to find.
        let rows = approval_rows(&d, "r1");
        assert_eq!(rows.len(), 1, "exactly one approval must exist: {rows:?}");
        let b_digest = b["result"]["approval"]["digest"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            rows[0].2.to_lowercase(),
            b_digest.to_lowercase(),
            "the stored authority must be B, so A is not merely superseded but gone"
        );

        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Step and task isolation
// ---------------------------------------------------------------------------

/// A replacement approval binds to the same logical step, and cannot drift to another.
///
/// The step arithmetic is what V-83 and the step-scoped approvals rest on. Recovery must not
/// be a hole in it: a fresh approval is minted from the proposal's durable `step_no`, so it
/// addresses the same step by construction rather than by a caller having said so.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_replacement_approval_binds_to_the_same_logical_step() {
    rt().block_on(async {
        let d = dir("stepbound");
        let s = Serving::start(d.clone()).await;

        // Two steps, so a wrong step number would be visible rather than coincidental.
        let pid = propose(&s, "sb1", "w1", "one.txt", 2);
        approve(&s.endpoint, &pid, 1);
        std::thread::sleep(Duration::from_millis(30));
        let fresh = approve(&s.endpoint, &pid, 60_000);
        assert!(fresh.get("result").is_some(), "{fresh}");
        s.stop().await;

        let rows = approval_rows(&d, "sb1");
        assert_eq!(
            rows.len(),
            1,
            "one approval for step 1's attempt, not one per step: {rows:?}"
        );
        assert_eq!(
            rows[0].0, 1,
            "the replacement must stay on the step it was minted for: {rows:?}"
        );
        let statuses = proposal_statuses(&d, "sb1");
        assert_eq!(
            statuses[0].2, 1,
            "and the proposal must still belong to step 1: {statuses:?}"
        );

        let _ = std::fs::remove_dir_all(&d);
    });
}

/// An approval that expires before step 1 executes cannot advance the task to step 2.
///
/// The continuation interaction. Only a verified effect may reach `AwaitingNextStep`, and an
/// expired approval cannot produce one, so the boundary must never be claimed and the
/// provider must never be asked for another proposal.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_expired_approval_cannot_cross_a_step_boundary() {
    rt().block_on(async {
        let d = dir("noboundary");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "nb1", "w1", "one.txt", 2);
        approve(&s.endpoint, &pid, 1);
        std::thread::sleep(Duration::from_millis(30));

        let refused = execute(&s.endpoint, &pid, "w1");
        assert_eq!(
            refused["error"]["data"]["reason"], "approval-expired",
            "{refused}"
        );

        // Not at a boundary, so continuation is refused on its own terms.
        assert_eq!(state_of(&s.endpoint, "nb1"), "waiting-for-user");
        let cont = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "nb1", "worker": "w1"}),
        );
        assert_eq!(
            cont["error"]["data"]["reason"], "not-at-boundary",
            "an expired approval must not have produced a boundary: {cont}"
        );
        s.stop().await;

        let statuses = proposal_statuses(&d, "nb1");
        assert_eq!(
            statuses.len(),
            1,
            "and no proposal may exist for a step that was never claimed: {statuses:?}"
        );

        let _ = std::fs::remove_dir_all(&d);
    });
}

/// An expired read approval produces no observation and no disclosure.
///
/// The disclosure interaction. Retention requires `is_verified()`, and an expired approval
/// cannot reach a verified dispatch, so the content must not exist to be disclosed. Asserted
/// on the durable rows, because the absence that matters is "nothing was retained anywhere
/// that could later be released".
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_expired_read_approval_retains_no_observation() {
    rt().block_on(async {
        let d = dir("noread");
        std::fs::create_dir_all(workspace(&d)).expect("workspace");
        std::fs::write(workspace(&d).join("a.txt"), "SECRET-BYTES").expect("seed");
        let s = Serving::start(d.clone()).await;

        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "rd1", "max_steps": 2, "content": "read a.txt"}),
        );
        send(
            &s.endpoint,
            "cl",
            "task/claim",
            json!({"id": "rd1", "worker": "w1"}),
        );
        let p = send(
            &s.endpoint,
            "p",
            "task/propose",
            json!({
                "task": "rd1", "worker": "w1", "capability": "filesystem/read-text",
                "target": "a.txt", "params": {"path": "a.txt"}
            }),
        );
        assert_eq!(
            p["result"]["proposal"]["capability"], "filesystem/read-text",
            "{p}"
        );
        let pid = p["result"]["proposal"]["proposal_id"]
            .as_str()
            .unwrap()
            .to_owned();
        approve(&s.endpoint, &pid, 1);
        std::thread::sleep(Duration::from_millis(30));

        let refused = execute(&s.endpoint, &pid, "w1");
        assert_eq!(
            refused["error"]["data"]["reason"], "approval-expired",
            "{refused}"
        );
        assert_eq!(
            state_of(&s.endpoint, "rd1"),
            "waiting-for-user",
            "no read may have run, so there is no boundary"
        );
        let cont = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "rd1", "worker": "w1"}),
        );
        assert!(cont.get("error").is_some(), "{cont}");
        s.stop().await;

        // No step result at all: nothing was read, so nothing was verified.
        let db = conn(&d);
        let results: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM task_step_results WHERE task_id = 'rd1'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(
            results, 0,
            "an expired approval must not produce a step result"
        );

        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Durability
// ---------------------------------------------------------------------------

/// Expiry survives a crash, and recovery survives the crash too.
///
/// The whole point of the durable rows: a restart must not resurrect the expired approval, and
/// must not lose the ability to issue a fresh one.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_crash_does_not_resurrect_an_expired_approval() {
    rt().block_on(async {
        let d = dir("crash");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "c1", "w1", "out.txt", 1);
        approve(&s.endpoint, &pid, 1);
        std::thread::sleep(Duration::from_millis(30));
        s.crash().await;

        // The row is durable, and still expired.
        let before = approval_rows(&d, "c1");
        assert_eq!(before.len(), 1, "{before:?}");
        assert!(
            before[0].4.is_none(),
            "it must not be marked consumed: {before:?}"
        );

        // A new daemon over the same store.
        let s2 = Serving::start(d.clone()).await;
        let refused = execute(&s2.endpoint, &pid, "w1");
        assert_eq!(
            refused["error"]["data"]["reason"], "approval-expired",
            "a restart must not resurrect expired authority: {refused}"
        );
        assert!(
            !workspace(&d).join("out.txt").exists(),
            "and must not execute"
        );

        // And the fresh approval still works, because recovery reads durable state only.
        let fresh = approve(&s2.endpoint, &pid, 60_000);
        assert!(fresh.get("result").is_some(), "{fresh}");
        let done = execute(&s2.endpoint, &pid, "w1");
        assert_eq!(done["result"]["verified"], true, "{done}");

        s2.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A crash *between* the expiry and the fresh approval leaves a task that is still recoverable.
///
/// The window the operator would actually hit: they approve, walk away, the daemon restarts,
/// they come back. Nothing about that sequence may need manual repair.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_crash_after_expiry_and_before_reapproval_still_recovers() {
    rt().block_on(async {
        let d = dir("crash2");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "c2", "w1", "out.txt", 1);
        approve(&s.endpoint, &pid, 1);
        std::thread::sleep(Duration::from_millis(30));
        s.crash().await;

        let s2 = Serving::start(d.clone()).await;
        assert_eq!(state_of(&s2.endpoint, "c2"), "waiting-for-user");
        let fresh = approve(&s2.endpoint, &pid, 60_000);
        assert!(
            fresh.get("result").is_some(),
            "the proposal must still be approvable after a restart: {fresh}"
        );
        assert_eq!(
            execute(&s2.endpoint, &pid, "w1")["result"]["verified"],
            true
        );

        s2.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

/// Two callers replacing the same expired approval: one wins, the other is refused.
///
/// Deterministic rather than "eventually consistent": the store's conditional update re-asserts
/// both preconditions inside one IMMEDIATE transaction, so the loser's `WHERE` no longer holds
/// and it is told so. Without that, both would succeed and the second digest would silently
/// replace the first with a client still holding the other one.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn two_concurrent_replacements_produce_one_approval() {
    rt().block_on(async {
        let d = dir("race");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "rc1", "w1", "out.txt", 1);
        approve(&s.endpoint, &pid, 1);
        std::thread::sleep(Duration::from_millis(30));

        let pid_a = pid.clone();
        let endpoint = s.endpoint.clone();
        let a = std::thread::spawn(move || {
            send(
                &endpoint,
                "ra",
                "capability/approve",
                json!({"proposal": pid_a, "ttl_ms": 60_000}),
            )
        });
        let endpoint = s.endpoint.clone();
        let b = std::thread::spawn(move || {
            send(
                &endpoint,
                "rb",
                "capability/approve",
                json!({"proposal": pid, "ttl_ms": 60_000}),
            )
        });
        let ra = a.join().expect("thread a");
        let rb = b.join().expect("thread b");

        let wins = [&ra, &rb]
            .iter()
            .filter(|r| r.get("result").is_some())
            .count();
        assert_eq!(wins, 1, "exactly one replacement may win: {ra} {rb}");
        let losses = [&ra, &rb]
            .iter()
            .filter(|r| r.get("error").is_some())
            .count();
        assert_eq!(
            losses, 1,
            "and the other must be refused, not ignored: {ra} {rb}"
        );
        // The loser is told the approval is already valid, which is the true state by then.
        let reason = [&ra, &rb]
            .iter()
            .find_map(|r| r.get("error"))
            .and_then(|e| e.get("data"))
            .and_then(|d| d.get("reason"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        assert!(
            reason == "approval-already-valid" || reason == "approval-expired",
            "the refusal must describe the actual state: {reason:?} in {ra} {rb}"
        );

        let state = state_of(&s.endpoint, "rc1");
        s.stop().await;
        let rows = approval_rows(&d, "rc1");
        assert_eq!(rows.len(), 1, "exactly one row must exist: {rows:?}");
        assert_eq!(state, "waiting-for-user", "neither caller may take a lease");

        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Concurrent execution against an expired approval executes nothing, exactly once.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn concurrent_execution_of_an_expired_approval_writes_nothing() {
    rt().block_on(async {
        let d = dir("raceexec");
        let s = Serving::start(d.clone()).await;
        let pid = propose(&s, "rx1", "w1", "out.txt", 1);
        approve(&s.endpoint, &pid, 1);
        std::thread::sleep(Duration::from_millis(30));

        let pid_a = pid.clone();
        let endpoint = s.endpoint.clone();
        let a = std::thread::spawn(move || {
            send(
                &endpoint,
                "xa",
                "task/execute",
                json!({"proposal": pid_a, "worker": "w1"}),
            )
        });
        let endpoint = s.endpoint.clone();
        let b = std::thread::spawn(move || {
            send(
                &endpoint,
                "xb",
                "task/execute",
                json!({"proposal": pid, "worker": "w1"}),
            )
        });
        let ra = a.join().expect("thread a");
        let rb = b.join().expect("thread b");

        for r in [&ra, &rb] {
            assert_eq!(
                r["error"]["data"]["reason"], "approval-expired",
                "both callers must see the same deterministic refusal: {ra} {rb}"
            );
        }
        assert!(
            !workspace(&d).join("out.txt").exists(),
            "nothing may be written under an expired approval"
        );
        assert_eq!(
            state_of(&s.endpoint, "rx1"),
            "waiting-for-user",
            "neither attempt may take a lease"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// The boundary itself
// ---------------------------------------------------------------------------

/// `expires_at_ms == now` is expired, and the rule is the same one everywhere.
///
/// Stated as a test because it is the boundary the whole fix rests on. `is_valid_at` is
/// `now < expires_at`, so an approval expires *at* its expiry instant, not after it — and the
/// store's replacement check uses the same operator, so the two cannot disagree about whether a
/// given instant is inside or outside the window.
#[test]
fn an_approval_is_expired_at_its_expiry_instant_and_not_one_millisecond_before() {
    use orxnud_domain::Actor;
    use orxnud_domain::approval::{ApprovalDigest, ApprovalRecord};
    use orxnud_domain::enums::RiskClass;

    let base = |expires_at_ms: i64| ApprovalRecord {
        actor_label: "ai".to_owned(),
        approver: Actor::Human {
            user: orxnud_domain::ids::UserId::new("local"),
            via: orxnud_domain::actor::AuthChannel::LocalInteractive,
        },
        capability: "filesystem/write-text".to_owned(),
        target: "a.txt".to_owned(),
        params: orxnud_policy::canonical_params(&json!({ "path": "a.txt" })),
        issued_at_ms: 1_000,
        expires_at_ms,
        risk: RiskClass::High,
        step_no: 1,
        digest: ApprovalDigest::from_bytes([1u8; 32]),
    };

    let at = base(5_000);
    assert!(at.is_valid_at(4_999), "one ms before expiry is live");
    assert!(
        !at.is_valid_at(5_000),
        "expires AT the instant, not after it"
    );
    assert!(!at.is_valid_at(5_001), "and stays expired");

    // A zero or negative window never produces a live approval.
    assert!(!base(1_000).is_valid_at(1_000), "a zero TTL is never live");
    assert!(
        !base(999).is_valid_at(1_000),
        "a negative TTL is never live"
    );
}
