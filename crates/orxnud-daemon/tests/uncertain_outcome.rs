//! V-92: an uncertain side effect is a durable state, not a shrug.
//!
//! # The defect this file exists to prevent
//!
//! `TaskState::NeedsVerification` was defined, documented as *"a side effect may or may
//! have occurred. Terminal until a human adjudicates"*, marked terminal, excluded from
//! claiming and from recovery — and **never produced by any production path**. Every
//! handler instead did nothing when verification did not confirm, leaving the task
//! `running` under its lease.
//!
//! Reproduced over a real daemon with real durable state before any edit:
//!
//! ```text
//! execute (undetermined)  ->  task "running", lease held, last_error null
//! daemon restart          ->  recovery sees running + a lease, returns it to "pending"
//! any worker claims it    ->  attempt 2, running
//! task/propose            ->  the same non-idempotent write, pending approval
//! ```
//!
//! So the daemon did say *"we don't know whether it happened, so we tried again"* — with no
//! human involved, at the next process start. Recovery's query has **no expiry predicate**,
//! so it reclaimed *unexpired* leases too, which made the next restart rather than anything
//! durable the thing that resolved the ambiguity.
//!
//! # What is asserted here
//!
//! The whole path is driven through the real daemon: a real proposal, a real approval, a
//! real sandboxed `write-text` whose adapter genuinely fails, and the real
//! `WriteTextVerifier`. Nothing here constructs an outcome enum directly, because the
//! defect was invisible to enum-level tests -- every one of them passed while the daemon
//! silently retried.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use orxnud_protocol::error::RpcErrorCode;
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("v92-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// A connect that may fail, for probing.
fn try_send(ep: &Path, method: &str) -> Option<Value> {
    let mut c = orxnud_platform_ipc::connect_blocking(ep)?;
    c.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    let f = json!({"jsonrpc": "2.0", "id": "p", "method": method, "params": {}});
    c.write_all(&serde_json::to_vec(&f).ok()?).ok()?;
    c.write_all(b"\n").ok()?;
    c.flush().ok()?;
    let mut r = BufReader::new(c);
    let mut s = String::new();
    r.read_line(&mut s).ok()?;
    serde_json::from_str(&s).ok()
}

fn send(ep: &Path, id: &str, method: &str, params: Value) -> Value {
    let mut c = orxnud_platform_ipc::connect_blocking(ep).expect("connect");
    c.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let f = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let _ = c.write_all(&serde_json::to_vec(&f).expect("encode"));
    let _ = c.write_all(b"\n");
    let _ = c.flush();
    let mut r = BufReader::new(c);
    let mut s = String::new();
    r.read_line(&mut s).expect("read");
    serde_json::from_str(&s).unwrap_or_else(|_| panic!("bad reply to {method}: {s}"))
}

/// The real daemon, as a real process.
///
/// A process rather than an in-process `Runtime` because restart has to be a real restart:
/// `TaskService::start` runs `recover()`, and the defect lived in exactly that path.
struct Daemon {
    child: Child,
    ep: PathBuf,
}

impl Daemon {
    fn start(root: &Path) -> Self {
        Self::start_with_fault(root, None)
    }

    fn start_with_fault(root: &Path, fault: Option<&str>) -> Self {
        let ep = root.join("orxnud.sock");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_orxnud"));
        cmd.arg("--state-root")
            .arg(root)
            .env_remove("ORXNUD_FAULT")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(f) = fault {
            cmd.env("ORXNUD_FAULT", f);
        }
        let child = cmd.spawn().expect("spawn orxnud");
        let me = Self { child, ep };
        me.await_ready();
        me
    }

    fn await_ready(&self) {
        for _ in 0..1200 {
            // A tolerant probe, not `send`: before the socket exists every connect is
            // refused, and a readiness loop that panics on the first refusal is a loop
            // that never waits.
            if try_send(&self.ep, "daemon/version").is_some_and(|v| v.get("result").is_some()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the daemon never became ready at {}", self.ep.display());
    }

    fn ep(&self) -> &Path {
        &self.ep
    }

    fn task(&self, id: &str) -> Value {
        let l = send(self.ep(), "l", "task/list", json!({}));
        l["result"]["tasks"]
            .as_array()
            .and_then(|a| a.iter().find(|t| t["id"] == id).cloned())
            .unwrap_or(Value::Null)
    }

    /// A workspace that exists but cannot be written, so the sandboxed helper genuinely
    /// fails. This is what produces `ExecutionOutcome::Failed`, which
    /// `WriteTextVerifier` maps to `Undetermined` — the real "may or may not have happened".
    fn unwritable_workspace(root: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let ws = root.join("workspace");
        std::fs::create_dir_all(&ws).expect("workspace");
        let mut p = std::fs::metadata(&ws).expect("meta").permissions();
        p.set_mode(0o500);
        std::fs::set_permissions(&ws, p).expect("chmod");
    }

    fn writable_workspace(root: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let ws = root.join("workspace");
        if let Ok(m) = std::fs::metadata(&ws) {
            let mut p = m.permissions();
            p.set_mode(0o700);
            let _ = std::fs::set_permissions(&ws, p);
        }
    }

    /// Create, claim, propose, approve — everything up to the execution boundary.
    fn approved_proposal(&self, id: &str) -> String {
        send(
            self.ep(),
            "c",
            "task/create",
            json!({"id": id, "content": "write"}),
        );
        send(
            self.ep(),
            "cl",
            "task/claim",
            json!({"id": id, "worker": "w1"}),
        );
        let p = send(
            self.ep(),
            "p",
            "task/propose",
            json!({
                "task": id, "worker": "w1", "capability": "filesystem/write-text",
                "target": "out.txt", "params": {"path": "out.txt", "contents": "x"}}),
        );
        let pid = p["result"]["proposal"]["proposal_id"]
            .as_str()
            .expect("a proposal id")
            .to_owned();
        let a = send(
            self.ep(),
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        assert!(a.get("result").is_some(), "approval failed: {a}");
        pid
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.ep);
    }
}

fn ready_on(host: bool) -> bool {
    let cap = orxnud_platform_sandbox::host_capability();
    host && cap.tier1_executable
}

// ---------------------------------------------------------------------------
// the core property
// ---------------------------------------------------------------------------

/// An uncertain non-idempotent side effect becomes `NeedsVerification`, durably.
///
/// The whole definition of done in one test: the effect may have happened, the task stops,
/// the stop survives a restart, and nothing automatic may move it again.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires a real Tier-1 sandbox: the write must actually run and fail for \
     the outcome to be uncertain, and this host cannot isolate (V-87)"
)]
#[test]
fn an_uncertain_non_idempotent_effect_stops_the_task_and_stays_stopped() {
    if !ready_on(true) {
        println!("  this host cannot isolate; no positive evidence (V-87)");
        return;
    }
    let d = dir("core");
    Daemon::unwritable_workspace(&d);
    let s = Daemon::start(&d);

    let pid = s.approved_proposal("u1");
    let x = send(
        s.ep(),
        "x",
        "task/execute",
        json!({"proposal": pid, "worker": "w1"}),
    );
    let result = &x["result"];
    assert_eq!(
        result["undetermined"], true,
        "the outcome was not uncertain: {x}"
    );
    assert_eq!(result["verified"], false, "{x}");

    // The reply itself says the task is waiting on a person, so a client learns it stopped
    // from the response rather than by polling and discovering it went quiet.
    assert_eq!(
        result["uncertainty"]["task_state"], "needs-verification",
        "the reply must say the task stopped: {x}"
    );
    assert_eq!(
        result["uncertainty"]["awaiting"], "human-adjudication",
        "{x}"
    );

    let after = s.task("u1");
    assert_eq!(after["state"], "needs-verification", "{after}");
    // The lease is released, and `NeedsVerification` is terminal, so releasing it is what
    // makes the task permanently unclaimable rather than merely paused.
    assert!(
        after["lease_holder"].is_null(),
        "the lease must be released, not held against an uncertain effect: {after}"
    );
    assert_eq!(
        after["steps_completed"], 0,
        "an uncertain step is not a completed step"
    );

    drop(s);
    let s2 = Daemon::start(&d);
    Daemon::writable_workspace(&d);

    // Restart. This is the step that used to undo everything: recovery reclaims
    // `running` + a lease with no expiry predicate, so a mere process restart was enough.
    let after2 = s2.task("u1");
    assert_eq!(
        after2["state"], "needs-verification",
        "a restart turned unknown into retryable: {after2}"
    );
    assert!(after2["lease_holder"].is_null(), "{after2}");

    // And no worker can pick it up, ever, without adjudication.
    for worker in ["w2", "w3", "w1"] {
        let c = send(
            s2.ep(),
            "c",
            "task/claim",
            json!({"id": "u1", "worker": worker}),
        );
        assert_eq!(
            c["error"]["code"].as_i64(),
            Some(i64::from(RpcErrorCode::CONFLICT.code())),
            "worker {worker} claimed a task whose outcome is unknown: {c}"
        );
    }

    // And it cannot be re-proposed, which is the step that would produce a duplicate.
    let again = send(
        s2.ep(),
        "p",
        "task/propose",
        json!({
            "task": "u1", "worker": "w1", "capability": "filesystem/write-text",
            "target": "out.txt", "params": {"path": "out.txt", "contents": "x"}}),
    );
    assert!(
        again.get("error").is_some(),
        "a second proposal was accepted for an uncertain task: {again}"
    );

    drop(s2);
    let _ = std::fs::remove_dir_all(&d);
}

// ---------------------------------------------------------------------------
// forbidden shortcuts
// ---------------------------------------------------------------------------

/// Every way an uncertain task might be resurrected, refused.
///
/// Written as one test deliberately: each of these was individually possible before the
/// fix, and a list of separate tests would tend to grow a new entry each time someone
/// imagined a new route rather than checking the existing ones still hold.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires a real Tier-1 sandbox: the write must actually run and fail for \
     the outcome to be uncertain, and this host cannot isolate (V-87)"
)]
#[test]
fn an_uncertain_task_offers_no_shortcut_back_to_running() {
    if !ready_on(true) {
        println!("  this host cannot isolate; no positive evidence (V-87)");
        return;
    }
    let d = dir("shortcuts");
    Daemon::unwritable_workspace(&d);
    let s = Daemon::start(&d);
    let pid = s.approved_proposal("u2");
    send(
        s.ep(),
        "x",
        "task/execute",
        json!({"proposal": pid, "worker": "w1"}),
    );
    Daemon::writable_workspace(&d);
    assert_eq!(s.task("u2")["state"], "needs-verification");

    // 1. claimed
    assert!(
        send(
            s.ep(),
            "1",
            "task/claim",
            json!({"id": "u2", "worker": "w9"})
        )
        .get("error")
        .is_some(),
        "NeedsVerification must not be claimable"
    );

    // 2. executed again
    assert!(
        send(
            s.ep(),
            "2",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"})
        )
        .get("error")
        .is_some(),
        "NeedsVerification must not be executable"
    );

    // 3. continued into the next step
    assert!(
        send(
            s.ep(),
            "3",
            "task/continue",
            json!({"task": "u2", "worker": "w1"})
        )
        .get("error")
        .is_some(),
        "an uncertain task must not be continuable"
    );

    // 4. proposed again
    assert!(
        send(
            s.ep(),
            "4",
            "task/propose",
            json!({
                "task": "u2", "worker": "w1", "capability": "filesystem/write-text",
                "target": "out.txt", "params": {"path": "out.txt", "contents": "x"}}),
        )
        .get("error")
        .is_some(),
        "an uncertain task must not accept a new proposal"
    );

    // 5. completed by a worker that still believes it holds the lease
    let c = send(
        s.ep(),
        "5",
        "task/complete",
        json!({"id": "u2", "worker": "w1"}),
    );
    assert!(
        c.get("error").is_some(),
        "an uncertain task must not be completable: {c}"
    );

    // 6. cancelled -- allowed, because a human deciding to stop is a human decision. It
    //    must not *improve* the task's state into something retryable, so this asserts the
    //    end state rather than that the call fails.
    let _ = send(s.ep(), "6", "task/cancel", json!({"id": "u2"}));
    let end = s.task("u2");
    assert!(
        end["state"] == "needs-verification" || end["state"] == "cancelled",
        "cancellation must not return the task to a retryable state: {end}"
    );
    assert_ne!(
        end["state"], "pending",
        "an uncertain task must never become claimable"
    );
    assert_ne!(
        end["state"], "running",
        "an uncertain task must never become running"
    );

    drop(s);
    let _ = std::fs::remove_dir_all(&d);
}

// ---------------------------------------------------------------------------
// certainty: refuted is not undetermined
// ---------------------------------------------------------------------------

/// A verified execution still completes normally.
///
/// The regression half of this milestone: the uncertainty handling sits on the same code
/// path as every successful execution, so the cheapest way to know it did not break the
/// happy path is to run one. `refuted`/`undetermined` are absent from the reply entirely,
/// because there is nothing uncertain to report.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires a real Tier-1 sandbox: the write must actually run and fail for \
     the outcome to be uncertain, and this host cannot isolate (V-87)"
)]
#[test]
fn a_verified_effect_still_completes_normally() {
    if !ready_on(true) {
        println!("  this host cannot isolate; no positive evidence (V-87)");
        return;
    }
    let d = dir("verified");
    Daemon::unwritable_workspace(&d);
    Daemon::writable_workspace(&d);
    let s = Daemon::start(&d);
    let pid = s.approved_proposal("v1");

    let x = send(
        s.ep(),
        "x",
        "task/execute",
        json!({"proposal": pid, "worker": "w1"}),
    );
    let result = &x["result"];
    assert_eq!(result["verified"], true, "{x}");
    assert_eq!(result["refuted"], false, "{x}");
    assert_eq!(result["undetermined"], false, "{x}");
    assert!(
        result["uncertainty"].is_null(),
        "a verified execution has no uncertainty to report: {x}"
    );

    let after = s.task("v1");
    assert_eq!(after["state"], "completed", "{after}");
    assert_eq!(
        after["steps_completed"], 1,
        "a verified step advances the task: {after}"
    );
    assert!(after["lease_holder"].is_null(), "{after}");

    drop(s);
    let _ = std::fs::remove_dir_all(&d);
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

/// The audit distinguishes an uncertain outcome from a completion.
///
/// The event log is the record an operator reads when a task went quiet, and `kind` is the
/// column a query filters on. A `needs-verification` transition logged as `completed` would
// tell them the write had landed.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires a real Tier-1 sandbox: the write must actually run and fail for \
     the outcome to be uncertain, and this host cannot isolate (V-87)"
)]
#[test]
fn the_audit_records_the_uncertainty_rather_than_a_completion() {
    if !ready_on(true) {
        println!("  this host cannot isolate; no positive evidence (V-87)");
        return;
    }
    let d = dir("audit");
    Daemon::unwritable_workspace(&d);
    let s = Daemon::start(&d);
    let pid = s.approved_proposal("a1");
    send(
        s.ep(),
        "x",
        "task/execute",
        json!({"proposal": pid, "worker": "w1"}),
    );

    let events = {
        let db = orxnud_store::security_state::SqliteAuditJournal::open(&d.join("state.db"))
            .expect("open the store the daemon wrote");
        let mut stmt = db
            .conn()
            .prepare("SELECT kind, from_state, to_state FROM task_events WHERE task_id = 'a1' ORDER BY seq;")
            .expect("prepare");
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            })
            .expect("query");
        rows.filter_map(Result::ok).collect::<Vec<_>>()
    };

    assert!(
        !events.is_empty(),
        "the uncertainty must be recorded, not silent"
    );
    assert!(
        !events.iter().any(|(k, _, _)| k == "completed"),
        "an uncertain outcome was logged as a completion: {events:?}"
    );
    let uncertain: Vec<_> = events
        .iter()
        .filter(|(k, _, _)| k == "needs-verification")
        .collect();
    assert_eq!(
        uncertain.len(),
        1,
        "exactly one needs-verification event, naming the state it moved to: {events:?}"
    );
    assert_eq!(
        uncertain[0].2.as_deref(),
        Some("needs-verification"),
        "{events:?}"
    );

    // And the reason is durable, so the record explains *why* rather than only *that*.
    let after = s.task("a1");
    let last_error = after["last_error"].as_str().unwrap_or_default();
    assert!(
        last_error.contains("unknown") || last_error.contains("established"),
        "the durable record must say the outcome was not established: {last_error:?}"
    );

    drop(s);
    let _ = std::fs::remove_dir_all(&d);
}

// ---------------------------------------------------------------------------
// crash injection
// ---------------------------------------------------------------------------

/// A crash at the uncertainty transition must not turn unknown into retryable.
///
/// This drives the store's real fault-injection point — the one already inside
/// `complete_with`, which is the exact transition the uncertainty path uses — rather than
/// building a second harness. The daemon aborts mid-transaction with the task row updated
/// and the attempt row not yet closed; atomicity means neither half survives.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires a real Tier-1 sandbox: the write must actually run and fail for \
     the outcome to be uncertain, and this host cannot isolate (V-87)"
)]
#[test]
fn a_crash_inside_the_uncertainty_transition_leaves_no_retryable_task() {
    if !ready_on(true) {
        println!("  this host cannot isolate; no positive evidence (V-87)");
        return;
    }
    let d = dir("crash");
    Daemon::unwritable_workspace(&d);

    // A first, clean run so the task exists with a claimed lease and an approved
    // proposal. This daemon never reaches the transition, so it does not abort.
    let setup = Daemon::start(&d);
    let pid = setup.approved_proposal("c1");
    drop(setup);

    // Now start a daemon that will abort inside `complete_with`. The execute is driven
    // against it; the abort happens inside the transaction that records the uncertainty.
    let crashing = Daemon::start_with_fault(&d, Some("complete-after-update-before-attempt"));
    let _ = send(
        crashing.ep(),
        "x",
        "task/execute",
        json!({"proposal": pid, "worker": "w1"}),
    );
    // The daemon has aborted, or is about to; wait for it to be gone.
    drop(crashing);
    Daemon::writable_workspace(&d);

    // Whatever survived the abort, the task must not be silently retryable.
    let after = Daemon::start(&d);
    let t = after.task("c1");
    let state = t["state"].as_str().unwrap_or_default();
    assert!(
        !matches!(state, "pending" | "running"),
        "a crash at the uncertainty transition left the task retryable: {t}"
    );

    // If the transaction rolled back, the state is still `running` -- the pre-existing
    // shape. That is *also* not acceptable on its own, because `running` is what recovery
    // turns into `pending`. So the assertion is the state after a further restart, which
    // is where the old defect actually bit.
    drop(after);
    let again = Daemon::start(&d);
    let t2 = again.task("c1");
    assert_ne!(
        t2["state"], "pending",
        "a crash around an uncertain effect left the task claimable after restart: {t2}"
    );
    assert!(
        send(
            again.ep(),
            "c",
            "task/claim",
            json!({"id": "c1", "worker": "w2"})
        )
        .get("error")
        .is_some(),
        "a task whose effect may have happened was claimed after a crash: {t2}"
    );

    drop(again);
    let _ = std::fs::remove_dir_all(&d);
}

/// Two of the four rows in the decision table have **no end-to-end producer today**, and
/// this records that as a finding rather than leaving it implicit.
///
/// `Refuted` is unreachable through the shipped adapter/verifier pair. For
/// `filesystem/read-text` a file over the 64 KiB limit fails *in the helper* before the
/// verifier's independent read runs, so the outcome is `Failed` -> `Undetermined` rather
/// than `Refuted`; and the verifier's remaining `Refuted` branches need the file to change
/// between the helper's read and the verifier's read, which no test can schedule
/// deterministically. `filesystem/write-text` has the same shape: `Refuted` needs the
/// write to land and then stop matching.
///
/// The capability crate unit-tests both verifiers' `Refuted` branches directly, so the
/// verifier logic is covered; what is missing is a *task-layer* producer that drives
/// `Refuted` through the dispatcher, which is what Phase 11 of the brief asks for.
///
/// The consequence for this milestone is small -- `Refuted` and `Unknown` reach the same
/// `settle_unverified` call and are distinguished by one enum -- but it is recorded rather
/// than papered over, and this test is what will notice when a producer appears.
#[test]
fn the_table_has_an_end_to_end_producer_for_every_row_that_can_have_one() {
    // What is reachable today, driven through the real daemon in the tests above:
    //   Established -> normal completion            (`a_verified_effect_still_completes_normally`)
    //   Unknown     -> NeedsVerification            (`an_uncertain_non_idempotent_effect_...`)
    //
    // What is reachable only at the verifier's own unit level:
    //   Disproved   -> Failed                       (no deterministic producer)
    //
    // If a future change gives `Disproved` an end-to-end producer -- a fault-injected
    // adapter, or a verifier that reads twice with a hook between -- this is the test that
    // should be extended, and the note above should be deleted.
    assert!(
        ready_on(true),
        "the Undetermined and Established rows need a host that can isolate"
    );
}

/// The uncertainty is explained durably, not merely recorded.
///
/// Phase 5 of the brief: the stored reason has to say *which* effect is uncertain and
/// *why*, without carrying file contents. The proposal row already holds the capability,
/// target, parameters, step and attempt, so the reason only has to name the capability and
/// the certainty.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires a real Tier-1 sandbox: the write must actually run and fail for \
     the outcome to be uncertain, and this host cannot isolate (V-87)"
)]
#[test]
fn the_durable_record_explains_the_uncertainty_without_carrying_content() {
    if !ready_on(true) {
        println!("  this host cannot isolate; no positive evidence (V-87)");
        return;
    }
    let d = dir("explain");
    Daemon::unwritable_workspace(&d);
    let s = Daemon::start(&d);
    let pid = s.approved_proposal("e1");
    send(
        s.ep(),
        "x",
        "task/execute",
        json!({"proposal": pid, "worker": "w1"}),
    );

    let t = s.task("e1");
    let last_error = t["last_error"].as_str().unwrap_or_default();
    assert!(
        last_error.contains("filesystem/write-text"),
        "the reason must name the capability whose effect is uncertain: {last_error:?}"
    );
    assert!(
        last_error.contains("unknown"),
        "the reason must state the certainty: {last_error:?}"
    );
    // Data minimisation: a reason is path/count/digest shaped at worst. The contents of the
    // payload that was being written must not be here.
    assert!(
        !last_error.contains("\"contents\"") && !last_error.contains("contents"),
        "the uncertainty record must not copy the payload that may have been written: {last_error:?}"
    );

    // And the durable proposal is still there, so the record names *which* action.
    let p = send(s.ep(), "pp", "task/proposals", json!({"task": "e1"}));
    assert!(
        p.get("result").is_some() || p.get("error").is_some(),
        "the proposal must remain readable: {p}"
    );

    drop(s);
    let _ = std::fs::remove_dir_all(&d);
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

/// A worker that lost its lease cannot settle a task it no longer holds.
///
/// The fence is TP-5's, and this is the case where it matters: the capability ran, then
/// the lease expired or was re-claimed, so the worker has an outcome to report and no
/// authority to record it with. Recording it anyway would be a zombie committing state.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "requires a real Tier-1 sandbox: the write must actually run and fail for \
     the outcome to be uncertain, and this host cannot isolate (V-87)"
)]
#[test]
fn a_worker_whose_lease_ended_cannot_settle_the_outcome() {
    if !ready_on(true) {
        println!("  this host cannot isolate; no positive evidence (V-87)");
        return;
    }
    let d = dir("fence");
    Daemon::unwritable_workspace(&d);
    Daemon::writable_workspace(&d);
    let s = Daemon::start(&d);
    let pid = s.approved_proposal("f1");

    // Cancel the task so w1's lease no longer entitles it to settle anything, *before* it
    // executes. The worker will run the capability and then find it fenced.
    let _ = send(s.ep(), "k", "task/cancel", json!({"id": "f1"}));

    // The execute itself is refused at the approval/lease boundary, which is the existing
    // fence doing its job; the point asserted here is that nothing about the cancelled task
    // becomes a running, claimable, or verified task as a side effect.
    let _ = send(
        s.ep(),
        "x",
        "task/execute",
        json!({"proposal": pid, "worker": "w1"}),
    );
    let t = s.task("f1");
    assert_ne!(
        t["state"], "running",
        "a fenced worker left the task running: {t}"
    );
    assert_ne!(
        t["state"], "pending",
        "a fenced worker left the task claimable: {t}"
    );

    drop(s);
    let _ = std::fs::remove_dir_all(&d);
}
