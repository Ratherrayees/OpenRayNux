//! V-94 P1-20: an approval-consume failure was logged and the capability ran anyway.
//!
//! Split into its own file because it needs a real daemon process, a real socket and a
//! real proposal/approval cycle. The five store-level reproductions live in
//! `orxnud-task/tests/v94_reproduction.rs`.

#![allow(clippy::uninlined_format_args)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("v94-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
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

/// The real daemon, as a real process.
struct Daemon {
    child: Child,
    ep: PathBuf,
}

impl Daemon {
    fn start(root: &Path) -> Self {
        let ep = root.join("orxnud.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_orxnud"))
            .arg("--state-root")
            .arg(root)
            .env_remove("ORXNUD_FAULT")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn orxnud");
        let me = Self { child, ep };
        me.await_ready();
        me
    }

    fn await_ready(&self) {
        for _ in 0..1200 {
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
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.ep);
    }
}

// ===========================================================================
// P1-20 — an approval-consume failure was logged, and the capability ran anyway
// ===========================================================================
//
// `execute_proposal` ordered its work as: begin the execution lease, then
// `consume_approval`, then dispatch. A `consume_approval` failure was
// `tracing::error!`-ed and execution continued -- so a task could dispatch a
// capability with no durable record that its approval was spent.
//
// Reproduced over the real runtime: a real daemon, a real socket, a real proposal and
// approval, and a SQLite trigger that makes the consume UPDATE a no-op. The trigger is
// SQLite's own mechanism and is installed by the test, so the failure is a genuine
// storage-level refusal rather than an injected error object.
//
// `text/word-count` is used deliberately: it is Tier-0 and in-process, so the capability
// genuinely executes on any host and this test needs no sandbox. Using a Tier-1
// capability here would have made the evidence conditional on sandbox infrastructure
// for a defect that has nothing to do with sandboxing.

/// Injects a failure into the task-domain approval consumption.
fn block_task_approval_consumption(db: &std::path::Path) {
    orxnud_store::Store::open(db, false)
        .expect("open")
        .conn()
        .execute_batch(
            "CREATE TRIGGER refuse_consumption BEFORE UPDATE OF consumed_at_ms ON task_approvals
             BEGIN SELECT RAISE(ABORT, 'injected consumption failure'); END;",
        )
        .expect("install the injected failure");
}

/// A consume failure must stop the capability from running.
#[test]
fn p1_20_a_consume_failure_must_not_let_the_capability_execute() {
    let d = dir("p1-20");
    std::fs::create_dir_all(d.join("workspace")).expect("workspace");
    let s = Daemon::start(&d);

    send(
        s.ep(),
        "c",
        "task/create",
        json!({"id": "p120", "content": "count"}),
    );
    let claimed = send(
        s.ep(),
        "cl",
        "task/claim",
        json!({"id": "p120", "worker": "w1"}),
    );
    assert!(claimed.get("result").is_some(), "claim failed: {claimed}");
    let p = send(
        s.ep(),
        "p",
        "task/propose",
        json!({
            "task": "p120", "worker": "w1", "capability": "text/word-count",
            "params": {"text": "one two three"}}),
    );
    let pid = p["result"]["proposal"]["proposal_id"]
        .as_str()
        .expect("a proposal id")
        .to_owned();
    let a = send(
        s.ep(),
        "a",
        "capability/approve",
        json!({"proposal": pid, "ttl_ms": 60_000}),
    );
    assert!(a.get("result").is_some(), "approval failed: {a}");

    // From here the only approval-consume write will fail.
    block_task_approval_consumption(&d.join("state.db"));

    let x = send(
        s.ep(),
        "x",
        "task/execute",
        json!({"proposal": pid, "worker": "w1"}),
    );

    // The refusal is the whole point: with no durable record that the approval was
    // spent, the daemon must not act on it.
    assert!(
        x.get("error").is_some(),
        "a consume failure let the execution proceed, so a capability ran with no \
         durable record of its approval: {x}"
    );

    // And the durable consequences must match: the task must not be a completed one,
    // and the step must not have been recorded as verified.
    let t = s.task("p120");
    assert_ne!(
        t["state"], "completed",
        "the task completed despite the consume failure: {t}"
    );
    assert_ne!(
        t["steps_completed"], 1,
        "the step was recorded as verified despite the consume failure: {t}"
    );
    assert_ne!(
        t["lease_holder"], "w1",
        "the execution lease was kept despite the consume failure: {t}"
    );
    drop(s);
    let _ = std::fs::remove_dir_all(&d);
}
