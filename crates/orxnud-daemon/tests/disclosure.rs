//! Stage 4c: the governed observation/disclosure runtime path.
//!
//! # What is being proven
//!
//! `observation.rs` proved the *rules*: an approved read's content is released to one
//! provider identity, for one proposal, whole-blob only, and consumed on release. Nothing
//! called it. This file proves the *wiring*: that a real `filesystem/read-text` dispatch,
//! approved and verified through the governed path, actually produces an observation, and
//! that the observation then reaches a provider request — and that every way of getting
//! content to somewhere it was not approved for fails.
//!
//! Each test drives a real daemon over a real Unix domain socket, so `tasks.rs`'s
//! `cfg_attr` gate and its reasoning apply here unchanged.
//!
//! # The flow
//!
//! ```text
//! task/ai-propose  -> proposes filesystem/read-text
//! human approves
//! task/execute     -> sandboxed read, independent verification
//!                     -> observation retained, bound to (task, step, endpoint, model)
//! task/continue    -> claims the next step, releases the observation into the request,
//!                     records a disclosure on its own audit correlation
//! ```
//!
//! The content never becomes durable: `read_text` declares its output ephemeral, so
//! `structured_output` is dropped and the bytes live only in memory until consumed.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use orxnud_daemon::Paths;
use orxnud_daemon::observation::{DisclosureSummary, ProviderIdentity};
use orxnud_daemon::proposer::{ProposalContext, ProposalProvider, ProviderError};
use orxnud_daemon::runtime::Runtime;
use orxnud_domain::security_state::AuditJournal;

use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use serde_json::{Value, json};

/// Unmistakable anywhere it should not be: in a prompt, a log, an audit detail, or a reply.
const SENTINEL: &str = "SENTINEL-READ-CONTENT-4a91c7e2";

struct NoSecrets;

#[derive(Debug, thiserror::Error)]
#[error("no secret store in the disclosure suite")]
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
    let d = std::env::temp_dir().join(format!("orxnud-disc-{}-{tag}", std::process::id()));
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
    async fn start_with(root: PathBuf, provider: Arc<dyn ProposalProvider>) -> Self {
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

/// A provider that answers from a script and records every context it was given.
///
/// Recording is the point: it is the only place a test can see what actually went into a
/// provider request, and it is how the positive tests assert the content arrived and the
/// negative ones assert it did not. The recorded contexts hold the real `DisclosureBatch`,
/// so a test can inspect the *structured* disclosure rather than parsing a rendered prompt.
struct Recorder {
    model: String,
    endpoint: String,
    script: Mutex<std::collections::VecDeque<String>>,
    seen: Mutex<Vec<ProposalContext>>,
}

impl Recorder {
    fn new(model: &str, endpoint: &str, script: &[&str]) -> Self {
        Self {
            model: model.to_owned(),
            endpoint: endpoint.to_owned(),
            script: Mutex::new(script.iter().map(|s| (*s).to_owned()).collect()),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn contexts(&self) -> Vec<ProposalContext> {
        self.seen.lock().expect("recorder lock").clone()
    }

    /// The disclosures attached to the `n`-th request, 0-based.
    fn disclosures_at(&self, n: usize) -> Vec<DisclosureSummary> {
        self.contexts()
            .get(n)
            .expect("a recorded context")
            .disclosures
            .summary()
    }

    fn total_disclosed_bytes(&self) -> usize {
        self.contexts()
            .iter()
            .map(|c| c.disclosures.total_bytes())
            .sum()
    }
}

impl ProposalProvider for Recorder {
    fn model_id(&self) -> &str {
        &self.model
    }

    fn destination(&self) -> Option<ProviderIdentity> {
        Some(ProviderIdentity::new(&self.endpoint, &self.model))
    }

    fn complete(&self, ctx: &ProposalContext) -> Result<String, ProviderError> {
        self.seen.lock().expect("recorder lock").push(ctx.clone());
        self.script
            .lock()
            .expect("script lock")
            .pop_front()
            .ok_or_else(|| ProviderError::Unreachable("the script is exhausted".to_owned()))
    }
}

/// The proposal that asks for the read, and the one that follows it.
const READ_PROPOSAL: &str =
    r#"{"capability":"filesystem/read-text","target":"a.txt","params":{"path":"a.txt"}}"#;
const WRITE_PROPOSAL: &str = r#"{"capability":"filesystem/write-text","target":"final.txt","params":{"path":"final.txt","contents":"done"}}"#;

/// Seeds a workspace holding the file the read will return.
fn seed(root: &Path) {
    let ws = workspace(root);
    std::fs::create_dir_all(&ws).expect("workspace");
    std::fs::write(ws.join("a.txt"), SENTINEL).expect("seed");
}

/// Creates a two-step task, claims it, and proposes the read.
fn propose_the_read(s: &Serving) -> String {
    send(
        &s.endpoint,
        "c",
        "task/create",
        json!({"id": "t1", "max_steps": 2, "content": "read a.txt then write final.txt"}),
    );
    send(
        &s.endpoint,
        "c",
        "task/claim",
        json!({"id": "t1", "worker": "w1"}),
    );
    let p = send(
        &s.endpoint,
        "p",
        "task/ai-propose",
        json!({"task": "t1", "worker": "w1"}),
    );
    assert_eq!(
        p["result"]["proposal"]["capability"], "filesystem/read-text",
        "the script must have proposed the read: {p}"
    );
    p["result"]["proposal"]["proposal_id"]
        .as_str()
        .expect("a proposal id")
        .to_owned()
}

/// Approves and executes, requiring a **verified** outcome.
///
/// A host that cannot sandbox cannot produce a verified read, and therefore cannot produce an
/// observation — that is a property of the design, not a workaround. The caller decides what
/// to assert about the refusal.
fn approve_and_run(s: &Serving, pid: &str) -> Value {
    approve_read(&s.endpoint, pid, true);
    let out = send(
        &s.endpoint,
        "x",
        "task/execute",
        json!({ "proposal": pid, "worker": "w1" }),
    );
    assert!(
        out["result"]["verified"] == true,
        "the read must verify for an observation to exist: {out}"
    );
    out
}

// ---------------------------------------------------------------------------
// The flow
// ---------------------------------------------------------------------------

/// The whole path, end to end: read → verify → observe → disclose → next proposal.
///
/// The positive case for the data-release boundary. Three things are asserted together
/// because each is a precondition of the next, and a failure in any one of them would
/// otherwise be reported as "no content reached the model" without saying which gate closed.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_approved_verified_read_reaches_the_next_proposal_and_nothing_else() {
    rt().block_on(async {
        let d = dir("happy");
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[READ_PROPOSAL, WRITE_PROPOSAL],
        ));
        let s = Serving::start_with(d.clone(), provider.clone()).await;

        let read_pid = propose_the_read(&s);
        approve_and_run(&s, &read_pid);
        assert_eq!(
            state_of(&s.endpoint, "t1"),
            "awaiting-next-step",
            "a verified read must park the task at a boundary"
        );

        // Nothing has been disclosed yet: the read informed nobody.
        assert_eq!(
            provider.disclosures_at(0),
            Vec::new(),
            "the read's own request must carry no content"
        );

        // Continue: one boundary, and the content goes with it.
        let next = send(
            &s.endpoint,
        "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(next["result"]["continued"], true, "{next}");
        assert_eq!(
            next["result"]["step"], 2,
            "the content must inform the *next* step: {next}"
        );

        // The reply names and counts what left, and carries none of it.
        let disclosed = next["result"]["disclosed"].as_array().expect("a list");
        assert_eq!(disclosed.len(), 1, "{next}");
        assert_eq!(disclosed[0]["path"], "a.txt");
        assert_eq!(disclosed[0]["byte_count"], SENTINEL.len() as u64);
        assert!(
            !serde_json::to_string(&next).unwrap().contains(SENTINEL),
            "the reply carried the content: {next}"
        );

        // And the provider really received it, as whole bytes.
        let sent = provider.disclosures_at(1);
        assert_eq!(sent.len(), 1, "the second request must carry the read");
        assert_eq!(sent[0].byte_count, SENTINEL.len());
        assert_eq!(provider.total_disclosed_bytes(), SENTINEL.len());

        // Consumed: a further proposal carries nothing.
        approve_read(
            &s.endpoint,
            next["result"]["proposal"]["proposal_id"].as_str().unwrap(),
            false,
        );
        send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": next["result"]["proposal"]["proposal_id"].as_str().unwrap(), "worker": "w1"}),
        );
        assert_eq!(state_of(&s.endpoint, "t1"), "completed");
        assert_eq!(
            provider.contexts().len(),
            2,
            "no further request was made after the task finished"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// The content reached the provider request and nowhere else in durable state.
///
/// The property that makes an observation distinct from a memory subsystem: after the
/// disclosure, the file's bytes exist in no durable row. Checked by grepping the whole
/// database file rather than one table, because "we did not put it in the obvious column" is
/// not the claim — the claim is that it is not anywhere.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_disclosed_content_appears_in_no_durable_row() {
    rt().block_on(async {
        let d = dir("nodurable");
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[READ_PROPOSAL, WRITE_PROPOSAL],
        ));
        let s = Serving::start_with(d.clone(), provider.clone()).await;

        let read_pid = propose_the_read(&s);
        approve_and_run(&s, &read_pid);
        let next = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(next["result"]["disclosed"][0]["path"], "a.txt", "{next}");
        s.stop().await;

        // Everything durable the daemon wrote, searched for the sentinel.
        for name in ["state.db", "audit.log"] {
            let path = d.join(name);
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            assert!(
                !bytes
                    .windows(SENTINEL.len())
                    .any(|w| w == SENTINEL.as_bytes()),
                "{name} contains the read's content: an observation that is also a durable \
                 row is a memory subsystem, not a disclosure"
            );
        }

        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// The audit record
// ---------------------------------------------------------------------------

/// Every audit record the journal holds, parsed.
fn audit_records(d: &Path) -> Vec<Value> {
    orxnud_store::security_state::SqliteAuditJournal::open(
        &d.join("state.db"),
        &orxnud_platform_fs::OsIdentity,
    )
    .expect("open the journal the daemon wrote")
    .entries()
    .expect("entries")
    .iter()
    .filter_map(|e| serde_json::from_slice::<Value>(&e.payload).ok())
    .collect()
}

/// A disclosure is recorded, on its own correlation, naming the approved read it came from.
///
/// The record has to answer four questions from itself: *what* was disclosed, *where* it went,
/// *how much*, and *which approval authorised it* — with none of them being the content. It
/// also has to be on a correlation of its own, so that it neither closes the read's
/// authorisation nor is closed by it (ADR-0045 D3).
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_disclosure_is_audited_on_its_own_correlation() {
    rt().block_on(async {
        let d = dir("audit");
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[READ_PROPOSAL, WRITE_PROPOSAL],
        ));
        let s = Serving::start_with(d.clone(), provider.clone()).await;
        let read_pid = propose_the_read(&s);
        approve_and_run(&s, &read_pid);
        let next = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(next["result"]["disclosed"][0]["path"], "a.txt", "{next}");
        s.stop().await;

        let records = audit_records(&d);
        let disclosures: Vec<&Value> = records
            .iter()
            .filter(|r| {
                r.get("capability").and_then(Value::as_str) == Some("orxnud.policy/disclose")
            })
            .collect();
        assert_eq!(
            disclosures.len(),
            1,
            "exactly one disclosure must be recorded: {}",
            serde_json::to_string(&records).unwrap()
        );
        let r = disclosures[0];

        // The actor is the human who approved the read, not the model and not the daemon.
        assert_eq!(r["actor"]["kind"], "human", "{r}");
        assert_eq!(r["risk"], "high", "{r}");

        // The bounded detail line answers the linkage question. It sits at
        // `outcome.detail.detail`: `outcome.detail` is the record's own
        // `{kind, at-ms, detail}` envelope, and reaching into it twice is the price of
        // the audit wire shape rather than something this path chooses.
        let detail = r["outcome"]["detail"]["detail"]
            .as_str()
            .unwrap_or_else(|| panic!("{r}"));
        for expected in [
            "parent_proposal=",
            "task=t1",
            "step_no=2",
            "path=a.txt",
            "endpoint=https://provider.test/v1",
            "model=scripted/reader",
            &format!("byte_count={}", SENTINEL.len()),
        ] {
            assert!(
                detail.contains(expected),
                "missing {expected:?} in {detail}"
            );
        }
        // And it names the read's own correlation as its parent.
        assert!(
            detail.contains("parent_read=t1#1"),
            "the disclosure must cite the read it came from: {detail}"
        );

        // Content-free, in the record and in the whole journal.
        let whole = serde_json::to_string(&records).unwrap();
        assert!(
            !whole.contains(SENTINEL),
            "the audit log holds the read's content"
        );
        assert!(
            !whole.contains("ignore previous instructions"),
            "the audit log holds the read's content"
        );

        // A correlation of its own: different from the read's, and neither is left
        // unresolved by the other.
        let disclosure_corr = r["request"].as_str().expect("a correlation");
        assert!(
            disclosure_corr.starts_with("disclosure:"),
            "the disclosure must not ride the read's correlation: {disclosure_corr}"
        );
        assert_ne!(disclosure_corr, "t1#1");

        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A read that is never disclosed leaves no disclosure record.
///
/// The converse, and the one that matters for "the audit must not claim disclosure occurred
/// when it did not". A task that reads and then finishes without a continuation must leave
/// the log describing a read and nothing else.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn no_disclosure_is_recorded_when_nothing_was_disclosed() {
    rt().block_on(async {
        let d = dir("nodisclosure");
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[READ_PROPOSAL],
        ));
        let s = Serving::start_with(d.clone(), provider.clone()).await;
        let read_pid = propose_the_read(&s);
        approve_and_run(&s, &read_pid);
        // Deliberately no continuation: the observation is simply abandoned.
        s.stop().await;

        let records = audit_records(&d);
        assert!(
            !records
                .iter()
                .any(|r| r.get("capability").and_then(Value::as_str)
                    == Some("orxnud.policy/disclose")),
            "a disclosure was recorded although none happened"
        );
        assert_eq!(provider.total_disclosed_bytes(), 0);

        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// The gates
// ---------------------------------------------------------------------------

/// A different provider identity receives nothing.
///
/// Same task, same step, same model *name* — a different endpoint. This is the substitution
/// ADR-0045 Decision 2 exists to refuse, and comparing the model alone would pass it.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_re_pointed_endpoint_receives_nothing() {
    rt().block_on(async {
        let d = dir("repoint");
        seed(&d);
        let reading = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[READ_PROPOSAL],
        ));
        let s = Serving::start_with(d.clone(), reading.clone()).await;
        let read_pid = propose_the_read(&s);
        approve_and_run(&s, &read_pid);
        s.stop().await;

        // The daemon comes back pointed at a different operator. Nothing durable survived the
        // restart either, which is the fail-safe — so this test also proves the two paths
        // independently: the observation is gone because the process is gone, and the identity
        // would have refused it anyway.
        let elsewhere = Arc::new(Recorder::new(
            "scripted/reader",
            "https://evil.example/v1",
            &[WRITE_PROPOSAL],
        ));
        let s2 = Serving::start_with(d.clone(), elsewhere.clone()).await;
        let next = send(
            &s2.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(next["result"]["continued"], true, "{next}");
        assert!(
            next["result"]["disclosed"]
                .as_array()
                .expect("a list")
                .is_empty(),
            "content reached a re-pointed endpoint: {next}"
        );
        assert_eq!(
            elsewhere.total_disclosed_bytes(),
            0,
            "and the provider must have been sent nothing"
        );
        s2.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// The content informs exactly one proposal, and a later one carries none.
///
/// The `(endpoint, model)` half of the identity cannot be exercised through this runtime at
/// all, and the reason is worth stating rather than papering over: a daemon has exactly one
/// configured provider, so within one process the identity never changes, and across a restart
/// the observation is gone anyway — which would make the test pass for the wrong reason. The
/// provider-identity rules are therefore proved where they can fail, on the store, in
/// `observation.rs`: `a_changed_model_on_the_same_endpoint_receives_nothing`,
/// `a_repointed_endpoint_does_not_receive_retained_bytes`, and
/// `a_mismatched_provider_is_refused_even_on_the_right_task_and_step`.
///
/// What *is* expressible here, and what would break if consumption were not enforced at the
/// runtime, is that a second continuation for the same task releases nothing.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn the_content_informs_exactly_one_proposal() {
    rt().block_on(async {
        let d = dir("consumeonce");
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[
                READ_PROPOSAL,
                WRITE_PROPOSAL,
                WRITE_PROPOSAL,
                WRITE_PROPOSAL,
            ],
        ));
        let s = Serving::start_with(d.clone(), provider.clone()).await;
        let read_pid = propose_the_read(&s);
        approve_and_run(&s, &read_pid);

        // The first continuation discloses.
        let first = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(first["result"]["disclosed"][0]["path"], "a.txt", "{first}");
        assert_eq!(
            provider.total_disclosed_bytes(),
            SENTINEL.len(),
            "the read informed exactly one request"
        );

        // The proposal it made is governed like any other.
        let step2 = first["result"]["proposal"]["proposal_id"]
            .as_str()
            .unwrap()
            .to_owned();
        approve_read(&s.endpoint, &step2, false);
        let done = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": step2, "worker": "w1"}),
        );
        assert_eq!(done["result"]["verified"], true, "{done}");
        assert_eq!(state_of(&s.endpoint, "t1"), "completed");

        // Any later request carries nothing. Enumerating every context *after* the disclosing
        // one, rather than a chosen index, so a reordered release would still be caught.
        let contexts = provider.contexts();
        let disclosing: Vec<usize> = contexts
            .iter()
            .enumerate()
            .filter(|(_, c)| c.disclosures.total_bytes() > 0)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            disclosing,
            vec![1],
            "content must be disclosed to exactly one request: {:?}",
            contexts
                .iter()
                .map(|c| c.disclosures.total_bytes())
                .collect::<Vec<_>>()
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A read proposed by a human produces no observation.
///
/// ADR-0045 authorises disclosure to *the provider identity that asked for the read*. A human
/// read has no such identity, so there is nothing the approval could have covered, and the
/// bytes must not migrate towards a provider because a task happened to involve one.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_human_proposed_read_produces_no_observation() {
    rt().block_on(async {
        let d = dir("humanread");
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[WRITE_PROPOSAL],
        ));
        let s = Serving::start_with(d.clone(), provider.clone()).await;

        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "t1", "max_steps": 2, "content": "read a.txt then write final.txt"}),
        );
        send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "t1", "worker": "w1"}),
        );
        // `task/propose` is the human route: the proposer is not an `Actor::Ai`.
        let p = send(
            &s.endpoint,
            "q",
            "task/propose",
            json!({
                "task": "t1", "worker": "w1", "capability": "filesystem/read-text",
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
        approve_and_run(&s, &pid);

        let next = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(next["result"]["continued"], true, "{next}");
        assert!(
            next["result"]["disclosed"]
                .as_array()
                .expect("a list")
                .is_empty(),
            "a human's read reached the provider: {next}"
        );
        assert_eq!(provider.total_disclosed_bytes(), 0);

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A task the provider did not ask the read for receives nothing.
///
/// `take_for` is keyed on the task, so one task's approved read cannot appear in another's
/// prompt even though both are served by the same daemon and the same provider identity.
/// Asserted by driving two tasks through the same provider and checking every request each
/// one made.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_observation_never_crosses_a_task_boundary() {
    rt().block_on(async {
        let d = dir("crosstask");
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[
                READ_PROPOSAL,
                WRITE_PROPOSAL,
                WRITE_PROPOSAL,
                WRITE_PROPOSAL,
                WRITE_PROPOSAL,
            ],
        ));
        let s = Serving::start_with(d.clone(), provider.clone()).await;

        // t1 reads a.txt and parks at a boundary, holding an observation.
        let read_pid = propose_the_read(&s);
        approve_and_run(&s, &read_pid);

        // t2 is created and proposed for, entirely separately. Its prompt must be clean.
        send(
            &s.endpoint,
            "c2",
            "task/create",
            json!({"id": "t2", "max_steps": 2, "content": "write final.txt"}),
        );
        send(
            &s.endpoint,
            "k2",
            "task/claim",
            json!({"id": "t2", "worker": "w2"}),
        );
        let t2_first = send(
            &s.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "t2", "worker": "w2"}),
        );
        assert_eq!(
            t2_first["result"]["disclosed"]
                .as_array()
                .expect("a list")
                .len(),
            0,
            "t2's first prompt carried content: {t2_first}"
        );

        // t1 continues and takes the observation with it.
        let t1_second = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "t1", "worker": "w1"}),
        );
        assert_eq!(
            t1_second["result"]["disclosed"][0]["path"], "a.txt",
            "{t1_second}"
        );

        // t2's next proposal, after t1 has consumed the observation, is also clean. If the
        // store had keyed on the provider alone, or on the daemon, this is where it would show.
        let t2_pid = t2_first["result"]["proposal"]["proposal_id"]
            .as_str()
            .unwrap()
            .to_owned();
        approve_read(&s.endpoint, &t2_pid, false);
        send(
            &s.endpoint,
            "x2",
            "task/execute",
            json!({"proposal": t2_pid, "worker": "w2"}),
        );
        let t2_second = send(
            &s.endpoint,
            "k2b",
            "task/continue",
            json!({"task": "t2", "worker": "w2"}),
        );
        assert_eq!(t2_second["result"]["continued"], true, "{t2_second}");
        assert!(
            t2_second["result"]["disclosed"]
                .as_array()
                .expect("a list")
                .is_empty(),
            "t1's approved read reached t2's prompt: {t2_second}"
        );

        // Enumerated, so a reordering of which request carried it would still be caught.
        let by_task: Vec<(String, usize)> = provider
            .contexts()
            .iter()
            .map(|c| (c.task_id.clone(), c.disclosures.total_bytes()))
            .collect();
        for (task, bytes) in &by_task {
            if task == "t2" {
                assert_eq!(*bytes, 0, "t2 received {bytes} bytes of t1's content");
            }
        }
        assert!(
            by_task
                .iter()
                .any(|(t, b)| t == "t1" && *b == SENTINEL.len()),
            "and t1's own read did reach its own next proposal: {by_task:?}"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A model cannot name an observation, and nothing in the request lets it try.
///
/// The confused-deputy case. The disclosure selection is `(task, step, provider identity)`
/// and nothing else, so a client cannot put an observation id, a path, or a correlation into a
/// request and have content chosen for it. Asserted against the actual request surface: the
/// continuation route reads only `task` and `worker`, and extra parameters are not consulted.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_client_cannot_select_an_observation_by_identifier() {
    rt().block_on(async {
        let d = dir("noselector");
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[READ_PROPOSAL, WRITE_PROPOSAL],
        ));
        let s = Serving::start_with(d.clone(), provider.clone()).await;
        let read_pid = propose_the_read(&s);
        approve_and_run(&s, &read_pid);

        // Every plausible selector a confused deputy might try, in one request.
        let next = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({
                "task": "t1", "worker": "w1",
                "observation_id": "1", "observation": "a.txt", "path": "a.txt",
                "include_content": true, "observations": ["a.txt"],
                "provider": "https://evil.example/v1", "model": "evil/model",
                "step_no": 99, "disclose": true,
            }),
        );
        assert_eq!(next["result"]["continued"], true, "{next}");
        // The selectors changed nothing: the disclosure is still the one the read authorised,
        // made to this provider, for this step. A request that could *choose* content would
        // have shown a different path or a different count here.
        assert_eq!(next["result"]["disclosed"][0]["path"], "a.txt", "{next}");
        assert_eq!(next["result"]["disclosed"].as_array().unwrap().len(), 1);
        assert_eq!(provider.disclosures_at(1)[0].byte_count, SENTINEL.len());
        assert_eq!(
            provider.disclosures_at(1)[0].path,
            "a.txt",
            "the provider must be told about the path the read approved, nothing else"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Two continuations racing over one observation: exactly one discloses it.
///
/// The store's consumption is under the same mutex the release takes, and the runtime serves
/// one connection at a time, so this is not a race the production path can lose — which is the
/// point of asserting it end to end rather than only on the store.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
             Unix domain socket, and the local IPC transport refuses on Windows \
             rather than binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn only_one_continuation_can_disclose_a_claim_of_the_boundary() {
    rt().block_on(async {
        let d = dir("race");
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[
                READ_PROPOSAL,
                WRITE_PROPOSAL,
                WRITE_PROPOSAL,
                WRITE_PROPOSAL,
            ],
        ));
        let s = Serving::start_with(d.clone(), provider.clone()).await;
        let read_pid = propose_the_read(&s);
        approve_and_run(&s, &read_pid);

        let endpoint = s.endpoint.clone();
        let a = std::thread::spawn(move || {
            send(
                &endpoint,
                "ka",
                "task/continue",
                json!({"task": "t1", "worker": "w1"}),
            )
        });
        let endpoint = s.endpoint.clone();
        let b = std::thread::spawn(move || {
            send(
                &endpoint,
                "kb",
                "task/continue",
                json!({"task": "t1", "worker": "w2"}),
            )
        });
        let ra = a.join().expect("thread a");
        let rb = b.join().expect("thread b");

        let disclosed: usize = [&ra, &rb]
            .iter()
            .map(|r| r["result"]["disclosed"].as_array().map_or(0, |a| a.len()))
            .sum();
        assert_eq!(
            disclosed, 1,
            "the same bytes must not inform two proposals: {ra} {rb}"
        );
        assert_eq!(
            provider.total_disclosed_bytes(),
            SENTINEL.len(),
            "and the provider must have seen them exactly once"
        );

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// The reviewed approval path for a read.
///
/// A fresh preview, which issues a challenge, and then an approval bound to that
/// challenge and explicitly acknowledging the disclosure. The daemon refuses an AI read
/// approval without both, so this is the only way the successful pipeline is reachable.
fn approve_read(endpoint: &Path, pid: &str, expect_challenge: bool) {
    let preview = send(
        endpoint,
        "p",
        "capability/preview",
        json!({ "proposal": pid }),
    );
    // A challenge is issued only for an **AI-generated file read** -- the one case the
    // reviewed path governs. A human-proposed read and a write are not covered by the
    // preview, and are approved on the ordinary route.
    // The preview answers for an AI-generated file read. A human proposal and a
    // write are not covered by it, and the daemon refuses the preview for them.
    let covered = preview
        .get("result")
        .and_then(|r| r.get("preview"))
        .is_some();
    let challenge = preview["result"]["preview"]["challenge"]
        .as_str()
        .map(str::to_owned);
    // A challenge is issued only for a **model-initiated** read, which is exactly the
    // proposal the preview reports as requiring a disclosure confirmation. A
    // human-delegated read carries no provider disclosure, so it is not part of the
    // reviewed path and is approved on the ordinary route.
    let approvable = preview["result"]["preview"]["requires_confirmation"] == true;
    if expect_challenge && covered && approvable {
        assert!(
            challenge.is_some(),
            "an eligible AI read preview must issue a challenge, so the read can be \
             approved through the reviewed path: {preview}"
        );
    }
    match challenge {
        Some(challenge) => {
            send(
                endpoint,
                "a",
                "capability/approve",
                json!({
                    "proposal": pid,
                    "ttl_ms": 60_000,
                    "challenge": challenge,
                    "confirmed": true,
                }),
            );
        }
        None => {
            send(
                endpoint,
                "a",
                "capability/approve",
                json!({ "proposal": pid, "ttl_ms": 60_000 }),
            );
        }
    }
}

/// The challenge-enforced approval path, checked against **persisted** state.
///
/// The disclosure suite above proves the *successful* route. These prove the *refused*
/// ones: that a rejected or replayed attempt creates no approval row and does not
/// decide the proposal. A returned error alone would not be evidence of that.
mod challenge_enforcement {
    use super::*;

    /// The daemon's state database, wherever it lives under the state root.
    fn state_db(root: &Path) -> PathBuf {
        let mut found: Vec<PathBuf> = Vec::new();
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "db") {
                    out.push(p);
                }
            }
        }
        walk(root, &mut found);
        found
            .into_iter()
            .find(|p| p.file_name().is_some_and(|n| n == "state.db"))
            .expect("the daemon must have a state database")
    }

    /// The persisted proposal: its task and its status.
    fn proposal_state(root: &Path, pid: &str) -> (String, String) {
        let db = state_db(root);
        let conn = rusqlite::Connection::open(&db).expect("open the state database");
        conn.query_row(
            "SELECT task_id, status FROM task_proposals WHERE proposal_id = ?1",
            [pid],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .unwrap_or_else(|e| panic!("the proposal {pid:?} must be persisted: {e}"))
    }

    /// How many approvals are persisted for a task.
    fn approvals_for_task(root: &Path, task_id: &str) -> i64 {
        let db = state_db(root);
        let conn = rusqlite::Connection::open(&db).expect("open the state database");
        conn.query_row(
            "SELECT COUNT(*) FROM task_approvals WHERE task_id = ?1",
            [task_id],
            |r| r.get(0),
        )
        .unwrap_or(0)
    }

    /// A fresh challenge for the proposal, or `None` when the preview is blocked.
    fn challenge_for(endpoint: &Path, pid: &str) -> Option<String> {
        let preview = send(
            endpoint,
            "p",
            "capability/preview",
            json!({ "proposal": pid }),
        );
        preview["result"]["preview"]["challenge"]
            .as_str()
            .map(str::to_owned)
    }

    /// The daemon serving a synthetic provider, with a read proposal already made.
    async fn serving_with_read(tag: &str) -> (Serving, PathBuf, String) {
        let d = dir(tag);
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[READ_PROPOSAL],
        ));
        let s = Serving::start_with(d.clone(), provider.clone()).await;
        let pid = propose_the_read(&s);
        (s, d, pid)
    }

    /// A model-initiated read cannot be approved without a challenge.
    #[test]
    fn an_ai_read_without_a_challenge_is_refused_and_leaves_the_proposal_pending() {
        rt().block_on(async {
            let (s, root, pid) = serving_with_read("nochallenge").await;
            let reply = send(
                &s.endpoint,
                "a",
                "capability/approve",
                json!({ "proposal": pid, "ttl_ms": 60_000 }),
            );
            assert!(
                reply.get("error").is_some(),
                "an AI read approval without a challenge must be refused: {reply}"
            );
            let (task_id, status) = proposal_state(&root, &pid);
            assert_eq!(status, "pending", "the proposal must not be decided");
            assert_eq!(
                approvals_for_task(&root, &task_id),
                0,
                "no approval may be created"
            );
        });
    }

    /// A challenge with the confirmation missing or false is refused, and the attempt
    /// consumes the challenge: a later attempt with the same challenge cannot succeed.
    #[test]
    fn a_challenge_without_an_affirmative_confirmation_is_refused_and_is_consumed() {
        rt().block_on(async {
            for (label, extra) in [("missing", serde_json::json!({})), ("false", json!({"confirmed": false}))] {
                let (s, root, pid) = serving_with_read(&format!("noconfirm-{label}")).await;
                let challenge = challenge_for(&s.endpoint, &pid).expect("an eligible preview issues a challenge");
                let mut params = json!({ "proposal": pid, "ttl_ms": 60_000, "challenge": challenge });
                for (k, v) in extra.as_object().expect("an object") {
                    params[k] = v.clone();
                }
                let reply = send(&s.endpoint, "a", "capability/approve", params);
                assert!(reply.get("error").is_some(), "the {label} confirmation must be refused: {reply}");
                let (task_id, status) = proposal_state(&root, &pid);
                assert_eq!(status, "pending", "the proposal must not be decided");
                assert_eq!(approvals_for_task(&root, &task_id), 0, "no approval may be created");

                // The failed attempt consumed the challenge, so the same challenge
                // cannot now be redeemed.
                let again = send(
                    &s.endpoint,
                    "a",
                    "capability/approve",
                    json!({ "proposal": pid, "ttl_ms": 60_000, "challenge": challenge, "confirmed": true }),
                );
                assert!(again.get("error").is_some(), "a consumed challenge must not be reusable: {again}");
                let (_, status) = proposal_state(&root, &pid);
                assert_eq!(status, "pending", "the proposal must still be pending");
                assert_eq!(approvals_for_task(&root, &task_id), 0, "still no approval");
            }
        });
    }

    /// A valid challenge with an affirmative confirmation creates exactly one approval,
    /// and replaying it creates no second one.
    #[test]
    fn a_confirmed_challenge_creates_one_approval_and_cannot_be_replayed() {
        rt().block_on(async {
            let (s, root, pid) = serving_with_read("confirmed").await;
            let challenge = challenge_for(&s.endpoint, &pid).expect("an eligible preview issues a challenge");
            let reply = send(
                &s.endpoint,
                "a",
                "capability/approve",
                json!({ "proposal": pid, "ttl_ms": 60_000, "challenge": challenge, "confirmed": true }),
            );
            assert!(reply.get("result").is_some(), "the confirmed approval must succeed: {reply}");
            let (task_id, status) = proposal_state(&root, &pid);
            assert_ne!(status, "pending", "the proposal must be decided");
            assert_eq!(approvals_for_task(&root, &task_id), 1, "exactly one approval");

            // The replay must not create a second approval.
            let replay = send(
                &s.endpoint,
                "a",
                "capability/approve",
                json!({ "proposal": pid, "ttl_ms": 60_000, "challenge": challenge, "confirmed": true }),
            );
            assert!(replay.get("error").is_some(), "a replay must be refused: {replay}");
            let (_, status_after) = proposal_state(&root, &pid);
            assert_eq!(status_after, status, "the replay must not change the proposal");
            assert_eq!(approvals_for_task(&root, &task_id), 1, "still exactly one approval");
        });
    }

    /// A challenge issued for one proposal cannot approve another: the binding is
    /// checked, and the attempt leaves the other proposal untouched.
    #[test]
    fn a_challenge_for_another_proposal_fails_closed() {
        rt().block_on(async {
            let (s, _root_a, first) = serving_with_read("bindmis-a").await;
            let challenge = challenge_for(&s.endpoint, &first).expect("an eligible preview issues a challenge");

            // A second, independent proposal on the same daemon.
            let d2 = dir("bindmis-b");
            seed(&d2);
            let provider = Arc::new(Recorder::new(
                "scripted/reader",
                "https://provider.test/v1",
                &[READ_PROPOSAL],
            ));
            let s2 = Serving::start_with(d2.clone(), provider).await;
            let other = propose_the_read(&s2);

            let reply = send(
                &s2.endpoint,
                "a",
                "capability/approve",
                json!({ "proposal": other, "ttl_ms": 60_000, "challenge": challenge, "confirmed": true }),
            );
            assert!(reply.get("error").is_some(), "a foreign challenge must be refused: {reply}");
            let (task_id, status) = proposal_state(&d2, &other);
            assert_eq!(status, "pending", "the other proposal must not be decided");
            assert_eq!(approvals_for_task(&d2, &task_id), 0, "no approval may be created");
        });
    }

    /// A change of provider endpoint or model invalidates a challenge: the destination
    /// fingerprint is part of the binding.
    #[test]
    fn a_changed_provider_destination_invalidates_the_challenge() {
        rt().block_on(async {
            let (s, _root, pid) = serving_with_read("drift").await;
            let challenge = challenge_for(&s.endpoint, &pid).expect("an eligible preview issues a challenge");

            // A daemon whose provider has a different endpoint and model.
            let d2 = dir("drift-2");
            seed(&d2);
            let provider = Arc::new(Recorder::new(
                "scripted/other",
                "https://other.test/v1",
                &[READ_PROPOSAL],
            ));
            let s2 = Serving::start_with(d2.clone(), provider).await;

            // The same proposal id, presented to a daemon with a different destination.
            let reply = send(
                &s2.endpoint,
                "a",
                "capability/approve",
                json!({ "proposal": pid, "ttl_ms": 60_000, "challenge": challenge, "confirmed": true }),
            );
            assert!(reply.get("error").is_some(), "a drifted destination must be refused: {reply}");
        });
    }
}

/// An inspection request classifies the proposal without minting a challenge.
///
/// A client that only wants to look -- to decide whether it needs an interactive
/// confirmation -- must not take a challenge it might abandon. The inspection
/// response carries the same authoritative classification and the same safe
/// information; only the challenge is absent.
#[test]
fn an_inspection_request_classifies_the_proposal_without_taking_a_challenge() {
    rt().block_on(async {
        let d = dir("inspect");
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[READ_PROPOSAL],
        ));
        let s = Serving::start_with(d.clone(), provider).await;
        let pid = propose_the_read(&s);

        let inspected = send(
            &s.endpoint,
            "p",
            "capability/preview",
            json!({ "proposal": pid, "inspect_only": true }),
        );
        let preview = &inspected["result"]["preview"];
        assert_eq!(preview["proposal_kind"], "model-initiated-file-read");
        assert_eq!(preview["requires_confirmation"], true);
        assert_eq!(preview["approval_allowed"], true);
        assert!(
            preview["challenge"].is_null(),
            "an inspection must not take a challenge: {inspected}"
        );

        // The ordinary preview still does, so inspection is a mode and not a
        // different contract.
        let ordinary = send(
            &s.endpoint,
            "p",
            "capability/preview",
            json!({ "proposal": pid }),
        );
        assert!(
            ordinary["result"]["preview"]["challenge"].is_string(),
            "an ordinary preview must still take a challenge: {ordinary}"
        );
    });
}

/// The dispatch boundary: a read needs **both** a policy-valid approval **and** a
/// daemon-side authorisation.
#[cfg(test)]
mod read_dispatch_authorization {
    use super::*;
    use std::sync::Arc;

    /// A provider that answers with the read proposal.
    fn reader(tag: &str) -> (PathBuf, Arc<Recorder>) {
        let d = dir(tag);
        seed(&d);
        let provider = Arc::new(Recorder::new(
            "scripted/reader",
            "https://provider.test/v1",
            &[READ_PROPOSAL],
        ));
        (d, provider)
    }

    /// Approves a read through the reviewed path, and returns the daemon's approval
    /// record and the proposal id.
    async fn approve_a_read(s: &Serving) -> (String, Value) {
        let pid = propose_the_read(s);
        let preview = send(
            &s.endpoint,
            "p",
            "capability/preview",
            json!({ "proposal": pid }),
        );
        let challenge = preview["result"]["preview"]["challenge"]
            .as_str()
            .expect("an eligible read must be given a challenge")
            .to_owned();
        let approved = send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({
                "proposal": pid,
                "ttl_ms": 60_000,
                "challenge": challenge,
                "confirmed": true,
            }),
        );
        assert!(
            approved["result"]["approval"].is_object(),
            "the approval must have been issued: {approved}"
        );
        (pid, approved["result"]["approval"].clone())
    }

    /// A dispatch request built entirely from the daemon's own approval record, so
    /// every field the digest covers is the daemon's.
    fn dispatch_request(approval: &Value) -> Value {
        // The approval's `params` is the *canonical string*; the digest covers the
        // parsed parameters, so the request has to carry the object back, not the
        // string. Passing the string through would produce an action whose parameters
        // are not the ones that were approved.
        let params: Value = serde_json::from_str(
            approval["params"]
                .as_str()
                .expect("the approval carries its params"),
        )
        .expect("the approval's params must be canonical JSON");
        json!({
            "capability": approval["capability"],
            "params": params,
            "target": approval["target"],
            // The step the approval was issued for: the digest was computed over it.
            "step": approval["step_no"],
            "approval": approval,
        })
    }

    /// A digest-valid approval that this daemon never authorised must not dispatch a
    /// read.
    ///
    /// The tuple is entirely genuine: the daemon issued it, for the right approver, the
    /// right action and the right step, and the policy's digest recomputation accepts
    /// it. What it lacks is the *daemon-side* authorisation -- the registry entry that
    /// `approve_proposal` creates for a read. It is presented to a **different daemon**,
    /// whose registry has never seen it, which is exactly the shape of a tuple obtained
    /// by a route that is no longer permitted.
    #[test]
    fn a_digest_valid_but_unregistered_approval_does_not_dispatch_a_read() {
        rt().block_on(async {
            let (d1, provider1) = reader("dispatch-a");
            let s1 = Serving::start_with(d1, provider1).await;
            let (_pid, approval) = approve_a_read(&s1).await;

            // A second daemon, with its own registry, which never authorised this.
            let (d2, provider2) = reader("dispatch-b");
            let s2 = Serving::start_with(d2, provider2).await;

            let reply = send(
                &s2.endpoint,
                "x",
                "capability/dispatch",
                dispatch_request(&approval),
            );
            assert!(
                reply.get("error").is_some(),
                "an unregistered read approval must be refused: {reply}"
            );
            let detail = reply["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            assert!(
                detail.contains("read-not-authorized") || detail.contains("read"),
                "the refusal must name the read authorisation: {reply}"
            );
        });
    }

    /// A genuine approval from a **previous runtime** cannot execute after a restart.
    ///
    /// The registry is deliberately ephemeral: a restart empties it, so an approval that
    /// was registered before the restart cannot authorise a read afterwards. The tuple
    /// itself is genuine -- issued by a daemon, for the right approver, action and step
    /// -- and the policy's own digest and expiry checks are untouched; what refuses it is
    /// the absent authorisation.
    #[test]
    fn an_approval_from_before_a_restart_cannot_execute_after_it() {
        rt().block_on(async {
            let (d1, provider1) = reader("restart-a");
            let s1 = Serving::start_with(d1, provider1).await;
            let (_pid, approval) = approve_a_read(&s1).await;

            // A fresh runtime: a new daemon, with a new -- therefore empty -- registry.
            let (d2, provider2) = reader("restart-b");
            let s2 = Serving::start_with(d2, provider2).await;

            let reply = send(
                &s2.endpoint,
                "x",
                "capability/dispatch",
                dispatch_request(&approval),
            );
            assert!(
                reply.get("error").is_some(),
                "an approval from before a restart must not execute: {reply}"
            );
            let reason = reply["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default();
            assert_eq!(
                reason, "read-not-authorized",
                "the refusal must be the missing authorisation: {reply}"
            );
            // No contents, and no observation, could have been produced.
            assert!(
                !reply.to_string().contains("contents"),
                "no file contents may be returned: {reply}"
            );
        });
    }

    /// One registered authorisation is claimed by exactly one dispatch.
    ///
    /// The route that actually executes a read is `task/execute`, which recomposes the
    /// approval from the durable row rather than trusting a client-supplied tuple. Two
    /// concurrent executions of the same proposal therefore race for the same
    /// authorisation, and exactly one may win.
    ///
    /// The daemon serialises requests under the governed mutex, so the two requests are
    /// serialised in practice; a `Barrier` is used so they start together. What this
    /// proves is the end-to-end single-use invariant, not a lock-free claim.
    #[test]
    fn one_registered_read_authorisation_is_claimed_by_exactly_one_dispatch() {
        rt().block_on(async {
            let (d, provider) = reader("dispatch-once");
            let s = Serving::start_with(d, provider).await;
            let (pid, _approval) = approve_a_read(&s).await;

            let barrier = Arc::new(std::sync::Barrier::new(2));
            let handles: Vec<_> = (0..2)
                .map(|i| {
                    let endpoint = s.endpoint.clone();
                    let pid = pid.clone();
                    let barrier = barrier.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        send(
                            &endpoint,
                            &format!("x{i}"),
                            "task/execute",
                            json!({ "proposal": pid, "worker": "w1" }),
                        )
                    })
                })
                .collect();
            let replies: Vec<Value> = handles
                .into_iter()
                .map(|h| h.join().expect("the request thread must not panic"))
                .collect();

            let succeeded = replies
                .iter()
                .filter(|r| r.get("result").is_some() && r["result"]["verified"] == true)
                .count();
            let refused = replies.iter().filter(|r| r.get("error").is_some()).count();
            assert_eq!(
                succeeded, 1,
                "exactly one dispatch may execute the read: {replies:?}"
            );
            assert_eq!(
                refused, 1,
                "the other dispatch must be refused: {replies:?}"
            );

            // The same proposal cannot be executed again: the authorisation and the
            // approval are both spent.
            let again = send(
                &s.endpoint,
                "x",
                "task/execute",
                json!({ "proposal": pid, "worker": "w1" }),
            );
            assert!(
                again.get("error").is_some(),
                "a spent read authorisation must not execute again: {again}"
            );
        });
    }
}
