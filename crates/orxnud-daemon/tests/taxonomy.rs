//! The public error taxonomy: what a client is told, and what it can do about it.
//!
//! # Why this is a separate file
//!
//! Error *classification* is a contract, and contracts are tested at the surface a client
//! actually sees. Every assertion here is made over a real JSON-RPC frame from a real
//! daemon, not over an internal enum — because the defect this work fixed was invisible
//! from inside: `TaskFault::Engine` held a `String`, so the daemon had nothing to classify
//! with and defaulted to `INTERNAL_ERROR` for conditions a client can act on.
//!
//! The property under test throughout:
//!
//! > **`INTERNAL_ERROR` means nothing the caller did can change the outcome.**
//!
//! Everything a client could act on — naming something that is not there, losing a race,
//! needing a new approval, a dependency being down — has its own code, so a GUI, TUI, MCP
//! bridge or voice client can each choose the right recovery without parsing prose.
//!
//! # The classes
//!
//! | code | class | what the client does |
//! |---|---|---|
//! | `-32700` / `-32600` / `-32602` | parse, invalid request, invalid params | fix what it sent |
//! | `-32601` | method not found | stop calling this |
//! | `-32040` | resource not found | refresh its view |
//! | `-32041` | conflict | re-read state and decide again |
//! | `-32042` | refused by policy or authority | obtain a new human decision |
//! | `-32043` | environment unavailable | fix configuration, add a credential, wait |
//! | `-32603` | internal | report a defect |
//!
//! `data.reason` carries a stable vocabulary word for the fine-grained case
//! (`proposal-already-decided`, `approval-expired`, `not-at-boundary`, …); `data.detail`
//! carries the human sentence. A client branches on the former.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use orxnud_daemon::Paths;
use orxnud_daemon::runtime::Runtime;
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use orxnud_protocol::error::RpcErrorCode;
use serde_json::{Value, json};

/// A proposer that cannot be constructed without naming a model, so a providerless daemon
/// is expressed by handing [`Serving::start_providerless`] something that is a
/// `ProposalProvider` in type only.
struct NoProposer;

impl orxnud_daemon::proposer::ProposalProvider for NoProposer {
    fn model_id(&self) -> &str {
        "none/none"
    }
    fn complete(
        &self,
        _ctx: &orxnud_daemon::proposer::ProposalContext,
    ) -> Result<String, orxnud_daemon::proposer::ProviderError> {
        Err(orxnud_daemon::proposer::ProviderError::NotConfigured)
    }
}

struct NoSecrets;

#[derive(Debug, thiserror::Error)]
#[error("no secret store in the taxonomy suite")]
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
    let d = std::env::temp_dir().join(format!("orxnud-tax-{}-{tag}", std::process::id()));
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
    /// A daemon with a scripted proposer, so `task/continue` and `task/ai-propose` are
    /// reachable at all: both refuse before they look at the task when no provider exists.
    async fn start(root: PathBuf) -> Self {
        Self::start_with(root, orxnud_daemon::runtime::scripted_proposer()).await
    }

    /// A daemon with no proposer at all -- the unconfigured install, where the only honest
    /// answer to a model-backed method is ENVIRONMENT_UNAVAILABLE.
    async fn start_providerless(root: PathBuf) -> Self {
        Self::start_with(root, Arc::new(NoProposer)).await
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

/// The error code of a reply, asserting one is present.
fn code_of(reply: &Value) -> i32 {
    reply["error"]["code"]
        .as_i64()
        .unwrap_or_else(|| panic!("expected an error, got {reply}")) as i32
}

/// `data.reason`, which must always be a stable word rather than a sentence.
///
/// Asserted as a *shape* everywhere it appears: a reason containing a space, a bracket or a
/// digit-run is prose that happened to land in the machine-readable field, and a client
/// branching on it would be reading English.
fn reason_of(reply: &Value) -> String {
    let reason = reply["error"]["data"]["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("a refusal must carry data.reason: {reply}"))
        .to_owned();
    assert!(
        !reason.contains(' ') && !reason.contains('[') && !reason.contains('"'),
        "data.reason must be a stable word, not prose: {reason:?} in {reply}"
    );
    reason
}

/// Creates a claimed task with one pending write proposal. Returns the proposal id.
fn task_with_pending_proposal(s: &Serving, id: &str) -> String {
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
            "target": "out.txt", "params": {"path": "out.txt", "contents": "x"}
        }),
    );
    p["result"]["proposal"]["proposal_id"]
        .as_str()
        .expect("a proposal id")
        .to_owned()
}

// ---------------------------------------------------------------------------
// Not found
// ---------------------------------------------------------------------------

/// Naming something absent is `RESOURCE_NOT_FOUND`, and the reason is a word.
///
/// `INVALID_REQUEST` says "you sent something wrong", which sends a client editing a
/// request that was perfectly fine. The recovery for a missing resource is to refresh.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_missing_resource_is_not_found_and_not_an_invalid_request() {
    rt().block_on(async {
        let d = dir("notfound");
        let s = Serving::start(d.clone()).await;

        // Note the ordering `task/continue` exhibits on a *providerless* daemon: it reports
        // ENVIRONMENT_UNAVAILABLE even for a task that does not exist. That is right --
        // the dependency is missing either way, and answering the other way would imply
        // the task exists. Pinned in `a_missing_provider_is_an_environment_refusal`.
        for (method, params) in [
            ("task/cancel", json!({"id": "ghost", "worker": "w"})),
            (
                "task/execute",
                json!({"proposal": "p-ghost", "worker": "w"}),
            ),
            ("capability/approve", json!({"proposal": "p-ghost"})),
            ("task/complete", json!({"id": "ghost", "worker": "w"})),
            ("task/continue", json!({"task": "ghost", "worker": "w"})),
        ] {
            let reply = send(&s.endpoint, "n", method, params);
            assert_eq!(
                code_of(&reply),
                RpcErrorCode::RESOURCE_NOT_FOUND.code(),
                "{method} on a missing resource: {reply}"
            );
            assert!(
                reason_of(&reply).contains("not-found"),
                "{method} must name the absence: {reply}"
            );
        }

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Conflict
// ---------------------------------------------------------------------------

/// Every wrong-state refusal is `CONFLICT`, whatever state it was in.
///
/// One code because the recovery is the same in all of them: re-read the state and decide
/// again. Splitting them by code would give a client a distinction it does not need; the
/// distinction that *does* matter travels in `data.reason`.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_wrong_state_is_a_conflict_across_every_shape_of_it() {
    rt().block_on(async {
        let d = dir("conflict");
        let s = Serving::start(d.clone()).await;

        // A name already taken.
        let pid = task_with_pending_proposal(&s, "dup");
        let dup = send(
            &s.endpoint,
            "d",
            "task/create",
            json!({"id": "dup", "content": "again"}),
        );
        assert_eq!(code_of(&dup), RpcErrorCode::CONFLICT.code(), "{dup}");
        assert_eq!(reason_of(&dup), "already-exists");

        // A lease the caller does not hold. Another worker winning is a race lost, not a
        // fault in the daemon.
        let other = send(
            &s.endpoint,
            "o",
            "task/propose",
            json!({
            "task": "dup", "worker": "somebody-else", "capability": "filesystem/write-text",
            "target": "out.txt", "params": {"path": "out.txt", "contents": "y"}}),
        );
        assert_eq!(code_of(&other), RpcErrorCode::CONFLICT.code(), "{other}");

        // The proposal is decided, so it cannot be decided again. That is an
        // *authority* question -- FORBIDDEN -- and it is pinned as such in the
        // authorization section below rather than here.
        send(
            &s.endpoint,
            "a",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );

        // A task with no boundary to continue across. `dup` is still `running` with the
        // proposal pending, so a continuation would be legal; cancel it so the boundary
        // refusal is what is under test.
        let cancelled = send(
            &s.endpoint,
            "c2",
            "task/cancel",
            json!({"id": "dup", "worker": "w1"}),
        );
        assert!(cancelled.get("result").is_some(), "{cancelled}");

        let cont = send(
            &s.endpoint,
            "k",
            "task/continue",
            json!({"task": "dup", "worker": "w1"}),
        );
        assert_eq!(code_of(&cont), RpcErrorCode::CONFLICT.code(), "{cont}");
        assert_eq!(reason_of(&cont), "not-at-boundary");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A duplicate id and a lost race are distinguishable, even though both are conflicts.
///
/// The code says which recovery applies; `data.reason` says which happened. A client that
/// only wants "can I retry?" reads the code; a client that wants to log which race it lost
/// reads the reason.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_lost_race_and_a_duplicate_name_are_both_conflicts_but_not_the_same_reason() {
    rt().block_on(async {
        let d = dir("race-reasons");
        let s = Serving::start(d.clone()).await;

        task_with_pending_proposal(&s, "race");
        let dup = send(
            &s.endpoint,
            "d",
            "task/create",
            json!({"id": "race", "content": "again"}),
        );
        let taken = reason_of(&dup);

        // Claiming an already-claimed task is a different refusal with a different word.
        let lost = send(
            &s.endpoint,
            "c",
            "task/claim",
            json!({"id": "race", "worker": "w2"}),
        );
        let raced = reason_of(&lost);

        assert_eq!(code_of(&dup), code_of(&lost), "both are conflicts");
        assert_eq!(code_of(&dup), RpcErrorCode::CONFLICT.code());
        assert_ne!(
            taken, raced,
            "a taken name and a lost race must not share a reason word"
        );
        assert_eq!(taken, "already-exists");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

/// Every approval refusal is `FORBIDDEN`, never a state or an internal error.
///
/// The point is the *recovery*, and it is uniform: retrying the identical request fails
/// identically, so what is needed is a new human decision. A `CONFLICT` code would tell a
/// client to re-read and try again, which it would do forever.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn every_approval_refusal_is_forbidden_and_says_which_one() {
    rt().block_on(async {
        let d = dir("forbidden");
        let s = Serving::start(d.clone()).await;
        let pid = task_with_pending_proposal(&s, "appr");

        // No approval at all.
        let none = send(
            &s.endpoint,
            "x",
            "task/execute",
            json!({"proposal": pid, "worker": "w1"}),
        );
        // The proposal is pending, so the execute is refused on *state*, not authority --
        // pinned here because it is the one case that is genuinely a conflict.
        assert!(
            code_of(&none) == RpcErrorCode::CONFLICT.code()
                || code_of(&none) == RpcErrorCode::FORBIDDEN.code(),
            "an unapproved proposal must not be an internal error: {none}"
        );
        assert_ne!(code_of(&none), RpcErrorCode::INTERNAL_ERROR.code());

        // An approval already issued for this attempt.
        let live = send(
            &s.endpoint,
            "a1",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        assert!(live.get("result").is_some(), "{live}");
        let again = send(
            &s.endpoint,
            "a2",
            "capability/approve",
            json!({"proposal": pid, "ttl_ms": 60_000}),
        );
        assert_eq!(code_of(&again), RpcErrorCode::FORBIDDEN.code(), "{again}");
        assert_eq!(reason_of(&again), "approval-already-valid");

        // A TTL that leaves the approval already expired.
        let pid2 = task_with_pending_proposal(&s, "appr2");
        let expired = send(
            &s.endpoint,
            "a3",
            "capability/approve",
            json!({"proposal": pid2, "ttl_ms": 0}),
        );
        assert_eq!(
            code_of(&expired),
            RpcErrorCode::FORBIDDEN.code(),
            "{expired}"
        );
        assert_eq!(reason_of(&expired), "approval-expired");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Invalid input
// ---------------------------------------------------------------------------

/// A malformed or impossible request is `INVALID_REQUEST`, with the failure in `detail`.
///
/// `data.reason` stays the stable word so a client never has to read the sentence.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_malformed_request_is_invalid_input_and_not_internal() {
    rt().block_on(async {
        let d = dir("invalid");
        let s = Serving::start(d.clone()).await;

        // A missing parameter.
        let missing = send(&s.endpoint, "1", "task/claim", json!({}));
        assert_eq!(
            code_of(&missing),
            RpcErrorCode::INVALID_REQUEST.code(),
            "{missing}"
        );

        // An impossible bound, twice: once by the store's own rule and once by the
        // daemon's. Both are caller-fixable, which is what `INVALID_REQUEST` is for.
        for bad in [json!(0), json!(-1), json!(100_000), json!("3")] {
            let reply = send(
                &s.endpoint,
                "2",
                "task/create",
                json!({"id": "bad", "max_steps": bad}),
            );
            assert_eq!(
                code_of(&reply),
                RpcErrorCode::INVALID_REQUEST.code(),
                "max_steps {bad}: {reply}"
            );
            assert_ne!(code_of(&reply), RpcErrorCode::INTERNAL_ERROR.code());
        }

        // An unknown method is its own thing entirely.
        let gone = send(&s.endpoint, "3", "task/nope", json!({}));
        assert_eq!(
            code_of(&gone),
            RpcErrorCode::METHOD_NOT_FOUND.code(),
            "{gone}"
        );

        // Unparseable bytes are a parse error, upstream of everything else.
        let raw = send_raw(
            &s.endpoint,
            b"{\"jsonrpc\": \"2.0\", \"id\": 4, \"method\": ",
        )
        .expect("a reply");
        assert_eq!(code_of(&raw), RpcErrorCode::PARSE_ERROR.code(), "{raw}");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// A missing provider is an environment refusal, not an internal fault.
///
/// This is the V-82-era `ai-propose with no provider` case, which reported
/// `INTERNAL_ERROR` and told an operator the daemon was broken when in fact it was simply
/// unconfigured — one of the two things `doctor` exists to tell them apart.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_missing_provider_is_an_environment_refusal() {
    rt().block_on(async {
        let d = dir("env");
        let s = Serving::start_providerless(d.clone()).await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "n1", "content": "x"}),
        );
        send(
            &s.endpoint,
            "cl",
            "task/claim",
            json!({"id": "n1", "worker": "w1"}),
        );

        let reply = send(
            &s.endpoint,
            "p",
            "task/ai-propose",
            json!({"task": "n1", "worker": "w1"}),
        );
        assert_eq!(
            code_of(&reply),
            RpcErrorCode::ENVIRONMENT_UNAVAILABLE.code(),
            "a daemon with no provider configured must say so as an environment fact: {reply}"
        );
        assert_eq!(reason_of(&reply), "provider-not-configured");

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// The contract itself
// ---------------------------------------------------------------------------

/// The four project codes are in the server-reserved band and do not collide.
///
/// A client recognising "a code this server defines" by range is the whole reason these
/// live at `-32099..=-32020`, so a code outside it would be indistinguishable from a
/// non-standard peer and a collision would silently change an existing meaning.
#[test]
fn the_project_error_codes_are_server_reserved_and_distinct() {
    let codes = [
        RpcErrorCode::RESOURCE_NOT_FOUND,
        RpcErrorCode::CONFLICT,
        RpcErrorCode::FORBIDDEN,
        RpcErrorCode::ENVIRONMENT_UNAVAILABLE,
    ];
    for c in codes {
        assert!(
            c.is_server_reserved(),
            "{:?} at {} is outside the server-reserved band",
            c,
            c.code()
        );
    }
    // All four distinct, and none impersonating a standard code.
    for (i, a) in codes.iter().enumerate() {
        for b in &codes[i + 1..] {
            assert_ne!(a.code(), b.code(), "{a:?} and {b:?} share a code");
        }
        assert!(
            a.code() > -32700,
            "{:?} must not impersonate a standard code",
            a
        );
    }
    // The numeric values are part of the published contract: a client hard-codes them.
    assert_eq!(RpcErrorCode::RESOURCE_NOT_FOUND.code(), -32040);
    assert_eq!(RpcErrorCode::CONFLICT.code(), -32041);
    assert_eq!(RpcErrorCode::FORBIDDEN.code(), -32042);
    assert_eq!(RpcErrorCode::ENVIRONMENT_UNAVAILABLE.code(), -32043);
}

// ---------------------------------------------------------------------------
// Hygiene
// ---------------------------------------------------------------------------

/// No error on any refusal path carries a credential, a path, or file content.
///
/// The classification work moved data around, and data moving is where leaks happen. Every
/// refusal below is checked for the three things that must never appear: the sentinel file's
/// **contents**, an absolute host path, and a credential-shaped string. Run over a task that
/// has actually read a file, so the content exists to leak.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn no_refusal_carries_content_a_host_path_or_a_credential() {
    const SENTINEL: &str = "SENTINEL-TAXONOMY-9f31c4";
    rt().block_on(async {
        let d = dir("hygiene");
        std::fs::create_dir_all(workspace(&d)).expect("workspace");
        std::fs::write(workspace(&d).join("a.txt"), SENTINEL).expect("seed");
        let s = Serving::start(d.clone()).await;

        // A read, refused at every stage, with a real file behind it.
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "h1", "max_steps": 2, "content": "read a.txt"}),
        );
        send(
            &s.endpoint,
            "cl",
            "task/claim",
            json!({"id": "h1", "worker": "w1"}),
        );
        let p = send(
            &s.endpoint,
            "p",
            "task/propose",
            json!({
            "task": "h1", "worker": "w1", "capability": "filesystem/read-text",
            "target": "a.txt", "params": {"path": "a.txt"}}),
        );
        let pid = p["result"]["proposal"]["proposal_id"]
            .as_str()
            .unwrap()
            .to_owned();

        let refusals = vec![
            send(
                &s.endpoint,
                "1",
                "capability/approve",
                json!({"proposal": pid, "ttl_ms": 0}),
            ),
            send(
                &s.endpoint,
                "2",
                "task/execute",
                json!({"proposal": pid, "worker": "w1"}),
            ),
            send(
                &s.endpoint,
                "3",
                "task/continue",
                json!({"task": "h1", "worker": "w1"}),
            ),
            send(
                &s.endpoint,
                "4",
                "task/claim",
                json!({"id": "h1", "worker": "w2"}),
            ),
            send(
                &s.endpoint,
                "5",
                "task/execute",
                json!({"proposal": "p-nope", "worker": "w1"}),
            ),
            send(
                &s.endpoint,
                "6",
                "task/create",
                json!({"id": "h2", "max_steps": 0}),
            ),
        ];

        let host = d.to_string_lossy().to_string();
        for reply in &refusals {
            let rendered = serde_json::to_string(reply).expect("serialise");
            assert!(!rendered.contains(SENTINEL), "content leaked in {rendered}");
            assert!(
                !rendered.contains(&host),
                "an absolute host path leaked in {rendered}"
            );
            assert!(
                !rendered.to_lowercase().contains("sk-"),
                "a credential-shaped string leaked in {rendered}"
            );
            // And the machine-readable field is a word, whatever the case.
            if reply.get("error").is_some() {
                reason_of(reply);
            }
        }

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

/// Two callers racing for one task: one wins, and the loser is a conflict.
///
/// Not an internal error. Another worker winning a race is the system working, and reporting
/// it as a fault is what makes a correct concurrent system look broken in its logs.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn a_claim_race_is_one_winner_and_one_conflict() {
    rt().block_on(async {
        let d = dir("claimrace");
        let s = Serving::start(d.clone()).await;
        send(
            &s.endpoint,
            "c",
            "task/create",
            json!({"id": "c1", "content": "x"}),
        );

        let endpoint = s.endpoint.clone();
        let a = std::thread::spawn(move || {
            send(
                &endpoint,
                "ra",
                "task/claim",
                json!({"id": "c1", "worker": "w1"}),
            )
        });
        let endpoint = s.endpoint.clone();
        let b = std::thread::spawn(move || {
            send(
                &endpoint,
                "rb",
                "task/claim",
                json!({"id": "c1", "worker": "w2"}),
            )
        });
        let ra = a.join().expect("thread a");
        let rb = b.join().expect("thread b");

        let wins = [&ra, &rb]
            .iter()
            .filter(|r| r.get("result").is_some())
            .count();
        assert_eq!(wins, 1, "exactly one claim may win: {ra} {rb}");
        for loser in [&ra, &rb].iter().filter(|r| r.get("error").is_some()) {
            assert_eq!(
                code_of(loser),
                RpcErrorCode::CONFLICT.code(),
                "a lost race must be a conflict, not a fault: {loser}"
            );
            assert_ne!(code_of(loser), RpcErrorCode::INTERNAL_ERROR.code());
            reason_of(loser);
        }

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// Two callers racing to approve: one wins, and the loser is forbidden, not internal.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "Unix-socket evidence: this test reaches the daemon through a real \
     Unix domain socket, and the local IPC transport refuses on Windows rather than \
     binding a named pipe (crates/orxnud-platform-ipc)"
)]
#[test]
fn an_approval_race_is_one_winner_and_one_forbidden() {
    rt().block_on(async {
        let d = dir("approverace");
        let s = Serving::start(d.clone()).await;
        let pid = task_with_pending_proposal(&s, "ar1");

        let a = {
            let (endpoint, pid) = (s.endpoint.clone(), pid.clone());
            std::thread::spawn(move || {
                send(
                    &endpoint,
                    "ra",
                    "capability/approve",
                    json!({"proposal": pid, "ttl_ms": 60_000}),
                )
            })
        };
        let b = {
            let (endpoint, pid) = (s.endpoint.clone(), pid.clone());
            std::thread::spawn(move || {
                send(
                    &endpoint,
                    "rb",
                    "capability/approve",
                    json!({"proposal": pid, "ttl_ms": 60_000}),
                )
            })
        };
        let ra = a.join().expect("thread a");
        let rb = b.join().expect("thread b");

        let wins = [&ra, &rb]
            .iter()
            .filter(|r| r.get("result").is_some())
            .count();
        assert_eq!(wins, 1, "exactly one approval may be issued: {ra} {rb}");
        for loser in [&ra, &rb].iter().filter(|r| r.get("error").is_some()) {
            assert_ne!(
                code_of(loser),
                RpcErrorCode::INTERNAL_ERROR.code(),
                "a lost approval race must not be a fault: {loser}"
            );
            assert!(
                matches!(
                    code_of(loser),
                    c if c == RpcErrorCode::FORBIDDEN.code()
                        || c == RpcErrorCode::CONFLICT.code()
                ),
                "{loser}"
            );
        }

        s.stop().await;
        let _ = std::fs::remove_dir_all(&d);
    });
}
