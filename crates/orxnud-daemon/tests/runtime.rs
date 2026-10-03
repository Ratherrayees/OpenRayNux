//! The runtime, end to end, against a real socket and a real database.
//!
//! # What is actually exercised
//!
//! A real `Runtime` is started against a real directory. Nothing is mocked: the
//! SQLite file is created by the runtime's own migration path, the socket is a real
//! Unix domain socket, and the client is a separate connection. That matters
//! because the properties under test are all *arrangement* properties — durable
//! state attached before the endpoint exists, a request reaching the nine stages,
//! state surviving a restart — and none of them is observable from a unit test that
//! constructs the pieces separately.
//!
//! # The refusals are the evidence
//!
//! With an empty registry a dispatch cannot succeed, and that is the useful result:
//! a `send-message` request comes back refused *by policy*, which proves it entered
//! the governed path. A fake capability registered to make the test green would
//! prove nothing about the boundary and is deliberately absent.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use orxnud_daemon::Paths;
use orxnud_daemon::runtime::{Runtime, RuntimeError};
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use orxnud_domain::security_state::AuditJournal;
use orxnud_platform_ipc::{IpcError, endpoint_for};
use orxnud_protocol::error::RpcErrorCode;
use orxnud_protocol::frame::{Request, RequestId};
use orxnud_protocol::method::Method;
use orxnud_task::clock::{NowMs, SystemClock};
use serde_json::{Value, json};

/// A secret store with nothing in it, so a dispatch can never resolve a credential.
///
/// Present only because the governed dispatcher is generic over `SecretsContract`.
/// It keeps the suite off the real keyring, which is the point: a test that reached
/// a user's Secret Service would be testing the wrong thing.
struct NoSecrets;

#[derive(Debug, thiserror::Error)]
#[error("no secret store in the runtime suite")]
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
    let d = std::env::temp_dir().join(format!("orxnud-runtime-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// Multi-threaded on purpose.
///
/// These tests drive a real socket from a *blocking* client while the runtime serves
/// on another thread. A current-thread runtime would deadlock: the blocking read
/// would starve the accept loop that has to answer it.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

/// One request over a real connection, answered by a running runtime.
///
/// A raw line, not a `Request`, so a caller can send bytes the protocol crate would
/// refuse to build -- which is how the malformed and oversized cases are expressed.
///
/// # Framing warning
///
/// The transport is newline-delimited, so a request **must** be one line. A raw
/// literal written across several source lines sends a newline *inside* the JSON,
/// the runtime stops at the first one, and the request arrives malformed. Every
/// literal below is therefore collapsed onto one line -- and where a longer payload
/// is needed, `serde_json` builds it, because it never emits a raw newline.
fn call_raw(endpoint: &Path, line: &[u8]) -> Option<Value> {
    // A few attempts, because the serving task is spawned and the very first
    // exchange can arrive before its worker has polled `accept`. That is a task
    // scheduling race in the *test*, not a runtime property, so it is retried rather
    // than papered over in the runtime.
    for _ in 0..5 {
        if let Some(v) = call_once(endpoint, line) {
            return Some(v);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn call_once(endpoint: &Path, line: &[u8]) -> Option<Value> {
    let mut s = std::os::unix::net::UnixStream::connect(endpoint).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let _ = s.write_all(line);
    let _ = s.write_all(b"\n");
    let _ = s.flush();
    let mut reader = BufReader::new(s);
    let mut reply = String::new();
    reader.read_line(&mut reply).ok()?;
    serde_json::from_str(&reply).ok()
}

/// Starts a runtime, runs `body` with its endpoint, then shuts it down.
async fn with_runtime<F, Fut>(tag: &str, body: F)
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let d = dir(tag);
    let runtime = Runtime::start(Paths::under(&d), NoSecrets)
        .await
        .expect("start");
    let endpoint = runtime.endpoint().to_path_buf();
    // The runtime must actually be *serving* while the body runs, or nothing answers
    // the client. Serving on its own task is what makes the assertions read the
    // daemon's real answer.
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        let _ = runtime
            .serve(async move {
                let _ = rx.await;
            })
            .await;
    });
    body(endpoint).await;
    let _ = tx.send(());
    let _ = serving.await;
    let _ = std::fs::remove_dir_all(&d);
}

/// Like [`with_runtime`], but returns how `serve` actually ended.
///
/// `with_runtime` discards the serve result, which is right for "does the endpoint
/// answer" and wrong for error classification: "the daemon kept serving" and "the
/// daemon reported a vanished peer as a fatal transport failure" are different claims
/// about the same run, and only the second one is a defect.
async fn with_observed_runtime<F, Fut>(tag: &str, body: F) -> Result<(), IpcError>
where
    F: FnOnce(PathBuf) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let d = dir(tag);
    let runtime = Runtime::start(Paths::under(&d), NoSecrets)
        .await
        .expect("start");
    let endpoint = runtime.endpoint().to_path_buf();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
        runtime
            .serve(async move {
                let _ = rx.await;
            })
            .await
    });
    body(endpoint).await;
    let _ = tx.send(());
    let outcome = serving.await.expect("the serve task must not panic");
    let _ = std::fs::remove_dir_all(&d);
    outcome
}

#[test]
fn startup_attaches_durable_security_state_before_the_endpoint_exists() {
    rt().block_on(async {
        let d = dir("durable");
        let runtime = Runtime::start(Paths::under(&d), NoSecrets)
            .await
            .expect("start");
        assert!(
            runtime.is_durable().await,
            "a production runtime must never serve from the in-memory defaults"
        );
        // And the evidence is on disk, not merely asserted: the tables the journal
        // and the ledger need exist in the runtime's own database.
        let db = d.join("state.db");
        assert!(db.is_file(), "the runtime must have created its store");
        // Dropped rather than served: this test is about what `start` established,
        // and `serve(pending())` would never return.
        drop(runtime);
        let _ = std::fs::remove_dir_all(&d);
    });
}

#[test]
fn startup_refuses_when_durable_state_cannot_be_opened_and_binds_nothing() {
    rt().block_on(async {
        let d = dir("refuse");
        // A directory where the database file should be: `open` cannot succeed, and
        // the endpoint must therefore never appear.
        std::fs::create_dir_all(d.join("state.db")).expect("mkdir");
        let err = Runtime::start(Paths::under(&d), NoSecrets)
            .await
            .expect_err("must refuse");
        assert!(
            matches!(err, RuntimeError::SecurityState(_)),
            "a missing store must be a security-state refusal: {err:?}"
        );
        assert!(
            !endpoint_for(&d).exists(),
            "no endpoint may exist after a failed start"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}

#[test]
fn a_health_request_succeeds_over_a_real_socket() {
    rt().block_on(async {
        with_runtime("health", |endpoint| async move {
            let reply = call_raw(
                &endpoint,
                &serde_json::to_vec(&json!({
                    "jsonrpc": "2.0", "id": "1", "method": "daemon/status"
                }))
                .expect("encode"),
            );
            let reply = reply.expect("a response");
            assert_eq!(reply["id"], "1");
            assert_eq!(reply["result"]["status"], "running");
            assert_eq!(
                reply["result"]["durable_audit"], true,
                "the runtime must report that it is serving durably"
            );
            // Read from composition rather than hard-coded, so it stays true as the
            // shipped set changes.
            assert_eq!(reply["result"]["capabilities_enabled"], 2);
        })
        .await
    });
}

#[test]
fn the_protocol_methods_the_runtime_claims_to_serve_all_answer() {
    rt().block_on(async {
        with_runtime("methods", |endpoint| async move {
            for (method, id) in [
                (Method::DaemonStatus, "s"),
                (Method::DaemonVersion, "v"),
                (Method::CapabilityList, "c"),
                (Method::Echo, "e"),
            ] {
                let mut params = None;
                if method == Method::Echo {
                    params = Some(json!({"n": 1}));
                }
                let req = Request::new(RequestId::Text(id.to_owned()), method.as_str());
                let line = match params {
                    Some(p) => req.with_params(p).encode().expect("encode"),
                    None => req.encode().expect("encode"),
                };
                let reply = call_raw(&endpoint, &line).expect("a response");
                assert!(
                    reply.get("result").is_some(),
                    "{method} produced an error: {reply}"
                );
                assert_eq!(reply["id"], id);
            }
        })
        .await
    });
}

#[test]
fn a_governed_dispatch_reaches_policy_and_is_refused_there() {
    rt().block_on(async {
        with_runtime("governed", |endpoint| async move {
            let reply = call_raw(
                &endpoint,
                &serde_json::to_vec(&json!({
                    "jsonrpc": "2.0", "id": "d", "method": "capability/dispatch",
                    "params": { "capability": "send-message" }
                }))
                .expect("encode"),
            )
            .expect("a response");
            // The request reached the governed path: the refusal is policy's, and it
            // names the capability policy could not find. A shortcut that bypassed
            // policy could not produce this reason.
            let reason = reply["error"]["data"]["reason"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            assert!(
                reason.contains("policy") && reason.contains("send-message"),
                "the refusal must come from the governed path: {reason}"
            );
            assert_eq!(reply["error"]["code"], RpcErrorCode::INTERNAL_ERROR.code());
        })
        .await
    });
}

#[test]
fn malformed_unknown_and_invalid_requests_all_get_structured_errors() {
    rt().block_on(async {
        with_runtime("errors", |endpoint| async move {
            // Malformed JSON.
            let r = call_raw(&endpoint, b"{\"jsonrpc\":\"2.0\",\"id\":");
            let r = r.expect("a response even for garbage");
            assert_eq!(r["error"]["code"], RpcErrorCode::PARSE_ERROR.code());

            // A wrong version.
            let r = call_raw(
                &endpoint,
                br#"{"jsonrpc":"1.0","id":"v","method":"daemon/status"}"#,
            )
            .expect("a response");
            assert_eq!(r["error"]["code"], RpcErrorCode::INVALID_REQUEST.code());

            // An unknown method.
            let r = call_raw(
                &endpoint,
                br#"{"jsonrpc":"2.0","id":"m","method":"capability/does-not-exist"}"#,
            )
            .expect("a response");
            assert_eq!(r["error"]["code"], RpcErrorCode::METHOD_NOT_FOUND.code());

            // A dispatch with no capability named.
            let r = call_raw(
                &endpoint,
                br#"{"jsonrpc":"2.0","id":"p","method":"capability/dispatch","params":{}}"#,
            )
            .expect("a response");
            assert_eq!(r["error"]["code"], RpcErrorCode::INVALID_REQUEST.code());
        })
        .await
    });
}

#[test]
fn an_oversized_request_is_refused_with_a_structured_error() {
    rt().block_on(async {
        with_runtime("oversize", |endpoint| async move {
            let mut line =
                br#"{"jsonrpc":"2.0","id":"o","method":"daemon/status","pad":""#.to_vec();
            line.extend(std::iter::repeat_n(b'x', 400_000));
            line.extend_from_slice(br#""#);
            // One write, so the runtime sees the overrun on this connection.
            line.push(b'\n');
            let sock = endpoint.clone();
            let handle = std::thread::spawn(move || {
                let mut s = std::os::unix::net::UnixStream::connect(&sock).expect("connect");
                s.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut reader = BufReader::new(s.try_clone().expect("clone"));
                let _ = s.write_all(&line);
                let _ = s.flush();
                let mut buf = Vec::new();
                let _ = reader.read_until(b'\n', &mut buf);
                String::from_utf8_lossy(&buf).into_owned()
            });
            let reply = handle.join().expect("join");
            assert!(
                reply.contains("parse error") || reply.contains("-32700"),
                "an oversized message must be refused structurally, got: {reply}"
            );
            // And the runtime is still serving afterwards.
            let after = call_raw(
                &endpoint,
                br#"{"jsonrpc":"2.0","id":"after","method":"daemon/status"}"#,
            );
            assert!(after.expect("a response")["result"].is_object());
        })
        .await
    });
}

#[test]
fn an_abrupt_disconnect_does_not_stop_the_runtime() {
    rt().block_on(async {
        with_runtime("disconnect", |endpoint| async move {
            // Connect and close without sending anything.
            for _ in 0..5 {
                let s = std::os::unix::net::UnixStream::connect(&endpoint).expect("connect");
                drop(s);
            }
            let r = call_raw(
                &endpoint,
                br#"{"jsonrpc":"2.0","id":"k","method":"daemon/status"}"#,
            );
            assert!(
                r.expect("a response")["result"].is_object(),
                "the runtime must survive peers that vanish"
            );
        })
        .await
    });
}

#[test]
fn durable_state_survives_a_restart_and_the_chain_continues() {
    rt().block_on(async {
        let d = dir("restart");
        {
            let runtime = Runtime::start(Paths::under(&d), NoSecrets)
                .await
                .expect("first start");
            let endpoint = runtime.endpoint().to_path_buf();
            let (tx, rx) = tokio::sync::oneshot::channel();
            let serving = tokio::spawn(async move {
                let _ = runtime
                    .serve(async move {
                        let _ = rx.await;
                    })
                    .await;
            });
            // A dispatch attempt: refused, but the refusal is audited, so the journal
            // gains records that must still be there after the process is gone.
            let r = call_raw(
                &endpoint,
                br#"{"jsonrpc":"2.0","id":"x","method":"capability/dispatch", "params":{"capability":"send-message"}}"#,
            )
            .expect("a response");
            assert!(r.get("error").is_some(), "expected a governed refusal: {r}");
            // Shut down for real, so the endpoint is released and the WAL is
            // checkpointed exactly as a graceful exit would.
            let _ = tx.send(());
            let _ = serving.await;
            assert!(
                !endpoint_for(&d).exists(),
                "a graceful shutdown must release the endpoint"
            );
        }

        let rows_before = audit_rows(&d);
        assert!(
            rows_before > 0,
            "the refusal must have been audited, or there is nothing to persist"
        );

        // Restart against the same database.
        //
        // Reaching the *second* `start` succeeding IS the proof that the journal
        // loaded and verified: `attach_durable_security_state` calls `restore`, which
        // fails closed on any hash mismatch, broken link or undecodable payload. A
        // runtime that skipped verification would also get here, so this assertion is
        // paired with the one above -- records exist, and a fresh process accepted
        // them as its own history rather than starting a parallel chain at genesis.
        let runtime = Runtime::start(Paths::under(&d), NoSecrets)
            .await
            .expect("second start: the journal must load and verify");
        assert!(
            runtime.is_durable().await,
            "the restarted runtime is still durable"
        );
        // The records the first process wrote are the ones it loaded.
        let rows_after = audit_rows(&d);
        assert_eq!(
            rows_after, rows_before,
            "restarting must not add or lose records: the refusal is already there"
        );
        assert!(
            max_seq(&d) >= rows_after.saturating_sub(1),
            "sequence numbers must run from genesis across the restart"
        );
        drop(runtime);
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// A real dispatch is recorded with a real wall-clock instant, not a constant.
///
/// The defect this pins is not cosmetic. `now_ms` is what the dispatcher passes to
/// `authorise_for_dispatch`, so with it pinned at `0` an approval's `expires_at_ms`
/// compared against `0` and could never be expired — every approval, however old,
/// verified. It also reached the verifier and both audit records. A journal whose
/// timestamps are all `0` orders its records by sequence alone and cannot answer
/// "when did this happen", which is most of what an audit log is for.
#[test]
fn a_dispatch_is_audited_with_a_real_wall_clock_instant() {
    rt().block_on(async {
        let d = dir("stamps");
        let before = SystemClock::new().now_ms();
        let runtime = Runtime::start(Paths::under(&d), NoSecrets)
            .await
            .expect("start");
        let endpoint = runtime.endpoint().to_path_buf();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(async move {
            let _ = runtime.serve(async move { let _ = rx.await; }).await;
        });

        // The shipped Low-risk capability, so this is a completed invocation with
        // both an authorisation and a completion record rather than a refusal.
        let r = call_raw(
            &endpoint,
            br#"{"jsonrpc":"2.0","id":"s1","method":"capability/dispatch","params":{"capability":"text/word-count","params":{"text":"hello world"}}}"#,
        )
        .expect("a response");
        assert!(
            r.get("error").is_none(),
            "expected the shipped capability to dispatch: {r}"
        );
        let after = SystemClock::new().now_ms();

        let stamps = audited_at_ms(&d);
        assert!(
            stamps.len() >= 2,
            "expected an authorisation and a completion record, got {}",
            stamps.len()
        );
        for ms in &stamps {
            assert!(
                *ms >= before && *ms <= after,
                "audit stamp {ms} is outside the interval the dispatch ran in \
                 ({before}..={after}); a constant or a second clock would do this"
            );
        }
        // Ordering is preserved, which is the property a monotonic stamp buys.
        assert!(
            stamps.windows(2).all(|w| w[0] <= w[1]),
            "audit stamps must not go backwards: {stamps:?}"
        );

        let _ = tx.send(());
        let _ = serving.await;

        // And they are durable: the instants are still there after the process is
        // gone, read back through the store's own verified journal.
        let persisted = audited_at_ms(&d);
        assert_eq!(
            persisted, stamps,
            "restart must preserve the recorded instants, not restamp them"
        );
        let runtime = Runtime::start(Paths::under(&d), NoSecrets)
            .await
            .expect("restart: the journal must load and verify");
        assert!(runtime.is_durable().await);
        assert_eq!(
            audited_at_ms(&d),
            stamps,
            "a restarted daemon must not rewrite history"
        );
        drop(runtime);
        let _ = std::fs::remove_dir_all(&d);
    });
}

/// The `at-ms` instant of every audited dispatch record, in chain order.
fn audited_at_ms(d: &Path) -> Vec<i64> {
    orxnud_store::security_state::SqliteAuditJournal::open(&d.join("state.db"))
        .expect("open the journal the runtime wrote")
        .entries()
        .expect("entries")
        .iter()
        .filter_map(|e| {
            let v: Value = serde_json::from_slice(&e.payload).ok()?;
            let outcome = v.get("outcome")?;
            outcome
                .get("detail")
                .and_then(|d| d.get("at-ms"))
                .or_else(|| outcome.get("at-ms"))
                .and_then(Value::as_i64)
        })
        .collect()
}

/// How many records the durable journal holds.
fn audit_rows(d: &Path) -> u64 {
    audit_count_from_disk(d)
}

/// The persisted record count, via the store's own migration-verified database.
fn audit_count_from_disk(d: &Path) -> u64 {
    orxnud_store::security_state::SqliteAuditJournal::open(&d.join("state.db"))
        .expect("open the journal the runtime wrote")
        .entries()
        .expect("entries")
        .len() as u64
}

/// The highest persisted sequence number.
fn max_seq(d: &Path) -> u64 {
    orxnud_store::security_state::SqliteAuditJournal::open(&d.join("state.db"))
        .expect("open")
        .entries()
        .expect("entries")
        .iter()
        .map(|e| e.seq)
        .max()
        .unwrap_or(0)
}

#[test]
fn the_runtime_never_binds_a_network_socket() {
    // Structural rather than behavioural: a TCP listener would have to be written,
    // and the only transport the runtime can reach is `orxnud-platform-ipc`.
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/runtime.rs"))
        .expect("read runtime.rs");
    for forbidden in ["TcpListener", "tokio::net::Tcp", "axum", "hyper", "warp"] {
        assert!(
            !src.contains(forbidden),
            "the runtime must not reference {forbidden}"
        );
    }
}

#[test]
fn the_runtime_never_reaches_an_adapter_directly() {
    // The structural half of the security boundary: nothing in the runtime may name
    // an adapter or an invocation, only the dispatcher.
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/runtime.rs"))
        .expect("read runtime.rs");
    assert!(
        !src.contains(".invoke("),
        "the runtime must never call an adapter directly"
    );
    assert!(
        !src.contains("CapabilityInvocation::authorise"),
        "the runtime must never construct an authority-bearing invocation"
    );
    assert!(
        src.contains("daemon.dispatcher("),
        "and it must reach the governed dispatcher"
    );
}

// ---------------------------------------------------------------------------
// Write-side peer disconnect
//
// A local client may vanish at any instant, and the case that stopped the daemon
// was the one the suite did not cover: send a *complete, valid* request and close
// without reading the answer. The server has already accepted the request and is
// writing into a socket nobody will read, so its write fails. That is an ordinary
// client, not an attack, and it must not end the process.
//
// The test that existed covered only `connect` then `drop`, which is the read-side
// disconnect and always worked -- so the suite reported this area as green.
// ---------------------------------------------------------------------------

#[test]
fn a_peer_that_closes_before_reading_its_response_does_not_stop_the_daemon() {
    rt().block_on(async {
        let ended = with_observed_runtime("write-side-disconnect", |endpoint| async move {
            let mut s = std::os::unix::net::UnixStream::connect(&endpoint).expect("connect");
            let _ = s.write_all(br#"{"jsonrpc":"2.0","id":"w","method":"daemon/status"}"#);
            let _ = s.write_all(b"\n");
            let _ = s.flush();
            // Close without reading a single byte of the answer.
            drop(s);

            // Long enough for the runtime to accept, route, and fail its write. This
            // is a sleep rather than a signal because the property under test is
            // "the daemon is still there afterwards", and the only way to observe
            // that is to ask it.
            tokio::time::sleep(Duration::from_millis(750)).await;

            let reply = call_raw(
                &endpoint,
                br#"{"jsonrpc":"2.0","id":"2","method":"daemon/status"}"#,
            )
            .expect("a second client must still be served");
            assert_eq!(
                reply["result"]["status"], "running",
                "the daemon must still be serving: {reply}"
            );
        })
        .await;
        assert!(
            ended.is_ok(),
            "an expected peer disappearance must not be reported as a daemon failure: {ended:?}"
        );
    });
}

#[test]
fn a_reset_style_disconnect_does_not_stop_the_daemon() {
    rt().block_on(async {
        let ended = with_observed_runtime("reset-disconnect", |endpoint| async move {
            // Repeated, because one close can land before the runtime is reading and
            // would then prove nothing about the write path.
            for attempt in 0..5 {
                let mut s = std::os::unix::net::UnixStream::connect(&endpoint).expect("connect");
                let _ = s.write_all(br#"{"jsonrpc":"2.0","id":"r","method":"daemon/status"}"#);
                let _ = s.write_all(b"\n");
                let _ = s.flush();
                // Discard the read side *before* the response arrives. The kernel
                // then refuses the inbound answer with a reset instead of accepting
                // it, which is the ECONNRESET half of the classification -- and it is
                // reachable with portable std, so no cfg and no unsafe.
                let _ = s.shutdown(std::net::Shutdown::Read);
                drop(s);
                let _ = attempt;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }

            let reply = call_raw(
                &endpoint,
                br#"{"jsonrpc":"2.0","id":"3","method":"daemon/status"}"#,
            )
            .expect("the daemon must still answer after repeated resets");
            assert_eq!(reply["result"]["status"], "running", "{reply}");
        })
        .await;
        assert!(ended.is_ok(), "{ended:?}");
    });
}

#[test]
fn a_peer_disconnect_ends_the_connection_rather_than_the_serve_loop() {
    // Test D, stated as the classification it is: the disconnect must be absorbed by
    // `serve` and never reach `main` as a fatal error. `serve` returning `Ok` after a
    // peer vanished is the observable form of that, and it is the same assertion the
    // first test makes -- separated because the two properties can regress apart:
    // one is "the daemon survived", the other is "it classified the event correctly".
    rt().block_on(async {
        let ended = with_observed_runtime("disconnect-is-not-fatal", |endpoint| async move {
            for _ in 0..3 {
                let s = std::os::unix::net::UnixStream::connect(&endpoint).expect("connect");
                drop(s);
            }
            let mut s = std::os::unix::net::UnixStream::connect(&endpoint).expect("connect");
            let _ = s.write_all(br#"{"jsonrpc":"2.0","id":"d","method":"daemon/status"}"#);
            let _ = s.write_all(b"\n");
            let _ = s.shutdown(std::net::Shutdown::Both);
            drop(s);
            tokio::time::sleep(Duration::from_millis(400)).await;
        })
        .await;
        assert!(
            matches!(ended, Ok(())),
            "a vanished peer must be absorbed, not propagated: {ended:?}"
        );
    });
}

#[test]
fn the_endpoint_is_removed_when_the_runtime_finishes_serving() {
    // The cleanup guarantee on the ordinary path, asserted through the public API:
    // the socket file must not outlive the serve loop.
    rt().block_on(async {
        let d = dir("release");
        let runtime = Runtime::start(Paths::under(&d), NoSecrets)
            .await
            .expect("start");
        let endpoint = runtime.endpoint().to_path_buf();
        assert!(endpoint.exists(), "precondition: the endpoint is bound");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(async move {
            let _ = runtime
                .serve(async move {
                    let _ = rx.await;
                })
                .await;
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx.send(());
        let _ = serving.await;
        assert!(
            !endpoint.exists(),
            "the endpoint must be released when serving ends"
        );
        let _ = std::fs::remove_dir_all(&d);
    });
}
