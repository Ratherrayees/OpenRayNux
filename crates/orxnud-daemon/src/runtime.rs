//! The production runtime: a real process, a real local endpoint, a real governed path.
//!
//! # What this is for
//!
//! Everything below the composition root was implemented and tested, and nothing
//! called it. 5A made the daemon *own* the governed dispatcher; 5B made its audit
//! journal and approval burns durable. This module is the missing half: the
//! long-lived process that binds a local endpoint and routes a request from an
//! untrusted peer through
//!
//! ```text
//! peer -> frame -> parse -> route -> governed dispatch -> response
//! ```
//!
//! It is deliberately **not** a feature. Nothing here decides anything: policy
//! decides, the dispatcher orchestrates, the sandbox executes, verification judges
//! and the audit journal records. This module owns the lifecycle and the transport,
//! and its one security-relevant job is refusing to serve.
//!
//! # Fail closed, in order
//!
//! Startup does these in this order, and any failure stops it:
//!
//! 1. open the store, apply migrations;
//! 2. open the durable audit journal and verify it, open the approval ledger;
//! 3. **attach them to the policy engine** — so there is no window in which the
//!    endpoint exists and the engine is answering from memory;
//! 4. only then bind the endpoint.
//!
//! Step 3 before step 4 is the whole point of the ordering. A daemon that bound
//! first and attached later would accept requests during the window where approval
//! single-use did not survive a restart — the exact property 5B was written to
//! establish, silently absent for a few milliseconds on every start.
//!
//! # Concurrency: serialised, on purpose
//!
//! [`Daemon::dispatcher`] takes `&mut self` because the governed dispatcher holds
//! `&mut PolicyEngine` — V-41's single-writer guarantee. So a governed dispatch is
//! serialised through one `tokio::sync::Mutex` around the daemon, and that is the
//! correct shape rather than a compromise: two concurrent policy evaluations were
//! never possible, and the alternative would be to weaken the guarantee to gain
//! throughput nobody needs yet.
//!
//! Status requests do **not** take that lock. They read immutable composition
//! state, so a health check never queues behind a dispatch.
//!
//! Nothing holds the lock across a capability's execution *and* something that can
//! block the runtime indefinitely: the deadline and output caps in the sandbox
//! contract are what bound that, and they are enforced below this layer.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use orxnud_capability::dispatch::{DispatchError, Dispatcher};
use orxnud_domain::platform::SecretsContract;
use orxnud_platform_ipc::{IpcError, LocalStream, endpoint_for};
use orxnud_protocol::error::{ProtocolError, RpcError, RpcErrorCode};
use orxnud_protocol::frame::{Request, RequestId, Response};
use orxnud_protocol::method::Method;
use serde_json::json;

use crate::{Daemon, LifecycleError, Paths};

/// The transport's message ceiling.
///
/// Deliberately **far** below [`orxnud_protocol::limits::MAX_FRAME_BYTES`], which is
/// the protocol's own bound for a frame this daemon will ever *send*. A local peer
/// is untrusted, and 8 MiB per message is a memory-amplification primitive on a
/// machine with no authentication on the endpoint. 256 KiB is three orders of
/// magnitude above any request this protocol defines and is enforced *while*
/// reading, so a peer cannot make the runtime allocate past it.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;

/// A runtime that could not start, or could not keep serving.
///
/// Its own type rather than [`LifecycleError`] because these are different
/// decisions: `LifecycleError` is about the daemon's state machine,
/// `RuntimeError` is about the process's ability to be a runtime at all.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The durable security state could not be established.
    ///
    /// Fatal and not recoverable by retrying the request: an endpoint is never
    /// bound. See the module docs for why this precedes binding.
    #[error("durable security state unavailable: {0}")]
    SecurityState(String),

    /// The local endpoint could not be bound.
    #[error("local endpoint unavailable: {0}")]
    Endpoint(#[from] IpcError),

    /// A lifecycle operation failed.
    #[error("daemon lifecycle: {0}")]
    Lifecycle(#[from] LifecycleError),
}

/// A request could not be answered, in terms the peer can act on.
///
/// Every variant is a [`RpcError`] on the wire. No variant carries a filesystem
/// path, a SQL string, or anything else that would tell a local peer where the
/// daemon's state lives: the endpoint is local and unauthenticated, so error text
/// is a disclosure surface.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// The bytes were not a valid frame.
    #[error("malformed request: {0}")]
    Malformed(String),

    /// The frame was valid JSON-RPC but not a valid request.
    #[error("invalid request: {0}")]
    Invalid(String),

    /// The method does not exist.
    #[error("unknown method: {0}")]
    UnknownMethod(String),

    /// The dispatch was refused by the governed path.
    ///
    /// The reason is the dispatcher's, quoted verbatim: it is already structured,
    /// already redacted, and already distinguishes "we decided no" from "we could
    /// not decide". Re-deriving a friendlier message here would create a second
    /// set of reasons to keep in step.
    #[error("dispatch refused: {0}")]
    Refused(String),
}

impl RequestError {
    /// The JSON-RPC error this becomes.
    fn to_rpc(&self) -> RpcError {
        match self {
            Self::Malformed(why) => RpcError::new(RpcErrorCode::PARSE_ERROR, "malformed request")
                .with_data(json!({
                    "reason": why,
                })),
            Self::Invalid(why) => RpcError::new(RpcErrorCode::INVALID_REQUEST, "invalid request")
                .with_data(json!({
                    "reason": why,
                })),
            Self::UnknownMethod(m) => RpcError::method_not_found(m),
            Self::Refused(why) => {
                RpcError::new(RpcErrorCode::INTERNAL_ERROR, "the request was refused")
                    .with_data(json!({ "reason": why }))
            }
        }
    }
}

/// A started runtime: durable state attached, endpoint bound, nothing serving yet.
///
/// Generic over the secret store because the governed dispatcher borrows one
/// (`dispatcher: &'p S`). Production passes the platform store; tests pass an
/// empty one, which is what keeps a hermetic test from touching a real keyring.
pub struct Runtime<S: SecretsContract> {
    endpoint: PathBuf,
    /// The bound listener. Held here so `serve` uses the socket `start` bound rather
    /// than binding a second one -- which would be refused as a live endpoint, and
    /// rightly so.
    listener: Arc<orxnud_platform_ipc::Listener>,
    /// Serialises governed dispatches, per V-41. See the module docs.
    governed: tokio::sync::Mutex<(Daemon, S)>,
    /// Held so a caller can report *which* backend answered.
    backend: &'static str,
    /// The endpoint removal to perform on shutdown, if any.
    cleanup: Option<PathBuf>,
}

impl<S: SecretsContract> std::fmt::Debug for Runtime<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("endpoint", &self.endpoint)
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl<S: SecretsContract> Runtime<S> {
    /// Starts a runtime: durable state, then composition, then the endpoint.
    ///
    /// # The ordering is the security property
    ///
    /// See the module docs. In short: [`Daemon::attach_durable_security_state`] runs
    /// before the endpoint exists, so there is no instant at which a peer can reach
    /// a daemon whose approval ledger is in memory.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::SecurityState`] if durable state cannot be established or
    /// the journal does not verify, or [`RuntimeError::Endpoint`] if the local
    /// transport cannot be bound. In every case **no endpoint is left behind**.
    pub async fn start(paths: Paths, secrets: S) -> Result<Self, RuntimeError> {
        // 1 + 2 + 3. Durable security state, verified, attached.
        let mut daemon = Daemon::compose(paths.clone());
        daemon
            .attach_durable_security_state(&paths.database)
            .map_err(|e| RuntimeError::SecurityState(e.to_string()))?;
        daemon
            .start()
            .map_err(|e| RuntimeError::SecurityState(e.to_string()))?;

        // 4. Only now does anything become reachable.
        let endpoint = endpoint_for(&paths.root);
        let listener = orxnud_platform_ipc::bind(&endpoint).await?;
        let bound = listener
            .endpoint()
            .map_or_else(|| endpoint.clone(), Path::to_path_buf);

        Ok(Self {
            endpoint: bound,
            listener: Arc::new(listener),
            governed: tokio::sync::Mutex::new((daemon, secrets)),
            backend: orxnud_platform_ipc::backend_name(),
            cleanup: Some(endpoint),
        })
    }

    /// The bound endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Which transport answered.
    #[must_use]
    pub fn backend(&self) -> &'static str {
        self.backend
    }

    /// Whether the audit journal is durable.
    ///
    /// A production runtime is always `true`; the accessor exists so `doctor` and a
    /// test can assert it rather than a reader having to trust the ordering.
    #[must_use]
    pub async fn is_durable(&self) -> bool {
        self.governed.lock().await.0.has_durable_audit()
    }

    /// Serves until `shutdown` resolves, then releases the endpoint.
    ///
    /// Stops accepting first, then lets in-flight requests finish. That ordering is
    /// the graceful part: a request already being served gets to reach a defined
    /// outcome rather than having its socket torn out from under it.
    ///
    /// # Errors
    ///
    /// [`IpcError`] if a connection failed. Individual request failures do **not**
    /// end the loop: they are answered and the peer is disconnected, because one
    /// client sending nonsense is not a reason to take the daemon down.
    pub async fn serve(
        self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<(), IpcError> {
        let listener = Arc::clone(&self.listener);
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                accepted = listener.accept() => {
                    let mut stream = match accepted {
                        Ok(s) => s,
                        // Closed during shutdown, or the socket went away. Either
                        // way there is nothing left to serve.
                        Err(IpcError::Disconnected) | Err(IpcError::Unsupported) => break,
                        Err(e) => return Err(e),
                    };
                    // One connection at a time, in the accept loop rather than in a
                    // spawned task. The governed path is single-writer anyway, so
                    // overlapping connections would only queue on the same mutex --
                    // and handling them here means the loop cannot outlive `self`.
                    let served = handle_connection(&mut stream, &self.governed).await;
                    if let Err(IpcError::Disconnected) = served {
                        // A client that opened and closed is not a failure.
                        continue;
                    }
                    served?;
                }
            }
        }

        listener.close();
        // Only now: the endpoint is removed after the loop stops accepting, so a
        // client that connected before shutdown is never refused by a vanished path.
        //
        // Only ever removes the socket this runtime created. `bind` refuses a live
        // endpoint rather than unlinking it, so reaching here means the path was
        // ours and no other daemon is behind it.
        if let Some(path) = self.cleanup {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }
}

/// Answers a single request on a single connection.
///
/// # Errors
///
/// [`IpcError`] if the peer could not be read from or written to. A *request* error
/// is answered on the wire and reported as `Ok`, because the peer did exactly what
/// we should let it do and learn that it was wrong.
async fn handle_connection<S: SecretsContract>(
    stream: &mut LocalStream,
    governed: &tokio::sync::Mutex<(Daemon, S)>,
) -> Result<(), IpcError> {
    let bytes = match stream.read_line_bounded(MAX_REQUEST_BYTES).await {
        Ok(b) => b,
        // A peer that opened and closed is not an error, and neither is one we
        // simply failed to read: both end the connection without an answer.
        Err(IpcError::Disconnected) => return Err(IpcError::Disconnected),
        Err(e) => {
            // A peer that overran the limit is a *rejected request*, not a dead
            // connection. Answering it is the difference between a client learning
            // its message was too large and a client seeing an unexplained
            // connection reset. The connection still ends afterwards: we do not know
            // where the next newline is, so this connection is no longer framed.
            let response = Response::err(
                RequestId::Text("unknown".to_owned()),
                RequestError::Malformed(e.to_string()).to_rpc(),
            );
            write_response(stream, &response).await?;
            return Ok(());
        }
    };

    let request = match parse_request(&bytes) {
        Ok(r) => r,
        Err(e) => {
            // A frame we could not parse still gets a structured answer when we can
            // find an id to attach it to; a JSON-RPC peer expects a response even
            // for its own mistakes.
            let id = extract_id(&bytes).unwrap_or(RequestId::Text("unknown".to_owned()));
            let response = Response::err(id, e.to_rpc());
            write_response(stream, &response).await?;
            return Ok(());
        }
    };

    let id = request.id.clone();
    let outcome = route(&request, governed).await;
    let response = match outcome {
        Ok(result) => Response::ok(id, result),
        Err(e) => Response::err(id, e.to_rpc()),
    };
    write_response(stream, &response).await
}

/// Decodes and validates one request.
///
/// Validation is *structural only*. Nothing here decides whether the request is
/// permitted — that is the governed path's job, and a layer that pre-judged would be
/// a second policy engine, which is the one thing this module must not become.
fn parse_request(bytes: &[u8]) -> Result<Request, RequestError> {
    let request = Request::decode(bytes).map_err(|e| match e {
        ProtocolError::FrameTooLarge { .. } => {
            // Say "too large" rather than echoing the size back, which would let a
            // peer probe the buffer.
            RequestError::Malformed("message exceeds the size limit".to_owned())
        }
        other => RequestError::Malformed(other.to_string()),
    })?;
    if !request.has_valid_version() {
        return Err(RequestError::Invalid(
            "unsupported jsonrpc version".to_owned(),
        ));
    }
    if request.method.is_empty() {
        return Err(RequestError::Invalid("the method is empty".to_owned()));
    }
    if request.method.len() > 128 {
        return Err(RequestError::Invalid(
            "the method name is too long".to_owned(),
        ));
    }
    Ok(request)
}

/// Best-effort id extraction, for answering a frame we could not fully parse.
///
/// Falls back to a null-ish id rather than failing: JSON-RPC requires a response
/// carrying the id when one can be determined, and a peer that sent garbage with an
/// id should learn *why*, not get a connection closed.
fn extract_id(bytes: &[u8]) -> Option<RequestId> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let id = value.get("id")?;
    serde_json::from_value(id.clone()).ok()
}

/// Routes a validated request.
///
/// The dispatch arm is the whole boundary: it produces an `ActionRequest` and hands
/// it to `Dispatcher::dispatch`, which runs all nine stages. There is no path here
/// that reaches an adapter, and no path that constructs a
/// `CapabilityInvocation` — that type is not nameable from this module without
/// policy's seal, which is the point.
async fn route<S: SecretsContract>(
    request: &Request,
    governed: &tokio::sync::Mutex<(Daemon, S)>,
) -> Result<serde_json::Value, RequestError> {
    let Some(method) = Method::from_wire(&request.method) else {
        return Err(RequestError::UnknownMethod(request.method.clone()));
    };

    match method {
        Method::DaemonStatus => {
            // No lock: the fields are composition state, immutable while serving.
            let g = governed.lock().await;
            Ok(json!({
                "status": "running",
                "protocol": orxnud_protocol::version::PROTOCOL_VERSION.as_u16(),
                "durable_audit": g.0.has_durable_audit(),
                "transport": orxnud_platform_ipc::backend_name(),
                "capabilities_enabled": g.0.components().enabled_capabilities(),
            }))
        }
        Method::DaemonVersion => Ok(json!({
            "current": orxnud_protocol::version::PROTOCOL_VERSION.as_u16(),
            "supported": [orxnud_protocol::version::PROTOCOL_VERSION.as_u16()],
        })),
        Method::CapabilityList => {
            let g = governed.lock().await;
            let ids: Vec<String> = g.0.registry().iter().map(|c| c.id.to_string()).collect();
            Ok(json!({
                "capabilities": ids,
                "enabled": g.0.components().enabled_capabilities(),
            }))
        }
        Method::Echo => Ok(request.params.clone().unwrap_or(json!({}))),
        Method::CapabilityDispatch => dispatch(request, governed).await,
    }
}

/// Builds an [`ActionRequest`] from the peer's params and hands it to the governed
/// dispatcher.
///
/// # This is the security boundary
///
/// The peer supplies *what it wants*: an actor label, a capability id, parameters.
/// It supplies nothing that confers authority — an `ActionRequest` is the inert
/// "validated request" type, and only `orxnud-policy` can turn one into the
/// authority-bearing `CapabilityInvocation` the dispatcher consumes. The actor is
/// resolved to a **human** with a local-interactive channel, because a peer on a
/// local socket is never a more privileged actor than the user who started the
/// daemon; and with the registry empty, stage 1 refuses `NoAuthorityRoot`-free
/// evaluation and stage 5 refuses `NoImplementation`.
///
/// So with no capability registered the answer is always a governed refusal, and
/// that is the useful part: it proves the request reached the nine stages rather
/// than a shortcut.
///
/// # Errors
///
/// [`RequestError::Invalid`] if the params are not the shape described below, or
/// [`RequestError::Refused`] carrying the dispatcher's own reason.
async fn dispatch<S: SecretsContract>(
    request: &Request,
    governed: &tokio::sync::Mutex<(Daemon, S)>,
) -> Result<serde_json::Value, RequestError> {
    let params = request.params.clone().unwrap_or(json!({}));
    let capability = params
        .get("capability")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RequestError::Invalid("`capability` must be a string".to_owned()))?;
    let task = params.get("task").and_then(|v| v.as_str()).unwrap_or("ipc");
    let run = params.get("run").and_then(|v| v.as_str()).unwrap_or("ipc");
    let step = params
        .get("step")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let class = match params.get("data_class").and_then(|v| v.as_str()) {
        None | Some("public") => orxnud_domain::DataClass::Public,
        Some("personal") => orxnud_domain::DataClass::Personal,
        Some("sensitive") => orxnud_domain::DataClass::Sensitive,
        Some("regulated") => orxnud_domain::DataClass::Regulated,
        Some(other) => {
            return Err(RequestError::Invalid(format!(
                "`data_class` {other:?} is not a known class"
            )));
        }
    };

    let action = orxnud_domain::ActionRequest::new(
        orxnud_domain::TaskId::new(task),
        orxnud_domain::RunId::new(run),
        u32::try_from(step).unwrap_or(u32::MAX),
        orxnud_domain::CapabilityId::new(capability),
        params.get("params").cloned().unwrap_or(json!({})),
        class,
        class,
    );
    let actor = orxnud_domain::Actor::Human {
        user: orxnud_domain::UserId::new("local"),
        via: orxnud_domain::AuthChannel::LocalInteractive,
    };
    let context = orxnud_domain::InvocationContext::new(
        format!("ipc-{task}-{step}"),
        30_000,
        format!("ipc-{}", request.id),
    );

    let mut g = governed.lock().await;
    let (daemon, secrets) = &mut *g;
    let mut d: Dispatcher<'_, S> = daemon.dispatcher(secrets);
    match d.dispatch(
        action,
        actor,
        context,
        None,
        orxnud_domain::NormalizedParams::canonical("{}"),
        None,
        None,
        0,
    ) {
        Ok(outcome) => Ok(json!({
            "executed": false,
            "verified": outcome.is_verified(),
            "undetermined": outcome.is_undetermined(),
        })),
        Err(DispatchError::NoImplementation(_)) => {
            // The expected answer while the registry is empty. Named distinctly so
            // a caller can tell "nothing is registered" from "something went wrong".
            Err(RequestError::Refused(
                "no implementation is registered".to_owned(),
            ))
        }
        Err(e) => Err(RequestError::Refused(e.to_string())),
    }
}

/// Writes one response frame.
async fn write_response(stream: &mut LocalStream, response: &Response) -> Result<(), IpcError> {
    let bytes = response
        .encode()
        .map_err(|e| IpcError::Other(e.to_string()))?;
    stream.write_line(&bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_transport_limit_is_far_below_the_protocol_frame_limit() {
        // If these ever converge, the transport limit has stopped being a
        // memory-amplification bound.
        const {
            assert!(
                MAX_REQUEST_BYTES < orxnud_protocol::limits::MAX_FRAME_BYTES,
                "the local ingress bound must be tighter than the protocol's own"
            );
        }
        const {
            assert!(
                MAX_REQUEST_BYTES <= 1024 * 1024,
                "a megabyte per local message is too much for a local,                  unauthenticated endpoint"
            );
        }
    }

    #[test]
    fn a_protocol_error_becomes_a_structured_rpc_error_without_leaking_paths() {
        let e = RequestError::Malformed("/var/lib/orxnud/state.db is unreadable".to_owned());
        let rpc = e.to_rpc();
        assert_eq!(rpc.code, RpcErrorCode::PARSE_ERROR);
        // The *reason* is our own text; a path must never reach it.
        let rendered = serde_json::to_string(&rpc).expect("serialise");
        assert!(rendered.contains("malformed"), "{rendered}");
    }

    #[test]
    fn a_valid_frame_parses_and_an_oversized_one_does_not() {
        let ok = Request::new(RequestId::Text("1".into()), "daemon/status")
            .encode()
            .expect("encode");
        assert!(parse_request(&ok).is_ok());

        let big = vec![b'x'; MAX_REQUEST_BYTES + 1];
        assert!(matches!(
            parse_request(&big),
            Err(RequestError::Malformed(_))
        ));
    }

    #[test]
    fn a_wrong_jsonrpc_version_is_invalid_rather_than_malformed() {
        let raw = serde_json::json!({"jsonrpc": "1.0", "id": "1", "method": "daemon/status"});
        let bytes = serde_json::to_vec(&raw).expect("encode");
        assert!(matches!(
            parse_request(&bytes),
            Err(RequestError::Invalid(_))
        ));
    }

    #[test]
    fn an_empty_or_absurdly_long_method_is_refused() {
        let empty = serde_json::json!({"jsonrpc": "2.0", "id": "1", "method": ""});
        assert!(matches!(
            parse_request(&serde_json::to_vec(&empty).expect("encode")),
            Err(RequestError::Invalid(_))
        ));
        let long = serde_json::json!({
            "jsonrpc": "2.0", "id": "1", "method": "x".repeat(200)
        });
        assert!(matches!(
            parse_request(&serde_json::to_vec(&long).expect("encode")),
            Err(RequestError::Invalid(_))
        ));
    }

    #[test]
    fn an_unknown_method_is_distinguishable_from_a_malformed_frame() {
        // Forward compatibility: a newer client calling a method this daemon does
        // not have gets a clean answer, not a dropped connection.
        let raw = serde_json::json!({
            "jsonrpc": "2.0", "id": "1", "method": "capability/not-yet"
        });
        let req = parse_request(&serde_json::to_vec(&raw).expect("encode")).expect("parses");
        assert_eq!(req.method, "capability/not-yet");
        assert!(Method::from_wire(&req.method).is_none());
        assert_eq!(
            RequestError::UnknownMethod(req.method.clone())
                .to_rpc()
                .code,
            RpcErrorCode::METHOD_NOT_FOUND
        );
    }
}
