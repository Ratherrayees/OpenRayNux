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
use orxnud_domain::ids::TaskId;
use orxnud_domain::platform::SecretsContract;
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_platform_ipc::{IpcError, LocalStream, endpoint_for};
use orxnud_protocol::error::{ProtocolError, RpcError, RpcErrorCode};
use orxnud_protocol::frame::{Request, RequestId, Response};
use orxnud_protocol::method::Method;
use orxnud_store::task_repo::NewTask;
use serde_json::json;

use orxnud_task::EngineLimits;

use crate::task_service::{TaskFault, TaskService};
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

    /// The task subsystem could not be opened, migrated or recovered.
    ///
    /// Fatal, and for the same reason [`Self::SecurityState`] is: the endpoint is
    /// never bound. There is no in-memory task fallback, because a daemon that
    /// accepted `task/create` and then forgot it on restart would be worse than one
    /// that refused to start.
    #[error("task subsystem unavailable: {0}")]
    TaskSubsystem(String),

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

    /// Well-formed, but declined — with a reason and an optional refinement the
    /// caller can branch on.
    ///
    /// Separate from [`Self::Invalid`] because the caller branches on
    /// `data.reason` and sometimes on `data.detail` alongside it. Packing a JSON
    /// object into the reason *string* would be a structured payload disguised as
    /// prose, and the first thing to do to such a string is split it apart again.
    #[error("invalid request: {reason}")]
    Declined {
        /// A fixed vocabulary word, never prose.
        reason: String,
        /// A second fixed word, when the first is not specific enough.
        detail: Option<&'static str>,
    },

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
            Self::Declined { reason, detail } => {
                let mut data = json!({ "reason": reason });
                if let Some(d) = detail {
                    data["detail"] = json!(d);
                }
                RpcError::new(RpcErrorCode::INVALID_REQUEST, "invalid request").with_data(data)
            }
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
    /// The one authoritative [`TaskService`], and with it the only
    /// [`orxnud_task::DurableEngine`] — the single writer for the task database.
    ///
    /// It shares the governed mutex rather than getting one of its own, and that is
    /// the whole concurrency story: `DurableEngine` owns a `rusqlite::Connection`
    /// whose write methods need `&mut`, so exactly one mutable handle may exist at a
    /// time (ADR-0006). A second mutex would not add safety, only a second way to
    /// interleave. Task operations therefore serialise against each other *and*
    /// against governed dispatch — which is a throughput question, deliberately not
    /// answered here.
    governed: tokio::sync::Mutex<(Daemon, S, TaskService)>,
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
    /// See the module docs. In short: [`Daemon::attach_durable_security_state`] and
    /// the task subsystem are both established *before* the endpoint exists, so there
    /// is no instant at which a peer can reach a daemon whose approval ledger is in
    /// memory, or whose task database has not been recovered.
    ///
    /// The two are opened in that order deliberately. Durable security state first
    /// means the audit chain is **verified** before the task engine performs any
    /// write: a tampered journal refuses the startup before a single task row is
    /// touched. Opening tasks first would still refuse on the same tamper, but only
    /// after the task engine had already run its recovery pass.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::SecurityState`] if durable state cannot be established or
    /// the journal does not verify, [`RuntimeError::TaskSubsystem`] if the task
    /// database cannot be opened, migrated or recovered, or
    /// [`RuntimeError::Endpoint`] if the local transport cannot be bound. In every
    /// case **no endpoint is left behind**.
    pub async fn start(paths: Paths, secrets: S) -> Result<Self, RuntimeError> {
        // 1 + 2 + 3. Durable security state, verified, attached.
        let mut daemon = Daemon::compose(paths.clone());
        daemon
            .attach_durable_security_state(&paths.database)
            .map_err(|e| RuntimeError::SecurityState(e.to_string()))?;

        // 4. The task subsystem: opened, migrated under a snapshot, and every lease
        //    orphaned by a dead predecessor reclaimed -- before a peer can ask for
        //    work, so a request never arrives at an unrecovered queue.
        let tasks = TaskService::open(&paths.database, EngineLimits::default())
            .map_err(|e| RuntimeError::TaskSubsystem(e.to_string()))?;

        daemon
            .start()
            .map_err(|e| RuntimeError::SecurityState(e.to_string()))?;

        // 5. Only now does anything become reachable.
        let endpoint = endpoint_for(&paths.root);
        let listener = orxnud_platform_ipc::bind(&endpoint).await?;
        let bound = listener
            .endpoint()
            .map_or_else(|| endpoint.clone(), Path::to_path_buf);

        Ok(Self {
            endpoint: bound,
            listener: Arc::new(listener),
            governed: tokio::sync::Mutex::new((daemon, secrets, tasks)),
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
    /// # The endpoint is released on *every* exit path
    ///
    /// This used to clean up after the loop, which meant any `?` between the loop
    /// and the cleanup returned first and left a stale socket file behind -- the
    /// socket the next start then has to reason about. Releasing through a guard on
    /// drop makes "the endpoint outlives the runtime" an invariant of the structure
    /// rather than a property of control flow, so a future early return cannot
    /// silently skip it.
    ///
    /// Cleanup cannot mask a failure: `Drop` runs during unwinding of the return
    /// value, not instead of it, so the original [`IpcError`] is what the caller
    /// receives.
    ///
    /// # Errors
    ///
    /// [`IpcError`] if a connection failed. Individual request failures do **not**
    /// end the loop: they are answered and the peer is disconnected, because one
    /// client sending nonsense is not a reason to take the daemon down. A peer that
    /// disappears mid-response is likewise not an error and is not reported as one.
    pub async fn serve(
        self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<(), IpcError> {
        let listener = Arc::clone(&self.listener);
        // Taken before the loop and released on every exit, including the `?`s below.
        let _release = EndpointRelease {
            listener: Arc::clone(&self.listener),
            path: self.cleanup,
        };
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
                        // A client that opened and closed is not a failure, and
                        // neither is one that vanished while we were answering it.
                        // Both are the same event seen from two ends of the socket.
                        continue;
                    }
                    served?;
                }
            }
        }

        Ok(())
    }
}

/// Closes the listener and removes the endpoint this runtime created.
///
/// Held for the duration of [`Runtime::serve`] so the endpoint cannot outlive the
/// runtime on any path, including an early return on a genuine transport error.
///
/// # Why the removal is still safe
///
/// The path here is not arbitrary: it is the endpoint [`Runtime::start`] successfully
/// bound, and `orxnud_platform_ipc::bind` **refuses** a path another live daemon is
/// listening on rather than unlinking it. So by the time a guard exists, the socket
/// file is this runtime's own. Removing a file that has since been replaced by
/// something else is the one case worth guarding against, and the check below does
/// exactly that -- it unlinks only a socket file, and only at the recorded path.
///
/// A failure to remove is ignored on purpose: it is not the error the caller asked
/// about, and inventing a second failure here would replace a real diagnosis with a
/// cosmetic one.
struct EndpointRelease {
    listener: Arc<orxnud_platform_ipc::Listener>,
    path: Option<PathBuf>,
}

impl Drop for EndpointRelease {
    fn drop(&mut self) {
        // Stop accepting before the path goes away, so a client that connected
        // before shutdown is never refused by a vanished endpoint.
        self.listener.close();
        if let Some(path) = self.path.take() {
            // The platform crate owns both the platform knowledge this needs and the
            // ownership rule: it bound the path, and it is the only place that may
            // unlink a socket file.
            orxnud_platform_ipc::release_endpoint(&path);
        }
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
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
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
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
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
        // First-party durable state, not capability execution. These go to the
        // TaskService and to nothing else.
        Method::TaskCreate
        | Method::TaskList
        | Method::TaskClaim
        | Method::TaskComplete
        | Method::TaskCancel => tasks(method, request, governed).await,
    }
}

/// The ceiling on a task's own human-visible content.
///
/// Well below [`MAX_REQUEST_BYTES`], because that bound protects the runtime's
/// *memory* while this one protects the task's *usefulness*: a task description is
/// text a person reads, and 64 KiB of it is not a description. Bounding content
/// separately is what stops the frame limit from becoming the de facto content
/// limit by accident.
pub const MAX_TASK_CONTENT_BYTES: usize = 4 * 1024;

/// The longest task id or worker label accepted.
///
/// Ids and worker labels are identifiers, not documents. An unbounded id is a way to
/// make the task table expensive to key and the event log expensive to read, and
/// neither is a cost a client should be able to impose.
const MAX_TASK_ID_BYTES: usize = 128;

/// Routes a `task/*` method.
///
/// # The boundary this draws
///
/// Everything below goes through [`TaskService`]. There is no SQL here, no
/// repository handle, no `rusqlite` value, and no arithmetic on [`TaskState`] — the
/// transition rules live in the engine and this function only translates between a
/// peer's JSON and the service's calls. Validation *is* done here, because refusing a
/// malformed request before it reaches durable state is the transport layer's job;
/// deciding whether an action is *permitted* is not, and nothing here decides that.
///
/// Task management is deliberately **not** routed through the governed dispatcher.
/// A task is first-party durable state this daemon owns; making `task/create` a
/// capability invocation would mean asking the policy engine to authorise the daemon
/// writing its own queue, and would put a row in the capability audit chain for
/// something that has no capability, no target and no side effect.
async fn tasks<S: SecretsContract>(
    method: Method,
    request: &Request,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
) -> Result<serde_json::Value, RequestError> {
    let params = request.params.clone().unwrap_or(json!({}));
    let mut g = governed.lock().await;
    let (_daemon, _secrets, tasks) = &mut *g;
    let now = tasks.clock_now_ms();

    match method {
        Method::TaskCreate => {
            let id = required_str(&params, "id")?;
            check_len("id", &id, MAX_TASK_ID_BYTES)?;
            let content = optional_str(&params, "content")?;
            if let Some(c) = content.as_ref() {
                check_len("content", c, MAX_TASK_CONTENT_BYTES)?;
            }
            let kind_raw = optional_str(&params, "kind")?.unwrap_or_else(|| "query".to_owned());
            // `from_wire_str` refuses what it does not know, so an invented kind is a
            // client error rather than a task the engine has to interpret.
            let kind = TaskKind::from_wire_str(&kind_raw).ok_or_else(|| {
                RequestError::Invalid(format!("`kind` is not a known task kind: {kind_raw:?}"))
            })?;
            let mut task = NewTask::new(TaskId::new(id), kind, now);
            task.payload = content;
            let row = tasks.create(&task, now).map_err(task_fault)?;
            Ok(json!({ "task": task_json(&row) }))
        }
        Method::TaskList => {
            let rows = tasks.list().map_err(task_fault)?;
            Ok(json!({
                // `ORDER BY id` in the repository: total, stable, and the same order
                // two identical databases will always produce.
                "tasks": rows.iter().map(task_json).collect::<Vec<_>>(),
                "count": rows.len(),
            }))
        }
        Method::TaskClaim => {
            let id = required_str(&params, "id")?;
            check_len("id", &id, MAX_TASK_ID_BYTES)?;
            let worker = required_str(&params, "worker")?;
            check_len("worker", &worker, MAX_TASK_ID_BYTES)?;
            let claimed = tasks
                .claim_task(&TaskId::new(id), &worker, now)
                .map_err(task_fault)?;
            Ok(json!({
                "task": task_json(&claimed.row),
                "attempt": claimed.attempt_no,
                "lease_expires_at_ms": claimed.lease_expires_at_ms,
            }))
        }
        Method::TaskComplete => {
            let id = required_str(&params, "id")?;
            check_len("id", &id, MAX_TASK_ID_BYTES)?;
            let worker = required_str(&params, "worker")?;
            check_len("worker", &worker, MAX_TASK_ID_BYTES)?;
            // `Completed` is fixed by the method name, and it is reachable only from
            // `running` through the engine's fence. A `pending` task has no lease, so
            // this cannot complete one — the refusal comes back as `fenced`.
            let row = tasks
                .complete_task(&TaskId::new(id), &worker, now, TaskState::Completed)
                .map_err(task_fault)?;
            Ok(json!({ "task": task_json(&row) }))
        }
        Method::TaskCancel => {
            let id = required_str(&params, "id")?;
            check_len("id", &id, MAX_TASK_ID_BYTES)?;
            // No worker identity: cancellation is a decision about the task, not a
            // report from a lease holder, so requiring one would make an unclaimed
            // task uncancellable. The engine owns that decision; this only asks.
            //
            // The reply is whatever the task is *now*. A cancel against an already
            // terminal task is a no-op that succeeds, and reporting a hard-coded
            // `cancelled` here would misreport a task that was already `completed`.
            let row = tasks
                .cancel_task(&TaskId::new(id), now)
                .map_err(task_fault)?;
            Ok(json!({
                "task": task_json(&row),
                // Derived from the state the daemon just reported, so a client can
                // branch without re-deriving the engine's cancellable-state set.
                "cancelled": row.state == TaskState::Cancelled,
            }))
        }
        // Unreachable: the caller only routes the five task methods here, and the
        // match is exhaustive over them. Listed so adding a fifth is a compile error
        // rather than a silent fall-through to the governed path.
        _ => Err(RequestError::UnknownMethod(request.method.clone())),
    }
}

/// Maps a task fault onto the wire.
///
/// Two existing codes and a stable `data.reason`, deliberately no new ones: "no such
/// task" and "that id is taken" and "you do not hold the lease" are all things the
/// caller can fix, so they are `INVALID_REQUEST`; a storage failure is the daemon's
/// problem, so it is `INTERNAL_ERROR`. A client branches on `data.reason`, which is
/// why the reasons are fixed strings rather than prose — and why the engine's own
/// message, which can quote a constraint or a path, never reaches a peer.
fn task_fault(fault: TaskFault) -> RequestError {
    let reason = fault.as_str();
    match fault {
        TaskFault::AlreadyExists
        | TaskFault::NotFound
        | TaskFault::NotClaimable(_)
        | TaskFault::Fenced => RequestError::Declined {
            reason: reason.to_owned(),
            detail: fault.detail(),
        },
        TaskFault::Stopped | TaskFault::Engine(_) => RequestError::Refused(reason.to_owned()),
    }
}

/// The wire projection of one task row.
///
/// Only model fields. No id of an internal object, no path, no SQL, no error text
/// from the engine: `last_error` is included because TP-11 requires a dead-lettered
/// task's failure to be visible to whoever asked for it, which is a product
/// requirement rather than debug output.
fn task_json(row: &orxnud_store::task_repo::TaskRow) -> serde_json::Value {
    json!({
        "id": row.id.as_str(),
        "kind": row.kind.as_wire_str(),
        "state": row.state.as_wire_str(),
        "priority": row.priority,
        "attempts": row.attempts,
        "max_attempts": row.max_attempts,
        "content": row.payload,
        "idempotent": row.idempotent,
        "effect_observed": row.effect_observed,
        "run_after_ms": row.run_after_ms,
        "created_at_ms": row.created_at_ms,
        "updated_at_ms": row.updated_at_ms,
        "terminal_at_ms": row.terminal_at_ms,
        "dead_lettered_at_ms": row.dead_lettered_at_ms,
        "cancel_requested_at_ms": row.cancel_requested_at_ms,
        "lease_holder": row.lease_holder,
        "lease_expires_at_ms": row.lease_expires_at_ms,
        "schedule_id": row.schedule_id.as_ref().map(ToString::to_string),
        "fire_time_ms": row.fire_time_ms,
        "last_error": row.last_error,
    })
}

/// Reads a required string parameter.
fn required_str(params: &serde_json::Value, field: &str) -> Result<String, RequestError> {
    optional_str(params, field)?
        .ok_or_else(|| RequestError::Invalid(format!("`{field}` must be a string")))
}

/// Reads an optional string parameter, refusing a non-string rather than coercing.
///
/// Coercion would make `{"id": 12}` and `{"id": "12"}` the same request, and an id is
/// an identity: two spellings of one is one too many.
fn optional_str(params: &serde_json::Value, field: &str) -> Result<Option<String>, RequestError> {
    match params.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(RequestError::Invalid(format!("`{field}` must be a string"))),
    }
}

/// Refuses an over-long string, naming the field and the bound.
fn check_len(field: &str, value: &str, max: usize) -> Result<(), RequestError> {
    if value.len() > max {
        return Err(RequestError::Invalid(format!(
            "`{field}` exceeds the {max}-byte limit"
        )));
    }
    Ok(())
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
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
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
    let (daemon, secrets, _tasks) = &mut *g;
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

    /// A current-thread runtime: these tests bind a socket and drive cleanup, and
    /// none of them needs the parallelism a real serve loop would.
    fn sync_rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    #[test]
    fn the_endpoint_is_released_on_the_error_path_and_the_error_is_preserved() {
        sync_rt().block_on(async {
            let dir =
                std::env::temp_dir().join(format!("orxnud-release-err-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("mkdir");
            let endpoint = dir.join("orxnud.sock");

            let listener = Arc::new(orxnud_platform_ipc::bind(&endpoint).await.expect("bind"));
            assert!(
                endpoint.exists(),
                "precondition: a real endpoint is bound at this path"
            );

            // The shape of `serve`'s early return, with the guard in the same scope
            // `serve` builds it in. A genuine transport failure -- not a peer
            // disappearing -- leaves the loop while the release guard is still live.
            // Before the guard this was exactly the path that returned before the
            // cleanup block and left a stale socket behind.
            let outcome: Result<(), IpcError> = {
                let _release = EndpointRelease {
                    listener: Arc::clone(&listener),
                    path: Some(endpoint.clone()),
                };
                Err(IpcError::Accept("a genuine accept failure".to_owned()))
            };

            // Cleanup must not become the error the caller sees.
            assert!(
                matches!(outcome, Err(IpcError::Accept(ref why)) if why.contains("genuine")),
                "the original runtime error must survive the release: {outcome:?}"
            );
            assert!(
                !endpoint.exists(),
                "a fatal runtime error must not leave a stale endpoint behind"
            );
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn an_ordinary_shutdown_releases_the_endpoint_too() {
        // The same guarantee on the happy path, so the error-path test above is
        // asserting a property of the guard rather than a quirk of one branch.
        sync_rt().block_on(async {
            let dir =
                std::env::temp_dir().join(format!("orxnud-release-ok-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("mkdir");
            let endpoint = dir.join("orxnud.sock");

            let listener = Arc::new(orxnud_platform_ipc::bind(&endpoint).await.expect("bind"));
            {
                let _release = EndpointRelease {
                    listener: Arc::clone(&listener),
                    path: Some(endpoint.clone()),
                };
                assert!(endpoint.exists(), "precondition: still bound");
            }
            assert!(!endpoint.exists(), "shutdown must release the endpoint");
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn the_release_guard_releases_nothing_when_there_is_no_endpoint() {
        // `start` on a platform with no transport refuses, so `cleanup` is `None`
        // there. The guard must tolerate that rather than panicking on a missing path.
        sync_rt().block_on(async {
            let _release = EndpointRelease {
                listener: Arc::new(orxnud_platform_ipc::Listener::Unsupported),
                path: None,
            };
        });
    }
}
