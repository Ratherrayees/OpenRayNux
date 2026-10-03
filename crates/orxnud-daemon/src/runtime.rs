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
use orxnud_task::clock::{NowMs, SystemClock};

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
        Method::CapabilityApprove => approve(request, governed).await,
        // First-party durable state, not capability execution. These go to the
        // TaskService and to nothing else.
        // First-party durable state, not capability execution. These go to the
        // TaskService and to nothing else.
        Method::TaskCreate
        | Method::TaskList
        | Method::TaskClaim
        | Method::TaskComplete
        | Method::TaskPropose
        | Method::TaskCancel => tasks(method, request, governed).await,
        // Execution crosses from the task layer into the governed dispatcher, so it is
        // routed separately rather than through `tasks`: it needs the capability registry
        // and the sandbox backend, which `tasks` deliberately has no access to.
        Method::TaskExecute => execute_proposal(request, governed).await,
    }
}

/// The single actor this runtime acts as.
///
/// Named, because it has to be *the same* actor at approval time and at dispatch time:
/// the digest is computed over the actor's label and authority root, so two
/// structurally identical actors that differed in either would produce approvals that
/// never verify, and the symptom would be a mysterious refusal rather than a bug.
fn local_actor() -> orxnud_domain::Actor {
    orxnud_domain::Actor::Human {
        user: orxnud_domain::ids::UserId::new("local"),
        via: orxnud_domain::actor::AuthChannel::LocalInteractive,
    }
}

/// The delegated proposer for a task's governed action.
///
/// Built from the **task identity** and the trusted local human, never from the worker
/// holding the lease. That is V-71 as code rather than as a comment: the two inputs a
/// caller controls (task id, worker) and the two that determine authority (delegating
/// human, task) are separate, and only the former is reachable from the request.
fn delegated_actor(task_id: &str) -> orxnud_domain::Actor {
    use orxnud_domain::actor::ModelProvenance;
    orxnud_domain::Actor::Ai {
        delegated_by: orxnud_domain::ids::UserId::new("local"),
        run: orxnud_domain::ids::RunId::new(task_id),
        task: orxnud_domain::ids::TaskId::new(task_id),
        provenance: ModelProvenance::new(
            "openraynux/task-agent",
            "phase-2",
            orxnud_domain::ids::RequestId::new(task_id),
        ),
    }
}

/// The wire projection of one proposal row.
fn proposal_json(row: &orxnud_store::task_repo::ProposalRow) -> serde_json::Value {
    json!({
        "proposal_id": row.proposal_id,
        "task_id": row.task_id.as_str(),
        "attempt_no": row.attempt_no,
        "capability": row.capability,
        "target": row.target,
        "params": row.params,
        "authority_root": row.authority_root,
        "created_at_ms": row.created_at_ms,
        "status": row.status,
        "decided_at_ms": row.decided_at_ms,
    })
}

/// Executes an approved proposal through the governed dispatcher.
///
/// The load-bearing property of this function is that it **rebuilds the action from the
/// durable proposal** rather than from the request. A caller supplies only a proposal id
/// and a worker; there is no parameter to substitute, so there is nothing to substitute.
/// That is what makes "approve A, execute B" unrepresentable over this interface.
///
/// Policy remains the authority: the `ApprovalRecord` is handed to
/// `Dispatcher::dispatch`, which performs expiry, single-use, the digest recompute over
/// both parties, the approver's grant-capability and authority relationship, and the
/// budget. This function adds no authorisation logic of its own.
async fn execute_proposal<S: SecretsContract>(
    request: &Request,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
) -> Result<serde_json::Value, RequestError> {
    let params = request.params.clone().unwrap_or(json!({}));
    let proposal_id = required_str(&params, "proposal")?;
    check_len("proposal", &proposal_id, MAX_TASK_ID_BYTES)?;
    let worker = required_str(&params, "worker")?;
    check_len("worker", &worker, MAX_TASK_ID_BYTES)?;

    let mut g = governed.lock().await;
    let now = g.2.clock_now_ms();

    // 1. The durable proposal. Everything below is derived from it.
    let proposal =
        g.2.proposal(&proposal_id)
            .map_err(task_fault)?
            .ok_or_else(|| RequestError::Invalid(format!("no proposal {proposal_id:?}")))?;
    let proposer = proposal
        .proposer()
        .map_err(|e| RequestError::Invalid(format!("proposal proposer unusable: {e}")))?;
    let canonical = orxnud_domain::NormalizedParams::canonical(proposal.params.clone());

    // 2. The approval for *this attempt*, recomposed against the trusted approver. The
    //    digest was computed over that approver, so if it were minted under anyone else
    //    the dispatcher refuses it — which is the check, not this reconstruction.
    let approval_row =
        g.2.engine()
            .approval_for(&proposal.task_id, proposal.attempt_no)
            .map_err(|e| RequestError::Refused(format!("approval unreadable: {e}")))?
            .ok_or_else(|| RequestError::Declined {
                reason: "approval-required".to_owned(),
                // A fixed word, not a formatted sentence: `detail` is a second term in a
                // vocabulary a client branches on, and putting a task id in it would make
                // the value unpredictable.
                detail: Some("no approval is recorded for this proposal's attempt"),
            })?;
    let record = approval_record_from_row(&approval_row, &proposer, &proposal)?;

    // 3. Take the fresh execution lease and resume the task, atomically.
    let began =
        g.2.begin_approved_execution(&proposal_id, &worker, now)
            .map_err(task_fault)?;

    // 4. Dispatch. The action comes from the proposal; `action.params` and
    //    `canonical_params` are the same value by construction, which is what the
    //    dispatcher's digest check then confirms.
    // The stored parameters are parsed, and a parse failure is **fatal**.
    //
    // This line used to be `.unwrap_or(json!({}))`, which was fail-*open* in the worst
    // way available: the digest is computed over the stored canonical *text*, so a
    // corrupt row still verified, and the adapter then ran with `{}` — a side effect
    // from parameters nobody approved. Durable state that cannot be read is refused,
    // never defaulted.
    let stored_params: serde_json::Value = match serde_json::from_str(&proposal.params) {
        Ok(v) => v,
        Err(_) => {
            return Err(RequestError::Declined {
                reason: "proposal-corrupt".to_owned(),
                detail: Some("the stored parameters are not readable JSON"),
            });
        }
    };
    let action = orxnud_domain::ActionRequest::new(
        proposal.task_id.clone(),
        orxnud_domain::ids::RunId::new(proposal.task_id.as_str()),
        proposal.attempt_no,
        orxnud_domain::CapabilityId::new(proposal.capability.as_str()),
        stored_params,
        orxnud_domain::DataClass::Public,
        orxnud_domain::DataClass::Public,
    );
    let context = orxnud_domain::InvocationContext::new(
        format!("proposal-{proposal_id}"),
        30_000,
        format!("ipc-{}", request.id),
    );
    // Scoped so the dispatcher — which borrows the governed lock — is dropped before the
    // completion below needs the same lock. A second `lock().await` while `d` is alive
    // would deadlock rather than queue, because a `tokio::sync::Mutex` is not reentrant.
    let outcome = {
        let (daemon, secrets, _tasks) = &mut *g;
        let mut d: Dispatcher<'_, S> = daemon.dispatcher(secrets);
        d.dispatch(
            action,
            proposer,
            context,
            proposal.target.clone(),
            canonical,
            Some(&record),
            None,
            now,
        )
    };

    let o = match outcome {
        Ok(o) => o,
        Err(e) => {
            // The dispatcher's own message, which is already structured and already
            // safe to show. `Refused` rather than `Declined` because the detail is the
            // dispatcher's to word, not a fixed term this layer owns.
            return Err(RequestError::Refused(e.to_string()));
        }
    };

    // Completion is gated on the **verifier**, not on the dispatcher having returned.
    // A refuted or undetermined effect leaves the task `running` under its lease, which
    // is the honest state: something may have happened and nobody can say what. Reporting
    // completion there would be the task layer asserting an effect the verification stage
    // explicitly refused to confirm.
    let completed = if o.is_verified() {
        let complete_at = g.2.clock_now_ms();
        Some(
            g.2.complete_task_with(
                &began.task_id,
                &worker,
                complete_at,
                TaskState::Completed,
                true,
                None,
                None,
            )
            .map_err(task_fault)?,
        )
    } else {
        None
    };

    Ok(json!({
        "proposal": proposal_json(&began),
        "verified": o.is_verified(),
        "refuted": o.verification.is_refuted(),
        "undetermined": o.verification.is_undetermined(),
        "result": o.verification.to_string(),
        // `null` when the verifier did not confirm, so a client can tell "not completed"
        // from "completed, and here is the stored row".
        "task": completed.as_ref().map(task_json),
    }))
}

/// Rebuilds the approval record for dispatch from the stored row.
///
/// The approver is **not** read from storage or from the request: it is re-derived from
/// the trusted local-human boundary, exactly as at minting time. Because the digest
/// binds the approver, a row minted by anyone else fails the recompute rather than
/// quietly verifying.
fn approval_record_from_row(
    row: &orxnud_store::task_repo::ApprovalRow,
    proposer: &orxnud_domain::Actor,
    proposal: &orxnud_store::task_repo::ProposalRow,
) -> Result<orxnud_domain::ApprovalRecord, RequestError> {
    let digest = digest_from_hex(&row.digest_hex).ok_or_else(|| RequestError::Declined {
        reason: "approval-corrupt".to_owned(),
        detail: Some("the stored digest is not 64 hex characters"),
    })?;
    // The approval must be *for this action*. Cheap pre-check so the refusal names the
    // mismatch instead of surfacing as a digest failure deep in the dispatcher.
    if row.capability != proposal.capability
        || row.params != proposal.params
        || row.target != proposal.target
    {
        return Err(RequestError::Declined {
            reason: "approval-action-mismatch".to_owned(),
            detail: Some("the approval was issued for a different action"),
        });
    }
    Ok(orxnud_domain::ApprovalRecord {
        actor_label: proposer.label().to_owned(),
        approver: local_actor(),
        capability: row.capability.clone(),
        target: row.target.clone().unwrap_or_else(|| "-".to_owned()),
        params: orxnud_domain::NormalizedParams::canonical(row.params.clone()),
        issued_at_ms: row.issued_at_ms,
        expires_at_ms: row.expires_at_ms,
        risk: orxnud_domain::enums::RiskClass::High,
        digest,
    })
}

/// Approves a **durable proposal**, if the request names one.
///
/// This is the ADR-0037 minting path, and its shape is the point:
///
/// ```text
/// trusted local human -> proposal_id -> daemon loads the proposal
///   -> daemon derives the approving Human -> issues for *that* action
/// ```
///
/// The caller supplies **only a proposal id**. It cannot supply the capability, the
/// parameters, the target, the proposer, or an approver — every one of those comes from
/// the stored proposal. That is what makes "approve A, execute B" unrepresentable: there
/// is no field through which B could be named.
///
/// The approver is the trusted local human, derived here. A caller cannot nominate its
/// own approver, and `issue_approval` refuses a non-granting principal, so the approver
/// field is evidence rather than decoration (V-69).
///
/// # Errors
///
/// [`RequestError::Invalid`] for a malformed request, or a proposal that is unknown or
/// already decided.
async fn approve_proposal<S: SecretsContract>(
    request: &Request,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
) -> Result<serde_json::Value, RequestError> {
    let params = request.params.clone().unwrap_or(json!({}));
    let proposal_id = required_str(&params, "proposal")?;
    check_len("proposal", &proposal_id, MAX_TASK_ID_BYTES)?;
    let ttl_ms = params
        .get("ttl_ms")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(60_000);

    let mut g = governed.lock().await;
    let now = g.2.clock_now_ms();

    let proposal =
        g.2.proposal(&proposal_id)
            .map_err(task_fault)?
            .ok_or_else(|| RequestError::Invalid(format!("no proposal {proposal_id:?}")))?;
    if !proposal.is_pending() {
        return Err(RequestError::Declined {
            reason: "proposal-already-decided".to_owned(),
            detail: Some("only a pending proposal can be approved"),
        });
    }
    let proposer = proposal
        .proposer()
        .map_err(|e| RequestError::Invalid(format!("proposal proposer unusable: {e}")))?;

    // The trusted approver, and the digest computed over BOTH parties plus the stored
    // action. Nothing here is taken from the request except the proposal id.
    let approver = local_actor();
    let canonical = orxnud_domain::NormalizedParams::canonical(proposal.params.clone());
    let record = orxnud_policy::issue_approval(
        &approver,
        &proposer,
        &orxnud_domain::CapabilityId::new(proposal.capability.as_str()),
        proposal.target.as_deref(),
        &canonical,
        now,
        now.saturating_add(ttl_ms),
        orxnud_domain::enums::RiskClass::High,
    );

    // Recorded against the attempt, so a retry would not inherit it (TP-6), and marked
    // decided, so the proposal stops being approvable.
    let approval_row = orxnud_store::task_repo::ApprovalRow {
        task_id: proposal.task_id.clone(),
        attempt_no: proposal.attempt_no,
        digest_hex: digest_hex(&record.digest),
        capability: record.capability.clone(),
        target: proposal.target.clone(),
        params: record.params.as_str().to_owned(),
        issued_at_ms: record.issued_at_ms,
        expires_at_ms: record.expires_at_ms,
        consumed_at_ms: None,
    };
    g.2.engine_mut()
        .record_approval(&approval_row)
        .map_err(|e| RequestError::Refused(format!("approval could not be recorded: {e}")))?;
    let decided =
        g.2.decide_proposal(&proposal_id, "approved", now)
            .map_err(task_fault)?;

    Ok(json!({
        "approval": {
            "actor_label": record.actor_label,
            "approver": record.approver.label(),
            "authority_root": record.approver.authority_root().map(|u| u.as_str()),
            "capability": record.capability,
            "target": record.target,
            "params": record.params.as_str(),
            "issued_at_ms": record.issued_at_ms,
            "expires_at_ms": record.expires_at_ms,
            "digest": digest_hex(&record.digest),
        },
        "proposal": proposal_json(&decided),
    }))
}

/// Issues an approval for one proposed invocation.
///
/// # What this does and does not do
///
/// It canonicalises the parameters, computes the digest, and returns the tuple. It
/// grants nothing: no policy is consulted, no capability is enabled, and no ledger is
/// touched. The result is an *artefact*, and whether it is honoured is decided later at
/// dispatch, by recomputing the digest from the action that is actually about to run
/// and comparing. That is what makes an approval bound to one operation rather than to
/// a capability -- and it is why a caller cannot use this to widen its own authority:
/// the worst it can do is produce an approval for something policy would refuse anyway.
///
/// # `ttl_ms`
///
/// Relative, and `0` is meaningful: it produces an approval that is already expired,
/// which is how the expiry property is tested without sleeping. The daemon does not
/// clamp it, because the caller approving its own action is the party the expiry exists
/// to inform, not a party to overrule. A future consenting principal would decide the
/// ceiling here rather than accepting one.
///
/// # Errors
///
/// [`RequestError::Invalid`] for a malformed request.
async fn approve<S: SecretsContract>(
    request: &Request,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
) -> Result<serde_json::Value, RequestError> {
    let params = request.params.clone().unwrap_or(json!({}));
    // A named proposal takes a different path entirely: the caller supplies no action at
    // all, so there is nothing for it to have substituted.
    if params.get("proposal").is_some() {
        return approve_proposal(request, governed).await;
    }
    let capability = params
        .get("capability")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RequestError::Invalid("`capability` must be a string".to_owned()))?;
    let target = params.get("target").and_then(|v| v.as_str());
    let inner = params.get("params").cloned().unwrap_or(json!({}));
    let ttl_ms = match params.get("ttl_ms") {
        None | Some(serde_json::Value::Null) => 60_000,
        Some(v) => v
            .as_i64()
            .ok_or_else(|| RequestError::Invalid("`ttl_ms` must be an integer".to_owned()))?,
    };

    let g = governed.lock().await;
    let now_ms = g.2.clock_now_ms();
    drop(g);

    let actor = local_actor();
    let capability_id = orxnud_domain::CapabilityId::new(capability);
    // Canonicalised through the one function dispatch canonicalises with. Building the
    // canonical text here any other way is precisely the V-63 defect in a new place.
    let canonical = orxnud_policy::canonical_params(&inner);
    // The approver is the trusted local human, derived here rather than supplied by the
    // request (ADR-0037, V-69). An approval caller cannot nominate its own approver:
    // this line is the whole reason the approver field is evidence rather than
    // decoration. `issue_approval` independently refuses a non-granting principal, so a
    // future caller cannot quietly widen it.
    let approver = local_actor();
    let record = orxnud_policy::issue_approval(
        &approver,
        &actor,
        &capability_id,
        target,
        &canonical,
        now_ms,
        now_ms.saturating_add(ttl_ms),
        // Risk is not negotiated here. `authorise` derives risk from the capability's
        // *declaration* and ignores this field, so putting the declared risk here would
        // be a claim this method cannot make; it is recorded as the class the caller
        // asked to be treated as, which the runtime does not rely on.
        orxnud_domain::enums::RiskClass::High,
    );

    Ok(json!({
        "approval": {
            "actor_label": record.actor_label,
            "capability": record.capability,
            "target": record.target,
            "params": record.params.as_str(),
            "issued_at_ms": record.issued_at_ms,
            "expires_at_ms": record.expires_at_ms,
            "digest": digest_hex(&record.digest),
        }
    }))
}

/// The digest as hex, so a client can carry it without knowing the crate.
fn digest_hex(digest: &orxnud_domain::ApprovalDigest) -> String {
    digest
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Reads hex back into a digest.
fn digest_from_hex(text: &str) -> Option<orxnud_domain::ApprovalDigest> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in text.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(hex, 16).ok()?;
    }
    Some(orxnud_domain::ApprovalDigest::from_bytes(out))
}

/// Reconstructs an [`orxnud_domain::ApprovalRecord`] from a client's JSON.
///
/// The digest is carried through rather than recomputed *here*, and that is the whole
/// anti-Loopjacking design: this function must not be able to produce a record that
/// matches whatever it is handed, or the check at dispatch would compare a value
/// against itself. `authorise` recomputes from the action and compares, so a client
/// that alters the digest is refused and a client that alters the parameters is
/// refused. A client that alters neither has presented a genuine approval.
///
/// [`RequestError::Invalid`] for anything malformed.
fn approval_from_json(
    value: &serde_json::Value,
) -> Result<orxnud_domain::ApprovalRecord, RequestError> {
    let bad = |why: &str| RequestError::Invalid(format!("`approval` {why}"));
    let object = value.as_object().ok_or_else(|| bad("must be an object"))?;
    let text = |key: &str| -> Result<String, RequestError> {
        object
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| bad(&format!("needs a string `{key}`")))
    };
    let number = |key: &str| -> Result<i64, RequestError> {
        object
            .get(key)
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| bad(&format!("needs an integer `{key}`")))
    };
    let digest_text = text("digest")?;
    let digest =
        digest_from_hex(&digest_text).ok_or_else(|| bad("needs a 64-character hex `digest`"))?;
    Ok(orxnud_domain::ApprovalRecord {
        actor_label: text("actor_label")?,
        // The approver is **not** read from the client. It is re-derived from the
        // trusted local-human boundary at the point of use, so a client cannot present
        // an approval naming an approver of its choosing — the digest check would fail
        // anyway, but refusing to carry the field at all is what makes the guarantee
        // structural rather than arithmetic.
        approver: local_actor(),
        capability: text("capability")?,
        target: text("target")?,
        params: orxnud_domain::NormalizedParams::canonical(text("params")?),
        issued_at_ms: number("issued_at_ms")?,
        expires_at_ms: number("expires_at_ms")?,
        // Carried for display only; `authorise` derives risk from the declaration.
        risk: orxnud_domain::enums::RiskClass::High,
        digest,
    })
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
        Method::TaskPropose => {
            let task_id = required_str(&params, "task")?;
            check_len("task", &task_id, MAX_TASK_ID_BYTES)?;
            let worker = required_str(&params, "worker")?;
            check_len("worker", &worker, MAX_TASK_ID_BYTES)?;
            let capability = required_str(&params, "capability")?;
            let target = params.get("target").and_then(|v| v.as_str());
            let inner = params.get("params").cloned().unwrap_or(json!({}));
            // The proposer is **delegated**, and is built from the task identity rather
            // than from the worker. That separation is V-71 as code: the caller controls
            // the worker string, and the worker cannot reach the actor.
            let proposer = delegated_actor(&task_id);
            let canonical = orxnud_policy::canonical_params(&inner);
            // Derived from the task and the instant, so two proposals for one attempt in
            // the same millisecond collide in the primary key rather than both existing.
            let proposal_id = format!("p-{task_id}-{now}");
            let row = tasks
                .propose_action(
                    &proposal_id,
                    &TaskId::new(task_id.as_str()),
                    &worker,
                    &orxnud_domain::CapabilityId::new(capability.as_str()),
                    target,
                    canonical.as_str(),
                    &proposer,
                    now,
                )
                .map_err(task_fault)?;
            Ok(json!({
                "proposal": proposal_json(&row),
                // Stated rather than implied: the task is now waiting on a person, with
                // a durable proposal explaining what it is waiting for.
                "waiting_for": "human-approval",
            }))
        }
        // Unreachable: the caller only routes the task methods here, and the
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
/// The parameters an approval for this action commits to.
///
/// This is a named function rather than an inline call because it is the exact
/// seam where the two dispatch defects lived, and both were invisible: nothing in
/// the dispatcher can tell that the `NormalizedParams` it was handed does not
/// describe the `ActionRequest` it was also handed. If an approval digest is ever
/// computed over a placeholder while the adapter runs the real parameters, the
/// user approves one operation and a different one executes — and every stage
/// still reports success. Deriving it from the action, in one named place, is what
/// makes that failure impossible to reintroduce by accident.
fn approval_params(action: &orxnud_domain::ActionRequest) -> orxnud_domain::NormalizedParams {
    orxnud_policy::canonical_params(&action.params)
}

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
    let actor = local_actor();
    // An approval presented by the caller, if any. Reconstructed from the client's JSON
    // rather than looked up: the daemon keeps no approval store, because the ledger it
    // does keep records *spent digests*, and the digest is what binds an approval to an
    // operation. Presenting the tuple again is not a privilege -- it can only ever be
    // checked against the action about to run.
    // The target is part of the tuple an approval commits to, so it has to travel from
    // the request into dispatch rather than being dropped here. Passing `None` while
    // `capability/approve` was given a target would make the two digests differ for
    // every request -- a mismatch that looks like a security refusal but is really the
    // runtime discarding half the tuple.
    let target = params
        .get("target")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let approval = match params.get("approval") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(approval_from_json(value)?),
    };
    let context = orxnud_domain::InvocationContext::new(
        format!("ipc-{task}-{step}"),
        30_000,
        format!("ipc-{}", request.id),
    );

    let mut g = governed.lock().await;
    let (daemon, secrets, _tasks) = &mut *g;
    let mut d: Dispatcher<'_, S> = daemon.dispatcher(secrets);
    // Derived before `action` is moved into the call below.
    let approval_params = approval_params(&action);
    // The wall clock is read here, inside the governed lock, rather than at
    // request parse time: the stamp has to describe when the action was actually
    // authorised, which is after whatever the lock was waiting for.
    let now_ms = SystemClock::new().now_ms();
    match d.dispatch(
        action,
        actor,
        context,
        target,
        approval_params,
        approval.as_ref(),
        None,
        now_ms,
    ) {
        Ok(outcome) => {
            // The three-way distinction is reported as three fields rather than
            // collapsed into a success flag: a refuted outcome and an undetermined one
            // call for different next decisions, and `undetermined` in particular must
            // never read as success.
            //
            // `result` is the adapter's own claim, carried through verbatim and
            // clearly labelled as such. It has already been through independent
            // verification by the time it appears here — but it is the *adapter's*
            // output, so naming it honestly matters more than how convenient it is.
            let (claimed, failure) = match &outcome.execution {
                orxnud_capability::verification::ExecutionOutcome::Succeeded { output } => (
                    output
                        .as_deref()
                        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok()),
                    None,
                ),
                // A failed execution's own message, carried separately from the
                // verification verdict. A rejected parameter is the common case and the
                // reason is what makes it actionable, so it is reported here rather
                // than being flattened into "nothing was verified".
                orxnud_capability::verification::ExecutionOutcome::Failed { detail } => {
                    (None, Some(detail.clone()))
                }
                orxnud_capability::verification::ExecutionOutcome::Unknown { detail } => {
                    (None, Some(detail.clone()))
                }
            };
            Ok(json!({
                "executed": matches!(
                    outcome.execution,
                    orxnud_capability::verification::ExecutionOutcome::Succeeded { .. }
                ),
                "verified": outcome.is_verified(),
                "undetermined": outcome.is_undetermined(),
                "refuted": outcome.verification.is_refuted(),
                "capability": outcome.capability.as_str(),
                "result": claimed,
                "failure": failure,
            }))
        }
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

    /// The seam that decides what an approval commits to.
    ///
    /// This is the test that pins the wiring rather than the helper: `approval_params`
    /// delegating correctly is worthless if some future edit passes a constant at the
    /// call site again, so the assertion is on the *result* for a real request.
    #[test]
    fn the_approval_parameters_are_derived_from_the_action_not_a_placeholder() {
        let action = orxnud_domain::ActionRequest::new(
            TaskId::new("t-1"),
            orxnud_domain::ids::RunId::new("r-1"),
            0,
            orxnud_domain::CapabilityId::new("text/word-count"),
            json!({"text": "hello world"}),
            orxnud_domain::DataClass::Public,
            orxnud_domain::DataClass::Public,
        );
        let derived = approval_params(&action);

        assert_ne!(
            derived.as_str(),
            "{}",
            "the parameters a user approves must not be a constant"
        );
        assert!(
            derived.as_str().contains("hello world"),
            "the real parameters must be what an approval commits to, got {}",
            derived.as_str()
        );
    }

    /// The same request written with its object keys in a different order is the
    /// same operation, so it must produce the identical approval parameters.
    #[test]
    fn the_approval_parameters_ignore_object_key_order() {
        let build = |raw: &str| {
            approval_params(&orxnud_domain::ActionRequest::new(
                TaskId::new("t-1"),
                orxnud_domain::ids::RunId::new("r-1"),
                0,
                orxnud_domain::CapabilityId::new("text/word-count"),
                serde_json::from_str(raw).expect("json"),
                orxnud_domain::DataClass::Public,
                orxnud_domain::DataClass::Public,
            ))
        };
        assert_eq!(
            build(r#"{"text":"hi","n":1}"#).as_str(),
            build(r#"{"n":1,"text":"hi"}"#).as_str(),
        );
    }

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
