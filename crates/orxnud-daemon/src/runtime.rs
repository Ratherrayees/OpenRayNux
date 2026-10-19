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
//! # Concurrency: what is serialised, and what is not
//!
//! [`Daemon::dispatcher`] takes `&mut self` because the governed dispatcher holds
//! `&mut PolicyEngine` — V-41's single-writer guarantee. So a governed dispatch is
//! serialised through one `tokio::sync::Mutex` around the daemon, and that is the
//! correct shape rather than a compromise: two concurrent policy evaluations were
//! never possible, and the alternative would be to weaken the guarantee to gain
//! throughput nobody needs yet.
//!
//! **Three things therefore do not wait for that lock**, and each was measured rather
//! than assumed. The transport is in [`crate::serve`].
//!
//! * **Connections are served concurrently**, each on its own task, within a bounded
//!   ceiling and under a bounded deadline. This module used to await every connection
//!   inline in the accept loop, so one peer that opened a socket and never finished its
//!   frame prevented every other client from being served.
//! * **`daemon/status` takes no lock at all.** It reads a snapshot of composition state
//!   taken before the endpoint was bound (`serve::StatusSnapshot`), so a health check
//!   cannot queue behind a dispatch or a model call.
//! * **The provider's network round trip is not held under the lock.** Both model routes
//!   are gathered, released, called and then written back under the repository's own
//!   fencing — see `gather_proposal_context` and `call_provider`.
//!
//! # What is still serialised, and why that is not yet fixed
//!
//! **A Tier-1 dispatch holds the lock across the sandbox execution**, which is up to ten
//! seconds. `Dispatcher::dispatch` is a synchronous function borrowing `&mut Daemon`, and
//! it settles its own audit obligation internally, so there is no seam at which the lock
//! could be released mid-effect without breaking that obligation. Narrowing it is a
//! change to the dispatcher — a seam between "authorised and audited" and "executed and
//! settled" — not to the transport, and it is **not** attempted here. What a request
//! needs durable state will therefore still queue behind an in-flight sandboxed write; the
//! health probe does not, which is why the diagnostic stays usable.
//!
//! Nothing holds the lock across a capability's execution *and* something that can
//! block the runtime indefinitely: the deadline and output caps in the sandbox
//! contract are what bound that, and they are enforced below this layer.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use orxnud_capability::dispatch::Dispatcher;
use orxnud_domain::ids::{CapabilityId, TaskId};
use orxnud_domain::platform::SecretsContract;
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_platform_ipc::{IpcError, LocalStream, endpoint_for};
use orxnud_protocol::error::{ProtocolError, RpcError, RpcErrorCode};
use orxnud_protocol::frame::{Request, RequestId, Response};
use orxnud_protocol::method::Method;
use orxnud_store::task_repo::{EffectStatus, NewTask};
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

/// A condition in which **no caller action changes the outcome**.
///
/// # Why this is an enum and not a string
///
/// `INTERNAL_ERROR` is a positive claim, and V-90 exists because that claim was made by
/// default: any failure that reached `RequestError::Refused { reason: e.to_string() }`
/// became `INTERNAL_ERROR`, so a stale approval and a corrupt database row were
/// indistinguishable to a client. `DispatchError` has eleven variants and `DenialReason`
/// has seventeen, and both were flattened into one code.
///
/// Naming a fault here is therefore an assertion that has to be defended. Each variant
/// below carries that argument, and adding one is a reviewable act rather than a free-form
/// string. The converse also holds and is the more important half: **there is no way to
/// write an `Internal` error without choosing from this list**, so a new caller-fixable
/// condition cannot quietly become an internal fault merely because nobody classified it.
///
/// # What is deliberately *not* here
///
/// Anything a caller or an operator can repair. A missing credential, a host that cannot
/// establish sandbox guarantees, an unwritable audit journal, an expired approval and an
/// unknown capability are all refusals a person can act on, and each maps to the class
/// named by its recovery. They are absences from this list on purpose: the list is the
/// exhaustive answer to "what is actually unrecoverable", and adding to it should feel
/// wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalFault {
    /// Durable state does not add up: an unreadable parameters column, a digest that is
    /// not hex, a task whose counters cannot be true.
    ///
    /// Not caller-actionable and not configuration-actionable. A caller cannot cause a row
    /// to stop parsing, and no setting restores it; recovery is repair or rebuild of the
    /// database, which is an operator action outside the protocol entirely.
    DurableStateCorrupt,

    /// The database could not be read or written.
    ///
    /// A storage fault rather than a logic fault, and retrying reaches the same fault. It
    /// shares `INTERNAL_ERROR` with corruption because from the protocol's point of view
    /// both are "the daemon cannot answer a question about its own state right now", and
    /// neither is something a client can fix by changing its request.
    StorageUnavailable,

    /// The in-process observation store is unusable because a previous holder panicked
    /// while holding workspace content.
    ///
    /// A poisoned lock is the *consequence* of a panic, and the panic is a daemon defect, so
    /// reporting this as an environment outage would be dishonest about the cause. No
    /// content was disclosed and nothing was written, so the disclosure is fail-closed.
    DisclosureStorePoisoned,

    /// A capability adapter ran and failed, timed out, or did not report.
    ///
    /// Not a permission problem — the invocation was already authorised — and not a caller
    /// input problem: the request was valid. It is also not one of the known environment
    /// gaps (no sandbox, no credential), which have their own variants and their own
    /// remedies. A client told "internal" here files a report, which is the right action
    /// for a capability that cannot do its job.
    CapabilityExecutionFailed,

    /// Verification could not be performed, so the effect is *undetermined* rather than
    /// verified.
    ///
    /// Reported as a fault because the verifier is part of the daemon: a verifier that
    /// cannot check an effect is a defect in the thing whose job is checking effects.
    CapabilityVerificationFailed,

    /// An adapter called back into the dispatcher while its own dispatch was running.
    ///
    /// An impossible invariant, kept as a variant so the daemon refuses and reports rather
    /// than deadlocking or panicking on a reentrancy the type system did not prevent.
    ReentrantDispatch,

    /// A capability's declared schema could not be evaluated.
    ///
    /// The declaration is compiled in and there is no runtime configuration that could
    /// change it, so no operator action reaches this: it is a defect in the build rather
    /// than a misconfiguration of a correct build.
    InvalidCapabilitySchema,
}

impl InternalFault {
    /// The stable wire vocabulary word for this fault.
    ///
    /// Kebab-case and fixed, because it lands in `data.reason` and a client branches on
    /// it. The human sentence belongs in `data.detail`.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::DurableStateCorrupt => "durable-state-corrupt",
            Self::StorageUnavailable => "storage-unavailable",
            Self::DisclosureStorePoisoned => "disclosure-store-poisoned",
            Self::CapabilityExecutionFailed => "capability-execution-failed",
            Self::CapabilityVerificationFailed => "capability-verification-failed",
            Self::ReentrantDispatch => "reentrant-dispatch",
            Self::InvalidCapabilitySchema => "invalid-capability-schema",
        }
    }
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
        /// Why, when the reason alone is not specific enough.
        ///
        /// Owned rather than `&'static str` because the most useful refinement is
        /// frequently dynamic — which parameter the model got wrong — and a refusal that
        /// cannot name the offending field sends an operator to the logs instead.
        detail: Option<String>,
    },

    /// The method does not exist.
    #[error("unknown method: {0}")]
    UnknownMethod(String),

    /// The request violates the resource's own rules.
    ///
    /// Separate from [`Self::Invalid`] because that variant carries a *sentence* in
    /// `data.reason`, which is fine for the many "you sent something malformed" call sites
    /// and wrong here: this is a typed domain refusal whose stable word belongs in the
    /// machine-readable field and whose explanation belongs in the detail.
    #[error("invalid request: {reason}")]
    InvalidInput {
        /// A stable vocabulary word, never prose.
        reason: String,
        /// Optional detail. Already redacted.
        detail: Option<String>,
    },

    /// The referenced resource does not exist.
    ///
    /// Separate from [`Self::Invalid`] because the request was well-formed: there is simply
    /// no such task or proposal. A client told "invalid request" fixes its request; a client
    /// told this refreshes its view, which is the only thing that helps.
    #[error("the referenced resource does not exist: {reason}")]
    NotFound {
        /// A stable vocabulary word, never prose.
        reason: String,
        /// Optional detail. Already redacted.
        detail: Option<String>,
    },

    /// The request was valid, but the resource is not in a state where it is legal.
    ///
    /// One variant for every such condition — already decided, already terminal, a stale
    /// lease, another worker winning a race — because the *recovery* is the same in all of
    /// them: re-read the state and decide again. What differs is only the reason, and that
    /// travels in `data.reason` for a client that needs to tell them apart.
    ///
    /// A caller losing a race lands here, which is the point: one worker winning is a normal
    /// outcome and reporting it as an internal fault is what makes a correct system look
    /// broken.
    #[error("the request conflicts with the current state: {reason}")]
    Conflict {
        /// A stable vocabulary word, never prose.
        reason: String,
        /// Optional detail. Already redacted.
        detail: Option<String>,
    },

    /// Refused by policy or authority.
    ///
    /// No approval, a spent or expired one, a digest that no longer matches, a capability
    /// that is not granted. Retry fails identically; what is needed is a new human decision.
    #[error("the action was refused by policy or authority: {reason}")]
    Forbidden {
        /// A stable vocabulary word, never prose.
        reason: String,
        /// Optional detail. Already redacted.
        detail: Option<String>,
    },

    /// A dependency or the execution environment is unavailable.
    ///
    /// The operation is permitted and something it needs is missing: a provider that cannot
    /// be reached, an absent credential, sandbox guarantees that could not be established,
    /// a platform with no backend. The remedy is external — fix configuration, add the
    /// credential, wait — so this is deliberately not `INTERNAL_ERROR`.
    #[error("a required dependency is unavailable: {reason}")]
    Unavailable {
        /// A stable vocabulary word, never prose.
        reason: String,
        /// Optional detail. Already redacted.
        detail: Option<String>,
    },

    /// A condition no caller action repairs. The only class that maps to
    /// `INTERNAL_ERROR`.
    ///
    /// This carries an [`InternalFault`] rather than a free `String`, which is the whole
    /// mechanism. `RequestError::Refused { reason: <anything>, detail }` used to be how a
    /// dispatcher failure reached the wire, so any caller-actionable condition could be
    /// spelled into `INTERNAL_ERROR` by anyone who reached that constructor — which is
    /// exactly what V-90 records, on two routes and probably more.
    ///
    /// Naming a condition here is now a deliberate act that requires choosing one of the
    /// enumerated faults, each of which has been argued for individually below. A new
    /// caller-fixable refusal cannot acquire `INTERNAL_ERROR` by default, because there is
    /// no default.
    #[error("the request could not be served: {fault:?}")]
    Internal {
        /// Which internal condition, from a closed set.
        fault: InternalFault,
        /// Optional detail. Already redacted: never a raw `Error`, a path, or SQL.
        detail: Option<String>,
    },

    /// The proposal provider could not be asked, or could not answer.
    ///
    /// Separate from [`Self::Declined`] because the two mean opposite things to a
    /// caller: a decline is the deterministic pipeline working correctly on a bad
    /// proposal, while this is the pipeline never reaching a verdict. Collapsing them
    /// would let "the model was unreachable" be reported as "the model's proposal was
    /// refused", which is how an outage starts looking like a policy decision.
    #[error("proposal provider failed: {reason}")]
    ProviderRefused {
        /// A fixed vocabulary word, never prose.
        reason: String,
        /// The provider's own words, already free of any credential.
        detail: Option<String>,
    },
}

impl RequestError {
    /// The JSON-RPC error this becomes.
    pub(crate) fn to_rpc(&self) -> RpcError {
        match self {
            // Found by the V-90 sweep: this was the same defect as the dispatcher's
            // `e.to_string()` calls, on the frame-decode path rather than the dispatch
            // path -- "malformed frame: EOF while parsing a value at line 1 column 19" was
            // landing in the field a client branches on, so classifying a parse failure
            // meant substring-matching serde's English. Now the word is fixed and the
            // parser's own explanation is the detail.
            Self::Malformed(why) => RpcError::new(RpcErrorCode::PARSE_ERROR, "malformed request")
                .with_data(json!({
                    "reason": "malformed-frame",
                    "detail": why,
                })),
            // The explanation is prose *because it has to be*: "which of your forty fields
            // is wrong, and how" has no stable vocabulary word. So the word goes in the
            // machine-readable field and the prose in the human one.
            //
            // This used to be the other way round, which meant every client that wanted to
            // classify a malformed request had to string-match English.
            Self::Invalid(why) => RpcError::new(RpcErrorCode::INVALID_REQUEST, "invalid request")
                .with_data(json!({
                    "reason": "invalid-request",
                    "detail": why,
                })),
            Self::Declined { reason, detail } => {
                let mut data = json!({ "reason": reason });
                if let Some(d) = detail {
                    data["detail"] = json!(d);
                }
                RpcError::new(RpcErrorCode::INVALID_REQUEST, "invalid request").with_data(data)
            }
            // Typed domain refusal: the specific word is stable, so unlike `Invalid` it can
            // be branched on directly.
            Self::InvalidInput { reason, detail } => {
                let mut data = json!({ "reason": reason });
                if let Some(d) = detail {
                    data["detail"] = json!(d);
                }
                RpcError::new(RpcErrorCode::INVALID_REQUEST, "invalid request").with_data(data)
            }
            Self::NotFound { reason, detail } => {
                let mut data = json!({ "reason": reason });
                if let Some(d) = detail {
                    data["detail"] = json!(d);
                }
                RpcError::new(RpcErrorCode::RESOURCE_NOT_FOUND, "no such resource").with_data(data)
            }
            Self::Conflict { reason, detail } => {
                let mut data = json!({ "reason": reason });
                if let Some(d) = detail {
                    data["detail"] = json!(d);
                }
                RpcError::new(
                    RpcErrorCode::CONFLICT,
                    "the request conflicts with the current state",
                )
                .with_data(data)
            }
            Self::Forbidden { reason, detail } => {
                let mut data = json!({ "reason": reason });
                if let Some(d) = detail {
                    data["detail"] = json!(d);
                }
                RpcError::new(
                    RpcErrorCode::FORBIDDEN,
                    "the action was refused by policy or authority",
                )
                .with_data(data)
            }
            Self::Unavailable { reason, detail } => {
                let mut data = json!({ "reason": reason });
                if let Some(d) = detail {
                    data["detail"] = json!(d);
                }
                RpcError::new(
                    RpcErrorCode::ENVIRONMENT_UNAVAILABLE,
                    "a required dependency is unavailable",
                )
                .with_data(data)
            }
            Self::UnknownMethod(m) => RpcError::method_not_found(m),
            Self::ProviderRefused { reason, detail } => {
                let mut data = json!({ "reason": reason });
                if let Some(d) = detail {
                    data["detail"] = json!(d);
                }
                // Environment, not internal. This variant only ever exists because the
                // *provider* could not be used: no provider configured, no credential, an
                // unreachable or refusing model. The daemon and its code are working; the
                // thing it depends on is absent. Reporting `INTERNAL_ERROR` here told an
                // operator their daemon was broken when the actual fix is `configure` or
                // `doctor` -- the single most misleading thing this whole taxonomy could do,
                // since it sends the reader to a bug report instead of their own config.
                RpcError::new(
                    RpcErrorCode::ENVIRONMENT_UNAVAILABLE,
                    "the proposal provider could not be used",
                )
                .with_data(data)
            }
            Self::Internal { fault, detail } => {
                let mut data = json!({ "reason": fault.reason() });
                if let Some(d) = detail {
                    data["detail"] = json!(d);
                }
                RpcError::new(
                    RpcErrorCode::INTERNAL_ERROR,
                    "the request could not be served",
                )
                .with_data(data)
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
    ///
    /// An `Arc` rather than a bare mutex so a per-connection task can hold it for the
    /// life of that connection (`serve.rs`). A bare `Mutex` cannot cross a task boundary
    /// at all, and the alternative — a `&'static` obtained by transmuting a borrow — is
    /// exactly what gate **G4** exists to forbid.
    governed: Arc<tokio::sync::Mutex<(Daemon, S, TaskService)>>,
    /// Approved, verified reads waiting to inform the next proposal.
    ///
    /// Its own small lock rather than the governed one, and deliberately: the governed mutex
    /// serialises task writes against governed dispatch, and a request that is only assembling
    /// a prompt should not queue behind a sandboxed dispatch. Every operation on this store is
    /// a bounded in-memory scan, so the lock is never held across I/O.
    ///
    /// Ephemeral by decision (ADR-0045 D4): a restart empties it, which is the fail-safe
    /// direction. See `ObservationStore` for why erasure is a stronger form of single-use than
    /// a durable flag would be.
    observations: Arc<std::sync::Mutex<crate::observation::ObservationStore>>,
    /// Held so a caller can report *which* backend answered.
    backend: &'static str,
    /// The endpoint removal to perform on shutdown, if any.
    cleanup: Option<PathBuf>,
    /// The proposer this daemon asks.
    ///
    /// Owned per runtime rather than held in a process-wide slot. The slot was tried
    /// first and it is wrong: it cannot be scoped against concurrency, so a test that
    /// installed a deliberately malformed provider changed the answer for every other
    /// test running at the same time — which the suite demonstrated by failing a test
    /// that had nothing to do with it. A process-global mutable value is only safe when
    /// there is exactly one value for the life of the process, and a test seam needs the
    /// opposite. Per-runtime also makes the real thing simpler: two daemons in one process
    /// can legitimately be configured differently.
    /// `None` means no provider is configured, and that is a refusal rather than a
    /// fallback. See [`scripted_proposer`].
    proposer: Option<Arc<dyn crate::proposer::ProposalProvider>>,
    /// The operating-system user this installation belongs to.
    ///
    /// Established once at startup from the bound endpoint's own metadata, and consulted
    /// for every connection. See [`InstallationIdentity`].
    installation: InstallationIdentity,
    /// The composition facts `daemon/status` reports, read once while nothing else can
    /// hold the mutex. See [`crate::serve::StatusSnapshot`] for why a health check must
    /// not queue behind a dispatch.
    status: Arc<crate::serve::StatusSnapshot>,
    /// How long a connection may take and how many may be in flight. See
    /// [`crate::serve::ServeLimits`]; every field is a bound, and none is unbounded.
    limits: crate::serve::ServeLimits,
}

impl<S: SecretsContract> std::fmt::Debug for Runtime<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("endpoint", &self.endpoint)
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl<S: SecretsContract + Send + Sync + 'static> Runtime<S> {
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
        Self::start_unconfigured(paths, secrets).await
    }

    /// Starts a runtime with **no** proposal provider.
    ///
    /// What [`Runtime::start`] does. Named separately so the absence is visible at the
    /// call site: `task/ai-propose` on such a runtime answers `provider-not-configured`.
    pub async fn start_unconfigured(paths: Paths, secrets: S) -> Result<Self, RuntimeError> {
        Self::build(paths, secrets, None).await
    }

    /// Starts a runtime that asks `proposer`.
    ///
    /// The public form of the configuration seam: a caller supplies a provider and gets
    /// a daemon that uses it, with no global state and nothing to clean up afterwards.
    pub async fn start_with(
        paths: Paths,
        secrets: S,
        proposer: Arc<dyn crate::proposer::ProposalProvider>,
    ) -> Result<Self, RuntimeError> {
        Self::build(paths, secrets, Some(proposer)).await
    }

    /// Starts a runtime that **grants** the argv-payload exception for this process.
    ///
    /// The only way left to grant it. There is deliberately no configuration key and no
    /// environment variable (see the note on `Daemon` in `lib.rs`), because R-1's
    /// exception requires an owner decision with a bounded period, a named host model
    /// and a review date, and a configuration value carries none of those while being
    /// settable by anything running as the user.
    ///
    /// What this trades away, stated plainly: a code-level grant is reachable by an
    /// embedder of this crate and by any test. That is the accepted cost of keeping the
    /// governed-path suites real, and it is visible -- this name is greppable, the call
    /// lands in review, and `no_configuration_key_or_environment_variable_can_permit_an_
    /// argv_payload` in `lib.rs` fails if anyone adds the ambient route back.
    ///
    /// **Delete this when S-17 lands.** Until then it is a test affordance wearing a
    /// production signature, and it should not outlive the reason it exists.
    pub async fn start_permitting_argv_payload_exposure(
        paths: Paths,
        secrets: S,
    ) -> Result<Self, RuntimeError> {
        let daemon = Daemon::compose(paths.clone()).with_argv_payload_exception_for_this_process();
        Self::finish(paths, secrets, daemon, None).await
    }

    async fn build(
        paths: Paths,
        secrets: S,
        proposer: Option<Arc<dyn crate::proposer::ProposalProvider>>,
    ) -> Result<Self, RuntimeError> {
        Self::finish(paths.clone(), secrets, Daemon::compose(paths), proposer).await
    }

    /// Everything after the daemon is composed.
    ///
    /// Split out so [`Self::build`] and
    /// [`Self::start_permitting_argv_payload_exposure`] share one sequence. They differ
    /// only in how the daemon was composed, and the steps after that must not be able
    /// to drift apart, because the order is load-bearing: security state, then the task
    /// subsystem, then `start`, and only then is anything reachable.
    async fn finish(
        paths: Paths,
        secrets: S,
        mut daemon: Daemon,
        proposer: Option<Arc<dyn crate::proposer::ProposalProvider>>,
    ) -> Result<Self, RuntimeError> {
        // 1 + 2 + 3. Durable security state, verified, attached.
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
        // Read before the endpoint moves into the struct: the owner is a property of the
        // path on disk, and a runtime that could not read it will refuse every connection
        // rather than serve an unattributable one.
        let installation = InstallationIdentity::establish(&bound);
        let governed = Arc::new(tokio::sync::Mutex::new((daemon, secrets, tasks)));

        // Composition facts for `daemon/status`, read here — after security state is
        // attached, before the endpoint is bound — so serving them later never needs the
        // governed mutex. See `crate::serve::StatusSnapshot`.
        let status = crate::serve::StatusSnapshot::capture(&*governed.lock().await);

        Ok(Self {
            endpoint: bound,
            listener: Arc::new(listener),
            governed,
            observations: Arc::new(std::sync::Mutex::new(
                crate::observation::ObservationStore::new(),
            )),
            backend: orxnud_platform_ipc::backend_name(),
            cleanup: Some(endpoint),
            proposer,
            installation,
            status: Arc::new(status),
            limits: crate::serve::ServeLimits::default(),
        })
    }

    /// The argv exposure to disclose at startup, if this build has any.
    ///
    /// For the banner. Reads the same composed state `daemon/status` reads, so the two
    /// cannot report different capabilities for the same daemon -- if they could, an
    /// operator would have two answers and no way to choose between them.
    ///
    /// `None` means nothing is exposed, and the caller prints nothing rather than
    /// printing a reassuring line that would read the same on an exposed build.
    #[must_use]
    pub fn argv_payload_disclosure(&self) -> Option<ArgvPayloadDisclosure> {
        // `try_lock` rather than `lock`: this runs before the serve loop starts, on a
        // runtime nothing else holds yet, and a startup banner must not be able to
        // deadlock behind an in-flight request. If something did hold it, the
        // composition is already fixed and re-reporting it is what the banner is for, so
        // reading it later would be wrong too -- declining to report is the honest
        // answer, and `daemon/status` still serves the same fact to a client that asks.
        let Ok(governed) = self.governed.try_lock() else {
            return None;
        };
        argv_payload_disclosure(&governed)
    }

    /// Returns this runtime with `proposer` as the proposer it asks.
    ///
    /// Available after [`Runtime::start`] because the proposer is only read while
    /// serving, and the endpoint is already bound by then. Takes and returns `Self` so it
    /// composes as `Runtime::start(..).await?.with_proposer(p)` without a mutable
    /// borrow, which matters because `serve` consumes the runtime.
    #[must_use]
    pub fn with_proposer(mut self, proposer: Arc<dyn crate::proposer::ProposalProvider>) -> Self {
        self.proposer = Some(proposer);
        self
    }

    /// The proposer this runtime asks.
    ///
    /// `pub` so a test can assert on the very provider a dispatch would use, rather than
    /// on a copy of it.
    #[must_use]
    pub fn proposer(&self) -> Option<&Arc<dyn crate::proposer::ProposalProvider>> {
        self.proposer.as_ref()
    }

    /// Whether this runtime has a proposal provider.
    ///
    /// `false` means `task/ai-propose` answers `provider-not-configured`.
    #[must_use]
    pub fn has_proposer(&self) -> bool {
        self.proposer.is_some()
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

    /// Whether the durable audit journal was found fully settled when it was loaded.
    ///
    /// # Why production asks this at all
    ///
    /// The dispatcher settles every authorisation by construction now, so this is not
    /// the primary defence — it is the check on the consequence. A `false` here means
    /// the journal contains an authorisation that no terminal record names, which is
    /// either a process that died mid-dispatch or a writer that skipped the settle.
    /// Both are facts about the world that a reader of the journal has to be told
    /// about, and until this existed nothing in production ever asked.
    ///
    /// Computed while the journal is being restored, before anything is served, so the
    /// answer describes what the *previous* process left behind rather than what this
    /// one has done so far.
    #[must_use]
    pub async fn restored_settlement(&self) -> orxnud_policy::SettlementReport {
        self.governed
            .lock()
            .await
            .0
            .policy()
            .restored_settlement()
            .cloned()
            .unwrap_or_default()
    }

    /// The live settlement state of the journal.
    ///
    /// For asserting the invariant after a dispatch, and for the status surface an
    /// operator can poll.
    #[must_use]
    pub async fn settlement_report(&self) -> orxnud_policy::SettlementReport {
        self.governed.lock().await.0.policy().settlement_report()
    }

    /// Serves until `shutdown` resolves, then releases the endpoint.
    ///
    /// Stops accepting first, then lets in-flight requests finish. That ordering is
    /// the graceful part: a request already being served gets to reach a defined
    /// outcome rather than having its socket torn out from under it.
    ///
    /// Each connection is served by its own task, and both a count and a time bound
    /// apply — see [`crate::serve::ServeLimits`] for the values and the reasoning.
    /// The previous implementation awaited every connection **inline** in this loop
    /// with no deadline, so one peer that opened a socket and never finished its frame
    /// prevented every other client from being served, for as long as it chose. That is
    /// reproducible from any process running as the daemon's own user, and is what
    /// `tests/serve_lifecycle.rs` now pins.
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
        mut self,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> Result<(), IpcError> {
        // The loop itself lives in `serve.rs`, beside the bounds that govern it. What
        // moves across the boundary is only the state: `Arc`s the loop can hand to a
        // per-connection task, plus the limits it enforces.
        //
        // `cleanup` is *taken* out of `self` rather than copied, because `serve` consumes
        // the runtime and the endpoint guard must own the one value it may unlink. Taking
        // it leaves `None` behind, so a second release cannot happen even if this function
        // were somehow re-entered.
        let cleanup = self.cleanup.take();
        let serving = crate::serve::Serving {
            listener: Arc::clone(&self.listener),
            governed: Arc::clone(&self.governed),
            proposer: self.proposer.clone(),
            observations: Arc::clone(&self.observations),
            installation: self.installation,
            status: Arc::clone(&self.status),
        };
        crate::serve::serve(serving, self.limits, cleanup, shutdown).await
    }

    /// The bounds this runtime's serving loop enforces.
    ///
    /// Read-only: the values are fixed at composition, because a limit that could be
    /// changed while serving would be a limit that could be raced.
    pub fn limits(&self) -> crate::serve::ServeLimits {
        self.limits
    }

    /// This runtime with different serving bounds.
    ///
    /// A builder rather than a configuration value, for the same reason the argv-payload
    /// exception is not one: a bound is a safety property, and a value that anything
    /// running as the user could set would be settable by a shell profile or a compromised
    /// dependency without an owner ever accepting it. Taken here, before `serve`, the
    /// change lands in review.
    ///
    /// Exists so the bounds can be driven *small* in a test without waiting out the
    /// production values - which is the only way to assert that a deadline is enforced
    /// rather than merely present.
    #[must_use]
    pub fn with_limits(mut self, limits: crate::serve::ServeLimits) -> Self {
        self.limits = limits;
        self
    }
}

/// Answers a single request on a single connection.
///
/// # Errors
///
/// [`IpcError`] if the peer could not be read from or written to. A *request* error
/// is answered on the wire and reported as `Ok`, because the peer did exactly what
/// we should let it do and learn that it was wrong.
pub(crate) async fn handle_connection<S: SecretsContract>(
    stream: &mut LocalStream,
    authenticated: AuthenticatedPrincipal,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
    provider: &Option<Arc<dyn crate::proposer::ProposalProvider>>,
    observations: &std::sync::Mutex<crate::observation::ObservationStore>,
    status: &crate::serve::StatusSnapshot,
    frame_read: std::time::Duration,
) -> Result<(), IpcError> {
    // The deadline on the read, and only on the read.
    //
    // `MAX_REQUEST_BYTES` bounds how *much* a peer may send; this bounds how *long* it may
    // take. Both are needed and neither substitutes for the other: a size bound alone
    // leaves a peer free to send one byte per hour forever, and a time bound alone leaves
    // it free to send 8 MiB in one millisecond.
    //
    // A peer that runs out of time is *not* a transport fault and *not* a disconnect. It
    // is answered with `Unavailable`, whose recovery is external — the daemon is fine,
    // the client was too slow — and the connection is dropped so the slot it held returns.
    let bytes =
        match tokio::time::timeout(frame_read, stream.read_line_bounded(MAX_REQUEST_BYTES)).await {
            Ok(outcome) => outcome,
            Err(_) => {
                let response = Response::err(
                    RequestId::Text("unknown".to_owned()),
                    RequestError::Unavailable {
                        reason: "request-read-deadline-exceeded".to_owned(),
                        detail: Some(format!(
                            "this peer did not finish sending one request within {}ms",
                            frame_read.as_millis()
                        )),
                    }
                    .to_rpc(),
                );
                // Best effort: if the peer is gone the answer is moot, and the connection ends
                // either way. A failure to write is not a reason to keep the slot.
                let _ = write_response(stream, &response).await;
                return Ok(());
            }
        };
    let bytes = match bytes {
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
    let outcome = route(
        &request,
        authenticated,
        governed,
        provider,
        observations,
        status,
    )
    .await;
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
/// The `argv_payload_exposure` block on `daemon/status`.
///
/// Returns `None` when no registered bundle exposes a payload, and the field is then
/// omitted entirely. **Absence is the signal**: a constant string would be present on
/// every build and would tell an operator nothing, and this is the field a reader
/// The argv exposure an operator is told about, on `daemon/status` and the banner.
///
/// One type for both surfaces, so they cannot drift: a banner that named a different
/// capability than `daemon/status`, or that described the exposure differently, would be
/// two answers to "is this build exposed?" and an operator would have to know which one
/// to believe.
///
/// Serialises with `exposed` / `permitted` / `refused`, and the caller inserts the whole
/// object under `argv_payload_exposure` **only when this exists at all**.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ArgvPayloadDisclosure {
    /// The exposure class, in the words the reader needs: what is readable, by whom, and
    /// for how long. Named here rather than as a bare string at the call site so that
    /// `daemon/status` and the banner say the same thing by construction.
    pub exposure: &'static str,
    /// Every registered bundle that puts user content in `argv`, with the most bytes
    /// each can place in a single argument string.
    ///
    /// A number per capability, not a boolean: "this build is exposed" and "up to
    /// 128 KiB of a user's file is in the process table" are different facts, and an
    /// operator deciding whether to accept the owner-approved exception needs the
    /// second one.
    pub exposed: Vec<ArgvExposureEntry>,
    /// Of those, the ones an owner-approved exception currently permits.
    pub permitted: Vec<String>,
    /// Of those, the ones the default posture refuses.
    pub refused: Vec<String>,
    /// How the operator changes the decision.
    pub control: &'static str,
    /// That the refusal is not a fix.
    pub status: &'static str,
}

/// One exposed capability, and what is known about the size of what it can leak.
///
/// The size is `null` whenever the implementation does not bound the payload itself,
/// which is the case for every caller-supplied payload. That is the honest answer: the
/// bytes are whatever the caller sent, and reporting a number here would state a host
/// kernel constant (`MAX_ARG_STRLEN`, which is `32 * PAGE_SIZE` and therefore differs
/// between a 4 KiB and a 64 KiB page) as though it were a property of this code.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ArgvExposureEntry {
    /// Which capability.
    pub capability: String,
    /// The bytes this implementation will place there, **if it bounds them itself**.
    /// `null` means it does not.
    pub implementation_bound_bytes: Option<usize>,
}

/// The `control` field of the argv-payload disclosure.
///
/// Named so a test can assert on the **value the daemon actually reports** rather
/// than on a copy of it. The wording was wrong: it described the transport as unfixed
/// until S-17, which had already landed, so it sent an operator after the wrong
/// remediation.
pub(crate) const ARGV_EXPOSURE_CONTROL: &str = "none a user can reach. No configuration \
    key and no environment variable can permit this, and a release build has no flag \
    that does either; the capability stays refused under ADR-0054 Decision 7 until its \
    R-1 evidence conditions are met. That is the plan's refusal posture, not a \
    degradation, and not a fix";

/// The `status` field of the argv-payload disclosure.
///
/// The transport change has landed; the refusal has not, deliberately. The wording
/// must not imply the capability is enabled, and must not claim R-1 is satisfied.
pub(crate) const ARGV_EXPOSURE_STATUS: &str = "OPEN -- the framed-stdin transport has \
    landed, but ADR-0054 Decision 7 keeps this capability refused by default until the \
    R-1 evidence conditions are met. Refusing by default limits reachability; it does \
    not remove the exposure for any execution that is permitted to run.";

/// What the operator is told when they have not asked for anything.
///
/// `None` when no registered bundle exposes a payload, and the caller must then leave the
/// field **absent** rather than `null`: absence is the signal, and a constant string (or a
/// constant `null`) would be a field that always reads the same and therefore says
/// nothing about whether it applies here.
pub(crate) fn argv_payload_disclosure<S: SecretsContract>(
    governed: &(Daemon, S, TaskService),
) -> Option<ArgvPayloadDisclosure> {
    // The dispatcher's own permit set, not a configuration lookup: there is no
    // configuration route any more, so the two cannot disagree.
    let exposure = governed
        .0
        .components()
        .dispatch
        .argv_payload_exposure(&governed.0.components().permitted_argv_payload);
    if exposure.is_empty() {
        return None;
    }
    let name = |id: &CapabilityId| id.to_string();
    let sized = |e: &orxnud_capability::dispatch::ArgvPayloadExposure| ArgvExposureEntry {
        capability: e.id.to_string(),
        implementation_bound_bytes: e.payload.implementation_bound(),
    };
    Some(ArgvPayloadDisclosure {
        exposed: exposure.iter().map(sized).collect(),
        exposure: "argv reaches the host process table, and /proc/<pid>/cmdline is \
                   mode 0444 for the life of the execution. Whether another uid can \
                   READ it is a property of this host's /proc, not of this program: \
                   cross-UID readability was DEMONSTRATED on the measured audit host \
                   with the default hidepid=0, and hidepid>=1 or a hardened kernel \
                   changes the answer. Do not read this field as a claim about every \
                   Linux host (V-67).",
        permitted: exposure
            .iter()
            .filter(|e| e.permitted)
            .map(|e| name(&e.id))
            .collect(),
        refused: exposure
            .iter()
            .filter(|e| !e.permitted)
            .map(|e| name(&e.id))
            .collect(),
        control: ARGV_EXPOSURE_CONTROL,
        status: ARGV_EXPOSURE_STATUS,
    })
}

/// Adds the disclosure to `status` only when there is one.
///
/// Separate from the disclosure itself so the absent case is testable: "the field is
/// missing" is a property of the JSON, and asserting it needs a daemon with nothing
/// exposed, which no shipped build is. This is the function production calls, so a test
/// on it is a test of the shipped behaviour rather than of a copy of the logic.
///
/// The `None` branch must **remove** the key rather than leave it: a field set to
/// `null` is still present, and a client asking "does this build expose argv payloads?"
/// cannot answer yes-or-no from a `null` that does not distinguish "not applicable" from
/// "no value".
fn insert_argv_disclosure(status: &mut serde_json::Value, exposure: Option<ArgvPayloadDisclosure>) {
    let Some(exposure) = exposure else {
        return;
    };
    status["argv_payload_exposure"] =
        serde_json::to_value(exposure).unwrap_or(serde_json::Value::Null);
}

/// Renders a capability list for the one-line banner, where an empty list must still read
/// as empty rather than as a blank the reader has to notice is missing.
pub fn join(ids: &[String]) -> String {
    if ids.is_empty() {
        "(none)".to_owned()
    } else {
        ids.join(", ")
    }
}

/// The exposed list for the banner, with the size, because the size is the point.
pub fn join_sized(entries: &[ArgvExposureEntry]) -> String {
    if entries.is_empty() {
        "(none)".to_owned()
    } else {
        entries
            .iter()
            .map(|e| match e.implementation_bound_bytes {
                // Never a fabricated number: `null` says "this implementation bounds
                // nothing", which is the truth for a caller-supplied payload.
                Some(n) => format!(
                    "{} (bounded at {n} bytes by this implementation)",
                    e.capability
                ),
                None => format!(
                    "{} (payload size not bounded by this implementation)",
                    e.capability
                ),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[allow(clippy::too_many_arguments)]
async fn route<S: SecretsContract>(
    request: &Request,
    authenticated: AuthenticatedPrincipal,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
    provider: &Option<Arc<dyn crate::proposer::ProposalProvider>>,
    observations: &std::sync::Mutex<crate::observation::ObservationStore>,
    status: &crate::serve::StatusSnapshot,
) -> Result<serde_json::Value, RequestError> {
    // Derived once per connection, before a method is chosen. Handlers receive the
    // *actor* rather than the principal, so nothing below this line can re-derive an
    // identity and no handler can reach the installation's uid at all.
    let actor = authenticated.actor();
    let Some(method) = Method::from_wire(&request.method) else {
        return Err(RequestError::UnknownMethod(request.method.clone()));
    };

    match method {
        Method::DaemonStatus => {
            // **No lock**, and deliberately. Every field here is composition state fixed
            // before the endpoint was bound, so reading it through the single-writer
            // mutex bought nothing and cost responsiveness: `doctor` is the command a
            // person runs when they think something is wrong, and it must not queue
            // behind a 60-second provider call or a 10-second sandboxed write. See
            // `crate::serve::StatusSnapshot`.
            //
            // The runtime sandbox capability below is the one field that is *not* from
            // the snapshot, because it is a property of the host rather than of the
            // composition and it is what the dispatcher consults; it is also a cheap
            // probe that takes no lock, so reading it now keeps the answer current
            // rather than reporting a cached verdict.
            // The host's *runtime* sandbox capability, not just the compile-time backend
            // name. `transport` above answers "which backend did this build select";
            // this answers "can a Tier-1 capability actually run here", which is the
            // question a caller — including the end-to-end tests — actually needs, and
            // the one that explains a refusal instead of hiding behind the name.
            let sandbox = orxnud_platform_sandbox::host_capability();
            let mut reply = json!({
                "status": "running",
                "protocol": orxnud_protocol::version::PROTOCOL_VERSION.as_u16(),
                "durable_audit": status.durable_audit(),
                "transport": orxnud_platform_ipc::backend_name(),
                "sandbox": {
                    "backend": sandbox.backend,
                    "mechanism": sandbox.mechanism,
                    "visibility": sandbox.guarantees.visibility,
                    "tree_lifetime": sandbox.guarantees.tree_lifetime,
                    "resources": sandbox.guarantees.resources,
                    "tier1_executable": sandbox.tier1_executable,
                },
                "capabilities_enabled": status.enabled_capabilities(),
            });
            // Absent when no registered bundle exposes a payload, so its presence is
            // itself the signal. A constant string here would be a field that always
            // reads the same and therefore says nothing.
            //
            // Inserted rather than written as `"key": argv_payload_disclosure(..)`:
            // `json!` turns a `None` into `null`, so the key would always be present and
            // a client distinguishing "not applicable" from "the value is null" would
            // have to know this implementation's internal type. The field has to be
            // *absent*, so it is inserted only when it has something to say.
            insert_argv_disclosure(&mut reply, status.argv_payload().cloned());
            Ok(reply)
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
        // Schedules are first-party durable state like the tasks. They grant nothing:
        // registering a schedule stores a row and nothing more, and the daemon's own timer
        // reads it. See `schedule` for why the authorised-by id is the authenticated
        // principal's rather than anything the request could have named.
        Method::ScheduleCreate | Method::ScheduleList => {
            schedule(method, request, authenticated, governed).await
        }
        Method::CapabilityDispatch => dispatch(request, &actor, governed).await,
        Method::CapabilityApprove => approve(request, &actor, governed).await,
        // First-party durable state, not capability execution. These go to the
        // TaskService and to nothing else.
        // First-party durable state, not capability execution. These go to the
        // TaskService and to nothing else.
        Method::TaskCreate
        | Method::TaskList
        | Method::TaskClaim
        | Method::TaskComplete
        | Method::TaskPropose
        | Method::TaskCancel => tasks(method, request, authenticated, governed).await,
        // Execution crosses from the task layer into the governed dispatcher, so it is
        // routed separately rather than through `tasks`: it needs the capability registry
        // and the sandbox backend, which `tasks` deliberately has no access to.
        Method::TaskExecute => {
            execute_proposal(request, &actor, governed, provider.as_ref(), observations).await
        }
        Method::TaskAiPropose => {
            ai_propose(
                request,
                authenticated,
                governed,
                provider.as_ref(),
                observations,
            )
            .await
        }
        // One boundary per call, and no execution: see `continue_task`.
        Method::TaskContinue => {
            continue_task(
                request,
                authenticated,
                governed,
                provider.as_ref(),
                observations,
            )
            .await
        }
    }
}

/// The single actor this runtime acts as.
///
/// The logical step an approval governs when it governs no task.
///
/// `orxnuctl capability approve` authorises one action outside any task, so it has exactly
/// one logical step and that step is 1. Named and explained rather than written as a bare
/// `1`, because a digest field that is always 1 is otherwise indistinguishable from one
/// filled in without thought.
const STANDALONE_APPROVAL_STEP: u32 = 1;

/// The operating-system user this installation belongs to.
///
/// # Why this is the reference, and not the caller
///
/// The daemon needs one question answered before it grants anything: *is this peer the
/// user this installation belongs to?* It answers it by comparing a kernel-reported uid
/// against the uid that owns the bound endpoint. Both halves are decided outside any
/// request, which is the entire point — a comparison against a value the caller could
/// name would be a comparison against itself.
///
/// # `Unavailable` is the fail-closed case, not an absence of one
///
/// A platform that cannot report an owner lands in [`Self::Unavailable`], and every
/// connection is then refused. That is the deliberate outcome for Windows, where no
/// local transport exists at all, and for any Unix whose endpoint metadata cannot be
/// read. The alternative — assume an owner so the daemon starts — would mean serving a
/// socket that cannot be attributed to anyone, which is the state this change exists to
/// end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstallationIdentity {
    /// The bound endpoint is owned by this uid.
    Owned(u32),
    /// The owner could not be established. Every connection is refused.
    Unavailable,
}

impl InstallationIdentity {
    /// Reads the owner of the bound endpoint.
    ///
    /// Unix-only in its implementation and total in its *result*: a platform without the
    /// metadata produces [`Self::Unavailable`] rather than a compile error or a guess.
    ///
    /// Read from the socket rather than from `geteuid(2)` deliberately: the two normally
    /// agree and stop agreeing in exactly the case that matters -- a daemon started by
    /// `sudo`, a system unit, or a launcher that drops privileges. There the process's
    /// uid need not be the user the installation is *for*, while the endpoint's owner is
    /// by definition, because it is the user who can reach it.
    ///
    /// The platform knowledge lives in `orxnud-platform-ipc::endpoint_owner_uid`: reading
    /// a uid is `cfg(target_os)`, and gate **G3** keeps that below this crate.
    fn establish(endpoint: &Path) -> Self {
        match orxnud_platform_ipc::endpoint_owner_uid(endpoint) {
            Some(uid) => Self::Owned(uid),
            None => Self::Unavailable,
        }
    }
}

/// What a connection proved about itself, established before any request is read.
///
/// # The smallest name that is accurate
///
/// A [`orxnud_platform_ipc::TransportPrincipal`] is a fact about a socket. An
/// `AuthenticatedPrincipal` is a fact about a *caller*, and the difference is the whole
/// boundary: the first is what the kernel said, the second is what the daemon concluded
/// from it by comparison with the installation. Keeping them as separate types is what
/// stops a uid being carried further up as though it were authority — becoming an
/// [`orxnud_domain::Actor`] is the only way across, and it is a single conversion with
/// one variant to convert to.
///
/// There is deliberately no "unknown" variant. A connection whose identity could not be
/// established is refused before it becomes one of these, so the absence of such a case
/// is the type saying that an unauthenticated caller cannot be *represented* as a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticatedPrincipal {
    /// The peer is the operating-system user this installation belongs to.
    ///
    /// Carries no uid of its own: the installation already is the identity, and keeping a
    /// second copy invites the two to be compared and found equal by accident.
    InstallationOwner,
}

impl AuthenticatedPrincipal {
    /// The actor this principal is entitled to be.
    fn actor(self) -> orxnud_domain::Actor {
        match self {
            Self::InstallationOwner => local_actor(),
        }
    }

    /// The human whose authority this principal spends.
    ///
    /// Exists so a delegated `Actor::Ai` is built from the authenticated principal rather
    /// than from a string literal. Returning [`orxnud_domain::ids::UserId`] rather than an
    /// `Option` is the load-bearing part: a root that *could* be absent would need a
    /// fallback at the delegation site, and that fallback would be an invented identity —
    /// the exact defect being removed. Here there is no way to write "no human to
    /// delegate from", because this daemon has one principal and it is a human.
    fn user(self) -> orxnud_domain::ids::UserId {
        match self {
            Self::InstallationOwner => orxnud_domain::ids::UserId::new("local"),
        }
    }
}

/// Decides who a freshly accepted connection is.
///
/// # The whole trust boundary, in one function
///
/// Everything the daemon will ever grant flows through here, and there are three
/// outcomes: an authenticated principal, a refusal, or — on a platform that cannot
/// answer — a refusal. The last is why there is no default arm.
///
/// # Why a wrong peer is FORBIDDEN and not CONFLICT
///
/// The taxonomy from ADR-0050 groups codes by *recovery*, and this is the case that
/// makes the grouping worth stating: there is nothing the caller can do to change the
/// outcome. Not retrying, not re-reading state, not obtaining another approval. Either
/// this peer is the installation's owner or it is not, and the kernel decided that.
/// `CONFLICT` would tell the client to try again and `INVALID_REQUEST` to edit a request
/// that was never the problem. `FORBIDDEN` is the only one whose instruction — *this
/// action is refused by authority* — is true.
///
/// # Why the refusals carry no detail
///
/// A refusal never names a uid, a socket path, or a syscall. The caller is told it is
/// not the owner; how the daemon knows that is not information it is entitled to, and a
/// uid in an error message would be an operating-system identifier leaving the daemon for
/// no benefit.
pub(crate) fn authenticate(
    stream: &LocalStream,
    installation: InstallationIdentity,
) -> Result<AuthenticatedPrincipal, RequestError> {
    // Refuse before asking who the peer is: with no installation to compare against
    // every comparison would fail for the same reason, and a reason that is not about the
    // caller is not worth transmitting.
    let owner = match installation {
        InstallationIdentity::Owned(uid) => uid,
        InstallationIdentity::Unavailable => {
            return Err(RequestError::Unavailable {
                reason: "peer-identity-unavailable".to_owned(),
                detail: Some(
                    "this daemon cannot establish the identity of a local caller on this \
                     platform, so no caller can be authenticated"
                        .to_owned(),
                ),
            });
        }
    };

    let principal = stream.principal().map_err(|_| RequestError::Unavailable {
        reason: "peer-identity-unavailable".to_owned(),
        detail: Some(
            "the operating system did not report this caller's identity, so it cannot be \
             authenticated"
                .to_owned(),
        ),
    })?;

    if !principal.is_owner(owner) {
        return Err(RequestError::Forbidden {
            reason: "not-installation-owner".to_owned(),
            detail: Some(
                "this daemon serves only the user it was installed for; this connection \
                 is not from that user"
                    .to_owned(),
            ),
        });
    }

    Ok(AuthenticatedPrincipal::InstallationOwner)
}

/// Named, because it has to be *the same* actor at approval time and at dispatch time:
/// the digest is computed over the actor's label and authority root, so two structurally
/// identical actors that differed in either would produce approvals that never verify,
/// and the symptom would be a mysterious refusal rather than a bug.
///
/// # Not reachable from a request
///
/// Every actor the daemon constructs is now built from an [`AuthenticatedPrincipal`],
/// and the only way to obtain one is [`authenticate`]. Note the empty parameter list:
/// there is no variant of this call that accepts a caller-supplied identity, and adding
/// one would be the regression this milestone exists to prevent.
fn local_actor() -> orxnud_domain::Actor {
    orxnud_domain::Actor::Human {
        // A *stable application identity*, not a derived value. It is what the approval
        // digest already binds (`orxnud_policy::digest::canonical_bytes` hashes the
        // approver's label and authority root), so deriving anything else would
        // invalidate every approval a previous daemon issued, for no security gain. The
        // uid is used to decide *whether* this principal exists and then discarded,
        // which also keeps an operating-system identifier out of every audit record.
        user: orxnud_domain::ids::UserId::new("local"),
        // Records that the caller reached the daemon over a local, same-owner socket.
        // It does **not** assert the caller is a person at a keyboard: a Unix domain
        // socket cannot tell an interactive shell from a cron job. Nothing here proves
        // interactivity and nothing depends on it — `AuthChannel` is not in the approval
        // digest and no policy rule reads it. Recorded as a known limit rather than
        // dressed up as evidence.
        via: orxnud_domain::actor::AuthChannel::LocalInteractive,
    }
}

/// Asks the configured proposer what it would do with a task, and persists a proposal
/// if — and only if — its answer is one this runtime can act on.
///
/// # The whole authority of this route
///
/// A model contributes exactly one thing: text. The capability allowlist, the parameter
/// validation, the durable proposal, the decision and the dispatch are all this
/// function's and the types it calls. There is no branch here that reaches an
/// `ApprovalRecord`, a `Dispatcher`, the policy engine or the store outside
/// `propose_action`, so "the model approved this" is not a state the code can represent
/// (ADR-0012, ADR-0037, V-71).
///
/// # Errors
///
/// [`RequestError::Invalid`] for a malformed request, or a structured refusal when the
/// model's output is not a proposal this build understands.
async fn ai_propose<S: SecretsContract>(
    request: &Request,
    authenticated: AuthenticatedPrincipal,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
    provider: Option<&Arc<dyn crate::proposer::ProposalProvider>>,
    observations: &std::sync::Mutex<crate::observation::ObservationStore>,
) -> Result<serde_json::Value, RequestError> {
    let delegated_by = authenticated.user();
    // No provider configured is a refusal with its own reason, never a scripted answer.
    // A daemon that cannot reach a model says so; it does not pretend the model agreed.
    let Some(provider) = provider else {
        return Err(RequestError::ProviderRefused {
            reason: crate::proposer::ProviderError::NotConfigured
                .reason()
                .to_owned(),
            detail: Some(
                "this daemon has no proposal provider; start it with a provider configured"
                    .to_owned(),
            ),
        });
    };
    let params = request.params.clone().unwrap_or(json!({}));
    let task_id = required_str(&params, "task")?;
    check_len("task", &task_id, MAX_TASK_ID_BYTES)?;
    let worker = required_str(&params, "worker")?;
    check_len("worker", &worker, MAX_TASK_ID_BYTES)?;

    // The gather/call/persist split, written out here rather than hidden behind a helper,
    // because **the release is the whole point** and a reader should not have to know a
    // helper exists to see it:
    //
    //   lock -> gather the menu and the context      (durable reads, no waiting)
    //   drop the lock
    //   call the provider                          (up to 60s, no lock held)
    //   lock -> persist, under the repository's own fencing
    //
    // The `?` between the phases means the lock is *not* held on the error path either,
    // which is what stops a failed model call from being the thing that wedges the daemon.
    // Everything `persist_proposal` and `complete_task_with` need is re-validated by the
    // store inside its own transaction, so a task that changed state during the call is
    // refused at the write rather than written on stale knowledge.
    let (asked, now) = {
        let mut g = governed.lock().await;
        let now = g.2.clock_now_ms();
        let ask = gather_proposal_context(&mut g, provider, &task_id, observations)?;
        (ask, now)
    };
    let text = call_provider(provider, &asked.ctx).await?;
    let asked = interpret_provider_answer(text, &asked)?;

    let mut g = governed.lock().await;
    let disclosed_json = disclosure_json(&asked.disclosed);
    let validated = match asked.outcome {
        crate::proposer::ProposalOutcome::Step(v) => v,
        // The model says there is nothing to do. Completing from here is the same fenced
        // engine completion any other terminal report goes through; the model did not move
        // the task, it answered a question the runtime asked. See ADR-0047.
        crate::proposer::ProposalOutcome::Done { summary } => {
            let finished =
                g.2.complete_task_with(
                    &TaskId::new(task_id.as_str()),
                    &worker,
                    now,
                    TaskState::Completed,
                    false,
                    Some(&format!("no work required: {summary}")),
                    None,
                )
                .map_err(task_fault)?;
            return Ok(json!({
                "completed": true,
                "summary": summary,
                "state": finished.state.as_wire_str(),
                "proposed_by": delegated_actor(&delegated_by, &task_id, provider.model_id()).label(),
                "model": provider.model_id(),
            }));
        }
    };

    let canonical = orxnud_policy::canonical_params(&validated.params);
    let proposal_id = format!("p-{task_id}-{now}");
    // The provider instance that just answered is the only authority on which model
    // produced this text. Read from it rather than from configuration, so the audit cannot
    // name a model that did not answer.
    let proposer = delegated_actor(&delegated_by, &task_id, provider.model_id());
    let proposed = persist_proposal(
        &mut g,
        ProposalWrite {
            proposal_id: &proposal_id,
            task_id: &task_id,
            worker: &worker,
            validated: &validated,
            canonical_params: canonical.as_str(),
            proposer: &proposer,
            now,
        },
    )?;

    Ok(json!({
        "proposal": proposal_json(&proposed),
        "waiting_for": "human-approval",
        // Restated for the caller, and not because it is a secret: the whole claim of
        // this path is that a model asked and a person decides, so both facts belong in
        // the reply rather than only in the database.
        "proposed_by": proposer.label(),
        "model": provider.model_id(),
        // Content that left the machine with this request, named and counted. An empty list
        // here is the normal case and is not an error: most proposals carry no content.
        "disclosed": disclosed_json,
    }))
}

/// Everything the model is shown, gathered while the governed state is locked.
///
/// # Shared, so the two model routes cannot drift
///
/// `task/ai-propose` and `task/continue` both come through here and through
/// [`call_provider`] and [`interpret_provider_answer`], so what the model is shown, the
/// strict parse, the allowlist check and the refusal taxonomy are one implementation. A
/// change to what the model is offered cannot land in one route and not in the other.
///
/// The task is re-read here rather than passed in, because both callers need the row they
/// read for a different reason — one to check a lease, one to check a boundary — and the
/// `attempt_no` in the context must be the attempt the claim just created.
///
/// # Why this is a separate function
///
/// Before the split, this whole assembly ran inside `ask_next_step`, which held the
/// governed mutex across the provider's network round trip. That made a slow model — up
/// to `http_provider.rs`'s 60 s — hold the single mutex that every other request needs,
/// including `daemon/status`. Concurrency at the transport was therefore necessary but
/// not sufficient: a spawned connection would still queue behind the mutex.
///
/// Everything here is local durable state and an in-memory scan. None of it waits on
/// anything outside the process, so holding the mutex across it costs nothing and is the
/// simpler, safer shape.
///
/// The disclosure release is the one part that *mutates* something, and it mutates the
/// observation store — which has its own lock precisely so it is not on the governed
/// mutex's critical path. Recording a disclosure before the request that carries it is the
/// property that matters and it is preserved: if the model then cannot be asked, the
/// content has already been recorded as disclosed, which is the conservative direction.
fn gather_proposal_context<S: SecretsContract>(
    g: &mut (Daemon, S, TaskService),
    provider: &Arc<dyn crate::proposer::ProposalProvider>,
    task_id: &str,
    observations: &std::sync::Mutex<crate::observation::ObservationStore>,
) -> Result<ProposalAsk, RequestError> {
    // The task's own words. Read here, from durable state, so the model is shown what
    // was actually asked rather than what a caller says was asked.
    let row =
        g.2.task(&TaskId::new(task_id))
            .map_err(task_fault)?
            .ok_or_else(|| RequestError::NotFound {
                reason: "task-not-found".to_owned(),
                // The id is the caller's own, so naming it discloses nothing, and a client
                // fixing a stale reference needs to see which reference missed.
                detail: Some(format!("no task {task_id:?}")),
            })?;

    // The menu is walked out of the capability registry: what exists, what parameters
    // each one declares, and whether it is enabled. Nothing here names a capability.
    //
    // The previous version listed `filesystem/write-text` literally, which meant adding
    // a capability required remembering to edit the proposer — a second list that would
    // drift the moment a capability was registered and nobody remembered the other file.
    // One list now: the registry. A capability that is registered and enabled is
    // proposable, with its own declared shape and its own target semantics, and the
    // schema the proposal is checked against is the schema the capability was declared
    // with rather than a copy of it.
    let registered_ids: Vec<String> =
        g.0.registry()
            .ids()
            .into_iter()
            .map(|id| id.to_string())
            .collect();
    let allowed: Vec<crate::proposer::AllowedCapability> =
        g.0.registry()
            .enabled()
            .into_iter()
            .map(|declaration| crate::proposer::AllowedCapability {
                id: declaration.id.to_string(),
                // Risk is included because the model should know what it is asking for: a
                // High-risk capability needs a human to say yes, and a proposer that cannot
                // see that will confidently propose work that is always going to wait.
                // `{:?}` until `RiskClass` grows a display form of its own.
                description: format!(
                    "{} — risk {:?}, isolation {:?}. {}",
                    declaration.display_name,
                    declaration.risk,
                    declaration.isolation,
                    declaration.params.description
                ),
                params: declaration
                    .params()
                    .schema
                    .field_names()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                schema: declaration.params().schema.clone(),
                target: declaration.target(),
            })
            .collect();
    // Prior-step metadata, derived from the durable step results at request time and used
    // for this request only. Nothing is persisted: it is a projection of rows that are
    // already committed, so there is no new record to keep in step with anything.
    //
    // A read failure here is not fatal to the proposal. Losing the *context* degrades what the
    // model is told; refusing the proposal would mean a reporting fault stops the work.
    let prior_steps = match g.2.step_results_for(&TaskId::new(task_id)) {
        Ok(rows) => crate::proposer::prior_step_context_from(&rows),
        Err(e) => {
            tracing::warn!(
                error = ?e,
                "prior-step context unavailable; proposing without it"
            );
            crate::proposer::PriorStepContext::default()
        }
    };

    // The disclosure channel, resolved before the context is assembled so that a failure to
    // *record* one stops the request rather than sending content nobody could afterwards see
    // had gone. Release itself cannot fail: the store filters by task, step and provider
    // identity, and returns whatever survives those plus the budget.
    let disclosures = release_observations(g, provider, task_id, observations)?;
    // Summarised here, before the batch is moved into the context, so the caller's reply can
    // report what was disclosed without keeping a second copy of the bytes.
    let disclosed = disclosures.summary();

    Ok(ProposalAsk {
        ctx: crate::proposer::ProposalContext {
            task_id: task_id.to_owned(),
            content: row.payload.clone().unwrap_or_default(),
            attempt_no: row.attempts,
            allowed,
            prior_steps,
            disclosures,
        },
        registered_ids,
        disclosed,
    })
}

/// Everything one model question needs, gathered with the governed state locked.
///
/// A struct rather than three return values because the three travel together into the
/// unlocked phase and naming them at the call site would be noise. `registered_ids` is
/// carried deliberately: the allowlist check after the call must be against the registry
/// **as it was when the menu was built**, not against whatever it is by the time the model
/// answers. Re-reading it later would let a capability registered mid-call become
/// proposable on the strength of a menu that never mentioned it.
struct ProposalAsk {
    ctx: crate::proposer::ProposalContext,
    registered_ids: Vec<String>,
    disclosed: Vec<crate::observation::DisclosureSummary>,
}

/// Asks the provider, with **no governed lock held**.
///
/// # Why this is a separate function, and why that matters
///
/// This is the change that makes transport concurrency *sufficient*. Before it, the call
/// sat between `governed.lock().await` and the proposal write, so a 60-second model round
/// trip held the one mutex every other request needs. A spawned connection would have
/// queued on it exactly as the inline one did, which is why transport concurrency alone
/// would have looked like a fix and not been one.
///
/// Two properties make the release safe:
///
/// * **Nothing here touches governed state.** The provider trait is a question about
///   itself and a text generator; it holds no handle on tasks, proposals, approvals,
///   policy, the audit chain or the filesystem.
/// * **The proposal write re-validates under its own transaction.** `propose_action`
///   re-reads the task's state and its live lease holder inside one SQLite transaction and
///   refuses unless the task is still `Running` under *this worker's* live lease. A task
///   claimed away, completed, cancelled or let-expire during the model call is therefore
///   refused **at the write**, not written on stale knowledge. The mutex was a convenience
///   serialiser; the repository has always been the authority.
///
/// # The provider stays synchronous
///
/// Handing it to the blocking pool keeps the trait free of async -- which is what stops
/// every implementor and every test from needing a runtime -- and keeps a synchronous
/// network call from occupying a runtime worker for the length of a model call.
async fn call_provider(
    provider: &Arc<dyn crate::proposer::ProposalProvider>,
    ctx: &crate::proposer::ProposalContext,
) -> Result<String, RequestError> {
    let asker = Arc::clone(provider);
    let for_call = ctx.clone();
    let answered = tokio::task::spawn_blocking(move || asker.complete(&for_call))
        .await
        .map_err(|e| RequestError::ProviderRefused {
            reason: crate::proposer::ProviderError::Unreachable(String::new())
                .reason()
                .to_owned(),
            detail: Some(format!("the provider task did not finish: {e}")),
        })?;
    // A provider failure is not a declined request: the caller did nothing wrong and the
    // deterministic reason is preserved so a client can tell "the model said no" from "the
    // model could not be asked".
    answered.map_err(|e| RequestError::ProviderRefused {
        reason: e.reason().to_owned(),
        detail: Some(e.to_string()),
    })
}

/// Interprets the model's text against the menu it was shown.
///
/// Reads no governed state, so the validation is a pure function of the answer and the
/// question. Kept separate so "the allowlist check happens here, against the registry as it
/// was when the menu was built" has one place to look.
fn interpret_provider_answer(text: String, ask: &ProposalAsk) -> Result<AskOutcome, RequestError> {
    let outcome = crate::proposer::validate(&text, &ask.ctx, &|id| {
        ask.registered_ids.iter().any(|r| r == id)
    })
    .map_err(|e| RequestError::Declined {
        reason: e.reason().to_owned(),
        // The refusal's own words, not a fixed string: "which field was wrong" is
        // the only thing that lets an operator tell a model that misunderstood the
        // shape from a capability that has drifted from its declaration.
        detail: Some(e.to_string()),
    })?;

    Ok(AskOutcome {
        outcome,
        disclosed: ask.disclosed.clone(),
    })
}

/// What one provider question produced: the answer, and what was sent to get it.
struct AskOutcome {
    /// The model's answer, already validated.
    outcome: crate::proposer::ProposalOutcome,
    /// Paths and byte counts of what was disclosed. Never the content.
    disclosed: Vec<crate::observation::DisclosureSummary>,
}

/// Renders the content-free disclosure summary for a request reply.
fn disclosure_json(disclosed: &[crate::observation::DisclosureSummary]) -> serde_json::Value {
    serde_json::Value::Array(
        disclosed
            .iter()
            .map(|d| json!({ "path": d.path, "byte_count": d.byte_count }))
            .collect(),
    )
}

/// Writes a validated step through the ordinary proposal path.
///
/// Every durable proposal in the runtime goes through here, so the model-sourced route and
/// the continuation route cannot diverge in what they persist: same canonicalisation, same
/// step binding, same approval requirement, same audit attribution.
fn persist_proposal<S: SecretsContract>(
    g: &mut (Daemon, S, TaskService),
    write: ProposalWrite<'_>,
) -> Result<orxnud_store::task_repo::ProposalRow, RequestError> {
    // From here the model is out of the picture. What follows is the same path a human
    // worker would take, and the proposer is an `Actor::Ai` derived from the task — never
    // from the worker holding the lease.
    g.2.propose_action(
        write.proposal_id,
        &TaskId::new(write.task_id),
        write.worker,
        &orxnud_domain::CapabilityId::new(write.validated.capability.as_str()),
        write.validated.target.as_deref(),
        write.canonical_params,
        write.proposer,
        write.now,
    )
    .map_err(task_fault)
}

/// Everything one durable proposal write needs, gathered so the call does not carry eight
/// positional arguments.
///
/// A struct rather than a tuple: at eight arguments the call site can no longer tell which
/// `&str` is the proposal id and which is the canonical params, and swapping those two
/// produces a valid-looking write of the wrong thing.
struct ProposalWrite<'a> {
    /// The id the daemon minted for this proposal.
    proposal_id: &'a str,
    /// The task it proposes to.
    task_id: &'a str,
    /// The worker holding the lease. Never the proposer — see `proposer`.
    worker: &'a str,
    /// The validated action.
    validated: &'a crate::proposer::ValidatedProposal,
    /// Its parameters, already canonicalised.
    canonical_params: &'a str,
    /// Who is asking. Always a delegated actor, never the lease holder.
    proposer: &'a orxnud_domain::actor::Actor,
    /// When.
    now: i64,
}

/// Advances a task across one step boundary and proposes what comes next.
///
/// # What one call does
///
/// Exactly three things, in this order, and then it stops:
/// 1. claims the next logical step (one durable boundary crossing);
/// 2. asks the configured provider what that step should do;
/// 3. persists the resulting proposal — or completes the task if the model says no
///    further work is needed.
///
/// It deliberately does **not** execute. Every consequential step therefore re-enters the
/// ordinary route (`task/ai-propose` → durable proposal → approval → dispatcher → sandbox
/// → verification → audit) with no continuation-specific shortcut, which is what makes
/// "the governed path is the only path" a property of the code rather than a claim about
/// it. A `task/continue` therefore ends in `waiting_for: human-approval`, exactly like a
/// proposal any human worker could have written.
///
/// # Why one boundary and not a loop
///
/// The orchestrator is a single step, not a driver that runs a task to completion.
/// A loop would need a place to record "this is the Nth retry", a rule for when to stop
/// asking a model that keeps failing, and a way to resume after a crash — three decisions
/// that each want their own record and their own review. Keeping the caller in charge of
/// whether to continue makes the bound explicit and the cost visible: each call is one
/// boundary and at most one provider call, and `max_steps` remains the only thing that
/// bounds a task's length (ADR-0043, ADR-0047).
///
/// # The claim and the proposal are not atomic, deliberately
///
/// A model call can take seconds; holding a write transaction across one would hold the
/// single SQLite writer for the duration of a network round trip. So the claim commits
/// first, and if the model then cannot be asked the boundary is released again — see
/// [`release_to_boundary`]. A crash between the two leaves a `Running` task with no
/// proposal, which is recoverable in the ordinary way: the lease expires and the task
/// returns to a claimable boundary.
///
/// # Errors
///
/// [`RequestError::ProviderRefused`] if no provider is configured or the model cannot be
/// reached, [`RequestError::Declined`] with `reason: not-at-boundary` if the task is not
/// sitting at one, or with the claim refusal's own reason if another worker got there
/// first, and [`RequestError::Invalid`] if the task does not exist.
async fn continue_task<S: SecretsContract>(
    request: &Request,
    authenticated: AuthenticatedPrincipal,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
    provider: Option<&Arc<dyn crate::proposer::ProposalProvider>>,
    observations: &std::sync::Mutex<crate::observation::ObservationStore>,
) -> Result<serde_json::Value, RequestError> {
    let delegated_by = authenticated.user();
    let Some(provider) = provider else {
        return Err(RequestError::ProviderRefused {
            reason: crate::proposer::ProviderError::NotConfigured
                .reason()
                .to_owned(),
            detail: Some(
                "this daemon has no proposal provider; start it with a provider configured"
                    .to_owned(),
            ),
        });
    };
    let params = request.params.clone().unwrap_or(json!({}));
    let task_id = required_str(&params, "task")?;
    check_len("task", &task_id, MAX_TASK_ID_BYTES)?;
    let worker = required_str(&params, "worker")?;
    check_len("worker", &worker, MAX_TASK_ID_BYTES)?;

    let id = TaskId::new(task_id.as_str());
    let mut g = governed.lock().await;
    let now = g.2.clock_now_ms();

    // Refused with the task's own state rather than a claim refusal, because the two mean
    // different things to a caller: this task has no boundary to cross, which is a fact
    // about the task, whereas a claim refusal is about losing a race.
    let before =
        g.2.task(&id)
            .map_err(task_fault)?
            .ok_or_else(|| RequestError::NotFound {
                reason: "task-not-found".to_owned(),
                // The id is the caller's own, so naming it discloses nothing, and a client
                // fixing a stale reference needs to see which reference missed.
                detail: Some(format!("no task {task_id:?}")),
            })?;
    if before.state != TaskState::AwaitingNextStep {
        return Err(RequestError::Conflict {
            reason: "not-at-boundary".to_owned(),
            detail: Some(format!(
                "task is {:?}, not {:?}; only a task between steps can be continued",
                before.state,
                TaskState::AwaitingNextStep
            )),
        });
    }

    // The one boundary crossing. Whoever gets here owns the next logical step; a second
    // caller in the same instant is refused by the conditional UPDATE inside the store,
    // not by anything this runtime decided.
    let claimed =
        g.2.claim_next_step(&id, &worker, now)
            .map_err(|e| match e {
                TaskFault::NotClaimable(r) => RequestError::Declined {
                    reason: r.as_str().to_owned(),
                    detail: Some(format!("the next step was not claimed: {r:?}")),
                },
                other => task_fault(other),
            })?;
    // The claimed step is `steps_completed + 1` of the row the claim returned, read from
    // durable state rather than counted here.
    let step = claimed.row.steps_completed + 1;

    // From here the boundary is crossed, so every failure has to put it back — otherwise
    // the task is left holding a lease for a step that will never be proposed and
    // continuation can never be retried.
    // The same gather/call/persist split as `ai_propose`, and for the same reason.
    //
    // Here it additionally lines up with what this function's own documentation already
    // promised: "the claim and the proposal are not atomic, deliberately -- a model call
    // can take seconds". The claim commits first, the boundary is released again if the
    // model cannot be asked, and a crash between the two leaves a `Running` task with no
    // proposal that recovers the ordinary way. Releasing the *mutex* across the call
    // extends that same window to the daemon's other clients: nothing here claims the task
    // was untouched, only that the claim is fenced and the boundary releasable, both of
    // which the store enforces.
    let asked = {
        let ask = gather_proposal_context(&mut g, provider, &task_id, observations);
        let call = match ask {
            Ok(ask) => call_provider(provider, &ask.ctx)
                .await
                .and_then(|text| interpret_provider_answer(text, &ask)),
            Err(e) => Err(e),
        };
        match call {
            Ok(asked) => asked,
            Err(e) => {
                let why = e.to_string();
                release_to_boundary(&mut g, &id, &worker, now, &why);
                return Err(e);
            }
        }
    };

    let disclosed_json = disclosure_json(&asked.disclosed);
    match asked.outcome {
        // The model says the work is finished. Completed through the same fenced engine
        // completion every other terminal report uses, by a caller holding a live lease,
        // with the reason recorded on the task. The model proposed "no further work is
        // needed"; it did not move the task, approve anything, or assert that an effect
        // succeeded — a `done` answer carries no capability, no target and no parameters,
        // so there is nothing here it could have been used to smuggle (ADR-0047).
        crate::proposer::ProposalOutcome::Done { summary } => {
            let finished =
                g.2.complete_task_with(
                    &id,
                    &worker,
                    now,
                    TaskState::Completed,
                    false,
                    Some(&format!("no work required: {summary}")),
                    None,
                )
                .map_err(task_fault)?;
            Ok(json!({
                "continued": false,
                "completed": true,
                "step": step,
                "steps_completed": finished.steps_completed,
                "summary": summary,
                "state": finished.state.as_wire_str(),
                // Restated for the caller: a task that ends because a model said so must
                // be attributable to that model in the reply, not only in the database.
                "proposed_by": delegated_actor(&delegated_by, &task_id, provider.model_id()).label(),
                "model": provider.model_id(),
                // Content went with this request even though no proposal was made from it.
                "disclosed": disclosed_json,
            }))
        }
        crate::proposer::ProposalOutcome::Step(validated) => {
            let canonical = orxnud_policy::canonical_params(&validated.params);
            let proposal_id = format!("p-{task_id}-{now}");
            let proposer = delegated_actor(&delegated_by, &task_id, provider.model_id());
            let proposed = match persist_proposal(
                &mut g,
                ProposalWrite {
                    proposal_id: &proposal_id,
                    task_id: &task_id,
                    worker: &worker,
                    validated: &validated,
                    canonical_params: canonical.as_str(),
                    proposer: &proposer,
                    now,
                },
            ) {
                Ok(row) => row,
                Err(e) => {
                    let why = e.to_string();
                    release_to_boundary(&mut g, &id, &worker, now, &why);
                    return Err(e);
                }
            };
            Ok(json!({
                "continued": true,
                "step": step,
                "steps_completed": before.steps_completed,
                "max_steps": before.max_steps,
                "proposal": proposal_json(&proposed),
                "waiting_for": "human-approval",
                "proposed_by": proposer.label(),
                "model": provider.model_id(),
                "disclosed": disclosed_json,
            }))
        }
    }
}

/// Releases the observations this request may disclose, and records each disclosure.
///
/// # The whole of the data-release boundary
///
/// Four things have to hold before a byte of approved workspace content reaches a provider,
/// and they are checked in this order, each of them by code that cannot be skipped:
///
/// 1. **The destination is nameable.** `provider.destination()` returning `None` releases
///    nothing at all. A provider that cannot say where it sends is one no content may reach.
/// 2. **The task matches.** Handled inside the store, keyed on the task this request is for.
/// 3. **The step matches.** Handled inside the store: an observation is eligible only for the
///    logical step immediately after the read that produced it.
/// 4. **The identity matches.** Handled inside the store, on `(endpoint, model)`, compared
///    against the identity recorded when the read was approved — not against a string from
///    configuration read now.
///
/// The store consumes what it releases, so a second request finds nothing, and a restart finds
/// nothing at all.
///
/// # Why the audit record is written *before* the request goes out
///
/// A disclosure record that is written after the response can miss one that happened: the
/// process can die between sending and receiving, and there is then no way to know whether the
/// bytes left. Writing first means the log can over-report by at most one record whose
/// transmission failed, which is the direction that errs towards telling an operator more
/// than happened. Under-reporting is the failure the audit exists to prevent, and
/// ADR-0045's whole purpose is that "the model saw the file" is not invisible.
///
/// Failing to write is therefore a **refusal to disclose**: content whose disclosure cannot be
/// recorded is content that leaves unobserved, which is precisely the outcome to refuse.
/// `steps_completed` is read here rather than the step recomputed, because the store must be
/// asked for the step the proposal belongs to and that is the durable counter plus one.
fn release_observations<S: SecretsContract>(
    g: &mut (Daemon, S, TaskService),
    provider: &Arc<dyn crate::proposer::ProposalProvider>,
    task_id: &str,
    observations: &std::sync::Mutex<crate::observation::ObservationStore>,
) -> Result<crate::observation::DisclosureBatch, RequestError> {
    let Some(identity) = provider.destination() else {
        return Ok(crate::observation::DisclosureBatch::empty());
    };
    // The service clock, not a row's `updated_at_ms`: TTL is a statement about now, and a
    // column that a task write may bump is the wrong thing to measure it from.
    let now = g.2.clock_now_ms();
    // Read from the durable counter rather than carried in from the caller, so the step the
    // store is asked about is the one the database says the task is on.
    let step_no =
        g.2.next_step_no(&orxnud_domain::ids::TaskId::new(task_id))
            .map_err(task_fault)?;

    let released = {
        let Ok(mut store) = observations.lock() else {
            // A poisoned lock means a previous holder panicked while holding workspace
            // content. Refusing is the only answer: recovering would require deciding which
            // observations a panicked path had already consumed.
            return Err(RequestError::Internal {
                fault: InternalFault::DisclosureStorePoisoned,
                detail: Some(
                    "the observation store is not usable; no content was disclosed".to_owned(),
                ),
            });
        };
        store.take_for(
            &orxnud_domain::ids::TaskId::new(task_id),
            step_no,
            &identity,
            now,
            crate::observation::DEFAULT_MAX_CONTENT_BYTES,
        )
    };

    if released.is_empty() {
        return Ok(crate::observation::DisclosureBatch::empty());
    }

    // Every released observation is recorded before any of them is attached. All-or-nothing:
    // a partially recorded disclosure would leave bytes in a request with no record of the
    // subset that travelled.
    for r in &released {
        let record = crate::observation::DisclosureRecord::from_verified_read(
            r.origin.parent_read_request.clone(),
            r.origin.parent_proposal_id.clone(),
            orxnud_domain::ids::TaskId::new(task_id),
            step_no,
            r.path.clone(),
            r.provider.clone(),
            r.byte_count,
            now,
        )
        .to_audit_record(r.origin.approver.clone());
        g.0.policy_mut()
            .append_audit_record(record)
            .map_err(|_e| RequestError::Unavailable {
                // The journal is a dependency the daemon needs and the operator can
                // repair (free space, permissions, a moved file), so this is an
                // environment outage rather than an internal fault.
                //
                // The underlying error is deliberately **dropped** rather than
                // interpolated. It is a `String` from the storage layer, so it can contain
                // a database path or a SQL fragment, and ADR-0051's rule is that an OS
                // identifier never leaves this daemon in an error. The reason word says
                // what happened and the detail says what it means; neither needs the
                // cause to be useful, and the server log already has it.
                reason: "disclosure-audit-unavailable".to_owned(),
                detail: Some(
                    "the disclosure could not be recorded, so nothing was disclosed".to_owned(),
                ),
            })?;
    }

    Ok(crate::observation::DisclosureBatch::from_released(released))
}

/// Returns a claimed step to its boundary so continuation can be retried.
///
/// The claim and the proposal are two writes, and only the second one is wanted if the
/// model cannot be asked. Releasing the boundary on that path is what keeps a provider
/// outage from stranding a task at a step it will never work on: the claim is undone and
/// the task is exactly where it was, with the lease released, so a later `task/continue`
/// starts over cleanly rather than finding a half-open step.
///
/// Best-effort by design. If this write fails the lease still expires and the task is
/// re-claimable at its boundary, which is a slower route to the same place — so this is
/// worth a loud log and not worth failing the caller's request, which has already been
/// failed for the real reason.
fn release_to_boundary<S: SecretsContract>(
    g: &mut (Daemon, S, TaskService),
    id: &TaskId,
    worker: &str,
    now: i64,
    why: &str,
) {
    if let Err(e) = g.2.complete_task_with(
        id,
        worker,
        now,
        TaskState::AwaitingNextStep,
        false,
        Some(why),
        None,
    ) {
        tracing::error!(
            error = ?e,
            "could not return a claimed step to its boundary; its lease will expire instead"
        );
    }
}

/// The provider a deterministic test uses when it does not care which one.
///
/// **Not a default.** [`Runtime::start`] leaves the runtime unconfigured and
/// `task/ai-propose` answers `provider-not-configured`; only a test that explicitly asks
/// for a scripted provider gets one. A production daemon quietly answering with a fixed
/// string would report a working intelligence loop that does not exist, and the failure
/// would only surface as an unexplained absence of judgement.
#[must_use]
pub fn scripted_proposer() -> Arc<dyn crate::proposer::ProposalProvider> {
    Arc::new(crate::proposer::ScriptedProvider::returning(
        "scripted/none",
        r#"{"capability":"filesystem/write-text","target":"final.txt","params":{"path":"final.txt","contents":"delegated governance works"}}"#,
    )) as Arc<dyn crate::proposer::ProposalProvider>
}

/// The delegated proposer for a task's governed action.
///
/// Built from the **task identity** and the trusted local human, never from the worker
/// holding the lease. That is V-71 as code rather than as a comment: the two inputs a
/// caller controls (task id, worker) and the two that determine authority (delegating
/// human, task) are separate, and only the former is reachable from the request.
/// Provenance for a proposal no model produced.
///
/// `task/propose` records a delegated `Actor::Ai` for a proposal asserted directly over the
/// wire, with no provider involved. This is what it says about the model: nothing. The
/// previous value here named a model that had not answered, which is the specific falsehood
/// this function existed to stop.
const NO_MODEL_PROPOSED: &str = "none/direct-proposal";

/// What a `dispatch()` failure proves about the side effect it was about to cause.
///
/// # Why this function exists
///
/// `execute_proposal` reserves the effect *before* dispatching, because a record made
/// afterwards cannot describe a crash. That leaves the reservation holding whatever the
/// dispatch then did, and until now every `Err` from `dispatch()` left it `pending` — the
/// one status the ledger defines as *"a dispatch was authorised and its outcome was never
/// established"*.
///
/// For most of `DispatchError` that is simply wrong, and provably so rather than by
/// opinion. `dispatch()` is staged, and the stages are ordered so that the side effect
/// happens in exactly one of them:
///
/// | stage | may run the capability | representative errors |
/// |---|---|---|
/// | 1-4 authority, policy, approval, budget | no | `Policy` |
/// | 5 capability resolution | no | `NoImplementation`, `ClassEscalation`, `Disabled` |
/// | 6 credential resolution | no | `Credential` |
/// | 7 execution | **yes** | `SandboxRefused` (a refusal, whose `certainty` says whether), `Audit` (see below) |
/// | 8 verification | ran already | — (a verifier error becomes `Undetermined`) |
/// | 9 audit / terminal record | ran already | `Audit` |
///
/// The stage-7 error is the load-bearing one, and it is the one that is **not** a single
/// class. `ExecutionBackend::execute` documents its own error as *"A refusal. Nothing was
/// executed, and the caller must not retry the capability as though it had"*, and
/// `outcome_from_report` says the same from the other side. That contract is what makes
/// an ordinary sandbox refusal a *positive* statement that the capability did not run.
///
/// It does not extend to every way stage 7 can fail, and there are two ways it does not:
/// `execute` is called inside a `catch_unwind`, so a backend that **panicked** produces the
/// same error type with no backend-supplied claim about whether a child was started; and a
/// backend that **gave up on a guarantee it had promised** produces it too, after it has
/// already started the capability. `SandboxRefusal::certainty` is how all three are told
/// apart, and this function reads it. Treating every `SandboxRefused` as a disproof records
/// "definitely did not happen" for events whose defining property is that nobody can say.
///
/// Both of those are unreachable-or-rare properties of *particular* runners rather than
/// guarantees of the type — a panic needs a panicking backend, and a give-up needs a runner
/// that can start a process and then lose track of it — so neither is a reason to weaken the
/// mapping. `ExecutionBackend` and `SandboxRunner` are public traits, and the sandbox
/// vocabulary now makes the give-up *reportable* rather than conflatable with a refusal
/// (`ExecutionStatus::Abandoned`), so a second backend or a future edit to the shipped one
/// cannot make `not-performed` mean something it does not.
///
/// # The two classes
///
/// * **`NotPerformed`** — the capability demonstrably did not run, or ran and was
///   *disproved*. Stages 1-6 cannot run it, a stage-7 refusal that carries
///   `NothingAttempted` declines to, `Reentrant` is refused before `execute`/`invoke` is
///   reached, and `VerificationRefuted` is the verifier positively disproving it. Recording
///   this as `not-performed` is not a guess: it is the one verdict in the ledger's
///   vocabulary that means "a repeat cannot duplicate anything", and it restores the retry
///   that V-93 correctly closed for the *uncertain* case.
/// * **`Unknown`** — the capability ran, or the contract cannot say. `Audit` is the
///   important one: it is raised in stage 9, *after* the capability has run and been
///   verified, and it discards the verdict on its way out. `dispatch_failure` already
///   calls this out — *"Fail-closed, and after execution too, which is the dangerous
///   direction"* — so the wire error was right while the ledger row was left claiming
///   nothing was known. `Unknown` is the honest reading and it keeps recovery holding the
///   task, which is the direction that cannot duplicate an effect.
///
/// Every arm is written out, for the same reason `dispatch_failure` writes out its own:
/// adding a variant must break the build here, where somebody has to say which class it
/// is in.
fn effect_status_for_dispatch_failure(
    e: &orxnud_capability::dispatch::DispatchError,
) -> EffectStatus {
    use orxnud_capability::dispatch::DispatchError;
    match e {
        // Ran, or the contract cannot establish that it did not. `Unknown` throughout.
        DispatchError::Audit(_) | DispatchError::Execution(_) | DispatchError::Verification(_) => {
            EffectStatus::Unknown
        }

        // **The refusal carries its own certainty, and this arm has to read it.**
        //
        // This was `DispatchError::SandboxRefused(_)` in the `NotPerformed` list, with
        // the `_` discarding the field. That made a *generic backend panic* — which the
        // dispatcher classifies as `Unknown` precisely because `execute` may have
        // spawned its child before unwinding — resolve to `NotPerformed` here, and
        // `NotPerformed` is the one status `recover()` treats as "a repeat cannot
        // duplicate anything". The task went to `pending`, any worker could claim it,
        // and the next attempt reserved a *fresh* idempotency key because that key
        // includes `attempt_no`. A non-idempotent capability whose side effect may have
        // happened was therefore re-dispatchable with no human involved.
        //
        // The defect was not the mapping's shape but one missing read, and it was
        // invisible because the *audit* channel (`terminal_outcome_for_failure`) did read
        // `certainty` — so the journal said `Uncertain` while this ledger said the
        // opposite, and the journal's claim was the correct one.
        //
        // The distinction is exactly the refusal's, and neither value is inferred:
        // `NothingAttempted` is set only where the refusal is decided before a process
        // exists, and `Unknown` only where the backend's own reporting failed. A backend
        // panic stays `Unknown`, and so does a backend that gives up on a containment
        // guarantee after the capability has started — the shipped Linux runner can do the
        // second without any fault injected, because its cgroup-membership poll gives up
        // both when the supervisor never joined and when it joined, ran and exited inside
        // the poll interval. `ExecutionBackend` and `SandboxRunner` are public traits, and
        // neither phase is inferable from the error, so the field is the only honest
        // source and this arm is the only place it can be read.
        DispatchError::SandboxRefused(r) => match r.certainty {
            orxnud_capability::dispatch::ExecutionCertainty::NothingAttempted => {
                EffectStatus::NotPerformed
            }
            orxnud_capability::dispatch::ExecutionCertainty::Unknown => EffectStatus::Unknown,
        },

        // Demonstrably did not run. See the stage table above.
        // Every arm above is a decision taken *before* a process exists, which is what
        // makes `not-performed` a warrant rather than an inference. ADR-0056 Decision 4.
        DispatchError::Policy(_)
        | DispatchError::NoImplementation(_)
        | DispatchError::Disabled { .. }
        | DispatchError::ClassEscalation { .. }
        | DispatchError::Credential(_)
        | DispatchError::Reentrant(_)
        | DispatchError::InvalidInput { .. } => EffectStatus::NotPerformed,

        // **Not** in the group above, and that is the whole point of this arm existing.
        //
        // A refuted *verification* is evidence about a postcondition. This error is raised
        // after the capability ran, so there is a world in which the effect happened and a
        // later actor changed or removed what it left. Reporting `not-performed` here
        // issued a retry permission for a possibly-performed non-idempotent effect, with no
        // human involved. It now records the uncertainty instead.
        //
        // Before ADR-0056 this arm sat in the list above, next to `Policy` and
        // `ClassEscalation`, which made a post-execution finding look like a pre-execution
        // refusal. The two are indistinguishable in the type and were not distinguished in
        // the mapping, which is how the defect survived a review that checked the verdict
        // and not the route.
        DispatchError::VerificationRefuted { .. } => EffectStatus::Unknown,
    }
}

/// Classifies a [`DispatchError`] by recovery semantics.
///
/// # The property this maintains
///
/// Every arm is written out. There is no `_ =>` catch-all, and that is the entire point:
/// the old shape was
///
/// ```text
/// match e { known => known_class, _ => Refused { reason: e.to_string() } }
/// ```
///
/// and the `_` became `INTERNAL_ERROR`, so any condition nobody had thought about was
/// reported to the caller as a server fault. Adding a `DispatchError` variant now breaks
/// the build here, where somebody has to say what a caller should do about it.
///
/// # Why classification is by recovery and not by name
///
/// `Policy` is not one class: it contains both "we decided no" and "we could not decide",
/// so it is delegated to [`policy_failure`]. `SandboxRefused` and `Credential` are
/// environment problems with operator remedies. `Execution` and `Verification` are
/// daemon-side defects with no remedy at all. Naming a variant tells you the *cause*; only
/// the recovery tells you the *class*, and the class is what a client branches on.
fn dispatch_failure(e: &orxnud_capability::dispatch::DispatchError) -> RequestError {
    use orxnud_capability::dispatch::DispatchError;
    match e {
        // --- the governed refusals, delegated to policy ---
        //
        // `Policy` carries `PolicyError`, which is itself a deny/error split, so this arm
        // is a hand-off and not a decision.
        DispatchError::Policy(p) => policy_failure(p),

        // --- environment: a dependency the daemon needs and an operator can repair ---
        //
        // Nothing ran. The host could not establish the guarantees the capability requires,
        // so the remedy is a different machine, a different kernel setting, or accepting
        // that this host cannot run Tier-1 work. Retrying identical requests cannot help,
        // which is why this is not a conflict.
        //
        // The detail names the missing guarantees, which are this daemon's own vocabulary
        // (`visibility`, `tree_lifetime`, `resources`) and never a path or a syscall.
        //
        // `missing` is reported, and `reason` is reported alongside it rather than
        // replaced by a fixed sentence. The fixed sentence was the bug: it asserted the
        // backend could not establish its guarantees on *every* refusal reaching here,
        // including ones decided long before the backend was consulted. A caller that
        // had supplied a traversing path was told their sandbox was broken, on a host
        // whose sandbox had executed a neighbouring capability seconds earlier, and the
        // reason the capability actually gave — which said exactly what was wrong — was
        // dropped on the floor here.
        DispatchError::SandboxRefused(r) => RequestError::Unavailable {
            reason: "sandbox-unavailable".to_owned(),
            detail: Some(format!(
                "no sandbox could be established for this capability: {} (missing: {})",
                r.reason,
                if r.missing.is_empty() {
                    "none".to_owned()
                } else {
                    r.missing.join(", ")
                }
            )),
        },

        // The capability rejected the request. Invalid-request, not environment: the
        // cause is the parameters, the caller can fix them, and nothing ran. Routing
        // this to `unavailable` is what made a bad path look like a host fault.
        DispatchError::InvalidInput { capability, detail } => RequestError::Declined {
            reason: "invalid-capability-parameters".to_owned(),
            detail: Some(format!("{capability} rejected the request: {detail}")),
        },

        // A credential that is not configured is fixed by *adding the credential*, which is
        // configuration work rather than a request edit -- hence environment rather than
        // invalid-request. `CredentialError` splits this from a store that is merely
        // unreachable, and both are environment; the reasons differ because a client may
        // want to prompt for one and retry the other.
        DispatchError::Credential(orxnud_capability::credential::CredentialError::Absent(_)) => {
            RequestError::Unavailable {
                reason: "credential-not-configured".to_owned(),
                detail: Some("a required credential is not configured".to_owned()),
            }
        }
        DispatchError::Credential(orxnud_capability::credential::CredentialError::Unavailable(
            _,
        )) => RequestError::Unavailable {
            reason: "credential-store-unavailable".to_owned(),
            // The store's own error is dropped: a `SecretService`/`DPAPI`/`Keychain`
            // failure can carry a socket path or a service name, and an IPC error is not
            // the place for it. The server log keeps it.
            detail: Some("the credential store could not be reached".to_owned()),
        },

        // --- caller-actionable: the request itself names something unservable ---
        //
        // `NoImplementation` means policy accepted the capability but no adapter is
        // registered for it. The caller cannot make it exist and cannot supply an approval
        // that changes it; the only repair is naming a capability this build can run, which
        // is an edit to the request.
        DispatchError::NoImplementation(c) => RequestError::InvalidInput {
            reason: "no-implementation-registered".to_owned(),
            detail: Some(format!("no implementation is registered for {c}")),
        },
        // The invocation under-declared its data class against the implementation's own
        // declaration. Purely a request edit: declare the class the action actually needs.
        DispatchError::ClassEscalation {
            id,
            declared,
            actual,
        } => RequestError::InvalidInput {
            reason: "class-escalation".to_owned(),
            detail: Some(format!(
                "{id} implements up to {declared:?} but was invoked at {actual:?}"
            )),
        },

        // --- caller-actionable: refused by configuration the owner chose ---
        //
        // `Disabled` is a switch a person flipped, so the recovery is that person flipping
        // it back -- which is "obtain authority", the same recovery `FORBIDDEN` names for
        // every other owner-controlled refusal. It is deliberately *not* environment: the
        // environment is working exactly as configured.
        //
        // The reason travels with the refusal rather than being flattened here. When this
        // arm reports `"capability-disabled"` for a capability the operator never switched
        // off -- one refused because it puts file contents in `argv` -- the operator is
        // told to go and flip a switch that does not exist. `DisabledReason::code()`
        // keeps the two distinguishable all the way to the CLI.
        DispatchError::Disabled { id, reason } => RequestError::Forbidden {
            reason: reason.code().to_owned(),
            detail: Some(format!("{id} is disabled: {reason}")),
        },

        // --- genuine internal faults ---
        //
        // No remedy exists for any of these at any layer, so `INTERNAL_ERROR` is the
        // truthful answer and not a fallback. Each names a specific fault so the audit
        // trail says which.
        DispatchError::Execution(_) => RequestError::Internal {
            fault: InternalFault::CapabilityExecutionFailed,
            detail: Some("the capability ran and failed".to_owned()),
        },
        DispatchError::Verification(_) => RequestError::Internal {
            fault: InternalFault::CapabilityVerificationFailed,
            detail: Some("the effect could not be verified".to_owned()),
        },
        DispatchError::Audit(_) => RequestError::Unavailable {
            // Fail-closed, and *after* execution too, which is the dangerous direction: an
            // action with no audit record is worse than a refused one. But the cause is
            // still an outage of a dependency the operator can repair, so it is
            // environment rather than a defect in the daemon's logic.
            reason: "audit-journal-unavailable".to_owned(),
            detail: Some(
                "the action could not be recorded, so it is not treated as \
                          completed"
                    .to_owned(),
            ),
        },
        DispatchError::Reentrant(_) => RequestError::Internal {
            fault: InternalFault::ReentrantDispatch,
            detail: Some("a capability called back into the dispatcher".to_owned()),
        },
        // The effect is known *not* to have happened. That is a fact about the world, not
        // a fault in the daemon, and the recovery is to re-read what actually happened --
        // the same recovery a conflict names. The successful-dispatch path reports this
        // inside the outcome rather than as an error; the arm exists so that if a route
        // ever does surface it as `Err`, it is classified as a conflict and not a fault.
        DispatchError::VerificationRefuted { .. } => RequestError::Conflict {
            reason: "effect-refuted".to_owned(),
            detail: Some("verification determined the effect did not happen".to_owned()),
        },
    }
}

/// Classifies a [`orxnud_policy::PolicyError`].
///
/// # Deny is not error
///
/// `PolicyError::Denied` is the policy engine saying "no" — a *decision*. Every other
/// variant is the engine being unable to reach one, which is a different fact and lands in
/// a different class. Collapsing them was how an outage became indistinguishable from a
/// refusal.
///
/// `ApprovalLedgerUnavailable` is the sharpest case and it is why this function exists:
/// we could not determine whether an approval was already spent. The only safe response is
/// to refuse, but the *reason* is an outage, so it is `ENVIRONMENT_UNAVAILABLE` rather
/// than `FORBIDDEN` — a client told "forbidden" would go and obtain an approval that would
/// then be refused for the same unanswerable reason.
fn policy_failure(e: &orxnud_policy::PolicyError) -> RequestError {
    use orxnud_policy::PolicyError;
    match e {
        PolicyError::Denied { reason } => denial_failure(reason),
        // An outage of a component the daemon depends on. No caller action reaches it.
        PolicyError::Unavailable(_) => RequestError::Unavailable {
            reason: "policy-unavailable".to_owned(),
            detail: Some("the policy set could not be loaded".to_owned()),
        },
        PolicyError::AuditUnavailable(_) => RequestError::Unavailable {
            reason: "audit-journal-unavailable".to_owned(),
            detail: Some("the decision could not be recorded".to_owned()),
        },
        PolicyError::ApprovalLedgerUnavailable(_) => RequestError::Unavailable {
            reason: "approval-ledger-unavailable".to_owned(),
            detail: Some(
                "the approval ledger could not be read, so no decision was reached".to_owned(),
            ),
        },
        // Compiled-in and not runtime-configurable, so nothing an operator can change
        // reaches it: a defect in the build rather than a misconfiguration of a sound one.
        PolicyError::InvalidSchema(_) => RequestError::Internal {
            fault: InternalFault::InvalidCapabilitySchema,
            detail: Some("a capability's declared schema could not be evaluated".to_owned()),
        },
    }
}

/// Classifies a [`orxnud_policy::DenialReason`] — the engine's *decisions*.
///
/// # Why most of these are `FORBIDDEN` and that is not a lump
///
/// `FORBIDDEN` is defined by recovery, not by severity: nothing the caller can do by
/// editing the request changes the outcome, and what is needed is a *new human decision*.
/// Every approval-related denial has exactly that recovery — obtain a fresh approval, or
/// one that actually describes this action — so they share a class honestly. The
/// distinctions that matter are preserved in `data.reason`, which is a fixed vocabulary
/// word rather than the previous rendering of this enum into a JSON string.
///
/// The four that are *not* `FORBIDDEN` are separated because their recoveries genuinely
/// differ: `UnknownCapability`, `InvalidParams` and `DataClassExceeded` are fixed by
/// editing the request; `PolicyUnavailable` and `AuditUnavailable` are outages that
/// editing anything cannot fix, and reporting them as `FORBIDDEN` would send an operator
/// to obtain consent for an action the daemon never evaluated.
///
/// Note the deliberate overlap with [`orxnud_policy::DenialReason::is_user_actionable`],
/// which answers a different question -- "whose problem is it" -- and treats
/// `NoAuthorityRoot` as not the user's to fix. Both can be true of the same reason: an
/// external actor has no authority (not the user's fault) *and* the recovery is to obtain
/// authority (`FORBIDDEN`). Recovery is what the class encodes.
fn denial_failure(d: &orxnud_policy::DenialReason) -> RequestError {
    use orxnud_policy::DenialReason as D;
    let reason = denial_reason_word(d);
    let detail = denial_detail(d);
    match d {
        // --- fixed by editing the request ---
        D::UnknownCapability { .. } | D::InvalidParams { .. } | D::DataClassExceeded { .. } => {
            RequestError::InvalidInput {
                reason: reason.to_owned(),
                detail: Some(detail),
            }
        }
        // --- fixed by waiting for, or repairing, something outside the request ---
        //
        // The engine could not reach a decision. Reporting these as `FORBIDDEN` would be
        // the most damaging kind of lie in this file: the action was never judged, and a
        // client told it was refused would respond by obtaining consent it does not need.
        D::PolicyUnavailable { .. } | D::AuditUnavailable { .. } => RequestError::Unavailable {
            reason: reason.to_owned(),
            detail: Some(detail),
        },
        // --- everything else needs a new human decision ---
        D::NoAuthorityRoot { .. }
        | D::ActorMayNotGrant { .. }
        | D::EgressNotConsented { .. }
        | D::NoGrant { .. }
        | D::GrantExpired { .. }
        | D::ApprovalRequired { .. }
        | D::ApprovalExpired { .. }
        | D::ApprovalDigestMismatch
        | D::ApprovalApproverCannotGrant
        | D::ApprovalApproverNotAuthorised { .. }
        | D::ApprovalAlreadyUsed
        | D::BudgetExceeded { .. } => RequestError::Forbidden {
            reason: reason.to_owned(),
            detail: Some(detail),
        },
    }
}

/// The human sentence for a denial, for `data.detail`.
///
/// # Why these are written out rather than rendered
///
/// `DenialReason`'s `Display` renders its `serde_json` form, which is *structured*, not
/// readable: `ApprovalDigestMismatch` is a unit variant, so it renders as
/// `{"reason":"approval-digest-mismatch"}` -- the same word `data.reason` already carries,
/// wrapped in an object. That was the previous content of `data.detail`, and a client
/// showing it to a person was showing them JSON.
///
/// `data.reason` is the machine field and these are the human ones, so the split is real:
/// no sentence here is ever parsed, and no word here is ever branched on. The structured
/// value is still available to anything that needs it, because it is in the audit record.
fn denial_detail(d: &orxnud_policy::DenialReason) -> String {
    use orxnud_policy::DenialReason as D;
    match d {
        D::NoAuthorityRoot { actor } => {
            format!("a {actor} actor has no human authority behind it")
        }
        D::ActorMayNotGrant { actor } => {
            format!("only a human may grant authority, and this is a {actor} actor")
        }
        D::UnknownCapability { capability } => format!("no such capability: {capability}"),
        D::InvalidParams { capability, detail } => {
            format!("{capability} rejected these parameters: {detail}")
        }
        D::DataClassExceeded {
            required,
            permitted,
        } => format!("this action is {required:?} data, which exceeds the {permitted:?} permitted"),
        D::EgressNotConsented { data_class } => {
            format!("{data_class:?} data may not leave this machine without consent")
        }
        D::NoGrant { capability } => format!("there is no grant for {capability}"),
        D::GrantExpired { capability, .. } => format!("the grant for {capability} has expired"),
        D::ApprovalRequired { risk } => {
            format!("this action is {risk:?} risk and needs an explicit approval")
        }
        D::ApprovalExpired { .. } => "the approval is outside its validity window".to_owned(),
        D::ApprovalDigestMismatch => {
            "the approval does not describe the action being performed".to_owned()
        }
        D::ApprovalApproverCannotGrant => {
            "the approval was signed by something that cannot grant authority".to_owned()
        }
        D::ApprovalApproverNotAuthorised { approver, proposer } => {
            format!("{approver} may not consent to an action proposed by {proposer}")
        }
        D::ApprovalAlreadyUsed => "the approval has already been used".to_owned(),
        D::BudgetExceeded { .. } => "this actor's budget for this action is exhausted".to_owned(),
        D::PolicyUnavailable { .. } => {
            "the policy set could not be loaded, so nothing was decided".to_owned()
        }
        D::AuditUnavailable { .. } => {
            "the decision could not be recorded, so nothing was decided".to_owned()
        }
    }
}
/// The stable wire vocabulary word for a denial.
///
/// Lives here rather than being derived from the enum's serde rendering, because
/// `data.reason` is a contract: a client branches on it, so it has to be a fixed kebab-case
/// word rather than whatever `serde_json` produces. The human sentence is
/// `DenialReason`'s own `Display`, which renders the structured value.
fn denial_reason_word(d: &orxnud_policy::DenialReason) -> &'static str {
    use orxnud_policy::DenialReason as D;
    match d {
        D::NoAuthorityRoot { .. } => "no-authority-root",
        D::ActorMayNotGrant { .. } => "actor-may-not-grant",
        D::UnknownCapability { .. } => "unknown-capability",
        D::InvalidParams { .. } => "invalid-capability-params",
        D::DataClassExceeded { .. } => "data-class-exceeded",
        D::EgressNotConsented { .. } => "egress-not-consented",
        D::NoGrant { .. } => "no-grant",
        D::GrantExpired { .. } => "grant-expired",
        D::ApprovalRequired { .. } => "approval-required",
        D::ApprovalExpired { .. } => "approval-expired",
        D::ApprovalDigestMismatch => "approval-digest-mismatch",
        D::ApprovalApproverCannotGrant => "approval-approver-cannot-grant",
        D::ApprovalApproverNotAuthorised { .. } => "approval-approver-not-authorised",
        D::ApprovalAlreadyUsed => "approval-already-used",
        D::BudgetExceeded { .. } => "budget-exceeded",
        D::PolicyUnavailable { .. } => "policy-unavailable",
        D::AuditUnavailable { .. } => "audit-unavailable",
    }
}
/// The delegated proposer actor for a task.
///
/// `model` is supplied by the caller and must come from whichever component actually
/// produced the proposal — [`ProposalProvider::model_id`] when a model answered,
/// [`NO_MODEL_PROPOSED`] when none did. It is a parameter rather than a constant precisely
/// so that no model identity can be written here: a hardcoded name in this function was
/// recorded into the signed audit journal as though a model had answered, and it named
/// `openraynux/task-agent` while the provider that actually answered was something else
/// entirely.
///
/// `prompt_hash` stays a placeholder. It describes a prompt-framing version this code does
/// not version, and changing it is a separate question from recording a truthful model.
fn delegated_actor(
    delegated_by: &orxnud_domain::ids::UserId,
    task_id: &str,
    model: &str,
) -> orxnud_domain::Actor {
    use orxnud_domain::actor::ModelProvenance;
    orxnud_domain::Actor::Ai {
        // The delegating human, taken from the authenticated principal at the call site.
        //
        // This was `UserId::new("local")` written inline, which made the delegation
        // chain of every model proposal an assertion about a string rather than a
        // consequence of who was authenticated. An `Ai` actor can never *grant* —
        // `can_grant` is `Human`-only, and `issue_approval` refuses a non-granting
        // approver — so naming the wrong human here could not have granted anything. It
        // could still have *attributed* a proposal to a human who never asked for it,
        // which is precisely what an audit record claims to be about.
        delegated_by: delegated_by.clone(),
        run: orxnud_domain::ids::RunId::new(task_id),
        task: orxnud_domain::ids::TaskId::new(task_id),
        provenance: ModelProvenance::new(
            model,
            "phase-2",
            orxnud_domain::ids::RequestId::new(task_id),
        ),
    }
}

/// What verification established about the side effect.
///
/// Not the same question as "what did the adapter report", and the distinction is the
/// whole point: an adapter can report success and still leave nothing behind, can report
/// failure and still have written, or can die and leave either. Only the verifier looks
/// at the world afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Certainty {
    /// The effect is present as described.
    Established,
    /// Nobody can say either way. The dangerous one.
    Unknown,
}

/// Decides what a non-verified execution means for the task, durably.
///
/// # Why this function exists at all
///
/// The previous behaviour was to do nothing: a refuted or undetermined execution left the
/// task `running` under its lease and returned. Reproduced over a real daemon against real
/// durable state, that meant:
///
/// ```text
/// execute (undetermined)  -> task "running", lease held, nothing recorded
/// daemon restart          -> recovery sees "running" + a lease and returns it to "pending"
/// any worker claims it    -> attempt 2, running
/// task/propose            -> the same non-idempotent write, approved again
/// ```
///
/// So the daemon did say "we don't know whether it happened, so we tried again" — with no
/// human involved, at the next restart. Recovery reclaims *unexpired* leases (there is no
/// expiry predicate in that query), so the ambiguity was resolved by the next process start
/// rather than by anything durable.
///
/// `TaskState::NeedsVerification` already existed, was already terminal, already excluded
/// from claim and from recovery, and was never produced by any production path. The engine
/// needed nothing: `Running -> NeedsVerification` is already a legal transition, and
/// `complete_task` already clears the lease under the same TP-5 fence every other completion
/// uses. What was missing was the decision to make it.
/// The decision itself, as a pure function so it can be tested exhaustively.
///
/// # The table, and where each row comes from
///
/// | certainty | capability | state | why |
/// |---|---|---|---|
/// | `Established` | any | *(never called)* | verified takes the completion path |
/// | `Disproved` | any | `Failed` | the effect is provably not as described, so repeating it cannot duplicate anything. `WriteTextVerifier` already reasons this way -- "only `Refuted` makes it safe" -- and this is where that reasoning has to become state |
/// | `Unknown` | idempotent | `Failed` | repeating is safe by the capability's own declaration, so an uncertain result costs nothing |
/// | `Unknown` | non-idempotent | **`NeedsVerification`** | TP-2: "a non-idempotent task whose effect outcome is uncertain must never be re-executed automatically -- it awaits a human" |
///
/// The `Disproved` row is deliberately not conditioned on idempotency. A capability's
/// author already decided which of its findings make a retry safe, and they recorded that
/// in the verifier; re-deciding it here would be a second policy that can disagree with the
/// first.
///
/// The idempotent case is read from the **capability declaration**, never inferred. An
/// action nobody can vouch for is treated as non-idempotent, because that is the direction
/// which cannot duplicate an effect.
fn uncertainty_target(certainty: Certainty, idempotent: bool) -> TaskState {
    match certainty {
        // Established never reaches here; if it somehow did, `Failed` is the fail-closed
        // answer, because it is the one row that does not claim an effect happened.
        Certainty::Established => TaskState::Failed,
        Certainty::Unknown if idempotent => TaskState::Failed,
        Certainty::Unknown => TaskState::NeedsVerification,
    }
}

fn settle_unverified(
    tasks: &mut TaskService,
    task_id: &TaskId,
    worker: &str,
    // Grouped so the call site reads as the three facts it is passing and the arity stays
    // under the lint's limit without an `#[allow]`.
    finding: (Certainty, bool, &str),
    reason: &str,
    now_ms: i64,
) -> Result<UnverifiedSettlement, RequestError> {
    let (certainty, idempotent, capability) = finding;
    // An idempotent capability may be repeated, so an uncertain result costs nothing and
    // the ordinary failure path is the honest one. `filesystem/read-text` and
    // `text/word-count` sit here.
    //
    // The distinction comes from the capability's own declaration, never from the task row:
    // the task's `idempotent` flag is a different concept (whether the *task* may be
    // re-run as a unit) and reading it here would be exactly the substitution Phase 12 of
    // the brief warns against.
    let target = uncertainty_target(certainty, idempotent);

    // `effect_observed` is false in both cases and for the same reason: nobody observed the
    // effect happen. For `Failed` the effect was disproved; for `NeedsVerification` nobody
    // can say. The column is a boolean and cannot hold "unknown", which is precisely why
    // the state is what carries the uncertainty rather than this flag.
    let detail = format!(
        "{} ({}); certainty: {}",
        reason,
        capability,
        match certainty {
            Certainty::Established => "established",
            Certainty::Unknown => "unknown",
        }
    );
    // `complete_task_with` rather than `complete_task`: this needs `effect_observed` to be
    // false and needs to write a reason, and it fences through the same TP-5 conditional
    // update every other completion uses, so a worker whose lease ended mid-capability
    // cannot settle a task it no longer holds.
    //
    // `TaskFault::Fenced` is returned rather than absorbed. It means this worker's
    // authority ended while the capability was running, which is a fact the caller needs
    // and not an internal fault -- so it is mapped to `CONFLICT` by the V-90 taxonomy.
    let row = tasks
        .complete_task_with(task_id, worker, now_ms, target, false, Some(&detail), None)
        .map_err(|f| match f {
            TaskFault::Fenced => RequestError::Conflict {
                reason: "lease-lost-during-execution".to_owned(),
                // The capability already ran; what is refused is only the *settling* of
                // it. Saying so is what stops a client retrying the whole execution.
                detail: Some(
                    "the execution lease ended before the outcome could be recorded; the \
                     task is no longer this worker's to settle"
                        .to_owned(),
                ),
            },
            other => task_fault(other),
        })?;

    Ok(UnverifiedSettlement {
        state: row.state,
        settled: true,
    })
}

/// The outcome of settling an unverified execution.
struct UnverifiedSettlement {
    /// The state the task is now in, read back from the store rather than assumed.
    state: TaskState,
    /// Always true: a lost fence is an error, not a quiet no-op.
    settled: bool,
}

/// Reads the certainty a verification outcome establishes.
///
/// **A `Refuted` finding establishes `Unknown`, not `Disproved` (ADR-0056).** This is the
/// change that closes F-17, and the whole of it is this one line.
///
/// A verifier reports evidence about a **postcondition**. `WriteTextVerifier` re-reads the
/// filesystem and compares bytes; it does not and cannot report whether a process ran. A
/// `write-text` that genuinely succeeded and whose file a second task, an editor or a
/// concurrent governed run then changed is byte-for-byte indistinguishable, from here, from
/// one that never wrote — and "the file is absent" is the same inference, because a write
/// that happened and whose output was later deleted also looks absent.
///
/// `Disproved` used to mean "this answer is a disproof", which conflated *the verdict's
/// shape* with *a warrant*. `not-performed` is the one status `recover()` excludes from its
/// "may already have happened" test, so it is a retry permission, and a postcondition is not
/// evidence that an effect did not occur.
///
/// `Disproved` is therefore no longer produced here, and this is deliberate rather than
/// tidy: the variant keeps its meaning ("demonstrably did not happen"), and the arms that
/// consume it still map it to `not-performed`. That mapping stays correct for a future
/// producer that *can* warrant it. What ADR-0056 removed is the producer, not the meaning —
/// so a warrant can only ever come from pre-execution evidence (`ExecutionCertainty::
/// NothingAttempted`, or a `Policy` refusal decided before a process exists), never from
/// looking at a file afterwards.
/// The effect-ledger status a settled certainty implies.
///
/// **This is the only place a verification outcome becomes an effect status**, and
/// `not-performed` deliberately has no arm (ADR-0056 Decision 1). It is a named function
/// rather than an inline `match` because the mapping is the load-bearing step of F-17 and
/// an inline one cannot be tested directly: the first version of the S-03 regression
/// re-implemented this `match` locally, which meant it tested its own copy rather than the
/// production one -- and a mutation of the real mapping passed the suite. Extraction is what
/// makes the property testable at the seam where it actually lives.
fn effect_status_for_certainty(certainty: Certainty) -> EffectStatus {
    match certainty {
        Certainty::Established => EffectStatus::Observed,
        Certainty::Unknown => EffectStatus::Unknown,
    }
}

fn certainty_of(o: &orxnud_capability::verification::VerificationOutcome) -> Certainty {
    use orxnud_capability::verification::VerificationOutcome as V;
    match o {
        V::Verified { .. } => Certainty::Established,
        // Read carefully before "fixing" this back to `Disproved`: the verdict really is
        // negative, and that is precisely why it may not be treated as proof.
        V::Refuted { .. } => Certainty::Unknown,
        V::Undetermined { .. } => Certainty::Unknown,
    }
}

/// The human-readable reason for an unverified outcome, taken from the verifier.
///
/// The verifier's own words, because it is the component that looked at the world. It is
/// written into `last_error`, so it is durable text: it is path/digest/count shaped and
/// carries no file contents, which is the same data-minimisation rule
/// `retain_read_observation` and `VerifiedStep::verification` already follow.
fn unverified_reason(o: &orxnud_capability::verification::VerificationOutcome) -> &'static str {
    match o {
        orxnud_capability::verification::VerificationOutcome::Verified { .. } => "verified",
        orxnud_capability::verification::VerificationOutcome::Refuted { .. } => {
            "verification disproved the effect"
        }
        orxnud_capability::verification::VerificationOutcome::Undetermined { .. } => {
            "the effect could not be established"
        }
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
    actor: &orxnud_domain::Actor,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
    provider: Option<&Arc<dyn crate::proposer::ProposalProvider>>,
    observations: &std::sync::Mutex<crate::observation::ObservationStore>,
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
            .ok_or_else(|| RequestError::NotFound {
                reason: "proposal-not-found".to_owned(),
                detail: Some(format!("no proposal {proposal_id:?}")),
            })?;
    let proposer = proposal
        .proposer()
        .map_err(|e| RequestError::Invalid(format!("proposal proposer unusable: {e}")))?;
    let canonical = orxnud_domain::NormalizedParams::canonical(proposal.params.clone());

    // 2. The approval for *this attempt*, recomposed against the trusted approver. The
    //    digest was computed over that approver, so if it were minted under anyone else
    //    the dispatcher refuses it — which is the check, not this reconstruction.
    let approval_row =
        g.2.engine()
            .approval_for(&proposal.task_id, proposal.step_no, proposal.attempt_no)
            .map_err(|_e| RequestError::Internal {
                // Could not read the ledger, so we cannot know whether an approval was
                // already spent. That is a storage fault and it is fail-closed, but it is
                // not caller-actionable: retrying reaches the same fault. The cause is
                // dropped rather than interpolated for the same redaction reason as the
                // disclosure audit case.
                fault: InternalFault::StorageUnavailable,
                detail: Some("the approval ledger could not be read".to_owned()),
            })?
            .ok_or_else(|| RequestError::Forbidden {
                reason: "approval-required".to_owned(),
                // A fixed word, not a formatted sentence: `detail` is a second term in a
                // vocabulary a client branches on, and putting a task id in it would make
                // the value unpredictable.
                detail: Some("no approval is recorded for this proposal's attempt".to_owned()),
            })?;
    let record = approval_record_from_row(&approval_row, actor, &proposer, &proposal)?;

    // 3. Refuse an expired approval *before* taking the execution lease.
    //
    // This used to be left entirely to the policy stage, which does refuse it correctly and
    // with nothing written -- but by then `begin_approved_execution` had already flipped the
    // task to `running` under a fresh lease. So the refusal was correct and the aftermath was
    // a task that could not be executed again until that lease expired, which is the same
    // dead end as V-82 reached by a different route (and, unlike V-82, reached on *every*
    // expired attempt rather than only the awkward ones).
    //
    // The check uses `now` -- the same single reading that is then handed to the dispatcher,
    // and so to the policy stage. Two clock reads here would be two chances to decide an
    // authority question differently, which is exactly the bug class V-82 is.
    if !record.is_valid_at(now) {
        return Err(RequestError::Forbidden {
            reason: "approval-expired".to_owned(),
            detail: Some(format!(
                "the approval for this attempt expired at {}",
                record.expires_at_ms
            )),
        });
    }

    // 4. Take the fresh execution lease **and** spend the approval, in one transaction.
    //
    // V-94. These were two calls, and a failure of the second was logged while execution
    // proceeded -- so a capability could run with no durable record that its approval had
    // been spent. Reproduced over a real daemon with a real `write-text`: the reply came
    // back `verified: true`, `state: completed`, `steps_completed: 1`, with the
    // consumption refused.
    //
    // One transaction means the two cannot disagree. Every refusal below -- a missing
    // proposal, a task not waiting, an attempt whose approval is already spent -- rolls the
    // whole thing back, so no lease is granted and the task stays exactly where it was
    // with its approval still retryable.
    //
    // # Which ledger is authoritative
    //
    // Neither one mirrors the other, and it is worth being precise because the old comment
    // claimed otherwise:
    //
    // * `spent_approvals`, written by `PolicyEngine::authorise` *inside* `dispatch` below,
    //   is the replay gate. It is read by `evaluate` before the decision and burned before
    //   the capability runs, so it stops one approval being presented twice across the
    //   whole installation and across restarts.
    // * `task_approvals.consumed_at_ms` is the task domain's record of which approval
    //   authorised which attempt of which step. `record_approval_replacing_expired` reads
    //   it when deciding whether a step's approval may be replaced.
    //
    // So at this point the authoritative ledger has *not* committed -- that happens four
    // steps down -- and the "the ledger is authoritative, so a failure here is only a
    // reporting fault" argument this call site used to make was not available. It is a
    // precondition now.
    let began =
        g.2.begin_execution_spending_approval(&proposal_id, &worker, now)
            .map_err(task_fault)?;

    // 5b. Reserve the side effect, *before* it is dispatched.
    //
    // This is the durable record that the world may already have changed, and it is
    // written here for the same reason the dedupe row is written before the call
    // rather than after: a record made afterwards cannot describe a crash. The
    // window between this line and the settlement below is the one V-93 exists to
    // close, and it is only closeable because something durable already says "a
    // dispatch was authorised and its outcome is not established".
    //
    // Before this existed the ledger was only written by tests, so
    // `TaskRepository::recover` had nothing to consult and an interrupted
    // non-idempotent task went back to `pending` on the next start.
    //
    // The key is scoped to `(task, capability, step, attempt)` — the same tuple
    // `task_approvals` uses as its primary key. All four parts are needed, and two
    // of the obvious narrower choices are wrong:
    //
    //  * `(task, capability, attempt)` is **not** unique: the attempt counter
    //    restarts at every step boundary (`complete_verified_step` clears it), so a
    //    two-step task that runs the same capability twice would collide on step 2
    //    and be refused as a duplicate dispatch. A real test caught this.
    //  * `(task, capability, step)` is **too** narrow: a retry of a disproved step
    //    keeps its step number and advances only its attempt, so the step-scoped
    //    key would make a step permanently un-retryable — including the
    //    `Refuted -> Failed` retry V-92 deliberately allows.
    //
    // So: within one `(step, attempt)` a resumed or duplicated dispatch is refused,
    // which is the dedupe guarantee ADR-0007 asks for; and a genuine retry gets a
    // fresh key.
    //
    // Recovery does **not** reason over every row for the task, and it did not even before
    // this slice — that claim was left here by the commit that introduced the ledger and
    // was not corrected when the scope was narrowed. It scopes to the execution being
    // recovered, `(task_id, step_no = steps_completed + 1, attempt_no = attempts)`, which
    // is the whole point of that change: a verified effect from a *completed earlier step*
    // says nothing about whether the step that just crashed may be retried, and because
    // `needs-verification` is terminal, letting it decide made a multi-step task
    // permanently unrecoverable. See `TaskRepository::recover`.
    //
    // The consequence worth stating at the call site: an unresolved row from an earlier
    // step or attempt no longer holds the task. What keeps such a row from being lost is
    // the invariant enforced below and in `propose_action` — a reserved unresolved effect
    // always has *some* owner, either a running execution that recovery will reclaim or an
    // explicitly resolved row — not a catch-all scan.
    // Whether repeating *this action* is safe comes from the capability's own
    // declaration. Read from the registry rather than the proposal or the task row,
    // and defaulted to `false` when the capability is unknown -- an unrecognised
    // action is treated as one that must not be repeated, which is the direction that
    // cannot duplicate an effect.
    //
    // Read here, before the reservation, because the reservation records it and the
    // recovery path reads it back. V-92 established the same source for the same
    // reason: the task row cannot answer this question.
    let capability_id = orxnud_domain::ids::CapabilityId::new(proposal.capability.as_str());
    let idempotent =
        g.0.registry()
            .get(&capability_id)
            .is_some_and(|d| d.idempotent);

    let effect_attempt_class = format!("{}/{}", proposal.step_no, proposal.attempt_no);
    let effect_key = orxnud_task::DurableEngine::idempotency_key(
        &proposal.task_id,
        &proposal.capability,
        &effect_attempt_class,
    );
    if !g
        .2
        .reserve_effect(
            &effect_key,
            &proposal.task_id,
            // From the proposal, not recomputed. The proposal is the durable record of
            // which step and attempt this execution is, and the reservation has to
            // describe the same execution `recover()` will later ask about.
            proposal.step_no,
            proposal.attempt_no,
            &proposal.capability,
            idempotent,
            now,
        )
        .map_err(task_fault)?
    {
        // This attempt already reserved this effect. Dispatching again would be the
        // duplicate ADR-0007's invariant 3 exists to prevent, so it is a conflict
        // and not a silent second run.
        return Err(RequestError::Conflict {
            reason: "effect-already-reserved".to_owned(),
            detail: Some(
                "this attempt already reserved the side effect; it cannot be dispatched twice"
                    .to_owned(),
            ),
        });
    }

    // 6. Dispatch. The action comes from the proposal; `action.params` and
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
            return Err(RequestError::Internal {
                fault: InternalFault::DurableStateCorrupt,
                detail: Some("the stored parameters are not readable JSON".to_owned()),
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

    // 7. Record what the effect turned out to be.
    //
    // The reservation above stays `pending` if the process dies here, and `pending`
    // is precisely the evidence recovery reads to refuse re-running uncertain
    // non-idempotent work. So *every* exit from a dispatch that reached the
    // capability has to resolve it, or the task stays uncertain forever.
    //
    // This mirrors the mapping V-92 already makes for the task state, from the same
    // `VerificationOutcome`, and is deliberately the same table:
    //
    // | verification | effect | task |
    // |---|---|---|
    // | `Verified`   | `observed`      | completes the step |
    // | `Refuted`    | `not-performed` | `Failed`, retryable |
    // | `Undetermined` | `unknown`     | `Failed` if idempotent, else `needs-verification` |
    //
    // An adapter-reported failure is not used here. A subprocess can die after
    // writing, so `ExecutionOutcome::Failed` is not evidence about the effect -- the
    // same reason V-92 does not treat it as a disproof.
    //
    // A `dispatch` *error* is a different question, and it is answered by the dispatch
    // contract rather than by this ledger. See `effect_status_for_dispatch_failure`.
    let o = match outcome {
        Ok(o) => o,
        Err(e) => {
            // Resolving *before* returning is what makes a later lease release safe: the
            // ledger is no longer holding an unresolved effect, so the execution lease
            // this call took can be released by a subsequent transition without making
            // anything invisible to recovery.
            //
            // The verdict comes from the dispatch contract, not from the status of the
            // call: stages 1-6 cannot have run the capability, and stage 7's error is a
            // positive statement that it did not. Leaving the row `pending` recorded
            // *less* than the dispatcher already knew, and since `pending` is what
            // recovery reads as "do not repeat this", a definitively-failed dispatch
            // became a terminal `needs-verification` and a permanently wedged task.
            let settled_at = g.2.clock_now_ms();
            let status = effect_status_for_dispatch_failure(&e);
            if let Err(resolve_err) =
                g.2.resolve_effect(&effect_key, status, Some(&e.to_string()), settled_at)
            {
                // The row stays `pending`. That is the fail-closed reading and it is still
                // reachable-by-recovery, because the task keeps the execution lease this
                // call took — `propose_action` refuses to release it while an unresolved
                // effect stands. So this is a degradation of the verdict, not a lost
                // record.
                tracing::error!(
                    error = ?resolve_err,
                    task = %proposal.task_id.as_str(),
                    effect = %effect_key,
                    "the dispatch failed and its effect could not be recorded; the effect stays unresolved"
                );
            }
            return Err(dispatch_failure(&e));
        }
    };
    // V-93's window: the effect is reserved and its outcome is not yet recorded.
    // A crash here leaves exactly the state `recover` has to recognise, so the
    // point is what makes that path testable through a real process rather than a
    // constructed row. `maybe_crash` is a no-op unless `ORXNUD_FAULT` names it.
    orxnud_store::faults::maybe_crash(
        orxnud_store::faults::FaultPoint::ExecutionReservedBeforeOutcome,
    );
    {
        let settled_at = g.2.clock_now_ms();
        let effect_status = effect_status_for_certainty(certainty_of(&o.verification));
        if let Err(e) =
            g.2.resolve_effect(&effect_key, effect_status, None, settled_at)
        {
            // The row stays `pending`, which is the fail-closed reading: recovery
            // will refuse to re-run a non-idempotent task whose effect it cannot
            // account for. Losing the fine-grained verdict costs a retry or a
            // human; inventing one would cost correctness.
            tracing::error!(
                error = ?e,
                task = %proposal.task_id.as_str(),
                effect = %effect_key,
                "the side-effect ledger could not record this outcome; the effect stays unresolved"
            );
        }
    }
    // Set only on the unverified path; `None` on the verified one.
    let mut outcome_uncertainty: Option<UnverifiedSettlement> = None;

    // Completion is gated on the **verifier**, not on the dispatcher having returned.
    //
    // What happens when the verifier does *not* confirm used to be nothing at all, and
    // that was the V-92 defect: the task stayed `running` under its lease, so the next
    // recovery pass returned it to `pending` -- where `claim` finds it -- and the same
    // non-idempotent action could be proposed, approved and executed again. Reproduced
    // end to end against a real daemon before this change.
    //
    // Now the uncertainty is settled durably: a disproved effect or an idempotent
    // capability takes the ordinary failure path, and an unknown effect on a
    // non-idempotent capability becomes `NeedsVerification`, which is terminal, is not
    // claimable, and is not touched by recovery.
    // Verified execution is where a logical step ends, and ending one is a durable fact
    // rather than a task-level event: the step result, the counter and the state all have
    // to agree, and they agree only inside one transaction. `complete_verified_step` is
    // that transaction, and it decides between `AwaitingNextStep` and `Completed` from the
    // task's own `max_steps`.
    //
    // The step number is read from the durable counter rather than carried in memory, and
    // checked against the proposal this execution came from, so an approval minted for one
    // step cannot advance another.
    // `idempotent` is read above, before the reservation, and reused here so the
    // ledger row and the task state cannot disagree about whether repeating this
    // action is safe.
    let advance = if o.is_verified() {
        let complete_at = g.2.clock_now_ms();
        let step_no = g.2.next_step_no(&began.task_id).map_err(task_fault)?;

        // The read's content becomes available to the *next* proposal on this task, and to
        // nothing else. Placed here rather than inside the capability, because the capability
        // does not know about providers, proposals or steps, and putting it there would make
        // the sandboxed adapter responsible for an egress decision.
        retain_read_observation(
            VerifiedRead {
                task_id: &began.task_id,
                proposal: &proposal,
                approval: &record,
                outcome: &o,
                step_no,
                now_ms: complete_at,
            },
            provider,
            observations,
        );
        let step = orxnud_store::task_repo::VerifiedStep {
            task_id: began.task_id.clone(),
            worker: &worker,
            step_no,
            proposal_id: &proposal_id,
            status: orxnud_store::task_repo::StepStatus::Verified,
            // Bounded metadata only, never the bytes. See `note_durable_evidence`: the
            // verifier's evidence is already path/count/digest shaped, and the verifier is
            // the component that established the content independently.
            verification: Some(o.verification.to_string()),
            // `structured_output` is durable, so it may only hold what a caller is willing to
            // keep. A capability that declares its output ephemeral (a workspace read) has
            // its output dropped here rather than written into the step result: the bytes
            // were returned to the dispatcher, and persisting them would copy file contents
            // into `task_step_results` merely because something read a file.
            //
            // Behaviour-neutral for every other capability: the default is `false`, and the
            // branch below is the same expression as before in that case.
            structured_output: durable_output(&o),
            // The step's target, as a workspace-relative reference. This is the capability
            // contract's own path vocabulary, already validated at dispatch, so it is the one
            // string a later step needs in order to *ask* for the content through a governed
            // read -- and it is a reference, not the content.
            //
            // `None` when the capability declared no target, and `Some` only when the stored
            // proposal named one, so nothing is synthesised here.
            artifacts: safe_artifact_reference(proposal.target.as_deref()),
            recorded_at_ms: complete_at,
        };
        Some(g.2.complete_verified_step(&step).map_err(task_fault)?)
    } else {
        let settle_at = g.2.clock_now_ms();
        let settled = settle_unverified(
            &mut g.2,
            &began.task_id,
            &worker,
            (
                certainty_of(&o.verification),
                idempotent,
                proposal.capability.as_str(),
            ),
            unverified_reason(&o.verification),
            settle_at,
        )?;
        // Surfaced rather than swallowed: the caller has to learn that the task stopped
        // and why, because "the call returned" and "the task is now waiting on a human"
        // are different outcomes.
        outcome_uncertainty = Some(settled);
        None
    };

    Ok(json!({
        "proposal": proposal_json(&began),
        "verified": o.is_verified(),
        "refuted": o.verification.is_refuted(),
        "undetermined": o.verification.is_undetermined(),
        "result": o.verification.to_string(),
        // What the uncertainty did to the task. `null` on the verified path, and
        // `state: "needs-verification"` on the path that matters: a client can see from
        // this reply alone that the task has stopped and is waiting on a person, rather
        // than having to poll `task/list` to discover it went quiet.
        "uncertainty": outcome_uncertainty.as_ref().map(|u| json!({
            "settled": u.settled,
            "task_state": u.state.as_wire_str(),
            "awaiting": if u.state == TaskState::NeedsVerification {
                "human-adjudication"
            } else {
                "retry"
            },
        })),
        // `null` when the verifier did not confirm, so a client can tell "not completed"
        // from "completed, and here is the stored row".
        "task": advance
            .as_ref()
            .map(|_| TaskId::new(began.task_id.as_str()))
            .map(|id| g.2.task(&id))
            .transpose()
            .map_err(task_fault)?
            .flatten()
            .as_ref()
            .map(task_json),
        // Which logical step just concluded, and how far the task now is. Present only
        // when the verifier confirmed, for the same reason `task` is.
        "step": advance.as_ref().map(|a| {
            json!({
                "completed": a.step_no,
                "steps_completed": a.steps_completed,
                "max_steps": a.max_steps,
                "next_step": a.steps_completed + 1,
            })
        }),
    }))
}

/// Retains a verified read's content so the next proposal on this task can be told about it.
///
/// # Every condition here is a refusal, and each exists for a stated reason
///
/// * **`output_is_ephemeral`** — the capability itself declared that its output is content
///   that must not become durable. This is what selects the read path without the runtime
///   naming `filesystem/read-text`: a second copy of the capability list would drift, and the
///   capability's own declaration is the authoritative statement of what its output is.
/// * **`is_verified`** — the verifier confirmed the bytes reported are the bytes on disk. A
///   read that exited zero, or that the verifier could not confirm, produces no observation.
///   `undetermined` in particular means "something may have happened and nobody can say what",
///   which is not a basis for sending anything anywhere.
/// * **Succeeded output** — the bytes are the dispatcher's own record of what the helper read.
/// * **`Actor::Ai`, with the configured model** — ADR-0045's approval covers disclosure to
///   *the provider identity that asked for the read*. A human reading a file creates no such
///   identity, so there is nothing the approval could have authorised and nothing is retained.
///   The model is then compared against the provider this daemon is actually configured to
///   ask, which closes the case where the configuration changed between the read and the
///   disclosure: the proposal names the model that asked, and only that model may be told.
/// * **A workspace-relative path** — the same rule the durable artifact reference uses, so a
///   string reaching a prompt and a string reaching an audit record are accepted identically.
///
/// # Nothing here can fail the request
///
/// A read that produces no observation is a normal outcome, not an error: the model re-proposes
/// the read, which is the documented recovery. Failing here would mean an operator's provider
/// configuration turned a completed, verified, correctly-recorded step into an error, which
/// would be a worse outcome than not disclosing.
fn retain_read_observation(
    read: VerifiedRead<'_>,
    provider: Option<&Arc<dyn crate::proposer::ProposalProvider>>,
    observations: &std::sync::Mutex<crate::observation::ObservationStore>,
) {
    if !read.outcome.output_is_ephemeral || !read.outcome.is_verified() {
        return;
    }
    let orxnud_capability::verification::ExecutionOutcome::Succeeded {
        output: Some(content),
    } = &read.outcome.execution
    else {
        return;
    };
    let Some(identity) = asking_provider_identity(read.proposal, provider) else {
        return;
    };
    let Some(path) = workspace_relative_path(read.proposal.target.as_deref().unwrap_or_default())
    else {
        return;
    };
    let origin = crate::observation::ObservationOrigin {
        // The read's own audit correlation, derived the same way policy derives it, so the
        // disclosure cites the same key the read's records rode rather than inventing one.
        parent_read_request: orxnud_domain::ids::RequestId::new(format!(
            "{}#{}",
            read.task_id.as_str(),
            read.step_no
        )),
        parent_proposal_id: read.proposal.proposal_id.clone(),
        approver: read.approval.approver.clone(),
    };

    let observation = crate::observation::Observation {
        task_id: read.task_id.clone(),
        step_no: read.step_no,
        path,
        provider: identity,
        bytes: content.clone().into_bytes(),
        recorded_at_ms: read.now_ms,
        origin,
    };

    match observations.lock() {
        Ok(mut store) => store.retain(observation),
        Err(e) => {
            // No content is disclosed, and the step itself still completes: the governed path
            // has already done its work correctly and this is a loss of an optional channel.
            tracing::error!(
                error = ?e,
                task = %read.task_id.as_str(),
                step_no = read.step_no,
                "an approved verified read could not be retained for disclosure"
            );
        }
    }
}

/// One verified dispatch, as the retention step needs to see it.
///
/// Gathered because the call site would otherwise carry eight arguments, and at that count it
/// is no longer possible to see which `&ProposalRow` is the executed one. A struct rather than a
/// tuple for the same reason as [`ProposalWrite`]: a positional one would allow the proposal
/// and the approval to be transposed.
struct VerifiedRead<'a> {
    /// The task it ran for.
    task_id: &'a TaskId,
    /// The proposal that was approved and executed.
    proposal: &'a orxnud_store::task_repo::ProposalRow,
    /// The approval that permitted it, recomposed against the trusted approver.
    approval: &'a orxnud_domain::ApprovalRecord,
    /// What the dispatcher and the verifier concluded.
    outcome: &'a orxnud_capability::dispatch::DispatchOutcome,
    /// The logical step it ran on.
    step_no: u32,
    /// When it was verified.
    now_ms: i64,
}

/// The provider identity an AI-proposed action asked through, if it is still this one.
///
/// Returns `None` unless the proposal's proposer is an `Actor::Ai` **and** the model it names
/// is the model this daemon is configured to ask. Both halves are load-bearing:
///
/// * a non-`Ai` proposer has no provider identity, and ADR-0045 authorises disclosure to an
///   identity that asked for the read — so there is nothing to authorise;
/// * the model comparison is what stops a *re-pointed or re-configured* provider from being
///   told about a read proposed under the old configuration. The endpoint alone would not
///   catch a same-endpoint model swap, and the model alone would not catch a re-point; the
///   identity carries both, and the identity is what the store later compares.
fn asking_provider_identity(
    proposal: &orxnud_store::task_repo::ProposalRow,
    provider: Option<&Arc<dyn crate::proposer::ProposalProvider>>,
) -> Option<crate::observation::ProviderIdentity> {
    let provider = provider?;
    let proposer = proposal.proposer().ok()?;
    let orxnud_domain::Actor::Ai { provenance, .. } = proposer else {
        return None;
    };
    if provenance.model != provider.model_id() {
        return None;
    }
    provider.destination()
}

/// The execution output that may be written to durable step state, if any.
///
/// # Why this exists as its own function
///
/// `task_step_results.structured_output` is durable. A capability whose output is
/// *ephemeral* -- a workspace read, where the bytes are the file's contents -- must have
/// its output dropped here rather than persisted, or reading a file would copy its contents
/// into the database as a side effect of nothing more than having read it.
///
/// Extracted so the decision is testable on its own. Left inline it would be a match arm
/// buried in a large JSON assembly, where the only way to exercise it is to run a whole
/// governed dispatch through a real sandbox -- and an untested version of this expression is
/// exactly how file contents would end up in a durable row.
fn durable_output(outcome: &orxnud_capability::dispatch::DispatchOutcome) -> Option<String> {
    if outcome.output_is_ephemeral {
        return None;
    }
    match &outcome.execution {
        orxnud_capability::verification::ExecutionOutcome::Succeeded { output } => output.clone(),
        _ => None,
    }
}

/// A workspace-relative path rendered as a bounded artifact reference.
///
/// Reuses the same acceptance rule as [`crate::proposer`]'s own filtering, so a value that
/// reaches a prompt is one that already satisfied it. Serialised as a one-element JSON array,
/// which is the form `bounded_artifacts` reads.
///
/// Returns `None` rather than an empty list, so "this step produced nothing addressable" and
/// "this step's target was not a path" do not have to be distinguished by a consumer.
fn safe_artifact_reference(target: Option<&str>) -> Option<String> {
    Some(serde_json::json!([workspace_relative_path(target?)?]).to_string())
}

/// The one workspace-relative path rule, in the form a single path needs.
///
/// Delegates to [`crate::proposer::safe_relative_path`] rather than repeating the check. It
/// previously kept a private copy with its own length bound, and two copies of "is this string
/// safe to put in a prompt" is exactly the arrangement in which one of them is later loosened
/// without the other. Both the durable artifact reference and the observation's own `path`
/// field now come through here, so a path that can reach a prompt and a path that can reach an
/// audit record are accepted by the same rule.
///
/// Returns `None` for an absolute path, for anything with a `..`, `.`, root or Windows
/// prefix component, and for an over-long name.
fn workspace_relative_path(target: &str) -> Option<String> {
    crate::proposer::safe_relative_path(target)
}

/// Rebuilds the approval record for dispatch from the stored row.
///
/// The approver is **not** read from storage or from the request: it is re-derived from
/// the trusted local-human boundary, exactly as at minting time. Because the digest
/// binds the approver, a row minted by anyone else fails the recompute rather than
/// quietly verifying.
fn approval_record_from_row(
    row: &orxnud_store::task_repo::ApprovalRow,
    approver: &orxnud_domain::Actor,
    proposer: &orxnud_domain::Actor,
    proposal: &orxnud_store::task_repo::ProposalRow,
) -> Result<orxnud_domain::ApprovalRecord, RequestError> {
    let digest = digest_from_hex(&row.digest_hex).ok_or_else(|| RequestError::Internal {
        fault: InternalFault::DurableStateCorrupt,
        detail: Some("the stored digest is not 64 hex characters".to_owned()),
    })?;
    // The approval must be *for this action*. Cheap pre-check so the refusal names the
    // mismatch instead of surfacing as a digest failure deep in the dispatcher.
    // Both rows name a step, and they must be the same one. The approval's own step is
    // what its digest was computed over, so that is the step carried forward; the check
    // exists so an approval recorded against a proposal for a different step is refused
    // rather than quietly reinterpreted as belonging to this one.
    if row.step_no != proposal.step_no {
        return Err(RequestError::Forbidden {
            reason: "approval-step-mismatch".to_owned(),
            detail: Some(
                "the approval was issued for a different logical step than the proposal it is recorded against"
                    .to_owned(),
            ),
        });
    }
    if row.capability != proposal.capability
        || row.params != proposal.params
        || row.target != proposal.target
    {
        return Err(RequestError::Forbidden {
            reason: "approval-action-mismatch".to_owned(),
            detail: Some("the approval was issued for a different action".to_owned()),
        });
    }
    Ok(orxnud_domain::ApprovalRecord {
        actor_label: proposer.label().to_owned(),
        // The approver is the authenticated actor, not a constant and not anything from
        // the request. See [`authenticate`].
        approver: approver.clone(),
        capability: row.capability.clone(),
        target: row.target.clone().unwrap_or_else(|| "-".to_owned()),
        params: orxnud_domain::NormalizedParams::canonical(row.params.clone()),
        issued_at_ms: row.issued_at_ms,
        expires_at_ms: row.expires_at_ms,
        risk: orxnud_domain::enums::RiskClass::High,
        step_no: row.step_no,
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
    actor: &orxnud_domain::Actor,
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
            .ok_or_else(|| RequestError::NotFound {
                reason: "proposal-not-found".to_owned(),
                detail: Some(format!("no proposal {proposal_id:?}")),
            })?;
    // The proposal's status records *the decision to approve*, and expiry is a property of
    // the approval row rather than of that decision. Before this, an `approved` proposal was
    // refused unconditionally, so an approval that expired while the task waited left the
    // proposal decided with no authority behind it and no way to issue another: the only
    // recovery was cancelling the task (V-82).
    //
    // So an `approved` proposal is re-approvable exactly when its approval has expired
    // unconsumed, and refused otherwise — and the refusal says which, because "there is a
    // live approval, use it" and "the approval was used, this step is done" ask a client to
    // do opposite things.
    let was_pending = proposal.is_pending();
    if !was_pending && proposal.status != "approved" {
        return Err(RequestError::Conflict {
            reason: "proposal-already-decided".to_owned(),
            detail: Some("only a pending proposal can be approved".to_owned()),
        });
    }
    let replacing = if was_pending {
        None
    } else {
        match g
            .2
            .engine()
            .approval_for(&proposal.task_id, proposal.step_no, proposal.attempt_no)
            .map_err(|_e| RequestError::Internal {
                // Could not read the ledger, so we cannot know whether an approval was
                // already spent. That is a storage fault and it is fail-closed, but it is
                // not caller-actionable: retrying reaches the same fault. The cause is
                // dropped rather than interpolated for the same redaction reason as the
                // disclosure audit case.
                fault: InternalFault::StorageUnavailable,
                detail: Some("the approval ledger could not be read".to_owned()),
            })? {
            // No approval row at all, yet the proposal says approved. The durable state
            // disagrees with itself; refusing is the only answer, and it is recoverable
            // because nothing was written.
            None => {
                return Err(RequestError::Forbidden {
                    reason: "approval-not-found".to_owned(),
                    detail: Some(
                        "the proposal is approved but no approval is recorded for it".to_owned(),
                    ),
                });
            }
            Some(row) => Some(row),
        }
    };

    // Both refusals decided from durable state, and both before anything is written.
    if let Some(prior) = &replacing {
        if prior.consumed_at_ms.is_some() {
            return Err(RequestError::Forbidden {
                reason: "approval-already-consumed".to_owned(),
                detail: Some("the approval for this attempt has already been used".to_owned()),
            });
        }
        // Half-open, matching `is_valid_at`: live while `now < expires_at_ms`.
        if now < prior.expires_at_ms {
            return Err(RequestError::Forbidden {
                reason: "approval-already-valid".to_owned(),
                detail: Some(format!(
                    "an approval for this attempt is valid until {}",
                    prior.expires_at_ms
                )),
            });
        }
    }
    let proposer = proposal
        .proposer()
        .map_err(|e| RequestError::Invalid(format!("proposal proposer unusable: {e}")))?;

    // The trusted approver, and the digest computed over BOTH parties plus the stored
    // action. Nothing here is taken from the request except the proposal id.
    //
    // `actor` is the authenticated principal's actor, threaded down from `route`. This
    // used to be `local_actor()` called here, so the approver was a constant: real
    // authority, attributed to whoever happened to hold the socket.
    let canonical = orxnud_domain::NormalizedParams::canonical(proposal.params.clone());
    let record = orxnud_policy::issue_approval(
        actor,
        &proposer,
        &orxnud_domain::CapabilityId::new(proposal.capability.as_str()),
        proposal.target.as_deref(),
        &canonical,
        now,
        now.saturating_add(ttl_ms),
        orxnud_domain::enums::RiskClass::High,
        // From the durable proposal, not from the caller and not from `attempt_no`: a
        // retried step keeps its step, so the two are not interchangeable.
        proposal.step_no,
    );

    // Recorded against the attempt, so a retry would not inherit it (TP-6), and marked
    // decided, so the proposal stops being approvable.
    let approval_row = orxnud_store::task_repo::ApprovalRow {
        task_id: proposal.task_id.clone(),
        attempt_no: proposal.attempt_no,
        step_no: proposal.step_no,
        digest_hex: digest_hex(&record.digest),
        capability: record.capability.clone(),
        target: proposal.target.clone(),
        params: record.params.as_str().to_owned(),
        issued_at_ms: record.issued_at_ms,
        expires_at_ms: record.expires_at_ms,
        consumed_at_ms: None,
    };
    // An approval that is expired the moment it is minted authorises nothing, so minting one
    // would move the proposal to `approved` with no authority behind it — the dead end this
    // whole change exists to remove, arrived at in a single request. Refused *before* any
    // write, so the proposal stays `pending` and the task stays `waiting-for-user`, and the
    // same call with a usable TTL simply works.
    //
    // The half-open comparison is `is_valid_at`'s, so an approval expires at exactly
    // `expires_at_ms` rather than one instant either side of it.
    if !record.is_valid_at(now) {
        return Err(RequestError::Forbidden {
            reason: "approval-expired".to_owned(),
            detail: Some(
                "the requested time to live leaves the approval already expired".to_owned(),
            ),
        });
    }

    let outcome =
        g.2.record_approval_replacing_expired(&approval_row, now)
            .map_err(task_fault)?;
    match outcome {
        orxnud_store::task_repo::ApprovalOutcome::Recorded
        | orxnud_store::task_repo::ApprovalOutcome::ReplacedExpired => {}
        // The store re-reads inside its own transaction, so this is the answer as of the
        // write rather than as of the read above. Reported as itself rather than retried:
        // the caller has to know which of "a live approval exists" and "the approval was
        // used" it is looking at, and one deterministic answer is worth more than a
        // transparent retry here.
        orxnud_store::task_repo::ApprovalOutcome::Refused(r) => {
            return Err(RequestError::Declined {
                reason: r.as_str().to_owned(),
                detail: Some(match r {
                    orxnud_store::task_repo::ApprovalRefusal::AlreadyValid { expires_at_ms } => {
                        format!("an approval for this attempt is valid until {expires_at_ms}")
                    }
                    orxnud_store::task_repo::ApprovalRefusal::AlreadyConsumed { .. } => {
                        "the approval for this attempt has already been used".to_owned()
                    }
                }),
            });
        }
    }

    // `decide_proposal` transitions a *pending* proposal. On the replacement path the
    // proposal is already `approved` and there is nothing to decide, so the call is skipped
    // rather than made tolerant: the transition table stays one-way, and an `approved`
    // proposal that somehow lost its approval row is reported by the check above rather than
    // papered over here.
    let decided = if was_pending {
        g.2.decide_proposal(&proposal_id, "approved", now)
            .map_err(task_fault)?
    } else {
        proposal
    };

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
    actor: &orxnud_domain::Actor,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
) -> Result<serde_json::Value, RequestError> {
    let params = request.params.clone().unwrap_or(json!({}));
    // A named proposal takes a different path entirely: the caller supplies no action at
    // all, so there is nothing for it to have substituted.
    if params.get("proposal").is_some() {
        return approve_proposal(request, actor, governed).await;
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

    let capability_id = orxnud_domain::CapabilityId::new(capability);
    // Canonicalised through the one function dispatch canonicalises with. Building the
    // canonical text here any other way is precisely the V-63 defect in a new place.
    let canonical = orxnud_policy::canonical_params(&inner);
    // The approver is the authenticated human, derived from the transport principal and
    // threaded in rather than supplied by the request (ADR-0037, V-69). An approval caller
    // cannot nominate its own approver: this line is the whole reason the approver field
    // is evidence rather than decoration. `issue_approval` independently refuses a
    // non-granting principal, so a future caller cannot quietly widen it.
    let record = orxnud_policy::issue_approval(
        actor,
        actor,
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
        STANDALONE_APPROVAL_STEP,
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
    approver: &orxnud_domain::Actor,
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
        // The approver is **not** read from the client, and is no longer a constant
        // either: it is the actor derived from the authenticated transport principal and
        // threaded in from `route`. So a client cannot present an approval naming an
        // approver of its choosing — the digest check would fail anyway, but refusing to
        // carry the field at all makes the guarantee structural rather than arithmetic,
        // and deriving it makes it true of whoever actually connected.
        approver: approver.clone(),
        capability: text("capability")?,
        target: text("target")?,
        params: orxnud_domain::NormalizedParams::canonical(text("params")?),
        issued_at_ms: number("issued_at_ms")?,
        expires_at_ms: number("expires_at_ms")?,
        // Carried for display only; `authorise` derives risk from the declaration.
        risk: orxnud_domain::enums::RiskClass::High,
        // Not read from the JSON. This approval governs no task and therefore has one
        // step; letting the caller name the step would let it claim authority it was
        // never granted for any other.
        step_no: STANDALONE_APPROVAL_STEP,
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

/// The most logical steps one task may have.
///
/// `max_steps` is the only thing bounding how long a task can run, so it is bounded here
/// as well as in the store: a caller asking for a million steps has not described a task,
/// it has handed the daemon a number it will never finish. Sixty-four is far beyond any
/// plausible plan and small enough that the worst case is a bounded number of governed
/// steps rather than an open-ended one.
const MAX_MAX_STEPS: u32 = 64;

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
/// Registers or lists schedules.
///
/// # Why this route had to be added
///
/// `TaskService::tick` and `next_wakeup_ms` existed, were tested, and had **no production
/// caller**: `Scheduler::add_schedule` had no route either, so no schedule could be
/// registered, so the timer had nothing to fire. A scheduler that cannot be written to is
/// not an unwired feature; it is an unreachable one. Adding the timer without this route
/// would have produced a test-only capability, which is the shape this repository is most
/// careful to avoid.
///
/// # What it grants, and what it does not
///
/// Nothing. A schedule is a row the daemon owns, exactly like a task: registering one
/// performs no capability invocation, resolves no credential, and creates no proposal. The
/// occurrence it eventually produces is a `Pending` task, which then goes through the
/// ordinary claim/propose/approve/execute route — so nothing here is a way around the
/// governed path, and nothing here is authorised *by* the schedule.
///
/// # Why `authorised_by` is the authenticated principal
///
/// It is taken from `AuthenticatedPrincipal::user()`, not from the request. A schedule
/// record that named its own author would be an assertion about a string, which is exactly
/// what ADR-0051 removed from the actor path.
#[allow(clippy::too_many_arguments)]
async fn schedule<S: SecretsContract>(
    method: Method,
    request: &Request,
    authenticated: AuthenticatedPrincipal,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
) -> Result<serde_json::Value, RequestError> {
    let params = request.params.clone().unwrap_or(json!({}));
    let mut g = governed.lock().await;
    let now = g.2.clock_now_ms();

    match method {
        Method::ScheduleCreate => {
            let id = required_str(&params, "id")?;
            check_len("id", &id, MAX_TASK_ID_BYTES)?;
            let cron = required_str(&params, "cron")?;
            check_len("cron", &cron, MAX_TASK_CONTENT_BYTES)?;
            // Defaults, stated rather than implied: the daemon's ambient local time is
            // never used, because a schedule whose meaning depends on the machine it was
            // registered on is not a schedule the user can reason about. `UTC` is
            // explicit and documented in the reply.
            let timezone = optional_str(&params, "timezone")?.unwrap_or_else(|| "UTC".to_owned());
            let authorised_by = authenticated.user();
            let limits = g.2.limits();
            // The scheduler owns validation: a bad cron expression or an unknown timezone
            // is refused here, at the point of creation, rather than at 3am on the first
            // pass that tries to use it.
            let spec = orxnud_task::scheduler::new_schedule(
                &id,
                &cron,
                &timezone,
                authorised_by.as_str(),
                limits,
            )
            .map_err(|e| RequestError::InvalidInput {
                reason: "schedule-rejected".to_owned(),
                detail: Some(e.to_string()),
            })?;
            g.2.add_schedule(&spec, now).map_err(schedule_fault)?;
            Ok(json!({
                "schedule": spec.id.as_str(),
                "cron": spec.cron,
                "timezone": spec.timezone,
                "misfire": format!("{:?}", spec.misfire),
                "catch_up_cap": spec.catch_up_cap,
                "enabled": spec.enabled,
                "authorised_by": spec.authorised_by.as_str(),
                "next_wakeup_ms": g.2.next_wakeup_ms(now).ok().flatten(),
            }))
        }
        Method::ScheduleList => {
            let rows = g.2.schedules().map_err(schedule_fault)?;
            Ok(json!({
                "schedules": rows
                    .iter()
                    .map(|r| json!({
                        "id": r.id.as_str(),
                        "cron": r.cron,
                        "timezone": r.timezone,
                        "enabled": r.enabled,
                        "authorised_by": r.authorised_by.as_str(),
                        "last_fired_ms": r.last_fired_ms,
                        "created_at_ms": r.created_at_ms,
                    }))
                    .collect::<Vec<_>>(),
                "next_wakeup_ms": g.2.next_wakeup_ms(now).ok().flatten(),
            }))
        }
        // Unreachable: `route` only sends this function the two methods above. Written as
        // a refusal rather than an `unreachable!` because a future arm added here must fail
        // closed, and a panic in a daemon is not failing closed.
        _ => Err(RequestError::UnknownMethod(method.as_str().to_owned())),
    }
}

/// A scheduler fault as a request error.
///
/// `InvalidInput` rather than `Internal`: an unusable cron expression or an id already
/// taken is the caller's to fix, and reporting it as an internal fault would send an
/// operator to a bug report instead of their own request.
fn schedule_fault(e: crate::task_service::TaskServiceError) -> RequestError {
    use crate::task_service::TaskServiceError;
    match e {
        TaskServiceError::Engine(inner) => RequestError::InvalidInput {
            reason: "schedule-rejected".to_owned(),
            detail: Some(inner.to_string()),
        },
        // A stopped service cannot accept a schedule; the daemon is shutting down.
        TaskServiceError::Stopped => RequestError::Unavailable {
            reason: "shutting-down".to_owned(),
            detail: Some(
                "the daemon is shutting down and is not accepting new schedules".to_owned(),
            ),
        },
    }
}

async fn tasks<S: SecretsContract>(
    method: Method,
    request: &Request,
    authenticated: AuthenticatedPrincipal,
    governed: &tokio::sync::Mutex<(Daemon, S, TaskService)>,
) -> Result<serde_json::Value, RequestError> {
    let delegated_by = authenticated.user();
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
            // Optional and defaulting to one, because a single-step task is the common
            // case and must keep working unchanged. A caller that wants a task to continue
            // across steps says so here; without this, `max_steps` stays at the schema
            // default of 1 and the task completes on its first verified effect, so no task
            // could ever reach the step boundary `task/continue` advances across.
            let max_steps = match params.get("max_steps") {
                None | Some(serde_json::Value::Null) => 1,
                Some(serde_json::Value::Number(n)) => n
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| {
                        RequestError::Invalid(format!(
                            "`max_steps` must be a whole number, not {n}"
                        ))
                    })?,
                Some(_) => {
                    return Err(RequestError::Invalid(
                        "`max_steps` must be a number".to_owned(),
                    ));
                }
            };
            // The store validates this too, but reporting it here keeps the refusal an
            // `INVALID_REQUEST` naming the field rather than an opaque internal error
            // from a repository the caller has no business knowing about.
            orxnud_store::task_repo::validate_max_steps(max_steps)
                .map_err(|e| RequestError::Invalid(format!("`max_steps` is unusable: {e}")))?;
            if max_steps > MAX_MAX_STEPS {
                return Err(RequestError::Invalid(format!(
                    "`max_steps` must be at most {MAX_MAX_STEPS}, not {max_steps}"
                )));
            }
            let mut task = NewTask::new(TaskId::new(id), kind, now);
            task.payload = content;
            task.max_steps = max_steps;
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
            let proposer = delegated_actor(&delegated_by, &task_id, NO_MODEL_PROPOSED);
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
    // Read before the match, because the `Engine` arm binds its own `detail` and would
    // otherwise shadow this one.
    let fault_detail = fault.detail().map(str::to_owned);
    // Every arm below is a *typed* decision. There is no branch that reads `reason` as
    // prose, and no fallback that dumps an unrecognised failure into `INTERNAL_ERROR`
    // merely because its shape was not anticipated here — an unanticipated cause is a real
    // internal fault and is reported as one.
    match fault {
        // A well-formed request naming something that is not there.
        TaskFault::NotFound => RequestError::NotFound {
            reason: reason.to_owned(),
            detail: fault_detail,
        },
        // Taken rather than invented: the name is taken, so the request is a conflict.
        // Likewise a lease the caller does not hold, or held and lost: another worker
        // winning is a normal outcome, and `CONFLICT` is the honest code for it.
        TaskFault::AlreadyExists | TaskFault::Fenced => RequestError::Conflict {
            reason: reason.to_owned(),
            detail: fault_detail,
        },
        // The **specific** refusal is the reason, not the coarse variant name. "not-claimable"
        // says only that a claim was refused; "not-found" says the task is gone, and a client
        // choosing between "refresh my view" and "retry in a moment" needs the second. Both
        // are `CONFLICT`, and `data.reason` is the branchable field.
        //
        // No detail: the reason already *is* the refusal (`ClaimRefusal::as_str`), so a
        // detail would repeat it.
        TaskFault::NotClaimable(r) => RequestError::Conflict {
            reason: r.as_str().to_owned(),
            detail: None,
        },
        // The service is stopping. Nothing is wrong and nothing can be retried until it is
        // not stopping — which is an environment fact, not an internal fault.
        TaskFault::Stopped => RequestError::Unavailable {
            reason: reason.to_owned(),
            detail: fault_detail,
        },
        TaskFault::Engine { cause, detail } => match cause {
            orxnud_task::TaskCause::NotFound => RequestError::NotFound {
                reason: reason.to_owned(),
                detail: Some(detail),
            },
            orxnud_task::TaskCause::AlreadyExists | orxnud_task::TaskCause::Conflict => {
                RequestError::Conflict {
                    reason: reason.to_owned(),
                    detail: Some(detail),
                }
            }
            orxnud_task::TaskCause::Forbidden => RequestError::Forbidden {
                reason: reason.to_owned(),
                detail: Some(detail),
            },
            orxnud_task::TaskCause::Unavailable => RequestError::Unavailable {
                reason: reason.to_owned(),
                detail: Some(detail),
            },
            // A caller-fixable violation of the resource's own rules. Same class as a
            // malformed request, and `INVALID_REQUEST` says "change the request", which is
            // exactly right.
            orxnud_task::TaskCause::InvalidInput => RequestError::Invalid(detail),
            // Durable state that does not add up, or a database that failed. Both are
            // genuine internal faults -- no client action produces a different outcome --
            // but they are different faults, and the reason word now says which. V-89
            // joined them because both landed on one code; that code was right and the
            // reason vocabulary was coarse.
            orxnud_task::TaskCause::Corrupt => RequestError::Internal {
                fault: InternalFault::DurableStateCorrupt,
                detail: fault_detail,
            },
            orxnud_task::TaskCause::Storage => RequestError::Internal {
                fault: InternalFault::StorageUnavailable,
                detail: fault_detail,
            },
        },
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
        // The step bound next to the attempt bound, because a caller that set one wants
        // to see the other: `max_steps` is what decides whether a verified step finishes
        // the task or parks it for continuation.
        "max_steps": row.max_steps,
        "steps_completed": row.steps_completed,
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
    actor: &orxnud_domain::Actor,
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
        Some(value) => Some(approval_from_json(value, actor)?),
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
        actor.clone(),
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
        Err(e) => Err(dispatch_failure(&e)),
    }
}

/// Writes one response frame.
pub(crate) async fn write_response(
    stream: &mut LocalStream,
    response: &Response,
) -> Result<(), IpcError> {
    let bytes = response
        .encode()
        .map_err(|e| IpcError::Other(e.to_string()))?;
    stream.write_line(&bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The effect critical section never suspends, so a request deadline cannot interrupt
    /// a reserved-but-unsettled effect.
    ///
    /// # What this pins
    ///
    /// `serve_one` wraps the whole of `handle_connection` in a `tokio::time::timeout`.
    /// A timeout can only fire when polled, and a future is only polled at an `.await`.
    /// `execute_proposal` therefore has a guarantee that holds only because of its *shape*:
    /// its one `.await` is the `governed.lock()` **before** the effect is reserved, so
    /// spending the approval, reserving the effect, dispatching into the sandbox and
    /// settling the result all run without a suspension point.
    ///
    /// That is what makes "a timeout cannot turn a possibly-completed non-idempotent
    /// effect into a retryable one" structural rather than lucky. Without this check it
    /// would be a comment: adding one `.await` between the reservation and its settlement
    /// would silently reintroduce a window in which a 120-second deadline could cut a
    /// governed dispatch in half.
    ///
    /// # Why a source check and not a runtime test
    ///
    /// A behavioural test cannot observe the absence of a suspension point, and the
    /// property is not about any observable state — it is about where the compiler is
    /// allowed to yield. The same reasoning as the argv-payload source check in this file:
    /// only a check that reads the *code* can fail on the *code*.
    ///
    /// The check is lexical and therefore needs the same care as any text scan: it counts
    /// `.await` occurrences in code positions only, so a mention in a comment — which is
    /// how the lock scope was once documented in this very function — cannot satisfy or
    /// fail it.
    #[test]
    fn the_effect_critical_section_never_suspends() {
        // Read this file rather than using `line!`-style spans, because the property is
        // about a *range* of the source and a span would move with every edit above it.
        let source = include_str!("runtime.rs");
        let lines: Vec<&str> = source.lines().collect();

        // The markers are the statements whose order defines the window. Locating them by
        // text rather than by a fixed line number is what lets this survive the edits above
        // without being updated.
        let reserve = lines
            .iter()
            .position(|l| l.contains(".reserve_effect("))
            .expect("execute_proposal must reserve an effect");
        let settle = lines
            .iter()
            .position(|l| l.contains(".resolve_effect("))
            .expect("execute_proposal must settle an effect");
        assert!(
            settle > reserve,
            "the reservation must precede the settlement; found reserve at {reserve} and              settle at {settle}"
        );

        // `.await` inside the window, in a code position. `split("//")` is not enough on its
        // own, because a string literal may contain `//`; so the check requires the `//` to
        // be preceded only by whitespace, which is what a line comment looks like.
        let offending: Vec<(usize, &str)> = lines
            .iter()
            .enumerate()
            .skip(reserve)
            .take(settle - reserve)
            .filter_map(|(i, l)| {
                let before_comment = l.split("//").next().unwrap_or(l);
                if !before_comment.contains(".await") {
                    return None;
                }
                Some((i + 1, *l))
            })
            .collect();

        assert!(
            offending.is_empty(),
            "an `.await` was added between reserving an effect (line {}) and settling it \
             (line {}): {:?}\n\nA request deadline in `serve_one` fires at an `.await`, so this \
             reintroduces a window in which a governed dispatch can be cut between reserving \
             its effect and settling it -- exactly the window the conservative \
             `needs-verification` path exists for. Move the await outside the window, or \
             restructure so the whole reserve/dispatch/settle sequence cannot yield.",
            reserve + 1,
            settle + 1,
            offending
        );
    }

    /// With no provider configured, a daemon asks the declared stand-in.
    ///
    /// A build with no credentials must still exercise the whole path, and a silent
    /// "no provider configured" would make the boundary indistinguishable from a missing
    /// feature.
    #[test]
    fn the_scripted_provider_is_available_and_identifies_itself() {
        let p = scripted_proposer();
        assert_eq!(p.model_id(), "scripted/none");
    }

    /// The identity boundary itself, exercised over a real socket.
    ///
    /// `authenticate` is one comparison against one kernel-reported integer, so the useful
    /// thing a test can do is show that the comparison is real in both directions and that
    /// its absence is a refusal rather than a pass. A test that only ever ran the matching
    /// case would be satisfied by a function that returned `Ok` unconditionally.
    ///
    /// The stream is a genuine accepted connection, so the principal being compared came
    /// from `SO_PEERCRED` and not from anything these tests could have supplied.
    mod identity_boundary {
        use super::*;
        /// Binds a listener, connects to it, and returns one accepted peer plus the
        /// endpoint's owner uid.
        ///
        /// The client is parked on a sleep so the connection is live for the assertions,
        /// which matters because the credential is read from the socket at accept.
        ///
        /// The owner uid is returned rather than looked up from the *process*, so these
        /// tests need no `cfg` of their own -- gate **G3** keeps `cfg(target_os)` below
        /// the platform crate -- and so what is compared is the exact pair the daemon
        /// compares: the peer's kernel-reported uid against the endpoint's owner.
        async fn a_real_peer(tag: &str) -> (u32, LocalStream) {
            let dir = std::env::temp_dir().join(format!("orxnud-id-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("mkdir");
            let path = dir.join("s.sock");
            let listener = orxnud_platform_ipc::bind(&path).await.expect("bind");
            let owner = orxnud_platform_ipc::endpoint_owner_uid(&path)
                .expect("this platform must report an endpoint owner");
            tokio::spawn(async move {
                let _s = orxnud_platform_ipc::connect(&path).await;
                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            });
            let accepted = listener.accept().await.expect("accept");
            (owner, accepted)
        }

        #[tokio::test]
        async fn the_owner_is_authenticated_and_anyone_else_is_refused() {
            let (uid, stream) = a_real_peer("owner").await;

            assert_eq!(
                authenticate(&stream, InstallationIdentity::Owned(uid)).expect("authenticate"),
                AuthenticatedPrincipal::InstallationOwner,
                "the installation's own user must be authenticated"
            );

            // The same stream, an installation owned by a different user. A test run
            // without privileges cannot become another user, so the comparison itself is
            // what is exercised here -- naming a different owner is what a foreign peer
            // would look like to this function, and a check that could not tell them
            // apart is exactly the check worth pinning.
            let wrong = authenticate(&stream, InstallationIdentity::Owned(uid.wrapping_add(1)))
                .expect_err("a different uid must not be the owner");
            assert!(
                matches!(
                    &wrong,
                    RequestError::Forbidden { reason, .. } if reason == "not-installation-owner"
                ),
                "{wrong:?}"
            );
        }

        #[tokio::test]
        async fn an_unestablishable_identity_refuses_everyone() {
            let (_uid, stream) = a_real_peer("noowner").await;
            // Even a real peer is refused: with no installation there is nothing to
            // compare against, and "nothing to compare against" must not mean "allowed".
            let err = authenticate(&stream, InstallationIdentity::Unavailable)
                .expect_err("an unknown installation must refuse");
            assert!(
                matches!(
                    &err,
                    RequestError::Unavailable { reason, .. }
                        if reason == "peer-identity-unavailable"
                ),
                "{err:?}"
            );
        }

        #[tokio::test]
        async fn the_refusals_name_no_operating_system_detail() {
            let (uid, stream) = a_real_peer("redact").await;
            let rendered = [
                authenticate(&stream, InstallationIdentity::Owned(uid.wrapping_add(1))),
                authenticate(&stream, InstallationIdentity::Unavailable),
            ]
            .into_iter()
            .map(|e| match e {
                Ok(_) => String::new(),
                Err(e) => serde_json::to_string(&e.to_rpc()).expect("serialise"),
            })
            .collect::<Vec<_>>()
            .join(" ");
            assert!(
                !rendered.is_empty(),
                "the join above must contain at least one refusal"
            );
            let leaks: &[&str] = &[&uid.to_string(), "SO_PEERCRED", "getsockopt", "/proc"];
            for leak in leaks {
                assert!(
                    !rendered.contains(leak),
                    "a refusal disclosed {leak:?}: {rendered}"
                );
            }
        }

        #[tokio::test]
        async fn the_principal_carries_no_uid_of_its_own() {
            let (uid, stream) = a_real_peer("nosuid").await;
            let principal =
                authenticate(&stream, InstallationIdentity::Owned(uid)).expect("authenticate");
            // The authenticated principal is a single field with no data in it, so no
            // operating-system identifier can travel above this line.
            assert_eq!(principal, AuthenticatedPrincipal::InstallationOwner);
            let rendered = format!("{principal:?}");
            assert!(
                !rendered.contains(&uid.to_string()),
                "the principal must not carry the uid: {rendered}"
            );
        }
    }

    /// The uncertainty decision table, exhaustively.
    ///
    /// Tested as a table rather than through the daemon because two of its four cells have
    /// **no end-to-end producer today**, and pretending otherwise would mean a test that
    /// passes for the wrong reason. See `the_table_has_an_end_to_end_producer_for_every_row`
    /// below, which fails when that stops being true.
    ///
    /// The exhaustive form matters because the safe direction is not symmetric: a row that
    /// wrongly sends an uncertain task to `Failed` requeues it and duplicates a side
    /// effect, while a row that wrongly sends an *established* task to `NeedsVerification`
    /// merely makes a finished task wait for a person. Only one of those is a correctness
    /// disaster, and this table is what stops the first one being introduced quietly.
    ///
    /// The `Disproved` rows that used to be here were deleted by ADR-0056, not relaxed.
    /// There is no longer a verification outcome that establishes non-execution, so the
    /// cells no longer exist; `Refuted` now lands on the `Unknown` rows below.
    #[test]
    fn the_uncertainty_decision_table_is_exhaustive_and_oriented() {
        use TaskState::{Failed, NeedsVerification};
        let cases = [
            // certainty, idempotent, expected
            (Certainty::Established, false, Failed),
            (Certainty::Established, true, Failed),
            (Certainty::Unknown, true, Failed),
            (Certainty::Unknown, false, NeedsVerification),
        ];
        for (certainty, idempotent, expected) in cases {
            assert_eq!(
                uncertainty_target(certainty, idempotent),
                expected,
                "{certainty:?} + idempotent={idempotent}"
            );
        }

        // The one asymmetry that matters, asserted directly: an unknown outcome on a
        // capability that is not idempotent is the *only* cell that stops the task.
        assert_ne!(
            uncertainty_target(Certainty::Unknown, false),
            uncertainty_target(Certainty::Unknown, true),
            "idempotency must change the recovery for an unknown outcome"
        );
    }

    /// The two mappings a socket test cannot reach, pinned where they are decided.
    ///
    /// Both are correct and both are unreachable over the wire, which is exactly why they
    /// need a test: nothing else in the suite can observe them, so reverting either would
    /// be invisible until the day a call site that reaches them was added.
    ///
    /// * `Stopped` requires a request to arrive while the task subsystem is shutting down.
    ///   Asserting it through a real daemon would mean racing the shutdown signal, which is
    ///   a flaky test rather than a strong one. It matters because the old code reported a
    ///   stopping daemon as `INTERNAL_ERROR`, telling the reader their daemon was broken
    ///   during a restart they had asked for.
    /// * `TaskCause::NotFound` is currently unreachable, measured: the whole workspace suite
    ///   reaches it zero times, because every route that could hand the engine a missing id
    ///   checks existence first and answers `RESOURCE_NOT_FOUND` directly. It is kept because
    ///   the match is exhaustive by design -- there is no fallback arm -- so a future call
    ///   site cannot silently acquire the old behaviour, and this test is what says the
    ///   mapping is intentional rather than leftover.
    #[test]
    fn the_mappings_a_socket_cannot_reach_are_still_pinned() {
        assert_eq!(
            task_fault(TaskFault::Stopped).to_rpc().code,
            RpcErrorCode::ENVIRONMENT_UNAVAILABLE,
            "a stopping daemon is an environment fact, not a fault"
        );
        assert_eq!(
            task_fault(TaskFault::Engine {
                cause: orxnud_task::TaskCause::NotFound,
                detail: "no such task".to_owned(),
            })
            .to_rpc()
            .code,
            RpcErrorCode::RESOURCE_NOT_FOUND,
        );
    }

    /// Every cause the store can produce maps to the class a caller can act on.
    ///
    /// Enumerated rather than sampled, because the mapping is a table and a table is only as
    /// good as its coverage. `Corrupt` and `Storage` are the two that must *stay* faults:
    /// those are the ones where nothing the caller did could change the outcome, which is
    /// the entire meaning of `INTERNAL_ERROR`.
    #[test]
    fn every_cause_maps_to_its_class_and_only_storage_is_internal() {
        let cases = [
            (
                orxnud_task::TaskCause::NotFound,
                RpcErrorCode::RESOURCE_NOT_FOUND,
            ),
            (
                orxnud_task::TaskCause::AlreadyExists,
                RpcErrorCode::CONFLICT,
            ),
            (orxnud_task::TaskCause::Conflict, RpcErrorCode::CONFLICT),
            (orxnud_task::TaskCause::Forbidden, RpcErrorCode::FORBIDDEN),
            (
                orxnud_task::TaskCause::Unavailable,
                RpcErrorCode::ENVIRONMENT_UNAVAILABLE,
            ),
            (
                orxnud_task::TaskCause::InvalidInput,
                RpcErrorCode::INVALID_REQUEST,
            ),
            (
                orxnud_task::TaskCause::Corrupt,
                RpcErrorCode::INTERNAL_ERROR,
            ),
            (
                orxnud_task::TaskCause::Storage,
                RpcErrorCode::INTERNAL_ERROR,
            ),
        ];
        for (cause, expected) in cases {
            assert_eq!(
                task_fault(TaskFault::Engine {
                    cause,
                    detail: "detail".to_owned(),
                })
                .to_rpc()
                .code,
                expected,
                "the cause maps to the wrong class"
            );
        }
    }

    /// Every condition that must stop a read's content becoming an observation.
    ///
    /// Driven directly rather than through a socket, because the conditions are *about the
    /// dispatch outcome* and arranging each one through a real sandboxed read would be a
    /// race rather than a test — the read verifier refutes only when the file changes
    /// between the child's read and its own. So the gate is exercised where it is decided,
    /// over every outcome shape it can be handed.
    ///
    /// This is the test that makes `is_verified()` load-bearing: drop it and nothing else in
    /// the suite notices, because a non-verified read cannot be produced on demand from the
    /// outside.
    mod read_retention_gate {
        use super::*;
        use orxnud_capability::verification::{ExecutionOutcome, VerificationOutcome};
        use orxnud_domain::Actor;
        use orxnud_domain::ids::TaskId;

        const READ: &str = "filesystem/read-text";
        const CONTENT: &str = "SENTINEL-READ-CONTENT-4a91c7e2";

        /// A read outcome with the given verification, by default a successful read whose
        /// content is the sentinel.
        fn read(
            verification: VerificationOutcome,
            ephemeral: bool,
        ) -> orxnud_capability::dispatch::DispatchOutcome {
            orxnud_capability::dispatch::DispatchOutcome {
                execution: ExecutionOutcome::Succeeded {
                    output: Some(CONTENT.to_owned()),
                },
                verification,
                capability: orxnud_domain::CapabilityId::new(READ),
                output_is_ephemeral: ephemeral,
            }
        }

        fn verified() -> VerificationOutcome {
            VerificationOutcome::Verified {
                evidence: "a.txt, 30 bytes, sha256:…".to_owned(),
            }
        }

        /// An `Actor::Ai` proposal row whose provenance names `model`.
        fn ai_proposal(model: &str) -> orxnud_store::task_repo::ProposalRow {
            orxnud_store::task_repo::ProposalRow {
                proposal_id: "p-1".to_owned(),
                task_id: TaskId::new("t1"),
                attempt_no: 1,
                step_no: 1,
                capability: READ.to_owned(),
                target: Some("a.txt".to_owned()),
                params: r#"{"path":"a.txt"}"#.to_owned(),
                proposer_json: serde_json::to_string(&Actor::Ai {
                    delegated_by: orxnud_domain::ids::UserId::new("local"),
                    run: orxnud_domain::ids::RunId::new("t1"),
                    task: TaskId::new("t1"),
                    provenance: orxnud_domain::actor::ModelProvenance::new(
                        model,
                        "ph",
                        orxnud_domain::ids::RequestId::new("r"),
                    ),
                })
                .expect("an actor serialises"),
                authority_root: Some("local".to_owned()),
                created_at_ms: 0,
                status: "approved".to_owned(),
                decided_at_ms: None,
            }
        }

        fn approval() -> orxnud_domain::ApprovalRecord {
            orxnud_domain::ApprovalRecord {
                actor_label: "ai".to_owned(),
                approver: Actor::Human {
                    user: orxnud_domain::ids::UserId::new("local"),
                    via: orxnud_domain::actor::AuthChannel::LocalInteractive,
                },
                capability: READ.to_owned(),
                target: "a.txt".to_owned(),
                params: orxnud_policy::canonical_params(&serde_json::json!({ "path": "a.txt" })),
                issued_at_ms: 0,
                expires_at_ms: 60_000,
                risk: orxnud_domain::enums::RiskClass::High,
                step_no: 1,
                digest: orxnud_domain::approval::ApprovalDigest::from_bytes([1u8; 32]),
            }
        }

        /// Retains `outcome` for `proposal` and reports whether anything was retained.
        fn retains(
            proposal: &orxnud_store::task_repo::ProposalRow,
            outcome: &orxnud_capability::dispatch::DispatchOutcome,
            provider: Option<&Arc<dyn crate::proposer::ProposalProvider>>,
        ) -> bool {
            let store = std::sync::Mutex::new(crate::observation::ObservationStore::new());
            retain_read_observation(
                VerifiedRead {
                    task_id: &TaskId::new("t1"),
                    proposal,
                    approval: &approval(),
                    outcome,
                    step_no: 1,
                    now_ms: 1_000,
                },
                provider,
                &store,
            );
            !store.into_inner().expect("store").is_empty()
        }

        fn scripted() -> Arc<dyn crate::proposer::ProposalProvider> {
            scripted_proposer()
        }

        /// The one combination that must retain.
        #[test]
        fn a_verified_ephemeral_read_by_the_configured_model_is_retained() {
            assert!(
                retains(
                    &ai_proposal("scripted/none"),
                    &read(verified(), true),
                    Some(&scripted())
                ),
                "the positive case must retain, or the whole path is dead"
            );
        }

        /// `refuted`: the verifier says the bytes are not what is on disk.
        #[test]
        fn a_refuted_read_is_not_retained() {
            assert!(!retains(
                &ai_proposal("scripted/none"),
                &read(
                    VerificationOutcome::Refuted {
                        evidence: "does not match what is on disk".to_owned(),
                    },
                    true,
                ),
                Some(&scripted()),
            ));
        }

        /// `undetermined`: nothing is known either way, which is emphatically not a licence.
        #[test]
        fn an_undetermined_read_is_not_retained() {
            assert!(!retains(
                &ai_proposal("scripted/none"),
                &read(
                    VerificationOutcome::Undetermined {
                        reason: "the independent read failed".to_owned(),
                    },
                    true,
                ),
                Some(&scripted()),
            ));
        }

        /// A capability whose output is durable is not a read at all, however well verified.
        #[test]
        fn a_durable_output_is_never_retained() {
            assert!(
                !retains(
                    &ai_proposal("scripted/none"),
                    &read(verified(), false),
                    Some(&scripted())
                ),
                "a durable output would be a second copy of the content"
            );
        }

        /// A proposal made by anything other than the model.
        #[test]
        fn a_non_ai_proposer_is_not_retained() {
            let mut p = ai_proposal("scripted/none");
            p.proposer_json = serde_json::to_string(&Actor::Human {
                user: orxnud_domain::ids::UserId::new("local"),
                via: orxnud_domain::actor::AuthChannel::LocalInteractive,
            })
            .expect("an actor serialises");
            assert!(!retains(&p, &read(verified(), true), Some(&scripted())));
        }

        /// The read names a model this daemon is no longer configured to ask.
        #[test]
        fn a_read_from_another_model_is_not_retained() {
            assert!(
                !retains(
                    &ai_proposal("some/other-model"),
                    &read(verified(), true),
                    Some(&scripted())
                ),
                "a re-pointed or re-configured provider must not inherit the read"
            );
        }

        /// No provider, so no identity, so nothing to authorise.
        #[test]
        fn no_provider_means_no_observation() {
            assert!(!retains(
                &ai_proposal("scripted/none"),
                &read(verified(), true),
                None
            ));
        }

        /// A target that is not a workspace-relative path.
        #[test]
        fn an_absolute_or_traversing_target_is_not_retained() {
            for target in ["/etc/passwd", "../escape.txt", "sub/../../out.txt", ""] {
                let mut p = ai_proposal("scripted/none");
                p.target = Some(target.to_owned());
                assert!(
                    !retains(&p, &read(verified(), true), Some(&scripted())),
                    "{target:?} was retained"
                );
            }
        }

        /// A failed execution, whatever the verification says about it.
        #[test]
        fn a_failed_execution_is_not_retained() {
            let mut outcome = read(verified(), true);
            outcome.execution = ExecutionOutcome::Failed {
                detail: "no such file".to_owned(),
            };
            assert!(!retains(
                &ai_proposal("scripted/none"),
                &outcome,
                Some(&scripted())
            ));
        }
    }

    /// The menu a model is shown is the registry, walked — not a list written next to the
    /// proposer. Asserted against the real registry so a capability that is registered
    /// and enabled appears without an edit here.
    #[test]
    fn the_proposal_menu_is_derived_from_the_registry() {
        let mut registry = orxnud_capability::CapabilityRegistry::empty();
        registry
            .register(orxnud_capability::write_text::declaration())
            .expect("write-text registers");
        registry
            .register(orxnud_capability::text::declaration())
            .expect("word-count registers");

        let menu: Vec<&str> = registry
            .enabled()
            .into_iter()
            .map(|d| {
                // The same projection `ai_propose` performs.
                let _ = d.params().schema.field_names();
                d.id.to_string()
            })
            .map(|id| Box::leak(id.into_boxed_str()) as &str)
            .collect();

        assert!(
            menu.contains(&"filesystem/write-text"),
            "an enabled capability must be proposable with no edit to the proposer: {menu:?}"
        );
        assert!(menu.contains(&"text/word-count"));
    }

    /// Every enabled declaration carries a usable shape, and one that needs a target says
    /// so. A capability that forgot to declare would otherwise be proposable with an
    /// empty shape and silently accept nothing.
    #[test]
    fn every_enabled_capability_declares_its_parameters() {
        let mut registry = orxnud_capability::CapabilityRegistry::empty();
        registry
            .register(orxnud_capability::write_text::declaration())
            .expect("write-text registers");
        registry
            .register(orxnud_capability::text::declaration())
            .expect("word-count registers");

        for declaration in registry.enabled() {
            let id = &declaration.id.to_string();
            assert!(
                !declaration.params().schema.fields().is_empty(),
                "{id} is enabled but declares no parameters"
            );
            assert!(
                !declaration.params().description.is_empty(),
                "{id} is enabled but has no parameter description to show a model"
            );
        }
    }

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
                let _release = crate::serve::EndpointRelease::new(
                    Arc::clone(&listener),
                    Some(endpoint.clone()),
                );
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
                let _release = crate::serve::EndpointRelease::new(
                    Arc::clone(&listener),
                    Some(endpoint.clone()),
                );
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
            let _release = crate::serve::EndpointRelease::new(
                Arc::new(orxnud_platform_ipc::Listener::Unsupported),
                None,
            );
        });
    }
}

/// The durable-vs-ephemeral boundary for execution output.
///
/// `task_step_results.structured_output` is a durable column. A read's output is the file's
/// contents, so persisting it would copy workspace data into the database. These tests use a
/// sentinel that would be unmistakable in the database, and assert on the *decision* rather
/// than by running a whole governed dispatch through a real sandbox.
#[cfg(test)]
mod durable_output_tests {
    use super::durable_output;
    use orxnud_capability::dispatch::DispatchOutcome;
    use orxnud_capability::verification::{ExecutionOutcome, VerificationOutcome};
    use orxnud_domain::ids::CapabilityId;

    /// Unmistakable if it ever reaches a durable row or a log.
    const SENTINEL: &str = "SENTINEL-READ-CONTENT-MUST-NOT-PERSIST-9d1e77";

    fn outcome(capability: &str, output: &str, ephemeral: bool) -> DispatchOutcome {
        DispatchOutcome {
            execution: ExecutionOutcome::Succeeded {
                output: Some(output.to_owned()),
            },
            verification: VerificationOutcome::Verified {
                evidence: "a.txt holds the 1 bytes the execution reported".to_owned(),
            },
            capability: CapabilityId::new(capability),
            output_is_ephemeral: ephemeral,
        }
    }

    /// The load-bearing assertion: a read's bytes never reach `structured_output`.
    #[test]
    fn an_ephemeral_output_is_never_persisted() {
        let o = outcome(orxnud_capability::read_text::READ_TEXT_ID, SENTINEL, true);
        let persisted = durable_output(&o);
        assert!(
            persisted.is_none(),
            "file content would be written to a durable row: {persisted:?}"
        );
    }

    /// Behaviour-neutral for everything else: a capability that does not declare its output
    /// ephemeral keeps exactly the behaviour it had, output included.
    #[test]
    fn a_durable_output_is_still_persisted() {
        let o = outcome(
            orxnud_capability::write_text::WRITE_TEXT_ID,
            "written",
            false,
        );
        assert_eq!(durable_output(&o).as_deref(), Some("written"));
    }

    #[test]
    fn a_failed_execution_persists_nothing_regardless() {
        let mut o = outcome(orxnud_capability::write_text::WRITE_TEXT_ID, "x", false);
        o.execution = ExecutionOutcome::Failed {
            detail: "boom".into(),
        };
        assert!(durable_output(&o).is_none());
    }

    /// The sentinel must not appear anywhere in what the durable path would receive.
    #[test]
    fn no_content_reaches_the_durable_step_result() {
        for capability in [
            orxnud_capability::read_text::READ_TEXT_ID,
            orxnud_capability::write_text::WRITE_TEXT_ID,
        ] {
            let o = outcome(capability, SENTINEL, true);
            let row = orxnud_store::task_repo::StepResultRow {
                task_id: orxnud_domain::ids::TaskId::new("t"),
                step_no: 1,
                status: orxnud_store::task_repo::StepStatus::Verified,
                verification: Some(match &o.verification {
                    VerificationOutcome::Verified { evidence } => evidence.clone(),
                    _ => String::new(),
                }),
                structured_output: durable_output(&o),
                artifacts: None,
                recorded_at_ms: 0,
            };
            let rendered = format!("{row:?}");
            assert!(
                !rendered.contains(SENTINEL),
                "{capability}: content leaked into the durable row: {rendered}"
            );
        }
    }
}

/// V-97: the effect verdict a `dispatch()` failure establishes.
///
/// The classification is the whole fix, so it is asserted exhaustively here rather than
/// only through the paths a daemon test can provoke. Every shipped capability either
/// works or is absent from the bundle map, and a Tier-1 capability is refused for want of
/// a sandbox only on some hosts — so a daemon-level test could cover a *subset* of these
/// arms and pass while the dangerous one (`Audit`, which is raised *after* the capability
/// has run) was misclassified. The function is pure, so it can be asked directly.
#[cfg(test)]
mod effect_status_for_dispatch_failure_tests {
    use super::effect_status_for_dispatch_failure;
    use orxnud_capability::dispatch::{
        DisabledReason, DispatchError, ExecutionCertainty, SandboxRefusal,
    };
    use orxnud_domain::ids::CapabilityId;
    use orxnud_store::task_repo::EffectStatus;

    fn cap() -> CapabilityId {
        CapabilityId::new("filesystem/write-text")
    }

    fn refusal() -> SandboxRefusal {
        SandboxRefusal::nothing_attempted(
            cap(),
            "no execution backend is configured",
            vec!["a sandbox execution backend"],
        )
    }

    /// Requirement: a dispatch that definitively fails *before* execution is recorded as
    /// `not-performed`, which is the one verdict that says a repeat cannot duplicate
    /// anything — and therefore the one that restores a legitimate retry.
    /// **F-17 / ADR-0056 regression.** The daemon half of the pair whose other half is
    /// `a_write_that_occurred_and_was_later_overwritten_is_refuted_and_survives_admission`
    /// in `orxnud-capability`.
    ///
    /// Drives the real production chain in the real order — `admit_verification`,
    /// `certainty_of`, the effect-status mapping, a real migrated database,
    /// `resolve_effect`, a process restart, `recover()`, `claim_specific` — and asserts the
    /// property end to end: a `write-text` that succeeded and whose file a later actor
    /// changed is **not** handed back to a worker.
    ///
    /// Nothing here is mocked. `WriteTextVerifier` cannot be named from this crate
    /// (`AdapterBundle` is `pub(crate)`), so the seam is the public `VerificationOutcome`
    /// enum; the capability-side test pins that the real verifier produces exactly this
    /// value for exactly this filesystem state, so the two together cover the chain without
    /// a gap in it.
    ///
    /// **F-17 remains probable exposure.** The competing write is staged, not raced, and no
    /// end-to-end live-daemon run has been performed. What is proven here is the mapping and
    /// the consequence, not the reachability of the timing window.
    #[test]
    fn a_refuted_write_text_does_not_authorise_a_retry_after_a_possible_execution() {
        use super::{Certainty, certainty_of, effect_status_for_certainty};
        use orxnud_capability::dispatch::admit_verification;
        use orxnud_capability::verification::{ExecutionOutcome, VerificationOutcome};
        use orxnud_domain::task_state::TaskKind;
        use orxnud_store::migration::MigrationRunner;
        use orxnud_store::pragma::Pragma;
        use orxnud_store::task_repo::{NewTask, TargetedClaimOutcome, TaskRepository};

        const NOW: i64 = 1_767_225_600_000;
        const LEASE: i64 = 60_000;

        // What the real `WriteTextVerifier` returns for a succeeded write whose file was
        // later changed: the postcondition does not hold, and it says so truthfully.
        let execution = ExecutionOutcome::Succeeded {
            output: Some(String::new()),
        };
        let reported = VerificationOutcome::Refuted {
            evidence: "…/f.txt exists but holds 24 bytes, not the 6 requested".to_owned(),
        };

        // Step 1 -- the real admission table. It must let a true observation through.
        let admitted = admit_verification(&execution, reported);
        assert!(
            matches!(admitted, VerificationOutcome::Refuted { .. }),
            "admission must not suppress a true postcondition observation; got {admitted:?}"
        );

        // Step 2 -- the real consumer. THIS is what ADR-0056 changed: a refuted
        // postcondition is uncertainty, never a disproof.
        assert_eq!(
            certainty_of(&admitted),
            Certainty::Unknown,
            "a refuted postcondition is evidence about a postcondition, not about whether the \
             effect occurred"
        );

        // Step 3 -- the real effect-ledger mapping, which is where the retry permission was
        // issued before.
        let status = effect_status_for_certainty(certainty_of(&admitted));
        assert_ne!(
            status,
            EffectStatus::NotPerformed,
            "`not-performed` is the one status `recover()` excludes, so writing it here is \
             the defect itself, not a description of it"
        );

        // Steps 4-7 -- the real durable chain.
        // Nonce-keyed rather than PID-keyed. A PID alone is not unique across runs on a
        // busy host, and two runs of this suite sharing a scratch directory produce
        // `AlreadyExists` on the second one -- a failure that has nothing to do with what
        // the test is asserting. Observed exactly that once while mutation-testing.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("f17-chain-{}-{nonce}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let db = dir.join("state.db");
        let tid = orxnud_domain::ids::TaskId::new("f17-task");
        let key = orxnud_task::DurableEngine::idempotency_key(&tid, "filesystem/write-text", "1/1");
        {
            let mut c = rusqlite::Connection::open(&db).expect("open");
            Pragma::critical().apply(&c).expect("pragmas");
            MigrationRunner::new(&c).migrate(&db).expect("migrate");
            let mut repo = TaskRepository::new(&mut c);
            repo.insert(&NewTask::new(tid.clone(), TaskKind::Query, NOW), NOW)
                .expect("insert");
            assert!(matches!(
                repo.claim_specific(&tid, "w1", NOW, LEASE),
                Ok(TargetedClaimOutcome::Claimed(_))
            ));
            // Non-idempotent, which is the only case where repeating the effect can do harm.
            repo.reserve_effect(&key, &tid, 1, 1, "filesystem/write-text", false, NOW)
                .expect("reserve")
                .expect("inserted");
            assert!(
                repo.resolve_effect(&key, status, None, NOW + 1)
                    .expect("resolve")
            );
        }
        {
            // A restart -- the only thing that calls recover() in production.
            let mut c = rusqlite::Connection::open(&db).expect("reopen");
            Pragma::critical().apply(&c).expect("pragmas");
            let mut repo = TaskRepository::new(&mut c);
            repo.recover(NOW + LEASE + 1).expect("recover");

            // THE PROPERTY: no second worker may repeat the effect.
            assert!(
                !matches!(
                    repo.claim_specific(&tid, "w2", NOW + LEASE + 2, LEASE),
                    Ok(TargetedClaimOutcome::Claimed(_))
                ),
                "the effect is non-idempotent and unresolved, so a repeat could duplicate an \
                 effect that already happened; recovery must not issue the retry permission"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The control for the regression above, and it is the one that keeps the fix honest.
    ///
    /// A pre-execution refusal still records `not-performed`, and that path must keep its
    /// retry permission. If it did not, the fix would be over-broad: every genuinely safe
    /// repeat would have become an adjudication, which is a real cost and not a safety win.
    /// Asserted here so that the two properties are pinned together and cannot be traded.
    #[test]
    fn a_refusal_before_execution_still_earns_its_retry_permission() {
        use orxnud_capability::dispatch::{ExecutionCertainty, SandboxRefusal};
        let refusal = SandboxRefusal::nothing_attempted(
            cap(),
            "the workspace was not writable",
            vec!["a writable workspace"],
        );
        assert_eq!(
            refusal.certainty,
            ExecutionCertainty::NothingAttempted,
            "a refusal decided before a process exists carries the warrant"
        );
        assert_eq!(
            effect_status_for_dispatch_failure(&DispatchError::SandboxRefused(refusal)),
            EffectStatus::NotPerformed,
            "positive evidence of non-execution keeps its retry permission; ADR-0056 \
             withdraws warrants from postcondition evidence, never from pre-execution ones"
        );
    }

    #[test]
    fn a_refusal_before_execution_is_recorded_as_not_performed() {
        let cases: Vec<(&str, DispatchError)> = vec![
            (
                "policy",
                DispatchError::Policy(orxnud_policy::PolicyError::Denied {
                    reason: orxnud_policy::DenialReason::UnknownCapability {
                        capability: cap().to_string(),
                    },
                }),
            ),
            ("sandbox refused", DispatchError::SandboxRefused(refusal())),
            ("no implementation", DispatchError::NoImplementation(cap())),
            (
                "disabled",
                DispatchError::Disabled {
                    id: cap(),
                    reason: DisabledReason::Configured,
                },
            ),
            (
                "class escalation",
                DispatchError::ClassEscalation {
                    id: cap(),
                    declared: orxnud_domain::enums::DataClass::Public,
                    actual: orxnud_domain::enums::DataClass::Regulated,
                },
            ),
            (
                "reentrant",
                DispatchError::Reentrant("called back in".to_owned()),
            ),
        ];
        for (label, e) in cases {
            assert_eq!(
                effect_status_for_dispatch_failure(&e),
                EffectStatus::NotPerformed,
                "{label}: stages 1-7 cannot have run the capability, so this must be a \
                 disproof. Recording it as anything else wedges the task forever."
            );
        }
    }

    /// ADR-0056 Decision 4: a refuted *verification* is NOT a disproof.
    ///
    /// This assertion used to read `NotPerformed`, and its justification was that reading it
    /// any other way "would make a *proven* non-effect indistinguishable from an uncertain
    /// one". That justification was the defect. The finding is not proven non-execution: it
    /// is a verdict about a postcondition, and the capability demonstrably ran before it was
    /// produced. `not-performed` is a retry permission, so this arm was authorising an
    /// automatic repeat of a possibly-performed non-idempotent effect.
    ///
    /// The evidence string is left saying "proved" on purpose — it is what a verifier can
    /// honestly write, and the point is that the ledger must not take the word for it.
    #[test]
    fn a_refuted_verification_is_recorded_as_unknown_not_as_not_performed() {
        let e = DispatchError::VerificationRefuted {
            evidence: "the verifier proved the file was not written".to_owned(),
        };
        assert_eq!(
            effect_status_for_dispatch_failure(&e),
            EffectStatus::Unknown,
            "a refuted postcondition is not evidence that the effect did not occur; \
             `not-performed` here would hand a possibly-performed non-idempotent effect \
             straight back to a worker"
        );
    }

    /// Requirement: an ambiguous outcome must NOT be recorded as a disproof.
    ///
    /// `Audit` is the one that matters and it is the reason this function exists. It is
    /// raised in stage 9 — after the capability ran and was verified — and it discards the
    /// verdict on its way out, so at this call site the only honest answer is "we know
    /// something ran and we cannot say what". `Unknown` is what keeps recovery holding the
    /// task.
    #[test]
    fn a_post_execution_failure_is_recorded_as_unknown() {
        let cases: Vec<(&str, DispatchError)> = vec![
            (
                "audit journal unavailable",
                DispatchError::Audit("the journal could not be written".to_owned()),
            ),
            (
                "execution failed",
                DispatchError::Execution("exit 1".to_owned()),
            ),
            (
                "verification failed",
                DispatchError::Verification(orxnud_capability::verification::VerifyError(
                    "the verifier could not run".to_owned(),
                )),
            ),
        ];
        for (label, e) in cases {
            assert_eq!(
                effect_status_for_dispatch_failure(&e),
                EffectStatus::Unknown,
                "{label}: this is raised after the capability ran, so recording it as \
                 `not-performed` would be a fabricated disproof and would permit exactly \
                 the repeat this ledger exists to prevent."
            );
        }
    }

    /// The two classes must not be the same value, or the test above proves nothing.
    #[test]
    fn the_two_classes_are_distinguishable() {
        assert_ne!(
            EffectStatus::NotPerformed,
            EffectStatus::Unknown,
            "if these compared equal the classification would be untestable"
        );
    }

    /// A refusal that carries `NothingAttempted` is a disproof in **both** channels.
    ///
    /// The refusal is decided before a process exists, so "nothing ran" is a fact rather
    /// than an absence of information, and both records may say so. Asserted across both
    /// channels because a one-sided assertion would pass while the other drifted.
    #[test]
    fn a_definite_pre_execution_refusal_is_not_performed_and_denied() {
        let e = DispatchError::SandboxRefused(refusal());
        assert_eq!(
            effect_status_for_dispatch_failure(&e),
            EffectStatus::NotPerformed,
            "a refusal decided before any process exists is a disproof"
        );
        let (kind, _) = orxnud_capability::dispatch::terminal_outcome_for_failure(&e);
        assert_eq!(
            kind,
            orxnud_audit::OutcomeKind::Denied,
            "the journal must agree: `Denied` is the disposition that asserts no execution"
        );
    }

    /// A refusal that carries `Unknown` is `Unknown` in the effect ledger and `Uncertain`
    /// in the journal.
    ///
    /// **This is the defect, pinned.** A generic backend panic reaches this shape: `execute`
    /// is called inside a `catch_unwind`, and a panic there says nothing about whether the
    /// child was spawned. The arm used to discard `certainty` and answer `NotPerformed`,
    /// which is the one status `recover()` treats as "a repeat cannot duplicate anything" —
    /// so a non-idempotent capability whose side effect may have happened became claimable
    /// and re-dispatchable, while the journal said `Uncertain` and was right.
    #[test]
    fn an_unknown_execution_is_unknown_in_the_ledger_and_uncertain_in_the_journal() {
        let e = DispatchError::SandboxRefused(SandboxRefusal {
            capability: cap(),
            reason: "the execution backend panicked".to_owned(),
            missing: vec!["a functioning execution backend"],
            certainty: ExecutionCertainty::Unknown,
        });
        assert_eq!(
            effect_status_for_dispatch_failure(&e),
            EffectStatus::Unknown,
            "nothing established that the child was never spawned, so `not-performed` \
             would be a fabricated disproof"
        );
        let (kind, _) = orxnud_capability::dispatch::terminal_outcome_for_failure(&e);
        assert_eq!(
            kind,
            orxnud_audit::OutcomeKind::Uncertain,
            "the journal must decline to claim an outcome"
        );
    }

    /// The same certainty, reached the way production reaches it, all the way to recovery.
    ///
    /// # What this adds to the test above
    ///
    /// The test above hand-builds the `SandboxRefusal`, so it proves the *mapping* and
    /// nothing about whether any producer ever emits that shape. Every K.1 in this area has
    /// been a producer disagreeing with a consumer while both were internally consistent and
    /// every hand-built test passed — the backend panic, and then the runner that gives up
    /// on containment after the capability has already started. Both were caught by
    /// production code emitting a value the consumers had no way to question.
    ///
    /// So the error here is the one the real `SandboxExecutionBackend` builds, obtained by
    /// asking it to execute against a runner that reports the post-spawn give-up, and the
    /// status it produces is then written through the real `TaskRepository` and read back by
    /// the real `recover()`. The chain under test is therefore:
    ///
    /// ```text
    /// sandbox reports a give-up after a start
    ///     -> SandboxRefusal with Unknown certainty      (orxnud-capability)
    ///     -> EffectStatus::Unknown                      (this module)
    ///     -> task_effects.status = 'unknown'            (orxnud-store)
    ///     -> recover(): needs-verification, terminal    (orxnud-store)
    /// ```
    ///
    /// and the claim is about the *end* of it: after a restart, a worker cannot claim this
    /// task and cannot re-dispatch the effect. `NotPerformed` would have made it claimable,
    /// and `not-performed` is the one status recovery reads as "a repeat cannot duplicate
    /// anything".
    #[test]
    fn a_give_up_after_a_start_survives_to_recovery_as_an_uncertain_effect() {
        use orxnud_capability::dispatch::ExecutionBackend;
        use orxnud_domain::TaskId;
        use orxnud_domain::task_state::{TaskKind, TaskState};
        use orxnud_platform_sandbox::contract::{
            AvailableGuarantees, CapturedStream, ExecutionResult, ExecutionStatus, SandboxRunner,
            SandboxSpec, SandboxUnavailable,
        };
        use orxnud_store::migration::MigrationRunner;
        use orxnud_store::pragma::Pragma;
        use orxnud_store::task_repo::{NewTask, TargetedClaimOutcome, TaskRepository};
        use std::sync::Arc;

        const NOW: i64 = 1_767_225_600_000;
        const LEASE: i64 = 60_000;

        /// A runner that gives up after starting, which is what
        /// `BwrapRunner::run`'s membership check does.
        struct GivesUp;
        impl SandboxRunner for GivesUp {
            fn run(&self, _spec: &SandboxSpec) -> Result<ExecutionResult, SandboxUnavailable> {
                Ok(ExecutionResult {
                    status: ExecutionStatus::Abandoned(SandboxUnavailable::GuaranteeUnavailable {
                        guarantee: "OS-enforced resource ceilings",
                        detail: "the supervisor did not join the dedicated cgroup".to_owned(),
                    }),
                    stdout: CapturedStream::empty(),
                    stderr: CapturedStream::empty(),
                    elapsed: std::time::Duration::ZERO,
                    unproven: Vec::new(),
                })
            }
            fn cancel(&self) -> Result<(), SandboxUnavailable> {
                Ok(())
            }
            fn available_guarantees(&self) -> AvailableGuarantees {
                AvailableGuarantees {
                    visibility: true,
                    tree_lifetime: true,
                    resources: true,
                }
            }
        }

        // --- the error, from the producer rather than from a literal -----------------
        let err =
            orxnud_capability::subprocess::SandboxExecutionBackend::with_runner(Arc::new(GivesUp))
                .execute(&orxnud_capability::dispatch::ExecutionContract {
                    stdin_payload: None,
                    capability: cap(),
                    program: "/bin/true".to_owned(),
                    args: Vec::new(),
                    env: Default::default(),
                    working_dir: "/".to_owned(),
                    grant_rw: Vec::new(),
                    grant_ro: Vec::new(),
                    network: false,
                    deadline_ms: 1_000,
                    output_cap_bytes: 1_024,
                    resources: orxnud_capability::dispatch::ResourcePolicy::default(),
                })
                .expect_err("a give-up after a start is a refusal-shaped error");
        let err = DispatchError::SandboxRefused(err);

        // --- both channels agree, and the effect channel withholds the retry ---------
        let status = effect_status_for_dispatch_failure(&err);
        assert_eq!(
            status,
            EffectStatus::Unknown,
            "the effect ledger must not call an execution that started a disproof"
        );
        assert_eq!(
            orxnud_capability::dispatch::terminal_outcome_for_failure(&err).0,
            orxnud_audit::OutcomeKind::Uncertain,
            "and the journal must not call it a denial either"
        );

        // --- the status, written and read back through the real repository -----------
        let dir = std::env::temp_dir().join(format!("k1-abandon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let db = dir.join("state.db");
        let key = orxnud_task::DurableEngine::idempotency_key(
            &TaskId::new("k1-task"),
            "filesystem/write-text",
            "1/1",
        );
        {
            let mut c = rusqlite::Connection::open(&db).expect("open");
            Pragma::critical().apply(&c).expect("pragmas");
            MigrationRunner::new(&c).migrate(&db).expect("migrate");
            let mut repo = TaskRepository::new(&mut c);
            repo.insert(
                &NewTask::new(TaskId::new("k1-task"), TaskKind::Query, NOW),
                NOW,
            )
            .expect("insert");
            assert!(
                matches!(
                    repo.claim_specific(&TaskId::new("k1-task"), "w1", NOW, LEASE),
                    Ok(TargetedClaimOutcome::Claimed(_))
                ),
                "a fresh task must be claimable"
            );
            // What `execute_proposal` does, in the order it does it.
            assert!(
                repo.reserve_effect(
                    &key,
                    &TaskId::new("k1-task"),
                    1,
                    1,
                    "filesystem/write-text",
                    // The capability declares itself non-idempotent, which is the whole
                    // reason this case is interesting.
                    false,
                    NOW,
                )
                .expect("reserve")
                .is_some(),
                "the effect must be reserved before it is dispatched"
            );
            assert!(
                repo.resolve_effect(&key, status, Some(&err.to_string()), NOW + 1)
                    .expect("resolve"),
                "the dispatch's verdict must be recorded"
            );
        }

        // --- the restart, and what recovery decides ----------------------------------
        {
            let mut c = rusqlite::Connection::open(&db).expect("reopen");
            Pragma::critical().apply(&c).expect("pragmas");
            let mut repo = TaskRepository::new(&mut c);
            assert_eq!(repo.recover(NOW + LEASE + 1).expect("recover"), 1);
            let row = repo
                .get(&TaskId::new("k1-task"))
                .expect("read")
                .expect("present");
            assert_eq!(
                row.state,
                TaskState::NeedsVerification,
                "an effect that may have happened on a non-idempotent capability must park \
                 the task for a human. `pending` here is the retry this whole chain exists \
                 to withhold."
            );
            assert!(
                !matches!(
                    repo.claim_specific(&TaskId::new("k1-task"), "w2", NOW + LEASE + 2, LEASE),
                    Ok(TargetedClaimOutcome::Claimed(_))
                ),
                "and a second worker must not be able to pick it up"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **Test E, and the end of the chain.** A refuted claim from a capability that did
    /// not report success cannot become a disproof, and cannot survive every layer that
    /// could turn one back into one.
    ///
    /// # The shape under test
    ///
    /// A `DispatchOutcome` whose execution is post-start and whose verification is
    /// `Refuted`. Before the capability layer's admission rule, that was reachable: a
    /// verifier written as "the target must not hold the old bytes" answers *absent*
    /// whenever it cannot confirm the write, and the daemon read that as
    /// a disproof. The whole downstream chain is then exercised here, in the
    /// production order and through the production functions, against real durable state:
    ///
    /// ```text
    /// certainty_of(verification)  ->  EffectStatus
    ///   -> resolve_effect          (real write, real file database)
    ///   -> reopen                  (a process restart, which is the only thing that
    ///                              ever calls recover() in production)
    ///   -> recover()               (the uncertainty predicate)
    ///   -> claim_specific          (may a second worker repeat the effect?)
    /// ```
    ///
    /// The expected verdict is `Undetermined` rather than `Refuted` because the admission
    /// rule already refused the claim, and this asserts it stays refused. So the two
    /// halves are the property and its proof that the property is not an accident of the
    /// particular verdict: a `Refuted` that *did* survive admission would have to be
    /// turned into `NotPerformed` by something downstream, and nothing downstream has a
    /// channel to do that.
    #[test]
    fn a_refuted_claim_from_a_silent_capability_can_never_become_a_disproof() {
        use super::{Certainty, certainty_of, effect_status_for_certainty};
        use orxnud_capability::dispatch::admit_verification;
        use orxnud_capability::verification::{
            ExecutionOutcome, VerificationOutcome, Verifier as _,
        };
        use orxnud_domain::task_state::{TaskKind, TaskState};
        use orxnud_store::migration::MigrationRunner;
        use orxnud_store::pragma::Pragma;
        use orxnud_store::task_repo::{NewTask, TaskRepository};

        const NOW: i64 = 1_767_225_600_000;
        const LEASE: i64 = 60_000;

        /// The M5 shape: a verifier that refutes whatever the execution did.
        struct RefutesRegardless;
        impl orxnud_capability::verification::Verifier for RefutesRegardless {
            fn verify(
                &self,
                _execution: &ExecutionOutcome,
                _params: &serde_json::Value,
                _at_ms: i64,
            ) -> Result<VerificationOutcome, orxnud_capability::verification::VerifyError>
            {
                Ok(VerificationOutcome::Refuted {
                    evidence: "the target does not hold the requested bytes".to_owned(),
                })
            }
        }

        // The verifier's raw answer, the admission rule's answer, and the effect status
        // each would produce -- for every post-start execution state.
        for (name, execution) in [
            (
                "failed",
                ExecutionOutcome::Failed {
                    detail: "exit 1".to_owned(),
                },
            ),
            (
                "silent",
                ExecutionOutcome::Unknown {
                    detail: "stopped at its deadline".to_owned(),
                },
            ),
        ] {
            let reported = RefutesRegardless
                .verify(&execution, &serde_json::json!({}), NOW)
                .expect("a verifier that always answers");
            assert!(
                reported.is_refuted(),
                "{name}: the fixture must produce the inadmissible finding under test"
            );

            let admitted = admit_verification(&execution, reported.clone());
            assert!(
                !admitted.is_refuted() && !admitted.is_verified(),
                "{name}: the admission rule must refuse a claim made against an execution \
                 that did not report success; got {admitted:?}"
            );
            assert_eq!(
                certainty_of(&admitted),
                Certainty::Unknown,
                "{name}: an admission-refused finding must land on uncertainty, never on a \
                 verdict that would authorise a repeat"
            );

            // The second line of defence, added by ADR-0056. Checked on the *unadmitted*
            // finding, so it holds even if the admission rule were removed: a refuted
            // postcondition is not proof of non-execution regardless of what admitted it.
            // Before ADR-0056 this assertion read `Disproved` -- it asserted that without
            // the admission rule the answer *would* have been a disproof, which was the
            // argument that the admission rule was the only thing standing in the way.
            // That is no longer true and no longer the desired property.
            assert_eq!(
                certainty_of(&reported),
                Certainty::Unknown,
                "{name}: even bypassing admission, a refuted postcondition must not become a \
                 disproof. `certainty_of` no longer has a disproof to give (ADR-0056)."
            );

            // Now the full durable chain with the admitted (conservative) verdict.
            let dir = std::env::temp_dir().join(format!("k1-claim-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch");
            let db = dir.join("state.db");
            let tid = orxnud_domain::ids::TaskId::new("claim-task");
            let key =
                orxnud_task::DurableEngine::idempotency_key(&tid, "filesystem/write-text", "1/1");
            let status = effect_status_for_certainty(certainty_of(&admitted));
            {
                let mut c = rusqlite::Connection::open(&db).expect("open");
                Pragma::critical().apply(&c).expect("pragmas");
                MigrationRunner::new(&c).migrate(&db).expect("migrate");
                let mut repo = TaskRepository::new(&mut c);
                repo.insert(&NewTask::new(tid.clone(), TaskKind::Query, NOW), NOW)
                    .expect("insert");
                assert!(matches!(
                    repo.claim_specific(&tid, "w1", NOW, LEASE),
                    Ok(orxnud_store::task_repo::TargetedClaimOutcome::Claimed(_))
                ));
                // Non-idempotent, because that is the only case where repeating the
                // effect can do harm.
                repo.reserve_effect(&key, &tid, 1, 1, "filesystem/write-text", false, NOW)
                    .expect("reserve")
                    .expect("inserted");
                assert!(
                    repo.resolve_effect(&key, status, None, NOW + 1)
                        .expect("resolve")
                );
            }
            {
                // A restart, which is the only thing that calls recover() in production.
                let mut c = rusqlite::Connection::open(&db).expect("reopen");
                Pragma::critical().apply(&c).expect("pragmas");
                let mut repo = TaskRepository::new(&mut c);
                assert_eq!(repo.recover(NOW + LEASE + 1).expect("recover"), 1);
                let row = repo.get(&tid).expect("read").expect("present");
                assert_eq!(
                    row.state,
                    TaskState::NeedsVerification,
                    "{name}: a claim from a capability that did not report success must \
                     never leave the task retryable"
                );
                assert!(
                    !matches!(
                        repo.claim_specific(&tid, "w2", NOW + LEASE + 2, LEASE),
                        Ok(orxnud_store::task_repo::TargetedClaimOutcome::Claimed(_))
                    ),
                    "{name}: and a second worker must not be able to repeat the effect"
                );
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// The invariant, over every production `DispatchError` variant at once.
    ///
    /// Two channels map the same input — this one to `EffectStatus` and
    /// `terminal_outcome_for_failure` to the journal's `OutcomeKind` — and they were
    /// separate `match`es over separate groupings. A variant added to one and not the
    /// other compiles, passes both modules' tests, and ships a contradiction. The defect
    /// this table exists to prevent is exactly that: it compiled cleanly and every test
    /// that existed at the time passed.
    ///
    /// The property asserted is the one the architecture needs: **no component may
    /// represent a may-have-run execution as definitely not-performed.** It is checked
    /// directly, per variant, rather than inferred from the two channels happening to
    /// agree today.
    ///
    /// `retry` is the operational consequence, not a separate claim: `recover()` sends a
    /// task to `needs-verification` unless the effect is `not-performed`
    /// (`status <> 'not-performed' AND idempotent = 0`), so `NotPerformed` *is* the retry
    /// permission and `Unknown` withholds it.
    #[test]
    fn the_two_channels_never_contradict_on_execution_certainty() {
        use orxnud_capability::dispatch::{DisabledReason, ExecutionCertainty};

        /// One row per `DispatchError` variant: what each channel must answer.
        struct Row {
            what: &'static str,
            error: DispatchError,
            /// Whether the capability could have executed. The fact the table is about.
            may_have_run: bool,
            /// What the effect ledger must record.
            effect: EffectStatus,
            /// What the journal must record.
            audit: orxnud_audit::OutcomeKind,
        }

        let unknown_refusal = SandboxRefusal {
            capability: cap(),
            reason: "the execution backend panicked".to_owned(),
            missing: vec!["a functioning execution backend"],
            certainty: ExecutionCertainty::Unknown,
        };

        let rows = vec![
            Row {
                what: "policy",
                audit: orxnud_audit::OutcomeKind::Denied,
                error: DispatchError::Policy(orxnud_policy::PolicyError::Denied {
                    reason: orxnud_policy::DenialReason::UnknownCapability {
                        capability: cap().to_string(),
                    },
                }),
                may_have_run: false,
                effect: EffectStatus::NotPerformed,
            },
            Row {
                what: "no implementation",
                audit: orxnud_audit::OutcomeKind::Denied,
                error: DispatchError::NoImplementation(cap()),
                may_have_run: false,
                effect: EffectStatus::NotPerformed,
            },
            Row {
                what: "disabled",
                audit: orxnud_audit::OutcomeKind::Denied,
                error: DispatchError::Disabled {
                    id: cap(),
                    reason: DisabledReason::Configured,
                },
                may_have_run: false,
                effect: EffectStatus::NotPerformed,
            },
            Row {
                what: "class escalation",
                audit: orxnud_audit::OutcomeKind::Denied,
                error: DispatchError::ClassEscalation {
                    id: cap(),
                    declared: orxnud_domain::enums::DataClass::Public,
                    actual: orxnud_domain::enums::DataClass::Regulated,
                },
                may_have_run: false,
                effect: EffectStatus::NotPerformed,
            },
            Row {
                what: "credential unavailable",
                audit: orxnud_audit::OutcomeKind::Denied,
                error: DispatchError::Credential(
                    orxnud_capability::credential::CredentialError::Absent("svc".to_owned()),
                ),
                may_have_run: false,
                effect: EffectStatus::NotPerformed,
            },
            Row {
                what: "invalid parameters",
                audit: orxnud_audit::OutcomeKind::Denied,
                error: DispatchError::InvalidInput {
                    capability: cap(),
                    detail: "traversing path".to_owned(),
                },
                may_have_run: false,
                effect: EffectStatus::NotPerformed,
            },
            Row {
                what: "reentrant",
                audit: orxnud_audit::OutcomeKind::Denied,
                error: DispatchError::Reentrant("called back in".to_owned()),
                may_have_run: false,
                effect: EffectStatus::NotPerformed,
            },
            Row {
                what: "sandbox refused, nothing attempted",
                audit: orxnud_audit::OutcomeKind::Denied,
                error: DispatchError::SandboxRefused(refusal()),
                may_have_run: false,
                effect: EffectStatus::NotPerformed,
            },
            Row {
                what: "sandbox refused, execution unknown",
                audit: orxnud_audit::OutcomeKind::Uncertain,
                error: DispatchError::SandboxRefused(unknown_refusal),
                may_have_run: true,
                effect: EffectStatus::Unknown,
            },
            Row {
                what: "audit failure",
                audit: orxnud_audit::OutcomeKind::Uncertain,
                error: DispatchError::Audit("journal unavailable".to_owned()),
                may_have_run: true,
                effect: EffectStatus::Unknown,
            },
            Row {
                what: "execution failed",
                audit: orxnud_audit::OutcomeKind::Failed,
                error: DispatchError::Execution("exit 1".to_owned()),
                may_have_run: true,
                effect: EffectStatus::Unknown,
            },
            Row {
                what: "verification failed",
                audit: orxnud_audit::OutcomeKind::Uncertain,
                error: DispatchError::Verification(orxnud_capability::verification::VerifyError(
                    "could not run".to_owned(),
                )),
                may_have_run: true,
                effect: EffectStatus::Unknown,
            },
            Row {
                what: "verification refuted",
                audit: orxnud_audit::OutcomeKind::Uncertain,
                error: DispatchError::VerificationRefuted {
                    evidence: "the file is absent".to_owned(),
                },
                // **Both of these changed, and they changed together** (ADR-0056
                // Decision 4). The row used to claim the capability `may_have_run: false`,
                // which is not true: the finding is raised in stage 9, after the capability
                // ran and was verified. The old comment read "this is the one row where 'it
                // ran' and 'the effect is absent' are both true" — and then it recorded
                // `may_have_run: false`, which contradicts its own sentence. The type could
                // not express the distinction, and the mapping picked the wrong side of it.
                //
                // Now that it is honestly `may_have_run: true`, the table's own
                // "unsafe direction" assertion below applies to this row too, which is the
                // property worth having: it is enforced by the table rather than exempted
                // from it.
                may_have_run: true,
                effect: EffectStatus::Unknown,
            },
        ];

        // Every arm of the classifier, or the table is not exhaustive. Adding a variant
        // without a row here is caught by the assertion below, because the classifier's
        // own exhaustiveness means an unlisted variant cannot reach it -- but the reverse
        // is not true, so the count is pinned.
        assert_eq!(
            rows.len(),
            13,
            "one row per DispatchError variant; extend this table when one is added"
        );

        for row in rows {
            assert_eq!(
                effect_status_for_dispatch_failure(&row.error),
                row.effect,
                "{}: the effect ledger must answer {:?}",
                row.what,
                row.effect
            );

            let (kind, detail) =
                orxnud_capability::dispatch::terminal_outcome_for_failure(&row.error);
            assert_eq!(
                kind, row.audit,
                "{}: the journal must record {:?} (got {kind:?}, detail {detail:?})",
                row.what, row.audit
            );

            // The invariant, stated in the two directions that matter.
            //
            // 1. **Unsafe direction.** A capability that may have run must not be
            //    recorded as definitely-absent by either channel. `Denied` asserts no
            //    execution and `not-performed` is the retry permission `recover()`
            //    grants, so either one alone re-opens the repeat.
            if row.may_have_run {
                assert_ne!(
                    row.effect,
                    EffectStatus::NotPerformed,
                    "{}: the capability may have run, so `not-performed` permits exactly \
                     the repeat this ledger exists to prevent",
                    row.what
                );
            }

            // 2. **The two channels must not disagree about whether the effect is
            //    established absent.** The relation is a lattice, not an equality:
            //
            //    | journal       | effect ledger            |
            //    |---------------|--------------------------|
            //    | `Denied`      | `NotPerformed` only      |
            //    | `Uncertain`   | `Unknown` only            |
            //    | `Completed`   | `Observed` only           |
            //    | `Failed`      | `NotPerformed` or `Unknown` |
            //
            //    `Failed` keeps two answers for a narrower reason than it used to: a
            //    capability can exit non-zero and still have left no effect, and the
            //    ledger cannot tell. `VerificationRefuted` used to live here as well, on
            //    the claim that a refuted postcondition is a proven absence. ADR-0056
            //    removed that claim, and the row moved to `Uncertain`/`Unknown`.
            //
            //    Every other pairing would be a contradiction in one direction or the
            //    other. `Denied` with `Unknown` contradicts the journal. `Uncertain` with
            //    `NotPerformed` is the defect this table was written for, and is now also
            //    the pairing ADR-0056 prevents a refuted verification from reaching.
            let allowed: &[EffectStatus] = match row.audit {
                orxnud_audit::OutcomeKind::Denied => &[EffectStatus::NotPerformed],
                orxnud_audit::OutcomeKind::Uncertain => &[EffectStatus::Unknown],
                orxnud_audit::OutcomeKind::Completed => &[EffectStatus::Observed],
                orxnud_audit::OutcomeKind::Failed | orxnud_audit::OutcomeKind::Cancelled => {
                    &[EffectStatus::NotPerformed, EffectStatus::Unknown]
                }
                // Never a terminal disposition, so no row can carry it. Listed rather than
                // wildcarded so that adding a new `OutcomeKind` forces a decision here
                // instead of silently inheriting a relation.
                other => panic!("{other:?} is not a terminal disposition"),
            };
            assert!(
                allowed.contains(&row.effect),
                "{}: journal {:?} does not admit effect status {:?}; allowed {allowed:?}",
                row.what,
                row.audit,
                row.effect
            );
        }
    }
}

/// The disclosure's own text must name the remediation that applies.
///
/// The `control` and `status` fields are what `daemon/status` returns, and they
/// described the transport as unfixed until S-17 -- a change that has already landed.
/// An operator reading `daemon/status` was being sent after the wrong thing. This
/// pins the corrected wording, and the parts of it that must survive: the refusal
/// stays until the R-1 evidence conditions are met, and refusing by default is not
/// the same as removing the exposure.
#[test]
fn the_disclosure_text_names_the_r1_evidence_and_not_an_unlanded_transport_change() {
    for (field, text) in [
        ("status", crate::runtime::ARGV_EXPOSURE_STATUS),
        ("control", crate::runtime::ARGV_EXPOSURE_CONTROL),
    ] {
        assert!(
            !text.contains("until S-17"),
            "the {field} still points at a transport change that has landed: {text}"
        );
        assert!(
            !text.contains("unfixed until S-17"),
            "the {field} still describes the transport as unfixed: {text}"
        );
        assert!(
            text.contains("Decision 7") && text.contains("R-1"),
            "the {field} must name ADR-0054 Decision 7 and its R-1 evidence conditions: \
             {text}"
        );
    }
    assert!(
        crate::runtime::ARGV_EXPOSURE_STATUS.contains("does not remove the exposure"),
        "the status must still say refusing by default does not remove the exposure: {}",
        crate::runtime::ARGV_EXPOSURE_STATUS
    );
    assert!(
        crate::runtime::ARGV_EXPOSURE_CONTROL.contains("not a degradation, and not a fix"),
        "the control must still say the refusal posture is not a fix: {}",
        crate::runtime::ARGV_EXPOSURE_CONTROL
    );
}

/// Negative control: the disclosure field is **absent**, not `null`, when nothing is
/// exposed.
///
/// Without this the field could be a constant `null` and every positive test above would
/// still pass -- `null` is not the disclosure it appears to be. A shipped daemon always
/// has `write-text` registered, so the absent branch is exercised here against the
/// function production calls rather than through a build that cannot be constructed.
#[test]
fn the_disclosure_field_is_absent_rather_than_null_when_nothing_is_exposed() {
    let mut status = json!({"status": "running"});
    assert!(
        status.get("argv_payload_exposure").is_none(),
        "precondition: the key must not already exist"
    );
    insert_argv_disclosure(&mut status, None);
    assert!(
        status.get("argv_payload_exposure").is_none(),
        "with nothing exposed the key must be absent, not null; got {status}"
    );
    assert!(
        !status
            .as_object()
            .expect("object")
            .contains_key("argv_payload_exposure"),
        "a null-valued key is still a key, and would be indistinguishable from a value; \
         got {status}"
    );
}

/// And when there *is* an exposure, the same function inserts it.
#[test]
fn the_disclosure_field_is_present_when_something_is_exposed() {
    let mut status = json!({"status": "running"});
    insert_argv_disclosure(
        &mut status,
        Some(ArgvPayloadDisclosure {
            exposure: "e",
            exposed: vec![ArgvExposureEntry {
                capability: "c".to_owned(),
                implementation_bound_bytes: Some(1),
            }],
            permitted: Vec::new(),
            refused: vec!["c".to_owned()],
            control: "k",
            status: "OPEN",
        }),
    );
    assert_eq!(
        status["argv_payload_exposure"]["exposed"][0]["capability"].as_str(),
        Some("c"),
        "the inserted field must carry the exposure, not merely exist; got {status}"
    );
}
