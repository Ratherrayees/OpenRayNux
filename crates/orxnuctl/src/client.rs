//! The local IPC client.
//!
//! # What this is
//!
//! Bytes over the approved local transport, and nothing else. Every frame is built
//! by `orxnud-protocol` and every socket operation by `orxnud-platform-ipc`; this
//! module connects the two and interprets the answer. It has no opinion about tasks,
//! leases or policy, because it cannot: those types are not nameable from this crate,
//! which is gate G2(b)'s whole point.
//!
//! # Why the runtime
//!
//! The transport's stream is async, so driving it needs an executor. A blocking
//! client would have to be a *second* implementation of the same socket, and the two
//! would then disagree about what a frame is — which is the bug class this repository
//! keeps paying for. One current-thread runtime per process is the cheaper trade.
//!
//! # Why errors are typed rather than printed
//!
//! `orxnuctl task list` with no daemon running is not the same failure as a daemon
//! that refused the request, and a user needs to be told which. [`ClientError`]
//! separates them so `main` can choose the exit path and the message without matching
//! on prose.

use std::path::{Path, PathBuf};

use orxnud_protocol::error::{ProtocolError, RpcError};
use orxnud_protocol::frame::{Request, RequestId, Response};
use orxnud_protocol::version::{PROTOCOL_VERSION, VersionRange};
use serde_json::Value;

/// The largest response this client will read.
///
/// One newline-terminated frame. The daemon's own ingress bound is
/// `orxnud_daemon::runtime::MAX_REQUEST_BYTES`; a *response* is bounded by the
/// protocol's frame ceiling, and refusing to read past this keeps a wrong or hostile
/// peer from making the CLI allocate without limit.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Why a request could not be completed.
///
/// Each variant is a fact a user can act on differently, which is why they are
/// separate rather than one string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// Nothing is listening at the endpoint.
    ///
    /// Distinct from a conversation that failed: "the daemon is not running" is
    /// fixed by starting it, whereas a broken pipe mid-request is not.
    #[error("cannot reach the OpenRayNux daemon at {endpoint}: {reason}")]
    Unavailable {
        /// The endpoint that was tried.
        endpoint: String,
        /// What the OS said. A path is never included; this is the socket.
        reason: String,
    },

    /// The transport failed while the request was in flight.
    #[error("the connection to the daemon failed: {0}")]
    Transport(String),

    /// The daemon answered with something that is not a protocol response.
    ///
    /// A real possibility on a local socket, and not one to paper over: it means the
    /// peer is not the daemon this client speaks to.
    #[error("the daemon sent something this client cannot read: {0}")]
    Malformed(String),

    /// The client could not build a valid request.
    ///
    /// Local, before anything is sent: `--params` that is not JSON is a typo, and
    /// reporting it as a server refusal would send the user looking in the wrong place.
    #[error("{detail}")]
    InvalidParams {
        /// What was wrong with the arguments.
        detail: String,
    },

    /// The daemon's protocol version is not one this build can speak.
    #[error("the daemon speaks protocol {daemon}, but this build speaks {client}")]
    VersionMismatch {
        /// What the daemon reported.
        daemon: u16,
        /// What this build speaks.
        client: u16,
    },

    /// The daemon answered, and the answer was "no".
    ///
    /// Carries the server's *structured* reason, never a message to be parsed: the
    /// daemon sends `data.reason` as a fixed word precisely so a client does not have
    /// to read English to find out what happened.
    #[error("{message}")]
    Refused {
        /// The JSON-RPC code.
        code: i32,
        /// The human-facing message.
        message: String,
        /// `data.reason`, when present.
        reason: Option<String>,
        /// `data.detail`, when present.
        detail: Option<String>,
    },
}

impl ClientError {
    /// The structured reason a user should be shown, if the daemon gave one.
    ///
    /// Prefers `detail`, which is the more specific of the two, and falls back to
    /// `reason`. Never the raw message: it can echo a parameter back, and the
    /// parameters are the user's own so that is harmless, but there is no reason to
    /// prefer prose over a stable word when both are available.
    #[must_use]
    pub fn structured_reason(&self) -> Option<&str> {
        match self {
            Self::Refused { reason, detail, .. } => detail.as_deref().or(reason.as_deref()),
            _ => None,
        }
    }
}

/// A client for one endpoint.
#[derive(Debug, Clone)]
pub struct Client {
    endpoint: PathBuf,
}

impl Client {
    /// A client for an explicit endpoint.
    #[must_use]
    pub fn new(endpoint: impl Into<PathBuf>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    /// A client for the endpoint a default install serves on.
    ///
    /// The same derivation the daemon uses, from the same function, so a CLI cannot
    /// end up looking somewhere the daemon is not.
    #[must_use]
    pub fn with_default_endpoint() -> Self {
        Self::new(orxnud_platform_ipc::default_endpoint())
    }

    /// The endpoint this client talks to.
    #[must_use]
    pub fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Sends one request and returns the `result` value.
    ///
    /// # Errors
    ///
    /// [`ClientError`] for every failure: unreachable, unreadable, wrong version, or
    /// a refusal the daemon returned.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        let request = Request::new(RequestId::Text("1".to_owned()), method).with_params(params);
        self.send(&request)?.into_result().map_err(|e| refusal(&e))
    }

    /// Sends a request and returns the whole response, error or not.
    ///
    /// Used by the version check, which needs to read a *successful* reply and would
    /// otherwise have to special-case its own probe.
    ///
    /// # Errors
    ///
    /// As [`Self::call`], except that a JSON-RPC error is returned rather than raised.
    pub fn send(&self, request: &Request) -> Result<Response, ClientError> {
        let frame = request.encode().map_err(protocol)?;
        let bytes = self.exchange(&frame)?;
        Response::decode(&bytes).map_err(|e| ClientError::Malformed(e.to_string()))
    }

    /// The version the daemon speaks, refusing one this build cannot use.
    ///
    /// Phase one of every conversation, so no task request is ever sent to a daemon
    /// whose answers this client would misread. "Not silently accepting a version it
    /// does not understand" is the whole requirement; doing it explicitly is cheaper
    /// than debugging a shape mismatch later.
    ///
    /// # Errors
    ///
    /// [`ClientError`] for any transport failure, or [`ClientError::VersionMismatch`]
    /// when the daemon's version is outside this build's range.
    pub fn negotiate(&self) -> Result<u16, ClientError> {
        let mine = VersionRange::default();
        let reply = self.call("daemon/version", Value::Null)?;
        let current = reply
            .get("current")
            .and_then(Value::as_u64)
            .and_then(|v| u16::try_from(v).ok())
            .ok_or_else(|| {
                ClientError::Malformed("daemon/version did not report a version".to_owned())
            })?;
        if !mine.accepts(orxnud_protocol::version::ProtocolVersion(current)) {
            return Err(ClientError::VersionMismatch {
                daemon: current,
                client: PROTOCOL_VERSION.as_u16(),
            });
        }
        Ok(current)
    }

    /// One request/response exchange on a fresh connection.
    ///
    /// A fresh connection per call, deliberately: the transport is one
    /// request/response per connection by design, and reusing a socket would mean
    /// owning its framing state in the client — which is the duplication this crate
    /// exists to avoid.
    fn exchange(&self, frame: &[u8]) -> Result<Vec<u8>, ClientError> {
        let endpoint = self.endpoint.clone();
        let endpoint_label = endpoint.display().to_string();
        let frame = frame.to_vec();

        runtime().block_on(async move {
            let mut stream = orxnud_platform_ipc::connect(&endpoint).await.map_err(|e| {
                ClientError::Unavailable {
                    endpoint: endpoint_label,
                    reason: transport_reason(&e),
                }
            })?;
            stream
                .write_line(&frame)
                .await
                .map_err(|e| ClientError::Transport(transport_reason(&e)))?;
            stream
                .read_line_bounded(MAX_RESPONSE_BYTES)
                .await
                // A daemon that hangs up instead of answering is a transport failure,
                // and `peer_io` already classified it as a peer disconnect -- so this
                // is a well-typed "no answer", not an unexplained EOF.
                .map_err(|e| ClientError::Transport(transport_reason(&e)))
        })
    }
}

/// A current-thread runtime, built once per process.
///
/// One thread, no work-stealing, no timers: this client makes a handful of syscalls
/// and then exits, so a runtime sized for anything else would be pure overhead.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime needs no OS resource to be unavailable")
}

/// A transport failure as something a user can read.
///
/// The `IpcError` display is already peer-relative ("the peer disconnected"), but for
/// a client the interesting half is the underlying OS reason, which `Other` carries.
/// Never the endpoint: the caller decides whether to print that.
fn transport_reason(e: &orxnud_platform_ipc::IpcError) -> String {
    match e {
        orxnud_platform_ipc::IpcError::Unsupported => {
            "this build has no local transport on this platform".to_owned()
        }
        other => other.to_string(),
    }
}

fn protocol(e: ProtocolError) -> ClientError {
    ClientError::Malformed(e.to_string())
}

/// Turns a JSON-RPC error into the CLI's refusal type.
#[must_use]
pub fn refusal(error: &RpcError) -> ClientError {
    let read = |key: &str| -> Option<String> {
        error
            .data
            .as_ref()
            .and_then(|d| d.get(key))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    ClientError::Refused {
        code: error.code.code(),
        message: error.message.clone(),
        reason: read("reason"),
        detail: read("detail"),
    }
}
