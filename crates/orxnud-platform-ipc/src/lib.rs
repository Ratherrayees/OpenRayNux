//! Local IPC transport: a Unix domain socket on Unix, a refusal on Windows.
//!
//! # Why this is a separate crate
//!
//! Gate **G3** permits `cfg(target_os)` only inside `crates/orxnud-platform-*`, and
//! that rule is what forces the placement. A socket is an operating-system
//! facility; a daemon that named one would be a daemon with an opinion about the
//! host, which is what the trait boundary exists to prevent. So the *selection*
//! lives here and everything above it asks for "the host's local transport".
//!
//! # What this crate is not
//!
//! It speaks **bytes**. It does not know JSON-RPC, does not parse a frame, and does
//! not know what a request is. `orxnud-protocol` owns the wire vocabulary and the
//! size bounds; this crate owns the socket. Neither may depend on the other, so the
//! framing lives one layer up in the runtime, which is also where a message limit
//! can be applied to *decoded* input rather than only to bytes off the wire.
//!
//! # Why no HTTP, and never TCP
//!
//! ADR-0003 chooses a Unix socket / named pipe. This is a single-user, local-first
//! daemon: a TCP listener would expose an unauthenticated control surface on every
//! interface, and an HTTP layer would add a web-server dependency to buy features
//! the protocol does not have. Neither is a future question — they are the wrong
//! shape for this product.
//!
//! # Windows
//!
//! `LocalListener::bind` **refuses** on Windows rather than binding something else.
//! A named pipe needs `CreateNamedPipeW` and `CreateFileW`, which means
//! `windows-sys` and `unsafe` — and gate **G4** forbids `unsafe` outside a platform
//! crate that has opted in. This crate has no `unsafe` and is not going to grow one
//! to host a transport nothing can test on this build host. The shape is already
//! correct for a pipe: [`Listener`] is the abstraction, and a Windows
//! implementation is an addition behind it rather than a redesign. This is the same
//! posture `orxnud-platform-sandbox` takes with `UnsupportedRunner`.
//!
//! Recording the gap rather than hiding it is the point. A Windows build of
//! OpenRayNux will refuse to serve IPC and say why, instead of silently falling
//! back to something that looks like it works.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::path::{Path, PathBuf};

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use unix::UnixSocketListener;

/// A local, non-network transport failure.
///
/// Its own type rather than `io::Error` so a caller cannot mistake a refused
/// endpoint for a transient socket hiccup and retry forever.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// The endpoint could not be bound.
    #[error("local endpoint `{path}` could not be bound: {reason}")]
    Bind {
        /// The endpoint that was attempted.
        path: String,
        /// What the OS said.
        reason: String,
    },

    /// A previously bound endpoint exists and is not ours to remove.
    ///
    /// Never resolved by deleting the path. See [`bind`].
    #[error("local endpoint `{0}` already exists; refusing to remove a path we did not create")]
    EndpointExists(String),

    /// Accepting a connection failed.
    #[error("could not accept a local connection: {0}")]
    Accept(String),

    /// The peer went away.
    ///
    /// A normal event, not an error: a client may disconnect at any point, and the
    /// runtime treats it as the end of that connection rather than a failure.
    #[error("the peer disconnected")]
    Disconnected,

    /// No transport backend exists on this platform.
    #[error("no local IPC backend is implemented for this platform")]
    Unsupported,

    /// Any other transport-level failure.
    #[error("local transport error: {0}")]
    Other(String),
}

/// A connected local peer.
///
/// Byte-oriented on purpose: framing is the caller's business, because only the
/// caller knows what a valid message is. [`LocalStream::read_line_bounded`] is
/// "read one line, but never more than N bytes" is the single most important thing a
/// provided because a "read one line, but never more than N bytes" contract is the
/// one thing a line protocol must not get wrong, and getting it wrong is a\n/// memory-exhaustion bug rather than a parse error.
pub struct LocalStream {
    inner: Inner,
}

#[cfg(unix)]
type Inner = tokio::net::UnixStream;

impl std::fmt::Debug for LocalStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the stream: it holds a file descriptor.
        f.debug_struct("LocalStream").finish_non_exhaustive()
    }
}

impl LocalStream {
    /// Wraps an accepted stream.
    fn wrap(inner: Inner) -> Self {
        Self { inner }
    }

    /// Reads one newline-terminated message, refusing to exceed `limit`.
    ///
    /// The limit is enforced **while reading**, not after: a peer that never sends
    /// a newline would otherwise be able to make this allocate without bound, which
    /// is a denial of service and not a parse error.
    ///
    /// # Errors
    ///
    /// [`IpcError::Other`] if the peer sends more than `limit` bytes without a
    /// newline, or [`IpcError::Disconnected`] if it closes first.
    pub async fn read_line_bounded(&mut self, limit: usize) -> Result<Vec<u8>, IpcError> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::with_capacity(limit.min(1024));
        let mut byte = [0u8; 1];
        loop {
            let n = self
                .inner
                .read(&mut byte)
                .await
                .map_err(|e| IpcError::Other(e.to_string()))?;
            if n == 0 {
                return if buf.is_empty() {
                    Err(IpcError::Disconnected)
                } else {
                    Err(IpcError::Other("peer closed mid-message".to_owned()))
                };
            }
            if byte[0] == b'\n' {
                return Ok(buf);
            }
            if buf.len() >= limit {
                return Err(IpcError::Other(format!(
                    "message exceeded the {limit}-byte limit without a newline"
                )));
            }
            buf.push(byte[0]);
        }
    }

    /// Writes one message, followed by a newline.
    ///
    /// # Errors
    ///
    /// [`IpcError::Other`] if the peer is gone or the write fails.
    pub async fn write_line(&mut self, bytes: &[u8]) -> Result<(), IpcError> {
        use tokio::io::AsyncWriteExt;
        self.inner
            .write_all(bytes)
            .await
            .map_err(|e| IpcError::Other(e.to_string()))?;
        self.inner
            .write_all(b"\n")
            .await
            .map_err(|e| IpcError::Other(e.to_string()))?;
        self.inner
            .flush()
            .await
            .map_err(|e| IpcError::Other(e.to_string()))
    }
}

/// The host's local transport.
///
/// An **enum**, not a trait object, and the reason is concrete: an `async fn` in a
/// trait is not dyn-compatible, so a trait would need `Box<dyn Future>` boxing or
/// an executor-abstraction crate to be stored in a `Daemon` field. With one
/// platform implemented and one refusing, an enum says the same thing without the
/// machinery, and it is exhaustive — a third platform cannot be forgotten at a call
/// site.
///
/// Callers get this one type and never name a platform, which is the property gate
/// **G3** exists to enforce.
#[derive(Debug)]
pub enum Listener {
    /// A Unix domain socket.
    #[cfg(unix)]
    Unix(UnixSocketListener),
    /// No backend is implemented here. Every operation refuses.
    Unsupported,
}

impl Listener {
    /// Waits for the next peer.
    ///
    /// Takes `&self` so the listener can sit behind an `Arc` in an accept loop that
    /// is also watching for shutdown. The socket is the only shared state and the
    /// OS serialises it.
    ///
    /// # Errors
    ///
    /// [`IpcError::Unsupported`] where no backend exists,
    /// [`IpcError::Disconnected`] once closed, or [`IpcError::Accept`] if the
    /// accept failed.
    pub async fn accept(&self) -> Result<LocalStream, IpcError> {
        match self {
            #[cfg(unix)]
            Self::Unix(l) => l.accept().await,
            Self::Unsupported => Err(IpcError::Unsupported),
        }
    }

    /// The endpoint this listener is bound to.
    ///
    /// # Panics
    ///
    /// Never for a bound listener. The unsupported variant is only ever produced by
    /// a failed [`bind`], so it is unreachable on a live endpoint; the endpoint is
    /// carried on the type rather than defaulted.
    #[must_use]
    pub fn endpoint(&self) -> Option<&Path> {
        match self {
            #[cfg(unix)]
            Self::Unix(l) => Some(l.endpoint()),
            Self::Unsupported => None,
        }
    }

    /// Stops accepting. In-flight connections are unaffected.
    pub fn close(&self) {
        match self {
            #[cfg(unix)]
            Self::Unix(l) => l.close(),
            Self::Unsupported => {}
        }
    }
}

/// Binds the host's local transport, or explains why it cannot.
///
/// # The stale-endpoint rule
///
/// A leftover socket file from a crashed daemon is *our* path, and removing it is
/// correct. A socket file that another live daemon is listening on is **not**, and
/// this function refuses rather than unlinking it: the standard way to tell them
/// apart is to try connecting. So:
///
/// * the endpoint does not exist → bind;
/// * it exists and something is listening → [`IpcError::EndpointExists`];
/// * it exists and nothing answers → remove the stale file and bind.
///
/// # Errors
///
/// [`IpcError::Bind`], [`IpcError::EndpointExists`], or [`IpcError::Unsupported`]
/// where no backend is implemented.
///
pub async fn bind(path: &Path) -> Result<Listener, IpcError> {
    #[cfg(unix)]
    {
        UnixSocketListener::bind_owned(path).await
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(IpcError::Unsupported)
    }
}

/// The name of the transport this build selected, for logs and `doctor`.
///
/// Never says "unix-socket" on a platform that did not select one.
#[must_use]
pub fn backend_name() -> &'static str {
    #[cfg(unix)]
    {
        "unix-domain-socket"
    }
    #[cfg(not(unix))]
    {
        "unsupported"
    }
}

/// Where the socket lives, under the daemon's state root.
///
/// Derived from the existing `Paths` convention — a sibling of the database file,
/// under the same root — so uninstalling means removing one directory and there is
/// no second place a runtime artefact can appear.
#[must_use]
pub fn endpoint_for(root: &Path) -> PathBuf {
    root.join("orxnud.sock")
}

/// Resolves when the host asks the process to stop.
///
/// SIGINT **and** SIGTERM on Unix: a daemon that answers only Ctrl-C has to be
/// `SIGKILL`ed by a service manager, which skips the endpoint cleanup and leaves a
/// stale socket for the next start to reason about. On a platform with neither, the
/// Ctrl-C handler is the whole contract.
///
/// This lives here rather than in the runtime because it is the one part of the
/// lifecycle that has to name a platform, and gate **G3** permits `cfg` only inside
/// `crates/orxnud-platform-*`. The gate caught that in the runtime during
/// development, which is what it is for.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_is_a_sibling_of_the_database_under_one_root() {
        let root = Path::new("/var/lib/orxnud");
        assert_eq!(endpoint_for(root), Path::new("/var/lib/orxnud/orxnud.sock"));
        assert!(
            endpoint_for(root).starts_with(root),
            "the endpoint must live under the state root, or uninstall misses it"
        );
    }

    #[test]
    fn the_backend_name_is_honest_about_this_platform() {
        let name = backend_name();
        assert!(name == "unix-domain-socket" || name == "unsupported");
        if cfg!(not(unix)) {
            assert_eq!(
                name, "unsupported",
                "a host with no backend must not claim one"
            );
        }
    }

    #[test]
    fn an_unsupported_platform_refuses_rather_than_binding_something_else() {
        if cfg!(unix) {
            return;
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let err = rt
            .block_on(bind(Path::new("ignored")))
            .expect_err("must refuse");
        assert!(matches!(err, IpcError::Unsupported), "{err:?}");
    }
}
