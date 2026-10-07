//! Local IPC transport: a Unix domain socket on Unix, a refusal on Windows.
//!
//! # Why this is a separate crate
//!
//! Gate **G3** permits platform predicates only inside `crates/orxnud-platform-*`, and
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
//!
//! # The one exception to "no unsafe here", and why it is here
//!
//! `deny` rather than `forbid`, with a single named exception: the Unix backend's
//! `peer_principal` calls `getsockopt(2)` to read `SO_PEERCRED`, because the safe wrappers
//! do not expose
//! it and the kernel's answer to "which operating-system user is this caller" is the
//! only thing in the tree that can tell the daemon who it is talking to.
//!
//! This is the opt-in gate **G4** describes — `unsafe` is forbidden outside a platform
//! crate that has chosen to have it — and the choice is recorded rather than implied:
//! one function, four lines, a `SAFETY` comment, and tests that read the principal back
//! off a real socket. Everything above this crate stays `forbid`, because the point of
//! the boundary is that nothing above the transport can name a peer it did not ask the
//! kernel about.

#![deny(unsafe_code)]
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

    /// The peer's operating-system identity could not be established.
    ///
    /// A distinct error rather than a variant of [`Self::Accept`], because the two mean
    /// opposite things to the caller above: a failed `accept(2)` is a transport fault to
    /// retry, while this is a **refusal to proceed with a peer whose identity is unknown**.
    ///
    /// It carries no detail on purpose. The underlying cause differs by platform — no
    /// `SO_PEERCRED` on macOS, a refused `getsockopt(2)` anywhere — and neither is useful
    /// to a caller, which needs to know only that there is no identity and therefore no
    /// authority to derive. A client cannot use it to tell which platforms lack peer
    /// credentials.
    #[error("the local peer's identity could not be established")]
    PeerIdentityUnavailable,

    /// Any other transport-level failure.
    #[error("local transport error: {0}")]
    Other(String),
}

/// Classifies an OS error raised by an operation on a peer-facing socket.
///
/// # Why this lives here and not in the daemon
///
/// A local client may vanish at any instant, *including while its response is being
/// written* -- a client that sends a request and closes without reading is ordinary
/// behaviour, not an attack. On Unix that surfaces as `EPIPE`/`ECONNRESET`. Deciding
/// what those errno values mean is operating-system knowledge, and gate **G3** exists
/// so only a `orxnud-platform-*` crate holds it. So the daemon sees only
/// [`IpcError::Disconnected`], and `serve` treats it as "this connection ended",
/// rather than learning that a vanished peer is somehow different from a dead one.
///
/// # What is deliberately *not* mapped
///
/// Only [`std::io::ErrorKind::BrokenPipe`] and
/// [`std::io::ErrorKind::ConnectionReset`] mean "the peer disappeared while we were
/// talking to it". Permission failures, a bad or closed descriptor, a short write for
/// any other reason, and every unrecognised OS error stay [`IpcError::Other`] and keep
/// propagating. Mapping every write failure to `Disconnected` would be the opposite
/// defect: it would turn a real server-side fault into silence, and a daemon that can
/// never report a transport problem is a daemon nobody can debug.
///
/// [`std::io::ErrorKind`] is used rather than raw `errno` precisely so this needs no
/// `cfg(target_os)`: the kinds are portable, so a future Windows pipe inherits the same
/// classification instead of a second, divergent copy of it.
fn peer_io(e: std::io::Error) -> IpcError {
    use std::io::ErrorKind::{BrokenPipe, ConnectionReset};
    match e.kind() {
        BrokenPipe | ConnectionReset => IpcError::Disconnected,
        _ => IpcError::Other(e.to_string()),
    }
}

/// Who the kernel says a connected local peer is.
///
/// # Why this exists at the lowest layer
///
/// Until now the only thing standing between a local caller and the daemon's authority
/// was the socket's mode. That is a real boundary, and it is the *only* one: `0600` on
/// the socket and `0700` on its parent directory mean the kernel will not let another
/// user `connect(2)`. But a permission bit is not an identity. Nothing anywhere in the
/// daemon ever asked "who is this?" and compared the answer to anything, so the daemon
/// asserted a human actor on the strength of a file mode that a different process, a
/// different mount namespace, or a different uid after `setuid` could in principle be
/// holding.
///
/// This type is the answer to that question, asked by the kernel rather than by us, and
/// it is deliberately the *only* thing in the tree that can answer it. It lives here
/// because this is the crate that owns the socket, and gate **G3** exists precisely so
/// that knowledge of `cfg(target_os)` and syscalls stays below the daemon.
///
/// # What the kernel gives, and what it does not
///
/// `SO_PEERCRED` reports the peer's real uid, gid and pid **at connect time**, and it is
/// not forgeable by the peer: those are the credentials of the process the kernel ran,
/// not anything the process wrote. That is the strongest native mechanism available for
/// a Unix domain socket and is why it was chosen over reading a username, over an
/// application-level token file, and over anything the caller supplies.
///
/// It proves *which operating-system user* the caller is. It does not prove intent, and
/// it does not prove the caller is interactive — so a caller must not read this as
/// authority over anything on its own. Turning it into authority is the daemon's job, and
/// the daemon compares it against the installation's owner before deciding anything.
///
/// Deliberately absent: any credential *material*. A uid is an identifier, not a secret,
/// but there is no reason to carry a gid or pid into a higher layer that needs neither,
/// so [`uid`](Self::uid) is the only accessor. Nothing here is ever serialised into an
/// audit record — see the daemon's `installation_identity` for the stable application
/// identity that is used instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportPrincipal {
    uid: u32,
}

impl TransportPrincipal {
    /// The peer's real user id, as the kernel reported it.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Whether this peer is the installation's owner.
    ///
    /// A plain integer equality, and deliberately the *only* question a caller above
    /// asks. "Is this the owner?" is answerable from this one fact; "may this peer drive
    /// the daemon?" is not, and is not this function's business to decide.
    #[must_use]
    pub const fn is_owner(&self, owner_uid: u32) -> bool {
        self.uid == owner_uid
    }
}

/// The operating-system user that owns a local endpoint, where the platform can say.
///
/// # Why this lives here and not above
///
/// The daemon needs the *installation's* owner to compare a peer's uid against, and
/// getting it means reading filesystem metadata -- which is `cfg(target_os)`. Gate **G3**
/// exists precisely so that knowledge stays below this crate, and putting a branch in the
/// daemon to read a uid would have defeated it. This crate already owns the endpoint's
/// lifecycle (it binds it, tightens its mode, and is the only thing permitted to unlink
/// it), so it is the natural home for one more question about it.
///
/// # Returns `None` rather than a default
///
/// `None` means the platform cannot report it, and the caller must refuse rather than
/// assume. The failure mode this avoids is a daemon that starts up, cannot learn who it
/// serves, and then grants on the strength of not knowing.
///
/// Deliberately not `Result`: there is no error to distinguish and no detail worth
/// returning. "Cannot answer" is the whole of it, and it maps to one refusal.
pub fn endpoint_owner_uid(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.uid())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// A connected local peer.
///
/// Byte-oriented on purpose: framing is the caller's business, because only the
/// caller knows what a valid message is. [`LocalStream::read_line_bounded`] is
/// "read one line, but never more than N bytes", and that bound is the one thing a
/// line protocol must not get wrong, because getting it wrong is a
/// memory-exhaustion bug rather than a parse error.
pub struct LocalStream {
    inner: Inner,
    /// The peer the kernel identified, or `None` where it could not be established.
    ///
    /// `None` is the whole fail-closed posture in one field: it is not a default
    /// identity, and [`Self::principal`] turns it into an error rather than letting a
    /// caller read it as "no information means no restriction".
    principal: Option<TransportPrincipal>,
}

#[cfg(unix)]
type Inner = tokio::net::UnixStream;

/// The stream a platform with no backend cannot have.
///
/// # Why this is a refusal and not a fake socket
///
/// The portable core names `LocalStream` in signatures it may not `cfg` — gate **G3**
/// forbids `cfg` above this crate — so the type has to exist everywhere even where no
/// connection can ever be made. The obvious ways to satisfy that are all wrong:
///
/// * `Option<tokio::net::UnixStream>` would need a Unix type in a non-Unix build.
/// * A second `read_line_bounded` under `#[cfg]` would give Windows its own framing
///   loop, which is precisely the second-implementation drift
///   [`LocalStream`]'s shared-framing design exists to prevent.
/// * A silent no-op stream would be the worst of the three: a Windows caller would
///   read an empty buffer forever and conclude the peer was quiet.
///
/// So the field is a type with no transport behind it, and every operation on it
/// refuses. This is the same posture [`Listener::Unsupported`] takes, one level down:
/// the refusal lives in the platform crate, and the caller above meets
/// [`IpcError::Unsupported`] at the three entry points that can actually reach a
/// stream — [`bind`], [`Listener::accept`] and [`connect`] — rather than here.
///
/// It is deliberately unreachable rather than merely discouraged: no public path
/// constructs a `LocalStream` without one of those three succeeding first, so this
/// exists to make "the mechanism does not exist here" total instead of leaving it to
/// an `unreachable!()` that would panic in a daemon.
#[cfg(not(unix))]
type Inner = RefusedStream;

/// A peer stream for a platform where no local transport is implemented.
///
/// Zero-sized and never constructed; it exists so [`LocalStream`] compiles and so
/// that any operation on one refuses rather than pretending to have read or written
/// bytes. This is the `orxnud-platform-sandbox` `UnsupportedRunner` shape applied to
/// the transport: refuse every operation, and say which facility is missing.
#[cfg(not(unix))]
struct RefusedStream;

#[cfg(not(unix))]
impl RefusedStream {
    /// The single refusal every operation reports.
    ///
    /// [`std::io::ErrorKind::Unsupported`] rather than a connection error, because
    /// nothing was ever connected: the message has to distinguish "this platform has
    /// no transport" from "the peer misbehaved", or a reader will debug the wrong
    /// layer.
    fn refuse() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "no local IPC backend is implemented for {}: this host has no {}, so a \
                 connected peer cannot exist here. Refusing rather than reporting an \
                 empty read",
                std::env::consts::OS,
                "unix domain socket or Windows named pipe",
            ),
        )
    }
}

#[cfg(not(unix))]
impl tokio::io::AsyncRead for RefusedStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(RefusedStream::refuse()))
    }
}

#[cfg(not(unix))]
impl tokio::io::AsyncWrite for RefusedStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(RefusedStream::refuse()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(RefusedStream::refuse()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(RefusedStream::refuse()))
    }
}

impl std::fmt::Debug for LocalStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the stream: it holds a file descriptor.
        f.debug_struct("LocalStream").finish_non_exhaustive()
    }
}

impl LocalStream {
    /// Wraps an accepted stream, recording who the kernel says the peer is.
    ///
    /// `#[cfg(unix)]` because the real backend is the only thing that produces one.
    /// On a platform with no backend this constructor must **not** exist: its absence
    /// is what makes [`LocalStream`] uninhabited there, rather than merely unlikely.
    ///
    /// The principal is read here, at accept, rather than on demand later: it is fixed
    /// at connect time, so reading it once is both sufficient and cheaper than reading
    /// it per request.
    #[cfg(unix)]
    fn wrap(inner: Inner) -> Self {
        let principal = unix::peer_principal(&inner);
        Self { inner, principal }
    }

    /// Who the kernel says this peer is.
    ///
    /// # The one thing every caller above must do
    ///
    /// This returns an error wherever an identity could not be established, including on
    /// a platform that has no peer-credential mechanism at all. There is deliberately no
    /// "unknown peer" value to read past: a caller that wants a principal has to handle
    /// the case where there isn't one, and the only way to make that impossible to skip
    /// is to hand out a `Result` with no success branch on those platforms.
    ///
    /// The consequence for the daemon is deliberate. Where this fails, the daemon must
    /// refuse the connection rather than fall back to treating the caller as somebody it
    /// recognises — a fallback is how an unverified peer becomes an authenticated one.
    ///
    /// # Errors
    ///
    /// [`IpcError::PeerIdentityUnavailable`] when the platform offers no peer-credential
    /// mechanism, or when the kernel refused to report one for this connection.
    pub fn principal(&self) -> Result<TransportPrincipal, IpcError> {
        self.principal.ok_or(IpcError::PeerIdentityUnavailable)
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
    /// newline, or [`IpcError::Disconnected`] if it closes -- or is reset -- first.
    pub async fn read_line_bounded(&mut self, limit: usize) -> Result<Vec<u8>, IpcError> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::with_capacity(limit.min(1024));
        let mut byte = [0u8; 1];
        loop {
            // A reset mid-read is the peer disappearing, exactly as a close is, and
            // `peer_io` says so for both without the caller having to know which.
            let n = self.inner.read(&mut byte).await.map_err(peer_io)?;
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
    /// [`IpcError::Disconnected`] if the peer has gone away -- the case that made a
    /// request-then-close client able to stop the daemon, because the write failed
    /// and the failure was reported as if the transport itself were broken. That is
    /// now classified here, at the boundary that can recognise it.
    ///
    /// [`IpcError::Other`] for every other write failure, which stays a real error.
    pub async fn write_line(&mut self, bytes: &[u8]) -> Result<(), IpcError> {
        use tokio::io::AsyncWriteExt;
        // Three syscalls, one classification: a peer that vanishes between the body
        // and the newline must be the same event as one that vanishes during it.
        self.inner.write_all(bytes).await.map_err(peer_io)?;
        self.inner.write_all(b"\n").await.map_err(peer_io)?;
        self.inner.flush().await.map_err(peer_io)
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

/// Connects to an endpoint this host's local transport is already serving.
///
/// The client half of [`bind`], for a peer that already knows where the daemon is.
/// It returns the same [`LocalStream`] the server side accepts, so both ends share
/// one framing implementation rather than each having its own idea of where a message
/// ends.
///
/// # Errors
///
/// [`IpcError::Unsupported`] where no backend exists, or [`IpcError::Other`] if nothing
/// is listening — which is *not* [`IpcError::Disconnected`]. "The daemon is not
/// running" and "the daemon hung up mid-conversation" are different facts and a
/// caller has to be able to report them differently.
pub async fn connect(path: &Path) -> Result<LocalStream, IpcError> {
    #[cfg(unix)]
    {
        LocalStream::connect(path).await
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(IpcError::Unsupported)
    }
}

/// The state root a default install uses.
///
/// The XDG convention, spelled out rather than pulled in as a dependency for one
/// call: the rule is two environment lookups, and a personal install that cannot be
/// relocated is a worse problem than a hand-written default.
///
/// # Why it lives here
///
/// Because [`endpoint_for`] takes a state root, *something* has to decide what that
/// root is, and a client that cannot ask the same question the daemon answered will
/// look in the wrong place — the failure mode being a CLI that reports "the daemon is
/// not running" while the daemon is serving somewhere else. The rule is
/// platform-and-environment knowledge, so it belongs in the crate that owns both the
/// endpoint name and the platform branch, and both sides call this one function.
#[must_use]
pub fn default_state_root() -> PathBuf {
    if let Some(base) = std::env::var_os("XDG_STATE_HOME")
        && !base.is_empty()
    {
        return PathBuf::from(base).join("orxnud");
    }
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from(".orxnud"), PathBuf::from);
    home.join(".local").join("state").join("orxnud")
}

/// The endpoint a default install serves on, and a client connects to.
///
/// [`endpoint_for`] applied to [`default_state_root`], so the two derivations cannot
/// drift into "the daemon is somewhere else".
#[must_use]
pub fn default_endpoint() -> PathBuf {
    endpoint_for(&default_state_root())
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

/// A blocking client connection to a bound endpoint.
///
/// One named type rather than an opaque `impl Read + Write`, because callers also need
/// `set_read_timeout` and `shutdown`, which no trait bound in that list provides. The
/// wrapper is what lets the daemon's end-to-end tests speak to a live socket without naming
/// a platform type: see [`connect_blocking`].
#[derive(Debug)]
pub struct BlockingClient {
    #[cfg(unix)]
    inner: std::os::unix::net::UnixStream,
}

impl BlockingClient {
    /// Sets a read deadline, so a caller cannot block forever on a silent peer.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            self.inner.set_read_timeout(timeout)
        }
        #[cfg(not(unix))]
        {
            let _ = timeout;
            Ok(())
        }
    }

    /// Duplicates the handle, so a reader and a writer can share one connection.
    pub fn try_clone(&self) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                inner: self.inner.try_clone()?,
            })
        }
        #[cfg(not(unix))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no local IPC backend is implemented for this platform",
            ))
        }
    }

    /// Closes the read direction, so a blocked reader returns rather than hanging.
    ///
    /// Named for what a caller needs -- the half it wants to interrupt -- because
    /// `std::net::Shutdown` cannot appear in this crate's signature off Unix.
    pub fn shutdown_read(&self) {
        #[cfg(unix)]
        {
            let _ = self.inner.shutdown(std::net::Shutdown::Read);
        }
    }
}

impl std::io::Read for BlockingClient {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        {
            self.inner.read(buf)
        }
        #[cfg(not(unix))]
        {
            let _ = buf;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no local IPC backend is implemented for this platform",
            ))
        }
    }
}

impl std::io::Write for BlockingClient {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        {
            self.inner.write(buf)
        }
        #[cfg(not(unix))]
        {
            let _ = buf;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "no local IPC backend is implemented for this platform",
            ))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            self.inner.flush()
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
}

/// Connects a **blocking** client to a bound endpoint, or `None` where there is none.
///
/// # Why this exists
///
/// Test suites that drive the daemon end to end need to speak to its socket from
/// synchronous code, with a read timeout, and they were doing it by naming
/// `std::os::unix::net::UnixStream` directly. That is an OS facility named outside the one
/// crate allowed to name it, so the `windows-check` lane's `--all-targets` failed with
/// `E0433: cannot find 'unix' in 'os'` on three daemon test binaries.
///
/// Per-test `#[cfg_attr(..., ignore)]` does not fix that: `ignore` stops a test *running*,
/// while the code still has to *compile*. Only removing the code from the non-Unix build
/// does, and gate **G3** permits `cfg` solely inside a `platform-*` crate. So the platform
/// decision lives here and the tests ask for a socket rather than naming one -- the same
/// inversion as [`bind`] and [`connect`].
///
/// `None` off Unix, which is the refusal posture rather than a second mechanism: there is
/// no transport to connect to, and returning `None` says so without pretending.
#[cfg(unix)]
#[must_use]
pub fn connect_blocking(path: &Path) -> Option<BlockingClient> {
    std::os::unix::net::UnixStream::connect(path)
        .ok()
        .map(|inner| BlockingClient { inner })
}

/// Non-Unix: there is no local transport here, so there is nothing to connect to.
///
/// `None` for the same reason [`bind`] refuses rather than binding something else. The
/// paired type is what lets a caller compile on either platform and handle `None`
/// identically.
#[cfg(not(unix))]
#[must_use]
pub fn connect_blocking(path: &Path) -> Option<BlockingClient> {
    let _ = path;
    None
}

/// Releases an endpoint this process created, on shutdown.
///
/// The runtime calls this when it stops serving, so the socket file cannot outlive
/// the daemon that owns it — including when the runtime exits on a genuine transport
/// error rather than an orderly shutdown. That ordering used to live in the serve
/// loop itself, where any early return could skip it and leave a stale socket behind.
///
/// # Why the removal is narrow
///
/// This unlinks the recorded path and nothing else, and only while that path is still
/// a socket. [`bind`] refuses a path a live daemon is listening on rather than
/// removing it, so reaching here means the file was this process's own; re-checking
/// the type covers the remaining window, where something else replaced the path
/// between bind and shutdown. A path that is not a socket is left alone rather than
/// deleted.
///
/// A failure to remove is deliberately ignored: it is not the error the caller is
/// dealing with, and reporting it would replace a real diagnosis with a cosmetic one.
/// The next start handles a leftover socket through the documented stale-endpoint
/// rule in [`bind`], so nothing is stranded.
pub fn release_endpoint(path: &Path) {
    if !is_socket(path) {
        return;
    }
    let _ = std::fs::remove_file(path);
}

/// Whether `path` is still a socket file.
fn is_socket(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            #[cfg(unix)]
            {
                std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type())
            }
            // No socket filesystem exists on this platform, and [`bind`] refuses
            // rather than binding something else, so a bound endpoint here is always
            // the Unix socket created above and the check can never be the thing that
            // prevents cleanup.
            #[cfg(not(unix))]
            {
                let _ = meta;
                true
            }
        }
        // Already gone, which is the outcome wanted. `false` means "nothing to do",
        // not "remove it anyway".
        Err(_) => false,
    }
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

    #[test]
    fn a_vanished_peer_is_disconnected_and_every_other_io_error_is_not() {
        use std::io::{Error, ErrorKind};
        // The conditions that mean "the peer disappeared while we were talking to
        // it", and nothing else. This is the whole classification, so it is worth
        // stating positively: these are Disconnected.
        for kind in [ErrorKind::BrokenPipe, ErrorKind::ConnectionReset] {
            let e = Error::from(kind);
            assert!(
                matches!(peer_io(e), IpcError::Disconnected),
                "{kind:?} is a peer disappearing and must be Disconnected"
            );
        }
        // And these are not. A blanket "write failed, assume the peer left" rule
        // would turn every one of them into silence, which is how a real fault gets
        // reported as a healthy daemon.
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
            ErrorKind::UnexpectedEof,
            ErrorKind::Other,
        ] {
            let e = Error::from(kind);
            let mapped = peer_io(e);
            assert!(
                matches!(mapped, IpcError::Other(_)),
                "{kind:?} is a real fault and must stay an error, got {mapped:?}"
            );
        }
    }

    #[test]
    fn releasing_an_endpoint_never_unlinks_something_that_is_not_a_socket() {
        let dir = std::env::temp_dir().join(format!("orxnud-release-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");

        // A regular file where the socket should be: the one way the release path
        // could destroy something it did not create.
        let file = dir.join("not-a-socket");
        std::fs::write(&file, b"a user document").expect("write");
        release_endpoint(&file);
        assert!(
            file.exists(),
            "release must leave a non-socket at the endpoint path alone"
        );

        // And a directory, which `remove_file` could not remove even if it tried.
        let subdir = dir.join("a-directory");
        std::fs::create_dir_all(&subdir).expect("mkdir");
        release_endpoint(&subdir);
        assert!(subdir.is_dir(), "release must leave a directory alone");

        // A path that is not there is the outcome wanted, not an error.
        release_endpoint(&dir.join("never-existed"));
        assert!(!dir.join("never-existed").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn writing_to_a_vanished_peer_is_a_disconnect_not_a_transport_failure() {
        // The defect, exercised at the layer that fixes it: a real socket, a real
        // peer that disappears, and a real write that used to fail as `Other` and
        // stop the daemon.
        let dir = std::env::temp_dir().join(format!("orxnud-vanish-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("orxnud.sock");

        let listener = bind(&path).await.expect("bind");
        let serving = tokio::spawn(async move {
            let mut s = listener.accept().await.expect("accept");
            // Take the request, so the peer is gone by the time we answer.
            let _ = s.read_line_bounded(4096).await;
            s
        });

        let client = std::os::unix::net::UnixStream::connect(&path).expect("connect");
        drop(client);
        // Let the close reach the server before it writes.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut stream = serving.await.expect("join");
        let err = stream
            .write_line(br#"{"jsonrpc":"2.0","id":1}"#)
            .await
            .expect_err("writing to a vanished peer cannot succeed");
        assert!(
            matches!(err, IpcError::Disconnected),
            "a peer that vanished mid-response is Disconnected, not a broken transport: {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
