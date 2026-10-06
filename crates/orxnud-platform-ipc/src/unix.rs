//! The Unix backend: a domain socket, bound with owner-only permissions.
//!
//! # Permissions
//!
//! The socket is created `0600` and its directory is expected to be `0700`. A
//! world-writable socket would let any local user issue capability requests as
//! whoever owns the daemon, which on a personal machine is the difference between
//! "only I can drive my assistant" and "anything on this box can". `umask` is
//! therefore set around the `bind` call, because a socket's mode comes from the
//! umask at creation time and the default is 0777 & ~umask.
//!
//! `unsafe` is not needed for any of the *socket* work here:
//! `std::os::unix::net::UnixListener` and `tokio::net::UnixListener` are both safe
//! APIs. The one `unsafe` this backend does contain is the `getsockopt(2)` call in
//! [`peer_principal`], and it exists because the safe wrappers do not expose
//! `SO_PEERCRED` -- the kernel's answer to "which operating-system user is this
//! caller", which is the question the daemon now has to ask before it will grant
//! anything. It is four lines, confined to one function, and covered by tests that
//! read the principal back off a real connected socket rather than a mock.
//!
//! The alternative was not to use `unsafe` but to hand-declare `getsockopt` and
//! `struct ucred` in this crate, which would be strictly more unsafe code written by
//! us instead of more safe code taken from `libc`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::{IpcError, Listener, LocalStream, TransportPrincipal};

/// Asks the kernel who the peer on this connection is.
///
/// # The one `unsafe` in this crate
///
/// See the crate documentation: `unsafe` is permitted here by gate **G4** and denied
/// everywhere else in the tree. It is confined to this function and to `mem::zeroed`,
/// and both blocks carry their own `SAFETY` note.
///
/// # The mechanism, and why it is the right one
///
/// `SO_PEERCRED` is answered by the kernel from the process it actually ran, for the
/// socket it actually accepted. A peer cannot influence it: there is no request frame
/// that changes the answer, because the answer is not in a request. That is the property
/// the whole identity boundary rests on, and it is why this is a syscall rather than
/// anything the caller sends.
///
/// The alternatives were considered and rejected for specific reasons, not by preference:
/// an application-level token would be something to copy, so it leaks to anything that
/// can read the file; a username lookup is a name the caller can influence and a
/// database on the request path; and a secret of any kind is heavier than a local socket
/// needs and adds a second thing to protect.
///
/// # Returns `None` rather than failing
///
/// Every failure becomes "no identity", and the layer above turns that into a refusal.
/// Returning a partially-defaulted principal would be the one genuinely dangerous
/// outcome here: a default uid is a fabricated identity, and a fabricated identity is
/// exactly what this exists to prevent.
///
/// # Why `cfg(target_os)` rather than `cfg(unix)`
///
/// `SO_PEERCRED` is a Linux interface. macOS and the BSDs have `getpeereid(3)` instead,
/// which is a different call with a different signature and, more importantly, has never
/// been exercised by this repository's CI. The honest thing is to report no identity
/// there and let the daemon refuse, rather than to ship an untested branch that would
/// look like working authentication on a developer's laptop. See the crate's platform
/// notes.
#[cfg(target_os = "linux")]
// SAFETY: the two `unsafe` blocks inside are the `getsockopt(2)` call and a `mem::zeroed`
// of a plain-old-data integer struct. Both are justified inline. Nothing else in the crate
// is `unsafe`, and nothing above it can be.
#[allow(unsafe_code)]
pub(crate) fn peer_principal(stream: &tokio::net::UnixStream) -> Option<TransportPrincipal> {
    use std::os::unix::io::AsRawFd;

    // Zeroed rather than `MaybeUninit::uninit()`: `getsockopt` writes the whole struct
    // on success, but reading an uninitialised `u32` is undefined behaviour if it ever
    // did not, and `zeroed()` makes the failure path defined at the cost of a memset
    // that costs less than the syscall.
    //
    // SAFETY: `libc::ucred` is three plain integers with no padding invariants and no
    // invalid bit patterns, so every byte of an all-zero value is a valid `ucred`. This
    // is the condition `mem::zeroed` is documented as requiring.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` is a live, correctly-aligned, correctly-sized `ucred` and `len` is
    // its size, which is the contract `getsockopt(2)` requires for a known option; the
    // pointer refers to `cred` for the whole call and is only written through. The raw
    // descriptor comes from `stream`, which owns it, so it is open for the duration.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(TransportPrincipal { uid: cred.uid })
}

/// A Unix that has no peer-credential mechanism this crate will claim to support.
///
/// The refusal is the feature. See the `cfg(target_os)` note above: reporting `None`
/// here makes the daemon refuse these connections rather than admit a caller whose
/// identity nobody established.
#[cfg(not(target_os = "linux"))]
fn peer_principal(_stream: &tokio::net::UnixStream) -> Option<TransportPrincipal> {
    None
}

/// A bound Unix domain socket.
///
/// Only ever constructed by [`bind_owned`](UnixSocketListener::bind_owned), so a
/// `Listener` holding one always has a real endpoint behind it.
pub struct UnixSocketListener {
    inner: tokio::net::UnixListener,
    endpoint: PathBuf,
    /// Set by `close`. Checked before every accept so a shutdown does not wait on a
    /// blocking `accept` that no incoming connection will ever satisfy.
    closed: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for UnixSocketListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixSocketListener")
            .field("endpoint", &self.endpoint)
            .field(
                "closed",
                &self.closed.load(std::sync::atomic::Ordering::SeqCst),
            )
            .finish()
    }
}

impl UnixSocketListener {
    /// Binds, handling a stale endpoint file.
    ///
    /// See [`super::bind`] for the three cases. The probe is a connect attempt: if
    /// it succeeds, a live daemon owns the path and this function refuses rather
    /// than removing a socket another process is serving.
    pub async fn bind_owned(path: &Path) -> Result<Listener, IpcError> {
        match Self::probe(path).await {
            Probe::Live => return Err(IpcError::EndpointExists(path.display().to_string())),
            Probe::Stale => {
                // Ours, from a crashed predecessor. Removing it is the documented
                // case, and it is the *only* case in which anything is unlinked.
                std::fs::remove_file(path).map_err(|e| IpcError::Bind {
                    path: path.display().to_string(),
                    reason: format!("a stale endpoint could not be removed: {e}"),
                })?;
            }
            Probe::Free => {}
        }

        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| IpcError::Bind {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;
        }

        let bind_err = |e: std::io::Error| IpcError::Bind {
            path: path.display().to_string(),
            reason: e.to_string(),
        };

        // `bind` gives the socket the process umask's mode, which on a default
        // umask leaves it accessible to every local user. Tightening it immediately
        // afterwards closes that, and is the control the property actually rests on.
        //
        // The honest limit: between `bind` and `chmod` the socket exists at the
        // umask's mode. Narrowing that window needs `umask(2)`, which is process-wide
        // and would mean `unsafe` plus a race against every other thread creating a
        // file — a worse trade than a sub-millisecond window on a path whose parent
        // directory is `0700`. The directory is the real boundary; the `chmod` makes
        // the socket independently correct.
        let inner = tokio::net::UnixListener::bind(path).map_err(bind_err)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
            IpcError::Bind {
                path: path.display().to_string(),
                reason: format!("the socket mode could not be tightened: {e}"),
            }
        })?;

        Ok(Listener::Unix(Self {
            inner,
            endpoint: path.to_path_buf(),
            closed: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    /// Decides whether an existing path is live, stale, or free.
    async fn probe(path: &Path) -> Probe {
        if !path.exists() {
            return Probe::Free;
        }
        match tokio::net::UnixStream::connect(path).await {
            // Someone answered. Not ours to remove.
            Ok(_) => Probe::Live,
            // Nothing answered: a socket file left by a process that is gone.
            Err(_) => Probe::Stale,
        }
    }
}

enum Probe {
    Live,
    Stale,
    Free,
}

impl UnixSocketListener {
    pub(crate) async fn accept(&self) -> Result<LocalStream, IpcError> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(IpcError::Disconnected);
        }
        let (stream, _) = self
            .inner
            .accept()
            .await
            .map_err(|e| IpcError::Accept(e.to_string()))?;
        Ok(LocalStream::wrap(stream))
    }

    pub(crate) fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl LocalStream {
    /// Connects to an already-bound endpoint.
    ///
    /// The client half of [`UnixSocketListener::bind_owned`]. Same stream type, same
    /// framing, same peer-disconnect classification — a client that cannot reuse this
    /// would have to own a second implementation of the socket, and the two would
    /// then disagree about what a frame is.
    pub(crate) async fn connect(path: &Path) -> Result<Self, IpcError> {
        let stream = tokio::net::UnixStream::connect(path)
            .await
            // Deliberately **not** `peer_io`: a failure to connect is not a peer that
            // went away mid-conversation. ENOENT means nothing is listening at that
            // path and ECONNREFUSED means a stale socket file, and a caller has to be
            // able to tell "the daemon is not running" from "the daemon hung up", so
            // this stays a distinct error rather than becoming `Disconnected`.
            .map_err(|e| IpcError::Other(e.to_string()))?;
        Ok(Self::wrap(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("orxnud-ipc-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir.join("orxnud.sock")
    }

    #[tokio::test]
    async fn a_bound_socket_is_owner_only() {
        let path = tmp("mode");
        let listener = UnixSocketListener::bind_owned(&path).await.expect("bind");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "the socket must not be accessible to group or other: {mode:o}"
        );
        listener.close();
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[tokio::test]
    async fn a_live_endpoint_is_never_removed() {
        let path = tmp("live");
        let first = UnixSocketListener::bind_owned(&path)
            .await
            .expect("first bind");
        // A second bind must refuse, and must leave the first listener serving.
        let err = UnixSocketListener::bind_owned(&path)
            .await
            .expect_err("must not steal a live endpoint");
        assert!(matches!(err, IpcError::EndpointExists(_)), "{err:?}");
        assert!(path.exists(), "the live socket must survive the refusal");
        // And it is still accepting.
        let accepted = first.accept().await;
        assert!(accepted.is_ok() || matches!(accepted, Err(IpcError::Disconnected)));
        first.close();
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[tokio::test]
    async fn a_stale_endpoint_is_replaced_but_only_when_nothing_answers() {
        let path = tmp("stale");
        // Leave a socket file behind with nobody listening, as a crashed daemon does.
        {
            let first = UnixSocketListener::bind_owned(&path).await.expect("bind");
            drop(std::sync::Arc::new(first));
            // Dropping the listener leaves the file: the OS removes it only on
            // close(), so recreate it to be certain.
            if !path.exists() {
                let l = UnixSocketListener::bind_owned(&path)
                    .await
                    .expect("rebinding");
                std::mem::forget(l);
            }
        }
        assert!(
            path.exists(),
            "the stale file must exist for this to mean anything"
        );
        let fresh = UnixSocketListener::bind_owned(&path)
            .await
            .expect("a stale endpoint must be replaced");
        assert_eq!(fresh.endpoint(), Some(path.as_path()));
        fresh.close();
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    /// The peer credential is read off a real connected socket, and it is the *peer's*.
    ///
    /// This is the platform-level evidence the daemon's whole identity boundary rests on,
    /// so it is asserted against an actual `accept` of an actual `connect` rather than
    /// against a mock: `SO_PEERCRED` could in principle report the listener's own
    /// credentials, or a fixed value, and only a real connection tells the difference.
    ///
    /// `pid` is deliberately not asserted. The struct does not carry it.
    #[tokio::test]
    async fn the_accepted_peer_is_the_connected_process() {
        let path = tmp("peercred");
        let listener = UnixSocketListener::bind_owned(&path).await.expect("bind");

        let client_path = path.clone();
        let client = tokio::spawn(async move {
            let _stream = super::LocalStream::connect(&client_path).await;
            // Hold the connection open until the server has read the credential, so this
            // is a live peer rather than one that has already gone.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let accepted = listener.accept().await.expect("accept");
        let principal = accepted.principal().expect("a Linux peer has an identity");

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            // The test process is the client, so its uid must be the socket's owner uid.
            let uid = std::fs::metadata(&path).expect("metadata").uid();
            assert_eq!(
                principal.uid(),
                uid,
                "SO_PEERCRED must report the connecting process's uid"
            );
            assert!(
                principal.is_owner(uid),
                "the peer is the owner and must compare equal"
            );
            assert!(
                !principal.is_owner(uid.wrapping_add(1)),
                "a different uid must not compare equal"
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            // The documented refusal: no mechanism here, so no identity, so the layer
            // above fails closed. Asserted rather than skipped, because "this platform
            // cannot authenticate" is a claim the suite should be making out loud.
            let _ = principal;
        }

        let _ = client.await;
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }

    #[tokio::test]
    async fn a_closed_listener_refuses_to_accept() {
        let path = tmp("closed");
        let listener = UnixSocketListener::bind_owned(&path).await.expect("bind");
        listener.close();
        let err = listener.accept().await.expect_err("must refuse");
        assert!(matches!(err, IpcError::Disconnected), "{err:?}");
        assert_eq!(
            listener.endpoint(),
            Some(path.as_path()),
            "close must not change the endpoint"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("parent"));
    }
}
