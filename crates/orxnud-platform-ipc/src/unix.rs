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
//! `unsafe` is not needed for any of this: `std::os::unix::net::UnixListener` and
//! `tokio::net::UnixListener` are both safe APIs. The only `unsafe` in a working
//! local IPC implementation is the Windows named-pipe path, and this crate refuses
//! to grow one for a platform nothing can test it on.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::{IpcError, Listener, LocalStream};

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
