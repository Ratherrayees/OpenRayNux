//! The provider's one outbound connection: plain TCP, or TLS over it.
//!
//! # Why the transport is separate from the provider
//!
//! `http_provider` speaks HTTP. This module moves bytes. Nothing above here knows whether
//! a connection was encrypted, and that is the point: adding TLS changed no line of the
//! request builder, the response reader or the provider error taxonomy. A future change to
//! either side cannot silently assume the other's behaviour.
//!
//! # Why there is no downgrade
//!
//! There are exactly two ways to end up here, and they are chosen before the socket opens:
//!
//! * `http://` — plaintext, refused unless the caller has explicitly allowed it, which
//!   only a local test server does;
//! * `https://` — TLS, always, with certificate chain *and* hostname verified.
//!
//! There is no third path where an `https://` URL is fetched over plaintext, no fallback
//! from TLS to plain when a handshake fails, and no redirect handling at all. Each of those
//! would be a way for a credential to leave the process in the clear while every log, the
//! audit record and the operator's own configuration all said it was encrypted. Not
//! following redirects is the load-bearing part: an `https://` endpoint that answers
//! `302 http://…` would otherwise be a downgrade delivered by the far side rather than by
//! us, which is the same failure with the blame moved.
//!
//! A failure to establish TLS is a refusal. It never becomes "try without encryption".

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// One connection, readable and writable, whatever is underneath.
///
/// A trait object cannot carry two non-auto traits, so the union needs a name of its own.
/// Declared here rather than exported: nothing above this module should be able to name
/// the plaintext/TLS split at all.
pub trait ByteStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> ByteStream for T {}

use crate::proposer::{ProviderError, StatusKind};

/// How a base URL should be connected to.
///
/// Resolved from the configured scheme with no defaults and no inference: a URL that does
/// not say which it wants is not a URL this will act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scheme {
    /// Plaintext HTTP. Only for a loopback test server, and refused unless explicitly
    /// permitted.
    PlainHttp,
    /// HTTP over TLS, with chain and hostname verification.
    Tls,
}

impl Scheme {
    /// The scheme word as written in a URL.
    pub fn parse(url: &str) -> Result<Self, ProviderError> {
        let trimmed = url.trim();
        if trimmed.starts_with("https://") {
            Ok(Self::Tls)
        } else if trimmed.starts_with("http://") {
            Ok(Self::PlainHttp)
        } else {
            Err(ProviderError::TransportUnsupported(if trimmed.is_empty() {
                "an empty scheme".to_owned()
            } else {
                trimmed
                    .split("://")
                    .next()
                    .unwrap_or("the configured scheme")
                    .to_owned()
            }))
        }
    }

    /// Whether this scheme may carry a credential.
    ///
    /// Only TLS. A plaintext connection is allowed to exist for a local test server, but it
    /// is never allowed to receive an `Authorization` header, so a credential cannot be
    /// tested into existence on a loopback socket and then carried to a real host by
    /// changing one character of the configuration.
    #[must_use]
    pub const fn carries_credentials(self) -> bool {
        matches!(self, Self::Tls)
    }
}

/// The host, port and path prefix a base URL addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `host` or `host:port`.
    pub authority: String,
    /// The path prefix, `""` or `/v1`.
    pub prefix: String,
    /// Whether the connection is encrypted.
    pub scheme: Scheme,
}

impl Target {
    /// Parses a base URL.
    ///
    /// # Errors
    ///
    /// [`ProviderError::NotConfigured`] for an empty base, model or authority, and
    /// [`ProviderError::TransportUnsupported`] for any scheme but `http` and `https`.
    pub fn parse(base_url: &str, model: &str) -> Result<Self, ProviderError> {
        let base = base_url.trim();
        if base.is_empty() || model.trim().is_empty() {
            return Err(ProviderError::NotConfigured);
        }
        let scheme = Scheme::parse(base)?;
        let rest = base.split_once("://").map_or("", |(_, r)| r);
        let (authority, prefix) = match rest.find('/') {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        if authority.is_empty() {
            return Err(ProviderError::NotConfigured);
        }
        Ok(Self {
            authority: authority.to_owned(),
            prefix: prefix.to_owned(),
            scheme,
        })
    }

    /// The `host:port` to connect to, defaulting the port from the scheme.
    ///
    /// A default is a protocol fact rather than a configuration guess: 443 for TLS and 80
    /// for plaintext are what those schemes *mean*.
    #[must_use]
    pub fn socket_authority(&self) -> String {
        if self.authority.contains(':') {
            self.authority.clone()
        } else {
            let port = match self.scheme {
                Scheme::Tls => 443,
                Scheme::PlainHttp => 80,
            };
            format!("{}:{}", self.authority, port)
        }
    }

    /// The name TLS verifies the certificate against.
    ///
    /// The host without the port. Handing `tokio-rustls` the authority instead would make
    /// it verify `example.test:443` as a name, which no certificate carries, and every
    /// connection would fail for a reason that has nothing to do with trust.
    #[must_use]
    pub fn tls_server_name(&self) -> String {
        self.authority
            .rsplit_once(':')
            .map_or_else(|| self.authority.clone(), |(host, _)| host.to_owned())
    }
}

/// Where the trusted roots come from.
///
/// [`Self::System`] is the only choice available to a running daemon. The pinned variant
/// exists for a test that must trust a certificate it generated itself, and it *adds* an
/// anchor rather than removing verification — a pinned root makes a connection more
/// trusted, never less, so it cannot become a way to weaken certificate checking.
#[derive(Clone)]
pub enum Roots {
    /// The host's trust store, read at connection time.
    System,
    /// These anchors, plus nothing else.
    Pinned(Vec<rustls_pki_types::CertificateDer<'static>>),
}

impl std::fmt::Debug for Roots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => f.write_str("System"),
            Self::Pinned(v) => write!(f, "Pinned({} anchors)", v.len()),
        }
    }
}

/// An established connection, encrypted or not.
#[derive(Debug)]
pub enum Connection {
    /// Plaintext.
    Plain(TcpStream),
    /// TLS, with the certificate chain and hostname already verified.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl Connection {
    /// Reads and writes the same connection either way.
    ///
    /// One method rather than exposing both variants, so no caller above this module can
    /// branch on whether the connection happened to be encrypted — the capability to make
    /// that decision does not exist above here.
    ///
    /// Boxed rather than an `impl Trait` in return position because the two variants are
    /// different concrete types; the box is the only place that union has to exist, and it
    /// is here rather than in the caller.
    pub fn as_stream(&mut self) -> Box<dyn ByteStream + '_> {
        match self {
            Self::Plain(s) => Box::new(s),
            Self::Tls(s) => Box::new(s.as_mut()),
        }
    }
}

/// A lazily built TLS configuration, so a provider that never connects never loads roots.
#[derive(Clone, Debug)]
pub struct TlsConfig {
    roots: Arc<Roots>,
}

impl TlsConfig {
    /// Trust the host's roots.
    #[must_use]
    pub fn system() -> Self {
        Self {
            roots: Arc::new(Roots::System),
        }
    }

    /// Trust exactly these anchors. For a test server with a generated certificate.
    #[must_use]
    pub fn pinned(anchors: Vec<rustls_pki_types::CertificateDer<'static>>) -> Self {
        Self {
            roots: Arc::new(Roots::Pinned(anchors)),
        }
    }

    /// The client configuration, or a refusal naming why roots could not be loaded.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Tls`] when the host trust store cannot be read or holds nothing
    /// usable. Refused rather than defaulted to "trust anything": a daemon that cannot
    /// establish who it is talking to has no business sending a credential.
    fn client_config(&self) -> Result<rustls::ClientConfig, ProviderError> {
        let mut store = rustls::RootCertStore::empty();
        match &*self.roots {
            Roots::Pinned(anchors) => {
                for anchor in anchors {
                    store.add(anchor.clone()).map_err(|e| {
                        ProviderError::Tls(format!("a pinned root is unusable: {e}"))
                    })?;
                }
            }
            Roots::System => {
                // `load_native_certs` reports per-certificate problems in its result
                // rather than as an error, so a partly-unreadable store is not fatal on
                // its own; only an empty one is.
                let loaded = rustls_native_certs::load_native_certs();
                let (added, ignored) = (loaded.certs.len(), loaded.errors.len());
                for cert in loaded.certs {
                    // A certificate this store does not recognise is skipped rather than
                    // fatal: a host trust store routinely contains entries a given rustls
                    // build cannot parse, and refusing to start would make one odd entry
                    // disable the feature entirely.
                    let _ = store.add(cert);
                }
                if added == 0 {
                    return Err(ProviderError::Tls(format!(
                        "the host trust store held no usable certificate ({ignored} ignored)"
                    )));
                }
            }
        }
        Ok(rustls::ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth())
    }

    /// Opens a connection, verifying the certificate if the scheme says to.
    ///
    /// # Errors
    ///
    /// [`ProviderError::Unreachable`] if the socket cannot be opened, and
    /// [`ProviderError::Tls`] if a TLS handshake, chain check or hostname check fails. The
    /// last is the important one: it is the error that must never be answered by trying
    /// again without encryption.
    pub async fn connect(
        &self,
        target: &Target,
        allow_plaintext: bool,
    ) -> Result<Connection, ProviderError> {
        let address = target.socket_authority();
        let tcp = TcpStream::connect(&address)
            .await
            .map_err(|e| ProviderError::Unreachable(format!("connect to {address} failed: {e}")))?;

        match target.scheme {
            Scheme::PlainHttp => {
                if !allow_plaintext {
                    return Err(ProviderError::PlaintextRefused(address));
                }
                Ok(Connection::Plain(tcp))
            }
            Scheme::Tls => {
                let config = self.client_config()?;
                let server_name = rustls_pki_types::ServerName::try_from(target.tls_server_name())
                    .map_err(|_| {
                        ProviderError::Tls(format!(
                            "{:?} is not a name a certificate can carry",
                            target.authority
                        ))
                    })?
                    .to_owned();
                let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
                let stream = connector.connect(server_name, tcp).await.map_err(|e| {
                    // Every TLS failure lands here and none of them is retried, downgraded
                    // or re-prompted. `rustls`'s own Display names the cause — an
                    // untrusted issuer, an expired certificate, a name mismatch — which is
                    // the difference between an operator fixing a clock and an operator
                    // guessing.
                    ProviderError::Tls(format!("the TLS handshake failed: {e}"))
                })?;
                Ok(Connection::Tls(Box::new(stream)))
            }
        }
    }
}

/// Whether a credential is usable, and if not, which of two distinct problems it is.
///
/// Separate from an error type because it is a *state*, not a failure: the caller reports
/// it as whatever the situation deserves. Nothing stored and no usable store both mean "no
/// credential", and they deserve different words — one is a setup step, the other is a
/// broken host — so they are not one state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialState {
    /// A non-empty credential is present.
    Ready,
    /// Nothing usable is stored.
    Absent(String),
    /// The store itself could not be read.
    StoreUnavailable(String),
}

/// Whether a reason names a transport failure rather than an HTTP or proposal outcome.
///
/// Not `const`: matching on a `&str` is not const-stable, and forcing it would mean
/// comparing bytes by hand.
#[must_use]
pub fn is_transport_reason(reason: &str) -> bool {
    matches!(
        reason,
        "provider-unreachable"
            | "provider-timeout"
            | "provider-tls-failed"
            | "provider-plaintext-refused"
            | "provider-transport-unsupported"
    )
}

/// Re-exported so the provider module can name a status kind without importing the
/// taxonomy twice.
pub use crate::proposer::StatusKind as HttpStatusKind;

const _: fn() = || {
    // A compile-time reminder that `StatusKind` belongs to HTTP, not to this module.
    let _ = StatusKind::Other;
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_two_schemes_are_accepted() {
        assert_eq!(Scheme::parse("https://h/v1").expect("https"), Scheme::Tls);
        assert_eq!(
            Scheme::parse("http://h/v1").expect("http"),
            Scheme::PlainHttp
        );
        for bad in ["ftp://h", "h/v1", "", "  ", "HTTPS://h"] {
            let err = Scheme::parse(bad).expect_err(bad);
            assert_eq!(err.reason(), "provider-transport-unsupported", "{bad:?}");
        }
    }

    #[test]
    fn an_uppercase_scheme_is_refused_rather_than_normalised() {
        // Normalising here would mean one place that lower-cases a URL and another that
        // does not, and the difference shows up as a connection nobody can explain.
        assert!(Scheme::parse("HTTPS://h").is_err());
    }

    #[test]
    fn only_tls_may_carry_a_credential() {
        assert!(Scheme::Tls.carries_credentials());
        assert!(!Scheme::PlainHttp.carries_credentials());
    }

    #[test]
    fn a_target_splits_into_authority_and_prefix() {
        for (url, authority, prefix) in [
            ("https://api.test/v1", "api.test", "/v1"),
            ("https://api.test", "api.test", ""),
            (
                "https://api.test:8443/openai/v1",
                "api.test:8443",
                "/openai/v1",
            ),
        ] {
            let t = Target::parse(url, "m").expect(url);
            assert_eq!(t.authority, authority, "{url}");
            assert_eq!(t.prefix, prefix, "{url}");
        }
    }

    #[test]
    fn the_default_port_comes_from_the_scheme_and_is_not_a_guess() {
        assert_eq!(
            Target::parse("https://api.test", "m")
                .expect("t")
                .socket_authority(),
            "api.test:443"
        );
        assert_eq!(
            Target::parse("http://api.test", "m")
                .expect("t")
                .socket_authority(),
            "api.test:80"
        );
        assert_eq!(
            Target::parse("https://api.test:8443", "m")
                .expect("t")
                .socket_authority(),
            "api.test:8443"
        );
    }

    #[test]
    fn the_tls_name_excludes_the_port() {
        // Verifying a certificate against "api.test:443" would fail for every real
        // endpoint, which is a confusing way to learn that a port is not a name.
        assert_eq!(
            Target::parse("https://api.test:8443/v1", "m")
                .expect("t")
                .tls_server_name(),
            "api.test"
        );
        assert_eq!(
            Target::parse("https://api.test", "m")
                .expect("t")
                .tls_server_name(),
            "api.test"
        );
    }

    #[test]
    fn an_incomplete_target_is_not_configured() {
        for (url, model) in [("", "m"), ("https://h", ""), ("https:///v1", "m")] {
            assert_eq!(
                Target::parse(url, model).expect_err("incomplete").reason(),
                "provider-not-configured",
                "{url:?} {model:?}"
            );
        }
    }

    #[test]
    fn plaintext_is_refused_unless_explicitly_allowed() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        rt.block_on(async {
            let config = TlsConfig::system();
            // Refused *after* connecting, so this reports the refusal rather than a
            // connection error to a closed port — the distinction is the point of the test.
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a port");
            let address = listener.local_addr().expect("an address").to_string();
            let target = Target::parse(&format!("http://{address}/v1"), "m").expect("t");
            let err = config.connect(&target, false).await.expect_err("refused");
            assert_eq!(err.reason(), "provider-plaintext-refused");
            let _ = target;
        });
    }

    #[test]
    fn transport_reasons_are_distinguishable_from_http_reasons() {
        for reason in [
            "provider-unreachable",
            "provider-timeout",
            "provider-tls-failed",
            "provider-plaintext-refused",
            "provider-transport-unsupported",
        ] {
            assert!(is_transport_reason(reason), "{reason}");
        }
        for reason in [
            "provider-rate-limited",
            "provider-server-error",
            "provider-response-malformed",
            "proposal-schema-mismatch",
            "proposal-capability-unknown",
        ] {
            assert!(
                !is_transport_reason(reason),
                "{reason} is not a transport reason"
            );
        }
    }
}
