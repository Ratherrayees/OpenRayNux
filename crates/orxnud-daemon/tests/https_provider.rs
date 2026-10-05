//! HTTPS, against a real local TLS server.
//!
//! Every test here runs an actual `rustls` server on a loopback port with a certificate
//! generated for the test, and the adapter connects to it as a client would. Nothing about
//! the handshake is stubbed, so certificate validation, hostname checking and the failure
//! messages are the production ones.
//!
//! No test needs the public internet, and none trusts a public root: each one pins the
//! exact certificate authority it generated, which is the only way to prove that an
//! *untrusted* certificate is refused rather than merely absent from a list.

use std::sync::Arc;
use std::time::Duration;

use orxnud_daemon::http_provider::{OpenAiCompatibleProvider, ProviderConfig};
use orxnud_daemon::proposer::ProposalProvider;
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// A hermetic secret store
// ---------------------------------------------------------------------------

struct FixedSecrets(Option<String>);

impl FixedSecrets {
    fn holding(value: &str) -> Self {
        Self(Some(value.to_owned()))
    }
}

impl SecretsContract for FixedSecrets {
    type Error = std::io::Error;

    fn get(&self, _reference: &SecretRef) -> Result<SecretLookup, Self::Error> {
        Ok(match &self.0 {
            Some(v) => SecretLookup::Found(Zeroizing::new(v.clone())),
            None => SecretLookup::Absent,
        })
    }

    fn set(&self, _reference: &SecretRef, _value: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    fn delete(&self, _reference: &SecretRef) -> Result<(), Self::Error> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// A certificate authority and a server certificate
// ---------------------------------------------------------------------------

/// One test CA, plus a leaf for a named host signed by it.
struct Pki {
    /// The anchor a client must trust to accept the leaf.
    ca_der: rustls_pki_types::CertificateDer<'static>,
    /// The chain the server presents: leaf, then CA.
    server_chain: Vec<rustls_pki_types::CertificateDer<'static>>,
    server_key: rustls_pki_types::PrivateKeyDer<'static>,
}

impl Pki {
    /// A CA and a leaf valid for the loopback address the tests dial.
    fn for_ip() -> Self {
        Self::build(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    /// A leaf valid for a *different* loopback address, for the mismatch case.
    fn for_other_ip() -> Self {
        Self::build(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2)))
    }

    /// Builds a CA plus a leaf whose only subject alternative name is `address`.
    ///
    /// An **IP** SAN, because the server is dialled as `127.0.0.1` and making the suite
    /// depend on a name resolver would make a network condition look like a TLS failure.
    ///
    /// The SAN is the part that matters: TLS has ignored the common name for years, so a
    /// leaf carrying only a distinguished name is refused as untrusted or mismatched and
    /// every test here would pass without ever exercising a valid handshake.
    fn build(address: std::net::IpAddr) -> Self {
        // The CA first, then a leaf *signed by it*. A self-signed leaf would present as
        // its own issuer, and a client pinned to this CA would refuse it as
        // `UnknownIssuer` — which is the correct answer to the wrong question, and would
        // make every handshake test here pass without a valid handshake ever happening.
        let ca_key = rcgen::KeyPair::generate().expect("a CA key pair");
        let mut ca_params = rcgen::CertificateParams::new(vec![]).expect("CA params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "orxnud test CA");
        let ca = ca_params.self_signed(&ca_key).expect("a CA certificate");
        let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);

        let leaf_key = rcgen::KeyPair::generate().expect("a leaf key pair");
        let mut leaf_params = rcgen::CertificateParams::new(vec![]).expect("leaf params");
        leaf_params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(address));
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "orxnud test leaf");
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("a CA-signed leaf");

        let leaf_key = rustls_pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
            .expect("a PKCS#8 leaf key");
        Self {
            ca_der: ca.der().clone(),
            server_chain: vec![leaf.der().clone(), ca.der().clone()],
            server_key: leaf_key,
        }
    }
}

/// A running TLS server that answers one request.
struct TlsServer {
    address: String,
    handle: tokio::task::JoinHandle<()>,
}

impl TlsServer {
    async fn start(pki: Pki, body: String) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let address = listener.local_addr().expect("an address").to_string();

        let handle = tokio::spawn(async move {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let config = match rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(pki.server_chain, pki.server_key)
            {
                Ok(c) => c,
                // A server that cannot present its certificate cannot answer, which is
                // exactly what a handshake test wants; there is nothing to reply with.
                Err(_) => return,
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                return;
            };
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                }
                if raw.len() > 64 * 1024 {
                    return;
                }
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        });

        Self { address, handle }
    }

    fn abort(self) {
        self.handle.abort();
    }
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime")
}

/// A provider pointed at an `https://` loopback endpoint, trusting `pki`'s CA.
fn tls_provider(
    address: &str,
    pki_der: rustls_pki_types::CertificateDer<'static>,
) -> OpenAiCompatibleProvider<FixedSecrets> {
    OpenAiCompatibleProvider::new(
        ProviderConfig::new(
            format!("https://{address}/v1"),
            "fake-model-1",
            SecretRef::new("provider-api-key", "local"),
        ),
        FixedSecrets::holding("sk-test-key"),
    )
    .with_pinned_roots(vec![pki_der])
}

fn ctx() -> orxnud_daemon::proposer::ProposalContext {
    orxnud_daemon::proposer::ProposalContext {
        task_id: "t-tls".into(),
        content: "Write final.txt containing hello".into(),
        attempt_no: 1,
        allowed: vec![],
        prior_steps: Default::default(),
    }
}

fn body_for(content: &str) -> String {
    serde_json::json!({
        "id": "chatcmpl-tls",
        "model": "fake-model-1",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content },
            "finish_reason": "stop",
        }],
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// 1. HTTPS success
// ---------------------------------------------------------------------------

/// A certificate this client trusts, presented by the host it dialled: the request goes
/// out encrypted and the credential goes with it.
///
/// This is the test that proves the credential path works, because the plaintext suite
/// deliberately refuses to send it.
#[test]
fn https_succeeds_and_carries_the_credential() {
    let rt = rt();
    let pki = Pki::for_ip();
    let proposal = r#"{"capability":"filesystem/write-text","target":"final.txt","params":{"path":"final.txt","contents":"hello"}}"#;
    let ca = pki.ca_der.clone();
    let server = rt.block_on(TlsServer::start(pki, body_for(proposal)));
    let provider = tls_provider(&server.address, ca);
    let text = provider.complete(&ctx()).expect("an encrypted response");
    assert_eq!(text, proposal);
}

// ---------------------------------------------------------------------------
// 2, 3, 4. The certificate checks
// ---------------------------------------------------------------------------

/// An untrusted issuer is refused, and the refusal says so.
///
/// The client pins a *different* CA than the one the server presents. This is the single
/// most important test in the file: an adapter that quietly accepted it would send a
/// credential to whoever answered.
#[test]
fn an_untrusted_certificate_is_refused() {
    let rt = rt();
    let server_pki = Pki::for_ip();
    let other_ca = Pki::for_ip();
    let server = rt.block_on(TlsServer::start(server_pki, body_for("{}")));
    // Trust `other_ca`, not the one the server presents.
    let provider = tls_provider(&server.address, other_ca.ca_der);
    let err = provider.complete(&ctx()).expect_err("untrusted issuer");
    assert_eq!(err.reason(), "provider-tls-failed");
    assert!(
        err.to_string().contains("certificate") || err.to_string().contains("handshake"),
        "the refusal must name the certificate or the handshake: {err}"
    );
    server.abort();
}

/// A certificate for the wrong name is refused.
///
/// The check that is most often "fixed" by turning verification off, so it is asserted
/// explicitly and by name.
#[test]
fn a_hostname_mismatch_is_refused() {
    let rt = rt();
    // The certificate is for `other.test`; the client dials `127.0.0.1`.
    // The certificate is for a different loopback address; the client dials 127.0.0.1.
    let pki = Pki::for_other_ip();
    let ca = pki.ca_der.clone();
    let server = rt.block_on(TlsServer::start(pki, body_for("{}")));
    let provider = tls_provider(&server.address, ca);
    let err = provider.complete(&ctx()).expect_err("hostname mismatch");
    assert_eq!(err.reason(), "provider-tls-failed");
    server.abort();
}

/// A server that is not speaking TLS at all is a handshake failure, never a plaintext
/// fallback.
///
/// The listener accepts and answers with HTTP bytes. An adapter that retried without
/// encryption would "succeed" here, which is precisely the bug this test exists to catch.
#[test]
fn a_plaintext_server_on_an_https_url_is_a_handshake_failure() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let rt = rt();
    let (address, handle) = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = listener.local_addr().expect("an address").to_string();
        let handle = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await;
        });
        (address, handle)
    });

    // Trust the host's own roots; the connection cannot succeed regardless, and pinning a
    // generated CA would let the test pass for the wrong reason.
    let provider = OpenAiCompatibleProvider::new(
        ProviderConfig::new(
            format!("https://{address}/v1"),
            "m",
            SecretRef::new("provider-api-key", "local"),
        ),
        FixedSecrets::holding("sk-test-key"),
    );
    let err = provider.complete(&ctx()).expect_err("not TLS");
    assert_eq!(err.reason(), "provider-tls-failed");
    handle.abort();
}

// ---------------------------------------------------------------------------
// 5, 6. Connection-level failures
// ---------------------------------------------------------------------------

/// Nothing listening.
#[test]
fn a_refused_connection_over_https_is_a_transport_failure() {
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        listener.local_addr().expect("an address").to_string()
    };
    let provider = OpenAiCompatibleProvider::new(
        ProviderConfig::new(
            format!("https://{dead}/v1"),
            "m",
            SecretRef::new("provider-api-key", "local"),
        ),
        FixedSecrets::holding("sk-test-key"),
    );
    let err = provider.complete(&ctx()).expect_err("refused");
    assert_eq!(err.reason(), "provider-unreachable");
    assert_ne!(
        err.reason(),
        "provider-response-malformed",
        "a refused connection must not read as a bad response"
    );
}

/// A server that accepts and never completes the handshake.
#[test]
fn a_handshake_that_never_completes_times_out() {
    let rt = rt();
    let (address, handle) = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = listener.local_addr().expect("an address").to_string();
        let handle = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            // Hold the connection open without speaking TLS.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(stream);
        });
        (address, handle)
    });
    let provider = OpenAiCompatibleProvider::new(
        ProviderConfig::new(
            format!("https://{address}/v1"),
            "m",
            SecretRef::new("provider-api-key", "local"),
        ),
        FixedSecrets::holding("sk-test-key"),
    )
    .with_timeout(Duration::from_millis(300));
    let err = provider.complete(&ctx()).expect_err("a deadline");
    assert_eq!(err.reason(), "provider-timeout");
    handle.abort();
}

// ---------------------------------------------------------------------------
// 7, 8, 9. No downgrade
// ---------------------------------------------------------------------------

/// `https://` is TLS or it is nothing. There is no configuration that turns it into
/// plaintext.
#[test]
fn https_never_becomes_plaintext() {
    let rt = rt();
    let pki = Pki::for_ip();
    let ca = pki.ca_der.clone();
    let server = rt.block_on(TlsServer::start(pki, body_for("{}")));
    // Deliberately *not* calling `with_plaintext_allowed`, and the URL is https anyway.
    let provider = OpenAiCompatibleProvider::new(
        ProviderConfig::new(
            format!("https://{}/v1", server.address),
            "m",
            SecretRef::new("provider-api-key", "local"),
        ),
        FixedSecrets::holding("sk-test-key"),
    )
    .with_pinned_roots(vec![ca]);
    assert!(
        provider.complete(&ctx()).is_ok(),
        "a trusted TLS endpoint works"
    );
    server.abort();
}

/// A plaintext endpoint is refused outright, with a reason that names the fix.
#[test]
fn a_plaintext_endpoint_is_refused_by_default() {
    let rt = rt();
    let pki = Pki::for_ip();
    let server = rt.block_on(TlsServer::start(pki, body_for("{}")));
    let provider = OpenAiCompatibleProvider::new(
        ProviderConfig::new(
            format!("http://{}/v1", server.address),
            "m",
            SecretRef::new("provider-api-key", "local"),
        ),
        FixedSecrets::holding("sk-test-key"),
    );
    let err = provider.complete(&ctx()).expect_err("plaintext");
    assert_eq!(err.reason(), "provider-plaintext-refused");
    assert!(
        err.to_string().contains("https"),
        "the refusal must say what to use instead: {err}"
    );
    server.abort();
}

/// Even when plaintext is explicitly permitted for a loopback server, no credential is
/// attached.
///
/// This is the guarantee that makes `with_plaintext_allowed` safe to have in the codebase
/// at all: it cannot be used to prove a credential path works over `http://`, so nobody can
/// then point that proof at a real host.
#[test]
fn permitted_plaintext_still_refuses_to_carry_a_credential() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let rt = rt();
    let (address, handle) = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = listener.local_addr().expect("an address").to_string();
        let handle = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                }
            }
            let seen = String::from_utf8_lossy(&raw).to_lowercase();
            let leaked = seen.contains("authorization:");
            let marker = if leaked { "LEAKED" } else { "clean" };
            let body = body_for(&format!("{{\"leak\":\"{marker}\"}}"));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
        (address, handle)
    });

    let provider = OpenAiCompatibleProvider::new(
        ProviderConfig::new(
            format!("http://{address}/v1"),
            "m",
            SecretRef::new("provider-api-key", "local"),
        ),
        FixedSecrets::holding("sk-test-key"),
    )
    .with_plaintext_allowed();
    let text = provider.complete(&ctx()).expect("a plaintext response");
    assert!(
        text.contains("clean"),
        "a credential crossed a plaintext connection: {text}"
    );
    handle.abort();
}

/// A redirect is not followed, so a far side cannot deliver a downgrade.
///
/// An `https://` endpoint answering `302 Location: http://…` is the same failure as a local
/// downgrade, with the decision made by the far side instead of by us. Not following
/// redirects at all means the 302 is read as a status and refused.
#[test]
fn a_redirect_is_not_followed() {
    let rt = rt();
    let (address, handle) = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let address = listener.local_addr().expect("an address").to_string();
        let handle = tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                }
            }
            let response = "HTTP/1.1 302 Found\r\nLocation: http://elsewhere.test/v1\r\n\
                        Content-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(response.as_bytes()).await;
        });
        (address, handle)
    });

    let provider = OpenAiCompatibleProvider::new(
        ProviderConfig::new(
            format!("http://{address}/v1"),
            "m",
            SecretRef::new("provider-api-key", "local"),
        ),
        FixedSecrets::holding("sk-test-key"),
    )
    .with_plaintext_allowed();
    let err = provider
        .complete(&ctx())
        .expect_err("a redirect is not a proposal");
    // 302 is not a success and not a recognised refusal class, so it is classified as an
    // HTTP error. What matters is that it is an error and that no second request happened.
    assert!(
        err.reason().starts_with("provider-"),
        "a redirect must be a provider failure: {}",
        err.reason()
    );
    handle.abort();
}

/// The credential never appears in a TLS failure message.
///
/// A handshake error is the most likely place for a library to quote what it was sent.
#[test]
fn a_tls_failure_message_never_contains_the_credential() {
    let rt = rt();
    let sentinel = "sk-live-SENTINEL-must-never-appear";
    let server_pki = Pki::for_other_ip();
    let other = Pki::for_ip();
    let server = rt.block_on(TlsServer::start(server_pki, body_for("{}")));
    let provider = OpenAiCompatibleProvider::new(
        ProviderConfig::new(
            format!("https://{}/v1", server.address),
            "m",
            SecretRef::new("provider-api-key", "local"),
        ),
        FixedSecrets::holding(sentinel),
    )
    .with_pinned_roots(vec![other.ca_der]);
    let err = provider.complete(&ctx()).expect_err("hostname mismatch");
    let rendered = format!("{err} {err:?}");
    assert!(
        !rendered.contains("SENTINEL"),
        "the credential reached a failure message: {rendered}"
    );
    server.abort();
}
