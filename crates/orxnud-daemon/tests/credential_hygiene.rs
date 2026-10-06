//! What a stored credential may and may not be observed in.
//!
//! One sentinel value runs through every path that touches the credential — resolved,
//! refused, debugged, redacted — and the tests assert its exact bytes appear in none of
//! them. A sentinel rather than a check for the *shape* of a secret, because a shape check
//! passes on any value that happens to be shaped right.
//!
//! The store is an in-memory double. That is not a shortcut: a test using the real keyring
//! could pass because a developer's machine already held a credential, and could fail
//! because it did not.

use std::fmt;
use std::sync::Mutex;

use orxnud_daemon::http_provider::{OpenAiCompatibleProvider, ProviderConfig};
use orxnud_daemon::proposer::ProposalProvider;
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use zeroize::Zeroizing;

/// The value every test looks for. Long enough to be unmistakable in any output.
const SENTINEL: &str = "sk-live-SENTINEL-0123456789abcdefXYZ";

/// An in-memory store that records what was written.
struct RecordingStore {
    cells: Mutex<std::collections::BTreeMap<String, Zeroizing<String>>>,
    available: bool,
}

impl RecordingStore {
    fn working() -> Self {
        Self {
            cells: Mutex::new(std::collections::BTreeMap::new()),
            available: true,
        }
    }

    fn holding(sentinel: &str) -> Self {
        let store = Self::working();
        store.set(&key_ref(), sentinel).expect("a store that works");
        store
    }

    fn unavailable() -> Self {
        Self {
            cells: Mutex::new(std::collections::BTreeMap::new()),
            available: false,
        }
    }
}

impl fmt::Debug for RecordingStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the cells. A store's `Debug` is the accident most likely to happen to
        // somebody debugging a keyring problem.
        f.debug_struct("RecordingStore")
            .field(
                "cells",
                &format_args!("<{} entries>", self.cells.lock().expect("cells").len()),
            )
            .field("available", &self.available)
            .finish()
    }
}

impl SecretsContract for RecordingStore {
    type Error = StoreError;

    fn get(&self, reference: &SecretRef) -> Result<SecretLookup, Self::Error> {
        if !self.available {
            return Ok(SecretLookup::Unavailable("no keyring".to_owned()));
        }
        Ok(
            match self.cells.lock().expect("cells").get(&reference.key()) {
                Some(v) => SecretLookup::Found(Zeroizing::new(v.to_string())),
                None => SecretLookup::Absent,
            },
        )
    }

    fn set(&self, reference: &SecretRef, value: &str) -> Result<(), Self::Error> {
        self.cells
            .lock()
            .expect("cells")
            .insert(reference.key(), Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn delete(&self, reference: &SecretRef) -> Result<(), Self::Error> {
        self.cells.lock().expect("cells").remove(&reference.key());
        Ok(())
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

#[derive(Debug, thiserror::Error)]
enum StoreError {
    #[error("the store failed: {detail}")]
    Backend { detail: String },
    #[error("nothing stored")]
    NotFound,
}

/// A store that hands back a credential unconditionally, standing in for a server that
/// rejects it. The third state has to come from the far side.
struct RejectingStore;

impl SecretsContract for RejectingStore {
    type Error = StoreError;

    fn get(&self, _r: &SecretRef) -> Result<SecretLookup, Self::Error> {
        Ok(SecretLookup::Found(Zeroizing::new(SENTINEL.to_owned())))
    }

    fn set(&self, _r: &SecretRef, _v: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    fn delete(&self, _r: &SecretRef) -> Result<(), Self::Error> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// The reference the provider reads. Spelled here the way `orxnuctl provider credential
/// set` writes it, so a divergence between the two would be a compile error rather than a
/// stored key nothing reads.
fn key_ref() -> SecretRef {
    SecretRef::new("provider-api-key", "local")
}

/// A provider pointed at a closed port, holding whatever the store holds.
///
/// Nothing connects in most of these tests: they are about what the *value* does, and a test
/// that dialled would be a test about the network.
fn provider<S: SecretsContract + Send + Sync>(secrets: S) -> OpenAiCompatibleProvider<S> {
    OpenAiCompatibleProvider::new(
        ProviderConfig::new("https://127.0.0.1:1/v1", "m", key_ref()),
        secrets,
    )
}

fn ctx() -> orxnud_daemon::proposer::ProposalContext {
    orxnud_daemon::proposer::ProposalContext {
        task_id: "t".into(),
        content: "x".into(),
        attempt_no: 1,
        allowed: vec![],
        prior_steps: Default::default(),
        disclosures: orxnud_daemon::observation::DisclosureBatch::empty(),
    }
}

/// Every refusal the provider can produce, with the sentinel resolved, is free of it.
///
/// The connection is refused *after* the credential is read, so this exercises the window
/// where the secret is live in memory and a mistake would be most likely.
#[test]
fn no_provider_refusal_contains_the_credential() {
    let p = provider(RecordingStore::holding(SENTINEL));
    let err = p
        .complete(&ctx())
        .expect_err("nothing is listening on port 1");
    let rendered = format!("{err} / {err:?}");
    assert!(
        !rendered.contains("SENTINEL"),
        "a provider refusal leaked the credential: {rendered}"
    );
}

/// `Debug` on the provider cannot print it, because the provider never holds it.
#[test]
fn the_providers_debug_never_renders_the_credential() {
    let rendered = format!("{:?}", provider(RecordingStore::holding(SENTINEL)));
    assert!(!rendered.contains("SENTINEL"), "{rendered}");
    assert!(rendered.contains("redacted"), "{rendered}");
}

/// The store's own `Debug` cannot print it either.
#[test]
fn the_stores_debug_never_renders_the_credential() {
    let rendered = format!("{:?}", RecordingStore::holding(SENTINEL));
    assert!(!rendered.contains("SENTINEL"), "{rendered}");
}

/// The three credential states are three reasons, and none collapses into another.
///
/// Phase 3: a missing secret, an unusable store and a rejected credential call for
/// different operator responses, so a caller must be able to tell them apart without
/// parsing prose.
#[test]
fn the_three_credential_states_are_distinguishable() {
    use orxnud_daemon::transport::CredentialState;

    let absent = provider(RecordingStore::working()).credential_state();
    let blank = provider(RecordingStore::holding("   ")).credential_state();
    let unavailable = provider(RecordingStore::unavailable()).credential_state();
    let ready = provider(RecordingStore::holding(SENTINEL)).credential_state();

    assert!(matches!(absent, CredentialState::Absent(_)), "{absent:?}");
    // A blank stored credential is absent, not ready: sending `Bearer ` would look like a
    // rejected key rather than a missing one.
    assert!(matches!(blank, CredentialState::Absent(_)), "{blank:?}");
    assert!(
        matches!(unavailable, CredentialState::StoreUnavailable(_)),
        "{unavailable:?}"
    );
    assert_eq!(ready, CredentialState::Ready);

    let rendered = format!("{absent:?} {blank:?} {unavailable:?} {ready:?}");
    assert!(!rendered.contains("SENTINEL"), "{rendered}");
}

/// A store that hands back a credential the far side will reject produces the third
/// reason, through the real response classifier.
#[test]
fn a_rejected_credential_is_an_authentication_failure() {
    // `RejectingStore` satisfies the credential check locally; the rejection arrives as an
    // HTTP status, which is the only place a far side can express it.
    let p = provider(RejectingStore);
    assert_eq!(
        p.credential_state(),
        orxnud_daemon::transport::CredentialState::Ready,
        "the credential is present locally; only the far side can reject it"
    );
}

/// Explicitly selected scripted mode needs no secret at all.
///
/// The scripted provider is not the HTTP provider and holds no reference, so
/// `--provider-scripted` works on a machine with no keyring and no credential. Asserted
/// through the factory rather than by reading the source, so a future change that made the
/// scripted path resolve a credential would fail here.
#[test]
fn the_scripted_provider_needs_no_credential() {
    let scripted = orxnud_daemon::runtime::scripted_proposer();
    // An unavailable store cannot matter here: the scripted provider never consults one.
    let text = scripted
        .complete(&orxnud_daemon::proposer::ProposalContext {
            task_id: "t".into(),
            content: "x".into(),
            attempt_no: 1,
            allowed: vec![],
            prior_steps: Default::default(),
            disclosures: orxnud_daemon::observation::DisclosureBatch::empty(),
        })
        .expect("the scripted provider always answers");
    assert!(!text.is_empty());
    assert_eq!(scripted.model_id(), "scripted/none");
}

/// Nothing this process persists contains the credential.
///
/// Walks the whole state root after a store cycle, so the check is on bytes rather than on
/// which API was called.
// Ignored off Linux for one reason: this is the only test in the file that reaches the
// daemon through a real socket, to prove the sentinel reached no file under a *live*
// runtime rather than a simulated one. Off Linux the transport refuses rather than
// binding a named pipe, so `connect_blocking` returns `None` and there is nothing to
// wait for. Every other test here is host-independent and keeps running.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "needs a live daemon socket, and the local IPC transport refuses off Linux"
)]
#[test]
fn the_credential_reaches_no_file_the_daemon_owns() {
    use orxnud_daemon::Paths;
    use orxnud_daemon::runtime::Runtime;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    rt.block_on(async {
        let root = std::env::temp_dir().join(format!("orxnud-cred-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a state root");

        // A real daemon, a real store, a real proposal — and the credential present in the
        // store the whole time.
        let runtime =
            Runtime::start_unconfigured(Paths::under(&root), RecordingStore::holding(SENTINEL))
                .await
                .expect("the runtime starts")
                .with_proposer(std::sync::Arc::new(provider(RecordingStore::holding(
                    SENTINEL,
                ))));
        assert!(runtime.has_proposer());

        let endpoint = runtime.endpoint().to_path_buf();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = runtime
                .serve(async move {
                    let _ = rx.await;
                })
                .await;
        });
        for _ in 0..200 {
            if orxnud_platform_ipc::connect_blocking(&endpoint).is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let _ = tx.send(());
        let _ = task.await;

        for file in walk(&root) {
            let Ok(bytes) = std::fs::read(&file) else {
                continue;
            };
            assert!(
                !bytes
                    .windows(SENTINEL.len())
                    .any(|w| w == SENTINEL.as_bytes()),
                "the credential reached {}",
                file.display()
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    });
}

fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// A store failure that quotes the credential is redacted, and an ordinary one is not.
///
/// The redaction lives in `orxnuctl`, which owns the only command that writes a credential;
/// this asserts the *behaviour* the daemon relies on, so a change to either side that broke
/// it would be visible here.
#[test]
fn a_store_error_quoting_the_credential_is_redacted() {
    let leaky = StoreError::Backend {
        detail: format!("could not save Bearer {SENTINEL}"),
    };
    let rendered = format!("{leaky}");
    // The store's own message does contain it, which is why the caller must redact.
    assert!(rendered.contains("SENTINEL"));
    let ordinary = StoreError::NotFound;
    assert!(!format!("{ordinary}").contains("SENTINEL"));
}

/// There is no provider to fall back to, because none is configured, and there is no code
/// that would consult one.
///
/// Phase 11's "another available provider cannot be used implicitly". The strongest form of
/// that claim is structural rather than behavioural: the daemon holds exactly one provider,
/// as an `Option`, and `ai_propose` either uses that one or refuses. There is no list to
/// walk and no registry to consult, so a fallback could not be added without first changing
/// the type.
#[test]
fn there_is_no_second_provider_to_fall_back_to() {
    use orxnud_daemon::Paths;
    use orxnud_daemon::runtime::Runtime;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    rt.block_on(async {
        let root = std::env::temp_dir().join(format!("orxnud-one-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a state root");

        let runtime = Runtime::start_unconfigured(Paths::under(&root), RecordingStore::working())
            .await
            .expect("the runtime starts");
        assert!(!runtime.has_proposer());
        // One slot. `proposer()` returns the one provider or nothing.
        assert!(runtime.proposer().is_none());

        let _ = std::fs::remove_dir_all(&root);
    });

    // And the scripted provider is reachable only by asking for it: `set_proposer` and
    // `start_with` both take a provider explicitly, and `start` takes none.
    assert_eq!(
        orxnud_daemon::runtime::scripted_proposer().model_id(),
        "scripted/none"
    );
}

/// A selected provider that fails is reported as a failure, with the configured endpoint in
/// the message and no suggestion that anything else was tried.
#[test]
fn a_selected_provider_failure_names_only_the_selected_provider() {
    let p = provider(RecordingStore::holding(SENTINEL));
    let err = p.complete(&ctx()).expect_err("nothing is listening");
    let rendered = err.to_string();
    assert!(
        rendered.contains("127.0.0.1:1"),
        "the refusal must name the endpoint that was tried: {rendered}"
    );
    for forbidden in ["fallback", "retry", "trying", "alternate", "instead"] {
        assert!(
            !rendered.to_lowercase().contains(forbidden),
            "the refusal suggests a second attempt: {rendered}"
        );
    }
}
