//! Deterministic test adapters.
//!
//! # These are fixtures, not integrations
//!
//! Every adapter here is a few lines of in-memory behaviour. None opens a socket,
//! reads a real credential, or touches the filesystem, because Phase 3's claim is
//! about the *boundary*, and a test that reached a real service would be testing the
//! service.
//!
//! # The hostile ones are the point
//!
//! [`PanickingAdapter`], [`HangingAdapter`], and [`MisreportingAdapter`] exist so the
//! dispatcher's failure handling can be tested rather than asserted. In particular
//! [`MisreportingAdapter`] is the fixture that makes "adapter returned Ok" and "the
//! effect happened" distinguishable; without it, a dispatcher that ignored
//! verification entirely would still pass every happy-path test.

#![allow(dead_code)] // each fixture is used by a different test binary

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use orxnud_capability::credential::CredentialHandle;
use orxnud_capability::dispatch::{AdapterBundle, CapabilityAdapter};
use orxnud_capability::verification::{
    ExecutionOutcome, VerificationOutcome, Verifier, VerifyError,
};
use orxnud_domain::enums::DataClass;
use orxnud_domain::ids::CapabilityId;
use orxnud_domain::invocation::DispatchView;

/// Shared recorder, so a test can assert on how many times an adapter ran.
#[derive(Debug, Default)]
pub struct Calls(AtomicUsize);

impl Calls {
    pub fn count(&self) -> usize {
        self.calls().load(Ordering::SeqCst)
    }
    fn calls(&self) -> &AtomicUsize {
        &self.0
    }
    fn bump(&self) {
        self.calls().fetch_add(1, Ordering::SeqCst);
    }
}

/// How a verifier behaves. Deterministic, never a real check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    /// Confirms success.
    Confirms,
    /// Refutes, even when execution reported success. The misreporting case.
    Refutes,
    /// Cannot run.
    Unavailable,
}

/// Pairs an adapter with a verifier.
pub struct Bundle<A: CapabilityAdapter> {
    adapter: A,
    mode: VerifyMode,
}

impl<A: CapabilityAdapter + 'static> AdapterBundle for Bundle<A> {
    fn adapter(&self) -> &dyn CapabilityAdapter {
        &self.adapter
    }
    fn verifier(&self) -> &dyn Verifier {
        // `Verifier for Bundle<A>` is what is actually dispatched, so this forwarder
        // is unreachable in practice; it exists to satisfy the trait.
        self
    }
}

/// The verifier half of a [`Bundle`].
///
/// Borrows the mode rather than the adapter, so `Bundle` can implement both traits
/// without a self-referential struct.
struct ModeVerifier(VerifyMode);

impl Verifier for ModeVerifier {
    fn verify(
        &self,
        execution: &ExecutionOutcome,
        _at_ms: i64,
    ) -> Result<VerificationOutcome, VerifyError> {
        // A verifier that ignored the execution outcome could confirm an effect that
        // never happened. Every mode below reads it.
        if let ExecutionOutcome::Failed { .. } | ExecutionOutcome::Unknown { .. } = execution {
            return Ok(VerificationOutcome::Undetermined {
                reason: "execution did not report success".into(),
            });
        }
        Ok(match self.0 {
            VerifyMode::Confirms => VerificationOutcome::Verified {
                evidence: "the fixture confirms".into(),
            },
            VerifyMode::Refutes => VerificationOutcome::Refuted {
                evidence: "the fixture refutes: the effect did not occur".into(),
            },
            VerifyMode::Unavailable => {
                return Err(VerifyError("the fixture cannot verify".into()));
            }
        })
    }
}

impl<A: CapabilityAdapter + 'static> Verifier for Bundle<A> {
    fn verify(
        &self,
        execution: &ExecutionOutcome,
        at_ms: i64,
    ) -> Result<VerificationOutcome, VerifyError> {
        ModeVerifier(self.mode).verify(execution, at_ms)
    }
}

impl<A: CapabilityAdapter + 'static> Bundle<A> {
    pub fn new(adapter: A, mode: VerifyMode) -> Self {
        Self { adapter, mode }
    }
    pub fn confirming(adapter: A) -> Self {
        Self::new(adapter, VerifyMode::Confirms)
    }
    pub fn refuting(adapter: A) -> Self {
        Self::new(adapter, VerifyMode::Refutes)
    }
    pub fn unverifiable(adapter: A) -> Self {
        Self::new(adapter, VerifyMode::Unavailable)
    }
    pub fn into_arc(self) -> Arc<dyn AdapterBundle + Send + Sync> {
        Arc::new(self)
    }
}

/// A synthetic secret store. No real secrets.
pub struct FakeSecrets {
    /// `RefCell`, because `SecretsContract` takes `&self` -- the trait's shape
    /// reflects a real keyring that mutates behind a shared reference.
    entries: std::cell::RefCell<std::collections::BTreeMap<String, String>>,
    pub fail: bool,
}

impl FakeSecrets {
    pub fn new() -> Self {
        Self {
            entries: std::cell::RefCell::new(std::collections::BTreeMap::new()),
            fail: false,
        }
    }
    pub fn with(self, name: &str, account: &str, value: &str) -> Self {
        self.entries.borrow_mut().insert(
            orxnud_domain::SecretRef::new(name, account).label(),
            value.to_owned(),
        );
        self
    }
    pub fn failing() -> Self {
        Self {
            entries: std::cell::RefCell::new(std::collections::BTreeMap::new()),
            fail: true,
        }
    }
}

impl Default for FakeSecrets {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("fake secret store unavailable")]
pub struct FakeSecretError;

impl orxnud_domain::SecretsContract for FakeSecrets {
    type Error = FakeSecretError;

    fn get(
        &self,
        reference: &orxnud_domain::SecretRef,
    ) -> Result<orxnud_domain::platform::SecretLookup, Self::Error> {
        if self.fail {
            return Err(FakeSecretError);
        }
        Ok(self
            .entries
            .borrow()
            .get(&reference.label())
            .map(|v| {
                orxnud_domain::platform::SecretLookup::Found(zeroize::Zeroizing::new(v.clone()))
            })
            .unwrap_or(orxnud_domain::platform::SecretLookup::Absent))
    }
    fn set(&self, reference: &orxnud_domain::SecretRef, value: &str) -> Result<(), Self::Error> {
        self.entries
            .borrow_mut()
            .insert(reference.label(), value.to_owned());
        Ok(())
    }
    fn delete(&self, reference: &orxnud_domain::SecretRef) -> Result<(), Self::Error> {
        self.entries.borrow_mut().remove(&reference.label());
        Ok(())
    }
    fn is_available(&self) -> bool {
        !self.fail
    }
}

// ---------------------------------------------------------------- the adapters

/// A well-behaved adapter.
pub struct SuccessfulAdapter {
    pub id: CapabilityId,
    pub calls: Arc<Calls>,
    /// Whether a credential was supplied. Lets a test prove stage 6 ran before
    /// stage 7 without exposing the value.
    pub saw_credential: Arc<AtomicBool>,
}

impl SuccessfulAdapter {
    pub fn new(id: &str) -> Self {
        Self {
            id: CapabilityId::new(id),
            calls: Arc::new(Calls::default()),
            saw_credential: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl CapabilityAdapter for SuccessfulAdapter {
    fn capability_id(&self) -> &CapabilityId {
        &self.id
    }
    fn declared_class(&self) -> DataClass {
        DataClass::Personal
    }
    fn invoke(
        &self,
        view: &DispatchView<'_>,
        credential: Option<&CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        self.calls.bump();
        self.saw_credential
            .store(credential.is_some(), Ordering::SeqCst);
        Ok(ExecutionOutcome::Succeeded {
            output: Some(format!("ran step {} of {}", view.step, view.capability)),
        })
    }
}

/// An adapter that reports a known failure.
pub struct FailingAdapter {
    pub id: CapabilityId,
    pub calls: Arc<Calls>,
    pub message: String,
}

impl FailingAdapter {
    pub fn new(id: &str, message: &str) -> Self {
        Self {
            id: CapabilityId::new(id),
            calls: Arc::new(Calls::default()),
            message: message.to_owned(),
        }
    }
}

impl CapabilityAdapter for FailingAdapter {
    fn capability_id(&self) -> &CapabilityId {
        &self.id
    }
    fn declared_class(&self) -> DataClass {
        DataClass::Personal
    }
    fn invoke(
        &self,
        _view: &DispatchView<'_>,
        _credential: Option<&CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        self.calls.bump();
        Ok(ExecutionOutcome::Failed {
            detail: self.message.clone(),
        })
    }
}

/// An adapter that never returns on its own.
///
/// The dispatcher does not implement a timeout -- that is the host's job in Phase 4+,
/// with the execution boundary compatible with the future subprocess model
/// (ADR-0009). What this fixture proves is narrower and still worth having: the
/// reentrancy guard can be observed as held while an adapter is running, so a caller
/// that *does* impose a deadline knows the guard is what it must release.
pub struct HangingAdapter {
    pub id: CapabilityId,
    pub release: Arc<AtomicBool>,
}

impl HangingAdapter {
    pub fn new(id: &str) -> Self {
        Self {
            id: CapabilityId::new(id),
            release: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl CapabilityAdapter for HangingAdapter {
    fn capability_id(&self) -> &CapabilityId {
        &self.id
    }
    fn declared_class(&self) -> DataClass {
        DataClass::Personal
    }
    fn invoke(
        &self,
        _view: &DispatchView<'_>,
        _credential: Option<&CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        // Bounded, so a test cannot wedge the suite. Deterministic in that it always
        // eventually returns the same thing.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !self.release.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(ExecutionOutcome::Unknown {
            detail: "the fixture was released without completing".into(),
        })
    }
}

/// An adapter that reports success without doing anything.
///
/// The fixture that makes verification load-bearing: paired with
/// [`VerifyMode::Refutes`], it proves the dispatcher does not translate `Ok` into
/// "the effect happened".
pub struct MisreportingAdapter {
    pub id: CapabilityId,
    pub calls: Arc<Calls>,
}

impl MisreportingAdapter {
    pub fn new(id: &str) -> Self {
        Self {
            id: CapabilityId::new(id),
            calls: Arc::new(Calls::default()),
        }
    }
}

impl CapabilityAdapter for MisreportingAdapter {
    fn capability_id(&self) -> &CapabilityId {
        &self.id
    }
    fn declared_class(&self) -> DataClass {
        DataClass::Personal
    }
    fn invoke(
        &self,
        _view: &DispatchView<'_>,
        _credential: Option<&CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        self.calls.bump();
        // The lie. A dispatcher that trusted this would declare success.
        Ok(ExecutionOutcome::Succeeded {
            output: Some("{\"status\":\"ok\",\"delivered\":true}".into()),
        })
    }
}

/// An adapter that panics.
///
/// ADR-0009's "a crashing optional integration should ideally not crash the core".
pub struct PanickingAdapter {
    pub id: CapabilityId,
    pub calls: Arc<Calls>,
}

impl PanickingAdapter {
    pub fn new(id: &str) -> Self {
        Self {
            id: CapabilityId::new(id),
            calls: Arc::new(Calls::default()),
        }
    }
}

impl CapabilityAdapter for PanickingAdapter {
    fn capability_id(&self) -> &CapabilityId {
        &self.id
    }
    fn declared_class(&self) -> DataClass {
        DataClass::Personal
    }
    fn invoke(
        &self,
        _view: &DispatchView<'_>,
        _credential: Option<&CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        self.calls.bump();
        panic!("the fixture panics, as a faulty adapter would");
    }
}

/// An adapter that mutates external state before failing, so the "did it happen?"
/// question is real rather than hypothetical.
///
/// Paired with a refuting verifier this is the TP-12 shape: the effect partially
/// occurred and must not be reported as a clean failure that invites a retry.
pub struct MutatingAdapter {
    pub id: CapabilityId,
    pub mutated: Arc<AtomicBool>,
}

impl MutatingAdapter {
    pub fn new(id: &str) -> Self {
        Self {
            id: CapabilityId::new(id),
            mutated: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl CapabilityAdapter for MutatingAdapter {
    fn capability_id(&self) -> &CapabilityId {
        &self.id
    }
    fn declared_class(&self) -> DataClass {
        DataClass::Personal
    }
    fn invoke(
        &self,
        _view: &DispatchView<'_>,
        _credential: Option<&CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        self.mutated.store(true, Ordering::SeqCst);
        Ok(ExecutionOutcome::Unknown {
            detail: "the effect partially occurred before the failure".into(),
        })
    }
}

// ------------------------------------------------------------------ phase 4b

/// The hostile helper binary, re-executed inside the sandbox.
///
/// `orxnud-platform-sandbox`'s own test binary, located in this crate's build
/// directory. It is a test binary rather than a shipped `bin`, so the adversary
/// cannot become a product artefact.
#[must_use]
pub fn helper_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let dir = exe.parent().expect("deps directory");
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read deps directory")
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                // Exclude the `.d` dependency file, which shares the prefix and can be
                // newer than the binary. Selecting it yields a "helper" that is not
                // executable, and bwrap reports a confusing `execvp ...: Permission denied`.
                .is_some_and(|n| n.starts_with("hostile_helper-") && !n.ends_with(".d"))
        })
        .collect();
    assert!(
        !found.is_empty(),
        "no hostile_helper-* binary in {}; run `cargo test --no-run` first",
        dir.display()
    );
    // Newest, not lexicographically first.
    //
    // Stale helper binaries accumulate in `target/debug/deps` across builds, and their
    // names embed a hash. Sorting by name and taking index 0 therefore picked whichever
    // hash happened to sort first -- frequently an *older* build. A mode added to the
    // helper then silently fell through to the catch-all `noop`, so a governed test
    // appeared to pass while proving nothing about the behaviour it named.
    found.sort_by_key(|p| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });
    found.pop().expect("non-empty")
}

/// The directory the helper lives in, which the sandbox must be granted read-only.
///
/// A real capability would be installed somewhere the sandbox already expects, so
/// this is a property of the fixture rather than of the design.
#[must_use]
pub fn sandbox_helpers_dir() -> PathBuf {
    helper_path().parent().expect("dir").to_path_buf()
}
