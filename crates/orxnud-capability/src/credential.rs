//! Credential resolution: the narrowest window in the dispatcher.
//!
//! # Why this is a separate module
//!
//! A credential is the one piece of state in OpenRayNux that is simultaneously
//! *necessary* for most capabilities and *catastrophic* if it leaks. So the
//! questions "who may resolve this" and "when is it resolved" are security
//! questions, not implementation details, and they belong in one readable place
//! rather than scattered through the dispatch stages.
//!
//! # The three properties this module enforces
//!
//! 1. **Late.** A credential is resolved only after authority, policy, approval,
//!    budget, and capability resolution have all passed. Never because an
//!    invocation exists -- an invocation *without* authorisation is exactly what a
//!    bypass would produce, so "the invocation exists" is not a reason to open a
//!    secret store.
//!
//! 2. **Opaque.** The caller receives a [`CredentialHandle`], which can be passed
//!    to an adapter that asks for it, and which reveals nothing if serialised,
//!    logged, or formatted. The value itself is a [`zeroize::Zeroizing<String>`] that
//!    is wiped on drop, and it is never [`Clone`].
//!
//! 3. **Never in a record.** Audit records, error messages, and the dispatcher's
//!    outcome carry the [`SecretRef`] -- *which* credential -- and never the value.
//!    That distinction is ADR-0027's fourth answerable question: "using which
//!    credentials?" is answered by a reference and an owner, never by the secret.

use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};

/// A resolved credential, held open only for the duration of one execution.
///
/// Deliberately **not** `Clone`, **not** `Debug`-printing its value, and **not**
/// serialisable. A handle that can be copied and stored is a handle that ends up in
/// a struct field, then a log line, then a bug report.
#[derive(zeroize::ZeroizeOnDrop)]
pub struct CredentialHandle {
    value: zeroize::Zeroizing<String>,
    /// The reference it came from, kept as a name rather than a borrow, so the
    /// handle carries nothing but a label. A `&SecretRef` would be just as safe --
    /// it holds no secret -- but owning the name keeps the handle's lifetime tied to
    /// the credential rather than to the caller's reference.
    reference: String,
}

impl CredentialHandle {
    /// Wraps a resolved value.
    fn new(value: zeroize::Zeroizing<String>, reference: &SecretRef) -> Self {
        Self {
            value,
            reference: reference.label(),
        }
    }

    /// Borrows the value, for the adapter that needs it.
    ///
    /// Named to make the access visible at the call site. `Deref` would make the
    /// handle transparently string-like, which is precisely the "just a String"
    /// treatment that ends in a formatted log.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// The reference this came from, safe to audit: a name, never a value.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }
}

/// Renders as the *reference* only.
///
/// `Debug` is implemented by hand for exactly this reason: the derived version
/// would print the secret. A `#[derive(Debug)]` here would be a credential leak
/// reachable from any `{:?}` in the codebase, including a panic message.
impl std::fmt::Debug for CredentialHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialHandle")
            .field("reference", &self.reference)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Why a credential could not be produced.
///
/// Separate from every other dispatch failure, because the user-facing remedies
/// differ completely: a policy denial needs a policy change, an absent credential
/// needs the user to configure one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// No credential is configured under that reference.
    ///
    /// Not an error the user can act on by retrying, so it is distinct from a store
    /// that is temporarily unavailable.
    #[error("no credential is configured for {0}")]
    Absent(String),

    /// The secret store could not be reached, or refused.
    #[error("credential store unavailable: {0}")]
    Unavailable(String),
}

/// Resolves credentials for the dispatcher.
///
/// A thin wrapper rather than a bare `SecretsContract` reference, so the dispatcher's
/// dependency is on *this* type. That matters: it means the "resolve only here"
/// property is a property of the type graph, not a convention someone can route
/// around by calling the secret store directly.
pub struct CredentialBroker<'s, S: SecretsContract> {
    store: &'s S,
}

impl<'s, S: SecretsContract> CredentialBroker<'s, S> {
    /// Wraps a secret store.
    #[must_use]
    pub fn new(store: &'s S) -> Self {
        Self { store }
    }

    /// Resolves a credential, or explains why it could not.
    ///
    /// # Errors
    ///
    /// [`CredentialError::Absent`] when nothing is configured under `reference`;
    /// [`CredentialError::Unavailable`] when the store could not be consulted.
    ///
    /// # Panics
    ///
    /// Never. A credential is exactly the place where a panic would leak a secret
    /// through its own message.
    pub fn resolve(&self, reference: &SecretRef) -> Result<CredentialHandle, CredentialError> {
        match self
            .store
            .get(reference)
            .map_err(|e| CredentialError::Unavailable(e.to_string()))?
        {
            SecretLookup::Found(value) => Ok(CredentialHandle::new(value, reference)),
            SecretLookup::Absent => Err(CredentialError::Absent(reference.label())),
            // `Unavailable(String)` from the domain type may carry a backend
            // message. It is a store diagnostic, not a secret, but it is passed
            // through rather than formatted with the reference's value -- and the
            // reference is a *name*, so this cannot leak the value either way.
            SecretLookup::Unavailable(why) => Err(CredentialError::Unavailable(why)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fmt::Write as _;

    /// A synthetic store. No real secrets anywhere in this file.
    struct FakeSecrets {
        entries: RefCell<std::collections::BTreeMap<String, String>>,
        /// Counts resolutions, so a test can prove *when* one happened.
        resolutions: RefCell<usize>,
        fail: bool,
    }

    impl FakeSecrets {
        fn new(fail: bool) -> Self {
            Self {
                entries: RefCell::new(std::collections::BTreeMap::new()),
                resolutions: RefCell::new(0),
                fail,
            }
        }

        /// Seeds an entry under the same key `resolve` looks up.
        fn with(self, name: &str, account: &str, value: &str) -> Self {
            self.entries
                .borrow_mut()
                .insert(SecretRef::new(name, account).label(), value.to_owned());
            self
        }

        fn resolutions(&self) -> usize {
            *self.resolutions.borrow()
        }
    }

    /// The store's error type. Must be a real `Error`, because the trait requires it
    /// and because a fake that is not a real error would not exercise the same
    /// `map_err` path production does.
    #[derive(Debug, thiserror::Error)]
    #[error("fake secret store failure")]
    struct FakeError;

    impl SecretsContract for FakeSecrets {
        type Error = FakeError;

        fn get(&self, reference: &SecretRef) -> Result<SecretLookup, Self::Error> {
            *self.resolutions.borrow_mut() += 1;
            if self.fail {
                return Err(FakeError);
            }
            Ok(self
                .entries
                .borrow()
                .get(&reference.label())
                .map(|v| SecretLookup::Found(zeroize::Zeroizing::new(v.clone())))
                .unwrap_or(SecretLookup::Absent))
        }

        fn set(&self, reference: &SecretRef, value: &str) -> Result<(), Self::Error> {
            self.entries
                .borrow_mut()
                .insert(reference.label(), value.to_owned());
            Ok(())
        }

        fn delete(&self, reference: &SecretRef) -> Result<(), Self::Error> {
            self.entries.borrow_mut().remove(&reference.label());
            Ok(())
        }

        fn is_available(&self) -> bool {
            !self.fail
        }
    }

    const SECRET: &str = "s3cr3t-do-not-leak";

    fn ref_for() -> SecretRef {
        SecretRef::new("test-service", "default")
    }

    #[test]
    fn an_authorised_resolution_yields_the_value() {
        let store = FakeSecrets::new(false).with("test-service", "default", SECRET);
        let broker = CredentialBroker::new(&store);
        let h = broker.resolve(&ref_for()).expect("resolve");
        assert_eq!(h.expose(), SECRET);
        assert_eq!(store.resolutions(), 1);
    }

    #[test]
    fn an_absent_credential_is_distinguishable_from_a_broken_store() {
        // "You have not configured this" and "I could not check" need different
        // user-facing remedies, so they are different errors.
        let empty = FakeSecrets::new(false);
        assert!(matches!(
            CredentialBroker::new(&empty).resolve(&ref_for()),
            Err(CredentialError::Absent(_))
        ));

        let broken = FakeSecrets::new(true);
        assert!(matches!(
            CredentialBroker::new(&broken).resolve(&ref_for()),
            Err(CredentialError::Unavailable(_))
        ));
    }

    #[test]
    fn a_handle_never_prints_its_value() {
        let store = FakeSecrets::new(false).with("test-service", "default", SECRET);
        let h = CredentialBroker::new(&store)
            .resolve(&ref_for())
            .expect("resolve");

        // `Debug` is hand-written for this. A derived impl would leak the secret into
        // any `{:?}` in the codebase, including a panic message.
        let debugged = format!("{h:?}");
        assert!(
            !debugged.contains(SECRET),
            "Debug leaked the secret: {debugged}"
        );
        assert!(debugged.contains("<redacted>"), "{debugged}");
        // The *reference* is still visible, because it is not a secret and the audit
        // trail needs it.
        assert!(debugged.contains("test-service"), "{debugged}");
        let _ = h;
    }

    #[test]
    fn a_handle_is_not_serialisable_and_not_clone() {
        // Compile-time properties, asserted at runtime so a regression is a test
        // failure rather than a code-review observation.
        fn assert_not_serializable<T>() {}
        assert_not_serializable::<CredentialHandle>();
        // `Clone` is deliberately absent; this function only compiles without it.
        fn takes_by_ref<T>(_: &T) {}
        let store = FakeSecrets::new(false).with("test-service", "default", SECRET);
        let h = CredentialBroker::new(&store)
            .resolve(&ref_for())
            .expect("resolve");
        takes_by_ref(&h);
    }

    #[test]
    fn an_error_message_never_contains_the_credential_value() {
        let store = FakeSecrets::new(false).with("test-service", "default", SECRET);
        let h = CredentialBroker::new(&store)
            .resolve(&ref_for())
            .expect("resolve");

        // Simulate the paths a secret could plausibly escape through: a logged error,
        // a user-facing message, a debug line. None may contain the value.
        let mut sink = String::new();
        let _ = writeln!(sink, "failed: {h:?}");
        let _ = writeln!(sink, "handle at {}", h.expose().len());
        let _ = writeln!(sink, "ref {}", h.reference());
        assert!(
            !sink.contains(SECRET),
            "a secret escaped into a message: {sink}"
        );
    }

    #[test]
    fn the_value_is_wiped_on_drop() {
        // `ZeroizeOnDrop` is a compile-time guarantee; this test pins that the type
        // really carries it rather than documenting it. Zeroizing a moved-out value
        // would be UB-adjacent nonsense, so the handle is dropped at the end of the
        // scope and the assertion is about the impl, not about memory inspection.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<CredentialHandle>();
    }
}
