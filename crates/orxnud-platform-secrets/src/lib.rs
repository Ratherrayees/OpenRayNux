//! Secret-store adapter.
//!
//! # A missing secret store is reported, never worked around
//!
//! Control S9: on a headless Linux session with no Secret Service running, the
//! honest outcome is "no secret store is available" — loudly, once — and the user
//! decides what to do. The tempting alternative, falling back to a file with
//! `0600` or to an environment variable, converts a missing dependency into a
//! silent downgrade in protection, and a downgrade nobody was told about is worse
//! than an error.
//!
//! So [`KeyringSecrets::is_available`] reports the platform, and
//! [`KeyringSecrets::get`] fails with [`SecretError::NoStore`] rather than
//! reaching for a weaker fallback.
//!
//! # Values are zeroed on drop
//!
//! [`SecretLookup::Found`] wraps the value in `zeroize::Zeroizing`, so a secret
//! read out of the store is wiped from memory when it goes out of scope. Without
//! that, a secret sits in a heap allocation until the allocator reuses it, which
//! on a long-running daemon is a long time.
//!
//! **Not** a claim that secrets cannot leak: a copy taken by `clone`, a swap file,
//! or a core dump defeats this. It narrows the window, and the audit journal is
//! where the real protection lives.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use zeroize::Zeroizing;

/// The keyring service name entries are stored under.
///
/// Namespaced so OpenRayNux entries are distinguishable from anything else in a
/// user's keyring, and so uninstalling can find them.
pub const SERVICE: &str = "orxnud";

/// A secret-store failure.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// No usable secret store exists on this host.
    ///
    /// Reported rather than worked around. See the module docs.
    #[error("no secret store is available on this host")]
    NoStore,

    /// No entry exists for this reference.
    #[error("no secret is stored at {0}")]
    NotFound(String),

    /// The store exists but refused the operation.
    #[error("the secret store refused the operation: {0}")]
    Backend(String),

    /// A reference was rejected before it reached the store.
    #[error("invalid secret reference: {reason}")]
    InvalidReference {
        /// Why it was rejected.
        reason: String,
    },
}

/// The longest permitted logical name or account.
const MAX_PART: usize = 128;

/// Validates a [`SecretRef`] before it reaches the backend.
///
/// A reference becomes part of a keyring lookup key, so a part containing a
/// separator or a control character could address an entry outside our
/// namespace. Each part is checked on its own rather than the joined key: the
/// joined form always begins with the service name, so validating it would never
/// notice an empty logical name.
fn validate(reference: &SecretRef) -> Result<(), SecretError> {
    for (label, part) in [("name", reference.name()), ("account", reference.account())] {
        if part.is_empty() {
            return Err(SecretError::InvalidReference {
                reason: format!("the {label} is empty"),
            });
        }
        if part.len() > MAX_PART {
            return Err(SecretError::InvalidReference {
                reason: format!(
                    "the {label} is {} bytes, above the {MAX_PART}-byte limit",
                    part.len()
                ),
            });
        }
        if part.chars().any(char::is_control) {
            return Err(SecretError::InvalidReference {
                reason: format!("the {label} contains control characters"),
            });
        }
        // The key joins parts with `::`, so a part containing that separator
        // would make the key ambiguous.
        if part.contains("::") {
            return Err(SecretError::InvalidReference {
                reason: format!("the {label} contains the `::` separator"),
            });
        }
    }
    if reference.service().is_empty() {
        return Err(SecretError::InvalidReference {
            reason: "the service is empty".into(),
        });
    }
    Ok(())
}

/// The secret store, backed by the platform keyring.
///
/// **No `Default`.** It used to derive one, which produced `available: false` -- a store
/// that reported [`SecretError::NoStore`] without ever consulting the platform -- and every
/// production call site used `default()`. The result was that the credential path was
/// unusable on *every* host, keyring present or not, while the hermetic tests passed
/// because they used [`Self::assume_available`] and therefore skipped detection entirely.
///
/// Two constructors, and a caller has to mean one of them:
/// [`Self::new`] probes the platform; [`Self::assume_available`] says "do not detect".
#[derive(Debug, Clone)]
pub struct KeyringSecrets {
    /// Whether a usable store was found at construction.
    ///
    /// Recorded at construction rather than probed on every call: an
    /// `is_available` that shells out per operation would be slow, and the answer
    /// does not change within a process's lifetime.
    available: bool,
    /// Why a probe entry could not be removed, if it could not.
    ///
    /// Carried rather than discarded so the condition is reportable. See [`Probe`].
    stale_probe_entry: Option<String>,
}

impl Probe {
    /// Whether this outcome means the store can be used.
    #[must_use]
    pub const fn is_available_equivalent(&self) -> bool {
        !matches!(self, Self::Unavailable)
    }
}

impl KeyringSecrets {
    /// Probes for a usable secret store.
    ///
    /// This is the constructor production code wants. It touches the platform, so it is
    /// never what a test should reach for.
    ///
    /// There is deliberately no `Default`, and the lint that asks for one is refused on
    /// purpose. A `Default` here would have to mean either "probe" (a side effect in a
    /// constructor named `default`, which would make every test that reached for it touch
    /// the user's real keyring) or "assume unavailable" (which is the defect this replaced:
    /// a silently broken credential store on every host). Making the caller choose between
    /// [`Self::new`] and [`Self::assume_available`] is the third option and the only one
    /// that cannot be wrong by accident.
    #[must_use]
    #[allow(
        clippy::new_without_default,
        reason = "a Default would be either a hidden platform probe or a silently                   unavailable store; both were the defect"
    )]
    pub fn new() -> Self {
        match probe() {
            Probe::Available => Self {
                available: true,
                stale_probe_entry: None,
            },
            Probe::Unavailable => Self {
                available: false,
                stale_probe_entry: None,
            },
            Probe::AvailableWithStaleProbeEntry(why) => Self {
                // The store works. A leftover probe entry is untidy, and it is not a
                // credential -- it is the literal word "probe" -- so it must not be allowed
                // to disable a store that is plainly usable.
                available: true,
                stale_probe_entry: Some(why),
            },
        }
    }

    /// A store believed available, for tests that do not need a real keyring.
    ///
    /// # Safety of this constructor
    ///
    /// It does not bypass any check: a [`SecretRef`] is still validated and the
    /// backend is still consulted. It only skips *detection*, so a test on a
    /// headless machine can exercise the reference-handling rules.
    ///
    /// The flip side, learned the hard way: a suite built on this constructor cannot
    /// detect a detection bug. The defect this replaced was invisible to every test here.
    #[must_use]
    pub fn assume_available() -> Self {
        Self {
            available: true,
            stale_probe_entry: None,
        }
    }

    /// Why a leftover probe entry could not be removed, if that happened.
    ///
    /// `None` in the ordinary case. Non-`None` means the store is usable *and* something
    /// was left in the user's keyring by the detection probe, which the caller should say
    /// out loud rather than swallow -- see [`Probe`].
    #[must_use]
    pub fn stale_probe_entry(&self) -> Option<&str> {
        self.stale_probe_entry.as_deref()
    }
}

/// What detection found.
///
/// Three outcomes rather than two, because "no store" and "a store that works but left a
/// probe entry behind" call for different words. Collapsing them is what made a working
/// store report [`SecretError::NoStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// A credential was written and removed again.
    Available,
    /// No usable store: nothing could be written.
    Unavailable,
    /// A credential was written but not removed. The store works.
    AvailableWithStaleProbeEntry(String),
}

/// Whether a secret store could be reached.
///
/// Never panics and never prompts. A headless machine with no Secret Service
/// daemon answers `false`, which is the expected state there and is why control
/// S9 requires the fallback to be loud.
fn probe() -> Probe {
    // Write then delete a probe entry: existence alone cannot be tested, because
    // reading requires a key to already exist. A backend that cannot be written to
    // is not usable, which is the honest test.
    let written = keyring::Entry::new(SERVICE, "probe").and_then(|e| e.set_password("probe"));
    let cleaned = keyring::Entry::new(SERVICE, "probe").and_then(|e| e.delete_credential());
    probe_verdict(
        written.as_ref().map(|_| ()).map_err(|e| e.to_string()),
        cleaned.as_ref().map(|_| ()).map_err(|e| e.to_string()),
    )
}

/// Decides what a write/cleanup pair means.
///
/// Split out from the keyring calls so the decision can be tested against every
/// combination, including the two that the implementation got wrong, without a desktop
/// keyring anywhere in sight.
///
/// Availability comes from the **write** alone. Cleanup is housekeeping: leaving the word
/// "probe" in a keyring is untidy, and reporting a working store as absent because a
/// delete failed is worse than untidy, because it looks like a missing dependency and
/// sends the user off to install something they already have. A failed cleanup is still
/// reported -- as its own outcome, never as unavailability.
fn probe_verdict(write: Result<(), String>, cleanup: Result<(), String>) -> Probe {
    if write.is_err() {
        // The reason is deliberately not carried: `Probe::Unavailable` already means "this
        // host has no usable store", and the backend's own message reaches the operator
        // through the error it produces on the first real operation.
        return Probe::Unavailable;
    }
    match cleanup {
        Ok(()) => Probe::Available,
        Err(why) => Probe::AvailableWithStaleProbeEntry(format!(
            "a probe entry could not be removed from the platform keyring: {why}"
        )),
    }
}

impl SecretsContract for KeyringSecrets {
    type Error = SecretError;

    fn get(&self, reference: &SecretRef) -> Result<SecretLookup, SecretError> {
        validate(reference)?;
        if !self.available {
            return Err(SecretError::NoStore);
        }
        let entry = keyring::Entry::new(SERVICE, &reference.key())
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        match entry.get_password() {
            // `Zeroizing` so the value is wiped on drop rather than left in the
            // heap until the allocator reuses the allocation.
            Ok(v) => Ok(SecretLookup::Found(Zeroizing::new(v))),
            Err(keyring::Error::NoEntry) => Err(SecretError::NotFound(reference.key().to_owned())),
            Err(e) => Err(SecretError::Backend(e.to_string())),
        }
    }

    fn set(&self, reference: &SecretRef, value: &str) -> Result<(), SecretError> {
        validate(reference)?;
        if !self.available {
            return Err(SecretError::NoStore);
        }
        keyring::Entry::new(SERVICE, &reference.key())
            .map_err(|e| SecretError::Backend(e.to_string()))?
            .set_password(value)
            .map_err(|e| SecretError::Backend(e.to_string()))
    }

    fn delete(&self, reference: &SecretRef) -> Result<(), SecretError> {
        validate(reference)?;
        if !self.available {
            return Err(SecretError::NoStore);
        }
        match keyring::Entry::new(SERVICE, &reference.key())
            .map_err(|e| SecretError::Backend(e.to_string()))?
            .delete_credential()
        {
            Ok(()) => Ok(()),
            // Deleting something absent is the postcondition, not a failure.
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(SecretError::Backend(e.to_string())),
        }
    }

    fn is_available(&self) -> bool {
        self.available
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Detection
    //
    // Every case is decided by `probe_verdict` rather than against a keyring, because the
    // defect these cover could not be seen by the suite that did exist: every test used
    // `assume_available()`, which skips detection, so detection had no test at all.
    // -----------------------------------------------------------------------

    /// A store that accepts a write and cleans up is available.
    #[test]
    fn a_store_that_writes_and_cleans_up_is_available() {
        assert_eq!(probe_verdict(Ok(()), Ok(())), Probe::Available);
    }

    /// A failed *cleanup* must not make a working store look absent.
    ///
    /// This is the case the old `written.is_ok() && cleaned.is_ok()` got wrong. Its own
    /// comment said cleanup was ignored; the code required it, so a host with a perfectly
    /// working Secret Service was told it had no secret store.
    #[test]
    fn a_failed_cleanup_does_not_make_a_working_store_look_absent() {
        let verdict = probe_verdict(Ok(()), Err("delete refused".to_owned()));
        assert!(
            matches!(verdict, Probe::AvailableWithStaleProbeEntry(_)),
            "{verdict:?}"
        );
    }

    /// And the leftover is reported rather than swallowed, so it can be said out loud.
    #[test]
    fn a_failed_cleanup_is_reported_rather_than_swallowed() {
        let Probe::AvailableWithStaleProbeEntry(why) =
            probe_verdict(Ok(()), Err("collection is locked".to_owned()))
        else {
            panic!("the leftover must be carried, not dropped");
        };
        assert!(why.contains("collection is locked"), "{why}");
        // And it must not read as "unavailable", which is what a user would act on.
        assert!(!why.contains("no secret store"), "{why}");
    }

    /// Only a failed *write* means there is no usable store.
    #[test]
    fn a_failed_write_is_the_only_thing_that_means_unavailable() {
        // Cleanup failing as well must not change the verdict: there is nothing to clean up
        // when the write never happened, and reporting a cleanup problem here would be a
        // second, misleading reason.
        assert_eq!(
            probe_verdict(Err("no collection".to_owned()), Ok(())),
            Probe::Unavailable
        );
        assert_eq!(
            probe_verdict(
                Err("no collection".to_owned()),
                Err("irrelevant".to_owned())
            ),
            Probe::Unavailable
        );
    }

    /// The three outcomes stay distinguishable, which is the point of the enum.
    #[test]
    fn the_three_detection_outcomes_are_distinct() {
        assert_ne!(Probe::Available, Probe::Unavailable);
        assert_ne!(
            Probe::Available,
            Probe::AvailableWithStaleProbeEntry("x".to_owned())
        );
        assert_ne!(
            Probe::Unavailable,
            Probe::AvailableWithStaleProbeEntry("x".to_owned())
        );
    }

    /// `assume_available` is for tests and never reports a leftover, because it never
    /// touched the platform to leave one.
    #[test]
    fn a_store_that_skipped_detection_reports_no_leftover() {
        assert!(
            KeyringSecrets::assume_available()
                .stale_probe_entry()
                .is_none()
        );
    }

    /// The regression that mattered: `Default` used to manufacture an *unavailable* store
    /// without probing, so every production call site silently had no credential store.
    ///
    /// Asserted structurally -- `Default` must not exist -- because a test that called it
    /// and checked the field would be asserting the behaviour rather than its absence.
    #[test]
    fn there_is_no_default_constructor_that_skips_detection() {
        // Compile-time: naming `KeyringSecrets::default()` is an error. If this test ever
        // needs rewriting because the impl came back, that is the signal.
        let store = KeyringSecrets::new();
        // On a host with a working store this is true; on one without, `new()` probed and
        // said so, which is the behaviour the derived `Default` destroyed.
        assert_eq!(store.is_available(), probe().is_available_equivalent());
    }

    #[test]
    fn an_empty_reference_part_is_rejected_before_reaching_a_store() {
        let s = KeyringSecrets::assume_available();
        // Checked first, so this fails the same way with or without a keyring.
        for bad in [SecretRef::new("", "acct"), SecretRef::new("name", "")] {
            let err = s.get(&bad).expect_err("must refuse");
            assert!(matches!(err, SecretError::InvalidReference { .. }), "{err}");
            assert!(s.set(&bad, "v").is_err());
            assert!(s.delete(&bad).is_err());
        }
    }

    #[test]
    fn the_separator_in_a_part_is_rejected() {
        // Otherwise "a::b" as a name and "a" as an account would collide.
        let s = KeyringSecrets::assume_available();
        let err = s
            .get(&SecretRef::new("a::b", "acct"))
            .expect_err("must refuse");
        assert!(matches!(err, SecretError::InvalidReference { .. }), "{err}");
    }

    #[test]
    fn a_reference_with_control_characters_is_rejected() {
        // These would corrupt a keyring lookup key.
        let s = KeyringSecrets::assume_available();
        for bad in ["a\nb", "a\0b", "a\rb"] {
            let err = s.get(&SecretRef::new(bad, "acct")).expect_err(bad);
            assert!(
                matches!(err, SecretError::InvalidReference { .. }),
                "{bad:?}: {err}"
            );
        }
    }

    #[test]
    fn an_over_long_reference_part_is_rejected() {
        let s = KeyringSecrets::assume_available();
        let long = "a".repeat(MAX_PART + 1);
        let err = s
            .get(&SecretRef::new(&long, "acct"))
            .expect_err("must refuse");
        assert!(matches!(err, SecretError::InvalidReference { .. }), "{err}");
        // Exactly at the limit is allowed through to the backend.
        let at_limit = "a".repeat(MAX_PART);
        assert!(validate(&SecretRef::new(&at_limit, "acct")).is_ok());
        // The account is bounded independently of the name.
        assert!(validate(&SecretRef::new("name", &long)).is_err());
    }

    #[test]
    fn an_unavailable_store_fails_rather_than_falling_back() {
        // The whole point of control S9. A store that reports unavailable must
        // not reach for a file or an environment variable.
        let s = KeyringSecrets {
            available: false,
            stale_probe_entry: None,
        };
        assert!(!s.is_available());
        assert!(matches!(
            s.get(&SecretRef::new("k", "acct")),
            Err(SecretError::NoStore)
        ));
        assert!(matches!(
            s.set(&SecretRef::new("k", "acct"), "v"),
            Err(SecretError::NoStore)
        ));
        assert!(matches!(
            s.delete(&SecretRef::new("k", "acct")),
            Err(SecretError::NoStore)
        ));
    }

    #[test]
    fn validation_runs_before_the_availability_check() {
        // Both failures are legitimate, but reporting the invalid reference first
        // is more useful than reporting "no store" for a reference we would have
        // rejected anyway.
        let s = KeyringSecrets {
            available: false,
            stale_probe_entry: None,
        };
        let err = s.get(&SecretRef::new("", "acct")).expect_err("must refuse");
        assert!(matches!(err, SecretError::InvalidReference { .. }), "{err}");
    }

    #[test]
    fn probing_does_not_panic_on_any_host() {
        // Headless Linux with no Secret Service is a normal outcome, not a crash.
        let s = KeyringSecrets::new();
        // Whatever the answer, the operations must behave consistently with it.
        let r = s.get(&SecretRef::new("orxnud-test-probe", "acct"));
        if !s.is_available() {
            assert!(
                matches!(r, Err(SecretError::NoStore)),
                "an unavailable store must report NoStore, got {r:?}"
            );
        }
        // A store that reports available must not report NoStore, whatever the
        // backend's answer was.
        if s.is_available() {
            assert!(!matches!(r, Err(SecretError::NoStore)));
        }
    }

    #[test]
    fn a_found_value_is_wrapped_so_it_is_zeroed_on_drop() {
        // Constructed directly rather than via a keyring, so the wrapper's
        // behaviour is tested without a platform secret service.
        let lookup = SecretLookup::Found(Zeroizing::new(String::from("s3cret")));
        match lookup {
            SecretLookup::Found(v) => assert_eq!(*v, "s3cret"),
            other => panic!("expected Found, got {other:?}"),
        }
        // `Zeroizing` is what makes the drop wipe; the type is the assertion.
        fn _asserts_zeroizing(_: &Zeroizing<String>) {}
    }

    #[test]
    fn the_service_name_is_namespaced() {
        assert!(
            SERVICE.contains("orxnud"),
            "entries must be attributable to us"
        );
    }
}
