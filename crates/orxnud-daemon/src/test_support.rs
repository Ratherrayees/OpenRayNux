//! Test support: a secret store backed by a file.
//!
//! # Why this exists
//!
//! The provider credential is read from the platform credential store, which on a
//! developer machine is the developer's own. A test that spawns the real daemon
//! binary and drives it against a synthetic provider would therefore depend on
//! whatever secret the machine happens to hold: it would pass on one host and
//! fail on another, and it would read a real credential to do it.
//!
//! This module gives such a test an isolated source instead. The daemon still
//! resolves a credential through the ordinary [`SecretsContract`], still refuses
//! when there is none, and still sends it in the `Authorization` header. Only the
//! *source* changes.
//!
//! # What it is not
//!
//! It is not a way to weaken the credential check. There is no "no credential
//! needed" mode here: a missing file, an unreadable file, or an empty file are
//! all failures, and the caller that uses this store must treat them as
//! refusals to start rather than as a reason to fall back to the platform store.
//!
//! The module is compiled out of release builds (`cfg(debug_assertions)`), so a
//! shipped binary has no route to it at all: no flag, no environment variable, no
//! configuration key.

#![deny(missing_docs)]

use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use zeroize::Zeroizing;

/// The credential name the provider asks for.
///
/// The provider's own `SecretRef` uses this name; a store that serves a
/// different one is serving a different credential.
const PROVIDER_CREDENTIAL_NAME: &str = "provider-api-key";

/// The account the provider asks for.
const PROVIDER_CREDENTIAL_ACCOUNT: &str = "local";

/// A secret store that serves one credential, read from a file.
///
/// The file is read **once**, when the store is built. A store that cannot be
/// built is a refusal to start, not a store that answers "absent" later: the
/// difference matters, because "absent" could be satisfied by falling back to
/// somewhere else, and this store has nowhere else to go.
pub struct FileSecrets {
    /// The credential name served.
    name: String,
    /// The account served.
    account: String,
    /// The credential itself.
    value: Zeroizing<String>,
}

impl FileSecrets {
    /// Reads the credential from `path`.
    ///
    /// # Errors
    ///
    /// If the file cannot be read, or holds nothing but whitespace. An empty
    /// credential is refused rather than stored: a provider that receives an
    /// empty `Authorization` header has been told a credential exists when none
    /// does.
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?;
        let value = raw.trim().to_owned();
        if value.is_empty() {
            return Err(format!("{} holds no credential", path.display()));
        }
        Ok(Self {
            name: PROVIDER_CREDENTIAL_NAME.to_owned(),
            account: PROVIDER_CREDENTIAL_ACCOUNT.to_owned(),
            value: Zeroizing::new(value),
        })
    }
}

impl Clone for FileSecrets {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            account: self.account.clone(),
            value: self.value.clone(),
        }
    }
}

impl std::fmt::Debug for FileSecrets {
    /// Never prints the credential.
    ///
    /// A derived `Debug` would print the value, and a value that reaches a log
    /// line is a value that has leaked.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSecrets")
            .field("name", &self.name)
            .field("account", &self.account)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// A failure from the file-backed store.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct FileSecretError(String);

impl SecretsContract for FileSecrets {
    type Error = FileSecretError;

    /// Resolves the provider credential.
    ///
    /// A reference this store does not serve is [`SecretLookup::Absent`], which
    /// the provider turns into "no credential" — a refusal, not a store error.
    fn get(&self, reference: &SecretRef) -> Result<SecretLookup, Self::Error> {
        if reference.name() == self.name && reference.account() == self.account {
            Ok(SecretLookup::Found(self.value.clone()))
        } else {
            Ok(SecretLookup::Absent)
        }
    }

    /// Refused. This store is read-only: a test supplies a credential, it does
    /// not manage one.
    fn set(&self, _reference: &SecretRef, _value: &str) -> Result<(), Self::Error> {
        Err(FileSecretError(
            "the file-backed test store is read-only".to_owned(),
        ))
    }

    /// Refused, for the same reason as [`SecretsContract::set`].
    fn delete(&self, _reference: &SecretRef) -> Result<(), Self::Error> {
        Err(FileSecretError(
            "the file-backed test store is read-only".to_owned(),
        ))
    }

    /// True. The file was read when this store was built, so the store exists or
    /// the caller never got one.
    fn is_available(&self) -> bool {
        true
    }
}
