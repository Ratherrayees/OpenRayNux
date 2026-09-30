//! Platform contracts — traits defined in the portable core, implemented by
//! `orxnud-platform-*` adapters.
//!
//! # The direction, and why it matters
//!
//! docs-03 §4: **"the core defines the trait; adapters implement it."** Not the
//! other way round. If a platform crate defined its own contract, the portable
//! core would need to depend on it to name the type — and the portable core
//! would stop being portable. The direction is the mechanism.
//!
//! These are pure trait *declarations*. There is no I/O here, no `std::fs`, no
//! `std::process`. That is what lets the portable-core gate (G9) compile this
//! module for `wasm32-unknown-unknown`.
//!
//! # What is genuinely platform-specific
//!
//! The *implementations*, in `orxnud-platform-{fs,secrets,notify}`, contain the
//! `cfg(target_os)` branches: XDG vs `%APPDATA%` vs `~/Library`, Secret Service
//! vs DPAPI vs Keychain, and per-OS notification delivery. CI gate G7 fails if
//! a `cfg(target_os)` appears anywhere else in the workspace.

use serde::{Deserialize, Serialize};

use crate::ids::CapabilityId;

/// A reference to a secret, never the secret itself.
///
/// Configuration stores these. The value is resolved through
/// [`SecretsContract`] at the moment of use, by the policy layer — never by the
/// model (control S1: the model has no credential handle at all).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRef {
    /// Logical name, e.g. `anthropic-api-key`.
    pub name: String,
    /// The OS credential store's service name.
    pub service: String,
    /// The account within that service.
    pub account: String,
}

impl SecretRef {
    /// Builds a reference with a uniform service name.
    #[must_use]
    pub fn new(name: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            service: "openraynux".to_owned(),
            account: account.into(),
        }
    }
}

/// A filesystem request, already scoped to a granted root.
///
/// Paths are `PathBuf`s and are validated against the granted root by the
/// implementation. The grant itself is policy's job; this trait assumes it has
/// already been decided and does not re-decide it.
pub trait FsContract {
    /// Error from a filesystem operation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Reads a whole file, bounded by `max_bytes`.
    ///
    /// `max_bytes` is a parameter rather than a constant so a caller cannot
    /// accidentally read a 10 GB "log file" into memory — the deserialisation
    /// bound from control S21.
    fn read_bounded(
        &self,
        path: &std::path::Path,
        max_bytes: u64,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Writes atomically: to a temporary sibling, then rename.
    ///
    /// Atomic rather than in-place because a torn file in `critical` state is
    /// worse than a missing one.
    fn write_atomic(&self, path: &std::path::Path, contents: &[u8]) -> Result<(), Self::Error>;

    /// Whether a path exists within the granted root.
    fn exists(&self, path: &std::path::Path) -> Result<bool, Self::Error>;

    /// Creates a directory and its parents, idempotently.
    fn ensure_dir(&self, path: &std::path::Path) -> Result<(), Self::Error>;
}

/// Outcome of a secret lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretLookup {
    /// Found. The value is wrapped so it can be zeroed on drop.
    Found(zeroize::Zeroizing<String>),
    /// Not present. Distinct from an error, because "no credential configured"
    /// and "the credential store failed" need different user-facing messages.
    Absent,
    /// The store is unavailable on this host.
    Unavailable(String),
}

/// A notification the product would like to show.
///
/// Modelled here so the *shape* is portable and testable, and so rate limiting
/// (control S28) can be enforced at the notification boundary regardless of the
/// transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationRequest {
    /// Short title.
    pub title: String,
    /// Body text. May be empty.
    pub body: String,
    /// Which of the user's configured channels to prefer, if any.
    pub preferred_channel: Option<CapabilityId>,
    /// Coarse urgency. The implementation maps this to platform-specific
    /// urgency hints, or drops it where none exists.
    pub urgency: Urgency,
}

/// Notification urgency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Urgency {
    /// Informational.
    Normal,
    /// Time-sensitive.
    High,
}

/// Secure secret storage.
pub trait SecretsContract {
    /// Error from a secret-store operation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Resolves a reference to its value.
    fn get(&self, reference: &SecretRef) -> Result<SecretLookup, Self::Error>;

    /// Stores a value. Used by an explicit user action, never automatically.
    fn set(&self, reference: &SecretRef, value: &str) -> Result<(), Self::Error>;

    /// Removes a stored value.
    fn delete(&self, reference: &SecretRef) -> Result<(), Self::Error>;

    /// Whether a usable secret store exists on this host.
    ///
    /// False on a headless Linux session with no Secret Service daemon, which
    /// is why ADR/control S9 requires a loud, explicit fallback rather than a
    /// silent one.
    fn is_available(&self) -> bool;
}

/// Desktop notification delivery.
pub trait NotifyContract {
    /// Error from a notification operation.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Delivers a notification.
    fn deliver(&self, request: &NotificationRequest) -> Result<(), Self::Error>;

    /// Whether a real transport exists on this host.
    ///
    /// False in Phase 1: there is no interface yet, so there is nothing to
    /// notify. The dispatcher uses this to avoid treating "no transport" as an
    /// error during development.
    fn is_available(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_ref_uses_the_uniform_service_name() {
        let r = SecretRef::new("anthropic-api-key", "default");
        assert_eq!(r.service, "openraynux");
        assert_eq!(r.name, "anthropic-api-key");
        assert_eq!(r.account, "default");
    }

    #[test]
    fn secret_lookup_distinguishes_absent_from_unavailable() {
        // Three outcomes, not two: a missing credential and a broken credential
        // store need different user-facing messages, and conflating them is
        // how users end up debugging the wrong thing.
        assert_ne!(SecretLookup::Absent, SecretLookup::Unavailable("x".into()));
    }

    #[test]
    fn notification_request_round_trips() {
        let r = NotificationRequest {
            title: "Task finished".into(),
            body: String::new(),
            preferred_channel: None,
            urgency: Urgency::Normal,
        };
        let json = serde_json::to_string(&r).expect("serialise");
        let back: NotificationRequest = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(r, back);
    }
}
