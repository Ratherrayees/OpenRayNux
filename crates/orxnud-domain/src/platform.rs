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

    /// The logical name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// A single stable label identifying this credential.
    ///
    /// Deliberately **not** `Display`: a `Display` impl is what a caller reaches for
    /// when interpolating a reference into an error message or a log line, and the
    /// reference is safe to log, so that is not a leak. What a `Display` impl would
    /// do is make the *name-only* choice invisible -- `format!("{ref}")` and
    /// "deliberately label" would look identical at the call site, and a future
    /// change to `Debug` would then reach audit output unnoticed. A method named
    /// `label` states what it produces.
    ///
    /// Contains no secret: it is a name, a service, and an account.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}/{}/{}", self.name, self.service, self.account)
    }

    /// The service the entry lives under.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The account within the service.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// The composite key a single-entry backend would use.
    ///
    /// A `SecretRef` names a `(service, account)` pair, but most credential stores
    /// key on a single string. Joining them here — in one place, with the
    /// separator visible — means an adapter cannot invent a different joining and
    /// end up addressing a different entry than the reference names.
    #[must_use]
    pub fn key(&self) -> String {
        format!("{}::{}", self.service, self.account)
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
    ///
    /// # Errors
    ///
    /// The implementation's error if the path is outside the granted root, does
    /// not exist, or is larger than `max_bytes`.
    fn read_bounded(&self, path: &std::path::Path, max_bytes: u64) -> Result<Vec<u8>, Self::Error>;

    /// Writes atomically: to a temporary sibling, then rename.
    ///
    /// Atomic rather than in-place because a torn file in `critical` state is
    /// worse than a missing one.
    ///
    /// # Errors
    ///
    /// The implementation's error if the path is outside the granted root, or if
    /// the temporary write or the rename fails.
    fn write_atomic(&self, path: &std::path::Path, contents: &[u8]) -> Result<(), Self::Error>;

    /// Whether a path exists within the granted root.
    ///
    /// # Errors
    ///
    /// The implementation's error if the path is outside the granted root.
    fn exists(&self, path: &std::path::Path) -> Result<bool, Self::Error>;

    /// Creates a directory and its parents, idempotently.
    ///
    /// # Errors
    ///
    /// The implementation's error if the path is outside the granted root or
    /// cannot be created.
    fn ensure_dir(&self, path: &std::path::Path) -> Result<(), Self::Error>;
}

/// A stable identity for a file, where the platform can establish one.
///
/// # What it is for
///
/// ADR-0058: a database's ownership is keyed by *path*, so a second name for the
/// same file defeats it. Detecting that second name needs the file's link count,
/// and checking that the file did not change underneath an open needs an identity
/// to compare. Both are facts about the file rather than about the name, which is
/// why they live here rather than in the store that consumes them.
///
/// # Why it is an enum, and why each variant keeps its native representation
///
/// The two supported platforms answer with different facts. POSIX supplies a
/// device and inode number; Windows supplies a volume serial number and a
/// **128-bit** file identifier. They are not convertible: truncating the Windows
/// identifier to the low 64 bits of a POSIX `ino` would conflate distinct files,
/// and hashing it would turn an exact comparison into a probabilistic one. Keeping
/// each representation intact means an identity observed on one platform cannot be
/// mistaken for an identity observed on another.
///
/// Neither representation is a promise that two observations of the same file
/// always match: a file that is replaced and then replaced back with the same
/// inode is the same file by this measure, and a file whose inode is reused after
/// deletion is a different file by every measure this offers. The guarantee they
/// support is narrow — "this path resolved to this file, and it still does" — and
/// that is the guarantee ADR-0058 Decision 3 asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileId {
    /// The POSIX device and inode number.
    Unix {
        /// The device the file lives on.
        dev: u64,
        /// The file's number within that device.
        ino: u64,
    },
    /// The Windows volume serial number and full 128-bit file identifier.
    Windows {
        /// The serial number of the volume the file lives on.
        volume_serial: u64,
        /// The file's identifier within that volume, exactly as
        /// `FILE_ID_INFO.FileId.Identifier` reports it.
        file_id: [u8; 16],
    },
}

/// What the platform established about a path.
///
/// # The three states, and why there are three
///
/// * [`FileFacts::Absent`] — the path does not exist. This is the normal state of
///   a database about to be created, and it is **not** a failure. It is also not
///   the same as "unknown": a caller that cannot tell them apart would either
///   refuse every fresh install or treat every unanswerable question as a
///   freshly-created file.
/// * [`FileFacts::Known`] — the platform established the facts. This is the only
///   state in which anything may be concluded.
/// * [`FileFacts::Unknown`] — the platform could not establish them. The reason
///   is carried so a refusal can name it, because "we could not tell" and "we
///   checked and it is fine" demand opposite responses and must never collapse
///   into the same answer.
///
/// ADR-0058 Decision 2 is the rule this type exists to support: **unknown is a
/// refusal**. A permissive default that read `Unknown` as "one name, safe" would
/// be exactly the bypass the finding describes, reached through a different door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFacts {
    /// The path does not exist.
    Absent,
    /// The platform established the facts about the file.
    Known {
        /// How many directory entries name this file's inode.
        ///
        /// One means no second name can reach it. More than one means a second
        /// name exists, and any ownership rule keyed by path is bypassed by it.
        name_count: u64,
        /// The file's stable identity, where the platform can supply one.
        ///
        /// `None` inside a `Known` means the platform answered the link-count
        /// question but not the identity question. A caller that needs identity
        /// continuity must treat that as unknown rather than as "unchanged".
        identity: Option<FileId>,
    },
    /// The platform could not establish the facts.
    Unknown {
        /// The platform that could not answer, named so a refusal can say why.
        platform: &'static str,
    },
}

/// What the platform established about the file behind SQLite's main-database
/// handle.
///
/// # Why this is not a [`FileFacts`]
///
/// An open connection cannot have an absent main database, and a handle that was
/// inspected always has an identity — the two optional states in `FileFacts` do
/// not exist here. Keeping the types separate makes "we inspected the handle but
/// it had no identity" unrepresentable rather than a case every caller must
/// remember to refuse.
///
/// # Why `NotApplicable` is not a pass
///
/// It is returned only by a platform that genuinely has no API for the question.
/// It means the caller's only identity evidence is the path observation, whose
/// limits are documented at the call site. A platform that has the API but could
/// not use it must answer [`SqliteMainFacts::Unknown`], because on Windows every
/// failure to inspect the handle is a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteMainFacts {
    /// This platform does not expose the connection's native main-database handle.
    NotApplicable,
    /// The platform inspected the file SQLite actually opened.
    Known {
        /// How many directory entries name the opened file.
        name_count: u64,
        /// The opened file's stable identity.
        identity: FileId,
    },
    /// The platform supports the check but could not establish the facts.
    Unknown {
        /// The platform that could not answer, named so a refusal can say why.
        platform: &'static str,
    },
}

/// A borrowed SQLite connection, erased so the portable core does not depend on
/// `rusqlite`.
///
/// # Why this exists
///
/// The only way to learn which file SQLite *actually* opened is to ask the
/// connection for its native main-database handle. That operation is
/// platform-specific and lives in `orxnud-platform-fs`; naming
/// `rusqlite::Connection` here would make `orxnud-domain` depend on SQLite and on
/// a C build, which the layering forbids. This wrapper carries the borrow without
/// naming the type.
///
/// # What the platform may assume
///
/// The connection is alive for the duration of the call. The platform must not
/// retain the borrow, close any handle, or take ownership. A platform that does
/// not recognise the erased type must answer [`SqliteMainFacts::Unknown`], never
/// [`SqliteMainFacts::NotApplicable`] — the latter is reserved for platforms that
/// have no such API at all.
#[derive(Clone, Copy)]
pub struct SqliteMainDatabase<'a> {
    connection: &'a dyn std::any::Any,
}

impl<'a> SqliteMainDatabase<'a> {
    /// Wraps a live connection for the duration of one observation.
    #[must_use]
    pub fn new<T: std::any::Any>(connection: &'a T) -> Self {
        Self { connection }
    }

    /// The erased connection, for a platform implementation that knows the
    /// concrete type.
    #[must_use]
    pub fn downcast_ref<T: std::any::Any>(&self) -> Option<&T> {
        self.connection.downcast_ref::<T>()
    }
}

/// The filesystem-identity capability ADR-0058 requires.
///
/// # The direction
///
/// The core defines the trait; `orxnud-platform-fs` implements it. That is the
/// arrangement every other contract in this module follows, and it is what lets
/// `orxnud-store` — which may depend on `orxnud-domain` and on no platform crate
/// — require the capability without naming an operating system.
///
/// # Why the observation is one call
///
/// The two facts that matter — how many names the file has, and which file it is
/// — are asked together on purpose. Two separate calls would be two separate
/// resolutions of the same path, and the file could change between them; the
/// pair would then describe two different files while looking like one
/// observation. One call is one resolution, so what it reports is internally
/// consistent.
pub trait FilesystemIdentity {
    /// What the platform can establish about `path`.
    ///
    /// Implementations must not invent a safe-looking answer. A metadata error,
    /// an unsupported platform, and a path that does not exist are three
    /// different facts and map to three different states.
    #[must_use]
    fn observe(&self, path: &std::path::Path) -> FileFacts;

    /// What the platform can establish about the file behind the main-database
    /// handle of `connection`.
    ///
    /// This is a second, independent observation. The path observation above can
    /// be invalidated by a rename between the check and SQLite's own open; the
    /// handle is the file SQLite is actually using. A platform that cannot
    /// inspect the handle must say so, and on Windows every failure to do so is
    /// a refusal rather than a fallback to the path check.
    #[must_use]
    fn observe_sqlite_main(&self, connection: SqliteMainDatabase<'_>) -> SqliteMainFacts;
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
    ///
    /// # Errors
    ///
    /// The implementation's error if no secret store is available, or the
    /// reference cannot be resolved.
    fn get(&self, reference: &SecretRef) -> Result<SecretLookup, Self::Error>;

    /// Stores a value. Used by an explicit user action, never automatically.
    ///
    /// # Errors
    ///
    /// The implementation's error if no secret store is available, or the write
    /// fails. A caller must treat failure as a refusal, never as "stored
    /// anyway".
    fn set(&self, reference: &SecretRef, value: &str) -> Result<(), Self::Error>;

    /// Removes a stored value.
    ///
    /// # Errors
    ///
    /// The implementation's error if no secret store is available, or the delete
    /// fails.
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
    ///
    /// # Errors
    ///
    /// The implementation's error if no transport exists or delivery fails. A
    /// caller should check [`Self::is_available`] first; Phase 1 has no
    /// interface, so this is expected to fail rather than to silently succeed.
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
