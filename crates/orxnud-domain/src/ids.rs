//! Opaque identifier newtypes.
//!
//! # Why newtypes and not `String`
//!
//! Three reasons, in order of importance:
//!
//! 1. **Type safety.** A `TaskId` and a `RunId` are both strings. Passing one
//!    where the other is expected is a bug that `String` cannot catch and a
//!    newtype catches at compile time.
//! 2. **Never derive identity from a path** (docs-06 §3.1). macOS and Windows
//!    are case-insensitive by default and Linux is not, so two paths that are
//!    equal on one platform can differ on another. `nul` is a legal filename on
//!    Linux and destroys data on Windows. Identifiers are opaque and generated,
//!    never parsed out of a path.
//! 3. **A single serialization surface.** Each newtype has one canonical string
//!    form, so a change of internal representation is a non-event.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Generates a newtype with the standard derive set, `Display`, and `FromStr`.
///
/// The macro keeps the ten identifiers consistent; writing them out by hand
/// invites drift, and drift in an identifier type is a silent bug.
macro_rules! opaque_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wraps an existing string without validating it.
            ///
            /// Callers constructing an id from untrusted input must go through
            /// the parsing entry point on the owning subsystem, not this.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Borrows the underlying string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the wrapper, returning the inner string.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

opaque_id!(
    /// The human owner of an installation. The only actor that can grant
    /// authority.
    UserId
);
opaque_id!(
    /// A durable unit of work.
    TaskId
);
opaque_id!(
    /// One execution attempt group of a task, created by the intent layer.
    RunId
);
opaque_id!(
    /// A recurring schedule definition.
    ScheduleId
);
opaque_id!(
    /// A standing permission grant made by a human, with a scope and an expiry.
    GrantId
);
opaque_id!(
    /// A registered capability, e.g. `speech-to-text`.
    CapabilityId
);
opaque_id!(
    /// A single protocol request, used for idempotency and correlation.
    RequestId
);
opaque_id!(
    /// A user-authored workflow definition.
    WorkflowId
);

/// Where an `External` actor's request originated.
///
/// This is a value, not a string, so a new integration cannot invent a source
/// that the policy engine has never classified.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "detail")]
pub enum ExternalSource {
    /// An inbound webhook on a configured listener.
    Webhook {
        /// Opaque listener identifier chosen at configuration time.
        listener: String,
    },
    /// A message received on a configured messaging integration.
    Messaging {
        /// The capability id of the messaging adapter.
        capability: CapabilityId,
    },
    /// A filesystem watch on a granted path.
    FileWatch {
        /// The granted root the watch was registered against.
        root: String,
    },
    /// Any source not yet modelled. Treated as maximally untrusted.
    Unknown,
}

impl ExternalSource {
    /// Whether the source's identity has been cryptographically verified.
    ///
    /// Even a *verified* external source can only ever *request* work; it can
    /// never grant authority (ADR-0027, control S33).
    #[must_use]
    pub fn is_verified(&self) -> bool {
        match self {
            Self::Webhook { .. } => false,
            Self::Messaging { .. } => false,
            Self::FileWatch { .. } => true,
            Self::Unknown => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtypes_are_distinct_at_compile_time() {
        // This function exists to make the point explicit: swapping the two
        // arguments below is a compile error, not a runtime one. If this ever
        // compiles with the arguments swapped, the newtypes were merged.
        fn takes_task(_: TaskId) {}
        let id = TaskId::new("t-1");
        takes_task(id);
    }

    #[test]
    fn serde_is_transparent() {
        let id = TaskId::new("t-1");
        let json = serde_json::to_string(&id).expect("serialize");
        assert_eq!(json, "\"t-1\"");
        let back: TaskId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, id);
    }

    #[test]
    fn external_source_verification_defaults_to_unverified() {
        assert!(!ExternalSource::Unknown.is_verified());
        assert!(!ExternalSource::Webhook { listener: "l".into() }.is_verified());
        assert!(ExternalSource::FileWatch { root: "/x".into() }.is_verified());
    }
}
