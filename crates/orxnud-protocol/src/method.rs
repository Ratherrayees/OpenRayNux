//! Method names.
//!
//! A closed set, as data rather than as string literals scattered across the
//! codebase. Two reasons:
//!
//! 1. **A typo becomes a compile error**, not a runtime "unknown method".
//! 2. **The set is the interface surface**, and a closed set is what makes
//!    "interfaces depend only on protocol types" enforceable in review.
//!
//! Phase 1 registers only what the foundation actually needs. No domain
//! methods exist yet, because there are no domains (docs-13 §8), and inventing
//! method names for capabilities that do not exist would be speculative.

use serde::{Deserialize, Serialize};

/// A protocol method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Method {
    /// Liveness and identity. The only method that must always exist.
    DaemonStatus,
    /// The daemon's protocol version range.
    DaemonVersion,
    /// Which capabilities are registered and their health.
    ///
    /// Returns an empty registry in Phase 1. Present because the protocol needs
    /// to be *discoverable*, not because a capability exists.
    CapabilityList,
    /// A round-trip used to measure latency and confirm the transport.
    ///
    /// Namespaced like every other method. An unnamespaced `echo` would be the
    /// first name in a flat namespace, and flat namespaces collide as the surface
    /// grows — which is the whole reason this is a closed enum.
    Echo,
    /// Invoke a capability through the governed path.
    ///
    /// The request carries an `ActionRequest`-shaped payload. The name is the only
    /// thing this crate contributes: what it *means*, whether it is permitted, and
    /// whether it runs are decided by `orxnud-policy` and `orxnud-capability`, and
    /// this enum cannot express any of that. A peer that can call it has asked for
    /// something; whether it happens is a separate and much stricter question.
    CapabilityDispatch,
}

impl Method {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DaemonStatus => "daemon/status",
            Self::DaemonVersion => "daemon/version",
            Self::CapabilityList => "capability/list",
            Self::Echo => "daemon/echo",
            Self::CapabilityDispatch => "capability/dispatch",
        }
    }

    /// Whether this method may be called before version negotiation completes.
    #[must_use]
    pub fn is_available_pre_negotiation(self) -> bool {
        matches!(self, Self::DaemonVersion)
    }

    /// Parses a wire name.
    #[must_use]
    pub fn from_wire(name: &str) -> Option<Self> {
        match name {
            "daemon/status" => Some(Self::DaemonStatus),
            "daemon/version" => Some(Self::DaemonVersion),
            "capability/list" => Some(Self::CapabilityList),
            "daemon/echo" => Some(Self::Echo),
            "capability/dispatch" => Some(Self::CapabilityDispatch),
            _ => None,
        }
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every registered method name, for the dispatcher's coverage test.
#[must_use]
pub fn all_method_names() -> Vec<&'static str> {
    vec![
        Method::DaemonStatus.as_str(),
        Method::DaemonVersion.as_str(),
        Method::CapabilityList.as_str(),
        Method::Echo.as_str(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_are_unique() {
        let mut names = all_method_names();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate method name");
    }

    #[test]
    fn round_trip_through_wire_names() {
        for name in all_method_names() {
            let m = Method::from_wire(name).expect("registered name must parse");
            assert_eq!(m.as_str(), name);
        }
    }

    #[test]
    fn unknown_names_do_not_parse() {
        // Forward compatibility: a newer client may call something we lack, and
        // the dispatcher turns this into a clean method-not-found.
        assert!(Method::from_wire("domain/jobs/apply").is_none());
        assert!(Method::from_wire("").is_none());
    }

    #[test]
    fn only_version_is_available_before_negotiation() {
        assert!(Method::DaemonVersion.is_available_pre_negotiation());
        for m in [Method::DaemonStatus, Method::CapabilityList, Method::Echo] {
            assert!(
                !m.is_available_pre_negotiation(),
                "{m} should require negotiation"
            );
        }
    }

    #[test]
    fn method_names_are_namespaced() {
        // A flat namespace would make collisions likely as the surface grows.
        for name in all_method_names() {
            assert!(name.contains('/'), "method {name} is not namespaced");
        }
    }
}
