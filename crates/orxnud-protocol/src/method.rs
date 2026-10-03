//! Method names.
//!
//! A closed set, as data rather than as string literals scattered across the
//! codebase. Two reasons:
//!
//! 1. **A typo becomes a compile error**, not a runtime "unknown method".
//! 2. **The set is the interface surface**, and a closed set is what makes
//!    "interfaces depend only on protocol types" enforceable in review.
//!
//! The `task/*` methods are the first domain surface. They are here because the
//! durable task engine already existed and was already correct, so naming them was
//! not speculative — it was the smallest addition that made real state reachable
//! from a real client. Capability methods are still only the ones that exist:
//! inventing a name for a capability nobody has registered would be.

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
    /// Enqueue a task.
    ///
    /// First-party durable state, not a capability invocation. That distinction is
    /// the whole reason this method exists separately from
    /// [`Self::CapabilityDispatch`]: a task is a row this daemon owns, and routing it
    /// through the governed dispatcher would mean asking the policy engine to
    /// authorise the daemon writing its own queue.
    TaskCreate,
    /// Every task, ordered by id.
    TaskList,
    /// Take a lease on one named task.
    ///
    /// The lease is what makes the later completion legitimate: the worker that
    /// claims is the worker that may report, and only while the lease is live.
    TaskClaim,
    /// Record a terminal outcome for a task the caller holds a live lease on.
    ///
    /// Cannot turn a `pending` task into `completed`: the queue contract requires
    /// `running` first, and the method does not have a path that skips it.
    TaskComplete,
    /// Cancel a task.
    ///
    /// Deliberately takes no worker identity, unlike [`Self::TaskComplete`]. That
    /// asymmetry is the engine's, not this enum's: cancellation is a decision about
    /// the *task* and clears whatever lease it holds, whereas completion is a report
    /// from the holder of that lease and is fenced by it. A cancel that had to name a
    /// worker could not cancel an unclaimed task at all.
    TaskCancel,
}

impl Method {
    /// Every registered method, in a fixed order.
    ///
    /// The single place the set is written down. `all_method_names` reads it, so a
    /// new variant cannot be added without appearing there too.
    pub const ALL: [Self; 10] = [
        Self::DaemonStatus,
        Self::DaemonVersion,
        Self::CapabilityList,
        Self::Echo,
        Self::CapabilityDispatch,
        Self::TaskCreate,
        Self::TaskList,
        Self::TaskClaim,
        Self::TaskComplete,
        Self::TaskCancel,
    ];

    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DaemonStatus => "daemon/status",
            Self::DaemonVersion => "daemon/version",
            Self::CapabilityList => "capability/list",
            Self::Echo => "daemon/echo",
            Self::CapabilityDispatch => "capability/dispatch",
            Self::TaskCreate => "task/create",
            Self::TaskList => "task/list",
            Self::TaskClaim => "task/claim",
            Self::TaskComplete => "task/complete",
            Self::TaskCancel => "task/cancel",
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
            "task/create" => Some(Self::TaskCreate),
            "task/list" => Some(Self::TaskList),
            "task/claim" => Some(Self::TaskClaim),
            "task/complete" => Some(Self::TaskComplete),
            "task/cancel" => Some(Self::TaskCancel),
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
///
/// **Every** method. This previously listed four names and omitted
/// `capability/dispatch`, so a coverage check built on it would have reported a
/// dispatcher that answered every method while never exercising one of them. The
/// list is now derived from the enum, which is the only thing that cannot fall
/// behind.
#[must_use]
pub fn all_method_names() -> Vec<&'static str> {
    Method::ALL.map(Method::as_str).to_vec()
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
    fn every_method_is_listed_in_all_method_names() {
        // The list is what a coverage test iterates. A method missing from it is a
        // method the suite silently never calls, which is how `capability/dispatch`
        // went untested by the coverage test that was supposed to cover it.
        assert_eq!(
            all_method_names().len(),
            Method::ALL.len(),
            "all_method_names must not omit a method"
        );
        for m in Method::ALL {
            assert!(
                all_method_names().contains(&m.as_str()),
                "{m} is missing from all_method_names"
            );
        }
    }

    #[test]
    fn only_version_is_available_before_negotiation() {
        assert!(Method::DaemonVersion.is_available_pre_negotiation());
        for m in Method::ALL
            .into_iter()
            .filter(|m| *m != Method::DaemonVersion)
        {
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
