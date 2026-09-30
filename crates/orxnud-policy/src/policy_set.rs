//! Grants and the policy set: the *configuration* the engine reads.
//!
//! # Configuration, not code
//!
//! A grant is data (ADR-0018 layer 8). Adding a permission is a configuration
//! change, never a code change — which is what makes "a second user customises
//! without forking" true (NFR-08).
//!
//! # Grants expire and are scoped
//!
//! A grant carries a scope, an expiry, and a revocation path (control S33).
//! There is deliberately no "always allowed" variant: an unbounded grant is a
//! standing permission that outlives the reason it was given, which is how
//! least-privilege quietly becomes no-privilege.

use std::collections::BTreeMap;

use orxnud_domain::enums::DataClass;
use orxnud_domain::ids::{CapabilityId, GrantId, UserId};
use serde::{Deserialize, Serialize};

/// A standing permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Which grant.
    pub id: GrantId,
    /// The human who made it. A grant made by an AI is not a grant.
    pub granted_by: UserId,
    /// Which capability it authorises.
    pub capability: CapabilityId,
    /// The highest data class it permits. `Regulated` is never granted here;
    /// regulated egress requires a per-flow consent, not a standing grant.
    pub max_data_class: DataClass,
    /// Whether this grant permits *creating* other grants. Always false in
    /// Phase 1; a grant that could mint grants is an authority escalation.
    pub may_grant: bool,
    /// Expiry, ms since epoch.
    pub expires_at_ms: i64,
    /// Whether the grant has been revoked.
    pub revoked: bool,
}

impl Grant {
    /// Whether the grant is usable at `now_ms`.
    #[must_use]
    pub fn is_valid_at(&self, now_ms: i64) -> bool {
        !self.revoked && !self.may_grant && now_ms < self.expires_at_ms
    }

    /// Whether the grant covers a data class.
    #[must_use]
    pub fn covers_data_class(&self, class: DataClass) -> bool {
        class <= self.max_data_class
    }
}

/// The full policy configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySet {
    /// A version string, recorded in every audit record. Policy is versioned so
    /// a historical decision can be interpreted against the rules that produced
    /// it.
    pub version: String,
    /// Grants, keyed by id.
    pub grants: BTreeMap<GrantId, Grant>,
    /// Data classes permitted to transit an external provider without a
    /// per-flow consent. `Regulated` is never in here.
    pub consented_egress: BTreeMap<DataClass, bool>,
}

impl PolicySet {
    /// A policy set that permits nothing. The Phase 1 default.
    ///
    /// Deny-by-default: an empty set means every action is refused, which is the
    /// correct starting point for a system whose capabilities have not been
    /// reviewed yet.
    #[must_use]
    pub fn deny_all(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            grants: BTreeMap::new(),
            consented_egress: BTreeMap::new(),
        }
    }

    /// Adds a grant.
    #[must_use]
    pub fn with_grant(mut self, grant: Grant) -> Self {
        self.grants.insert(grant.id.clone(), grant);
        self
    }

    /// Finds a valid grant for a capability at `now_ms`.
    #[must_use]
    pub fn find_grant(
        &self,
        capability: &CapabilityId,
        now_ms: i64,
    ) -> Option<(&Grant, GrantLookup)> {
        self.grants
            .values()
            .find(|g| g.capability == *capability)
            .map(|g| {
                let lookup = if g.revoked {
                    GrantLookup::Revoked
                } else if now_ms >= g.expires_at_ms {
                    GrantLookup::Expired(g.expires_at_ms)
                } else {
                    GrantLookup::Valid
                };
                (g, lookup)
            })
    }

    /// Whether a data class has standing egress consent.
    #[must_use]
    pub fn egress_consented(&self, class: DataClass) -> bool {
        // Regulated data is never consented by standing policy (NR-02 / S18).
        if class.is_blocked_by_default() {
            return false;
        }
        self.consented_egress.get(&class).copied().unwrap_or(false)
    }
}

/// Why a grant lookup succeeded or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantLookup {
    /// Usable now.
    Valid,
    /// Revoked.
    Revoked,
    /// Expired at the given time.
    Expired(i64),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(expires: i64) -> Grant {
        Grant {
            id: GrantId::new("g-1"),
            granted_by: UserId::new("u-1"),
            capability: CapabilityId::new("send-message"),
            max_data_class: DataClass::Personal,
            may_grant: false,
            expires_at_ms: expires,
            revoked: false,
        }
    }

    #[test]
    fn an_empty_policy_set_denies_everything() {
        let p = PolicySet::deny_all("v1");
        assert!(p.grants.is_empty());
        assert!(p.find_grant(&CapabilityId::new("anything"), 0).is_none());
        assert!(!p.egress_consented(DataClass::Public));
    }

    #[test]
    fn grant_validity_is_half_open_in_time() {
        let g = grant(1000);
        assert!(g.is_valid_at(0));
        assert!(g.is_valid_at(999));
        assert!(!g.is_valid_at(1000));
        assert!(!g.is_valid_at(1001));
    }

    #[test]
    fn a_revoked_grant_is_never_valid() {
        let mut g = grant(i64::MAX);
        g.revoked = true;
        assert!(!g.is_valid_at(0));
    }

    #[test]
    fn a_grant_that_may_grant_is_never_valid() {
        // A grant that could mint grants is an authority escalation, so the
        // lookup treats it as unusable rather than special-casing it.
        let mut g = grant(i64::MAX);
        g.may_grant = true;
        assert!(!g.is_valid_at(0));
    }

    #[test]
    fn lookup_distinguishes_valid_revoked_and_expired() {
        let mut p = PolicySet::deny_all("v1").with_grant(grant(1000));
        let cap = CapabilityId::new("send-message");
        assert_eq!(
            p.find_grant(&cap, 500).map(|(_, l)| l),
            Some(GrantLookup::Valid)
        );
        assert_eq!(
            p.find_grant(&cap, 1000).map(|(_, l)| l),
            Some(GrantLookup::Expired(1000))
        );

        let mut g = grant(1000);
        g.revoked = true;
        p = PolicySet::deny_all("v1").with_grant(g);
        assert_eq!(
            p.find_grant(&cap, 0).map(|(_, l)| l),
            Some(GrantLookup::Revoked)
        );
    }

    #[test]
    fn grants_cover_only_their_own_data_class_and_below() {
        let g = grant(i64::MAX);
        assert!(g.covers_data_class(DataClass::Public));
        assert!(g.covers_data_class(DataClass::Personal));
        assert!(!g.covers_data_class(DataClass::Sensitive));
        assert!(!g.covers_data_class(DataClass::Regulated));
    }

    #[test]
    fn regulated_data_is_never_consented_by_standing_policy() {
        // NR-02: regulated egress requires a per-flow consent, not a standing
        // grant. Even if configuration tried to allow it, the check refuses.
        let mut p = PolicySet::deny_all("v1");
        p.consented_egress.insert(DataClass::Regulated, true);
        p.consented_egress.insert(DataClass::Sensitive, true);
        assert!(!p.egress_consented(DataClass::Regulated));
        assert!(p.egress_consented(DataClass::Sensitive));
    }

    #[test]
    fn egress_consent_defaults_to_denied() {
        let p = PolicySet::deny_all("v1");
        for c in [
            DataClass::Public,
            DataClass::Personal,
            DataClass::Sensitive,
            DataClass::Regulated,
        ] {
            assert!(!p.egress_consented(c), "{c:?} should default to denied");
        }
    }
}
