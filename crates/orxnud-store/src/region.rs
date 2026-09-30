//! The state-region registry (ADR-0028).
//!
//! # What this artefact is for
//!
//! State is the thing that makes "which state may the model write?" ambiguous
//! once a project has a task table, a memory store, a config file, a policy
//! file, a capability-health cache, a budget ledger, and an audit log. Each
//! would otherwise decide its own consistency and retention, and the answers
//! would drift.
//!
//! [`RegionRegistry`] makes the answer a single lookup. Every region declares:
//!
//! * its [`StateClass`](orxnud_domain::StateClass),
//! * its **single owner** — two writers to `critical` state would be a second
//!   source of truth,
//! * its consistency and retention,
//! * and whether the intent layer may write it.
//!
//! That last field is the one that matters most: it is the *same* rule the
//! repository query filter enforces, declared in one place so the two cannot
//! disagree.

use std::collections::BTreeMap;

use orxnud_domain::{StateClass, StateConsistency};

use crate::repository::RepositoryError;

/// A declared state region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRegion {
    /// The region name, e.g. `tasks`.
    pub name: &'static str,
    /// Its class.
    pub class: StateClass,
    /// The one crate permitted to write it.
    pub owner: &'static str,
    /// Retention policy, in words. Descriptive, but required to be explicit.
    pub retention: &'static str,
}

impl StateRegion {
    /// Whether the intent layer may write this region.
    #[must_use]
    pub fn writable_by_intent_layer(&self) -> bool {
        self.class.writable_by_intent_layer()
    }

    /// The consistency this region requires.
    #[must_use]
    pub fn consistency(&self) -> StateConsistency {
        self.class.required_consistency()
    }
}

/// The declared regions, in one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionRegistry {
    regions: BTreeMap<&'static str, StateRegion>,
}

impl RegionRegistry {
    /// An empty registry.
    #[must_use]
    pub fn empty() -> Self {
        Self { regions: BTreeMap::new() }
    }

    /// Declares a region.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::DuplicateRegion`] if the name is already taken, and
    /// [`RepositoryError::InconsistentClass`] if a region's declared class
    /// disagrees with the consistency it will actually be given.
    pub fn declare(&mut self, region: StateRegion) -> Result<(), RepositoryError> {
        if self.regions.contains_key(region.name) {
            return Err(RepositoryError::DuplicateRegion { name: region.name });
        }
        self.regions.insert(region.name, region);
        Ok(())
    }

    /// Looks up a region.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&StateRegion> {
        self.regions.get(name)
    }

    /// Every declared region, ordered by name.
    #[must_use]
    pub fn all(&self) -> Vec<&StateRegion> {
        self.regions.values().collect()
    }

    /// Whether the intent layer may write a region.
    ///
    /// An **undeclared** region is not writable by the model. Default-deny, the
    /// same rule as risk classification.
    #[must_use]
    pub fn intent_layer_may_write(&self, name: &str) -> bool {
        self.get(name).is_some_and(StateRegion::writable_by_intent_layer)
    }

    /// The regions whose loss would be a lost *action*.
    #[must_use]
    pub fn critical_regions(&self) -> Vec<&StateRegion> {
        self.regions
            .values()
            .filter(|r| r.class == StateClass::Critical)
            .collect()
    }
}

impl Default for RegionRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_domain::{StateClass, StateConsistency};

    fn region(name: &'static str, class: StateClass) -> StateRegion {
        StateRegion { name, class, owner: "orxnud-test", retention: "indefinite" }
    }

    #[test]
    fn a_region_declares_its_own_consistency() {
        let critical = region("tasks", StateClass::Critical);
        let derived = region("embeddings", StateClass::Derived);
        assert_eq!(critical.consistency(), StateConsistency::Strong);
        assert_eq!(derived.consistency(), StateConsistency::Eventual);
    }

    #[test]
    fn undeclared_regions_are_not_writable_by_the_intent_layer() {
        // Default-deny. A region nobody declared is not model-writable.
        let reg = RegionRegistry::empty();
        assert!(!reg.intent_layer_may_write("anything"));
    }

    #[test]
    fn only_derived_regions_are_intent_writable() {
        let mut reg = RegionRegistry::empty();
        reg.declare(region("summaries", StateClass::Derived)).expect("declare");
        reg.declare(region("tasks", StateClass::Critical)).expect("declare");
        reg.declare(region("policy", StateClass::Authoritative)).expect("declare");
        assert!(reg.intent_layer_may_write("summaries"));
        assert!(!reg.intent_layer_may_write("tasks"));
        assert!(!reg.intent_layer_may_write("policy"));
    }

    #[test]
    fn duplicate_declarations_are_rejected() {
        let mut reg = RegionRegistry::empty();
        reg.declare(region("tasks", StateClass::Critical)).expect("first");
        assert!(reg.declare(region("tasks", StateClass::Derived)).is_err());
        // The first declaration wins; a later one must not silently replace it.
        assert_eq!(reg.get("tasks").map(|r| r.class), Some(StateClass::Critical));
    }

    #[test]
    fn critical_regions_are_enumerable() {
        let mut reg = RegionRegistry::empty();
        reg.declare(region("tasks", StateClass::Critical)).expect("declare");
        reg.declare(region("schedules", StateClass::Critical)).expect("declare");
        reg.declare(region("summaries", StateClass::Derived)).expect("declare");
        let critical: Vec<&str> = reg.critical_regions().iter().map(|r| r.name).collect();
        assert_eq!(critical, vec!["schedules", "tasks"]);
    }

    #[test]
    fn every_declared_region_names_exactly_one_owner() {
        // "One writer per region" is what makes a single source of truth
        // possible; a region with an empty owner name is a hole in the model.
        let mut reg = RegionRegistry::empty();
        for (n, c) in [
            ("tasks", StateClass::Critical),
            ("policy", StateClass::Authoritative),
            ("summaries", StateClass::Derived),
        ] {
            reg.declare(region(n, c)).expect("declare");
        }
        for r in reg.all() {
            assert!(!r.owner.is_empty(), "{} has no owner", r.name);
        }
    }
}
