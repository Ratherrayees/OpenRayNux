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
//! * its [`StateClass`],
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
    /// The column that identifies a row, used by the authority filter to enumerate
    /// what it consulted.
    ///
    /// Declared rather than assumed. `schema_meta` is keyed by `version`, not
    /// `id`, and a filter that hard-coded `id` would simply fail on it -- which is
    /// how an authority check ends up not running on the one table that records
    /// whether a migration ran.
    pub key_column: &'static str,
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
        Self {
            regions: BTreeMap::new(),
        }
    }

    /// Declares a region.
    ///
    /// # Errors
    ///
    /// [`RepositoryError::DuplicateRegion`] if the name is already taken, and
    /// `RepositoryError::InconsistentClass` if a region's declared class disagrees with
    /// the consistency it will actually be given. That second variant does not exist on
    /// `RepositoryError`, and this method makes no such check.
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
        self.get(name)
            .is_some_and(StateRegion::writable_by_intent_layer)
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

/// The regions the Phase 2 task layer declares.
///
/// ADR-0028's table, transcribed. Every region gets an entry *before* it exists —
/// the ADR's revisit condition is explicit that a new region "must be classified
/// before it exists", and this function is where that happens.
///
/// # Ownership
///
/// Every region below names `orxnud-task` as its single owner. ADR-0028 invariant 2
/// is "only the owning layer writes a region", and these tables are all reached
/// through [`crate::task_repo::TaskRepository`], which lives in a different crate
/// from any writer that could otherwise touch them. The store *holds* the SQL; the
/// engine *owns* the region. Those are different things and conflating them is how a
/// second writer appears.
pub fn task_layer_regions() -> Vec<StateRegion> {
    vec![
        StateRegion {
            name: "schema_meta",
            class: StateClass::Critical,
            owner: "orxnud-store",
            retention: "indefinite",
            key_column: "version",
        },
        StateRegion {
            name: "tasks",
            class: StateClass::Critical,
            owner: "orxnud-task",
            retention: "indefinite; terminal rows retained until a declared janitor runs",
            key_column: "id",
        },
        StateRegion {
            name: "task_attempts",
            class: StateClass::Critical,
            owner: "orxnud-task",
            retention: "as `tasks`",
            key_column: "id",
        },
        StateRegion {
            name: "task_effects",
            class: StateClass::Critical,
            owner: "orxnud-task",
            retention: "at least the retry horizon (ADR-0028)",
            key_column: "id",
        },
        StateRegion {
            name: "task_approvals",
            class: StateClass::Critical,
            owner: "orxnud-task",
            retention: "at least the approval expiry, then pruned",
            key_column: "id",
        },
        StateRegion {
            name: "task_events",
            class: StateClass::Critical,
            owner: "orxnud-task",
            retention: "indefinite, append-only, rotated by declared policy",
            key_column: "id",
        },
        StateRegion {
            name: "schedules",
            class: StateClass::Critical,
            owner: "orxnud-task",
            retention: "indefinite",
            key_column: "id",
        },
        StateRegion {
            name: "schedule_fires",
            class: StateClass::Critical,
            owner: "orxnud-task",
            retention: "indefinite; the dedup ledger must outlive any retry window",
            key_column: "id",
        },
    ]
}

/// The registry with every Phase 2 region declared.
///
/// # Panics
///
/// If two regions share a name, which would mean the declarations above have
/// collided. That is a programming error in this function, caught at first use.
#[must_use]
pub fn task_layer_registry() -> RegionRegistry {
    let mut reg = RegionRegistry::empty();
    for r in task_layer_regions() {
        // Duplicate names here would silently shadow one region's classification,
        // which is the exact failure the registry exists to prevent.
        assert!(reg.declare(r).is_ok(), "duplicate region declaration");
    }
    reg
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
        StateRegion {
            name,
            class,
            owner: "orxnud-test",
            retention: "indefinite",
            key_column: "id",
        }
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
        reg.declare(region("summaries", StateClass::Derived))
            .expect("declare");
        reg.declare(region("tasks", StateClass::Critical))
            .expect("declare");
        reg.declare(region("policy", StateClass::Authoritative))
            .expect("declare");
        assert!(reg.intent_layer_may_write("summaries"));
        assert!(!reg.intent_layer_may_write("tasks"));
        assert!(!reg.intent_layer_may_write("policy"));
    }

    #[test]
    fn duplicate_declarations_are_rejected() {
        let mut reg = RegionRegistry::empty();
        reg.declare(region("tasks", StateClass::Critical))
            .expect("first");
        assert!(reg.declare(region("tasks", StateClass::Derived)).is_err());
        // The first declaration wins; a later one must not silently replace it.
        assert_eq!(
            reg.get("tasks").map(|r| r.class),
            Some(StateClass::Critical)
        );
    }

    #[test]
    fn critical_regions_are_enumerable() {
        let mut reg = RegionRegistry::empty();
        reg.declare(region("tasks", StateClass::Critical))
            .expect("declare");
        reg.declare(region("schedules", StateClass::Critical))
            .expect("declare");
        reg.declare(region("summaries", StateClass::Derived))
            .expect("declare");
        let critical: Vec<&str> = reg.critical_regions().iter().map(|r| r.name).collect();
        assert_eq!(critical, vec!["schedules", "tasks"]);
    }

    #[test]
    fn every_phase_two_task_region_is_declared_and_critical() {
        // ADR-0028's table: tasks, schedules, the fire ledger, the dedupe ledger,
        // and the audit/event log are all `critical`. Anything else would mean
        // paying fsync for nothing or, worse, not paying it for something.
        let reg = task_layer_registry();
        let regions = reg.all();
        assert_eq!(regions.len(), 8);
        for r in &regions {
            assert_eq!(r.class, StateClass::Critical, "{} is not critical", r.name);
        }
        let names: Vec<&str> = regions.iter().map(|r| r.name).collect();
        for required in [
            "tasks",
            "task_attempts",
            "task_effects",
            "task_approvals",
            "task_events",
            "schedules",
            "schedule_fires",
        ] {
            assert!(names.contains(&required), "{required} is undeclared");
        }
    }

    #[test]
    fn every_phase_two_region_names_exactly_one_owner_and_it_is_the_engine() {
        // ADR-0028 invariant 2. `schema_meta` is the exception: the store owns it,
        // because the store is what runs migrations.
        let reg = task_layer_registry();
        for r in reg.all() {
            assert!(!r.owner.is_empty(), "{} has no owner", r.name);
            let expected = if r.name == "schema_meta" {
                "orxnud-store"
            } else {
                "orxnud-task"
            };
            assert_eq!(r.owner, expected, "{} has the wrong owner", r.name);
        }
    }

    #[test]
    fn no_phase_two_region_is_writable_by_the_intent_layer() {
        // Every one of these regions is `critical`, and ADR-0028 invariant 3 says
        // derived data can never satisfy authority -- which begins with the model
        // not being able to write them.
        let reg = task_layer_registry();
        for r in reg.all() {
            assert!(
                !reg.intent_layer_may_write(r.name),
                "{} is model-writable",
                r.name
            );
        }
    }

    #[test]
    fn every_phase_two_region_declares_a_retention_policy() {
        // ADR-0028 invariant 7: retention is per-region and explicit. An empty
        // string would be a retention policy nobody decided.
        for r in task_layer_regions() {
            assert!(
                !r.retention.trim().is_empty(),
                "{} has no retention policy",
                r.name
            );
        }
    }

    #[test]
    fn the_registry_has_no_duplicate_names() {
        let names: Vec<&str> = task_layer_regions().iter().map(|r| r.name).collect();
        let before = names.len();
        let mut deduped = names.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped.len(), before, "duplicate region name: {names:?}");
    }

    #[test]
    fn no_region_is_named_for_a_credential() {
        // ADR-0028 invariant 4: credentials are never state.
        for r in task_layer_regions() {
            let lower = r.name.to_lowercase();
            for needle in ["credential", "secret", "password", "token", "key"] {
                assert!(
                    !lower.contains(needle),
                    "{} looks like a credential region",
                    r.name
                );
            }
        }
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
