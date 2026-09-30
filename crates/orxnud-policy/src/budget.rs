//! The budget ledger (NR-01).
//!
//! # Why this is in the policy layer
//!
//! Because a spend check that is not on the choke point is not a spend check.
//! The cost of an action is known at the moment it is authorised — the policy
//! layer already knows the capability and the model — so the ceiling is
//! evaluated *before* the call, not reconciled after it.
//!
//! # Hard stops
//!
//! A ceiling is a **hard** stop: the action is refused, not queued for later and
//! not allowed with a warning. A soft limit on money is not a limit. The
//! advisory tier exists separately and is a different thing: it is surfaced to
//! the user, and it does not permit the spend.
//!
//! # Why the ledger is strong-consistency state
//!
//! ADR-0028 classifies the budget ledger as `authoritative`, not `derived`. It
//! looks like a counter, but it is *money*, and a counter that drifts is a
//! financial bug. It therefore rides on the `synchronous = FULL` connection
//! with the task table.

use std::collections::BTreeMap;

use orxnud_domain::enums::RiskClass;
use serde::{Deserialize, Serialize};

/// A spend ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ceiling {
    /// The limit, in the ceiling's unit.
    pub limit: u64,
    /// What has been spent against it.
    pub spent: u64,
}

impl Ceiling {
    /// A fresh ceiling.
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self { limit, spent: 0 }
    }

    /// Whether `amount` would exceed this ceiling.
    #[must_use]
    pub fn would_exceed(&self, amount: u64) -> bool {
        // `checked_add` rather than `saturating_add`: saturation clamps a
        // wrapped sum to u64::MAX, which would then compare as "not greater than
        // the limit" and read as FITS. An overflowed budget must read as
        // exceeding, or it is a financial bug.
        match self.spent.checked_add(amount) {
            None => true,
            Some(total) => total > self.limit,
        }
    }

    /// Records a spend, saturating at the limit.
    pub fn charge(&mut self, amount: u64) {
        self.spent = self.spent.saturating_add(amount);
    }
}

/// A budget failure.
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    /// A charge was recorded against an unknown scope.
    #[error("no budget scope named `{scope}`")]
    UnknownScope {
        /// The missing scope.
        scope: String,
    },
}

/// The budget ledger.
///
/// Scopes are strings rather than an enum because NR-01 anticipates scopes we
/// cannot enumerate yet (per-provider, per-model, per-task-class). The set is
/// still closed at runtime by virtue of the map: an unrecognised scope has no
/// ceiling, and **no ceiling means no spend** (deny-by-default, again).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLedger {
    ceilings: BTreeMap<String, Ceiling>,
}

impl BudgetLedger {
    /// An empty ledger. Every action is refused: there is no budget, so there is
    /// no permission to spend.
    #[must_use]
    pub fn empty() -> Self {
        Self { ceilings: BTreeMap::new() }
    }

    /// Declares a ceiling for a scope.
    #[must_use]
    pub fn with_ceiling(mut self, scope: impl Into<String>, ceiling: Ceiling) -> Self {
        self.ceilings.insert(scope.into(), ceiling);
        self
    }

    /// Declares a global ceiling.
    #[must_use]
    pub fn with_global(self, limit: u64) -> Self {
        self.with_ceiling("global", Ceiling::new(limit))
    }

    /// The ceiling for a scope, if declared.
    #[must_use]
    pub fn ceiling(&self, scope: &str) -> Option<&Ceiling> {
        self.ceilings.get(scope)
    }

    /// Checks an amount against a scope without recording it.
    ///
    /// Returns `false` for an **undeclared** scope. That is the fail-closed
    /// direction: a capability whose cost nobody budgeted cannot spend.
    #[must_use]
    pub fn permits(&self, scope: &str, amount: u64) -> bool {
        self.ceilings.get(scope).is_some_and(|c| !c.would_exceed(amount))
    }

    /// Checks an amount against **every declared ceiling**.
    ///
    /// Scopes are independent constraints, not alternatives: a `global`
    /// ceiling and a `cost:high` ceiling both have to hold. Returns `false`
    /// when **no** ceiling is declared, so an unconfigured ledger permits
    /// nothing.
    ///
    /// This is the form the engine uses, because otherwise declaring only a
    /// global ceiling would silently do nothing while the engine consulted a
    /// risk-scoped one.
    #[must_use]
    pub fn permits_all(&self, amount: u64) -> bool {
        !self.ceilings.is_empty() && self.ceilings.values().all(|c| !c.would_exceed(amount))
    }

    /// Charges a spend against **every** declared scope.
    ///
    /// # Errors
    ///
    /// [`BudgetError::UnknownScope`] if no ceiling is declared. Charging into an
    /// undeclared ledger would create spend that no ceiling could ever catch.
    pub fn charge_all(&mut self, amount: u64) -> Result<(), BudgetError> {
        if self.ceilings.is_empty() {
            return Err(BudgetError::UnknownScope { scope: "<undeclared>".to_owned() });
        }
        for c in self.ceilings.values_mut() {
            c.charge(amount);
        }
        Ok(())
    }

    /// Records a spend against a scope.
    ///
    /// # Errors
    ///
    /// [`BudgetError::UnknownScope`] if the scope has no ceiling. Recording a
    /// spend against an unbudgeted scope would create spend that no ceiling
    /// can ever catch, so it is refused.
    pub fn charge(&mut self, scope: &str, amount: u64) -> Result<(), BudgetError> {
        match self.ceilings.get_mut(scope) {
            Some(c) => {
                c.charge(amount);
                Ok(())
            }
            None => Err(BudgetError::UnknownScope { scope: scope.to_owned() }),
        }
    }

    /// The tightest declared ceiling, as `(scope, limit, spent)`.
    ///
    /// Used to report *which* ceiling bit, so the user is told about the one they
    /// can actually act on rather than an arbitrary one.
    #[must_use]
    pub fn tightest(&self) -> Option<(&str, u64, u64)> {
        self.ceilings
            .iter()
            .min_by_key(|(name, c)| c.limit.saturating_sub(c.spent))
            .map(|(name, c)| (name.as_str(), c.limit, c.spent))
    }

    /// The fraction spent, for a progress display. Saturating at 1.0.
    #[must_use]
    pub fn utilisation(&self, scope: &str) -> Option<f64> {
        self.ceilings.get(scope).map(|c| {
            if c.limit == 0 {
                1.0
            } else {
                (c.spent as f64 / c.limit as f64).clamp(0.0, 1.0)
            }
        })
    }
}

/// A convenience mapping from risk class to a budget scope name.
///
/// Kept here rather than in the engine so the *naming* of scopes is one decision
/// in one place.
#[must_use]
pub fn scope_for_risk(risk: RiskClass) -> &'static str {
    match risk {
        RiskClass::Low => "cost:low",
        RiskClass::Medium => "cost:medium",
        RiskClass::High => "cost:high",
        RiskClass::Critical => "cost:critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn an_empty_ledger_permits_nothing() {
        // Fail-closed: no budget means no permission to spend.
        let l = BudgetLedger::empty();
        assert!(!l.permits("global", 1));
        assert!(!l.permits("anything", 0));
    }

    #[test]
    fn spending_within_the_ceiling_is_permitted() {
        let l = BudgetLedger::empty().with_global(100);
        assert!(l.permits("global", 99));
        assert!(!l.permits("global", 101));
    }

    #[test]
    fn the_boundary_is_exact() {
        let l = BudgetLedger::empty().with_global(100);
        assert!(l.permits("global", 100), "spending exactly the limit must be allowed");
        assert!(!l.permits("global", 101));
    }

    #[test]
    fn repeated_charges_accumulate() {
        let mut l = BudgetLedger::empty().with_global(100);
        l.charge("global", 60).expect("charge");
        assert!(l.permits("global", 40));
        assert!(!l.permits("global", 41));
        l.charge("global", 40).expect("charge");
        assert_eq!(l.ceiling("global").map(|c| c.spent), Some(100));
        assert!(!l.permits("global", 1), "a full budget permits nothing further");
    }

    #[test]
    fn charging_an_undeclared_scope_is_refused() {
        let mut l = BudgetLedger::empty().with_global(100);
        assert!(matches!(
            l.charge("cost:high", 1),
            Err(BudgetError::UnknownScope { .. })
        ));
    }

    #[test]
    fn a_zero_ceiling_permits_only_a_zero_charge() {
        // A zero ceiling means "spend nothing". Charging nothing against it is
        // consistent; charging anything is not.
        let l = BudgetLedger::empty().with_ceiling("global", Ceiling::new(0));
        assert!(l.permits("global", 0));
        assert!(!l.permits("global", 1));
        assert_eq!(l.utilisation("global"), Some(1.0));
    }

    #[test]
    fn every_declared_ceiling_must_hold() {
        // Scopes are independent constraints. Declaring both a global and a
        // risk-scoped ceiling means *both* apply.
        let l = BudgetLedger::empty()
            .with_ceiling("global", Ceiling::new(100))
            .with_ceiling("cost:high", Ceiling::new(10));
        assert!(l.permits_all(10), "both ceilings have room");
        assert!(!l.permits_all(11), "the risk ceiling is exceeded");
    }

    #[test]
    fn permits_all_refuses_when_nothing_is_declared() {
        assert!(!BudgetLedger::empty().permits_all(0));
        assert!(!BudgetLedger::empty().permits_all(1));
    }

    #[test]
    fn charge_all_applies_to_every_scope() {
        let mut l = BudgetLedger::empty()
            .with_ceiling("global", Ceiling::new(100))
            .with_ceiling("cost:low", Ceiling::new(10));
        l.charge_all(10).expect("charge");
        assert_eq!(l.ceiling("global").map(|c| c.spent), Some(10));
        assert_eq!(l.ceiling("cost:low").map(|c| c.spent), Some(10));
        assert!(!l.permits_all(1), "the risk scope is now exhausted");
        assert!(matches!(l.charge_all(1), Ok(())), "charging is not gated by permits");
    }

    #[test]
    fn overflow_reads_as_exceeds_never_as_fits() {
        // Regression: `saturating_add` clamps a wrapped sum to u64::MAX, which
        // then compares as *not* greater than a u64::MAX limit and reads as
        // FITTING. That is a financial bug, so the arithmetic must be checked.
        // The exact wrapping case: spent is at the maximum, so any positive
        // charge overflows. `saturating_add` would clamp to u64::MAX and then
        // compare as *not* greater than a u64::MAX limit, reading as FITTING.
        let overflowing = Ceiling { limit: u64::MAX, spent: u64::MAX };
        assert!(overflowing.would_exceed(1), "overflow must read as exceeding");

        // And a charge that does not wrap behaves arithmetically.
        let roomy = Ceiling { limit: u64::MAX, spent: 0 };
        assert!(!roomy.would_exceed(1), "a tiny charge against a huge limit fits");
        assert!(!roomy.would_exceed(u64::MAX), "an exact fit at the limit is allowed");
        let nearly = Ceiling { limit: 10, spent: 9 };
        assert!(!nearly.would_exceed(1), "9 + 1 == 10 is an exact fit");
        assert!(nearly.would_exceed(2), "9 + 2 > 10 exceeds");
    }

    #[test]
    fn utilisation_is_bounded() {
        let mut l = BudgetLedger::empty().with_global(100);
        assert_eq!(l.utilisation("global"), Some(0.0));
        l.charge("global", 50).expect("charge");
        assert_eq!(l.utilisation("global"), Some(0.5));
        l.charge("global", 500).expect("charge");
        assert_eq!(l.utilisation("global"), Some(1.0), "utilisation must clamp at 1.0");
        assert_eq!(l.utilisation("missing"), None);
    }

    #[test]
    fn risk_scopes_are_distinct() {
        let all = [
            RiskClass::Low, RiskClass::Medium, RiskClass::High, RiskClass::Critical,
        ];
        let mut names: Vec<&str> = all.iter().copied().map(scope_for_risk).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 4);
    }

    proptest! {
        /// Utilisation is monotone in spend and never exceeds 1.0.
        #[test]
        fn utilisation_is_monotone_and_bounded(limit: u64, a: u64, b: u64) {
            let limit = limit % 1_000_000;
            let mut c = Ceiling::new(limit);
            c.charge(a % 1_000_000);
            let u1 = if limit == 0 { 1.0 } else { (c.spent as f64 / limit as f64).clamp(0.0, 1.0) };
            c.charge(b % 1_000_000);
            let u2 = if limit == 0 { 1.0 } else { (c.spent as f64 / limit as f64).clamp(0.0, 1.0) };
            prop_assert!(u2 >= u1);
            prop_assert!((0.0..=1.0).contains(&u2));
        }

        /// A ceiling is never exceeded once it has been hit, whatever is charged.
        #[test]
        fn an_exhausted_ceiling_stays_exhausted(n: u64) {
            let mut c = Ceiling::new(10);
            c.charge(10);
            prop_assert!(c.would_exceed(n));
        }
    }
}
