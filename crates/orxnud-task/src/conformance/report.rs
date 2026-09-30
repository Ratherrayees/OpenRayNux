//! Reporting: twelve named results, not a boolean.
//!
//! A harness that reports "tests passed" is useless when a property regresses —
//! you want to know *which* property broke. So every run produces one
//! [`PropertyResult`] per property, each naming the property, the seed, and a
//! diagnostic.

use std::fmt;

/// The outcome of one property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyOutcome {
    /// The property holds for every point the harness exercised.
    Holds {
        /// How many cases were run.
        cases: u32,
    },
    /// The property was violated.
    Violated {
        /// What went wrong, in enough detail to reproduce it.
        detail: String,
    },
    /// The property could not be evaluated by this engine.
    ///
    /// Distinct from `Violated`: "unsupported" is a design statement, "violated"
    /// is a bug. A Phase 2 engine that cannot support TP-5 (lease fencing) must
    /// say so rather than quietly pass.
    Unsupported {
        /// Why.
        detail: String,
    },
}

impl fmt::Display for PropertyOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Holds { cases } => write!(f, "HOLDS ({cases} cases)"),
            Self::Violated { detail } => write!(f, "VIOLATED: {detail}"),
            Self::Unsupported { detail } => write!(f, "UNSUPPORTED: {detail}"),
        }
    }
}

/// One property's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyResult {
    /// The property id, e.g. `TP-5`.
    pub id: &'static str,
    /// What the property requires.
    pub statement: &'static str,
    /// The outcome.
    pub outcome: PropertyOutcome,
    /// The seed the run used, so a failure is reproducible.
    pub seed: u64,
}

/// The overall verdict.
///
/// A report is only `Conforms` when **every** property either holds or is
/// explicitly unsupported *and* the caller has declared those exclusions
/// acceptable. `run_suite` never returns `Conforms` on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Every property holds.
    Conforms,
    /// At least one property is violated.
    NonConforming,
    /// Nothing was violated, but some properties are unsupported.
    ConformsWithGaps,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conforms => f.write_str("CONFORMS"),
            Self::NonConforming => f.write_str("NON-CONFORMING"),
            Self::ConformsWithGaps => f.write_str("CONFORMS WITH GAPS"),
        }
    }
}

/// A full suite result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    /// The engine's self-reported name.
    pub engine: String,
    /// The suite version.
    pub suite_version: &'static str,
    /// The seed used for all randomised injection.
    pub seed: u64,
    /// One result per property.
    pub results: Vec<PropertyResult>,
}

impl ConformanceReport {
    /// Builds a report, filling in statements from the canonical list.
    #[must_use]
    pub fn new(engine: impl Into<String>, seed: u64, results: Vec<PropertyResult>) -> Self {
        Self {
            engine: engine.into(),
            suite_version: crate::CONFORMANCE_SUITE_VERSION,
            seed,
            results,
        }
    }

    /// The verdict.
    ///
    /// `Unsupported` yields `ConformsWithGaps` — never `Conforms`. An engine
    /// that declines to implement a property has not been shown to satisfy it.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        if self
            .results
            .iter()
            .any(|r| matches!(r.outcome, PropertyOutcome::Violated { .. }))
        {
            Verdict::NonConforming
        } else if self
            .results
            .iter()
            .any(|r| matches!(r.outcome, PropertyOutcome::Unsupported { .. }))
        {
            Verdict::ConformsWithGaps
        } else {
            Verdict::Conforms
        }
    }

    /// Whether every property holds, with no gaps.
    #[must_use]
    pub fn fully_conforms(&self) -> bool {
        self.verdict() == Verdict::Conforms
    }

    /// The properties that were violated.
    #[must_use]
    pub fn violations(&self) -> Vec<&'static str> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, PropertyOutcome::Violated { .. }))
            .map(|r| r.id)
            .collect()
    }

    /// The properties that were unsupported.
    #[must_use]
    pub fn gaps(&self) -> Vec<&'static str> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, PropertyOutcome::Unsupported { .. }))
            .map(|r| r.id)
            .collect()
    }

    /// A human-readable rendering, one line per property.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!(
            "conformance: {} v{} (seed {})\n  verdict: {}\n",
            self.engine,
            self.suite_version,
            self.seed,
            self.verdict()
        );
        for r in &self.results {
            out.push_str(&format!("  {} {:<52} {}\n", r.id, r.statement, r.outcome));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: &'static str, outcome: PropertyOutcome) -> PropertyResult {
        PropertyResult {
            id,
            statement: "s",
            outcome,
            seed: 7,
        }
    }

    #[test]
    fn a_violation_makes_the_report_non_conforming() {
        let r = ConformanceReport::new(
            "e",
            7,
            vec![
                result("TP-1", PropertyOutcome::Holds { cases: 1 }),
                result(
                    "TP-5",
                    PropertyOutcome::Violated {
                        detail: "zombie committed".into(),
                    },
                ),
            ],
        );
        assert_eq!(r.verdict(), Verdict::NonConforming);
        assert!(!r.fully_conforms());
        assert_eq!(r.violations(), vec!["TP-5"]);
    }

    #[test]
    fn unsupported_is_never_reported_as_conforming() {
        // "We chose not to implement it" is not "it works".
        let r = ConformanceReport::new(
            "e",
            7,
            vec![result(
                "TP-5",
                PropertyOutcome::Unsupported {
                    detail: "no leases".into(),
                },
            )],
        );
        assert_eq!(r.verdict(), Verdict::ConformsWithGaps);
        assert!(!r.fully_conforms());
        assert_eq!(r.gaps(), vec!["TP-5"]);
    }

    #[test]
    fn all_holding_is_conforming() {
        let r = ConformanceReport::new(
            "e",
            7,
            (1..=12)
                .map(|i| result(PROP_IDS[i - 1], PropertyOutcome::Holds { cases: 3 }))
                .collect(),
        );
        assert_eq!(r.verdict(), Verdict::Conforms);
        assert!(r.fully_conforms());
    }

    const PROP_IDS: [&str; 12] = [
        "TP-1", "TP-2", "TP-3", "TP-4", "TP-5", "TP-6", "TP-7", "TP-8", "TP-9", "TP-10", "TP-11",
        "TP-12",
    ];

    #[test]
    fn the_report_renders_every_property() {
        let r = ConformanceReport::new(
            "fixture",
            42,
            PROP_IDS
                .iter()
                .map(|id| result(id, PropertyOutcome::Holds { cases: 1 }))
                .collect(),
        );
        let text = r.render();
        for id in PROP_IDS {
            assert!(text.contains(id), "report omits {id}");
        }
        assert!(text.contains("seed 42"));
    }
}
