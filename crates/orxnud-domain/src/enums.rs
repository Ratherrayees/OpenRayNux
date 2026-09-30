//! Closed enums that constrain behaviour at construction, not at the call site.
//!
//! The pattern throughout this file: a value that would be dangerous if
//! *constructed* wrongly is prevented from being constructed wrongly, rather
//! than being checked at every use site. A check that lives at the constructor
//! cannot be forgotten; a check at a call site eventually will be.

use serde::{Deserialize, Serialize};

/// How dangerous an action is, independent of how it is performed.
///
/// The critical property is [`RiskClass::classify_unknown`]: anything not
/// explicitly classified is `High`. A new capability cannot be low-risk by
/// omission — it has to be classified, deliberately, to be low-risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskClass {
    /// Reading something already in scope. No external effect.
    Low,
    /// A local, reversible effect.
    Medium,
    /// An externally visible or costly effect that is reversible.
    High,
    /// Irreversible, destructive, privileged, or financial.
    Critical,
}

impl RiskClass {
    /// The default for anything not explicitly classified.
    pub const UNKNOWN: Self = Self::High;

    /// Classifies a capability, defaulting unrecognised names to `High`.
    ///
    /// This is the mechanism behind control S5 and the OWASP pattern: unknown
    /// tools default to the *gated* class, so adding a capability is a decision
    /// to gate it until someone says otherwise.
    #[must_use]
    pub fn classify_unknown(name: &str) -> Self {
        match name {
            "read" | "list" | "stat" | "search" => Self::Low,
            "draft" | "prepare" | "preview" => Self::Medium,
            "send" | "publish" | "apply" | "submit" => Self::High,
            "delete" | "purchase" | "grant" | "install" => Self::Critical,
            // The whole point: unrecognised is not "probably fine".
            _ => Self::UNKNOWN,
        }
    }

    /// Whether an action of this class requires an explicit, digest-bound,
    /// single-use human approval.
    #[must_use]
    pub fn requires_approval(self) -> bool {
        self >= Self::High
    }

    /// Whether an action of this class additionally requires step-up
    /// re-authentication.
    #[must_use]
    pub fn requires_step_up(self) -> bool {
        self >= Self::Critical
    }
}

/// Coarse approval tier, aligned with control S5's approval levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalLevel {
    /// Informational. Logged.
    L0,
    /// Reversible local effect. Logged.
    L1,
    /// External but reversible, and explicitly requested by the user.
    L2,
    /// Consequential. Digest-bound, single-use approval.
    L3,
    /// Irreversible or privileged. Digest-bound approval plus explicit scope.
    L4,
    /// A policy or configuration change. Approval plus step-up re-authentication.
    L5,
}

impl ApprovalLevel {
    /// Derives the level implied by a risk class.
    ///
    /// The mapping is deliberately conservative: it never returns a *lower*
    /// level than the risk class warrants.
    #[must_use]
    pub fn for_risk(risk: RiskClass) -> Self {
        match risk {
            RiskClass::Low => Self::L0,
            RiskClass::Medium => Self::L1,
            RiskClass::High => Self::L3,
            RiskClass::Critical => Self::L4,
        }
    }

    /// Whether this level gates the action.
    #[must_use]
    pub fn is_gated(self) -> bool {
        self >= Self::L3
    }
}

/// Sensitivity class of data, controlling egress and retention
/// (control S18 and docs-04 §6).
///
/// Derived data inherits the *highest* class of its sources, so summarising a
/// regulated record cannot launder it into `Public`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataClass {
    /// Already public.
    Public,
    /// The user's own, non-sensitive material.
    Personal,
    /// Messages, browsing history, applications.
    Sensitive,
    /// Health, biometrics, financial.
    Regulated,
}

impl DataClass {
    /// Combines two classes, keeping the more sensitive.
    ///
    /// Used when derived data merges sources, and when a capability declares
    /// both input and output classes.
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        if other > self { other } else { self }
    }

    /// Whether data of this class may transit an external provider without
    /// explicit, per-flow consent.
    #[must_use]
    pub fn requires_explicit_consent(self) -> bool {
        self >= Self::Sensitive
    }

    /// Whether this class is blocked from external providers by default.
    #[must_use]
    pub fn is_blocked_by_default(self) -> bool {
        self >= Self::Regulated
    }
}

/// Where a capability's code runs, and therefore how much we trust it
/// (ADR-0009).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationTier {
    /// In-process Rust trait. Built-ins only; a panic is a bug we fix.
    InProcess,
    /// Separate process. Crash-contained, language-agnostic, sandboxable.
    Subprocess,
    /// Remote over MCP Streamable HTTP. Untrusted.
    Remote,
}

impl IsolationTier {
    /// Whether code at this tier is assumed hostile.
    ///
    /// Only `Remote` is. A `Subprocess` is assumed *buggy*, not *malicious*:
    /// it is ours, it is sandboxed, but it is third-party code.
    #[must_use]
    pub fn is_untrusted(self) -> bool {
        matches!(self, Self::Remote)
    }

    /// Whether code at this tier is allowed to be GPL/AGPL/NC-licensed.
    ///
    /// Never, in-process: a copyleft component linked into the core binary
    /// creates a licensing obligation (ADR-0006, ADR-0009, ADR-0019). It may
    /// run as a separate process the user installs, which keeps the copyleft at
    /// arm's length.
    #[must_use]
    pub fn permits_copyleft(self) -> bool {
        !matches!(self, Self::InProcess)
    }
}

/// Consistency requirement of a state region (ADR-0028).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StateConsistency {
    /// Synchronous, fsync'd. For anything whose loss is a lost *action*.
    Strong,
    /// Read-your-writes, but not necessarily immediately durable.
    Eventual,
    /// No guarantee. Regenerable.
    Ephemeral,
}

/// A state region's class (ADR-0028).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StateClass {
    /// Tasks, schedules, audit, dedupe. `synchronous = FULL`.
    Critical,
    /// Profile, config, policy, health, budget ledger.
    Authoritative,
    /// Summaries, entities, embeddings. **Never** authoritative.
    Derived,
    /// In-flight context. Never persisted.
    Ephemeral,
}

impl StateClass {
    /// The consistency a region of this class requires.
    #[must_use]
    pub fn required_consistency(self) -> StateConsistency {
        match self {
            Self::Critical | Self::Authoritative => StateConsistency::Strong,
            Self::Derived => StateConsistency::Eventual,
            Self::Ephemeral => StateConsistency::Ephemeral,
        }
    }

    /// Whether the intent layer (the model) may write a region of this class.
    ///
    /// **This is the answer to "which state may the model write?"** — a single
    /// method, so the question has exactly one answer rather than one per call
    /// site. Enforced again as a repository query filter (ADR-0013), because a
    /// predicate that is only checked on one side of a boundary is not a
    /// boundary.
    #[must_use]
    pub fn writable_by_intent_layer(self) -> bool {
        matches!(self, Self::Derived | Self::Ephemeral)
    }

    /// Whether a region of this class can satisfy an authority check.
    #[must_use]
    pub fn is_authoritative(self) -> bool {
        matches!(self, Self::Critical | Self::Authoritative)
    }
}

/// A capability's current health, from its health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityHealth {
    /// Never checked.
    Unknown,
    /// Health check passed.
    Available,
    /// Failing but retrying. Visible to the user with a plain-language reason.
    Degraded,
    /// Too many consecutive failures. Not retried silently.
    Quarantined,
    /// Explicitly turned off.
    Disabled,
}

impl CapabilityHealth {
    /// Whether the dispatcher may route to this capability.
    #[must_use]
    pub fn is_routable(self) -> bool {
        matches!(self, Self::Available | Self::Degraded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn unknown_capability_classifies_as_high_not_low() {
        // The single most important behaviour in this file.
        assert_eq!(RiskClass::classify_unknown("brand-new-thing"), RiskClass::High);
        assert!(RiskClass::classify_unknown("brand-new-thing").requires_approval());
        assert_eq!(RiskClass::classify_unknown("read"), RiskClass::Low);
        assert_eq!(RiskClass::classify_unknown("delete"), RiskClass::Critical);
    }

    #[test]
    fn empty_and_unicode_names_classify_as_high() {
        for name in ["", "  ", "💥", "../../etc/passwd", "READ", "read "] {
            assert_eq!(
                RiskClass::classify_unknown(name),
                RiskClass::High,
                "unexpected classification for {name:?}"
            );
        }
    }

    #[test]
    fn risk_ordering_drives_approval() {
        assert!(!RiskClass::Low.requires_approval());
        assert!(!RiskClass::Medium.requires_approval());
        assert!(RiskClass::High.requires_approval());
        assert!(RiskClass::Critical.requires_approval());
        assert!(RiskClass::Critical.requires_step_up());
        assert!(!RiskClass::High.requires_step_up());
    }

    #[test]
    fn approval_level_never_undercuts_risk() {
        for risk in [
            RiskClass::Low,
            RiskClass::Medium,
            RiskClass::High,
            RiskClass::Critical,
        ] {
            let level = ApprovalLevel::for_risk(risk);
            assert!(
                level >= ApprovalLevel::for_risk(RiskClass::Critical.min(risk)),
                "level too low for {risk:?}"
            );
        }
        assert_eq!(ApprovalLevel::for_risk(RiskClass::High), ApprovalLevel::L3);
        assert_eq!(ApprovalLevel::for_risk(RiskClass::Critical), ApprovalLevel::L4);
    }

    #[test]
    fn data_class_combine_keeps_the_more_sensitive() {
        assert_eq!(
            DataClass::Public.combine(DataClass::Regulated),
            DataClass::Regulated
        );
        assert_eq!(
            DataClass::Regulated.combine(DataClass::Public),
            DataClass::Regulated
        );
        assert_eq!(DataClass::Sensitive.combine(DataClass::Personal), DataClass::Sensitive);
    }

    #[test]
    fn regulated_data_is_blocked_from_providers_by_default() {
        assert!(!DataClass::Public.requires_explicit_consent());
        assert!(DataClass::Sensitive.requires_explicit_consent());
        assert!(DataClass::Regulated.is_blocked_by_default());
        assert!(!DataClass::Personal.is_blocked_by_default());
    }

    #[test]
    fn only_subprocess_and_remote_permit_copyleft() {
        // The mechanism by which GPL/AGPL components (Piper, eSpeak-NG) stay out
        // of the core binary without being unusable (ADR-0009).
        assert!(!IsolationTier::InProcess.permits_copyleft());
        assert!(IsolationTier::Subprocess.permits_copyleft());
        assert!(IsolationTier::Remote.permits_copyleft());
    }

    #[test]
    fn only_remote_is_untrusted() {
        assert!(!IsolationTier::InProcess.is_untrusted());
        assert!(!IsolationTier::Subprocess.is_untrusted());
        assert!(IsolationTier::Remote.is_untrusted());
    }

    #[test]
    fn only_derived_and_ephemeral_are_writable_by_the_intent_layer() {
        // "Which state may the model write?" — one method, one answer.
        assert!(!StateClass::Critical.writable_by_intent_layer());
        assert!(!StateClass::Authoritative.writable_by_intent_layer());
        assert!(StateClass::Derived.writable_by_intent_layer());
        assert!(StateClass::Ephemeral.writable_by_intent_layer());
    }

    #[test]
    fn derived_state_is_never_authoritative() {
        assert!(!StateClass::Derived.is_authoritative());
        assert!(!StateClass::Ephemeral.is_authoritative());
        assert!(StateClass::Critical.is_authoritative());
        assert!(StateClass::Authoritative.is_authoritative());
    }

    #[test]
    fn critical_and_authoritative_require_strong_consistency() {
        // This is why they get `synchronous = FULL` and derived does not.
        assert_eq!(StateClass::Critical.required_consistency(), StateConsistency::Strong);
        assert_eq!(StateClass::Authoritative.required_consistency(), StateConsistency::Strong);
        assert_eq!(StateClass::Derived.required_consistency(), StateConsistency::Eventual);
    }

    #[test]
    fn health_routability() {
        assert!(CapabilityHealth::Available.is_routable());
        assert!(CapabilityHealth::Degraded.is_routable());
        assert!(!CapabilityHealth::Quarantined.is_routable());
        assert!(!CapabilityHealth::Disabled.is_routable());
        assert!(!CapabilityHealth::Unknown.is_routable());
    }

    proptest! {
        /// No state class is ever both authoritative and writable by the intent
        /// layer. This is the invariant behind ADR-0013/ADR-0028: derived data
        /// can never satisfy an authority check, and authoritative data is never
        /// model-writable. Generated over the whole class set so a future
        /// variant cannot be added in a way that breaks it.
        #[test]
        fn no_state_class_is_both_authoritative_and_model_writable(a: u8) {
            let all = [
                StateClass::Critical,
                StateClass::Authoritative,
                StateClass::Derived,
                StateClass::Ephemeral,
            ];
            let x = all[(a % 4) as usize];
            prop_assert!(
                !(x.is_authoritative() && x.writable_by_intent_layer()),
                "{x:?} is both authoritative and model-writable"
            );
        }

        /// A gated risk class always yields a gated approval level, and the
        /// level is monotone as risk increases. This is what makes "unknown is
        /// not safe" hold end to end: RiskClass::UNKNOWN is High, and High maps
        /// to L3, which is gated.
        #[test]
        fn gated_risk_implies_gated_approval(step: u8) {
            let ladder = [
                RiskClass::Low,
                RiskClass::Medium,
                RiskClass::High,
                RiskClass::Critical,
            ];
            let i = (step % 4) as usize;
            let risk = ladder[i];
            let level = ApprovalLevel::for_risk(risk);
            if risk.requires_approval() {
                prop_assert!(level.is_gated(), "risk {risk:?} produced ungated {level:?}");
            }
            if i + 1 < ladder.len() {
                prop_assert!(level <= ApprovalLevel::for_risk(ladder[i + 1]));
            }
            // The documented default for anything unclassified must gate.
            prop_assert!(RiskClass::UNKNOWN.requires_approval());
        }

        /// Data class combination is commutative and returns the maximum.
        #[test]
        fn data_class_combine_is_commutative(a: u8, b: u8) {
            let all = [
                DataClass::Public,
                DataClass::Personal,
                DataClass::Sensitive,
                DataClass::Regulated,
            ];
            let x = all[(a % 4) as usize];
            let y = all[(b % 4) as usize];
            prop_assert_eq!(x.combine(y), y.combine(x));
            prop_assert!(x.combine(y) >= x);
            prop_assert!(x.combine(y) >= y);
        }
    }
}
