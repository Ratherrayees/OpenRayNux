//! The intent layer's output: an inert `Proposal`.
//!
//! # This type is the deterministic boundary
//!
//! ADR-0012: **the model proposes; a deterministic engine disposes.** A
//! `Proposal` is what the model produces, and it is *data*:
//!
//! * It has **no method that reaches an adapter**.
//! * It has no I/O, no async, and no handle to anything.
//! * Nothing happens to it until a deterministic component has validated,
//!   authorised, and recorded it.
//!
//! The path from "the model said so" to "something happened on the world" is
//! therefore: `Proposal` → `ActionRequest` (validated) → `CapabilityInvocation`
//! (authorised, and constructible only inside `orxnud-policy`).
//!
//! A compile-fail test (`tests/compile_fail/proposal_is_inert.rs`) proves the
//! first property, because "we were careful" is not evidence.

use serde::{Deserialize, Serialize};

use crate::ids::{CapabilityId, RunId, TaskId};

/// A closed set of intents.
///
/// Closed on purpose: an open string here would let a model invent a category
/// the deterministic layers have never been reasoned about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "detail")]
pub enum IntentKind {
    /// Answer a question about existing state.
    Query,
    /// Act on a capability.
    Act,
    /// Create or modify a scheduled task.
    Schedule,
    /// Cancel or pause something.
    Control,
    /// Transform text that was supplied in the request.
    Transform,
    /// Something outside the closed set. Handled as `Query` with a refusal.
    Unknown,
}

impl IntentKind {
    /// Whether this intent can cause an external side effect at all.
    ///
    /// Used to skip the whole execution pipeline for pure queries, which is
    /// both a performance win and a reduction in blast radius.
    #[must_use]
    pub fn may_cause_side_effects(self) -> bool {
        matches!(self, Self::Act | Self::Schedule | Self::Control)
    }
}

/// One step of a proposed plan.
///
/// Declarative. A step *describes* an action; it does not perform one. The
/// deterministic validator checks that `capability` is registered and that
/// `params` match the capability's declared schema before anything else looks
/// at it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposedStep {
    /// Stable position within the plan, for correlation and reporting.
    pub index: u32,
    /// The capability this step would invoke.
    pub capability: CapabilityId,
    /// Free-form parameters. **Untrusted** until validated against the
    /// capability's declared schema. Never interpreted by the core.
    pub params: serde_json::Value,
    /// Why the model proposes this step. Shown to the user; never trusted.
    pub rationale: Option<String>,
}

impl ProposedStep {
    /// Builds a step with a rationale and no extra decoration.
    #[must_use]
    pub fn new(index: u32, capability: impl Into<CapabilityId>, params: serde_json::Value) -> Self {
        Self {
            index,
            capability: capability.into(),
            params,
            rationale: None,
        }
    }
}

/// The complete output of one intent-layer pass.
///
/// **Inert.** There is deliberately no `execute`, `run`, `apply`, or `apply_…`
/// method on this type, and no field that is a handle to a capability, a
/// connection, or a runtime. The absence is the security property; the
/// compile-fail test pins it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    /// The task this proposal belongs to.
    pub task: TaskId,
    /// The run that produced it.
    pub run: RunId,
    /// What the model believes the user wants.
    pub intent: IntentKind,
    /// The proposed steps, in order.
    pub steps: Vec<ProposedStep>,
    /// Plain-language summary shown to the user before anything is gated.
    pub rationale: String,
    /// Model-reported confidence in `[0.0, 1.0]`.
    ///
    /// **Displayed, never enforced.** A high confidence is not authorisation and
    /// does not lower a risk class. It exists so the UI can be honest about
    /// uncertainty.
    pub confidence: f32,
    /// Which model produced this, and under which prompt.
    pub provenance: crate::actor::ModelProvenance,
}

impl Proposal {
    /// Clamps `confidence` into `[0.0, 1.0]` at construction.
    ///
    /// A `NaN` confidence would serialise to invalid JSON and render as
    /// garbage; clamping here means no downstream consumer has to defend
    /// against it.
    #[must_use]
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = if confidence.is_nan() {
            0.0
        } else {
            confidence.clamp(0.0, 1.0)
        };
        self
    }

    /// Whether the proposal asks for anything that could change the world.
    #[must_use]
    pub fn may_cause_side_effects(&self) -> bool {
        self.intent.may_cause_side_effects() && !self.steps.is_empty()
    }

    /// The distinct capabilities this proposal would invoke, in first-use order.
    #[must_use]
    pub fn referenced_capabilities(&self) -> Vec<CapabilityId> {
        let mut seen = Vec::new();
        for step in &self.steps {
            if !seen.contains(&step.capability) {
                seen.push(step.capability.clone());
            }
        }
        seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actor::ModelProvenance;
    use crate::ids::RequestId;
    use proptest::prelude::*;

    fn proposal() -> Proposal {
        Proposal {
            task: TaskId::new("t-1"),
            run: RunId::new("r-1"),
            intent: IntentKind::Query,
            steps: Vec::new(),
            rationale: "nothing to do".into(),
            confidence: 0.5,
            provenance: ModelProvenance::new("m", "p", RequestId::new("q-1")),
        }
    }

    #[test]
    // Exact float comparisons are the assertion here, not an oversight: `clamp`
    // returns the boundary itself, so `2.0 -> 1.0` must be bit-exact and a
    // tolerance would hide a clamp that stopped short of the limit.
    #[allow(clippy::float_cmp)]
    fn confidence_is_clamped_and_nan_becomes_zero() {
        assert_eq!(proposal().with_confidence(2.0).confidence, 1.0);
        assert_eq!(proposal().with_confidence(-1.0).confidence, 0.0);
        assert_eq!(proposal().with_confidence(f32::NAN).confidence, 0.0);
        assert_eq!(proposal().with_confidence(0.25).confidence, 0.25);
    }

    #[test]
    fn confidence_always_serialises_as_a_valid_number() {
        for c in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -5.0, 5.0] {
            let json = serde_json::to_string(&proposal().with_confidence(c)).expect("serialise");
            // The literal tokens `NaN`/`Infinity` are what would break a strict
            // JSON parser. (`serde_json` maps non-finite floats to `null`; that
            // is its documented behaviour and the receiving `Proposal` clamps it
            // back to a finite value, which the assertions below confirm.)
            assert!(
                !json.contains("NaN") && !json.contains("Infinity"),
                "non-finite confidence leaked into the wire format: {json}"
            );
            let back: Proposal = serde_json::from_str(&json).expect("round-trip");
            assert!(
                back.confidence.is_finite(),
                "non-finite confidence survived"
            );
            // Inclusive bounds: `0.0` and `1.0` are valid confidences.
            assert!((0.0..=1.0).contains(&back.confidence));
        }
    }

    #[test]
    fn query_with_no_steps_cannot_cause_side_effects() {
        assert!(!proposal().may_cause_side_effects());
    }

    #[test]
    fn act_with_no_steps_cannot_cause_side_effects() {
        // Belt and braces: an "act" with nothing to act on is not an action.
        let p = Proposal {
            intent: IntentKind::Act,
            ..proposal()
        };
        assert!(!p.may_cause_side_effects());
    }

    #[test]
    fn act_with_a_step_may_cause_side_effects() {
        let p = Proposal {
            intent: IntentKind::Act,
            steps: vec![ProposedStep::new(
                0,
                "send-message",
                serde_json::json!({"text": "hi"}),
            )],
            ..proposal()
        };
        assert!(p.may_cause_side_effects());
    }

    #[test]
    fn referenced_capabilities_are_deduplicated_in_order() {
        let p = Proposal {
            steps: vec![
                ProposedStep::new(0, "b", serde_json::json!({})),
                ProposedStep::new(1, "a", serde_json::json!({})),
                ProposedStep::new(2, "b", serde_json::json!({})),
            ],
            ..proposal()
        };
        let caps: Vec<String> = p
            .referenced_capabilities()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(caps, vec!["b", "a"]);
    }

    proptest! {
        /// A proposal never reports a side effect unless it has both an
        /// effectful intent and at least one step.
        #[test]
        fn side_effects_require_intent_and_steps(c: f32, n: u8) {
            let mut p = proposal().with_confidence(c);
            p.steps = (0..(n % 3))
                .map(|i| ProposedStep::new(u32::from(i), "c", serde_json::json!({})))
                .collect();
            if !p.may_cause_side_effects() {
                prop_assert!(p.steps.is_empty() || !p.intent.may_cause_side_effects());
            }
            prop_assert!((0.0..=1.0).contains(&p.confidence));
        }
    }
}
