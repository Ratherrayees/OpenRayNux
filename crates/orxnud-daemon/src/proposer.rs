//! The AI task proposer: a model's only route into the governed system.
//!
//! # The boundary this module exists to enforce
//!
//! A language model gets to say what it *proposes*. It never gets to say what
//! happens. Concretely, the type below is the whole of its authority:
//!
//! ```text
//! &ProposalContext  ->  String   (untrusted text)
//! ```
//!
//! It is handed a read-only view of one task and the capabilities it may ask for,
//! and it returns text. It holds no client, no task service, no dispatcher, no policy
//! engine and no store handle, so there is no call it could make even if its output
//! asked for one. Everything after the string — parsing, validation, the durable
//! proposal, the human decision, the dispatch — belongs to the deterministic runtime.
//!
//! That is the whole of "model proposes; engine disposes" as a *type*, rather than as
//! a convention somebody might forget under time pressure.
//!
//! # What the model does not get
//!
//! Not approval authority, not policy mutation, not a sandbox handle, not a dispatch
//! entry point, and not the worker's lease. The last one deserves spelling out: the
//! worker identity appears in the *context* as an opaque string for correlation, and
//! nothing derives an actor from it. `Actor::Ai`'s authority comes from
//! `delegated_by`, which is set by the runtime (V-71, ADR-0038 D5).
//!
//! # The shipped adapter is not a model
//!
//! [`ScriptedProvider`] returns a fixed, declared response. It is here so the pipeline
//! is provable end to end without credentials, and it is named for what it is. No
//! network call, no model, no inference — and therefore no claim anywhere in this
//! repository that OpenRayNux has asked a language model to do anything. The first
//! real adapter is one implementation of [`ProposalProvider`] away, and it will need
//! the V-67 protected-parameter channel before it carries anything sensitive.

use serde::Deserialize;

/// A provider that cannot be reached.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// The provider was asked and could not answer.
    #[error("the proposal provider could not be reached: {0}")]
    Unavailable(String),
}

/// One capability the model is permitted to ask for.
///
/// An allowlist rather than a hint. A model that asks for something not on this list
/// gets a rejection, not a warning, because "the model suggested something else" is the
/// normal failure mode of a model asked an open question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedCapability {
    /// The capability id.
    pub id: String,
    /// A human-readable description, shown to the model.
    pub description: String,
    /// The parameter names it takes, so the model need not guess the schema.
    pub params: Vec<String>,
}

/// What the model is shown about the task.
///
/// Read-only by construction: there is no handle here to anything. Note that
/// `worker` is carried purely for correlation in the response — it grants nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalContext {
    /// The task being proposed for.
    pub task_id: String,
    /// Its human-visible content: the request.
    pub content: String,
    /// The attempt this proposal would belong to.
    pub attempt_no: u32,
    /// What may be asked for.
    pub allowed: Vec<AllowedCapability>,
}

/// A source of proposal text.
///
/// The return type is `String` on purpose. Whatever a real provider sends — JSON,
/// prose, a refusal, an apology — arrives here as untrusted text with no structure
/// attached, and the parsing that gives it structure is the next step, not this one.
pub trait ProposalProvider: Send + Sync {
    /// Which model produced this, for the audit record's provenance.
    fn model_id(&self) -> &str;

    /// Produces proposal text for a task, or fails.
    ///
    /// # Errors
    ///
    /// [`ProviderError`] if the provider cannot answer.
    fn complete(&self, ctx: &ProposalContext) -> Result<String, ProviderError>;
}

/// A provider that returns a declared response.
///
/// **Not a language model.** It exists so the governed pipeline can be exercised and
/// tested where no credentials exist, and so the boundary above has something on the
/// far side of it. Its output goes through exactly the same validation a real model's
/// would, which is the point: the interesting failures are in the parsing, not in the
/// generation.
#[derive(Debug, Clone)]
pub struct ScriptedProvider {
    model: String,
    response: String,
}

impl ScriptedProvider {
    /// A provider that always returns `response`.
    #[must_use]
    pub fn returning(model: impl Into<String>, response: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            response: response.into(),
        }
    }
}

impl ProposalProvider for ScriptedProvider {
    fn model_id(&self) -> &str {
        &self.model
    }

    fn complete(&self, _ctx: &ProposalContext) -> Result<String, ProviderError> {
        Ok(self.response.clone())
    }
}

/// The structured form a provider's text must take.
///
/// `deny_unknown_fields` is doing real work here rather than being tidiness: a model
/// that invents an extra key is a model whose output we do not understand, and silently
/// ignoring the key would execute a *different* operation from the one that was
/// described. Refusing is the only safe reading of "I am not sure what this means".
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProposal {
    capability: String,
    #[serde(default)]
    target: Option<String>,
    params: serde_json::Value,
}

/// Why a provider's text did not become a proposal.
///
/// Every variant is a refusal. There is no "best effort" path, because a proposal the
/// runtime only half-understood is an action nobody approved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProposalRejected {
    /// The text was not the expected JSON object.
    #[error("the model's output was not a proposal this runtime understands")]
    Unreadable,
    /// It named a capability that is not on the allowlist.
    #[error("the model asked for a capability it was not offered: {0:?}")]
    CapabilityNotAllowed(String),
    /// It named a capability this build does not have.
    #[error("the model asked for an unknown capability: {0:?}")]
    UnknownCapability(String),
}

impl ProposalRejected {
    /// A fixed word for the wire, so a client branches on a vocabulary rather than on
    /// prose that may change.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Unreadable => "proposal-unreadable",
            Self::CapabilityNotAllowed(_) => "proposal-capability-not-allowed",
            Self::UnknownCapability(_) => "proposal-unknown-capability",
        }
    }
}

/// The validated result: an action the runtime is willing to persist a proposal for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedProposal {
    /// The capability asked for.
    pub capability: String,
    /// The target, if any.
    pub target: Option<String>,
    /// The parameters.
    pub params: serde_json::Value,
}

/// Turns provider text into a proposal the runtime will persist.
///
/// Three refusals, in order, and no fallbacks: unreadable text, a capability outside
/// the allowlist, and a capability this build does not implement. Note what is *not*
/// checked here — the capability's own parameter validation happens when the plan is
/// built at execution, so a malformed parameter set becomes a refusal there rather than
/// a proposal that cannot run.
///
/// # Errors
///
/// [`ProposalRejected`] if the text cannot be understood or names something not
/// permitted.
pub fn validate(
    text: &str,
    ctx: &ProposalContext,
    is_registered: &dyn Fn(&str) -> bool,
) -> Result<ValidatedProposal, ProposalRejected> {
    // Parsed strictly: a bare string, a list, or an object with unexpected keys is not
    // a proposal, and guessing at the intent is exactly the creative interpretation the
    // deterministic side exists to prevent.
    let raw: RawProposal =
        serde_json::from_str(text.trim()).map_err(|_| ProposalRejected::Unreadable)?;

    if !ctx.allowed.iter().any(|c| c.id == raw.capability) {
        return Err(ProposalRejected::CapabilityNotAllowed(raw.capability));
    }
    if !is_registered(&raw.capability) {
        return Err(ProposalRejected::UnknownCapability(raw.capability));
    }
    Ok(ValidatedProposal {
        capability: raw.capability,
        target: raw.target,
        params: raw.params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ProposalContext {
        ProposalContext {
            task_id: "t-1".into(),
            content: "Create final.txt containing 'delegated governance works'.".into(),
            attempt_no: 1,
            allowed: vec![AllowedCapability {
                id: "filesystem/write-text".into(),
                description: "Write a text file into the workspace".into(),
                params: vec!["path".into(), "contents".into()],
            }],
        }
    }

    fn registered(id: &str) -> bool {
        id == "filesystem/write-text"
    }

    #[test]
    fn a_well_formed_proposal_is_accepted() {
        let p = validate(
            r#"{"capability":"filesystem/write-text","target":"final.txt","params":{"path":"final.txt","contents":"delegated governance works"}}"#,
            &ctx(),
            &registered,
        )
        .expect("a valid proposal");
        assert_eq!(p.capability, "filesystem/write-text");
        assert_eq!(p.params["contents"], "delegated governance works");
    }

    /// The demonstration case from the milestone: the model states a plain request and
    /// the runtime turns it into exactly one structured action.
    #[test]
    fn the_demonstration_task_produces_the_expected_action() {
        let p = validate(
            r#"{"capability":"filesystem/write-text","target":"final.txt","params":{"path":"final.txt","contents":"delegated governance works"}}"#,
            &ctx(),
            &registered,
        )
        .expect("valid");
        assert_eq!(p.target.as_deref(), Some("final.txt"));
    }

    /// Malformed output is refused, never interpreted. Each case is a different way a
    /// model can be unclear, and all of them end the same way.
    #[test]
    fn malformed_or_ambiguous_output_is_refused_rather_than_interpreted() {
        for bad in [
            // Not JSON at all.
            "I would be happy to create that file for you!",
            // JSON, but not the shape.
            r#"["filesystem/write-text"]"#,
            r#""filesystem/write-text""#,
            // An unknown extra field: the runtime does not know what was meant, and
            // dropping the key would execute a different operation.
            r#"{"capability":"filesystem/write-text","params":{},"sudo":true}"#,
            // Missing the capability.
            r#"{"params":{"path":"a.txt"}}"#,
            // Empty text.
            "",
            // A capability nobody offered, even though it exists.
            r#"{"capability":"filesystem/delete-everything","params":{}}"#,
        ] {
            let err = validate(bad, &ctx(), &registered).expect_err("must be refused");
            assert!(
                matches!(
                    err,
                    ProposalRejected::Unreadable | ProposalRejected::CapabilityNotAllowed(_)
                ),
                "{bad:?} produced {err:?}"
            );
        }
    }

    #[test]
    fn an_offered_but_unimplemented_capability_is_refused_separately() {
        let mut c = ctx();
        c.allowed.push(AllowedCapability {
            id: "email/send".into(),
            description: "Send an email".into(),
            params: vec!["to".into()],
        });
        let err = validate(
            r#"{"capability":"email/send","params":{"to":"a@b.test"}}"#,
            &c,
            &registered,
        )
        .expect_err("not implemented here");
        assert_eq!(
            err,
            ProposalRejected::UnknownCapability("email/send".into())
        );
        assert_eq!(err.reason(), "proposal-unknown-capability");
    }

    /// The allowlist is what stops a model from asking for something merely because it
    /// knows the name.
    #[test]
    fn a_capability_outside_the_allowlist_is_refused_even_when_it_exists() {
        let err = validate(
            r#"{"capability":"text/word-count","params":{}}"#,
            &ctx(),
            &|id| id == "text/word-count",
        )
        .expect_err("not offered");
        assert_eq!(err.reason(), "proposal-capability-not-allowed");
    }

    /// The context handed to a provider is inert: it names the worker for correlation
    /// and carries no handle to anything.
    #[test]
    fn the_context_grants_nothing() {
        // Compile-time evidence, expressed as a test so it is checked: the only way to
        // construct one is by value, and it holds no reference type at all.
        let c = ctx();
        let _: String = c.task_id;
        let _: String = c.content;
        let _: u32 = c.attempt_no;
        assert!(!c.allowed.is_empty());
    }
}
