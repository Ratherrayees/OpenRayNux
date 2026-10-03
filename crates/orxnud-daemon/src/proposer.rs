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
    /// The declared shape, carried so [`validate`] can check a proposal against the same
    /// declaration the capability was registered with.
    ///
    /// Not shown to the model. The model is told the field *names*; the shape is what the
    /// deterministic side enforces, and telling a model the exact schema invites it to
    /// contrive a shape-satisfying request rather than an honest one.
    pub schema: orxnud_domain::ParamSchema,
    /// Whether the capability needs a named target.
    pub target: orxnud_domain::TargetSemantics,
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
    /// It named a capability that acts on a target, and supplied none.
    #[error("{capability:?} acts on a named target and the model supplied none")]
    MissingTarget {
        /// The capability asked for.
        capability: String,
    },
    /// The parameters do not match the capability's declared shape.
    ///
    /// Carries every problem found, not just the first: a model that got the shape wrong
    /// usually got it wrong in several places, and a single message would make it guess.
    #[error("{capability:?} parameters do not match the declared shape: {}", .problems.join("; "))]
    SchemaMismatch {
        /// The capability asked for.
        capability: String,
        /// What was wrong, one clause per problem.
        problems: Vec<String>,
    },
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
            Self::MissingTarget { .. } => "proposal-target-missing",
            Self::SchemaMismatch { .. } => "proposal-schema-mismatch",
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

    // Whether the model was *offered* this capability. The menu is built by walking the
    // registry, so this is "not enabled in this build" rather than a curated list — a
    // capability added to the registry is proposable with no edit here, which is the
    // drift this replaced.
    let Some(offered) = ctx.allowed.iter().find(|c| c.id == raw.capability) else {
        return Err(ProposalRejected::CapabilityNotAllowed(raw.capability));
    };
    if !is_registered(&raw.capability) {
        return Err(ProposalRejected::UnknownCapability(raw.capability));
    }

    // A capability that acts on a named target cannot be asked to act without one.
    if !offered.target.satisfied_by(raw.target.is_some()) {
        return Err(ProposalRejected::MissingTarget {
            capability: raw.capability,
        });
    }

    // The declared shape, checked *here* so a malformed request never becomes a durable
    // proposal that only fails later. The capability's own parser still runs at
    // execution — this is the first gate, not the only one, and the two are asserted to
    // agree so the shape can never be the stricter of them in a way that refuses valid
    // work.
    if let Err(problems) = offered.schema.validate(&raw.params) {
        return Err(ProposalRejected::SchemaMismatch {
            capability: raw.capability,
            problems,
        });
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

    /// The declared shape `filesystem/write-text` is registered with, so these tests
    /// check real enforcement rather than a permissive fixture.
    fn write_text_schema() -> orxnud_domain::ParamSchema {
        orxnud_domain::ParamSchema::new(vec![
            orxnud_domain::ParamField::required(
                "path",
                orxnud_domain::ParamKind::String,
                "File name.",
            ),
            orxnud_domain::ParamField::required(
                "contents",
                orxnud_domain::ParamKind::String,
                "The text.",
            ),
        ])
    }

    fn write_text() -> AllowedCapability {
        AllowedCapability {
            id: "filesystem/write-text".into(),
            description: "Write a text file into the workspace".into(),
            params: vec!["path".into(), "contents".into()],
            schema: write_text_schema(),
            target: orxnud_domain::TargetSemantics::Required,
        }
    }

    fn ctx() -> ProposalContext {
        ProposalContext {
            task_id: "t-1".into(),
            content: "Create final.txt containing 'delegated governance works'.".into(),
            attempt_no: 1,
            allowed: vec![write_text()],
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
            schema: orxnud_domain::ParamSchema::new(vec![orxnud_domain::ParamField::required(
                "to",
                orxnud_domain::ParamKind::String,
                "Recipient.",
            )]),
            target: orxnud_domain::TargetSemantics::Required,
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

    /// The declared shape is enforced at propose time, so a malformed request never
    /// becomes a durable proposal that can only fail later.
    ///
    /// This is the case that used to be invisible: the shape existed only inside the
    /// capability, reached at execution, where the proposal had already been written and
    /// a human had already been asked to approve it.
    #[test]
    fn parameters_must_match_the_declared_shape() {
        let cases: Vec<(&str, &str)> = vec![
            (
                r#"{"capability":"filesystem/write-text","target":"final.txt","params":{"path":"final.txt"}}"#,
                "`contents` is required",
            ),
            (
                r#"{"capability":"filesystem/write-text","target":"final.txt","params":{"path":"final.txt","contents":42}}"#,
                "`contents` must be string",
            ),
            (
                r#"{"capability":"filesystem/write-text","target":"final.txt","params":{"path":"a.txt","contents":"x","sudo":true}}"#,
                "`sudo` is not a parameter",
            ),
        ];
        for (text, expected) in cases {
            let err = validate(text, &ctx(), &registered)
                .expect_err("a malformed parameter set must not become a proposal");
            assert_eq!(err.reason(), "proposal-schema-mismatch", "{text}");
            let ProposalRejected::SchemaMismatch { problems, .. } = &err else {
                panic!("expected a schema refusal, got {err:?}");
            };
            assert!(
                problems.iter().any(|p| p.contains(expected)),
                "{text}: {problems:?} does not mention {expected:?}"
            );
        }
    }

    /// A well-formed proposal still passes, and the refusal above is not a blanket ban.
    #[test]
    fn a_conforming_proposal_is_accepted() {
        let ok = validate(
            r#"{"capability":"filesystem/write-text","target":"final.txt","params":{"path":"final.txt","contents":"delegated governance works"}}"#,
            &ctx(),
            &registered,
        );
        assert!(ok.is_ok(), "a conforming proposal must be accepted");
    }

    /// A capability that acts on a named target cannot be asked to act without one. This
    /// used to reach the execution planner, where a `None` target became a missing-file
    /// error attributed to the sandbox rather than to the request.
    #[test]
    fn a_capability_that_needs_a_target_must_be_given_one() {
        let err = validate(
            r#"{"capability":"filesystem/write-text","params":{"path":"final.txt","contents":"x"}}"#,
            &ctx(),
            &registered,
        )
        .expect_err("no target supplied");
        assert_eq!(err.reason(), "proposal-target-missing");
        assert_eq!(
            err,
            ProposalRejected::MissingTarget {
                capability: "filesystem/write-text".into()
            }
        );
    }

    /// A capability with no target semantics accepts a request either way — refusing
    /// here would be a rule about the wire rather than about the capability.
    #[test]
    fn a_capability_with_no_target_semantics_needs_no_target() {
        let mut c = ctx();
        c.allowed = vec![AllowedCapability {
            id: "text/word-count".into(),
            description: "Count words".into(),
            params: vec!["text".into()],
            schema: orxnud_domain::ParamSchema::new(vec![orxnud_domain::ParamField::required(
                "text",
                orxnud_domain::ParamKind::String,
                "The text.",
            )]),
            target: orxnud_domain::TargetSemantics::None,
        }];
        let counted = |target: &str| {
            validate(
                &format!(
                    r#"{{"capability":"text/word-count",{target}"params":{{"text":"hello world"}}}}"#
                ),
                &c,
                &|id| id == "text/word-count",
            )
        };
        assert!(counted("").is_ok(), "no target is fine");
        assert!(counted(r#""target":"a.txt","#).is_ok(), "a target is fine");
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
