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
    /// No provider is configured for this daemon.
    ///
    /// A distinct refusal rather than a fallback. A daemon with no provider answering
    /// `task/ai-propose` with a scripted proposal would be indistinguishable from a
    /// working model, which is the one confusion this whole path must not have.
    #[error("no proposal provider is configured (provider-not-configured)")]
    NotConfigured,
    /// The provider is configured but its credential is not present.
    #[error("the proposal provider has no credential stored: {0}")]
    CredentialAbsent(String),
    /// The credential store could not be reached.
    ///
    /// Never carries the credential itself, and never the store's error verbatim if that
    /// error might quote the value it failed to handle.
    #[error("the credential store is unavailable: {0}")]
    CredentialStore(String),
    /// The provider was asked and could not be reached at all: no route, refused
    /// connection, DNS failure.
    ///
    /// Split from [`Self::Tls`] on purpose. "The host is down" and "the certificate did
    /// not verify" call for different operator responses, and a caller deciding whether to
    /// retry needs to tell them apart — retrying a certificate failure just fails again,
    /// and retrying a refused connection is legitimate.
    #[error("the proposal provider could not be reached: {0}")]
    Unreachable(String),
    /// A TLS handshake, certificate chain check or hostname check failed.
    ///
    /// Never answered by retrying without encryption, and never by trying another
    /// endpoint. That would turn a failed authentication of the far side into a plaintext
    /// request carrying a credential.
    #[error("{0}")]
    Tls(String),
    /// A plaintext provider was configured and plaintext is not permitted.
    ///
    /// A refusal rather than a warning, and it exists because a credential must never
    /// travel unencrypted: `http://` remains available only for a loopback test server,
    /// which is explicitly opted into and refuses to carry an `Authorization` header.
    #[error("a plaintext provider cannot be used here ({0}); use https")]
    PlaintextRefused(String),
    /// The provider did not answer within the deadline.
    ///
    /// Its own variant rather than `Unavailable` because the two call for different
    /// operator responses and collapsing them tells an operator nothing useful.
    #[error("the proposal provider did not answer within {millis}ms")]
    Timeout {
        /// The deadline that elapsed.
        millis: u64,
    },
    /// The provider answered with a non-success status.
    ///
    /// Only the status code is retained. The response body is dropped unread: it is
    /// attacker-influenced text, and putting it in an error string is how untrusted
    /// content ends up in logs and audit records.
    #[error("the proposal provider answered HTTP {status} ({kind:?})")]
    Status {
        /// The HTTP status code.
        status: u16,
        /// What that status means for a caller.
        kind: StatusKind,
    },
    /// The provider answered, but not in a shape this adapter understands.
    #[error("the proposal provider's response was not in the expected shape: {0}")]
    MalformedResponse(String),
    /// The configured transport is not implemented.
    ///
    /// Refused rather than downgraded. Silently dropping TLS would turn a configured
    /// `https://` endpoint into a plaintext attempt at the same host, which is the kind
    /// of quiet downgrade nobody notices until it matters.
    #[error("{0} is not supported by this provider (provider-transport-unsupported)")]
    TransportUnsupported(String),
}

impl ProviderError {
    /// A fixed word for the wire, so a client branches on a vocabulary rather than on
    /// prose that may change.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::NotConfigured => "provider-not-configured",
            Self::CredentialAbsent(_) => "provider-credential-absent",
            Self::CredentialStore(_) => "provider-credential-store-unavailable",
            Self::Unreachable(_) => "provider-unreachable",
            Self::Tls(_) => "provider-tls-failed",
            Self::PlaintextRefused(_) => "provider-plaintext-refused",
            Self::Timeout { .. } => "provider-timeout",
            Self::Status { kind, .. } => match kind {
                StatusKind::Authentication => "provider-authentication-failed",
                StatusKind::RateLimited => "provider-rate-limited",
                StatusKind::Server => "provider-server-error",
                StatusKind::Other => "provider-http-error",
            },
            Self::MalformedResponse(_) => "provider-response-malformed",
            Self::TransportUnsupported(_) => "provider-transport-unsupported",
        }
    }
}

/// What an HTTP status means to a caller.
///
/// Grouped rather than passed through raw, because 401 and 503 are both "the provider
/// did not do what was asked" and an operator's next step differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    /// 401, 403: the credential was rejected.
    Authentication,
    /// 429: too many requests.
    RateLimited,
    /// 5xx: the provider failed.
    Server,
    /// Any other non-success status.
    Other,
}

impl StatusKind {
    /// Classifies a status code.
    #[must_use]
    pub const fn of(status: u16) -> Self {
        match status {
            401 | 403 => Self::Authentication,
            429 => Self::RateLimited,
            500..=599 => Self::Server,
            _ => Self::Other,
        }
    }
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

/// How a prior logical step concluded, as the model is allowed to see it.
///
/// The **closed** four-value vocabulary, never free text. `task_step_results.verification`
/// holds prose written by a verifier — for a read it names a path, a byte count and a digest,
/// and in general it is whatever that verifier chose to say. Forwarding it would put
/// workspace-derived text into a prompt, so it stays in the durable record and is not
/// carried here. The status is the bounded summary instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorStepStatus {
    /// The step's effect was observed and verified.
    Verified,
    /// Verification established the effect did not occur.
    Refuted,
    /// Verification could not decide.
    Undetermined,
    /// The step failed.
    Failed,
}

impl PriorStepStatus {
    /// The label rendered into the prompt.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Refuted => "refuted",
            Self::Undetermined => "undetermined",
            Self::Failed => "failed",
        }
    }
}

/// One prior logical step, as the model is shown it.
///
/// Metadata only. There is no field here that could hold file contents, capability output or
/// helper stdout, which is the property the type exists to guarantee: adding one would be a
/// visible change to this struct rather than a quiet widening of a `String`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorStep {
    /// The 1-based logical step. Durable, and never inferred from an attempt number.
    pub step_no: u32,
    /// How it concluded, from the closed vocabulary.
    pub status: PriorStepStatus,
    /// Workspace-relative paths this step produced, bounded in count and length.
    ///
    /// Relative because the capability contract already speaks in workspace-relative paths
    /// and an absolute host path is both useless to a model and a disclosure of the host's
    /// directory layout.
    pub artifacts: Vec<String>,
}

/// Bounded prior-step metadata, derived at request time and never persisted.
///
/// The whole of what a model learns about earlier steps. It exists only for the duration of
/// one provider request: it is a projection of `task_step_results`, not a new record, so
/// there is no table, no schema change and nothing to keep consistent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PriorStepContext {
    /// Steps in ascending `step_no` order. Ascending because that is what the store returns,
    /// and never a hash-map iteration order.
    pub steps: Vec<PriorStep>,
}

impl PriorStepContext {
    /// Whether there is anything to say.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// The most recent `keep` steps, oldest first.
    ///
    /// Trimming drops the **oldest** steps and keeps the most recent, because the most recent
    /// is the one whose output the next step is most likely to build on. Selection is by
    /// position in an ascending list, so it is deterministic.
    #[must_use]
    pub fn most_recent(&self, keep: usize) -> Self {
        if self.steps.len() <= keep {
            return self.clone();
        }
        Self {
            steps: self.steps[self.steps.len() - keep..].to_vec(),
        }
    }
}

/// Builds the model-facing context from durable step rows.
///
/// # What is deliberately not carried across
///
/// * `structured_output` — for `filesystem/read-text` this is the file's bytes. It is already
///   dropped before it reaches a step result (see `AdapterBundle::output_is_ephemeral`), and
///   it is dropped again here so a future capability cannot reintroduce the leak by writing
///   output into that column.
/// * `verification` — verifier prose, workspace-derived for a read. It stays in the durable
///   record for audit and is replaced here by the bounded `status`.
/// * the row's `recorded_at_ms` and the worker/lease identity behind the step.
pub fn prior_step_context_from(
    rows: &[orxnud_store::task_repo::StepResultRow],
) -> PriorStepContext {
    PriorStepContext {
        steps: rows
            .iter()
            .map(|row| PriorStep {
                step_no: row.step_no,
                status: match row.status {
                    orxnud_store::task_repo::StepStatus::Verified => PriorStepStatus::Verified,
                    orxnud_store::task_repo::StepStatus::Refuted => PriorStepStatus::Refuted,
                    orxnud_store::task_repo::StepStatus::Undetermined => {
                        PriorStepStatus::Undetermined
                    }
                    orxnud_store::task_repo::StepStatus::Failed => PriorStepStatus::Failed,
                },
                artifacts: bounded_artifacts(row.artifacts.as_deref()),
            })
            .collect(),
    }
}

/// Longest artifact path forwarded. Long enough for any real workspace path, short enough
/// that a pathological one cannot dominate the request.
const MAX_ARTIFACT_PATH: usize = 256;

/// How many artifact paths one step may contribute.
const MAX_ARTIFACTS_PER_STEP: usize = 32;

/// Extracts workspace-relative artifact paths from a step row.
///
/// # Why this parses rather than forwards
///
/// `task_step_results.artifacts` is a free-form column, and this is where the guarantee
/// "no arbitrary metadata reaches the model" is actually enforced. Anything that is not
/// recognisably a relative path — an absolute path, a `..` component, an empty segment — is
/// **dropped**, not sanitised: a rewritten path would be a different path, and quietly
/// changing what a model is told about is worse than telling it less.
///
/// Entries are read as JSON when the column holds a JSON array, which is how the runtime
/// writes it, and as a single path otherwise so a hand-written row still yields something
/// useful. Both forms still go through the same checks below.
fn bounded_artifacts(raw: Option<&str>) -> Vec<String> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    if raw.is_empty() || raw.len() > MAX_ARTIFACT_PATH * MAX_ARTIFACTS_PER_STEP {
        return Vec::new();
    }

    let candidates: Vec<String> = match serde_json::from_str::<Vec<String>>(raw) {
        Ok(list) => list,
        Err(_) => vec![raw.to_owned()],
    };

    let mut out: Vec<String> = Vec::new();
    for candidate in candidates {
        if out.len() >= MAX_ARTIFACTS_PER_STEP {
            break;
        }
        if let Some(clean) = safe_relative_path(&candidate) {
            out.push(clean);
        }
    }
    out
}

/// Accepts a workspace-relative path, or refuses it.
///
/// The same rules the capability contract uses: not absolute, no `..`, no empty, and not so
/// long that it could be used to fill a request.
fn safe_relative_path(candidate: &str) -> Option<String> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_ARTIFACT_PATH {
        return None;
    }
    let path = std::path::Path::new(trimmed);
    if path.is_absolute() {
        return None;
    }
    for component in path.components() {
        // Anything that is not a plain name is refused: `..`, `.`, and on Windows a prefix.
        if !matches!(component, std::path::Component::Normal(_)) {
            return None;
        }
    }
    Some(trimmed.to_owned())
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
    /// What earlier steps of this task did, as metadata.
    ///
    /// Defaulted so every existing construction site keeps compiling and, more importantly,
    /// keeps behaving as it did: a task with no prior steps renders exactly the message it
    /// rendered before this field existed.
    pub prior_steps: PriorStepContext,
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

/// The model's *other* answer: that no further work is needed.
///
/// A second declared shape rather than a third field on [`RawProposal`], because the two
/// answers are mutually exclusive and saying both at once is not a request we can
/// interpret. Carrying a `done` key selects this shape, so `{"done": true, "capability":
/// ...}` is refused as unreadable rather than resolved by preferring one half.
///
/// `summary` is the model's own account of why it is stopping. It is descriptive
/// metadata with no authority -- it grants nothing, executes nothing, and is never read
/// back as input to a decision -- so it is bounded rather than refused: an over-verbose
/// summary must not strand a task that has correctly finished.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDone {
    done: bool,
    summary: String,
}

/// The longest `summary` kept from a `done` answer.
///
/// Describing the work in one short sentence is all this field is for; anything longer is
/// cut rather than refused, so verbosity cannot become a way to fail to finish.
pub const MAX_DONE_SUMMARY_CHARS: usize = 280;

/// What the model said the next step is — or that there isn't one.
///
/// The type exists so "do the next thing" and "there is nothing left to do" are two
/// named cases a reviewer can find, rather than one case plus a magic capability string
/// that would have to be registered, allow-listed and dispatched in order to mean
/// *nothing happens*. Nothing here is a capability: a [`ProposalOutcome::Done`] carries
/// no target, no parameters and no authority, and cannot be proposed for, approved, or
/// executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalOutcome {
    /// The model proposed work to do.
    Step(ValidatedProposal),
    /// The model says no further work is needed.
    Done {
        /// Why, in the model's words. Descriptive only.
        summary: String,
    },
}

/// Why a provider's text did not become a proposal.
///
/// Every variant is a refusal. There is no "best effort" path, because a proposal the
/// runtime only half-understood is an action nobody approved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProposalRejected {
    /// The text was not the expected JSON object.
    ///
    /// Prose wrapped around a JSON object is refused, and so is a second object after a
    /// valid one. Guessing which action was meant is exactly the ambiguity the
    /// deterministic side exists to refuse.
    #[error("the model's output was not a single proposal object this runtime understands")]
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
            Self::Unreadable => "proposal-malformed",
            // The menu is walked from `Registry::enabled()`, so "not on the menu" and
            // "unknown to this build" are the same observation a model can make, and it
            // gets the name that says so.
            Self::CapabilityNotAllowed(_) => "proposal-capability-unknown",
            Self::UnknownCapability(_) => "proposal-capability-not-implemented",
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
/// Returns which of the two declared shapes the provider answered with. Every failure is
/// a refusal — there is no "best effort" path, because a proposal the runtime only
/// half-understood is an action nobody approved.
///
/// A `done` answer short-circuits the checks below, because it names no capability and
/// so has nothing to check against the allowlist: it cannot ask for a capability it was
/// not offered. It is for the *runtime* to decide what to do with, since only the runtime
/// knows whether a caller is entitled to stop the task.
///
/// Otherwise the refusals, in order: unreadable text, a capability outside the allowlist,
/// and a capability this build does not implement. Note what is *not* checked here — the
/// capability's own parameter validation happens when the plan is built at execution, so a
/// malformed parameter set becomes a refusal there rather than a proposal that cannot
/// run.
///
/// # Errors
///
/// [`ProposalRejected`] if the text cannot be understood or names something not
/// permitted.
pub fn validate(
    text: &str,
    ctx: &ProposalContext,
    is_registered: &dyn Fn(&str) -> bool,
) -> Result<ProposalOutcome, ProposalRejected> {
    // Parsed strictly: a bare string, a list, or an object with unexpected keys is not
    // an answer, and guessing at the intent is exactly the creative interpretation the
    // deterministic side exists to prevent.
    //
    // The two declared shapes are told apart by the presence of a `done` key, so neither
    // is a special case of the other and a contradictory answer resolves to nothing
    // rather than to whichever half happened to be readable.
    let text = text.trim();
    let shape: serde_json::Value =
        serde_json::from_str(text).map_err(|_| ProposalRejected::Unreadable)?;

    if shape.get("done").is_some() {
        let RawDone { done, summary } =
            serde_json::from_value::<RawDone>(shape).map_err(|_| ProposalRejected::Unreadable)?;
        // `{"done": false, ...}` asks for neither shape. Read as "keep going" it would
        // be an invitation to keep asking a model that is answering badly; refused
        // instead, so a malformed "done" is visible rather than silently reinterpreted.
        if !done {
            return Err(ProposalRejected::Unreadable);
        }
        return Ok(ProposalOutcome::Done {
            summary: summary.chars().take(MAX_DONE_SUMMARY_CHARS).collect(),
        });
    }

    let raw: RawProposal =
        serde_json::from_value(shape).map_err(|_| ProposalRejected::Unreadable)?;

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

    Ok(ProposalOutcome::Step(ValidatedProposal {
        capability: raw.capability,
        target: raw.target,
        params: raw.params,
    }))
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
            prior_steps: Default::default(),
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
        let ProposalOutcome::Step(p) = p else {
            panic!("a proposal asking for work must not read as a task finished")
        };
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
        let ProposalOutcome::Step(p) = p else {
            panic!("a proposal asking for work must not read as a task finished")
        };
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
        assert_eq!(err.reason(), "proposal-capability-not-implemented");
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
        assert_eq!(err.reason(), "proposal-capability-unknown");
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

/// Stage 4b: the prior-step context the model is shown.
///
/// The governing property is negative: this is metadata, and the type is built so that
/// content cannot be put into it by accident. Each test below pins one way content could
/// arrive, because "the model is only told metadata" is a claim about every field.
#[cfg(test)]
mod prior_step_tests {
    use super::*;
    use orxnud_store::task_repo::{StepResultRow, StepStatus};

    /// Unmistakable in a prompt, a request body or a log.
    const SENTINEL: &str = "SENTINEL-PRIOR-CONTENT-MUST-NOT-LEAK-71ac3f";

    fn row(step: u32, status: StepStatus) -> StepResultRow {
        StepResultRow {
            task_id: orxnud_domain::ids::TaskId::new("t"),
            step_no: step,
            status,
            verification: Some(format!("{SENTINEL} held 42 bytes (deadbeef)")),
            // The column a read *could* have used to carry content. It must not be forwarded.
            structured_output: Some(format!("{{\"contents\":\"{SENTINEL}\"}}")),
            artifacts: None,
            recorded_at_ms: NOW_MS,
        }
    }

    const NOW_MS: i64 = 1_767_225_600_000;

    fn rendered(ctx: &PriorStepContext) -> String {
        format!("{ctx:?}")
    }

    // ------------------------------------------------ derivation

    #[test]
    fn context_is_derived_from_durable_rows_in_step_order() {
        let rows = vec![row(1, StepStatus::Verified), row(2, StepStatus::Refuted)];
        let ctx = prior_step_context_from(&rows);
        assert_eq!(
            ctx.steps.iter().map(|s| s.step_no).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[test]
    fn every_status_maps_to_the_closed_vocabulary() {
        let rows = vec![
            row(1, StepStatus::Verified),
            row(2, StepStatus::Refuted),
            row(3, StepStatus::Undetermined),
            row(4, StepStatus::Failed),
        ];
        let ctx = prior_step_context_from(&rows);
        assert_eq!(
            ctx.steps
                .iter()
                .map(|s| s.status.as_str())
                .collect::<Vec<_>>(),
            vec!["verified", "refuted", "undetermined", "failed"]
        );
    }

    /// The load-bearing exclusion: verifier prose is workspace-derived for a read.
    #[test]
    fn verifier_evidence_is_not_forwarded() {
        let ctx = prior_step_context_from(&[row(1, StepStatus::Verified)]);
        let text = rendered(&ctx);
        assert!(
            !text.contains("deadbeef"),
            "the durable digest leaked into the context: {text}"
        );
        assert!(
            !text.contains(SENTINEL),
            "verifier evidence leaked into the context: {text}"
        );
    }

    /// And the column a read's bytes would have used.
    #[test]
    fn structured_output_is_not_forwarded() {
        let ctx = prior_step_context_from(&[row(1, StepStatus::Verified)]);
        let text = rendered(&ctx);
        assert!(
            !text.contains(SENTINEL),
            "structured_output leaked into the context: {text}"
        );
    }

    #[test]
    fn the_step_number_is_the_durable_logical_step() {
        // Step 3 on its third attempt is still step 3; nothing here consults an attempt.
        let ctx = prior_step_context_from(&[row(3, StepStatus::Verified)]);
        assert_eq!(ctx.steps[0].step_no, 3);
    }

    // ---------------------------------------------------- artifacts

    #[test]
    fn artifacts_are_read_as_workspace_relative_paths() {
        let mut r = row(1, StepStatus::Verified);
        r.artifacts = Some(r#"["a.txt","sub/b.txt"]"#.to_owned());
        let ctx = prior_step_context_from(&[r]);
        assert_eq!(
            ctx.steps[0].artifacts,
            vec!["a.txt".to_owned(), "sub/b.txt".to_owned()]
        );
    }

    /// Absolute host paths are dropped, not sanitised: a rewritten path is a different path.
    #[test]
    fn absolute_host_paths_are_dropped() {
        let mut r = row(1, StepStatus::Verified);
        r.artifacts = Some(r#"["/home/rayees/Projects/secret.env","a.txt"]"#.to_owned());
        let ctx = prior_step_context_from(&[r]);
        assert_eq!(ctx.steps[0].artifacts, vec!["a.txt".to_owned()]);
        assert!(
            !rendered(&ctx).contains("rayees"),
            "a host path leaked: {:?}",
            ctx.steps[0].artifacts
        );
    }

    #[test]
    fn traversing_and_empty_artifact_paths_are_dropped() {
        for bad in ["../escape.txt", "a/../../b.txt", "", "   ", "."] {
            let mut r = row(1, StepStatus::Verified);
            r.artifacts = Some(serde_json::json!([bad]).to_string());
            let ctx = prior_step_context_from(&[r]);
            assert!(
                ctx.steps[0].artifacts.is_empty(),
                "{bad:?} must be dropped, got {:?}",
                ctx.steps[0].artifacts
            );
        }
    }

    #[test]
    fn a_single_path_is_accepted_without_json() {
        let mut r = row(1, StepStatus::Verified);
        r.artifacts = Some("a.txt".to_owned());
        assert_eq!(
            prior_step_context_from(&[r]).steps[0].artifacts,
            vec!["a.txt"]
        );
    }

    #[test]
    fn the_artifact_count_and_length_are_bounded() {
        let mut r = row(1, StepStatus::Verified);
        r.artifacts = Some(
            serde_json::json!((0..200).map(|i| format!("f{i}.txt")).collect::<Vec<_>>())
                .to_string(),
        );
        let ctx = prior_step_context_from(&[r]);
        assert!(
            ctx.steps[0].artifacts.len() <= 32,
            "artifact count is unbounded: {}",
            ctx.steps[0].artifacts.len()
        );

        let mut r2 = row(1, StepStatus::Verified);
        r2.artifacts = Some(serde_json::json!(["x".repeat(4096)]).to_string());
        assert!(
            prior_step_context_from(&[r2]).steps[0].artifacts.is_empty(),
            "an absurdly long path must be dropped, not forwarded"
        );
    }

    #[test]
    fn an_absurdly_large_artifacts_column_is_dropped_whole() {
        let mut r = row(1, StepStatus::Verified);
        r.artifacts = Some("x".repeat(100_000));
        assert!(prior_step_context_from(&[r]).steps[0].artifacts.is_empty());
    }

    // -------------------------------------------------- ephemerality

    #[test]
    fn the_context_carries_no_handle_to_anything() {
        // A structural check rather than a behavioural one: the type has no field that could
        // reach the store, the filesystem, policy or the dispatcher.
        let ctx = prior_step_context_from(&[row(1, StepStatus::Verified)]);
        let _: &PriorStep = &ctx.steps[0];
        // Compiles only because there is nothing else to hold.
        let _clone = ctx.clone();
    }

    // ------------------------------------------------ determinism

    #[test]
    fn selection_keeps_the_most_recent_steps_in_order() {
        let rows: Vec<StepResultRow> = (1..=5).map(|n| row(n, StepStatus::Verified)).collect();
        let ctx = prior_step_context_from(&rows);
        assert_eq!(
            ctx.most_recent(2)
                .steps
                .iter()
                .map(|s| s.step_no)
                .collect::<Vec<_>>(),
            vec![4, 5],
            "the newest steps survive, still ascending"
        );
        assert_eq!(
            ctx.most_recent(99).steps.len(),
            5,
            "asking for more is not lossy"
        );
        assert!(ctx.most_recent(0).is_empty());
    }

    #[test]
    fn derivation_is_deterministic_across_repeated_calls() {
        let rows: Vec<StepResultRow> = (1..=4).map(|n| row(n, StepStatus::Failed)).collect();
        let first = rendered(&prior_step_context_from(&rows));
        for _ in 0..8 {
            assert_eq!(rendered(&prior_step_context_from(&rows)), first);
        }
    }

    #[test]
    fn no_rows_is_an_empty_context() {
        assert!(prior_step_context_from(&[]).is_empty());
        assert_eq!(prior_step_context_from(&[]), PriorStepContext::default());
    }
}
