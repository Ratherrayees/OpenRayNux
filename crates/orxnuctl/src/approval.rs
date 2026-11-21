//! The protocol-level approval workflow, shared by the CLI and the TUI.
//!
//! # What lives here
//!
//! The sequence that turns a proposal into an approval, and nothing that belongs to a
//! particular surface:
//!
//! 1. an inspection-only preview, which classifies the proposal without minting a
//!    challenge;
//! 2. for a model-initiated file read, a **fresh** challenge-bearing preview, a human
//!    decision, and an approval carrying that challenge and `confirmed: true`;
//! 3. for every other proposal, the ordinary approval route with no challenge and no
//!    confirmation.
//!
//! The workflow is staged rather than callback-driven. [`begin_approval`] performs the
//! protocol steps and either submits the approval or returns a [`Review`] describing
//! what a human must decide. [`submit_review`] finishes the review. A caller renders the
//! review in whatever medium it owns — a terminal or a terminal UI — and no `BufRead` or
//! `Write` appears in this module.
//!
//! The daemon remains the security authority. This module decides only which requests
//! to send; it never decides whether an approval is valid. In particular it never adds
//! a recipient, path, capability, endpoint or any other authority-bearing field to an
//! approval request — it only copies the challenge from the fresh preview the daemon
//! just produced.

use serde_json::{Value, json};

use crate::client::{CallFailure, CallOrigin, Client, ClientError};

/// The protocol step at which an approval workflow failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStage {
    /// Validating the caller's approval payload, before any RPC.
    Payload,
    /// The inspection-only preview.
    InspectPreview,
    /// The fresh challenge-bearing preview for a file read.
    ChallengePreview,
    /// An `capability/approve` submission.
    ApprovalSubmission,
}

/// Where an approval failure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalFailureOrigin {
    /// The request could not be encoded; nothing was sent.
    RequestEncoding,
    /// The reply could not be decoded; the request may have been executed.
    ResponseDecoding,
    /// Writing or reading the request failed; the outcome is ambiguous.
    Transport,
    /// The daemon answered with an explicit error.
    Refusal,
    /// No connection could be established; nothing was sent.
    PreSendUnavailable,
    /// A local validation check rejected the response or request.
    LocalValidation,
    /// The caller could not provide a more precise origin.
    Unknown,
}

/// An approval failure with its stage and origin, carrying the original error once.
#[derive(Debug)]
pub struct ApprovalFailure {
    /// The protocol step that failed.
    pub stage: ApprovalStage,
    /// Where the failure originated.
    pub origin: ApprovalFailureOrigin,
    /// The original client error, unchanged.
    pub error: ClientError,
}

fn from_call(stage: ApprovalStage, failure: CallFailure) -> ApprovalFailure {
    let origin = match failure.origin {
        CallOrigin::RequestEncoding => ApprovalFailureOrigin::RequestEncoding,
        CallOrigin::ResponseDecoding => ApprovalFailureOrigin::ResponseDecoding,
        CallOrigin::Transport => ApprovalFailureOrigin::Transport,
        CallOrigin::Refusal => ApprovalFailureOrigin::Refusal,
        CallOrigin::PreSendUnavailable => ApprovalFailureOrigin::PreSendUnavailable,
        CallOrigin::Unknown => ApprovalFailureOrigin::Unknown,
    };
    ApprovalFailure {
        stage,
        origin,
        error: failure.error,
    }
}

fn from_local(stage: ApprovalStage, error: ClientError) -> ApprovalFailure {
    ApprovalFailure {
        stage,
        origin: ApprovalFailureOrigin::LocalValidation,
        error,
    }
}

/// What the daemon says a proposal is, and therefore what the caller must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalKind {
    /// A model-initiated file read: approving it discloses the contents to the
    /// provider that originated the proposal, so it needs a reviewed confirmation.
    ModelInitiatedFileRead,
    /// A model-initiated proposal of some other capability.
    ModelInitiated,
    /// A direct, human-delegated proposal.
    DirectProposal,
}

/// Reads the server's classification of a proposal.
///
/// # Failing closed
///
/// Anything missing, unknown, or internally inconsistent is an error. A client that
/// cannot tell what it is approving must not approve it, and in particular must not
/// conclude that a proposal is human-originated merely because a recipient label or a
/// fingerprint is missing.
pub fn classify_proposal(preview: &Value) -> Result<ProposalKind, String> {
    let p = preview
        .get("preview")
        .ok_or("the preview reply carried no `preview`")?;
    let kind = p
        .get("proposal_kind")
        .and_then(Value::as_str)
        .ok_or("the preview carried no `proposal_kind`")?;
    let requires = p
        .get("requires_confirmation")
        .and_then(Value::as_bool)
        .ok_or("the preview carried no `requires_confirmation`")?;
    let operation = p
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("the preview carried no `operation`")?;
    match kind {
        "model-initiated-file-read" => {
            if !requires {
                return Err(
                    "a model-initiated file read must require a disclosure confirmation".to_owned(),
                );
            }
            if operation != "file-read" {
                return Err(format!(
                    "a model-initiated file read must be a file read, not {operation:?}"
                ));
            }
            Ok(ProposalKind::ModelInitiatedFileRead)
        }
        "model-initiated" => {
            if requires {
                return Err(
                    "only a model-initiated file read may require a disclosure confirmation"
                        .to_owned(),
                );
            }
            Ok(ProposalKind::ModelInitiated)
        }
        "direct-proposal" => {
            if requires {
                return Err("a direct proposal cannot require a disclosure confirmation".to_owned());
            }
            Ok(ProposalKind::DirectProposal)
        }
        other => Err(format!("unknown proposal kind {other:?}")),
    }
}

/// Display budget for one untrusted field in the narrow TUI review pane.
///
/// The bound counts *displayed characters after escaping*, so an escape such as
/// `\u{202e}` consumes eight characters of the budget rather than the one the raw
/// codepoint would. Truncation keeps a prefix and a suffix so a path's final component
/// is not hidden, and states how many displayed characters were omitted.
const DISPLAY_LIMIT: usize = 160;

/// Whether a codepoint must not be emitted verbatim into a review or terminal field.
///
/// Coverage policy (explicit, not a claim of full Unicode general-category classification):
/// - Cc: everything `char::is_control()` reports, plus line/paragraph separators that
///   would otherwise inject a new rendered line.
/// - Cf: the assigned format characters, including bidi overrides/isolates and
///   zero-width/invisible characters. This is the category the standard library's
///   `is_control()` does **not** cover, and it includes the measured canaries
///   U+202E, U+200B, U+2066, U+2069 and U+FEFF.
/// - Interlinear annotation and tag characters that can reorder or hide text.
///
/// Deliberately not escaped: variation selectors (Mn), combining marks and emoji
/// modifiers, which are needed for legitimate script and emoji rendering. ZWJ/ZWNJ
/// *are* in the escaped Cf set (U+200D/U+200C), so joining text and some emoji
/// sequences can render differently in this review pane; that is an intentional
/// security-over-shaping trade. This is a targeted safety policy, not a guarantee of
/// full Unicode general-category or default-ignorable classification, and truncation
/// is per codepoint, so a grapheme cluster can be split at the display boundary.
/// The emitted string is bounded, but token construction iterates the raw field first;
/// raw field size is bounded by the transport frame, not by this helper.
fn must_escape(c: char) -> bool {
    let u = c as u32;
    c.is_control()
        || matches!(
            u,
            0x00AD
                | 0x0600..=0x0605
                | 0x061C
                | 0x06DD
                | 0x070F
                | 0x0890..=0x0891
                | 0x08E2
                | 0x180E
                | 0x200B..=0x200F
                | 0x2028..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x206F
                | 0xFEFF
                | 0xFFF9..=0xFFFB
                | 0x110BD
                | 0x110CD
                | 0x13430..=0x1343F
                | 0x1BCA0..=0x1BCA3
                | 0x1D173..=0x1D17A
                | 0xE0001
                | 0xE0020..=0xE007F
        )
}

fn display_token(c: char) -> String {
    if must_escape(c) {
        format!("\\u{{{:x}}}", c as u32)
    } else {
        c.to_string()
    }
}

/// Renders one untrusted field safely and within [`DISPLAY_LIMIT`].
///
/// Escaping is applied per codepoint before the bound is checked, so no escape
/// sequence is split and no unbounded intermediate string is built for the emitted
/// representation. The omitted count is in displayed (post-escape) characters.
fn bounded_display(value: &str) -> String {
    let tokens: Vec<String> = value.chars().map(display_token).collect();
    let total: usize = tokens.iter().map(|t| t.chars().count()).sum();
    if total <= DISPLAY_LIMIT {
        return tokens.concat();
    }

    let marker = |omitted: usize| format!("…[{} chars omitted]…", omitted);
    let mut omitted = total.saturating_sub(DISPLAY_LIMIT);
    for _ in 0..8 {
        let marker = marker(omitted);
        let budget = DISPLAY_LIMIT.saturating_sub(marker.chars().count());
        let prefix_budget = budget / 2;
        let suffix_budget = budget - prefix_budget;

        let mut prefix = String::new();
        let mut prefix_used = 0usize;
        for token in &tokens {
            let n = token.chars().count();
            if prefix_used + n > prefix_budget {
                break;
            }
            prefix.push_str(token);
            prefix_used += n;
        }
        let mut suffix = String::new();
        let mut suffix_used = 0usize;
        for token in tokens.iter().rev() {
            let n = token.chars().count();
            if suffix_used + n > suffix_budget {
                break;
            }
            suffix.insert_str(0, token);
            suffix_used += n;
        }

        let remaining = total.saturating_sub(prefix_used + suffix_used);
        let rendered = format!("{prefix}{marker}{suffix}");
        if remaining == omitted || rendered.chars().count() > DISPLAY_LIMIT {
            return rendered;
        }
        omitted = remaining;
    }
    marker(omitted)
}

/// Whether a value would be truncated by the display bound.
///
/// A truncation marker makes the loss visible, but an incomplete review is not a
/// complete review. Callers use this to fail closed rather than to relabel the marker.
#[must_use]
pub fn exceeds_display_limit(value: &str) -> bool {
    value
        .chars()
        .map(display_token)
        .map(|token| token.chars().count())
        .sum::<usize>()
        > DISPLAY_LIMIT
}

/// Makes an untrusted stored value or daemon-supplied field safe to display.
///
/// Ordinary readable text is preserved; control, bidi and invisible characters are
/// shown as code points, and the result is bounded with a visible truncation marker.
pub fn safe_text(value: &str) -> String {
    bounded_display(value)
}

/// The recipient label, if it is safe to print.
///
/// The daemon supplies a *safe* label, built by its own projection. If it ever supplied
/// something that looks like a raw URL carrying user information, a query or a fragment,
/// it is **not** printed: a credential must not reach a review because a projection
/// changed.
pub fn safe_recipient(label: &str) -> Option<String> {
    if label.contains('@') || label.contains('?') || label.contains('#') {
        return None;
    }
    Some(safe_text(label))
}

/// The requests the approval workflow makes.
///
/// The real client and the deterministic test fakes of both surfaces satisfy this
/// trait, so the sequence the tests record is the sequence production runs — not a
/// second implementation of it. It is public because the TUI supplies its own fake.
pub trait PreviewRequests {
    /// Performs one request and returns its `result` value.
    fn call(&self, method: &str, params: Value) -> Result<Value, ClientError>;

    /// As [`Self::call`], with failure provenance for callers that need it.
    ///
    /// Implementations that cannot provide a precise origin conservatively report
    /// [`CallOrigin::Unknown`].
    fn call_staged(&self, method: &str, params: Value) -> Result<Value, CallFailure> {
        self.call(method, params).map_err(|error| {
            let origin = match &error {
                ClientError::Refused { .. } => CallOrigin::Refusal,
                ClientError::Unavailable { .. } => CallOrigin::PreSendUnavailable,
                ClientError::Transport(_) => CallOrigin::Transport,
                ClientError::Malformed(_) => CallOrigin::ResponseDecoding,
                ClientError::InvalidParams { .. } | ClientError::VersionMismatch { .. } => {
                    CallOrigin::Unknown
                }
            };
            CallFailure { origin, error }
        })
    }
}

impl PreviewRequests for Client {
    fn call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        Client::call(self, method, params)
    }

    fn call_staged(&self, method: &str, params: Value) -> Result<Value, CallFailure> {
        Client::call_staged(self, method, params)
    }
}

/// The complete, explicitly allowlisted shape of a `capability/approve` request.
///
/// Callers hand the shared workflow a JSON payload because the shipped CLI and TUI
/// already build one, but that payload is parsed into this struct before any request
/// is sent. Only the proposal id, the CLI's optional target and TTL survive; everything
/// else is refused locally. The daemon still re-derives every authority-bearing field
/// from durable state — this type is a client-side contract, not a second policy engine.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovalRequest {
    proposal: String,
    target: Option<String>,
    ttl_ms: Option<i64>,
}

impl ApprovalRequest {
    fn from_payload(proposal_id: &str, payload: &Value) -> Result<Self, ClientError> {
        let object = payload
            .as_object()
            .ok_or_else(|| ClientError::InvalidParams {
                detail: "an approval payload must be a JSON object".to_owned(),
            })?;
        for key in object.keys() {
            if !matches!(key.as_str(), "proposal" | "target" | "ttl_ms") {
                return Err(ClientError::InvalidParams {
                    detail: format!("an approval cannot carry caller-supplied `{key}`"),
                });
            }
        }
        let proposal = object
            .get("proposal")
            .and_then(Value::as_str)
            .ok_or_else(|| ClientError::InvalidParams {
                detail: "an approval must name exactly one proposal".to_owned(),
            })?;
        if proposal != proposal_id {
            return Err(ClientError::InvalidParams {
                detail: "the approval payload and the requested proposal disagree".to_owned(),
            });
        }
        let target = match object.get("target") {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => {
                return Err(ClientError::InvalidParams {
                    detail: "`target` must be a string".to_owned(),
                });
            }
        };
        let ttl_ms = match object.get("ttl_ms") {
            None => None,
            Some(v) => Some(v.as_i64().ok_or_else(|| ClientError::InvalidParams {
                detail: "`ttl_ms` must be an integer".to_owned(),
            })?),
        };
        Ok(Self {
            proposal: proposal.to_owned(),
            target,
            ttl_ms,
        })
    }

    fn into_value(self) -> Value {
        let mut payload = json!({ "proposal": self.proposal });
        if let Some(target) = self.target {
            payload["target"] = json!(target);
        }
        if let Some(ttl) = self.ttl_ms {
            payload["ttl_ms"] = json!(ttl);
        }
        payload
    }
}

/// A review that a human must decide on before an approval may be submitted.
///
/// The challenge is held privately and deliberately excluded from [`Review::preview`]:
/// a renderer can show every fact of the fresh preview without ever displaying or
/// logging the secret it carries. Only [`submit_review`] can use it.
pub struct Review {
    proposal_id: String,
    classification: ProposalKind,
    preview: Value,
    challenge: String,
    request: ApprovalRequest,
}

impl Review {
    /// The proposal this review is about. An action must name this id and no other.
    #[must_use]
    pub fn proposal_id(&self) -> &str {
        &self.proposal_id
    }

    /// The daemon's classification of the proposal.
    #[must_use]
    pub fn classification(&self) -> ProposalKind {
        self.classification
    }

    /// The fresh preview, with the challenge removed.
    ///
    /// This is the preview the operator actually authorises. It is not the earlier
    /// inspection: the two can differ, and the fresh one is authoritative.
    #[must_use]
    pub fn preview(&self) -> &Value {
        &self.preview
    }
}

impl std::fmt::Debug for Review {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Review")
            .field("proposal_id", &self.proposal_id)
            .field("classification", &self.classification)
            .field("preview", &self.preview)
            .field("challenge", &"<redacted>")
            .finish()
    }
}

/// The result of beginning an approval.
#[derive(Debug)]
pub enum ApprovalStart {
    /// No reviewed confirmation was needed; the approval was submitted already.
    Submitted {
        /// The daemon's reply to `capability/approve`.
        reply: Value,
    },
    /// A model-initiated file read needs an explicit human decision.
    NeedsReview(Review),
}

/// Verifies that a preview reply describes the proposal the caller asked for.
///
/// The check is shared with the TUI so a preview adopted for display cannot be
/// labelled with a different proposal id than the one the daemon returned.
pub fn check_preview_id(preview: &Value, requested: &str) -> Result<(), ClientError> {
    match preview
        .get("preview")
        .and_then(|p| p.get("proposal_id"))
        .and_then(Value::as_str)
    {
        Some(id) if id == requested => Ok(()),
        Some(id) => Err(ClientError::Malformed(format!(
            "the preview described proposal {id:?}, not the requested {requested:?}"
        ))),
        None => Err(ClientError::Malformed(
            "the preview carried no proposal_id".to_owned(),
        )),
    }
}

#[cfg(test)]
const FORGED_PAYLOAD_KEYS: [&str; 8] = [
    "recipient",
    "fingerprint",
    "path",
    "capability",
    "endpoint",
    "model",
    "challenge",
    "confirmed",
];

/// Begins the approval of one proposal.
///
/// The inspection comes first because it carries no challenge: a client that turns out
/// not to need a review has not left one behind in the daemon's bounded store. For a
/// model-initiated file read, an answer is required *before* the challenge-bearing
/// preview is requested, for the same reason.
///
/// # Errors
///
/// A failed request, a malformed or inconsistent reply, a caller-supplied
/// authority-bearing field, or a non-interactive caller facing a disclosure. No
/// approval is submitted on any of those paths.
pub fn begin_approval_staged(
    requests: &impl PreviewRequests,
    interactive: bool,
    proposal_id: &str,
    payload: Value,
) -> Result<ApprovalStart, ApprovalFailure> {
    let request = ApprovalRequest::from_payload(proposal_id, &payload)
        .map_err(|e| from_local(ApprovalStage::Payload, e))?;

    let inspected = requests
        .call_staged(
            "capability/preview",
            json!({ "proposal": proposal_id, "inspect_only": true }),
        )
        .map_err(|f| from_call(ApprovalStage::InspectPreview, f))?;
    check_preview_id(&inspected, proposal_id)
        .map_err(|e| from_local(ApprovalStage::InspectPreview, e))?;
    let kind = classify_proposal(&inspected).map_err(|why| {
        from_local(
            ApprovalStage::InspectPreview,
            ClientError::InvalidParams { detail: why },
        )
    })?;
    if kind != ProposalKind::ModelInitiatedFileRead {
        let reply = requests
            .call_staged("capability/approve", request.into_value())
            .map_err(|f| from_call(ApprovalStage::ApprovalSubmission, f))?;
        return Ok(ApprovalStart::Submitted { reply });
    }

    if !interactive {
        return Err(from_local(
            ApprovalStage::ChallengePreview,
            ClientError::InvalidParams {
                detail: "approving a model-generated file read needs an interactive \
                          confirmation: the read's contents may be disclosed to the \
                          model provider, and that has to be accepted by a person."
                    .to_owned(),
            },
        ));
    }

    let fresh = requests
        .call_staged("capability/preview", json!({ "proposal": proposal_id }))
        .map_err(|f| from_call(ApprovalStage::ChallengePreview, f))?;
    check_preview_id(&fresh, proposal_id)
        .map_err(|e| from_local(ApprovalStage::ChallengePreview, e))?;
    let fresh_kind = classify_proposal(&fresh).map_err(|why| {
        from_local(
            ApprovalStage::ChallengePreview,
            ClientError::InvalidParams { detail: why },
        )
    })?;
    if fresh_kind != ProposalKind::ModelInitiatedFileRead {
        return Err(from_local(
            ApprovalStage::ChallengePreview,
            ClientError::InvalidParams {
                detail: "the proposal changed between the inspection and the review; \
                          nothing was approved."
                    .to_owned(),
            },
        ));
    }
    if fresh["preview"]
        .get("approval_allowed")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(from_local(
            ApprovalStage::ChallengePreview,
            ClientError::InvalidParams {
                detail: fresh["preview"]
                    .get("blocked_reason")
                    .and_then(Value::as_str)
                    .unwrap_or("this read cannot currently be approved")
                    .to_owned(),
            },
        ));
    }
    let challenge = fresh["preview"]
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            from_local(
                ApprovalStage::ChallengePreview,
                ClientError::Malformed(
                    "the preview carried no challenge, so the read cannot be reviewed".to_owned(),
                ),
            )
        })?
        .to_owned();

    let mut preview = fresh;
    if let Some(fields) = preview.get_mut("preview").and_then(Value::as_object_mut) {
        fields.remove("challenge");
    }

    Ok(ApprovalStart::NeedsReview(Review {
        proposal_id: proposal_id.to_owned(),
        classification: kind,
        preview,
        challenge,
        request,
    }))
}

/// Compatibility wrapper returning the original [`ClientError`] to existing callers.
pub fn begin_approval(
    requests: &impl PreviewRequests,
    interactive: bool,
    proposal_id: &str,
    payload: Value,
) -> Result<ApprovalStart, ClientError> {
    begin_approval_staged(requests, interactive, proposal_id, payload)
        .map_err(|failure| failure.error)
}

/// Finishes a reviewed approval, or declines it without sending anything.
///
/// `confirmed: false` means the person said no, cancelled, or the review was abandoned.
/// No approval request is sent in that case; the challenge the daemon issued simply
/// expires on its own.
///
/// # Errors
///
/// The request failing. A decline is not an error.
pub fn submit_review_staged(
    requests: &impl PreviewRequests,
    review: Review,
    confirmed: bool,
) -> Result<Option<Value>, ApprovalFailure> {
    if !confirmed {
        return Ok(None);
    }
    let mut payload = review.request.into_value();
    payload["challenge"] = json!(review.challenge);
    payload["confirmed"] = json!(true);
    let reply = requests
        .call_staged("capability/approve", payload)
        .map_err(|f| from_call(ApprovalStage::ApprovalSubmission, f))?;
    Ok(Some(reply))
}

/// Compatibility wrapper returning the original [`ClientError`] to existing callers.
pub fn submit_review(
    requests: &impl PreviewRequests,
    review: Review,
    confirmed: bool,
) -> Result<Option<Value>, ClientError> {
    submit_review_staged(requests, review, confirmed).map_err(|failure| failure.error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Recorder {
        calls: Mutex<Vec<(String, Value)>>,
        replies: Mutex<Vec<Result<Value, ClientError>>>,
    }

    impl Recorder {
        fn new(replies: Vec<Result<Value, ClientError>>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                replies: Mutex::new(replies),
            }
        }
        fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().expect("recorder lock").clone()
        }
        fn methods(&self) -> Vec<String> {
            self.calls().into_iter().map(|(m, _)| m).collect()
        }
    }

    impl PreviewRequests for Recorder {
        fn call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
            self.calls
                .lock()
                .expect("recorder lock")
                .push((method.to_owned(), params));
            let mut replies = self.replies.lock().expect("recorder lock");
            if replies.is_empty() {
                return Err(ClientError::Malformed("no reply was configured".to_owned()));
            }
            replies.remove(0)
        }
    }

    fn inspection(kind: &str, requires: bool, operation: &str) -> Value {
        json!({
            "preview": {
                "proposal_id": "p-1",
                "capability": "filesystem/read-text",
                "path": "src/main.rs",
                "operation": operation,
                "proposal_kind": kind,
                "requires_confirmation": requires,
                "approval_allowed": true,
                "recipient": "https://api.example.invalid/v1 (model: some-model)",
                "recipient_status": "identified",
                "read_ceiling_bytes": 65536,
                "observation_ceiling_bytes": 32768,
                "max_entries": 8,
                "effective_bytes": 32768,
                "disclosure": {
                    "limits": "an observation that does not fit is skipped entirely, not truncated",
                    "timing": "eligibility is limited to the immediately following logical step",
                },
            }
        })
    }

    fn fresh_preview(challenge: &str) -> Value {
        let mut v = inspection("model-initiated-file-read", true, "file-read");
        v["preview"]["challenge"] = json!(challenge);
        v
    }

    fn ok_approval() -> Result<Value, ClientError> {
        Ok(json!({ "approval": { "digest": "abc" } }))
    }

    fn review_of(recorder: &Recorder, payload: Value) -> Review {
        match begin_approval(recorder, true, "p-1", payload).expect("a review is required") {
            ApprovalStart::NeedsReview(review) => review,
            ApprovalStart::Submitted { .. } => panic!("a model read must need a review"),
        }
    }

    #[test]
    fn the_classification_is_read_from_the_server() {
        assert_eq!(
            classify_proposal(&inspection("model-initiated-file-read", true, "file-read"))
                .expect("classified"),
            ProposalKind::ModelInitiatedFileRead
        );
        assert_eq!(
            classify_proposal(&inspection("direct-proposal", false, "file-read"))
                .expect("classified"),
            ProposalKind::DirectProposal
        );
        assert_eq!(
            classify_proposal(&inspection("model-initiated", false, "other")).expect("classified"),
            ProposalKind::ModelInitiated
        );
    }

    #[test]
    fn an_unknown_or_inconsistent_classification_fails_closed() {
        assert!(classify_proposal(&inspection("something-else", true, "file-read")).is_err());
        assert!(
            classify_proposal(&inspection("model-initiated-file-read", false, "file-read"))
                .is_err()
        );
        assert!(
            classify_proposal(&inspection("model-initiated-file-read", true, "file-write"))
                .is_err()
        );
        assert!(classify_proposal(&inspection("model-initiated", true, "other")).is_err());
        assert!(classify_proposal(&inspection("direct-proposal", true, "file-read")).is_err());
        assert!(classify_proposal(&json!({})).is_err());
    }

    #[test]
    fn the_model_read_sequence_is_inspection_then_fresh_preview_then_confirmation_then_approval() {
        let recorder = Recorder::new(vec![
            Ok(inspection("model-initiated-file-read", true, "file-read")),
            Ok(fresh_preview("challenge-fresh")),
            ok_approval(),
        ]);
        let payload = json!({ "proposal": "p-1", "ttl_ms": 60_000 });
        let review = review_of(&recorder, payload);
        assert_eq!(
            recorder.methods(),
            vec!["capability/preview", "capability/preview"],
            "the first two calls are the inspection and the fresh preview"
        );
        assert_eq!(
            recorder.calls()[0].1["inspect_only"],
            json!(true),
            "the first preview must be an inspection"
        );
        assert!(recorder.calls()[0].1.get("challenge").is_none());
        assert!(
            recorder.calls()[1].1.get("inspect_only").is_none(),
            "the second preview must be the challenge-bearing one"
        );

        let reply = submit_review(&recorder, review, true)
            .expect("approved")
            .expect("the approval must have been submitted");
        assert!(reply.get("approval").is_some());
        assert_eq!(
            recorder.methods(),
            vec![
                "capability/preview",
                "capability/preview",
                "capability/approve"
            ]
        );
        let approve = &recorder.calls()[2].1;
        assert_eq!(
            *approve,
            json!({
                "proposal": "p-1",
                "ttl_ms": 60_000,
                "challenge": "challenge-fresh",
                "confirmed": true
            }),
            "the serialized approval payload must be exactly the allowlisted shape"
        );
    }

    #[test]
    fn the_review_shows_the_fresh_preview_and_never_the_challenge() {
        let mut fresh = fresh_preview("CHALLENGE-MUST-NOT-BE-RENDERED");
        fresh["preview"]["path"] = json!("src/fresh.rs");
        let recorder = Recorder::new(vec![
            Ok(inspection("model-initiated-file-read", true, "file-read")),
            Ok(fresh),
        ]);
        let review = review_of(&recorder, json!({ "proposal": "p-1" }));
        assert_eq!(review.proposal_id(), "p-1");
        assert_eq!(
            review.classification(),
            ProposalKind::ModelInitiatedFileRead
        );
        assert_eq!(
            review.preview()["preview"]["path"],
            json!("src/fresh.rs"),
            "the review must describe the fresh preview, not the inspection"
        );
        assert!(
            !serde_json::to_string(review.preview())
                .expect("json")
                .contains("CHALLENGE-MUST-NOT-BE-RENDERED"),
            "the challenge must not be reachable through the review surface"
        );
    }

    #[test]
    fn a_decline_submits_no_approval() {
        let recorder = Recorder::new(vec![
            Ok(inspection("model-initiated-file-read", true, "file-read")),
            Ok(fresh_preview("challenge-fresh")),
        ]);
        let review = review_of(&recorder, json!({ "proposal": "p-1" }));
        assert!(
            submit_review(&recorder, review, false)
                .expect("a decline is not an error")
                .is_none()
        );
        assert_eq!(
            recorder.methods(),
            vec!["capability/preview", "capability/preview"],
            "a decline must send no approval request"
        );
    }

    #[test]
    fn a_non_interactive_caller_takes_no_challenge_and_submits_nothing() {
        let recorder = Recorder::new(vec![Ok(inspection(
            "model-initiated-file-read",
            true,
            "file-read",
        ))]);
        let err = begin_approval(&recorder, false, "p-1", json!({ "proposal": "p-1" }))
            .expect_err("a non-interactive caller must fail closed");
        assert!(format!("{err:?}").contains("interactive"), "{err:?}");
        assert_eq!(
            recorder.methods(),
            vec!["capability/preview"],
            "only the inspection may have happened"
        );
    }

    #[test]
    fn a_direct_proposal_keeps_its_established_approval_route() {
        let recorder = Recorder::new(vec![
            Ok(inspection("direct-proposal", false, "file-read")),
            ok_approval(),
        ]);
        match begin_approval(
            &recorder,
            true,
            "p-1",
            json!({ "proposal": "p-1", "ttl_ms": 60_000 }),
        )
        .expect("no error")
        {
            ApprovalStart::Submitted { reply } => assert!(reply.get("approval").is_some()),
            ApprovalStart::NeedsReview(_) => panic!("a direct proposal needs no review"),
        }
        assert_eq!(
            recorder.methods(),
            vec!["capability/preview", "capability/approve"]
        );
        assert_eq!(recorder.calls()[0].1["inspect_only"], json!(true));
        let approve = &recorder.calls()[1].1;
        assert_eq!(approve["ttl_ms"], json!(60_000));
        assert!(approve.get("challenge").is_none());
        assert!(approve.get("confirmed").is_none());
    }

    #[test]
    fn an_unrelated_model_capability_keeps_its_established_approval_route() {
        let recorder = Recorder::new(vec![
            Ok(inspection("model-initiated", false, "other")),
            ok_approval(),
        ]);
        assert!(matches!(
            begin_approval(&recorder, true, "p-1", json!({ "proposal": "p-1" })).expect("no error"),
            ApprovalStart::Submitted { .. }
        ));
        assert_eq!(
            recorder.methods(),
            vec!["capability/preview", "capability/approve"]
        );
        assert!(recorder.calls()[1].1.get("challenge").is_none());
        assert!(recorder.calls()[1].1.get("confirmed").is_none());
    }

    #[test]
    fn a_failed_inspection_submits_no_approval() {
        let mut blocked = inspection("model-initiated-file-read", true, "file-read");
        blocked["preview"]["approval_allowed"] = json!(false);
        blocked["preview"]["blocked_reason"] = json!("the recipient cannot be identified");
        for reply in [
            Ok(blocked),
            Err(ClientError::Malformed("the daemon fell over".to_owned())),
            Ok(json!({ "nonsense": true })),
        ] {
            let recorder = Recorder::new(vec![reply]);
            assert!(
                begin_approval(&recorder, true, "p-1", json!({ "proposal": "p-1" })).is_err(),
                "a failed inspection must fail closed"
            );
            assert!(!recorder.methods().iter().any(|m| m == "capability/approve"));
        }
    }

    #[test]
    fn a_blocked_or_inconsistent_preview_submits_no_approval() {
        let mut blocked = fresh_preview("challenge-fresh");
        blocked["preview"]["approval_allowed"] = json!(false);
        blocked["preview"]["blocked_reason"] = json!("the recipient cannot be identified");

        let mut no_challenge = inspection("model-initiated-file-read", true, "file-read");
        no_challenge["preview"]["approval_allowed"] = json!(true);

        let mut wrong_kind = fresh_preview("challenge-fresh");
        wrong_kind["preview"]["proposal_kind"] = json!("model-initiated");

        for preview in [blocked, no_challenge, wrong_kind] {
            let recorder = Recorder::new(vec![
                Ok(inspection("model-initiated-file-read", true, "file-read")),
                Ok(preview),
            ]);
            assert!(
                begin_approval(&recorder, true, "p-1", json!({ "proposal": "p-1" })).is_err(),
                "a blocked preview must fail closed"
            );
            assert_eq!(
                recorder.methods(),
                vec!["capability/preview", "capability/preview"]
            );
        }
    }

    #[test]
    fn a_preview_for_another_proposal_is_refused_before_a_review_or_approval() {
        let mut wrong_inspection = inspection("model-initiated-file-read", true, "file-read");
        wrong_inspection["preview"]["proposal_id"] = json!("p-other");
        let recorder = Recorder::new(vec![Ok(wrong_inspection)]);
        assert!(begin_approval(&recorder, true, "p-1", json!({ "proposal": "p-1" })).is_err());
        assert!(!recorder.methods().iter().any(|m| m == "capability/approve"));

        let mut wrong_fresh = fresh_preview("challenge-fresh");
        wrong_fresh["preview"]["proposal_id"] = json!("p-other");
        let recorder = Recorder::new(vec![
            Ok(inspection("model-initiated-file-read", true, "file-read")),
            Ok(wrong_fresh),
        ]);
        assert!(begin_approval(&recorder, true, "p-1", json!({ "proposal": "p-1" })).is_err());
        assert!(!recorder.methods().iter().any(|m| m == "capability/approve"));
    }

    #[test]
    fn caller_supplied_authority_fields_are_refused_before_any_request() {
        for key in FORGED_PAYLOAD_KEYS {
            let recorder = Recorder::new(vec![]);
            let mut payload = json!({ "proposal": "p-1" });
            payload[key] = json!("forged");
            assert!(
                begin_approval(&recorder, true, "p-1", payload).is_err(),
                "{key} must not be caller-supplied"
            );
            assert!(recorder.methods().is_empty(), "no request may be sent");
        }
    }

    #[test]
    fn safe_text_escapes_control_bidi_and_invisible_canaries() {
        let input = "a\u{1b}[31mb\u{202e}c\u{200b}d\u{2066}e\u{2069}f\u{feff}g\n".to_owned();
        let out = safe_text(&input);
        for escaped in [
            "\\u{1b}",
            "\\u{202e}",
            "\\u{200b}",
            "\\u{2066}",
            "\\u{2069}",
            "\\u{feff}",
            "\\u{a}",
        ] {
            assert!(out.contains(escaped), "missing {escaped:?} in {out:?}");
        }
        for raw in ['\u{1b}', '\u{202e}', '\u{200b}', '\u{feff}'] {
            assert!(!out.contains(raw), "raw invisible character in {out:?}");
        }
        assert!(out.contains('a') && out.contains('g'), "{out}");
    }

    #[test]
    fn safe_text_preserves_ordinary_readable_unicode() {
        let input = "café — 東京 — hello world";
        assert_eq!(
            safe_text(input),
            input,
            "legible text must survive unchanged"
        );
    }

    #[test]
    fn exceeds_display_limit_tracks_the_sanitizer_bound() {
        assert!(!exceeds_display_limit(&"R".repeat(160)));
        assert!(exceeds_display_limit(&"R".repeat(161)));
        assert!(
            exceeds_display_limit(&"\u{202e}".repeat(30)),
            "escapes consume the bound"
        );
    }

    #[test]
    fn safe_text_bounds_output_and_keeps_suffix_with_visible_marker() {
        let input = format!("{}{}", "A".repeat(400), "END-MARKER");
        let out = safe_text(&input);
        assert!(out.chars().count() <= DISPLAY_LIMIT, "{out}");
        assert!(out.contains("chars omitted"), "{out}");
        assert!(
            out.ends_with("END-MARKER"),
            "the suffix must remain visible: {out}"
        );
        assert!(out.starts_with('A'));

        let invisibles = "\u{202e}".repeat(100);
        let escaped = safe_text(&invisibles);
        assert!(escaped.chars().count() <= DISPLAY_LIMIT, "{escaped}");
        assert!(escaped.contains("\\u{202e}"), "{escaped}");
    }

    #[test]
    fn direct_approval_payload_is_exactly_allowlisted_with_target_and_ttl() {
        let recorder = Recorder::new(vec![
            Ok(inspection("direct-proposal", false, "file-read")),
            ok_approval(),
        ]);
        let payload = json!({ "proposal": "p-1", "target": "notes.txt", "ttl_ms": 1200 });
        assert!(matches!(
            begin_approval(&recorder, true, "p-1", payload).expect("approval"),
            ApprovalStart::Submitted { .. }
        ));
        assert_eq!(
            recorder.calls()[1].1,
            json!({ "proposal": "p-1", "target": "notes.txt", "ttl_ms": 1200 })
        );
    }

    #[test]
    fn model_read_payload_has_no_optional_fields_when_absent() {
        let recorder = Recorder::new(vec![
            Ok(inspection("model-initiated-file-read", true, "file-read")),
            Ok(fresh_preview("challenge-fresh")),
            ok_approval(),
        ]);
        let review = review_of(&recorder, json!({ "proposal": "p-1" }));
        submit_review(&recorder, review, true).expect("approval");
        assert_eq!(
            recorder.calls()[2].1,
            json!({
                "proposal": "p-1",
                "challenge": "challenge-fresh",
                "confirmed": true
            })
        );
    }

    #[test]
    fn malformed_or_mismatched_approval_input_is_rejected_before_any_rpc() {
        for payload in [
            json!({ "proposal": "p-other" }),
            json!({ "proposal": "p-1", "risk": "low" }),
            json!({ "proposal": "p-1", "ttl_ms": "1200" }),
            json!({ "proposal": "p-1", "target": 7 }),
            json!("not-an-object"),
        ] {
            let recorder = Recorder::new(vec![]);
            assert!(
                begin_approval(&recorder, true, "p-1", payload.clone()).is_err(),
                "{payload} must be refused"
            );
            assert!(
                recorder.methods().is_empty(),
                "no RPC may be sent for {payload}"
            );
        }
    }

    #[test]
    fn staged_inspect_failure_reports_stage_and_origin() {
        let recorder = Recorder::new(vec![Err(ClientError::Malformed("bad frame".to_owned()))]);
        let failure = begin_approval_staged(&recorder, true, "p-1", json!({ "proposal": "p-1" }))
            .expect_err("a failed preview is an error");
        assert_eq!(failure.stage, ApprovalStage::InspectPreview);
        assert_eq!(failure.origin, ApprovalFailureOrigin::ResponseDecoding);
    }

    #[test]
    fn staged_submission_failure_reports_refusal_origin() {
        let recorder = Recorder::new(vec![
            Ok(inspection("direct-proposal", false, "file-write")),
            Err(ClientError::Refused {
                code: -32042,
                message: "refused".to_owned(),
                reason: Some("approval-required".to_owned()),
                detail: None,
            }),
        ]);
        let failure = begin_approval_staged(&recorder, true, "p-1", json!({ "proposal": "p-1" }))
            .expect_err("a refused approval is an error");
        assert_eq!(failure.stage, ApprovalStage::ApprovalSubmission);
        assert_eq!(failure.origin, ApprovalFailureOrigin::Refusal);
    }

    #[test]
    fn begin_approval_wrapper_preserves_the_original_error() {
        let recorder = Recorder::new(vec![Err(ClientError::Transport("peer lost".to_owned()))]);
        let staged = begin_approval_staged(&recorder, true, "p-1", json!({ "proposal": "p-1" }))
            .expect_err("a transport failure is an error");
        assert_eq!(staged.origin, ApprovalFailureOrigin::Transport);
        let recorder = Recorder::new(vec![Err(ClientError::Transport("peer lost".to_owned()))]);
        let plain = begin_approval(&recorder, true, "p-1", json!({ "proposal": "p-1" }))
            .expect_err("a transport failure is an error");
        assert_eq!(plain, staged.error);
    }
}
