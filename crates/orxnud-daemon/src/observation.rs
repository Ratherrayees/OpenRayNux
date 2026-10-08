//! Stage 4c: handing an approved, verified observation to the next proposal.
//!
//! # The gap this closes
//!
//! `filesystem/read-text` is a correct governed observation capability: high risk, approved,
//! sandboxed, independently verified, durable result carrying metadata only. But its bytes
//! are dropped at the end of the request that read them, so the model can *propose* a read and
//! then has nowhere to receive what it read. `PriorStepContext` cannot fix that, and must not:
//! it is durable metadata and stays that way.
//!
//! So there are two channels, deliberately not conflated:
//!
//! ```text
//! PriorStepContext        durable metadata, never content
//! EphemeralObservation    approved read output, memory only, one proposal
//! ```
//!
//! # What authorises this
//!
//! A human approving `filesystem/read-text` authorises the resulting bytes to be sent to the
//! provider identity that asked for the read -- and to that identity only. This is the first
//! time one approval is read as covering two acts: a local read, and a disclosure to a
//! third-party endpoint. ADR-0045 states that explicitly so it is a decision rather than an
//! implementation convention.
//!
//! The binding is `(endpoint, model)`, not the model string. Re-pointing the endpoint while
//! keeping the same model name would otherwise send approved content to a new destination
//! under a rule written to prevent exactly that.
//!
//! # What is deliberately absent
//!
//! Nothing here is durable. Observations live in daemon process memory, are consumed by one
//! proposal, and expire on a TTL. A restart destroys them, and the model re-proposes the read.
//! That is fail-safe: the alternative — retaining workspace content across restarts — is the
//! thing this whole design exists to avoid.

use orxnud_audit::{AuditOutcome, AuditRecord, OutcomeKind};
use orxnud_domain::Actor;
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{RequestId, TaskId};

/// Longest a retained observation may wait for a proposal before it is discarded.
///
/// A backstop, not the mechanism: consumption normally happens first.
pub const DEFAULT_TTL_MS: i64 = 15 * 60 * 1_000;

/// How many observations one task may hold at once.
///
/// Retention is newest-per-path, so this bounds distinct paths rather than read count.
pub const DEFAULT_MAX_ENTRIES: usize = 8;

/// Default ceiling on observation bytes released into one provider request.
pub const DEFAULT_MAX_CONTENT_BYTES: usize = 32 * 1024;

/// Who an observation may be shown to.
///
/// Both parts matter. Comparing the model string alone would let a re-pointed endpoint
/// inherit an approval given to the old one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderIdentity {
    endpoint: String,
    model: String,
}

impl ProviderIdentity {
    /// Derives an identity from a provider's own configuration.
    ///
    /// Canonicalised on construction so two spellings of one endpoint compare equal: a
    /// trailing slash, a default port, and case in the scheme and host are all normalised.
    /// Identity that compared raw strings would refuse legitimate reuse for cosmetic reasons
    /// and — worse — could be made to differ deliberately.
    #[must_use]
    pub fn new(endpoint: impl AsRef<str>, model: impl Into<String>) -> Self {
        Self {
            endpoint: canonical_endpoint(endpoint.as_ref()),
            model: model.into(),
        }
    }

    /// The canonical endpoint. Exposed for audit records, which must agree with the check.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The model id.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Whether content may be released to this provider.
    ///
    /// Exact on both fields. Not "same model name", and not "same host": a different model on
    /// the same endpoint is a different destination for a different computation, and the same
    /// model name on a different endpoint is a different operator entirely.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint && self.model == other.model
    }
}

/// Reduces an endpoint to a comparable form.
///
/// Deliberately conservative: it normalises only what cannot change which operator is being
/// addressed. It does **not** resolve DNS or follow redirects, because a name that resolves
/// differently later is a trust decision this layer has no business making.
fn canonical_endpoint(raw: &str) -> String {
    let trimmed = raw.trim();
    let (scheme, rest) = trimmed.split_once("://").unwrap_or(("https", trimmed));
    let scheme = scheme.to_ascii_lowercase();

    // Host and optional port, then the path. A default port for the scheme is dropped so
    // `https://h/v1` and `https://h:443/v1` are one destination.
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let (host, port) = authority
        .rsplit_once(':')
        .filter(|(h, p)| !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    let host = host.to_ascii_lowercase();
    let default_port = matches!(
        (scheme.as_str(), port),
        ("https", Some("443")) | ("http", Some("80"))
    );
    let authority = match port {
        Some(p) if !default_port => format!("{host}:{p}"),
        _ => host,
    };

    // Trailing slashes are noise on a base URL; interior ones are not.
    let path = path.trim_end_matches('/');
    if path.is_empty() {
        format!("{scheme}://{authority}")
    } else {
        format!("{scheme}://{authority}{path}")
    }
}

/// One approved, verified observation awaiting a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The task whose approved read produced it. Observations never cross tasks.
    pub task_id: TaskId,
    /// The logical step whose approved, verified read produced it.
    ///
    /// This is what makes the disclosure bound to *one* boundary rather than to "the rest of
    /// the task". A read approved at step 1 may inform the proposal for step 2, and nothing
    /// else: without this field a retained observation could inform any later proposal, so an
    /// approval given for "the next thing" would quietly become an approval for every later
    /// thing, including ones made after other steps had run. The rule is `step_no + 1`, not
    /// `step_no`, because the read and the proposal it informs are different acts on
    /// different steps — which is also why it is exactly one boundary and not a range.
    pub step_no: u32,
    /// The workspace-relative path that was read.
    pub path: String,
    /// The provider identity allowed to receive it.
    pub provider: ProviderIdentity,
    /// The bytes. Never durable.
    pub bytes: Vec<u8>,
    /// When the read was verified.
    pub recorded_at_ms: i64,
    /// What the disclosure record will cite about the read that produced these bytes.
    pub origin: ObservationOrigin,
}

/// The approved read an observation came from, kept so the disclosure can cite it.
///
/// # Why this is a citation and not a second copy of the authority
///
/// The approval row stays authoritative: it is what permitted the read, and nothing here
/// can change that. These three values exist because the disclosure happens *later*, on a
/// different request, when the read's proposal and approval may be spent and unreadable —
/// and an audit record is a statement about the past, so it must be able to name the human
/// who approved the read and the correlation it rode, not re-derive them from rows that have
/// since moved on.
///
/// Nothing here is a capability, a target or a parameter. The observation cannot be widened
/// by editing this struct, because there is nothing in it that authorises anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationOrigin {
    /// The correlation the read's own audit records rode, so the disclosure can cite its
    /// parent without closing or being closed by it.
    pub parent_read_request: RequestId,
    /// The proposal that was approved and executed to produce these bytes.
    pub parent_proposal_id: String,
    /// The human who approved that read.
    ///
    /// The disclosure rests on this authority and on nothing else (ADR-0045): one approval
    /// covered the local read *and* the sending of its result to one provider identity.
    pub approver: Actor,
}

/// The disclosed reads attached to one proposal request.
///
/// A newtype with a private field rather than a `serde_json::Value`, a map, or a bare `Vec`.
///
/// The reason is not taste. This is the only structure in the system that carries workspace
/// content toward a third party, so "what else could go in here" is the security question, and
/// the answer should not be reachable by constructing a different value. There is exactly one
/// way to build one — from what the store released — and it takes no extra arguments, so a
/// caller cannot add content the store did not hand over, rename it, or attach an
/// ungoverned blob. Everything a prompt may show about it comes from the store's own
/// filtering.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DisclosureBatch {
    released: Vec<ReleasedObservation>,
}

impl DisclosureBatch {
    /// No content. The value for any request with no eligible observation.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            released: Vec::new(),
        }
    }

    /// Wraps what [`ObservationStore::take_for`] released.
    #[must_use]
    pub fn from_released(released: Vec<ReleasedObservation>) -> Self {
        Self { released }
    }

    /// Whether this request carries any content.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.released.is_empty()
    }

    /// How many observations are attached.
    #[must_use]
    pub fn len(&self) -> usize {
        self.released.len()
    }

    /// The attached observations, in release order (newest read first).
    pub fn iter(&self) -> impl Iterator<Item = &ReleasedObservation> {
        self.released.iter()
    }

    /// Total bytes attached. Bounded by the store's own ceiling, which is the smaller of the
    /// caller's budget and `max_content_bytes`.
    #[must_use]
    pub fn total_bytes(&self) -> usize {
        self.released.iter().map(|r| r.byte_count).sum()
    }

    /// What was disclosed, as paths and byte counts.
    ///
    /// For the request reply and the operator's benefit. Content-free by construction: there
    /// is no field here that could hold bytes, so an operator can see that content left and
    /// how much without a second disclosure channel existing.
    #[must_use]
    pub fn summary(&self) -> Vec<DisclosureSummary> {
        self.released
            .iter()
            .map(|r| DisclosureSummary {
                path: r.path.clone(),
                byte_count: r.byte_count,
            })
            .collect()
    }
}

/// One disclosed read, named but not quoted.
///
/// A distinct type from [`ReleasedObservation`] so that the reply value cannot accidentally
/// gain a `bytes` field — it is constructed here from two fields and has nowhere else to
/// look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureSummary {
    /// The workspace-relative path that was read.
    pub path: String,
    /// How many bytes were disclosed.
    pub byte_count: usize,
}

/// An observation handed to a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleasedObservation {
    /// The workspace-relative path.
    pub path: String,
    /// Where it is going, for the disclosure audit record.
    pub provider: ProviderIdentity,
    /// How many bytes are going. Recorded, never the bytes themselves.
    pub byte_count: usize,
    /// The content.
    pub bytes: Vec<u8>,
    /// What the disclosure audit record cites about the read this came from.
    ///
    /// Carried out with the bytes so the audit record is built from what was actually
    /// released, rather than from a second lookup that could disagree with it.
    pub origin: ObservationOrigin,
}

/// In-memory retention of approved observations, for one daemon process.
///
/// # Why a `Vec` and not a map
///
/// Release order has to be deterministic and newest-first, and eviction has to be
/// deterministic too. A hash map would make both depend on iteration order, which is exactly
/// the kind of hidden nondeterminism that turns into "it worked on my machine". A vector
/// scanned in reverse insertion order gives both for free; the lookup cost is irrelevant at
/// `DEFAULT_MAX_ENTRIES`.
#[derive(Debug, Clone)]
pub struct ObservationStore {
    ttl_ms: i64,
    max_entries: usize,
    max_content_bytes: usize,
    entries: Vec<Observation>,
}

impl ObservationStore {
    /// A store with the documented defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_TTL_MS,
            DEFAULT_MAX_ENTRIES,
            DEFAULT_MAX_CONTENT_BYTES,
        )
    }

    /// A store with explicit limits, for tests and for an operator who wants them tighter.
    #[must_use]
    pub fn with_limits(ttl_ms: i64, max_entries: usize, max_content_bytes: usize) -> Self {
        Self {
            ttl_ms,
            max_entries,
            max_content_bytes,
            entries: Vec::new(),
        }
    }

    /// Retains an observation, replacing any older one for the same `(task_id, path)`.
    ///
    /// Replacement rather than accumulation: re-reading a file should leave the newer bytes,
    /// and a stale version of the same path is never what a proposal wants.
    pub fn retain(&mut self, observation: Observation) {
        self.expire(observation.recorded_at_ms);
        self.entries
            .retain(|e| !(e.task_id == observation.task_id && e.path == observation.path));
        self.entries.push(observation);
        // Bounded by count, dropping the oldest first, so the store cannot grow without limit.
        while self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
    }

    /// Removes and returns the observations eligible for one proposal.
    ///
    /// Eligible means: not expired, same task, the **immediately following** logical step, and
    /// same provider identity. Ordered newest-first. Whole observations only -- a file is never
    /// truncated to fit, because a prefix presented as a whole file is the one outcome a model
    /// cannot detect.
    ///
    /// # Arguments
    ///
    /// * `task_id` — the task being proposed for. Observations from other tasks are never
    ///   visible, which is what stops one task's approved read reaching another's prompt.
    /// * `step_no` — the logical step of the proposal being requested. An observation is
    ///   eligible only when `observation.step_no + 1 == step_no`: the read happened on one
    ///   step and informs the next, and never a later one.
    /// * `provider` — the identity asking. Compared on `(endpoint, model)`.
    /// * `now_ms` — for expiry.
    /// * `budget` — a per-request ceiling from the caller.
    ///
    ///   The effective ceiling is the **smaller** of this and the store's own
    ///   `max_content_bytes`, so a caller cannot widen the store's limit by passing a large
    ///   number. The store's ceiling is the one that holds when nobody supplies one.
    pub fn take_for(
        &mut self,
        task_id: &TaskId,
        step_no: u32,
        provider: &ProviderIdentity,
        now_ms: i64,
        budget: usize,
    ) -> Vec<ReleasedObservation> {
        let budget = budget.min(self.max_content_bytes);
        self.expire(now_ms);

        // Newest first. Reverse insertion order is the total order, so equal timestamps still
        // resolve deterministically rather than by chance.
        let mut candidates: Vec<usize> = (0..self.entries.len()).rev().collect();
        candidates.retain(|&i| {
            let e = &self.entries[i];
            e.task_id == *task_id
                // Saturating so a step-0 observation (which no store should hold, and which
                // `retain` does not prevent a caller from constructing) is ineligible rather
                // than eligible-by-overflow.
                && e.step_no.saturating_add(1) == step_no
                && e.provider.matches(provider)
        });

        let mut released = Vec::new();
        let mut used = 0usize;
        let mut consumed: Vec<usize> = Vec::new();
        for i in candidates {
            let e = &self.entries[i];
            // Whole-observation only. An observation that does not fit is left retained
            // rather than partially released: it may fit a later request with a larger
            // budget, and it expires on the TTL regardless.
            if used.saturating_add(e.bytes.len()) > budget {
                continue;
            }
            used += e.bytes.len();
            released.push(ReleasedObservation {
                path: e.path.clone(),
                provider: e.provider.clone(),
                byte_count: e.bytes.len(),
                bytes: e.bytes.clone(),
                origin: e.origin.clone(),
            });
            consumed.push(i);
        }

        // Consume exactly what was released. An observation skipped for budget stays for a
        // later proposal; one that is released is gone, so it cannot inform a second prompt.
        //
        // `consumed` is already in **descending** index order — candidates were built by
        // walking the vector backwards — and removing from the highest index down keeps every
        // remaining index valid. Reversing here would remove the wrong entries once more than
        // one was consumed, which is exactly what the determinism test caught.
        for i in consumed {
            self.entries.remove(i);
        }
        released
    }

    /// Drops everything older than the TTL.
    pub fn expire(&mut self, now_ms: i64) {
        self.entries
            .retain(|e| now_ms.saturating_sub(e.recorded_at_ms) <= self.ttl_ms);
    }

    /// How many observations are currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ObservationStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Stage 4c: the disclosure audit record.
///
/// # Why this exists and why it is shaped this way
///
/// Disclosing approved workspace bytes to a remote provider is the highest-consequence event
/// in this slice. The existing audit records that a *read* happened, with metadata only; it
/// does not, and would not, record that the bytes then left the machine. Without this,
/// "the model saw the file" is invisible to anyone reviewing afterwards.
///
/// It reuses [`AuditOutcome::Finished`] rather than adding a `Disclosed` variant. `Finished`
/// is a terminal marker, and disclosure *is* terminal — the event is complete once the bytes
/// have been handed over. What makes that truthful rather than a stretch is that the
/// disclosure rides its **own correlation**, so it neither closes the read's nor is closed
/// by it.
///
/// # Why the disclosure correlation cannot be supplied
///
/// The correlation id is **private and minted inside** [`Self::from_verified_read`]. The
/// caller supplies the *parent read* correlation; it never supplies the disclosure's.
///
/// That is not fastidiousness. A disclosure sharing a read's correlation silently closes that
/// read's authorisation, and the read then disappears from
/// `unresolved_authorisations` — so a crash during the read would stop being visible. That
/// failure is quiet, it survives code review, and nothing about the call site looks wrong.
/// Leaving it to every future caller to remember is exactly the kind of invariant that gets
/// violated during a refactor.
///
/// So the property `disclosure_request != parent_read_request` holds **structurally**: the
/// caller has no way to make them equal. The test that demonstrates the hazard is
/// `a_disclosure_correlation_cannot_be_made_to_equal_its_parent`.
///
/// # What is never recorded
///
/// The bytes. Not a prefix, not a content digest, not an excerpt. The record answers *what
/// was disclosed, where, and how much* — never *what it said*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosureRecord {
    parent_read_request: RequestId,
    disclosure_request: RequestId,
    parent_proposal_id: String,
    task_id: TaskId,
    step_no: u32,
    path: String,
    provider: crate::observation::ProviderIdentity,
    byte_count: usize,
    at_ms: i64,
}

/// Mints disclosure correlation ids that no protocol request can collide with.
///
/// A process-local counter, so an id is never repeated within a process even for two
/// disclosures of the same file in the same millisecond. `pid` and `at_ms` keep it distinct
/// across a restart, where the audit chain resumes from durable storage and a counter alone
/// would start over.
fn mint_disclosure_request(at_ms: i64) -> RequestId {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    RequestId::new(format!(
        "disclosure:{pid}:{at_ms}:{n}",
        pid = std::process::id()
    ))
}

impl DisclosureRecord {
    /// Builds a disclosure record, minting its own correlation.
    ///
    /// The caller supplies the read's correlation and everything being disclosed *about*.
    /// The disclosure's correlation is minted here, so it cannot be made to match the
    /// parent's.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_read(
        parent_read_request: RequestId,
        parent_proposal_id: impl Into<String>,
        task_id: TaskId,
        step_no: u32,
        path: impl Into<String>,
        provider: crate::observation::ProviderIdentity,
        byte_count: usize,
        at_ms: i64,
    ) -> Self {
        Self {
            disclosure_request: mint_disclosure_request(at_ms),
            parent_read_request,
            parent_proposal_id: parent_proposal_id.into(),
            task_id,
            step_no,
            path: path.into(),
            provider,
            byte_count,
            at_ms,
        }
    }

    /// The read whose approved result produced these bytes.
    #[must_use]
    pub fn parent_read_request(&self) -> &RequestId {
        &self.parent_read_request
    }

    /// This disclosure's own correlation. Never equal to the parent's.
    #[must_use]
    pub fn disclosure_request(&self) -> &RequestId {
        &self.disclosure_request
    }

    /// The task the disclosure belongs to.
    #[must_use]
    pub fn task_id(&self) -> &TaskId {
        &self.task_id
    }

    /// The step the disclosure happened at.
    #[must_use]
    pub fn step_no(&self) -> u32 {
        self.step_no
    }

    /// The workspace-relative path that was read.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The canonical identity the bytes went to.
    ///
    /// The same value that authorised the release, so the record and the check cannot
    /// disagree about where the content went.
    #[must_use]
    pub fn provider(&self) -> &crate::observation::ProviderIdentity {
        &self.provider
    }

    /// How many bytes were disclosed. A count, never the content.
    #[must_use]
    pub fn byte_count(&self) -> usize {
        self.byte_count
    }

    /// Renders this disclosure as an audit record on its own correlation.
    ///
    /// The `capability` is `orxnud.policy/disclose` — it names the disclosure rather than
    /// the read, so a reviewer scanning capabilities sees that a disclosure happened rather
    /// than inferring one from a `Finished` on some other action.
    ///
    /// The actor is the **human who approved the read**: that is the authority the
    /// disclosure rests on, since one approval covers both the local read and the sending of
    /// its result to this provider identity, and nothing else (ADR-0045).
    #[must_use]
    pub fn to_audit_record(&self, approver: Actor) -> AuditRecord {
        AuditRecord {
            seq: 0, // assigned by the chain
            authority_root: approver.authority_root().map(ToString::to_string),
            actor: approver,
            capability: "orxnud.policy/disclose".to_owned(),
            target: Some(self.path.clone()),
            data_class: DataClass::Public,
            risk: RiskClass::High,
            policy_version: "v1".to_owned(),
            // No approval digest: this is not an approval, it is the *consequence* of one.
            approval: None,
            secret_ref: None,
            task: Some(self.task_id.clone()),
            // The dedicated correlation. This is what keeps the disclosure from closing, or
            // being closed by, the read's own authorisation record.
            request: Some(self.disclosure_request.clone()),
            // Settles nothing, and says so. A disclosure is not the terminal
            // disposition of an authorisation: it is an additional fact about the world,
            // recorded because the bytes left the machine. The authorisation it depends
            // on is the read's, and that one is settled by the read's own terminal
            // record — so claiming it here would settle the same authorisation twice,
            // which is exactly the double-count the identity model exists to prevent.
            //
            // A `Finished` record with no `settles` therefore means "a recorded fact
            // that is not a settlement", and contributes nothing to
            // `unresolved_authorisations`' settled set. That is why no separate
            // "settles nothing" flag is needed.
            settles: None,
            outcome: AuditOutcome::Finished {
                kind: OutcomeKind::Completed,
                at_ms: self.at_ms,
                // Bounded and content-free: identifiers, a count, and the canonical
                // destination identity.
                detail: Some(self.detail()),
            },
        }
    }

    /// The bounded, content-free detail line.
    ///
    /// Fixed key order. An auditor can answer "which approved read sent what, where, and how
    /// much" from this alone, without reconstructing anything from timestamps — which is
    /// what `parent_read` and `disclosure` correlations are both cited for.
    #[must_use]
    pub fn detail(&self) -> String {
        format!(
            "disclosure parent_read={} disclosure={} parent_proposal={} task={} step_no={} \
             path={} endpoint={} model={} byte_count={}",
            self.parent_read_request,
            self.disclosure_request,
            self.parent_proposal_id,
            self.task_id,
            self.step_no,
            self.path,
            self.provider.endpoint(),
            self.provider.model(),
            self.byte_count,
        )
    }
}

/// Stage 4c: the retention and release rules.
///
/// Each test pins one clause of the contract. The ones that matter most are the negative
/// ones — cross-task, cross-provider and repeat-release — because those are the ways approved
/// content could reach somewhere it was not approved for.
#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_767_225_600_000;
    /// Unmistakable in a prompt or a log if it ever appears where it should not.
    const SENTINEL: &str = "SENTINEL-OBSERVATION-b7e2d1";

    fn provider() -> ProviderIdentity {
        ProviderIdentity::new("https://api.groq.com/openai/v1", "openai/gpt-oss-120b")
    }

    /// The read step every fixture here came from, so a fixture observation is eligible for
    /// `READ_STEP + 1` and for nothing else.
    const READ_STEP: u32 = 1;
    /// The step the proposal asking for it is on.
    const NEXT_STEP: u32 = READ_STEP + 1;

    fn approver() -> Actor {
        Actor::Human {
            user: orxnud_domain::ids::UserId::new("local"),
            via: orxnud_domain::actor::AuthChannel::LocalInteractive,
        }
    }

    fn origin() -> ObservationOrigin {
        ObservationOrigin {
            parent_read_request: RequestId::new("req-read-1"),
            parent_proposal_id: "p-1".to_owned(),
            approver: approver(),
        }
    }

    fn obs(path: &str, provider: ProviderIdentity, at: i64) -> Observation {
        Observation {
            task_id: TaskId::new("t-1"),
            step_no: READ_STEP,
            path: path.to_owned(),
            provider,
            bytes: SENTINEL.as_bytes().to_vec(),
            recorded_at_ms: at,
            origin: origin(),
        }
    }

    // ------------------------------------------------- provider identity

    #[test]
    fn the_same_endpoint_and_model_is_eligible() {
        assert!(provider().matches(&provider()));
    }

    /// The case the model-string-only rule would have got wrong.
    #[test]
    fn a_different_model_on_the_same_endpoint_is_refused() {
        let other = ProviderIdentity::new("https://api.groq.com/openai/v1", "some/other-model");
        assert!(!provider().matches(&other));
    }

    #[test]
    fn a_different_endpoint_with_the_same_model_is_refused() {
        let other = ProviderIdentity::new("https://evil.example/openai/v1", "openai/gpt-oss-120b");
        assert!(
            !provider().matches(&other),
            "the same model name on another operator's endpoint must not inherit the approval"
        );
    }

    #[test]
    fn a_different_endpoint_and_model_is_refused() {
        let other = ProviderIdentity::new("https://elsewhere.test/v1", "other/model");
        assert!(!provider().matches(&other));
    }

    /// Cosmetic spellings of one endpoint must not refuse legitimate reuse, or the rule
    /// becomes something operators work around.
    #[test]
    fn cosmetic_spellings_of_one_endpoint_canonicalise_together() {
        let a = ProviderIdentity::new("https://API.Groq.com/openai/v1/", "m");
        let b = ProviderIdentity::new("https://api.groq.com:443/openai/v1", "m");
        let c = ProviderIdentity::new("  https://api.groq.com/openai/v1  ", "m");
        assert!(
            a.matches(&b) && b.matches(&c) && a.matches(&c),
            "{a:?} {b:?} {c:?}"
        );
        // And an http endpoint on the same host is a different destination.
        assert!(!ProviderIdentity::new("http://api.groq.com/v1", "m").matches(&a));
    }

    #[test]
    fn the_identity_reports_what_an_audit_record_would_cite() {
        let p = ProviderIdentity::new("https://api.groq.com/openai/v1/", "openai/gpt-oss-120b");
        assert_eq!(p.endpoint(), "https://api.groq.com/openai/v1");
        assert_eq!(p.model(), "openai/gpt-oss-120b");
    }

    // ---------------------------------------------------- task isolation

    #[test]
    fn observations_are_never_visible_across_tasks() {
        let mut store = ObservationStore::new();
        store.retain(obs("a.txt", provider(), NOW));

        let other_task = TaskId::new("t-2");
        let released = store.take_for(&other_task, NEXT_STEP, &provider(), NOW, 64 * 1024);
        assert!(
            released.is_empty(),
            "one task's approved read reached another task's prompt: {released:?}"
        );
        // And it was not consumed by the attempt.
        assert_eq!(
            store.len(),
            1,
            "the observation must still be there for its own task"
        );
    }

    #[test]
    fn the_owning_task_releases_it() {
        let mut store = ObservationStore::new();
        store.retain(obs("a.txt", provider(), NOW));
        let released = store.take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].bytes, SENTINEL.as_bytes());
        assert_eq!(released[0].byte_count, SENTINEL.len());
    }

    // ------------------------------------------------- provider binding

    #[test]
    fn a_repointed_endpoint_does_not_receive_retained_bytes() {
        let mut store = ObservationStore::new();
        store.retain(obs("a.txt", provider(), NOW));
        let elsewhere = ProviderIdentity::new("https://elsewhere.test/v1", "openai/gpt-oss-120b");
        let released = store.take_for(&TaskId::new("t-1"), NEXT_STEP, &elsewhere, NOW, 64 * 1024);
        assert!(released.is_empty(), "{released:?}");
        assert_eq!(
            store.len(),
            1,
            "and the observation is retained, not consumed"
        );
    }

    #[test]
    fn a_changed_model_does_not_receive_retained_bytes() {
        let mut store = ObservationStore::new();
        store.retain(obs("a.txt", provider(), NOW));
        let other_model = ProviderIdentity::new("https://api.groq.com/openai/v1", "other/model");
        assert!(
            store
                .take_for(&TaskId::new("t-1"), NEXT_STEP, &other_model, NOW, 64 * 1024)
                .is_empty()
        );
    }

    // --------------------------------------------------- consume exactly once

    #[test]
    fn an_observation_is_consumed_by_one_proposal() {
        let mut store = ObservationStore::new();
        store.retain(obs("a.txt", provider(), NOW));
        let first = store.take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024);
        assert_eq!(first.len(), 1);
        let second = store.take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024);
        assert!(
            second.is_empty(),
            "the same approved bytes informed a second proposal: {second:?}"
        );
        assert!(store.is_empty());
    }

    /// The step boundary, in both directions.
    ///
    /// The read happened on one step and informs the *next* one. A request on the read's own
    /// step would be the read telling itself what it already knows; a request two or more
    /// steps later would turn one approval into standing permission for every proposal the
    /// task will ever make, including ones made after other steps have run.
    #[test]
    fn an_observation_informs_only_the_immediately_following_step() {
        let mut store = ObservationStore::new();
        store.retain(obs("a.txt", provider(), NOW));

        // The same step the read happened on.
        assert!(
            store
                .take_for(&TaskId::new("t-1"), READ_STEP, &provider(), NOW, 64 * 1024)
                .is_empty(),
            "a step must not be told by the read it just performed"
        );
        // Two steps later.
        assert!(
            store
                .take_for(
                    &TaskId::new("t-1"),
                    NEXT_STEP + 1,
                    &provider(),
                    NOW,
                    64 * 1024
                )
                .is_empty(),
            "an approval for the next proposal must not become permission for later ones"
        );
        assert_eq!(store.len(), 1, "and neither ineligible lookup consumed it");

        // The one boundary it was approved for.
        assert_eq!(
            store
                .take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024)
                .len(),
            1
        );
        assert!(store.is_empty());
    }

    /// Every wrong axis at once, with the right one unable to rescue it.
    ///
    /// Separated from the single-axis tests above because the interesting failure is a
    /// *combination*: an observation that matches task and step but not provider is exactly
    /// what a re-pointed endpoint produces, and it is the case a review is least likely to
    /// notice.
    #[test]
    fn a_mismatched_provider_is_refused_even_on_the_right_task_and_step() {
        let mut store = ObservationStore::new();
        store.retain(obs("a.txt", provider(), NOW));

        for elsewhere in [
            ProviderIdentity::new("https://elsewhere.test/v1", "openai/gpt-oss-120b"),
            ProviderIdentity::new("https://api.groq.com/openai/v1", "other/model"),
        ] {
            let released =
                store.take_for(&TaskId::new("t-1"), NEXT_STEP, &elsewhere, NOW, 64 * 1024);
            assert!(
                released.is_empty(),
                "content reached {elsewhere:?} on the right task and step: {released:?}"
            );
        }
        assert_eq!(store.len(), 1, "and it survives for its own provider");
    }

    /// A restart cannot resurrect a consumed observation, because there is nothing to
    /// resurrect.
    ///
    /// ADR-0045 Decision 4 made retention non-durable deliberately. The consequence worth
    /// stating as a property rather than leaving implied: single-use is enforced by erasure,
    /// not by a durable "consumed" flag that a crash could roll back. A restart yields an
    /// empty store, so the strongest possible version of "one observation informs one
    /// proposal" holds — a consumed observation is not merely marked used, it is gone.
    #[test]
    fn a_consumed_observation_is_gone_rather_than_merely_marked_used() {
        let mut store = ObservationStore::new();
        store.retain(obs("a.txt", provider(), NOW));
        assert_eq!(
            store
                .take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024)
                .len(),
            1
        );
        // A restart is a new process with a new, empty store.
        let mut after_restart = ObservationStore::new();
        assert!(
            after_restart
                .take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024)
                .is_empty(),
            "a restarted daemon must not be able to re-release a consumed observation"
        );
    }

    /// The released bytes carry the read's citation with them.
    ///
    /// The disclosure audit record is built from this, so a mismatch between what was
    /// released and what the record cites would let the audit name the wrong approval.
    #[test]
    fn the_release_carries_the_reads_citation() {
        let mut store = ObservationStore::new();
        store.retain(obs("a.txt", provider(), NOW));
        let released = store.take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].origin, origin());
        assert_eq!(
            released[0].byte_count,
            released[0].bytes.len(),
            "the recorded count must describe the bytes actually released"
        );
    }

    /// The API selects by `(task, step, provider identity)` and offers nothing finer.
    ///
    /// There is deliberately no observation id anywhere in this module: an id a request could
    /// name would be a selector, and selectors are what a confused-deputy attempt iterates.
    /// The only caller is the runtime, which asks for "whatever belongs to the task and step I
    /// am already working on" — so this asserts that asking is all-or-nothing over the
    /// eligible set. A subset selection would mean something had chosen one.
    #[test]
    fn the_release_is_selected_only_by_task_step_and_provider() {
        let mut store = ObservationStore::new();
        for p in ["a.txt", "b.txt", "c.txt"] {
            store.retain(obs(p, provider(), NOW));
        }
        let released = store.take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024);
        assert_eq!(
            released.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            vec!["c.txt", "b.txt", "a.txt"],
            "every eligible observation is released; none can be picked out"
        );
        assert!(store.is_empty(), "and all of them are consumed");
    }

    #[test]
    fn an_observation_that_is_not_released_is_not_consumed() {
        let mut store = ObservationStore::new();
        store.retain(obs("big.txt", provider(), NOW));
        // A budget too small for it.
        let none = store.take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 4);
        assert!(none.is_empty());
        assert_eq!(
            store.len(),
            1,
            "an unreleased observation must survive for a later budget"
        );
        // And it is still whole when it does fit.
        let some = store.take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024);
        assert_eq!(some[0].bytes, SENTINEL.as_bytes());
    }

    // ------------------------------------------------------------- expiry

    #[test]
    fn an_observation_expires_on_the_ttl() {
        let mut store = ObservationStore::with_limits(1_000, 8, 64 * 1024);
        store.retain(obs("a.txt", provider(), NOW));
        assert_eq!(
            store
                .take_for(
                    &TaskId::new("t-1"),
                    NEXT_STEP,
                    &provider(),
                    NOW + 999,
                    64 * 1024,
                )
                .len(),
            1
        );
        store.retain(obs("a.txt", provider(), NOW + 5_000));
        // Still inside the TTL at +5_100, which is the boundary the check has to respect.
        assert_eq!(
            store
                .take_for(
                    &TaskId::new("t-1"),
                    NEXT_STEP,
                    &provider(),
                    NOW + 5_100,
                    64 * 1024,
                )
                .len(),
            1,
            "100ms into a 1000ms TTL must not expire"
        );
        store.retain(obs("b.txt", provider(), NOW + 20_000));
        assert!(
            store
                .take_for(
                    &TaskId::new("t-1"),
                    NEXT_STEP,
                    &provider(),
                    NOW + 20_000 + 1_001,
                    64 * 1024,
                )
                .is_empty(),
            "past the TTL it must be withheld"
        );
        assert!(
            store.is_empty(),
            "an expired observation must be deleted, not just withheld"
        );
    }

    // -------------------------------------------------------- accumulation

    #[test]
    fn a_newer_read_replaces_the_older_one_for_the_same_path() {
        let mut store = ObservationStore::new();
        store.retain(Observation {
            bytes: b"old".to_vec(),
            ..obs("a.txt", provider(), NOW)
        });
        store.retain(Observation {
            bytes: b"new".to_vec(),
            ..obs("a.txt", provider(), NOW + 1)
        });
        assert_eq!(
            store.len(),
            1,
            "a stale version of the same path must not accumulate"
        );
        let released = store.take_for(
            &TaskId::new("t-1"),
            NEXT_STEP,
            &provider(),
            NOW + 1,
            64 * 1024,
        );
        assert_eq!(released[0].bytes, b"new".to_vec());
    }

    #[test]
    fn distinct_paths_accumulate_up_to_the_limit() {
        let mut store = ObservationStore::with_limits(60_000, 3, 64 * 1024);
        for i in 1..=5 {
            store.retain(obs(&format!("f{i}.txt"), provider(), NOW + i64::from(i)));
        }
        assert_eq!(store.len(), 3, "the store is bounded");
        let released = store.take_for(
            &TaskId::new("t-1"),
            NEXT_STEP,
            &provider(),
            NOW + 5,
            64 * 1024,
        );
        assert_eq!(
            released.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
            vec!["f5.txt", "f4.txt", "f3.txt"],
            "newest first, and the oldest were evicted"
        );
    }

    // ---------------------------------------------------- content budget

    #[test]
    fn whole_observations_only_and_newest_first() {
        let mut store = ObservationStore::new();
        for (i, size) in [(1, 10usize), (2, 10), (3, 10)] {
            store.retain(Observation {
                bytes: vec![b'a' + i as u8; size],
                ..obs(&format!("f{i}.txt"), provider(), NOW + i64::from(i))
            });
        }
        // Room for two of the three.
        let released = store.take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW + 3, 20);
        assert_eq!(released.len(), 2);
        assert_eq!(released[0].path, "f3.txt", "newest first");
        assert_eq!(released[1].path, "f2.txt");
        assert!(
            released.iter().all(|r| r.byte_count == 10),
            "nothing was truncated"
        );
        assert_eq!(store.len(), 1, "the skipped observation is retained");
    }

    #[test]
    fn a_never_truncated_blob_is_whole_or_absent() {
        let mut store = ObservationStore::new();
        store.retain(Observation {
            bytes: vec![b'x'; 100],
            ..obs("big.txt", provider(), NOW)
        });
        let released = store.take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 99);
        assert!(
            released.is_empty(),
            "a 100-byte blob must not be released into a 99-byte budget"
        );
    }

    #[test]
    fn release_order_is_deterministic_for_equal_timestamps() {
        let render = || {
            let mut store = ObservationStore::new();
            for i in 1..=4 {
                store.retain(obs(&format!("f{i}.txt"), provider(), NOW));
            }
            store
                .take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024)
                .iter()
                .map(|r| r.path.clone())
                .collect::<Vec<_>>()
        };
        let first = render();
        for _ in 0..8 {
            assert_eq!(render(), first);
        }
        assert_eq!(first, vec!["f4.txt", "f3.txt", "f2.txt", "f1.txt"]);
    }

    #[test]
    fn a_mismatched_task_or_provider_releases_nothing_and_consumes_nothing() {
        let mut store = ObservationStore::new();
        store.retain(obs("a.txt", provider(), NOW));
        let _ = store.take_for(
            &TaskId::new("other"),
            NEXT_STEP,
            &provider(),
            NOW,
            64 * 1024,
        );
        let _ = store.take_for(
            &TaskId::new("t-1"),
            NEXT_STEP,
            &ProviderIdentity::new("https://x.test/v1", "m"),
            NOW,
            64 * 1024,
        );
        assert_eq!(
            store.len(),
            1,
            "an ineligible lookup must not consume anything"
        );
        assert_eq!(
            store
                .take_for(&TaskId::new("t-1"), NEXT_STEP, &provider(), NOW, 64 * 1024,)
                .len(),
            1
        );
    }
}

/// The store's own ceiling cannot be widened by a caller.
///
/// A caller passing a large budget must not be able to exceed what the store was configured
/// with, because the configured limit is the one an operator reasoned about. The effective
/// ceiling is the smaller of the two.
#[cfg(test)]
mod ceiling_tests {
    use super::*;

    const NOW: i64 = 1_767_225_600_000;
    /// The step these fixtures' reads happened on; the request is the next one.

    #[test]
    fn a_caller_cannot_exceed_the_stores_own_ceiling() {
        let mut store = ObservationStore::with_limits(60_000, 8, 100);
        let provider = ProviderIdentity::new("https://p.test/v1", "m");
        for i in 1..=3 {
            store.retain(Observation {
                task_id: TaskId::new("t"),
                step_no: 1,
                path: format!("f{i}.txt"),
                provider: provider.clone(),
                bytes: vec![b'x'; 80],
                recorded_at_ms: NOW + i64::from(i),
                origin: ObservationOrigin {
                    parent_read_request: RequestId::new("req"),
                    parent_proposal_id: "p".to_owned(),
                    approver: Actor::Human {
                        user: orxnud_domain::ids::UserId::new("local"),
                        via: orxnud_domain::actor::AuthChannel::LocalInteractive,
                    },
                },
            });
        }
        let released = store.take_for(&TaskId::new("t"), 2, &provider, NOW + 3, 100_000);
        assert_eq!(
            released.len(),
            1,
            "the caller's huge budget must not override the configured 100-byte ceiling"
        );
        assert_eq!(released[0].byte_count, 80);
        assert_eq!(store.len(), 2, "the rest stay retained, untruncated");
    }

    #[test]
    fn a_smaller_caller_budget_still_wins() {
        let mut store = ObservationStore::with_limits(60_000, 8, 10_000);
        let provider = ProviderIdentity::new("https://p.test/v1", "m");
        store.retain(Observation {
            task_id: TaskId::new("t"),
            step_no: 1,
            path: "a.txt".to_owned(),
            provider: provider.clone(),
            bytes: vec![b'x'; 500],
            recorded_at_ms: NOW,
            origin: ObservationOrigin {
                parent_read_request: RequestId::new("req"),
                parent_proposal_id: "p".to_owned(),
                approver: Actor::Human {
                    user: orxnud_domain::ids::UserId::new("local"),
                    via: orxnud_domain::actor::AuthChannel::LocalInteractive,
                },
            },
        });
        assert!(
            store
                .take_for(&TaskId::new("t"), 2, &provider, NOW, 100)
                .is_empty(),
            "a per-request budget below the blob size must release nothing"
        );
        assert_eq!(store.len(), 1);
    }
}

/// The disclosure record's interaction with the audit chain.
///
/// These are the assertions that answer the question 4c was gated on: can a disclosure ride
/// its own correlation without disturbing the read's, without inventing an "outcome unknown",
/// and without weakening the meaning of `Finished`?
#[cfg(test)]
mod disclosure_tests {
    use super::*;
    use orxnud_audit::AuditChain;
    use orxnud_domain::actor::AuthChannel;
    use orxnud_domain::ids::UserId;

    const NOW: i64 = 1_767_225_600_000;
    const SENTINEL: &str = "SENTINEL-DISCLOSURE-CONTENT-4a91c7";

    fn approver() -> Actor {
        Actor::Human {
            user: UserId::new("local"),
            via: AuthChannel::LocalInteractive,
        }
    }

    fn provider() -> ProviderIdentity {
        ProviderIdentity::new("https://api.groq.com/openai/v1/", "openai/gpt-oss-120b")
    }

    fn disclosure(path: &str, bytes: usize) -> DisclosureRecord {
        DisclosureRecord::from_verified_read(
            RequestId::new("req-read-1"),
            "p-1",
            TaskId::new("t-1"),
            2,
            path,
            provider(),
            bytes,
            NOW,
        )
    }

    fn read_auth(request: RequestId) -> AuditRecord {
        AuditRecord::authorised(
            approver(),
            "filesystem/read-text",
            Some("a.txt".to_owned()),
            DataClass::Public,
            RiskClass::High,
            "v1",
            None,
            None,
            Some(TaskId::new("t-1")),
            Some(request),
            NOW,
        )
    }

    /// The structural invariant: the disclosure correlation is minted, so it cannot be the
    /// read's. Asserted directly rather than inferred from behaviour.
    #[test]
    fn a_disclosure_correlation_cannot_be_made_to_equal_its_parent() {
        let d = disclosure("a.txt", 42);
        assert_ne!(
            d.disclosure_request(),
            d.parent_read_request(),
            "a disclosure sharing its read's correlation would close the read's authorisation"
        );
        // And repeatedly minting against the same parent still yields distinct ids.
        let ids: Vec<String> = (0..8)
            .map(|_| disclosure("a.txt", 42).disclosure_request().to_string())
            .collect();
        let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), 8, "disclosure correlations repeated: {ids:?}");
    }

    #[test]
    fn the_disclosure_record_carries_no_content() {
        let detail = disclosure("a.txt", SENTINEL.len()).detail();
        assert!(!detail.contains(SENTINEL), "{detail}");
        assert!(detail.contains("byte_count="), "{detail}");
        assert!(detail.len() < 400, "unbounded detail: {detail}");
    }

    /// The identity in the record is the canonical one, byte for byte.
    #[test]
    fn the_record_cites_the_canonical_identity() {
        let d = disclosure("a.txt", 10);
        let identity = provider();
        assert!(
            d.detail()
                .contains(&format!("endpoint={}", identity.endpoint())),
            "not the canonical endpoint: {}",
            d.detail()
        );
        assert!(d.detail().contains(&format!("model={}", identity.model())));
        assert_eq!(
            d.to_audit_record(approver()).capability,
            "orxnud.policy/disclose"
        );
    }

    /// An auditor can answer the linkage question from the record alone.
    #[test]
    fn the_linkage_to_the_approved_read_is_explicit() {
        let detail = disclosure("sub/a.txt", 42).detail();
        for expected in [
            "parent_read=req-read-1",
            "parent_proposal=p-1",
            "task=t-1",
            "step_no=2",
            "path=sub/a.txt",
            "byte_count=42",
        ] {
            assert!(
                detail.contains(expected),
                "missing {expected:?} in {detail}"
            );
        }
        assert!(detail.contains("disclosure=disclosure:"), "{detail}");
    }

    /// The decisive one: a disclosure neither closes the read's authorisation nor
    /// manufactures an unresolved one.
    #[test]
    fn a_disclosure_does_not_disturb_the_read_correlation() {
        let mut chain = AuditChain::new();
        let read = read_auth(RequestId::new("req-read-1"));
        chain.append(read.clone()).expect("append");
        chain
            .append(disclosure("a.txt", 42).to_audit_record(approver()))
            .expect("append");
        // Still open: the read has not been closed by the disclosure.
        assert_eq!(
            chain.unresolved_authorisations().len(),
            1,
            "the disclosure closed the read's authorisation"
        );
        // `.settling(0)` because that is what production writes: `record_terminal` names
        // the authorisation it closes. Without it this record is a fact about the world
        // that settles nothing — the disclosure's case — and the read stays open, which is
        // the correct behaviour for a record with no identity and the *wrong* one here.
        chain
            .append(read.finished(OutcomeKind::Completed, NOW, None).settling(0))
            .expect("append");
        assert!(chain.unresolved_authorisations().is_empty());
        chain.verify().expect("the chain still verifies");
    }

    /// A disclosure's terminal record carries no authorisation identity, so it cannot
    /// close anything — including a read whose authorisation it happens to share a
    /// request label with.
    ///
    /// Asserted separately from the test above because it is a different claim: that one
    /// shows the disclosure does not *wrongly* close the read, this one shows the read's
    /// own terminal record is what closes it. Between them they pin the direction of the
    /// rule, which is the one that has to be right: a disclosure may under-claim, never
    /// over-claim.
    #[test]
    fn a_disclosure_record_settles_nothing() {
        let record = disclosure("a.txt", 42).to_audit_record(approver());
        assert_eq!(
            record.settles_authorisation(),
            None,
            "a disclosure is a recorded fact, not the disposition of an authorisation"
        );
        assert!(
            matches!(record.outcome, AuditOutcome::Finished { .. }),
            "it is still a terminal record about something"
        );
    }

    /// And a disclosure never manufactures one either.
    #[test]
    fn a_disclosure_alone_creates_no_unresolved_authorisation() {
        let mut chain = AuditChain::new();
        chain
            .append(disclosure("a.txt", 42).to_audit_record(approver()))
            .expect("append");
        assert!(chain.unresolved_authorisations().is_empty());
        chain.verify().expect("verify");
    }

    #[test]
    fn two_disclosures_of_the_same_file_get_distinct_correlations() {
        let mut chain = AuditChain::new();
        chain
            .append(disclosure("a.txt", 10).to_audit_record(approver()))
            .expect("append");
        chain
            .append(disclosure("a.txt", 20).to_audit_record(approver()))
            .expect("append");
        assert!(chain.unresolved_authorisations().is_empty());
        chain.verify().expect("verify");
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn disclosures_for_different_tasks_do_not_interfere() {
        let a = DisclosureRecord::from_verified_read(
            RequestId::new("req-a"),
            "p-a",
            TaskId::new("t-a"),
            1,
            "a.txt",
            provider(),
            5,
            NOW,
        );
        let b = DisclosureRecord::from_verified_read(
            RequestId::new("req-b"),
            "p-b",
            TaskId::new("t-b"),
            1,
            "b.txt",
            provider(),
            5,
            NOW,
        );
        assert_ne!(a.disclosure_request(), b.disclosure_request());
        assert_eq!(a.task_id(), &TaskId::new("t-a"));
        assert_eq!(b.task_id(), &TaskId::new("t-b"));
    }
}
