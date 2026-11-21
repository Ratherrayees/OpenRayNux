//! Application state and actions, independent of rendering.
//!
//! Every action is one protocol call and one state update. There is no rule here about
//! what a task or proposal *means*: the daemon's own words are what get stored and
//! shown, so the surface cannot drift into a second definition of a governed concept.
//!
//! The one thing this module does hold is a claim generation issued by a particular
//! `task/claim` response. It is kept with the task and worker it was issued to, and a
//! claim-bound operation refuses to run unless both still match. It is never derived
//! from `task/list` and never invented.

use std::collections::HashMap;
use std::path::Path;

use orxnuctl::approval::{
    self, ApprovalFailure, ApprovalFailureOrigin, ApprovalStage, ApprovalStart, PreviewRequests,
    Review,
};
use orxnuctl::client::{Client, ClientError};
use serde_json::{Value, json};

/// What this surface can talk to.
///
/// Implemented by the shipped client and by deterministic test fakes, so an action's
/// exact requests can be asserted without a daemon. The approval half of the protocol
/// is the shared [`PreviewRequests`] trait; this adds only negotiation and the endpoint.
pub trait Rpc: PreviewRequests {
    /// Perform the protocol version negotiation, returning the agreed version.
    fn negotiate(&self) -> Result<u16, ClientError>;

    /// The socket this surface talks to.
    fn endpoint(&self) -> &Path;
}

impl Rpc for Client {
    fn negotiate(&self) -> Result<u16, ClientError> {
        Client::negotiate(self)
    }

    fn endpoint(&self) -> &Path {
        Client::endpoint(self)
    }
}

/// One line of status for the footer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// The text to show.
    pub text: String,
    /// Whether this is an error, rendered differently from an informational note.
    pub is_error: bool,
}

impl Notice {
    fn info(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
        }
    }

    fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }
}

enum RefreshOutcome {
    Refreshed,
    StatusFailed,
    TaskListFailed,
}

const KNOWN_TASK_STATES: [&str; 11] = [
    "pending",
    "running",
    "waiting-for-user",
    "waiting-for-external",
    "paused",
    "cancelled",
    "completed",
    "failed",
    "dead-lettered",
    "needs-verification",
    "awaiting-next-step",
];

/// Which pane has focus for text entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input {
    /// No input: keys navigate and act.
    None,
    /// Typing a proposal id for preview/approve/execute.
    Proposal,
    /// Typing the id of a task to create.
    TaskId,
    /// Typing the content of the task to create.
    TaskContent,
    /// Typing the worker identity used by claim/propose/execute/complete.
    Worker,
}

/// The generation a specific claim returned, with the identity it was issued to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The task the claim was for.
    pub task: String,
    /// The worker that received the claim.
    pub worker: String,
    /// The generation returned by that claim, verbatim.
    pub generation: i64,
}

/// Origin metadata for a proposal this TUI created through `task/ai-propose`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AiProposalProvenance {
    proposal_id: String,
    worker: String,
    claim_generation: i64,
}

/// What is known about an approval for one proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalDisposition {
    NotAccepted,
    SubmittedUnknown,
    Refused,
    Accepted,
}

/// What is known about the execution of one proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionDisposition {
    ApprovedReady,
    OutcomeUnknown,
    NoEffectConsumed,
    RefusedEffectPossible,
    ResultReceived,
}

/// The last-known context an open review was created under.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReviewContext {
    task_id: String,
    proposal_id: String,
    adoption_worker: String,
    origin_worker: Option<String>,
    originating_claim_generation: Option<i64>,
    observed_claim_generation: Option<i64>,
    proposal_status: Option<String>,
    attempt_no: Option<u64>,
    step_no: Option<u64>,
}

/// What is on screen.
#[derive(Debug)]
pub struct App<R: Rpc = Client> {
    /// The daemon, reached through the CLI's client.
    client: R,
    /// `daemon/status`, verbatim. `None` until the first successful refresh.
    pub status: Option<Value>,
    /// The `tasks` array from `task/list`, verbatim.
    pub tasks: Vec<Value>,
    /// Index into `tasks`.
    pub selected: usize,
    /// The preview response for the id the operator supplied.
    pub preview: Option<Value>,
    /// The id of the preview currently shown (so an action cannot target a different one).
    pub preview_id: Option<String>,
    /// The execution verdict from the last `task/execute`, verbatim.
    pub verdict: Option<Value>,
    /// Validated execution results, keyed by proposal id.
    execution_results: HashMap<String, Value>,
    /// A model-initiated read awaiting an explicit human decision.
    pub review: Option<Review>,
    /// Whether the open review is hidden rather than consumed.
    review_hidden: bool,
    /// The last-known context the open review was created under.
    review_context: Option<ReviewContext>,
    /// AI proposal provenance, keyed by proposal id and retained for this session.
    ai_provenance: HashMap<String, AiProposalProvenance>,
    /// Worker label active when the current preview was adopted.
    adoption_worker: Option<String>,
    /// Approval dispositions, keyed by proposal id.
    approval_dispositions: HashMap<String, ApprovalDisposition>,
    /// Execution dispositions, keyed by proposal id.
    execution_dispositions: HashMap<String, ExecutionDisposition>,
    /// Whether the terminal currently shows every security-relevant review field.
    /// Recomputed from the real layout each event-loop pass; confirmation is refused
    /// while false. Decline stays available as a safe exit.
    review_displayable: bool,
    /// The claim this surface received, if any.
    pub claim: Option<Claim>,
    /// The id typed for a task that is about to be created.
    pub new_task_id: Option<String>,
    /// Worker identity used for claim/propose/execute/complete. A label, not an authority.
    pub worker: String,
    /// The current input buffer, when one is active.
    pub buffer: String,
    /// Which input is active.
    pub input: Input,
    /// The last message for the footer.
    pub notice: Option<Notice>,
    /// Set by `quit`; the event loop reads it.
    pub should_quit: bool,
}

/// Minimum review-pane width, shared by measurement and the confirmation gate.
pub const MIN_REVIEW_PANE_WIDTH: u16 = 24;

/// The result of measuring a review against the real terminal layout.
///
/// The boolean is derived from dimensions supplied by the renderer; callers cannot
/// assert "displayable" directly. No wrapping calculation lives here — the event
/// loop supplies the pane dimensions and the renderer-derived required height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewGeometry {
    fits: bool,
}

impl ReviewGeometry {
    /// Computes eligibility from the measured pane and required content height.
    #[must_use]
    pub fn from_measurement(pane_width: u16, pane_height: u16, required_height: u16) -> Self {
        Self {
            fits: pane_width >= MIN_REVIEW_PANE_WIDTH && pane_height >= required_height,
        }
    }

    /// Whether the measurement allows confirmation.
    #[must_use]
    pub fn fits(&self) -> bool {
        self.fits
    }
}

impl<R: Rpc> App<R> {
    /// Construct with an explicit client, for tests against a synthetic daemon.
    #[must_use]
    pub fn with_client(client: R) -> Self {
        Self {
            client,
            status: None,
            tasks: Vec::new(),
            selected: 0,
            preview: None,
            preview_id: None,
            verdict: None,
            execution_results: HashMap::new(),
            review: None,
            review_hidden: false,
            review_context: None,
            ai_provenance: HashMap::new(),
            adoption_worker: None,
            approval_dispositions: HashMap::new(),
            execution_dispositions: HashMap::new(),
            review_displayable: false,
            claim: None,
            new_task_id: None,
            worker: "tui".to_owned(),
            buffer: String::new(),
            input: Input::None,
            notice: None,
            should_quit: false,
        }
    }

    /// The endpoint this surface talks to.
    #[must_use]
    pub fn endpoint(&self) -> &Path {
        self.client.endpoint()
    }

    /// Fetch status and tasks in two protocol calls.
    ///
    /// A failure is reported in the footer and leaves the previous state on screen:
    /// a transient daemon failure must not make the operator think the task list is
    /// empty, which would look like the tasks had vanished.
    pub fn refresh(&mut self) {
        let _ = self.refresh_outcome();
    }

    fn refresh_outcome(&mut self) -> RefreshOutcome {
        match self
            .client
            .negotiate()
            .and_then(|_| self.client.call("daemon/status", json!({})))
        {
            Ok(status) => self.status = Some(status),
            Err(e) => {
                self.notice = Some(Notice::error(format!("daemon status: {e}")));
                return RefreshOutcome::StatusFailed;
            }
        }
        match self.client.call("task/list", json!({})) {
            Ok(reply) => {
                let previous = self.selected_task_id();
                self.tasks = task_array(&reply);
                self.selected = self.selected.min(self.tasks.len().saturating_sub(1));
                if self.selected_task_id() != previous {
                    self.clear_active_context();
                } else if self.review.is_some() {
                    let state = self
                        .selected_task()
                        .and_then(|t| t.get("state"))
                        .and_then(Value::as_str);
                    let generation = self
                        .selected_task()
                        .and_then(|t| t.get("claim_generation"))
                        .and_then(Value::as_i64);
                    let invalid = state != Some("waiting-for-user")
                        || self.review_context.as_ref().is_some_and(|ctx| {
                            ctx.observed_claim_generation.is_some()
                                && generation != ctx.observed_claim_generation
                        });
                    if invalid {
                        self.clear_active_context();
                        self.notice = Some(Notice::error(
                            "task state or claim changed; review invalidated — re-preview",
                        ));
                        return RefreshOutcome::Refreshed;
                    }
                    if let Some(ctx) = self.review_context.as_mut() {
                        ctx.observed_claim_generation = generation;
                    }
                }
                self.notice = Some(Notice::info(format!(
                    "refreshed: {} task(s)",
                    self.tasks.len()
                )));
                RefreshOutcome::Refreshed
            }
            Err(e) => {
                self.notice = Some(Notice::error(format!("task list: {e}")));
                RefreshOutcome::TaskListFailed
            }
        }
    }

    /// Move the selection, clamped rather than wrapped: a silent wrap at the ends
    /// makes it look like a different task was selected.
    pub fn move_selection(&mut self, delta: isize) {
        if self.tasks.is_empty() {
            self.selected = 0;
            return;
        }
        let previous = self.selected_task_id();
        let last = self.tasks.len() - 1;
        self.selected = if delta < 0 {
            self.selected.saturating_sub(delta.unsigned_abs())
        } else {
            self.selected.saturating_add(delta as usize).min(last)
        };
        if self.selected_task_id() != previous {
            // A verdict describes the previously selected task. The review is hidden,
            // not consumed: returning to its task can reopen it without a new RPC.
            self.verdict = None;
            if self.review.is_some() {
                self.review_hidden = true;
                self.notice = Some(Notice::info(
                    "review hidden; return to its task and press a to reopen",
                ));
            }
        }
    }

    /// The selected task, if any.
    #[must_use]
    pub fn selected_task(&self) -> Option<&Value> {
        self.tasks.get(self.selected)
    }

    /// The id of the selected task, if the daemon supplied one.
    fn selected_task_id(&self) -> Option<String> {
        self.selected_task()
            .and_then(|t| t.get("id"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    /// The claim only when it still answers to this task and this worker.
    fn claim_for(&self, task: &str) -> Option<&Claim> {
        self.claim
            .as_ref()
            .filter(|c| c.task == task && c.worker == self.worker)
    }

    /// The active proposal id when a task is selected and any stored preview agrees.
    fn active_preview_id(&self) -> Option<String> {
        let id = self.preview_id.clone()?;
        let task = self.selected_task_id()?;
        if let Some(preview) = self.preview.as_ref() {
            let fields = preview.get("preview")?;
            if fields.get("proposal_id")?.as_str()? != id
                || fields.get("task_id")?.as_str()? != task
            {
                return None;
            }
        }
        Some(id)
    }

    fn clear_active_context(&mut self) {
        self.preview = None;
        self.preview_id = None;
        self.adoption_worker = None;
        self.review = None;
        self.review_hidden = false;
        self.review_context = None;
        self.review_displayable = false;
        self.verdict = None;
    }

    fn provenance_for(&self, id: &str) -> Option<&AiProposalProvenance> {
        self.ai_provenance.get(id)
    }

    fn no_replay(&self, id: &str) -> bool {
        matches!(
            self.execution_dispositions.get(id),
            Some(ExecutionDisposition::OutcomeUnknown)
                | Some(ExecutionDisposition::RefusedEffectPossible)
                | Some(ExecutionDisposition::ResultReceived)
        )
    }

    /// One shared policy for state-changing actions while a human decision is pending.
    ///
    /// A `Review` holds a daemon-issued challenge and is consumed only by
    /// [`Self::decide_review`]. No other action may discard it, send a new proposal
    /// request, or change the task/worker context it describes. Read-only actions
    /// (selection, refresh, quit) are deliberately not gated: they send no governed
    /// request and cannot invalidate the review or its claim.
    fn reject_while_review_open(&mut self, action: &str) -> bool {
        if self.review.is_some() {
            let guidance = if self.review_displayable {
                "press y to confirm or d to decline".to_owned()
            } else {
                let reason = self
                    .review_confirmation_reason()
                    .unwrap_or("confirmation is unavailable");
                format!("{reason}; press d to decline")
            };
            self.notice = Some(Notice::error(format!(
                "finish the open review first: {guidance} before {action}"
            )));
            true
        } else {
            false
        }
    }

    /// Begin typing a proposal id.
    pub fn begin_proposal_input(&mut self) {
        if self.reject_while_review_open("entering a proposal id") {
            return;
        }
        self.input = Input::Proposal;
        self.buffer.clear();
        self.notice = Some(Notice::info("proposal id: Enter to preview, Esc to cancel"));
    }

    /// Begin typing the id of a task to create.
    pub fn begin_task_id_input(&mut self) {
        if self.reject_while_review_open("creating a task") {
            return;
        }
        self.input = Input::TaskId;
        self.buffer.clear();
        self.new_task_id = None;
        self.notice = Some(Notice::info("new task id: Enter, Esc to cancel"));
    }

    /// Begin typing the worker identity.
    pub fn begin_worker_input(&mut self) {
        if self.reject_while_review_open("changing the worker") {
            return;
        }
        self.input = Input::Worker;
        self.buffer.clear();
        self.notice = Some(Notice::info("worker: Enter to set, Esc to cancel"));
    }

    /// Cancel the active input without acting.
    pub fn cancel_input(&mut self) {
        self.input = Input::None;
        self.buffer.clear();
        self.new_task_id = None;
        self.notice = Some(Notice::info("cancelled"));
    }

    /// Accept the input line. Returns `true` when a protocol action was attempted.
    pub fn accept_input(&mut self) -> bool {
        let value = self.buffer.trim().to_owned();
        let acted = match self.input {
            Input::Proposal if !value.is_empty() => {
                self.preview_proposal(&value);
                true
            }
            Input::TaskId if !value.is_empty() => {
                self.new_task_id = Some(value);
                self.input = Input::TaskContent;
                self.buffer.clear();
                self.notice = Some(Notice::info("task content: Enter to create, Esc to cancel"));
                return true;
            }
            Input::TaskContent => {
                let id = self.new_task_id.take().unwrap_or_default();
                self.new_task_id = None;
                if !id.is_empty() {
                    self.create_task(&id, &value);
                }
                true
            }
            Input::Worker if !value.is_empty() => {
                if self.reject_while_review_open("changing the worker") {
                    return true;
                }
                self.worker = value;
                // A generation belongs to the worker that received it. Changing the
                // worker drops it and the active preview/review context; historical
                // AI provenance stays bound to its original proposal.
                let dropped_claim = self.claim.take().is_some();
                let had_context = self.preview_id.is_some() || self.review.is_some();
                self.clear_active_context();
                self.notice = Some(Notice::info(format!(
                    "worker set to {}{}{}",
                    self.worker,
                    if dropped_claim {
                        "; claim cleared — claim again before proposing or completing"
                    } else {
                        ""
                    },
                    if had_context {
                        "; preview and review closed — re-preview before approving or executing"
                    } else {
                        ""
                    }
                )));
                true
            }
            Input::None => false,
            _ => {
                self.notice = Some(Notice::error("an id is required"));
                true
            }
        };
        if acted {
            self.input = Input::None;
            self.buffer.clear();
        }
        acted
    }

    /// Create a one-step task. The daemon decides whether the id is free.
    pub fn create_task(&mut self, id: &str, content: &str) {
        if self.reject_while_review_open("creating a task") {
            return;
        }
        match self
            .client
            .call("task/create", json!({ "id": id, "content": content }))
        {
            Ok(reply) => {
                let task = reply.get("task").and_then(Value::as_object);
                let state = task.and_then(|t| t.get("state")).and_then(Value::as_str);
                let Some(returned_id) = task
                    .and_then(|t| t.get("id"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                else {
                    let partial = state.map_or_else(
                        || {
                            "task/create: unexpected reply; creation unconfirmed and may \
                            already exist; press r to inspect."
                                .to_owned()
                        },
                        |state| {
                            format!(
                                "task/create: unexpected reply (state: {state}); \
                                 unconfirmed; may already exist; press r."
                            )
                        },
                    );
                    self.notice = Some(Notice::error(partial));
                    return;
                };
                let state = state.unwrap_or("not reported");
                match self.refresh_outcome() {
                    RefreshOutcome::Refreshed => {
                        self.notice = Some(Notice::info(format!(
                            "Task {returned_id} was created successfully (state: {state}); \
                             task list refreshed."
                        )));
                    }
                    RefreshOutcome::StatusFailed => {
                        self.notice = Some(Notice::error(format!(
                            "Task {returned_id} was created successfully (state: {state}); \
                             status refresh failed; may be stale; press r."
                        )));
                    }
                    RefreshOutcome::TaskListFailed => {
                        self.notice = Some(Notice::error(format!(
                            "Task {returned_id} was created successfully (state: {state}); \
                             list refresh failed; may be stale; press r."
                        )));
                    }
                }
            }
            Err(e) => self.notice = Some(Notice::error(format!("create: {e}"))),
        }
    }

    /// Claim the selected task, retaining the generation the daemon returns.
    ///
    /// A missing or malformed generation is an error and leaves no claim behind: a
    /// later proposal or completion must not invent one from the task id.
    pub fn claim_selected(&mut self) {
        if self.reject_while_review_open("claiming a task") {
            return;
        }
        let Some(id) = self.selected_task_id() else {
            self.notice = Some(Notice::error("select a task before claiming it"));
            return;
        };
        match self
            .client
            .call("task/claim", json!({ "id": id, "worker": self.worker }))
        {
            Ok(reply) => match reply.get("claim_generation").and_then(Value::as_i64) {
                Some(generation) => {
                    self.claim = Some(Claim {
                        task: id.clone(),
                        worker: self.worker.clone(),
                        generation,
                    });
                    self.notice = Some(Notice::info(format!(
                        "claimed {id}; generation retained for this task and worker"
                    )));
                }
                None => {
                    self.claim = None;
                    self.notice = Some(Notice::error(
                        "task/claim returned no usable claim_generation; no claim was retained",
                    ));
                }
            },
            Err(e) => {
                self.claim = None;
                self.notice = Some(Notice::error(format!("claim: {e}")));
            }
        }
    }

    /// Ask the daemon's AI proposer for a proposal on the claimed task.
    pub fn ai_propose_selected(&mut self) {
        if self.reject_while_review_open("requesting a new proposal") {
            return;
        }
        let Some(id) = self.selected_task_id() else {
            self.notice = Some(Notice::error("select a task before proposing"));
            return;
        };
        let Some(generation) = self.claim_for(&id).map(|c| c.generation) else {
            self.notice = Some(Notice::error(
                "claim this task with the current worker before asking for a proposal",
            ));
            return;
        };
        let origin_worker = self.worker.clone();
        match self.client.call(
            "task/ai-propose",
            json!({ "task": id, "worker": origin_worker.clone(), "claim_generation": generation }),
        ) {
            Ok(reply) => match proposal_for_task(&reply, &id) {
                Some(pid) => {
                    self.ai_provenance.insert(
                        pid.clone(),
                        AiProposalProvenance {
                            proposal_id: pid.clone(),
                            worker: origin_worker,
                            claim_generation: generation,
                        },
                    );
                    self.approval_dispositions
                        .insert(pid.clone(), ApprovalDisposition::NotAccepted);
                    self.preview_id = Some(pid.clone());
                    self.preview = None;
                    self.verdict = None;
                    self.notice = Some(Notice::info(format!(
                        "proposal {pid}; preview it before approving"
                    )));
                }
                None => {
                    self.notice = Some(Notice::error(
                        "the proposal reply did not name a proposal for this task",
                    ))
                }
            },
            Err(e) => self.notice = Some(Notice::error(format!("ai-propose: {e}"))),
        }
    }

    /// Read-only preview. `inspect_only` is deliberate: looking must not mint a
    /// challenge the operator then abandons, which is the daemon's own rule.
    pub fn preview_proposal(&mut self, id: &str) {
        if self.reject_while_review_open("previewing another proposal") {
            return;
        }
        if let Some(origin) = self.provenance_for(id)
            && origin.worker != self.worker
        {
            self.notice = Some(Notice::error(format!(
                "proposal {id} belongs to worker {}; switch back before previewing",
                origin.worker
            )));
            return;
        }
        let adoption_worker = self.worker.clone();
        let selected_task = self.selected_task_id();
        match self.client.call(
            "capability/preview",
            json!({ "proposal": id, "inspect_only": true }),
        ) {
            Ok(reply) => match approval::check_preview_id(&reply, id) {
                Ok(())
                    if selected_task.as_deref().is_some_and(|task| {
                        reply
                            .get("preview")
                            .and_then(|p| p.get("task_id"))
                            .and_then(Value::as_str)
                            == Some(task)
                    }) =>
                {
                    self.adoption_worker = Some(adoption_worker);
                    self.approval_dispositions
                        .entry(id.to_owned())
                        .or_insert(ApprovalDisposition::NotAccepted);
                    self.preview = Some(reply);
                    self.preview_id = Some(id.to_owned());
                    self.verdict = None;
                    self.notice = Some(Notice::info(format!("preview of {id}")));
                }
                Ok(()) => {
                    self.notice = Some(Notice::error(format!(
                        "preview: the reply did not describe task {}",
                        selected_task.as_deref().unwrap_or("?")
                    )))
                }
                Err(e) => self.notice = Some(Notice::error(format!("preview: {e}"))),
            },
            Err(e) => self.notice = Some(Notice::error(format!("preview: {e}"))),
        }
    }

    /// Begin the shared approval workflow for the previewed proposal.
    ///
    /// A direct proposal is approved immediately. A model-initiated file read returns a
    /// [`Review`] of the fresh challenge-bearing preview and waits for an explicit
    /// decision; the challenge is never stored on this surface.
    pub fn request_approval(&mut self) {
        let Some(task) = self.selected_task_id() else {
            self.notice = Some(Notice::error("select a task before approving"));
            return;
        };
        let Some(id) = self.active_preview_id() else {
            self.notice = Some(Notice::error("preview a proposal before approving it"));
            return;
        };
        let id = id.to_owned();
        if self.reject_while_review_open("starting another approval") {
            return;
        }
        if self
            .adoption_worker
            .as_deref()
            .is_some_and(|worker| worker != self.worker.as_str())
        {
            self.notice = Some(Notice::error(
                "the worker changed since this preview was adopted; re-preview it",
            ));
            return;
        }
        if let Some(origin) = self.provenance_for(&id)
            && origin.worker != self.worker
        {
            self.notice = Some(Notice::error(format!(
                "proposal {id} belongs to worker {}; switch back before approving",
                origin.worker
            )));
            return;
        }
        match approval::begin_approval_staged(&self.client, true, &id, json!({ "proposal": id })) {
            Ok(ApprovalStart::Submitted { reply }) => {
                if approval_accepted(&reply, &id) {
                    self.approval_dispositions
                        .insert(id.clone(), ApprovalDisposition::Accepted);
                    self.execution_dispositions
                        .insert(id.clone(), ExecutionDisposition::ApprovedReady);
                    self.notice = Some(Notice::info(format!("approval accepted for {id}")));
                } else {
                    self.approval_dispositions
                        .insert(id.clone(), ApprovalDisposition::SubmittedUnknown);
                    self.notice = Some(Notice::error(format!(
                        "approval for {id}: outcome unconfirmed; refresh and reinspect"
                    )));
                }
            }
            Ok(ApprovalStart::NeedsReview(review)) => {
                let fields = review.preview().get("preview");
                let provenance = self.provenance_for(&id);
                self.review_context = Some(ReviewContext {
                    task_id: task,
                    proposal_id: id.clone(),
                    adoption_worker: self
                        .adoption_worker
                        .clone()
                        .unwrap_or_else(|| self.worker.clone()),
                    origin_worker: provenance.map(|p| p.worker.clone()),
                    originating_claim_generation: provenance.map(|p| p.claim_generation),
                    observed_claim_generation: self
                        .selected_task()
                        .and_then(|t| t.get("claim_generation"))
                        .and_then(Value::as_i64),
                    proposal_status: fields
                        .and_then(|p| p.get("status"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    attempt_no: fields
                        .and_then(|p| p.get("attempt_no"))
                        .and_then(Value::as_u64),
                    step_no: fields
                        .and_then(|p| p.get("step_no"))
                        .and_then(Value::as_u64),
                });
                self.approval_dispositions
                    .insert(id.clone(), ApprovalDisposition::NotAccepted);
                self.review_hidden = false;
                self.notice = Some(Notice::info(format!(
                    "review required for {id}: confirm the disclosure explicitly"
                )));
                self.review = Some(review);
            }
            Err(failure) => self.apply_approval_failure(&id, &failure),
        }
    }

    fn apply_approval_failure(&mut self, id: &str, failure: &ApprovalFailure) {
        if failure.stage == ApprovalStage::ApprovalSubmission {
            match failure.origin {
                ApprovalFailureOrigin::Refusal => {
                    self.approval_dispositions
                        .insert(id.to_owned(), ApprovalDisposition::Refused);
                    self.notice = Some(approval_failure_notice(id, &failure.error));
                    return;
                }
                ApprovalFailureOrigin::RequestEncoding
                | ApprovalFailureOrigin::PreSendUnavailable
                | ApprovalFailureOrigin::LocalValidation => {
                    self.notice = Some(Notice::error(format!(
                        "approval for {id} was NOT submitted: {}; you may retry",
                        failure.error
                    )));
                    return;
                }
                ApprovalFailureOrigin::Transport
                | ApprovalFailureOrigin::ResponseDecoding
                | ApprovalFailureOrigin::Unknown => {
                    self.approval_dispositions
                        .insert(id.to_owned(), ApprovalDisposition::SubmittedUnknown);
                    self.notice = Some(Notice::error(format!(
                        "approval for {id}: outcome unknown; do NOT submit again; refresh and reinspect"
                    )));
                    return;
                }
            }
        }
        self.notice = Some(Notice::error(format!(
            "review for {id} was not completed: {}",
            failure.error
        )));
    }

    /// Records a renderer-derived geometry measurement for the open review.
    ///
    /// The event loop is the only production caller. UI actions never call it, and
    /// callers cannot pass an arbitrary boolean: eligibility is computed by
    /// [`ReviewGeometry::from_measurement`] from actual dimensions.
    pub fn set_review_geometry(&mut self, geometry: ReviewGeometry) {
        self.review_displayable = geometry.fits;
    }

    /// Whether the open review is fully displayed and may be confirmed.
    ///
    /// Read-only: rendering uses this to avoid advertising a disabled action.
    #[must_use]
    pub fn review_is_displayable(&self) -> bool {
        self.review.is_some() && !self.review_hidden && self.review_displayable
    }

    /// Whether the review pane should currently be drawn.
    #[must_use]
    pub fn review_is_visible(&self) -> bool {
        self.review.is_some() && !self.review_hidden
    }

    /// Why confirmation is unavailable, when it is.
    ///
    /// Distinguishes a geometry problem (resizing can help) from an incomplete
    /// disclosure (resizing cannot). Never returns a reason when confirmation is
    /// available.
    #[must_use]
    pub fn review_confirmation_reason(&self) -> Option<&'static str> {
        let review = self.review.as_ref()?;
        if self.review_displayable {
            return None;
        }
        if orxnuctl::task::disclosure_prose_complete(review.preview()) {
            Some("the review does not fit on screen (resize to show it fully)")
        } else {
            Some("the disclosure is incomplete (resizing cannot fix this)")
        }
    }

    /// Hide the open review without consuming it or its challenge.
    pub fn hide_review(&mut self) {
        if self.review.is_some() {
            self.review_hidden = true;
            self.notice = Some(Notice::info(
                "review hidden; its context is last-known; press a to reopen",
            ));
        }
    }

    /// Reopen the still-valid hidden review without issuing any RPC.
    pub fn reopen_review(&mut self) -> bool {
        if self.review.is_none() || !self.review_hidden {
            return false;
        }
        if !self.review_context_matches() {
            self.clear_active_context();
            self.notice = Some(Notice::error(
                "the hidden review's context changed; re-preview the proposal",
            ));
            return false;
        }
        self.review_hidden = false;
        self.notice = Some(Notice::info(
            "review reopened (last-known context); decline or confirm",
        ));
        true
    }

    fn review_context_matches(&self) -> bool {
        let Some(ctx) = &self.review_context else {
            return false;
        };
        let Some(review) = &self.review else {
            return false;
        };
        ctx.proposal_id == review.proposal_id()
            && self.selected_task_id().as_deref() == Some(ctx.task_id.as_str())
            && ctx.adoption_worker == self.worker
            && ctx.origin_worker.as_ref().is_none_or(|w| w == &self.worker)
            && ctx.observed_claim_generation.is_none_or(|observed| {
                ctx.originating_claim_generation
                    .is_none_or(|origin| origin == observed)
            })
    }

    /// Finish the open review. A decline submits no approval at all.
    pub fn decide_review(&mut self, confirmed: bool) {
        // A missing review takes precedence: `y` with no review must not be reported
        // as a geometry failure.
        if self.review.is_none() {
            self.notice = Some(Notice::error("no review is open"));
            return;
        }
        let proposal_id = self
            .review
            .as_ref()
            .map_or_else(|| "unknown".to_owned(), |r| r.proposal_id().to_owned());
        if confirmed {
            if self.review_hidden {
                self.notice = Some(Notice::error(
                    "the review is hidden; press a to reopen before confirming",
                ));
                return;
            }
            if !self.review_displayable {
                self.notice = Some(Notice::error(format!(
                    "approval for {proposal_id} was NOT submitted: the review did not fit on screen. \
                     Resize so the whole review is visible (wider and/or taller) or decline with d, \
                     then reinspect before retrying."
                )));
                return;
            }
            if !self.review_context_matches() {
                self.clear_active_context();
                self.notice = Some(Notice::error(format!(
                    "approval for {proposal_id} was NOT submitted: its review context changed; \
                     re-preview and reinspect before retrying"
                )));
                return;
            }
        }
        let Some(review) = self.review.take() else {
            self.notice = Some(Notice::error("no review is open"));
            return;
        };
        self.review_hidden = false;
        self.review_context = None;
        if !confirmed {
            self.notice = Some(Notice::info("declined: nothing was approved"));
            return;
        }
        match approval::submit_review_staged(&self.client, review, true) {
            Ok(Some(reply)) => {
                if approval_accepted(&reply, &proposal_id) {
                    self.approval_dispositions
                        .insert(proposal_id.clone(), ApprovalDisposition::Accepted);
                    self.execution_dispositions
                        .insert(proposal_id.clone(), ExecutionDisposition::ApprovedReady);
                    self.notice =
                        Some(Notice::info(format!("approval accepted for {proposal_id}")));
                } else {
                    self.approval_dispositions
                        .insert(proposal_id.clone(), ApprovalDisposition::SubmittedUnknown);
                    self.notice = Some(Notice::error(format!(
                        "approval for {proposal_id}: outcome unconfirmed; refresh and reinspect"
                    )));
                }
            }
            Ok(None) => self.notice = Some(Notice::info("declined: nothing was approved")),
            Err(failure) => self.apply_approval_failure(&proposal_id, &failure),
        }
    }

    /// Execute the proposal currently previewed, and display the daemon's verdict.
    ///
    /// The three flags are copied verbatim. The TUI does not decide that `verified`
    /// means success: a governed read that did not verify is exactly the state the
    /// operator must see as unresolved.
    pub fn execute_previewed(&mut self) {
        if self.reject_while_review_open("executing a proposal") {
            return;
        }
        let Some(task) = self.selected_task_id() else {
            self.notice = Some(Notice::error("select a task before executing"));
            return;
        };
        let Some(id) = self.active_preview_id() else {
            self.notice = Some(Notice::error("preview a proposal before executing it"));
            return;
        };
        let id = id.to_owned();
        if self
            .adoption_worker
            .as_deref()
            .is_some_and(|worker| worker != self.worker.as_str())
        {
            self.notice = Some(Notice::error(
                "the worker changed since this preview was adopted; re-preview it",
            ));
            return;
        }
        if let Some(origin) = self.provenance_for(&id)
            && origin.worker != self.worker
        {
            self.notice = Some(Notice::error(format!(
                "proposal {id} belongs to worker {}; switch back before executing",
                origin.worker
            )));
            return;
        }
        if self.approval_dispositions.get(&id) != Some(&ApprovalDisposition::Accepted) {
            self.notice = Some(Notice::error(
                "a validated approval is required before executing this proposal",
            ));
            return;
        }
        if self.no_replay(&id) {
            self.notice = Some(Notice::error(format!(
                "execution for {id} has an unresolved outcome; do not replay it; refresh and reinspect"
            )));
            return;
        }
        match self.client.call(
            "task/execute",
            json!({ "proposal": id, "worker": self.worker }),
        ) {
            Ok(reply) if valid_execution_result(&reply, &id, &task) => {
                self.execution_results.insert(id.clone(), reply.clone());
                self.execution_dispositions
                    .insert(id.clone(), ExecutionDisposition::ResultReceived);
                self.approval_dispositions
                    .insert(id.clone(), ApprovalDisposition::NotAccepted);
                self.verdict = Some(execution_verdict(&reply));
                self.notice = Some(Notice::info(format!("execution returned for {id}")));
            }
            Ok(_) => {
                self.execution_dispositions
                    .insert(id.clone(), ExecutionDisposition::OutcomeUnknown);
                self.notice = Some(Notice::error(format!(
                    "execution for {id}: outcome unconfirmed; do not replay; refresh and reinspect"
                )));
            }
            Err(e) => {
                let disposition = match &e {
                    ClientError::Unavailable { .. }
                    | ClientError::InvalidParams { .. }
                    | ClientError::VersionMismatch { .. } => ExecutionDisposition::NoEffectConsumed,
                    ClientError::Refused { reason, .. }
                        if matches!(
                            reason.as_deref(),
                            Some("approval-required")
                                | Some("approval-expired")
                                | Some("proposal-not-found")
                                | Some("read-not-authorized")
                        ) =>
                    {
                        ExecutionDisposition::NoEffectConsumed
                    }
                    ClientError::Refused { .. } => ExecutionDisposition::RefusedEffectPossible,
                    ClientError::Transport(_) | ClientError::Malformed(_) => {
                        ExecutionDisposition::OutcomeUnknown
                    }
                };
                self.execution_dispositions.insert(id.clone(), disposition);
                self.notice = Some(Notice::error(format!("execute: {e}")));
            }
        }
    }

    /// Report a completion for the claimed task, using that claim's generation.
    pub fn complete_selected(&mut self) {
        if self.reject_while_review_open("completing a task") {
            return;
        }
        let Some(id) = self.selected_task_id() else {
            self.notice = Some(Notice::error("select a task before completing it"));
            return;
        };
        let Some(generation) = self.claim_for(&id).map(|c| c.generation) else {
            self.notice = Some(Notice::error(
                "claim this task with the current worker before completing it",
            ));
            return;
        };
        match self.client.call(
            "task/complete",
            json!({ "id": id, "worker": self.worker, "claim_generation": generation }),
        ) {
            Ok(reply) => {
                let task = reply.get("task").and_then(Value::as_object);
                let returned_id = task
                    .and_then(|t| t.get("id"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty());
                let state = task
                    .and_then(|t| t.get("state"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty());
                let confirmed = match (returned_id, state) {
                    (Some(returned_id), Some("completed")) if returned_id == id => {
                        Some(returned_id.to_owned())
                    }
                    _ => None,
                };
                let Some(returned_id) = confirmed else {
                    let partial = match state {
                        Some(state) => format!(
                            "Unexpected reply (state: {state}); unconfirmed; may be completed; \
                             reclaim; press r to inspect."
                        ),
                        None => "Unexpected reply; unconfirmed; may be completed; reclaim; \
                                 press r to inspect."
                            .to_owned(),
                    };
                    self.claim = None;
                    self.notice = Some(Notice::error(partial));
                    return;
                };
                self.claim = None;
                match self.refresh_outcome() {
                    RefreshOutcome::Refreshed => {
                        self.notice = Some(Notice::info(format!(
                            "Task {returned_id} marked completed; effect not verified; \
                             task list refreshed."
                        )));
                    }
                    RefreshOutcome::StatusFailed => {
                        self.notice = Some(Notice::error(format!(
                            "Task {returned_id} marked completed; effect not verified; \
                             status refresh failed; may be stale; press r."
                        )));
                    }
                    RefreshOutcome::TaskListFailed => {
                        self.notice = Some(Notice::error(format!(
                            "Task {returned_id} marked completed; effect not verified; \
                             list refresh failed; may be stale; press r."
                        )));
                    }
                }
            }
            Err(e) => self.notice = Some(Notice::error(format!("complete: {e}"))),
        }
    }

    /// Cancel the selected task and display the daemon's actual answer.
    ///
    /// The daemon decides whether the task was cancelled or was already terminal. A
    /// local "cancelled" wording would be a lie for an already-completed task.
    pub fn cancel_selected(&mut self) {
        if self.reject_while_review_open("cancelling a task") {
            return;
        }
        let Some(id) = self.selected_task_id() else {
            self.notice = Some(Notice::error("select a task before cancelling it"));
            return;
        };
        match self.client.call("task/cancel", json!({ "id": id })) {
            Ok(reply) => {
                let task = reply.get("task").and_then(Value::as_object);
                let returned_id = task
                    .and_then(|t| t.get("id"))
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty());
                let state = task
                    .and_then(|t| t.get("state"))
                    .and_then(Value::as_str)
                    .filter(|value| KNOWN_TASK_STATES.contains(value));
                let cancelled = reply.get("cancelled").and_then(Value::as_bool);
                let valid = match (returned_id, state, cancelled) {
                    (Some(returned_id), Some(state), Some(cancelled))
                        if returned_id == id && cancelled == (state == "cancelled") =>
                    {
                        Some((returned_id.to_owned(), state, cancelled))
                    }
                    _ => None,
                };
                let Some((returned_id, state, cancelled)) = valid else {
                    let partial = state.map_or_else(
                        || {
                            "Outcome unconfirmed; cancellation may have succeeded; \
                             press r to inspect."
                                .to_owned()
                        },
                        |state| {
                            format!(
                                "Outcome unconfirmed (state: {state}); cancellation may \
                                 have succeeded; press r."
                            )
                        },
                    );
                    self.claim = None;
                    self.notice = Some(Notice::error(partial));
                    return;
                };
                self.claim = None;
                let shown_id = display_task_id(&returned_id);
                let outcome = if cancelled {
                    format!(
                        "{shown_id} cancelled; in-flight work may continue; effects not reversed"
                    )
                } else {
                    format!("{shown_id} unchanged; state {state}; no cancellation")
                };
                match self.refresh_outcome() {
                    RefreshOutcome::Refreshed => {
                        self.notice =
                            Some(Notice::info(format!("{outcome}; task list refreshed.")));
                    }
                    RefreshOutcome::StatusFailed => {
                        self.notice =
                            Some(Notice::error(format!("{outcome}; status failed; stale; r")));
                    }
                    RefreshOutcome::TaskListFailed => {
                        self.notice =
                            Some(Notice::error(format!("{outcome}; list failed; stale; r")));
                    }
                }
            }
            Err(e) => self.notice = Some(Notice::error(format!("cancel: {e}"))),
        }
    }
}

impl App<Client> {
    /// Connect to the default local endpoint. Nothing is sent until `refresh`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_client(Client::with_default_endpoint())
    }
}

/// Classifies a failed approval submission by what the exchange actually proves.
///
/// `Refused` is a definite daemon answer. `Unavailable`, `InvalidParams` and
/// `VersionMismatch` happen before a request reaches the approval handler. `Transport`
/// and `Malformed` are conservative "unknown": the client cannot tell whether the
/// write reached the daemon, and the daemon redeems the challenge before it replies.
/// Those errors are never retried here; the operator must reinspect first.
fn approval_failure_notice(proposal_id: &str, error: &ClientError) -> Notice {
    match error {
        ClientError::Refused {
            message, reason, ..
        } => {
            let detail = reason.as_deref().unwrap_or(message.as_str());
            Notice::error(format!(
                "approval refused by the daemon for {proposal_id}: {detail}"
            ))
        }
        ClientError::Unavailable { .. } => Notice::error(format!(
            "approval for {proposal_id} was NOT submitted: the daemon is unreachable. \
             Reinspect the proposal before deciding."
        )),
        ClientError::InvalidParams { detail } => Notice::error(format!(
            "approval for {proposal_id} was NOT submitted: invalid request ({detail}). \
             Reinspect the proposal before deciding."
        )),
        ClientError::VersionMismatch { .. } => Notice::error(format!(
            "approval for {proposal_id} was NOT submitted: protocol version mismatch. \
             Reinspect the proposal before deciding."
        )),
        ClientError::Transport(_) | ClientError::Malformed(_) => Notice::error(format!(
            "APPROVAL OUTCOME UNKNOWN for {proposal_id}: the daemon may have accepted the \
             request, but the client could not confirm the result. Do NOT issue another \
             approval. Refresh and reinspect the proposal and task state first."
        )),
    }
}

/// The id of a proposal returned for a specific task.
///
/// Both fields come from the daemon's `proposal_json`. Requiring the task to match
/// prevents a reply for another task from being bound to the current task/worker
/// context; the daemon remains authoritative for the approval itself.
fn proposal_for_task(reply: &Value, task: &str) -> Option<String> {
    let proposal = reply.get("proposal")?;
    let id = proposal.get("proposal_id")?.as_str()?;
    if proposal.get("task_id")?.as_str()? != task {
        return None;
    }
    Some(id.to_owned())
}

fn display_task_id(id: &str) -> String {
    let safe = approval::safe_text(id);
    if safe.chars().count() <= 8 {
        return safe;
    }
    let chars: Vec<char> = safe.chars().collect();
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[chars.len() - 3..].iter().collect();
    format!("{prefix}…{suffix}")
}

/// Pull the `tasks` array out of a `task/list` reply.
fn task_array(reply: &Value) -> Vec<Value> {
    reply
        .get("tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Copy the daemon's execution result out of a `task/execute` reply.
///
fn valid_execution_result(reply: &Value, id: &str, task: &str) -> bool {
    for key in [
        "proposal",
        "verified",
        "refuted",
        "undetermined",
        "result",
        "uncertainty",
        "task",
        "step",
    ] {
        if reply.get(key).is_none() {
            return false;
        }
    }
    let Some(proposal) = reply.get("proposal").and_then(Value::as_object) else {
        return false;
    };
    if proposal.get("proposal_id").and_then(Value::as_str) != Some(id)
        || proposal.get("task_id").and_then(Value::as_str) != Some(task)
        || proposal.get("attempt_no").and_then(Value::as_u64).is_none()
        || proposal.get("status").and_then(Value::as_str).is_none()
    {
        return false;
    }
    let flags: Vec<bool> = ["verified", "refuted", "undetermined"]
        .iter()
        .filter_map(|key| reply.get(*key).and_then(Value::as_bool))
        .collect();
    if flags.len() != 3 || flags.iter().filter(|flag| **flag).count() != 1 {
        return false;
    }
    if reply
        .get("result")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return false;
    }
    if let Some(uncertainty) = reply.get("uncertainty")
        && !uncertainty.is_null()
    {
        let Some(u) = uncertainty.as_object() else {
            return false;
        };
        if u.get("settled").and_then(Value::as_bool).is_none()
            || u.get("task_state")
                .and_then(Value::as_str)
                .is_none_or(|state| !KNOWN_TASK_STATES.contains(&state))
            || u.get("awaiting").and_then(Value::as_str).is_none()
        {
            return false;
        }
    }
    if let Some(task_value) = reply.get("task")
        && !task_value.is_null()
    {
        let Some(row) = task_value.as_object() else {
            return false;
        };
        if row.get("id").and_then(Value::as_str) != Some(task)
            || row
                .get("state")
                .and_then(Value::as_str)
                .is_none_or(|state| !KNOWN_TASK_STATES.contains(&state))
        {
            return false;
        }
    }
    if let Some(step) = reply.get("step")
        && !step.is_null()
    {
        let Some(s) = step.as_object() else {
            return false;
        };
        for key in ["completed", "steps_completed", "max_steps", "next_step"] {
            if s.get(key).and_then(Value::as_u64).is_none() {
                return false;
            }
        }
    }
    true
}

fn approval_accepted(reply: &Value, id: &str) -> bool {
    let Some(approval) = reply.get("approval").and_then(Value::as_object) else {
        return false;
    };
    let Some(digest) = approval.get("digest").and_then(Value::as_str) else {
        return false;
    };
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let Some(proposal) = reply.get("proposal").and_then(Value::as_object) else {
        return false;
    };
    proposal.get("proposal_id").and_then(Value::as_str) == Some(id)
        && proposal.get("status").and_then(Value::as_str) == Some("approved")
}

/// Missing fields stay missing; they are never defaulted, because a reply this build
/// does not understand must not be rendered as "nothing happened". The `uncertainty`
/// object is kept verbatim: it is how the daemon says the task stopped and is waiting
/// for a person, and it must be visible without polling `task/list`.
pub fn execution_verdict(reply: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for key in [
        "verified",
        "refuted",
        "undetermined",
        "result",
        "uncertainty",
        "task",
    ] {
        if let Some(v) = reply.get(key) {
            out.insert(key.to_owned(), v.clone());
        }
    }
    Value::Object(out)
}

impl Default for App<Client> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeRpc {
        calls: Mutex<Vec<(String, Value)>>,
        replies: Mutex<Vec<Result<Value, ClientError>>>,
    }

    impl FakeRpc {
        fn new(replies: Vec<Result<Value, ClientError>>) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                replies: Mutex::new(replies),
            }
        }
        fn calls(&self) -> Vec<(String, Value)> {
            self.calls.lock().expect("lock").clone()
        }
        fn methods(&self) -> Vec<String> {
            self.calls().into_iter().map(|(m, _)| m).collect()
        }
    }

    impl PreviewRequests for FakeRpc {
        fn call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
            self.calls
                .lock()
                .expect("lock")
                .push((method.to_owned(), params));
            let mut replies = self.replies.lock().expect("lock");
            if replies.is_empty() {
                return Err(ClientError::Malformed("no reply configured".to_owned()));
            }
            replies.remove(0)
        }
    }

    impl Rpc for FakeRpc {
        fn negotiate(&self) -> Result<u16, ClientError> {
            Ok(1)
        }
        fn endpoint(&self) -> &Path {
            Path::new("/tmp/orxnu-tui-test.sock")
        }
    }

    impl App<FakeRpc> {
        fn calls(&self) -> Vec<(String, Value)> {
            self.client.calls()
        }
        fn methods(&self) -> Vec<String> {
            self.client.methods()
        }
    }

    fn fitting_geometry() -> ReviewGeometry {
        ReviewGeometry::from_measurement(160, 13, 12)
    }

    fn clipped_geometry() -> ReviewGeometry {
        ReviewGeometry::from_measurement(160, 12, 13)
    }

    fn app_with(replies: Vec<Result<Value, ClientError>>) -> App<FakeRpc> {
        let mut app = App::with_client(FakeRpc::new(replies));
        app.tasks = vec![json!({"id": "t1", "state": "pending"})];
        app
    }

    fn with_task(app: &mut App<FakeRpc>, id: &str) {
        app.tasks = vec![json!({"id": id, "state": "pending"})];
        app.selected = 0;
    }

    fn app_with_claim(replies: Vec<Result<Value, ClientError>>) -> App<FakeRpc> {
        let mut all = vec![Ok(json!({
            "task": {"id": "t1"},
            "claim_generation": 7
        }))];
        all.extend(replies);
        let mut app = app_with(all);
        app.claim_selected();
        app
    }

    fn cancelled_reply(cancelled: bool, state: &str) -> Value {
        json!({
            "task": {
                "id": "t1",
                "kind": "query",
                "state": state,
                "priority": 0,
                "attempts": 1,
                "claim_generation": 7,
                "max_attempts": 3,
                "max_steps": 1,
                "steps_completed": 1,
                "content": "content",
                "idempotent": false,
                "effect_observed": true,
                "run_after_ms": 0,
                "created_at_ms": 0,
                "updated_at_ms": 0,
                "terminal_at_ms": 0,
                "dead_lettered_at_ms": null,
                "cancel_requested_at_ms": 0,
                "lease_holder": null,
                "lease_expires_at_ms": null,
                "schedule_id": null,
                "fire_time_ms": null,
                "last_error": null
            },
            "cancelled": cancelled
        })
    }

    fn completed_reply(id: &str, state: &str) -> Value {
        json!({
            "task": {
                "id": id,
                "kind": "query",
                "state": state,
                "priority": 0,
                "attempts": 1,
                "claim_generation": 7,
                "max_attempts": 3,
                "max_steps": 1,
                "steps_completed": 1,
                "content": "content",
                "idempotent": false,
                "effect_observed": true,
                "run_after_ms": 0,
                "created_at_ms": 0,
                "updated_at_ms": 0,
                "terminal_at_ms": 0,
                "dead_lettered_at_ms": null,
                "cancel_requested_at_ms": null,
                "lease_holder": null,
                "lease_expires_at_ms": null,
                "schedule_id": null,
                "fire_time_ms": null,
                "last_error": null
            }
        })
    }

    fn created_reply(id: &str) -> Value {
        json!({
            "task": {
                "id": id,
                "kind": "query",
                "state": "pending",
                "priority": 0,
                "attempts": 0,
                "claim_generation": 0,
                "max_attempts": 3,
                "max_steps": 1,
                "steps_completed": 0,
                "content": "content",
                "idempotent": false,
                "effect_observed": false,
                "run_after_ms": 0,
                "created_at_ms": 0,
                "updated_at_ms": 0,
                "terminal_at_ms": null,
                "dead_lettered_at_ms": null,
                "cancel_requested_at_ms": null,
                "lease_holder": null,
                "lease_expires_at_ms": null,
                "schedule_id": null,
                "fire_time_ms": null,
                "last_error": null
            }
        })
    }

    fn execution_reply(id: &str, verified: bool, refuted: bool, undetermined: bool) -> Value {
        json!({
            "proposal": {
                "proposal_id": id,
                "task_id": "t1",
                "attempt_no": 1,
                "status": "approved"
            },
            "verified": verified,
            "refuted": refuted,
            "undetermined": undetermined,
            "result": if verified { "verified" } else if refuted { "refuted" } else { "undetermined" },
            "uncertainty": Value::Null,
            "task": Value::Null,
            "step": Value::Null
        })
    }

    fn approved_reply(id: &str) -> Value {
        json!({
            "approval": { "digest": "a".repeat(64) },
            "proposal": {
                "proposal_id": id,
                "task_id": "t1",
                "attempt_no": 1,
                "status": "approved"
            }
        })
    }

    fn model_read(id: &str, kind: &str, requires: bool, challenge: Option<&str>) -> Value {
        let mut p = json!({
            "proposal_id": id,
            "task_id": "t1",
            "proposal_kind": kind,
            "requires_confirmation": requires,
            "operation": "file-read",
            "approval_allowed": true,
            "path": "src/main.rs",
            "recipient": "provider (model: m)",
            "disclosure": {
                "read_ceiling_bytes": 65536u64,
                "observation_ceiling_bytes": 32768u64,
                "max_entries": 8u64,
                "effective_bytes": 32768u64,
                "read_only": true,
                "disclosure_possible": true,
                "summary": "filesystem/read-text reads a file and does not write one.",
                "limits": "A read returns at most 65536 bytes. No observation is truncated.",
                "timing": "Eligibility is limited to the immediately following logical step."
            }
        });
        if let Some(c) = challenge {
            p["challenge"] = json!(c);
        }
        json!({ "preview": p })
    }

    #[test]
    fn task_array_reads_the_daemon_field_and_degrades_to_empty() {
        let good = json!({ "tasks": [{"id": "a"}, {"id": "b"}], "count": 2 });
        assert_eq!(task_array(&good).len(), 2);
        for bad in [
            json!({}),
            json!({ "tasks": null }),
            json!({ "tasks": "no" }),
        ] {
            assert!(task_array(&bad).is_empty(), "{bad}");
        }
    }

    #[test]
    fn the_verdict_copies_only_the_flags_the_daemon_sent() {
        let full = json!({ "verified": false, "refuted": false, "undetermined": true });
        let got = execution_verdict(&full);
        assert_eq!(got["undetermined"], true);
        assert_eq!(got["verified"], false);
        let partial = json!({ "verified": true, "other": 7 });
        let got = execution_verdict(&partial);
        assert_eq!(got["verified"], true);
        assert!(got.get("refuted").is_none());
        assert!(got.get("other").is_none());
    }

    #[test]
    fn an_uncertain_execution_result_is_visible_without_a_refresh() {
        let mut reply = execution_reply("p-1", false, false, true);
        reply["uncertainty"] = json!({
            "settled": false,
            "task_state": "needs-verification",
            "awaiting": "human-adjudication"
        });
        let mut app = app_with(vec![Ok(reply)]);
        app.preview_id = Some("p-1".to_owned());
        app.approval_dispositions
            .insert("p-1".to_owned(), ApprovalDisposition::Accepted);
        app.execution_dispositions
            .insert("p-1".to_owned(), ExecutionDisposition::ApprovedReady);
        app.execute_previewed();
        assert_eq!(
            app.methods(),
            vec!["task/execute"],
            "no refresh or other RPC"
        );
        let verdict = app.verdict.as_ref().expect("verdict");
        assert_eq!(
            verdict["uncertainty"]["task_state"],
            json!("needs-verification")
        );
        assert_eq!(
            verdict["uncertainty"]["awaiting"],
            json!("human-adjudication")
        );
        assert_eq!(
            verdict["verified"], false,
            "an uncertain result is not success"
        );
        assert!(verdict.get("nonsense").is_none());
    }

    #[test]
    fn selection_is_clamped_and_never_wraps() {
        let mut app = App::new();
        app.tasks = vec![json!({"id": "a"}), json!({"id": "b"}), json!({"id": "c"})];
        app.move_selection(-1);
        assert_eq!(app.selected, 0);
        app.move_selection(10);
        assert_eq!(app.selected, 2);
        app.move_selection(1);
        assert_eq!(app.selected, 2);
        app.tasks.clear();
        app.move_selection(1);
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn actions_require_a_preview_id() {
        let mut app = app_with(vec![]);
        app.request_approval();
        assert!(app.notice.as_ref().is_some_and(|n| n.is_error));
        app.notice = None;
        app.execute_previewed();
        assert!(app.notice.as_ref().is_some_and(|n| n.is_error));
        assert!(
            app.methods().is_empty(),
            "neither action may send an RPC without a preview id"
        );
    }

    #[test]
    fn input_acceptance_never_targets_a_different_id() {
        let mut app = app_with(vec![
            Ok(model_read("p-1", "direct-proposal", false, None)),
            Ok(model_read(
                "p-shown",
                "model-initiated-file-read",
                true,
                None,
            )),
            Ok(model_read(
                "p-shown",
                "model-initiated-file-read",
                true,
                Some("challenge-secret"),
            )),
        ]);
        app.begin_proposal_input();
        app.buffer = "p-1".to_owned();
        assert!(app.accept_input());
        assert_eq!(app.input, Input::None);
        assert!(app.buffer.is_empty());

        app.preview = None;
        app.preview_id = Some("p-shown".to_owned());
        app.request_approval();
        let calls = app.calls();
        assert_eq!(calls[1].0, "capability/preview");
        assert_eq!(
            calls[1].1["proposal"],
            json!("p-shown"),
            "the stored preview id, not the cleared buffer, names the action"
        );
        assert_eq!(
            app.review.as_ref().expect("review").proposal_id(),
            "p-shown"
        );
    }

    #[test]
    fn execution_verdict_preserves_result_uncertainty_and_task_without_defaults() {
        let reply = json!({
            "verified": false,
            "refuted": false,
            "undetermined": true,
            "result": "the effect could not be established (filesystem/read-text)",
            "uncertainty": {
                "settled": "unknown",
                "task_state": "needs-verification",
                "awaiting": "human-adjudication"
            },
            "task": { "id": "t1", "state": "needs-verification" },
            "unrelated": "not a verdict field"
        });
        let got = execution_verdict(&reply);
        assert_eq!(got["verified"], false);
        assert_eq!(got["refuted"], false);
        assert_eq!(got["undetermined"], true);
        assert_eq!(
            got["result"],
            json!("the effect could not be established (filesystem/read-text)")
        );
        assert_eq!(got["uncertainty"]["settled"], json!("unknown"));
        assert_eq!(
            got["uncertainty"]["task_state"],
            json!("needs-verification")
        );
        assert_eq!(got["uncertainty"]["awaiting"], json!("human-adjudication"));
        assert_eq!(got["task"]["id"], json!("t1"));
        assert_eq!(got["task"]["state"], json!("needs-verification"));
        assert!(
            got.get("unrelated").is_none(),
            "unrelated fields are not copied"
        );
        assert!(got.get("verified_at").is_none(), "no field is inferred");

        let minimal = execution_verdict(&json!({ "verified": true }));
        assert_eq!(minimal["verified"], true);
        assert!(
            minimal.get("result").is_none(),
            "a missing result stays missing"
        );
        assert!(
            minimal.get("uncertainty").is_none(),
            "uncertainty is not invented"
        );
        assert!(minimal.get("task").is_none(), "task is not invented");
        assert!(
            minimal.get("refuted").is_none(),
            "a missing flag is not false"
        );
    }

    #[test]
    fn a_missing_or_malformed_claim_generation_prevents_bound_operations() {
        for reply in [
            Ok(json!({ "task": { "id": "t1" } })),
            Ok(json!({ "task": { "id": "t1" }, "claim_generation": "7" })),
        ] {
            let mut app = app_with(vec![reply.clone()]);
            app.claim_selected();
            assert!(app.claim.is_none(), "{reply:?}");
            assert!(app.notice.as_ref().is_some_and(|n| n.is_error));
            app.ai_propose_selected();
            assert_eq!(
                app.methods(),
                vec!["task/claim"],
                "a claim-bound operation must not run without a retained generation"
            );
        }
    }

    #[test]
    fn the_generation_sent_is_exactly_the_one_the_claim_returned() {
        let mut app = app_with(vec![
            Ok(json!({ "task": { "id": "t1" }, "claim_generation": 7 })),
            Ok(json!({ "proposal": { "proposal_id": "p-1", "task_id": "t1" } })),
            Ok(completed_reply("t1", "completed")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": []})),
        ]);
        app.claim_selected();
        assert_eq!(app.claim.as_ref().expect("claim").generation, 7);
        app.ai_propose_selected();
        assert_eq!(app.preview_id.as_deref(), Some("p-1"));
        let calls = app.calls();
        assert_eq!(calls[1].0, "task/ai-propose");
        assert_eq!(calls[1].1["claim_generation"], json!(7));
        assert_eq!(calls[1].1["task"], json!("t1"));
        assert_eq!(calls[1].1["worker"], json!("tui"));
        app.complete_selected();
        let calls = app.calls();
        assert_eq!(calls[2].0, "task/complete");
        assert_eq!(calls[2].1["claim_generation"], json!(7));
    }

    #[test]
    fn changing_the_worker_or_task_cannot_reuse_a_claim() {
        let mut app = app_with(vec![Ok(
            json!({ "task": { "id": "t1" }, "claim_generation": 7 }),
        )]);
        app.claim_selected();
        app.worker = "other".to_owned();
        app.ai_propose_selected();
        assert_eq!(
            app.methods(),
            vec!["task/claim"],
            "a different worker must not reuse the generation"
        );

        let mut app = app_with(vec![Ok(
            json!({ "task": { "id": "t1" }, "claim_generation": 7 }),
        )]);
        app.claim_selected();
        with_task(&mut app, "t2");
        app.ai_propose_selected();
        assert_eq!(
            app.methods(),
            vec!["task/claim"],
            "a different task must not reuse the generation"
        );
    }

    #[test]
    fn the_reviewed_proposal_is_the_one_approved_and_executed() {
        let mut app = app_with(vec![
            Ok(model_read(
                "p-shown",
                "model-initiated-file-read",
                true,
                None,
            )),
            Ok(model_read(
                "p-shown",
                "model-initiated-file-read",
                true,
                Some("challenge-secret"),
            )),
            Ok(approved_reply("p-shown")),
            Ok(execution_reply("p-shown", true, false, false)),
        ]);
        app.preview = None;
        app.preview_id = Some("p-shown".to_owned());
        app.request_approval();
        app.set_review_geometry(fitting_geometry());
        let review = app.review.as_ref().expect("a review is required");
        assert_eq!(review.proposal_id(), "p-shown");
        assert!(
            !serde_json::to_string(review.preview())
                .expect("json")
                .contains("challenge-secret")
        );
        app.decide_review(true);
        let calls = app.calls();
        assert_eq!(calls[2].0, "capability/approve");
        assert_eq!(calls[2].1["proposal"], json!("p-shown"));
        assert_eq!(calls[2].1["challenge"], json!("challenge-secret"));
        assert_eq!(calls[2].1["confirmed"], true);
        app.execute_previewed();
        let calls = app.calls();
        assert_eq!(calls[3].0, "task/execute");
        assert_eq!(calls[3].1["proposal"], json!("p-shown"));
    }

    #[test]
    fn a_declined_model_read_submits_no_approval() {
        let mut app = app_with(vec![
            Ok(model_read("p-1", "model-initiated-file-read", true, None)),
            Ok(model_read(
                "p-1",
                "model-initiated-file-read",
                true,
                Some("challenge-secret"),
            )),
        ]);
        app.preview_id = Some("p-1".to_owned());
        app.request_approval();
        app.decide_review(false);
        assert_eq!(
            app.methods(),
            vec!["capability/preview", "capability/preview"]
        );
        assert!(
            app.notice
                .as_ref()
                .is_some_and(|n| n.text.contains("declined"))
        );
    }

    #[test]
    fn a_direct_proposal_is_approved_without_a_review() {
        let mut app = app_with(vec![
            Ok(model_read("p-1", "direct-proposal", false, None)),
            Ok(approved_reply("p-1")),
        ]);
        app.preview_id = Some("p-1".to_owned());
        app.request_approval();
        assert!(app.review.is_none());
        assert_eq!(
            app.methods(),
            vec!["capability/preview", "capability/approve"]
        );
    }

    #[test]
    fn cancellation_reports_the_daemons_answer_not_a_local_assumption() {
        let mut app = app_with_claim(vec![
            Ok(cancelled_reply(false, "completed")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": [{"id": "t1", "state": "completed"}]})),
        ]);
        app.cancel_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("unchanged"), "{notice}");
        assert!(notice.contains("completed"), "{notice}");
        assert!(notice.contains("no cancellation"), "{notice}");
        assert!(notice.contains("task list refreshed"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert!(app.claim.is_none());
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/cancel", "daemon/status", "task/list"]
        );
    }

    #[test]
    fn a_review_blocks_execution_until_it_is_decided() {
        let mut app = app_with(vec![
            Ok(model_read("p-1", "model-initiated-file-read", true, None)),
            Ok(model_read(
                "p-1",
                "model-initiated-file-read",
                true,
                Some("challenge-secret"),
            )),
            Ok(execution_reply("p-shown", true, false, false)),
        ]);
        app.preview_id = Some("p-1".to_owned());
        app.request_approval();
        app.execute_previewed();
        assert_eq!(
            app.methods(),
            vec!["capability/preview", "capability/preview"]
        );
        assert!(app.notice.as_ref().is_some_and(|n| n.is_error));
    }

    fn app_with_open_review() -> App<FakeRpc> {
        let mut app = app_with(vec![
            Ok(model_read("p-1", "model-initiated-file-read", true, None)),
            Ok(model_read(
                "p-1",
                "model-initiated-file-read",
                true,
                Some("challenge-secret"),
            )),
        ]);
        app.preview_id = Some("p-1".to_owned());
        app.request_approval();
        assert!(app.review.is_some(), "fixture must open a review");
        app
    }

    #[test]
    fn an_open_review_blocks_state_changing_operations_without_any_rpc() {
        let mut app = app_with_open_review();
        app.ai_propose_selected();
        app.create_task("t9", "content");
        app.claim_selected();
        app.complete_selected();
        app.cancel_selected();
        app.preview_proposal("p-other");
        app.request_approval();
        app.execute_previewed();
        assert_eq!(
            app.methods(),
            vec!["capability/preview", "capability/preview"],
            "only the two preview calls that opened the review may have been sent"
        );
        let review = app.review.as_ref().expect("review must survive");
        assert_eq!(review.proposal_id(), "p-1");
    }

    #[test]
    fn an_open_review_blocks_worker_change_and_creation_input() {
        let mut app = app_with_open_review();
        app.begin_worker_input();
        assert_eq!(
            app.input,
            Input::None,
            "worker input must not start mid-review"
        );
        app.buffer = "other".to_owned();
        assert!(
            !app.accept_input(),
            "no input is active, so nothing is accepted"
        );
        assert_eq!(app.worker, "tui", "worker must not change mid-review");
        app.begin_task_id_input();
        assert_eq!(
            app.input,
            Input::None,
            "task creation must not start mid-review"
        );
        assert!(app.review.is_some());
        assert_eq!(
            app.methods(),
            vec!["capability/preview", "capability/preview"]
        );
    }

    #[test]
    fn declining_the_review_allows_the_next_eligible_operation() {
        let mut app = app_with_open_review();
        app.decide_review(false);
        assert!(app.review.is_none());
        app.preview_proposal("p-2");
        assert_eq!(
            app.methods(),
            vec![
                "capability/preview",
                "capability/preview",
                "capability/preview"
            ]
        );
    }

    #[test]
    fn confirming_a_review_consumes_it_exactly_once() {
        let mut app = app_with(vec![
            Ok(model_read("p-1", "model-initiated-file-read", true, None)),
            Ok(model_read(
                "p-1",
                "model-initiated-file-read",
                true,
                Some("challenge-secret"),
            )),
            Ok(approved_reply("p-1")),
        ]);
        app.preview_id = Some("p-1".to_owned());
        app.request_approval();
        app.set_review_geometry(fitting_geometry());
        app.decide_review(true);
        assert!(app.review.is_none());
        app.decide_review(true);
        assert_eq!(
            app.methods(),
            vec![
                "capability/preview",
                "capability/preview",
                "capability/approve"
            ],
            "no second approval may be submitted"
        );
    }

    #[test]
    fn a_failed_second_claim_clears_the_stale_generation() {
        let mut app = app_with(vec![
            Ok(json!({ "task": { "id": "t1" }, "claim_generation": 7 })),
            Err(ClientError::Transport("daemon unavailable".to_owned())),
        ]);
        app.claim_selected();
        assert_eq!(app.claim.as_ref().expect("claim").generation, 7);
        app.claim_selected();
        assert!(
            app.claim.is_none(),
            "a failed claim must not leave a stale generation"
        );
        app.ai_propose_selected();
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/claim"],
            "no claim-bound RPC may run"
        );
    }

    #[test]
    fn creating_a_task_uses_the_production_input_transition_and_payload() {
        let mut app = app_with(vec![
            Ok(created_reply("t9")),
            Ok(json!({})),
            Ok(json!({ "tasks": [] })),
        ]);
        app.begin_task_id_input();
        app.buffer = "t9".to_owned();
        assert!(app.accept_input());
        assert_eq!(app.input, Input::TaskContent);
        app.buffer = "do the thing".to_owned();
        assert!(app.accept_input());
        let calls = app.calls();
        assert_eq!(calls[0].0, "task/create");
        assert_eq!(calls[0].1, json!({ "id": "t9", "content": "do the thing" }));
    }

    fn review_with_approval_reply(reply: Result<Value, ClientError>) -> App<FakeRpc> {
        let mut app = app_with(vec![
            Ok(model_read("p-1", "model-initiated-file-read", true, None)),
            Ok(model_read(
                "p-1",
                "model-initiated-file-read",
                true,
                Some("challenge-secret"),
            )),
            reply,
        ]);
        app.preview_id = Some("p-1".to_owned());
        app.request_approval();
        assert!(app.review.is_some());
        app.set_review_geometry(fitting_geometry());
        app
    }

    #[test]
    fn approval_success_consumes_the_review_once_and_reports_the_proposal() {
        let mut app = review_with_approval_reply(Ok(approved_reply("p-1")));
        app.decide_review(true);
        assert!(app.review.is_none());
        let notice = app.notice.as_ref().expect("notice").text.clone();
        assert!(notice.contains("p-1"), "{notice}");
        assert!(notice.contains("accepted"), "{notice}");
        assert_eq!(
            app.methods(),
            vec![
                "capability/preview",
                "capability/preview",
                "capability/approve"
            ]
        );
    }

    #[test]
    fn a_daemon_refusal_is_reported_as_a_refusal_not_an_unknown_outcome() {
        let mut app = review_with_approval_reply(Err(ClientError::Refused {
            code: -32042,
            message: "approval refused".to_owned(),
            reason: Some("approval-expired".to_owned()),
            detail: None,
        }));
        app.decide_review(true);
        assert!(app.review.is_none());
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("refused"), "{notice}");
        assert!(notice.contains("approval-expired"), "{notice}");
        assert!(!notice.contains("UNKNOWN"), "{notice}");
    }

    #[test]
    fn an_ambiguous_transport_failure_consumes_the_review_without_a_second_rpc() {
        let mut app =
            review_with_approval_reply(Err(ClientError::Transport("peer disconnected".to_owned())));
        app.decide_review(true);
        assert!(
            app.review.is_none(),
            "the review must not be retried or restored"
        );
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("outcome unknown"), "{notice}");
        assert!(notice.contains("do NOT submit again"), "{notice}");
        assert!(notice.contains("refresh and reinspect"), "{notice}");
        assert!(!notice.contains("issued"), "{notice}");
        assert!(!notice.contains("refused"), "{notice}");
        assert!(
            !notice.contains("challenge-secret"),
            "no challenge in a notice: {notice}"
        );
        assert_eq!(
            app.methods(),
            vec![
                "capability/preview",
                "capability/preview",
                "capability/approve"
            ],
            "no automatic second approval"
        );
    }

    #[test]
    fn a_malformed_response_is_classified_conservatively() {
        let mut app = review_with_approval_reply(Err(ClientError::Malformed(
            "reply was not JSON-RPC".to_owned(),
        )));
        app.decide_review(true);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("outcome unknown"), "{notice}");
        assert!(app.review.is_none());
    }

    #[test]
    fn an_unreachable_daemon_is_not_reported_as_an_unknown_outcome() {
        let mut app = review_with_approval_reply(Err(ClientError::Unavailable {
            endpoint: "/tmp/sock".to_owned(),
            reason: " connection refused".to_owned(),
        }));
        app.decide_review(true);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("NOT submitted"), "{notice}");
        assert!(!notice.contains("OUTCOME UNKNOWN"), "{notice}");
    }

    #[test]
    fn refresh_remains_available_after_an_ambiguous_approval() {
        let mut app = review_with_approval_reply(Err(ClientError::Transport("lost".to_owned())));
        app.client
            .replies
            .lock()
            .expect("lock")
            .push(Ok(json!({ "status": "running" })));
        app.client
            .replies
            .lock()
            .expect("lock")
            .push(Ok(json!({ "tasks": [] })));
        app.decide_review(true);
        app.refresh();
        let methods = app.methods();
        assert!(methods.contains(&"daemon/status".to_owned()), "{methods:?}");
        assert!(methods.contains(&"task/list".to_owned()), "{methods:?}");
    }

    #[test]
    fn confirmation_is_refused_when_the_review_does_not_fit_but_decline_still_works() {
        let mut app = app_with_open_review();
        app.set_review_geometry(clipped_geometry());
        app.decide_review(true);
        assert!(
            app.review.is_some(),
            "an unseen review must not be consumed"
        );
        assert_eq!(
            app.methods(),
            vec!["capability/preview", "capability/preview"]
        );
        assert!(
            app.notice
                .as_ref()
                .is_some_and(|n| n.text.contains("NOT submitted"))
        );
        app.decide_review(false);
        assert!(app.review.is_none(), "decline is always the safe exit");
    }

    #[test]
    fn proposal_id_input_is_guarded_while_a_review_is_open() {
        let mut app = app_with_open_review();
        app.begin_proposal_input();
        assert_eq!(app.input, Input::None);
        assert!(app.review.is_some());
        assert_eq!(
            app.methods(),
            vec!["capability/preview", "capability/preview"]
        );
    }

    #[test]
    fn a_direct_confirmation_is_refused_until_geometry_is_evaluated() {
        let mut app = app_with_open_review();
        app.decide_review(true);
        assert!(
            app.review.is_some(),
            "an unmeasured review must never be confirmable"
        );
        assert_eq!(
            app.methods(),
            vec!["capability/preview", "capability/preview"],
            "no approval RPC may have been sent"
        );
        assert!(
            app.notice
                .as_ref()
                .is_some_and(|n| n.text.contains("did not fit"))
        );

        app.client
            .replies
            .lock()
            .expect("lock")
            .push(Ok(approved_reply("p-1")));
        app.set_review_geometry(fitting_geometry());
        app.decide_review(true);
        assert!(app.review.is_none());
        assert_eq!(
            app.methods().last().map(String::as_str),
            Some("capability/approve")
        );
    }

    #[test]
    fn a_preview_reply_for_another_proposal_is_not_adopted() {
        let mut app = app_with(vec![Ok(model_read(
            "p-other",
            "direct-proposal",
            false,
            None,
        ))]);
        app.preview_proposal("p-1");
        assert!(
            app.preview.is_none(),
            "a mismatched preview must not be displayed"
        );
        assert!(
            app.preview_id.is_none(),
            "a mismatched preview must not bind an id"
        );
        assert!(
            app.notice
                .as_ref()
                .is_some_and(|n| n.text.contains("p-other")),
            "the operator must be told why it was refused"
        );
        assert_eq!(app.methods(), vec!["capability/preview"]);
    }

    #[test]
    fn an_ai_proposal_reply_for_another_task_is_not_adopted() {
        let mut app = app_with(vec![
            Ok(json!({ "task": { "id": "t1" }, "claim_generation": 7 })),
            Ok(json!({ "proposal": { "proposal_id": "p-other", "task_id": "t2" } })),
        ]);
        app.claim_selected();
        app.ai_propose_selected();
        assert!(
            app.preview_id.is_none(),
            "a proposal for another task must not bind"
        );
        assert!(
            app.notice
                .as_ref()
                .is_some_and(|n| n.text.contains("this task")),
            "the notice must explain the rejection"
        );
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/ai-propose"],
            "no approval or execution may follow a rejected proposal"
        );
    }

    #[test]
    fn an_ai_proposal_reply_without_a_task_id_is_not_adopted() {
        let mut app = app_with(vec![
            Ok(json!({ "task": { "id": "t1" }, "claim_generation": 7 })),
            Ok(json!({ "proposal": { "proposal_id": "p-1" } })),
        ]);
        app.claim_selected();
        app.ai_propose_selected();
        assert!(app.preview_id.is_none());
        assert_eq!(app.methods(), vec!["task/claim", "task/ai-propose"]);
    }

    #[test]
    fn successful_create_with_production_shape_is_reported_from_daemon_fields() {
        assert!(created_reply("t9")["task"].get("created").is_none());
        let mut app = app_with(vec![
            Ok(created_reply("t9")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": [{"id": "t9", "state": "pending"}]})),
        ]);
        app.create_task("t9", "content");
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("t9"), "{notice}");
        assert!(notice.contains("pending"), "{notice}");
        assert!(notice.contains("created successfully"), "{notice}");
        assert!(notice.contains("task list refreshed"), "{notice}");
        assert!(!notice.contains("created="), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert_eq!(
            app.methods(),
            vec!["task/create", "daemon/status", "task/list"]
        );
    }

    #[test]
    fn malformed_create_reply_is_not_reported_as_success() {
        for (reply, partial_state) in [
            (json!({}), None),
            (json!({"task": null}), None),
            (json!({"task": {"state": "pending"}}), Some("pending")),
            (
                json!({"task": {"id": "", "state": "pending"}}),
                Some("pending"),
            ),
        ] {
            let mut app = app_with(vec![Ok(reply.clone())]);
            app.create_task("t9", "content");
            let notice = &app.notice.as_ref().expect("notice").text;
            assert!(app.notice.as_ref().expect("notice").is_error, "{notice}");
            assert!(notice.contains("unconfirmed"), "{notice}");
            assert!(notice.contains("may already exist"), "{notice}");
            assert!(notice.contains("press r"), "{notice}");
            assert!(notice.chars().count() <= 96, "footer bound: {notice}");
            assert!(!notice.contains("created successfully"), "{notice}");
            if let Some(state) = partial_state {
                assert!(notice.contains(state), "{notice}");
            }
            assert_eq!(
                app.methods(),
                vec!["task/create"],
                "a malformed reply must not trigger another create or a refresh: {notice}"
            );
        }
    }

    #[test]
    fn create_success_with_failed_daemon_status_refresh_preserves_outcome() {
        let mut app = app_with(vec![
            Ok(created_reply("t9")),
            Err(ClientError::Malformed("status unavailable".to_owned())),
        ]);
        app.create_task("t9", "content");
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("t9"), "{notice}");
        assert!(notice.contains("pending"), "{notice}");
        assert!(notice.contains("status refresh failed"), "{notice}");
        assert!(notice.contains("may be stale"), "{notice}");
        assert!(notice.contains("press r"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert!(!notice.contains("task list refreshed"), "{notice}");
        assert_eq!(app.methods(), vec!["task/create", "daemon/status"]);
    }

    #[test]
    fn create_success_with_failed_task_list_refresh_does_not_claim_refresh() {
        let mut app = app_with(vec![
            Ok(created_reply("t9")),
            Ok(json!({"status": "running"})),
            Err(ClientError::Malformed("list unavailable".to_owned())),
        ]);
        app.create_task("t9", "content");
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("t9"), "{notice}");
        assert!(notice.contains("pending"), "{notice}");
        assert!(notice.contains("list refresh failed"), "{notice}");
        assert!(notice.contains("may be stale"), "{notice}");
        assert!(notice.contains("press r"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert!(!notice.contains("task list refreshed"), "{notice}");
        assert_eq!(
            app.methods(),
            vec!["task/create", "daemon/status", "task/list"]
        );
    }

    #[test]
    fn create_success_with_healthy_refresh_reports_both_outcomes() {
        let mut app = app_with(vec![
            Ok(created_reply("t9")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": [{"id": "t9", "state": "pending"}]})),
        ]);
        app.create_task("t9", "content");
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("t9"), "{notice}");
        assert!(notice.contains("pending"), "{notice}");
        assert!(notice.contains("created successfully"), "{notice}");
        assert!(notice.contains("task list refreshed"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert!(!app.notice.as_ref().expect("notice").is_error);
    }

    #[test]
    fn create_rpc_error_is_reported_as_error_not_success() {
        let mut app = app_with(vec![Err(ClientError::Malformed(
            "create refused".to_owned(),
        ))]);
        app.create_task("t9", "content");
        assert!(app.notice.as_ref().expect("notice").is_error);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("create:"), "{notice}");
        assert!(!notice.contains("created successfully"), "{notice}");
        assert_eq!(app.methods(), vec!["task/create"]);
    }

    #[test]
    fn worker_change_explains_claim_invalidation() {
        let mut app = app_with(vec![Ok(
            json!({"task": {"id": "t1"}, "claim_generation": 7}),
        )]);
        app.claim_selected();
        app.begin_worker_input();
        app.buffer = "other".to_owned();
        assert!(app.accept_input());
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("claim cleared"), "{notice}");
        assert!(app.claim.is_none());
    }

    #[test]
    fn confirm_without_a_review_reports_no_review_not_geometry() {
        let mut app = app_with(vec![]);
        app.decide_review(true);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert_eq!(notice, "no review is open", "{notice}");
        assert!(!notice.contains("fit on screen"), "{notice}");
    }

    #[test]
    fn clipped_review_blocked_action_does_not_advertise_confirmation() {
        let mut app = app_with_open_review();
        app.set_review_geometry(clipped_geometry());
        app.ai_propose_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(!notice.contains("press y"), "{notice}");
        assert!(notice.contains("press d to decline"), "{notice}");
        assert!(
            app.review.is_some(),
            "the review must survive the blocked action"
        );
        assert_eq!(
            app.methods(),
            vec!["capability/preview", "capability/preview"]
        );
    }

    fn model_read_with_limits(id: &str, limits: &str) -> Value {
        let mut p = model_read(id, "model-initiated-file-read", true, None);
        p["preview"]["disclosure"]["limits"] = json!(limits);
        p
    }

    #[test]
    fn incomplete_disclosure_reports_incomplete_not_resize() {
        let mut fresh = model_read_with_limits("p-1", &"Z".repeat(200));
        fresh["preview"]["challenge"] = json!("challenge-secret");
        let mut app = app_with(vec![
            Ok(model_read_with_limits("p-1", &"Z".repeat(200))),
            Ok(fresh),
        ]);
        app.preview_id = Some("p-1".to_owned());
        app.request_approval();
        assert!(app.review.is_some());
        app.ai_propose_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("incomplete"), "{notice}");
        assert!(!notice.contains("resize"), "{notice}");
        assert!(!notice.contains("press y"), "{notice}");
        assert!(app.review.is_some());
    }

    #[test]
    fn clipped_geometry_reports_resize_not_incomplete() {
        let mut app = app_with_open_review();
        app.set_review_geometry(clipped_geometry());
        app.ai_propose_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("does not fit"), "{notice}");
        assert!(notice.contains("resize"), "{notice}");
        assert!(!notice.contains("incomplete"), "{notice}");
    }

    #[test]
    fn selecting_another_task_clears_the_previous_verdict() {
        let mut app = app_with(vec![]);
        app.tasks = vec![
            json!({"id": "t1", "state": "completed"}),
            json!({"id": "t2", "state": "pending"}),
        ];
        app.verdict = Some(json!({"verified": true}));
        app.move_selection(1);
        assert_eq!(app.selected_task_id().as_deref(), Some("t2"));
        assert!(
            app.verdict.is_none(),
            "a verdict must not follow a different task"
        );
    }

    #[test]
    fn completion_fixture_has_no_fabricated_completed_field() {
        assert!(
            completed_reply("t1", "completed")["task"]
                .get("completed")
                .is_none()
        );
    }

    #[test]
    fn successful_completion_with_production_shape_is_reported_from_daemon_fields() {
        let mut app = app_with_claim(vec![
            Ok(completed_reply("t1", "completed")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": [{"id": "t1", "state": "completed"}]})),
        ]);
        app.complete_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("t1"), "{notice}");
        assert!(notice.contains("marked completed"), "{notice}");
        assert!(notice.contains("effect not verified"), "{notice}");
        assert!(notice.contains("task list refreshed"), "{notice}");
        assert!(!notice.contains("completed=true"), "{notice}");
        assert!(!notice.contains("completed=false"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert!(app.claim.is_none());
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/complete", "daemon/status", "task/list"]
        );
    }

    #[test]
    fn malformed_completion_reply_is_not_reported_as_success() {
        for (reply, partial_state) in [
            (json!({}), None),
            (json!({"task": null}), None),
            (json!({"task": "not an object"}), None),
            (json!({"task": {"state": "completed"}}), None),
            (json!({"task": {"id": "", "state": "completed"}}), None),
            (
                json!({"task": {"id": "other", "state": "completed"}}),
                Some("completed"),
            ),
            (json!({"task": {"id": "t1"}}), None),
            (json!({"task": {"id": "t1", "state": 42}}), None),
            (
                json!({"task": {"id": "t1", "state": "running"}}),
                Some("running"),
            ),
        ] {
            let mut app = app_with_claim(vec![Ok(reply.clone())]);
            app.complete_selected();
            assert!(app.notice.as_ref().expect("notice").is_error);
            let notice = &app.notice.as_ref().expect("notice").text;
            assert!(notice.contains("unconfirmed"), "{notice}");
            assert!(notice.contains("may be completed"), "{notice}");
            assert!(notice.contains("reclaim"), "{notice}");
            assert!(notice.contains("press r to inspect"), "{notice}");
            assert!(!notice.contains("marked completed"), "{notice}");
            assert!(notice.chars().count() <= 96, "footer bound: {notice}");
            if let Some(state) = partial_state {
                assert!(notice.contains(&format!("state: {state}")), "{notice}");
            }
            assert!(
                app.claim.is_none(),
                "a usable reply may have released the lease"
            );
            assert_eq!(
                app.methods(),
                vec!["task/claim", "task/complete"],
                "no second completion or refresh after an unusable reply: {notice}"
            );
        }
    }

    #[test]
    fn completion_success_with_failed_daemon_status_refresh_preserves_outcome() {
        let mut app = app_with_claim(vec![
            Ok(completed_reply("t1", "completed")),
            Err(ClientError::Malformed("status down".to_owned())),
        ]);
        app.complete_selected();
        assert!(app.notice.as_ref().expect("notice").is_error);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("t1"), "{notice}");
        assert!(notice.contains("marked completed"), "{notice}");
        assert!(notice.contains("effect not verified"), "{notice}");
        assert!(notice.contains("status refresh failed"), "{notice}");
        assert!(notice.contains("may be stale"), "{notice}");
        assert!(notice.contains("press r"), "{notice}");
        assert!(!notice.contains("task list refreshed"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/complete", "daemon/status"]
        );
    }

    #[test]
    fn completion_success_with_failed_task_list_refresh_does_not_claim_refresh() {
        let mut app = app_with_claim(vec![
            Ok(completed_reply("t1", "completed")),
            Ok(json!({"status": "running"})),
            Err(ClientError::Malformed("list down".to_owned())),
        ]);
        app.complete_selected();
        assert!(app.notice.as_ref().expect("notice").is_error);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("t1"), "{notice}");
        assert!(notice.contains("marked completed"), "{notice}");
        assert!(notice.contains("list refresh failed"), "{notice}");
        assert!(notice.contains("may be stale"), "{notice}");
        assert!(notice.contains("press r"), "{notice}");
        assert!(!notice.contains("task list refreshed"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/complete", "daemon/status", "task/list"]
        );
    }

    #[test]
    fn completion_success_with_healthy_refresh_reports_both_outcomes() {
        let mut app = app_with_claim(vec![
            Ok(completed_reply("t1", "completed")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": [{"id": "t1", "state": "completed"}]})),
        ]);
        app.complete_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("marked completed"), "{notice}");
        assert!(notice.contains("effect not verified"), "{notice}");
        assert!(notice.contains("task list refreshed"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert!(!app.notice.as_ref().expect("notice").is_error);
        assert!(app.claim.is_none());
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/complete", "daemon/status", "task/list"]
        );
    }

    #[test]
    fn completion_rpc_error_is_reported_as_error_not_success() {
        let mut app = app_with_claim(vec![Err(ClientError::Malformed(
            "complete refused".to_owned(),
        ))]);
        app.complete_selected();
        assert!(app.notice.as_ref().expect("notice").is_error);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("complete:"), "{notice}");
        assert!(!notice.contains("marked completed"), "{notice}");
        assert!(
            app.claim.is_some(),
            "a definite refusal must not drop a live claim"
        );
        assert_eq!(app.methods(), vec!["task/claim", "task/complete"]);
    }

    #[test]
    fn stale_claim_or_fenced_completion_is_reported_as_error() {
        let fenced = ClientError::Refused {
            code: -32040,
            message: "the task is not claimable by this worker".to_owned(),
            reason: Some("fenced".to_owned()),
            detail: None,
        };
        let mut app = app_with_claim(vec![Err(fenced)]);
        app.complete_selected();
        assert!(app.notice.as_ref().expect("notice").is_error);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("complete:"), "{notice}");
        assert!(!notice.contains("marked completed"), "{notice}");
        assert_eq!(app.methods(), vec!["task/claim", "task/complete"]);
    }

    #[test]
    fn repeated_completion_sends_one_rpc_per_invocation_and_refusals_are_not_success() {
        let fenced = ClientError::Refused {
            code: -32040,
            message: "the task is already terminal".to_owned(),
            reason: Some("fenced".to_owned()),
            detail: None,
        };
        let mut app = app_with_claim(vec![
            Ok(completed_reply("t1", "completed")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": [{"id": "t1", "state": "completed"}]})),
            Err(fenced),
        ]);
        app.complete_selected();
        assert_eq!(
            app.methods()
                .iter()
                .filter(|method| method.as_str() == "task/complete")
                .count(),
            1,
            "one user action must not generate a duplicate completion RPC"
        );

        app.claim = Some(Claim {
            task: "t1".to_owned(),
            worker: "tui".to_owned(),
            generation: 7,
        });
        app.complete_selected();
        assert!(app.notice.as_ref().expect("notice").is_error);
        assert_eq!(
            app.methods()
                .iter()
                .filter(|method| method.as_str() == "task/complete")
                .count(),
            2,
            "a later deliberate invocation is still allowed"
        );
    }

    #[test]
    fn successful_cancellation_with_production_shape_reports_limitation() {
        let mut app = app_with_claim(vec![
            Ok(cancelled_reply(true, "cancelled")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": [{"id": "t1", "state": "cancelled"}]})),
        ]);
        app.cancel_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("t1"), "{notice}");
        assert!(
            notice.contains("cancelled; in-flight work may continue"),
            "{notice}"
        );
        assert!(notice.contains("effects not reversed"), "{notice}");
        assert!(notice.contains("task list refreshed"), "{notice}");
        assert!(!notice.contains("cancelled=true"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert!(app.claim.is_none());
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/cancel", "daemon/status", "task/list"]
        );
    }

    #[test]
    fn repeated_cancellation_true_is_reported_without_claiming_a_new_event() {
        let mut app = app_with_claim(vec![
            Ok(cancelled_reply(true, "cancelled")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": [{"id": "t1", "state": "cancelled"}]})),
            Ok(cancelled_reply(true, "cancelled")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": [{"id": "t1", "state": "cancelled"}]})),
        ]);
        app.cancel_selected();
        assert!(
            app.notice
                .as_ref()
                .expect("notice")
                .text
                .contains("cancelled; in-flight work may continue")
        );
        assert!(
            app.notice
                .as_ref()
                .expect("notice")
                .text
                .contains("effects not reversed")
        );
        app.claim = Some(Claim {
            task: "t1".to_owned(),
            worker: "tui".to_owned(),
            generation: 7,
        });
        app.cancel_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(
            notice.contains("cancelled; in-flight work may continue"),
            "{notice}"
        );
        assert!(!notice.contains("new cancellation"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert_eq!(
            app.methods()
                .iter()
                .filter(|method| method.as_str() == "task/cancel")
                .count(),
            2,
            "one cancellation RPC per deliberate invocation"
        );
    }

    #[test]
    fn cancellation_false_with_paused_state_reports_actual_state() {
        let mut app = app_with_claim(vec![
            Ok(cancelled_reply(false, "paused")),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": [{"id": "t1", "state": "paused"}]})),
        ]);
        app.cancel_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("unchanged"), "{notice}");
        assert!(notice.contains("paused"), "{notice}");
        assert!(notice.contains("no cancellation"), "{notice}");
        assert!(
            !notice.contains("cancelled; in-flight work may continue"),
            "{notice}"
        );
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert!(app.claim.is_none());
    }

    #[test]
    fn malformed_or_inconsistent_cancellation_replies_are_unconfirmed() {
        for (reply, partial_state) in [
            (json!({}), None),
            (json!({"task": null, "cancelled": true}), None),
            (json!({"task": "not an object", "cancelled": true}), None),
            (
                json!({"task": {"state": "cancelled"}, "cancelled": true}),
                Some("cancelled"),
            ),
            (
                json!({"task": {"id": "", "state": "cancelled"}, "cancelled": true}),
                Some("cancelled"),
            ),
            (
                json!({"task": {"id": "other", "state": "cancelled"}, "cancelled": true}),
                Some("cancelled"),
            ),
            (
                json!({"task": {"id": "t1", "state": "cancelled"}}),
                Some("cancelled"),
            ),
            (
                json!({"task": {"id": "t1", "state": "cancelled"}, "cancelled": "true"}),
                Some("cancelled"),
            ),
            (json!({"task": {"id": "t1"}, "cancelled": true}), None),
            (
                json!({"task": {"id": "t1", "state": "bogus"}, "cancelled": true}),
                None,
            ),
            (
                json!({"task": {"id": "t1", "state": "completed"}, "cancelled": true}),
                Some("completed"),
            ),
            (
                json!({"task": {"id": "t1", "state": "cancelled"}, "cancelled": false}),
                Some("cancelled"),
            ),
        ] {
            let mut app = app_with_claim(vec![Ok(reply.clone())]);
            app.cancel_selected();
            assert!(app.notice.as_ref().expect("notice").is_error);
            let notice = &app.notice.as_ref().expect("notice").text;
            assert!(notice.contains("unconfirmed"), "{notice}");
            assert!(notice.contains("may have succeeded"), "{notice}");
            assert!(notice.contains("press r"), "{notice}");
            assert!(
                !notice.contains("cancelled; in-flight work may continue"),
                "{notice}"
            );
            assert!(!notice.contains("unchanged"), "{notice}");
            assert!(notice.chars().count() <= 96, "footer bound: {notice}");
            if let Some(state) = partial_state {
                assert!(notice.contains(&format!("state: {state}")), "{notice}");
            }
            assert!(
                app.claim.is_none(),
                "a usable reply may have released the lease"
            );
            assert_eq!(
                app.methods(),
                vec!["task/claim", "task/cancel"],
                "no refresh or second cancellation after an unusable reply: {notice}"
            );
        }
    }

    #[test]
    fn cancellation_with_failed_daemon_status_refresh_preserves_outcome() {
        let mut app = app_with_claim(vec![
            Ok(cancelled_reply(true, "cancelled")),
            Err(ClientError::Malformed("status down".to_owned())),
        ]);
        app.cancel_selected();
        assert!(app.notice.as_ref().expect("notice").is_error);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(
            notice.contains("cancelled; in-flight work may continue"),
            "{notice}"
        );
        assert!(notice.contains("effects not reversed"), "{notice}");
        assert!(notice.contains("status failed"), "{notice}");
        assert!(notice.contains("stale; r"), "{notice}");
        assert!(!notice.contains("task list refreshed"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/cancel", "daemon/status"]
        );
    }

    #[test]
    fn cancellation_with_failed_task_list_refresh_does_not_claim_refresh() {
        let mut app = app_with_claim(vec![
            Ok(cancelled_reply(true, "cancelled")),
            Ok(json!({"status": "running"})),
            Err(ClientError::Malformed("list down".to_owned())),
        ]);
        app.cancel_selected();
        assert!(app.notice.as_ref().expect("notice").is_error);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(
            notice.contains("cancelled; in-flight work may continue"),
            "{notice}"
        );
        assert!(notice.contains("effects not reversed"), "{notice}");
        assert!(notice.contains("list failed"), "{notice}");
        assert!(notice.contains("stale; r"), "{notice}");
        assert!(!notice.contains("task list refreshed"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/cancel", "daemon/status", "task/list"]
        );
    }

    #[test]
    fn cancellation_false_with_refresh_failures_preserves_actual_state() {
        for (kind, replies, failure) in [
            (
                "status",
                vec![
                    Ok(cancelled_reply(false, "paused")),
                    Err(ClientError::Malformed("status down".to_owned())),
                ],
                "status failed",
            ),
            (
                "list",
                vec![
                    Ok(cancelled_reply(false, "paused")),
                    Ok(json!({"status": "running"})),
                    Err(ClientError::Malformed("list down".to_owned())),
                ],
                "list failed",
            ),
        ] {
            let mut app = app_with_claim(replies);
            app.cancel_selected();
            assert!(app.notice.as_ref().expect("notice").is_error);
            let notice = &app.notice.as_ref().expect("notice").text;
            assert!(notice.contains("unchanged"), "{kind}: {notice}");
            assert!(notice.contains("paused"), "{kind}: {notice}");
            assert!(notice.contains(failure), "{kind}: {notice}");
            assert!(notice.contains("stale; r"), "{kind}: {notice}");
            assert!(!notice.contains("task list refreshed"), "{kind}: {notice}");
            assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        }
    }

    #[test]
    fn pending_effect_refusal_is_an_error_not_success() {
        let refused = ClientError::Refused {
            code: -32040,
            message: "the task has an unresolved effect".to_owned(),
            reason: Some("effect-outcome-unresolved".to_owned()),
            detail: None,
        };
        let mut app = app_with_claim(vec![Err(refused)]);
        app.cancel_selected();
        assert!(app.notice.as_ref().expect("notice").is_error);
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("cancel:"), "{notice}");
        assert!(
            !notice.contains("cancelled; in-flight work may continue"),
            "{notice}"
        );
        assert!(!notice.contains("unchanged"), "{notice}");
        assert!(
            app.claim.is_some(),
            "a definite refusal must not drop the claim"
        );
        assert_eq!(app.methods(), vec!["task/claim", "task/cancel"]);
    }

    #[test]
    fn cancellation_fixture_matches_the_daemon_response_shape() {
        let reply = cancelled_reply(true, "cancelled");
        assert!(reply["cancelled"].is_boolean());
        assert!(reply["task"].get("created").is_none());
        assert!(reply["task"].get("completed").is_none());
        assert_eq!(reply["task"]["id"], json!("t1"));
        assert_eq!(reply["task"]["state"], json!("cancelled"));
    }

    #[test]
    fn long_task_identifier_keeps_both_safety_qualifications_visible() {
        let long_id = "X".repeat(40);
        let mut reply = cancelled_reply(true, "cancelled");
        reply["task"]["id"] = json!(long_id.clone());
        let mut app = app_with_claim(vec![
            Ok(reply),
            Ok(json!({"status": "running"})),
            Ok(json!({"tasks": []})),
        ]);
        with_task(&mut app, &long_id);
        app.claim = Some(Claim {
            task: long_id.clone(),
            worker: "tui".to_owned(),
            generation: 7,
        });
        app.cancel_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("XXXX…XXX"), "{notice}");
        assert!(!notice.contains(&long_id), "{notice}");
        assert!(
            notice.contains("cancelled; in-flight work may continue"),
            "{notice}"
        );
        assert!(notice.contains("effects not reversed"), "{notice}");
        assert!(notice.chars().count() <= 96, "footer bound: {notice}");
        assert!(app.claim.is_none());
        assert_eq!(
            app.methods(),
            vec!["task/claim", "task/cancel", "daemon/status", "task/list"]
        );
    }

    #[test]
    fn a_preview_for_another_task_is_not_adopted() {
        let mut reply = model_read("p-x", "direct-proposal", false, None);
        reply["preview"]["task_id"] = json!("other-task");
        let mut app = app_with(vec![Ok(reply)]);
        app.preview_proposal("p-x");
        assert!(app.preview.is_none());
        assert!(app.preview_id.is_none());
        assert_eq!(app.methods(), vec!["capability/preview"]);
    }

    #[test]
    fn known_ai_provenance_blocks_wrong_worker_before_preview_rpc() {
        let mut app = app_with_claim(vec![Ok(
            json!({"proposal": {"proposal_id": "p-ai", "task_id": "t1"}}),
        )]);
        app.ai_propose_selected();
        assert!(app.ai_provenance.contains_key("p-ai"));
        app.worker = "other".to_owned();
        app.claim = None;
        app.preview_proposal("p-ai");
        assert_eq!(app.methods(), vec!["task/claim", "task/ai-propose"]);
        assert_eq!(app.preview_id.as_deref(), Some("p-ai"));
    }

    #[test]
    fn typed_id_adoption_does_not_inherit_other_provenance() {
        let mut app = app_with(vec![Ok(model_read(
            "p-typed",
            "direct-proposal",
            false,
            None,
        ))]);
        app.preview_proposal("p-typed");
        assert!(app.ai_provenance.is_empty());
        assert_eq!(app.adoption_worker.as_deref(), Some("tui"));
    }

    #[test]
    fn worker_change_invalidates_active_context_but_keeps_provenance() {
        let mut app = app_with_claim(vec![
            Ok(json!({"proposal": {"proposal_id": "p-ai", "task_id": "t1"}})),
            Ok(model_read("p-ai", "direct-proposal", false, None)),
        ]);
        app.ai_propose_selected();
        app.preview_proposal("p-ai");
        app.worker = "other".to_owned();
        app.claim = None;
        app.clear_active_context();
        assert!(app.preview.is_none());
        assert!(app.adoption_worker.is_none());
        assert!(app.ai_provenance.contains_key("p-ai"));
    }

    #[test]
    fn hiding_and_reopening_a_review_issues_no_rpc() {
        let mut app = app_with(vec![
            Ok(model_read("p-1", "model-initiated-file-read", true, None)),
            Ok(model_read(
                "p-1",
                "model-initiated-file-read",
                true,
                Some("challenge-secret"),
            )),
        ]);
        app.preview_id = Some("p-1".to_owned());
        app.request_approval();
        app.set_review_geometry(fitting_geometry());
        let before = app.methods();
        app.hide_review();
        assert!(app.review.is_some());
        assert!(app.review_hidden);
        assert!(app.reopen_review());
        assert!(!app.review_hidden);
        assert_eq!(app.methods(), before);
    }

    #[test]
    fn execution_requires_validated_approval() {
        let mut app = app_with(vec![Ok(execution_reply("p-1", true, false, false))]);
        app.preview_id = Some("p-1".to_owned());
        app.execute_previewed();
        assert_eq!(app.methods(), Vec::<String>::new());
        assert!(
            app.notice
                .as_ref()
                .is_some_and(|n| n.text.contains("validated approval"))
        );
    }

    #[test]
    fn malformed_execution_reply_blocks_replay() {
        let mut app = app_with(vec![Ok(execution_reply("p-1", true, false, false))]);
        app.preview_id = Some("p-1".to_owned());
        app.approval_dispositions
            .insert("p-1".to_owned(), ApprovalDisposition::Accepted);
        app.execution_dispositions
            .insert("p-1".to_owned(), ExecutionDisposition::ApprovedReady);
        let mut bad = execution_reply("p-1", true, false, false);
        bad.as_object_mut().expect("object").remove("proposal");
        app.client.replies.lock().expect("lock").clear();
        app.client.replies.lock().expect("lock").push(Ok(bad));
        app.execute_previewed();
        assert_eq!(
            app.execution_dispositions.get("p-1"),
            Some(&ExecutionDisposition::OutcomeUnknown)
        );
        let calls = app.methods();
        app.execute_previewed();
        assert_eq!(app.methods(), calls, "a blocked replay sends no RPC");
    }

    #[test]
    fn execution_no_replay_states_are_independent_per_proposal() {
        let mut app = app_with(vec![]);
        app.execution_dispositions
            .insert("p-1".to_owned(), ExecutionDisposition::OutcomeUnknown);
        app.execution_dispositions
            .insert("p-2".to_owned(), ExecutionDisposition::ApprovedReady);
        assert!(app.no_replay("p-1"));
        assert!(!app.no_replay("p-2"));
    }

    #[test]
    fn strict_execution_result_validation_requires_all_key_fields() {
        let good = execution_reply("p-1", true, false, false);
        assert!(valid_execution_result(&good, "p-1", "t1"));
        let mut missing = good.clone();
        missing.as_object_mut().expect("object").remove("step");
        assert!(!valid_execution_result(&missing, "p-1", "t1"));
        let mut wrong = good;
        wrong["proposal"]["proposal_id"] = json!("p-other");
        assert!(!valid_execution_result(&wrong, "p-1", "t1"));
    }
}
