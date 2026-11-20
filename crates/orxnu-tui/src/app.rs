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

use std::path::Path;

use orxnuctl::approval::{self, ApprovalStart, PreviewRequests, Review};
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
    /// A model-initiated read awaiting an explicit human decision.
    pub review: Option<Review>,
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
            review: None,
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
        match self
            .client
            .negotiate()
            .and_then(|_| self.client.call("daemon/status", json!({})))
        {
            Ok(status) => self.status = Some(status),
            Err(e) => {
                self.notice = Some(Notice::error(format!("daemon status: {e}")));
                return;
            }
        }
        match self.client.call("task/list", json!({})) {
            Ok(reply) => {
                self.tasks = task_array(&reply);
                self.selected = self.selected.min(self.tasks.len().saturating_sub(1));
                self.notice = Some(Notice::info(format!(
                    "refreshed: {} task(s)",
                    self.tasks.len()
                )));
            }
            Err(e) => {
                self.notice = Some(Notice::error(format!("task list: {e}")));
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
        let last = self.tasks.len() - 1;
        self.selected = if delta < 0 {
            self.selected.saturating_sub(delta.unsigned_abs())
        } else {
            self.selected.saturating_add(delta as usize).min(last)
        };
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

    /// One shared policy for state-changing actions while a human decision is pending.
    ///
    /// A `Review` holds a daemon-issued challenge and is consumed only by
    /// [`Self::decide_review`]. No other action may discard it, send a new proposal
    /// request, or change the task/worker context it describes. Read-only actions
    /// (selection, refresh, quit) are deliberately not gated: they send no governed
    /// request and cannot invalidate the review or its claim.
    fn reject_while_review_open(&mut self, action: &str) -> bool {
        if self.review.is_some() {
            self.notice = Some(Notice::error(format!(
                "finish the open review first: press y to confirm or d to decline before {action}"
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
                // worker drops it rather than letting it be presented again.
                self.claim = None;
                self.notice = Some(Notice::info(format!("worker set to {}", self.worker)));
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
                self.notice = Some(Notice::info(format!(
                    "task/create: created={}",
                    reply
                        .get("created")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                )));
                self.refresh();
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
        match self.client.call(
            "task/ai-propose",
            json!({ "task": id, "worker": self.worker, "claim_generation": generation }),
        ) {
            Ok(reply) => match proposal_for_task(&reply, &id) {
                Some(pid) => {
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
        match self.client.call(
            "capability/preview",
            json!({ "proposal": id, "inspect_only": true }),
        ) {
            Ok(reply) => match approval::check_preview_id(&reply, id) {
                Ok(()) => {
                    self.preview = Some(reply);
                    self.preview_id = Some(id.to_owned());
                    self.verdict = None;
                    self.notice = Some(Notice::info(format!("preview of {id}")));
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
        let Some(id) = self.preview_id.clone() else {
            self.notice = Some(Notice::error("preview a proposal before approving it"));
            return;
        };
        if self.reject_while_review_open("starting another approval") {
            return;
        }
        match approval::begin_approval(&self.client, true, &id, json!({ "proposal": id })) {
            Ok(ApprovalStart::Submitted { .. }) => {
                self.notice = Some(Notice::info(format!("approval issued for {id}")));
            }
            Ok(ApprovalStart::NeedsReview(review)) => {
                self.notice = Some(Notice::info(format!(
                    "review required for {id}: confirm the disclosure explicitly"
                )));
                self.review = Some(review);
            }
            Err(e) => self.notice = Some(Notice::error(format!("approve: {e}"))),
        }
    }

    /// Records a renderer-derived geometry measurement for the open review.
    ///
    /// The event loop is the only production caller. UI actions never call it, and
    /// callers cannot pass an arbitrary boolean: eligibility is computed by
    /// [`ReviewGeometry::from_measurement`] from actual dimensions.
    pub fn set_review_geometry(&mut self, geometry: ReviewGeometry) {
        self.review_displayable = geometry.fits;
    }

    /// Finish the open review. A decline submits no approval at all.
    pub fn decide_review(&mut self, confirmed: bool) {
        if confirmed && !self.review_displayable {
            let proposal_id = self
                .review
                .as_ref()
                .map_or_else(|| "unknown".to_owned(), |r| r.proposal_id().to_owned());
            self.notice = Some(Notice::error(format!(
                "approval for {proposal_id} was NOT submitted: the review did not fit on screen. \
                 Resize so the whole review is visible (wider and/or taller) or decline with d, \
                 then reinspect before retrying."
            )));
            return;
        }
        let Some(review) = self.review.take() else {
            self.notice = Some(Notice::error("no review is open"));
            return;
        };
        let proposal_id = review.proposal_id().to_owned();
        if !confirmed {
            self.notice = Some(Notice::info("declined: nothing was approved"));
            return;
        }
        match approval::submit_review(&self.client, review, true) {
            Ok(Some(_)) => {
                self.notice = Some(Notice::info(format!("approval issued for {proposal_id}")))
            }
            Ok(None) => self.notice = Some(Notice::info("declined: nothing was approved")),
            Err(e) => self.notice = Some(approval_failure_notice(&proposal_id, &e)),
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
        let Some(id) = self.preview_id.clone() else {
            self.notice = Some(Notice::error("preview a proposal before executing it"));
            return;
        };
        match self.client.call(
            "task/execute",
            json!({ "proposal": id, "worker": self.worker }),
        ) {
            Ok(reply) => {
                self.verdict = Some(execution_verdict(&reply));
                self.notice = Some(Notice::info(format!("execution returned for {id}")));
            }
            Err(e) => self.notice = Some(Notice::error(format!("execute: {e}"))),
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
                self.notice = Some(Notice::info(format!(
                    "task/complete: completed={}",
                    reply
                        .get("completed")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                )));
                self.claim = None;
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
                let cancelled = reply
                    .get("cancelled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let state = reply
                    .get("task")
                    .and_then(|t| t.get("state"))
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                self.notice = Some(Notice::info(format!(
                    "task/cancel: daemon reported cancelled={cancelled}, state={state}"
                )));
                if self.claim.as_ref().is_some_and(|c| c.task == id) {
                    self.claim = None;
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

    fn model_read(id: &str, kind: &str, requires: bool, challenge: Option<&str>) -> Value {
        let mut p = json!({
            "proposal_id": id,
            "proposal_kind": kind,
            "requires_confirmation": requires,
            "operation": "file-read",
            "approval_allowed": true,
            "path": "src/main.rs",
            "recipient": "provider (model: m)",
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
        let mut app = app_with(vec![Ok(json!({
            "verified": false,
            "refuted": false,
            "undetermined": true,
            "uncertainty": {
                "settled": "unknown",
                "task_state": "needs-verification",
                "awaiting": "human-adjudication"
            }
        }))]);
        app.preview_id = Some("p-1".to_owned());
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
            Ok(json!({ "completed": true })),
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
            Ok(json!({ "approval": { "digest": "d" } })),
            Ok(json!({ "verified": true })),
        ]);
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
            Ok(json!({ "approval": { "digest": "d" } })),
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
        let mut app = app_with(vec![Ok(json!({
            "cancelled": false,
            "task": { "id": "t1", "state": "completed" }
        }))]);
        app.cancel_selected();
        let notice = &app.notice.as_ref().expect("notice").text;
        assert!(notice.contains("cancelled=false"), "{notice}");
        assert!(notice.contains("completed"), "{notice}");
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
            Ok(json!({ "verified": true })),
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
            Ok(json!({ "approval": { "digest": "d" } })),
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
            Ok(json!({ "created": true })),
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
        let mut app = review_with_approval_reply(Ok(json!({ "approval": { "digest": "d" } })));
        app.decide_review(true);
        assert!(app.review.is_none());
        let notice = app.notice.as_ref().expect("notice").text.clone();
        assert!(notice.contains("p-1"), "{notice}");
        assert!(notice.contains("issued"), "{notice}");
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
        assert!(notice.contains("OUTCOME UNKNOWN"), "{notice}");
        assert!(notice.contains("Do NOT issue another approval"), "{notice}");
        assert!(notice.contains("Refresh and reinspect"), "{notice}");
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
        assert!(notice.contains("OUTCOME UNKNOWN"), "{notice}");
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
            .push(Ok(json!({ "approval": { "digest": "d" } })));
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
}
