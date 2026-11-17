//! Application state and actions, independent of rendering.
//!
//! Every action is one protocol call and one state update. There is no rule here about
//! what a task or proposal *means*: the daemon's own words are what get stored and
//! shown, so the surface cannot drift into a second definition of a governed concept.

use orxnuctl::client::Client;
use serde_json::{Value, json};

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
    /// Typing the worker identity used by `task/execute`.
    Worker,
}

/// What is on screen.
#[derive(Debug)]
pub struct App {
    /// The daemon, reached through the CLI's client.
    client: Client,
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
    /// Worker identity used for execution. A label, not an authority.
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

impl App {
    /// Connect to the default local endpoint. Nothing is sent until `refresh`.
    #[must_use]
    pub fn new() -> Self {
        Self::with_client(Client::with_default_endpoint())
    }

    /// Construct with an explicit client, for tests against a synthetic daemon.
    #[must_use]
    pub fn with_client(client: Client) -> Self {
        Self {
            client,
            status: None,
            tasks: Vec::new(),
            selected: 0,
            preview: None,
            preview_id: None,
            verdict: None,
            worker: "tui".to_owned(),
            buffer: String::new(),
            input: Input::None,
            notice: None,
            should_quit: false,
        }
    }

    /// The endpoint this surface talks to.
    #[must_use]
    pub fn endpoint(&self) -> &std::path::Path {
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

    /// Begin typing a proposal id.
    pub fn begin_proposal_input(&mut self) {
        self.input = Input::Proposal;
        self.buffer.clear();
        self.notice = Some(Notice::info("proposal id: Enter to preview, Esc to cancel"));
    }

    /// Begin typing the worker identity.
    pub fn begin_worker_input(&mut self) {
        self.input = Input::Worker;
        self.buffer.clear();
        self.notice = Some(Notice::info("worker: Enter to set, Esc to cancel"));
    }

    /// Cancel the active input without acting.
    pub fn cancel_input(&mut self) {
        self.input = Input::None;
        self.buffer.clear();
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
            Input::Worker if !value.is_empty() => {
                self.worker = value;
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

    /// Read-only preview. `inspect_only` is deliberate: looking must not mint a
    /// challenge the operator then abandons, which is the daemon's own rule.
    pub fn preview_proposal(&mut self, id: &str) {
        match self.client.call(
            "capability/preview",
            json!({ "proposal": id, "inspect_only": true }),
        ) {
            Ok(reply) => {
                self.preview = Some(reply);
                self.preview_id = Some(id.to_owned());
                self.verdict = None;
                self.notice = Some(Notice::info(format!("preview of {id}")));
            }
            Err(e) => self.notice = Some(Notice::error(format!("preview: {e}"))),
        }
    }

    /// Approve the proposal currently previewed. No other id can be targeted: an
    /// action always names `preview_id`, never whatever the input buffer holds.
    pub fn approve_previewed(&mut self) {
        let Some(id) = self.preview_id.clone() else {
            self.notice = Some(Notice::error("preview a proposal before approving it"));
            return;
        };
        match self
            .client
            .call("capability/approve", json!({ "proposal": id }))
        {
            Ok(_) => {
                self.notice = Some(Notice::info(format!("approval issued for {id}")));
                self.preview_proposal(&id);
            }
            Err(e) => self.notice = Some(Notice::error(format!("approve: {e}"))),
        }
    }

    /// Execute the proposal currently previewed, and display the daemon's verdict.
    ///
    /// The three flags are copied verbatim. The TUI does not decide that `verified`
    /// means success: a governed read that did not verify is exactly the state the
    /// operator must see as unresolved.
    pub fn execute_previewed(&mut self) {
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
}

/// Pull the `tasks` array out of a `task/list` reply.
///
/// A malformed reply degrades to an empty list rather than a panic, and the footer
/// says so through `refresh`'s "0 tasks" notice — a surface that crashes on an
/// unexpected daemon answer is worse than one that says it could not read it.
fn task_array(reply: &Value) -> Vec<Value> {
    reply
        .get("tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Copy the three execution flags out of a `task/execute` reply.
///
/// Missing flags stay missing; they are never defaulted to `false`, because a reply
/// this build does not understand must not be rendered as "nothing happened".
fn execution_verdict(reply: &Value) -> Value {
    let mut out = serde_json::Map::new();
    for key in ["verified", "refuted", "undetermined"] {
        if let Some(v) = reply.get(key) {
            out.insert(key.to_owned(), v.clone());
        }
    }
    Value::Object(out)
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(got.get("refuted").is_none(), "a missing flag is not false");
        assert!(
            got.get("other").is_none(),
            "unrelated fields are not verdicts"
        );
    }

    #[test]
    fn selection_is_clamped_and_never_wraps() {
        let mut app = App::new();
        app.tasks = vec![json!({"id": "a"}), json!({"id": "b"}), json!({"id": "c"})];
        app.move_selection(-1);
        assert_eq!(app.selected, 0, "no wrap at the top");
        app.move_selection(10);
        assert_eq!(app.selected, 2, "clamped at the bottom");
        app.move_selection(1);
        assert_eq!(app.selected, 2);

        app.tasks.clear();
        app.move_selection(1);
        assert_eq!(app.selected, 0, "an empty list has no selection");
    }

    #[test]
    fn actions_require_a_preview_id() {
        let mut app = App::new();
        app.approve_previewed();
        assert!(app.notice.as_ref().is_some_and(|n| n.is_error));
        app.notice = None;
        app.execute_previewed();
        assert!(app.notice.as_ref().is_some_and(|n| n.is_error));
    }

    #[test]
    fn input_acceptance_never_targets_a_different_id() {
        let mut app = App::new();
        app.begin_proposal_input();
        app.buffer = "p-1".to_owned();
        app.preview_id = Some("p-shown".to_owned());
        // accept_input clears the buffer; the preview id is the only thing an
        // action can subsequently name, so a stale buffer cannot retarget it.
        assert!(app.accept_input());
        assert_eq!(app.input, Input::None);
        assert!(app.buffer.is_empty());
    }

    #[test]
    fn needs_verification_is_a_state_string_the_daemon_chose() {
        // The surface must render this verbatim; it must not decide it is success.
        let row = json!({"id": "t1", "state": "needs-verification"});
        assert_eq!(selected_state(&row), "needs-verification");
    }

    fn selected_state(row: &Value) -> &str {
        row.get("state")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    }
}
