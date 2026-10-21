//! The `task` commands.
//!
//! # The CLI owns no task rule
//!
//! Every semantic decision here is the daemon's: whether an id is free, whether a task
//! can be claimed, whether a lease still belongs to the worker asking to complete it,
//! and what a state is called. This module builds a request, sends it, and renders
//! whatever comes back.
//!
//! That is why there is no state check anywhere in this file. A `task complete` on a
//! pending task is *not* pre-judged here and refused locally — the request is sent, and
//! the daemon's `fenced` answer is shown. A local check would be a second copy of the
//! queue contract, and it would be wrong the moment the contract changed.
//!
//! What the CLI does own: argument shape, and presentation. Turning a refusal into an
//! exit code and a line of text is presentation. Deciding *whether* to refuse is not.

use serde_json::{Value, json};

use crate::client::{Client, ClientError, refusal};

/// A `task` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskCommand {
    /// Enqueue a task.
    Create {
        /// The task id.
        id: String,
        /// The task kind, or the protocol's default when absent.
        kind: Option<String>,
        /// The task's human-visible content.
        content: Option<String>,
        /// How many logical steps the task may have; the daemon's default of one when
        /// absent.
        ///
        /// Optional rather than always present so the common case stays a short command,
        /// and so a task created without it keeps behaving exactly as before.
        max_steps: Option<u32>,
    },
    /// List every task.
    List,
    /// Take a lease on one named task.
    Claim {
        /// The task id.
        id: String,
        /// The worker identity taking the lease.
        worker: String,
    },
    /// Record a completion for a task the caller holds a lease on.
    Complete {
        /// The task id.
        id: String,
        /// The worker identity holding the lease.
        worker: String,
    },
    /// Cancel a task.
    ///
    /// No worker identity, because the engine does not want one: cancellation is a
    /// decision about the task and clears whatever lease it holds, so a cancel that
    /// had to name a worker could not cancel an unclaimed task at all.
    Cancel {
        /// The task id.
        id: String,
    },
    /// Ask for a governed action to be performed by a running task.
    ///
    /// Creates a durable proposal and parks the task for human approval. The worker is
    /// the task's current lease holder and gains no authority from being named here.
    Propose {
        /// The task id.
        task: String,
        /// The worker holding the task's lease.
        worker: String,
        /// Which capability to ask for.
        capability: String,
        /// The capability's parameters, verbatim JSON.
        params: String,
        /// The human-readable target, if any.
        target: Option<String>,
    },
    /// Execute an approved proposal.
    Execute {
        /// Which proposal.
        proposal: String,
        /// The worker taking the fresh execution lease.
        worker: String,
    },
    /// Ask the AI proposer what it would do with a task.
    ///
    /// The model proposes; it does not act. This persists a durable proposal and parks
    /// the task for human approval, exactly as `propose` does — the only difference is
    /// who composed the action.
    AiPropose {
        /// The task id.
        task: String,
        /// The worker holding the task's lease.
        worker: String,
    },
    /// Advance a task that has finished one step to the next.
    ///
    /// Claims the next step, asks the proposer what it should do, and persists an
    /// ordinary proposal for human approval. It does not execute, so running a task to
    /// completion is a sequence of approve/execute/continue calls rather than one call.
    Continue {
        /// The task id.
        task: String,
        /// The worker taking ownership of the next step.
        worker: String,
    },
}

/// Runs a task command and returns what to print.
///
/// # Errors
///
/// [`ClientError`] if the daemon is unreachable, answers with something unreadable,
/// speaks a version this build cannot, or refuses the request.
pub fn run(command: &TaskCommand, client: &Client) -> Result<String, ClientError> {
    // Before anything else: refuse to talk to a daemon whose answers this build would
    // misread. Cheap, and it turns a confusing shape mismatch into one clear line.
    client.negotiate()?;

    match command {
        TaskCommand::Create {
            id,
            kind,
            content,
            max_steps,
        } => {
            let mut params = json!({ "id": id });
            if let Some(k) = kind {
                params["kind"] = json!(k);
            }
            if let Some(c) = content {
                params["content"] = json!(c);
            }
            if let Some(m) = max_steps {
                params["max_steps"] = json!(m);
            }
            let reply = client.call("task/create", params)?;
            Ok(render_task_field(&reply, "created"))
        }
        TaskCommand::List => {
            let reply = client.call("task/list", json!({}))?;
            Ok(render_list(&reply))
        }
        TaskCommand::Claim { id, worker } => {
            let reply = client.call("task/claim", json!({ "id": id, "worker": worker }))?;
            Ok(render_claim(&reply))
        }
        TaskCommand::Propose {
            task,
            worker,
            capability,
            params,
            target,
        } => {
            let params: Value =
                serde_json::from_str(params).map_err(|e| ClientError::InvalidParams {
                    detail: format!("`--params` is not valid JSON: {e}"),
                })?;
            let mut payload = json!({
                "task": task,
                "worker": worker,
                "capability": capability,
                "params": params,
            });
            if let Some(t) = target {
                payload["target"] = json!(t);
            }
            let reply = client.call("task/propose", payload)?;
            Ok(render_proposal(&reply))
        }
        TaskCommand::AiPropose { task, worker } => {
            let reply =
                client.call("task/ai-propose", json!({ "task": task, "worker": worker }))?;
            let mut out = render_proposal(&reply);
            // Stated plainly, because the reply's existence is not the interesting part:
            // what matters is that a model asked and a person still has to decide.
            for key in ["proposed_by", "model"] {
                if let Some(v) = reply.get(key).and_then(Value::as_str) {
                    out.push_str(&format!("  {key}: {v}\n"));
                }
            }
            render_recipient(&reply, &mut out);
            Ok(out)
        }
        TaskCommand::Continue { task, worker } => {
            let reply = client.call("task/continue", json!({ "task": task, "worker": worker }))?;
            // The two outcomes are different enough that they are rendered differently:
            // a completion has no proposal to show, and printing an empty one would read
            // as a continuation that produced nothing to approve.
            if reply.get("completed").and_then(Value::as_bool) == Some(true) {
                let mut out = format!(
                    "task finished after {} step(s)\n",
                    reply
                        .get("steps_completed")
                        .and_then(Value::as_u64)
                        .unwrap_or(0)
                );
                if let Some(summary) = reply.get("summary").and_then(Value::as_str) {
                    out.push_str(&format!("  summary: {summary}\n"));
                }
                // Restated here for the same reason `ai-propose` does it: a task that ends
                // because a model said so is only trustworthy if that is visible.
                for key in ["proposed_by", "model"] {
                    if let Some(v) = reply.get(key).and_then(Value::as_str) {
                        out.push_str(&format!("  {key}: {v}\n"));
                    }
                }
                return Ok(out);
            }
            let mut out = render_proposal(&reply);
            render_recipient(&reply, &mut out);
            if let Some(step) = reply.get("step").and_then(Value::as_u64) {
                out.push_str(&format!("  step: {step}\n"));
            }
            for key in ["proposed_by", "model"] {
                if let Some(v) = reply.get(key).and_then(Value::as_str) {
                    out.push_str(&format!("  {key}: {v}\n"));
                }
            }
            Ok(out)
        }
        TaskCommand::Execute { proposal, worker } => {
            let reply = client.call(
                "task/execute",
                json!({ "proposal": proposal, "worker": worker }),
            )?;
            let mut out = render_proposal(&reply);
            // The verdict is the daemon's, not a local guess: a proposal that dispatched
            // but did not verify must not read as success to a script.
            let flag = |k: &str| reply.get(k).and_then(Value::as_bool).unwrap_or(false);
            out.push_str(&format!(
                "verified: {}\nrefuted: {}\nundetermined: {}\n",
                flag("verified"),
                flag("refuted"),
                flag("undetermined"),
            ));
            Ok(out)
        }
        TaskCommand::Complete { id, worker } => {
            let reply = client.call("task/complete", json!({ "id": id, "worker": worker }))?;
            Ok(render_task_field(&reply, "completed"))
        }
        TaskCommand::Cancel { id } => {
            let reply = client.call("task/cancel", json!({ "id": id }))?;
            Ok(render_cancel(&reply))
        }
    }
}

/// Renders the safe recipient status of an AI-generated proposal.
///
/// The daemon sends a `recipient` label only when the configured destination could be
/// represented safely, and a `recipient_status` of `identified` or `unavailable`. There
/// is no fallback to a raw endpoint: the client is never given one to print.
///
/// This is **not** an informed-approval notice. It tells the operator who the proposal
/// is bound to before they run the separate approval command; the approval flow itself
/// still issues an approval without a preview or an explicit confirmation, and that
/// remains outstanding work.
fn render_recipient(reply: &Value, out: &mut String) {
    match reply.get("recipient").and_then(Value::as_str) {
        Some(label) => {
            out.push_str(&format!("  recipient: {label}\n"));
        }
        None => {
            let status = reply
                .get("recipient_status")
                .and_then(Value::as_str)
                .unwrap_or("unavailable");
            if status == "identified" {
                out.push_str("  recipient: (the daemon reported no recipient label)\n");
            } else {
                out.push_str(
                    "  recipient: cannot be safely identified, so file-content \
                     disclosure is unavailable\n",
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The disclosure preview and the confirmation that follows it.
//
// A model-initiated file read discloses the file's contents to the model provider
// that asked for it. The operator must therefore see what they are authorising -- the
// path, the recipient, and the limits -- and must say yes, before an approval is
// created. The daemon enforces the challenge; the client is what turns a request
// into an informed decision.
//
// These are separated from the request sequence so that the parts that can be wrong
// quietly -- the classification, the rendering, the parsing -- can be tested without a
// terminal, a socket, or a provider.
// ---------------------------------------------------------------------------

/// What the daemon says a proposal is, and therefore what the client must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProposalKind {
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
pub(crate) fn classify_proposal(preview: &Value) -> Result<ProposalKind, String> {
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
    let kind = match kind {
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
            ProposalKind::ModelInitiatedFileRead
        }
        "model-initiated" => {
            if requires {
                return Err(
                    "only a model-initiated file read may require a disclosure confirmation"
                        .to_owned(),
                );
            }
            ProposalKind::ModelInitiated
        }
        "direct-proposal" => {
            if requires {
                return Err("a direct proposal cannot require a disclosure confirmation".to_owned());
            }
            ProposalKind::DirectProposal
        }
        other => return Err(format!("unknown proposal kind {other:?}")),
    };
    Ok(kind)
}

/// Makes a stored value safe to print.
///
/// A path or a label comes from durable state, and a value carrying an escape
/// sequence could otherwise move the operator's cursor, rewrite the line, or hide
/// what it says. Control characters are shown as their code point instead.
pub(crate) fn safe_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_control() {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// The recipient label, if it is safe to print.
///
/// The daemon supplies a *safe* label, built by its own projection. If it ever
/// supplied something that looks like a raw URL carrying user information, a query
/// or a fragment, it is **not** printed: a credential must not reach the terminal
/// because a projection changed.
fn safe_recipient(label: &str) -> Option<String> {
    if label.contains('@') || label.contains('?') || label.contains('#') {
        return None;
    }
    Some(safe_text(label))
}

/// Renders the disclosure preview the operator is asked to confirm.
///
/// Every fact shown comes from the server's response, and the recipient is the
/// **safe label** the daemon produced. A raw endpoint, a credential, or an
/// unfiltered URL is never printed, and stored text is escaped.
pub(crate) fn render_read_preview(
    preview: &Value,
    out: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let p = &preview["preview"];
    let text = |k: &str| {
        p.get(k)
            .and_then(Value::as_str)
            .unwrap_or("(not reported)")
            .to_owned()
    };
    let num = |k: &str| p.get(k).and_then(Value::as_u64);
    let disclosure = &p["disclosure"];
    let dtext = |k: &str| {
        disclosure
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };

    writeln!(out, "This action is waiting for your approval.\n")?;
    writeln!(out, "  proposal:   {}", safe_text(&text("proposal_id")))?;
    writeln!(out, "  capability: {}", safe_text(&text("capability")))?;
    writeln!(out, "  path:       {}", safe_text(&text("path")))?;
    writeln!(
        out,
        "  operation:  {} -- this READS a file; it does not write one.",
        safe_text(&text("operation"))
    )?;

    // Only a proposal that actually discloses to a model provider may say so. A
    // direct, human-delegated proposal must not be told that its content is going
    // to a model provider, because it is not.
    if p.get("requires_confirmation")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        writeln!(
            out,
            "\n  The file's contents MAY BE DISCLOSED to the model provider that originated"
        )?;
        writeln!(
            out,
            "  this proposal, for the AI request immediately following it. Disclosure is"
        )?;
        writeln!(
            out,
            "  not guaranteed: the content may be skipped or not retained at all."
        )?;
    }

    match p
        .get("recipient")
        .and_then(Value::as_str)
        .and_then(safe_recipient)
    {
        Some(label) => writeln!(out, "\n  recipient:  {label}")?,
        None => writeln!(out, "\n  recipient:  (not identified)")?,
    }
    if let Some(why) = p.get("blocked_reason").and_then(Value::as_str) {
        writeln!(out, "  blocked:    {}", safe_text(why))?;
    }

    writeln!(out, "\n  limits:")?;
    if let Some(b) = num("read_ceiling_bytes") {
        writeln!(out, "    at most {b} bytes are read by one operation")?;
    }
    if let Some(b) = num("observation_ceiling_bytes") {
        writeln!(
            out,
            "    at most {b} bytes are disclosed per provider request, in total"
        )?;
    }
    if let Some(n) = num("max_entries") {
        writeln!(
            out,
            "    at most {n} observations are released per provider request"
        )?;
    }
    if let Some(b) = num("effective_bytes") {
        writeln!(out, "    the effective per-request capacity is {b} bytes")?;
    }
    let limits = dtext("limits");
    if !limits.is_empty() {
        writeln!(out, "    {limits}")?;
    }
    let timing = dtext("timing");
    if !timing.is_empty() {
        writeln!(out, "    {timing}")?;
    }
    writeln!(
        out,
        "    observations are never truncated to fit: one too large for the budget is skipped whole"
    )?;
    writeln!(
        out,
        "    eligible content is available only to the immediately following logical step"
    )?;
    Ok(())
}

/// Whether a line is an explicit affirmative.
///
/// The default is **no**. Only `y` or `yes`, trimmed and compared case-insensitively,
/// are accepted. An empty line, `n`, `no`, anything unrecognised, EOF and a read
/// error all decline.
pub(crate) fn parse_confirmation(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Reads one line and decides whether the operator accepted.
///
/// `Ok(false)` means declined -- which includes EOF. `Err` is a read failure, and
/// it also declines: no approval may be submitted on either.
pub(crate) fn read_confirmation(input: &mut dyn std::io::BufRead) -> Result<bool, String> {
    let mut line = String::new();
    match input.read_line(&mut line) {
        Ok(0) => Ok(false),
        Ok(_) => Ok(parse_confirmation(&line)),
        Err(e) => Err(format!("could not read the confirmation: {e}")),
    }
}

/// The requests the approval orchestration makes.
///
/// The real client and the test fake both satisfy it, so the sequence the tests
/// record is the sequence production runs -- not a second implementation of it.
pub(crate) trait PreviewRequests {
    /// Performs one request and returns its `result` value.
    fn call(&self, method: &str, params: Value) -> Result<Value, ClientError>;
}

impl PreviewRequests for Client {
    fn call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        Client::call(self, method, params)
    }
}

/// The approval orchestration for a proposal, as one testable function.
///
/// # The sequence
///
/// inspection (no challenge) -> terminal check -> fresh preview (with a challenge) ->
/// render -> confirm -> approve with that challenge and `confirmed: true`.
///
/// The terminal check sits **before** the challenge-bearing preview, so a
/// non-interactive caller never leaves a challenge behind in the bounded store.
///
/// # Why the inspection comes first
///
/// The inspection carries no challenge and only classifies the proposal, so the
/// client knows whether a reviewed confirmation is needed at all before it takes one.
/// The fresh preview is what is displayed and what the challenge comes from: a
/// preview shown to the operator and a challenge submitted must describe the same
/// thing.
pub(crate) fn approve_proposal_with(
    requests: &impl PreviewRequests,
    interactive: bool,
    input: &mut dyn std::io::BufRead,
    out: &mut dyn std::io::Write,
    proposal_id: &str,
    payload: &mut Value,
) -> Result<Option<Value>, ClientError> {
    // Inspection first. It carries no challenge, so a client that turns out not to
    // need a confirmation has not left one behind in the bounded store.
    let inspected = requests.call(
        "capability/preview",
        json!({ "proposal": proposal_id, "inspect_only": true }),
    )?;
    let kind =
        classify_proposal(&inspected).map_err(|why| ClientError::InvalidParams { detail: why })?;
    if kind == ProposalKind::ModelInitiatedFileRead {
        // The terminal check comes **before** a challenge-bearing preview, so a
        // non-interactive caller never mints a challenge it cannot use.
        if !interactive {
            return Err(ClientError::InvalidParams {
                detail: "approving a model-generated file read needs an interactive \
                          confirmation: the read's contents may be disclosed to the \
                          model provider, and that has to be accepted at a terminal."
                    .to_owned(),
            });
        }
        // The fresh preview is authoritative for what is displayed and for the
        // challenge that is submitted; the inspection above is only a
        // classification.
        let fresh = requests.call("capability/preview", json!({ "proposal": proposal_id }))?;
        let fresh_kind =
            classify_proposal(&fresh).map_err(|why| ClientError::InvalidParams { detail: why })?;
        if fresh_kind != ProposalKind::ModelInitiatedFileRead {
            return Err(ClientError::InvalidParams {
                detail: "the proposal changed between the inspection and the review; \
                          nothing was approved."
                    .to_owned(),
            });
        }
        if fresh["preview"]
            .get("approval_allowed")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return Err(ClientError::InvalidParams {
                detail: fresh["preview"]
                    .get("blocked_reason")
                    .and_then(Value::as_str)
                    .unwrap_or("this read cannot currently be approved")
                    .to_owned(),
            });
        }
        let challenge = fresh["preview"]
            .get("challenge")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ClientError::Malformed(
                    "the preview carried no challenge, so the read cannot be reviewed".to_owned(),
                )
            })?
            .to_owned();

        render_read_preview(&fresh, out)
            .map_err(|e| ClientError::Malformed(format!("could not render the preview: {e}")))?;
        write!(
            out,
            "\n  Authorise this read, and the disclosure of its contents to the \
             recipient above? [y/N] "
        )
        .map_err(|e| ClientError::Malformed(format!("could not write the prompt: {e}")))?;
        std::io::Write::flush(out)
            .map_err(|e| ClientError::Malformed(format!("could not write the prompt: {e}")))?;
        let accepted = read_confirmation(input).unwrap_or(false);
        if !accepted {
            // Nothing is sent. The challenge that was taken expires on its own.
            return Ok(None);
        }
        payload["challenge"] = json!(challenge);
        payload["confirmed"] = json!(true);
    }

    // The approval is submitted **here**, so that the whole journey -- inspection,
    // the review, and the approval -- is one observable orchestration. A caller that
    // only classified the proposal and then returned would leave the direct and
    // non-read routes with no approval at all.
    let reply = requests.call("capability/approve", payload.clone())?;
    Ok(Some(reply))
}

/// Renders a proposal from a `task/propose` or `task/execute` reply.
fn render_proposal(reply: &Value) -> String {
    let Some(p) = reply.get("proposal") else {
        return "no proposal in reply\n".to_owned();
    };
    let field = |k: &str| p.get(k).map_or_else(|| "-".to_owned(), Value::to_string);
    let mut out = String::new();
    out.push_str("proposal\n");
    out.push_str(&format!("  id: {}\n", field("proposal_id")));
    out.push_str(&format!("  task: {}\n", field("task_id")));
    out.push_str(&format!("  attempt: {}\n", field("attempt_no")));
    out.push_str(&format!("  capability: {}\n", field("capability")));
    out.push_str(&format!("  status: {}\n", field("status")));
    out.push_str(&format!("  params: {}\n", field("params")));
    if let Some(w) = reply.get("waiting_for").and_then(Value::as_str) {
        out.push_str(&format!("  waiting_for: {w}\n"));
    }
    out
}

/// Renders `task/cancel`.
///
/// The heading is chosen from the state the **daemon** reported, not from the fact
/// that a cancel was requested. The two differ: cancelling an already-terminal task is
/// a no-op that succeeds, so a client that printed `cancelled` unconditionally would be
/// reporting something that is not true of a task that was already `completed`.
///
/// This is one comparison against a wire value, not a rule about which states are
/// cancellable — that set belongs to the engine, and re-deriving it here is how a
/// client starts disagreeing with its daemon.
fn render_cancel(reply: &Value) -> String {
    let cancelled = reply
        .get("cancelled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let heading = if cancelled { "cancelled" } else { "unchanged" };
    let mut out = render_task_field(reply, heading);
    if !cancelled {
        out.push_str("  (the daemon reported this task as already terminal)\n");
    }
    out
}

/// Renders the fields of a single task, from the daemon's own projection.
///
/// Reads the wire representation and prints it. It does not interpret: `state` is
/// printed as the word the daemon used, not as one this build maps to a colour or a
/// number, because a mapping table here is a rule that can disagree with the daemon's.
fn render_task_field(reply: &Value, heading: &str) -> String {
    let Some(task) = reply.get("task") else {
        return format!("{heading}: the daemon returned no task\n");
    };
    let mut out = format!("{heading}\n");
    for (label, key) in [
        ("id", "id"),
        ("kind", "kind"),
        ("state", "state"),
        ("attempts", "attempts"),
        ("steps_completed", "steps_completed"),
        ("max_steps", "max_steps"),
    ] {
        if let Some(v) = task.get(key) {
            out.push_str(&format!("  {label}: {}\n", scalar(v)));
        }
    }
    if let Some(content) = task.get("content") {
        out.push_str(&format!("  content: {}\n", scalar(content)));
    }
    out
}

/// Renders `task/list`.
///
/// The order is the daemon's, passed through untouched: re-sorting client-side would
/// be the client inventing a ranking the daemon did not ask for, and the two could
/// disagree.
fn render_list(reply: &Value) -> String {
    let empty = vec![];
    let tasks = reply
        .get("tasks")
        .and_then(Value::as_array)
        .unwrap_or(&empty);

    if tasks.is_empty() {
        return "no tasks\n".to_owned();
    }

    let header = ["ID", "STATE", "KIND", "ATTEMPTS", "CONTENT"];
    let rows: Vec<[String; 5]> = tasks
        .iter()
        .map(|t| {
            [
                text(t, "id"),
                text(t, "state"),
                text(t, "kind"),
                text(t, "attempts"),
                text(t, "content"),
            ]
        })
        .collect();

    // Column widths from the data, so nothing is truncated and nothing is guessed.
    let mut widths = header.map(str::len);
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let mut out = String::new();
    let line = |cells: &[String; 5], widths: &[usize; 5]| -> String {
        let mut s = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                s.push_str(cell);
            } else {
                s.push_str(&format!("{:width$}  ", cell, width = widths[i]));
            }
        }
        s.trim_end().to_owned()
    };
    let header_cells: [String; 5] = std::array::from_fn(|i| header[i].to_owned());
    out.push_str(&line(&header_cells, &widths));
    for row in &rows {
        out.push('\n');
        out.push_str(&line(row, &widths));
    }
    out.push('\n');
    out
}

/// Renders `task/claim`.
///
/// `lease_expires_at_ms` is printed because the daemon decided it — the CLI cannot
/// compute an expiry and does not try. `attempt` likewise: it is the daemon's count,
/// reported rather than predicted.
fn render_claim(reply: &Value) -> String {
    let mut out = String::from("claimed\n");
    if let Some(task) = reply.get("task") {
        for (label, key) in [("id", "id"), ("state", "state"), ("worker", "lease_holder")] {
            if let Some(v) = task.get(key) {
                out.push_str(&format!("  {label}: {}\n", scalar(v)));
            }
        }
    }
    // `attempt` rather than the row's cumulative `attempts`: they are the same number
    // here, and printing both reads as a disagreement. The claim's own count is the
    // one that answers "which attempt is this".
    if let Some(n) = reply.get("attempt") {
        out.push_str(&format!("  attempt: {}\n", scalar(n)));
    }
    if let Some(ms) = reply.get("lease_expires_at_ms") {
        out.push_str(&format!(
            "  lease expires (ms since epoch): {}\n",
            scalar(ms)
        ));
    }
    out
}

/// The `task` field of a reply, as text, or a dash when absent.
///
/// A dash rather than an empty string, so a blank cell in a table is visibly blank
/// rather than looking like a formatting slip.
fn text(task: &Value, key: &str) -> String {
    match task.get(key) {
        None | Some(Value::Null) => "-".to_owned(),
        Some(v) => scalar(v),
    }
}

/// A JSON value as one line of terminal text.
///
/// Strings print bare; a missing `content` is a dash. Multi-line content is shown on
/// one line rather than being reformatted, because the CLI is not a renderer and a
/// user comparing against what they typed should see exactly what is stored.
fn scalar(v: &Value) -> String {
    match v {
        Value::Null => "-".to_owned(),
        Value::String(s) if s.is_empty() => "-".to_owned(),
        Value::String(s) => s.replace(['\n', '\r'], " "),
        other => other.to_string(),
    }
}

/// Runs `capability run` and returns what to print.
///
/// # What the CLI does not decide
///
/// Whether the capability exists, is enabled, is granted, is permitted, needs an
/// approval or has a credential is **entirely** the daemon's answer. This function
/// builds a request from two strings and renders a reply; it holds no capability list,
/// no risk table and no idea what any particular capability's parameters mean. That is
/// what keeps "the CLI is not a second policy engine" structural rather than aspirational.
///
/// # Parameters are passed through verbatim
///
/// `--params` is forwarded as written and the *daemon* parses it. The CLI does not
/// validate the JSON against a schema, because it has no schema and inventing one would
/// be the second definition this design exists to avoid. A malformed value is the
/// daemon's structured refusal to report.
pub fn run_capability(
    capability: &str,
    params: &str,
    target: Option<&str>,
    approval: Option<&str>,
    client: &Client,
) -> Result<(String, bool), ClientError> {
    let params: Value = serde_json::from_str(params).map_err(|e| ClientError::InvalidParams {
        detail: format!("`--params` is not valid JSON: {e}"),
    })?;
    // Parsed here so a malformed approval is a local, explanatory error rather than a
    // round trip that fails somewhere inside the daemon. It is still untrusted: the
    // daemon recomputes the digest from the parameters it is about to run.
    let approval: Option<Value> = match approval {
        None => None,
        Some(text) => Some(
            serde_json::from_str(text).map_err(|e| ClientError::InvalidParams {
                detail: format!("`--approval` is not valid JSON: {e}"),
            })?,
        ),
    };
    client.negotiate()?;

    let mut payload = json!({ "capability": capability, "params": params });
    if let Some(t) = target {
        payload["target"] = json!(t);
    }
    if let Some(a) = approval {
        payload["approval"] = a;
    }
    let reply = client.call("capability/dispatch", payload)?;

    // The exit status follows the **daemon's** verdict rather than anything decided
    // here. Reporting exit 0 for an execution that failed or was never verified would
    // make a script believe a capability ran when it did not, which is the failure mode
    // the whole verification stage exists to prevent. This is not a policy judgement:
    // the server already decided, and this only propagates what it said.
    // `failure` is always present in the reply and is null when there is none, so the
    // test is for a non-null value rather than for the key being absent.
    let succeeded = reply.get("verified").and_then(Value::as_bool) == Some(true)
        && reply.get("failure").is_none_or(Value::is_null);
    Ok((render_capability(capability, &reply), succeeded))
}

/// Asks the daemon for an approval of one proposed operation.
///
/// Returns the approval object as JSON text, which is what `--approval` on
/// [`run_capability`] takes. Deliberately not interpreted here: the client cannot
/// evaluate a digest it has no business computing, and printing a decoded digest would
/// invite someone to hand-assemble one. The object is carried, not understood.
///
/// Nothing is granted by this. The daemon consults no policy and touches no ledger; the
/// result is an artefact whose digest the dispatcher will later recompute from the
/// action it is actually about to run.
pub fn approve_capability(
    capability: Option<&str>,
    params: Option<&str>,
    proposal: Option<&str>,
    target: Option<&str>,
    ttl_ms: Option<i64>,
    client: &Client,
) -> Result<String, ClientError> {
    client.negotiate()?;

    // A proposal carries its own action, so nothing else is sent — which is what makes
    // the approved action unforgeable by the caller.
    let payload = match (proposal, capability) {
        (Some(p), _) => json!({ "proposal": p }),
        (None, Some(c)) => {
            let raw = params.ok_or_else(|| ClientError::InvalidParams {
                detail: "`--params` is required with `--capability`".to_owned(),
            })?;
            let parsed: Value =
                serde_json::from_str(raw).map_err(|e| ClientError::InvalidParams {
                    detail: format!("`--params` is not valid JSON: {e}"),
                })?;
            json!({ "capability": c, "params": parsed })
        }
        (None, None) => {
            return Err(ClientError::InvalidParams {
                detail: "either --proposal or --capability is required".to_owned(),
            });
        }
    };
    let mut payload = payload;
    if let Some(t) = target {
        payload["target"] = json!(t);
    }
    if let Some(ttl) = ttl_ms {
        payload["ttl_ms"] = json!(ttl);
    }
    let reply = if let Some(proposal_id) = proposal {
        match approve_proposal_with(
            client,
            std::io::IsTerminal::is_terminal(&std::io::stdin()),
            &mut std::io::stdin().lock(),
            &mut std::io::stdout(),
            proposal_id,
            &mut payload,
        )? {
            Some(reply) => reply,
            None => return Ok("Declined: nothing was approved.".to_owned()),
        }
    } else {
        // A standalone approval names its own action and has no proposal to review.
        client.call("capability/approve", payload)?
    };

    let approval = reply.get("approval").ok_or_else(|| {
        ClientError::Malformed("the daemon's approval reply carried no `approval` field".to_owned())
    })?;
    // Round-tripped rather than concatenated, so the text handed to `--approval` is
    // exactly the structure the daemon produced.
    serde_json::to_string_pretty(approval)
        .map_err(|e| ClientError::Malformed(format!("the approval could not be re-rendered: {e}")))
}

/// Renders a `capability/dispatch` reply.
///
/// The three verification states are printed distinctly, because they are not the same
/// answer: `verified` means an independent check agreed, `refuted` means it disagreed,
/// and `undetermined` means nobody could tell. Collapsing them into a boolean would
/// discard the distinction the pipeline exists to preserve.
///
/// No policy internals, no approval internals and no audit hashes are printed — none of
/// them are in the reply, and inventing them for display would mean the CLI
/// reconstructing server-side state.
fn render_capability(capability: &str, reply: &Value) -> String {
    let mut out = format!("capability: {capability}\n");
    let flag = |k: &str| reply.get(k).and_then(Value::as_bool).unwrap_or(false);
    out.push_str(&format!("verified: {}\n", flag("verified")));
    if flag("undetermined") {
        out.push_str("undetermined: true\n");
    }
    if flag("refuted") {
        out.push_str("refuted: true\n");
    }
    // A failed execution's own reason, which is where a rejected parameter shows up.
    // Reported separately from the verdict so "your input was wrong" is not reported
    // as "the effect was disproved".
    if let Some(reason) = reply.get("failure").and_then(Value::as_str) {
        out.push_str(&format!("failure: {reason}\n"));
    }
    if let Some(Value::Object(fields)) = reply.get("result") {
        for (key, value) in fields {
            out.push_str(&format!("{key}: {}\n", scalar(value)));
        }
    }
    out
}

/// Turns a refusal into the line a user reads.
///
/// The **reason** is shown, not the most specific string available. `reason` is the fixed
/// vocabulary word the daemon sends for exactly this purpose, and a client — or a person —
/// is meant to be able to branch on it. Preferring the detail hides the vocabulary
/// behind prose, which is the opposite of what a reason is for. The detail is appended
/// when it says something the reason does not.
#[must_use]
pub fn describe_refusal(error: &ClientError) -> String {
    match error {
        ClientError::Refused {
            code,
            message,
            reason,
            detail,
        } => {
            let reason = reason.as_deref().unwrap_or("refused");
            let line =
                format!("error: the daemon refused the request ({code}, {reason}): {message}");
            match detail {
                Some(detail) if detail != message && !detail.is_empty() => {
                    format!("{line}\n  {detail}")
                }
                _ => line,
            }
        }
        other => format!("error: {other}"),
    }
}

/// Builds the refusal for a response the client has already decoded.
///
/// # Errors
///
/// Always `Err`, carrying [`ClientError::Refused`].
pub fn refuse(error: &orxnud_protocol::RpcError) -> Result<Value, ClientError> {
    Err(refusal(error))
}

#[cfg(test)]
mod recipient_rendering_tests {
    use super::render_recipient;
    use serde_json::json;

    /// An identified recipient is shown, and the raw endpoint is never a fallback.
    #[test]
    fn an_identified_recipient_is_rendered_and_no_raw_endpoint_appears() {
        let reply = json!({
            "recipient": "https://api.example.invalid:8443/v1 (model: some-model)",
            "recipient_status": "identified",
        });
        let mut out = String::new();
        render_recipient(&reply, &mut out);
        assert!(out.contains("recipient:"), "{out}");
        assert!(out.contains("api.example.invalid"), "{out}");
        assert!(!out.contains("secret"), "{out}");
    }

    /// An unavailable recipient is stated plainly: the content cannot be disclosed.
    #[test]
    fn an_unavailable_recipient_says_disclosure_is_unavailable() {
        let reply = json!({ "recipient": null, "recipient_status": "unavailable" });
        let mut out = String::new();
        render_recipient(&reply, &mut out);
        assert!(out.contains("cannot be safely identified"), "{out}");
        assert!(out.contains("disclosure is unavailable"), "{out}");
    }

    /// The canaries of a rejected endpoint never reach the output, because the client
    /// is never given a raw endpoint to print.
    #[test]
    fn a_rejected_destination_never_reaches_the_output() {
        let canary_userinfo = "user:CANARY-USERINFO-4b1e";
        let canary_query = "CANARY-QUERY-TOKEN-9d2c";
        let canary_fragment = "CANARY-FRAGMENT-77aa";
        let reply = json!({ "recipient": null, "recipient_status": "unavailable" });
        let mut out = String::new();
        render_recipient(&reply, &mut out);
        for canary in [canary_userinfo, canary_query, canary_fragment] {
            assert!(!out.contains(canary), "a canary reached the output: {out}");
        }
    }
}

#[cfg(test)]
mod disclosure_preview_tests {
    use super::*;
    use serde_json::json;

    /// A complete, eligible model-initiated file-read preview.
    fn read_preview() -> Value {
        json!({
            "preview": {
                "proposal_id": "p-1",
                "task_id": "t-1",
                "capability": "filesystem/read-text",
                "path": "src/main.rs",
                "operation": "file-read",
                "proposal_kind": "model-initiated-file-read",
                "requires_confirmation": true,
                "approval_allowed": true,
                "recipient": "https://api.example.invalid/v1 (model: some-model)",
                "recipient_status": "identified",
                "read_ceiling_bytes": 65536,
                "observation_ceiling_bytes": 32768,
                "max_entries": 8,
                "effective_bytes": 32768,
                "disclosure": {
                    "read_ceiling_bytes": 65536,
                    "observation_ceiling_bytes": 32768,
                    "max_entries": 8,
                    "effective_bytes": 32768,
                    "limits": "an observation that does not fit the applicable budget is skipped entirely, not truncated",
                    "timing": "eligibility is limited to the immediately following logical step",
                },
            }
        })
    }

    #[test]
    fn only_an_explicit_yes_accepts() {
        assert!(parse_confirmation("y"));
        assert!(parse_confirmation("yes"));
        assert!(parse_confirmation("Y"));
        assert!(parse_confirmation("YES"));
        assert!(parse_confirmation("  Yes  "));
    }

    #[test]
    fn everything_else_declines() {
        for line in [
            "", "   ", "n", "no", "N", "NO", "yep", "y yes", "approve", "1", "true",
        ] {
            assert!(!parse_confirmation(line), "{line:?} must decline");
        }
    }

    #[test]
    fn eof_and_a_read_error_decline() {
        let mut empty = std::io::Cursor::new(b"".as_slice());
        assert!(
            !read_confirmation(&mut empty).expect("EOF is not an error"),
            "EOF must decline"
        );

        let mut text = std::io::Cursor::new(
            b"yes
"
            .as_slice(),
        );
        assert!(
            read_confirmation(&mut text).expect("a read"),
            "a read must accept"
        );

        let mut text = std::io::Cursor::new(
            b"nope
"
            .as_slice(),
        );
        assert!(
            !read_confirmation(&mut text).expect("a read"),
            "unrecognised input must decline"
        );
    }

    #[test]
    fn the_classification_is_read_from_the_server() {
        assert_eq!(
            classify_proposal(&read_preview()).expect("classified"),
            ProposalKind::ModelInitiatedFileRead
        );

        let mut direct = read_preview();
        direct["preview"]["proposal_kind"] = json!("direct-proposal");
        direct["preview"]["requires_confirmation"] = json!(false);
        assert_eq!(
            classify_proposal(&direct).expect("classified"),
            ProposalKind::DirectProposal
        );

        let mut other = read_preview();
        other["preview"]["proposal_kind"] = json!("model-initiated");
        other["preview"]["requires_confirmation"] = json!(false);
        assert_eq!(
            classify_proposal(&other).expect("classified"),
            ProposalKind::ModelInitiated
        );
    }

    #[test]
    fn an_unknown_or_inconsistent_classification_fails_closed() {
        let mut unknown = read_preview();
        unknown["preview"]["proposal_kind"] = json!("something-else");
        assert!(
            classify_proposal(&unknown).is_err(),
            "an unknown kind must fail closed"
        );

        let mut inconsistent = read_preview();
        inconsistent["preview"]["requires_confirmation"] = json!(false);
        assert!(
            classify_proposal(&inconsistent).is_err(),
            "a model-initiated read that does not require confirmation must fail closed"
        );

        let mut wrong_operation = read_preview();
        wrong_operation["preview"]["operation"] = json!("file-write");
        assert!(
            classify_proposal(&wrong_operation).is_err(),
            "a model-initiated file read must not claim to be a write"
        );

        let mut missing = read_preview();
        missing["preview"]
            .as_object_mut()
            .expect("an object")
            .remove("proposal_kind");
        assert!(
            classify_proposal(&missing).is_err(),
            "a missing kind must fail closed"
        );

        assert!(
            classify_proposal(&json!({})).is_err(),
            "a reply with no preview must fail closed"
        );
    }

    #[test]
    fn the_rendered_preview_carries_everything_the_operator_needs() {
        let mut out: Vec<u8> = Vec::new();
        render_read_preview(&read_preview(), &mut out).expect("rendered");
        let text = String::from_utf8(out).expect("utf-8");
        for expected in [
            "p-1",
            "filesystem/read-text",
            "src/main.rs",
            "READS a file",
            "MAY BE DISCLOSED",
            "https://api.example.invalid/v1 (model: some-model)",
            "65536",
            "32768",
            "not truncated",
            "immediately following logical step",
        ] {
            assert!(
                text.contains(expected),
                "the preview must contain {expected:?}:\n{text}"
            );
        }
    }

    #[test]
    fn a_direct_proposal_is_not_described_as_a_model_disclosure() {
        let mut preview = read_preview();
        preview["preview"]["proposal_kind"] = json!("direct-proposal");
        preview["preview"]["requires_confirmation"] = json!(false);
        let mut out: Vec<u8> = Vec::new();
        render_read_preview(&preview, &mut out).expect("rendered");
        let text = String::from_utf8(out).expect("utf-8");
        assert!(
            !text.contains("MAY BE DISCLOSED"),
            "a direct proposal must not be described as a model disclosure: {text}"
        );
    }

    #[test]
    fn canaries_never_reach_the_output_and_control_characters_are_escaped() {
        let mut preview = read_preview();
        preview["preview"]["path"] = json!("a\u{1b}[31mplain-path.txt");
        preview["preview"]["recipient"] = json!(
            "https://user:CANARY-USERINFO-4b1e@host/v1?token=CANARY-QUERY-9d2c#CANARY-FRAG-77aa"
        );
        let mut out: Vec<u8> = Vec::new();
        render_read_preview(&preview, &mut out).expect("rendered");
        let text = String::from_utf8(out).expect("utf-8");
        for canary in [
            "CANARY-USERINFO-4b1e",
            "CANARY-QUERY-9d2c",
            "CANARY-FRAG-77aa",
        ] {
            assert!(
                !text.contains(canary),
                "a canary reached the output: {text}"
            );
        }
        // The escape sequence must not survive as control characters.
        assert!(
            !text.contains('\u{1b}'),
            "an escape sequence reached the output"
        );
        assert!(
            text.contains("\\u{1b}"),
            "the control character must be shown as a code point: {text}"
        );
    }
}

#[cfg(test)]
mod approval_sequence_tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    /// A recording request caller, standing in for the client.
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

    /// An inspection reply: the classification, and no challenge.
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

    /// A challenge-bearing reply.
    fn fresh_preview(challenge: &str) -> Value {
        let mut v = inspection("model-initiated-file-read", true, "file-read");
        v["preview"]["challenge"] = json!(challenge);
        v
    }

    fn ok_approval() -> Result<Value, ClientError> {
        Ok(json!({ "approval": { "digest": "abc" } }))
    }

    /// The whole sequence, and the challenge that is actually submitted.
    #[test]
    fn the_model_read_sequence_is_inspection_then_preview_then_confirmation_then_approval() {
        let recorder = Recorder::new(vec![
            Ok(inspection("model-initiated-file-read", true, "file-read")),
            Ok(fresh_preview("challenge-fresh")),
            ok_approval(),
        ]);
        let mut input = std::io::Cursor::new(
            b"y
"
            .as_slice(),
        );
        let mut out: Vec<u8> = Vec::new();
        let mut payload = json!({ "proposal": "p-1", "ttl_ms": 60_000 });

        let approved =
            approve_proposal_with(&recorder, true, &mut input, &mut out, "p-1", &mut payload)
                .expect("approved");
        assert!(approved.is_some(), "the approval must have been submitted");

        // The exact order.
        assert_eq!(
            recorder.methods(),
            vec![
                "capability/preview".to_owned(),
                "capability/preview".to_owned(),
                "capability/approve".to_owned(),
            ],
            "the sequence must be inspection, then the fresh preview, then the approval"
        );
        let calls = recorder.calls();
        assert_eq!(
            calls[0].1["inspect_only"],
            json!(true),
            "the first preview must be an inspection"
        );
        assert!(
            calls[0].1.get("challenge").is_none(),
            "the inspection must not ask for a challenge"
        );
        assert!(
            calls[1].1.get("inspect_only").is_none(),
            "the second preview must be the challenge-bearing one"
        );

        // The approval carries the fresh challenge and the confirmation.
        assert_eq!(payload["proposal"], json!("p-1"));
        assert_eq!(payload["ttl_ms"], json!(60_000));
        assert_eq!(payload["challenge"], json!("challenge-fresh"));
        assert_eq!(payload["confirmed"], json!(true));
        // And nothing the caller could have used to override daemon state.
        for forbidden in ["recipient", "fingerprint", "path", "capability", "endpoint"] {
            assert!(
                payload.get(forbidden).is_none(),
                "the approval must not carry {forbidden:?}: {payload}"
            );
        }

        // The preview was rendered before the confirmation was consumed.
        let rendered = String::from_utf8(out).expect("utf-8");
        assert!(rendered.contains("src/main.rs"), "{rendered}");
        assert!(rendered.contains("READS a file"), "{rendered}");
    }

    /// A decline, and every other way of not saying yes, submits nothing.
    #[test]
    fn a_decline_submits_no_approval() {
        for answer in ["\n", "n\n", "no\n", "maybe\n", ""] {
            let recorder = Recorder::new(vec![
                Ok(inspection("model-initiated-file-read", true, "file-read")),
                Ok(fresh_preview("challenge-fresh")),
            ]);
            let mut input = std::io::Cursor::new(answer.as_bytes());
            let mut out: Vec<u8> = Vec::new();
            let mut payload = json!({ "proposal": "p-1" });
            let approved =
                approve_proposal_with(&recorder, true, &mut input, &mut out, "p-1", &mut payload)
                    .expect("no error");
            assert!(approved.is_none(), "{answer:?} must decline");
            assert!(
                payload.get("challenge").is_none(),
                "a decline must not submit an approval: {payload}"
            );
            assert_eq!(
                recorder.methods(),
                vec![
                    "capability/preview".to_owned(),
                    "capability/preview".to_owned()
                ],
                "{answer:?}: no approval request may be sent"
            );
        }
    }

    /// A non-interactive caller must not take a challenge at all.
    #[test]
    fn a_non_interactive_caller_takes_no_challenge_and_submits_nothing() {
        let recorder = Recorder::new(vec![Ok(inspection(
            "model-initiated-file-read",
            true,
            "file-read",
        ))]);
        let mut input = std::io::Cursor::new(
            b"y
"
            .as_slice(),
        );
        let mut out: Vec<u8> = Vec::new();
        let mut payload = json!({ "proposal": "p-1" });
        let err =
            approve_proposal_with(&recorder, false, &mut input, &mut out, "p-1", &mut payload)
                .expect_err("a non-interactive caller must fail closed");
        assert!(format!("{err:?}").contains("interactive"), "{err:?}");
        assert_eq!(
            recorder.methods(),
            vec!["capability/preview".to_owned()],
            "only the inspection may have happened"
        );
        assert!(payload.get("challenge").is_none(), "{payload}");
    }

    /// A direct proposal keeps its established route: one inspection, then the ordinary
    /// approval, exactly once, with no challenge and no confirmation.
    ///
    /// This is the regression the previous revision of this test could not see: it
    /// exercised only the classification helper, so the approval submission -- which the
    /// caller performed -- was invisible, and a broken route would have looked correct.
    #[test]
    fn a_direct_proposal_keeps_its_established_approval_route() {
        let recorder = Recorder::new(vec![
            Ok(inspection("direct-proposal", false, "file-read")),
            ok_approval(),
        ]);
        let mut input = std::io::Cursor::new(b"y\n".as_slice());
        let mut out: Vec<u8> = Vec::new();
        let mut payload = json!({ "proposal": "p-1", "ttl_ms": 60_000 });
        let reply =
            approve_proposal_with(&recorder, true, &mut input, &mut out, "p-1", &mut payload)
                .expect("no error")
                .expect("the direct proposal must be approved");
        assert!(reply.get("approval").is_some(), "{reply}");
        assert_eq!(
            recorder.methods(),
            vec![
                "capability/preview".to_owned(),
                "capability/approve".to_owned()
            ],
            "a direct proposal must keep its established approval route"
        );
        let calls = recorder.calls();
        assert_eq!(
            calls[0].1["inspect_only"],
            json!(true),
            "the first preview must be an inspection"
        );
        let approve = &calls[1].1;
        assert_eq!(approve["proposal"], json!("p-1"));
        assert_eq!(approve["ttl_ms"], json!(60_000));
        assert!(approve.get("challenge").is_none(), "{approve}");
        assert!(approve.get("confirmed").is_none(), "{approve}");
    }

    /// A model-initiated capability that is not a file read keeps its route too.
    #[test]
    fn an_unrelated_model_capability_keeps_its_established_approval_route() {
        let recorder = Recorder::new(vec![
            Ok(inspection("model-initiated", false, "other")),
            ok_approval(),
        ]);
        let mut input = std::io::Cursor::new(b"y\n".as_slice());
        let mut out: Vec<u8> = Vec::new();
        let mut payload = json!({ "proposal": "p-1", "ttl_ms": 60_000 });
        approve_proposal_with(&recorder, true, &mut input, &mut out, "p-1", &mut payload)
            .expect("no error")
            .expect("the proposal must be approved");
        assert_eq!(
            recorder.methods(),
            vec![
                "capability/preview".to_owned(),
                "capability/approve".to_owned()
            ],
            "an unrelated model capability must keep its established approval route"
        );
        let calls = recorder.calls();
        assert!(calls[1].1.get("challenge").is_none(), "{:?}", calls[1].1);
        assert!(calls[1].1.get("confirmed").is_none(), "{:?}", calls[1].1);
    }

    /// A blocked inspection, a request failure and a malformed reply each submit no
    /// approval at all.
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
            let mut input = std::io::Cursor::new(b"y\n".as_slice());
            let mut out: Vec<u8> = Vec::new();
            let mut payload = json!({ "proposal": "p-1" });
            assert!(
                approve_proposal_with(&recorder, true, &mut input, &mut out, "p-1", &mut payload)
                    .is_err(),
                "a failed inspection must fail closed"
            );
            assert!(
                !recorder
                    .calls()
                    .iter()
                    .any(|(m, _)| m == "capability/approve"),
                "no approval may be sent"
            );
        }
    }

    /// A blocked or inconsistent fresh preview submits nothing.
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
            let mut input = std::io::Cursor::new(
                b"y
"
                .as_slice(),
            );
            let mut out: Vec<u8> = Vec::new();
            let mut payload = json!({ "proposal": "p-1" });
            let result =
                approve_proposal_with(&recorder, true, &mut input, &mut out, "p-1", &mut payload);
            assert!(result.is_err(), "a blocked preview must fail closed");
            assert!(payload.get("challenge").is_none(), "{payload}");
            assert_eq!(
                recorder.methods(),
                vec![
                    "capability/preview".to_owned(),
                    "capability/preview".to_owned()
                ],
                "no approval may be sent"
            );
        }
    }
}
