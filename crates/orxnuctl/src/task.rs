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
        TaskCommand::Create { id, kind, content } => {
            let mut params = json!({ "id": id });
            if let Some(k) = kind {
                params["kind"] = json!(k);
            }
            if let Some(c) = content {
                params["content"] = json!(c);
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
        TaskCommand::Complete { id, worker } => {
            let reply = client.call("task/complete", json!({ "id": id, "worker": worker }))?;
            Ok(render_task_field(&reply, "completed"))
        }
    }
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

/// Turns a refusal into the line a user reads.
///
/// The structured reason is preferred over the daemon's prose, because the daemon sends
/// `reason` as a fixed word for exactly this purpose. The code is included so a script
/// can see what happened without parsing the message.
#[must_use]
pub fn describe_refusal(error: &ClientError) -> String {
    match error {
        ClientError::Refused { code, message, .. } => {
            let reason = error.structured_reason().unwrap_or("refused");
            format!("error: the daemon refused the request ({code}, {reason}): {message}")
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
