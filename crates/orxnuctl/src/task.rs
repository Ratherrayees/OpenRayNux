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
    /// Cancel a task.
    ///
    /// No worker identity, because the engine does not want one: cancellation is a
    /// decision about the task and clears whatever lease it holds, so a cancel that
    /// had to name a worker could not cancel an unclaimed task at all.
    Cancel {
        /// The task id.
        id: String,
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
        TaskCommand::Cancel { id } => {
            let reply = client.call("task/cancel", json!({ "id": id }))?;
            Ok(render_cancel(&reply))
        }
    }
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
    capability: &str,
    params: &str,
    target: Option<&str>,
    ttl_ms: Option<i64>,
    client: &Client,
) -> Result<String, ClientError> {
    let params: Value = serde_json::from_str(params).map_err(|e| ClientError::InvalidParams {
        detail: format!("`--params` is not valid JSON: {e}"),
    })?;
    client.negotiate()?;

    let mut payload = json!({ "capability": capability, "params": params });
    if let Some(t) = target {
        payload["target"] = json!(t);
    }
    if let Some(ttl) = ttl_ms {
        payload["ttl_ms"] = json!(ttl);
    }
    let reply = client.call("capability/approve", payload)?;

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
