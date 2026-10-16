//! The `schedule` verbs.
//!
//! # Why these exist
//!
//! `TaskService::tick` and `next_wakeup_ms` were implemented and tested, and
//! `Scheduler::add_schedule` had no route at all — so no schedule could ever be
//! registered and the daemon's timer had nothing to fire. This is the client half of
//! closing that, and it is deliberately thin: a schedule is a row the daemon owns, so
//! every decision about what a valid schedule is belongs to the daemon. `timezone`
//! defaults to `UTC` here only because it has to be *a* value to send, and the daemon
//! documents that default in its own reply so a client cannot rely on it silently.

use crate::ScheduleCommand;
use crate::client::Client;
use serde_json::{Value, json};

/// Runs one `schedule` verb against the daemon.
///
/// # Errors
///
/// [`crate::client::ClientError`] from the transport, or the daemon's own structured
/// refusal, rendered as the message a person reads.
pub fn run(verb: &ScheduleCommand, client: &Client) -> Result<String, crate::client::ClientError> {
    match verb {
        ScheduleCommand::Add { id, cron, timezone } => {
            let mut params = json!({ "id": id, "cron": cron });
            if let Some(tz) = timezone {
                params["timezone"] = json!(tz);
            }
            let reply = client.call("schedule/create", params)?;
            Ok(render_added(&reply))
        }
        ScheduleCommand::List => {
            let reply = client.call("schedule/list", json!({}))?;
            Ok(render_list(&reply))
        }
    }
}

fn render_added(reply: &Value) -> String {
    let schedule = reply.get("schedule").and_then(Value::as_str).unwrap_or("?");
    let cron = reply.get("cron").and_then(Value::as_str).unwrap_or("?");
    let tz = reply.get("timezone").and_then(Value::as_str).unwrap_or("?");
    let next = reply
        .get("next_wakeup_ms")
        .and_then(Value::as_i64)
        .map_or_else(|| "none".to_owned(), |ms| ms.to_string());
    format!(
        "registered\n  id: {schedule}\n  cron: {cron}\n  timezone: {tz}\n  \
         next wakeup (ms since epoch): {next}\n"
    )
}

fn render_list(reply: &Value) -> String {
    let rows = reply
        .get("schedules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let next = reply
        .get("next_wakeup_ms")
        .and_then(Value::as_i64)
        .map_or_else(|| "none".to_owned(), |ms| ms.to_string());
    if rows.is_empty() {
        return format!(
            "no schedules are registered; the daemon's timer is idle\nnext wakeup (ms since epoch): {next}\n"
        );
    }
    let mut out = String::from("ID  CRON  TIMEZONE  LAST FIRED\n");
    for r in rows {
        out.push_str(&format!(
            "{}  {}  {}  {}\n",
            r.get("id").and_then(Value::as_str).unwrap_or("?"),
            r.get("cron").and_then(Value::as_str).unwrap_or("?"),
            r.get("timezone").and_then(Value::as_str).unwrap_or("?"),
            r.get("last_fired_ms")
                .and_then(Value::as_i64)
                .map_or_else(|| "-".to_owned(), |ms| ms.to_string()),
        ));
    }
    out.push_str(&format!("next wakeup (ms since epoch): {next}\n"));
    out
}
