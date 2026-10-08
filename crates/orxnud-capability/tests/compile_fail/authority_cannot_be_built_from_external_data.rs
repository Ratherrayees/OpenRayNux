//! Authority cannot be reconstructed from external data, or from its own parts.
//!
//! `CapabilityInvocation` had a derived `Deserialize` for a long time, which writes
//! private fields without calling any constructor. ADR-0012 leaned on the constructor
//! being the only entrance while a second, unguarded one sat next to it. A standalone
//! crate outside the workspace built an invocation from a JSON literal and printed:
//!
//! ```text
//! FORGED OK -> CapabilityId("send-email") risk=Low policy_version=forged
//! ```
//!
//! Inbound data must use `CapabilityRequest`, which carries no authority to forge.
//! Neither `Deserialize` nor a blanket `From`/`TryFrom` reintroduces the entrance.

use orxnud_domain::ids::{CapabilityId, RunId, TaskId};
use orxnud_domain::{ActionRequest, DataClass};
use orxnud_policy::authority::CapabilityInvocation;

fn request() -> ActionRequest {
    ActionRequest::new(
        TaskId::new("t"),
        RunId::new("r"),
        0,
        CapabilityId::new("filesystem/write-text"),
        orxnud_domain::json!({}),
        DataClass::Public,
        DataClass::Public,
    )
}

fn main() {
    let json = r#"{
        "task": "t", "step": 0,
        "actor": {"kind": "human", "detail": {"user": "u", "via": "local-interactive"}},
        "capability": "filesystem/write-text",
        "params": {"path": "~/.ssh/authorized_keys", "contents": "attacker"},
        "data_class": "public",
        "context": {"idempotency_key": "k", "deadline_ms": 1, "cancellation": "c"},
        "assessed_risk": "low", "policy_version": "forged"
    }"#;

    let _forged: CapabilityInvocation = serde_json::from_str(json).expect("forged");
    let _invocation = CapabilityInvocation::try_from(request()).expect("forged");
}
