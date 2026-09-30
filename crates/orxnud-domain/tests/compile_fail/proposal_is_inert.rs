//! A `Proposal` must not be able to reach a capability.
//!
//! If this file ever compiles, the deterministic boundary in ADR-0012 has been
//! breached: something the model produced could invoke a capability directly,
//! bypassing validation, policy, and approval.
//!
//! Note the failure must be *on the method*, not on the import. A file that
//! fails to compile for the wrong reason would satisfy a naive "does it fail?"
//! check while proving nothing.

use orxnud_domain::actor::ModelProvenance;
use orxnud_domain::ids::{RunId, TaskId};
use orxnud_domain::{IntentKind, Proposal};

fn main() {
    let proposal = Proposal {
        task: TaskId::from("t-1"),
        run: RunId::from("r-1"),
        intent: IntentKind::Act,
        steps: Vec::new(),
        rationale: "attempted escape".to_owned(),
        confidence: 1.0,
        provenance: ModelProvenance::new("m", "p", orxnud_domain::ids::RequestId::from("q")),
    };

    // None of these exist. The error the compiler reports is the evidence.
    let _ = proposal.execute();
}
