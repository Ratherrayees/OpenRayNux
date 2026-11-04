//! Regression for CONC-002: worker names do not identify one lease acquisition.

use orxnud_domain::actor::Actor;
use orxnud_domain::actor::SystemComponent;
use orxnud_domain::task_state::TaskState;
use orxnud_domain::{CapabilityId, TaskId, TaskKind};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::{ClaimedTask, NewTask};
use orxnud_task::{DurableEngine, EngineLimits};
use rusqlite::Connection;

const NOW: i64 = 1_767_225_600_000;

fn task_id() -> TaskId {
    TaskId::new("conc002-same-name")
}

fn engine() -> DurableEngine {
    let conn = Connection::open_in_memory().expect("open in-memory database");
    Pragma::critical()
        .apply(&conn)
        .expect("apply required pragmas");
    MigrationRunner::new(&conn)
        .migrate_ephemeral()
        .expect("migrate schema");
    DurableEngine::new(conn, EngineLimits::documented()).expect("construct engine")
}

fn claim(engine: &mut DurableEngine, now_ms: i64) -> ClaimedTask {
    let outcome = engine
        .claim_task_id(&task_id(), "same-worker", now_ms)
        .expect("claim must not fail");
    match outcome {
        orxnud_task::engine::ClaimAttempt::Claimed(claim) => *claim,
        orxnud_task::engine::ClaimAttempt::Refused(reason) => {
            panic!("task should be claimable, got {reason:?}")
        }
    }
}

#[test]
fn same_name_reclaim_rejects_old_claim_operations() {
    let mut engine = engine();
    engine
        .enqueue_new(&NewTask::new(task_id(), TaskKind::Query, NOW), NOW)
        .expect("enqueue");

    let first = claim(&mut engine, NOW);
    assert_eq!(first.attempt_no, 1);

    assert_eq!(engine.recover(NOW + 1).expect("recover"), 1);
    let replacement = claim(&mut engine, NOW + 2);
    assert_eq!(replacement.attempt_no, 2);
    assert_ne!(first.claim_generation, replacement.claim_generation);

    // Stale completion from the first claim must not mutate the replacement claim.
    let stale_completion = engine
        .complete_task(
            &task_id(),
            "same-worker",
            first.claim_generation,
            NOW + 3,
            TaskState::Completed,
            false,
            Some("stale worker result"),
        )
        .expect("a fencing refusal is a value, not a storage failure");
    assert!(!stale_completion);

    // Stale heartbeat must not renew the replacement lease.
    let stale_heartbeat = engine
        .heartbeat(&task_id(), "same-worker", first.claim_generation, NOW + 3)
        .expect("a fencing refusal is a value, not a storage failure");
    assert!(!stale_heartbeat);

    // Stale proposal write must not persist.
    let stale_proposal = engine.propose_action(
        "p-stale",
        &task_id(),
        "same-worker",
        first.claim_generation,
        &CapabilityId::new("filesystem/write-text"),
        Some("out.txt"),
        "{}",
        &Actor::System {
            component: SystemComponent::HealthCheck,
        },
        NOW + 3,
    );
    assert!(stale_proposal.is_err());

    let current = engine
        .task(&task_id())
        .expect("read task")
        .expect("task exists");
    assert_eq!(current.state, TaskState::Running);
    assert_eq!(current.lease_holder.as_deref(), Some("same-worker"));
    assert_eq!(current.attempts, replacement.attempt_no);
    assert_eq!(
        current.lease_expires_at_ms,
        Some(replacement.lease_expires_at_ms)
    );

    // The current claim remains usable.
    assert!(
        engine
            .heartbeat(
                &task_id(),
                "same-worker",
                replacement.claim_generation,
                NOW + 4,
            )
            .expect("current heartbeat")
    );
    assert!(
        engine
            .complete_task(
                &task_id(),
                "same-worker",
                replacement.claim_generation,
                NOW + 5,
                TaskState::Completed,
                false,
                None,
            )
            .expect("current completion")
    );
}
