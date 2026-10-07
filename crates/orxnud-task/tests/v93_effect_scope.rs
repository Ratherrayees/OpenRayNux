//! V-93 follow-up: recovery must reason about the execution that was interrupted.
//!
//! # The defect
//!
//! `recover()` asked whether a task held *any* effect row that was not `not-performed`
//! and was flagged non-idempotent. That is a question about the whole task. The question
//! it needs to answer is about one execution: the `(step, attempt)` that was interrupted.
//!
//! The two differ because `tasks.attempts` counts attempts *within the current logical
//! step* and is reset to `0` at every step boundary — so step 1's first attempt and
//! step 2's first attempt are both `attempt_no = 1` — and because
//! `filesystem/read-text` and `filesystem/write-text` both deliberately leave
//! `idempotent` false.
//!
//! The consequence: a *verified* effect from a **completed earlier step** made the whole
//! task unrecoverable, and `NeedsVerification` is terminal and unclaimable. A two-step
//! task that completed a read in step 1 and then crashed in step 2 could never be
//! recovered again, no matter what step 2 had or had not done.
//!
//! # What is asserted
//!
//! Ten cases, each stated as *what recovery must decide* rather than as a description of
//! the implementation. Tests 1, 5 and 6 have no equivalent anywhere in the suite before
//! this file: every pre-existing recovery test is single-step, so none of them could
//! have detected this.
//!
//! Every fixture builds its state through the production operations. No test writes a
//! `task_effects` row by hand, because a hand-written row would prove only that SQL does
//! what the test's author expected.

use std::path::{Path, PathBuf};

use orxnud_domain::ids::TaskId;
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::{EffectStatus, TaskRepository};
use orxnud_task::{DurableEngine, EngineLimits};
use rusqlite::Connection;

/// Fixed, so every assertion is about the transition and not a clock that moved.
const NOW: i64 = 1_767_225_600_000;
const LEASE_MS: i64 = 30_000;
const LATER: i64 = NOW + 3_600_000;

/// A capability that deliberately declares itself non-idempotent — `read-text` does,
/// because "a read has no effect to be idempotent about", and `write-text` does because
/// it offers no compare-before-write. Under the task-scoped predicate either one is
/// enough to wedge a whole task, which is what these tests exist to disprove.
const NON_IDEMPOTENT: &str = "filesystem/read-text";
/// The only capability that declares itself idempotent.
const IDEMPOTENT: &str = "text/word-count";

/// The lease holder every governed fixture runs as.
const WORKER: &str = "w1";

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("orxnud-v93-scope-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn db_in(d: &Path) -> PathBuf {
    d.join("state.db")
}

fn tid(s: &str) -> TaskId {
    TaskId::new(s)
}

fn open_engine(path: &Path) -> DurableEngine {
    let conn = Connection::open(path).expect("open");
    Pragma::critical().apply(&conn).expect("pragmas");
    Pragma::critical().verify(&conn).expect("verify pragmas");
    MigrationRunner::new(&conn).run(true).expect("migrate");
    DurableEngine::new(conn, EngineLimits::documented()).expect("engine")
}

fn open_raw(path: &Path) -> Connection {
    let conn = Connection::open(path).expect("open");
    Pragma::critical().apply(&conn).expect("pragmas");
    MigrationRunner::new(&conn).run(true).expect("migrate");
    conn
}

/// Enqueues a task with `max_steps`, so a multi-step fixture is built by configuration
/// rather than by mutating counters afterwards.
fn enqueue(e: &mut DurableEngine, id: &str, steps: i64) {
    e.enqueue_new(
        &orxnud_store::task_repo::NewTask::new(tid(id), TaskKind::Workflow, NOW),
        NOW,
    )
    .expect("enqueue");
    if steps != 1 {
        e.conn()
            .execute(
                "UPDATE tasks SET max_steps = ?2 WHERE id = ?1;",
                rusqlite::params![id, steps],
            )
            .expect("configure step count");
    }
}

/// Reserves an effect through the production reservation, with the step and attempt the
/// caller's execution actually is.
fn reserve(
    e: &mut DurableEngine,
    id: &str,
    step_no: u32,
    attempt_no: u32,
    capability: &str,
    idempotent: bool,
    at_ms: i64,
) {
    let key =
        DurableEngine::idempotency_key(&tid(id), capability, &format!("{step_no}/{attempt_no}"));
    assert!(
        e.reserve_effect(
            &key,
            &tid(id),
            step_no,
            attempt_no,
            capability,
            idempotent,
            at_ms
        )
        .expect("reserve"),
        "the first reservation for {id} step {step_no} attempt {attempt_no} must succeed"
    );
}

fn resolve(
    e: &mut DurableEngine,
    id: &str,
    step_no: u32,
    attempt_no: u32,
    capability: &str,
    status: EffectStatus,
    at_ms: i64,
) {
    let key =
        DurableEngine::idempotency_key(&tid(id), capability, &format!("{step_no}/{attempt_no}"));
    assert!(
        e.resolve_effect(&key, status, None, at_ms)
            .expect("resolve"),
        "resolving {id} step {step_no} attempt {attempt_no} must change a row"
    );
}

/// Advances the task across a step boundary exactly as production does: a verified step
/// result, which resets the attempt counter.
fn complete_step(e: &mut DurableEngine, id: &str, step_no: u32, max_steps: u32) {
    let proposal = format!("proposal-{step_no}");
    {
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.propose_action(
            &proposal,
            &tid(id),
            // The lease holder. `propose_action` refuses anyone else, which is the
            // fence that stops a task being steered while another worker owns it.
            WORKER,
            NON_IDEMPOTENT,
            Some("in.txt"),
            r#"{"path":"in.txt"}"#,
            r#"{"kind":"human"}"#,
            None,
            step_no,
            NOW,
        )
        .expect("propose");
        repo.decide_proposal(&proposal, "approved", NOW)
            .expect("approve");
        repo.record_approval(&orxnud_store::task_repo::ApprovalRow {
            task_id: tid(id),
            step_no,
            attempt_no: 1,
            digest_hex: "ab".repeat(32),
            capability: NON_IDEMPOTENT.to_owned(),
            target: Some("in.txt".to_owned()),
            params: r#"{"path":"in.txt"}"#.to_owned(),
            issued_at_ms: NOW,
            expires_at_ms: LATER,
            consumed_at_ms: None,
        })
        .expect("record approval");
        // Spend the approval and take the lease in one operation, which is what
        // production does before it dispatches.
        repo.begin_execution_spending_approval(&proposal, WORKER, NOW, LEASE_MS)
            .expect("begin execution");
    }
    // A verified outcome for the step: this is the only thing that advances the counter,
    // and it resets `attempts` to 0 on the boundary.
    let done = orxnud_store::task_repo::VerifiedStep {
        task_id: tid(id),
        worker: WORKER,
        step_no,
        proposal_id: &format!("proposal-{step_no}"),
        status: orxnud_store::task_repo::StepStatus::Verified,
        verification: Some("verified".to_owned()),
        structured_output: None,
        artifacts: None,
        recorded_at_ms: NOW + 1,
    };
    let advance = e
        .complete_verified_step(&done)
        .expect("complete verified step");
    assert_eq!(advance.step_no, step_no);
    assert_eq!(
        advance.state,
        if advance.steps_completed < max_steps {
            TaskState::AwaitingNextStep
        } else {
            TaskState::Completed
        },
        "a verified step must advance the counter and land on the right side of the \
         boundary, got {advance:?}"
    );
}

/// Asserts the whole terminal contract of an uncertain task.
fn assert_uncertain(e: &mut DurableEngine, id: &str, why: &str) {
    let row = e.task(&tid(id)).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::NeedsVerification,
        "{why}: the interrupted execution may have changed the world, so it must not be \
         retried automatically. got {:?}",
        row.state
    );
    assert!(
        row.state.is_terminal(),
        "{why}: uncertainty is terminal. A state that is terminal but not claimable, or \
         claimable but not terminal, would each be a different bug: {row:?}"
    );
    assert!(
        !row.state.is_claimable(),
        "{why}: an uncertain task must be unclaimable or a worker will re-run it: {row:?}"
    );
    assert!(
        e.claim_task("greedy-worker", LATER)
            .expect("claim")
            .is_none(),
        "{why}: no worker may claim an uncertain task, so a non-idempotent effect cannot \
         be duplicated by the retry path"
    );
}

/// Asserts the task is recoverable, without consuming the claim. Used where the test
/// goes on to claim it itself; [`assert_recoverable`] claims as part of its check.
fn assert_pending(e: &mut DurableEngine, id: &str, why: &str) {
    let row = e.task(&tid(id)).expect("read").expect("present");
    assert_eq!(row.state, TaskState::Pending, "{why}: got {:?}", row.state);
    assert!(
        row.lease_holder.is_none(),
        "{why}: the lease must be released: {row:?}"
    );
    assert!(
        row.state.is_claimable(),
        "{why}: pending is the claimable state: {row:?}"
    );
}

/// Asserts the whole recoverable contract.
fn assert_recoverable(e: &mut DurableEngine, id: &str, why: &str) {
    let row = e.task(&tid(id)).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::Pending,
        "{why}: nothing about the interrupted execution prevents a retry, so the task \
         must be claimable again. got {:?}",
        row.state
    );
    assert!(
        row.lease_holder.is_none(),
        "{why}: the lease must be released: {row:?}"
    );
    assert!(
        e.claim_task("next-worker", LATER).expect("claim").is_some(),
        "{why}: a recoverable task must actually be claimable, not merely non-terminal"
    );
}

// ============================================================ 1. earlier-step evidence

/// **Test 1 — the primary bug.** Step 1 ran a non-idempotent capability and its effect
/// was verified. Step 2 began and the worker died before reserving anything.
///
/// Recovery must return the task to `pending`. Step 1's verified effect is settled
/// history; it says nothing about step 2, which provably never dispatched.
///
/// Before the fix this produced `needs-verification` — permanently, because the state is
/// terminal.
#[test]
fn a_verified_effect_from_a_completed_earlier_step_does_not_wedge_the_task() {
    let d = dir("earlier-step-evidence");
    let db = db_in(&d);

    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 2);

        // Step 1: non-idempotent capability, effect reserved and verified.
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        assert_eq!(claimed.attempts, 1);
        reserve(&mut e, "t", 1, 1, NON_IDEMPOTENT, false, NOW);
        resolve(
            &mut e,
            "t",
            1,
            1,
            NON_IDEMPOTENT,
            EffectStatus::Observed,
            NOW + 1,
        );
        drop(claimed);

        // Cross the boundary into step 2. Production resets `attempts` to 0 here, so
        // step 2's first attempt is *also* attempt 1 — the collision that made the
        // task-scoped predicate unable to tell the two steps apart.
        complete_step(&mut e, "t", 1, 2);
        let row = e.task(&tid("t")).expect("read").expect("present");
        assert_eq!(row.state, TaskState::AwaitingNextStep);
        assert_eq!(row.steps_completed, 1);
        assert_eq!(
            row.attempts, 0,
            "the attempt counter resets at the boundary; this is what made \
             `attempt_no = 1` ambiguous across steps"
        );

        // Step 2: claimed, then the worker dies before reserving anything.
        let second = e
            .claim_next_step(&tid("t"), "w2", NOW + 2)
            .expect("boundary claim");
        assert!(
            !matches!(
                second,
                orxnud_store::task_repo::TargetedClaimOutcome::Refused(_)
            ),
            "step 2 must be claimable: {second:?}"
        );
        let row = e.task(&tid("t")).expect("read").expect("present");
        assert_eq!(row.state, TaskState::Running);
        assert_eq!(row.attempts, 1, "step 2's first attempt is attempt 1 again");
    }

    let mut e = open_engine(&db);
    let recovered = e.recover(LATER).expect("recovery");
    assert_eq!(
        recovered, 1,
        "the orphaned lease was reclaimed exactly once"
    );
    assert_recoverable(&mut e, "t", "Test 1: a completed step's effect is history");

    // And nothing claimed it as uncertain on the way.
    let settling = TaskRepository::new_readonly(e.conn())
        .all_events()
        .expect("events")
        .iter()
        .filter(|ev| ev.kind.as_str().contains("needs-verification"))
        .count();
    assert_eq!(
        settling, 0,
        "no event may claim this task became uncertain. A task that is merely recoverable \
         must not leave an audit record saying a person has to decide"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ================================================ 2. current unresolved non-idempotent

/// **Test 2 — the property V-93 exists to protect.** The *current* step and attempt
/// reserved a non-idempotent effect and dispatched; the process died before the outcome
/// was recorded.
///
/// Recovery must settle it into `needs-verification`. This is the case the whole design
/// is for, and the scoping fix must not weaken it.
#[test]
fn an_unresolved_current_non_idempotent_effect_is_never_retried() {
    let d = dir("current-unresolved-non-idempotent");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 1);
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        // Reserved and dispatched; nothing resolved it.
        reserve(&mut e, "t", 1, claimed.attempts, NON_IDEMPOTENT, false, NOW);
    }

    let mut e = open_engine(&db);
    e.recover(LATER).expect("recovery");
    assert_uncertain(
        &mut e,
        "t",
        "Test 2: the effect of the interrupted execution may have fired, and it may not \
         be repeated",
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The same, two steps in, to prove the scope is *current step* and not merely
/// "an effect exists somewhere".
#[test]
fn an_unresolved_current_non_idempotent_effect_is_detected_in_step_two() {
    let d = dir("current-unresolved-step-two");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 2);
        e.claim_task("w1", NOW).expect("claim").expect("claimable");
        complete_step(&mut e, "t", 1, 2);
        let second = e
            .claim_next_step(&tid("t"), "w2", NOW + 2)
            .expect("boundary claim");
        assert!(!matches!(
            second,
            orxnud_store::task_repo::TargetedClaimOutcome::Refused(_)
        ));
        let attempt = e.task(&tid("t")).expect("read").expect("present").attempts;
        // Step 2, attempt 1, unresolved and non-idempotent.
        reserve(&mut e, "t", 2, attempt, NON_IDEMPOTENT, false, NOW + 3);
    }

    let mut e = open_engine(&db);
    e.recover(LATER).expect("recovery");
    assert_uncertain(
        &mut e,
        "t",
        "Test 2b: scoping to the current step must not stop detecting an unresolved \
         effect in step 2 — the collision with step 1's attempt 1 is exactly what the \
         step number disambiguates",
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ==================================================== 3. current unresolved idempotent

/// **Test 3.** The same interruption, but the capability declares itself idempotent, so
/// repeating it cannot duplicate anything.
#[test]
fn an_unresolved_current_idempotent_effect_stays_retryable() {
    let d = dir("current-unresolved-idempotent");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 1);
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        reserve(&mut e, "t", 1, claimed.attempts, IDEMPOTENT, true, NOW);
    }

    let mut e = open_engine(&db);
    e.recover(LATER).expect("recovery");
    assert_recoverable(
        &mut e,
        "t",
        "Test 3: an effect declared idempotent cannot be duplicated by repeating it, so \
         uncertainty about its outcome is not a reason to stop",
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ============================================================ 4. previous attempt

/// **Test 4.** Within one step: attempt 1 left an unresolved non-idempotent effect, then
/// a second attempt began and was itself interrupted.
///
/// Recovery must reason from the *current* attempt. Two sub-cases, because they point
/// opposite ways and only one of them is safe:
///
/// * attempt 2 also reserved an **idempotent** effect → retryable, because attempt 1's
///   row is not the execution being recovered and attempt 2's own row says repeating is
///   safe;
/// * attempt 2 also reserved a **non-idempotent** effect → uncertain, and it must be
///   uncertain because of *attempt 2's* row, not attempt 1's.
///
/// The first sub-case is the one a stale-row implementation gets wrong in the dangerous
/// direction.
#[test]
fn recovery_reasons_from_the_current_attempt_not_a_stale_one() {
    // --- attempt 2 interrupted on an idempotent effect: attempt 1 must not decide it.
    let d = dir("stale-attempt-idempotent");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 1);
        let first = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        // Attempt 1: unresolved, non-idempotent. Never resolved, so it stays pending.
        reserve(&mut e, "t", 1, first.attempts, NON_IDEMPOTENT, false, NOW);
        // The lease expires and recovery puts it back on the queue.
        e.conn()
            .execute(
                "UPDATE tasks SET state = 'pending', lease_holder = NULL, \
                   lease_expires_at_ms = NULL WHERE id = 't';",
                [],
            )
            .expect("simulate lease expiry");
        let second = e
            .claim_task("w2", NOW + 10)
            .expect("claim")
            .expect("claimable");
        assert_eq!(second.attempts, 2, "a second claim advances the counter");
        // Attempt 2: unresolved, but idempotent.
        reserve(&mut e, "t", 1, second.attempts, IDEMPOTENT, true, NOW + 11);
    }

    let mut e = open_engine(&db);
    e.recover(LATER).expect("recovery");
    assert_recoverable(
        &mut e,
        "t",
        "Test 4a: attempt 1's unresolved row must not decide attempt 2. Attempt 2's own \
         row says repeating is safe, and that is the execution recovery is asked about",
    );
    let _ = std::fs::remove_dir_all(&d);

    // --- attempt 2 interrupted on a non-idempotent effect: uncertain, for attempt 2's row.
    let d = dir("stale-attempt-non-idempotent");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 1);
        let first = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        reserve(&mut e, "t", 1, first.attempts, NON_IDEMPOTENT, false, NOW);
        resolve(
            &mut e,
            "t",
            1,
            first.attempts,
            NON_IDEMPOTENT,
            EffectStatus::NotPerformed,
            NOW + 1,
        );
        e.conn()
            .execute(
                "UPDATE tasks SET state = 'pending', lease_holder = NULL, \
                   lease_expires_at_ms = NULL WHERE id = 't';",
                [],
            )
            .expect("simulate lease expiry");
        let second = e
            .claim_task("w2", NOW + 10)
            .expect("claim")
            .expect("claimable");
        assert_eq!(second.attempts, 2);
        reserve(
            &mut e,
            "t",
            1,
            second.attempts,
            NON_IDEMPOTENT,
            false,
            NOW + 11,
        );
    }

    let mut e = open_engine(&db);
    e.recover(LATER).expect("recovery");
    assert_uncertain(
        &mut e,
        "t",
        "Test 4b: attempt 1 was disproved and attempt 2 is unresolved, so the task is \
         uncertain on attempt 2's evidence alone",
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The converse, and the one that would be a false *negative* if the attempt scope were
/// wrong in the other direction: a stale earlier-attempt row must not be *ignored* when
/// it is the only live evidence.
///
/// It is asserted through the reachable path rather than by constructing the state. The
/// tempting fixture is "attempt 1 unresolved, attempt 2 disproved, expect uncertainty" —
/// and that state cannot occur, because an unresolved effect row can only exist while its
/// task is `running` under a lease, and the only ways out of `running` all resolve the
/// row or adjudicate it first:
///
///   * `recover()` examines the row before returning the task to the queue;
///   * `complete_verified_step` needs a `Verified` result, which follows `resolve_effect`;
///   * `complete_with` is only reached once `dispatch` has returned, and every exit from
///     a dispatch that reached the capability resolves the row first;
///   * a `dispatch` *error* returns immediately, leaving the task `running` and leased.
///
/// So attempt 1's row is adjudicated by the recovery pass that admits attempt 2, and
/// attempt-scoped matching cannot drop evidence that nothing else will ever re-examine.
/// This test walks that sequence and asserts each step.
#[test]
fn an_unresolved_attempt_is_adjudicated_before_a_later_attempt_can_exist() {
    let d = dir("adjudicated-before-next-attempt");
    let db = db_in(&d);

    // Attempt 1: an unresolved non-idempotent effect.
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 1);
        let first = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        assert_eq!(first.attempts, 1);
        reserve(&mut e, "t", 1, first.attempts, NON_IDEMPOTENT, false, NOW);
    }

    // The lease is lost. Recovery is the only route back to the queue, and it must
    // adjudicate attempt 1's row rather than pass over it.
    {
        let mut e = open_engine(&db);
        e.recover(LATER).expect("recovery");
        assert_uncertain(
            &mut e,
            "t",
            "an unresolved non-idempotent effect on attempt 1 must be settled here,              before any later attempt can exist. If this ever returned `pending`,              attempt-scoped matching would be dropping evidence that nothing else re-examines",
        );
    }

    // So attempt 2 cannot start, and the task cannot be made to retry by asking.
    {
        let mut e = open_engine(&db);
        assert!(
            e.claim_task("w2", LATER + 1).expect("claim").is_none(),
            "there is no attempt 2: the task was settled, not requeued"
        );
        assert_eq!(
            e.recover(LATER + 2).expect("second recovery"),
            0,
            "and a second pass finds nothing, because the state is terminal"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// The narrower version, which *is* reachable and which is what makes attempt-scoping
/// worth having: an earlier attempt that was **disproved**, followed by an interrupted
/// attempt 2 whose own effect is idempotent.
///
/// Attempt 1's row is excluded on status, so attempt 2's row decides — and attempt 2's
/// row says retrying is safe. Attempt 4a above is the same shape; this one pins that the
/// disproof is what makes the earlier row irrelevant, rather than its attempt number.
#[test]
fn a_disproved_earlier_attempt_does_not_decide_a_later_one() {
    let d = dir("disproved-earlier-attempt");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 1);
        let first = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        reserve(&mut e, "t", 1, first.attempts, NON_IDEMPOTENT, false, NOW);
        resolve(
            &mut e,
            "t",
            1,
            first.attempts,
            NON_IDEMPOTENT,
            EffectStatus::NotPerformed,
            NOW + 1,
        );
        // Attempt 1 is safely requeued by recovery.
        e.recover(LATER).expect("recovery");
        assert_pending(&mut e, "t", "a disproved attempt 1 is retryable");

        // Attempt 2 reserves an idempotent effect and is interrupted.
        let second = e
            .claim_task("w2", LATER + 1)
            .expect("claim")
            .expect("claimable");
        assert_eq!(second.attempts, 2);
        reserve(&mut e, "t", 1, second.attempts, IDEMPOTENT, true, LATER + 2);
    }

    let mut e = open_engine(&db);
    e.recover(LATER + 3).expect("recovery");
    assert_recoverable(
        &mut e,
        "t",
        "attempt 2's own row is the one that decides it, and it says repeating is safe",
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ====================================================== 5. previous-step unknown effect

/// **Test 5.** Step 1 left an *unresolved* (not merely verified) effect. Step 2 is the
/// current step and is interrupted before reserving anything.
///
/// Recovery must return the task to `pending`: step 2's execution never dispatched, so
/// retrying step 2 cannot duplicate step 1's effect — it would not re-run step 1 at all.
#[test]
fn an_unresolved_earlier_step_effect_does_not_contaminate_the_current_step() {
    let d = dir("earlier-step-unknown");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 2);
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        // Step 1 reserved and never resolved. The boundary is crossed by hand here
        // because production cannot cross it while an effect is unresolved -- so this
        // state is one only a stale ledger can produce, which is exactly why the
        // tolerance has to be tested.
        reserve(&mut e, "t", 1, claimed.attempts, NON_IDEMPOTENT, false, NOW);
        e.conn()
            .execute(
                "UPDATE tasks SET state = 'awaiting-next-step', steps_completed = 1, \
                   attempts = 0, lease_holder = NULL, lease_expires_at_ms = NULL, \
                   effect_observed = 1 WHERE id = 't';",
                [],
            )
            .expect("force the boundary");
        let second = e
            .claim_next_step(&tid("t"), "w2", NOW + 2)
            .expect("boundary claim");
        assert!(!matches!(
            second,
            orxnud_store::task_repo::TargetedClaimOutcome::Refused(_)
        ));
    }

    let mut e = open_engine(&db);
    e.recover(LATER).expect("recovery");
    assert_recoverable(
        &mut e,
        "t",
        "Test 5: step 2 never dispatched, so retrying it cannot duplicate step 1's \
         effect. Step 1's row is history however unresolved it is",
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ================================================= 7. an effect that is disproved

/// **Test 7.** The current step's effect was explicitly disproved, which is the one
/// finding a retry cannot duplicate. The task must stay retryable.
#[test]
fn a_disproved_current_effect_leaves_the_task_retryable() {
    let d = dir("not-performed");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 1);
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        reserve(&mut e, "t", 1, claimed.attempts, NON_IDEMPOTENT, false, NOW);
        resolve(
            &mut e,
            "t",
            1,
            claimed.attempts,
            NON_IDEMPOTENT,
            EffectStatus::NotPerformed,
            NOW + 1,
        );
    }

    let mut e = open_engine(&db);
    e.recover(LATER).expect("recovery");
    assert_recoverable(
        &mut e,
        "t",
        "Test 7: a disproved effect is the one finding a retry cannot duplicate, so it is \
         excluded from the uncertainty predicate",
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ================================================= 8. uncertainty is genuinely terminal

/// **Test 8.** `needs-verification` has no automatic exit. Asserted directly rather than
/// inferred, because "terminal" and "unclaimable" are two different claims and a state
/// that was one without the other would be a different defect.
#[test]
fn uncertainty_is_terminal_unclaimable_and_has_no_automatic_exit() {
    let d = dir("terminal");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 1);
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        reserve(&mut e, "t", 1, claimed.attempts, NON_IDEMPOTENT, false, NOW);
    }
    {
        let mut e = open_engine(&db);
        e.recover(LATER).expect("recovery");
        assert_uncertain(&mut e, "t", "Test 8");
    }

    // A second recovery pass must not resurrect it, and must not report work done.
    let mut e = open_engine(&db);
    let again = e.recover(LATER + 1).expect("second recovery");
    assert_eq!(
        again, 0,
        "an uncertain task is terminal, so a second pass has nothing to settle"
    );
    let row = e.task(&tid("t")).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::NeedsVerification,
        "and it must still be uncertain rather than having drifted back to claimable"
    );

    // There is no sanctioned exit, and that is asserted rather than assumed.
    //
    // `request_cancel` is the obvious candidate and it does not work: its first
    // transaction returns early for any terminal state, and its second excludes
    // `needs-verification` from the states it will move to `cancelled`. So the state has
    // no transition out of it anywhere in the repository.
    //
    // Asserted because it is the reason the task-scoping defect was P1 rather than P2:
    // a task wedged here is not merely inconvenient, it is unrecoverable through every
    // path the product exposes, and the only remedy is editing the row.
    {
        let mut repo = TaskRepository::new(e.conn_mut());
        repo.request_cancel(&tid("t"), LATER + 2)
            .expect("cancel must be accepted, not refused");
    }
    let row = e.task(&tid("t")).expect("read").expect("present");
    assert_eq!(
        row.state,
        TaskState::NeedsVerification,
        "cancelling is a no-op on a terminal state, so uncertainty has no exit at all. \
         If this ever changes it must be a deliberate decision, not a side effect"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ================================================== 9. concurrent recovery

/// **Test 9.** Two connections recover the same orphaned task. Exactly one settling
/// transition may be recorded, and the loser must be told there was nothing to do rather
/// than being handed an unexplained error.
#[test]
fn two_workers_recovering_one_orphan_produce_one_settling_transition() {
    let d = dir("concurrent-recovery");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 1);
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        reserve(&mut e, "t", 1, claimed.attempts, NON_IDEMPOTENT, false, NOW);
    }

    let results: Vec<_> = (0..4)
        .map(|_| {
            let p = db.clone();
            std::thread::spawn(move || {
                let mut e = open_engine(&p);
                e.recover(LATER).map_err(|e| e.to_string())
            })
        })
        .collect();
    let settled: usize = results
        .into_iter()
        .map(|h| {
            h.join().expect("recovery thread").unwrap_or_else(|e| {
                panic!("a losing recovery failed rather than finding nothing: {e}")
            })
        })
        .sum::<u64>() as usize;
    assert_eq!(
        settled, 1,
        "four recoveries over one orphan must settle it once. More than one would mean \
         the log claims the task moved more than once"
    );

    let e = open_engine(&db);
    let transitions = TaskRepository::new_readonly(e.conn())
        .all_events()
        .expect("events")
        .iter()
        .filter(|ev| ev.kind.as_str().contains("recovered"))
        .count();
    assert_eq!(
        transitions, 1,
        "exactly one settling transition on the record, whatever order the workers ran in"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ============================== 10. the row survives a process boundary, read on reopen

/// **Test 10, storage half.** The reservation is durable and the step is on it before
/// anything is dispatched, so a process that dies has left a row that recovery can read.
///
/// The *process-death* half of this test is
/// `crash_recovery_uncertainty::v93_uncertainty_holds_when_recovery_races_claims_and_a_second_recovery`,
/// which uses a real `SIGKILL`. This one asserts the durable shape, because a step
/// boundary plus a crash is the case this milestone fixes and it needs its own evidence
/// rather than the single-step case's.
#[test]
fn a_reservation_is_durable_across_a_reopen_and_names_its_step() {
    let d = dir("durable-step");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 2);
        e.claim_task("w1", NOW).expect("claim").expect("claimable");
        complete_step(&mut e, "t", 1, 2);
        let second = e
            .claim_next_step(&tid("t"), "w2", NOW + 2)
            .expect("boundary claim");
        assert!(!matches!(
            second,
            orxnud_store::task_repo::TargetedClaimOutcome::Refused(_)
        ));
        let attempt = e.task(&tid("t")).expect("read").expect("present").attempts;
        reserve(&mut e, "t", 2, attempt, NON_IDEMPOTENT, false, NOW + 3);
    }

    // Reopened by a different connection, as a restarted daemon would be.
    let conn = open_raw(&db);
    let (step_no, attempt_no, idempotent, status): (i64, i64, i64, String) = conn
        .query_row(
            "SELECT step_no, attempt_no, idempotent, status FROM task_effects
              WHERE task_id = 't';",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("the reservation survived the reopen");
    assert_eq!(step_no, 2, "the row names the step it was reserved for");
    assert_eq!(attempt_no, 1, "and the attempt within that step");
    assert_eq!(idempotent, 0, "and the capability's repeat-safety");
    assert_eq!(
        status, "pending",
        "and is still unresolved, which is the evidence"
    );

    // And recovery, on this reopened connection, reaches the same verdict.
    drop(conn);
    let mut e = open_engine(&db);
    e.recover(LATER).expect("recovery");
    assert_uncertain(
        &mut e,
        "t",
        "Test 10: the reopened database sees the unresolved step-2 reservation and acts \
         on it",
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ============================== a task with no effect rows is recoverable, unchanged

/// The complement of Test 2, and the guard against over-correcting into permissiveness.
/// A task that crashed before dispatching anything left no row, so nothing about the
/// world may have changed.
#[test]
fn a_task_that_crashed_before_dispatching_anything_is_recoverable() {
    let d = dir("no-effects");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 1);
        e.claim_task("w1", NOW).expect("claim").expect("claimable");
    }
    let mut e = open_engine(&db);
    e.recover(LATER).expect("recovery");
    assert_recoverable(
        &mut e,
        "t",
        "a task with no effect rows crashed before dispatching, so the world is unchanged \
         and re-running is safe. Conflating 'non-idempotent' with 'uncertain' would park \
         every such task forever",
    );
    let _ = std::fs::remove_dir_all(&d);
}
// ===================================== 6. a genuine schema-10 upgrade, with real history

/// Brings a connection up to exactly `version`, as an older build would have left it.
/// The same technique the store's own migration tests use, and for the same reason: a
/// full re-run would apply migrations a real runner skips.
fn migrate_to(conn: &Connection, version: u32) {
    let applied: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_meta;",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    for m in orxnud_store::migration::MIGRATIONS
        .iter()
        .filter(|m| m.version <= version && m.version > applied)
    {
        conn.execute_batch(m.sql).expect("migration sql");
        conn.execute(
            "INSERT OR REPLACE INTO schema_meta (version, name, applied_at) VALUES (?1, ?2, 0);",
            rusqlite::params![m.version, m.name],
        )
        .expect("record");
    }
}

/// **Test 6 — the real upgrade.** A database genuinely stopped at schema 10, with
/// historical effect rows written by the code that existed then, carried through
/// migrations 11, 12 and 13.
///
/// What must hold:
///
/// * no step number is fabricated for a historical row;
/// * no status is rewritten — in particular nothing becomes `not-performed`, which would
///   fabricate a *proof* that an effect did not happen;
/// * the valid task history around them survives untouched;
/// * recovery then behaves according to the legacy policy: a row whose step is unknown is
///   treated as possibly belonging to the execution being recovered, so a task carrying
///   one is settled rather than retried.
#[test]
fn a_schema_10_database_with_historical_effects_upgrades_without_fabrication() {
    let d = dir("schema-10-upgrade");
    let db = db_in(&d);

    // --- build the older database, with real rows in it.
    {
        let conn = Connection::open(&db).expect("open");
        Pragma::critical().apply(&conn).expect("pragmas");
        migrate_to(&conn, 10);

        let mut e = DurableEngine::new(conn, EngineLimits::documented()).expect("engine");
        // Two tasks, so the fixture proves the migration does not disturb unrelated work.
        e.enqueue_new(
            &orxnud_store::task_repo::NewTask::new(tid("historic"), TaskKind::Workflow, NOW),
            NOW,
        )
        .expect("enqueue");
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        // Written through the *old* shape: no `idempotent`, and at version 10 there is no
        // `step_no` column at all. This is what such a row actually looks like.
        e.conn()
            .execute(
                "INSERT INTO task_effects
                   (idempotency_key, task_id, attempt_no, step_key, status, reserved_at_ms,
                    resolved_at_ms)
                 VALUES ('historic-key', 'historic', 1, 'text/word-count', 'observed', ?1, ?2);",
                rusqlite::params![NOW, NOW + 1],
            )
            .expect("insert a pre-migration effect row");
        e.conn()
            .execute(
                "INSERT INTO task_effects
                   (idempotency_key, task_id, attempt_no, step_key, status, reserved_at_ms)
                 VALUES ('unresolved-key', 'historic', 2, 'filesystem/write-text', 'pending',
                         ?1);",
                rusqlite::params![NOW],
            )
            .expect("insert an unresolved pre-migration effect row");
        e.conn()
            .execute(
                "UPDATE tasks SET state = 'running', attempts = ?1 WHERE id = 'historic';",
                rusqlite::params![claimed.attempts],
            )
            .expect("leave it mid-flight");
    }

    // --- carry it forward.
    {
        let conn = open_raw(&db);

        // Every historical row's step is unknown, and said so rather than guessed.
        let rows: Vec<(String, Option<i64>, i64, i64, String)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT idempotency_key, step_no, attempt_no, idempotent, status
                       FROM task_effects ORDER BY idempotency_key;",
                )
                .expect("prepare");
            stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
        };
        assert_eq!(rows.len(), 2, "both historical rows must survive: {rows:?}");
        for (key, step_no, _, _, _) in &rows {
            assert_eq!(
                *step_no, None,
                "{key}: a row written before the column existed has no step, and the \
                 migration must say so rather than assert `step_no = 1`"
            );
        }

        // No status was rewritten. `observed` and `pending` are what the older build
        // recorded, and in particular nothing became `not-performed` — that value is a
        // *proof* an effect did not happen, and inventing it would be the most damaging
        // thing this migration could do.
        let observed = rows.iter().find(|r| r.0 == "historic-key").expect("row");
        assert_eq!(
            observed.4, "observed",
            "a verified effect must still be verified after the upgrade"
        );
        let unresolved = rows.iter().find(|r| r.0 == "unresolved-key").expect("row");
        assert_eq!(
            unresolved.4, "pending",
            "an unresolved dispatch must still be unresolved after the upgrade"
        );
        assert_eq!(
            observed.3, 0,
            "migration 11's `DEFAULT 0` still applies: repeat-safety nobody recorded must \
             not be read as safe to repeat"
        );

        // And the task row itself is intact.
        let (state, steps): (String, i64) = conn
            .query_row(
                "SELECT state, steps_completed FROM tasks WHERE id = 'historic';",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("read task");
        assert_eq!(state, "running", "the migration must not touch task state");
        assert_eq!(steps, 0, "nor its step counter");
    }

    // --- recovery, under the legacy policy.
    {
        let mut e = open_engine(&db);
        e.recover(LATER).expect("recovery");
        assert_uncertain(
            &mut e,
            "historic",
            "Test 6: a historical row whose step was never recorded cannot be attributed, \
             so it is treated as possibly belonging to the execution being recovered and \
             the task is settled rather than retried. That is the expensive direction, and \
             it is chosen because the cheaper one cannot be justified from the evidence",
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// The other half of the legacy policy: a task whose historical rows are all
/// `not-performed` is retryable after the upgrade, because a disproof is a disproof
/// whatever step it was recorded against.
#[test]
fn a_schema_10_disproved_effect_stays_retryable_across_the_upgrade() {
    let d = dir("schema-10-disproved");
    let db = db_in(&d);
    {
        let conn = Connection::open(&db).expect("open");
        Pragma::critical().apply(&conn).expect("pragmas");
        migrate_to(&conn, 10);
        let mut e = DurableEngine::new(conn, EngineLimits::documented()).expect("engine");
        e.enqueue_new(
            &orxnud_store::task_repo::NewTask::new(tid("t"), TaskKind::Workflow, NOW),
            NOW,
        )
        .expect("enqueue");
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        e.conn()
            .execute(
                "INSERT INTO task_effects
                   (idempotency_key, task_id, attempt_no, step_key, status, reserved_at_ms,
                    resolved_at_ms)
                 VALUES ('disproved', 't', 1, 'filesystem/write-text', 'not-performed',
                         ?1, ?2);",
                rusqlite::params![NOW, NOW + 1],
            )
            .expect("insert a disproved effect");
        e.conn()
            .execute(
                "UPDATE tasks SET state = 'running', attempts = ?1 WHERE id = 't';",
                rusqlite::params![claimed.attempts],
            )
            .expect("leave it mid-flight");
    }
    let mut e = open_engine(&db);
    e.recover(LATER).expect("recovery");
    assert_recoverable(
        &mut e,
        "t",
        "a historical row that was disproved is excluded whatever its step, because a \
         disproof is what makes a retry safe -- and that is the one historical fact this \
         migration is allowed to rely on",
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// A row written *after* the upgrade carries a real step, and is matched on it. Without
/// this, a schema that merely tolerated `NULL` would pass every legacy test while new
/// rows were never scoped at all.
#[test]
fn a_row_written_after_the_upgrade_carries_and_is_matched_on_its_step() {
    let d = dir("post-upgrade-scoped");
    let db = db_in(&d);
    {
        let mut e = open_engine(&db);
        enqueue(&mut e, "t", 2);
        let claimed = e.claim_task("w1", NOW).expect("claim").expect("claimable");
        reserve(&mut e, "t", 1, claimed.attempts, NON_IDEMPOTENT, false, NOW);
    }
    {
        let mut e = open_engine(&db);
        let (step_no, idempotent): (i64, i64) = e
            .conn()
            .query_row(
                "SELECT step_no, idempotent FROM task_effects WHERE task_id = 't';",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("read");
        assert_eq!(
            step_no, 1,
            "a new row records its step rather than leaving it NULL"
        );
        assert_eq!(idempotent, 0, "and the capability's repeat-safety");

        let recovered = e.recover(LATER).expect("recovery");
        assert_eq!(recovered, 1);
        assert_uncertain(&mut e, "t", "a scoped row is matched on its step");
    }
    let _ = std::fs::remove_dir_all(&d);
}
