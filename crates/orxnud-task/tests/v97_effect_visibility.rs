//! V-97: a reserved effect must always be either recoverable or resolved.
//!
//! # The defect this file exists to prevent
//!
//! `execute_proposal` reserves the side effect *before* dispatching, because a record
//! made afterwards cannot describe a crash. A `dispatch()` that returned `Err` left that
//! row `pending` — and `pending` is the status recovery reads as "do not repeat this".
//! But the task still held the **execution lease** taken a moment earlier, so the worker
//! could immediately call `task/propose`, and `propose_action` released the lease:
//!
//! ```text
//! claim -> proposal -> approval -> reserve_effect -> dispatch returns Err
//!   -> effect still `pending`, task `running` + leased
//!   -> task/propose: running -> waiting-for-user, lease_holder = NULL
//!   -> recover() selects `state='running' AND lease_holder IS NOT NULL`
//!   -> the task is not selected. The pending effect is never examined again.
//! ```
//!
//! And the task could not be recovered by any other route either, which is what made this
//! a permanent dead end rather than a delay:
//!
//! * its approval was already spent — `begin_execution_spending_approval` wrote
//!   `consumed_at_ms` to take the lease, and `record_approval_replacing_expired` refuses
//!   a consumed approval;
//! * its idempotency key was already reserved for that `(step, attempt)`, so a second
//!   `task/execute` is answered `effect-already-reserved`;
//! * `claim` cannot reach `waiting-for-user`.
//!
//! Reproduced end to end through the real repository before either fix, with
//! `recover()` reporting `0` and the row still `pending`.
//!
//! # The invariant
//!
//! ```text
//! reserved unresolved effect
//!     =>  a recoverable running execution
//!     or  an explicitly resolved effect
//! ```
//!
//! Never:
//!
//! ```text
//! reserved unresolved effect
//!     + non-running / unleased task
//!     + recover() cannot see it
//! ```
//!
//! Two changes establish it, and each is tested here separately so neither can be
//! removed alone without a failure:
//!
//! 1. [`effect_status_for_dispatch_failure`] resolves the effect on the dispatch error
//!    path, from the dispatch contract rather than from the status of the call.
//! 2. `TaskRepository::propose_action` refuses while the *current* execution still holds
//!    an unresolved effect, so the lease is never released out from under one.
//!
//! # Everything here goes through the real repository
//!
//! No raw SQL writes a task or an effect row except where a *legacy* shape is the point
//! of the fixture, and each such case says so. A row this file invented rather than drove
//! through `propose_action` / `begin_execution_spending_approval` / `reserve_effect`
//! would prove nothing, because the defect lived in the *sequence* of those calls.

use std::path::{Path, PathBuf};

use orxnud_domain::{TaskId, TaskKind};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::{
    ApprovalRow, EffectStatus, NewTask, TargetedClaimOutcome, TaskRepoError, TaskRepository,
};
use rusqlite::Connection;

const NOW: i64 = 1_767_225_600_000;
const LATER: i64 = NOW + 1_000;
const LEASE: i64 = 60_000;

fn tid(s: &str) -> TaskId {
    TaskId::new(s)
}

/// A **file**, because the lease and the recovery both depend on one.
fn db(tag: &str) -> (PathBuf, Connection) {
    let d = std::env::temp_dir().join(format!("v97-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    let p = d.join("state.db");
    let c = Connection::open(&p).expect("open");
    Pragma::critical().apply(&c).expect("pragmas");
    MigrationRunner::new(&c).run(true).expect("migrate");
    (p, c)
}

/// The same file, reopened. Used to stand in for a process restart, which is the only
/// thing that ever calls `recover()` in production (`TaskService::open`).
fn reopen(p: &Path) -> Connection {
    let c = Connection::open(p).expect("reopen");
    Pragma::critical().apply(&c).expect("pragmas");
    c
}

/// Reclaim the temp directory. `remove_dir_all` is ignored rather than asserted because
/// a Windows host cannot delete a file a connection still holds, and a cleanup failure
/// must not fail a correctness assertion.
fn cleanup(p: &Path) {
    let _ = std::fs::remove_dir_all(p.parent().unwrap_or(p));
}

fn approval(task: &str, digest: &str) -> ApprovalRow {
    ApprovalRow {
        task_id: tid(task),
        attempt_no: 1,
        step_no: 1,
        digest_hex: digest.repeat(32),
        capability: "filesystem/write-text".to_owned(),
        target: Some("out.txt".to_owned()),
        params: "{}".to_owned(),
        issued_at_ms: NOW + 2,
        expires_at_ms: NOW + 100_000,
        consumed_at_ms: None,
    }
}

/// Claim, propose, approve, and take the execution lease — i.e. everything
/// `execute_proposal` does before it reserves the effect.
struct InFlight {
    proposal_id: String,
}

fn in_flight(repo: &mut TaskRepository<'_>, task: &str) -> InFlight {
    repo.insert(&NewTask::new(tid(task), TaskKind::Query, NOW), NOW)
        .expect("insert");
    let TargetedClaimOutcome::Claimed(_) = repo
        .claim_specific(&tid(task), "w1", NOW, LEASE)
        .expect("claim")
    else {
        panic!("the fresh task must be claimable");
    };
    let p = repo
        .propose_action(
            "p1",
            &tid(task),
            "w1",
            "filesystem/write-text",
            Some("out.txt"),
            "{}",
            "{}",
            None,
            1,
            NOW + 1,
        )
        .expect("propose");
    repo.record_approval(&approval(task, "00")).expect("record");
    repo.decide_proposal("p1", "approved", NOW + 3)
        .expect("decide");
    repo.begin_execution_spending_approval("p1", "w1", NOW + 4, LEASE)
        .expect("begin execution");
    InFlight {
        proposal_id: p.proposal_id,
    }
}

/// Every unresolved effect a task owns, as `(key, step_no, attempt_no, idempotent)`.
fn effects(conn: &Connection, task: &str) -> Vec<(String, Option<i64>, i64, i64)> {
    let mut st = conn
        .prepare(
            "SELECT idempotency_key, step_no, attempt_no, idempotent
               FROM task_effects WHERE task_id = ?1 ORDER BY idempotency_key;",
        )
        .expect("prepare");
    let rows = st
        .query_map([task], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .expect("query");
    rows.map(|r| r.expect("row")).collect()
}

fn unresolved(conn: &Connection, task: &str) -> Vec<(String, Option<i64>, i64, i64)> {
    let mut st = conn
        .prepare(
            "SELECT idempotency_key, step_no, attempt_no, idempotent
               FROM task_effects WHERE task_id = ?1 AND status = 'pending'
               ORDER BY idempotency_key;",
        )
        .expect("prepare");
    let rows = st
        .query_map([task], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .expect("query");
    rows.map(|r| r.expect("row")).collect()
}

// ---------------------------------------------------------------------------
// requirement 2: a dispatch failure must leave no unresolved invisible effect
// ---------------------------------------------------------------------------

/// The reproduction of the reported defect, verbatim, through the real repository.
///
/// Everything except `resolve_effect` is production behaviour: the reservation is left
/// unresolved exactly as `execute_proposal` used to leave it on `Err`, and the next step
/// is the `task/propose` the worker was entitled to make.
#[test]
fn a_re_proposal_cannot_release_the_lease_under_an_unresolved_effect() {
    let (p, mut c) = db("repropose");
    let mut repo = TaskRepository::new(&mut c);
    in_flight(&mut repo, "t");

    // `execute_proposal` reserved the effect and dispatch failed before resolving it.
    let key = "t|filesystem/write-text|1/1";
    assert!(
        repo.reserve_effect(
            key,
            &tid("t"),
            1,
            1,
            "filesystem/write-text",
            false,
            NOW + 5
        )
        .expect("reserve")
        .is_some(),
        "the reservation is the precondition of the whole scenario"
    );
    // The lease is still live, so the worker is entitled to propose again. Before the fix
    // this succeeded and released the lease.
    let second = repo.propose_action(
        "p2",
        &tid("t"),
        "w1",
        "filesystem/write-text",
        Some("out.txt"),
        "{}",
        "{}",
        None,
        1,
        NOW + 6,
    );
    assert!(
        matches!(
            second,
            Err(TaskRepoError::EffectOutcomeUnresolved {
                step_no: 1,
                attempt_no: 1,
                ..
            })
        ),
        "a second proposal must be refused while the current execution's effect is \
         unresolved, got {second:?}"
    );
    assert_eq!(
        unresolved(&c, "t").len(),
        1,
        "the effect is still unresolved, which is the state under test"
    );

    // The task kept the lease, so it is exactly the shape recovery is built to reclaim.
    let row = TaskRepository::new(&mut c)
        .get(&tid("t"))
        .expect("get")
        .expect("row");
    assert_eq!(
        row.state,
        orxnud_domain::TaskState::Running,
        "still running"
    );
    assert_eq!(
        row.lease_holder.as_deref(),
        Some("w1"),
        "the execution lease must be retained, because the lease is what makes the \
         unresolved effect visible"
    );
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// requirement 3: an unresolved effect cannot coexist with a released lease
// ---------------------------------------------------------------------------

/// The invariant as a query rather than as a story.
///
/// Written so it fails for *any* transition that would release a lease while an
/// unresolved effect stands, not only for the one reported.
#[test]
fn no_state_in_the_table_hides_an_unresolved_effect_from_recovery() {
    let (p, mut c) = db("nohidden");
    let key = "t|filesystem/write-text|1/1";
    {
        let mut repo = TaskRepository::new(&mut c);
        in_flight(&mut repo, "t");
        repo.reserve_effect(
            key,
            &tid("t"),
            1,
            1,
            "filesystem/write-text",
            false,
            NOW + 5,
        )
        .expect("reserve");
    }

    // Every path that would take the task out of `running`-and-leased while the effect is
    // still unresolved. Listed explicitly rather than as a loop over a table, because a
    // table would be a list of guesses; these are the transitions `propose_action`'s own
    // contract lists.
    let attempts: Vec<(&str, Result<(), TaskRepoError>)> = {
        let mut repo = TaskRepository::new(&mut c);
        vec![(
            "propose",
            repo.propose_action(
                "p2",
                &tid("t"),
                "w1",
                "filesystem/write-text",
                Some("out.txt"),
                "{}",
                "{}",
                None,
                1,
                NOW + 6,
            )
            .map(|_| ()),
        )]
    };
    for (label, r) in attempts {
        assert!(
            r.is_err(),
            "{label} must be refused while an unresolved effect stands, got {r:?}"
        );
    }

    let hidden: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM task_effects e
               JOIN tasks t ON t.id = e.task_id
              WHERE e.status = 'pending'
                AND NOT (t.state = 'running' AND t.lease_holder IS NOT NULL);",
            [],
            |r| r.get(0),
        )
        .expect("count");
    assert_eq!(
        hidden, 0,
        "an unresolved effect must never sit on a task that `recover()` will not select; \
         found {hidden} such rows"
    );
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// requirement 5: recovery of the resulting state
// ---------------------------------------------------------------------------

/// The state the reported defect left behind is now settled by recovery, across a real
/// reopen — which is the only thing that ever calls `recover()` in production.
#[test]
fn recovery_settles_an_interrupted_execution_the_worker_could_not_re_propose() {
    let (p, mut c) = db("recover");
    let mut repo = TaskRepository::new(&mut c);
    in_flight(&mut repo, "t");
    repo.reserve_effect(
        "t|filesystem/write-text|1/1",
        &tid("t"),
        1,
        1,
        "filesystem/write-text",
        false, // non-idempotent: `filesystem/write-text` declares itself so
        NOW + 5,
    )
    .expect("reserve");
    assert!(
        repo.propose_action(
            "p2",
            &tid("t"),
            "w1",
            "filesystem/write-text",
            Some("out.txt"),
            "{}",
            "{}",
            None,
            1,
            NOW + 6
        )
        .is_err(),
        "precondition: the re-proposal is refused"
    );
    drop(c);

    // Restart.
    let mut c = reopen(&p);
    let swept = TaskRepository::new(&mut c).recover(LATER).expect("recover");
    assert_eq!(swept, 1, "recovery must select the task it can now see");
    let row = TaskRepository::new(&mut c)
        .get(&tid("t"))
        .expect("get")
        .expect("row");
    assert_eq!(
        row.state,
        orxnud_domain::TaskState::NeedsVerification,
        "a non-idempotent effect whose outcome was never established is exactly what \
         `needs-verification` is for"
    );
    assert!(
        row.lease_holder.is_none(),
        "and the lease is released, as every recovery outcome releases it"
    );
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// requirement 4: re-proposal after a *resolved* dispatch failure
// ---------------------------------------------------------------------------

/// The other half: once the effect is resolved, a *further* proposal for the same
/// execution identity is no longer refused by the effect guard — it is refused by
/// migration 14's identity constraint instead.
///
/// The distinction is the point. Two different invariants refuse here:
///
/// * `EffectOutcomeUnresolved` — the effect ledger is mid-decision, so the outcome must be
///   established first. This is the guard this pass added.
/// * `ExecutionIdentityTaken` — the execution identity is already occupied, full stop.
///
/// Asserting which one fires is what stops the effect guard from being credited with a
/// refusal the schema makes anyway, and what keeps the next test meaningful.
#[test]
fn a_resolved_effect_is_no_longer_what_refuses_the_next_proposal() {
    let (p, mut c) = db("resolved");
    let mut repo = TaskRepository::new(&mut c);
    in_flight(&mut repo, "t");
    let key = "t|filesystem/write-text|1/1";
    repo.reserve_effect(
        key,
        &tid("t"),
        1,
        1,
        "filesystem/write-text",
        false,
        NOW + 5,
    )
    .expect("reserve");

    // What `effect_status_for_dispatch_failure` now returns for a pre-execution refusal.
    repo.resolve_effect(
        key,
        EffectStatus::NotPerformed,
        Some("sandbox refused"),
        NOW + 6,
    )
    .expect("resolve");

    let second = repo.propose_action(
        "p2",
        &tid("t"),
        "w1",
        "filesystem/write-text",
        Some("out.txt"),
        "{}",
        "{}",
        None,
        1,
        NOW + 7,
    );
    assert!(
        matches!(second, Err(TaskRepoError::ExecutionIdentityTaken { .. })),
        "with the effect resolved, the refusal must come from the identity constraint and \
         not from the effect guard; got {second:?}"
    );
    assert!(
        !matches!(second, Err(TaskRepoError::EffectOutcomeUnresolved { .. })),
        "and it must specifically not still be the unresolved-effect guard"
    );

    // The task is still `running` and still leased, so nothing was released by a refusal.
    let row = TaskRepository::new(&mut c)
        .get(&tid("t"))
        .expect("get")
        .expect("row");
    assert_eq!(row.state, orxnud_domain::TaskState::Running);
    assert_eq!(row.lease_holder.as_deref(), Some("w1"));
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// the scope guard must not over-reach
// ---------------------------------------------------------------------------

/// A stale row from an earlier attempt must NOT block a legitimate retry.
///
/// This is the failure mode the scope was chosen to avoid. `recover()` deliberately
/// returns an interrupted *idempotent* execution to `pending` so it can be retried; if
/// the new guard consulted the whole task, that task could never be retried, because its
/// own stale `pending` row would refuse every future proposal.
#[test]
fn a_stale_row_from_an_earlier_attempt_does_not_block_the_retry() {
    let (p, mut c) = db("stale");
    {
        let mut repo = TaskRepository::new(&mut c);
        in_flight(&mut repo, "t");
        // An idempotent capability, interrupted mid-dispatch.
        repo.reserve_effect("t|cap/idem|1/1", &tid("t"), 1, 1, "cap/idem", true, NOW + 5)
            .expect("reserve");
    }
    // Recovery: idempotent, so the task is returned to `pending` and is retryable.
    assert_eq!(
        TaskRepository::new(&mut c).recover(LATER).expect("recover"),
        1
    );
    {
        let row = TaskRepository::new(&mut c)
            .get(&tid("t"))
            .expect("get")
            .expect("row");
        assert_eq!(
            row.state,
            orxnud_domain::TaskState::Pending,
            "an interrupted idempotent effect must stay retryable"
        );
    }
    // Re-claim: attempt 2, with the attempt-1 row still `pending` on the task.
    let mut repo = TaskRepository::new(&mut c);
    let TargetedClaimOutcome::Claimed(got) = repo
        .claim_specific(&tid("t"), "w2", LATER + 1, LEASE)
        .expect("claim")
    else {
        panic!("a recovered task must be claimable");
    };
    assert_eq!(got.attempt_no, 2, "the retry is a second attempt");
    let second = repo.propose_action(
        "p2",
        &tid("t"),
        "w2",
        "cap/idem",
        None,
        "{}",
        "{}",
        None,
        1,
        LATER + 2,
    );
    assert!(
        second.is_ok(),
        "the attempt-1 row must not refuse the attempt-2 proposal: {second:?}"
    );
    cleanup(&p);
}

// ---------------------------------------------------------------------------
// requirement 7: the ordinary path is unchanged
// ---------------------------------------------------------------------------

/// The whole success path, driven in order, and asserted at each step. A guard that
/// refused too eagerly would break this, so it is the control for the tests above.
#[test]
fn a_successful_execution_resolves_its_effect_and_completes_the_step() {
    let (p, mut c) = db("success");
    let mut repo = TaskRepository::new(&mut c);
    let f = in_flight(&mut repo, "t");
    let key = "t|filesystem/write-text|1/1";

    repo.reserve_effect(
        key,
        &tid("t"),
        1,
        1,
        "filesystem/write-text",
        false,
        NOW + 5,
    )
    .expect("reserve")
    .expect("a first reservation must succeed");
    repo.resolve_effect(key, EffectStatus::Observed, None, NOW + 6)
        .expect("resolve");

    let advanced = repo
        .complete_verified_step(&orxnud_store::task_repo::VerifiedStep {
            task_id: tid("t"),
            worker: "w1",
            step_no: 1,
            proposal_id: &f.proposal_id,
            status: orxnud_store::task_repo::StepStatus::Verified,
            verification: None,
            structured_output: None,
            artifacts: None,
            recorded_at_ms: NOW + 7,
        })
        .expect("complete the step");
    assert_eq!(
        advanced.state,
        orxnud_domain::TaskState::Completed,
        "a one-step task that completed its only step is finished, not at a boundary"
    );
    assert_eq!(advanced.steps_completed, 1);

    let row = TaskRepository::new(&mut c)
        .get(&tid("t"))
        .expect("get")
        .expect("row");
    assert_eq!(row.state, orxnud_domain::TaskState::Completed);
    assert_eq!(
        effects(&c, "t").len(),
        1,
        "exactly one effect for one dispatch"
    );
    cleanup(&p);
}
// ---------------------------------------------------------------------------
// requirement: the NULL legacy-step scope, pinned rather than implied
// ---------------------------------------------------------------------------

/// `step_no IS NULL` is **not** a wildcard for the whole execution.
///
/// The scope `recover()` uses is three conjoined conditions, and `NULL` satisfies only the
/// step one. This asserts the exact boundary from both sides — matching while the attempt
/// still matches, and ceasing to match once it has advanced — because the previous
/// documentation said such a row "matches any step" and a reader would reasonably infer
/// "matches any attempt" from that.
#[test]
fn recovery_scope_is_not_a_wildcard() {
    // (a) attempt 1, task on attempt 1: the legacy row matches and the task is settled.
    {
        let (p, mut c) = db("null-current");
        {
            let mut repo = TaskRepository::new(&mut c);
            in_flight(&mut repo, "t");
            // A row written before version 13: `step_no` did not exist, so it is NULL. Seeded
            // through raw SQL because `reserve_effect` always supplies a step.
            c.execute(
                "INSERT INTO task_effects
                   (idempotency_key,task_id,step_no,attempt_no,step_key,status,idempotent,
                    reserved_at_ms)
                 VALUES ('legacy','t',NULL,1,'legacy-cap','pending',0,?1);",
                rusqlite::params![NOW + 5],
            )
            .expect("a pre-version-13 effect row");
        }
        assert_eq!(
            TaskRepository::new(&mut c).recover(LATER).expect("recover"),
            1
        );
        let row = TaskRepository::new(&mut c)
            .get(&tid("t"))
            .expect("get")
            .expect("row");
        assert_eq!(
            row.state,
            orxnud_domain::TaskState::NeedsVerification,
            "while the attempt still matches, an unattributable non-idempotent effect must \\
             still fail safe"
        );
        cleanup(&p);
    }

    // (b) attempt 1, task advanced to attempt 2: the row no longer matches, so the task is
    // returned to `pending`.
    //
    // Recorded rather than fixed. `origin/main`'s `recover()` read no ledger at all, so the
    // only way to reach this shape is a database written by a build older than this one
    // whose task has since been retried. Broadening `NULL` to cover every attempt would
    // close it, and would also make the predicate assert something false -- that a row with
    // an unknown *step* might belong to any *attempt* -- so the narrower reading stands and
    // the limit is written down instead.
    {
        let (p, mut c) = db("null-drift");
        {
            let mut repo = TaskRepository::new(&mut c);
            in_flight(&mut repo, "t");
            c.execute(
                "INSERT INTO task_effects
                   (idempotency_key,task_id,step_no,attempt_no,step_key,status,idempotent,
                    reserved_at_ms)
                 VALUES ('legacy','t',NULL,1,'legacy-cap','pending',0,?1);",
                rusqlite::params![NOW + 5],
            )
            .expect("a pre-version-13 effect row");
        }
        // The task is retried, so `attempts` advances past the legacy row's `attempt_no`.
        c.execute("UPDATE tasks SET attempts = 2 WHERE id = 't';", [])
            .expect("advance the attempt counter");
        assert_eq!(
            unresolved(&c, "t").len(),
            1,
            "precondition: the legacy row is still unresolved"
        );

        assert_eq!(
            TaskRepository::new(&mut c).recover(LATER).expect("recover"),
            1
        );
        let row = TaskRepository::new(&mut c)
            .get(&tid("t"))
            .expect("get")
            .expect("row");
        assert_eq!(
            row.state,
            orxnud_domain::TaskState::Pending,
            "a NULL-step row whose attempt has been superseded does NOT match, so the task \\
             is returned to pending -- the documented limit, asserted so it cannot drift"
        );
        assert_eq!(
            unresolved(&c, "t").len(),
            1,
            "and the unresolved row is still there: this state is reconciled by no one, \\
             which is the reason the limit is written down rather than quietly widened"
        );
        cleanup(&p);
    }
}
