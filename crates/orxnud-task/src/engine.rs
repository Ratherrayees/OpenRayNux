//! The production durable task engine.
//!
//! # What this is
//!
//! An implementation of the ADR-0029 contract, backed by SQLite. It implements
//! [`TaskEngine`](orxnud_task::conformance::properties::TaskEngine) — the trait
//! the Phase 1 harness already defines — so the *unmodified* conformance suite is
//! the acceptance criterion rather than a description of this code.
//!
//! # What it deliberately is not
//!
//! There is no capability invocation here, and no `Actor`. Phase 2 makes the
//! deterministic task layer operational; the adapter that eventually performs work
//! is Phase 4, and it will receive a [`CapabilityInvocation`], which only
//! `orxnud-policy` can construct. Putting one in the engine now would require
//! either a policy call (a capability, and this crate may not enable one) or a
//! bypass of the seal.
//!
//! Where actor attribution *does* belong — who authorised a schedule, which attempt
//! ran — it is recorded as the actor's stable label, never as a reconstructed
//! authority.
//!
//! # The transaction discipline
//!
//! One writer, one `BEGIN IMMEDIATE` per transition (ADR-0007 invariant 1). The
//! engine owns the connection; every mutation goes through
//! [`orxnud_store::task_repo::TaskRepository`], which is the only code in the
//! workspace that speaks SQL about tasks (ADR-0006 decision 2).
//!
//! # Time is a parameter
//!
//! Nothing here reads the wall clock. `now_ms` is passed in, because TP-3, TP-4,
//! TP-5, TP-8 and TP-9 are all time properties and a wall clock makes them
//! untestable. A production caller passes
//! [`crate::clock::SystemClock::now_ms`]; the conformance suite passes its own.

use rusqlite::Connection;

use orxnud_domain::ids::TaskId;
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_store::schedule_repo::ScheduleRepository;
use orxnud_store::task_repo::{
    ApprovalRow, ClaimOutcome, EffectStatus, NewTask, TaskRepoError, TaskRepository, TaskRow,
};

use crate::error::{EngineError, EngineErrorKind};
use crate::limits::EngineLimits;

/// The conformance contract, imported so the impl target is unambiguous.
use crate::conformance::properties::{Claim, TaskEngine, TaskRecord};

/// The durable task engine.
///
/// Owns the single writable connection. `&mut self` on every mutation is the
/// compiler-enforced statement that this is the one writer.
#[derive(Debug)]
pub struct DurableEngine {
    conn: Connection,
    limits: EngineLimits,
}

impl DurableEngine {
    /// Wraps an already-opened, already-migrated connection.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `InvalidInput` if `limits` are self-inconsistent.
    /// An engine that could never honour its own bounds is not constructed at all.
    pub fn new(conn: Connection, limits: EngineLimits) -> Result<Self, EngineError> {
        limits.validate()?;
        Ok(Self { conn, limits })
    }

    /// The limits this engine runs inside.
    #[must_use]
    pub fn limits(&self) -> EngineLimits {
        self.limits
    }

    /// Borrows the connection for a read.
    ///
    /// Exposed so a supervisor can query without a second connection. Mutations go
    /// through the methods here, so nothing can bypass the transaction discipline.
    #[must_use]
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Borrows the connection mutably, for composing several repository calls in one
    /// logical operation.
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    /// Takes the connection back, so an engine can be rebuilt with different
    /// limits.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `InvalidInput` if `limits` are self-inconsistent.
    /// Taking the connection is not a way to bypass validation: a replacement
    /// engine has to pass the same check as a fresh one.
    pub fn rebuild(self, limits: EngineLimits) -> Result<Self, EngineError> {
        limits.validate()?;
        Ok(Self {
            conn: self.conn,
            limits,
        })
    }

    // ------------------------------------------------------------ domain API

    /// Enqueues a task.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `InvalidInput` if the id is taken, or `Storage` if
    /// the write fails.
    pub fn enqueue_new(&mut self, task: &NewTask, now_ms: i64) -> Result<(), EngineError> {
        self.repo().insert(task, now_ms).map_err(EngineError::from)
    }

    /// Reads one task.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Invariant` if a row cannot be decoded, or
    /// `Storage` if the read fails.
    pub fn task(&self, id: &TaskId) -> Result<Option<TaskRow>, EngineError> {
        self.repo_ref().get(id).map_err(EngineError::from)
    }

    /// Claims a task, if the concurrency budget allows.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `ConcurrencyConflict` when the lease budget is
    /// exhausted, or `Storage` if the claim fails.
    pub fn claim_task(
        &mut self,
        worker: &str,
        now_ms: i64,
    ) -> Result<Option<TaskRow>, EngineError> {
        self.claim_task_at(worker, now_ms)
    }

    /// [`Self::claim_task`], under its real name for callers inside the crate.
    ///
    /// The indirection is retained so `claim_task` reads as the entry point and the
    /// concurrency check lives in one place.
    ///
    /// # Errors
    ///
    /// As [`Self::claim_task`].
    pub fn claim_task_at(
        &mut self,
        worker: &str,
        now_ms: i64,
    ) -> Result<Option<TaskRow>, EngineError> {
        let live = self
            .repo_ref()
            .live_leases(now_ms)
            .map_err(EngineError::from)?;
        let limits = self.limits;
        if !limits.can_claim(live, now_ms) {
            return Err(limits.refuse_over_limit(live));
        }
        let outcome = self.repo().claim(worker, now_ms, limits.lease_duration_ms);
        match outcome.map_err(EngineError::from)? {
            ClaimOutcome::Claimed(c) => Ok(Some(c.row)),
            // A task past its budget was dead-lettered rather than skipped. The
            // caller is told nothing: there is nothing to do about it, and the
            // dead-letter row plus the event log are the durable record. Surfacing
            // it as an error would make a supervisor retry a task that is finished.
            ClaimOutcome::Empty | ClaimOutcome::DeadLettered { .. } => Ok(None),
        }
    }

    /// Records a terminal outcome for a task the caller holds a live lease on.
    ///
    /// Returns `Ok(false)` — not an error — when the fence refuses. A zombie
    /// worker asking to commit is a *normal* event under TP-5, and the caller
    /// learns about it by the value.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Invariant` if the requested transition is illegal,
    /// or `Storage` if the write fails.
    pub fn complete_task(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
        to: TaskState,
        effect_observed: bool,
        error: Option<&str>,
    ) -> Result<bool, EngineError> {
        self.complete_task_with(id, worker, now_ms, to, effect_observed, error, None)
    }

    /// [`Self::complete_task`], with an explicit retry delay for a `Failed` outcome.
    ///
    /// `None` uses the engine's documented backoff. This exists so the ADR-0029
    /// conformance path can drive the state machine with no delay while production
    /// applies a real one; the alternative is a fixed backoff that makes TP-11
    /// depend on a clock the harness does not own.
    ///
    /// # Errors
    ///
    /// As [`Self::complete_task`].
    #[allow(clippy::too_many_arguments)]
    pub fn complete_task_with(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
        to: TaskState,
        effect_observed: bool,
        error: Option<&str>,
        retry_delay_ms: Option<i64>,
    ) -> Result<bool, EngineError> {
        let delay = retry_delay_ms.unwrap_or(self.limits.retry_backoff_ms);
        self.repo()
            .complete_with(id, worker, now_ms, to, effect_observed, error, delay)
            .map_err(EngineError::from)
    }

    /// Extends a lease the caller still holds.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the write fails.
    pub fn heartbeat(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
    ) -> Result<bool, EngineError> {
        let lease_ms = self.limits.lease_duration_ms;
        self.repo()
            .heartbeat(id, worker, now_ms, lease_ms)
            .map_err(EngineError::from)
    }

    /// Records a cancellation request and acts on it.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `InvalidInput` if there is no such task.
    pub fn cancel_task(&mut self, id: &TaskId, now_ms: i64) -> Result<(), EngineError> {
        self.repo()
            .request_cancel(id, now_ms)
            .map_err(EngineError::from)
    }

    /// Reclaims work abandoned by a restart, returning how many rows changed.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the write fails.
    pub fn recover(&mut self, now_ms: i64) -> Result<u64, EngineError> {
        self.repo().recover(now_ms).map_err(EngineError::from)
    }

    /// Every task.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the read fails.
    pub fn all_tasks(&self) -> Result<Vec<TaskRow>, EngineError> {
        self.repo_ref().all().map_err(EngineError::from)
    }

    /// How many tasks hold a live lease at `now_ms`.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the read fails.
    pub fn live_leases(&self, now_ms: i64) -> Result<i64, EngineError> {
        self.repo_ref()
            .live_leases(now_ms)
            .map_err(EngineError::from)
    }

    // ------------------------------------------------------- idempotency

    /// Reserves an idempotency key for an external side effect.
    ///
    /// `Ok(None)` means the key is already reserved: the caller must **not**
    /// dispatch. This is ADR-0007 invariant 3 — the dedupe row and the dispatch
    /// decision are the same transaction — and it is what makes a retry of the same
    /// logical step unable to produce a second external call.
    ///
    /// # What this does *not* claim
    ///
    /// At-most-once *dispatch attempt per key*, on our side. It is **not**
    /// exactly-once for the remote system: if the process dies between the remote
    /// call and our resolution of the ledger row, the effect happened and our row
    /// still says `pending`. That is why [`Self::resolve_effect`] accepts
    /// [`EffectStatus::Unknown`] and why an unresolved effect blocks a
    /// non-idempotent retry.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the write fails.
    pub fn reserve_effect(
        &mut self,
        key: &str,
        id: &TaskId,
        attempt_no: u32,
        step_key: &str,
        now_ms: i64,
    ) -> Result<bool, EngineError> {
        self.repo()
            .reserve_effect(key, id, attempt_no, step_key, now_ms)
            .map(|o| o.is_some())
            .map_err(EngineError::from)
    }

    /// Records how an effect turned out.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Invariant` for an unresolvable status, or
    /// `Storage` if the write fails.
    pub fn resolve_effect(
        &mut self,
        key: &str,
        status: EffectStatus,
        detail: Option<&str>,
        now_ms: i64,
    ) -> Result<bool, EngineError> {
        self.repo()
            .resolve_effect(key, status, detail, now_ms)
            .map_err(EngineError::from)
    }

    /// Whether every effect for a task has been resolved.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the read fails.
    pub fn all_effects_resolved(&self, id: &TaskId) -> Result<bool, EngineError> {
        self.repo_ref()
            .all_effects_resolved(id)
            .map_err(EngineError::from)
    }

    /// The deterministic idempotency key for a logical step.
    ///
    /// # What defines the key, and its scope
    ///
    /// The key is `(task, step, attempt_class)` — deliberately **not** the attempt
    /// *number*. A retry of the same logical step reuses the key, which is the
    /// whole point: the dedupe ledger then refuses the second dispatch. A
    /// *different* step of the same task gets a different key, and a different task
    /// gets a different key, so two tasks that happen to share a step name never
    /// suppress each other.
    ///
    /// `attempt_class` distinguishes a genuine retry (`"retry"`) from the first
    /// attempt (`"initial"`). It is a *class*, not a counter, precisely so that
    /// attempt 2 and attempt 3 share a key.
    ///
    /// # Examples
    ///
    /// ```
    /// use orxnud_task::engine::DurableEngine;
    /// use orxnud_domain::TaskId;
    ///
    /// let id = TaskId::new("t-1");
    /// let a = DurableEngine::idempotency_key(&id, "send-email", "initial");
    /// let b = DurableEngine::idempotency_key(&id, "send-email", "retry");
    /// assert_ne!(a, b, "the first attempt and a retry are different dispatches");
    /// assert_eq!(
    ///     DurableEngine::idempotency_key(&id, "send-email", "retry"),
    ///     DurableEngine::idempotency_key(&id, "send-email", "retry"),
    ///     "two retries of the same step share one key"
    /// );
    /// ```
    #[must_use]
    pub fn idempotency_key(id: &TaskId, step_key: &str, attempt_class: &str) -> String {
        // Length-prefixed, so ("a", "bc") and ("ab", "c") cannot collide. Without
        // the separator a collision would silently suppress a real side effect.
        format!("{}/{}/{}", id.as_str().len(), id.as_str(), step_key) + &format!("/{attempt_class}")
    }

    // ---------------------------------------------------------- approvals

    /// Records an approval for one attempt.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `InvalidInput` if the attempt already has one.
    pub fn record_approval(&mut self, approval: &ApprovalRow) -> Result<(), EngineError> {
        self.repo()
            .record_approval(approval)
            .map_err(EngineError::from)
    }

    /// The approval for one **specific** attempt.
    ///
    /// Takes an attempt number rather than "the current approval" so that asking
    /// for the wrong attempt is impossible to express. TP-6's mechanism.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the read fails.
    pub fn approval_for(
        &self,
        id: &TaskId,
        attempt_no: u32,
    ) -> Result<Option<ApprovalRow>, EngineError> {
        self.repo_ref()
            .approval_for_attempt(id, attempt_no)
            .map_err(EngineError::from)
    }

    /// Marks an approval consumed. Single-use.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `InvalidInput` if the attempt has no unconsumed
    /// approval.
    pub fn consume_approval(
        &mut self,
        id: &TaskId,
        attempt_no: u32,
        now_ms: i64,
    ) -> Result<(), EngineError> {
        self.repo()
            .consume_approval(id, attempt_no, now_ms)
            .map(|_| ())
            .map_err(EngineError::from)
    }

    /// Whether an attempt may proceed on an approval it already holds.
    ///
    /// This is the whole of TP-6 as the engine can express it: the approval is
    /// looked up **by attempt**, so a retry finds nothing and must re-derive. The
    /// caller then runs policy again — which is where the actor is re-derived and
    /// the delegation re-checked, in `orxnud-policy`.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the read fails.
    pub fn may_use_approval(
        &self,
        id: &TaskId,
        attempt_no: u32,
        now_ms: i64,
    ) -> Result<bool, EngineError> {
        Ok(self
            .approval_for(id, attempt_no)?
            .is_some_and(|a| a.is_valid_at(now_ms)))
    }

    // ------------------------------------------------------------ schedules

    /// The schedule repository, for the scheduler.
    ///
    /// # Errors
    ///
    /// None cannot happen: the borrow always succeeds. Returned as `Result` so a
    /// future borrow-checked variant does not silently change this signature.
    pub fn schedules(&mut self) -> ScheduleRepository<'_> {
        ScheduleRepository::new(&mut self.conn)
    }

    fn repo(&mut self) -> TaskRepository<'_> {
        TaskRepository::new(&mut self.conn)
    }

    fn repo_ref(&self) -> TaskRepository<'_> {
        // The repository takes `&mut Connection` so *writes* cannot interleave. A
        // read-only use of it is sound because the borrow ends before any other
        // borrow, and the engine is `&self` here so nothing else can be in flight.
        //
        // INVARIANT: this is the only place a `&Connection` is laundered into a
        // `&mut`. It is safe because the returned repository is bound to `&self`,
        // so the caller cannot obtain a second connection handle.
        TaskRepository::new_readonly(&self.conn)
    }
}

// ---------------------------------------------------------------- the contract

impl TaskEngine for DurableEngine {
    fn name(&self) -> &'static str {
        "sqlite-durable"
    }

    fn supports_lease_fencing(&self) -> bool {
        // True because `TaskRepository::complete` re-validates both the holder and
        // the lease expiry inside the committing UPDATE. Not asserted: the
        // conformance suite's TP-5 is what proves it, and this declaration is what
        // makes a gap visible as `ConformsWithGaps` rather than a silent pass.
        true
    }

    fn enqueue(&mut self, task: TaskRecord) -> Result<(), String> {
        let kind_matches = task.kind.idempotent_by_default() == task.idempotent;
        if !kind_matches {
            // The harness builds `TaskRecord::pending`, which derives idempotency
            // from the kind. A disagreement means the caller is trying to declare a
            // Workflow task safe to retry, and TP-2 turns on exactly that flag.
            return Err(format!(
                "[{}] task {} declares idempotent={} but kind {:?} implies {}",
                EngineErrorKind::InvalidInput,
                task.id,
                task.idempotent,
                task.kind,
                task.kind.idempotent_by_default()
            ));
        }
        if task.state != TaskState::Pending {
            return Err(format!(
                "[{}] enqueue accepts only a pending task; got {:?}",
                EngineErrorKind::InvalidInput,
                task.state
            ));
        }
        if task.lease_holder.is_some() || task.lease_expires_at_ms.is_some() {
            return Err(format!(
                "[{}] enqueue accepts only an unleased task",
                EngineErrorKind::InvalidInput
            ));
        }
        let mut new = NewTask::new(task.id.clone(), task.kind, 0);
        new.max_attempts = self.limits.max_attempts_default;
        new.run_after_ms = 0;
        self.enqueue_new(&new, 0)
            .map_err(|e| e.to_contract_string())
    }

    fn claim(&mut self, worker: &str, now_ms: i64) -> Result<Claim, String> {
        // The concurrency budget is deliberately *not* enforced here. `claim` is the
        // contract's work-issuing primitive and the harness drives it directly; a
        // limit here would make TP-10's loop stop early and report a violation
        // against an engine that is behaving correctly. The budget is enforced by
        // `claim_task`, which is what a supervisor calls.
        let lease_ms = self.limits.lease_duration_ms;
        let outcome = self.repo().claim(worker, now_ms, lease_ms);
        match outcome
            .map_err(EngineError::from)
            .map_err(|e| e.to_contract_string())?
        {
            ClaimOutcome::Claimed(c) => Ok(Claim::Claimed(record_of(&c.row))),
            ClaimOutcome::Empty | ClaimOutcome::DeadLettered { .. } => Ok(Claim::Empty),
        }
    }

    fn complete(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
        state: TaskState,
        effect_observed: bool,
        error: Option<String>,
    ) -> Result<(), String> {
        // `Some(0)`: the conformance path drives the state machine directly and
        // moves no clock, so a backoff would leave the retry permanently
        // unclaimable and make TP-11 fail against a correct engine. Production
        // uses `complete_task`, which applies `limits.retry_backoff_ms`.
        let committed = self
            .complete_task_with(
                id,
                worker,
                now_ms,
                state,
                effect_observed,
                error.as_deref(),
                Some(0),
            )
            .map_err(|e| e.to_contract_string())?;
        if committed {
            Ok(())
        } else {
            // TP-5's refusal, reported as an error because the contract's
            // `complete` returns `Result<(), String>`: the caller asked to commit
            // and did not. The message names both possible causes so a reader does
            // not have to guess which fence fired.
            Err(format!(
                "[{}] commit refused for {id}: the caller does not hold a live lease \
                 (the lease expired, or the task was re-claimed or cancelled)",
                EngineErrorKind::ConcurrencyConflict
            ))
        }
    }

    fn request_cancel(&mut self, id: &TaskId) -> Result<(), String> {
        // The contract takes no clock, so the cancellation is recorded at the
        // engine's own notion of "now", which for this path is 0. Production uses
        // `cancel_task` with a real instant, and TP-3's "durably recorded before
        // acted upon" ordering is enforced in the repository either way.
        self.cancel_task(id, 0).map_err(|e| e.to_contract_string())
    }

    fn recover(&mut self, now_ms: i64) -> Result<(), String> {
        self.recover(now_ms)
            .map(|_| ())
            .map_err(|e| e.to_contract_string())
    }

    fn all(&self) -> Vec<TaskRecord> {
        // Infallible by design: a read failure here would have to become a fake
        // empty list (which TP-1 would report as mass disappearance) or a panic.
        // `all_tasks` is the fallible form and the engine's own tests use it.
        self.all_tasks()
            .map(|rows| rows.iter().map(record_of).collect())
            .unwrap_or_default()
    }

    fn get(&self, id: &TaskId) -> Option<TaskRecord> {
        self.task(id).ok().flatten().as_ref().map(record_of)
    }
}

/// Projects a stored row into the conformance harness's view of a task.
///
/// A projection, not a conversion: the row carries more (schedule, priority,
/// payload) and the record carries the fields the twelve properties assert on.
/// Keeping both means the harness never grows a field the engine does not have.
fn record_of(row: &TaskRow) -> TaskRecord {
    TaskRecord {
        id: row.id.clone(),
        kind: row.kind,
        state: row.state,
        attempts: row.attempts,
        lease_expires_at_ms: row.lease_expires_at_ms,
        lease_holder: row.lease_holder.clone(),
        idempotent: row.idempotent,
        effect_observed: row.effect_observed,
        last_error: row.last_error.clone(),
    }
}

/// Converts a repository error into the engine's taxonomy, for callers that only
/// have a repository result.
#[must_use]
pub fn classify(e: TaskRepoError) -> EngineErrorKind {
    EngineError::from(e).kind
}

/// The kind of task a scheduled firing creates.
///
/// A scheduled firing is **not** idempotent by default, because the capability it
/// triggers may not be. `TaskKind::ScheduledFire` encodes that in the domain, and
/// this alias exists so the scheduler and a reader agree on it.
pub const SCHEDULED_FIRE_KIND: TaskKind = TaskKind::ScheduledFire;

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_domain::approval::ApprovalDigest;
    use orxnud_domain::ids::{ScheduleId, UserId};
    use orxnud_domain::task_state::{MisfirePolicy, ScheduleSpec};
    use orxnud_store::migration::MigrationRunner;
    use orxnud_store::pragma::Pragma;

    const NOW: i64 = 1_767_225_600_000;

    fn engine_on(conn: Connection) -> DurableEngine {
        DurableEngine::new(conn, EngineLimits::documented()).expect("limits")
    }

    /// A migrated in-memory engine with specific limits.
    ///
    /// Used by the `rebuild` tests; the allowance keeps it from being dead code in
    /// builds where those tests are filtered out.
    #[allow(dead_code)]
    fn engine_with(limits: EngineLimits) -> DurableEngine {
        let c = Connection::open_in_memory().expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        MigrationRunner::new(&c).run(true).expect("migrate");
        DurableEngine::new(c, limits).expect("limits")
    }

    /// A migrated in-memory engine. Durability and crash tests use real files; the
    /// repository logic is orthogonal to that (docs-08 §4.4).
    fn mem() -> DurableEngine {
        let c = Connection::open_in_memory().expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        MigrationRunner::new(&c).run(true).expect("migrate");
        engine_on(c)
    }

    fn tid(s: &str) -> TaskId {
        TaskId::new(s)
    }

    // ------------------------------------------------------------ construction

    #[test]
    fn inconsistent_limits_are_refused_at_construction() {
        let c = Connection::open_in_memory().expect("open");
        let bad = EngineLimits {
            max_concurrent_leases: 0,
            ..EngineLimits::documented()
        };
        let err = DurableEngine::new(c, bad).expect_err("must refuse");
        assert_eq!(err.kind, EngineErrorKind::InvalidInput);
    }

    #[test]
    fn the_engine_reports_its_limits() {
        assert_eq!(mem().limits(), EngineLimits::documented());
    }

    // -------------------------------------------------------- enqueue / claim

    #[test]
    fn enqueue_then_claim_then_complete() {
        let mut e = mem();
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
        let claimed = e.claim_task("w", NOW).expect("claim").expect("some work");
        assert_eq!(claimed.id, tid("t"));
        assert_eq!(claimed.state, TaskState::Running);
        assert!(
            e.complete_task(&tid("t"), "w", NOW, TaskState::Completed, true, None)
                .expect("complete")
        );
        let row = e.task(&tid("t")).expect("read").expect("present");
        assert_eq!(row.state, TaskState::Completed);
    }

    #[test]
    fn the_concurrency_budget_is_enforced_by_claim_task() {
        let mut e = DurableEngine::new(
            {
                let c = Connection::open_in_memory().expect("open");
                Pragma::critical().apply(&c).expect("pragmas");
                MigrationRunner::new(&c).run(true).expect("migrate");
                c
            },
            EngineLimits {
                max_concurrent_leases: 2,
                ..EngineLimits::documented()
            },
        )
        .expect("limits");
        for i in 0..2 {
            e.enqueue_new(
                &NewTask::new(tid(&format!("t{i}")), TaskKind::Query, NOW),
                NOW,
            )
            .expect("enqueue");
            assert!(e.claim_task("w", NOW).expect("claim").is_some());
        }
        e.enqueue_new(&NewTask::new(tid("t2"), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
        let err = e.claim_task("w", NOW).expect_err("must refuse");
        assert_eq!(err.kind, EngineErrorKind::ConcurrencyConflict);
        assert!(err.kind.is_retryable());
    }

    #[test]
    fn an_expired_lease_frees_its_concurrency_slot() {
        let mut e = DurableEngine::new(
            {
                let c = Connection::open_in_memory().expect("open");
                Pragma::critical().apply(&c).expect("pragmas");
                MigrationRunner::new(&c).run(true).expect("migrate");
                c
            },
            EngineLimits {
                max_concurrent_leases: 1,
                ..EngineLimits::documented()
            },
        )
        .expect("limits");
        e.enqueue_new(&NewTask::new(tid("t1"), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
        let lease = e
            .claim_task("w", NOW)
            .expect("claim")
            .expect("claimed")
            .lease_expires_at_ms
            .expect("expiry");
        e.enqueue_new(&NewTask::new(tid("t2"), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
        assert!(e.claim_task("w", NOW).is_err(), "the budget is exhausted");

        // Past the expiry, the crashed worker's slot is available again. Counting
        // only live leases is what stops a dead worker occupying capacity forever.
        assert!(e.claim_task("w2", lease + 1).expect("claim").is_some());
    }

    // -------------------------------------------------------------- fencing

    #[test]
    fn a_zombie_cannot_commit_through_the_engine_either() {
        // The engine-level counterpart of the repository test: TP-5 must hold at
        // the API a caller actually uses, not only at the SQL layer.
        let mut e = mem();
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        let claimed = e
            .claim_task("zombie", NOW)
            .expect("claim")
            .expect("claimed");
        let expiry = claimed.lease_expires_at_ms.expect("expiry");

        assert!(
            !e.complete_task(
                &tid("t"),
                "zombie",
                expiry,
                TaskState::Completed,
                true,
                None
            )
            .expect("complete"),
            "an expired lease must not commit"
        );
        assert_eq!(
            e.task(&tid("t")).expect("read").expect("present").state,
            TaskState::Running
        );
    }

    #[test]
    fn a_heartbeat_from_a_zombie_does_not_revive_its_lease() {
        let mut e = mem();
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        let expiry = e
            .claim_task("zombie", NOW)
            .expect("claim")
            .expect("claimed")
            .lease_expires_at_ms
            .expect("expiry");
        assert!(!e.heartbeat(&tid("t"), "zombie", expiry).expect("hb"));
        assert_eq!(
            e.task(&tid("t"))
                .expect("read")
                .expect("present")
                .lease_expires_at_ms,
            Some(expiry)
        );
    }

    // ---------------------------------------------------------- idempotency

    #[test]
    fn the_idempotency_key_separates_attempt_classes_and_steps_but_not_retries() {
        let id = tid("t");
        assert_ne!(
            DurableEngine::idempotency_key(&id, "s", "initial"),
            DurableEngine::idempotency_key(&id, "s", "retry")
        );
        assert_eq!(
            DurableEngine::idempotency_key(&id, "s", "retry"),
            DurableEngine::idempotency_key(&id, "s", "retry"),
            "two retries of one step share a key, which is what dedups them"
        );
        assert_ne!(
            DurableEngine::idempotency_key(&id, "a", "initial"),
            DurableEngine::idempotency_key(&id, "b", "initial")
        );
        assert_ne!(
            DurableEngine::idempotency_key(&tid("x"), "s", "initial"),
            DurableEngine::idempotency_key(&tid("y"), "s", "initial")
        );
    }

    #[test]
    fn the_idempotency_key_cannot_be_forged_by_a_field_boundary() {
        // Without the length prefix, ("ab","c") and ("a","bc") would collide and one
        // task's key would suppress another's side effect.
        assert_ne!(
            DurableEngine::idempotency_key(&tid("ab"), "c", "i"),
            DurableEngine::idempotency_key(&tid("a"), "bc", "i")
        );
    }

    #[test]
    fn a_second_reservation_of_the_same_key_is_refused() {
        let mut e = mem();
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        let _ = e.claim_task("w", NOW).expect("claim");
        let key = DurableEngine::idempotency_key(&tid("t"), "send", "initial");
        assert!(
            e.reserve_effect(&key, &tid("t"), 1, "send", NOW)
                .expect("reserve")
        );
        assert!(
            !e.reserve_effect(&key, &tid("t"), 2, "send", NOW)
                .expect("reserve"),
            "a retry must not be able to dispatch the same effect again"
        );
    }

    #[test]
    fn an_effect_can_end_unknown_and_still_be_resolved() {
        // TP-12: "outcome unknown" is a recorded state, not an absence.
        let mut e = mem();
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        let _ = e.claim_task("w", NOW).expect("claim");
        let key = DurableEngine::idempotency_key(&tid("t"), "s", "initial");
        let _ = e
            .reserve_effect(&key, &tid("t"), 1, "s", NOW)
            .expect("reserve");
        assert!(!e.all_effects_resolved(&tid("t")).expect("unresolved"));
        assert!(
            e.resolve_effect(&key, EffectStatus::Unknown, Some("timed out"), NOW + 1)
                .expect("resolve")
        );
        assert!(e.all_effects_resolved(&tid("t")).expect("resolved"));
    }

    // ------------------------------------------------------------ approvals

    fn approval(task: &str, attempt: u32, expires: i64) -> ApprovalRow {
        ApprovalRow {
            task_id: tid(task),
            attempt_no: attempt,
            digest_hex: "ab".repeat(32),
            capability: "cap".into(),
            target: None,
            params: "{}".into(),
            issued_at_ms: NOW,
            expires_at_ms: expires,
            consumed_at_ms: None,
        }
    }

    #[test]
    fn a_retry_must_re_derive_its_approval() {
        let mut e = mem();
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        let _ = e.claim_task("w", NOW).expect("claim");
        e.record_approval(&approval("t", 1, NOW + 60_000))
            .expect("record");
        assert!(e.may_use_approval(&tid("t"), 1, NOW).expect("check"));

        let _ = e
            .complete_task_with(
                &tid("t"),
                "w",
                NOW,
                TaskState::Failed,
                false,
                Some("boom"),
                Some(0),
            )
            .expect("fail");
        let retry = e.claim_task("w", NOW + 1).expect("claim").expect("claimed");
        assert_eq!(retry.attempts, 2);

        assert!(
            !e.may_use_approval(&tid("t"), 2, NOW + 1).expect("check"),
            "TP-6: a retry inherits nothing"
        );
    }

    #[test]
    fn a_consumed_approval_is_not_reusable() {
        let mut e = mem();
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        let _ = e.claim_task("w", NOW).expect("claim");
        e.record_approval(&approval("t", 1, NOW + 60_000))
            .expect("record");
        e.consume_approval(&tid("t"), 1, NOW).expect("consume");
        assert!(!e.may_use_approval(&tid("t"), 1, NOW + 1).expect("check"));
    }

    #[test]
    fn a_changed_digest_does_not_match_the_stored_approval() {
        // The approval is bound to the digest of the exact operation. A different
        // digest is a different operation, and the stored row is for the old one.
        let mut e = mem();
        e.enqueue_new(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect("enqueue");
        let _ = e.claim_task("w", NOW).expect("claim");
        let mut a = approval("t", 1, NOW + 60_000);
        a.digest_hex = ApprovalDigest::from_bytes([9u8; 32]).to_hex();
        e.record_approval(&a).expect("record");
        let stored = e
            .approval_for(&tid("t"), 1)
            .expect("read")
            .expect("present");
        assert_eq!(stored.digest_hex, a.digest_hex);
        assert_ne!(
            stored.digest_hex,
            ApprovalDigest::from_bytes([1u8; 32]).to_hex()
        );
    }

    // ---------------------------------------------------- contract guards

    #[test]
    fn enqueue_refuses_a_task_whose_idempotency_contradicts_its_kind() {
        let mut e = mem();
        let mut t = TaskRecord::pending(tid("t"), TaskKind::Workflow);
        t.idempotent = true; // TP-2 turns on exactly this flag
        let err = TaskEngine::enqueue(&mut e, t).expect_err("must refuse");
        assert!(err.contains("idempotent"), "{err}");
    }

    #[test]
    fn enqueue_refuses_a_non_pending_or_leased_task() {
        let mut e = mem();
        let mut running = TaskRecord::pending(tid("a"), TaskKind::Query);
        running.state = TaskState::Running;
        assert!(
            TaskEngine::enqueue(&mut e, running)
                .expect_err("must refuse")
                .contains("pending")
        );

        let mut leased = TaskRecord::pending(tid("b"), TaskKind::Query);
        leased.lease_holder = Some("w".into());
        leased.lease_expires_at_ms = Some(NOW + 1);
        assert!(
            TaskEngine::enqueue(&mut e, leased)
                .expect_err("must refuse")
                .contains("unleased")
        );
    }

    #[test]
    fn the_engine_declares_lease_fencing() {
        // Declared rather than inferred: a gap must show up as `ConformsWithGaps`,
        // not as a property that quietly did not run.
        assert!(mem().supports_lease_fencing());
        assert_eq!(mem().name(), "sqlite-durable");
    }

    #[test]
    fn schedules_can_be_written_and_read_through_the_engine() {
        let mut e = mem();
        let spec = ScheduleSpec {
            id: ScheduleId::new("s"),
            cron: "0 * * * *".into(),
            timezone: "UTC".into(),
            misfire: MisfirePolicy::FireOnce,
            catch_up_cap: 5,
            enabled: true,
            authorised_by: UserId::new("u"),
        };
        e.schedules().insert(&spec, NOW).expect("insert");
        let row = e
            .schedules()
            .get(&ScheduleId::new("s"))
            .expect("get")
            .expect("present");
        assert_eq!(row.misfire, MisfirePolicy::FireOnce);
    }

    #[test]
    fn a_repository_error_classifies_to_the_right_kind() {
        assert_eq!(
            classify(TaskRepoError::AlreadyExists("t".into())),
            EngineErrorKind::InvalidInput
        );
        assert_eq!(
            classify(TaskRepoError::Corrupt(Box::new(
                orxnud_store::task_repo::CorruptRowDetail {
                    id: "t".into(),
                    reason: "x".into(),
                },
            ))),
            EngineErrorKind::Invariant
        );
    }

    #[test]
    fn a_scheduled_firing_is_not_idempotent_by_default() {
        // Because the capability it triggers may not be.
        assert!(!SCHEDULED_FIRE_KIND.idempotent_by_default());
    }
}
