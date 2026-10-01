//! Task persistence: the SQL, and the transaction boundaries around it.
//!
//! # One writer, one transaction per transition
//!
//! Every mutation runs inside `BEGIN IMMEDIATE` (ADR-0007 invariant 1), and every
//! method that writes takes `&mut Connection`, so the compiler — not a review —
//! prevents two callers interleaving inside a transaction.
//!
//! # The three invariants ADR-0007 names
//!
//! 1. **Every state transition is a single `BEGIN IMMEDIATE` transaction.**
//!    `sqlite.org/lang_transaction.html`: *"If the BEGIN IMMEDIATE operation
//!    succeeds, then no subsequent operations in that transaction will ever fail
//!    with a SQLITE_BUSY error."*
//! 2. **Claim is atomic** — `UPDATE ... WHERE id = (SELECT ... LIMIT 1) RETURNING *`.
//!    Never `SELECT` then `UPDATE`, which has a window in which two workers claim
//!    the same task.
//! 3. **Every external side effect carries a deterministic idempotency key, and
//!    the dedupe row is written in the same transaction as the DB write.**
//!    See [`TaskRepository::reserve_effect`].
//!
//! # Fencing (TP-5) is one `WHERE` clause
//!
//! [`TaskRepository::complete`] does not read-then-check-then-write. It is a
//! single conditional `UPDATE` whose `WHERE` names the holder **and** requires
//! the lease to still be live:
//!
//! ```sql
//! WHERE id = ? AND lease_holder = ? AND lease_expires_at_ms > ?
//! ```
//!
//! That matters, and it is the case ADR-0032 found broken in `apalis-sqlite`:
//! a zombie whose lease expired but whose task was not yet re-claimed still finds
//! its `worker` id matching. Checking `lease_holder` alone passes the re-claimed
//! case and fails the expired-but-unclaimed one. Checking only `lease_expires_at`
//! passes that one and fails the re-claimed one. Both are required, in one
//! statement, so there is no window between them.
//!
//! # Untrusted rows
//!
//! Every value read back out of a row goes through [`TaskState::from_wire_str`] or
//! an equivalent refusal. An unrecognised state is an error, never a default —
//! and the default that matters here would be `Pending`, the only claimable state,
//! so defaulting an unreadable row would resurrect a task somebody deliberately
//! made terminal.

use rusqlite::{Connection, OptionalExtension, Transaction};

use orxnud_domain::ids::{ScheduleId, TaskId};
use orxnud_domain::task_state::{TaskKind, TaskState};

use crate::faults::{self, FaultPoint};

/// A persistence failure.
///
/// Distinct variants because the *remedies* differ: a transient SQLite busy is
/// retried, a constraint violation is a bug, and a corrupt row is data loss.
// The variants differ in size because `Sqlite` wraps rusqlite's error and the
// string variants wrap `String`s. Boxing every one of them would cost an
// allocation on the happy path to satisfy a lint, so the enum carries an
// allowance with a reason instead.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, thiserror::Error)]
pub enum TaskRepoError {
    /// An underlying SQLite error.
    ///
    /// Boxed, not `#[from]`: `rusqlite::Error` is ~136 bytes, which made every
    /// `Result` in the crate that large — on a path taken once per task
    /// transition. Boxing costs nothing on the happy path and one allocation only
    /// when something has already gone wrong.
    #[error("sqlite error: {0}")]
    Sqlite(Box<rusqlite::Error>),

    /// A row could not be decoded; see [`CorruptRowDetail`].
    ///
    /// Boxed and transparent: two `String`s inline make the variant much larger
    /// than its neighbours, and an unboxed fat variant makes *every* `Result` in
    /// the crate large — a real cost on a path taken per task transition.
    /// `transparent` because `thiserror` cannot interpolate through a `Box`, and
    /// the detail type already renders the whole message.
    #[error(transparent)]
    Corrupt(Box<CorruptRowDetail>),

    /// The row exists but its `state` is not a state this build knows.
    ///
    /// Reported rather than coerced. See the module docs on untrusted rows.
    /// Boxed for the same reason as `Sqlite`.
    #[error(transparent)]
    UnknownState(Box<UnknownStateDetail>),

    /// A row could not be decoded into its domain type.
    ///
    /// Boxed: the two `String`s make the variant far larger than its neighbours,
    /// and an unboxed fat variant makes *every* `Result` in the crate large.
    /// A task with this id already exists.
    ///
    /// A distinct variant because the caller may legitimately want to treat it as
    /// idempotent — and must then *say so*, rather than have the store decide.
    #[error("task {0} already exists")]
    AlreadyExists(String),

    /// No task with this id.
    #[error("no task {0}")]
    NotFound(String),
}

/// What an unreadable `state` column contained.
#[derive(Debug, thiserror::Error)]
#[error("task {id} has unrecognised state {raw:?}")]
pub struct UnknownStateDetail {
    /// The offending task.
    pub id: String,
    /// What was in the row.
    pub raw: String,
}

/// Why a row could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptRowDetail {
    /// The offending task.
    pub id: String,
    /// What was wrong.
    pub reason: String,
}

impl std::fmt::Display for CorruptRowDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "task {} is corrupt: {}", self.id, self.reason)
    }
}

impl std::error::Error for CorruptRowDetail {}

/// One task row, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRow {
    /// The id.
    pub id: TaskId,
    /// What kind.
    pub kind: TaskKind,
    /// Lifecycle state.
    pub state: TaskState,
    /// Higher runs first.
    pub priority: i64,
    /// Attempts made.
    pub attempts: u32,
    /// Attempt ceiling before dead-lettering.
    pub max_attempts: u32,
    /// Lease expiry, ms since epoch.
    pub lease_expires_at_ms: Option<i64>,
    /// The worker holding the lease.
    pub lease_holder: Option<String>,
    /// Whether repeating is safe.
    pub idempotent: bool,
    /// Whether an effect has been observed.
    pub effect_observed: bool,
    /// When the task may next be claimed.
    pub run_after_ms: i64,
    /// Whether this run came from catch-up.
    pub catch_up: bool,
    /// The last error, for diagnostics and for TP-11's visibility requirement.
    pub last_error: Option<String>,
    /// When cancellation was durably requested.
    pub cancel_requested_at_ms: Option<i64>,
    /// The schedule this came from, if any.
    pub schedule_id: Option<ScheduleId>,
    /// The fire time, if any.
    pub fire_time_ms: Option<i64>,
    /// When the row was created.
    pub created_at_ms: i64,
    /// When the row last changed.
    pub updated_at_ms: i64,
    /// When it dead-lettered.
    pub dead_lettered_at_ms: Option<i64>,
    /// When it reached a terminal end state.
    pub terminal_at_ms: Option<i64>,
}

impl TaskRow {
    /// Whether the lease is dead at `now_ms`.
    ///
    /// Half-open: a lease is live iff `now < expiry`. Matches
    /// [`orxnud_domain::task_state::TaskStatus::lease_is_expired_at`].
    #[must_use]
    pub fn lease_is_expired_at(&self, now_ms: i64) -> bool {
        self.lease_expires_at_ms.is_some_and(|e| now_ms >= e)
    }

    /// Whether the retry budget is spent.
    #[must_use]
    pub fn retries_exhausted(&self) -> bool {
        self.attempts >= self.max_attempts
    }

    /// Whether the task is claimable right now.
    #[must_use]
    pub fn is_claimable_at(&self, now_ms: i64) -> bool {
        self.state.is_claimable() && self.run_after_ms <= now_ms && !self.retries_exhausted()
    }
}

/// How a task is to be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTask {
    /// The id.
    pub id: TaskId,
    /// What kind.
    pub kind: TaskKind,
    /// Higher runs first.
    pub priority: i64,
    /// Attempt ceiling before dead-lettering.
    pub max_attempts: u32,
    /// When it may first be claimed.
    pub run_after_ms: i64,
    /// The originating schedule, if any.
    pub schedule_id: Option<ScheduleId>,
    /// The originating fire time, if any.
    pub fire_time_ms: Option<i64>,
    /// Whether this run came from catch-up.
    pub catch_up: bool,
    /// An opaque payload, validated on the way in and on the way out.
    pub payload: Option<String>,
}

impl NewTask {
    /// A new task with the given kind.
    #[must_use]
    pub fn new(id: TaskId, kind: TaskKind, now_ms: i64) -> Self {
        Self {
            id,
            kind,
            priority: 0,
            // Three is the documented default retry budget. Bounded on purpose:
            // an unbounded retry budget is a retry storm (TP-10).
            max_attempts: 3,
            run_after_ms: now_ms,
            schedule_id: None,
            fire_time_ms: None,
            catch_up: false,
            payload: None,
        }
    }
}

/// A claimed task: the row plus the attempt number this claim opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedTask {
    /// The row as it now stands.
    pub row: TaskRow,
    /// The attempt number, 1-based.
    pub attempt_no: u32,
    /// The lease expiry granted.
    pub lease_expires_at_ms: i64,
}

/// The result of asking for work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// A task was claimed.
    ///
    /// Boxed: `ClaimedTask` embeds a whole `TaskRow`, making this variant ~240
    /// bytes next to a 24-byte sibling. Without the box, every *empty* claim — the
    /// common case when the queue is idle — moved 240 bytes.
    Claimed(Box<ClaimedTask>),
    /// Nothing was claimable.
    Empty,
    /// A task was past its retry budget and was dead-lettered instead of being
    /// handed out, and there was nothing else to claim.
    DeadLettered {
        /// The task that was dead-lettered.
        task_id: TaskId,
    },
}

/// An event in the transition log (ADR-0028 invariant 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskEvent {
    /// Monotonic, never reused.
    pub seq: i64,
    /// The task, if the event is about one.
    pub task_id: Option<TaskId>,
    /// When.
    pub at_ms: i64,
    /// What happened.
    pub kind: String,
    /// The state before, if this is a transition.
    pub from_state: Option<TaskState>,
    /// The state after.
    pub to_state: Option<TaskState>,
    /// The worker involved.
    pub worker: Option<String>,
    /// The attempt involved.
    pub attempt_no: Option<u32>,
    /// Free detail. Never a secret.
    pub detail: Option<String>,
}

/// A reserved but unresolved side effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedEffect {
    /// The dedup key.
    pub idempotency_key: String,
    /// The task.
    pub task_id: TaskId,
    /// The attempt that reserved it.
    pub attempt_no: u32,
    /// The step within the task.
    pub step_key: String,
    /// `observed`, `unknown`, or `not-performed`.
    pub status: String,
    /// Detail. Never a secret.
    pub detail: Option<String>,
}

/// An approval, bound to exactly one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRow {
    /// The task.
    pub task_id: TaskId,
    /// The attempt this approval belongs to.
    pub attempt_no: u32,
    /// The digest, hex-encoded.
    pub digest_hex: String,
    /// The capability the human believed they were approving.
    pub capability: String,
    /// The target.
    pub target: Option<String>,
    /// The canonical parameters.
    pub params: String,
    /// Issue time.
    pub issued_at_ms: i64,
    /// Expiry.
    pub expires_at_ms: i64,
    /// When it was consumed, if it has been.
    pub consumed_at_ms: Option<i64>,
}

impl ApprovalRow {
    /// Whether the approval is usable at `now_ms`.
    #[must_use]
    pub fn is_valid_at(&self, now_ms: i64) -> bool {
        self.consumed_at_ms.is_none() && now_ms < self.expires_at_ms
    }
}

/// The task store. Every SQL statement for the task layer lives here.
#[derive(Debug)]
pub struct TaskRepository<'a> {
    conn: &'a Connection,
}

fn unknown_state(id: String, raw: String) -> TaskRepoError {
    TaskRepoError::UnknownState(Box::new(UnknownStateDetail { id, raw }))
}

impl From<rusqlite::Error> for TaskRepoError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(Box::new(e))
    }
}

impl<'a> TaskRepository<'a> {
    /// Wraps a connection for writing.
    #[must_use]
    pub fn new(conn: &'a mut Connection) -> Self {
        Self { conn }
    }

    /// The connection this repository reads and writes through.
    #[must_use]
    pub fn connection(&self) -> &Connection {
        self.conn
    }

    /// Wraps a connection for **reading only**.
    ///
    /// The write methods take `&mut Connection` so that two callers cannot
    /// interleave inside a transaction. A read needs no such exclusivity, and
    /// demanding `&mut` for a read would force a caller that only wants to inspect
    /// state to have write access.
    ///
    /// # Why this is safe
    ///
    /// The repository's read methods take `&self`, so the `&Connection` cannot be
    /// used to write. `new` (the writing constructor) requires `&mut`, so a caller
    /// holding only `&Connection` can never obtain a writing repository from it.
    #[must_use]
    pub fn new_readonly(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Begins an immediate transaction.
    ///
    /// `IMMEDIATE`, never `DEFERRED`: with a deferred transaction the write lock
    /// is taken at the first *read*, so a second writer can change the table
    /// between our read and our write and the statement is retried — which for a
    /// state transition means deciding again whether it is legal.
    fn tx(&mut self) -> Result<Transaction<'_>, TaskRepoError> {
        // `unchecked_transaction` is required, not chosen: a transaction needs a
        // `&mut` borrow of the connection, and this repository deliberately holds a
        // shared one so that reads do not require write access. The single-writer
        // discipline (ADR-0006) is what makes this safe: exactly one `&mut
        // TaskRepository` exists at a time, so exactly one transaction can be open.
        Ok(self.conn.unchecked_transaction()?)
    }

    // ---------------------------------------------------------------- enqueue

    /// Inserts a new task.
    ///
    /// # Errors
    ///
    /// [`TaskRepoError::AlreadyExists`] if the id is taken. Plain `INSERT`: a
    /// silent upsert would let a re-enqueue overwrite a task that had already
    /// made progress, which is TP-1's "silently disappears" in the other
    /// direction.
    pub fn insert(&mut self, task: &NewTask, now_ms: i64) -> Result<(), TaskRepoError> {
        let tx = self.tx()?;
        let n = insert_outcome(tx.execute(
            "INSERT INTO tasks (
                id, kind, state, priority, payload, idempotent, effect_observed,
                attempts, max_attempts, lease_holder, lease_expires_at_ms,
                run_after_ms, catch_up, cancel_requested_at_ms, schedule_id, fire_time_ms,
                created_at_ms, updated_at_ms, completed_at_ms, dead_lettered_at_ms)
             VALUES (?1, ?2, 'pending', ?3, ?4, ?5, 0, 0, ?6, NULL, NULL,
                     ?7, ?8, NULL, ?9, ?10, ?11, ?11, NULL, NULL);",
            rusqlite::params![
                task.id.as_str(),
                task.kind.as_wire_str(),
                task.priority,
                task.payload,
                task.kind.idempotent_by_default(),
                task.max_attempts,
                task.run_after_ms,
                task.catch_up,
                task.schedule_id.as_ref().map(ToString::to_string),
                task.fire_time_ms,
                now_ms,
            ],
        ))?;
        if is_unique_violation(&n) {
            return Err(TaskRepoError::AlreadyExists(task.id.to_string()));
        }
        log(
            &tx,
            Some(&task.id),
            now_ms,
            "enqueued",
            None,
            Some(TaskState::Pending),
            None,
            None,
            Some(task.kind.as_wire_str()),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// How many tasks exist.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn count(&self) -> Result<i64, TaskRepoError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM tasks;", [], |r| r.get(0))?)
    }

    /// How many tasks are in a given state.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn count_in_state(&self, state: TaskState) -> Result<i64, TaskRepoError> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM tasks WHERE state = ?1;",
            [state.as_wire_str()],
            |r| r.get(0),
        )?)
    }

    // ------------------------------------------------------------------ read

    /// Reads one task.
    ///
    /// # Errors
    ///
    /// [`TaskRepoError::UnknownState`] if the stored state is unrecognised, or
    /// [`TaskRepoError::CorruptRow`] if another column cannot be decoded.
    pub fn get(&self, id: &TaskId) -> Result<Option<TaskRow>, TaskRepoError> {
        let sql = "SELECT id, kind, state, priority, attempts, max_attempts,
                          lease_expires_at_ms, lease_holder, idempotent, effect_observed,
                          run_after_ms, catch_up, last_error, cancel_requested_at_ms,
                          schedule_id, fire_time_ms, created_at_ms, updated_at_ms,
                          dead_lettered_at_ms, completed_at_ms
                     FROM tasks WHERE id = ?1;";
        self.conn
            .query_row(sql, [id.as_str()], decode_row)
            .optional()?
            .transpose()
    }

    /// Reads every task, ordered by id.
    ///
    /// A **full scan**, deliberately. `TaskEngine::all` is the accessor the
    /// conformance suite's TP-1 uses to prove nothing vanished, so bounding it
    /// would weaken the property it exists to check. Production diagnostics that
    /// merely want a sample use [`Self::list_limited`].
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub fn all(&self) -> Result<Vec<TaskRow>, TaskRepoError> {
        let sql = "SELECT id, kind, state, priority, attempts, max_attempts,
                          lease_expires_at_ms, lease_holder, idempotent, effect_observed,
                          run_after_ms, catch_up, last_error, cancel_requested_at_ms,
                          schedule_id, fire_time_ms, created_at_ms, updated_at_ms,
                          dead_lettered_at_ms, completed_at_ms
                     FROM tasks ORDER BY id;";
        self.read_rows(sql)
    }

    /// Reads at most `limit` tasks, for a diagnostic that does not need them all.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub fn list_limited(&self, limit: u32) -> Result<Vec<TaskRow>, TaskRepoError> {
        let sql = "SELECT id, kind, state, priority, attempts, max_attempts,
                          lease_expires_at_ms, lease_holder, idempotent, effect_observed,
                          run_after_ms, catch_up, last_error, cancel_requested_at_ms,
                          schedule_id, fire_time_ms, created_at_ms, updated_at_ms,
                          dead_lettered_at_ms, completed_at_ms
                     FROM tasks ORDER BY id LIMIT ?1;";
        self.read_rows_with(sql, [i64::from(limit)])
    }

    /// Tasks with a live lease, for a supervisor's concurrency check.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn live_leases(&self, now_ms: i64) -> Result<i64, TaskRepoError> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM tasks WHERE lease_holder IS NOT NULL AND lease_expires_at_ms > ?1;",
            [now_ms],
            |r| r.get(0),
        )?)
    }

    fn read_rows(&self, sql: &str) -> Result<Vec<TaskRow>, TaskRepoError> {
        self.read_rows_with(sql, [])
    }

    fn read_rows_with<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
    ) -> Result<Vec<TaskRow>, TaskRepoError> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(params, decode_row)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    // ----------------------------------------------------------------- claim

    /// Atomically claims one claimable task, taking a lease.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn claim(
        &mut self,
        worker: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<ClaimOutcome, TaskRepoError> {
        let tx = self.tx()?;

        // INVARIANT (ADR-0007 invariant 2): the SELECT and the UPDATE are one
        // statement. A separate SELECT followed by an UPDATE has a window in which
        // two workers both see the same free task.
        //
        // The partial index `idx_tasks_claimable` contains exactly the rows this
        // subquery can return, so the scan is proportional to the backlog rather
        // than to history.
        let claimed: Option<(String, String, i64, i64)> = tx
            .query_row(
                "UPDATE tasks
                    SET state                  = 'running',
                        lease_holder           = ?1,
                        lease_expires_at_ms    = ?2,
                        attempts               = attempts + 1,
                        updated_at_ms          = ?3
                  WHERE id = (
                        SELECT id FROM tasks
                         WHERE state = 'pending'
                           AND run_after_ms <= ?3
                           AND attempts < max_attempts
                         ORDER BY priority DESC, created_at_ms ASC, id ASC
                         LIMIT 1)
                 RETURNING id, kind, lease_expires_at_ms, attempts;",
                rusqlite::params![worker, now_ms.saturating_add(lease_ms), now_ms],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;

        let Some((id, kind, lease_expires_at_ms, attempts)) = claimed else {
            // Nothing claimable. A task past its budget is not claimable either --
            // but leaving it `pending` forever is the retry-storm bug TP-10 warns
            // about, so it is dead-lettered here, loudly, rather than being
            // silently skipped on every pass.
            let stranded: Option<String> = tx
                .query_row(
                    "SELECT id FROM tasks
                      WHERE state = 'pending' AND attempts >= max_attempts
                      ORDER BY created_at_ms ASC, id ASC LIMIT 1;",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(task_id) = stranded else {
                tx.commit()?;
                return Ok(ClaimOutcome::Empty);
            };
            dead_letter(&tx, &task_id, now_ms, "retry budget exhausted before claim")?;
            log(
                &tx,
                Some(&TaskId::new(&task_id)),
                now_ms,
                "dead-lettered",
                Some(TaskState::Pending),
                Some(TaskState::DeadLettered),
                None,
                None,
                Some("retries exhausted"),
            )?;
            tx.commit()?;
            return Ok(ClaimOutcome::DeadLettered {
                task_id: TaskId::new(&task_id),
            });
        };

        let task_id = TaskId::new(&id);
        let attempt_no = u32::try_from(attempts).unwrap_or(u32::MAX);

        // Test-only: die holding the claim but with no attempt row. A restart must
        // see neither a lease nor an attempt, because the claim never committed.
        faults::maybe_crash(FaultPoint::ClaimAfterTakeBeforeAttempt);

        tx.execute(
            "INSERT INTO task_attempts (task_id, attempt_no, worker, started_at_ms)
             VALUES (?1, ?2, ?3, ?4);",
            rusqlite::params![task_id.as_str(), attempt_no, worker, now_ms],
        )?;
        log(
            &tx,
            Some(&task_id),
            now_ms,
            "claimed",
            Some(TaskState::Pending),
            Some(TaskState::Running),
            Some(worker),
            Some(attempt_no),
            Some(&kind),
        )?;
        tx.commit()?;

        let row = self
            .get(&task_id)?
            .ok_or_else(|| TaskRepoError::NotFound(id.clone()))?;
        Ok(ClaimOutcome::Claimed(Box::new(ClaimedTask {
            row,
            attempt_no,
            lease_expires_at_ms,
        })))
    }

    // --------------------------------------------------------------- complete

    /// Records a terminal outcome, **fencing on a live lease held by `worker`**.
    ///
    /// Returns `Ok(false)` when the fence rejects the commit — an expired lease, a
    /// task held by somebody else, or no such task. It is not an *error*: a
    /// zombie worker asking to commit is a normal, expected event under TP-5, and
    /// the caller learns about it by the value.
    ///
    /// # Errors
    ///
    /// Any SQLite error, or [`TaskRepoError::CorruptRow`] if the stored state is
    /// unrecognisable.
    pub fn complete(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
        to: TaskState,
        effect_observed: bool,
        error: Option<&str>,
    ) -> Result<bool, TaskRepoError> {
        self.complete_with(id, worker, now_ms, to, effect_observed, error, 0)
    }

    /// [`Self::complete`], with an explicit retry delay.
    ///
    /// # Why a retry delay is a parameter
    ///
    /// A `Failed` task whose budget remains is put back to `pending` rather than
    /// being left terminal — otherwise "within the retry budget" would mean "no
    /// retry", and a task that fails transiently once would be permanently dead.
    /// With that, *when* it becomes claimable is a scheduling decision: a
    /// production caller passes a backoff to avoid a hot retry loop, and a caller
    /// that is driving the state machine directly passes 0.
    ///
    /// The alternative — a fixed backoff baked into the repository — would make
    /// TP-11 untestable without also moving a clock the harness does not own.
    ///
    /// # Errors
    ///
    /// As [`Self::complete`].
    #[allow(clippy::too_many_arguments)]
    pub fn complete_with(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
        to: TaskState,
        effect_observed: bool,
        error: Option<&str>,
        retry_delay_ms: i64,
    ) -> Result<bool, TaskRepoError> {
        let tx = self.tx()?;

        // INVARIANT: the fence is evaluated **before** the legality check, and
        // inside the same IMMEDIATE transaction, so the two cannot disagree and
        // no other writer can change the row between them.
        //
        // The ordering is load-bearing. A worker whose task was cancelled, or whose
        // lease expired, must be told "you do not hold this" -- not "illegal
        // transition", which would blame the worker for something the engine did.
        let current: Option<(String, Option<String>, Option<i64>)> = tx
            .query_row(
                "SELECT state, lease_holder, lease_expires_at_ms FROM tasks WHERE id = ?1;",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        let Some((from_raw, holder, expiry)) = current else {
            tx.commit()?;
            return Ok(false);
        };
        let from_state = TaskState::from_wire_str(&from_raw)
            .ok_or_else(|| unknown_state(id.to_string(), from_raw.clone()))?;

        // Both halves of the fence, checked together (ADR-0032's finding).
        if holder.as_deref() != Some(worker) || expiry.is_none_or(|e| now_ms >= e) {
            tx.commit()?;
            return Ok(false);
        }

        // INVARIANT (TP-5): ONE conditional UPDATE whose WHERE names both the
        // holder and a live lease. `lease_expires_at_ms > ?now` makes the lease
        // half-open, matching `TaskStatus::lease_is_expired_at`.
        //
        // Checking `lease_holder` alone is what `apalis-sqlite` does, and it fails
        // the expired-but-unclaimed case (ADR-0032). Checking the expiry alone
        // fails the re-claimed case. Both, atomically, is the only version that
        // satisfies both.
        let dead_lettered = to == TaskState::DeadLettered
            || (to == TaskState::Failed && {
                let attempts: u32 = tx.query_row(
                    "SELECT attempts FROM tasks WHERE id = ?1;",
                    [id.as_str()],
                    |r| r.get(0),
                )?;
                let max: u32 = tx.query_row(
                    "SELECT max_attempts FROM tasks WHERE id = ?1;",
                    [id.as_str()],
                    |r| r.get(0),
                )?;
                attempts >= max
            });

        let final_state = if dead_lettered {
            TaskState::DeadLettered
        } else {
            to
        };

        // The *worker's* requested outcome is what must be legal. The requeue to
        // `pending` is a separate, always-legal bookkeeping step, so checking
        // `stored_state` here would wrongly reject a legitimate retry.
        if !orxnud_domain::task_state::is_legal_transition(from_state, final_state)
            && from_state != final_state
        {
            tx.commit()?;
            return Err(TaskRepoError::Corrupt(Box::new(CorruptRowDetail {
                id: id.to_string(),
                reason: format!("illegal transition {from_state:?} -> {final_state:?}"),
            })));
        }

        // A failed task inside its retry budget goes back to `pending` with a
        // fresh `run_after_ms`, so the retry is visible as a scheduling decision
        // rather than hidden inside the failure.
        let requeue = to == TaskState::Failed && !dead_lettered;
        let stored_state = if requeue {
            TaskState::Pending
        } else {
            final_state
        };

        let changed = tx.execute(
            "UPDATE tasks
                SET state               = ?4,
                    effect_observed     = ?5,
                    last_error          = ?6,
                    lease_holder        = NULL,
                    lease_expires_at_ms = NULL,
                    updated_at_ms       = ?3,
                    run_after_ms        = CASE WHEN ?4 = 'pending' THEN ?3 + ?7
                                              ELSE run_after_ms END,
                    completed_at_ms     = CASE WHEN ?4 IN ('completed','dead-lettered','cancelled')
                                              THEN ?3 ELSE NULL END,
                    dead_lettered_at_ms = CASE WHEN ?4 = 'dead-lettered' THEN ?3
                                              ELSE NULL END
              WHERE id          = ?1
                AND lease_holder = ?2
                AND lease_expires_at_ms IS NOT NULL
                AND lease_expires_at_ms > ?3;",
            rusqlite::params![
                id.as_str(),
                worker,
                now_ms,
                stored_state.as_wire_str(),
                effect_observed,
                error,
                retry_delay_ms,
            ],
        )?;

        if changed == 0 {
            // The fence held. Nothing was written, and that is the whole point.
            tx.commit()?;
            return Ok(false);
        }

        // Test-only: die here, with the tasks row updated and the attempt row not
        // yet closed. Atomicity means neither half survives.
        faults::maybe_crash(FaultPoint::CompleteAfterUpdateBeforeAttempt);

        // Close the attempt row.
        tx.execute(
            "UPDATE task_attempts
                SET finished_at_ms = ?3, outcome = ?4, error = ?5
              WHERE task_id = ?1 AND worker = ?2 AND finished_at_ms IS NULL;",
            rusqlite::params![id.as_str(), worker, now_ms, to.as_wire_str(), error],
        )?;

        log(
            &tx,
            Some(id),
            now_ms,
            // The event kind must name what actually happened. Logging a
            // dead-letter as `completed` because the worker *asked* for `Failed`
            // would be a lie in the one log a support request reads.
            if dead_lettered {
                "dead-lettered"
            } else if requeue {
                "failed-will-retry"
            } else {
                "completed"
            },
            Some(from_state),
            Some(stored_state),
            Some(worker),
            None,
            Some(error.unwrap_or("")),
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Extends a lease the caller still holds.
    ///
    /// Returns `Ok(false)` if the caller does not hold a live lease — the same
    /// fence as [`Self::complete`]. A heartbeat from a zombie must not revive a
    /// dead lease, because that is how a task gets two live owners.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn heartbeat(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<bool, TaskRepoError> {
        let changed = write(self.conn.execute(
            "UPDATE tasks
                SET lease_expires_at_ms = ?4, updated_at_ms = ?3
              WHERE id = ?1 AND lease_holder = ?2
                AND lease_expires_at_ms IS NOT NULL AND lease_expires_at_ms > ?3;",
            rusqlite::params![id.as_str(), worker, now_ms, now_ms.saturating_add(lease_ms)],
        ))?;
        Ok(changed > 0)
    }

    // ----------------------------------------------------------------- cancel

    /// Records a cancellation request, then acts on it.
    ///
    /// Two transactions, deliberately. ADR-0029 TP-3 requires the request to be
    /// *"durably recorded before it is acted upon"*: a cancellation that is only
    /// visible as the state change cannot be distinguished from a cancellation that
    /// was simply never requested. Recording `cancel_requested_at_ms` first makes
    /// the request itself observable, so "who asked, and when" survives even if
    /// the process dies between the two writes.
    ///
    /// A task that is already terminal is left alone — cancelling a completed task
    /// would be resurrection.
    ///
    /// # Errors
    ///
    /// [`TaskRepoError::NotFound`] if there is no such task, or any SQLite error.
    pub fn request_cancel(&mut self, id: &TaskId, now_ms: i64) -> Result<(), TaskRepoError> {
        // Step 1: durably record the request.
        {
            let tx = self.tx()?;
            let state: Option<String> = tx
                .query_row(
                    "SELECT state FROM tasks WHERE id = ?1;",
                    [id.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(raw) = state else {
                tx.commit()?;
                return Err(TaskRepoError::NotFound(id.to_string()));
            };
            let from_state = TaskState::from_wire_str(&raw)
                .ok_or_else(|| unknown_state(id.to_string(), raw.clone()))?;
            if from_state.is_terminal() {
                tx.commit()?;
                return Ok(());
            }
            tx.execute(
                "UPDATE tasks SET cancel_requested_at_ms = ?2, updated_at_ms = ?2
                  WHERE id = ?1;",
                rusqlite::params![id.as_str(), now_ms],
            )?;
            log(
                &tx,
                Some(id),
                now_ms,
                "cancel-requested",
                Some(from_state),
                Some(from_state),
                None,
                None,
                None,
            )?;
            tx.commit()?;
        }

        // Step 2: act on it. A separate transaction so the request is durable
        // before the transition that depends on it.
        let tx = self.tx()?;
        let changed = tx.execute(
            "UPDATE tasks
                SET state               = 'cancelled',
                    lease_holder        = NULL,
                    lease_expires_at_ms = NULL,
                    updated_at_ms       = ?2,
                    completed_at_ms     = ?2
              WHERE id = ?1
                AND state NOT IN ('completed','failed','cancelled','dead-lettered',
                                  'needs-verification','paused')
                AND lease_holder IS NOT NULL;",
            rusqlite::params![id.as_str(), now_ms],
        )?;
        // A task that was not leased is cancelled by the same statement without
        // the lease condition.
        if changed == 0 {
            tx.execute(
                "UPDATE tasks
                    SET state = 'cancelled', updated_at_ms = ?2, completed_at_ms = ?2
                  WHERE id = ?1
                    AND state NOT IN ('completed','failed','cancelled','dead-lettered',
                                      'needs-verification','paused');",
                rusqlite::params![id.as_str(), now_ms],
            )?;
        }
        // Test-only: die with the state already flipped to `cancelled` but with no
        // `cancelled` event row. TP-3 requires cancellation to be *observable*, so
        // a state change without an event would be a silent cancellation and must
        // not survive.
        faults::maybe_crash(FaultPoint::CancelBeforeEvent);

        log(
            &tx,
            Some(id),
            now_ms,
            "cancelled",
            None,
            Some(TaskState::Cancelled),
            None,
            None,
            None,
        )?;
        tx.commit()?;
        Ok(())
    }

    // ---------------------------------------------------------------- recover

    /// Reclaims work abandoned by a restart, and returns how many rows changed.
    ///
    /// "Restart", not "expired lease": a restart means the previous process is
    /// gone, so **every** lease it held is orphaned regardless of expiry. An engine
    /// that only reclaimed expired leases would strand work forever — the orphan
    /// bug ADR-0029 TP-4 exists to catch.
    ///
    /// A task past its retry budget goes to `dead-lettered` rather than back to
    /// `pending`, because re-queueing it would start a retry loop that no amount of
    /// waiting ends.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn recover(&mut self, now_ms: i64) -> Result<u64, TaskRepoError> {
        let tx = self.tx()?;

        let orphaned: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM tasks
                  WHERE state = 'running' AND lease_holder IS NOT NULL
                  ORDER BY id;",
            )?;
            stmt.query_map([], |r| r.get::<_, String>(0))?
                .filter_map(Result::ok)
                .collect()
        };
        for id in &orphaned {
            tx.execute(
                "UPDATE tasks
                    SET state = CASE WHEN attempts >= max_attempts THEN 'dead-lettered'
                                     ELSE 'pending' END,
                        lease_holder = NULL,
                        lease_expires_at_ms = NULL,
                        updated_at_ms = ?2,
                        dead_lettered_at_ms = CASE WHEN attempts >= max_attempts THEN ?2
                                                  ELSE dead_lettered_at_ms END
                  WHERE id = ?1;",
                rusqlite::params![id, now_ms],
            )?;
            // The attempt never finished; record that, so "we do not know whether
            // the work happened" is visible rather than assumed to have succeeded.
            tx.execute(
                "UPDATE task_attempts
                    SET finished_at_ms = ?2, outcome = 'recovered', error = 'owner lost'
                  WHERE task_id = ?1 AND finished_at_ms IS NULL;",
                rusqlite::params![id, now_ms],
            )?;
            log(
                &tx,
                Some(&TaskId::new(id)),
                now_ms,
                "recovered",
                Some(TaskState::Running),
                None,
                None,
                None,
                Some("lease orphaned by restart"),
            )?;
        }

        // Anything pending that is past its budget is dead-lettered, for the same
        // reason: leaving it claimable would make `claim` refuse it forever while
        // it sits in the table looking like work.
        let stranded: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT id FROM tasks
                  WHERE state = 'pending' AND attempts >= max_attempts ORDER BY id;",
            )?;
            stmt.query_map([], |r| r.get::<_, String>(0))?
                .filter_map(Result::ok)
                .collect()
        };
        for id in &stranded {
            dead_letter(&tx, id, now_ms, "retry budget exhausted")?;
            log(
                &tx,
                Some(&TaskId::new(id)),
                now_ms,
                "dead-lettered",
                Some(TaskState::Pending),
                Some(TaskState::DeadLettered),
                None,
                None,
                Some("retries exhausted"),
            )?;
        }

        tx.commit()?;
        Ok(u64::try_from(orphaned.len() + stranded.len()).unwrap_or(u64::MAX))
    }

    // ---------------------------------------------------------------- effects

    /// Reserves an idempotency key for an external side effect.
    ///
    /// Returns `Ok(None)` if the key is already reserved — the dedupe guarantee.
    /// ADR-0007 invariant 3 requires the dedupe row to be written in the *same*
    /// transaction as the dispatch decision; this is that row, and `false` is the
    /// caller's signal not to dispatch.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn reserve_effect(
        &mut self,
        idempotency_key: &str,
        task_id: &TaskId,
        attempt_no: u32,
        step_key: &str,
        now_ms: i64,
    ) -> Result<Option<ReservedEffect>, TaskRepoError> {
        let tx = self.tx()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO task_effects
                (idempotency_key, task_id, attempt_no, step_key, status, reserved_at_ms)
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5);",
            rusqlite::params![
                idempotency_key,
                task_id.as_str(),
                attempt_no,
                step_key,
                now_ms
            ],
        )?;
        tx.commit()?;
        if inserted == 0 {
            return Ok(None);
        }
        Ok(Some(ReservedEffect {
            idempotency_key: idempotency_key.to_owned(),
            task_id: task_id.clone(),
            attempt_no,
            step_key: step_key.to_owned(),
            status: "pending".to_owned(),
            detail: None,
        }))
    }

    /// Records how an effect turned out.
    ///
    /// `status` must be one of `observed`, `unknown`, or `not-performed`. Writing
    /// `unknown` is TP-12's explicit answer: the effect may have happened and
    /// nothing knows, and that is a legitimate recorded state — whereas leaving the
    /// row `pending` forever would mean the same thing invisibly.
    ///
    /// # Errors
    ///
    /// [`TaskRepoError::CorruptRow`] for a status outside the vocabulary.
    pub fn resolve_effect(
        &mut self,
        idempotency_key: &str,
        status: EffectStatus,
        detail: Option<&str>,
        now_ms: i64,
    ) -> Result<bool, TaskRepoError> {
        if status == EffectStatus::Pending {
            return Err(TaskRepoError::Corrupt(Box::new(CorruptRowDetail {
                id: idempotency_key.to_owned(),
                reason: "an effect cannot be resolved to `pending`".to_owned(),
            })));
        }
        let changed = write(self.conn.execute(
            "UPDATE task_effects SET status = ?2, detail = ?3, resolved_at_ms = ?4
              WHERE idempotency_key = ?1 AND status = 'pending';",
            rusqlite::params![idempotency_key, status.as_str(), detail, now_ms],
        ))?;
        Ok(changed > 0)
    }

    /// Reads an effect ledger entry.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn effect(&self, idempotency_key: &str) -> Result<Option<ReservedEffect>, TaskRepoError> {
        Ok(self
            .conn
            .query_row(
                "SELECT idempotency_key, task_id, attempt_no, step_key, status, detail
                   FROM task_effects WHERE idempotency_key = ?1;",
                [idempotency_key],
                |r| {
                    Ok(ReservedEffect {
                        idempotency_key: r.get(0)?,
                        task_id: TaskId::new(r.get::<_, String>(1)?),
                        attempt_no: r.get(2)?,
                        step_key: r.get(3)?,
                        status: r.get(4)?,
                        detail: r.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    /// Every effect reserved for a task, oldest first.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn effects_for(&self, task_id: &TaskId) -> Result<Vec<ReservedEffect>, TaskRepoError> {
        let mut stmt = self.conn.prepare(
            "SELECT idempotency_key, task_id, attempt_no, step_key, status, detail
               FROM task_effects WHERE task_id = ?1 ORDER BY reserved_at_ms, idempotency_key;",
        )?;
        let rows = stmt.query_map([task_id.as_str()], |r| {
            Ok(ReservedEffect {
                idempotency_key: r.get(0)?,
                task_id: TaskId::new(r.get::<_, String>(1)?),
                attempt_no: r.get(2)?,
                step_key: r.get(3)?,
                status: r.get(4)?,
                detail: r.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Whether every effect reserved for a task has been resolved.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn all_effects_resolved(&self, task_id: &TaskId) -> Result<bool, TaskRepoError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM task_effects WHERE task_id = ?1 AND status = 'pending';",
            [task_id.as_str()],
            |r| r.get(0),
        )?;
        Ok(n == 0)
    }

    // -------------------------------------------------------------- approvals

    /// Records an approval for **this attempt only**.
    ///
    /// TP-6's mechanism. The primary key is `(task_id, attempt_no)`, so a retry —
    /// which increments `attempt_no` on claim — cannot read the previous attempt's
    /// approval even if the digest would still match. Nothing *checks* that the
    /// retry did not reuse it; it is structurally unable to.
    ///
    /// # Errors
    ///
    /// [`TaskRepoError::AlreadyExists`] if this attempt already has an approval, or
    /// any SQLite error.
    pub fn record_approval(&mut self, approval: &ApprovalRow) -> Result<(), TaskRepoError> {
        let tx = self.tx()?;
        let changed = tx.execute(
            "INSERT OR IGNORE INTO task_approvals
                (task_id, attempt_no, digest, capability, target, params,
                 issued_at_ms, expires_at_ms, consumed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL);",
            rusqlite::params![
                approval.task_id.as_str(),
                approval.attempt_no,
                hex_to_bytes(&approval.digest_hex),
                approval.capability,
                approval.target,
                approval.params,
                approval.issued_at_ms,
                approval.expires_at_ms,
            ],
        )?;
        tx.commit()?;
        if changed == 0 {
            return Err(TaskRepoError::AlreadyExists(format!(
                "{} attempt {} already has an approval",
                approval.task_id, approval.attempt_no
            )));
        }
        Ok(())
    }

    /// Reads the approval for a **specific** attempt.
    ///
    /// Takes `attempt_no` rather than "the current approval" precisely so that
    /// asking for the wrong attempt is impossible to express.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn approval_for_attempt(
        &self,
        task_id: &TaskId,
        attempt_no: u32,
    ) -> Result<Option<ApprovalRow>, TaskRepoError> {
        Ok(self
            .conn
            .query_row(
                "SELECT task_id, attempt_no, hex(digest), capability, target, params,
                        issued_at_ms, expires_at_ms, consumed_at_ms
                   FROM task_approvals WHERE task_id = ?1 AND attempt_no = ?2;",
                rusqlite::params![task_id.as_str(), attempt_no],
                decode_approval,
            )
            .optional()?)
    }

    /// Marks an approval consumed. Single-use.
    ///
    /// # Errors
    ///
    /// [`TaskRepoError::NotFound`] if the attempt has no approval.
    pub fn consume_approval(
        &mut self,
        task_id: &TaskId,
        attempt_no: u32,
        now_ms: i64,
    ) -> Result<bool, TaskRepoError> {
        let changed = write(self.conn.execute(
            "UPDATE task_approvals SET consumed_at_ms = ?3
              WHERE task_id = ?1 AND attempt_no = ?2 AND consumed_at_ms IS NULL;",
            rusqlite::params![task_id.as_str(), attempt_no, now_ms],
        ))?;
        if changed == 0 {
            // Either there was never an approval, or it was already consumed.
            // Both mean "this attempt may not use an approval".
            return Err(TaskRepoError::NotFound(format!(
                "{task_id} attempt {attempt_no} has no unconsumed approval"
            )));
        }
        Ok(true)
    }

    // ----------------------------------------------------------------- events

    /// Appends to the transition log.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    // Nine parameters because they are nine columns of one log row. A struct would
    // only move them somewhere else, and this call has exactly one caller shape.
    #[allow(clippy::too_many_arguments)]
    pub fn append_event(
        &mut self,
        task_id: Option<&TaskId>,
        now_ms: i64,
        kind: &str,
        from: Option<TaskState>,
        to: Option<TaskState>,
        worker: Option<&str>,
        attempt_no: Option<u32>,
        detail: Option<&str>,
    ) -> Result<i64, TaskRepoError> {
        let tx = self.tx()?;
        log(
            &tx, task_id, now_ms, kind, from, to, worker, attempt_no, detail,
        )?;
        let seq = tx.last_insert_rowid();
        tx.commit()?;
        Ok(seq)
    }

    /// Reads the log for a task, oldest first.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn events_for(&self, task_id: &TaskId) -> Result<Vec<TaskEvent>, TaskRepoError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, task_id, at_ms, kind, from_state, to_state, worker, attempt_no, detail
               FROM task_events WHERE task_id = ?1 ORDER BY seq;",
        )?;
        let rows = stmt.query_map([task_id.as_str()], decode_event)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Every event, oldest first. For a diagnostic.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn all_events(&self) -> Result<Vec<TaskEvent>, TaskRepoError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, task_id, at_ms, kind, from_state, to_state, worker, attempt_no, detail
               FROM task_events ORDER BY seq;",
        )?;
        let rows = stmt.query_map([], decode_event)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Attempts for a task, oldest first.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn attempts_for(&self, task_id: &TaskId) -> Result<Vec<TaskAttemptRow>, TaskRepoError> {
        let mut stmt = self.conn.prepare(
            "SELECT task_id, attempt_no, worker, started_at_ms, finished_at_ms, outcome, error
               FROM task_attempts WHERE task_id = ?1 ORDER BY attempt_no;",
        )?;
        let rows = stmt.query_map([task_id.as_str()], |r| {
            Ok(TaskAttemptRow {
                task_id: TaskId::new(r.get::<_, String>(0)?),
                attempt_no: r.get(1)?,
                worker: r.get(2)?,
                started_at_ms: r.get(3)?,
                finished_at_ms: r.get(4)?,
                outcome: r.get(5)?,
                error: r.get(6)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

/// Appends one row to the transition log.
///
/// A free function rather than a method: it needs only the transaction, and as a
/// method it would borrow `self` immutably while `self.tx()` still holds it
/// mutably. That borrow conflict is the compiler correctly preventing a caller
/// from logging inside a transaction it owns elsewhere.
#[allow(clippy::too_many_arguments)] // one column per event field; a struct would only move them
fn log(
    tx: &Transaction<'_>,
    task_id: Option<&TaskId>,
    at_ms: i64,
    kind: &str,
    from: Option<TaskState>,
    to: Option<TaskState>,
    worker: Option<&str>,
    attempt_no: Option<u32>,
    detail: Option<&str>,
) -> Result<(), TaskRepoError> {
    tx.execute(
        "INSERT INTO task_events
            (task_id, at_ms, kind, from_state, to_state, worker, attempt_no, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);",
        rusqlite::params![
            task_id.map(ToString::to_string),
            at_ms,
            kind,
            from.map(TaskState::as_wire_str),
            to.map(TaskState::as_wire_str),
            worker,
            attempt_no,
            detail,
        ],
    )?;
    Ok(())
}

/// Moves a task to `dead-lettered`, preserving any error it already had.
///
/// `COALESCE` rather than an overwrite: a task that failed with a real error keeps
/// it, because TP-11 requires the dead-letter to carry *its last error* and
/// replacing that with "retries exhausted" would throw the diagnosis away.
fn dead_letter(
    tx: &Transaction<'_>,
    id: &str,
    now_ms: i64,
    reason: &str,
) -> Result<(), TaskRepoError> {
    tx.execute(
        "UPDATE tasks
            SET state = 'dead-lettered', dead_lettered_at_ms = ?2, updated_at_ms = ?2,
                lease_holder = NULL, lease_expires_at_ms = NULL,
                last_error = COALESCE(last_error, ?3)
          WHERE id = ?1;",
        rusqlite::params![id, now_ms, reason],
    )?;
    Ok(())
}

/// One recorded attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAttemptRow {
    /// The task.
    pub task_id: TaskId,
    /// Which attempt, 1-based.
    pub attempt_no: u32,
    /// Who claimed it.
    pub worker: String,
    /// When the claim happened.
    pub started_at_ms: i64,
    /// When it finished, if it has.
    pub finished_at_ms: Option<i64>,
    /// How it ended.
    pub outcome: Option<String>,
    /// Why, if it failed.
    pub error: Option<String>,
}

/// How a side effect turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectStatus {
    /// Reserved; not yet resolved. Cannot be written by `resolve_effect`.
    Pending,
    /// The effect happened.
    Observed,
    /// The effect may or may not have happened. TP-12's honest answer.
    Unknown,
    /// The effect definitely did not happen, so retrying is safe.
    NotPerformed,
}

impl EffectStatus {
    /// The persisted spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Observed => "observed",
            Self::Unknown => "unknown",
            Self::NotPerformed => "not-performed",
        }
    }

    /// Parses the persisted spelling, refusing anything unrecognised.
    ///
    /// Named `parse` rather than `from_str` so it cannot be mistaken for
    /// `std::str::FromStr::from_str`, which returns a `Result`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "observed" => Some(Self::Observed),
            "unknown" => Some(Self::Unknown),
            "not-performed" => Some(Self::NotPerformed),
            _ => None,
        }
    }
}

/// Decodes one `tasks` row.
///
/// The state is decoded through [`TaskState::from_wire_str`], which refuses
/// anything unrecognised. A row that cannot be decoded is an error rather than a
/// default, because the dangerous default is `pending` — the only claimable state.
fn decode_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Result<TaskRow, TaskRepoError>> {
    let id: String = r.get(0)?;
    let kind_raw: String = r.get(1)?;
    let state_raw: String = r.get(2)?;

    let state = match TaskState::from_wire_str(&state_raw) {
        Some(s) => s,
        None => {
            return Ok(Err(unknown_state(id, state_raw)));
        }
    };
    let kind = match TaskKind::from_wire_str(&kind_raw) {
        Some(k) => k,
        None => {
            return Ok(Err(TaskRepoError::Corrupt(Box::new(CorruptRowDetail {
                id,
                reason: format!("unrecognised kind {kind_raw:?}"),
            }))));
        }
    };
    let schedule_raw: Option<String> = r.get(14)?;

    Ok(Ok(TaskRow {
        id: TaskId::new(id),
        kind,
        state,
        priority: r.get(3)?,
        attempts: r.get(4)?,
        max_attempts: r.get(5)?,
        lease_expires_at_ms: r.get(6)?,
        lease_holder: r.get(7)?,
        idempotent: r.get::<_, i64>(8)? != 0,
        effect_observed: r.get::<_, i64>(9)? != 0,
        run_after_ms: r.get(10)?,
        catch_up: r.get::<_, i64>(11)? != 0,
        last_error: r.get(12)?,
        cancel_requested_at_ms: r.get(13)?,
        schedule_id: schedule_raw.map(ScheduleId::new),
        fire_time_ms: r.get(15)?,
        created_at_ms: r.get(16)?,
        updated_at_ms: r.get(17)?,
        dead_lettered_at_ms: r.get(18)?,
        terminal_at_ms: r.get(19)?,
    }))
}

fn decode_event(r: &rusqlite::Row<'_>) -> rusqlite::Result<TaskEvent> {
    let task_raw: Option<String> = r.get(1)?;
    let from_raw: Option<String> = r.get(4)?;
    let to_raw: Option<String> = r.get(5)?;
    Ok(TaskEvent {
        seq: r.get(0)?,
        task_id: task_raw.map(TaskId::new),
        at_ms: r.get(2)?,
        kind: r.get(3)?,
        // A log written by a future version could name a state this build does not
        // know. `None` rather than a refusal: history is not something to refuse to
        // read, and losing the rest of the row would be worse than an unknown
        // label on one field.
        from_state: from_raw.as_deref().and_then(TaskState::from_wire_str),
        to_state: to_raw.as_deref().and_then(TaskState::from_wire_str),
        worker: r.get(6)?,
        attempt_no: r.get(7)?,
        detail: r.get(8)?,
    })
}

fn decode_approval(r: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRow> {
    Ok(ApprovalRow {
        task_id: TaskId::new(r.get::<_, String>(0)?),
        attempt_no: r.get(1)?,
        digest_hex: r.get(2)?,
        capability: r.get(3)?,
        target: r.get(4)?,
        params: r.get(5)?,
        issued_at_ms: r.get(6)?,
        expires_at_ms: r.get(7)?,
        consumed_at_ms: r.get(8)?,
    })
}

/// Converts a write result into the repository's error type.
///
/// `rusqlite::Connection::execute` takes `&self`, so a write through a shared
/// reference compiles. Every write in this repository goes through here or through
/// an explicit `tx()`, which is what keeps ADR-0006's single-writer discipline a
/// property of the *callers* rather than of this struct's signature.
fn write(result: Result<usize, rusqlite::Error>) -> Result<usize, TaskRepoError> {
    result.map_err(TaskRepoError::from)
}

/// Distinguishes "the row already existed" from "the insert succeeded".
///
/// `rusqlite::Connection::execute` returns an **error** for a UNIQUE violation
/// rather than a zero row count, so the duplicate has to be recognised from the
/// error. Doing it the obvious way — checking for `changed == 0` — silently never
/// fires, and a duplicate `enqueue` would surface as an opaque SQLite error instead
/// of the `AlreadyExists` the caller needs to decide whether re-submission is
/// idempotent.
#[allow(clippy::too_many_arguments)] // see `log`
fn insert_outcome(result: Result<usize, rusqlite::Error>) -> Result<usize, TaskRepoError> {
    match result {
        Ok(n) => Ok(n),
        Err(rusqlite::Error::SqliteFailure(e, msg))
            if e.code == rusqlite::ErrorCode::ConstraintViolation
                && msg.as_deref().is_some_and(|m| m.contains("tasks.id")) =>
        {
            // Reported as success-with-zero so the caller's duplicate check fires;
            // the id is recovered by the caller.
            Ok(0)
        }
        Err(e) => Err(TaskRepoError::from(e)),
    }
}

fn is_unique_violation(n: &usize) -> bool {
    *n == 0
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let bytes: Vec<u8> = hex.as_bytes().to_vec();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16);
        let lo = (bytes[i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(l)) => out.push(u8::try_from(h * 16 + l).unwrap_or(0)),
            _ => return Vec::new(),
        }
        i += 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::MigrationRunner;
    use crate::pragma::Pragma;

    const NOW: i64 = 1_767_225_600_000;
    const LEASE: i64 = 5_000;

    /// A migrated in-memory connection.
    ///
    /// In-memory is fine for the *repository logic* tests here; the durability and
    /// crash tests use real files, because an in-memory database has no WAL and no
    /// recovery (docs-08 §4.4).
    fn mem() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        MigrationRunner::new(&c).run(true).expect("migrate");
        c
    }

    fn tid(s: &str) -> TaskId {
        TaskId::new(s)
    }

    fn insert(repo: &mut TaskRepository<'_>, id: &str, kind: TaskKind) {
        repo.insert(&NewTask::new(tid(id), kind, NOW), NOW)
            .expect("insert");
    }

    /// Inserts directly, for tests that need the connection afterwards.
    fn insert_raw(conn: &mut Connection, id: &str, kind: TaskKind) {
        TaskRepository::new(conn)
            .insert(&NewTask::new(tid(id), kind, NOW), NOW)
            .expect("insert");
    }

    #[test]
    fn insert_then_read_round_trips() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t1", TaskKind::Query);
        let row = repo.get(&tid("t1")).expect("get").expect("present");
        assert_eq!(row.id, tid("t1"));
        assert_eq!(row.kind, TaskKind::Query);
        assert_eq!(row.state, TaskState::Pending);
        assert_eq!(row.attempts, 0);
        assert!(row.idempotent, "a Query is idempotent by default");
        assert!(row.lease_holder.is_none());
        assert_eq!(row.max_attempts, 3);
    }

    #[test]
    fn a_workflow_is_not_idempotent_by_default() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "w", TaskKind::Workflow);
        let row = repo.get(&tid("w")).expect("get").expect("present");
        assert!(!row.idempotent);
    }

    #[test]
    fn a_duplicate_id_is_refused_rather_than_overwritten() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let err = repo
            .insert(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
            .expect_err("duplicate");
        assert!(matches!(err, TaskRepoError::AlreadyExists(_)), "{err}");
        // And the original is untouched.
        assert_eq!(
            repo.get(&tid("t")).expect("get").expect("present").kind,
            TaskKind::Query
        );
    }

    #[test]
    fn claim_takes_a_lease_and_records_one_attempt() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let ClaimOutcome::Claimed(claimed) = repo.claim("w1", NOW, LEASE).expect("claim") else {
            panic!("expected a claim");
        };
        assert_eq!(claimed.attempt_no, 1);
        assert_eq!(claimed.row.state, TaskState::Running);
        assert_eq!(claimed.row.lease_holder.as_deref(), Some("w1"));
        assert_eq!(claimed.lease_expires_at_ms, NOW + LEASE);

        let attempts = repo.attempts_for(&tid("t")).expect("attempts");
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].worker, "w1");
        assert!(attempts[0].finished_at_ms.is_none());
    }

    #[test]
    fn a_claim_on_an_empty_queue_is_empty_not_an_error() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        assert_eq!(
            repo.claim("w", NOW, LEASE).expect("claim"),
            ClaimOutcome::Empty
        );
    }

    #[test]
    fn two_workers_never_claim_the_same_task() {
        // ADR-0007 invariant 2. Two sequential claims must not both get `t1`.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t1", TaskKind::Query);
        let first = repo.claim("w1", NOW, LEASE).expect("claim");
        let second = repo.claim("w2", NOW, LEASE).expect("claim");
        assert!(matches!(first, ClaimOutcome::Claimed(_)));
        assert_eq!(second, ClaimOutcome::Empty, "the task was already claimed");
    }

    #[test]
    fn a_running_task_is_not_claimable() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t1", TaskKind::Query);
        insert(&mut repo, "t2", TaskKind::Query);
        let _ = repo.claim("w1", NOW, LEASE).expect("claim 1");
        let _ = repo.claim("w2", NOW, LEASE).expect("claim 2");
        assert_eq!(
            repo.claim("w3", NOW, LEASE).expect("claim 3"),
            ClaimOutcome::Empty
        );
    }

    #[test]
    fn complete_clears_the_lease_and_records_the_outcome() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let ClaimOutcome::Claimed(cl) = repo.claim("w", NOW, LEASE).expect("claim") else {
            panic!("expected a claim");
        };
        assert!(
            repo.complete(&tid("t"), "w", NOW, TaskState::Completed, true, None)
                .expect("complete")
        );
        let row = repo.get(&tid("t")).expect("get").expect("present");
        assert_eq!(row.state, TaskState::Completed);
        assert!(row.effect_observed);
        assert!(row.lease_holder.is_none(), "the lease must be released");
        assert!(row.lease_expires_at_ms.is_none());
        assert!(
            row.terminal_at_ms.is_some(),
            "a completed task must carry a terminal time"
        );
        assert_eq!(
            repo.attempts_for(&tid("t")).expect("attempts")[0]
                .outcome
                .as_deref(),
            Some("completed")
        );
        let _ = cl;
    }

    #[test]
    fn a_lease_is_half_open() {
        // Live iff now < expiry. An expiry exactly at `now` is dead.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let ClaimOutcome::Claimed(cl) = repo.claim("w", NOW, LEASE).expect("claim") else {
            panic!("expected a claim");
        };
        assert!(!cl.row.lease_is_expired_at(NOW));
        assert!(!cl.row.lease_is_expired_at(NOW + LEASE - 1));
        assert!(cl.row.lease_is_expired_at(NOW + LEASE));
    }

    #[test]
    fn a_worker_that_does_not_hold_the_task_cannot_complete() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let _ = repo.claim("owner", NOW, LEASE).expect("claim");
        assert!(
            !repo
                .complete(&tid("t"), "impostor", NOW, TaskState::Completed, true, None)
                .expect("complete"),
            "a non-holder must not commit"
        );
        assert_eq!(
            repo.get(&tid("t")).expect("get").expect("present").state,
            TaskState::Running
        );
    }

    #[test]
    fn an_expired_lease_cannot_complete_even_with_the_right_holder() {
        // TP-5 case 1: the lease is dead but nobody else has claimed the task.
        // Checking `lease_holder` alone would pass this -- it is the bug
        // ADR-0032 documents.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let ClaimOutcome::Claimed(cl) = repo.claim("zombie", NOW, LEASE).expect("claim") else {
            panic!("expected a claim");
        };
        let after = NOW + cl.lease_expires_at_ms - NOW; // strictly past expiry
        assert!(
            !repo
                .complete(&tid("t"), "zombie", after, TaskState::Completed, true, None)
                .expect("complete"),
            "an expired lease was allowed to commit"
        );
        let row = repo.get(&tid("t")).expect("get").expect("present");
        assert_ne!(row.state, TaskState::Completed);
        assert_eq!(row.state, TaskState::Running, "the refusal changed nothing");
    }

    #[test]
    fn a_zombie_whose_task_was_reclaimed_cannot_complete() {
        // TP-5 case 2. Different failure from the above: here the *holder* changed.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let _ = repo.claim("zombie", NOW, LEASE).expect("claim");
        let later = NOW + LEASE + 1;
        repo.recover(later).expect("recover");
        let ClaimOutcome::Claimed(_) = repo.claim("fresh", later, LEASE).expect("claim") else {
            panic!("expected the recovered task to be re-claimed");
        };
        assert!(
            !repo
                .complete(&tid("t"), "zombie", later, TaskState::Completed, true, None)
                .expect("complete"),
            "a zombie must not commit after its task was re-claimed"
        );
    }

    #[test]
    fn a_refused_commit_leaves_the_row_byte_for_byte_unchanged() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let _ = repo.claim("zombie", NOW, LEASE).expect("claim");
        let before = repo.get(&tid("t")).expect("get").expect("present");
        let _ = repo.complete(
            &tid("t"),
            "zombie",
            NOW + LEASE + 1,
            TaskState::Completed,
            true,
            None,
        );
        assert_eq!(repo.get(&tid("t")).expect("get").expect("present"), before);
    }

    #[test]
    fn a_heartbeat_from_a_zombie_does_not_revive_the_lease() {
        // Otherwise a zombie could keep a task alive forever with nobody working
        // on it -- and, worse, a second worker could be handed a task that already
        // has an owner.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let _ = repo.claim("zombie", NOW, LEASE).expect("claim");
        assert!(
            !repo
                .heartbeat(&tid("t"), "zombie", NOW + LEASE + 1, LEASE)
                .expect("hb")
        );
        let row = repo.get(&tid("t")).expect("get").expect("present");
        assert_eq!(
            row.lease_expires_at_ms,
            Some(NOW + LEASE),
            "the expiry must not move"
        );
    }

    #[test]
    fn a_live_holder_can_heartbeat() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let _ = repo.claim("w", NOW, LEASE).expect("claim");
        assert!(
            repo.heartbeat(&tid("t"), "w", NOW + 1_000, LEASE)
                .expect("hb")
        );
        assert_eq!(
            repo.get(&tid("t"))
                .expect("get")
                .expect("present")
                .lease_expires_at_ms,
            Some(NOW + 1_000 + LEASE)
        );
    }

    #[test]
    fn cancelling_a_pending_task_is_terminal_and_observable() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        repo.request_cancel(&tid("t"), NOW).expect("cancel");
        let row = repo.get(&tid("t")).expect("get").expect("present");
        assert_eq!(row.state, TaskState::Cancelled);
        assert_eq!(
            row.cancel_requested_at_ms,
            Some(NOW),
            "the request must be recorded"
        );
        // And it is not claimable.
        assert_eq!(
            repo.claim("w", NOW, LEASE).expect("claim"),
            ClaimOutcome::Empty
        );
    }

    #[test]
    fn cancelling_records_the_request_before_the_state_change() {
        // TP-3: "a cancellation request is durably recorded *before* it is acted
        // upon". Two events, in that order, is the observable form of that.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        repo.request_cancel(&tid("t"), NOW).expect("cancel");
        let kinds: Vec<String> = repo
            .events_for(&tid("t"))
            .expect("events")
            .into_iter()
            .map(|e| e.kind)
            .collect();
        let req = kinds.iter().position(|k| k == "cancel-requested");
        let act = kinds.iter().position(|k| k == "cancelled");
        assert!(req.is_some() && act.is_some(), "{kinds:?}");
        assert!(
            req.expect("req") < act.expect("act"),
            "the request must come first: {kinds:?}"
        );
    }

    #[test]
    fn cancelling_a_running_task_strips_its_lease() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let ClaimOutcome::Claimed(cl) = repo.claim("w", NOW, LEASE).expect("claim") else {
            panic!("expected a claim");
        };
        repo.request_cancel(&tid("t"), NOW + 1).expect("cancel");
        let row = repo.get(&tid("t")).expect("get").expect("present");
        assert_eq!(row.state, TaskState::Cancelled);
        assert!(row.lease_holder.is_none());
        // The in-flight worker cannot commit afterwards: the fence rejects it.
        assert!(
            !repo
                .complete(&tid("t"), "w", NOW + 1, TaskState::Completed, true, None)
                .expect("complete"),
            "a worker whose task was cancelled must not commit"
        );
        let _ = cl;
    }

    #[test]
    fn a_terminal_task_cannot_be_cancelled_into_resurrection() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let _ = repo.claim("w", NOW, LEASE).expect("claim");
        repo.complete(&tid("t"), "w", NOW, TaskState::Completed, true, None)
            .expect("complete");
        repo.request_cancel(&tid("t"), NOW + 10)
            .expect("cancel is a no-op");
        assert_eq!(
            repo.get(&tid("t")).expect("get").expect("present").state,
            TaskState::Completed
        );
    }

    #[test]
    fn cancelling_an_unknown_task_is_an_error() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        assert!(matches!(
            repo.request_cancel(&tid("nope"), NOW),
            Err(TaskRepoError::NotFound(_))
        ));
    }

    #[test]
    fn recover_reclaims_every_lease_because_a_restart_orphans_all_of_them() {
        // Even a lease that has not expired. The worker holding it died with the
        // process.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t1", TaskKind::Query);
        insert(&mut repo, "t2", TaskKind::Query);
        let _ = repo.claim("w1", NOW, LEASE).expect("claim 1");
        let _ = repo.claim("w2", NOW, LEASE).expect("claim 2");
        assert_eq!(repo.live_leases(NOW).expect("live"), 2);

        let recovered = repo.recover(NOW + 1).expect("recover");
        assert_eq!(recovered, 2);
        assert_eq!(repo.live_leases(NOW + 1).expect("live"), 0);
        for id in ["t1", "t2"] {
            let row = repo.get(&tid(id)).expect("get").expect("present");
            assert_eq!(row.state, TaskState::Pending, "{id}");
            assert!(row.lease_holder.is_none(), "{id}");
        }
    }

    #[test]
    fn recover_does_not_disturb_a_cancelled_task() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        repo.request_cancel(&tid("t"), NOW).expect("cancel");
        repo.recover(NOW + 1).expect("recover");
        assert_eq!(
            repo.get(&tid("t")).expect("get").expect("present").state,
            TaskState::Cancelled,
            "TP-3: cancellation must survive recovery"
        );
    }

    #[test]
    fn recover_marks_the_interrupted_attempt_as_finished() {
        // The attempt never completed. Recording that is TP-12's requirement that
        // an unknown outcome be recorded rather than assumed successful.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let _ = repo.claim("w", NOW, LEASE).expect("claim");
        repo.recover(NOW + 1).expect("recover");
        let attempts = repo.attempts_for(&tid("t")).expect("attempts");
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].outcome.as_deref(), Some("recovered"));
        assert!(attempts[0].finished_at_ms.is_some());
    }

    #[test]
    fn a_task_past_its_retry_budget_is_dead_lettered_not_requeued() {
        // TP-10/TP-11: re-queueing it would start a loop nothing ends.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        for i in 0..3 {
            let ClaimOutcome::Claimed(cl) = repo.claim("w", NOW + i, LEASE).expect("claim") else {
                panic!("expected claim {i}");
            };
            assert!(
                repo.complete(
                    &tid("t"),
                    "w",
                    NOW + i,
                    TaskState::Failed,
                    false,
                    Some("boom")
                )
                .expect("complete")
            );
            let _ = cl;
        }
        let row = repo.get(&tid("t")).expect("get").expect("present");
        assert_eq!(row.state, TaskState::DeadLettered, "the budget was spent");
        assert!(row.dead_lettered_at_ms.is_some());
        assert_eq!(
            row.last_error.as_deref(),
            Some("boom"),
            "TP-11: the error must be visible"
        );
        assert_eq!(
            repo.claim("w", NOW + 10, LEASE).expect("claim"),
            ClaimOutcome::Empty
        );
    }

    #[test]
    fn a_dead_lettered_task_is_never_handed_out_again() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        // Exhaust it by direct completion.
        for i in 0..3 {
            let _ = repo.claim("w", NOW + i, LEASE).expect("claim");
            let _ = repo.complete(&tid("t"), "w", NOW + i, TaskState::Failed, false, Some("e"));
        }
        assert_eq!(
            repo.get(&tid("t")).expect("get").expect("present").state,
            TaskState::DeadLettered
        );
        for i in 10..20 {
            assert_eq!(
                repo.claim("w", NOW + i, LEASE).expect("claim"),
                ClaimOutcome::Empty
            );
        }
    }

    #[test]
    fn claim_dead_letters_a_stranded_over_budget_task_and_reports_it() {
        // A task can arrive over budget via recovery or a direct insert; `claim`
        // must surface that rather than skipping it in silence forever.
        let mut c = mem();
        let mut t = NewTask::new(tid("t"), TaskKind::Query, NOW);
        t.max_attempts = 1;
        {
            let mut repo = TaskRepository::new(&mut c);
            repo.insert(&t, NOW).expect("insert");
        }
        // Force the counter up without a claim, to simulate a task that was
        // requeued after its budget was spent.
        c.execute("UPDATE tasks SET attempts = 5 WHERE id = 't';", [])
            .expect("force");
        let mut repo = TaskRepository::new(&mut c);
        let outcome = repo.claim("w", NOW, LEASE).expect("claim");
        assert!(
            matches!(outcome, ClaimOutcome::DeadLettered { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            repo.get(&tid("t")).expect("get").expect("present").state,
            TaskState::DeadLettered
        );
    }

    #[test]
    fn a_failed_task_is_requeued_so_it_can_actually_retry() {
        // The bug this test exists to catch: marking a failed task terminal made
        // "within the retry budget" mean "no retry", so a task that failed once
        // transiently was permanently dead and TP-11 could only ever be satisfied
        // by never retrying.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let ClaimOutcome::Claimed(first) = repo.claim("w", NOW, LEASE).expect("claim") else {
            panic!("expected a claim");
        };
        assert_eq!(first.attempt_no, 1);
        assert!(
            repo.complete(&tid("t"), "w", NOW, TaskState::Failed, false, Some("boom"))
                .expect("fail")
        );

        let row = repo.get(&tid("t")).expect("get").expect("present");
        assert_eq!(row.state, TaskState::Pending, "a retry must be possible");
        assert!(!row.state.is_terminal());
        assert!(
            row.is_claimable_at(NOW),
            "with no delay it is immediately claimable"
        );

        let ClaimOutcome::Claimed(second) = repo.claim("w", NOW, LEASE).expect("claim") else {
            panic!("expected the retry to be claimable");
        };
        assert_eq!(second.attempt_no, 2, "the retry is a new attempt");
    }

    #[test]
    fn a_retry_delay_defers_the_next_claim() {
        // The production path: a backoff, so a failing dependency is not hammered.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let _ = repo.claim("w", NOW, LEASE).expect("claim");
        repo.complete_with(
            &tid("t"),
            "w",
            NOW,
            TaskState::Failed,
            false,
            Some("boom"),
            60_000,
        )
        .expect("fail with backoff");
        assert!(
            !repo
                .get(&tid("t"))
                .expect("get")
                .expect("present")
                .is_claimable_at(NOW)
        );
        assert_eq!(
            repo.claim("w", NOW, LEASE).expect("claim"),
            ClaimOutcome::Empty
        );
        assert!(matches!(
            repo.claim("w", NOW + 60_000, LEASE).expect("claim"),
            ClaimOutcome::Claimed(_)
        ));
    }

    #[test]
    fn a_task_dies_exactly_at_max_attempts_not_before() {
        // The boundary is the whole of TP-11's retry budget.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        for i in 0..3 {
            let _ = repo.claim("w", NOW + i, LEASE).expect("claim");
            repo.complete(&tid("t"), "w", NOW + i, TaskState::Failed, false, Some("e"))
                .expect("fail");
            let row = repo.get(&tid("t")).expect("get").expect("present");
            let expected = if i == 2 {
                TaskState::DeadLettered
            } else {
                TaskState::Pending
            };
            assert_eq!(row.state, expected, "after attempt {}", i + 1);
        }
    }

    #[test]
    fn a_failed_task_does_not_advance_its_attempt_counter() {
        // TP-6's engine-level half: attempts advance only on a claim.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let _ = repo.claim("w", NOW, LEASE).expect("claim");
        repo.complete(&tid("t"), "w", NOW, TaskState::Failed, false, Some("boom"))
            .expect("fail");
        let row = repo.get(&tid("t")).expect("get").expect("present");
        assert_eq!(row.attempts, 1);
        assert!(
            row.lease_holder.is_none(),
            "a failed task must not still be leased"
        );
    }

    #[test]
    fn a_future_run_after_defers_the_claim() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        let mut t = NewTask::new(tid("t"), TaskKind::Query, NOW);
        t.run_after_ms = NOW + 10_000;
        repo.insert(&t, NOW).expect("insert");
        assert_eq!(
            repo.claim("w", NOW, LEASE).expect("claim"),
            ClaimOutcome::Empty
        );
        assert!(matches!(
            repo.claim("w", NOW + 10_000, LEASE).expect("claim"),
            ClaimOutcome::Claimed(_)
        ));
    }

    #[test]
    fn priority_beats_creation_order() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        let mut low = NewTask::new(tid("low"), TaskKind::Query, NOW);
        low.priority = 0;
        let mut high = NewTask::new(tid("high"), TaskKind::Query, NOW);
        high.priority = 10;
        repo.insert(&low, NOW).expect("low");
        repo.insert(&high, NOW).expect("high");
        let ClaimOutcome::Claimed(cl) = repo.claim("w", NOW, LEASE).expect("claim") else {
            panic!("expected a claim");
        };
        assert_eq!(
            cl.row.id,
            tid("high"),
            "the higher priority task runs first"
        );
    }

    // ------------------------------------------------------------------ effects

    #[test]
    fn an_effect_reserves_once_and_the_second_reservation_is_refused() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let first = repo
            .reserve_effect("key-1", &tid("t"), 1, "step-1", NOW)
            .expect("reserve");
        assert!(first.is_some());
        let second = repo
            .reserve_effect("key-1", &tid("t"), 2, "step-1", NOW)
            .expect("reserve");
        assert!(
            second.is_none(),
            "the dedupe key must reject the second reservation"
        );
    }

    #[test]
    fn an_effect_can_be_resolved_to_each_terminal_status() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        for (i, status) in [
            EffectStatus::Observed,
            EffectStatus::Unknown,
            EffectStatus::NotPerformed,
        ]
        .into_iter()
        .enumerate()
        {
            let key = format!("k{i}");
            let _ = repo
                .reserve_effect(&key, &tid("t"), 1, "s", NOW)
                .expect("reserve");
            assert!(
                repo.resolve_effect(&key, status, None, NOW + 1)
                    .expect("resolve")
            );
            assert_eq!(
                repo.effect(&key).expect("read").expect("present").status,
                status.as_str()
            );
        }
    }

    #[test]
    fn an_effect_cannot_be_resolved_to_pending() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let _ = repo
            .reserve_effect("k", &tid("t"), 1, "s", NOW)
            .expect("reserve");
        assert!(
            repo.resolve_effect("k", EffectStatus::Pending, None, NOW)
                .is_err()
        );
    }

    #[test]
    fn an_effect_is_resolved_at_most_once() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let _ = repo
            .reserve_effect("k", &tid("t"), 1, "s", NOW)
            .expect("reserve");
        assert!(
            repo.resolve_effect("k", EffectStatus::Unknown, None, NOW)
                .expect("first")
        );
        assert!(
            !repo
                .resolve_effect("k", EffectStatus::Observed, None, NOW + 1)
                .expect("second"),
            "an effect's outcome must not be rewritten"
        );
    }

    #[test]
    fn an_unresolved_effect_is_visible_as_unresolved() {
        // TP-12: "pending" is the state that means "we do not know yet", and it
        // must be *queryable*, not merely absent.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let _ = repo
            .reserve_effect("k", &tid("t"), 1, "s", NOW)
            .expect("reserve");
        assert!(!repo.all_effects_resolved(&tid("t")).expect("resolved?"));
        let _ = repo.resolve_effect("k", EffectStatus::Unknown, None, NOW);
        assert!(repo.all_effects_resolved(&tid("t")).expect("resolved?"));
    }

    // ---------------------------------------------------------------- approvals

    fn approval(task: &str, attempt: u32, expires: i64) -> ApprovalRow {
        ApprovalRow {
            task_id: tid(task),
            attempt_no: attempt,
            digest_hex: "00".repeat(32),
            capability: "cap".into(),
            target: Some("/tmp/x".into()),
            params: "{\"a\":1}".into(),
            issued_at_ms: NOW,
            expires_at_ms: expires,
            consumed_at_ms: None,
        }
    }

    #[test]
    fn a_retry_cannot_read_the_previous_attempts_approval() {
        // TP-6, structurally. Attempt 1 has an approval; attempt 2 must not.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let _ = repo.claim("w", NOW, LEASE).expect("claim");
        repo.record_approval(&approval("t", 1, NOW + 60_000))
            .expect("record");

        let _ = repo
            .complete(&tid("t"), "w", NOW, TaskState::Failed, false, Some("boom"))
            .expect("fail");
        let ClaimOutcome::Claimed(second) = repo.claim("w", NOW + 1, LEASE).expect("claim") else {
            panic!("expected a retry");
        };
        assert_eq!(second.attempt_no, 2, "the retry is attempt 2");

        // The query takes an attempt number, so asking for attempt 1 still works
        // and asking for attempt 2 finds nothing. There is no "current approval".
        assert!(
            repo.approval_for_attempt(&tid("t"), 1)
                .expect("a1")
                .is_some()
        );
        assert!(
            repo.approval_for_attempt(&tid("t"), 2)
                .expect("a2")
                .is_none(),
            "the retry must not inherit the approval"
        );
    }

    #[test]
    fn an_attempt_cannot_carry_two_approvals() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        repo.record_approval(&approval("t", 1, NOW + 1_000))
            .expect("first");
        assert!(
            repo.record_approval(&approval("t", 1, NOW + 2_000))
                .is_err()
        );
    }

    #[test]
    fn an_approval_is_single_use() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        repo.record_approval(&approval("t", 1, NOW + 60_000))
            .expect("record");
        assert!(repo.consume_approval(&tid("t"), 1, NOW).expect("consume"));
        // A second consumption is refused.
        assert!(repo.consume_approval(&tid("t"), 1, NOW + 1).is_err());
        let row = repo
            .approval_for_attempt(&tid("t"), 1)
            .expect("read")
            .expect("present");
        assert!(
            !row.is_valid_at(NOW + 1),
            "a consumed approval is not valid"
        );
    }

    #[test]
    fn consuming_an_approval_that_was_never_given_is_an_error() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        assert!(matches!(
            repo.consume_approval(&tid("t"), 1, NOW),
            Err(TaskRepoError::NotFound(_))
        ));
    }

    #[test]
    fn an_expired_approval_is_not_valid() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        repo.record_approval(&approval("t", 1, NOW + 1_000))
            .expect("record");
        let row = repo
            .approval_for_attempt(&tid("t"), 1)
            .expect("read")
            .expect("present");
        assert!(row.is_valid_at(NOW + 999));
        assert!(!row.is_valid_at(NOW + 1_000));
    }

    // ------------------------------------------------------------------- events

    #[test]
    fn every_state_change_is_logged_with_its_from_and_to() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let _ = repo.claim("w", NOW, LEASE).expect("claim");
        let _ = repo.complete(&tid("t"), "w", NOW, TaskState::Completed, true, None);
        let events = repo.events_for(&tid("t")).expect("events");
        let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(kinds, vec!["enqueued", "claimed", "completed"]);

        let claimed = &events[1];
        assert_eq!(claimed.from_state, Some(TaskState::Pending));
        assert_eq!(claimed.to_state, Some(TaskState::Running));
        assert_eq!(claimed.worker.as_deref(), Some("w"));
        assert_eq!(claimed.attempt_no, Some(1));

        let done = &events[2];
        assert_eq!(done.from_state, Some(TaskState::Running));
        assert_eq!(done.to_state, Some(TaskState::Completed));
    }

    #[test]
    fn a_refused_commit_logs_nothing() {
        // A log entry for a commit that did not happen would make the history
        // claim a transition the database never made.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        let _ = repo.claim("zombie", NOW, LEASE).expect("claim");
        let before = repo.events_for(&tid("t")).expect("events").len();
        let _ = repo.complete(
            &tid("t"),
            "zombie",
            NOW + LEASE + 1,
            TaskState::Completed,
            true,
            None,
        );
        assert_eq!(repo.events_for(&tid("t")).expect("events").len(), before);
    }

    #[test]
    fn event_sequence_numbers_are_monotonic_and_never_reused() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let first = repo
            .append_event(Some(&tid("t")), NOW, "manual", None, None, None, None, None)
            .expect("e1");
        let second = repo
            .append_event(Some(&tid("t")), NOW, "manual", None, None, None, None, None)
            .expect("e2");
        assert!(second > first, "{first} then {second}");
    }

    #[test]
    fn an_unrecognised_state_in_a_row_is_an_error_not_a_default() {
        // The dangerous default would be `pending`, the only claimable state.
        let mut c = mem();
        insert_raw(&mut c, "t", TaskKind::Query);
        // Bypass the CHECK to simulate a row written by a newer build.
        c.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("ignore checks");
        c.execute("UPDATE tasks SET state = 'thinking' WHERE id = 't';", [])
            .expect("force");
        let repo = TaskRepository::new(&mut c);
        let err = repo
            .get(&tid("t"))
            .expect_err("must refuse an unknown state");
        assert!(matches!(err, TaskRepoError::UnknownState(_)), "{err}");
    }

    #[test]
    fn counts_reflect_the_table() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "a", TaskKind::Query);
        insert(&mut repo, "b", TaskKind::Workflow);
        let _ = repo.claim("w", NOW, LEASE).expect("claim");
        assert_eq!(repo.count().expect("count"), 2);
        assert_eq!(repo.count_in_state(TaskState::Pending).expect("pending"), 1);
        assert_eq!(repo.count_in_state(TaskState::Running).expect("running"), 1);
        assert_eq!(
            repo.count_in_state(TaskState::Completed)
                .expect("completed"),
            0
        );
    }

    #[test]
    fn all_returns_every_task_and_list_limited_bounds_itself() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        for i in 0..10 {
            insert(&mut repo, &format!("t{i}"), TaskKind::Query);
        }
        assert_eq!(
            repo.all().expect("all").len(),
            10,
            "TP-1's accessor must not truncate"
        );
        assert_eq!(repo.list_limited(4).expect("limited").len(), 4);
        assert_eq!(repo.list_limited(0).expect("zero").len(), 0);
    }

    #[test]
    fn effects_for_a_task_are_ordered_by_reservation() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Workflow);
        for i in 0..3 {
            let _ = repo
                .reserve_effect(&format!("k{i}"), &tid("t"), 1, &format!("s{i}"), NOW + i)
                .expect("r");
        }
        let keys: Vec<String> = repo
            .effects_for(&tid("t"))
            .expect("effects")
            .into_iter()
            .map(|e| e.idempotency_key)
            .collect();
        assert_eq!(keys, vec!["k0", "k1", "k2"]);
    }

    #[test]
    fn an_illegal_transition_is_refused_rather_than_written() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t", TaskKind::Query);
        let _ = repo.claim("w", NOW, LEASE).expect("claim");
        // Running -> Pending is not a legal transition.
        let err = repo
            .complete(&tid("t"), "w", NOW, TaskState::Pending, false, None)
            .expect_err("must refuse");
        assert!(matches!(err, TaskRepoError::Corrupt(_)), "{err}");
    }

    #[test]
    fn hex_round_trips_through_the_blob_column() {
        assert_eq!(hex_to_bytes("00ff10"), vec![0x00, 0xff, 0x10]);
        assert_eq!(hex_to_bytes(""), Vec::<u8>::new());
        assert_eq!(
            hex_to_bytes("zz"),
            Vec::<u8>::new(),
            "non-hex must not silently decode"
        );
    }
}
