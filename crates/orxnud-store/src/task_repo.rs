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

    /// No proposal with this id.
    #[error("no action proposal {0}")]
    NoSuchProposal(String),

    /// A composition field was given a value the task cannot hold.
    ///
    /// See [`CompositionError`]. Reported rather than clamped: a counter that was quietly
    /// pulled back into range would leave the caller's arithmetic wrong and the database
    /// apparently right, which is the harder of the two to debug.
    #[error(transparent)]
    InvalidComposition(Box<CompositionError>),

    /// The proposal cannot be decided or executed in its current state.
    ///
    /// Carries the state it was in, because "why was this refused" is the whole
    /// question a caller has when a proposal is not `pending`.
    #[error("action proposal {id} is {status}, not {expected}")]
    ProposalNotInState {
        /// The proposal.
        id: String,
        /// What it actually is.
        status: String,
        /// What the caller needed.
        expected: &'static str,
    },
}

/// A composition field that was handed a value its task cannot hold.
///
/// Carries the field and both numbers rather than a sentence alone, so a caller can tell
/// *which* bound was violated and by how much without re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositionError {
    /// The field that was out of range.
    pub field: &'static str,
    /// The value that was refused.
    pub value: u32,
    /// The other number involved, where the check compares two fields.
    pub against: u32,
    /// Why the pair is impossible.
    pub reason: &'static str,
}

impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} = {} is out of range: {}",
            self.field, self.value, self.reason
        )?;
        write!(f, " (the task allows {})", self.against)
    }
}

impl std::error::Error for CompositionError {}

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
    /// The task's own content, as written by [`NewTask::payload`].
    ///
    /// This column was always written and never read: `insert` has carried it since
    /// the table was created, while every read listed its columns by hand and left it
    /// out. So a task's content was durable and invisible at the same time, which
    /// made "list my tasks" unable to say what any of them *were*. Exposing the
    /// existing column is the whole fix — no migration, no second column.
    pub payload: Option<String>,
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
    /// The most logical steps this task may have.
    ///
    /// Written through [`validate_max_steps`]; never clamped.
    pub max_steps: u32,
    /// How many logical steps have been verified.
    ///
    /// Read-only in this stage: advancing it belongs to the execution slice, because a
    /// counter that moved on insert would let a stored result stand in for a verification.
    pub steps_completed: u32,
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

/// Why one *specific* task could not be claimed.
///
/// A dedicated type rather than a bool or a string, because the caller has to answer
/// a peer with something stable: "no such task", "already running", "not due yet"
/// and "out of retries" are four different operational facts and a client cannot
/// act on any of them if they all arrive as `false`.
///
/// Every variant is derived from durable state read inside the claim's own
/// transaction, never from a separate pre-flight query — see
/// [`TaskRepository::claim_specific`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimRefusal {
    /// No task carries that id.
    NotFound,
    /// The task is not `pending`, so it is not claimable — already running,
    /// already finished, or explicitly paused.
    NotPending,
    /// `run_after_ms` is still in the future.
    NotYetRunnable,
    /// `attempts` has reached `max_attempts`.
    ///
    /// Defence in depth. The public paths do not produce this state: `complete_with`
    /// escalates an over-budget failure to `dead-lettered` rather than requeueing it,
    /// and `recover` does the same for an orphaned lease. It is reported precisely
    /// rather than folded into "not claimable" so that if a future writer *does*
    /// produce it, the reason a request failed is still the true one.
    ///
    /// The task stays `pending` and is dead-lettered by the next generic
    /// [`TaskRepository::claim`] pass, exactly as before: escalating here would make
    /// a targeted request able to destroy a task it merely asked about.
    RetriesExhausted,
    /// The task is at a step boundary, but every step it has is already verified.
    ///
    /// Distinct from `NotPending` because the task *is* in a claimable state and the reason
    /// it cannot be claimed is arithmetic rather than lifecycle: its counters say there is no
    /// next step. Reported precisely so a caller can tell "nothing left to do" from "not your
    /// turn".
    NoStepsRemaining,
}

impl ClaimRefusal {
    /// A stable wire spelling, so a peer branches on data rather than on prose.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not-found",
            Self::NotPending => "not-claimable",
            Self::NotYetRunnable => "not-yet-runnable",
            Self::RetriesExhausted => "retries-exhausted",
            Self::NoStepsRemaining => "no-steps-remaining",
        }
    }
}

/// The result of asking for one named task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetedClaimOutcome {
    /// That task was claimed.
    Claimed(Box<ClaimedTask>),
    /// It was not, for a stated reason.
    Refused(ClaimRefusal),
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

/// A governed action a task has asked to perform (ADR-0038).
///
/// Durable *before* the task is observable as `WaitingForUser`, so the wait is
/// explained by a record rather than by an absence.
///
/// The proposer is stored as canonical JSON and re-read at execution time, never
/// re-derived from the task or its lease. That is V-71 expressed as a schema: there
/// is no worker column here at all, so the lease holder cannot become the actor even
/// by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalRow {
    /// This proposal's id.
    pub proposal_id: String,
    /// The task that asked.
    pub task_id: TaskId,
    /// The attempt that asked. Unchanged across the human wait.
    pub attempt_no: u32,
    /// The 1-based logical step this proposal belongs to, from the durable row.
    ///
    /// Read from the row rather than derived from `attempt_no`: a retried step holds its
    /// step number and advances its attempt number, so the two are not interchangeable.
    pub step_no: u32,
    /// The capability requested.
    pub capability: String,
    /// The target, if the capability names one.
    pub target: Option<String>,
    /// Canonical JSON parameters — what an approval will be computed over.
    pub params: String,
    /// The proposer, as canonical `Actor` JSON.
    pub proposer_json: String,
    /// The human whose authority the proposer acts under, when it has one.
    pub authority_root: Option<String>,
    /// When the proposal was made.
    pub created_at_ms: i64,
    /// `pending`, `approved`, `rejected` or `expired`.
    pub status: String,
    /// When it was decided, if it has been.
    pub decided_at_ms: Option<i64>,
}

impl ProposalRow {
    /// Whether this proposal is still awaiting a decision.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.status == "pending"
    }

    /// The proposer, decoded.
    ///
    /// An error rather than a silent default: a proposal whose actor cannot be read
    /// must not become an execution with no actor, because the whole authorisation path
    /// hangs off that identity.
    ///
    /// # Errors
    ///
    /// If the stored JSON is not a valid `Actor`.
    pub fn proposer(&self) -> Result<orxnud_domain::Actor, String> {
        serde_json::from_str(&self.proposer_json).map_err(|e| {
            format!(
                "proposal {} has an unreadable proposer: {e}",
                self.proposal_id
            )
        })
    }
}

/// An approval, bound to exactly one attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRow {
    /// The task.
    pub task_id: TaskId,
    /// The attempt this approval belongs to.
    pub attempt_no: u32,
    /// The 1-based logical step this approval was minted for, from the durable row.
    ///
    /// Distinct from `attempt_no` throughout: a retried step holds its step number and
    /// advances its attempt number.
    pub step_no: u32,
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

/// The columns every read of `tasks` selects, in [`decode_row`]'s order.
///
/// One definition, because these were previously written out by hand in three places
/// and that is exactly how `payload` came to be written but never read: the insert
/// statement and the read statements had nothing to keep them in step, so adding a
/// column to one silently did nothing to the other.
const TASK_COLUMNS: &str = "id, kind, state, priority, payload, attempts, max_attempts, \
     lease_expires_at_ms, lease_holder, idempotent, effect_observed, run_after_ms, \
     catch_up, last_error, cancel_requested_at_ms, schedule_id, fire_time_ms, \
     created_at_ms, updated_at_ms, dead_lettered_at_ms, completed_at_ms, \
     max_steps, steps_completed";

/// A task must have at least one step, or it could never complete.
///
/// The only value the storage type admits below the bound is zero: `max_steps` is an
/// unsigned integer, so a negative is not representable and is not tested for.
pub fn validate_max_steps(max_steps: u32) -> Result<(), CompositionError> {
    if max_steps < 1 {
        return Err(CompositionError {
            field: "max_steps",
            value: max_steps,
            against: 1,
            reason: "a task must have at least one step",
        });
    }
    Ok(())
}

/// A task cannot have completed more steps than it has.
///
/// Checks `max_steps` first, so a task whose own bound is impossible is reported as such
/// rather than as an over-count that merely looks consistent.
pub fn validate_steps_completed(
    max_steps: u32,
    steps_completed: u32,
) -> Result<(), CompositionError> {
    validate_max_steps(max_steps)?;
    if steps_completed > max_steps {
        return Err(CompositionError {
            field: "steps_completed",
            value: steps_completed,
            against: max_steps,
            reason: "a task cannot have completed more steps than it has",
        });
    }
    Ok(())
}

/// Steps are numbered from 1, and a step must be one the task actually has.
///
/// The lower bound is not a formality: reading a stored `step_no` of 0 as "the first step"
/// would let an uninitialised row authorise a write.
pub fn validate_step_no(max_steps: u32, step_no: u32) -> Result<(), CompositionError> {
    validate_max_steps(max_steps)?;
    if step_no < 1 {
        return Err(CompositionError {
            field: "step_no",
            value: step_no,
            against: 1,
            reason: "steps are numbered from 1",
        });
    }
    if step_no > max_steps {
        return Err(CompositionError {
            field: "step_no",
            value: step_no,
            against: max_steps,
            reason: "a step must be one the task has",
        });
    }
    Ok(())
}

/// How one logical step concluded.
///
/// The four values are the schema's `CHECK` list, written out here so a caller cannot
/// invent a fifth. `Failed` is present because a step that gave up is still an outcome;
/// what is *not* representable is a step with two final outcomes, which is what the
/// `(task_id, step_no)` primary key refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    /// The step's effect was observed and verified.
    Verified,
    /// Verification looked for the effect and did not find it.
    Refuted,
    /// Verification could not decide.
    Undetermined,
    /// The step failed and its attempts were exhausted.
    Failed,
}

impl StepStatus {
    /// The stored spelling.
    #[must_use]
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Refuted => "refuted",
            Self::Undetermined => "undetermined",
            Self::Failed => "failed",
        }
    }

    /// Parses a stored spelling, refusing anything else.
    #[must_use]
    pub fn from_wire_str(raw: &str) -> Option<Self> {
        match raw {
            "verified" => Some(Self::Verified),
            "refuted" => Some(Self::Refuted),
            "undetermined" => Some(Self::Undetermined),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// One logical step's durable result.
///
/// Observational only: this records what happened to a step and nothing about who was
/// allowed to cause it. There is deliberately no worker, lease, digest, approval or actor
/// field, because a second copy of any of those would be a second thing to keep in step
/// and the most likely route to a result row being mistaken for permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepResultRow {
    /// The task the step belongs to.
    pub task_id: TaskId,
    /// The 1-based logical step. Not the attempt: one row covers every attempt.
    pub step_no: u32,
    /// How the step concluded.
    pub status: StepStatus,
    /// How it was verified, if it was.
    pub verification: Option<String>,
    /// Whatever the step produced.
    pub structured_output: Option<String>,
    /// Files or other artefacts it produced.
    pub artifacts: Option<String>,
    /// When the result was recorded.
    pub recorded_at_ms: i64,
}

/// The task row as the completion transaction needs to see it, in one read.
///
/// Named because a five-element tuple read positionally is how `max_steps` and
/// `steps_completed` get swapped by a later edit, and both are load-bearing here.
struct FenceRow {
    state: String,
    holder: Option<String>,
    expiry: Option<i64>,
    max_steps: i64,
    steps_completed: i64,
}

/// What a verified logical step is being completed with.
///
/// The step number is an input rather than something derived here, because the caller is
/// the runtime that dispatched the work and knows which step it dispatched; the
/// repository's job is to check it against durable state, not to invent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStep<'a> {
    /// The task the step belongs to.
    pub task_id: TaskId,
    /// The worker whose lease is being spent.
    pub worker: &'a str,
    /// The logical step being completed.
    pub step_no: u32,
    /// The proposal this execution came from, checked to belong to `step_no`.
    pub proposal_id: &'a str,
    /// The verifier's conclusion. Only [`StepStatus::Verified`] advances anything.
    pub status: StepStatus,
    /// What verified it.
    pub verification: Option<String>,
    /// What the step produced.
    pub structured_output: Option<String>,
    /// Files or other artefacts it produced.
    pub artifacts: Option<String>,
    /// When the result was recorded.
    pub recorded_at_ms: i64,
}

/// Where a task ended up after a verified step, and how far it got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepAdvance {
    /// The logical step that was just completed.
    pub step_no: u32,
    /// The counter after the increment.
    pub steps_completed: u32,
    /// The task's ceiling.
    pub max_steps: u32,
    /// [`TaskState::AwaitingNextStep`] when another step remains,
    /// [`TaskState::Completed`] when it does not.
    pub state: TaskState,
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

type Taken = (String, String, i64, i64);

/// Takes the lease, for either entry point.
///
/// `target` of `None` means "whichever task the queue picks"; `Some(id)` means
/// exactly that task and no other.
///
/// Both forms are **one statement** (ADR-0007 invariant 2): the selection and the
/// update are the same `UPDATE ... WHERE id = (...) RETURNING`. A `SELECT` followed
/// by a separate `UPDATE` has a window in which two workers both see the same free
/// task, and a targeted claim has the same race as a generic one — narrowing *which*
/// row may be taken does not make the taking atomic.
///
/// The two SQL texts differ only in their `WHERE`, so the binding and the decoding
/// are written once here rather than copied per entry point.
fn take_lease(
    tx: &Transaction<'_>,
    worker: &str,
    now_ms: i64,
    lease_ms: i64,
    target: Option<&TaskId>,
) -> Result<Option<Taken>, TaskRepoError> {
    const NEXT: &str = "SELECT id FROM tasks
                          WHERE state = 'pending'
                            AND run_after_ms <= ?3
                            AND attempts < max_attempts
                          ORDER BY priority DESC, created_at_ms ASC, id ASC
                          LIMIT 1";
    let sql = match target {
        // The partial index `idx_tasks_claimable` contains exactly the rows the
        // subquery can return, so this scan is proportional to the backlog rather
        // than to history.
        None => format!(
            "UPDATE tasks
                SET state                  = 'running',
                    lease_holder           = ?1,
                    lease_expires_at_ms    = ?2,
                    attempts               = attempts + 1,
                    updated_at_ms          = ?3
              WHERE id = ({NEXT})
             RETURNING id, kind, lease_expires_at_ms, attempts;"
        ),
        Some(_) => "UPDATE tasks
                SET state                  = 'running',
                    lease_holder           = ?1,
                    lease_expires_at_ms    = ?2,
                    attempts               = attempts + 1,
                    updated_at_ms          = ?3
              WHERE id = ?4
                AND state = 'pending'
                AND run_after_ms <= ?3
                AND attempts < max_attempts
             RETURNING id, kind, lease_expires_at_ms, attempts;"
            .to_owned(),
    };
    let bound = now_ms.saturating_add(lease_ms);
    let taken = match target {
        None => tx.query_row(&sql, rusqlite::params![worker, bound, now_ms], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        }),
        Some(id) => tx.query_row(
            &sql,
            rusqlite::params![worker, bound, now_ms, id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ),
    };
    Ok(taken.optional()?)
}

/// Opens the attempt row and the `claimed` event, then commits them together.
///
/// Every path that has taken a lease must come through here, so "a claim always
/// opens an attempt, always logs `claimed`, and always commits both or neither" is
/// one piece of code rather than a convention each caller has to remember.
///
/// Takes the transaction **by value** and commits it. That is what releases the
/// write borrow on the connection, which is why the caller can read the row back
/// afterwards — the ordering the fence depends on: the lease is durable before
/// anybody is told about it.
///
/// Returns the 1-based attempt number this claim opened.
/// The logical step a fresh attempt belongs to: `steps_completed + 1`.
///
/// Read inside the claiming transaction, so the attempt row cannot name a step taken from a
/// different moment than the lease it accompanies.
fn step_no_in(tx: &Transaction<'_>, task_id: &str) -> Result<u32, TaskRepoError> {
    let completed: i64 = tx.query_row(
        "SELECT steps_completed FROM tasks WHERE id = ?1;",
        rusqlite::params![task_id],
        |r| r.get(0),
    )?;
    Ok((completed as u32).saturating_add(1))
}

fn commit_claim(
    tx: Transaction<'_>,
    id: &str,
    kind: &str,
    attempts: i64,
    step_no: u32,
    worker: &str,
    now_ms: i64,
) -> Result<u32, TaskRepoError> {
    let task_id = TaskId::new(id);
    let attempt_no = u32::try_from(attempts).unwrap_or(u32::MAX);

    // Test-only: die holding the claim but with no attempt row. A restart must
    // see neither a lease nor an attempt, because the claim never committed.
    faults::maybe_crash(FaultPoint::ClaimAfterTakeBeforeAttempt);

    tx.execute(
        "INSERT INTO task_attempts (task_id, step_no, attempt_no, worker, started_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5);",
        rusqlite::params![task_id.as_str(), step_no, attempt_no, worker, now_ms],
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
        Some(kind),
    )?;
    tx.commit()?;
    Ok(attempt_no)
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

    /// The logical step currently being worked on: `steps_completed + 1`.
    ///
    /// Read from the durable counter every time rather than carried in memory, so a
    /// process that starts mid-task asks the same question as one that has been here the
    /// whole time. The result is validated, so a counter that has run past the ceiling
    /// surfaces here rather than as an impossible proposal later.
    ///
    /// # Errors
    ///
    /// `NotFound` if the task does not exist, or `InvalidComposition` if the task's own
    /// counters are impossible.
    pub fn next_step_no(&self, task_id: &TaskId) -> Result<u32, TaskRepoError> {
        let (max_steps, steps_completed) = self
            .conn
            .query_row(
                "SELECT max_steps, steps_completed FROM tasks WHERE id = ?1;",
                rusqlite::params![task_id.as_str()],
                |r| Ok((r.get::<_, i64>(0)? as u32, r.get::<_, i64>(1)? as u32)),
            )
            .optional()?
            .ok_or_else(|| TaskRepoError::NotFound(task_id.to_string()))?;
        validate_steps_completed(max_steps, steps_completed)
            .map_err(|e| TaskRepoError::InvalidComposition(Box::new(e)))?;
        // A finished task has no next step. `max_steps + 1` is returned rather than an
        // error so a caller polling a completed task is not treated as broken, and it is
        // past any task's ceiling, so it can never be proposed or completed.
        Ok(steps_completed.saturating_add(1))
    }

    /// Completes one verified logical step, and moves the task on if there is another.
    ///
    /// This is the whole post-verification transition, in **one** `IMMEDIATE`
    /// transaction. Nothing here is committed on its own, so none of the four states this
    /// could otherwise leave behind is reachable:
    ///
    /// ```text
    /// result present + counter not advanced   <- refused before the insert
    /// counter advanced + result absent        <- impossible; both are in this tx
    /// completed with no final result          <- impossible; both are in this tx
    /// awaiting-next-step with no result        <- impossible; both are in this tx
    /// ```
    ///
    /// The order inside the transaction is load-bearing. The lease fence and the step
    /// identity are settled first, then the result is written, then the counter is
    /// incremented and validated, and only then is the new state chosen -- because the
    /// choice depends on the *incremented* counter, and computing it earlier is how a task
    /// ends up `Completed` with a step still outstanding.
    ///
    /// The lease is cleared by the same conditional `UPDATE` that sets the state, at the
    /// boundary as well as at the end. The next step must not inherit the prior worker's
    /// lease; acquiring a fresh one is a later slice, and until then the task is simply
    /// left claimable and unclaimed.
    ///
    /// The step identity check is what makes a repeated completion harmless: the step being
    /// completed must be `steps_completed + 1`, so once the counter has moved past it the
    /// step is no longer the current one and this call is refused. The `(task_id, step_no)`
    /// primary key is the second guard -- neither is trusted to carry the whole weight.
    ///
    /// This method is deliberately **not** shared with [`Self::complete_with`]. That method
    /// finishes a task under the caller's chosen state; this one decides the state itself
    /// from a counter, and its post-conditions (result, counter, boundary lease release)
    /// have no counterpart there. Sharing would mean one method with a mode flag, which is
    /// how a verified step ends up skipping its result.
    ///
    /// # Errors
    ///
    /// * `NotFound` if the task or the named proposal does not exist.
    /// * `Corrupt` if the task is not `running` -- this is not an operation on a task that
    ///   is already finished, waiting, or cancelled.
    /// * `InvalidComposition` if `step_no` is not the current logical step, if the
    ///   verifier's conclusion was not `verified`, or if the resulting counter would exceed
    ///   `max_steps`.
    /// * `AlreadyExists` if the step already has a result row.
    pub fn complete_verified_step(
        &mut self,
        done: &VerifiedStep<'_>,
    ) -> Result<StepAdvance, TaskRepoError> {
        // Only a verified effect advances a logical step. Refuted, undetermined and failed
        // are all "this step did not conclude", and writing a result row for any of them
        // would both consume the step's single result and invent progress.
        if done.status != StepStatus::Verified {
            return Err(TaskRepoError::InvalidComposition(Box::new(
                CompositionError {
                    field: "status",
                    value: 0,
                    against: 1,
                    reason: "only a verified outcome completes a logical step",
                },
            )));
        }

        let tx = self.tx()?;

        // INVARIANT: the fence is evaluated first, inside the same IMMEDIATE transaction,
        // so no other writer can change the row between the check and the update -- the
        // same ordering `complete_with` uses, for the same reason.
        let current: Option<FenceRow> = tx
            .query_row(
                "SELECT state, lease_holder, lease_expires_at_ms, max_steps, steps_completed
                   FROM tasks WHERE id = ?1;",
                rusqlite::params![done.task_id.as_str()],
                |r| {
                    Ok(FenceRow {
                        state: r.get(0)?,
                        holder: r.get(1)?,
                        expiry: r.get(2)?,
                        max_steps: r.get(3)?,
                        steps_completed: r.get(4)?,
                    })
                },
            )
            .optional()?;
        let Some(FenceRow {
            state: from_raw,
            holder,
            expiry,
            max_steps,
            steps_completed,
        }) = current
        else {
            return Err(TaskRepoError::NotFound(done.task_id.to_string()));
        };
        let max_steps = max_steps as u32;
        let steps_completed = steps_completed as u32;

        let from_state = TaskState::from_wire_str(&from_raw)
            .ok_or_else(|| unknown_state(done.task_id.to_string(), from_raw.clone()))?;
        if from_state != TaskState::Running {
            // Named rather than folded into the digest mismatch: "this task is not
            // executing" and "this approval was for another step" call for different fixes.
            return Err(TaskRepoError::Corrupt(Box::new(CorruptRowDetail {
                id: done.task_id.to_string(),
                reason: format!(
                    "cannot complete step {} of a task that is {}, not running",
                    done.step_no,
                    from_state.as_wire_str()
                ),
            })));
        }
        // Both halves of the lease fence (ADR-0032): the holder *and* a live lease.
        if holder.as_deref() != Some(done.worker) || expiry.is_none_or(|e| done.recorded_at_ms >= e)
        {
            return Err(TaskRepoError::Corrupt(Box::new(CorruptRowDetail {
                id: done.task_id.to_string(),
                reason: format!(
                    "{} does not hold a live lease on {}",
                    done.worker, done.task_id
                ),
            })));
        }

        // The task's own counters must be coherent before they are reasoned about.
        validate_steps_completed(max_steps, steps_completed)
            .map_err(|e| TaskRepoError::InvalidComposition(Box::new(e)))?;
        validate_step_no(max_steps, done.step_no)
            .map_err(|e| TaskRepoError::InvalidComposition(Box::new(e)))?;

        // The step being completed must be the step the task is on. This is the guard that
        // makes a duplicate completion harmless: after the counter moves, this step is no
        // longer `steps_completed + 1`, so a replay is refused here rather than counting
        // the same logical step twice.
        let current_step = steps_completed.saturating_add(1);
        if done.step_no != current_step {
            return Err(TaskRepoError::InvalidComposition(Box::new(
                CompositionError {
                    field: "step_no",
                    value: done.step_no,
                    against: current_step,
                    reason: "a step can only be completed when it is the step being worked on",
                },
            )));
        }

        // The proposal this execution came from must belong to the same step, so an
        // approval for one step cannot advance another. Its attempt number is recorded on
        // the event, so a step boundary can be traced back to the attempt that crossed it.
        let proposal_step: Option<(u32, u32)> = tx
            .query_row(
                "SELECT step_no, attempt_no FROM task_proposals WHERE proposal_id = ?1;",
                rusqlite::params![done.proposal_id],
                |r| Ok((r.get::<_, i64>(0)? as u32, r.get::<_, i64>(1)? as u32)),
            )
            .optional()?;
        match proposal_step {
            None => {
                return Err(TaskRepoError::NoSuchProposal(done.proposal_id.to_owned()));
            }
            Some((step, _)) if step != done.step_no => {
                return Err(TaskRepoError::InvalidComposition(Box::new(
                    CompositionError {
                        field: "step_no",
                        value: done.step_no,
                        against: step,
                        reason: "the proposal belongs to a different logical step",
                    },
                )));
            }
            // Belongs to this step: nothing to refuse.
            Some(_) => {}
        }
        // The attempt that crossed the boundary, recorded on the event so a step edge can be
        // traced back to the attempt that caused it. Bound after the match because it only
        // exists once the proposal has been shown to belong to this step.
        let proposal_attempt = proposal_step.map(|(_, attempt)| attempt);

        // The result, then the counter. The primary key refuses a second result for this
        // step, and because the insert and the increment share a transaction, a refusal
        // leaves the counter untouched.
        let inserted = tx.execute(
            "INSERT INTO task_step_results
                (task_id, step_no, status, verification, structured_output, artifacts,
                 recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
            rusqlite::params![
                done.task_id.as_str(),
                done.step_no,
                done.status.as_wire_str(),
                done.verification,
                done.structured_output,
                done.artifacts,
                done.recorded_at_ms,
            ],
        );
        match inserted {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(TaskRepoError::AlreadyExists(format!(
                    "{} step {} already has a result",
                    done.task_id, done.step_no
                )));
            }
            Err(e) => return Err(e.into()),
        }

        // The window the fault point exists to interrupt: the step result is written and
        // the counter has not moved. Both are uncommitted, so a crash here must undo both.
        faults::maybe_crash(FaultPoint::AdvanceStepAfterResultBeforeCounter);

        // The increment, validated rather than assumed. `steps_completed == max_steps`
        // cannot increment: the step identity check above already refuses it, and this
        // catches it a second time for a counter that moved underneath us.
        let new_completed = steps_completed.checked_add(1).ok_or_else(|| {
            TaskRepoError::InvalidComposition(Box::new(CompositionError {
                field: "steps_completed",
                value: u32::MAX,
                against: max_steps,
                reason: "the counter cannot be represented one higher",
            }))
        })?;
        validate_steps_completed(max_steps, new_completed)
            .map_err(|e| TaskRepoError::InvalidComposition(Box::new(e)))?;

        // The state follows the *incremented* counter. Computed here rather than earlier
        // because computing it from the pre-increment value is how a task reaches
        // `Completed` with a step still outstanding.
        let next_state = if new_completed < max_steps {
            TaskState::AwaitingNextStep
        } else {
            TaskState::Completed
        };
        debug_assert!(
            orxnud_domain::task_state::is_legal_transition(from_state, next_state),
            "running must be able to reach both boundaries"
        );

        // `attempts` is reset here, in the same transaction, because it counts attempts
        // **within the current logical step**. A step that took three attempts must not spend
        // the next step's retry budget, and the next step's first claim becomes attempt 1.
        //
        // It has to be in this transaction rather than after it: a crash between "step
        // recorded" and "attempts cleared" would leave a durable row claiming three attempts
        // on a step that is over, which is precisely the step/attempt conflation the two
        // columns exist to prevent.
        //
        // Only on the *boundary*, though. A task that has just become `Completed` keeps its
        // count, because that number is the only record of how much work the task took and
        // it is reported by `task/list`. Clearing it would erase the history of a finished
        // task on the strength of a rule about starting a new step, and there is no new step
        // to start.
        //
        // One conditional UPDATE naming the holder and a live lease (TP-5), which also
        // clears the lease at the boundary. `Completed` gets its timestamp; the boundary
        // state must not, because the task has not ended.
        let changed = tx.execute(
            "UPDATE tasks
                SET steps_completed    = ?5,
                    state               = ?4,
                    effect_observed     = 1,
                    attempts            = CASE WHEN ?4 = 'awaiting-next-step' THEN 0
                                              ELSE attempts END,
                    last_error          = NULL,
                    lease_holder        = NULL,
                    lease_expires_at_ms = NULL,
                    updated_at_ms       = ?3,
                    completed_at_ms     = CASE WHEN ?4 = 'completed' THEN ?3 ELSE NULL END
              WHERE id          = ?1
                AND lease_holder = ?2
                AND lease_expires_at_ms IS NOT NULL
                AND lease_expires_at_ms > ?3;",
            rusqlite::params![
                done.task_id.as_str(),
                done.worker,
                done.recorded_at_ms,
                next_state.as_wire_str(),
                new_completed,
            ],
        )?;
        if changed == 0 {
            // The fence held a moment ago and the transaction is IMMEDIATE, so this is
            // unreachable rather than merely unlikely. Rolling back keeps that honest
            // instead of leaving a result row with no counter move.
            return Err(TaskRepoError::Corrupt(Box::new(CorruptRowDetail {
                id: done.task_id.to_string(),
                reason: "the execution lease was lost inside the completion transaction".to_owned(),
            })));
        }

        log(
            &tx,
            Some(&done.task_id),
            done.recorded_at_ms,
            if next_state == TaskState::Completed {
                "completed"
            } else {
                "awaiting-next-step"
            },
            Some(from_state),
            Some(next_state),
            Some(done.worker),
            proposal_attempt,
            Some(&format!("step {} of {}", done.step_no, max_steps)),
        )?;

        tx.commit()?;
        Ok(StepAdvance {
            step_no: done.step_no,
            steps_completed: new_completed,
            max_steps,
            state: next_state,
        })
    }

    /// Claims the next logical step of a task sitting at a step boundary.
    ///
    /// The counterpart to [`Self::complete_verified_step`]: that one stops at the boundary
    /// and releases the lease, this one starts the next step with a **fresh** one. Kept as a
    /// separate operation rather than folded into [`Self::claim_specific`] because the two
    /// claim different things. A `Pending` task has never run; a task at a boundary has run
    /// and finished a step, and inheriting anything from the previous lease -- holder,
    /// expiry, ownership -- would be claiming authority over an action that lease was never
    /// granted for.
    ///
    /// The transition is `AwaitingNextStep -> Running`, in one `IMMEDIATE` transaction, as a
    /// single conditional `UPDATE`. Not two statements, and never a hop through `Pending`: a
    /// task observed as `pending` by anything else in the system would be indistinguishable
    /// from one that had never run, which is the confusion the explicit boundary state exists
    /// to prevent.
    ///
    /// The `WHERE` clause is the whole concurrency story. Two workers racing for one
    /// boundary both run the same statement; SQLite serialises the writes, the loser's
    /// `UPDATE` matches no row because the state has become `running` and a live lease is
    /// present, and it is told the task is not claimable. There is no second lock and no
    /// read-then-write window.
    ///
    /// `attempts` is incremented exactly as a `Pending` claim increments it, so the next
    /// step's first execution is attempt 1 of that step. The reset that made that true is
    /// part of [`Self::complete_verified_step`], and the two are deliberately adjacent: the
    /// counter is cleared at the boundary and spent again here, in two halves of one
    /// meaning.
    ///
    /// No approval, proposal, step result, execution or audit authorisation is created here.
    /// Claiming establishes ownership of the next step and nothing else; capability
    /// authority still comes from the proposal/approval/dispatcher path.
    ///
    /// # Errors
    ///
    /// `NotFound` if the task does not exist. `UnknownState` if its stored state cannot be
    /// parsed. `InvalidComposition` if its counters are impossible.
    pub fn claim_next_step(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<TargetedClaimOutcome, TaskRepoError> {
        let tx = self.tx()?;

        // A boundary with no steps left is not a boundary this operation may act on. The
        // guard is here rather than only in the `WHERE` so the refusal can say why: a task
        // whose counters are finished must not be re-entered by asking for its next step.
        let bounds: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT state, max_steps, steps_completed FROM tasks WHERE id = ?1;",
                rusqlite::params![id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        let Some((state_raw, max_steps, steps_completed)) = bounds else {
            tx.commit()?;
            return Ok(TargetedClaimOutcome::Refused(ClaimRefusal::NotFound));
        };
        // An unreadable state is neither claimable nor unclaimable; say so rather than guess.
        let state = TaskState::from_wire_str(&state_raw)
            .ok_or_else(|| unknown_state(id.to_string(), state_raw.clone()))?;
        let (max_steps, steps_completed) = (max_steps as u32, steps_completed as u32);

        let refusal = if state != TaskState::AwaitingNextStep {
            // Not at a boundary. `NotPending` is reported rather than a new variant: it
            // already means "this task is not in a claimable state", and adding a variant to
            // distinguish a boundary from a fresh task would be surface area for its own sake.
            Some(ClaimRefusal::NotPending)
        } else {
            validate_steps_completed(max_steps, steps_completed)
                .map_err(|e| TaskRepoError::InvalidComposition(Box::new(e)))?;
            // Every step already verified: there is no next step to claim, whatever the row
            // claims about its own state.
            if steps_completed >= max_steps {
                Some(ClaimRefusal::NoStepsRemaining)
            } else {
                None
            }
        };
        if let Some(refusal) = refusal {
            tx.commit()?;
            return Ok(TargetedClaimOutcome::Refused(refusal));
        }

        // INVARIANT (TP-5): ONE conditional UPDATE whose WHERE names the boundary state,
        // the absence of any lease, and the counter guard. All four clauses are needed:
        // the state alone would let a second worker in after the first has claimed, the
        // lease clauses refuse a boundary row that somehow still carries one, and the
        // counter clause is what stops a finished task being re-entered.
        let bound = now_ms.saturating_add(lease_ms);
        let taken: Option<(String, String, i64, i64)> = tx
            .query_row(
                "UPDATE tasks
                    SET state               = 'running',
                        lease_holder        = ?2,
                        lease_expires_at_ms = ?3,
                        attempts            = attempts + 1,
                        updated_at_ms       = ?4
                  WHERE id                   = ?1
                    AND state                = 'awaiting-next-step'
                    AND lease_holder         IS NULL
                    AND lease_expires_at_ms IS NULL
                    AND steps_completed      < max_steps
                 RETURNING id, kind, lease_expires_at_ms, attempts;",
                rusqlite::params![id.as_str(), worker, bound, now_ms],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;

        let Some((taken_id, kind, lease_expires_at_ms, attempts)) = taken else {
            // The loser of a race lands here: the winner's transaction already moved the
            // state and wrote the lease, so this statement matched nothing. Reported as the
            // contention it is, using the existing refusal vocabulary.
            tx.commit()?;
            return Ok(TargetedClaimOutcome::Refused(ClaimRefusal::NotPending));
        };

        let attempt_no = commit_claim(
            tx,
            &taken_id,
            &kind,
            attempts,
            steps_completed + 1,
            worker,
            now_ms,
        )?;
        let row = self
            .get(&TaskId::new(&taken_id))?
            .ok_or_else(|| TaskRepoError::NotFound(taken_id.clone()))?;
        Ok(TargetedClaimOutcome::Claimed(Box::new(ClaimedTask {
            row,
            attempt_no,
            lease_expires_at_ms,
        })))
    }

    /// Records the final result of one logical step.
    ///
    /// **One row per logical step, however many attempts it took.** A step that failed
    /// twice and verified on the third writes here once; the failed attempts live in the
    /// attempt and audit records. A second result for the same step is refused rather than
    /// merged, because a step with two final outcomes has no meaning and picking one
    /// silently would discard evidence.
    ///
    /// `steps_completed` is deliberately **not** advanced. Verification and counter
    /// movement have to happen together or not at all, and that transaction belongs to the
    /// execution slice; doing it here would let a stored row stand in for a verification.
    ///
    /// The step is checked against the task's own `max_steps` before the insert. The
    /// schema's `CHECK (step_no >= 1)` is not relied upon: it cannot see `max_steps`.
    ///
    /// # Errors
    ///
    /// `NotFound` if the task does not exist. `InvalidComposition` if `step_no` is 0 or
    /// beyond the task's `max_steps`. `AlreadyExists` if the step already has a result.
    pub fn record_step_result(&mut self, result: &StepResultRow) -> Result<(), TaskRepoError> {
        let tx = self.tx()?;
        let (max_steps, _) = tx
            .query_row(
                "SELECT max_steps, steps_completed FROM tasks WHERE id = ?1;",
                rusqlite::params![result.task_id.as_str()],
                |r| Ok((r.get::<_, i64>(0)? as u32, r.get::<_, i64>(1)? as u32)),
            )
            .optional()?
            .ok_or_else(|| TaskRepoError::NotFound(result.task_id.to_string()))?;
        validate_step_no(max_steps, result.step_no)
            .map_err(|e| TaskRepoError::InvalidComposition(Box::new(e)))?;

        let n = tx.execute(
            "INSERT INTO task_step_results
                (task_id, step_no, status, verification, structured_output, artifacts,
                 recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7);",
            rusqlite::params![
                result.task_id.as_str(),
                result.step_no,
                result.status.as_wire_str(),
                result.verification,
                result.structured_output,
                result.artifacts,
                result.recorded_at_ms,
            ],
        );
        let inserted = match n {
            Ok(n) => n,
            // The `(task_id, step_no)` primary key is what refuses the second result, so
            // it is reported as the conflict it is rather than as a SQLite failure.
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(TaskRepoError::AlreadyExists(format!(
                    "{} step {} already has a result",
                    result.task_id, result.step_no
                )));
            }
            Err(e) => return Err(e.into()),
        };
        if inserted == 0 {
            return Err(TaskRepoError::AlreadyExists(format!(
                "{} step {} already has a result",
                result.task_id, result.step_no
            )));
        }
        tx.commit()?;
        Ok(())
    }

    /// The final result of one logical step, if it has one.
    ///
    /// # Errors
    ///
    /// Any SQLite error, or `UnknownState`/`Corrupt` if a row cannot be decoded.
    pub fn step_result(
        &self,
        task_id: &TaskId,
        step_no: u32,
    ) -> Result<Option<StepResultRow>, TaskRepoError> {
        self.conn
            .query_row(
                "SELECT task_id, step_no, status, verification, structured_output,
                        artifacts, recorded_at_ms
                   FROM task_step_results WHERE task_id = ?1 AND step_no = ?2;",
                rusqlite::params![task_id.as_str(), step_no],
                decode_step_result,
            )
            .optional()?
            .transpose()
    }

    /// Whether a logical step has concluded.
    ///
    /// Cheaper than [`Self::step_result`] when only the fact matters, which is the case
    /// that will recur: the execution path asks this before every step.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn step_result_exists(
        &self,
        task_id: &TaskId,
        step_no: u32,
    ) -> Result<bool, TaskRepoError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM task_step_results WHERE task_id = ?1 AND step_no = ?2;",
            rusqlite::params![task_id.as_str(), step_no],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Every result a task has, in step order.
    ///
    /// # Errors
    ///
    /// Any SQLite error, or `UnknownState`/`Corrupt` if a row cannot be decoded.
    pub fn step_results_for(&self, task_id: &TaskId) -> Result<Vec<StepResultRow>, TaskRepoError> {
        let mut stmt = self.conn.prepare(
            "SELECT task_id, step_no, status, verification, structured_output,
                    artifacts, recorded_at_ms
               FROM task_step_results WHERE task_id = ?1 ORDER BY step_no;",
        )?;
        let rows = stmt.query_map(rusqlite::params![task_id.as_str()], decode_step_result)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
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
    /// `TaskRepoError::CorruptRow` if another column cannot be decoded. The variant is
    /// spelled `TaskRepoError::Corrupt`; it carries a [`CorruptRowDetail`].
    pub fn get(&self, id: &TaskId) -> Result<Option<TaskRow>, TaskRepoError> {
        let sql = format!("SELECT {TASK_COLUMNS} FROM tasks WHERE id = ?1;");
        self.conn
            .query_row(&sql, [id.as_str()], decode_row)
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
        let sql = format!("SELECT {TASK_COLUMNS} FROM tasks ORDER BY id;");
        self.read_rows(&sql)
    }

    /// Reads at most `limit` tasks, for a diagnostic that does not need them all.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub fn list_limited(&self, limit: u32) -> Result<Vec<TaskRow>, TaskRepoError> {
        let sql = format!("SELECT {TASK_COLUMNS} FROM tasks ORDER BY id LIMIT ?1;");
        self.read_rows_with(&sql, [i64::from(limit)])
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

        let Some((id, kind, lease_expires_at_ms, attempts)) =
            take_lease(&tx, worker, now_ms, lease_ms, None)?
        else {
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

        let step_no = step_no_in(&tx, &id)?;
        let attempt_no = commit_claim(tx, &id, &kind, attempts, step_no, worker, now_ms)?;
        let row = self
            .get(&TaskId::new(&id))?
            .ok_or_else(|| TaskRepoError::NotFound(id.clone()))?;
        let claimed = ClaimedTask {
            row,
            attempt_no,
            lease_expires_at_ms,
        };
        Ok(ClaimOutcome::Claimed(Box::new(claimed)))
    }

    /// Atomically claims **one named task**, taking a lease.
    ///
    /// The same lease, the same attempt, the same event and the same fencing as
    /// [`Self::claim`]; the only difference is which row is eligible. Narrowing the
    /// choice does not narrow the transaction, so this cannot become the weak link
    /// the generic claim is careful not to be.
    ///
    /// # Why the refusal is classified inside the same transaction
    ///
    /// When the conditional `UPDATE` matches nothing, the row is read back to say
    /// *why*. That read happens before the commit, so it observes the state the
    /// failed `UPDATE` saw: `BEGIN IMMEDIATE` holds the write lock throughout, and no
    /// other writer can slip between the two statements. Asking first and updating
    /// afterwards would be the race this method exists not to have.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn claim_specific(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<TargetedClaimOutcome, TaskRepoError> {
        let tx = self.tx()?;

        let taken = take_lease(&tx, worker, now_ms, lease_ms, Some(id))?;
        let Some((taken_id, kind, lease_expires_at_ms, attempts)) = taken else {
            let refusal: Option<(String, String, i64, i64, i64)> = tx
                .query_row(
                    "SELECT id, state, run_after_ms, attempts, max_attempts
                       FROM tasks WHERE id = ?1;",
                    [id.as_str()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            let Some((_, state_raw, run_after_ms, attempts, max_attempts)) = refusal else {
                tx.commit()?;
                return Ok(TargetedClaimOutcome::Refused(ClaimRefusal::NotFound));
            };
            // A state this build cannot parse is not "claimable" and not "not
            // claimable": it is unreadable, so say so instead of guessing.
            let state = TaskState::from_wire_str(&state_raw)
                .ok_or_else(|| unknown_state(id.to_string(), state_raw.clone()))?;
            let refusal = if state != TaskState::Pending {
                ClaimRefusal::NotPending
            } else if run_after_ms > now_ms {
                ClaimRefusal::NotYetRunnable
            } else if attempts >= max_attempts {
                ClaimRefusal::RetriesExhausted
            } else {
                // Claimable by every condition the UPDATE tested, yet not taken. The
                // only honest answer: something is wrong that this layer will not
                // paper over.
                ClaimRefusal::NotPending
            };
            tx.commit()?;
            return Ok(TargetedClaimOutcome::Refused(refusal));
        };

        let step_no = step_no_in(&tx, &taken_id)?;
        let attempt_no = commit_claim(tx, &taken_id, &kind, attempts, step_no, worker, now_ms)?;
        let row = self
            .get(&TaskId::new(&taken_id))?
            .ok_or_else(|| TaskRepoError::NotFound(taken_id.clone()))?;
        let claimed = ClaimedTask {
            row,
            attempt_no,
            lease_expires_at_ms,
        };
        Ok(TargetedClaimOutcome::Claimed(Box::new(claimed)))
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
    /// Any SQLite error, or `TaskRepoError::CorruptRow` if the stored state is
    /// unrecognisable. There is no `CorruptRow` variant: an unrecognisable stored
    /// state is reported as [`TaskRepoError::UnknownState`], and a transition the
    /// stored state cannot support is reported as `TaskRepoError::Corrupt`.
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

    // ------------------------------------------------------- action proposals

    /// Records a governed action a task is asking to perform, and parks the task.
    ///
    /// ADR-0038. **One transaction, three writes**: the proposal row, the transition to
    /// `waiting_for_user`, and the `task_events` entry. The single transaction is the
    /// requirement rather than a convenience: a task that is observably waiting with no
    /// proposal behind it is unexplainable state, and a proposal with no waiting task
    /// is an action nobody was ever asked about. Neither is recoverable by reading.
    ///
    /// ## The lease is released, not carried
    ///
    /// The lease is cleared here rather than held across the human wait. `limits.rs`
    /// states the invariant — a lease expires and the task is reclaimable, *never a task
    /// held forever* — and a human approval routinely outlives the 30s default lease.
    /// Carrying it would leave the task `running` with a dead lease: `complete_with`
    /// requires a live one, and `take_lease` only accepts `pending`, so the task could
    /// never complete. Execution takes a fresh lease in
    /// [`Self::begin_approved_execution`].
    ///
    /// The worker is verified to hold the live lease *before* the proposal is accepted,
    /// so only the task's current owner may propose on its behalf. That is a check that
    /// the caller owns the task — it grants nothing, and it is deliberately not how the
    /// proposer identity is decided (V-71).
    ///
    /// # Errors
    ///
    /// [`TaskRepoError::NotFound`] if the task is unknown, [`TaskRepoError::AlreadyExists`]
    /// if this attempt already has a proposal, or any SQLite error.
    #[allow(clippy::too_many_arguments)] // One column per argument; see the docs for why each is needed.
    pub fn propose_action(
        &mut self,
        proposal_id: &str,
        task_id: &TaskId,
        worker: &str,
        capability: &str,
        target: Option<&str>,
        canonical_params: &str,
        proposer_json: &str,
        authority_root: Option<&str>,
        step_no: u32,
        now_ms: i64,
    ) -> Result<ProposalRow, TaskRepoError> {
        let tx = self.tx()?;

        let row: (String, String, Option<i64>, u32, i64) = tx.query_row(
            "SELECT state, lease_holder, lease_expires_at_ms, attempts, max_steps
               FROM tasks WHERE id = ?1;",
            rusqlite::params![task_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        let state = TaskState::from_wire_str(&row.0).ok_or_else(|| {
            TaskRepoError::UnknownState(Box::new(UnknownStateDetail {
                id: task_id.to_string(),
                raw: row.0,
            }))
        })?;
        if state != TaskState::Running {
            return Err(TaskRepoError::ProposalNotInState {
                id: proposal_id.to_owned(),
                status: format!("task is {}", state.as_wire_str()),
                expected: "running",
            });
        }
        // Ownership of the task, not authority over it. A proposal from a worker that
        // does not hold the live lease would let any caller speak for a running task.
        if row.1.as_str() != worker || row.2.is_none_or(|e| now_ms >= e) {
            return Err(TaskRepoError::ProposalNotInState {
                id: proposal_id.to_owned(),
                status: format!("the caller does not hold the live lease on {}", task_id),
                expected: "running under a live lease held by the caller",
            });
        }

        // The step is supplied by the runtime, which reads it from the task's durable
        // `steps_completed` (see `next_step_no`) and knows which logical step it is asking
        // for. What the repository does is refuse it: the step must be one the task has, and
        // it must be the step actually being worked on. That second check is what stops a
        // stale caller from proposing step 1 again after the task moved to step 2.
        let max_steps = row.4 as u32;
        validate_step_no(max_steps, step_no)
            .map_err(|e| TaskRepoError::InvalidComposition(Box::new(e)))?;
        let steps_completed: i64 = tx.query_row(
            "SELECT steps_completed FROM tasks WHERE id = ?1;",
            rusqlite::params![task_id.as_str()],
            |r| r.get(0),
        )?;
        let current_step = (steps_completed as u32).saturating_add(1);
        if step_no != current_step {
            return Err(TaskRepoError::InvalidComposition(Box::new(
                CompositionError {
                    field: "step_no",
                    value: step_no,
                    against: current_step,
                    reason: "a proposal must be for the step currently being worked on",
                },
            )));
        }

        tx.execute(
            "INSERT INTO task_proposals
               (proposal_id, task_id, attempt_no, step_no, capability, target, params,
                proposer, authority_root, created_at_ms, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'pending');",
            rusqlite::params![
                proposal_id,
                task_id.as_str(),
                row.3,
                step_no,
                capability,
                target,
                canonical_params,
                proposer_json,
                authority_root,
                now_ms,
            ],
        )
        .map_err(|e| {
            if String::from_utf8_lossy(e.to_string().as_bytes()).contains("UNIQUE") {
                TaskRepoError::AlreadyExists(format!(
                    "a proposal already exists for {task_id} attempt {}",
                    row.3
                ))
            } else {
                TaskRepoError::Sqlite(Box::new(e))
            }
        })?;

        // `WaitingForUser` and the lease release in one statement, so there is no
        // interleaving in which the task is waiting while still holding a lease.
        tx.execute(
            "UPDATE tasks
                SET state = 'waiting-for-user',
                    lease_holder = NULL,
                    lease_expires_at_ms = NULL,
                    updated_at_ms = ?2
              WHERE id = ?1 AND state = 'running';",
            rusqlite::params![task_id.as_str(), now_ms],
        )?;

        log(
            &tx,
            Some(task_id),
            now_ms,
            "action-proposed",
            Some(state),
            Some(TaskState::WaitingForUser),
            Some(worker),
            Some(row.3),
            Some(proposal_id),
        )?;

        tx.commit()?;
        self.proposal_by_id(proposal_id)?
            .ok_or_else(|| TaskRepoError::NoSuchProposal(proposal_id.to_owned()))
    }

    /// Reads one proposal by id.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn proposal_by_id(&self, id: &str) -> Result<Option<ProposalRow>, TaskRepoError> {
        let mut stmt = self.conn.prepare(
            "SELECT proposal_id, task_id, attempt_no, step_no, capability, target, params,
                    proposer, authority_root, created_at_ms, status, decided_at_ms
               FROM task_proposals WHERE proposal_id = ?1;",
        )?;
        let mut rows = stmt.query(rusqlite::params![id])?;
        let Some(r) = rows.next()? else {
            return Ok(None);
        };
        Ok(Some(ProposalRow {
            proposal_id: r.get(0)?,
            task_id: TaskId::new(r.get::<_, String>(1)?.as_str()),
            attempt_no: r.get::<_, i64>(2)? as u32,
            step_no: r.get::<_, i64>(3)? as u32,
            capability: r.get(4)?,
            target: r.get(5)?,
            params: r.get(6)?,
            proposer_json: r.get(7)?,
            authority_root: r.get(8)?,
            created_at_ms: r.get(9)?,
            status: r.get(10)?,
            decided_at_ms: r.get(11)?,
        }))
    }

    /// Records a human decision on a proposal.
    ///
    /// Deliberately does **not** change the task's state or take a lease: the task stays
    /// `waiting-for-user` until execution actually begins, so an approved proposal that
    /// is never executed leaves a task that is honestly still waiting rather than one
    /// that looks like it is running.
    ///
    /// # Errors
    ///
    /// [`TaskRepoError::NoSuchProposal`], [`TaskRepoError::ProposalNotInState`] if it
    /// was already decided, or any SQLite error.
    pub fn decide_proposal(
        &mut self,
        id: &str,
        status: &'static str,
        now_ms: i64,
    ) -> Result<ProposalRow, TaskRepoError> {
        debug_assert!(matches!(status, "approved" | "rejected" | "expired"));
        let tx = self.tx()?;
        let existing: Option<(String, String)> = tx
            .query_row(
                "SELECT task_id, status FROM task_proposals WHERE proposal_id = ?1;",
                rusqlite::params![id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((task_id, was)) = existing else {
            return Err(TaskRepoError::NoSuchProposal(id.to_owned()));
        };
        if was != "pending" {
            return Err(TaskRepoError::ProposalNotInState {
                id: id.to_owned(),
                status: was,
                expected: "pending",
            });
        }
        tx.execute(
            "UPDATE task_proposals
                SET status = ?2, decided_at_ms = ?3
              WHERE proposal_id = ?1 AND status = 'pending';",
            rusqlite::params![id, status, now_ms],
        )?;
        let from: String = tx.query_row(
            "SELECT state FROM tasks WHERE id = ?1;",
            rusqlite::params![task_id.as_str()],
            |r| r.get(0),
        )?;
        let from_state = TaskState::from_wire_str(&from);
        log(
            &tx,
            Some(&TaskId::new(task_id.as_str())),
            now_ms,
            &format!("action-{status}"),
            from_state,
            from_state,
            None,
            None,
            Some(id),
        )?;
        tx.commit()?;
        self.proposal_by_id(id)?
            .ok_or_else(|| TaskRepoError::NoSuchProposal(id.to_owned()))
    }

    /// Begins execution of an approved proposal: fresh lease, and back to `running`.
    ///
    /// This is Option C's transaction, and it is where the two properties the user
    /// separated come together:
    ///
    /// * **Fencing continuity, not lease reservation.** The wait released the lease; this
    ///   takes a *fresh* time-bounded one, so `limits.rs`'s "never a task held forever"
    ///   holds across an arbitrarily long human wait.
    /// * **The attempt does not advance.** `attempts` is deliberately untouched. A human
    ///   wait is not a retry — TP-6 requires a fresh approval after a retry, and the
    ///   whole point of binding the approval to this attempt is that it stays the same
    ///   attempt. Incrementing here would put the approval and the execution it
    ///   authorises on different attempt numbers.
    ///
    /// The worker named here gains **execution ownership and nothing else**. The proposer
    /// and approver come from the proposal and the approval respectively (V-71).
    ///
    /// # Errors
    ///
    /// [`TaskRepoError::NoSuchProposal`], [`TaskRepoError::ProposalNotInState`] if the
    /// proposal is not `approved` or the task is not `waiting-for-user`, or any SQLite
    /// error.
    pub fn begin_approved_execution(
        &mut self,
        id: &str,
        worker: &str,
        now_ms: i64,
        lease_ms: i64,
    ) -> Result<ProposalRow, TaskRepoError> {
        let tx = self.tx()?;
        let row: Option<(String, String, u32)> = tx
            .query_row(
                "SELECT task_id, status, attempt_no FROM task_proposals WHERE proposal_id = ?1;",
                rusqlite::params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u32)),
            )
            .optional()?;
        let Some((task_id, status, _attempt)) = row else {
            return Err(TaskRepoError::NoSuchProposal(id.to_owned()));
        };
        if status != "approved" {
            return Err(TaskRepoError::ProposalNotInState {
                id: id.to_owned(),
                status,
                expected: "approved",
            });
        }
        let task = TaskId::new(task_id.as_str());
        let from: String = tx.query_row(
            "SELECT state FROM tasks WHERE id = ?1;",
            rusqlite::params![task_id.as_str()],
            |r| r.get(0),
        )?;
        let state = TaskState::from_wire_str(&from).ok_or_else(|| {
            TaskRepoError::UnknownState(Box::new(UnknownStateDetail {
                id: task_id.clone(),
                raw: from.clone(),
            }))
        })?;
        if state != TaskState::WaitingForUser {
            return Err(TaskRepoError::ProposalNotInState {
                id: id.to_owned(),
                status: format!("task is {}", state.as_wire_str()),
                expected: "waiting-for-user",
            });
        }
        tx.execute(
            "UPDATE tasks
                SET state = 'running',
                    lease_holder = ?2,
                    lease_expires_at_ms = ?3,
                    updated_at_ms = ?4
              WHERE id = ?1 AND state = 'waiting-for-user';",
            rusqlite::params![
                task_id.as_str(),
                worker,
                now_ms.saturating_add(lease_ms),
                now_ms
            ],
        )?;
        log(
            &tx,
            Some(&task),
            now_ms,
            "approved-execution-begun",
            Some(state),
            Some(TaskState::Running),
            Some(worker),
            Some(_attempt),
            Some(id),
        )?;
        tx.commit()?;
        self.proposal_by_id(id)?
            .ok_or_else(|| TaskRepoError::NoSuchProposal(id.to_owned()))
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
    /// `TaskRepoError::CorruptRow` for a status outside the vocabulary. There is no
    /// `CorruptRow` variant; the error is reported as `TaskRepoError::Corrupt`.
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
        // An approval must speak for a step its task actually has. Checked before the
        // insert rather than trusted, because the digest binds the step: an approval for a
        // step the task does not have could never be honoured, and storing it would leave a
        // record that looks usable and is not.
        let max_steps: i64 = tx
            .query_row(
                "SELECT max_steps FROM tasks WHERE id = ?1;",
                rusqlite::params![approval.task_id.as_str()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| TaskRepoError::NotFound(approval.task_id.to_string()))?;
        validate_step_no(max_steps as u32, approval.step_no)
            .map_err(|e| TaskRepoError::InvalidComposition(Box::new(e)))?;

        let changed = tx.execute(
            "INSERT OR IGNORE INTO task_approvals
                (task_id, attempt_no, step_no, digest, capability, target, params,
                 issued_at_ms, expires_at_ms, consumed_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL);",
            rusqlite::params![
                approval.task_id.as_str(),
                approval.attempt_no,
                approval.step_no,
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
                "SELECT task_id, attempt_no, hex(digest), step_no, capability, target, params,
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
            "SELECT task_id, step_no, attempt_no, worker, started_at_ms, finished_at_ms,
                    outcome, error
               FROM task_attempts WHERE task_id = ?1 ORDER BY step_no, attempt_no;",
        )?;
        let rows = stmt.query_map([task_id.as_str()], |r| {
            Ok(TaskAttemptRow {
                task_id: TaskId::new(r.get::<_, String>(0)?),
                step_no: r.get(1)?,
                attempt_no: r.get(2)?,
                worker: r.get(3)?,
                started_at_ms: r.get(4)?,
                finished_at_ms: r.get(5)?,
                outcome: r.get(6)?,
                error: r.get(7)?,
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
    /// The logical step the attempt belongs to, 1-based.
    ///
    /// Distinct from `attempt_no`: a retried step keeps its step and advances its attempt,
    /// and a later step starts its attempt counting again.
    pub step_no: u32,
    /// Which attempt within that step, 1-based.
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
/// The column order is [`TASK_COLUMNS`], which is also the table's own order with
/// `payload` restored, so the indices below read left to right against that list.
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
    let schedule_raw: Option<String> = r.get(15)?;

    Ok(Ok(TaskRow {
        id: TaskId::new(id),
        kind,
        state,
        priority: r.get(3)?,
        payload: r.get(4)?,
        attempts: r.get(5)?,
        max_attempts: r.get(6)?,
        lease_expires_at_ms: r.get(7)?,
        lease_holder: r.get(8)?,
        idempotent: r.get::<_, i64>(9)? != 0,
        effect_observed: r.get::<_, i64>(10)? != 0,
        run_after_ms: r.get(11)?,
        catch_up: r.get::<_, i64>(12)? != 0,
        last_error: r.get(13)?,
        cancel_requested_at_ms: r.get(14)?,
        schedule_id: schedule_raw.map(ScheduleId::new),
        fire_time_ms: r.get(16)?,
        created_at_ms: r.get(17)?,
        updated_at_ms: r.get(18)?,
        dead_lettered_at_ms: r.get(19)?,
        terminal_at_ms: r.get(20)?,
        max_steps: r.get(21)?,
        steps_completed: r.get(22)?,
    }))
}

fn decode_step_result(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<StepResultRow, TaskRepoError>> {
    let id: String = r.get(0)?;
    let status_raw: String = r.get(2)?;
    let Some(status) = StepStatus::from_wire_str(&status_raw) else {
        return Ok(Err(TaskRepoError::Corrupt(Box::new(CorruptRowDetail {
            id,
            reason: format!("unrecognised step status {status_raw:?}"),
        }))));
    };
    Ok(Ok(StepResultRow {
        task_id: TaskId::new(r.get::<_, String>(0)?.as_str()),
        step_no: r.get::<_, i64>(1)? as u32,
        status,
        verification: r.get(3)?,
        structured_output: r.get(4)?,
        artifacts: r.get(5)?,
        recorded_at_ms: r.get(6)?,
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
        step_no: r.get(3)?,
        capability: r.get(4)?,
        target: r.get(5)?,
        params: r.get(6)?,
        issued_at_ms: r.get(7)?,
        expires_at_ms: r.get(8)?,
        consumed_at_ms: r.get(9)?,
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

    // ------------------------------------------------- targeted claim (V-57)
    //
    // The generic claim hands out whichever task the queue picks, which is right for
    // a worker pool and wrong for a caller that has already decided what it is
    // working on. These pin the targeted form to the *same* semantics as the generic
    // one: same lease, same attempt, same event, same fence.

    #[test]
    fn a_targeted_claim_takes_the_requested_task() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t1", TaskKind::Query);
        insert(&mut repo, "t2", TaskKind::Query);

        let TargetedClaimOutcome::Claimed(got) = repo
            .claim_specific(&tid("t2"), "w", NOW, LEASE)
            .expect("claim")
        else {
            panic!("a pending task must be claimable");
        };
        assert_eq!(
            got.row.id,
            tid("t2"),
            "the *requested* task, not another one"
        );
        assert_eq!(got.row.state, TaskState::Running);
        assert_eq!(got.row.lease_holder.as_deref(), Some("w"));
        assert_eq!(got.row.lease_expires_at_ms, Some(NOW + LEASE));
        assert_eq!(got.attempt_no, 1, "the first attempt opens as 1");
        assert_eq!(got.row.attempts, 1);

        // The task that was not asked for is untouched, and still claimable.
        let other = repo.get(&tid("t1")).expect("get").expect("present");
        assert_eq!(other.state, TaskState::Pending);
        assert!(other.lease_holder.is_none());
    }

    #[test]
    fn a_targeted_claim_records_the_same_event_the_generic_claim_does() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t1", TaskKind::Query);
        repo.claim_specific(&tid("t1"), "w", NOW, LEASE)
            .expect("claim");

        let events = repo.events_for(&tid("t1")).expect("events");
        let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["enqueued", "claimed"],
            "a targeted claim must leave the same trail, not a thinner one"
        );
        let claimed = &events[1];
        assert_eq!(claimed.from_state, Some(TaskState::Pending));
        assert_eq!(claimed.to_state, Some(TaskState::Running));
        assert_eq!(claimed.worker.as_deref(), Some("w"));
        assert_eq!(claimed.attempt_no, Some(1));

        // And it opened an attempt row, exactly as the generic path does.
        let attempts = repo.attempts_for(&tid("t1")).expect("attempts");
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].worker, "w");
    }

    #[test]
    fn a_targeted_claim_refuses_a_task_that_does_not_exist() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        let out = repo
            .claim_specific(&tid("absent"), "w", NOW, LEASE)
            .expect("claim");
        assert_eq!(out, TargetedClaimOutcome::Refused(ClaimRefusal::NotFound));
        assert_eq!(ClaimRefusal::NotFound.as_str(), "not-found");
    }

    #[test]
    fn a_targeted_claim_refuses_a_task_that_is_not_pending() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t1", TaskKind::Query);
        // Claim it once, so it is `running`.
        repo.claim_specific(&tid("t1"), "w1", NOW, LEASE)
            .expect("claim");

        // A second worker asking for the same task is refused, and specifically as
        // "not claimable" rather than "not found": the distinction is what tells a
        // client it lost a race rather than named a task that never existed.
        let out = repo
            .claim_specific(&tid("t1"), "w2", NOW, LEASE)
            .expect("claim");
        assert_eq!(out, TargetedClaimOutcome::Refused(ClaimRefusal::NotPending));
        assert_eq!(ClaimRefusal::NotPending.as_str(), "not-claimable");
    }

    #[test]
    fn a_targeted_claim_refuses_a_task_that_is_not_yet_runnable() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        let mut task = NewTask::new(tid("t1"), TaskKind::Query, NOW);
        task.run_after_ms = NOW + 1_000;
        repo.insert(&task, NOW).expect("insert");

        let out = repo
            .claim_specific(&tid("t1"), "w", NOW, LEASE)
            .expect("claim");
        assert_eq!(
            out,
            TargetedClaimOutcome::Refused(ClaimRefusal::NotYetRunnable)
        );

        // Once it is due, the same call succeeds.
        let later = NOW + 1_000;
        assert!(matches!(
            repo.claim_specific(&tid("t1"), "w", later, LEASE)
                .expect("claim"),
            TargetedClaimOutcome::Claimed(_)
        ));
    }

    #[test]
    fn a_targeted_claim_reports_an_exhausted_budget_without_dead_lettering() {
        // Reaching "pending with the budget spent" through the public API is not
        // possible: `complete_with` escalates to `dead-lettered` rather than
        // requeueing an over-budget task, and so does `recover`. So the row is built
        // with SQL here. That makes this a test of a *defensive* branch — it proves
        // that if some other writer ever produces that state, a targeted claim says
        // so precisely and, above all, does not destroy the row on its way past.
        let mut c = mem();
        insert_raw(&mut c, "t1", TaskKind::Query);
        c.execute(
            "UPDATE tasks SET state = 'pending', attempts = max_attempts WHERE id = 't1';",
            [],
        )
        .expect("force the state");

        let mut repo = TaskRepository::new(&mut c);
        let out = repo
            .claim_specific(&tid("t1"), "w", NOW, LEASE)
            .expect("claim");
        assert_eq!(
            out,
            TargetedClaimOutcome::Refused(ClaimRefusal::RetriesExhausted)
        );
        assert_eq!(ClaimRefusal::RetriesExhausted.as_str(), "retries-exhausted");

        // The refusal must not have destroyed the row: dead-lettering is the generic
        // pass's job, and a targeted request that merely asked must not escalate it.
        let row = repo.get(&tid("t1")).expect("get").expect("present");
        assert_eq!(row.state, TaskState::Pending);
        assert!(row.dead_lettered_at_ms.is_none());
    }

    #[test]
    fn a_budgeted_failure_requeues_so_the_next_claim_can_retry() {
        // The counterpart to the test above, and the reachable path: a `Failed`
        // outcome while the budget still holds puts the task back in the queue, which
        // is what makes the targeted claim retryable rather than one-shot.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        let mut task = NewTask::new(tid("t1"), TaskKind::Query, NOW);
        task.max_attempts = 2;
        repo.insert(&task, NOW).expect("insert");

        let TargetedClaimOutcome::Claimed(first) = repo
            .claim_specific(&tid("t1"), "w1", NOW, LEASE)
            .expect("claim")
        else {
            panic!("a pending task must be claimable");
        };
        assert_eq!(first.attempt_no, 1);
        assert!(
            repo.complete(
                &tid("t1"),
                "w1",
                NOW,
                TaskState::Failed,
                false,
                Some("boom")
            )
            .expect("complete"),
            "the fence should accept this completion"
        );

        let row = repo.get(&tid("t1")).expect("get").expect("present");
        assert_eq!(row.state, TaskState::Pending, "a budgeted failure requeues");

        let TargetedClaimOutcome::Claimed(second) = repo
            .claim_specific(&tid("t1"), "w2", NOW + 1, LEASE)
            .expect("claim")
        else {
            panic!("the requeued task must be claimable again");
        };
        assert_eq!(second.attempt_no, 2, "the retry is the second attempt");
        assert!(
            repo.complete(&tid("t1"), "w2", NOW + 2, TaskState::Completed, true, None)
                .expect("complete"),
            "the retry's holder completes"
        );
    }

    #[test]
    fn a_completed_task_cannot_be_claimed_targeted() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t1", TaskKind::Query);
        repo.claim_specific(&tid("t1"), "w", NOW, LEASE)
            .expect("claim");
        assert!(
            repo.complete(&tid("t1"), "w", NOW, TaskState::Completed, true, None)
                .expect("complete"),
            "the fence should accept this completion"
        );
        let out = repo
            .claim_specific(&tid("t1"), "w", NOW, LEASE)
            .expect("claim");
        assert_eq!(out, TargetedClaimOutcome::Refused(ClaimRefusal::NotPending));
    }

    #[test]
    fn a_targeted_lease_completes_only_for_its_holder_and_only_while_live() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t1", TaskKind::Query);
        repo.claim_specific(&tid("t1"), "holder", NOW, LEASE)
            .expect("claim");

        // A different worker cannot commit somebody else's work (TP-5).
        assert!(
            !repo
                .complete(
                    &tid("t1"),
                    "intruder",
                    NOW,
                    TaskState::Completed,
                    true,
                    None
                )
                .expect("complete"),
            "a worker without the lease must be fenced out"
        );

        // An expired lease cannot either, however it was obtained.
        let expired = NOW + LEASE;
        assert!(
            !repo
                .complete(
                    &tid("t1"),
                    "holder",
                    expired,
                    TaskState::Completed,
                    true,
                    None
                )
                .expect("complete"),
            "an expired lease must be fenced out"
        );

        // Still `running`: no refusal above moved the state.
        let row = repo.get(&tid("t1")).expect("get").expect("present");
        assert_eq!(row.state, TaskState::Running);

        // The holder, inside its lease, commits.
        assert!(
            repo.complete(
                &tid("t1"),
                "holder",
                NOW + 1,
                TaskState::Completed,
                true,
                None
            )
            .expect("complete"),
            "the holder must be able to complete inside its own lease"
        );
        let row = repo.get(&tid("t1")).expect("get").expect("present");
        assert_eq!(row.state, TaskState::Completed);
    }

    #[test]
    fn recovery_after_a_targeted_claim_reclaims_it_as_before() {
        let mut c = mem();
        insert_raw(&mut c, "t1", TaskKind::Query);
        let mut repo = TaskRepository::new(&mut c);
        repo.claim_specific(&tid("t1"), "w", NOW, LEASE)
            .expect("claim");

        // Recovery is what a restart does, and it must treat a targeted claim
        // exactly like a generic one: the lease is orphaned, so the task is pending
        // again.
        assert_eq!(repo.recover(NOW + 1).expect("recover"), 1);
        let row = repo.get(&tid("t1")).expect("get").expect("present");
        assert_eq!(row.state, TaskState::Pending);
        assert!(row.lease_holder.is_none());

        // And the reopened task can be claimed and completed normally.
        let TargetedClaimOutcome::Claimed(got) = repo
            .claim_specific(&tid("t1"), "w2", NOW + 2, LEASE)
            .expect("claim")
        else {
            panic!("the recovered task must be claimable again");
        };
        assert_eq!(got.attempt_no, 2, "recovery does not refund the attempt");
        assert!(
            repo.complete(&tid("t1"), "w2", NOW + 3, TaskState::Completed, true, None)
                .expect("complete"),
            "the second holder must be able to complete"
        );
    }

    #[test]
    fn the_generic_claim_is_unchanged_by_the_targeted_one() {
        // The targeted path shares its machinery with the generic path; this is what
        // stops that sharing from having quietly changed the generic behaviour.
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t1", TaskKind::Query);

        let ClaimOutcome::Claimed(got) = repo.claim("w", NOW, LEASE).expect("claim") else {
            panic!("one pending task must be claimable");
        };
        assert_eq!(got.row.id, tid("t1"));
        assert_eq!(got.attempt_no, 1);

        // An empty queue still reports Empty, and still dead-letters a stranded task
        // on the way past.
        assert_eq!(
            repo.claim("w", NOW, LEASE).expect("claim"),
            ClaimOutcome::Empty
        );
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
            step_no: 1,
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

/// Stage 3b: the repository side of bounded linear composition.
///
/// Nothing here advances a task. These tests exist to prove that the storage primitives
/// are trustworthy *before* the execution path is allowed to write through them: a step
/// result is one row per logical step however many attempts it took, a step number is
/// checked against the task's own `max_steps` rather than trusted, and the composition
/// counters refuse impossible values instead of clamping them.
#[cfg(test)]
mod composition_tests {
    use super::*;
    use crate::migration::{MIGRATIONS, MigrationRunner};
    use crate::pragma::Pragma;

    const NOW: i64 = 1_767_225_600_000;

    /// A fully migrated in-memory connection, like the sibling repository tests use.
    fn mem() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        MigrationRunner::new(&c).run(true).expect("migrate");
        c
    }

    fn tid(s: &str) -> TaskId {
        TaskId::new(s)
    }

    /// A database stopped at `version`, so migration 8 can be observed doing its work.
    /// A database built forwards and stopped at `version`, so the later migrations can be
    /// observed doing their work.
    ///
    /// Forward-only on purpose: a migration can only be *applied*, so a database already at
    /// the current version cannot be turned back into an older one. Starting from a blank
    /// connection is the only faithful way to stand where an older build stood.
    fn mem_at(version: u32) -> Connection {
        let c = Connection::open_in_memory().expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        for m in MIGRATIONS.iter().filter(|m| m.version <= version) {
            c.execute_batch(m.sql.as_ref()).expect("apply migration");
            c.execute(
                "INSERT INTO schema_meta (version, name, applied_at) VALUES (?1, ?2, 0);",
                rusqlite::params![m.version, m.name],
            )
            .expect("record migration");
        }
        c
    }

    fn insert(repo: &mut TaskRepository<'_>, id: &str) {
        repo.insert(&NewTask::new(tid(id), TaskKind::Workflow, NOW), NOW)
            .expect("insert");
    }

    /// A task whose composition bounds are set directly, because the repository has no
    /// counter write path yet: advancing `steps_completed` is Stage 3c's job and this
    /// stage must not add one.
    fn set_bounds(c: &mut Connection, id: &str, max_steps: u32, steps_completed: u32) {
        c.execute(
            "UPDATE tasks SET max_steps = ?2, steps_completed = ?3 WHERE id = ?1;",
            rusqlite::params![id, max_steps, steps_completed],
        )
        .expect("set bounds");
    }

    /// A connection holding one task with the given composition bounds, and nothing
    /// borrowed, so the caller can take a repository afterwards.
    ///
    /// The bounds are written straight to the row because the repository has no counter
    /// write path in this stage: advancing `steps_completed` is Stage 3c's job.
    fn mem_task(max_steps: u32, steps_completed: u32) -> Connection {
        let mut c = mem();
        {
            let mut repo = TaskRepository::new(&mut c);
            repo.insert(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
                .expect("insert");
        }
        set_bounds(&mut c, "t", max_steps, steps_completed);
        c
    }

    fn result(task: &str, step: u32) -> StepResultRow {
        StepResultRow {
            task_id: tid(task),
            step_no: step,
            status: StepStatus::Verified,
            verification: Some("{\"checked\":true}".into()),
            structured_output: Some("{\"lines\":1}".into()),
            artifacts: Some("[\"a.txt\"]".into()),
            recorded_at_ms: NOW,
        }
    }

    // ------------------------------------------------ step-result repository

    #[test]
    fn a_step_result_round_trips() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t");
        repo.record_step_result(&result("t", 1)).expect("record");

        let got = repo
            .step_result(&tid("t"), 1)
            .expect("read")
            .expect("present");
        assert_eq!(got.step_no, 1);
        assert_eq!(got.task_id, tid("t"));
        assert_eq!(got.status, StepStatus::Verified);
        assert!(repo.step_result_exists(&tid("t"), 1).expect("exists"));
    }

    /// One logical step, one final result -- however many attempts it took.
    #[test]
    fn a_second_final_result_for_the_same_step_is_refused() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t");
        repo.record_step_result(&result("t", 1)).expect("first");

        let second = repo.record_step_result(&result("t", 1));
        assert!(
            matches!(second, Err(TaskRepoError::AlreadyExists(_))),
            "a step cannot have two final results, got {second:?}"
        );
        // And the first result is untouched rather than overwritten.
        assert!(repo.step_result_exists(&tid("t"), 1).expect("exists"));
    }

    #[test]
    fn different_tasks_may_use_the_same_step_number() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "a");
        insert(&mut repo, "b");
        repo.record_step_result(&result("a", 1)).expect("a");
        repo.record_step_result(&result("b", 1)).expect("b");
        assert!(repo.step_result_exists(&tid("a"), 1).expect("a"));
        assert!(repo.step_result_exists(&tid("b"), 1).expect("b"));
    }

    #[test]
    fn one_task_may_hold_several_step_results() {
        let mut c = mem_task(3, 0);
        let mut repo = TaskRepository::new(&mut c);
        for step in 1..=3 {
            repo.record_step_result(&result("t", step)).expect("record");
        }
        let all = repo.step_results_for(&tid("t")).expect("all");
        assert_eq!(
            all.iter().map(|r| r.step_no).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "results come back in step order"
        );
    }

    /// Attempts are not steps. A step that failed twice and verified on the third attempt
    /// still has exactly one result row, and nothing forces one per attempt.
    #[test]
    fn attempts_do_not_require_step_result_rows() {
        let mut c = mem_task(1, 0);
        let mut repo = TaskRepository::new(&mut c);

        // Three attempts, no result rows at all: the step has not concluded.
        assert!(!repo.step_result_exists(&tid("t"), 1).expect("exists"));
        assert!(repo.step_results_for(&tid("t")).expect("all").is_empty());

        // The concluding attempt writes exactly one.
        repo.record_step_result(&result("t", 1)).expect("record");
        assert_eq!(repo.step_results_for(&tid("t")).expect("all").len(), 1);
    }

    /// `task_step_results` records what happened and authorises nothing.
    ///
    /// Checked against the table itself rather than the Rust struct, because the struct
    /// cannot reveal a column the repository does not select.
    #[test]
    fn a_step_result_row_carries_only_observational_fields() {
        let c = mem();
        let columns: Vec<String> = c
            .prepare("SELECT name FROM pragma_table_info('task_step_results')")
            .expect("pragma")
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect();

        assert_eq!(
            columns,
            vec![
                "task_id",
                "step_no",
                "status",
                "verification",
                "structured_output",
                "artifacts",
                "recorded_at_ms",
            ],
            "the observable shape changed: {columns:?}"
        );
        for forbidden in [
            "worker",
            "lease",
            "lease_expires_at_ms",
            "lease_holder",
            "digest",
            "approval",
            "approver",
            "authority_root",
            "actor",
            "actor_label",
            "proposal_id",
            "attempt_no",
        ] {
            assert!(
                !columns.iter().any(|c| c == forbidden),
                "a step result must not carry {forbidden}: {columns:?}"
            );
        }
    }

    #[test]
    fn a_step_result_round_trips_its_payload_exactly() {
        let mut c = mem_task(4, 0);
        let mut repo = TaskRepository::new(&mut c);

        // Absent fields stay absent rather than becoming empty strings.
        let bare = StepResultRow {
            task_id: tid("t"),
            step_no: 1,
            status: StepStatus::Failed,
            verification: None,
            structured_output: None,
            artifacts: None,
            recorded_at_ms: NOW,
        };
        repo.record_step_result(&bare).expect("record");
        let got = repo
            .step_result(&tid("t"), 1)
            .expect("read")
            .expect("present");
        assert_eq!(got.status, StepStatus::Failed);
        assert_eq!(got.verification, None);
        assert_eq!(got.structured_output, None);
        assert_eq!(got.artifacts, None);

        // Every status the schema admits survives the round trip, and payloads that look
        // like JSON are not reformatted on the way through.
        for (step, status) in [
            (2, StepStatus::Verified),
            (3, StepStatus::Refuted),
            (4, StepStatus::Undetermined),
        ] {
            let exact = r#"{"a":[1,2,{"b":"}"}],"c":"  spaced  "}"#.to_owned();
            repo.record_step_result(&StepResultRow {
                task_id: tid("t"),
                step_no: step,
                status,
                verification: Some(exact.clone()),
                structured_output: Some(exact.clone()),
                artifacts: Some(exact.clone()),
                recorded_at_ms: NOW + i64::from(step),
            })
            .expect("record");
            let got = repo
                .step_result(&tid("t"), step)
                .expect("read")
                .expect("present");
            assert_eq!(got.status, status);
            assert_eq!(got.verification.as_deref(), Some(exact.as_str()));
            assert_eq!(got.structured_output.as_deref(), Some(exact.as_str()));
            assert_eq!(got.artifacts.as_deref(), Some(exact.as_str()));
            assert_eq!(got.recorded_at_ms, NOW + i64::from(step));
        }
    }

    #[test]
    fn an_unknown_status_is_refused_rather_than_stored() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t");
        let bad = c.execute(
            "INSERT INTO task_step_results
                (task_id, step_no, status, recorded_at_ms) VALUES ('t', 1, 'invented', 1);",
            [],
        );
        assert!(bad.is_err(), "the schema must refuse an unknown status");
    }

    // ---------------------------------- proposal / approval step persistence

    #[test]
    fn a_proposal_round_trips_its_step() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t");
        let row = claim_and_propose(&mut repo, "t", "w", "p1");
        assert_eq!(row.step_no, 1, "the repository writes the step explicitly");

        let read = repo.proposal_by_id("p1").expect("read").expect("present");
        assert_eq!(read.step_no, 1);
        assert_eq!(read.attempt_no, row.attempt_no);
    }

    #[test]
    fn an_approval_round_trips_its_step() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t");
        repo.record_approval(&ApprovalRow {
            task_id: tid("t"),
            attempt_no: 1,
            step_no: 1,
            digest_hex: "ab".repeat(32),
            capability: "filesystem/write-text".into(),
            target: Some("a.txt".into()),
            params: "{}".into(),
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60_000,
            consumed_at_ms: None,
        })
        .expect("record");

        let read = repo
            .approval_for_attempt(&tid("t"), 1)
            .expect("read")
            .expect("present");
        assert_eq!(read.step_no, 1);
        assert_eq!(read.attempt_no, 1);
    }

    /// A retried step holds its step number and advances its attempt number. The two are
    /// not interchangeable, and conflating them would invent a multi-step history.
    #[test]
    fn several_attempts_may_share_one_step_number() {
        let mut c = mem();
        let first = {
            let mut repo = TaskRepository::new(&mut c);
            insert(&mut repo, "t");
            claim_and_propose(&mut repo, "t", "w", "p1")
        };
        assert_eq!((first.step_no, first.attempt_no), (1, 1));

        // The attempt is abandoned and the task is claimed again, which is what a retry looks
        // like from the store's side. The release is written directly because a schema CHECK
        // ties `lease_holder` and `lease_expires_at_ms` together, and hand-editing one without
        // the other is exactly the shortcut that hides a real constraint.
        c.execute(
            "UPDATE tasks SET state = 'pending', lease_holder = NULL,
                            lease_expires_at_ms = NULL WHERE id = 't';",
            [],
        )
        .expect("release for retry");

        let second = claim_and_propose(&mut TaskRepository::new(&mut c), "t", "w", "p2");

        assert_eq!(
            (second.step_no, second.attempt_no),
            (1, 2),
            "the retry stays on step 1 while its attempt advances"
        );
        let repo = TaskRepository::new(&mut c);
        for id in ["p1", "p2"] {
            let row = repo.proposal_by_id(id).expect("read").expect("present");
            assert_eq!(row.step_no, 1, "{id} must stay on step 1");
        }
        assert_ne!(first.attempt_no, second.attempt_no);
    }

    #[test]
    fn associating_a_step_leaves_the_attempt_number_alone() {
        let mut c = mem();
        {
            let mut repo = TaskRepository::new(&mut c);
            insert(&mut repo, "t");
            let row = claim_and_propose(&mut repo, "t", "w", "p1");
            assert_eq!(row.attempt_no, 1);
        }
        let before: i64 = c
            .query_row("SELECT attempts FROM tasks WHERE id = 't';", [], |r| {
                r.get(0)
            })
            .expect("attempts");

        // Reading the proposal back is the operation that reports which step it belongs to,
        // and it must leave the attempt count alone. The repository borrows the connection
        // exclusively, so it is scoped and the count is read straight from the row.
        let read = TaskRepository::new(&mut c)
            .proposal_by_id("p1")
            .expect("read")
            .expect("present");
        assert_eq!(read.step_no, 1);
        assert_eq!(read.attempt_no, 1);

        let after: i64 = c
            .query_row("SELECT attempts FROM tasks WHERE id = 't';", [], |r| {
                r.get(0)
            })
            .expect("attempts");
        assert_eq!(
            before, after,
            "associating a step must not touch the attempt count"
        );
    }

    // ------------------------------------------------- counter invariants

    #[test]
    fn max_steps_of_one_is_accepted() {
        assert!(validate_max_steps(1).is_ok());
    }

    /// `max_steps = 0` would mean a task with no steps, which cannot complete.
    #[test]
    fn max_steps_below_one_is_refused() {
        let e = validate_max_steps(0).expect_err("zero must be refused");
        assert_eq!(e.field, "max_steps");
        // u32 is the storage type, so a negative is not representable to test; the
        // refusal is of the only value below the bound that the type admits.
        assert!(e.to_string().contains("max_steps"));
    }

    #[test]
    fn zero_steps_completed_is_accepted() {
        assert!(validate_steps_completed(3, 0).is_ok());
    }

    #[test]
    fn steps_completed_equal_to_max_steps_is_accepted() {
        assert!(validate_steps_completed(3, 3).is_ok());
        assert!(validate_steps_completed(1, 1).is_ok());
    }

    #[test]
    fn steps_completed_beyond_max_steps_is_refused() {
        let e = validate_steps_completed(2, 3).expect_err("over-count must be refused");
        assert_eq!(e.field, "steps_completed");
    }

    /// Both the bound and the counter are checked, so a bad `max_steps` is caught even
    /// when `steps_completed` happens to be consistent with it.
    #[test]
    fn an_invalid_max_steps_is_refused_even_with_a_consistent_counter() {
        assert!(validate_steps_completed(0, 0).is_err());
        assert!(validate_steps_completed(0, 1).is_err());
    }

    #[test]
    fn step_one_is_accepted_when_max_steps_is_one() {
        assert!(validate_step_no(1, 1).is_ok());
    }

    #[test]
    fn step_equal_to_max_steps_is_accepted() {
        assert!(validate_step_no(4, 4).is_ok());
        assert!(validate_step_no(4, 1).is_ok());
    }

    /// Steps are 1-based. Zero is not a step, and must not be quietly read as the first.
    #[test]
    fn step_zero_is_refused() {
        let e = validate_step_no(3, 0).expect_err("zero must be refused");
        assert_eq!(e.field, "step_no");
    }

    #[test]
    fn a_step_beyond_max_steps_is_refused() {
        let e = validate_step_no(2, 3).expect_err("past the end must be refused");
        assert_eq!(e.field, "step_no");
    }

    // ------------------------------------------- the write paths use them

    #[test]
    fn recording_a_step_result_beyond_max_steps_is_refused() {
        let mut c = mem_task(2, 0);
        let mut repo = TaskRepository::new(&mut c);

        let out = repo.record_step_result(&result("t", 3));
        assert!(
            matches!(out, Err(TaskRepoError::InvalidComposition(_))),
            "step 3 of a 2-step task must be refused, got {out:?}"
        );
        assert!(!repo.step_result_exists(&tid("t"), 3).expect("exists"));
    }

    #[test]
    fn recording_a_step_result_for_step_zero_is_refused() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        insert(&mut repo, "t");
        let out = repo.record_step_result(&result("t", 0));
        assert!(
            matches!(out, Err(TaskRepoError::InvalidComposition(_))),
            "step 0 must be refused, got {out:?}"
        );
    }

    #[test]
    fn a_step_result_for_an_absent_task_is_refused() {
        let mut c = mem();
        let mut repo = TaskRepository::new(&mut c);
        let out = repo.record_step_result(&result("ghost", 1));
        assert!(
            matches!(out, Err(TaskRepoError::NotFound(_))),
            "a result cannot outlive the task it describes, got {out:?}"
        );
    }

    /// Recording a result must not move the counter. Advancement is Stage 3c's, and a
    /// repository that incremented here would let an insert stand in for a verification.
    #[test]
    fn recording_a_step_result_does_not_advance_steps_completed() {
        let mut c = mem_task(3, 0);
        let mut repo = TaskRepository::new(&mut c);
        repo.record_step_result(&result("t", 1)).expect("record");

        let row = repo.get(&tid("t")).expect("get").expect("present");
        assert_eq!(row.steps_completed, 0, "the counter belongs to Stage 3c");
        assert_eq!(row.max_steps, 3);
    }

    #[test]
    fn a_proposal_for_a_task_with_impossible_bounds_is_refused() {
        // A task whose own bounds are corrupt must not yield a proposal either. `max_steps`
        // is NOT NULL with no CHECK, so the row can hold 0; the repository is what refuses.
        let mut c = mem_task(0, 0);
        let mut repo = TaskRepository::new(&mut c);
        let out = claim_and_propose_result(&mut repo, "t", "w", "p1");
        assert!(
            matches!(out, Err(TaskRepoError::InvalidComposition(_))),
            "a task with max_steps=0 cannot have a step, got {out:?}"
        );
    }

    #[test]
    fn an_approval_beyond_max_steps_is_refused() {
        let mut c = mem_task(1, 0);
        let mut repo = TaskRepository::new(&mut c);
        let out = repo.record_approval(&ApprovalRow {
            task_id: tid("t"),
            attempt_no: 1,
            step_no: 2,
            digest_hex: "ab".repeat(32),
            capability: "filesystem/write-text".into(),
            target: Some("a.txt".into()),
            params: "{}".into(),
            issued_at_ms: NOW,
            expires_at_ms: NOW + 60_000,
            consumed_at_ms: None,
        });
        assert!(
            matches!(out, Err(TaskRepoError::InvalidComposition(_))),
            "an approval cannot authorise a step the task does not have, got {out:?}"
        );
    }

    // ------------------------------------------------ legacy compatibility

    #[test]
    fn a_migrated_completed_task_is_one_step_of_one_done() {
        let mut c = legacy_db();
        migrate_to_current(&c);
        let repo = TaskRepository::new(&mut c);
        let row = repo.get(&tid("retried")).expect("get").expect("present");
        assert_eq!(
            (row.max_steps, row.steps_completed),
            (1, 1),
            "a finished legacy task is 1 of 1, whatever its retries"
        );
        assert_eq!(
            row.attempts, 3,
            "the retry count is a record of what happened and must survive untouched"
        );
    }

    #[test]
    fn a_migrated_unfinished_task_has_done_nothing() {
        let mut c = legacy_db();
        migrate_to_current(&c);
        let repo = TaskRepository::new(&mut c);
        let row = repo.get(&tid("open")).expect("get").expect("present");
        assert_eq!(
            (row.max_steps, row.steps_completed),
            (1, 0),
            "an unfinished legacy task completed no steps"
        );
        assert_eq!(row.attempts, 2);
    }

    #[test]
    fn historical_proposals_and_approvals_stay_on_step_one_with_their_attempts() {
        let mut c = legacy_db();
        migrate_to_current(&c);
        let repo = TaskRepository::new(&mut c);
        for attempt in 1..=3u32 {
            let p = repo
                .proposal_by_id(&format!("p-retried-{attempt}"))
                .expect("read")
                .expect("present");
            assert_eq!(
                (p.step_no, p.attempt_no),
                (1, attempt),
                "attempt {attempt} is a retry of step 1, not a later step"
            );
            let a = repo
                .approval_for_attempt(&tid("retried"), attempt)
                .expect("read")
                .expect("present");
            assert_eq!((a.step_no, a.attempt_no), (1, attempt));
        }
    }

    /// A new install and an upgraded one must not differ in what the repository accepts.
    #[test]
    fn a_fresh_and_a_migrated_database_behave_identically() {
        let mut fresh = mem();
        let mut migrated = legacy_db();
        migrate_to_current(&migrated);

        for c in [&mut fresh, &mut migrated] {
            let mut repo = TaskRepository::new(&mut *c);
            repo.insert(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
                .expect("insert");
            assert!(repo.record_step_result(&result("t", 1)).is_ok());
            assert!(repo.record_step_result(&result("t", 1)).is_err());
            assert!(matches!(
                repo.record_step_result(&result("t", 99)),
                Err(TaskRepoError::InvalidComposition(_))
            ));
            let row = repo.get(&tid("t")).expect("get").expect("present");
            assert_eq!((row.max_steps, row.steps_completed), (1, 0));
        }
    }

    // ------------------------------------------------------------ helpers

    fn claim_and_propose(
        repo: &mut TaskRepository<'_>,
        task: &str,
        worker: &str,
        proposal_id: &str,
    ) -> ProposalRow {
        claim_and_propose_result(repo, task, worker, proposal_id).expect("propose")
    }

    fn claim_and_propose_result(
        repo: &mut TaskRepository<'_>,
        task: &str,
        worker: &str,
        proposal_id: &str,
    ) -> Result<ProposalRow, TaskRepoError> {
        repo.claim_specific(&tid(task), worker, NOW, NOW + 60_000)
            .expect("claim");
        repo.propose_action(
            proposal_id,
            &tid(task),
            worker,
            "filesystem/write-text",
            Some("a.txt"),
            "{}",
            "{}",
            None,
            1,
            NOW,
        )
    }

    /// A database at version 6 holding rows that predate composition entirely.
    fn legacy_db() -> Connection {
        let c = mem_at(6);
        let seed = |id: &str, state: &str, attempts: i64| {
            c.execute(
                "INSERT INTO tasks (id,kind,state,idempotent,attempts,max_attempts,
                                   created_at_ms,updated_at_ms)
                 VALUES (?1,'workflow',?2,0,?3,9,1,1);",
                rusqlite::params![id, state, attempts],
            )
            .expect("task");
            for attempt in 1..=attempts {
                c.execute(
                    "INSERT INTO task_proposals (proposal_id,task_id,attempt_no,capability,
                                                 target,params,proposer,created_at_ms,status)
                     VALUES (?1,?2,?3,'filesystem/write-text','a.txt','{}','{}',1,'approved');",
                    rusqlite::params![format!("p-{id}-{attempt}"), id, attempt],
                )
                .expect("proposal");
                c.execute(
                    "INSERT INTO task_approvals (task_id,attempt_no,digest,capability,target,
                                                 params,issued_at_ms,expires_at_ms)
                     VALUES (?1,?2,?3,'filesystem/write-text','a.txt','{}',1,2);",
                    rusqlite::params![id, attempt, vec![attempt as u8; 8]],
                )
                .expect("approval");
            }
        };
        seed("retried", "completed", 3);
        seed("single", "completed", 1);
        seed("open", "running", 2);
        c
    }

    fn migrate_to_current(c: &Connection) {
        let target = MIGRATIONS.iter().map(|m| m.version).max().unwrap_or(0);
        let applied: u32 = c
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_meta;",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        for m in MIGRATIONS
            .iter()
            .filter(|m| m.version <= target && m.version > applied)
        {
            c.execute_batch(m.sql.as_ref()).expect("apply migration");
            c.execute(
                "INSERT INTO schema_meta (version, name, applied_at) VALUES (?1, ?2, 0);",
                rusqlite::params![m.version, m.name],
            )
            .expect("record migration");
        }
    }
}

/// Stage 3c: the post-verification step-advancement transaction.
///
/// Everything asserted here is asserted about **one** transaction: a verified step either
/// leaves a durable result, a counter advanced by exactly one, a state that agrees with
/// both, and a released lease -- or it leaves all four as they were. The failure cases are
/// the interesting half, because the states that must never exist are the ones nothing
/// fails loudly about: a result with no counter, a counter with no result, and a terminal
/// task whose last step is unrecorded.
#[cfg(test)]
mod advancement_tests {
    use super::*;
    use crate::migration::MigrationRunner;
    use crate::pragma::Pragma;

    const NOW: i64 = 1_767_225_600_000;
    const LEASE: i64 = 60_000;

    fn mem() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        MigrationRunner::new(&c).run(true).expect("migrate");
        c
    }

    fn tid(s: &str) -> TaskId {
        TaskId::new(s)
    }

    /// A database holding one task with the given bounds and nothing borrowed.
    fn mem_task(max_steps: u32) -> Connection {
        let mut c = mem();
        {
            let mut repo = TaskRepository::new(&mut c);
            repo.insert(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
                .expect("insert");
        }
        c.execute(
            "UPDATE tasks SET max_steps = ?1, steps_completed = 0 WHERE id = 't';",
            rusqlite::params![max_steps],
        )
        .expect("set bounds");
        c
    }

    /// Claim the task and propose the step a worker is currently on, which is what the
    /// runtime does before dispatching. `step` is what the caller believes it is running;
    /// the repository validates it rather than believing it.
    fn start_step(c: &mut Connection, step: u32, attempt_proposal: &str) -> ProposalRow {
        let mut repo = TaskRepository::new(&mut *c);
        repo.claim_specific(&tid("t"), "w", NOW, NOW + LEASE)
            .expect("claim");
        propose_and_resume(repo, step, attempt_proposal)
    }

    /// The second half of starting a step: propose, approve, and take the execution lease.
    ///
    /// Separate from the claim so the next-step path can supply its own claim and still
    /// drive an identical proposal/execution sequence.
    fn propose_and_resume(
        mut repo: TaskRepository<'_>,
        step: u32,
        attempt_proposal: &str,
    ) -> ProposalRow {
        repo.propose_action(
            attempt_proposal,
            &tid("t"),
            "w",
            "filesystem/write-text",
            Some("a.txt"),
            "{}",
            "{}",
            None,
            step,
            NOW,
        )
        .expect("propose");
        // Proposing parks the task in `waiting-for-user`; approval and resuming are what put
        // it back to `running` under a fresh execution lease. Driving the real path rather
        // than writing the state directly means these tests exercise the same sequence the
        // runtime does.
        repo.decide_proposal(attempt_proposal, "approved", NOW)
            .expect("approve");
        repo.begin_approved_execution(attempt_proposal, "w", NOW, LEASE)
            .expect("resume")
    }

    fn verified(step: u32, proposal_id: &str) -> VerifiedStep<'_> {
        VerifiedStep {
            task_id: tid("t"),
            worker: "w",
            step_no: step,
            proposal_id,
            status: StepStatus::Verified,
            verification: Some("{\"checked\":true}".into()),
            structured_output: Some("{\"lines\":1}".into()),
            artifacts: Some("[\"a.txt\"]".into()),
            recorded_at_ms: NOW,
        }
    }

    /// The task row's state, step counters and lease holder, read together.
    fn state_of(c: &Connection) -> (String, u32, u32, Option<String>) {
        c.query_row(
            "SELECT state, steps_completed, max_steps, lease_holder FROM tasks WHERE id = 't';",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get::<_, i64>(1)? as u32,
                    r.get::<_, i64>(2)? as u32,
                    r.get(3)?,
                ))
            },
        )
        .expect("row")
    }

    /// A task left `running` with a live lease, having proposed `step`.
    fn running_on(c: &mut Connection, step: u32, proposal_id: &str) -> ProposalRow {
        start_step(c, step, proposal_id)
    }

    /// Claim the next logical step for real, through the Stage-3d path.
    ///
    /// This used to write `state = 'pending'` by hand, because a boundary was unclaimable
    /// and multi-step tests had no other way through. With the claim implemented the
    /// stand-in is gone and these tests exercise the same operation production will.
    fn claim_next_step(c: &mut Connection, worker: &str, step: u32, proposal_id: &str) {
        assert!(
            matches!(
                TaskRepository::new(&mut *c).claim_next_step(&tid("t"), worker, NOW, LEASE),
                Ok(TargetedClaimOutcome::Claimed(_))
            ),
            "the boundary must be claimable now that Stage 3d exists"
        );
        // Claiming establishes the lease and nothing else, so the step's proposal follows
        // exactly as it did for step 1.
        propose_and_resume(TaskRepository::new(&mut *c), step, proposal_id);
    }

    // ------------------------------------------------- multi-step advancement

    #[test]
    fn a_verified_first_of_two_steps_waits_for_the_next() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        let out = TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("advance");
        assert_eq!(
            out.state,
            TaskState::AwaitingNextStep,
            "another logical step remains, so this is a boundary and not an ending"
        );
        assert_eq!(out.step_no, 1);
        assert_eq!(out.steps_completed, 1);
        assert_eq!(state_of(&c).0, "awaiting-next-step");
    }

    #[test]
    fn the_first_verified_step_advances_the_counter_by_exactly_one() {
        let mut c = mem_task(3);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("advance");
        assert_eq!(state_of(&c).1, 1, "not 0 and not 2");
    }

    #[test]
    fn a_verified_first_step_result_is_durable() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("advance");
        let row = TaskRepository::new(&mut c)
            .step_result(&tid("t"), 1)
            .expect("read")
            .expect("present");
        assert_eq!(row.status, StepStatus::Verified);
    }

    #[test]
    fn a_verified_second_step_completes_the_task() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("first");
        // The boundary released the lease, so the next step needs a fresh claim.
        claim_next_step(&mut c, "w", 2, "p2");
        let out = TaskRepository::new(&mut c)
            .complete_verified_step(&verified(2, "p2"))
            .expect("second");
        assert_eq!(out.state, TaskState::Completed);
        assert_eq!(out.step_no, 2);
        assert_eq!(out.steps_completed, 2);
        assert_eq!(state_of(&c).0, "completed");
    }

    #[test]
    fn two_logical_steps_produce_two_distinct_results() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("first");
        claim_next_step(&mut c, "w", 2, "p2");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(2, "p2"))
            .expect("second");

        let all = TaskRepository::new(&mut c)
            .step_results_for(&tid("t"))
            .expect("results");
        assert_eq!(
            all.iter().map(|r| r.step_no).collect::<Vec<_>>(),
            vec![1, 2],
            "one row per logical step, not per attempt and not one shared row"
        );
    }

    /// The next step is `steps_completed + 1`, and it is read from the durable counter
    /// rather than being carried in memory from the previous advancement.
    #[test]
    fn the_next_step_is_the_counter_plus_one() {
        let mut c = mem_task(3);
        assert_eq!(
            TaskRepository::new(&mut c)
                .next_step_no(&tid("t"))
                .expect("next"),
            1
        );
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("first");
        assert_eq!(
            TaskRepository::new(&mut c)
                .next_step_no(&tid("t"))
                .expect("next"),
            2
        );
        claim_next_step(&mut c, "w", 2, "p2");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(2, "p2"))
            .expect("second");
        assert_eq!(
            TaskRepository::new(&mut c)
                .next_step_no(&tid("t"))
                .expect("next"),
            3
        );
    }

    #[test]
    fn no_step_beyond_the_maximum_can_be_completed() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("first");
        claim_next_step(&mut c, "w", 2, "p2");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(2, "p2"))
            .expect("second");
        // The task is finished. A third step does not exist to be completed.
        assert_eq!(state_of(&c).1, 2);
        let out = TaskRepository::new(&mut c).complete_verified_step(&verified(3, "p3"));
        assert!(out.is_err(), "step 3 of 2 must be refused, got {out:?}");
    }

    /// A step number past `max_steps` is refused before anything is written, which is what
    /// stops a task growing an extra step by accident.
    #[test]
    fn a_proposal_for_a_step_past_the_maximum_is_refused() {
        let mut c = mem_task(2);
        let mut repo = TaskRepository::new(&mut c);
        repo.claim_specific(&tid("t"), "w", NOW, NOW + LEASE)
            .expect("claim");
        let out = repo.propose_action(
            "p9",
            &tid("t"),
            "w",
            "filesystem/write-text",
            Some("a.txt"),
            "{}",
            "{}",
            None,
            3,
            NOW,
        );
        assert!(
            matches!(out, Err(TaskRepoError::InvalidComposition(_))),
            "got {out:?}"
        );
    }

    // ------------------------------------------------------ failure semantics

    /// Nothing but a verified outcome may move the counter. A failure is not a step.
    #[test]
    fn a_failed_verification_does_not_advance() {
        for status in [
            StepStatus::Failed,
            StepStatus::Refuted,
            StepStatus::Undetermined,
        ] {
            let mut c = mem_task(2);
            running_on(&mut c, 1, "p1");
            let mut done = verified(1, "p1");
            done.status = status;
            let out = TaskRepository::new(&mut c).complete_verified_step(&done);
            assert!(out.is_err(), "{status:?} must not advance, got {out:?}");

            let (state, completed, _, _) = state_of(&c);
            assert_eq!(completed, 0, "{status:?} left the counter moved");
            assert_eq!(state, "running", "{status:?} ended the task");
            assert!(
                TaskRepository::new(&mut c)
                    .step_results_for(&tid("t"))
                    .expect("results")
                    .is_empty(),
                "{status:?} wrote a result row it should not have"
            );
        }
    }

    /// The lease is still held and the task still running after a failure, so the existing
    /// retry path can do its job untouched.
    #[test]
    fn a_failed_verification_leaves_the_lease_and_state_alone() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        let mut done = verified(1, "p1");
        done.status = StepStatus::Refuted;
        assert!(
            TaskRepository::new(&mut c)
                .complete_verified_step(&done)
                .is_err()
        );
        let (state, completed, _, holder) = state_of(&c);
        assert_eq!(state, "running");
        assert_eq!(completed, 0);
        assert_eq!(holder.as_deref(), Some("w"), "the retry needs its lease");
    }

    /// A retry is a new attempt on the *same* step: the counter does not move and the step
    /// number does not either.
    #[test]
    fn a_retry_stays_on_the_same_step() {
        let mut c = mem_task(2);
        let first = running_on(&mut c, 1, "p1");
        assert_eq!(first.step_no, 1);

        // Refuted, so no advancement; the attempt is abandoned and retried.
        let mut done = verified(1, "p1");
        done.status = StepStatus::Refuted;
        assert!(
            TaskRepository::new(&mut c)
                .complete_verified_step(&done)
                .is_err()
        );

        c.execute(
            "UPDATE tasks SET state = 'pending', lease_holder = NULL,
                            lease_expires_at_ms = NULL WHERE id = 't';",
            [],
        )
        .expect("release");
        let second = running_on(&mut c, 1, "p2");
        assert_eq!(
            (second.step_no, second.attempt_no),
            (1, 2),
            "the retry is attempt 2 of step 1, not step 2"
        );
        assert_eq!(state_of(&c).1, 0, "the counter never moved");
    }

    // -------------------------------------------------------- lease boundary

    #[test]
    fn a_verified_non_final_step_releases_the_lease() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        assert_eq!(state_of(&c).3.as_deref(), Some("w"), "precondition");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("advance");
        assert_eq!(
            state_of(&c).3,
            None,
            "the next step must not inherit the prior worker's lease"
        );
    }

    #[test]
    fn the_lease_and_its_expiry_are_both_cleared() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("advance");
        let (holder, expiry): (Option<String>, Option<i64>) = c
            .query_row(
                "SELECT lease_holder, lease_expires_at_ms FROM tasks WHERE id = 't';",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("row");
        assert_eq!(holder, None);
        assert_eq!(
            expiry, None,
            "a half-cleared lease trips the schema CHECK, which is the point of asserting both"
        );
    }

    /// Stage 3c stops at the boundary. Nothing here acquires a lease for the next step; the
    /// task is left claimable and unclaimed.
    #[test]
    fn no_lease_is_acquired_for_the_next_step() {
        let mut c = mem_task(3);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("advance");
        let (state, _, _, holder) = state_of(&c);
        assert_eq!(state, "awaiting-next-step");
        assert_eq!(holder, None, "Stage 3d acquires the next lease, not 3c");
    }

    // ------------------------------------------------ duplicate / crash safety

    #[test]
    fn the_same_step_cannot_be_counted_twice() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("first");
        // The task left `running` and holds no lease, so the second attempt is fenced out
        // before the counter could move again.
        let second = TaskRepository::new(&mut c).complete_verified_step(&verified(1, "p1"));
        assert!(
            second.is_err(),
            "a repeated completion must be refused: {second:?}"
        );
        assert_eq!(state_of(&c).1, 1, "the counter moved twice");
        assert_eq!(
            TaskRepository::new(&mut c)
                .step_results_for(&tid("t"))
                .expect("r")
                .len(),
            1
        );
    }

    /// Even with the lease and state forced back to look re-runnable, the durable result
    /// row refuses the second insert. The counter is guarded by the same row.
    #[test]
    fn a_reinserted_result_cannot_advance_the_task_again() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("first");
        // Force the row back into a runnable shape, as a crash-and-replay might.
        c.execute(
            "UPDATE tasks SET state = 'running', steps_completed = 0, lease_holder = 'w',
                            lease_expires_at_ms = ?1 WHERE id = 't';",
            rusqlite::params![NOW + LEASE],
        )
        .expect("force");
        let out = TaskRepository::new(&mut c).complete_verified_step(&verified(1, "p1"));
        assert!(
            out.is_err(),
            "the existing result row must refuse this: {out:?}"
        );
        assert_eq!(
            state_of(&c).1,
            0,
            "a refused duplicate must leave the counter where it was"
        );
    }

    /// A task cannot be sitting in a terminal state whose last step has no result.
    #[test]
    fn a_completed_task_always_has_its_final_step_result() {
        for max in 1..=3u32 {
            let mut c = mem_task(max);
            for step in 1..=max {
                if step > 1 {
                    claim_next_step(&mut c, "w", step, &format!("p{step}"));
                } else {
                    running_on(&mut c, step, &format!("p{step}"));
                }
                TaskRepository::new(&mut c)
                    .complete_verified_step(&verified(step, &format!("p{step}")))
                    .unwrap_or_else(|e| panic!("step {step} of {max}: {e}"));
            }
            let (state, completed, _, _) = state_of(&c);
            assert_eq!(state, "completed");
            assert_eq!(completed, max);
            assert!(
                TaskRepository::new(&mut c)
                    .step_result(&tid("t"), max)
                    .expect("read")
                    .is_some(),
                "a completed {max}-step task has no result for step {max}"
            );
        }
    }

    #[test]
    fn the_counter_never_exceeds_the_maximum() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("first");
        claim_next_step(&mut c, "w", 2, "p2");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(2, "p2"))
            .expect("second");
        let (_, completed, max, _) = state_of(&c);
        assert!(completed <= max, "{completed} > {max}");
    }

    /// Incrementing an already-finished task is refused rather than wrapped.
    #[test]
    fn a_finished_task_refuses_to_advance_again() {
        let mut c = mem_task(1);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("first");
        let out = TaskRepository::new(&mut c).complete_verified_step(&verified(1, "p1"));
        assert!(out.is_err(), "{out:?}");
        assert_eq!(state_of(&c).1, 1);
    }

    // ---------------------------------------------------- step propagation

    #[test]
    fn a_second_step_proposal_records_its_own_step() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("first");
        claim_next_step(&mut c, "w", 2, "p2");
        let read = TaskRepository::new(&mut c)
            .proposal_by_id("p2")
            .expect("read")
            .expect("present");
        assert_eq!(read.step_no, 2);
    }

    /// The executing step must be the current logical step. An approval or proposal for a
    /// different step cannot advance this one.
    #[test]
    fn a_step_other_than_the_current_one_cannot_advance() {
        let mut c = mem_task(3);
        running_on(&mut c, 1, "p1");
        // Step 2 has not been reached: steps_completed is still 0.
        let out = TaskRepository::new(&mut c).complete_verified_step(&verified(2, "p1"));
        assert!(
            matches!(out, Err(TaskRepoError::InvalidComposition(_))),
            "step 2 is not the step being executed: {out:?}"
        );
        assert_eq!(state_of(&c).1, 0);
        assert!(
            TaskRepository::new(&mut c)
                .step_results_for(&tid("t"))
                .expect("r")
                .is_empty()
        );
    }

    /// Isolates the step-identity guard from the other two.
    ///
    /// The obvious test for "only the current step may advance" also trips the proposal
    /// check, so it would keep passing with the identity guard deleted. This builds the
    /// state the guard exists for directly: a proposal that genuinely belongs to the step
    /// being claimed, no result row for it, and a counter that has already moved past it.
    /// Only the identity rule can refuse that.
    #[test]
    fn a_step_the_task_has_already_moved_past_cannot_advance() {
        let mut c = mem_task(3);
        // Counter says two steps are done; no results exist, so the primary key cannot help.
        c.execute(
            "UPDATE tasks SET steps_completed = 2, state = 'running', lease_holder = 'w',
                            lease_expires_at_ms = ?1 WHERE id = 't';",
            rusqlite::params![NOW + LEASE],
        )
        .expect("wind the counter forward");
        c.execute(
            "INSERT INTO task_proposals (proposal_id, task_id, attempt_no, step_no,
                                          capability, target, params, proposer, created_at_ms,
                                          status)
             VALUES ('p-old', 't', 9, 2, 'filesystem/write-text', 'a.txt', '{}', '{}', ?1,
                     'approved');",
            rusqlite::params![NOW],
        )
        .expect("a proposal that really does belong to step 2");

        // Step 2 is real, the proposal matches, and no result exists for it -- and it is
        // still refused, because the task is on step 3 now.
        let out = TaskRepository::new(&mut c).complete_verified_step(&verified(2, "p-old"));
        assert!(
            matches!(out, Err(TaskRepoError::InvalidComposition(_))),
            "a step the counter has passed must not advance: {out:?}"
        );
        assert_eq!(state_of(&c).1, 2, "the counter stayed where it was");
        assert!(
            TaskRepository::new(&mut c)
                .step_results_for(&tid("t"))
                .expect("r")
                .is_empty()
        );
    }

    /// The proposal check, isolated.
    ///
    /// Constructed so the identity guard *passes*: the counter says the task is on step 2
    /// and the completion claims step 2, but the proposal it names belongs to step 1. Only
    /// the proposal check can refuse this, which is what stops an approval minted for one
    /// step from advancing the next one.
    #[test]
    fn a_proposal_for_another_step_cannot_advance_this_one() {
        let mut c = mem_task(3);
        c.execute(
            "UPDATE tasks SET steps_completed = 1, state = 'running', lease_holder = 'w',
                            lease_expires_at_ms = ?1 WHERE id = 't';",
            rusqlite::params![NOW + LEASE],
        )
        .expect("one step done");
        c.execute(
            "INSERT INTO task_proposals (proposal_id, task_id, attempt_no, step_no,
                                          capability, target, params, proposer, created_at_ms,
                                          status)
             VALUES ('p1', 't', 1, 1, 'filesystem/write-text', 'a.txt', '{}', '{}', ?1,
                     'approved');",
            rusqlite::params![NOW],
        )
        .expect("a proposal for step 1");

        // Step 2 is genuinely the current step, so the identity guard is satisfied...
        let out = TaskRepository::new(&mut c).complete_verified_step(&verified(2, "p1"));
        assert!(
            matches!(out, Err(TaskRepoError::InvalidComposition(_))),
            "step 1's proposal must not advance step 2: {out:?}"
        );
        // ...and nothing was written.
        assert_eq!(state_of(&c).1, 1, "the counter stayed put");
        assert!(
            TaskRepository::new(&mut c)
                .step_results_for(&tid("t"))
                .expect("r")
                .is_empty()
        );
    }

    /// The proposal a completion claims must itself belong to the step being completed.
    #[test]
    fn a_completion_must_name_a_proposal_for_that_step() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        let out = TaskRepository::new(&mut c).complete_verified_step(&verified(1, "nope"));
        assert!(out.is_err(), "an unknown proposal must be refused: {out:?}");
        assert_eq!(state_of(&c).1, 0);
    }

    /// `attempt_no` is never the step. A task on its third attempt is still on step 1.
    #[test]
    fn the_step_is_never_derived_from_the_attempt_number() {
        let mut c = mem_task(3);
        let first = {
            let mut repo = TaskRepository::new(&mut c);
            repo.claim_specific(&tid("t"), "w", NOW, NOW + LEASE)
                .expect("claim");
            repo.propose_action(
                "p1",
                &tid("t"),
                "w",
                "filesystem/write-text",
                Some("a.txt"),
                "{}",
                "{}",
                None,
                1,
                NOW,
            )
            .expect("propose")
        };
        assert_eq!(first.attempt_no, 1);

        c.execute(
            "UPDATE tasks SET state = 'pending', lease_holder = NULL,
                            lease_expires_at_ms = NULL WHERE id = 't';",
            [],
        )
        .expect("release");
        let mut repo = TaskRepository::new(&mut c);
        repo.claim_specific(&tid("t"), "w", NOW, NOW + LEASE)
            .expect("claim again");
        let third_attempt = repo
            .propose_action(
                "p3",
                &tid("t"),
                "w",
                "filesystem/write-text",
                Some("a.txt"),
                "{}",
                "{}",
                None,
                1,
                NOW,
            )
            .expect("propose");
        assert_eq!(
            (third_attempt.step_no, third_attempt.attempt_no),
            (1, 2),
            "a later attempt is still step 1"
        );
        assert_eq!(state_of(&c).1, 0);
    }

    /// A worker without the lease cannot advance the task, whoever it says it is.
    #[test]
    fn a_worker_without_the_lease_cannot_advance() {
        let mut c = mem_task(2);
        running_on(&mut c, 1, "p1");
        let mut other = verified(1, "p1");
        other.worker = "impostor";
        let out = TaskRepository::new(&mut c).complete_verified_step(&other);
        assert!(out.is_err(), "{out:?}");
        assert_eq!(state_of(&c).1, 0);
        assert_eq!(state_of(&c).0, "running");
    }

    /// `Completed` is terminal: nothing here reopens it.
    #[test]
    fn a_completed_task_is_not_reopened() {
        let mut c = mem_task(1);
        running_on(&mut c, 1, "p1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&verified(1, "p1"))
            .expect("first");
        let row = TaskRepository::new(&mut c)
            .get(&tid("t"))
            .expect("get")
            .expect("row");
        assert_eq!(row.state, TaskState::Completed);
        assert!(row.state.is_terminal(), "Completed must stay terminal");
        assert!(
            !orxnud_domain::task_state::is_legal_transition(
                TaskState::Completed,
                TaskState::AwaitingNextStep
            ),
            "there must be no Completed -> AwaitingNextStep edge"
        );
    }
}

/// Stage 3d: claiming the next logical step.
///
/// Stage 3c stops at the boundary with the lease cleared. These tests are about the other
/// half: that the boundary is claimable, that the claim is a *fresh* lease rather than a
/// continuation of the previous one, and that two workers racing for it produce one winner
/// rather than two owners of one step.
#[cfg(test)]
mod next_step_claim_tests {
    use super::*;
    use crate::migration::MigrationRunner;
    use crate::pragma::Pragma;

    const NOW: i64 = 1_767_225_600_000;
    const LEASE: i64 = 60_000;

    fn mem() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        MigrationRunner::new(&c).run(true).expect("migrate");
        c
    }

    fn tid(s: &str) -> TaskId {
        TaskId::new(s)
    }

    fn mem_task(max_steps: u32) -> Connection {
        let mut c = mem();
        {
            let mut repo = TaskRepository::new(&mut c);
            repo.insert(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
                .expect("insert");
        }
        c.execute(
            "UPDATE tasks SET max_steps = ?1, steps_completed = 0 WHERE id = 't';",
            rusqlite::params![max_steps],
        )
        .expect("set bounds");
        c
    }

    /// Drive step 1 all the way to `Verified`, leaving the task at the boundary.
    ///
    /// Uses the same claim/propose/approve/resume sequence as the runtime, so the state
    /// these tests claim is one the real path produces rather than one assembled by hand.
    fn at_boundary(c: &mut Connection, max_steps: u32) {
        {
            let mut repo = TaskRepository::new(&mut *c);
            repo.claim_specific(&tid("t"), "worker-a", NOW, LEASE)
                .expect("claim step 1");
            repo.propose_action(
                "p1",
                &tid("t"),
                "worker-a",
                "filesystem/write-text",
                Some("a.txt"),
                "{}",
                "{}",
                None,
                1,
                NOW,
            )
            .expect("propose");
            repo.decide_proposal("p1", "approved", NOW)
                .expect("approve");
            repo.begin_approved_execution("p1", "worker-a", NOW, LEASE)
                .expect("resume");
        }
        TaskRepository::new(&mut *c)
            .complete_verified_step(&VerifiedStep {
                task_id: tid("t"),
                worker: "worker-a",
                step_no: 1,
                proposal_id: "p1",
                status: StepStatus::Verified,
                verification: Some("evidence".into()),
                structured_output: None,
                artifacts: None,
                recorded_at_ms: NOW,
            })
            .expect("advance");
        assert_eq!(
            row_of(c).0,
            "awaiting-next-step",
            "precondition: Stage 3c leaves the task at the boundary"
        );
        assert!(max_steps >= 2, "a boundary only exists when a step remains");
    }

    fn row_of(c: &Connection) -> (String, i64, i64, i64, Option<String>, Option<i64>) {
        c.query_row(
            "SELECT state, steps_completed, max_steps, attempts, lease_holder,
                    lease_expires_at_ms
               FROM tasks WHERE id = 't';",
            [],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .expect("row")
    }

    fn claim_next(c: &mut Connection, worker: &str) -> TargetedClaimOutcome {
        TaskRepository::new(&mut *c)
            .claim_next_step(&tid("t"), worker, NOW, LEASE)
            .expect("claim next step")
    }

    // ------------------------------------------------------- basic claim

    #[test]
    fn a_task_at_the_boundary_can_be_claimed() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        assert!(matches!(
            claim_next(&mut c, "worker-b"),
            TargetedClaimOutcome::Claimed(_)
        ));
    }

    #[test]
    fn claiming_the_boundary_moves_it_to_running() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        claim_next(&mut c, "worker-b");
        assert_eq!(row_of(&c).0, "running");
    }

    #[test]
    fn claiming_the_boundary_creates_a_live_lease() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        claim_next(&mut c, "worker-b");
        let (_, _, _, _, holder, expiry) = row_of(&c);
        assert!(holder.is_some(), "a claimed task must hold a lease");
        assert!(expiry.is_some(), "a lease without an expiry is not a fence");
    }

    #[test]
    fn the_lease_belongs_to_the_claimant() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        claim_next(&mut c, "worker-b");
        assert_eq!(row_of(&c).4.as_deref(), Some("worker-b"));
    }

    /// The expiry is recomputed from the claim time, never carried over.
    #[test]
    fn the_lease_expiry_is_freshly_calculated() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        claim_next(&mut c, "worker-b");
        let (_, _, _, _, _, expiry) = row_of(&c);
        assert_eq!(
            expiry,
            Some(NOW + LEASE),
            "the existing lease-duration policy, applied to the claim time"
        );
    }

    #[test]
    fn claiming_does_not_move_the_step_counters() {
        let mut c = mem_task(3);
        at_boundary(&mut c, 3);
        let (_, completed, max, _, _, _) = row_of(&c);
        claim_next(&mut c, "worker-b");
        let (_, completed_after, max_after, _, _, _) = row_of(&c);
        assert_eq!(completed, 1);
        assert_eq!(completed_after, completed, "claiming is not progress");
        assert_eq!(max_after, max, "and it does not resize the task");
    }

    // ------------------------------------------------ freshness of the lease

    #[test]
    fn the_cleared_lease_is_still_absent_while_awaiting() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        let (_, _, _, _, holder, expiry) = row_of(&c);
        assert_eq!(holder, None, "Stage 3c must have cleared the holder");
        assert_eq!(expiry, None, "and the expiry with it");
    }

    /// The prior worker's identity is gone, and the new lease belongs to whoever claimed.
    #[test]
    fn the_new_holder_is_not_the_previous_one_by_default() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        claim_next(&mut c, "worker-b");
        assert_eq!(
            row_of(&c).4.as_deref(),
            Some("worker-b"),
            "the lease is the claimant's, not step 1's"
        );
    }

    /// A different claim time must produce a different expiry.
    #[test]
    fn a_later_claim_does_not_reuse_an_earlier_expiry() {
        let mut c = mem_task(3);
        at_boundary(&mut c, 3);
        claim_next(&mut c, "worker-b");
        let first_expiry = row_of(&c).5.expect("expiry");

        // Back to the boundary for step 2, then claimed much later.
        TaskRepository::new(&mut c)
            .complete_verified_step(&VerifiedStep {
                task_id: tid("t"),
                worker: "worker-b",
                step_no: 2,
                proposal_id: "p2",
                status: StepStatus::Verified,
                verification: None,
                structured_output: None,
                artifacts: None,
                recorded_at_ms: NOW,
            })
            .ok();
        let later = NOW + 5_000_000;
        let outcome = TaskRepository::new(&mut c)
            .claim_next_step(&tid("t"), "worker-c", later, LEASE)
            .expect("claim step 2");
        if let TargetedClaimOutcome::Claimed(_) = outcome {
            assert_ne!(
                row_of(&c).5,
                Some(first_expiry),
                "a later claim must not reuse the previous expiry"
            );
        }
    }

    /// The old worker cannot complete the next step on the strength of its old lease.
    #[test]
    fn the_previous_worker_cannot_complete_the_next_step_with_its_old_identity() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        claim_next(&mut c, "worker-b");

        // `worker-a` held the step-1 lease, which Stage 3c cleared. It has no lease now.
        let forged = VerifiedStep {
            task_id: tid("t"),
            worker: "worker-a",
            step_no: 2,
            proposal_id: "p2",
            status: StepStatus::Verified,
            verification: None,
            structured_output: None,
            artifacts: None,
            recorded_at_ms: NOW,
        };
        let out = TaskRepository::new(&mut c).complete_verified_step(&forged);
        assert!(
            out.is_err(),
            "step 1's worker must not complete step 2: {out:?}"
        );
    }

    // ------------------------------------------------------------ concurrency

    /// Two claims, one winner.
    ///
    /// Sequential rather than threaded because the loser must be shown to be refused *by
    /// the database*, not by a lock the test happened to serialise: the second call sees
    /// `running` with a live lease and its conditional `UPDATE` matches nothing.
    #[test]
    fn a_second_claim_of_the_same_boundary_is_refused() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        assert!(matches!(
            claim_next(&mut c, "worker-b"),
            TargetedClaimOutcome::Claimed(_)
        ));
        assert!(
            matches!(
                claim_next(&mut c, "worker-c"),
                TargetedClaimOutcome::Refused(_)
            ),
            "the loser must not get a second lease"
        );
        assert_eq!(
            row_of(&c).4.as_deref(),
            Some("worker-b"),
            "and the lease still belongs to the winner"
        );
    }

    #[test]
    fn a_refused_claim_leaves_the_winner_able_to_work() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        claim_next(&mut c, "worker-b");
        let _ = claim_next(&mut c, "worker-c");
        // The winner still holds a live lease, so the Stage-3c fence still admits it.
        let ok = VerifiedStep {
            task_id: tid("t"),
            worker: "worker-b",
            step_no: 2,
            proposal_id: "p2",
            status: StepStatus::Verified,
            verification: None,
            structured_output: None,
            artifacts: None,
            recorded_at_ms: NOW,
        };
        // The proposal for step 2 does not exist yet, so this is refused for *that*
        // reason -- never for want of a lease.
        let out = TaskRepository::new(&mut c).complete_verified_step(&ok);
        assert!(
            !matches!(out, Err(TaskRepoError::Corrupt(_))),
            "the winner was refused as if it had no lease: {out:?}"
        );
    }

    // -------------------------------------------------------- step identity

    #[test]
    fn the_next_step_after_claiming_is_the_counter_plus_one() {
        let mut c = mem_task(3);
        at_boundary(&mut c, 3);
        assert_eq!(
            TaskRepository::new(&mut c)
                .next_step_no(&tid("t"))
                .expect("next"),
            2
        );
        claim_next(&mut c, "worker-b");
        assert_eq!(
            TaskRepository::new(&mut c)
                .next_step_no(&tid("t"))
                .expect("next"),
            2
        );
    }

    /// Claiming starts the next step's attempt budget at one, so its first proposal is
    /// attempt 1 of step 2 rather than a continuation of step 1's counting.
    #[test]
    fn the_next_steps_first_proposal_is_attempt_one() {
        let mut c = mem_task(3);
        at_boundary(&mut c, 3);
        claim_next(&mut c, "worker-b");
        let proposal = {
            let mut repo = TaskRepository::new(&mut c);
            repo.propose_action(
                "p2",
                &tid("t"),
                "worker-b",
                "filesystem/write-text",
                Some("a.txt"),
                "{}",
                "{}",
                None,
                2,
                NOW,
            )
            .expect("propose step 2")
        };
        assert_eq!(
            (proposal.step_no, proposal.attempt_no),
            (2, 1),
            "step 2's first execution is attempt 1 of step 2"
        );
    }

    /// The attempt row itself records which step it belongs to.
    ///
    /// Without this the step number on `task_attempts` is unobserved, and an implementation
    /// that read the step off the attempt counter would pass every other test -- the two
    /// numbers coincide for the first attempt of each step, which is the only case a
    /// simple test tends to reach.
    #[test]
    fn each_step_keeps_its_own_attempt_numbering() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        claim_next(&mut c, "worker-b");
        let attempts = TaskRepository::new(&mut c)
            .attempts_for(&tid("t"))
            .expect("attempts");
        assert_eq!(
            attempts
                .iter()
                .map(|a| (a.step_no, a.attempt_no))
                .collect::<Vec<_>>(),
            vec![(1, 1), (2, 1)],
            "step 2 restarts its attempt numbering without overwriting step 1's"
        );
    }

    /// A step boundary resets the attempt counter, so a step that took three attempts does
    /// not spend the next step's retry budget.
    #[test]
    fn a_step_boundary_does_not_carry_the_previous_steps_attempts() {
        let mut c = mem_task(3);
        // Give the task three attempts on step 1, then verify it.
        {
            let mut repo = TaskRepository::new(&mut c);
            repo.claim_specific(&tid("t"), "worker-a", NOW, LEASE)
                .expect("claim 1");
            repo.propose_action(
                "p1",
                &tid("t"),
                "worker-a",
                "filesystem/write-text",
                Some("a.txt"),
                "{}",
                "{}",
                None,
                1,
                NOW,
            )
            .expect("propose 1");
            repo.decide_proposal("p1", "approved", NOW)
                .expect("approve");
            repo.begin_approved_execution("p1", "worker-a", NOW, LEASE)
                .expect("resume 1");
        }
        c.execute("UPDATE tasks SET attempts = 3 WHERE id = 't';", [])
            .expect("three attempts on step 1");
        TaskRepository::new(&mut c)
            .complete_verified_step(&VerifiedStep {
                task_id: tid("t"),
                worker: "worker-a",
                step_no: 1,
                proposal_id: "p1",
                status: StepStatus::Verified,
                verification: None,
                structured_output: None,
                artifacts: None,
                recorded_at_ms: NOW,
            })
            .expect("advance");
        assert_eq!(
            row_of(&c).3,
            0,
            "the attempt counter belongs to the step that just finished"
        );
    }

    /// The reset belongs to the boundary only.
    ///
    /// A finished task keeps its attempt count: it is the only record of how much work the
    /// task took, and `task/list` reports it. There is no next step to start, so the reason
    /// for resetting does not apply.
    #[test]
    fn a_task_that_completes_keeps_its_attempt_count() {
        let mut c = mem_task(1);
        {
            let mut repo = TaskRepository::new(&mut c);
            repo.claim_specific(&tid("t"), "w", NOW, LEASE)
                .expect("claim");
            repo.propose_action(
                "p1",
                &tid("t"),
                "w",
                "filesystem/write-text",
                Some("a.txt"),
                "{}",
                "{}",
                None,
                1,
                NOW,
            )
            .expect("propose");
            repo.decide_proposal("p1", "approved", NOW)
                .expect("approve");
            repo.begin_approved_execution("p1", "w", NOW, LEASE)
                .expect("resume");
        }
        TaskRepository::new(&mut c)
            .complete_verified_step(&VerifiedStep {
                task_id: tid("t"),
                worker: "w",
                step_no: 1,
                proposal_id: "p1",
                status: StepStatus::Verified,
                verification: None,
                structured_output: None,
                artifacts: None,
                recorded_at_ms: NOW,
            })
            .expect("advance");
        let (state, _, _, attempts, _, _) = row_of(&c);
        assert_eq!(state, "completed");
        assert_eq!(
            attempts, 1,
            "a finished task's attempt count is its history, not a stale budget"
        );
    }

    // ------------------------------------------------------------- restart

    /// The boundary is durable state, not a lease: it survives a reopen with no lease
    /// reconstructed and is still claimable afterwards.
    #[test]
    fn the_boundary_survives_a_reopen_and_is_still_claimable() {
        let dir = std::env::temp_dir().join(format!("orxnud-3d-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("tasks.db");
        {
            let mut c = Connection::open(&path).expect("open");
            Pragma::critical().apply(&c).expect("pragmas");
            MigrationRunner::new(&c).run(true).expect("migrate");
            TaskRepository::new(&mut c)
                .insert(&NewTask::new(tid("t"), TaskKind::Workflow, NOW), NOW)
                .expect("insert");
            c.execute(
                "UPDATE tasks SET max_steps = 2, steps_completed = 0 WHERE id = 't';",
                [],
            )
            .expect("bounds");
            at_boundary(&mut c, 2);
        }

        // Reopened: nothing rebuilt, nothing recovered.
        {
            let c = Connection::open(&path).expect("reopen");
            let (state, completed, _, _, holder, expiry) = row_of(&c);
            assert_eq!(state, "awaiting-next-step");
            assert_eq!(completed, 1, "the counter is durable");
            assert_eq!(
                holder, None,
                "no lease is reconstructed for an unclaimed boundary"
            );
            assert_eq!(expiry, None);
        }
        // And still claimable.
        {
            let mut c = Connection::open(&path).expect("reopen again");
            Pragma::critical().apply(&c).expect("pragmas");
            assert!(matches!(
                TaskRepository::new(&mut c).claim_next_step(&tid("t"), "worker-b", NOW, LEASE),
                Ok(TargetedClaimOutcome::Claimed(_))
            ));
            assert_eq!(row_of(&c).0, "running");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Recovery must not treat a boundary as an orphaned lease.
    #[test]
    fn recovery_leaves_an_unclaimed_boundary_alone() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        let recovered = TaskRepository::new(&mut c).recover(NOW).expect("recover");
        assert_eq!(recovered, 0, "a boundary has no lease to reclaim");
        assert_eq!(row_of(&c).0, "awaiting-next-step");
        assert!(matches!(
            claim_next(&mut c, "worker-b"),
            TargetedClaimOutcome::Claimed(_)
        ));
    }

    // -------------------------------------------------------- compatibility

    #[test]
    fn the_pending_claim_is_unchanged() {
        let mut c = mem();
        {
            let mut repo = TaskRepository::new(&mut c);
            repo.insert(&NewTask::new(tid("p"), TaskKind::Query, NOW), NOW)
                .expect("insert");
            assert!(matches!(
                repo.claim_specific(&tid("p"), "w", NOW, LEASE),
                Ok(TargetedClaimOutcome::Claimed(_))
            ));
        }
        let (state, _, _, attempts, holder, expiry) = {
            let c2 = Connection::open_in_memory().ok();
            let _ = c2;
            row_of_id(&c, "p")
        };
        assert_eq!(state, "running");
        assert_eq!(attempts, 1, "a pending claim still counts as an attempt");
        assert_eq!(holder.as_deref(), Some("w"));
        assert_eq!(expiry, Some(NOW + LEASE));
    }

    /// The generic claim does not hand out step boundaries: that is a deliberate
    /// consequence of keeping the `Pending -> Running` path separate, and it is asserted so
    /// a future change to the claim query has to notice.
    #[test]
    fn the_generic_claim_does_not_take_a_step_boundary() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        let claimed = TaskRepository::new(&mut c)
            .claim("poller", NOW, LEASE)
            .expect("generic claim");
        assert!(
            matches!(claimed, ClaimOutcome::Empty),
            "the boundary is claimed deliberately, not swept up by a poll: {claimed:?}"
        );
        assert_eq!(row_of(&c).0, "awaiting-next-step");
    }

    /// Every state that is not a boundary stays unclaimable by the new path.
    #[test]
    fn states_other_than_a_boundary_are_refused() {
        for (state, extra) in [
            ("pending", ""),
            ("running", ""),
            ("completed", ""),
            ("cancelled", ""),
            ("dead-lettered", "x"),
            ("needs-verification", ""),
            ("paused", ""),
            ("failed", ""),
        ] {
            let mut c = mem_task(2);
            // `dead-lettered` is tied to `dead_lettered_at_ms` by a schema CHECK, so a
            // forced state has to bring its own timestamp with it.
            c.execute(
                "UPDATE tasks SET state = ?1, lease_holder = NULL,
                                lease_expires_at_ms = NULL,
                                dead_lettered_at_ms = ?2 WHERE id = 't';",
                rusqlite::params![state, if extra.is_empty() { None } else { Some(NOW) }],
            )
            .expect("force state");
            let out = claim_next(&mut c, "worker-b");
            assert!(
                matches!(out, TargetedClaimOutcome::Refused(_)),
                "{state} must not be claimable as a step boundary, got {out:?}"
            );
        }
    }

    #[test]
    fn a_task_at_a_boundary_with_a_live_lease_is_not_claimable() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        // A boundary row that somehow still carries a lease is not eligible.
        c.execute(
            "UPDATE tasks SET lease_holder = 'ghost', lease_expires_at_ms = ?1
               WHERE id = 't';",
            rusqlite::params![NOW + LEASE],
        )
        .expect("force a lease");
        let out = claim_next(&mut c, "worker-b");
        assert!(
            matches!(out, TargetedClaimOutcome::Refused(_)),
            "an active lease must block the claim: {out:?}"
        );
    }

    #[test]
    fn a_missing_task_is_refused_rather_than_created() {
        let mut c = mem_task(2);
        let out =
            TaskRepository::new(&mut c).claim_next_step(&tid("ghost"), "worker-b", NOW, LEASE);
        assert!(matches!(
            out,
            Ok(TargetedClaimOutcome::Refused(ClaimRefusal::NotFound))
        ));
    }

    /// A finished task cannot be pushed back into `AwaitingNextStep` to be re-run.
    #[test]
    fn a_task_whose_steps_are_all_done_is_not_claimable_as_a_boundary() {
        let mut c = mem_task(1);
        {
            let mut repo = TaskRepository::new(&mut c);
            repo.claim_specific(&tid("t"), "w", NOW, LEASE)
                .expect("claim");
            repo.propose_action(
                "p1",
                &tid("t"),
                "w",
                "filesystem/write-text",
                Some("a.txt"),
                "{}",
                "{}",
                None,
                1,
                NOW,
            )
            .expect("propose");
            repo.decide_proposal("p1", "approved", NOW)
                .expect("approve");
            repo.begin_approved_execution("p1", "w", NOW, LEASE)
                .expect("resume");
        }
        TaskRepository::new(&mut c)
            .complete_verified_step(&VerifiedStep {
                task_id: tid("t"),
                worker: "w",
                step_no: 1,
                proposal_id: "p1",
                status: StepStatus::Verified,
                verification: None,
                structured_output: None,
                artifacts: None,
                recorded_at_ms: NOW,
            })
            .expect("advance");
        assert_eq!(row_of(&c).0, "completed");
        // Forcing the state back must not make it claimable: the counter guard refuses it.
        c.execute(
            "UPDATE tasks SET state = 'awaiting-next-step' WHERE id = 't';",
            [],
        )
        .expect("force");
        let out = claim_next(&mut c, "worker-b");
        assert!(
            matches!(out, TargetedClaimOutcome::Refused(_)),
            "a task with no steps left must not be claimable: {out:?}"
        );
    }

    /// End to end through the boundary: step 1 verified, boundary, claimed, step 2 running
    /// with a proposal and approval bound to step 2.
    #[test]
    fn a_task_can_cross_the_boundary_and_work_on_step_two() {
        let mut c = mem_task(2);
        at_boundary(&mut c, 2);
        claim_next(&mut c, "worker-b");

        let proposal = {
            let mut repo = TaskRepository::new(&mut c);
            let row = repo
                .propose_action(
                    "p2",
                    &tid("t"),
                    "worker-b",
                    "filesystem/write-text",
                    Some("b.txt"),
                    "{}",
                    "{}",
                    None,
                    2,
                    NOW,
                )
                .expect("propose step 2");
            repo.decide_proposal("p2", "approved", NOW)
                .expect("approve");
            repo.record_approval(&ApprovalRow {
                task_id: tid("t"),
                attempt_no: row.attempt_no,
                step_no: row.step_no,
                digest_hex: "ab".repeat(32),
                capability: "filesystem/write-text".into(),
                target: Some("b.txt".into()),
                params: "{}".into(),
                issued_at_ms: NOW,
                expires_at_ms: NOW + LEASE,
                consumed_at_ms: None,
            })
            .expect("approval");
            row
        };
        assert_eq!(proposal.step_no, 2);

        // The proposal parked the task waiting for the human; resuming gives the execution
        // lease and leaves it running step 2.
        {
            let mut repo = TaskRepository::new(&mut c);
            repo.begin_approved_execution("p2", "worker-b", NOW, LEASE)
                .expect("resume step 2");
        }
        let approval = TaskRepository::new(&mut c)
            .approval_for_attempt(&tid("t"), proposal.attempt_no)
            .expect("read approval")
            .expect("present");
        assert_eq!(
            approval.step_no, 2,
            "the approval stays bound to the step it was minted for"
        );

        TaskRepository::new(&mut c)
            .complete_verified_step(&VerifiedStep {
                task_id: tid("t"),
                worker: "worker-b",
                step_no: 2,
                proposal_id: "p2",
                status: StepStatus::Verified,
                verification: None,
                structured_output: None,
                artifacts: None,
                recorded_at_ms: NOW,
            })
            .expect("finish step 2");
        let (state, completed, _, _, holder, _) = row_of(&c);
        assert_eq!((state.as_str(), completed, holder), ("completed", 2, None));
    }

    fn row_of_id(c: &Connection, id: &str) -> (String, i64, i64, i64, Option<String>, Option<i64>) {
        c.query_row(
            "SELECT state, steps_completed, max_steps, attempts, lease_holder,
                    lease_expires_at_ms
               FROM tasks WHERE id = ?1;",
            [id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            },
        )
        .expect("row")
    }
}
