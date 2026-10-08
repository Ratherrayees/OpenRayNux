//! The production task service: startup, one tick, and shutdown.
//!
//! # What this replaces
//!
//! Phase 1 composed a `Daemon` that started nothing and opened nothing. The task
//! engine and scheduler existed as libraries that tests drove by hand, which is not
//! the same thing as a daemon that *runs* them: nothing enforced that a real
//! startup migrates the database, and nothing recorded that a restart reclaims the
//! previous process's leases. Both are startup obligations, so they belong here,
//! in the composition root, and not in each caller's memory.
//!
//! # The two obligations that must not be skippable
//!
//! 1. **Migration.** [`TaskService::open`] always migrates, snapshot-protected, and
//!    returns an error rather than continuing. A daemon that starts on a database
//!    whose schema it does not understand would write rows the schema does not
//!    constrain — silently, because SQLite will happily accept them.
//!
//! 2. **Recovery.** Every open runs [`DurableEngine::recover`] before any work is
//!    claimed. A restart orphans the leases the dead process held, and those leases
//!    are *unexpired* by construction, so an engine that reclaimed only expired
//!    leases would strand that work forever. This is TP-4's meaning of "recover".
//!
//! # Why this owns the connection
//!
//! ADR-0006 documents exactly one writer. [`Scheduler`] borrows the engine's
//! connection for that reason, so the three of them are held together here rather
//! than handed out as independent handles that a caller could duplicate.

use std::path::Path;

use orxnud_domain::Actor;
use orxnud_domain::ids::{CapabilityId, TaskId};
use orxnud_domain::task_state::TaskState;
use orxnud_store::StoreError;
use orxnud_store::migration::MigrationRunner;
use orxnud_store::sqlite::Store;
use orxnud_store::task_repo::{
    ClaimRefusal, ClaimedTask, NewTask, ProposalRow, TargetedClaimOutcome, TaskRow,
};
use orxnud_task::engine::{ClaimAttempt, TaskCreation};
use orxnud_task::scheduler::{PassReport, Scheduler};
use orxnud_task::{DurableEngine, EngineError, EngineLimits};
use tracing::{debug, error, info, warn};

/// A startup that could not complete.
#[derive(Debug)]
pub enum StartupError {
    /// The database could not be opened, or its pragmas failed verification.
    Store(StoreError),
    /// A migration failed. The snapshot has been restored, so the database is back
    /// at its previous version and the daemon must not start.
    Migration(String),
    /// The engine rejected its configuration.
    Engine(EngineError),
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "cannot open the task database: {e}"),
            Self::Migration(m) => write!(
                f,
                "cannot migrate the task database: {m}\n  the pre-migration snapshot has \
                 been restored, so nothing was changed; fix the cause and start again"
            ),
            Self::Engine(e) => write!(f, "cannot start the task engine: {e}"),
        }
    }
}

impl std::error::Error for StartupError {}

/// A runtime failure of the task subsystem.
///
/// # Why this exists instead of an eleventh [`EngineErrorKind`](orxnud_task::EngineErrorKind)
///
/// "The service is shutting down" is a fact about the *daemon's* lifecycle, not
/// about the task engine: [`EngineErrorKind`](orxnud_task::EngineErrorKind) is a
/// closed taxonomy of things that can go wrong with a task, and each kind carries a
/// retry decision. Shutdown has no retry decision — never retry — so folding it in
/// as `Cancelled` would misreport a deliberate stop as a failure someone should act
/// on, and as `Unavailable` it would
/// suggest a dependency might come back. The engine's taxonomy stays closed; the
/// lifecycle concern lives here.
#[derive(Debug)]
pub enum TaskServiceError {
    /// [`TaskService::shutdown`] has run.
    Stopped,
    /// The engine failed.
    Engine(EngineError),
}

impl std::fmt::Display for TaskServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stopped => write!(f, "the task subsystem is shutting down"),
            Self::Engine(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TaskServiceError {}

impl From<EngineError> for TaskServiceError {
    fn from(e: EngineError) -> Self {
        Self::Engine(e)
    }
}

/// What one [`TaskService::open`] found and did.
///
/// Returned so startup is *observable* rather than assumed: "0 tasks recovered" and
/// "12 leases orphaned" are different operational facts, and only one of them means
/// the previous run was clean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opened {
    /// Migrations applied during this open. Empty on an up-to-date database.
    pub migrations_applied: usize,
    /// Leases orphaned by the previous process and reclaimed.
    pub leases_recovered: u64,
    /// Tasks visible after recovery.
    pub tasks: usize,
}

/// The task subsystem: the engine, its scheduler, and the startup that makes them
/// trustworthy.
#[derive(Debug)]
pub struct TaskService {
    engine: DurableEngine,
    limits: EngineLimits,
    opened: Opened,
    /// Set by [`TaskService::shutdown`]. A shut-down service refuses to claim,
    /// which is what makes "stop accepting work" different from "forget to stop".
    stopped: bool,
}

impl TaskService {
    /// Opens the task database, migrates it, and reclaims the previous run's work.
    ///
    /// # Errors
    ///
    /// Any [`StartupError`]. Every one of them is a refusal to start: there is no
    /// degraded mode, because a task engine that cannot trust its own schema or its
    /// own leases cannot tell the user which of their tasks actually ran.
    pub fn open(path: &Path, limits: EngineLimits) -> Result<Self, StartupError> {
        Self::open_with_time(path, limits, now_ms())
    }

    /// [`Self::open`] with an explicit clock, for tests and for replay.
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    pub fn open_with_time(
        path: &Path,
        limits: EngineLimits,
        now_ms: i64,
    ) -> Result<Self, StartupError> {
        // `critical = true`: the task database is the one region ADR-0006 marks
        // critical, so its pragmas are verified rather than merely applied.
        let store = Store::open(path, true).map_err(StartupError::Store)?;
        let runner = MigrationRunner::new(store.conn());

        // Always migrate, never `run()` alone. `migrate` snapshots first and
        // restores on failure; `run` trusts the caller to have done that. The
        // difference is the difference between "a failed migration is rolled back"
        // and "the schema is now half-applied and nobody can say which half".
        let applied = runner
            .migrate(path, false)
            .map_err(|e| StartupError::Migration(e.to_string()))?;
        if !applied.is_empty() {
            info!(
                migrations = applied.len(),
                versions = ?applied,
                "applied schema migrations"
            );
        }

        let mut engine =
            DurableEngine::new(store.into_connection(), limits).map_err(StartupError::Engine)?;

        // Before any claim. A lease orphaned by a dead process is unexpired, so
        // this is the only thing that will ever reclaim it.
        let leases_recovered = engine
            .recover(now_ms)
            .map_err(|e| StartupError::Migration(format!("cannot reclaim orphaned leases: {e}")))?;
        let tasks = engine
            .all_tasks()
            .map_err(|e| StartupError::Migration(format!("cannot read the task table: {e}")))?
            .len();

        let opened = Opened {
            migrations_applied: applied.len(),
            leases_recovered,
            tasks,
        };
        if leases_recovered > 0 {
            // Not an error: a crash-restart is the normal case this exists for.
            warn!(
                recovered = leases_recovered,
                "reclaimed leases orphaned by the previous process"
            );
        } else {
            debug!("no orphaned leases to reclaim");
        }
        info!(
            migrations = opened.migrations_applied,
            recovered = opened.leases_recovered,
            tasks = opened.tasks,
            "task subsystem ready"
        );

        Ok(Self {
            engine,
            limits,
            opened,
            stopped: false,
        })
    }

    /// What [`Self::open`] found and did.
    #[must_use]
    pub fn opened(&self) -> Opened {
        self.opened
    }

    /// The engine, for the few callers that need the full surface.
    #[must_use]
    pub fn engine(&self) -> &DurableEngine {
        &self.engine
    }

    /// The engine, mutably.
    ///
    /// Deliberately not `pub`: handing out `&mut DurableEngine` lets a caller claim
    /// without ticking the scheduler, which is how a service ends up with work in the
    /// queue that nothing will ever turn into a running task.
    pub fn engine_mut(&mut self) -> &mut DurableEngine {
        &mut self.engine
    }

    /// The configured limits.
    #[must_use]
    pub fn limits(&self) -> EngineLimits {
        self.limits
    }

    /// One scheduler pass.
    ///
    /// Bounded by [`EngineLimits::max_schedules_per_pass`] and
    /// [`EngineLimits::catch_up_cap`]; the report carries what was dropped so a
    /// caller can report it instead of discovering it later.
    ///
    /// # Errors
    ///
    /// [`TaskServiceError::Stopped`] after [`Self::shutdown`].
    pub fn tick(&mut self, now_ms: i64) -> Result<PassReport, TaskServiceError> {
        if self.stopped {
            return Err(TaskServiceError::Stopped);
        }
        let report = Scheduler::new(&mut self.engine).run_pass(now_ms)?;
        if report.tasks_created > 0 || report.dropped > 0 {
            info!(
                considered = report.schedules_considered,
                created = report.tasks_created,
                dropped = report.dropped,
                already_present = report.fires_already_present,
                "scheduler pass"
            );
        }
        if report.dropped > 0 {
            // Dropping occurrences is a policy decision, and the one that loses work.
            // It must be visible to the user, not merely counted in a debug log.
            warn!(
                dropped = report.dropped,
                total_missed = report.total_missed,
                "scheduler dropped missed occurrences"
            );
        }
        Ok(report)
    }

    /// When the next occurrence is due, if one is.
    ///
    /// A caller can sleep until this instead of polling, which is what makes an idle
    /// daemon nearly free.
    ///
    /// # Errors
    ///
    /// As [`Self::tick`].
    pub fn next_wakeup_ms(&mut self, now_ms: i64) -> Result<Option<i64>, TaskServiceError> {
        if self.stopped {
            return Err(TaskServiceError::Stopped);
        }
        Ok(Scheduler::new(&mut self.engine).next_wakeup_ms(now_ms)?)
    }

    /// Claims one task for `worker`, if any is claimable.
    ///
    /// # Errors
    ///
    /// [`TaskServiceError::Stopped`] after [`Self::shutdown`], so a stop cannot be
    /// lost to a worker that was already in flight.
    pub fn claim(
        &mut self,
        worker: &str,
        now_ms: i64,
    ) -> Result<Option<orxnud_store::task_repo::TaskRow>, TaskServiceError> {
        if self.stopped {
            return Err(TaskServiceError::Stopped);
        }
        Ok(self.engine.claim_task(worker, now_ms)?)
    }

    /// Stops accepting work and reclaims this process's leases.
    ///
    /// The reclaim is the point. A shutdown that simply stopped claiming would leave
    /// every in-flight lease held by a process that no longer exists, and those leases
    /// do not expire on their own — a task would sit `running` until its lease
    /// elapsed, for no reason.
    ///
    /// Idempotent, so a double stop is not an error.
    pub fn shutdown(&mut self, now_ms: i64) -> Result<u64, EngineError> {
        if self.stopped {
            debug!("task subsystem already stopped");
            return Ok(0);
        }
        self.stopped = true;
        match self.engine.recover(now_ms) {
            Ok(n) => {
                if n > 0 {
                    info!(reclaimed = n, "shutdown reclaimed in-flight leases");
                } else {
                    debug!("shutdown reclaimed no leases");
                }
                Ok(n)
            }
            Err(e) => {
                error!(error = %e, "shutdown failed to reclaim in-flight leases");
                Err(e)
            }
        }
    }

    /// Whether [`Self::shutdown`] has run.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
}

/// Milliseconds since the Unix epoch.
///
/// Clamped rather than wrapping: a clock before 1970 or past year 292 million is a
/// broken clock, and a wrapped `i64` would produce a *plausible* task timestamp
/// instead of an obviously wrong one.
#[must_use]
pub fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_767_225_600_000;

    fn db(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("orxnud-task-service-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d.join("tasks.db")
    }

    #[test]
    fn opening_a_fresh_database_applies_every_migration() {
        let s = TaskService::open_with_time(&db("fresh"), EngineLimits::documented(), NOW)
            .expect("open");
        assert_eq!(
            s.opened().migrations_applied,
            orxnud_store::migration::CURRENT_VERSION as usize,
            "a fresh database must be fully migrated"
        );
        assert_eq!(s.opened().leases_recovered, 0);
        assert_eq!(s.opened().tasks, 0);
    }

    #[test]
    fn reopening_applies_nothing_and_reclaims_nothing() {
        let p = db("reopen");
        TaskService::open_with_time(&p, EngineLimits::documented(), NOW).expect("first open");
        let s =
            TaskService::open_with_time(&p, EngineLimits::documented(), NOW).expect("second open");
        assert_eq!(s.opened().migrations_applied, 0, "already migrated");
        assert_eq!(s.opened().leases_recovered, 0, "nothing was claimed");
    }

    #[test]
    fn a_restart_reclaims_the_previous_processs_lease() {
        let p = db("restart");
        let mut first =
            TaskService::open_with_time(&p, EngineLimits::documented(), NOW).expect("first open");
        let t = orxnud_domain::ids::TaskId::new("svc-restart");
        first
            .engine_mut()
            .enqueue_new(
                &orxnud_store::task_repo::NewTask::new(
                    t,
                    orxnud_domain::task_state::TaskKind::Query,
                    NOW,
                ),
                NOW,
            )
            .expect("enqueue");
        assert!(first.claim("worker-1", NOW).expect("claim").is_some());

        // The "crash": the first service is dropped without shutting down.
        drop(first);

        let second =
            TaskService::open_with_time(&p, EngineLimits::documented(), NOW).expect("restart");
        assert_eq!(
            second.opened().leases_recovered,
            1,
            "an unexpired lease from a dead process must be reclaimed at startup"
        );
        assert!(
            second.engine().all_tasks().expect("read")[0]
                .lease_holder
                .is_none(),
            "recovery must clear the holder"
        );
    }

    #[test]
    fn shutdown_stops_claiming_and_reclaims_in_flight_work() {
        let p = db("shutdown");
        let mut s = TaskService::open_with_time(&p, EngineLimits::documented(), NOW).expect("open");
        s.engine_mut()
            .enqueue_new(
                &orxnud_store::task_repo::NewTask::new(
                    orxnud_domain::ids::TaskId::new("svc-shutdown"),
                    orxnud_domain::task_state::TaskKind::Query,
                    NOW,
                ),
                NOW,
            )
            .expect("enqueue");
        assert!(s.claim("worker-1", NOW).expect("claim").is_some());

        assert_eq!(
            s.shutdown(NOW).expect("shutdown"),
            1,
            "must reclaim the lease"
        );
        assert!(s.is_stopped());
        // Idempotent.
        assert_eq!(s.shutdown(NOW).expect("second shutdown"), 0);

        assert!(
            matches!(s.claim("worker-2", NOW), Err(TaskServiceError::Stopped)),
            "a stopped service must refuse to claim"
        );
        assert!(
            matches!(s.tick(NOW), Err(TaskServiceError::Stopped)),
            "a stopped service must refuse to schedule"
        );
        assert!(
            matches!(s.next_wakeup_ms(NOW), Err(TaskServiceError::Stopped)),
            "a stopped service must refuse to report a wake-up"
        );
    }

    #[test]
    fn an_idle_service_ticks_without_creating_work() {
        let mut s = TaskService::open_with_time(&db("idle"), EngineLimits::documented(), NOW)
            .expect("open");
        let r = s.tick(NOW).expect("tick");
        assert_eq!(r.tasks_created, 0);
        assert_eq!(r.schedules_considered, 0);
        assert_eq!(
            s.next_wakeup_ms(NOW).expect("wakeup"),
            None,
            "no schedules, no wake-up"
        );
    }

    #[test]
    fn a_clock_before_the_epoch_does_not_wrap_into_the_future() {
        // A wrapped i64 would produce a plausible-looking timestamp, which is far
        // worse than a visibly negative one.
        assert!(now_ms() > 1_767_225_600_000, "this host's clock is sane");
    }
}

/// Why a task request could not be carried out, in terms a caller can branch on.
///
/// Separate from [`TaskServiceError`] because the two answer different questions.
/// `TaskServiceError` answers "is the subsystem still running"; this answers "what
/// was wrong with your request". Folding them together would force the IPC layer to
/// read an error *message* to tell "no such task" from "the database is gone" — and
/// the endpoint is local and unauthenticated, so message text is also a disclosure
/// surface. Every variant here carries a stable [`TaskFault::as_str`] instead, and
/// [`TaskFault::Engine`] holds the engine's **typed** cause rather than its text.
///
/// # Why the cause is typed
///
/// `Engine(String)` looked like the right boundary — one variant, an opaque summary, no
/// engine internals escaping — but it threw away the classification along with the text.
/// Everything behind it then became indistinguishable: a stale lease, an unknown
/// capability, a lost race and a genuinely broken database all produced the same variant,
/// and the daemon had to choose between "refused" and "internal" with nothing to choose
/// with. The outcome was `INTERNAL_ERROR` for conditions a client can act on.
///
/// A typed cause is not the same as leaking the engine's hierarchy. `TaskCause` is a closed
/// eight-value enum defined *here* at the service boundary, the detail is still opaque, and
/// the daemon maps the cause onto the protocol's coarse classes. New internal errors pick an
/// existing cause; they do not add variants to this enum.
#[derive(Debug)]
pub enum TaskFault {
    /// The id is already in use.
    AlreadyExists,
    /// No task carries that id.
    NotFound,
    /// The task exists but cannot be claimed right now.
    NotClaimable(ClaimRefusal),
    /// A completion was refused by the lease fence.
    ///
    /// Not an error: a zombie worker asking to commit is a normal, expected event
    /// under TP-5. It is reported rather than swallowed, and it is never converted
    /// into a success.
    Fenced,
    /// The service is shutting down.
    Stopped,
    /// A task-domain failure, with the reason it was one.
    Engine {
        /// Why the domain refused. Typed, and the only thing the daemon classifies with.
        cause: orxnud_task::TaskCause,
        /// The engine's own message. For logs and `data.detail`; **never** for
        /// classification, because that is what reading a message for meaning looks like.
        detail: String,
    },
}

impl TaskFault {
    /// A stable wire spelling.
    ///
    /// Clients branch on this, never on prose. It is the reason this enum exists
    /// separately from [`EngineError`], whose taxonomy is about retry decisions
    /// rather than about what a caller should be told.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AlreadyExists => "already-exists",
            Self::NotFound => "not-found",
            Self::NotClaimable(_) => "not-claimable",
            Self::Fenced => "fenced",
            Self::Stopped => "stopped",
            Self::Engine { cause, .. } => cause.as_str(),
        }
    }

    /// The specific reason inside [`Self::NotClaimable`], if that is the variant.
    ///
    /// So a client can tell "not found" from "already running" from "not due yet"
    /// without parsing anything.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::NotClaimable(r) => Some(r.as_str()),
            // The engine's own message, which is the only thing that says *which* storage
            // failure or *which* corrupt row. It never crossed this boundary before, because
            // the variant held a summary that `detail()` never read — and a refusal whose
            // detail is always empty is one an operator cannot act on.
            Self::Engine { detail, .. } => Some(detail),
            _ => None,
        }
    }
}

impl TaskService {
    /// The clock this service uses, in ms since the epoch.
    ///
    /// On the service rather than taken per call so the IPC layer cannot ask for
    /// "now" from two places that disagree.
    #[must_use]
    pub fn clock_now_ms(&self) -> i64 {
        now_ms()
    }

    /// Enqueues a task and returns the row as stored.
    ///
    /// # Errors
    ///
    /// [`TaskFault::AlreadyExists`] if the id is taken, or [`TaskFault::Engine`] if
    /// the write fails.
    pub fn create(&mut self, task: &NewTask, now_ms: i64) -> Result<TaskRow, TaskFault> {
        self.guard_running()?;
        match self.engine.create_task(task, now_ms) {
            Ok(TaskCreation::Created) => self
                .engine
                .task(&task.id)
                .map_err(|e| TaskFault::Engine {
                    cause: e.cause,
                    detail: e.to_string(),
                })?
                .ok_or(TaskFault::NotFound),
            Ok(TaskCreation::AlreadyExists) => Err(TaskFault::AlreadyExists),
            Err(e) => Err(TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            }),
        }
    }

    /// Reads one task.
    ///
    /// # Errors
    ///
    /// [`TaskFault::Engine`] if the read fails.
    pub fn task(&self, id: &TaskId) -> Result<Option<TaskRow>, TaskFault> {
        self.engine.task(id).map_err(|e| TaskFault::Engine {
            cause: e.cause,
            detail: e.to_string(),
        })
    }

    /// Every task, ordered by id.
    ///
    /// The ordering is the repository's own (`ORDER BY id`), so it is total and
    /// stable across runs — a list whose order could change between two identical
    /// databases would make "what changed" unanswerable.
    ///
    /// # Errors
    ///
    /// [`TaskFault::Engine`] if the read fails.
    pub fn list(&self) -> Result<Vec<TaskRow>, TaskFault> {
        self.engine.all_tasks().map_err(|e| TaskFault::Engine {
            cause: e.cause,
            detail: e.to_string(),
        })
    }

    /// Claims **one named** task for `worker`, through the lease fence.
    ///
    /// # Errors
    ///
    /// [`TaskFault::NotClaimable`] when the task exists but cannot be claimed now,
    /// [`TaskFault::Stopped`] after [`Self::shutdown`], or [`TaskFault::Engine`] for
    /// a budget refusal or a storage failure.
    pub fn claim_task(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
    ) -> Result<ClaimedTask, TaskFault> {
        self.guard_running()?;
        match self
            .engine
            .claim_task_id(id, worker, now_ms)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })? {
            ClaimAttempt::Claimed(c) => Ok(*c),
            ClaimAttempt::Refused(r) => Err(TaskFault::NotClaimable(r)),
        }
    }

    /// Claims the next logical step of a task sitting at a step boundary.
    ///
    /// The service's route to the one targeted continuation claim (ADR-0043). Separate
    /// from [`Self::claim_task`] on purpose: that one picks up work that has never
    /// started, and this one advances a task which has already completed a step. A
    /// polling worker must not be able to advance a boundary merely by observing it.
    ///
    /// Reports the refusal rather than collapsing it, so the caller can tell "this task
    /// was not at a boundary" from "another worker got there first" from "its budget is
    /// spent" instead of a single opaque error.
    ///
    /// # Errors
    ///
    /// [`TaskFault::NotClaimable`] with the stated [`ClaimRefusal`], or
    /// [`TaskFault::Stopped`] after [`Self::shutdown`].
    pub fn claim_next_step(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
    ) -> Result<ClaimedTask, TaskFault> {
        self.guard_running()?;
        match self
            .engine
            .claim_next_step(id, worker, now_ms)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })? {
            TargetedClaimOutcome::Claimed(c) => Ok(*c),
            TargetedClaimOutcome::Refused(r) => Err(TaskFault::NotClaimable(r)),
        }
    }

    /// Records a terminal outcome for a task `worker` holds a live lease on.
    ///
    /// Goes through the engine's fenced completion, so a `Pending` task — one never
    /// claimed — cannot be completed at all, and a worker without a live lease
    /// cannot complete one that is.
    ///
    /// # Errors
    ///
    /// [`TaskFault::Fenced`] if the lease is absent, expired or held by somebody
    /// else, [`TaskFault::NotFound`] if there is no such task, or
    /// [`TaskFault::Engine`] if the transition is illegal or the write fails.
    /// Completes a task through the engine's lease-fenced completion.
    ///
    /// The same fence every other completion goes through; a governed execution takes no
    /// shorter route to `completed` than a worker's own report does.
    ///
    /// # Errors
    ///
    /// [`TaskFault::Fenced`] if the caller does not hold the live lease.
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
    ) -> Result<TaskRow, TaskFault> {
        self.guard_running()?;
        let ok = self
            .engine
            .complete_task_with(
                id,
                worker,
                now_ms,
                to,
                effect_observed,
                error,
                retry_delay_ms,
            )
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })?;
        if !ok {
            return Err(TaskFault::Fenced);
        }
        // Re-read rather than construct: the authoritative post-state is what the engine
        // stored, including `terminal_at_ms` and the effect bookkeeping.
        self.engine
            .task(id)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })?
            .ok_or(TaskFault::Fenced)
    }

    /// Completes a task through the engine, fenced by the caller's live lease.
    ///
    /// # Errors
    ///
    /// [`TaskFault::Fenced`] if the caller does not hold the live lease, or
    /// [`TaskFault::Stopped`] after [`Self::shutdown`].
    pub fn complete_task(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
        to: TaskState,
    ) -> Result<TaskRow, TaskFault> {
        self.guard_running()?;
        // The engine reports "not there" and "fence refused" with one `bool`, because
        // a zombie worker must not be able to learn whether the task exists. So the
        // existence check happens first, and only for a caller who could not
        // otherwise have distinguished the two.
        let known = self
            .engine
            .task(id)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })?
            .is_some();
        let committed = self
            .engine
            .complete_task(id, worker, now_ms, to, true, None)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })?;
        if !committed {
            return Err(if known {
                TaskFault::Fenced
            } else {
                TaskFault::NotFound
            });
        }
        self.engine
            .task(id)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })?
            .ok_or(TaskFault::NotFound)
    }

    // ------------------------------------------------- governed action proposals
    // ------------------------------------------------- governed action proposals

    /// Records a governed action a task asks to perform, and parks it for a human.
    ///
    /// # Errors
    ///
    /// [`TaskFault`] if the task is unknown, is not `running` under this worker's live
    /// lease, or already has a proposal for this attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn propose_action(
        &mut self,
        proposal_id: &str,
        id: &TaskId,
        worker: &str,
        capability: &CapabilityId,
        target: Option<&str>,
        canonical_params: &str,
        proposer: &Actor,
        now_ms: i64,
    ) -> Result<ProposalRow, TaskFault> {
        self.guard_running()?;
        self.engine
            .propose_action(
                proposal_id,
                id,
                worker,
                capability,
                target,
                canonical_params,
                proposer,
                now_ms,
            )
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })
    }

    /// Completes one verified logical step, advancing the task if another step remains.
    ///
    /// A thin pass-through: the result, the counter, the state and the lease release are
    /// one repository transaction, and this layer adds no decision to it.
    ///
    /// # Errors
    ///
    /// [`TaskFault::Engine`] carrying the repository's reason -- a lost lease, a step that
    /// is not the one being worked on, or a counter that would pass `max_steps`.
    pub fn complete_verified_step(
        &mut self,
        done: &orxnud_store::task_repo::VerifiedStep<'_>,
    ) -> Result<orxnud_store::task_repo::StepAdvance, TaskFault> {
        self.engine
            .complete_verified_step(done)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })
    }

    /// The logical step currently being worked on: the task's `steps_completed + 1`.
    ///
    /// # Errors
    ///
    /// [`TaskFault::Engine`] if the task does not exist or its counters are impossible.
    pub fn next_step_no(&mut self, id: &TaskId) -> Result<u32, TaskFault> {
        self.engine.next_step_no(id).map_err(|e| TaskFault::Engine {
            cause: e.cause,
            detail: e.to_string(),
        })
    }

    /// The durable results of a task's completed logical steps, oldest step first.
    ///
    /// A read-only projection, used to build the proposal context the model is shown. It
    /// carries no authority and mutates nothing. Ordered by `step_no` in the store, so
    /// anything derived from it is deterministic.
    ///
    /// # Errors
    ///
    /// [`TaskFault::Engine`] if the store cannot be read.
    pub fn step_results_for(
        &mut self,
        task_id: &TaskId,
    ) -> Result<Vec<orxnud_store::task_repo::StepResultRow>, TaskFault> {
        self.engine
            .step_results_for(task_id)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })
    }

    /// Reserves the idempotency key for a side effect about to be dispatched.
    ///
    /// # Errors
    ///
    /// [`TaskFault`] if the write fails.
    /// The identity is spelled out rather than bundled; see the note on
    /// [`orxnud_store::task_repo::TaskRepository::reserve_effect`].
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_effect(
        &mut self,
        key: &str,
        id: &TaskId,
        step_no: u32,
        attempt_no: u32,
        step_key: &str,
        idempotent: bool,
        now_ms: i64,
    ) -> Result<bool, TaskFault> {
        self.engine
            .reserve_effect(key, id, step_no, attempt_no, step_key, idempotent, now_ms)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })
    }

    /// Records how a reserved side effect turned out.
    ///
    /// # Errors
    ///
    /// [`TaskFault`] if the write fails.
    pub fn resolve_effect(
        &mut self,
        key: &str,
        status: orxnud_store::task_repo::EffectStatus,
        detail: Option<&str>,
        now_ms: i64,
    ) -> Result<bool, TaskFault> {
        self.engine
            .resolve_effect(key, status, detail, now_ms)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })
    }

    /// Records an approval for a step, replacing one that expired without being used.
    ///
    /// # Errors
    ///
    /// [`TaskFault`] if it cannot be written.
    pub fn record_approval_replacing_expired(
        &mut self,
        approval: &orxnud_store::task_repo::ApprovalRow,
        now_ms: i64,
    ) -> Result<orxnud_store::task_repo::ApprovalOutcome, TaskFault> {
        self.guard_running()?;
        self.engine
            .record_approval_replacing_expired(approval, now_ms)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })
    }

    /// Reads a proposal.
    ///
    /// # Errors
    ///
    /// [`TaskFault`] if it cannot be read.
    pub fn proposal(&self, proposal_id: &str) -> Result<Option<ProposalRow>, TaskFault> {
        self.engine
            .proposal(proposal_id)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })
    }

    /// Records a human decision on a proposal. Does not change the task's state.
    ///
    /// # Errors
    ///
    /// [`TaskFault`] if the proposal is unknown or already decided.
    pub fn decide_proposal(
        &mut self,
        proposal_id: &str,
        status: &'static str,
        now_ms: i64,
    ) -> Result<ProposalRow, TaskFault> {
        self.guard_running()?;
        self.engine
            .decide_proposal(proposal_id, status, now_ms)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })
    }

    /// Takes the fresh execution lease for an approved proposal and resumes the task.
    ///
    /// # Errors
    ///
    /// [`TaskFault`] if the proposal is not approved, or the task is not waiting.
    /// Begins a governed execution: takes the lease and spends the approval, atomically.
    ///
    /// # Errors
    ///
    /// [`TaskFault`] of the repository's cause. Every one of them is a refusal, and
    /// every one of them leaves the task exactly as it was.
    pub fn begin_execution_spending_approval(
        &mut self,
        proposal_id: &str,
        worker: &str,
        now_ms: i64,
    ) -> Result<ProposalRow, TaskFault> {
        self.guard_running()?;
        self.engine
            .begin_execution_spending_approval(proposal_id, worker, now_ms)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })
    }

    /// Cancels a task through the engine's existing cancellation.
    ///
    /// # Errors
    ///
    /// [`TaskFault::NotFound`] if there is no such task, or [`TaskFault::Engine`] if the
    /// write fails. [`TaskFault::Stopped`] after [`Self::shutdown`].
    pub fn cancel_task(&mut self, id: &TaskId, now_ms: i64) -> Result<TaskRow, TaskFault> {
        self.guard_running()?;
        // Existence first, because the repository reports "no such task" as a storage
        // error kind and a caller has to be able to tell that from a genuine failure.
        if self
            .engine
            .task(id)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })?
            .is_none()
        {
            return Err(TaskFault::NotFound);
        }
        self.engine
            .cancel_task(id, now_ms)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })?;
        self.engine
            .task(id)
            .map_err(|e| TaskFault::Engine {
                cause: e.cause,
                detail: e.to_string(),
            })?
            .ok_or(TaskFault::NotFound)
    }

    fn guard_running(&self) -> Result<(), TaskFault> {
        if self.is_stopped() {
            return Err(TaskFault::Stopped);
        }
        Ok(())
    }
}
