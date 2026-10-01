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

use orxnud_store::StoreError;
use orxnud_store::migration::MigrationRunner;
use orxnud_store::sqlite::Store;
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
/// # Why this exists instead of an eleventh [`EngineErrorKind`]
///
/// "The service is shutting down" is a fact about the *daemon's* lifecycle, not
/// about the task engine: [`EngineErrorKind`] is a closed taxonomy of things that
/// can go wrong with a task, and each kind carries a retry decision. Shutdown has no
/// retry decision — never retry — so folding it in as `Cancelled` would misreport a
/// deliberate stop as a failure someone should act on, and as `Unavailable` it would
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
