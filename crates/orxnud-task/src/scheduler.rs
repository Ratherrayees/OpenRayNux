//! The scheduler: recurring schedules, bounded catch-up, and event-driven wake-up.
//!
//! # Occurrence arithmetic is not reimplemented here
//!
//! Enumeration and misfire resolution live in
//! [`crate::conformance::schedule::catch_up_plan`], which is where ADR-0029's TP-8 and
//! TP-9 are stated and tested. This module *calls* it. A second implementation of
//! DST and catch-up arithmetic would be two answers to the same correctness
//! question, and they would disagree at exactly the edge cases that matter.
//!
//! # No busy polling
//!
//! [`Scheduler::next_wakeup_ms`] returns the earliest instant at which anything
//! could change. A caller sleeps until then rather than polling, so an idle
//! scheduler costs nothing per unit time — which is what makes ADR-0030's "disabled
//! means zero operational cost" achievable for scheduling as well as for
//! capabilities.
//!
//! # The dedup key is the schema
//!
//! Every fire is inserted through
//! [`ScheduleRepository::record_fire_with_task`](orxnud_store::schedule_repo::ScheduleRepository::record_fire_with_task),
//! whose primary key is `(schedule_id, fire_time_ms)`. A fire that already exists
//! is reported, not re-created. That is TP-8's exactly-once guarantee, and it holds
//! across a crash because SQLite serialises writes and the constraint is checked
//! inside the same transaction.
//!
//! # Translating ADR-0021's window into the harness's
//!
//! ADR-0021 decision 3 specifies the catch-up window as **`(last_fired_at, now]`**
//! — closed at the top, so an occurrence due exactly now does fire. The Phase 1
//! harness's `occurrences` takes a window that is **open at both ends**, and
//! pins that in its own test (`the_window_is_half_open`). Both are correct; they
//! are windows with different conventions.
//!
//! The harness is the specification and is not modified, so this module
//! translates: the upper bound passed down is `now_ms + 1`. At millisecond
//! resolution with whole-second cron occurrences that makes the enumeration
//! exactly `(last_fired, now]`. `saturating_add` because a clock near `i64::MAX`
//! must clamp, not wrap into the past and make the window enormous.
//!
//! The alternative — changing `occurrences` to a closed upper bound — would break
//! two Phase 1 assertions that pin the open-ended behaviour, which is the
//! signature of a deliberate convention rather than an oversight.
//!
//! # Catch-up is bounded twice
//!
//! By the schedule's own `catch_up_cap`, and by the engine's ceiling
//! ([`EngineLimits::effective_catch_up_cap`]), which can only *lower* a cap. A
//! schedule cannot raise the documented startup bound. Whatever is dropped is
//! **reported** in [`PassReport::dropped`], because a clamp nobody is told about
//! looks identical to a week of success.

use orxnud_domain::ids::{ScheduleId, TaskId, UserId};
use orxnud_domain::task_state::{MisfirePolicy, ScheduleFire, ScheduleSpec, TaskKind};
use orxnud_store::schedule_repo::{FireInsert, ScheduleRow};

use crate::conformance::schedule::{CatchUpPlan, catch_up_plan};
use crate::engine::DurableEngine;
use crate::error::EngineError;
use crate::limits::EngineLimits;

/// What one scheduler pass did.
///
/// Every number here is *observable*, not inferred. A pass that silently dropped a
/// week of occurrences would satisfy "bounded" while lying about it, which is why
/// `dropped` exists and why it is compared against `total_missed`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PassReport {
    /// The instant this pass ran for.
    pub now_ms: i64,
    /// How many schedules were considered. Bounded by
    /// [`EngineLimits::max_schedules_per_pass`].
    pub schedules_considered: usize,
    /// How many were *skipped* because that bound was reached.
    pub schedules_skipped: usize,
    /// Tasks created by this pass.
    pub tasks_created: usize,
    /// Fires the ledger already contained — dedup working, not an error.
    pub fires_already_present: usize,
    /// Occurrences the misfire policy or the cap dropped.
    pub dropped: usize,
    /// Occurrences that were genuinely missed, before any policy.
    pub total_missed: usize,
    /// Per-schedule detail, so a user can be told *which* schedule lost what.
    pub per_schedule: Vec<SchedulePass>,
}

/// What happened to one schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulePass {
    /// Which schedule.
    pub schedule_id: ScheduleId,
    /// Occurrences that were missed.
    pub missed: usize,
    /// Occurrences fired.
    pub fired: usize,
    /// Occurrences the ledger already held — the dedup working, counted so it is
    /// observable rather than merely absent.
    pub already_present: usize,
    /// Occurrences dropped by policy or cap.
    pub dropped: usize,
    /// How the misfire policy resolved.
    pub outcome: crate::conformance::schedule::MisfireOutcome,
    /// When the next occurrence is due, if one is.
    pub next_wakeup_ms: Option<i64>,
}

/// The scheduler.
///
/// Holds no connection of its own: it borrows the engine's, because ADR-0006
/// documents exactly one writer and a second connection writing schedules would be
/// a second writer.
#[derive(Debug)]
pub struct Scheduler<'a> {
    engine: &'a mut DurableEngine,
    limits: EngineLimits,
}

impl<'a> Scheduler<'a> {
    /// A scheduler over `engine`.
    #[must_use]
    pub fn new(engine: &'a mut DurableEngine) -> Self {
        let limits = engine.limits();
        Self { engine, limits }
    }

    /// Runs one pass, returning what it did.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the store fails. A failure here is
    /// **not** swallowed: a scheduler that could not read its schedules must not
    /// report that it had none, which would look like "no work is due".
    pub fn run_pass(&mut self, now_ms: i64) -> Result<PassReport, EngineError> {
        let mut report = PassReport {
            now_ms,
            ..PassReport::default()
        };

        let enabled = self.engine.schedules().enabled()?;
        report.schedules_considered = enabled.len().min(self.limits.max_schedules_per_pass);
        report.schedules_skipped = enabled.len().saturating_sub(report.schedules_considered);

        // Stable order by id, so two passes over unchanged data perform the same
        // sequence of writes.
        let due: Vec<ScheduleRow> = enabled
            .into_iter()
            .take(report.schedules_considered)
            .collect();

        for schedule in due {
            let pass = self.process_one(&schedule, now_ms)?;
            report.tasks_created += pass.fired;
            report.fires_already_present += pass.already_present;
            report.total_missed += pass.missed;
            report.dropped += pass.dropped;
            report.per_schedule.push(pass);
        }
        Ok(report)
    }

    fn process_one(
        &mut self,
        schedule: &ScheduleRow,
        now_ms: i64,
    ) -> Result<SchedulePass, EngineError> {
        // The catch-up lower bound. `latest_fire` rather than `last_fired_ms`: the
        // ledger is the authority on what has actually happened, and it is what the
        // UNIQUE constraint protects. A schedule that has never fired starts from
        // its creation, not from the epoch — otherwise a new hourly schedule would
        // try to catch up on every occurrence since 1970.
        let lower = match schedule.last_fired_ms {
            Some(ms) => ms,
            None => schedule.created_at_ms,
        };

        // `now_ms + 1`: see the module docs. ADR-0021's window is `(last, now]`;
        // the harness's is open at both ends.
        let window_end = now_ms.saturating_add(1);
        let plan = catch_up_plan(
            &schedule.cron,
            &schedule.timezone,
            lower,
            window_end,
            schedule.misfire,
            self.limits.effective_catch_up_cap(schedule.catch_up_cap) as usize,
        );

        let mut fired = 0usize;
        let mut already = 0usize;
        let mut task_ids: Vec<TaskId> = Vec::with_capacity(plan.to_fire.len());
        for occurrence in &plan.to_fire {
            let task_id = TaskId::new(task_id_for(&schedule.id, occurrence));
            match self.record_fire(schedule, occurrence, &task_id, now_ms)? {
                FireInsert::Inserted => {
                    fired += 1;
                    task_ids.push(task_id);
                }
                FireInsert::AlreadyPresent => already += 1,
            }
        }

        // Advance the ledger only once the fires exist. If it advanced first and
        // the inserts then failed, the window between the new lower bound and the
        // last real fire would be silently skipped.
        if let Some(last) = plan.to_fire.iter().map(|f| f.fire_time_ms).max() {
            self.engine
                .schedules()
                .advance_last_fired(&schedule.id, last)?;
        }

        Ok(SchedulePass {
            schedule_id: schedule.id.clone(),
            missed: plan.total_missed,
            fired,
            already_present: already,
            dropped: plan.skipped,
            outcome: plan.outcome,
            next_wakeup_ms: next_wakeup(&plan, now_ms, schedule),
        })
    }

    fn record_fire(
        &mut self,
        schedule: &ScheduleRow,
        occurrence: &ScheduleFire,
        task_id: &TaskId,
        now_ms: i64,
    ) -> Result<FireInsert, EngineError> {
        let insert = self.engine.schedules().record_fire_with_task(
            &schedule.id,
            occurrence.fire_time_ms,
            occurrence.catch_up,
            task_id,
            now_ms,
        )?;

        // The task is created only for a fire that was actually new. Creating it for
        // an existing fire would give one occurrence two tasks — the duplicate TP-8
        // exists to prevent, arriving by a different route.
        if insert == FireInsert::Inserted {
            let mut task = orxnud_store::task_repo::NewTask::new(
                task_id.clone(),
                TaskKind::ScheduledFire,
                now_ms,
            );
            task.max_attempts = self.limits.max_attempts_default;
            task.schedule_id = Some(schedule.id.clone());
            task.fire_time_ms = Some(occurrence.fire_time_ms);
            task.catch_up = occurrence.catch_up;
            self.engine.enqueue_new(&task, now_ms)?;
        }
        Ok(insert)
    }

    /// The earliest instant at which something could change.
    ///
    /// `None` means nothing is scheduled: a caller should then sleep indefinitely
    /// (or until shutdown) rather than poll. This is what keeps an idle scheduler
    /// free.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the store fails.
    pub fn next_wakeup_ms(&mut self, now_ms: i64) -> Result<Option<i64>, EngineError> {
        let enabled = self.engine.schedules().enabled()?;
        let mut next: Option<i64> = None;
        for schedule in enabled.into_iter().take(self.limits.max_schedules_per_pass) {
            let lower = schedule.last_fired_ms.unwrap_or(schedule.created_at_ms);
            // A plan over a zero-width window yields nothing, which is what we want:
            // we are asking "when is the next occurrence", not "what is overdue".
            let plan = catch_up_plan(
                &schedule.cron,
                &schedule.timezone,
                lower,
                lower,
                schedule.misfire,
                1,
            );
            let candidate = plan
                .all_missed
                .first()
                .map(|f| f.fire_time_ms)
                .or_else(|| next_occurrence_after(&schedule.cron, &schedule.timezone, now_ms));
            if let Some(c) = candidate {
                next = Some(next.map_or(c, |cur: i64| cur.min(c)));
            }
        }
        Ok(next)
    }

    /// Registers a schedule.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `InvalidInput` if the id is taken, or `Storage` if
    /// the write fails.
    pub fn add_schedule(&mut self, spec: &ScheduleSpec, now_ms: i64) -> Result<(), EngineError> {
        self.engine.schedules().insert(spec, now_ms)?;
        Ok(())
    }

    /// Every enabled schedule.
    ///
    /// # Errors
    ///
    /// [`EngineError`] of kind `Storage` if the store fails.
    pub fn schedules(&mut self) -> Result<Vec<ScheduleRow>, EngineError> {
        Ok(self.engine.schedules().enabled()?)
    }
}

/// The task id for one occurrence.
///
/// Derived from `(schedule_id, fire_time_ms)`, so the same occurrence always
/// produces the same id. That makes a repeated pass idempotent at the *task* level
/// too: even if the fire ledger were lost, re-deriving the id would collide with
/// the existing task rather than creating a second one.
fn task_id_for(schedule: &ScheduleId, occurrence: &ScheduleFire) -> String {
    format!("sched-{}-{}", schedule.as_str(), occurrence.fire_time_ms)
}

/// When a schedule should next wake up.
fn next_wakeup(plan: &CatchUpPlan, now_ms: i64, schedule: &ScheduleRow) -> Option<i64> {
    plan.to_fire
        .iter()
        .map(|f| f.fire_time_ms)
        .filter(|ms| *ms > now_ms)
        .min()
        .or_else(|| {
            // Nothing due inside the window: look past `now`.
            next_occurrence_after(&schedule.cron, &schedule.timezone, now_ms)
        })
}

/// The first occurrence strictly after `now_ms`, or `None`.
///
/// `None` for an expression croner cannot parse is deliberate — a malformed
/// schedule must not become a busy loop, and it must not become a silent
/// "never fires" either. The parse failure surfaces the first time the schedule is
/// read, and the row stays in the table for a human to fix.
fn next_occurrence_after(cron: &str, timezone: &str, now_ms: i64) -> Option<i64> {
    let zone = jiff::tz::TimeZone::get(timezone).ok()?;
    let schedule: croner::Cron = cron.parse().ok()?;
    let from = jiff::Timestamp::from_millisecond(now_ms).ok()?;
    let start = from.to_zoned(zone);
    schedule
        .iter_after(start)
        .next()
        .map(|z| z.timestamp().as_millisecond())
}

/// Whether a policy would run nothing at all, for a schedule in this state.
///
/// Used by a caller deciding whether to warn a user, and by tests. Kept here so the
/// knowledge lives next to the pass that applies it.
#[must_use]
pub fn policy_runs_nothing(policy: MisfirePolicy) -> bool {
    matches!(policy, MisfirePolicy::Pause)
}

/// Builds a schedule specification with the documented defaults.
///
/// # Errors
///
/// [`EngineError`] of kind `InvalidInput` if the cron expression or timezone is
/// invalid — checked here so an invalid schedule is refused at the point it is
/// created rather than at 3am on the first pass that tries to use it.
pub fn new_schedule(
    id: &str,
    cron: &str,
    timezone: &str,
    authorised_by: &str,
    limits: EngineLimits,
) -> Result<ScheduleSpec, EngineError> {
    cron.parse::<croner::Cron>()
        .map_err(|e| EngineError::invalid(format!("invalid cron {cron:?}: {e}")))?;
    jiff::tz::TimeZone::get(timezone)
        .map_err(|e| EngineError::invalid(format!("invalid timezone {timezone:?}: {e}")))?;
    Ok(ScheduleSpec {
        id: ScheduleId::new(id),
        cron: cron.to_owned(),
        timezone: timezone.to_owned(),
        misfire: MisfirePolicy::FireOnce,
        catch_up_cap: limits.catch_up_cap,
        enabled: true,
        authorised_by: UserId::new(authorised_by),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_store::migration::MigrationRunner;
    use orxnud_store::pragma::Pragma;

    const NOW: i64 = 1_767_225_600_000; // 2026-01-01T00:00:00Z
    const HOUR: i64 = 3_600_000;

    fn engine() -> DurableEngine {
        let c = rusqlite::Connection::open_in_memory().expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        MigrationRunner::new(&c).run(true).expect("migrate");
        DurableEngine::new(c, EngineLimits::documented()).expect("engine")
    }

    fn limits() -> EngineLimits {
        EngineLimits::documented()
    }

    /// A schedule created `created_ms` ago.
    fn spec(id: &str, cron: &str, tz: &str, _created_ms: i64) -> ScheduleSpec {
        ScheduleSpec {
            id: ScheduleId::new(id),
            cron: cron.to_owned(),
            timezone: tz.to_owned(),
            misfire: MisfirePolicy::FireAll,
            catch_up_cap: 100,
            enabled: true,
            authorised_by: UserId::new("u"),
        }
    }

    #[test]
    fn a_new_schedule_produces_no_tasks_until_its_first_occurrence() {
        let mut e = engine();
        e.schedules()
            .insert(&spec("s", "0 * * * *", "UTC", NOW), NOW)
            .expect("insert");
        let report = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
        assert_eq!(
            report.tasks_created, 0,
            "nothing is due at the creation instant"
        );
        assert_eq!(report.per_schedule.len(), 1);
        assert_eq!(report.per_schedule[0].missed, 0);
    }

    #[test]
    fn a_due_occurrence_creates_exactly_one_task() {
        let mut e = engine();
        // Created an hour ago, so 00:00 of the following hour is due at `NOW`.
        e.schedules()
            .insert(&spec("s", "0 * * * *", "UTC", NOW - HOUR), NOW - HOUR)
            .expect("insert");
        let report = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
        assert_eq!(report.tasks_created, 1);
        assert_eq!(report.total_missed, 1);
        assert_eq!(report.fires_already_present, 0);

        let tasks = e.all_tasks().expect("tasks");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].kind, TaskKind::ScheduledFire);
        assert!(
            tasks[0].catch_up,
            "a fire produced after the fact is catch-up"
        );
        assert_eq!(tasks[0].schedule_id, Some(ScheduleId::new("s")));
    }

    #[test]
    fn a_second_pass_over_the_same_window_creates_nothing() {
        // TP-8: the same occurrence must not fire twice, however many passes run.
        let mut e = engine();
        e.schedules()
            .insert(&spec("s", "0 * * * *", "UTC", NOW - HOUR), NOW - HOUR)
            .expect("insert");
        let first = Scheduler::new(&mut e).run_pass(NOW).expect("first");
        assert_eq!(first.tasks_created, 1);
        // The ledger advanced to the occurrence just fired, so the next pass's window
        // starts *after* it. Nothing is due, and nothing is duplicated.
        let second = Scheduler::new(&mut e).run_pass(NOW).expect("second");
        assert_eq!(
            second.tasks_created, 0,
            "a repeated pass must create nothing"
        );
        assert_eq!(second.total_missed, 0);
        assert_eq!(e.all_tasks().expect("tasks").len(), 1);
    }

    #[test]
    fn an_overlapping_window_is_deduplicated_by_the_ledger() {
        // The dedup path, forced rather than assumed: the ledger is rewound so the
        // next pass's window covers an occurrence that already fired. This is the
        // state after a crash between the fire insert and the ledger update, and it
        // must not produce a second task.
        let mut e = engine();
        e.schedules()
            .insert(&spec("s", "0 * * * *", "UTC", NOW - HOUR), NOW - HOUR)
            .expect("insert");
        assert_eq!(
            Scheduler::new(&mut e)
                .run_pass(NOW)
                .expect("first")
                .tasks_created,
            1
        );

        // Rewind the ledger. The fire row is still there -- that is the point.
        e.conn_mut()
            .execute(
                "UPDATE schedules SET last_fired_ms = NULL WHERE id = 's';",
                [],
            )
            .expect("rewind");
        let again = Scheduler::new(&mut e).run_pass(NOW + 1).expect("second");
        assert_eq!(again.tasks_created, 0, "the fire already exists");
        assert_eq!(again.fires_already_present, 1, "and the pass says so");
        assert_eq!(
            e.all_tasks().expect("tasks").len(),
            1,
            "still exactly one task"
        );
    }

    #[test]
    fn two_schedules_firing_at_the_same_instant_each_get_a_task() {
        let mut e = engine();
        e.schedules()
            .insert(&spec("a", "0 * * * *", "UTC", NOW - HOUR), NOW - HOUR)
            .expect("a");
        e.schedules()
            .insert(&spec("b", "0 * * * *", "UTC", NOW - HOUR), NOW - HOUR)
            .expect("b");
        let report = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
        assert_eq!(
            report.tasks_created, 2,
            "the dedup key includes the schedule"
        );
    }

    #[test]
    fn a_week_of_backlog_is_clamped_and_the_clamp_is_reported() {
        // TP-9: bounded, and *visibly* bounded.
        let mut e = DurableEngine::new(
            {
                let c = rusqlite::Connection::open_in_memory().expect("open");
                Pragma::critical().apply(&c).expect("pragmas");
                MigrationRunner::new(&c).run(true).expect("migrate");
                c
            },
            EngineLimits {
                catch_up_cap: 10,
                ..EngineLimits::documented()
            },
        )
        .expect("engine");
        let week = 7 * 24 * HOUR;
        e.schedules()
            .insert(&spec("s", "0 * * * *", "UTC", NOW - week), NOW - week)
            .expect("insert");
        let report = Scheduler::new(&mut e).run_pass(NOW).expect("pass");

        assert!(
            report.total_missed >= 168,
            "a week of hourly fires should be seen"
        );
        assert_eq!(report.tasks_created, 10, "the cap must bind");
        assert_eq!(report.dropped, report.total_missed - 10);
        // The crucial half: the drop is *counted*, not silently swallowed.
        assert!(report.dropped > 0);
        assert_eq!(report.per_schedule[0].dropped, report.dropped);
    }

    #[test]
    fn each_misfire_policy_behaves_as_documented() {
        let week = 7 * 24 * HOUR;
        for (policy, expect_fires) in [
            (MisfirePolicy::FireAll, true),
            (MisfirePolicy::FireOnce, true),
            (MisfirePolicy::FireNextOnly, true),
            (MisfirePolicy::SkipIfOlderMinutes(60), true),
            (MisfirePolicy::Pause, false),
        ] {
            let mut e = engine();
            let mut s = spec("s", "0 * * * *", "UTC", NOW - week);
            s.misfire = policy;
            e.schedules().insert(&s, NOW - week).expect("insert");
            let report = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
            let created = report.tasks_created;
            assert_eq!(
                created > 0,
                expect_fires,
                "{policy:?} produced {created} fires"
            );
            let pass = &report.per_schedule[0];
            if created == 0 {
                assert_eq!(
                    pass.outcome,
                    crate::conformance::schedule::MisfireOutcome::Paused
                );
                assert!(
                    pass.dropped > 0,
                    "{policy:?} dropped nothing but fired nothing"
                );
            }
        }
    }

    #[test]
    fn a_paused_schedule_fires_nothing_and_says_so() {
        let mut e = engine();
        let mut s = spec("s", "0 * * * *", "UTC", NOW - HOUR);
        s.misfire = MisfirePolicy::Pause;
        e.schedules().insert(&s, NOW - HOUR).expect("insert");
        let report = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
        assert_eq!(report.tasks_created, 0);
        assert_eq!(
            report.per_schedule[0].outcome,
            crate::conformance::schedule::MisfireOutcome::Paused
        );
        assert!(
            report.per_schedule[0].dropped > 0,
            "silence must be reported"
        );
        assert!(policy_runs_nothing(MisfirePolicy::Pause));
        assert!(!policy_runs_nothing(MisfirePolicy::FireAll));
    }

    #[test]
    fn a_disabled_schedule_is_never_considered() {
        let mut e = engine();
        let mut s = spec("s", "0 * * * *", "UTC", NOW - HOUR);
        s.enabled = false;
        e.schedules().insert(&s, NOW - HOUR).expect("insert");
        let report = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
        assert_eq!(report.schedules_considered, 0);
        assert_eq!(report.tasks_created, 0);
    }

    #[test]
    fn the_schedule_loop_is_bounded_and_reports_what_it_skipped() {
        let mut e = DurableEngine::new(
            {
                let c = rusqlite::Connection::open_in_memory().expect("open");
                Pragma::critical().apply(&c).expect("pragmas");
                MigrationRunner::new(&c).run(true).expect("migrate");
                c
            },
            EngineLimits {
                max_schedules_per_pass: 3,
                ..EngineLimits::documented()
            },
        )
        .expect("engine");
        for i in 0..10 {
            e.schedules()
                .insert(
                    &spec(&format!("s{i}"), "0 * * * *", "UTC", NOW - HOUR),
                    NOW - HOUR,
                )
                .expect("insert");
        }
        let report = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
        assert_eq!(report.schedules_considered, 3);
        assert_eq!(report.schedules_skipped, 7, "a truncation must be visible");
    }

    #[test]
    fn the_wakeup_time_is_the_earliest_due_instant() {
        let mut e = engine();
        e.schedules()
            .insert(&spec("late", "0 23 * * *", "UTC", NOW), NOW)
            .expect("late");
        e.schedules()
            .insert(&spec("early", "30 * * * *", "UTC", NOW), NOW)
            .expect("early");
        let next = Scheduler::new(&mut e).next_wakeup_ms(NOW).expect("next");
        let n = next.expect("a schedule exists, so a wakeup must exist");
        assert!(n > NOW, "the wakeup must be in the future: {n}");
        assert!(n < NOW + HOUR, "and within the hour: {n}");
    }

    #[test]
    fn no_schedules_means_no_wakeup_rather_than_a_poll() {
        // An idle scheduler must be able to sleep forever, not poll.
        let mut e = engine();
        assert_eq!(
            Scheduler::new(&mut e).next_wakeup_ms(NOW).expect("next"),
            None
        );
        let report = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
        assert_eq!(report.schedules_considered, 0);
        assert_eq!(report.tasks_created, 0);
    }

    #[test]
    fn the_wakeup_time_moves_forward_as_time_passes() {
        let mut e = engine();
        e.schedules()
            .insert(&spec("s", "0 * * * *", "UTC", NOW), NOW)
            .expect("insert");
        let first = Scheduler::new(&mut e)
            .next_wakeup_ms(NOW)
            .expect("first")
            .expect("some");
        let second = Scheduler::new(&mut e)
            .next_wakeup_ms(first)
            .expect("second")
            .expect("some");
        assert!(second > first, "{second} should be after {first}");
    }

    #[test]
    fn a_malformed_cron_or_zone_is_refused_at_creation() {
        // Refused here rather than at 3am on the first pass that uses it.
        let err = new_schedule("s", "not a cron", "UTC", "u", limits()).expect_err("must refuse");
        assert_eq!(err.kind, crate::EngineErrorKind::InvalidInput);
        let err =
            new_schedule("s", "0 * * * *", "Not/AZone", "u", limits()).expect_err("must refuse");
        assert_eq!(err.kind, crate::EngineErrorKind::InvalidInput);
    }

    #[test]
    fn a_valid_schedule_is_accepted_and_uses_the_documented_cap() {
        let s = new_schedule("s", "0 9 * * 1-5", "Europe/Berlin", "u", limits()).expect("valid");
        assert_eq!(s.cron, "0 9 * * 1-5");
        assert_eq!(s.timezone, "Europe/Berlin");
        assert_eq!(s.catch_up_cap, limits().catch_up_cap);
        assert_eq!(s.authorised_by, UserId::new("u"));
    }

    #[test]
    fn the_task_id_is_derived_from_the_schedule_and_fire_time() {
        // Deterministic, so a replayed pass collides with the existing task rather
        // than creating a second one.
        let fire = ScheduleFire {
            schedule: ScheduleId::new("s"),
            fire_time_ms: 42,
            catch_up: false,
        };
        let a = task_id_for(&ScheduleId::new("s"), &fire);
        let b = task_id_for(&ScheduleId::new("s"), &fire);
        assert_eq!(a, b);
        assert!(a.contains("42"), "{a}");
        assert_ne!(a, task_id_for(&ScheduleId::new("other"), &fire));
    }

    #[test]
    fn a_dst_transition_produces_the_documented_number_of_fires() {
        // ADR-0021's table, checked through the scheduler rather than only in the
        // property test. Berlin spring-forward 2026-03-29: a daily 02:30 job still
        // runs exactly once.
        let mut e = engine();
        let day = 1_774_738_800_000; // 2026-03-29T00:00 local
        e.schedules()
            .insert(&spec("dst", "30 2 * * *", "Europe/Berlin", day), day)
            .expect("insert");
        let report = Scheduler::new(&mut e)
            .run_pass(day + 86_400_000)
            .expect("pass");
        assert_eq!(
            report.tasks_created, 1,
            "a fixed-time job fires once across the gap, not zero and not twice"
        );
    }

    #[test]
    fn a_fall_back_transition_fires_once_not_twice() {
        // The duplicated hour is the case where "run for each occurrence" would
        // double-execute a daily job.
        let mut e = engine();
        let day = 1_792_879_200_000; // 2026-10-25T00:00 local
        e.schedules()
            .insert(&spec("dst", "30 2 * * *", "Europe/Berlin", day), day)
            .expect("insert");
        let report = Scheduler::new(&mut e)
            .run_pass(day + 86_400_000)
            .expect("pass");
        assert_eq!(
            report.tasks_created, 1,
            "a fixed-time job fires once across the overlap"
        );
    }

    #[test]
    fn every_fire_is_linked_to_its_task() {
        // A fire with no task is a fire that produced no work -- TP-1's silent
        // disappearance, arriving through the scheduler instead of the queue.
        let mut e = engine();
        e.schedules()
            .insert(&spec("s", "0 * * * *", "UTC", NOW - HOUR), NOW - HOUR)
            .expect("insert");
        let _ = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
        let linked: i64 = e
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM schedule_fires WHERE task_id IS NOT NULL;",
                [],
                |r| r.get(0),
            )
            .expect("query");
        assert_eq!(linked, 1, "every fire must name the task it created");
    }

    #[test]
    fn a_backwards_clock_jump_does_not_re_fire() {
        // TP-8: "does not cause a task to be lost, duplicated, or executed an
        // unbounded number of times". `advance_last_fired` only moves forward, and
        // the UNIQUE key rejects a repeat.
        let mut e = engine();
        e.schedules()
            .insert(&spec("s", "0 * * * *", "UTC", NOW - HOUR), NOW - HOUR)
            .expect("insert");
        let _ = Scheduler::new(&mut e).run_pass(NOW).expect("first");
        let jumped_back = Scheduler::new(&mut e)
            .run_pass(NOW - HOUR / 2)
            .expect("back");
        assert_eq!(
            jumped_back.tasks_created, 0,
            "a backwards jump must not re-fire"
        );
        assert_eq!(e.all_tasks().expect("tasks").len(), 1);
    }

    #[test]
    fn a_schedule_inserted_twice_is_refused() {
        let mut e = engine();
        let s = spec("s", "0 * * * *", "UTC", NOW);
        let mut sched = Scheduler::new(&mut e);
        sched.add_schedule(&s, NOW).expect("first");
        assert!(sched.add_schedule(&s, NOW).is_err());
    }

    #[test]
    fn the_scheduler_lists_only_enabled_schedules() {
        let mut e = engine();
        let mut sched = Scheduler::new(&mut e);
        sched
            .add_schedule(&spec("on", "0 * * * *", "UTC", NOW), NOW)
            .expect("on");
        let mut off = spec("off", "0 * * * *", "UTC", NOW);
        off.enabled = false;
        sched.add_schedule(&off, NOW).expect("off");
        let listed = sched.schedules().expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, ScheduleId::new("on"));
    }
}
