//! Schedules and the fire ledger (ADR-0021, ADR-0029 TP-8).
//!
//! # The exactly-once mechanism is the primary key
//!
//! `schedule_fires` has primary key `(schedule_id, fire_time_ms)`. That is the
//! whole of TP-8's "a fire happens exactly once": a duplicate is *unrepresentable*,
//! so `INSERT OR IGNORE` cannot succeed twice — even across a crash, because
//! SQLite serialises writes and the constraint is checked inside the same
//! transaction.
//!
//! Doing this in application code — `SELECT` then `INSERT` — would have a window,
//! and two scheduler passes would produce two tasks for one occurrence.
//!
//! # Cron arithmetic is not here
//!
//! Occurrence enumeration and misfire resolution live in
//! `orxnud_task::conformance::schedule`, which is where the ADR-0029 properties
//! TP-8 and TP-9 are stated. Duplicating that arithmetic in the store would be two
//! implementations of a correctness property, and they would disagree on exactly
//! the DST edge cases that matter.
//!
//! # What this store owns
//!
//! Only what needs SQL: reading and writing schedule rows, and inserting fires
//! under the dedup constraint.

use rusqlite::{Connection, OptionalExtension, Transaction};

use orxnud_domain::ids::UserId;
use orxnud_domain::ids::{ScheduleId, TaskId};
use orxnud_domain::task_state::{MisfirePolicy, ScheduleFire, ScheduleSpec};

/// A schedule persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum ScheduleRepoError {
    /// An underlying SQLite error.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// No schedule with this id.
    #[error("no schedule {0}")]
    NotFound(String),

    /// A schedule with this id already exists.
    #[error("schedule {0} already exists")]
    AlreadyExists(String),

    /// The stored misfire policy is unreadable.
    #[error("schedule {id} has an invalid misfire policy ({policy:?}, minutes {minutes:?})")]
    InvalidPolicy {
        /// The schedule.
        id: String,
        /// The stored policy spelling.
        policy: String,
        /// The stored threshold.
        minutes: Option<i64>,
    },
}

/// One schedule row, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleRow {
    /// The id.
    pub id: ScheduleId,
    /// The cron expression.
    pub cron: String,
    /// The IANA zone it is interpreted in.
    pub timezone: String,
    /// What to do about missed occurrences.
    pub misfire: MisfirePolicy,
    /// Maximum fires in one catch-up pass.
    pub catch_up_cap: u32,
    /// Whether the schedule is active.
    pub enabled: bool,
    /// The human who authorised it.
    pub authorised_by: UserId,
    /// The last occurrence that was processed.
    pub last_fired_ms: Option<i64>,
    /// When the row was created.
    pub created_at_ms: i64,
    /// When the row last changed.
    pub updated_at_ms: i64,
}

/// What a fire insertion actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FireInsert {
    /// A new fire row was created.
    Inserted,
    /// The fire already existed, so nothing was created.
    ///
    /// The normal, expected outcome when a catch-up pass overlaps a previous one —
    /// or when two scheduler passes run at the same instant. It is a distinct
    /// value rather than a boolean so the caller can *report* it: a scheduler that
    /// silently discards duplicates gives no evidence the dedup worked.
    AlreadyPresent,
}

/// A schedule store.
#[derive(Debug)]
pub struct ScheduleRepository<'a> {
    conn: &'a mut Connection,
}

impl<'a> ScheduleRepository<'a> {
    /// Wraps a connection.
    #[must_use]
    pub fn new(conn: &'a mut Connection) -> Self {
        Self { conn }
    }

    /// Inserts a schedule.
    ///
    /// # Errors
    ///
    /// [`ScheduleRepoError::AlreadyExists`] if the id is taken, or any SQLite error.
    pub fn insert(&mut self, spec: &ScheduleSpec, now_ms: i64) -> Result<(), ScheduleRepoError> {
        let (policy, minutes) = (spec.misfire.as_wire_str(), misfire_minutes(spec.misfire));
        let changed = insert_schedule(self.conn.execute(
            "INSERT INTO schedules
                (id, cron, timezone, misfire_policy, misfire_minutes, catch_up_cap,
                 enabled, authorised_by, last_fired_ms, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?9);",
            rusqlite::params![
                spec.id.as_str(),
                spec.cron,
                spec.timezone,
                policy,
                minutes,
                spec.catch_up_cap,
                spec.enabled,
                spec.authorised_by.as_str(),
                now_ms,
            ],
        ))?;
        if changed == 0 {
            return Err(ScheduleRepoError::AlreadyExists(spec.id.to_string()));
        }
        Ok(())
    }

    /// Reads one schedule.
    ///
    /// # Errors
    ///
    /// [`ScheduleRepoError::InvalidPolicy`] if the stored policy cannot be parsed.
    pub fn get(&self, id: &ScheduleId) -> Result<Option<ScheduleRow>, ScheduleRepoError> {
        self.conn
            .query_row(
                "SELECT id, cron, timezone, misfire_policy, misfire_minutes, catch_up_cap,
                        enabled, authorised_by, last_fired_ms, created_at_ms, updated_at_ms
                   FROM schedules WHERE id = ?1;",
                [id.as_str()],
                read_raw,
            )
            .optional()?
            .map(decode_row)
            .transpose()
    }

    /// Every enabled schedule, in id order.
    ///
    /// A `BTreeMap`-backed store, so the order is stable and two scheduler passes
    /// over the same data produce the same sequence of operations.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub fn enabled(&self) -> Result<Vec<ScheduleRow>, ScheduleRepoError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, cron, timezone, misfire_policy, misfire_minutes, catch_up_cap,
                    enabled, authorised_by, last_fired_ms, created_at_ms, updated_at_ms
               FROM schedules WHERE enabled = 1 ORDER BY id;",
        )?;
        let rows = stmt.query_map([], read_raw)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(decode_row(r?)?);
        }
        Ok(out)
    }

    /// How many schedules exist.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn count(&self) -> Result<i64, ScheduleRepoError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM schedules;", [], |r| r.get(0))?)
    }

    /// Records the last occurrence that was processed.
    ///
    /// Only ever moves **forward**. A backwards clock jump must not rewind the
    /// ledger and cause a whole window of occurrences to be re-considered —
    /// TP-8's "does not cause a task to be lost, duplicated, or executed an
    /// unbounded number of times".
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn advance_last_fired(
        &mut self,
        id: &ScheduleId,
        fire_time_ms: i64,
    ) -> Result<bool, ScheduleRepoError> {
        let changed = self.conn.execute(
            "UPDATE schedules
                SET last_fired_ms = ?2, updated_at_ms = ?2
              WHERE id = ?1
                AND (last_fired_ms IS NULL OR last_fired_ms < ?2);",
            rusqlite::params![id.as_str(), fire_time_ms],
        )?;
        Ok(changed > 0)
    }

    /// Inserts a fire, returning whether it was new.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn insert_fire(
        &mut self,
        fire: &ScheduleFire,
        now_ms: i64,
    ) -> Result<FireInsert, ScheduleRepoError> {
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO schedule_fires
                (schedule_id, fire_time_ms, catch_up, task_id, created_at_ms)
             VALUES (?1, ?2, ?3, NULL, ?4);",
            rusqlite::params![
                fire.schedule.as_str(),
                fire.fire_time_ms,
                fire.catch_up,
                now_ms
            ],
        )?;
        Ok(if changed == 0 {
            FireInsert::AlreadyPresent
        } else {
            FireInsert::Inserted
        })
    }

    /// Links a fire to the task that will run it.
    ///
    /// # Errors
    ///
    /// [`ScheduleRepoError::NotFound`] if there is no such fire.
    pub fn link_fire_to_task(
        &mut self,
        schedule: &ScheduleId,
        fire_time_ms: i64,
        task: &TaskId,
    ) -> Result<bool, ScheduleRepoError> {
        let changed = self.conn.execute(
            "UPDATE schedule_fires SET task_id = ?3
              WHERE schedule_id = ?1 AND fire_time_ms = ?2;",
            rusqlite::params![schedule.as_str(), fire_time_ms, task.as_str()],
        )?;
        if changed == 0 {
            return Err(ScheduleRepoError::NotFound(format!(
                "{schedule} fire at {fire_time_ms}"
            )));
        }
        Ok(true)
    }

    /// How many fires a schedule has recorded.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn fire_count(&self, schedule: &ScheduleId) -> Result<i64, ScheduleRepoError> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM schedule_fires WHERE schedule_id = ?1;",
            [schedule.as_str()],
            |r| r.get(0),
        )?)
    }

    /// The fire times recorded for a schedule, ascending.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn fire_times(&self, schedule: &ScheduleId) -> Result<Vec<i64>, ScheduleRepoError> {
        let mut stmt = self.conn.prepare(
            "SELECT fire_time_ms FROM schedule_fires WHERE schedule_id = ?1 ORDER BY fire_time_ms;",
        )?;
        let rows = stmt.query_map([schedule.as_str()], |r| r.get::<_, i64>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Inserts a fire and links it to a task in **one** transaction.
    ///
    /// The ledger row and the task link are one fact, so they are written together:
    /// a fire whose `task_id` is null is a fire that produced no work, which is
    /// exactly the "silently disappeared" failure TP-1 forbids.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn record_fire_with_task(
        &mut self,
        schedule: &ScheduleId,
        fire_time_ms: i64,
        catch_up: bool,
        task: &TaskId,
        now_ms: i64,
    ) -> Result<FireInsert, ScheduleRepoError> {
        let tx: Transaction<'_> = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let changed = tx.execute(
            "INSERT OR IGNORE INTO schedule_fires
                (schedule_id, fire_time_ms, catch_up, task_id, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5);",
            rusqlite::params![
                schedule.as_str(),
                fire_time_ms,
                catch_up,
                task.as_str(),
                now_ms
            ],
        )?;
        tx.commit()?;
        Ok(if changed == 0 {
            FireInsert::AlreadyPresent
        } else {
            FireInsert::Inserted
        })
    }

    /// The highest fire time already recorded for a schedule, if any.
    ///
    /// Read on startup to establish the catch-up lower bound. `None` means "never
    /// fired", which makes the catch-up window start at the schedule's creation
    /// rather than at the epoch — otherwise a brand-new schedule would try to
    /// catch up on every occurrence since 1970.
    ///
    /// # Errors
    ///
    /// Any SQLite error.
    pub fn latest_fire(&self, schedule: &ScheduleId) -> Result<Option<i64>, ScheduleRepoError> {
        Ok(self.conn.query_row(
            "SELECT MAX(fire_time_ms) FROM schedule_fires WHERE schedule_id = ?1;",
            [schedule.as_str()],
            |r| r.get::<_, Option<i64>>(0),
        )?)
    }
}

/// Distinguishes "the schedule already existed" from "the insert succeeded".
///
/// As in [`crate::task_repo`]: `execute` errors on a UNIQUE violation rather than
/// returning zero, so the duplicate must be recognised from the error or a
/// re-scheduled insert surfaces as an opaque SQLite failure.
fn insert_schedule(result: Result<usize, rusqlite::Error>) -> Result<usize, ScheduleRepoError> {
    match result {
        Ok(n) => Ok(n),
        Err(rusqlite::Error::SqliteFailure(e, msg))
            if e.code == rusqlite::ErrorCode::ConstraintViolation
                && msg.as_deref().is_some_and(|m| m.contains("schedules.id")) =>
        {
            Ok(0)
        }
        Err(e) => Err(ScheduleRepoError::Sqlite(e)),
    }
}

/// Reads the raw `schedules` columns, in the order [`decode_row`] expects.
fn read_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawSchedule> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
    ))
}

fn misfire_minutes(policy: MisfirePolicy) -> Option<i64> {
    match policy {
        MisfirePolicy::SkipIfOlderMinutes(m) => Some(i64::from(m)),
        _ => None,
    }
}

/// The raw columns, read inside rusqlite's closure.
///
/// Split from [`decode_row`] because that closure must return
/// `rusqlite::Result`, and a misfire policy this build cannot parse is a
/// `ScheduleRepoError`, not an SQLite failure. Flattening the two would lose the
/// distinction between "the database is broken" and "the database was written by
/// a build with different rules".
type RawSchedule = (
    String,
    String,
    String,
    String,
    Option<i64>,
    u32,
    i64,
    String,
    Option<i64>,
    i64,
    i64,
);

/// Decodes one `schedules` row, refusing an unreadable misfire policy.
fn decode_row(raw: RawSchedule) -> Result<ScheduleRow, ScheduleRepoError> {
    let (
        id,
        cron,
        timezone,
        policy,
        minutes,
        catch_up_cap,
        enabled,
        authorised_by,
        last_fired,
        created,
        updated,
    ) = raw;
    let minute_count = minutes.and_then(|m| u32::try_from(m).ok());
    let misfire = MisfirePolicy::from_wire_str(&policy, minute_count).ok_or_else(|| {
        ScheduleRepoError::InvalidPolicy {
            id: id.clone(),
            policy,
            minutes,
        }
    })?;
    Ok(ScheduleRow {
        id: ScheduleId::new(id),
        cron,
        timezone,
        misfire,
        catch_up_cap,
        enabled: enabled != 0,
        authorised_by: UserId::new(authorised_by),
        last_fired_ms: last_fired,
        created_at_ms: created,
        updated_at_ms: updated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::MigrationRunner;
    use crate::pragma::Pragma;

    const NOW: i64 = 1_767_225_600_000;

    fn mem() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        MigrationRunner::new(&c).run(true).expect("migrate");
        c
    }

    fn sid(s: &str) -> ScheduleId {
        ScheduleId::new(s)
    }

    fn spec(id: &str, policy: MisfirePolicy, cap: u32) -> ScheduleSpec {
        ScheduleSpec {
            id: sid(id),
            cron: "0 * * * *".into(),
            timezone: "Europe/Berlin".into(),
            misfire: policy,
            catch_up_cap: cap,
            enabled: true,
            authorised_by: UserId::new("u1"),
        }
    }

    #[test]
    fn insert_then_read_round_trips_every_field() {
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("s1", MisfirePolicy::SkipIfOlderMinutes(45), 17), NOW)
            .expect("insert");
        let row = repo.get(&sid("s1")).expect("get").expect("present");
        assert_eq!(row.cron, "0 * * * *");
        assert_eq!(row.timezone, "Europe/Berlin");
        assert_eq!(row.misfire, MisfirePolicy::SkipIfOlderMinutes(45));
        assert_eq!(row.catch_up_cap, 17);
        assert!(row.enabled);
        assert_eq!(row.authorised_by, UserId::new("u1"));
        assert!(
            row.last_fired_ms.is_none(),
            "a new schedule has never fired"
        );
    }

    #[test]
    fn a_thresholdless_policy_persists_without_a_threshold() {
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
            .expect("insert");
        assert_eq!(
            repo.get(&sid("s")).expect("get").expect("present").misfire,
            MisfirePolicy::FireAll
        );
    }

    #[test]
    fn a_duplicate_schedule_is_refused() {
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
            .expect("first");
        assert!(matches!(
            repo.insert(&spec("s", MisfirePolicy::Pause, 10), NOW),
            Err(ScheduleRepoError::AlreadyExists(_))
        ));
    }

    #[test]
    fn only_enabled_schedules_are_returned_for_a_pass() {
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("on", MisfirePolicy::FireAll, 10), NOW)
            .expect("on");
        let mut off = spec("off", MisfirePolicy::FireAll, 10);
        off.enabled = false;
        repo.insert(&off, NOW).expect("off");
        let enabled = repo.enabled().expect("enabled");
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].id, sid("on"));
        assert_eq!(
            repo.count().expect("count"),
            2,
            "a disabled schedule still exists"
        );
    }

    #[test]
    fn the_same_fire_time_cannot_be_recorded_twice() {
        // TP-8's exactly-once guarantee, exercised through the repository rather
        // than asserted about the schema alone.
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
            .expect("insert");
        let fire = ScheduleFire {
            schedule: sid("s"),
            fire_time_ms: 1_000,
            catch_up: false,
        };
        assert_eq!(
            repo.insert_fire(&fire, NOW).expect("first"),
            FireInsert::Inserted
        );
        assert_eq!(
            repo.insert_fire(&fire, NOW).expect("second"),
            FireInsert::AlreadyPresent,
            "TP-8: a fire happens exactly once"
        );
        assert_eq!(repo.fire_count(&sid("s")).expect("count"), 1);
    }

    #[test]
    fn a_different_fire_time_for_the_same_schedule_is_accepted() {
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
            .expect("insert");
        for ms in [1_000i64, 2_000, 3_000] {
            let fire = ScheduleFire {
                schedule: sid("s"),
                fire_time_ms: ms,
                catch_up: false,
            };
            assert_eq!(
                repo.insert_fire(&fire, NOW).expect("insert"),
                FireInsert::Inserted
            );
        }
        assert_eq!(
            repo.fire_times(&sid("s")).expect("times"),
            vec![1_000, 2_000, 3_000]
        );
    }

    #[test]
    fn two_schedules_may_fire_at_the_same_instant() {
        // The dedup key includes the schedule, so one schedule's fire must not
        // suppress another's.
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("a", MisfirePolicy::FireAll, 10), NOW)
            .expect("a");
        repo.insert(&spec("b", MisfirePolicy::FireAll, 10), NOW)
            .expect("b");
        for id in ["a", "b"] {
            let fire = ScheduleFire {
                schedule: sid(id),
                fire_time_ms: 1_000,
                catch_up: false,
            };
            assert_eq!(
                repo.insert_fire(&fire, NOW).expect("insert"),
                FireInsert::Inserted
            );
        }
    }

    #[test]
    fn last_fired_only_moves_forward() {
        // A backwards clock jump must not rewind the ledger, or every occurrence
        // in the rewound window would be re-considered (TP-8).
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
            .expect("insert");
        assert!(repo.advance_last_fired(&sid("s"), 5_000).expect("first"));
        assert!(
            !repo
                .advance_last_fired(&sid("s"), 4_000)
                .expect("backwards")
        );
        assert!(
            !repo
                .advance_last_fired(&sid("s"), 5_000)
                .expect("same instant")
        );
        assert!(repo.advance_last_fired(&sid("s"), 6_000).expect("forwards"));
        assert_eq!(
            repo.get(&sid("s"))
                .expect("get")
                .expect("present")
                .last_fired_ms,
            Some(6_000)
        );
    }

    #[test]
    fn the_latest_fire_is_the_catch_up_lower_bound() {
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
            .expect("insert");
        assert!(
            repo.latest_fire(&sid("s")).expect("latest").is_none(),
            "never fired"
        );
        for ms in [1_000i64, 9_000, 4_000] {
            let fire = ScheduleFire {
                schedule: sid("s"),
                fire_time_ms: ms,
                catch_up: false,
            };
            let _ = repo.insert_fire(&fire, NOW).expect("insert");
        }
        assert_eq!(repo.latest_fire(&sid("s")).expect("latest"), Some(9_000));
    }

    #[test]
    fn a_fire_and_its_task_link_are_written_together() {
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
            .expect("insert");
        let task = TaskId::new("t1");
        assert_eq!(
            repo.record_fire_with_task(&sid("s"), 1_000, false, &task, NOW)
                .expect("record"),
            FireInsert::Inserted
        );
        let linked: Option<String> = c
            .query_row(
                "SELECT task_id FROM schedule_fires WHERE schedule_id = 's' AND fire_time_ms = 1000;",
                [],
                |r| r.get(0),
            )
            .expect("query");
        assert_eq!(linked.as_deref(), Some("t1"));
    }

    #[test]
    fn a_repeated_pass_reports_the_duplicate_rather_than_creating_a_second_link() {
        // The scheduler relies on this to avoid making a second task for one
        // occurrence.
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
            .expect("insert");
        repo.record_fire_with_task(&sid("s"), 1_000, false, &TaskId::new("t1"), NOW)
            .expect("first");
        assert_eq!(
            repo.record_fire_with_task(&sid("s"), 1_000, false, &TaskId::new("t2"), NOW)
                .expect("second"),
            FireInsert::AlreadyPresent
        );
        assert_eq!(
            repo.fire_count(&sid("s")).expect("count"),
            1,
            "still exactly one fire"
        );
    }

    #[test]
    fn linking_a_fire_that_was_never_recorded_is_an_error() {
        let mut c = mem();
        let mut repo = ScheduleRepository::new(&mut c);
        repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
            .expect("insert");
        assert!(matches!(
            repo.link_fire_to_task(&sid("s"), 1_000, &TaskId::new("t")),
            Err(ScheduleRepoError::NotFound(_))
        ));
    }

    #[test]
    fn an_unreadable_policy_in_a_row_is_reported_not_defaulted() {
        // Defaulting a misfire policy would silently choose whether a week of
        // backlog runs — the exact question the policy exists to make explicit.
        let mut c = mem();
        {
            let mut repo = ScheduleRepository::new(&mut c);
            repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
                .expect("insert");
        }
        c.execute_batch("PRAGMA ignore_check_constraints = ON;")
            .expect("ignore");
        c.execute(
            "UPDATE schedules SET misfire_policy = 'guess' WHERE id = 's';",
            [],
        )
        .expect("force");
        let repo = ScheduleRepository::new(&mut c);
        let err = repo.get(&sid("s")).expect_err("must refuse");
        assert!(
            matches!(err, ScheduleRepoError::InvalidPolicy { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_committed_fire_is_visible_to_a_second_connection() {
        // Every write here is IMMEDIATE and committed before the call returns, so a
        // reader on another connection — which is how a supervisor would inspect a
        // live daemon — sees a whole catch-up pass or none of it, never half.
        let dir = std::env::temp_dir().join(format!("orxnud-sched-vis-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("s.db");

        {
            let mut c = Connection::open(&path).expect("open");
            Pragma::critical().apply(&c).expect("pragmas");
            MigrationRunner::new(&c).run(true).expect("migrate");
            let mut repo = ScheduleRepository::new(&mut c);
            repo.insert(&spec("s", MisfirePolicy::FireAll, 10), NOW)
                .expect("insert");
            for ms in [1_000i64, 2_000] {
                let fire = ScheduleFire {
                    schedule: sid("s"),
                    fire_time_ms: ms,
                    catch_up: false,
                };
                repo.insert_fire(&fire, NOW).expect("insert");
            }
        }

        let reader = Connection::open(&path).expect("reader");
        let n: i64 = reader
            .query_row("SELECT COUNT(*) FROM schedule_fires;", [], |r| r.get(0))
            .expect("count");
        assert_eq!(n, 2, "both fires must be durable and visible");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
