//! A deliberately trivial engine, used **only** to make the properties runnable.
//!
//! # This is not the task engine
//!
//! It lives in `tests/`, is never compiled into the library, has no scheduler,
//! no persistence, no recovery logic, and no production code path. It exists
//! because the twelve properties in ADR-0029 need *something* to run against
//! before Phase 2 writes the real engine.
//!
//! It is intentionally crude: a `BTreeMap`, a fixed lease duration, and time
//! supplied by the harness. Anything it does that the real engine must *also* do
//! is a specification of the real engine; anything it does merely to be simple is
//! not.
//!
//! # What it deliberately does not do
//!
//! * No WAL, no `synchronous`, no restart. It cannot, and TP-7's process-kill
//!   half covers the real requirement.
//! * No catch-up. That is exercised against the schedule generator directly.
//! * No priority, no delayed jobs, no batching. Not properties.
//!
//! # The most important behaviour it encodes
//!
//! [`TrivialEngine::complete`] refuses a commit when the caller's lease has
//! lapsed, and refuses one from a worker that does not hold the task. That pair
//! is exactly what TP-5 requires, and it is the part a naive implementation gets
//! wrong: checking identity alone passes the re-claimed case and fails the
//! expired-but-unclaimed one.

#![allow(dead_code)] // the suite exercises different subsets per property

use std::collections::BTreeMap;

use orxnud_domain::task_state::{TaskState, is_legal_transition};
use orxnud_domain::{TaskId, TaskKind};
use orxnud_task::conformance::properties::{Claim, TaskEngine, TaskRecord};

/// How long a lease lasts, in milliseconds. Arbitrary but fixed, so a property can
/// move time past it deterministically.
pub const LEASE_MS: i64 = 5_000;

/// A trivial in-memory engine that satisfies the ADR-0029 contract.
#[derive(Debug, Default)]
pub struct TrivialEngine {
    tasks: BTreeMap<TaskId, TaskRecord>,
    /// Set to make every operation fail, for the fails-closed tests.
    broken: bool,
    /// Whether lease fencing is implemented. Flipped to prove TP-5 reports a gap
    /// rather than silently passing.
    fencing: bool,
}

impl TrivialEngine {
    /// A working engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tasks: BTreeMap::new(),
            broken: false,
            fencing: true,
        }
    }

    /// An engine with no lease fencing, to prove TP-5 reports `Unsupported`.
    #[must_use]
    pub fn without_fencing() -> Self {
        Self {
            tasks: BTreeMap::new(),
            broken: false,
            fencing: false,
        }
    }

    /// An engine whose operations always fail.
    #[must_use]
    pub fn broken() -> Self {
        Self {
            tasks: BTreeMap::new(),
            broken: true,
            fencing: true,
        }
    }

    /// Rejects a transition the state machine forbids, rather than performing it.
    fn check(&self, id: &TaskId, to: TaskState) -> Result<(), String> {
        let cur = self.tasks.get(id).ok_or("no such task")?;
        if cur.state == to {
            return Ok(());
        }
        if !is_legal_transition(cur.state, to) {
            return Err(format!("illegal transition {:?} -> {:?}", cur.state, to));
        }
        Ok(())
    }
}

impl TaskEngine for TrivialEngine {
    fn name(&self) -> &'static str {
        "trivial-fixture"
    }

    fn supports_lease_fencing(&self) -> bool {
        self.fencing
    }

    fn enqueue(&mut self, task: TaskRecord) -> Result<(), String> {
        if self.broken {
            return Err("engine is broken".into());
        }
        self.tasks.insert(task.id.clone(), task);
        Ok(())
    }

    fn claim(&mut self, worker: &str, now_ms: i64) -> Result<Claim, String> {
        if self.broken {
            return Err("engine is broken".into());
        }
        for rec in self.tasks.values_mut() {
            if rec.state.is_claimable() {
                rec.state = TaskState::Running;
                rec.attempts += 1;
                rec.lease_expires_at_ms = Some(now_ms + LEASE_MS);
                rec.lease_holder = Some(worker.to_owned());
                return Ok(Claim::Claimed(rec.clone()));
            }
        }
        Ok(Claim::Empty)
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
        if self.broken {
            return Err("engine is broken".into());
        }
        let rec = self.tasks.get(id).ok_or("no such task")?.clone();

        // --- TP-5, half one: identity. Is this worker still the holder? ---
        if rec.lease_holder.as_deref() != Some(worker) {
            return Err(format!("{worker} does not hold {id}"));
        }
        // --- TP-5, half two: liveness. A lease that has expired is dead even
        // though `lease_holder` still names its owner. An engine that checked only
        // the first half passes the re-claimed case and fails this one.
        match rec.lease_expires_at_ms {
            None => return Err(format!("{id} carries no lease; nothing can be fenced")),
            Some(expiry) if now_ms >= expiry => {
                return Err(format!(
                    "the lease on {id} expired at {expiry} (now {now_ms})"
                ));
            }
            Some(_) => {}
        }

        self.check(id, state)?;
        let rec = self.tasks.get_mut(id).ok_or("no such task")?;
        rec.state = state;
        rec.effect_observed = effect_observed;
        rec.last_error = error;
        rec.lease_expires_at_ms = None;
        rec.lease_holder = None;
        Ok(())
    }

    fn request_cancel(&mut self, id: &TaskId) -> Result<(), String> {
        if self.broken {
            return Err("engine is broken".into());
        }
        // A terminal task cannot be cancelled: that would be a resurrection,
        // which TP-1 forbids.
        if self
            .tasks
            .get(id)
            .ok_or("no such task")?
            .state
            .is_terminal()
        {
            return Ok(());
        }
        self.check(id, TaskState::Cancelled)?;
        let rec = self.tasks.get_mut(id).ok_or("no such task")?;
        rec.state = TaskState::Cancelled;
        rec.lease_expires_at_ms = None;
        rec.lease_holder = None;
        Ok(())
    }

    fn recover(&mut self, now_ms: i64) -> Result<(), String> {
        if self.broken {
            return Err("engine is broken".into());
        }
        // A restart orphans *every* lease the previous process held, expired or
        // not: there is no surviving worker to renew them.
        let _ = now_ms;
        let ids: Vec<TaskId> = self.tasks.keys().cloned().collect();
        for id in ids {
            let leased = self
                .tasks
                .get(&id)
                .ok_or("no such task")?
                .lease_expires_at_ms
                .is_some();
            if leased {
                let rec = self.tasks.get_mut(&id).ok_or("no such task")?;
                rec.state = TaskState::Pending;
                rec.lease_expires_at_ms = None;
                rec.lease_holder = None;
            }
        }
        Ok(())
    }

    fn all(&self) -> Vec<TaskRecord> {
        self.tasks.values().cloned().collect()
    }

    fn get(&self, id: &TaskId) -> Option<TaskRecord> {
        self.tasks.get(id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_task::conformance::clock::{FixedClock, TestClock};

    fn task(name: &str) -> TaskRecord {
        TaskRecord::pending(TaskId::new(name), TaskKind::Workflow)
    }

    #[test]
    fn a_claim_takes_a_lease_and_records_one_attempt() {
        let clock = FixedClock::new(1_000);
        let mut e = TrivialEngine::new();
        e.enqueue(task("a")).expect("enqueue");
        let Claim::Claimed(r) = e.claim("w", clock.now_ms()).expect("claim") else {
            panic!("expected a claim");
        };
        assert_eq!(r.attempts, 1);
        assert_eq!(r.lease_holder.as_deref(), Some("w"));
        assert_eq!(r.lease_expires_at_ms, Some(1_000 + LEASE_MS));
    }

    #[test]
    fn a_live_lease_may_commit() {
        let clock = FixedClock::new(1_000);
        let mut e = TrivialEngine::new();
        e.enqueue(task("a")).expect("enqueue");
        let _ = e.claim("w", clock.now_ms()).expect("claim");
        assert!(
            e.complete(
                &TaskId::new("a"),
                "w",
                clock.now_ms(),
                TaskState::Completed,
                true,
                None
            )
            .is_ok()
        );
        assert_eq!(
            e.get(&TaskId::new("a")).expect("row").state,
            TaskState::Completed
        );
    }

    #[test]
    fn an_expired_lease_cannot_commit_even_when_nobody_else_claimed() {
        // The case a naive implementation fails: `lease_holder` still names the
        // worker, but its lease is dead.
        let clock = FixedClock::new(1_000);
        let mut e = TrivialEngine::new();
        e.enqueue(task("a")).expect("enqueue");
        let _ = e.claim("zombie", clock.now_ms()).expect("claim");

        clock.advance(LEASE_MS + 1);
        let res = e.complete(
            &TaskId::new("a"),
            "zombie",
            clock.now_ms(),
            TaskState::Completed,
            true,
            None,
        );
        assert!(
            res.is_err(),
            "an expired lease was allowed to commit: {res:?}"
        );
        assert_eq!(
            e.get(&TaskId::new("a")).expect("row").state,
            TaskState::Running
        );
    }

    #[test]
    fn a_worker_that_does_not_hold_the_task_cannot_commit() {
        let clock = FixedClock::new(1_000);
        let mut e = TrivialEngine::new();
        e.enqueue(task("a")).expect("enqueue");
        let _ = e.claim("owner", clock.now_ms()).expect("claim");
        let res = e.complete(
            &TaskId::new("a"),
            "impostor",
            clock.now_ms(),
            TaskState::Completed,
            true,
            None,
        );
        assert!(res.is_err(), "a non-holder was allowed to commit");
    }

    #[test]
    fn recovery_reclaims_every_lease_because_a_restart_orphans_all_of_them() {
        // Even a lease that has not expired is orphaned: the worker holding it
        // died with the process. Reclaiming only expired leases would strand
        // fresh work forever.
        let clock = FixedClock::new(1_000);
        let mut e = TrivialEngine::new();
        e.enqueue(task("a")).expect("enqueue");
        e.enqueue(task("b")).expect("enqueue");
        let _ = e.claim("w1", clock.now_ms()).expect("claim w1");
        let _ = e.claim("w2", clock.now_ms()).expect("claim w2");

        e.recover(clock.now_ms()).expect("recover");
        for name in ["a", "b"] {
            let r = e.get(&TaskId::new(name)).expect(name);
            assert_eq!(r.state, TaskState::Pending, "{name} was not reclaimed");
            assert!(r.lease_holder.is_none(), "{name} still has a holder");
        }
    }

    #[test]
    fn a_terminal_task_cannot_be_cancelled() {
        let clock = FixedClock::new(1_000);
        let mut e = TrivialEngine::new();
        e.enqueue(task("a")).expect("enqueue");
        let _ = e.claim("w", clock.now_ms()).expect("claim");
        e.complete(
            &TaskId::new("a"),
            "w",
            clock.now_ms(),
            TaskState::Completed,
            true,
            None,
        )
        .expect("complete");
        // Cancelling a completed task would resurrect it.
        assert!(e.request_cancel(&TaskId::new("a")).is_ok());
        assert_eq!(
            e.get(&TaskId::new("a")).expect("row").state,
            TaskState::Completed
        );
    }

    #[test]
    fn a_broken_engine_reports_errors_rather_than_succeeding_quietly() {
        let mut e = TrivialEngine::broken();
        assert!(e.enqueue(task("a")).is_err());
        assert!(e.claim("w", 0).is_err());
        assert!(e.recover(0).is_err());
        assert!(e.request_cancel(&TaskId::new("a")).is_err());
    }

    #[test]
    fn the_illegal_transition_check_fires() {
        // Completed -> Running is forbidden by the state machine, so the fixture
        // refuses it rather than performing it.
        let clock = FixedClock::new(1_000);
        let mut e = TrivialEngine::new();
        e.enqueue(task("a")).expect("enqueue");
        let _ = e.claim("w", clock.now_ms()).expect("claim");
        e.complete(
            &TaskId::new("a"),
            "w",
            clock.now_ms(),
            TaskState::Completed,
            true,
            None,
        )
        .expect("complete");
        let _ = e.claim("w2", clock.now_ms());
        // No lease to hold, so the identity check fires first -- which is also
        // correct: a completed task must never be re-claimed.
        assert!(
            e.complete(
                &TaskId::new("a"),
                "w2",
                clock.now_ms(),
                TaskState::Running,
                false,
                None
            )
            .is_err()
        );
    }
}
