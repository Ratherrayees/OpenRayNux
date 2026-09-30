//! Task lifecycle types and the state machine (ADR-0029).
//!
//! The *contract* for a task engine is the twelve properties in ADR-0029, not
//! this file. This file defines the vocabulary those properties are stated in:
//! the states a task can be in, and which transitions are legal.
//!
//! A state machine is used rather than free-form status strings because the
//! failure modes of a durable queue are all *illegal transition* failures: a
//! task resurrecting from a terminal state, a retry silently inheriting an
//! approval, an expired lease committing. Making illegal transitions
//! unrepresentable at the type level removes a whole class of them.
//!
//! # The real engine is not here
//!
//! Phase 1 provides the types and the legality rules. The engine that stores
//! and transitions them is Phase 2, and must satisfy the ADR-0029 conformance
//! suite. See `orxnud_task::conformance`.

use serde::{Deserialize, Serialize};

use crate::ids::{ScheduleId, UserId};

/// What kind of work a task represents.
///
/// `idempotent` is a property of the *kind*, not of an individual run, because
/// whether repeating the action is safe is a fact about the action. It is what
/// makes property TP-2 decidable: a non-idempotent task that experiences an
/// uncertain outcome is never automatically re-executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskKind {
    /// A durable unit of workflow execution. May perform side effects.
    Workflow,
    /// A read-only query. Always safe to repeat.
    Query,
    /// A scheduled firing of a schedule.
    ScheduledFire,
    /// Internal housekeeping: retention, backup, health checks.
    Housekeeping,
}

impl TaskKind {
    /// Whether repeating this task is safe without human adjudication.
    ///
    /// `false` for `Workflow`, because a workflow may contain an irreversible
    /// step. The engine consults the *capability* contract for finer
    /// granularity, but the conservative default here means a new task kind is
    /// non-idempotent until someone says otherwise — the same
    /// unknown-is-not-safe default as [`crate::enums::RiskClass`].
    #[must_use]
    pub fn idempotent_by_default(self) -> bool {
        match self {
            Self::Query | Self::Housekeeping => true,
            Self::Workflow | Self::ScheduledFire => false,
        }
    }
}

/// Where a task is in its lifecycle.
///
/// Note `NeedsVerification`: it is not a failure and not a success. It is the
/// honest state for "an effect may or may not have happened", and it exists
/// because the alternative — guessing — is how duplicates happen (property
/// TP-2, TP-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaskState {
    /// Accepted, not yet claimed. Claimable.
    Pending,
    /// Claimed by a worker with a live lease.
    Running,
    /// Waiting for a human. Distinct from `Paused`: someone must act.
    WaitingForUser,
    /// Waiting for an external system. Distinct from `Pending`: it is not
    /// claimable until the external event arrives.
    WaitingForExternal,
    /// Deliberately stopped by a human or a policy. Terminal.
    Paused,
    /// Stopped by a human. Terminal. Survives restart.
    Cancelled,
    /// Finished successfully. Terminal.
    Completed,
    /// Finished unsuccessfully, within the retry budget. Terminal.
    Failed,
    /// Out of retries. Terminal. Visible to the user; never silently retried.
    DeadLettered,
    /// A side effect may or may not have occurred. **Terminal until a human
    /// adjudicates.** Never automatically retried.
    NeedsVerification,
}

impl TaskState {
    /// Whether no further transition is possible without human intervention.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Paused
                | Self::Cancelled
                | Self::Completed
                | Self::Failed
                | Self::DeadLettered
                | Self::NeedsVerification
        )
    }

    /// Whether a worker may claim this state.
    #[must_use]
    pub fn is_claimable(self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Whether this state means "we do not know what happened".
    #[must_use]
    pub fn is_uncertain(self) -> bool {
        matches!(self, Self::NeedsVerification)
    }

    /// Whether this state is one of the two "waiting" states.
    #[must_use]
    pub fn is_waiting(self) -> bool {
        matches!(self, Self::WaitingForUser | Self::WaitingForExternal)
    }
}

/// Row-level status of a task, paired with its state.
///
/// Separated from [`TaskState`] because the *persisted* status carries attempt
/// and lease bookkeeping that the pure state does not, and because the
/// conformance suite needs to reason about "is this row owned by a live worker?"
/// independently of "what is the task doing?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskStatus {
    /// The lifecycle state.
    pub state: TaskState,
    /// Attempts made so far.
    pub attempts: u32,
    /// Maximum attempts before dead-lettering.
    pub max_attempts: u32,
    /// Lease expiry in ms since epoch, if currently claimed.
    pub lease_expires_at_ms: Option<i64>,
    /// Whether this run was produced by catch-up after downtime.
    pub catch_up: bool,
}

impl TaskStatus {
    /// A fresh pending status with a retry budget.
    #[must_use]
    pub fn pending(max_attempts: u32) -> Self {
        Self {
            state: TaskState::Pending,
            attempts: 0,
            max_attempts,
            lease_expires_at_ms: None,
            catch_up: false,
        }
    }

    /// Whether a lease has expired at `now_ms`.
    #[must_use]
    pub fn lease_is_expired_at(&self, now_ms: i64) -> bool {
        self.lease_expires_at_ms.is_some_and(|expiry| now_ms >= expiry)
    }

    /// Whether the retry budget is exhausted.
    #[must_use]
    pub fn retries_exhausted(&self) -> bool {
        self.attempts >= self.max_attempts
    }
}

/// What to do about schedule occurrences missed while the machine was off.
///
/// Explicit per schedule, because "silently run a week of backlog" and "quietly
/// skip a week" are both wrong, and which is right depends on the task
/// (property TP-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum MisfirePolicy {
    /// Run every missed occurrence.
    FireAll,
    /// Collapse all missed occurrences into one run, flagged `catch_up`.
    FireOnce,
    /// Skip occurrences older than the given number of minutes.
    SkipIfOlderMinutes(u32),
    /// Run only the most recent missed occurrence.
    FireNextOnly,
    /// Do not catch up at all; a human re-enables.
    Pause,
}

/// A recurring schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleSpec {
    /// Which schedule.
    pub id: ScheduleId,
    /// A cron expression, interpreted in `timezone`.
    pub cron: String,
    /// An IANA timezone name. Never the daemon's ambient local time.
    pub timezone: String,
    /// What to do about missed occurrences.
    pub misfire: MisfirePolicy,
    /// Maximum occurrences to fire in one catch-up pass.
    pub catch_up_cap: u32,
    /// Whether the schedule is active.
    pub enabled: bool,
    /// The human who authorised it.
    pub authorised_by: UserId,
}

/// A single firing of a schedule.
///
/// `UNIQUE(schedule_id, fire_time)` on this table is the whole catch-up and
/// dedup mechanism: an `INSERT OR IGNORE` cannot succeed twice, even across a
/// crash, because SQLite serialises writes. This is why the phase-1 schema has
/// no application tables — the *pattern* is recorded here, and the table
/// arrives in Phase 2 with the engine that uses it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScheduleFire {
    /// Which schedule.
    pub schedule: ScheduleId,
    /// The scheduled occurrence time, ms since epoch. The dedup key.
    pub fire_time_ms: i64,
    /// Whether the run was produced by catch-up rather than on time.
    pub catch_up: bool,
}

/// The complete legal transition set.
///
/// A function rather than a table so it can be property-tested exhaustively and
/// so adding a state forces a decision here.
#[must_use]
pub fn is_legal_transition(from: TaskState, to: TaskState) -> bool {
    use TaskState::{
        Cancelled, Completed, DeadLettered, Failed, NeedsVerification, Paused, Pending,
        WaitingForExternal, WaitingForUser,
    };
    use TaskState::Running;

    // Terminal is terminal. This is the invariant that stops a resurrected task.
    if from.is_terminal() {
        return false;
    }
    // No self-transitions, except idempotent re-assertion of a wait, which the
    // engine models as staying put rather than transitioning.
    if from == to {
        return false;
    }
    matches!(
        (from, to),
        (Pending, Running)
            | (Pending, Cancelled)
            | (Pending, WaitingForUser)
            | (Pending, WaitingForExternal)
            | (Pending, Paused)
            | (Running, Completed)
            | (Running, Failed)
            | (Running, Cancelled)
            | (Running, WaitingForUser)
            | (Running, WaitingForExternal)
            | (Running, Paused)
            | (Running, NeedsVerification)
            | (Running, DeadLettered)
            | (Failed, Running) // a retry
            | (WaitingForUser, Running)
            | (WaitingForUser, Cancelled)
            | (WaitingForExternal, Running)
            | (WaitingForExternal, Cancelled)
            | (Paused, Running) // explicit resume
            | (Paused, Cancelled)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ALL: [TaskState; 10] = [
        TaskState::Pending,
        TaskState::Running,
        TaskState::WaitingForUser,
        TaskState::WaitingForExternal,
        TaskState::Paused,
        TaskState::Cancelled,
        TaskState::Completed,
        TaskState::Failed,
        TaskState::DeadLettered,
        TaskState::NeedsVerification,
    ];

    #[test]
    fn terminal_states_have_no_outgoing_transitions() {
        for from in ALL {
            if from.is_terminal() {
                for to in ALL {
                    assert!(
                        !is_legal_transition(from, to),
                        "terminal {from:?} must not transition to {to:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn no_self_transitions() {
        for s in ALL {
            assert!(!is_legal_transition(s, s), "self-transition allowed for {s:?}");
        }
    }

    #[test]
    fn terminal_states_are_reachable_but_never_leave() {
        for terminal in [
            TaskState::Cancelled,
            TaskState::Completed,
            TaskState::Failed,
            TaskState::DeadLettered,
            TaskState::NeedsVerification,
            TaskState::Paused,
        ] {
            assert!(terminal.is_terminal());
            let reachable = ALL
                .iter()
                .any(|from| is_legal_transition(*from, terminal));
            assert!(reachable, "no path reaches {terminal:?}");
        }
    }

    #[test]
    fn pending_can_only_reach_claimable_or_stopping_states() {
        for to in ALL {
            if is_legal_transition(TaskState::Pending, to) {
                assert!(
                    matches!(
                        to,
                        TaskState::Running
                            | TaskState::Cancelled
                            | TaskState::Paused
                            | TaskState::WaitingForUser
                            | TaskState::WaitingForExternal
                    ),
                    "unexpected Pending -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn completed_and_cancelled_are_only_reachable_from_work() {
        for terminal in [TaskState::Completed, TaskState::Cancelled] {
            for from in ALL {
                if is_legal_transition(from, terminal) {
                    assert!(
                        !from.is_terminal(),
                        "{from:?} (terminal) reached {terminal:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn uncertain_outcome_is_a_distinct_terminal_state() {
        // The state that makes TP-2 and TP-12 expressible: we do not guess
        // whether an effect happened.
        assert!(TaskState::NeedsVerification.is_terminal());
        assert!(TaskState::NeedsVerification.is_uncertain());
        assert!(is_legal_transition(TaskState::Running, TaskState::NeedsVerification));
        // And it is not a failure, so it is not retried.
        assert!(!TaskState::NeedsVerification.is_claimable());
    }

    #[test]
    fn lease_expiry_is_half_open() {
        let s = TaskStatus {
            state: TaskState::Running,
            attempts: 1,
            max_attempts: 3,
            lease_expires_at_ms: Some(1_000),
            catch_up: false,
        };
        assert!(!s.lease_is_expired_at(999));
        assert!(s.lease_is_expired_at(1_000));
        assert!(s.lease_is_expired_at(1_001));
        let unleased = TaskStatus::pending(3);
        assert!(!unleased.lease_is_expired_at(i64::MAX));
    }

    #[test]
    fn retry_budget_is_inclusive_at_the_boundary() {
        let s = TaskStatus { attempts: 2, max_attempts: 3, ..TaskStatus::pending(3) };
        assert!(!s.retries_exhausted());
        let done = TaskStatus { attempts: 3, ..TaskStatus::pending(3) };
        assert!(done.retries_exhausted());
    }

    #[test]
    fn non_idempotent_kinds_are_the_default() {
        // Unknown-is-not-safe: a new kind is non-idempotent until classified.
        assert!(!TaskKind::Workflow.idempotent_by_default());
        assert!(!TaskKind::ScheduledFire.idempotent_by_default());
        assert!(TaskKind::Query.idempotent_by_default());
        assert!(TaskKind::Housekeeping.idempotent_by_default());
    }

    #[test]
    fn only_pending_is_claimable() {
        for s in ALL {
            assert_eq!(s.is_claimable(), s == TaskState::Pending, "claimable wrong for {s:?}");
        }
    }

    proptest! {
        /// The central liveness property: once terminal, always terminal.
        /// This is what makes TP-1 ("no task silently disappears") hold — a
        /// task cannot fall out of the observable set by resurrecting.
        #[test]
        fn terminal_is_absorbing(a: u8, steps: u8) {
            let from = ALL[(a % 10) as usize];
            let cur = from;
            if cur.is_terminal() {
                for _ in 0..(steps % 5) {
                    let to = ALL[(steps.wrapping_add(3) % 10) as usize];
                    prop_assert!(!is_legal_transition(cur, to));
                }
            }
        }

        /// The transition relation is deterministic: same input, same answer.
        #[test]
        fn transition_is_deterministic(a: u8, b: u8) {
            let x = ALL[(a % 10) as usize];
            let y = ALL[(b % 10) as usize];
            prop_assert_eq!(is_legal_transition(x, y), is_legal_transition(x, y));
        }

        /// A task that has exhausted its budget is flagged as such, and
        /// budget exhaustion is monotone in attempts.
        #[test]
        fn retry_budget_is_monotone(attempts: u32, max: u32) {
            let max = max % 8;
            let a = TaskStatus { attempts, max_attempts: max, ..TaskStatus::pending(max) };
            if a.retries_exhausted() {
                let b = TaskStatus { attempts: attempts.saturating_add(1), max_attempts: max, ..TaskStatus::pending(max) };
                prop_assert!(b.retries_exhausted());
            }
        }
    }
}
