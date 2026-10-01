//! Resource bounds.
//!
//! # Why these are a type and not a comment
//!
//! ADR-0029 TP-10 says every spawn has a concurrency limit and a wedged task is
//! killed at its deadline. A limit expressed in prose is a limit that survives
//! until the first review that does not remember it. [`EngineLimits`] makes the
//! bounds values the engine is constructed with, so a caller cannot get an engine
//! without having chosen them, and a test can assert the values are enforced.
//!
//! # Every bound here answers "what happens when this is exceeded?"
//!
//! * `max_concurrent_leases` — [`DurableEngine::can_claim`] returns false; a
//!   supervisor stops issuing claims. Never a queue that grows without limit.
//! * `lease_duration_ms` — a lease expires and the task is reclaimable. Never a
//!   task held forever.
//! * `max_attempts_default` — the task dead-letters. Never an unbounded retry.
//! * `retry_backoff_ms` — the next attempt is deferred. Never a hot loop.
//! * `catch_up_cap` — the scheduler clamps and *reports* what it dropped, because
//!   a clamp nobody is told about looks like success (TP-9).
//! * `deadline_timeout_ms` — the caller kills the work. A wedged task is bounded.

use crate::error::{EngineError, EngineErrorKind};

/// The resource envelope the engine runs inside.
///
/// No `Default` beyond the documented values: a caller that cares must state its
/// choices, and a caller that does not gets the documented defaults explicitly via
/// [`EngineLimits::documented`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineLimits {
    /// How long a lease lasts before the task becomes reclaimable.
    ///
    /// Long enough that a worker doing ordinary work never loses its lease to
    /// jitter; short enough that a crashed worker's task is not stuck for minutes.
    pub lease_duration_ms: i64,

    /// How long a worker may hold a task before its deadline kills it.
    pub deadline_timeout_ms: i64,

    /// The maximum number of tasks that may hold a live lease at once.
    ///
    /// Enforced by [`DurableEngine::can_claim`](crate::engine::DurableEngine::can_claim).
    /// A personal daemon's whole point is being light, so this is small.
    pub max_concurrent_leases: i64,

    /// The default attempt ceiling for a new task.
    pub max_attempts_default: u32,

    /// How long a failed task waits before it becomes claimable again.
    pub retry_backoff_ms: i64,

    /// The most fires one catch-up pass may insert for one schedule.
    pub catch_up_cap: u32,

    /// The most schedules one scheduler pass will consider.
    ///
    /// A bound on the *loop*, not on the work: a user with a pathological number of
    /// schedules gets a visible truncation rather than a startup that never ends.
    pub max_schedules_per_pass: usize,
}

impl EngineLimits {
    /// The documented defaults.
    ///
    /// # Why these numbers
    ///
    /// * `lease_duration_ms = 30_000` — a task that has not heartbeat for half a
    ///   minute is presumed dead. A heartbeat every 10 s gives three chances to
    ///   renew before expiry.
    /// * `deadline_timeout_ms = 300_000` — five minutes. Long enough for real work,
    ///   short enough that a wedge does not hold a concurrency slot for ever.
    /// * `max_concurrent_leases = 8` — a personal assistant on a laptop. Higher
    ///   numbers trade throughput for memory and for the single-writer contention
    ///   ADR-0006 already documents.
    /// * `max_attempts_default = 3` — one initial attempt plus two retries. A task
    ///   that has failed three times is nearly always a real failure.
    /// * `retry_backoff_ms = 1_000` — one second. Long enough not to spin, short
    ///   enough that a transient blip is invisible to a user.
    /// * `catch_up_cap = 50` — ADR-0021 leaves this to the schedule; this is the
    ///   engine-wide ceiling so one schedule cannot consume startup.
    /// * `max_schedules_per_pass = 1_000` — well beyond any personal use, and low
    ///   enough that the loop is bounded by construction.
    #[must_use]
    pub const fn documented() -> Self {
        Self {
            lease_duration_ms: 30_000,
            deadline_timeout_ms: 300_000,
            max_concurrent_leases: 8,
            max_attempts_default: 3,
            retry_backoff_ms: 1_000,
            catch_up_cap: 50,
            max_schedules_per_pass: 1_000,
        }
    }

    /// The lease expiry for a claim at `now_ms`.
    ///
    /// Saturating rather than wrapping: a clock near `i64::MAX` must produce an
    /// expiry that is *very late*, not one in the past — a wrapped expiry would
    /// make every claim look immediately expired.
    #[must_use]
    pub const fn lease_expiry(&self, now_ms: i64) -> i64 {
        now_ms.saturating_add(self.lease_duration_ms)
    }

    /// Whether the lease budget allows one more claim at `now_ms`.
    ///
    /// `live_leases` counts only leases that have not expired, so a crashed
    /// worker's task does not consume a slot forever.
    #[must_use]
    pub fn can_claim(&self, live_leases: i64, now_ms: i64) -> bool {
        let _ = now_ms;
        live_leases < self.max_concurrent_leases
    }

    /// The refusal when the budget is exhausted.
    ///
    /// A `ConcurrencyConflict` rather than an `Invariant`: nothing is broken, the
    /// engine is simply saturated, and the caller should wait. That distinction is
    /// what lets a supervisor retry instead of treating it as a bug.
    #[must_use]
    pub fn refuse_over_limit(&self, live_leases: i64) -> EngineError {
        EngineError::new(
            EngineErrorKind::ConcurrencyConflict,
            format!(
                "concurrency limit reached: {live_leases} live leases of {}",
                self.max_concurrent_leases
            ),
        )
    }

    /// Whether a schedule's declared cap exceeds the engine-wide ceiling.
    ///
    /// The schedule's own cap wins when it is lower — a user who asked for 5 gets
    /// 5. The engine ceiling only ever *lowers* a cap, never raises it, so no
    /// schedule can exceed the documented startup bound.
    #[must_use]
    pub const fn effective_catch_up_cap(&self, schedule_cap: u32) -> u32 {
        if schedule_cap < self.catch_up_cap {
            schedule_cap
        } else {
            self.catch_up_cap
        }
    }

    /// Whether the limits are self-consistent.
    ///
    /// Checked at construction so a nonsensical envelope fails immediately rather
    /// than at the moment a lease is claimed.
    pub fn validate(&self) -> Result<(), EngineError> {
        if self.lease_duration_ms <= 0 {
            return Err(EngineError::invalid("lease_duration_ms must be positive"));
        }
        if self.deadline_timeout_ms < self.lease_duration_ms {
            // A deadline shorter than the lease means a task is killed before its
            // own lease could expire — the worker is killed while it still believes
            // it holds the task, which is the zombie case with extra steps.
            return Err(EngineError::invalid(
                "deadline_timeout_ms must be at least lease_duration_ms",
            ));
        }
        if self.max_concurrent_leases <= 0 {
            return Err(EngineError::invalid(
                "max_concurrent_leases must be positive",
            ));
        }
        if self.max_attempts_default == 0 {
            return Err(EngineError::invalid(
                "max_attempts_default must be at least 1",
            ));
        }
        if self.retry_backoff_ms < 0 {
            return Err(EngineError::invalid(
                "retry_backoff_ms must not be negative",
            ));
        }
        if self.max_schedules_per_pass == 0 {
            return Err(EngineError::invalid(
                "max_schedules_per_pass must be positive",
            ));
        }
        Ok(())
    }
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self::documented()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_documented_limits_are_internally_consistent() {
        EngineLimits::documented()
            .validate()
            .expect("the defaults must be valid");
    }

    #[test]
    fn every_documented_bound_is_actually_bounded() {
        let l = EngineLimits::documented();
        // The point of documenting them is that they are limits. Each of these
        // asserts the value is a real bound rather than an absent one.
        assert!(l.lease_duration_ms > 0);
        assert!(l.deadline_timeout_ms >= l.lease_duration_ms);
        assert!(l.max_concurrent_leases > 0);
        assert!(l.max_attempts_default > 0);
        assert!(l.retry_backoff_ms > 0);
        assert!(l.catch_up_cap > 0);
        assert!(l.max_schedules_per_pass > 0);
    }

    #[test]
    fn a_lease_expiry_saturates_rather_than_wrapping_into_the_past() {
        let l = EngineLimits::documented();
        // A wrapped expiry would make every claim look already expired, so a task
        // would never run and the failure would look like a bug in `claim`.
        assert_eq!(l.lease_expiry(i64::MAX - 1), i64::MAX);
        assert_eq!(l.lease_expiry(1_000), 1_000 + l.lease_duration_ms);
    }

    #[test]
    fn the_concurrency_limit_is_enforced_at_the_boundary() {
        let l = EngineLimits {
            max_concurrent_leases: 3,
            ..EngineLimits::documented()
        };
        assert!(l.can_claim(0, 0));
        assert!(l.can_claim(2, 0));
        assert!(!l.can_claim(3, 0), "the limit itself must be refused");
        assert!(!l.can_claim(4, 0));
    }

    #[test]
    fn refusing_the_concurrency_limit_is_a_conflict_not_a_bug() {
        // A supervisor must be able to tell "wait" from "broken" and retry.
        let l = EngineLimits::documented();
        let e = l.refuse_over_limit(l.max_concurrent_leases);
        assert_eq!(e.kind, EngineErrorKind::ConcurrencyConflict);
        assert!(e.kind.is_retryable());
        assert!(
            e.message.contains(&l.max_concurrent_leases.to_string()),
            "{}",
            e.message
        );
    }

    #[test]
    fn a_deadline_shorter_than_a_lease_is_rejected() {
        // Otherwise a task is killed while its worker still believes it holds a
        // live lease — the zombie case, manufactured by configuration.
        let bad = EngineLimits {
            lease_duration_ms: 30_000,
            deadline_timeout_ms: 1_000,
            ..EngineLimits::documented()
        };
        let err = bad.validate().expect_err("must refuse");
        assert!(err.message.contains("lease_duration_ms"), "{}", err.message);
    }

    #[test]
    fn nonsensical_limits_are_refused_at_construction() {
        for bad in [
            EngineLimits {
                lease_duration_ms: 0,
                ..EngineLimits::documented()
            },
            EngineLimits {
                max_concurrent_leases: 0,
                ..EngineLimits::documented()
            },
            EngineLimits {
                max_attempts_default: 0,
                ..EngineLimits::documented()
            },
            EngineLimits {
                retry_backoff_ms: -1,
                ..EngineLimits::documented()
            },
            EngineLimits {
                max_schedules_per_pass: 0,
                ..EngineLimits::documented()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn the_engine_ceiling_only_ever_lowers_a_schedule_cap() {
        let l = EngineLimits {
            catch_up_cap: 50,
            ..EngineLimits::documented()
        };
        assert_eq!(l.effective_catch_up_cap(5), 5, "a user's lower cap wins");
        assert_eq!(l.effective_catch_up_cap(50), 50);
        assert_eq!(
            l.effective_catch_up_cap(1_000),
            50,
            "a higher cap is clamped"
        );
    }
}
