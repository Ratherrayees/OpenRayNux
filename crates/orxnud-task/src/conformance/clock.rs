//! A controllable clock.
//!
//! # Why a clock trait at all
//!
//! TP-3, TP-4, TP-5, TP-8, and TP-9 are all *time* properties. Testing them
//! against the wall clock would make them slow, flaky, and impossible to run at
//! the interesting moments — a DST transition, a lease expiring between two
//! statements, a week of missed schedules. So time is a parameter, and the
//! engine under test takes a clock.
//!
//! The production clock is a Phase 2 concern. What matters in Phase 1 is that
//! the *contract* is testable, and that a test can pin a moment in time exactly.

use std::cell::Cell;

/// A clock the harness can move.
pub trait TestClock {
    /// The current time, ms since epoch.
    fn now_ms(&self) -> i64;

    /// Moves time forward by `delta_ms`.
    fn advance(&self, delta_ms: i64);

    /// Jumps to an absolute instant.
    ///
    /// Needed because TP-8 requires a *backwards* jump to be representable; a
    /// forward-only clock could not express "the clock went back at 02:00".
    fn set_ms(&self, ms: i64);
}

/// A clock that only moves when told to.
#[derive(Debug)]
pub struct FixedClock {
    now: Cell<i64>,
}

impl FixedClock {
    /// A clock pinned at `start_ms`.
    #[must_use]
    pub fn new(start_ms: i64) -> Self {
        Self {
            now: Cell::new(start_ms),
        }
    }

    /// Jumps to an absolute time. Used for the clock-manipulation tests (TP-8).
    pub fn set(&self, ms: i64) {
        self.now.set(ms);
    }
}

impl Default for FixedClock {
    fn default() -> Self {
        // 2026-01-01T00:00:00Z. An arbitrary, documented, fixed instant: nothing
        // in the suite depends on the real current time.
        Self::new(1_767_225_600_000)
    }
}

impl TestClock for FixedClock {
    fn now_ms(&self) -> i64 {
        self.now.get()
    }

    fn advance(&self, delta_ms: i64) {
        self.now.set(self.now.get().saturating_add(delta_ms));
    }

    fn set_ms(&self, ms: i64) {
        self.now.set(ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_clock_only_moves_when_told() {
        let c = FixedClock::new(1000);
        assert_eq!(c.now_ms(), 1000);
        assert_eq!(c.now_ms(), 1000, "reading must not advance time");
        c.advance(500);
        assert_eq!(c.now_ms(), 1500);
    }

    #[test]
    fn time_can_jump_forwards_and_backwards() {
        // TP-8 requires surviving a backwards jump, so the clock must permit one.
        let c = FixedClock::new(1000);
        c.set(5_000);
        assert_eq!(c.now_ms(), 5_000);
        c.set(500);
        assert_eq!(c.now_ms(), 500, "a backwards jump must be representable");
    }

    #[test]
    fn advance_saturates_rather_than_wrapping() {
        let c = FixedClock::new(i64::MAX);
        c.advance(1_000_000);
        assert_eq!(c.now_ms(), i64::MAX);
    }
}
