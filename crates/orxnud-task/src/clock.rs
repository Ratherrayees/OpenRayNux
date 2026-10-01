//! Wall-clock access, as a trait, so nothing else has to.
//!
//! # Why the engine takes time as a parameter and this exists anyway
//!
//! [`crate::engine::DurableEngine`] takes `now_ms` on every operation, because
//! TP-3, TP-4, TP-5, TP-8 and TP-9 are all *time* properties and a wall clock
//! makes them untestable at the only moments that matter. So the engine has no
//! clock at all.
//!
//! A production caller still needs one, and the temptation is `SystemTime::now()`
//! inline — which would put a hidden, non-injectable time source back into the
//! system. [`SystemClock`] is the single place that reads the wall clock, which
//! makes it greppable: one file, one `SystemTime::now()`.

use std::time::{SystemTime, UNIX_EPOCH};

/// A source of the current time.
pub trait NowMs {
    /// The current instant, ms since the Unix epoch.
    ///
    /// Saturates at 0 if the system clock is before 1970 rather than panicking. A
    /// clock that has gone backwards that far is a broken machine, and the useful
    /// behaviour is a timestamp a caller can reason about, not a panic in a
    /// scheduler tick.
    fn now_ms(&self) -> i64;
}

/// The wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    /// The wall clock.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl NowMs for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_millis()).ok())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_is_after_2020() {
        // A sanity bound, not a precision test. Its purpose is to catch a clock
        // that is reading milliseconds *since some other epoch*.
        let now = SystemClock.now_ms();
        assert!(
            now > 1_577_836_800_000,
            "the clock is implausibly early: {now}"
        );
        assert!(
            now < 4_102_444_800_000,
            "the clock is implausibly late: {now}"
        );
    }

    #[test]
    fn reading_the_clock_twice_does_not_go_backwards() {
        // A monotonicity check on the *measurement*, catching a broken
        // implementation. A real NTP step can move the wall clock backwards, which
        // is exactly why the engine takes time as a parameter and TP-8 exists.
        let a = SystemClock.now_ms();
        let b = SystemClock.now_ms();
        assert!(b >= a, "{b} < {a}");
    }
}
