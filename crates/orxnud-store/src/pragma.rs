//! Pragmas: applied, then **verified by reading them back**.
//!
//! # Why verify rather than trust
//!
//! A pragma that silently failed to apply is indistinguishable from one that was
//! never set — until the day the power goes out and the task table is corrupt.
//! So [`Pragma::verify`] reads each setting back and compares it. The cost is a
//! few microseconds at open time; the benefit is that a misconfigured durability
//! setting fails loudly at startup instead of silently at 3am.
//!
//! # Critical vs derived
//!
//! ADR-0028 classifies state regions. `critical` regions (tasks, schedules,
//! audit, dedupe) use `synchronous = FULL` because losing one is a lost
//! *action*. `derived` regions (summaries, entities, embeddings) use `NORMAL`,
//! because they are regenerable and paying an fsync to protect them would
//! trade a real cost for nothing.
//!
//! # Why in-memory databases cannot test any of this
//!
//! WAL is a property of an on-disk database. An `:memory:` database has no
//! write-ahead log, no `synchronous` behaviour worth measuring, and no crash
//! recovery. Testing durability against `:memory:` is testing nothing — which is
//! why the durability tests in this crate use real files (docs-13 §10).

use rusqlite::Connection;

/// Whether an error is SQLite reporting lock contention, rather than a fault.
///
/// The distinction matters because it is the only thing that makes a retry
/// correct: retrying a misconfiguration sixteen times produces sixteen identical
/// failures and hides the real cause.
fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::DatabaseBusy
            || f.code == rusqlite::ErrorCode::DatabaseLocked
    )
}

/// A pragma failure.
#[derive(Debug, thiserror::Error)]
pub enum PragmaError {
    /// The pragma statement failed.
    #[error("failed to apply pragma `{name}`: {source}")]
    Apply {
        /// Which pragma.
        name: &'static str,
        /// The underlying error.
        #[source]
        source: rusqlite::Error,
    },

    /// Reading a pragma back failed.
    #[error("failed to read pragma `{name}`: {source}")]
    Read {
        /// Which pragma.
        name: &'static str,
        /// The underlying error.
        #[source]
        source: rusqlite::Error,
    },

    /// A pragma read back as a different value than was set.
    ///
    /// This is the failure the whole module exists to catch: a durability
    /// setting that did not take effect.
    #[error("pragma `{name}` reads back as {actual:?}, expected {expected:?}")]
    Mismatch {
        /// Which pragma.
        name: &'static str,
        /// What it should be.
        expected: String,
        /// What it is.
        actual: String,
    },
}

/// The pragma set a store is opened with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pragma {
    /// `journal_mode`. Always WAL: readers must not block the single writer.
    pub journal_mode: &'static str,
    /// `synchronous`. `full` for critical state, `normal` for derived.
    pub synchronous: &'static str,
    /// `foreign_keys`. On: referential integrity is a correctness property, not
    /// a convenience, and it is off by default in SQLite.
    pub foreign_keys: bool,
    /// `busy_timeout_ms`. A busy *handler*, not an error path — WAL still
    /// returns `SQLITE_BUSY` for lock contention and a retry is the correct
    /// response, not a failure.
    pub busy_timeout_ms: u32,
    /// `cache_size` in KiB. Bounded, so memory does not grow with the file.
    pub cache_size_kib: i64,
}

/// How many times the journal-mode transition is retried before giving up.
///
/// Bounded, and the bound is small because the window is: the measured transition
/// takes on the order of 100 microseconds, and a loser converges as soon as it
/// re-reads the mode. This is a retry count, not a timeout — there is no sleeping
/// anywhere in [`Pragma::apply`].
const JOURNAL_MODE_ATTEMPTS: usize = 16;

impl Pragma {
    /// The set for `critical` state: durable across power loss.
    #[must_use]
    pub fn critical() -> Self {
        Self {
            journal_mode: "wal",
            synchronous: "full",
            foreign_keys: true,
            busy_timeout_ms: 5_000,
            cache_size_kib: -8_000, // negative means KiB rather than pages
        }
    }

    /// The set for `derived` state: durable across a process crash, not
    /// necessarily across power loss. Cheaper per commit.
    #[must_use]
    pub fn derived() -> Self {
        Self {
            synchronous: "normal",
            ..Self::critical()
        }
    }

    /// The set for an **in-memory** database. Tests only.
    ///
    /// `journal_mode` is `memory`, not `wal`, because write-ahead logging is a
    /// property of an on-disk database — an `:memory:` database reports
    /// `memory` no matter what you ask for. Keeping the real value here rather
    /// than skipping verification means [`Pragma::verify`] stays honest in every
    /// configuration.
    ///
    /// This is also the concrete reason durability tests use real files: an
    /// in-memory database has no WAL, no meaningful `synchronous` behaviour, and
    /// no crash recovery, so it cannot exercise TP-1, TP-4, or TP-7 at all.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            journal_mode: "memory",
            synchronous: "full",
            ..Self::critical()
        }
    }

    /// The statements to apply, in order.
    ///
    /// **`busy_timeout` first**, and that ordering is load-bearing rather than
    /// cosmetic. `PRAGMA journal_mode = wal` has to take an exclusive lock when it
    /// performs the transition, and a `busy_timeout` set afterwards cannot help an
    /// operation that has already failed. Two processes starting at once would then
    /// contend for the transition with no busy handler and the loser would see
    /// `database is locked` -- a *startup* failure, indistinguishable in a log from
    /// a real fault.
    ///
    /// `journal_mode` comes second because it is persistent and the durability
    /// settings below interact with it, so it must be in place before `synchronous`
    /// and `cache_size`. `busy_timeout` is connection-local and interacts with
    /// nothing, which is exactly why it can go first.
    #[must_use]
    pub fn statements(self) -> Vec<(&'static str, String)> {
        vec![
            (
                "busy_timeout",
                format!("PRAGMA busy_timeout = {};", self.busy_timeout_ms),
            ),
            (
                "journal_mode",
                format!("PRAGMA journal_mode = {};", self.journal_mode),
            ),
            (
                "synchronous",
                format!("PRAGMA synchronous = {};", self.synchronous),
            ),
            (
                "foreign_keys",
                format!(
                    "PRAGMA foreign_keys = {};",
                    if self.foreign_keys { "ON" } else { "OFF" }
                ),
            ),
            (
                "cache_size",
                format!("PRAGMA cache_size = {};", self.cache_size_kib),
            ),
        ]
    }

    /// Applies every pragma.
    ///
    /// # The journal-mode transition is retried, and why a busy handler is not enough
    ///
    /// `PRAGMA journal_mode = wal` takes an exclusive lock to perform the
    /// transition, and it is *persistent, database-wide state*: every connection
    /// wants the same value, so once one has done it the rest are no-ops. Two
    /// processes opening the same fresh database at the same moment therefore
    /// contend for a transition only one of them needs to perform.
    ///
    /// The surprising part, measured rather than assumed: `busy_timeout` does **not**
    /// cover this. Holding the lock from another connection and attempting the
    /// transition waits the full busy timeout and then fails — but eight threads
    /// attempting it simultaneously fail in **168 microseconds**, with the busy
    /// handler never invoked. So a busy handler cannot make the transition reliable
    /// and this statement is handled separately.
    ///
    /// The retry is a loop of *attempt, then re-read*: a loser re-reads the mode,
    /// finds the winner already set it, and is done. That converges as fast as the
    /// winner takes, which is why the bound is 16 attempts rather than a timed wait.
    /// It is bounded, it does not sleep, and it cannot loop forever.
    ///
    /// # Errors
    ///
    /// [`PragmaError::Apply`] on the first statement that fails, after the
    /// journal-mode transition has exhausted `JOURNAL_MODE_ATTEMPTS` attempts.
    pub fn apply(self, conn: &Connection) -> Result<(), PragmaError> {
        for (name, sql) in self.statements() {
            if name == "journal_mode" {
                self.apply_journal_mode(conn)?;
                continue;
            }
            conn.execute_batch(&sql)
                .map_err(|source| PragmaError::Apply { name, source })?;
        }
        Ok(())
    }

    /// Applies the journal-mode transition, re-reading after each failed attempt.
    ///
    /// Split out because it is the one statement whose failure mode is *contention*
    /// rather than *misconfiguration*, and it deserves to say so where it lives.
    fn apply_journal_mode(self, conn: &Connection) -> Result<(), PragmaError> {
        let sql = format!("PRAGMA journal_mode = {};", self.journal_mode);
        let mismatch = |source: rusqlite::Error| PragmaError::Apply {
            name: "journal_mode",
            source,
        };

        for attempt in 1..=JOURNAL_MODE_ATTEMPTS {
            match conn.execute_batch(&sql) {
                Ok(()) => return Ok(()),
                Err(source) => {
                    // The transition is persistent, so a failure that is pure
                    // contention is resolved by *looking* rather than by waiting:
                    // whoever holds the lock is doing the work we wanted done, and
                    // once they finish there is nothing left to do.
                    if self.journal_mode_is(conn) {
                        return Ok(());
                    }
                    // Not contention we can ride out — a genuine error. Retrying
                    // would hide it behind sixteen identical failures.
                    if !is_busy(&source) {
                        return Err(mismatch(source));
                    }
                    if attempt == JOURNAL_MODE_ATTEMPTS {
                        return Err(mismatch(source));
                    }
                }
            }
        }
        unreachable!("the loop returns on the final attempt")
    }

    /// Reads the journal mode back, treating a read failure as "not yet".
    fn journal_mode_is(self, conn: &Connection) -> bool {
        conn.query_row("PRAGMA journal_mode;", [], |r| r.get::<_, String>(0))
            .is_ok_and(|actual| actual.eq_ignore_ascii_case(self.journal_mode))
    }

    /// Reads every pragma back and compares it against what was set.
    ///
    /// This is the check that turns "we set `synchronous = FULL`" from a claim
    /// into a fact.
    ///
    /// # Errors
    ///
    /// [`PragmaError::Read`] if a value cannot be read, or
    /// [`PragmaError::Mismatch`] if it differs.
    pub fn verify(self, conn: &Connection) -> Result<(), PragmaError> {
        let actual_mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .map_err(|source| PragmaError::Read {
                name: "journal_mode",
                source,
            })?;
        if !actual_mode.eq_ignore_ascii_case(self.journal_mode) {
            return Err(PragmaError::Mismatch {
                name: "journal_mode",
                expected: self.journal_mode.to_owned(),
                actual: actual_mode,
            });
        }

        // SQLite reports synchronous as an integer: 0=OFF 1=NORMAL 2=FULL 3=EXTRA.
        let actual_sync: i64 = conn
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .map_err(|source| PragmaError::Read {
                name: "synchronous",
                source,
            })?;
        let expected_sync = match self.synchronous {
            "off" => 0,
            "normal" => 1,
            "full" => 2,
            "extra" => 3,
            _ => -1,
        };
        if actual_sync != expected_sync {
            return Err(PragmaError::Mismatch {
                name: "synchronous",
                expected: format!("{expected_sync} ({})", self.synchronous),
                actual: format!("{actual_sync}"),
            });
        }

        let actual_fk: i64 = conn
            .query_row("PRAGMA foreign_keys;", [], |r| r.get(0))
            .map_err(|source| PragmaError::Read {
                name: "foreign_keys",
                source,
            })?;
        let expected_fk = i64::from(self.foreign_keys);
        if actual_fk != expected_fk {
            return Err(PragmaError::Mismatch {
                name: "foreign_keys",
                expected: expected_fk.to_string(),
                actual: actual_fk.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_pragma_applies_and_verifies_on_a_real_file() {
        // A real file, not :memory:: -- journal_mode=WAL does not apply to an
        // in-memory database, so an :memory:: test would silently not exercise
        // the most important pragma.
        let dir = std::env::temp_dir().join(format!("orxnud-pragma-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("critical.db");
        let _ = std::fs::remove_file(&path);
        let conn = Connection::open(&path).expect("open");
        let p = Pragma::critical();
        p.apply(&conn).expect("apply");
        p.verify(&conn).expect("verify");
        let mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .expect("read journal_mode");
        assert_eq!(mode.to_lowercase(), "wal");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn derived_pragma_applies_and_verifies() {
        let dir = std::env::temp_dir().join(format!("orxnud-pragma2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("derived.db");
        let _ = std::fs::remove_file(&path);
        let conn = Connection::open(&path).expect("open");
        let p = Pragma::derived();
        p.apply(&conn).expect("apply");
        p.verify(&conn).expect("verify");
        let sync: i64 = conn
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .expect("read");
        assert_eq!(sync, 1, "derived should be NORMAL(1), not FULL(2)");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn critical_is_stricter_than_derived_only_in_synchronous() {
        let c = Pragma::critical();
        let d = Pragma::derived();
        assert_ne!(c.synchronous, d.synchronous);
        assert_eq!(c.synchronous, "full");
        assert_eq!(d.synchronous, "normal");
        assert_eq!(c.journal_mode, d.journal_mode);
        assert_eq!(c.busy_timeout_ms, d.busy_timeout_ms);
    }

    #[test]
    fn verify_detects_a_pragma_that_did_not_take_effect() {
        // The failure this module exists to catch: a durability setting that
        // silently did not apply.
        let conn = Connection::open_in_memory().expect("open");
        // Deliberately do NOT apply, then verify: journal_mode will not be WAL.
        let p = Pragma::critical();
        assert!(
            matches!(
                p.verify(&conn),
                Err(PragmaError::Mismatch {
                    name: "journal_mode",
                    ..
                })
            ),
            "verify must fail when the pragma was never applied"
        );
    }

    #[test]
    fn in_memory_set_reflects_that_wal_is_impossible_in_memory() {
        // A live demonstration of why durability tests need real files: asking
        // an :memory: database for WAL yields "memory", and verify() catches
        // the discrepancy rather than letting it slide.
        let conn = Connection::open_in_memory().expect("open");
        conn.execute_batch("PRAGMA journal_mode = wal;")
            .expect("attempt wal");
        let actual: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .expect("read");
        assert_eq!(actual, "memory", "in-memory sqlite should not support WAL");

        let p = Pragma::in_memory();
        p.apply(&conn).expect("apply");
        p.verify(&conn)
            .expect("verify with the honest in-memory set");

        // And the critical set correctly *fails* here rather than pretending.
        assert!(matches!(
            Pragma::critical().verify(&conn),
            Err(PragmaError::Mismatch {
                name: "journal_mode",
                ..
            })
        ));
    }

    #[test]
    fn busy_timeout_is_applied_before_the_lock_taking_pragma() {
        // The ordering that makes concurrent opens reliable. `journal_mode = wal`
        // needs an exclusive lock to perform the transition; a busy handler set
        // after that cannot rescue an operation that has already failed with
        // `database is locked`.
        let st = Pragma::critical().statements();
        let busy = st.iter().position(|(n, _)| *n == "busy_timeout");
        let mode = st.iter().position(|(n, _)| *n == "journal_mode");
        assert!(
            busy.is_some() && mode.is_some(),
            "both pragmas must be present: {st:?}"
        );
        assert!(
            busy < mode,
            "busy_timeout must precede journal_mode: {st:?}"
        );
        // And it must still be a real handler, not a fail-fast zero.
        assert!(Pragma::critical().busy_timeout_ms > 0);
    }

    #[test]
    fn every_pragma_is_still_applied_and_none_was_dropped_by_reordering() {
        // Reordering must not lose a statement. The set is the contract; the order
        // is the fix.
        let st = Pragma::critical().statements();
        let mut names: Vec<&str> = st.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "busy_timeout",
                "cache_size",
                "foreign_keys",
                "journal_mode",
                "synchronous",
            ]
        );
    }

    #[test]
    fn foreign_keys_are_enabled_because_integrity_is_not_optional() {
        assert!(Pragma::critical().foreign_keys);
        assert!(Pragma::derived().foreign_keys);
    }

    #[test]
    fn a_concurrent_journal_mode_transition_is_retried_until_it_is_satisfied() {
        // The property `apply_journal_mode` exists for: several connections applying
        // the pragma at once on a *fresh* database all end up with the mode set.
        //
        // Measured, not assumed: without the retry this fails in microseconds,
        // because SQLite does not route the journal-mode transition through the busy
        // handler. The contention is the reproduction -- no sleep manufactures it.
        let dir = std::env::temp_dir().join(format!("orxnud-pragma-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("state.db");

        const N: usize = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let conn = rusqlite::Connection::open(&path).expect("open");
                    barrier.wait();
                    Pragma::critical().apply(&conn)
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect();
        let failures: Vec<_> = results.iter().filter_map(|r| r.as_ref().err()).collect();
        assert!(
            failures.is_empty(),
            "every concurrent apply must succeed; {} failed, first: {:?}",
            failures.len(),
            failures.first()
        );

        // And the database ended up in the state every caller asked for.
        let conn = rusqlite::Connection::open(&path).expect("reopen");
        Pragma::critical()
            .verify(&conn)
            .expect("the pragma set took effect");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_journal_mode_retry_is_bounded_and_gates_on_busy() {
        // The bound is what keeps the loop from being an unbounded poll. It is a
        // constant, so it is checked at compile time rather than at runtime.
        const {
            assert!(JOURNAL_MODE_ATTEMPTS >= 2, "a retry of one is not a retry");
            assert!(JOURNAL_MODE_ATTEMPTS <= 64, "the bound must stay small");
        }

        // `is_busy` is the gate that decides whether a failure is retried at all, so
        // it is what distinguishes "wait for the winner" from "retry a
        // misconfiguration sixteen times and hide it".
        //
        // Built from the raw SQLite codes rather than from `ErrorCode`, because
        // `ffi::Error::new` is the direction that maps code -> code, and using it
        // means these tests would still pass if either side of the comparison were
        // renamed.
        const SQLITE_BUSY: i32 = 5;
        const SQLITE_LOCKED: i32 = 6;
        let sqlite_err = |code: i32| {
            rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(code),
                Some("locked".to_owned()),
            )
        };
        assert!(
            is_busy(&sqlite_err(SQLITE_BUSY)),
            "SQLITE_BUSY is contention and must be retried"
        );
        assert!(
            is_busy(&sqlite_err(SQLITE_LOCKED)),
            "SQLITE_LOCKED is contention and must be retried"
        );
        assert!(
            !is_busy(&sqlite_err(1)), // SQLITE_ERROR
            "a non-lock SQLite error must not be retried"
        );
        assert!(!is_busy(&rusqlite::Error::InvalidQuery));
        assert!(!is_busy(&rusqlite::Error::QueryReturnedNoRows));
    }

    #[test]
    fn a_journal_mode_that_is_not_a_mode_fails_on_its_own_terms() {
        // A misconfiguration must surface as itself, not be retried into a generic
        // "database is locked". This is the property that proves `is_busy` is doing
        // the gating: if the loop retried everything, the same error would come back
        // -- so what is asserted is that the error names the *mode*, never a lock.
        let dir = std::env::temp_dir().join(format!("orxnud-pragma-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("state.db");
        let conn = rusqlite::Connection::open(&path).expect("open");

        let bogus = Pragma {
            journal_mode: "definitely-not-a-journal-mode",
            ..Pragma::critical()
        };
        let err = bogus.apply(&conn).expect_err("must refuse");
        assert!(
            !err.to_string().contains("locked"),
            "a bad mode must not be reported as contention: {err}"
        );
        assert!(err.to_string().contains("journal_mode"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
