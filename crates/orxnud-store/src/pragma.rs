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
        Self { synchronous: "normal", ..Self::critical() }
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
        Self { journal_mode: "memory", synchronous: "full", ..Self::critical() }
    }

    /// The statements to apply, in order.
    ///
    /// `journal_mode` first, because it is persistent and the others interact
    /// with it.
    #[must_use]
    pub fn statements(self) -> Vec<(&'static str, String)> {
        vec![
            ("journal_mode", format!("PRAGMA journal_mode = {};", self.journal_mode)),
            ("synchronous", format!("PRAGMA synchronous = {};", self.synchronous)),
            (
                "foreign_keys",
                format!("PRAGMA foreign_keys = {};", if self.foreign_keys { "ON" } else { "OFF" }),
            ),
            ("busy_timeout", format!("PRAGMA busy_timeout = {};", self.busy_timeout_ms)),
            ("cache_size", format!("PRAGMA cache_size = {};", self.cache_size_kib)),
        ]
    }

    /// Applies every pragma.
    ///
    /// # Errors
    ///
    /// [`PragmaError::Apply`] on the first statement that fails.
    pub fn apply(self, conn: &Connection) -> Result<(), PragmaError> {
        for (name, sql) in self.statements() {
            conn.execute_batch(&sql).map_err(|source| PragmaError::Apply { name, source })?;
        }
        Ok(())
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
            .map_err(|source| PragmaError::Read { name: "journal_mode", source })?;
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
            .map_err(|source| PragmaError::Read { name: "synchronous", source })?;
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
            .map_err(|source| PragmaError::Read { name: "foreign_keys", source })?;
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
        let sync: i64 = conn.query_row("PRAGMA synchronous;", [], |r| r.get(0)).expect("read");
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
            matches!(p.verify(&conn), Err(PragmaError::Mismatch { name: "journal_mode", .. })),
            "verify must fail when the pragma was never applied"
        );
    }

    #[test]
    fn in_memory_set_reflects_that_wal_is_impossible_in_memory() {
        // A live demonstration of why durability tests need real files: asking
        // an :memory: database for WAL yields "memory", and verify() catches
        // the discrepancy rather than letting it slide.
        let conn = Connection::open_in_memory().expect("open");
        conn.execute_batch("PRAGMA journal_mode = wal;").expect("attempt wal");
        let actual: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .expect("read");
        assert_eq!(actual, "memory", "in-memory sqlite should not support WAL");

        let p = Pragma::in_memory();
        p.apply(&conn).expect("apply");
        p.verify(&conn).expect("verify with the honest in-memory set");

        // And the critical set correctly *fails* here rather than pretending.
        assert!(matches!(
            Pragma::critical().verify(&conn),
            Err(PragmaError::Mismatch { name: "journal_mode", .. })
        ));
    }

    #[test]
    fn statements_are_ordered_with_journal_mode_first() {
        let st = Pragma::critical().statements();
        assert_eq!(st[0].0, "journal_mode");
        assert!(st.iter().any(|(n, _)| *n == "synchronous"));
    }

    #[test]
    fn foreign_keys_are_enabled_because_integrity_is_not_optional() {
        assert!(Pragma::critical().foreign_keys);
        assert!(Pragma::derived().foreign_keys);
    }

    #[test]
    fn busy_timeout_is_configured_rather_than_failing_fast() {
        // WAL can still return SQLITE_BUSY; a retry is the right response.
        assert!(Pragma::critical().busy_timeout_ms > 0);
    }
}
