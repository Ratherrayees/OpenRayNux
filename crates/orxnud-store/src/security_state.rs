//! Durable security state: the audit journal and the spent-approval ledger.
//!
//! # One connection each, to the same file
//!
//! Both adapters own their own [`Connection`] rather than borrowing the task
//! service's. That is deliberate and it is not a violation of ADR-0006's
//! single-writer rule: that rule is **per region**, and `audit_log` and
//! `spent_approvals` are their own regions, separate from the task tables. One
//! region, one writer — this file is that writer.
//!
//! Borrowing instead would put a lifetime on `PolicyEngine`, which the governed
//! dispatcher holds by `&mut`, and that parameter would then propagate into every
//! type that names a policy engine. Owning the connection is what keeps the
//! port free of lifetimes.
//!
//! # Ordering and atomicity come from SQLite, not from a mutex
//!
//! `audit_log.seq` is the primary key, so a writer whose idea of the chain head
//! went stale fails at insert rather than forking the journal -- and it fails with
//! [`JournalError::PositionTaken`], which names the reason and tells the caller to
//! reload instead of retrying blindly. Two writers *can* both read the same head;
//! what they cannot both do is record it.
//!
//! `spent_approvals.digest` is the primary key, so single-use approval is one
//! `INSERT` — not a `SELECT` followed by an `INSERT`, which is race-prone by
//! construction and would let two dispatches both succeed.
//!
//! No process-local lock appears anywhere in this file, and none should be added:
//! a mutex here would be correct for one process and useless for two, which is
//! precisely the case durability is for.

use rusqlite::{Connection, OptionalExtension, params};

use orxnud_domain::ApprovalDigest;
use orxnud_domain::security_state::{
    ApprovalLedger, AuditJournal, JournalEntry, JournalError, LedgerError,
};

use crate::migration::MigrationRunner;
use crate::pragma::Pragma;

/// A SQLite-backed [`AuditJournal`].
///
/// # Verifying what was loaded
///
/// This type stores what the chain computed; it cannot check it. Verification is
/// `orxnud_audit::AuditChain::restore`'s job, because the chain owns the
/// hashing algorithm. It is written as plain code rather than a link on purpose:
/// `orxnud-audit` depends on this crate, so this crate cannot name it. Loading
/// and verifying are separate steps on purpose: a corrupted journal must be
/// *detected and reported*, not quietly repaired, and only the component that
/// knows the algorithm can tell corruption from a legitimately empty journal.
#[derive(Debug)]
pub struct SqliteAuditJournal {
    conn: Connection,
    /// Shared ownership, held for the journal's lifetime (S-31).
    _ownership: crate::ownership::SharedOwnership,
}

impl SqliteAuditJournal {
    /// # Concurrency
    ///
    /// Two *adapters over one file* is the supported arrangement, and concurrent
    /// writes through them are serialised by SQLite. Concurrent **opens** are also
    /// supported: the journal-mode transition is retried with a re-read
    /// ([`crate::pragma::Pragma::apply`]) and migrations run `BEGIN IMMEDIATE`, so
    /// several processes opening one fresh database at the same instant all succeed.
    /// See `concurrent_opens_of_one_database_all_succeed`.
    /// Opens the journal on an existing database file, applying any pending
    /// migration so a caller cannot read a table that does not exist yet.
    ///
    /// # Errors
    ///
    /// [`JournalError::Unavailable`] if the database cannot be opened, migrated,
    /// or given the critical pragmas.
    pub fn open(path: &std::path::Path) -> Result<Self, JournalError> {
        let unavailable = |e: String| JournalError::Unavailable(e);
        // Read *before* the file is opened or created. Only a file this call created may
        // be removed after a failed first migration.
        let pre_existing = path.exists();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| unavailable(e.to_string()))?;
        }
        // S-31: ownership before the connection. The audit journal is the record of
        // what the system did; it is exactly the thing that must not be writable
        // behind a restore's back.
        let ownership =
            crate::ownership::acquire_shared(path).map_err(|e| unavailable(e.to_string()))?;
        let conn = Connection::open(path).map_err(|e| unavailable(e.to_string()))?;
        // `critical`, not `derived`: a lost audit record is a lost record, and
        // this table is the `critical` region ADR-0028 names for exactly this.
        let pragma = Pragma::critical();
        pragma
            .apply(&conn)
            .map_err(|e| unavailable(e.to_string()))?;
        pragma
            .verify(&conn)
            .map_err(|e| unavailable(e.to_string()))?;
        // The whole database's schema is migrated here, not just the journal's: every
        // migration in `MIGRATIONS` creates tables in this one file, and this function
        // runs **before** `TaskService::open` does. So this is the site's first shot at
        // changing the schema, and it is the site S-11 recorded as taking no snapshot and
        // restoring nothing.
        //
        // It now takes the same route every other production caller takes: a verified
        // snapshot before any statement runs, and a restore on failure. The sequence is
        // the awkward part — the restore needs *exclusive* ownership and this function
        // holds a *shared* lease plus an open connection, and `flock` conflicts between
        // them even in one process — so both are dropped before recovery.
        match MigrationRunner::new(&conn).migrate(path) {
            Ok(_) => Ok(Self {
                conn,
                _ownership: ownership,
            }),
            Err(crate::migration::MigrationError::RecoveryRequired { source, snapshot }) => {
                // Drop the connection and the shared lease before anything asks for
                // exclusive ownership. Scoped so the drops happen on this path rather than
                // at the end of the function.
                drop(conn);
                drop(ownership);
                crate::migration::recover_from_snapshot(path, &snapshot)
                    .map_err(|e| unavailable(e.to_string()))?;
                Err(unavailable(source.to_string()))
            }
            Err(e) => {
                drop(conn);
                drop(ownership);
                // A failure with no snapshot to recover from, on a file this call created:
                // remove it, so the next start begins clean instead of inheriting a
                // half-built schema. `pre_existing` was read before opening, so a file
                // that was already there is never touched.
                crate::migration::discard_failed_initialisation(path, pre_existing);
                Err(unavailable(e.to_string()))
            }
        }
    }

    /// An in-memory journal, migrated. **Tests only** — a real install must not
    /// lose the audit history when the process ends.
    ///
    /// `#[cfg(test)]` rather than a doc comment saying "tests only". The journal it builds
    /// is *ephemeral by construction* -- an in-memory database is gone when the process
    /// ends, so the tamper evidence the system exists to keep simply evaporates. A public
    /// function that can only be misused, documented not to be, is the same shape as the
    /// `snapshot_verified: bool` this crate was audited for (S-11/F-26): a claim where a
    /// boundary belongs. Compiling it out puts the refusal in the type system.
    ///
    /// The companion [`SqliteAuditJournal::migrate`] that used to let any caller migrate a
    /// connection it had been handed is gone for the same reason. `Self::open` is the only
    /// way to obtain a journal over a real database, and it snapshots first.
    #[cfg(test)]
    #[must_use]
    fn open_in_memory() -> Self {
        let conn = Connection::open_in_memory().expect("in-memory connection");
        MigrationRunner::new(&conn)
            .migrate_ephemeral()
            .expect("migrate the in-memory journal");
        Self {
            conn,
            // No file, so nothing to coordinate across processes.
            _ownership: crate::ownership::SharedOwnership::in_memory(),
        }
    }

    /// The connection, for tests that need to corrupt a row on purpose.
    #[must_use]
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

impl AuditJournal for SqliteAuditJournal {
    fn append(&self, entry: &JournalEntry) -> Result<(), JournalError> {
        let unavailable = |e: rusqlite::Error| JournalError::Unavailable(e.to_string());
        // DEFERRED, and it does not need to be anything else. V-95.
        //
        // This comment previously said "`IMMEDIATE` before the read: taking the write
        // lock first is what stops two writers both computing the same successor",
        // over a `DEFERRED` transaction -- and the claim was wrong twice over. There is
        // no read in this transaction: its only statement is the `INSERT`, so the write
        // lock is taken on the first statement either way. And the read that decides the
        // successor is not here at all -- it belongs to the caller, which must load the
        // chain head, hash it, and then call `append`.
        //
        // That caller's race is real, and the primary key is what resolves it: two
        // writers that both computed `seq = N` collide, and the loser gets
        // `JournalError::PositionTaken`, which says its idea of the head was stale and
        // that it must reload rather than retry blindly. That is a classified refusal
        // naming the reason -- the same shape `TaskRepository` now produces for a lost
        // authority race, arrived at by a different mechanism. Fixing it properly would
        // mean moving the head read inside this transaction, which is a change to the
        // journal's interface and out of scope for V-95; it is recorded as a follow-up.
        let tx = self.conn.unchecked_transaction().map_err(unavailable)?;
        tx.execute(
            "INSERT INTO audit_log (seq, prev_hash, record_hash, record)
             VALUES (?1, ?2, ?3, ?4);",
            params![
                entry.seq as i64,
                entry.prev_hash.as_slice(),
                entry.hash.as_slice(),
                String::from_utf8_lossy(&entry.payload),
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                JournalError::PositionTaken { seq: entry.seq }
            }
            other => unavailable(other),
        })?;
        tx.commit().map_err(unavailable)
    }

    fn entries(&self) -> Result<Vec<JournalEntry>, JournalError> {
        let unavailable = |e: rusqlite::Error| JournalError::Unavailable(e.to_string());
        let mut stmt = self
            .conn
            .prepare("SELECT seq, prev_hash, record_hash, record FROM audit_log ORDER BY seq;")
            .map_err(unavailable)?;
        let rows = stmt
            .query_map([], |row| {
                let seq: i64 = row.get(0)?;
                let prev: Vec<u8> = row.get(1)?;
                let hash: Vec<u8> = row.get(2)?;
                let payload: String = row.get(3)?;
                Ok((seq, prev, hash, payload))
            })
            .map_err(unavailable)?;

        let mut out = Vec::new();
        for r in rows {
            let (seq, prev, hash, payload) = r.map_err(unavailable)?;
            let bad = |what: &str| JournalError::Undecodable {
                seq: seq.unsigned_abs(),
                reason: what.to_owned(),
            };
            let seq = u64::try_from(seq).map_err(|_| bad("negative sequence number"))?;
            let prev: [u8; 32] = prev
                .try_into()
                .map_err(|_| bad("prev_hash is not 32 bytes"))?;
            let hash: [u8; 32] = hash
                .try_into()
                .map_err(|_| bad("record_hash is not 32 bytes"))?;
            out.push(JournalEntry {
                seq,
                prev_hash: prev,
                hash,
                payload: payload.into_bytes(),
            });
        }
        Ok(out)
    }

    fn len(&self) -> Result<u64, JournalError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_log;", [], |row| row.get(0))
            .map_err(|e| JournalError::Unavailable(e.to_string()))?;
        u64::try_from(n).map_err(|_| JournalError::Unavailable("negative count".into()))
    }
}

/// A SQLite-backed [`ApprovalLedger`].
///
/// # Atomicity
///
/// [`consume_at`](ApprovalLedger::consume_at) is one `INSERT`. The primary key does the
/// work: a second insert of the same digest raises a uniqueness violation, which
/// becomes [`LedgerError::AlreadyConsumed`]. There is no window between "have I
/// used this?" and "mark it used", which is the window a `SELECT`-then-`INSERT`
/// implementation would leave open.
pub struct SqliteApprovalLedger {
    conn: Connection,
    /// Shared ownership, held for the ledger's lifetime (S-31).
    ///
    /// The approval ledger decides what may execute. A restore that ran while another
    /// process could write it would be restoring a record of decisions that had
    /// already moved on, so it participates like every other open.
    _ownership: crate::ownership::SharedOwnership,
}

impl std::fmt::Debug for SqliteApprovalLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the connection: it can carry the whole database path.
        f.debug_struct("SqliteApprovalLedger")
            .finish_non_exhaustive()
    }
}

impl SqliteApprovalLedger {
    /// Opens the ledger on an existing database file.
    ///
    /// # Concurrency
    ///
    /// Same as [`SqliteAuditJournal::open`]: concurrent opens of one database are
    /// supported. Concurrent writes are serialised by the write lock and the primary key,
    /// not by a transaction mode -- this type opens no transaction at all.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Unavailable`] if the database cannot be opened, migrated,
    /// or given the critical pragmas.
    pub fn open(path: &std::path::Path) -> Result<Self, LedgerError> {
        let unavailable = |e: String| LedgerError::Unavailable(e);
        // Read *before* the file is opened or created; see `Journal::open`.
        let pre_existing = path.exists();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|e| unavailable(e.to_string()))?;
        }
        let ownership =
            crate::ownership::acquire_shared(path).map_err(|e| unavailable(e.to_string()))?;
        let conn = Connection::open(path).map_err(|e| unavailable(e.to_string()))?;
        let pragma = Pragma::critical();
        pragma
            .apply(&conn)
            .map_err(|e| unavailable(e.to_string()))?;
        pragma
            .verify(&conn)
            .map_err(|e| unavailable(e.to_string()))?;
        // As with `SqliteAuditJournal::open`: this migrates the whole database, and this
        // is the site's first attempt at it. The approval ledger is the replay gate that
        // stops one approval being presented twice across restarts, so a half-applied
        // migration here is the failure mode K.1 is about.
        match MigrationRunner::new(&conn).migrate(path) {
            Ok(_) => Ok(Self {
                conn,
                _ownership: ownership,
            }),
            Err(crate::migration::MigrationError::RecoveryRequired { source, snapshot }) => {
                drop(conn);
                drop(ownership);
                crate::migration::recover_from_snapshot(path, &snapshot)
                    .map_err(|e| unavailable(e.to_string()))?;
                Err(unavailable(source.to_string()))
            }
            Err(e) => {
                drop(conn);
                drop(ownership);
                // A failure with no snapshot to recover from, on a file this call created:
                // remove it, so the next start begins clean instead of inheriting a
                // half-built schema. `pre_existing` was read before opening, so a file
                // that was already there is never touched.
                crate::migration::discard_failed_initialisation(path, pre_existing);
                Err(unavailable(e.to_string()))
            }
        }
    }
}

impl ApprovalLedger for SqliteApprovalLedger {
    fn consume_at(&mut self, digest: &ApprovalDigest, now_ms: i64) -> Result<(), LedgerError> {
        let unavailable = |e: rusqlite::Error| LedgerError::Unavailable(e.to_string());
        // One statement. The uniqueness violation *is* the single-use mechanism, and the
        // timestamp is written by that same statement -- so there is no window in which a
        // digest is recorded as spent with no time, or timed with no spend. V-94.
        //
        // The violation is classified by *extended* code, not by "is it a constraint
        // violation". `spent_approvals` has a CHECK on the digest's length, so a
        // malformed digest would otherwise arrive here as `AlreadyConsumed` -- telling
        // the caller this approval was already spent, when in fact it was never a
        // digest. Single-use is a primary-key property and is reported as one.
        self.conn
            .execute(
                "INSERT INTO spent_approvals (digest, consumed_at_ms) VALUES (?1, ?2);",
                params![digest.as_bytes().as_slice(), now_ms],
            )
            .map(|_| ())
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation
                        && f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY =>
                {
                    LedgerError::AlreadyConsumed
                }
                rusqlite::Error::SqliteFailure(f, m)
                    if f.code == rusqlite::ErrorCode::ConstraintViolation =>
                {
                    // A constraint that is not the primary key: the row was refused for
                    // a reason that has nothing to do with a replay, and reporting it as
                    // one would tell the caller to stop retrying when retrying cannot help.
                    LedgerError::Unavailable(format!(
                        "the spent-approval ledger refused the row: {}",
                        m.unwrap_or_else(|| format!("code {}", f.extended_code))
                    ))
                }
                other => unavailable(other),
            })
    }

    fn is_consumed(&self, digest: &ApprovalDigest) -> Result<bool, LedgerError> {
        self.conn
            .query_row(
                "SELECT 1 FROM spent_approvals WHERE digest = ?1;",
                params![digest.as_bytes().as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map(|found| found.is_some())
            .map_err(|e| LedgerError::Unavailable(e.to_string()))
    }
}

/// Convenience: the two adapters for one path.
///
/// Not a builder — just the two calls a composition root would otherwise repeat.
pub mod prelude {
    pub use super::{SqliteApprovalLedger, SqliteAuditJournal};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::CURRENT_VERSION;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn db_path(tag: &str) -> std::path::PathBuf {
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("orxnud-sec-{}-{tag}-{n}", std::process::id()))
    }

    fn digest(n: u8) -> ApprovalDigest {
        ApprovalDigest::from_bytes([n; 32])
    }

    fn entry(seq: u64, hash: [u8; 32]) -> JournalEntry {
        JournalEntry {
            seq,
            prev_hash: [0u8; 32],
            hash,
            payload: format!("record-{seq}").into_bytes(),
        }
    }

    #[test]
    fn the_migration_creates_both_tables_at_the_current_version() {
        let path = db_path("mig");
        let j = SqliteAuditJournal::open(&path).expect("open");
        assert_eq!(
            MigrationRunner::new(j.conn())
                .applied_version()
                .expect("version"),
            CURRENT_VERSION
        );
        let tables: Vec<String> = j
            .conn()
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
            .expect("prepare")
            .query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .map(std::result::Result::unwrap)
            .collect();
        assert!(tables.contains(&"audit_log".to_owned()), "{tables:?}");
        assert!(tables.contains(&"spent_approvals".to_owned()), "{tables:?}");
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn an_appended_entry_is_read_back_in_order() {
        let j = SqliteAuditJournal::open_in_memory();
        for i in 0..3u64 {
            j.append(&entry(i, [i as u8; 32])).expect("append");
        }
        let got = j.entries().expect("entries");
        assert_eq!(got.len(), 3);
        assert_eq!(j.len().expect("len"), 3);
        assert!(!j.is_empty().expect("empty"));
        for (i, e) in got.iter().enumerate() {
            assert_eq!(e.seq, i as u64);
            assert_eq!(e.payload, format!("record-{i}").into_bytes());
        }
    }

    #[test]
    fn a_second_writer_at_the_same_position_is_refused() {
        // The mechanism that stops a stale chain head from forking the journal.
        let path = db_path("collide");
        let a = SqliteAuditJournal::open(&path).expect("open a");
        let b = SqliteAuditJournal::open(&path).expect("open b");
        a.append(&entry(0, [1u8; 32])).expect("first writer");
        let err = b.append(&entry(0, [2u8; 32])).expect_err("second writer");
        assert!(
            matches!(err, JournalError::PositionTaken { seq: 0 }),
            "{err:?}"
        );
        // And the refused write left nothing behind.
        assert_eq!(b.entries().expect("entries").len(), 1);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn the_ledger_refuses_a_replay_and_accepts_a_distinct_digest() {
        let path = db_path("ledger");
        let mut l = SqliteApprovalLedger::open(&path).expect("open");
        l.consume_at(&digest(1), 0).expect("first");
        assert!(l.is_consumed(&digest(1)).expect("read"));
        assert!(matches!(
            l.consume_at(&digest(1), 0),
            Err(LedgerError::AlreadyConsumed)
        ));
        l.consume_at(&digest(2), 0).expect("distinct");
        assert!(!l.is_consumed(&digest(3)).expect("read"));
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn a_spent_approval_survives_the_process() {
        let path = db_path("restart");
        {
            let mut l = SqliteApprovalLedger::open(&path).expect("open");
            l.consume_at(&digest(9), 0).expect("consume");
        }
        let l = SqliteApprovalLedger::open(&path).expect("reopen");
        assert!(
            l.is_consumed(&digest(9)).expect("read"),
            "a consumed approval must still be consumed after a restart"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn two_ledgers_racing_for_one_digest_produce_exactly_one_success() {
        // Two independent connections to one file: the concurrency case durability
        // exists for. Exactly one INSERT wins; the other sees the constraint.
        let dir = db_path("race");
        std::fs::create_dir_all(&dir).expect("mkdir");
        // **The same file**, opened twice. Two different databases would each
        // accept the insert, and two successes would be correct rather than a
        // failure — which is exactly what an earlier version of this test
        // asserted.
        let db = dir.join("state.db");
        let first = SqliteApprovalLedger::open(&db).expect("open a");
        let second = SqliteApprovalLedger::open(&db).expect("open b");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [first, second]
            .into_iter()
            .map(|mut ledger| {
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let d = digest(42);
                    ledger.consume_at(&d, 0)
                })
            })
            .collect();
        let outcomes: Vec<Result<(), LedgerError>> = handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect();

        let wins = outcomes.iter().filter(|r| r.is_ok()).count();
        let replays = outcomes
            .iter()
            .filter(|r| matches!(r, Err(LedgerError::AlreadyConsumed)))
            .count();
        assert_eq!(wins, 1, "exactly one consumer may succeed: {outcomes:?}");
        assert_eq!(replays, 1, "the other must see a replay: {outcomes:?}");

        let check = SqliteApprovalLedger::open(&db).expect("reopen");
        assert!(check.is_consumed(&digest(42)).expect("read"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_length_checks_refuse_a_malformed_hash_before_it_is_ever_stored() {
        // The `CHECK (length(...) = 32)` constraints are not decoration: they make
        // the short-hash corruption path unreachable, so the reader's length check
        // is defence in depth rather than the primary defence.
        let j = SqliteAuditJournal::open_in_memory();
        j.append(&entry(0, [7u8; 32])).expect("append");
        for column in ["record_hash", "prev_hash"] {
            let sql = format!("UPDATE audit_log SET {column} = x'00' WHERE seq = 0;");
            let err = j.conn().execute(&sql, []).expect_err("must be refused");
            assert!(
                err.to_string().contains("CHECK constraint failed"),
                "{column} must be constrained: {err}"
            );
        }
        assert_eq!(
            j.entries().expect("entries").len(),
            1,
            "and nothing changed"
        );
    }

    #[test]
    fn a_payload_that_is_not_a_record_is_reported_rather_than_skipped() {
        // The corruption that *is* reachable: `record` is TEXT with no constraint,
        // so a row can hold something that is not an audit record. Reporting it is
        // what stops a corrupted journal being quietly shorter than it looks.
        let j = SqliteAuditJournal::open_in_memory();
        j.append(&entry(0, [7u8; 32])).expect("append");
        j.conn()
            .execute(
                "UPDATE audit_log SET record = 'not json at all' WHERE seq = 0;",
                [],
            )
            .expect("corrupt");
        // The store hands the bytes back faithfully — it does not interpret them.
        assert_eq!(j.entries().expect("entries")[0].payload, b"not json at all");
        // And the chain, which does interpret them, refuses.
        let err = orxnud_audit_undecodable(&j);
        assert!(err, "a non-record payload must be reported");
    }

    /// Asserts that the *chain* — not the store — refuses a payload it cannot
    /// decode. Kept as a helper so the store test can state that division without
    /// depending on `orxnud-audit`, which depends on this crate.
    fn orxnud_audit_undecodable(j: &SqliteAuditJournal) -> bool {
        // Decode by hand: the store's contract is "return the bytes", so the
        // refusal belongs to whoever defines what a record is.
        j.entries()
            .map(|rows| {
                rows.iter()
                    .all(|r| serde_json::from_slice::<serde_json::Value>(&r.payload).is_err())
            })
            .unwrap_or(false)
    }

    #[test]
    fn a_reopened_journal_reports_the_same_head() {
        let path = db_path("head");
        let hash = [5u8; 32];
        {
            let j = SqliteAuditJournal::open(&path).expect("open");
            j.append(&entry(0, hash)).expect("append");
        }
        let j = SqliteAuditJournal::open(&path).expect("reopen");
        assert_eq!(j.entries().expect("entries")[0].hash, hash);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn the_migration_list_is_ascending_and_unique() {
        let versions: Vec<u32> = crate::migration::MIGRATIONS
            .iter()
            .map(|m| m.version)
            .collect();
        let mut sorted = versions.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(versions, sorted, "versions must ascend with no repeats");
        assert_eq!(*versions.last().expect("non-empty"), CURRENT_VERSION);
        // `security_state` must be applied, but it is no longer *last*: composition
        // landed after it. Pinning the position rather than the name is what lets a later
        // migration exist without either silently reordering the list or requiring this
        // assertion to be rewritten.
        assert!(
            crate::migration::MIGRATIONS
                .iter()
                .any(|m| m.name == "security_state"),
            "security_state must still be a registered migration"
        );
    }

    #[test]
    fn concurrent_opens_of_one_database_all_succeed() {
        // The regression this file's `open` docs describe.
        //
        // `PRAGMA journal_mode = wal` needs an exclusive lock, and `busy_timeout` is
        // what turns a lost race for that lock into a wait rather than an error. If
        // the busy handler is not established *first*, two processes starting at once
        // contend for the journal-mode transition with no handler, and one of them
        // fails with "database is locked" -- which is a startup failure, not a busy
        // condition, and is indistinguishable from a real problem in the log.
        //
        // No sleep is used, and none can be: the reproduction is the contention
        // itself. Eight threads released together on a *fresh* path means eight
        // simultaneous journal-mode transitions, and the first code path that
        // established `journal_mode` before `busy_timeout` failed this.
        let dir = db_path("concurrent-open");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let db = dir.join("state.db");

        const N: usize = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|_| {
                let db = db.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    SqliteAuditJournal::open(&db).map(|_| ())
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
            "every concurrent open must succeed; {} failed, first: {:?}",
            failures.len(),
            failures.first()
        );

        // The shared database is still usable, and the chain is intact.
        let journal = SqliteAuditJournal::open(&db).expect("reopen");
        journal.append(&entry(0, [3u8; 32])).expect("append");
        assert_eq!(journal.entries().expect("entries").len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_opens_of_both_adapters_over_one_database_all_succeed() {
        // The same race through the other adapter, and through both at once, because
        // a daemon and a CLI subprocess would contend exactly this way.
        let dir = db_path("concurrent-both");
        std::fs::create_dir_all(&dir).expect("mkdir");
        let db = dir.join("state.db");

        const N: usize = 6;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let db = db.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    // Both adapters are mapped to the same error shape, because the
                    // point of the test is *that* the open succeeds, not which
                    // adapter it was.
                    if i % 2 == 0 {
                        SqliteAuditJournal::open(&db)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    } else {
                        SqliteApprovalLedger::open(&db)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    }
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
            "every concurrent open must succeed; {} failed, first: {:?}",
            failures.len(),
            failures.first()
        );
        // And both regions exist and work afterwards.
        SqliteAuditJournal::open(&db)
            .expect("journal afterwards")
            .append(&entry(0, [4u8; 32]))
            .expect("append afterwards");
        SqliteApprovalLedger::open(&db)
            .expect("ledger afterwards")
            .consume_at(&digest(1), 0)
            .expect("consume afterwards");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ----------------------------------------------------------------------
    // Production-path recovery: a failing migration must leave the security
    // state exactly as it was, and must leave the journal/ledger unusable rather
    // than half-built.
    //
    // This is the S-11/F-26 regression. `SqliteAuditJournal::open` and
    // `SqliteApprovalLedger::open` used to call `MigrationRunner::run(true)`: no
    // snapshot, no restore, and the two constructors that guard the system's only
    // tamper evidence were the two that changed the schema with nothing to roll
    // back to. These two tests drive the *production* entry points rather than the
    // runner, because the runner behaving correctly while its caller ignores it
    // was the whole defect.
    // ----------------------------------------------------------------------

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("orxnud-secstate-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d.join("state.db")
    }

    /// A file-backed database at `version`, already carrying audit and approval rows.
    ///
    /// Seeded through SQL rather than through the journal's own API, because seeding
    /// through the API would require a working journal -- which is the thing whose
    /// construction is failing.
    fn stage_pre_migration(tag: &str, version: u32) -> std::path::PathBuf {
        let path = tmp_path(tag);
        let c = Connection::open(&path).expect("open");
        crate::pragma::Pragma::critical()
            .apply(&c)
            .expect("pragmas");
        for m in crate::migration::MIGRATIONS
            .iter()
            .filter(|m| m.version <= version)
        {
            c.execute_batch(m.sql)
                .unwrap_or_else(|e| panic!("migration {}: {e}", m.version));
            c.execute(
                "INSERT OR REPLACE INTO schema_meta (version, name, applied_at) VALUES (?1,?2,0);",
                rusqlite::params![m.version, m.name],
            )
            .expect("record");
        }
        c.execute_batch(
            "INSERT INTO tasks (id,kind,state,idempotent,attempts,max_attempts,
                                 created_at_ms,updated_at_ms)
               VALUES ('t1','query','completed',1,1,3,1,1);",
        )
        .expect("task");
        // One audit record and one consumed approval, so recovery has something to lose.
        c.execute(
            "INSERT INTO audit_log (seq, prev_hash, record_hash, record) VALUES (1,?1,?2,'{}');",
            rusqlite::params![[1u8; 32], [2u8; 32]],
        )
        .expect("audit row");
        c.execute(
            "INSERT INTO spent_approvals (digest, consumed_at_ms) VALUES (?1, 7);",
            rusqlite::params![[3u8; 32]],
        )
        .expect("spent approval");
        drop(c);
        path
    }

    /// Two different actions for one execution identity: exactly what migration 14
    /// refuses to guess between.
    fn seed_conflicting_proposals(path: &std::path::Path) {
        let c = Connection::open(path).expect("open");
        for (id, capability, target) in [
            ("p-a", "cap.one", "out.txt"),
            ("p-b", "cap.two", "OTHER.txt"),
        ] {
            c.execute(
                "INSERT INTO task_proposals (proposal_id,task_id,step_no,attempt_no,capability,
                                              target,params,proposer,created_at_ms,status)
                 VALUES (?1,'t1',1,1,?2,?3,'{}','me',100,'pending');",
                rusqlite::params![id, capability, target],
            )
            .expect("proposal");
        }
        drop(c);
    }

    fn audit_and_approval_rows(path: &std::path::Path) -> (i64, i64, u32) {
        let c = Connection::open(path).expect("reopen");
        let audits: i64 = c
            .query_row("SELECT COUNT(*) FROM audit_log;", [], |r| r.get(0))
            .expect("audit count");
        let spent: i64 = c
            .query_row("SELECT COUNT(*) FROM spent_approvals;", [], |r| r.get(0))
            .expect("spent count");
        let version: u32 = c
            .query_row("SELECT MAX(version) FROM schema_meta;", [], |r| r.get(0))
            .expect("version");
        drop(c);
        (audits, spent, version)
    }

    /// `SqliteAuditJournal::open` on a database whose migration fails must restore it.
    #[test]
    fn the_journal_constructor_recovers_the_database_when_its_migration_fails() {
        let path = stage_pre_migration("journal-recover", 13);
        seed_conflicting_proposals(&path);
        assert_eq!(
            audit_and_approval_rows(&path),
            (1, 1, 13),
            "precondition: staged at version 13 with one audit row and one spent approval"
        );

        let Err(err) = SqliteAuditJournal::open(&path) else {
            panic!("migration 14 must refuse the conflicting proposals");
        };
        let text = err.to_string();
        assert!(
            text.contains("authority decision"),
            "the original failure must be reported, not swallowed by the recovery: {text}"
        );

        // The snapshot was taken before anything ran and restored after the failure, so
        // the version is back where it started and the seeded rows are intact. Before this
        // change there was no snapshot and no restore, so the schema was left wherever the
        // failed migration had reached -- which for this database is indistinguishable
        // from a migrated one at a version it never completed.
        assert_eq!(
            audit_and_approval_rows(&path),
            (1, 1, 13),
            "a failed migration must leave the security state exactly as it was"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// The same for `SqliteApprovalLedger::open`.
    #[test]
    fn the_ledger_constructor_recovers_the_database_when_its_migration_fails() {
        let path = stage_pre_migration("ledger-recover", 13);
        seed_conflicting_proposals(&path);

        let Err(err) = SqliteApprovalLedger::open(&path) else {
            panic!("migration 14 must refuse the conflicting proposals");
        };
        assert!(
            err.to_string().contains("authority decision"),
            "the original failure must be reported: {err}"
        );

        assert_eq!(
            audit_and_approval_rows(&path),
            (1, 1, 13),
            "a failed migration must leave the security state exactly as it was"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// The negative control, and the reason the two tests above are worth anything.
    ///
    /// A database with no conflicting proposals migrates, and the journal opens. Without
    /// this, "the constructor failed" would satisfy both tests above -- a constructor that
    /// refuses every database would pass them.
    #[test]
    fn the_journal_constructor_opens_when_the_migration_succeeds() {
        let path = stage_pre_migration("journal-ok", 13);
        let journal = SqliteAuditJournal::open(&path).expect("no conflict, so this must open");
        let (audits, spent, version) = audit_and_approval_rows(&path);
        assert_eq!(
            (audits, spent, version),
            (1, 1, crate::migration::CURRENT_VERSION),
            "a successful migration applies the remaining versions and discards its snapshot"
        );
        // And the migrated database is usable through the normal API. One row is seeded
        // directly by SQL at seq 1, so the next entry is seq 2.
        journal
            .append(&entry(2, [9u8; 32]))
            .expect("append to the journal that opened");
        drop(journal);
        assert_eq!(
            audit_and_approval_rows(&path).0,
            2,
            "the audit chain is writable after the migration"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    /// And the ledger, likewise.
    #[test]
    fn the_ledger_constructor_opens_when_the_migration_succeeds() {
        let path = stage_pre_migration("ledger-ok", 13);
        let _ledger = SqliteApprovalLedger::open(&path).expect("no conflict, so this must open");
        assert_eq!(
            audit_and_approval_rows(&path).2,
            crate::migration::CURRENT_VERSION
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }
}
