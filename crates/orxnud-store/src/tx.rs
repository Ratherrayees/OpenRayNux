//! The transaction that durable-authority mutations must run inside.
//!
//! # The one decision this module makes
//!
//! A mutation of durable authority -- a task state transition, a lease, an approval
//! spend -- has to hold SQLite's write lock from **before its first read** until after
//! its last write. `BEGIN IMMEDIATE` is the only way to ask for that. The reason is
//! documented in [`authority_transaction`], and it is short enough to state twice.
//!
//! Everything else in the store opens its transaction the obvious way. That is not
//! inconsistency: the other transactions do not read before they write, and
//! [`authority_transaction`] exists precisely because the task layer does.
//!
//! # Why not `EXCLUSIVE`
//!
//! `EXCLUSIVE` also takes the write lock at `BEGIN`, and additionally prevents readers.
//! In WAL mode readers are already decoupled from the writer, and `busy_timeout` exists
//! to make writer/writer contention wait rather than fail. Taking the database
//! exclusively would turn every state transition into a stop-the-world event for every
//! reader in the process -- the daemon's status reads included -- to buy nothing.
//!
//! # Why not `DEFERRED`
//!
//! Because the write lock is then taken at the first *write*, and the task layer reads
//! first. Measured, not assumed: a deferred read-then-write whose snapshot a competing
//! writer has invalidated fails with `SQLITE_BUSY_SNAPSHOT` -- extended code 5 -- and
//! SQLite never passes that code to the busy handler, because waiting cannot turn a
//! stale snapshot into a current one. `busy_timeout` does not rescue it. The failure
//! renders as "database is locked": no reason, no statement of which decision became
//! undecidable, and indistinguishable at the call site from a genuine lock.
//!
//! See `crates/orxnud-task/tests/v95_concurrency.rs`, which reproduces all of that with
//! two real connections and asserts the difference afterwards.

use rusqlite::{Connection, Transaction, TransactionBehavior};

/// Begins the transaction that a durable-authority mutation must run inside.
///
/// `IMMEDIATE`. Not a preference, and not a performance trade: the alternative loses the
/// ability to decide.
///
/// A task transition is a read followed by a conditional write. The read answers "is
/// this still legal?", and the write asserts that the answer still holds. With the write
/// lock taken only at the write, another connection can commit in between, and then:
///
/// * the decision was made against a snapshot that no longer exists, and
/// * the write is refused outright with `SQLITE_BUSY_SNAPSHOT`, which no busy handler
///   and no `busy_timeout` can wait out.
///
/// The refusal is safe but useless: it says "database is locked" for an operation that
/// was not contended at all, and it tells the caller nothing about which authority
/// question became unanswerable. Taking the lock up front converts that failure into the
/// operation's own typed refusal, after it has re-read current state -- which is the
/// answer a caller can act on.
///
/// # Why this is one function rather than a call at each site
///
/// Transaction semantics are exactly the kind of thing that decays quietly. One name,
/// one body, one place to read: if a future operation needs different semantics it has to
/// argue with this module instead of quietly typing `unchecked_transaction()`.
///
/// # Errors
///
/// Any SQLite error, including `SQLITE_BUSY` if `busy_timeout` expires before the write
/// lock becomes available.
pub fn authority_transaction(conn: &Connection) -> Result<Transaction<'_>, rusqlite::Error> {
    Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
}

#[cfg(test)]
mod tests {
    use super::authority_transaction;
    use crate::migration::MigrationRunner;
    use crate::pragma::Pragma;
    use rusqlite::{Connection, Transaction, TransactionBehavior};

    /// A real file, because locking is a property of a shared database. Two
    /// `:memory:` connections are two *different* databases and would share no lock, so
    /// a test written on them would pass for the wrong reason -- which is the failure
    /// mode this whole milestone is about.
    fn path(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("orxnud-v95-tx-{}-{tag}.db", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn open(p: &std::path::Path) -> Connection {
        let conn = Connection::open(p).expect("open");
        Pragma::critical().apply(&conn).expect("pragmas");
        MigrationRunner::new(&conn).run(true).expect("migrate");
        conn
    }

    /// A second connection to the *same already-migrated* file.
    ///
    /// It deliberately does not migrate. Re-running migrations from a peer means reading
    /// `schema_meta`, which takes a read snapshot -- and a peer that has taken a snapshot
    /// cannot later upgrade to a writer against a WAL that has moved on. That is
    /// SQLITE_BUSY_SNAPSHOT again, this time caused by the test harness rather than the
    /// code, which is a good illustration of how easy the trap is to fall into.
    fn peer(p: &std::path::Path) -> Connection {
        let conn = Connection::open(p).expect("open peer");
        Pragma::critical().apply(&conn).expect("peer pragmas");
        conn
    }

    /// The mode is asserted rather than documented. A comment saying `IMMEDIATE` above
    /// `unchecked_transaction()` is exactly what went wrong, so the executable statement
    /// is the thing under test.
    #[test]
    fn authority_transaction_begins_immediate() {
        let p = path("immediate");
        let conn = open(&p);
        let tx = authority_transaction(&conn).expect("begin");

        let other = peer(&p);
        assert!(
            other.execute_batch("BEGIN IMMEDIATE;").is_err(),
            "another connection took the write lock while `authority_transaction` was \
             open. That is only true under IMMEDIATE: a DEFERRED transaction does not \
             hold the write lock until its first write, so this would succeed and the \
             difference would be untestable."
        );

        tx.commit().expect("commit");

        // After the commit the lock is free again, so the assertion above is a statement
        // about the lock and not about a database that has stopped accepting writers.
        other
            .execute_batch("BEGIN IMMEDIATE;")
            .expect("the lock must be released on commit");
        let _ = std::fs::remove_file(&p);
    }

    /// The control that gives the test above its meaning: the same two connections, the
    /// same instant, under `DEFERRED` -- and the second writer gets in.
    #[test]
    fn a_deferred_transaction_would_not_hold_the_write_lock_yet() {
        let p = path("deferred");
        let conn = open(&p);
        let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Deferred)
            .expect("begin deferred");

        let other = peer(&p);
        assert!(
            other.execute_batch("BEGIN IMMEDIATE;").is_ok(),
            "a DEFERRED transaction holds no write lock before its first write. This is \
             the entire reason `authority_transaction` exists, asserted rather than \
             described."
        );
        other
            .execute_batch("ROLLBACK;")
            .expect("release the second writer");
        drop(tx);
        let _ = std::fs::remove_file(&p);
    }
}
