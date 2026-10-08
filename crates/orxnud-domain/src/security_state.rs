//! Ports for the two pieces of security state that must outlive a process.
//!
//! # Why these live in the domain crate
//!
//! Not because they are domain *concepts* — they are storage ports — but because
//! of the dependency direction. `orxnud-store` cannot depend on `orxnud-audit`
//! or `orxnud-policy`, because both of those already depend on it. A port defined
//! by its consumer, in a crate every layer shares, is the only placement that
//! keeps `orxnud-store` the single crate that speaks SQL.
//!
//! This is the arrangement `platform.rs` already uses for
//! [`SecretsContract`](crate::platform::SecretsContract): a pure trait here, a
//! SQLite implementation in the store, and consumers that cannot see the SQL.
//!
//! # Why the audit port carries opaque bytes
//!
//! [`AuditJournal`] does not know what an audit record *is*. It stores a
//! sequence number, two hashes, and a payload chosen by the caller.
//! `orxnud-audit` owns the canonical form and the BLAKE3 chain algorithm, and
//! this port persists the *inputs and results* of that computation rather than
//! re-deriving them. A second hashing implementation is a second definition of the
//! chain, and two definitions of a tamper-evidence mechanism is worse than one
//! weak one.
//!
//! # What is deliberately not here
//!
//! No secret material. Neither port can carry a credential value: the audit
//! payload is whatever the caller serialises, and the caller is the chain, which
//! has no field that could hold one.

use crate::approval::ApprovalDigest;

/// One persisted audit entry, as the store sees it.
///
/// Opaque by design — see the module docs. The store validates and persists these
/// fields; it does not interpret them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEntry {
    /// Monotonic position in the chain. The store's primary key, so two writers
    /// cannot claim the same position.
    pub seq: u64,
    /// The hash of the entry before this one, or all zeroes for the first.
    pub prev_hash: [u8; 32],
    /// This entry's hash, as computed by the chain.
    pub hash: [u8; 32],
    /// The canonical serialisation the hash was computed over.
    pub payload: Vec<u8>,
}

/// A failure writing or reading the durable audit journal.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The underlying storage refused the operation.
    #[error("audit journal unavailable: {0}")]
    Unavailable(String),

    /// Another writer already holds this sequence number.
    ///
    /// Distinct from [`Self::Unavailable`] because it means the *chain* lost a
    /// race for a position, not that storage is down. The caller must not retry
    /// blindly: it must reload, because its idea of the head was wrong.
    #[error("audit journal position {seq} is already taken: the chain head is stale")]
    PositionTaken {
        /// The contested position.
        seq: u64,
    },

    /// A stored entry could not be decoded into a record.
    #[error("audit journal entry {seq} could not be decoded: {reason}")]
    Undecodable {
        /// Where the failure was found.
        seq: u64,
        /// What went wrong.
        reason: String,
    },
}

/// Durable, append-only storage for audit chain entries.
///
/// # Ordering
///
/// Implementations must serialise concurrent writers and must reject a second
/// write to an occupied [`JournalEntry::seq`]. A process-local lock is not
/// sufficient: two `OpenRayNux` processes on one machine would each hold their own.
#[allow(clippy::module_name_repetitions)]
pub trait AuditJournal {
    /// Persists one entry.
    ///
    /// # Errors
    ///
    /// [`JournalError::PositionTaken`] if `entry.seq` is already occupied, or
    /// [`JournalError::Unavailable`] if storage refused the write. On error
    /// nothing is persisted.
    fn append(&self, entry: &JournalEntry) -> Result<(), JournalError>;

    /// Every persisted entry, in sequence order.
    ///
    /// # Errors
    ///
    /// [`JournalError::Unavailable`] if storage could not be read.
    fn entries(&self) -> Result<Vec<JournalEntry>, JournalError>;

    /// How many entries are persisted.
    ///
    /// # Errors
    ///
    /// [`JournalError::Unavailable`] if storage could not be read.
    fn len(&self) -> Result<u64, JournalError>;

    /// Whether the journal is empty.
    ///
    /// # Errors
    ///
    /// [`JournalError::Unavailable`] if storage could not be read.
    fn is_empty(&self) -> Result<bool, JournalError> {
        Ok(self.len()? == 0)
    }
}

/// A failure consulting the approval ledger.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// The ledger could not be read or written.
    #[error("approval ledger unavailable: {0}")]
    Unavailable(String),

    /// This approval has already been consumed.
    ///
    /// Control S6 / ADR-0029 TP-6: an approval is single-use. This is the
    /// *replay* answer, and it is deliberately its own variant rather than a
    /// generic failure, because a caller must be able to tell "you may not reuse
    /// this" from "the ledger is down" — the first is a policy decision, the
    /// second is an outage.
    #[error("approval has already been used")]
    AlreadyConsumed,
}

/// Durable record of which approvals have been spent.
///
/// # The operation that matters
///
/// [`consume_at`](Self::consume_at) is the whole point: it must be a *single atomic
/// step*. Two dispatches presenting the same approval must produce one success
/// and one [`LedgerError::AlreadyConsumed`], never two successes and never two
/// refusals. A `SELECT` followed by an `INSERT` is race-prone by construction and
/// is not an acceptable implementation of this trait.
#[allow(clippy::module_name_repetitions)]
pub trait ApprovalLedger {
    /// Atomically marks `digest` spent at `now_ms`, or reports that it already was.
    ///
    /// # Why the time is a parameter, and not the ledger's business
    ///
    /// V-94. The durable implementation previously wrote `0` — the epoch — into
    /// `spent_approvals.consumed_at_ms`, so the ledger could answer *whether* a digest
    /// had been spent and never *when*. A sentinel is not a weaker timestamp, it is a
    /// missing one: zero is indistinguishable from "never recorded", and an incident
    /// review, a retention decision or a replay-window question has no answer at all.
    ///
    /// The clock stays with the caller, for two reasons that are the same reason. The
    /// domain has no clock by design (testability: no hidden time source), and a ledger
    /// that read one would make its own output untestable without a seam. The caller
    /// already has one — the same single reading `authorise` takes and hands down — so
    /// passing it in means the recorded time is the time the decision was made, not a
    /// second reading taken a moment later.
    ///
    /// The timestamp is written by the same single statement that records the spend, so
    /// there is no window in which a digest is marked spent with no time, or timed with
    /// no spend.
    ///
    /// # Errors
    ///
    /// [`LedgerError::AlreadyConsumed`] if the digest was already spent — which
    /// is a *succeed-or-refuse* answer, not a storage failure — or
    /// [`LedgerError::Unavailable`] if the ledger could not be consulted.
    fn consume_at(&mut self, digest: &ApprovalDigest, now_ms: i64) -> Result<(), LedgerError>;

    /// Whether `digest` has been spent.
    ///
    /// # Errors
    ///
    /// [`LedgerError::Unavailable`] if the ledger could not be consulted.
    fn is_consumed(&self, digest: &ApprovalDigest) -> Result<bool, LedgerError>;
}

/// The default [`ApprovalLedger`]: the digests spent in this process.
///
/// # Why the in-memory ledger still exists
///
/// It is what [`PolicyEngine`](https://docs.rs/orxnud-policy) uses when no
/// durable ledger is attached, which is how it behaved before durability existed
/// and how its own unit tests are written. It is **not** sufficient for a system
/// that takes autonomous or delegated actions: a restart returns every consumed
/// approval to the pool. The daemon attaches a durable ledger instead.
///
/// # Why it lives here rather than in `orxnud-policy`
///
/// So that policy has exactly one code path. `evaluate` asks
/// [`ApprovalLedger::is_consumed`] and `authorise` calls
/// [`ApprovalLedger::consume_at`] regardless of which implementation is attached;
/// there is no second set of rules to drift out of step.
#[derive(Debug, Clone, Default)]
pub struct InMemoryApprovals {
    spent: std::collections::BTreeSet<ApprovalDigest>,
}

impl InMemoryApprovals {
    /// A ledger with nothing spent.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ApprovalLedger for InMemoryApprovals {
    fn consume_at(&mut self, digest: &ApprovalDigest, _now_ms: i64) -> Result<(), LedgerError> {
        if self.spent.contains(digest) {
            return Err(LedgerError::AlreadyConsumed);
        }
        self.spent.insert(*digest);
        Ok(())
    }

    fn is_consumed(&self, digest: &ApprovalDigest) -> Result<bool, LedgerError> {
        Ok(self.spent.contains(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> ApprovalDigest {
        ApprovalDigest::from_bytes([n; 32])
    }

    #[test]
    fn the_in_memory_ledger_is_single_use() {
        let mut l = InMemoryApprovals::new();
        assert!(!l.is_consumed(&digest(1)).expect("read"));
        l.consume_at(&digest(1), 0).expect("first consume");
        assert!(l.is_consumed(&digest(1)).expect("read"));
        assert!(matches!(
            l.consume_at(&digest(1), 0),
            Err(LedgerError::AlreadyConsumed)
        ));
    }

    #[test]
    fn distinct_digests_are_independent() {
        let mut l = InMemoryApprovals::new();
        l.consume_at(&digest(1), 0).expect("one");
        l.consume_at(&digest(2), 0).expect("two");
        assert!(l.is_consumed(&digest(1)).expect("read"));
        assert!(l.is_consumed(&digest(2)).expect("read"));
        assert!(!l.is_consumed(&digest(3)).expect("read"));
    }

    #[test]
    fn replay_and_outage_are_distinguishable() {
        // A caller must be able to tell "you may not reuse this" from "the ledger
        // is down". Collapsing them would turn an outage into a policy denial.
        let mut l = InMemoryApprovals::new();
        l.consume_at(&digest(7), 0).expect("consume");
        let replay = l.consume_at(&digest(7), 0).expect_err("replay");
        let text = replay.to_string();
        assert!(text.contains("already been used"), "{text}");
        assert!(!text.contains("unavailable"), "{text}");
    }
}
