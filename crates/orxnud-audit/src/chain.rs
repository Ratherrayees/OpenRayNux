//! The hash chain.
//!
//! `hash_n = H(canonical(record_n) || hash_{n-1})`. Altering or removing any
//! entry invalidates every hash after it, so tampering is *detectable* even
//! though it is not preventable against an attacker who owns the whole file.

use blake3;

use orxnud_domain::security_state::{AuditJournal, JournalEntry, JournalError};

use crate::record::{AuditOutcome, AuditRecord};

/// The hash the chain starts from, before any record.
pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// A failure recording an entry durably.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The entry could not be persisted.
    ///
    /// The in-memory chain is **unchanged**: a record that was not persisted is
    /// not in the journal, and a chain that disagreed with the journal would be
    /// worse than one that is short.
    #[error("audit journal unavailable: {0}")]
    Journal(#[from] JournalError),

    /// The record's sequence number did not follow its predecessor.
    #[error("{0}")]
    Chain(#[from] ChainError),
}

/// A chain failure.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// Records were appended out of sequence.
    #[error("expected seq {expected}, got {got}")]
    OutOfOrder {
        /// The next expected sequence number.
        expected: u64,
        /// What was supplied.
        got: u64,
    },

    /// A record's stored hash did not match its recomputed hash.
    #[error("hash mismatch at seq {seq}: the chain has been altered")]
    HashMismatch {
        /// Where the mismatch was found.
        seq: u64,
    },

    /// A record's `prev` did not match the running hash.
    #[error("broken link at seq {seq}: record does not follow its predecessor")]
    BrokenLink {
        /// Where the break was found.
        seq: u64,
    },
}

/// The append-only hash chain.
///
/// The journal is append-only and unbounded by design; *retention* is a separate
/// concern handled by rotation at the storage layer, because a chain whose
/// entries are silently dropped is no longer verifiable.
///
/// # Durable, and who owns what
///
/// This type owns the canonical form and the chain algorithm, and **nothing else
/// may**. [`record`](Self::record) computes a position, a link, and a hash, then
/// hands the result to an [`AuditJournal`] to persist; [`restore`](Self::restore)
/// reads them back and hands them to [`verify`](Self::verify). The journal stores
/// bytes and never interprets them, so there is exactly one definition of the
/// chain in this workspace.
///
/// [`append`](Self::append) remains the pure in-memory primitive. It is what the
/// chain's own tests use, and it is correct — but it is not sufficient for a
/// system that acts across process lifetimes, because a record it accepted would
/// not survive the process. Production appends through [`record`](Self::record).
#[derive(Debug, Clone, Default)]
pub struct AuditChain {
    entries: Vec<(AuditRecord, [u8; 32])>,
}

impl AuditChain {
    /// An empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// The most recent hash, or [`GENESIS_HASH`] when empty.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.entries.last().map_or(GENESIS_HASH, |(_, h)| *h)
    }

    /// The number of records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the chain is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The records, in order.
    ///
    /// Returns a copy rather than a slice because the chain stores each record
    /// beside its hash; exposing a slice would mean a caller holding a `&mut`
    /// could change a record without recomputing its hash, which would quietly
    /// break verification.
    #[must_use]
    pub fn entries(&self) -> Vec<AuditRecord> {
        self.entries.iter().map(|(r, _)| r.clone()).collect()
    }

    /// The records, in order, without copying, for read-only inspection.
    #[must_use]
    pub fn records(&self) -> impl ExactSizeIterator<Item = &AuditRecord> {
        self.entries.iter().map(|(r, _)| r)
    }

    /// Computes the hash an entry *would* have.
    #[must_use]
    pub fn hash_of(record: &AuditRecord, prev: [u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&prev);
        hasher.update(&record.canonical_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Appends a record, assigning its sequence number.
    ///
    /// # Errors
    ///
    /// [`ChainError::OutOfOrder`] if the caller supplied a `seq` other than the
    /// next one. Callers normally leave `seq` at 0 and let the chain assign it;
    /// a caller that sets it is asserting something, and the assertion is
    /// checked.
    pub fn append(&mut self, mut record: AuditRecord) -> Result<u64, ChainError> {
        let expected = self.entries.len() as u64;
        if record.seq != 0 && record.seq != expected {
            return Err(ChainError::OutOfOrder {
                expected,
                got: record.seq,
            });
        }
        record.seq = expected;
        let hash = Self::hash_of(&record, self.head());
        self.entries.push((record, hash));
        Ok(expected)
    }

    /// Rebuilds a chain from a durable journal, then verifies it.
    ///
    /// # What this refuses to do
    ///
    /// It does not repair. A hash mismatch, a broken link, or an out-of-order
    /// sequence is returned to the caller as an error, because a corrupted
    /// journal that was silently corrected is a corrupted journal nobody knows
    /// about — which is the exact failure tamper-evidence exists to prevent.
    ///
    /// Verification runs the *existing* [`verify`](Self::verify), on the payloads
    /// the chain itself hashed. Decoding a stored payload into a record is the one
    /// thing done here that `verify` cannot do, and a payload that will not decode
    /// is reported as [`JournalError::Undecodable`] rather than skipped.
    ///
    /// # Errors
    ///
    /// [`JournalError::Unavailable`] if storage could not be read,
    /// [`JournalError::Undecodable`] if a payload is not a valid record, or a
    /// [`ChainError`] if the reconstructed chain does not verify.
    pub fn restore(journal: &dyn AuditJournal) -> Result<Self, RecordError> {
        let stored = journal.entries()?;
        let mut entries: Vec<(AuditRecord, [u8; 32])> = Vec::with_capacity(stored.len());
        for e in stored {
            let JournalEntry {
                seq,
                prev_hash,
                hash,
                payload,
            } = e;
            let text = String::from_utf8(payload).map_err(|e| JournalError::Undecodable {
                seq,
                reason: format!("payload is not UTF-8: {e}"),
            })?;
            let record: AuditRecord =
                serde_json::from_str(&text).map_err(|e| JournalError::Undecodable {
                    seq,
                    reason: e.to_string(),
                })?;
            // The stored `prev_hash` is the link the chain computed, and `verify`
            // re-derives it from the previous record. Disagreement between the
            // two is corruption, so it is checked here rather than trusted.
            if prev_hash != Self::link_before(&entries) {
                return Err(RecordError::Chain(ChainError::BrokenLink { seq }));
            }
            entries.push((record, hash));
        }
        let chain = Self { entries };
        chain.verify()?;
        Ok(chain)
    }

    /// The hash the entry at `seq` must carry as its `prev_hash`.
    fn link_before(entries: &[(AuditRecord, [u8; 32])]) -> [u8; 32] {
        entries.last().map_or(GENESIS_HASH, |(_, h)| *h)
    }

    /// Appends a record and persists it.
    ///
    /// The only append a system that acts across process lifetimes should use.
    /// Ordering is: compute, persist, then commit in memory.
    ///
    /// # Why that order
    ///
    /// Persisting first means a journal failure leaves the in-memory chain
    /// untouched, so the two never disagree. The reverse order would leave a
    /// record the chain believed in and the journal did not — and `verify` would
    /// happily pass on it, because it only ever sees memory.
    ///
    /// # Errors
    ///
    /// [`RecordError::Chain`] if the caller supplied a `seq` that is not the next
    /// one, in which case nothing is persisted; or [`RecordError::Journal`] if the
    /// write failed, in which case nothing is persisted and nothing is held in
    /// memory.
    pub fn record(
        &mut self,
        mut record: AuditRecord,
        journal: &dyn AuditJournal,
    ) -> Result<u64, RecordError> {
        let seq = self.entries.len() as u64;
        if record.seq != 0 && record.seq != seq {
            return Err(RecordError::Chain(ChainError::OutOfOrder {
                expected: seq,
                got: record.seq,
            }));
        }
        record.seq = seq;
        let prev = self.head();
        let hash = Self::hash_of(&record, prev);
        let payload = serde_json::to_vec(&record).map_err(|e| {
            RecordError::Journal(JournalError::Unavailable(format!(
                "record could not be serialised: {e}"
            )))
        })?;
        journal.append(&JournalEntry {
            seq,
            prev_hash: prev,
            hash,
            payload,
        })?;
        self.entries.push((record, hash));
        Ok(seq)
    }

    /// Re-verifies the whole chain.
    ///
    /// # Errors
    ///
    /// [`ChainError::HashMismatch`] if any stored hash no longer matches, or
    /// [`ChainError::BrokenLink`] if a record does not follow its predecessor.
    pub fn verify(&self) -> Result<(), ChainError> {
        let mut prev = GENESIS_HASH;
        for (i, (record, stored)) in self.entries.iter().enumerate() {
            if record.seq != i as u64 {
                return Err(ChainError::OutOfOrder {
                    expected: i as u64,
                    got: record.seq,
                });
            }
            let recomputed = Self::hash_of(record, prev);
            if recomputed != *stored {
                return Err(ChainError::HashMismatch { seq: record.seq });
            }
            prev = *stored;
        }
        Ok(())
    }

    /// Returns the sequence numbers of `Authorised` records that have no
    /// matching terminal record.
    ///
    /// # Why the match is by correlation id, not by position
    ///
    /// An append-only hash chain cannot update a record after writing it, so a
    /// terminal outcome is a **separate record** correlated by
    /// [`RequestId`](orxnud_domain::ids::RequestId). Matching by sequence number
    /// would be wrong: the outcome record has its own, later sequence number.
    ///
    /// This is the **"outcome unknown"** detector. A process that died between
    /// the pre-call and post-call audit writes leaves exactly this pattern, and
    /// it is how TP-12's "no effect without a record" becomes *auditable*
    /// rather than merely intended.
    #[must_use]
    pub fn unresolved_authorisations(&self) -> Vec<u64> {
        let mut open: Vec<(u64, String)> = Vec::new();
        for (record, _) in &self.entries {
            let Some(corr) = record.correlation_key() else {
                continue;
            };
            match &record.outcome {
                AuditOutcome::Authorised { .. } => open.push((record.seq, corr)),
                AuditOutcome::Finished { .. } => {
                    if let Some(pos) = open.iter().position(|(_, c)| *c == corr) {
                        open.remove(pos);
                    }
                }
            }
        }
        open.into_iter().map(|(seq, _)| seq).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::OutcomeKind;
    use orxnud_domain::actor::{Actor, AuthChannel};
    use orxnud_domain::ids::{RequestId, TaskId, UserId};
    use orxnud_domain::{DataClass, RiskClass};

    fn rec() -> AuditRecord {
        AuditRecord::authorised(
            Actor::Human {
                user: UserId::new("u-1"),
                via: AuthChannel::LocalInteractive,
            },
            "c",
            None,
            DataClass::Personal,
            RiskClass::Low,
            "v1",
            None,
            None,
            Some(TaskId::new("t-1")),
            None,
            1000,
        )
    }

    #[test]
    fn an_empty_chain_verifies_and_has_the_genesis_head() {
        let c = AuditChain::new();
        assert!(c.is_empty());
        assert_eq!(c.head(), GENESIS_HASH);
        assert!(c.verify().is_ok());
    }

    #[test]
    fn sequence_numbers_are_assigned_by_the_chain() {
        let mut c = AuditChain::new();
        assert_eq!(c.append(rec()).expect("append"), 0);
        assert_eq!(c.append(rec()).expect("append"), 1);
        assert_eq!(c.append(rec()).expect("append"), 2);
        assert_eq!(c.len(), 3);
        assert!(c.verify().is_ok());
    }

    #[test]
    fn each_hash_depends_on_its_predecessor() {
        let mut c = AuditChain::new();
        c.append(rec()).expect("a");
        let h1 = c.head();
        c.append(rec()).expect("b");
        let h2 = c.head();
        assert_ne!(h1, h2, "identical records must chain to different hashes");
    }

    #[test]
    fn tampering_with_an_earlier_record_is_detected() {
        let mut c = AuditChain::new();
        c.append(rec()).expect("a");
        c.append(rec()).expect("b");
        c.append(rec()).expect("c");
        assert!(c.verify().is_ok());

        // Alter the first record's capability. Everything after it is now wrong.
        c.entries[0].0.capability = "tampered".into();
        assert!(matches!(
            c.verify(),
            Err(ChainError::HashMismatch { seq: 0 })
        ));
    }

    #[test]
    fn removing_an_entry_is_detected() {
        let mut c = AuditChain::new();
        c.append(rec()).expect("a");
        c.append(rec()).expect("b");
        c.append(rec()).expect("c");
        c.entries.remove(1);
        assert!(c.verify().is_err(), "a removed entry must break the chain");
    }

    #[test]
    fn out_of_order_append_is_refused() {
        let mut c = AuditChain::new();
        c.append(rec()).expect("a");
        let mut bad = rec();
        bad.seq = 7;
        assert!(matches!(
            c.append(bad),
            Err(ChainError::OutOfOrder {
                expected: 1,
                got: 7
            })
        ));
        assert_eq!(c.len(), 1, "the refused append must not have been stored");
    }

    /// An `Authorised` record and its terminal record share a correlation id.
    fn corr(id: &str) -> AuditRecord {
        let mut r = rec();
        r.request = Some(RequestId::new(id));
        r
    }

    #[test]
    fn unresolved_authorisations_are_found() {
        // The "outcome unknown" detector, which is what makes TP-12 auditable.
        let mut c = AuditChain::new();
        c.append(corr("A")).expect("a"); // seq 0: authorised, never terminated
        c.append(corr("B")).expect("b"); // seq 1: authorised
        c.append(corr("B").finished(OutcomeKind::Completed, 2, None))
            .expect("c"); // closes B
        let unresolved = c.unresolved_authorisations();
        assert!(
            unresolved.contains(&0),
            "seq 0 was never resolved: {unresolved:?}"
        );
        assert!(
            !unresolved.contains(&1),
            "seq 1 was resolved by the correlated record"
        );
    }

    #[test]
    fn a_complete_lifecycle_leaves_nothing_unresolved() {
        let mut c = AuditChain::new();
        c.append(corr("A")).expect("a");
        c.append(corr("A").finished(OutcomeKind::Completed, 2, None))
            .expect("b");
        assert!(c.unresolved_authorisations().is_empty());
    }

    #[test]
    fn the_denial_path_is_auditable() {
        // A policy that logs its allows and not its denies cannot be reviewed.
        let mut c = AuditChain::new();
        c.append(corr("A")).expect("a");
        c.append(corr("A").finished(OutcomeKind::Denied, 2, Some("no grant".into())))
            .expect("b");
        assert!(c.verify().is_ok());
        assert!(c.unresolved_authorisations().is_empty());
    }

    #[test]
    fn an_uncertain_outcome_closes_the_correlation_explicitly() {
        // `Uncertain` is a *terminal* recorded outcome: we said we do not know.
        // It closes the correlation because the uncertainty was recorded, and the
        // human adjudication happens in the task engine, not the journal.
        let mut c = AuditChain::new();
        c.append(corr("A")).expect("a");
        c.append(corr("A").finished(OutcomeKind::Uncertain, 2, None))
            .expect("b");
        assert!(c.unresolved_authorisations().is_empty());
    }

    #[test]
    fn records_without_any_correlation_id_are_ignored_by_the_detector() {
        // Better to ignore them than to match them arbitrarily: guessing a
        // correlation would produce a *wrong* "resolved" verdict, which is worse
        // than no verdict.
        let mut uncorrelatable = rec();
        uncorrelatable.request = None;
        uncorrelatable.task = None;
        assert_eq!(uncorrelatable.correlation_key(), None);

        let mut c = AuditChain::new();
        c.append(uncorrelatable).expect("a");
        assert!(c.unresolved_authorisations().is_empty());
    }

    #[test]
    fn correlation_falls_back_from_request_to_task() {
        let mut r = rec();
        r.request = None;
        assert_eq!(r.correlation_key().as_deref(), Some("task:t-1"));
        r.task = None;
        assert_eq!(r.correlation_key(), None);
    }
}
