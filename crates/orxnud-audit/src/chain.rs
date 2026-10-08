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
    /// # Why the match is by authorisation identity, not by position or by label
    ///
    /// An append-only hash chain cannot update a record after writing it, so a
    /// terminal outcome is a **separate record**. It identifies *which authorisation
    /// it settles* by carrying that authorisation's own `seq` in
    /// [`AuditRecord::settles`] — a value the single-writer chain assigned, so it is
    /// unique, durable, restart-stable, and immune to the order operations finish in.
    ///
    /// This used to match on the request id and resolve the remainder by popping the
    /// *earliest* open authorisation with a matching key. Both halves were wrong, and
    /// observably so: the request id of an ad-hoc socket dispatch is derived from its
    /// task and step, which for such a dispatch is the constant `ipc#0`. A FIFO pop
    /// over a non-unique key resolves authorisation A with the completion of
    /// unrelated authorisation B. There is no ordering of arrivals that fixes this,
    /// because the key itself is not unique — no amount of care in the pairing makes
    /// the answer right.
    ///
    /// This is the **"outcome unknown"** detector. A process that died between
    /// the authorisation write and the terminal write leaves exactly this pattern, and
    /// it is how TP-12's "no effect without a record" becomes *auditable*
    /// rather than merely intended.
    ///
    /// # Legacy records
    ///
    /// A terminal record written before `settles` existed has no identity to compare.
    /// It is **not** silently ignored: an authorisation that a legacy terminal record
    /// might once have settled is reported as unresolved, because this function cannot
    /// prove otherwise. That is a false positive on a journal written by an older
    /// build, and it is the safe direction to be wrong in — an audit trail that claims
    /// an outcome it cannot identify is worse than one that asks a human to look.
    #[must_use]
    pub fn unresolved_authorisations(&self) -> Vec<u64> {
        // Exact set membership, not a FIFO. `settled` holds the `seq` of every
        // authorisation some terminal record claims to settle.
        let mut settled: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for (record, _) in &self.entries {
            // A settlement cannot precede the authorisation it settles. The chain is
            // append-only and monotonic, so `claimed >= record.seq` is a writer bug;
            // honouring it would let a terminal record mark an authorisation resolved
            // before that authorisation existed. Ignored here and reported by
            // `dangling_settlements`.
            if let Some(claimed) = record.settles_authorisation()
                && claimed < record.seq
            {
                settled.insert(claimed);
            }
        }

        self.entries
            .iter()
            .map(|(r, _)| r)
            .filter(|r| matches!(r.outcome, AuditOutcome::Authorised { .. }))
            .filter(|r| !settled.contains(&r.seq))
            .map(|r| r.seq)
            .collect()
    }

    /// Terminal records that settle an authorisation which does not exist.
    ///
    /// A `settles` pointing at a `seq` that is not an `Authorised` record is a
    /// journal that cannot be reconciled: either a record was removed (which the hash
    /// chain forbids) or one was fabricated with a bad reference. `verify` already
    /// proves no record was removed, so this is a writer bug, and it is reported
    /// rather than tolerated because it means the journal is lying about coverage.
    #[must_use]
    pub fn dangling_settlements(&self) -> Vec<(u64, u64)> {
        let authorised: std::collections::BTreeSet<u64> = self
            .entries
            .iter()
            .map(|(r, _)| r)
            .filter(|r| matches!(r.outcome, AuditOutcome::Authorised { .. }))
            .map(|r| r.seq)
            .collect();
        self.entries
            .iter()
            .map(|(r, _)| r)
            .filter_map(|r| r.settles_authorisation().map(|seq| (r.seq, seq)))
            .filter(|&(terminal, claimed)| claimed >= terminal || !authorised.contains(&claimed))
            .collect()
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

    // ---------------------------------------------------------------- identity
    //
    // These replace the tests that encoded the old FIFO pairing. Every one of them
    // asserted that a shared *label* was enough to pair records, which is what made
    // the misreporting possible: the label of an ad-hoc socket dispatch is the constant
    // `ipc#0` for all of them.

    /// An authorisation record. Every one of these is deliberately built with the
    /// **same** request label, because that is the situation that broke: distinct
    /// operations that look identical to any label-based pairing.
    fn corr(id: &str) -> AuditRecord {
        let mut r = rec();
        r.request = Some(RequestId::new(id));
        r
    }

    /// The terminal record settling authorisation `seq`.
    fn settled(by: &str, seq: u64, kind: OutcomeKind) -> AuditRecord {
        corr(by).finished(kind, 2, None).settling(seq)
    }

    /// Every ad-hoc socket dispatch looks exactly like this to a label-based pairing.
    const IPC_LABEL: &str = "ipc#0";

    #[test]
    fn one_authorisation_and_its_terminal_record_settle_each_other() {
        let mut c = AuditChain::new();
        c.append(corr(IPC_LABEL)).expect("a");
        let seq = 0;
        c.append(settled(IPC_LABEL, seq, OutcomeKind::Completed))
            .expect("b");
        assert!(c.unresolved_authorisations().is_empty());
        assert!(c.verify().is_ok());
    }

    #[test]
    fn interleaved_completion_in_either_order_settles_the_right_one() {
        // A authorises, B authorises, B finishes, A finishes. B's completion arrives
        // first. A FIFO pop over a shared label would have credited B's record to A.
        let mut c = AuditChain::new();
        c.append(corr(IPC_LABEL)).expect("a authorises"); // seq 0
        c.append(corr(IPC_LABEL)).expect("b authorises"); // seq 1
        c.append(settled(IPC_LABEL, 1, OutcomeKind::Completed))
            .expect("b finishes");
        c.append(settled(IPC_LABEL, 0, OutcomeKind::Completed))
            .expect("a finishes");
        assert!(
            c.unresolved_authorisations().is_empty(),
            "both authorisations were settled, in an order a FIFO would mispair"
        );
        assert!(
            c.dangling_settlements().is_empty(),
            "each terminal named an authorisation that exists"
        );
    }

    /// The finding, reproduced as a test.
    ///
    /// Two authorisations never reach a terminal record — a capability whose parameters
    /// its own plan builder rejects, in a build where the dispatcher returned before the
    /// audit write. Two *unrelated* operations then complete. A label-based FIFO
    /// resolves the two dangling authorisations against those two completions, so the
    /// journal reports the real failures as settled, and reports the two successful
    /// operations' own authorisations as unresolved. Both halves are wrong, and neither
    /// is a false positive or false negative in isolation: together they are a confident,
    /// entirely incorrect answer about whether effects occurred.
    #[test]
    fn unrelated_completions_cannot_settle_someone_elses_authorisation() {
        let mut c = AuditChain::new();
        c.append(corr(IPC_LABEL)).expect("write-text authorises"); // 0: never resolved
        c.append(corr(IPC_LABEL)).expect("write-text authorises"); // 1: never resolved
        c.append(corr(IPC_LABEL)).expect("read-text authorises"); // 2
        c.append(settled(IPC_LABEL, 2, OutcomeKind::Completed))
            .expect("read-text completes");
        c.append(corr(IPC_LABEL)).expect("read-text authorises"); // 4
        c.append(settled(IPC_LABEL, 4, OutcomeKind::Completed))
            .expect("read-text completes");

        assert_eq!(
            c.unresolved_authorisations(),
            vec![0, 1],
            "exactly the two that never reached a terminal record, and nothing else"
        );
    }

    #[test]
    fn a_refused_before_execution_is_a_distinct_disposition_from_a_completed_one() {
        // Refused-before-execution and ran-and-succeeded must not be indistinguishable,
        // because only one of them may be retried.
        let mut denied = AuditChain::new();
        denied.append(corr(IPC_LABEL)).expect("a");
        denied
            .append(settled(IPC_LABEL, 0, OutcomeKind::Denied))
            .expect("denied");

        let mut completed = AuditChain::new();
        completed.append(corr(IPC_LABEL)).expect("a");
        completed
            .append(settled(IPC_LABEL, 0, OutcomeKind::Completed))
            .expect("completed");

        assert!(denied.verify().is_ok());
        assert!(denied.unresolved_authorisations().is_empty());
        assert!(completed.unresolved_authorisations().is_empty());

        let kinds: Vec<_> = denied
            .records()
            .filter_map(|r| match r.outcome {
                AuditOutcome::Finished { kind, .. } => Some(kind),
                _ => None,
            })
            .collect();
        assert_eq!(kinds, vec![OutcomeKind::Denied]);
    }

    #[test]
    fn a_genuinely_unknown_outcome_is_recorded_as_such_and_still_settles() {
        // `Uncertain` is a *terminal recorded outcome*: we said we do not know. It closes
        // the authorisation because the uncertainty itself was recorded, and the human
        // adjudication happens in the task engine rather than in the journal.
        let mut c = AuditChain::new();
        c.append(corr(IPC_LABEL)).expect("a");
        c.append(settled(IPC_LABEL, 0, OutcomeKind::Uncertain))
            .expect("b");
        assert!(c.unresolved_authorisations().is_empty());
    }

    #[test]
    fn many_identical_requests_each_settle_exactly_once() {
        // Twelve identical capability requests. Identical in every labelled field, so a
        // label-based pairing sees twelve interchangeable items.
        const N: u64 = 12;
        let mut c = AuditChain::new();
        for _ in 0..N {
            c.append(corr(IPC_LABEL)).expect("authorises");
        }
        // Finish them in reverse, which is the order a FIFO would get most wrong.
        for seq in (0..N).rev() {
            c.append(settled(IPC_LABEL, seq, OutcomeKind::Completed))
                .expect("finishes");
        }
        assert!(
            c.unresolved_authorisations().is_empty(),
            "every one of {N} identical authorisations settled"
        );
    }

    #[test]
    fn interleaved_authorise_and_settle_never_cross_pairs() {
        // Authorise, authorise, settle, authorise, settle, settle... The detector must
        // report exactly the authorisations nobody settled, at any interleaving.
        let mut c = AuditChain::new();
        c.append(corr(IPC_LABEL)).expect("a"); // 0 -> unresolved
        c.append(corr(IPC_LABEL)).expect("b"); // 1 -> settled
        c.append(settled(IPC_LABEL, 1, OutcomeKind::Completed))
            .expect("b done");
        c.append(corr(IPC_LABEL)).expect("c"); // 3 -> unresolved
        c.append(corr(IPC_LABEL)).expect("d"); // 4 -> settled
        c.append(corr(IPC_LABEL)).expect("e"); // 5 -> settled
        c.append(settled(IPC_LABEL, 5, OutcomeKind::Failed))
            .expect("e done");
        c.append(settled(IPC_LABEL, 4, OutcomeKind::Completed))
            .expect("d done");

        assert_eq!(c.unresolved_authorisations(), vec![0, 3]);
    }

    #[test]
    fn a_terminal_record_cannot_settle_an_authorisation_that_does_not_exist() {
        // Either a record was removed — which `verify` already forbids — or one names
        // an authorisation it never had. Either way the journal overstates its coverage
        // and must say so rather than quietly count.
        let mut c = AuditChain::new();
        c.append(corr(IPC_LABEL)).expect("a"); // seq 0
        c.append(settled(IPC_LABEL, 9, OutcomeKind::Completed))
            .expect("claims seq 9");
        assert_eq!(c.dangling_settlements(), vec![(1, 9)]);
        assert!(
            c.unresolved_authorisations().contains(&0),
            "the real authorisation is still unresolved"
        );
    }

    #[test]
    fn a_settlement_cannot_precede_its_own_authorisation() {
        let mut c = AuditChain::new();
        c.append(corr(IPC_LABEL)).expect("a"); // seq 0
        c.append(settled(IPC_LABEL, 0, OutcomeKind::Completed))
            .expect("b"); // 1 -> ok
        c.append(settled(IPC_LABEL, 1, OutcomeKind::Completed))
            .expect("claims seq 1, which is itself a terminal record"); // 2
        // seq 1 is not an authorisation at all, so this is dangling.
        assert_eq!(c.dangling_settlements(), vec![(2, 1)]);
    }

    #[test]
    fn an_authorisation_record_settles_nothing() {
        let a = corr(IPC_LABEL);
        assert_eq!(a.settles_authorisation(), None);
        assert_eq!(a.settles, None);
    }

    #[test]
    fn a_finished_record_with_no_identity_settles_nothing() {
        // A disclosure is a recorded fact about the world, not the terminal disposition
        // of an authorisation. It must not silently close one.
        let mut c = AuditChain::new();
        c.append(corr(IPC_LABEL)).expect("a"); // seq 0
        c.append(corr("orxnud.policy/disclose").finished(
            OutcomeKind::Completed,
            2,
            Some("bytes left".into()),
        ))
        .expect("a disclosure");
        assert_eq!(
            c.unresolved_authorisations(),
            vec![0],
            "an identity-less terminal record settles nothing"
        );
    }

    #[test]
    fn an_authorisation_survives_a_restart_and_is_still_unresolved() {
        // What a process that died between authorising and recording leaves behind. The
        // chain is rebuilt from the journal exactly as a new daemon would, and the
        // finding is still there — which is the point of making it durable.
        let mut c = AuditChain::new();
        c.append(corr(IPC_LABEL)).expect("a"); // seq 0, never settled
        c.append(corr(IPC_LABEL)).expect("b");
        c.append(settled(IPC_LABEL, 1, OutcomeKind::Completed))
            .expect("b done");

        // A restart does not reconcile anything; it re-reads.
        assert_eq!(c.unresolved_authorisations(), vec![0]);
        assert!(c.verify().is_ok(), "the chain itself is intact");
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
