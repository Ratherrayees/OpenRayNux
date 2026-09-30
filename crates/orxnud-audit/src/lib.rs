//! The append-only, hash-chained audit journal.
//!
//! # Why a journal at all
//!
//! Control S33 requires that for every action the record answers five questions:
//! who requested it, on whose authority, under which policy, with which
//! credential *reference*, and as part of which task. Reconstructing that
//! afterwards from logs is not possible; the journal is the primary record and
//! logs are the human-readable view of it.
//!
//! # Tamper-*evident*, not tamper-proof
//!
//! Each entry hashes the previous entry's hash, so altering or removing an entry
//! invalidates every hash after it. A local attacker with write access to all
//! our files can rewrite the whole chain — nothing running as the same user can
//! prevent that. What the chain buys is that *partial* tampering, and accidental
//! corruption, are **detectable**. Stated plainly rather than oversold
//! (docs-11 §4 lists this as accepted technical debt).
//!
//! # Order of writes
//!
//! Policy writes the authorisation record **before** the capability call and the
//! outcome **after**. There is no unlogged path. An entry whose outcome is
//! absent means the process died between the two, which is exactly the
//! "outcome unknown" case ADR-0029's TP-12 requires us to represent.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod chain;
pub mod record;

pub use chain::{AuditChain, ChainError, GENESIS_HASH};
pub use record::{AuditOutcome, AuditRecord, OutcomeKind};

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_domain::{Actor, AuthChannel, DataClass, RiskClass, UserId};

    /// A canonical, deterministic instant for tests.
    ///
    /// The journal takes time as a parameter, so tests never read the wall clock;
    /// this is the value they pass.
    #[must_use]
    pub(crate) const fn fixed_now() -> i64 {
        1_700_000_000_000
    }

    #[test]
    fn the_test_clock_is_the_value_the_chain_records() {
        // Keeps the helper honest: if the journal ever starts stamping its own
        // time, this is where it shows up.
        let record = AuditRecord::authorised(
            Actor::Human {
                user: UserId::new("u"),
                via: AuthChannel::LocalInteractive,
            },
            "capability.test",
            None,
            DataClass::Public,
            RiskClass::Low,
            "policy/1",
            None,
            None,
            None,
            None,
            fixed_now(),
        );
        assert_eq!(
            record.outcome,
            AuditOutcome::Authorised { at_ms: fixed_now() }
        );
    }
}
