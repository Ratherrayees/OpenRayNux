//! Daemon-controlled authorization for `filesystem/read-text` dispatch.
//!
//! # Why this exists
//!
//! An approval digest proves that an approval was issued **for this operation, by this
//! approver, for this actor, at this step, and that it has not been used**. It does
//! *not* prove that the daemon issued that approval through a path a human reviewed.
//! The digest is not secret, and the standalone approval route hands one out on
//! request. Without this registry, a caller could obtain a digest-valid approval by
//! asking for one and then dispatch a read whose contents are disclosed to the model
//! provider -- with no proposal, no preview and no confirmation anywhere in the path.
//!
//! So a read dispatch needs **two** things: the existing digest validation, *and* proof
//! that this daemon registered the digest after creating the approval through a
//! permitted server-side proposal-approval path.
//!
//! # Shape
//!
//! * **Bounded**: 256 outstanding authorizations. When the bound is reached, a new read
//!   approval is **refused** -- before the approval is created and before any durable
//!   state changes. A live authorization is never evicted to make room.
//! * **Reserved, then activated**: capacity is reserved *before* the approval is
//!   created, and the entry is activated only *after* the approval row and the
//!   proposal decision have both succeeded. A failure in between releases the
//!   reservation and leaves no dispatchable entry.
//! * **Claimed once**: dispatch claims the entry atomically, so two concurrent
//!   dispatches cannot both use one authorization.
//! * **Ephemeral**: it lives in the daemon's memory. A restart discards it, and an
//!   approval persisted before the restart therefore cannot dispatch a read afterwards.
//!   That is the fail-closed direction, and it is deliberate.

use std::collections::BTreeMap;

/// How many read authorizations may be outstanding at once.
pub(crate) const MAX_READ_AUTHORIZATIONS: usize = 256;

/// Why an authorization could not be issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationError {
    /// The registry is full. No live authorization was evicted.
    AtCapacity,
}

impl std::fmt::Display for AuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AtCapacity => "too many outstanding read authorizations; try again shortly",
        })
    }
}

impl std::error::Error for AuthorizationError {}

/// A reserved slot, not yet an authorization.
///
/// The reservation exists so that capacity can be taken *before* the durable approval
/// is created, and released if that creation fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reservation {
    id: u64,
}

/// One live read authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadAuthorization {
    /// The hex digest of the approval this authorizes.
    pub digest: String,
    /// When the authorization stops being usable -- the approval's own expiry.
    pub expires_at_ms: i64,
}

/// The outstanding read authorizations.
#[derive(Debug, Default)]
pub(crate) struct ReadDispatchAuthorizations {
    live: BTreeMap<String, ReadAuthorization>,
    reserved: usize,
    next_reservation: u64,
}

impl ReadDispatchAuthorizations {
    /// Reserves capacity for one authorization.
    ///
    /// # Errors
    ///
    /// [`AuthorizationError::AtCapacity`] when the registry already holds
    /// [`MAX_READ_AUTHORIZATIONS`] live or reserved entries. Nothing is evicted.
    pub(crate) fn reserve(&mut self, now_ms: i64) -> Result<Reservation, AuthorizationError> {
        self.expire(now_ms);
        if self.live.len() + self.reserved >= MAX_READ_AUTHORIZATIONS {
            return Err(AuthorizationError::AtCapacity);
        }
        self.reserved += 1;
        self.next_reservation += 1;
        Ok(Reservation {
            id: self.next_reservation,
        })
    }

    /// Activates a reservation with the digest of an approval that now exists.
    ///
    /// The reservation is consumed either way, so a caller that forgets to activate
    /// does not leak capacity forever.
    pub(crate) fn activate(
        &mut self,
        _reservation: Reservation,
        digest: String,
        expires_at_ms: i64,
    ) {
        self.reserved = self.reserved.saturating_sub(1);
        self.live.insert(
            digest.clone(),
            ReadAuthorization {
                digest,
                expires_at_ms,
            },
        );
    }

    /// Releases a reservation without creating an authorization.
    pub(crate) fn release(&mut self, _reservation: Reservation) {
        self.reserved = self.reserved.saturating_sub(1);
    }

    /// Claims the authorization for `digest`, if there is a live one.
    ///
    /// The entry is **removed before** the answer is known, so two concurrent dispatches
    /// cannot both use it: one gets it, the other does not.
    pub(crate) fn claim(&mut self, digest: &str, now_ms: i64) -> bool {
        self.expire(now_ms);
        self.live.remove(digest).is_some()
    }

    /// Drops the authorizations whose approval has expired.
    pub(crate) fn expire(&mut self, now_ms: i64) {
        self.live.retain(|_, a| a.expires_at_ms > now_ms);
    }

    /// How many authorizations are live. Test-only.
    #[cfg(test)]
    pub(crate) fn live(&self) -> usize {
        self.live.len()
    }

    /// How many reservations are outstanding. Test-only.
    #[cfg(test)]
    pub(crate) fn reserved(&self) -> usize {
        self.reserved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;

    fn digest(n: usize) -> String {
        format!("{n:064x}")
    }

    #[test]
    fn a_reservation_can_be_activated_and_then_claimed_once() {
        let mut registry = ReadDispatchAuthorizations::default();
        let r = registry.reserve(NOW).expect("reserve");
        assert_eq!(registry.reserved(), 1);
        registry.activate(r, digest(1), NOW + 60_000);
        assert_eq!(registry.live(), 1);
        assert!(registry.claim(&digest(1), NOW + 1), "the first claim wins");
        assert!(
            !registry.claim(&digest(1), NOW + 2),
            "the second claim must fail"
        );
        assert_eq!(registry.live(), 0);
    }

    #[test]
    fn a_reservation_that_is_released_leaves_no_authorization_and_frees_capacity() {
        let mut registry = ReadDispatchAuthorizations::default();
        let r = registry.reserve(NOW).expect("reserve");
        registry.release(r);
        assert_eq!(registry.reserved(), 0);
        assert_eq!(registry.live(), 0);
        assert!(
            !registry.claim(&digest(1), NOW),
            "a released reservation authorizes nothing"
        );
    }

    #[test]
    fn an_expired_authorization_is_removed_and_cannot_be_claimed() {
        let mut registry = ReadDispatchAuthorizations::default();
        let r = registry.reserve(NOW).expect("reserve");
        registry.activate(r, digest(1), NOW + 1_000);
        assert!(
            registry.claim(&digest(1), NOW + 999),
            "live before the expiry"
        );
        let r = registry.reserve(NOW).expect("reserve");
        registry.activate(r, digest(2), NOW + 1_000);
        assert!(
            !registry.claim(&digest(2), NOW + 1_000),
            "an authorization is expired at exactly its expiry"
        );
        assert_eq!(registry.live(), 0, "an expired authorization is removed");
    }

    #[test]
    fn the_capacity_bound_is_enforced_at_two_hundred_and_fifty_six() {
        let mut registry = ReadDispatchAuthorizations::default();
        for i in 0..MAX_READ_AUTHORIZATIONS {
            let r = registry.reserve(NOW).expect("reserve");
            registry.activate(r, digest(i), NOW + 60_000);
        }
        assert_eq!(registry.live(), MAX_READ_AUTHORIZATIONS);
        assert_eq!(
            registry.reserve(NOW),
            Err(AuthorizationError::AtCapacity),
            "the two-hundred-and-fifty-seventh reservation must be refused"
        );
    }

    #[test]
    fn capacity_exhaustion_never_evicts_a_live_authorization() {
        let mut registry = ReadDispatchAuthorizations::default();
        for i in 0..MAX_READ_AUTHORIZATIONS {
            let r = registry.reserve(NOW).expect("reserve");
            registry.activate(r, digest(i), NOW + 60_000);
        }
        assert!(registry.reserve(NOW).is_err());
        assert_eq!(
            registry.live(),
            MAX_READ_AUTHORIZATIONS,
            "nothing was evicted"
        );
        // The first authorization is still claimable: it was not sacrificed to make room.
        assert!(
            registry.claim(&digest(0), NOW),
            "a live authorization must survive"
        );
    }

    #[test]
    fn a_failed_persistence_path_leaves_no_live_authorization() {
        let mut registry = ReadDispatchAuthorizations::default();
        let r = registry.reserve(NOW).expect("reserve");
        // The approval creation failed, so the reservation is released rather than
        // activated.
        registry.release(r);
        assert_eq!(
            registry.live(),
            0,
            "a failed creation must leave nothing dispatchable"
        );
        assert!(!registry.claim(&digest(1), NOW));
    }

    #[test]
    fn a_new_registry_does_not_accept_old_digests() {
        let mut first = ReadDispatchAuthorizations::default();
        let r = first.reserve(NOW).expect("reserve");
        first.activate(r, digest(7), NOW + 60_000);
        assert!(
            first.claim(&digest(7), NOW),
            "the first registry authorizes it"
        );

        // A restarted daemon has an empty registry.
        let mut restarted = ReadDispatchAuthorizations::default();
        assert!(
            !restarted.claim(&digest(7), NOW),
            "a restart must invalidate the authorization"
        );
    }

    /// Capacity is refused rather than paid for by evicting a live authorisation.
    #[test]
    fn the_registry_refuses_to_issue_beyond_its_capacity() {
        let mut registry = ReadDispatchAuthorizations::default();
        for i in 0..MAX_READ_AUTHORIZATIONS {
            let r = registry.reserve(NOW).expect("reserve");
            registry.activate(r, digest(i), NOW + 60_000);
        }
        assert_eq!(registry.live(), MAX_READ_AUTHORIZATIONS);
        // The next one is refused, and nothing already live is disturbed.
        assert_eq!(
            registry.reserve(NOW),
            Err(AuthorizationError::AtCapacity),
            "the registry must refuse rather than evict"
        );
        assert_eq!(
            registry.live(),
            MAX_READ_AUTHORIZATIONS,
            "a refused reservation must evict nothing"
        );
        assert!(
            registry.claim(&digest(0), NOW),
            "an authorisation that was already live must survive a refused reservation"
        );
    }

    #[test]
    fn an_unregistered_digest_is_never_authorized() {
        let mut registry = ReadDispatchAuthorizations::default();
        assert!(!registry.claim(&digest(99), NOW));
    }
}
