//! Preview challenges: the server's record of *what was shown*.
//!
//! # What a challenge is, and is not
//!
//! A challenge is **not** an approval and it grants nothing. It is a short-lived
//! record that a particular preview — of a particular proposal, for a particular
//! recipient, to a particular principal — was taken, so that an approval which
//! follows can be checked against exactly that.
//!
//! It exists because an approval digest binds the *operation* and proves nothing
//! about the *review*: a digest that recomputes correctly says the read is the
//! approved read, not that anyone saw what the read would disclose. The challenge is
//! the half of the boundary the digest cannot express.
//!
//! # Lifetime
//!
//! Everything here is in memory. A daemon restart discards every outstanding
//! challenge, which is the fail-safe direction: a preview that was taken before a
//! restart is not a preview the current process knows about.
//!
//! # Clocks
//!
//! Every operation takes the time explicitly. Production callers must supply a
//! **monotonic, runtime-relative** millisecond value — not a wall clock, which can
//! move backwards and would extend a challenge's life. Tests supply the same kind of
//! value directly, so no test ever sleeps.

use orxnud_domain::ids::TaskId;

/// How long a challenge stays usable, in milliseconds.
pub(crate) const CHALLENGE_TTL_MS: i64 = 120_000;

/// How many live challenges may exist at once.
pub(crate) const MAX_LIVE_CHALLENGES: usize = 64;

/// The disclosure policy a challenge is issued under.
///
/// A challenge is a promise about the *rules* the operator was shown, so the rules
/// are part of what is bound. This identifier stands for all of them: the 64 KiB
/// read ceiling, the 32 KiB combined per-request observation ceiling, the
/// eight-entry limit, the rule that an observation is released whole rather than
/// truncated to fit, and the rule that eligibility lasts only for the immediately
/// following logical step.
///
/// Changing any of those rules changes this identifier, and every outstanding
/// challenge then fails to match — which is the point: a preview taken under the old
/// rules was not a preview of what the operator would now be shown.
pub(crate) const DISCLOSURE_POLICY_VERSION: &str = "f26b-disclosure-v1";

/// Everything a challenge is bound to.
///
/// # What is deliberately absent
///
/// No raw endpoint URL, no credential, no file content, and no serialised request
/// body. The endpoint is represented by a **fingerprint** of it, which is enough to
/// detect a change and useless for reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChallengeBinding {
    /// The proposal the preview was of.
    pub proposal_id: String,
    /// The task that asked.
    pub task_id: TaskId,
    /// The attempt that asked.
    pub attempt_no: u32,
    /// The logical step the proposal belongs to.
    pub step_no: u32,
    /// The capability that was previewed.
    pub capability: String,
    /// The target the capability names.
    pub target: Option<String>,
    /// The canonical parameters that were shown.
    pub canonical_params: String,
    /// The persisted identity of the proposer.
    pub proposer_identity: String,
    /// The provider-destination fingerprint stored with the proposal.
    pub original_fingerprint: String,
    /// The provider-destination fingerprint verified when the preview was taken.
    pub current_fingerprint: String,
    /// The stable identity of the principal the preview was for.
    pub actor_identity: String,
    /// The disclosure policy the preview was taken under.
    pub policy_version: String,
}

/// Why a challenge could not be issued or redeemed.
///
/// # What these messages may say
///
/// Nothing that was stored. A challenge is a record of a proposal, a path and a
/// recipient, and an error that echoed any of it would turn a failed redemption into
/// an oracle. The variants distinguish *kinds* of failure and nothing more.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChallengeError {
    /// There is no such challenge: it was never issued, it has expired, or it has
    /// already been redeemed.
    Unknown,
    /// A challenge exists, but it was issued for something else.
    Mismatch,
    /// The store is full. No live challenge was evicted to make room.
    AtCapacity,
}

impl std::fmt::Display for ChallengeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unknown => "the preview challenge is unknown, expired, or already used",
            Self::Mismatch => "the preview challenge does not match what is being approved",
            Self::AtCapacity => "too many preview challenges are pending; try again shortly",
        })
    }
}

impl std::error::Error for ChallengeError {}

/// One outstanding challenge.
#[derive(Debug, Clone)]
pub(crate) struct Challenge {
    /// What the challenge authorises.
    pub binding: ChallengeBinding,
    /// When it stops being usable.
    pub expires_at_ms: i64,
}

/// The outstanding challenges.
///
/// Small, in memory, and **fail-closed**. When it is full, issuing is refused rather
/// than a live challenge being evicted to make room: eviction would let one
/// principal's confirmation be silently replaced by another's, and the replacement
/// would be for something the first principal never saw.
#[derive(Debug, Default)]
pub(crate) struct ChallengeStore {
    pending: std::collections::BTreeMap<String, Challenge>,
}

impl ChallengeStore {
    /// Allocates a challenge for `binding` at `now_ms`.
    ///
    /// # Why not `issue`
    ///
    /// `issue` is the policy crate's word: `AuthorisationProof::issue` is the only
    /// constructor of the proof behind an approval, and gate G2d reserves the name
    /// so that nothing outside `orxnud-policy` can look like it. This method grants
    /// nothing -- a challenge is a *record* that a preview was taken, checked and
    /// consumed before an approval is created -- so it does not belong under a name
    /// that means "authority is minted here".
    ///
    /// The identifier is a UUID v4: 122 bits from the operating system's
    /// cryptographically secure generator. It is **opaque** — it encodes nothing about
    /// the proposal, the path or the recipient — so it can be handed to a client and
    /// logged without disclosing anything.
    ///
    /// # Errors
    ///
    /// [`ChallengeError::AtCapacity`] when the store already holds
    /// [`MAX_LIVE_CHALLENGES`] live challenges. Nothing is evicted.
    pub(crate) fn allocate(
        &mut self,
        binding: ChallengeBinding,
        now_ms: i64,
    ) -> Result<String, ChallengeError> {
        self.expire(now_ms);
        if self.pending.len() >= MAX_LIVE_CHALLENGES {
            return Err(ChallengeError::AtCapacity);
        }
        let id = uuid::Uuid::new_v4().to_string();
        self.pending.insert(
            id.clone(),
            Challenge {
                binding,
                expires_at_ms: now_ms.saturating_add(CHALLENGE_TTL_MS),
            },
        );
        Ok(id)
    }

    /// Redeems the challenge `id` against the `expected` binding at `now_ms`.
    ///
    /// # Redemption semantics
    ///
    /// The challenge is **consumed first**, and the binding is compared afterwards.
    /// That ordering is the point: an expired challenge, or one issued for something
    /// else, must not be redeemable a second time with corrected parameters or by
    /// another principal. A failed attempt costs the caller a fresh preview.
    ///
    /// # Errors
    ///
    /// [`ChallengeError::Unknown`] when there is no such live challenge, and
    /// [`ChallengeError::Mismatch`] when there is one but it was issued for something
    /// else. Neither error carries anything that was stored.
    pub(crate) fn redeem(
        &mut self,
        id: &str,
        expected: &ChallengeBinding,
        now_ms: i64,
    ) -> Result<(), ChallengeError> {
        self.expire(now_ms);
        let Some(challenge) = self.pending.remove(id) else {
            return Err(ChallengeError::Unknown);
        };
        if challenge.expires_at_ms <= now_ms {
            return Err(ChallengeError::Unknown);
        }
        if &challenge.binding != expected {
            return Err(ChallengeError::Mismatch);
        }
        Ok(())
    }

    /// Removes the challenges that have expired at `now_ms`.
    ///
    /// A challenge issued at `t` expires at `t + CHALLENGE_TTL_MS`, and is expired at
    /// exactly that instant. A live challenge is never removed.
    pub(crate) fn expire(&mut self, now_ms: i64) {
        self.pending.retain(|_, c| c.expires_at_ms > now_ms);
    }

    /// How many challenges are live. Test-only.
    #[cfg(test)]
    pub(crate) fn live(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic binding. Every field is a literal so that a mismatch can be
    /// attributed to the field that changed.
    fn binding(actor: &str) -> ChallengeBinding {
        ChallengeBinding {
            proposal_id: "p-1".to_owned(),
            task_id: TaskId::new("t1"),
            attempt_no: 1,
            step_no: 2,
            capability: "filesystem/read-text".to_owned(),
            target: Some("a.txt".to_owned()),
            canonical_params: r#"{"path":"a.txt"}"#.to_owned(),
            proposer_identity: "ai:some-model".to_owned(),
            original_fingerprint: "aa".repeat(32),
            current_fingerprint: "aa".repeat(32),
            actor_identity: actor.to_owned(),
            policy_version: DISCLOSURE_POLICY_VERSION.to_owned(),
        }
    }

    const NOW: i64 = 1_000_000;

    #[test]
    fn a_challenge_is_issued_and_redeemed() {
        let mut store = ChallengeStore::default();
        let expected = binding("human:local");
        let id = store.allocate(expected.clone(), NOW).expect("allocate");
        assert!(!id.is_empty());
        store.redeem(&id, &expected, NOW + 1).expect("redeem");
    }

    #[test]
    fn the_identifier_is_opaque_and_distinct() {
        let mut store = ChallengeStore::default();
        let expected = binding("human:local");
        let first = store.allocate(expected.clone(), NOW).expect("allocate");
        let second = store.allocate(expected, NOW).expect("allocate");
        assert_ne!(first, second, "two challenges must not share an identifier");
        // A UUID v4: 36 characters, and nothing about the proposal in it.
        assert_eq!(first.len(), 36);
        for secret in [
            "p-1",
            "a.txt",
            "filesystem",
            "human:local",
            &"aa".repeat(32),
        ] {
            assert!(
                !first.contains(secret),
                "the identifier must be opaque, but it contains {secret:?}: {first}"
            );
        }
    }

    #[test]
    fn redemption_consumes_the_challenge() {
        let mut store = ChallengeStore::default();
        let expected = binding("human:local");
        let id = store.allocate(expected.clone(), NOW).expect("allocate");
        assert_eq!(store.live(), 1);
        store.redeem(&id, &expected, NOW).expect("redeem");
        assert_eq!(store.live(), 0, "a redeemed challenge is consumed");
    }

    #[test]
    fn a_redeemed_challenge_cannot_be_replayed() {
        let mut store = ChallengeStore::default();
        let expected = binding("human:local");
        let id = store.allocate(expected.clone(), NOW).expect("allocate");
        store.redeem(&id, &expected, NOW).expect("redeem");
        assert_eq!(
            store.redeem(&id, &expected, NOW),
            Err(ChallengeError::Unknown),
            "a replay must fail"
        );
    }

    #[test]
    fn a_binding_mismatch_fails_and_consumes_the_challenge() {
        let mut store = ChallengeStore::default();
        let issued = binding("human:local");
        let id = store.allocate(issued.clone(), NOW).expect("allocate");

        let mut other = issued.clone();
        other.canonical_params = r#"{"path":"b.txt"}"#.to_owned();
        assert_eq!(
            store.redeem(&id, &other, NOW),
            Err(ChallengeError::Mismatch),
            "a changed parameter must not redeem"
        );
        assert_eq!(
            store.live(),
            0,
            "a failed redemption consumes the challenge"
        );
        // And it cannot be retried with the right binding.
        assert_eq!(
            store.redeem(&id, &issued, NOW),
            Err(ChallengeError::Unknown)
        );
    }

    #[test]
    fn another_actor_cannot_redeem_the_challenge() {
        let mut store = ChallengeStore::default();
        let issued = binding("human:local");
        let id = store.allocate(issued.clone(), NOW).expect("allocate");
        let other_actor = binding("human:someone-else");
        assert_eq!(
            store.redeem(&id, &other_actor, NOW),
            Err(ChallengeError::Mismatch),
            "a challenge is bound to one principal"
        );
        assert_eq!(store.live(), 0, "the failed attempt consumed it");
    }

    #[test]
    fn expiry_is_enforced_at_the_exact_boundary() {
        let mut store = ChallengeStore::default();
        let expected = binding("human:local");
        let id = store.allocate(expected.clone(), NOW).expect("allocate");
        // One millisecond before the boundary it is still live.
        assert!(
            store
                .redeem(&id, &expected, NOW + CHALLENGE_TTL_MS - 1)
                .is_ok(),
            "a challenge must be live right up to its expiry"
        );

        let mut store = ChallengeStore::default();
        let id = store.allocate(expected.clone(), NOW).expect("allocate");
        // At the boundary it has expired.
        assert_eq!(
            store.redeem(&id, &expected, NOW + CHALLENGE_TTL_MS),
            Err(ChallengeError::Unknown),
            "a challenge must be expired at exactly its TTL"
        );
    }

    #[test]
    fn expired_entries_are_cleaned_before_a_new_issuance() {
        let mut store = ChallengeStore::default();
        let expected = binding("human:local");
        let id = store.allocate(expected.clone(), NOW).expect("allocate");
        assert_eq!(store.live(), 1);
        let _ = store
            .allocate(expected.clone(), NOW + CHALLENGE_TTL_MS)
            .expect("allocate");
        assert_eq!(
            store.live(),
            1,
            "the expired challenge must be gone, and only the new one left"
        );
        assert_eq!(
            store.redeem(&id, &expected, NOW + 1),
            Err(ChallengeError::Unknown)
        );
    }

    #[test]
    fn capacity_is_enforced_at_sixty_four() {
        let mut store = ChallengeStore::default();
        let expected = binding("human:local");
        for i in 0..MAX_LIVE_CHALLENGES {
            let mut b = expected.clone();
            b.proposal_id = format!("p-{i}");
            store.allocate(b, NOW).expect("allocate");
        }
        assert_eq!(store.live(), MAX_LIVE_CHALLENGES);
        assert_eq!(
            store.allocate(expected, NOW),
            Err(ChallengeError::AtCapacity),
            "the sixty-fifth challenge must be refused"
        );
    }

    #[test]
    fn capacity_exhaustion_never_evicts_a_live_challenge() {
        let mut store = ChallengeStore::default();
        let expected = binding("human:local");
        let mut ids = Vec::new();
        for i in 0..MAX_LIVE_CHALLENGES {
            let mut b = expected.clone();
            b.proposal_id = format!("p-{i}");
            ids.push(store.allocate(b, NOW).expect("allocate"));
        }
        assert!(store.allocate(expected.clone(), NOW).is_err());
        assert_eq!(store.live(), MAX_LIVE_CHALLENGES, "nothing was evicted");
        // A live challenge is still redeemable: none was sacrificed to make room.
        // `ids[1]` is the one bound to the unmodified `expected` binding.
        store
            .redeem(&ids[1], &expected, NOW)
            .expect("a live challenge must survive a refused issuance");
        assert_eq!(store.live(), MAX_LIVE_CHALLENGES - 1);
    }

    #[test]
    fn an_invalid_redemption_leaves_unrelated_challenges_alone() {
        let mut store = ChallengeStore::default();
        let expected = binding("human:local");
        let keep = store.allocate(expected.clone(), NOW).expect("allocate");
        let spent = store.allocate(expected.clone(), NOW).expect("allocate");

        // A redemption of an identifier that was never issued.
        assert_eq!(
            store.redeem("not-a-challenge", &expected, NOW),
            Err(ChallengeError::Unknown)
        );
        // A redemption with the wrong binding.
        let mut other = expected.clone();
        other.step_no = 99;
        assert_eq!(
            store.redeem(&spent, &other, NOW),
            Err(ChallengeError::Mismatch)
        );

        assert_eq!(store.live(), 1, "only the spent challenge was consumed");
        store
            .redeem(&keep, &expected, NOW)
            .expect("the unrelated challenge must still be redeemable");
    }

    #[test]
    fn errors_reveal_nothing_that_was_stored() {
        let mut store = ChallengeStore::default();
        let expected = binding("human:local");
        let id = store.allocate(expected.clone(), NOW).expect("allocate");
        let mut other = expected.clone();
        other.canonical_params = r#"{"path":"secret.txt"}"#.to_owned();
        let mismatch = store.redeem(&id, &other, NOW).expect_err("must fail");
        let unknown = store
            .redeem("00000000-0000-4000-8000-000000000000", &expected, NOW)
            .expect_err("must fail");
        let at_capacity = {
            let mut full = ChallengeStore::default();
            for i in 0..MAX_LIVE_CHALLENGES {
                let mut b = expected.clone();
                b.proposal_id = format!("p-{i}");
                full.allocate(b, NOW).expect("allocate");
            }
            full.allocate(expected.clone(), NOW).expect_err("must fail")
        };
        for err in [mismatch, unknown, at_capacity] {
            let text = err.to_string();
            for secret in [
                "p-1",
                "a.txt",
                "secret.txt",
                "filesystem/read-text",
                "human:local",
                "ai:some-model",
                &"aa".repeat(32),
            ] {
                assert!(
                    !text.contains(secret),
                    "an error must not reveal {secret:?}: {text}"
                );
            }
        }
    }
}

/// A monotonic, runtime-relative clock.
///
/// Wall-clock time can move backwards — an NTP step, a leap second, a clock
/// adjustment — and a challenge whose expiry is measured against it could live longer
/// than its TTL. The store's own API takes the time explicitly so that tests never
/// sleep; this is the production source of that time.
#[derive(Debug)]
pub(crate) struct MonotonicClock {
    origin: std::time::Instant,
}

impl MonotonicClock {
    /// Starts a clock at "now".
    pub(crate) fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }

    /// Milliseconds since the clock started. Never decreases.
    pub(crate) fn now_ms(&self) -> i64 {
        i64::try_from(self.origin.elapsed().as_millis()).unwrap_or(i64::MAX)
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

/// The daemon's challenge state: the store, and the clock it is timed against.
///
/// The two live together so that every challenge in the process shares one time
/// base. The store itself takes the time as a parameter, which is what keeps its unit
/// tests deterministic.
#[derive(Debug, Default)]
pub(crate) struct ChallengeState {
    store: ChallengeStore,
    clock: MonotonicClock,
}

impl ChallengeState {
    /// Issues a challenge, timed against this state's clock.
    pub(crate) fn allocate(&mut self, binding: ChallengeBinding) -> Result<String, ChallengeError> {
        let now = self.clock.now_ms();
        self.store.allocate(binding, now)
    }

    /// Redeems a challenge, timed against this state's clock.
    pub(crate) fn redeem(
        &mut self,
        id: &str,
        expected: &ChallengeBinding,
    ) -> Result<(), ChallengeError> {
        let now = self.clock.now_ms();
        self.store.redeem(id, expected, now)
    }
}

/// A stable identity for an actor, used to bind a challenge to one principal.
///
/// The human's user id rather than a label: a label can be shared between principals,
/// and a challenge must bind to exactly one of them.
pub(crate) fn actor_identity(actor: &orxnud_domain::Actor) -> String {
    match actor {
        orxnud_domain::Actor::Human { user, .. } => format!("human:{}", user.as_str()),
        orxnud_domain::Actor::Ai { provenance, .. } => format!("ai:{}", provenance.model),
        // Every other principal kind is named by its variant, so an unrecognised
        // principal is still a distinct identity rather than a shared one.
        other => format!("other:{}", other.label()),
    }
}
