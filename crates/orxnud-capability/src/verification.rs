//! Verification: distinguishing "the adapter returned" from "the effect happened".
//!
//! # The distinction this contract exists to force
//!
//! ```text
//! adapter returned Ok   ≠   the real-world operation succeeded
//! ```
//!
//! Those are different claims and only one of them is usually true. A browser
//! driver returns `Ok` when it clicked; the click may have hit a re-rendered page. A
//! message API returns `Ok` when it queued; the message may never have been
//! delivered. A shell command returns `Ok` when it exited zero; it may have exited
//! zero without doing what was meant.
//!
//! Collapsing them into one boolean is how "the agent said it worked" becomes "the
//! agent worked". TP-12 exists for the same reason: an outcome whose truth is unknown
//! must be recorded as unknown, never optimistically.
//!
//! # The six states
//!
//! [`VerificationOutcome`] deliberately has more states than a success flag. Three
//! dimensions are being reported at once, and a single enum variant per result loses
//! the distinction between them:
//!
//! | | execution | verification |
//! |---|---|---|
//! | [`ExecutionOutcome::Succeeded`] | the adapter returned | — |
//! | [`VerificationOutcome::Verified`] | | confirmed independently |
//! | [`VerificationOutcome::Refuted`] | | **proven not to have happened** |
//! | [`VerificationOutcome::Undetermined`] | | genuinely unknowable |
//!
//! [`ExecutionOutcome::Failed`] and [`ExecutionOutcome::Unknown`] are the cases where
//! nothing ran or nothing reported. `Unknown` is the one that must never be recorded
//! as success, and it is a first-class state rather than an error string.

use std::fmt;

/// What the adapter reported.
///
/// Distinct from [`VerificationOutcome`] deliberately: "the code returned" is a
/// statement about the adapter, and "the thing happened" is a statement about the
/// world. An adapter that is lying reports `Succeeded` here, which is exactly the
/// case verification exists to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// The adapter returned successfully.
    ///
    /// Says nothing about the real world. See the module docs.
    Succeeded {
        /// What the adapter claims it produced. Untrusted: an adapter can lie.
        output: Option<String>,
    },
    /// The adapter reported a failure it knew about.
    Failed {
        /// The adapter's own message. Redacted before it reaches an audit record.
        detail: String,
    },
    /// The adapter did not report. Timed out, was cancelled, or the subprocess died.
    ///
    /// Not the same as `Failed`, and the difference matters: `Failed` means nothing
    /// happened, `Unknown` means *something may have happened and nobody knows*.
    Unknown {
        /// Why the report is missing.
        detail: String,
    },
}

/// What verification concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationOutcome {
    /// Independently confirmed that the effect occurred.
    Verified {
        /// What confirmed it.
        evidence: String,
    },
    /// Independently confirmed that the effect did **not** occur.
    ///
    /// A first-class state, not an error. "Proven absent" and "unknown" are
    /// different, and only one of them means it is safe to retry.
    Refuted {
        /// What refuted it.
        evidence: String,
    },
    /// Verification could not be performed, or is incapable of being performed.
    ///
    /// This is the state a capability is in when it has no verification strategy. It
    /// is a legitimate answer, not a failure — and the task layer decides what it
    /// means, because for an idempotent read-only call "unverified" may be fine,
    /// while for a payment it is not.
    Undetermined {
        /// Why verification was impossible.
        reason: String,
    },
}

impl VerificationOutcome {
    /// Whether the effect is known to have happened.
    ///
    /// The single question a caller most often needs. Note that it is **false** for
    /// both `Refuted` and `Undetermined`: neither is success, and collapsing them
    /// into `true`/`false` on a three-state enum is the bug this enum's shape
    /// prevents.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// Whether the effect is known **not** to have happened.
    #[must_use]
    pub fn is_refuted(&self) -> bool {
        matches!(self, Self::Refuted { .. })
    }

    /// Whether the truth is genuinely unknown.
    #[must_use]
    pub fn is_undetermined(&self) -> bool {
        matches!(self, Self::Undetermined { .. })
    }
}

/// A verification strategy, run after execution.
///
/// A trait rather than a flag, because "verify by re-reading the resource" and
/// "verify by asking the user" are different amounts of code and neither should be
/// expressed as a boolean on a declaration.
pub trait Verifier {
    /// Checks whether the intended effect actually occurred.
    ///
    /// Receives the execution outcome, because verification is meaningless without
    /// it: if nothing ran, there is nothing to confirm, and a verifier that returns
    /// `Verified` for a `Failed` execution is itself broken.
    ///
    /// # Errors
    ///
    /// A failure to *verify* is not a verification failure. An error here means the
    /// check could not be run, which maps to [`VerificationOutcome::Undetermined`]
    /// — never to `Refuted`, and never to `Verified`.
    fn verify(
        &self,
        execution: &ExecutionOutcome,
        at_ms: i64,
    ) -> Result<VerificationOutcome, VerifyError>;
}

/// A verification could not be performed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("verification could not run: {0}")]
pub struct VerifyError(pub String);

impl fmt::Display for VerificationOutcome {
    /// Renders without the evidence text.
    ///
    /// Evidence can contain what the adapter returned, which is untrusted and may
    /// contain user data. The state is what belongs in a summary line; the evidence
    /// is retrieved deliberately.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified { .. } => f.write_str("verified"),
            Self::Refuted { .. } => f.write_str("refuted"),
            Self::Undetermined { .. } => f.write_str("undetermined"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_verified_counts_as_verified() {
        assert!(
            VerificationOutcome::Verified {
                evidence: "e".into()
            }
            .is_verified()
        );
        // The important pair: refuted and undetermined are both *not* success, and
        // must not be conflated with each other either.
        assert!(
            !VerificationOutcome::Refuted {
                evidence: "e".into()
            }
            .is_verified()
        );
        assert!(!VerificationOutcome::Undetermined { reason: "r".into() }.is_verified());
    }

    #[test]
    fn refuted_and_undetermined_are_different_states() {
        let r = VerificationOutcome::Refuted {
            evidence: "resource absent".into(),
        };
        let u = VerificationOutcome::Undetermined {
            reason: "no API to check".into(),
        };
        assert!(r.is_refuted() && !r.is_undetermined());
        assert!(u.is_undetermined() && !u.is_refuted());
        assert_ne!(r, u);
    }

    #[test]
    fn unknown_execution_is_not_failure_execution() {
        // The distinction TP-12 turns on.
        let failed = ExecutionOutcome::Failed {
            detail: "refused by peer".into(),
        };
        let unknown = ExecutionOutcome::Unknown {
            detail: "timed out".into(),
        };
        assert_ne!(failed, unknown);
    }

    #[test]
    fn display_omits_evidence() {
        // Evidence may carry untrusted adapter output; a summary line must not.
        let v = VerificationOutcome::Verified {
            evidence: "user@example.test".into(),
        };
        assert_eq!(v.to_string(), "verified");
    }

    /// The verifier contract, exercised by a deterministic fixture.
    struct AlwaysRefutes;
    impl Verifier for AlwaysRefutes {
        fn verify(
            &self,
            execution: &ExecutionOutcome,
            _at_ms: i64,
        ) -> Result<VerificationOutcome, VerifyError> {
            // Proves the verifier actually reads the execution outcome: for a failed
            // execution it must not claim the effect was refuted-and-therefore-safe-to-
            // retry, it must report that there was nothing to check.
            if matches!(execution, ExecutionOutcome::Failed { .. }) {
                return Ok(VerificationOutcome::Undetermined {
                    reason: "nothing ran, so there is nothing to verify".into(),
                });
            }
            Ok(VerificationOutcome::Refuted {
                evidence: "the fixture always refutes".into(),
            })
        }
    }

    #[test]
    fn a_verifier_sees_the_execution_outcome() {
        let v = AlwaysRefutes;
        let out = v
            .verify(&ExecutionOutcome::Succeeded { output: None }, 0)
            .expect("verify");
        assert!(out.is_refuted());

        let out = v
            .verify(&ExecutionOutcome::Failed { detail: "d".into() }, 0)
            .expect("verify");
        assert!(out.is_undetermined(), "a failed run has nothing to verify");
    }
}
