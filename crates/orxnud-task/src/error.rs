//! The error taxonomy.
//!
//! # Why an enum and not a string
//!
//! docs-08 §9 requires every error to carry a user-facing message *and* a
//! machine-readable code, and Phase 2 requires that invalid input, policy
//! rejection, an unavailable dependency, a transient failure, a permanent
//! failure, a storage failure, a concurrency conflict, cancellation, a timeout and
//! an internal invariant violation stay distinguishable.
//!
//! A `String` collapses all of those into "something went wrong", which is
//! precisely the error message docs-08 §9 calls a bug. Worse, it makes retry
//! decisions impossible: a caller cannot tell "try again" from "this will never
//! work" from both being strings.
//!
//! [`EngineErrorKind`] is the part callers *branch* on, and it is a closed enum
//! so adding a category is a compile-time decision rather than a new string
//! somebody has to remember.

use std::fmt;

use orxnud_store::task_repo::TaskRepoError;

/// The machine-readable category of a failure.
///
/// Deliberately a closed set. Every variant maps to one of the categories Phase 2
/// names, and nothing maps to "other".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EngineErrorKind {
    /// The input was malformed or violated an invariant the caller owns.
    InvalidInput,
    /// A policy decision refused the action. Never retried.
    PolicyRefused,
    /// A dependency the operation needs is not present or not usable.
    Unavailable,
    /// A failure that may succeed on a later attempt.
    Transient,
    /// A failure that will not succeed on a later attempt.
    Permanent,
    /// The store could not complete the operation.
    Storage,
    /// Another writer got there first.
    ConcurrencyConflict,
    /// The operation was cancelled.
    Cancelled,
    /// The operation exceeded its deadline.
    Timeout,
    /// An internal invariant was violated. A bug.
    Invariant,
}

impl EngineErrorKind {
    /// A stable, lowercase identifier, for logs and for a future JSON-RPC code.
    ///
    /// Stable because a log line's meaning must not change when the enum is
    /// reordered; the wire name is what a support request quotes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid-input",
            Self::PolicyRefused => "policy-refused",
            Self::Unavailable => "unavailable",
            Self::Transient => "transient",
            Self::Permanent => "permanent",
            Self::Storage => "storage",
            Self::ConcurrencyConflict => "concurrency-conflict",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::Invariant => "invariant",
        }
    }

    /// Whether retrying the same operation could plausibly succeed.
    ///
    /// The retry decision, in one place. `InvalidInput`, `PolicyRefused` and
    /// `Permanent` are `false` — retrying a refused action is how a policy becomes
    /// a suggestion.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Transient | Self::ConcurrencyConflict | Self::Unavailable
        )
    }
}

impl fmt::Display for EngineErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A task-engine failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError {
    /// What kind of failure this is.
    pub kind: EngineErrorKind,
    /// A human-facing message. Never contains a secret: the caller redacts before
    /// constructing, and nothing here interpolates a payload.
    pub message: String,
    /// The task involved, when there is one.
    pub task_id: Option<String>,
    /// The attempt involved, when there is one.
    pub attempt_no: Option<u32>,
}

impl EngineError {
    /// Builds an error.
    #[must_use]
    pub fn new(kind: EngineErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            task_id: None,
            attempt_no: None,
        }
    }

    /// Attaches a task id.
    #[must_use]
    pub fn for_task(mut self, id: &str) -> Self {
        self.task_id = Some(id.to_owned());
        self
    }

    /// Attaches an attempt number.
    #[must_use]
    pub fn at_attempt(mut self, attempt_no: u32) -> Self {
        self.attempt_no = Some(attempt_no);
        self
    }

    /// The one-line form, for the `TaskEngine` contract's `Result<_, String>`.
    ///
    /// The kind is included because the contract's error channel is untyped. A
    /// caller of the conformance trait gets the category without losing it.
    #[must_use]
    pub fn to_contract_string(&self) -> String {
        let mut s = format!("[{}] {}", self.kind, self.message);
        if let Some(id) = &self.task_id {
            s.push_str(&format!(" (task {id}"));
            if let Some(a) = self.attempt_no {
                s.push_str(&format!(", attempt {a}"));
            }
            s.push(')');
        }
        s
    }

    /// A storage failure.
    #[must_use]
    pub fn storage(message: impl fmt::Display) -> Self {
        Self::new(EngineErrorKind::Storage, message.to_string())
    }

    /// An invalid input.
    #[must_use]
    pub fn invalid(message: impl fmt::Display) -> Self {
        Self::new(EngineErrorKind::InvalidInput, message.to_string())
    }

    /// An internal invariant violation — a bug.
    #[must_use]
    pub fn invariant(message: impl fmt::Display) -> Self {
        Self::new(EngineErrorKind::Invariant, message.to_string())
    }

    /// A concurrency conflict: another writer won.
    #[must_use]
    pub fn conflict(message: impl fmt::Display) -> Self {
        Self::new(EngineErrorKind::ConcurrencyConflict, message.to_string())
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_contract_string())
    }
}

impl std::error::Error for EngineError {}

impl From<TaskRepoError> for EngineError {
    fn from(e: TaskRepoError) -> Self {
        // The mapping is by *meaning*, not by convenience. A constraint violation
        // on an id is invalid input; everything else from the repository is a
        // storage failure, because the repository only reports storage problems
        // plus the two caller-fixable ones.
        let kind = match &e {
            // A proposal that is missing or in the wrong state is a caller-fixable
            // condition, not a storage failure — the same category as an unknown task
            // id. Mapping it to `Storage` would report "the database is broken" for what
            // is really "you asked to execute something nobody approved".
            TaskRepoError::AlreadyExists(_)
            | TaskRepoError::NotFound(_)
            | TaskRepoError::NoSuchProposal(_)
            | TaskRepoError::ProposalNotInState { .. } => EngineErrorKind::InvalidInput,
            TaskRepoError::UnknownState { .. } | TaskRepoError::Corrupt(_) => {
                EngineErrorKind::Invariant
            }
            TaskRepoError::Sqlite(inner)
                if matches!(
                    inner.as_ref(),
                    rusqlite::Error::SqliteFailure(e, _)
                        if e.code == rusqlite::ErrorCode::DatabaseBusy
                            || e.code == rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                EngineErrorKind::ConcurrencyConflict
            }
            TaskRepoError::Sqlite(_) => EngineErrorKind::Storage,
        };
        Self::new(kind, e.to_string())
    }
}

impl From<orxnud_store::schedule_repo::ScheduleRepoError> for EngineError {
    fn from(e: orxnud_store::schedule_repo::ScheduleRepoError) -> Self {
        use orxnud_store::schedule_repo::ScheduleRepoError as S;
        let kind = match &e {
            S::AlreadyExists(_) | S::NotFound(_) => EngineErrorKind::InvalidInput,
            S::InvalidPolicy { .. } => EngineErrorKind::Invariant,
            S::Sqlite(_) => EngineErrorKind::Storage,
        };
        Self::new(kind, e.to_string())
    }
}

impl From<orxnud_store::migration::MigrationError> for EngineError {
    fn from(e: orxnud_store::migration::MigrationError) -> Self {
        use orxnud_store::migration::MigrationError as M;
        let kind = match &e {
            // A failed migration is not retryable: the schema is in an unknown
            // state and retrying could compound the damage.
            M::Failed { .. } | M::RestoreFailed(_) | M::Snapshot(_) => EngineErrorKind::Invariant,
            M::NoSnapshot => EngineErrorKind::InvalidInput,
        };
        Self::new(kind, e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_kind_has_a_distinct_stable_name() {
        let kinds = [
            EngineErrorKind::InvalidInput,
            EngineErrorKind::PolicyRefused,
            EngineErrorKind::Unavailable,
            EngineErrorKind::Transient,
            EngineErrorKind::Permanent,
            EngineErrorKind::Storage,
            EngineErrorKind::ConcurrencyConflict,
            EngineErrorKind::Cancelled,
            EngineErrorKind::Timeout,
            EngineErrorKind::Invariant,
        ];
        let mut names = BTreeSet::new();
        for k in kinds {
            assert!(names.insert(k.as_str()), "duplicate wire name for {k:?}");
            assert_eq!(
                k.to_string(),
                k.as_str(),
                "Display must match the wire name"
            );
        }
        assert_eq!(names.len(), 10);
    }

    #[test]
    fn only_transient_failures_are_retryable() {
        for k in [
            EngineErrorKind::InvalidInput,
            EngineErrorKind::PolicyRefused,
            EngineErrorKind::Permanent,
            EngineErrorKind::Storage,
            EngineErrorKind::Cancelled,
            EngineErrorKind::Timeout,
            EngineErrorKind::Invariant,
        ] {
            assert!(!k.is_retryable(), "{k} must not be retryable");
        }
        for k in [
            EngineErrorKind::Transient,
            EngineErrorKind::ConcurrencyConflict,
            EngineErrorKind::Unavailable,
        ] {
            assert!(k.is_retryable(), "{k} must be retryable");
        }
    }

    #[test]
    fn a_refusal_is_never_retryable() {
        // Retrying a refused action is how a policy becomes a suggestion.
        assert!(!EngineErrorKind::PolicyRefused.is_retryable());
    }

    #[test]
    fn the_contract_string_carries_the_kind_and_the_task() {
        let e = EngineError::storage("db is locked")
            .for_task("t-1")
            .at_attempt(2);
        let s = e.to_contract_string();
        assert!(s.starts_with("[storage]"), "{s}");
        assert!(s.contains("task t-1"), "{s}");
        assert!(s.contains("attempt 2"), "{s}");
    }

    #[test]
    fn a_repository_duplicate_maps_to_invalid_input_not_storage() {
        let e = EngineError::from(TaskRepoError::AlreadyExists("t".into()));
        assert_eq!(e.kind, EngineErrorKind::InvalidInput);
    }

    #[test]
    fn an_unreadable_row_maps_to_an_invariant_violation() {
        // A row this build cannot decode is a bug, not bad luck.
        let e = EngineError::from(TaskRepoError::UnknownState(Box::new(
            orxnud_store::task_repo::UnknownStateDetail {
                id: "t".into(),
                raw: "?".into(),
            },
        )));
        assert_eq!(e.kind, EngineErrorKind::Invariant);
    }

    #[test]
    fn a_busy_database_maps_to_a_concurrency_conflict() {
        // Constructed by hand rather than provoked: provoking a real SQLITE_BUSY
        // needs a second connection holding a write lock, which belongs in the
        // concurrency integration tests, not in a mapping unit test.
        let busy = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("database is locked".into()),
        );
        let e = EngineError::from(TaskRepoError::Sqlite(Box::new(busy)));
        assert_eq!(e.kind, EngineErrorKind::ConcurrencyConflict);
        assert!(e.kind.is_retryable());
    }

    #[test]
    fn other_sqlite_failures_map_to_storage() {
        let e = EngineError::from(TaskRepoError::Sqlite(Box::new(
            rusqlite::Error::QueryReturnedNoRows,
        )));
        assert_eq!(e.kind, EngineErrorKind::Storage);
    }

    #[test]
    fn a_failed_migration_is_not_retryable() {
        let e = EngineError::from(orxnud_store::migration::MigrationError::Failed {
            version: 3,
            source: rusqlite::Error::QueryReturnedNoRows,
        });
        assert_eq!(e.kind, EngineErrorKind::Invariant);
        assert!(
            !e.kind.is_retryable(),
            "retrying a migration could compound the damage"
        );
    }

    #[test]
    fn a_missing_snapshot_is_invalid_input_not_a_bug() {
        let e = EngineError::from(orxnud_store::migration::MigrationError::NoSnapshot);
        assert_eq!(e.kind, EngineErrorKind::InvalidInput);
    }
}
