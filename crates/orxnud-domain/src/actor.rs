//! Identity and Actor — the first-class "who is acting" model (ADR-0027).
//!
//! # The question this answers
//!
//! For every action, the audit record must be able to answer five questions
//! (control S33):
//!
//! 1. Who requested this action?
//! 2. **On whose authority?**
//! 3. Under which policy?
//! 4. Using which credentials?
//! 5. As part of which task?
//!
//! This module supplies (1) and (2). `Actor` is a value that *carries its own
//! delegation chain*, so authority can never be inferred from ambient context
//! such as "which interface called us" or "what did we do last time".
//!
//! # The three rules that make it safe
//!
//! * **`External` can never grant.** It may *request*; only a `Human` authorises.
//!   This is what makes webhooks, inbound messages, and file watches safe to
//!   accept at all.
//! * **An `Ai` actor's authority is exactly its delegating human's authority,
//!   intersected with current task policy — never additive.** An AI actor can
//!   never do anything the human could not do directly in that context. This is
//!   the structural expression of "the model proposes; a deterministic engine
//!   disposes" (ADR-0012).
//! * **`System` is not network-reachable** and is never used for user-visible
//!   actions. It exists for housekeeping: migrations, retention, backup.

use serde::{Deserialize, Serialize};

use crate::ids::{CapabilityId, GrantId, RequestId, RunId, ScheduleId, TaskId, UserId};

/// How a human authenticated to this daemon.
///
/// A seam, not an implementation. v1 has exactly one local user; a future
/// multi-user or cloud deployment extends this enum rather than the actor
/// model (ADR-0027 revisit conditions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthChannel {
    /// Local interactive session (GUI, TUI, CLI on the same machine).
    LocalInteractive,
    /// Local non-interactive (a script, a systemd unit, a scheduled job).
    LocalNonInteractive,
    /// A remote client over the cloud transport.
    Remote,
    /// A paired device.
    Device,
}

/// Which part of the daemon is acting as `System`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SystemComponent {
    /// Schema migrations and version housekeeping.
    Migration,
    /// Scheduled backup and verified restore.
    Backup,
    /// Retention and deletion policy enforcement.
    Retention,
    /// A capability health check.
    HealthCheck,
}

/// Provenance of a model response.
///
/// Recorded so a proposal can be traced to the exact model and prompt that
/// produced it, and so the non-blocking AI evaluation track has a key to join
/// on. It is *advisory*: a `ModelProvenance` grants nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelProvenance {
    /// Provider-neutral model identifier, e.g. `some-provider/some-model`.
    pub model: String,
    /// Provider-reported model revision or snapshot, when available.
    pub revision: Option<String>,
    /// Hash of the prompt/agent configuration that framed the request.
    pub prompt_hash: String,
    /// Correlation id for the provider request.
    pub request_id: RequestId,
}

impl ModelProvenance {
    /// Builds a provenance record with no revision.
    #[must_use]
    pub fn new(
        model: impl Into<String>,
        prompt_hash: impl Into<String>,
        request_id: RequestId,
    ) -> Self {
        Self {
            model: model.into(),
            revision: None,
            prompt_hash: prompt_hash.into(),
            request_id,
        }
    }
}

/// Who is performing an action.
///
/// Every `orxnud_policy::CapabilityInvocation` carries one. The capability layer
/// never sees it — authority is settled by policy *before* the invocation is
/// dispatched — so a capability cannot learn its caller and become a confused
/// deputy (ADR-0027, control S8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "detail")]
pub enum Actor {
    /// The human owner. The **only** actor that can grant authority.
    Human {
        /// Which human.
        user: UserId,
        /// How they authenticated.
        via: AuthChannel,
    },

    /// The model, acting on a human's behalf.
    ///
    /// Carries the delegation. An `Ai` actor with no human delegation has **no
    /// authority at all** — `delegated_by` is not optional, by design.
    Ai {
        /// The human whose authority is being used.
        delegated_by: UserId,
        /// The run this model activity belongs to.
        run: RunId,
        /// The task the run belongs to.
        task: TaskId,
        /// Which model, and under which prompt.
        provenance: ModelProvenance,
    },

    /// The daemon itself, for housekeeping. Never network-reachable.
    System {
        /// Which component.
        component: SystemComponent,
    },

    /// A configured integration acting inside a grant a human made.
    Integration {
        /// The capability performing the work.
        capability: CapabilityId,
        /// The human who granted it.
        granted_by: UserId,
        /// The standing grant being exercised.
        grant: GrantId,
    },

    /// A scheduled task, acting within authority captured when it was created.
    Scheduled {
        /// Which schedule.
        schedule: ScheduleId,
        /// The human who authorised the schedule.
        authorised_by: UserId,
        /// The task instance this execution belongs to.
        task: TaskId,
    },

    /// An inbound event from outside. Can *request*; can never *grant*.
    External {
        /// Where it came from.
        source: crate::ids::ExternalSource,
        /// Correlation id for the inbound request.
        request: RequestId,
    },
}

impl Actor {
    /// The human whose authority underpins this actor, if any.
    ///
    /// This is the delegation chain. For `Human` it is the actor itself; for
    /// `Ai`, `Integration` and `Scheduled` it is the delegating/authorising
    /// human; for `System` and `External` there is none, because neither can
    /// borrow a human's authority.
    #[must_use]
    pub fn authority_root(&self) -> Option<&UserId> {
        match self {
            Self::Human { user, .. } => Some(user),
            Self::Ai { delegated_by, .. } => Some(delegated_by),
            Self::Integration { granted_by, .. } => Some(granted_by),
            Self::Scheduled { authorised_by, .. } => Some(authorised_by),
            Self::System { .. } | Self::External { .. } => None,
        }
    }

    /// Whether this actor can ever grant authority to something else.
    ///
    /// Only a `Human`. Everything else may *exercise* a grant but never create
    /// one. This is the single check that makes "the LLM must never be the
    /// authority that grants itself permission" a property rather than a hope.
    #[must_use]
    pub fn can_grant(&self) -> bool {
        matches!(self, Self::Human { .. })
    }

    /// Whether this actor is the model.
    ///
    /// Used by the non-blocking AI evaluation track to exclude model-originated
    /// activity from human-trust accounting.
    #[must_use]
    pub fn is_ai(&self) -> bool {
        matches!(self, Self::Ai { .. })
    }

    /// Whether this actor originated outside the trust boundary.
    #[must_use]
    pub fn is_external(&self) -> bool {
        matches!(self, Self::External { .. })
    }

    /// Whether this actor is the daemon's own housekeeping.
    #[must_use]
    pub fn is_system(&self) -> bool {
        matches!(self, Self::System { .. })
    }

    /// A short, stable label for logs and audit lines.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Human { .. } => "human",
            Self::Ai { .. } => "ai",
            Self::System { .. } => "system",
            Self::Integration { .. } => "integration",
            Self::Scheduled { .. } => "scheduled",
            Self::External { .. } => "external",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ExternalSource;
    use proptest::prelude::*;

    fn human() -> UserId {
        UserId::new("u-1")
    }

    fn request() -> RequestId {
        RequestId::new("r-1")
    }

    fn run() -> RunId {
        RunId::new("run-1")
    }

    fn task() -> TaskId {
        TaskId::new("t-1")
    }

    fn provenance() -> ModelProvenance {
        ModelProvenance::new("m", "p", request())
    }

    fn all_actors() -> Vec<Actor> {
        vec![
            Actor::Human {
                user: human(),
                via: AuthChannel::LocalInteractive,
            },
            Actor::Ai {
                delegated_by: human(),
                run: run(),
                task: task(),
                provenance: provenance(),
            },
            Actor::System {
                component: SystemComponent::Backup,
            },
            Actor::Integration {
                capability: CapabilityId::new("c"),
                granted_by: human(),
                grant: GrantId::new("g"),
            },
            Actor::Scheduled {
                schedule: ScheduleId::new("s"),
                authorised_by: human(),
                task: task(),
            },
            Actor::External {
                source: ExternalSource::Unknown,
                request: request(),
            },
        ]
    }

    #[test]
    fn only_a_human_can_grant() {
        for actor in all_actors() {
            let expected = matches!(actor, Actor::Human { .. });
            assert_eq!(
                actor.can_grant(),
                expected,
                "can_grant wrong for {:?}",
                actor.label()
            );
        }
    }

    #[test]
    fn system_and_external_have_no_authority_root() {
        // System and External cannot borrow a human's authority. This is what
        // stops a webhook from acting with the user's permissions.
        assert!(
            Actor::System {
                component: SystemComponent::Migration
            }
            .authority_root()
            .is_none()
        );
        assert!(
            Actor::External {
                source: ExternalSource::Unknown,
                request: request()
            }
            .authority_root()
            .is_none()
        );
    }

    #[test]
    fn ai_actor_authority_is_exactly_its_delegating_human() {
        let other = UserId::new("u-2");
        let ai = Actor::Ai {
            delegated_by: human(),
            run: run(),
            task: task(),
            provenance: provenance(),
        };
        assert_eq!(ai.authority_root(), Some(&human()));
        assert_ne!(ai.authority_root(), Some(&other));
    }

    #[test]
    fn ai_actor_never_outranks_its_human() {
        // The structural statement of "never additive": an AI actor derives
        // its authority, it does not hold any of its own.
        let human_actor = Actor::Human {
            user: human(),
            via: AuthChannel::LocalInteractive,
        };
        let ai_actor = Actor::Ai {
            delegated_by: human(),
            run: run(),
            task: task(),
            provenance: provenance(),
        };
        assert!(!ai_actor.can_grant());
        assert!(human_actor.can_grant());
        assert_eq!(human_actor.authority_root(), ai_actor.authority_root());
    }

    #[test]
    fn labels_are_distinct() {
        let mut labels: Vec<&str> = all_actors().iter().map(Actor::label).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), 6, "actor labels must be distinct");
    }

    proptest! {
        /// A non-human actor never reports `can_grant`, whatever its shape.
        /// Generated rather than enumerated so the property covers future
        /// variants without the test needing updating.
        #[test]
        fn only_human_grants(ai_task: (String, String)) {
            let actor = Actor::Ai {
                delegated_by: UserId::new(ai_task.0),
                run: RunId::new(ai_task.1.clone()),
                task: TaskId::new(ai_task.1.clone()),
                provenance: ModelProvenance::new("m", "p", RequestId::new("q")),
            };
            prop_assert!(!actor.can_grant());
            prop_assert!(actor.is_ai());
            prop_assert!(!actor.is_external());
        }
    }
}
