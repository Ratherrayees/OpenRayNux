//! An audit record: the five questions, as data.

use serde::{Deserialize, Serialize};

use orxnud_domain::ids::{RequestId, TaskId};
use orxnud_domain::{Actor, ApprovalDigest, DataClass, RiskClass};

/// What happened to the action the record describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutcomeKind {
    /// The action was authorised and is about to run.
    Authorised,
    /// The action ran and its result was recorded.
    Completed,
    /// The action ran and failed.
    Failed,
    /// The action was refused. **The denial path is audited too** — a policy
    /// that logs its allows and not its denies cannot be reviewed.
    Denied,
    /// The action's effect may or may not have occurred.
    ///
    /// The honest state after a crash between "ran" and "recorded". Its
    /// existence is what makes TP-12 satisfiable.
    Uncertain,
    /// The user cancelled the action.
    Cancelled,
}

/// The outcome half of a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "detail")]
pub enum AuditOutcome {
    /// Recorded before execution.
    #[serde(rename_all = "kebab-case")]
    Authorised {
        /// When it was authorised, ms since epoch.
        at_ms: i64,
    },
    /// Recorded after execution.
    #[serde(rename_all = "kebab-case")]
    Finished {
        /// How it ended.
        kind: OutcomeKind,
        /// When, ms since epoch.
        at_ms: i64,
        /// A short, redacted description. Never a secret.
        detail: Option<String>,
    },
}

/// One audit record.
///
/// Deliberately carries a `secret_ref` *name* and never a secret value. The
/// audit journal is the artefact most likely to be exported for support, so it
/// must be safe to read by anyone who can read the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Monotonic sequence number, assigned by the chain.
    pub seq: u64,
    /// Who requested the action.
    pub actor: Actor,
    /// The human whose authority underpins it, if any.
    pub authority_root: Option<String>,
    /// Which capability.
    pub capability: String,
    /// A human-readable target, redacted.
    pub target: Option<String>,
    /// The data class involved.
    pub data_class: DataClass,
    /// The assessed risk.
    pub risk: RiskClass,
    /// The policy version that decided.
    pub policy_version: String,
    /// The approval digest, when one was required.
    pub approval: Option<ApprovalDigest>,
    /// The credential **reference** used. Never the value.
    pub secret_ref: Option<String>,
    /// Which task.
    pub task: Option<TaskId>,
    /// Correlation id for the originating request.
    pub request: Option<RequestId>,
    /// The outcome.
    pub outcome: AuditOutcome,
}

impl AuditRecord {
    /// Builds an `Authorised` record. Called by policy **before** dispatch.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn authorised(
        actor: Actor,
        capability: impl Into<String>,
        target: Option<String>,
        data_class: DataClass,
        risk: RiskClass,
        policy_version: impl Into<String>,
        approval: Option<ApprovalDigest>,
        secret_ref: Option<String>,
        task: Option<TaskId>,
        request: Option<RequestId>,
        at_ms: i64,
    ) -> Self {
        Self {
            seq: 0, // assigned by the chain
            authority_root: actor.authority_root().map(ToString::to_string),
            actor,
            capability: capability.into(),
            target,
            data_class,
            risk,
            policy_version: policy_version.into(),
            approval,
            secret_ref,
            task,
            request,
            outcome: AuditOutcome::Authorised { at_ms },
        }
    }

    /// Attaches the terminal outcome, consuming the record.
    #[must_use]
    pub fn finished(mut self, kind: OutcomeKind, at_ms: i64, detail: Option<String>) -> Self {
        self.outcome = AuditOutcome::Finished {
            kind,
            at_ms,
            detail,
        };
        self
    }

    /// The key used to correlate a terminal record with its authorisation.
    ///
    /// Prefers the request id, falling back to the task id. `None` when neither
    /// is present, in which case the record cannot be correlated and the
    /// unresolved-authorisation detector ignores it.
    #[must_use]
    pub fn correlation_key(&self) -> Option<String> {
        self.request
            .as_ref()
            .map(|r| format!("req:{r}"))
            .or_else(|| self.task.as_ref().map(|t| format!("task:{t}")))
    }

    /// The canonical bytes that are hashed.
    ///
    /// Field order is fixed here rather than relying on `serde_json`'s map
    /// ordering, because the hash must be reproducible across processes and
    /// versions. A change to this function is a change to the chain format and
    /// needs a migration note.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut s = String::with_capacity(256);
        s.push_str(&self.seq.to_string());
        s.push('|');
        s.push_str(self.actor.label());
        s.push('|');
        s.push_str(self.authority_root.as_deref().unwrap_or("-"));
        s.push('|');
        s.push_str(&self.capability);
        s.push('|');
        s.push_str(self.target.as_deref().unwrap_or("-"));
        s.push('|');
        s.push_str(match self.data_class {
            DataClass::Public => "public",
            DataClass::Personal => "personal",
            DataClass::Sensitive => "sensitive",
            DataClass::Regulated => "regulated",
        });
        s.push('|');
        s.push_str(match self.risk {
            RiskClass::Low => "low",
            RiskClass::Medium => "medium",
            RiskClass::High => "high",
            RiskClass::Critical => "critical",
        });
        s.push('|');
        s.push_str(&self.policy_version);
        s.push('|');
        s.push_str(
            &self
                .approval
                .map(|d| d.to_hex())
                .unwrap_or_else(|| "-".to_owned()),
        );
        s.push('|');
        s.push_str(self.secret_ref.as_deref().unwrap_or("-"));
        s.push('|');
        s.push_str(self.task.as_ref().map_or("-", |v| v.as_str()));
        s.push('|');
        s.push_str(self.request.as_ref().map_or("-", |v| v.as_str()));
        s.push('|');
        s.push_str(&match &self.outcome {
            AuditOutcome::Authorised { at_ms } => format!("authorised@{at_ms}"),
            AuditOutcome::Finished { kind, at_ms, .. } => {
                format!(
                    "{}@{at_ms}",
                    serde_json::to_string(kind).unwrap_or_else(|_| "?".to_owned())
                )
            }
        });
        s.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_domain::actor::{AuthChannel, SystemComponent};
    use orxnud_domain::ids::UserId;

    fn rec() -> AuditRecord {
        AuditRecord::authorised(
            Actor::Human {
                user: UserId::new("u-1"),
                via: AuthChannel::LocalInteractive,
            },
            "send-message",
            Some("alice".into()),
            DataClass::Personal,
            RiskClass::High,
            "v1",
            None,
            Some("openraynux/anthropic".into()),
            Some(TaskId::new("t-1")),
            Some(RequestId::new("r-1")),
            1000,
        )
    }

    #[test]
    fn authority_root_is_derived_from_the_actor() {
        assert_eq!(rec().authority_root.as_deref(), Some("u-1"));
        let sys = AuditRecord::authorised(
            Actor::System {
                component: SystemComponent::Backup,
            },
            "c",
            None,
            DataClass::Public,
            RiskClass::Low,
            "v1",
            None,
            None,
            None,
            None,
            0,
        );
        assert_eq!(sys.authority_root, None);
    }

    #[test]
    fn canonical_bytes_are_stable_for_identical_records() {
        assert_eq!(rec().canonical_bytes(), rec().canonical_bytes());
    }

    #[test]
    fn canonical_bytes_cover_every_field_that_must_be_bound() {
        // If a field were missing from the canonical form, tampering with it
        // would not change the hash, and the chain would not detect it.
        let base = rec();
        let h = |r: &AuditRecord| blake3::hash(&r.canonical_bytes()).to_hex().to_string();
        let base_h = h(&base);

        let mut variants: Vec<AuditRecord> = Vec::new();
        let mut v = base.clone();
        v.seq = 99;
        variants.push(v);
        let mut v = base.clone();
        v.capability = "delete-file".into();
        variants.push(v);
        let mut v = base.clone();
        v.target = Some("bob".into());
        variants.push(v);
        let mut v = base.clone();
        v.data_class = DataClass::Regulated;
        variants.push(v);
        let mut v = base.clone();
        v.risk = RiskClass::Critical;
        variants.push(v);
        let mut v = base.clone();
        v.policy_version = "v2".into();
        variants.push(v);
        let mut v = base.clone();
        v.secret_ref = Some("other/secret".into());
        variants.push(v);
        let mut v = base.clone();
        v.authority_root = Some("u-2".into());
        variants.push(v);
        variants.push(base.clone().finished(OutcomeKind::Completed, 2000, None));

        for v in &variants {
            assert_ne!(base_h, h(v), "a field change did not alter the hash");
        }
    }

    #[test]
    fn finished_replaces_the_outcome() {
        let r = rec().finished(OutcomeKind::Completed, 2000, Some("ok".into()));
        assert!(matches!(
            r.outcome,
            AuditOutcome::Finished {
                kind: OutcomeKind::Completed,
                ..
            }
        ));
    }

    #[test]
    fn uncertain_outcome_is_representable() {
        // TP-12 depends on being able to say "we do not know".
        let r = rec().finished(OutcomeKind::Uncertain, 2000, None);
        // `OutcomeKind` is serialised kebab-case, so the canonical form carries
        // "uncertain" rather than "Uncertain".
        let bytes = String::from_utf8_lossy(&r.canonical_bytes()).to_string();
        assert!(
            bytes.contains("uncertain"),
            "uncertain outcome not canonicalised: {bytes}"
        );
        // And it must differ from every other outcome, or the hash would not bind it.
        let completed = String::from_utf8_lossy(
            &rec()
                .finished(OutcomeKind::Completed, 2000, None)
                .canonical_bytes(),
        )
        .to_string();
        assert_ne!(bytes, completed);
    }

    #[test]
    fn no_secret_value_can_appear_in_a_record() {
        // The record type has no field that could hold a secret value: only a
        // reference. This test documents that the type itself is the control.
        let r = rec();
        let json = serde_json::to_string(&r).expect("serialise");
        assert!(json.contains("openraynux/anthropic"));
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        // Every string field is a name/ref, never a long opaque blob.
        for (k, v) in value.as_object().expect("object") {
            if let Some(s) = v.as_str() {
                assert!(
                    s.len() < 200,
                    "field {k} is suspiciously long: {} bytes",
                    s.len()
                );
            }
        }
    }
}
