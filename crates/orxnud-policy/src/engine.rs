//! The engine: evaluate an action, and produce the only authorisation proof.

use orxnud_audit::{AuditChain, AuditOutcome, OutcomeKind};
use orxnud_domain::ids::{CapabilityId, RequestId};
use orxnud_domain::{
    ActionRequest, Actor, ApprovalRecord, AuthorisationProof, CapabilityInvocation, DataClass,
    InvocationContext, NormalizedParams, RiskClass,
};

use crate::budget::{BudgetLedger, scope_for_risk};
use crate::decision::{Decision, DenialReason, PolicyError};
use crate::digest::digest_for;
use crate::policy_set::{GrantLookup, PolicySet};
use crate::seal;

/// A capability's declared contract, as policy sees it.
///
/// Declared *data*, not a live adapter. A capability is not "registered" because
/// some code says so; it is registered because a manifest declares its risk,
/// data envelope, and parameter schema. That is what makes the registry
/// reviewable (ADR-0007: review capacity, not demand, is the constraint).
#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityDeclaration {
    /// Which capability.
    pub id: CapabilityId,
    /// Its declared risk. `RiskClass::UNKNOWN` until classified, which gates it.
    pub risk: RiskClass,
    /// The highest data class it may touch.
    pub max_data_class: DataClass,
    /// Whether it reaches the network. Egress consent is checked only for
    /// capabilities that do.
    pub networked: bool,
    /// Relative cost per invocation, charged against the risk scope.
    pub cost: u64,
}

impl CapabilityDeclaration {
    /// A minimal declaration. Phase 1 registers none.
    #[must_use]
    pub fn new(
        id: CapabilityId,
        risk: RiskClass,
        max_data_class: DataClass,
        networked: bool,
        cost: u64,
    ) -> Self {
        Self {
            id,
            risk,
            max_data_class,
            networked,
            cost,
        }
    }
}

/// The deterministic policy engine.
#[derive(Debug)]
pub struct PolicyEngine {
    policy: PolicySet,
    budget: BudgetLedger,
    capabilities: Vec<CapabilityDeclaration>,
    audit: AuditChain,
    policy_version: String,
    /// Digests of approvals already honoured, so an approval is single-use (S6).
    ///
    /// A `BTreeSet` rather than a `HashSet`: the audit chain and policy output must be
    /// reproducible across runs, and iteration order leaking into behaviour would make
    /// a denial depend on hash seeds.
    consumed_approvals: std::collections::BTreeSet<orxnud_domain::approval::ApprovalDigest>,
}

impl PolicyEngine {
    /// Builds an engine that permits nothing.
    #[must_use]
    pub fn new(policy: PolicySet, budget: BudgetLedger, policy_version: impl Into<String>) -> Self {
        Self {
            policy,
            budget,
            capabilities: Vec::new(),
            audit: AuditChain::new(),
            policy_version: policy_version.into(),
            consumed_approvals: std::collections::BTreeSet::new(),
        }
    }

    /// Registers a capability declaration.
    pub fn register(&mut self, decl: CapabilityDeclaration) {
        self.capabilities.push(decl);
    }

    /// The audit journal. Read-only, so a caller cannot alter the chain.
    #[must_use]
    pub fn audit(&self) -> &AuditChain {
        &self.audit
    }

    /// Marks an approval digest as spent.
    ///
    /// Called by [`Self::authorise`] when it permits a gated action. Exposed so a
    /// caller that obtains an approval through some other route — a UI approval
    /// dialog, say — can record the consumption in the same place the decision reads
    /// it, rather than in a second ledger that could drift.
    pub fn consume_approval(&mut self, digest: orxnud_domain::approval::ApprovalDigest) {
        self.consumed_approvals.insert(digest);
    }

    /// Whether an approval digest has already been spent.
    #[must_use]
    pub fn approval_is_consumed(&self, digest: &orxnud_domain::approval::ApprovalDigest) -> bool {
        self.consumed_approvals.contains(digest)
    }

    /// The policy version recorded in every audit record.
    #[must_use]
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }

    fn declaration(&self, id: &CapabilityId) -> Option<&CapabilityDeclaration> {
        self.capabilities.iter().find(|c| &c.id == id)
    }

    /// Evaluates an action, without producing an invocation.
    ///
    /// This is the pure decision path. [`Self::authorise`] layers audit and
    /// budget mutation on top, so the decision logic can be tested exhaustively
    /// without a journal.
    ///
    /// # Errors
    ///
    /// [`PolicyError::Unavailable`] if the policy set cannot be read, which
    /// fails closed.
    pub fn evaluate(
        &self,
        request: &ActionRequest,
        actor: &Actor,
        target: Option<&str>,
        params: &NormalizedParams,
        approval: Option<&ApprovalRecord>,
        now_ms: i64,
    ) -> Result<Decision, PolicyError> {
        // --- 0. AUTHORITY. The step that did not exist before Actor did. ---
        //
        // Only a human may grant, and only a human has an authority root that
        // policy can borrow. An External actor is refused here, before anything
        // else is even looked at.
        if !actor.can_grant() && actor.authority_root().is_none() {
            return Ok(Decision::Deny {
                reason: DenialReason::NoAuthorityRoot {
                    actor: actor.label().to_owned(),
                },
            });
        }

        // --- 1. Registration ---
        let Some(decl) = self.declaration(&request.capability) else {
            return Ok(Decision::Deny {
                reason: DenialReason::UnknownCapability {
                    capability: request.capability.to_string(),
                },
            });
        };

        // --- 2/3. Data class within the capability's declared envelope ---
        let effective = request.effective_class();
        if effective > decl.max_data_class {
            return Ok(Decision::Deny {
                reason: DenialReason::DataClassExceeded {
                    required: effective,
                    permitted: decl.max_data_class,
                },
            });
        }

        // --- 4. Grant ---
        match self.policy.find_grant(&request.capability, now_ms) {
            None => {
                return Ok(Decision::Deny {
                    reason: DenialReason::NoGrant {
                        capability: request.capability.to_string(),
                    },
                });
            }
            Some((_, GrantLookup::Revoked)) => {
                return Ok(Decision::Deny {
                    reason: DenialReason::NoGrant {
                        capability: request.capability.to_string(),
                    },
                });
            }
            Some((_, GrantLookup::Expired(expired_at_ms))) => {
                return Ok(Decision::Deny {
                    reason: DenialReason::GrantExpired {
                        capability: request.capability.to_string(),
                        expired_at_ms,
                        now_ms,
                    },
                });
            }
            Some((grant, GrantLookup::Valid)) => {
                if !grant.covers_data_class(effective) {
                    return Ok(Decision::Deny {
                        reason: DenialReason::DataClassExceeded {
                            required: effective,
                            permitted: grant.max_data_class,
                        },
                    });
                }
            }
        }

        // --- 5. Risk, with the data-class escalation from the domain layer ---
        let risk = request.effective_risk(decl.risk);

        // --- 7. Egress consent, for networked capabilities only ---
        if decl.networked
            && effective.requires_explicit_consent()
            && !self.policy.egress_consented(effective)
        {
            return Ok(Decision::Deny {
                reason: DenialReason::EgressNotConsented {
                    data_class: effective,
                },
            });
        }

        // --- 6. Approval, if the risk class requires one ---
        if risk.requires_approval() {
            let Some(record) = approval else {
                return Ok(Decision::Deny {
                    reason: DenialReason::ApprovalRequired { risk },
                });
            };
            if !record.is_valid_at(now_ms) {
                return Ok(Decision::Deny {
                    reason: DenialReason::ApprovalExpired {
                        expired_at_ms: record.expires_at_ms,
                        now_ms,
                    },
                });
            }
            // The anti-Loopjacking check: recompute from the action about to
            // run, and compare with what the user approved.
            let recomputed = digest_for(
                actor,
                &request.capability,
                target,
                params,
                record.issued_at_ms,
                record.expires_at_ms,
            );
            if recomputed != record.digest {
                return Ok(Decision::Deny {
                    reason: DenialReason::ApprovalDigestMismatch,
                });
            }
            // Single-use. See `DenialReason::ApprovalAlreadyUsed`: the digest proves
            // this is the approved operation, and this proves it has not already run.
            if self.consumed_approvals.contains(&record.digest) {
                return Ok(Decision::Deny {
                    reason: DenialReason::ApprovalAlreadyUsed,
                });
            }
            // An approval is honoured only for the human who gave it, so the
            // gate names that human rather than the delegating actor kind.
            let approver = match actor.authority_root() {
                Some(user) => Actor::Human {
                    user: user.clone(),
                    via: orxnud_domain::actor::AuthChannel::LocalInteractive,
                },
                // Unreachable: step 0 already refused any actor without a root.
                None => actor.clone(),
            };
            return Ok(Decision::Gate {
                risk,
                required_digest: recomputed,
                approver,
            });
        }

        // --- 8. Budget is checked at authorise(), because it mutates ---
        Ok(Decision::Allow { risk })
    }

    /// Evaluates and, if permitted, produces the only authorisation proof.
    ///
    /// Ordering is deliberate and is the reason this is not one expression:
    ///
    /// 1. **Evaluate** (pure). No side effects; exhaustively testable.
    /// 2. **Budget check.** Before the audit record, so we never write an
    ///    "authorised" entry for an action we are about to refuse.
    /// 3. **Audit the authorisation.** *Before* the call. A journal failure here
    ///    fails closed: an action that cannot be recorded must not run.
    /// 4. **Charge the budget.** Only now that the decision is to proceed.
    /// 5. **Audit a denial**, so the refusal path is reviewable too.
    ///
    /// # Errors
    ///
    /// Fails closed on any journal failure.
    // Eight parameters, which is the point: this is the single narrowing point
    // where actor, context, target, params, approval and time all meet. Bundling
    // them into a struct would move the decision behind a constructor and make
    // it harder to see that nothing is dropped. `audit_pair` is the same shape
    // because it records the same decision.
    #[allow(clippy::too_many_arguments)]
    pub fn authorise(
        &mut self,
        request: ActionRequest,
        actor: Actor,
        context: InvocationContext,
        target: Option<String>,
        params: NormalizedParams,
        approval: Option<&ApprovalRecord>,
        now_ms: i64,
    ) -> Result<Decision, PolicyError> {
        let decision = self.evaluate(
            &request,
            &actor,
            target.as_deref(),
            &params,
            approval,
            now_ms,
        )?;

        // --- 2. Budget, before anything is recorded as authorised. ---
        let declared_cost = self.declaration(&request.capability).map_or(0, |d| d.cost);
        let risk = match &decision {
            Decision::Allow { risk } | Decision::Gate { risk, .. } => *risk,
            Decision::Deny { .. } => RiskClass::UNKNOWN,
        };
        if !decision.is_denied() && !self.budget.permits_all(declared_cost) {
            let scope = scope_for_risk(risk);
            // Report against the tightest ceiling, which is the one that bit.
            let tightest = self
                .budget
                .tightest()
                .map_or((scope.to_owned(), 0, 0), |(name, limit, spent)| {
                    (name.to_owned(), limit, spent)
                });
            let denial = Decision::Deny {
                reason: DenialReason::BudgetExceeded {
                    scope: tightest.0,
                    limit: tightest.1,
                    spent: tightest.2,
                },
            };
            self.audit_pair(
                &request,
                &actor,
                &risk,
                target.as_deref(),
                approval,
                &denial,
                now_ms,
            )?;
            return Ok(denial);
        }

        // --- 3 + 5. Audit. Fails closed. ---
        self.audit_pair(
            &request,
            &actor,
            &risk,
            target.as_deref(),
            approval,
            &decision,
            now_ms,
        )?;

        if decision.is_denied() {
            return Ok(decision);
        }

        // --- 3b. Consume the approval, now that the decision is to proceed. ---
        //
        // In `authorise` rather than only in the dispatch helper, so every path that
        // permits a gated action burns the approval -- including a future caller that
        // does not go through `authorise_for_dispatch`. A replay or a retry is then
        // refused at the next decision (S6: single-use).
        if let Some(record) = approval {
            self.consumed_approvals.insert(record.digest);
        }

        // --- 4. Charge, now that the decision is to proceed. ---
        if declared_cost > 0 {
            // Safe: `permits_all` already returned false for an undeclared
            // ledger, so at least one ceiling exists here.
            let _ = self.budget.charge_all(declared_cost);
        }

        let proof = AuthorisationProof::issue(
            &seal(),
            self.policy_version.clone(),
            match &decision {
                Decision::Gate {
                    required_digest, ..
                } => Some(*required_digest),
                _ => approval.map(|a| a.digest),
            },
            risk,
        );
        // Constructed and immediately dropped: Phase 1 has no dispatcher to hand
        // it to, and building one would be a capability. Constructing it here is
        // the proof that policy is the only crate that can -- the constructor
        // demands this crate's seal, and gate G2 forbids any other crate from
        // naming it.
        let _invocation = CapabilityInvocation::authorise(&seal(), request, actor, context, proof);
        Ok(decision)
    }

    /// [`Self::authorise`], but **returns** the authorised invocation instead of
    /// discarding it.
    ///
    /// # Why this exists
    ///
    /// [`Self::authorise`] builds the invocation and drops it on the floor, because
    /// Phase 1 had no dispatcher to hand one to. The dispatcher cannot build one
    /// itself: `CapabilityInvocation::authorise` demands *this crate's*
    /// [`PolicySeal`], and gate G2 forbids any other crate from naming it. So the
    /// only way an invocation can reach the dispatcher is for policy to hand it out
    /// — which is exactly the shape the boundary is supposed to have.
    ///
    /// The alternative — letting the dispatcher construct invocations — would move
    /// the authority decision's *output* to the caller while leaving the *decision*
    /// in policy. Two places would then hold authority, and only one of them would be
    /// audited.
    ///
    /// # Errors
    ///
    /// As [`Self::authorise`], plus:
    ///
    /// - [`PolicyError::Denied`] when the decision is not a permit. An invocation is
    ///   returned **only** for `Allow` and for a satisfied `Gate`. There is no path
    ///   from a refusal to an invocation.
    #[allow(clippy::too_many_arguments)]
    pub fn authorise_for_dispatch(
        &mut self,
        request: ActionRequest,
        actor: Actor,
        context: InvocationContext,
        target: Option<String>,
        params: NormalizedParams,
        approval: Option<&ApprovalRecord>,
        now_ms: i64,
    ) -> Result<AuthorisedInvocation, PolicyError> {
        let decision = self.authorise(
            request.clone(),
            actor.clone(),
            context.clone(),
            target,
            params,
            approval,
            now_ms,
        )?;
        if decision.is_denied() {
            return Err(PolicyError::Denied {
                reason: decision.denial().map_or_else(
                    || "refused without a stated reason".to_owned(),
                    ToString::to_string,
                ),
            });
        }
        // `authorise` consumed `request`, `actor` and `context` and returned only a
        // `Decision`, so clones above were needed to run it at all. The proof is
        // then re-derived from the decision that `authorise` already computed, rather
        // than asking policy to decide twice -- a second evaluation could charge the
        // budget again and append a second audit record for one caller action.
        let proof = AuthorisationProof::issue(
            &seal(),
            self.policy_version.clone(),
            match &decision {
                Decision::Gate {
                    required_digest, ..
                } => Some(*required_digest),
                _ => approval.map(|a| a.digest),
            },
            decision.risk(),
        );
        let invocation = CapabilityInvocation::authorise(&seal(), request, actor, context, proof);
        Ok(AuthorisedInvocation {
            invocation,
            decision,
        })
    }

    /// Writes the pre-call authorisation record, plus a terminal record when the
    /// decision was a refusal.
    ///
    /// Both records share a correlation key, so `unresolved_authorisations`
    /// closes correctly (the journal is append-only; a record cannot be updated).
    #[allow(clippy::too_many_arguments)]
    fn audit_pair(
        &mut self,
        request: &ActionRequest,
        actor: &Actor,
        risk: &RiskClass,
        target: Option<&str>,
        approval: Option<&ApprovalRecord>,
        decision: &Decision,
        now_ms: i64,
    ) -> Result<(), PolicyError> {
        let request_id = RequestId::new(correlation_of(request));
        let approved_digest = match decision {
            Decision::Gate {
                required_digest, ..
            } => Some(*required_digest),
            _ => approval.map(|a| a.digest),
        };
        let authorised = orxnud_audit::AuditRecord::authorised(
            actor.clone(),
            request.capability.to_string(),
            target.map(str::to_owned),
            request.effective_class(),
            *risk,
            self.policy_version.clone(),
            approved_digest,
            None,
            Some(request.task.clone()),
            Some(request_id.clone()),
            now_ms,
        );
        self.audit
            .append(authorised)
            .map_err(|e| PolicyError::AuditUnavailable(e.to_string()))?;

        if let Decision::Deny { reason } = decision {
            let terminal = orxnud_audit::AuditRecord::authorised(
                actor.clone(),
                request.capability.to_string(),
                target.map(str::to_owned),
                request.effective_class(),
                *risk,
                self.policy_version.clone(),
                approved_digest,
                None,
                Some(request.task.clone()),
                Some(request_id),
                now_ms,
            )
            .finished(OutcomeKind::Denied, now_ms, Some(reason.code().to_owned()));
            self.audit
                .append(terminal)
                .map_err(|e| PolicyError::AuditUnavailable(e.to_string()))?;
        }
        Ok(())
    }
}

/// A stable correlation key for the two audit records of one authorisation.
///
/// Derived from the task and step, so a retry of the *same* step correlates to
/// the *same* key (which is what lets the journal see the retry as a retry)
/// while a different step does not.
fn correlation_of(request: &ActionRequest) -> String {
    format!("{}#{}", request.task, request.step)
}

/// Whether an outcome marks the authorisation as resolved.
#[must_use]
pub fn outcome_resolves(outcome: &AuditOutcome) -> bool {
    matches!(outcome, AuditOutcome::Finished { .. })
}

/// A policy-authorised invocation, plus the decision that produced it.
///
/// Returned by [`PolicyEngine::authorise_for_dispatch`]. Carrying the `Decision`
/// alongside is not redundant: the dispatcher needs the assessed risk for the audit
/// record, and re-deriving it would mean asking policy a second time about a
/// decision it has already made and already charged for.
#[derive(Debug, Clone)]
pub struct AuthorisedInvocation {
    /// The authority-bearing invocation. Only this crate can build one.
    pub invocation: CapabilityInvocation,
    /// The decision that permitted it.
    pub decision: Decision,
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_domain::actor::{AuthChannel, SystemComponent};
    use orxnud_domain::ids::{RunId, TaskId, UserId};

    const NOW: i64 = 1_000;

    fn human() -> Actor {
        Actor::Human {
            user: UserId::new("u-1"),
            via: AuthChannel::LocalInteractive,
        }
    }
    fn cap() -> CapabilityId {
        CapabilityId::new("send-message")
    }
    fn params() -> NormalizedParams {
        NormalizedParams::canonical("{\"to\":\"alice\"}")
    }
    fn request(a: DataClass, b: DataClass) -> ActionRequest {
        ActionRequest::new(
            TaskId::new("t-1"),
            RunId::new("r-1"),
            0,
            cap(),
            orxnud_domain::json!({}),
            a,
            b,
        )
    }
    /// A valid, unconsumed approval record.
    fn approval_record(actor: &Actor, target: &str, issued: i64, expires: i64) -> ApprovalRecord {
        ApprovalRecord {
            actor_label: actor.label().to_owned(),
            capability: cap().to_string(),
            target: target.to_owned(),
            params: params(),
            issued_at_ms: issued,
            expires_at_ms: expires,
            risk: RiskClass::High,
            digest: digest_for(actor, &cap(), Some(target), &params(), issued, expires),
        }
    }

    fn grant(max: DataClass, expires: i64) -> crate::policy_set::Grant {
        crate::policy_set::Grant {
            id: orxnud_domain::ids::GrantId::new("g-1"),
            granted_by: UserId::new("u-1"),
            capability: cap(),
            max_data_class: max,
            may_grant: false,
            expires_at_ms: expires,
            revoked: false,
        }
    }
    fn engine_with(
        decl: CapabilityDeclaration,
        policy: PolicySet,
        budget: BudgetLedger,
    ) -> PolicyEngine {
        let mut e = PolicyEngine::new(policy, budget, "v1");
        e.register(decl);
        e
    }
    fn ok_decl() -> CapabilityDeclaration {
        CapabilityDeclaration::new(cap(), RiskClass::Low, DataClass::Personal, false, 0)
    }
    fn low_policy() -> PolicySet {
        PolicySet::deny_all("v1").with_grant(grant(DataClass::Personal, i64::MAX))
    }

    /// ADR-0027 and control S6: approvals are **single-use**.
    ///
    /// This test was written because the bypass suite failed without it, not because
    /// the digest check looked insufficient. It turned out to be exactly that: the
    /// digest proved *which* operation was approved, and nothing proved it had not
    /// already run. A record is a value, and a value can be presented twice.
    #[test]
    fn an_approval_is_single_use() {
        let decl =
            CapabilityDeclaration::new(cap(), RiskClass::High, DataClass::Personal, false, 0);
        let mut e = engine_with(decl, low_policy(), BudgetLedger::empty().with_global(1_000));
        let approval = approval_record(&human(), "alice", 900, 1_000_000);

        // Through `authorise`, not `evaluate` + a manual `consume_approval`: the
        // property under test is that *authorising* burns the approval, and a test
        // that calls the setter itself only proves the setter works. That test
        // variant passed with the consumption line deleted -- which is how this was
        // caught.
        e.authorise(
            request(DataClass::Public, DataClass::Public),
            human(),
            InvocationContext::new("k", 1_000, "c"),
            Some("alice".into()),
            params(),
            Some(&approval),
            1_000,
        )
        .expect("the first authorisation must succeed");
        assert!(
            e.approval_is_consumed(&approval.digest),
            "authorise must consume it"
        );

        let second = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &human(),
                Some("alice"),
                &params(),
                Some(&approval),
                1_000,
            )
            .expect("evaluate");
        assert_eq!(
            second.denial().map(|r| r.code()),
            Some("approval_already_used"),
            "a replayed approval must be refused"
        );
    }

    /// The refusal must not depend on *which* invocation presents it, or a retry
    /// under a fresh context would slip through.
    #[test]
    fn a_consumed_approval_is_refused_for_any_retry() {
        let decl =
            CapabilityDeclaration::new(cap(), RiskClass::High, DataClass::Personal, false, 0);
        let mut e = engine_with(decl, low_policy(), BudgetLedger::empty().with_global(1_000));
        let approval = approval_record(&human(), "alice", 900, 1_000_000);
        e.authorise(
            request(DataClass::Public, DataClass::Public),
            human(),
            InvocationContext::new("k-1", 1_000, "c-1"),
            Some("alice".into()),
            params(),
            Some(&approval),
            1_000,
        )
        .expect("first authorisation");

        // A different step, a different deadline, a different cancellation handle --
        // none of which change the digest, because the digest is over
        // (actor, capability, target, params, issued, expires).
        for step in 0..3u32 {
            let mut req = request(DataClass::Public, DataClass::Public);
            req.step = step;
            let d = e
                .evaluate(
                    &req,
                    &human(),
                    Some("alice"),
                    &params(),
                    Some(&approval),
                    1_000,
                )
                .expect("evaluate");
            assert_eq!(
                d.denial().map(|r| r.code()),
                Some("approval_already_used"),
                "step {step} must not reuse a consumed approval"
            );
        }
    }

    #[test]
    fn an_external_actor_is_refused_before_anything_else_is_examined() {
        // The step that makes webhooks safe to accept at all.
        let e = engine_with(
            ok_decl(),
            low_policy(),
            BudgetLedger::empty().with_global(100),
        );
        let external = Actor::External {
            source: orxnud_domain::ids::ExternalSource::Unknown,
            request: RequestId::new("r"),
        };
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &external,
                Some("alice"),
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert!(d.is_denied());
        assert_eq!(d.denial().map(|r| r.code()), Some("no_authority_root"));
    }

    #[test]
    fn a_system_actor_is_refused_likewise() {
        let e = engine_with(
            ok_decl(),
            low_policy(),
            BudgetLedger::empty().with_global(100),
        );
        let sys = Actor::System {
            component: SystemComponent::Backup,
        };
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &sys,
                None,
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert!(d.is_denied());
    }

    #[test]
    fn an_unregistered_capability_is_refused() {
        // The engine registers `cap()`; this asks for a *different* one.
        let e = engine_with(
            ok_decl(),
            low_policy(),
            BudgetLedger::empty().with_global(100),
        );
        let mut req = request(DataClass::Public, DataClass::Public);
        req.capability = CapabilityId::new("never-registered");
        let d = e
            .evaluate(&req, &human(), None, &params(), None, NOW)
            .expect("evaluate");
        assert_eq!(d.denial().map(|r| r.code()), Some("unknown_capability"));
    }

    #[test]
    fn no_grant_means_denied() {
        let e = engine_with(
            ok_decl(),
            PolicySet::deny_all("v1"),
            BudgetLedger::empty().with_global(100),
        );
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &human(),
                None,
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert_eq!(d.denial().map(|r| r.code()), Some("no_grant"));
    }

    #[test]
    fn an_expired_grant_is_denied_with_its_expiry() {
        // A grant that expires at 1_000, evaluated at 2_000.
        let expiring = PolicySet::deny_all("v1").with_grant(grant(DataClass::Personal, 1_000));
        let e = engine_with(ok_decl(), expiring, BudgetLedger::empty().with_global(100));
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &human(),
                None,
                &params(),
                None,
                2_000,
            )
            .expect("evaluate");
        assert_eq!(d.denial().map(|r| r.code()), Some("grant_expired"));
    }

    #[test]
    fn data_class_beyond_the_grant_is_denied() {
        let e = engine_with(
            ok_decl(),
            low_policy(),
            BudgetLedger::empty().with_global(100),
        );
        let d = e
            .evaluate(
                &request(DataClass::Sensitive, DataClass::Sensitive),
                &human(),
                None,
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert_eq!(d.denial().map(|r| r.code()), Some("data_class_exceeded"));
    }

    #[test]
    fn data_class_beyond_the_capability_is_denied_even_with_a_grant() {
        let decl = CapabilityDeclaration::new(cap(), RiskClass::Low, DataClass::Public, false, 0);
        let e = engine_with(decl, low_policy(), BudgetLedger::empty().with_global(100));
        let d = e
            .evaluate(
                &request(DataClass::Sensitive, DataClass::Sensitive),
                &human(),
                None,
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert_eq!(d.denial().map(|r| r.code()), Some("data_class_exceeded"));
    }

    #[test]
    fn a_low_risk_permitted_action_is_allowed() {
        let e = engine_with(
            ok_decl(),
            low_policy(),
            BudgetLedger::empty().with_global(100),
        );
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &human(),
                Some("alice"),
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert!(d.is_allowed(), "expected allow, got {d:?}");
    }

    #[test]
    fn a_high_risk_action_without_approval_is_denied_as_requiring_one() {
        let decl =
            CapabilityDeclaration::new(cap(), RiskClass::High, DataClass::Personal, false, 0);
        let e = engine_with(decl, low_policy(), BudgetLedger::empty().with_global(100));
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &human(),
                Some("alice"),
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert_eq!(d.denial().map(|r| r.code()), Some("approval_required"));
    }

    #[test]
    fn a_matching_approval_gates_the_action() {
        let decl =
            CapabilityDeclaration::new(cap(), RiskClass::High, DataClass::Personal, false, 0);
        let e = engine_with(decl, low_policy(), BudgetLedger::empty().with_global(100));
        let digest = digest_for(&human(), &cap(), Some("alice"), &params(), 900, 2_000);
        let approval = ApprovalRecord {
            actor_label: "human".into(),
            capability: cap().to_string(),
            target: "alice".into(),
            params: params(),
            issued_at_ms: 900,
            expires_at_ms: 2_000,
            risk: RiskClass::High,
            digest,
        };
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &human(),
                Some("alice"),
                &params(),
                Some(&approval),
                NOW,
            )
            .expect("evaluate");
        assert!(d.is_gated(), "expected gate, got {d:?}");
        match d {
            Decision::Gate {
                required_digest, ..
            } => assert_eq!(required_digest, digest),
            other => panic!("expected gate, got {other:?}"),
        }
    }

    #[test]
    fn an_approval_for_a_different_target_is_a_digest_mismatch() {
        // THE anti-Loopjacking test: the user approved "alice"; the action is
        // for "bob". It must be refused, not silently executed.
        let decl =
            CapabilityDeclaration::new(cap(), RiskClass::High, DataClass::Personal, false, 0);
        let e = engine_with(decl, low_policy(), BudgetLedger::empty().with_global(100));
        let digest = digest_for(&human(), &cap(), Some("alice"), &params(), 900, 2_000);
        let approval = ApprovalRecord {
            actor_label: "human".into(),
            capability: cap().to_string(),
            target: "alice".into(),
            params: params(),
            issued_at_ms: 900,
            expires_at_ms: 2_000,
            risk: RiskClass::High,
            digest,
        };
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &human(),
                Some("bob"),
                &params(),
                Some(&approval),
                NOW,
            )
            .expect("evaluate");
        assert_eq!(
            d.denial().map(|r| r.code()),
            Some("approval_digest_mismatch")
        );
    }

    #[test]
    fn an_approval_for_different_params_is_a_digest_mismatch() {
        let decl =
            CapabilityDeclaration::new(cap(), RiskClass::High, DataClass::Personal, false, 0);
        let e = engine_with(decl, low_policy(), BudgetLedger::empty().with_global(100));
        let digest = digest_for(&human(), &cap(), Some("alice"), &params(), 900, 2_000);
        let approval = ApprovalRecord {
            actor_label: "human".into(),
            capability: cap().to_string(),
            target: "alice".into(),
            params: params(),
            issued_at_ms: 900,
            expires_at_ms: 2_000,
            risk: RiskClass::High,
            digest,
        };
        let other = NormalizedParams::canonical("{\"to\":\"bob\"}");
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &human(),
                Some("alice"),
                &other,
                Some(&approval),
                NOW,
            )
            .expect("evaluate");
        assert_eq!(
            d.denial().map(|r| r.code()),
            Some("approval_digest_mismatch")
        );
    }

    #[test]
    fn an_expired_approval_is_denied() {
        let decl =
            CapabilityDeclaration::new(cap(), RiskClass::High, DataClass::Personal, false, 0);
        let e = engine_with(decl, low_policy(), BudgetLedger::empty().with_global(100));
        let digest = digest_for(&human(), &cap(), Some("alice"), &params(), 900, 1_000);
        let approval = ApprovalRecord {
            actor_label: "human".into(),
            capability: cap().to_string(),
            target: "alice".into(),
            params: params(),
            issued_at_ms: 900,
            expires_at_ms: 1_000,
            risk: RiskClass::High,
            digest,
        };
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &human(),
                Some("alice"),
                &params(),
                Some(&approval),
                1_000,
            )
            .expect("evaluate");
        assert_eq!(d.denial().map(|r| r.code()), Some("approval_expired"));
    }

    #[test]
    fn a_networked_capability_needing_consent_is_denied_without_it() {
        // The grant must cover Sensitive, otherwise the *grant* check denies first
        // and the egress check is never reached -- which is itself correct
        // ordering, and is asserted separately.
        let decl = CapabilityDeclaration::new(cap(), RiskClass::Low, DataClass::Sensitive, true, 0);
        let policy = PolicySet::deny_all("v1").with_grant(grant(DataClass::Sensitive, i64::MAX));
        let e = engine_with(decl, policy, BudgetLedger::empty().with_global(100));
        let d = e
            .evaluate(
                &request(DataClass::Sensitive, DataClass::Sensitive),
                &human(),
                None,
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert_eq!(d.denial().map(|r| r.code()), Some("egress_not_consented"));
    }

    #[test]
    fn the_grant_check_precedes_the_egress_check() {
        // Ordering matters: a narrow grant denies before we ever consider
        // sending anything, which is the cheaper and safer answer.
        let decl = CapabilityDeclaration::new(cap(), RiskClass::Low, DataClass::Sensitive, true, 0);
        let e = engine_with(decl, low_policy(), BudgetLedger::empty().with_global(100));
        let d = e
            .evaluate(
                &request(DataClass::Sensitive, DataClass::Sensitive),
                &human(),
                None,
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert_eq!(d.denial().map(|r| r.code()), Some("data_class_exceeded"));
    }

    #[test]
    fn regulated_data_is_never_consented_by_standing_policy() {
        let decl = CapabilityDeclaration::new(cap(), RiskClass::Low, DataClass::Regulated, true, 0);
        let policy = PolicySet::deny_all("v1").with_grant(grant(DataClass::Regulated, i64::MAX));
        let e = engine_with(decl, policy, BudgetLedger::empty().with_global(100));
        let d = e
            .evaluate(
                &request(DataClass::Regulated, DataClass::Regulated),
                &human(),
                None,
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert!(
            d.is_denied(),
            "regulated egress must never pass standing policy: {d:?}"
        );
    }

    #[test]
    fn an_empty_budget_denies_even_a_permitted_action() {
        // Fail-closed on money: no ceiling means no spend.
        let e = engine_with(ok_decl(), low_policy(), BudgetLedger::empty());
        let mut e2 = PolicyEngine::new(low_policy(), BudgetLedger::empty(), "v1");
        e2.register(ok_decl());
        let _ = e;
        let mut req = request(DataClass::Public, DataClass::Public);
        req.capability = cap();
        let d = e2
            .authorise(
                req,
                human(),
                InvocationContext::new("k", 1000, "c"),
                None,
                params(),
                None,
                NOW,
            )
            .expect("authorise");
        assert_eq!(d.denial().map(|r| r.code()), Some("budget_exceeded"));
    }

    #[test]
    fn a_successful_authorisation_is_audited_before_the_call() {
        let mut e = PolicyEngine::new(low_policy(), BudgetLedger::empty().with_global(100), "v1");
        e.register(ok_decl());
        let d = e
            .authorise(
                request(DataClass::Public, DataClass::Public),
                human(),
                InvocationContext::new("k-1", 1000, "c"),
                Some("alice".into()),
                params(),
                None,
                NOW,
            )
            .expect("authorise");
        assert!(d.is_allowed(), "{d:?}");
        // The journal already holds the pre-call record.
        assert_eq!(e.audit().len(), 1);
        assert!(e.audit().verify().is_ok());
    }

    #[test]
    fn a_denial_is_audited_too() {
        // A policy that logs allows and not denies cannot be reviewed.
        let mut e = PolicyEngine::new(
            PolicySet::deny_all("v1"),
            BudgetLedger::empty().with_global(100),
            "v1",
        );
        e.register(ok_decl());
        let d = e
            .authorise(
                request(DataClass::Public, DataClass::Public),
                human(),
                InvocationContext::new("k-2", 1000, "c"),
                None,
                params(),
                None,
                NOW,
            )
            .expect("authorise");
        assert!(d.is_denied());
        assert!(!e.audit().is_empty(), "the denial must leave a record");
    }

    #[test]
    fn a_scheduled_actor_may_exercise_its_delegating_humans_grant() {
        // A schedule is authority captured at creation, not a bypass.
        let scheduled = Actor::Scheduled {
            schedule: orxnud_domain::ids::ScheduleId::new("s"),
            authorised_by: UserId::new("u-1"),
            task: TaskId::new("t-1"),
        };
        let e = engine_with(
            ok_decl(),
            low_policy(),
            BudgetLedger::empty().with_global(100),
        );
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &scheduled,
                Some("alice"),
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert!(
            d.is_allowed(),
            "a scheduled task within its grant should proceed: {d:?}"
        );
    }

    #[test]
    fn an_ai_actor_acts_under_its_delegating_human() {
        use orxnud_domain::actor::ModelProvenance;
        let ai = Actor::Ai {
            delegated_by: UserId::new("u-1"),
            run: orxnud_domain::ids::RunId::new("r"),
            task: TaskId::new("t-1"),
            provenance: ModelProvenance::new("m", "p", RequestId::new("q")),
        };
        let e = engine_with(
            ok_decl(),
            low_policy(),
            BudgetLedger::empty().with_global(100),
        );
        let d = e
            .evaluate(
                &request(DataClass::Public, DataClass::Public),
                &ai,
                Some("alice"),
                &params(),
                None,
                NOW,
            )
            .expect("evaluate");
        assert!(
            d.is_allowed(),
            "an AI actor within its human's grant should proceed: {d:?}"
        );
    }
}
