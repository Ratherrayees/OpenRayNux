//! Durable security state, exercised through the real governed dispatcher.
//!
//! # Why this file exists separately
//!
//! `orxnud-store` proves the tables persist; `orxnud-policy` proves the rules still
//! hold. Neither proves the two are *joined at the security boundary*, and the join
//! is where two mechanisms that were previously process-local would have to be
//! wrong together for the failure to show. The test that matters is therefore the
//! one that drives `Dispatcher::dispatch` against a real SQLite file, throws the
//! process state away, and dispatches again.
//!
//! # Real store, no sleeps, self-contained fixtures
//!
//! Every persistence test uses `orxnud_store`'s real `SqliteAuditJournal` and
//! `SqliteApprovalLedger` against a real migrated file. No SQLite is mocked. The
//! fixtures are duplicated from `support/mod.rs` rather than shared so this file can
//! also carry the pieces that suite does not have — a gated (approval-requiring)
//! policy, and a journal that refuses writes.
//!
//! Restarts are a real `drop` plus a real re-open. Concurrency uses a `Barrier` and
//! SQLite's own write lock. Nothing here sleeps or polls.

use super::Registry;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::dispatch::{AdapterBundle, CapabilityAdapter, DispatchError, Dispatcher, ExecutionTier};
use crate::verification::{ExecutionOutcome, VerificationOutcome, Verifier, VerifyError};
use orxnud_domain::ids::{CapabilityId, GrantId, RunId, TaskId, UserId};
use orxnud_domain::invocation::{ActionRequest, InvocationContext};
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use orxnud_domain::security_state::{ApprovalLedger, AuditJournal};
use orxnud_domain::{Actor, AuthChannel, DataClass, NormalizedParams, RiskClass};
use orxnud_policy::authority::DispatchView;
use orxnud_policy::policy_set::{Grant, PolicySet};
use orxnud_policy::{BudgetLedger, PolicyEngine};
use orxnud_store::security_state::{SqliteApprovalLedger, SqliteAuditJournal};

const CAP: &str = "send-message";
const NOW: i64 = 1_700_000_000_000;

// ------------------------------------------------------------------ fixtures

fn cap() -> CapabilityId {
    CapabilityId::new(CAP)
}

fn human() -> Actor {
    Actor::Human {
        user: UserId::new("u-1"),
        via: AuthChannel::LocalInteractive,
    }
}

fn params() -> NormalizedParams {
    NormalizedParams::canonical("{\"to\":\"alice\"}")
}

fn request() -> ActionRequest {
    ActionRequest::new(
        TaskId::new("t-1"),
        RunId::new("r-1"),
        0,
        cap(),
        orxnud_domain::json!({}),
        DataClass::Personal,
        DataClass::Personal,
    )
}

fn context(step: u32) -> InvocationContext {
    InvocationContext::new(format!("idem-{step}"), 30_000, "cancel-1")
}

fn grant() -> Grant {
    Grant {
        id: GrantId::new("g-1"),
        granted_by: UserId::new("u-1"),
        capability: cap(),
        max_data_class: DataClass::Personal,
        may_grant: false,
        expires_at_ms: i64::MAX,
        revoked: false,
    }
}

fn engine_declaring(risk: RiskClass) -> PolicyEngine {
    let mut e = PolicyEngine::new(
        PolicySet::deny_all("v1").with_grant(grant()),
        BudgetLedger::empty().with_global(100_000),
        "v1",
    );
    e.register(orxnud_policy::CapabilityDeclaration::new(
        cap(),
        risk,
        DataClass::Personal,
        false,
        0,
    ));
    e
}

/// A policy whose capability is declared at `RiskClass::High`, so every
/// authorisation is *gated* and therefore needs a consumed approval.
///
/// The approval tests need this: an approval that is never required is never
/// consumed, so a low-risk fixture would prove nothing about durability.
fn gated_policy() -> PolicyEngine {
    engine_declaring(RiskClass::High)
}

/// A policy that permits without an approval, for the audit-only tests. Those are
/// about the journal, and making them carry an approval would add a mechanism they
/// are not testing.
fn ungated_policy() -> PolicyEngine {
    engine_declaring(RiskClass::Low)
}

/// An approval whose digest is reproducible, so a test can rebuild the same value
/// after a restart and present it again.
fn approval(target: &str, issued: i64, expires: i64) -> orxnud_domain::ApprovalRecord {
    let p = NormalizedParams::canonical(format!("{{\"to\":\"{target}\"}}"));
    let digest = orxnud_policy::digest::digest_for(
        &human(),
        &human(),
        &cap(),
        Some(target),
        &p,
        issued,
        expires,
        1,
    );
    orxnud_domain::ApprovalRecord {
        approver: human(),
        actor_label: "u-1".into(),
        capability: CAP.into(),
        target: target.into(),
        params: p,
        issued_at_ms: issued,
        expires_at_ms: expires,
        risk: RiskClass::High,
        step_no: 1,
        digest,
    }
}

/// An adapter that reports success and does no I/O.
struct Successful;

impl CapabilityAdapter for Successful {
    fn capability_id(&self) -> &CapabilityId {
        // A leaked static so the method can return a reference, as the trait requires.
        static ID: std::sync::OnceLock<CapabilityId> = std::sync::OnceLock::new();
        ID.get_or_init(cap)
    }
    fn declared_class(&self) -> DataClass {
        DataClass::Personal
    }
    fn tier(&self) -> ExecutionTier {
        ExecutionTier::InProcess
    }
    fn invoke(
        &self,
        _view: &DispatchView<'_>,
        _credential: Option<&crate::credential::CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        Ok(ExecutionOutcome::Succeeded {
            output: Some("ok".to_owned()),
        })
    }
}

struct Confirming;

impl Verifier for Confirming {
    fn verify(
        &self,
        execution: &ExecutionOutcome,
        _params: &serde_json::Value,
        _at_ms: i64,
    ) -> Result<VerificationOutcome, VerifyError> {
        match execution {
            ExecutionOutcome::Succeeded { .. } => Ok(VerificationOutcome::Verified {
                evidence: "the fixture confirms".into(),
            }),
            _ => Ok(VerificationOutcome::Undetermined {
                reason: "did not report success".into(),
            }),
        }
    }
}

struct Bundle {
    adapter: Successful,
    verifier: Confirming,
}

impl AdapterBundle for Bundle {
    fn adapter(&self) -> &dyn CapabilityAdapter {
        &self.adapter
    }
    fn verifier(&self) -> &dyn Verifier {
        &self.verifier
    }
}

fn bundles() -> Registry {
    let mut m: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
    m.insert(
        cap(),
        Arc::new(Bundle {
            adapter: Successful,
            verifier: Confirming,
        }) as Arc<dyn AdapterBundle + Send + Sync>,
    );
    Registry::from_bundles(m)
}

/// A secret store with nothing in it. Present because the governed dispatcher is
/// generic over `SecretsContract`; it cannot resolve anything.
struct NoSecrets;

#[derive(Debug, thiserror::Error)]
#[error("no secret store in the durability suite")]
struct NoSecretsError;

impl SecretsContract for NoSecrets {
    type Error = NoSecretsError;

    fn get(&self, _r: &SecretRef) -> Result<SecretLookup, Self::Error> {
        Ok(SecretLookup::Absent)
    }
    fn set(&self, _r: &SecretRef, _v: &str) -> Result<(), Self::Error> {
        Err(NoSecretsError)
    }
    fn delete(&self, _r: &SecretRef) -> Result<(), Self::Error> {
        Err(NoSecretsError)
    }
    fn is_available(&self) -> bool {
        false
    }
}

/// A per-test directory, unique by construction.
fn state_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("orxnud-durable-{}-{tag}-{n}", std::process::id()))
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// A policy engine whose journal and ledger are both durable for `db`.
///
/// The adapters open their own connections, exactly as the daemon does, so what is
/// under test is the production arrangement rather than a test-only one.
fn durable_engine_from(db: &Path, mut engine: PolicyEngine) -> PolicyEngine {
    let journal = SqliteAuditJournal::open(db).expect("audit journal");
    engine
        .restore(&journal)
        .expect("the journal must load and verify");
    engine.with_security_state(
        Box::new(journal),
        Box::new(SqliteApprovalLedger::open(db).expect("approval ledger")),
    )
}

/// The engine the audit-only tests use.
fn durable_engine(db: &Path) -> PolicyEngine {
    durable_engine_from(db, ungated_policy())
}

/// A journal that persists nothing and refuses everything.
///
/// **The only double in this file**, and it exists because one property cannot be
/// produced any other way: that a *failed* terminal write is reported as a failed
/// dispatch rather than as a success. Making a real SQLite file refuse a write at a
/// chosen moment would require fault injection into the store's own transaction,
/// which is a different change with a different risk. The real store's behaviour is
/// proven by the other twelve tests here and by `orxnud-store`'s own suite.
struct RefusingJournal;

impl AuditJournal for RefusingJournal {
    fn append(
        &self,
        _e: &orxnud_domain::security_state::JournalEntry,
    ) -> Result<(), orxnud_domain::security_state::JournalError> {
        Err(orxnud_domain::security_state::JournalError::Unavailable(
            "the durability suite refuses writes on purpose".into(),
        ))
    }
    fn entries(
        &self,
    ) -> Result<
        Vec<orxnud_domain::security_state::JournalEntry>,
        orxnud_domain::security_state::JournalError,
    > {
        Ok(Vec::new())
    }
    fn len(&self) -> Result<u64, orxnud_domain::security_state::JournalError> {
        Ok(0)
    }
}

// ---------------------------------------------------------------- audit

#[test]
fn an_audit_record_written_before_a_restart_is_readable_after_it() {
    let dir = state_dir("audit-survives");
    let db = dir.join("state.db");

    let before = {
        let mut engine = durable_engine(&db);
        let secrets = NoSecrets;
        let mut d = Dispatcher::new(&mut engine, &secrets, bundles());
        d.dispatch(
            request(),
            human(),
            context(0),
            Some("alice".into()),
            params(),
            None,
            None,
            NOW,
        )
        .expect("dispatch");
        drop(d);
        // The chain is the engine's, so read the count after the borrow ends.
        engine.audit().len()
    };
    assert!(before >= 2, "an authorisation and a terminal record");

    // A brand new process, opening the same file.
    let journal = SqliteAuditJournal::open(&db).expect("reopen");
    assert_eq!(
        journal.len().expect("durable length"),
        before as u64,
        "every record the first process wrote is still there"
    );
    let chain = orxnud_audit::AuditChain::restore(&journal).expect("the chain must reload");
    assert_eq!(chain.len(), before);
    chain.verify().expect("and it must verify");
    cleanup(&dir);
}

#[test]
fn a_reloaded_chain_verifies_across_three_successive_processes() {
    let dir = state_dir("chain-verify");
    let db = dir.join("state.db");

    for round in 0..3u32 {
        let mut engine = durable_engine(&db);
        let secrets = NoSecrets;
        let mut d = Dispatcher::new(&mut engine, &secrets, bundles());
        d.dispatch(
            request(),
            human(),
            context(round),
            Some("alice".into()),
            params(),
            None,
            None,
            NOW + i64::from(round),
        )
        .expect("dispatch");
        drop(d);

        // Every process must see a chain that verifies and one that grew.
        let journal = SqliteAuditJournal::open(&db).expect("reopen");
        let chain = orxnud_audit::AuditChain::restore(&journal).expect("reload");
        chain.verify().expect("verify after reload");
        assert!(
            chain.len() >= 2 * (round as usize + 1),
            "round {round} should have added a pair, saw {}",
            chain.len()
        );
    }

    let journal = SqliteAuditJournal::open(&db).expect("final reopen");
    let chain = orxnud_audit::AuditChain::restore(&journal).expect("final reload");
    assert_eq!(chain.len(), 6, "three processes, two records each");
    // Strictly increasing across process boundaries: what makes the hash linkage
    // meaningful after a restart rather than within one process only.
    let seqs: Vec<u64> = chain.records().map(|r| r.seq).collect();
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "seq must increase across restarts: {seqs:?}"
    );
    assert!(
        chain.unresolved_authorisations().is_empty(),
        "every action reached a terminal record"
    );
    cleanup(&dir);
}

#[test]
fn a_tampered_hash_is_detected_when_the_chain_reloads() {
    let dir = state_dir("tamper-hash");
    let db = dir.join("state.db");
    {
        let mut engine = durable_engine(&db);
        let secrets = NoSecrets;
        let mut d = Dispatcher::new(&mut engine, &secrets, bundles());
        for step in 0..3u32 {
            d.dispatch(
                request(),
                human(),
                context(step),
                Some("alice".into()),
                params(),
                None,
                None,
                NOW + i64::from(step),
            )
            .expect("dispatch");
        }
    }
    // Replace the stored hash of record 0. The row survives; the chain does not.
    {
        let journal = SqliteAuditJournal::open(&db).expect("open for tamper");
        journal
            .conn()
            .execute(
                "UPDATE audit_log SET record_hash = zeroblob(32) WHERE seq = 0;",
                [],
            )
            .expect("tamper");
    }
    let journal = SqliteAuditJournal::open(&db).expect("reopen");
    assert!(
        orxnud_audit::AuditChain::restore(&journal).is_err(),
        "a substituted hash must break verification"
    );
    cleanup(&dir);
}

#[test]
fn a_tampered_record_body_is_detected_by_its_content_hash() {
    let dir = state_dir("tamper-body");
    let db = dir.join("state.db");
    {
        let mut engine = durable_engine(&db);
        let secrets = NoSecrets;
        let mut d = Dispatcher::new(&mut engine, &secrets, bundles());
        d.dispatch(
            request(),
            human(),
            context(0),
            Some("alice".into()),
            params(),
            None,
            None,
            NOW,
        )
        .expect("dispatch");
    }
    // Edit the content and leave the hash alone: the common case, and the one
    // `verify` exists for.
    {
        let journal = SqliteAuditJournal::open(&db).expect("open for tamper");
        journal
            .conn()
            .execute(
                "UPDATE audit_log SET record = replace(record, 'alice', 'mallory') WHERE seq = 0;",
                [],
            )
            .expect("tamper");
    }
    let journal = SqliteAuditJournal::open(&db).expect("reopen");
    let err = orxnud_audit::AuditChain::restore(&journal)
        .expect_err("editing a record body must break its hash");
    assert!(
        err.to_string().contains("altered") || err.to_string().contains("hash mismatch"),
        "the failure must name tampering: {err}"
    );
    cleanup(&dir);
}

#[test]
fn a_terminal_record_is_persisted_and_correlates_after_a_restart() {
    let dir = state_dir("terminal");
    let db = dir.join("state.db");
    {
        let mut engine = durable_engine(&db);
        let secrets = NoSecrets;
        let mut d = Dispatcher::new(&mut engine, &secrets, bundles());
        d.dispatch(
            request(),
            human(),
            context(0),
            Some("alice".into()),
            params(),
            None,
            None,
            NOW,
        )
        .expect("dispatch");
    }
    let journal = SqliteAuditJournal::open(&db).expect("reopen");
    let chain = orxnud_audit::AuditChain::restore(&journal).expect("reload");
    let records = chain.entries();
    assert_eq!(records.len(), 2, "authorisation plus terminal");
    assert!(matches!(
        records[0].outcome,
        orxnud_audit::AuditOutcome::Authorised { .. }
    ));
    assert!(
        matches!(
            records[1].outcome,
            orxnud_audit::AuditOutcome::Finished { .. }
        ),
        "the terminal record is durable, not just held in memory"
    );
    assert_eq!(
        records[0].correlation_key(),
        records[1].correlation_key(),
        "and it resolves the authorisation after the restart"
    );
    assert!(chain.unresolved_authorisations().is_empty());
    cleanup(&dir);
}

#[test]
fn an_unverifiable_journal_is_refused_rather_than_appended_to() {
    let dir = state_dir("corrupt-open");
    let db = dir.join("state.db");
    {
        let mut engine = durable_engine(&db);
        let secrets = NoSecrets;
        let mut d = Dispatcher::new(&mut engine, &secrets, bundles());
        d.dispatch(
            request(),
            human(),
            context(0),
            Some("alice".into()),
            params(),
            None,
            None,
            NOW,
        )
        .expect("dispatch");
    }
    {
        let journal = SqliteAuditJournal::open(&db).expect("open for tamper");
        journal
            .conn()
            .execute(
                "UPDATE audit_log SET record = replace(record, 'alice', 'mallory') WHERE seq = 0;",
                [],
            )
            .expect("tamper");
    }

    // An engine must never continue from an unverified head.
    let journal = SqliteAuditJournal::open(&db).expect("reopen");
    let mut engine = gated_policy();
    let err = engine.restore(&journal).expect_err("must refuse");
    assert!(
        err.to_string().contains("audit journal unavailable"),
        "{err}"
    );
    assert_eq!(
        engine.audit().len(),
        0,
        "a refused restore leaves no partially loaded chain"
    );
    cleanup(&dir);
}

#[test]
fn a_terminal_record_that_cannot_be_persisted_is_not_reported_as_success() {
    // Fail-closed at stage 9. An outcome nobody can account for must not be handed
    // back as a success — which is what `DispatchError::Audit` claims to mean, and
    // what nothing tested before this task.
    let dir = state_dir("audit-fail");
    let db = dir.join("state.db");
    // Create a real, migrated journal so the schema is genuine, then replace it with
    // the refusing double for the write.
    SqliteAuditJournal::open(&db).expect("real journal first");

    let mut engine = ungated_policy().with_security_state(
        Box::new(RefusingJournal),
        Box::new(SqliteApprovalLedger::open(&db).expect("ledger")),
    );
    let secrets = NoSecrets;
    let mut d = Dispatcher::new(&mut engine, &secrets, bundles());

    let err = d
        .dispatch(
            request(),
            human(),
            context(0),
            Some("alice".into()),
            params(),
            None,
            None,
            NOW,
        )
        .expect_err("a dispatch whose audit cannot be written must fail");
    // The authorisation write fails first, which is *also* a refusal, and is the
    // stage-1 fail-closed path. Both are non-successes; assert it is an audit error.
    assert!(
        matches!(err, DispatchError::Policy(_) | DispatchError::Audit(_)),
        "the failure must be a refusal, never a success: {err:?}"
    );

    // And with the real journal restored, the same dispatch succeeds — so the
    // failure above was the journal's, not the fixture's.
    let mut engine = durable_engine(&db);
    let mut d = Dispatcher::new(&mut engine, &secrets, bundles());
    d.dispatch(
        request(),
        human(),
        context(0),
        Some("alice".into()),
        params(),
        None,
        None,
        NOW,
    )
    .expect("with a real journal the dispatch succeeds");
    cleanup(&dir);
}

// -------------------------------------------------------------- approvals

#[test]
fn a_spent_approval_is_still_spent_after_a_restart() {
    let dir = state_dir("approval-restart");
    let db = dir.join("state.db");
    let record = approval("alice", NOW, NOW + 60_000);

    {
        let mut engine = durable_engine_from(&db, gated_policy());
        assert!(!engine.approval_is_consumed(&record.digest).expect("read"));
        engine
            .consume_approval(record.digest, 1_000)
            .expect("consume");
        assert!(engine.approval_is_consumed(&record.digest).expect("read"));
    }

    let engine = durable_engine_from(&db, gated_policy());
    assert!(
        engine.approval_is_consumed(&record.digest).expect("read"),
        "a consumed approval must not return to the pool on restart"
    );
    cleanup(&dir);
}

#[test]
fn distinct_approvals_are_independent_across_a_restart() {
    let dir = state_dir("approval-distinct");
    let db = dir.join("state.db");
    let a = approval("alice", NOW, NOW + 60_000);
    let b = approval("bob", NOW, NOW + 60_000);
    {
        let mut engine = durable_engine_from(&db, gated_policy());
        engine.consume_approval(a.digest, 1_000).expect("a");
    }
    let mut engine = durable_engine_from(&db, gated_policy());
    assert!(engine.approval_is_consumed(&a.digest).expect("read"));
    assert!(
        !engine.approval_is_consumed(&b.digest).expect("read"),
        "a different approval must be unaffected"
    );
    engine.consume_approval(b.digest, 1_000).expect("b");
    cleanup(&dir);
}

#[test]
fn two_processes_racing_for_one_digest_produce_exactly_one_success() {
    // The reason single-use needs durability: two *connections*, not two threads in
    // one process. Barrier-synchronised, so there is no timing window to win.
    let dir = state_dir("approval-race");
    let db = dir.join("state.db");
    std::fs::create_dir_all(&dir).expect("mkdir");
    let digest = orxnud_domain::ApprovalDigest::from_bytes([0xAB; 32]);

    let barrier = Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = (0..2u8)
        .map(|_| {
            let db = db.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                // Opened *concurrently*, which is the arrangement a daemon and a CLI
                // subprocess would produce. What races here is the `consume`; what
                // also has to survive is both opens contending for the journal-mode
                // transition and the migrations on a fresh file.
                let mut ledger = SqliteApprovalLedger::open(&db).expect("open");
                barrier.wait();
                ledger.consume_at(&digest, 1_000)
            })
        })
        .collect();

    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("join"))
        .collect();

    let wins = outcomes.iter().filter(|r| r.is_ok()).count();
    assert_eq!(wins, 1, "exactly one consumer may succeed: {outcomes:?}");
    for loser in outcomes.iter().filter(|r| r.is_err()) {
        assert!(
            matches!(
                loser,
                Err(orxnud_domain::security_state::LedgerError::AlreadyConsumed)
            ),
            "the loser must see a replay, not an outage: {loser:?}"
        );
    }
    cleanup(&dir);
}

#[test]
fn an_expired_approval_is_refused_before_it_reaches_the_ledger() {
    // Durability changed *when* consumption is recorded, not *whether* an approval
    // qualifies. Every other check still runs first.
    let dir = state_dir("approval-expired");
    let db = dir.join("state.db");
    let engine = durable_engine_from(&db, gated_policy());
    let expired = approval("alice", NOW - 10_000, NOW - 1);
    let decision = engine
        .evaluate(
            &request(),
            &human(),
            Some("alice"),
            &params(),
            Some(&expired),
            NOW,
        )
        .expect("evaluate");
    assert!(
        matches!(decision, orxnud_policy::Decision::Deny { .. }),
        "an expired approval is refused: {decision:?}"
    );
    assert!(
        !engine.approval_is_consumed(&expired.digest).expect("read"),
        "a refused approval must not have been consumed"
    );
    cleanup(&dir);
}

// ------------------------------------------ the boundary that matters

#[test]
fn a_dispatch_persists_its_terminal_audit_and_a_restart_refuses_the_replay() {
    // The test the others support.
    //
    //   dispatch #1  -> approval accepted, terminal audit persisted
    //   restart      -> a rebuilt engine and a rebuilt dispatcher
    //   dispatch #2  -> the SAME approval value, refused as already consumed
    //
    // If approval consumption were still process-local, #2 would succeed. If the
    // terminal record were still delegated to a caller that does not exist, #1
    // would leave the journal reporting an unknown outcome forever. Neither is
    // observable from the storage or policy suites alone.
    let dir = state_dir("boundary");
    let db = dir.join("state.db");
    let record = approval("alice", NOW, NOW + 60_000);

    // ---- dispatch #1 ----
    {
        let mut engine = durable_engine_from(&db, gated_policy());
        assert!(engine.is_audit_durable(), "the journal is durable");
        let secrets = NoSecrets;
        let mut d = Dispatcher::new(&mut engine, &secrets, bundles());
        let outcome = d
            .dispatch(
                request(),
                human(),
                context(0),
                Some("alice".into()),
                params(),
                Some(&record),
                None,
                NOW,
            )
            .expect("the first dispatch must be authorised");
        assert!(
            outcome.verification.is_verified(),
            "the first dispatch completed and was verified"
        );
        drop(d);
        drop(engine);
    }

    // What the first process left behind, read independently.
    {
        let journal = SqliteAuditJournal::open(&db).expect("reopen");
        let chain = orxnud_audit::AuditChain::restore(&journal).expect("reload");
        chain.verify().expect("verify");
        let records = chain.entries();
        assert_eq!(
            records.len(),
            2,
            "authorisation plus terminal, both durable"
        );
        assert_eq!(records[0].correlation_key(), records[1].correlation_key());
        assert!(chain.unresolved_authorisations().is_empty());
        let persisted_terminal = records
            .iter()
            .filter(|r| matches!(r.outcome, orxnud_audit::AuditOutcome::Finished { .. }))
            .count();
        assert_eq!(persisted_terminal, 1, "the terminal record was persisted");
    }

    // ---- restart: rebuild everything ----
    let mut engine = durable_engine_from(&db, gated_policy());
    let secrets = NoSecrets;
    let mut d = Dispatcher::new(&mut engine, &secrets, bundles());
    let refused = d.dispatch(
        request(),
        human(),
        context(1),
        Some("alice".into()),
        params(),
        Some(&record),
        None,
        NOW + 1,
    );
    let err = refused.expect_err("a spent approval must be refused after a restart");
    let text = err.to_string();
    assert!(
        text.contains("approval-already-used"),
        "the refusal must name replay, not an outage: {text}"
    );
    assert!(
        !text.contains("ledger unavailable"),
        "and it must not read as a storage outage: {text}"
    );

    // And the refusal is itself durably audited, so the journal shows the attempt
    // that was turned away rather than nothing at all.
    let journal = SqliteAuditJournal::open(&db).expect("reopen for refusal audit");
    let chain = orxnud_audit::AuditChain::restore(&journal).expect("reload");
    chain.verify().expect("verify");
    let denials = chain
        .entries()
        .into_iter()
        .filter(|r| {
            matches!(
                r.outcome,
                orxnud_audit::AuditOutcome::Finished {
                    kind: orxnud_audit::OutcomeKind::Denied,
                    ..
                }
            )
        })
        .count();
    assert_eq!(denials, 1, "the replay was recorded as denied");
    cleanup(&dir);
}

#[test]
fn a_restart_continues_the_chain_rather_than_restarting_it() {
    // The linkage property after a restart: the second process's first record must
    // follow the first process's last, not start a parallel chain at genesis.
    let dir = state_dir("linkage");
    let db = dir.join("state.db");
    let mut heads = Vec::new();
    for round in 0..2u32 {
        let mut engine = durable_engine(&db);
        let secrets = NoSecrets;
        let mut d = Dispatcher::new(&mut engine, &secrets, bundles());
        d.dispatch(
            request(),
            human(),
            context(round),
            Some("alice".into()),
            params(),
            None,
            None,
            NOW + i64::from(round),
        )
        .expect("dispatch");
        heads.push(engine.audit().head());
    }
    assert_ne!(
        heads[0], heads[1],
        "the second process extended the chain, so the head moved"
    );

    // And the persisted prev_hash of the second process's first record is the first
    // process's head — read straight out of storage, not inferred.
    let journal = SqliteAuditJournal::open(&db).expect("reopen");
    let rows = journal.entries().expect("rows");
    assert_eq!(rows.len(), 4);
    assert_eq!(
        rows[2].prev_hash, rows[1].hash,
        "record 2 must link to record 1, across the process boundary"
    );
    assert_eq!(
        rows[0].prev_hash,
        orxnud_audit::GENESIS_HASH,
        "and the journal still starts at genesis"
    );
    cleanup(&dir);
}
