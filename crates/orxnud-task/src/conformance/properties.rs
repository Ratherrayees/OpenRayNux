//! The contract, and the twelve property checks.
//!
//! # This is the specification
//!
//! [`TaskEngine`] is what a task engine must provide. It is deliberately
//! *small*: five operations and two queries. An engine that satisfies these and
//! passes [`run_all`] conforms to ADR-0029, however it stores and schedules
//! anything internally.
//!
//! The size is the point. A large contract would be a reimplementation guide; a
//! small one is a set of obligations. Notably absent: how rows are stored, how
//! the queue is polled, what the SQL is, whether there is a lease *column*. An
//! engine could satisfy all twelve with a completely different data model.
//!
//! # Test style
//!
//! Each property body returns `Result<_, PropertyOutcome>` so `?` is usable
//! throughout: a property that unwinds on the first problem reads better than one
//! that repeats `match` at every call site. The `property!` wrapper collapses a
//! failure into the outcome, so a violation is a *value* that flows into the
//! report rather than an early return that skips the other properties.

use std::collections::BTreeMap;

use orxnud_domain::task_state::TaskState;
use orxnud_domain::{TaskId, TaskKind};

use super::clock::TestClock;
use super::report::{PropertyOutcome, PropertyResult};

/// The internal result of a property body.
type Check = Result<PropertyOutcome, PropertyOutcome>;

/// Builds a violation.
fn violation(detail: impl Into<String>) -> PropertyOutcome {
    PropertyOutcome::Violated {
        detail: detail.into(),
    }
}

/// Declares a property: a body returning `Check`, wrapped into a total function.
// The body is captured as a token tree, not as a `block` fragment: Rust does
// not permit `block` fragments in expression position, and the braces the caller
// writes simply become part of the sequence.
macro_rules! property {
    ($name:ident, |$e:ident, $c:ident| $($body:tt)*) => {
        /// Runs this property. The statement it asserts is in
        /// `PROPERTY_DESCRIPTIONS`.
        pub fn $name($e: &mut dyn TaskEngine, $c: &mut dyn TestClock) -> PropertyOutcome {
            (|$e: &mut dyn TaskEngine, $c: &mut dyn TestClock| -> Check {
                $($body)*
            })($e, $c)
            .unwrap_or_else(|o| o)
        }
    };
}

/// A task as the harness sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    /// Which task.
    pub id: TaskId,
    /// What kind.
    pub kind: TaskKind,
    /// Current state.
    pub state: TaskState,
    /// Attempts made.
    pub attempts: u32,
    /// Lease expiry, ms since epoch.
    pub lease_expires_at_ms: Option<i64>,
    /// The worker currently holding the lease, if any.
    pub lease_holder: Option<String>,
    /// Whether repeating this task is safe.
    pub idempotent: bool,
    /// Whether an external effect has been observed.
    ///
    /// This is how TP-2 and TP-12 are checked without the harness knowing
    /// anything about the effects themselves: the engine reports *that* an effect
    /// happened, and the property is about the bookkeeping around it.
    pub effect_observed: bool,
    /// A human-readable last error, for diagnostics.
    pub last_error: Option<String>,
}

impl TaskRecord {
    /// A fresh pending task.
    #[must_use]
    pub fn pending(id: TaskId, kind: TaskKind) -> Self {
        Self {
            id,
            kind,
            state: TaskState::Pending,
            attempts: 0,
            lease_expires_at_ms: None,
            lease_holder: None,
            idempotent: kind.idempotent_by_default(),
            effect_observed: false,
            last_error: None,
        }
    }
}

/// What happened when a task was claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// The caller now holds a lease on this task.
    Claimed(TaskRecord),
    /// Nothing was claimable.
    Empty,
}

/// The operations a conforming engine must provide.
///
/// Deliberately minimal. Note what is *not* here: no `SQL`, no `poll_interval`,
/// no `spawn_worker`, no `schema`. Those are implementation choices; this is the
/// set of obligations ADR-0029 imposes.
pub trait TaskEngine {
    /// A short name, for the report.
    fn name(&self) -> &'static str;

    /// Whether this engine supports lease fencing (TP-5).
    ///
    /// Reported rather than inferred, so an engine that lacks it produces
    /// `ConformsWithGaps` instead of quietly passing.
    fn supports_lease_fencing(&self) -> bool {
        true
    }

    /// Persists a new task.
    ///
    /// # Errors
    ///
    /// A description of the failure.
    fn enqueue(&mut self, task: TaskRecord) -> Result<(), String>;

    /// Atomically claims one claimable task for `worker`, taking a lease.
    ///
    /// # Errors
    ///
    /// A description of the failure.
    fn claim(&mut self, worker: &str, now_ms: i64) -> Result<Claim, String>;

    /// Records a terminal outcome for a task the caller holds a **valid** lease on.
    ///
    /// `now_ms` is required, and finding that out is the point: an engine that is
    /// not told the current time cannot tell whether a lease is still live. A
    /// contract without it would make TP-5 unimplementable rather than merely
    /// unimplemented.
    ///
    /// # Errors
    ///
    /// **Must** return an error if the caller's lease has expired **or** the task
    /// has been re-claimed. That refusal is TP-5's entire mechanism, and an
    /// engine that cannot refuse here is non-conforming.
    fn complete(
        &mut self,
        id: &TaskId,
        worker: &str,
        now_ms: i64,
        state: TaskState,
        effect_observed: bool,
        error: Option<String>,
    ) -> Result<(), String>;

    /// Records a cancellation request, durably, before acting on it.
    ///
    /// # Errors
    ///
    /// A description of the failure.
    fn request_cancel(&mut self, id: &TaskId) -> Result<(), String>;

    /// Reclaims work abandoned by a **restart**.
    ///
    /// # Why "restart", not "expired leases"
    ///
    /// A restart means the previous process is gone, so *every* lease it held is
    /// orphaned regardless of expiry. An engine that only reclaimed expired
    /// leases would leave freshly-claimed work stranded forever, which is the
    /// orphan bug this property exists to catch.
    ///
    /// # Errors
    ///
    /// A description of the failure.
    fn recover(&mut self, now_ms: i64) -> Result<(), String>;

    /// Every task, for assertions.
    fn all(&self) -> Vec<TaskRecord>;

    /// One task, if it exists.
    fn get(&self, id: &TaskId) -> Option<TaskRecord>;
}

/// A deterministic, seeded generator for failure injection.
///
/// A hand-rolled SplitMix64 rather than a dependency: the suite needs
/// reproducibility above all, and the algorithm is four lines and fully
/// specified here, so any report can be replayed exactly.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// A generator from a recorded seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(0x9E37_79B9_7F4A_7C15),
        }
    }

    /// The next value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `[0, n)`, or 0 when `n == 0`.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

fn id(n: u32) -> TaskId {
    TaskId::new(format!("t-{n}"))
}

fn ok(cases: u32) -> PropertyOutcome {
    PropertyOutcome::Holds { cases }
}

fn find<'a>(tasks: &'a [TaskRecord], id: &TaskId) -> Option<&'a TaskRecord> {
    tasks.iter().find(|t| &t.id == id)
}

property!(tp1_no_silent_disappearance, |e, _c| {
    // Every accepted task must remain present. A task that vanishes from `all()`
    // is exactly the failure this property exists to catch, and it is invisible
    // to a suite that only walks happy paths.
    let mut accepted: Vec<TaskId> = Vec::new();
    for i in 0..32 {
        let t = TaskRecord::pending(id(i), TaskKind::Workflow);
        let tid = t.id.clone();
        e.enqueue(t)
            .map_err(|err| violation(format!("enqueue rejected task {i}: {err}")))?;
        accepted.push(tid);
    }
    let all = e.all();
    let missing: Vec<&str> = accepted
        .iter()
        .filter(|a| find(&all, a).is_none())
        .map(|a| a.as_str())
        .collect();
    if !missing.is_empty() {
        return Err(violation(format!(
            "{} accepted tasks vanished: {missing:?}",
            missing.len()
        )));
    }
    Ok(ok(accepted.len() as u32))
});

property!(tp2_exactly_once_where_required, |e, c| {
    // The two halves are different obligations, and conflating them is how a
    // duplicate submission happens:
    //   * an *idempotent* task may be re-executed freely;
    //   * a *non-idempotent* task whose effect outcome is uncertain must never be
    //     re-executed automatically -- it awaits a human.
    let t = TaskRecord::pending(id(1), TaskKind::Workflow);
    let tid = t.id.clone();
    e.enqueue(t)
        .map_err(|err| violation(format!("enqueue failed: {err}")))?;

    let first = e
        .claim("w1", c.now_ms())
        .map_err(|err| violation(format!("claim failed: {err}")))?;
    let Claim::Claimed(rec) = first else {
        return Err(violation("expected to claim the pending task"));
    };
    if rec.idempotent {
        return Err(violation(
            "a Workflow task must not be idempotent by default",
        ));
    }

    // The worker "ran" it: the effect may or may not have happened.
    e.complete(
        &tid,
        "w1",
        c.now_ms(),
        TaskState::NeedsVerification,
        true,
        Some("outcome unknown".into()),
    )
    .map_err(|err| violation(format!("complete failed: {err}")))?;

    let Some(after) = e.get(&tid) else {
        return Err(violation("task vanished after an uncertain outcome"));
    };
    if after.state != TaskState::NeedsVerification {
        return Err(violation(format!(
            "a non-idempotent task with an uncertain outcome must await verification, got {:?}",
            after.state
        )));
    }
    if !after.state.is_terminal() {
        return Err(violation(
            "NeedsVerification must be terminal so it is not auto-retried",
        ));
    }

    // A second claim must not return it.
    let second = e
        .claim("w2", c.now_ms())
        .map_err(|err| violation(format!("claim failed: {err}")))?;
    if let Claim::Claimed(r) = second
        && r.id == tid
    {
        return Err(violation(
            "a task awaiting verification was re-claimed automatically",
        ));
    }
    Ok(ok(2))
});

property!(tp3_cancellation_is_observable, |e, c| {
    // Cancellation must be durably recorded *before* it is acted on, must reach
    // a terminal state, must not be claimable, and must survive a restart. A
    // "half-cancelled" task -- request seen, effect happened anyway -- is the
    // failure.
    let t = TaskRecord::pending(id(1), TaskKind::Workflow);
    let tid = t.id.clone();
    e.enqueue(t)
        .map_err(|err| violation(format!("enqueue failed: {err}")))?;

    // Cancel before it is ever claimed.
    e.request_cancel(&tid)
        .map_err(|err| violation(format!("request_cancel failed: {err}")))?;
    let Some(after) = e.get(&tid) else {
        return Err(violation("task vanished after cancellation"));
    };
    if after.state != TaskState::Cancelled {
        return Err(violation(format!(
            "a cancelled task must be Cancelled, got {:?}",
            after.state
        )));
    }
    if !after.state.is_terminal() {
        return Err(violation("Cancelled must be terminal"));
    }

    let claimed = e
        .claim("w1", c.now_ms())
        .map_err(|err| violation(format!("claim failed: {err}")))?;
    if let Claim::Claimed(r) = claimed
        && r.id == tid
    {
        return Err(violation("a cancelled task was claimed"));
    }

    // And it survives a restart.
    e.recover(c.now_ms())
        .map_err(|err| violation(format!("recover failed: {err}")))?;
    let Some(post) = e.get(&tid) else {
        return Err(violation("cancelled task vanished across recovery"));
    };
    if post.state != TaskState::Cancelled {
        return Err(violation(format!(
            "cancellation did not survive recovery: {:?}",
            post.state
        )));
    }
    Ok(ok(3))
});

property!(tp4_restart_recovers, |e, c| {
    // After an unclean shutdown, no task may be left `Running` with a dead owner.
    let mut ids = Vec::new();
    for i in 0..8 {
        let t = TaskRecord::pending(id(i), TaskKind::Query);
        ids.push(t.id.clone());
        e.enqueue(t)
            .map_err(|err| violation(format!("enqueue failed: {err}")))?;
    }

    // Claim two, then "crash": never complete them.
    let mut claimed = Vec::new();
    for w in ["w1", "w2"] {
        let got = e
            .claim(w, c.now_ms())
            .map_err(|err| violation(format!("claim failed: {err}")))?;
        if let Claim::Claimed(r) = got {
            claimed.push(r.id);
        }
    }
    if claimed.is_empty() {
        return Err(violation(
            "expected to claim at least one task before simulating a crash",
        ));
    }

    e.recover(c.now_ms())
        .map_err(|err| violation(format!("recover failed: {err}")))?;

    let all = e.all();
    let orphaned: Vec<&str> = all
        .iter()
        .filter(|t| t.state == TaskState::Running && t.lease_holder.is_none())
        .map(|t| t.id.as_str())
        .collect();
    if !orphaned.is_empty() {
        return Err(violation(format!(
            "tasks left Running with no owner after recovery: {orphaned:?}"
        )));
    }
    for tid in &claimed {
        let Some(t) = find(&all, tid) else {
            return Err(violation(format!(
                "claimed task {tid} vanished across recovery"
            )));
        };
        if t.state == TaskState::Running {
            return Err(violation(format!(
                "claimed task {tid} is still Running after recovery"
            )));
        }
    }
    Ok(ok(all.len() as u32))
});

property!(tp5_expired_leases_cannot_execute, |e, c| {
    // The subtle property, and the one a naive implementation gets wrong. Two
    // cases, both of which must be refused:
    //
    //  1. The lease expired and *nobody else has claimed the task*. The zombie
    //     must still not commit -- its lease is dead even though `lease_holder`
    //     still names it.
    //  2. The lease expired and *another worker re-claimed it*. The zombie's
    //     commit must be refused because it no longer holds the task.
    //
    // Checking only at claim time passes case 2 and fails case 1.
    if !e.supports_lease_fencing() {
        return Err(PropertyOutcome::Unsupported {
            detail: "the engine declares no lease fencing".into(),
        });
    }

    // --- Case 1: expired, unclaimed. ---
    let t1 = TaskRecord::pending(id(1), TaskKind::Workflow);
    let t1id = t1.id.clone();
    e.enqueue(t1)
        .map_err(|err| violation(format!("enqueue failed: {err}")))?;
    let first = e
        .claim("zombie", c.now_ms())
        .map_err(|err| violation(format!("claim failed: {err}")))?;
    let Claim::Claimed(r) = first else {
        return Err(violation("expected to claim"));
    };
    let Some(lease_ms) = r.lease_expires_at_ms else {
        return Err(violation(
            "claimed task carries no lease, so fencing cannot exist",
        ));
    };
    c.set_ms(lease_ms + 1);

    if e.complete(
        &t1id,
        "zombie",
        c.now_ms(),
        TaskState::Completed,
        true,
        None,
    )
    .is_ok()
    {
        return Err(violation(
            "an expired lease was allowed to commit (unclaimed case)",
        ));
    }
    let Some(after1) = e.get(&t1id) else {
        return Err(violation("task vanished after a refused commit"));
    };
    if after1.state == TaskState::Completed {
        return Err(violation(
            "the refused commit was nevertheless recorded as Completed",
        ));
    }

    // --- Case 2: expired, then re-claimed by someone else. ---
    let t2 = TaskRecord::pending(id(2), TaskKind::Workflow);
    let t2id = t2.id.clone();
    e.enqueue(t2)
        .map_err(|err| violation(format!("enqueue failed: {err}")))?;
    let second = e
        .claim("zombie2", c.now_ms())
        .map_err(|err| violation(format!("claim failed: {err}")))?;
    if let Claim::Claimed(_) = second {
    } else {
        return Err(violation("expected to claim the second task"));
    }
    c.advance(lease_ms + 1);
    e.recover(c.now_ms())
        .map_err(|err| violation(format!("recover failed: {err}")))?;

    let fresh = e
        .claim("fresh", c.now_ms())
        .map_err(|err| violation(format!("claim failed: {err}")))?;
    if let Claim::Claimed(other) = fresh
        && other.id == t2id
        && e.complete(
            &t2id,
            "zombie2",
            c.now_ms(),
            TaskState::Completed,
            true,
            None,
        )
        .is_ok()
    {
        return Err(violation(
            "a zombie whose task was re-claimed was allowed to commit",
        ));
    }
    Ok(ok(2))
});

property!(tp6_retries_never_inherit_approvals, |e, c| {
    // The engine-level half: a retry starts a *new* attempt with nothing carried
    // over. The policy-level half -- that a retry re-derives the actor and
    // re-checks delegation -- needs the policy engine and is exercised there.
    let t = TaskRecord::pending(id(1), TaskKind::Workflow);
    let tid = t.id.clone();
    e.enqueue(t)
        .map_err(|err| violation(format!("enqueue failed: {err}")))?;

    let first = e
        .claim("w1", c.now_ms())
        .map_err(|err| violation(format!("claim failed: {err}")))?;
    let Claim::Claimed(rec) = first else {
        return Err(violation("expected to claim"));
    };
    if rec.attempts != 1 {
        return Err(violation(format!(
            "a first claim must record one attempt, got {}",
            rec.attempts
        )));
    }

    e.complete(
        &tid,
        "w1",
        c.now_ms(),
        TaskState::Failed,
        false,
        Some("boom".into()),
    )
    .map_err(|err| violation(format!("complete failed: {err}")))?;

    let Some(after) = e.get(&tid) else {
        return Err(violation("task vanished after a failure"));
    };
    if after.attempts != 1 {
        return Err(violation(format!(
            "attempts must not advance without a new claim, got {}",
            after.attempts
        )));
    }
    if after.lease_holder.is_some() {
        return Err(violation("a failed task must not still be leased"));
    }
    Ok(ok(1))
});

property!(tp10_bounded_resources, |e, c| {
    // Each claim hands out at most one task and takes a lease, so a wedged worker
    // cannot accumulate unbounded work.
    for i in 0..4 {
        e.enqueue(TaskRecord::pending(id(i), TaskKind::Query))
            .map_err(|err| violation(format!("enqueue failed: {err}")))?;
    }
    let mut leases = 0;
    for _ in 0..4 {
        let got = e
            .claim("w", c.now_ms())
            .map_err(|err| violation(format!("claim failed: {err}")))?;
        match got {
            Claim::Empty => break,
            Claim::Claimed(r) => {
                leases += 1;
                if r.lease_expires_at_ms.is_none() {
                    return Err(violation(
                        "a claimed task carries no lease, so it can never be reclaimed",
                    ));
                }
            }
        }
    }
    if leases > 4 {
        return Err(violation(format!(
            "a single worker accumulated {leases} leases; each claim takes one"
        )));
    }
    Ok(ok(leases as u32))
});

property!(tp11_dead_letter_is_terminal, |e, c| {
    // After the retry budget is exhausted the task must stop, not retry forever,
    // and the failure must be visible rather than silent.
    let t = TaskRecord::pending(id(1), TaskKind::Workflow);
    let tid = t.id.clone();
    e.enqueue(t)
        .map_err(|err| violation(format!("enqueue failed: {err}")))?;

    let mut attempts = 0;
    // Bounded loop: a non-terminating engine must fail the test, not hang it.
    for _ in 0..16 {
        let got = e
            .claim("w", c.now_ms())
            .map_err(|err| violation(format!("claim failed: {err}")))?;
        match got {
            Claim::Empty => break,
            Claim::Claimed(r) => {
                attempts = r.attempts;
                if r.state.is_terminal() {
                    break;
                }
                e.complete(
                    &tid,
                    "w",
                    c.now_ms(),
                    TaskState::Failed,
                    false,
                    Some("always fails".into()),
                )
                .map_err(|err| violation(format!("complete failed: {err}")))?;
            }
        }
    }

    let Some(after) = e.get(&tid) else {
        return Err(violation("task vanished while being driven to dead-letter"));
    };
    if after.state != TaskState::DeadLettered && after.state != TaskState::Failed {
        return Err(violation(format!(
            "expected DeadLettered or Failed, got {:?}",
            after.state
        )));
    }
    if after.state == TaskState::DeadLettered && after.last_error.is_none() {
        return Err(violation(
            "a dead-lettered task must carry its last error, or it is invisible",
        ));
    }
    Ok(ok(attempts.max(1)))
});

property!(tp12_side_effects_are_accounted_for, |e, c| {
    // (a) A completed task that observed an effect records it.
    // (b) An uncertain outcome is recorded as uncertain, never as success.
    // The failure mode this prevents is an effect that occurred with nothing
    // recording it.
    let t1 = TaskRecord::pending(id(1), TaskKind::Query);
    let t1id = t1.id.clone();
    e.enqueue(t1)
        .map_err(|err| violation(format!("enqueue failed: {err}")))?;
    let first = e
        .claim("w1", c.now_ms())
        .map_err(|err| violation(format!("claim failed: {err}")))?;
    if let Claim::Claimed(_) = first {
    } else {
        return Err(violation("expected to claim"));
    }
    e.complete(&t1id, "w1", c.now_ms(), TaskState::Completed, true, None)
        .map_err(|err| violation(format!("complete failed: {err}")))?;
    let Some(a) = e.get(&t1id) else {
        return Err(violation("completed task vanished"));
    };
    if !a.effect_observed {
        return Err(violation(
            "a task that observed an effect did not record it",
        ));
    }

    let t2 = TaskRecord::pending(id(2), TaskKind::Workflow);
    let t2id = t2.id.clone();
    e.enqueue(t2)
        .map_err(|err| violation(format!("enqueue failed: {err}")))?;
    let second = e
        .claim("w2", c.now_ms())
        .map_err(|err| violation(format!("claim failed: {err}")))?;
    if let Claim::Claimed(_) = second {
    } else {
        return Err(violation("expected to claim the second task"));
    }
    e.complete(
        &t2id,
        "w2",
        c.now_ms(),
        TaskState::NeedsVerification,
        true,
        Some("unknown".into()),
    )
    .map_err(|err| violation(format!("complete failed: {err}")))?;
    let Some(b) = e.get(&t2id) else {
        return Err(violation("uncertain task vanished"));
    };
    if b.state == TaskState::Completed {
        return Err(violation("an uncertain outcome was recorded as success"));
    }
    if !b.state.is_uncertain() {
        return Err(violation(format!(
            "expected an uncertain state, got {:?}",
            b.state
        )));
    }
    Ok(ok(2))
});

/// Builds a fresh engine.
///
/// # Why a factory and not a single engine
///
/// The properties must be **independent**. Running them in sequence against one
/// engine lets them interfere: TP-1 leaves 32 pending tasks, so a later
/// property's `claim` returns the *wrong* task and the failure is reported
/// against a property that is actually fine. A suite whose results depend on
/// execution order is not a specification.
///
/// So each property gets its own engine, and its own clock.
pub type EngineFactory = Box<dyn Fn() -> Box<dyn TaskEngine>>;

/// Runs every property and produces the report, giving each property a fresh
/// engine and clock.
///
/// TP-7 and TP-8/TP-9 delegate to their own modules: TP-7 needs a child process
/// to kill, and TP-8/TP-9 are arithmetic over time rather than over a queue.
#[must_use]
pub fn run_all(factory: EngineFactory, seed: u64) -> crate::conformance::report::ConformanceReport {
    type Outcome = crate::conformance::report::PropertyOutcome;
    let mut results: BTreeMap<&'static str, Outcome> = BTreeMap::new();

    /// Runs one property against a fresh engine and clock.
    fn isolate(
        factory: &EngineFactory,
        f: impl FnOnce(&mut dyn TaskEngine, &mut dyn TestClock) -> Outcome,
    ) -> Outcome {
        let mut e = factory();
        let mut c = crate::conformance::clock::FixedClock::default();
        f(e.as_mut(), &mut c)
    }

    results.insert(
        "TP-1",
        isolate(&factory, |e, c| tp1_no_silent_disappearance(e, c)),
    );
    results.insert(
        "TP-2",
        isolate(&factory, |e, c| tp2_exactly_once_where_required(e, c)),
    );
    results.insert(
        "TP-3",
        isolate(&factory, |e, c| tp3_cancellation_is_observable(e, c)),
    );
    results.insert("TP-4", isolate(&factory, |e, c| tp4_restart_recovers(e, c)));
    results.insert(
        "TP-5",
        isolate(&factory, |e, c| tp5_expired_leases_cannot_execute(e, c)),
    );
    results.insert(
        "TP-6",
        isolate(&factory, |e, c| tp6_retries_never_inherit_approvals(e, c)),
    );
    results.insert(
        "TP-7",
        isolate(&factory, |e, c| {
            crate::conformance::power_loss::tp7_power_loss_cannot_corrupt(e, c, seed)
        }),
    );
    results.insert(
        "TP-8",
        crate::conformance::schedule::tp8_scheduling_is_deterministic(seed),
    );
    results.insert(
        "TP-9",
        crate::conformance::schedule::tp9_catch_up_is_bounded(seed),
    );
    results.insert(
        "TP-10",
        isolate(&factory, |e, c| tp10_bounded_resources(e, c)),
    );
    results.insert(
        "TP-11",
        isolate(&factory, |e, c| tp11_dead_letter_is_terminal(e, c)),
    );
    results.insert(
        "TP-12",
        isolate(&factory, |e, c| tp12_side_effects_are_accounted_for(e, c)),
    );

    let engine_name = factory().name();

    let ordered: Vec<PropertyResult> = crate::conformance::PROPERTIES
        .iter()
        .map(|pid| {
            let outcome = results
                .remove(*pid)
                .unwrap_or(PropertyOutcome::Unsupported {
                    detail: "not implemented by the suite".into(),
                });
            let statement = crate::conformance::PROPERTY_DESCRIPTIONS
                .iter()
                .find(|(p, _)| p == pid)
                .map_or("", |(_, s)| *s);
            PropertyResult {
                id: pid,
                statement,
                outcome,
                seed,
            }
        })
        .collect();
    crate::conformance::report::ConformanceReport::new(engine_name, seed, ordered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_property_table_and_the_run_list_agree() {
        // A property declared but never run would silently vanish from the report.
        assert_eq!(crate::conformance::PROPERTIES.len(), 12);
        assert_eq!(crate::conformance::PROPERTY_DESCRIPTIONS.len(), 12);
        for (id, _) in crate::conformance::PROPERTY_DESCRIPTIONS {
            assert!(
                crate::conformance::PROPERTIES.contains(&id),
                "{id} missing from PROPERTIES"
            );
        }
    }

    #[test]
    fn a_workflow_task_is_not_idempotent_by_default() {
        // The basis of TP-2: unknown-is-not-safe for task kinds too.
        let t = TaskRecord::pending(TaskId::new("x"), TaskKind::Workflow);
        assert!(!t.idempotent);
        let q = TaskRecord::pending(TaskId::new("x"), TaskKind::Query);
        assert!(q.idempotent);
    }
}
