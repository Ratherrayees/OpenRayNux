//! The Phase 2 schema: tasks, leases, attempts, effects, approvals, events,
//! schedules and the fire ledger.
//!
//! # Where these tables come from
//!
//! Every table here is required by something already written down, not by this
//! phase's convenience:
//!
//! | Table | Required by |
//! |---|---|
//! | `tasks` | ADR-0028 (`critical` region, task engine is the only writer), ADR-0007 |
//! | `task_attempts` | ADR-0029 TP-11 ("carries its last error, is surfaced"), ADR-0007 observability |
//! | `task_effects` | ADR-0029 TP-12 ("every externally-visible effect either has a recorded result or leaves the task in a state that says unknown"), ADR-0007's dedupe row |
//! | `task_approvals` | ADR-0029 TP-6 ("an approval is single-use, expires, and is bound to a specific action digest — never carried forward") |
//! | `task_events` | ADR-0028 invariant 6 ("every state transition is observable — via the audit journal or the event log, never by inspecting a table after the fact") |
//! | `schedules` | ADR-0021 ("schedules are persisted, and every schedule carries a timezone and a misfire policy as data") |
//! | `schedule_fires` | ADR-0029 TP-8 (`UNIQUE(schedule_id, fire_time)`), ADR-0021 decision 3 |
//!
//! # What is deliberately NOT here
//!
//! * **No `task_checkpoints`.** ADR-0007 sketches it but its own rationale says
//!   step-level replay is not needed ("Nobody needs step-level replay"). Creating
//!   it now would be an empty table plus a promise we have not scoped.
//! * **No separate `dedupe` table.** ADR-0007 lists one, but `task_effects` has
//!   `idempotency_key` as its primary key and therefore *is* the dedupe ledger.
//!   Two tables that must agree are a bug waiting to happen.
//! * **No tables for health, jobs, learning, messaging, memories, providers, MCP
//!   servers, or UI preferences.** Phase 2 is the task layer; those regions are
//!   classified in ADR-0028 but their arrival is not this phase.
//! * **No credentials, ever.** ADR-0028 invariant 4. Nothing here stores a
//!   secret; only `secret_ref` pointers would ever point into the OS keyring.
//!
//! # Why the CHECK constraints matter
//!
//! Each `CHECK` encodes an invariant the engine relies on, so a bug that violates
//! it fails at the storage layer with a named constraint rather than producing a
//! row that silently misbehaves later. Concretely:
//!
//! * `tasks.state IN (...)` — the state vocabulary is closed, and it is exactly
//!   the vocabulary the conformance suite's TP-7 verifier accepts. If a new state
//!   is added to the domain and not here, the insert fails loudly.
//! * `tasks: (lease_holder IS NULL) = (lease_expires_at_ms IS NULL)` — a lease is
//!   an indivisible pair. A holder with no expiry could never be fenced (TP-5),
//!   which is the exact bug ADR-0032 found in `apalis-sqlite`.
//! * `task_effects: (status = 'pending') = (resolved_at_ms IS NULL)` — an effect
//!   is either reserved-and-unresolved or resolved. "Resolved but stamped with no
//!   time" is TP-12's failure mode.
//! * `schedule_fires` primary key `(schedule_id, fire_time_ms)` — this *is* the
//!   TP-8 exactly-once mechanism. It is the schema, not an application check.
//!
//! # Determinism
//!
//! Migrations are applied in ascending version order, each in its own
//! transaction, recorded in `schema_meta`, and are `IF NOT EXISTS`-shaped so a
//! re-run is a no-op. There is no data-dependent branching and no timestamp in
//! the SQL, so the same starting version always produces the same schema.

/// The states the `tasks.state` column accepts.
///
/// Deliberately identical to `is_known_state` in the conformance harness's TP-7
/// verifier. If these two lists ever diverge, TP-7 starts accepting rows the state
/// machine considers impossible — or rejecting ones it does not — so there is a
/// test asserting they are the same set.
pub const TASK_STATES: &[&str] = &[
    "pending",
    "running",
    "waiting-for-user",
    "waiting-for-external",
    "paused",
    "cancelled",
    "completed",
    "failed",
    "dead-lettered",
    "needs-verification",
    "awaiting-next-step",
];

/// The effect statuses the `task_effects.status` column accepts.
///
/// `unknown` is the TP-12 answer. `not-performed` is distinct from `unknown`
/// because "definitely did not happen" and "may have happened" are different
/// facts and only one of them is safe to retry.
pub const EFFECT_STATUSES: &[&str] = &["pending", "observed", "unknown", "not-performed"];

/// The misfire policies the `schedules.misfire_policy` column accepts.
pub const MISFIRE_POLICIES: &[&str] = &[
    "fire-all",
    "fire-once",
    "fire-next-only",
    "skip-if-older",
    "pause",
];

/// `tasks` plus `task_attempts`. One migration, one transaction.
///
/// Split out from the effects/approvals migration only so that a rollback of a
/// later feature cannot take the task table with it.
pub const MIGRATION_TASKS: &str = r#"
CREATE TABLE IF NOT EXISTS tasks (
    id                     TEXT    NOT NULL PRIMARY KEY,
    kind                   TEXT    NOT NULL,
    state                  TEXT    NOT NULL,
    priority               INTEGER NOT NULL DEFAULT 0,
    payload                TEXT,
    idempotent             INTEGER NOT NULL,
    effect_observed        INTEGER NOT NULL DEFAULT 0,
    attempts               INTEGER NOT NULL DEFAULT 0,
    max_attempts           INTEGER NOT NULL,
    lease_holder           TEXT,
    lease_expires_at_ms    INTEGER,
    run_after_ms           INTEGER NOT NULL DEFAULT 0,
    catch_up               INTEGER NOT NULL DEFAULT 0,
    last_error             TEXT,
    cancel_requested_at_ms INTEGER,
    schedule_id            TEXT,
    fire_time_ms           INTEGER,
    created_at_ms          INTEGER NOT NULL,
    updated_at_ms          INTEGER NOT NULL,
    completed_at_ms        INTEGER,
    dead_lettered_at_ms    INTEGER,

    -- The state vocabulary is closed, and identical to the one the TP-7 power-loss
    -- verifier accepts.
    CHECK (state IN (
        'pending','running','waiting-for-user','waiting-for-external','paused',
        'cancelled','completed','failed','dead-lettered','needs-verification',
        'awaiting-next-step'
    )),

    -- A lease is an indivisible pair. A holder with no expiry could never be
    -- fenced, which is precisely the bug ADR-0032 found in `apalis-sqlite`.
    CHECK ((lease_holder IS NULL) = (lease_expires_at_ms IS NULL)),

    -- Retry budget and counters cannot be negative, and a task always has at
    -- least one attempt available.
    CHECK (attempts >= 0),
    CHECK (max_attempts >= 1),
    CHECK (effect_observed IN (0, 1)),
    CHECK (catch_up IN (0, 1)),

    -- Only a terminal-failure state carries a dead-letter timestamp.
    CHECK ((state = 'dead-lettered') = (dead_lettered_at_ms IS NOT NULL)),

    -- `catch_up` is a claim about how the run came to exist; it is only
    -- meaningful for a scheduled firing.
    CHECK ((schedule_id IS NULL) = (fire_time_ms IS NULL))
);

-- The claim query. Partial, so the index contains only claimable rows: a table of
-- a million completed tasks must not cost a million index entries on every claim.
CREATE INDEX IF NOT EXISTS idx_tasks_claimable
    ON tasks (priority DESC, created_at_ms ASC, id ASC)
    WHERE state = 'pending';

-- Recovery scans for leases to reclaim.
CREATE INDEX IF NOT EXISTS idx_tasks_leased
    ON tasks (state, lease_expires_at_ms)
    WHERE lease_holder IS NOT NULL;

-- `schedule_id` is intentionally NOT a foreign key to `schedules`. The schedule
-- table arrives in a later migration of this same phase, and a firing must remain
-- readable even if its schedule is later removed -- an audit row that vanishes
-- with its parent is worse than a dangling reference.
CREATE TABLE IF NOT EXISTS task_attempts (
    task_id       TEXT    NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    attempt_no    INTEGER NOT NULL,
    worker        TEXT    NOT NULL,
    started_at_ms INTEGER NOT NULL,
    finished_at_ms INTEGER,
    outcome       TEXT,
    error         TEXT,
    actor_label   TEXT,
    PRIMARY KEY (task_id, attempt_no)
);
"#;

/// `task_effects` and `task_approvals`.
///
/// Two tables in one migration because they are the two halves of the same
/// obligation: what a task was allowed to do (approval), and what it actually did
/// (effect). Splitting them would let an effect exist with no approval record for
/// the attempt that produced it.
pub const MIGRATION_ACCOUNTING: &str = r#"
-- The side-effect ledger (TP-12).
--
-- `idempotency_key` is the primary key, which makes this table *also* the dedupe
-- ledger ADR-0007 asked for: reserving a key twice is impossible, so a retry of
-- the same logical step cannot dispatch a second external call.
CREATE TABLE IF NOT EXISTS task_effects (
    idempotency_key TEXT    NOT NULL PRIMARY KEY,
    task_id         TEXT    NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    attempt_no      INTEGER NOT NULL,
    step_key        TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    detail          TEXT,
    reserved_at_ms  INTEGER NOT NULL,
    resolved_at_ms  INTEGER,

    CHECK (status IN ('pending','observed','unknown','not-performed')),

    -- An effect is either reserved-and-unresolved or resolved. "Resolved but not
    -- stamped" is exactly the TP-12 hole.
    CHECK ((status = 'pending') = (resolved_at_ms IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_task_effects_task
    ON task_effects (task_id, attempt_no);

-- Per-attempt approvals (TP-6).
--
-- The primary key is (task_id, attempt_no), NOT (task_id). That is the whole
-- mechanism: a retry increments `attempt_no`, so it cannot read the previous
-- attempt's approval row even if the digest would otherwise match. Carrying an
-- approval forward is not prevented by a check that could be bypassed -- it is
-- structurally impossible.
-- A governed action requested by a task, awaiting a human decision.
--
-- ADR-0038. A *proposal* is "this action is being requested"; an approval is "this
-- action has been authorised" and lives in `task_approvals`. They are deliberately
-- different tables and deliberately not the same row with a nullable digest: collapsing
-- them would make "the task asked" and "permission was granted" indistinguishable in
-- the audit trail, which is the distinction the trail exists to preserve.
--
-- `proposer` and `authority_root` are stored so the exact actor can be reconstructed
-- at execution time without re-deriving it from anything transient. Note what is NOT
-- here: the worker. The lease holder is execution ownership, and storing it beside the
-- proposer is how a task lease would quietly become an authority token (V-71).
--
-- One proposal per attempt (`UNIQUE (task_id, attempt_no)`), because a human wait is
-- not a retry: the same attempt that asked is the attempt that may execute.
CREATE TABLE IF NOT EXISTS task_proposals (
    proposal_id    TEXT    NOT NULL PRIMARY KEY,
    task_id        TEXT    NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    attempt_no     INTEGER NOT NULL,
    capability     TEXT    NOT NULL,
    target         TEXT,
    params         TEXT    NOT NULL,
    proposer       TEXT    NOT NULL,
    authority_root TEXT,
    created_at_ms  INTEGER NOT NULL,
    status         TEXT    NOT NULL,
    decided_at_ms  INTEGER,
    CHECK (status IN ('pending', 'approved', 'rejected', 'expired'))
);

CREATE TABLE IF NOT EXISTS task_approvals (
    task_id        TEXT    NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    attempt_no     INTEGER NOT NULL,
    digest         BLOB    NOT NULL,
    capability     TEXT    NOT NULL,
    target         TEXT,
    params         TEXT    NOT NULL,
    issued_at_ms   INTEGER NOT NULL,
    expires_at_ms  INTEGER NOT NULL,
    consumed_at_ms INTEGER,
    PRIMARY KEY (task_id, attempt_no)
);
"#;

/// The transition log (ADR-0028 invariant 6).
///
/// Append-only. `AUTOINCREMENT` rather than a bare rowid so sequence numbers are
/// **monotonic and never reused**: a log that reuses a sequence number after a
/// delete makes "what happened after event 41" unanswerable.
pub const MIGRATION_EVENTS: &str = r#"
CREATE TABLE IF NOT EXISTS task_events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT,
    at_ms       INTEGER NOT NULL,
    kind        TEXT    NOT NULL,
    from_state  TEXT,
    to_state    TEXT,
    worker      TEXT,
    attempt_no  INTEGER,
    detail      TEXT
);

CREATE INDEX IF NOT EXISTS idx_task_events_task ON task_events (task_id, seq);
"#;

/// `schedules` and the `schedule_fires` ledger.
pub const MIGRATION_SCHEDULES: &str = r#"
CREATE TABLE IF NOT EXISTS schedules (
    id              TEXT    NOT NULL PRIMARY KEY,
    cron            TEXT    NOT NULL,
    timezone        TEXT    NOT NULL,
    misfire_policy  TEXT    NOT NULL,
    misfire_minutes INTEGER,
    catch_up_cap    INTEGER NOT NULL,
    enabled         INTEGER NOT NULL,
    authorised_by   TEXT    NOT NULL,
    last_fired_ms   INTEGER,
    created_at_ms   INTEGER NOT NULL,
    updated_at_ms   INTEGER NOT NULL,

    CHECK (misfire_policy IN ('fire-all','fire-once','fire-next-only','skip-if-older','pause')),
    CHECK (enabled IN (0, 1)),
    CHECK (catch_up_cap >= 0),

    -- The threshold is present exactly when the policy needs one.
    CHECK ((misfire_policy = 'skip-if-older') = (misfire_minutes IS NOT NULL))
);

-- The TP-8 exactly-once mechanism, expressed as the primary key rather than as a
-- unique index added later: a duplicate fire is unrepresentable, so
-- `INSERT OR IGNORE` cannot succeed twice even across a crash, because SQLite
-- serialises writes.
CREATE TABLE IF NOT EXISTS schedule_fires (
    schedule_id   TEXT    NOT NULL REFERENCES schedules(id) ON DELETE CASCADE,
    fire_time_ms  INTEGER NOT NULL,
    catch_up      INTEGER NOT NULL,
    task_id       TEXT,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (schedule_id, fire_time_ms),
    CHECK (catch_up IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_schedule_fires_task ON schedule_fires (task_id);
"#;

/// Durable security state: the audit journal and the spent-approval ledger.
///
/// Two tables, and the constraints *are* the mechanisms:
///
/// * `audit_log` — `seq INTEGER PRIMARY KEY`. Two writers cannot claim one
///   position, so a stale chain head fails loudly at insert rather than
///   silently forking the journal. `record` holds the canonical bytes the chain
///   hashed; `prev_hash` and `record_hash` are that computation's inputs and
///   result, stored so a reload can re-verify without reimplementing BLAKE3
///   chain assembly anywhere else.
/// * `spent_approvals` — `digest BLOB PRIMARY KEY`. Single-use is then an
///   `INSERT` that either lands once or fails with a uniqueness violation, which
///   is atomic by construction. A `SELECT`-then-`INSERT` pair would not be.
///
/// `audit_log` carries no column for a secret: the record type has no field that
/// could hold one, and `secret_ref` is a name.
pub const MIGRATION_SECURITY_STATE: &str = r#"
CREATE TABLE IF NOT EXISTS audit_log (
    seq         INTEGER NOT NULL PRIMARY KEY,
    prev_hash   BLOB    NOT NULL,
    record_hash BLOB    NOT NULL,
    record      TEXT    NOT NULL,
    CHECK (length(prev_hash) = 32),
    CHECK (length(record_hash) = 32)
);

CREATE TABLE IF NOT EXISTS spent_approvals (
    digest          BLOB    NOT NULL PRIMARY KEY,
    consumed_at_ms  INTEGER NOT NULL,
    CHECK (length(digest) = 32)
);
"#;

/// The SQL for every Phase 2 migration, in the order it must be applied.
///
/// Concatenated into [`crate::migration::MIGRATIONS`] at compile time so there is
/// exactly one place a table can be created.
pub const MIGRATION_SQL: &[(&str, &str)] = &[
    ("tasks", MIGRATION_TASKS),
    ("task_accounting", MIGRATION_ACCOUNTING),
    ("task_events", MIGRATION_EVENTS),
    ("schedules", MIGRATION_SCHEDULES),
    ("security_state", MIGRATION_SECURITY_STATE),
];

// ---------------------------------------------------------------------------
// Bounded linear composition: durable representation only (stage 2)
// ---------------------------------------------------------------------------
//
// # What this migration adds, and what it deliberately does not
//
// Columns and one table, so the durable model can *represent* a sequence of governed
// steps. Nothing reads them yet: claim, lease, proposal, approval and execution behave
// exactly as they did at stage 1. A task created after this migration still takes one
// action, because `max_steps` defaults to 1.
//
// # Why existing rows are backfilled from `attempts` rather than from 1
//
// The obvious default -- `step_no = 1` for every existing row -- is wrong, and not
// harmlessly so. A task may already hold several proposals, one per attempt, and
// `UNIQUE (task_id, step_no)` would then fail to apply to a perfectly valid database.
//
// Today `attempt_no` *is* the logical step identity: each claim opens an attempt, each
// attempt may propose once, and a task that has been claimed three times has three
// governed steps' worth of history. So the faithful mapping is `step_no := attempt_no`,
// and it is derived from the existing creation semantics rather than guessed.
//
// The same reasoning fixes the task counters:
//
//   max_steps       = max(attempts, 1)
//   steps_completed = max(attempts, 1) when the task is Completed, else 0
//
// so a finished task reads as "N of N steps done" and an unfinished one as "0 of N", with
// no task ever claiming to have completed more steps than it was allowed. A task with no
// attempts yet is `0 of 1`, which is exactly a fresh single-step task.
//
// # Traps
//
// * `ALTER TABLE ... ADD COLUMN` cannot add a CHECK constraint in SQLite, so the new
//   counters carry no `>= 0` guarantee the way `attempts >= 0` does. That is deferred to
//   stage 3, which is where anything first writes these columns; it needs a trigger or a
//   write-path check, and adding one here would enforce behaviour in a stage meant to
//   change none.
// * `ALTER TABLE` is not `IF NOT EXISTS`-shaped. Idempotency comes from the runner, which
//   applies each version once and records it in `schema_meta`.
// * Fresh and migrated databases converge, because migration 2 still creates `tasks`
//   without these columns and migration 7 adds them either way.
///
/// The correction to [`MIGRATION_COMPOSITION`].
///
/// # What stage 2 got wrong
///
/// It treated `attempt_no` as the step identity, backfilling `step_no := attempt_no` and
/// declaring `UNIQUE (task_id, step_no)`. Both are wrong under the settled semantics:
///
/// * `step_no` is the **logical step**; `attempt_no` is the **retry within** it. A step
///   that fails and is retried produces two proposals on the *same* step, so
///   `UNIQUE (task_id, step_no)` cannot represent a retry -- it would refuse it.
/// * Reading a legacy row's `attempt_no` as its step number invents a multi-step history
///   that never happened. Every task before composition existed was **one** logical step,
///   however many times it was retried.
///
/// # What this does
///
/// * Drops the per-step unique index and replaces it with a plain lookup index over
///   `(task_id, step_no, attempt_no)`. No new uniqueness is introduced: the
///   proposal-per-attempt rule stays where it already lives, in the daemon's state guard.
/// * Renumbers every historical proposal and approval to logical step 1.
/// * Sets `max_steps = 1` for every legacy task and `steps_completed = 1` only where the
///   task is `Completed`.
///
/// `task_step_results` keeps `PRIMARY KEY (task_id, step_no)`: one durable final result
/// per logical step, with failed and retried attempts represented by the existing attempt
/// and audit records rather than by extra rows.
///
/// A forward migration rather than an edit to stage 2, because a database that already
/// applied stage 2 holds the bad index and the attempt-derived numbering, and editing the
/// old version would leave both in place while claiming they were never created.
///
/// Nothing is deleted: only `step_no`, `max_steps` and `steps_completed` are rewritten,
/// and `attempt_no` -- the record of what actually happened -- is not touched.
pub const MIGRATION_COMPOSITION_CORRECTION: &str = r#"
DROP INDEX IF EXISTS idx_task_proposals_step;

CREATE INDEX IF NOT EXISTS idx_task_proposals_step_attempt
    ON task_proposals (task_id, step_no, attempt_no);

UPDATE task_proposals SET step_no = 1;
UPDATE task_approvals  SET step_no = 1;
UPDATE tasks SET max_steps = 1;
UPDATE tasks SET steps_completed = CASE WHEN state = 'completed' THEN 1 ELSE 0 END;
"#;

/// The SQL itself.
pub const MIGRATION_COMPOSITION: &str = r#"
ALTER TABLE tasks ADD COLUMN max_steps       INTEGER NOT NULL DEFAULT 1;
ALTER TABLE tasks ADD COLUMN steps_completed INTEGER NOT NULL DEFAULT 0;

UPDATE tasks SET max_steps = MAX(attempts, 1);
UPDATE tasks SET steps_completed = CASE WHEN state = 'completed' THEN MAX(attempts, 1) ELSE 0 END;

ALTER TABLE task_proposals ADD COLUMN step_no INTEGER NOT NULL DEFAULT 1;
UPDATE task_proposals SET step_no = attempt_no;

ALTER TABLE task_approvals ADD COLUMN step_no INTEGER NOT NULL DEFAULT 1;
UPDATE task_approvals SET step_no = attempt_no;

CREATE UNIQUE INDEX IF NOT EXISTS idx_task_proposals_step
    ON task_proposals (task_id, step_no);

-- The recorded outcome of one step.
--
-- Deliberately free of execution semantics: no lease, no worker, no approval, no digest.
-- Those are owned by `task_proposals`, `task_approvals` and the governed dispatcher, and a
-- second copy of any of them here would be a second thing to keep in step. This table
-- records what happened and what was produced; it authorises nothing.
--
-- `verification` is free text rather than a closed vocabulary, because the verifier's own
-- verdict string is the authoritative rendering and inventing a second one here would
-- create a vocabulary that stage 3 has to keep in step with `ExecutionOutcome`. A
-- `status` vocabulary is closed, because the step lifecycle is this table's own business.
CREATE TABLE IF NOT EXISTS task_step_results (
    task_id           TEXT    NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    step_no           INTEGER NOT NULL,
    status            TEXT    NOT NULL,
    verification      TEXT,
    structured_output TEXT,
    artifacts         TEXT,
    recorded_at_ms    INTEGER NOT NULL,
    PRIMARY KEY (task_id, step_no),
    CHECK (step_no >= 1),
    CHECK (status IN ('verified', 'refuted', 'undetermined', 'failed'))
);
"#;

/// Migration 9: `task_attempts` is keyed per logical step.
///
/// `attempts` counts attempts **within the current logical step**, so step 2's first
/// execution is attempt 1 of step 2. Under `PRIMARY KEY (task_id, attempt_no)` every step
/// after the first collided with step 1 on the same `attempt_no`, which made the settled
/// counter meaning unrepresentable rather than merely untidy.
///
/// A forward migration rather than an edit to an earlier version, because a database that
/// already applied version 1 holds the old key and rewriting that version's `CREATE TABLE`
/// would leave existing databases with the old shape while claiming they never had it.
///
/// The table is rebuilt rather than altered: SQLite cannot drop or narrow a primary key, so
/// the only way to widen one is to create the new table, copy, drop the old and rename. The
/// row order below matters -- copy before drop.
///
/// Backfill is `step_no = 1` for every existing row, which is the same legacy mapping
/// migration 8 applies to `tasks` and `task_proposals`: an attempt recorded before
/// composition existed was a retry of step 1, not a step of its own. Nothing is deleted and
/// `attempt_no` is not rewritten.
pub const MIGRATION_ATTEMPT_STEP_SCOPE: &str = r#"
CREATE TABLE task_attempts_scoped (
    task_id       TEXT    NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    step_no       INTEGER NOT NULL DEFAULT 1,
    attempt_no    INTEGER NOT NULL,
    worker        TEXT    NOT NULL,
    started_at_ms INTEGER NOT NULL,
    finished_at_ms INTEGER,
    outcome       TEXT,
    error         TEXT,
    actor_label   TEXT,
    PRIMARY KEY (task_id, step_no, attempt_no),
    CHECK (step_no >= 1)
);

INSERT INTO task_attempts_scoped
    (task_id, step_no, attempt_no, worker, started_at_ms, finished_at_ms, outcome, error,
     actor_label)
SELECT task_id, 1, attempt_no, worker, started_at_ms, finished_at_ms, outcome, error,
       actor_label
  FROM task_attempts;

DROP TABLE task_attempts;

ALTER TABLE task_attempts_scoped RENAME TO task_attempts;
"#;

/// The correction `MIGRATION_ATTEMPT_STEP_SCOPE` owed `task_approvals`.
///
/// # What stage 2 and the composition correction missed
///
/// Both fixed `attempt_no` used as a step identity, but only `task_attempts` and
/// `task_proposals` were given a `(task_id, step_no, attempt_no)` key. `task_approvals`
/// kept `PRIMARY KEY (task_id, attempt_no)` from stage 2.
///
/// That is wrong under the settled semantics, because **`attempt_no` restarts at 1 for
/// every logical step**: `complete_verified_step` resets `attempts` to 0 when a task
/// parks at a boundary, so the first attempt of step 2 is attempt 1 just as the first
/// attempt of step 1 was. Two logical steps of one task therefore collide on
/// `(task_id, 1)`.
///
/// The collision is silent rather than loud, which is what makes it worth a migration
/// rather than a code guard: `record_approval` is an `INSERT OR IGNORE`, so step 2's
/// approval is discarded and `approval_for` hands back step 1's row. A multi-step task
/// could then never have its second step approved, and the only symptom was an
/// `approval-step-mismatch` refusal naming a mismatch the caller had not caused.
///
/// Discovered by making continuation reachable rather than by inspection: before
/// `task/continue` existed no task ever reached a second logical step, so the key was
/// unreachable and untested.
///
/// # What this does
///
/// The same table rebuild [`MIGRATION_ATTEMPT_STEP_SCOPE`] applies to `task_attempts`:
/// create the corrected table, copy every row across unchanged, drop the old one, rename.
/// Copying verbatim rather than renumbering is the point — every historical approval was
/// recorded on a single logical step, so its `step_no` is already right, and inventing
/// numbers here would fabricate a multi-step history that did not happen.
///
/// A forward migration rather than an edit to stage 2, for the reason the composition
/// correction gives: a database that already applied stage 2 holds the old primary key,
/// and editing the old version would leave it in place while claiming it never existed.
pub const MIGRATION_APPROVAL_STEP_SCOPE: &str = r#"
CREATE TABLE task_approvals_scoped (
    task_id        TEXT    NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    step_no        INTEGER NOT NULL DEFAULT 1,
    attempt_no     INTEGER NOT NULL,
    digest         BLOB    NOT NULL,
    capability     TEXT    NOT NULL,
    target         TEXT,
    params         TEXT    NOT NULL,
    issued_at_ms   INTEGER NOT NULL,
    expires_at_ms  INTEGER NOT NULL,
    consumed_at_ms INTEGER,
    PRIMARY KEY (task_id, step_no, attempt_no),
    CHECK (step_no >= 1)
);

INSERT INTO task_approvals_scoped
    (task_id, step_no, attempt_no, digest, capability, target, params,
     issued_at_ms, expires_at_ms, consumed_at_ms)
SELECT task_id, step_no, attempt_no, digest, capability, target, params,
       issued_at_ms, expires_at_ms, consumed_at_ms
  FROM task_approvals;

DROP TABLE task_approvals;

ALTER TABLE task_approvals_scoped RENAME TO task_approvals;
"#;

/// Migration 11 — the side-effect ledger records its own repeat-safety. V-93.
pub const MIGRATION_EFFECT_IDEMPOTENCY: &str = r#"
-- The repeat-safety of the *effect*, recorded when it is reserved.
--
-- V-93. `tasks.idempotent` says whether the task may be re-run as a unit; this says
-- whether *this* side effect may be repeated. They are different facts and V-92
-- already made that point deliberately, reading the capability's own declaration
-- rather than the task row. Recovery needs the same answer at a point where the
-- task row cannot supply it: a task is created before the capability that will run
-- on it is known, and the daemon's `task/create` defaults to a `query` kind, so a
-- task that goes on to run a non-idempotent capability is very often flagged
-- idempotent at the task level. Deciding recovery from that flag would leave the
-- hole open.
--
-- `NOT NULL DEFAULT 0` is the fail-closed direction: a row written before this
-- column existed, or by any writer that did not supply it, is treated as one that
-- must not be repeated. That is the correct reading of an effect whose repeat-safety
-- nobody recorded.
--
-- Added by `ALTER TABLE` rather than by recreating the table, so the existing CHECK
-- and the foreign key are untouched. The column therefore carries no CHECK of its
-- own, which is why `idempotent IN (0,1)` is enforced in `decode_effect` instead --
-- `max_steps` and `steps_completed` have the same gap.
ALTER TABLE task_effects ADD COLUMN idempotent INTEGER NOT NULL DEFAULT 0;
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    /// Applies the Phase 2 SQL to a fresh connection.
    fn migrated() -> Connection {
        let c = Connection::open_in_memory().expect("open");
        for (_, sql) in MIGRATION_SQL {
            c.execute_batch(sql).expect("apply");
        }
        c
    }

    /// Tables we created, excluding SQLite's own `sqlite_%` bookkeeping.
    ///
    /// `sqlite_sequence` appears because `task_events` uses AUTOINCREMENT, and
    /// that is deliberate: it is what makes log sequence numbers monotonic and
    /// never reused. It is SQLite's table, not ours.
    fn table_names(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table'
                   AND name NOT LIKE 'sqlite_%' ORDER BY name;",
            )
            .expect("prepare");
        stmt.query_map([], |r| r.get::<_, String>(0))
            .expect("query")
            .filter_map(Result::ok)
            .collect()
    }

    #[test]
    fn phase_two_creates_exactly_the_declared_tables() {
        // Named explicitly so a table added "just in case" fails this test.
        // `schema_meta` is added by the migration runner and so is absent here.
        let names = table_names(&migrated());
        // Every name here is required by a decision already written down, and this
        // test is what makes adding one a deliberate act rather than a side effect.
        // `audit_log` and `spent_approvals` are the durable security state:
        // ADR-0027's control S33 ("for every action the record answers five
        // questions") and TP-6's single-use, which were previously both
        // process-local and therefore only true for one process lifetime.
        let mut expected = vec![
            "audit_log",
            "schedule_fires",
            "schedules",
            "spent_approvals",
            "task_approvals",
            "task_attempts",
            "task_proposals",
            "task_effects",
            "task_events",
            "tasks",
        ];
        expected.sort_unstable();
        assert_eq!(names, expected, "unexpected tables");
    }

    #[test]
    fn the_sql_is_idempotent() {
        // Re-running every migration must be a no-op, because ADR-0017 requires
        // migrations to be idempotent and a retry after a crash is routine.
        let c = migrated();
        for (_, sql) in MIGRATION_SQL {
            c.execute_batch(sql).expect("re-apply");
        }
        assert_eq!(table_names(&c).len(), 10);
    }

    #[test]
    fn a_leased_task_is_insertable_and_an_unknown_state_is_not() {
        let c = migrated();
        let ok = "INSERT INTO tasks (id, kind, state, idempotent, max_attempts,
                       lease_holder, lease_expires_at_ms, created_at_ms, updated_at_ms)
                   VALUES ('t', 'workflow', 'running', 0, 3, 'w1', 999, 0, 0)";
        c.execute(ok, []).expect("a valid leased row must insert");
        let bad = "INSERT INTO tasks (id, kind, state, idempotent, max_attempts,
                       created_at_ms, updated_at_ms)
                   VALUES ('u', 'workflow', 'thinking', 0, 3, 0, 0)";
        assert!(
            c.execute(bad, []).is_err(),
            "an unknown state must be refused by the CHECK"
        );
    }

    #[test]
    fn a_lease_holder_without_an_expiry_is_refused() {
        // The exact shape that would make fencing impossible (ADR-0032's finding).
        let c = migrated();
        let sql = "INSERT INTO tasks (id, kind, state, idempotent, max_attempts,
                          lease_holder, created_at_ms, updated_at_ms)
                   VALUES ('t', 'workflow', 'running', 0, 3, 'w1', 0, 0)";
        let err = c
            .execute(sql, [])
            .expect_err("half a lease must be refused");
        assert!(
            err.to_string().contains("lease_holder"),
            "the named constraint should identify the lease pair: {err}"
        );
    }

    #[test]
    fn a_dead_lettered_task_must_carry_its_timestamp_and_vice_versa() {
        let c = migrated();
        let missing_ts = "INSERT INTO tasks (id, kind, state, idempotent, max_attempts,
                                         created_at_ms, updated_at_ms)
                          VALUES ('a','workflow','dead-lettered',0,3,0,0)";
        assert!(
            c.execute(missing_ts, []).is_err(),
            "missing dead_lettered_at_ms"
        );
        let spurious_ts = "INSERT INTO tasks (id, kind, state, idempotent, max_attempts,
                                              dead_lettered_at_ms, created_at_ms, updated_at_ms)
                           VALUES ('b','workflow','failed',0,3,5,0,0)";
        assert!(
            c.execute(spurious_ts, []).is_err(),
            "dead_lettered_at_ms on a non-dead-lettered task"
        );
    }

    #[test]
    fn an_effect_is_pending_exactly_while_unresolved() {
        let c = migrated();
        c.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,max_attempts,created_at_ms,updated_at_ms)
                   VALUES ('t','query','pending',1,3,0,0)",
            [],
        )
        .expect("task");
        let pending = "INSERT INTO task_effects
            (idempotency_key,task_id,attempt_no,step_key,status,reserved_at_ms)
            VALUES ('k','t',1,'s','pending',0)";
        c.execute(pending, [])
            .expect("a reserved effect must insert");
        let stamped = "INSERT INTO task_effects
            (idempotency_key,task_id,attempt_no,step_key,status,reserved_at_ms,resolved_at_ms)
            VALUES ('k2','t',1,'s','pending',0,99)";
        assert!(
            c.execute(stamped, []).is_err(),
            "a pending effect with a resolution time is the TP-12 hole"
        );
    }

    #[test]
    fn the_same_idempotency_key_cannot_be_reserved_twice() {
        // The dedupe guarantee, at the schema level rather than in application code.
        let c = migrated();
        c.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,max_attempts,created_at_ms,updated_at_ms)
                   VALUES ('t','query','pending',1,3,0,0)",
            [],
        )
        .expect("task");
        let ins = "INSERT INTO task_effects
            (idempotency_key,task_id,attempt_no,step_key,status,reserved_at_ms)
            VALUES (?1,'t',1,'s','pending',0)";
        c.execute(ins, rusqlite::params!["same-key"])
            .expect("first reservation");
        assert!(
            c.execute(ins, rusqlite::params!["same-key"]).is_err(),
            "a duplicate idempotency key must be refused"
        );
    }

    #[test]
    fn approvals_are_scoped_to_one_attempt() {
        // The TP-6 mechanism: two attempts on one task cannot share an approval row.
        let c = migrated();
        c.execute(
            "INSERT INTO tasks (id,kind,state,idempotent,max_attempts,created_at_ms,updated_at_ms)
                   VALUES ('t','workflow','pending',0,3,0,0)",
            [],
        )
        .expect("task");
        let ins = "INSERT INTO task_approvals
            (task_id,attempt_no,digest,capability,target,params,issued_at_ms,expires_at_ms)
            VALUES ('t',?1,x'00',?2,NULL,'',0,999)";
        c.execute(ins, rusqlite::params![1i64, "cap"])
            .expect("attempt 1 approval");
        assert!(
            c.execute(ins, rusqlite::params![1i64, "cap"]).is_err(),
            "the same attempt must not carry two approvals"
        );
        assert!(
            c.execute(ins, rusqlite::params![2i64, "cap"]).is_ok(),
            "a new attempt is a new row, which is why it cannot inherit the old one"
        );
    }

    #[test]
    fn a_fire_is_identifiable_only_by_its_schedule_and_time() {
        // TP-8's exactly-once key.
        let c = migrated();
        c.execute(
            "INSERT INTO schedules (id,cron,timezone,misfire_policy,catch_up_cap,enabled,
                                           authorised_by,created_at_ms,updated_at_ms)
                   VALUES ('s','0 * * * *','UTC','fire-all',10,1,'u',0,0)",
            [],
        )
        .expect("schedule");
        let ins = "INSERT INTO schedule_fires (schedule_id,fire_time_ms,catch_up,created_at_ms)
                   VALUES ('s',?1,0,0)";
        c.execute(ins, rusqlite::params![1000i64])
            .expect("first fire");
        assert!(
            c.execute(ins, rusqlite::params![1000i64]).is_err(),
            "duplicate fire"
        );
        assert!(
            c.execute(ins, rusqlite::params![2000i64]).is_ok(),
            "a different instant is fine"
        );
    }

    #[test]
    fn the_misfire_threshold_is_present_exactly_when_the_policy_needs_one() {
        let c = migrated();
        let base = "INSERT INTO schedules (id,cron,timezone,misfire_policy,misfire_minutes,
                                            catch_up_cap,enabled,authorised_by,created_at_ms,updated_at_ms)
                    VALUES (?1,'0 * * * *','UTC',?2,?3,10,1,'u',0,0)";
        c.execute(
            base,
            rusqlite::params!["a", "fire-all", Option::<i64>::None],
        )
        .expect("no threshold");
        assert!(
            c.execute(base, rusqlite::params!["b", "fire-all", Some(60i64)])
                .is_err(),
            "a threshold on a policy that ignores it"
        );
        assert!(
            c.execute(
                base,
                rusqlite::params!["c", "skip-if-older", Option::<i64>::None]
            )
            .is_err(),
            "a threshold is required by skip-if-older"
        );
        c.execute(base, rusqlite::params!["d", "skip-if-older", Some(60i64)])
            .expect("both present");
    }

    #[test]
    fn the_state_list_is_the_domain_state_list() {
        // Derived from the domain, not hand-written. A `CHECK` constraint that
        // omits a state would make that state unstorable, and one that names a
        // state the domain does not have would accept a row no state machine
        // recognises. Both are silent, so the two lists are compared here.
        //
        // The TP-7 power-loss verifier has its *own* vocabulary, and it is checked
        // against this list from `orxnud-task` -- which is the only crate allowed to
        // see both (store may not depend on task; see gate G2).
        let from_domain: Vec<&str> = orxnud_domain::task_state::TaskState::ALL
            .iter()
            .map(|s| s.as_wire_str())
            .collect();
        assert_eq!(TASK_STATES, from_domain.as_slice());
    }

    #[test]
    fn the_misfire_and_effect_vocabularies_are_the_domains() {
        // Same reasoning as the state list: one source of truth per vocabulary.
        let policies: Vec<&str> = [
            orxnud_domain::task_state::MisfirePolicy::FireAll,
            orxnud_domain::task_state::MisfirePolicy::FireOnce,
            orxnud_domain::task_state::MisfirePolicy::FireNextOnly,
            orxnud_domain::task_state::MisfirePolicy::Pause,
        ]
        .iter()
        .map(|p| p.as_wire_str())
        .collect();
        for p in &policies {
            assert!(
                MISFIRE_POLICIES.contains(p),
                "{p} is missing from the CHECK list"
            );
        }
        assert!(
            MISFIRE_POLICIES.contains(
                &orxnud_domain::task_state::MisfirePolicy::SkipIfOlderMinutes(0).as_wire_str()
            ),
            "skip-if-older is missing from the CHECK list"
        );
        assert_eq!(EFFECT_STATUSES.len(), 4);
        assert!(
            EFFECT_STATUSES.contains(&"unknown"),
            "TP-12 needs an `unknown` status"
        );
    }

    #[test]
    fn every_migration_sql_block_is_non_empty() {
        for (name, sql) in MIGRATION_SQL {
            assert!(!sql.trim().is_empty(), "{name} is empty");
            assert!(sql.contains("CREATE TABLE"), "{name} creates no table");
        }
    }

    #[test]
    fn no_migration_mentions_a_credential() {
        // ADR-0028 invariant 4: credentials are never state. A schema that grew a
        // secret column would be a serious breach, so the SQL is checked for it.
        let suspicious = [
            "password",
            "secret_value",
            "api_key",
            "token_value",
            "credential",
        ];
        for (name, sql) in MIGRATION_SQL {
            let lower = sql.to_lowercase();
            for needle in suspicious {
                assert!(
                    !lower.contains(needle),
                    "{name} mentions {needle:?}; ADR-0028 invariant 4 forbids it"
                );
            }
        }
    }
}
