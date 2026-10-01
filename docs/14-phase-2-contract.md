# 14 — Phase 2 Contract and Delivery Record

Status:

```text
Phase 2 implementation: COMPLETE
Windows verification:   OPEN (V-29)
```

These are separate. The Linux implementation is complete and verified; the Windows
cross-check is unrun because this host has no MSVC C toolchain. V-29 is an open
verification item, **not** a Phase 2 implementation gap, and it is not recorded as
one.

Phase 2 made the deterministic task layer operational:
persistent storage, the production task repository, the durable engine, the
scheduler, and crash/restart recovery — with all twelve ADR-0029 properties passing
against the **unmodified** Phase 1 harness.

This document records what Phase 2 was required to build, what it built, and — more
usefully — what it found.

---

## 1. Objective

> Make the deterministic task layer operational, and prove it against the contract
> that already existed.

The contract was written first, in Phase 1, and was **not** amended to suit the
implementation. Where the two disagreed, the harness won. The four places that
happened are recorded as amendments A-001 … A-004 in
[`12-verification-register.md`](12-verification-register.md).

---

## 2. What Phase 2 delivered

| # | Deliverable | Where |
|---|---|---|
| 1 | Persistent storage: 7 task-layer tables, versioned migrations | `orxnud-store/src/schema.rs` |
| 2 | Snapshot-protected migration with restore-on-failure (ADR-0017) | `orxnud-store/src/backup.rs`, `migration.rs` |
| 3 | The production task repository, all SQL in one crate (ADR-0006 §2) | `orxnud-store/src/task_repo.rs` |
| 4 | The durable engine, implementing the unchanged `TaskEngine` | `orxnud-task/src/engine.rs` |
| 5 | The scheduler: DST-correct, bounded catch-up, event-driven wake-up | `orxnud-task/src/scheduler.rs` |
| 6 | A structured error taxonomy (10 categories, closed) | `orxnud-task/src/error.rs` |
| 7 | Explicit resource bounds, enforced rather than asserted | `orxnud-task/src/limits.rs` |
| 8 | ADR-0028 region declarations + the ADR-0013 authority filter | `orxnud-store/src/region.rs`, `repository.rs` |
| 9 | **Production startup**: open, migrate snapshot-protected, reclaim the previous run's leases, and refuse to start if any of that fails | `orxnud-daemon/src/task_service.rs` |
| 10 | Structured observability of migrations, recovery, leases, retries, dead-lettering, and dropped occurrences | `orxnud-daemon/src/task_service.rs` |

### 8b. A bug only production wiring could find

`TaskService::open` is the first caller of `MigrationRunner::migrate` in the whole
repository. Every Phase 2 migration test drove `run`, which trusts its caller's
snapshot claim and never takes one — so the snapshot path had **no** coverage at all
until startup began using it.

It failed immediately, on a **brand-new database**: `Backup::verify` rejected a
snapshot with no `schema_meta` table, on the grounds that restoring it would erase a
user's database. Sound reasoning, wrong target — a fresh install has nothing to
erase, so the first migration could not run and the daemon could not start on any
machine where OpenRayNux had never run.

The fix judges emptiness **relative to the source** (`Backup::verify_against_source`):
an empty snapshot is a failure only when the database it protects was not itself
empty. The strict guard is unchanged and tested in both directions.

The same review found a second gap: the "a row count, so *verified* means *has the
data we expected*" comment described a protection the code never performed —
`total_rows` was computed and returned but compared against nothing. `BackupError::Empty`
now enforces it.

---

## 3. Schema — and what is deliberately absent

Seven tables, each traceable to a requirement already written down:

| Table | Required by | Class (ADR-0028) |
|---|---|---|
| `tasks` | ADR-0007, ADR-0028 | `critical` |
| `task_attempts` | TP-11 ("carries its last error, is surfaced") | `critical` |
| `task_effects` | TP-12, ADR-0007's dedupe row | `critical` |
| `task_approvals` | TP-6 ("single-use … never carried forward") | `critical` |
| `task_events` | ADR-0028 invariant 6 | `critical` |
| `schedules` | ADR-0021 decision 2 | `critical` |
| `schedule_fires` | TP-8's `UNIQUE(schedule_id, fire_time)` | `critical` |

Plus `schema_meta`, the migration bookkeeping table Phase 1 created.

**Not created, and why:**

- **`task_checkpoints`** — ADR-0007 sketches it, and the same ADR's rationale says
  step-level replay is not needed. An empty table plus an unscoped promise.
- **A separate `dedupe` table** — `task_effects.idempotency_key` *is* the primary
  key, so it is already the dedupe ledger. Two tables that must agree are a bug
  waiting to happen.
- **Anything for a later phase.** No users, health, jobs, learning, messaging,
  memories, documents, embeddings, providers, MCP servers, preferences, budget
  ledger, or credentials. A test asserts their absence by name
  (`no_table_outside_the_task_layer_exists`), because "we did not build it" is
  otherwise indistinguishable from "we forgot".

### Invariants carried in the schema, not in code

Each `CHECK` fails a bug at the storage layer rather than producing a row that
misbehaves later:

- `tasks.state IN (...)` — the vocabulary is closed and derived from
  `TaskState::ALL`, so a new state cannot be stored until the schema knows it.
- `(lease_holder IS NULL) = (lease_expires_at_ms IS NULL)` — a lease is an
  indivisible pair. A holder with no expiry could never be fenced, which is
  precisely ADR-0032's finding.
- `task_effects: (status = 'pending') = (resolved_at_ms IS NULL)` — "resolved but
  not stamped" is TP-12's hole.
- `schedule_fires` primary key `(schedule_id, fire_time_ms)` — TP-8's
  exactly-once guarantee *is* the key.
- `task_approvals` primary key `(task_id, attempt_no)` — TP-6 is structural: a
  retry increments `attempt_no`, so it cannot read the previous approval even if
  the digest would match.

---

## 4. Durability

| Setting | Value | Enforced by |
|---|---|---|
| SQLite | **3.53.2 bundled** (≥ the 3.51.3 floor) | `build.rs` parses `SQLITE_VERSION_NUMBER` from the header `libsqlite3-sys` compiles, and `const_assert_min_sqlite` asserts on *that* |
| `journal_mode` | `wal` | applied **and read back** on every connection |
| `synchronous` | `full` | applied, read back, and a test reproduces ADR-0032's `= OFF` and proves verification catches it |
| `foreign_keys` | `on` | read back |
| `busy_timeout` | 5 000 ms | lock contention retries rather than erroring |
| `cache_size` | −8 000 KiB | bounded, so memory does not grow with the file |

The version assertion reads the header rather than comparing a constant we wrote,
so downgrading `rusqlite` — or pointing `LIBSQLITE3_SYS_USE_PKG_CONFIG` at a
system 3.51.2 — is a **build error**, not a warning.

---

## 5. Conformance — all twelve, unchanged

`cargo test -p orxnud-task --test conformance_production` runs the **same**
`run_suite` the Phase 1 trivial fixture runs, from a separate test binary, against
`DurableEngine` on real files.

| Property | Result | Cases |
|---|---|---|
| TP-1 no silent disappearance | HOLDS | 32 |
| TP-2 exactly-once where required | HOLDS | 2 |
| TP-3 cancellation observable | HOLDS | 3 |
| TP-4 restart recovers | HOLDS | 8 |
| TP-5 expired leases cannot execute | HOLDS | 2 |
| TP-6 retries never inherit approvals | HOLDS | 1 |
| TP-7 power loss cannot corrupt | HOLDS | 3 |
| TP-8 DST/clock determinism | HOLDS | 9 |
| TP-9 catch-up bounded | HOLDS | 6 |
| TP-10 bounded resources | HOLDS | 4 |
| TP-11 dead-letter terminal | HOLDS | 3 |
| TP-12 side effects accounted for | HOLDS | 2 |

The suite is also asserted to have **teeth**: a deliberately broken store must
produce a `NonConforming` report, so agreement between engine and harness is known
to be meaningful rather than vacuous.

---

## 6. Failure testing performed

### Killed from outside, between calls

Every crash is a real `SIGKILL` to a real child process against a real file — no
unwinding, no destructors, no flush.

| Interruption point | What was proven |
|---|---|
| `before-write` | A usable database, nothing to recover |
| `after-enqueue` | An accepted task is durable and immediately reclaimable |
| `after-claim` | An **unexpired** lease is still orphaned, because the crash orphaned it |
| `after-complete-before-ack` | The committed task is terminal and is **not** retried |
| `after-effect-reserved` | The ledger row survives as `pending`, not fabricated as a result |

### Killed from inside, mid-transaction

The suite originally also listed a point called `during-complete`. **That was
false.** The child looped *immediately before* calling `complete`, so it died with
no transaction open. It proved the pre-crash state survives — which the five points
above already prove — while appearing to cover the most important case in the file.

The window is microseconds wide and inside `orxnud_store`'s transaction, so it
cannot be reached from outside. `crates/orxnud-store/src/faults.rs` therefore calls
`std::process::abort()` *from inside* the transaction: `SIGABRT`, no unwinding, no
`Drop`, no flush. The body is compiled out unless the crate's `fault-injection`
feature is on, which is not a default feature and is not enabled by any release
profile (`orxnud-store/tests/fault_feature_is_not_shipped.rs` asserts that, by
reading manifests — `cargo tree -e features` cannot see a `cfg`-only feature).

| Fault point | What the crash undoes |
|---|---|
| `claim-after-take-before-attempt` | the claim: no lease, no attempt row, task still `pending` |
| `complete-after-update-before-attempt` | the completion: the tasks row update, the lease clear, **and** the attempt close all roll back together |
| `cancel-before-event` | the cancellation, so a task can never end up `cancelled` with no event explaining it — TP-3's silent case |

Each test also asserts the rolled-back work **can be redone**, which is a stronger
claim than "nothing happened": a task whose claim rolled back must be claimable
again, and one whose completion rolled back must be completable again.

Plus: repeated crashes at the same point, a table-driven pass over every point, six
concurrent worker threads claiming twelve tasks (exactly one winner each), a
`SQLITE_BUSY` contention case classified as retryable rather than as corruption,
and an interrupted transaction rolled back with nothing partial left.

The master property — *no failure injection produces silent data loss or an
unauthorised side effect* — is asserted at every point.

---

## 7. Measurements

Conditions: Rust 1.98.1, SQLite 3.53.2 bundled, 16 CPUs, **btrfs over LUKS**,
`/home` filesystem. Full output in
`cargo test -p orxnud-task --test measurements -- --nocapture`.

| Operation | `synchronous = FULL` |
|---|---|
| `enqueue` | ~2.3 ms |
| `claim` (work available) | 2.6–2.9 ms |
| `complete` (fenced) | 2.2–3.4 ms |
| `recover` (500 leases) | 54–78 µs/op |
| idle scheduler pass + wakeup | 16–26 µs/op |
| startup, warm | 0.8–1.1 ms |
| startup, cold (with migration) | 24 ms |

**Q-OPEN-17 is answered**: `FULL` costs ~2.3 ms per commit against ~0.2 ms for
`NORMAL` — a ratio observed between 7.3× and 14.3× across four runs, so the
*magnitude* is the reliable figure and the ratio is a range. That leaves 30–55%
headroom against the < 5 ms transition budget. The default stays `FULL`.

**A trap, recorded because it nearly produced a false result (V-31):** the first
run put its databases in `/tmp`, which is **tmpfs**, where `fsync` is a no-op. It
reported `FULL` and `NORMAL` as *identical* — which would have "shown" that `FULL`
is free. The harness now refuses to measure durability on a memory-backed
filesystem.

---

## 8. Deviations

1. **`orxnud-domain` uses `serde_json` and `zeroize`** beyond the contract's
   `serde`/`thiserror` (A-001, carried from Phase 1). Both are pure; gate G2
   asserts the list mechanically.
2. **The retry delay is a parameter of the committing call**, not a repository
   constant, so TP-11 can drive the state machine without moving a clock (A-004).
3. **`orxnud-daemon` has a local `TaskServiceError` instead of an eleventh
   `EngineErrorKind`.** `EngineErrorKind` is a closed taxonomy of things that can go
   wrong with a *task*, and each kind carries a retry decision. "The daemon is
   shutting down" has no retry decision — never retry — so as `Cancelled` it would
   misreport a deliberate stop as a failure to act on, and as `Unavailable` it would
   suggest a dependency might return. The taxonomy stays closed; the lifecycle
   concern lives in the lifecycle layer.
4. **The `fault-injection` hook is compiled out by default**, so mid-transaction
   atomicity is covered by tests in `orxnud-store`'s own test binary rather than by
   turning the hook on for `orxnud-task`. Cargo rejects naming one crate twice under
   different names, and needing a test to compile `abort()` into a library build is a
   far larger blast radius than the hook deserves.
5. **`orxnuctl` lost its `clap` dependency.** The command set is two verbs; a
   hand-written parser makes "an unexpected argument is refused" a rule rather
   than a framework's default behaviour.
6. **Three `TaskRepoError` variants and one `ClaimOutcome` variant are boxed.**
   `rusqlite::Error` is ~136 bytes, which made every `Result` in the crate that
   large on a path taken once per task transition. Zero cost on the happy path.

---

## 9. Amendments

A-001 … A-004 in [`12-verification-register.md`](12-verification-register.md). In
summary: the domain dependency list; the catch-up window's upper-bound convention;
TP-7's child-process entry point being a per-binary requirement; and `Failed` tasks
needing to be requeued so TP-11 is not satisfied vacuously.

**No property was weakened, no assertion removed, no case skipped.**

---

## 10. Intentionally absent

No LLM provider · no agent framework · no intent interpretation · no domain model
(health, jobs, learning) · no GUI · no TUI behaviour · no voice · no messaging ·
no browser automation · no MCP · no cloud deployment · no multi-tenancy · no
device sync · no PostgreSQL / Redis / Kafka / Temporal / Restate / DBOS · no vector
database · no embeddings · no dynamic plugin loading · no capability invocation in
the engine · no remote telemetry · no memory semantics beyond the task ledger.

`CapabilityRegistry` is empty and `CapabilityInvocation` cannot be constructed
outside `orxnud-policy`, so the absence is mechanical rather than asserted.

---

## 11. Status

All Phase 2 implementation exit criteria are met.

The Windows `cargo check` remains partial, blocked for the six crates behind
bundled SQLite by the absence of an MSVC C toolchain on this host
(`cc-rs: failed to find tool "lib.exe"`). The other nine crates -- including
`orxnud-store`'s own platform-independent peers `orxnud-task`, `orxnud-policy` and
`orxnud-daemon` apart from their SQLite dependency -- check clean for MSVC. V-29 is
carried forward and is **not** claimed. Nothing in this document depends on it: the
storage and engine layers are platform-independent, and the platform boundary is
enforced by gate G3 rather than by a successful Windows build.

### Next-phase entry condition

The task engine is now the most security-sensitive subsystem in the repository, so
before any capability is registered, the chain

```text
Actor → authority → policy → approval → dispatch → execution → verification → audit
```

must have no bypass path from external input to a side effect. **Verified as of this
commit:** there is none, and the absence is mechanical rather than editorial —

- `orxnud-task` depends on `orxnud-domain`, `orxnud-store`, `orxnud-policy`, and
  `orxnud-audit`. It does not depend on `orxnud-capability`, and no task-layer source
  names `Dispatcher`, `CapabilityRegistry`, or `CapabilityInvocation`.
- Gate G2 enforces that dependency edge in both directions, so the capability crate
  cannot be reached from the engine without failing the build.
- Gate G2 also greps `AuthorisationProof`, `PolicySeal`, and `.authorise(` out of every
  crate's production sources, so a task cannot construct its own authorisation even
  if it could name policy.

`DurableEngine::reserve_effect` records *that* an external call was intended and
whether its outcome is known. It does not make calls: reserving an effect is a ledger
write, and nothing in Phase 2 performs the effect. The dispatch and execution legs of
the chain are Phase 4+, which is where this property has to be re-checked rather than
assumed to have carried forward.
