# Release-safety boundary review

Status: **read-only inventory, 2026-11-17.** No code, gate, manifest or audit document was
changed by this review. It exists so the three remaining release-safety findings can be taken
through their own review and remediation, rather than accumulated as isolated fixes.

The governing distinction, from ADR-0012 and the register: **a design document wins over this
file where they disagree**. Every statement below is a report of what the source and the
recorded evidence say at `4164fa3`; where a document's own wording is stronger than what the
code enforces, that is recorded as a gap rather than smoothed over.

The three areas have different guarantees and are **not** one finding:

| Area | What must be established | Status today |
|---|---|---|
| F-26 / S-11 | Every production schema-changing path requires a verified recovery point | Open |
| F-26b | Restore recovery is logically correct and durable on supported platforms | Open (Windows) |
| F-26c / S-31 | Ownership and identity stay valid through open, restore and recovery | Open / implemented but not complete |

---

## 1. F-26 / S-11 — the migration snapshot boundary

### Invariant

The register (F-26 row) states: *"Every production schema-changing upgrade holds a verified
pre-migration recovery snapshot, and refuses to migrate without one (S-11-INV)."* The same
row already records that this is **NOT VERIFIED** and that the reason is that `orxnud-store`
still publishes live `Connection` values and G16 is lexical, not a type guarantee.

The code implements a narrower property than the wording claims: the old
`MigrationRunner::run(bool)` and its `NoSnapshot` refusal were **removed** (ADR-0057
D-S11-a), and `migrate(&self, db_path, identity)` (`crates/orxnud-store/src/migration.rs:753`)
always verifies or takes a snapshot before calling the internal `migrate_ephemeral` (`:838`).
So there is no boolean to forge — but there is also no observable refusal, and the
no-snapshot method still exists as a `pub fn` (`:634`). Safety rests on one production entry
point **plus a source gate forbidding the other**, not on a type the caller cannot misuse.

### Production entry points (actual call graph)

1. **Daemon startup, three migrate calls, security-relevant order** — `main.rs:283`/`:464` →
   `runtime.rs:605,613,624,687,709-770`:
   - `SqliteAuditJournal::open` → `security_state.rs:158` — first schema-changing site;
   - `SqliteApprovalLedger::open` → `security_state.rs:418`;
   - `TaskService::open` → `task_service.rs:190-192` → `Store::open` then `migrate`.
   All converge on `migration.rs:753-870`, and all three hit the early return after the first
   one migrates the whole schema.
2. **Public `open_and_migrate`** — `migration.rs:1161-1186`; no in-tree production caller, but
   reachable to embedders. Takes a path and an identity, no boolean.
3. **Connection-returning constructors** — `Store::open` (`sqlite.rs:350-404`),
   `Store::open_in_memory` (`:433-451`, "tests only" in prose but **not `#[cfg(test)]`**),
   `Daemon::probe_store` (`daemon/lib.rs:1492-1499`), and the public accessors
   `Store::conn`/`conn_mut`/`into_connection`/`into_parts` (`sqlite.rs:467,473,479,492`) and
   `SqliteAuditJournal::conn` (`security_state.rs:218`). `rusqlite::execute_batch` takes
   `&Connection`, so DDL is reachable from any of these.

Test-only seams (`test_support::stage_schema` under a feature enabled by dev-dependencies,
in-module `migrate_to`, backup seams) are `#[cfg(test)]`-gated and not this finding's gap.

### Enforcement mechanism

| Control | Class | Where |
|---|---|---|
| No `run(bool)`; single production `migrate` | visibility / API shape | `migration.rs:634,753` |
| Snapshot verified (`integrity_check`, provenance, `schema_meta`, non-empty) | runtime | `backup.rs:705-807`; `migration.rs:1053-1071` |
| Publication and serialisation (staging, rename, fsync, `SnapshotLock`) | runtime | `backup.rs:386-391,439-485,507-577`; `migration.rs:71-98,767` |
| `migrate_ephemeral` forbidden in production source | **gate G16, lexical** | `scripts/gate_policy.py:450-507,510`; exemptions `:444-447` |
| DDL keywords forbidden in production source | **gate G16, lexical** | `gate_policy.py:592-597,623-661` |
| Drift detection (`run(bool)` reappearing, method renamed) | gate G13 self-tests | `scripts/gate-selftest.py:471-640` (22 G16 cases) |

No type-level control prevents a public `Connection` holder from applying DDL, and G16 sees
only literal DDL keywords in this workspace — runtime-assembled SQL is invisible to it.

### Evidence

Named tests recorded in source: `a_failing_file_backed_migration_hands_back_a_snapshot_that_exists_and_verifies`
(`migration.rs:2090`), `a_failed_migration_replaces_a_snapshot_that_does_not_verify` (`:2171`),
`the_journal_constructor_recovers_the_database_when_its_migration_fails` (`security_state.rs:965`),
the ledger counterpart (`:998`), concurrency opens (`security_state.rs:759,811`), and the
feature-isolation test `test_support_feature_is_not_shipped.rs`. Recorded gate results (A-009,
A-010, A-011 in `docs/12`): G16 green, G13 90/90 then 95/95, full gate green — all at the
older test counts; current tree G9 is 1898/1898 with G16 green.

### Remaining gap

The row's own words are the finding: "refuses to migrate without one" asserts a refusal that
no longer exists as an observable path, and the load-bearing control is a lexical gate over
one workspace. An embedder, or a build that does not run G16, can reach `migrate_ephemeral`
or a public `Connection` and change schema without a verified snapshot.

### Exact condition to close it

1. A verified snapshot becomes an **unforgeable type prerequisite** for applying schema SQL —
   a token constructible only by the snapshot-owning coordinator after `verify`/`take`, which
   ADR-0057 D-S11-a explicitly considered and rejected at `docs/09:6234-6245`. A decision is
   needed to revisit that rejection.
2. A `compile_fail`-style test proving that a caller holding only a public `Connection` and a
   `Path` cannot obtain the apply capability — with G16 **disabled**, so the proof does not
   depend on the gate it is meant to replace.
3. Every public live-`Connection` return in §"entry points" removed or made DDL-incapable,
   with a public-API survey as evidence.
4. The F-26 wording and ADR-0057 reconciled with whichever mechanism is chosen.
5. S-11's full specification produced and each acceptance criterion discharged — that
   specification is **not in this repository** (`docs/09:6222-6223`), so this row cannot be
   closed from the evidence available here.

---

## 2. F-26b — restore recovery and durability

### Invariant (A-042, four clauses)

1. **No false success** — `Ok` only when the post-install logical digest equals the snapshot's.
2. **The intent is the commit point** — published only after contents *and* parent directory
   entry are durable; every interruption until `clear_intent` is completed on next open;
   installs are idempotent.
3. **Pre-commit failures are logically state-preserving** — the guard's checkpoint changes
   bytes, not logical content.
4. **Platform precondition** — a platform that cannot make the intent's directory entry
   durable refuses before staging, intent or install.

### Production entry points

- `Backup::restore_coordinated` (`backup.rs:1010`) — public production entry; acquires its
  own guard. Reached from `migration::recover_from_snapshot` (`migration.rs:1210`), the two
  `security_state.rs` constructors (`:170,427`), `open_and_migrate` (`:1177`) and
  `task_service.rs:214`.
- `Backup::restore` (`:849`) and `RestoreGuard::acquire_with` (`:1180`) are `pub(crate)`;
  the target comes from the guard, never the caller.
- `restore_with_lease_for_tests` (`:976`) is a plain `pub fn` **compiled into production**,
  with no `#[cfg(test)]`; it demands the same exclusive lease the restore already requires,
  so it grants no new authority, but it is a production API surface.
- Crash recovery runs on **every open** through `ownership::acquire_shared`/`acquire_exclusive`
  (`ownership.rs:515,551`) → `complete_outstanding_restore` (`recovery.rs:877-938`), covering
  `Store::open`, both security-state opens and the restore guard itself. Gate **G17** checks
  this boundary by source inspection.

### Enforcement mechanism

Clauses 1–3 are enforced by code: digest verification before publish (`backup.rs:908-926`)
and again inside `install_staged` (`recovery.rs:746-757`); `fsync_file(staging)` →
`fsync_dir(parent)` → `publish_intent` ordering (`backup.rs:928-947`, `recovery.rs:480-511`);
failures before publish leave the live database unchanged. Clause 4 is a **runtime refusal**:
`Durability::require()` (`recovery.rs:372-390`) uses
`directory_fsync_supported()` (`backup.rs:1037-1045`) and is called at `backup.rs:862`, after
the state-preserving checkpoint but before staging. `fsync_dir` is a documented no-op when
unsupported (`recovery.rs:431-433`) — safety depends entirely on `require()` having refused.

The seven `#[cfg(test)]` fault seams (`BeforeIntentPublish`, `AfterIntentPublish`,
`DuringCopy`, `BeforeFinalize`, `DuringVerification`, `BeforeClearIntent`, `DirectoryFlush`;
`recovery.rs:104-123`) and nine scenario tests (`:1186-1891`) are the evidence for clauses 1–3
on Linux. The ordering test `the_staged_images_parent_directory_is_flushed_before_the_intent_is_published`
(`:2023`) and the fault test `a_failed_directory_flush_prevents_progression_to_destructive_work`
(`:2074`) pin the directory discipline.

### Remaining gap

Clause 4 is code-enforced and documented but **untested on Windows**. A-042's four-assertion
test is designed, not written. The Windows CI lane `windows-portability` selects only
`s31_alias_safety` and `s31_windows_identity` (`.github/workflows/ci.yml:351-356`), so a unit
test added to `recovery.rs` would not run there without a target selection change.

**Precision correction to A-042:** the design says to assert a `DurabilityUnavailable` error.
At the public API boundary the error is rendered as `BackupError::Io` whose text names the
missing directory durability (`recovery.rs:332-339`, used at `backup.rs:862`). The test should
assert the message, not a variant that callers never see.

### Exact condition to close it

- **Bounded slice (can be done now):** a `cfg(windows)` test calling `restore_coordinated`
  with a valid snapshot, asserting (a) refusal text naming directory durability, (b) no
  intent, (c) no staging file, (d) unchanged logical digest despite the preceding checkpoint;
  plus a Windows CI selection that runs it. This evidences clause 4; it does **not** establish
  Windows crash recovery.
- **Windows crash recovery (separate):** a native directory flush (`FlushFileBuffers` on a
  `FILE_FLAG_BACKUP_SEMANTICS` handle) that makes `directory_fsync_supported()` true and
  `fsync_dir` real; `require()` then permits restore; the **same** seven seams and nine
  scenarios run on Windows with clauses 1–4 asserted; CI selects them. Without the primitive,
  a crash-mid-restore Windows test would be vacuous because no restore reaches the commit point.

---

## 3. F-26c / S-31 — ownership and identity

### Invariants, kept separate

- **F-26c:** *a database reached through more than one name is refused, and a file replaced
  during the open is detected unless replaced and restored inside the window* (ADR-0058
  Decision 4, `docs/09:6597-6600`). Detection implemented is **not** bypass eliminated
  (`:6501-6505`).
- **S-31:** stable exclusive ownership across processes for the whole restore lifecycle.
  Closure requires an explicit acceptance decision for the narrowed threat model **or**
  elimination of the bypass: "a known bypass **or an unaccepted residual window**" keeps it
  open (`docs/09:7064-7069`).

ADR-0058 explicitly permits: refusing when identity is unknown (`:6497,6547-6559`); treating
the residual window as **not closed** (`:6498,6579-6595`); and S-31 remaining open while a
window is unaccepted (`:6499`). It explicitly does **not** accept the residual window, and
does not propose a descriptor-backed/VFS approach (`:6591-6595,7125-7128`).

### Production entry points

- `alias::open_shared` (`alias.rs:633-696`) and `open_exclusive` (`:712-754`) — the two ordinary
  open choke points. Order: sidecar observe → lease → pre-check path → `Connection::open`
  **by filename** (`:656`) → post-check path → handle observation → main check.
- `ownership::acquire_shared` (`:486-525`) and `acquire_exclusive` (`:543-554`) — lease first,
  recovery state read under lease; `resolve_lease_target` (`:262-315`) canonicalises the parent
  and never falls back to caller text.
- `backup::RestoreGuard::acquire_with` (`:1180`) — exclusive open, sidecar re-verification,
  then checkpoint.
- `recovery::install_staged` (`:662`), `finalize_log` (`:777`) and `live_digest` (`:840-850`)
  open the live database **without alias checks by design**, under the exclusive lease; the
  register records this as a bounded exception (`docs/12:1321-1332`).
- `Store::open` (`sqlite.rs:350-404`) requires `&dyn FilesystemIdentity` with no default.
- Plain-`pub` test seams compiled into production: `acquire_exclusive_for_tests`
  (`ownership.rs:396`), `acquire_shared_for_tests` (`:410`), `restore_with_lease_for_tests`
  (`backup.rs:976`). All demand the same authority as the production path.

### Enforcement mechanism

| Control | Class | Platform |
|---|---|---|
| Link count + two-sided path identity | runtime, refuse on `Unknown` | Unix `st_nlink`; Windows native `FileStandardInfo` |
| Symlink resolution for the lease key | runtime, fail-closed | all |
| SQLite main-handle identity | runtime | Windows only; Unix `NotApplicable` (not a pass) |
| Sidecar alias verification (path only) | runtime | all; handle identity deliberately not compared |
| Exclusive lease + private ownership fields | runtime + type-level authority | all |
| "Every production open goes through the boundary" | **gate G17, lexical** | CI |

### Residual threat

Between `pre_check` (`alias.rs:655`) and the post-open observation (`:663-665`), SQLite is
opened by filename. A path changed **and changed back** inside that window is not detected.
Unix main DB and sidecars on every platform remain path observations; Windows main-DB handle
was closed for the tested scope by A-018, but links created after the handle check, sidecars,
and Windows long paths / network-share identity remain as recorded (`docs/12:2240-2255,2284-2287`).
The capability required to create a hard link in the state directory is the daemon's uid, and
a same-uid hostile process is explicitly **outside** the stated threat model, so this is a
**named, untested local TOCTOU window**, not a demonstrated exploit and not a proven
impossibility.

### Closure conditions — separate

- **F-26c:** either close the residual window, or **explicitly accept** it with a recorded
  decision naming the narrowed guarantee. The register is unambiguous: "Closing F-26c needs
  the residual window closed or explicitly accepted, and neither has happened"
  (`docs/12:2052-2058`). Closing the hard-link bypass alone, or green Windows focused suites
  alone, is not sufficient.
- **S-31:** an explicit acceptance decision for the narrowed threat model, or elimination of
  the bypass — and it cannot be declared complete while the F-26c window is merely named.
  Preserved two-process interleaving results, G17 and required-capability typing accompany
  closure but do not substitute for the decision.

No VFS or unsafe descriptor-backed implementation is proposed by this review, per the
instruction to establish the threat first.

---

## What this review does not claim

No code, gate, manifest, ADR or register entry was changed by this pass; all tests and gate
results quoted are the repository's own recorded numbers, not results re-run here. No finding
is closed by this document. No statement is made that the residual alias window is locally
exploitable or impossible to win. Windows crash recovery is not claimed for any build of this
tree. S-31 is not complete merely because its original bypass was closed, and S-11 is not
closed from a specification that is not present in the repository.

| | |
|---|---|
| **date** | 2026-11-17 |
| **basis** | `main` at `4164fa3` (after PRs #4–#12) |
| **method** | read-only source and evidence inventory; three areas traced independently |
| **next** | one finding at a time, through its own review and remediation; the bounded F-26b Windows refusal test and the TUI's proposal-list/history slice can proceed in parallel |
