# 13 — Phase 1 Implementation Contract

Status: **Delivered** · Executed as Phase 1 (commit `2f331ed`), with Phase 2 built
on top of it. This document remains the record of what Phase 1 promised: the
workspace, the crate graph, the twelve gates, and the ADR-0029 conformance
machinery. Where the implementation corrected the contract, the correction is
recorded in `12-verification-register.md` (amendments A-001 … A-004) rather than
quietly folded in here.

---

## 1. Objective

Establish the workspace, the crate graph, the enforced boundaries, and the
conformance machinery — with **zero features** working.

> **Phase 1 succeeds when the architecture is mechanically enforced and nothing
> works yet.** A passing test suite that proves a capability can *do* something
> would mean Phase 1 overran.

---

## 2. Preconditions — all met

| # | Precondition | Status |
|---|---|---|
| 1 | Rust 1.98.1 stable, edition 2024, rustfmt/clippy/rust-analyzer/nextest/deny | ✅ verified |
| 2 | Tauri Linux native deps (webkit2gtk 2.54.0 etc.) | ✅ verified, link-tested |
| 3 | Architecture documented; 32 ADRs with revisit conditions | ✅ |
| 4 | Verification register with sources and triggers | ✅ `12-…` |
| 5 | Node 24.21.0 LTS project-local, checksum-verified | ✅ ADR-0031 |
| 6 | `apalis-sqlite` contingency closed | ✅ ADR-0032 |
| 7 | Repository initialised, signed commit, tree clean | ✅ |

**Explicitly NOT preconditions** (they do not gate Phase 1): Q-OPEN-01 (Telegram
legal review), Q-OPEN-05…Q-OPEN-21.

---

## 3. Deliverable 1 — the workspace

**One Cargo workspace, `resolver = "3"`, edition 2024, MSRV 1.98.1 declared in
`[workspace.package]`.**

### 3.1 Crate graph (exact)

```
orxnud-domain        ── pure types + invariants. Deps: serde, serde_json,
                            thiserror, zeroize. No I/O. No async. No platform.
                            No storage. (Amended: the contract originally said
                            serde/thiserror only; see register A-001. Both added
                            crates are pure and portable, and gate G2 asserts
                            the list mechanically.)
       ▲
       │ depends on (types only)
orxnud-protocol      ── local wire types. The ONLY crate interfaces may use.
       ▲
       │
orxnud-store         ── SQLite repositories, migrations, backup/restore.
orxnud-policy        ── permissions, risk, approval digest, egress, budget.
orxnud-task          ── task table, scheduler, leases, idempotency, DLQ.
orxnud-capability    ── registry, contracts, dispatcher.
orxnud-audit         ── append-only hash-chained journal.
orxnud-config        ── layered config + schema versioning + migration.
orxnud-obs           ── tracing wiring + redaction + optional OTLP.
       ▲
       │
orxnud-daemon        ── composition root, supervision, lifecycle, single-instance.
orxnuctl             ── the CLI. Depends on protocol ONLY.
```

**Platform adapters** (Phase 1 creates only the three with no OS risk):

```
orxnud-platform-fs           orxnud-platform-secrets      orxnud-platform-notify
```

**Deferred to later phases** (declared here so the seams are visible, not created
now): `platform-process`, `platform-net`, `platform-audio`, `platform-single-instance`,
`platform-autostart`, `orxnud-llm`, `orxnud-voice-in/out`, `orxnud-web`, `orxnud-mcp`,
`orxnud-msg`, `orxnud-otel`, all `orxnud-domains-*`, all interfaces.

### 3.2 Dependency rules — enforced, not documented

| Rule | Enforcement |
|---|---|
| Deps point **inward** toward the core; never sideways | workspace member dependency lists; a violation is a compile error |
| `orxnud-domain` has no I/O, no async, no platform dep | its own dependency list is the check |
| Interfaces depend on `orxnud-protocol` **only** | not created in Phase 1; recorded as a Phase 6 gate |
| `cfg(target_os)` / `cfg(windows)` / `env::consts::OS` appear **only** in `orxnud-platform-*` | **CI grep gate** (see §5) |
| The portable core builds with no platform crate available | **CI check:** `cargo check -p orxnud-domain -p orxnud-protocol --target wasm32-unknown-unknown` (or equivalent), proving the boundary is real rather than asserted |

---

## 4. Deliverable 2 — foundational types

### 4.1 `orxnud-domain` — pure, no I/O

Required types, each with its invariants **tested**:

- **`Actor`** (ADR-0027) — the six variants. `Ai` carries `delegated_by`;
  `Integration` carries `granted_by`; `Scheduled` carries `authorised_by`.
  Invariant: an `Ai` actor's authority is derived from its `Human`, never
  independent.
- **`UserId`, `TaskId`, `RunId`, `ScheduleId`, `GrantId`, `CapabilityId`,
  `RequestId`, `ModelProvenance`** — opaque newtypes. **Never** derived from
  filesystem paths (cross-platform: Windows and macOS are case-insensitive by
  default; `nul` is legal on Linux and destroys data on Windows).
- **`Proposal`** (ADR-0012) — **inert**. Fields only. **No method that reaches an
  adapter.** A compile-fail test asserts the absence.
- **`ActionRequest`** — validated, pre-policy.
- **`CapabilityInvocation`** — carries `actor`, `task_id`, `step_key`,
  `capability_id`, `adapter_id`, `params`, data classes, `idempotency_key`,
  `deadline`, `cancellation`, `policy_context`.
- **`RiskClass`, `ApprovalLevel`, `DataClass`, `IsolationTier`, `StateClass`**
  — closed enums, with `unknown ⇒ RiskClass::High` as a **constructor** invariant,
  not a runtime check at the call site.
- **`ApprovalDigest`** — deterministic hash over
  `(actor, capability, target, normalised_params, issued_at, expiry)`.
  Invariant: any single-field mutation changes the digest (property test).
- **`TaskState`, `TaskKind`, `ScheduleSpec`, `MisfirePolicy`** — the state machine
  of ADR-0029, as data.

### 4.2 `orxnud-protocol`

JSON-RPC 2.0 framing for the local transport (ADR-0003). Version negotiation;
`protocolVersion`; capability advertisement; **forward compatibility** — unknown
methods return a well-formed "unknown method" error and unknown fields are
ignored, both tested.

**Explicitly NOT in Phase 1:** the HTTP adapter, TLS, auth, and the cloud profile.

---

## 5. Deliverable 3 — the CI gate (the real deliverable)

Phase 1's job is to make violations **fail the build**, not to document them.

| Gate | Command / mechanism | Fails on |
|---|---|---|
| Format | `cargo fmt --all -- --check` | any deviation |
| Lint | `cargo clippy --all-targets -- -D warnings` | any warning |
| Test | `cargo nextest run` | any failure |
| Supply chain | `cargo deny check` | advisories, unapproved licences, duplicates, bans |
| Vulns | `cargo audit` | any known advisory |
| Semver | `cargo semver-checks` | breaking change without a major bump |
| **Platform boundary** | **CI grep:** `cfg(target_os)` / `cfg(windows)` / `std::env::consts::OS` outside `orxnud-platform-*` | a platform branch in the portable core |
| **Copyleft** | `cargo deny` licence allowlist — **no GPL/AGPL/NC in any crate** | a licence regression (ADR-0006, ADR-0019) |
| **Portable core** | `cargo check` of domain+protocol for a target with no platform crates | an accidental platform dependency |
| **No `unsafe`** | Phase 1 target: **zero** `unsafe` blocks outside `platform-*` | any `unsafe` in the core (ADR: `08-…` §14) |
| **Secret hygiene** | CI grep for `.env`, PEM headers, `sk-`/`gho_` patterns | a committed credential |
| Windows build | MSVC toolchain, `cargo check` only in Phase 1 | a Windows-incompatible construct (ADR-0026) |

**CI runtime budget:** the Linux PR lane < 10 min. Windows is a **nightly**
`check` in Phase 1 (full test parity arrives with the GUI, because WebView2 and
Tauri need a real Windows runner).

---

## 6. Deliverable 4 — `orxnud-store` with two hard requirements

### 6.1 Bundled SQLite, version-asserted (ADR-0006)

- `libsqlite3-sys` with the **`bundled`** feature. **Never** the system library.
- **A compile-time assertion that the bundled `SQLITE_VERSION_NUMBER >= 3.51.3`.**
  A build that fails this does not compile. This is the *checkable* form of V-02.
- The pinned `SQLITE_SOURCE_ID` and SHA-256 recorded for the SBOM.
- **A test that reads the pragma back** and asserts `journal_mode=wal` and
  `synchronous=FULL` on the task connection. Reading it back matters: the
  assertion catches a pragma that silently failed to apply.

### 6.2 Repository layer (ADR-0006, ADR-0028)

- Domain operations only. **No raw-SQL escape hatch** in the public API.
- Every state region registered with: class, single owner, consistency, retention
  (ADR-0028). The registry is the artefact that answers *"which state may the
  model write?"*
- `critical` regions on a `synchronous = FULL` connection; `derived` regions
  explicitly **writable by the intent layer** and **provably not readable as
  authority** — the repository filter, tested with a query that *must* exclude
  derived rows.
- Migrations: forward, transactional, idempotent, snapshot-protected (ADR-0017).
  **No application tables yet** — Phase 1 creates the migration *machinery* and
  one `schema_meta` table, nothing else.

---

## 7. Deliverable 5 — the ADR-0029 conformance harness

**This is the highest-value item in Phase 1** and the reason the task engine is
replaceable. Twelve properties, each with a named test. The harness is the
deliverable; the queue is not.

| Property | Phase 1 test | Requires a queue? |
|---|---|---|
| TP-1 no silent disappearance | kill-at-N-random-points, assert every row reaches terminal or provably-owned | yes |
| TP-2 exactly-once where required | injected outcomes; `idempotent:false` + uncertain ⇒ `needs_verification` | yes |
| TP-3 cancellation observable | cancel recorded **before** acted on; survives restart | yes |
| TP-4 restart recovers | no row left `running` with a dead owner | yes |
| **TP-5 expired leases cannot execute** | **zombie worker**: force lease expiry, then let the original worker attempt to commit — **it must fail** | yes |
| TP-6 retries never inherit approvals | retry after approval expiry is refused by policy; actor re-derived | partly |
| TP-7 power loss cannot corrupt | kill-at-random-points; state is pre- or post-transaction, never torn | yes |
| TP-8 DST/clock determinism | property tests over spring-forward, fall-back, and clock jumps | yes (schedule only) |
| TP-9 catch-up bounded | a week offline does not execute a week of backlog | yes |
| TP-10 bounded resources | every spawn has a concurrency limit | no |
| TP-11 dead-letter terminal | permanently failing task dead-letters and stops | yes |
| TP-12 side effects accounted for | no effect without a recorded result or explicit "unknown" | partly |

**Honest scoping:** several of these need a queue to be meaningful. Phase 1 builds
the **harness** (kill-at-random-points, the zombie-worker rig, the clock/DST
property generators, the atomic-claim fixture) as reusable infrastructure, and
runs them against a **minimal reference queue fixture** — a deliberately trivial
in-test implementation whose only job is to make the properties executable. The
real queue arrives in Phase 2, and must pass the same suite unchanged.

> That is the whole point of specifying properties instead of an implementation:
> **the suite is written before the thing it tests.**

---

## 8. Explicitly NOT in Phase 1

Stated so scope cannot drift:

| Not built | Why |
|---|---|
| Any **capability** (ASR, TTS, LLM, browser, messaging) | Phase 4+. Phase 1 builds the *registry* and the *dispatcher* shell, wired to nothing |
| The **task queue implementation** | Phase 2. Phase 1 builds the conformance harness |
| Any **interface** — GUI, TUI, CLI commands beyond `--version`/`doctor` | Phase 6. Only protocol types are created |
| **Tauri / Svelte / Vite / pnpm** | Phase 6. Node is provisioned (ADR-0031) but unused until then |
| **Windows MSI, installers, signing** | Procured in parallel (lead time), built in Phase 5 |
| Any **schema beyond `schema_meta`** | The brief prohibits creating application schemas in this phase |
| **Migrations for real tables** | Machinery only |
| **A second SQLite writer, any server, any daemon** | Prohibited (ADR-0006, V-24) |
| **Any heuristic, tuning, or optimisation** | There is nothing to optimise yet; premature tuning is a cost |
| New architecture | Phase 1 implements `03-…`. It does not amend it. |

---

## 9. Exit criteria

Phase 1 is complete when **all** hold, and not before:

- [ ] Workspace builds clean on Rust 1.98.1, edition 2024, `cargo check --all-targets`
- [x] All 12 CI gates green, including the platform-boundary grep and the licence gate — `scripts/ci-gates.sh` exits 0. G12 (semver) skips visibly until a release tag exists; it is not counted as green.
- [ ] **Zero** `unsafe` outside `platform-*`
- [ ] `orxnud-domain` and `orxnud-protocol` compile for a target with no platform crates
- [ ] Bundled SQLite ≥ 3.51.3, asserted at **compile time**, and pragmas verified by a test that reads them back
- [ ] `orxnud-domain` invariants property-tested (actor derivation, risk defaulting, digest mutation-sensitivity, state-machine legality)
- [ ] A compile-fail test proves `Proposal` has no method reaching an adapter
- [ ] `CapabilityInvocation` cannot be constructed outside `orxnud-policy`'s API
- [ ] The ADR-0029 harness runs end-to-end against the reference queue fixture, with all 12 properties reported
- [ ] Windows `cargo check` green on the nightly lane — **partly open (V-29)**: on this development host the six crates behind bundled SQLite are blocked by a missing MSVC C toolchain (`cc-rs: failed to find tool "lib.exe"`), not by a code defect, and no Rust-level error was observed in any of them. The other **9 of 15** crates — including all four platform adapters, `orxnud-domain`, `orxnud-protocol`, `orxnud-config`, `orxnud-obs` and `orxnuctl` — check clean for MSVC, and a second lane now runs the platform-neutral suites as tests rather than only compiling them. Windows *sandbox isolation* remains NOT PROVEN and is refused at runtime rather than degraded.
- [ ] `cargo deny`, `cargo audit`, `cargo semver-checks` green; zero GPL/AGPL/NC
- [ ] Repository `schema_meta` only; **no application tables**
- [ ] **Zero capabilities enabled; zero features working**
- [ ] No global machine state changed: `PATH`, shell init, `.gitconfig`, Hermes, and the default `node` all identical to their pre-Phase-1 values
- [ ] `docs/12-verification-register.md` reviewed; any new external claim has a V-ID, source, trigger, date, and consequence

---

## 10. Phase 1 test philosophy

Tests are the deliverable, so they are written to the *specification*, not to the
implementation:

1. **Property tests, not examples**, for every invariant that has a quantifier
   ("all mutations", "all transitions", "all clock jumps").
2. **Harnesses over unit tests** where failure modes are interleavings: kill,
   expiry, cancellation, time.
3. **Every property is reported per-run** (12 named results), so a regression names
   the property rather than a line number.
4. **Compile-fail tests** for the negative space — what must *not* be constructible
   or reachable (ADR-0012).
5. **The tests must be readable as the specification.** If a reader cannot tell
   from the test what property is being enforced, the test is not finished.
6. **No mocked SQLite for durability tests.** Real files, real WAL, real fsync. A
   `:memory:` database cannot test power-loss, migration-on-existing-file, or WAL
   recovery — testing those in memory is testing nothing.
7. **Deterministic time and IDs** via `Clock` and `IdGen` traits, so DST and
   golden-file tests are exact rather than flaky.

---

## 11. Risks specific to Phase 1

| Risk | Impact | Mitigation |
|---|---|---|
| **TP-5 fencing is easy to get subtly wrong** — check the lease at claim but not at commit, and a zombie worker commits | Silent duplicate side effects | The zombie-worker rig is a **named, isolated Phase 1 deliverable**, not part of the bulk |
| Building the harness without the real queue gives false confidence | Holes discovered in Phase 2 | The fixture is deliberately minimal; the suite is written first and re-run unchanged against the real thing |
| Crate-graph bikeshedding | Phase 1 becomes design work | The graph in §3.1 is **fixed by this contract**; deviating requires an ADR |
| Premature `unsafe` for SQLite ergonomics | Licence/safety policy erosion | Compile-time-zero target + grep gate; `rusqlite` needs none |
| Windows lane added too early and breaks the PR budget | CI cost, ignored gates | Windows is `check`-only and **nightly** in Phase 1 |
| Scope creep into a first capability | Phase 1 overruns; boundaries unproven | §8 is explicit; "zero features working" is an exit criterion, not a shortfall |

---

## 12. What Phase 1 must **not** decide

To protect the next phases from inheriting premature commitments:

- Which **LLM provider** is default (none is — ADR-0011)
- Which **ASR/TTS engine** beyond the declared default capability id (ADR-0014)
- The **config schema v1 shape** (mechanism only; the schema is Phase 2)
- The **domain model** for any FR-01..FR-15 domain
- Whether **macOS** is promoted to T-A (ADR-0023 — not until we can test it)
- Anything requiring **legal review** (Q-OPEN-01 Telegram)

If Phase 1 finds itself needing any of these, that is a signal the contract is
wrong — raise it, do not decide it here.
