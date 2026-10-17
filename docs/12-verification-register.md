# 12 — Verification Register & Freshness Policy

Status: **Draft v0.5** · Adopted 2026-09-30 · last reconciled **2026-10-10** against
`HEAD` (`1fa2d0b`); previously reconciled 2026-10-08 against `c5934970`.

96 V-rows (V-01 … V-97, V-44 deliberately unused) plus one non-V row, `K.1`, so 97 bolded
table rows in total. **`F-26` was added to §2 on 2026-10-14, taking that total to 98.** (The
pre-existing discrepancy between "96" and the rows actually present in §2 is left as found; it
is not this row's business to reconcile, and guessing a corrected total would be a second
unsourced number in a register whose whole purpose is that its numbers are sourced.) No V-ID appears twice. V-96 was reclassified from `*(undefined)*` to a
recovered definition on 2026-10-10; see the note below. Every V-ID cited anywhere in `docs/`
is present here, with the single exception of **V-44**, which is cited in `09-decisions.md`
and `README.md` *as* the deliberately-unused identifier.

**Three numbering gaps, all deliberate**, recorded rather than renumbered because
renumbering would break every existing citation, and because a silent gap is
indistinguishable from an omission — which is precisely the failure this register exists to
catch: **V-44** is unused, and **ADR-0041** and **ADR-0042** are unused. A future entry that
needs V-44 or ADR-0041 should take it rather than skip past it. A fourth, **V-96**, was
until 2026-10-10 recorded in this file as a fourth, *undeliberate* gap; that record was
wrong and is corrected below.

**The fourth gap, V-96, is now closed, and it was closed here by recovery rather than by
invention.** V-93, V-94, V-95 and V-97 were carried out and are recorded below as of this
reconciliation. This register, until 2026-10-10, also recorded V-96 as `(undefined)` and
asserted that *no definition of V-96 exists anywhere in this repository — not in `docs/`,
not in the commit history, not in the tree*. **That assertion was false**, and it was false
in a way this register exists to prevent, because the evidence was in this repository the
whole time.

V-96 was defined, implemented and cited:

* **Defined** — `08-testing-engineering-standards.md` §"Platform boundary", row
  `cfg(target_os)` gate: *"**V-96:** it matched raw text, so a comment could switch it off
  and seven of nine `cfg` spellings -- every nested one -- were invisible; G3 now classifies
  source lexically and reads predicates at any depth. Self-tested against fixtures by gate
  G13."*
* **Implemented** — commit `7bf9da8` *"test(ci): drive the boundary gates against adversarial
  rewrites"*, which added the fixture-driven self-tests and the lexical classifier
  (`scripts/rustscan.py:58-176` `code_mask`, a real Rust lexer for nested block comments,
  raw strings, escapes and the char-literal/lifetime ambiguity;
  `scripts/gate_policy.py` predicate reading at any depth;
  `scripts/gate-selftest.py:126-135`, which drives the **real** `scripts/ci-gates.sh` over
  temporary fixture trees and reads the process exit code as the verdict).
* **Cited** — the same `08` row, and commit `b73246d` *"refactor(gates): anchor G2d on the
  authority surface policy now owns"*.

**How the false claim survived.** It was written during a reconciliation that correctly
found V-93/V-94/V-95/V-97 *missing* from this file, and the search that established "V-96 is
undefined" looked for a row here rather than for the identifier across `docs/`. An
identifier that is defined in one document and numbered in another is exactly the
cross-document drift this file is supposed to make visible; asserting its absence, in the
document whose job is to be complete, turned a reconciliation into a fabrication. The row
has been rewritten below from recovered evidence. **Nothing was renamed and no identifier
was invented.**

**What this does not claim.** The recovered row records the fix that exists, and it names
the residual gap found on 2026-10-10 rather than closing over it: gate G3 still matches
platform API paths *literally*, so importing the path once under an alias defeats it.

> **What was stale before this reconciliation, recorded because the drift is the lesson.**
> The header claimed 86 entries / V-01…V-87 while the file already contained V-88 through
> V-92, and V-93/V-94/V-95/V-97 had landed in `main` with **no** entry at all. Four
> verification slices of real work were undocumented, and the artifacts proving them
> (`v94_reproduction.rs`, `v95_atomicity.rs`, `v95_concurrency.rs`,
> `v97_effect_visibility.rs`, `v97_proposal_identity.rs`) sat in the tree with nothing
> pointing at them. A register that under-reports is worse than no register, because it
> asserts a completeness it does not have.

**What "verified" means here.** A `last verified` date is a claim that the verification
source was *read on that date*, not that nothing has changed since. Where an entry's
trigger has fired and the entry has been re-read, the row says so in its prose. Where a
trigger has fired and the entry has *not* been re-read, that is the register's own failure
mode and several rows below now name it.

---

## 1. The rule

> **Every architectural claim in this repository that can become false over time
> MUST have:**
>
> 1. a **verification source** — the authoritative place that would tell us it
>    changed, and
> 2. a **review trigger** — the specific, checkable event that makes us re-read
>    it, and
> 3. a **last-verified date**, and
> 4. a **named consequence** if it silently drifts.

A claim without these is an assumption wearing a decision's clothes. This
register makes the difference visible and gives each claim an owner.

**Why this exists.** Every major architecture decision in `09-decisions.md` rests
on an external fact that will change: a spec revision, a release, a licence, a
platform requirement. The TypeScript 7 incident in ADR-0005's amendment record is
the worked example: a claim that was *true but insufficiently checked* became a
wrong architectural decision, and it was only caught by a second reviewer. This
register exists so that the next such claim is caught by a *process*, not by
luck.

---

## 2. The register

Legend — **Cadence**: `event` (re-checked on a named trigger) · `quarterly` ·
`release` (re-checked before each release) · `milestone` (re-checked at a named
phase gate).

| ID | Claim | Verification source | Cadence / trigger | Last verified | Consequence of silent drift |
| **F-26** | **Every production schema-changing upgrade holds a verified pre-migration recovery snapshot, and refuses to migrate without one (S-11-INV).** | **NOT VERIFIED. F-26 is OPEN and S-11 is not implemented.** **AMENDED 2026-10-17 (A-009): the trust-me APIs are gone, which removes the specific mechanism this row cited but does not close the finding.** `MigrationRunner::run(bool)`, the `snapshot_verified_by_caller` parameter on `migrate`, the `snapshot_verified` parameter on `open_and_migrate`, `MigrationError::NoSnapshot`, and both `SqliteAuditJournal::migrate(&Connection)` / `SqliteApprovalLedger::migrate(&Connection)` helpers **no longer exist in the source**, so the six entry points this row named are not reachable by those names. The four `security_state.rs` callers now go through `migrate(path)` and recover through `migration::recover_from_snapshot`, with tests driving both production constructors to a genuine mid-migration failure and asserting the restored `schema_meta`, `audit_log` and `spent_approvals` state. Gate **G16** refuses the one remaining unprotected path (`migrate_ephemeral`) in production source and is exercised in 16 directions by G13. **Still open:** F-26b and F-26c (hard-link alias, ADR-0058 — research candidate, not approved), and S-11's wider specification. The original 2026-10-14 text follows, retained because it records what was measured.**

The snapshot *mechanism* is implemented and separately covered: `Backup::take` uses SQLite's online backup API (`backup.rs:164`), `verify_impl` runs `PRAGMA integrity_check` and requires `schema_meta` (`backup.rs:258`), `verify_against_source` compares against the source (`backup.rs:229`), `migrate` verifies-or-takes and restores on failure (`migration.rs:396`). **The invariant is not, because `run(snapshot_verified: bool)` trusts the boolean** (`migration.rs:299`) rather than requiring a snapshot to exist, and **six production entry points reach it**: `task_service.rs:170` (`migrate(path, false)`, correct); `security_state.rs:92`, `:116`, `:270`, `:290` (all `.run(true)`); and `migration.rs:468` `open_and_migrate`, which forwards an unverified caller boolean straight into the trusting API. Two of the four (`SecurityState::migrate`, `Ledger::migrate`) take only `&Connection` and therefore **cannot** snapshot as written. `Ledger::open` is reachable in production at `daemon/src/lib.rs:908`. **Existing coverage does not reach any of them**: the single test of the snapshotting path is `migration.rs:1137`, and no test drives a production entry point. **A second, distinct defect was measured on 2026-10-14.** `Backup::restore` rewrites the main file but never neutralises `state.db-wal`/`state.db-shm` (`backup.rs:351`). Measured against the real mechanism: the production path (restore while the runner's connection is open) is **safe**, but replaying a **stale `-wal`** beside a restored main file makes **post-snapshot data resurface — deterministically, 3/3 repeats** — while `PRAGMA integrity_check` returns **`ok`**, `schema_meta` still reads the pre-snapshot version, and `Backup::verify` still passes. SQLite's salt check does not prevent it, and structural post-restore checking is therefore **proven insufficient**. The invariant this forces is **S-11-RESTORE** in ADR-0057: sidecar removal is a *precondition of the restore*, and the post-restore guarantee must be **logical**. **The two halves are now tracked separately and the dependency is hard.** S-30 (`S-11-RESTORE`,
§7-S30) owns the restore defect; S-11 (§7-S11) owns the six entry points. **S-11 is blocked on
S-30** and must not claim safety until S-30's five acceptance criteria hold — a coordinator whose
rollback can return `Ok(())` while restoring the wrong state would make its own safety claim
false. Both are P1; the split is scope and test boundary, not severity. D-S11-a is approved,
D-S11-b approved in principle, D-S11-c measured.

**Update 2026-10-14: S-30 is now implemented and its five acceptance criteria are met — see
A-007. F-26b is nonetheless recorded as still open**, on the grounds A-007 sets out: the
invariant is enforced within one process only, and a failed restore after a stale log was
folded in leaves post-snapshot data absorbed rather than discarded. It fails closed rather than
reporting success, but that is not a clean rollback and this row does not claim it is.
**S-11 is not unblocked by this**, and S-29 remains blocked behind S-11 (§6.4). | **event:** any change to `MigrationRunner`, `Backup`, `Store::open`, `open_and_migrate`, or any function that calls `migrate(`, `migrate_ephemeral(` or `Backup::take`; and on any change to gate **G16** or to `scripts/rustscan.py`'s test-region rules, which that gate depends on; and on any change adding a persisted table, column, `CHECK` constraint or task-state value, which is gated on S-11 (§6.4) | 2026-10-17 (**A-009 applied; confirmed still open**) | **High.** A migration failure on a production upgrade leaves a half-applied schema and the only copy of the user's data with no verified way back. Four of six entry points cannot produce one even on request. |

|----|-------|--------------------|-------------------|---------------|---------------------------|
| **V-01** | **MCP spec revision is `2026-07-28`; the protocol is stateless; Sampling/Roots/Logging are deprecated with a ≥12-month window; Tasks is an extension** | `https://modelcontextprotocol.io/specification/latest` and the versioned changelog at `/specification/2026-07-28/changelog` | **event:** any new revision date on the latest page; plus quarterly | 2026-09-30 | **High.** A new revision may reintroduce sessions, change the Tasks extension, or move a deprecation to removal. Our MRTR mapping and our stateless-safety argument (ADR-0010) both depend on it. |
| **V-02** | **SQLite minimum bundled version is ≥ 3.51.3** (WAL-reset corruption fix) | `https://www3.sqlite.org/releaselog/3_51_3.html`; WAL semantics at `https://sqlite.org/wal.html` | **release:** verify the bundled `SQLITE_VERSION_NUMBER` at build time; **event:** any new SQLite release note mentioning corruption | 2026-09-30 | **Critical.** Below 3.51.3 the task table can corrupt under our exact multi-connection write workload. Enforced by a build-time assertion (ADR-0006). |
| **V-03** | **SQLite `synchronous=NORMAL` does not survive power loss; `FULL` is required on the task connection** | `https://sqlite.org/wal.html` | **event:** any WAL documentation change; re-assert in the durability test | 2026-09-30 | **Critical.** The entire power-loss guarantee (TP-7) rests on it. |
| **V-04** | **Rust stable is 1.98.1; MSRV floor is 1.98.1** | `rustc --version`; the MSRV table in `02-technology-evaluation.md` §3.1 | **quarterly** + on any dependency bump | 2026-09-30 | **Medium.** `sqlx` needs 1.94 and `egui` 1.95; our floor is only 3–4 minor versions above the tightest. A silent MSRV rise would force a floor decision. |
| **V-05** | **Node 24.21.0 ("Krypton") is the current LTS line; Node 26.x is `lts=false`** | `https://nodejs.org/dist/index.json` (the `lts` field); the LTS schedule page | **event:** a new LTS codename appears; **quarterly** | 2026-09-30 | **Medium.** The frontend build runtime is pinned to an LTS line. When Krypton leaves maintenance, the toolchain ADR-0031 must be revisited. |
| **V-06** | **TypeScript 7.0.2 is latest stable; Svelte supports it via `svelte-check --tsgo` with TS6 co-installed; `svelte-check` 4.7.6** | `https://registry.npmjs.org/typescript/latest`; the `svelte-check` tarball's `README.md` **and `bin/ts-version-check.js`**; `svelte-language-server` | **event:** a new `svelte-check` major/minor; TS 7.1 shipping the stable API; any change to the peer range | 2026-09-30 | **High.** Getting this backwards again would pin a superseded compiler for a year. **Read the tool's source, not just its peer range** (ADR-0005 amendment). |
| **V-07** | **Tauri 2.12.0 is current stable; its Linux native dependency set is unchanged** | `https://tauri.app/blog/`; `crates.io/api/v1/crates/tauri`; `https://registry.npmjs.org/@tauri-apps/cli/latest` | **event:** a Tauri 2.x release; **release:** re-verify the Fedora native deps before packaging | 2026-09-30 | **Medium.** A dependency change breaks packaging silently — we would not find out until a build fails. |
| **V-08** | **Tauri 2's WebView memory cost is ~80–150 MB on Linux** | **No authoritative source exists.** Must be measured by us. | **milestone:** Phase 1, on ≥ 3 distributions | *unmeasured* | **Medium.** This is a *budget*, not a claim. If it is materially higher, ADR-0002's GUI decision must be revisited (Slint is the documented fallback). |
| **V-09** | **Windows requires Authenticode; MSI; MSVC; WebView2; long-path awareness; reserved-filename sanitisation** | `https://learn.microsoft.com/` (MSVC, WebView2, code signing, DPAPI, Task Scheduler) | **event:** any Microsoft packaging/signing policy change; **milestone:** Phase 1 | 2026-09-30 | **High.** Certificate procurement has external lead time (ADR-0026). A policy change discovered late delays a release. |
| **V-10** | **`sherpa-onnx` 1.13.8 is active, Apache-2.0, with first-party Rust bindings and a 1–3 week release cadence** | `crates.io/api/v1/crates/sherpa-onnx`; `https://github.com/k2-fsa/sherpa-onnx` | **quarterly** + on a >6-week release gap | 2026-09-30 | **High.** It is our *default* local ASR engine. A cadence break stalls a headline capability. |
| **V-11** | **`ort` has never released 2.0 stable (newest stable 1.16.3, 2023-11-12; newest is `2.0.0-rc.13`)** | `crates.io/api/v1/crates/ort` | **quarterly** | 2026-09-30 | **Medium.** Affects `parakeet-rs` (optional ASR engine). Not load-bearing — `sherpa-onnx` is the default. |
| **V-12** | **`playwright-rs` 0.19.0 is the live crate; the crate named `playwright` is a dead 2022 fork; there is still no official Playwright-for-Rust** | `crates.io/api/v1/crates/{playwright-rs,playwright}`; `https://github.com/microsoft/playwright/issues/18266` | **quarterly** + on reaching 1.0 | 2026-09-30 | **Medium.** Naming trap plus bus-factor 1. Affects the optional browser capability only. |
| **V-13** | **WebDriver BiDi is a W3C Working Draft, not a Recommendation; Safari has no implementation** | `https://www.w3.org/TR/webdriver-bidi/`; `https://wpt.fyi/results/webdriver/tests/bidi` | **event:** BiDi reaching Recommendation status; **quarterly** | 2026-09-30 | **Low** for us — we deliberately deferred BiDi. Would trigger ADR-0015 revisiting. |
| **V-14** | **Chrome 136+ ignores `--remote-debugging-port` against the default profile** | `https://developer.chrome.com/blog/remote-debugging-port`; the Chromium CDP README | **event:** any change to Chrome's remote-debugging restrictions | 2026-09-30 | **Medium.** Determines that the browser capability must own a dedicated profile. If relaxed, we could reconsider (but probably still would not). |
| **V-15** | **Professional-UI GUI grounding accuracy ≈ 61.6 % (ScreenSpot-Pro family); the original paper's headline was 18.9 %** | `https://arxiv.org/abs/2504.07981`; the UI-TARS and RegionFocus papers | **event:** a published model exceeding ~95 %; **quarterly** | 2026-09-30 | **Medium.** Justifies accessibility-tree-first grounding. Above ~95 % we would reconsider visual grounding as primary. |
| **V-16** | **Telegram API ToS §1.5 prohibits using Telegram-obtained data for AI development/deployment** | `https://core.telegram.org/api/terms` | **event:** any change to the API Terms | 2026-09-30 | **High (product).** Determines that the Telegram adapter is notification-output-only. **Requires legal review, not just a doc read** (Q-OPEN-01). |
| **V-17** | **Discord self-bots are categorically forbidden (⇒ termination) and soliciting a user token is prohibited** | `https://discord.com/guidelines` §14; the Platform Manipulation Policy; the Developer Policy | **event:** any policy change | 2026-09-30 | **High.** Hard constraint on the messaging capability. |
| **V-18** | **WhatsApp Cloud API forbids "personal, family, or household purposes"; the 3P Agent platform is beta and undocumented** | `https://www.whatsappbusiness.com/policy`; the WhatsApp Business ToS; the "Terms of Service for Use of Third Party Agents" | **event:** 3P Agents reaching GA **with public developer docs** | 2026-09-30 | **Medium.** Gates whether WhatsApp is ever implemented. |
| **V-19** | **Signal publishes no API; `signal-cli` self-declares a 3-month support window** | `https://signal.org/docs/`; `https://github.com/AsamK/signal-cli` | **quarterly** | 2026-09-30 | **Low.** We refuse Signal. Would only change if Signal shipped an official API. |
| **V-20** | **Piper is GPL-3.0; Coqui/XTTS is CPML (non-commercial + viral); `canary-1b` is CC-BY-NC-4.0; openWakeWord weights are CC-BY-NC-SA** | The respective `LICENSE` files, the HF model-card `license` field, and the crate/repository licence | **release:** re-audit before any model or voice component ships; **event:** any upstream licence change | 2026-09-30 | **Critical (legal).** A silent licence change would make a shipped binary non-compliant. Enforced by the model-licence registry (ADR-0019). |
| **V-21** | **`apalis-sqlite` sets `PRAGMA synchronous = OFF` and has no stable release** | `src/lib.rs` of the published crate; `crates.io/api/v1/crates/apalis-sqlite` | **event:** a stable 1.0 release, or a PR adding a durability knob | 2026-09-30 | **Medium.** Closes ADR-0007's contingency (Q-OPEN-02). A stable release alone does **not** reopen it — TP-7 must also pass. |
| **V-22** | **`croner` documents Vixie-compatible DST semantics; `jiff` provides correct DST arithmetic** | `https://docs.rs/croner/` (DST section); `crates.io/api/v1/crates/{croner,jiff}` | **quarterly** + on a major bump | 2026-09-30 | **High.** DST correctness is a correctness property (TP-8), and `croner` is the only Rust cron that documents it. |
| **V-23** | **The Rust task-scheduler ecosystem's viable options are `croner` and `cron` only** | `crates.io/api/v1/crates/{croner,cron,clokwerk,job_scheduler,tokio-cron-scheduler}` | **quarterly** | 2026-09-30 | **Medium.** If `croner` is abandoned we have no documented-DST alternative. |
| **V-24** | **PostgreSQL, Redis, Kafka and Kubernetes are absent from the personal install** | `rpm -q`; the deployment profile definition | **release:** assert the dependency manifest contains none | 2026-09-30 | **Medium.** This is the property that makes the product lightweight; drift is silent and cumulative. |
| **V-25** | **Core-only idle RSS < 60 MB; core-only binary < 40 MB; core-only cold start < 150 ms** | No external source. Measured by our own harness: `scripts/measure-v25.sh` + `crates/orxnud-daemon/tests/v25_measure.rs`. | **milestone:** CI on every commit (reported, not gated — see the variance column); re-baseline per release | **met on the measured host**, with limits recorded | **High.** These are the budgets that make the lightweight promise honest, and until now a regression was invisible. **Definition:** "core-only" is the `orxnud` binary with **no provider**, serving on its local socket — daemon + local IPC + SQLite engine + policy + audit + identity boundary + core task lifecycle. `--provider-scripted` is deliberately not used. A regression was invisible without measurement; now it is not, which is the point of closing this row. **Method:** release profile (thin LTO, codegen-units 1, panic=abort, strip=symbols), rustc 1.98.1, x86_64-unknown-linux-gnu on a 16-core i5-12500H / 15.3 GiB / btrfs-on-LUKS-NVMe host, bundled SQLite, measurement databases on a **verified non-memory-backed** filesystem. **Cold start** is timed to the daemon *answering a request*, not to `exec`, because `Runtime::start` does durable state + engine + bind before anyone can be served. **Results (N in brackets):** binary **7,492,472 B = 7.15 MiB** stripped, 18.7% of budget; idle RSS **9.11 MiB**, 15% of budget; cold start **p50 81.9 ms / p99 82.6 ms** [30], 55% of budget; IPC request **p50 90.8 us** (connect 13.8 us) [2000]; durable create **p50 2.07 ms**, claim 2.42 ms, propose 2.32 ms, complete 26 us [150]; sustained **454 commits/s** [500]; Tier-1 sandboxed execution **p50 67.8 ms** [12]. Idle daemon: 20 threads, 21 fds, **0 child processes**. **Variance:** binary size exact; cold start ~0.2%; RSS ~1%; IPC ~17% (noisy). Binary size and the dependency graph are gated; the noisy measurements are reported. **Dominant costs, from evidence:** sandbox isolation at 67.8 ms is **30x** a durable commit and dominates interactive latency; durable writes cost ~2.1 ms each, confirming V-30's `synchronous = FULL` figure; and **86% of idle RSS is file-backed**, so the RSS and binary-size budgets are substantially the same quantity -- growing the binary grows idle RSS nearly one-for-one, and there is no separate heap problem. **The unstripped build of the same source is 48.8 MiB and would fail the 40 MB budget**, so the stripped number is the one compared, stated explicitly because it is a decision. **Gated architecture, not numbers:** six static checks in `tests/v25_architecture.rs` hold one TLS implementation, no telemetry exporter, a local store rather than a database client, and no GUI/server framework in the core. **Limits, stated rather than implied:** (1) this host has 16 cores and NVMe, so the budgets' "modest baseline 2c/4 GiB" column is **not** verified; (2) every figure is page-cache-warm, because `drop_caches` needs privileges this environment lacks -- the favourable direction, and it is said so; (3) hosted CI reports rather than gates, because a runner that is occasionally slow must not teach engineers to ignore the number. Resource *ceilings* are not duplicated here -- `tests/governed_path.rs` already observes the real cgroup, and all 24 of its tests pass on this host including kernel-enforced memory, wall-clock, output-cap and descendant containment. |
| **V-30** | **`synchronous = FULL` costs ~8–14× `NORMAL` per commit on this machine: ~2.3 ms vs ~0.2 ms** | `crates/orxnud-task/tests/measurements.rs::insertion_throughput_with_synchronous_full_is_usable`, on btrfs-over-LUKS, Rust 1.98.1, SQLite 3.53.2 bundled | **milestone:** re-measure per release; **event:** a storage or filesystem change | 2026-09-30 | **High.** This settles **Q-OPEN-17**. The ratio varies run to run (7.3×–14.3× observed over four runs) because the `NORMAL` baseline is small and disk-scheduling-noisy, so the **magnitude** (~2.3 ms) is the reliable figure and the ratio is a range, not a number. FULL is affordable for a personal daemon at roughly 430 state transitions/second, which is far above what one user generates — but it is *not* affordable as a default for anything batch. Measured on an encrypted btrfs volume, which is a pessimistic case; an SSD without encryption would be materially faster. The transition-latency budget in docs-05 is < 5 ms and a fenced commit measures 2.2–3.4 ms, so the headroom is roughly 30–55% and not comfortable. See V-35. **Default stays FULL** (ADR-0006 invariant 1). The `NORMAL` mode exists and is tested, and choosing it requires an ADR, because ADR-0008's revisit condition says *"demote the cheapest-to-lose region, never weaken the task table."* |
| **V-31** | **Durability cannot be measured on tmpfs: `fsync` is a no-op there** | `/tmp` is `tmpfs` on this host; measured `fsync`-only cost 3 µs vs ~2.3 ms on btrfs. `measurements.rs` first reported FULL and NORMAL as **1.0× identical** | `fs.stat -f -c %T`, `/proc/mounts`, and the ratio in the same test | **release:** any harness that measures durability must assert its filesystem | 2026-09-30 | **High.** This is the failure mode where a measurement *confirms the wrong thing*: on tmpfs the harness would have "shown" that `synchronous = FULL` is free, which is the opposite of the truth. `measurements.rs` now refuses to run on a memory-backed filesystem and names `ORXNUD_MEASURE_DIR` as the override. Any future durability benchmark must do the same. |
| **V-32** | **The Phase 2 engine passes all twelve ADR-0029 properties against the *unmodified* Phase 1 harness** | `cargo test -p orxnud-task --test conformance_production`; `crates/orxnud-task/tests/conformance_production.rs` calls the same `run_suite` the trivial fixture uses | **milestone:** every change to `conformance::properties` or `conformance::schedule` | 2026-09-30 | **Critical.** ADR-0029's whole claim is that the contract is implementation-independent. Verified by: the harness was not edited; the suite is called from a second test binary with a different engine; and a deliberately broken engine is asserted to produce a *non-clean* report, so the suite is known to have teeth against this engine rather than merely agreeing with it. |

| **V-33** | **A fresh install could not start; only production wiring found it** | `orxnud-daemon/src/task_service.rs::open` was the first caller of `MigrationRunner::migrate`; `Backup::verify` rejected the snapshot of an unmigrated database | `orxnud-store/src/migration.rs::migrating_a_brand_new_database_succeeds`, and `Backup::verify_against_source` | **release:** any change to the migration or backup entry point | 2026-09-30 | **High.** Every Phase 2 migration test drove `MigrationRunner::run`, which trusts its caller's snapshot claim and never takes one — so the snapshot path had no coverage until startup used it. It failed on a brand-new database: `Backup::verify` rejected a snapshot with no `schema_meta`, on the sound grounds that restoring it would erase a user's data, which is the wrong target when there is no data yet. The first migration could not run, so the daemon could not start on any machine where OpenRayNux had never run. Emptyness is now judged relative to the source. The lesson recorded for its own sake: **a helper used only by production code has no test coverage until production calls it.** |
| **V-34** | **The "verified snapshot has data" guard was documentation, not code** | `Backup::verify` computed `total_rows` and returned it; nothing compared it. `BackupError::Empty` now refuses a snapshot whose `schema_meta` exists but is empty | `orxnud-store/src/backup.rs`, `an_emptied_snapshot_of_a_real_database_is_still_rejected` | **release:** any change to snapshot verification | 2026-09-30 | **High.** The comment claimed "a row count, so *verified* means *has the data we expected*" — and the code did not do it. Found while fixing V-33, in the same function, because the fresh-install fix made the emptiness question unavoidable. Two guards, both now enforced and both tested in both directions: absent `schema_meta` is refused, and present-but-empty is refused, while an empty snapshot of an equally empty source is accepted. |
| **V-35** | **`synchronous = FULL` costs ~2.3 ms per state transition, consuming 45–70% of the < 5 ms budget** | Re-measure per release; the headroom is thin enough that a slower disk makes the budget the binding constraint | `crates/orxnud-task/tests/measurements.rs` | **milestone:** if a transition p99 exceeds 5 ms, this is the first thing to re-examine — and ADR-0008 requires the decision to demote a cheaper region rather than weaken the task table | 2026-09-30 | **High.** See V-30 for the measurement. Recorded separately because the *risk* is distinct from the *number*: A fenced commit measures 2.2–3.4 ms across runs, so the budget is not generous, so this belongs on the re-measure list rather than being considered settled. |

| **V-36** | **`CapabilityInvocation` was forgeable from JSON; the type-level policy boundary did not hold** | `orxnud-domain/tests/compile_fail/invocation_cannot_be_deserialised.rs` (with recorded `.stderr`), plus the standalone-crate proof in ADR-0034 | **release:** any change to `orxnud-domain`'s serde derives on authority-bearing types | 2026-09-30 | **Critical.** The type derived both `Serialize` and `Deserialize` with private fields, and a derived `Deserialize` writes private fields without a constructor — so `PolicySeal`, `AuthorisationProof`, and policy evaluation were all bypassed. Demonstrated, not theorised: a crate outside the workspace built an invocation from a JSON literal and printed `FORGED OK ... risk=Low policy_version=forged` with no policy and no human. ADR-0012's claim that this "is not *possible*" was false, and ADR-0034 corrects it. Found by asking what each dispatcher stage would do to a forged value **before** writing the dispatcher — stage 6 (credential resolution) would have handed real credentials to a fabricated `Human` actor. Fixed by removing the derive and introducing `CapabilityRequest` as the only capability-shaped type that accepts external data. Verified with teeth: re-adding `Deserialize` fails the compile-fail test. |
| **V-37** | **A derived `Deserialize` is a constructor, and private fields do not make it an authority boundary** | `serde` docs: `Deserialize` is a mechanism for constructing a value from external data. `CapabilityRequest` *does* derive it, deliberately | review any serde derive on a type carrying authority, risk assessment, policy version, approval digest, or credential handle | 2026-09-30 | **High.** The generalisable rule, recorded because V-36 will recur in another form. The asymmetry is the point: `Serialize` on an authority-bearing type is a disclosure risk a caller must consciously own (audit, hashing); `Deserialize` is an authorisation bypass no caller should be able to perform. Enforced by the same compile-fail mechanism, and by the structural rule that ingress converges on `CapabilityRequest` — one untrusted representation, one authorisation pipeline. Also: authority-bearing types must not be persistence types either, or the storage layer restores the same confusion. |

| **V-38** | **`Serialize` on `CapabilityInvocation` is retained under review, not declared permanently safe** | `orxnud-domain/src/invocation.rs`; ADR-0034 | **review trigger:** any new use of serialising an invocation — a wire type, an event payload, a log line, an MCP payload, or a persistence DTO | 2026-09-30 | **Medium.** `Serialize` cannot *forge* authority, but it can *expose* authority-bearing metadata (actor, policy version, approval digest, task) across a boundary that the type was not meant to cross. Asymmetric with `Deserialize`, which was removed outright (V-36): serialising authority **out** is a disclosure risk a caller must consciously own, deserialising it **in** is an authorisation bypass nobody should be able to perform. Not changed now, because the current code has no actual unsafe serialization path — the only consumer is the audit chain's canonical hashing, which is intentional. Recorded as a review invariant rather than a fix. Permitted uses: audit representation, canonical hashing, diagnostics explicitly designed to expose it. Forbidden: JSON-RPC DTO, generic event payload, log serialization, MCP payload, untrusted message, persistence DTO. If the projection discipline turns out to need policing at more than one call site, the likely end state is a dedicated `InvocationView` / `InvocationDigestInput` projection rather than relying on every future caller to pick the right one of two derives. |

| **V-39** | **Approvals were documented as single-use and were not enforced** | `orxnud-policy/src/engine.rs` (`consumed_approvals`, `DenialReason::ApprovalAlreadyUsed`); `an_approval_is_single_use`, `a_consumed_approval_is_refused_for_any_retry`, `a_consumed_approval_cannot_authorise_a_second_dispatch` | **milestone:** any change to approval validation or the digest | 2026-09-30 | **High.** ADR-0027 and control S6 both state approvals are single-use. Nothing implemented it: the digest check answered "is this the approved operation?", and nothing answered "has this approval already been used?" A record is a value, and a value can be presented twice — so a retry could inherit an approval, which ADR-0027 forbids outright. Found by the bypass suite, not by reading the code. **A first version of the unit test was itself toothless**: it called the consumption setter directly and passed with the consumption *deleted* from `authorise`. It now drives `authorise`, and deleting the one-line insert turns three tests red across two files. Generalisable: a test that calls the mechanism under test's collaborator is testing the collaborator. |
| **V-40** | **Capability contract points 4 and 6 are unproven, by construction** | `crates/orxnud-capability/tests/contract.rs` records them as `declared_only`, and `the_declaration_only_points_are_named_explicitly` asserts exactly 4 and 6 appear there | **milestone:** Tier 1+ subprocess isolation -- FIRED, re-read 2026-10-05; and **release:** any change to `tests/contract.rs`| 2026-10-05 | **High.** "No undeclared filesystem or network access" needs a real sandbox; "a disabled capability leaves no residue" needs a real process. An in-process fixture can observe neither, so ADR-0009's 10-point suite is **8 points proven, 2 declared**. The harness states this rather than claiming full coverage, and a test fails if either point is silently promoted to `proven` — which is what stops a future change from quietly turning a documentation gap into a false assurance. **This is a known, recorded gap, not a passing criterion.** Re-read because its trigger fired, and the answer is that the claim survives: Tier-1 subprocess isolation now exists in quantity, yet `tests/contract.rs` still records exactly points 4 and 6 as `declared_only` and still asserts that set. That is deliberate and is not an oversight -- the contract harness is an in-process fixture and cannot observe a namespace or a process, so promoting those points would be a false assurance. The evidence that *does* exist lives in `tests/isolation.rs` and `tests/read_text_real.rs`, which is a different harness with a different subject. Recorded so the next reader does not read the unchanged entry as an unread one. |
| **V-41** | **The governed dispatch path is single-writer, so it cannot be parallelised** | `Dispatcher` holds `&mut PolicyEngine`; ADR-0006 documents one writer | **release:** if multi-writer dispatch is ever required, this changes the design rather than the tests | 2026-09-30 | **Medium.** Recorded because "test concurrent dispatch" invites a test that fakes concurrency. The honest answer is structural: `&mut PolicyEngine` means `Dispatcher` is neither `Sync` nor shareable, which is the single-writer guarantee as a type. The concurrency suite therefore tests what *is* concurrent — repeated approvals racing for one authorisation, budget ceilings under many attempts, audit-chain linkage across many appends, and guard release after an adapter panic — and asserts the single-writer property as compile-time fact. No actor runtime or broker was added (ADR-0024 rejects one). |

| **V-42** | **A Phase 2 concurrency test was load-sensitive and passed by luck** | `orxnud-task/tests/durability.rs::n_workers_sharing_a_file_produce_exactly_one_winner_per_task`; failed once under whole-suite `nextest` load and passed 5/5 in isolation | `is_retryable` on `EngineErrorKind`; the fixture now retries a retryable conflict and panics on a non-retryable one | **release:** any test that ignores a `Result` from a concurrent operation | 2026-09-30 | **Medium.** The test spawned six writers and did `if let Ok(Some(row)) = e.claim_task(..)`, discarding errors. A `SQLITE_BUSY` that lost the five-second busy-timeout race therefore vanished silently, so fewer than 12 tasks were claimed and the assertion blamed the engine for a scheduling artifact. It only surfaced because G9 runs the whole suite in parallel — the load was the trigger, not the cause. A real worker retries a retryable conflict, so the fixture now does, using the **existing** `EngineErrorKind::is_retryable` classification rather than an invented policy. Five consecutive whole-suite runs green afterwards. Worth noting the shape: the failure looked like a Phase 2 regression in a Phase 3 change, and it was neither. |
| **V-43** | **Approval is consumed before execution, so a post-authorisation failure burns the approval** | `PolicyEngine::authorise` consumes the digest as part of permitting, before `dispatch` reaches stage 5 | **milestone:** Phase 4/5 -- FIRED (Phase 4a and 4b delivered 2026-10-01); still undecided, re-read 2026-10-05| 2026-10-05 | **Medium.** Security-safe: burning early is fail-closed, so the failure mode is an extra approval prompt rather than an unauthorised action. But it is a real usability cost, and the alternative is worse. A failure *after* authorisation and *before* the side effect — capability resolution, credential acquisition, adapter lookup — consumes an approval that produced nothing. With three such stages between the burn and the effect, a user retrying a credential-store outage re-prompts for an action they already approved. The alternative (burn after execution) reintroduces exactly the replay window single-use exists to close: two concurrent dispatches could both pass the check before either burns. **Not changed in Phase 3**, because fail-closed is the correct default when the semantics are unspecified. Phase 4/5 must decide this explicitly and test it, rather than inheriting it by accident. The clean resolution is probably a *reservation* distinct from a *consumption* — reserve at stage 3, consume at stage 7 — but that needs its own replay analysis and is not a Phase 3 change. Re-read 2026-10-05 because its trigger fired and no decision was recorded, which is a register failure rather than a code one. `PolicyEngine::authorise` still consumes the digest before dispatch reaches stage 5, so the semantics are unchanged and untested-by-decision. The behaviour is now better characterised than when this was written: with the approval digest at **v3** and `step_no` bound into it (V-83), a burnt approval is also scoped to one logical step, so a multi-step task cannot inherit a sibling step's consent. The single-step liveness cost is unchanged and still real. Still not fixed: the clean resolution remains a *reservation* distinct from a *consumption*, which needs its own replay analysis. |
| **V-45** | **A measurement reported a sandbox escape that did not happen** | `crates/orxnud-platform-sandbox/src/linux.rs` module docs; ADR-0035 | **release:** any liveness check on a sandboxed process | 2026-09-30 | **Critical.** The Phase 4 research spike concluded that a detached, `SIGTERM`-ignoring grandchild escaped `--unshare-pid --die-with-parent`, `--unshare-pid`, and `--die-with-parent`, and reported Phase 4 BLOCKED on that basis. **The check was wrong**: liveness was tested by looking for the grandchild's PID in the host's `/proc`, but the helper had reported the PID it saw *inside* its new PID namespace, and `3` on the host is an unrelated process. Re-measured by watching an on-disk heartbeat advance: `--unshare-pid --die-with-parent` contains it, 5 of 5 runs under both `SIGTERM` and `SIGKILL`; the other three combinations do not. **Scope of this claim: the exact OpenRayNux sandbox topology in `build_command` — `--unshare-pid` *and* `--die-with-parent` together, the supervisor signalling `bwrap`, no `--share-pid`, no privilege retained, PID 1 of the namespace being `bwrap`'s own child.** It is **not** a general statement about bubblewrap, and **not** a guarantee for a different flag set: the three other combinations in the same matrix do not contain. Anyone changing a namespace flag must re-run `isolation.rs`'s containment test before the containment claim survives. The blocker was an artefact. **The generalisable lesson: a liveness assertion must distinguish a live process from a stale artefact.** `os.path.exists` and a fixed PID both fail that; an advancing heartbeat does not. This is the same shape as V-31, where a benchmark on tmpfs confirmed the wrong thing. |
| **V-46** | **cgroup mechanism and governed path PROVEN on Linux, with limit validation added; Windows NOT_PROVEN** | `crates/orxnud-platform-sandbox/src/{cgroup,linux}.rs`; `crates/orxnud-capability/tests/governed_path.rs` | **Mechanism (commit 1ef7eb3, mutation-verified):** `memory.max` 64 MiB with `memory.events max` 914 refusals; `pids.max` 8 with `pids.events max` 3 refused forks against 40 attempts; `cpu.max` throttled, not terminated; `cgroup.kill` 2 members -> 0 across a three-level subtree; dedicated-child invariant V-55. **Governed path:** the runner creates a dedicated child, writes ceilings before spawning, joins the supervisor via `sh -c 'printf $$ > cgroup.procs; exec bwrap'` (membership is inherited at `fork`, so adopt-after-spawn leaves pre-forked work unconstrained), then *verifies* membership from `cgroup.procs`. Observed: `memory.max=50331648` on a child strictly below base, payload present as a member, `leftover=0`; with a 16 MiB ceiling a bounded 64 MiB page-touching workload could not retain its request while `memory.current` stayed under the ceiling. **Refusal:** a required control the host cannot establish refuses with the backend invoked **zero** times; a required control with no budget is refused as an incomplete policy, before the backend is consulted (see ADR note below). **Mutation:** removing the cgroup join fails 3 governed tests and *fails closed* (refusal, no fallback). **NOT_APPLICABLE (ADR-0036):** governed `cgroup.kill` teeth are not separable on Linux -- `bwrap --unshare-pid --die-with-parent` already reaps descendants, so removing the runner's `cgroup.kill` leaves the suite green. The PID namespace is the load-bearing tree-lifetime mechanism and `cgroup.kill` is a deliberate redundant backstop; `cgroup.kill`'s independent teeth are proven in the mechanism suite, which has no PID namespace. No artificial mutation will be built to separate redundant mechanisms. | **milestone:** Phase 4b -- Windows Job Object equivalence | 2026-10-01 | **Partial, deliberately not promoted to complete.** **PROVEN:** the cgroup mechanism, independently and by mutation. **PROVEN:** the governed path uses it -- the dispatcher reaches the runner, the runner owns the cgroup, and the actual supervisor is a verified member. **PROVEN:** resource-policy completeness semantics -- `requirement` stays a prerequisite and `budget` a concrete ceiling (V-56); a required control with no budget is refused rather than given an invented default, because the backend must enforce policy and not create it. **PROVEN (this change): resource-limit validation and fail-closed setup.** Every externally supplied limit is now validated against boundaries *measured* on this host by writing the value and reading the kernel's answer back: `memory.max` is signed, so anything at or above `i64::MAX` is stored as the literal `max`; `pids.max` accepts `1..=4194304` (`PID_MAX_LIMIT`); `cpu.max` accepts quota `1000..=17592186044415` us and period `1000..=1000000` us. Five fail-open paths were found by measurement and closed: (1) `cpu_cores` of `NaN`/`0.0`/negative was silently **dropped** (`NaN > 0.0` is false), so a *required* CPU ceiling ran with no CPU ceiling and nothing recorded the gap; (2) `cpu_cores` of `inf`/`1e300` saturated `as u64` to `u64::MAX`, which the kernel stores as `max` -- a requested ceiling silently became *unlimited*; (3) `memory_bytes` of `u64::MAX` did the same, verified by readback `"max"`; (4) a kernel `EINVAL` was reported as "this host does not delegate these controllers", sending an operator to debug a delegation that was working -- `ResourceMiss` now carries a `ResourceMissKind` that separates `ControllerUndelegated` (`EPERM`) from `ValueRejected` (`EINVAL`); (5) `Resource::Required` with **no** ceiling named ran the payload unbounded and reported `unproven: []` -- a required guarantee silently absent, which is now refused as incoherent. Additionally, a control-write failure leaked its cgroup directory (only the "controller missing" branch cleaned up); verified on this host that a rejected write leaves the directory present, so those accumulated in the shared base. All failure paths now remove it. **Mutation-verified:** restoring the silent drop and disabling the fail-open guard fails 5 tests; removing the write-failure cleanup fails 1; making execution cgroup names collide fails the concurrency test. **Concurrency proven:** 6 threads create 6 cgroups with distinct ceilings, each reads back its own `memory.max`, and each owner's removal leaves the others intact. **Also corrected:** `create` no longer re-probes for a base while validating against `self.availability` -- two independent probes could place a cgroup under one base and configure it from another's answers. **PROVEN (review follow-up): placement precedes execution.** Distinct from "membership is verified", which only shows the process eventually joined: the helper's *first* instruction on entry allocates and touches memory (`mem-hog`), and the observer reads the execution cgroup's own `memory.events`. Any work done before placement would be charged to a different cgroup and would not appear here. Measured: 36-103 refused allocations recorded against the execution cgroup from a payload whose first act was to allocate, against a 32 MiB ceiling. Mutation-verified: making the join shell not write `$$` fails the test. The remaining window -- instructions executed by the joining shell between `fork` and its write -- belongs to `/bin/sh`, not to attacker-controlled code, which has not started; `bwrap` is not exec'd until after the write. The window is therefore small rather than zero, and no claim is made that it is zero. **Corrected in review:** `memory.max` was documented as a "hard address-space ceiling". It is not: it limits the cgroup's charged memory usage, so a process may still reserve a very large virtual address space inside it. A reader taking it for `RLIMIT_AS` would conclude that huge reservations are prevented, which this control does not do. **Decided in review: sub-page memory budgets.** `memory.max` is page-accounted, and measured here `1 -> 0`, `4095 -> 0`, `4097 -> 4096`. A 1-byte budget is therefore stored as a *zero* ceiling -- `u64::MAX -> max` in miniature, where the caller is told one thing and the kernel enforces another. Measured: a fresh process joining a cgroup with `memory.max = 0` is OOM-killed (`oom_kill 1`) before doing any work. Round-up was rejected because it would *widen* the requested budget; round-down-and-document was rejected because the documented and effective values would differ silently. Values below one page are now **refused**, which is the only option where what the caller was told cannot differ from what the kernel enforces. `memory.swap.max = 0` deliberately stays valid: "no swap at all" is a real policy, and rounding a swap ceiling down to 0 produces the policy that was asked for, whereas rounding a memory ceiling down produces one that cannot be met. **Follow-up, deliberately NOT in this change:** `scripts/run-resource-tests.sh` and `docs/07`, `lib.rs` asserted "this host delegates no cgroup controllers". That was true for one host and false for another -- measured 2026-10-02, the Phase 4 host's `user.slice/user-1000.slice/user@1000.service/app.slice` delegates memory, swap, pids, cpu and `cgroup.kill`, and the enforcement suite passes natively. Delegation is per-host, so those files now report what a host actually has instead of asserting a remembered answer. **Recorded, not changed -- portability limitation, not a V-46 failure:** the `1..=4194304` and `1..=1.75e13` bounds were measured on one host and are encoded as constants, so a host with a different `PID_MAX_LIMIT` would need them re-measured and validation would then *refuse* a value that host would accept. That fails closed and is therefore safe, but it is a portability wart: the validator uses Host A's discovered bounds on Host B. Deriving the bounds from the target kernel at runtime is the proper fix and is deliberately not attempted here, because it means probing the hierarchy's limits rather than stating them. `Isolation requirements (ADR-0036):** `NOT_APPLICABLE` for governed `cgroup.kill` teeth. **Recorded architecture (not changed here):** stage order is `CREDENTIAL -> SANDBOX`, so a required-resource refusal necessarily *follows* credential resolution. The guaranteed invariant is that the backend is never invoked, so no subprocess exists and no credential material is bound into any environment. Claiming 'credential lookup never occurs' would be a false claim about this architecture; changing the order is a separate ADR. **Corrections applied in review:** rejected implicit `DEFAULT_MEMORY_BYTES`/`DEFAULT_PROCESSES`/`DEFAULT_CPU_CORES` in the backend; replaced an unbounded memory adversary (which exhausted the host twice during mutation experiments) with a 64 MiB bounded page-touching workload and `memory.current`/`memory.events` evidence, with no OOM kill required; removed a second fixed-name cgroup probe from `linux.rs`; fixed `helper_path()` to select the newest *executable* helper (it sorted by name and took index 0, i.e. usually a stale build, making a governed test pass vacuously via a silent `noop` fallthrough). |
| **V-47** | **Descriptor hygiene is proven, but its teeth-check is inconclusive on this host** | `isolation.rs::the_supervisor_leaks_no_descriptors_into_the_sandbox` compares against an unsandboxed baseline | **release:** a CI runner whose stdin is not already null | 2026-09-30 | **Medium.** The test asserts the sandboxed child holds no *more* extra descriptors than the same helper run unsandboxed. Absolute counts are wrong: `bubblewrap` leaves one of its own behind (`/proc/<ns-init>/fd`). But mutating `Stdio::null()` to `Stdio::inherit()` does **not** fail the test here, because this runner's stdin is already null, so inheriting it adds nothing observable. The property is asserted and the limitation is recorded rather than hidden; a runner with a real stdin would make the mutation fail. The other five mutations all produced failures (see below). |
| **V-48** | **All five Phase 4a mechanisms were verified by deliberate mutation** | `--clearenv` removed → 2 failures; `--unshare-net` removed → 1; output cap removed in the reader → 1; `--` separator removed → 18; stdin inherited → inconclusive (V-47) | **release:** any change to `build_command` or the reader | 2026-09-30 | **High.** The brief asked for adversarial mutations and the results are reported rather than summarised. Two of the six mutations found nothing: the stdin one for an environmental reason, and an earlier attempt that mutated the *reporting* of the output cap rather than its *enforcement* — a reminder that a mutation must break the property, not its description. Removing `--die-with-parent` additionally revealed a genuine hang: the supervisor blocked forever on reader threads whose pipes were held open by a surviving descendant, which is now fixed by a bounded join (`join_bounded`). |

| **V-49** | **A required sandbox guarantee is refused; there is no unsandboxed fallback** | `AvailableGuarantees::check` → `Refused(GuaranteeUnavailable)`; `BwrapRunner::run` refuses before `Command::spawn`; asserted by `a_spec_with_nothing_granted_starts_no_process_for_an_ungranted_capability` and `a_spec_demanding_os_enforced_resources_is_refused_on_this_host` | **milestone:** Phase 4b — the dispatcher integration must preserve this | 2026-09-30 | **Critical.** The invariant: *every Tier-1 execution request is rejected when a required sandbox guarantee cannot be established; there is no "best effort" fallback to unsandboxed execution.* `bwrap` missing yields `MechanismMissing`, not a run without isolation — an unsandboxed capability has no isolation at all, which is worse than no capability. Relaxation exists but is explicit (`accepting_best_effort_containment()`), named in the diff, and recorded in `ExecutionResult::unproven` so an audit record can state the gap rather than imply otherwise. Phase 4a's evidence for this is negative-path only: it proves refusal, not that a *governed* execution path consumes it, because no such path exists yet. |
| **V-50** | **CLOSED by V-51 -- the sandbox **is** reachable from the dispatcher** | `orxnud-platform-sandbox` has no consumer; `grep -rn SandboxRunner crates/` finds only its own tests | **closed:** superseded by V-51| 2026-10-05 | **High.** Recorded as an explicit gap rather than an omission. The full governed path — `Dispatcher → execution contract → sandbox supervisor → Tier-1 subprocess → result → Verification → Audit` — does not exist, so Phase 4a proves a boundary that nothing yet enforces. A later execution path could bypass it accidentally, which is precisely the failure the Phase 3 exit criteria were written to prevent. Phase 4b must wire it with synthetic adapters only and prove no bypass exists. **Nothing is registered and nothing runs unsandboxed today**, so no capability is currently at risk; the risk is architectural drift, not an active exposure. Re-verified 2026-10-05 and closed. Its stated verification source was `grep -rn SandboxRunner crates/ finds only its own tests`, and that command now returns `crates/orxnud-capability/src/subprocess.rs:37,84,103,299` and `governed_path.rs:984,1342,1346` -- the entry was disproved by its own evidence and had never been re-read, which register rule 2 exists to prevent. V-51 is the closure. |
| **V-54** | **A Tier-1 `Subprocess` capability cannot fall back to in-process execution — MUTATION-VERIFIED** | `crates/orxnud-capability/src/dispatch.rs:905-977`; the arms' bodies swapped, `Subprocess` left carrying the in-process body. `governed_path`: **10 of 16 FAILED**, restored **16 passed**. Repeated twice (plus a narrow single-test run): identical every time | **release:** any change to the execution arms in `dispatch`, to `CapabilityAdapter::tier`, or to `with_execution` | 2026-09-30 | **High.** Three enforcement layers, now distinguished and all three demonstrated. **(1) STRUCTURALLY ENFORCED** — a `Subprocess` adapter's `invoke` panics by design, so an in-process route surfaces as a loud failure rather than a silent unsandboxed execution. **(2) MECHANICALLY GATE-ENFORCED** — gate G2 rejects `Command::new` anywhere in `orxnud-capability`; verified by injection (exit 1, named message). **(3) MUTATION-VERIFIED** — swapping the two match arms' bodies makes 10 governed-path tests fail, with the primary mechanism reported by the suite itself: `Tier-1 adapter invoked in-process: the sandbox route was bypassed`, and a Tier-1 capability with no sandbox returning a `DispatchOutcome` where `SandboxRefused` was required. The mutation touched production code only — 45 lines, one file, no test, assertion, error text or documentation changed — and compiled cleanly, so it was a behaviour change and not a build break. The two earlier failed attempts (V-54's prior state) had relabelled an arm without swapping bodies; recorded because the fix was to *locate the exact branch and its boundaries first*, not to retry harder. |
| **V-51** | **Tier-1 execution now runs through the governed path; a sandboxless Tier-1 capability is refused** | `crates/orxnud-capability/tests/governed_path.rs` (16 tests, real subprocesses) | **release:** any change to `dispatch`, `subprocess`, or the sandbox contract; fired 2026-10-05 (`dispatch.rs`, `isolation.rs`, and the daemon `Runtime` all changed)| 2026-10-05 | **Critical.** Closes V-50. `CapabilityAdapter::tier()` returns `InProcess` or `Subprocess`; a `Subprocess` adapter has **no** in-process route, because its `invoke` panics by design -- if the sandbox branch were ever bypassed the suite says so loudly. `with_execution` is the only way to enable subprocess execution; there is deliberately no setter taking a program and arguments, which would be the `dispatcher -> direct subprocess` bypass. Refusals are counted, not inferred from timing: a policy, budget, credential or capability-resolution refusal reaches the backend **zero** times. The `ExecutionContract` carries no credential and no `SecretRef`, because a contract is logged and audited. **Scope:** proved on this host with `bubblewrap`. Windows remains unverified (V-29). Re-verified 2026-10-05. `governed_path` is now 24 tests rather than 16, `read_text_real` adds 12 more against a real sandboxed read, and `cli_e2e` drives the whole loop through the shipped binaries. The claim is unchanged and still true: a `Subprocess` adapter has no in-process route, and a host with no namespace guarantees refuses before a process exists. |
| **V-52** | **cgroup v2 controls are writable in a delegated container; end-to-end enforcement is NOT yet proven** | `scripts/run-resource-tests.sh`; `memory.max`, `memory.swap.max`, `pids.max`, `cpu.max`, `cgroup.kill` all WRITABLE; `cgroup_kill_terminates_a_member_that_forked_a_descendant` PASSES | **milestone:** directory selection inside the test image | 2026-09-30 | **High.** Partial progress on V-46, and recorded as partial rather than promoted. **Proven:** the controls are writable where cgroups are delegated, and `cgroup.kill` terminates a member's descendants -- the property a signal cannot offer. **Not proven:** memory/pids/cpu *enforcement* end to end, because the cgroup directory the probe selects inside `rust:1-bookworm` is not one it can create children in, so the suite reports NOT_PROVEN there. `alpine` was separately verified to accept a subdirectory at the hierarchy root, so the remainder is directory selection, not a missing kernel capability. Two host facts worth recording: `--cgroupns=host` is required, because Docker's private cgroup namespace makes PID spaces disagree and `cgroup.procs` writes fail with ENOENT on an obviously-correct path; and the own-cgroup path is not always creatable, so discovery falls back to the hierarchy root rather than reporting "no delegation" in an environment that delegates. |
| **V-53** | **A resource ceiling is required per capability, not by blanket default** | `ExecutionContract::require_resource_ceilings`; `spec_for` maps it to `Resource::Required` or `Resource::Observed` | **release:** any change to the contract's defaults | 2026-09-30 | **Medium.** A blanket `Required` default would refuse every Tier-1 capability on a host without delegated cgroups -- fail-closed in form, but a sandbox that never runs in practice, and pressure to weaken the default later. The distinction is per capability: something that cannot safely exceed a limit sets `true` and is **refused**; something that can sets `false` and receives supervisor-side observation, recorded in `ExecutionResult::unproven`. Fail-closed is preserved where it belongs -- the *host* never silently degrades a limit the caller asked for. |

| **V-55** | **The cgroup base is a parent, never the execution's home** | `CgroupV2::is_dedicated_child`; `resources.rs::an_execution_lands_in_a_dedicated_child_cgroup` | **release:** any change to `own_cgroup` or `CgroupV2::create` | 2026-09-30 | **Critical.** The phrase "falls back to the hierarchy root" was ambiguous and is now a checked property. Discovery may resolve the base to the cgroup hierarchy root (V-52), which is safe **only** because `create` always builds `base/orxnud-<name>`, writes limits to that child, and adopts processes into that child. Nothing ever writes a control to the base. Writing `memory.max` or `pids.max` on the shared base would throttle or kill processes OpenRayNux does not own, so `CgroupV2` now retains its `base` and exposes `is_dedicated_child()`, and a test asserts the execution directory is strictly below it and that the base carries no limit. **Reviewed rather than assumed** — the original wording would have been the basis for a wrong claim. |
| **V-56** | **Resource requirement and resource budget are separate, and the rule is in the contract** | `ResourcePolicy { required, budget }`; `a_requirement_is_not_a_budget`; applied in `spec_for` | **release:** any change to the resource rule | 2026-09-30 | **High.** A requirement is a precondition (`memory isolation or it does not run`); a budget is a per-invocation ceiling (`this invocation may use 64 MiB`). The deterministic rule, encoded in the contract rather than inferred by the dispatcher from what the host happens to offer: ```capability requires control X + X cannot be established -> REFUSE``` ```capability requires nothing + budget X unenforceable -> PROCEED, record the gap``` Replacing the earlier single `require_resource_ceilings: bool` with an explicit requirement list removes the temptation to read one field as both meanings. Recorded coarsening: any required control makes the request `Required` because the sandbox crate models resource enforcement as one switch, so a capability needing only `pids.max` is refused on a host offering `pids.max` but not `memory.max`. Coarse and safe beats fine and surprising. |

| **V-27** | **`cargo-deny` 0.20 removed `[licenses] deny`** — the copyleft prohibition is now expressed by the *absence* of copyleft from `[licenses] allow` | `cargo deny check licenses` on this tree; the tool's own error output (`error[deprecated]`) | **release:** re-read the tool's config schema | 2026-09-30 | **Medium.** ADR-0006/ADR-0019 forbid GPL/AGPL/NC. If a future `deny.toml` reintroduces a `deny` key, cargo-deny will *error* rather than silently ignore it — the failure is loud, but only if someone reads it. `scripts/ci-gates.sh` G8 fails on any cargo-deny error. |
| **V-28** | **The twelve Phase 1 gates actually pass on this tree** | `scripts/ci-gates.sh` (exit 0), run locally against Rust 1.98.1 | **milestone:** every commit in CI; **event:** a toolchain or dependency bump | 2026-09-30 | **High.** The gates are the Phase 1 deliverable (docs-13 §5). A gate that silently stops running is worse than a gate that fails, so G12 skips loudly when no release tag exists rather than passing vacuously. |
| **V-29** | ****Windows: all 16 crates compile for MSVC and the platform-neutral suites pass on a hosted Windows runner; the sandbox still has no Windows backend and a Tier-1 execution is refused there rather than degraded**** | `cargo check -p <crate> --all-targets --target x86_64-pc-windows-msvc`: clean for `orxnud-domain`, `orxnud-protocol`, `orxnud-config`, `orxnud-obs`, `orxnuctl`, `orxnud-platform-fs`, `orxnud-platform-sandbox`, `orxnud-platform-secrets`, `orxnud-platform-notify`; the `orxnud-platform-sandbox` `windows-portability` CI lane; mutation check: a type error planted in the `not(target_os = "linux")` arm fails the MSVC build and not the Linux build, so the Windows path is compiled, not dead | **release:** the Windows lanes report the result -- green on run 37343986458 (2026-10-05); **milestone:** any change to `platform::host_backend`, `SandboxRunner`, `spec_for`, or a platform crate's MSVC reachability| 2026-10-05 | **Scope, and what is deliberately still NOT proven.** The original V-29 was a single fact: the MSVC check was blocked *on this development host* by a missing C toolchain (`cc-rs: failed to find tool "lib.exe"`), not by a code defect. That remains true for the six crates behind bundled SQLite (`store`, `task`, `policy`, `audit`, `capability`, `daemon`) and no Rust-level error was observed in any of them. What has changed is that the Windows claim is no longer a single undifferentiated open item Reconciled 2026-10-05, and the entry was materially wrong before. It accounted for **15 of 16** crates -- `orxnud-platform-ipc` appeared nowhere in this file at all -- and it asserted that no Rust-level error had been observed. Both were false, and a hosted runner is what showed it. Five Rust-level MSVC defects were found and fixed across `9609892`, `3928e75`, `92808e4` and `1721761`: `Inner` declared only under `#[cfg(unix)]` in `platform-ipc`; `PermissionsExt` used unguarded in `orxnud-daemon`; three daemon *test* binaries naming `std::os::unix::net::UnixStream`; Linux-kernel tests in the sandbox lib; and two errno helpers left dead by that gating. The middle one is the instructive one -- gate **G3** greps for `cfg`, not for a platform API, so unguarded `std::os::unix` passed G3 and broke MSVC, which is this entry's own recorded "consequence of drift" arriving on schedule. **Corrected count: 16 of 16 crates**, 11 verifiable on a C-toolchain-free host and the remaining 5 (`store`, `task`, `policy`, `capability`, `daemon`) verifiable only on a runner with a real MSVC toolchain. **Still NOT PROVEN, and unchanged in substance:** Windows *isolation*. No Job Object or AppContainer backend exists, `host_backend()` binds the refusing `UnsupportedRunner` there, and a Tier-1 execution is refused rather than degraded. The portable core is now genuinely portable -- the mutation check proving the Windows arm is compiled rather than dead still holds -- but portability is not isolation. |

**PROVEN (compile-time, cross-checked):** the sandbox crate's platform dispatch is a real abstraction rather than a Linux import behind a portable name. Before this work `orxnud-capability` imported `linux::BwrapRunner` directly, so a Windows build would have bound a Linux backend and adding one would have required a `cfg` in a crate gate G3 forbids. `spec_for` also tested `program.starts_with('/')` for absoluteness, which is correct on Unix and refuses *every* Windows program (`C:\\...` is absolute and does not begin with `/`); it now uses `Path::is_absolute`, which was **measured** to be the identical predicate on Unix (19 inputs, 0 divergences) and correct on Windows.

**PROVEN (behaviour, on Linux):** a host with no sandbox backend reports `AvailableGuarantees::none()` and refuses every spec — including one that had relaxed every guarantee — with `MechanismMissing`, so the dispatcher's refusal happens before a spec is built, before a credential resolves, and before any process is created. `UnsupportedRunner` is the backend `host_backend()` binds off Linux, so this test is the Windows shape proved on a Linux host.

**NOT PROVEN, and deliberately so:** Windows *isolation*. Job Objects, AppContainer and Windows resource limits remain unimplemented (ADR-0035), which is why `host_backend()` returns the refusing runner there. A Windows backend would need `windows-sys` and `unsafe`, neither of which can be compiled or exercised on this host, so writing one here would have meant asserting enforcement that was never observed — precisely the failure this register exists to catch. **NOT PROVEN:** the Windows-native tests (`governed_path`, the sandbox integration suites, `measurements`) are Linux evidence and are excluded from the Windows lane with a stated reason each; they still **compile** for MSVC, which is what `cargo check --all-targets` proves.

**Consequence of drift:** a future change that hard-codes a Linux mechanism in the portable core, or that reintroduces a POSIX spelling of a path question, would not be caught by the Linux gate set — G3 only greps for `cfg`, not for a Linux type name. The Windows MSVC check and the new `windows-portability` lane are what catch it, and neither runs on this host. |

| **V-26** | **`libxdo.pc` on Fedora declares `/usr/local` prefixes that are wrong** | `/usr/lib64/pkgconfig/libxdo.pc` | **event:** a Fedora packaging change | 2026-09-30 | **Low.** Cosmetic; we do not feed its cflags to a compiler. |
| **V-57** | **The task engine's concurrency-budget check is outside the claim transaction; single-writer ownership is what makes it safe** | `crates/orxnud-task/src/engine.rs::claim_task_id` reads `live_leases` *before* `repo().claim_specific(...)` opens `BEGIN IMMEDIATE` | **release:** any change that lets a second writer reach a `DurableEngine`, or any move of the budget check | 2026-10-03 | **Medium.** The check-then-take shape is a TOCTOU on its face, and it is deliberate: it is the structure `claim_task_at` already used, kept identical rather than "improved", because correctness here rests on ADR-0006 single-writer plus the runtime's single `Mutex` around `(Daemon, Secrets, TaskService)` — two claims cannot interleave, so nothing can slip between the count and the take. Preserved as-is in the targeted-claim slice. The risk is that this is now load-bearing on *ownership* while reading as a transaction concern: a second writer — a second runtime, a background scheduler thread, a future IPC server per connection — would let the budget be exceeded with no error and no log. Nothing enforces the single-writer assumption at the type level. Do not "fix" the ordering without also recording why the new ordering is safe. |
| **V-58** | **4 of the 5 sandbox network-isolation tests do not fail when `--unshare-net` is removed** | Mutation: disabling the `argv.push("--unshare-net")` in `crates/orxnud-platform-sandbox/src/linux.rs` fails only `a_child_cannot_connect_outwards_without_a_grant`; `a_child_cannot_reach_the_host_network_even_though_it_may_bind_a_socket`, `a_child_cannot_resolve_dns`, `a_granted_network_removes_the_namespace_...` and `a_socket_bound_in_the_namespace_is_unreachable_from_the_host` all stay green | **milestone:** before any test is relied on as evidence of network isolation | 2026-10-03 | **Medium.** Not a sandbox defect — the mechanism is independently verified (see V-46) and the sandbox was *proven healthy* during the fixture repair. Two causes, both pre-existing. (1) `a_child_cannot_reach_the_host_network...` asserts only `stdout.contains("RESULT")`, accepting PASS or FAIL on purpose; its own comment records that as a deliberate correction, since a netns does not prevent `bind(2)`. (2) `a_child_cannot_resolve_dns` passes for a *filesystem* reason: the sandbox tmpfs root binds `/usr /lib /lib64 /bin /sbin` and **not** `/etc`, so `/etc/resolv.conf` is absent and resolution fails regardless of the netns. So the suite has exactly one netns-sensitive network test. Strengthening the others is a separate task and must not be done by weakening assertions. |
| **V-59** | **`request_cancel` refuses a `paused` task although `is_legal_transition` allows `Paused → Cancelled`** | `crates/orxnud-store/src/task_repo.rs::request_cancel` returns `Ok(())` for any state where `TaskState::is_terminal()` holds, and `is_terminal` includes `Paused` (`crates/orxnud-domain/src/task_state.rs:171`); but `is_legal_transition` maps `Paused => matches!(to, Running \| Cancelled)` (`task_state.rs:386`) | **release:** any change to `is_terminal` or to the transition relation | 2026-10-03 | **Low, and deliberately not changed.** The implementation refuses **more** than the transition relation requires, which is the fail-closed direction: a task that cannot be cancelled cannot be wrongly cancelled. Found while exposing cancellation over IPC, by reading the implementation rather than its comments — the CLI surface makes the question "which states can be cancelled?" one a user can now actually ask. Either `Paused` should be removed from `is_terminal` (it is a resting state, not an end) or `Paused → Cancelled` should be dropped from the transition relation; changing either alters established engine semantics, so it is recorded rather than fixed. Until then `paused` tasks are uncancellable and this is the documented, deliberate answer. |
| **V-60** | **`Verifier` could not see the invocation's parameters, so a deterministic capability could only be verified against itself** | `Verifier::verify(&self, execution, at_ms)` received no input; `AdapterBundle::verifier()` returns a per-capability singleton (`crates/orxnud-capability/src/dispatch.rs`) | **release:** any change to the `Verifier` trait | 2026-10-03 | **High, and fixed.** For a capability whose whole effect is a function of its input, the only independent verification route is to recompute the answer from that input. Without it, a verifier can inspect the adapter's output and nothing else, so it returns `Verified` for any well-formed output — including a wrong one. `verify` now also takes the validated `params`, which reach it already normalised by policy and via the actor-free view. The three-way `Verified`/`Refuted`/`Undetermined` model is unchanged; the verifier gained the *information* it needed rather than any new way to conclude. Independence is bounded and the bound is documented in `crates/orxnud-capability/src/text.rs`: the verifier and adapter use structurally different algorithms, so a shared *implementation* defect is caught, but a shared *misreading of the contract* would not be — the contract is the shared input, and for a pure function that is inherent. Mitigated by stating the contract in module docs and pinning each case in tests. |
| **V-61** | **`BudgetLedger::permits_all` is conjunctive, so per-risk ceilings cannot express "only Low may spend"** | The engine checks one cost against **every** declared ceiling (`permits_all`/`charge_all`, `crates/orxnud-policy/src/engine.rs`). Verified by running the daemon: funding `cost:low` and zeroing `cost:medium`/`high`/`critical` refused the Low-risk capability, naming `cost:critical` as the ceiling that bit | **milestone:** before any per-risk budget is configured | 2026-10-03 | **Medium.** Four per-risk ceilings read as four independent permissions and are one conjunctive constraint on a single number, so the intuitive configuration ("fund the cheap scope, zero the rest") silently refuses everything. The failure is loud at runtime and silent in the source. The shipped budget is therefore a single `with_global` ceiling. This does **not** widen authority: a declaration, a grant covering the data class, and — for High and above — a single-use digest-bound approval are all still required, and a global ceiling supplies none of them. Worth stating because the natural next change is "give each risk class its own budget", which would look like a refinement and would instead couple the scopes. |
| **V-62** | **Production dispatch stamped every audit record `at-ms: 0`, which also made approval expiry vacuous** | `crates/orxnud-daemon/src/runtime.rs::dispatch` passed a literal `0` as `now_ms`. That value is not only recorded — `Dispatcher::dispatch` forwards it to `authorise_for_dispatch` (which compares an approval's `expires_at_ms` against it), to `Verifier::verify`, and to the stage-9 completion record. Observed live before the fix: both records of a `text/word-count` dispatch carried `"at-ms": 0` | **release:** any change to the daemon's dispatch call, or to how `now_ms` reaches `dispatch`** | 2026-10-03 | **High, and fixed.** Two independent harms. (1) *Audit:* a journal whose every timestamp is `0` orders records by sequence alone and cannot answer "when", which is most of what an audit log exists for — and approval expiry and any future time-based policy would read it as authoritative. (2) *Authorisation:* `expires_at_ms` compared against `0` can never be in the past, so **every approval verified regardless of age** — the single-use/time-boxed part of the approval model was inert while looking enforced. The second harm is the serious one and it was silent: nothing errored, and the low-risk capability that exposed the timestamps is precisely the one that needs no approval, so no visible behaviour changed. Fixed by reading the wall clock inside the governed lock, immediately before `dispatch`, via `orxnud_task::clock::SystemClock` — the crate whose module doc claims to be the single `SystemTime::now()` in the tree, so no new time source was introduced. Pinned by `a_dispatch_is_audited_with_a_real_wall_clock_instant` (asserts every stamp lies inside the interval the dispatch ran in, is non-decreasing, and is unchanged by a restart) and mutation-verified: restoring the literal `0` fails it. Note `crates/orxnud-daemon/src/task_service.rs:356` reads `SystemTime::now()` directly, so that "single source" claim was already untrue — see V-64. |
| **V-63** | **The approval digest was computed over a constant `{}` while the adapter ran the real parameters** | `crates/orxnud-daemon/src/runtime.rs::dispatch` passed `NormalizedParams::canonical("{}")`, discarding `ActionRequest::params` (`crates/orxnud-domain/src/invocation.rs:53`), which is the value the adapter and verifier actually receive (`invocation.rs:392`) | **release:** any change to how `NormalizedParams` is derived for a dispatch, or to `canonical_params` | 2026-10-03 | **High, and fixed — the more serious of the two dispatch defects.** `dispatch` receives the parameters twice, once raw inside `ActionRequest` and once normalised as `NormalizedParams`, and nothing in the dispatcher can detect that the second does not describe the first. So one approval would have covered *every* invocation of that capability: a user could approve `{"to":"alice"}`, have the digest verified, and have `{"to":"attacker@evil.test"}` execute — with all nine stages reporting success. Latent today only because the sole shipped capability is Low-risk under a standing grant, so no digest is ever compared; it becomes live the instant a High-risk capability exists. Fixed by deriving the parameters from the action at a single named seam (`approval_params`) via `orxnud_policy::canonical_params`, which sorts object keys recursively. The sort is explicit rather than inherited from `serde_json::to_string` on purpose: serde_json is built without `preserve_order`, so its `Map` is a `BTreeMap` and would already have sorted — relying on that would make every approval digest depend on a feature flag in a `Cargo.toml` nobody reading `digest.rs` would look for. Array order is deliberately **not** normalised, since `["a","b"]` and `["b","a"]` are different arguments. Pinned by 5 tests in `orxnud-policy` that fail against the placeholder (mutation-verified) plus a proptest for key-order invariance, and by 2 seam tests in `runtime.rs` proving the wiring. Honest limit: the key-order tests alone do **not** catch the placeholder — a constant is trivially order-invariant — so the load-bearing tests are the digest-*changes*-with-parameters ones. |
| **V-64** | **`orxnud-task::clock`'s claim to be the tree's only wall-clock read is already untrue** | `crates/orxnud-task/src/clock.rs:13` states "`SystemClock` is the single place that reads the wall clock, which makes it greppable: one file, one `SystemTime::now()`", but `crates/orxnud-daemon/src/task_service.rs:356` (`fn now_ms`) and `crates/orxnud-store/src/migration.rs:323` both call `SystemTime::now()` directly | **milestone:** before any time-dependent policy or approval expiry is relied upon** | 2026-10-03 | **Low.** Recorded because V-62's fix routes capability dispatch through `SystemClock` on the strength of that claim, and the claim is wrong: there are three direct clock reads, not one. Nothing is broken by it today — `task_service::now_ms` and `SystemClock` agree to the millisecond, and `migration.rs` stamps a one-time bootstrap. The hazard is future and specific: a change that needs the *same* instant in two subsystems can pick two sources, get values differing by a millisecond, and produce an off-by-one in a window comparison (`issued_at <= now < expires_at`) with no error anywhere. Worth collapsing to one source when time starts mattering structurally, and worth correcting the comment now that it is known to be aspirational. Not fixed here because both call sites are load-bearing established behaviour and this slice is about dispatch correctness. |
| **V-65** | **A `pids.max` of 1 makes every Tier-1 capability fail with an opaque `EAGAIN` from `bwrap`** | `ResourceBudget.processes` bounded the payload, but `pids.max` bounds the whole cgroup — which also holds the sandbox supervisor's own task tree. Measured on this host: `pids.max = 1` fails at namespace creation (`Creating new namespace failed: Resource temporarily unavailable`), `= 2` fails at `Can't fork for pid 1`, `>= 4` runs. The shipped `filesystem/write-text` budget originally requested `Some(1)` and every sandboxed invocation failed | **release:** any change to a Tier-1 capability's resource budget, or to how the supervisor is spawned | 2026-10-03 | **Medium, and fixed by understanding rather than by guessing.** The failure mode is genuinely nasty: it presents as a sandbox failure, is unaffected by anything the capability does, and is fixed by a number that looks arbitrary in the source. Two things are worth keeping from it. First, `processes` means *processes this invocation may use*, where "this invocation" includes the machinery that runs it — the tidier-looking `1` is the one that does not work. Second, the shipped value is `16`, not the measured floor of `4`: a ceiling set exactly at the floor turns a future sandbox that grows a task or two into a capability that fails for a reason nothing in the capability's source mentions. Discovered by probing the backend with the five limit combinations rather than by reading, because no amount of reading `write_text.rs` would have suggested that `1` was the problem. |
| **V-66** | **Tier-1 invocation parameters cannot reach a sandboxed child: `AdapterBundle::sandbox_plan()` took no invocation** | `crates/orxnud-capability/src/dispatch.rs` — `sandbox_plan(&self)` returned a constant `SandboxPlan`, and for `ExecutionTier::Subprocess` the dispatcher never calls the adapter's `invoke` (it executes the contract built from that plan). The only dynamic channel into the child was `CREDENTIAL_ENV`, injected by the backend for credentials | **milestone:** before any second parameterised Tier-1 capability | 2026-10-03 | **High, and fixed with the smallest change that works.** A parameterised Tier-1 capability was not implementable at all: the adapter is not consulted, so `dispatch` receives the parameters twice — raw in `ActionRequest.params` and normalised as `NormalizedParams` — and nothing could carry the first to the child. The alternatives were both worse than the defect. Passing data through the credential environment variable would put a payload somewhere that is specifically redacted for secrets and audited as credential-shaped. Writing a request file host-side *before* dispatch would create a filesystem side effect *before authorisation*, which is strictly worse than the bug this was found alongside. So `sandbox_plan` now takes `&CapabilityInvocation`: additive (the one Tier-0 bundle returns `None` and ignores it), two dispatcher call sites, one test impl, and the sandbox crate, verifier and stage order are all untouched. Worth stating plainly because it means the capability layer's plan interface was, until now, missing a parameter it structurally needed. |
| **V-67** | **`SandboxSpec` has no stdin channel, so Tier-1 parameters travel in `argv` and are visible in the host process table — OPEN, P0** | `filesystem/write-text` passes `--path` and `--contents` as arguments; `crates/orxnud-capability/src/subprocess.rs::spec_for` forwards `contract.args` to the sandbox command line; `crates/orxnud-platform-sandbox/src/linux.rs` renders every `spec.env` pair as an `--setenv K V` **argv** pair. **Cross-UID exposure demonstrated 2026-10-10, not inferred from file mode:** on the audit host a container sharing the host PID namespace and running as uid 12345 (`CapEff 0`, same user namespace inode `user:[4026531837]` as the uid-1000 target) **read the target's `/proc/<pid>/cmdline` successfully**, recovering the sentinel argv bytes. Controls in the same run: writing `/proc/<pid>/cmdline` was **denied** (so `0444` is the operative constraint for writes), and reading `/proc/<pid>/environ` was **denied** (`0400`, owner-only) — the credential path is distinguishable from the payload path only because `spec.env` becomes argv. **Condition — this is host-dependent and must be re-measured, not assumed:** `/proc` is mounted `rw,nosuid,nodev,noexec,relatime` with **no `hidepid` option**, i.e. the default `hidepid=0`. `hidepid>=1`, or a `ptrace`-scoped hardened kernel, restricts cross-user process-directory access and would change the answer. `ls -l` mode alone is **not** evidence of a cross-UID read and is recorded here only as supporting context | **release:** any **payload-carrying or credential-carrying** Tier-1 capability; and **governance:** none may ship until the stdin transport is verified — re-read on any change to `SandboxSpec`, `spawn_supervisor`, `write_text.rs`, or the credential-environment path. The prior trigger, *"any Tier-1 capability whose parameters are sensitive"*, was too narrow: it would not have fired for `write-text`, whose contents are a workspace payload rather than a secret | 2026-10-10 | **P0, OPEN — not mitigated.** Reconciled 2026-10-10 against the independent audit (`docs/16` finding F-10) and its validation (`docs/17`), and against the remediation plan (`docs/18` §12 R-1, §7 S-02/S-17). **The earlier characterisation of this row as "Low for this capability" was wrong and is withdrawn.** It judged the exposure by whether the bytes are secret; the actual exposure is that **any local uid can read this user's process table for the life of every `write-text` execution**. **Current exposure:** the shipped `filesystem/write-text` passes its payload as process arguments, so it is readable through `/proc/<pid>/cmdline` for as long as the execution lives. This has **not** been fixed. **Governance restriction, in force now:** no new payload-carrying or credential-carrying Tier-1 capability may ship until the stdin transport (plan slice **S-17**) is verified against its stated acceptance criteria. That is a **governance decision recorded here and in `docs/18` §12 R-1 — it is not enforced by any runtime check, CI gate, or configuration in this repository.** **Verification boundary — recording this restriction does not fix the runtime.** The interim
control (plan slice **S-02**) **is implemented and verified as of 2026-10-10**, and it is
**containment of reachability for the default posture, not a mitigation of the exposure**.
What was built: `AdapterBundle::argv_payload` has **no default** and returns
`ArgvPayload::{None, Content { implementation_bound }}`, so every bundle must declare what it
places in `args`; the dispatcher refuses such a bundle at stage 5 — **before** credential
resolution and before any process exists — with `DisabledReason::ArgvPayload`, surfacing as the
distinct code `argv_payload_exposure_refused` rather than a generic `capability-disabled`; and
`daemon/status` plus the startup banner disclose the exposure class, the affected capability,
the refused/permitted split and `status: OPEN`, with the field **absent** rather than `null`
when nothing is exposed.

**Two corrections this row now carries, both narrowing an earlier overstatement.**
*Cross-UID readability is host-dependent and is not claimed generally.* `/proc/<pid>/cmdline`
is mode `0444`; that a **different** uid can *read* it was **demonstrated on the measured audit
host with the default `hidepid=0`**, and `hidepid>=1` or a `ptrace`-scoped hardened kernel
changes the answer. The disclosure says so rather than asserting it for every Linux host.
*No payload-size number is published.* The earlier `Some(131072)` is withdrawn: that figure is
Linux `MAX_ARG_STRLEN` (`32 * PAGE_SIZE`, including the terminator), which is **131072 on a
4 KiB page and 2097152 on a 64 KiB one**, and it is a host kernel constant rather than a bound
this implementation enforces — `write-text` puts the caller's `contents` there verbatim and
imposes no limit. The disclosure reports `implementation_bound_bytes: null`.

**ADR-0054 implemented 2026-10-10 — the payload half is fixed and measured; F-10 stays open.**
The Tier-1 payload no longer travels in `argv`. `write_text`'s plan carries only `--path` and a
transport-version flag; the body is a **framed** payload on the child's stdin
(`ORXNUD-STDIN/1` + `contents-length` + a bounded header cap), the supervisor writes it on a
dedicated thread and **closes stdin before waiting** (Decision 3a), and the helper refuses every
deviation. Verified on the production path, not on a copy of the rendering:
`the_payload_does_not_appear_in_the_bwrap_argument_vector` drives the shipped bundle through a
real policy engine and `dispatcher.dispatch`, renders the spec and the exact `bwrap` argv with
`BwrapRunner::argv_for`, and asserts the sentinel is absent — **that one assertion covers both of
R-1's command-line surfaces**, because the cgroup branch launches
`/bin/sh -c '… exec "$@"' … BWRAP <argv>` and the joiner shell carries the same vector.

**R-1's four conditions, checked individually rather than in aggregate.**

**The real sandbox lane was run end to end for the first time on 2026-10-11, and it is
green: 120 tests, 0 failures, exit 0.** `scripts/run-sandbox-tests.sh` inside the pinned
`rust:1-bookworm@sha256:114c7a44…` image, on the unprivileged uid with every capability
dropped. Per suite: `governed_path` 31/31, `read_text_real` 10/10, `write_text` **17/17**,
`orxnud-platform-sandbox --test isolation` 26/26, `cli_e2e` 36/36. The container's own
preflight is affirmative and is the positive Tier-1 evidence this lane exists to produce:

    RESULT: a Tier-1 capability can be sandboxed and executed here.
    shape:  NESTED user namespace -- the production configuration
    guarantees: visibility=true tree_lifetime=true resources=false
    tier1_executable: yes

`resources=false` is honest and load-bearing: cgroups are **not** delegated inside this
container, so resource-ceiling enforcement is not established here. That is what
`scripts/run-resource-tests.sh` is for, and it is why it is a separate lane.

`write_text` 17/17 is the end-to-end result for S-17: the framed payload was written,
closed and consumed by a real `orxnud-fswrite` inside a real `bwrap` sandbox — including
`bytes_arrive_exactly_with_nothing_interpreted`, `an_empty_file_is_the_requested_effect_not_a_
missing_one`, and `an_approved_write_reaches_the_sandbox_and_verifies_from_the_filesystem`.

**Running that lane for the first time exposed three real defects, none of them in S-17.**
1. `setpriv` changes the uid but not the environment, so the unprivileged run inherited
   `HOME=/root` and `cargo-nextest` died with `Permission denied` on
   `/root/.config/nextest/config.toml` — the lane aborted **before a single Tier-1 test ran**.
   `HOME` and the XDG directories are now set on the `setpriv` line.
2. `run-sandbox-tests-inner.sh` still selected `governed_path`, `read_text_real` and
   `write_text` with `--test`, but those are **modules inside `src/tests/`**, not integration
   binaries, so the build failed with `no test target named 'governed_path'`. They are now
   nextest **filters** on the module path. The same stale spelling had already been corrected
   once in `ci.yml`; this script was missed, and only an end-to-end run could find it.
3. `governed_path::v46::an_unexpressible_budget_is_refused_before_any_cgroup_or_process_exists`
   asserted that the refusal comes from *budget validation*, but on a host that cannot make
   cgroups `can_fulfil` refuses **first**, with a different message. It passed on a developer
   machine and failed in the container: it was measuring the environment, not the code. It now
   asserts the property both branches share — *refused before any cgroup or process exists* —
   and additionally that neither refusal reports a cgroup path.

1. **NOT MET.** The *payload* sentinel is absent from every readable `/proc` surface, measured
   live while a real sandboxed execution ran: `/proc` mount options
   `"rw,nosuid,nodev,noexec,relatime"` (no `hidepid` option), `cmdline` mode `444`, `environ`
   mode `400`, observed `cmdline = false`, `environ = false`. **The credential half is vacuous**:
   credential-bearing Tier-1 capabilities remain prohibited (ADR-0054 Decision 5), so there is
   no credential to carry a sentinel. The condition is **not satisfied** and must not be reported
   as if it were.
2. **MET.** `write_text`, `read_text` and `governed_path`: 65 tests, 65 passed — and now also
   inside the container, where `write_text` is 17/17 against the real sandbox.
3. **MET, with the recorded qualification.** `scripts/run-sandbox-tests.sh` completed end to
   end on a user-namespace-capable host: 120 tests, 0 failures, exit 0, with an affirmative
   preflight. This is the dedicated lane R-1 names, not a substitute for it. It was not run on
   a GitHub-hosted runner, which cannot create a user namespace and therefore cannot produce
   this evidence; the lane's own reporting on such a host would be `reduced coverage`, not
   isolation.
4. **NOT MET**, and cannot be while (1) is open.

**What the framing rules are worth, demonstrated.** A declared zero is a valid empty write; an
empty *stream* is refused and writes nothing (`an_empty_stream_is_refused_rather_than_writing_an_
empty_file`); a short body, trailing bytes, a duplicate or malformed length, an unknown protocol
and an over-cap header are each refused **with no file created**; 1,048,576 bytes exactly is
accepted and one more is refused before any process exists; the bound is counted in UTF-8 bytes,
proven by a payload that is under the limit in *characters* and over it in *bytes*. The
close-after-frame requirement is a negative test against a reader that never reaches EOF, and it
is shown to still complete once the stream closes, so it is measuring the missing EOF rather than a
reader that simply never terminates. 16 concurrent helper processes each receive their own body.

**Credential handling is unchanged and still open.** `SandboxSpec.env` renders as `--setenv K V`,
which is `argv`. ADR-0054 explicitly did **not** change this, and a stdin fix does not touch it.

**Design record, 2026-10-10 — no fix has landed.** The permanent correction is decided and written
as **ADR-0054**: the payload travels on the sandboxed child's stdin and never in `argv`, with a
1 MiB bound measured in UTF-8 bytes of the normalised `contents` that refuses rather than
truncates, a writer thread so the parent cannot deadlock, and a **versioned frame carrying the
expected payload length** so that a declared length of zero is a valid empty write while
missing metadata, an unexpected EOF, a length mismatch or excess trailing data are each
refused rather than written. Daemon/helper transport versioning is explicit, so an old helper
with a new daemon is refused rather than silently mismatched. Feasibility was **measured** on the development host before any edit — `bwrap`
forwards its own stdin to the sandboxed child, and 262144 bytes complete with no deadlock when
the child reads — and the cross-uid harness above was reproduced on that same host (`cmdline` read
by uid 4242 succeeded; `environ` denied). **ADR-0054 is written and not yet merged, and
`docs/18` §6.3 gates the implementation phase on that, so no S-17 code exists.** Two consequences
recorded rather than smoothed over: `SandboxSpec.env` still renders as `--setenv K V`, so the
**credential** channel is unaffected by any stdin fix and credential-carrying Tier-1 capabilities
remain prohibited; and R-1's first condition requires a credential sentinel, which is not
reachable while no credential-carrying capability exists — so a payload-only pass would leave that
condition **vacuous**, not satisfied.

**What this is not.** The argv transport is unchanged. Any execution permitted to run still
places its payload in the host process table for the life of the execution — **F-10 stays open
and this row is not evidence of containment.** **There is also no user-reachable way to grant
the exception:** the configuration key and environment variable that were briefly added have
been removed, and the one remaining route (a flag used by suites that spawn the real binary) is
compiled out of release builds. Granting it therefore requires a source-level decision, which is
*not* the plan's bounded owner approval — that mechanism does not exist, and the open owner
decision is recorded in `docs/18` §12.

**Evidence.** `a_fully_approved_write_is_refused_by_default_and_writes_nothing` drives propose →
**real human approval** → execute against a daemon in the shipped default posture and asserts
both the named refusal and that no file was written (the approval is load-bearing: the gate is
at stage 5, so an unapproved request would be refused by policy and prove nothing);
`an_argv_payload_capability_is_refused_by_default_and_spawns_nothing` was demonstrated **failing
before the change** with `DispatchOutcome { execution: Succeeded(...), verification: Verified(...) }`
— the real helper ran — and passes after. Negative controls assert that `text/word-count` and a
no-payload Tier-1 bundle are unaffected, that the disclosure cannot be a constant, and that the
exposure text carries the `hidepid` condition. **Not claimed:** no mutation testing was run.

**Credential handling is a separate risk, and credential redaction does not mitigate this exposure.** `CREDENTIAL_ENV` remains the only channel carrying anything secret and is redacted throughout; that is a distinct and still-latent concern. It does **not** reduce this row: the payload is not a credential and never passes through the redacted path, and because `spec.env` is rendered as `--setenv K V` **argv pairs**, any bundle that populated `env` would place that value in the same world-readable `cmdline`. The two exposures must not be described as one mitigated problem. Adding a stdin channel means changing `SandboxSpec` and the supervisor; that change is specified but **unbuilt**. |
| **V-68** | ****`orxnud-task`'s `n_workers_sharing_a_file_produce_exactly_one_winner_per_task` fails intermittently under full-workspace parallel load -- now 4 recorded occurrences, and the cause is still undiagnosed**** | Observed once in `./scripts/ci-gates.sh` while 1004 tests ran concurrently; passed 13/13 in isolation and in 8 consecutive `cargo nextest run -p orxnud-task` runs. This slice changed no file in `orxnud-task` or `orxnud-store` | **milestone:** before relying on a full-workspace green run as evidence -- re-read 2026-10-05| 2026-10-05 | **Low, pre-existing, and not this slice's to fix.** Recorded rather than dismissed because a suite that is intermittently red cannot distinguish a real regression from load, which is exactly the value it is being relied on for. It is a concurrency test over a shared file, so the likely cause is timing under CPU contention rather than a logic error — but "likely" is a guess, and the honest next step is to reproduce it under deliberate contention and read what the failure actually says. Left alone here: this slice changed nothing in `orxnud-task`, and a drive-by fix to a task-engine concurrency test would be a worse change than the flake. Corrected 2026-10-05, because the entry understated its own subject. It said "observed once" with a 13/13 isolation pass rate; the commit that introduced multi-step composition recorded the same test failing **twice more** in full runs while passing **8/8** in isolation, and V-42 records a fourth. So: 4 occurrences across V-42 and V-68, and the isolation pass count fell from 13/13 to 8/8. The cause is still not known -- it is a concurrency test over a shared file, so timing under CPU contention is a *guess*, and this register does not record guesses as findings. What is now measured and stable: the full-workspace suite is green, and has been on every run since, including 1360/1360 locally and 1244/1244 on a hosted runner under the G9 scope ADR-0046 defines. A suite that is intermittently red cannot distinguish a regression from load, so this stays open until someone reproduces it under deliberate contention and reads what it says. |
| **V-69** | **An approval carries no approver identity anywhere, so it is a bearer token that proves parameters but not consent** | `ApprovalRecord` (`crates/orxnud-domain/src/approval.rs`) has fields `actor_label`, capability, target, params, issued/expires, risk, digest — no approver. `canonical_bytes` (`crates/orxnud-policy/src/digest.rs`) binds `actor.label()`, `actor.authority_root()`, capability, target, params and the time bounds: the *proposer's* identity is inside the digest, the approver's is not. `actor_label` is written to the record and to `task_approvals.actor_label` and is **never read at dispatch** (`grep` finds no comparison outside tests). `Decision::Gate.approver` is *derived* at `engine.rs:396` from the proposer's `authority_root()` — an inference where evidence belongs | **milestone:** before any actor other than `Human` reaches the dispatcher, and **release:** on any change to `canonical_bytes`, `ApprovalRecord`, or the `can_grant` enforcement at `engine.rs:266` | 2026-10-03 | **High, latent, and it becomes live the moment a delegated actor exists.** Not exploitable today: with one local user behind a 0700 socket, minting an approval on request is equivalent to that user consenting. The reason it is High anyway is the *shape* of the failure. `capability/approve` answers any caller, and the runtime hardcodes the approver to the local human, so a pipeline built on this would let an AI-side workflow obtain its own approval through the same endpoint and every stage would report success — a **false demonstration of governance**, which is worse than no delegation because it would be trusted. The load-bearing consequence is that `can_grant()` is currently enforced in exactly one non-test place and only refuses an actor with neither grant capability nor an authority root; it cannot check *who approved* because there is nothing to check. **Now implemented.** ADR-0037 (D1, D2) landed: the record carries an explicit `approver`, `canonical_bytes` binds both parties under a `v2` prefix, `authorise` refuses a non-granting approver and an approver who is not the proposer's authority root, and `issue_approval` refuses to mint without `can_grant()`. Verified by mutation: removing the approver from the digest fails `the_digest_binds_the_approver_so_one_consent_cannot_be_replayed_by_another`. Demonstrated end-to-end on the governed task path, where a proposal delegated by the local human is approved with `actor_label: ai`, `approver: human`, `authority_root: local`. |
| **V-70** | **An `Actor` arriving over local IPC is an asserted principal, not an authenticated identity, and the type does not say so** | `Actor` derives `Serialize, Deserialize` (`crates/orxnud-domain/src/actor.rs`), so `Actor { user: "H" }` can be sent by any caller. `crates/orxnud-daemon/src/runtime.rs:560` hardcodes `local_actor()` and never reads an actor from the request, so nothing depends on this yet | **release:** any move to multi-user access, any transport beyond the local socket, or any code that starts treating a deserialised `Actor` as proof of identity | 2026-10-03 | **Medium, and it is a hazard rather than a defect.** Nothing is wrong today: the practical boundary is the 0700 Unix socket plus the single-user local model, and the runtime not accepting an actor at all is the strongest possible current posture. The risk is entirely in what comes next — `Actor` being `Deserialize` is easy to later read as "the daemon knows who this is", which is the same class of mistake ADR-0034 caught in `CapabilityInvocation`. Three things must stay distinct in naming, docs and tests: *principal assertion* ≠ *principal authentication* ≠ *principal authorization*. Recorded so that multi-user work starts by naming the boundary rather than inheriting an ambiguity. Settled as a constraint by ADR-0037 (D6); deliberately **not** fixed, because multi-user authentication is out of scope and inventing a half-measure now would be worse than the honest gap. |
| **V-71** | **Task lease and worker identity must never grant or derive capability authority — currently true only by absence of code** | A lease grants exactly one capability: completion fencing (`complete` requires a live lease from that worker), plus `extend`/heartbeat and the concurrency slot. Verified: **no `Actor::` is constructed from a task or a lease anywhere in `orxnud-task`, `orxnud-daemon` or `orxnud-store`** — the only non-test construction is the hardcoded local human at `runtime.rs:560` | **milestone:** before `task → capability` execution is wired, and **release:** on any change that derives an actor, a grant or an approval from a task id, a lease or a worker identity | 2026-10-03 | **Low now, and the most important thing in this block to preserve.** It is currently guaranteed by nothing but the absence of the code path that would break it, which is exactly the kind of truth that erodes without anyone deciding to erode it. The foreseeable regression is convenient rather than malicious: wiring task-driven execution makes it natural to derive the actor from the claimed task, and that derivation would silently convert *ownership of a workflow* into *authority to perform every capability the workflow represents*. **Now implemented and demonstrated.** The proposal path builds the proposer from the task identity and never from the lease holder, and the `task_proposals` table has no worker column at all, so the escalation is unavailable by schema as well as by code. ADR-0038 (D5) is a regression test: `the_lease_holder_does_not_become_the_proposer` asserts that a worker without the live lease cannot propose and that a legitimate holder's proposal records a delegated actor rather than itself. Verified by mutation: deriving the actor from the worker string fails it. Also worth keeping in view while wiring: `may_use_approval` checks expiry only and never verifies the digest against the action, deferring that to policy — so it must not be read as "this action is authorised". |
| **V-72** | **Durable proposal parameters were parsed with `.unwrap_or(json!({}))`, so unreadable stored state produced a *verified* execution of `{}`** | `execute_proposal` in `crates/orxnud-daemon/src/runtime.rs` built the `ActionRequest` from `serde_json::from_str(&proposal.params).unwrap_or(json!({}))`, while the digest is computed over the stored canonical **text**. A corrupt row therefore still matched its own digest and the adapter then ran with empty parameters | **milestone:** closed in this slice, before any second delegated capability | 2026-10-03 | **High, and fixed.** The shape is the reason it matters: this was not a crash and not an error, it was a *successful governed execution of parameters nobody approved*, reported as `verified: true`. Defaulting is only safe when the default is also what was authorised, and here it never is. It is worth recording as a class rather than an instance: any durable field that feeds a digest must be parsed with a hard failure, because the digest covers the text and therefore cannot detect that the structured reading of that text failed. `unreadable_stored_parameters_are_refused_rather_than_defaulted` corrupts both the proposal and the approval row so the action-mismatch pre-check cannot mask the parse guard, and asserts `proposal-corrupt` with no side effect. |
| **V-73** | **A consistently wrong canonicalisation is invisible to every behavioural test** | Discovered by mutation: replacing the proposal's canonical form with `{}` left all 26 governed tests green, because the proposal stores what it is given, approval is computed over the stored value, and execution replays the stored value — so a uniform substitution is self-consistent | **milestone:** before any capability whose parameters carry authority, and **release:** on any change to `canonical_params` or to how a proposal's params are stored | 2026-10-03 | **Medium, mitigated.** Not a defect in the implementation — a gap in what behavioural tests can see. Every end-to-end assertion in the governed suite asks "did the right thing happen", and a uniformly-wrong canonicalisation still does the right thing *for the wrong recorded operation*. The only test that catches it compares the stored canonical text against the request that produced it (`the_proposal_commits_to_the_parameters_that_were_requested`), which was added after this was found by mutation rather than by reading. Recorded because the general lesson is easy to forget: mutation testing finds holes that green suites do not, and this one was invisible until a mutation was aimed at it. |
| **V-74** | **`orxnud-task`'s wall-clock regression bounds fail under CPU contention, and they are the only tests in the workspace that can** | Observed twice in isolated `git archive` builds of this milestone: `completion_latency_is_the_other_half_of_the_hot_path` and `recovery_scales_with_the_backlog_and_stays_bounded` failed while a cold workspace build was still finishing. Both pass 3/3 in the warm checkout, and both call `report(...)`, which asserts a per-operation microsecond bound rather than a correctness property | **milestone:** before treating an isolated-build verification run as evidence, and **release:** if the task engine's write path changes | 2026-10-05 | **Low, and deliberately not "fixed".** The failure is the tests doing their stated job — the file's own comment says the purpose is to notice a 10x regression, and a cold build competing for CPU is not a 10x regression in the engine. Raising the bounds would destroy the only signal these tests provide. The honest consequence is procedural: **an isolated-build run of the full suite is not a valid verification signal while a build is in flight**, and the isolated run must be repeated on a quiet machine before it is believed. Distinct from V-68, which is a correctness test flaking under parallel test load; this is a performance bound flaking under *build* load, and the two should not be conflated when triaging. Re-read 2026-10-05; **not triggered** by this work, and the reason is worth keeping. Every verification run behind V-85/86/87 was against a warm `target/`, which is exactly the condition under which this entry says the signal is valid -- an isolated cold build while a build is still in flight is what invalidates it. `completion_latency_is_the_other_half_of_the_hot_path` and `recovery_scales_with_the_backlog_and_stays_bounded` both pass on the warm checkout, in the full-workspace run and as gate G9. |
| **V-75** | ****CLOSED, on live-run evidence: a real language model has produced and executed a governed action proposal inside OpenRayNux. This is a recorded operator run, NOT reproducible CI evidence**** | Groq `https://api.groq.com/openai/v1`, model `openai/gpt-oss-120b`, real credential resolved from the platform Secret Service, real TLS handshake. The model emitted `{"contents":"OpenRayNux real model verification","path":"final.txt"}` for capability `filesystem/write-text`; the deterministic parser and `ParamSchema` accepted it unchanged; proposal `p-v75-1791123558254` reached `waiting-for-user` with an empty workspace; unapproved execution was refused `approval-required`; a human approval recorded `approver=human, proposer=ai, authority_root=local`; the governed path re-ran policy, took a fresh lease, executed in the Tier-1 sandbox and returned `verified: true`; `final.txt` matched the requested bytes exactly (sha256 `47499ca1…`); the task reached `completed`; `spent_approvals` held one row | **milestone:** closed on a live run; **release:** re-run if the provider adapter, the proposal parser, or the approval path changes materially -- the recorded run is not re-executed by any gate| 2026-10-05 | **Closed on evidence, in three stages, and the failures were as informative as the success.** Stage one: the model chose the right capability and parameters but omitted `target`, and was refused `proposal-target-missing` three times with **zero** durable proposals, approvals or audit rows. The cause was ours — the menu announced `id`, `purpose` and `parameters` and never mentioned that a capability might *require* a target, so compliance was impossible. Fixed by deriving a `target:` line from `TargetSemantics` (V-80). Stage two: a successful run wrote `provenance.model = "openraynux/task-agent"` into the signed audit journal while the provider that answered was `openai/gpt-oss-120b` — the reply was always right and the *journal* was wrong, which is the worse direction for an audit. `delegated_actor` now takes the model identity as a parameter sourced from `provider.model_id()`, the provider instance that actually ran `complete()`; the direct `task/propose` path, where no model participates, records `none/direct-proposal` rather than a model name; and `prompt_hash` remains an explicit placeholder because this code does not version its prompt framing (V-81). Both fixes are regression-tested from the **durable row**, not the reply, and each was verified to fail when the provenance is reverted. What this does **not** claim: that the model reasoned well. The task was one sentence with one obvious answer, and a 120B model got it right after being told the field existed. It demonstrates the *contract* works end to end with a real model, not that OpenRayNux can do useful work. Re-read 2026-10-05 to fix a category error this entry invited. It is closed, and the closure is real: a real Groq `openai/gpt-oss-120b` produced a proposal, a human approval recorded `approver=human, proposer=ai`, the governed path executed it in the Tier-1 sandbox, and the file matched byte for byte. But nothing in CI performs that run, and no gate can, because it needs a live credential and a third-party endpoint. **What CI does cover is everything around the model call**, and that is now substantial: `tests/http_provider.rs` and `tests/https_provider.rs` drive the real adapter against a real `rustls` server (11 handshake tests), `tests/credential_hygiene.rs` runs a sentinel through every path that touches the credential, `proposer.rs` carries 29 `prior_step` tests, and `cli_e2e` drives propose-approve-execute end to end through the shipped binaries. The distinction to keep: **the model's contribution is live-run evidence; the path around it is CI evidence.** Neither substitutes for the other. |
| **V-76** | **A capability now refuses an unrecognised parameter instead of ignoring it, and the proposer enforces the declared shape before a proposal is durable** | `write_text::parse` and `text::text_param` reject a field they do not read (`crates/orxnud-capability/src/{write_text,text}.rs`); `ParamSchema::validate` is the same rule stated once in the domain layer and asserted to agree with both parsers (`crates/orxnud-capability/src/schema.rs`); `proposer::validate` applies it at propose time (`proposal-schema-mismatch`, `proposal-target-missing`). Found by the schema/capability agreement test the moment it was written | **milestone:** before a model is trusted to emit parameters for a capability whose parser it cannot see, and **release:** while any capability accepts unknown fields | 2026-10-04 | **Real behaviour change, not a refactor.** Previously a caller could send `{"text":"hello","data_class":"regulated"}` to `text/word-count` and receive `words: 1, verified: true` — safe, because the forged field was inert, but it reported success for a request the capability had not actually understood. Ignoring an unknown field is how "I asked for regulated handling and got default handling" happens without anything looking wrong. Two independent tests had encoded the permissive behaviour as correct (`cli_e2e::a_client_cannot_forge_authority_through_parameters` asserted a verified count for forged input). Refusal is now the stronger position and both layers hold it: the schema catches it at propose time, and the parser still catches it at execution for a proposal that reached execution another way. The refusal names the offending field, because an operator cannot otherwise tell a capability bug from a malformed request. Reported as `verified: false, undetermined: true` rather than a refuted outcome, which is correct: nothing ran, so nothing was disproved. |
| **V-77** | **CLOSED — the provider adapter speaks TLS, with certificate chain and hostname verification, and cannot be downgraded to plaintext** | `transport::TlsConfig::connect` (`crates/orxnud-daemon/src/transport.rs`) uses `tokio-rustls` against `rustls-native-certs`, so the host trust store is read at run time; `Scheme::carries_credentials` is true only for TLS, so an `Authorization` header cannot be attached to a plaintext connection even when plaintext is explicitly permitted; redirects are not followed, so a far side cannot deliver a downgrade either. `crates/orxnud-daemon/tests/https_provider.rs` drives a real `rustls` server on a loopback port with a certificate generated per test by `rcgen` | **release:** blocking — a credential must not cross an unencrypted connection | 2026-10-04 | **Closed with tests rather than with a claim.** Eleven tests run a genuine handshake: a trusted certificate succeeds, an untrusted issuer is refused, a certificate for the wrong address is refused by name, a plaintext server on an `https://` URL is a handshake failure, a handshake that never completes times out, a refused connection is `provider-unreachable` rather than a bad response, `https` never becomes plaintext, a plaintext endpoint is refused with a reason naming `https`, permitted plaintext still carries no credential, a redirect is not followed, and a TLS failure message never contains the credential. The tests pin a generated CA rather than trusting a public root, so an *untrusted* certificate is genuinely refused instead of merely absent from a list. Mutation-tested: making the TLS branch answer over plaintext fails three of them. Licences were checked before the dependency was added — `ISC` and `BSD-3-Clause` joined the `deny.toml` allowlist for `rustls-webpki`, `untrusted`, `ring` and `subtle`, and `webpki-roots` was rejected as MPL-2.0. |
| **V-78** | **CLOSED, after V-79 — `orxnuctl provider credential set` stores the provider API key through the platform secret store. The first closure of this entry was premature: the command could not store anything on any host, because the store it used never probed (V-79)** | `crates/orxnuctl/src/provider.rs` reads the value from stdin via `read_from_stdin` and writes it with `SecretsContract::set` against `SecretRef(provider-api-key, local)` — the same reference `http_provider` resolves; the argument parser refuses every spelling that would carry a value (`no_spelling_of_the_command_accepts_a_credential_as_an_argument`); `credential_state()` classifies nothing-stored, blank and store-unavailable as three distinct states rather than one | **release:** blocking — the feature was complete and unreachable | 2026-10-04 | **Closed, and the storage path is the whole point of the slice.** The value is read from stdin because an argument is visible in `ps` output and shell history; nothing echoes it back, not even a prefix, because a prefix is four characters of a credential in every terminal scrollback and CI log. An empty value is refused rather than stored: an empty credential that *exists* produces `Bearer ` and a failure that looks like a rejected key rather than a missing one. `crates/orxnud-daemon/tests/credential_hygiene.rs` runs one sentinel value through every path that touches it and asserts its exact bytes appear in none of them — provider refusals, `Debug` on the provider, `Debug` on the store, `status` output in all three states, and every file under a real daemon's state root after a full store-and-serve cycle. A store whose failure quotes the credential is redacted at the CLI boundary while an ordinary store error is still reported, because redaction must not swallow the diagnosis. Gate G2(b) was amended to permit `orxnud-domain` and `orxnud-platform-secrets` for the CLI, on the reasoning that this command must use the authoritative `SecretRef` rather than invent one that would write a credential the provider cannot read. **Two defects found by real-host verification and since fixed:** `KeyringSecrets` had a derived `Default` that skipped detection entirely, so `set`/`status`/`delete` reported "no secret store is available on this host" on a host whose Secret Service was working (V-79); and `probe()` required `delete_credential()` to succeed although its own comment said cleanup failure was ignored, so a store that could be written to but not cleaned up was reported absent. Detection now returns `Probe::{Available, Unavailable, AvailableWithStaleProbeEntry}` -- availability comes from the write alone, and a leftover probe entry is reported as its own outcome and surfaced at startup rather than being swallowed or mistaken for a missing store. Verified on the real host: `status` reported nothing stored, `set` reported `stored`, `status` reported `present`, `delete` reported `removed`, and passing `--api-key` was still refused. |
| **V-79** | **`KeyringSecrets` derived a `Default` that manufactured an unavailable store, so the credential path was inoperable on every host while the whole test suite passed** | `KeyringSecrets` had `#[derive(Default)]` over `available: bool`, so `default()` produced `available: false` without probing; all three production call sites used `default()` (`orxnud-daemon/src/main.rs` twice, `orxnuctl/src/main.rs`). Found only by running `orxnuctl provider credential status` on the real host during V-78 verification, after `secret-tool` had already proved the Secret Service was reachable | **release:** blocking — the feature was unusable everywhere, not merely on some hosts | 2026-10-04 | **The hermetic suite could not have caught this, which is the finding.** Every test in the tree constructs a store with `assume_available()`, which skips detection, so detection had **no test at all**; a suite that never exercises the code under repair cannot report it broken. The real-host check was the only thing that found it: `KeyringSecrets::new()` probed and reported the store present, while `default()` reported `NoStore` on the same machine, same keyring, same second. Fixed by removing the `Default` entirely rather than redefining it, because every possible meaning of it is a footgun -- "probe" makes a side-effecting constructor out of `default` and would drag the real keyring into tests, and "assume unavailable" is the bug itself. `new()` and `assume_available()` now have to be chosen by name, and `clippy::new_without_default` is refused on purpose with that reasoning recorded. The related cleanup defect -- `probe()` requiring `delete_credential()` to succeed while its own comment said cleanup was ignored, which reported a working store as absent -- is fixed alongside it and recorded under V-78. |
| **V-80** | **The AI capability menu never announced a capability's target requirement, so a real model was asked for a field it had never been told about** | `user_message` emitted `id`, `purpose` and `parameters` per capability and nothing about `TargetSemantics`, while the validator enforced it (`crates/orxnud-daemon/src/http_provider.rs`). Found by the first live run: `openai/gpt-oss-120b` omitted `target` on three consecutive attempts and was refused each time | **milestone:** closed with the menu fix | 2026-10-04 | **An information gap, not model misbehaviour, and not a reason to loosen the parser.** `AllowedCapability` has always carried `target: TargetSemantics`; the *validator* read it and the *menu* did not. Asking for a field we never described, then refusing the model for omitting it, is a defect on our side dressed up as a correct refusal. The fix adds a `target:` line derived from the declaration so a capability cannot be announced as needing a target when it does not, asserted for all three variants plus one-line-per-entry attribution. Nothing in the parser, `ParamSchema`, approval flow or capability semantics changed. |
| **V-81** | **Audit provenance named a hardcoded model that never answered** | `delegated_actor` passed the literal `"openraynux/task-agent"` into `ModelProvenance`, so every AI actor in the signed journal claimed that model regardless of which provider replied | **release:** blocking for any claim of truthful audit | 2026-10-04 | **The reply was always right; the journal was wrong.** The API response said `model: openai/gpt-oss-120b` on the very first successful run while `task_proposals.proposer` and both `audit_log` records said `openraynux/task-agent`. An audit that misattributes the model is worse than no audit, because it looks like evidence. The model identity is now a parameter to `delegated_actor`, supplied by the provider instance that actually executed `complete()` via `model_id()` — read from the answering object rather than from configuration, so it cannot name a model that did not answer. The direct `task/propose` path, where no model participates at all, records `none/direct-proposal` rather than borrowing a model name. `revision` and `prompt_hash` are unchanged: `prompt_hash` remains the literal `"phase-2"`, which describes a prompt-framing version this code does not version — recorded as a known placeholder rather than quietly left to look meaningful. Two tests read the **durable** row rather than the reply, and both were confirmed to fail when the provenance is reverted to the hardcoded value. |
| **V-82** | **An expired approval authorises nothing and never dead-ends a proposal: it is refused before any write, refused again before the execution lease is taken, and a proposal whose approval lapsed unconsumed can be approved again with a fresh digest** | `TaskRepository::record_approval_replacing_expired` (Recorded / ReplacedExpired / Refused, one IMMEDIATE transaction, conditional `UPDATE` re-asserting both preconditions); `capability/approve` checks `is_valid_at(now)` before writing and re-checks the stored row; `task/execute` checks `is_valid_at(now)` before `begin_approved_execution`, using the same `now` the policy stage then receives. Evidence: `tests/expiry.rs` (12), `task_repo.rs::replace_expired` (7), and the rewritten `an_expired_approval_is_refused_and_writes_nothing` | **closed, implemented** — ADR-0049. Superseded the previous `tracked, not fixed`. The **scoped session grant** half of Q-OPEN-14 is explicitly *not* closed by this. | **release:** any change to `ApprovalRecord::is_valid_at`, `record_approval_replacing_expired`, the `capability/approve` guards, or the `task/execute` ordering | 2026-10-06 | **CLOSED, after being reproduced against the real store before any edit. What was proven,
and how.** Reproduced first: `approve(ttl_ms: 0)` returned success with `expires_at ==
issued_at` and set the proposal to `approved`; a second approve was refused with
`proposal-already-decided`; `task/execute` was refused with `approval-expired`; the task was left
`running` under a fresh 30-second lease; and cancellation was the only recovery. **Two further
facts the original entry did not record, both found while reproducing it:** an approval that
expired *while the task waited* -- the ordinary case, since a human wait is unbounded and a TTL
is not -- produced the same dead end and was the **more** common route; and `task/execute` took
the lease *before* the policy stage refused, so every expired attempt parked the task as well as
dead-ending it. Both are fixed. **The security half was never wrong**, and its existing test is
kept and strengthened: an expired approval writes nothing. **What the fix changes:** an approval
already expired on arrival is refused before any write, so an operator's mistyped TTL cannot
produce this at all; an expired unconsumed approval is replaced by a **fresh digest** rather
than extended, so no surviving authority is left to present; a live or consumed approval may not
be replaced, which is what keeps single-use intact; and the expiry refusal now happens before the
execution lease is taken. **Boundary, pinned:** `is_valid_at` is `now < expires_at`, so an
approval is expired *at* its expiry instant, and the store's replacement check uses the same
operator. **Mutation-checked**, with two exceptions recorded in ADR-0049 rather than omitted: two
redundant preconditions could be deleted without a test failing, because an earlier guard inside
the same transaction decides those cases; the authoritative guard for each was separately
confirmed to be caught. **Concurrency:** two callers replacing one expired approval produce one
replacement and one refusal, deterministically. **Restart:** a crash after expiry neither
resurrects the expired approval nor blocks recovery, both tested through the real store.
**Step and task isolation:** a replacement binds the proposal's durable `step_no`, and an expired
approval can neither cross a step boundary nor retain a read observation — both tested. **The fourth thing it recorded is now fixed by ADR-0050 / V-89:** the `INTERNAL_ERROR` an
ordinary state refusal returned was cross-cutting rather than expiry-specific, so it was left out
of this defect's scope and closed separately; `TaskFault::Engine` no longer exists as a
classified `INTERNAL_ERROR` sink. |

| **V-83** | **One approval authorised the same action at every step of a multi-step task** | Under digest `v2` the canonical tuple was (approver label, approver root, proposer label, proposer root, capability, target, canonical params, issued, expiry) with no logical step, so a task whose step 2 repeated step 1's exact action found step 1's approval still matching. `authorise` recomputed the digest with no step, and the single-use `consumed_approvals` ledger is keyed by that digest, so one consent silently covered N identical steps. | **fixed** | 2026-10-04 | The digest prefix is now `v3` and `step_no` is the final canonical field; `ApprovalRecord` carries `step_no`, and `authorise` verifies against the step recorded on the approval rather than a caller-supplied one. Tests written first: `the_v3_tuple_is_the_v2_tuple_with_a_version_and_a_trailing_step`, `two_identical_actions_at_different_steps_have_different_digests`, `every_pre_existing_field_still_changes_the_digest`, `v3_and_v2_differ_for_the_same_action`, `a_v2_digest_does_not_verify_under_v3`, `the_step_on_the_record_is_the_step_that_is_verified`. Mutation-checked: dropping `step_no` from the tuple, reverting the prefix to `v2`, and hardcoding the recomputed step to `1` each fail at least one test. Historical `v2` approvals fail closed and remain structurally verifiable in the audit chain; no compatibility shim was added. The durable proposal is the only authority on the step — no CLI field supplies it, and it is never inferred from `attempt_no`. Composing the counter itself is later Stage 3 work and is not done here. |

| **V-84** | ****A task at a step boundary is advanced only by an explicit `claim_next_step()`, and only `task/continue` calls it: the generic claim still never advances a boundary**** | `claim()` and `take_lease()` select `WHERE state = 'pending'`, and `idx_tasks_claimable` is `WHERE state = 'pending'`. A task in `AwaitingNextStep` is therefore invisible to a polling worker and is advanced only by the targeted `claim_next_step()` added in Stage 3d. This is a deliberate separation, not an oversight: continuation is a distinct operation from first dispatch. **Satisfied 2026-10-06 (ADR-0047):** `task/continue` is the production caller, and `the_generic_claim_does_not_take_a_step_boundary` still pins that the generic claim path stays `Pending`-only and the index was not widened. | **met** | 2026-10-06 | **Orchestration requirement, recorded so it is not rediscovered as a bug:** a production execution loop **must explicitly resume `AwaitingNextStep` via `claim_next_step()` and must never depend on `claim()` polling to discover a boundary.** The intended shape is `execute step -> verified -> AwaitingNextStep -> continuation notices boundary -> claim_next_step() -> propose next step`, and after human approval `approval -> claim_next_step() -> fresh lease -> Running -> execution`. Widening the generic claim was considered and declined: it would assert that *any* polling worker seeing a boundary is entitled to advance it, which is a new scheduling contract broader than the composition work designed so far, and it would additionally require deciding `Pending`/`AwaitingNextStep` coexistence and ordering semantics, changing `idx_tasks_claimable`, and confirming every existing worker implementation understands the new state. The claim index was not widened. (Migration **10** was later added for an unrelated key defect: `task_approvals` was keyed `(task_id, attempt_no)` while `attempt_no` restarts per step, so a second step's approval collided with the first's and was silently discarded by an `INSERT OR IGNORE`. That key is now `(task_id, step_no, attempt_no)`, matching `task_attempts`.) The behaviour is pinned by `the_generic_claim_does_not_take_a_step_boundary`, so a future change to the claim query has to notice and revisit this decision deliberately. Until a continuation loop exists above the repository primitive, multi-step tasks stop at the boundary by design. Re-read 2026-10-05 and the second half of the claim is now stated, because it is the half a reader is most likely to assume the other way. `TaskRepository::claim_next_step()` exists and is tested (`task_repo::advancement_tests` plus `the_generic_claim_does_not_take_a_step_boundary`, which pins that the generic claim path stays `Pending`-only and `idx_tasks_claimable` was not widened). **There was no production caller** when this entry was first written: `grep -rn claim_next_step crates --include=*.rs | grep -v task_repo.rs` returned nothing and `orxnud-daemon` exposed no IPC method that reached it, so the delivered state was a *governed primitive* -- a state, a targeted claim, step-scoped approvals and attempts, a step-bound digest -- with the orchestration deliberately unwritten. ADR-0043 recorded that as a requirement rather than a bug, and this entry was where a reader was to confirm it was still unmet. **Now met:** `orxnud-task`'s engine and `orxnud-daemon`'s `TaskService` each expose exactly one pass-through to it, `task/continue` calls it once per boundary and never widens the generic claim, and `crates/orxnud-daemon/tests/continuation.rs` asserts the exactly-once behaviour under two concurrent continuations. Reaching the boundary also required making `max_steps` settable at `task/create`; without it the schema default of 1 meant no task could ever reach one, so this gap was not only unwired but unreachable. |
| **V-85** | **A GitHub-hosted Linux runner ships `bwrap` and cannot use it, so `host_backend_name()` reports a backend on a host that can isolate nothing** | `host_backend_name()` is compile-time; `BwrapRunner::probe()` is runtime. Measured: with `bwrap` present, `AvailableGuarantees { visibility: false, tree_lifetime: false }`, so `check()` refuses and `can_fulfil` is false — which is the `the execution backend cannot establish the required sandbox guarantees` refusal two `orxnuctl::cli_e2e` tests were failing on. Root cause is `kernel.apparmor_restrict_unprivileged_userns` on Ubuntu 24.04+ with no per-binary AppArmor grant for `bwrap`. The full fingerprint is printed by `scripts/preflight.sh` on every `linux-gates` run | **milestone:** every `linux-gates` run — the step is placed *before* the gates so the reason is in the log on exactly the runs that need explaining | 2026-10-05 | **High, and it was invisible.** Nothing in the tree said the runner could not sandbox: the backend name said `bwrap`, `bwrap --version` succeeded, and the only symptom was a red test whose message named a guarantee without naming the host. Three consequences followed. (1) A host-level `bwrap --version` check would have reported success on a host that can isolate nothing — so presence is not capability, and the probe has to *run* the namespace. (2) CI fail-fasts, so the two visible failures were hiding six more: `--no-fail-fast` on a simulated incapable host found 8 `cli_e2e` tests in total, 14 in `governed_path`, and 25 in the sandbox crate. Any future "only two tests fail" reading of this register should be checked against that. (3) The test's gate was `#[cfg_attr(not(target_os = "linux"), ignore)]`, which asks a platform question rather than a capability one and skips rather than tests, leaving the interesting state untested everywhere. ADR-0046 fixes the surfacing and the assertions; it does not change the contract. |
| **V-86** | **`--privileged` and `--cap-add=SYS_ADMIN` make the Tier-1 probe pass without creating a user namespace, so a container green run is not evidence for the production configuration** | `BwrapRunner::probe_identity()`, which runs the *same* argv as `namespace_probe` and reads `/proc/self/uid_map` and `CapEff` from inside the result. Measured: production host and the chosen container both give `uid_map 1000 0 1`, `CapEff 0000000000000000` — a single-entry nested map with no capabilities. `--cap-add=SYS_ADMIN` gives `uid_map 0 0 4294967295`, `CapEff 00000000a82425fb` — the full identity map, i.e. no nested user namespace at all | **release:** any change to `scripts/run-sandbox-tests.sh`'s container flags, and on any `sandbox-integration` run, which calls `preflight --require` first and exits non-zero unless the nested shape is observed | 2026-10-05 | **Critical, and the reason the obvious fix was rejected.** Inside a `CAP_SYS_ADMIN` container `bwrap` runs with the caller's pre-existing privilege over the container's own mount namespace, so it never exercises the unprivileged-userns path every real user depends on — a leak contained there may not be contained in production, and a capability that fails to nest there is never tested. A passing Tier-1 suite in that container would be evidence about a configuration OpenRayNux will never ship, which is worse than no evidence because it looks like evidence. The container actually used grants **nothing**: `--security-opt seccomp=unconfined` (Docker's default seccomp returns EPERM for `unshare(CLONE_NEWUSER)`, measured — with seccomp on even `unshare -U` fails) and `--security-opt systempaths=unconfined` (Docker bind-mounts over `/proc/kcore` and `/proc/sys`, so procfs is not "fully visible" and the kernel refuses a nested procfs mount, measured as `bwrap: Can't mount proc on /proc`). The tests then run under `setpriv` as uid 1000 with `--inh-caps=-all --bounding-set=-all`, which forces `bwrap` to nest. The generalisable rule: **a sandbox test is evidence only if it ran in the same privilege configuration as production, and the way to know that is to read the identity from inside the sandbox, not to infer it from how the sandbox was launched.** |

| **V-87** | **A container cannot escape `apparmor_restrict_unprivileged_userns` on a GitHub-hosted runner, so no positive Tier-1 evidence is obtainable in GitHub-hosted CI** | `scripts/run-sandbox-tests.sh`, measured on `ubuntu-latest` inside the container it configures (`seccomp=unconfined`, `systempaths=unconfined`, uid 1000, every capability dropped). Reported on every run of CI job `sandbox-integration`, before any suite: `uid/gid 1000/1000`, `CapEff 0000000000000000`, `guarantees: visibility=false tree_lifetime=false resources=false`, `tier1_executable: no`, `== sandbox identity unavailable ==`. `--security-opt apparmor=unconfined` was tried and does not help: the restriction is a sysctl, not a profile on `bwrap` | **release:** any change to the container flags or to `ubuntu-latest`; re-measure before believing any claim that CI proves the sandbox | 2026-10-05 | **High, and it corrects a conclusion this project would otherwise have drawn wrongly.** The same container **does** reproduce production on a host with no AppArmor loaded -- measured, `uid_map 1000 0 1` and `CapEff 0` inside the sandbox, against the full identity map `0 0 4294967295` a `--cap-add=SYS_ADMIN` container gives. So a local pass was available and would have been a **false assurance**: the difference between the two hosts is the one thing that matters, and only the runner shows it. Recorded consequence: *a sandbox measurement taken on a host whose confinement policy differs from production is not evidence about production*, which is the same shape as V-46's "delegation is per-host" and the reason the preflight prints the identity rather than a boolean. **Deliberately not fixed by weakening the host.** Turning this green needs either `kernel.apparmor_restrict_unprivileged_userns=0` or a per-binary AppArmor profile for `bwrap` loaded on the runner, and both are a host security-policy change made so a test can pass -- the trade `scripts/run-resource-tests.sh` already declines about a desktop session's cgroup delegation. So the lane reports the gap in capitals, produces no positive evidence, and exits successfully; **a green `sandbox-integration` means "the environment was measured", not "the sandbox was proven."** Positive Tier-1 evidence comes from a host that can create an unprivileged user namespace (`run-sandbox-tests.sh --host`), and cgroup enforcement from `run-resource-tests.sh`, which needs delegation and therefore a different container. |

| **V-88** | ****Only the verified output of an approved `filesystem/read-text`, released once, across one step boundary, to the `(endpoint, model)` identity that asked for it, can leave this machine for a provider**** | `Observation::step_no` and `ObservationStore::take_for` (eligibility is `step_no + 1 == requesting step_no`, plus task and `ProviderIdentity::matches`); `ProposalProvider::destination` defaults to `None`; `retain_read_observation` requires `output_is_ephemeral && is_verified()` and an `Actor::Ai` naming the configured model; `DisclosureBatch` has a private field; `release_observations` appends a `DisclosureRecord` before the request and refuses on append failure. Evidence: `crates/orxnud-daemon/tests/disclosure.rs` (10), `runtime.rs::read_retention_gate` (9), `observation.rs` store tests (5), `http_provider::disclosure_rendering_tests` (2), `proposer::tests` destination (1). **Mutation-checked** — breaking the task check, the step check, the identity check, single-use consumption, the size limit, the verification requirement, or the audit append each fails the suite. | **release:** any change to `ObservationStore::take_for`, `ProviderIdentity::matches`, `ProposalProvider::destination`, `retain_read_observation`, `release_observations`, or `render_disclosures`; any capability that declares ephemeral output | 2026-10-06 | **High, because this is the first data-release boundary in the build, and it is the claim ADR-0045 was written to make enforceable.** Scope is deliberately one capability's output, one proposal, one destination. What is **not** claimed: no memory subsystem, no retrieval across proposals, no semantic search, no unrestricted export — an observation informs one explicitly authorised proposal and is then gone. Single-use is enforced by **erasure** rather than by a durable consumed flag, because the store is process memory (ADR-0045 D4); a crash therefore loses content rather than restoring it. Enabling `filesystem/read-text` in `SHIPPED_POLICY` is part of this claim and was a **defect fix**: the capability menu already advertised it and policy refused it as `unknown-capability`, so the whole subsystem was unreachable for a reason unrelated to leaving it unwired. **Evidence boundary:** every test in `disclosure.rs` needs a verified sandboxed read, so it is excluded from the hosted G9 scope and runs in the ADR-0046 container, which per V-87 cannot itself obtain positive Tier-1 evidence on a GitHub runner. The gate-level controls that do not need a sandbox (renderer delimiters, the `destination` default, store eligibility, the retention gates) run everywhere. |
| **V-98** | **CLOSED — every CI lane installed an unauthenticated, mutable, root-owned executable on every push** | `scripts/run-sandbox-tests.sh:125` ran `curl -LsSf https://get.nexte.st/latest/linux \| tar zxf - -C /usr/local/cargo/bin` inside the container bootstrap, as root, before any build step: a mutable tag, no integrity check, and network content piped into a root-owned system path | **release:** any change to `scripts/install-nextest-verified.sh`, the pins in `scripts/run-sandbox-tests.sh` / `scripts/run-resource-tests.sh`, or the CI toolchain install path — re-read 2026-10-10 | 2026-10-10 | **Closed on verification, and the three defects were independent.** **(1) Mutable:** `/latest/linux` resolved to whatever upstream last published, so the lane's behaviour changed with no diff here. Replaced by an exact release, **cargo-nextest 0.9.146**, `x86_64-unknown-linux-gnu` — the version `.github/workflows/ci.yml` already pins and documents, so the project keeps *one* cargo-nextest and a container pass cannot disagree with a gate pass. **(2) Unauthenticated:** the pin is `sha256` **`682c21b777c333e96fd532e114d3a5a894e0729ab88d94c0a9f20f8419695428`**, read from the `.sha256` asset published *with* release `cargo-nextest-0.9.146`, and then **confirmed against the artifact itself** — downloaded from the release and hashed locally — so the two agreeing is evidence, not an assumption. It is a **literal**: `test-ci-toolchain-pinning.sh` fails if it becomes `${...}`, because an overrideable checksum is a suggestion. A `ORXNUD_NEXTEST_BASE_URL` mirror override **is** allowed and is safe precisely because the pin still governs — the mirror may change where bytes come from, never what they must be. **(3) Root, into a system path, from a pipe:** the download now lands in a file, is verified **before** extraction, and is installed and executed as **uid 1000** into `/home/orxnud/.local/bin`, owned by that uid — demonstrated in the real container (`orxnud 755 /home/orxnud/.local/bin/cargo-nextest`, run under `setpriv --reuid=1000 --bounding-set=-all`). **Images pinned by registry digest**, not tag: `rust:1-bookworm@sha256:114c7a4425406451c2866b6aafe69fe29b1b298832db1277d411ac73c82d04d6` (OCI **index**, so it stays immutable *and* resolves on arm64 developer hosts), read from the Docker Hub registry API and re-fetched **by digest** to confirm it resolves; the `linux/amd64` manifest it resolves to is `sha256:b36c246742b4d323472588f789601be34eb4af053255e2af53969078ee8dcec7`. **This is a registry manifest digest, not a local `docker images` ID**, which is the confusion the slice names. **Negative-tested, twice.** `scripts/test-ci-toolchain-pinning.sh` drives the **real** installer with a locally-built artifact that does not match the pin and requires nonzero exit **and** no installed binary **and** no execution; mutating the production checksum comparison to `if false` makes it report `rc=0` and *installs the bad artifact*. A second mutation -- reverting the release-asset URL to the form that 404s -- was also caught, and that one existed because the **positive** run found it: an earlier check ("does the URL mention the version?") passed against a 404, so the check now reads the URL the installer **actually requested**. Enforced as **gate G14**. **In the real pinned container**, a refusing install left no binary and the following build step never ran (container exit 1, build marker never printed), which is the ordering the criterion asks for. **Not claimed:** this closes the *supply-chain* defect only. It produces **no** Tier-1 isolation evidence, and `sandbox-integration` still reports that the environment was measured rather than that the sandbox was proven. The unauthenticated path is not merely relabelled — it no longer exists. |

Recorded per operating rule 5: wrongness is worth recording, because it is how
this register improves.

---

## 2a. Amendments

### A-002 — the catch-up window's upper bound

**What ADR-0021 says:** the catch-up window is `(last_fired_at, now]` — closed at
the top, so an occurrence due exactly *now* fires.

**What the Phase 1 harness does:** `conformance::schedule::occurrences` takes a
window that is **open at both ends**, and pins that in `the_window_is_half_open`.

**Both are correct.** They are windows with different conventions, and the
conflict only appeared when Phase 2 built a scheduler on top: with the harness's
convention, a schedule created an hour before the pass produced **zero** fires,
because the occurrence at exactly `now` was excluded.

**Resolution:** the harness is the specification and was **not** modified. The
scheduler translates, passing `now_ms + 1` as the upper bound, which makes the
enumeration exactly `(last_fired, now]` at millisecond resolution. Two Phase 1
assertions pin the open-ended behaviour, which is the signature of a deliberate
convention rather than an oversight. Recorded here because a future change to
`occurrences` would silently break every catch-up path.

**Evidence:** `scheduler.rs::process_one` and its module documentation; the
regression test `a_due_occurrence_creates_exactly_one_task` fails without the
translation.

### A-003 — TP-7's child-process entry point is a per-binary requirement

**What the harness does:** `power_loss::spawn_victim` re-executes `current_exe()`
with `--exact victim_entry_point --ignored`.

**The problem:** Phase 2 added a *second* test binary that runs the suite, and it
had no such entry point. TP-7 reported *"victim 0 never signalled readiness"* — a
30-second timeout, not an error.

**Resolution:** each test binary that runs the suite exposes a three-line shim
calling `conformance::power_loss::victim_entry_point`. The victim itself still
lives once, in the library. The harness, its properties, and its assertions were
not touched. A test in `conformance_production.rs` asserts the Phase 1 fixture file
still defines its own, because the only symptom of a rename would be a timeout.

**Why this is an amendment and not a weakening:** the duplicated code is a shim,
not a property. No assertion changed; a second engine now passes the same suite.

### A-004 — `complete(Failed)` must requeue, or TP-11 passes vacuously

**The bug, found by writing the fixture before the tests:** marking a `Failed` task
terminal made *"within the retry budget"* mean *"no retry"*. A task that failed
once transiently was permanently dead, and TP-11 would have been satisfied by an
engine that never retried at all — the loop would break on `Claim::Empty` and find
the task in `Failed`, which TP-11 accepts.

**Resolution:** a `Failed` task whose budget remains returns to `pending` with a
`run_after_ms` set from an explicit `retry_delay_ms`, and only becomes
`dead_lettered` at the budget. TP-11 now exercises three real attempts and
dead-letters, which is the property ADR-0029 actually describes.

**Consequence for the scheduler/clock:** the retry delay is a *parameter*, not a
constant baked into the repository, because a fixed backoff would leave TP-11's
retry unclaimable without moving a clock the harness does not own. The conformance
path passes `Some(0)`; production passes `None`, which uses
`EngineLimits::retry_backoff_ms`.

### A-005 — an unexplained intermittent G9 failure, recorded because it is unexplained

**Observed:** 2026-10-10, during the S-17 design pass. A single `scripts/ci-gates.sh` run
reported `1 failed: G9` (the test gate). The test binaries were **unchanged** by that pass —
it touched `docs/09-decisions.md`, `docs/12` and `docs/18` only — so the failure is not
attributable to any edit in it.

**What is known.** Re-running `scripts/ci-gates.sh G9` in isolation gave
`1664 tests run: 1664 passed, 0 failed, 6 skipped`, and three further consecutive full gate
runs reported `all selected gates passed`. The failure was **not captured**: its test name,
failure message and exit status were not recorded at the time, because the output was
filtered to the summary line. **It therefore cannot be diagnosed from what was kept.**

**Why it is recorded rather than dismissed.** Three green runs afterwards are evidence that it
did not recur *in those three runs*. They are not evidence that it was harmless, and the
difference matters: an intermittent red gate is a gate whose colour does not mean what it
appears to mean. The honest position is that one unexplained failure exists in the record, its
cause is unknown, and no attempt was made to attribute it to V-68's known load-sensitive
flakiness — V-68 records a *different, named* test and understanding it, whereas this failure
has no identity at all. Claiming it is "probably V-68" would be a guess recorded as a finding,
which this register does not do.

**The lesson, which is the actionable part.** The failure was filtered out of the log by a
`grep` that kept only the summary. That is the whole mechanism by which a real signal was
discarded: the run was being read for its verdict, not for its evidence. **Next time, capture
`FAIL` lines before filtering.** Any future occurrence should record the test name, the
assertion, and whether it reproduces in isolation.

**Milestone:** before a future intermittent is treated as a known-bad gate, or before this is
closed as unreproducible, produce a reproduction. **Status: OPEN, undiagnosed.**

### A-001 — `orxnud-domain`'s dependency list

**What the contract said:** `serde` and `thiserror` only.

**What the implementation needs:** `serde_json` and `zeroize` as well.

**Why the deviation is correct rather than a shortcut:**

- `serde_json` because `ActionRequest.params`, `CapabilityInvocation.params`, and
  `Proposal`'s field values are `serde_json::Value`. They were `Value` from the
  first line of the implementation. Using a second untyped value type — `toml::Value`,
  a hand-rolled enum — would have meant a lossy conversion at every boundary, and
  `serde_json::Value` is the vocabulary `orxnud-protocol` already speaks.
- `zeroize` because `SecretLookup::Found` must wipe a secret on drop. Without it a
  secret sits in a heap allocation until the allocator happens to reuse it, which
  on a long-running daemon is a long time.

**Both are still pure, portable, and dependency-light.** Neither can perform I/O,
spawn a runtime, or reach the OS, so the property the restriction exists to protect
— that `orxnud-domain` is a pure core — is intact. Gate G2 asserts it mechanically
by rejecting any of `tokio`, `rusqlite`, `keyring`, `clap`, `reqwest`, `walkdir`,
`notify`, `directories`, `uuid`, `croner`, `jiff`, or `blake3`.

**Status:** the contract text in docs-13 §3.1 should be amended to name these two.
Recorded here first so the discrepancy is not silent.

---

### A-008 — S-31: cross-process database ownership for the whole restore lifecycle

**F-26c REMAINS OPEN.** The cross-process evidence below is sound for the paths it tests, but
a follow-up review found a **real ownership bypass that is not fixed**: a database reachable
through more than one hard link gets a lock file per name, so a competitor opening the alias
participates in nothing. Until that is rejected, or the safety contract is explicitly narrowed
and enforced, cross-process ownership is **not fully proven** and the finding stays open.

**F-26 and F-26b also remain open.** All three are open; none is closed by this work.

**The race S-31 closes.** S-30's guard takes exclusive authority **instantaneously and in
one process**. Between its checkpoint and its copy, a second daemon could open and write the
database; a second process is not in this process's connection set, so its presence never
made our checkpoint report busy. The online backup API's destination lock covers the backup
operation, not the surrounding lifecycle.

**Mechanism, and why it fits.** A stable per-database lock file, `<db>.lock`, held with the
standard library's advisory file locking (`File::try_lock` for exclusive,
`try_lock_shared` for shared). **No new dependency**, and no MSRV change: the API stabilised
in Rust 1.89 and the workspace declares `rust-version = "1.98.1"`. SQLite's own locking is
deliberately *not* used for this — a transaction lock says "I am writing now", not "I am
restoring and nobody may open this for the next fifty milliseconds".

**Ownership semantics.** Ordinary opens take a **shared** lease held for the connection's
lifetime (a field on `Store`, `SqliteAuditJournal`, `SqliteApprovalLedger`, so it survives
`open()` returning). A restore takes an **exclusive** lease before the checkpoint and holds
it through the copy, the logical verification, and the outcome. Contention **fails fast** with
a typed `OwnershipError::Conflicted`; nothing waits.

**How migration recovery releases its own connection.** This required restructuring, and it
is the substantive change. `MigrationRunner` borrows a `&Connection` whose owning `Store`
holds a shared lease — and `flock` conflicts between open file descriptions **even within
one process**, so a restore from inside `migrate()` would deadlock against our own lease.
`migrate` therefore no longer restores: it returns `MigrationError::RecoveryRequired
{ source, snapshot }`, and `TaskService::open` drops the store (closing the connection and
releasing the lease) before calling `Backup::restore_coordinated`. `Store::into_parts`
returns the connection **and** its lease so the lease follows the connection when the store
is consumed by the engine.

**Lock identity.** `lock_path_for` canonicalises, resolves symlinks where the target exists,
and for a not-yet-created database canonicalises the *parent* and joins the file name — so
identity is absolute and stable rather than derived from the caller's string. The lock file
is created with `create(true)` and never unlinked or replaced, so two processes racing to
create it end on the same inode rather than on two lock files.

**Evidence.**

| Requirement | Result | Test |
|---|---|---|
| A — competing process excluded | **pass** | `a_competing_process_is_excluded_during_the_restore_lifecycle` |
| B — controlled checkpoint-to-restore interleaving | **pass** | `b_a_competitor_cannot_act_inside_the_checkpoint_to_restore_window` |
| C — every entry point participates | **pass** | `c_every_entry_point_participates_in_the_ownership_rule`, `c_task_service_open_refuses_through_its_own_opener` |
| D — no coordination bypass | **pass** | `d_restore_refuses_without_exclusive_ownership_and_recovers_when_free`, plus S-30's `restoring_from_outside_the_crate_does_not_compile` |
| Lock identity, shared/exclusive, path aliases, unusable lock path | **pass** | `ownership::tests::*` (4 tests) |

Both two-process tests use a **real restore paused inside the window** as the exclusive
holder, not a synthetic lock holder, so they exercise the same exclusive window production
uses.

**Mutation-checked.** Removing the lock from `acquire_exclusive` **and** from
`acquire_shared` each made both two-process tests **fail**; restoring the code made them
pass. Without this they could have been passing for an unrelated reason.

```
cargo test -p orxnud-store            307 + 7 + 3 + 3 + 1 + 3 + 3 passed, 0 failed, 2 ignored
cargo test -p orxnud-task             20 suites, 0 failed
cargo test --workspace                1734 passed, 0 failed, 7 ignored
cargo fmt --all --check               clean
cargo clippy --workspace --all-targets -- -D warnings   clean, exit 0
CI=deny ./scripts/ci-gates.sh         all selected gates passed (G12 skipped, no tag)
```

**Entry-point coverage is structural, not incidental.** `Store::open`, `open_and_migrate`,
`SqliteAuditJournal::open` and `SqliteApprovalLedger::open` are each asserted to refuse while
exclusive ownership is held, and each asserted to *work* once released — so the refusals are
about ownership rather than a broken database. `TaskService::open` is covered through the
opener it uses. No other file-backed open path exists in production: a sweep of every
`Connection::open`, `Store::open`, `open_and_migrate` and `open_in_memory` outside
`#[cfg(test)]` found the sites instrumented here plus the internal connections inside
`Backup` itself.

**Failures that cannot succeed.** An unusable lock path returns `OwnershipError::Unavailable`,
tested. Two exclusive requests conflict, tested. A restore attempted while another owner holds
the database returns a typed ownership refusal and leaves the data untouched, tested twice
(in-process and cross-process).

**Test-side seams, disclosed.** `Backup::restore_coordinated` is the public restore and
acquires ownership itself. `ownership::acquire_exclusive_for_tests` is `pub` so integration
tests can stand where a restore stands; it grants no capability a restore does not already
require. One environment-variable seam in `RestoreGuard::acquire` pauses the restore between
checkpoint and copy so Test B's interleaving is **deterministic** rather than a timing race;
it is outside any public API and has its own unit test.

**A-008 follow-up — review found three boundaries. Two were real defects and are fixed; one is
an open blocker and is NOT fixed.**

1. **Hard-linked aliases bypass ownership. REAL, and NOT FIXED.** Measured:
   `state.db` and `alias.db` are one inode (20445) but `lock_path_for` produces
   `state.db.lock` and `alias.db.lock` — **two locks for one database**, so a competitor
   opening the alias participates in nothing. Keying locks by inode does not fix it:
   `link(2)` permits a hard link in a different directory on the same filesystem, so an
   inode-keyed name would still need a parent directory and the two parents can differ. The
   correct fix is to **refuse** a database with more than one name, which needs the link count —
   and that is unreachable from `orxnud-store`: gate **G3** forbids a platform `cfg` outside
   `orxnud-platform-*`, and gate **G2**'s layering forbids `orxnud-store` from depending on a
   platform crate (it may depend only on `orxnud-domain`).
   `orxnud_platform_fs::hard_link_count` now exists, correctly placed and G3-compliant, but is
   **unreachable from the crate that takes the lease**. Resolving it needs a design decision —
   an ownership API moved to a platform crate, or a link count carried across the boundary.
   **Until then ownership is not alias-safe**, and this row does not claim otherwise.

2. **The production restore seam was reachable. REAL, and FIXED.** The first seam triggered on
   `ORXNUD_S31_RESTORE_WINDOW` alone and was gated on `#[cfg(not(test))]`, which means it was
   compiled **into** a production binary: any ambient variable could pause a real restore for
   sixty seconds. A second attempt gated it on an inherited descriptor; it was better but needed
   `pre_exec`, which is `unsafe` and so barred by gate **G4**, and its negative test read the
   ambient `/dev/fd/9` so it passed alone and failed in the full suite. **All of it is gone.**
   `grep` over the library source finds no seam. Test B now works by taking the exclusive lease
   through `acquire_exclusive_for_tests` and restoring under it via
   `Backup::restore_with_lease_for_tests`, which demands an exclusive lease — exactly what the
   restore already demands — so it grants no capability production does not have.

3. **Two ordinary daemons must both be able to run. CONFIRMED, not a defect.** The review asked
   whether the implementation had over-corrected into refusing concurrent opens. It has not:
   `ordinary_opens_share_rather_than_excluding_each_other` (in-process) and
   `c_two_processes_may_both_hold_the_database_open_normally` (two real processes) both assert
   that shared ownership **coexists**. The intended protocol holds exactly as specified:

   | Situation | Result |
   |---|---|
   | Two daemons open normally (shared) | **Both may open** — proven cross-process |
   | A restore holds exclusive | A competing open is **refused** — proven cross-process |
   | A restore starts while shared owners remain | The restore is **refused** — proven in-process |
   | Two processes attempt competing restores | **At most one** acquires exclusive — implied by the above and by the single-flight lock |

   The availability change is therefore **narrower than earlier reported**: only a *restore*
   excludes, never an ordinary open. A second daemon starts normally.

**Addendum — the three open decisions on the hard-link fix were approved (ADR-0058), and one
further portability fact was established by measurement.**

* *Detection is not elimination.* The distinction now governs acceptance and closure: a
  hard-link **detector** does not establish that the **bypass** is eliminated. The two-sided
  identity check observes a path before and after SQLite opened it; it does not prove that
  SQLite's connection refers to the inode those checks saw, because SQLite opens by filename
  through `sqlite3_open_v2` and rusqlite's API likewise takes paths. `SQLITE_OPEN_NOFOLLOW`
  rejects symlinks and is **not** a hard-link defence.
* **Decision 1 approved — refuse on unknown, with a portability consequence.** Verified
  against this toolchain's own `std` documentation (1.98.1): on Windows,
  `MetadataExt::number_of_links`, `file_index` and `volume_serial_number` are **nightly-only
  experimental** (`windows_by_handle #63010`). `identity` needs the latter two, so on stable
  Windows the capability is unavailable *in full* and the fail-closed rule means the platform
  implementation must either call native Win32 or **refuse every open on Windows**. That is a
  support decision and is not this record's to make.
* **Decision 2 approved — the residual window is not to be called closed.** Stronger enforcement
  (a custom VFS or equivalent) is to be *investigated*, with feasibility **and WAL interaction**
  evidenced, before any descriptor-backed opening is committed to. Nothing is proposed.
* **Decision 3 approved — S-31 remains implemented but NOT complete**, and S-30 is not declared
  fully closed. Documenting a narrower guarantee is not evidence that the stronger one holds.
* **The scripted identity-change test is scope-limited**, as recorded in ADR-0058: it proves a
  *detectable* change between observations is refused. It does not prove every replacement during
  SQLite's own open is impossible, and is not to be described as though it did.

**Feasibility evidence, gathered from the pinned dependencies (ADR-0058).** Read from
`rusqlite 0.40.2`, `libsqlite3-sys 0.38.2` and bundled **SQLite 3.53.2**, not from recollection:

* **VFS feasibility: technically viable in principle, not a drop-in fix.** `rusqlite 0.40.2`
  has no `vfs` module and no `vfs` feature, so registration means hand-building `sqlite3_vfs` and
  `sqlite3_io_methods` in raw FFI. A **delegating** VFS closes nothing — `unixOpen` takes a
  pathname and re-resolves it. A **binding** VFS must serve all **17** members including the four
  WAL shm methods.
* **Sidecar names are string-derived** — `zWal = sqlite3_mprintf("%s-wal", zMove)` — so the
  `/proc/self/fd/12` descriptor-path trick asks for `/proc/self/fd/12-wal`, which is not a valid
  sidecar. **An earlier claim here that this "breaks WAL for the VFS route" was over-generalised
  and is withdrawn:** `xOpen` receives every name SQLite opens, including derived sidecars, so a
  VFS can serve them. WAL is a cost on this route, not a blocker.
* **No portable public control reaches a native handle.** `SQLITE_FCNTL_FILE_POINTER` returns the
  `sqlite3_file`, `SQLITE_FCNTL_HAS_MOVED` is not a link-count check, and
  `SQLITE_FCNTL_WIN32_GET_HANDLE` is Windows-only — so `xOpen` is the only real enforcement point.
* **No ready-made Rust solution was found.** `sqlite-vfs` requires a `WalIndex` implementation
  (declared in a `wip` module) and ships `WalDisabled`; `rsqlite-vfs` defaults `iVersion` to 1 with
  the shm callbacks absent, and its own docs state raising the version alone does not implement
  them.
* **A much smaller route exists and was not previously considered.** SQLite's unix VFS
  **already** does this check: `verifyDbFile` runs unconditionally at open and close and
  `osFstat`s the **real descriptor**, warning `"multiple links to file"` when `st_nlink > 1`.
  It is stronger than a path-based pre/post check because there is no second name resolution.
  The only gap is that `sqlite3_log` **warns and continues**; enforcement means enabling
  rusqlite's `trace` feature and calling `config_log` before any connection exists, with the
  callback flagging rather than acting (it must not re-enter SQLite).
* **Its limits are recorded, not glossed:** `verifyDbFile` returns early on `UNIXFILE_NOLOCK` and
  covers **the main database only** — **WAL/SHM sidecars are not covered** — and it is
  process-global and non-atomic. It closes the measured database-file bypass; it does not close
  the multi-name WAL hazard.
* **A bounded Linux proof of concept was built and executed** (authorised as "the isolated Linux
  VFS proof only"), outside this repository at `/tmp/opencode/vfsproof`, pinning
  `libsqlite3-sys =0.38.2` so the bundled SQLite is the **3.53.2** under analysis — asserted by a
  test, not assumed. **11 proof tests plus a version test pass; 10 consecutive runs all green.**
  The gate delegates `xOpen` to the unix VFS, then `fstat`s the descriptor that resulted and
  refuses with `SQLITE_CANTOPEN` before returning; because the parent installs its own method
  table, WAL and locking remain SQLite's own code and **no `io_methods` trampolines were needed**.
  WAL/shm keep the exact names SQLite derives, the WAL grows and truncates around a checkpoint,
  rollback-journal mode still works, 4 concurrent writer processes yield exactly 12 rows, and a
  writer killed with `process::exit(9)` leaves state a later process recovers and checkpoints.
  **Control:** ungated, the hard-link alias opens and reads the same data — so the refusals are
  attributable to the gate and nothing else.
* **Finding that corrects the design's wording.** The link count belongs to the **inode**, not
  the name: once an alias exists every path has `nlink == 2`, so enforcement is
  **all-or-nothing per inode** and the original legitimate name is refused too. A first draft of
  the test expected otherwise and was wrong. Safe, but it must present as a diagnostic rather
  than a bare "unable to open".
* **Finding: the checkpoint pragma's counters are advisory.** A `wal_checkpoint(TRUNCATE)` that
  demonstrably ran and truncated the WAL to 0 bytes returned `busy=0 log=0 ckpt=0`. Assert
  observable state instead.
* **A Shape A proof of concept was then built and executed** (authorised as "the isolated Shape A
  Linux VFS proof only"), same isolated crate, same SQLite **3.53.2**. The VFS performs `open(2)`
  itself and serves every method from a descriptor it owns, so the identity check and the open
  are one event and **no private `unixFile` layout is consulted** — asserted structurally, not
  merely documented. **26 tests pass (14 Shape A, 11 Shape B, 1 version); 12 consecutive full
  runs, zero failures.** Demonstrated: descriptor binding; refusal of a sidecar whose base path
  was replaced by a different inode (path continuity); refusal of an existing alias; **failure of
  the commit when a link appears after the open**; WAL sidecar names, rollback-journal mode,
  two-process agreement, 4 concurrent writers yielding exactly 12 rows, crash recovery and
  checkpointing; and refusal with no silent fall back.
* **Defects the multi-process tests caught** — recorded because each failed plausibly rather than
  loudly: `SQLITE_SHM_NLOCK` and `SQLITE_SHM_EXCLUSIVE` are the **same value (8)** and only
  `SQLITE_SHM_LOCK` discriminates them; mapping a shared region **past EOF raises SIGBUS**;
  EXCLUSIVE must take a **write** lock on the shared range; EXCLUSIVE must **release** the
  PENDING and RESERVED bytes or it starves other processes; and **`PENDING_BYTE` is the runtime
  global `sqlite3PendingByte`**, read here via `sqlite3_test_control(..., 0)` rather than
  hardcoded.
* **A stock-VFS patch was then built and executed** (authorised as "the isolated patched-SQLite
  experiment") against a patched copy of `libsqlite3-sys 0.38.2`, outside this repository.
  **92 lines, 35 additions, 9 deletions, four hunks**; applies cleanly with `patch -p1` and
  round-trips byte-identically. `verifyDbFile` returns a verdict instead of logging, `fillInUnixFile`
  refuses the open (releasing the inode reference under the unix mutex), and `unixSync` re-checks
  the link count on the commit path.
* **Measured differential — the result's whole value.** The hard-link refusal test **fails against
  stock SQLite 3.53.2** (stock opens the alias and only logs `multiple links to file`) and
  **passes against the patched build**. The refusal is attributable to the patch alone.
  **11 tests pass; 12 consecutive runs, zero failures.** Covered: refusal at open rather than first
  use; every name refused; no `-wal`/`-shm` created for a refused alias; a link appearing after the
  open failing the commit; WAL sidecars, `TRUNCATE` checkpointing, rollback-journal persistence,
  cross-process writer/reader agreement, 4 concurrent writers yielding exactly 12 rows, crash
  recovery, and 200 consecutive refusals leaving no leaked descriptor or inode reference.
* **New risk introduced, recorded rather than discovered:** refusing a commit when a link appears
  converts an integrity control into an **availability** hazard — anyone who can create a hard link
  can make every commit fail. Fail-closed, but a denial-of-service vector absent from stock SQLite
  that needs explicit assessment.
* **Still not established:** a maintained fork of SQLite (`deny.toml` `allow-git = []` fails G8 for
  a git-hosted fork; vendoring 9.5 MB in-tree or a deliberate `deny.toml` change is required);
  the patch must be re-applied on every SQLite upgrade, with the refusal test as its canary;
  **SQLite's own regression suite has not been run against this build** — now feasible and the most
  valuable remaining check; Linux/glibc/LP64 only; the non-participating-process residual is
  unchanged.
* **Neither proof closes S-31.** Shape A removes the post-open window and the private-layout
  dependency, but it is ~400 lines of unsafe FFI reimplementing SQLite's I/O, locking and
  WAL-index mapping — correctness **demonstrated, not established**. A non-participating process
  remains ungated; sidecar multi-name behaviour across ungated processes is untouched; link
  creation after the open is caught at sync but not prevented; `xSectorSize` is claimed rather
  than measured and `xFileControl` is minimal. Linux/glibc/LP64/3.53.2 only — no fuzzing, no
  SQLite regression suite, no stress run. **Nothing has been implemented in this repository.**

* **Follow-up validation, 2026-10-16** (evidence in
  `~/.local/share/opencode/sqlite-3.53.2-validation/run-20261016T090048Z-c1d13381/`, nothing copied
  into this repository). Canonical `version-3.53.2 @ ccc132c5`; the amalgamation it generates is
  byte-identical to the `sqlite3.c` `libsqlite3-sys 0.38.2` bundles. Candidate patch SHA-256
  `243ee4eaa53500472303a577e2f542a520ec1b936b87087e5abc0630f76128ef` (103 lines, +45/-13). A defect
  was found and corrected, not waived: the first candidate's link-count check also caught
  **directories**, whose link count is 2 or more by POSIX construction, breaking upstream
  `backup2-10`; restricting it to `S_ISREG(buf.st_mode)` restores the stock `disk I/O error` and
  keeps hard-link refusal. The earlier 92-line patch is **not** the candidate.
* **Upstream suite completed, not partial.** 1,188 `.test` files exist; 1,186 are test cases and
  `all.test` / `permutations.test` are harness drivers (zero `do_test` cases, both call
  `finish_test`, `all.test` standalone re-runs the suite). Both builds classified all 1,186
  **identically**: 1,171 PASS, 6 PASS without summary, 3 FAIL, 3 TIMEOUT, 3 INFRA, with **zero class
  divergences**. `memleak.test` remains INFRA-classified because `memleak_check` is absent from the
  3.53.2 tree, so the malloc/leak suite is **substitute evidence and not a completed run of that
  test**. `sysfault.test` ran 12 more passing cases on the patched build; the mechanism (an extra
  `osFstat` per sync lengthening the fault-injection loop) is source-grounded but **not directly
  syscall-counted**, as `strace` was unavailable.
* **Post-open hard-link behaviour is journal-mode dependent, over five consistent iterations per
  cell.** In **DELETE** mode the patched build **refused the commit** and the marker did not persist.
  In **WAL** mode it **allowed the commit**, so the transaction became durable in the WAL, and
  refused the **checkpoint** with a disk I/O error; removing the link made the retry succeed.
  Open-time refusal applies in **both** modes. Durability was established by closing, unlinking and
  **reopening**, not by trusting the error; integrity was `ok` throughout, with no descriptor leak
  across 300 refusals.
* **Not claimed.** Commit-time enforcement is **not** universal — it does not fire in WAL mode. The
  database is **not** protected against every non-participating process. Availability is
  **unresolved** and differs by mode. Verification is Linux/glibc/LP64 only. **No SQLite patch has
  been integrated into OpenRayNux**; Shape A and Shape B remain prototypes and this patch remains a
  research candidate requiring a deliberate production-design and availability decision.

**Windows (decided 2026-10-14): fail closed, defer native.** Stable Windows supplies neither
`name_count` nor `identity`, so Decision 1 means **every open is refused on Windows** until a
native `GetFileInformationByHandle` path exists. Recorded as a support decision, not an omission.

**Limitations, stated rather than smoothed over.**
* **Advisory locks coordinate only participants that follow the protocol.** A process opening
  the database by some other route participates in nothing. Every application-managed open is
  instrumented, which is what makes the claim hold here — and it is a property of this
  codebase, not of the filesystem.
* **Filesystem support is unverified.** The behaviour is measured on this host's local
  filesystem. Network filesystems may implement advisory locking weakly or not at all, and no
  evidence is claimed for them. A silently non-locking filesystem would reintroduce the
  exact gap S-31 closes, and detecting that would need a runtime probe this change does not
  contain.
* **Linux only.** The locking call is cross-platform in `std`, but only Linux was exercised.
  Windows was not tested and no claim is made for it.
* **Hard links are not detected** — see the follow-up above. This is the most significant
  remaining limitation: it is a real ownership bypass, it is measured, and it is unresolved
  for the gate reasons given.
* **Only a *restore* excludes.** Two ordinary daemons both run (proven cross-process); a
  restore refuses rather than waiting, and is refused while any shared owner remains.
* **S-30's residual gap is unchanged by this work**: if a stale log is present when `acquire`
  runs, the checkpoint folds it into the main file before the copy overwrites it, so a
  *failed* restore leaves post-snapshot data absorbed rather than discarded. It fails closed
  rather than reporting success, which is the required behaviour, but it is not a clean
  rollback.

### A-009 — S-11 (D-S11-a, D-S11-b): the trust-me migration APIs are gone, and the one remaining unprotected path is refused in production source

**F-26 remains OPEN. F-26b and F-26c remain OPEN. S-11 is NOT closed and S-29 remains blocked.**
This amendment records what was built and what was measured. It does **not** close the finding.

**What was removed, and why removal rather than restriction.**

`MigrationRunner::run(&self, snapshot_verified: bool)` took no snapshot and restored nothing. It
refused only when the boolean was `false`, so `run(true)` — which both production callers in
`security_state.rs` passed — applied every migration unprotected. Its one real behaviour was the
refusal, and a refusal that a caller can talk its way out of is a claim rather than a mechanism.

The boolean is gone rather than hidden. `run` is replaced by `migrate_ephemeral()`, which has no
parameter, and `MigrationError::NoSnapshot` is deleted with it: a variant named for a refusal
that can no longer happen would advertise a guarantee the type no longer has, which is the
failure this register exists to prevent. `migrate(db_path)` and `open_and_migrate(path)` lost
their booleans too. `SqliteAuditJournal::open_in_memory` is now `#[cfg(test)]` rather than a
public function documented as "tests only", for the same reason — a public constructor that can
only be misused is the same shape as the flag.

**Enforcement is a source check, and why it has to be.** Gate **G16**
(`scripts/gate_policy.py g16`, wired into `scripts/ci-gates.sh` and therefore into CI) reads
every crate's production source — comments and string literals blanked, `#[cfg(test)]` regions
stripped, using `scripts/rustscan.py`'s own rules — and fails if `migrate_ephemeral` is reached
outside two declared exemptions, each counted so that any addition fails the gate. No
behavioural test can do this: both paths end in the same migrations and the same `schema_meta`,
so a test that ran the wrong one would see the same database. It also fails on **drift** — if
`migrate_ephemeral` is renamed away, or `run(bool)` returns, the gate refuses rather than
passing vacuously. G13 drives it against 16 injected cases in both directions, including the
wrappings an ordinary refactor produces (a bare import, a free-function wrapper,
`#[cfg(any(test, unix))]`, `examples/`, `benches/`).

**Two latent defects in `Backup::take`, exposed by building this.**

Making the production path actually snapshot made two concurrency bugs reachable that were
previously merely present, because nothing had ever taken two snapshots of one database at once:

* *Non-atomic publication.* `take` deleted the canonical snapshot path and wrote the copy into
  it in place, so a second `take` removed the first one's file mid-write and the first then
  verified a half-written snapshot. `take` now builds at a unique staging name and renames into
  place, so the canonical path only ever names a snapshot that was built **and verified in
  full** — a restore, or the next `migrate` deciding whether to reuse a snapshot, cannot arrive
  mid-write. Measured: `the_canonical_snapshot_path_never_names_a_half_written_database` fails
  with the in-place write and passes with staging plus rename.
* *Verification read after the copy.* `verify_against_source` decided whether an empty snapshot
  was legitimate by asking the **live** source. Asked after the copy, that describes a database
  another thread may have migrated in between, so a faithful copy of an unmigrated database was
  refused with "has no `schema_meta` table". Observed directly: **eight concurrent opens of one
  fresh database failed seven of the time.** The emptiness answer is now a **required parameter**
  the caller must read before the copy, so an ordering mistake is a visible edit to a documented
  parameter rather than a silent re-read.

**Measured after the change.** `security_state::tests::concurrent_opens_of_{one,both}` — the
tests that found the bug — pass 8 runs of 8. Two pre-existing tests that had been passing on
the unprotected path were failing during the change and are now the evidence for the fix.

**Read-ordering: the deterministic gap is closed (A-010).** The mutation that re-derives the
emptiness flag from the live source at verification time — M6 — was left uncaught by this suite
and is now caught **deterministically**. `Backup::on_after_copy` and `Backup::on_before_publish`
are two `#[cfg(test)]`, thread-local, one-shot seams placed on the two boundaries the
staging-and-rename design introduces.
`a_snapshot_taken_from_an_unmigrated_source_verifies_even_if_that_source_is_migrated_after_the_copy`
installs a hook that migrates the source **from a second connection between the copy and the
verification** — the exact interleaving that made eight concurrent opens fail seven times — and
requires the snapshot to verify anyway, because the flag it was verified against was captured for
that snapshot. Measured: with the re-read restored, **3 of 3 runs fail**; with the correct
implementation, **3 of 3 pass**, and the whole `orxnud-store` suite is 326/327 with the mutant
against 327/327 without it. The probabilistic concurrent-open tests are no longer the only line
of defence. The seams are absent from the production rlib (verified by symbol table), are
`#[cfg(test)]` at every declaration, are thread-local so they cannot cross between parallel
tests, and add no public API.

**Two further defects found in `Backup::take` while hardening it (A-010), both fixed.**

* **A false premise, and a destructive fallback built on it.** `publish` carried a Windows
  `remove_file`-then-rename retry on the stated premise that `std::fs::rename` does not replace
  an existing file there. Verified against this toolchain's own `std::fs::rename` documentation
  (1.98.1): *"replacing the original file if `to` already exists"*, implemented on Windows as
  `MoveFileExW` with a fallback to `SetFileInformationByHandle`. The premise is false, and the
  fallback had a failure mode the direct rename does not: if the retry failed, the snapshot that
  may be the only good copy of the database had already been deleted. The fallback is deleted,
  not repaired. `a_failed_publication_leaves_the_existing_snapshot_in_place` fails if it is
  restored (mutation M9).
* **The staging file leaked on publication failure.** `take` cleaned up around the copy and
  verification and then used `?` on the publication, so a failed rename left a verified,
  never-published snapshot beside the database under a name no reader looks at — one per failed
  publication, reclaimed by nothing, because a later `take` only removes the staging name it
  generated itself. `a_failed_publication_removes_the_staging_file_it_never_published` covers it
  (mutation M10), and `publish` being reduced to a silent copy is caught too (M11).

**Measured, not assumed: the sidecar cleanup does not break a concurrent reader.**
`discard_failed_initialisation` removes `-wal` and `-shm`, and S-30's criterion 4(b) measured that
removing a memory-mapped `-shm` gives the affected connection `disk I/O error`. S-31 *shared*
ownership deliberately lets a second process hold the database, so a failed first initialisation
can run its cleanup while another connection is reading. Both callers drop their own connection
and lease first, and
`discarding_a_failed_initialisation_while_another_connection_has_it_open` measures the two cases
— an independent idle connection, and one holding a **live read transaction** across the
cleanup. **Both survive, with the sidecars confirmed deleted** (the test asserts the deletion
happened, because an earlier version of this file's sidecar test passed while the code it claimed
to cover was deleted). This is an in-process measurement on Linux; it does **not** extend to a
separate process with its own mappings, and is not offered as if it did.

**Not verified, stated plainly.**

* **The Windows runtime behaviour of `Backup::publish` was not executed.** The replace-existing
  property is asserted from the `std` documentation, not measured on Windows, and
  `publication_replaces_an_existing_destination_with_the_new_snapshot` is written so it will
  assert it wherever `orxnud-store`'s lib tests run. **No current CI lane runs them there**:
  `windows-portability` excludes `orxnud-store` with a stated reason (bundled SQLite built by
  `cl.exe`; the MSVC target has no working linker on a bare runner, which is why `windows-check`
  is check-only), and this host cannot even build it — `cc-rs: failed to find tool "lib.exe"`.
  Adding a step that cannot be run or verified locally would put a red lane into CI for reasons
  unrelated to this work, so none was added.
* No Tier-1 sandbox behaviour is claimed, and the hosted runner still cannot produce it.
* F-26b/F-26c, ADR-0058, and S-11's wider specification are untouched by this.

**Evidence.** Gate G16 green; G13 **90 of 90** self-tests (16 of them G16's); G15 green after
fixing three intra-doc links to the removed items, which it caught. `cargo clippy --workspace
--all-targets -- -D warnings` clean, `cargo fmt --all --check` clean, `cargo test --workspace`
**1759 passed, 0 failed, 7 ignored**, and `ci-gates.sh` all 16 gates pass with G12 skipped for
want of a release tag.

### A-010 — WP-2 hardening: the read-ordering gap closed deterministically, and two more `Backup::take` defects found

**F-26, F-26b and F-26c remain OPEN. S-11 is NOT closed.** A-010 records verification hardening
inside WP-2. It changes no guarantee's status; it changes what is *proven* about two of them.

**What A-009 left open, and what closed it.** A-009 reported M6 — the mutation that re-derives the
snapshot's emptiness answer from the live source at verification time, rather than using the
answer captured for that snapshot — as **uncaught**, with the only coverage being the two
probabilistic concurrent-open tests (3 of 8 runs failing with the mutant). That was an accurate
report of a genuine weakness in the evidence, and it is now closed.

The fix is two `#[cfg(test)]`, thread-local, one-shot seams on the boundaries the
staging-and-rename design introduces: one between the copy and the verification, one between the
verification and the publication. The first lets a test migrate the source **from a second
connection** at exactly the moment that distinguishes a verifier using what it captured from
one re-reading live state. Measured, not argued:

| Implementation | Result |
|---|---|
| Correct (flag captured pre-copy) | 3 of 3 runs pass; `orxnud-store` 327/327 |
| M6 restored (flag re-read at verification) | **3 of 3 runs fail**; `orxnud-store` 326/327 |

The failing test is
`backup::tests::a_snapshot_taken_from_an_unmigrated_source_verifies_even_if_that_source_is_migrated_after_the_copy`.
A companion test asserts the seam fires exactly once and before publication, so a green run
cannot mean "the seam was never reached" — the same vacuity this file has already produced twice.

The seams are verified absent from production: every declaration is `#[cfg(test)]`, and the
symbols are not in the non-test `rlib`. They are thread-local so parallel tests cannot interfere,
they add no public API, and they grant no capability the production path lacks.

**Two more defects in `Backup::take`, found by tracing rather than by a failing test.**

1. `publish` carried a Windows `remove_file`-then-rename retry, premised on `std::fs::rename` not
   replacing an existing file on Windows. That premise is **false** — this toolchain's own
   `std::fs::rename` documentation (1.98.1) says it replaces, implemented as `MoveFileExW`. The
   fallback was not merely unnecessary but destructive: had the retry failed, the snapshot that
   may be the only good copy of the database would already have been deleted. Removed rather than
   repaired; mutation M9 confirms a test catches its return.
2. `take` cleaned up its staging file only around the copy and verification, then used `?` on the
   publication — so a failed rename leaked a verified, never-published snapshot per attempt, and
   nothing reclaimed them, because a later `take` removes only the staging name it generated
   itself. Mutations M10 (cleanup reverted) and M11 (`publish` reduced to a silent copy) both fail.

**A hypothesis tested and closed.** `discard_failed_initialisation` removes `-wal`/`-shm`, and
S-30 criterion 4(b) measured that removing a mapped `-shm` breaks the affected connection with
`disk I/O error`; S-31 shared ownership lets a second process hold the database, so the case is
reachable in principle. Measured: an independent idle connection **and** one holding a live read
transaction both survive, with the sidecars confirmed deleted. In-process, Linux, one host.

**Evidence.** `cargo fmt --all --check` clean. `cargo clippy --workspace --all-targets -D warnings`
clean. `cargo test -p orxnud-store --lib` 327 passed, 0 failed, 1 ignored. G16 green; G13 90/90.

**Still unproven, and unchanged by this amendment.**

* **No Windows runtime evidence.** `publication_replaces_an_existing_destination_with_the_new_snapshot`
  will assert the replace-existing property wherever `orxnud-store`'s lib tests run, but no CI lane
  runs them on Windows: `windows-portability` excludes `orxnud-store` for a stated reason (bundled
  SQLite via `cl.exe`; the MSVC target has no working linker on a bare runner, which is why
  `windows-check` is check-only), and this host cannot build it at all — `cc-rs: failed to find
  tool "lib.exe"`. No CI step was added, because a step that cannot be run or verified here would
  turn the lane red for reasons unrelated to this work.
* The in-process sidecar measurement does **not** extend to a separate process with its own
  mappings.
* **A residual enforcement gap: `MIGRATIONS` is public, so G16 does not cover every route to
  the schema.** `pub const MIGRATIONS: &[Migration]` exposes the raw SQL of every migration,
  because tests need it to stage a database at a chosen version. Production code can therefore
  execute that SQL directly — `conn.execute_batch(m.sql)` for each entry — and reach the schema
  without `migrate` or `migrate_ephemeral` at all. **G16 checks only for `migrate_ephemeral`,
  so that route is not policed by it.**
  This is blunter than the bypasses G16 does close: it would skip `schema_meta` bookkeeping and
  the per-migration `IMMEDIATE` transaction, and the schema-invariant tests
  (`the_schema_contains_exactly_the_declared_tables_and_nothing_more`, `migration_versions_are_unique_and_ascending`,
  `fresh_and_migrated_schemas_converge`) would fail if it were done. It is nonetheless a real
  hole, and it is recorded here rather than minimised.
  **It is not fixed.** Closing it means either narrowing `MIGRATIONS` to `pub(crate)` with a
  test-only accessor, or extending G16 to detect direct execution of migration SQL. Neither is
  a narrow correction, and both change a public API; the decision belongs to whoever owns
  S-11's remaining specification, not to this hardening pass.
  **What must not be claimed:** that all migration bypasses are impossible, or that the
  schema can only be changed through the snapshotting path.
* F-26b, F-26c and ADR-0058 are untouched; S-11's wider specification is not discharged by
  removing the trust-me APIs.

### A-007 — S-30 (`S-11-RESTORE`): the restore path is now coordinated and logically verified

**F-26b remains OPEN.** This amendment records what was built and proven; it does **not**
close the finding. F-26 also remains open. S-11 and S-29 remain blocked.

**The ownership and coordination rule that was chosen.** `Backup::restore` is now
`pub(crate)` and takes a `&RestoreGuard`. The guard is `pub(crate)` with a private field, so
it cannot be constructed outside the crate. The only public entry point,
`Backup::restore_coordinated(db_path)`, acquires authority internally — the capability
survives, the unsafe primitive does not, and there is no step for a caller to skip. The guard
reads the target path from **itself**, not from a caller's argument, so a permit taken for one
database cannot authorise restoring another.

**What authority means, and what it deliberately does not claim.** `RestoreGuard::acquire`
runs `PRAGMA wal_checkpoint(TRUNCATE)` and **refuses** (`BackupError::Busy`) when SQLite
reports `busy != 0`, which is its signal that another connection holds a read transaction.
Measured first: `PRAGMA locking_mode = EXCLUSIVE` does **not** exclude a second handle (it
opened and read successfully), so it was not used and is not sufficient.

**Two design decisions were forced by measurement, not chosen.**

* **The copy is in place, not a rename.** `fs::rename` over a database file another
  connection has open **strands** that connection on the old inode: measured, the handle kept
  reading pre-restore rows while the writer saw the restored ones. The online backup API
  writes through the existing file and an open handle observes the restored state.
* **Sidecars are not deleted.** The first implementation removed `-wal` and `-shm` after the
  checkpoint as "belt and braces", and criterion 4(b) caught it: with an independent connection
  open, deleting the memory-mapped `-shm` left that connection failing with `disk I/O error`.
  That is exactly the hazard S-30's specification warned about, and it is why sidecar deletion
  is not the mechanism. An empty write-ahead log replays nothing, which is the property that
  matters; the in-place copy overwrites whatever the checkpoint folded in.

**What prevents a restore without coordination:** `restore` being `pub(crate)`. Verified
mechanically, not asserted — `crates/orxnud-store/tests/s30_restore_not_public.rs` compiles a
probe against the crate as an external consumer and requires it to fail on the mechanism.

**Acceptance results.**

| Criterion | Result | Evidence |
|---|---|---|
| 1 — stale `-wal`; stale `-wal` + `-shm` | **pass** | `criterion1_a_*`, `criterion1_b_*` |
| 2 — unreadable is failure | **pass** | `criterion2_an_unreadable_restored_database_is_a_failure_not_an_absence` |
| 3 — logical-state verification | **pass** | `criterion3_logical_comparison_detects_what_structural_checks_cannot` |
| 4(a) — mechanism prevents replay | **pass** | `criterion4a_the_guard_prevents_replay_before_the_copy` |
| 4(b) — independent handle | **pass** | `criterion4b_an_independent_open_handle_is_either_safe_or_refused` |
| 4(b) — coordination bypass | **pass** | `criterion4b_restore_cannot_be_reached_without_a_permit`, `criterion4b_the_public_entry_point_refuses_while_a_reader_holds_the_database`, `restoring_from_outside_the_crate_does_not_compile` |
| 5 — failure/interruption | **pass** | `criterion5_an_interrupted_restore_reports_an_error_and_keeps_the_snapshot`, `criterion5_a_snapshot_that_fails_verification_is_refused_outright` |

**Commands and outcomes.**

```
cargo test -p orxnud-store --lib -- criterion      11 passed, 0 failed
cargo test -p orxnud-store                         301 + 7 + 3 + 3 + 1 + 0 passed, 0 failed, 2 ignored
cargo test --workspace                             1723 passed, 0 failed, 7 ignored
cargo fmt --all --check                            clean
cargo clippy --workspace --all-targets -- -D warnings   clean, exit 0
CI=deny ./scripts/ci-gates.sh                      all selected gates passed (G12 skipped, no tag)
```

**Two tests were wrong before they were right, and both are recorded because the wrongness is
the evidence.** The compile-fail probe originally called `restore(&Path)` when the method takes
`&RestoreGuard`, so it failed on a **type mismatch** and would have reported success whether or
not the method was public — it proved nothing. It was rewritten to the real bypass shape and
then **mutation-checked**: with `restore`, `RestoreGuard` and `acquire` all made `pub`, the
probe compiles and the test **fails**, as it must. Separately, criterion 5's "interruption" first
deleted the target file, which is not an interruption at all — SQLite creates a fresh database
at the path and the restore succeeds — so the test would have passed without testing anything.
It now makes the target read-only, which is a real failure.

**Update 2026-10-14, after S-31: the cross-process gap recorded here is enforced by a stable
per-database lock file held across the whole restore lifecycle, with two-process evidence —
but F-26c REMAINS OPEN**, because a hard-linked alias still bypasses ownership (A-008
follow-up). **F-26b remains open** on the narrower point below; **F-26 remains open** and
belongs to S-11.

**F-26b stays open on a *different* ground, now F-26c.** The
in-process evidence above is sound and is not discounted: it establishes that a stale log no
longer resurfaces, that a live idle handle observes the restored state, that an active reader
is refused, and that the restore is compared logically before `Ok`. What none of it can reach is
a writer in **another process**. `RestoreGuard::acquire`'s checkpoint is an instantaneous check,
not a lease; a second daemon is not in this process's connection set, so its presence does not
make our checkpoint report busy; and the online backup API's destination lock covers the backup
operation, not the surrounding lifecycle. Some interleavings SQLite refuses on its own —
**refusing by accident is not a guarantee** and is not treated as one. Tracked as **S-31
(F-26c)**; the chain is **S-31 → S-30 closure → S-11**.

**What remains outstanding.** The invariant is enforced **within one
process**. Nothing coordinates a second *daemon process* against a first: `TaskService::open`
can run concurrently against the same database, and the guard would observe a reader and refuse
— safely — but there is no inter-process ownership. `Backup::take` and `Backup::verify` are
unchanged. And the underlying staleness question is unchanged: if a stale log is present when
`acquire` runs, the checkpoint folds it into the main file before the copy overwrites it, so a
**failed** restore could leave post-snapshot data absorbed rather than discarded. That path
returns an error rather than `Ok(())`, which is the required fail-closed behaviour, but it is
not a clean rollback and S-30 does not claim it is.

### A-006 — K.1's second half: a refuted *postcondition* was also a retry permission (F-17)

**This amends K.1, which is now half superseded.** K.1 closed the case "a verifier returns
`Refuted` for an execution that did not report success", and it closed it well. It stated, as
its own scope boundary, that "after admission, a `Succeeded + Refuted` is trusted, exactly as
V-92 chose to trust it". **That is the half that was wrong, and ADR-0056 withdraws it.**

K.1 also recorded "`Certainty`, `EffectStatus`, `TaskState`, `recover()` and its predicate are
all unchanged". `Certainty` and the certainty-to-status mapping are now changed; `EffectStatus`,
`TaskState` and `recover()`'s predicate are **not**.

**What changed.** Three routes issued the retry permission from postcondition evidence:

1. `certainty_of` mapped `Refuted` to `Certainty::Disproved`, which mapped to
   `EffectStatus::NotPerformed`. **The producer was removed, not the meaning.**
2. `effect_status_for_dispatch_failure` grouped `DispatchError::VerificationRefuted` with six
   genuine pre-execution refusals and answered `NotPerformed`. That grouping was the defect in
   one line: a post-execution finding sat beside `Policy` and `ClassEscalation`, which *are*
   decided before a process exists. Split out, now `Unknown`.
3. The audit journal recorded `VerificationRefuted` as `Failed`. Moving only the ledger would
   have produced `Failed` beside `Unknown` — the exact channel contradiction the conformance
   table exists to prevent. It caught this; the journal is now `Uncertain`.

`Certainty::Disproved` was deleted rather than left unconstructed. It encoded "the verifier
established that the effect did not occur", which no verifier in this repository can establish:
`WriteTextVerifier` re-reads bytes and cannot tell a genuine write-then-overwrite from a write
that never ran. Deleting the variant makes the invariant structural, and `clippy -D warnings`
(gate G6) requires it — an unconstructed variant is a `dead_code` failure. The arms that
consumed it kept their meaning for a future producer that *can* warrant it.

**Evidence.**

| Command | Result |
|---|---|
| `cargo test -p orxnud-daemon --lib` (pre-fix) | 1 failed — the F-17 regression, `Refuted { evidence: "…exists but holds 24 bytes, not the 6 requested" }` |
| `cargo test -p orxnud-daemon --lib` | **173 passed, 0 failed** |
| `cargo test -p orxnud-capability --lib write_text::tests::` | **8 passed, 0 failed** |
| `cargo test --workspace` | **1711 passed, 0 failed, 7 ignored** |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean, exit 0 |
| `CI=deny ./scripts/ci-gates.sh` | G8 and G11 fail — see below |

Four mutations, each reverted after observation, **all caught**:

| Mutation | Caught by |
|---|---|
| M1 `effect_status_for_certainty`: `Unknown` → `NotPerformed` | the F-17 regression, the pre-existing `a_refuted_claim_from_a_silent_capability_can_never_become_a_disproof`, and one duplicate listing — 3 failures |
| M2 journal: `VerificationRefuted` → `Failed` | `the_two_channels_never_contradict_on_execution_certainty` |
| M3 `effect_status_for_dispatch_failure`: → `NotPerformed` | `a_refuted_verification_is_recorded_as_unknown_not_as_not_performed` + the two-channel table |
| M4 `certainty_of`: `Refuted` → `Established` | the F-17 regression + the silent-capability test — 3 failures |

**M1 survived its first run, and that is the most useful result here.** The regression originally
re-implemented the certainty-to-status `match` locally, so it tested its own copy: the production
mapping was mutated and 173 tests passed. The `match` was extracted to
`effect_status_for_certainty` and both the regression and K.1's existing chain test now call it.
A test that mints the answer it is checking passes against the defect; the extraction is what
made the seam real.

**Controls, none weakened to obtain a green suite.** `a_refusal_before_execution_still_earns_its_retry_permission`
is new and asserts `NothingAttempted` → `NotPerformed` survives. `an_unknown_row_stops_a_non_idempotent_task_from_being_retried`
(the `orxnud-store` control) and the three pre-existing refusal tests are unchanged and green.
`a_write_that_never_happened_still_proves_absence` was **renamed and re-justified** per ADR-0056
Decision 7: it still asserts `Refuted`, because the verifier's observation remains true — what
changed is what the consumer may do with it. A capability-side test
(`a_write_that_occurred_and_was_later_overwritten_is_refuted_and_survives_admission`) stops anyone
"fixing" F-17 by suppressing a true observation.

**Scope: F-17 remains PROBABLE EXPOSURE.** The competing write is staged in the workspace
between the adapter's write and the verifier's re-read, not raced. **No live-daemon reproduction
has been performed**; it needs a second write to land inside the verification window, which is
timing-dependent. What is proven is the mapping and its consequence through real admission, real
settlement, a real migrated database, and the real `recover`/`claim_specific` predicates — not
the reachability of the timing window.

**Known limitation, recorded rather than invented around.** A refuted non-idempotent effect now
settles to `NeedsVerification`, which is terminal and has **no exit** until S-29 supplies an
adjudication path. That is a stranding risk taken deliberately: the alternative was an
occasional duplicate non-idempotent effect with no human involved. S-04 remains blocked on S-29
and was **not** implemented here. No schema change was made; Option B remains unbuilt.

**Gate failures at the time of this slice, and what became of them.** G8 and G11 both failed on
four `rustls` 0.23.45 advisories (RUSTSEC-2026-0346/0347/0348/0349, all dated 2026-10-14).
Neither failure was caused by this slice, which modifies no dependency file.

Both were remediated afterwards by a lockfile-only bump, `rustls 0.23.45 -> 0.23.46`
(`cargo update -p rustls --precise 0.23.46`): a two-line delta — version and checksum — with
no transitive churn and no `Cargo.toml` edit, because `rustls = "0.23"` is a caret requirement
that already admits 0.23.46 and `tokio-rustls 0.26.6` requires `>= 0.23.27`. `CI=deny
./scripts/ci-gates.sh` now reports **all selected gates passed** (G12 skipped, no release tag).

**A correction to this row's earlier text.** The previous version of this entry attributed G8's
failure to `getrandom` being duplicated in `Cargo.lock`. That was wrong. G8 runs
`cargo deny check bans sources advisories`, which **includes advisories**; it was the `rustls`
advisories that failed it. The `getrandom` duplicate is a `warning[duplicate]`, not an error —
`cargo deny check bans sources` exits 0 with it present — and it has never failed a gate. It
remains in the lockfile (0.2.17 via `ring 0.17.14`, plus 0.3.4 and 0.4.3), was untouched by this
bump, and is left alone rather than suppressed.

**Reachability of the four advisories, assessed rather than assumed.** At `rustls 0.23.45` with
this repository's configuration — `default-features = false`, features `ring`, `std`, `tls12`,
`logging`, no `aws-lc-rs` — none of the four vulnerable paths is reachable:

| Advisory | Precondition | This repository |
|---|---|---|
| -0346 `Debug` leaks session secrets | a **custom** `ClientSessionStore` formatting session values with `Debug` | **Not applicable.** `transport.rs:269` uses `ClientConfig::builder().with_root_certificates(..).with_no_client_auth()`, i.e. the built-in store, whose `Debug` the advisory states is redacted. No `ClientSessionStore` impl in the tree. |
| -0347 ECH rejection leaks buffered data | `EchMode::Enable` | **Not applicable.** `EchMode` is never configured anywhere in the tree. |
| -0348 Brotli cert decompression 1 GiB alloc | the non-default `brotli` feature | **Not applicable.** Enabled features are `ring`, `std`, `tls12`, `logging`. |
| -0349 PQ downgrade via stored kx group | a PQ hybrid in `supported_groups`, with resumption storing it | **Not applicable.** The **`ring`** provider's `DEFAULT_KX_GROUPS` is `[X25519, SECP256R1, SECP384R1]` (`rustls-0.23.45/src/crypto/ring/mod.rs:181`) — `X25519MLKEM768` exists only in the `aws_lc_rs` provider, which this repository does not enable. There is no post-quantum preference to lose. |

The bump was made anyway: the fix is a patch release inside an already-permitted range, it costs
nothing, and "no advisory is currently reachable" is a statement about today's configuration
rather than a property that survives someone enabling `brotli`, adding a custom session store, or
switching crypto provider. The analysis is recorded so that a future change in any of those three
directions can be checked against this row.

| | |
|---|---|
| **event** | any change to `certainty_of`, `effect_status_for_certainty`, `effect_status_for_dispatch_failure`, the audit classifier for `VerificationRefuted`, or the `Certainty` enum |
| **date** | 2026-10-14 |
| **severity** | **High.** Silent drift re-opens an automatic repeat of a possibly-performed non-idempotent effect, with no human involved. |

## 3. The three highest-risk claims

Not by severity of consequence alone, but by **(likelihood of silent drift) ×
(consequence if it drifts)**:

1. **V-06 (TypeScript / Svelte)** — a *claim that was already wrong once*. The
   register entry therefore mandates reading the tool's **source**, not its
   metadata. Peer ranges state what a package declares, not what is possible.
2. **V-20 (model licences)** — licences change silently, upstream is under no
   obligation to announce it, and the failure is *legal*, discovered after
   shipping.
3. **V-08 / V-25 (the resource budgets)** — these are the only claims in the
   entire architecture with **no external source at all**. They are our
   assertions, and they are the ones most likely to drift because nothing will
   tell us they are wrong. Hence: measured in CI, not asserted in prose.

---

## 4. Operating rules

1. **Every ADR that rests on an external fact cites its V-ID.** A decision
   without one is either a pure design preference (fine, say so) or an
   unverified claim (not fine).
2. **Reviewers check the register, not just the diff.** A PR touching a
   registered claim must update `last verified` or explain why not.
3. **`event` triggers are checked by a human, deliberately.** A bot that
   "re-verifies" by re-fetching proves liveness, not correctness. The judgement
   — "did this actually change anything we rely on?" — must stay human.
4. **CI asserts what is machine-checkable** and nothing else: the bundled SQLite
   version (V-02), the resource budgets (V-25), the absence of heavyweight
   dependencies (V-24), the licence policy (V-20, via `cargo deny`).
5. **A claim that turns out to have been wrong gets an amendment record**, in
   the style of ADR-0005's. Wrongness is worth recording; it is how the register
   improves.
6. **This register is itself reviewed quarterly.** A register that only grows is
   a liability, not an asset.

| **V-90** | **`INTERNAL_ERROR` was produced by default rather than by an argument: routes that reached `RequestError::Refused` reported whatever landed there as a server fault** | The shape, not one mapping. `RequestError::Refused { reason: String, detail }` mapped to `-32603`, so any condition that reached it became a server fault, and two catch-alls reached it from every `DispatchError` variant while also writing `e.to_string()` into `data.reason`. Three independent causes: (1) `Err(e) => Refused { reason: e.to_string() }` on both dispatch paths, flattening 11 `DispatchError` variants; (2) `PolicyError::Denied` carried a `String` built by `ToString`, with a `"refused without a stated reason"` fallback for a case the type system made unreachable, so classifying a policy denial meant substring-matching rendered JSON; (3) `RequestError::Malformed` put serde's sentence in `data.reason`. **Previously observed:** `capability/dispatch` digest mismatch and `task/execute` sandbox refusal, both found by accident while writing tests for ADR-0051. **Newly discovered by the survey:** ten `Refused` construction sites in total; cause (2); cause (3), on the frame-decode path rather than the dispatch path; and `Credential::{Absent,Unavailable}`, `NoImplementation`, `Disabled`, `ClassEscalation`, `PolicyError::{Unavailable,AuditUnavailable,ApprovalLedgerUnavailable,InvalidSchema}` and four `DenialReason`s reaching the same flattening. **Not exhaustively provable:** whether *any* route was missed — see below. | **fixed** | 2026-10-06 | `RequestError::Refused` is **gone**. `INTERNAL_ERROR` is `RequestError::Internal { fault: InternalFault, detail }`, where `InternalFault` is a closed enum of seven variants each carrying its own argument for being unrecoverable by caller action. No default, no free-form string, and **no `_` arm** in any of the three classifiers — so a new `DispatchError` or `DenialReason` is a *compile error*, which is the outcome the old shape made impossible. `PolicyError::Denied` now carries a typed `DenialReason`, so the 17 reasons are classified exhaustively. Classified by recovery rather than variant name: sandbox and both credential variants, `PolicyError::{Unavailable,AuditUnavailable,ApprovalLedgerUnavailable}` and `DenialReason::{PolicyUnavailable,AuditUnavailable}` → `-32043`; `NoImplementation`, `ClassEscalation`, `DenialReason::{UnknownCapability,InvalidParams,DataClassExceeded}` → `-32600`; `Disabled` and the 13 remaining denials → `-32042`; `Execution`/`Verification`/`Reentrant`/`InvalidSchema` → `-32603`. **Four refusals stopped interpolating a raw error `String`** — storage and secret-store layers can return a path or a SQL fragment, so those now carry a fixed sentence and the cause stays in the server log (ADR-0051's no-OS-identifier rule extended to error text). **Deliberately unchanged:** no classification that was already correct was touched. `approval-already-consumed` and `no-grant` stay `FORBIDDEN` despite `CONFLICT` being arguable, because those words are on the wire and this work is about false `INTERNAL_ERROR`, not about re-litigating the taxonomy. **Vocabulary:** `TaskCause::Storage`/`Corrupt` split into `storage-unavailable`/`durable-state-corrupt`; `proposal-corrupt` and `approval-corrupt` unified under `durable-state-corrupt`. Both words shipped only in unreleased `main`. **Evidence:** `tests/taxonomy.rs` 10 → 14 (each class reachable for its own reason; a **real** corrupt-row fixture still `-32603`; both previously-known routes pinned; a sweep asserting no reachable refusal puts prose in `data.reason`), `tests/refusal_completeness.rs` (5 static checks on the shape). **Mutation-checked: 14 of 15 caught, 0 unobserved, 1 skipped** (a no-op pattern, reported as skipped rather than counted) — sandbox and credential classification, `NoImplementation`/`Disabled` to internal, policy flattened to internal, each denial group moved to the wrong class, a reason word changed, prose returned to `reason`, `_` fallback arm reintroduced, conflict→invalid, not-found→internal, ledger outage→internal, storage fault→environment. **Remaining, and the reason this is not "exhaustive":** the survey was static, so it can prove what the source *contains* and not what a future route will contain. What it does prove is that a future route cannot reach `INTERNAL_ERROR` without naming a fault — which is the stronger property, and the one `refusal_completeness.rs` holds in place. |
| **V-92** | **An uncertain non-idempotent side effect left the task `running` under its lease, so the next daemon restart made it retryable and the same action could be executed again** | `TaskState::NeedsVerification` was defined, documented as "a side effect may or may have occurred. Terminal until a human adjudicates", marked terminal, excluded from `claim` and from `recover()`, and stored as a legal `Running -> NeedsVerification` transition — and **no production path produced it**. Every handler did nothing when verification did not confirm. Reproduced over a real daemon with real durable state: `execute(undetermined)` -> `running`, lease held, `last_error` null; restart -> `recover()` sees `running` + a lease and returns it to `pending` (the query has **no expiry predicate**, so it reclaimed *unexpired* leases too); any worker claims it -> attempt 2; `task/propose` -> the same `write-text`, pending approval. The daemon was saying "we don't know whether it happened, so we tried again" with no human involved, at the next process start. The engine needed nothing — the state, the terminal flag, the claim/recovery exclusions and the lease-clearing fenced transition all already existed; what was missing was the decision. | **fixed** | 2026-10-06 | Introduces the decision, classified by **certainty** rather than by the adapter's outcome: established -> the existing completion path; **disproved** (`Refuted`) -> `Failed`, retryable; **unknown** + idempotent -> `Failed`; **unknown** + non-idempotent -> `NeedsVerification`. The brief's suggested `failed -> retry` row is *not reachable* for a non-idempotent capability, because `WriteTextVerifier` maps `ExecutionOutcome::Failed` to `Undetermined` — a subprocess can die after writing, so an adapter-reported failure is not evidence about the effect. **`Refuted` is retryable regardless of idempotency**, because the verifier already decided which findings make a retry safe ("only `Refuted` makes it safe") and the task layer has strictly less information. **Idempotency is read from the capability declaration**, never inferred, and an unknown capability is treated as non-idempotent — the direction that cannot duplicate an effect. **The lease is released**, which is safe only because the state is terminal; holding it would park the task on a 30s timer and hand it back to `pending`, the same defect by another route. **A lost fence maps to `CONFLICT`**, so the caller learns the *settling* was refused without retrying the execution whose status is in doubt. Two smaller corrections: the task event was logged `completed` for any non-requeue transition (the same lie the adjacent comment condemns for dead-lettering), and the execute reply now carries `uncertainty` so a client learns the task stopped from the response. **Evidence:** `tests/uncertain_outcome.rs` — 8 tests through a real daemon, real sandbox, real `WriteTextVerifier`, real restart and real fault injection at `complete-after-update-before-attempt` — plus an exhaustive decision-table test in `runtime.rs`. **Forbidden shortcuts pinned individually:** not claimable, not executable, not continuable, not proposable, not completable by a worker that still believes it holds the lease, never `pending`, never `running`, and not turned into a completion by a later worker reporting success. **Audit:** exactly one `needs-verification` event naming the state it moved to, no `completed` event for it, and a durable reason naming the capability and the certainty — with an assertion that it does **not** copy the payload that may have been written. **Mutation-checked: 10 of 10 caught, 0 unobserved, 0 skipped** — unknown+non-idempotent to `Failed`, unknown+idempotent to `NeedsVerification`, disproved to `NeedsVerification`, idempotency hardcoded true, idempotency inverted, the event-kind lie reintroduced, the fence ignored, `effect_observed` claimed true, the whole settlement bypassed (which restores the original defect), and the uncertainty hidden from the reply. **Restart:** proven across a real process restart, which is the step that used to undo everything. **Crash:** proven at the fault point inside the transition; the task is never retryable after, on either side of the transaction. **Not claimed:** the user-facing adjudication UX, and in particular that "assume it succeeded" is represented. A human adjudicating an uncertainty is not a verifier establishing a fact, and recording it as `verified = true` would put a falsehood in the audit chain — so Q-OPEN-18's open half now names that as a constraint on its design rather than leaving it implied. **Known evidence gap, recorded:** two of the four table rows have **no deterministic end-to-end producer**. `Refuted` is unreachable through the shipped adapter/verifier pair — an over-limit read fails in the helper before the verifier's independent read runs — so the remaining `Refuted` branches need the file to change between two reads, which no test can schedule. The capability crate unit-tests both verifiers' `Refuted` branches, so the verifier logic is covered; what is missing is a task-layer producer, and a test now fails if that changes silently. |

| **V-91** | **Any process that could open the local socket obtained `Actor::Human`, because the daemon asserted a human rather than establishing one** | Every handler called `local_actor()` — a function taking **no arguments** — returning `Actor::Human { user: UserId::new("local") }`. The actor model (ADR-0027) was correct; the boundary that was supposed to *produce* those actors did not exist. Authority was real and attribution was fiction: the only thing standing between a local process and full human authority was the socket's `0600` mode, a filesystem ACL that no code compared to anything. Every audit record claiming a human approved something was a claim about a file mode. Separately, `delegated_by` was `UserId::new("local")` written inline, so every model proposal's delegation chain was an assertion about a string rather than a consequence of who was authenticated. | **fixed** | 2026-10-06 | Introduces the boundary ADR-0051 records. `orxnud-platform-ipc` reads `SO_PEERCRED` at `accept` and stores it on the stream; `InstallationIdentity` reads the bound endpoint's owner once at startup (from the socket, not `geteuid`, which diverges under privilege drop); `authenticate` compares and runs **before a byte is read**, returning an `AuthenticatedPrincipal` or a refusal. **The negative finding is as important as the fix:** a raw JSON-RPC caller *cannot* forge an actor field — `Request` has no actor member, `_meta` is never read for identity, no handler reads any identity-shaped param, and declaring `actor`/`user_id`/`approver`/`delegated_by`/`granted_by`/`authorised_by` over the real socket changed nothing. That is the comfortable answer and the wrong one to stop at, because the caller obtained `Human` either way, from a constant, having proved nothing. **Structural, not arithmetic:** `AuthenticatedPrincipal` has **no "unknown" variant**, so an unauthenticated caller cannot be represented as a caller; `route` derives the `Actor` once and hands handlers the actor, not the principal, so no handler can reach the uid. `local_actor()` now has exactly one caller. Refusals use ADR-0050 by recovery — `FORBIDDEN` for a wrong peer (nothing the caller does changes it), `ENVIRONMENT_UNAVAILABLE` when no identity was established, which refuses *everyone* because "nothing to compare against" must not mean "allowed". **No detail leaks:** no uid, socket path or syscall name appears in any refusal. `UserId` stays `"local"` (what the approval digest binds, so no issued approval is invalidated) and the uid is discarded after the comparison, keeping an OS identifier out of every audit record and IPC error. **Platforms, separately:** Linux **proven** on every run — `the_accepted_peer_is_the_connected_process` reads a principal off a real accepted connection and compares it to the connecting process's own uid. Windows **fails closed** at `bind` (`Listener::Unsupported`); no identity is claimed and none is faked. Other Unix reports no identity rather than shipping an untested `getpeereid` branch. **Persisted actor is not authentication:** `proposer_json` reads back as an `Actor`, and granting nothing because the approval path re-derives the approver from the authenticated principal — `persisted-proposer-becomes-human` is caught. **Evidence:** 10 wire tests in `tests/identity.rs` (every forged field, `_meta`, restart stability, 8 concurrent clients deriving one identity, the real `orxnuctl` binary), 4 in `runtime.rs::identity_boundary` over a real socket, 1 in the platform crate. **Mutation-checked: 18 of 18 caught, 0 unobserved** — principal→Human conversion, owner comparison in both directions, unknown-installation fail-closed, uid plumbing, AI delegation binding, approver sourced from the request, persisted-proposer-as-human, restart identity, and `External`/`System`/`Ai`/`Integration`/`Scheduled` each being made grantable. **Latency:** no measurable cost; see the register note below. **Harness:** mutations ran in a throwaway worktree via `scripts/mutate.sh`, which refuses a dirty tree — a prior in-tree runner's `git checkout` discarded uncommitted work during V-89 and `mutation_harness_is_safe` (3 tests) now proves the guard. **Not claimed:** `AuthChannel::LocalInteractive` records local-and-same-owner, not a person at a keyboard; a Unix socket cannot tell a shell from a cron job, nothing depends on it, and no policy rule reads it. `SO_PEERCRED` reports a user, not a session. **Unchanged:** task state, claim/lease, approval expiry and replacement, continuation, observation, disclosure, provider identity matching, capability declarations, sandboxing, resource limits, and every approval digest. **Latency, measured not asserted:** the daemon serves one request per connection and closes, so per-request and per-connection are the same number and the identity check is paid on every request. Best-of-three over 3000 request round trips, release build, same host, alternating between this commit and its parent in isolated worktrees: **63.8µs / 64.7µs / 68.3µs with** the boundary against **65.3µs / 65.5µs / 68.2µs without**. The distributions overlap in both directions, so the honest claim is that **one `getsockopt` per connection is not distinguishable from noise** on a ~65µs path — not that it is free. V-25's latency/RSS budget is **not** re-proven by this entry. |
| **K.1** | **A capability verifier could return `Refuted` for an execution that did not report success, and `Refuted` is the only verification finding that becomes `EffectStatus::NotPerformed` — the one status `recover()` reads as "a repeat cannot duplicate anything"** | Two producers could issue a retry permission without a warrant, and both are now closed **at their source**, not in recovery. (1) *The sandbox half.* `BwrapRunner::run`'s cgroup-membership check gives up **after** `spawn_supervisor` returned, but reported the same `ExecutionStatus::Refused` as the five refusals decided before a process exists; the status carried no phase, so `SandboxExecutionBackend::execute` was obliged to read it as `SandboxRefusal::nothing_attempted`, the journal as `Denied`, and the ledger as `not-performed`. `ExecutionStatus::Abandoned` now reports "a process existed and the runner could not vouch for the run", and gate G2 rule (g) fails the build if any in-tree `SandboxRunner` constructs a pre-spawn-only status after a spawn. (2) *The verifier half.* `VerificationOutcome::Refuted` → `certainty_of` → `Certainty::Disproved` → `EffectStatus::NotPerformed`, via two code paths that never consulted `ExecutionOutcome`. A capability that failed or went silent may still have produced its effect — a sandboxed helper writes its file and is *then* stopped at the deadline — so "I looked and it is not there" and "I never got to look" are the same sentence. `Verifier::verify` now states the admissibility rule ("`Verified` and `Refuted` are admissible only against a `Succeeded` execution") and `admit_verification` enforces it at the single production `verify` call site, over all nine `ExecutionOutcome` x `VerificationOutcome` cells with no wildcard, so a new variant on either enum breaks the build there. `Certainty`, `EffectStatus`, `TaskState`, `recover()` and its predicate are all unchanged. **Evidence:** the verifier mutation (`Unknown` execution → `Refuted`, one line in `WriteTextVerifier`) reproduces the whole chain with all 1647 tests green — real daemon, real bubblewrap, real non-idempotent `filesystem/write-text`, a real file on disk, `not-performed` + task `pending` + a second worker claiming `attempt 2`. After the fix the identical mutation is inert, and disabling the enforcement instead fails 7 invariant tests across three crates. **Historical rows:** no migration and no prose matcher; a genuine pre-start refusal and a post-start give-up are not structurally separable, and the verifier half of the exposure is zero because no verifier in this repository's history has ever had a `Refuted` arm reachable outside its `Succeeded` arm. Decision recorded at `task_repo.rs` beside the predicate. **Scope boundary, and it is the important part:** what is mechanically enforced is the **relationship between execution standing and what a verifier may claim**. The verifier's *world claim* remains the capability author's responsibility — after admission, a `Succeeded + Refuted` is trusted, exactly as V-92 chose to trust it. A claim in an inadmissible frame is now impossible; a wrong claim in an admissible frame is a semantic error in a capability, caught by reviewing that capability. This row is therefore a statement about the *shipped, in-tree* execution path, not a proof that no implementation of the public `SandboxRunner` can misreport a phase; the trust that carries is the extension model's own (§2.1, host-side execution is **core trust**, and untrusted code reaches the host only as a Tier-1 `Subprocess` capability that *consumes* a runner rather than supplying one). **Not claimed:** that any refutation is independently confirmed; that a third-party runner cannot misreport a phase; and that the `Undetermined { reason }` a refusal carries is durable — it is currently unread in production, which is observability debt rather than a safety gap. | **event:** any change to `ExecutionOutcome`, `VerificationOutcome`, `ExecutionCertainty`, `EffectStatus`, `recover()`'s predicate, `SandboxRunner`, or `Verifier`; and on any new capability shipping a `Refuted` branch | 2026-10-08 | **High.** Silent drift means a non-idempotent effect that may already exist becomes claimable with no human involved, while the journal records `Uncertain` beside a ledger reading `not-performed`. |

| **V-93** | **A reservation outcome could not be distinguished from a failure, so a refused dispatch and an already-done dispatch shared one representation** | `TaskRepository::reserve_effect` used `INSERT OR IGNORE`, which resolves a primary-key collision, a NOT NULL failure and a CHECK failure identically: the row is skipped and the statement reports zero rows. `Ok(None)` therefore meant both "this key is already reserved" (the caller's signal *not* to dispatch) and "this reservation was invalid". An invalid reservation reported as a duplicate looks like work already done. The production operation also accepted a zero-row state change as success. | **fixed** | 2026-10-08 | Replaced with a plain `INSERT`, identifying the duplicate by SQLite extended code `SQLITE_CONSTRAINT_PRIMARYKEY` rather than by substring-matching a message, and refusing a zero-row state change in the production path too, so `None` is now unambiguously "already reserved". **Evidence:** `crates/orxnud-task/tests/v94_reproduction.rs` — the assertions are about *observable durable state* (a row that exists, an event that was or was not written) rather than about an error variant, so each compiles and **fails** against the defective implementation. Also pinned there: absence of a task or of an approval is a refusal and not an empty proposal or an execution; a spent approval is a refusal and not a second execution; the reservation outcomes are exactly two and neither is an error; and every `execution_begun` and `action_proposed` event is cross-checked against the durable state it claims. |
| **V-94** | **The five audited defects had no reproduction, so each fix was argued rather than demonstrated** | The Phase 0 discipline requires every finding to be reproducible against the unmodified code before it is fixed, and the reproductions did not exist in the tree. A defect argued from reading is a defect that can be argued away the same way. | **fixed** | 2026-10-08 | Phase 0 reproductions exist in `crates/orxnud-task/tests/v94_reproduction.rs`, written against **observable durable state** specifically so that each one compiles and fails pre-fix rather than failing to build. This entry records the *discipline*, and the five findings it covers are recorded under V-93, V-95 and V-97; what V-94 guarantees is that each of those has a test that fails without the fix. |
| **V-95** | **`TaskRepository::tx` was documented as beginning an IMMEDIATE transaction while behaving otherwise, so two writers could both decide and only one write** | The docs claimed `IMMEDIATE` and explained, correctly, why it is required; the implementation took the lock *after* reading the state it was deciding on, so a decision could be made against state another writer was in the middle of changing. That is the classic read-then-decide race, and its visible symptom was a competing state change surfacing as an unclassifiable SQLite busy error instead of a refusal. | **fixed** | 2026-10-08 | The write lock is now taken **before** the deciding read, and `DEFERRED` versus `IMMEDIATE` is asserted to differ in exactly that way. **Evidence, in two files separated by subject.** `v95_atomicity.rs` proves the atomicity boundary *by what survives a failure*: the window baseline commits state, authority and event together; a failure at the first write, after the state mutation, or after the event leaves no mutation and no event; a task refused by a failed attempt is still fully retryable; a failure inside `propose_action` leaves neither proposal nor state change. `v95_concurrency.rs` proves what happens when two writers *meet*: a competing state change is a classified refusal on both the lease path and the proposal path; two workers racing one approval never both execute, verified over many runs; two and then four recoveries racing settle each orphan exactly once; recovery racing a claim leaves exactly one owner; a competing cancellation makes the contender wait and then see the new state. |
| **V-96** | **The platform-boundary gate G3 matched raw text, so a comment could switch it off and seven of nine `cfg` spellings — every nested one — were invisible** | G3 originally classified source by pattern-matching the raw file. That has three consequences, all demonstrated by the reproductions in `scripts/gate-selftest.py`: (1) a `//` comment containing a platform key satisfied the gate, because the matcher did not know what a comment was; (2) `cfg(all(unix, target_os = "linux"))`, `cfg(any(test, unix))` and predicates split across lines were not recognised as platform predicates at all, because only the outermost key was read; (3) the gate was therefore satisfiable by text that did not compile as a platform branch at all — the definition of a gate that gives false confidence. | **partially fixed** | 2026-10-10 | Gate G3 now reads source lexically before classifying it: `scripts/rustscan.py:58-176` (`code_mask`) is a Rust lexer covering nested block comments, `r#"…"#`/`br`/`cr` raw strings, escaped strings, and the char-literal-vs-lifetime ambiguity; `:317-344` (`predicate_keys`) blanks string values and extracts keys at any nesting depth; `:419-453` (`_eval_test_only`) evaluates `not`/`all`/`any` structurally, so `cfg(any(test, unix))` is correctly *not* test-only. The gate is now self-tested by **G13** (`scripts/gate-selftest.py`), which invokes the real `scripts/ci-gates.sh` over temporary fixture trees and asserts the process exit code — including must-fail adversarial rewrites (comment moved, test module renamed, attribute reformatted across lines, predicate split one key per line and nested three deep, fully qualified paths, re-exported aliases, associated-function import used bare, a minting call in a nested production module) and four must-pass cases in the other direction (a local variable named `target_os`, a parameter named `windows`, a field named `target_arch`, a block comment describing a platform predicate). Introduced by commit `7bf9da8`. **Evidence:** 60+ self-test cases across `G2D_CASES`, `G3_CASES`, `DRIFT_CASES`, `G2D_TRANSFORMS`, `G3_TRANSFORMS`, `G3_LEGITIMATE_TRANSFORMS`. **Not fully closed, recorded here rather than hidden:** the platform-API half of G3 still matches paths *literally* (`rustscan.py:387-400`), so importing the path once under an alias defeats it — `use std::env::consts as host; … host::OS` and `use std::os; … os::unix::fs::PermissionsExt` both pass G3 today. G3 also does not scan `include!`d or `OUT_DIR`-generated files, and exempts every crate whose path matches `orxnud-platform-*` (`gate_policy.py:410,418`) and all code outside `crates/` (`production_sources`, `gate_policy.py:52-57`). **Reconciliation note:** this row previously read `*(undefined)*` and asserted that no definition of V-96 existed in `docs/`, the commit history, or the tree. That was incorrect; the definition is `08-testing-engineering-standards.md` (row `cfg(target_os)` gate) and the implementation is `7bf9da8`. The row was rewritten from recovered evidence on 2026-10-10. **Status is `partially fixed`, not `fixed`,** because the aliasing bypass above is open. |
| **V-97** | **Two identity defects let one execution identity produce two governed proposals, and let an unresolved side effect be invisible to recovery** | (1) `task_proposals` carried no uniqueness on the execution identity — only the surrogate `proposal_id`, minted as `p-{task_id}-{milliseconds}` — so two proposals for one identity could exist and an approval would then choose between work that should have been one. (2) `execute_proposal` reserves the effect *before* dispatching, because a record made afterwards cannot describe a crash; but a `dispatch()` that returned `Err` left that reservation behind, and no row in the table exposed it, so recovery could not see an effect that might already exist. | **fixed** | 2026-10-08 | (1) A unique key on the execution identity, kept distinct from the existing approval-consumption key so the two produce two *different* refusals rather than colliding — the two-unique-keys case is itself a test. A retry of the same step on a new attempt is still representable; concurrent proposals for one identity produce exactly one winner; equivalent pre-existing duplicates reconcile to one and are recorded, while conflicting ones stop the migration without touching anything; distinct identities are never conflicts. (2) No row in any state table hides an unresolved effect from recovery: re-proposal cannot release the lease under an unresolved effect, recovery settles an interrupted execution the worker could not re-propose, a resolved effect is no longer what refuses the next proposal, and a stale row from an earlier attempt does not block the retry. **Evidence:** `crates/orxnud-task/tests/v97_proposal_identity.rs` and `crates/orxnud-task/tests/v97_effect_visibility.rs`. Migration 12 preserves approval-consumption state across the change. |
| **V-89** | **Every expected refusal on every task route was reported as `INTERNAL_ERROR` or as `INVALID_REQUEST`, so a client could only string-match English to work out what had happened** | Four independent breaks in one chain. (1) `From<TaskRepoError> for EngineError` collapsed `NotFound`, `NoSuchProposal`, `AlreadyExists`, `ProposalNotInState` and `InvalidComposition` into `EngineErrorKind::InvalidInput`, discarding the store's distinctions at the crate boundary. (2) `TaskService` turned an `EngineError` into `TaskFault::Engine(String)`, dropping the kind, so `task_fault()` had nothing to classify with. (3) `task_fault()` mapped `TaskFault::Engine` *and* `TaskFault::Stopped` to `RequestError::Refused`, which maps to `INTERNAL_ERROR`. (4) Separately, all ~26 direct `RequestError::Declined` sites mapped to `INVALID_REQUEST`, conflating absent / taken / unauthorised / unconfigured, and `RequestError::Invalid` put prose in the machine-readable `data.reason`. Reproduced against a real daemon over a real socket: a wrong-state `task/propose` answered `-32603` / `reason: "internal"`, and a missing provider the same — pointing the reader at a bug report when the remedy was `doctor` or `configure`. A fifth defect surfaced during the fix: `TaskRepository::propose_action()` read the schema-nullable `lease_holder` as `String`, so for any task holding no lease the read failed `Invalid column type Null at index: 1` and the state check beneath it never ran — silently converting a conflict into a storage failure. It survived because every existing test proposed while holding a lease, where the column is non-null: the suite's *shape*, not its assertions, was the reason. | **fixed** | 2026-10-06 | Introduces `TaskCause` (store → engine), `TaskFault::Engine { cause, detail }` (engine → service) and `RequestError::{NotFound, Conflict, Forbidden, Unavailable, InvalidInput}`, mapping to four codes in the server-reserved band: `-32040` not found, `-32041` conflict, `-32042` forbidden, `-32043` environment unavailable. The property asserted is one sentence — **INTERNAL_ERROR means nothing the caller did can change the outcome** — and `task_fault()` has no fallback arm that dumps an unrecognised fault there, so an unclassifiable path now fails the tests rather than the reader's log. Codes are grouped by *recovery*, so all wrong-state refusals share `-32041` and the actionable distinctions travel in `data.reason`, which is now always a stable word with the sentence in `data.detail` (and `None` where the reason already is the refusal). `ClaimRefusal` is the case that makes this load-bearing: coarse `not-claimable` versus specific `not-found`, same code, different recovery. **Evidence:** `crates/orxnud-daemon/tests/taxonomy.rs`, 10 tests over a real socket — each class, the reason-word shape, redaction, a claim race and an approval race. Each defect reproduced against the real store before any edit; the full before/after table is in ADR-0050. **Mutation-checked: 11 of 13 mutations fail at least one test** -- every reachable `TaskCause` → class mapping, the `ProviderRefused` code, the `Stopped` mapping, the specific-claim-reason, the reason/detail split, and both halves of the `lease_holder` fix (the nullability *and* the comparison). **Two mutations are not caught, and the reason is worth more than the count:** `TaskRepoError::{NotFound, NoSuchProposal}` and `AlreadyExists` reach `TaskCause` **zero times across the whole workspace suite**, measured with an instrumented `From` rather than assumed -- every route that could observe them checks existence first and answers `RESOURCE_NOT_FOUND` or `CONFLICT` directly. They are kept because a `From` impl should be total and correct, and the same measurement is why `TaskCause::NotFound` is pinned by a unit test rather than a socket test. Recorded as unobserved rather than omitted. **Boundary, pinned:** `task/continue` and `task/ai-propose` check for a provider before they look at the task, so a providerless daemon answers `ENVIRONMENT_UNAVAILABLE` even for a task that does not exist — deliberate, since the dependency is missing either way and the alternative would imply the task exists. **Not claimed:** no task-state, approval, continuation, observation, disclosure, authorization, sandbox or provider semantics changed, successes are byte-identical, and no new dependency, cross-crate error enum, or string matching on error text was introduced; `no_refusal_carries_content_a_host_path_or_a_credential` checks that no SQL text, host path, credential or content reaches a refusal. The `propose_action` nullability fix is a **defect fix in its own right** and would have been worth doing alone. |
