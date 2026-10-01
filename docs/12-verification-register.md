# 12 — Verification Register & Freshness Policy

Status: **Draft v0.1** · Adopted 2026-09-30 in response to review.

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
| **V-25** | **Core-only idle RSS < 60 MB; core-only binary < 40 MB; core-only cold start < 150 ms** | **No external source. Measured by our own benchmark harness.** | **milestone:** CI on every commit; re-baseline per release | *target, unmeasured* | **High.** These are the budgets that make the lightweight promise honest. A regression is invisible without measurement. |
| **V-30** | **`synchronous = FULL` costs ~8–14× `NORMAL` per commit on this machine: ~2.3 ms vs ~0.2 ms** | `crates/orxnud-task/tests/measurements.rs::insertion_throughput_with_synchronous_full_is_usable`, on btrfs-over-LUKS, Rust 1.98.1, SQLite 3.53.2 bundled | **milestone:** re-measure per release; **event:** a storage or filesystem change | 2026-09-30 | **High.** This settles **Q-OPEN-17**. The ratio varies run to run (7.3×–14.3× observed over four runs) because the `NORMAL` baseline is small and disk-scheduling-noisy, so the **magnitude** (~2.3 ms) is the reliable figure and the ratio is a range, not a number. FULL is affordable for a personal daemon at roughly 430 state transitions/second, which is far above what one user generates — but it is *not* affordable as a default for anything batch. Measured on an encrypted btrfs volume, which is a pessimistic case; an SSD without encryption would be materially faster. The transition-latency budget in docs-05 is < 5 ms and a fenced commit measures 2.2–3.4 ms, so the headroom is roughly 30–55% and not comfortable. See V-35. **Default stays FULL** (ADR-0006 invariant 1). The `NORMAL` mode exists and is tested, and choosing it requires an ADR, because ADR-0008's revisit condition says *"demote the cheapest-to-lose region, never weaken the task table."* |
| **V-31** | **Durability cannot be measured on tmpfs: `fsync` is a no-op there** | `/tmp` is `tmpfs` on this host; measured `fsync`-only cost 3 µs vs ~2.3 ms on btrfs. `measurements.rs` first reported FULL and NORMAL as **1.0× identical** | `fs.stat -f -c %T`, `/proc/mounts`, and the ratio in the same test | **release:** any harness that measures durability must assert its filesystem | 2026-09-30 | **High.** This is the failure mode where a measurement *confirms the wrong thing*: on tmpfs the harness would have "shown" that `synchronous = FULL` is free, which is the opposite of the truth. `measurements.rs` now refuses to run on a memory-backed filesystem and names `ORXNUD_MEASURE_DIR` as the override. Any future durability benchmark must do the same. |
| **V-32** | **The Phase 2 engine passes all twelve ADR-0029 properties against the *unmodified* Phase 1 harness** | `cargo test -p orxnud-task --test conformance_production`; `crates/orxnud-task/tests/conformance_production.rs` calls the same `run_suite` the trivial fixture uses | **milestone:** every change to `conformance::properties` or `conformance::schedule` | 2026-09-30 | **Critical.** ADR-0029's whole claim is that the contract is implementation-independent. Verified by: the harness was not edited; the suite is called from a second test binary with a different engine; and a deliberately broken engine is asserted to produce a *non-clean* report, so the suite is known to have teeth against this engine rather than merely agreeing with it. |

| **V-33** | **A fresh install could not start; only production wiring found it** | `orxnud-daemon/src/task_service.rs::open` was the first caller of `MigrationRunner::migrate`; `Backup::verify` rejected the snapshot of an unmigrated database | `orxnud-store/src/migration.rs::migrating_a_brand_new_database_succeeds`, and `Backup::verify_against_source` | **release:** any change to the migration or backup entry point | 2026-09-30 | **High.** Every Phase 2 migration test drove `MigrationRunner::run`, which trusts its caller's snapshot claim and never takes one — so the snapshot path had no coverage until startup used it. It failed on a brand-new database: `Backup::verify` rejected a snapshot with no `schema_meta`, on the sound grounds that restoring it would erase a user's data, which is the wrong target when there is no data yet. The first migration could not run, so the daemon could not start on any machine where OpenRayNux had never run. Emptyness is now judged relative to the source. The lesson recorded for its own sake: **a helper used only by production code has no test coverage until production calls it.** |
| **V-34** | **The "verified snapshot has data" guard was documentation, not code** | `Backup::verify` computed `total_rows` and returned it; nothing compared it. `BackupError::Empty` now refuses a snapshot whose `schema_meta` exists but is empty | `orxnud-store/src/backup.rs`, `an_emptied_snapshot_of_a_real_database_is_still_rejected` | **release:** any change to snapshot verification | 2026-09-30 | **High.** The comment claimed "a row count, so *verified* means *has the data we expected*" — and the code did not do it. Found while fixing V-33, in the same function, because the fresh-install fix made the emptiness question unavoidable. Two guards, both now enforced and both tested in both directions: absent `schema_meta` is refused, and present-but-empty is refused, while an empty snapshot of an equally empty source is accepted. |
| **V-35** | **`synchronous = FULL` costs ~2.3 ms per state transition, consuming 45–70% of the < 5 ms budget** | Re-measure per release; the headroom is thin enough that a slower disk makes the budget the binding constraint | `crates/orxnud-task/tests/measurements.rs` | **milestone:** if a transition p99 exceeds 5 ms, this is the first thing to re-examine — and ADR-0008 requires the decision to demote a cheaper region rather than weaken the task table | 2026-09-30 | **High.** See V-30 for the measurement. Recorded separately because the *risk* is distinct from the *number*: A fenced commit measures 2.2–3.4 ms across runs, so the budget is not generous, so this belongs on the re-measure list rather than being considered settled. |

| **V-36** | **`CapabilityInvocation` was forgeable from JSON; the type-level policy boundary did not hold** | `orxnud-domain/tests/compile_fail/invocation_cannot_be_deserialised.rs` (with recorded `.stderr`), plus the standalone-crate proof in ADR-0034 | **release:** any change to `orxnud-domain`'s serde derives on authority-bearing types | 2026-09-30 | **Critical.** The type derived both `Serialize` and `Deserialize` with private fields, and a derived `Deserialize` writes private fields without a constructor — so `PolicySeal`, `AuthorisationProof`, and policy evaluation were all bypassed. Demonstrated, not theorised: a crate outside the workspace built an invocation from a JSON literal and printed `FORGED OK ... risk=Low policy_version=forged` with no policy and no human. ADR-0012's claim that this "is not *possible*" was false, and ADR-0034 corrects it. Found by asking what each dispatcher stage would do to a forged value **before** writing the dispatcher — stage 6 (credential resolution) would have handed real credentials to a fabricated `Human` actor. Fixed by removing the derive and introducing `CapabilityRequest` as the only capability-shaped type that accepts external data. Verified with teeth: re-adding `Deserialize` fails the compile-fail test. |
| **V-37** | **A derived `Deserialize` is a constructor, and private fields do not make it an authority boundary** | `serde` docs: `Deserialize` is a mechanism for constructing a value from external data. `CapabilityRequest` *does* derive it, deliberately | review any serde derive on a type carrying authority, risk assessment, policy version, approval digest, or credential handle | 2026-09-30 | **High.** The generalisable rule, recorded because V-36 will recur in another form. The asymmetry is the point: `Serialize` on an authority-bearing type is a disclosure risk a caller must consciously own (audit, hashing); `Deserialize` is an authorisation bypass no caller should be able to perform. Enforced by the same compile-fail mechanism, and by the structural rule that ingress converges on `CapabilityRequest` — one untrusted representation, one authorisation pipeline. Also: authority-bearing types must not be persistence types either, or the storage layer restores the same confusion. |

| **V-38** | **`Serialize` on `CapabilityInvocation` is retained under review, not declared permanently safe** | `orxnud-domain/src/invocation.rs`; ADR-0034 | **review trigger:** any new use of serialising an invocation — a wire type, an event payload, a log line, an MCP payload, or a persistence DTO | 2026-09-30 | **Medium.** `Serialize` cannot *forge* authority, but it can *expose* authority-bearing metadata (actor, policy version, approval digest, task) across a boundary that the type was not meant to cross. Asymmetric with `Deserialize`, which was removed outright (V-36): serialising authority **out** is a disclosure risk a caller must consciously own, deserialising it **in** is an authorisation bypass nobody should be able to perform. Not changed now, because the current code has no actual unsafe serialization path — the only consumer is the audit chain's canonical hashing, which is intentional. Recorded as a review invariant rather than a fix. Permitted uses: audit representation, canonical hashing, diagnostics explicitly designed to expose it. Forbidden: JSON-RPC DTO, generic event payload, log serialization, MCP payload, untrusted message, persistence DTO. If the projection discipline turns out to need policing at more than one call site, the likely end state is a dedicated `InvocationView` / `InvocationDigestInput` projection rather than relying on every future caller to pick the right one of two derives. |

| **V-27** | **`cargo-deny` 0.20 removed `[licenses] deny`** — the copyleft prohibition is now expressed by the *absence* of copyleft from `[licenses] allow` | `cargo deny check licenses` on this tree; the tool's own error output (`error[deprecated]`) | **release:** re-read the tool's config schema | 2026-09-30 | **Medium.** ADR-0006/ADR-0019 forbid GPL/AGPL/NC. If a future `deny.toml` reintroduces a `deny` key, cargo-deny will *error* rather than silently ignore it — the failure is loud, but only if someone reads it. `scripts/ci-gates.sh` G8 fails on any cargo-deny error. |
| **V-28** | **The twelve Phase 1 gates actually pass on this tree** | `scripts/ci-gates.sh` (exit 0), run locally against Rust 1.98.1 | **milestone:** every commit in CI; **event:** a toolchain or dependency bump | 2026-09-30 | **High.** The gates are the Phase 1 deliverable (docs-13 §5). A gate that silently stops running is worse than a gate that fails, so G12 skips loudly when no release tag exists rather than passing vacuously. |
| **V-29** | **The Windows check is blocked on this host by a missing MSVC C toolchain, not by a code defect** | `cargo check -p orxnud-store --target x86_64-pc-windows-msvc` → `cc-rs: failed to find tool "lib.exe"` | **release:** the Windows nightly lane reports the result | 2026-09-30 | **Scope.** This is a *verification* item, not an implementation gap: Phase 2's storage and engine layers are platform-independent, and the platform boundary is enforced by gate G3 rather than by a successful Windows build. Recorded as `Windows verification: OPEN`, never as a Phase 2 failure. | **Medium.** 7 of 14 crates — including all three platform adapters, `orxnud-domain`, `orxnud-protocol`, `orxnud-config`, `orxnud-obs`, `orxnuctl` — check clean for MSVC today. The other 7 are blocked transitively by `libsqlite3-sys` and `blake3`, which need `cl.exe`/`lib.exe`. **No Rust-level error was observed for any crate.** The Windows claim is therefore *unverified*, not *failing*; it is a Phase 1 exit criterion (docs-13 §9) and stays open until the nightly runner reports. |

| **V-26** | **`libxdo.pc` on Fedora declares `/usr/local` prefixes that are wrong** | `/usr/lib64/pkgconfig/libxdo.pc` | **event:** a Fedora packaging change | 2026-09-30 | **Low.** Cosmetic; we do not feed its cflags to a compiler. |

---

## 2a. Amendments

Recorded per operating rule 5: wrongness is worth recording, because it is how
this register improves.

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
