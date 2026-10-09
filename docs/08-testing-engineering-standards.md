# 08 — Testing & Engineering Standards

Status: **Draft v0.5** · Reconciled **2026-10-09** against `HEAD` (`c5934970`). All five CI
lanes green; one known intermittent failure under load in `v95_concurrency` — see
[`README.md`](README.md) §8.

**This document previously described a CI that does not exist.** Four items in its gate
list had no gate behind them, and its platform-lane list named runners that are not
configured. Both are corrected below. The rule applied throughout: *do not call something
"enforced in CI" unless a gate or a workflow step actually runs it.* A documented
enforcement that does not exist is worse than an admitted gap, because it is the failure
V-79 records — a control asserted as test-backed with nothing behind it.

---

## Part I — Testing strategy

## 1. The problem with testing an AI system

An OpenRayNux test suite has to answer two different questions:

1. **Are the deterministic parts correct?** — fully decidable. Proptest, model
   checking, crash injection, golden tests.
2. **Is the probabilistic part useful?** — not decidable by assertion. "Did the
   intent classifier pick the right intent?" has no stable ground truth, and
   asserting on model output produces a suite that fails on model updates and
   passes on a bad model.

**The resolution:** the probabilistic layer is tested by *contract and
distribution*, never by exact-output assertion. And critically — **most of the
system is deterministic**, so most of the system is tested normally. That is a
direct benefit of the determinism boundary in `00-…` §6.

---

## 2. The pyramid

| Layer | Share | What | Determinism |
|---|---|---|---|
| **Unit** | ~60 % | Pure domain logic, validators, state machine, schema, policy evaluation, redaction | 100 % |
| **Property** | ~15 % | `proptest` over parsers, state machines, policy, migrations, idempotency | 100 % |
| **Contract** | ~10 % | Every capability against the shared contract suite; every LLM provider against the abstraction | 100 % (mocked) — **note:** 3 capabilities ship, and points 4 and 6 of the contract remain `declared_only` **by decision**, because the contract harness is in-process and cannot observe a namespace (V-40). The real isolation evidence is in `tests/isolation.rs`. |
| **Integration** | ~10 % | Real SQLite (temp files), real IPC, real subprocesses, real scheduler | 100 % — **note:** the real-subprocess suites need a host that can sandbox; see §19. |
| **Failure injection** | ~3 % | Kill, timeouts, malformed output, partial writes, provider outages | 100 % |
| **E2E** | ~2 % | Scripted user journeys across the daemon and one interface | Mostly |
| **AI evaluation** | separate track | Offline dataset + distribution metrics, run on demand, **not** in the blocking CI gate | N/A |

The proportions are a target, not a rule. The invariant that matters: **the
blocking CI gate is 100 % deterministic.** A test that requires a live model or
network does not block a merge.

---

## 3. Deterministic AI testing

### 3.1 Provider simulation (mandatory)

A **scripted, replayable provider** implementing the same `ModelProvider` trait:

- Returns recorded responses for recorded requests.
- Can inject: malformed JSON, schema-valid-but-nonsense content, refusals,
  tool calls with wrong argument types, multi-step plans, empty responses,
  truncated streams, and timeouts.
- Records every request for assertion: "did we send the right schema?", "did we
  redact before sending?"

This is what makes LLM-dependent code testable at all. A test that needs an API
key is a test that will not run.

### 3.2 The AI evaluation track (separate, non-blocking)

- A **golden dataset**: real utterances → expected intent class, expected
  required capabilities, expected `should_not_include` properties.
- **Metrics**, not assertions: intent accuracy, per-class precision/recall,
  capability-selection accuracy, plan-step precision, refusal rate on
  out-of-scope inputs, **false-approval rate** (the metric that matters most).
- Run on a schedule and on demand; compared against the previous run. A regression
  is a signal, not a build failure.
- The **false-approval rate** is the headline number: a system that is
  *appropriately* refusing is safe; a system that is confidently wrong about
  permissions is not.

### 3.3 Determinism for the probabilistic layer itself

Three techniques make probabilistic behaviour testable:

1. **Seeded sampling.** Where a model call only decides *presentation*, allow a
   seeded deterministic mode. Never for anything safety-relevant.
2. **Recorded-transcript replay.** Full end-to-end replay of a session from the
   event log, with a scripted provider.
3. **Assertion on *invariants*, not content.** "The proposal's `steps` only
   reference registered capabilities", "no step has risk above HIGH without a
   gate", "the proposal does not contain a credential path". These hold for
   *all* model outputs and are the assertions that matter.

---

## 4. Test layers in detail

### 4.1 Unit

- Domain invariants, state machine transitions (legal/illegal), config merge
  semantics, schema validation, redaction patterns, budget arithmetic,
  DST/cron edge cases, approval-digest computation and mismatch detection.

### 4.2 Property-based (`proptest`)

| Property | Why property testing, not examples |
|---|---|
| Policy evaluation never widens a grant | Monotone, hard to enumerate |
| State machine: no illegal transition reachable | Exhaustive by construction |
| Parser round-trip: `parse(encode(x)) == x` for all valid `x` | Finds the weird inputs |
| Redaction removes all secrets, keeps non-secrets | Secret shapes are unbounded |
| Migration: schema N → N+1 → N is lossless; N → N+2 is valid | Migrations are the riskiest code |
| Idempotency: replaying a step N times == once | Timing and crash interleavings |
| Config layering is deterministic regardless of file order | Merge bugs are order bugs |
| Approval digest detects any single-parameter mutation | Security-critical, combinatorial |
| Task table survives arbitrary kill points | The crash test as a property |
| No `%` in SQL strings (compile-time or lint assertion) | Injection surface |

### 4.3 Contract (per capability, mandatory — `07-…` §8)

The ten-point suite listed there. It runs for **every** implementation of every
capability, which is the mechanism that makes substitutability real.

### 4.4 Integration

- **Real SQLite on real temp files.** Never `:memory:` for anything touching
  durability. A memory DB cannot test WAL, `synchronous=FULL`, crash recovery,
  or migration on an existing file.
- **Real IPC.** The daemon over a real socket, a real client.
- **Real subprocesses.** Tier 1 adapters over real stdio, including the
  kill-and-recover path.
- **Real scheduler.** Including DST transitions and machine-off catch-up.
- **Real migrations** on a copy of a previous-version database.

### 4.5 Task-engine correctness properties (ADR-0029) — normative

These are the contract for the task engine, independent of implementation. A
future engine (e.g. `apalis`) is substitutable **iff** it passes this suite.

| ID | Property | Test that proves it |
|----|----------|---------------------|
| TP-1 | No task silently disappears | Kill-at-N-random-points; every task reaches a terminal or provably-owned state |
| TP-2 | Exactly-once where required, at-least-once otherwise | Per-capability injected outcomes; `idempotent: false` + uncertain outcome ⇒ `needs_verification`, never auto-retry |
| TP-3 | Cancellation is observable | Cancel is durably recorded *before* it is acted on; survives restart; bounded latency per capability |
| TP-4 | Restart recovers durable work | No task left `running` with a dead owner after unclean shutdown |
| TP-5 | **Expired leases cannot execute** | **Zombie-worker test:** force lease expiry, then let the original worker attempt to commit. It **must fail** (fence re-validated at commit, not just at claim) |
| TP-6 | Retries never inherit approvals | Retry after approval expiry is refused by policy; actor re-derived, delegation re-checked |
| TP-7 | Power loss cannot corrupt task state | Kill-at-random-points; state is pre- or post-transaction, never torn (WAL + `synchronous=FULL`) |
| TP-8 | Scheduling deterministic under time manipulation | Property tests over DST transitions and forward/backward clock jumps |
| TP-9 | Catch-up bounded and explicit | A week offline does not execute a week of backlog; `catch_up_cap` and misfire policy honoured; collapsed runs flagged |
| TP-10 | Bounded resources | Every spawn has a concurrency limit; a wedged task is killed at its deadline |
| TP-11 | Dead-lettering terminal and visible | A permanently failing task dead-letters, surfaces, and stops |
| TP-12 | Every side effect is accounted for | No effect can occur without a recorded result or an explicit "outcome unknown" state |

**Master property across all of them:** *no failure injection ever produces
silent data loss or an unauthorised side effect.*

### 4.6 Failure injection

| Injected failure | Expected behaviour |
|---|---|
| `kill -9` at each of N random points during a task | No lost, duplicated, or orphaned task; non-idempotent steps marked `needs_verification` |
| Model returns malformed JSON | Rejected cleanly; task fails with a clear error; no partial effect |
| Model returns a `refusal` | Handled as a distinct outcome, not as malformed output |
| Model returns a tool call with wrong arg types | Rejected before dispatch |
| Model requests an unregistered capability | Rejected; recorded as an attempt |
| Policy evaluation throws | **Fail closed.** Deny |
| Audit write fails | **Fail closed.** Deny |
| Adapter segfaults | Daemon survives; task recoverable; adapter quarantined after N |
| Adapter hangs | Deadline kills it; backoff; quarantine |
| Provider returns 429 | Respect `Retry-After`; no hot loop |
| Provider 5xx for an hour | Circuit breaker opens; user notified; not silent |
| Disk full | Graceful degradation; no partial state |
| Clock jumps backwards/forwards | Scheduler stays correct |
| Migration fails midway | Rollback; previous binary works |
| SQLite WAL corrupted | Detected; restore from backup |
| Approval tampered with | Digest mismatch; abort |

**Property:** *no failure injection ever produces a silent data loss or an
unauthorised side effect.* That single property is the most valuable test in the
suite.

### 4.7 Concurrency

- Task claim under N concurrent workers → exactly one winner.
- No deadlock between the DB thread, the policy engine, and adapters.
- Cancellation is prompt and complete (bounded latency).
- Bounded concurrency actually bounds: a runaway task cannot exhaust memory.
- `tokio::task` leak detection over a long soak.

### 4.8 Security tests (in CI, not optional)

- **S1 verification:** the intent-layer context **cannot** resolve a secret.
- **S33 / ADR-0027 authority:** an `External` actor cannot grant; an expired
  delegation is refused; an approval bound to one actor is rejected for another.
- Prompt-injection corpus → assert no unauthorised side effect ever occurs.
- SSRF: every outbound request's destination is checked against the grant.
- Path traversal in any capability that accepts a path.
- Command injection: metacharacters in every user-controlled parameter.
- Deserialisation bombs: depth and size limits enforced.
- Redaction: secrets never appear in logs, traces, or error messages.
- Audit chain: tampering is detectable.
- Approval digest: any parameter mutation invalidates it.
- Sandbox: an adapter attempting an undeclared path or host is blocked.

---

### 4.9 Mutation testing (normative)

A green test proves nothing about the code it does not exercise. Deliberately breaking
the mechanism and observing the intended test fail is the only direct evidence that the
test has teeth.

#### 4.9.1 A mutation must be shown to have applied

Four checks, in order. Failing any of them means the mutation is not evidence:

| # | Check | Why |
|---|-------|-----|
| 1 | The source edit **applies** — the pattern matched | A pattern that does not match silently changes nothing |
| 2 | The resulting file **differs** from the baseline | Guards against 1 being fooled by a no-op write |
| 3 | The **behaviour** changes in the expected direction | Distinguishes a real mutation from an unrelated one |
| 4 | The **intended** test fails, and for the expected reason | A failure anywhere is not evidence for this mutation |

Check 1 is not theoretical. During V-46 a mutation "passed" because its replacement
string did not exist in the file (`ResourceControl::Memory` versus `Self::Memory`), so
nothing was mutated and the suite stayed green. It was briefly reported as a successful
mutation. Checks 1 and 2 exist because of that.

#### 4.9.2 A mutation test must remain safe when the mutation removes the control

**This is the hard rule, and it is normative.**

> Removing a safety control to prove the test detects its absence must not turn the test
> workload into a hazard when the control is gone.

The reasoning is structural, not incidental. An adversarial workload is only safe to run
when the thing under test is what bounds it — and a mutation that removes the bound is
precisely the case where that assumption is false. The workload then runs against
whatever remains, which on a shared machine is the host.

During V-46, `mem_hog` allocated until the allocator refused, on the reasoning that
`memory.max` would always stop it first. Two mutations that removed the cgroup turned it
into a whole-machine allocation and drove the host into swap exhaustion, freezing the
machine twice.

The consequences are now requirements, not advice:

- **Every adversarial fixture bounds itself.** `mem_hog` caps at a fixed, small budget and
  retains its pages, so running it unenforced costs a bounded amount of memory. The
  enforcement evidence is unchanged, because a ceiling well below the cap still stops it.
- **Enforcement evidence must not depend on the workload being stopped by the control.**
  The governed test asserts the workload could not retain what it requested, using
  `memory.max` and `memory.current`. `memory.events` counters are reported, not required:
  reading them from a watcher thread is a sampling race, and pinning
  `memory.swap.max = 0` makes the kernel OOM-kill rather than reclaim, so `max` reads 0
  for a correctly enforced ceiling.
- **Do not require a specific signal or exit code.** `memory.max` is entitled to refuse,
  reclaim, or OOM-kill. A test that demands one particular mechanism is testing the
  mechanism, not the property.
- **A fixture must not be runnable into an unbounded state by accident.** If a helper can
  only be exercised safely through the governed path, it is not to be invoked directly
  outside it.
- **Interrupt safety.** A mutation experiment must be able to restore its baseline from
  something other than memory. Verify the restore by diffing against a saved copy, and
  never by the suite being green. A timed-out experiment once left a mutation live in
  production code and leaked workers.

#### 4.9.3 Redundant mechanisms are not isolated by mutation

Where two mechanisms provide the same property, removing one may change nothing
observable. That is a finding about the architecture, not a defect in the test, and the
correct response is to record it rather than to contrive a scenario that separates them.

During V-46, removing the runner's `cgroup.kill` on timeout left the suite green, because
`bwrap --unshare-pid --die-with-parent` already tears the PID namespace down when the
supervisor dies. The two mechanisms are redundant under this execution model (ADR-0036).
The teeth of `cgroup.kill` are real and are proven where they *are* distinguishable — in
the direct mechanism suite, which has no PID namespace — and the governed-path claim is
recorded as redundant rather than artificially isolated.

---

## 5. Test data & fixtures

- **No production data in tests.** Synthetic fixtures with realistic *shapes*.
- **No real credentials, ever.** A `.env` with real keys must be structurally
  impossible to commit (CI grep + pre-commit hook).
- **Deterministic time.** A `Clock` trait so DST and time-travel tests are exact.
- **Deterministic IDs.** A seeded ID generator, so golden tests are stable.
- **Golden files** for provider request/response pairs, versioned, with a
  documented regeneration procedure (never "just re-record" without review).

---

## 6. CI gates

**Blocking:**

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo nextest run` (parallel; faster than `cargo test`)
### Actually enforced — every item below is a real gate or a real workflow step

Gates are `scripts/ci-gates.sh` G1–G12, run on every push and every PR, and re-runnable
locally. Was verified against run `37343986458` (all green); see the pinned-inputs section
below for the current CI state on `main`.

| Gate | What it runs |
|---|---|
| G1 | `cargo fmt --check` |
| G2 | dependency-graph direction, incl. the CLI's permitted-crate rule (G2(b)) |
| G3 | `cfg(target_os)` / `cfg(windows)` / `env::consts::OS` grep outside `orxnud-platform-*` |
| G4 | zero `unsafe` outside `orxnud-platform-*` |
| G5 | `cargo check -p orxnud-domain -p orxnud-protocol --target wasm32-unknown-unknown` |
| G6 | `cargo clippy -D warnings` |
| G7 | workspace member list matches the declared crate graph |
| G8 | `cargo deny` — licences and supply chain |
| G9 | `cargo nextest run --workspace` |
| G10 | secret hygiene greps — no PEM key, no token pattern, no committed `.env` |
| G11 | `cargo audit` |
| G12 | `cargo semver-checks` — **skips with a loud message when no release tag exists** |

Plus, in `.github/workflows/ci.yml`: `cargo doc --workspace --no-deps` with
`RUSTDOCFLAGS: -D warnings`; a `windows-check` lane (`cargo check --workspace
--all-targets` on `windows-2025`, on every push and PR as well as nightly); a `windows-portability` lane running the
platform-neutral suites as tests; a `portable-core` wasm32 lane; a `sandbox-integration`
lane; and a preflight step that prints the runner's measured sandbox capability.

Property tests **do** run (`proptest` in `orxnud-policy` and `orxnuctl`).

### Claimed here previously, and NOT enforced — corrections

| Was claimed | Reality |
|---|---|
| `cargo vet` | **Not a gate.** G1–G12 do not include it. |
| Feature-matrix resource regression check (CR-2) | **Does not exist.** No feature matrix in `ci-gates.sh` or the workflow, and no committed baseline file. The underlying budget is **unmeasured** (V-25). |
| Golden files for provider request/response pairs | **None exist.** The provider tests assert on the request body inline. |
| A hand-kept `CHANGELOG.md` | **No `CHANGELOG.md` exists.** |
| `cargo geiger` in CI, `unsafe` count tracked | **Not present.** The actual control is gate **G4**, a grep. |
| Licence scan of model manifests | **No models ship**, so there is nothing to scan. |
| Migrations up and down on a copy of a real previous DB | Partially true: `orxnud-store` tests migration and rollback, and the conformance suite runs `synchronous = FULL` durability cases. Not a gate in the form stated. |
| Cross-compile check for the portable core | **True** — gate G5 plus the `portable-core` job. |
| `cfg(target_os)` gate | **True** — gate G3. Two blind spots, both now closed. **V-29:** it grepped for `cfg` rather than a platform *API*, so unguarded `std::os::unix` passed it and broke MSVC; G3 now detects `std::os::{unix,windows}` paths directly. **V-96:** it matched raw text, so a comment could switch it off and seven of nine `cfg` spellings -- every nested one -- were invisible; G3 now classifies source lexically and reads predicates at any depth. Self-tested against fixtures by gate G13. |

**Non-blocking / scheduled — what is actually configured:** the AI evaluation track.
`windows-check` is **not** nightly-only: it carries no `if:` condition and no path filter, so
the workflow-level `pull_request:` trigger runs it on every PR as well as on the nightly cron.
*(Corrected 2026-10-08; this document previously called it nightly-only, and being wrong in
that direction is not harmless — it is why a real MSVC breakage, an integration test using
`std::os::unix` with no `cfg`, sat undetected until a pull request ran the lane for the
first time.)* **Not configured:** full soak, performance comparison reports,
fuzz targets, macOS, Linux aarch64, and any release pipeline with signature.

---

# Part II — Engineering standards

## 7. Module boundaries

1. **The core defines traits; adapters implement them.** Never the reverse.
2. **No module may reach past its neighbour.** Enforced by crate boundaries.
3. **Interfaces import protocol types only.** No domain types.
4. **A crate has one reason to change.** If you need "and" to describe it, split it.
5. **Policy is a choke point, not a layer.** One construction site for
   `CapabilityInvocation`.
6. **No circular crate dependencies.** Enforced structurally.

## 8. Dependency direction

Inward only, toward the core. Never sideways. Enforced by workspace layout,
reviewed in PRs, and by the `cfg(target_os)` gate for the platform boundary.

**New dependency rule:** a new direct dependency requires an ADR, a licence
check, a maintenance check (last release date, bus factor), and a written reason.
Transitive additions are reviewed via `cargo deny`.

## 9. Error handling

- **Errors are values, not panics.** `thiserror` for libraries, `anyhow` only at
  the top of a binary.
- **Every error carries a user-facing message** and a machine-readable code.
  "Something went wrong" is a bug.
- **Never swallow an error silently.** `let _ =` on a `Result` needs a comment
  explaining why it is safe.
- **Panics are for bugs only.** In a Tier 0 adapter, a panic is caught at the
  dispatch boundary and converted to a task failure — it must never take down
  the daemon.
- **No `unwrap()` / `expect()` outside tests** — enforced by clippy configuration
  and review.
- **Error chains are preserved** for diagnosis but **redacted** for display.

## 10. Ownership and lifetimes

- Prefer owned data at boundaries; borrow internally.
- No interior mutability in the core. If you need `Arc<Mutex<_>>`, you probably
  need a message-passing design instead.
- `Send + Sync` is a design constraint, checked at compile time, not asserted.
- Shared caches are bounded (`moka`) and evicting, never unbounded `HashMap`.
- No `static mut`. No interior `unsafe`. `unsafe` requires a written invariant
  plus a test; the default is to find a safe alternative.

## 11. Async boundaries

- **Async all the way down, or not at all.** No blocking calls in an async
  context — use `spawn_blocking` (rusqlite is synchronous by design).
- **Every long operation has a deadline and a `CancellationToken`.**
- **No unbounded fan-out.** Every spawn site has a concurrency limit.
- **Structured supervision.** Each task runs under a supervisor that restarts it
  with backoff and escalates after N. Tokio has no built-in supervision, so we
  build a small, explicit one.
- **The DB thread model is explicit and documented.** One writer, a bounded read
  pool, no surprises.
- **No `block_on` inside a runtime.** Ever.

## 12. Naming and API design

- `new` for constructors; `with_*` for builders; `try_*` for fallible; `_*_async`
  reserved for the few APIs that are genuinely async.
- Public items get doc comments with a `# Errors` section where relevant.
- Errors are enums, not strings, at library boundaries.
- Constructors take `impl Into<String>`-style arguments; getters return `&str`.
- Public APIs are `pub(crate)` by default and promoted deliberately.
- Semver is respected: pre-1.0 crates are `0.x` and may break; the **protocol**
  is versioned independently of the implementation.

## 13. Documentation

- Every public item: what it does, what it guarantees, what it does *not* do.
- `ADR` for every architectural decision.
- Module-level `//!` explaining *why the module exists*.
- **Decision-shaped comments** (`// SAFETY:`, `// INVARIANT:`, `// WHY NOT:`) for
  anything non-obvious. A comment explaining *what* is noise; *why* is essential.
- A `CHANGELOG.md` kept by hand, with a `[Unreleased]` section, following
  Keep a Changelog. Written for users, not generated from commits.

## 14. `unsafe` and FFI

- `unsafe` requires: a `// SAFETY:` comment proving the invariant, a test that
  exercises the invariant, and a second reviewer.
- FFI boundaries are isolated in dedicated modules with a safe wrapper. The rest
  of the codebase never sees a raw pointer.
- `cargo geiger` in CI; `unsafe` count is a tracked metric that must not grow
  without an ADR.
- Every FFI dependency's licence and maintenance is reviewed (this is how we
  caught the GPL/NC/AGPL landmines).

## 15. Feature flags

- Every optional capability is a Cargo feature. No runtime "enable/disable" via
  env var for compile-time-conditional code.
- Additive by default: a feature may only *add* behaviour. It may never change
  the meaning of existing code.
- Every feature has a test that builds with it on and off.
- CR-2 is enforced by a resource-delta test across the feature matrix.

## 16. Versioning and compatibility

- Follow semver strictly; `cargo semver-checks` in CI.
- **The wire protocol is versioned independently** and negotiated at runtime.
  Clients tolerate unknown methods and fields.
- **Config schema is versioned**, and migrations are one-way, tested, and
  reversible.
- **Capability contracts are versioned per capability.** A capability declares
  which contract versions it implements; the dispatcher adapts.
- **Data migrations are irreversible but snapshot-protected** (ADR-0017).
- **Deprecation policy:** announce → 2 minor releases → remove. Model it on MCP's
  own 12-month window, which is a good external reference.

## 17. Security advisories

- `cargo audit` blocks the build on a known advisory.
- `cargo deny` blocks unapproved licences, duplicate versions, and yanked crates.
- **Advisories are triaged within 48 h.** A critical RCE: patch or mitigate
  immediately, with a release. A low-severity informational item: document and
  defer with a reason.
- Dependabot/Renovate for version bumps, with the same gates.
- **Model and browser artefacts are checksum-pinned** (S23) and reverified on
  use.

## 18. Supply-chain security

- `Cargo.lock` committed; `--locked` in CI.
- **Reproducible release builds** with documented, pinned toolchain and target.
- SBOM generated per release.
- Release binaries are **signed** (minisign for Linux, Authenticode for Windows).
- Dependencies reviewed on addition, not just on alert.
- No build-time downloads from unpinned URLs. This is why
  `sherpa-onnx`'s "auto-download a prebuilt `-lib`" needs a pinned, checksummed
  mirror in our build.
- Minimal `.github/dependabot.yml` breadth — no auto-merge on anything touching
  auth, crypto, network, or serialisation.

## 19. CI — what is configured

Five jobs; all were green on run `37343986458` (2026-10-05). **Currently, on `main` at
`c5934970`, all five pass** — run `37919194011`, "all selected gates passed", nextest
1505/1505. One earlier run of the same commit (`37916621851`) failed at G9 on an intermittent
`v95_concurrency` `SQLITE_BUSY_SNAPSHOT`; see [`README.md`](README.md) §8.

| Job | Trigger | What it proves |
|---|---|---|
| `linux-gates` (G1–G11) | every push and PR | the twelve gates, over the host-applicable test scope |
| `windows-check` | every push and PR, plus nightly | all 16 crates compile for MSVC, all targets |
| `windows-portability` | every push and PR | the platform-neutral suites **run** on Windows, not merely compile |
| `portable-core` | every push and PR | the portable core builds for `wasm32-unknown-unknown` |
| `sandbox-integration` | every push and PR | measures whether a Tier-1 sandbox is possible here, and says so |

**Not configured**, contrary to what this section previously claimed: Linux aarch64,
macOS, any feature-combination matrix, and a signed release pipeline.

Caching is keyed on `Cargo.lock` and the toolchain. The scheduled lane is deliberately
off the hour (03:17 UTC), because scheduled runs cluster at `:00` and the queue is longer
than the work.

### The pinned CI inputs, and why every one of them

Adopted 2026-10-08. This repository's claims are evidence claims, and evidence is only
evidence if the thing that produced it can be identified afterwards. Four classes of input
to a CI run were floating; all four are now pinned.

| Input | Was | Now |
|---|---|---|
| `actions/checkout` | `@v4` | `@v7.0.1` — exact version at all five call sites |
| `Swatinem/rust-cache` | `@v2` | `@v2.9.2` |
| Linux runner | `ubuntu-latest` | `ubuntu-24.04` |
| Windows runner | `windows-latest` | `windows-2025` |
| `cargo-deny` | unpinned | `0.20.2` |
| `cargo-audit` | unpinned | `0.22.2` |
| `cargo-semver-checks` | unpinned | `0.51.0` |
| `cargo-nextest` | unpinned | `0.9.146` (see the note below) |

**A major tag is a moving pointer.** `rust-cache@v2` in particular does not reliably resolve
to the newest 2.x, so two runs a week apart can execute different action code under one
commit SHA.

**`--locked` was doing less than it appeared to.** It pins the *dependency graph* of
whichever release is installed; it does not pin *which* release gets installed. So
`cargo install cargo-deny --locked` means today's CI and tomorrow's CI can run different
cargo-deny under an unchanged commit. That drift was not hypothetical: two of the four tools
whose latest release had moved past what the reference machine had installed were
`cargo-semver-checks 0.50.0 → 0.51.0` and `cargo-nextest 0.9.146 → 0.9.148`, so an unpinned
run would have silently upgraded the very gates producing the evidence. (The nextest drift is
historical: the installed pin settled at 0.9.146 for the manifest reason given below.)

**The pins are installed from prebuilt binaries, not compiled.** Pinning by
`cargo install <tool> --version X --locked` compiles each tool from source on a cold hosted
runner, before any project test can run. That made `linux-gates` unreliable in a specific
and misleading way: the job declared `timeout-minutes: 15` and was killed inside G9 having
produced **zero** test results, three runs in a row. A cancelled lane reports nothing at all
about the code, and beside four green lanes it reads as though five things were verified.

`taiki-e/install-action` fetches upstream release binaries instead, pinned to a full commit
SHA (`f7e5d7c9…`, release 2.87.26) rather than a major tag, with `fallback: none` on every
step so a source build is impossible rather than merely unlikely. The `linux-gates` timeout
was raised to 30 minutes as headroom — explicitly the second line, not the fix.

**`cargo-nextest` is pinned to 0.9.146, and that is not a typo.** The action installs from a
manifest of known versions with recorded hashes, and *that manifest is the ceiling* — not
the upstream release feed. Its `cargo-nextest` entries stop at 0.9.146, so requesting 0.9.148
fails the step outright with "supported but version 0.9.148 for 'x86_64_linux' is not
supported", even though the upstream gnu asset exists and downloads fine. The other three
pins sit exactly on their ceilings (deny 0.20.2, audit 0.22.2, semver-checks 0.51.0), which
is why they installed. The two releases in between contain no test-runner behaviour change:
0.9.147 and 0.9.148 are stress-run exit-code corrections, a setup-script config error, and
dependency bumps. `fallback: none` is what made this loud — without it the step would have
quietly compiled 0.9.148 from source and reinstated the cost the prebuilt install removes.

**The runner images are pinned for an evidentiary reason, not a hygienic one.** The
`sandbox-integration` job exists to produce positive Tier-1 evidence, and that result is a
measurement of a *particular image* — it refuses `--privileged` because that would weaken
the identity-inside-the-sandbox claim. A floating label lets the image change underneath
such a finding without anything recording that it changed. `ubuntu-latest` currently
aliases 24.04 and GitHub publishes 26.04 as a selectable label already, so pinning names
the image in the finding and upgrading becomes a deliberate commit.

Every version above was checked to exist before being written, because a wrong action tag
does not degrade gracefully — it fails the job. Each tool's MSRV (1.88 / 1.88 / 1.93 / 1.91)
sits below the pinned toolchain's 1.98.1, and the two versions that moved were installed
from source under that toolchain and the full gate set re-run with them actually present,
rather than declared and assumed.

> **The cost of pinning, and how it was paid.** `cargo install … --locked` builds each
> tool from source on every run instead of resolving a cached binary, which consumed most of
> the `linux-gates` budget: the job declared `timeout-minutes: 15`, and on `main` at
> `6224fa57` it reached `G9: tests` and was killed there having produced **zero** test results.
> Three runs in a row, all `cancelled` rather than `failure` — so the lane was not reporting a
> defect, it was reporting nothing at all.
>
> **Paid, not deferred.** The tools now install from prebuilt upstream binaries via
> `taiki-e/install-action`, SHA-pinned, `fallback: none`; and `timeout-minutes` is 30 as
> headroom. Note that caching was considered and is the weaker option: `rust-cache` saves only
> after a successful job, so a lane that repeatedly times out may never establish a useful
> cache — it is not a dependable first-run solution. Prebuilt installs have no such dependency.
>
> Full account in [`README.md`](README.md) §8.

### The current baseline, precisely

* **1655 tests, 1655 passed, 0 failed, 7 ignored** locally on a host that can create an
    unprivileged user namespace. *(Was 1419/1419 with 5 skipped before the 2026-10-08
    reconciliation: the suite grew by 236 tests and the ignored count by 2.)*
* The **7 ignores** are `#[ignore]`d child-process entry points — re-exec targets for
  power-loss and failure injection, and the hostile sandbox helper. They are entry points,
  not tests.
* **Leaky tests: 1 or 2, and the count is not stable.** nextest's leak detector samples
  child processes at test end, so which of the two cgroup tests trip it depends on
  scheduling:
  * `orxnud-platform-sandbox::resources::cgroup_kill_terminates_a_member_that_forked_a_descendant`
    — trips consistently;
  * `orxnud-platform-sandbox::enforcement::a_repeated_kill_stays_deterministic` — trips
    intermittently, and reports 2 leaky on every subset run of that crate.

  Both are pre-existing, both are `cgroup.kill` subtree tests, and **neither is a failure** —
  they pass. Recorded as a range rather than a number because a fixed figure here would be
  wrong within a week, which is the failure this whole document was corrected for.
* On the hosted runner, G9 runs fewer tests, not all of them, and all of those pass. The
  difference is the Tier-1 sandbox-evidence suites, which the runner cannot execute; the
  gate prints which ones it excluded and why. The exact figure is not recorded here because
  it moves with the suite list and a stale number is worse than none — read it from the run.

  **Continuation is sandbox evidence, and that is a property of the code rather than a
  choice about the tests.** Reaching `AwaitingNextStep` requires a *verified* effect, and
  `text/word-count` deliberately returns `Undetermined` rather than `Verified` — counting
  words has no effect to observe — so `filesystem/write-text` is the only capability that can
  put a task at a boundary. Six of the nine tests in `tests/continuation.rs` therefore have
  to execute one first, are named in the G9 exclusion list, and run in the ADR-0046
  container. The three that do not execute a capability — the `max_steps` bounds, the
  `done`-shape refusals, and the prior-step disclosure shape — run on every host.

  This was got wrong once: the first version of that exclusion list named five, on the
  reasoning that a test which only *asserts a race* does not need a sandbox. It does —
  it has to put the task at a boundary to have a boundary to race over — and hosted CI
  caught it (`a_boundary_is_claimed_by_exactly_one_worker`). The lesson is that the
  exclusion list has to be derived from what a test must *set up*, not from what it
  asserts.

  **The same argument covers `binary(disclosure)` in its entirety.** Every test in it has to
  produce a *verified* `filesystem/read-text` before it can assert anything about disclosure,
  so there is no host-independent test to keep in that binary. The three tests that do not need
  a sandbox were moved next to the code they exercise — `observation.rs`,
  `proposer.rs::tests` and `http_provider::disclosure_rendering_tests` — so the binary stays
  wholly sandbox evidence and one name covers it instead of ten.

  The general lesson, now recorded twice: **derive an exclusion from what a test must set up,
  not from what it asserts.** Both mistakes were caught by hosted CI rather than locally, which
  is itself worth noting — a filter that is wrong in the permissive direction fails loudly, and
  the one nobody checks is the one that excludes too much.

  `expiry.rs` splits the same way, for the same reason: five of its twelve tests have to execute
  `filesystem/write-text` to a *verified* result to be able to assert that a fresh approval works
  and a used one does not, so those five are named. The seven that only assert refusals — the
  boundary case, the read case, both race cases, the store-level rules and the expiry-instant
  arithmetic — run everywhere.

### What a green CI run does and does not prove

**It proves:** all twelve gates pass on Linux; every crate compiles for MSVC; the
platform-neutral suites behave on a real Windows host; the portable core is genuinely
portable; and on the hosted Linux runner a Tier-1 capability is **refused** with the
missing guarantee named — which is the fail-closed property, and is asserted positively
rather than skipped.

**It does not prove:** that a Tier-1 capability executes under isolation. The hosted
runner ships `bwrap` and cannot create an unprivileged user namespace (Ubuntu 24.04+
`kernel.apparmor_restrict_unprivileged_userns`), and a container does not escape it either
— measured, with AppArmor applying inside the container too. **`governed_path`,
`read_text_real`, `write_text`, `isolation` and the sandbox suites are positive Tier-1
evidence only on a host that can create one**, which is a developer machine
(`scripts/run-sandbox-tests.sh --host`) or a container on such a host. The
`sandbox-integration` job reports this rather than weakening anything to hide it (V-85,
V-86, V-87, ADR-0046).

So: **a green run and a full local suite are not the same claim, and neither is positive
hosted Tier-1 isolation evidence.** That evidence does not exist in GitHub-hosted CI and
this document now says so where a reader would otherwise assume it.

## 20. Code review

- Two approvals for: `unsafe`, capability contracts, policy, migrations,
  anything touching credentials, anything touching the network.
- The ADR list is the review checklist — a PR touching a boundary names the ADR.
- Reviewer must be able to answer "what could this break?" before approving.
- **Reviewers read the diff for intent, not just correctness.** The most
  expensive bugs are wrong-but-plausible code.

## 21. Architecture decision records

Every architectural decision gets an ADR with: Context, Problem, Options
considered, Evidence, Decision, Why, Trade-offs, Consequences, Rejected
alternatives, and **Revisit conditions**. A decision without revisit conditions
is a decision that will never be revisited, which is a smell.

## 22. What we deliberately do *not* do

Over-engineering is a real failure mode, not a hypothetical one. We do **not**:

- build a generic plugin framework before the third real capability,
- build a rule engine before the fifth real policy,
- build a vector index before the retrieval quality demands it,
- abstract storage before a second backend is actually needed,
- add a dependency for something we can write in 100 correct lines,
- build a UI component library before the third screen,
- support a platform before someone can test it,
- write a scheduler before we know the cron semantics we need.

**Every abstraction needs a stated reason and a named cost.** If a reviewer
cannot name the concrete thing it buys, it is not yet justified.
