# OpenRayNux — Documentation Index

Status: **Stages 1–4c delivered. Both 4c wirings are in production: the continuation loop
(`task/continue`, ADR-0047) and the observation/disclosure path (ADR-0048).**

Reconciled **2026-10-09** against `HEAD` (`c5934970`). Workspace suite: **1655 passed,
0 failed**. All five CI lanes pass on run `37919194011` — but the same commit also has a
failing run, so `linux-gates` is **not** reliably green: an intermittent `v95_concurrency`
failure under load is open and undiagnosed. See
[§8](#-8-ci-state-the-tool-install-problem-is-resolved-one-test-flake-is-not).

OpenRayNux is a local-first personal AI operating layer: one long-lived Rust process owning
the user's time, data and integrations, with several surfaces driving the *same* governed
capability set. One surface ships today.

> **The foundational principle:**
> **The model proposes; a deterministic engine disposes.**
> The LLM is never the security authority, the scheduler, the credential authority, the
> transaction authority, or the final arbiter of whether an action succeeded.

---

## 1. What exists today

**A working, governed execution core — not a finished AI OS.**

| | |
|---|---|
| Workspace | 16 Rust crates, 1.98.1, gate-enforced dependency direction |
| Storage | SQLite (bundled, ≥ 3.51.3), schema at **v10**, snapshot-protected migrations |
| Task engine | Durable, hand-rolled; passes all 12 ADR-0029 properties from a second test binary |
| Governance | 9-stage dispatcher; `CapabilityInvocation` cannot be constructed outside `orxnud-policy` |
| Audit | Append-only, hash-chained, durable, survives restart |
| Approvals | Single-use, digest-bound **v3**, time-boxed, bound to an approver *and* a logical step |
| Sandbox | Tier-1 execution under `bubblewrap`; cgroup v2 ceilings where the host delegates |
| Transport | JSON-RPC 2.0 over a 0600 Unix socket, protocol version 1, 15 methods |
| CLI | `orxnuctl` — hand-written parser, 5 verb groups |
| Daemon | `orxnud` — composition root, single-instance lock, serves the socket |
| Provider | **One real HTTPS provider**, TLS with chain and hostname verification |
| AI | **A real proposer**: registry-derived menu → model → durable proposal → approval → governed execution |

## 2. What is actually executable

Three capabilities are registered. This is the whole list, from one function
(`shipped_declarations()`) so the registry, the bundles and the policy table cannot drift:

```bash
orxnuctl capability run --capability text/word-count \
  --params '{"text":"hello world"}'          # Low, Tier 0, in-process, no prompt

APPROVAL=$(orxnuctl capability approve \
  --capability filesystem/write-text --target notes.txt \
  --params '{"path":"notes.txt","contents":"hello"}' --ttl-ms 60000)

orxnuctl capability run --capability filesystem/write-text \
  --target notes.txt --params '{"path":"notes.txt","contents":"hello"}' \
  --approval "$APPROVAL"                     # High, Tier 1, sandboxed, single-use
```

An approval is bound to the exact parameters it was issued for. Presenting it with
`contents` changed is refused `approval-digest-mismatch` before anything runs.

The full AI loop, through the shipped binaries:

```bash
orxnud --state-root "$ROOT" --provider-base-url https://api.groq.com/openai/v1 \
       --provider-model openai/gpt-oss-120b &
orxnuctl task create --id t1 "write notes.txt"
orxnuctl task claim  --id t1 --worker ai
orxnuctl task ai-propose --task t1 --worker ai     # model picks a capability from the registry
orxnuctl capability approve --proposal <id> --ttl-ms 60000
orxnuctl task execute --proposal <id> --worker ai  # governed; Tier-1; verified
```

## 3. Security guarantees that are real

* **Authority cannot be forged from data.** `CapabilityInvocation` does not derive
  `Deserialize`; its constructor demands `orxnud-policy`'s private seal. A compile-fail test
  with a recorded `.stderr` proves re-adding the derive breaks the build.
* **One route out.** `Dispatcher::dispatch` is the only path from an authorised intent to an
  effect. A `Subprocess` adapter's `invoke` panics by design, so a bypass is loud rather
  than silent, and gate G2 rejects `Command::new` anywhere in `orxnud-capability`.
* **Fail closed, everywhere.** A host that cannot establish the required guarantees refuses
  every Tier-1 capability — before a credential resolves, before a process exists. There is
  no unsandboxed fallback and no `BestEffort` path in the governed route.
* **Approvals mean consent.** Digest v3 binds the approver, their authority root, the
  proposer, capability, target, canonical parameters, time bounds **and the logical step**.
  One consent cannot cover a sibling step, and the durable proposal records the model that
  actually answered rather than a configured name.
* **Credential hygiene is tested, not asserted.** A sentinel value runs through every path
  that touches the provider key — resolved, refused, debugged, redacted, persisted — and its
  exact bytes are asserted absent from all of them, including every file under a real
  daemon's state root.
* **TLS cannot be downgraded.** `Scheme::carries_credentials` is true only for TLS,
  redirects are not followed, and eleven tests drive a real `rustls` handshake.

## 4. Platforms: what is proven

| | Linux | Windows |
|---|---|---|
| Compiles | ✅ | ✅ **all 16 crates, MSVC, all targets** |
| Behaviour tests run | ✅ | ✅ platform-neutral suites, on a real runner |
| Tier-1 sandbox | ✅ where the host provides guarantees | ❌ **refuses** — no backend exists |
| Isolation proven | ✅ mutation-verified (V-46) | ❌ **NOT PROVEN** (V-29) |

Windows is neither "untested" nor "sandbox-supported". It is **portable and compiled, with
isolation unproven**: there is no Job Object or AppContainer backend, so a Tier-1 execution
is refused rather than degraded. Refusing is correct — an unsandboxed Tier-1 subprocess is
worse than no capability at all.

**GitHub-hosted Linux CI cannot produce positive Tier-1 sandbox evidence.** The hosted
runner ships `bwrap` and cannot create an unprivileged user namespace (Ubuntu 24.04+
`kernel.apparmor_restrict_unprivileged_userns`), and a container does not escape it either.
That is measured and printed on every run. The `sandbox-integration` job reports the
limitation rather than weakening anything to hide it — see §6.

## 5. What is intentionally not wired

The 4c governance core **and both of its wirings** are delivered. What remains unwired is
the surfaces listed last, and nothing else.

* **Continuation is wired.** `task/continue` crosses a step boundary by claiming one step
  and proposing the next through the ordinary approval gate (ADR-0047). `claim_next_step()`
  is called from `orxnud-daemon`'s runtime, not only from tests — see
  `runtime.rs`, the `continue_task` handler. A multi-step task still stops at the boundary
  until somebody asks it to continue, which is the designed behaviour rather than a gap
  (ADR-0043, V-84).
* **Observation/disclosure is wired.** An **approved, verified read** informs **one**
  subsequent proposal, to the `(endpoint, model)` identity that asked for the read, and
  only across the **immediately following** step. `PriorStepContext` is untouched and stays
  metadata-only — the content travels on a separate, ephemeral channel that is consumed on
  release and never becomes durable (ADR-0048, V-88). This is the first path in the build on
  which workspace content can leave the machine, and `3c8a413` names itself the rollback
  point immediately before that happens.
* **An earlier version of this section claimed both of the above were absent** — that
  `claim_next_step()` had "nothing in production calls it", and that the runtime "does not
  read or write" the observation store. Both statements were true when written and are now
  false, and they contradicted §3 of [`03-system-architecture.md`](03-system-architecture.md),
  which already described the 4c governance core as delivered *with* both wirings. They are
  corrected here rather than left to contradict a normative document.
* Also absent: no GUI or Tauri application, no TUI, no MCP surface, no messaging, no local
  ASR/TTS, no general shell capability, no unrestricted filesystem capability, no Windows
  sandbox backend, no actor runtime beyond the local authority model.

## 6. Where the evidence is, and what it does not prove

**1655 tests, 1655 passed, 0 failed** locally, with 1–2 *leaky* results depending on
scheduling — both are pre-existing `cgroup.kill` tests that pass and are named in
[`08`](08-testing-engineering-standards.md) §19. On the hosted runner, gate G9 runs fewer
and all of those pass — the difference is the Tier-1 sandbox-evidence suites, which the
runner cannot execute, and the gate prints which it excluded and why. The hosted figure is
read from the run rather than recorded here, because it moves with the suite list.

**A green CI run proves:** twelve gates on Linux; every crate compiles for MSVC; the
platform-neutral suites behave on real Windows; the portable core is portable; and on the
hosted runner a Tier-1 capability is **refused** with the missing guarantee named.

**It does not prove** that a Tier-1 capability executes under isolation.
`governed_path`, `read_text_real`, `write_text`, `isolation` and the sandbox suites are
positive evidence **only on a host that can create an unprivileged user namespace** — a
developer machine (`scripts/run-sandbox-tests.sh --host`) or a container on such a host.

Two claims that look like guarantees and are not:

* **Positive hosted Tier-1 isolation evidence does not exist.** A green
  `sandbox-integration` means *the environment was measured*, not *the sandbox was proven*.
* **V-75 is live-run evidence.** A real Groq `openai/gpt-oss-120b` produced and executed a
  governed proposal. No gate performs that run and none can — it needs a live credential.
  Everything *around* the model call is CI-covered; the model's contribution is not.

## 7. Current next milestone

**The next milestone is deliberately undecided, and that is the finding rather than an
omission.** Verification work has been carried out under the identifiers V-93, V-94, V-95
and V-97 — all of them now in `main`, all of them recorded in
[`12`](12-verification-register.md) as of this reconciliation. There is a **gap at V-96**,
and no definition of V-96 exists anywhere in the repository: not in `docs/`, not in the
register, not in the commit history, not in the tree.

So V-96 is **not** something this document will define by guessing. Inventing a plausible
defeating for an unknown ID would put a fabricated requirement into a normative document,
which is the exact failure mode
[`12`](12-verification-register.md)'s freshness policy exists to prevent. The next
engineering milestone therefore has two steps in order:

1. **Recover or define V-96 explicitly** — decide whether it was a planned slice that was
   skipped (in which case define its scope and evidence) or a numbering artefact (in which
   case record the gap the way V-44 and ADR-0041/0042 are recorded: named, not renumbered).
2. **Then** implement and verify it.

Standing candidates already named in this document, offered as input to that decision and
not as its answer: the actor model beyond one local human (V-70), where positive Tier-1
isolation evidence should live given that hosted runners cannot supply it, and the
`linux-gates` timeout defect in §8.

## 8. CI state: the tool-install problem is resolved, one test flake is not

**`linux-gates` passes on `main` as of `c5934970`.** It did not, for a while, and the
failure mode was misleading enough to be worth recording.

### Resolved: the gate tools could not be installed in the budget

Between `6224fa57` and `965a509` the lane was **cancelled** on three consecutive runs. It was
not failing on the code: it reached `G9: tests` and was killed there having produced **zero**
test results, which places the death in the cold workspace compile rather than in any test.
A cancelled lane reports nothing about the code at all, and next to four green lanes it
reads as though five things had been verified.

The cause was our own reproducibility work. `a1c0b2e` pinned the four gate tools to exact
versions, which is right, but installed them with `cargo install … --locked` — and that
compiles each tool from source on a cold runner, before any project test can start, against a
`timeout-minutes: 15` budget. Fixed in three steps: install from prebuilt upstream binaries via
`taiki-e/install-action` pinned to a full commit SHA with `fallback: none` (`6bc2d44`); correct
`cargo-nextest` to `0.9.146`, the ceiling of that action's manifest rather than the upstream
release feed (`965a509`); raise the job timeout to 30 minutes as headroom, explicitly the
second line rather than the fix.

`Run the gates` is now green: **all selected gates passed**, nextest 1505/1505. The
tool-install problem is resolved.

### Open: an intermittent `v95_concurrency` failure under load

Run `37916621851` at `c5934970` failed at G9 on
`orxnud-task::v95_concurrency::recovery_racing_a_claim_leaves_exactly_one_owner`:

```
recovery was told the database was busy rather than what it settled:
sqlite error: database is locked
```

**A later run of the identical commit is green.** `37919194011`, same SHA `c5934970`, all five
jobs succeeded, all selected gates passed, and all 13 `v95_concurrency` tests passed
individually — including the one above. So the lane is not deterministically broken, and
whether a given push is red on G9 is currently a coin-flip.

Reproduced locally only under artificial load: 0 failures in 25 runs unloaded, **9 in 30** with
the box CPU-saturated. The observed error is `SQLITE_BUSY_SNAPSHOT` (extended code 5) at
`BEGIN IMMEDIATE`, which is returned immediately by SQLite when a write transaction cannot
upgrade its snapshot; a `busy_timeout` or busy handler does not absorb it.

**No root cause is established and no fix exists.** The working hypothesis is a defect in the
test's own `race()` fixture rather than in production code — it installs a busy handler and
assumes that is sufficient — but that has not been proven, and an edit attempted on
2026-10-08 was reverted because a controlled comparison showed it changed nothing (10/30 under
load versus 9/30 for the unmodified binary). Recorded here as an open defect with its
reproduced symptoms, not as a diagnosed cause. It is invisible locally on an idle machine,
which is exactly the property that makes it worth writing down.

### Everything else is green

`windows-check` (MSVC), `windows-portability`, `portable-core` (wasm32) and
`sandbox-integration` (Tier-1) pass. G12 is skipped for want of a release tag to compare
against. Local: 1655/1655, and `CI=true ./scripts/ci-gates.sh` passes end to end in about 21
seconds on a warm target directory.

---

## Read in this order

| # | Document | What it is for |
|---|----------|----------------|
| **03** | [System Architecture](03-system-architecture.md) | **Start here.** The shape, the crate graph, the 9 dispatcher stages, **§9a: where the implementation actually stands**, and **§10: the verifier-admission invariant (K.1)**. |
| **12** | [Verification Register](12-verification-register.md) | **The highest-leverage file.** 96 rows: every claim that can become false, its verification source, its review trigger, and the consequence of drift. |
| **09** | [Architecture Decision Records](09-decisions.md) | 51 ADRs, ADR-0001…ADR-0053 (0041 and 0042 deliberately unused; ADR-0050 also carries an amendment, which is not a separate record). Evidence, trade-offs, rejected alternatives, **revisit conditions**. |
| **07** | [Extension & Capability Model](07-extension-capability-model.md) | The dispatcher order, the declaration structure, parameter schemas, target semantics, and the real registry. |
| **04** | [Security & Threat Model](04-security-threat-model.md) | **Normative.** Trust boundaries, threats, controls — and **§5a: the threats Stage 4c and the CI work introduced.** |
| **06** | [Deployment & Platform Model](06-deployment-platform-model.md) | Profiles, the platform boundary, and **§2.3: the honest per-platform assessment.** |
| **08** | [Testing & Engineering Standards](08-testing-engineering-standards.md) | **§19: what CI actually enforces, the real baseline, and what a green run does not prove.** |
| **04→** | [Critical Review](11-critical-review.md) | The adversarial section. What we assume, what is deliberately minimal, what we must never build. |
| **00** | [System Requirements](00-system-requirements.md) | What it must *be*. A research record. |
| **02** | [Technology Evaluation](02-technology-evaluation.md) | The decision table and licence posture. A dated evaluation. |
| **01** | [Architecture Research](01-architecture-research.md) | What the ecosystem looks like, and corrections to widely-repeated claims. |
| **05** | [Resource & Performance Model](05-resource-performance-model.md) | Budgets. All **unmeasured** — see the correction in its header. |
| **10** | [Open Questions](10-open-questions.md) | Live questions, plus preserved resolved answers. Six reconciled 2026-10-05. |
| **13** | [Phase 1 Contract](13-phase-1-contract.md) | **Historical.** The agreement Phase 1 was measured against. |
| **14** | [Phase 2 Contract & Delivery Record](14-phase-2-contract.md) | **Historical.** Durability, the engine, measured `synchronous = FULL`. |
| **15** | [Phase 4a Record](15-phase-4a-record.md) | **Historical.** The verified execution boundary, including the V-45 measurement correction. |
| **sources.md** | [Sources](sources.md) | Version claims with URLs and access dates. |

## The decisions at a glance

| Area | Decision | ADR |
|---|---|---|
| Core language | **Rust** | [0001](09-decisions.md#adr-0001) |
| Desktop | **Tauri 2**, optional separate process — *future* | [0002](09-decisions.md#adr-0002) |
| Local transport | **Unix socket + JSON-RPC 2.0**; named pipe *future* | [0003](09-decisions.md#adr-0003) |
| Runtime | **Tokio** + an explicit supervisor | [0004](09-decisions.md#adr-0004) |
| Frontend | **Svelte 5 + Vite 8** — *future* | [0005](09-decisions.md#adr-0005) |
| Storage | **SQLite** via `rusqlite`, bundled **≥ 3.51.3** | [0006](09-decisions.md#adr-0006) |
| Task engine | **Hand-rolled durable task table** | [0007](09-decisions.md#adr-0007) |
| Vector search | **None.** FTS5 now; interface exists | [0008](09-decisions.md#adr-0008) |
| Capabilities | **Three isolation tiers, no dynamic plugins** | [0009](09-decisions.md#adr-0009) |
| MCP | **External, untrusted integration boundary only** | [0010](09-decisions.md#adr-0010) |
| LLM abstraction | **Provider-neutral**, one real adapter | [0011](09-decisions.md#adr-0011) |
| Determinism | **Model proposes; engine disposes** | [0012](09-decisions.md#adr-0012) |
| Authority | **`CapabilityInvocation` is not deserialisable** | [0034](09-decisions.md#adr-0034) |
| Tier-1 execution | **PID namespace + `PDEATHSIG`**, and what it does not do | [0035](09-decisions.md#adr-0035) |
| Tree lifetime | **The PID namespace is load-bearing; `cgroup.kill` is a backstop** | [0036](09-decisions.md#adr-0036) |
| Approvals | **An approval names its approver**, and the digest binds them | [0037](09-decisions.md#adr-0037) |
| Proposals | **Durable before approved**; a lease never grants authority | [0038](09-decisions.md#adr-0038) |
| Parameters | **A capability declares them; the proposer reads the declaration** | [0039](09-decisions.md#adr-0039) |
| Provider | **One real provider over HTTP**, credential in the secret store | [0040](09-decisions.md#adr-0040) |
| Continuation | **An explicit operation, not a widened claim** | [0043](09-decisions.md#adr-0043) |
| Observation | **Governed reads; a context that carries no content** | [0044](09-decisions.md#adr-0044) |
| Disclosure | **One approval, two acts**, bound to `(endpoint, model)` | [0045](09-decisions.md#adr-0045) |
| CI boundary | **A missing guarantee is a refusal to assert, not a skip** | [0046](09-decisions.md#adr-0046) |

The full table of all 44 is in [09-decisions.md](09-decisions.md).

## Open before implementation

| ID | Question | Status |
|----|----------|--------|
| 🔴 [Q-OPEN-01](10-open-questions.md) | **Telegram ToS §1.5** — legal review | **Open, deliberately not blocking.** No messaging code exists; the boundary it would protect is enforced at the read layer instead. |
| 🟡 [Q-OPEN-21](10-open-questions.md) | Do TS6 and `--tsgo` diagnostics agree? | Open; a frontend deliverable, and there is no frontend yet |
| 🟡 [Q-OPEN-05](10-open-questions.md) | Model cost ceiling: per-provider or per-user? | Open — one provider ships, so the question is not yet forced |
| ✅ [Q-OPEN-17](10-open-questions.md) | Is `synchronous = FULL` affordable? | **RESOLVED** — ~2.3 ms/commit. [V-30](12-verification-register.md) |

## Reproducing the verification state

```bash
./scripts/ci-gates.sh                     # the twelve gates; ~3 min
./scripts/preflight.sh                    # what THIS host can actually isolate
./scripts/preflight.sh --require          # fail unless it is the production configuration
scripts/run-sandbox-tests.sh --host       # the Tier-1 suites, on a capable host
scripts/run-resource-tests.sh             # cgroup enforcement, in a delegated container
```

Last research/verification date: **2026-10-05**.
