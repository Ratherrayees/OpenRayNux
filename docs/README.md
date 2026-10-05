# OpenRayNux — Documentation Index

Status: **Stages 1–4b delivered. The 4c governance core is delivered. The 4c runtime
continuation and observation wiring is intentionally not enabled.**

Reconciled **2026-10-05** against `HEAD` (`1721761`) and CI run `37343986458`, where all
five jobs are green.

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
| Storage | SQLite (bundled, ≥ 3.51.3), schema at **v9**, snapshot-protected migrations |
| Task engine | Durable, hand-rolled; passes all 12 ADR-0029 properties from a second test binary |
| Governance | 9-stage dispatcher; `CapabilityInvocation` cannot be constructed outside `orxnud-policy` |
| Audit | Append-only, hash-chained, durable, survives restart |
| Approvals | Single-use, digest-bound **v3**, time-boxed, bound to an approver *and* a logical step |
| Sandbox | Tier-1 execution under `bubblewrap`; cgroup v2 ceilings where the host delegates |
| Transport | JSON-RPC 2.0 over a 0600 Unix socket, protocol version 1, 14 methods |
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

The 4c *governance core* is delivered. The loop that would drive it is not.

* **`AwaitingNextStep`, step-scoped attempts and approvals, and `claim_next_step()` exist
  and are tested — and nothing in production calls it.** No IPC method reaches it. A
  multi-step task stops at the boundary *by design*, not by accident (ADR-0043, V-84).
* **`PriorStepContext` exists and is tested; the observation store exists and is tested; the
  daemon's runtime does not read or write it.** A model can propose a read and has nowhere
  to receive the bytes. `3c8a413` names itself the rollback point immediately before moving
  approved workspace content to a third party.
* Also absent: no GUI or Tauri application, no TUI, no MCP surface, no messaging, no local
  ASR/TTS, no general shell capability, no unrestricted filesystem capability, no Windows
  sandbox backend, no actor runtime beyond the local authority model.

## 6. Where the evidence is, and what it does not prove

**1360 tests, 1360 passed, 5 skipped** locally, with 1–2 *leaky* results depending on
scheduling — both are pre-existing `cgroup.kill` tests that pass and are named in
[`08`](08-testing-engineering-standards.md) §19. On the hosted runner, gate G9 runs
**1244** and all 1244 pass — the difference is the Tier-1 sandbox-evidence suites, which the
runner cannot execute, and the gate prints which it excluded and why.

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

Wire the 4c runtime: the continuation loop that calls `claim_next_step()`, and the
observation path that hands an approved, verified read to the next proposal. Both are
one-way doors — the second is the first time approved workspace content leaves the machine —
so each needs its own decision record and its own evidence, not a drive-by.

After that: the actor model beyond one local human (V-70), and a decision on where positive
Tier-1 evidence should live, since GitHub-hosted runners cannot supply it.

---

## Read in this order

| # | Document | What it is for |
|---|----------|----------------|
| **03** | [System Architecture](03-system-architecture.md) | **Start here.** The shape, the crate graph, the 9 dispatcher stages, and **§9a: where the implementation actually stands.** |
| **12** | [Verification Register](12-verification-register.md) | **The highest-leverage file.** 86 entries: every claim that can become false, its verification source, its review trigger, and the consequence of drift. |
| **09** | [Architecture Decision Records](09-decisions.md) | 44 ADRs, ADR-0001…ADR-0046 (0041 and 0042 deliberately unused). Evidence, trade-offs, rejected alternatives, **revisit conditions**. |
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
