# 11 — Critical Review

Status: **Draft v0.1** · The uncomfortable section. Written to be argued with.

This document answers §32 of the brief. It is deliberately adversarial toward our
own design: a plan that only lists its virtues has not been reviewed.

---

## 1. What are we currently assuming that could later hurt OpenRayNux?

Ordered by expected damage.

### 1.1 That SQLite's single writer is enough — for years

**The assumption.** One writer, one machine, single user. Personal-assistant
write volume is single-digit to low-hundreds of state transitions per minute.
SQLite has 4–5 orders of magnitude of headroom over that.

**How it could hurt.** It is not about volume — it is about **multi-device**.
"Use your phone to check what the desktop is doing" means a second process, and a
second writer, and SQLite's answer is `SQLITE_BUSY`. The escape hatches are
`BEGIN IMMEDIATE` with careful retry, or a move to a server database — and a
move means re-implementing the repository layer, re-testing the task engine's
atomic claim, and re-validating every durability claim. That is weeks of work
chosen by a future feature request.

**Mitigation already in place.** The repository layer is mandatory (ADR-0006) and
the task-claim query is written as a single atomic statement precisely so it
ports. **Residual risk: real and deferred.** IR-3 (mobile as a future API
consumer) is the requirement that will eventually force this.

### 1.2 That Tauri stays a good trade as the frontend grows

**The assumption.** The webview's ~80–150 MB is acceptable *because* the GUI is
an optional separate process, and the web platform's richness saves us months of
native UI work.

**How it could hurt.** Two failure modes. (a) The product becomes genuinely
UI-heavy — live streaming transcripts, a task graph visualiser, a
calendar/timeline view, an accessibility-first editor — and the webview's cost
becomes the *dominant* resource cost of a product whose entire premise is
lightweight. (b) WebView2, WebKitGTK, and WKWebView diverge enough that
"works on Linux" quietly becomes "works on Chromium desktops" — a
cross-platform regression discovered by users.

**Mitigation.** Slint 1.18.1 is documented as the strong fallback (ADR-0002), and
the GUI is a separate process so switching is a client swap, not a core change.
**Residual risk: moderate.** Phase 1 must measure actual RSS on three
distributions, not one.

### 1.3 That `sherpa-onnx` is a foundation we can stand on

**The assumption.** It is first-party, Apache-2.0, releases every 1–3 weeks, and
covers the whole speech pipeline in Rust.

**How it could hurt.** It is a large native build that **downloads a prebuilt
library at build time**. Its model zoo is Mandarin-first. If its maintainers' pace
slacks, our *default* voice engine stalls — and voice is a headline capability.
The alternative we deprioritised (`whisper.cpp`) has a decade of production use
and 54 k stars but its Rust binding is single-maintainer with an archived repo.
**There is no low-risk option in Rust-native ASR.** That is uncomfortable and
should be stated rather than smoothed over.

**Mitigation.** The trait boundary (ADR-0014) is real; `parakeet-rs` and
`whisper.cpp` are behind it; the model registry is separate from the engine.

### 1.4 That the LLM-provider abstraction will hold

**The assumption.** Capability negotiation lets us use providers' strengths
without coupling to any of them, and a schema sanitiser smooths over
divergence.

**How it could hurt.** Provider APIs change faster than we can abstract. Tool
calling, reasoning tokens, and caching semantics differ per provider and shift
per release. Our `ProviderCapabilities` descriptor is a bet that the *set* of
capabilities is roughly stable — and providers add capabilities constantly, which
means the descriptor is a permanent maintenance burden with a slow drift toward
provider-shaped design.

**Second-order risk we have not designed for:** the industry is converging on
provider-hosted *agent* primitives. If OpenAI/Anthropic ship first-class
durable-agent and tool-execution services, the honest answer may be "use theirs"
— and our harness becomes a compatibility shim. This is the single most likely
way our AI layer is obsoleted.

**Mitigation.** The task engine, policy layer, and capability layer do not depend
on the LLM abstraction. Only the intent layer does. Losing the harness would
cost the *harness*, not the product.

### 1.5 That users will accept digest-bound, per-action approvals

**The assumption.** The safety model (S6) is correct, and users will tolerate
approvals that are single-use, short-lived, and non-inheritable.

**How it could hurt.** This is the design most likely to be *felt* as bad UX. A
ten-step workflow where step 7 sends an email should not require the user to have
approved "the workflow" — it should require approval of that specific send. If we
get this wrong in the permissive direction we ship a security hole; in the
restrictive direction we ship something users disable, and a disabled approval
prompt is a removed approval prompt.

**This is the highest-risk *product* decision in the whole plan, and it has no
research to lean on.** Q-OPEN-14 and Q-OPEN-13 are open because we genuinely do
not know the answer. We should be prepared to find out empirically and early,
not in Phase 8.

### 1.6 That "TypeScript 6, not 7" will not age badly — **CORRECTED, see below**

> **Post-review correction (2026-09-30).** This assumption was itself an error,
> and it is preserved here because the failure mode is instructive. Revision 1
> inferred from `svelte-check`'s peer range that TypeScript 7 was unsupported for
> Svelte. Inspecting the published package showed a documented `--tsgo` path and
> a matching one in `svelte-language-server`. **The peer range said what the
> package *declares*, not what is *possible*.** ADR-0005 is now revised: TS 7.0.2
> is the baseline, TS 6.0.3 is co-installed for tooling that embeds the compiler
> API. See §1.6a.

### 1.6a The generalisable lesson: tooling constraints are not architecture

The error was **the converse of "latest-blinkism"** — declining the current
stable release on the basis of a peer-dependency artefact. Both directions are
the same mistake: letting a *mechanical* fact decide an *architectural* question.

The generalisable rule now recorded in ADR-0005 and `sources.md`:

> Before promoting a tooling limitation to an architectural decision, read the
> tool's own source and docs for a supported path. A peer range is a declaration,
> not a prohibition.

This matters beyond TypeScript. It is the same discipline that made us check
`apalis-sqlite`'s actual `PRAGMA synchronous` (Q-OPEN-02) rather than assume it,
and that made us read `sherpa-onnx`'s crate source rather than trust its
description.

### 1.6b The original assumption, restated correctly



**The assumption.** Microsoft's exclusion of Svelte is temporary, and pinning to
6.0.3 costs us nothing material.

**How it could hurt.** If TypeScript 7.1's programmatic API lands and Volar
catches up quickly, we will have chosen the older compiler for a build-speed
benefit a desktop frontend does not need — and we will have carried a pin and a
workaround for a year. Minor. **The real cost is process**: we now have a
documented "we deliberately do not use the newest TypeScript" position that a
future contributor will read as an error.

**Mitigation.** Documented with an explicit revisit condition (ADR-0005).

### 1.7 That a hand-rolled task engine is cheaper than a library

**The assumption.** ~200–400 lines of queue logic beats adopting `apalis` and
absorbing its RC status, single maintainer, and one unverified setting.

**How it could hurt.** Queue semantics are deceptively hard: lease expiry,
clock skew across restarts, orphan recovery, priority inversion, backoff
jitter, dead-letter policy, catch-up bounding. If we get one of them subtly
wrong, the symptom is *silent* — a task that "didn't run" or "ran twice" — and
the user finds out weeks later. Hand-rolled durability code is where quiet bugs
live.

**Mitigation (strengthened post-review).** The contract is now the twelve
**normative properties** in ADR-0029, specified independently of this
implementation, each with a named test — including a *zombie-worker* test for
TP-5 (expired leases must not be able to commit), which is the subtlest of the
twelve and the one a naive implementation gets wrong. The failure-injection suite
and the "no silent data loss" master property exist precisely for this. **Residual
risk: this is the code we own and the code we will get wrong** — but it is now
code with a falsifiable specification rather than code with an adjective
("reasonable"). Q-OPEN-02 gates the escape hatch.

### 1.8 That prompt injection can be contained by structure rather than detection

**The assumption.** We do not detect injection; we make it *harmless* by removing
the model's access to authority (S1) and by making every side effect
policy-gated.

**How it could hurt.** This is the right architecture, but it is a *hard* design
to maintain. Every future contributor who adds a capability with network or
filesystem access is a potential S1 regression. And there will be a bug: the
capability that "genuinely needs" to read a file to decide, added under deadline,
will get filesystem access. That is the moment the model regains a lever.

**Mitigation.** The S1 verification test (§4 of `04-…`) is automated, so a
regression *fails the build* rather than shipping. **This is the most important
test in the repository.**

### 1.9 Assumptions we have not examined because they feel safe

| Assumption | Why it might not be |
|---|---|
| Rust 1.98.1 is enough MSRV headroom | `sqlx` needs 1.94, `egui` 1.95. Two more dependency bumps and our floor moves. |
| Feature flags deliver CR-2 | Verified only in CI for *our* build. A dependency that ignores features can silently link anyway. |
| `synchronous=FULL` is affordable | Unmeasured (Q-OPEN-17). Rotational storage would break the 5 ms target. |
| FTS5 is enough retrieval | If it is not, we discover it late and the fix is `sqlite-vec`, which is 6 months stale. |
| Append-only hash-chained audit is tamper-evident | It is tamper-*evident*, not tamper-proof. A determined local attacker with write access can rewrite the whole chain. |
| One user, one machine, is the actual use case | The brief says open-source, general-purpose, cloud-deployable. Those pull toward multi-user, and we are betting single-user for v1. |

---

## 2. Which parts are genuinely future-proof?

Genuinely durable — these are unlikely to need revisiting:

1. **The determinism boundary** (ADR-0012). *The model proposes; a deterministic
   engine disposes.* This holds regardless of model, provider, or language
   technology. It is the product's character.
2. **Policy as a non-bypassable choke point.** If there is exactly one
   construction site for an authorised invocation, then adding capabilities,
   interfaces, and providers cannot widen authority. Security properties that are
   *structural* do not decay.
3. **Interfaces as thin clients over one core** (IR-2). Every new interface is
   nearly free, and the "no domain types in interfaces" rule makes it true rather
   than aspirational.
4. **Enforced layering of crates + a machine-checked platform boundary.** The
   `cfg(target_os)` grep gate means cross-platform hygiene cannot silently rot.
5. **Separated memory classes with a repository-level authority filter** (ADR-0013).
   Whatever storage we end up with, "derived data is never authoritative" is
   enforced by a query, not a convention.
6. **Capability manifests as data.** Policy, UI, and resource accounting all read
   the same manifest. Adding a capability becomes a data change.
7. **Disabled = zero, measured in CI.** This is the mechanism that keeps the
   lightweight promise honest as features accumulate. It gets *harder* to violate
   over time, not easier.
8. **Digest-bound approvals** (S6). The mitigation for a named, published threat
   class does not become obsolete because models changed.
9. **One codebase, four deployment profiles.** Cloud is an envelope change.
9a. **The Actor concept (ADR-0027).** Six actor kinds are a fact of the product's
    shape, not an implementation detail. It will grow (a second human, a
    device, an agent acting for an agent) without structural change.
9b. **State classification (ADR-0028).** `critical` / `authoritative` / `derived` /
    `ephemeral` is a distinction that stays correct as storage evolves, and it is
    the mechanical answer to "which state may the model write?"
9c. **The task-engine correctness properties (ADR-0029).** Specified
    implementation-independently, so the engine is swappable without
    renegotiating the contract — and so "correct" is auditable rather than
    asserted.
10. **Writing down revisit conditions.** Not an architectural property, but the
    mechanism that stops any of the above from calcifying.

---

## 3. Which parts are deliberately minimal?

Minimal on purpose, and we should resist "fixing" them:

| Minimal | Why | When to revisit |
|---|---|---|
| **No vector DB; FTS5 only** | Derived data; a server in a personal install is unacceptable | When *measured* retrieval quality fails (ADR-0008) |
| **No agent framework; a thin harness** | Three primary sources, including the vendor's own team, say abstraction is what to remove (ADR-0024) | If something we need genuinely requires one |
| **No WASM plugin system** | The capabilities we need to isolate are where WASM is weakest (ADR-0009) | Component Model stabilises *and* a fitting capability exists |
| **One agent, ~10–20 tools** | Anthropic and OpenAI both converge here | If task complexity genuinely demands more |
| **SQLite only, no repository abstraction beyond ports** | A second backend is speculative (ADR-0006) | P4 multi-tenancy, or measurable contention |
| **No self-updater** | An updater with network write access that can brick a single-copy install is a bad trade (ADR-0017) | After signed staged rollout + tested rollback exist |
| **Native OTLP exporter only; no collector** | A collector is a daemon (ADR-0020) | Never for the local profile |
| **TUI exempted from accessibility** | AT-SPI in a terminal is not realistically achievable (Q-OPEN-19) | Probably never |
| **Cloud ASR/TTS with no default provider** | Prices and quality move; the user should choose (Q-OPEN-07) | n/a |
| **WhatsApp deferred; Signal refused** | Legally/structurally wrong today (ADR-0016) | 3P Agents GA + documented |
| **No RayNux data import** | The brief says design from scratch; a lossy import imports the data model (Q-OPEN-10) | If the user wants continuity more than a clean model |
| **Hand-rolled scheduler** | `croner` + `jiff` with documented DST semantics, and a ~30-line catch-up | If a Rust cron ever documents DST *and* catch-up |

**The discipline here is the point:** every one of these is a decision to not
build, with a stated condition that would reverse it. The failure mode to avoid
is adding infrastructure "just in case", which is exactly what
`02-technology-evaluation.md` §3 refuses to do.

---

## 4. Where are we accepting technical debt intentionally?

| Debt | Why it is worth it | Cost of later fix |
|---|---|---|
| **Hand-rolled task engine** | Avoids a RC library, an extra abstraction, and an unverified durability default. Matches what three primary sources recommend. | Moderate — but the schema and invariants are designed for it |
| **A single hand-rolled supervisor for Tokio** | Tokio has no structured concurrency; adopting a framework for it would be heavier than the problem | Low |
| **Dual TypeScript install** (7.0.2 + 6.0.3 co-installed) | Tools that embed the compiler API need 6.0's API, which 7.0 does not ship until 7.1. This is the vendor-documented pattern, not our workaround. | Trivial — collapse to TS7 alone when 7.1 ships the API and `svelte-check` widens its peer range |
| **No `sqlx` async DB** | SQLite is single-writer; async buys little. MSRV 1.94 costs headroom. | Low — repository layer exists |
| **`ort` RC dependency (via `parakeet-rs`)** | Best WER/RAM for local ASR | Moderate — but not the default engine |
| **`playwright-rs` bus factor 1** | It is the only live Playwright-for-Rust; the official one is explicitly out of scope | Moderate — vendor on adoption |
| **No a11y for TUI** | Not achievable in a terminal | High if a user needs it — hence GUI as the accessible default |
| **A hash-chained audit log that is tamper-evident, not tamper-proof** | Proportionate to a local single-user threat model | High if multi-tenant (P4) |
| **Schema sanitiser losing JSON Schema fidelity** | Portability beats richness when providers 400 on rich schemas | Low |
| **Approval UX is unvalidated** | No research exists; it must be discovered empirically | High — this is the product's feel |
| **Windows untested until Phase 1** | It is scheduled early for a reason, but it *is* untested | High if it slips — hence the Phase 1 commitment |

---

## 5. What should we absolutely NOT build?

Stated to protect future phases from well-intentioned scope creep.

| Never build | Why |
|---|---|
| **A dynamic-library plugin system** | No stable Rust ABI; a crash kills the core. Contradicts the brief's own requirement (ADR-0009). |
| **A capability marketplace** | Every capability is a security surface. Review capacity, not demand, is the constraint. |
| **Multi-agent swarms** | Anthropic and OpenAI both say one agent with tools suffices. Swarms add cost, latency, and non-determinism. |
| **A vector database** | A server to store regenerable data (ADR-0008). |
| **Postgres/Redis/Kafka/Kubernetes in a personal install** | Each is a daemon to install, secure, back up, and upgrade. The product's core promise is that it does not. |
| **Auto-connecting MCP servers** | A connection is a trust grant. Never implicit. |
| **Browser stealth / anti-bot evasion** | Makes us indistinguishable from an attacker — exactly what these defences are tuned to catch. And it arms an arms race we lose. |
| **Any telemetry, phone-home, or crash upload** | A privacy and resource violation, and the brief prohibits it (ADR-0020). |
| **A self-updater that is the only update path** | One bad migration plus one copy of the data equals total loss (ADR-0017). |
| **Shell execution as a capability** | No shell. `execve` argv only, never `sh -c` (S20). |
| **An LLM that grants itself permission, however framed** | The one decision that does not get revisited. |
| **A "trusted" flag that grants a capability everything** | Grants are per capability, per task, per parameter scope. There is no trust escalation shortcut. |
| **Learning/executing instructions from retrieved content** | The single highest-severity threat (TH-01, TH-02) |
| **A GUI-specific business rule** | If the GUI can implement a rule, the rule is not in the core, and it will be implemented twice (IR-2). |
| **Assuming a model update is safe** | Every harness assumption is a liability ("Harnesses encode assumptions that go stale as models improve") — so the evaluation track is not optional |

---

## 6. What architecture decisions would be expensive to change later?

Ranked by the cost of reversal. This is the list to protect.

| Decision | Cost to reverse | Why |
|---|---|---|
| **The determinism boundary / policy choke point** | **Very high — architectural** | Retrofitting means auditing every code path, not refactoring one module. Getting this wrong early is unrecoverable. |
| **One daemon owning all state (no second writer)** | **Very high** | Two writers means two truths. Unwinding requires a distributed-consensus story we do not want. |
| **Interfaces as thin clients with no domain access** | **High** | If a GUI ever holds domain logic, every interface is a fork, and the "one core" property is gone. |
| **The capability trust-tier model (Tier 0/1/2)** | **High** | It determines where every future capability lives and what its security review is. A late change means re-reviewing everything. |
| **SQLite + repository ports as the storage contract** | **Moderate** | Ported by design, but the task-claim SQL, the migration story, and every durability test are SQLite-specific. |
| **The local JSON-RPC protocol shape** | **Moderate** | Every interface, the MCP mapping, and the cloud adapter depend on it. Renaming methods is cheap; changing the *shape* is not. |
| **The task state machine's states** | **Moderate** | States are persisted; changing them needs a migration. Adding a state is cheap; renaming or merging is not. |
| **The 11 config layers** | **Moderate** | The merge precedence is user-visible behaviour. |
| **Tauri vs Slint for the shell** | **Low–moderate** | The GUI is a separate process speaking the protocol, so this is a client swap. *This is the whole point of ADR-0002.* |
| **The chosen voice engine** | **Low** | The trait boundary exists for this. |
| **The LLM provider abstraction** | **Low** | Isolated to the intent layer. |
| **FTS5 vs a vector index** | **Low** | An interface exists; `sqlite-vec` is an implementation swap. |

**The pattern:** the expensive decisions are all about *where authority lives*.
Everything the user can do is mediated by a small number of choke points, and
those choke points are what must not move. Everything else — the UI toolkit, the
model, the vector index — is deliberately behind an interface so it can change.

---

## 7. What did we discover that was NOT in the original requirements?

This is the section the brief specifically asked for. Twelve items, each of which
would have been discovered late and expensively if not found in research.

### 7.1 Requirements that were missing

1. **Cost/budget enforcement (NR-01).** The brief never mentions cost. A personal
   assistant making scheduled LLM calls has an unbounded financial exposure, and
   a misconfigured cron expression is an unbounded liability. A *hard* rule
   follows: a scheduled task cannot be created without a spend ceiling.
2. **Sensitive-data egress control (NR-02).** Health data, job applications, and
   message bodies must not transit a third-party model without explicit
   per-flow consent. Nothing in the brief addressed data leaving the machine.
3. **Multi-user / profile isolation (NR-04).** The brief wants
   general-purpose open-source software *and* cloud deployability — both imply
   more than one user — while the config model is implicitly single-user.
   Retrofitting tenancy is the classic expensive mistake.
4. **Idempotency as a first-class primitive (NR-05).** Browser submissions, job
   applications, and messaging all have irreversible duplicate side effects. Not
   mentioned in the brief; it is a core architectural concern.
5. **Backup, restore, and portable export as a product feature (NR-03).**
   Durability is a *claim*; restore is the *proof*. And the migration path is the
   highest-risk write path in the system.
6. **Update and supply-chain integrity for the *installed* product (NR-08).** The
   install runs third-party models, browser builds, and MCP servers. Provenance
   verification is a trust feature, not a CI detail.
7. **Internationalisation and locale correctness (NR-06).** A product that
   schedules things must handle timezones, DST, and locale-aware formatting
   correctly. A timezone bug makes a personal assistant unusable.
8. **Accessibility as an acceptance criterion (NR-07).** A daily-driver
   personal/health tool used in long sessions carries an accessibility
   obligation regardless of the user's own disability status.
9. **Provenance and confidence on AI-derived content (NR-09).** "Never blindly
   trust AI-generated memory" is a requirement in the brief, but making it real
   needs an *enforced data distinction*, not a convention.
10. **An information-capture loop (NR-10).** Every listed domain is
    knowledge-shaped, not just action-shaped. Nothing in the brief covers
    clipboard/file/URL capture → organise → recall, which is a distinct loop
    from workflow execution.

### 7.2 Facts discovered that invalidate widely-repeated advice

11. **MCP is no longer session-based.** Spec `2026-07-28` removed
    `initialize`, `Mcp-Session-Id`, SSE resumability, and server-initiated
    requests, and **deprecated Sampling, Roots, and Logging** with a 12-month
    window. Any architecture document citing the session-based model is
    describing a two-revisions-old protocol. This changes both our integration
    design (statelessness *helps* our security posture) and our long-running-task
    story (→ the Tasks extension).
12. **Microsoft explicitly excludes Svelte from TypeScript 7.** npm's `latest` is
    7.0.2, but the 7.0 announcement says Svelte projects "will need to continue
    using TypeScript 6.0 for now", and `svelte-check` peers confirm it. A
    "just use the latest" policy would have shipped a broken type-checking path.

### 7.3 External constraints that shape the product

13. **Signal has no API at all**, and `signal-cli` self-declares a **3-month**
    support window. A platform on the user's integration wishlist is simply not
    buildable.
14. **Discord self-bots are categorically forbidden** — termination, not "risk of
    termination" — and the platform **prohibits even soliciting a user's token**.
15. **Telegram ToS §1.5 prohibits using Telegram-obtained data for AI
    development/deployment.** For an AI assistant reading a user's messages,
    this is a **legal gate**, not a technical detail. Hence the interim decision
    to ship Telegram as notification-output-only.
16. **WhatsApp's Cloud API forbids "personal, family, or household purposes"** —
    which is arguably what a personal assistant is. The correct mechanism (3P
    Agents) is beta and **has no public developer documentation**. Hence deferral.
17. **Chrome 136+ blocks CDP attach to the default browser profile.** Browser
    automation must own a dedicated profile. This is a technical impossibility
    now, not a security preference.
18. **Professional-UI GUI grounding accuracy is ≈61.6 %** (and the original
    paper's headline was **18.9 %**). Visual grounding therefore **cannot** be
    primary — a 1-in-3 failure rate on a "Submit payment" click is unacceptable.
    Accessibility-tree grounding is both safer and dramatically cheaper.
19. **SQLite ≤ 3.51.2 has a documented corruption bug** (WAL-reset), fixed in
    3.51.3. Fedora 44 ships 3.51.2 — *below the fix* — and a durable task queue is
    exactly the multi-connection write workload that triggers it. Hence: bundle
    SQLite ≥ 3.51.3 and pin it in a test.
20. **Piper changed licence MIT → GPL-3.0**, and its eSpeak-NG phonemizer is also
    GPL. **Coqui/XTTS is non-commercial with a viral derivative clause** and its
    code is two years stale. **Kokoro is Apache-2.0.** Any local-TTS plan built on
    pre-2024 knowledge would have shipped a licence violation.
21. **Picovoice Porcupine's free tier ended 2026-06-30** and **openWakeWord's
    weights are CC-BY-NC-SA (non-commercial)** — while its *code* is Apache-2.0,
    which is not obvious. Wake-word selection is a licensing minefield.
22. **NVIDIA's model licences are not uniform.** `parakeet-tdt-0.6b-v3` and
    `canary-1b-flash` are CC-BY-4.0; the flagship-sounding **`canary-1b` is
    CC-BY-NC-4.0, non-commercial.** And `NVIDIA/NeMo` now 301-redirects to
    `NVIDIA-NeMo/Speech`. Assuming "NVIDIA model" means one thing would have
    shipped non-commercial weights.
23. **The Rust scheduler ecosystem has rotted.** `clokwerk` (2022),
    `job_scheduler` (2020), `lifeguard` (2020), `sailor` (2019),
    `rusty-scheduler` (2021) are all dead; `tokio-cron-scheduler` has no SQLite
    backend. Only `croner` and `cron` are alive, and only `croner` documents DST
    semantics. **"Effect for Rust" does not exist** — `effect-rs` is a name squat
    with 32 lifetime downloads and a 404 repository.
24. **"Rust has no Temporal" is no longer true.** `temporalio-sdk` hit **1.0.0 on
    2026-09-04**, and Restate has a first-party Rust SDK with a single-binary
    server. We still reject both locally — but the *reason* is deployment weight,
    not ecosystem immaturity, which materially changes the cloud story.
25. **`ort` (ONNX Runtime for Rust) has never released 2.0 stable** — newest
    stable is 1.16.3 from 2023-11-12. Every modern ONNX-based Rust crate depends
    on a release candidate.
26. **Anthropic, OpenAI, and LangChain's own team all independently concluded
    that agent frameworks add abstraction that should be removed** — and
    converged on Session / Harness / Sandbox, which is exactly our task table +
    thin loop + subprocess model. The "use a framework" default is contradicted by
    the framework vendor.
27. **A measured claim we could not make.** A public benchmark of
    LangChain/LangGraph overhead exists but is single-author and unreplicated. We
    therefore do **not** cite a latency number — the decision rests on primary
    sources. Recorded because "we had a number and chose not to use it" is a
    finding.

---

## 8. The three things most likely to be wrong

If this plan is wrong, it is most likely wrong about these:

1. **The approval UX (1.5).** Entirely unvalidated. Security-correct and
   user-hostile is a real possibility, and users disable security features.
2. **"Disabled = zero" surviving contact with a large frontend (3, §1.1).** A
   webview-enabled GUI, a bundled browser, and ML models all fight this. The CI
   check is designed to catch it, but the *temptation* grows monotonically.
3. **Tauri remaining the right call at scale (1.2).** Fine at Phase 6, unclear at
   Phase 20. The mitigation (separate process) is good, but it does not help if
   the webview's *behavioural* divergence bites harder than its memory cost.

Each has a named owner, a measurement, and a point at which it is checked.
