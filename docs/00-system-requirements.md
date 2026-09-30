# 00 — System Requirements

Status: **Draft v0.1** · Research date: **2026-09-30** · No code exists yet.

This document states what OpenRayNux must *be*, in a form that later phases can
test against. Nothing here is a technology decision. Technology choices live in
`02-technology-evaluation.md`; the reasoning lives in `09-decisions.md`.

---

## 1. Vision restated as a testable statement

OpenRayNux is a **local-first personal AI operating layer**: a single long-lived
Rust process that owns the user's time, data and integrations, and a set of
surfaces (GUI, TUI, CLI, voice, messaging) that all drive the *same* capability
set.

The vision is falsifiable. It succeeds when a user can express an intent —
preferably by voice — and have a workflow complete with their attention required
only at genuinely irreversible points, without the user navigating between
files, apps, tabs, sites and messengers.

### 1.1 The non-goal that matters most

OpenRayNux is **not** a chat UI with tool calling bolted on. The distinguishing
property is that it must be useful with the LLM **turned off**. Every core
function — scheduling, persistence, policy enforcement, audit, capability
invocation, local automation — must function deterministically. See §6.

---

## 2. Functional requirements

### 2.1 Domains (each individually enable-able)

| ID | Domain | Notes on difficulty discovered in research |
|----|--------|--------------------------------------------|
| FR-01 | Time management | Calendar read/write. Provider-neutral; OAuth-heavy. |
| FR-02 | Job discovery & application assistance | Highest-risk domain: consequential, ToS-exposed, requires human approval gates. |
| FR-03 | Open-source contribution assistance | GitHub API. Auth via `gh`-style device flow. |
| FR-04 | Learning | Content acquisition + spaced repetition. Needs document ingestion. |
| FR-05 | Skills development | Similar to FR-04; shares the practice-scheduler capability. |
| FR-06 | Interview preparation | Combines FR-04/05 with voice (FR-30) and role-play. |
| FR-07 | Health / lifestyle | **Most sensitive data class.** See NR-01, SR-09. |
| FR-08 | Cognitive capability development | Mostly scheduling + practice loops over FR-05. |
| FR-09 | Social / messaging connectivity | Legally constrained per platform. See §5. |
| FR-10 | Day-to-day assistance | The "assistant" generalist case. |
| FR-11 | MCP / tool integration | Spec 2026-07-28. See ADR-0011. |
| FR-12 | Adaptive personalization | Config + memory, **not** code modification. See §7. |
| FR-13 | Automation & workflows | Durable task engine. See ADR-0007. |
| FR-14 | Voice interaction | Abstraction-first. See ADR-0014. |
| FR-15 | Digital task execution | Browser + local automation. See ADR-0015. |
| FR-16 | **Identity & actor resolution** | Every action carries a first-class actor and delegation chain. See ADR-0027. |
| FR-17 | **State classification & ownership** | Every state region is declared, classified, and singly owned. See ADR-0028. |

**No domain is mandatory.** A user with only FR-10 enabled must get a coherent,
fully functional product.

### 2.2 Capability composition (the composability requirement)

Requirements:

- **CR-1** Capabilities are independently enable-able at install *and* runtime.
- **CR-2** A disabled capability has **zero operational cost and zero reachable
  capability** (ADR-0030). It cannot execute, holds no credentials, starts no
  worker, consumes no model resources, performs no network activity, and adds no
  meaningful idle CPU/RAM. Build-time feature elimination additionally removes
  binary/storage cost where practical — an optimisation, not the guarantee.
  See `05-resource-performance-model.md` §4.
- **CR-3** Adding a capability must not require modifying the core. A first-class
  capability may live out-of-process and be registered by declaration alone.
- **CR-4** Two capabilities must never be able to observe or corrupt each other's
  private state without an explicit, policy-mediated grant.

Reference shape from the brief, which CR-1..4 make concrete:

```
SpeechToText   : faster-whisper | NeMo | whisper.cpp | sherpa-onnx | cloud
Messaging      : Signal | Telegram | Discord | WhatsApp | Matrix | email
Domains        : Jobs | Learning | Health | Open-source | ...
```

### 2.3 Interface requirements

- **IR-1** Every capability is reachable from every interface.
- **IR-2** **Business logic exists exactly once.** Interfaces are clients. This
  is the single hardest architectural constraint in the project and the reason
  for the daemon split (ADR-0003).
- **IR-3** Interfaces: desktop GUI, TUI, CLI, voice, messaging/DM, programmatic
  API. Mobile is a *future* consumer of the same API, not a separate codebase.
- **IR-4** An interface must be independently installable and independently
  disposable. Deleting the GUI must not lose data or break the CLI.
- **IR-5** Voice is a *modality*, not a separate application. It transcribes to
  the same intent path the text GUI uses.

### 2.4 Task lifecycle requirements

The task model must represent, durably and inspectably:

`short` · `long` · `scheduled` · `recurring` · `paused` · `cancelled` · `failed` ·
`retrying` · `waiting-for-user` · `waiting-for-external-system`

Additional, non-obvious but required (see §8, NR-05). The engine's **correctness
properties are normative and implementation-independent** (ADR-0029): TP-1 no
task silently disappears · TP-2 exactly-once where required, at-least-once
otherwise · TP-3 cancellation is observable · TP-4 restart recovers durable
work · TP-5 expired leases cannot execute · TP-6 retries never inherit
approvals · TP-7 power loss cannot corrupt task state · TP-8 scheduling is
deterministic under time manipulation · TP-9 catch-up is bounded and explicit ·
TP-10 bounded resources · TP-11 dead-lettering is terminal and visible ·
TP-12 every side effect is accounted for.

- **TL-1** A scheduled task must not silently disappear because the application
  was closed. Catch-up is explicit and per-schedule configurable.
- **TL-2** Every task state transition is a durable, atomic, transactional write.
- **TL-3** No task performs an unrecorded external side effect.
- **TL-4** Any task can be inspected while running: what it is doing, what it has
  already done, what it will do next, and what it is waiting for.
- **TL-5** Cancellation is honoured at a bounded latency for every capability, and
  cancellation is *itself* durable (a cancelled task does not resume after
  restart).

---

## 3. Non-functional requirements

| ID | Requirement | How it will be falsified |
|----|-------------|--------------------------|
| NFR-01 | Fast | Cold/warm startup and idle RAM budgets in `05-…` §2. Measured, not asserted. |
| NFR-02 | Resource efficient | Same budgets, per-capability, with a "disabled = zero cost" assertion in CI. |
| NFR-03 | Reliable | Failure-injection suite; no silent data loss; every task recoverable. |
| NFR-04 | Secure | Threat model in `04-…`; LLM is never an authority. |
| NFR-05 | Portable | Portable core has **zero** `cfg(target_os)` branches outside `platform` crates. Enforced in CI by grep + review. |
| NFR-06 | Observable | Structured logs + traces locally, OTLP-exportable optionally, no telemetry server required. |
| NFR-07 | Extensible | A new capability implemented purely as an adapter crate + manifest. |
| NFR-08 | Customizable | Second user customizes via config/data only, **zero** source forks. |
| NFR-09 | Privacy-conscious | Data minimisation by default; explicit consent per outbound data flow. |
| NFR-10 | Recoverable | Crash, power loss, and bad-migration drills produce no unrecoverable state. |
| NFR-11 | Offline where practical | Core + all local capabilities work with the network cable pulled. |
| NFR-12 | Cloud-deployable | Same binary, same capability set, different deployment envelope. |
| NFR-13 | Non-technical-user-suitable | Installer, guided setup, meaningful errors, no CLI required. |

---

## 4. Explicitly out of scope (for now)

Stated so that later phases do not quietly expand scope:

- A hosted multi-tenant SaaS product with billing.
- Mobile apps (the API must *anticipate* them; the apps are not built).
- A general-purpose agent marketplace.
- Training or fine-tuning any model.
- Any "AI browser" that replaces the user's own browser session by default.
- Cross-compiling to Windows from Linux as a supported build path.

---

## 5. Constraint discovered in research that constrains requirements

These are not preferences; they are external facts that limit what FR-02,
FR-09, FR-07 and FR-15 can promise. Full detail in
`01-architecture-research.md` §5 and `docs/sources.md`.

| Platform | Hard constraint | Consequence for OpenRayNux |
|----------|-----------------|----------------------------|
| Signal | **No API exists.** `signal.org/docs/` publishes protocol specs only. `signal-cli` self-declares a 3-month support window. | No Signal integration in the general product. If ever built: user-owned, single-user, opt-in, alert-only. |
| Discord | Self-bots explicitly forbidden; termination is the stated consequence. | Bot-token surface only. Never user-account. |
| Telegram | Bot API cannot read the user's existing chats. **ToS §1.5 prohibits using Telegram-obtained data for AI development/deployment.** | Bot API is the only sanctioned path, and it carries a **legal review gate** before any AI inference on message content. |
| WhatsApp | Cloud API: 24-hour service window (templates only outside it); **ToS forbids "personal, family, or household purposes"**; mandatory human escalation path. | Cloud API is structurally wrong for a *personal* assistant. WhatsApp 3P Agent platform is beta and undocumented. Defer. |
| Web (browser) | Chrome 136+ **ignores** `--remote-debugging-port` against the default profile. | We must own a dedicated browser profile. Cannot piggyback the user's daily browser. |
| Web (grounding) | Best reported professional-UI GUI grounding accuracy ≈ 61.6% (ScreenSpot-Pro family). | Visual grounding **cannot** be the primary mechanism. Accessibility-tree grounding must be. |

---

## 6. Determinism boundary (first-class requirement)

This is the requirement that makes the rest safe. It is stated here, not buried
in the threat model, because it determines module boundaries.

**Deterministic — must not depend on a model:**

- Permission grants and revocations
- Policy evaluation and enforcement
- Approval gates and their binding to a specific action
- All state transitions and transaction boundaries
- Scheduling, misfire and catch-up decisions
- Retry, backoff, idempotency and deduplication
- Audit logging
- Input validation and schema conformance
- Budget enforcement (see NR-01)
- Secret handling and redaction

**Probabilistic — model output is advisory:**

- Intent interpretation
- Summarisation and rewriting
- Classification and routing *suggestions*
- Planning and step decomposition
- Conversational phrasing
- Element grounding *suggestions* (must be validated before action)

**The invariant:** *the model proposes; a deterministic engine disposes.* No
model output may directly cause a side effect, grant a permission, or alter
authoritative state. Any path from model output to side effect passes through
validation, policy evaluation, and — for consequential actions — a human approval
bound to a digest of the exact action.

---

## 7. Personalization model requirement

The user must be able to radically change OpenRayNux without forking it.

Distinct, separately-versioned layers (see ADR-0018):

1. **Application defaults** — shipped, immutable at runtime
2. **Schema/version metadata** — for migration
3. **User configuration** — settings
4. **User profile** — identity, locale, timezone, working hours
5. **Domain configuration** — per-domain behaviour
6. **Provider configuration** — endpoints, models, credentials references
7. **Capability configuration** — which implementations are enabled
8. **Policy** — permissions, approval thresholds, redaction rules
9. **Memory** — preferences and derived knowledge (never authoritative)
10. **Workflow** — user-authored task definitions
11. **Extension** — external capabilities

Layers 1–8 are configuration and are strictly layered (later overrides earlier,
with the merge made explicit and inspectable). Layers 9–10 are *data*. Layer 11
is *code*, and is therefore a trust decision, not a configuration decision.

Requirement: **import/export of layers 3–10 as one portable, versioned document.**

---

## 8. Requirements discovered during research (not in the original brief)

These were identified as necessary during the research phase and are recorded
here as requirements. Full rationale in `10-open-questions.md` §Q-OPEN-01.

| ID | Requirement | Why discovered |
|----|-------------|----------------|
| NR-01 | **Cost/budget enforcement.** Per-provider, per-model, per-task-class spend ceilings with hard circuit-breakers. | Scheduled LLM tasks are the dominant cost of this product and the brief never mentions cost. A runaway recurring task has a direct financial consequence. |
| NR-02 | **Sensitive-data egress control.** Domain-tagged data (health, job, financial) must not transit a third-party model without explicit per-flow consent. | FR-07 health data meets FR-09 messaging data meets LLM providers. Classifying at the provider boundary is the only reliable place to enforce this. |
| NR-03 | **Backup, restore and portable export** as a product feature, including pre-migration snapshots. | SQLite durability is a *claim*; restore is the *proof*. Migrations are the highest-risk write path in the system. |
| NR-04 | **Multi-user / profile isolation** in the config and data model, even if v1 is single-user. | The brief wants open-source general-purpose software and cloud deployability, which both imply >1 user. Retrofitting tenancy into a single-user data model is the classic expensive mistake. |
| NR-05 | **Idempotency and duplicate-submission protection** as a first-class primitive of every capability, not per-integration improvisation. | Browser form submission, messaging, and job applications all have irreversible duplicate side effects. |
| NR-06 | **Internationalisation and locale correctness** — timezone, DST, locale-aware formatting and sorting, RTL readiness. | The product schedules things and speaks to users. A personal assistant with a timezone bug is unusable. |
| NR-07 | **Accessibility as a first-class acceptance criterion** for all interfaces. | A daily-driver personal/health tool used for long sessions has an accessibility obligation regardless of the user's own disability status. |
| NR-08 | **Update and supply-chain integrity** for the *installed* product, not just CI. | The install runs third-party MCP servers, models and browser builds. The user's trust depends on verifiable provenance. |
| NR-09 | **Provenance and confidence marking on all AI-derived content** entering the knowledge store. | AI-generated memory that is later treated as fact is a documented failure mode. Requires an explicit, enforced data distinction — not a convention. |
| NR-10 | **Information-capture loop** (clipboard, files, URLs → organised, retrievable knowledge) as a distinct product loop from workflow execution. | The domains are knowledge-shaped, not just action-shaped. No capability covers the read/organise/recall path. |
| NR-11 | **Actor provenance for every action.** Who requested it, on whose authority, under which policy version, with which credential reference, as part of which task. | Actions come from six actor kinds (human, AI, system, integration, schedule, external event). Without a first-class actor, authority leaks into the capability layer — the confused-deputy failure (ADR-0027). |
| NR-12 | **Single-owner, classified state.** Every state region has exactly one writer, an explicit consistency class, and a retention policy. | Persistence decisions scatter without this, and the answer to "which state may the model write?" becomes ambiguous (ADR-0028). |

---

## 9. Verification criteria for this requirements document

This document is considered settled enough to build against when:

- Every FR maps to at least one capability in `07-extension-capability-model.md`.
- Every NFR maps to a measurable budget in `05-resource-performance-model.md`.
- Every constraint in §5 has a corresponding ADR or open question.
- Every NR in §8 has an owner and a phase assignment in `09-decisions.md` §9.

**Unsettled:** items marked `OPEN` in `10-open-questions.md`.
