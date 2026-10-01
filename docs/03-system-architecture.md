# 03 — System Architecture

Status: **Draft v0.1** · Decisions referenced as ADR-NNNN live in
`09-decisions.md`.

---

## 1. The shape, and why it is not the shape in the brief

The brief suggested:

```
Interfaces → Application/Intent → Task/Workflow → Policy/Governance
→ Capability → Adapter/Provider → Platform/Infrastructure
```

That ordering is **almost** right, and the two places we change it are the
places that matter most.

**Change 1 — Policy is not a layer in the chain; it is a mandatory gate on
every arrow.** A linear "policy layer between workflow and capability" is a
design where a code path can route around it. Policy must be a non-bypassable
interceptor at the capability boundary, so that *no* call reaches an adapter
without evaluation. Concretely: policy is enforced inside the capability
dispatcher, not above it.

**Change 2 — Verification is a first-class stage, and it sits between execution
and completion.** The brief's loop ends at "report result". A system that acts
on the world must confirm the world changed as intended, or report that it did
not. Verification is not a detail of execution; it is a stage with its own
records.

**Change 3 — Identity/Actor and State are elevated to first-class concepts.**
The brief listed Intent · Task · Policy · Capability · Audit. That is missing two
things the product cannot work without:

- **Identity/Actor** (ADR-0027). As the system gains actors — human, AI, system,
  integration, scheduled task, external event — the question of *who is acting,
  on whose authority* must be a first-class value carried on every action, not an
  implicit field. Without it, authority leaks into the capability layer, which is
  the confused-deputy failure (TH-04) in its purest form.
- **State** (ADR-0028). As state accumulates across tasks, schedules, memory,
  documents, config, policy, audit, credentials and budgets, persistence
  decisions will scatter unless state is declared, classified
  (`critical` / `authoritative` / `derived` / `ephemeral`), and given exactly one
  owner. The classification *is* the answer to "which state may the model write?"

Everything else is kept.

```
┌──────────────────────────────────────────────────────────────────────┐
│  INTERFACES  (clients — all disposable, all replaceable)              │
│  Desktop GUI · TUI · CLI · Voice · Messaging/DM · Programmatic API    │
└───────────────────────────────┬──────────────────────────────────────┘
                                │  one local protocol (JSON-RPC 2.0)
                                │  UDS / named pipe · TCP only in cloud mode
┌───────────────────────────────▼──────────────────────────────────────┐
│  DAEMON  (the only long-lived process)                               │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ IDENTITY & ACTOR — first-class (ADR-0027). WHO is acting.      │  │
│  │   Human · Ai(delegated) · System · Integration · Scheduled ·   │  │
│  │   External. Resolved by policy, never by an adapter.           │  │
│  │   An Ai actor has exactly the authority of the Human that      │  │
│  │   delegated to it, intersected with task policy. Never additive.│  │
│  └────────────────────────────────────────────────────────────────┘  │
│                              │ Actor                              │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ INTENT LAYER — probabilistic. Understands, proposes.            │  │
│  │ ══ may NOT: write non-derived state (ADR-0028) ══              │  │
│  │ ══ may NOT: be an authority — acts UNDER delegation ══         │  │
│  │   • intent classification (suggested)                           │  │
│  │   • plan synthesis (suggested)                                  │  │
│  │   • tool selection (suggested)                                  │  │
│  │   • element grounding (suggested)                               │  │
│  │   ══ may NOT: call an adapter, write state, grant permission ══  │  │
│  └───────────────────────────┬────────────────────────────────────┘  │
│                              │ Proposal (typed, validated)            │
│  ┌───────────────────────────▼────────────────────────────────────┐  │
│  │ TASK / WORKFLOW ENGINE — deterministic. Owns the truth.        │  │
│  │   Conforms to the 12 normative properties in ADR-0029.         │  │
│  │   • task table (durable, transactional, sync=FULL)             │  │
│  │   • scheduler (croner + jiff, explicit misfire policy)         │  │
│  │   • state machine + lease/heartbeat + orphan recovery          │  │
│  │   • idempotency ledger                                         │  │
│  │   • budget enforcement (NR-01)                                 │  │
│  │   • cancellation propagation (CancellationToken)               │  │
│  │   • supervision: every task is a child of a supervised actor   │  │
│  │   • NEVER inherits an approval across a retry (TP-6)           │  │
│  └───────────────────────────┬────────────────────────────────────┘  │
│                              │ Actor + Validated ActionRequest                    │
│         ╔════════════════════▼════════════════════════════════════╗   │
│         ║  POLICY / GOVERNANCE — deterministic, non-bypassable    ║   │
│         ║  Evaluates (actor, capability, params, data classes,              ║   │
│         ║              task context)                                        ║   │
│         ║  • AUTHORITY: what MAY this actor do?                             ║   │
│         ║  • capability permission (per task × capability × param)║   │
│         ║  • risk classification; unknown ⇒ HIGH ⇒ gated          ║   │
│         ║  • approval bound to a digest (incl. actor)                       ║   │
│         ║  • data-egress classification (NR-02)                   ║   │
│         ║  • redaction policy                                     ║   │
│         ║  • budget check                                         ║   │
│         ║  • audit record (before AND after)                      ║   │
│         ║  ✗ FAILS CLOSED — on any error, deny.                   ║   │
│         ╚════════════════════┬════════════════════════════════════╝   │
│                              │ Authorised CapabilityInvocation          │
│                              │  { actor, task_id, step_key,                 │
│                              │    capability_id, adapter_id, params,  │
│                              │    data_classes, idempotency_key,   }│
│                              │    deadline, cancellation, policy_ctx}│
│  ┌───────────────────────────▼────────────────────────────────────┐  │
│  │ CAPABILITY LAYER — contracts, no knowledge of *who* calls      │  │
│  │   (authority was settled by policy; a capability that          │  │
│  │    learns its caller becomes a confused deputy — TH-04)        │  │
│  │   • registry: id, version, risk class, cost class, isolation    │  │
│  │   • dispatcher: the ONLY route to an adapter                   │  │
│  │   • per-capability contract tests                              │  │
│  └───────────┬──────────────────────────────┬─────────────────────┘  │
│              │ Tier 0 in-process            │ Tier 1/2 subprocess / │
│              │                              │ MCP remote           │
│  ┌───────────▼──────────────┐  ┌────────────▼──────────────────────┐  │
│  │ ADAPTER / PROVIDER LAYER │  │ EXTERNAL CAPABILITY PROCESSES     │  │
│  │  • ASR: sherpa-onnx,     │  │  • browser driver (opt-in)        │  │
│  │          parakeet, cloud │  │  • third-party capabilities       │  │
│  │  • TTS: kokoro, espeak   │  │  • MCP servers (untrusted)        │  │
│  │  • LLM: provider-neutral │  │  • copyleft components (subproc)  │  │
│  │  • messaging providers   │  │                                 │  │
│  │  • storage repos         │  │                                 │  │
│  └───────────┬──────────────┘  └──────────────────────────────────┘  │
│              │                                                        │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ STATE — first-class (ADR-0028). Classified regions.            │  │
│  │   critical: tasks·schedules·audit·dedupe (sync=FULL)           │  │
│  │   authoritative: profile·config·policy·health·budget           │  │
│  │   derived: summaries·entities·embeddings (NEVER auth.)         │  │
│  │   ephemeral: in-flight ctx  │ NEVER: credentials               │  │
│  └────────────────────────────────────────────────────────────────┘  │
│              │                                                        │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  ▼────────────────────────────────────────────────────────────────┐  │
│  ┌───────────▼─────────────────────────────────────────────────────┐  │
│  │ PLATFORM / INFRASTRUCTURE — the ONLY place OS specifics live    │  │
│  │  fs · process mgr · credentials · notifications · audio ·       │  │
│  │  network · single-instance lock · autostart · packaging         │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  CROSS-CUTTING: config layering · observability · migration  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 2. Dependency direction (the rule that makes the boundaries real)

**The one rule:** *dependencies point inward, toward the core, and never
sideways between layers.*

```
platform  ──►  (nothing depends on platform except platform)
adapters  ──►  capability contracts
capability ──► policy contracts, task contracts
task       ──► policy, storage ports
intent     ──► capability contracts (read-only, for planning only)
daemon     ──► all of the above
interfaces ──► protocol types ONLY  (never domain types directly)
```

Enforcement, in order of strength:

1. **Workspace-level crate dependency rules.** Each crate is a workspace member;
   the `Cargo.toml` `[dependencies]` list is the enforcement point. A layer
   violation is a compile error, not a review comment.
2. **`cargo deny` / `cargo vet`** for supply-chain and duplicate policy.
3. **A CI grep gate:** `cfg(target_os)` / `cfg(windows)` / `std::env::consts::OS`
   may appear **only** in `crates/platform-*`. Any occurrence elsewhere fails
   the build. This makes NFR-05 machine-checked rather than aspirational.
4. **Code review** with the ADR list as the checklist.

**Interfaces get a special rule:** an interface may depend on the *protocol
types* crate and on nothing else. It cannot import domain types. This is what
makes IR-2 (business logic exactly once) true rather than aspirational — a GUI
cannot reimplement a rule, because it cannot see the rule's types.

---

## 3. Process topology

One process, by default. Exceptions are explicit and justified.

```
┌─ user session ────────────────────────────────────────────────┐
│                                                                   │
│  orxnud  (the daemon)  ── the only writer, the only authority ──│
│    ├── config, task table, memory, audit   (SQLite, one file)   │
│    ├── policy engine                                               │
│    ├── capability dispatcher ──► Tier 0 (in-process adapters)    │
│    │                          └─► Tier 1 (subprocess, JSON-RPC)  │
│    │                          └─► Tier 2 (MCP remote, opt-in)    │
│    └── HTTP listener  (cloud profile only; off by default)       │
│                                                                   │
│  orxnu-gui   ─┐                                                 │
│  orxnu-tui    ├─ thin clients over UDS / named pipe              │
│  orxnuctl     ┤  (CLI)                                           │
│  voice I/O   ─┘  (voice input/output lives in the daemon;        │
│                   clients render)                                │
└───────────────────────────────────────────────────────────────────┘
```

**Why a daemon at all?** The brief asks for GUI + TUI + CLI + voice + messaging
over one capability set. Three requirements force the split:

1. **Persistence of scheduled work.** A GUI window closing must not kill
   tomorrow's 07:00 job. Something must outlive the UI.
2. **Single-writer discipline.** SQLite has one writer. One writer is easier to
   reason about than N writers contending, and it is where the task table's
   atomic claim lives.
3. **Failure containment.** An adapter that segfaults in the daemon takes the
   whole product down. A subprocess takes only itself.

**Why a GUI process is separate from the daemon:** the WebViewGTK/WebView2
web process is the largest memory consumer in the product, and the brief's NFR-01
demands that a CLI-only user not pay for it. Keeping the shell out-of-process
makes "GUI cost" literally opt-in.

---

## 4. The local protocol

**JSON-RPC 2.0 over a Unix domain socket (Linux/macOS) or named pipe
(Windows).** In cloud profile only, the same frames travel over HTTP.

Rationale, and the alternatives genuinely considered:

| Concern | Why UDS/named-pipe + JSON-RPC wins |
|---|---|
| One protocol stack | JSON-RPC 2.0 **is** MCP's wire format. Local client, MCP client, and remote API share framing, error codes, and auth vocabulary. One implementation, one test suite. |
| Authorization | A UDS file has filesystem permissions. That *is* the authorisation boundary, enforced by the kernel. A loopback HTTP port has neither identity nor a natural ACL. |
| Deployment | No port allocation, no "which port is it on", no firewall prompts, no TLS ceremony for a socket that only this user can open. |
| Streaming | Notifications over a framed stream handle progress and voice partials without a WebSocket layer. |
| Cloud | The same frames over HTTP with mTLS/OAuth is a thin adapter, not a second protocol. |

**Rejected:** a bespoke binary protocol (no ecosystem, no interop, no reason);
gRPC/protobuf (codegen, poor fit for dynamic tool schemas, no local-socket
story); a WebSocket-first design (fine for cloud, needless for local).

**Versioning:** a `protocolVersion` in the handshake, plus **capability
negotiation** — a client asks what the daemon supports and adapts. Clients must
tolerate unknown methods and unknown fields. This is what stops the interface
layer from becoming a coupling point.

---

## 5. Deterministic vs probabilistic — the module contract

This is the single most important boundary in the system, so it is enforced
structurally, not by convention.

### 5.1 The rule

> **Intent may only produce a `Proposal`. A `Proposal` is inert data. Nothing
> happens until a deterministic component has validated, authorised, and
> recorded it.**

```rust
// The only shape the intent layer can emit. It has no methods that do anything.
pub struct Proposal {
    pub intent:      IntentKind,        // enum, closed
    pub steps:       Vec<ProposedStep>, // declarative
    pub rationale:   String,            // shown to the user
    pub confidence:  f32,               // shown to the user, gates nothing by itself
    pub provenance:  ModelProvenance,   // model, version, prompt hash, timestamp
}

// A Proposal is deserialisable but NOT constructible with side effects.
// There is no `Proposal::execute()`. There is no `impl Proposal { async fn run() }`.
```

### 5.2 The split, enumerated

| Deterministic (never touches a model) | Probabilistic (advisory only) |
|---|---|
| Permission grants/revocations | Intent classification |
| Policy evaluation | Plan synthesis |
| Approval issue + binding + verification | Step ordering suggestions |
| All state transitions | Summarisation, rewriting, tone |
| Transaction boundaries | Element grounding **candidates** |
| Scheduling, misfire, catch-up | Tool selection **candidates** |
| Retry, backoff, jitter | Intent confidence scores |
| Idempotency and dedup | Conversational phrasing |
| Audit log writes | Memory candidate extraction |
| Input + schema validation | Domain/entity extraction |
| Budget accounting | Classification of documents |
| Secret resolution, redaction | |
| Sandbox/isolation decisions | |
| Migration and backup | |

### 5.3 Why this is structural and not behavioural

Three mechanisms make the boundary non-bypassable rather than merely intended:

1. **Type-level.** The intent layer's output type has no method that can reach
   an adapter. It is *not possible* to write the unsafe code without
   deliberately constructing an authorised `CapabilityInvocation`, which only
   the policy layer's constructor can produce.
2. **Capability-scoped process isolation.** Intent-layer model calls run in a
   context with no credential handle, no filesystem grant, and no network
   egress beyond the configured provider endpoints. A prompt injection in a web
   page cannot make the model read a credential, because the model *has no
   access to one* — the same lesson Anthropic drew the hard way ("any untrusted
   code that Claude generated was run in the same container as credentials — so
   a prompt injection only had to convince Claude to read its own environment").
3. **Audit before and after.** Every authorisation is written *before* the call
   and the outcome *after*. There is no unlogged path.

---

## 6. The intent → execution loop

Illustrative, per the brief. Each stage names its owner and determinism.

```
 user utterance / click / CLI arg
        │
        ▼
 ┌─���────────────┐  PROBABILISTIC
 │  UNDERSTAND  │  transcribe → intent → Proposal {steps[], confidence}
 └──────┬───────┘
        │  Proposal is inert data
        ▼
 ┌──────────────┐  DETERMINISTIC
 │   VALIDATE   │  schema-conform? capability exists? params in range?
 └──────┬───────┘  fail → ask the user, never guess
        ▼
 ┌──────────────┐  DETERMINISTIC
 │  AUTHORISE   │  policy(capability, risk, params, data-class) → allow | gate | deny
 └──────┬───────┘  gate → bind approval to digest(capability, target, normalised params)
        ▼            and set a short expiry
 ┌──────────────┐  DETERMINISTIC
 │   SCHEDULE   │  persist task row(s) — durable BEFORE any side effect
 └──────┬───────┘  assign idempotency keys
        ▼
 ┌──────────────┐  PROBABILISTIC (per step) / DETERMINISTIC (state)
 │   EXECUTE    │  claim lease → invoke capability → record result
 └──────┬───────┘  (the probabilistic part is *inside* a capability;
        ▼           it may not produce the side effect itself)
 ┌──────────────┐  DETERMINISTIC
 │  VERIFY      │  did the world change as intended? observable postcondition
 └──────┬───────┘  no → retry (bounded) | dead-letter | report honestly
        ▼
 ┌──────────────┐  DETERMINISTIC
 │   REPORT     │  to the originating interface, in the user's language
 └──────┬───────┘
        ▼
 ┌──────────────┐  DETERMINISTIC
 │    PERSIST   │  authoritative state (strong) vs memory (derived, marked)
 └──────────────┘
        ▼
 ┌──────────────┐  feedback is *explicit only*
 │   LEARN      │  the user corrects → correction stored as authoritative
 └──────────────┘  model self-assessment is never stored as fact (NR-09)
```

**The loop is resumable at every deterministic stage**, because each one is a
transaction. A crash between any two stages leaves a task row in a state that
the recovery path understands. See ADR-0007 for the state machine.

---

## 7. Component inventory

### 7.1 Core (always present, no optional dependencies)

| Component | Responsibility |
|---|---|
| `orxnud-protocol` | Wire types for the local protocol. The **only** crate interfaces may depend on. |
| `orxnud-domain` | Pure domain types and invariants. Zero I/O, zero async. |
| `orxnud-store` | SQLite repositories, migrations, backup/restore. Owns the DB. |
| `orxnud-policy` | Permissions, risk classification, approval binding, egress control, budget. **Fails closed.** |
| `orxnud-task` | Task table, state machine, scheduler, leases, idempotency, dead-letter. **Must never be able to reach `orxnud-capability`.** |
| `orxnud-capability` | Registry, contracts, dispatcher, sandbox policy. Sits above `orxnud-task` in the graph; the direction *between* these two is open, the reverse edge is forbidden. |
| `orxnud-audit` | Append-only, tamper-evident journal. |
| `orxnud-config` | Layered configuration + schema versioning + migration. |
| `orxnud-obs` | `tracing` wiring, redaction, optional OTLP exporter. |
| `orxnud-daemon` | Composition root, supervision, lifecycle, single-instance lock. |

### 7.2 Optional (feature-gated; zero cost when disabled — CR-2)

| Component | Cargo feature | Cost when off |
|---|---|---|
| `orxnud-llm` | `llm` | No provider crates linked, no endpoints, no keys |
| `orxnud-voice-in` | `asr` | No ONNX/native libs, no models, no audio device opened |
| `orxnud-voice-out` | `tts` | as above |
| `orxnud-web` | `browser` | No browser binary, no profile dir, no CDP socket |
| `orxnud-mcp` | `mcp` | No MCP client, no server config parsing |
| `orxnud-msg` | `messaging` | No provider clients linked |
| `orxnud-domains-*` | per domain | No schedulers, no tables, no jobs |
| `orxnud-otel` | `otlp` | No OTLP exporter linked |

**Enforcement of CR-2:** a CI check asserts that a `default`-features build's
resident set and binary size do not change when optional features are added.
Drift beyond a stated threshold fails the build. This turns "optional" from a
claim into a measured property.

### 7.3 Platform adapters (one crate per OS concern, all behind traits)

`fs` · `process` · `secrets` · `notify` · `audio` · `net` · `single-instance` ·
`autostart` · `power` · `path-conventions`

### 7.4 Interfaces (thin clients)

`orxnu-gui` (Tauri+Svelte) · `orxnu-tui` (Ratatui) · `orxnuctl` (Clap) ·
`orxnu-mcp-host` (optional stdio bridge) · programmatic API crate

---

## 8. What is core, optional, platform-specific, provider-specific

| Class | Members |
|---|---|
| **Core** | protocol, domain, store, policy, task, capability, audit, config, obs, daemon. No provider, no OS, no model. |
| **Optional** | llm, asr, tts, browser, mcp, messaging, every domain, otlp. All feature-gated. |
| **Platform-specific** | Everything that touches the OS: paths, processes, keyrings, notifications, audio devices, autostart, single-instance. Behind traits, one crate per concern. |
| **Provider-specific** | Each LLM provider, each messaging platform, each ASR/TTS engine. One adapter crate each, behind a shared contract. |
| **Deployment-specific** | HTTP listener (cloud only), TLS, remote auth. Behind the same protocol. |
| **Third-party, untrusted** | MCP servers, third-party capabilities, user-installed plugins. Always Tier 1/2. Never in-process. |

---

## 9. Boundary explanations

**Why interfaces get only protocol types.** If a GUI could import domain types it
would eventually reimplement a rule to render a state it disagrees with, and the
bug would be a UI bug that is invisible to every test in the core. Protocol types
are a lossy, explicit projection; the loss is the point.

**Why the daemon is the only authority for state.** A second writer means a
second opinion about what is true. SQLite already permits only one writer, so
this constraint is *free* — and it converts an architectural hope into a
property of the storage engine.

**Why policy is inside the dispatcher, not above it.** A layer can be skipped by
a direct call. A type that only the policy layer can construct cannot.

**Why approval is bound to a digest, not to a session.** This is the mitigation
for *Loopjacking* — a human approves operation A while the implementation
executes operation B. The approval record carries
`(capability, target, normalised params, actor, timestamp, expiry)`; the digest
is re-verified immediately before execution and the call aborts on mismatch.
Approvals are short-lived, single-use, and never inherited by a retry.

**Why capabilities are not allowed to know their caller.** If `SendEmail` knew
it was being called by "the jobs workflow", then adding a new workflow required
auditing every capability. Caller-agnostic contracts mean the permission check
has exactly one place to live.

**Why external capabilities are subprocesses, not libraries.** A crashing
optional integration must not crash the core. A `cdylib` cannot give that: it
shares the address space, has no versioned ABI in Rust, and must be recompiled
against every host change. A subprocess gives crash containment, a language
boundary, a versioned contract, and — with the right sandbox — real isolation.

---

## 10. Deliberate non-architectures

Stated so later phases do not drift into them:

- **No plugin marketplace or capability economy.** Capability count is bounded
  by the user's patience and our review capacity.
- **No multi-agent swarm.** One agent, a thin loop, a bounded tool set, a
  max-turns cap. That is what Anthropic and OpenAI both converged on.
- **No hidden ambient authority.** No "the assistant knows it can do X because
  it did last time." Every invocation is authorised.
- **No ambient session in the protocol.** This is reinforced by MCP's own move
  to statelessness — ambient connection state is a confused-deputy risk.
- **No self-modifying behaviour.** Personalisation is configuration and data.
  Never code.
