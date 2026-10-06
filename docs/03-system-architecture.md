# 03 — System Architecture

Status: **Draft v0.4** · Decisions referenced as ADR-NNNN live in
`09-decisions.md`. Reconciled **2026-10-05** against `HEAD`
(`1721761`) and CI run `37343986458`.

**How to read this document now.** Sections 1–6 and 9 describe the architecture as
*implemented*. Section 7 is the component inventory and has been corrected against the
workspace manifest. Where a row describes something that does **not** exist, it is marked
**FUTURE** and says so — this document used to present the whole planned system in the
present tense, which made it impossible to tell a reader what was real. That distinction
is now load-bearing rather than cosmetic, because the milestone boundary in
[`12-verification-register.md`](12-verification-register.md) depends on it: the 4c
*governance core* and both its continuation and observation/disclosure wiring are
delivered.

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

**JSON-RPC 2.0 over a Unix domain socket.** In cloud profile only (FUTURE — no cloud
profile exists), the same frames would travel over HTTP.

**Correction, 2026-10-05.** This previously read "or named pipe (Windows)". There is no
named-pipe backend. `orxnud-platform-ipc` is a Unix socket on Unix and a **refusal** on
every other platform: `bind`, `connect` and `Listener::accept` all return
`IpcError::Unsupported`. A named pipe needs `CreateNamedPipeW` and `CreateFileW`, which
means `windows-sys` and `unsafe`, and gate **G4** forbids `unsafe` outside a platform
crate that has opted in. ADR-0003 chose UDS/named-pipe as the *shape*; only the Unix half
is built. A Windows pipe is an addition behind `Listener`, not a redesign.

**Peer identity (ADR-0051).** The transport also establishes *who a caller is*, because the
actor model needs a boundary that produces those actors and no layer above the transport
can name a peer it has not asked the kernel about. On Linux, `accept` reads `SO_PEERCRED`
and records it on the stream; the daemon compares that uid against the bound endpoint's owner
**before reading a request**, so an unauthenticated caller never reaches parsing.

```text
accept()  ->  authenticate(stream, owner)  ->  AuthenticatedPrincipal | refusal
                                                     |
                                       (then, and only then)  v
                                               read a request, route it
```

The result is an `Option` with no default: a fabricated uid is the failure this prevents, so
`LocalStream::principal()` returns an error where no identity was established. The uid is
compared and then discarded — it never becomes a `UserId`, an audit field, or an IPC error.

This is the platform crate's first `unsafe` (four lines, one function, gate **G4**'s opt-in),
because the safe wrappers do not expose `SO_PEERCRED`. `getpeereid(3)` would be the
equivalent on macOS and is **not** implemented: no CI exercises it, so it would be an
untested branch that looked like working authentication on a developer's laptop.

Protocol version is **1** (`orxnud-protocol::PROTOCOL_VERSION`), and it is exact: the
daemon's supported range is `1..=1`, so a version mismatch is refused rather than
best-effort parsed.

**The 14 shipped methods** (`crates/orxnud-protocol/src/method.rs`):
`daemon/status` · `daemon/version` · `capability/list` · `echo` · `capability/dispatch` ·
`capability/approve` · `task/create` · `task/list` · `task/claim` · `task/complete` ·
`task/cancel` · `task/propose` · `task/execute` · `task/ai-propose`.

`daemon/status` returns the runtime sandbox capability — the three guarantees and
`tier1_executable` — alongside the transport name. That is deliberate: the transport name
is a compile-time fact and says nothing about whether the host can isolate anything, and a
status line reading `sandbox backend: bwrap` on a host where every Tier-1 dispatch is
refused is exactly the kind of diagnostic that misleads.

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
| `orxnud-capability` | Registry, contracts, dispatcher, sandbox policy, the governed provider/proposal path. **Distinct from `orxnud-task`, and neither depends on the other** (ADR-0033); gate G2 enforces the direction. |
| `orxnud-audit` | Append-only, tamper-evident journal. |
| `orxnud-config` | Layered configuration + schema versioning + migration. |
| `orxnud-obs` | `tracing` wiring, redaction, optional OTLP exporter. |
| `orxnud-daemon` | Composition root, supervision, lifecycle, single-instance lock. |

### 7.2 Optional components — **FUTURE DESIGN, none of it exists**

The design below is ADR-0009, ADR-0011, ADR-0014, ADR-0015, ADR-0016 and ADR-0025. It is
retained because it is the shape those decisions imply, and it is marked because a reader
must not infer any of it from the workspace.

| Component | Cargo feature | Cost when off | Exists? |
|---|---|---|---|
| `orxnud-llm` | `llm` | No provider crates linked, no endpoints, no keys | **No** |
| `orxnud-voice-in` | `asr` | No ONNX/native libs, no models, no audio device opened | **No** |
| `orxnud-voice-out` | `tts` | as above | **No** |
| `orxnud-web` | `browser` | No browser binary, no profile dir, no CDP socket | **No** |
| `orxnud-mcp` | `mcp` | No MCP client, no server config parsing | **No** |
| `orxnud-msg` | `messaging` | No provider clients linked | **No** |
| `orxnud-domains-*` | per domain | No schedulers, no tables, no jobs | **No** |
| `orxnud-otel` | `otlp` | No OTLP exporter linked | **No** |

**Two corrections to what this section previously claimed.**

*The provider is not feature-gated, because there is no provider crate.* What exists is
`orxnud-daemon`'s `ProposalProvider` trait and one adapter inside the daemon,
`http_provider.rs`, which speaks OpenAI-compatible `chat/completions` over hand-written
HTTP/1.1 on `tokio` with `tokio-rustls`. It is always linked. A second provider, or a
provider moved into its own crate, is future work.

*"Enforcement of CR-2" is not enforced.* The paragraph claiming a CI check asserts that
resident set and binary size do not change when optional features are added described a
gate that does not exist — there is no feature matrix in `ci-gates.sh` or in
`.github/workflows/ci.yml`, and no committed baseline file. The underlying budget is
**unmeasured** (V-25), which V-25's own row already says. The claim is removed here rather
than softened, because a documented enforcement that does not exist is worse than an
admitted gap: it is the failure V-79 records, where a control was asserted as test-backed
with nothing behind it.

### 7.3 Platform adapters — five exist

| Crate | Concern | Absent platform behaviour |
|---|---|---|
| `orxnud-platform-fs` | Bounded reads, atomic writes, rooted jail, owner-only directories | — |
| `orxnud-platform-sandbox` | Tier-1 execution boundary and OS resource ceilings | Windows: binds the **refusing** `UnsupportedRunner`; no Job Object or AppContainer backend (ADR-0035, V-29) |
| `orxnud-platform-secrets` | Credential storage via the platform keyring | — |
| `orxnud-platform-notify` | Desktop notification | — |
| `orxnud-platform-ipc` | Local transport **and local peer identity** (ADR-0051) | Windows: **refuses**. No named-pipe backend, because that needs `windows-sys` and `unsafe`, and gate G4 forbids `unsafe` outside a platform crate that has opted in. Non-Linux Unix: transport works, **peer identity does not**, so the daemon refuses every connection rather than assume an owner |

**FUTURE:** `process`, `audio`, `net`, `single-instance`, `autostart`, `power`,
`path-conventions`. Single-instance enforcement currently lives in `orxnud-daemon` as an
instance lock rather than behind a platform trait.

Gate **G3** permits `cfg(target_os)` **only** inside these five crates, and gate **G7**
asserts the workspace member list matches this table. Both are enforced. G3's known blind
spot is recorded in V-29: it greps for `cfg`, not for a platform *API*, so unguarded
`std::os::unix` passed G3 and broke the MSVC build. That happened, was found on a hosted
runner, and is fixed (V-29).

### 7.4 Interfaces — one exists

| Interface | State |
|---|---|
| `orxnuctl` | **Ships.** Hand-written argument parser — `clap` is a workspace dependency and is deliberately **unused**, recorded in `crates/orxnuctl/Cargo.toml` as the smaller dependency for a closed verb set. Verbs: `version`, `doctor`, `task {create,list,claim,complete,cancel,propose,execute,ai-propose}`, `capability {run,approve}`, `provider credential {set,delete,status}` |
| `orxnu-gui` (Tauri 2 + Svelte 5) | **FUTURE** (ADR-0002, ADR-0005). No crate, no `package.json` |
| `orxnu-tui` (Ratatui) | **FUTURE** |
| `orxnu-mcp-host` | **FUTURE** (ADR-0010) |
| Programmatic API crate | **FUTURE** |

`orxnuctl` also runs against a **real** `orxnud` binary in `crates/orxnuctl/tests/cli_e2e.rs`
— 34 tests that spawn the shipped daemon and drive the whole product loop over the local
socket. Gate G2(b) restricts which internal crates the CLI may name, so a CLI verb cannot
reimplement a domain rule.

---

## 8. What is core, optional, platform-specific, provider-specific

| Class | Members | Exists? |
|---|---|---|
| **Core** | protocol, domain, store, policy, task, capability, audit, config, obs, daemon. No OS, no model. | **All ten** |
| **Provider adapter** | `orxnud-daemon/src/http_provider.rs` — one OpenAI-compatible HTTPS client. It lives in the daemon rather than its own crate, so the core-class row above is accurate only for the *other* nine. | **Yes, one** |
| **Optional** | llm, asr, tts, browser, mcp, messaging, every domain, otlp. All feature-gated. | **None** |
| **Platform-specific** | paths and bounded I/O, process isolation and ceilings, keyrings, notifications, local IPC. Behind traits, one crate per concern. | **Five crates** |
| **Provider-specific** | Each LLM provider, each messaging platform, each ASR/TTS engine. One adapter each, behind a shared contract. | **One adapter** |
| **Deployment-specific** | HTTP listener (cloud only), remote auth. | **None** — no cloud profile exists |
| **Third-party, untrusted** | MCP servers, third-party capabilities, user-installed plugins. Always Tier 1/2. Never in-process. | **None** |

TLS is the one piece of this table that arrived early and unremarked: the provider's
transport is `tokio-rustls` with `rustls-native-certs`, inside the daemon, not a
deployment-specific concern (ADR-0040, V-77).

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

**Phase 3: how the stages are enforced.** `orxnud-capability/src/dispatch.rs`
implements the `07-…` §4 order, and the ordering is structural rather than
conventional:

| Stage | Enforced by | Test |
|---|---|---|
| 1 AUTHORITY | `PolicyEngine::evaluate` step 0 — no authority root, no grant | `an_external_actor_is_refused_before_the_adapter_is_resolved` |
| 2 POLICY | `evaluate`, deny-by-default | `an_unknown_capability_is_refused` |
| 3 APPROVAL | digest recomputed from the action about to run; **single-use** since V-39 | `an_approval_for_a_different_target_is_refused`, `a_consumed_approval_cannot_authorise_a_second_dispatch` |
| 4 BUDGET | charged in `authorise` before the permit is recorded | `an_invocation_over_budget_is_refused_before_execution` |
| 5 CAPABILITY RESOLUTION | dispatcher registry + class check against the implementation | `a_capability_with_no_implementation_is_refused_at_stage_five` |
| 6 CREDENTIAL RESOLUTION | `CredentialBroker`, after 1–5 | `an_unauthorised_invocation_never_opens_the_secret_store` |
| 7 EXECUTION | `catch_unwind`, so a faulty adapter cannot kill the daemon | `a_panicking_adapter_does_not_take_down_the_dispatcher` |
| 8 VERIFICATION | `Verifier` trait, evaluated even when the adapter reports success | `a_misreporting_adapter_is_not_treated_as_success` |
| 9 AUDIT | `audit_pair` before the call; terminal record belongs to the caller | `the_audit_chain_records_the_authorisation` |

Two properties are worth stating because they are *not* obvious from the stage list:

- **Stages 1–4 run inside `orxnud-policy`, not in the dispatcher.** The dispatcher
  orchestrates and enforces ordering; policy decides. A dispatcher that reimplemented
  any of them would be a second authorization system, and the two would eventually
  disagree.
- **`authorise_for_dispatch` is the only way an invocation reaches the dispatcher.**
  `CapabilityInvocation` cannot be deserialised (ADR-0034) and its constructor demands
  policy's private seal (G2), so policy must hand the invocation out — and that method
  returns one *only* for a permit. There is no path from a refusal to an invocation.

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

## 9a. Where the implementation actually stands

Added 2026-10-05, because the rest of this document describes a system and a reader needs
to know which parts of it are built.

### Delivered and exercised

The governed path is real and tested end to end: `Dispatcher::dispatch` runs the nine
stages above, `PolicyEngine::authorise_for_dispatch` performs stages 1–4 inside the policy
crate so no second authorisation system can exist, and `CapabilityInvocation` cannot be
constructed outside `orxnud-policy` because its constructor demands a private seal
(ADR-0034). `CapabilityInvocation` does not derive `Deserialize`, so a forged invocation
cannot enter from JSON — demonstrated by a compile-fail test with a recorded `.stderr`.

Tier-1 execution runs through that path and nowhere else. A `Subprocess` adapter's
`invoke` **panics by design**, so a bypass surfaces as a loud failure rather than a silent
unsandboxed run, and gate G2 rejects `Command::new` anywhere in `orxnud-capability`. There
is deliberately no setter that takes a program and arguments, because that would be the
`dispatcher -> direct subprocess` bypass the whole design exists to prevent.

Three capabilities are registered (`crates/orxnud-daemon/src/lib.rs::shipped_declarations`,
one list so the registry, the bundles and the policy table cannot drift):

| id | Risk | Tier | Target | Idempotent | Approval |
|---|---|---|---|---|---|
| `text/word-count` | `Low` | `InProcess` | `None` | yes | none — a standing grant suffices |
| `filesystem/write-text` | `High` | `Subprocess` | `Required` | **no** | single-use, digest-bound, time-boxed |
| `filesystem/read-text` | `High` | `Subprocess` | `Required` | **no** | single-use, digest-bound, time-boxed |

Both `Subprocess` capabilities declare `Public -> Public` data classes, state a resource
budget (64 MiB, 16 processes, 1.0 core) and **require no control** — `ResourcePolicy.required`
is empty, so they run on a host that delegates nothing and record the gap rather than
refusing for no security gain. `read-text` additionally caps a read at 64 KiB, enforced
*by the read* and measured with a byte-counting reader, not inferred from an oversized file
being refused.

The provider path is real: `ProposalProvider` is provider-neutral, one adapter implements
it over HTTPS with `tokio-rustls` and `rustls-native-certs`, credentials are stored through
the platform secret store and resolved per request, and the capability menu handed to the
model is **walked from the registry** rather than hand-listed (ADR-0039). Proposals are
durable before approval (ADR-0038), approvals name their approver and bind the logical step
into a **v3** digest (ADR-0037, V-83), and the durable proposal records the model that
actually answered rather than a configured name (V-81).

### Multi-step composition: the boundary is now crossed (ADR-0047)

`AwaitingNextStep` is a task state, attempts and approvals are scoped to a logical step, and
`TaskRepository::claim_next_step()` is the only thing that advances a boundary.

`task/continue` is now the production caller, and `orxnuctl task continue` is how a user
reaches it. **One call crosses one boundary** — claim the next step, ask the provider what it
should do, persist the result as an ordinary durable proposal — and then stops, in
`WaitingForUser`, exactly where `task/ai-propose` leaves a task. It does **not** execute, so
a continued step re-enters `task/ai-propose` → approval → dispatcher → sandbox →
verification → audit with no continuation-specific shortcut. There is no loop here to bound:
each call is one boundary and at most one provider call, and `max_steps` remains the only
thing bounding a task's length (ADR-0043).

Three things had to be true before the call could exist, and each was a finding rather than
a design choice:

* **`max_steps` had to be settable.** It defaulted to 1 in the schema and `NewTask` had no
  field for it, so every task completed on its first verified effect and no task could reach
  a boundary at all. `task/create` takes an optional `max_steps`, defaulting to one,
  validated and never clamped, bounded at 64.
* **The approvals table had to be able to hold two steps.** The attempt counter resets at a
  boundary, so `attempt_no` restarts at 1 per step and `(task_id, attempt_no)` names two
  different approvals. `INSERT OR IGNORE` discarded step 2's silently. Schema **10** rebuilds
  `task_approvals` on `(task_id, step_no, attempt_no)`, the treatment `task_attempts` already
  had.
* **A terminal answer needed a name.** `{"done": true, "summary": ...}` is a second declared
  shape, not a capability, so it carries no target, no parameters and nothing that could be
  executed or smuggled past the allowlist. The runtime completes the task through the same
  fenced completion every other terminal report uses; `steps_completed` does not move.

If the provider cannot be asked after the boundary is crossed, the boundary is released and
the task is retryable — otherwise one outage would strand it holding a lease for a step that
will never be proposed. The generic claim path is deliberately still `Pending`-only, and a
test pins that.

### Observation and disclosure: wired, bounded, and separate from `PriorStepContext` (ADR-0048)

* **`PriorStepContext` is unchanged.** It carries step number, status and workspace-relative
  artifact paths into the provider request — never file contents, never prior
  `structured_output`, never prior verification text. `PriorStepContext` and the disclosure
  channel are deliberately two fields with two lifetimes: `prior_steps` is a re-derivable
  projection of committed rows, `disclosures` is ephemeral content that exists for one
  request. Widening one cannot widen the other.
* **The disclosure channel.** `ProposalContext::disclosures` is a `DisclosureBatch` — a
  newtype with a private field, so the only way to build one is from what
  `ObservationStore::take_for` released. It cannot be assembled from anything else.
* **The full flow**, which is now production code rather than an unreachable primitive:

  ```text
  task/ai-propose  proposes filesystem/read-text
  human approves   (RiskClass::High: grant + single-use, time-boxed, digest-v3 approval)
  task/execute     sandboxed read → independent verification
                   output_is_ephemeral + is_verified + Actor::Ai naming the configured model
                   → ObservationStore::retain, bound to (task, step, endpoint, model)
  task/continue    claims the next step; take_for(task, step+1, identity, now, ≤32 KiB)
                   → one DisclosureRecord per released blob, on its own minted correlation
                   → ProposalContext::disclosures → the provider request
  ```

* **What may leave:** the verified output of an approved `filesystem/read-text`, as whole
  blobs, once, to the identity that asked for the read, for the immediately following step.
  **What may not:** verifier evidence, subprocess output, audit records, digests, credentials,
  absolute paths, another task's or another step's content. `PriorStepContext` and the audit
  log are both asserted content-free by tests that search for a sentinel.
* **Consumption is erasure.** `take_for` removes what it returns, and the store is process
  memory, so a consumed observation cannot be restored by a crash or a restart — there is
  nothing to restore. That is a stronger form of single-use than a durable flag, and it is why
  ADR-0045 Decision 4's non-durability is a property rather than a compromise.
* **`filesystem/read-text` became reachable in this slice**, because it was advertised by the
  capability menu and refused by policy. That was a defect, not a decision — see ADR-0048.
* **`3c8a413` remains the last commit at which no workspace content could reach a provider.**

So: **stages 1–4b are delivered, and the 4c governance core is delivered with both its
continuation wiring (ADR-0047) and its observation/disclosure wiring (ADR-0048).**

### Not implemented, and not planned into the near milestone

No GUI or Tauri application. No TUI. No MCP surface (ADR-0010 keeps MCP an external
integration boundary). No messaging integration. No local ASR or TTS runtime. No general
shell capability. No unrestricted filesystem capability — both filesystem capabilities
address exactly one file inside a sandbox-controlled workspace, with no directory creation,
no deletion, no copy and no permission change. No Windows Tier-1 sandbox backend. No actor
runtime beyond the authority model implemented here: `Actor` is still a *principal
assertion* over the local socket, not an authenticated identity (V-70), and no delegated
actor can reach the dispatcher.

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
