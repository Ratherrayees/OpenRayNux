# 07 — Extension & Capability Model

Status: **Draft v0.1**

---

## 1. What a capability is

A capability is **the unit of product surface the user enables, disables, grants
permissions to, and pays for.** It is not a class, not a module, not a plugin.

```
Capability
    ├── Contract        — a trait, or a versioned wire schema (Tier 0 vs 1/2)
    ├── Manifest        — id, version, risk class, cost class, isolation tier,
    │                     required grants, data classes, health check
    ├── Implementation  — one or more adapters (a contract may have several)
    └── Policy          — what it may do, per task, per parameter scope
```

A capability with several implementations is a **provider group**:

```
SpeechToText  (contract)
  ├─ sherpa-onnx  (local, streaming, Apache-2.0)     ← default
  ├─ parakeet     (local, best WER, CC-BY-4.0)
  ├─ whisper-cpp  (local, widest acceleration)
  └─ cloud        (lowest CPU, network cost, privacy cost)
```

The user picks the default; the system may suggest a different one **inside
policy and budget limits**, and must say which it chose and why.

---

## 2. Isolation tiers — the central design decision

This is the part the brief specifically cautioned against: *"Do not automatically
create a dynamic plugin system. A crashing optional integration should ideally
not crash the core."*

### 2.1 Tier comparison

| | **Tier 0** — in-process | **Tier 1** — subprocess | **Tier 2** — remote |
|---|---|---|---|
| **Mechanism** | Rust trait | Separate process, JSON-RPC over stdio/UDS | MCP Streamable HTTP |
| **ABI stability** | **None** — recompile per version | **Wire protocol** — stable across versions | Protocol — stable across versions |
| **Crash containment** | ❌ **None.** A panic kills the daemon | ✅ Process dies, daemon survives | ✅ Remote, survives |
| **Language** | Rust only | Any | Any |
| **Isolation strength** | None (same address space) | **OS process boundary**; sandboxing possible | Network boundary |
| **Call overhead** | ~ns | ~1–5 ms | ~10–100 ms + network |
| **Memory cost** | In-process | +5–20 MB | Remote |
| **Upgrade** | Requires rebuilding the host | Independent | Independent |
| **Trust** | Core trust | Semi-trusted, still sandboxed | **Untrusted** |
| **Typed API** | ✅ Compile-time | ⚠️ Generated/checked at boundaries | ⚠️ Schema |
| **Can be untrusted code?** | ❌ **No** | ✅ Yes | ✅ Yes |

### 2.2 Why dynamic libraries are rejected

A `cdylib` plugin looks attractive and is a trap:

1. **There is no stable Rust plugin ABI.** A plugin must be compiled against the
   exact host version and dependency graph. "Just rebuild" turns every plugin
   into a source-distribution problem.
2. **A segfault kills the host.** There is no recovery. The brief's requirement
   — "a crashing optional integration should ideally not crash the core" — is
   *impossible* to satisfy in-process.
3. **It shares the address space**, so it can read every secret in the daemon.
4. **It shares the dependency versions**, so a plugin wanting a different
   `tokio` or `serde` cannot be satisfied.

Cost: one IPC hop (~1–5 ms) and a process. Benefit: the core can never be
killed by a bad integration, and the trust boundary is real rather than
aspirational. For capabilities that are not on the hot path — which is nearly
all of them — this is obviously correct.

### 2.3 Tier assignment rules

| Assign to Tier 0 when | Assign to Tier 1+ when |
|---|---|
| It is a built-in and its panic would be a bug we fix | It is third-party or user-supplied |
| It must be fast (in-memory index, hot loop) | It may crash |
| It needs no isolation | It needs filesystem/network restrictions |
| It is GPL/AGPL/NC-licensed (impossible in-process without copyleft exposure) | It is untrusted |
| | It is a resource-heavy component the core should not host (browser, models) |

**Rule for licence:** anything GPL/AGPL **must** be Tier 1 or excluded. This is
why Piper and eSpeak-NG are subprocesses, not linked libraries.

**Rule for models:** the ASR/TTS engines are heavy native code. Tier 1 keeps a
segfault in ONNX Runtime from taking down the daemon, and lets us lazy-load and
unload models to protect the idle budget (`05-…` §6).

### 2.4 WASM/WASI — deliberately deferred

Attractive on paper: a strong sandbox, portable bytecode, no ABI problem.
Rejected **for now** for a specific reason rather than in principle: the
capabilities we most need to isolate are exactly the ones WASM sandboxes worst
— filesystem, network, and **subprocess spawning**. Audio device access, browser
driving, and OS keyrings have no comfortable WASI story. The Component Model is
still stabilising.

**Revisit when:** the Component Model reaches a stable release, *and* at least
one candidate capability (e.g. a pure text-transform or scoring capability)
exists that needs no host resources.

---

## 3. The capability manifest

Every capability declares this. It is the input to policy, to the UI, and to the
resource accounting — so it is data, not code.

```yaml
id:               speech-to-text
version:          1
contract:         builtin            # builtin | jsonrpc-1.0 | mcp-2026-07-28
isolation:        subprocess
risk:             medium              # low | medium | high | critical | unknown→high
cost:             { cpu: heavy, memory_mb: 400, network: none, disk_mb: 34 }
grants:
  filesystem:     [ { read: ["$DATA_DIR/models"] } ]
  network:        none
  subprocess:     none
  secrets:        none
data_classes:     [ voice ]           # what it may see
produces:         [ transcript ]      # what it may return
side_effects:     none
timeout_ms:       30000
reversible:       true
health_check:     { type: load-model, model: moonshine-tiny }
```

`side_effects` and `reversibility` are the fields policy actually uses. Getting
them right is a design task per capability, not a mechanical one.

**Manifests are signed.** A capability from an untrusted source is identified as
such regardless of what its manifest claims — the manifest is *data to be
validated*, never an authority.

---

## 4. Dispatch: the only route to an adapter

```
CapabilityInvocation {
    actor,               // ADR-0027 — first-class; carries the delegation chain.
                         // Resolved and consumed by policy. NEVER passed to
                         // the capability: a capability that learns its caller
                         // becomes a confused deputy (TH-04).
    task_id, step_key, capability_id, adapter_id,
    params,              // must match the contract schema
    data_classes_in, data_classes_out,
    idempotency_key,
    deadline, cancellation_token,
    policy_context,      // includes the policy version that authorised it
}
        │
        ▼
   ┌─────────────────────────────────────┐
   │  DISPATCHER  (the choke point)      │
   │  0. AUTHORITY: may THIS actor do    │
   │     this? (delegation chain valid,  │  ──▶ gate or deny  (S33, ADR-0027)
   │     not expired, not revoked)       │
   │  1. capability exists? version ok?  │  ──▶ deny
   │  2. params validate vs contract?    │  ──▶ deny
   │  3. data classes ⊆ task's classes?  │  ──▶ deny
   │  4. POLICY: grant present?          │  ──▶ gate or deny  (S4, S5, S6)
   │  5. BUDGET: within ceiling?         │  ──▶ deny          (S17)
   │  6. EGRESS: consent for classes?     │  ──▶ deny          (S18)
   │  7. AUDIT: record authorisation     │  ──▶ **must succeed** or deny
   │  8. ISOLATION: tier, sandbox, limits │  ──▶ configure
   │  9. VERIFY approval digest          │  ──▶ abort on mismatch (S6)
   └──────────────┬──────────────────────┘
                  ▼
        adapter  ──▶  audit result
```

**Steps 0–7 are deterministic and synchronous. They cannot be skipped, because
no other code path constructs a `CapabilityInvocation`.** That is the structural
guarantee; a review checklist would not be.

**Step 0 is authority, and it precedes everything else.** An `External` actor can
never grant; an `Ai` actor's authority is exactly its delegating `Human`'s,
intersected with current task policy and never additive. See ADR-0027.

---

## 5. Capability lifecycle

```
   discover ──▶ validate manifest ──▶ health check ──▶ AVAILABLE
                                                      │
                            ┌─────────────────────────┼──────────────┐
                            ▼                         ▼              ▼
                        ENABLED                   DEGRADED        QUARANTINED
                     (grants active)           (failing, retrying)  (N failures)
                                                              │
                                                              ▼
                                                        DISABLED
```

- **Health check** before first enable, and periodically after. A capability
  that cannot prove it works is not offered.
- **Degraded** is visible to the user, with a plain-language reason.
- **Quarantined** after N consecutive failures. Never retried silently forever.
- **Disabled** stops the subprocess, unloads models, and (per CR-2) leaves no
  resident cost.

---

## 6. Provider groups and configurability

The brief's example is the requirement, stated exactly:

```
ASR:      faster-whisper: enabled   NeMo: disabled   another: enabled
Messaging: Signal: enabled          Telegram: enabled
          Discord: disabled         WhatsApp: disabled
Domains:  Jobs: enabled             Learning: enabled
          Health: disabled          Open-source: enabled
```

Implemented as:

- **Config layers** (`09-…` ADR-0018). A capability's enabled state and its
  selected adapter are configuration, versioned and schema-validated.
- **Disabled config is an error, not a no-op.** A typo in a disabled
  capability's key surfaces immediately rather than silently doing nothing.
- **Provider selection is per-capability-group, with a documented default** and a
  recorded reason when the system deviates from it.
- **Enabling a capability is a policy event**, audited, and — for Tier 2 — a
  one-time approval with explicit argument scope (approval level L4).

---

## 7. MCP: where it belongs

**MCP is the protocol for capabilities OpenRayNux does not implement. It is not
the internal capability protocol, and MCP servers are not trusted.**

Rationale:

- The internal protocol is a narrow JSON-RPC dialect optimised for our contracts
  and our policy. Conforming it to MCP's semantics would import spec churn into
  the core.
- MCP's value is **interoperability** — letting the user attach tools we have
  never heard of. That is exactly the untrusted Tier 2 case.
- MCP's own spec says: "Tools represent arbitrary code execution and must be
  treated with appropriate caution … descriptions of tool behavior such as
  annotations should be considered untrusted."

### 7.1 MCP posture (spec 2026-07-28)

| Concern | Our handling |
|---|---|
| **Stateless protocol** | *Good for us.* No session object to confuse with a grant. Each request declares its own version and capabilities. |
| **Sampling deprecated** | *Good for us.* Removes an LLM-proxy pattern; we call providers directly. |
| **Roots / Logging deprecated** | No impact; we never adopted them. |
| **Tasks extension** | **The** candidate for third-party long-running work. Polling (`tasks/get`) + mid-flight input (`tasks/update`) + durable handles. Map to our task engine — but note it is an **extension**, negotiated at init, so it may be absent. |
| **MRTR (`input_required`)** | Maps naturally to our "waiting-for-user" task state. The client answers by retrying the original request. |
| **SSE resumability removed** | A broken stream loses the in-flight request. **We must re-issue with an idempotency key** (S7) or we get duplicates. |
| **`ttlMs` / `cacheScope` on list results** | Use it. Cache `tools/list` rather than polling. |
| **No auto-consent** | Per-tool, per-scope approval, digest-bound like our own capabilities. |
| **Per-server kill switch** | Independent revocation. |
| **Version negotiation** | `server/discover` up front; fall back to STDIO probe. |
| **HTTP+SSE deprecated** | We only implement Streamable HTTP. |

### 7.2 Trust tiers for capabilities

```
┌─ BUILT-IN (Tier 0/1) ─────────────────────────────────────────┐
│  our code, reviewed, signed, in the release                    │
│  trust: high · still policy-controlled · still audited         │
└────────────────────────────────────────────────────────────────┘
┌─ TRUSTED INTEGRATION (Tier 1) ────────────────────────────────┐
│  user-installed, source-available, reviewed by the *user*      │
│  trust: medium · sandboxed · per-capability grants            │
└────────────────────────────────────────────────────────────────┘
┌─ THIRD-PARTY MCP (Tier 2) ────────────────────────────────────┐
│  remote or local, opaque binary or source, we did not review   │
│  trust: NONE · sandboxed · no auto-consent · kill switch      │
│  ⚠ may exfiltrate anything it can reach. Containment is the    │
│    entire mitigation.                                          │
└────────────────────────────────────────────────────────────────┘
```

An **MCP server's own tool descriptions are never trusted to describe the tool
correctly.** Risk classification is *ours*, assigned by inspecting the
capability, not by reading the server's annotations.

---

## 8. Capability contract testing

Every capability must pass the same suite. This is what makes "any
implementation is substitutable" true rather than aspirational.

**Contract tests (all implementations, mandatory).**
*Phase 3 note: implemented as `crates/orxnud-capability/tests/contract.rs`. Points 4
and 6 were **declaration-only** — sandbox isolation and process residue cannot be
observed by an in-process fixture.*

*Phase 4a note: both points now have **process-level evidence** in
`crates/orxnud-platform-sandbox/tests/isolation.rs`, using real subprocesses under a
real sandbox: undeclared filesystem and network access are refused, a disabled
capability starts no process, and a hung or flooding helper is bounded. Point 4 is
`PROVEN`; point 6 is `PROVEN` for process residue but still `NOT_PROVEN` for resource
ceilings, because this host delegates no cgroup controllers (V-46). The Phase 3 harness
still reports 4 and 6 as `declared_only`, and that is intentional: it is an
in-process harness and must not claim what only the subprocess tests can establish.
See ADR-0035.

1. Invalid params are rejected, not coerced.
2. Cancellation is honoured within the declared bound.
3. The declared timeout is honoured.
4. No undeclared filesystem or network access occurs.
5. Output validates against the contract schema.
6. The capability is disabled → no residue (no process, no open file, no
   connection).
7. Crash the adapter → the daemon survives and the task is recoverable.
8. A capability that is not enabled cannot be invoked.
9. Idempotency: a repeated call with the same key does not duplicate the effect.
10. Grants are enforced: invoking without the grant fails **closed**.

**Provider-group tests (per implementation):**

- Adapter-specific conformance and a documented list of deviations.

---

## 9. Capability inventory (initial, non-exhaustive)

| Capability | Contract | Tier | Notes |
|---|---|---|---|
| `clock`, `calendar` | builtin | 0 | ICS + provider adapters |
| `task-engine` | builtin | 0 | The core's own scheduler |
| `filesystem` | builtin | 0 | Scoped, audited, deny-by-default |
| `notify` | builtin | 0 | Per-platform |
| `llm` | builtin | 0 | Provider-neutral; see ADR-0012 |
| `memory` | builtin | 0 | Derived vs authoritative separation |
| `search` (lexical) | builtin | 0 | SQLite FTS5 |
| `http` | builtin | 0 | The HTTP-first browser tier |
| `speech-to-text` | builtin | 1 | sherpa-onnx / parakeet / whisper-cpp / cloud |
| `text-to-speech` | builtin | 1 | kokoro / espeak-ng / cloud |
| `browser` | builtin | 1 | **opt-in**; dedicated profile; HTTP-first default |
| `messaging` | builtin | 0/1 | Per provider; see §10 |
| `mcp-host` | builtin | 0 | Client for Tier 2 |
| `github` | builtin | 0 | API, not browser automation |
| `email` | builtin | 0/1 | IMAP/SMTP; needs IDLE or polling |
| `matrix` | builtin | 0 | The one user-account-sanctioned platform |
| `web-search` | builtin | 0 | |
| `domain-*` | builtin | 0 | Per FR-01 |

**Deliberately absent from v1:** WhatsApp, Discord user accounts, Signal, any
vector-database capability, any dynamic-library plugin system.

---

## 10. Messaging: a narrow common denominator, honestly

Providers are **not** equivalent, and the interface must not pretend otherwise.

**Common denominator (all implementations):**

```
send(message: OutboundMessage)      → { provider_message_id }
receive()                           → stream<InboundMessage>
capabilities()                      → ProviderCapabilities
health()                            → Health
```

`OutboundMessage` is intentionally small: text, media references, reply-to,
thread reference, formatting hint. Everything beyond that is a
**provider extension**, accessed explicitly, and a UI that uses it must handle
"this provider cannot do that" as a first-class state.

`ProviderCapabilities` is data — `max_media_bytes`, `supports_reactions`,
`supports_threads`, `supports_edit`, `can_read_history`, `window_seconds` — so
the UI and the policy engine can reason without hard-coding provider names.

| Platform | Tier | `can_read_history` | Blocking constraint |
|---|---|---|---|
| Telegram (Bot API) | 0 | **No** — only chats the user initiated | ToS §1.5 AI clause → **legal review gate** |
| Discord (bot) | 0 | Channel-scoped | `MESSAGE_CONTENT` privileged intent; IDENTIFY 1000/24h |
| Matrix | 0 | **Yes** | — (the only fully user-account-sanctioned option) |
| Email (IMAP/SMTP) | 0 | **Yes** | No push; IDLE or polling |
| WhatsApp Cloud | — | **Defer** | 24 h template window; ToS forbids household use |
| Discord user account | — | **Prohibited** | Self-bots ⇒ termination |
| Signal | — | **No API exists** | 3-month self-imposed support window |
| Webhook-in | 1 | Push only | We must expose a listener |

**Rate limits are data, not comments.** `capabilities()` carries the limits so
backoff can be computed correctly — Telegram's 1 msg/s per chat, WhatsApp's
1 msg/6 s per user, Discord's 50 req/s global, Meta's 80 mps per business number.

---

## 11. What we refuse to build

| Refused | Why |
|---|---|
| A capability marketplace | Review capacity, not user demand, is the constraint. Every capability is a security surface. |
| Auto-connecting MCP servers | A connection is a trust grant. Never implicit. |
| A capability that self-grants | Contradicts the entire security model. |
| Learning tools that execute | No. |
| Zero-config "just works" for anything with a network grant | The user must know what reaches the network. |
| Cross-capability calls | A capability cannot invoke another capability. Composition happens in the task engine, under policy. |
