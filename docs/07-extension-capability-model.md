# 07 — Extension & Capability Model

Status: **Draft v0.3** · reconciled **2026-10-05** against `HEAD`.

**Three claims here were fictional or wrong and are corrected in place.** The dispatcher
diagram showed a ten-step order numbered 0–9 with approval verification at step 9 and a
separate EGRESS stage; the implemented order is **nine** stages with approval at **stage 3**
and no EGRESS stage, and the difference is a security property rather than bookkeeping. The
manifest schema implied a signed YAML file; there is no manifest and nothing is signed —
what exists is a compiled-in `CapabilityDeclaration` struct. The inventory listed 18
planned capabilities including `filesystem` as Tier 0; **three** are registered, and
`filesystem` is Tier 1 at `High` risk.

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

**Manifests are signed.** **This claim is false of the implementation, corrected
2026-10-05.** There is no manifest file, no manifest format, and no signing anywhere in the
workspace. What exists is `CapabilityDeclaration` — a Rust struct in
`crates/orxnud-capability/src/lib.rs` — with fields `id`, `display_name`, `risk`, `reads`,
`writes`, `isolation`, `idempotent`, `params: ParamSpec`, `target: TargetSemantics` and
`enabled`. Declarations are compiled into the binary, not loaded from disk, so there is
nothing to sign and nothing to trust-but-verify at load time.

The intent behind the original sentence is still right and is enforced differently: a
declaration is *not* an authority. It says what calling a capability **means**, never what
it does; `CapabilityInvocation` carries a private seal that only `orxnud-policy` can mint
(ADR-0034). Two of the schema's fields have no counterpart in the old YAML sketch and both
are load-bearing: `params` is the declared shape the proposer validates against (ADR-0039,
V-76) and `target` is `TargetSemantics::{None, Optional, Required}`, which the proposer
announces so a model is never asked for a field it was not told about (V-80).

Dynamic loading remains future design under ADR-0009, and gate **G7** asserts the crate
list so a new capability cannot arrive without appearing in the workspace manifest.

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
   ┌──────────────────────────────────────────────┐
   │  DISPATCHER  (the choke point)               │
   │  1. AUTHORITY              who is asking,    │
   │                            and on whose      │  ──▶ gate or deny  (S33, ADR-0027)
   │  2. POLICY                 deterministic:    │
   │                            allow, gate, deny │  ──▶ gate or deny  (S4, S5)
   │  3. APPROVAL               digest-bound,     │
   │                            single-use,      │  ──▶ abort on mismatch (S6)
   │                            re-verified      │
   │  4. BUDGET                 charged BEFORE    │
   │                            execution        │  ──▶ deny          (S17)
   │  5. CAPABILITY RESOLUTION  find an           │
   │                            implementation   │  ──▶ deny
   │  6. CREDENTIAL RESOLUTION  resolve a secret, │
   │                            iff permitted     │  ──▶ deny
   │  7. EXECUTION              call the adapter  │  ──▶ execute
   │  8. VERIFICATION           did the effect    │  ──▶ verified / refuted /
   │                            actually happen?  │      undetermined
   │  9. AUDIT / FINAL STATE    hash-chained      │  ──▶ **must succeed**
   └──────────────────┬───────────────────────────┘
                      ▼
            adapter  ──▶  audit result
```

> **Corrected 2026-10-05 — this diagram was wrong, and it disagreed with `docs/03` §9.**
> It showed a **ten**-step order numbered 0–9, with approval-digest verification at **step
> 9** and a separate **EGRESS** stage. The implemented order is the **nine** stages above,
> and the difference is not cosmetic:
>
> * **Approval is stage 3, not step 9.** `can_fulfil` / `authorise_for_dispatch` re-verify
>   the digest *before* capability resolution and long before credential resolution, so a
>   digest mismatch never reaches the secret store at all. The old diagram implied a peer
>   could present a mismatched approval and still have stage 6 run.
> * **There is no EGRESS stage.** Data-class consent is folded into the policy decision
>   (stage 2). A separate stage would have been a second place the same rule is written.
> * **Stage 7 is not synchronous.** For a `Subprocess` capability it is asynchronous
>   subprocess work behind the sandbox supervisor.
>
> The authoritative list is the module documentation of
> `crates/orxnud-capability/src/dispatch.rs`, which states the same nine stages and why
> the order is not negotiable.

**Stages 1–4 are deterministic and are performed inside `orxnud-policy`, not here.**
That is deliberate: policy is the sole authority for its own decisions, and a dispatcher
that reimplemented any of them would be a second authorisation system. **They cannot be
skipped, because no other code path constructs a `CapabilityInvocation`.** That is the structural
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
`PROVEN`; point 6 is `PROVEN` for process residue, and since Phase 4b also for resource
ceilings on a host that delegates the cgroup controllers (V-46). Delegation is a property
of the host rather than of the code: where the controllers are unavailable the same tests
report `NOT_PROVEN` and a capability requiring ceilings is **refused** rather than
downgraded. The Phase 3 harness still reports 4 and 6 as `declared_only`, and that is
intentional: it is an in-process harness and must not claim what only the subprocess tests
can establish. See ADR-0035.

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

## 9. Capability inventory — what is registered at `HEAD`

**Three capabilities, and this is the whole list.** It comes from one function,
`shipped_declarations()` in `crates/orxnud-daemon/src/lib.rs`, deliberately a single list
so the registry, the adapter bundles and the policy table cannot drift apart — three
hand-written lists eventually disagree, and the disagreement is a capability that is
declared but unresolvable, or resolvable but undeclared.

| id | Risk | Tier | Data classes | Target | Idempotent | Approval |
|---|---|---|---|---|---|---|
| `text/word-count` | `Low` | `InProcess` | `Public → Public` | `None` | **yes** | none; a standing grant suffices |
| `filesystem/write-text` | `High` | `Subprocess` | `Public → Public` | `Required` | **no** | single-use, digest-bound **v3**, time-boxed |
| `filesystem/read-text` | `High` | `Subprocess` | `Public → Public` | `Required` | **no** | single-use, digest-bound **v3**, time-boxed |

Both `Subprocess` capabilities declare `ResourcePolicy.required` **empty** and state a
budget (64 MiB, 16 processes, 1.0 core). That is a decision, not an omission: requiring a
control would refuse the capability on any host that cannot delegate, for no security gain,
so the host offers what it can and the gap is recorded in `ExecutionResult::unproven`
(V-53, V-56). Both are deliberately **not idempotent**, so an uncertain outcome becomes
`NeedsVerification` rather than a retry that would duplicate an effect (TP-2, TP-12).

Neither grants more than one file inside a sandbox-controlled workspace. There is no
directory creation, no deletion, no copy, no permission change, no shell and no network —
and that narrowness is the point, because it is what the sandbox contract can actually
enforce.

### What this section previously claimed, and why it was wrong

The old inventory listed 18 planned capabilities including `filesystem | builtin | Tier 0`
and `llm | builtin | Tier 0`. Two of those rows were wrong in the direction that matters:

* `filesystem` is not Tier 0. It is two **Tier-1 subprocess** capabilities, both `High`
  risk, both requiring human approval. A reader told "Tier 0" would assume an in-process
  call with no sandbox and no prompt.
* `llm` is not an unbuilt Tier-0 placeholder. A real provider ships: one adapter speaking
  OpenAI-compatible `chat/completions` over HTTPS, with the credential in the platform
  secret store (ADR-0039, ADR-0040).

The other 16 rows remain **future design** under ADR-0009 and are not marked "exists"
because they do not.

### MCP

**Future design, and it stays outside the capability set.** ADR-0010 makes MCP an
*external integration boundary*: something OpenRayNux calls or is called by, never a way to
add capability to this process. No `orxnud-mcp` crate exists, no MCP client is linked, and
no MCP server configuration is parsed. An MCP tool, if it ever arrives, would be reached
through a governed `Subprocess` capability under the same nine stages as everything else —
which is the whole reason the boundary is drawn there rather than in the core.


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
