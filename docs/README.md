# OpenRayNux — Documentation Index

Status: **Phase 0 — architecture complete, repository initialised.**
No application code exists. Last research/verification date: **2026-09-30**.

OpenRayNux is a local-first personal AI operating layer: one long-lived Rust
process owning the user's time, data and integrations, with several surfaces
(GUI, TUI, CLI, voice, messaging) driving the *same* capability set.

> **The foundational principle:**
> **The model proposes; a deterministic engine disposes.**
> The LLM is never the security authority, the scheduler, the credential
> authority, the transaction authority, or the final arbiter of whether an action
> succeeded.

---

## Read in this order

| # | Document | What it is for |
|---|----------|----------------|
| **00** | [System Requirements](00-system-requirements.md) | What it must *be*. Functional + non-functional requirements, the determinism boundary, and the ten requirements discovered during research. |
| **03** | [System Architecture](03-system-architecture.md) | The proposed structure, dependency direction, process topology, local protocol, and the execution loop. **Start here if you want the shape.** |
| **09** | [Architecture Decision Records](09-decisions.md) | 30 ADRs — every major decision with evidence, trade-offs, rejected alternatives, and **revisit conditions**. |
| **11** | [Critical Review](11-critical-review.md) | The adversarial section. What we are assuming, what is future-proof, what is deliberately minimal, where we accept debt, what we must never build, and what is most likely to be wrong. |
| **02** | [Technology Evaluation](02-technology-evaluation.md) | The full decision table, cross-compatibility findings, and licence posture. |
| **01** | [Architecture Research](01-architecture-research.md) | What the ecosystem actually looks like, and **corrections to widely-repeated claims**. |
| **04** | [Security & Threat Model](04-security-threat-model.md) | 5 trust boundaries, 30 threats, 33 controls, 6 approval levels, 4 data classes. |
| **05** | [Resource & Performance Model](05-resource-performance-model.md) | Budgets (all to be *measured*, none asserted), the disabled-capability guarantee, and the honest cost table. |
| **06** | [Deployment & Platform Model](06-deployment-platform-model.md) | Four deployment profiles, the platform support matrix, and what actually differs per OS. |
| **07** | [Extension & Capability Model](07-extension-capability-model.md) | Three isolation tiers, the manifest, the dispatcher, and MCP's place. |
| **08** | [Testing & Engineering Standards](08-testing-engineering-standards.md) | The testing pyramid, the deterministic-vs-AI split, and project standards. |
| **10** | [Open Questions](10-open-questions.md) | 21 unresolved items with interim positions. **Three block Phase 0/1.** |
| **12** | [Verification Register](12-verification-register.md) | **Every claim that can become false over time, with its verification source, review trigger, and consequence of drift.** |
| **13** | [Phase 1 Contract](13-phase-1-contract.md) | The exact agreement the next phase is measured against: workspace, crate graph, 12 CI gates, exit criteria, and what is explicitly excluded. |
| **sources.md** | [Sources](sources.md) | Every version claim, with URLs and access dates, plus the method's limits. |

---

## The 32 decisions at a glance

| Area | Decision | ADR |
|---|---|---|
| Core language | **Rust** | [0001](09-decisions.md#adr-0001) |
| Desktop | **Tauri 2**, optional separate process | [0002](09-decisions.md#adr-0002) |
| Local IPC | **Unix socket / named pipe + JSON-RPC 2.0** | [0003](09-decisions.md#adr-0003) |
| Runtime | **Tokio** + an explicit supervisor | [0004](09-decisions.md#adr-0004) |
| Frontend | **Svelte 5 + Vite 8; TS 7.0.2 baseline, TS 6.0.3 co-installed** | [0005](09-decisions.md#adr-0005) |
| Storage | **SQLite** via `rusqlite`, bundled **≥ 3.51.3** | [0006](09-decisions.md#adr-0006) |
| Task engine | **Hand-rolled durable task table** | [0007](09-decisions.md#adr-0007) |
| Vector search | **None.** FTS5 now; interface exists | [0008](09-decisions.md#adr-0008) |
| Extensions | **Three isolation tiers, no dynamic plugins** | [0009](09-decisions.md#adr-0009) |
| MCP | **External, untrusted integration boundary only** | [0010](09-decisions.md#adr-0010) |
| LLM abstraction | **Provider-neutral, capability negotiation** | [0011](09-decisions.md#adr-0011) |
| Determinism | **Model proposes; engine disposes** | [0012](09-decisions.md#adr-0012) |
| Memory | **Derived vs authoritative, enforced in the schema** | [0013](09-decisions.md#adr-0013) |
| Voice | **Abstraction first; `sherpa-onnx` default; eSpeak-NG floor** | [0014](09-decisions.md#adr-0014) |
| Browser | **HTTP-first, browser opt-in, a11y-tree grounding** | [0015](09-decisions.md#adr-0015) |
| Messaging | **Narrow denominator; defer WhatsApp; refuse Signal/userbots** | [0016](09-decisions.md#adr-0016) |
| Updates | **No self-updater; snapshot → migrate → rollback** | [0017](09-decisions.md#adr-0017) |
| Configuration | **11 layers, schema-versioned, secrets by reference** | [0018](09-decisions.md#adr-0018) |
| Dependencies | **Permissive-only in the core binary** | [0019](09-decisions.md#adr-0019) |
| Observability | **tracing always, OTLP optional, zero telemetry** | [0020](09-decisions.md#adr-0020) |
| Scheduling | **`croner` + `jiff`, explicit misfire policy** | [0021](09-decisions.md#adr-0021) |
| Deployment | **One codebase, four profiles** | [0022](09-decisions.md#adr-0022) |
| Platforms | **Linux + Windows T-A; ARM64/macOS T-B** | [0023](09-decisions.md#adr-0023) |
| Orchestration | **No agent frameworks; own a thin harness** | [0024](09-decisions.md#adr-0024) |
| Testing | **Deterministic gate; AI evaluation on a separate track** | [0025](09-decisions.md#adr-0025) |
| Windows | **Prepared early, in Phase 1** | [0026](09-decisions.md#adr-0026) |
| Identity | **Actor is a first-class concept** | [0027](09-decisions.md#adr-0027) |
| State | **Classified regions with a single owner** | [0028](09-decisions.md#adr-0028) |
| Task contract | **12 normative properties, implementation-independent** | [0029](09-decisions.md#adr-0029) |
| "Disabled" | **Zero operational cost and zero reachable capability** | [0030](09-decisions.md#adr-0030) |
| Node toolchain | **Project-local Node 24.21.0 LTS; global env untouched** | [0031](09-decisions.md#adr-0031) |
| `apalis-sqlite` | **Rejected — `synchronous = OFF` fails TP-7** | [0032](09-decisions.md#adr-0032) |

---

## Blocking before implementation

| ID | Question | Status |
|----|----------|--------|
| ✅ [Q-OPEN-02](10-open-questions.md) | `apalis-sqlite`'s durability pragma | **RESOLVED** — `synchronous = OFF`; rejected. [ADR-0032](09-decisions.md#adr-0032) |
| ✅ [Q-OPEN-03](10-open-questions.md) | Node 26 vs Node LTS | **RESOLVED** — project-local Node 24.21.0, global env untouched. [ADR-0031](09-decisions.md#adr-0031) |
| ✅ [Q-OPEN-04](10-open-questions.md) | Two empty workspace directories | **RESOLVED** — this repository is canonical |
| 🔴 [Q-OPEN-01](10-open-questions.md) | **Telegram ToS §1.5** — legal review | **Open, and deliberately not blocking.** The adapter boundary must be built capable of the notification-only implementation. |
| 🟡 [Q-OPEN-21](10-open-questions.md) | Do TS6 and `--tsgo` diagnostics agree? | Open; a Phase 6 deliverable |
| 🟢 [Q-OPEN-17](10-open-questions.md) | Is `synchronous = FULL` affordable? | Open; a Phase 2 measurement |

---

## Next

**[Phase 1 — Foundation Contract](13-phase-1-contract.md)** is written and awaiting
execution. Its single objective:

> Establish the workspace, the crate graph, the enforced boundaries, and the
> conformance machinery — with **zero features** working.

Nothing is scaffolded yet. The first crates to be created are `orxnud-domain`,
`orxnud-protocol`, and the three `orxnud-platform-*` adapters; the highest-value
deliverable is the **ADR-0029 conformance harness**, written *before* the queue it
will test.

---

## What does not exist yet

No application code. No crates. No `Cargo.toml`, `package.json`, or
`tauri.conf.json`. No database, no schema, no migrations. No services. No
dependencies installed. No CI. This repository currently contains **only this
documentation**.
