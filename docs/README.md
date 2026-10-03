# OpenRayNux — Documentation Index

Status: **Phase 3 complete. Windows verification open (V-29).**

```text
Phase 1  ✅ Foundation
Phase 2  ✅ Durable execution
Phase 3  ✅ Governed capability dispatch
Phase 4a  ✅ Process isolation
Phase 4b  ⚠️ V-50/V-54/V-55/V-56 complete / V-46 mechanism + governed path + limit validation PROVEN, cgroup.kill redundant (ADR-0036) / V-29 open
```

Remaining Phase 4b work, as two bounded tracks:

```text
4b-Linux    V-46 cgroup mechanism       [done — PROVEN, mutation-verified]
            V-46 governed-path adoption   [done — PROVEN, mutation-verified]
            V-46 cgroup.kill teeth         [closed — redundant on Linux, ADR-0036]
            V-46 limit validation          [done — PROVEN, mutation-verified]
            resource-policy finalisation  [done — V-56]
            V-54 fallback mutation         [done — MUTATION-VERIFIED]

4b-Windows  V-29 MSVC compile cross-check    [done — 9/15 crates, mutation-verified]
            V-29 Windows behaviour test lane  [done — wired into CI, first run pending]
            Job Object process-tree and resource tests
            a Windows execution backend
```

Phase 4b progress: **V-50 complete** -- the governed dispatcher now executes Tier-1
capabilities only through the sandbox, with no in-process route and no unsandboxed
fallback (V-51). **V-46 open, three halves** -- the cgroup *mechanism* is proven and
mutation-verified; the *governed path* uses it (the runner owns a dedicated child, writes
ceilings before spawning, joins the supervisor via a cgroup `exec` wrapper and verifies
membership from `cgroup.procs`, failing closed if it cannot); and *limit validation* closes
six measured fail-open paths, the sharpest being that `memory.max` is signed in the kernel,
so `u64::MAX` is stored as `max` -- a requested ceiling silently becoming **unlimited**.
Placement is now also shown to precede execution, not merely to be verified afterwards. ADR-0036 records that
`cgroup.kill` is a deliberate redundant backstop on this path rather than a load-bearing
mechanism: `--unshare-pid --die-with-parent` already reaps descendants, so the governed
test cannot separate them and no artificial mutation will be built to try. **V-29** is
reconciled into this branch, and Windows *runtime* evidence is still absent -- see below.

**V-29 partly closed, and split into what is and is not proven.** The portable core no
longer names a Linux mechanism: `orxnud-capability` asks the sandbox crate for *the
host's* backend, and that crate selects `BwrapRunner` on Linux and a **refusing**
`UnsupportedRunner` everywhere else. Nine of fifteen crates -- every platform adapter,
`orxnud-domain`, `orxnud-protocol`, `orxnud-config`, `orxnud-obs`, `orxnuctl` -- check
clean for MSVC, and a type error planted in the Windows-only arm fails the MSVC build
and not the Linux build, so that arm is compiled rather than dead. The remaining six
are blocked on this host by a missing MSVC C toolchain (`libsqlite3-sys`), not by any
Rust-level error. Two real defects were fixed on the way: a Tier-1 program was tested
for absoluteness with `starts_with('/')`, which would have refused *every* Windows
program, and `SandboxSpec`'s default working directory was a literal POSIX root in the
portable contract. **Still NOT PROVEN: Windows isolation.** No Job Object or
AppContainer backend exists, so a Tier-1 execution on Windows is refused outright --
deliberately, because an unsandboxed Tier-1 subprocess is worse than no capability at
all. A second CI lane now runs the platform-neutral suites on Windows as tests rather
than only compiling them.

**Recorded, not changed:** the stage order is `CREDENTIAL -> SANDBOX`, so a
required-resource refusal necessarily follows credential resolution. The guaranteed
invariant is that the backend is never invoked, so no subprocess exists and no
credential material reaches any environment. Reversing the order is a separate ADR.

**Recorded, not changed:** cgroup delegation is a property of the *host*, so several files
previously asserting "this host delegates nothing" were wrong for a different host.
Delegation is now measured and reported, never assumed -- `scripts/run-resource-tests.sh`
prints the own-cgroup path instead of a remembered verdict. The validation bounds
(`pids.max <= 4194304`, the largest finite `cpu.max` quota) were measured on one host and
are encoded as constants, so a host with different limits would fail closed and need them
re-measured. Deriving them at runtime is the proper fix and is a separate piece of work.


Phase 4b has three objectives: wire the sandbox into the Phase 3 dispatcher so the
governed path actually uses it (V-50), prove hard resource ceilings where cgroup
delegation exists (V-46), and obtain Windows evidence for Job Objects / AppContainer
rather than documenting them (V-29).

The security model is no longer prose: `CapabilityInvocation` is not deserialisable,
policy is the only crate that can mint one, the dispatcher is the only route to an
adapter, and credentials resolve after every check that can refuse.

The Windows cross-check is partial: the crates behind bundled SQLite cannot be
cross-checked from this host, which has no MSVC C toolchain. That is an open
verification item, not an implementation gap.
Phase 1 (workspace, crate graph, CI gates, the ADR-0029 conformance harness) and
Phase 2 (bundled-SQLite storage, the task schema, the production engine and
scheduler) are both implemented. **No capability is enabled and no feature works** —
that remains the invariant of Phases 0–2. Last research/verification date:
**2026-09-30**.

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
| **10** | [Open Questions](10-open-questions.md) | Open items with interim positions. **Q-OPEN-17 resolved** by Phase 2 measurement: `synchronous=FULL` is affordable. |
| **12** | [Verification Register](12-verification-register.md) | **Every claim that can become false over time, with its verification source, review trigger, and consequence of drift.** |
| **13** | [Phase 1 Contract](13-phase-1-contract.md) | The agreement Phase 1 was measured against: workspace, crate graph, 12 CI gates, exit criteria, and what is explicitly excluded. |
| **14** | [Phase 2 Contract & Delivery Record](14-phase-2-contract.md) | Persistence, the durable engine and scheduler, the 12 properties passing against an unmodified harness, real crash injection, measured `synchronous=FULL` cost, and what Phase 2 found. |
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
| ✅ [Q-OPEN-17](10-open-questions.md) | Is `synchronous = FULL` affordable? | **RESOLVED** — measured at ~2.3 ms/commit (7–14× `NORMAL`); default stays `FULL`. [V-30](12-verification-register.md) |

---

## Next

**Phase 3** is not yet contracted. What exists today:

- `crates/orxnud-store` — bundled SQLite, the Phase 2 task schema, the
  repositories, and the snapshot-protected migration runner (ADR-0006, ADR-0017).
- `crates/orxnud-task` — `DurableEngine` and `Scheduler`, passing all twelve
  ADR-0029 properties against the Phase 1 harness unchanged (ADR-0029, V-32).
- `crates/orxnud-platform-sandbox` — the Tier-1 execution boundary: a portable
  contract (`what` isolation is required) and a `bubblewrap` backend (`how` on Linux).
  Environment, filesystem, network, output, timeout, descriptor hygiene and
  process-tree containment are **proven with real subprocesses**; OS-enforced resource
  ceilings are **not** and are refused rather than downgraded. See
  [`14-phase-2-contract.md`](14-phase-2-contract.md) and ADR-0035.
- `crates/orxnud-daemon` — `TaskService`, the production startup: snapshot-protected
  migration, reclaim of the previous run's leases, and a refusal to start if either
  fails. See [`14-phase-2-contract.md`](14-phase-2-contract.md) §8b for the fresh-install
  bug that only this wiring could find.
- `scripts/ci-gates.sh` — the twelve gates, runnable locally and in CI.

Two capabilities exist. **`text/word-count`** is a pure in-process text measurement
reachable through `orxnuctl capability run`; it was first because proving the governed
pipeline needs no authority — it reads nothing, writes nothing, resolves no credential
and spawns no process.

**`filesystem/write-text`** is the first capability with a real side effect, and the
first that the rest of the architecture exists to govern. It writes one text file into
a sandbox-controlled workspace, and it is **High risk**, so policy refuses it unless a
single-use, time-boxed, parameter-bound approval is presented. Everything else about it
is narrow on purpose: one file, no directories, no deletion, no copy, no permission
change, no shell, no network, and no option that widens any of those. It executes as
**Tier 1** — a real subprocess under the host sandbox — and its `invoke` refuses
outright, so the in-process path is a refusal rather than an unwitnessed fallback. A
separate verifier re-reads the file and compares its bytes, so verification is a
statement about the filesystem rather than about what the writer said.

Approval issuance is exposed as `orxnuctl capability approve`, whose output is passed
straight back as `capability run --approval`:

```bash
APPROVAL=$(orxnuctl capability approve \
  --capability filesystem/write-text --target notes.txt \
  --params '{"path":"notes.txt","contents":"hello"}' --ttl-ms 60000)

orxnuctl capability run \
  --capability filesystem/write-text --target notes.txt \
  --params '{"path":"notes.txt","contents":"hello"}' \
  --approval "$APPROVAL"
```

An approval is bound to the exact parameters it was issued for. Presenting it with
`contents` changed is refused with `approval-digest-mismatch` before anything runs,
which is the property the digest exists for. Still absent by design: any interface
beyond the CLI, and any provider integration. A **task** domain surface now exists over IPC
(`task/create`, `task/list`, `task/claim`, `task/complete`, `task/cancel`) because the durable task
engine was already there and correct; it manages first-party state and is
deliberately not routed through the capability dispatcher.
`docs/13-phase-1-contract.md` remains the record of what Phase 1 promised and
delivered.

---

## What does not exist yet

`CapabilityRegistry` holds two entries — `text/word-count` and
`filesystem/write-text` — and both are reachable only through the governed dispatcher.
Neither reaches a sandbox by a second route, and neither has a general-purpose
filesystem or shell capability behind it. `CapabilityInvocation` still cannot be
constructed outside `orxnud-policy`, so declaring a capability is not the same as being
able to run one. No
interface exists beyond `orxnuctl --version` and `doctor`. No provider integration,
no MCP surface, no Tauri or Svelte project. The task engine stores and transitions
tasks; it performs no work, because performing work is a capability and capabilities
are Phase 4+.

What *does* exist is the foundation those phases need: pinned and verified SQLite,
a versioned schema with a tested migration and rollback path, a durable task engine
that satisfies its normative contract, and twelve CI gates.
