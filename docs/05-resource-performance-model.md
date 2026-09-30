# 05 — Resource & Performance Model

Status: **Draft v0.1** · **All targets are budgets to be measured, not claims.**
Nothing in this document asserts a performance figure we have not observed.

---

## 1. Method, and the reference machine

**Reference machine (development):**

| | |
|---|---|
| CPU | Intel Core i5-12500H, 12 cores / 16 threads, 2.5 GHz base |
| RAM | 15 GiB (6.8 GiB available at measurement time) |
| GPU | Intel Iris Xe (integrated) + NVIDIA RTX 3050 Mobile (4 GiB) |
| Storage | LUKS-encrypted NVMe SSD, 244 GiB free |
| OS | Fedora Linux 44, kernel 7.2.7-200.fc44 |
| Toolchain | rustc 1.98.1, release profile default |

**This machine is a reference, not a target.** Budgets are stated for a
**modest baseline** (2 cores, 4 GiB RAM, no GPU) and for the reference machine.
If a feature only fits the reference machine, it is marked **Tier 2** and is
opt-in.

**Measurement discipline.** Every budget in §2 is a *target*. A budget becomes a
*fact* only when a benchmark exists in the repository and CI compares against it.
§7 specifies that harness. Until then, treat all numbers as design intent.

---

## 2. Budgets

### 2.1 Startup (cold = no OS page cache for our binaries)

| Measurement | Target (baseline 2c/4 GiB) | Target (reference) |
|---|---|---|
| Daemon cold start, **core features only** | < 150 ms | < 80 ms |
| Daemon cold start, **all features enabled** | < 400 ms | < 250 ms |
| Daemon warm start | < 40 ms | < 25 ms |
| Core DB open + migration check | < 30 ms | < 15 ms |
| CLI `orxnuctl --version` | < 30 ms | < 15 ms |
| TUI first paint | < 100 ms | < 60 ms |
| **GUI window to interactive** | < 1.2 s | < 700 ms |

**The dominant GUI cost is the system WebView's first process launch**, not our
Rust code. This is why the GUI is a separate process: a CLI-only user never pays
it (CR-2, ADR-0002).

### 2.2 Idle

| Measurement | Target |
|---|---|
| **Daemon idle RSS, core only** | **< 60 MB** |
| Daemon idle RSS, all features enabled but unused | < 120 MB |
| Daemon idle CPU | **< 0.5%** of one core |
| Daemon wakeups/sec while idle | < 2 |
| DB file size, empty install | < 1 MB |
| DB growth, 1 year of typical personal use | < 250 MB |
| **GUI shell incremental RSS (reference)** | +80–150 MB (WebKitGTK web process) |
| TUI incremental RSS | +5–15 MB |

**The 60 MB core target is the single most important budget in the document.**
It is what forces SQLite (not a server), no embedded vector DB, an
append-only-file audit rather than a log database, bounded caches, and no
mandatory telemetry. It is the budget that makes the rest of the architecture
honest.

### 2.3 Active

| Operation | Target (reference) |
|---|---|
| Task claim + state transition (fsync'd, `synchronous=FULL`) | < 5 ms |
| Policy evaluation (cached grant hit) | < 1 ms |
| Policy evaluation (miss → full evaluation) | < 10 ms |
| Audit record append (hash chain) | < 2 ms |
| LLM intent classification (short model) | < 800 ms |
| LLM plan synthesis | < 3 s |
| Text-to-speech first audio chunk (Kokoro) | < 400 ms |
| Speech-to-text partial (sherpa-onnx streaming, CPU) | < 300 ms after 1 s of audio |
| UI input → visual response (GUI) | < 50 ms |
| UI input → visual response (TUI) | < 16 ms |

**Fencing:** any long-running operation carries a deadline and a
`CancellationToken`. No operation may hold a task lease without heartbeating.

### 2.4 Disk

| Artefact | Budget |
|---|---|
| Core binary (release, stripped) | < 25 MB |
| GUI binary + frontend bundle | < 15 MB |
| **Total, core only (no optional features)** | **< 40 MB** |
| Total, all features except browser | < 120 MB |
| ASR model, small (Moonshine-tiny q8) | 34 MB |
| ASR model, medium (Parakeet v3 q8 GGUF) | 680 MB |
| TTS model, Kokoro q8 | 82 MB |
| TTS, eSpeak-NG (no model) | 0 (system pkg) |
| Browser tier (`playwright-rs` + Chromium) | **~530 MB** (Node ~130 MB + browser ~400 MB) |
| Backups (rotating, 7 daily + 4 weekly) | 7 × DB size |

### 2.5 Network

| Operation | Budget |
|---|---|
| Idle telemetry | **0 bytes.** No phoning home, ever |
| Local IPC round trip | < 1 ms |
| MCP local subprocess call | < 5 ms overhead |
| LLM request (non-streaming, short) | provider-determined |
| Browser automation, HTTP-first | < 200 ms/page |
| Browser automation, real browser | < 1.5 s/page |

**Network is a resource, not a free utility.** Every outbound flow is classified
and consented (S18). "Phone home for telemetry" is not a feature we will build.

---

## 3. Cost model

LLM spend is the largest recurring cost and the least visible. NR-01 makes it
first-class.

| Tier | Mechanism | Enforcement |
|---|---|---|
| **L0** | Per-provider monthly ceiling | Hard stop at 100 % |
| **L1** | Per-model daily ceiling | Hard stop |
| **L2** | Per-task-class ceiling (e.g. "classification ≤ $0.50/day") | Hard stop |
| **L3** | Per-task ceiling | Task refuses to start above it |
| **L4** | Global circuit breaker | All spend halts; user notified |
| **L5** | Approval-to-exceed | Requires explicit user grant, logged |

**Rule: a scheduled task without a spend ceiling cannot be created.** A cron
expression is an unbounded financial instrument.

---

## 4. The "disabled" invariant (CR-2) — ADR-0030

> **Disabled = zero operational cost and zero reachable capability.** Build-time
> feature elimination, where practical, additionally removes binary and storage
> cost — an optimisation, never the guarantee.

This is the mechanism that makes the product honest about being lightweight, so
it is enforced mechanically, not by intention.

### 4.1 Tier 1 — the guarantee (measured in CI, contract-level)

A disabled capability:

| # | Property | Verified by |
|---|---|---|
| 1 | **Cannot execute** | Contract test: invocation while disabled is refused by the dispatcher (fails closed) |
| 2 | **Holds no credentials** | No `secret_ref` resolves on its behalf; the S1 test covers the invocation path |
| 3 | **Starts no worker** | No process, thread, or supervisor child; asserted by process/thread count |
| 4 | **Consumes no model resources** | No model or ONNX runtime loaded; asserted by handle/RSS inspection |
| 5 | **Performs no network activity** | No socket opened; verified by syscall/network trace in CI |
| 6 | **Adds no meaningful idle CPU/RAM** | RSS and CPU deltas against a committed baseline, within a stated threshold |
| 7 | **Has no reachable state** | No tables, rows, scheduled jobs; config keys **rejected**, not ignored |
| 8 | **Is unreachable by any interface** | No interface can obtain an invocation handle; protocol test suite |

These eight hold **regardless of build flags** and are enforced by tests rather
than binary inspection. They are the properties that determine the blast radius
of a bug in a disabled subsystem — i.e. they are *security* properties.

### 4.2 Tier 2 — the optimisation (measured, regression-tracked)

Binary size, install size, and startup delta via Cargo features. Recorded per
release so drift is visible in review. **Not normative**, because a transitive
dependency may link code regardless of features — that is a *bytes* concern, not
a reachability one, and failing builds on third-party linking behaviour would
produce alert fatigue.

**Cargo features** gate every optional component at compile time:

```
default = ["core"]              # nothing optional
asr, tts, browser, mcp, messaging, otlp, llm, domain-*  # all opt-in
```

A disabled capability must have:

1. **No code linked** — verified by binary size delta.
2. **No resident memory** — verified by RSS delta.
3. **No startup cost** — verified by startup-time delta.
4. **No file handles, no device opened** — verified by inspection.
5. **No network listener or outbound connection** — verified by inspection.
6. **No tables, no rows, no scheduled jobs** — verified by DB diff.
7. **No configuration surface** — a disabled capability's config keys are
   rejected, not ignored, so typos surface immediately.

**CI enforcement:** a build matrix over feature combinations asserts (1)–(3)
against committed baselines. Drift beyond a stated threshold fails the build.
The `all-features` binary size is recorded per release so regressions are
visible in review.

**This is why the browser is a capability and not a dependency.** Bundling
`playwright-rs` + Chromium by default would add ~530 MB and break CR-2 for
every user who never enables it.

---

## 5. Per-capability cost table

Costs are additive and only apply when the capability is **enabled and active**.

| Capability | Idle RSS | Disk | Notes |
|---|---|---|---|
| Core daemon | 40–60 MB | < 40 MB | Always |
| + LLM (cloud) | ~0 | ~2 MB | No local model; cost is network+provider |
| + LLM (local model) | model-dependent | 1–15 GB | Off by default; explicitly gated |
| + ASR (sherpa-onnx, Moonshine-tiny) | +200–400 MB | +34 MB | Model must be loaded → lazy load + unload |
| + ASR (Parakeet v3 q8) | +800 MB–1.2 GB | +680 MB | GPU strongly preferred; CPU viable but slow |
| + TTS (Kokoro q8) | +150–300 MB | +82 MB | Lazy load |
| + TTS (eSpeak-NG) | +15 MB | 0 | The always-available floor |
| + Browser (HTTP-first) | +10–50 MB | ~0 | Default browser tier |
| + Browser (real, opt-in) | +400–600 MB | ~530 MB | Separate process; killable |
| + MCP (local stdio) | +5–20 MB/server | varies | Per-server subprocess |
| + Messaging (per provider) | +10–40 MB | ~0 | Long-lived connections |
| + Desktop GUI | +80–150 MB | +15 MB | WebKitGTK/WebView2 web process |
| Domain (per domain) | +1–5 MB | small | Tables + schedulers only |

**The uncomfortable truth, stated plainly:** a *fully enabled* OpenRayNux with
local ASR, local TTS, a real browser and a desktop GUI is **not lightweight** —
it can reach 1.5–2 GB RSS. It would be dishonest to claim otherwise.

What *is* true, and is the actual product promise:

- **Core + CLI is genuinely tiny** (< 60 MB, < 40 MB disk).
- **Every capability's cost is opt-in and attributable.**
- **Disabled capabilities cost exactly nothing**, measured in CI.
- **A cloud-LLM + TUI + eSpeak-NG configuration stays in the low hundreds of MB**
  and is a genuinely good everyday assistant.

---

## 6. Avoiding platform-mandated bloat

Some costs are not ours to choose, so we state them and design around them:

| Cost | Cause | Mitigation |
|---|---|---|
| WebKitGTK web process (~80–150 MB) | Tauri's system WebView on Linux | GUI is a separate, optional process. Documented in ADR-0002. |
| Node runtime in `playwright-rs` (~130 MB) | Playwright's server is Node; Microsoft does not ship an official Rust binding and has said so on the record | Browser is an opt-in capability; a pure-HTTP tier is the default |
| Model load time | ASR/TTS models are 34 MB–2 GB | **Lazy load + idle unload.** Never hold a model resident "just in case" |
| SQLite page cache | Default is fine but unbounded growth is possible | Explicit `PRAGMA cache_size`; bounded in-memory caches (`moka`) |
| Audit log growth | Append-only | Rotation + size cap; export rather than retain forever |

---

## 7. Performance test harness (required before optimising)

**Do not optimise what has not been measured.** The harness:

1. **Criterion-style micro-benchmarks** for hot paths (policy evaluation, audit
   append, task claim, schema validation). No network, no LLM.
2. **Startup benchmarks** in release mode, cold and warm, across a feature
   matrix. Committed baselines; CI compares.
3. **Allocation assertions** — `#[global_allocator]` counting in tests, to catch
   regressions that RSS alone would hide.
4. **A soak test** — 72 h of simulated task churn, verifying no RSS growth, no
   WAL growth without checkpointing, and no scheduler drift.
5. **DST correctness tests** — schedule across spring-forward and fall-back
   transitions, asserting the documented `croner` semantics.
6. **A crash/power-loss harness** — kill -9 at randomised points; assert that
   no task is lost, duplicated, or stuck in `running` with a dead lease.
7. **End-to-end latency** for a scripted daily scenario, with per-stage timing.

Measure on the **baseline profile** (2 cores, 4 GiB, no GPU) in CI, not only on
the reference machine.

---

## 8. Performance risks

| Risk | Impact | Mitigation |
|---|---|---|
| WebKitGTK memory higher than expected on some distros | Breaks the 150 MB GUI assumption | GUI is optional and separate; measure on 3 distros in Phase 1 |
| ONNX Runtime build/link time and binary size | Slow builds, large binaries for ASR | Lazy feature gating; prebuilt `-lib`; document build cost |
| `synchronous=FULL` fsync cost on slow storage | Misses the 5 ms transition target | Measure on baseline; if HDD is a target, offer a documented `NORMAL` mode with a loud power-loss warning |
| Audit hash-chain grows the write path | Latency creep | Batch appends per transaction, not per record |
| Model files in the install directory | Disk bloat, and users forget | Registry with explicit install/uninstall, disk accounting in the UI |
| Concurrent browser tabs | RAM blowup | Per-context caps; hard kill at a ceiling |
| LLM prompt growth over months | Cost and latency creep | Context budgeting, summarisation with provenance, hard token caps |

---

## 9. Acceptance criteria for the resource model

The model is satisfied when, in CI:

- [ ] Core-only idle RSS < 60 MB on the baseline profile
- [ ] Core-only binary < 40 MB
- [ ] Core-only cold start < 150 ms on baseline
- [ ] Adding any optional feature does not change core-only measurements
- [ ] `default` features and `all-features` builds both exist; deltas are recorded
- [ ] 72 h soak shows no RSS or unbounded-WAL growth
- [ ] Kill -9 at 10 000 random points leaves no lost, duplicated, or orphaned task
- [ ] A task cannot be created without a spend ceiling
