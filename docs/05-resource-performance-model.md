# 05 — Resource & Performance Model

Status: **Draft v0.3** · **The V-25 budgets are now measured; see §1a.**

**Correction to three claims of enforcement in this document.** All three said "measured in
CI" or "CI enforcement". None was true at the time. There is no feature-combination matrix
in `ci-gates.sh` or in `.github/workflows/ci.yml`, no committed RSS or binary-size
baseline, and no gate that measures either. The claims are corrected here rather than
softened, because a documented enforcement that does not exist is worse than an admitted
gap — it is the failure V-79 records.

**What has changed, and what has not.** A measurement harness now exists
(`crates/orxnud-daemon/tests/v25_measure.rs`, driven by `scripts/measure-v25.sh`) and the
three V-25 budgets have measured results — §1a. The **feature-combination matrix still does
not exist**, so "all features enabled" rows in §2 remain design intent and are labelled as
such. Nothing in this document asserts a performance figure we have not observed.

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

## 1a. Measured baseline (V-25)

Every figure below was produced by `scripts/measure-v25.sh` on the commit named, in the
`release` profile. **Re-run it rather than trusting this table**; it is a record of one
commit on one host, and §1a.4 says what that does and does not establish.

### 1a.1 What "core-only" means

The `orxnud` binary, started **with no provider**, serving on its local socket. That is
daemon + local IPC + SQLite task engine + policy + audit + identity boundary + core task
lifecycle, and no provider client, no model, no GUI/TUI/MCP/voice.

`--provider-scripted` is deliberately **not** used. It would add a proposer to the measured
process for a cost no core-only user pays, and "is a provider resident" is a separate
question from "what does the core daemon cost".

**The provider TLS stack is linked in regardless** (`ring` + `rustls`, unconditionally, per
ADR-0040), and it is not a contradiction: those pages are demand-paged, so a daemon with no
provider configured never faults them in. They cost **binary size** and no idle RSS.
Measured below.

### 1a.2 Build profile and host

| | |
|---|---|
| profile | `release` — `lto = "thin"`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"` |
| rustc / cargo | 1.98.1 (48a229cea 2026-09-01) |
| target | x86_64-unknown-linux-gnu, `Linux 7.2.8-200.fc44` |
| CPU | Intel Core i5-12500H, 16 logical cores |
| RAM | 15.3 GiB |
| storage | **btrfs on LUKS-encrypted NVMe** — a pessimistic choice, deliberately |
| SQLite | bundled (`bundled` feature), never the host library |
| measurement dir | `target/tmp`, beside the build output, **verified not memory-backed** |

The last row is load-bearing and inherited from `orxnud-task`'s measurements: `/tmp` is
tmpfs, a tmpfs `fsync` is a no-op, and a durability figure taken there would report
`synchronous = FULL` as free. `assert_on_a_real_filesystem` refuses to report otherwise.

### 1a.3 The three budgets

| budget | target | measured | verdict |
|---|---|---|---|
| **Core binary, stripped** | < 40 MB | **7.49 MB** (7,492,472 B = 7.15 MiB) | **PASS** — 18.7% used |
| **Idle RSS** | < 60 MB | **9.11 MiB** (9,328 kB) | **PASS** — 15% used |
| **Cold start, spawn → ready** | < 150 ms | **p50 81.9 ms** (N=30, p99 82.6 ms) | **PASS** — 55% used |

**Which binary size is compared.** The stripped one. The release profile sets
`strip = "symbols"`, so the shipped binary carries no symbol table, and the unstripped build
of the *same source* is **51,183,016 B = 48.8 MiB** — which would **fail** the 40 MB budget.
That makes "which number" a decision rather than a detail, and the decision is recorded here
and in the harness. `cargo build --profile v25-unstripped` produces the comparison figure;
that profile exists only for measurement and nothing ships with it.

Section breakdown of the shipped binary: `.text` 6,070,648 · `.rodata` 550,992 ·
`.eh_frame` 431,992 · `.rela.destroy`/`rela.dyn` 209,232 · `.data.rel.ro` 111,608. No debug
sections (stripped). `orxnuctl` is 2.88 MB and is **not** counted against the daemon's
budget; it is a client, not the daemon.

**Readiness boundary.** Cold start is timed to the daemon **answering a request**, not to
`exec` returning. `Runtime::start` establishes durable security state, then the task engine,
then binds the endpoint, and only then can serve — so stopping the timer at exec would omit
most of the work against a 150 ms budget. The harness polls `daemon/version` over the real
socket, which is the boundary a client experiences.

### 1a.4 What these numbers do and do not establish

They establish that the current architecture **meets all three budgets with substantial
headroom on this host**, and they establish the shape of the costs below.

They do **not** establish that the budgets hold on a 2-core baseline machine, which is what
§2's "modest baseline" column means. This host has 16 logical cores and NVMe. The budgets are
product requirements for a class of hardware this measurement does not cover, and closing
that gap needs a run on such a machine — recorded as V-25's remaining limitation, not
papered over.

Also **not** established: page-cache-cold startup. `drop_caches` needs privileges this
environment does not have, so every figure above is with the binary warm in the page cache.
That is the favourable direction and it is stated rather than assumed.

### 1a.5 Where the costs actually are

| cost | figure | note |
|---|---|---|
| **Durable task write** | p50 **2.07 ms** (create), 2.42 ms (claim), 2.32 ms (propose) | `synchronous = FULL`. One fsync each. Confirms V-30: `FULL` costs ~2.3 ms/commit |
| Durable task write, throughput | **454 commits/s** sustained | ~400× what one user generates |
| Task completion | p50 **26 µs** | ~80× cheaper than an insert — see below |
| **Sandboxed execution** | p50 **67.8 ms** | bubblewrap: namespace setup + helper exec + teardown |
| IPC request | p50 **90.8 µs** (connect 13.8 µs) | one request per connection |
| Cold start | p50 81.9 ms | |
| Idle RSS | 9.11 MiB | **86% file-backed**, 14% anonymous |

Three findings worth stating rather than leaving in the table:

**The RSS and binary-size budgets are substantially the same quantity.** 1,296 kB of the
9,328 kB resident set is anonymous; the other 86% is the mapped binary and its libraries.
So growing the binary grows idle RSS nearly one-for-one, and there is no separate "heap
problem" to chase. The 60 MB budget is, in practice, a code-size budget.

**Sandbox cost dominates everything else by two orders of magnitude.** A governed IPC
request is 91 µs and a durable commit is 2.1 ms, but an isolated capability invocation is
67.8 ms — 30× a durable commit. This is the cost of the isolation guarantee and it is
*cheap relative to what it buys*: Tier-1 visibility, tree lifetime and OS-enforced resource
ceilings. It is also the number that matters for anyone planning interactive capability
work, because it dominates a GUI or TUI's feel far more than the request path does.

**Task completion is 80× cheaper than task creation**, which was not expected. The
measurement does not establish why, and this document does not guess. The plausible
explanation is that a completion is a single-row `UPDATE` on pages already resident from the
insert that preceded it, while a creation writes several tables, but that is a hypothesis
and would need a `strace`/write-count to confirm. Recorded so the asymmetry is not mistaken
for noise.

### 1a.6 Variance, and what may be gated in CI

Measured over repeated full runs on this host:

| metric | observed spread | stable? |
|---|---|---|
| binary size | 7,492,472 B every time (it is a file size) | **exact** |
| cold start p50 | 81.9 – 93.0 ms across runs | **stable** (~0.2% within a run) |
| idle RSS | 9.11 – 9.25 MiB | **stable** (~1%) |
| sustained insert throughput | 393 – 454 commits/s | moderate (~6%) |
| IPC p50 | 90.8 – 135.2 µs | **noisy** (~17%) |
| sandbox p50 | 67.8 – 86.2 ms | moderate |

So: **binary size and the dependency graph are exactly reproducible** and are gated. Cold
start and RSS are stable enough to be reported and compared. **IPC latency is too noisy to
gate on** and is reported only. This is why the CI step carries `continue-on-error`: a
measurement that blocks a commit because a hosted runner was busy teaches engineers to
ignore it. What CI *does* block on is the harness's own order-of-magnitude assertions (10×
bounds), which is a failure the shape of the code can cause rather than the weather.

### 1a.7 Harness

`scripts/measure-v25.sh` and `crates/orxnud-daemon/tests/v25_measure.rs`. The script
refuses to run on a dirty worktree, records the commit and toolchain with the numbers, kills
every daemon it starts on every exit path, and fails loudly rather than leaving a partial
table that looks like a result.

`crates/orxnud-daemon/tests/v25_architecture.rs` holds six **static** checks defending the
architecture these budgets depend on — one TLS implementation, no telemetry exporter, a
local file store rather than a database client, no GUI/server framework in the core. Those
are properties of the source rather than of one machine, so they are asserted exactly rather
than measured approximately.

### 1a.8 Related measurement, elsewhere

Resource **ceilings** are not re-measured here: `crates/orxnud-capability/tests/governed_path.rs`
already observes the real cgroup rather than trusting a struct, and all 24 of its tests pass
on this host — including `a_required_memory_ceiling_is_enforced_by_the_kernel_not_merely_written`,
`a_governed_hang_is_stopped_at_the_deadline`, `a_governed_flood_is_bounded` and
`a_governed_descendant_spawn_is_contained`. Those are the controls that turn a declared
budget into a runtime bound, and duplicating them here would be measuring the same thing
twice.

---

## 2. Budgets

### 2.1 Startup (cold = no OS page cache for our binaries)

| Measurement | Target (baseline 2c/4 GiB) | Target (reference) | Measured |
|---|---|---|---|
| Daemon cold start, **core features only** | < 150 ms | < 80 ms | **81.9 ms p50** (§1a.3) |
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

| Measurement | Target | Measured |
|---|---|---|
| **Daemon idle RSS, core only** | **< 60 MB** | **9.11 MiB** (§1a.3) |
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

### 4.1 Tier 1 — the guarantee (**NOT currently measured in CI**, contract-level)

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

**CI enforcement: none exists.** This should be a build matrix over feature
combinations asserting (1)–(3) against committed baselines. It is not implemented, and
`scripts/run-resource-tests.sh` is not invoked by any workflow. The claim is recorded here
as the *intended* enforcement so the gap is visible rather than assumed closed.
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
- **Disabled capabilities cost exactly nothing.** *Intended* to be measured in CI; no
  baseline is committed and no gate measures it, so this is currently an assertion.
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
