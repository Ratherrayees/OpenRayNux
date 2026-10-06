# 10 — Open Questions

Status: **Draft v0.3** · Reconciled **2026-10-05** against `HEAD`.

**This file says it contains "only unresolved items", and it did not — it also held three
resolved answers as full records.** That is a defensible format and it is kept, but the
header now says so, because a reader needs to know that a `✅ RESOLVED` entry here is a
preserved answer rather than a live question.

**Six entries changed status on 2026-10-05** because the code answered them, not because
the questions got easier: Q-OPEN-14 (partly), Q-OPEN-15 (owner), Q-OPEN-16 (closed by
delivery), Q-OPEN-18 (owner), Q-OPEN-20 (interim position falsified by delivery), and
Q-OPEN-01 (interim position overtaken by a different mechanism). Each says which.

This document contains **only unresolved items**. Anything decided is in
`09-decisions.md`; anything required is in `00-system-requirements.md`.

Each question states: the question, why it matters, what we will do **in the
meantime**, and what would settle it. "In the meantime" matters most — an open
question with no interim position is a decision deferred to whoever reads it
last.

---

## Q-OPEN-01 — Telegram's ToS §1.5 and AI inference on message content 🔴 **BLOCKING for Telegram**

> **Reconciled 2026-10-05 — still open, but the interim position was overtaken.** The
> question is a legal one and it remains unanswered; ADR-0016 and V-16 still make Telegram
> notification-output-only. What changed is the *enforcement*. The interim position said
> "Phase 1 must build the adapter boundary capable of the notification-only implementation",
> and **that was not built** — there is no messaging code at all
> (`grep -rn telegram crates --include=*.rs` returns nothing). What shipped instead is
> stronger for the case that does exist: reads are governed structurally rather than by
> convention, with `filesystem/read-text` at `RiskClass::High` requiring approval per read,
> and ADR-0045/ADR-0046 governing what may then be disclosed and to whom. So: no Telegram
> adapter, no interim position, and the boundary it was meant to protect is enforced at a
> different layer.

**Question.** Telegram's API Terms §1.5 state:

> "you are prohibited from using, accessing or aggregating data obtained from the
> Telegram platform to **train, fine-tune or otherwise engage in the development,
> enhancement or deployment of artificial intelligence**, machine learning models
> and similar technologies."

Is an assistant that *reads a user's own Telegram messages via a bot and runs
inference on them* a violation?

**Why it matters.** If yes, the Telegram integration cannot include any
intelligence — which removes it from the "message me things" use case entirely
and makes it a notification sink. This is a legal question, and it is
first-order for FR-09.

**Interim position (confirmed by review 2026-09-30 — do not block on this).**
Telegram ships as **notification output only**: outbound-only, plus commands
*into* the bot. No reading of message content, no inference on it. The
capability is behind its own toggle and defaults to the restricted mode.

**This question does not block the core architecture**, and must not be
allowed to. The messaging capability's *contract* is provider-neutral
(ADR-0016), so the restricted implementation is fully expressible today.
Phase 1 must therefore build the **adapter boundary capable of the
notification-only implementation**, and treat broader scope as a separate,
later review gate.

**What settles it.** Legal counsel, or a written clarification from Telegram.
**Owner:** project lead. **Blocks:** the Telegram messaging capability's v1 scope.

**Related.** Telegram's "one `api_id` per phone number" constraint and the fact
that GramJS and Telethon are both archived make userbots unattractive on
maintenance grounds too (ADR-0016).

---

## Q-OPEN-02 — `apalis-sqlite`'s durability pragma ✅ **RESOLVED 2026-09-30**

**Question.** What `PRAGMA synchronous` does `apalis-sqlite` use by default, and
is `journal_mode=WAL` enabled?

**Answer, read directly from the published crate** (`apalis-sqlite` `1.0.0-rc.9`,
`src/lib.rs:149–166`):

```rust
sqlx::query("PRAGMA journal_mode = 'WAL';").execute(pool).await?;      // WAL: yes
sqlx::query("PRAGMA temp_store = MEMORY;").execute(pool).await?;
sqlx::query("PRAGMA synchronous = OFF;").execute(pool).await?;          // ← OFF
```

- **WAL: yes**, as required.
- **`synchronous = OFF`** — *weaker* than `NORMAL`. Per `sqlite.org/wal.html`,
  data survives an application crash but **the database may become corrupted on
  OS crash or power loss**.
- **No configuration knob.** `synchronous` appears once in the whole `src/` tree;
  `config.rs` exposes no durability settings.
- **Applied per-pool, not per-connection** (a one-shot `.execute(pool)`, not in the
  `after_connect` hook the crate does register) — and `synchronous` is a
  per-connection pragma, so durability is at best unreliable and at worst
  inconsistent between connections.
- **TP-5 only partial.** `ack.sql` fences on `lock_by` identity but **not on lease
  expiry**, so a zombie worker whose task has not been re-claimed can still commit.
- **No stable release has ever shipped** — all 14 versions are pre-releases.

**Consequence.** **Rejected.** This fails **TP-7** outright, which is the property
the brief's power-loss requirement exists to guarantee. ADR-0007's contingency is
**closed**: the hand-rolled engine is currently the only known conforming
implementation. See **[ADR-0032](09-decisions.md#adr-0032)**. Registered as V-21.

**What would reopen it.** *Both* a documented durability configuration *and* a
passing ADR-0029 conformance suite (TP-7 and TP-5 specifically). A stable 1.0
alone is not enough. `apalis` remains usable for **non-critical** work such as a
best-effort notification queue.

## Q-OPEN-03 — Node 26 vs the LTS requirement ✅ **RESOLVED 2026-09-30**

**Question.** `node` on this workstation resolves to **v26.7.0** (Node *Current*,
`lts=false`) via `~/.local/bin/node` → `~/.hermes/node/bin/node`, shadowing
Fedora's `nodejs24-24.18.0` at `/usr/bin/node`. **How should Node ownership be
resolved?**

**Resolution — an OpenRayNux-local pinned runtime, global state untouched.**

| | |
|---|---|
| **Runtime** | `.toolchains/node-v24.21.0-linux-x64/` (project-local, gitignored) |
| **Source** | official `nodejs.org` tarball for **v24.21.0** (LTS codename **"Krypton"**, 2026-09-07) |
| **Integrity** | SHA-256 `fd8e59d5…f56cb2d6`, verified against the published `SHASUMS256.txt` — **`OK`** |
| **Verified** | `node --version` → `v24.21.0`; `npm` 11.19.0; `pnpm --version` → 12.8.1 works against it |
| **Declaration** | committed `.node-version` = `24.21.0` (consumable by any future version manager) |
| **Global state** | **unchanged** — `PATH` hash byte-identical to its pre-task value; `~/.bashrc`, `~/.bash_profile`, `~/.profile` mtimes all predate today; `~/.local/bin` untouched; **Hermes still resolves `node` → v26.7.0** |

**Why this and not fnm on `PATH`.** Changing the default `node` would make Node 24
the runtime for *every* tool on the machine — including Hermes and the
globally-installed npm CLIs. That is a cross-application change made for one
application's benefit, and it adjudicates a conflict between two applications
with legitimate, incompatible needs rather than removing the contention. A
project-local runtime is additive, reversible by deleting one directory, and
reproducible from `.node-version` plus a published hash.

**Consequence.** The frontend build has a correct LTS runtime without any global
change. See **[ADR-0031](09-decisions.md#adr-0031)**. Registered as V-05: re-verify
when Krypton leaves maintenance or a new LTS codename appears.

**Remaining sub-item.** The frontend needs a **dual TypeScript install**
(`typescript@~6` plus `@typescript/native@npm:typescript@7`, per ADR-0005 rev 2),
so the toolchain must resolve npm aliases. That is a `pnpm` configuration detail
and is a Phase 6 deliverable, tracked in **Q-OPEN-21**.

## Q-OPEN-04 — Duplicate empty workspace directories 🟢 **cosmetic, BLOCKING for `git init`**

**Question.** Two empty directories exist: `~/Projects/OpenSource/OpenRayNux`
(created per the brief) and `~/Projects/OpenRayNux` (pre-existing, and the
current shell's working directory). Which is canonical?

**Why it matters.** Cosmetic until `git init`, at which point it is a wrong-repo
in-the-wrong-place problem.

**Interim position.** All documentation is in `~/Projects/OpenSource/OpenRayNux`
per the brief. Nothing else has been done to either directory.

**What settles it.** A user decision. **Owner:** project lead. **Blocks:**
repository initialisation (Phase 1).

---

## Q-OPEN-05 — Is the model cost ceiling per-provider or per-user? 🟡

**Question.** NR-01 requires spend ceilings. Should the budget be a global
user-level budget, per provider, or per capability group — and should a ceiling
be *hard* (refuse) or *advisory* (warn)?

**Interim position.** Hard ceilings at L0–L3; advisory at L4–L5 (explicit
grant). A hard global daily ceiling plus per-provider sub-ceilings. Recurring
tasks cannot be created without a ceiling.

**What settles it.** Real usage data from a running instance, and a decision
about whether users prefer being stopped or warned. **Owner:** implementer, after
Phase 5.

---

## Q-OPEN-06 — What is the tenancy boundary for P4? 🟡

**Question.** If multi-tenant cloud ever happens, is tenancy at the database
level (row-level, separate schemas, or separate databases per tenant), the
process level, or both?

**Interim position.** NR-04 requires the *data model* to anticipate it (profile
support from day one) but P4 is explicitly out of scope. Single-tenant cloud
uses SQLite; multi-tenancy would require Postgres.

**What settles it.** Whether multi-tenancy is ever a real requirement. Until
then the honest answer is "separate database per tenant", which is the simplest
correct isolation and does not need deciding now.

---

## Q-OPEN-07 — Which cloud ASR/TTS, if any, and under what default? 🟢

**Question.** Local-first is the default. When cloud is enabled, which provider
is the default, and is the choice global or per-capability?

**Evidence gathered** (all verified 2026-09-30, prices per hour): OpenAI
`gpt-4o-mini-transcribe` $0.18, `whisper-1` $0.36; Google STT v2 Standard $0.96,
Dynamic Batch $0.18; AWS Transcribe $0.36 batch / $0.60 streaming; Deepgram
Nova-3 ~$0.26–0.46 ⚠ unverified against the official page; Azure ~$0.18–1.00 ⚠
**unverified** (JS-rendered page); Groq WLV3-Turbo ~$0.04 ⚠ unverified. OpenAI's
newer transcribe models return **`json` only** — only legacy `whisper-1` still
returns word timestamps.

**Interim position.** No cloud default. Cloud is opt-in per capability, with the
price shown before enabling. Word-timestamp dependence (if any) would lock us to
a legacy model, so avoid depending on them.

**What settles it.** Actual user preference and a re-check of pricing at
implementation time. **Owner:** implementer, Phase 7+.

---

## Q-OPEN-08 — Is `ort`'s 2.0 RC acceptable long-term? 🟡

**Question.** `ort` (ONNX Runtime for Rust) has never released a 2.0 stable; the
newest stable is **1.16.3 from 2023-11-12** and the newest is
**`2.0.0-rc.13` (2026-07-28)**. `parakeet-rs` depends on the RC. Do we accept
this for the ASR path?

**Interim position.** Accept, but do not make it load-bearing. `sherpa-onnx` is
the default and does not use `ort`; `parakeet-rs` is an optional engine.

**What settles it.** `ort` 2.0 GA, or a mature alternative. **Owner:**
implementer — re-check at every voice-related phase.

---

## Q-OPEN-09 — Should we vendor `whisper-rs`? 🟢

**Question.** `whisper-rs` 0.16.0 (2026-03-12) has an **archived** GitHub repo
(moved to Codeberg), one dominant maintainer, and version skew between
`whisper-rs` 0.16.0 and `whisper-rs-sys` 0.15.0. It is also the most
battle-tested local ASR in existence (54 k★, a decade of use).

**Interim position.** Not a default engine. If adopted, vendor it.

**What settles it.** Whether `whisper.cpp`'s acceleration breadth (Vulkan,
CoreML, OpenVINO) proves necessary for target hardware. **Owner:** implementer.

---

## Q-OPEN-10 — What is the migration story for a user's *existing* RayNux data? 🟡

**Question.** OpenRayNux must not inherit RayNux's accidental architecture — but
a real user may have years of RayNux data. Is there a one-way import, and if so
at what fidelity?

**Interim position.** **No import in v1.** The brief is explicit that OpenRayNux
is designed from scratch. A lossy import would import RayNux's data model, which
is the thing being avoided.

**What settles it.** Whether the user wants continuity more than a clean model.
**Owner:** project lead. **Blocks:** nothing, but a late import is far more
expensive than an early one.

---

## Q-OPEN-11 — How are model weights licensed-tracked in practice? 🟢

**Question.** ADR-0019 requires a model-licence registry with manual review. With
hundreds of candidate models, what is the sustainable process?

**Interim position.** A registry file in the repository, listing only models we
actually offer, each with its licence, source URL, and checksum, reviewed on
addition. Explicitly *not* an attempt to enumerate the model universe.

**What settles it.** Experience after the first few additions. **Owner:**
implementer.

---

## Q-OPEN-12 — Does the a11y-tree-first grounding assumption hold on real sites? 🟡

**Question.** ADR-0015 grounds on the accessibility tree first. How often will
real target sites defeat that, forcing escalation to visual grounding or a
`data-testid` injection?

**Interim position.** Assume it holds often enough to be the default, and
**measure the escalation rate** in a real pilot. If escalation is near 100 %,
the HTTP-first + accessibility-tree pairing is mis-designed and needs revisiting
before it is built at scale.

**What settles it.** A pilot against ~20 real target sites, recording the tier
that satisfied each request. **Owner:** implementer, Phase 7.

---

## Q-OPEN-13 — Is one approval mechanism enough across GUI, TUI, CLI, and messaging? 🟢

**Question.** Approval needs a rich preview (screenshot, highlighted element,
exact parameters). A messaging interface cannot show a screenshot. What is the
approval UX on a channel with no rich rendering?

**Interim position.** A capability declares its `preview_capability`
(`rich` | `text` | `none`). Capabilities that cannot produce an adequate preview
in a given interface are **not offered** there — or downgrade to text-only, which
raises the risk classification and requires a stronger confirmation phrase.
Never silently show less and let the user approve blind.

**What settles it.** Designing the messaging interface (Phase 8).

---

## Q-OPEN-14 — What happens to a task whose *approval expires* mid-workflow? 🟡

> **Reconciled 2026-10-06.** **The expiry half is answered and closed; the session-grant half is still prose, and still open.** Two independent halves were conflated here and V-82 tracked only one of them.
>
> *Per-step re-approval* **shipped**: the approval digest is v3 and binds `step_no`, so one consent cannot cover a sibling step (ADR-0037, V-83).
>
> *What an expired approval means* **shipped**: an expired approval authorises nothing, and a proposal whose approval expired unconsumed can be approved again — a fresh digest, not an extension. ADR-0049; V-82 is closed.
>
> *The scoped session grant* is **still not implemented** — `grep -rn 'session_grant' crates` returns nothing, and ADR-0049 explicitly declines it. **This half remains open**, and deliberately so: recovery from an expiry is not a grant, and nothing in ADR-0049 shortens the re-approval round trip.

**Question.** Approvals are short-lived and single-use (S6) and are never
inherited by a retry. For a long workflow, does the user re-approve each
consequential step (correct but tedious), or is there a scoped grant?

**What is still open.** Only the ergonomics question, and only in its
"should a long workflow not need a prompt per step" form. The failure mode is
no longer "an expired approval bricks the task" — that is fixed and pinned —
so what remains is the *tedium*, not the dead end.

**Interim position.** Per-step re-approval for anything above L3, with the UI
offering an explicit **scoped session grant** ("allow *sending mail to these
recipients* for the next 30 minutes") that is itself logged, time-bounded, and
revocable. Never an open-ended grant.

**What settles it.** Real long-workflow ergonomics testing. **Owner:**
implementer, Phase 3.

---

## Q-OPEN-15 — Do we need a formal policy language for permissions? 🟢

> **Reconciled 2026-10-05.** **Owner corrected; the question is still open.** The interim position — a hand-written, typed, testable evaluator — is what ships, and the limitation is now documented rather than theoretical: `BudgetLedger::permits_all` is **conjunctive**, so four per-risk ceilings are one constraint on a single number and "fund the cheap scope, zero the rest" silently refuses everything (V-61). The shipped budget is therefore a single `with_global` ceiling. Owner is no longer "implementer, Phase 3"; Phase 3 is shipped.

**Question.** The policy engine evaluates permissions. At what complexity does a
hand-written evaluator stop sufficating, and does that justify a rule language
(a Datalog/POL/Rego-like system)?

**Interim position.** A hand-written, typed, testable evaluator with a
closed vocabulary of facts. **No** rule language. The brief's own warning —
"do not over-engineer" — and ADR-0024's lesson about abstractions that obscure
the thing they wrap both apply.

**What settles it.** Revisit at the *fifth* real policy, not before (our own
`08-…` §22 rule). **Owner:** implementer, Phase 3.

---

## Q-OPEN-16 — Should the daemon be one process or a small supervisor + workers? 🟢

> **Reconciled 2026-10-05.** **Closed by decision and delivery.** The interim position — one daemon, with Tier-1/2 adapters in separate processes — is what is built. `orxnud-daemon/src/lib.rs` is the composition root and owns the single-instance lock; a `Subprocess` capability runs as a real child under `bwrap`. The owner line still said "implementer, Phase 4", which was stale by two phases.

**Question.** ADR-0004 puts everything in one daemon process with in-process
adapters. Is that right, or should Tier 1/2 adapters each get a supervised
worker so a wedged adapter cannot consume daemon resources?

**Interim position.** One daemon. Tier 1/2 adapters are already separate
processes with declared resource limits, timeouts, and quarantine — which
addresses the actual risk (an adapter misbehaving) without multiplying processes.
The daemon itself supervises its internal task tree.

**What settles it.** If an adapter can degrade daemon performance despite its
limits, the answer becomes "workers". **Owner:** implementer, Phase 4.

---

## Q-OPEN-17 — Is `synchronous = FULL` affordable? ✅ RESOLVED 2026-09-30

**Question.** ADR-0006 requires `synchronous=FULL` for power-loss durability,
which costs an fsync per transaction. Does that threaten the transition-latency
target (< 5 ms)?

**Answer, measured** (V-30; `crates/orxnud-task/tests/measurements.rs`, btrfs over
LUKS, SQLite 3.53.2 bundled, Rust 1.98.1):

| Operation | `synchronous = FULL` | `synchronous = NORMAL` |
|---|---|---|
| `enqueue` (one fsynced commit) | **~2.3 ms** | ~0.2–0.3 ms |
| `claim` (fenced, work available) | 2.6–2.9 ms | — |
| `complete` (fenced commit) | 2.2–3.4 ms | — |
| `recover` (500 orphaned leases, bulk) | 54–78 µs/op | — |
| idle scheduler pass + wakeup query | 16–26 µs/op | — |

**Verdict.** Affordable, with roughly 30–55% headroom against the < 5 ms budget —
about 430 state transitions per second, far above what one user generates.

**The ratio is a range, not a number.** Four runs gave 7.3×, 12.0×, 13.2× and
14.3×, because the `NORMAL` baseline is a fraction of a millisecond and therefore
dominated by disk scheduling noise. The reliable figure is the magnitude
(~2.3 ms per commit); quoting a single ratio would imply a precision the
measurement does not have.

**Decision: the default stays `FULL`.** ADR-0008's revisit condition is explicit
that the answer would be to *"demote the cheapest-to-lose region, never weaken the
task table"* — and the task table is the region that matters. A `NORMAL` mode
exists and is tested (`Pragma::derived`); selecting it for the task connection
requires an ADR and a loud warning, and it does not survive power loss.

**A trap worth recording (V-31).** The first run of this measurement put its
databases in `/tmp`, which is **tmpfs** on this host, where `fsync` costs 3 µs
because it does nothing. That run reported `FULL` and `NORMAL` as **identical**. It
would have "shown" that `FULL` is free, and quoting that as a result would have been the
more dangerous error of the two. The harness now refuses to measure
durability on a memory-backed filesystem, and says which variable to set.

**Caveat.** btrfs-over-LUKS is a pessimistic case: the numbers will be materially
better on an unencrypted SSD and materially worse on rotational storage.

---

## Q-OPEN-18 — What is the recovery UX for a task that may have had a side effect? 🟡

> **Reconciled 2026-10-05.** **Owner corrected; still open.** The `NeedsVerification` task state exists (`orxnud-domain/src/task_state.rs`) and is reachable, but nothing offers the three choices this question is about — assume succeeded, retry, verify externally — so the UX is unbuilt. Owner is no longer "implementer, Phase 3".

**Question.** A crash during a non-idempotent step (a job application submitted,
a message sent) leaves us unable to know whether the effect occurred. S7 says
mark it `needs_verification` and require human confirmation. But how does the
system *present* that to a user who may not remember the context?

> **Reconciled 2026-10-06 — SPLIT. The backend half is closed by V-92; the
> user-facing half remains open.** The reconciliation above said `NeedsVerification`
> "exists and is reachable". **It existed and was not reachable** — no production
> path produced it. Every handler instead left an uncertain task `running` under
> its lease, which meant the next recovery pass returned it to `pending`, where
> `claim` found it, and the same non-idempotent action could be proposed,
> approved and executed again. The daemon was saying *"we don't know whether it
> happened, so we tried again"* — with no human involved, at the next process
> start.
>
> **Closed by V-92 (backend):** an uncertain effect on a non-idempotent capability
> now becomes `NeedsVerification`, durably. Terminal, not claimable, not touched
> by recovery, lease released, reason persisted, and it survives restart. A
> disproved effect and an idempotent capability take the ordinary retry path.
> Nothing about the three choices is implied by the state, and nothing guesses.
>
> **Still open (this question):** how a user is *shown* it and what the three
> choices do. The state exists; the affordance does not.

**Interim position.** The task record shows the exact action that may have
succeeded, with the target, parameters, and timestamp, and offers three explicit
choices: *assume it succeeded and continue* · *retry* · *verify externally first*.
It never guesses.

**What settles it.** Designing the failure UX, and possibly a per-capability
"probe" operation (e.g. "did this application get submitted?"). Two constraints
are now settled by V-92 and constrain that design:

* **"Assume it succeeded" must not be recorded as verification.** A human
  adjudicating an uncertainty and a verifier establishing a fact are different
  events, and conflating them would write a false `verified = true` into the audit
  chain. The adjudication needs its own typed representation; the state machine
  deliberately leaves that space free.
* **"Retry" must not reuse the old approval.** V-82's expiry/replacement rules
  and TP-6 apply unchanged, and an adjudication that authorises a retry has to go
  through the ordinary approval path rather than reviving the spent one.

**Owner:** implementer, Phase 3.

---

## Q-OPEN-19 — Should observations (TS-07 style) be part of v1? 🟢

**Question.** TUI accessibility is a genuine gap (Ratatui has no AT-SPI support,
and TUI is inherently visual). Does that make the TUI non-compliant with NR-07?

**Interim position.** NR-07 is scoped to the GUI and API. The TUI is documented as
an accessibility-exempt advanced interface, and the GUI is the accessible
default. Not ideal; honest.

**What settles it.** Whether a screen-reader-accessible TUI is achievable at all
— which is probably not, in a terminal.

---

## Q-OPEN-20 — What is the minimum viable "intelligence" for a first release? 🟡

> **Reconciled 2026-10-05.** **The interim position was falsified by delivery, and should be read as superseded rather than as guidance.** It said start with *structured extraction and classification*, then tool selection, then planning. What shipped first was **tool selection**: `task/ai-propose` builds a menu walked from the capability registry (ADR-0039) and a real model chose `filesystem/write-text` (V-75). Extraction and classification are not started. Whether that was the right rung is now an open question rather than a settled one.

**Question.** Phase 5 is "first AI provider". Is the first useful thing
*intent classification*, *tool selection*, *planning*, or *summarisation*? The
last is easiest and least risky; the first two are most useful.

**Interim position.** Start with **structured extraction and classification**
with strict schemas (lowest risk, no side effects, easy to evaluate), then tool
selection, then planning. Do not ship planning first — planning without
reliable classification compounds errors.

**What settles it.** The AI evaluation track (ADR-0025) once it has run. **Owner:**
implementer, Phase 5.

---

## Q-OPEN-21 — Do TS6 and `--tsgo` diagnostics agree on our code? 🟡

**Question.** We now adopt TypeScript 7.0.2 as the baseline with 6.0.3
co-installed. But `--tsgo` is documented as *"subject to the same limitations as
`--incremental`"*, and the two compilers are different implementations. Do they
report the same diagnostics on our code?

**Why it matters.** If they diverge, we have two possible type-checking answers
for the same file, and a contributor will eventually get whichever one their
editor happens to use. In a security-relevant UI, "which compiler told you this
is fine" should not be ambiguous.

**Interim position.** Run both over the codebase in Phase 6 and record any
divergence as a tracked issue. Do **not** disable TS7 on the basis of a
difference we have not yet observed — that would repeat the error ADR-0005 rev 2
corrected. Prefer TS7 as the reporting compiler where they agree, and treat
divergence as a bug to understand, not noise to suppress.

**What settles it.** A Phase 6 comparison run. **Owner:** implementer.
**Blocks:** nothing; it is a Phase 6 deliverable.

## Appendix A — Questions explicitly *not* asked (and why)

Recorded so their absence is a decision, not an oversight.

| Not asked | Why |
|---|---|
| "Is TypeScript 7 supported for Svelte?" | **Now answered — yes, via a flagged dual-install path.** It was wrongly treated as an open constraint in revision 1; see ADR-0005's amendment record and Q-OPEN-21 for the remaining *measured* question (diagnostic parity). |
| "Which LLM provider is best?" | Deliberately not a question — ADR-0011 makes the answer irrelevant to the design, and provider choice is a user preference. |
| "Should we use PostgreSQL?" | ADR-0006 settles it for the local case, and P4 is out of scope. |
| "How big should the team be?" | Not an architecture question. |
| "What is the roadmap date?" | Unknowns dominate; a date would be invented. |
| "Should we support Android/iOS?" | Explicitly out of scope; the API anticipates them (IR-3). |
| "Which vector database?" | ADR-0008 rejects the category. |
| "Should we use Kubernetes?" | Never, for a personal application. |
