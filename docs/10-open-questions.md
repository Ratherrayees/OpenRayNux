# 10 — Open Questions

Status: **Draft v0.1**

This document contains **only unresolved items**. Anything decided is in
`09-decisions.md`; anything required is in `00-system-requirements.md`.

Each question states: the question, why it matters, what we will do **in the
meantime**, and what would settle it. "In the meantime" matters most — an open
question with no interim position is a decision deferred to whoever reads it
last.

---

## Q-OPEN-01 — Telegram's ToS §1.5 and AI inference on message content 🔴 **BLOCKING for Telegram**

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

**Interim position.** Telegram ships as **notification output only** in v1 —
outbound-only, plus commands *into* the bot. No reading of message content, no
inference on it. The capability is behind its own toggle and defaults to the
restricted mode.

**What settles it.** Legal counsel, or a written clarification from Telegram.
**Owner:** project lead. **Blocks:** the Telegram messaging capability's v1 scope.

**Related.** Telegram's "one `api_id` per phone number" constraint and the fact
that GramJS and Telethon are both archived make userbots unattractive on
maintenance grounds too (ADR-0016).

---

## Q-OPEN-02 — `apalis-sqlite`'s durability pragma 🔴 **BLOCKING for ADR-0007 contingency**

**Question.** What `PRAGMA synchronous` does `apalis-sqlite` use by default, and
is `journal_mode=WAL` enabled?

**Why it matters.** `sqlite.org/wal.html` is explicit that
`synchronous=NORMAL` in WAL mode does **not** survive power loss. The brief
requires surviving power loss. If `apalis-sqlite` defaults to `NORMAL`, it
cannot be adopted without a patch, and ADR-0007's contingency evaporates.

**Interim position.** ADR-0007's primary decision stands: we hand-roll. This
question only gates the *contingency*.

**What settles it.** Read the source. Thirty minutes. **Owner:** implementer.
**Blocks:** the decision to switch to `apalis` if the hand-rolled engine exceeds
~600 lines.

---

## Q-OPEN-03 — Node 26 vs the LTS requirement 🟡 **BLOCKING for the first frontend build**

**Question.** `node` on this workstation resolves to **v26.7.0 (Current line,
`lts=false`)** via `~/.local/bin/node` → `~/.hermes/node/bin/node`, shadowing
Fedora's `nodejs24-24.18.0` at `/usr/bin/node`. Node **24.21.0 (LTS codename
"Krypton", 2026-09-07)** is the current LTS line and is what Vite 8 requires
(`engines: ^20.19.0 || >=22.12.0` — satisfied by both, but we want LTS).
**How should Node ownership be resolved?**

**Why it matters.** The environment-preparation phase deliberately deferred
this. It becomes blocking at the first `pnpm install` for the Svelte frontend.
Deferring it further means building a frontend on an unsupported Node line.

**Interim position.** Frontend builds pin Node via a checked-in
`.node-version` / `package.json` `engines` field, so the *project* declares its
requirement regardless of what the shell resolves. A developer using the wrong
Node gets a clear error rather than a mystery. The `pnpm` binary is already
user-scoped and version-pinned (12.8.1), so it is unaffected by the shell's
`node`.

**Now also required (ADR-0005 rev 2):** the frontend needs a *dual* TypeScript
install — `typescript@~6` plus `@typescript/native@npm:typescript@7` — so the
toolchain must be able to resolve npm aliases. That is a `pnpm`/`npm`
configuration detail, but it means the first frontend setup is not a bare
`pnpm install`.

**Options (user's call, not ours):** install fnm and make Node 24 LTS the
default (touches an existing tool's environment) · leave the shell alone and
require an explicit `fnm use` per session · use Fedora's `/usr/bin/node` directly
via a project-local `.npmrc`/toolchain pin.

**What settles it.** A user decision. **Owner:** project lead. **Blocks:**
Phase 6 (first interface with a frontend).

---

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

**Question.** Approvals are short-lived and single-use (S6) and are never
inherited by a retry. For a long workflow, does the user re-approve each
consequential step (correct but tedious), or is there a scoped grant?

**Interim position.** Per-step re-approval for anything above L3, with the UI
offering an explicit **scoped session grant** ("allow *sending mail to these
recipients* for the next 30 minutes") that is itself logged, time-bounded, and
revocable. Never an open-ended grant.

**What settles it.** Real long-workflow ergonomics testing. **Owner:**
implementer, Phase 3.

---

## Q-OPEN-15 — Do we need a formal policy language for permissions? 🟢

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

## Q-OPEN-17 — Is the 60 MB idle-RSS target realistic with `synchronous=FULL`? 🟡

**Question.** ADR-0006 requires `synchronous=FULL` for power-loss durability,
which costs an fsync per transaction. Does that threaten the transition-latency
target (< 5 ms) or the idle budget?

**Interim position.** Measure it in Phase 2. On an SSD an fsync is ~0.1–1 ms, so
it should be fine; on spinning disk it would not be. If baseline hardware
includes rotational storage, a documented `NORMAL` mode with a loud warning is
acceptable — the *default* stays `FULL`.

**What settles it.** The Phase 2 benchmark harness. **Owner:** implementer.

---

## Q-OPEN-18 — What is the recovery UX for a task that may have had a side effect? 🟡

**Question.** A crash during a non-idempotent step (a job application submitted,
a message sent) leaves us unable to know whether the effect occurred. S7 says
mark it `needs_verification` and require human confirmation. But how does the
system *present* that to a user who may not remember the context?

**Interim position.** The task record shows the exact action that may have
succeeded, with the target, parameters, and timestamp, and offers three explicit
choices: *assume it succeeded and continue* · *retry* · *verify externally first*.
It never guesses.

**What settles it.** Designing the failure UX, and possibly a per-capability
"probe" operation (e.g. "did this application get submitted?"). **Owner:**
implementer, Phase 3.

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
