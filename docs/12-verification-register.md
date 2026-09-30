# 12 — Verification Register & Freshness Policy

Status: **Draft v0.1** · Adopted 2026-09-30 in response to review.

---

## 1. The rule

> **Every architectural claim in this repository that can become false over time
> MUST have:**
>
> 1. a **verification source** — the authoritative place that would tell us it
>    changed, and
> 2. a **review trigger** — the specific, checkable event that makes us re-read
>    it, and
> 3. a **last-verified date**, and
> 4. a **named consequence** if it silently drifts.

A claim without these is an assumption wearing a decision's clothes. This
register makes the difference visible and gives each claim an owner.

**Why this exists.** Every major architecture decision in `09-decisions.md` rests
on an external fact that will change: a spec revision, a release, a licence, a
platform requirement. The TypeScript 7 incident in ADR-0005's amendment record is
the worked example: a claim that was *true but insufficiently checked* became a
wrong architectural decision, and it was only caught by a second reviewer. This
register exists so that the next such claim is caught by a *process*, not by
luck.

---

## 2. The register

Legend — **Cadence**: `event` (re-checked on a named trigger) · `quarterly` ·
`release` (re-checked before each release) · `milestone` (re-checked at a named
phase gate).

| ID | Claim | Verification source | Cadence / trigger | Last verified | Consequence of silent drift |
|----|-------|--------------------|-------------------|---------------|---------------------------|
| **V-01** | **MCP spec revision is `2026-07-28`; the protocol is stateless; Sampling/Roots/Logging are deprecated with a ≥12-month window; Tasks is an extension** | `https://modelcontextprotocol.io/specification/latest` and the versioned changelog at `/specification/2026-07-28/changelog` | **event:** any new revision date on the latest page; plus quarterly | 2026-09-30 | **High.** A new revision may reintroduce sessions, change the Tasks extension, or move a deprecation to removal. Our MRTR mapping and our stateless-safety argument (ADR-0010) both depend on it. |
| **V-02** | **SQLite minimum bundled version is ≥ 3.51.3** (WAL-reset corruption fix) | `https://www3.sqlite.org/releaselog/3_51_3.html`; WAL semantics at `https://sqlite.org/wal.html` | **release:** verify the bundled `SQLITE_VERSION_NUMBER` at build time; **event:** any new SQLite release note mentioning corruption | 2026-09-30 | **Critical.** Below 3.51.3 the task table can corrupt under our exact multi-connection write workload. Enforced by a build-time assertion (ADR-0006). |
| **V-03** | **SQLite `synchronous=NORMAL` does not survive power loss; `FULL` is required on the task connection** | `https://sqlite.org/wal.html` | **event:** any WAL documentation change; re-assert in the durability test | 2026-09-30 | **Critical.** The entire power-loss guarantee (TP-7) rests on it. |
| **V-04** | **Rust stable is 1.98.1; MSRV floor is 1.98.1** | `rustc --version`; the MSRV table in `02-technology-evaluation.md` §3.1 | **quarterly** + on any dependency bump | 2026-09-30 | **Medium.** `sqlx` needs 1.94 and `egui` 1.95; our floor is only 3–4 minor versions above the tightest. A silent MSRV rise would force a floor decision. |
| **V-05** | **Node 24.21.0 ("Krypton") is the current LTS line; Node 26.x is `lts=false`** | `https://nodejs.org/dist/index.json` (the `lts` field); the LTS schedule page | **event:** a new LTS codename appears; **quarterly** | 2026-09-30 | **Medium.** The frontend build runtime is pinned to an LTS line. When Krypton leaves maintenance, the toolchain ADR-0031 must be revisited. |
| **V-06** | **TypeScript 7.0.2 is latest stable; Svelte supports it via `svelte-check --tsgo` with TS6 co-installed; `svelte-check` 4.7.6** | `https://registry.npmjs.org/typescript/latest`; the `svelte-check` tarball's `README.md` **and `bin/ts-version-check.js`**; `svelte-language-server` | **event:** a new `svelte-check` major/minor; TS 7.1 shipping the stable API; any change to the peer range | 2026-09-30 | **High.** Getting this backwards again would pin a superseded compiler for a year. **Read the tool's source, not just its peer range** (ADR-0005 amendment). |
| **V-07** | **Tauri 2.12.0 is current stable; its Linux native dependency set is unchanged** | `https://tauri.app/blog/`; `crates.io/api/v1/crates/tauri`; `https://registry.npmjs.org/@tauri-apps/cli/latest` | **event:** a Tauri 2.x release; **release:** re-verify the Fedora native deps before packaging | 2026-09-30 | **Medium.** A dependency change breaks packaging silently — we would not find out until a build fails. |
| **V-08** | **Tauri 2's WebView memory cost is ~80–150 MB on Linux** | **No authoritative source exists.** Must be measured by us. | **milestone:** Phase 1, on ≥ 3 distributions | *unmeasured* | **Medium.** This is a *budget*, not a claim. If it is materially higher, ADR-0002's GUI decision must be revisited (Slint is the documented fallback). |
| **V-09** | **Windows requires Authenticode; MSI; MSVC; WebView2; long-path awareness; reserved-filename sanitisation** | `https://learn.microsoft.com/` (MSVC, WebView2, code signing, DPAPI, Task Scheduler) | **event:** any Microsoft packaging/signing policy change; **milestone:** Phase 1 | 2026-09-30 | **High.** Certificate procurement has external lead time (ADR-0026). A policy change discovered late delays a release. |
| **V-10** | **`sherpa-onnx` 1.13.8 is active, Apache-2.0, with first-party Rust bindings and a 1–3 week release cadence** | `crates.io/api/v1/crates/sherpa-onnx`; `https://github.com/k2-fsa/sherpa-onnx` | **quarterly** + on a >6-week release gap | 2026-09-30 | **High.** It is our *default* local ASR engine. A cadence break stalls a headline capability. |
| **V-11** | **`ort` has never released 2.0 stable (newest stable 1.16.3, 2023-11-12; newest is `2.0.0-rc.13`)** | `crates.io/api/v1/crates/ort` | **quarterly** | 2026-09-30 | **Medium.** Affects `parakeet-rs` (optional ASR engine). Not load-bearing — `sherpa-onnx` is the default. |
| **V-12** | **`playwright-rs` 0.19.0 is the live crate; the crate named `playwright` is a dead 2022 fork; there is still no official Playwright-for-Rust** | `crates.io/api/v1/crates/{playwright-rs,playwright}`; `https://github.com/microsoft/playwright/issues/18266` | **quarterly** + on reaching 1.0 | 2026-09-30 | **Medium.** Naming trap plus bus-factor 1. Affects the optional browser capability only. |
| **V-13** | **WebDriver BiDi is a W3C Working Draft, not a Recommendation; Safari has no implementation** | `https://www.w3.org/TR/webdriver-bidi/`; `https://wpt.fyi/results/webdriver/tests/bidi` | **event:** BiDi reaching Recommendation status; **quarterly** | 2026-09-30 | **Low** for us — we deliberately deferred BiDi. Would trigger ADR-0015 revisiting. |
| **V-14** | **Chrome 136+ ignores `--remote-debugging-port` against the default profile** | `https://developer.chrome.com/blog/remote-debugging-port`; the Chromium CDP README | **event:** any change to Chrome's remote-debugging restrictions | 2026-09-30 | **Medium.** Determines that the browser capability must own a dedicated profile. If relaxed, we could reconsider (but probably still would not). |
| **V-15** | **Professional-UI GUI grounding accuracy ≈ 61.6 % (ScreenSpot-Pro family); the original paper's headline was 18.9 %** | `https://arxiv.org/abs/2504.07981`; the UI-TARS and RegionFocus papers | **event:** a published model exceeding ~95 %; **quarterly** | 2026-09-30 | **Medium.** Justifies accessibility-tree-first grounding. Above ~95 % we would reconsider visual grounding as primary. |
| **V-16** | **Telegram API ToS §1.5 prohibits using Telegram-obtained data for AI development/deployment** | `https://core.telegram.org/api/terms` | **event:** any change to the API Terms | 2026-09-30 | **High (product).** Determines that the Telegram adapter is notification-output-only. **Requires legal review, not just a doc read** (Q-OPEN-01). |
| **V-17** | **Discord self-bots are categorically forbidden (⇒ termination) and soliciting a user token is prohibited** | `https://discord.com/guidelines` §14; the Platform Manipulation Policy; the Developer Policy | **event:** any policy change | 2026-09-30 | **High.** Hard constraint on the messaging capability. |
| **V-18** | **WhatsApp Cloud API forbids "personal, family, or household purposes"; the 3P Agent platform is beta and undocumented** | `https://www.whatsappbusiness.com/policy`; the WhatsApp Business ToS; the "Terms of Service for Use of Third Party Agents" | **event:** 3P Agents reaching GA **with public developer docs** | 2026-09-30 | **Medium.** Gates whether WhatsApp is ever implemented. |
| **V-19** | **Signal publishes no API; `signal-cli` self-declares a 3-month support window** | `https://signal.org/docs/`; `https://github.com/AsamK/signal-cli` | **quarterly** | 2026-09-30 | **Low.** We refuse Signal. Would only change if Signal shipped an official API. |
| **V-20** | **Piper is GPL-3.0; Coqui/XTTS is CPML (non-commercial + viral); `canary-1b` is CC-BY-NC-4.0; openWakeWord weights are CC-BY-NC-SA** | The respective `LICENSE` files, the HF model-card `license` field, and the crate/repository licence | **release:** re-audit before any model or voice component ships; **event:** any upstream licence change | 2026-09-30 | **Critical (legal).** A silent licence change would make a shipped binary non-compliant. Enforced by the model-licence registry (ADR-0019). |
| **V-21** | **`apalis-sqlite` sets `PRAGMA synchronous = OFF` and has no stable release** | `src/lib.rs` of the published crate; `crates.io/api/v1/crates/apalis-sqlite` | **event:** a stable 1.0 release, or a PR adding a durability knob | 2026-09-30 | **Medium.** Closes ADR-0007's contingency (Q-OPEN-02). A stable release alone does **not** reopen it — TP-7 must also pass. |
| **V-22** | **`croner` documents Vixie-compatible DST semantics; `jiff` provides correct DST arithmetic** | `https://docs.rs/croner/` (DST section); `crates.io/api/v1/crates/{croner,jiff}` | **quarterly** + on a major bump | 2026-09-30 | **High.** DST correctness is a correctness property (TP-8), and `croner` is the only Rust cron that documents it. |
| **V-23** | **The Rust task-scheduler ecosystem's viable options are `croner` and `cron` only** | `crates.io/api/v1/crates/{croner,cron,clokwerk,job_scheduler,tokio-cron-scheduler}` | **quarterly** | 2026-09-30 | **Medium.** If `croner` is abandoned we have no documented-DST alternative. |
| **V-24** | **PostgreSQL, Redis, Kafka and Kubernetes are absent from the personal install** | `rpm -q`; the deployment profile definition | **release:** assert the dependency manifest contains none | 2026-09-30 | **Medium.** This is the property that makes the product lightweight; drift is silent and cumulative. |
| **V-25** | **Core-only idle RSS < 60 MB; core-only binary < 40 MB; core-only cold start < 150 ms** | **No external source. Measured by our own benchmark harness.** | **milestone:** CI on every commit; re-baseline per release | *target, unmeasured* | **High.** These are the budgets that make the lightweight promise honest. A regression is invisible without measurement. |
| **V-26** | **`libxdo.pc` on Fedora declares `/usr/local` prefixes that are wrong** | `/usr/lib64/pkgconfig/libxdo.pc` | **event:** a Fedora packaging change | 2026-09-30 | **Low.** Cosmetic; we do not feed its cflags to a compiler. |

---

## 3. The three highest-risk claims

Not by severity of consequence alone, but by **(likelihood of silent drift) ×
(consequence if it drifts)**:

1. **V-06 (TypeScript / Svelte)** — a *claim that was already wrong once*. The
   register entry therefore mandates reading the tool's **source**, not its
   metadata. Peer ranges state what a package declares, not what is possible.
2. **V-20 (model licences)** — licences change silently, upstream is under no
   obligation to announce it, and the failure is *legal*, discovered after
   shipping.
3. **V-08 / V-25 (the resource budgets)** — these are the only claims in the
   entire architecture with **no external source at all**. They are our
   assertions, and they are the ones most likely to drift because nothing will
   tell us they are wrong. Hence: measured in CI, not asserted in prose.

---

## 4. Operating rules

1. **Every ADR that rests on an external fact cites its V-ID.** A decision
   without one is either a pure design preference (fine, say so) or an
   unverified claim (not fine).
2. **Reviewers check the register, not just the diff.** A PR touching a
   registered claim must update `last verified` or explain why not.
3. **`event` triggers are checked by a human, deliberately.** A bot that
   "re-verifies" by re-fetching proves liveness, not correctness. The judgement
   — "did this actually change anything we rely on?" — must stay human.
4. **CI asserts what is machine-checkable** and nothing else: the bundled SQLite
   version (V-02), the resource budgets (V-25), the absence of heavyweight
   dependencies (V-24), the licence policy (V-20, via `cargo deny`).
5. **A claim that turns out to have been wrong gets an amendment record**, in
   the style of ADR-0005's. Wrongness is worth recording; it is how the register
   improves.
6. **This register is itself reviewed quarterly.** A register that only grows is
   a liability, not an asset.
