# 01 — Architecture Research

Status: **Draft v0.1** · All version claims verified against primary registries on **2026-09-30**.
Source URLs and access dates: `docs/sources.md`.

This document records *what the ecosystem actually looks like today*, before any
opinion is formed. Where a widely-repeated claim turned out to be wrong or stale,
it is called out explicitly — those corrections matter more than the
confirmations.

---

## 1. Method and honesty notes

- **Rust crates:** verified via the `crates.io` JSON API, filtering out
  pre-releases. "Max stable" below means the newest non-`yanked`, non-prerelease
  version. MSRV is the crates.io `rust_version` field.
- **npm packages:** verified via the npm registry `/latest` endpoint.
- **Node / Go / MCP spec:** verified via `nodejs.org/dist/index.json`,
  `go.dev/dl`, and `modelcontextprotocol.io`.
- Where a subagent reported a version from a secondary source, it is marked
  `⚠ UNVERIFIED` and is **not** used to justify a decision.
- **GitHub REST API rate limit (60/hr, unauthenticated) was exhausted** during
  this research. Claims that needed it and could not be obtained are marked
  `⚠ UNVERIFIED` rather than asserted.

---

## 2. Corrections to widely-repeated claims

These are the highest-value findings in the document. Each one invalidates
advice that is still circulating.

### 2.1 MCP is no longer session-based — the spec changed in July 2026

**Claim usually made:** "MCP has an `initialize` handshake and a session, and
servers keep per-connection state."

**Reality (spec `2026-07-28`):** MCP is now **stateless**.

- `initialize` / `notifications/initialized` are **removed**. Every request
  carries protocol version and client capabilities in `_meta`.
- `Mcp-Session-Id` is **removed** from Streamable HTTP.
- New `server/discover` RPC lets clients select a version up front.
- Multi Round-Trip Requests (MRTR) replace server-initiated requests:
  `roots/list`, `sampling/createMessage`, `elicitation/create` are no longer
  server-initiated. A server returns `resultType: "input_required"` with
  `inputRequests`; the client answers by **retrying the original request** with
  `inputResponses`.
- **SSE stream resumability and message redelivery are removed** (`Last-Event-ID`
  dropped). A broken response stream loses the in-flight request; the client
  must re-issue it.
- `tools/list`, `resources/list`, `prompts/list` must now return `ttlMs` and
  `cacheScope` — cacheability is part of the protocol.
- Tool `inputSchema`/`outputSchema` loosened to full JSON Schema 2020-12.
- New deprecation policy: minimum **12-month** deprecation window plus a public
  registry.

**Why this matters to us:** the old "MCP server holds a session, so it can act
with ambient authority" model is gone. This is *good* for our security posture —
there is no longer a session object that could be confused for a grant. But it
also means we cannot lean on MCP for stateful workflow; that is precisely what
the **Tasks extension** (`io.modelcontextprotocol/tasks`) is for.

### 2.2 MCP **Sampling** is deprecated

Deprecated along with Roots and Logging under the new lifecycle policy. The
recommended migration is to *integrate directly with LLM provider APIs*.

**Why this matters to us:** it removes a pattern we never wanted — an MCP server
acting as an LLM proxy, i.e. an LLM-adjacent component with credential access.
We already call providers directly (ADR-0012). This is now also the spec's
recommendation, not just our preference.

### 2.3 TypeScript 7 explicitly excludes Svelte

`typescript@latest` is **7.0.2** (2026-07-08) — a 10× faster native Go port with
8–12× build speedups and ~15% lower build memory. It is genuinely impressive.

Microsoft's own 7.0 announcement states, verbatim:

> "workflows that use Vue, MDX, Astro, **Svelte**, and others will likely not yet
> be able to leverage TypeScript 7. … This is mainly because TypeScript 7 does
> not yet expose a stable programmatic API, and so tools (such as Volar) which
> embed TypeScript into their own compilers and language services can only
> currently rely on TypeScript 6.0."
>
> "**Projects using Vue, MDX, Astro, Svelte, and others will need to continue
> using TypeScript 6.0 for now.**"

Independently confirmed by the registry: `svelte-check` 4.7.6 declares
`peerDependencies: { typescript: "^5.0.0 || ^6.0.0" }`.

This is the clearest possible case for "current stable" ≠ "npm latest".
**Decision: TypeScript 6.0.3 (2026-04-16), not 7.0.2.** Revisit when Volar and
`svelte-check` widen their peer ranges.

### 2.4 `NVIDIA/NeMo` no longer exists

301-redirects to `NVIDIA-NeMo/Speech` (Apache-2.0, **v3.0.0**, 2026-08-07).
Architecture documents citing the old path are citing a dead URL.

Also, and more importantly: the *model* licenses are not uniform.
`nvidia/parakeet-tdt-0.6b-v3` and `canary-1b-flash` are **CC-BY-4.0** (commercially
usable). `nvidia/canary-1b` — the "flagship" many people mean by "Canary" — is
**CC-BY-NC-4.0, non-commercial**. And NVIDIA's *own* Open Model License is
custom, revocable, and was itself replaced on 2026-03-15. Do not assume
"NVIDIA model" ⇒ one license.

### 2.5 Picovoice Porcupine no longer has a free tier

Free Tier **discontinued 2026-06-30**; the `picovoice/picovoice` repo is archived
(last push 2025-04-11). No non-commercial tier is planned. Most "open wake word"
comparisons predate this and are now wrong.

Separately, `openWakeWord`'s *code* is Apache-2.0 but its **pretrained weights are
CC-BY-NC-SA 4.0 — non-commercial**. Not obvious from the README.

### 2.6 Piper changed licence; Coqui TTS is commercially unusable

- `rhasspy/piper` is **archived**; successor `OHF-Voice/piper1-gpl` is
  **GPL-3.0** (was MIT).
- Piper's **eSpeak-NG phonemizer is also GPL-3.0** — two copyleft surfaces.
- Many Piper voices finetuned from `lessac` carry the Blizzard "Materials"
  license restricting use to *research purposes only*.
- `coqui-ai/TTS` last pushed 2024-08-16; PyPI `TTS` 0.22.0 requires Python
  `<3.12`. XTTS-v2 is under the **Coqui Public Model License**: non-commercial,
  **including outputs**, with a **viral derivative clause**. Corporate
  dissolution did **not** put the weights in the public domain.
- `hexgrad/Kokoro-82M` is **Apache-2.0** (weights and card), 82M params, 8
  languages / 54 voices, ONNX exports 82–310 MB. This is the clean local TTS.

### 2.7 SQLite ≤ 3.51.2 has a documented corruption bug

From `sqlite.org/wal.html` (page updated 2026-08-25):

> "The bug is likely present in all version of SQLite from 3.7.0 (2010-07-21)
> through 3.51.2 (2026-01-09). It is fixed in version 3.51.3 (2026-03-13) and
> later. Backports … 3.44.6 and 3.50.7."

It is the WAL-reset bug, requiring two+ connections writing/checkpointing
concurrently. Telemetry suggests a rate comparable to SSD malfunctions — i.e.
rare but not zero, and *exactly* the workload a durable task queue creates.

**Action: the bundled SQLite must be ≥ 3.51.3.** Fedora 44 ships 3.51.2, so the
system library on the dev machine is *not* sufficient for this; we bundle.

### 2.8 `ort` (ONNX Runtime for Rust) has never released 2.0 stable

Latest is `2.0.0-rc.13` (2026-07-28). The newest **stable** is `1.16.3`, from
**2023-11-12**. Every modern ONNX-based Rust crate (e.g. `parakeet-rs`) depends
on the RC. Enormous adoption, works in practice — but a real supply-chain entry.

### 2.9 The Rust scheduler ecosystem has largely rotted

| Crate | Latest | Verdict |
|---|---|---|
| `clokwerk` | 0.4.0 (2022-11-23) | stale ~4 y, in-memory only |
| `job_scheduler` | 1.2.1 (2020-04-01) | **dead**, 6+ y |
| `lifeguard` | 0.6.1 (2020-11-21) | stale, needs Redis |
| `sailor` | 0.1.0 (2019-09-08) | dead, 4 downloads/90 d |
| `rusty-scheduler` | 0.1.1 (2021-11-17) | dead |
| `tokio-cron-scheduler` | 0.15.1 (2025-10-28) | ~11 mo stale, **Postgres/Nats only, no SQLite** |
| `effect-rs` | 0.1.0 | **name squat** — 32 lifetime downloads, repo 404s |
| `croner` | **4.0.0 (2026-08-31)** | healthy; only Rust cron with **documented Vixie-compatible DST semantics** |
| `cron` | 0.17.0 (2026-06-18) | healthy |
| `jiff` | **0.2.37 (2026-09-12)** | 73.5 M dl/30 d; correct DST arithmetic; `croner` backend |

"Effect for Rust" does not exist. Effect is TypeScript-only (`effect` 3.22.2).

### 2.10 "Rust has no Temporal" is no longer true

`temporalio-sdk` reached **1.0.0 on 2026-09-04** (Public Preview since
2026-05-07), first-party, MIT, backed by the same `temporalio-sdk-core` that
powers TS/Python/.NET. `restate-sdk` 0.12.1 is a first-party Rust SDK with a
**single self-contained server binary** and exactly-once invocation semantics.

We still reject both for the local case — but the reason is *deployment weight
and single-node over-engineering*, **not** ecosystem immaturity. That distinction
matters, because it means the cloud story is genuinely open.

### 2.11 A `wfaas` crate looks like a workflow engine and is not

`wfaas` 1.1.0 (2026-08-25), 1.7 M downloads, described as "Workflow-as-a-Service
engine" — but its `repository` field points at `smg-project/smg`, an **LLM
gateway**. Name/description and repository disagree. Do not evaluate.

---

## 3. Verified technology landscape (as of 2026-09-30)

### 3.1 Rust core

| Crate | Max stable | Released | MSRV | dl/30 d |
|---|---|---|---|---|
| `tokio` | 1.53.1 | 2026-07-20 | 1.71 | 238.3 M |
| `hyper` | 1.11.1 | 2026-08-28 | 1.63 | 215.1 M |
| `axum` | 0.8.9 | 2026-04-14 | 1.80 | 123.4 M |
| `tower` | 0.5.3 | 2026-01-12 | 1.64 | 181.9 M |
| `tower-http` | 0.7.1 | 2026-08-31 | 1.65 | 158.7 M |
| `sqlx` | 0.9.0 | 2026-05-21 | **1.94** | 40.7 M |
| `sqlx-sqlite` | 0.9.0 | 2026-05-21 | **1.94** | 37.6 M |
| `rusqlite` | 0.40.2 | 2026-08-08 | — | 37.4 M |
| `libsqlite3-sys` | 0.38.2 | 2026-08-08 | — | 71.8 M |
| `serde` | 1.0.229 | 2026-07-18 | 1.56 | 331.1 M |
| `serde_json` | 1.0.151 | 2026-07-20 | 1.71 | 332.7 M |
| `tracing` | 0.1.44 | 2025-12-18 | 1.65 | 202.7 M |
| `tracing-subscriber` | 0.3.23 | 2026-03-23 | 1.65 | 149.2 M |
| `opentelemetry` | 0.33.0 | 2026-09-18 | 1.75 | 63.4 M |
| `thiserror` | 2.0.21 | 2026-09-23 | 1.77 | 388.0 M |
| `reqwest` | 0.13.5 | 2026-09-08 | 1.85 | 196.9 M |
| `rustls` | 0.23.45 | 2026-09-14 | 1.71 | 213.6 M |
| `tokio-util` | 0.7.19 | 2026-07-21 | 1.71 | 177.0 M |
| `jiff` | 0.2.37 | 2026-09-12 | 1.70 | 73.6 M |
| `croner` | 4.0.0 | 2026-08-31 | — | 3.67 M |
| `keyring` | 4.2.0 | 2026-08-29 | 1.88 | 12.3 M |
| `zeroize` | 1.9.0 | 2026-06-12 | 1.85 | 187.1 M |
| `secrecy` | 0.10.3 | 2024-10-09 | 1.60 | 43.1 M |
| `moka` | 0.12.16 | 2026-08-09 | 1.71 | 38.3 M |
| `rmcp` | 3.5.0 | 2026-09-28 | 1.88 | 16.1 M |
| `tui` widget crates | — | — | — | 404 (naming) |

**Local toolchain:** rustc/cargo **1.98.1**, rustup 1.29.1, host
`x86_64-unknown-linux-gnu`, edition 2024 verified working. MSRV headroom is
1.98.1 − 1.94 (`sqlx`) = ~4 minor versions, which is comfortable but not infinite.

### 3.2 Desktop / TUI / CLI

| Crate | Max stable | Released | MSRV | Note |
|---|---|---|---|---|
| `tauri` | **2.12.0** | 2026-09-26 | 1.90 | Rust CLI/API at npm `2.12.0` — versions align |
| `tauri-build` | 2.7.0 | 2026-09-26 | 1.90 | |
| `tauri-plugin-notification` | 2.5.0 | 2026-09-26 | 1.90 | |
| `tauri-plugin-autostart` | 2.6.0 | 2026-09-26 | 1.90 | |
| `slint` | 1.18.1 | 2026-09-21 | 1.92 | credible non-webview alternative |
| `egui` / `eframe` | 0.36.2 | 2026-09-08 | **1.95** | very high MSRV |
| `iced` | 0.14.0 | 2025-12-07 | 1.88 | ~10 mo stale |
| `ratatui` | 0.30.2 | 2026-06-19 | 1.88 | |
| `clap` | 4.6.7 | 2026-09-14 | 1.85 | |
| `cpal` | 0.18.2 | 2026-08-16 | 1.85 | cross-platform audio I/O |
| `webrtc-vad` | 0.4.0 | **2019-10-01** | — | 7 years stale; evaluate alternatives |

### 3.3 Frontend

| Package | `latest` | Released | Engines | Verdict |
|---|---|---|---|---|
| `svelte` | 5.57.1 | — | `>=18` | usable |
| `svelte-check` | 4.7.6 | — | — | **TS peer `^5 \|\| ^6`** |
| `vite` | 8.3.1 | — | `^20.19 \|\| >=22.12` | usable |
| `@sveltejs/vite-plugin-svelte` | 7.3.1 | — | `^20.19 \|\| ^22.12 \|\| >=24` | |
| `typescript` | **7.0.2** | 2026-07-08 | — | ⛔ **not for Svelte** |
| `typescript` | **6.0.3** | 2026-04-16 | — | ✅ **chosen** |
| `rolldown` | 1.2.12 | — | — | Vite 8's bundler |
| `@modelcontextprotocol/sdk` | 1.31.0 | — | `>=18` | reference impl |
| `playwright` | 1.63.0 | 2026-09-04 | `>=20` | Apache-2.0 |

### 3.4 Runtime / language comparison points

| | Rust 1.98.1 | Go 1.27.1 | C++ |
|---|---|---|---|
| Memory safety | Compile-time guarantees | GC + escape analysis; unsafe in `unsafe`/`cgo` | UB is the default hazard model |
| Concurrency model | `Send`/`Sync` enforced; `tokio` | goroutines + channels; GC pauses | threads + UB risk |
| Binary | small, no runtime | static, no runtime | depends |
| Cold start | ~ms | ~ms | ~ms |
| Idle RSS | lowest of the three | moderate (GC + runtime) | lowest, but unsafe |
| Cross-compile | good, needs per-target C toolchain | excellent, near-trivial | painful |
| Ecosystem depth for this domain | `tokio` 238 M dl/30 d; `serde`, `tracing`, `axum` | strong but thinner for desktop/GUI | fragmented |
| Supply-chain posture | `cargo-deny` + `cargo audit` + crates.io MSRV metadata | `govulncheck`, module proxy | varies wildly |
| Desktop GUI story | Tauri/Slint/egui | weak | Qt/wxWidgets (heavy) |

### 3.5 Node and Go support status

- **Node LTS lines** (`nodejs.org/dist/index.json`): Iron 20.20.2, **Jod 22.23.3**,
  **Krypton 24.21.0 (2026-09-07)** ← current LTS.
- **Node 26.x: `lts=false`** on every release. Current line only.
- **Go:** 1.27.1 and 1.26.8 both `stable=true`.

This *confirms* the environment-preparation phase's premise: Node 24 (Krypton)
is the LTS target and Node 26 is not.

### 3.6 Storage extensions

| Option | Version | Note |
|---|---|---|
| `sqlite-vec` | 0.1.9 (2026-03-31) | 1.24 M dl/30 d. Pre-v1; **no release for 6 months** |
| SQLite FTS5 | bundled | mature, part of core |
| SQLite session extension | bundled | needed for CDC/sync later |

---

## 4. Ecosystem health signals that actually discriminate

Popularity is a weak signal. These are the ones that predicted trouble above:

1. **Time since last release**, relative to the project's own cadence.
2. **Whether the "official" binding is first-party or a community wrapper.**
   (`sherpa-onnx` ships Rust bindings in-tree — first-party. `whisper-rs` is a
   single-maintainer wrapper whose GitHub repo is **archived**, moved to
   Codeberg, last published 2026-03-12.)
3. **Whether the primary documentation is stale.** (faster-whisper's README
   benchmarks still cite `v1.1.0` while the crate is at 1.2.1 with no release in
   ~11 months.)
4. **Whether the crate's `repository` field matches its description.** (Caught
   `wfaas`.)
5. **Model *weight* licences**, not just code licences.
6. **Whether a project's own docs contradict its ecosystem's docs.** (Discord
   support page vs API docs on file-size limits; the API's
   `attachment_size_limit` is the only authoritative value.)

---

## 5. External capability reality (condensed)

Full per-platform detail, with auth methods, rate limits, message types, file
sizes and policy citations, is in the research corpus summarised in
`docs/sources.md` §Messaging. Condensed verdicts:

| Platform | Official read API | Official write API | User-account automation | Blunt verdict |
|---|---|---|---|---|
| **Telegram** | Bot API `getUpdates` / webhook (24 h buffer) | Yes, ~90 methods | MTProto, but **observed/ToS-risky** | Best-supported bot path; **ToS §1.5 AI clause is a legal gate**; cannot read your existing chats |
| **Discord** | Gateway WS (with resume) | Yes | **Categorically forbidden** (self-bot ⇒ termination) | Excellent bot surface; `MESSAGE_CONTENT` is a **privileged intent**; `IDENTIFY` 1000/24 h auto-resets the token |
| **Signal** | **None** | **None** | `signal-cli`, self-declared **3-month** support window | Do not build. No API exists. |
| **WhatsApp** | Webhooks only | Cloud API | Baileys = ToS-violating by design | Cloud API forbids **"personal, family, or household purposes"**; 24 h template window; 1 msg/6 s per user. 3P Agent platform is beta/undocumented. |
| **Matrix** | Full CS API | Yes | **Yes, officially** | The only platform where a real user account is a first-class, sanctioned use case |
| **Email** | IMAP | SMTP | Yes | Universal, but no push; needs polling or IDLE |
| **Webhooks** | n/a | n/a | n/a | Inbound-only, requires us to expose a listener |

**Design consequence:** the messaging capability interface must be a **narrow
common denominator plus per-provider extension points**, and the UI must be
able to say "this provider cannot do X" rather than pretending parity.

---

## 6. Browser automation reality (condensed)

| Approach | Standard | Maturity | Key gap |
|---|---|---|---|
| **Plain HTTP** (`reqwest`) | HTTP/1.1, 2, 3 | Decades | No JS execution, no interaction |
| **CDP** | Chromium project only | Production, daily rolls | Chromium-only; **Chrome 136+ blocks default-profile attach** |
| **WebDriver BiDi** | **W3C Working Draft, 2026-09-30** | Living WD, *not* a Recommendation | No request/response body access; no UA/timezone/locale emulation; no downloads body; **Safari: absent** |
| **Playwright** | library API | 1.63.0, Apache-2.0 | Rust support is community-only |

**BiDi implementation status** (measured by the subagent from wpt.fyi raw run
artifacts on 2026-09-30): Firefox 99.8%, Edge 99.0%, Chrome 97.6%, Safari **no
coverage at all**. Chrome implements BiDi as a **JavaScript mapper translating
BiDi→CDP** inside a hidden tab — so on Chrome, BiDi cannot exceed CDP.

Chromium's own docs, on the trust boundary:

> "Protocol clients are typically considered trusted, as they can navigate to
> arbitrary origins and have access to all origin data. … **These restrictions
> are not extended to other types of clients.**"

**Grounding reality:** best reported accuracy on professional-UI GUI grounding
(ScreenSpot-Pro family) is ≈**61.6%**; the original paper's headline for
existing models was **18.9%**. Roughly **1 in 3** grounding attempts fails. This
is categorically unacceptable for clicking "Submit" on a payment form.

**The converged answer** is demonstrated in production by `@playwright/mcp`
0.0.83: **accessibility-tree snapshots with stable element refs, not pixels**.
That is also the cheapest (a few hundred text tokens vs 1000–3000+ image tokens
per step).

**Bot defence is a strategic fact:** DataDome's detection models explicitly
enumerate "Puppeteer Extra Stealth" and "Headless Browser Forged Fingerprint" as
target classes, and their "Proof of Browser" makes spoofed engines fail. But
the IETF **Web Bot Auth** WG (charter approved; first WG document
`draft-ietf-webbotauth-httpsig-protocol` adopted 2026-09-01) and Cloudflare's
production implementation mean *cryptographic identity is now a legitimate
lane*. Do not build a stealth stack — it makes us indistinguishable from an
attacker, which is exactly what these defences are tuned to catch.

---

## 7. Voice reality (condensed)

| Concern | Finding |
|---|---|
| Best Rust-native ASR | `sherpa-onnx` **1.13.8** (2026-09-11), Apache-2.0, **first-party in-tree Rust bindings**, release every 1–3 weeks, covers streaming ASR + TTS (Kokoro/VITS/Piper) + VAD + diarization + `KeywordSpotter` |
| Most battle-tested | `whisper.cpp` 1.9.4 (54 k★) via `whisper-rs` 0.16.0 — but the **GitHub repo is archived**, moved to Codeberg, 758 k dl |
| Best accuracy/RAM | `nvidia/parakeet-tdt-0.6b-v3`, CC-BY-4.0, 6.34 % WER clean, 680 MB q8 GGUF, via `parakeet-rs` 0.3.8 (2026-09-23) — depends on `ort` **RC** |
| Smallest viable | Moonshine-tiny, **34 MB** q8, ~306 MB RAM, MIT, English-only |
| Streaming is real only for | `sherpa-onnx` `OnlineRecognizer`; whisper.cpp's "streaming" is **re-transcribing a rolling window** and its own README calls it "a naive example" |
| Wake word | Avoid third-party engines. `openWakeWord` weights are **non-commercial**; Porcupine has no free tier. Use always-on VAD + a keyword-spotter/turn-detector. |
| Clean local TTS | Kokoro-82M via `sherpa-onnx` (Apache-2.0 both sides). Piper is GPL-3.0 now; XTTS is non-commercial and viral. |
| Absolute floor | eSpeak-NG: **~15 MB RAM, ~0.001 RTF** — robotic, GPL-3.0, never fails |

---

## 8. Task/workflow engine reality (condensed)

| Option | Version | Deployment | Verdict for local |
|---|---|---|---|
| Hand-rolled task table on SQLite | — | **nothing** | ✅ **chosen** |
| `apalis` + `apalis-sqlite` | 0.7.4 / 1.0.0-rc.9 | library + `.db` | ⚠️ strong candidate; **RC only for the SQLite backend, single maintainer, and `synchronous` mode unverified** |
| `fang` | 0.11.0 | library + SQLite | ⚠️ 2 maintainers; cron is **UTC-only** |
| Temporal (Rust SDK 1.0.0) | 1.0.0 (2026-09-04) | **server + DB** | ⛔ local; ✅ cloud |
| Restate | 0.12.1 | **single binary** | ⛔ local; ✅ cloud |
| DBOS (Rust) | 0.5.0 | **Postgres only**, 1 173 dl, "under construction" | ⛔ |
| `apalis-workflow` | 0.1.0-rc.10 | — | ⛔ beta, in-memory examples |
| Windmill | — | Postgres + Docker + workers, **AGPL** | ⛔ |
| Inngest | — | no Rust SDK (abandoned port) | ⛔ |
| Hatchet | 0.2.8 | Go engine + Postgres | ⛔ |
| LangGraph / LangChain | 1.2.12 | Python | ⛔ see below |

**The most important finding in this document is not a version — it is a
convergence.** Anthropic, OpenAI, *and* LangChain's own authors all reached the
same conclusion from three directions:

- Anthropic: "the most successful implementations **weren't using complex
  frameworks**"; frameworks "create extra layers of abstraction that can obscure
  the underlying prompts and responses."
- OpenAI: "**maximize a single agent's capabilities first** … often a single agent
  with tools is sufficient."
- LangChain's own team: "we … decided that was **little to no abstraction at
  all**. Instead, we focused on control and durability."

And the shape they converged on — *Session / Harness / Sandbox* — is exactly a
durable task table plus a thin model loop plus a disposable execution sandbox.

⚠️ A public benchmark claiming LangGraph +28.2 % / LangChain +17.2 % latency
overhead exists but is **low credibility** (2 commits, single author,
self-published, no replication). It is **not** cited as evidence here. The
argument for hand-rolling rests on the primary sources above, not on a number.

---

## 9. What the research changed about the brief's hypotheses

| Hypothesis | Verdict | Change |
|---|---|---|
| Rust core | ✅ upheld | MSRV 1.98.1 clears every candidate except `egui` (1.95), which is uncomfortably close |
| Tokio | ✅ upheld | Compensate for its known gaps (no structured concurrency, no built-in supervision) with our own supervisor |
| Axum + Tower | ⚠️ **demoted** | Not the local transport. HTTP is a *cloud* concern; local IPC is not HTTP. See ADR-0003. |
| SQLx | ⚠️ **re-evaluated** | MSRV 1.94 vs `rusqlite`'s flexibility; and SQLite *is* single-writer, so async buys little. See ADR-0006. |
| SQLite | ✅ upheld, with a **mandate** | Must bundle ≥ 3.51.3 (§2.7) and use `synchronous=FULL` + WAL for power-loss durability |
| Serde | ✅ upheld | |
| tracing | ✅ upheld | |
| OpenTelemetry | ⚠️ **demoted to optional** | Must not require a collector in a personal install. Native exporter only. |
| Tauri | ✅ upheld, with a **cost admission** | WebKitGTK's web process is ~80–150 MB RSS on Linux. Not "lightweight", but cheaper than reimplementing the UI. |
| Svelte | ✅ upheld | |
| TypeScript | ⚠️ **demoted 7 → 6** | §2.3. First-party Microsoft statement. |
| Vite | ✅ upheld | |
| Ratatui | ✅ upheld | |
| Clap | ✅ upheld | |
| MCP | ⚠️ **re-scoped** | External integration protocol only, **not** the internal capability protocol. Spec changed under us (§2.1). |
| Playwright | ⚠️ **demoted to a capability, not a core dependency** | Ships Node ~130 MB + Chromium ~400 MB. Must be opt-in. HTTP-first is the default. |
| Vector DB | ❌ **rejected** | sqlite-vec 0.1.9, 6 months without a release. Embeddings are derived data and belong in SQLite. See ADR-0013. |

---

## 10. Research gaps (carried to `10-open-questions.md`)

| Item | Status |
|---|---|
| `apalis-sqlite`'s `PRAGMA synchronous` default | ⚠ unverified — blocks adoption for a power-loss guarantee |
| `apalis-sqlite` WAL default | ⚠ unverified |
| SQLite write-throughput ceiling on our hardware | **No authoritative number exists.** Must be measured, not cited. |
| Independent 2026 benchmark of agent-framework overhead | does not exist |
| Azure Speech pricing | ⚠ unverified (JS-rendered page) |
| WhatsApp 3P Agent platform developer docs | not found; terms exist, API docs do not |
| Tauri 2 measured idle RAM on Fedora 44 | not measured — must be measured in Phase 1 |
| Rust `tui` ecosystem crate names | 404 on the guessed name; to be resolved at implementation time |
