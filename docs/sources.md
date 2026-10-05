# Sources

Status: **Draft v0.2** · All URLs accessed **2026-09-30** unless otherwise noted.

**One correction, 2026-10-05.** §1 is titled "Rust — core dependencies" and reads as the
dependency manifest. It is not: it lists **evaluated candidates**, several of which are not
dependencies and will not be (`opentelemetry`, `reqwest`, `tokio-util`/`futures`,
`moka`/`dashmap`/`parking_lot`, `cpal`, `notify`/`notify-rust`, `sqlite-vec`). The
authoritative dependency list is the workspace `Cargo.toml`.

**Added since the research date, with no source rows here:** the TLS stack ADR-0040 approved
— `tokio-rustls`, `rustls-native-certs`, `ring`, `rustls-webpki` (ISC and BSD-3-Clause
added to `deny.toml`; `webpki-roots` rejected as MPL-2.0) — and `rcgen`, used only to
generate per-test certificates in `tests/https_provider.rs`. The Groq endpoint and model in
V-75 are recorded in the register rather than here, and **Groq's pricing page remains
unverified**.

## Verification method and its limits

- **Rust crates** — the `crates.io` JSON API
  (`https://crates.io/api/v1/crates/{name}` and `/versions`), filtering out
  pre-releases and yanked versions. "Max stable" = newest non-prerelease,
  non-yanked. MSRV from the `rust_version` field. Queried with a read-only
  script; no crates downloaded.
- **npm packages** — `https://registry.npmjs.org/{package}/latest`.
- **Node** — `https://nodejs.org/dist/index.json` (the `lts` field).
- **Go** — `https://go.dev/dl/?mode=json`.
- **MCP** — `https://modelcontextprotocol.io/specification/latest` and
  `.../2026-07-28/changelog`, fetched directly.
- **TypeScript** — the npm registry plus
  `https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/`,
  fetched directly.
- **GitHub** — the REST API where available. **⚠ The unauthenticated rate limit
  (60 req/hr) was exhausted during this research.** Claims that required it and
  could not be obtained are marked `⚠ UNVERIFIED` in the documents and are **not**
  used to justify any decision.
- **Local machine** — direct inspection of the development workstation
  (Fedora 44, x86_64, kernel 7.2.7-200.fc44). No writes, no installs, no
  services started.

**Correction logged 2026-09-30 (post-review).** Revision 1 of ADR-0005 concluded
that "Svelte projects must stay on TypeScript 6" and cited `svelte-check`'s peer
range as proof. That inference was **wrong**, and it is recorded here because the
error class is generalisable: **a peer-dependency range states what a package
*declares*, not what is *possible*.** Inspecting the published `svelte-check`
4.7.6 tarball showed a documented, supported TypeScript 7 path
(`--tsgo` / `--tsgo-experimental-api`, requiring TS7 + TS6 co-installed) and a
matching path in `svelte-language-server` 0.18.4. See ADR-0005's amendment
record. **Lesson: before promoting a tooling limitation to an architectural
decision, read the tool's own source and docs for a supported path.**

**Standing caveat:** version numbers are a snapshot. Anything used for a
dependency pin must be re-verified at implementation time. This is why
`Cargo.lock` is committed and `--locked` is used in CI (ADR-0019).

---

## 1. Rust — core dependencies

| Crate | Source |
|---|---|
| `tokio` 1.53.1 | https://crates.io/api/v1/crates/tokio |
| `hyper` 1.11.1 | https://crates.io/api/v1/crates/hyper |
| `axum` 0.8.9 | https://crates.io/api/v1/crates/axum |
| `tower` 0.5.3 · `tower-http` 0.7.1 | https://crates.io/api/v1/crates/{tower,tower-http} |
| `sqlx` / `sqlx-sqlite` 0.9.0 | https://crates.io/api/v1/crates/sqlx |
| `rusqlite` 0.40.2 · `libsqlite3-sys` 0.38.2 | https://crates.io/api/v1/crates/rusqlite |
| `serde` 1.0.229 · `serde_json` 1.0.151 | https://crates.io/api/v1/crates/serde |
| `tracing` 0.1.44 · `tracing-subscriber` 0.3.23 | https://crates.io/api/v1/crates/tracing |
| `opentelemetry` / `-sdk` 0.33.0 | https://crates.io/api/v1/crates/opentelemetry |
| `thiserror` 2.0.21 · `anyhow` 1.0.104 | https://crates.io/api/v1/crates/thiserror |
| `reqwest` 0.13.5 · `rustls` 0.23.45 | https://crates.io/api/v1/crates/reqwest |
| `tokio-util` 0.7.19 · `futures` 0.3.34 | https://crates.io/api/v1/crates/tokio-util |
| `jiff` 0.2.37 · `time` 0.3.55 | https://crates.io/api/v1/crates/jiff |
| `keyring` 4.2.0 | https://crates.io/api/v1/crates/keyring |
| `zeroize` 1.9.0 · `secrecy` 0.10.3 | https://crates.io/api/v1/crates/zeroize |
| `moka` 0.12.16 · `dashmap` 6.2.1 · `parking_lot` 0.12.5 | https://crates.io/api/v1/crates/moka |
| `uuid` 1.26.1 | https://crates.io/api/v1/crates/uuid |
| `directories` 6.0.0 · `fs4` 1.1.0 | https://crates.io/api/v1/crates/directories |
| `cpal` 0.18.2 | https://crates.io/api/v1/crates/cpal |
| `blake3` 1.8.7 · `argon2` 0.6.0 | https://crates.io/api/v1/crates/blake3 |
| `notify` 8.2.0 · `notify-rust` 4.18.1 | https://crates.io/api/v1/crates/notify |
| `webrtc-vad` 0.4.0 (**2019-10-01 — 7 years stale**) | https://crates.io/api/v1/crates/webrtc-vad |
| `sqlite-vec` 0.1.9 (2026-03-31) | https://crates.io/api/v1/crates/sqlite-vec |

## 2. Rust — desktop, TUI, CLI, voice

| Crate | Source |
|---|---|
| `tauri` 2.12.0 · `tauri-build` 2.7.0 | https://crates.io/api/v1/crates/tauri |
| `tauri-plugin-notification` 2.5.0 · `-autostart` 2.6.0 · `-shell` 2.4.0 | https://crates.io/api/v1/crates/tauri-plugin-notification |
| `slint` 1.18.1 (MSRV 1.92) | https://crates.io/api/v1/crates/slint |
| `egui` 0.36.2 (**MSRV 1.95**) · `iced` 0.14.0 (2025-12-07) | https://crates.io/api/v1/crates/egui |
| `ratatui` 0.30.2 · `clap` 4.6.7 | https://crates.io/api/v1/crates/ratatui |
| `sherpa-onnx` 1.13.8 (2026-09-11) | https://crates.io/api/v1/crates/sherpa-onnx |
| `parakeet-rs` 0.3.8 (2026-09-23) | https://crates.io/api/v1/crates/parakeet-rs |
| `whisper-rs` 0.16.0 (2026-03-12) | https://crates.io/api/v1/crates/whisper-rs |
| `ort` (**2.0.0-rc.13; newest *stable* 1.16.3, 2023-11-12**) | https://crates.io/api/v1/crates/ort |
| `ct2rs` 0.10.1 | https://crates.io/api/v1/crates/ct2rs |
| `playwright-rs` 0.19.0 (2026-09-26) | https://crates.io/api/v1/crates/playwright-rs |
| `playwright` 0.0.20 (**2022 — dead fork**) | https://crates.io/api/v1/crates/playwright |
| `espeak-ng` 0.2.0 (pure-Rust port) | https://crates.io/api/v1/crates/espeak-ng |

## 3. Rust — scheduling and orchestration

| Crate | Source |
|---|---|
| `croner` 4.0.0 (2026-08-31) | https://crates.io/api/v1/crates/croner |
| `cron` 0.17.0 · `cron-parser` 0.12.0 | https://crates.io/api/v1/crates/cron |
| `apalis` 0.7.4 stable / **1.0.0-rc.10 newest** · `apalis-sqlite` **1.0.0-rc.9 (2026-09-16), no stable ever released** (all 14 versions are pre-releases) | https://crates.io/api/v1/crates/apalis |
| **`apalis-sqlite` source read directly** — `src/lib.rs:149–166` `SqliteStorage::setup()` sets `PRAGMA synchronous = OFF` (line 156) with no config knob; applied via `.execute(pool)` rather than `after_connect`, so a per-connection pragma lands on one connection. `queries/task/ack.sql` fences on `lock_by` identity but **not** on lease expiry. **Verdict: TP-7 fails, TP-5 partial → rejected (ADR-0032, Q-OPEN-02)** | tarball `https://static.crates.io/crates/apalis-sqlite/apalis-sqlite-1.0.0-rc.9.crate`, read 2026-09-30 |
| `apalis-workflow` 0.1.0-rc.10 | https://crates.io/api/v1/crates/apalis-workflow |
| `fang` 0.11.0 (2026-07-02) | https://crates.io/api/v1/crates/fang |
| `temporalio-sdk` **1.0.0 (2026-09-04)** | https://crates.io/api/v1/crates/temporalio-sdk |
| `restate-sdk` 0.12.1 (2026-09-22) | https://crates.io/api/v1/crates/restate-sdk |
| `dbos` 0.5.0 (1 173 lifetime downloads) | https://crates.io/api/v1/crates/dbos |
| `hatchet-sdk` 0.2.8 · `inngest` 0.1.1 (2024-11-01, abandoned) | https://crates.io/api/v1/crates/hatchet-sdk |
| `tokio-cron-scheduler` 0.15.1 (**2025-10-28**) | https://crates.io/api/v1/crates/tokio-cron-scheduler |
| **Dead:** `clokwerk` 0.4.0 (2022-11-23) · `job_scheduler` 1.2.1 (2020-04-01) · `lifeguard` 0.6.1 (2020-11-21) · `sailor` 0.1.0 (2019-09-08) · `rusty-scheduler` 0.1.1 (2021-11-17) | https://crates.io/api/v1/crates/ |
| **`effect-rs` 0.1.0 — name squat, 32 lifetime downloads, repo 404s** | https://crates.io/api/v1/crates/effect-rs |
| ⚠ `wfaas` 1.1.0 — **description says "Workflow-as-a-Service engine" but `repository` points at an LLM gateway. Do not evaluate.** | https://crates.io/api/v1/crates/wfaas |

## 4. MCP

| Item | Source | Date |
|---|---|---|
| **Current spec revision: `2026-07-28`** | https://modelcontextprotocol.io/specification/latest | fetched 2026-09-30 |
| Full changelog since `2025-11-25` (statelessness, MRTR, Tasks extension, deprecations) | https://modelcontextprotocol.io/specification/2026-07-28/changelog | fetched 2026-09-30 |
| Schema | https://github.com/modelcontextprotocol/specification/blob/main/schema/2026-07-28/schema.ts | — |
| SEP-2567 (remove sessions) · SEP-2575 (stateless) · SEP-2663 (tasks extension) · SEP-2322 (MRTR) · SEP-2106 (JSON Schema 2020-12) · SEP-2352 (issuer-bound credentials) · SEP-2596 (feature lifecycle) | https://github.com/modelcontextprotocol/modelcontextprotocol/pull/ | — |
| Rust SDK `rmcp` 3.5.0 (2026-09-28) | https://crates.io/api/v1/crates/rmcp | — |
| Reference TS SDK `@modelcontextprotocol/sdk` 1.31.0 | https://registry.npmjs.org/@modelcontextprotocol%2Fsdk/latest | — |
| Security principles ("tools represent arbitrary code execution… annotations should be considered untrusted") | https://modelcontextprotocol.io/specification/latest | fetched 2026-09-30 |

## 5. Frontend

| Package | `latest` | Source |
|---|---|---|
| `svelte` 5.57.1 | 5.57.1 | https://registry.npmjs.org/svelte/latest |
| `svelte-check` 4.7.6 — **peers `typescript ^5 \|\| ^6`** | 4.7.6 | https://registry.npmjs.org/svelte-check/latest |
| `vite` 8.3.1 (`engines: ^20.19.0 \|\| >=22.12.0`) | 8.3.1 | https://registry.npmjs.org/vite/latest |
| `@sveltejs/vite-plugin-svelte` 7.3.1 | 7.3.1 | https://registry.npmjs.org/@sveltejs%2Fvite-plugin-svelte/latest |
| `typescript` **`latest` = 7.0.2 (2026-07-08)** — excluded for Svelte | — | https://registry.npmjs.org/typescript |
| `typescript` **6.0.3 (2026-04-16)** — co-installed as the `typescript` package | — | https://registry.npmjs.org/typescript |
| **`svelte-check` 4.7.6 — TypeScript 7 support exists**: README *"TypeScript 7 support currently requires the `--tsgo` or `--tsgo-experimental-api` flag. You need to install both TypeScript 7 and TypeScript 6."*; and `bin/ts-version-check.js` (the code that actually runs) *"TypeScript 7 support currently requires both TypeScript 7 and TypeScript 6 installed in your project … `npm install --save-dev typescript@~6 @typescript/native@npm:typescript@7`"* | — | https://registry.npmjs.org/svelte-check/latest (tarball inspected 2026-09-30) |
| `svelte-language-server` **0.18.4** — also carries `tsgo` / `tsgo-experimental-api` (editor-side TS7 support) | — | https://registry.npmjs.org/svelte-language-server/latest (tarball inspected 2026-09-30) |
| `rolldown` 1.2.12 | 1.2.12 | https://registry.npmjs.org/rolldown/latest |
| **TypeScript 7.0 announcement** — "Projects using … **Svelte** … will need to continue using TypeScript 6.0 for now"; 7.0 ships no programmatic API until 7.1 | — | https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/ (2026-07-08, fetched 2026-09-30) |
| `playwright` 1.63.0 (2026-09-04, Apache-2.0, Node ≥ 20) | — | https://registry.npmjs.org/playwright/latest |
| **Tauri 2.12** announcement (verified HTTP 200) | — | https://tauri.app/blog/tauri-2.12/ |
| **MCP blog: the 2026-07-28 specification** (verified HTTP 200) — authoritative prose companion to the changelog | — | https://blog.modelcontextprotocol.io/posts/2026-07-28/ |
| `@playwright/mcp` 0.0.83 (2026-09-28) — snapshot/accessibility-tree-based | — | https://playwright.dev/mcp/introduction |

## 6. Runtime and language support status

| Item | Source |
|---|---|
| **Node LTS lines:** Iron 20.20.2 · **Jod 22.23.3** · **Krypton 24.21.0 (2026-09-07)** ← current LTS | https://nodejs.org/dist/index.json |
| **Node 26.x: `lts=false` on every release** — Current line only | https://nodejs.org/dist/index.json |
| Go **1.27.1** and **1.26.8** both `stable=true` | https://go.dev/dl/?mode=json |
| Rust **1.98.1** (48a229cea 2026-09-01), rustup 1.29.1 — verified locally | `rustc --version`, `rustup --version` |

## 7. SQLite

| Topic | Source | Date |
|---|---|---|
| WAL: single-writer ("there can only be one writer at a time"); `synchronous` semantics | https://sqlite.org/wal.html | page updated 2026-08-25 |
| **WAL-reset corruption bug: present 3.7.0 → 3.51.2, fixed in 3.51.3 (2026-03-13); backports 3.50.7, 3.44.6** | https://sqlite.org/wal.html | 2026-08-25 |
| **SQLite 3.51.3 release log** (verified, fetched 2026-09-30) — *"Changes in this specific patch release, version 3.51.3 (2026-03-13): Fix the WAL-reset database corruption bug."* Also in 3.51.0: *"Improved resistance to database corruption caused by an application breaking Posix advisory locks using close()"* — a second fix in the same area | https://www3.sqlite.org/releaselog/3_51_3.html | 2026-03-13 |
| Single-writer isolation | https://sqlite.org/isolation.html | — |
| `BEGIN IMMEDIATE` — "no subsequent operations in that transaction will ever fail with a SQLITE_BUSY error" | https://sqlite.org/lang_transaction.html | — |
| `BEGIN CONCURRENT` (Chromium hctree) — still serialises COMMIT | https://sqlite.org/hctree/doc/begin-concurrent/doc/begin_concurrent.md | — |
| Installed on the dev machine: **3.51.2** (Fedora `sqlite-3.51.2-2.fc44`) — **below the 3.51.3 fix** → must bundle | `rpm -q sqlite` | 2026-09-30 |

⚠ **There is no authoritative benchmark for SQLite write throughput.** The only
figure found (22.6k → 6.0k inserts/s at 1→16 writers) is from a single
un-auditable blog post and is **not** cited. This must be measured on our own
hardware (Q-OPEN-17).

## 8. Agent orchestration — primary sources

| Source | URL |
|---|---|
| Anthropic, *Building effective agents* (2024-12-19) — "weren't using complex frameworks"; "start by using LLM APIs directly" | https://www.anthropic.com/engineering/building-effective-agents |
| **Anthropic, *Scaling Managed Agents: Decoupling the brain from the hands* (2026-04-08)** — Session/Harness/Sandbox; "Harnesses encode assumptions that go stale as models improve"; the credentials-in-sandbox post-mortem | https://www.anthropic.com/engineering/managed-agents |
| Anthropic, *Effective harnesses for long-running agents* (2025-11-26) | https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents |
| OpenAI, *A practical guide to building agents* — "maximize a single agent's capabilities first" | https://openai.com/business/guides-and-resources/a-practical-guide-to-building-ai-agents |
| OpenAI, orchestration & handoffs | https://developers.openai.com/api/docs/guides/agents/orchestration |
| OpenAI, Structured Outputs — `json_schema.strict`; the `refusal` field | https://developers.openai.com/api/docs/guides/structured-outputs |
| **LangChain, *Building LangGraph* (Sept 2025) — "little to no abstraction at all… control and durability"** | https://www.langchain.com/blog/building-langgraph |
| Temporal Rust SDK **1.0.0 (2026-09-04)** · Public Preview 2026-05-07 | https://temporal.io/changelog/rust-sdk-public-preview |
| Restate Rust SDK 0.12.1 · architecture · durability modes | https://docs.restate.dev/references/architecture |
| DBOS (Rust) — "under construction… the scheduler is not yet"; Postgres-only | https://docs.dbos.dev/architecture |
| AWS transactional outbox | https://microservices.io/patterns/data/transactional-outbox |
| Stripe idempotent requests | https://docs.stripe.com/api/idempotent_requests |
| AWS SQS dead-letter queues · capturing problematic messages | https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html |
| **Anthropic schema strictness** (Vercel AI had to add `sanitizeJsonSchema`) | https://github.com/vercel/ai/issues/14342 |
| Anthropic grammar-size ceiling (`"The compiled grammar is too large"`) | https://github.com/anthropics/anthropic-sdk-python/issues/1185 |

⚠ **Framework-overhead benchmark explicitly NOT relied upon:**
https://github.com/liam-langchain/langgraph-vs-openai-benchmark — 2 commits, single
author, self-published, no replication. Cited only as an example of weak
evidence, never as a decision input.

## 9. Security

| Topic | Source |
|---|---|
| **OWASP AI Agent Security Cheat Sheet** — separate decision from execution; bind approval to normalised parameters; fail closed; unknown tools default HIGH | https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html |
| **"Loopjacking: Hijacking Human-in-the-Loop Approval"** (2026-09) — approval bound to operation A, implementation executes B | https://arxiv.org/abs/2609.21081 |
| EU AI Act Art. 12 (record-keeping), Art. 14 (human oversight) | Regulation (EU) 2024/1689 |
| NIST AI RMF — MAP 3.5, GOVERN 3.2, MANAGE 2.4 | https://airc.nist.gov/AI_RMF_Knowledge_Base/AI_RMF |
| **Chrome 136+ ignores `--remote-debugging-port` on the default profile** (motivated by cookie theft) | https://developer.chrome.com/blog/remote-debugging-port |
| Chromium: "Protocol clients are typically considered trusted… restrictions are not extended to other types of clients" | https://chromium.googlesource.com/chromium/src/+/HEAD/third_party/blink/public/devtools_protocol/README.md |
| Chromium: BiDi will **not** replace CDP | https://developer.chrome.com/blog/webdriver-bidi |
| **IETF Web Bot Auth WG** — charter approved; first WG document `draft-ietf-webbotauth-httpsig-protocol` adopted 2026-09-01 | https://datatracker.ietf.org/wg/webbotauth/about/ |
| Cloudflare Web Bot Auth production implementation (Ed25519 → JWK directory → HTTP Message Signatures) | https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/ |
| DataDome AI/bot detection — names Playwright/Puppeteer stealth as target classes; "Proof of Browser" | https://docs.datadome.co/docs/ai-detection |

## 10. Messaging platforms

Full per-platform detail (auth methods, rate limits, message types, file-size
limits, policy citations, client-library maintenance) is in the research corpus;
the load-bearing sources are below.

| Platform | Key sources |
|---|---|
| **Telegram** | Bot API terms: https://core.telegram.org/api/terms (**§1.4, §1.5**) · Bot FAQ + rate limits: https://core.telegram.org/bots/faq · obtaining `api_id`: https://core.telegram.org/api/obtaining_api_id (**"all accounts that log in using unofficial Telegram API clients are automatically put under observation"**) · Webhooks: https://core.telegram.org/bots/webhooks (HTTPS, ports 443/80/88/8443, `secret_token`, 24 h buffer) · MTProto: https://core.telegram.org/api · SRP: https://core.telegram.org/api/srp |
| **Discord** | Guidelines §14 (**self-bots forbidden → termination**): https://discord.com/guidelines · Platform Manipulation Policy: https://discord.com/safety/platform-manipulation-policy-explainer · Self-bots support article: https://support.discord.com/.../Automated-User-Accounts-Self-Bots · Developer Policy (**may not solicit user login credentials**): https://discord.com/developers/policies/agreement · Rate limits (50 req/s global, Gateway 120 events/60 s, **IDENTIFY 1000/24 h → automatic token reset**, Cloudflare 10 000/10 min): https://discord.com/developers/docs/topics/rate-limits · **MESSAGE_CONTENT privileged intent** + the 10 000-user review threshold: https://discord.com/developers/docs/topics/gateway#privileged-intents |
| **Signal** | **No API** — https://signal.org/docs/ (protocol specs only) · libsignal "**Use outside of Signal is unsupported**": https://github.com/signalapp/libsignal (AGPL-3.0) · signal-cli "**unofficial**" and the **3-month expiry**: https://github.com/AsamK/signal-cli · Attachment limit 100→200 MB (2026-07-31): https://aboutsignal.com/news/signal-increases-attachment-size-limit-from-100-mb-to-200-mb/ |
| **WhatsApp** | Business Platform policy (**24 h window, approved templates, mandatory human escalation**): https://www.whatsappbusiness.com/policy · On-Premises API **expired 2025-10-23**: https://developers.facebook.com/docs/whatsapp/overview · ToS restrictions (**"must not use for personal, family, or household purposes"**; no reverse engineering; no multi-device network sharing) · **"Terms of Service for Use of Third Party Agents"** (2026-08-25) — 3P Agents: ≤5, 1:1 only, **not E2E-encrypted**, revocable at Meta's discretion, **still limited beta** ⚠ **no developer API documentation found** · Supported media types & limits: https://developers.facebook.com/docs/whatsapp/cloud-api/reference/media |
| **Matrix** | Client-Server API spec: https://spec.matrix.org/latest/client-server-api/ · Sliding Sync: https://spec.matrix.org/latest/sliding-sync/ · Rust SDK: https://crates.io/crates/matrix-sdk |
| **Email** | IMAP4rev2 (RFC 9051) · IDLE extension (RFC 2177) · SMTP (RFC 5321) |
| **Webhooks** | Standard HTTPS callbacks; idempotency and signature verification are the implementer's responsibility |

## 11. Browser automation

| Topic | Source |
|---|---|
| **WebDriver BiDi — W3C Working Draft, 2026-09-30** (not a Recommendation) | https://www.w3.org/TR/webdriver-bidi/ · versioned: https://www.w3.org/TR/2026/WD-webdriver-bidi-20260930/ · editor's draft: https://w3c.github.io/webdriver-bidi/ · history: https://www.w3.org/standards/history/webdriver-bidi/ |
| Implementation status (Firefox 99.8 %, Edge 99.0 %, Chrome 97.6 %, **Safari no coverage**) — aggregated by the subagent from wpt.fyi raw run artifacts | https://wpt.fyi/results/webdriver/tests/bidi |
| Chrome implements BiDi as a **JavaScript mapper BiDi→CDP in a hidden tab** | https://github.com/GoogleChromeLabs/chromium-bidi · https://developer.chrome.com/docs/chromedriver/downloads |
| CDP is not deprecated; stability guarantees; **daily protocol roll** (`devtools-protocol` 0.0.1707781, 2026-09-30) | https://chromedevtools.github.io/devtools-protocol/ · https://github.com/ChromeDevTools/devtools-protocol/blob/master/changelog.md |
| **Playwright is NOT shifting to BiDi** — no mention in release notes; `microsoft/playwright#37277` (protocol config) and **#32577** (blockers: no body access, no UA/tz/locale, no downloads) both open | https://github.com/microsoft/playwright/issues/32577 |
| **No official Playwright for Rust** — `microsoft/playwright#18266` closed by a maintainer: "This is unfortunately out of scope" | https://github.com/microsoft/playwright/issues/18266 |
| `playwright-rs` 0.19.0 — bundles Playwright 1.63.0, Apache-2.0, MSRV 1.88, 6 open issues, single dominant maintainer | https://crates.io/crates/playwright-rs · https://github.com/padamson/playwright-rust |
| The crate named `playwright` on crates.io is a **dead 2022 fork** (0.0.20, 2022-08-20) | https://crates.io/crates/playwright |
| Playwright auth / `storageState` / `launchPersistentContext` guidance | https://playwright.dev/docs/auth |
| **Accessibility-tree grounding as the agent pattern** — "far cheaper than DOM dumps or screenshots"; "no vision models required" | https://playwright.dev/mcp/introduction |
| WAI-ARIA 1.2 (Recommendation, 2023-06-06) · Accname 1.2 (WD 2026-09-23) · Core AAM 1.2 (CRD 2026-08-29) | https://www.w3.org/TR/wai-aria-1.2/ · https://www.w3.org/TR/accname-1.2/ |
| **GUI grounding accuracy** — ScreenSpot-Pro (professional UIs): "the best model achieving only **18.9%**" | https://arxiv.org/abs/2504.07981 |
| Best current reported ≈ **61.6 %** (UI-TARS-1.5 / RegionFocus + Qwen2.5-VL-72B) | https://github.com/xdcszlx/UI-TARS-paper · https://arxiv.org/html/2505.00684v1 |
| End-to-end GUI agent success still ≈ **47.5 %** on OSWorld | UI-TARS paper (above) |
| Set-of-Mark prompting; OmniParser (Microsoft, CC-BY-4.0) | https://arxiv.org/html/2310.11441v2 · https://github.com/microsoft/OmniParser |
| HTTP-first rationale (browser as escalation on evidence, not default) | https://scantir.com/blog/direct-http-first (2026-06-28) — practitioner, corroborating only |

⚠ The frequently-cited "HTTP scraper 4× faster / 8× less RAM" numbers come from a
single vendor-adjacent blog (n=6 sites). They are **not** used as decision
evidence; the structural argument (no layout, no paint, no JS, no process) stands
alone.

## 12. Voice

| Topic | Source |
|---|---|
| `sherpa-onnx` — **first-party Rust bindings**, releases every 1–3 weeks, streaming ASR + TTS + VAD + diarization + `KeywordSpotter` | https://github.com/k2-fsa/sherpa-onnx · https://k2-fsa.github.io/sherpa/onnx/rust-api/ · https://crates.io/crates/sherpa-onnx |
| `sherpa-rs` 0.6.8 — **repo archived**; use `sherpa-onnx` | https://crates.io/crates/sherpa-rs |
| `whisper.cpp` v1.9.4 (2026-09-11, 54 k★) — `whisper-stream` described in its own README as "a naive example"; built-in VAD; CUDA/Vulkan/Metal/CoreML/OpenVINO/HIP | https://github.com/ggml-org/whisper.cpp |
| `whisper-rs` 0.16.0 — **GitHub repo archived**, moved to Codeberg | https://crates.io/crates/whisper-rs · https://codeberg.org/tazz4843/whisper-rs |
| faster-whisper 1.2.1 (2025-10-31) — **batch only**, CUDA 12/cuDNN 9, no release in ~11 months; README benchmarks cite a version a year old | https://github.com/SYSTRAN/faster-whisper |
| `nvidia/parakeet-tdt-0.6b-v3` — **CC-BY-4.0**, 6.34 % WER clean, 25 European languages, 680 MB q8 GGUF, "at least 2 GB RAM to load" | https://huggingface.co/nvidia/parakeet-tdt-0.6b-v3 |
| **⚠ `nvidia/canary-1b` is CC-BY-NC-4.0 — non-commercial.** `canary-1b-flash` and `canary-qwen-2.5b` are CC-BY-4.0 | https://huggingface.co/nvidia/canary-1b |
| `NVIDIA/NeMo` **301-redirects** to `NVIDIA-NeMo/Speech` v3.0.0 (2026-08-07), Apache-2.0 | https://github.com/NVIDIA-NeMo/Speech |
| `OpenASR/moonshine-tiny` — MIT, **34 MB** q8, ~306 MB RAM, English only | https://huggingface.co/OpenASR/moonshine-tiny |
| `hexgrad/Kokoro-82M` — **Apache-2.0**, v1.0, 82 M params, 8 languages / 54 voices, documented training provenance | https://huggingface.co/hexgrad/Kokoro-82M |
| ONNX export sizes (fp32 310 MB / fp16 155 MB / int8 88 MB / q8f16 82 MB) | https://huggingface.co/onnx-community/Kokoro-82M-v1.0-ONNX |
| **`rhasspy/piper` archived (MIT) → `OHF-Voice/piper1-gpl` GPL-3.0**; espeak-ng phonemizer also GPL-3.0; many voices research-only | https://github.com/rhasspy/piper · https://github.com/OHF-Voice/piper1-gpl |
| **Coqui TTS 0.22.0 (2023-12-12), repo last push 2024-08-16; XTTS-v2 under the Coqui Public Model License — non-commercial including outputs, viral derivative clause** | https://github.com/coqui-ai/TTS · https://huggingface.co/coqui/XTTS-v2/blob/main/LICENSE.txt |
| **Picovoice Porcupine free tier discontinued 2026-06-30; repo archived** | https://github.com/picovoice/picovoice |
| ⚠ **`openWakeWord` code Apache-2.0 but pretrained weights CC-BY-NC-SA 4.0 — non-commercial**; PyPI 0.6.0, no release in ~2.5 years | https://github.com/dscripka/openWakeWord |
| `livekit-wakeword` (2026-02-26) + Rust crate 0.1.3 — Apache-2.0, low adoption | https://github.com/livekit/wakeword |
| eSpeak-NG — ~0.001 RTF, ~15 MB RAM, GPL-3.0 | https://github.com/espeak-ng/espeak-ng |
| `ort` — **no 2.0 stable**; `2.0.0-rc.13` (2026-07-28), last stable 1.16.3 (2023-11-12) | https://crates.io/crates/ort · https://github.com/pykeio/ort |
| `cpal` 0.18.2 — cross-platform audio I/O | https://crates.io/crates/cpal |

### Cloud ASR pricing (verified 2026-09-30 unless marked)

| Provider | Source | Note |
|---|---|---|
| OpenAI — `gpt-4o-mini-transcribe` $0.003/min, `whisper-1` $0.006/min, `gpt-realtime-whisper` $0.017/min | https://developers.openai.com/api/docs/pricing | **gpt-4o transcribe models return `json` only — only `whisper-1` still returns word timestamps and SRT/VTT** |
| Google Cloud STT v2 Standard $0.016/min; Dynamic Batch $0.003/min | https://cloud.google.com/speech-to-text/pricing | ⚠ `chirp_3` as a distinct SKU unverified |
| AWS Transcribe — batch $0.006/min, streaming $0.010/min (us-east-1) | https://aws.amazon.com/transcribe/pricing/ | AWS states batch and streaming are **no longer priced identically**; many secondary sources still publish the old tiered table |
| Deepgram — Aura TTS verified; Nova-3 STT ⚠ **not verified against the official page** | https://deepgram.com/pricing | Flux TTS free period ended 2026-09-12 |
| Azure Speech | ⚠ **UNVERIFIED** — the page is JS-rendered and returned placeholders | — |
| Groq | ⚠ **UNVERIFIED** against the official pricing page | — |

## 13. Desktop platform specifics

| Topic | Source |
|---|---|
| Tauri 2.12.0 (Rust + `@tauri-apps/cli` 2.12.0, versions aligned) | https://crates.io/crates/tauri · https://registry.npmjs.org/@tauri-apps%2Fcli/latest |
| Tauri plugins: notification 2.5.0, autostart 2.6.0, shell 2.4.0 | https://crates.io/crates/tauri-plugin-notification |
| **Fedora 44 native deps, verified installed and linkable on 2026-09-30:** webkit2gtk4.1-devel 2.54.0, libappindicator-gtk3-devel 12.10.1, librsvg2-devel 2.62.3, libxdo-devel 3.20211022.1, sqlite 3.51.2, sqlite-devel 3.51.2 | `rpm -q`, `pkg-config --modversion`, and a **compile+link+execute probe** run in `/tmp` (since removed) |
| ⚠ **Fedora packaging bug:** `libxdo.pc` declares `libdir=/usr/local/lib`, `includedir=/usr/local/include`; the files are actually in `/usr/lib64` and `/usr/include`. `pkg-config --cflags libxdo` emits a bogus `-I/usr/local/include`. Linking works (default search paths); `#include <xdo.h>` works without the flag | `cat /usr/lib64/pkgconfig/libxdo.pc` |
| macOS WKWebView, Keychain, launchd, notarisation | Apple developer documentation |
| Windows WebView2, DPAPI, Task Scheduler, Authenticode, MSI | Microsoft Learn |
| Linux XDG Base Directory spec, Secret Service / D-Bus, systemd user units | https://specifications.freedesktop.org/ |

## 14. Development machine (local inspection, 2026-09-30)

| Item | Value |
|---|---|
| OS | Fedora Linux 44 (Workstation Edition), stable, EOL 2027-05-19 |
| Kernel / arch | 7.2.7-200.fc44.x86_64 / x86_64 |
| CPU | Intel Core i5-12500H — 12 cores / 16 threads, 2.5 GHz max |
| RAM | 15 GiB total, 6.8 GiB available at inspection; 8 GiB swap |
| GPU | Intel Iris Xe (integrated) + NVIDIA RTX 3050 Mobile (4 GiB) |
| Storage | 475 GiB, 244 GiB free, LUKS-encrypted |
| Toolchain | rustc 1.98.1, cargo 1.98.1, rustup 1.29.1, host `x86_64-unknown-linux-gnu` |
| Node | `node` → v26.7.0 (Hermes runtime, **Current line**); `/usr/bin/node` → v24.18.0 (Fedora nodejs24, LTS line) — see Q-OPEN-03 |
| pnpm | 12.8.1 (user-scoped standalone binary) |
| Containers | Podman 5.8.7, Docker 29.8.1 — both pre-existing, **not introduced by this project** |
| Git | 2.55.0; identity `Rayees <rayiesamin@gmail.com>`; `gpg.format=ssh`, `commit.gpgsign=true`; GitHub HTTPS works via `gh` credential helper; **SSH is not registered** |

**Toolchain provisioning (2026-09-30, ADR-0031).** Node **v24.21.0** (LTS
codename **"Krypton"**, 2026-09-07) provisioned **project-locally** at
`.toolchains/node-v24.21.0-linux-x64/` from the official tarball, SHA-256
`fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6`, verified
against `https://nodejs.org/dist/v24.21.0/SHASUMS256.txt` — **checksum `OK`**.
`PATH`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.local/bin` and the
Hermes symlink were **not modified**; `node` still resolves to v26.7.0 and the
`PATH` hash is byte-identical to its pre-task value.

**No application code, no dependencies installed into the project, and no services
were started at any point.** `apalis-sqlite` was downloaded to `/tmp` and read as
source only; it is **not** a project dependency.
