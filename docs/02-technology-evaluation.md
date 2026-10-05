# 02 — Technology Evaluation

Status: **Draft v0.2** · **Two verdict rows corrected 2026-10-05** — see below; the rest is
a dated evaluation record and is preserved. · All versions verified 2026-09-30 against crates.io,
npm registry, `nodejs.org`, `go.dev`. Sources in `docs/sources.md`.

**Scoring note:** no numerical scores are used. Where a measurable quantity
exists (dl/30 d, RSS, RTF, WER, MSRV) it is stated as a number with its source.
Where judgement is involved, the reasoning is given and the trade-off is named.

---

## 1. Technology decision table

| Area | Candidate | Stable version | Evidence | Advantages | Disadvantages | Resource cost | Portability | Security | Decision |
|---|---|---|---|---|---|---|---|---|---|
| **Core language** | Rust | 1.98.1 (2026-09-01) | toolchain verified; `tokio` 238 M dl/30 d; MSRV metadata ecosystem-wide | No GC, no UB, `Send`/`Sync` enforcement, excellent tooling, single-binary, strongest supply-chain tooling for the domain | Slowest iteration, FFI pain for C/C++/CUDA libs, higher compile times, no runtime reflection | Lowest idle RSS; fastest cold start | Good, but each target needs its own linker/C toolchain | Memory safety by construction; `cargo audit`/`cargo deny` | **✅ ADOPT** |
| | Go | 1.27.1 | `go.dev/dl` | Trivial cross-compile, tiny binaries, garbage-collected simplicity, great concurrency | GC pauses, weak desktop-GUI story, weaker FFI ergonomics for ML libs, cgo/unsafe surface | Higher idle RSS (GC + runtime) | Excellent | Memory-safe; `govulncheck` good | ❌ Reject — GUI gap is disqualifying for a desktop-first product |
| | C++ | n/a | — | Maximal control, every ML library available | UB, build complexity, no memory safety, 5–10× slower to develop safely | Lowest possible | Painful — per-target toolchains everywhere | Poor by default | ❌ Reject |
| **Async runtime** | Tokio | 1.53.1 (2026-07-20) | 238 M dl/30 d | Ecosystem gravity is unrepeatable, cancellation tokens, mature timers, `spawn_blocking` | No structured concurrency, no built-in supervision, `Send`-bound ergonomics can bite | ~200 KB binary; a few MB RSS at idle | Windows/macOS/Linux first-class | Tasks are `Send`; no shared mutable state without a mutex | **✅ ADOPT + build our own supervisor** |
| | async-std / smol | stale | — | Lighter, `async fn` in traits is friendlier | No cancellation story, a fraction of the ecosystem, effectively abandoned as a default | Lower | Similar | Weaker isolation story | ❌ Reject |
| | std threads | n/a | — | Simplest, no runtime tax | No async I/O without OS-specific code | Lowest | Best | Fine | ⚠️ Use *inside* blocking tasks (`spawn_blocking`) |
| **Local IPC** | UDS / named pipe + JSON-RPC 2.0 | — | `axum` uses `hyper`; JSON-RPC is also MCP's wire format | One protocol stack for local + MCP + remote; filesystem ACLs on the socket; no TLS needed; no port allocation | Not cross-machine by default (solved by a TCP listener in cloud mode) | Negligible | UDS on Unix, named pipes on Windows — both give ACLs | **Filesystem permissions are a real, OS-enforced boundary** | **✅ ADOPT as primary** |
| | HTTP (axum) as local transport | 0.8.9 | 123 M dl/30 d | Familiar, cross-machine, easy debugging, WebSocket for streaming | Port allocation, no ambient identity, TLS ceremony for a loopback socket that already has filesystem ACLs | Slightly higher | Excellent | Weaker by default — HTTP has no built-in per-caller authorisation | ⚠️ **Cloud/remote adapter only** |
| | gRPC / tonic | — | — | Strong typing, streaming, good for services | Code generation, poor fit for dynamic tool schemas, heavier client story, no local-socket story | Higher | Good | mTLS available | ❌ Reject for the local path |
| **Cloud edge** | axum + tower + tower-http | 0.8.9 / 0.5.3 / 0.7.1 | verified | Same process, same handlers; mature; we already depend on the stack | None material | Only resident in cloud mode | Excellent | Needs explicit authn/authz | **✅ ADOPT, deployment-gated** |
| **Serialization** | serde + serde_json | 1.0.229 / 1.0.151 | 331/332 M dl/30 d | Ubiquitous; the entire ecosystem speaks it; MCP and OpenAI schemas are JSON Schema | `serde_json` is not the fastest; `Value` is easy to overuse | Negligible | Universal | Deserialization is an attack surface — must be bounded (see §6) | **✅ ADOPT**, with `deny_unknown_fields` policy per type |
| **Storage (local)** | SQLite via `rusqlite` bundled | 0.40.2 / libsqlite3-sys 0.38.2 | 37/72 M dl/30 d | Synchronous API matches a single-writer DB; lowest MSRV; compile-time SQL checked via `rusqlite` macros; trivial to inspect with `sqlite3` | Sync — needs a disciplined DB-thread or pool; no `async` | ~1–2 MB RSS per connection; single `.db` file | **Linux/macOS/Windows + cloud** | No network exposure; `synchronous=FULL` gives power-loss durability | **✅ ADOPT** — with bundled SQLite ≥ 3.51.3 |
| | SQLx | 0.9.0 (MSRV **1.94**) | 40.7 M dl/30 d | Native async, compile-time verified queries, Postgres+MySQL path for cloud | MSRV 1.94 eats 4 of our minor versions of headroom; async buys little for a single-writer DB; a bigger surface to audit | Similar | Good | Same | ⚠️ **Deferred** — hidden behind the repository trait (ADR-0006) |
| | PostgreSQL | — | — | Real concurrency, cloud-scale | Requires a **server** in a personal install; contradicts the core product constraint | 100s of MB + a daemon | Linux/cloud | Attack surface, auth, TLS | ❌ Reject for local; ✅ acceptable for the cloud profile only |
| | Vector DB (Qdrant/pgvector/Milvus/…) | — | — | Purpose-built ANN | **A server** for most of them; duplicates SQLite; premature | 100s MB+ | Server-only | New attack surface, new backup problem | ❌ **Reject** — embeddings are derived data |
| | `sqlite-vec` | 0.1.9 (2026-03-31) | 1.24 M dl/30 d, **no release in 6 months** | In-process, zero infra, works with any SQLite build | Pre-1.0, stale, small ANN surface | In-process, ~0 extra RSS | Any host that runs SQLite | Runs in-process — inherits SQLite's trust boundary | ⚠️ **Optional feature, off by default, abstracted** |
| | SQLite FTS5 | bundled | — | Mature, part of core, no deps | Lexical only; BM25 ranking is basic | In-process | Universal | In-process | **✅ ADOPT** for lexical search |
| **Observability** | `tracing` + `tracing-subscriber` | 0.1.44 / 0.3.23 | 203/149 M dl/30 d | Ecosystem standard; structured; cheap; spans compose | Subscriber must be chosen per deployment | ~1 MB | Universal | **Log redaction must be enforced at the subscriber layer** | **✅ ADOPT** |
| | OpenTelemetry | 0.33.0 (2026-09-18) | 63.4 M dl/30 d | Interop with existing infra; MCP now standardises `traceparent` propagation | Heavy if misused; implies a collector | Native exporter only; **zero** collector required | Good | Trace data can leak PII — must be scrubbed | ⚠️ **ADOPT as optional native OTLP exporter only** |
| **Desktop** | Tauri 2 | 2.12.0 (2026-09-26) | Rust + npm CLI both 2.12.0 | System WebView (no bundled browser); small Rust binary; strong plugin ecosystem; Tauri plugins exist for notification/autostart/shell | **WebKitGTK web process ~80–150 MB RSS on Linux**; frontend toolchain; WebView content is the attack surface for prompt injection | **Desktop shell: +80–150 MB** | Linux (WebKitGTK), Windows (WebView2); macOS (WKWebView) | CSP, isolation pattern, capability-scoped IPC | **✅ ADOPT for the desktop shell** |
| | Slint | 1.18.1 (2026-09-21) | MSRV 1.92 | Declarative, Rust-native, no webview, small, genuinely good a11y | Younger ecosystem, fewer rich-text/complex-widget primitives, designer tooling less mature | Likely lowest | Linux/Windows/macOS | Smaller content attack surface — no JS runtime | ⚠️ **Strong fallback**; reconsider if a11y/bundle cost dominates |
| | egui/eframe | 0.36.2 | MSRV **1.95** — 3 minor versions below ours | Immediate-mode, superb for debug/tools UI, fastest to iterate | Immediate mode is a poor fit for a polished long-lived product UI; **MSRV 1.95 is a real constraint** | Low | Good | No JS surface | ❌ Reject for product shell; ✅ use for in-app diagnostics |
| | iced | 0.14.0 (2025-12-07) | ~10 mo stale | Nice reactive model | Stale | Low | Good | — | ❌ Reject — maintenance signal |
| **Frontend** | Svelte 5 + Vite 8 + TS 6 | 5.57.1 / 8.3.1 / 6.0.3 | npm registry | Compile-time reactivity (runes), small runtime, no virtual DOM, lowest boilerplate of the credible options | Smaller hiring/ecosystem than React; `svelte-check` caps TS at 6 | Smallest bundle of the three | Any webview | Same XSS model as React | **✅ ADOPT** |
| | React 19 + Vite | — | — | Largest ecosystem, most hiring pool, most third-party components | Largest runtime, most boilerplate, reconciler overhead | Highest | Any webview | Same XSS model | ⚠️ **Viable alternative**, deliberately rejected on bundle/verbosity; cheap to switch since both run on Vite |
| | TypeScript 7.0.2 | 7.0.2 (2026-07-08) | MS blog + `svelte-check` peers | 8–12× faster builds, 15 % less build memory | **Microsoft explicitly excludes Svelte**; no stable programmatic API until 7.1 | Lower build cost | — | — | ⛔ **Not for this stack** — revisit after 7.1 + Volar |
| **TUI** | Ratatui | 0.30.2 (2026-06-19) | 19.6 M dl/30 d | De-facto Rust TUI; immediate-mode; excellent widgets | Not accessible (no AT-SPI), terminal-only | Negligible | Terminals only | N/A | **✅ ADOPT for the TUI** (NR-07 exemption documented) |
| **CLI** | Clap | 4.6.7 (2026-09-14) | 240 M dl/30 d | Derive macros, completions, excellent UX | Verbose for a single command | Negligible | Universal | Arg parsing is an injection surface — must be explicit | **❌ NOT USED** — *corrected 2026-10-05.* `clap` remains a workspace dependency and `orxnuctl` deliberately does **not** use it; the parser is hand-written, recorded in `crates/orxnuctl/Cargo.toml` as the smaller dependency for a closed verb set. |
| **Task engine** | Hand-rolled on SQLite | — | design in §7 of ADR-0007 | Zero deps, exact durability semantics, inspectable rows, no extra process | We own the bugs | ~0 extra RSS | Universal | Single trust boundary | **✅ ADOPT** |
| | `apalis` + `apalis-sqlite` | 0.7.4 / 1.0.0-rc.9 | 331 k dl/30 d | Ready-made queue, heartbeats, orphan recovery, priorities | SQLite backend is **RC only**, single maintainer, `synchronous` default **unverified** | In-process | Any | In-process | ⚠️ **Adopt if and only if** the durability pragma is verified correct; else hand-roll — **❌ REJECTED, the condition was evaluated and failed.** `SqliteStorage::setup()` sets `PRAGMA synchronous = OFF`, which fails TP-7. ADR-0032; Q-OPEN-02 resolved. |
| | Temporal (Rust 1.0.0) | 1.0.0 (2026-09-04) | first-party, MIT | Industry-standard durable execution; first-party Rust | Requires **server + DB**; workflow code must be deterministic, fighting LLM nondeterminism | Process + DB | Cloud | Separate trust boundary | ⛔ local · ✅ **cloud profile** |
| | Restate | 0.12.1 | first-party | Single binary; exactly-once; `ctx.sleep()`; **"durable agents"** is a first-class concept | SDK 0.x, self-declared breaking; still a second process; RocksDB not SQLite | Process | Cloud | Separate boundary | ⛔ local · ✅ **cloud profile, preferred** |
| | LangGraph / LangChain | 1.2.12 | Python | Mature checkpointer model | Python; primary sources (incl. LangChain's own) advise against the abstraction | Interpreter + deps | — | Extra runtime | ❌ **Reject** |
| **Capabilities** | Rust trait (in-process) | — | — | Fastest, zero IPC, best typing | A panic kills the core; recompile per version; **no ABI stability** | In-process | Any | Same trust as core | **✅ Tier 0 for built-ins only** |
| | Subprocess + JSON-RPC/MCP-stdio | — | — | Crash containment, language-agnostic, versioned, sandboxable | Process overhead, IPC latency | ~5–20 MB per adapter | Any | **OS-level isolation available** | **✅ Tier 1 — the default for third-party capabilities** |
| | MCP remote (Streamable HTTP) | spec 2026-07-28 | `rmcp` 3.5.0 | Interop with the ecosystem; stateless; tasks extension | Untrusted code; network exposure; spec churn (2 major revisions in 12 mo) | Remote | Any | **Must be treated as untrusted** | **✅ Tier 2, opt-in, never auto-consent** |
| | Dynamic library (dylib/cdylib) | — | — | Direct calls | **Rust has no stable plugin ABI**; recompiles against the host; a segfault kills the process | In-process | Any | Shares the core's address space | ❌ **Reject** |
| | WASM / WASI component | — | — | Strong sandbox, portable bytecode | Component model still stabilising; weakest exactly where we need strength (file/net/subprocess); poor ergonomics for audio and browser driving | Per-runtime | Excellent | Best-in-class *if* the capability set fits | ⚠️ **Revisit**, not now |
| **MCP** | Spec 2026-07-28 | — | modelcontextprotocol.io | Interop; stateless design *helps* our security posture; tasks extension; OTEL propagation | Sampling/Roots/Logging deprecated; stateless removes stateful workflows; spec churn | Client-side only | Any | Explicitly: "Tools represent arbitrary code execution and must be treated with appropriate caution" | **✅ ADOPT as the external integration protocol only** |
| **Browser** | `reqwest` HTTP-first | 0.13.5 | 197 M dl/30 d | ~4× faster, ~8× less RAM, deterministic, clean failures | Cannot execute JS or interact | ~10–50 MB | Universal | No browser surface | **✅ DEFAULT tier** |
| | `playwright-rs` | 0.19.0 (2026-09-26) | 133 k dl/90 d; bundles Playwright 1.63.0 | Cross-browser, a11y-tree grounding, auto-waiting | **Pre-1.0, single maintainer (bus factor 1); ships Node ~130 MB + browsers ~400 MB** | **Opt-in: 130 MB (Node) + ~400 MB (browser)** | Linux/Windows/macOS | Real browser = real credentials surface | ⚠️ **Tier 2, opt-in capability** |
| | BiDi | W3C WD 2026-09-30 | wpt.fyi | Standard, cross-vendor | No body access, no UA/tz/locale, no downloads; Safari absent; on Chrome it is a JS mapper over CDP | Browser | Firefox/Chromium/Edge | — | ❌ Not now |
| **Voice ASR** | `sherpa-onnx` | 1.13.8 (2026-09-11) | 475 k lifetime dl; releases every 1–3 wk; **first-party Rust** | Only complete native Rust pipeline: streaming ASR + TTS + VAD + KWS + diarization | Heavy native build; Mandarin-first model zoo; prebuilt lib downloaded at build time | ~200–600 MB with a model | x86/ARM/RISC-V, Linux/Win/macOS | Model files are third-party artifacts | **✅ ADOPT as the default local engine** |
| | `parakeet-rs` | 0.3.8 (2026-09-23) | depends on `ort` **RC** | Best WER/RAM (6.34 % clean); CC-BY-4.0 | `ort` never released 2.0 stable (last stable 2023-11-12) | 680 MB q8 weights | Linux/CUDA/CoreML/DirectML | — | ⚠️ **Optional engine behind the same trait** |
| | `whisper.cpp` + `whisper-rs` | 1.9.4 / 0.16.0 | 54 k★; `whisper-rs` repo **archived** | Most battle-tested; widest acceleration (CUDA/Vulkan/Metal/CoreML/OpenVINO) | "Streaming" is re-transcribing a rolling window; Rust binding is single-maintainer, repo archived, 6.5 mo stale | 273 MB (tiny) – 3.9 GB (large) | Excellent incl. Vulkan | — | ⚠️ **Optional engine; plan to vendor** |
| | faster-whisper | 1.2.1 (2025-10-31) | **no release in ~11 months** | Excellent batched throughput; MIT | Batch only (no streaming); CUDA 12/cuDNN 9 only; README benchmarks cite a version a year old | 1.4–6 GB | Linux/Win | — | ❌ Not for live voice |
| **Voice TTS** | Kokoro via `sherpa-onnx` | model 1.0 (2025-01-27) | **Apache-2.0 weights** | 82 M params, 8 languages/54 voices, 82–310 MB ONNX, ~0.12 RTF | Quality below a large cloud TTS; espeak-ng fallback is GPL | 82–310 MB | All | Clean licence | **✅ ADOPT as the default** |
| | Piper | 1.8.0 (`piper-tts`) | successor is **GPL-3.0** | Good quality, fast | **GPL-3.0 (was MIT)** + GPL espeak-ng; many voices are research-only | 60–75 MB | All | Copyleft | ⚠️ Only as an **out-of-process subprocess** to keep copyleft at arm's length |
| | Coqui / XTTS | 0.22.0 (2023-12-12) | code 2 y stale | Voice cloning | **CPML: non-commercial including outputs, viral derivative clause**; Python <3.12 | Varies | — | Licence forbids commercial use | ❌ **Reject** |
| | eSpeak-NG | — | ~0.001 RTF, ~15 MB | Never fails, 100+ languages, zero GPU | Robotic; GPL-3.0 | **15 MB** | Universal | — | ✅ **Always available fallback** |
| | Wake word | — | Porcupine free tier gone 2026-06-30; openWakeWord weights **CC-BY-NC-SA** | — | Licensing traps everywhere | ~50–300 MB | — | — | ❌ No third-party wake-word engine; use VAD + `KeywordSpotter` |
| **Config** | Layered TOML + JSON Schema | — | `toml` + `jsonschema` | Human-editable, diffable, versionable, schema-validated, layerable | No live reload of every type | ~0 | Universal | Secrets must be *references*, never values | **✅ ADOPT** |
| **Secrets** | `keyring` | 4.2.0 (2026-08-29) | MSRV 1.88 | Secret Service (Linux), DPAPI (Windows), Keychain (macOS) | Linux headless has no Secret Service — needs `libsecret`/file fallback with explicit warning | Negligible | All three | OS-backed, correct | **✅ ADOPT**, config stores references only |
| **Scheduling** | `croner` + `jiff` | 4.0.0 / 0.2.37 | 3.67 M / 73.6 M dl/30 d | **Only Rust cron with documented Vixie-compatible DST semantics**; jiff does correct DST arithmetic | We must implement catch-up ourselves (~30 lines) | Negligible | Universal | Pure computation | **✅ ADOPT** |
| | `clokwerk`/`job_scheduler`/`tokio-cron-scheduler` | stale/dead | 2020–2022, no SQLite | — | In-memory only or no SQLite backend | — | — | — | ❌ Reject |

---

## 2. Cross-cutting compatibility findings

These are the checks that individual "is it stable?" queries miss, and they
changed decisions.

| Compatibility check | Finding | Consequence |
|---|---|---|
| Svelte × TypeScript | `svelte-check` peers `^5 \|\| ^6`; MS says Svelte "will need to continue using TypeScript 6.0 for now" | **TS 6.0.3, not 7.0.2** |
| Svelte 5 × Vite 8 | `@sveltejs/vite-plugin-svelte` 7.3.1 engines `^20.19 \|\| ^22.12 \|\| >=24` | Frontend build needs Node ≥ 24 — matches the Krypton LTS target |
| Tauri Rust × Tauri CLI | `tauri` 2.12.0 = `@tauri-apps/cli` 2.12.0 | Aligned; pin both |
| Tauri × SQLite | Tauri bundles its own SQLite for the app state; ours is separate | No conflict, but two SQLite copies — accept |
| `axum` MSRV vs our toolchain | axum 1.80, sqlx 1.94, egui 1.95, our 1.98.1 | ~4 minor versions of headroom; **`sqlx` and `egui` are the tightest** |
| `rmcp` × MCP spec | `rmcp` 3.5.0 (2026-09-28); spec 2026-07-28 | Both new; expect churn |
| SQLite version × durability | Fedora ships 3.51.2 — **below the 3.51.3 corruption-bug fix** | Must bundle |
| `sherpa-onnx` build | auto-downloads a prebuilt `-lib` at build time if `SHERPA_ONNX_LIB_DIR` unset | Builds need network on first run; pin the URL in CI |
| `ort` × `parakeet-rs` | `parakeet-rs` needs `ort` 2.0.0-rc.13; `ort` never had a 2.0 stable | Accepted risk, recorded |
| `webrtc-vad` | last release 2019-10-01 | Do not adopt; evaluate `sherpa-onnx` VAD instead |
| Fedora `libxdo.pc` | declares `/usr/local/{lib,include}`; files are in `/usr/lib64` + `/usr/include` | Do not feed `pkg-config --cflags libxdo` to a compiler |

---

## 3. Deliberate non-choices

Things we could adopt and are choosing not to, with reasons:

| Not adopting | Why |
|---|---|
| A vector database | `sqlite-vec` is 6 months stale and pre-1.0; embeddings are *derived* data, regenerable from the source; a vector DB adds a server, a backup problem, and a new trust boundary to solve a problem SQLite solves in-process. Abstract the interface; ship FTS5 now. |
| A graph database | No requirement drives it. Personal-assistant knowledge is naturally a document graph, which SQLite + FTS5 handles. |
| Kafka / NATS / Redis | A personal install must run one process. `tokio-cron-scheduler` needing Nats is a symptom of the same disease. |
| Kubernetes / Helm | Never. The product is a personal application. |
| LangChain / LangGraph / CrewAI / AutoGen | Three independent primary sources — including LangChain's own authors — argue for minimal abstraction. Python. |
| A web framework for the *local* interface | A loopback HTTP server has no ambient identity and needs port allocation. A Unix socket / named pipe has OS-enforced ACLs for free. |
| A telemetry server | A personal install must not require a collector. Native exporter only. |
| A dynamic plugin system (dylib) | No stable Rust plugin ABI; a crash in a plugin kills the core. Subprocesses give real isolation. |
| A stealth/anti-bot browser stack | Makes us indistinguishable from an attacker — exactly what the defences are tuned to catch. And it is an arms race we lose. |
| Bundling a browser by default | ~530 MB (Node + Chromium) for a capability most users will not enable. Violates CR-2. |
| `unsafe` Rust in the core | Not banned outright, but each `unsafe` block needs a written invariant and a test. Prefer safe alternatives even at a small perf cost. |

---

## 4. Licence posture of the selected stack

| Component | Licence | Concern |
|---|---|---|
| Rust deps (core) | MIT/Apache-2.0 dominant | `cargo deny` enforces; see ADR-0019 |
| Tauri / Svelte / Vite / TS | MIT / Apache-2.0 | Clean |
| `sherpa-onnx` | Apache-2.0 | Clean |
| Kokoro-82M weights | **Apache-2.0** | Clean — and it documents its training data provenance |
| Parakeet v3 weights | **CC-BY-4.0** | Attribution required. Commercially usable. |
| `nvidia/canary-1b` weights | **CC-BY-NC-4.0** | ⛔ Never ship. |
| Piper successor | **GPL-3.0** | ⛔ Do not link. Subprocess only. |
| eSpeak-NG | **GPL-3.0** | ⛔ Do not link. |
| Coqui XTTS | **CPML** (non-commercial, viral) | ⛔ Never. |
| signal-cli | GPL-3.0 | ⛔ Do not build. |
| openWakeWord weights | **CC-BY-NC-SA 4.0** | ⛔ Never ship. |
| Windmill | **AGPL-3.0** | ⛔ Not adopting anyway. |
| DBOS | Postgres license | ⛔ Not adopting anyway. |

**Rule adopted:** the core binary links only permissively-licensed code. Any
copyleft (GPL/AGPL) or non-commercial (NC) component must run as a separate
process the user installs, or be excluded — enforced in CI by `cargo deny` plus
a manual model-licence registry review.
