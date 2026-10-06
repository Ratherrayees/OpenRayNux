# 09 — Architecture Decision Records

Status: **Draft v0.3** · Adopted 2026-09-30 · index and metadata reconciled
**2026-10-06** against `HEAD` (`4ad1832`).

Each ADR follows: Context · Problem · Options · Evidence · Decision · Why ·
Trade-offs · Consequences · Rejected alternatives · **Revisit conditions**.

Revisit conditions are mandatory. A decision without them is a decision that
will never be revisited, which is a smell.

**47 ADRs, numbered ADR-0001 … ADR-0049.** Two numbers in that range are
deliberately unused: **ADR-0041** and **ADR-0042**. They are recorded rather than
renumbered because renumbering would break every existing citation, and because a
silent gap is indistinguishable from an omission. `V-44` is unused in the
verification register for the same reason.

**Reading the dates.** ADR-0001 … ADR-0030 were written on 2026-09-30 against
`Draft v0.1` of the architecture, and their *reasoning* is a point-in-time record
that is preserved as written. The Status column below is navigational metadata and
has been corrected where it was stale — notably ADR-0007's contingency, which
ADR-0032 closed. The bodies of the early ADRs have **not** been rewritten to sound
current, because a decision log edited to agree with the present stops being
evidence of what was decided. Where a later change made an early ADR's prose
obsolete, an amendment is appended to that ADR rather than its reasoning edited.

Three ADRs gained dated amendments in the 2026-10-05 pass because their Status line had
become actively misleading: **ADR-0035** (its "gap Phase 4b must close" is closed
by V-51), **ADR-0043** ("implemented" overstated it — the primitive existed with no
production caller), and **ADR-0044** ("implementation begins in Stage 4"
understated what shipped, and omitted that the wiring is deliberately absent).

**ADR-0043 gained a further amendment on 2026-10-06**, when ADR-0047 closed the
orchestration gap it had recorded as unmet, and **ADR-0044 gained a note** recording
that continuation is now the first routine path showing a model anything about earlier
steps — without that decision changing, since `PriorStepContext` still carries no
content.

**Index**

| ADR | Decision | Status |
|---|---|---|
| [0001](#adr-0001) | Core language: Rust | Accepted |
| [0002](#adr-0002) | Desktop: Tauri 2 + Svelte, as an optional separate process | Accepted |
| [0003](#adr-0003) | Local transport: Unix socket / named pipe + JSON-RPC 2.0 | Accepted |
| [0004](#adr-0004) | Runtime: Tokio + an explicit supervisor | Accepted |
| [0005](#adr-0005) | Frontend: Svelte 5 + Vite 8; **TS 7.0.2 baseline + TS 6.0.3 co-installed** | **Amended (rev 2)** |
| [0006](#adr-0006) | Storage: SQLite via rusqlite, bundled ≥ 3.51.3 | Accepted |
| [0007](#adr-0007) | Task engine: hand-rolled durable task table | Accepted — contingency **closed** by ADR-0032 |
| [0008](#adr-0008) | No vector database | Accepted |
| [0009](#adr-0009) | Capability model: three isolation tiers, no dynamic plugins | Accepted |
| [0010](#adr-0010) | MCP as an external integration protocol only | Accepted |
| [0011](#adr-0011) | Provider-neutral LLM abstraction with capability negotiation | Accepted |
| [0012](#adr-0012) | Model proposes, deterministic engine disposes | Accepted |
| [0013](#adr-0013) | Memory: derived vs authoritative, with an enforced distinction | Accepted |
| [0014](#adr-0014) | Voice: abstraction first, `sherpa-onnx` default, eSpeak-NG floor | Accepted |
| [0015](#adr-0015) | Browser: HTTP-first, browser opt-in, a11y-tree grounding | Accepted |
| [0016](#adr-0016) | Messaging: narrow common denominator; defer WhatsApp; refuse Signal/userbots | Accepted |
| [0017](#adr-0017) | Updates: no self-updater; snapshot-migrate-rollback | Accepted |
| [0018](#adr-0018) | Configuration: 11 layers, schema-versioned, secrets by reference | Accepted |
| [0019](#adr-0019) | Dependency & licence policy: permissive-only in core | Accepted |
| [0020](#adr-0020) | Observability: tracing always, OTLP optional, zero telemetry | Accepted |
| [0021](#adr-0021) | Scheduling: `croner` + `jiff`, explicit misfire policy | Accepted |
| [0022](#adr-0022) | Deployment: one codebase, four profiles | Accepted |
| [0023](#adr-0023) | Platform: Linux + Windows T-A; ARM64 T-B; macOS T-B | Accepted |
| [0024](#adr-0024) | Reject agent frameworks; own a thin harness | Accepted |
| [0025](#adr-0025) | Tests: deterministic gate; AI evaluation on a separate track | Accepted |
| [0026](#adr-0026) | Windows as the second first-class platform, prepared early | Accepted |
| [0027](#adr-0027) | **Identity & Actor as a first-class concept** | **Accepted (new)** |
| [0028](#adr-0028) | **State as a first-class concept** | **Accepted (new)** |
| [0029](#adr-0029) | **Task-engine correctness properties are normative; the implementation is not** | **Accepted (new)** |
| [0030](#adr-0030) | **"Disabled" means zero operational cost and zero reachable capability** | **Accepted (new)** |
| [0031](#adr-0031) | **Node toolchain: OpenRayNux-local Node 24.21.0 LTS; global environment untouched** | **Accepted (new)** |
| [0032](#adr-0032) | **`apalis-sqlite` rejected: `synchronous = OFF` fails TP-7; ADR-0007's contingency is closed** | **Accepted (new)** |
| [0033](#adr-0033) | **`orxnud-task` and `orxnud-capability` are distinct layers** | **Accepted + implemented** |
| [0034](#adr-0034) | **`CapabilityInvocation` is not deserialisable; ingress uses `CapabilityRequest`** | **Accepted + implemented** (closes V-36) |
| [0035](#adr-0035) | **Tier-1 execution: PID namespace + `PDEATHSIG`, and what it does not do** | **Accepted + implemented** (its "gap Phase 4b must close" is closed by V-51) |
| [0036](#adr-0036) | **Tree lifetime on Linux: the PID namespace is load-bearing, `cgroup.kill` a redundant backstop** | **Accepted** |
| [0037](#adr-0037) | **An approval names its approver, and the digest binds them** (v2 → v3) | **Accepted + implemented** |
| [0038](#adr-0038) | **A governed action is proposed durably before it is approved** | **Accepted + implemented** |
| [0039](#adr-0039) | **A capability declares its parameters; the proposer reads the declaration** | **Accepted + implemented** |
| [0040](#adr-0040) | **One real provider, over HTTP, with the credential in the secret store** | **Accepted + implemented** (closes V-77, V-78) |
| [0043](#adr-0043) | **Continuation is an explicit operation, not a widened claim** | **Accepted + primitive implemented; no production caller** |
| [0044](#adr-0044) | **Observation is governed: approved reads, and a context that carries no content** | **Accepted + governance core implemented** |
| [0045](#adr-0045) | **One approval, two acts: a read and its disclosure to a provider identity** | **Accepted + governance core implemented** |
| [0046](#adr-0046) | **A missing host guarantee is a refusal to assert, not a test to skip** | **Accepted + implemented** |
| [0047](#adr-0047) | **A continuation is one boundary and one proposal, and the caller decides whether to take another** | **Accepted + implemented** |
| [0048](#adr-0048) | **An observation is released once, across one boundary, to the identity that asked for the read — and the read capability had to be made reachable to prove any of it** | **Accepted + implemented** |
| [0049](#adr-0049) | **An expired approval is not a decision, and a proposal whose approval lapsed is not a dead end** | **Accepted + implemented** |

---

<a id="adr-0001"></a>
## ADR-0001 — Core language: Rust

**Context.** The product is a long-lived personal daemon that runs continuously,
holds credentials, acts on a person's behalf, must be cross-platform, and must
be light on memory.

**Problem.** Choose an implementation language for the portable core.

**Options.** Rust · Go · C++ · TypeScript (Node).

**Evidence.**

| | Rust 1.98.1 | Go 1.27.1 | C++ |
|---|---|---|---|
| Memory safety | Compile-time; no UB | GC; `unsafe` + cgo surface | UB is the default hazard |
| Concurrency safety | `Send`/`Sync` enforced | goroutines are safe; shared state is not free | threads; UB |
| Idle RSS | Lowest | GC + runtime overhead | Lowest, but unsafe |
| Domain ecosystem | `tokio` 238 M dl/30 d; `serde` 331 M; `tracing` 203 M; `axum` 123 M | thinner for desktop/ML FFI | fragmented |
| Desktop options | Tauri 2.12.0, Slint 1.18.1, egui 0.36.2 | weak | Qt/wxWidgets (heavy) |
| ONNX/ML FFI | `ort`, `sherpa-onnx` (first-party) | cgo | best, natively |
| Supply-chain tooling | `cargo deny`, `cargo audit`, `cargo vet`, crates.io MSRV metadata | `govulncheck` | varies |
| Cross-compile | needs a per-target C toolchain | near-trivial | painful |

**Decision.** **Rust** for the portable core, the daemon, all capability
adapters, and the CLI. MSRV 1.98.1.

**Why.** The dominant requirement is *not* raw speed — it is **a long-lived
process holding credentials that must not corrupt its own memory or have its
concurrent state silently racy.** Rust enforces both at compile time. Go's GC
and C++'s UB model are both poor fits for a security-critical resident process.
Rust's desktop and ML ecosystems are mature enough; Go's are not. And Rust's
supply-chain tooling is the best in the industry, which matters for a project
whose threat model includes dependency compromise (TH-17).

**Trade-offs.** Slower iteration than Go. FFI friction for C/C++/CUDA model
runtimes. Higher compile times. A ~4-minor-version MSRV headroom against the
tightest dependencies (`sqlx` 1.94, `egui` 1.95).

**Consequences.** `unsafe` is minimised and audited. Cross-compilation needs
per-target C toolchains (only a build concern, not a correctness one). Compile
times are a real cost in the inner loop and CI must be budgeted for it.

**Rejected alternatives.** **Go** — no credible desktop story, GC in a resident
credential-holding process, and the ML FFI story is cgo. **C++** — UB is
structurally incompatible with a product holding user credentials.
**TypeScript/Node** — a ~130 MB runtime for the core, the worst memory profile,
and the weakest guarantee story. Also, MCP already standardises JSON-RPC, so
there is no protocol advantage.

**Revisit conditions.** If a hard performance requirement appears that Rust
cannot meet on the baseline profile, benchmark it and revisit with data — not
with a preference. Revisit the MSRV floor if a required dependency demands
> 1.99.

---

<a id="adr-0002"></a>
## ADR-0002 — Desktop: Tauri 2, as an optional separate process

**Context.** The product needs a desktop GUI on Linux and Windows, on a 15 GiB
laptop, competing for memory with everything else. Tauri was proposed.

**Problem.** Which desktop technology, and does it compromise the lightweight
goal?

**Options.** Tauri 2 (system webview) · Wry (raw) · Slint · egui/eframe ·
iced.

**Evidence.**

| | Tauri 2.12.0 | Slint 1.18.1 | egui 0.36.2 | iced 0.14.0 |
|---|---|---|---|---|
| Runtime | System WebView (WebKitGTK 4.1 / WebView2 / WKWebView) | Native | Native | Native |
| Binary size | Small (no bundled browser) | Small | Small | Small |
| **Incremental RSS** | **+80–150 MB** (WebKitGTK web process) | Likely lowest | Low | Low |
| Cold start to interactive | ~0.7–1.2 s | Likely faster | Fast | Fast |
| Rich text / complex widgets | **Excellent** (whole web platform) | Good, fewer primitives | Adequate | Adequate |
| Streaming async UI | **Excellent** | Good | Awkward | Good |
| Accessibility | Web platform (good, if authored well) | **Genuinely good** | Poor | Poor |
| Ecosystem for the UI | **Largest** (any web lib) | Younger | Smaller | Smaller |
| Maturity | 2.12.0, active, plugins for notification/autostart/shell | 1.18.1, active | Active | ~10 mo stale |
| MSRV | 1.90 | 1.92 | **1.95** | 1.88 |
| Security surface | Web content + IPC (mitigable: CSP, isolation pattern, capability-scoped IPC) | Smaller | Smaller | Smaller |

WebView behaviour differs across WebKitGTK / WebView2 / WKWebView — a real cost.

**Decision.** **Tauri 2.12.0 for the desktop shell, running as a separate
process** from the daemon, and **entirely optional** (CR-2).

**Why.** The product needs streaming async UI, rich text, lists, forms, and
long-lived reactive state. In a webview that is free; in a native toolkit it is
months of work we should not spend. The webview's memory cost is real, so we
contain it: **the GUI is a separate process**, which makes "GUI cost" literally
opt-in — a CLI-only or TUI-only user never pays the 80–150 MB. And Tauri 2's
plugin ecosystem already covers the OS concerns we need (notifications 2.5.0,
autostart 2.6.0, shell 2.4.0).

**Trade-offs.** The largest single resource cost in the product. A second
process and a second protocol client. Webview behavioural divergence across
platforms. A JS attack surface, mitigated by CSP, Tauri's isolation pattern, and
capability-scoped IPC. Requires the full Node/Vite toolchain to build the
frontend.

**Consequences.** The frontend build is a real toolchain commitment (ADR-0005).
`cfg(target_os)` is forbidden outside `crates/platform-*` even though Tauri is
itself OS-specific — the GUI crate is the one place that is allowed to know about
webviews, and it does so via its own adapters. Accessibility must be *authored*,
not assumed. Startup is dominated by the webview's first launch, which is why
the target is < 1.2 s, not < 100 ms.

**Rejected alternatives.** **Slint** — genuinely attractive (native, small, good
a11y, no JS surface) and the strongest fallback; rejected only because rich-text
and complex async UI would cost us months. **egui** — immediate mode is a poor
fit for a polished long-lived product, and MSRV 1.95 is only 3 minor versions
below ours. Rejected for the product shell, **adopted for an in-app
diagnostics panel**, where immediate mode is ideal. **iced** — stale. **Wry** —
Tauri's own renderer; using it directly means reimplementing Tauri's plugin,
IPC, and packaging layers for no benefit.

**Revisit conditions.** Revisit Slint if (a) the measured GUI RSS exceeds 200 MB
on the baseline profile, or (b) accessibility authoring proves impractical, or
(c) the web toolchain becomes a maintenance burden. Revisit if Tauri 2
materially regresses in maintenance or security. Revisit `egui` MSRV if it
exceeds our toolchain.

---

<a id="adr-0003"></a>
## ADR-0003 — Local transport: Unix socket / named pipe + JSON-RPC 2.0

**Context.** Six interfaces (GUI, TUI, CLI, voice, messaging, API) must drive
one capability set. Cloud deployment must reuse the same logic.

**Problem.** Choose the inter-process contract.

**Options.** HTTP/axum as the local transport · Unix socket + JSON-RPC ·
gRPC/protobuf · a bespoke binary protocol · WebSocket.

**Evidence.** MCP's wire format **is JSON-RPC 2.0** (spec 2026-07-28), and its
SDK is the largest in the ecosystem. `axum` 0.8.9 / `hyper` 1.11.1 are excellent
for remote services. Filesystem permissions on a socket are enforced by the
kernel.

**Decision.** **JSON-RPC 2.0 over a Unix domain socket (Linux/macOS) or a named
pipe (Windows)** as the primary local transport. The same frames travel over
HTTPS via `axum` **only** in the cloud profile.

> **Amended by ADR-0034.** The frames on this transport carry `CapabilityRequest`,
> **not** `CapabilityInvocation`. An inbound frame is untrusted data; policy
> re-authorises it from scratch on arrival. `CapabilityInvocation` is an internal,
> authority-bearing type and is not a wire type in any profile.

**Why.** Four reasons, in order of weight:

1. **One protocol stack.** Local clients, the MCP client, and the remote API
   share framing, error codes, and vocabulary. One implementation, one test
   suite, one debugging story.
2. **Authorization for free.** A socket file has filesystem permissions. That is
   the authorisation boundary, enforced by the kernel, with no tokens to manage.
   A loopback HTTP port has neither identity nor a natural ACL.
3. **Deployment simplicity.** No port allocation, no "which port is it on", no
   firewall prompt, no TLS ceremony for a socket only this user can open.
4. **It is not a network API by fashion.** The brief explicitly warned against
   creating a network API because APIs are fashionable. A local socket is not
   that.

**Trade-offs.** Not cross-machine by default (solved by a TCP listener in cloud
mode). Named pipes have different ACL and timeout semantics from Unix sockets,
so the transport is genuinely tested twice. No HTTP tooling (`curl`,
`devtools`) for local debugging — mitigated by a `orxnuctl rpc` debug subcommand
and a documented frame format.

**Consequences.** One protocol to spec, version, and test. Clients must be
tolerant of unknown methods and fields. The `platform-*` crate owns the socket
setup; the core never names a socket.

**Rejected alternatives.** **HTTP/axum as the local transport** — the strongest
runner-up, and it is exactly what we are avoiding: port allocation, no ambient
identity, TLS ceremony for a loopback socket. Axum is retained for the cloud
profile. **gRPC** — codegen, a poor fit for dynamic tool schemas, no local-socket
story. **A bespoke binary protocol** — no ecosystem, no interop, and MCP
compatibility would have to be built anyway. **WebSocket** — fine for remote
streaming, needless locally.

**Revisit conditions.** Revisit if MCP's protocol diverges so far from JSON-RPC
2.0 that sharing a stack costs more than it saves. Revisit if Windows named-pipe
limitations (max pipe instances, message size, ACL granularity) prove
insufficient for the interface set.

---

<a id="adr-0004"></a>
## ADR-0004 — Runtime: Tokio, plus an explicit supervisor

**Context.** Concurrent I/O across the network, the database, subprocesses,
audio, and a browser.

**Problem.** Choose an async runtime, and compensate for its weaknesses.

**Options.** Tokio · async-std/smol · std threads · a bespoke executor.

**Evidence.** `tokio` 1.53.1 (2026-07-20, MSRV 1.71) at **238.3 M downloads in
30 days** — an order of magnitude above everything else. `tokio-util` 0.7.19
supplies `CancellationToken`. async-std/smol are materially smaller but have no
cancellation story and a fraction of the ecosystem.

**Decision.** **Tokio** for the runtime, with two explicit compensations we own:
a **task supervisor** and a **structured cancellation discipline**.

**Why.** The ecosystem gravity is decisive and irrepeatable: every capability
we might write will assume Tokio. Fighting it would cost us in adapters forever.
Its real weaknesses are well understood and both are addressable.

**Trade-offs and the two compensations:**

| Tokio gap | Our mitigation |
|---|---|
| No structured concurrency — detached tasks can outlive their parent | A supervisor actor per task tree: `JoinSet` for the subtree, restart with backoff, escalate after N, and **no `tokio::spawn` outside the supervisor** (enforced in review) |
| No built-in backpressure or bounded concurrency | Every spawn site has an explicit `Semaphore`; the DB writer is a single bounded queue |
| Detached-task leaks | Leak detection in tests; soak test asserts no growth |

**Consequences.** Structured concurrency is a **convention plus a review rule**,
not a type-system guarantee — the one place where our determinism story is
weaker than we would like, and it is called out rather than glossed over. A
bounded scheduler abstraction is needed; that is Phase 2 work.

**Consequences (continued).** Shutdown must be explicit and bounded: stop
accepting, drain in-flight, persist state, release locks, within a deadline.

**Rejected alternatives.** **async-std/smol** — smaller, but no cancellation and a
much weaker ecosystem; the long-run cost is higher. **std threads** — retained
*inside* blocking tasks (`spawn_blocking` for rusqlite), not as the main runtime.

**Revisit conditions.** Revisit if Tokio's MSRV exceeds ours by a wide margin, or
if a credible alternative reaches comparable adoption with structured concurrency
built in.

---

<a id="adr-0005"></a>
## ADR-0005 — Frontend: Svelte 5 + Vite 8, with TypeScript 7.0.2 as the baseline and 6.0.3 co-installed

> **Amended 2026-09-30 (revision 2).** The original decision ("TypeScript 6, not
> 7") was **too strong and is corrected here.** `svelte-check` ships a supported
> TS7 path that the original research missed. The *pattern* is dual-install; the
> *baseline* is TypeScript 7. See the Amendment record at the end of this ADR.

**Context.** The Tauri frontend needs a framework, a bundler, and a type
checker. The brief proposed Svelte, TypeScript, Vite, Tauri.

**Problem.** Verify actual current compatibility rather than assuming each
project is individually stable — and do not let a tooling constraint masquerade
as an architectural decision.

**Options.** Svelte 5 · React 19. Bundler: Vite 8. TypeScript: 7.0.2 alone ·
6.0.3 alone · **7.0.2 + 6.0.3 co-installed**.

**Evidence.** Verified against the npm registry and the published package
contents on 2026-09-30.

| Package | `latest` | Released | Relevant fact |
|---|---|---|---|
| `svelte` | 5.57.1 | — | runes (compile-time reactivity) |
| `svelte-check` | **4.7.6** | — | peers `svelte ^4\|\|^5`, `typescript ^5\|\|^6`; **but ships a TS7 path** |
| `svelte-language-server` | **0.18.4** | — | **also contains `tsgo` / `tsgo-experimental-api` support** (editor support exists) |
| `vite` | 8.3.1 | — | `engines: ^20.19.0 \|\| >=22.12.0` |
| `@sveltejs/vite-plugin-svelte` | 7.3.1 | — | `^20.19 \|\| ^22.12 \|\| >=24` |
| `typescript` | **7.0.2** | 2026-07-08 | latest stable; native Go port; **no stable programmatic API until 7.1** |
| `typescript` | **6.0.3** | 2026-04-16 | the release that still ships the compiler API |

**The decisive evidence** is inside `svelte-check` 4.7.6 itself. Its README:

> "TypeScript 7 support currently requires the `--tsgo` or
> `--tsgo-experimental-api` flag. **You need to install both TypeScript 7 and
> TypeScript 6.**"

and its own flag table:

> `--tsgo` | Use TypeScript's Go implementation. Needs to have
> `@typescript/native-preview` installed. Subject to the same limitations as
> `--incremental`

and, most authoritatively, `bin/ts-version-check.js`, which is what actually
runs:

> "TypeScript 7 support currently requires both TypeScript 7 and TypeScript 6
> installed in your project, and requires using the `--tsgo` or
> `--tsgo-experimental-api` flag. You can setup both version with an npm alias
> via the following command.
> `npm install --save-dev typescript@~6 @typescript/native@npm:typescript@7`"

Microsoft's TS 7.0 announcement documents the same co-install pattern
independently (`@typescript/native` plus `@typescript/typescript6` via npm
alias), and notes that TS 7.0 "does not ship with an API… We expect TypeScript
7.1 to ship with a new (and different) API."

**Reading this together:** the `typescript@^5 || ^6` peer range is *not* a
statement that TS7 is unsupported. It is a statement that **the package named
`typescript` must be 6.x**, because tools that *embed* the compiler API still
need 6.0's API. TS7 is reached **alongside**, under an alias, selected by flag.

**Decision.**

1. **TypeScript 7.0.2 is the baseline** — the language level, the target, and
   what we evaluate against. We do **not** architect around a superseded
   compiler.
2. **TypeScript 6.0.3 is co-installed under the conventional package name**
   (`typescript@~6`) wherever tooling requires the compiler API. This is the
   documented vendor-recommended pattern, not a workaround.
3. **TypeScript 7 is installed as `@typescript/native`** (aliasing
   `typescript@7`) and enabled with `--tsgo` / `--tsgo-experimental-api`.
4. **Editor support** uses `svelte-language-server` 0.18.4, which also carries
   the `tsgo` path.
5. **TS7 adoption is evaluated explicitly** — a tracked, deliberate decision with
   a measurement, not a silent default in either direction. If `--tsgo` produces
   diagnostics that differ from the TS6 path, that difference is a tracked issue,
   not a reason to disable TS7.
6. **Svelte 5.57.1 + Vite 8.3.1.** Node 24 (Krypton LTS) as the build runtime
   (satisfies Vite's `>=22.12`).

**Why.** The original decision conflated *"the package named `typescript` must be
6.x"* with *"TypeScript 7 is unsupported for Svelte."* They are different
claims, and only the first is true. Pinning 6.0.3 outright would have made a
**tooling constraint into an architectural decision** — exactly the error the
brief warned against ("do not choose 'latest' versions blindly when
maturity/compatibility argue against them" — the converse error is just as real).
TS7 is stable, first-party, documented by the framework's own maintainers, and
available to us today. Declining it would be declining the current stable
release on the basis of a peer-dependency artefact.

**Trade-offs.** Two TypeScript installations to reason about, and a flag whose
name and package (`--tsgo` vs `@typescript/native` vs the README's older
`@typescript/native-preview`) is inconsistent *between the vendor's own docs* —
pinned explicitly in the lockfile to remove ambiguity. `--tsgo` is documented as
subject to the same limitations as `--incremental`, so it is not a
parity-guaranteed path and must be validated, not assumed. A smaller ecosystem
and hiring pool than React. **The frontend build requires Node ≥ 24**, and the
workstation's `node` currently resolves to v26.7.0 (Current, non-LTS) — see
Q-OPEN-03.

**Consequences.** Exact pins in the lockfile for *both* compilers, so a
`pnpm update` cannot silently cross a boundary. A short Phase-6 work item:
*verify TS6 and `--tsgo` diagnostics agree on our own code*; any divergence is
filed and tracked. Frontend accessibility must be authored, not inherited
(NR-07).

**Rejected alternatives.** **TypeScript 6.0.3 alone** — *rejected in revision 2*;
declines the current stable release for a peer-dependency artefact.
**TypeScript 7.0.2 alone, with no 6.x** — not possible: tools that embed the
compiler API need 6.0, and the vendor's own install command installs both.
**React 19** — viable and a near-trivial change since both run on Vite; rejected
on runtime size and boilerplate, not capability. **Vite 7** — no reason to prefer
an older major.

**Revisit conditions.** Revisit when TypeScript 7.1 ships the stable
programmatic API — at which point the dual-install may collapse to TS7 alone and
`svelte-check`'s peer range may widen to `^7`. Re-evaluate if `svelte-check`
retires the `--tsgo` flag. Revisit Svelte vs React if Svelte 6 changes the
reactivity model in a way that breaks our assumptions, or if a required UI
dependency becomes React-only.

### Amendment record — revision 1 → revision 2

| | Revision 1 (original) | Revision 2 (current) |
|---|---|---|
| Claim | "Microsoft explicitly excludes Svelte from TS7" | **Overstated.** Microsoft excludes Svelte from the *`tsc`/API path*; `svelte-check` ships a flagged TS7 path |
| Evidence used | `svelte-check` peer range `^5 \|\| ^6` | Peer range **plus** `svelte-check` README + `bin/ts-version-check.js` + `svelte-language-server` 0.18.4 |
| Decision | TS 6.0.3 only | **TS 7.0.2 baseline + TS 6.0.3 co-installed** |
| Error class | **Converse of "latest-blinkism"**: a tooling constraint promoted to an architectural decision | Corrected |

**Lesson recorded because it is generalisable:** a peer-dependency range tells
you what a package *declares*, not what is *possible*. Before promoting a
tooling limitation to an architectural decision, read the tool's own source and
docs for a supported path.

---

<a id="adr-0006"></a>
## ADR-0006 — Storage: SQLite via rusqlite, bundled ≥ 3.51.3

**Context.** Local-first, no server, durable across power loss, possibly
Postgres later.

**Problem.** Choose the storage engine and the Rust driver.

**Options.** `rusqlite` (sync, bundled) · `sqlx` 0.9 (async) · PostgreSQL ·
embedded KV · document store.

**Evidence.**

| | `rusqlite` 0.40.2 | `sqlx` 0.9.0 |
|---|---|---|
| MSRV | — | **1.94** (≈4 of our minor versions) |
| Model | Synchronous | Native async |
| Compile-time SQL checking | Yes, via macros | Yes |
| Multi-backend (for cloud) | No | Yes (SQLite, Postgres, MySQL) |
| Downloads/30 d | 37.4 M | 40.7 M |

SQLite facts (from `sqlite.org/wal.html`, updated 2026-08-25):
- WAL mode is mandatory and persistent.
- **"There can only be a single writer at a time."** (also `isolation.html`)
- `synchronous=NORMAL` in WAL: *"syncing the content to the disk is not
  required, as long as the application is willing to sacrifice durability
  following a power loss or hard reboot."* — **not** power-loss safe.
- `synchronous=FULL` in WAL: *"Writers sync the WAL on every transaction
  commit."*
- **A corruption bug (WAL-reset) is present in all versions 3.7.0 → 3.51.2, fixed
  in 3.51.3** (2026-03-13), plus backports 3.50.7 and 3.44.6.

**Decision.**
1. **SQLite** as the local store, accessed through `rusqlite` 0.40.2 with
   **`libsqlite3-sys` `bundled`**, and the bundled version asserted **≥ 3.51.3** in
   a build-time test.
2. **All access through a repository layer** that exposes domain operations, not
   raw SQL. The driver is therefore swappable.
3. **`journal_mode=WAL` + `synchronous=FULL`** on the task/queue connection,
   because the brief requires survival of power loss.
4. **`sqlx` is deferred**, not rejected — see revisit conditions.
5. **Packaging policy (added 2026-09-30, revision 2):** OpenRayNux **bundles and
   pins its own SQLite**. It does **not** link the system library, and it does not
   rely on whatever SQLite the host happens to ship. See below.

**Why.**

- **SQLite over any server** because the product must be a single local process
  with no daemon to install, start, secure, back up, or upgrade. This is the
  decision that makes "lightweight" real.
- **`rusqlite` over `sqlx`** because SQLite *is* single-writer — the async
  benefit largely does not exist for our dominant access pattern — while
  `sqlx`'s MSRV 1.94 consumes a quarter of our headroom for a benefit we do not
  need. `rusqlite` also keeps rows directly inspectable with the `sqlite3` CLI,
  which matters during development and for support.
- **Bundle ≥ 3.51.3** because Fedora 44 ships 3.51.2, which carries the
  WAL-reset corruption bug — and a durable task queue is precisely the
  multi-connection write workload that triggers it.
- **`synchronous=FULL`** because `NORMAL` explicitly does not survive power loss,
  and the brief requires it. We accept the fsync cost and will measure it
  (`05-…` §7).

**Trade-offs.** Synchronous access must not block the runtime — mitigated with a
single writer thread plus `spawn_blocking` for reads. `synchronous=FULL` costs an
fsync per state transition. Single-writer means the DB must not be opened by
another writer process. `rusqlite` gives no path to Postgres for the cloud
profile — which is precisely why the repository layer is mandatory. **Bundling
SQLite means we own a C build in our toolchain and a pin in our release process**
(see below).

### Packaging and version policy (revision 2)

The SQLite 3.51.3 finding is only half a decision. The other half is: *what do we
actually ship?*

| Environment | SQLite | Verdict |
|---|---|---|
| **Development workstation (Fedora 44)** | 3.51.2 | **Acceptable for development only.** It is *below* the 3.51.3 fix, so a durability bug present in our target is **not reproducible locally** — which is itself a reason not to develop against it exclusively. |
| **What we ship** | **Bundled, pinned, ≥ 3.51.3** | The only version we support. |

**Policy:**

1. **Bundle, do not link the system library.** `libsqlite3-sys` with the
   `bundled` feature. Every platform gets a *known* SQLite, not a distro's.
2. **Assert the version at build time.** A compile-time assertion (and a test)
   that the bundled `SQLITE_VERSION_NUMBER` ≥ 3.51.3. A release that fails this
   does not build. This makes the requirement mechanically enforced rather than
   a comment.
3. **Pin the exact amalgamation** in the lockfile, and record the pinned
   `SQLITE_SOURCE_ID` / SHA3 in the SBOM. SQLite releases are
   security-relevant artefacts.
4. **Track SQLite releases** as a supply-chain dependency (ADR-0019), because the
   WAL-reset bug class is exactly the kind of thing that appears without an
   announcement in a changelog.
5. **Document the minimum for anyone building from source outside our build**
   (distro packagers, contributors), and make a too-old system SQLite a
   **clear build error**, not a warning.
6. **A development-machine SQLite below the minimum is permitted but must be
   called out**, because it means local testing does not cover the shipped
   configuration. Our own machine is currently in exactly this state — which is a
   reason to bundle sooner rather than later.

**Why bundle rather than require.** OpenRayNux is a personal application
installed on machines we do not control, across Linux distributions, Windows, and
eventually macOS and ARM64. Requiring "SQLite ≥ 3.51.3" is a support burden
(users would have to build SQLite), a security risk (an old system SQLite would
silently reintroduce a data-corruption bug), and an unfalsifiable promise (we
cannot verify the host's SQLite before running). Bundling converts a
distribution problem into a release-process problem, which we can own and test.

**Trade-off accepted.** We now compile and ship a C library. That means a C
toolchain in our build, a cross-compilation concern for every target, and a
supply-chain pin. That is a real cost — and it is smaller than the cost of a user
running a data-corrupting SQLite because their distro was slow to update.

**Re-verification note.** 3.51.3's own changelog also adds *"Improved resistance
to database corruption caused by an application breaking Posix advisory locks
using close()"* — a second fix in the same area. Both are reasons to be on
3.51.3+, and both reinforce that SQLite needs active tracking, not a once-ever
version pin.

**Consequences.** One file to back up, and a backup must include `-wal`/`-shm`
via the SQLite backup API, never a naive file copy. A single-instance lock is
mandatory. The DB thread model is documented (`08-…` §11). The bundled SQLite
version is a security-relevant dependency and is tracked in CI.

**Rejected alternatives.** **`sqlx` 0.9 now** — its async model buys little
against a single-writer engine, and its MSRV is the tightest in the stack. Not
rejected on merit. **PostgreSQL** — requires a server in a personal install,
which contradicts the product's core constraint. **An embedded KV store** — a KV
store cannot express the relational task/schedule/audit model or FTS. **A
document store** — no referential integrity for the task graph, and no FTS5.

### Phase 2 verification record (added 2026-09-30)

The policy above is now **enforced and measured**, not just written down.

| Requirement | How it is enforced | Evidence |
|---|---|---|
| Bundled, never the system library | `rusqlite` with `bundled`; `DEP_SQLITE3_INCLUDE` is what the `backup`/version machinery reads | `Cargo.toml`, `crates/orxnud-store/build.rs` |
| Assert `>= 3.51.3` at **compile time** | `build.rs` parses `SQLITE_VERSION_NUMBER` out of the header `libsqlite3-sys` actually compiles and emits it as a `rustc-env`; `const_assert_min_sqlite` asserts on *that*, not on a constant we wrote | `crates/orxnud-store/build.rs`, `sqlite.rs` |
| `journal_mode = WAL` + `synchronous = FULL` | Applied **and read back** on *every* connection, in `Store::open` | `pragma.rs::verify` |
| Never `synchronous = OFF` | `Pragma::verify` refuses it; a test reproduces ADR-0032's exact failure and proves verification catches it | `crates/orxnud-task/tests/durability.rs::a_weakened_durability_setting_is_caught_by_verification` |
| Not linked to a system SQLite ≥ 3.51.3 | The minimum is enforced at build time, so a `pkg-config` build against 3.51.2 fails the build rather than warning | V-02, and the failure message in `build.rs` |
| Is `FULL` affordable? | **Measured**: ~2.3 ms/commit vs ~0.2 ms for `NORMAL` (7.3×–14.3× over four runs) | V-30, V-35 |

Two findings from this verification that the ADR did not anticipate:

1. **`SQLITE_DEFAULT_SYNCHRONOUS` is already FULL** in the bundled build, and
   `rusqlite` enables foreign keys on open. So "we forgot to set it" is not the
   failure mode — **someone weakening it** is, which is precisely what ADR-0032
   found in `apalis-sqlite`. Verification is therefore load-bearing rather than
   decorative, and `WAL` is the only default that genuinely has to be set (and once
   set it is persistent).
2. **Durability cannot be measured on tmpfs.** `fsync` is a no-op there, so the
   first run of the measurement harness reported `synchronous = FULL` and `= NORMAL`
   as *identical*. The harness now refuses to run on a memory-backed filesystem.
   See V-31.
3. **The headroom is real but not generous.** A fenced commit measures 2.2–3.4 ms
   against a < 5 ms budget, so 30–55% remains — and the ratio against `NORMAL`
   swings between 7.3× and 14.3× between runs, because the `NORMAL` baseline is a
   fraction of a millisecond and dominated by disk scheduling. The durable figure is
   the magnitude; the ratio is a range. See V-35.

**Revisit conditions.** **Revisit bundling** only if a security advisory in the
SQLite amalgamation proves impractical to patch quickly, or if a target platform's
toolchain cannot build it (in which case: pin and verify the system version
per-platform rather than reverting to "trust the host"). **Revisit `sqlx` when** we need genuine concurrent
read/write from many async tasks and the blocking model measurably hurts, or
when the cloud profile needs one repository over SQLite *and* Postgres. In that
case, the repository layer already exists. **Revisit the engine** only if
SQLite cannot meet a measured requirement — it has never failed a durability
claim, but it has one writer, which is a real ceiling we have not yet hit.

---

<a id="adr-0007"></a>
## ADR-0007 — Task engine: hand-rolled durable task table

**Context.** Tasks must be short, long, scheduled, recurring, paused, cancelled,
failed, retrying, waiting-for-user, or waiting-for-external-system — and must
survive app restart, power loss, and reboot. The brief warned against adopting an
AI framework just because it is AI-related.

**Problem.** Choose an orchestration model.

**Options.** Hand-rolled on SQLite · `apalis` + `apalis-sqlite` · `fang` ·
Temporal · Restate · DBOS · LangGraph · a bespoke state machine.

**Evidence.**

| Option | Version | Deployment | Verdict |
|---|---|---|---|
| `apalis` / `apalis-sqlite` | 0.7.4 / **1.0.0-rc.9** | library + one `.db` | Strong candidate; SQLite backend is **RC**, single maintainer, and its `synchronous` default is **unverified** |
| `fang` | 0.11.0 | library + SQLite | 2 maintainers; **cron is UTC-only** |
| `temporalio-sdk` | **1.0.0 (2026-09-04)** | **server + DB** | ⛔ local, ✅ cloud |
| `restate-sdk` | 0.12.1 | single binary | ⛔ local, ✅ cloud |
| `dbos` (Rust) | 0.5.0, **1 173 lifetime downloads** | **Postgres only**; docs say "the scheduler is not yet" | ⛔ |
| `apalis-workflow` | 0.1.0-rc.10 | — | ⛔ beta, in-memory examples |
| Windmill | — | Postgres + Docker + workers, **AGPL** | ⛔ |
| Inngest | — | **no Rust SDK** | ⛔ |
| LangGraph | 1.2.12 | Python | ⛔ (ADR-0024) |
| `clokwerk` / `job_scheduler` / `tokio-cron-scheduler` | 2020–2022, **no SQLite** | — | ⛔ |

**Decision.** **A hand-rolled durable task table on SQLite**, structured as an
explicit state machine with atomic claim, leases, heartbeats, an idempotency
ledger, and a dead-letter state.

> **Amended 2026-09-30:** the *contract* for this engine is now specified
> independently of this implementation as the twelve normative properties in
> **[ADR-0029](#adr-0029)**. This ADR chooses the implementation; ADR-0029
> defines what "correct" means. A future engine (e.g. `apalis`) is substitutable
> if and only if it passes the ADR-0029 conformance suite.

**Why.** The requirement is *task-queue durability*, not *replay-based durable
execution*. Nobody needs step-level replay; what is needed is
`pending → running → done` being transactional — roughly 200–400 lines. Every
durable-execution platform adds a process, a log format, a determinism
constraint on workflow code (which fights LLM nondeterminism), and a payload
codec. For one user on one machine that is pure cost. Owning it also means the
rows are inspectable with `sqlite3`, which matters when a user asks "why did
that job not run?".

**Core schema (design, not implementation):**

```
tasks(id, kind, payload, status, priority, run_after, attempt_count,
      max_attempts, lease_until, worker_id, last_error,
      created_at, updated_at, dead_lettered_at)
schedule_fires(schedule_id, fire_time, status, claimed_at, started_at,
               finished_at, UNIQUE(schedule_id, fire_time))
schedules(id, cron_expr, timezone, misfire_policy, catch_up_cap,
          enabled, last_fired_at)
task_checkpoints(task_id, step_key, result)
dedupe(key PRIMARY KEY, result, created_at)
```

**Three invariants, stated as requirements:**

1. **Every state transition is a single `BEGIN IMMEDIATE` transaction.**
   `sqlite.org/lang_transaction.html`: *"If the BEGIN IMMEDIATE operation
   succeeds, then no subsequent operations in that transaction will ever fail
   with a SQLITE_BUSY error."*
2. **Claim is atomic** — `UPDATE ... WHERE id = (SELECT ... LIMIT 1) RETURNING *`
   inside that transaction. Never `SELECT` then `UPDATE`.
3. **Every external side effect carries a deterministic idempotency key**, and
   the dedupe row is written in the **same** transaction as the DB write.

**Trade-offs.** We own the bugs. Scheduling, catch-up, DST, and dead-lettering
are all ours to get right. No third-party roadmap.

**Consequences.** `apalis` is the first thing to reconsider if the hand-rolled
version grows past ~600 lines of queue logic — but **only after verifying its
`PRAGMA synchronous` default**, because the whole power-loss guarantee depends
on it. That verification is an open action, not a decision (Q-OPEN-02).

> **RESOLVED 2026-09-30 (Q-OPEN-02).** The contingency is **CLOSED**.
> `apalis-sqlite` `1.0.0-rc.9` sets **`PRAGMA synchronous = OFF`** in
> `SqliteStorage::setup()` (`src/lib.rs:156`) with no configuration knob, and
> never released a stable. That fails **TP-7** outright and partially fails
> **TP-5**. See **[ADR-0032](#adr-0032)**. The hand-rolled engine is therefore
> not merely the default — it is currently the **only** conforming option.

**Cloud.** In the cloud profile, a single instance still runs its own scheduler.
The upgrade to Restate (preferred: single binary, exactly-once, `ctx.sleep()`,
and "durable agents" as a first-class concept) or Temporal is triggered by
*multi-instance* or *long-running-workflow* needs — **not** by "we are in the
cloud".

**Rejected alternatives.** See table. `apalis` is rejected *for now* on RC
status and one unverified setting, not on quality.

### Phase 2 record (added 2026-09-30)

The engine exists and passes the ADR-0029 conformance suite **unchanged**
(V-32). Four things about it that the design above did not say, and that a future
swapping engine would need to know:

1. **A `Failed` task must be requeued, not left terminal.** `TaskState::Failed`
   is terminal in the state machine *and* documented as "within the retry budget".
   Taken literally, "terminal" wins and no retry ever happens — which satisfies
   TP-11 vacuously. The engine therefore requeues a `Failed` task whose budget
   remains, and dead-letters only at the budget. See amendment A-004.
2. **The retry delay is a parameter of the committing call**, not a repository
   constant, because TP-11 drives the state machine without moving a clock. A
   fixed backoff would make its retry unclaimable.
3. **The fence must evaluate identity *and* liveness before legality.** A worker
   whose task was cancelled must be told "you do not hold this", not "illegal
   transition" — it did nothing wrong, and the second message sends the reader
   looking for a bug in the caller.
4. **The catch-up window convention belongs to the harness**, not the engine. See
   amendment A-002.

**Line count.** Queue logic is ~1 000 lines including the SQL, the repositories,
the scheduler, and their tests — over the ~600-line threshold at which this ADR
says to reconsider `apalis`. That reconsideration was already **closed** by
ADR-0032 on the merits (`synchronous = OFF`), not on size, so the threshold being
crossed does not reopen it. Recorded rather than quietly ignored.

**Revisit conditions.** Revisit if the hand-rolled engine exceeds ~600 lines of
queue logic, or if multi-instance execution is ever required (→ Restate).
Revisit if a durable-execution library reaches Rust 1.0 with **SQLite** as a
first-class backend and a documented power-loss guarantee.

---

<a id="adr-0008"></a>
## ADR-0008 — No vector database

**Context.** The brief warned: *"Avoid infrastructure merely because 'AI
applications need vector DBs.'"*

**Problem.** Where do embeddings and semantic retrieval live?

**Options.** Qdrant · Milvus · pgvector · Weaviate · `sqlite-vec` · SQLite FTS5
plus an in-process index · nothing yet.

**Evidence.** `sqlite-vec` **0.1.9 (2026-03-31)**, 1.24 M downloads/30 d —
popular, but **pre-1.0 and no release in 6 months**. Every server-based vector
DB adds a service to install, secure, back up, and upgrade.

**Decision.**
1. **No vector database.** Embeddings, when they exist, are **derived data** in
   SQLite.
2. **SQLite FTS5** (BM25) for lexical retrieval **now**.
3. The vector interface is **abstracted and optional**, off by default.
4. `sqlite-vec` may be adopted behind that interface **when it reaches 1.0**.

**Why.** An embedding is a *derived* artefact: delete the source, regenerate the
embedding. Storing derived data in a system that needs its own backups,
availability guarantees, and trust boundary is a poor trade. FTS5 is bundled,
mature, needs no service, and — for a personal knowledge base of the size a
human generates — lexical search is frequently sufficient. `sqlite-vec`'s
six-month release gap means depending on it now means depending on an abandoned
project.

**Trade-offs.** Semantic (meaning-based) retrieval is unavailable in v1. This
will need revisiting as the knowledge base grows — and it should be revisited
with a measurement, not a feeling: *measure whether FTS5 + reranking fails on
real queries* before adding infrastructure.

**Consequences.** A retrieval abstraction exists from day one, so swapping the
backend is cheap. The "no infrastructure" property is preserved.

**Rejected alternatives.** **Qdrant/Milvus/Weaviate** — a server. **pgvector** —
a Postgres server. All rejected for the same reason as ADR-0006: no daemons in a
personal install.

**Revisit conditions.** Revisit when measured retrieval quality on real queries
falls short of acceptable with FTS5 + reranking, **or** when the knowledge base
exceeds what SQLite handles comfortably. Revisit `sqlite-vec` at 1.0.

---

<a id="adr-0009"></a>
## ADR-0009 — Capability model: three isolation tiers, no dynamic plugins

**Context.** The brief: *"A crashing optional integration should ideally not
crash the core"* and *"Do not automatically create a dynamic plugin system."*

**Problem.** Choose an extension mechanism.

**Options.** Rust traits · dynamic libraries · subprocesses · MCP · WASM/WASI ·
RPC.

**Decision.** **Three tiers.**

| Tier | Mechanism | For | Trust |
|---|---|---|---|
| **0** | Rust trait, in-process | Built-ins; hot paths | Core |
| **1** | Subprocess, JSON-RPC over stdio | User-installed integrations; heavy/fragile native code; **all** GPL/AGPL/NC components | Sandboxed |
| **2** | MCP remote (Streamable HTTP) | Third-party, untrusted | Untrusted |

**Why.**

1. **A `cdylib` cannot satisfy the requirement.** Rust has no stable plugin ABI
   (a plugin must be rebuilt against every host version), a segfault kills the
   host, it shares the address space so it can read every secret, and it shares
   dependency versions. Cost of subprocess: one ~1–5 ms hop. Benefit: the core
   can never be killed by a bad integration, and the trust boundary is real.
2. **Licence forces the boundary.** GPL/AGPL must not be linked into the core
   binary. This is *why* Piper and eSpeak-NG are subprocesses — the licence, not
   an aesthetic, puts them there.
3. **Heavy native code belongs outside.** ONNX Runtime, browser drivers, and
   model runtimes are exactly the components that segfault.

**Tier rules.** Tier 0 only for built-ins where a panic is a bug we fix, or
where sub-millisecond latency is required. Everything third-party, untrusted,
or copyleft is Tier 1+. No capability may invoke another capability.

**WASM/WASI: deferred, with a specific reason.** Not rejected in principle —
rejected because the capabilities we most need to isolate (filesystem, network,
**subprocess spawning**, audio, browser driving) are exactly where WASM's
sandbox is weakest and the Component Model is least mature.

**Trade-offs.** IPC latency (~1–5 ms) and ~5–20 MB per Tier 1 process. A
capability manifest and a versioned wire contract to maintain. A capability
cannot be a bare Rust trait if it is out-of-process — so Tier 1/2 need schema
validation at the boundary, losing compile-time type safety.

**Consequences.** Every capability ships a 10-point contract test suite
(`07-…` §8) — this is what makes substitutability real rather than aspirational.
Manifests are data, signed, and treated as untrusted claims.

> **Phase 3 record.** The harness exists as `crates/orxnud-capability/tests/contract.rs`,
> and it is deliberately honest about what it cannot yet prove: **points 4 and 6 are
> declaration-only.** "No undeclared filesystem or network access" and "a disabled
> capability leaves no residue" are properties of a real sandbox and a real process
> respectively. An in-process fixture can observe neither, so the harness records them
> as `declared_only` with the reason, and a test asserts that exactly points 4 and 6
> appear there. If a future change promotes them to `proven`, that test fails and
> someone has to justify it.
>
> A contract suite that *claimed* to verify subprocess isolation while running only
> in-process fixtures would be worse than none, because it would let a reviewer
> believe the boundary was tested.

**Rejected alternatives.** **Dynamic libraries** — see above. **WASM** — see
above. **A single "plugin" mechanism** — one size fits none; the tiers exist
because the requirements genuinely differ.

**Revisit conditions.** Revisit WASM when the Component Model is stable **and**
a real capability exists needing no host resources. Revisit Tier 0 for anything
currently Tier 1+ if profiling shows the IPC cost matters on a hot path.

---

<a id="adr-0010"></a>
## ADR-0010 — MCP as an external integration protocol only

**Context.** The brief asks where MCP belongs, and warns: *"MCP must not become
synonymous with 'trusted code.'"*

**Problem.** Decide MCP's role.

**Options.** MCP as the internal capability protocol · MCP as the external
integration protocol · MCP everywhere · not at all.

**Evidence.** Spec revision **`2026-07-28`** is current (verified at
`modelcontextprotocol.io/specification/latest`). Major changes since
`2025-11-25`:

- **MCP is now stateless.** `initialize`/`notifications/initialized` and
  `Mcp-Session-Id` are **removed**; each request carries version and capabilities
  in `_meta`.
- `server/discover` added for up-front version selection.
- **MRTR** (Multi Round-Trip Requests) replaces server-initiated requests;
  `roots/list`, `sampling/createMessage`, `elicitation/create` are no longer
  server-initiated.
- **Sampling, Roots, and Logging are deprecated**, with a 12-month minimum window
  and a public registry. The stated migration for sampling is to *"integrate
  directly with LLM provider APIs"* — which is what we do.
- **SSE resumability and message redelivery are removed.**
- Tasks moved to an **extension** (`io.modelcontextprotocol/tasks`).
- `tools/list` and friends must return `ttlMs` and `cacheScope`.
- The spec itself: *"Tools represent arbitrary code execution and must be treated
  with appropriate caution. … descriptions of tool behavior such as annotations
  should be considered untrusted, unless obtained from a trusted server."*
- `rmcp` (Rust SDK) 3.5.0, 2026-09-28 — both new; expect churn.

**Decision.**
1. **MCP is the protocol for capabilities OpenRayNux does not implement.** It is
   **not** the internal capability protocol (ADR-0009 handles that).
2. **MCP servers are untrusted**, always Tier 2 (or Tier 1 for local stdio), never
   in-process.
3. **No auto-consent**, ever. Per-tool, per-argument-scope approval, bound to a
   digest exactly like our own capabilities.
4. **Per-server kill switch**, independent revocation.
5. **Client only** in v1. We do not ship an MCP *server* for our own capabilities
   (deferred — see revisit).
6. Given SSE resumability was removed, **re-issue lost requests with an
   idempotency key** (S7) to avoid duplicates.

**Why.** MCP's value is *interoperability* — attaching tools we have never heard
of. That is exactly the untrusted case, and the spec says so. Conforming the
internal protocol to MCP would import spec churn (two major revisions in twelve
months) into the core for no benefit. Statelessness is, notably, *good* for our
security posture: there is no longer a session object that could be confused for
a grant.

**Trade-offs.** We maintain two protocols. MCP churn is real. Tool discovery and
policy must be implemented against a moving spec. The Tasks extension may be
absent, so long-running third-party work needs a fallback.

**Consequences.** A `mcp` Cargo feature, off by default. The Tasks extension maps
to our task table (`waiting-for-external-system`), with a fallback when the
extension is not negotiated. `tools/list` results are cached per `ttlMs`.

**Rejected alternatives.** **MCP as the internal protocol** — churn and a
lowest-common-denominator constraint on our own contracts. **Shipping an MCP
server** for our capabilities — genuinely attractive for ecosystem
interoperability, but it is an *outbound* surface and it is a commitment to a
moving spec. Deferred, not rejected. **Not using MCP at all** — gives up the main
reason the ecosystem exists.

**Revisit conditions.** Revisit the server direction when the spec stabilises and
there is demonstrated user demand for external agents to call OpenRayNux. Revisit
the Tasks mapping when the extension reaches a stable, widely-implemented state.
**Track the 12-month deprecation windows** — do not build on deprecated features.

---

<a id="adr-0011"></a>
## ADR-0011 — Provider-neutral LLM abstraction with capability negotiation

**Context.** The brief: *"Do not couple OpenRayNux to OpenAI, Anthropic,
OpenRouter, Groq, NVIDIA or any other provider."*

**Problem.** Design an LLM abstraction that is genuinely neutral.

**Options.** A thin HTTP client per provider behind one trait · the lowest
common denominator · capability negotiation · an existing abstraction crate.

**Evidence.** Cross-provider divergence is real and material:

- **Structured output strictness.** OpenAI's Structured Outputs is on by default
  for `gpt-4o`+ via `text.format.json_schema.strict`. Anthropic implements it
  via `output_config.format` with `json_schema` and **strictly validates schema
  keywords** where tool schemas silently ignore unsupported ones — a Zod
  `z.number().positive()` → `exclusiveMinimum: 0` yields a **400** on Anthropic
  but is fine on OpenAI. Vercel AI had to add `sanitizeJsonSchema` for exactly
  this.
- **Grammar-size ceilings.** Complex schemas hit
  *"The compiled grammar is too large"* on Anthropic's GA structured outputs.
- **Refusals are a separate outcome.** Structured Outputs does not bind the
  safety layer: *"the API response will include a new field called `refusal`."*
- Tool-calling schemas differ in what they tolerate.
- Word-level timestamps: only OpenAI's legacy `whisper-1` still returns them;
  the newer transcribe models return `json` only.

**Decision.**
1. A `ModelProvider` trait exposing **capabilities as data**, not as a
   lowest-common-denominator method set.
2. `ProviderCapabilities { tools, structured_output, streaming, vision,
   word_timestamps, max_context, ... }`. Callers **branch on capability**, never
   on provider name. Provider-name checks in the core are a lint violation.
3. **A schema sanitiser** emitting a portable JSON Schema subset: `string,
   number, boolean, integer, object, array, enum, anyOf`; all properties
   `required`; `additionalProperties: false`; **no `$ref`/`$defs`**; shallow
   nesting. Sanitised before every send.
4. **Refusal is a first-class outcome**, not an error.
5. **Small, purpose-specific schemas** — one "decision" schema and one
   "extraction" schema, not a monolith.
6. **Provider calls are a capability**, so they pass through policy, budget, and
   egress classification. The model never holds a credential (S1).

**Why.** Capability negotiation is the only way to be genuinely neutral: it lets
us *use* a provider's strengths rather than flattening to the intersection. The
sanitiser exists because the providers demonstrably disagree, and a 400 from a
strict provider is a correctness bug, not a provider quirk.

**Trade-offs.** More code than a lowest-common-denominator trait. Capability
branching means more code paths, hence more tests. The sanitiser will lose
fidelity on rich schemas — accepted deliberately, because a portable schema that
works everywhere beats a rich one that 400s.

**Consequences.** Adding a provider is one adapter crate and a capability
descriptor. No core change. The non-blocking AI evaluation track
(ADR-0025) exists partly because provider behaviour drifts.

**Rejected alternatives.** **Lowest common denominator** — would forfeit
structured output and streaming on some providers, making the product worse for
no gain. **An existing abstraction crate** — each abstracts to *its author's*
provider set and couples us to that crate's model of the world. **Direct
provider SDKs in the core** — maximum coupling.

**Revisit conditions.** Revisit if a standards body produces a portable
structured-output profile that removes the need for our sanitiser. Revisit the
schema subset if a provider's grammar limits are lifted.

---

<a id="adr-0012"></a>
## ADR-0012 — Model proposes; deterministic engine disposes

**Context.** The brief's most important safety requirement: *"The LLM must never
be the authority that grants itself permission."*

**Problem.** Enforce the deterministic/probabilistic boundary structurally, not
by convention.

**Decision.** Three mechanisms, layered.

1. **Type-level.** The intent layer's only output is `Proposal` — inert data with
   **no method that reaches an adapter**. Writing the unsafe path requires
   deliberately constructing an authorised `CapabilityInvocation`, which only the
   policy layer's constructor produces. It is not *possible* to do this without
   going through policy.

   > **Amended by ADR-0034.** This claim was **false** as written. `CapabilityInvocation`
   > also derived `Deserialize`, and a derived `Deserialize` writes private fields
   > without calling any constructor — so it bypassed `PolicySeal`,
   > `AuthorisationProof`, and policy entirely. Phase 3 proved the bypass
   > exploitable before building anything on it. See ADR-0034.
2. **Capability-scoped isolation (S1).** The model runs in a context with **no
   credential handle**, no arbitrary filesystem grant, and network egress
   restricted to configured provider endpoints. A prompt injection cannot make
   the model read a secret, because the model has no way to reach one. This is
   the lesson from Anthropic's own post-mortem: *"any untrusted code that Claude
   generated was run in the same container as credentials — so a prompt injection
   only had to convince Claude to read its own environment."*
3. **Audit before and after.** Authorisation is written *before* the call, the
   outcome *after*. There is no unlogged path.

**Why.** Convention fails. A code review catches "the model called the tool
directly" once; a type system catches it always. The distinction matters because
the failure mode is a prompt injection that works on the day nobody is reviewing.

**Trade-offs.** Some legitimate model-driven actions need more ceremony than a
prompt would suggest. The `Proposal` type is deliberately not ergonomic to build
by hand. Capability scoping means the model cannot read a file to decide — the
task engine must fetch and pass content. That is more code, and it is correct.

**Consequences.** A test asserts the intent-layer context cannot resolve a
secret. Model output is schema-validated before any use. Every task is
resumable at every deterministic stage because each is a transaction.

**Rejected alternatives.** **Convention and lint rules** — insufficient for a
security boundary. **A "safe mode" flag** — off-by-default security fails open in
practice. **Trusting the model's self-assessment of risk** — the brief's explicit
prohibition, and obviously wrong.

**Revisit conditions.** None. This decision does not get revisited; it gets
enforced. If a future design *requires* violating it, that design is wrong.

---

<a id="adr-0013"></a>
## ADR-0013 — Memory: derived vs authoritative, with an enforced distinction

**Context.** The brief: *"Do not define 'memory' as simply a vector database"*
and *"Never blindly trust AI-generated memory as authoritative fact."*

**Problem.** Design the memory model.

**Options.** One `memories` table · a vector store · a knowledge graph ·
separated classes with enforced provenance.

**Decision.** **Separate the classes in the schema, not in documentation.**

| Class | Consistency | Authority | Examples |
|---|---|---|---|
| Authoritative state | **Strong** | Yes | Tasks, schedules, user profile, explicit user statements, corrections |
| User preferences | Strong | Yes | Declared preferences, confirmed corrections |
| Task state | Strong | Yes | Task rows, checkpoints, audit |
| Conversation history | Append-only | No | Event log |
| Documents | Strong (metadata), lazy (content) | Source is authoritative | Imported files |
| Derived knowledge | Eventual | **Never** | Summaries, extracted entities, inferences |
| Embeddings | Eventual, regenerable | **Never** | Vectors |
| Temporary context | None | **Never** | In-flight context |
| Audit history | Append-only, hash-chained | Yes | Journal |

**Enforcement, not documentation:**

1. Every memory row carries `provenance` (`user` | `model` | `imported` |
   `derived`), `confidence`, `created_at`, and a **`derived` boolean**.
2. **A `derived` row can never satisfy an authority check.** This is a query
   filter in the repository layer, not a UI convention.
3. **User corrections are authoritative and supersede.** A correction to a derived
   fact marks the derived item stale and creates an authoritative replacement.
4. **Every derived item is visible, editable, and deletable**, and a deletion
   **propagates** to items derived from it.
5. Derived data inherits the **highest data class** of its sources (ADR
   `04-…` §6).
6. Confidence scores from models are **displayed, never enforced**. A 0.99
   confidence is not authorisation.

**Why.** "Memory" as one concept is how AI systems end up treating a model's
guess as a fact. The only reliable fix is a schema-level distinction plus a
repository query that makes the wrong thing impossible to retrieve.

**Trade-offs.** More tables, more code, more joins. Deletion propagation is
non-trivial (a DAG, so it needs cycle detection and a bounded traversal).
Eventual consistency for derived data means a stale derived item may briefly
contradict a corrected authoritative one — accepted, and surfaced in the UI.

**Consequences.** "What does OpenRayNux know about me?" becomes a queryable,
deletable, exportable answer — which the brief's privacy requirements effectively
demand. NR-09 is satisfied structurally.

**Rejected alternatives.** **A single `memories` table** — the failure mode this
decision exists to prevent. **A vector store as memory** — ADR-0008. **A graph
database** — no requirement drives it.

**Revisit conditions.** Revisit derived-data storage (a graph, a dedicated
engine) if measured query patterns outgrow SQLite. Revisit the authority filter
only if a use case genuinely needs model output to be authoritative — which would
mean the user explicitly confirming it, at which point it is no longer derived.

---

<a id="adr-0014"></a>
## ADR-0014 — Voice: abstraction first; `sherpa-onnx` default; eSpeak-NG floor

**Context.** The brief: *"Do not select one ASR system yet. Design the
abstraction first."*

**Problem.** Choose an ASR/TTS architecture without premature commitment.

**Options.** faster-whisper · whisper.cpp · NVIDIA NeMo · sherpa-onnx · cloud ASR.
For TTS: Piper · Coqui/XTTS · Kokoro · eSpeak-NG · cloud.

**Evidence (all verified 2026-09-30).**

| Engine | Status | Licence | Rust | Streaming |
|---|---|---|---|---|
| **`sherpa-onnx` 1.13.8** (2026-09-11) | Active, releases every 1–3 wk | **Apache-2.0** | **First-party, in-tree** | **Real** (`OnlineRecognizer`) |
| `parakeet-rs` 0.3.8 (2026-09-23) | Very active | MIT/Apache-2.0 | Community (via `ort` **RC**) | Chunked |
| `whisper.cpp` 1.9.4 + `whisper-rs` 0.16.0 | 54 k★, active | MIT / Unlicense | **Repo archived → Codeberg**; 758 k dl, 6.5 mo stale | Rolling window re-transcription |
| faster-whisper 1.2.1 (2025-10-31) | **No release in ~11 months** | MIT | `ct2rs` 0.10.1 (low adoption) | **Batch only** |
| NVIDIA NeMo (`NVIDIA-NeMo/Speech` v3.0.0) | Active | Apache-2.0 (code) | **None** (Python) | Chunked |

| TTS | Status | Licence |
|---|---|---|
| **Kokoro-82M** via sherpa-onnx | 82 M params, 8 langs/54 voices, ONNX 82–310 MB | **Apache-2.0** — cleanest in the landscape |
| Piper (`OHF-Voice/piper1-gpl` 1.8.0) | Active | **GPL-3.0** (was MIT) + GPL espeak-ng; some voices research-only |
| Coqui TTS 0.22.0 (2023-12-12) | **2 years stale**, Python `<3.12` | **CPML — non-commercial including outputs, viral derivative clause** |
| **eSpeak-NG** | Ancient, reliable | GPL-3.0 · **~0.001 RTF, ~15 MB RAM** |

Model licences: `parakeet-tdt-0.6b-v3` **CC-BY-4.0** (commercially usable);
**`canary-1b` is CC-BY-NC-4.0 — non-commercial**; `moonshine-tiny` MIT at
**34 MB / ~306 MB RAM**. Wake words: **Porcupine's free tier ended 2026-06-30**;
**openWakeWord weights are CC-BY-NC-SA (non-commercial)**.

**Decision.**
1. **The abstraction comes first**: `SpeechToText` and `TextToSpeech` traits with
   a `VoiceSession` supporting streaming, partials, VAD-driven segmentation,
   barge-in, and cancellation.
2. **Default local ASR: `sherpa-onnx`** — the only complete, first-party,
   actively-released Rust speech stack, Apache-2.0, with real streaming.
3. **Optional engines** behind the same trait: `parakeet-rs` (best WER/RAM) and
   `whisper.cpp` (widest acceleration). **Cloud ASR** for users who prefer it.
4. **Default local TTS: Kokoro via sherpa-onnx.** **eSpeak-NG always available as
   the floor** — GPL-3.0, so it runs as a **subprocess** (ADR-0009), and it never
   fails.
5. **Piper only as a subprocess**, never linked (GPL-3.0). **Coqui never.**
6. **No third-party wake-word engine.** Use always-on VAD plus sherpa-onnx's
   `KeywordSpotter`. This avoids the licence traps entirely and is where both
   Deepgram's Flux and LiveKit converged (turn detection, not keyword spotting).
7. **Models are lazily loaded and unloaded** to protect the idle budget
   (`05-…` §6).
8. **Local/cloud is a user choice**, per capability, with the privacy and cost
   trade-off stated in the UI.

**Why.** `sherpa-onnx` is the only option that is first-party, Apache-2.0,
actively released, and complete. The abstraction first is what makes the user's
requirement — *"change ASR implementation without changing the rest of
OpenRayNux"* — true.

**Trade-offs.** sherpa-onnx is a heavy native build and downloads a prebuilt
library at build time (must be pinned and checksummed, `08-…` §18). The model zoo
is Mandarin-first. `parakeet-rs` depends on `ort`, which **has never released 2.0
stable** (last stable 1.16.3, 2023-11-12) — an accepted, recorded risk.
`whisper-rs`'s archived repo makes it a vendoring candidate. Cloud ASR leaks
audio off-device — a real privacy cost that the UI must state.

**Consequences.** Voice is a feature-gated capability with a real resource
profile, disclosed before enabling. Copyleft stays out of the core binary.
Model licences are tracked in a registry (`02-…` §4).

**Rejected alternatives.** **faster-whisper** — batch only, so unusable for live
voice; and no release in 11 months. **NeMo** — no Rust bindings at all.
**whisper.cpp as default** — more battle-tested, but its "streaming" is
re-transcribing a rolling window (its own README calls it "a naive example"),
and the Rust binding is single-maintainer with an archived repo. **Piper
linked** — GPL-3.0. **Coqui/XTTS** — non-commercial, viral, and 2 years stale.

**Revisit conditions.** Revisit the default if `parakeet-rs` drops its `ort` RC
dependency, or if sherpa-onnx's release cadence breaks. Revisit TTS if a
permissively-licensed model clearly beats Kokoro on quality. **Re-evaluate
`ort` at 2.0 GA.** Vendor `whisper-rs` if we adopt it.

---

<a id="adr-0015"></a>
## ADR-0015 — Browser automation: HTTP-first, browser opt-in, accessibility-tree grounding

**Context.** The long-term vision is reducing manual navigation. This is also
the highest-risk capability (TH-07, TH-08).

**Problem.** Choose the browser architecture and the element-grounding method.

**Options.** Playwright (JS/Python) · `playwright-rs` · CDP via `chromiumoxide` ·
WebDriver BiDi · plain HTTP · visual grounding.

**Evidence.**

- **WebDriver BiDi** is a **W3C Working Draft (2026-09-30)** — *not* a
  Recommendation. Measured BiDi WPT pass rates: Firefox 99.8 %, Edge 99.0 %,
  Chrome 97.6 %, **Safari has no coverage at all**. Chrome implements BiDi as a
  **JavaScript mapper translating BiDi→CDP** in a hidden tab, so on Chrome it
  cannot exceed CDP. Playwright's own blocker list (`microsoft/playwright#32577`)
  records **no request/response body access**, no UA/timezone/locale emulation, no
  download bodies; Playwright-suite pass on BiDi: Chrome 61 %, Firefox 38 %.
- **CDP is not deprecated** — Chromium's own answer to "will BiDi replace CDP?" is
  *"No."* But **Chrome 136+ ignores `--remote-debugging-port` against the default
  data directory** (motivated by cookie theft), and Chromium documents clients as
  trusted: *"Protocol clients are typically considered trusted, as they can
  navigate to arbitrary origins and have access to all origin data. … These
  restrictions are not extended to other types of clients."*
- **`playwright-rs` 0.19.0** (2026-09-26) is the live crate — **the crate named
  `playwright` on crates.io is a dead 2022 fork**. It is community-only;
  Microsoft has said on the record that a Rust binding is out of scope
  (`microsoft/playwright#18266`). It ships a bundled **Node ~130 MB** and is
  pre-1.0, single-maintainer.
- **Grounding accuracy is the decisive number.** ScreenSpot-Pro (professional
  desktop UIs) — the original paper reports **18.9 %** for existing models; best
  current reported ≈ **61.6 %**. Consumer web (ScreenSpot-V2) ≈ 94 %. End-to-end
  GUI agents still fail **more than half** of real tasks (OSWorld 47.5 %).
- **Production proof of a better approach:** `@playwright/mcp` 0.0.83
  (2026-09-28) is *snapshot-based on the accessibility tree* — *"far cheaper than
  DOM dumps or screenshots"*, *"no vision models required"*.
- **HTTP-first evidence:** ~4× faster, ~8× less RAM, higher success rate in the
  one measured comparison available, and cleaner failure modes. *(The specific
  numbers come from a single low-authority source and are therefore **not** used
  as the argument; the structural arguments — no layout, no paint, no JS
  execution, no process spawn — stand on their own.)*

**Decision.**
1. **HTTP-first is the default tier.** Try `reqwest` 0.13.5; escalate to a
   browser **only on evidence** (a WAF challenge, data present only after JS, or
   the task requires interaction). Record which tier satisfied each request.
2. **The browser tier is an opt-in capability**, not a core dependency — it costs
   ~530 MB and must not be paid by users who never enable it (CR-2).
3. **A dedicated, non-default browser profile.** Never the user's daily browser.
   This is now a technical necessity (Chrome 136+), not just hygiene.
4. **Grounding is accessibility-tree-first** — `getByRole`/accessible name,
   with stable element refs — and **visual grounding is a fallback only**, never
   primary. The numbers above make this non-negotiable: a 61.6 % click accuracy
   on a payment form is unacceptable.
5. **All consequential actions are gated** with a preview (screenshot +
   highlighted element + exact normalised parameters) and a **digest-bound,
   re-verified** approval (S6, S12) — the Loopjacking mitigation.
6. **Idempotency keys on every form submission** (S7, NR-05), and page-change
   detection between preview and click.
7. **No stealth or anti-bot evasion.** Signing requests via Web Bot Auth where a
   site accepts it is fine; spoofing is not.

**Why.** HTTP-first is faster, lighter, more deterministic, and fails cleanly.
The browser is the escalation path, not the default. Accessibility-tree grounding
is both more accurate *and* dramatically cheaper than pixels — the decisive point,
since a 1-in-3 grounding failure rate would make the capability unsafe.
Visual grounding is retained only for canvas and custom widgets where there is no
DOM/ARIA at all.

**Trade-offs.** HTTP-first cannot handle JS-rendered sites, so escalation is
common on modern sites. The browser tier's 530 MB and Node dependency are real
costs. `playwright-rs` is pre-1.0 and single-maintainer — a supply-chain risk
(TH-17) requiring vendoring or a contingency. Accessibility-tree grounding fails
on sites with bad ARIA, requiring a `data-testid`-style injection fallback. Bot
detection is an arms race we do not join.

**Consequences.** Automation is a *capability* with a manifest, not a library
call. The browser process is killable and revocable in one action. Every
consequential action produces a reviewable artifact. A dedicated profile is
encrypted at rest, never synced, never committed.

**Rejected alternatives.** **Playwright JS/Python** — wrong language for a
Rust-first core, and would mean embedding an interpreter. **CDP directly**
(`chromiumoxide`) — a real fallback, Chromium-only, and it is what
`playwright-rs` uses anyway. **WebDriver BiDi** — a Working Draft with the gaps
above; correct to defer. **Visual grounding as primary** — 61.6 % is not safe.

**Revisit conditions.** Revisit BiDi when it reaches Recommendation status and
Playwright's own blockers are resolved. Revisit the browser driver if
`playwright-rs` reaches 1.0 or if `rustenium` matures. Re-evaluate grounding if
professional-UI grounding accuracy exceeds ~95 %. Reconsider HTTP-first default if
measured escalation rates are so high the browser is always used anyway.

---

<a id="adr-0016"></a>
## ADR-0016 — Messaging: narrow common denominator; defer WhatsApp; refuse Signal and userbots

**Context.** The brief requires messaging connectivity but warns: *"Do not
assume every service offers equivalent automation capabilities."*

**Problem.** Decide which platforms, and how to model their differences honestly.

**Options.** Implement all platforms · implement only officially-sanctioned
ones · build one lowest-common-denominator interface · per-platform interfaces.

**Evidence.** Full detail in `01-…` §5. Decisive constraints:

| Platform | Finding |
|---|---|
| **Telegram Bot API** | Official, both directions. **But** ToS §1.5: *"you are prohibited from using, accessing or aggregating data obtained from the Telegram platform to train, fine-tune or otherwise engage in the development, enhancement or deployment of artificial intelligence."* `getUpdates` buffers **24 h** then discards. |
| **Telegram MTProto** | User accounts via Telethon/GramJS/**teleproto**. Telegram: *"all accounts that log in using unofficial Telegram API clients are automatically put under observation."* GramJS **archived 2026-07-14**; Telethon **archived 2026-02-21**, moved to Codeberg. |
| **Discord bot** | Official, excellent (Gateway + resume). `MESSAGE_CONTENT` is a **privileged intent**. **Self-bots categorically forbidden** — *"result in an account termination if found."* We may not even *collect* a user's token. `IDENTIFY` capped at 1000/24 h with **automatic token reset**. |
| **Signal** | **No API exists.** `signal.org/docs/` publishes protocol specs only. `libsignal`: *"Use outside of Signal is unsupported"*, AGPL-3.0. `signal-cli` self-declares: *"signal-cli releases older than three months may not work correctly."* |
| **WhatsApp Cloud API** | Official, best-documented limits — but **24-hour service window** (approved templates only outside it), mandatory human escalation path, and ToS: *"must not use our Business Services for personal, family, or household purposes."* The **3P Agent** platform is the right mechanism — and is **beta and undocumented**. |
| **Matrix** | Full official CS API; the **only** platform where real user-account automation is sanctioned. |
| **Email** | IMAP/SMTP; universal; no push (IDLE or polling). |

**Decision.**
1. **A narrow common denominator interface** — `send`, `receive`,
   `capabilities()`, `health()` — where `ProviderCapabilities` carries
   `can_read_history`, `max_media_bytes`, `supports_reactions`,
   `supports_threads`, `window_seconds`, and the **rate limits as data** so
   backoff is correct.
2. **Per-provider extensions are explicit**, and "this provider cannot do that"
   is a first-class UI state, not an error.
3. **Implement:** Telegram (Bot API only), Discord (bot only), Matrix, Email.
4. **Defer WhatsApp** — the Cloud API is structurally wrong for a personal
   assistant, and the correct mechanism (3P Agents) is beta and undocumented.
5. **Refuse Signal.** No API exists; the tooling imposes a permanent quarterly
   upgrade tax with an unrecoverable-compromise failure mode.
6. **Refuse all user-account automation** (Telegram MTProto, Discord self-bots,
   WhatsApp Baileys) — categorically ToS-violating or surveilled, and a
   permanent-ban risk that would harm the *user's* account.
7. **A written platform-compliance record (S29) is a release gate** for any
   messaging integration.

**Why.** This is the clearest case for the brief's own warning. The platforms
where user-account automation would be most valuable are precisely the ones
where it would get the user's account banned. Shipping a "read and reply to your
own Telegram" feature would risk their account for our convenience. The narrow
denominator is honest: it says what cannot be done rather than pretending
parity.

**Trade-offs.** The assistant cannot read the user's existing conversations on
Telegram or Discord — the Bot API only sees chats the user initiated. That
limits the "message my colleagues" use case significantly. Telegram's AI clause
(§1.5) needs **legal review** before any inference on message content, which is
an open legal question, not a technical one. Matrix's user-account support is
the workaround for the limitation — and a reason it is prioritised.

**Consequences.** A UI that renders capability differences rather than hiding
them. Rate limits handled generically from `ProviderCapabilities`. Each platform
adapter is small and independent.

**Rejected alternatives.** **All platforms** — Signal is impossible and the
userbots are ToS-violating. **Userbots "as opt-in"** — the risk falls on the
user's account, and "ask the user first" is not a mitigation for termination.
**One interface pretending parity** — dishonest and will produce bugs.

**Revisit conditions.** Revisit WhatsApp when the 3P Agent platform is GA **and**
developer-documented. Revisit Signal only if Signal ships an official API.
Re-evaluate Telegram's §1.5 with legal counsel. Revisit userbots only if a
platform formally sanctions them for personal use.

---

<a id="adr-0017"></a>
## ADR-0017 — Updates: no self-updater; snapshot → migrate → verify, with rollback

**Context.** The brief: *"Do not design an auto-updater that can brick the user's
installation."* A personal system with a single database file is one bad
migration away from total loss.

**Problem.** Design the update path.

**Options.** In-app auto-updater (Tauri updater) · package-manager only · a
migrator with mandatory snapshots and rollback · manual.

**Decision.**
1. **No self-updater in v1.** Updates arrive through the OS package manager
   (dnf/deb/PackageKit, **Windows MSI**) or by replacing the binary.
2. **Every migration is preceded by an automatic, verified snapshot.**
3. **Migrations run at startup, before any other work**, in a transaction, and
   are **idempotent** and **reversible** within the version boundary.
4. **A failed migration restores the snapshot and leaves the previous binary
   working.** The previous binary must always be able to start against the
   restored data.
5. **The restore path is tested in CI**, not just written.
6. **Release binaries are signed** (minisign, Authenticode) and reproducible.
7. **Compatibility window:** N and N−1 can both read the data. N+1 requires
   migration. Breaking data-format changes require a major version.

**Why.** The database is the user's data and there is exactly one copy. The
asymmetry is stark: an auto-updater is a convenience; a bricked install with an
unrecoverable database is a catastrophic failure. Deferring the self-updater also
avoids the security exposure of an in-app updater with network write access.

**Trade-offs.** Users must update via the package manager — friction, and on
Windows the MSI path needs Authenticode to avoid SmartSmartScreen friction. The
previous binary must be retained, which is disk. Cross-version compatibility
constrains how fast the schema can move.

**Consequences.** Windows Authenticode procurement starts in **Phase 1** (lead
time). Migration tests run on a copy of a real previous-version database in CI.
`10-…` NR-03 (backup/restore) becomes a Phase 2 deliverable, not a later
polish item.

**Rejected alternatives.** **Tauri updater** — network write access in the app is
a meaningful attack surface, and a failed update is unrecoverable. Revisit only
with signed manifests, a verified rollback, and a staged rollout. **Manual
migration only** — too error-prone for a non-technical user (NFR-13).

**Revisit conditions.** Revisit a self-updater once signatures, staged rollout,
and automated rollback are implemented *and tested* — as an additive convenience,
never as the only path.

---

<a id="adr-0018"></a>
## ADR-0018 — Configuration: 11 layers, schema-versioned, secrets by reference

**Context.** The brief: *"user-focused but not user-locked"* — a second user must
be able to radically customise OpenRayNux without forking it, and
personalisation must be *data*, not source changes.

**Problem.** Design the configuration model.

**Options.** A single TOML file · a database table · environment variables ·
layered files · a remote config service.

**Decision.** **Eleven separately-versioned layers** (`00-…` §7), where layers
1–8 are **configuration** (strictly layered, later overrides earlier, merge
explicit and inspectable) and 9–10 are **data** (memory, workflows) and 11 is
**code** (extensions, a trust decision).

1. Application defaults (immutable at runtime)
2. Schema/version metadata
3. User configuration
4. User profile (identity, locale, timezone, working hours)
5. Domain configuration
6. Provider configuration
7. Capability configuration
8. **Policy** (permissions, approval thresholds, redaction, budget)
9. Memory (data)
10. Workflows (data)
11. Extensions (code — trust boundary)

**Rules.**

- **TOML + JSON Schema** — human-editable, diffable, reviewable, git-friendly.
- **Schema-versioned with forward-compatible migrations**, one-way, tested both
  directions.
- **Secrets are references, never values.** The config names a `keyring` entry
  (`{ kind: "keyring", service: "openraynux", user: "anthropic" }`); the
  `keyring` crate 4.2.0 resolves it.
- **Import/export of layers 3–10 as one portable, versioned document** — this is
  how a second user customises radically, and it is a core feature.
- **Multi-profile from day one**, even though v1 is single-user. Retrofitting
  tenancy is the classic expensive mistake (NR-04).
- **Environment variables** may only *override* a small documented set — never
  carry secrets, never carry structural config.
- **A disabled capability's keys are rejected, not ignored**, so typos surface
  immediately.
- **Every effective configuration is inspectable** — "what is actually in
  effect, and why" is a first-class question, answered by showing the merged
  result with per-key provenance.

**Why.** This is the mechanism that makes NFR-08 ("a second user customises
without forking") structurally true rather than aspirational. A single file
cannot express per-layer provenance; a database cannot be diffed.

**Trade-offs.** Layering complexity and a merge-precedence puzzle. Schema
migrations are a permanent maintenance cost. Supporting multi-profile before it
is needed is speculative — accepted because retrofitting it is far more
expensive.

**Consequences.** A `config` CLI for dump/diff/validate/export/import. A schema
lives in the repo and is the source of truth for validation.

**Rejected alternatives.** **A single file** — no provenance, painful layering.
**A database table** — not diffable, not hand-editable, hostile to support.
**Environment variables for everything** — untestable, unlayerable, and a
credential-leak risk. **A remote config service** — a network dependency in the
local install; violates the core constraint.

**Revisit conditions.** Revisit multi-profile if a cloud multi-tenant mode
becomes real (it will need proper tenant isolation, not just profiles). Revisit
the format if TOML's expressiveness blocks a needed structure.

---

<a id="adr-0019"></a>
## ADR-0019 — Dependency & licence policy: permissive-only in the core binary

**Context.** TH-17 (dependency compromise) and the licence landmines found in
research: Piper → GPL-3.0, Coqui/XTTS → CPML non-commercial + viral,
`canary-1b` → CC-BY-NC, openWakeWord weights → CC-BY-NC-SA, signal-cli → GPL-3.0,
libsignal → AGPL-3.0, Windmill → AGPL-3.0.

**Problem.** Set the dependency and licence policy.

**Decision.**
1. **The core binary links only permissively-licensed code** — MIT, Apache-2.0,
   BSD, ISC, Zlib, Unicode-3.0, or the Unlicense.
2. **Anything GPL/AGPL/NC runs as a separate process** the user installs, or is
   excluded. Enforced by the capability tier rules (ADR-0009).
3. **`cargo deny check`** in CI enforces: advisories, licences, duplicate
   versions, and a curated ban list.
4. **`cargo audit`** blocks the build on a known advisory; triage within 48 h.
5. **Model licences are tracked separately** in a registry with a manual review
   gate — a model file is an artefact with a licence, exactly like a dependency.
6. **New dependencies require an ADR**, a licence check, and a maintenance check
   (last release, bus factor, MSRV). Transitive additions are reviewed.
7. **Minimal `dependabot` breadth.** No auto-merge for anything touching auth,
   crypto, network, or serialisation.
8. **`Cargo.lock` committed; `--locked` in CI. Reproducible release builds with a
   documented, pinned toolchain. SBOM per release. Signed binaries.**
9. **No build-time downloads from unpinned URLs** — including
   `sherpa-onnx`'s prebuilt-library download, which must be mirrored, pinned, and
   checksummed.

**Why.** Licence and supply-chain risk are *design* inputs, not legal
afterthoughts. The GPL/NC landmines above would each have been discovered late
and expensively; making the policy structural means they are caught in review.
Supply-chain integrity is a first-class threat (TH-17) in a product that
downloads and executes third-party models and browser builds.

**Trade-offs.** Slower dependency adoption. The model-licence registry is manual
work. Reproducible builds need a pinned toolchain, which is a maintenance
burden. A ban list needs curating.

**Consequences.** A "copyleft" CI check that fails the build. A model registry
that must be updated with every model. Release signing is a hard requirement, not
a nice-to-have.

**Rejected alternatives.** **Permissive-only for the core but no enforcement** —
the policy would be aspirational. **An allow-all-by-default licence policy** —
would have admitted `openWakeWord` and `canary-1b`. **Vendoring everything** —
unmaintainable.

**Revisit conditions.** Revisit a specific dependency when its licence changes
(watch `sherpa-rs` → archived, `whisper-rs` → archived, Piper → MIT→GPL,
`ort` → still RC). Revisit the ban list quarterly.

---

<a id="adr-0020"></a>
## ADR-0020 — Observability: tracing always, OTLP optional, zero telemetry

**Context.** The brief: *"Do not add a heavyweight observability stack to a
personal local installation"* and *"without requiring a telemetry server."*

**Decision.**
1. **`tracing` + `tracing-subscriber` always.** Structured, hierarchical, cheap,
   and the ecosystem standard.
2. **Redaction at the subscriber layer**, so no call site can leak a secret by
   forgetting (S9, TH-*). This is a structural property, not a discipline.
3. **OpenTelemetry is an optional feature** (`otlp`) — a **native exporter only**,
   no collector, no agent, no daemon.
4. **Zero telemetry. Ever.** No phone-home, no crash upload, no usage analytics, no
   update ping. The network budget is **0 bytes while idle**.
5. **Local diagnostics are a first-class UI**, using `egui` (ADR-0002) — a log
   viewer, a task inspector, a config diff, and a health dashboard.
6. **MCP now standardises `traceparent`/`tracestate`/`baggage` in `_meta`**
   (spec 2026-07-28), so we propagate trace context to MCP servers for free.
7. **A `--diagnostics` bundle** export the user can attach to an issue: config
   (redacted), versions, health checks, and a bounded log window.

**Why.** Privacy and the resource budget both point the same way: no collector,
no daemon, no outbound. Native export keeps the cloud profile genuinely useful
without imposing anything locally.

**Trade-offs.** No centralised correlation for a personal install — a real loss
when debugging something that spans days. Mitigated by the append-only session
event log (which is a product feature anyway, for resumability and memory).

**Consequences.** Logs are the primary debugging tool, so redaction must be
exhaustively tested. The diagnostics bundle is what replaces "send us your logs"
in a privacy-respecting product.

**Rejected alternatives.** **A bundled OTel collector** — a daemon. **Any
telemetry** — a privacy and resource violation, and the brief's prohibition.

**Revisit conditions.** None that would relax the zero-telemetry rule. Revisit
the local UI if a better diagnostic tool appears.

---

<a id="adr-0021"></a>
## ADR-0021 — Scheduling: `croner` + `jiff`, with an explicit misfire policy

**Context.** The brief: *"A scheduled task must not silently disappear because
the application was closed."*

**Problem.** Choose a scheduler and define catch-up semantics.

**Evidence.** The Rust cron ecosystem has largely rotted: `clokwerk` (2022),
`job_scheduler` (2020), `lifeguard` (2020), `sailor` (2019), `rusty-scheduler`
(2021) all abandoned; `tokio-cron-scheduler` has not shipped since 2025-10-28 and
supports **only Postgres/Nats** — no SQLite. `croner` **4.0.0** (2026-08-31) and
`cron` 0.17.0 are healthy. `croner` is the **only** Rust cron with
**documented, Vixie-compatible DST semantics**; `jiff` **0.2.37** (2026-09-12,
73.5 M dl/30 d) has correct DST arithmetic and is a `croner` backend.

`croner`'s documented behaviour:

| Transition | Fixed-time jobs | Interval/wildcard jobs |
|---|---|---|
| Spring forward (gap) | Run at the first valid second after the gap | Occurrences **inside the gap are skipped** |
| Fall back (overlap) | Run **once**, at the first occurrence | Run for **each** occurrence in the duplicated hour |

**Decision.**
1. **`croner` 4.0 + `jiff` 0.2.37.** No scheduler framework.
2. **Schedules are persisted**, and every schedule carries a **`timezone`** and a
   **misfire policy** as data.
3. **Catch-up is explicit** (the ~30-line algorithm): on startup, enumerate
   occurrences in `(last_fired_at, now]`, bounded by `catch_up_cap`, and insert
   into `schedule_fires` with **`UNIQUE(schedule_id, fire_time)`**. The
   `INSERT OR IGNORE` success *is* the deduplication, guaranteed across crashes
   because SQLite serialises writes.
4. **Misfire policies, chosen per schedule and stored explicitly:**
   `FireAll` · `FireOnce` (collapsed, flagged `catch_up`) · `SkipIfOlder(θ)` ·
   `FireNextOnly` · `Pause`.
5. **DST behaviour is documented, not fought.** The `croner` semantics above are
   written into the docs and asserted in property tests.
6. **A scheduled task cannot be created without a spend ceiling** (NR-01).

**Why.** `croner` is the only option with DST semantics anyone has written down,
and DST is exactly where hand-rolled schedulers are wrong. Catch-up is a genuine
product requirement with no crate providing it, and the `UNIQUE(schedule_id,
fire_time)` idiom is the correct, crash-safe way to express it — a "guard with a
unique row per period" pattern.

**Trade-offs.** DST-interval schedules *skip* gap occurrences by design. That is
almost always right, and it is documented rather than silently surprising. We own
the catch-up logic, including the bounded-traversal limit.

**Consequences.** DST correctness becomes a tested property. A schedule is fully
described by data (expr, tz, misfire policy, cap, enabled). A machine being off
for a week does not silently lose jobs.

**Rejected alternatives.** **`clokwerk`/`job_scheduler`/`tokio-cron-scheduler`** —
stale, in-memory, or no SQLite. **A framework scheduler (Temporal, Restate)** —
a server, for a single local process. **UTC-only** (as `fang` does) — a real
usability bug for a personal assistant that thinks in local time.

**Revisit conditions.** Revisit if `croner` is abandoned. Revisit the catch-up
cap if a legitimate use case needs unbounded catch-up (we would then need
per-occurrence idempotency, which is a bigger change).

---

<a id="adr-0022"></a>
## ADR-0022 — Deployment: one codebase, four profiles

**Decision.** **P1 Desktop · P2 Headless · P3 Cloud · P4 Multi-tenant (not
v1).** A profile selects adapters and transports; it does not fork the code.

The same JSON-RPC frames travel over a UDS/named pipe in P1/P2 and over HTTPS in
P3. The daemon binary is identical. SQLite in P1–P3 (single-tenant, one writer);
Postgres only in P4.

**Why.** The brief requires local Linux, Windows, cloud, and headless, and warns
that "cross-platform" does not mean "one binary everywhere." The profile model
makes the differences *configuration* where they can be and *adapter* where they
must be.

**Trade-offs.** P3 needs real auth (OAuth2/OIDC) and TLS, which is a genuine
attack surface — mitigated by it being opt-in and off by default. P4 is explicitly
out of scope and its absence is a scope decision, not an oversight.

**Rejected alternatives.** **Separate binaries per profile** — code drift. **An
HTTP API in v1** — the brief's warning against fashion-for-fashion's-sake.

**Revisit conditions.** P4 when multi-tenancy is a real requirement — which is
exactly when NR-04's data model must be validated.

---

<a id="adr-0023"></a>
## ADR-0023 — Platform: Linux + Windows T-A; ARM64 T-B; macOS T-B

**Decision.**

| Platform | Tier | Rationale |
|---|---|---|
| Linux x86_64 | **T-A** | Dev machine; native deps verified (webkit2gtk 2.54.0, appindicator 12.10.1, librsvg 2.62.3, libxdo, SQLite 3.51.2 + headers) |
| **Windows x86_64** | **T-A** | Explicitly required by the brief. Highest risk: Authenticode, MSVC CI, WebView2, named-pipe semantics, reserved filenames |
| **Linux aarch64** | **T-B** | Where a personal assistant plausibly runs permanently (a Pi in a cupboard). `sherpa-onnx` ships ARM builds. Cheap now, expensive later |
| **macOS** | **T-B** | Reachable via Tauri, but untestable for us now. Promise it and we will fail that promise |
| Windows ARM64 | T-C | DirectML is the only acceleration for some GPUs; ARM64 ONNX is patchy |

**Why not macOS first-class:** the brief names Linux and Windows. First-class
means tested and supported; we cannot test what we cannot run.

**Why ARM64 is worth early investment:** it is a genuinely plausible deployment
target for a small always-on assistant, the ML ecosystem already publishes ARM
builds, and CI for it is cheap *now* and expensive after the codebase hardens.

**Consequences.** Per-OS concerns live in `platform-*` crates, enforced by a CI
grep gate. Windows-specific work starts in Phase 1 (certificate procurement has
lead time). Long paths and reserved-filename sanitisation are Phase 1 items, not
later polish.

**Rejected alternatives.** **macOS as T-A** — untestable. **Linux-only** — the
brief requires Windows. **ARM64 as T-A** — aarch64 CI cost and a much smaller
test matrix for little benefit initially.

**Revisit conditions.** Promote macOS to T-A when we can run and test it.
Promote ARM64 to T-A when a real deployment target exists.

---

<a id="adr-0024"></a>
## ADR-0024 — Reject agent frameworks; own a thin harness

**Context.** The brief: *"Avoid adopting LangChain/LangGraph/CrewAI/etc. merely
because they are AI-related."*

**Problem.** Build the orchestration layer, or adopt one?

**Evidence.** Three independent primary sources converge:

- **Anthropic**, *Building effective agents*: *"the most successful
  implementations **weren't using complex frameworks or specialized
  libraries**"*; frameworks *"create extra layers of abstraction that can obscure
  the underlying prompts and responses, making them harder to debug. They can
  also make it tempting to add complexity when a simpler setup would suffice."*
  Recommended: *"start by using LLM APIs directly."*
- **OpenAI**, *A practical guide to building agents*: *"**maximize a single
  agent's capabilities first** … often a single agent with tools is sufficient."*
- **LangChain's own team**, *Building LangGraph*: *"we … decided that was
  **little to no abstraction at all**. Instead, we focused on control and
  durability."*

And the shape they converged on — Anthropic's *Scaling Managed Agents* (2026-04-08)
— is **Session / Harness / Sandbox**, which maps exactly onto our task table +
thin loop + disposable sandbox. Their opening argument is the one that should
stick: *"**Harnesses encode assumptions that go stale as models improve.**"* — with
a concrete dated example of a harness workaround (context resets for Sonnet 4.5)
becoming dead weight on Opus 4.5.

⚠️ A public benchmark claiming LangGraph +28.2 % / LangChain +17.2 % latency
overhead exists but is **low credibility** (2 commits, single author,
self-published). It is **not** used as evidence here. The argument rests on the
primary sources.

**Decision.**
1. **No agent framework.** No LangChain, LangGraph, CrewAI, AutoGen, PydanticAI,
   Mastra, or Effect.
2. **One agent, a thin loop**, ~10–20 well-documented tools, a max-turns cap, and
   a durable task record around each *run* — not around each reasoning step.
3. **The harness is built around interfaces, not workarounds** — no behaviour
   encoded that depends on a specific model's weaknesses.
4. **The harness is stateless and disposable**; durable state is the append-only
   session event log, outside the harness and outside the context window.
5. **Tools are documented with extreme care** — Anthropic: *"We actually spent
   more time optimizing our tools than the overall prompt."* Absolute paths, clear
   descriptions, and — as they state — *"It is unacceptable to remove or edit
   tests because this could lead to missing or buggy functionality."*
6. **Never provision anything until a step needs it.** Their measured win came
   from lazy sandbox provisioning (p50 TTFT −60 %, p95 −90 %). So: no model
   loaded, no browser started, no subprocess spawned until a step actually needs
   it. Directly serves the resource budget.

**Why.** Three primary sources, including the framework vendor's own team,
conclude that abstraction is the thing to remove. And the architectural
justification is stronger than the framework argument: our orchestration *must*
be deterministic, durable, and policy-governed (ADR-0012), which is precisely
what a general agent framework abstracts away. A framework would put the
security boundary in someone else's code.

**Trade-offs.** We own the loop, the tool-calling edge cases, and provider
quirks. No community-built capability composes with our harness. A growing
harness codebase over time — mitigated by keeping it thin on purpose.

**Consequences.** A small, testable, provider-agnostic harness. A session event
log that is a product feature (resumability, memory, debugging) rather than a
framework internal. Tool design gets the scrutiny it deserves.

**Rejected alternatives.** **LangGraph** — Python, and its own authors conclude
the abstraction is unwanted. **Effect** — TypeScript only; `effect-rs` is a name
squat with 32 lifetime downloads and a 404 repository. **Temporal for local
orchestration** — a server, for a single process.

**Revisit conditions.** Revisit only if we need something a hand-rolled harness
genuinely cannot do and that a Rust-native, policy-respecting library provides
*and* can be adopted without moving the security boundary into it.

---

<a id="adr-0025"></a>
## ADR-0025 — Testing: deterministic gate; AI evaluation on a separate track

**Decision.**
1. **The blocking CI gate is 100 % deterministic.** No live model, no network.
2. **A scripted, replayable provider** implementing `ModelProvider` — the
   mandatory precondition for testing AI-dependent code at all.
3. **AI-dependent behaviour is asserted on invariants, not content**: "the
   proposal only references registered capabilities", "no step exceeds HIGH risk
   without a gate", "the proposal contains no credential path". These hold for
   *all* model outputs.
4. **AI evaluation is a separate, non-blocking track**: a golden dataset,
   distribution metrics, run on a schedule. The headline metric is the
   **false-approval rate** — a system that is appropriately refusing is safe; a
   system confidently wrong about permissions is not.
5. **Property tests** for the security-critical invariants (`08-…` §4.2).
6. **Failure injection** is a first-class suite, with the master property: *no
   failure injection ever produces silent data loss or an unauthorised side
   effect.*
7. **Real SQLite files**, never `:memory:` for durability tests.
8. **`cargo nextest`** for the suite; `cargo deny`, `cargo audit`, `cargo vet`
   as gates.

**Why.** Asserting on model output yields a suite that fails on model updates
and passes on a bad model — the worst of both. Separating the tracks lets the
correctness suite be a hard gate while capability is measured honestly.

**Trade-offs.** Two test systems to maintain. Non-blocking AI tests can rot
silently, mitigated by scheduling and trend comparison. Deterministic CI cannot
detect "the model got worse" — which is exactly what the evaluation track is
for.

**Rejected alternatives.** **Asserting exact model output** — brittle and
meaningless. **Only deterministic tests** — would leave the probabilistic layer
completely unmeasured. **Live-model CI** — non-reproducible, slow, expensive.

**Revisit conditions.** Revisit the split if deterministic model testing
(deterministic decoding) becomes available for hosted providers.

---

<a id="adr-0026"></a>
## ADR-0026 — Windows as the second first-class platform, prepared early

**Context.** The brief requires Windows. Windows-specific work has long lead
times that are easy to defer and expensive to discover late.

**Problem.** Decide *when* Windows work starts, not whether.

**Decision.** **Windows-specific work starts in Phase 1, not Phase 9.** Phase 1
deliverables: MSVC toolchain in CI; long-path manifests; reserved-filename
sanitisation for all derived filenames; the named-pipe transport; a real
`platform-secrets` DPAPI test. **Authenticode certificate procurement starts in
Phase 1** because it has external lead time.

**Why.** The lead-time argument is the whole point. A certificate, a Windows
runner, and a WebView2 bootstrapper cannot be retrofitted in a week, and
discovering that during a release is how Windows support slips.

**Trade-offs.** Windows CI costs from day one. Some early abstractions are shaped
by Windows constraints (named pipes, reserved names) that Linux developers find
annoying. Accepted: shaping by the *harder* platform early is cheaper than
retrofitting.

**Consequences.** The `platform-*` crate boundary is validated by a real second
platform, not just by discipline. `NUL`, `CON`, `PRN`, `AUX`, `COM1`–`9`,
`LPT1`–`9` are sanitised everywhere a filename is derived from user or web
content. Case-insensitive filesystems are respected: **never derive identity
from a path** — use content hashes or opaque IDs.

**Rejected alternatives.** **"Cross-platform" as a late concern** — the classic
cause of a Windows port that is really a rewrite. **Linux-only CI with a
"should work on Windows" claim** — untested and untrue.

**Revisit conditions.** Revisit the CI breadth if Windows build times dominate
the pipeline; consider a tiered schedule (per-PR vs nightly) for mature crates.

---

<a id="adr-0027"></a>
## ADR-0027 — Identity & Actor as a first-class concept

**Context.** Original architecture listed Intent · Task · Policy · Capability ·
Audit. As the product gains actors, the question of *who* is acting stops being
implicit.

**Problem.** Eventually many things produce actions:

```
Human  ·  AI  ·  System  ·  Integration  ·  Scheduled task  ·  External event
```

Every one of them can trigger a side effect. Without a first-class actor concept,
authority leaks into the capability layer — which is precisely the confused-deputy
pattern (TH-04) we are trying to prevent.

**Options.** Implicit (actor as a field nobody checks) · a `user_id` column ·
a first-class **Actor** value carried on every action · a full identity provider
in v1.

**Decision.** **A first-class `Actor` value, carried explicitly on every action,
and resolved at the policy layer — never by the capability.**

```rust
/// WHO is acting. Not WHAT is acting (that's the capability) and not
/// WHETHER they may (that's policy).
pub enum Actor {
    /// The human owner of this installation. The only actor that can grant
    /// authority. Step-up authentication re-verifies this.
    Human { user_id: UserId, via: AuthChannel },
    /// The model, acting on a human's behalf. NEVER an authority in itself:
    /// it carries the *delegation* of the Human who initiated the run, and
    /// nothing more. An AI actor with no human delegation has no authority at all.
    Ai { delegated_by: UserId, run_id: RunId, model: ModelProvenance },
    /// The daemon itself, for its own housekeeping (housekeeping, backup,
    /// migrations, retention). Narrowest scope: NEVER a network-reachable
    /// identity, and never used for user-visible actions.
    System { component: SystemComponent },
    /// A configured integration acting within a grant made by a Human.
    Integration { capability_id: CapabilityId, granted_by: UserId, grant_id: GrantId },
    /// A scheduled task, resuming within a grant captured at creation time.
    Scheduled { schedule_id: ScheduleId, authorised_by: UserId },
    /// An inbound event from outside (webhook, message, file watch). The
    /// weakest actor: it can REQUEST work, never GRANT it.
    External { source: ExternalSource, verified: bool },
}
```

**Every `CapabilityInvocation` carries an `Actor`.** Policy evaluates
`(actor, capability, params, data_classes, task_context)`. There is no path to an
adapter that omits it — enforced by the type, as in ADR-0012.

**The four questions this makes answerable**, and which the audit log must answer
for every single action:

1. **Who requested this action?** → `actor`
2. **On whose authority?** → `actor`'s delegation chain
   (`Ai { delegated_by }`, `Integration { granted_by }`, `Scheduled { authorised_by }`)
3. **Under which policy?** → the policy version + decision recorded at call time
4. **Using which credentials?** → the resolved `secret_ref` and *whose* it is
   (never a raw secret; the audit records the reference, never the value)
5. **As part of which task?** → `task_id` + `step_key`

**Non-negotiable rules:**

- **`External` can never grant.** It may request; a `Human` must authorise.
- **An `Ai` actor's authority is exactly its delegating `Human`'s authority,
  intersected with the current task's policy.** It is never additive. An AI actor
  cannot exceed what the human could do directly.
- **`System` is not network-reachable** and is never used for user-visible actions.
- **Delegation is explicit and expiring.** A `Grant` carries a scope, an expiry,
  and a revocation path. No ambient, unbounded delegation.
- **Actor identity is in the audit record before the call**, not reconstructed
  afterwards.

**Trade-offs.** A type to thread through every call site — friction, and a
reviewer-visible cost. Actor resolution adds a lookup to the policy path
(cached; target < 1 ms, `05-…` §2.3). A full identity provider in v1 would be
premature; v1 has exactly one `Human` and it is the local user.

**Consequences.** Audit records become genuinely reconstructive rather than
best-effort. The approval digest (S6) now includes the actor, so an approval
granted to one actor cannot be used by another. DM interfaces become first-class
citizens rather than a special case, because a message *is* an `External` actor
request. Retries and resumption must re-derive the actor and re-check delegation
expiry — never inherit a stale actor.

> **Phase 3 amendment — single-use was claimed and not enforced.**
>
> This section said approvals are *"single-use"*, and until Phase 3 **nothing
> implemented it**. The digest check answered *"is this the approved operation?"* and
> nothing answered *"has this approval already been used?"* A record is a value, and
> a value can be presented twice.
>
> Found by a bypass test rather than by reading the code, which is the argument for
> writing those tests even where the code looks right. `PolicyEngine` now holds a
> `consumed_approvals` set, and `authorise` burns the digest as part of permitting a
> gated action (`DenialReason::ApprovalAlreadyUsed`). It lives in `authorise` rather
> than in the dispatcher so that every path that permits a gated action burns it.
>
> The first version of the unit test called `consume_approval` directly — and therefore
> **passed with the consumption line deleted**, proving only that the setter worked.
> It now drives `authorise`. Verified with teeth: deleting the one-line insert turns
> three tests red across two files.

**Rejected alternatives.** **Implicit actor** — the confused-deputy failure by
omission. **A `user_id` column** — answers "which user", not "who requested,
on whose authority, under which policy"; it cannot express `Ai` vs `System` vs
`External`, which is exactly the distinction that matters. **A full IdP in v1** —
premature for a single-user local install; the seam is `AuthChannel` so it can be
added without touching the actor model.

**Revisit conditions.** Revisit when P4 multi-tenancy becomes real, or when a
second human user exists — at which point `Human` gains real identity
resolution and `AuthChannel` grows. Revisit if a "delegated authority" concept
(e.g. an agent acting *for another agent* under a chain) proves necessary.

**Amended by [ADR-0051](#adr-0051).** This record decided *what an `Actor` means*
and was right about it. It left one thing unsaid, and the omission turned out to be
load-bearing: it never said **who decides that a given caller may become which
`Actor`**. As implemented, every handler built `local_actor()` — a function taking
no arguments — so any peer that reached a request received `Human { user: "local" }`
and could approve anything. The actor model was correct and the *boundary* that was
supposed to produce those actors was absent, which meant the daemon asserted a human
rather than having established one. ADR-0051 adds that boundary. The decision below
stands unchanged.

---

<a id="adr-0028"></a>
## ADR-0028 — State as a first-class concept

**Context.** Original architecture had Task as the durability mechanism but no
explicit answer to "what is the system's authoritative state, and who may read
and write it."

**Problem.** As state accumulates (tasks, schedules, memory, documents, config,
audit, policy, credentials, capability health, budgets), the absence of a
first-class state concept guarantees scattered, inconsistent persistence
decisions — and inconsistent consistency requirements.

**Options.** Scatter persistence across modules · a state store abstraction over
SQLite · **a first-class `State` concept with explicitly classified regions**.

**Decision.** **State is a first-class architectural concept with explicitly
classified regions.** Every piece of state is declared, and its class determines
its consistency, retention, authority, and who may read it.

| Region | Class | Consistency | Authority | Retention | Written by |
|---|---|---|---|---|---|
| **Tasks** (rows, leases, checkpoints) | `critical` | **Strong, synchronous, fsync'd** | Yes | Indefinite | Task engine only |
| **Schedules + fire ledger** | `critical` | **Strong** | Yes | Indefinite | Task engine only |
| **Audit journal** | `critical` | **Append-only, hash-chained** | Yes | Configurable, rotated | Policy (pre-call **and** post-call) |
| **User profile** | `authoritative` | Strong | Yes | Indefinite | Config/Human |
| **User configuration** | `authoritative` | Strong | Yes | Indefinite | Config/Human |
| **Policy** | `authoritative` | Strong, version-stamped | Yes | Indefinite | Human only (L5) |
| **Capability health** | `authoritative` | Eventual | Yes | Rolling | Health checks |
| **Budget ledger** | `authoritative` | **Strong** — money must not drift | Yes | Indefinite | Policy only |
| **Dedupe / idempotency ledger** | `critical` | Strong | Yes | ≥ retry horizon | Task engine |
| **Documents** | `authoritative` (source) | Strong metadata, lazy content | Source is | Per policy | Import/Human |
| **Preferences** | `derived-authoritative` | Strong | Yes, if user-set | Indefinite | Human |
| **Summaries, extracted entities, inferences** | `derived` | **Eventual** | **Never** | Regenerable | Intent layer |
| **Embeddings** | `derived` | Eventual, regenerable | **Never** | Regenerable | Retrieval |
| **Conversation/event log** | `append-only` | Append-only | No (history) | Configurable | Every layer |
| **Credentials** | `critical` | **Never in this store** | — | — | `keyring` only, by reference |
| **Transient context** | `ephemeral` | None | **Never** | Session | Intent layer |

**Non-negotiable invariants:**

1. **`critical` state is written with `synchronous=FULL`** (ADR-0006). Losing a
   task row is a lost action; losing a summary is not.
2. **Only the owning layer writes a region.** A region has exactly one writer.
   Two writers to `critical` state would be a second source of truth.
3. **`derived` state can never satisfy an authority check** — enforced by a
   repository query, not a convention (ADR-0013).
4. **Credentials are never state.** They are `secret_ref` pointers into the
   OS keyring. No credential value is ever written to this store, ever.
5. **State is versioned and migratable** (ADR-0017), and a migration is preceded
   by a verified snapshot.
6. **Every state transition is observable** — via the audit journal or the event
   log, never by inspecting a table after the fact.
7. **Retention is per-region and explicit.** Nothing is deleted by a background
   janitor without a declared policy, and deletions are audited.

**Trade-offs.** Classification is a real design burden and is easy to get wrong —
over-classifying as `critical` means paying fsync on non-critical writes;
under-classifying risks silent data loss. The budget ledger is a good example of
why this matters: it looks like a counter, but it is *money*, so it is
`authoritative` with strong consistency, not `derived` with eventual
consistency. A central registry of regions also means a schema change touches a
documented list rather than "whatever a module happens to own".

**Consequences.** A `StateRegistry` in code declaring region, class, owner,
retention, and consistency — the single place to look for "what is authoritative
here?". This is the artefact that makes the answer to *"which state may the
model write?"* unambiguous and mechanically checkable. Backup and export become
region-driven: `critical` + `authoritative` are backed up; `derived` is
regenerable and can be excluded (which also makes backups small).

**Rejected alternatives.** **Scatter persistence** — guarantees inconsistency.
**A single "state" abstraction hiding everything** — loses the per-region
classification that is the entire point, and makes retention undiscussable.
**Redis / an external state store** — a daemon, and `lifeguard`-style crates
requiring Redis are already noted as stale.

**Revisit conditions.** Revisit the classification when a new region is added
(it must be classified before it exists). Revisit `critical` consistency if
`synchronous=FULL` proves unaffordable on baseline hardware (Q-OPEN-17) — the
answer would be to demote the *cheapest-to-lose* region, never to weaken the
task table.

---

<a id="adr-0029"></a>
## ADR-0029 — Task-engine correctness properties are normative; the implementation is not

**Context.** ADR-0007 chose a hand-rolled durable task engine on SQLite and named
it the single largest self-owned risk. "Reasonable for a personal daemon" is not
a specification.

**Problem.** Define what "correct" means for the task engine **independently of
whether it is hand-rolled, `apalis`, or something else** — so that the
implementation can be swapped without renegotiating the contract, and so that
"it works on my machine" is never the acceptance criterion.

**Options.** Specify the implementation · specify the behaviour informally ·
**specify normative properties that any conforming implementation must satisfy**.

**Decision.** **The following properties are normative.** They are stated
implementation-independently, are enforced as tests, and any conforming engine
must satisfy them. The engine chosen in ADR-0007 is one implementation, not the
specification.

| ID | Normative property |
|----|--------------------|
| **TP-1** | **No task silently disappears.** Every task accepted for execution reaches a terminal state (`completed` · `failed` · `cancelled` · `dead_lettered`) or a non-terminal state that is provably still owned. A task must never become unobservable — not by a crash, not by a lease bug, not by a scheduler miss. |
| **TP-2** | **Exactly-once where required, at-least-once otherwise — and the requirement is explicit per task kind.** A task declared `idempotent: false` with an external side effect is **never** automatically re-executed after an uncertain outcome; it transitions to `needs_verification` and requires human adjudication (Q-OPEN-18). |
| **TP-3** | **Cancellation is observable.** A cancellation request is durably recorded *before* it is acted upon; the task reaches a terminal `cancelled` state; the effect survives restart; and cancellation latency is bounded per capability (declared `timeout_ms`). A task cannot "half cancel". |
| **TP-4** | **Restart recovers durable work.** After an unclean shutdown, every task in a non-terminal state is either recovered (lease valid) or returned to the queue / flagged for verification (lease expired). No task is left in `running` with a dead owner. |
| **TP-5** | **Expired leases cannot execute.** A worker whose lease has expired must not be able to complete or commit work, even if it is still alive and believes it holds the task. Fencing: the claim is re-validated at commit time, not only at acquire time. |
| **TP-6** | **Retries never inherit approvals.** A retry, resumption, or lease-expiry recovery re-derives the actor (ADR-0027) and re-runs policy. An approval is single-use, expires, and is bound to a specific action digest — never carried forward. |
| **TP-7** | **Power loss cannot corrupt task state.** After abrupt power loss, the state is either the pre-transaction or post-transaction state, never a torn intermediate. Guaranteed by SQLite WAL + `synchronous=FULL` on the task connection, and verified by kill-at-random-point tests. |
| **TP-8** | **Scheduling is deterministic under time manipulation.** A clock jump forwards, backwards, or across a DST transition does not cause a task to be lost, duplicated, or executed an unbounded number of times. `UNIQUE(schedule_id, fire_time)` makes a fire exactly-once. |
| **TP-9** | **Catch-up is bounded and explicit.** A machine that was off for a week does not silently execute a week of backlog. Catch-up obeys the per-schedule misfire policy and `catch_up_cap`, and any collapsed run is flagged `catch_up: true`. |
| **TP-10** | **Bounded resources.** Every spawn has a concurrency limit. A task that wedges consumes bounded resources and is killed at its deadline. No unbounded fan-out from a workflow. |
| **TP-11** | **Dead-lettering is terminal and visible.** After `max_attempts`, a failing task moves to `dead_lettered` with its last error, is surfaced to the user, and is never silently retried. Retention is declared. |
| **TP-12** | **Every side effect is accounted for.** Every externally-visible effect either has a recorded result or leaves the task in a state that says "outcome unknown". There is no path where an effect occurred and nothing records it. |

**How these are verified** (see `08-testing-engineering-standards.md` §4.5):

- **TP-1, 4, 7** — kill-at-N-random-points harness. Property: *no injection ever
  produces a lost, duplicated, or orphaned task.*
- **TP-2, 12** — injected outcomes per capability contract test.
- **TP-3, 10** — cancellation and resource-bound tests.
- **TP-5** — a "zombie worker" test: force lease expiry, then let the original
  worker try to commit. It must fail.
- **TP-6** — a test that a retry after approval expiry is refused by policy.
- **TP-8, 9** — property tests over DST transitions and clock jumps.
- **TP-11** — a test that a permanently failing task dead-letters and stops.

**Why properties rather than an implementation.** ADR-0007's contingency is to
swap in `apalis`. If the contract were the code, the swap is a rewrite. Because
the contract is these twelve properties, the swap is an implementation change
gated by a conformance suite. This also makes the engine's risk *auditable*: a
reviewer checks conformance, not cleverness.

**Trade-offs.** Twelve properties is a real specification burden, and TP-5
(fencing) in particular is easy to get subtly wrong — it requires re-validating
at commit, not just at claim, and most naive implementations check only at claim.
It also constrains implementation freedom. Accepted: this is the code we own and
the code we will get wrong, and the properties are what make "we will get it
right" a testable claim rather than a hope.

### Phase 2 record (added 2026-09-30)

The suite is no longer hypothetical. A production SQLite engine
(`orxnud_task::DurableEngine`) passes all twelve properties **with the harness
unmodified** (V-32), from a second test binary, against real files with WAL and
`synchronous = FULL`.

Two things the properties turned out to require that the ADR did not state:

* **A `Failed` task must be requeued**, or TP-11 is satisfied by an engine that
  never retries. Amendment A-004.
* **`recover` means *restart*, not *expiry*.** TP-4 is only meaningful if recovery
  reclaims a lease that had not expired, because a restart orphans every lease the
  previous process held. An engine that reclaims only expired leases strands work
  forever.

The properties were **not** weakened to accommodate the implementation. Where the
implementation and the harness disagreed, the harness won and the implementation
changed (amendment A-002 is the worked example).

**Consequences.** The conformance suite is part of the engine's definition of
done. A future engine must pass all twelve. `apalis` adoption (gated by
Q-OPEN-02) must demonstrate TP-7 and TP-5 specifically, since those are where a
generic queue library is least likely to match our semantics.

**Rejected alternatives.** **Specify the implementation** — makes a swap a
rewrite and hides the actual contract. **Informal behaviour description** — what
"reasonable" was in ADR-0007. **Adopt a library and inherit its semantics** —
most libraries target Postgres/Nats durability, and none document
power-loss-with-`synchronous=NORMAL` behaviour for SQLite; we would be
*discovering* rather than *specifying* our own safety properties.

**Revisit conditions.** Revisit the *properties* only if a requirement genuinely
changes (e.g. multi-instance execution would add a distributed-consistency
property set, at which point Temporal/Restate become candidates again). The
*implementation* is revisitable at any time that satisfies these twelve.

---

<a id="adr-0030"></a>
## ADR-0030 — "Disabled" means zero operational cost and zero reachable capability

**Context.** The resource model and the composability requirement both rest on
"disabled capabilities cost nothing". As originally worded, this set an
unachievable expectation: that a disabled feature must contribute *literally
zero bytes* to a binary that may still contain it.

**Problem.** Define what is actually guaranteed, in terms that are both
**measurable** and **achievable**.

**Options.** "Disabled = zero" (unachievable as literally stated) · "disabled
costs as little as practical" (unmeasurable) · **two explicit tiers: a
measurable operational guarantee, plus an opportunistic build-time
elimination**.

**Decision.** The principle is restated as:

> ### Disabled = zero operational cost and zero reachable capability.
> Build-time feature elimination, where practical, additionally removes binary
> and storage cost — but that is an optimisation, never the guarantee.

**Tier 1 — the guarantee. Measured in CI, for every capability:**

A disabled capability:

| # | Property | How measured |
|---|----------|--------------|
| 1 | **Cannot execute** | Contract test: invoking it while disabled is refused by the dispatcher (fails closed) |
| 2 | **Holds no credentials** | No `secret_ref` resolves on its behalf; S1 test covers the invocation path |
| 3 | **Starts no worker** | No process, thread, or supervisor child; asserted by process/thread count |
| 4 | **Consumes no model resources** | No model or ONNX runtime is loaded; asserted by handle/RSS inspection |
| 5 | **Performs no network activity** | No socket opened; verified by a network-namespace or syscall trace in CI |
| 6 | **Adds no meaningful idle CPU/RAM** | RSS and CPU deltas measured against a committed baseline, within a stated threshold |
| 7 | **Has no reachable state** | No tables, no rows, no scheduled jobs, no config keys accepted (a disabled capability's keys are *rejected*, surfacing typos) |
| 8 | **Is unreachable by any interface** | An interface cannot obtain an invocation handle; covered by the protocol test suite |

These eight are **contract-level**, hold regardless of build flags, and are
enforced by tests rather than by binary inspection.

**Tier 2 — the optimisation. Best-effort, measured but not guaranteed:**

| Property | Mechanism |
|----------|-----------|
| No code linked | Cargo feature |
| No binary size delta | `default` vs `all-features` build, size recorded per release |
| No install/storage delta | Excluded from the bundle manifest |
| No startup-time delta | Measured across the feature matrix |

Tier 2 is recorded and regression-tracked so drift is *visible in review*, but a
dependency that links code regardless of features can violate it without being a
correctness failure.

**Why two tiers.** Collapsing them produced a promise that cannot be kept
honestly: with a configurable binary, "zero bytes" is achievable only for
capabilities behind a Cargo feature, and even then a transitive dependency may
defeat it. Making that the headline would either (a) set an expectation we will
break, or (b) be quietly weakened to "we tried". Two tiers let us state a hard
guarantee about **behaviour and reachability** — the part that is both
security-relevant and fully within our control — while treating **bytes** as an
optimisation we measure and improve.

The security framing is the important part. "Cannot execute, holds no
credentials, starts no worker, performs no network activity" is exactly the set
of properties that determines the blast radius of a bug in a disabled subsystem.
Binary size is a resource concern; *reachability* is a security concern. They
should not share a single, weaker, unactionable sentence.

**Trade-offs.** Tier 2 being non-normative means a regression in binary size is
not a build failure by default (it is a review signal). Accepted: failing builds
on third-party linking behaviour would produce alert fatigue, and the security
properties are the ones that must never regress silently.

**Consequences.** CR-2 is restated in these terms (`00-…` §2.2). The feature
matrix CI job asserts Tier 1 (contract tests) and records Tier 2 (deltas). A
capability that cannot satisfy all eight Tier-1 properties cannot be shipped
disabled, which is a useful forcing function on capability design.

**Rejected alternatives.** **"Disabled = zero"** — unactionable, and conflates a
security property with a resource optimisation. **"Costs as little as practical"**
— no threshold, so nothing is ever a failure. **A single blended promise** —
either too strong to keep or too vague to test.

**Revisit conditions.** Promote Tier 2 to normative if the feature matrix ever
reaches 100 % compliance across all capabilities and the baseline is stable.
Re-split if a capability is found where a linked transitive dependency grants
*reachability* rather than merely bytes — that would be a Tier 1 failure and must
be treated as a security bug.

---

<a id="adr-0031"></a>
## ADR-0031 — Node toolchain: OpenRayNux-local Node 24.21.0 LTS

> **Accepted 2026-09-30.** Resolves **Q-OPEN-03**, the environment conflict
> deferred from the preparation phase.

**Context.** The workstation's `node` resolves to **v26.7.0** — the Node *Current*
line, `lts=false` — because `~/.local/bin/node` is a symlink into the Hermes
agent's private runtime and shadows Fedora's `nodejs24-24.18.0` at `/usr/bin/node`.
Node **24.21.0 (LTS codename "Krypton", released 2026-09-07)** is the current LTS
line. The frontend build needs LTS, and the deferral is now blocking.

**Problem.** Establish an OpenRayNux-local Node 24.21.0 **without** changing the
global shell environment and **without** disturbing Hermes' Node 26.

**Options.** Change the default `node` (fnm on `PATH`) · run everything on Node 26
· ignore it and hope · **a project-local pinned runtime, global state untouched**.

**Evidence.**

| Item | Value | Source |
|---|---|---|
| Node 24.21.0 | `lts = "Krypton"`, dated 2026-09-07 | `https://nodejs.org/dist/index.json` |
| Node 26.x | `lts = false` on every release | same |
| Official tarball SHA-256 | `fd8e59d5…f56cb2d6  node-v24.21.0-linux-x64.tar.xz` | `https://nodejs.org/dist/v24.21.0/SHASUMS256.txt` |
| Verified | checksum confirmed `OK`; `node --version` → `v24.21.0`; `npm` 11.19.0 | local, 2026-09-30 |
| pnpm | 12.8.1 works against it | local |

**Decision.**

1. **A project-local Node 24.21.0 runtime** at
   `.toolchains/node-v24.21.0-linux-x64/`, provisioned from the **official
   nodejs.org tarball** and **checksum-verified** against the published
   `SHASUMS256.txt`.
2. **`.toolchains/` is gitignored** — the *declaration* is committed, the bytes
   are not. A committed `.node-version` (`24.21.0`) states the requirement and is
   consumable by any future version manager (fnm, nvm, volta, asdf, mise).
3. **The global environment is not modified.** Specifically *not* touched: `PATH`,
   `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.local/bin`, and the Hermes
   symlink `~/.local/bin/node`. **Verified after provisioning**: `node` still
   resolves to v26.7.0, and the `PATH` hash is byte-identical to its pre-task
   value.
4. **Hermes' Node 26 is untouched** and remains the default for every other tool
   on this machine. We do not, and will not, repurpose another application's
   runtime.
5. **Frontend build invocations use an explicit, non-exported path prefix**, never
   a shell-init modification. Documented per-command in the Phase 1 contract.
6. **Register as V-05** in `12-verification-register.md`: re-verify when Krypton
   leaves maintenance or a new LTS codename appears.

**Why.** The user's requirement — *"keep Hermes' Node 26 untouched and establish
OpenRayNux-local Node 24.21.0 LTS rather than changing the global shell
environment"* — is also the architecturally correct answer for three reasons:

1. **It is additive and reversible.** Deleting `.toolchains/` fully reverts it. No
   other tool on the machine can regress.
2. **It is reproducible and verifiable.** Checksummed from the official release;
   anyone can re-derive the exact runtime from `.node-version` plus the recorded
   hash.
3. **It sidesteps the whole class of "who owns `node`" conflict** that the global
   approach would have to resolve — a conflict between two applications with
   legitimate, incompatible needs. Localising the runtime removes the contention
   instead of adjudicating it.

**Trade-offs.** ~204 MiB on disk (duplicated across projects that need it). A
developer must remember the path prefix, or use a `.node-version`-aware manager
later. The runtime must be re-provisioned per machine (it is gitignored by
design — committing 200 MiB of Node would be worse than the duplication).

**Consequences.** A documented, one-line way to build the frontend on the correct
runtime, with no global state changed. No dependency on a version manager being
installed later. If a version manager is ever adopted, `.node-version` is already
in place and nothing needs to change.

**Rejected alternatives.** **fnm on `PATH`** — changes global shell behaviour and
would make Node 24 the default for *every* tool, including Hermes and the
globally-installed npm CLIs (`claude`, `cline`, `ocr`, `mimo`). That is a
cross-application change made for one application's benefit. **Run on Node 26** —
26 is `lts=false`; building a long-lived product on a Current line means a
forced, un-timed migration later. **Change `~/.local/bin/node`** — actively
destructive to another application.

**Revisit conditions.** Revisit when Krypton leaves maintenance (V-05), or when
a version manager is adopted for developer ergonomics — at which point
`.node-version` is already the input it needs, and `.toolchains/` can be retired.

---

<a id="adr-0032"></a>
## ADR-0032 — `apalis-sqlite` rejected: `synchronous = OFF` fails TP-7

> **Accepted 2026-09-30.** Resolves **Q-OPEN-02**, and **closes ADR-0007's
> contingency**.

**Context.** ADR-0007 chose a hand-rolled durable task engine and named
`apalis` + `apalis-sqlite` as the contingency if it outgrew ~600 lines. That
contingency was gated on one unverified question: *what `PRAGMA synchronous` does
`apalis-sqlite` use?*

**Problem.** Answer the question from the source, not from the documentation.

**Evidence — read directly from the published crate.** `apalis-sqlite`
`1.0.0-rc.9` (2026-09-16), `src/lib.rs:149–166`:

```rust
/// Perform migrations for storage
#[cfg(feature = "migrate")]
pub async fn setup(pool: &SqlitePool) -> Result<(), Error> {
    sqlx::query("PRAGMA journal_mode = 'WAL';").execute(pool).await?;
    sqlx::query("PRAGMA temp_store = MEMORY;").execute(pool).await?;
    sqlx::query("PRAGMA synchronous = OFF;").execute(pool).await?;   // ← line 156
    sqlx::query("PRAGMA cache_size = 64000;").execute(pool).await?;
    sqlx::query("PRAGMA journal_size_limit = 67108864;").execute(pool).await?;
    sqlx::query("PRAGMA optimize;").execute(pool).await?;
    Self::migrations().run(pool).await.map_err(sqlx::Error::from)?;
    Ok(())
}
```

**Four findings, in order of severity:**

1. **TP-7 fails outright.** `synchronous = OFF` is *weaker* than `NORMAL`.
   Per `sqlite.org/wal.html`, `OFF` means SQLite continues without syncing once
   data is handed to the OS: data survives an *application* crash, but **the
   database may become corrupted if the operating system crashes or the machine
   loses power**. ADR-0006 requires `synchronous = FULL` on the task connection;
   TP-7 requires that power loss cannot corrupt task state. **`apalis-sqlite`
   makes both false by default.**
2. **There is no configuration knob.** `synchronous` appears exactly once in the
   entire `src/` tree. `config.rs` exposes `batch_size`, `heartbeat_interval`,
   `missed_heartbeats`, `queue`, `database_url`, `lock_tasks`,
   `persist_results` — no durability settings. Correcting it requires a fork.
3. **The pragma is applied per-pool, not per-connection.** It is issued via
   `.execute(pool)`, not inside the `after_connect` hook that the crate *does*
   register (for the update hook, `src/lib.rs:136`). Because `synchronous` is a
   **per-connection** pragma, applying it once through a pool is at best
   unreliable and at worst makes durability *inconsistent between connections* —
   which is worse than a consistent weak setting, because the behaviour is not
   knowable from configuration. (Recorded as a source reading; the precise
   `sqlx` pool semantics should be confirmed in a spike if this ever changes.)
4. **TP-5 is only partially satisfied.** `queries/task/ack.sql`:

   ```sql
   UPDATE Jobs SET status = j.status, attempts = j.attempt, last_result = j.result, ...
   FROM j WHERE Jobs.id = j.task_id AND Jobs.lock_by = ?2
   ```

   This fences on **worker identity** (`lock_by`) but **not on lease expiry**. A
   zombie worker whose lease has expired and whose task has *not yet been
   re-claimed* will still find `lock_by` matching — and can still commit. ADR-0029
   calls out exactly this as the subtle case: *"a worker whose lease has expired
   must not be able to complete or commit work, even if it is still alive and
   believes it holds the task."*

**Additionally:** `apalis-sqlite` has **never released a stable version** — all
14 published versions are pre-releases, newest `1.0.0-rc.9`; `apalis` core's
newest is `1.0.0-rc.10`. It is effectively single-maintainer.

**In fairness, the design is good.** Orphan re-enqueue
(`queries/reenqueue_orphaned.rs`), heartbeats with `missed_heartbeats`, priorities,
delayed jobs, unique jobs, and SQLite **update hooks** for event-driven
(sub-100 ms) pickup instead of polling are all genuinely well-judged for this
problem. And the maintenance is active. The rejection is about **one unconfigurable
line that makes a stated correctness property false**, not about quality.

**Decision.** **`apalis-sqlite` is rejected as the task engine.** ADR-0007's
hand-rolled engine stands, and its contingency is **closed**. ADR-0029's twelve
properties are the contract; the hand-rolled engine is the only implementation
currently known to satisfy all twelve.

**Trade-offs.** We own the queue. That was already the decision; this removes the
comfort of a fallback, so the ADR-0029 conformance suite and the failure-injection
harness become load-bearing rather than merely good practice. Accepted — a
fallback that silently fails TP-7 is worse than no fallback, because it is
discovered at the worst moment.

**Consequences.** Register as **V-21**. `apalis` may still be evaluated for
**non-critical** uses (a best-effort notification queue, where
`synchronous = OFF` is acceptable) — but never for the task table.

**Rejected alternatives.** **Fork `apalis-sqlite` to change the pragma.** A
one-line fork of a pre-1.0, single-maintainer crate means owning the fork,
re-basing on every RC, and re-deriving its migrations — at which point we own it
anyway, with extra steps. **Re-issue `PRAGMA synchronous = FULL` after calling
`setup()`.** Ordering is racy against sqlx's connection pool, and the pragma
would still be unset on connections created later; it fights the library rather
than fixing it. **Use `apalis` with a different backend.** Every other backend is
a server (Postgres, Redis, SQS, NATS, AMQP), which violates the core
single-process constraint (ADR-0006, V-24).

**Revisit conditions.** Revisit only if **both**: (a) `apalis-sqlite` exposes a
documented durability configuration, **and** (b) it passes the ADR-0029
conformance suite — specifically **TP-7** (power loss) and **TP-5** (lease-expiry
fencing at commit). A stable 1.0 release alone is **not** sufficient.

---

<a id="adr-0033"></a>
## ADR-0033 — `orxnud-task` and `orxnud-capability` are distinct layers

> **Accepted 2026-09-30.** Documentation and CI correction. No architectural
> redesign; the crate graph is unchanged.

**Context.** `docs/03` §7.1 lists the core crates as a flat table, and gate G2's
layer list grouped them:

```sh
"orxnud-task|orxnud-capability"
```

That `|` group was chosen to mean "these two are peers, both above `orxnud-policy`".
The gate enforced the right thing — the inward check permits only strictly-earlier
layers, so `orxnud-task → orxnud-capability` has always been rejected — but the
*presentation* implied the edge was permitted.

**Why that mattered, concretely.** The Phase 2 record states the engine cannot
reach a capability. To check that, a reader had to run gate G2 and read a failure
message, or reason about the layer semantics. For the single most important
security property in the repository, "legible by reading the list" is not good
enough. A reader who assumes the `|` group means mutual permission will draw the
wrong graph, and the wrong graph is what gets built.

**Decision.** Separate entries, plus a named assertion.

```sh
"orxnud-task"
"orxnud-capability"
```

and, as its own gate check that fails by name:

- `orxnud-task` **must not** depend on `orxnud-capability`.
- The reverse direction is **deliberately not asserted.**

**Why not assert the reverse.** An earlier draft of this gate also required
`orxnud-capability → orxnud-task`, on the theory that a capability runs as a task
step. `orxnud-capability` does not depend on `orxnud-task` today. Whether the
dispatcher should call into the task engine, or `orxnud-daemon` should compose both
and pass a task context in, is an open design question — and asserting it would smuggle
a design choice into a documentation correction, making the gate fail for the wrong
reason. The forbidden direction is a boundary fact; the permitted one is not yet a
decision.

**Consequences.** The intended direction is now obvious on its face:

```text
orxnud-task  -X->  orxnud-capability
```

Verified by injecting the forbidden edge and observing gate G2 fail with
`orxnud-task depends on orxnud-capability, which is not inward`, then observing
`ok  orxnud-task cannot reach orxnud-capability` on the restored tree.

**Revisit conditions.** Revisit when the dispatcher's task-integration direction is
decided (Phase 3), at which point the reverse edge may be asserted if it exists.

---

<a id="adr-0034"></a>
## ADR-0034 — `CapabilityInvocation` is not deserialisable; ingress uses `CapabilityRequest`

> **Accepted 2026-09-30.** Closes the Phase 3 precondition. Amendment to ADR-0003
> and ADR-0012.

**Context.** The architecture's central structural claim is that policy cannot be
bypassed because the type that reaches an adapter has exactly one constructor, and
that constructor needs a `PolicySeal` and an `AuthorisationProof`:

```text
External → interface → Proposal → ActionRequest → [POLICY] → CapabilityInvocation → adapter
```

ADR-0012 stated the consequence as *"It is not possible to do this without going
through policy."*

**The problem.** `CapabilityInvocation` derived **both** `Serialize` and
`Deserialize`, with private fields:

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityInvocation { /* private fields */ }
```

A derived `Deserialize` is a **second constructor**. It writes the private fields
directly, so the seal, the proof, and policy evaluation are all bypassed — the exact
thing the private fields existed to prevent.

**Evidence: it was exploitable, not merely untidy.** Before implementing anything in
Phase 3, a standalone crate outside the workspace was built against `orxnud-domain`
and minted an authorised invocation from a JSON literal:

```rust
let forged: CapabilityInvocation = serde_json::from_str(json).expect("forged");
```

```text
FORGED OK -> CapabilityId("send-email") risk=Low policy_version=forged
           params={"to":"attacker@evil.test"}
```

No policy evaluation. No `AuthorisationProof`. No `PolicySeal`. No human. The caller
asserted its own `assessed_risk: "low"` and `policy_version: "forged"`, and the type
accepted both.

This is worth stating plainly: it was found by *building the Phase 3 dispatcher and
asking what would happen to each stage*, not by reading the code. The dispatcher was
not written, because stage 1 (AUTHORITY) would have validated a fabricated actor and
stage 6 (CREDENTIAL RESOLUTION) would have handed real credentials to it.

**Decision.** Two types with different trust levels, and the boundary is the
*difference between them*:

| Type | Means | Deserialize? |
|---|---|---|
| `CapabilityRequest` | "someone asked for this" | **yes** — it is the inbound type |
| `ActionRequest` | "validated against the capability's schema" | yes |
| `CapabilityInvocation` | "OpenRayNux authorised this exact action" | **no** |

```text
External / CLI / GUI / TUI / Voice / DM / API / Scheduled / Integration
        │
        ▼
CapabilityRequest          (untrusted; carries no authority)
        │
        ▼
validation + normalisation
        │
        ▼
Policy → Authority → Approval → Budget
        │
        ▼
CapabilityInvocation      (authority-bearing; only policy can construct)
        │
        ▼
Dispatcher → Execution
```

`CapabilityRequest` deliberately has **no** field for `assessed_risk`,
`policy_version`, approval digest, credential handle, `PolicySeal`, or
`AuthorisationProof`. Those are derived by trusted deterministic code during
authorisation; a caller-settable field would be a caller-lieable field.

**Why `Serialize` stays on the invocation.** The two are not symmetric. Serialising
an authority-bearing value *out* is a disclosure risk that a caller must consciously
own (audit records, hashing). Deserialising one *in* is an authorisation bypass that
no caller should be able to perform at all. Only one of those is a boundary.

**Also: the invocation is not a persistence type.** Audit and task rows must use
explicitly designed structures, not a serialised `CapabilityInvocation`. Otherwise a
future developer restores the same trust confusion through the storage layer, which
is the same bug wearing a different hat.

**Consequences.**

- ADR-0003 amended: JSON-RPC frames carry `CapabilityRequest`, never
  `CapabilityInvocation`. An inbound frame is untrusted data that policy
  re-authorises from scratch on arrival.
- ADR-0012 amended: its type-level claim now holds, and says what makes it hold.
- Every ingress — CLI, GUI, TUI, voice, DM, API, scheduled, integration — converges
  on `CapabilityRequest`. One untrusted representation, one authorisation pipeline.
- `tests/compile_fail/invocation_cannot_be_deserialised.rs` pins the absence, with a
  recorded `.stderr`, so re-adding the derive fails the build. Verified with teeth:
  re-adding `Deserialize` turns that test red.

**Rejected alternatives.**

- **Keep `Deserialize` but validate on the way in.** Rejected: one type would then
  serve two trust levels, and the validity of a deserialised invocation would depend
  on which constructor produced it — not knowable from the value.
- **Add a `verify_after_deserialisation` method.** Same problem in a worse shape: it
  makes the safe path a runtime check the caller can forget, which is the documentary
  enforcement this ADR exists to replace.

**Revisit conditions.** Revisit only if an interface must forward an *already
authorised* invocation across a process boundary — and then the correct answer is to
send the `CapabilityRequest` plus a reference to the authorisation record, and
re-authorise on arrival. Forwarding authority across a trust boundary should never be
the design.

---

<a id="adr-0035"></a>
## ADR-0035 — Tier-1 execution: PID namespace plus `PDEATHSIG`, and what it does not do

> **Accepted 2026-09-30.** Phase 4a. `orxnud-platform-sandbox`.

**Context.** ADR-0009 assigns third-party, untrusted and copyleft capabilities to
Tier 1 — a subprocess, so that a segfault in a native dependency cannot kill the core.
Phase 3 left ADR-0009's contract points 4 and 6 (`no undeclared filesystem or network
access`, `a disabled capability leaves no residue`) as `declared_only`, because an
in-process fixture can observe neither. Both are claims about *processes*.

**Problem.** What mechanism actually provides isolation here, and — the part that
mattered most — what does it *not* provide?

**Decision.** A portable contract (`crates/orxnud-platform-sandbox/src/contract.rs`)
expressing **what** is required, with `bubblewrap` supplying it on Linux.

### Three guarantees, deliberately separate

| Guarantee | Linux | Windows | Phase 4a status |
|---|---|---|---|
| **Visibility** — what exists at all | PID + mount + net namespaces | Job Object / AppContainer | PROVEN |
| **Tree lifetime** — a detached descendant cannot outlive the execution | `--unshare-pid` + `--die-with-parent` | Job Object kill-on-close | PROVEN |
| **Resource ceilings** — hard memory/CPU/PID limits | cgroup v2 controllers | Job Object limits | **NOT PROVEN** |

Conflating these is what made the phase look blocked. A PID namespace gives visibility,
not lifetime; a parent-death signal gives the direct child, not the subtree.

### Why `--unshare-pid --die-with-parent` *is* tree containment

This is the opposite of the first analysis, and the correction is the most useful
finding in the phase.

An earlier measurement reported that a detached, `SIGTERM`-ignoring grandchild
**escaped** all three of `--unshare-pid --die-with-parent`, `--unshare-pid`, and
`--die-with-parent`. **That was a measurement error.** Liveness was checked by looking
for the grandchild's PID in the host's `/proc`, but the helper had reported the PID it
saw **inside** its new namespace — and on the host, `3` is an unrelated process. The
check found a live `/proc/3` and concluded the grandchild had escaped.

Corrected measurement, watching the grandchild's on-disk heartbeat *advance*:

```text
--unshare-pid --die-with-parent  -> CONTAINED   (5 of 5, SIGTERM and SIGKILL)
--unshare-pid only              -> ESCAPED
--die-with-parent only          -> ESCAPED
neither                         -> ESCAPED
```

The mechanism: `bwrap`'s forked child becomes **PID 1 of a new PID namespace**, and the
kernel guarantees that when a namespace's init dies, every remaining process in it is
sent `SIGKILL`. `PDEATHSIG` supplies the trigger when `bwrap` is signalled, and the
namespace supplies the reach. A detached grandchild cannot opt out — leaving a PID
namespace needs privileges the sandboxed process does not have.

**Conditions, all of which the claim depends on.** The guarantee is a property of
*this topology*, not of bubblewrap:

1. `--unshare-pid` **and** `--die-with-parent` together. Either alone does not contain
   — that is the other three rows of the matrix above.
2. The supervisor signals **`bwrap`**, never the inner process. Signalling the child
   kills its parent without firing `PDEATHSIG`, leaving the namespace init alive.
3. No `--share-pid`, no privilege retained, and `bwrap`'s own forked child is PID 1 of
   the namespace.

Stated as a rule: **this is not "bubblewrap guarantees arbitrary descendant
termination", it is "the OpenRayNux sandbox configuration contains a detached
descendant, and changing a namespace flag invalidates the claim until
`isolation.rs` is re-run."** The verification register (V-45) carries the same scope,
so a later reader cannot widen the claim from the ADR alone.

**Rejected: `cgroup.kill` as the Phase 4a mechanism.** It is the stronger answer — it
walks the cgroup, so it needs no namespace and handles concurrent forks — and
`cgroup.kill` *is* writable here. It is not used because the resource controllers beside
it are not, so adopting cgroups for lifetime alone would give a second mechanism to
maintain for no additional guarantee. It becomes the right choice in Phase 4b.

**Rejected: hand-rolled namespaces.** Needs `unsafe`; gate G4 forbids it. `bwrap` also
gets the ordering right (namespaces unshare before mounts, so the child never sees a
half-built root) and handles `setuid` restoration.

### Fail-closed, not fail-open

`TreeLifetime` and `Resource` default to **`Required`**. On a host that cannot provide
them, `SandboxSpec::run` returns `Refused(GuaranteeUnavailable)` rather than running a
weaker sandbox. A caller may opt out explicitly with
`accepting_best_effort_containment`, and then `ExecutionResult::unproven` records what
was not provided — so an audit record can say "this ran without subtree kill" instead of
implying otherwise. Relaxing containment is visible in a diff because the method name
says so.

### What this does **not** provide

- **Resource ceilings.** `memory.max`, `pids.max` and `cpu.max` are unwritable in this
  user session — the controllers are listed in `cgroup.controllers` and every write is
  refused. Requested by default, refused in practice. Phase 4b.
- **`bind` denial.** A network namespace blocks connectivity but **not** `bind(2)`. A
  helper can bind a socket inside its namespace; it is unreachable from outside, which
  is the property that matters. Asserting that `bind` must fail would have demanded a
  weaker sandbox.
- **Windows.** Nothing implemented, nothing claimed. Job Objects are the intended
  mechanism for both tree kill and resource limits, and AppContainer for filesystem,
  registry, network and process restriction. Unverified (V-29).
- **Cloud.** Documented only: same process contract, platform-specific backend;
  microVMs where the isolation requirement exceeds what containers can promise.

### The invariant this must preserve

> Every Tier-1 execution request is **rejected** when a required sandbox guarantee
> cannot be established. There is no "best effort" fallback to unsandboxed execution.

`bwrap` absent yields `MechanismUnavailable`; an unavailable guarantee yields
`Refused(GuaranteeUnavailable)` — both **before** any process is spawned. An
unsandboxed capability has no isolation at all, which is worse than no capability.
Relaxation exists, is named (`accepting_best_effort_containment()`), appears in a diff,
and lands in `ExecutionResult::unproven` so an audit record states the gap. Recorded as
V-49.

### Phase 4b: the governed path now consumes it

`Dispatcher::dispatch` gained an execution branch keyed on `CapabilityAdapter::tier()`.
A `Subprocess` adapter is invoked **only** through `ExecutionBackend::execute`; there
is no in-process route and no unsandboxed fallback (V-51, V-50 closed).

Three properties are structural rather than conventional:

1. **`tier()` is on the adapter, not the declaration.** A declaration claiming Tier 0
   while the implementation spawns a process would be exactly the bypass this phase
   exists to close, and the adapter is the thing that knows how it runs.
2. **`with_execution` is the only way to enable subprocess execution.** There is
   deliberately no setter taking a program and arguments, because that *is* the
   `dispatcher -> direct subprocess` bypass.
3. **`ExecutionReport` has no `sandboxed: bool`.** A result that exists came from a
   sandbox, because `Err` is how a refusal is expressed. A boolean would permit `Ok`
   with `sandboxed: false` -- the unsandboxed fallback in all but name.

### The gap Phase 4b must close — **CLOSED, see the amendment below**

> **Amendment, 2026-10-05.** This section is preserved as written because it is the record
> of what was true when Phase 4a was accepted. **The gap is closed.** The governed path
> exists and is exercised end to end: `orxnud-capability/src/subprocess.rs` holds the
> `SandboxRunner`, `tests/governed_path.rs` runs 24 tests through `Dispatcher::dispatch`
> against real sandboxed subprocesses, `tests/read_text_real.rs` adds 12 more for a governed
> read, and `cli_e2e` drives the shipped binaries through the whole loop. **V-50 recorded
> this gap and V-51 closed it**; the entry that stated it was simply never re-read, which
> is the register's own failure mode. Contract points 4 and 6 of ADR-0009's suite remain
> `declared_only` **by decision**, not by omission — the contract harness is in-process and
> cannot observe a namespace; the evidence lives in `tests/isolation.rs`. See V-40.

The original text follows.

`orxnud-platform-sandbox` currently has **no consumer**. The governed path

```text
Dispatcher → execution contract → sandbox supervisor → Tier-1 subprocess
           → result → Verification → Audit
```

does not exist, so Phase 4a proves a boundary that nothing enforces yet. Nothing is
registered and nothing runs unsandboxed, so there is no active exposure — the risk is
architectural drift, and V-50 records it. Phase 4b must wire it with synthetic adapters
only, and prove no bypass exists.

**Consequences.** Contract points 4 and 6 of ADR-0009's 10-point suite can move from
`declared_only` to evidence-backed, with the residual gaps named above. ADR-0017's
"snapshot → migrate → verify" is unaffected: this is execution, not migration.

**Revisit conditions.** Revisit the mechanism when a host delegates cgroup controllers
(Phase 4b), at which point `cgroup.kill` replaces the namespace approach for tree
lifetime. Revisit the contract if a capability legitimately needs weaker containment —
by relaxing that one spec, not by changing the default.

---

<a id="adr-0036"></a>

## ADR-0036 — Tree lifetime on Linux: the PID namespace is load-bearing, `cgroup.kill` is a redundant backstop

**Status:** accepted
**Date:** 2026-10-01
**Supersedes:** nothing. Extends ADR-0035 (which established `--unshare-pid` +
`PDEATHSIG` as the containment topology, and was careful not to overclaim).

### Context

ADR-0035 established that process-tree containment on Linux comes from a PID namespace
plus `--die-with-parent`: when the supervisor dies, the namespace's init dies, and the
kernel tears down every process in it. It explicitly declined to claim more than that.

V-46 added a second mechanism. The runner creates a dedicated cgroup, adopts the
supervisor into it, and issues `cgroup.kill` on timeout, on cancellation, and at
teardown. Both mechanisms were then observed to terminate a detached, signal-ignoring
descendant — but only one of them can be credited.

The evidence is asymmetric. Mutating the runner's `cgroup.kill` away leaves the entire
governed suite green (`M2`, no teeth): `--unshare-pid --die-with-parent` has already
reaped the descendant by then. The mechanism suite, which has no PID namespace, does
show `cgroup.kill` terminating a three-level subtree, and that is mutation-verified.

So the question is not whether `cgroup.kill` works. It is what it is *for*.

### Decision

1. **The PID namespace is the load-bearing tree-lifetime mechanism on Linux.** This is
   already what the code assumes: `BwrapRunner` derives `tree_lifetime` from the
   namespace probe, not from `cgroup.kill`, and a host offering `cgroup.kill` but no PID
   namespace is refused. Fail-closed and consistent.

2. **`cgroup.kill` is a deliberate redundant backstop, not an independent guarantee.**
   It is issued on every teardown path, and it is what makes cgroup removal prompt — a
   descendant holding `stdout` open cannot keep the cgroup alive. Redundancy is
   acceptable: two mechanisms for one property fail safer than one, and the cost is
   three extra file writes per execution.

3. **The governed-path `cgroup.kill` claim is `NOT_APPLICABLE`, not `NOT_PROVEN`.**
   Under this execution model the distinguishing scenario is unreachable, so no test can
   separate the two. Recording it as unproven would imply a test exists and is failing;
   recording it as not-applicable states the architectural fact. No artificial mutation
   will be built to manufacture a distinction.

4. **Sandboxed processes cannot escape the cgroup, so the backstop cannot be the sole
   defence for a reachable case.** Leaving the cgroup requires writing another
   `cgroup.procs`, and leaving the PID namespace requires `CAP_SYS_ADMIN`. `bwrap` mounts
   no `/sys/fs/cgroup` for the payload, so the former is unavailable and the latter is
   unprivileged. This is why the redundancy is safe rather than merely convenient.

### Consequences

- V-46 closes with the honest shape: mechanism proven, governed-path adoption proven,
  governed `cgroup.kill` teeth recorded as redundant rather than proven.
- The capability layer stays free of Linux specifics; the decision lives entirely in the
  platform runner.
- A future execution model without a PID namespace — a Windows Job Object runner, or a
  Linux path that cannot unshare PIDs — inherits the converse obligation: there,
  `cgroup.kill` becomes load-bearing and must be proven on its own. This is the coupling
  that makes V-29's evidence requirement real rather than clerical.

### What this ADR does not claim

It does not claim `cgroup.kill` is useless, nor that the two mechanisms are
interchangeable. It claims only that on the current Linux path the namespace already
provides the property, so the governed test cannot distinguish them, and that the honest
record is redundancy.

---

<a id="adr-0037"></a>

## ADR-0037 — An approval names its approver, and the digest binds them

**Status.** **Implemented.** `ApprovalRecord` carries an explicit `approver: Actor`;
`canonical_bytes` binds both parties and its prefix moved `v1` -> `v2` so a pre-change
digest cannot verify; `authorise` refuses a non-granting approver
(`approval_approver_cannot_grant`) and an approver who is not the proposer's authority
root (`approval_approver_not_authorised`); and `issue_approval` asserts
`approver.can_grant()` at minting. The minting path re-derives the approver from the
trusted local-human boundary and never reads it from the request. Cites V-69 and V-70.

**Amendment — the digest binds the logical step (`v2` -> `v3`).** `canonical_bytes` now
appends `step_no` as its final field and its prefix moved `v2` -> `v3`. `ApprovalRecord`
carries `step_no: u32`, and `authorise` recomputes with **the step recorded on the
approval**, never one supplied by the caller: a record that does not say which step it
speaks for cannot be told apart from one that speaks for another, so under `v2` a single
human approval would authorise the same action at *every* step of a multi-step task.

The field is **required, not defaulted**. Every production call site supplies an explicit
step: the task path reads it from the durable proposal (`task_proposals.step_no`) and
`runtime` refuses an approval whose step disagrees with the proposal it is recorded
against (`approval-step-mismatch`); the standalone `capability approve` path, which
governs no task and therefore has exactly one step, uses the named constant
`STANDALONE_APPROVAL_STEP`.

Appending rather than inserting keeps every previously-bound field in its
previously-hashed position, so the entire difference from `v2` is one prefix and one
field.

**There is no version to read out of a stored digest.** `ApprovalDigest` is a bare
32-byte blake3 hash; the `v2` marker lives *inside* the hashed bytes and is not
recoverable. A superseded `v2` digest and a malformed `v3` one are therefore genuinely
indistinguishable, and both are refused through the same `approval_digest_mismatch`
denial — inventing a distinction would mean parsing hash bytes, which would be a guess
dressed as a check. The authorization result is identical either way.

Historical `v2` approvals fail closed. They remain readable and structurally verifiable
in the audit chain, because the digest is stored as an opaque hash: **no migration shim
was added, and none should be**, since one would only obscure the transition. See V-83.

**Context.** ADR-0012 committed this project to "the model proposes; the deterministic
engine disposes", and ADR-0034 later proved one of its structural claims false in the
way that matters: `CapabilityInvocation` derived `Deserialize`, and a derived
`Deserialize` writes private fields without a constructor, so the type-level seal was
bypassable. The lesson carried forward is that a claim about who *may* authorise has to
be checked where authorisation happens, not asserted at the type that carries it.

**Problem.** The approval as it exists today is a **bearer token**. `ApprovalRecord`
carries `actor_label`, capability, target, params, issued/expires, risk and a digest —
and **no approver**, anywhere:

- `canonical_bytes` binds `actor.label()`, `actor.authority_root()`, capability, target,
  params, issued-at and expires-at. The *proposer's* identity is bound. The approver's
  is not.
- `actor_label` is written to the record and to `task_approvals.actor_label`, and **no
  dispatch-time code reads it.**
- `Decision::Gate.approver` is *derived* at `engine.rs:396` from the proposer's
  `authority_root()` — an inference sitting where evidence should be. The system
  asserts "the approver is the human whose authority is being used" rather than
  recording that a human was asked.
- `Actor::can_grant()` is enforced in exactly one non-test place (`engine.rs:266`), and
  only to refuse an actor with neither grant capability nor an authority root. It cannot
  check *who approved*, because there is nothing to check.

So an approval currently establishes: *these parameters, for this proposer, before this
time*. It does not establish: *a specific human examined this and consented*. Combined
with a minting endpoint that answers any caller, a delegated pipeline built on this
would be a **false demonstration** — the AI side could obtain its own approval through
the same mechanism, and every stage would report success.

**Decision.** An approval is a statement about a *pair* of parties, and the digest
covers both.

1. **D1 — approval is non-bearer.** The bound tuple becomes
   `approver + proposer/actor + authority_root + capability + target +
   normalized params + issued_at + expires_at`. An approval cannot be detached and
   reused for a different actor or action, because both parties are inside the digest.
2. **D2 — the approver is explicit and grant-capable.** `ApprovalRecord` gains an
   approver identity. Dispatch verifies, in order: the approval exists, is unexpired,
   is unconsumed, its digest matches the action about to run, the approver
   `can_grant()`, and `approver == proposer.authority_root()` for delegated execution.
   The authority-root relation becomes a **checked** equality rather than an assumption
   the engine makes on the actor's behalf.
3. **D6 — a wire actor is an asserted principal, not an authenticated identity.**
   `Actor` crossing local IPC means the structure deserialises; it does not mean the
   caller possesses that identity. The three are kept distinct in naming, docs and
   tests: *principal assertion* ≠ *principal authentication* ≠ *principal
   authorization*. Today's boundary is the 0700 Unix socket plus the single-user local
   model, and that is stated as the boundary rather than implied by the type.

### Consequences

- For `Actor::Ai { delegated_by: H, .. }`, the approval must come from `H`. The
  delegation becomes enforceable rather than descriptive: **delegation is not authority
  creation**, and an AI actor's authority is bounded by its delegating human's.
- Human approval becomes the only place new authority enters the chain, which is what
  makes ADR-0012's sentence true of the *runtime* and not only of the type.
- The register gains V-69 (the gap above) and V-70 (asserted principal vs authenticated
  identity), because both are claims that will silently become false.
- Multi-user authentication stays out of scope, and is now *named* as out of scope. The
  hazard is specific: an `Actor { user: "H" }` arriving over a socket is easy to later
  mistake for proof that the caller is `H`.

### What this ADR does not claim

It does not claim the current approval flow is exploitable today. With one local user
behind a 0700 socket, minting on request is equivalent to that user consenting, so V-69
is a **latent** defect that becomes live the moment a non-human proposer exists. It does
not claim adding an approver field alone is sufficient: the minting path must also be
reachable only by a grant-capable principal, or the field is decoration.

### Amendment trigger

Re-read if any of: an actor other than `Human` reaches the dispatcher; a capability is
reachable over anything other than the local socket; `can_grant` gains a second true
variant; or multi-user support is proposed.

---

<a id="adr-0038"></a>

## ADR-0038 — A governed action is proposed durably before it is approved

**Status.** **Implemented.** A `task_proposals` table carries the durable proposal;
`TaskRepository::propose_action` commits the proposal, the transition to
`waiting_for_user` and the task event in one transaction, and releases the lease;
`decide_proposal` records the human's decision without touching task state; and
`begin_approved_execution` takes a **fresh** lease and resumes the task in one
transaction, leaving `attempts` untouched. The proposal carries an `Actor::Ai` proposer
derived from the task identity, never from the lease holder. Cites V-71. Builds on
ADR-0037.

**Context.** ADR-0037 settles *what an approval is*. It says nothing about the thing
that precedes one, and the store already contains a half-built answer that is worth
reading before adding anything.

**Problem.** Three concrete gaps, all verified against source rather than inferred:

1. **There is no durable proposal.** `task_approvals` is keyed `(task_id, attempt_no)`
   and its `digest` column is `NOT NULL`, so a row can only exist *once approved*. A
   proposed-but-unapproved action has no representation at all — which means there is
   no durable answer to "why did this task enter `WaitingForUser`?", and an approval row
   appears with no antecedent.
2. **Two approval ledgers exist with materially different strength.** The policy layer's
   `spent_approvals` is digest-keyed and verifies the digest against the action, checks
   expiry, and enforces single-use. The task layer's `may_use_approval` checks
   `is_valid_at(now_ms)` **only** — it never verifies the digest, and its own doc
   defers that to policy. Reading `may_use_approval() == true` as "this action is
   authorised" would be wrong.
3. **`WaitingForUser` already exists and is already correct.** The transitions are
   `Pending → WaitingForUser`, `Running → WaitingForUser`, and
   `WaitingForUser → Running | Cancelled`. A task can rest awaiting a human and resume.

**Decision.**

1. **D3 — the proposal precedes the approval, durably.** `ActionProposal` is a new
   durable object holding capability, target, normalized params, proposer `Actor`,
   authority root, `created_at`, status, and a nullable approval reference. It exists
   *before* the task rests in `WaitingForUser`, so the wait is explained by a record
   rather than by an absence.
2. **A new table, not a nullable digest.** `task_approvals` stays the **approved-action
   ledger**. Overloading it with a nullable-digest proposal row was considered and
   rejected: it would make "the task asked for permission" and "permission was granted"
   the same row, which is precisely the distinction the audit trail exists to preserve.
3. **D4 — approval remains per-attempt.** A retry creates a new attempt, which derives
   its own proposal and requires its own approval. This is what TP-6 already implies by
   keying approvals on `(task_id, attempt_no)`; the proposal inherits the same keying
   rather than inventing a second scheme.
4. **D5 — a lease never grants authority, and this becomes a test.** The current state is
   structurally sound: a lease grants exactly one thing, completion fencing, and **no
   `Actor` is constructed from a task or lease anywhere** — the only non-test `Actor::`
   in the codebase is the hardcoded local human in the runtime. That is true by absence
   of code paths, which is exactly the kind of truth that erodes silently. It becomes a
   regression test: a task claimed by a worker must not influence the actor, the
   authority, or the approval at dispatch.

### Consequences

- The lifecycle becomes: `Running → (ordinary work | governed action proposed) →
  WaitingForUser → approved → Running → capability → verification → task completion`,
  with rejection reaching a terminal task outcome. **No new task state is introduced**;
  the reason for waiting lives in the proposal's status, not in the state machine.
- An **expired approval implies neither approval nor execution.** It is a terminal
  status on the proposal, and a retry is a new attempt with a new proposal.
- The two ledgers stay separate and their boundary is documented: the task ledger scopes
  and consumes per attempt, the policy ledger is the only place a digest is verified
  against an action. Any future caller of `may_use_approval` must still go through
  policy.
- V-71 exists because D5's invariant is currently guaranteed by nothing but the absence
  of the code path that would break it.

### What this ADR does not claim

It does not claim the proposal needs to be a first-class table forever; a proposal that
never leaves `pending` may later prove to be derivable from the task's own attempt
record, and this decision can be amended if that is shown. It does not claim rejection
needs a task state — it does not. It does not claim `WaitingForUser` is well-named for
every future use; it is reused here because adding `WaitingForApproval` would duplicate
a state that already means "a human is required to continue".

### Amendment trigger

Re-read if a second waiting-for-human reason appears that `WaitingForUser` cannot
express; if `task_approvals` is ever asked to represent an unapproved proposal; or if
`may_use_approval` is called from a dispatch path without a subsequent policy check.

---

<a id="adr-0039"></a>

## ADR-0039 — A capability declares its parameters; the proposer reads the declaration

**Status.** **Implemented.** `CapabilityDeclaration` carries `params: ParamSpec` (prose
plus a machine-checkable `ParamSchema`) and `target: TargetSemantics`; `ai_propose` walks
`Registry::enabled()` to build the menu it offers a model instead of a literal list;
`proposer::validate` refuses a proposal whose parameters do not match the declared shape
(`proposal-schema-mismatch`) or that omits a required target
(`proposal-target-missing`); and the provider is owned per `Runtime` rather than by a
process-global slot. Cites V-76.

**Context.** V-75's slice left one hardcoded list standing. `ai_propose` named
`filesystem/write-text` literally, alongside its display name and its two parameter
names, in a file that had nothing to do with the capability. The capability itself carried
no statement of what it accepted: `write_text::parse` knew the rule, and the proposer
knew a second, partial copy of it. Two lists, one of them in the wrong place, and the
drift was structural rather than accidental — the next capability added would be
registrable and therefore invisible to the model until somebody remembered to edit the
proposer.

The deeper problem is that a proposal could be *persisted* with parameters no capability
would accept. The shape check lived inside the capability, reached only when the execution
plan was built, which is after the proposal was durable and after a human had been asked
to approve it. So the cost of a malformed parameter set was paid at the most expensive
moment in the pipeline, and attributed to the sandbox rather than to the request.

**Decision.** A capability describes its own parameters, in the domain layer so that the
capability and its callers share one type without either depending on the other. The
schema is *shape only* — field names, types, which are required, what a nested object
contains — and value rules stay with the capability that understands the world. A schema
that expressed "a path must stay inside the workspace" would either become a second
implementation of the capability's own checks or a constraint language nobody could read.
`orxnud-capability` asserts the two agree, so the shape can never be the stricter of them
in a way that refuses valid work.

`ai_propose` walks the registry. A capability that is registered and enabled is
proposable, with its own declared shape and target semantics, and adding one requires no
edit to the proposer.

The provider moved from a process-global `OnceLock` to a field on `Runtime`. The
`OnceLock` panicked on its second write, which meant the suite could test exactly one
provider scenario and no more. Replacing it with a scoped, restorable `RwLock` fixed that
and introduced a worse bug: a process-global mutable value cannot be scoped against
concurrency, so one test installing a malformed provider changed the answer another test
was receiving at the same moment — which the suite demonstrated by failing a test that
had nothing to do with it. Per-runtime ownership makes the interference structurally
impossible rather than merely unlikely, and it is also simply true that two daemons in one
process may be configured differently.

**Alternatives rejected.**

* *A capability-owned validator trait, invoked by the proposer.* Rejected: it puts the
  capability crate's parse path behind the proposal path, so a shape error and a semantic
  error become indistinguishable at both ends, and a model cannot be told which it made.
* *Keeping the hardcoded list and adding a test that it matches the registry.* Rejected:
  this is a synchronisation test for a duplication that should not exist. It would have
  caught the first drift and then required a second edit per capability forever.
* *Expressing the schema in JSON Schema and validating with a library.* Rejected for now:
  it adds a dependency to the domain layer, which is held to serde alone, and buys
  expressiveness that no shipped capability uses. A constraint language is also
  unreadable in an approval prompt, which is one of the consumers this slice names.
* *Passing the schema to the model so it can conform exactly.* Rejected: it invites a
  model to contrive a shape-satisfying request rather than an honest one. The model is
  told field *names*; the deterministic side holds the shape and enforces it.

**Consequences.** The model is told what each capability is for, what its parameters are
called, and what risk it carries — risk included, because a proposer that cannot see that
a capability is High will confidently propose work that is always going to wait for a
human. A malformed parameter set is refused at propose time, costs nothing, and is
attributed to the request. Approval presentation has a single source to render from,
which is the consumer this slice was building toward. `ParamKind::Array` has no element
type: no shipped capability takes an array, and an unconstrained array is honest about
that where a guessed element type would not be.

The refusal reasons are diagnostic on purpose. `proposal-capability-not-allowed` and
`proposal-unknown-capability` stay distinct because they say different things about a
model's mistake — it asked for something real but off-limits, or it invented an id.

### Amendment trigger

Re-read if a capability needs a parameter constraint the shape cannot express (at which
point the split between shape and semantics is being tested rather than respected); if a
second consumer needs the schema to be something other than prose plus structure; or if
the model is ever handed the schema itself.

---

<a id="adr-0040"></a>

## ADR-0040 — One real provider, over HTTP, with the credential in the secret store

**Status.** **Implemented.** V-77 and V-78 are closed: TLS via `rustls` with certificate
chain and hostname verification, and `orxnuctl provider credential set` as the user-facing
path into the platform secret store. Provider selection is **manual and authoritative** —
there is no automatic fallback of any kind, and a future one is a separate decision.

**Amendment: manual selection, and no fallback.** The originally selected provider and model
are exactly what the runtime uses. If that provider fails, the failure is reported; no other
provider, model, endpoint or script is tried. This is deliberate rather than merely
unimplemented. A provider outage is an outage, and a task's text may be personal or
sensitive, so "the configured provider is unavailable" is not permission to transmit the same
context to a different company. Automatic fallback is deferred until several real providers
exist and there is evidence about their behaviour; if it is ever built, it will be an explicit
opt-in policy with its own data-boundary rules (public context may fall back freely,
regulated context may not), not a default.

**Amendment: the credential has one supported path.** `orxnuctl provider credential set`
reads the value from **stdin** and writes it through `SecretsContract::set`. No spelling of
the command takes a credential as an argument — an argument is visible in `ps` output and in
shell history — and the argument parser is tested against every plausible attempt to pass
one. Nothing echoes the value back, not even a prefix, because a prefix is four characters of
a credential in every scrollback and CI log.

**Amendment: TLS, and no downgrade.** `https://` is TLS or it is nothing. There is no
configuration that turns it into plaintext, no retry from TLS to plain when a handshake
fails, and no redirect following — an `https://` endpoint answering `302 http://…` would
otherwise be a downgrade delivered by the far side rather than by us, which is the same
failure with the blame moved. `http://` remains reachable only when explicitly permitted,
which only a loopback test server does, and the transport refuses to attach an
`Authorization` header over plaintext at all. That last rule is what makes the permission
safe to have in the codebase: it cannot be used to prove a credential path works over
`http://` and then carry that expectation to a real host differing by one character.

`orxnud-config` and gate G2(b) were both amended deliberately. The CLI's permitted internal
crates gained `orxnud-domain` and `orxnud-platform-secrets`, because the credential command
must use the authoritative `SecretRef` and `SecretsContract` rather than hand-roll a
reference format that would write a credential the provider cannot read. That is the gate's
own reasoning applied: naming the real types is safer than inventing copies. The licence
allowlist gained `ISC` and `BSD-3-Clause`, required by `rustls-webpki`, `untrusted`, `ring`
and `subtle`; all four are permissive, and `ring` is `Apache-2.0 AND ISC` so ISC had to be
acceptable for `rustls` to be usable at all. `webpki-roots` was rejected: it is MPL-2.0, and
bundled roots also go stale. `rustls-native-certs` reads the host trust store instead.

One HTTP bug was fixed on the way. The response reader waited for the peer to close, which
was wrong twice: a provider answering `Connection: close` with a kept-alive connection would
hang until the deadline, and a TLS peer closing without `close_notify` looked like a
truncation error. The reader now delimits the body by HTTP framing — `Content-Length` where
declared — so the end of a response is a fact about the response rather than about the peer's
manners.

`OpenAiCompatibleProvider<S>` speaks
OpenAI-compatible `chat/completions` over HTTP/1.1, is injected per `Runtime`, resolves its
credential through `SecretsContract`, and returns text only. `ProviderError` grew from one
variant to eight, each with a fixed reason and no retry. `Runtime::start` now leaves the
provider **unconfigured** and `task/ai-propose` answers `provider-not-configured`. Cites
V-77 and V-78.

**Context.** V-75 shipped the pipeline and the boundary with a scripted provider, and said
plainly that the interesting half — a real model producing a sensible proposal — was
unproven. This slice is that half, minus the part no credential can reach.

**Decision.** One provider, no framework. `ProposalProvider` was not redesigned: it stays
synchronous and takes a context by reference. A synchronous network call inside the
daemon's async task would occupy a runtime worker for the length of a model call, and making
the trait `async` would push a runtime into every implementor and every test — so the call
site hands the provider to `tokio::task::spawn_blocking` instead. The provider drives a
private current-thread runtime. One call is in flight per daemon, so this costs a thread.

The transport is HTTP/1.1 written on `tokio`'s socket types rather than a new dependency.
`http://` is complete; **`https://` is refused**, not downgraded (V-77). Silently dropping
TLS would turn a configured `https://` endpoint into a plaintext attempt at the same host
with the credential in the clear, and nothing in a log would show it. The refusal is a
refusal precisely because it is inconvenient.

The credential is a `SecretRef`, never a `String` in a struct, resolved per request into a
`Zeroizing`. `orxnud-config` states that an environment variable must never be treated as a
secret store — it is visible to every process of the same user and ends up in `ps` output
and crash dumps — so the key comes from `SecretsContract` and the two provider settings come
from arguments. The key is dereferenced to `&str` for the `Authorization` header and
nowhere else, which means there is no expression that can put it in a log line: `Zeroizing`
has no `Display`. Third-party error strings are passed through a deliberately crude
redactor, because a credential store that fails while quoting the secret must not launder it
into a daemon log through us.

`Runtime::start` no longer installs the scripted provider. A daemon with no provider answers
`provider-not-configured`, and `--provider-scripted` is an explicit opt-in that announces
itself on stderr and records `scripted/none` in the audit record. The previous arrangement
would have let a production daemon quietly answer with a fixed string and report a working
intelligence loop that did not exist.

**Alternatives rejected.**

* *`https` via a TLS dependency (`ureq` + `rustls`).* Deferred, not rejected: it is the
  right answer and it is roughly fifteen crates into a repository that holds its domain
  layer to serde and thiserror alone. It deserves its own decision and its own licence
  review under G8, not a side effect of adding a provider.
* *An environment variable for the API key.* Rejected by the repository's own stated
  position on secrets, before any other consideration.
* *A transport trait so tests could mock HTTP.* Rejected in favour of a real loopback
  server. A mocked transport cannot catch a malformed request line, a wrong
  `Content-Length`, or a body limit that never engages — which are precisely the parts that
  have never been executed.
* *Retrying, or falling back to the scripted provider on failure.* Rejected. A retry is a
  second proposal attempt with different text, and a fallback is a daemon reporting a model
  that is not there.
* *Handing the model the `ParamSchema`.* Rejected for the reason ADR-0039 gives: it invites
  a model to contrive a shape-satisfying request rather than an honest one.

**Consequences.** The model is told the menu, the parameter names, and the risk class, and
nothing else; the request body is asserted to contain no dispatcher, task service, policy
engine, store handle or credential. The system prompt states the output contract and asks
for no safety behaviour, because a model that follows instructions is not a security
control. Every refusal is enforced after the text returns, and fifteen adversarial outputs
are refused by the parser while three semantic ones — a traversing path, an absolute path, a
nested path — are asserted to satisfy the *shape* and be refused by the capability, because
`ParamSchema` is shape-only and a test claiming otherwise would be claiming a job the
schema does not do.

`orxnuctl` now shows the `reason` word rather than the most specific string available,
because a reason exists to be branched on and hiding it behind prose defeats that. Provider
failures are a distinct wire error from a declined proposal: "the model was unreachable"
must not read as "the model's proposal was refused", or an outage starts looking like a
policy decision.

### Amendment: detection has to be asked for by name

`KeyringSecrets` no longer implements `Default`. It had one, derived over a single
`available: bool`, so `default()` built a store that reported "no secret store" without
consulting the platform -- and all three production call sites used it. The credential path
was therefore inoperable on every host, while every test passed, because every test builds
its store with `assume_available()` and so never exercised detection at all (V-79).

The lesson is recorded because it is not specific to this bug: **a test suite that skips
the code under repair cannot report it broken.** Detection now returns a three-way
`Probe`, availability comes from the write alone, a leftover probe entry is its own outcome
rather than a false "unavailable", and `clippy::new_without_default` is refused on purpose
with the reasoning in the source. `new()` probes; `assume_available()` does not; the caller
has to mean one.

### Amendment: the answering provider is the authority on who answered

`delegated_actor` takes the model identity as a parameter rather than naming one. It used to
pass the literal `openraynux/task-agent`, and so every AI actor in the signed audit journal
claimed that model whatever replied. The first live run made the cost concrete: the API
response said `openai/gpt-oss-120b` while `task_proposals.proposer` and both `audit_log`
records said something else entirely.

The rule this establishes: **the model recorded in an audit record is supplied by the
component that actually executed the request**, read from the answering object rather than
from configuration, so it cannot name a model that did not answer. Where no model
participates — the direct `task/propose` path — the record says `none/direct-proposal`
rather than borrowing a name. This is the same posture as `scripted/none` in V-75: the
audit's job is to say what happened, and a confident wrong value is the failure mode.

`prompt_hash` is still the literal `phase-2`. It is a placeholder for a prompt-framing
version this code does not version, and left alone deliberately: inventing a hash of nothing
would look like provenance while being exactly the kind of confident fiction this amendment
exists to remove (V-81).

### Amendment: the menu must state everything the validator enforces

The capability menu now announces each capability's target requirement, derived from
`TargetSemantics`. It did not, and a real model was asked for a `target` field it had never
been told about, then refused three times for omitting it (V-80).

The general rule: **a component that enforces a requirement is responsible for announcing
it.** A validator that refuses output for omitting a field the model was never told about
has found its own information gap, not the model's disobedience. The parser was not made
more permissive to accommodate the model; the description was made complete.

### Amendment trigger

Re-read when TLS lands (V-77); when a user can store a provider credential (V-78); if a
second provider is added, at which point the question is whether `ProviderConfig` was the
right place for the shared parts; if a provider ever needs to be reachable without a
credential; if anything else in the tree grows a `Default` that quietly decides whether a
platform capability is present; or if the prompt framing is actually versioned, at which
point `prompt_hash` becomes a real hash rather than the placeholder it is today.

---

<a id="adr-0043"></a>

## ADR-0043 — Continuation is an explicit operation, not a widened claim

**Status.** **Decided and now implemented.** `AwaitingNextStep` is advanced only by
`TaskRepository::claim_next_step()`. The generic claim path (`claim()` / `take_lease()` /
`claim_specific()`) remains `Pending`-only, and `idx_tasks_claimable` was not widened.

**Amendment, 2026-10-06 — the orchestration exists.** ADR-0047 closes the "recorded" this
decision left open, and the "explicit operation, not a widened claim" half of the title is
what it delivered: `task/continue` is the sole production caller of `claim_next_step()`, one
boundary per call, and it does not execute. Three facts surfaced while doing it, none of them
design choices: no task could reach a boundary at all because `max_steps` defaulted to 1 and
nothing could set it; `task_approvals` was keyed `(task_id, attempt_no)` while `attempt_no`
restarts per step, so a second step's approval was silently discarded (schema 10); and no
capability other than a sandboxed Tier-1 one verifies, which is why reaching a boundary is
sandbox evidence.

**Amendment, 2026-10-05 — "implemented" overstated this.** As of `HEAD`, the *governance
primitive* is complete and tested: the state exists, `claim_next_step()` exists,
step-scoped attempts and approvals exist, and the digest binds `step_no` (ADR-0037, V-83).
**No production code calls it.** `orxnud-daemon` exposes no IPC method that reaches
`claim_next_step`, and `grep -rn claim_next_step crates --include=*.rs` outside
`task_repo.rs` returns nothing. So a multi-step task stops at the boundary by design. The
requirement recorded below stands, and V-84 is where a reader should confirm it is still
unmet.

**Context.** Stage 3d made `AwaitingNextStep -> Running` claimable. The obvious alternative
was to extend the existing claim query so a polling worker would pick boundaries up
alongside fresh work. That is one line of SQL and a much larger decision.

**Decision.** Continuation stays a separate, explicit operation.

**Why.** Widening the generic claim would assert that *any* worker which sees a boundary is
entitled to advance it. That is a new scheduling contract, not a composition detail, and it
would drag in three questions the composition work never had to answer: what
`Pending`/`AwaitingNextStep` coexistence means for priority and ordering, whether every
existing worker implementation understands a state it was not written for, and whether
automatic discovery is desirable at all. It also fails the rule this project keeps applying
to authority — new behaviour should not appear merely because an existing generic path was
widened.

The two paths are now deliberately asymmetric, and the asymmetry is the point:

```text
Pending            -> generic worker claim()
AwaitingNextStep   -> explicit claim_next_step()
```

**Consequence, recorded as an orchestration requirement.** A production execution loop must
explicitly resume `AwaitingNextStep` and must never rely on `claim()` polling to find a
boundary. Until such a loop exists, a multi-step task stops at the boundary by design rather
than by accident. See V-84.

---

<a id="adr-0044"></a>

## ADR-0044 — Observation is governed: approved reads, and a context that carries no content

**Status.** **Decided. The governance core is implemented; the runtime wiring is
deliberately absent.**

**Note, 2026-10-06.** ADR-0047 delivered the *continuation* wiring, which is the first
routine path that shows a model anything about earlier steps. It did not change this
decision: `PriorStepContext` still carries step number, status and workspace-relative
artifact names and nothing else, and `prior_step_context_carries_status_and_names_but_
never_content` now asserts that shape directly so a later content field cannot be added
without failing a test.

**Amendment, 2026-10-06 — the observation wiring has landed.** ADR-0048 wires it, and
Decision 2's content boundary is now enforced in the production path rather than holding only
because nothing was wired. Two things did **not** change. `PriorStepContext` is untouched: the
approved content travels on `ProposalContext::disclosures`, a second channel with a different
lifetime and different provenance, so the two cannot be conflated or widened together. And
`3c8a413` remains the last commit at which no workspace content could reach a provider — which
is now the *history* rather than the present, and the reason that entry exists.

**Amendment, 2026-10-05.** "Implementation begins in Stage 4" understated what shipped.
At `HEAD` both mechanisms exist and are tested: `filesystem/read-text` is a registered
Tier-1 capability (`read_text.rs`, 1045 lines, 34 tests including 12 against a real
sandbox), and `PriorStepContext` is derived from durable rows and carried into the provider
request (29 `prior_step` tests). What did **not** exist at `HEAD` when this was written is the wiring: `orxnud-daemon`'s
runtime neither read nor wrote an `ObservationStore`, so a model could *propose* a read and
has nowhere to receive the bytes. That absence was deliberate — `3c8a413` names itself the
rollback point immediately before moving approved workspace content to a remote provider —
and it meant ADR-0044 Decision 2's content boundary held **in practice** at the time. ADR-0048
now makes it hold *by construction*. See
V-84 for the parallel gap on continuation and ADR-0045 for the disclosure decision this
one forced.

**Context.** Stage 3 gave a task multiple logical steps, each with a durable result. Until
now the model was blind after its first proposal: it could not see what an earlier step
produced, so a second step was a guess. Stage 4 closes that with two mechanisms — a
`filesystem/read-text` capability, and a `PriorStepContext` carrying earlier steps into the
proposal prompt.

Either one alone is insufficient. `read-text` with no context is a capability the model has
no reason to call; context with no `read-text` would have to push content to the model.

**Decision 1 — `filesystem/read-text` is `RiskClass::High` and requires human approval.**

The same posture as `filesystem/write-text`, and deliberately so. Reading is disclosure. A
file's contents are workspace data, and `read-text` is *the* mechanism by which the model
observes prior-step output, so a lower risk class would create the project's first
capability whose entire purpose is to release information to a party that has not been
individually asked. The cost is a human round trip per observation, paid on purpose.

**Decision 2 — `PriorStepContext` carries step number, status and artifact paths. Never
file contents, never prior `structured_output`, never prior `verification` text.**

This is the first egress of task-derived data to a remote provider, so the default is what
the model needs to *decide* rather than what it might want to *have*. Step numbers and
statuses say what happened; artifact paths say what exists. The content behind those paths
is reached by `read-text`, which means every byte of it passes the approval path in
Decision 1.

The alternative — including `structured_output` — was rejected for a specific reason rather
than a general one: `structured_output` is **untrusted content by construction**. It is
whatever an adapter claimed, and adapters can lie. Forwarding it into a prompt makes it
prompt material, and prompt material is instruction-shaped. Excluding it means the only
workspace content that ever reaches the model is content a human approved a specific read
for, fetched one deliberate call at a time.

**Consequences.**

* The model learns *that* step 1 produced `a.txt`, then pulls `a.txt` deliberately. More
  round trips; the content boundary stays inside the approval path.
* Prior steps cannot be summarised by the runtime on the model's behalf, because a summary
  would reintroduce the content this decision excludes.
* `PriorStepContext` is derived from `task_step_results` at request time and is **not
  durable**: it is a projection of committed state, not a new record of it.

---

<a id="adr-0045"></a>

## ADR-0045 — One approval, two acts: a read and its disclosure to a provider identity

**Status.** **Decided. Governance core implemented; runtime wiring deliberately absent.**

This record exists because `crates/orxnud-daemon/src/observation.rs` cites it, and the
decision is not covered by any earlier ADR. It was made and implemented in Stage 4c; this
entry registers it. Nothing here is being decided for the first time — the rationale is the
module's own documentation (`observation.rs:1-35`) and the evidence is its 29 tests.

**Context.** ADR-0044 established that `filesystem/read-text` is `RiskClass::High` and
requires human approval, and that `PriorStepContext` carries metadata only. That leaves the
content with nowhere to go: the model can *propose* a read and then has no channel to receive
what it read. Solving that is what forces the question this ADR answers.

**Decision 1 — one approval covers two acts: the local read, and the disclosure of its
result to the provider identity that asked for the read.**

This is the project's first case of a single human approval authorising both an action on
this machine and an egress to a third party. It is stated explicitly because the alternative
is the more defensible-looking design: a *separate* approval for the disclosure. That was
rejected for a specific reason rather than a general one — a second prompt for the same bytes
trains the user to click through prompts, and the two acts are not independently
separable: the bytes exist only because the read happened, and withholding them would make
the approved read pointless. The cost is accepted and is the same cost ADR-0044 Decision 1
accepts: a human round trip per observation, paid on purpose.

**Decision 2 — the authorisation is bound to `(endpoint, model)`, not to the model string.**

Comparing the model alone would let a re-pointed endpoint inherit an approval given to the
old one, which is precisely the substitution the rule exists to prevent. `ProviderIdentity`
canonicalises endpoint spellings so cosmetic differences do not refuse a legitimate match,
and `matches()` requires both halves.

**Decision 3 — the disclosure gets its own audit correlation, minted internally.**

`DisclosureRecord` renders as an audit record with `capability = "orxnud.policy/disclose"`,
the **human who approved the read** as the actor, and a correlation distinct from the read's
own. Minting it inside the record is what makes it unforgeable from outside:
`a_disclosure_correlation_cannot_be_made_to_equal_its_parent` asserts the invariant, so a
disclosure can neither close nor be closed by the read's authorisation record. The audit
detail is bounded and content-free — identifiers, a byte count, and the canonical
destination.

**Decision 4 — nothing here is durable.**

Observations live in daemon process memory, are consumed by exactly one proposal, and expire
on a TTL (15 min, 8 entries per task, 32 KiB whole-blob ceiling; a truncated blob is dropped
rather than released). A restart destroys them and the model re-proposes the read. That is
fail-safe: retaining workspace content across restarts is the thing this design exists to
avoid. `PriorStepContext` and `EphemeralObservation` are deliberately two channels and are
not conflated — the first is durable metadata, the second is memory-only content.

**Evidence.** 29 tests in `observation.rs` — 19 for the store, 8 for disclosure, 2 for the
ceiling — covering task isolation, `(endpoint, model)` binding including a re-pointed
endpoint and a changed model, consume-once, whole-blob budget, TTL, and correlation
distinctness.

**Consequences.**

* Approving a read is approving its transmission. The prompt and the register entry for this
  capability must say so; a user who does not know is not consenting to what was asked.
* `orxnud-daemon`'s runtime does not yet read or write an `ObservationStore`, so this
  mechanism is unreachable today. That is deliberate and is the rollback point immediately
  before the most sensitive change in the project. Until the wiring lands, no workspace
  content can reach a provider, and the ADR-0044 Decision 2 boundary is intact in practice.

---

<a id="adr-0046"></a>

## ADR-0046 — A missing host guarantee is a refusal to assert, not a test to skip

**Status.** **Decided and implemented.** The capability report, the preflight, the
environment-aware end-to-end assertions, and the container lane are all in the tree. The
positive Tier-1 evidence depends on the container reproducing the production configuration,
which CI verifies on every run of that lane and fails if it stops doing so.

**Context.** Two end-to-end tests failed on `origin/main` with

```text
the execution backend cannot establish the required sandbox guarantees
(missing: the requested sandbox guarantees)
```

and nothing in the log said why. The cause is not a defect: a GitHub-hosted Linux runner
ships `bwrap` and cannot use it, so `BwrapRunner::probe()` reports no guarantees and every
Tier-1 dispatch is correctly refused. Three things were wrong with how that surfaced.

1. `host_backend_name()` answers a **compile-time** question, so the runner reported
   `sandbox backend: bwrap` while being able to isolate nothing. A host-level
   `bwrap --version` check would have reported success too.
2. The tests asserted **successful execution unconditionally**, so a correct refusal was
   recorded as a failure — and CI fail-fasts, so two failures were hiding six more.
3. The gate those tests carried was `#[cfg_attr(not(target_os = "linux"), ignore)]`, which
   asks a *platform* question rather than a *capability* one, and is an `ignore`. A skip
   teaches nothing, and the interesting host state — a Linux machine that cannot sandbox —
   was therefore untested everywhere.

**Decision 1 — the sandbox contract is unchanged, and nothing here may weaken it.**

No default is relaxed, no requirement becomes `BestEffort`, and no host is exempted. A
host that cannot isolate still refuses every Tier-1 capability, before a credential
resolves and before a process exists (ADR-0035, V-49). What changes is only which
assertion the test suite makes about a given host.

**Decision 2 — the test asserts the property that is true of the host it is running on.**

Where isolation is available: successful, verified, sandboxed execution, unchanged. Where it
is not: a **positively asserted** refusal — non-zero exit, the missing guarantee named, and
nothing written. Not a skip, not a tolerated failure, not a mock. The refusal branch checks
*why* it failed, so "it failed somehow" can never be mistaken for "it refused because it
could not isolate", and that branch is exercised on every incapable host.

The invariant this preserves:

> OpenRayNux never executes Tier-1 work merely because CI wants the test to pass.

It holds structurally rather than by convention: on a host that cannot isolate, the
assertable outcome *is* the refusal, so the code path that would execute Tier-1 work is
unreachable and unasserted.

**Decision 3 — one source of truth for the capability answer, surfaced where it is needed.**

`orxnud-platform-sandbox::host_capability()` reads the runner's own
`available_guarantees()` and runs the same `AvailableGuarantees::check` the dispatcher runs.
It adds no second probe, because a diagnostic that could disagree with the dispatch that
refused a capability would be worse than none. It is reported through `daemon/status`,
`orxnud daemon --doctor` and `orxnuctl doctor`, and read by the tests from the same place a
user would.

**Decision 4 — positive Tier-1 evidence runs in a container that must look like
production, and the lane fails if it does not.**

The obvious fix — run the Tier-1 suites in a `--privileged` container — was measured and
rejected. `--cap-add=SYS_ADMIN` and `--privileged` both make the probe pass, and inside
either, `bwrap` creates **no user namespace**: the identity is the full map
`0 0 4294967295` with the container's capabilities, against the production
`1000 0 1` with none. That is a materially weaker claim about the boundary and is not
evidence that the path users run works.

What works, and is used instead, grants nothing: `--security-opt seccomp=unconfined`
(Docker's default seccomp returns EPERM for `unshare(CLONE_NEWUSER)`) and
`--security-opt systempaths=unconfined` (Docker's masked `/proc` paths make a nested procfs
mount illegal). The tests then run as an unprivileged uid with every capability dropped, so
`bwrap` has no choice but to nest a user namespace. `preflight --require` runs first in that
lane and exits non-zero unless a Tier-1 capability can be sandboxed there **and** the
observed identity is the nested shape, so the lane cannot pass quietly in a weaker
configuration.

**Decision 5 — the host lane reports rather than gates.**

The `linux-gates` job prints the capability **before** the gates, because a diagnostic
after a failing step is a diagnostic nobody reads. It is not `--require`: that host is
allowed to be incapable, and its Tier-1 result is a correct refusal.

**Consequences.**

* Two tests stopped being platform-gated and are now asserted on every platform, including
  the ones that previously skipped.
* `orxnuctl doctor` now answers "can this host run a Tier-1 capability", which is the
  question an operator with a refusal actually has. It says `unknown` when no daemon
  answers, never `no`.
* `doctor` accepts `--endpoint`. `main` already read `invocation.endpoint` on that path, so
  the parser had been refusing a flag the code depended on and `doctor` could only observe
  the default endpoint.
* Windows remains **NOT_PROVEN** for isolation, and none of this changes that. The container
  is Linux evidence about the Linux configuration.


---

## ADR-0047 — A continuation is one boundary and one proposal, and the caller decides whether to take another

**Status.** **Decided and implemented.** `task/continue` and `orxnuctl task continue` ship;
`tests/continuation.rs` and the `cli_e2e` loop are the evidence.

**Context.** ADR-0043 recorded that a multi-step task continues by *executing a recorded
step and proposing a governed next step*, and left "recorded" as the open question. That
question closed with three findings from the code rather than from preference.

First, **the primitives already existed and nothing reached them.**
`complete_verified_step` moves a task to `AwaitingNextStep` and resets `attempts`; the
targeted claim `claim_next_step` is the only way across that boundary; `propose_action`
binds a proposal to `steps_completed + 1`. `claim_next_step` had **no caller at all**.

Second, **no task could ever reach a boundary.** `max_steps` defaults to 1 in the schema
and `NewTask` had no field for it, so every task created through `task/create` completed
on its first verified effect. A correct continuation implementation would have been
unreachable code.

Third, **the approvals table could not represent two steps of one task.**
`complete_verified_step` resets the attempt counter at a boundary, so `attempt_no` restarts
at 1 for each logical step and step 2's first attempt is `(task_id, 1)` exactly as step 1's
was. `task_approvals` was keyed `PRIMARY KEY (task_id, attempt_no)` — the key stage 2 got
wrong for `task_proposals` and which the composition correction (ADR-0043's predecessor)
fixed there but not here. `record_approval` is an `INSERT OR IGNORE`, so step 2's approval
was silently discarded and the lookup returned step 1's row. The only symptom was an
`approval-step-mismatch` refusal blaming a mismatch the caller had not caused. Migration
10 rebuilds the table keyed `(task_id, step_no, attempt_no)`, the same treatment
`MIGRATION_ATTEMPT_STEP_SCOPE` gave `task_attempts`.

**Problem.** How does a task reach its second step, without giving the model a way to do
anything it could not already do?

**Options considered.**

1. *A background driver that runs a task to completion.* Rejected. It needs somewhere to
   record "this is the Nth retry", a rule for when to stop asking a model that keeps
   failing, and a resume point after a crash — three decisions that each want their own
   record and their own review, in the one component with no user present to object.
2. *Fold advancement into the existing generic claim.* Rejected. ADR-0043 and V-84 both
   record that advancing a boundary is a distinct operation from picking up fresh work;
   widening the generic claim would assert that any polling worker which *observes* a
   boundary is entitled to advance it. `claim_next_step` stays separate and stays the only
   route.
3. *Extend the proposal to an orchestrated capability.* Rejected on the same grounds as
   ADR-0037: it would put execution planning inside the capability registry.
4. *One explicit call that claims, asks and proposes.* **Chosen.**

**Decision 1 — one call, one boundary, no execution.**

`task/continue` does exactly three things: claim the next logical step, ask the provider
what it should do, persist the result as an ordinary durable proposal. It then stops, in
`WaitingForUser`, exactly where `task/ai-propose` leaves a task.

It deliberately does **not** execute. That is what makes "the governed path is the only
path" a property of the code rather than a claim about it: a continued step re-enters
`task/ai-propose` → durable proposal → approval → dispatcher → sandbox → verification →
audit with no continuation-specific shortcut, and `tests/continuation.rs` asserts that an
unapproved continuation does not run.

**Decision 2 — the caller decides whether there is another boundary.**

The orchestrator is a step, not a driver. There is no loop here to bound, which is the
point: each call is one boundary and at most one provider call, and `max_steps` remains the
only thing that bounds a task's length. The alternative would have required a durable retry
counter and a new policy for when to stop asking, and neither is a decision this change
should make on its own.

**Decision 3 — the terminal answer is a declared shape, not a magic capability.**

`{"done": true, "summary": "..."}` is a **second declared shape**, selected by the presence
of a `done` key, so `{"done": true, "capability": ...}` is refused as unreadable rather than
resolved in favour of one half. `ProposalOutcome` names both cases. Nothing about `done` is a
capability: it carries no target, no parameters and no authority, so there is nothing in it
that could have been used to smuggle an action past the allowlist — which is asserted
directly in `a_done_answer_cannot_carry_an_action_and_contradictions_are_refused`.

**Decision 4 — the model proposes completion; the engine disposes.**

`done` is not a state transition the model performs. The runtime completes the task
through the same fenced `complete_task_with` every other terminal report uses, holding a
live lease, with the reason recorded on the task and the model named in the reply. The
model answered a question the runtime asked; it did not move the task, approve anything, or
assert that an effect succeeded. That distinction is the whole reason the answer is a
separate shape rather than a capability — a capability could be *executed*.

`steps_completed` does not move, because no effect was verified. The task finished without
doing another thing, which is different from having done another thing.

**Decision 5 — a failed ask returns the boundary.**

The claim commits, then the model is asked, then the proposal commits: a network call
cannot be held inside the single SQLite write transaction. If the ask or the write fails,
`release_to_boundary` puts the task back on `AwaitingNextStep` and releases the lease.
Without it, one provider outage would strand a task holding a lease for a step that will
never be proposed, and since `task/continue` only ever acts at a boundary, continuation
could never be retried. A crash between the two is recoverable the ordinary way: the lease
expires and the task returns to a claimable boundary.

**Decision 6 — `max_steps` is a caller-set field, bounded, never clamped.**

`task/create` takes an optional `max_steps`, defaulting to one so no existing task changes
behaviour. It is validated through the store's own `validate_max_steps` and refused above
64 (`MAX_MAX_STEPS`). Refused rather than clamped at both ends: a silent clamp would let a
caller ask for three steps, get one, and never learn, and `max_steps = 0` is a task that can
never finish. The wire stays strict — the CLI parses what a person types and sends a JSON
number, so there is one spelling of a number and the daemon owns the bound.

**Trade-offs.**

* Running a task to completion is a sequence of `approve` / `execute` / `continue` calls,
  not one call. That is more work for a user than a driver would be, and it is the cost of
  not having a component nobody supervises.
* A caller in a loop will keep asking a model that keeps failing, and nothing stops it. Each
  iteration is bounded and visible; nothing is bounded *across* iterations, because a retry
  policy is a decision this change declines to make.
* `max_steps` reaching 64 is refused even though `validate_max_steps` would accept it. The
  store's invariant is a lower bound; the daemon adds an upper one.

**Consequences.**

* Schema **10**. Fresh and migrated databases converge because migrations run in order.
* `Method::ALL` is 15. `orxnuctl task continue` and `task create --max-steps` are new.
* `PriorStepContext` is unchanged and still carries status and workspace-relative artifact
  names only. Continuation is the first routine path that shows a model anything about
  earlier steps, so `prior_step_context_carries_status_and_names_but_never_content` asserts
  the shape directly: no content, no verification text, no absolute path (ADR-0044).
* Reaching a boundary needs a *verified* effect, and `text/word-count` deliberately returns
  `Undetermined` rather than `Verified`. So there is **no host-independent way** to reach a
  boundary, and the five continuation tests that execute are sandbox evidence: named in the
  G9 exclusion list, run in the ADR-0046 container. The four that do not execute run
  everywhere.

**Rejected alternatives.**

* *Let `max_steps` keep defaulting to 1 and add a way to change it later.* The feature would
  ship with no way to reach the code it adds.
* *Model-signalled completion as a reserved capability id.* A magic string that would have to
  be registered, allow-listed and dispatched in order to mean *nothing happens* — and would
  then be approvable and executable like any other.
* *Complete the task when the model's `done` arrives without an intervening claim.* Would
  complete from a state the model has not been given a lease on.

**Revisit conditions.**

* Revisit if a supervisor appears that could own a retry budget and a stop rule.
* Revisit if `max_steps` proves too coarse a bound and per-step bounds are needed.
* Revisit if `attempt_no` is ever made global rather than per-step, which would remove the
  reason migration 10 exists.
* Revisit if a terminal signal ever needs to carry more than a bounded, non-authoritative
  summary.


---

<a id="adr-0048"></a>

## ADR-0048 — An observation is released once, across one boundary, to the identity that asked for the read

**Status.** **Decided and implemented.** `task/continue` now discloses; ADR-0045's decision is
unchanged and this record adds the four things it deliberately did not decide.

**Context.** ADR-0044 left the observation wiring deliberately absent and `3c8a413` named
itself the rollback point immediately before workspace content moved to a third party. ADR-0045
decided what an approval would cover once that happened. What was left open was *where the
bytes may go and who may cause them to*: the store keyed on `(task, provider identity)` and
nothing else, the runtime called none of it, and — the part that turned out to matter most —
`filesystem/read-text` was not reachable at all.

**The exact question this answers.** Not "can we pass bytes", but: *what exact bytes, under
what exact authorisation, to what exact destination, at what exact step, may leave this
machine?*

**Answer, as implemented.** The `ExecutionOutcome::Succeeded` output of a
`filesystem/read-text` dispatch whose **verifier returned `Verified`**, proposed by an
`Actor::Ai` naming the model this daemon is still configured to ask, with a
workspace-relative target — released into **one** provider request for **the immediately
following logical step** of **the same task**, to the **identical `(canonical endpoint,
model)`** identity, as **whole blobs** under `min(caller budget, 32 KiB)`, at most 8 retained
and only for 15 minutes, **consumed on release** and **never durable**.

Nothing else may leave: not verifier evidence, not subprocess stdout or stderr, not audit
records, not approval digests, not credentials, not absolute paths, not another task's or
another step's content. `PriorStepContext` is unchanged and still carries step number, status
and workspace-relative artifact names only — the content travels on a second, separate channel
so widening one cannot widen the other.

**Decision 1 — an observation informs exactly the next step, and never a later one.**

`Observation` gains `step_no`, and eligibility is `observation.step_no + 1 == requesting
step_no`.

The store previously had no step at all, so a retained observation could inform *any* later
proposal on the task — which turns one approval into standing permission for every proposal the
task will ever make, including ones made after other steps have run. The rule is `+1` and not
equality because the read and the proposal it informs are different acts on different steps.
This is a narrowing of an existing type, not a new field for symmetry.

**Decision 2 — a provider must state its own destination, and the default is to decline.**

`ProposalProvider` gains `fn destination(&self) -> Option<ProviderIdentity>`, **defaulting to
`None`**, and `None` releases nothing. A provider that cannot say where it sends gets
metadata-only requests, which is the same position a daemon with no provider is in — not a
licence to infer one from configuration the caller happens to hold.

This gives the provider knowledge of exactly one thing about itself. It does **not** get the
task store, the observation store, the approval ledger, policy, audit, or the filesystem:
the authorised request is assembled before the trait is touched. The alternative — passing the
`ProviderConfig` down from `main` — was rejected because the provider's own configured
endpoint is the authoritative answer to "where does this send", and a value reconstructed at
the call site is a value that can drift from it.

**Decision 3 — a disclosure is recorded before the bytes are sent, and a record that cannot be
written refuses the disclosure.**

The disclosure audit record is appended before the provider request, not after the response.
A record written afterwards can miss one that happened: the process can die between sending and
receiving, and there is then no way to know whether the bytes left. Writing first means the log
can over-report by at most one record whose transmission failed — the direction that tells an
operator *more* than happened. Under-reporting is the failure the audit exists to prevent.

Consequently a failed append is a **refusal to disclose** (`disclosure-audit-unavailable`),
not a disclosure with a logging problem.

**Decision 4 — consumption happens before the request, so a provider outage costs the content
and a restart costs nothing.**

`ObservationStore::take_for` consumes what it releases, and that happens while the context is
being assembled, before the provider is called. A provider failure therefore loses the
observation: the retry at the same boundary proposes without it. This is the documented
recovery — the model re-proposes the read — and it is fail-safe in the direction that matters,
because the alternative (releasing the bytes back into the store on failure) is a resurrection
path for workspace content, which is precisely what a non-durable store exists to prevent.

On restart there is nothing to resurrect: the store is process memory. **Single-use is therefore
enforced by erasure rather than by a durable "consumed" flag**, which is a stronger form of the
property than a flag a crash could roll back.

**The defect this slice found, and why it is called out rather than filed as bookkeeping.**

`filesystem/read-text` was in `shipped_declarations()`, so the dispatcher's registry held it and
`ask_next_step`'s menu — walked from the registry — **offered it to the model**. Policy had no
declaration for it in `SHIPPED_POLICY` and refused every attempt as `unknown-capability`. A
capability the menu advertises and the pipeline always refuses is not a governed capability; it
is a broken promise, and it meant the entire observation subsystem was unreachable in
production for a reason that had nothing to do with the decision to leave it unwired.

Adding the entry is what makes the two lists agree. It is called out here because it is the
first time this build enables a capability whose output can leave the machine, and the security
posture changed with it: `read-text` is `RiskClass::High`, needs a standing grant *and* a
single-use, time-boxed, parameter-bound approval, so every read is a human round trip. Its
output is declared ephemeral, so `structured_output` is dropped and the bytes exist only in
memory.

**What is deliberately still absent.**

* No memory subsystem. An observation informs one explicitly authorised proposal and is gone.
  There is no retrieval, no semantic search, no vectors, no embeddings, no summarisation cache.
* No unrestricted content export. Only a verified, approved read's bytes, once.
* No new `TaskState`. The disclosure happens while the task is `Running`, between claiming the
  boundary and persisting the proposal, which the existing states already express.
* No observation identifier, anywhere. The store is selected by `(task, step, provider
  identity)` and by nothing else, so there is no selector for a request to iterate. A model
  cannot choose an observation by naming one.

**Evidence.** `crates/orxnud-daemon/tests/disclosure.rs` (10 socket tests), 9 gate tests in
`runtime.rs::read_retention_gate`, 5 new store tests in `observation.rs`, and 3 rendering and
trait tests moved next to the code they exercise. Mutation-checked: breaking the task check, the
step check, the identity check, single-use consumption, the size limit, the verification
requirement, or the audit record each fails the suite.

**Revisit conditions.**

* Revisit if a supervisor appears that could own an observation's lifetime durably — the
  erasure argument above is what would have to be traded away.
* Revisit if reads stop being the only ephemeral-output capability, since the retention path
  selects on `output_is_ephemeral` rather than on a capability id and would then cover more.
* Revisit if `attempt_no` ever becomes global rather than per-step, which is the invariant the
  disclosure's step arithmetic rests on.


---

<a id="adr-0049"></a>

## ADR-0049 — An expired approval is not a decision, and a proposal whose approval lapsed is not a dead end

**Status.** **Decided and implemented.** Closes V-82 and the expiry half of Q-OPEN-14. The
**scoped session grant** half of that question is explicitly **not** decided here.

**Context.** V-82 recorded a liveness gap found by an operator during live verification, and
deliberately left unfixed because "what does an expired-but-unconsumed approval *mean* —
reclaimable, or terminal?" was called a policy question rather than a bug fix. That was the
right call at the time and the reason it needed an ADR.

**The defect, as reproduced before any edit.** Against the real store over a real socket:

```
approve(ttl_ms: 0)      -> success. expires_at == issued_at. proposal status := "approved"
approve(ttl_ms: 60_000) -> refused: "proposal-already-decided"
task/propose            -> refused: "internal"          (INTERNAL_ERROR, see below)
task/execute            -> refused: "approval-expired"
task/list               -> state "running", lease held by w1 for 30s
task_proposals          -> ["status=approved"]          (terminal)
task_approvals          -> ["expires==issued, consumed=None"]
```

Three defects, one of which the register did not record:

1. **The liveness gap.** The proposal's `approved` status recorded *the decision to approve*
   and was then read as *the authority to execute*. Expiry is a property of the approval row,
   not of the decision, and nothing could ever bring the two apart again.
2. **An over-short TTL was not the only route.** An approval that expired *while the task
   waited* — the ordinary case, since a human wait is unbounded and a TTL is not — produced
   exactly the same dead end. The register mentioned it in passing; reproducing it showed it
   was the *more* common route.
3. **Every expired attempt additionally parked the task.** `task/execute` took the execution
   lease *before* the policy stage refused, flipping the task to `running` under a fresh
   30-second lease. So even the refusal was followed by a state in which the task could not be
   executed again until that lease expired.

A fourth, smaller thing: a legitimate `task/propose` in that state answered
`INTERNAL_ERROR` / `reason: "internal"`, because `TaskFault::Engine` maps there. INTERNAL_ERROR
tells an operator the server is broken, which is the wrong thing to say about a client action.
**Fixed, separately and later, by ADR-0050.** It was left alone here because it is not this
defect's: it affects every task route, and a fix confined to the expiry paths would have left
the same lie in place everywhere else. The reproduction above is what identified it as
cross-cutting, and the expiry path merely happened to reach it first.

**Decision 1 — an approval that is expired on arrival is never minted.**

`capability/approve` checks `is_valid_at(now)` on the record it has just built, *before* any
write. A TTL that leaves the approval already expired is refused with `approval-expired`, and
the proposal stays `pending` with the task in `waiting-for-user`.

This removes the dead end at its cheapest point rather than making it recoverable afterwards:
the one case an operator can cause by mistyping a flag can no longer occur at all, and the same
call with a usable TTL simply works.

**Decision 2 — the proposal's status is the decision; the approval row is the authority.**

`task_proposals.status` keeps meaning "a decision was taken" and is **one-way**. Expiry is
evaluated lazily against `task_approvals.expires_at_ms` at both `capability/approve` and
`task/execute`. No new status, no new transition, and no background expiry worker.

The schema already declares `'expired'` as a proposal status and `decide_proposal` already
accepts it, and **neither is used** — deliberately. Expiry is not a decision anyone took, so
writing it into the decision column would be asserting something that did not happen, and
making the column two-way would buy a state the authority row already implies. The word stays
available and unused, and this record says why so nobody re-litigates it.

**Decision 3 — an expired, unconsumed approval may be replaced. A live or used one may not.**

`TaskRepository::record_approval_replacing_expired` is the single place that answers "may this
attempt be approved again?", and it answers from one IMMEDIATE transaction:

* **no prior row** → `Recorded`;
* **expired and unconsumed** → `ReplacedExpired`. The row is overwritten with a **new digest
  and a new expiry**. The old authority ceases to exist rather than being extended, so there is
  nothing left that could later be presented;
* **still live** → `Refused(AlreadyValid)`. This is what keeps an approval single-use in the
  sense that matters: a second `capability/approve` cannot silently supersede an unused one,
  so "the approval a client holds" and "the approval in the database" cannot diverge;
* **consumed, or the step has concluded** → `Refused(AlreadyConsumed)`.

Refusals are values rather than errors, so the caller reports which of the two reasons applies
instead of parsing prose, and the two map to two fixed wire reasons
(`approval-already-valid`, `approval-already-consumed`) because they ask a client to do
opposite things.

**Decision 4 — an expired approval is refused before the execution lease is taken.**

`task/execute` now checks `record.is_valid_at(now)` before `begin_approved_execution`, using
**the same `now`** that is then handed to the dispatcher and so to the policy stage. Two clock
reads here would be two chances to decide an authority question differently, which is the bug
class V-82 is. The policy stage's own `approval_expired` refusal is unchanged and remains the
authority; this check exists so that reaching it no longer costs the task a lease.

**Decision 5 — `task_approvals.consumed_at_ms` is now actually written.**

Found while implementing Decision 3 and worth recording on its own: the column was **never
written by anything in the daemon**. Single-use is enforced by the policy engine's spent-digest
ledger, written by `authorise`, and the task-domain copy was permanently `NULL` — a lookup on it
returns "not used" and means "nobody ever wrote it down". A security decision came to depend on
it, so `execute_proposal` now marks the row spent when the lease is taken, mirroring the
ledger. It is written at the same point the ledger is, and it is best-effort with a logged
error: the ledger is authoritative for single-use, so a reporting fault is not a reason to
refuse an otherwise-authorised execution.

The store's replacement guard additionally refuses when `steps_completed >= step_no`, read from
the task row it already has open. That is an independent confirmation of "this approval was
acted on", so the decision does not rest on a single write.

**The exact expiry boundary.** `ApprovalRecord::is_valid_at` is `now < expires_at_ms`, so an
approval is live on `[issued_at, expires_at)` and **expired at its expiry instant**. The store's
replacement check uses the same operator, so the two cannot disagree about a boundary instant.
`an_approval_is_expired_at_its_expiry_instant_and_not_one_millisecond_before` pins it, together
with zero and negative TTLs never being live.

**Concurrency.** Expiry is lazy: a property of a timestamp, evaluated where authority is
decided. No timer, no polling, no per-approval task, no scan of expired rows — so there is no
new subsystem and no hot-path cost beyond the read the replacement path already needs.

Two callers racing to replace the same expired approval produce **one replacement and one
refusal**, deterministically: the conditional `UPDATE` re-asserts both preconditions inside the
transaction, so the loser's `WHERE` no longer holds.

**Recovery is a human decision, and it stays one.** Nothing is re-approved automatically, no
approval is inherited by a retry, and the fresh approval is minted from the proposal's durable
`step_no` — so it binds the same logical step, the same capability, target and canonical
parameters, and is single-use and time-bounded exactly as the first one was.

**What this deliberately does not do.**

* **No scoped session grant.** Q-OPEN-14's other half is untouched. Recovery from an expiry is
  not a grant: it requires a human to approve again, and ADR-0049 does not shorten that.
* **No `ApprovalExpired` task state.** Existing states already express the situation: the task
  stays in `waiting-for-user`, which is exactly "waiting for a human to decide".
* **No renewal workflow, no approval service, no new authority path.** One store operation, one
  runtime check, one reordering.

**Evidence.** `crates/orxnud-daemon/tests/expiry.rs` (12), `task_repo.rs`'s
`replace_expired` module (7), and the rewritten `an_expired_approval_is_refused_and_writes_nothing`.

**Mutation-checked.** Reverting to the pre-fix behaviour fails the suite. So does accepting an
approval at its exact expiry instant, minting one already expired on arrival, letting an
expired approval reach the dispatcher, replacing a *used* approval, and dropping the expiry
precondition from the replacement's conditional update.

Two preconditions did **not** fail the suite when removed, and both are defence in depth rather
than the deciding guard: the store's early `now < prior_expires_at_ms` return (the `UPDATE`'s
`WHERE ... AND expires_at_ms <= ?now` decides the same case and was shown to be caught), and the
`AND consumed_at_ms IS NULL` clause (the early consumed return above it decides that case
inside the same transaction). Recorded rather than quietly omitted, because "we mutated it and
nothing happened" is only informative if you say which.

**Revisit conditions.**

* Revisit if approvals ever become durable across a restart *and* the ledger stops being
  authoritative, since `consumed_at_ms` would then have to carry the single-use property alone.
* Revisit if the proposal status ever becomes two-way, which would put `decided_at_ms` in
  question and reopen Decision 2.
* Revisit if a scoped grant is ever adopted (Q-OPEN-14's open half): it would change what an
  approval *is*, and this record's "one approval, one attempt" framing would need restating
  rather than extending.
* ~~Revisit if `TaskFault::Engine` stops mapping to `INTERNAL_ERROR` for ordinary state
  refusals.~~ **It did, under ADR-0050**, which replaced the flat mapping with four codes in the
  server-reserved band. Condition closed. What would reopen it is a *fifth* class of refusal
  with no honest home among not-found, conflict, forbidden or unavailable -- at which point the
  question is whether the class or the code count grows, not whether the default becomes
  `INTERNAL_ERROR` again.

<a id="adr-0050"></a>

## ADR-0050 — INTERNAL_ERROR means nothing the caller did could change the outcome

**Status.** **Decided and implemented.** Closes V-89. Independent of ADR-0049: that record
found this defect on the expiry path and deliberately left it, because it is wider than
expiry.

**Context.** ADR-0049 recorded, in passing and as "a fourth, smaller thing", that a
legitimate `task/propose` answered `INTERNAL_ERROR` / `reason: "internal"`. Reproducing V-82
over a real socket confirmed it was not an expiry-path quirk. It was the *only* answer an
ordinary wrong-state refusal had.

The chain that produced it had four separate breaks, and the mapping was the last of them:

1. `TaskRepoError` distinguished `NotFound`, `NoSuchProposal`, `AlreadyExists`,
   `ProposalNotInState` and `InvalidComposition`, and `From<TaskRepoError> for EngineError`
   collapsed every one of them into `EngineErrorKind::InvalidInput`. The store's own
   distinctions were discarded at the crate boundary.
2. `TaskService` converted an `EngineError` into `TaskFault::Engine(String)`. The kind was
   dropped there, so by the time `task_fault()` ran there was nothing to classify with.
3. `task_fault()` mapped both `TaskFault::Engine` and `TaskFault::Stopped` to
   `RequestError::Refused`, and `Refused` mapped to `INTERNAL_ERROR`. Stopping is not a
   fault either.
4. Separately and independently, `RequestError::Declined` — used at every direct semantic
   refusal — mapped to `INVALID_REQUEST`, conflating "you named something absent", "the name
   is taken", "you are not authorised" and "this is not configured" into one code whose only
   instruction is *edit your request*.

A fifth defect was found while fixing the fourth, and is the more interesting one.
`TaskRepository::propose_action()` read `lease_holder` as `String` while the schema declares it
nullable, with the constraint `(holder IS NULL) = (expires IS NULL)`. For any task holding no
lease the read failed with `Invalid column type Null at index: 1, name: lease_holder` — so the
state check *below* it never ran, and the caller saw a storage failure instead of the conflict
that check existed to produce. Every existing test passed because they all proposed while
holding a lease, where the column is non-null. **A type error in a query silently converted one
error class into another;** the test suite's shape, not its assertions, was why it survived.

**Decision 1 — four codes, chosen by recovery rather than by cause.**

| code | class | the caller's recovery |
|---|---|---|
| `-32040` | `RESOURCE_NOT_FOUND` | refresh its view |
| `-32041` | `CONFLICT` | re-read the state and decide again |
| `-32042` | `FORBIDDEN` | obtain a new human decision |
| `-32043` | `ENVIRONMENT_UNAVAILABLE` | fix configuration, add a credential, wait |

They live in the server-reserved band (`-32099..=-32020`), spaced from the existing `-32022`,
so a client can recognise "a code this server defines" without a registry and nothing existing
had to move. The numeric values are part of the published contract.

The grouping is by *recovery*, which is why all wrong-state refusals share one code: whether a
task is completed, cancelled, already claimed, mid-proposal, or at a stale boundary, the client
does the same thing next. Splitting them by code would hand a client a distinction it cannot
act on. The distinctions that *are* actionable travel in `data.reason`.

**Decision 2 — `INTERNAL_ERROR` is now a positive claim, not a fallback.**

It is returned for storage and corruption faults, and for an unanticipated cause. A path that
cannot classify a failure now fails the *tests*, not the reader's log: `task_fault()` has no
fallback arm that dumps an unrecognised fault into `INTERNAL_ERROR`. The property is stated as
one sentence so it can be checked: **INTERNAL_ERROR means nothing the caller did can change the
outcome.** A daemon that is stopping reports `ENVIRONMENT_UNAVAILABLE`, not a fault.

**Decision 3 — `data.reason` is a word, `data.detail` is a sentence.**

`RequestError::Invalid` had been putting prose into the machine-readable field, so a client
wanting to classify a malformed request had to string-match English — the very dependence this
record exists to remove. All ~26 sites now emit the fixed word `invalid-request` as the reason
and keep the explanation in `data.detail`. Where the reason already *is* the refusal
(`ClaimRefusal::as_str`), `detail` is `None` rather than repeating it.

`ClaimRefusal` is the case that shows why this is a real contract and not a tidiness rule: the
coarse variant name is `not-claimable`, and the specific refusals are `not-found` (the task is
gone) and `not-claimable` (someone else has it). Both are `CONFLICT`; a client choosing between
"refresh" and "retry in a moment" branches on the reason, not the code.

**Decision 4 — `ProviderRefused` is an environment fact.**

It existed only to report that the *provider* could not be used: unconfigured, no credential,
unreachable, refusing. The daemon and its code are working; a dependency is absent. As
`INTERNAL_ERROR` this pointed an operator at a bug report when the fix is `configure` or
`doctor`. This was the single most misleading mapping in the chain, because it actively
redirects the reader away from the remedy.

`task/continue` and `task/ai-propose` check for a provider *before* they look at the task, so a
providerless daemon answers `ENVIRONMENT_UNAVAILABLE` even for a task that does not exist. That
is deliberate and is now tested: the dependency is missing either way, and the alternative would
imply the task exists.

**What is not claimed.** No task-state, approval, continuation, observation, disclosure,
authorization, sandbox or provider *semantics* changed — this record changes only which code
reports them. Successes are byte-identical. No new dependency, no cross-crate error enum, no
string matching on error text, and no raw SQL, host path, credential or content in any
refusal; `no_refusal_carries_content_a_host_path_or_a_credential` checks the last of those over a
refusal path with a real file behind it.

**Revisit conditions.**

* Revisit if a fifth class of refusal appears with no honest home among these four; the question
  is then whether the class count or the code count grows, never whether the default becomes
  `INTERNAL_ERROR` again.
* Revisit if the codes are ever extended past `-32099`, which would leave the reserved band and
  cost clients the registry-free recognition the band buys.
* Revisit if a client is ever given an approval it can replay: `FORBIDDEN` is chosen for
  single-use authority, and a replayable grant is a different recovery (`CONFLICT`).
* Revisit if `data.detail` grows a caller that trusts it as structured data. It is a sentence by
  contract; anything branchable belongs in `data.reason`.

**Evidence.** `crates/orxnud-daemon/tests/taxonomy.rs` — 10 tests driven through a real daemon
over a real socket, covering each class, the reason-word shape, redaction, a claim race and an
approval race — plus three unit tests in `runtime.rs` pinning the mappings a socket cannot reach.
Each defect above was reproduced against the real store before any edit, and the table below is
the before/after.

**What mutation checking could and could not confirm.** Eleven of thirteen mutations fail at
least one test. The two that do not are `TaskRepoError::{NotFound, NoSuchProposal}` and
`AlreadyExists` reaching `TaskCause`, which an instrumented `From` measured as **zero
occurrences across the whole workspace suite** -- every route that could observe them checks
existence first and answers directly. They are kept because a `From` impl should be total; the
honest statement is that they are currently unobservable, not that they are verified.

| refusal | before | after | reason |
|---|---|---|---|
| `task/propose` on a `waiting-for-user` task | `-32603` `internal` | `-32041` | `conflict` |
| `task/propose` for an unknown capability | `-32603` `internal` | `-32041` | `conflict` |
| `task/execute` for an unknown proposal | `-32600` prose | `-32040` | `proposal-not-found` |
| `task/claim` for a missing task | `-32041` `not-claimable` | `-32041` | `not-found` |
| `task/cancel`, `task/complete` for a missing task | `-32041` | `-32040` | `not-found` |
| `task/create` for a duplicate id | `-32041` | `-32041` | `already-exists` |
| `task/execute` on a decided proposal | `-32600` prose | `-32041` | `conflict` |
| `capability/approve` with `ttl_ms: 0` | `-32042` | `-32042` | `approval-expired` |
| `task/continue` off a boundary | `-32041` | `-32041` | `not-at-boundary` |
| `task/continue` with no provider | `-32603` `internal` | `-32043` | `provider-not-configured` |
| `task/ai-propose` with no provider | `-32603` `internal` | `-32043` | `provider-not-configured` |
| `task/create` with `max_steps: 0` | `-32600` prose in `reason` | `-32600` | `invalid-request` + detail |


---

## ADR-0050, amended — the sweep that closed V-90

**Status.** **Decided and implemented.** Closes V-90. The taxonomy below is unchanged; what
changed is that the code now obeys it.

**Context.** The taxonomy this record established shipped, and two routes did not obey it:
`capability/dispatch` reported an approval-digest mismatch as `-32603`, and `task/execute`
reported an unusable sandbox as `-32603`. Both are caller- or operator-actionable. Both were
found *by accident*, by tests written for an unrelated milestone, which is the argument for
the survey below rather than for patching the two.

**The survey.** Ten `RequestError::Refused` construction sites, eleven `DispatchError`
variants, five `PolicyError` variants and seventeen `DenialReason` variants sit behind them.
Three independent causes produced the false `INTERNAL_ERROR`:

1. **Two catch-alls.** `Err(e) => Refused { reason: e.to_string() }` on both dispatch paths
   flattened all eleven `DispatchError` variants into one code — and put English prose in
   `data.reason`, the field a client branches on.
2. **`PolicyError::Denied` carried a `String`**, produced by `ToString` at the point of
   refusal, with a `"refused without a stated reason"` fallback for a case the type system
   already made unreachable. So the only route to classifying a policy denial was
   substring-matching rendered JSON.
3. **`RequestError::Malformed` put serde's own sentence in `data.reason`** — the same defect
   as (1), on the frame-decode path, and found by the sweep's own prose test rather than by
   reading.

**Decision 1 — classification is by recovery, not by variant name.**

The variant name is the *cause*; only the recovery is the *class*. So `Policy` is not one
class — it contains both "we decided no" and "we could not decide" — and it is handed to a
second classifier. `SandboxRefused` and both `Credential` variants are environment problems
with operator remedies. `Execution` and `Verification` are daemon-side defects with none.
`Disabled` is refused by configuration a person chose, which is `FORBIDDEN`'s recovery.

| source | class | code | recovery |
|---|---|---|---|
| `DispatchError::SandboxRefused` | environment | `-32043` | run Tier-1 work somewhere that can isolate |
| `Credential::Absent` / `::Unavailable` | environment | `-32043` | add the credential / fix the store |
| `PolicyError::{Unavailable, AuditUnavailable, ApprovalLedgerUnavailable}` | environment | `-32043` | repair the subsystem |
| `DenialReason::{PolicyUnavailable, AuditUnavailable}` | environment | `-32043` | repair the subsystem |
| `DispatchError::NoImplementation` | invalid request | `-32600` | name a capability this build can run |
| `DispatchError::ClassEscalation` | invalid request | `-32600` | declare the class the action needs |
| `DenialReason::{UnknownCapability, InvalidParams, DataClassExceeded}` | invalid request | `-32600` | fix the request |
| `DispatchError::Disabled` | forbidden | `-32042` | the owner switches it back on |
| the thirteen remaining `DenialReason`s | forbidden | `-32042` | obtain a new human decision |
| `DispatchError::{Execution, Verification, Reentrant}` | internal | `-32603` | none exists |
| `PolicyError::InvalidSchema` | internal | `-32603` | none; the declaration is compiled in |

The third group is deliberately one code. Every approval-related denial shares the same
recovery — obtain a fresh approval, or one that describes this action — so `FORBIDDEN` is
honest for all of them, and the distinctions that matter live in `data.reason`. The
sharpest case is the fourth row: reporting an outage as `FORBIDDEN` would tell a client to
obtain consent for an action the daemon **never evaluated**, which is the most damaging lie
available in this file.

**Decision 2 — the mechanism, which is the actual fix.**

`RequestError::Refused` is **gone**. `INTERNAL_ERROR` is now

```rust
RequestError::Internal { fault: InternalFault, detail: Option<String> }
```

where `InternalFault` is a closed enum whose seven variants each carry their own argument
for being unrecoverable by caller action. Three consequences, and the third is the point:

* There is **no default**. Naming a fault is a deliberate act.
* There is **no free-form string**, so the original escape hatch is closed rather than
  discouraged.
* There is **no `_` arm** in any of the three classifiers, so a new `DispatchError` or
  `DenialReason` is a compile error. A future caller-actionable condition therefore cannot
  silently acquire `INTERNAL_ERROR` by not being classified — it fails to build, which is
  the outcome the old shape made impossible.

`crates/orxnud-daemon/tests/refusal_completeness.rs` asserts all of this statically, so a
later patch cannot quietly widen `INTERNAL_ERROR` again. Reintroducing a `_` arm is a caught
mutation.

**Decision 3 — `INTERNAL_ERROR` survives, and each entry is argued.**

The property is not "zero `INTERNAL_ERROR`". It is that every one is intentional and
unrecoverable by caller action: `durable-state-corrupt`, `storage-unavailable`,
`disclosure-store-poisoned`, `capability-execution-failed`,
`capability-verification-failed`, `reentrant-dispatch`, `invalid-capability-schema`. A real
corrupt-row fixture is created in the test suite and asserted to remain `-32603`, because the
only honest way to show a class is not over-used is to produce it on purpose.

Two vocabulary decisions: `TaskCause::Storage` and `TaskCause::Corrupt` were joined on one
code and are now split into `storage-unavailable` and `durable-state-corrupt`, so an operator
can tell a full disk from a corrupt row. `proposal-corrupt` and `approval-corrupt` are
*unified* under `durable-state-corrupt`, because they are one fault and the detail says
which row. Both words shipped only in unreleased `main`.

**Decision 4 — what was deliberately *not* changed.**

No classification that was already correct was touched. `approval-already-consumed` and
`no-grant` stay `FORBIDDEN` even though `CONFLICT` is arguable, because those words are on
the wire and this milestone is about false `INTERNAL_ERROR`, not about re-litigating the
taxonomy. Reclassifying a correct answer would be scope the task refused and churn a
contract for no gain.

**Decision 5 — four refusals stopped interpolating a raw error.**

The storage and secret-store layers return `String`s that can contain a database path or a
SQL fragment, and four sites formatted them into `detail`. Those now carry a fixed sentence
and the cause stays in the server log. ADR-0051's rule that no operating-system identifier
leaves this daemon applies to error text as much as to identities.

**Evidence.** `crates/orxnud-daemon/tests/taxonomy.rs` grows from 10 to 14 tests: each class
reachable for its own reason, a genuine internal fault still `-32603`, both previously-known
routes pinned individually, and a sweep asserting no reachable refusal puts prose in
`data.reason`. `refusal_completeness.rs` (5 static checks). Workspace 1460 passing.
14 of 15 mutations caught, 0 unobserved, 1 skipped as a no-op.

**Revisit conditions** (extending this record's own):

* Revisit if a class is ever added to `INTERNAL_ERROR`'s siblings for convenience. The test
  is whether a person reading the refusal would know what to do next, and "wait" and "fix
  your request" and "get a human" are not interchangeable.
* Revisit if `InternalFault` grows a variant that a caller can influence. That is the line:
  if a caller's request can turn a fault on, it is not a fault.

<a id="adr-0051"></a>

## ADR-0051 — An `Actor` is derived from the transport peer, never from the request

**Status.** **Decided and implemented.** Closes V-89 (identity half) and V-90.

**Context.** ADR-0027 made `Actor` first-class and got the model right: only a `Human`
grants, an `Ai` carries delegated authority and is never additive, `External` can request
but never grant, `System` is housekeeping, `Integration` and `Scheduled` derive authority
from a human grant. It never said **who is allowed to become which `Actor`**.

That gap was invisible in the type definitions, which is why it needed an evidence-first
audit rather than a reading. Traced over the real daemon, the answer was worse than a
missing check:

```
runtime.rs   fn local_actor() -> Actor      // no arguments
                  Human { user: UserId::new("local"), via: LocalInteractive }
                  called from 6 sites: every approver, every dispatch
```

Every handler called a zero-argument function and got `Human`. The authority was
**real** — a `Human` genuinely could grant, and approvals genuinely were issued — but
**attribution was fiction**: nothing had established anything about the caller. The only
thing standing between a local process and full human authority was the socket's `0600`
mode — a filesystem ACL, never checked, never mapped to an identity, and invisible to the
code above it.

**What the audit established, and what it did not.** A raw JSON-RPC caller **cannot forge
an actor field**: `Request` has no actor member, `_meta` is never read for identity, no
handler reads `params.actor` / `user_id` / `approver` / `delegated_by` / `granted_by` /
`authorised_by`, and reproduced over the real socket, declaring all of them changed
nothing. `approval_from_json` already refused a client-supplied `approver` structurally,
before the digest arithmetic made it moot.

That is the comfortable answer, and it is the wrong one to stop at. "We ignore what you say
about who you are" and "we know who you are" are different properties, and only the second
one makes an audit record mean anything. The caller obtained `Human` either way — from a
constant, having proved nothing. Every audit record claiming a human approved something
was a claim about a file mode.

Two smaller findings fell out of the same trace. `delegated_by` was
`UserId::new("local")` written inline, so every model proposal's delegation chain was an
assertion about a string rather than a consequence of who was authenticated — harmless for
*granting*, since an `Ai` can never grant, but it could attribute a proposal to a human who
never asked for it, which is exactly what an audit record claims to be about. And
`proposer_json` is deserialized back into an `Actor`, so storage is a real path from bytes
to an actor — the one place "it was persisted earlier" could be mistaken for "it is
authenticated".

**Decision 1 — the identity comes from the kernel, at accept.**

`orxnud-platform-ipc` reads `SO_PEERCRED` when a connection is accepted. It is the
strongest native mechanism available for a Unix domain socket because it is answered by
the kernel from the process it actually ran: **there is no request that changes the answer,
because the answer is not in a request.** The alternatives were rejected for specific
reasons rather than by preference — an application token is something to copy and so leaks
to anything that can read the file; a username is a name the caller can influence and puts
a lookup on the request path; a secret of any kind is heavier than a local socket needs and
adds a second thing to protect.

The result is an `Option`, and `LocalStream::principal()` turns `None` into an error rather
than a default. A defaulted uid would be a *fabricated identity*, which is the one outcome
this exists to prevent, so there is no value a caller could read past.

**Decision 2 — the installation's owner is the reference, and it is read from the socket.**

The daemon reads the bound endpoint's owner once at startup and compares. From the socket
rather than `geteuid(2)`, because the two normally agree and stop agreeing exactly where it
matters: under `sudo`, a system unit, or a launcher that drops privileges, the process uid
need not be the user the installation is *for*, while the endpoint's owner is by definition
— it is the user who can reach it.

**Decision 3 — one function, called before a single byte is read.**

```text
accept()  ->  authenticate(stream, installation)  ->  AuthenticatedPrincipal | refusal
                                                      |
                            (then, and only then)     v
                                            read a request, route it
```

`route` derives the `Actor` once and hands handlers the *actor*, not the principal, so
nothing below that line can re-derive an identity and no handler can reach the uid at all.

There is deliberately **no "unknown" variant** of `AuthenticatedPrincipal`. A connection
whose identity could not be established is refused before it becomes one, so the absence of
such a case is the type system saying an unauthenticated caller cannot be *represented* as a
caller. That is the property; an `Option<AuthenticatedPrincipal>` threaded downward would
have been the same work with the guarantee left to be re-established at each use.

**Decision 4 — refusals use the ADR-0050 taxonomy by recovery, and say nothing about the OS.**

A wrong peer is **`FORBIDDEN`**, not `CONFLICT`: nothing the caller does changes the
outcome. Not retrying, not re-reading state, not obtaining another approval — either this
peer is the installation's owner or it is not, and the kernel decided that. `CONFLICT`
would say "try again" and `INVALID_REQUEST` would say "edit your request", both of which are
false instructions. An unestablishable identity is **`ENVIRONMENT_UNAVAILABLE`**, and it
refuses *everyone*: with no installation to compare against, "nothing to compare against"
must not decay into "allowed".

No refusal names a uid, a socket path, or a syscall. The caller is told it is not the owner;
how the daemon knows is not information it is entitled to.

**Decision 5 — the identity is a stable application identity, and the uid is discarded.**

`UserId` stays `"local"`. It is what the approval digest already binds
(`canonical_bytes` hashes the approver's label and authority root), so deriving it from a
uid would invalidate every approval a previous daemon issued, for no security gain. The uid
is used to decide *whether* a principal exists and then dropped — which also keeps an
operating-system identifier out of every audit record, and out of every IPC error.

**Decision 6 — the platform boundary is documented, not papered over.**

| platform | mechanism | what is proven |
|---|---|---|
| Linux | `SO_PEERCRED` at accept | proven on every run: a test reads the principal off a real accepted connection and compares it to the connecting process's own uid |
| Windows | none — no local transport exists | fails closed at `bind` (`Listener::Unsupported`). No identity claim is made, and none is faked |
| other Unix | none claimed | `peer_principal` returns `None`, so every connection is refused. `getpeereid(3)` would be the right call and is **not** implemented: no CI exercises it, and an untested branch that looked like working authentication on a developer's laptop would be worse than an honest refusal |

**What is not claimed.** `AuthChannel::LocalInteractive` records that the caller reached the
daemon over a local, same-owner socket. It does **not** assert a person is at a keyboard: a
Unix domain socket cannot tell an interactive shell from a cron job. Nothing depends on it
— `AuthChannel` is not in the approval digest and no policy rule reads it — and it is
recorded as a known limit rather than dressed up as evidence.

Multi-user identity, session grants, remote exposure, and step-up authentication are all
still absent, exactly as ADR-0027 left them. This record establishes *one* identity for
*one* local installation.

**Deliberately not changed.** Task state, claim/lease, approval expiry and replacement,
continuation, observation, disclosure, provider identity matching, capability declarations,
sandboxing and resource limits are untouched. No approval digest changes, so every approval
issued by a previous daemon still verifies.

**Revisit conditions.**

* Revisit if a second human can use one installation — that is P4 multi-tenancy, and
  `InstallationIdentity` becomes a set rather than a uid.
* Revisit if a peer can be authenticated *without* being the owner, e.g. a paired device;
  `AuthenticatedPrincipal` gains a variant and each must carry its own authority root.
* Revisit if `SO_PEERCRED` is ever found insufficient — it reports a uid, not a session, so
  it cannot distinguish a user from a compromised process of that user. Nothing here depends
  on that distinction, and a future one should not assume it.
* Revisit if a non-Linux Unix becomes supported: implement `getpeereid`, and only then, with
  CI.
* Revisit if Windows gains a local transport. It must establish peer identity before this
  daemon will serve it, or the daemon must keep refusing.
* Revisit if a capability ever needs to know *who* called — that is the confused-deputy
  boundary ADR-0027 drew, and it does not move because identity got stronger.

**Evidence.** `crates/orxnud-daemon/tests/identity.rs` (10 wire tests), the
`identity_boundary` module in `runtime.rs` (4, over a real socket),
`orxnud-platform-ipc::unix::tests::the_accepted_peer_is_the_connected_process` (1), and
`crates/orxnud-store/tests/mutation_harness_is_safe.rs` (3, for the harness the mutation
evidence depends on). 18 of 18 mutations caught, 0 unobserved. Workspace 1451 passing.

**Boundary finding, since fixed.** `capability/dispatch` answered a *policy* denial with
`-32603 INTERNAL_ERROR`, which contradicts ADR-0050. It was pre-existing and unrelated to
identity — `dispatch` had always mapped `PolicyError` through `RequestError::Refused`, and
V-89 fixed only the task routes — so it was asserted as-is and filed as V-90 rather than
fixed inside a milestone forbidden to change error semantics. **V-90 is now closed**, by a
dedicated milestone; see the amendment to [ADR-0050](#adr-0050) below for the full survey
and the classification it produced.

<a id="adr-0052"></a>

## ADR-0052 — Two decisions the V-25 measurement had to make explicitly

**Status.** **Decided and implemented.** Closes V-25.

**Context.** V-25 stated three budgets (idle RSS < 60 MB, binary < 40 MB, cold start
< 150 ms) with no benchmark behind them. Closing it required a harness, and building that
harness surfaced two questions that the documents answered only by omission. Both had
defensible-looking default answers, and one default would have made the result false.

**Decision 1 — cold start is measured to an *answered request*, not to `exec`.**

`Runtime::start` opens durable security state, verifies the audit chain, opens and recovers
the task database, and only then binds the endpoint. Timing from process spawn to `exec`
returning would report the cost of the runtime's work and silently drop the cost of starting
the program — and against a 150 ms budget that is most of the quantity being budgeted.

So the harness polls `daemon/version` over the real socket and stops the timer at the reply.
That is also the boundary a client experiences: the first instant at which the daemon is
useful is the first instant at which it answers.

The alternative — an "endpoint file exists" probe — was rejected because it stops before the
accept loop is serving. A socket that exists can be bound by a daemon that has not yet
finished initialising, and measuring that would move the boundary earlier without making it
more real.

**Decision 2 — the 40 MB budget applies to the *stripped* binary, and that is a decision.**

The release profile sets `strip = "symbols"`. The shipped binary is **7,492,472 B
(7.15 MiB)**; the unstripped build of the same source is **51,183,016 B (48.8 MiB)**, which
would **fail** the 40 MB budget.

Both numbers are honest measurements of real artefacts. Only one is the shipped artefact.
Recording the stripped figure as *the* figure without saying so would have left a future
engineer comparing against 48.8 MiB and concluding the budget was missed; recording 48.8
would have implied a regression that does not exist. So the choice is stated in the budget,
in the register and in the harness's own output.

A measurement-only cargo profile (`v25-unstripped`) exists so the comparison figure can be
reproduced. It `inherits = "release"`, so it cannot drift on optimisation, LTO or codegen
units — the only difference is that symbols are kept — and nothing ships with it.

**Decision 3 — the measurement is reported in CI, not gated on it.**

Measured variance: binary size is exact (it is a file size), cold start ~0.2%, idle RSS ~1%,
IPC p50 ~17%. Gating a metric whose natural spread is 17% would produce a red build
periodically for no reason, and a gate that cries wolf is worse than no gate — the same
argument docs-08 makes about checks that cannot fail, in the other direction.

So: binary size and the six static dependency-graph checks are **blocking**, because they are
exactly reproducible. Cold start and RSS are **reported**, with the harness's own assertions
set at 10× bounds so an order-of-magnitude regression still fails loudly. IPC latency is
**reported only**, on the evidence that its noise exceeds the quantity anyone would want to
gate on.

**What this record does not do.** It does not claim the budgets are met. It records what was
measured, on one host, with its limitations stated: 16 cores and NVMe rather than the 2c/4 GiB
baseline §2 specifies, and page-cache-warm throughout because `drop_caches` needs privileges
this environment does not have. Both are the favourable direction and both are named.

**Evidence.** `scripts/measure-v25.sh`, `crates/orxnud-daemon/tests/v25_measure.rs` (7
measurements), `crates/orxnud-daemon/tests/v25_architecture.rs` (6 static checks), and
docs-05 §1a, which holds the full table with sample counts.

**A finding worth more than the numbers.** The measurement work surfaced a defect in
neighbouring evidence: `orxnud-task`'s conformance harness keyed TP-7's scratch directory by
`{pid}-{tag}` with a fixed tag, and `cargo test` runs a binary's tests as parallel threads of
one process. Three tests that each run the suite therefore deleted each other's database, and
the conformance report printed `TP-7 power loss cannot corrupt task state: VIOLATED`. A
conformance report claiming NON-CONFORMING for a race in its own harness is worse than no
report, and it appeared only once added parallel load made the window reliable. Fixed by
per-call isolation, with the old assertion — "the same tag must yield the same path" — which
was the bug written down as an expectation, now asserting the opposite.

**Revisit conditions.**

* Revisit if a 2-core / 4 GiB host becomes available and does not meet the budgets. That is
  the one unverified column and it is the honest gap in this record.
* Revisit if `strip` is removed from the release profile: the budget comparison changes, and
  Decision 2 with it.
* Revisit if IPC latency becomes materially less noisy — a keep-alive transport would remove
  one connection per request from the measurement — at which point it becomes gateable.

<a id="adr-0053"></a>

## ADR-0053 — An uncertain side effect is a durable state, not a delay before a retry

**Status.** **Decided and implemented.** Closes V-92. Settles the backend half of
Q-OPEN-18; its user-facing half stays open.

**Context.** ADR-0027 defined `TaskState::NeedsVerification` — *"a side effect may or may
not have occurred. Terminal until a human adjudicates."* It was marked terminal, excluded
from `claim`, excluded from lease recovery, and stored as a legal `Running ->
NeedsVerification` transition.

**No production path ever produced it.** Every handler did nothing when verification did not
confirm. Reproduced over a real daemon with real durable state, before any edit:

```text
execute (undetermined)  ->  task "running", lease held, last_error null
daemon restart          ->  recovery sees running + a lease, returns it to "pending"
any worker claims it    ->  attempt 2, running
task/propose            ->  the same non-idempotent write, pending approval
```

So the daemon did say *"we don't know whether it happened, so we tried again"* — with no
human involved, at the next process start. The ambiguity was resolved by a restart, not by
anything durable, which is the opposite of the contract the state was written for.

**The root cause is one missing decision, not a missing state.** The engine needed nothing:
`Running -> NeedsVerification` was already legal, `NeedsVerification` was already terminal,
`claim` already selected only `pending`, `recover()` already selected only `running`, and
`complete_with` already clears the lease under the same TP-5 fence every completion uses.
What was missing was somebody deciding, from the verification outcome, which of those to use.

**Decision 1 — classify by *certainty*, not by the adapter's outcome.**

| certainty | capability | state |
|---|---|---|
| established | any | the existing completion path |
| **disproved** (`Refuted`) | any | `Failed`, retryable |
| **unknown** (`Undetermined`) | idempotent | `Failed`, retryable |
| **unknown** (`Undetermined`) | non-idempotent | **`NeedsVerification`** |

The distinction that matters is between *proven not to have happened* and *nobody can say*.
The brief's suggested table had a `failed -> failed/retry` row; that row is not reachable for
a non-idempotent capability, because `WriteTextVerifier` maps `ExecutionOutcome::Failed` to
`Undetermined` — a subprocess can die *after* writing, so an adapter-reported failure is not
evidence about the effect. The table is derived from the verifier's own contract rather than
from the brief.

**Decision 2 — `Refuted` is retryable regardless of idempotency.**

This looks like the wrong way round and is deliberately so. The capability's verifier already
decided which of its findings make a retry safe, and recorded that decision in its own
comments: *"a missing file is `Refuted` — proven absent — which is the state that makes a
retry safe, and only `Refuted` makes it safe."* Re-deciding it in the task layer would be a
second policy free to disagree with the first, and the task layer has strictly less
information than the verifier about what actually happened on disk.

**Decision 3 — idempotency is read from the capability declaration, never inferred.**

An action nobody can vouch for is treated as non-idempotent, because that is the direction
which cannot duplicate an effect. This is the opposite of the tempting default: a capability
that fails to declare itself idempotent must not be *granted* the benefit of the doubt.

**Decision 4 — the lease is released, and that is safe because the state is terminal.**

Holding a lease across an open question would park a task on a 30-second timer and hand it
back to `pending` when it expired — the same defect by another route. Releasing it is safe
*only* because `NeedsVerification` is terminal and unclaimable, which is why the two
decisions are made together and not separately.

**Decision 5 — a lost fence is refused, not absorbed.**

If the lease ended while the capability was running, the outcome cannot be recorded by that
worker. Mapping `TaskFault::Fenced` to `CONFLICT` (ADR-0050, by recovery) tells the caller
that the *settling* was refused without suggesting it should retry the execution — which
would duplicate the very effect whose status is in doubt.

**Two smaller corrections found on the way.** The task event was logged as `completed` for
any non-requeue transition, which is the same lie the adjacent comment already condemns for
dead-lettering: an operator filtering the event log by `kind` would read "completed" for the
event that stopped their task. It now reads `needs-verification`. And the execute reply
carries an `uncertainty` object, so a client learns from the response that the task stopped
rather than by polling and discovering it went quiet.

**What is deliberately absent.** No user-facing adjudication. A human choosing "assume it
succeeded" must not be recorded as `verified = true` — a person adjudicating an uncertainty
and a verifier establishing a fact are different events, and the audit chain must keep them
apart. The typed representation for that decision belongs to Q-OPEN-18's open half, and the
state machine leaves the space free rather than guessing at it.

**Evidence.** `crates/orxnud-daemon/tests/uncertain_outcome.rs` (8 tests, real daemon, real
sandbox, real `WriteTextVerifier`, real restart and crash injection), plus an exhaustive
decision-table test in `runtime.rs`. 1483 passing.

**Known evidence gap.** Two of the four rows have **no deterministic end-to-end producer**.
`Refuted` is unreachable through the shipped adapter/verifier pair: an over-limit read fails
in the *helper* before the verifier's independent read runs, so the outcome is `Failed` ->
`Undetermined`; the remaining `Refuted` branches need the file to change between two reads,
which no test can schedule. The capability crate unit-tests both verifiers' `Refuted` branches
directly, so the verifier logic is covered — what is missing is a *task-layer* producer, and a
test now says so rather than letting the absence pass unnoticed.

**Revisit conditions.**

* Revisit if a per-capability probe lands (Q-OPEN-18): it would give `Refuted` a deterministic
  producer and close the gap above.
* Revisit if `Disproved` ever needs to condition on idempotency. That would mean a verifier
  had concluded a retry was unsafe, and the right response would be for the verifier to say
  `Undetermined` rather than for the task layer to second-guess it.
* Revisit if `NeedsVerification` ever becomes claimable for an *idempotent* capability. Today
  idempotency is decided before the state is chosen, so such a task never reaches
  `NeedsVerification`; changing that would be a change to Decision 3.
