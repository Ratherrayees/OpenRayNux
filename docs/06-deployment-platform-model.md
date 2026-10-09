# 06 — Deployment & Platform Model

Status: **Draft v0.4** · Reconciled **2026-10-09** against `HEAD` (`c5934970`). Both Windows
lanes are green on `main`, as are the wasm32 and Tier-1 sandbox lanes. No platform finding is
open; see [`README.md`](README.md) §8 for CI state.

**The one thing to read first.** Windows is **not** "untested" and it is **not**
"sandbox-supported". Both of those were wrong here. It is *portable and compiled, and its
isolation is unproven*: all 16 crates compile for MSVC, both Windows CI lanes pass, and
there is still no Job Object or AppContainer backend, so a Tier-1 execution on Windows is
**refused** rather than degraded. Refusing is correct — an unsandboxed Tier-1 subprocess is
worse than no capability at all (ADR-0035).

---

## 1. One codebase, four profiles

The same binary and the same capability set, in four deployment envelopes. No
profile is a fork; a profile selects which adapters are bound and which
transports are opened.

| Profile | Transport | Persistence | Autostart | Use case |
|---|---|---|---|---|
| **P1 Desktop** | UDS (**FUTURE** — no GUI crate) | SQLite in the user data dir | user session | The intended default. Not buildable today: there is no desktop application. |
| **P2 Headless** | UDS | SQLite | service manager | **This is what exists.** `orxnud` + `orxnuctl` over a 0600 Unix socket. Optional TCP is FUTURE and is not implemented. |
| **P3 Cloud** | HTTPS (mTLS or OAuth) | SQLite *(v1)* → Postgres *(later)* | managed | Single-tenant hosted instance. |
| **P4 Multi-tenant cloud** | HTTPS + per-tenant identity | Postgres, tenant-partitioned | managed | The "platform" mode. **Not v1.** |

**P1 → P2 → P3 is a deployment change, not a rewrite.** P4 is where the
data-model work in NR-04 pays off; it is deliberately deferred and explicitly
out of scope for v1.

---

## 2. Platform support model

### 2.1 Support tiers (stated as a policy, not an aspiration)

| Tier | Meaning | Platforms |
|---|---|---|
| **T-A** | **First-class.** CI builds, tests, and packages. Bug reports accepted. | Linux x86_64, Windows x86_64 |
| **T-B** | **Supported.** Builds and is tested on release, but not in every CI run. | Linux aarch64, macOS aarch64/apple silicon |
| **T-C** | **Best-effort.** Compiles; platform gaps documented; not promised. | Linux armv7, Windows aarch64, FreeBSD |
| **T-D** | **Not supported.** | — |

### 2.2 The honest current assessment

### 2.3 The honest current assessment, per platform

**Linux.** Tier-1 execution works **where the host provides the guarantees**, and refuses
where it does not. That is not a caveat; it is the design. `bwrap` with PID and mount
namespaces provides visibility and tree lifetime; `cgroup v2` provides resource ceilings
**where the host delegates the controllers**, which is a per-host property and is measured
rather than assumed — `scripts/run-resource-tests.sh` prints the own-cgroup path rather
than a remembered verdict, and the governed path writes ceilings *before* spawning and
verifies membership from `cgroup.procs` afterwards. A host that delegates nothing still
runs the shipped capabilities, because they *require* no control, and records the gap in
`ExecutionResult::unproven` rather than refusing for no security gain.

**Windows.** Two CI lanes, both green: `windows-check` runs `cargo check --workspace
--all-targets` nightly, and `windows-portability` runs the platform-neutral suites as
*tests* rather than only compiling them. Five Rust-level MSVC defects were found and fixed
during 2026-10-05 — including one that gate **G3** structurally could not see, because G3
greps for `cfg` and not for a platform *API*, so an unguarded `std::os::unix` passed the
gate and broke the build. All 16 crates now compile for MSVC.

**Isolation remains NOT_PROVEN.** No Job Object, no AppContainer, no Windows resource
limits. `host_backend()` binds the refusing `UnsupportedRunner` off Linux, so a Tier-1
execution on Windows is refused with a reason rather than degraded. A Windows sandbox
backend needs `windows-sys` and `unsafe`, in a platform crate that has not opted in under
G4 — that is the honest blocker, and it is a design decision rather than an oversight.

**GitHub-hosted Linux CI — a measured limitation, not a defect.** The hosted runner ships
`bwrap` and **cannot create an unprivileged user namespace**, because Ubuntu 24.04+ sets
`kernel.apparmor_restrict_unprivileged_userns`. Measured, and printed on every run by the
preflight step in `linux-gates`:

```text
sandbox backend: bwrap
guarantees: visibility=false tree_lifetime=false resources=false
tier1_executable: no (Tier-1 capabilities are refused here; this is correct, not a fault)
```

So the hosted Linux lane asserts the **refusal**, which is the property that is true there,
and the `sandbox-integration` job measures whether a container can do better. It cannot:
AppArmor's restriction applies inside the container too, measured. That job therefore
reports the limitation in capitals and produces **no positive Tier-1 evidence**, rather than
disabling AppArmor or granting a capability to manufacture a green run.

**Positive Tier-1 sandbox evidence comes from a host that can create an unprivileged user
namespace** — a developer machine via `scripts/run-sandbox-tests.sh --host`, or a container
on such a host. That is where `governed_path`, `read_text_real`, `write_text`, `isolation`
and the `cli_e2e` loop are exercised against a real sandbox.


| Platform | Current tier | Target | Evidence and gaps |
|---|---|---|---|
| **Linux x86_64** | **T-A** | T-A | Native deps verified working on Fedora 44 (webkit2gtk 2.54.0, appindicator 12.10.1, librsvg 2.62.3, libxdo, SQLite 3.51.2 + headers). Dev machine. |
| **Windows x86_64** | none | **T-A** | Requires WebView2 (**FUTURE** — no GUI crate exists); MSVC toolchain ✅; DPAPI keyring ✅ (`orxnud-platform-secrets` compiles for MSVC, untested at runtime); a real signing story ❌ (no packaging pipeline). **Portability PROVEN, isolation NOT PROVEN** — no named-pipe transport and no sandbox backend, so Tier-1 refuses. |
| **Linux aarch64** | none | T-B | Raspberry Pi and ARM SBCs are a genuinely attractive personal-assistant target. `sherpa-onnx` already publishes x86/ARM/RISC-V builds. Needs aarch64 CI. |
| **macOS** | none | T-B | WKWebView, Keychain, `launchd` autostart, notarisation. The Tauri stack supports it. **Deliberately not first-class:** the stated platforms are Linux and Windows. |
| **Windows on ARM** | none | T-C | DirectML is the only acceleration path for some GPUs (whisper.cpp has no DirectML); ARM64 ONNX is patchy. |

### 2.4 Are macOS and ARM64 first-class? — the decision

**macOS: no, not first-class. ARM64: yes, but as Tier B, not Tier A.**

*macOS* — the brief names Linux and Windows. macOS would add: notarisation and
signing, a second WebView engine to validate against, different sandbox and
permission UX, and a `launchd` lifecycle to test. Tauri supports it, so it is
*reachable* — but promising it as first-class would be promising something we
cannot test. **Tier B, revisited after Windows is T-A.**

*ARM64* — different in kind. ARM64 Linux is where a personal assistant is
plausibly deployed permanently (a Pi in a cupboard), where the ONNX and
sherpa-onnx ecosystems already publish ARM builds, and where a small CPU-only
install is a realistic configuration. **Tier B with dedicated CI.** This is
cheap to add now and expensive to retrofit.

**What "cross-platform" actually means here:** not "one binary everywhere". It
means: *one capability contract, with a platform adapter per OS concern, and
platform-specific behaviour confined to adapters.* See §4.

---

## 3. Per-OS concern matrix

Each row is a `platform-*` crate behind a trait. This table is the definition of
"adapter", and gate **G3** enforces that no `cfg(target_os)` appears outside one.

> **Corrected 2026-10-05 — this table mixes shipped code with design, and did not say
> which is which.** Gate G7 now asserts the workspace member list, and it contains **five**
> platform crates: `fs`, `sandbox`, `secrets`, `notify`, `ipc`. Every other row below is
> **future design** — a place the architecture intends to put a boundary, not a crate that
> exists. Two rows that were actively wrong:
>
> * **IPC on Windows** said "named pipe". It refuses; there is no pipe backend.
> * **Browser, WebView, Tray, Audio capture, Autostart, WebKit/WebView2** all name Tauri
>   plugins and `cpal`. No Tauri application exists, so none of these are linked.
>
> The matrix is kept because it is a reasonable statement of where each concern belongs.
> It is not a dependency list, and `Cargo.toml` is.

**The five that exist:** `orxnud-platform-fs` (bounded reads, atomic writes, rooted jail),
`orxnud-platform-sandbox` (Tier-1 boundary + ceilings; refuses off Linux),
`orxnud-platform-secrets` (`keyring` → Secret Service / DPAPI / Keychain),
`orxnud-platform-notify`, `orxnud-platform-ipc` (UDS on Unix; refuses elsewhere).

| Concern | Linux | Windows | macOS | Notes |
|---|---|---|---|---|
| **Config dir** | XDG (`~/.config/openraynux`) | `%APPDATA%` | `~/Library/Application Support` | via `directories` 6.0.0 |
| **Data dir** | XDG_STATE_HOME | `%LOCALAPPDATA%` | `~/Library/Application Support` | |
| **IPC** | Unix domain socket | **refuses** | Unix domain socket | **Correction 2026-10-05:** there is no named-pipe backend. `orxnud-platform-ipc` is a UDS on Unix and a refusal everywhere else, because a pipe needs `windows-sys` and `unsafe` and gate **G4** forbids `unsafe` outside a platform crate that has opted in. |
| **Single instance** | `flock` on a lockfile | named-pipe mutex / lockfile | `flock` | Must be crash-safe |
| **Secrets** | Secret Service (`libsecret`) | **DPAPI** | Keychain | via `keyring` 4.2.0 |
| **Notifications** | `notify-send` / D-Bus (portal) | **Windows Toast / Action Center** | `UNUserNotificationCenter` | via `tauri-plugin-notification` 2.5.0 |
| **Autostart** | XDG autostart `.desktop` | **Task Scheduler / Registry Run** | LaunchAgent | via `tauri-plugin-autostart` 2.6.0 |
| **Process mgmt** | systemd user unit | **Windows Service** | launchd | P2 profile |
| **Audio capture** | **PipeWire → ALSA fallback** | **WASAPI** (shared/exclusive) | CoreAudio | via `cpal` 0.18.2 |
| **Browser** | Chromium/Chrome | Chrome/Edge | — | dedicated profile only |
| **WebView** | **WebKitGTK 4.1** | **WebView2** | WKWebView | Tauri-provided |
| **Tray** | `libayatana`/`libappindicator` | **tray icon** | menu bar | |
| **Packaging** | `.rpm`, `.deb`, Flatpak, AppImage | **MSI + NSIS**, code signing | `.dmg`, notarisation | |
| **Updates** | package manager | **MSI upgrade** (no auto-updater) | Sparkle (if adopted) | ADR-0017 |
| **Paths** | case-sensitive, `/`, no drive letters | case-insensitive, `\`, reserved names, `MAX_PATH` | case-insensitive (default) | **A real source of cross-platform bugs** |
| **Line endings / encoding** | LF, UTF-8 | CRLF, UTF-16 APIs | LF, UTF-8 | |
| **Permissions** | POSIX modes, SELinux | **ACLs, no POSIX modes** | Sandbox profiles | Capability grants differ in *expressiveness* |

### 3.1 Platform differences that will actually bite

Not theoretical — these are the ones that cause real bugs:

1. **Filesystem case sensitivity.** macOS and Windows are case-insensitive by
   default; Linux is not. A path built on Linux can break on Windows. Rule: never
   derive identity from a path; use content hashes or opaque IDs.
2. **Path separators and reserved names.** `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`9`,
   `LPT1`–`9` are illegal on Windows. `nul` as a filename works on Linux and
   destroys data on Windows. Filenames derived from user or web content **must**
   be sanitised for the target platform.
3. **`MAX_PATH` and long paths.** Windows needs long-path awareness or short
   paths.
4. **No POSIX permissions on Windows.** Capability grants that rely on chmod are
   meaningless on Windows; the isolation model must rely on the *process*
   boundary, which works on both. This is why S11 is process-based.
5. **WebView behavioural divergence.** WebKitGTK, WebView2 (Chromium), and
   WKWebView differ in CSS support, form autofill, file pickers, and
   `navigator` APIs. Never assume a webview feature exists; feature-detect.
6. **Audio capture divergence.** PipeWire is the Linux default and behaves
   differently from ALSA; WASAPI has shared vs exclusive modes. Audio device
   enumeration and format negotiation need real per-OS testing.
7. **Notifications require different setup.** Windows toasts need an AppUserModelID;
   the Linux portal needs a running D-Bus session; macOS needs user authorisation.
8. **Systemd vs Windows Service lifecycle.** Restart policies, graceful shutdown
   timeouts, and "was the machine rebooted?" semantics differ. The scheduler's
   catch-up logic must be identical on both — it is the same code path, which is
   good, but the *trigger* differs (systemd timer vs Task Scheduler vs boot event).

---

## 4. The platform abstraction boundary

```
        portable core  ── zero OS knowledge, zero platform crates
                │
                │  traits (defined in core, implemented in adapters)
                │
   ┌────────────┴────────────┬──────────────┬──────────────┐
   │  platform-fs            │ platform-secrets  │ platform-notify
   │  platform-process       │ platform-audio     │ platform-autostart
   │  platform-net           │ platform-single-instance
   └─────────────────────────┴──────────────────┘
```

**Rule:** the core defines the trait; adapters implement it; the core never names
an OS. Enforced by (a) CI gate G3, which reads `cfg` predicates at any nesting
depth, for `cfg(target_os)` / `cfg(windows)` /
`env::consts::OS` outside `crates/platform-*`, and (b) a CI job that builds the
core for a target with no platform adapter available (e.g. `wasm32-unknown-unknown`
for the pure-logic subset) to prove the boundary is real.

---

## 5. Packaging

| Platform | Artefact | Update path | Signing |
|---|---|---|---|
| Linux | `.rpm`, `.deb`, AppImage, Flatpak | Distro repo or Flatpak | RPM key / AppImage zsync |
| Windows | **MSI** (per-user and per-machine) + NSIS installer | **MSI upgrade** | **Authenticode** (EV cert for SmartScreen) |
| macOS (Tier B) | `.dmg` | Not decided | Developer ID + notarisation |

**Packaging is not deferred to the end.** Windows MSI and Authenticode signing
have lead times (certificate procurement) that can block a release, so that
process starts in Phase 1, not Phase 9.

**Flatpak is a special case:** excellent sandboxing (which we want, S11) but a
confined environment breaks system keyrings, arbitrary subprocess spawning, and
process-service integration. If we ship Flatpak it must be an explicitly
reduced profile with those limitations documented — not the recommended install.

---

## 6. Cloud deployment (P3)

**The design constraint: the local install must not be forced to know about
cloud.** Same daemon, different envelope.

- **Storage:** SQLite in v1. The repository layer abstracts it so Postgres is a
  later swap (ADR-0006). For a single-tenant instance, SQLite remains defensible
  even in a container *if* the volume is a real persistent disk and there is one
  writer — which is exactly our architecture.
- **Transport:** the same JSON-RPC frames over HTTPS, with `axum` 0.8.9 as a
  thin adapter. Auth: OAuth2/OIDC for users, mTLS or signed tokens for machines.
- **Scaling:** one instance per tenant. No horizontal sharding in v1. This is a
  deliberate scope decision, not an oversight.
- **Task engine:** in cloud, the scheduler still runs in-process. The durable
  platform upgrade (Restate preferred, Temporal acceptable) is triggered by
  *multi-instance* or *long-running-workflow* needs, not by "we are in the
  cloud" (ADR-0007).
- **Secrets:** cloud-native secret stores, injected at the policy boundary, never
  in config.
- **Observability:** the optional OTLP exporter becomes genuinely useful here.
  Still never *required*.

---

## 7. Windows specifics (the risk register for the second platform)

Stated now, while there is time to act:

| Item | Why it matters | When to start |
|---|---|---|
| **Authenticode certificate** | SmartScreen blocks unsigned installers; procurement has lead time | **Phase 1** |
| **MSVC toolchain in CI** | Required for any Windows build | Phase 1 |
| **WebView2 bootstrapper** | Offline users need the bootstrapper bundled | Phase 5 (GUI) |
| **Named-pipe transport** | Not a code swap from UDS, but path/ACL/timeout semantics differ | Phase 1 |
| **DPAPI keyring** | `keyring` 4.2.0 supports it; needs a real test | Phase 2 |
| **Windows Service / Task Scheduler** | P2 lifecycle | Phase 2 |
| **Toast notifications** | Needs AppUserModelID + shortcut | Phase 5 |
| **Long paths** | Enable in CI manifests | Phase 1 |
| **Antivirus false positives** | Rust + subprocess + browser drivers will trip heuristics; budget for signing and reputation | Phase 5 |
| **Reserved filenames** | `nul`, `con`, etc. — sanitise all derived filenames | **Phase 1** |

---

## 8. Installation, uninstallation, recovery

**Install must be reversible and non-destructive.** Specifically:

- Never delete user data on uninstall. Offer an explicit, separate "remove data"
  choice.
- Migration is always preceded by an automatic snapshot.
- A failed migration restores the snapshot and leaves the previous binary working.
- The user can always start the previous version against a restored snapshot
  (ADR-0017).

**Crash recovery** is a first-class path, not an afterthought:

1. On start, the daemon checks for an unclean-shutdown marker.
2. Any task in `running` with an expired lease is returned to the queue
   (orphan recovery) — with the caveat in S7 that a *non-idempotent* side effect
   may have already occurred, so such tasks are marked `needs_verification` and
   require human confirmation rather than blind retry.
3. WAL recovery is SQLite's job; the bundled version must be ≥ 3.51.3.
4. Backups are verified on a schedule, and the **restore path is tested** in CI.
