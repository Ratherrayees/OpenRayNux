# OpenRayNux — Documentation Index

Status: **Stages 1–4c delivered. Both 4c wirings are in production: the continuation loop
(`task/continue`, ADR-0047) and the observation/disclosure path (ADR-0048).**

Header, counts and the sections touched by the 2026-10-23/24 remediation were
re-measured against `main` at **`358b547`** (tree `ab1b8c9e`), the merge of PR #14, on
2026-11-18. PR #14 changed `orxnud-store`'s `fsync_file` unconditionally (a portable
write-open) plus two Windows-only tests and one CI step. That production change applies to
Linux as well as Windows: `fsync_file` has no platform gate around its body. Apart from that
acknowledged change, the source relevant to the specific Linux findings compared in this index
is unchanged between `e0f6784` and `358b547`; this is not a claim that all Linux production
source is identical.
A recorded full local gate run during Phase 1 / Phase 1.1 was **2072 run, 2072 passed
(2 leaky), 6 skipped** (`CI=true ./scripts/ci-gates.sh`, gate G9; the "leaky" count varies
between runs and is process accounting, not a test failure). That count was measured on
this working tree with the uncommitted TUI and shared-approval changes, not on clean
`main`; later working-tree runs recorded 2089 and 2102, and the newest Phase 1.5 result
is recorded below. The boundary-gate self-tests are **181**, and G12 remains a documented
skip because no release tag is available.

After the Phase 1.3 terminal-safety and state-consistency corrections were applied to the
same uncommitted working tree, a fresh local gate on 2026-11-18 recorded **2089 run, 2089
passed (2 leaky), 6 skipped**, with G12 skipped for the same reason. The leaky count is
process accounting and has been observed as both 1 and 2 across runs; neither figure is a
test failure. This later count is also a working-tree result, not a result from clean
`main`, and does not replace the historical Phase 1/1.1 figure above.

After the Phase 1.4 correctness and approval-outcome corrections were applied to the same
uncommitted working tree, a fresh local gate on 2026-11-18 recorded **2102 run, 2102 passed
(2 leaky), 6 skipped**, again with G12 skipped. CLI/TUI tests rose from 144 to 157. All of
these are working-tree results on 2026-11-18, not hosted CI results and not results from
clean `main`; the 2072 and 2089 figures above are retained as historical records.

After the Phase 1.5 geometry and CLI-sanitization corrections were applied to the same
uncommitted working tree, a fresh local gate on 2026-11-18 recorded **2108 run, 2108 passed
(1 leaky), 6 skipped**, with G12 skipped. CLI/TUI tests rose from 157 to 163. The leaky
count is process accounting and has varied between 1 and 2 across runs. These are local
working-tree results, not hosted CI and not clean `main`; earlier counts remain historical.

After the Phase 1.6 disclosure-fidelity and review-gate API corrections were applied to
the same uncommitted working tree, a fresh local gate on 2026-11-18 recorded **2115 run,
2115 passed (2 leaky), 6 skipped**, with G12 skipped. CLI/TUI tests rose from 163 to 170.
These are local working-tree results, not hosted CI and not clean `main`; earlier counts
remain historical records.

After the Phase 1.7 disclosure-completeness correction was applied to the same uncommitted
working tree, a fresh local gate on 2026-11-18 recorded **2120 run, 2120 passed (2 leaky),
6 skipped**, with G12 skipped. CLI/TUI tests rose from 170 to 175. These are local
working-tree results, not hosted CI and not clean `main`; earlier counts remain historical.
CI has **six jobs** (see §8), and a hosted run **is** recorded against the committed
baseline `358b547`, not against the uncommitted working tree described above:
[run 44298832443](https://github.com/Ratherrayees/OpenRayNux/actions/runs/44298832443)
on `358b547`, scheduled event, all six jobs green. The recorded hosted G9 result for that
run is **1898 run, 1898 passed, 116 skipped** (per the CI log baseline). The 116 are the
ADR-0046 scope exclusions on a hosted runner that cannot isolate — the hosted run is not
evidence about the Tier-1 sandbox suites. Gate G9 does **not** accept a
`cargo test --workspace` run as equivalent; the old "1652"/"1655"/"2001"/"2054" counts
are stale.
`main` is **protected**: six required status checks, `strict`, pull request required, no
force pushes or branch deletion, merge commits the only merge method.
**V-68 is closed**, not open: A-040 diagnosed it (the fixture claimed 12 tasks against a
concurrency budget of 8 and depended on a non-atomic check), and A-041 closed the separate
engine defect that diagnosis exposed. PRs #4–#8 are merged with their original history
preserved. The historical `v95_concurrency` failure under load has no new occurrence in
these records. See [§8](#-8-ci-state-the-tool-install-problem-is-resolved-one-test-flake-is-not).

OpenRayNux is a local-first personal AI operating layer: one long-lived Rust process owning
the user's time, data and integrations, with several surfaces driving the *same* governed
capability set. One surface ships today.

> **The foundational principle:**
> **The model proposes; a deterministic engine disposes.**
> The LLM is never the security authority, the scheduler, the credential authority, the
> transaction authority, or the final arbiter of whether an action succeeded.

---

## 1. What exists today

**A working, governed execution core — not a finished AI OS.**

| | |
|---|---|
| Workspace | 17 Rust crates, 1.98.1, gate-enforced dependency direction |
| Storage | SQLite (bundled, ≥ 3.51.3), schema at **v15** (`CURRENT_VERSION`, `migration.rs:510`), snapshot-protected migrations |
| Task engine | Durable, hand-rolled; passes all 12 ADR-0029 properties from a second test binary |
| Governance | 9-stage dispatcher; `CapabilityInvocation` cannot be constructed outside `orxnud-policy` |
| Audit | Append-only, hash-chained, durable, survives restart |
| Approvals | Single-use, digest-bound **v3**, time-boxed, bound to an approver *and* a logical step |
| Sandbox | Tier-1 execution under `bubblewrap`; cgroup v2 ceilings where the host delegates |
| Transport | JSON-RPC 2.0 over a 0600 Unix socket, protocol version 1, 18 methods |
| CLI | `orxnuctl` — hand-written parser, 5 verb groups |
| TUI | `orxnu-tui` — narrow Ratatui slice; daemon status, tasks, preview, approval, execution |
| Daemon | `orxnud` — composition root, single-instance endpoint, serves the socket |
| Provider | **One real HTTPS provider**, TLS with chain and hostname verification |
| AI | **A real proposer**: registry-derived menu → model → durable proposal → approval → governed execution |

## 2. What is actually executable

Three shipped capabilities are declared and granted independently of adapter registration.
`AdapterRegistry::shipped(workspace)` in `crates/orxnud-capability/src/dispatch.rs` always
registers `text/word-count`; it registers `filesystem/write-text` when the `orxnud-fswrite`
helper resolves, and registers `filesystem/read-text` when that same helper path resolves,
deriving the `orxnud-fsread` path without independently validating it. If `orxnud-fswrite`
cannot be resolved, both filesystem adapters are omitted and dispatch refuses those
capabilities with `NoImplementation`.
Only `text/word-count` runs without an approval in the shipped build:

```bash
orxnuctl capability run --capability text/word-count \
  --params '{"text":"hello world"}'          # Low, Tier 0, in-process, no prompt
```

`filesystem/read-text` is High, Tier 1, and requires a single-use approval. `filesystem/write-text`
is also High and Tier 1, but **the shipped build refuses it by default**, even with a valid
approval:

```bash
APPROVAL=$(orxnuctl capability approve \
  --capability filesystem/write-text --target notes.txt \
  --params '{"path":"notes.txt","contents":"hello"}' --ttl-ms 60000)

orxnuctl capability run --capability filesystem/write-text \
  --target notes.txt --params '{"path":"notes.txt","contents":"hello"}' \
  --approval "$APPROVAL"
# refused: argv_payload_exposure_refused; nothing is written
```

The refusal is deliberate: ADR-0054 Decision 7 keeps the payload-bearing capability disabled
until R-1's evidence conditions are met. It is enforced at dispatch before any process exists,
and an approval does **not** lift it. There is no operator configuration or environment variable
that enables it; the test-only exception (`with_argv_payload_exception_for_this_process`) is not
reachable from the shipped CLI. The capability remains registered so its declaration, policy and
refusal stay visible and testable.

An approval is bound to the exact parameters it was issued for. Presenting it with
`contents` changed is refused `approval-digest-mismatch` before anything runs. This binding is
part of the governance path; it is not a substitute for the separate default refusal above.

The full AI loop, through the shipped binaries:

```bash
orxnud --state-root "$ROOT" --provider-base-url https://api.groq.com/openai/v1 \
       --provider-model openai/gpt-oss-120b &
orxnuctl task create --id t1 "write notes.txt"
orxnuctl task claim  --id t1 --worker ai
orxnuctl task ai-propose --task t1 --worker ai     # model picks a capability from the registry
orxnuctl capability approve --proposal <id> --ttl-ms 60000
orxnuctl task execute --proposal <id> --worker ai  # governed; write-text is refused by default
```

The model may propose `filesystem/write-text`, but the shipped build refuses it with
`argv_payload_exposure_refused`, so that loop demonstrates the governed refusal rather
than a completed write. A successful Tier-1 execution needs a reviewed `read-text`
proposal.

## 3. Security guarantees that are real

* **Authority cannot be forged from data.** `CapabilityInvocation` does not derive
  `Deserialize`; its constructor demands `orxnud-policy`'s private seal. A compile-fail test
  with a recorded `.stderr` proves re-adding the derive breaks the build.
* **One route out.** `Dispatcher::dispatch` is the only path from an authorised intent to an
  effect. A `Subprocess` adapter has no in-process implementation: the shipped adapters'
  `invoke` returns an error rather than performing the effect, and the governed-path test
  adapter panics if the route is bypassed, so a bypass is loud rather than silent. Gate G2
  rejects `Command::new` anywhere in `orxnud-capability`.
* **Fail closed, everywhere.** A host that cannot establish the required guarantees refuses
  every Tier-1 capability — before a credential resolves, before a process exists. There is
  no unsandboxed fallback and no `BestEffort` path in the governed route.
* **Approvals mean consent.** Digest v3 binds the approver, their authority root, the
  proposer, capability, target, canonical parameters, time bounds **and the logical step**.
  One consent cannot cover a sibling step, and the durable proposal records the model that
  actually answered rather than a configured name.
* **Credential hygiene is tested, not asserted.** A sentinel value runs through every path
  that touches the provider key — resolved, refused, debugged, redacted, persisted — and its
  exact bytes are asserted absent from all of them, including every file under a real
  daemon's state root.
* **TLS cannot be downgraded.** `Scheme::carries_credentials` is true only for TLS,
  redirects are not followed, and eleven tests drive a real `rustls` handshake.

## 4. Platforms: what is proven

| | Linux | Windows |
|---|---|---|
| Compiles | ✅ | ✅ **all 16 crates, MSVC, all targets** |
| Behaviour tests run | ✅ | ✅ platform-neutral suites, on a real runner |
| Tier-1 sandbox | ✅ where the host provides guarantees | ❌ **refuses** — no backend exists |
| Isolation proven | ✅ mutation-verified (V-46) | ❌ **NOT PROVEN** (V-29) |

The Windows entries record the audit-baseline evidence; no hosted Windows run is recorded
against this worktree. Windows is neither "untested" nor "sandbox-supported". It is
**portable and compiled, with isolation unproven**: there is no Job Object or AppContainer backend, so a Tier-1 execution
is refused rather than degraded. Refusing is correct — an unsandboxed Tier-1 subprocess is
worse than no capability at all.

**The pinned GitHub-hosted Linux CI image cannot produce positive Tier-1 sandbox evidence.**
On `ubuntu-24.04` the runner cannot create an unprivileged user namespace (Ubuntu 24.04+
`kernel.apparmor_restrict_unprivileged_userns`), and a container does not escape it either.
That is measured and printed on every run. The `sandbox-integration` job reports the
limitation rather than weakening anything to hide it — see §6. **The boundary of that
statement (measured 2026-11-08):** it is the *image* that cannot isolate, not hosted CI as a
class — a hosted `ubuntu-22.04` image establishes the production Tier-1 posture on the host
itself. The Tier-1 suites have not been run there, so there is still no positive Tier-1
evidence in CI.

## 5. What is intentionally not wired

The 4c governance core **and both of its wirings** are delivered. What remains unwired is
the surfaces listed last, and nothing else.

* **Continuation is wired.** `task/continue` crosses a step boundary by claiming one step
  and proposing the next through the ordinary approval gate (ADR-0047). `claim_next_step()`
  is called from `orxnud-daemon`'s runtime, not only from tests — see
  `runtime.rs`, the `continue_task` handler. A multi-step task still stops at the boundary
  until somebody asks it to continue, which is the designed behaviour rather than a gap
  (ADR-0043, V-84).
* **Observation/disclosure is wired.** An **approved, verified read** informs **one**
  subsequent proposal, to the `(endpoint, model)` identity that asked for the read, and
  only across the **immediately following** step. `PriorStepContext` is untouched and stays
  metadata-only — the content travels on a separate, ephemeral channel that is consumed on
  release and never becomes durable (ADR-0048, V-88). This is the first path in the build on
  which workspace content can leave the machine, and `3c8a413` names itself the rollback
  point immediately before that happens.
* **An earlier version of this section claimed both of the above were absent** — that
  `claim_next_step()` had "nothing in production calls it", and that the runtime "does not
  read or write" the observation store. Both statements were true when written and are now
  false, and they contradicted §3 of [`03-system-architecture.md`](03-system-architecture.md),
  which already described the 4c governance core as delivered *with* both wirings. They are
  corrected here rather than left to contradict a normative document.
* **The scheduler is wired.** `TaskService::tick` and `next_wakeup_ms` had **no production
  caller** and `Scheduler::add_schedule` had no route at all, so no schedule could be
  registered and the timer had nothing to fire. Both are now live: `schedule/create` and
  `schedule/list` are reachable through `orxnuctl schedule add|list`, and the daemon's own
  event loop runs a bounded pass when the engine's next occurrence is due — re-reading the
  deadline each pass, so a schedule created after the timer was armed takes effect at once
  rather than waiting out the old one. A due occurrence is now created with **no request
  arriving**. Evidence: `crates/orxnud-daemon/tests/serve_lifecycle.rs`.
* **Connections are served concurrently, with bounds.** Each is its own task, under a
  connection ceiling and a frame-read deadline; `daemon/status` answers from a composition
  snapshot and takes no governed lock, and neither model route holds that lock across the
  provider's network round trip. Before this, one peer that opened a socket and never
  finished a frame prevented every other client from being served — reproducibly, and
  indefinitely. See `crates/orxnud-daemon/src/serve.rs`.
* **Still not fixed, and recorded rather than hidden:** a Tier-1 dispatch holds the
  governed lock across the sandbox execution (up to 10 s), because `Dispatcher::dispatch`
  is a synchronous function that settles its own audit obligation internally and offers no
  seam at which the lock could be released mid-effect. A request that needs durable state
  therefore still queues behind an in-flight sandboxed write. Narrowing that is a change to
  the dispatcher, not to the transport.
* A narrow **`orxnu-tui`** now exists: a Ratatui client that reuses `orxnuctl`'s transport and
  the shared approval workflow in `orxnuctl::approval`. It shows daemon status, task listing
  and inspection, and supports a one-step workflow — create a task, claim it while retaining
  the daemon-issued generation, request an AI proposal, review and approve it, execute it,
  complete or cancel it. A model-initiated file read shows the fresh challenge-bearing
  preview and requires an explicit confirmation; the daemon still validates the challenge.
  Execution results preserve the daemon's `uncertainty` fields, and `NeedsVerification` is
  rendered as unresolved rather than success. It holds no policy, storage or domain rule.
  Multi-step continuation, proposal listing, execution history, provider credential setup
  and unresolved-effect adjudication remain separate work.
* Also absent: no GUI or Tauri application, no MCP surface, no messaging, no local ASR/TTS, no
  general shell capability, no unrestricted filesystem capability, no Windows sandbox backend,
  no actor runtime beyond the local authority model.

## 6. Where the evidence is, and what it does not prove

**2072 tests run, 2072 passed (2 leaky), 6 skipped** in the latest full local gate, measured
on this working tree (`358b547` plus uncommitted Phase 1 / Phase 1.1 changes), with a varying
*leaky* count. The leak detector reports processes that outlive their test; the count varies
between runs and is not a test failure. All 6 skips are `#[ignore]`d child-process entry
points, not tests. A hosted run **is** recorded against committed `main`
([44298832443](https://github.com/Ratherrayees/OpenRayNux/actions/runs/44298832443)):
all six jobs green, recorded G9 **1898 run, 1898 passed, 116 skipped**. On a hosted runner
that cannot isolate, gate G9 excludes the Tier-1 sandbox-evidence suites and prints which it
excluded and why — those 116 exclusions are not evidence about the sandbox. The hosted
`ubuntu-24.04` runner cannot create an unprivileged user namespace; positive Tier-1 evidence
comes from this Linux development host (Fedora 44, bwrap 0.12.0), where
`scripts/run-sandbox-tests.sh --host` reported nested userns with `CapEff 0` and the
governed-path, read-text, write-text and isolation suites all passing.

**Two caveats that a green run does not carry, found 2026-10-10.** The enforcement and
resource suites `println!` and `return` when the host cannot delegate cgroups
(`crates/orxnud-platform-sandbox/tests/enforcement.rs:119-126`), which is a *pass* to
nextest and to gate G9, and no gate reads the reason. One isolation test,
`a_socket_bound_in_the_namespace_is_unreachable_from_the_host`
(`tests/isolation.rs:374`), returns early and skips its own assertion when the helper's
`bind` succeeds inside the netns — which it does on a host that can create a user
namespace. On the host this repository was measured on, that is exactly what happened.

**A green CI run proves:** the numbered gates G1–G17 plus the G2d sub-gate are
exercised on Linux (G12 is skipped without a release tag); every crate compiles for MSVC;
the platform-neutral suites behave on real Windows; the portable core is portable; and on
a host that cannot isolate, a Tier-1 capability is **refused** with the missing guarantee
named.

**It does not prove** that a Tier-1 capability executes under isolation.
`governed_path`, `read_text_real`, `write_text`, `isolation` and the sandbox suites are
positive evidence **only on a host that can create an unprivileged user namespace** — a
developer machine (`scripts/run-sandbox-tests.sh --host`) or a container on such a host.

Two claims that look like guarantees and are not:

* **Positive hosted Tier-1 isolation evidence does not exist.** A green
  `sandbox-integration` means *the environment was measured*, not *the sandbox was proven*.
* **V-75 is live-run evidence.** A real Groq `openai/gpt-oss-120b` produced and executed a
  governed proposal. No gate performs that run and none can — it needs a live credential.
  Everything *around* the model call is CI-covered; the model's contribution is not.

## 7. Current next milestone

**V-96 is recovered, not missing. This section previously said otherwise, and it was
wrong.** Verification work was carried out under V-93, V-94, V-95 and V-97, all in `main`.
This document then reported a **gap at V-96** and stated that "no definition of V-96 exists
anywhere in the repository: not in `docs/`, not in the register, not in the commit history,
not in the tree." **All four of those loci were checkable, and all four were wrong.**

A definition existed the whole time, in
[`08`](08-testing-engineering-standards.md) §"Platform boundary", row `cfg(target_os)` gate:
**V-96** is that gate G3 matched raw text, so a comment could switch it off and seven of
nine `cfg` spellings — every nested one — were invisible. The fix is implemented: commit
`7bf9da8` *"test(ci): drive the boundary gates against adversarial rewrites"* added
`scripts/rustscan.py`'s lexical classifier and `scripts/gate-selftest.py`, which drives the
real `scripts/ci-gates.sh` over temporary fixture trees. Commit `b73246d` cites it again.

The register and this section both asserted an absence that was contradicted by the file
they were describing. That is the failure mode the register's own freshness policy exists
to catch, produced *by* a reconciliation. The register row is now rewritten from recovered
evidence and is marked **`partially fixed`**, because G3 still matches platform-API paths
literally and is defeated by `use std::env::consts as host; … host::OS` — a real residual
bypass, recorded rather than closed over.

**So the next engineering milestone is no longer "define V-96".** The previous four-step
plan was built on a false premise and withdrawn; the current order was decided after PRs
#4–#8 landed and `main` went green and protected:

1. **Documentation reconciliation — landed (PR #9).** That PR reconciled this index
   against `b069595` without touching the protected audit documents; this snapshot has since
   been re-measured against `e0f6784` after the F-26b record (PR #10) and the TUI (PR #11),
   and against `358b547` after PR #14 (Windows `fsync_file` portability).
2. **F-26b investigation** — re-establish the restore/checkpoint failure sequence against
   the current source, define the recovery invariant, and design deterministic
   failure-injection tests. A focused investigation first, not an implementation; kept
   separate from S-11, F-26c and S-31. See `docs/12` F-26b.
3. **TUI vertical slice — first slice landed.** The narrow Ratatui client is in the tree
   (ADR-0060): daemon status, task listing and inspection, read-only preview, approval and
   execution, and a visible `NeedsVerification` state. No policy, storage or domain logic in
   the surface. Remaining: deeper inspection before the 2026-11-30 MVP.
4. **Remaining F-26 / S-11 / S-31 review** — establish the release safety boundaries.

The enforced constraint is that another extended round of verification-infrastructure work
must not consume the MVP time: the next milestone has to demonstrate that a human can use
the governed system through its required interface. The other candidates above remain
recorded in `docs/12` but are not the decided order.

## 8. CI state: the tool-install problem is resolved, and the load-sensitive test is fixed

**Current tree (`358b547`, tree `ab1b8c9e`): six jobs** — `Linux gates (G1-G17 + G2d)`,
`Windows cargo check (nightly)`, `Windows portability tests`,
`Tier-1 sandbox (production configuration)`, `cgroup resource enforcement (delegated)`,
`Portable core builds for wasm32`. Hosted evidence on this exact commit:
[run 44298832443](https://github.com/Ratherrayees/OpenRayNux/actions/runs/44298832443),
**all six jobs green**, recorded G9 `1898 run, 1898 passed, 116 skipped`. `main` is **protected**
with all six checks required, `strict`, pull requests required, and no force pushes or
branch deletion. The history below is preserved.

**V-68 is closed**, with two distinct records: A-040 diagnosed the fixture-observation
failure (12 claimed tasks against a budget of 8, with the extra claims slipping past a
non-atomic check — the tasks were never lost, they stayed `pending`), and A-041 closed the
engine defect it exposed (`max_concurrent_leases` is now checked inside the claim's own
`BEGIN IMMEDIATE`, on the generic and targeted paths). PR #7 and PR #8 carry the two
fixes; the occurrence records in `docs/12` were kept as written.

**`linux-gates` passes on `main` as of `c5934970`.** It did not, for a while, and the
failure mode was misleading enough to be worth recording.

### Resolved: the gate tools could not be installed in the budget

Between `6224fa57` and `965a509` the lane was **cancelled** on three consecutive runs. It was
not failing on the code: it reached `G9: tests` and was killed there having produced **zero**
test results, which places the death in the cold workspace compile rather than in any test.
A cancelled lane reports nothing about the code at all, and next to four green lanes it
reads as though five things had been verified.

The cause was our own reproducibility work. `a1c0b2e` pinned the four gate tools to exact
versions, which is right, but installed them with `cargo install … --locked` — and that
compiles each tool from source on a cold runner, before any project test can start, against a
`timeout-minutes: 15` budget. Fixed in three steps: install from prebuilt upstream binaries via
`taiki-e/install-action` pinned to a full commit SHA with `fallback: none` (`6bc2d44`); correct
`cargo-nextest` to `0.9.146`, the ceiling of that action's manifest rather than the upstream
release feed (`965a509`); raise the job timeout to 30 minutes as headroom, explicitly the
second line rather than the fix.

`Run the gates` is now green: **all selected gates passed**, nextest 1505/1505. The
tool-install problem is resolved.

### Open: an intermittent `v95_concurrency` failure under load

Run `37916621851` at `c5934970` failed at G9 on
`orxnud-task::v95_concurrency::recovery_racing_a_claim_leaves_exactly_one_owner`:

```
recovery was told the database was busy rather than what it settled:
sqlite error: database is locked
```

**A later run of the identical commit is green.** `37919194011`, same SHA `c5934970`, all five
jobs succeeded, all selected gates passed, and all 13 `v95_concurrency` tests passed
individually — including the one above. So the lane is not deterministically broken, and
whether a given push is red on G9 is currently a coin-flip.

Reproduced locally only under artificial load: 0 failures in 25 runs unloaded, **9 in 30** with
the box CPU-saturated. The observed error is `SQLITE_BUSY_SNAPSHOT` (extended code 5) at
`BEGIN IMMEDIATE`, which is returned immediately by SQLite when a write transaction cannot
upgrade its snapshot; a `busy_timeout` or busy handler does not absorb it.

**No root cause is established and no fix exists.** The working hypothesis is a defect in the
test's own `race()` fixture rather than in production code — it installs a busy handler and
assumes that is sufficient — but that has not been proven, and an edit attempted on
2026-10-08 was reverted because a controlled comparison showed it changed nothing (10/30 under
load versus 9/30 for the unmodified binary). Recorded here as an open defect with its
reproduced symptoms, not as a diagnosed cause. It is invisible locally on an idle machine,
which is exactly the property that makes it worth writing down.

### Everything else is green

`Windows cargo check` (MSVC), `Windows portability`, `Portable core builds` (wasm32) and
`Tier-1 sandbox` all pass on `358b547` — hosted run
[44298832443](https://github.com/Ratherrayees/OpenRayNux/actions/runs/44298832443), six for
six. G12 is skipped for want of a release tag to compare against. Local: 2072/2072 on the
working tree described above, and
`CI=true ./scripts/ci-gates.sh` passes end to end in about 27 seconds on a warm target
directory.

---

## Read in this order

| # | Document | What it is for |
|---|----------|----------------|
| **03** | [System Architecture](03-system-architecture.md) | **Start here.** The shape, the crate graph, the 9 dispatcher stages, **§9a: where the implementation actually stands**, and **§10: the verifier-admission invariant (K.1)**. |
| **12** | [Verification Register](12-verification-register.md) | **The highest-leverage file.** 109 rows (107 V rows plus `K.1` and `F-26`): every claim that can become false, its verification source, its review trigger, and the consequence of drift. |
| **09** | [Architecture Decision Records](09-decisions.md) | 57 primary ADRs, ADR-0001…ADR-0059 (0041 and 0042 deliberately unused; ADR-0050 also carries an amendment, and ADR-0058 carries three implementation notes, none of which are separate records). Evidence, trade-offs, rejected alternatives, **revisit conditions**. |
| **07** | [Extension & Capability Model](07-extension-capability-model.md) | The dispatcher order, the declaration structure, parameter schemas, target semantics, and the real registry. |
| **04** | [Security & Threat Model](04-security-threat-model.md) | **Normative.** Trust boundaries, threats, controls — and **§5a: the threats Stage 4c and the CI work introduced.** |
| **06** | [Deployment & Platform Model](06-deployment-platform-model.md) | Profiles, the platform boundary, and **§2.3: the honest per-platform assessment.** |
| **08** | [Testing & Engineering Standards](08-testing-engineering-standards.md) | **§19: what CI actually enforces, the real baseline, and what a green run does not prove.** |
| **04→** | [Critical Review](11-critical-review.md) | The adversarial section. What we assume, what is deliberately minimal, what we must never build. |
| **00** | [System Requirements](00-system-requirements.md) | What it must *be*. A research record. |
| **02** | [Technology Evaluation](02-technology-evaluation.md) | The decision table and licence posture. A dated evaluation. |
| **01** | [Architecture Research](01-architecture-research.md) | What the ecosystem looks like, and corrections to widely-repeated claims. |
| **05** | [Resource & Performance Model](05-resource-performance-model.md) | Budgets. All **unmeasured** — see the correction in its header. |
| **10** | [Open Questions](10-open-questions.md) | Live questions, plus preserved resolved answers. Six reconciled 2026-10-05. |
| **13** | [Phase 1 Contract](13-phase-1-contract.md) | **Historical.** The agreement Phase 1 was measured against. |
| **14** | [Phase 2 Contract & Delivery Record](14-phase-2-contract.md) | **Historical.** Durability, the engine, measured `synchronous = FULL`. |
| **15** | [Phase 4a Record](15-phase-4a-record.md) | **Historical.** The verified execution boundary, including the V-45 measurement correction. |
| **sources.md** | [Sources](sources.md) | Version claims with URLs and access dates. |

## The decisions at a glance

| Area | Decision | ADR |
|---|---|---|
| Core language | **Rust** | [0001](09-decisions.md#adr-0001) |
| Desktop | **Tauri 2**, optional separate process — *future* | [0002](09-decisions.md#adr-0002) |
| Local transport | **Unix socket + JSON-RPC 2.0**; named pipe *future* | [0003](09-decisions.md#adr-0003) |
| Runtime | **Tokio** + an explicit supervisor | [0004](09-decisions.md#adr-0004) |
| Frontend | **Svelte 5 + Vite 8** — *future* | [0005](09-decisions.md#adr-0005) |
| Storage | **SQLite** via `rusqlite`, bundled **≥ 3.51.3** | [0006](09-decisions.md#adr-0006) |
| Task engine | **Hand-rolled durable task table** | [0007](09-decisions.md#adr-0007) |
| Vector search | **None.** FTS5 now; interface exists | [0008](09-decisions.md#adr-0008) |
| Capabilities | **Three isolation tiers, no dynamic plugins** | [0009](09-decisions.md#adr-0009) |
| MCP | **External, untrusted integration boundary only** | [0010](09-decisions.md#adr-0010) |
| LLM abstraction | **Provider-neutral**, one real adapter | [0011](09-decisions.md#adr-0011) |
| Determinism | **Model proposes; engine disposes** | [0012](09-decisions.md#adr-0012) |
| Authority | **`CapabilityInvocation` is not deserialisable** | [0034](09-decisions.md#adr-0034) |
| Tier-1 execution | **PID namespace + `PDEATHSIG`**, and what it does not do | [0035](09-decisions.md#adr-0035) |
| Tree lifetime | **The PID namespace is load-bearing; `cgroup.kill` is a backstop** | [0036](09-decisions.md#adr-0036) |
| Approvals | **An approval names its approver**, and the digest binds them | [0037](09-decisions.md#adr-0037) |
| Proposals | **Durable before approved**; a lease never grants authority | [0038](09-decisions.md#adr-0038) |
| Parameters | **A capability declares them; the proposer reads the declaration** | [0039](09-decisions.md#adr-0039) |
| Provider | **One real provider over HTTP**, credential in the secret store | [0040](09-decisions.md#adr-0040) |
| Continuation | **An explicit operation, not a widened claim** | [0043](09-decisions.md#adr-0043) |
| Observation | **Governed reads; a context that carries no content** | [0044](09-decisions.md#adr-0044) |
| Disclosure | **One approval, two acts**, bound to `(endpoint, model)` | [0045](09-decisions.md#adr-0045) |
| CI boundary | **A missing guarantee is a refusal to assert, not a skip** | [0046](09-decisions.md#adr-0046) |

The full table of all 58 primary ADRs is in [09-decisions.md](09-decisions.md).

## Open before implementation

| ID | Question | Status |
|----|----------|--------|
| 🔴 [Q-OPEN-01](10-open-questions.md) | **Telegram ToS §1.5** — legal review | **Open, deliberately not blocking.** No messaging code exists; the boundary it would protect is enforced at the read layer instead. |
| 🟡 [Q-OPEN-21](10-open-questions.md) | Do TS6 and `--tsgo` diagnostics agree? | Open; a frontend deliverable, and there is no frontend yet |
| 🟡 [Q-OPEN-05](10-open-questions.md) | Model cost ceiling: per-provider or per-user? | Open — one provider ships, so the question is not yet forced |
| ✅ [Q-OPEN-17](10-open-questions.md) | Is `synchronous = FULL` affordable? | **RESOLVED** — ~2.3 ms/commit. [V-30](12-verification-register.md) |

## Reproducing the verification state

```bash
./scripts/ci-gates.sh                     # numbered gates G1–G17 plus G2d; ~3 min
./scripts/preflight.sh                    # what THIS host can actually isolate
./scripts/preflight.sh --require          # fail unless it is the production configuration
scripts/run-sandbox-tests.sh --host       # the Tier-1 suites, on a capable host
scripts/run-resource-tests.sh             # cgroup enforcement, in a delegated container
```

Last research/verification date: **2026-11-18** (index reconciled against `main` at
`358b547`, hosted run 44298832443; local gate evidence measured on the working tree with
uncommitted Phase 1 / Phase 1.1 changes).
