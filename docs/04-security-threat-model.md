# 04 — Security & Threat Model

Status: **Draft v0.3** · Normative · reconciled **2026-10-05** against `HEAD`.

**Corrections in this pass, all in service of the word "Normative".** Four claims here
contradicted the implementation and were fixed rather than softened: the approval record's
fields (the digest is v3 and carries the approver *and* the logical step), the T2 boundary
(the model **does** hold the provider credential and **does** have network egress — what it
must not hold is a *capability* credential), the S11 row (OS hardening is no longer optional
for anything shipped), and the approval-level table (L0/L1 said no prompt; both shipped
filesystem capabilities are `High` risk and always require approval). One claim was
**withdrawn** because no such test exists: §1.9's "the S1 verification test is automated".
**§5a is new** and records the threats Stage 4c and the CI work introduced. Every control here is a requirement for
Phase 3 onward.

This product reads a person's mail, messages, calendar, health data, files and
browser sessions, and lets a probabilistic system act on their behalf. That is
a high-value target with a large blast radius. This document is written on the
assumption that **the LLM will eventually be talked into something stupid**, and
that the design must be such that this does not matter.

---

## 1. Assets

| # | Asset | Why it matters | Worst-case loss |
|---|---|---|---|
| A1 | LLM provider credentials | Full spend access; may expose other users' data if shared | Financial, cross-tenant breach |
| A2 | Messaging tokens / sessions | Read and send as the user; **Signal/Telegram sessions are non-revocable account takeover** | Complete loss of the account |
| A3 | Browser profile / cookies | Session hijack for every site the user is logged into | Total account compromise across services |
| A4 | Personal data (health, job, financial) | Intimately identifying; regulated in some jurisdictions | Irreversible privacy harm |
| A5 | Task state / memory | Integrity matters: corrupted memory becomes a wrong action | Silent, persistent incorrect behaviour |
| A6 | Audit log | The only forensic record; its absence or tampering destroys accountability | Undetectable abuse |
| A7 | Local filesystem | Documents, keys, source code | Data destruction |
| A8 | The user's attention | A spam loop is a denial-of-service on a human | Loss of trust in the product |
| A9 | System integrity | If the daemon is compromised, all of the above | Full compromise |

---

## 2. Trust boundaries

```
┌─ T0  USER ────────────────────────────────────────────────────────┐
│  the only actor who can grant authority                             │
└────────────────────────────────────────────────────────────────────┘
        │ explicit, per-grant consent
┌─ T1  CONTROL PLANE ───────────────────────────────────────────────┐
│  policy engine · approval service · config · capability registry   │
│  deterministic · fails closed · append-only audit                  │
└────────────────────────────────────────────────────────────────────┘
        │ authorised, narrow, logged
┌─ T2  EXECUTION ───────────────────────────────────────────────────┐
│  task engine · capability dispatcher · in-process adapters          │
│  ⚠ CORRECTED 2026-10-05: the model DOES hold a credential  │
│    handle (the provider key) and DOES have network egress.  │
│    What it must not hold is a *capability* credential — see │
│    the note below the diagram.                               │
└────────────────────────────────────────────────────────────────────┘
        │ process boundary
┌─ T3  ADAPTER PROCESSES ───────────────────────────────────────────┐
│  browser driver · third-party capabilities · copyleft components   │
│  ⚠ assumed buggy, not assumed malicious                           │
└────────────────────────────────────────────────────────────────────┘
        │ process + network boundary
┌─ T4  UNTRUSTED ───────────────────────────────────────────────────┐
│  MCP servers · remote tools · web content · email bodies           │
│  ⚠ ASSUMED HOSTILE. Every byte is attacker-controlled input.      │
└────────────────────────────────────────────────────────────────────┘
```

**The load-bearing rule:** T4 input may influence *what* the system proposes and
*what the model says*, and nothing else. T4 can never cause a side effect, grant
a permission, or reach a credential.

---

## 3. Threat register

Severity: **C**ritical / **H**igh / **M**edium / **L**ow.
Likelihood assumes an attacker who is *trying*, not an accident.

| ID | Threat | Vector | Sev | Controls |
|---|---|---|---|---|
| **TH-01** | **Direct prompt injection** — hostile text in a page, email, file, or message steers the model | T4→T2 | **C** | S1, S2, S3, S13 |
| **TH-02** | **Indirect/second-order injection** — injected content in data the model later *retrieves* for an unrelated task | T4→T2 | **C** | S2, S13, S16 |
| **TH-03** | **Tool abuse / excess agency** — model invokes a capability beyond user intent | T2 | **C** | S4, S5, S6, S13 |
| **TH-04** | **Confused deputy** — a capability with broad rights is invoked via a narrow-intent request | T2 | **C** | S4, S5, S8, S33 |
| **TH-05** | **Loopjacking** — user approves operation A, system executes materially different B | T2 | **C** | S6 (digest binding) |
| **TH-06** | **Credential theft via the model** — model is talked into reading/exfiltrating a secret | T2→T4 | **C** | S1, S2, S9 |
| **TH-07** | **Prompt injection into a browser session** — page content convinces the driver to act | T4→T3 | **C** | S10, S11, S6 |
| **TH-08** | **Browser session theft** — profile copied, cookies exfiltrated | T3 | **C** | S9, S12 |
| **TH-09** | **Malicious MCP server** — a third-party server is hostile from the start | T4 | **C** | S14, S15, S3 |
| **TH-10** | **Tool-description injection** — a server's tool *descriptions/annotations* lie about what a tool does | T4 | **H** | S3 (spec says treat as untrusted), S5 |
| **TH-11** | **Duplicate submission** — a retry re-executes a non-idempotent action | T2 | **H** | S7 |
| **TH-12** | **Unbounded spend** — a runaway loop or a misconfigured schedule drains the account | T2 | **H** | S17 |
| **TH-13** | **Sensitive data to a third-party model** — health/job data transits an external provider without consent | T2→T4 | **H** | S18 (NR-02) |
| **TH-14** | **Memory poisoning** — AI-generated memory later treated as authoritative fact | T2 | **H** | S19 (NR-09) |
| **TH-15** | **Shell/command injection** — user or T4 data reaches a shell | T2/T3 | **C** | S20 |
| **TH-16** | **SQL injection / deserialisation abuse** | T2 | **H** | S21 |
| **TH-17** | **Supply-chain compromise of a dependency** | build | **H** | S22 |
| **TH-18** | **Supply-chain compromise of a model file** | T4 | **H** | S23 |
| **TH-19** | **Local privilege escalation** from an adapter | T3 | **H** | S11, S24 |
| **TH-20** | **Poisoned memory / context stuffing** — huge content crowds out the system prompt | T4 | **M** | S25 |
| **TH-21** | **Audit tampering or deletion** | T1 | **H** | S26 |
| **TH-22** | **Schema-confused structured output** — malformed/malicious model output parsed unsafely | T2 | **M** | S21, S27 |
| **TH-23** | **Cross-provider schema divergence** — a strict provider rejects, a lenient one accepts a subtly different schema | T2 | **M** | S27 |
| **TH-24** | **Plugin escape** — a third-party capability reaches beyond its grant | T3 | **H** | S11, S14 |
| **TH-25** | **Denial of service on the user** — spam loops, notification storms, runaway schedules | T2 | **M** | S28 |
| **TH-26** | **Telegram/Discord account termination** via ToS-violating automation | T3→T4 | **M** | S29 (per-platform policy gate) |
| **TH-27** | **Toxic/hostile user content** stored and re-injected | T4→T1 | **M** | S30 |
| **TH-28** | **Update bricks the install** | — | **H** | S31 |
| **TH-29** | **Database corruption loses the only copy of user data** | — | **H** | S32 (bundled SQLite ≥ 3.51.3, backups) |
| **TH-30** | **Time-of-check/time-of-use on an approval** | T2 | **H** | S6 (re-verify digest at execution) |

---

## 4. Controls

### S1 — The model has no credentials (structural)

The single most important control, and the one most systems get wrong.

The context in which the model runs **cannot reach a secret handle.** It has no
`keyring` handle, no unredacted config, no unrestricted filesystem grant, and
network egress restricted to configured provider endpoints. Capabilities that
*need* credentials are invoked **through the daemon**, which injects them after
policy approval — the model never holds them.

> Direct precedent: "any untrusted code that Claude generated was run in the
> same container as credentials — so a prompt injection only had to convince
> Claude to read its own environment. … The structural fix was to make sure the
> tokens are never reachable from the sandbox where Claude's generated code
> runs." (Anthropic, *Scaling Managed Agents*, 2026-04-08)

**Verification:** a test asserts that the intent-layer execution context cannot
resolve a secret. Not a lint — a test.

### S2 — Capability-scoped sandboxing, default-deny

Every capability declares, in its manifest: the filesystem paths it needs, the
network destinations, the sub-processes it may spawn, the data classes it may
touch, its risk class, and its cost class. Grants are **denied by default**.
Absent a grant, the capability cannot do the thing. There is no "trusted" flag
that grants everything.

### S3 — Untrusted input is untrusted input

Everything from T4 — MCP tool descriptions and annotations, web page text, email
bodies, file contents, message text, model output — is labelled untrusted and
treated as data. Per the MCP spec itself: *"descriptions of tool behavior such
as annotations should be considered untrusted, unless obtained from a trusted
server."* We treat *all* of it as untrusted, including from nominally trusted
servers, because a server that was trusted yesterday may not be today.

### S4 — Least privilege per invocation

Permissions are granted per `(task × capability × parameter-scope)`, not per
capability. "May read mail from this account" is not "may read all mail".

### S5 — Risk classification, unknown ⇒ HIGH ⇒ gated

Every capability has a risk class. Anything unclassified defaults to HIGH and
requires explicit approval. No silent promotion of risk. This mirrors the OWASP
pattern: `ACTION_RISK.get(tool, HIGH) is not LOW ⇒ approval required`.

### S6 — Approval bound to a digest, short-lived, single-use, re-verified

Because human approval is the last boundary, it must actually bind.

- An approval record contains `(capability, target, **normalised** parameters,
  actor, timestamp, expiry)`.

  **Corrected 2026-10-05 — the tuple is larger than stated.** The canonical digest is
  now **`orxnud-approval-v3`** and carries, in order: approver label, approver authority
  root, proposer label, proposer authority root, capability, target, canonical params,
  issued-at, expiry, and **`step_no`** as the final field (ADR-0037, ADR-0037's v2→v3
  amendment, V-83). Two of those fields did not exist when this was written and both
  were found by asking what the record was missing:

  * **the approver.** `ApprovalRecord` had no approver field at all, `actor_label` was
    written and never read, and `Decision::Gate.approver` was *derived* from the
    proposer's authority root — an inference where evidence belonged. An approval was
    therefore a bearer token proving *parameters*, not *consent* (V-69).
  * **the step.** Without a step in the tuple, one approval authorised the same action
    at every step of a multi-step task, because the single-use ledger is keyed by that
    digest (V-83).

  Verification: `crates/orxnud-policy/src/digest.rs`, and mutation-checked — dropping
  `step_no`, reverting the prefix to `v2`, or hardcoding the recomputed step to `1` each
  fail at least one test. Historical `v2` approvals fail closed and remain structurally
  verifiable in the audit chain; no compatibility shim was added..
- A digest of that tuple is what the user is shown **and** what is verified.
- The digest is **re-verified immediately before execution**; mismatch ⇒ abort.
- Approvals expire in seconds-to-minutes, are **single-use**, and are **never
  inherited by a retry or a resumed task**. A resumed task re-requests approval.
- An **expired approval authorises nothing**, and it never leaves a dead end
  behind it (ADR-0049, V-82). Three properties, each of which is a threat if it
  fails:
  * it is refused **before any write**, so a mistyped TTL cannot mint authority
    that is unusable and mark the proposal decided anyway;
  * it is refused **before the execution lease is taken**, using the same single
    clock reading the policy stage receives — so a refusal cannot also park the
    task in `running` under a lease, and so no two clock reads can disagree about
    one authority question;
  * a proposal whose approval lapsed **unconsumed** can be approved again, but
    only with a **fresh digest**. Nothing of the old authority survives to be
    presented, and a live or consumed approval may not be replaced at all, so
    single-use is not weakened to buy the recovery.
- Risk classification, approval validation, policy lookup, or audit write
  **failure ⇒ deny** (fail closed).

> The threat this defeats is named in the literature: **Loopjacking** — "a human
> approves what they understand as operation A, while the implementation uses
> that decision for a materially different operation B." Without digest binding,
> the human-in-the-loop control is decorative.

### S7 — Idempotency keys on every side effect

Every task step carries a deterministic idempotency key derived from
`(task_id, step_key, attempt_class)`, recorded in the same transaction as the
DB write. Providers that support idempotency keys get the key. Retries reuse the
key; a **different** action requires a **new** key. Duplicate confirmation is
required for genuinely non-idempotent, irreversible actions (NR-05).

### S8 — Capability contracts are caller-agnostic

A capability never learns *who* called it, so permission checks have exactly one
place to live. This structurally prevents the confused-deputy pattern. Actor
identity is resolved by the policy layer (S33) and is **not** passed to the
capability — the invocation is already authorised by the time it arrives.

### S9 — Secret storage; config holds references only

`keyring` 4.2.0 → Secret Service (Linux), DPAPI (Windows), Keychain (macOS).
Configuration stores an *identifier*, never a secret value. Secrets are wrapped
in `zeroize` types that zero on drop. Linux headless has no Secret Service; the
fallback is an encrypted file with a **loud, explicit** warning.

**Known platform limits, stated rather than hidden:**

- **Signal `signal-cli` data dir contains the account password and all
  cryptographic keys.** A leak is unrecoverable account takeover with no
  rotation. Highest-value target in the system.
- **Telegram MTProto session** = the account authorisation key. Leaked sessions
  are portable between libraries (GramJS/Telethon share a format) — convenient
  for migration, dangerous for blast radius.
- **WhatsApp System User tokens** are long-lived and high-privilege; a leak is
  send-as-the-business to any opted-in user.
- **Browser profiles are full session credentials** for every site.

### S10 — Browser isolation and a dedicated profile

A **dedicated, non-default** `user_data_dir` per assistant identity. Never the
user's daily profile. This is also now a *requirement*, not just hygiene:
**Chrome 136+ ignores `--remote-debugging-port` against the default data
directory** (motivated by cookie theft), and Chromium's own docs warn that
"Protocol clients are typically considered trusted, as they can navigate to
arbitrary origins and have access to all origin data … These restrictions are
not extended to other types of clients."

So: our own profile, non-default, encrypted at rest, never synced, never
committed, revocable in one action.

### S11 — Subprocess sandboxing for all non-built-in capabilities

Tier 1/2 capabilities run as separate processes with:

- no ambient credentials (S1),
- a restricted filesystem view (read-only default; writes to a per-capability dir),
- an explicit network allowlist,
- a resource limit (memory, CPU time, output size) and a hard timeout,
- automatic restart with backoff, and quarantine after N failures.

**OS hardening is no longer optional.** Corrected 2026-10-05: this row previously read
"optional ... not required for v1", which is no longer true of anything shipped. Every
`Subprocess` capability executes under `bubblewrap` with PID and mount namespaces, and a
host that cannot establish the required guarantees **refuses the dispatch** — before a
credential resolves and before a process exists. There is no unsandboxed fallback and no
`BestEffort` path in the governed route (ADR-0035, V-49, V-51). What remains optional is
narrower: cgroup resource ceilings are stated as budgets rather than requirements for the
shipped capabilities, so a host that delegates nothing runs them and records the gap in
`ExecutionResult::unproven` rather than refusing for no security gain (V-53, V-56).

**Optional OS hardening** where available: Linux `seccomp`/`bubblewrap`/
namespaces; Windows Job Objects + restricted token. Not required for v1, but the
architecture must not preclude it — hence the process boundary now.

### S12 — Loopjacking-resistant confirmation UI

The confirmation prompt must render the **real** target, not a description of it:

- the exact URL/origin,
- the element's accessible name and role, highlighted in a screenshot,
- the exact normalised parameter values,
- a diff of what will change.

If the page changes between render and click, the digest no longer matches and
the call aborts (S6).

### S13 — Untrusted content cannot change instructions

- No T4 content may enter the *system* prompt or alter tool definitions.
- Tool descriptions from untrusted servers are wrapped in explicit delimiters
  and labelled as data, not instructions.
- Retrieved content is never concatenated into an instruction position.
- Output is validated against a schema before any use.

### S14 — MCP servers are untrusted by default

- Connection is **opt-in and explicit**; never auto-connected.
- **No auto-consent.** Per-tool, per-argument-scope approval, matching the same
  digest-binding rules as our own capabilities.
- Per-server kill switch, independently revocable.
- A server that is unreachable, slow, or misbehaving is quarantined, not retried
  forever.
- Servers cannot request capabilities from other servers.

**Spec-awareness:** MCP `2026-07-28` is stateless, which *helps* — there is no
session object to confuse with a grant. But the spec also removed SSE
resumability, so **a broken stream loses the in-flight request and we must
re-issue it** — with an idempotency key, or we get duplicates (S7).

### S15 — Local vs remote MCP are not equally trusted

Local stdio servers: better isolation, still untrusted.
Remote HTTP servers: also untrusted **and** network-exposed. Higher risk class,
stricter default policy, never auto-approved.

### S16 — Retrieval is scoped and provenance-tagged

Retrieved content carries provenance (source, time, trust class) and the
retrieval step is a **policy-controlled capability**, not a free-for-all. The
model can only retrieve what the current task's policy permits.

### S17 — Budget enforcement (NR-01)

Per-provider, per-model, per-**task-class** ceilings, with a hard circuit
breaker. Budget checks happen in the policy layer, before the call. Recurring
tasks have an explicit spend ceiling because a misconfigured cron expression is
an unbounded financial liability.

### S18 — Data-egress classification (NR-02)

Data is tagged by class (public / personal / sensitive / regulated). Sensitive
and regulated data may not transit an external provider without explicit,
per-flow, per-provider consent that names the provider. Enforcement is at the
provider boundary, because that is the last point where it is still possible.

### S19 — Memory is never authoritative (NR-09)

Every stored memory item carries: provenance (model/user/imported), confidence,
timestamp, and a `derived` flag. AI-generated memory is *always* derived and can
never satisfy an authority check. Corrections by the user are stored as
authoritative and supersede. Every derived item is visible, editable, and
deletable — and a deletion propagates to derived items built on it.

### S20 — No shell by default

No capability invokes a shell. Where a subprocess is genuinely required, it uses
`execve`-style argument arrays, never `sh -c`. No string interpolation into a
command. Anything requiring shell semantics is a Tier 1 subprocess with a
reviewable argv.

### S21 — Input validation and bounded deserialisation

- Every inbound payload is schema-validated **before** it reaches a type.
- Deserialisation is depth- and size-bounded; a 10 MB "web page" is rejected at
  a size limit, not parsed.
- ~~`deny_unknown_fields` on protocol types so a peer cannot smuggle fields.~~
  **Not implemented as stated, corrected 2026-10-05.** There is exactly one
  `deny_unknown_fields` in the workspace and it is on *model output*, in
  `crates/orxnud-daemon/src/proposer.rs`, because an unrecognised field from a model is a
  capability bug rather than a protocol-version question. Protocol types do not carry it.
  What *does* enforce the same property where it matters is V-76: a capability refuses an
  unrecognised parameter at parse time, and `ParamSchema::validate` states the same rule
  once in the domain layer and is asserted to agree with every parser. So the intent is
  enforced for capability parameters and not for protocol frames — stated here rather than
  left implying coverage that does not exist.
- SQL is parameterised; no string-built SQL anywhere (enforced in review, and
  by the repository layer exposing no raw-SQL escape hatch by default).
- Structured model output is validated against the schema, and the refusal path
  is handled as a distinct outcome (OpenAI documents that Structured Outputs
  does not bind the safety layer: "the API response will include a new field
  called `refusal`").

### S22 — Supply-chain controls

`cargo deny` (licence/advisory/bans/duplicates), `cargo audit`, `cargo vet`,
`cargo nextest` in CI, MSRV checking, `Cargo.lock` committed, reproducible
release builds, and SBOM generation. Dependency additions are reviewed, not
auto-merged.

### S23 — Model and external artifact integrity

Model files, browser builds, and downloaded capability binaries are
**checksum-verified** against a pinned manifest before use. A model whose hash
does not match is not loaded. This matters because a compromised model file is
indistinguishable from a compromised binary.

### S24 — Least privilege on the daemon itself

The daemon runs as an unprivileged user. Where a capability genuinely needs
elevation, it is a separate, narrowly-scoped, explicitly-invoked helper — never
a `sudo` call from the core.

### S25 — Context budget and injection resistance

A hard bound on retrieved content size. Retrieved content is truncated and
labelled before entering context. Truncation is logged, because a truncated
instruction is a silently degraded one.

### S26 — Tamper-evident audit

Append-only, hash-chained (each record includes the previous record's hash).
Exportable. Retention is configurable. Deletion is itself an audited event.
Because the audit journal is the only forensic record, tampering with it must be
*detectable*, not merely discouraged.

### S27 — Portable schema subset + sanitisation

The JSON Schema subset we emit is restricted to `string, number, boolean,
integer, object, array, enum, anyOf`; all properties in `required`;
`additionalProperties: false`; no `$ref`/`$defs`; shallow nesting. We
**sanitise** schemas before sending them to a provider, because providers
diverge sharply: Anthropic strictly validates schema keywords (a Zod
`z.number().positive()` → `exclusiveMinimum: 0` yields a **400**) whereas
OpenAI is lenient; and complex schemas can hit a provider-side grammar-size
ceiling.

### S28 — Anti-runaway and notification hygiene

Global concurrency caps. Per-interface rate limits. A hard ceiling on
outbound notifications per hour. A circuit breaker that disables a repeatedly
failing capability and *tells the user* rather than retrying silently.

### S29 — Per-platform policy gate

Before any messaging integration ships, a written platform-compliance record
exists covering: official API status, bot-vs-user, documented rate limits, and
the specific ToS clauses relied upon. This gate has already **rejected** Signal
(no API), Discord user accounts (forbidden), and WhatsApp Cloud API (forbids
household use) — see `01-architecture-research.md` §5. Shipping an integration
without this record is a policy violation of the project, not a bug.

### S30 — Content handling

Toxic or hostile content is stored as data, never as instructions, and is
redacted in logs. User-visible content is escaped by construction.

### S31 — Update safety

Updates are staged, never in-place-destructive. Pre-update backup is
mandatory. A failed migration rolls back. The daemon can always be started from
the previous binary against a restored snapshot. **There is no auto-updater that
can leave the user with nothing.** See ADR-0017.

### S32 — Data integrity and recoverability

Bundled SQLite **≥ 3.51.3** (Fedora 44's 3.51.2 carries the WAL-reset corruption
bug — see `01-…` §2.7). `journal_mode=WAL` + **`synchronous=FULL`** on the
task/queue connection, because `synchronous=NORMAL` explicitly does **not**
survive power loss. Scheduled, encrypted, rotating backups with a
**restore drill** in the test suite. Backups include `-wal`/`-shm` via the
SQLite backup API, never a naive file copy.

---

### S33 — Actor provenance and delegation integrity (ADR-0027)

Every action carries a first-class `Actor`, resolved by policy and **never
visible to the capability**.

- **The five questions the audit record must answer for every action:** who
  requested it · on whose authority · under which policy version · with which
  credential *reference* · as part of which task.
- **`External` can never grant.** It may *request*; a `Human` must authorise.
  This is what makes webhooks, inbound messages, and file watches safe to accept.
- **An `Ai` actor's authority is exactly its delegating `Human`'s authority,
  intersected with current task policy — never additive.** An AI actor cannot do
  anything the human could not do directly in that context.
- **Delegation is explicit, scoped, expiring, and revocable.** No ambient or
  unbounded delegation exists. A `Grant` carries a scope, an expiry, and a
  revocation path.
- **The approval digest includes the actor** (S6), so an approval granted to one
  actor cannot be used by another.
- **Retries and resumption re-derive the actor and re-check delegation expiry** —
  they never inherit a stale actor (TP-6).
- **`System` is not network-reachable** and is never used for user-visible
  actions.
- **Actor identity is written to the audit journal *before* the call**, never
  reconstructed afterwards.

**Verification (CI, not optional):** an `External` actor attempting to grant is
refused; an expired delegation is refused; an approval bound to actor A is
rejected for actor B; an `Ai` actor's authority never exceeds its delegating
`Human`'s under any policy.

### S34 — A local caller's identity is established by the transport, not declared (ADR-0051)

The socket's `0600` mode is a real boundary but it is a *filesystem ACL*: nothing in
the daemon compared it to anything, and no code above the transport could name a
peer it had not asked the kernel about. So every handler built `Actor::Human`
from a zero-argument function, and any process that could reach the socket
obtained human authority. The actor model was correct; the boundary that was
supposed to *produce* those actors was absent.

- **The peer identity comes from `SO_PEERCRED` at accept** (Linux). The kernel
  answers from the process it actually ran, so no request can change the answer.
- **It is compared against the installation's owner**, read from the bound
  endpoint's own metadata at startup — not `geteuid`, which diverges under
  privilege drop.
- **The comparison happens before a byte is read**, so an unauthenticated caller
  never reaches request parsing. There is no `AuthenticatedPrincipal` variant for
  "unknown": an unauthenticated caller cannot be represented as a caller.
- **An unestablishable identity refuses everyone.** "Nothing to compare against"
  must not decay into "allowed" — which is why Windows, having no local transport
  at all, keeps failing closed at `bind`, and why an unclaimed Unix reports no
  identity rather than shipping an untested `getpeereid` branch.
- **The uid is discarded after the comparison.** It never becomes a `UserId`, an
  audit field, or an IPC error, so no OS identifier leaves the daemon.
- **Declaring an identity changes nothing.** The wire protocol has no actor field
  and no handler reads one; every identity-shaped parameter a caller can send is
  ignored, and `approval_from_json` refuses a client-supplied approver
  *structurally* rather than relying on the digest to catch it.
- **Actor persistence is not authentication.** `proposer_json` is read back as an
  `Actor`, so storage is a genuine path from bytes to an actor — and it grants
  nothing, because the approval path re-derives the approver from the authenticated
  principal and never from the stored proposer.

**Verification (CI, not optional):** `crates/orxnud-daemon/tests/identity.rs`,
the `identity_boundary` module in `runtime.rs`, and
`orxnud-platform-ipc::unix::tests::the_accepted_peer_is_the_connected_process`,
which reads a principal off a real accepted connection and compares it to the
connecting process's own uid.

**Stated limit:** `SO_PEERCRED` reports a *user*, not a *session*, so it cannot
distinguish the owner from a compromised process of the owner. Nothing here depends
on that distinction. `AuthChannel::LocalInteractive` likewise records that the
caller is local and same-owner, not that a person is at a keyboard.


## 5. Approval levels

> **Corrected 2026-10-05 — this table contradicted the code.** L0 and L1 said a filesystem
> read and a filesystem write need no prompt. **Both shipped filesystem capabilities are
> `RiskClass::High` and always require a single-use, digest-bound, time-boxed approval.**
> `filesystem/read-text` is High *by decision*, not by accident: ADR-0044 Decision 1 states
> that reading is disclosure, and that `read-text` is the mechanism by which a model
> observes prior-step output, so a lower class would create the project's first capability
> whose entire purpose is to release information to a party that has not been individually
> asked. The cost is a human round trip per observation, paid on purpose. The levels below
> are kept as the *intended* policy; the mapping from risk class to prompt is what ships, and
> it is stricter than L0/L1 as written.

| Level | Examples | Requirement | Exists? |
|---|---|---|---|
| **L0 — Informational** | Read a file the user named; summarise a document they opened | No prompt; logged | **Not used by any shipped capability** |
| **L1 — Reversible local** | Write to a scratch dir; create a local note; re-run a read | No prompt; logged | **Not used** |
| **L2 — External but reversible** | Send a message the user explicitly asked for; fetch a URL | No prompt *if* the exact target was user-specified; logged |
| **L3 — Consequential** | Submit a job application; post publicly; send email on the user's behalf; spend money | **Approval, digest-bound, single-use** |
| **L4 — Irreversible or privileged** | Delete data; change permissions; install software; grant a new capability; run a third-party MCP tool for the first time | **Approval, digest-bound, single-use, plus explicit per-argument scope** |
| **L5 — Policy change** | Change policy, budget, or redaction rules; export data; rotate secrets | **Approval + re-authentication (step-up)** |

**Unknown ⇒ L4.** Risk classification is a property of the *action*, never of the
tool, never of the model, never of "the user asked for something similar last
time".

---

## 5a. Threats introduced by Stage 4c, and by the CI work

Added 2026-10-05. A threat model that stops at the phase that last revised it is a model
of a system that no longer exists, and three genuinely new exposures appeared.

### T-n4 — one approval now covers two acts

**The threat.** ADR-0045: a human approving `filesystem/read-text` authorises the local
read **and** the disclosure of the resulting bytes to a provider identity. This is the
first time one consent covers both an action on this machine and an egress to a third
party. A user who does not know that is not consenting to what was asked, and the failure
is silent — every stage reports success.

**The controls, as implemented.** The disclosure is bound to `(endpoint, model)`, not to
the model string, so re-pointing the endpoint while keeping the same model name cannot
inherit an approval given to the old destination. The disclosure gets its own audit
correlation, minted inside the record so it cannot collide with the read it descends from,
carrying `orxnud.policy/disclose`, the approving human as actor, and a bounded
content-free detail line. Nothing is durable: observations live in process memory, are
consumed by exactly one proposal, and expire on a TTL (15 min, 8 entries per task, 32 KiB
whole-blob ceiling; a truncated blob is dropped rather than released).

**Status: live since ADR-0048.** The mechanism and its runtime wiring are both implemented.
Approved workspace content can now reach a provider — that is the feature — so the exposure is
no longer hypothetical, and the controls below are what stand between a governed read and a
third party.

What the disclosure path enforces, and where each control is proved:

| control | where | evidence |
|---|---|---|
| one approval covers the read *and* the disclosure to one identity, and nothing else | ADR-0045; `ObservationOrigin` cites the approver | `observation.rs` disclosure tests |
| bound to `(canonical endpoint, model)`, not a model string | `ProviderIdentity::matches` | `a_different_endpoint_with_the_same_model_is_refused`, `a_changed_model_on_the_same_endpoint_receives_nothing` |
| the provider must name its destination, or nothing is released | `ProposalProvider::destination`, default `None` | `a_provider_without_a_declared_destination_is_declined_by_the_trait` |
| only a **verified** read produces content | `retain_read_observation` requires `is_verified()` | `a_refuted_read_is_not_retained`, `an_undetermined_read_is_not_retained` |
| only an AI-proposed read, whose model this daemon still asks | `asking_provider_identity` | `a_non_ai_proposer_is_not_retained`, `a_read_from_another_model_is_not_retained` |
| task-scoped | keyed in the store | `observations_are_never_visible_across_tasks`, `an_observation_never_crosses_a_task_boundary` |
| **step-scoped**: informs step *n+1* only | `Observation::step_no` | `an_observation_informs_only_the_immediately_following_step` |
| single-use, by erasure | `take_for` removes | `an_observation_is_consumed_by_one_proposal`, `a_consumed_observation_is_gone_rather_than_merely_marked_used` |
| whole blobs, `min(caller budget, 32 KiB)`, never truncated | store ceiling | `a_never_truncated_blob_is_whole_or_absent`, `a_caller_cannot_exceed_the_stores_own_ceiling` |
| no selector: `(task, step, identity)` and nothing else | no id exists | `a_client_cannot_select_an_observation_by_identifier` |
| never durable | `output_is_ephemeral` drops `structured_output` | `the_disclosed_content_appears_in_no_durable_row` |
| recorded before transmission; unrecordable ⇒ refused | `release_observations` | `the_disclosure_is_audited_on_its_own_correlation`, `no_disclosure_is_recorded_when_nothing_was_disclosed` |

**What is still not reachable.** There is no observation identifier to name, no retrieval, no
memory across proposals, no semantic search, and no path by which content reaches a provider
without a human approving that specific read. `PriorStepContext` remains metadata-only, so
prior steps cannot be summarised into a prompt on the model's behalf.

`3c8a413` is the last commit at which no workspace content could reach a provider; that is now
history rather than the present.

### T-n5 — a host that cannot isolate, and a test suite that wants it to

**The threat.** ADR-0046. The obvious way to make a sandbox test green on a host that
cannot sandbox is to weaken the contract. The subtler way is to weaken the *assertion* —
report a run as passing because the thing that would have failed did not run.

**The controls, as implemented.** `BwrapRunner::probe()` measures what the host provides
by *running* the namespace, because `bwrap --version` succeeding says nothing: a
GitHub-hosted runner ships `bwrap` and cannot create a user namespace, and reports the
tier-1 capability as refused. `host_capability()` surfaces that through `daemon/status`,
`orxnud --doctor` and `orxnuctl doctor`, reading the runner's own answer and the same
`AvailableGuarantees::check` the dispatcher runs — so a diagnostic cannot disagree with the
dispatch that refused. On a host that cannot isolate, the end-to-end tests assert a
**refusal** — non-zero exit, missing guarantee named, nothing written — rather than a
successful execution or a skip. Gate G9 measures the host before choosing its scope and
prints what it excluded, then greps its own output for the refusal sentinel so a suite
added later and forgotten fails the gate instead of being silently dropped.

**The invariant, stated so it can be checked:** *OpenRayNux never executes Tier-1 work
merely because CI wants the test to pass.* It holds structurally rather than by
convention — on a host that cannot isolate the assertable outcome **is** the refusal, so
the executing path is unreachable.

**What is deliberately not done.** Making the hosted `sandbox-integration` lane produce
positive Tier-1 evidence would require disabling AppArmor's unprivileged-userns
restriction, or loading a per-binary AppArmor profile for `bwrap`, on the runner. Both are
host security-policy changes made so a test can pass. Neither was done. The lane reports
the limitation and produces no positive evidence, and a green run there means "the
environment was measured", not "the sandbox was proven" (V-85, V-86, V-87).

### T-n6 — a sandbox measured in a configuration no user runs

**The threat.** A `--privileged` or `CAP_SYS_ADMIN` container makes the Tier-1 probe pass
while exercising nothing real: `bwrap` then creates **no** user namespace, and the identity
inside the sandbox is the full map `0 0 4294967295` with the container's capabilities,
against production's `1000 0 1` with none. A green suite there would be evidence about a
configuration OpenRayNux will never ship — worse than no evidence, because it looks like
evidence.

**The control.** `BwrapRunner::probe_identity()` reads `uid_map` and `CapEff` from *inside*
the probe sandbox, so the configuration is read rather than inferred from how the sandbox
was launched. The Tier-1 lane runs `preflight --require` first and exits non-zero unless
the nested shape is observed. The generalisable rule, and the one worth keeping: **a
sandbox test is evidence only if it ran in the same privilege configuration as
production.**

### T-n7 — Windows: portable is not isolated

**The threat.** Reading "all 16 crates compile for MSVC" as "Windows is supported".

**The facts.** It is now true that all 16 compile and that both Windows CI lanes are green,
and it remains true that **Windows isolation is NOT PROVEN**. No Job Object or AppContainer
backend exists; `host_backend()` binds the refusing `UnsupportedRunner` off Linux, so a
Tier-1 execution on Windows is refused rather than degraded. Refusing is the correct
behaviour and is preferable to an unsandboxed Tier-1 subprocess. Gate G4's `unsafe`
prohibition is a large part of why no Windows backend exists yet: a real one needs
`windows-sys` and `unsafe`, in a platform crate that has not opted in (ADR-0035, V-29).

---

## 6. Data classification and retention

| Class | Examples | Default egress | Default retention |
|---|---|---|---|
| **Public** | Open-source repos, public docs, public job posts | Any configured provider | Indefinite |
| **Personal** | Calendar, notes, messages | Named providers only, consented | Indefinite, user-deletable |
| **Sensitive** | Message bodies, browsing history, job applications | **Explicit per-flow consent** | Indefinite, user-deletable |
| **Regulated** | Health, biometrics, financial | **Blocked by default** | Explicitly configurable, audited |

Derived data (embeddings, summaries, extracted entities) inherits the **highest**
class of its sources. Deleting a source deletes its derived items.

---

## 7. Emergency controls

- **Kill switch** — a single action that: cancels all tasks, revokes all pending
  approvals, drops all MCP connections, and kills the browser. Must work while
  the daemon is saturated.
- **Lockdown mode** — disables every capability requiring external network
  access, leaving local-only capabilities and all data intact. The correct mode
  for a hostile network or a suspected compromise.
- **Revoke a single capability** without uninstalling.
- **Revoke a single credential** without touching the rest.
- **Export-everything** — the user's data, portable, at any time, with no
  dependency on the product working.
- **Full wipe** — delete all state, keeping only config. Irreversible; requires
  confirmation.

---

## 8. What this model explicitly does *not* claim

Honesty about limits, because a threat model that overclaims is worse than none:

- **It cannot stop the user from approving a bad action.** Mitigation is
  legibility: real previews, real diffs, plain language. The user is the final
  authority by design.
- **It cannot make an untrusted MCP server safe.** It can only contain it. The
  sandbox boundary is the mitigation, not the code review of the server.
- **It cannot prevent all prompt injection.** It prevents injection from having
  *consequences* — which is the achievable goal. S1 means a successful injection
  can at worst cause the assistant to do something embarrassing within already-granted,
  already-logged, already-bounded permissions.
- **It cannot make third-party model providers safe.** Data egress is consented,
  classified, and audited, but once data leaves, it is outside our control.
- **It does not defend against a compromised host.** If the machine is rooted,
  the keyring is compromised.
- **Bot-detection evasion is deliberately out of scope.** Building a stealth
  stack makes us indistinguishable from an attacker, which is what these
  defences are optimised to catch.
