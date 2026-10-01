# 15 — Phase 4a Record: verified execution boundary

Status:

```text
Phase 4a implementation: COMPLETE
Phase 4b (cgroup ceilings, Windows Job Objects): NOT STARTED
Windows verification:     OPEN (V-29)
```

Phase 4a turned ADR-0009's two `declared_only` isolation properties into
**process-level evidence**, and corrected a Phase 3 blocker that turned out to be a
measurement error rather than a missing mechanism.

---

## 1. The correction

Phase 4 opened with a BLOCKED report: a detached, `SIGTERM`-ignoring grandchild
"escaped" `--unshare-pid --die-with-parent`, `--unshare-pid`, and `--die-with-parent`,
and `cgroup.kill` was unwritable.

**The escape result was wrong.** Liveness was checked by looking for the grandchild's
PID in the host's `/proc`, but the helper had reported the PID it saw **inside** its
new PID namespace — and on the host, `3` is an unrelated process. The check found a
live `/proc/3` and concluded the grandchild had escaped.

Re-measured by watching the grandchild's on-disk heartbeat *advance*:

| Flags | Result |
|---|---|
| `--unshare-pid --die-with-parent` | **CONTAINED** (5 of 5, `SIGTERM` and `SIGKILL`) |
| `--unshare-pid` only | ESCAPED |
| `--die-with-parent` only | ESCAPED |
| neither | ESCAPED |

The mechanism: `bwrap`'s forked child becomes **PID 1 of a new PID namespace**, and the
kernel guarantees that when a namespace's init dies, every remaining process in it is
sent `SIGKILL`. `PDEATHSIG` supplies the trigger; the namespace supplies the reach. A
detached grandchild cannot opt out, because leaving a PID namespace needs privileges
the sandboxed process does not have.

Recorded as **V-45**, with the generalisable lesson: a liveness assertion must
distinguish a live process from a stale artefact. `os.path.exists` and a fixed PID both
fail that; an advancing heartbeat does not. Same shape as V-31, where a tmpfs
benchmark confirmed the wrong thing.

**Condition, stated plainly:** the supervisor must signal **`bwrap`**, never the inner
process. Signalling the child kills its parent without firing `PDEATHSIG`, leaving the
namespace init alive.

---

## 2. Three guarantees, deliberately not conflated

The original single property — "no undeclared access, and no residue" — collapsed
three things provided by different kernel facilities. That collapse is what made the
phase look blocked rather than merely unfinished.

| Guarantee | Linux mechanism | Windows | Phase 4a |
|---|---|---|---|
| **Visibility** | PID + mount + net namespaces | Job Object / AppContainer | PROVEN |
| **Tree lifetime** | `--unshare-pid` + `--die-with-parent` | Job Object kill-on-close | PROVEN |
| **Resource ceilings** | cgroup v2 controllers | Job Object limits | **NOT PROVEN** |

A PID namespace gives visibility, not lifetime. A parent-death signal gives the direct
child, not the subtree. `cgroup.kill` gives both, and is writable here — but the
resource controllers beside it are not, so it is deferred to Phase 4b rather than
adopted for lifetime alone (V-46).

---

## 3. Fail-closed, not fail-open

`TreeLifetime` and `Resource` both default to **`Required`**. On a host that cannot
provide them, `SandboxSpec::run` returns `Refused(GuaranteeUnavailable)` rather than
running a weaker sandbox.

Relaxing is explicit — `accepting_best_effort_containment()` — and then
`ExecutionResult::unproven` records what was not provided, so an audit record can say
"this ran without subtree kill" instead of implying otherwise. The method name makes
the relaxation visible in a diff.

---

## 4. What the hostile helpers proved

Every one is a real subprocess under a real sandbox
(`crates/orxnud-platform-sandbox/tests/isolation.rs`).

| Hostile attempt | Result | OS mechanism |
|---|---|---|
| read an ungranted file | refused | `--ro-bind` allowlist |
| write outside the grant | host file untouched | private tmpfs + `--bind` allowlist |
| list a denied directory | contents invisible | `--tmpfs` overmount |
| connect to the host loopback | refused | `--unshare-net`, proved against a live listener |
| bind a socket | **succeeds** (unreachable) | `--unshare-net` blocks connectivity, not `bind(2)` |
| resolve DNS | refused | no resolver in the namespace |
| read the parent's environment | absent | `env_clear` on the supervisor + `--clearenv` in the sandbox |
| find a synthetic credential marker | absent | closed environment |
| reach a credential path | absent | no host filesystem in the sandbox |
| flood 50 MB of stdout | capped at 64 KiB | supervisor-side reader cap |
| flood stderr | capped | same |
| hang forever | killed at the deadline | supervisor deadline, `SIGKILL` (a `SIGTERM`-ignoring helper cannot be waited on) |
| inherit a descriptor | none beyond the sandbox's own | `Stdio::null` + baseline comparison |

Two of these corrected my own assertions rather than the sandbox:

- **`bind(2)` succeeds.** A network namespace blocks connectivity, not socket creation.
  The first test asserted `bind` must fail and failed — correctly identifying that my
  claim was wrong. The property that matters is *unreachability*, now tested directly
  by binding inside and connecting from the host.
- **A write into the sandbox's own tmpfs succeeds.** Asserting the write must fail would
  have demanded a weaker sandbox — one that denies the helper its own scratch space.
  The property is that the **host** is untouched.

---

## 5. Teeth

Every mechanism was verified by deliberate mutation, and the results are reported
rather than summarised (V-48):

| Mutation | Result |
|---|---|
| remove `--clearenv` | 2 failures |
| remove `--unshare-net` | 1 failure |
| disable the output cap in the reader | 1 failure |
| remove the `--` separator | 18 failures |
| inherit stdin on the supervisor | **inconclusive** (V-47) |
| remove `--die-with-parent` | **hung** — and revealed a real bug |

Two findings about the tests themselves:

- **The stdin mutation is inconclusive here.** The runner's stdin is already null, so
  inheriting it adds nothing observable. The property is asserted and the gap recorded.
- **An earlier mutation broke the wrong thing.** It disabled the *reporting* of the
  output cap rather than its *enforcement*, and nothing failed — a reminder that a
  mutation must break the property, not its description.

The `--die-with-parent` mutation found a genuine defect: the supervisor blocked forever
on reader threads whose pipes were held open by a surviving descendant. Fixed with a
bounded join (`join_bounded`); a hang is the worst failure a supervisor can have, so
the threads are abandoned and the output reported as truncated.

---

## 6. Security claims

| Claim | Status |
|---|---|
| Environment isolation | **PROVEN** |
| Filesystem isolation | **PROVEN** |
| Network isolation (unreachability) | **PROVEN** |
| Network isolation (`bind` denial) | **NOT PROVIDED** — documented, not claimed |
| Output bounds | **PROVEN** |
| Timeout cannot hang the daemon | **PROVEN** |
| Descriptor hygiene | **PROVEN (weak)** — teeth inconclusive, V-47 |
| Process visibility | **PROVEN** |
| Process-tree containment | **PROVEN** |
| OS-enforced memory/CPU/PID ceilings | **NOT PROVEN** — refused, V-46 |
| Credential non-leakage | **PROVEN** |
| Windows isolation | **NOT PROVEN** — no code written, V-29 |
| Cloud sandboxing | **NOT IMPLEMENTED** — documented only |

---

## 7. Deviations

1. **No Windows implementation.** Job Objects (tree kill, limits) and AppContainer
   (file, registry, network, process restriction) are the intended mechanisms and are
   documented, but nothing is written. Nothing on this host could validate it, and the
   brief forbids claiming a Linux implementation proves Windows isolation.
2. **No cgroup resource limits.** Requested by default and refused. Phase 4b.
3. **The Phase 3 contract harness still reports points 4 and 6 as `declared_only`.**
   Deliberate: it is an in-process harness and must not claim what only subprocess tests
   can establish. The process-level evidence lives in `isolation.rs`, and ADR-0009's
   documentation points at both.
4. **`bwrap` must be installed.** `BwrapRunner::probe()` reports
   `MechanismMissing` rather than falling back to running without a sandbox. An
   unsandboxed capability has no isolation at all, which is worse than no capability.

---

## 8. Amendments

ADR-0035 (new), ADR-0009 (contract points 4 and 6 now have process-level evidence),
`docs/07` (both notes), `docs/09`, `docs/12` (V-45 … V-48), `docs/README.md`.

---

## 9. Intentionally absent

No LLM. No provider. No GUI, TUI, voice, messaging, browser, or MCP. No real
capability is registered. No Phase 5+ feature. `CapabilityRegistry` still has no
production registrations; the sandbox crate has no consumer yet, which is correct — the
dispatcher integration is Phase 4b work once a governed execution path exists to hang
it on.
