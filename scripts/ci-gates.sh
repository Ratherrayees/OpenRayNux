#!/usr/bin/env bash
# Phase 1 CI gates (docs/13-phase-1-contract.md §5).
#
# # Why a script rather than CI YAML
#
# The gates must be runnable locally, on a laptop, with no CI minutes and no
# runner. A gate that only exists in YAML is a gate nobody runs until it fails in
# CI, which is the worst possible time to discover it was wrong.
#
# Every gate here is *mechanical*. Where a gate cannot be fully mechanical, that
# is stated in its comment rather than papered over -- a check that cannot fail is
# not a gate.
#
# # Usage
#
#   scripts/ci-gates.sh            # all gates
#   scripts/ci-gates.sh G3 G5      # named gates
#   CI=true scripts/ci-gates.sh    # a missing tool fails instead of skipping
#
# Exit status is 0 only if every selected gate passed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Gates needing a tool this machine may lack. Under `is_strict` (below) a missing
# tool is a failure; locally it is a visible skip. A silently skipped gate is worse
# than a missing one, which is why skips are counted and printed.

# Whether a value means "yes" in this script's environment.
#
# Empty, `0`, `false`, `no` and `off` mean no. Everything else means yes. Kept as
# one function so the strict-mode decision has a single definition, and so it can
# be *tested* — the previous version compared against a literal at six separate
# sites, which is how it came to disagree with its own documentation.
truthy() {
    case "${1:-}" in
        ''|0|false|no|off|FALSE|NO|OFF) return 1 ;;
        *) return 0 ;;
    esac
}

# Whether a missing tool must fail the run rather than skip.
#
# The contract, in one place:
#
#   CI set to anything truthy           -> strict   (this is what CI sets)
#   ORXNUD_STRICT set to anything truthy -> strict   (explicit local opt-in)
#   anything else                        -> developer-friendly skips
#
# `CI=deny` remains strict, so the previously-documented explicit spelling still
# works, and `CI=true` — which is what GitHub Actions actually sets — is strict
# for the first time.
is_strict() {
    truthy "${ORXNUD_STRICT:-}" || truthy "${CI:-}"
}

have() { command -v "$1" >/dev/null 2>&1; }

# The crate graph fixed by docs/13 §3.1. Gate G7 compares the workspace manifest
# and the directory listing against this, so the expected list exists in exactly
# one place a reviewer can diff against the docs.
EXPECTED_CRATES=(
  orxnud-domain
  orxnud-protocol
  orxnud-store
  orxnud-policy
  orxnud-task
  orxnud-capability
  orxnud-audit
  orxnud-config
  orxnud-obs
  orxnud-daemon
  orxnuctl
  orxnud-platform-fs
  orxnud-platform-sandbox
  orxnud-platform-secrets
  orxnud-platform-notify
  orxnud-platform-ipc
)

FAILED=()
SKIPPED=()

declare -A NAMES=(
  [G1]="format"
  [G2]="dependency graph"
  [G2d]="authority boundary"
  [G3]="platform boundary"
  [G4]="unsafe"
  [G5]="portable core (wasm)"
  [G6]="clippy"
  [G7]="workspace members"
  [G8]="licences and supply chain"
  [G9]="tests"
  [G10]="secret hygiene"
  [G11]="vulnerabilities"
  [G12]="semver"
  [G13]="boundary gate self-tests"
)

banner() { printf '\n\033[1m== %s: %s\033[0m\n' "$1" "${NAMES[$1]}"; }
ok()      { printf '   \033[32mok\033[0m    %s\n' "$1"; }
bad()     { printf '   \033[31mFAIL\033[0m  %s\n' "$1"; }
note_skip() { printf '   \033[33mskip\033[0m  %s\n' "$1"; SKIPPED+=("$gate"); }
# Informational only. Deliberately NOT `note_skip`: a narrower test scope on a host that
# cannot isolate is not a skipped gate -- the gate still runs, still runs the tests that
# apply, and still fails if any of them fail. Calling it a skip would overstate it.
note()     { printf '   \033[2m%s\033[0m\n' "$1"; }
fail_gate() { bad "$1"; FAILED+=("$gate"); }

# The `[dependencies]` section of a manifest, one bare dependency name per line.
#
# Dev-dependencies are excluded on purpose: they do not participate in the
# layering rule, and `proptest`/`trybuild` in a core crate is expected.
#
# The name is cut at `=`, `{`, or whitespace, because a line reads
# `orxnud-domain = { workspace = true }` and comparing the whole line against a
# bare crate name never matches -- a gate that silently finds no edges is worse
# than no gate at all.
manifest_deps() {
  awk '
    /^\[dependencies\]/{f=1;next}
    /^\[/{f=0}
    f && NF {
      line=$0
      sub(/[ \t]*=.*$/, "", line)   # drop ` = { ... }`
      sub(/[ \t]*#.*$/, "", line)   # drop a trailing comment
      gsub(/^[ \t]+|[ \t]+$/, "", line)
      if (line != "") print line
    }
  ' "$1"
}

# Test-only region removal, and both boundary gates, live in scripts/gate_policy.py.
#
# They were here as an awk script and two regular expressions, and all three failed in
# the same way: a regular expression cannot tell code from a comment, so text that
# merely *looks* like the forbidden thing switched the check off or evaded it. The
# replacement classifies characters lexically (Rust's comment and literal grammar,
# including nested block comments, raw strings and the char/lifetime ambiguity) and
# then looks inside cfg predicates rather than at a prefix.
#
# Kept in Python because `scripts/mutate.sh` already requires `python3`, so this adds no
# new tool to CI. See scripts/rustscan.py for the reasoning.

# The root under test. `ORXNUD_GATE_ROOT` points the boundary gates at a fixture tree
# instead of this repository, which is how `scripts/gate-selftest.py` drives *these*
# functions against temporary sources rather than against a reimplementation of them.
gate_root() {
  printf '%s' "${ORXNUD_GATE_ROOT:-$REPO_ROOT}"
}

# G2d -- authority is minted only by orxnud-policy, and only where rustc can see it.
#
# The boundary is now a compiler fact rather than a convention. `AuthorisationProof`,
# `CapabilityInvocation` and `DispatchView` live in orxnud-policy beside the
# `pub(crate)` constructors that produce them, and `CapabilityAdapter`/`AdapterBundle`
# are whole `pub(crate)` traits. Rust has no friend crates, so "exactly one crate may
# construct this" is only expressible as `pub(crate)` on a type its owner can see.
#
# The invariant is about *minting*, not naming. A capability crate legitimately takes a
# `CapabilityInvocation` as an argument -- that is the whole point of it -- and cannot
# construct one. So the gate forbids the minting verbs outside orxnud-policy, asserts the
# constructors are still `pub(crate)` and the sealed traits still `pub(crate)`, and
# refuses a re-export from orxnud-domain, which everything depends on.
#
# Why keep a lexical scan when rustc already refuses the obvious attempts: because this
# gate's own history is the argument. It reported `ok` on a tree that forged authority
# three separate ways from a standalone crate, two of which named none of the symbols it
# looked for. A gate that cannot fail is worse than no gate, so this one is asserted
# against drift by its own self-tests (G13) as well as by `gate_policy.py`.
gate_G2d() {
  banner G2d
  if python3 scripts/gate_policy.py g2d --root "$(gate_root)"; then
    ok "authority is minted only by orxnud-policy, and only through pub(crate)"
  else
    fail_gate "authority is reachable outside orxnud-policy, or its constructors widened"
  fi
}

# G3 -- no platform branch outside orxnud-platform-*.
#
# The boundary is only real if it is checked. A `cfg(target_os)` in the core means the
# core has an opinion about the OS, which is what the trait boundary exists to prevent.
#
# The previous pattern required the platform key to be the *first* token inside `cfg(`,
# so seven of the nine spellings of a platform branch were invisible -- including every
# nested form, which is what `not`/`all`/`any` exist to produce. The predicate is now
# read as a predicate and searched at any depth. See scripts/rustscan.py.
gate_G3() {
  banner G3
  local out
  out="$(python3 scripts/gate_policy.py g3 --root "$(gate_root)" 2>&1)" && out="" || true
  if [ -z "$out" ]; then
    ok "no platform branch or platform value outside orxnud-platform-*"
    python3 scripts/gate_policy.py g3-platform-crates --root "$(gate_root)" | sed 's/^/   /'
  else
    printf '%s\n' "$out" | sed 's/^/   /'
    fail_gate "a platform branch exists outside orxnud-platform-*"
  fi
}

gate_G1() {
  banner G1
  if cargo fmt --all -- --check; then
    ok "cargo fmt --check"
  else
    fail_gate "formatting differs; run 'cargo fmt --all'"
  fi
}

# G2 — the crate graph, from docs/13 §3.2.
#
# Three rules, each checkable by reading manifests:
#   a. `orxnud-domain` depends on nothing that can do I/O, spawn a runtime, or
#      reach the OS.
#   b. `orxnuctl` may depend on `orxnud-protocol` and nothing else internal.
#   c. Internal dependency edges point inward: a crate never names a crate that
#      already depends on it.
#
# (d) `orxnud-task` and `orxnud-capability` are separate layers on purpose, even
#     though both sit above `orxnud-policy`. They were one `|`-grouped entry until
#     Phase 3, which read as though `orxnud-task -> orxnud-capability` were permitted.
#     It never was -- the inward check only allows strictly-earlier layers -- but a
#     reader checking whether the task engine can reach a capability had to run the
#     gate rather than read the list. The dependency direction is now obvious on its
#     face:
#
#         orxnud-task        -X-> orxnud-capability   (the engine cannot reach one)
#
#     The task engine is the most security-sensitive subsystem in the repository, so
#     "the engine has no edge to any capability" must be legible without executing
#     anything. See docs/09 ADR-0033.
gate_G2() {
  banner G2
  local ok_all=1

  # The internal crates an interface (`orxnuctl`) is allowed to name.
  #
  # Transport and wire vocabulary, plus the two crates that own the provider credential.
  #
  # Everything that could carry a *domain rule* -- store, task engine, policy,
  # capability, daemon -- is absent on purpose, because the whole point of the check is
  # that the CLI cannot reimplement a rule it cannot see (docs-03 §2, IR-2).
  #
  # `orxnud-domain` and `orxnud-platform-secrets` were added for one command,
  # `provider credential`, and the reasoning is the gate's own: that command must use the
  # authoritative `SecretRef` and `SecretsContract` rather than hand-roll a reference
  # format, because a CLI that invented its own would silently write a credential the
  # provider cannot read. Naming the real types is the safer arrangement, not the
  # dangerous one -- and the CLI still cannot decide anything, because a `SecretRef` is a
  # name and the authority to read it lives in the store.
  local CLI_ALLOWED_INTERNAL="orxnud-platform-ipc orxnud-protocol orxnud-domain orxnud-platform-secrets"

  # --- (a) the domain has no I/O or runtime dependency ---
  local domain_deps
  domain_deps="$(manifest_deps crates/orxnud-domain/Cargo.toml)"
  printf '   orxnud-domain depends on: %s\n' "$(echo "$domain_deps" | tr '\n' ' ')"
  local forbidden='^(tokio|rusqlite|keyring|clap|reqwest|walkdir|notify|directories|uuid|croner|jiff|blake3)$'
  if printf '%s\n' "$domain_deps" | grep -Eq "$forbidden"; then
    printf '%s\n' "$domain_deps" | grep -E "$forbidden" | sed 's/^/     offending: /'
    fail_gate "orxnud-domain has an I/O or runtime dependency"
    ok_all=0
  else
    ok "orxnud-domain has no I/O or runtime dependency"
  fi

  # --- (b) interfaces depend on protocol only ---
  local cli_internal unexpected
  cli_internal="$(manifest_deps crates/orxnuctl/Cargo.toml | grep -E '^orxnud-' | sort -u | tr '\n' ' ')"
  cli_internal="${cli_internal% }"
  # A *subset* test against the permitted set, not an equality test against one name.
  #
  # `orxnud-platform-ipc` is permitted because opening the approved local transport is
  # not the thing this gate protects against. The rule's purpose (docs-03 §2, IR-2) is
  # that a CLI cannot reimplement a domain rule it cannot see -- so the danger is
  # domain, business and security types, not sockets. Concretely:
  #
  #   transport dependency  = ALLOWED   (orxnud-platform-ipc: the socket)
  #   wire vocabulary       = ALLOWED   (orxnud-protocol: the frames)
  #   domain/business/security = FORBIDDEN (orxnud-domain, -store, -task, -policy,
  #                                         -capability, -daemon)
  #
  # An equality test would have to be edited every time a permitted crate is added,
  # and the failure that gets caught is the wrong one. A subset test fails on
  # anything *added* without a deliberate edit to this list, which is the direction
  # that matters.
  unexpected="$(comm -23 \
    <(printf '%s\n' $cli_internal | sort -u) \
    <(printf '%s\n' $CLI_ALLOWED_INTERNAL | sort -u) \
    | tr '\n' ' ')"
  unexpected="${unexpected% }"
  if [ -z "$unexpected" ]; then
    ok "orxnuctl depends only on the permitted internal crates: ${cli_internal:-none}"
  else
    fail_gate "orxnuctl depends on internal crates it may not: ${unexpected}"
    ok_all=0
  fi

  # --- (c) inward-pointing edges ---
  # Ordered deepest-dependency-first: a crate may name anything *earlier* in this
  # list and nothing later. The order is read off the current graph, so it is worth
  # re-deriving rather than assuming: `orxnud-audit` depends on `orxnud-store`, so
  # store must precede audit. Getting this backwards produces a gate that fails on
  # correct code, which is how gates get disabled.
  #
  # Platform adapters sit at layer 1: they depend only on the domain and are
  # depended on *only* by the daemon. Putting them at the top would make a
  # platform crate able to depend on the daemon, which is exactly backwards.
  local layers=(
    "orxnud-domain"
    "orxnud-protocol|orxnud-store|orxnud-obs|orxnud-config|orxnud-platform-fs|orxnud-platform-secrets|orxnud-platform-notify|orxnud-platform-sandbox|orxnud-platform-ipc"
    "orxnud-audit"
    "orxnud-policy"
    "orxnud-task"
    "orxnud-capability"
    "orxnud-daemon"
    "orxnuctl"
  )
  local i crate dep allowed_names manifest
  for i in "${!layers[@]}"; do
    # Every layer strictly before this one is permitted.
    #
    # The `|` group separators become spaces, and *must* become plain spaces:
    # replacing them with ", " would leave entries reading "orxnud-store," which
    # never matches a bare crate name under `grep -x`. The gate then rejects
    # correct code, which is how a gate earns itself a bypass.
    allowed_names="${layers[*]:0:$i}"
    allowed_names="${allowed_names//|/ }"
    for crate in $(echo "${layers[$i]}" | tr '|' ' '); do
      manifest="crates/$crate/Cargo.toml"
      [ -f "$manifest" ] || continue
      for dep in $(manifest_deps "$manifest" | grep -E '^orxnud-' || true); do
        if ! printf '%s\n' $allowed_names | grep -qx -- "$dep"; then
          fail_gate "$crate depends on $dep, which is not inward (may depend on: $(echo $allowed_names | tr " " ", "))"
          ok_all=0
        fi
      done
    done
  done
  # The policy-seal check was rule (d) here. It is now gate G2d, because a boundary
  # that can only be exercised as part of a larger gate cannot be self-tested in
  # isolation -- and an untested enforcement gate is the thing this milestone exists to
  # repair. `ALL_GATES` includes G2d, so `scripts/ci-gates.sh` with no arguments still
  # runs it; only a caller that asked for G2 alone now gets the dependency graph.

  # --- (e) the task engine cannot reach a capability ---
  #
  # The inward check above already implies this. Asserting it separately anyway,
  # because this single fact is the one Phase 3 depends on: if the engine could name
  # a capability, then AUTHORITY -- stage 1 of the dispatcher -- would be validating
  # a value the engine itself minted, and every stage after it would be decorative.
  # A property worth naming is worth a check that fails by name.
  if manifest_deps crates/orxnud-task/Cargo.toml | grep -qx 'orxnud-capability'; then
    fail_gate "orxnud-task depends on orxnud-capability: the task engine must not be able to reach a capability"
    ok_all=0
  else
    ok "orxnud-task cannot reach orxnud-capability"
  fi

  # The reverse direction is deliberately NOT asserted.
  #
  # An earlier version of this check also demanded `orxnud-capability ->
  # orxnud-task` on the theory that a capability runs as a task step. That is an
  # architectural decision, not a boundary fact, and `orxnud-capability` does not
  # depend on `orxnud-task` today. Whether the dispatcher should call into the task
  # engine, or the daemon should compose both and pass a task context in, is open.
  # Asserting it here would smuggle a design choice into a documentation commit and
  # make the graph fail for the wrong reason. The one property that must hold today
  # is the forbidden direction above.

  # --- (f) only the sandbox crate may spawn a capability process ---
  #
  # Phase 4b's central invariant (V-50/V-51): a Tier-1 capability executes only
  # through `ExecutionBackend`, whose implementation lives in the sandbox crate. A
  # `Command::new` anywhere in `orxnud-capability` would be a second, unaudited
  # execution route -- and `orxnud-task` may not even reach that crate, so it could
  # not be caught by the seal grep or by review alone.
  local spawners
  spawners="$(grep -RIn 'Command::new\|process::Command' crates/orxnud-capability/src \
    --include='*.rs' | grep -vE ':[0-9]+:[[:space:]]*(//|///|//!|\*|/\*)' || true)"
  if [ -n "$spawners" ]; then
    printf '%s\n' "$spawners" | sed 's/^/     /'
    fail_gate "orxnud-capability spawns a process directly; Tier-1 execution must go through ExecutionBackend"
    ok_all=0
  else
    ok "only the sandbox crate spawns capability processes"
  fi

  # --- (g) no SandboxRunner may report a refusal after it has started a process ---
  #
  # `ExecutionStatus::Refused` is a *claim that nothing ran*. A runner that starts a
  # process and then reports it is claiming something it cannot know, and the two
  # shipped consumers turn that claim into a retry permission: the capability layer reads
  # it as `ExecutionCertainty::NothingAttempted`, the journal as `Denied`, and the effect
  # ledger as `not-performed` -- the one status `recover()` reads as "a repeat cannot
  # duplicate anything".
  #
  # `ExecutionStatus::Abandoned` exists for the post-start case, so there is no reason for
  # a runner to reach for `Refused` after a spawn, and the compile-time check that would
  # make the mistake impossible does not exist. A mutation experiment confirmed the gap:
  # a *second* `SandboxRunner` that spawns a real process and then returns `Refused`
  # compiles, and the whole workspace suite stays green.
  #
  # Per `impl SandboxRunner for`, because the whole point is to cover implementations the
  # Linux backend's own unit test cannot see. Scoped to production sources: a test fixture
  # that returns a chosen status is not claiming anything about the world.
  local runners refusal_after_spawn
  runners="$(grep -RIl 'impl .*SandboxRunner for' crates/*/src --include='*.rs' || true)"
  refusal_after_spawn=""
  for runner in $runners; do
    refusal_after_spawn="$refusal_after_spawn$(awk '
      /^impl .*SandboxRunner for/ { inimpl = 1; depth = 0 }
      inimpl {
        n = gsub(/\{/, "{"); depth += n
        n = gsub(/\}/, "}"); depth -= n
        # A comment line is not a construction. Stripped whole-line, which is enough
        # because a construction is never on the same line as a comment marker.
        line = $0
        sub(/[ \t]*\/\/.*$/, "", line)
        if (line ~ /ExecutionStatus::Refused/ && seen_spawn) {
          printf "%s:%d:%s\n", FILENAME, FNR, line
        }
        if (line ~ /Command::new|spawn_supervisor|\.spawn\(/) { seen_spawn = 1 }
        if (depth <= 0 && NR > 1 && inimpl) { inimpl = 0; seen_spawn = 0 }
      }
    ' "$runner")"
  done
  if [ -n "$refusal_after_spawn" ]; then
    printf '%s\n' "$refusal_after_spawn" | sed 's/^/     /'
    fail_gate "a SandboxRunner reports ExecutionStatus::Refused after starting a process; Refused claims nothing ran, and a post-start give-up is ExecutionStatus::Abandoned"
    ok_all=0
  else
    ok "no SandboxRunner reports a pre-spawn-only status after starting a process"
  fi

  [ "$ok_all" -eq 1 ] && ok "all internal dependency edges point inward"
}

# G4 — zero unsafe outside orxnud-platform-*.
#
# Phase 1's target is a hard zero (docs-13 §9). Every crate also carries
# `#![forbid(unsafe_code)]`, so a violation fails the build; this gate reports the
# count so a regression is visible in review rather than only in CI output.
gate_G4() {
  banner G4
  local hits
  # Comment lines and the `unsafe_code` attribute are excluded: both mention the
  # word without using it, and every crate legitimately carries
  # `#![forbid(unsafe_code)]` precisely *because* the count must be zero.
  hits="$(grep -RInE '\bunsafe\b' crates --include='*.rs' \
    | grep -vE '^crates/orxnud-platform-[a-z]+/' \
    | grep -vE ':[0-9]+:[[:space:]]*(//|///|//!|\*|/)' || true)"
  if [ -z "$hits" ]; then
    ok "zero unsafe outside orxnud-platform-*"
  else
    printf '%s\n' "$hits" | sed 's/^/     /'
    fail_gate "unsafe appears outside orxnud-platform-*"
  fi
}

# G5 — the portable core builds for a target with no platform crates.
#
# This is the gate that makes "the core is portable" a fact rather than a claim. A
# wasm32 check cannot succeed if a core crate transitively depends on a platform
# crate, because none of them build for wasm.
gate_G5() {
  banner G5
  if ! rustup target list --installed 2>/dev/null | grep -qx wasm32-unknown-unknown; then
    if is_strict; then
      fail_gate "wasm32-unknown-unknown is not installed (rustup target add wasm32-unknown-unknown)"
    else
      note_skip "wasm32-unknown-unknown not installed"
    fi
    return
  fi
  if cargo check -p orxnud-domain -p orxnud-protocol --target wasm32-unknown-unknown; then
    ok "orxnud-domain + orxnud-protocol check for wasm32-unknown-unknown"
  else
    fail_gate "the portable core does not build for a platform-free target"
  fi
}

gate_G6() {
  banner G6
  if cargo clippy --workspace --all-targets -- -D warnings; then
    ok "clippy clean with -D warnings"
  else
    fail_gate "clippy reported warnings"
  fi
}

# G7 — the workspace member list matches docs/13 §3.1 exactly.
#
# A crate added under `crates/` but not declared would never be built or tested. A
# crate removed from the contract but left on disk would look like work in
# progress. Both are drift, so both fail.
gate_G7() {
  banner G7
  local ok_all=1

  local declared expected on_disk undeclared
  declared="$(awk '/^members = \[/{f=1;next} /^\]/{f=0} f' Cargo.toml \
    | tr -d ' ", ' | grep -v '^$' | sed 's|crates/||' | sort)"
  expected="$(printf '%s\n' "${EXPECTED_CRATES[@]}" | sort)"

  if [ "$declared" = "$expected" ]; then
    ok "workspace members match the contract (${#EXPECTED_CRATES[@]} crates)"
  else
    printf '     declared: %s\n' "$(echo "$declared" | tr '\n' ' ')"
    printf '     contract: %s\n' "$(echo "$expected" | tr '\n' ' ')"
    fail_gate "the workspace member list differs from docs/13 §3.1"
    ok_all=0
  fi

  on_disk="$(find crates -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort)"
  undeclared="$(comm -23 <(printf '%s\n' "$on_disk") <(printf '%s\n' "$expected") || true)"
  if [ -n "$undeclared" ]; then
    printf '     on disk but not in the contract: %s\n' "$(echo "$undeclared" | tr '\n' ' ')"
    fail_gate "an undeclared crate directory exists; adding one requires an ADR"
    ok_all=0
  else
    ok "no undeclared crate directories"
  fi

  # Every internal dependency must inherit the pinned version rather than pinning
  # its own, so a version bump is one edit.
  for crate in "${EXPECTED_CRATES[@]}"; do
    local manifest="crates/$crate/Cargo.toml"
    [ -f "$manifest" ] || continue
    if grep -qE '^orxnud-[a-z-]+ *= *\{[^}]*path' "$manifest"; then
      fail_gate "$crate names an internal dependency by path instead of inheriting it"
      ok_all=0
    fi
  done
  [ "$ok_all" -eq 1 ] && ok "internal dependencies inherit from [workspace.dependencies]"
}

gate_G8() {
  banner G8
  if ! have cargo-deny; then
    if is_strict; then
      fail_gate "cargo-deny is not installed (cargo install cargo-deny)"
    else
      note_skip "cargo-deny not installed"
    fi
    return
  fi
  # `licenses` is the copyleft gate; the rest covers bans, unknown registries, and
  # advisories.
  if cargo deny check licenses; then
    ok "licences accepted; no GPL/AGPL/NC (deny.toml)"
  else
    fail_gate "a licence is outside the allowlist, or is copyleft"
  fi
  if cargo deny check bans sources advisories; then
    ok "supply chain: bans, sources, advisories"
  else
    fail_gate "cargo deny reported a ban, an unknown source, or an advisory"
  fi
}

gate_G9() {
  banner G9
  if have cargo-nextest; then
    # `nextest` rather than `cargo test` for one concrete reason: it runs each
    # test in its own process. TP-7 spawns and SIGKILLs a child, and a test that
    # kills processes or exits from a destructor would take the rest of a
    # single-process test binary down with it.
    #
    # # Scope is measured, not assumed
    #
    # Some suites assert that a Tier-1 capability *executes under isolation*, and
    # that is only observable on a host that can isolate. A GitHub-hosted Linux
    # runner ships `bwrap` and cannot create a user namespace, so those suites
    # cannot pass there and their failure says nothing about OpenRayNux.
    #
    # So the host's capability is asked first, via the same probe the dispatcher
    # uses, and the scope follows the answer:
    #
    #   * can isolate  -> everything runs, unchanged;
    #   * cannot       -> the sandbox-evidence binaries are excluded, each with a
    #                     stated reason, and the reason is printed.
    #
    # This is not a silent skip. The exclusion is narrower than "the sandbox
    # tests": the refusal-path tests inside those same binaries DO run, because
    # they assert the property that is true on an incapable host. And the positive
    # evidence is not dropped -- `scripts/run-sandbox-tests.sh` runs exactly these
    # suites in a container verified to reproduce the production configuration, and
    # CI runs it on every push. See ADR-0046, V-85, V-86.
    # `ORXNUD_TIER1_ASSUMED` is an escape hatch for a caller that has already measured the
    # host and knows the suites apply -- `scripts/run-sandbox-tests.sh` uses it inside the
    # container, where the point is to run them unconditionally.
    local filter=()
    if [ -z "${ORXNUD_TIER1_ASSUMED:-}" ] && ! scripts/preflight.sh --check >/dev/null 2>&1; then
      # The sentinel a Tier-1 suite fails with when it cannot run here. Checked below, so
      # a suite added to this repository later and forgotten in this list fails the gate
      # with a pointed message instead of being silently skipped. A hand-maintained
      # exclusion rots; this makes it complain when it does.
      local refusal="cannot establish the required sandbox guarantees"

      # Binaries whose whole subject is Tier-1 sandboxed execution.
      #
      # `test(...)` matches a substring of the test's own name, which for a `#[cfg(test)]`
      # module inside a crate does not include the module path -- hence plain names here.
      #
      # The `linux::tests::` module is excluded whole rather than name by name: it is the
      # Linux backend's own suite, it is unobservable on a host with no sandbox, and
      # naming five of its tests would be a list with five more places to rot. The one
      # sandbox-dependent test in `platform::tests` is named individually, because the rest
      # of that module is the refusing-backend evidence and must keep running.
      #
      # The `orxnud-daemon` tests are named individually because their modules also hold
      # proposal, approval, bound and disclosure evidence that holds on any host.
      #
      # The `continuation` ones are named for a sharper reason than the rest: reaching a
      # step boundary requires a *verified* effect, and the only capability in this build
      # that verifies is Tier-1 and sandboxed -- `text/word-count` deliberately returns
      # `Undetermined` rather than `Verified`, because counting words has no effect to
      # observe. So there is no host-independent way to put a task at a boundary, and the
      # continuation evidence is sandbox evidence. Six of that file's nine tests are named
      # here for that reason; the three that do not execute a capability are NOT excluded
      # and run everywhere.
      filter=(
        -E 'not (binary(governed_path) or binary(read_text_real) or binary(write_text) or binary(isolation) or binary(enforcement) or binary(resources) or binary(hostile_helper) or binary(disclosure)
              or test(linux::tests::)
              or test(the_host_backend_is_selected_at_compile_time_and_reports_honestly)
              or test(a_proposed_action_is_approved_executed_verified_and_completes_its_task)
              or test(a_proposal_and_its_waiting_task_survive_a_restart_unchanged)
              or test(an_approval_cannot_be_executed_twice)
              or test(an_approval_for_one_proposal_does_not_execute_another)
              or test(an_ai_proposal_becomes_a_governed_action)
              or test(a_multi_step_task_advances_across_a_verified_step_boundary)
              or test(a_single_step_task_completes_and_cannot_be_continued)
              or test(a_boundary_is_claimed_by_exactly_one_worker)
              or test(a_provider_failure_returns_the_task_to_its_boundary_and_is_retryable)
              or test(a_model_can_say_no_further_work_is_needed)
              or test(continuation_without_a_provider_is_refused_before_the_boundary_is_crossed)
              or test(an_approval_that_expires_while_waiting_is_recoverable)
              or test(a_live_approval_is_not_replaceable_and_a_used_one_certainly_is_not)
              or test(an_expired_approval_cannot_be_replayed_after_a_fresh_one_exists)
              or test(a_crash_does_not_resurrect_an_expired_approval)
              or test(a_crash_after_expiry_and_before_reapproval_still_recovers))'
      )
      note "host cannot isolate: excluding the Tier-1 sandbox-evidence tests."
      note "  governed_path, read_text_real, write_text, isolation, enforcement,"
      note "  resources, hostile_helper  -- binaries whose subject is a real sandbox."
      note "  linux::tests::              -- the Linux backend's own suite."
      note "  6 named tests               -- sandbox-evidence tests inside tasks.rs."
      note "  6 named tests               -- continuation.rs, which cannot reach a step"
      note "                                 boundary without a verified sandboxed effect."
      note "  5 named tests               -- expiry.rs, which cannot prove a fresh"
      note "                                 approval works without a verified execution."
      note "  Everything else runs, including every refusal-path assertion."
      note "  Positive evidence: scripts/run-sandbox-tests.sh (CI job sandbox-integration)."

      local out rc=0
      # shellcheck disable=SC2086 # the filter is intentionally several words
      out="$(cargo nextest run --workspace --no-fail-fast "${filter[@]}" 2>&1)" || rc=$?
      echo "$out"
      if printf '%s' "$out" | grep -q "$refusal"; then
        fail_gate "a suite outside the exclusion list needs a real sandbox: it failed with \"$refusal\" on a host that cannot isolate, so it was never excluded. Add its binary to the G9 filter above, or run it in scripts/run-sandbox-tests.sh"
        return
      fi
      if [ "$rc" -ne 0 ]; then
        fail_gate "tests failed"
        return
      fi
      ok "cargo nextest run (all host-applicable tests)"
      return
    fi
    if cargo nextest run --workspace; then
      ok "cargo nextest run (all tests)"
    else
      fail_gate "tests failed"
    fi
    return
  fi
  if is_strict; then
    fail_gate "cargo-nextest is not installed"
    return
  fi
  note_skip "cargo-nextest not installed; using cargo test (process isolation is lost)"
  if cargo test --workspace; then
    ok "cargo test --workspace"
  else
    fail_gate "tests failed"
  fi
}

# G10 — no committed credential.
#
# The patterns are deliberately narrow. A greedy search for "password" would match
# this file and every document discussing the rule. What is looked for is the
# *shape* of an actual credential.
gate_G10() {
  banner G10
  local ok_all=1 hits

  hits="$(git grep -InE '-----BEGIN (RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----' -- . 2>/dev/null || true)"
  if [ -z "$hits" ]; then
    ok "no PEM private key"
  else
    printf '%s\n' "$hits" | sed 's/^/     /'
    fail_gate "a PEM private key is committed"
    ok_all=0
  fi

  hits="$(git grep -InE '(sk-[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{30,})' -- . 2>/dev/null || true)"
  if [ -z "$hits" ]; then
    ok "no provider token patterns"
  else
    printf '%s\n' "$hits" | sed 's/^/     /'
    fail_gate "what looks like a provider token is committed"
    ok_all=0
  fi

  hits="$(git ls-files 2>/dev/null | grep -E '(^|/)\.env($|\.)' | grep -vE '\.env\.(example|sample|template|dist)$' || true)"
  if [ -z "$hits" ]; then
    ok "no committed .env file"
  else
    printf '%s\n' "$hits" | sed 's/^/     /'
    fail_gate "a .env file is committed"
    ok_all=0
  fi

  [ "$ok_all" -eq 1 ] && ok "no committed credential"
}

gate_G11() {
  banner G11
  if have cargo-audit; then
    if cargo audit; then
      ok "cargo audit: no known advisory"
    else
      fail_gate "cargo audit reported an advisory"
    fi
    return
  fi
  if is_strict; then
    fail_gate "cargo-audit is not installed"
  else
    note_skip "cargo-audit not installed"
  fi
}

gate_G12() {
  banner G12
  if have cargo-semver-checks; then
    # The baseline is the release tag. Phase 1 has no tag yet, so this gate skips
    # rather than comparing HEAD to itself, which would always pass and be worse
    # than useless.
    local baseline
    baseline="$(git describe --tags --abbrev=0 2>/dev/null || true)"
    if [ -z "$baseline" ]; then
      note_skip "no release tag to compare against (create one to activate this gate)"
      return
    fi
    if cargo semver-checks check-release --baseline-rev "$baseline"; then
      ok "no breaking change against $baseline"
    else
      fail_gate "cargo semver-checks found a breaking change against $baseline"
    fi
    return
  fi
  if is_strict; then
    fail_gate "cargo-semver-checks is not installed"
  else
    note_skip "cargo-semver-checks not installed"
  fi
}

# G13 -- the boundary gates, self-tested.
#
# An enforcement gate that is never exercised against a known violation is a gate whose
# strength is unknown. This runs `scripts/gate-selftest.py`, which builds temporary
# fixture trees and drives *these* gate functions over them via ORXNUD_GATE_ROOT. It
# tests the real gates, not a copy of their logic -- a copy is a second implementation
# that can agree with the first while both are wrong.
gate_G13() {
  banner G13
  if python3 scripts/gate-selftest.py; then
    ok "G2d and G3 self-tests pass (real gate logic, temporary fixtures)"
  else
    fail_gate "a boundary-gate self-test failed: the gate does not do what it claims"
  fi
}

ALL_GATES=(G1 G2 G2d G3 G4 G5 G6 G7 G8 G9 G10 G11 G12 G13)

run() {
  case "$1" in
G1) gate_G1 ;;  G2) gate_G2 ;;  G2d) gate_G2d ;;  G3) gate_G3 ;;  G4) gate_G4 ;;
    G5) gate_G5 ;;  G6) gate_G6 ;;  G7) gate_G7 ;;  G8) gate_G8 ;;  G9) gate_G9 ;;
    G10) gate_G10 ;;  G11) gate_G11 ;;  G12) gate_G12 ;;  G13) gate_G13 ;;
    *) printf 'unknown gate: %s (expected G1..G13)\n' "$1" >&2; exit 2 ;;
  esac
}

main() {
  local gates=("$@")
  [ ${#gates[@]} -eq 0 ] && gates=("${ALL_GATES[@]}")

  printf '\033[1mOpenRayNux Phase 1 gates\033[0m\n'
  printf 'rustc   %s\n' "$(rustc --version)"
  printf 'repo    %s\n' "$REPO_ROOT"
  is_strict && printf 'strict  yes: a missing tool fails\n'

  local gate
  for gate in "${gates[@]}"; do
    run "$gate"
  done

  printf '\n\033[1m== summary\033[0m\n'
  if [ ${#FAILED[@]} -gt 0 ]; then
    printf '   \033[31m%d failed\033[0m: %s\n' "${#FAILED[@]}" "${FAILED[*]}"
  else
    printf '   \033[32mall selected gates passed\033[0m\n'
  fi
  if [ ${#SKIPPED[@]} -gt 0 ]; then
    printf '   \033[33m%d skipped\033[0m: %s\n' "${#SKIPPED[@]}" "${SKIPPED[*]}"
  fi

  [ ${#FAILED[@]} -eq 0 ]
}

# Sourcing this file defines the gate functions and runs nothing, so the strict-mode
# decision can be tested by `source scripts/ci-gates.sh` rather than by copying it.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
