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
)

banner() { printf '\n\033[1m== %s: %s\033[0m\n' "$1" "${NAMES[$1]}"; }
ok()      { printf '   \033[32mok\033[0m    %s\n' "$1"; }
bad()     { printf '   \033[31mFAIL\033[0m  %s\n' "$1"; }
note_skip() { printf '   \033[33mskip\033[0m  %s\n' "$1"; SKIPPED+=("$gate"); }
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

# Prints a Rust source file with its `#[cfg(test)]` modules removed.
#
# Needed because a *test* may legitimately reach for a policy-only symbol (to build
# a fixture), while a *production* path may not. G2's seal check reads the output
# of this, so the gate distinguishes "reachable at runtime" from "reachable from a
# test".
#
# The module's closing brace is the first line starting with `}` at column 0; inner
# braces are indented, which is the rustfmt convention every file here follows.
strip_cfg_test() {
  awk '
    /#\[cfg\(test\)\]/                        { in_test = 1 }
    in_test          { if ($0 ~ /^\}/) in_test = 0; next }
    { print }
  ' "$1"
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
  # Transport and wire vocabulary only. Everything that could carry a domain rule --
  # domain, store, task engine, policy, capability, daemon -- is absent on purpose,
  # because the whole point of the check is that the CLI cannot reimplement a rule it
  # cannot see (docs-03 §2, IR-2).
  local CLI_ALLOWED_INTERNAL="orxnud-platform-ipc orxnud-protocol"

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
  # --- (d) the policy seal is reachable only from orxnud-policy ---
  #
  # ADR-0013 makes `AuthorisationProof` unconstructible except through
  # `PolicySeal::attest`, which only `orxnud-policy` can name. That is the whole
  # capability boundary: a capability crate cannot *become* authorised, it can only
  # ask. A type-level property is only as good as the check that enforces it, and
  # nothing was checking that -- a manifest gate cannot see symbols.
  #
  # So this greps the sealed symbols out of every production source file, after
  # removing `#[cfg(test)]` modules. Two crates are exempt by design:
  #   * orxnud-domain, which *defines* them (and orxnud-capability, which depends
  #     on it, is the trap: naming a seal in production code is the violation);
  #   * orxnud-policy, which is the only authoriser by definition.
  # `tests/` is not scanned at all: `compile_fail/` must name them to prove the
  # seal holds.
  local sealed='AuthorisationProof|PolicySeal|\.authorise\('
  local offenders f
  offenders=""
  for f in $(find crates -type f -name '*.rs' -path '*/src/*' | sort); do
    local crate
    crate="$(printf '%s' "$f" | cut -d/ -f2)"
    case "$crate" in
      orxnud-domain|orxnud-policy) continue ;;
    esac
    local hits
    hits="$(strip_cfg_test "$f" | grep -nE "$sealed" || true)"
    if [ -n "$hits" ]; then
      offenders="$offenders$f: $hits\n"
      printf '     %s\n' "$(printf '%s' "$hits" | head -3 | sed 's/^/  /')"
      printf '     ^ in %s\n' "$f"
    fi
  done
  if [ -n "$offenders" ]; then
    fail_gate "a policy-seal symbol is reachable outside orxnud-policy in production code"
    ok_all=0
  else
    ok "the policy seal is reachable only from orxnud-policy (production code)"
  fi

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

  [ "$ok_all" -eq 1 ] && ok "all internal dependency edges point inward"
}

# G3 — no platform branch outside orxnud-platform-*.
#
# The boundary is only real if it is checked. A `cfg(target_os)` in the core means
# the core has an opinion about the OS, which is what the trait boundary exists to
# prevent.
gate_G3() {
  banner G3
  local pattern='cfg[_a-z!]*\s*\(\s*(target_os|target_family|target_env|windows|unix|target_pointer_width)|env::consts::OS'
  local hits
  # Comment lines are excluded. `orxnud-domain/src/platform.rs` *documents* this
  # rule and must name `cfg(target_os)` to do so; matching prose would force the
  # documentation to become vague, which is the wrong trade for a lint.
  hits="$(grep -RInE "$pattern" crates --include='*.rs' \
    | grep -vE '^crates/orxnud-platform-[a-z]+/' \
    | grep -vE ':[0-9]+:[[:space:]]*(//|///|//!|\*|/\*)' || true)"
  if [ -z "$hits" ]; then
    ok "no cfg(target_os)/cfg(windows)/env::consts::OS outside orxnud-platform-*"
  else
    printf '%s\n' "$hits" | sed 's/^/     /'
    fail_gate "a platform branch exists outside orxnud-platform-*"
  fi
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

ALL_GATES=(G1 G2 G3 G4 G5 G6 G7 G8 G9 G10 G11 G12)

run() {
  case "$1" in
    G1) gate_G1 ;;  G2) gate_G2 ;;  G3) gate_G3 ;;  G4) gate_G4 ;;  G5) gate_G5 ;;
    G6) gate_G6 ;;  G7) gate_G7 ;;  G8) gate_G8 ;;  G9) gate_G9 ;; G10) gate_G10 ;;
    G11) gate_G11 ;; G12) gate_G12 ;;
    *) printf 'unknown gate: %s (expected G1..G12)\n' "$1" >&2; exit 2 ;;
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
