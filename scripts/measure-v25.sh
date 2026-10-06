#!/usr/bin/env bash
# V-25: measure the core daemon's resource budgets.
#
# # Why a script and not a habit
#
# V-89's lesson, applied here: the earlier mutation harness ran in the developer's
# working tree and its `git checkout` between mutations destroyed uncommitted work.
# A measurement harness has the same exposure and one extra hazard -- if it leaves a
# daemon running, every later measurement of this host is wrong and nothing says so.
# So the guarantees are enforced below rather than remembered:
#
#   * it refuses to run on a dirty worktree
#   * it never edits tracked source
#   * every daemon it starts is killed on exit, including on failure or Ctrl-C
#   * it records the commit and toolchain with the numbers
#   * it exits non-zero on a failed measurement, and prints the failure rather than
#     letting a partial table look like a result
#
# # Usage
#
#   scripts/measure-v25.sh              # measure with the shipping release profile
#   scripts/measure-v25.sh --debug      # smoke-test the harness on an unoptimised build
#
# The release profile is the default and is the only one whose numbers mean anything:
# docs-05's budgets are about what ships.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE=release
[[ "${1:-}" == "--debug" ]] && PROFILE=debug

die() { printf 'measure-v25: %s\n' "$1" >&2; exit 1; }

# --- harness integrity: refuse a dirty tree --------------------------------
# Same rule `scripts/mutate.sh` uses, and for the same reason: a measurement taken
# against unknown source is not evidence about anything.
if ! git diff --quiet --ignore-submodules HEAD -- \
   || [ -n "$(git ls-files --others --exclude-standard)" ]; then
  die "the working tree is dirty. Commit or stash first: this harness records the commit \
     it measured, and a dirty tree would make that record false."
fi

# --- provenance ------------------------------------------------------------
SHA="$(git rev-parse HEAD)"
RUSTC="$(rustc --version)"
CARGO="$(cargo --version)"
HOST="$(uname -srm)"
KERNEL="$(uname -r)"
CPU="$(awk -F: '/model name/{gsub(/^ +/,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)"
CORES="$(nproc 2>/dev/null || echo '?')"
MEM="$(awk '/MemTotal/{printf "%.1f GiB", $2/1048576}' /proc/meminfo 2>/dev/null || echo unknown)"
FS="$(df -PT . | awk 'NR==2{print $2" on "$1}' 2>/dev/null || echo unknown)"
SQLITE="$(grep -oP 'libsqlite3-sys"\s*version\s*=\s*"\K[0-9.]+' Cargo.lock 2>/dev/null | head -1 || echo '?')"

echo "=============================================================="
echo " V-25 resource baseline"
echo "=============================================================="
echo " commit   : $SHA"
echo " profile  : $PROFILE"
echo " rustc    : $RUSTC"
echo " cargo    : $CARGO"
echo " host     : $HOST (kernel $KERNEL)"
echo " cpu      : $CPU ($CORES logical cores)"
echo " memory   : $MEM"
echo " storage  : $FS"
echo " sqlite   : libsqlite3-sys $SQLITE (bundled, never the host library)"
echo "=============================================================="
echo

# --- build, then measure --------------------------------------------------
echo "-- building ($PROFILE) --"
V25_RUSTC="$RUSTC" cargo build --profile "$PROFILE" --workspace --tests \
  || die "the build failed; there is nothing to measure"

BIN="$(find "target/$PROFILE" -maxdepth 1 -name orxnud -type f | head -1)"
[[ -n "$BIN" ]] || die "no orxnud binary in target/$PROFILE"
echo " core binary: $BIN ($(stat -c%s "$BIN") bytes, $(du -h "$BIN" | cut -f1) on disk)"
echo

echo "-- measuring --"
# `--test-threads=1`: several of these measurements start a daemon and measure its
# readiness, and two at once would have them contend for CPU and report each other as
# slow. The IPC and task-engine sections use N in the thousands instead, which is how
# variance is controlled there.
V25_RUSTC="$RUSTC" cargo test --profile "$PROFILE" -p orxnud-daemon --test v25_measure \
  -- --nocapture --test-threads=1
STATUS=$?

# --- cleanup, always ------------------------------------------------------
# Nothing here starts a background process -- the harness spawns daemons itself and
# reaps them -- but a failed run may have left a socket behind, and a stale socket is
# the next run's first confusing failure.
rm -rf "target/tmp/v25-"* 2>/dev/null || true

echo
if [[ $STATUS -ne 0 ]]; then
  # Explicit, because a partial table printed above looks exactly like a result.
  die "the measurement run FAILED (exit $STATUS). Any numbers above are incomplete and \
       must not be recorded."
fi

echo "=============================================================="
echo " baseline complete -- record this alongside commit $SHA"
echo " re-run with scripts/measure-v25.sh; compare p50, not min."
echo "=============================================================="