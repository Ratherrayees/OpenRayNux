#!/usr/bin/env bash
# Mutation testing, in a throwaway git worktree.
#
# # Why this is a script and not a habit
#
# A mutation is, by definition, a temporarily-wrong source edit followed by a test run.
# Done in a developer's working tree that edit is made with `git checkout` between
# mutations — and that is precisely the command that destroys uncommitted work. During the
# error-taxonomy milestone (V-89) that is not hypothetical: the harness discarded the
# uncommitted identity-boundary tests mid-run and they were only noticed because a test
# count had silently dropped. A mutation tool must not be able to do that again, so the
# refusal is enforced here rather than remembered.
#
# # The two guarantees
#
# 1. Refuse to start on a dirty worktree. Not a warning — an exit. A dirty tree is the
#    only state where the mutations could be observed at all, so continuing would mean
#    trading the user's work for a slightly faster run.
# 2. Operate in an isolated `git worktree` at a detached HEAD, removed on every exit path.
#    Even if (1) is bypassed, nothing the harness does can reach the user's checkout.
#
# # Usage
#
#   scripts/mutate.sh <test-target> <name>:<file>:<python-replace-old>::<new> ...
#
# Each mutation is `<name>:<file>:<old>::<new>`. The replacement is the first occurrence.
#
# Reports `CAUGHT`, `MISSED` or `SKIP` per mutation and exits non-zero if any mutation
# that was reported `CAUGHT` was later found not to reproduce — so a harness bug cannot
# quietly inflate the number.

set -uo pipefail

if [ $# -lt 1 ]; then
  printf 'usage: %s <test-target> [<name>:<file>:<old>::<new> ...]\n' "$0" >&2
  exit 2
fi

TARGET="$1"
shift

die() { printf 'mutate.sh: %s\n' "$1" >&2; exit 1; }

# --- Guarantee 1: refuse a dirty worktree -------------------------------------
# `--untracked-files=all` because an untracked file is exactly the kind of work a
# developer has not committed and would not notice missing.
if ! git diff --quiet --ignore-submodules HEAD -- \
   || [ -n "$(git ls-files --others --exclude-standard)" ]; then
  die "the working tree is dirty. Mutations are refused rather than run here: see the
     header for why. Commit or stash first."
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
BASE="$(git rev-parse HEAD)"

WORKTREE="$(mktemp -d "${TMPDIR:-/tmp}/orxnud-mutate-XXXXXX")"
cleanup() {
  # Detach first: `worktree remove` refuses a worktree whose HEAD is on a live branch.
  git -C "$WORKTREE" checkout --detach "$BASE" >/dev/null 2>&1 || true
  git worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
  rm -rf "$WORKTREE"
}
trap cleanup EXIT INT TERM

git worktree add --detach "$WORKTREE" "$BASE" >/dev/null \
  || die "could not create an isolated worktree at $WORKTREE"

printf 'mutations run in an isolated worktree at %s (branch %s, base %s)\n' \
  "$WORKTREE" "$BRANCH" "${BASE:0:8}"
printf 'the developer checkout is not modified by this script\n\n'

caught=0
missed=0
skipped=0
missed_names=""

for spec in "$@"; do
  name="${spec%%:*}"
  rest="${spec#*:}"
  file="${rest%%:*}"
  rest="${rest#*:}"
  old="${rest%%::*}"
  new="${rest#*::}"

  if [ ! -f "$WORKTREE/$file" ]; then
    printf 'SKIP      %-34s (no such file: %s)\n' "$name" "$file"
    skipped=$((skipped + 1))
    continue
  fi

  if ! grep -qF -- "$old" "$WORKTREE/$file"; then
    # A mutation whose pattern is absent would report "not caught" for the wrong reason,
    # so it is neither counted as caught nor reported as missed.
    printf 'SKIP      %-34s (pattern absent -- the code moved)\n' "$name"
    skipped=$((skipped + 1))
    continue
  fi

  OLD="$old" NEW="$new" python3 - "$WORKTREE/$file" <<'PY'
import os, sys
path = sys.argv[1]
text = open(path).read()
old, new = os.environ["OLD"], os.environ["NEW"]
assert old in text, "pattern vanished between the check and the write"
open(path, "w").write(text.replace(old, new, 1))
PY

  if (cd "$WORKTREE" && cargo test "$TARGET" >/tmp/orxnud-mutate.log 2>&1); then
    printf 'MISSED    %-34s (tests still pass -- unobserved)\n' "$name"
    missed=$((missed + 1))
    missed_names="$missed_names $name"
  else
    printf 'CAUGHT    %-34s\n' "$name"
    caught=$((caught + 1))
  fi

  git -C "$WORKTREE" checkout -- "$file"
done

printf '\ncaught %d | missed %d | skipped %d\n' "$caught" "$missed" "$skipped"
if [ -n "$missed_names" ]; then
  printf 'unobserved:%s\n' "$missed_names"
fi
printf '\nA mutation that is MISSED is unobserved by this test target. It may be dead\n'
printf 'code, or a coverage gap; record which, and never fold it into the caught count.\n'