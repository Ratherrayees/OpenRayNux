#!/usr/bin/env bash
#
# Shared helpers for the CI gates.
#
# Sourced by `scripts/ci-gates.sh`, and exercised directly by
# `scripts/gate-selftest.py`. Both must use the SAME implementation: a self-test
# of a copy proves only that the copy agrees with itself, so a copy that
# disagreed with the gate would leave the gate untested.
#
# # Why this file exists
#
# The G9 refusal diagnostic was written as
#
#     printf '%s' "$out" | grep -q "$refusal"
#
# and it never fired, despite the refusal string being present in the output it
# was searching. `grep -q` exits at its first match, which closes the pipe; the
# producer then takes SIGPIPE and dies with 141; and because the script runs
# under `set -o pipefail`, the PIPELINE's status is that 141 rather than grep's
# 0. The `if` was therefore false on a match and true on a miss -- the exact
# inverse of what it was written to do.
#
# The size of the output decides it. `grep` finds the match early, before the
# producer has finished writing, so the producer is still alive to be killed.
# A short output is written whole before grep ever reads it, so no SIGPIPE
# occurs and the pipeline happens to work. Measured against the real G9 output
# -- 486 KB, with the refusal near the beginning -- the pipeline form does not
# fire; against a 5 MB fixture with the refusal in the first 10%, it does not
# fire either. A search that works on small inputs and silently fails on large
# ones is worse than no search at all, because the failure looks like the answer.
#
# A here-string has no pipeline: bash writes the text to a temporary file or
# pipe and `grep` reads it to completion, so there is no producer left to kill
# and no status for `pipefail` to mangle.

# gate_contains <pattern> <text>
#
# Whether <text> contains <pattern>, read as a BRE (grep's default) rather than
# as a regular expression, so a pattern that happens to contain a metacharacter
# matches literally instead of meaning something else.
#
# The `--` stops a pattern beginning with `-` from being read as an option.
gate_contains() {
    local pattern="$1" text="$2"
    grep -q -F -- "$pattern" <<<"$text"
}

# gate_matches <regex> <text>
#
# Whether <text> matches <regex>, as a regular expression.
#
# The same here-string, for the same reason: a pipeline into `grep -q` cannot
# distinguish a match from a SIGPIPE-killed producer, and under `set -o
# pipefail` it reports the producer's status. Two of the gates need a regular
# expression rather than a literal, and they must not have to go back to the
# pipeline to get one.
gate_matches() {
    local regex="$1" text="$2"
    grep -q -E -- "$regex" <<<"$text"
}

# gate_contains_line <word> <text>
#
# Whether <text> contains <word> as a WHOLE line.
#
# The crate-layering check needs this: it asks "is this dependency name one of
# the permitted ones", and `grep -x` is what answers that. A substring match
# would accept `orxnud-domain` for the dependency `orxnud-domain-extra`, which
# is a different crate.
gate_contains_line() {
    local word="$1" text="$2"
    grep -q -x -F -- "$word" <<<"$text"
}
