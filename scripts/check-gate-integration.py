#!/usr/bin/env python3
"""Check that the CI gates use the shared diagnostic helper, and only it.

# Why this exists

The G9 refusal diagnostic was written as

    printf '%s' "$out" | grep -q "$refusal"

and it never fired, despite the refusal string being present in the output it
was searching. `grep -q` exits at its first match, which closes the pipe; the
producer then takes SIGPIPE and dies with 141; and because the gates run under
`set -o pipefail`, the PIPELINE's status is that 141 rather than grep's 0. The
`if` was therefore false on a match and true on a miss -- the exact inverse of
what it was written to do.

The size of the output decided it. `grep` finds the match early, before the
producer has finished writing, so the producer is still alive to be killed. A
short output is written whole before grep ever reads it, so no SIGPIPE occurs
and the pipeline happens to work. A search that works on small inputs and
silently fails on large ones is worse than no search at all, because the failure
looks like the answer.

`scripts/gate_lib.sh` holds the one implementation, and the gates use it. This
check is what stops a future edit from quietly going back to the pipeline.

# What it checks

1. `scripts/gate_lib.sh` is sourced by the gate script.
2. Every gate-side substring search goes through the shared helper -- the
   literal form (`gate_contains`) or the regular-expression form
   (`gate_matches`) -- and NOT through a pipeline into `grep`.
3. The gate script contains no `printf ... | grep -q` pipeline at all.

Only the standard library is used.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# The gate script and the helper it sources, relative to a repository root.
GATE_SCRIPT = Path("scripts/ci-gates.sh")
GATE_LIB = Path("scripts/gate_lib.sh")

# A `printf` whose output is piped into a `grep -q`. This is the shape that
# cannot distinguish a match from a SIGPIPE-killed producer.
_PIPELINE_SEARCH = re.compile(r"printf\b[^\n|]*\|\s*grep\b[^\n]*-q")


def strip_comments(text: str) -> str:
    """Remove shell comments, keeping the line structure intact.

    The gate script *explains* the pipeline it no longer uses, and that
    explanation contains the pipeline's own text. A check that cannot tell prose
    from code would flag the very comment that documents the fix, so the
    comments are removed before anything is scanned. The reasoning is the same as
    `scripts/gate_policy.py`'s: a regular expression cannot tell code from a
    comment, so the classification is done before the pattern is applied.

    Only the whole of a line after a `#` is removed. A `#` inside a word --
    `local pattern="$1"` has none, but `"$#"` counts the arguments -- is not
    treated as a comment, because treating it as one would silently delete code.
    """
    lines = []
    for line in text.split("\n"):
        # A `#` that is not inside a quoted string starts a comment.
        in_single = False
        in_double = False
        cut = len(line)
        for index, char in enumerate(line):
            if char == "'" and not in_double:
                in_single = not in_single
            elif char == '"' and not in_single:
                in_double = not in_double
            elif char == "#" and not in_single and not in_double:
                if index == 0 or line[index - 1] in " \t":
                    cut = index
                    break
        lines.append(line[:cut])
    return "\n".join(lines)


# A call to one of the shared helpers. `-F`/`-E` live in the helper; the call
# site only names it.
_HELPER_CALL = re.compile(r"\bgate_(contains|matches)\b")

# The helper's own definition, so the check does not count the library file
# itself when it is scanned.
_HELPER_DEFINITION = re.compile(r"^\s*gate_(contains|matches)\s*\(\)\s*\{", re.MULTILINE)


class IntegrationError(Exception):
    """The gate script is not wired to the shared diagnostic helper."""


def read(path: Path) -> str:
    """Read a file, failing closed when it cannot be read."""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise IntegrationError(f"{path}: cannot be read: {error}") from error


def check(root: Path) -> None:
    """Check the gate script under `root`, raising on the first problem."""
    gate_path = root / GATE_SCRIPT
    lib_path = root / GATE_LIB
    if not gate_path.is_file():
        raise IntegrationError(f"{gate_path}: does not exist")
    if not lib_path.is_file():
        raise IntegrationError(f"{lib_path}: does not exist")

    gate = read(gate_path)
    lib = read(lib_path)

    # The comments are stripped before anything is scanned, so that the
    # explanation of the pipeline cannot be mistaken for the pipeline.
    gate_code = strip_comments(gate)

    # 1. The helper must exist and define both forms.
    for name in ("gate_contains", "gate_matches"):
        if not re.search(rf"^\s*{name}\s*\(\)\s*\{{", lib, re.MULTILINE):
            raise IntegrationError(f"{lib_path}: does not define {name}")

    # 2. The gate script must source it. The source line has to be a real
    #    statement, not a mention in a comment -- the comments are stripped
    #    before this runs, so a comment cannot satisfy it.
    if not re.search(
        r"^\s*source\s+\"?\$\{?REPO_ROOT\}?/scripts/gate_lib\.sh",
        gate_code,
        re.MULTILINE,
    ):
        raise IntegrationError(
            f"{gate_path}: does not source {GATE_LIB}; the shared helper would not be "
            "the implementation the gates use"
        )

    # 3. No pipeline into `grep -q` may remain in the gate script. This is the
    #    shape that cannot tell a match from a SIGPIPE-killed producer.
    found = _PIPELINE_SEARCH.search(gate_code)
    if found is not None:
        line = gate_code[: found.start()].count("\n") + 1
        raise IntegrationError(
            f"{gate_path}:{line}: a `printf ... | grep -q` pipeline is back. "
            "`grep -q` exits at its first match, the producer takes SIGPIPE, and "
            "under `set -o pipefail` the pipeline reports 141 instead of grep's 0 -- "
            "so the `if` is false on a match. Use `gate_contains` or `gate_matches` "
            "from scripts/gate_lib.sh instead"
        )

    # 4. The helper must actually be used, or the pipeline check above would
    #    pass on a script that had simply deleted the searches.
    calls = [
        match
        for match in _HELPER_CALL.finditer(gate_code)
        if not _HELPER_DEFINITION.match(gate_code, match.start())
    ]
    if not calls:
        raise IntegrationError(
            f"{gate_path}: uses neither `gate_contains` nor `gate_matches`; the "
            "diagnostic searches must go through the shared helper"
        )


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: check-gate-integration.py <repository-root>", file=sys.stderr)
        return 2
    root = Path(argv[0])
    try:
        check(root)
    except IntegrationError as error:
        print(f"gate integration error: {error}", file=sys.stderr)
        return 1
    print("gate integration: the gates use the shared diagnostic helper")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
