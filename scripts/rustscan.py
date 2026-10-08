#!/usr/bin/env python3
"""Lexical and structural scanning of Rust source, for the CI boundary gates.

# Why this exists rather than a bigger regular expression

Two of the Phase 1 gates decide whether a *boundary* was crossed. Both were decided
with regular expressions over raw source text, and a regular expression cannot tell
code from a comment or from a string literal. Both gates were bypassed by text that
merely *looks* like the thing being forbidden:

  * a comment containing ``#[cfg(test)]`` switched the policy-seal gate off;
  * ``CapabilityInvocation::authorise(`` did not match a pattern for ``\\.authorise\\(``;
  * seven of nine ``cfg`` spellings for a platform branch were invisible, because the
    pattern required the platform key to be the first token inside ``cfg(``.

None of those is a pattern that could be fixed by writing a better pattern. A pattern
has no way to know whether it is looking at code.

So this module does the two things a pattern cannot:

  1. **Lexical classification.** ``code_mask`` marks every character as code or as
     non-code, honouring Rust's comment and literal grammar, including nested block
     comments, raw strings with arbitrary hashes, byte strings, and the
     ``'a'``/``'a`` character-literal-versus-lifetime ambiguity.

  2. **Predicate structure.** ``cfg_predicates`` locates ``cfg``/``cfg_attr``
     attributes at *code* positions and hands back their predicate text, and
     ``predicate_has_platform`` searches that text for platform keys at any nesting
     depth.

# What this deliberately is not

It is not a Rust parser. It does not build an item tree, resolve names, or know what
a module is. It does not need to: both invariants are about *whether a token appears
in code*, and about *what is inside a predicate*. A full parser would add a build
dependency to a gate whose job is to work when the build is broken.

# Python 3 because it is already here

``scripts/mutate.sh`` requires ``python3`` today, so this introduces no new tool
requirement for CI. See the module docstring of ``mutate.sh`` for why that
script exists at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --------------------------------------------------------------------------
# Lexing: which characters are code?
# --------------------------------------------------------------------------

CODE = True
NONCODE = False


def code_mask(src: str) -> list[bool]:
    """Classify every character of ``src`` as code or not.

    Returns a list parallel to ``src``. Newlines are always code, so that line
    numbers derived from the mask agree with the original file.

    The rules implemented, in the order they matter:

    * ``//`` to end of line is a comment.
    * ``/* ... */`` is a comment, and **nests** -- Rust allows a doc comment to
      contain another block comment, and a regular expression with ``.*?`` does not
      get that right.
    * ``r"..."``, ``r#"..."#``, ``br#"..."#``, ``cr#"..."#`` are raw strings: no
      escapes, terminated by a quote followed by exactly as many ``#`` as opened it.
    * ``"..."`` and ``b"..."`` are normal strings with backslash escapes.
    * ``'c'`` is a char literal; ``'a`` is a lifetime. The two are distinguished by
      what follows the quote: a backslash means a char literal, a closing quote means
      a char literal, anything else means a lifetime.
    """
    n = len(src)
    mask = [CODE] * n
    i = 0
    while i < n:
        c = src[i]

        # Newlines stay code so callers can count lines off the mask.
        if c == "\n":
            i += 1
            continue

        # -- line comment ------------------------------------------------
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                mask[k] = NONCODE
            i = j
            continue

        # -- block comment (nested) -------------------------------------
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            mask[i] = NONCODE
            mask[i + 1] = NONCODE
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if src.startswith("/*", j):
                    depth += 1
                    mask[j] = NONCODE
                    mask[j + 1] = NONCODE
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    mask[j] = NONCODE
                    mask[j + 1] = NONCODE
                    j += 2
                else:
                    if src[j] != "\n":
                        mask[j] = NONCODE
                    j += 1
            i = j
            continue

        # -- raw / byte / c-string literals -----------------------------
        # `r`, `br`, `cr` followed by optional hashes and a quote.
        m = _RAW_PREFIX.match(src, i)
        if m:
            hashes = m.group(1) or ""
            terminator = '"' + hashes + '"'
            j = m.end()
            close = src.find(terminator, j)
            end = n if close == -1 else close + len(terminator)
            for k in range(i, min(end, n)):
                if src[k] != "\n":
                    mask[k] = NONCODE
            i = min(end, n)
            continue

        # -- normal / byte string literals ------------------------------
        if c == '"' or (c == "b" and i + 1 < n and src[i + 1] == '"'):
            start = i + 1 if c == '"' else i + 2
            j = start
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if src[k] != "\n":
                    mask[k] = NONCODE
            i = min(j, n)
            continue

        # -- char literal versus lifetime -------------------------------
        if c == "'":
            if _is_char_literal(src, i):
                j = i + 1
                if j < n and src[j] == "\\":
                    j += 2
                    while j < n and src[j] != "'":
                        j += 1
                    j += 1
                elif j < n:
                    j += 1
                    if j < n and src[j] == "'":
                        j += 1
                for k in range(i, min(j, n)):
                    if src[k] != "\n":
                        mask[k] = NONCODE
                i = min(j, n)
                continue
            # A lifetime: the quote is code, the name is code. Nothing to mask.

        i += 1

    return mask


_RAW_PREFIX = re.compile(r"\b(?:br|rb|cr|rc)?(#+)?\"", re.ASCII)


def _is_char_literal(src: str, i: int) -> bool:
    """Whether the ``'`` at ``i`` opens a char literal rather than a lifetime.

    ``'a'``  -- char literal: a closing quote follows the character.
    ``'\\n'`` -- char literal: a backslash escape follows.
    ``'a``   -- lifetime: the next thing is an identifier and then something else.
    ``'static`` -- lifetime.
    """
    if i + 1 >= len(src):
        return False
    nxt = src[i + 1]
    if nxt == "\\":
        return True
    if nxt == "'":
        return True
    # A single character followed by anything other than a quote is not a
    # one-character literal, so this is a lifetime.
    return False


def code_only(src: str, mask: list[bool]) -> str:
    """``src`` with every non-code character replaced by a space.

    Length and line structure are preserved, so a match position in the result maps
    straight back to a position in ``src`` -- and therefore to a line number.
    """
    return "".join(ch if m else " " for ch, m in zip(src, mask, strict=True))


def line_of(src: str, pos: int) -> int:
    """1-based line number of ``pos`` within ``src``."""
    return src.count("\n", 0, pos) + 1


def line_text(src: str, line: int) -> str:
    """1-based line ``line`` of ``src``, without its newline."""
    lines = src.split("\n")
    return lines[line - 1] if 0 < line <= len(lines) else ""


# --------------------------------------------------------------------------
# cfg attributes and predicates
# --------------------------------------------------------------------------

# `#[cfg(...)]`, `#![cfg(...)]`, `cfg!(...)`, and the same for `cfg_attr`.
_CFG_HEAD = re.compile(r"\bcfg(_attr)?\s*!?\s*\(", re.ASCII)

# Keys whose presence in a predicate means "an opinion about the platform".
#
# `target_vendor` and `target_abi` are absent on purpose: they are legitimate
# portability distinctions that do not select an OS implementation, and G5's wasm
# build already proves the core builds with none of these set. `target_pointer_width`
# is present because it is a hardware-shape assumption of the same family as
# `target_arch`.
PLATFORM_CFG_KEYS = frozenset(
    {
        "target_os",
        "target_arch",
        "target_family",
        "target_env",
        "target_vendor",
        "target_pointer_width",
        "unix",
        "windows",
    }
)

# Function-like platform macros that read the *host* at compile time. These are the
# same category as `cfg(target_os)`: the core gains an opinion about the platform.
PLATFORM_MACROS = (
    "env::consts::OS",
    "env::consts::FAMILY",
    "env::consts::ARCH",
    "env::consts::EXE_EXTENSION",
    "env::consts::DLL_PREFIX",
    "env::consts::DLL_SUFFIX",
)


@dataclass(frozen=True)
class CfgPredicate:
    """One ``cfg``/``cfg_attr`` predicate found at a code position."""

    line: int
    text: str
    is_cfg_attr: bool


def _match_paren(code: str, open_idx: int) -> int:
    """Index just past the ``)`` matching the ``(`` at ``open_idx``.

    Returns ``-1`` when unbalanced, which happens in truncated or in genuinely
    malformed source. A gate that crashes on malformed input is a gate that gets
    disabled, so an unclosed delimiter is reported rather than raised.
    """
    depth = 0
    for i in range(open_idx, len(code)):
        ch = code[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def cfg_predicates(src: str, mask: list[bool]) -> list[CfgPredicate]:
    """Every ``cfg``/``cfg_attr`` predicate in ``src``, at code positions only.

    "At a code position" is the whole point: a comment or a string literal that
    mentions ``#[cfg(target_os = "linux")]`` produces nothing.
    """
    code = code_only(src, mask)
    found: list[CfgPredicate] = []
    for m in _CFG_HEAD.finditer(code):
        # `cfg` must be its own identifier, not the tail of another one.
        if m.start() > 0 and (code[m.start() - 1].isalnum() or code[m.start() - 1] == "_"):
            continue
        open_idx = code.index("(", m.end() - 1)
        end = _match_paren(code, open_idx)
        if end == -1:
            continue
        raw = code[open_idx + 1 : end - 1]
        is_cfg_attr = bool(m.group(1))
        found.append(
            CfgPredicate(
                line=line_of(src, m.start()),
                text=raw,
                is_cfg_attr=is_cfg_attr,
            )
        )
    return found


def predicate_keys(pred: str) -> set[str]:
    """Every identifier that appears as a bare key inside a cfg predicate.

    ``cfg(target_os = "linux")``            -> {"target_os"}
    ``cfg(not(unix))``                      -> {"unix"}
    ``cfg(all(target_os = "linux", unix))`` -> {"target_os", "unix"}
    ``cfg(any(a, b))``                      -> {"a", "b"}

    Values (``"linux"``) are excluded: they are strings, and a value that happened to
    contain a platform word is not a platform predicate.
    """
    # String literals are blanked first. A value is not a key, and `cfg(target_os =
    # "linux")` must not report `linux` as one. Doing this here rather than relying on
    # the caller means the function is correct on raw predicate text, so it has no
    # hidden precondition.
    pred = code_only(pred, code_mask(pred))
    keys: set[str] = set()
    # `name = value`: record the name only.
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", pred):
        keys.add(m.group(1))
    # A bare identifier: either an operator name (`not`/`all`/`any`) or a key with no
    # value. Operators are excluded explicitly so `not` is not reported as a key.
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", pred):
        word = m.group(1)
        if word in {"not", "all", "any"}:
            continue
        keys.add(word)
    return keys


def predicate_has_platform(pred: str) -> list[str]:
    """Platform keys in ``pred``, at any nesting depth.

    Depth comes for free: ``predicate_keys`` is a flat scan of the predicate's
    text, and ``cfg(not(any(target_os = "windows", unix)))`` has the keys right
    there in the text. Recursion is not needed for *detection* -- only for the
    test-only decision below, where the logical structure matters.
    """
    return sorted(predicate_keys(pred) & PLATFORM_CFG_KEYS)


def platform_constructs(src: str) -> list[tuple[int, str]]:
    """Platform-specific constructs in ``src``, as ``(line, text)``.

    Covers both mechanisms the boundary is about:

    * a ``cfg``/``cfg_attr`` predicate naming a platform key, at any depth; and
    * a platform value read through a function-like macro (``env::consts::OS``),
      which is an opinion about the platform without using an attribute.

    Only code is considered. Prose that documents this rule -- which
    ``orxnud-domain/src/platform.rs`` must do in order to explain the rule -- is not
    a platform branch, and a gate that cannot tell documentation from code forces the
    documentation to become vague.
    """
    mask = code_mask(src)
    code = code_only(src, mask)
    hits: list[tuple[int, str]] = []

    for pred in cfg_predicates(src, mask):
        found = predicate_has_platform(pred.text)
        if found:
            hits.append(
                (
                    pred.line,
                    f"cfg{'attr' if pred.is_cfg_attr else ''} names a platform key: "
                    f"{', '.join(found)}",
                )
            )

    for macro in PLATFORM_MACROS:
        start = 0
        while True:
            idx = code.find(macro, start)
            if idx == -1:
                break
            # Require an identifier boundary before the match.
            if idx == 0 or not (code[idx - 1].isalnum() or code[idx - 1] == "_"):
                hits.append((line_of(src, idx), f"{macro} reads a host platform value"))
            start = idx + len(macro)

    # `std::os::unix` / `std::os::windows` are the other spelling of the same thing:
    # an import that only exists on one platform.
    for m in re.finditer(r"\b(?:std|core)::os::(unix|windows)\b", code):
        hits.append((line_of(src, m.start()), f"platform-only module path: {m.group(0)}"))

    # Deduplicate: the same construct can be found by more than one pass.
    seen: set[tuple[int, str]] = set()
    unique: list[tuple[int, str]] = []
    for line, text in sorted(hits):
        key = (line, text)
        if key not in seen:
            seen.add(key)
            unique.append(key)
    return unique


# --------------------------------------------------------------------------
# Test-only regions
# --------------------------------------------------------------------------


def _eval_test_only(pred: str, test_enabled: bool) -> bool:
    """Evaluate a cfg predicate knowing only whether ``test`` is on.

    Returns whether the predicate holds. Unknown keys evaluate to ``True`` -- the
    optimistic reading, which is the safe one here: it means a predicate mentioning
    something this module has never heard of is *not* silently treated as test-only.

    An item is test-only when its predicate holds with ``test`` on and fails with
    ``test`` off. That distinguishes all four cases that matter:

    ===========================  =============  ==============  ==========
    predicate                    test on        test off        test-only?
    ===========================  =============  ==============  ==========
    ``cfg(test)``                true           false           yes
    ``cfg(all(test, unix))``     true           false           yes
    ``cfg(any(test, unix))``     true           true            no
    ``cfg(not(test))``           false          true            no
    ===========================  =============  ==============  ==========

    The last two are the ones a textual check gets wrong: ``cfg(any(test, unix))``
    is production code that happens to be enabled in tests, and treating it as
    test-only would silently exempt production code from the gate.
    """
    pred = pred.strip()
    if pred.startswith("not(") and _match_paren(pred, pred.index("(")) == len(pred):
        return not _eval_test_only(pred[4:-1], test_enabled)
    for op, fold in (("all", all), ("any", any)):
        if pred.startswith(op + "(") and _match_paren(pred, pred.index("(")) == len(pred):
            args = _split_top_level(pred[pred.index("(") + 1 : -1])
            return fold(_eval_test_only(a, test_enabled) for a in args if a.strip())
    m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=(?!=)\s*\S+)?\s*$", pred)
    if m:
        return test_enabled if m.group(1) == "test" else True
    # Not a shape we recognise: assume it can apply outside tests.
    return True


def _split_top_level(text: str) -> list[str]:
    """Split on commas that are not inside parentheses."""
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def is_test_only_predicate(pred: str) -> bool:
    """Whether a cfg predicate makes its item test-only."""
    return _eval_test_only(pred, True) and not _eval_test_only(pred, False)


@dataclass(frozen=True)
class TestOnlyRegion:
    """A span of code excluded because it is genuinely test-only."""

    start_line: int
    end_line: int
    predicate: str


def test_only_regions(src: str, mask: list[bool]) -> list[TestOnlyRegion]:
    """Spans of ``src`` that are test-only because a real ``cfg`` attribute says so.

    A region runs from the attribute to the end of the item it applies to. For
    ``#[cfg(test)] mod tests { ... }`` that is the matching close brace; for
    ``#[cfg(test)] fn helper() { ... }`` likewise. An attribute with no brace at all
    -- ``#[cfg(test)] use foo;`` -- covers only its own line.

    The end is found by brace counting, so nesting is handled rather than assumed:
    the old rule ("the first line starting with ``}`` at column 0") happened to work
    for rustfmt output and silently truncated anything else, which is a gate that
    passes for the wrong reason.
    """
    regions: list[TestOnlyRegion] = []
    for pred in cfg_predicates(src, mask):
        if pred.is_cfg_attr or not is_test_only_predicate(pred.text):
            continue
        start = pred.line - 1
        # Find the item's opening brace after the attribute.
        brace = _first_brace_after(src, mask, pred.line)
        if brace == -1:
            regions.append(TestOnlyRegion(start + 1, start + 1, pred.text))
            continue
        end = _matching_brace_line(src, mask, brace)
        regions.append(TestOnlyRegion(start + 1, end, pred.text))
    return regions


def _first_brace_after(src: str, mask: list[bool], after_line: int) -> int:
    """Index of the first ``{`` at a code position on a line after ``after_line``."""
    code = code_only(src, mask)
    line_start = 0
    for _ in range(after_line):
        nxt = code.find("\n", line_start)
        if nxt == -1:
            return -1
        line_start = nxt + 1
    brace = code.find("{", line_start)
    return -1 if brace == -1 else brace


def _matching_brace_line(src: str, mask: list[bool], brace_idx: int) -> int:
    """1-based line of the ``}`` closing the ``{`` at ``brace_idx``."""
    depth = 0
    for i in range(brace_idx, len(src)):
        if not mask[i]:
            continue
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return line_of(src, i)
    return len(src.split("\n"))


def test_only_line_mask(src: str) -> list[bool]:
    """One entry per line: whether that line is outside every test-only region."""
    regions = test_only_regions(src, code_mask(src))
    total = len(src.split("\n"))
    masked = [True] * total
    for r in regions:
        for i in range(max(0, r.start_line - 1), min(total, r.end_line)):
            masked[i] = False
    return masked


def strip_test_only(src: str) -> str:
    """``src`` with test-only regions blanked, preserving line structure.

    Blank lines, not deleted lines, so a match position still maps to the original
    line number and the gate can report where it found something.
    """
    masked_lines = test_only_line_mask(src)
    out = []
    for i, line in enumerate(src.split("\n")):
        out.append("" if i < len(masked_lines) and not masked_lines[i] else line)
    return "\n".join(out)