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


# The prefixes Rust actually accepts for a raw string: `r`, `br` and `cr`. `rb` and
# `rc` are not Rust syntax and were removed. The bare `r` alternative is the one that
# was missing, and it is what made the whole lexer fail: with it absent, `r#"..."#`
# could not be recognised, the scanner fell through to the ordinary-string branch, and
# the `"` that opens the raw string terminated a *normal* string instead. The result
# was a string run that swallowed the rest of the file -- 216,876 characters of
# `runtime.rs` were classified as string content, and every `{` in it with them.
_RAW_PREFIX = re.compile(r"\b(?:br|cr|r)?(#+)?\"", re.ASCII)


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
    # A one-character literal may be any single character, punctuation included:
    # `'{'` is a char literal, and `'}''` is not a lifetime. The discriminator is
    # the *closing* quote: if the character after the candidate is `'`, it is a
    # literal; otherwise it is a lifetime.
    #
    # This was wrong before: only `\` and `''` were accepted, so `'{'` was
    # mis-read as a lifetime and the brace it contained was counted as code.
    if i + 2 < len(src) and src[i + 2] == "'":
        return True
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
    #: Index just past the ``]`` that closes the attribute this predicate is in.
    #:
    #: The predicate alone does not say where the *item* it applies to begins: an
    #: attribute is ``#[cfg(...)]``, and the item follows the closing bracket. This
    #: is what lets the item's extent be found from the text that actually follows
    #: the attribute, instead of by searching forwards for an item keyword.
    attr_end: int = 0


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
        # The attribute's closing bracket: the first `]` at a code position after
        # the predicate. A `]` inside a string is not a code position, so it cannot
        # be mistaken for the end of the attribute.
        close = code.find("]", end)
        attr_end = len(src) if close == -1 else close + 1
        found.append(
            CfgPredicate(
                line=line_of(src, m.start()),
                text=raw,
                is_cfg_attr=is_cfg_attr,
                attr_end=attr_end,
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


def _matching_brace(src: str, mask: list[bool], open_idx: int) -> int:
    """Index of the ``}`` closing the ``{`` at ``open_idx``, or ``-1``.

    Counts only code positions, so a brace inside a string, a raw string or a
    comment cannot shift the match.
    """
    depth = 0
    for i in range(open_idx, len(src)):
        if not mask[i]:
            continue
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _skip_attributes_and_space(src: str, mask: list[bool], i: int) -> int:
    """Index of the first code token at or after ``i``, skipping attributes.

    Attributes and whitespace may sit between the attribute under examination
    and the item it applies to (``#[cfg(test)] #[derive(Debug)] struct S``), and
    comments sit there too. All three are skipped, because the item is what
    follows them, not any of them.
    """
    n = len(src)
    while i < n:
        if src[i] == "#":
            j = i + 1
            while j < n and src[j] in " \t":
                j += 1
            if j < n and src[j] == "[":
                depth = 0
                while j < n:
                    if src[j] == "[":
                        depth += 1
                    elif src[j] == "]":
                        depth -= 1
                        if depth == 0:
                            j += 1
                            break
                    j += 1
                i = j
                continue
            break
        if not mask[i] or src[i].isspace():
            i += 1
            continue
        break
    return i


def attributed_item_span(src: str, mask: list[bool], after: int) -> tuple[int, int] | None:
    """The character span of the item an attribute applies to.

    ``after`` is the index just past the attribute's closing ``]``. The returned
    span is ``(start, end)``: ``start`` is the item's first code token and
    ``end`` is one past the item's last character.

    # Why the item is found from the text that follows the attribute

    The previous rule searched *forwards* for an item keyword (``fn``, ``mod``,
    ``impl``, ...) and then took the body after it. That silently attributes an
    attribute to a **later, unrelated** item whenever the item it really applies
    to is not one of those keywords — a ``use`` item, a macro invocation, or a
    statement. The consequence is not a cosmetic off-by-one: the *later* item's
    body is blanked, so production code disappears from the scanner's input and
    the gates stop seeing it.

    That is not hypothetical. In ``crates/orxnud-store/src/backup.rs`` the line
    ``#[cfg(test)] use std::cell::RefCell;`` sits immediately above
    ``impl Backup { ... }``. The keyword search skipped the ``use`` item, found
    ``impl``, and blanked the whole ``impl`` block — 608 lines of production
    code, including every ``Connection::open`` in it — out of the view of gate
    **G17**. The rule is therefore: find the item where the attribute says it
    is, not where the next keyword happens to be.

    # The extent of an item

    * An item with a body — ``fn``, ``mod``, ``impl``, ``struct``, ``enum``, a
      macro invocation — ends at the ``}`` matching the first ``{`` at depth 0.
    * An item without one — ``use``, ``let``, a statement — ends at the first
      ``;`` at depth 0.
    * A ``use`` item's braces are a *use tree*, not a body, so a ``use`` ends at
      its ``;`` even though it contains braces.

    Depth is tracked over ``()``, ``[]`` and ``{}``, so a brace inside a call's
    arguments is not mistaken for a body.

    # Failure behaviour

    ``None`` means no item could be located. The caller decides what to do with
    that, and the callers all fail in the safe direction: blank too little and a
    gate may report a false positive, which is visible and cheap; blank too much
    and production code is hidden, which is not.
    """
    start = _skip_attributes_and_space(src, mask, after)
    if start >= len(src):
        return None

    # A `use` item's braces are a use tree, not a body.
    j = start
    while j < len(src) and (src[j].isalnum() or src[j] == "_"):
        j += 1
    is_use = src[start:j] == "use"

    depth = 0
    i = start
    while i < len(src):
        if mask[i]:
            c = src[i]
            if c in "([{":
                if c == "{" and depth == 0 and not is_use:
                    close = _matching_brace(src, mask, i)
                    if close == -1:
                        return None
                    return (start, close + 1)
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif c == ";" and depth == 0:
                return (start, i + 1)
        i += 1
    return None


def test_only_regions(src: str, mask: list[bool]) -> list[TestOnlyRegion]:
    """Spans of ``src`` that are test-only because a real ``cfg`` attribute says so.

    A region runs from the attribute to the end of the item it applies to. For
    ``#[cfg(test)] mod tests { ... }`` that is the matching close brace; for
    ``#[cfg(test)] fn helper() { ... }`` likewise. An attribute with no brace at all
    -- ``#[cfg(test)] use foo;`` -- covers only its own line.

    The end is found from the item the attribute applies to, using
    :func:`attributed_item_span`, so nesting is handled rather than assumed and
    an attribute is never allowed to swallow a *later* item's body.
    """
    regions: list[TestOnlyRegion] = []
    for pred in cfg_predicates(src, mask):
        if pred.is_cfg_attr or not is_test_only_predicate(pred.text):
            continue
        start = pred.line - 1
        span = attributed_item_span(src, mask, pred.attr_end)
        if span is None:
            regions.append(TestOnlyRegion(start + 1, start + 1, pred.text))
            continue
        end = line_of(src, span[1] - 1)
        regions.append(TestOnlyRegion(start + 1, end, pred.text))
    return regions


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

_OPEN = {"(": ")", "[": "]", "{": "}"}
_CLOSE = {v: k for k, v in _OPEN.items()}


def delimiter_matches(src: str, mask: list[bool]) -> dict[int, int]:
    """Map every opening delimiter index in ``src`` to its matching close index.

    # Why this exists

    Every previous attempt to find the end of a test function counted braces by hand
    over text that had already been modified, and every one of them was wrong:

    * counting over text blanked by an earlier pass loses the braces that pass removed;
    * counting over pristine text is confused by ``use super::{A, b};``, which opens and
      closes on one line;
    * counting by indentation blanks production code that sits next to a test item.

    The fix is not a better heuristic. It is to stop matching structure in a *derived*
    string. ``code_mask`` is already a single-pass lexer that tells comments, raw
    strings, byte strings, c-strings, char literals and lifetimes apart, so the
    delimiters that matter are exactly the code characters carrying ``(``, ``[``, ``{``.
    Walking those through a stack gives an exact pairing, and because the walk is over
    the original source, a match is an *offset* into the original file rather than a
    position in some intermediate rendering. Callers blank by offset and leave every
    other character -- and every offset -- exactly where it was.

    Braces inside ordinary and raw strings, escapes, byte and raw-byte strings, nested
    block comments and char literals are all excluded because ``code_mask`` has already
    classified them as non-code.
    """
    stack: list[tuple[str, int]] = []
    out: dict[int, int] = {}
    for i, ch in enumerate(src):
        if not mask[i]:
            continue
        if ch in _OPEN:
            stack.append((ch, i))
        elif ch in _CLOSE:
            want = _CLOSE[ch]
            # A stray closer with no opener is not our problem to repair; it belongs to
            # whatever the caller failed to strip. Ignoring it is safe because it can
            # only appear where there was already an unmatched delimiter.
            for depth in range(len(stack) - 1, -1, -1):
                if stack[depth][0] == want:
                    for _, o in stack[depth + 1:]:
                        out.pop(o, None)
                    o = stack[depth][1]
                    del stack[depth:]
                    out[o] = i
                    break
    return out


def blank_range(src: str, start: int, end: int) -> str:
    """``src`` with ``[start, end)`` replaced by spaces.

    Length, line structure and every offset outside the range are preserved, so a match
    found in the result still maps to the same line in the original file.
    """
    if start < 0 or end > len(src) or start >= end:
        return src
    return src[:start] + " " * (end - start) + src[end:]


def classify(src: str) -> list[str]:
    """One label per character: ``"code"``, ``"string"`` or ``"comment"``.

    Newlines are labelled ``"code"`` so that callers counting lines off any mask agree
    with the original file.

    This is the single lexer the module exposes. The three masks below are all views of
    it, because deriving one mask from another was how a DDL detector ended up unable to
    see DDL (it is a string) while a brace walk ended up unable to trust braces (they
    must ignore strings but honour comments' absence).
    """
    n = len(src)
    kind = ["code"] * n
    i = 0
    while i < n:
        c = src[i]
        if c == "\n":
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                kind[k] = "comment"
            i = j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            kind[i] = kind[i + 1] = "comment"
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if src.startswith("/*", j):
                    depth += 1
                    kind[j] = kind[j + 1] = "comment"
                    j += 2
                elif src.startswith("*/", j):
                    depth -= 1
                    kind[j] = kind[j + 1] = "comment"
                    j += 2
                else:
                    if src[j] != "\n":
                        kind[j] = "comment"
                    j += 1
            i = j
            continue
        m = _RAW_PREFIX.match(src, i)
        if m:
            # The terminator of a raw string is a quote followed by the opening
            # hashes -- `"#` for `r#"..."#`, `"##` for `r##"..."##`. It is *not* a
            # quote, the hashes, and another quote: that three-character form is what
            # this code used to build, and because it never occurs in the source, the
            # `find` below always failed and the token ran to the end of the file.
            # That single character is the reason 216,876 characters of `runtime.rs`
            # were classified as string content, and why every `{` in that span with
            # them -- including the `mod tests {` that started this investigation.
            term = '"' + (m.group(1) or "")
            close = src.find(term, m.end())
            end = n if close == -1 else close + len(term)
            for k in range(i, min(end, n)):
                if src[k] != "\n":
                    kind[k] = "string"
            i = min(end, n)
            continue
        if c == '"' or (c == "b" and i + 1 < n and src[i + 1] == '"'):
            j = i + 1 if c == '"' else i + 2
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
                    kind[k] = "string"
            i = min(j, n)
            continue
        if c == "'" and _is_char_literal(src, i):
            j = i + 1
            if j < n and src[j] == "\\":
                j += 2
                while j < n and src[j] != "'":
                    j += 1
                j += 1
            else:
                j += 1
                if j < n and src[j] == "'":
                    j += 1
            for k in range(i, min(j, n)):
                if src[k] != "\n":
                    kind[k] = "string"
            i = min(j, n)
            continue
        i += 1
    return kind


def code_mask(src: str) -> list[bool]:
    """Code only -- comments and string contents are False. Newlines stay True."""
    return [k == "code" for k in classify(src)]


def code_or_string_mask(src: str) -> list[bool]:
    """Everything except comments. Newlines stay True.

    Use this when a pattern lives *inside* a string literal -- DDL, a JSON key, a SQL
    keyword. ``code_mask`` would blank the very text being searched for.
    """
    return [k != "comment" for k in classify(src)]


# --------------------------------------------------------------------------
# Self-tests for the lexer. Run with `python3 scripts/rustscan.py`.
# --------------------------------------------------------------------------

def _selftest() -> int:
    import re as _re

    failures: list[str] = []

    def check(name: str, got: object, want: object) -> None:
        if got != want:
            failures.append(f"{name}: got {got!r}, want {want!r}")

    def label(src: str, marker: str) -> str:
        """The classification of the first occurrence of ``marker``."""
        return classify(src)[src.index(marker)]

    # -- 1. the prefix expression, in isolation ----------------------------
    # Each entry is (source, expected span of the raw-string opener).
    for src, want_span in [
        ('r#"{"capability":"filesystem/write-text"}"#', (0, 3)),
        ('r"plain raw string"', (0, 2)),
        ('br#"raw bytes { }"#', (0, 4)),
        ('cr#"raw C string { }"#', (0, 4)),
        ('r##"hashes ## inside"##', (0, 4)),
    ]:
        m = _RAW_PREFIX.match(src, 0)
        check(f"prefix span {src[:12]!r}", None if m is None else m.span(), want_span)

    # The raw opener must be recognised at the `r`, not one character later.
    m = _RAW_PREFIX.match('r#"x"#', 0)
    check("raw opener starts at the r", None if m is None else m.group(0), 'r#"')

    # Near-misses: a prefix must not be recognised inside an identifier.
    for src in ['var"x"', 'crab"x"', 'b"bytes"', 'xr"y"']:
        m = _RAW_PREFIX.match(src, 0)
        check(f"near-miss {src!r} is not a raw opener", m is not None, False)

    # -- 2. through classify() ---------------------------------------------
    # The exact literal that exposed the defect, followed by code.
    src = 'r#"{"capability":"filesystem/write-text"}"#; let after = 1;'
    check("raw literal is string", label(src, 'r#"'), "string")
    check("code after raw literal is code", label(src, "let after"), "code")

    # A raw string containing braces must not desynchronise matching.
    src = 'fn f() { let s = r##"a { b "# c"##; let after = 1; }'
    check("brace inside raw string is string", label(src, "{ b "), "string")
    check("shorter quote/hash inside raw string is string", label(src, '"# c'), "string")
    check("code after raw string is code", label(src, "let after"), "code")

    # Ordinary escaped strings.
    src = 'let s = "a \\" b"; let after = 1;'
    check("escaped quote is string", label(src, chr(92) + ""), "string")
    check("code after escaped string is code", label(src, "let after"), "code")

    # Byte strings.
    src = 'let s = b"bytes"; let after = 1;'
    check("byte string is string", label(src, 'b"'), "string")
    check("code after byte string is code", label(src, "let after"), "code")

    # Char literal versus lifetime.
    src = "let c = '{'; fn g<'a>(x: &'a str) { let after = 1; }"
    check("char literal is string", label(src, "'{'"), "string")
    check("lifetime is code", label(src, "'a"), "code")
    check("code after lifetime is code", label(src, "let after"), "code")

    # Nested block comments.
    src = "/* outer /* inner { */ still comment */ let after = 1;"
    check("nested comment is comment", label(src, "{"), "comment")
    check("code after nested comment is code", label(src, "let after"), "code")

    # Line comments.
    src = "// a comment with { and a quote \"\nlet after = 1;"
    check("line comment is comment", label(src, "{ and"), "comment")
    check("code after line comment is code", label(src, "let after"), "code")

    # `use super::{A, B};` is a balanced group, not an item body.
    src = "use super::{A, B};\nfn f() { let after = 1; }"
    check("use group braces are code", label(src, "{A"), "code")
    check("code after use group is code", label(src, "let after"), "code")

    # -- 3. the two mask views ---------------------------------------------
    ddl = 'const S: &str = "CREATE TABLE t (id TEXT)";'
    check("DDL hidden from code_mask", "CREATE TABLE" in code_only(ddl, code_mask(ddl)), False)
    check("DDL visible to code_or_string_mask", "CREATE TABLE" in code_only(ddl, code_or_string_mask(ddl)), True)

    # -- 4. structural matching keeps offsets ------------------------------
    src = 'fn f() { let s = "}"; }'
    m = delimiter_matches(src, code_mask(src))
    check("delimiter count", len(m), 2)
    check("blank_range preserves length", len(blank_range(src, 3, 7)), len(src))
    check("blank_range preserves surrounding code", blank_range(src, 3, 7)[8:], src[8:])

    # -- 5. which item an attribute applies to ------------------------------
    #
    # The defect these guard: the item was found by searching *forwards* for an
    # item keyword, so an attribute whose item was not keyword-introduced -- a
    # `use`, a macro invocation, a statement -- was attributed to a **later**,
    # unrelated item, whose body was then blanked. In
    # `crates/orxnud-store/src/backup.rs` the line `#[cfg(test)] use
    # std::cell::RefCell;` sits immediately above `impl Backup { ... }`, and the
    # whole `impl` block -- 608 lines of production code, including every
    # `Connection::open` in it -- was blanked out of gate G17's view.

    def span_text(src: str) -> str:
        """The text of the item the first `#[cfg(test)]` attribute applies to."""
        mask = code_mask(src)
        close = src.index("]")
        span = attributed_item_span(src, mask, close + 1)
        return "" if span is None else src[span[0] : span[1]]

    check(
        "a use item's span is the statement",
        span_text("#[cfg(test)]\nuse std::cell::RefCell;\n\nimpl Backup { fn p() {} }\n").strip(),
        "use std::cell::RefCell;",
    )
    check(
        "a macro invocation's span is the whole invocation",
        span_text(
            "#[cfg(test)]\nstd::thread_local! {\n    static S: u8 = const { 0 };\n}\n"
            "\nfn p() {}\n"
        ),
        "std::thread_local! {\n    static S: u8 = const { 0 };\n}",
    )
    check(
        "a statement's span ends at its semicolon",
        span_text("#[cfg(test)]\nseams::check(Fault::X);\n\nfn p() {}\n").strip(),
        "seams::check(Fault::X);",
    )

    # A production function after a test-only macro invocation must survive.
    src = """
#[cfg(test)]
std::thread_local! {
    static SEAMS: RefCell<u8> = const { RefCell::new(0) };
}

pub fn production() {
    let _ = 1;
}
"""
    view = strip_test_only(src)
    check("a production fn after a cfg(test) macro survives", "pub fn production" in view, True)
    check("the cfg(test) macro is excluded", "SEAMS" in view, False)

    # The `use` item that hid 608 lines of production code.
    src = """
#[cfg(test)]
use std::cell::RefCell;

impl Backup {
    pub fn production(&self) -> u8 { 1 }
}
"""
    view = strip_test_only(src)
    check("an impl after a cfg(test) use survives", "impl Backup" in view, True)
    check("the cfg(test) use is excluded", "use std::cell::RefCell" in view, False)

    # Nested braces inside a test-only item must not swallow what follows.
    src = """
#[cfg(test)]
fn a_test() {
    let x = Foo { a: { b: 1 } };
}

pub fn production() {}
"""
    view = strip_test_only(src)
    check("nested braces do not swallow the next item", "pub fn production" in view, True)
    check("the test fn's body is excluded", "Foo {" in view, False)

    # Braces and test-looking text inside strings and comments must not move a
    # boundary.
    src = """
#[cfg(test)]
fn a_test() {
    let s = "} { #[cfg(test)] fn fake() {";
    /* a comment with { and } */
}

pub fn production() {}
"""
    view = strip_test_only(src)
    check("a brace in a string does not corrupt the boundary", "pub fn production" in view, True)
    check("a cfg inside a string is not a region", "fn fake()" in view, False)

    # A test-only function is excluded, and the production code after it is not.
    src = """
#[cfg(test)]
fn a_test() {
    let _c = rusqlite::Connection::open("/tmp/scratch.db");
}

pub fn production() {}
"""
    view = strip_test_only(src)
    check("a cfg(test) fn's body is excluded", "scratch.db" in view, False)
    check("the production fn after it survives", "pub fn production" in view, True)

    if failures:
        for f in failures:
            print(f"FAIL {f}")
        return 1
    print("rustscan self-tests: all passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
