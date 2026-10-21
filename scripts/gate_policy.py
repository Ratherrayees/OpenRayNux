#!/usr/bin/env python3
"""G2d and G3, implemented over the lexical scanner in ``rustscan``.

Split out of ``ci-gates.sh`` so that both gates have one implementation, in one
language, that the self-test can drive directly. The shell script remains the entry
point CI runs; this is what it runs.

Two invariants are enforced.

**G2d — the policy seal.** Production code, outside a genuinely test-only region and
outside the two exempt crates, must not be able to mint a capability authorisation.

The exemption is not a symbol list; it is derived. ``PolicySeal`` is the *root* of the
authority chain: ``AuthorisationProof::issue`` and ``CapabilityInvocation::authorise``
both require a ``&PolicySeal``, so the seal is the only thing that has to be kept
unreachable. ``check_authority_surface_is_unchanged`` re-derives that structure from the
domain's own source and **fails loudly** if the domain has grown a new ungated
constructor, so the list below cannot silently go stale.

**G3 — the platform boundary.** A portable-core crate must not acquire a platform
opinion. That covers ``cfg``/``cfg_attr`` predicates naming a platform key at any
nesting depth, host values read through ``env::consts``, and ``std::os::{unix,windows}``
paths. Only code is considered, so prose documenting the rule is not a violation.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass

# No `__pycache__` in the repository: a CI script must not leave build artefacts
# behind, and this one runs from a checkout that is expected to stay clean.
sys.dont_write_bytecode = True

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import rustscan  # noqa: E402

# --------------------------------------------------------------------------
# What counts as production source
# --------------------------------------------------------------------------

# The locations that can become production code for their crate.
#
# `tests/` is deliberately excluded and the exclusion is load-bearing: a `compile_fail`
# test must *name* the sealed types to prove the seal holds, and `trybuild` fixtures are
# compiled by the harness rather than by cargo. That is the only excluded Rust source,
# and `tests/` is never part of a shipped binary.
SOURCE_GLOBS = (
    ("src", ".rs"),
    ("examples", ".rs"),
    ("benches", ".rs"),
    ("build.rs", None),
)

# Crates allowed to *mint* authority.
#
# orxnud-policy *owns* the authority types now: `AuthorisationProof`, `CapabilityInvocation`
# and `DispatchView` live in `crates/orxnud-policy/src/authority.rs`, beside the
# `pub(crate)` constructors that produce them. Rust has no friend crates, so the only way
# to make "exactly one crate may construct this" a compiler fact rather than a code-review
# convention is to put the type where that crate can see it and everyone else cannot.
#
# Naming an authority type as a parameter type is legitimate elsewhere -- a capability
# crate receives an invocation and cannot construct one -- so the invariant stays about
# minting, not naming.
EXEMPT_CRATES = frozenset({"orxnud-policy"})

# The authority surface, asserted rather than trusted. `check_authority_surface` verifies
# each of these against the owning crate's source and fails if authority has moved.
#
# Each entry is (type, minting constructor, expected visibility). Visibility is part of the
# invariant, not decoration: a `pub(crate)` constructor is enforced by `rustc`, a `pub` one
# is enforced by this scan and by nothing else. `rustc` is the stronger instrument, so the
# assertion here exists to catch the day someone widens it.
EXPECTED_AUTHORITY_TYPES = ("AuthorisationProof", "CapabilityInvocation", "DispatchView")
EXPECTED_MINTING_CONSTRUCTORS = {
    "AuthorisationProof": "issue",
    "CapabilityInvocation": "authorise",
}
EXPECTED_CONSTRUCTOR_VISIBILITY = "pub(crate)"

# The trait boundary in orxnud-capability. Both are whole `pub(crate)` traits, not `pub`
# traits with `pub(crate)` methods: a `pub` trait could still be *implemented* from outside,
# which would let an external bundle enter the registry. Asserting the trait's own
# visibility catches that, and asserting the method's catches a re-widening inside the crate.
EXPECTED_SEALED_ITEMS = (
    ("orxnud-capability", "CapabilityAdapter", "trait"),
    ("orxnud-capability", "AdapterBundle", "trait"),
)

# Identifiers that *mint* authority. `authorise` alone catches the method-call form,
# `Type::fn` and `use Type::fn; fn(..)`. `attest` is gone with the seal it belonged to.
#
# `dispatch_view` is deliberately absent. It is `pub` and legitimately called from
# orxnud-capability, because producing the adapter's input from an authorised invocation
# is the dispatcher's job and cannot happen inside the policy crate. It mints nothing:
# it requires an invocation to call, so it is downstream of `authorise` rather than
# another way past it. The distinction is that a minting verb creates authority from
# parts, and this one can only re-derive a view of authority that already exists.
MINTING_VERBS = ("authorise", "issue")


@dataclass(frozen=True)
class Violation:
    """One boundary crossing, with enough context to act on it."""

    path: str
    line: int
    what: str

    def render(self, root: str) -> str:
        rel = os.path.relpath(self.path, root) if root else self.path
        return f"{rel}:{self.line}: {self.what}"


def crate_of(path: str, root: str) -> str:
    """The crate directory name for ``path``, or "" when it is not under ``crates/``."""
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return ""
    parts = rel.split(os.sep)
    if len(parts) >= 2 and parts[0] == "crates":
        return parts[1]
    return ""


def production_sources(root: str) -> list[str]:
    """Every Rust file under ``root`` that can affect production behaviour.

    Enumerated from :data:`SOURCE_GLOBS` rather than by a broad ``find``, so the coverage
    is a decision a reviewer can read instead of an accident of directory layout. The
    previous gate used ``find ... -path '*/src/*'``, which silently excluded
    ``examples/`` -- and ``cargo check --example`` compiles those, so an example is
    production-reachable code that the gate never looked at.
    """
    crates_dir = os.path.join(root, "crates")
    if not os.path.isdir(crates_dir):
        return []
    found: list[str] = []
    for crate in sorted(os.listdir(crates_dir)):
        crate_dir = os.path.join(crates_dir, crate)
        if not os.path.isdir(crate_dir):
            continue
        for entry, ext in SOURCE_GLOBS:
            target = os.path.join(crate_dir, entry)
            if not os.path.exists(target):
                continue
            if os.path.isfile(target):
                if ext is None or target.endswith(ext):
                    found.append(target)
                continue
            for dirpath, _dirnames, filenames in os.walk(target):
                for name in sorted(filenames):
                    if ext is None or name.endswith(ext):
                        found.append(os.path.join(dirpath, name))
    return sorted(found)


# --------------------------------------------------------------------------
# G2d -- the policy seal
# --------------------------------------------------------------------------


def authority_violations(root: str, sources: list[str]) -> list[Violation]:
    """Where production code outside an exempt crate can mint authorisation."""
    out: list[Violation] = []
    for path in sources:
        if crate_of(path, root) in EXEMPT_CRATES:
            continue
        src = open(path, encoding="utf-8").read()
        # Only code outside genuinely test-only regions counts.
        production = rustscan.strip_test_only(src)
        mask = rustscan.code_mask(production)
        code = rustscan.code_only(production, mask)

        # `finditer`, not `findall`: each occurrence needs its own position, so that a
        # file with two violations reports two lines rather than both at line 1.
        for m in _IDENT_RE.finditer(code):
            ident = m.group(0)
            line = rustscan.line_of(production, m.start())
            if ident in MINTING_VERBS:
                out.append(
                    Violation(
                        path,
                        line,
                        f"calls `{ident}`, which mints authority or the proof behind it. "
                        f"Only {sorted(EXEMPT_CRATES)[0]} may, and it does so through a "
                        f"`pub(crate)` constructor that `rustc` keeps to that crate.",
                    )
                )
    return out


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _fn_visibility_in_impl(code: str, type_name: str, fn_name: str) -> str | None:
    """The modifier in front of `Type::fn`, searching only inside `impl Type { .. }`.

    Scoping to the impl block is the whole point. `PolicyEngine::authorise` and
    `CapabilityInvocation::authorise` are different functions with the same name, and
    only the second one is a constructor. A naive `fn authorise` search across the file
    finds the first and reports the wrong visibility -- which here means reading a
    `pub` and calling the boundary broken when it is not.
    """
    for m in re.finditer(rf"impl(?:<[^>]*>)?\s+(?:\w+::)*{type_name}\b", code):
        start = code.find("{", m.end())
        if start == -1:
            continue
        depth, i = 0, start
        while i < len(code):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        block = code[start:i]
        fm = re.search(rf"((?:pub\s*(?:\(\s*crate\s*\))?\s*)?)fn {fn_name}\s*[(<]", block)
        if fm:
            return fm.group(1).strip() or "(private)"
    return None


def check_authority_surface(root: str) -> list[str]:
    """Assert where authority lives and who can mint it; report any drift.

    A gate whose expectation is a hand-maintained constant decays: someone widens a
    constructor, nobody edits the gate, and the gate keeps passing. So every claim is
    checked against the source and fails loudly.

    Five things this asserts, and each fails loudly:

    1. each authority type is defined in the *owning* crate, not merely reachable from
       it -- a `pub use` re-export would put the constructor back within reach of the
       type's own visibility rules, and that is the mistake worth catching;
    2. each minting constructor exists and is exactly the expected name;
    3. each minting constructor is ``pub(crate)``, which is the assertion that makes the
       boundary a compiler fact rather than a convention;
    4. no authority type is re-exported from a crate *below* the owner, since
       ``orxnud-domain`` is depended on by everything and a re-export there would give
       the minting constructor a second, wider audience; and
    5. each sealed capability item is a whole ``pub(crate)`` trait, not a ``pub`` trait
       with ``pub(crate)`` methods.

    # What this deliberately cannot detect

    A *brand-new, unrelated* public type with a public constructor that happens to grant
    capability execution. Nothing marks it as authority -- guessing would mean flagging
    every constructor in the crate, which is noise a reviewer learns to skip, and a gate
    that cries wolf is a gate that gets disabled. Introducing a new authority type is a
    design decision and comes through an ADR; this gate's job is to notice when the
    *existing* surface changes shape underneath it.
    """
    problems: list[str] = []
    owner_crate = "orxnud-policy"
    owner = os.path.join(root, "crates", owner_crate, "src")
    if not os.path.isdir(owner):
        return [f"{owner_crate} source not found at {owner}"]

    defined: dict[str, str] = {}  # type -> path that defines it, with `pub struct`
    visibility: dict[str, str] = {}  # (type, fn) -> the modifier in front of `fn`
    for dirpath, _dirnames, filenames in os.walk(owner):
        for name in sorted(filenames):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            code = _code_of(path)
            for t in EXPECTED_AUTHORITY_TYPES:
                if re.search(rf"^pub struct {t}\b", code, re.M):
                    defined[t] = os.path.relpath(path, root)
            # `pub(crate) fn issue`, `pub fn issue`, `fn issue` -- whichever applies.
            for t, fn in EXPECTED_MINTING_CONSTRUCTORS.items():
                found = _fn_visibility_in_impl(code, t, fn)
                if found is not None:
                    visibility[(t, fn)] = found

    # (1) ownership.
    for t in EXPECTED_AUTHORITY_TYPES:
        if t not in defined:
            problems.append(
                f"{owner_crate}: `{t}` is missing or is no longer defined here. Authority "
                f"moved, which means the `pub(crate)` constructors moved with it and the "
                f"boundary this gate asserts is no longer where it was."
            )

    # (2) + (3) the minting constructors and their visibility.
    for t, expected_fn in EXPECTED_MINTING_CONSTRUCTORS.items():
        seen = visibility.get((t, expected_fn))
        if seen is None:
            problems.append(
                f"{owner_crate}: `{t}::{expected_fn}` is missing. Without it the type "
                f"cannot be minted even by policy, so either the boundary is gone or the "
                f"constructor was renamed."
            )
            continue
        if seen != EXPECTED_CONSTRUCTOR_VISIBILITY:
            problems.append(
                f"{owner_crate}: `{t}::{expected_fn}` is `{seen}`, not "
                f"`{EXPECTED_CONSTRUCTOR_VISIBILITY}`. `rustc` only refuses other crates at "
                f"`pub(crate)`; anything wider hands the minting constructor to every "
                f"dependent, and the lexical scan below is the only thing left."
            )

    # (4) no re-export from a lower layer.
    domain = os.path.join(root, "crates", "orxnud-domain", "src")
    for dirpath, _dirnames, filenames in os.walk(domain):
        for name in sorted(filenames):
            if not name.endswith(".rs"):
                continue
            code = _code_of(os.path.join(dirpath, name))
            for t in EXPECTED_AUTHORITY_TYPES:
                for m in re.finditer(rf"pub use [^;]*\b{t}\b", code):
                    line = rustscan.line_of(open(os.path.join(dirpath, name), encoding="utf-8").read(), m.start())
                    problems.append(
                        f"{owner_crate}: `{t}` is re-exported from "
                        f"{os.path.relpath(os.path.join(dirpath, name), root)}:{line}. "
                        f"Everything depends on orxnud-domain, so a re-export there puts "
                        f"the minting constructor in reach of the whole workspace."
                    )

    # (5) the sealed capability traits.
    for crate, item, kind in EXPECTED_SEALED_ITEMS:
        base = os.path.join(root, "crates", crate, "src")
        if not os.path.isdir(base):
            problems.append(f"{crate} source not found at {base}")
            continue
        found_wide = False
        for dirpath, _dirnames, filenames in os.walk(base):
            for name in sorted(filenames):
                if not name.endswith(".rs"):
                    continue
                code = _code_of(os.path.join(dirpath, name))
                if re.search(rf"^pub {kind} {item}\b", code, re.M):
                    found_wide = True
                    problems.append(
                        f"{crate}: `{item}` is `pub`. A `pub` trait cannot be sealed by "
                        f"its methods' visibility, because another crate can still "
                        f"*implement* it -- which would let an external adapter bundle "
                        f"enter the registry."
                    )
        if not found_wide and not any(
            re.search(rf"^pub\(crate\) {kind} {item}\b", _code_of(os.path.join(dp, n)), re.M)
            for dp, _dn, fns in os.walk(base)
            for n in fns
            if n.endswith(".rs")
        ):
            problems.append(f"{crate}: `{item}` is not declared at all; the sealed surface moved.")
    return problems


def _code_of(path: str) -> str:
    src = open(path, encoding="utf-8").read()
    return rustscan.code_only(src, rustscan.code_mask(src))


# A public function that *returns a type* -- `-> Self` or `-> TypeName` -- and does not
# take a bare `self`. Getters are excluded because a method on an existing value is not
# a way to obtain one.
_CTOR_RE = re.compile(
    r"pub (?:const )?fn (\w+)\s*\(([^)]*)\)\s*(?:->\s*([^;{]*?))?\s*\{",
    re.S,
)


def _public_constructors(code: str) -> list[tuple[str, str, str, str]]:
    """``(owner, fn, params, return_type)`` for every public constructor in ``code``."""
    out: list[tuple[str, str, str, str]] = []
    for m in re.finditer(r"impl(?:<[^>]*>)?\s+(\w+)", code):
        owner = m.group(1)
        start = code.find("{", m.end() - 1)
        if start == -1:
            continue
        depth = 0
        end = -1
        for i in range(start, len(code)):
            if code[i] == "{":
                depth += 1
            elif code[i] == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end == -1:
            continue
        body = code[start:end]
        for ctor in _CTOR_RE.finditer(body):
            fn, params, ret = ctor.group(1), ctor.group(2), (ctor.group(3) or "").strip()
            if ret == "Self":
                ret = owner
            if not ret or ret not in {owner}:
                continue
            if "self" in {a.strip() for a in params.split(",")}:
                continue
            out.append((owner, fn, params, ret))
    return out


# --------------------------------------------------------------------------
# G3 -- the platform boundary
# --------------------------------------------------------------------------

# Crates that exist to hold platform implementations.
PLATFORM_CRATE_PREFIX = "orxnud-platform-"


def platform_violations(root: str, sources: list[str]) -> list[Violation]:
    """Platform-specific constructs outside the designated platform crates."""
    out: list[Violation] = []
    for path in sources:
        crate = crate_of(path, root)
        if crate.startswith(PLATFORM_CRATE_PREFIX):
            continue
        src = open(path, encoding="utf-8").read()
        production = rustscan.strip_test_only(src)
        for line, what in rustscan.platform_constructs(production):
            out.append(Violation(path, line, what))
    return out


# --------------------------------------------------------------------------
# G16 -- the migration snapshot path is not optional in production
# --------------------------------------------------------------------------

#: Where `migrate_ephemeral` is allowed to appear in production code, and how many times.
#:
#: Exemptions are counted, not located, so that any addition fails the gate. A line-number
#: exemption would go stale on the first unrelated edit and then quietly permit whatever
#: landed in its place; a count cannot be satisfied by a new call site.
#:
#: * `orxnud-store/src/migration.rs` -- two. The `fn` itself, and the one call inside
#:   `MigrationRunner::migrate`. That internal call is the safe path *executing* its own
#:   apply step after it has already taken and verified a snapshot, so it is not a second
#:   way in; it is the first way in, and it cannot be reached without the snapshot.
#: * `orxnud-task/src/conformance/power_loss.rs` -- one. The TP-7 victim, which is killed at
#:   an arbitrary instruction and whose entire point is that nothing survives it. A
#:   snapshot taken there would have to outlive a `SIGKILL`.
MIGRATION_EPHEMERAL_EXEMPTIONS = {
    os.path.join("crates", "orxnud-store", "src", "migration.rs"): 2,
    os.path.join("crates", "orxnud-task", "src", "conformance", "power_loss.rs"): 1,
}


def migration_violations(root: str, sources: list[str]) -> list[Violation]:
    """Production calls to `MigrationRunner::migrate_ephemeral`.

    # Why a source check and not a test

    The property is "production code reaches the schema only through the path that snapshots
    first". No behavioural test can observe that, because both paths end in the same
    migrations and the same `schema_meta`; the difference is entirely *which function was
    called*, and a test that ran the wrong one would see the same database. This is the
    same reasoning as `no_refusal_is_constructed_after_a_process_exists` in
    `orxnud-platform-sandbox/src/linux.rs`: the thing to check is control flow that no
    execution can be made to reach.

    # Why this method had to exist at all

    `MigrationRunner::run(&self, snapshot_verified: bool)` (S-11/F-26) took no snapshot and
    restored nothing; it refused only when the boolean was false, so `run(true)` -- what
    production actually called, twice, for the audit journal and the approval ledger --
    applied every migration unprotected. A boolean that names its own safety is not a
    safety mechanism. Replacing it with `migrate_ephemeral` is only an improvement if
    reaching it is *disallowed* rather than discouraged, which is what this gate does.

    # How production code is found

    Comments and string literals are blanked first (`code_only`), then `#[cfg(test)]`
    regions (`strip_test_only`). Both steps preserve length, so a match maps back to the
    line it was written on. Blanking comments is what lets the module documentation name
    this method freely while the gate still reports only real code.
    """
    out: list[Violation] = []
    for path in sources:
        src = open(path, encoding="utf-8").read()
        code = rustscan.code_only(src, rustscan.code_mask(src))
        production = rustscan.strip_test_only(code)
        rel = os.path.relpath(path, root)
        found = [
            rustscan.line_of(production, at)
            for m in production_matcher.finditer(production)
            for at in [m.start()]
        ]
        if not found:
            continue
        allowed = MIGRATION_EPHEMERAL_EXEMPTIONS.get(rel, 0)
        if len(found) > allowed:
            extra = ", ".join(str(n) for n in found[allowed:]) or "-"
            out.append(
                Violation(
                    path,
                    found[allowed],
                    "production code reaches `MigrationRunner::migrate_ephemeral`, which "
                    "applies schema changes with no verified snapshot and no rollback. "
                    f"{len(found)} occurrence(s) here, {allowed} allowed; the unallowed "
                    f"one(s) start at line(s) {extra}. Use "
                    "`MigrationRunner::migrate(path)`, which takes and verifies its own "
                    "snapshot and hands back a recovery obligation on failure.",
                )
            )
    return out


production_matcher = re.compile(r"migrate_ephemeral")

#: Schema-changing SQL. Deliberately not a keyword search over the whole file: the point
#: is to catch *production source* that applies DDL, and the two legitimate places that
#: do it are `migration.rs` (the migrations themselves) and `test_support` (behind a
#: feature that a shipped build does not have).
#:
#: Measured before this rule existed: the workspace contained **zero** occurrences in
#: production source. There is nothing to exempt today, so nothing is exempted, and a
#: first offence is a real offence rather than a known exception.
def strip_comments_only(src: str) -> str:
    """Blank Rust comments, leaving string literals intact.

    # Why this exists and why it is not `rustscan.code_only`

    This gate looks for schema DDL, and in Rust **DDL is always a string literal** --
    you execute it as `conn.execute_batch("CREATE TABLE ...")`. `code_only`, which
    blanks comments *and* string literals, therefore blanks the very thing being
    searched for, and the rule silently matched nothing.

    That was found by the negative control, not by reading: the first injected
    production `CREATE TABLE` passed the gate. A gate that cannot fail is worse than
    no gate, so the check is only trusted once it has been observed to fail.

    This is a small scanner rather than a change to `rustscan.py` because
    `rustscan`'s job is the opposite one -- deciding what is *code* for the platform
    and authority gates, where blanking strings is correct.
    """
    out = list(src)
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == '"':
            # Skip a string literal. Raw strings need the hash count.
            hashes = 0
            j = i - 1
            while j >= 0 and src[j] == "#":
                hashes += 1
                j -= 1
            if j >= 0 and src[j] in "rRbB" and (j == 0 or src[j - 1] != "\\"):
                term = '"' + "#" * hashes
                k = src.find(term, i + 1)
                i = n if k == -1 else k + len(term)
            else:
                k = i + 1
                while k < n:
                    if src[k] == "\\":
                        k += 2
                        continue
                    if src[k] == '"':
                        break
                    k += 1
                i = min(k + 1, n)
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            k = src.find("\n", i)
            k = n if k == -1 else k
            for x in range(i, k):
                out[x] = " "
            i = k
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            depth = 1
            k = i + 2
            while k < n and depth:
                if src.startswith("/*", k):
                    depth += 1
                    k += 2
                elif src.startswith("*/", k):
                    depth -= 1
                    k += 2
                else:
                    k += 1
            for x in range(i, min(k, n)):
                out[x] = " "
            i = k
            continue
        i += 1
    return "".join(out)


SCHEMA_DDL = re.compile(
    r"\b(?:CREATE\s+(?:TEMP\s+|TEMPORARY\s+|UNIQUE\s+|VIRTUAL\s+)?(?:TABLE|INDEX|TRIGGER|VIEW)"
    r"|ALTER\s+TABLE"
    r"|DROP\s+(?:TABLE|INDEX|TRIGGER|VIEW))\b",
    re.IGNORECASE,
)

#: Production files permitted to contain schema DDL, each for a stated reason.
#:
#: Two, and neither is "this file is special":
#:
#: * `schema.rs` **is** the schema. Its `MIGRATION_*` constants hold the DDL as
#:   *data*; nothing executes them here. They are `pub(crate)` since the S-11
#:   change, so the only consumer in the workspace is `migration.rs`, which runs
#:   them through `migrate_ephemeral` inside a per-migration transaction.
#: * `power_loss.rs` is the TP-7 crash-test **victim**. It calls
#:   `migrate_ephemeral` — already an explicit G16 exemption, for the same reason:
#:   the process is about to be `SIGKILL`ed, so a snapshot taken at that moment
#:   could not survive to be useful. The `CREATE TABLE tp7_tasks` below is that
#:   victim's own scratch table in a database that is about to be killed; it is
#:   not part of the product schema and nothing else references it.
#:
#: Every other file must be free of DDL. Measured before this rule existed:
#: `schema.rs` and `power_loss.rs` were the only production sources containing any.
SCHEMA_DDL_EXEMPT = {
    os.path.join("crates", "orxnud-store", "src", "migration.rs"),
    os.path.join("crates", "orxnud-store", "src", "schema.rs"),
    os.path.join("crates", "orxnud-task", "src", "conformance", "power_loss.rs"),
}


def ddl_violations(root: str, sources: list[str]) -> list[Violation]:
    """Production source that applies schema-changing SQL outside the migrations.

    # Why the API narrowing is not enough

    Narrowing `MIGRATIONS` and the `schema::MIGRATION_*` constants removes the route
    that hands out the DDL as data. It does not remove a caller who writes its own
    `CREATE TABLE`, and `orxnud-store` publishes `rusqlite::Connection` values
    (`Store::conn()` and friends), so one is reachable. This is the second layer, and
    the ordering matters: the API is the control and this is the check that the control
    has not been routed around.

    A keyword search cannot distinguish DDL *about this schema* from DDL in some
    unrelated embedded database, so it would produce false positives. The alternative
    would be to accept the false positives and maintain an exemption list, which is
    how a gate becomes a list of known mistakes. The measurement above decided it: zero
    production DDL today, so the rule starts empty.
    """
    out: list[Violation] = []
    for path in sources:
        rel = os.path.relpath(path, root)
        if rel in SCHEMA_DDL_EXEMPT:
            continue
        text = open(path, encoding="utf-8").read()
        production = strip_comments_only(rustscan.strip_test_only(text))
        for m in SCHEMA_DDL.finditer(production):
            out.append(
                Violation(
                    path,
                    rustscan.line_of(production, m.start()),
                    "production source applies schema-changing SQL "
                    f"(`{m.group(0)}`). Every production schema change must go through "
                    "`MigrationRunner::migrate(path)`, which takes and verifies a "
                    "snapshot first and hands back a recovery obligation on failure. "
                    "This crate publishes `Connection` values, so writing DDL here is "
                    "reachable and unprotected.",
                )
            )
    return out


def migration_surface_drift(root: str) -> list[str]:
    """Whether the surface this gate depends on still has the shape it was written for.

    A gate that cannot fail is worse than no gate, so it is asserted against drift: the
    method must still exist (otherwise the gate would pass on a tree where the ephemeral
    path was renamed away and the guarantee silently moved somewhere unchecked), and the
    exempt sites must still be present, because an exemption nobody calls is a hole waiting
    for the next caller.
    """
    out: list[str] = []
    migration = os.path.join(root, "crates", "orxnud-store", "src", "migration.rs")
    src = open(migration, encoding="utf-8").read()
    if "pub fn migrate_ephemeral(&self)" not in rustscan.code_only(
        src, rustscan.code_mask(src)
    ):
        out.append(
            "MigrationRunner::migrate_ephemeral is gone. If it was renamed, this gate is "
            "checking a name nobody can call and the guarantee it protects has moved; if "
            "it was removed because the ephemeral path was eliminated, delete this gate in "
            "the same commit rather than leaving it green."
        )
    if "pub fn run(&self, snapshot_verified: bool)" in rustscan.code_only(
        src, rustscan.code_mask(src)
    ):
        out.append(
            "MigrationRunner::run(&self, snapshot_verified: bool) is back. That is the "
            "S-11/F-26 trust-me API: it snapshots nothing and refuses only on `false`."
        )
    return out


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def report(name: str, violations: list[Violation], root: str) -> int:
    if violations:
        for v in violations:
            print(f"   {v.render(root)}")
        print(f"FAIL  {name}: {len(violations)} violation(s)", file=sys.stderr)
        return 1
    return 0


def all_rust_sources(root: str) -> list[str]:
    """Every Rust file under ``crates/``, tests included.

    G4 is about the *keyword*, and the keyword is just as much a declaration in a
    test file as anywhere else, so this gate does not narrow to production
    sources the way the authority gates do.
    """
    out: list[str] = []
    crates = os.path.join(root, "crates")
    for dirpath, _dirnames, filenames in os.walk(crates):
        for name in sorted(filenames):
            if name.endswith(".rs"):
                out.append(os.path.join(dirpath, name))
    return out


def unsafe_violations(root: str) -> list[Violation]:
    """Every use of the ``unsafe`` keyword outside the platform crates.

    Only **code** counts. A string literal or a comment that happens to contain
    the word is prose, not a declaration -- and every other gate in this file
    already works that way; G3 says so in its own documentation. This gate used a
    shell ``grep`` over raw text, so it flagged ordinary sentences, including
    the word inside a diagnostic message, and treated them as unsafe code.

    The rule itself is unchanged: the keyword may appear only in the
    ``orxnud-platform-*`` crates, where the platform work belongs.
    """
    out: list[Violation] = []
    for path in all_rust_sources(root):
        if crate_of(path, root).startswith("orxnud-platform-"):
            continue
        code = _code_of(path)
        for m in re.finditer(r"\bunsafe\b", code):
            out.append(
                Violation(
                    path,
                    rustscan.line_of(code, m.start()),
                    "uses the `unsafe` keyword",
                )
            )
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "gate", choices=["g2d", "g3", "g3-platform-crates", "g4", "g16", "g17"]
    )
    ap.add_argument(
        "--root",
        default=None,
        help="repository root; defaults to the parent of this script's directory. The "
        "self-test points this at a fixture tree.",
    )
    args = ap.parse_args(argv)

    root = os.path.abspath(args.root) if args.root else os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
    sources = production_sources(root)

    if args.gate == "g2d":
        drift = check_authority_surface(root)
        if drift:
            for d in drift:
                print(f"   {d}")
            print(
                "FAIL  G2d: the authority surface has changed. This is a "
                "decision, not a formality: re-read the invariant and update the gate.",
                file=sys.stderr,
            )
            return 1
        return report(
            "G2d: a policy-seal symbol is reachable outside orxnud-policy in production code",
            authority_violations(root, sources),
            root,
        )

    if args.gate == "g16":
        drift = migration_surface_drift(root)
        if drift:
            for d in drift:
                print(f"   {d}")
            print(
                "FAIL  G16: the migration surface has changed. This is a decision, not a "
                "formality: re-read ADR-0017 and update the gate.",
                file=sys.stderr,
            )
            return 1
        both = migration_violations(root, sources) + ddl_violations(root, sources)
        both.sort(key=lambda v: (v.path, v.line))
        return report(
            "G16: production code can change the schema outside the snapshotting path",
            both,
            root,
        )

    if args.gate == "g17":
        both = (
            unguarded_open_violations(root, sources)
            + unchecked_lease_violations(root, sources)
            + unguarded_recovery_write_violations(root, sources)
        )
        both.sort(key=lambda v: (v.path, v.line))
        if _APPLIED_EXEMPTIONS:
            print("   intentional omissions (opens of a file that is not the database):")
            for note in sorted(_APPLIED_EXEMPTIONS):
                print(f"     {note}")
        return report(
            "G17: production code bypasses the recovery-aware opening boundary",
            both,
            root,
        )

    if args.gate == "g4":
        return report(
            "G4: unsafe appears outside orxnud-platform-*",
            unsafe_violations(root),
            root,
        )

    if args.gate == "g3":
        return report(
            "G3: a platform branch exists outside orxnud-platform-*",
            platform_violations(root, sources),
            root,
        )

    # g3-platform-crates: how many crates are exempt, and which. Reported so the
    # exemption list is visible rather than implicit in a prefix match.
    exempt = sorted(
        {crate_of(p, root) for p in sources} - {""}
    )
    exempt = [c for c in exempt if c.startswith(PLATFORM_CRATE_PREFIX)]
    print(f"   platform crates exempt from G3: {' '.join(exempt)}")
    return 0




# --------------------------------------------------------------------------
# G17 -- every production SQLite open is recovery-aware
# --------------------------------------------------------------------------

#: Production files allowed to open a file-backed database without going through the
#: recovery-aware ownership boundary. **Not a filename blacklist**: each entry is a
#: *narrowly justified* site, and the rule is otherwise "no file-backed open outside
#: ownership".
#:
#: * `ownership.rs` acquires the lease; it is the boundary, not a user of it.
#: * `recovery.rs` completes a restore and must therefore install into the live database
#:   while holding the lease it already took. It never opens without one.
#:
#: `security_state.rs` and `sqlite.rs` are **deliberately absent**: they look like
#: candidates and are the reason this gate exists. Both call
#: `ownership::acquire_shared` first, which is the boundary.
#:
#: * `power_loss.rs` is the TP-7 **crash verifier**. It opens the file a child process was
#:   `SIGKILL`ed on, to check that what survived is coherent. Holding a lease is not just
#:   unnecessary there but wrong: the point is to inspect the state a *dead* owner left, and
#:   a lease taken over a database with no live owner would be indistinguishable from a
#:   live owner. Its build scope was verified rather than assumed: `verify_file_coherent`
#:   is reached only from the victim/verifier paths in that module, whose own `migrate_ephemeral`
#:   and DDL are already declared G16 exemptions on the same grounds.
OPEN_EXEMPT = {
    os.path.join("crates", "orxnud-store", "src", "ownership.rs"),
    os.path.join("crates", "orxnud-store", "src", "recovery.rs"),
    os.path.join("crates", "orxnud-task", "src", "conformance", "power_loss.rs"),
}

#: A file-backed `Connection::open*` / `Store::open`. `:memory:` and the test-support
#: helpers are excluded by the surrounding expressions.
_FILE_OPEN = re.compile(
    r"(?:Connection|rusqlite::Connection)::open(?:_with_flags\w*)?\s*\("
)



def strip_cfg_test_fns(src: str, count_src: str | None = None) -> str:
    """Blank the bodies of `#[test]`- and `#[cfg(test)]`-attributed items.

    # How this works

    Structure is taken from :func:`rustscan.delimiter_matches`, which pairs delimiters
    with a stack over the *code* characters of the source. Strings, raw strings, byte
    strings, char literals, lifetimes and comments are excluded by the lexer, so a
    brace inside any of them cannot shift a match.

    Every blank is an offset-length-preserving replacement
    (:func:`rustscan.blank_range`), so the offsets used later in the pass still point
    at the same characters, and the code outside the blanked item is untouched
    byte-for-byte.

    # Which item an attribute applies to

    The item is found from the text that **immediately follows** the attribute, by
    :func:`rustscan.attributed_item_span`. It is not found by searching forwards for
    an item keyword.

    That distinction is the whole point, and it was a real defect. The previous rule
    searched for the next ``fn``/``mod``/``impl``/... and took the body after it, so
    an attribute whose item was *not* one of those keywords -- a ``use`` item, a macro
    invocation, a statement -- was silently attributed to a **later, unrelated** item,
    whose body was then blanked. In ``crates/orxnud-store/src/backup.rs`` the line
    ``#[cfg(test)] use std::cell::RefCell;`` sits immediately above ``impl Backup {
    ... }``; the keyword search skipped the ``use`` item, found ``impl``, and blanked
    the whole block -- 608 lines of production code, including every
    ``Connection::open`` in it -- out of gate **G17**'s view. The gate was not
    checking that file at all, and nothing said so.

    # Why the previous implementations were wrong

    * Counting braces over already-stripped text lost structural braces and
      desynchronised, blanking 2002 of 2446 lines of `backup.rs`.
    * Counting braces over pristine text stopped early on `use super::{A, b};`, a
      balanced group that opens and closes on one line, so the six test-only opens in
      `runtime.rs` were reported as production.
    * Matching by indentation blanked *production* code adjacent to a test item, which
      hid a synthetic `acquire_exclusive_unchecked` route in `backup.rs` from G17.
    * Searching forwards for an item keyword attributed an attribute to the *wrong*
      item whenever the item it applied to was not a keyword -- a `use`, a macro
      invocation, or a statement -- and blanked that later item's body instead.

    The lexer that feeds this was itself wrong for a long time: `_RAW_PREFIX` omitted
    the standalone `r` prefix, and the raw-string terminator was built as a quote, the
    hashes and *another* quote -- a three-character sequence that never occurs, so the
    search for it always failed and the token ran to the end of the file. 216,876
    characters of `runtime.rs` were classified as string content as a result. Both are
    fixed and covered by `rustscan`'s own self-tests.

    # Failure behaviour

    If an attribute is recognised but no item body can be located, only the attribute
    itself is blanked. Blanking too little risks a false positive, which is visible
    and cheap; blanking too much hides production code, which is the dangerous
    direction.
    """
    _ = count_src
    code = rustscan.code_mask(src)
    edits: list[tuple[int, int]] = []

    def blank(a: int, b: int) -> None:
        a = max(0, a)
        b = min(len(src), b)
        if b > a:
            edits.append((a, b))

    for m in _TEST_ATTR.finditer(src):
        if not all(code[m.start():m.end()]):
            continue
        span = rustscan.attributed_item_span(src, code, m.end())
        if span is None:
            # No item could be located. Blank the attribute alone: a false positive
            # is visible and cheap, a hidden production open is not.
            blank(m.start(), m.end())
            continue
        blank(m.start(), span[1])
    for a_, b_ in sorted(edits, reverse=True):
        src = rustscan.blank_range(src, a_, b_)
    return src


#: A test-only attribute: `#[test]`, or `#[cfg(...)]` whose predicate mentions `test`.
_TEST_ATTR = re.compile(r"#\[\s*(?:test|cfg\s*\([^\]]*\btest\b[^\]]*\))\s*\]")


def production_view(text: str) -> str:
    """``text`` with comments stripped and every test-only item removed.

    The single entry point every G17 rule must use. Comments go because a commented-out
    `Connection::open` must not count as an open; test items go because a test's
    database is not a production one. Strings are deliberately *kept*: they are where
    the SQL DDL lives, and the DDL gate needs them.
    """
    return rustscan.strip_test_only(strip_cfg_test_fns(strip_comments_only(text)))


#: How far above an open to look for the ownership acquisition that makes it legitimate.
#: The pattern the tree actually uses is `acquire_shared` then `Connection::open` on the
#: next few lines, so this is a window rather than a scope analysis. It is lexical and can
#: be fooled by an acquisition in an unrelated statement; the trade is accepted because a
#: scope-accurate version needs a real parser, and the gate is defence in depth rather than
#: the primary control.
_ACQUIRE_WINDOW = 12

_ACQUIRE = re.compile(r"ownership::acquire_(?:shared|exclusive)|(?:^|[^:])acquire_(?:shared|exclusive)\s*\(")


#: The internal lease acquisitions that skip the recovery check by design.
_UNCHECKED = re.compile(r"acquire_(?:shared|exclusive)_unchecked")

#: The recovery operations that write: they publish an intent, install staged content
#: into the live database, or clear the recovery state.
#:
#: These are `pub(crate)` in the Rust source, so the compiler already refuses an
#: out-of-crate call. This rule is the *second* half of the boundary: it refuses an
#: in-crate call from a module that does not hold the exclusive ownership the
#: operation requires. `backup.rs` calls them under a `RestoreGuard`, which holds
#: the exclusive lease; `recovery.rs` calls them under the exclusive lease it takes
#: itself.
_WRITE_CALLS = re.compile(r"\b(?:install_staged|publish_intent|clear_intent)\b")

#: The modules permitted to call the recovery write operations, and why.
_WRITE_EXEMPT = {
    # Where they are defined.
    os.path.join("crates", "orxnud-store", "src", "recovery.rs"),
    # The restore path, which runs under a `RestoreGuard` holding the exclusive lease.
    os.path.join("crates", "orxnud-store", "src", "backup.rs"),
}

#: Production files allowed to use them. `recovery.rs` only -- it is the mechanism that
#: exists in order to complete a restore without recursing into the check.
_UNCHECKED_EXEMPT = {
    # Where they are *defined*; calling them from here is the whole point of the module.
    os.path.join("crates", "orxnud-store", "src", "ownership.rs"),
    # The only module permitted to *call* them.
    os.path.join("crates", "orxnud-store", "src", "recovery.rs"),
}


def unchecked_lease_violations(root: str, sources: list[str]) -> list[Violation]:
    """Production use of a lease acquisition that bypasses the recovery-intent check.

    # Why this is a separate rule

    G17's first rule proves a production open cannot skip **ownership**. It does not by
    itself prove an open cannot skip **recovery**: `acquire_*_unchecked` takes the lease
    with the recovery check deliberately skipped, and any production caller other than the
    recovery mechanism itself would be able to take a lease and open a half-restored
    database without ever consulting the intent.

    The two properties are distinct, and only the first was checked. This is the second,
    and it is structural rather than runtime: `_unchecked` is `pub(crate)`, and this gate
    confines it to the one module that must use it.
    """
    out: list[Violation] = []
    for path in sources:
        rel = os.path.relpath(path, root)
        if rel in _UNCHECKED_EXEMPT:
            continue
        text = open(path, encoding="utf-8").read()
        production = production_view(text)
        for m in _UNCHECKED.finditer(production):
            line = rustscan.line_of(production, m.start())
            out.append(
                Violation(
                    path,
                    line,
                    "production code takes a lease with the recovery-intent check skipped. "
                    "`acquire_*_unchecked` exists only so `recovery.rs` can complete a "
                    "restore without recursing into the check that triggered it; any other "
                    "caller can take a lease and open a database whose restore intent was "
                    "never consulted.",
                )
            )
    return out


def unguarded_recovery_write_violations(
    root: str, sources: list[str]
) -> list[Violation]:
    """Production calls to the recovery write operations outside the guarded modules.

    # Why this is a rule and not a comment

    `install_staged` overwrites the live database, `publish_intent` publishes the
    record that authorises doing so, and `clear_intent` removes it. They are
    `pub(crate)`, so a dependent crate cannot reach them -- but an *in-crate* module
    can, and a call from a module that does not hold the exclusive lease would write
    to a live database with nothing coordinating it. Visibility alone does not
    establish that; this does.
    """
    out: list[Violation] = []
    for path in sources:
        rel = os.path.relpath(path, root)
        if rel in _WRITE_EXEMPT:
            continue
        text = open(path, encoding="utf-8").read()
        production = production_view(text)
        for m in _WRITE_CALLS.finditer(production):
            line = rustscan.line_of(production, m.start())
            out.append(
                Violation(
                    path,
                    line,
                    "production code calls a recovery write operation "
                    "(`install_staged`, `publish_intent` or `clear_intent`) outside the "
                    "modules that hold the exclusive lease. These modify the live "
                    "database or the intent that authorises modifying it, and the "
                    "coordination they require is the exclusive ownership lease.",
                )
            )
    return out


#: Opens of a file that is **not** the database the ownership boundary protects.
#:
#: Keyed by ``(relative path, the path expression passed to ``open``)``. The
#: expression is matched exactly, with whitespace collapsed, so a rename breaks the
#: exemption loudly rather than silently widening it.
#:
#: # Why these exist at all
#:
#: G17's rule is "no production open of a file-backed database outside the
#: ownership boundary", and its purpose is narrower: *the live database* must not be
#: opened without the recovery-aware lease, because an open that skips ownership can
#: serve a half-restored database.
#:
#: The sites below open **copies** of the database -- the pre-migration snapshot and
#: the staging files the snapshot and the restore are written through. They are
#: created by this crate, they are not under ownership, they have no restore intent,
#: and their integrity is established by the snapshot verification and the
#: staged-digest comparison rather than by the ownership lease. Taking the *live*
#: database's lease over them would be wrong: the restore path already holds that
#: lease exclusively, and ``flock`` conflicts between open file descriptions even
#: within one process (S-31).
#:
#: # Why the exemption is per-site and not per-file
#:
#: A file-level exemption would switch off the rule for every open in that file,
#: including a future open of the *live* database there -- which is exactly the kind
#: of hole this gate exists to close. A per-site exemption keeps the file under
#: the rule: the live database's path expression (``db_path``) is **not** among
#: these, so an open of it in the same file is still refused.
#:
#: The scanner fix that made these visible is in ``rustscan.attributed_item_span``:
#: before it, ``#[cfg(test)] use std::cell::RefCell;`` in ``backup.rs`` caused the
#: whole ``impl Backup`` block to be blanked out of the gate's view, and G17 had
#: never seen this file at all.
_DERIVED_OPEN_EXEMPT: dict[tuple[str, str], str] = {
    (
        os.path.join("crates", "orxnud-store", "src", "backup.rs"),
        "dst_path",
    ): "the snapshot staging file this crate is writing, not the database",
    (
        os.path.join("crates", "orxnud-store", "src", "backup.rs"),
        "path",
    ): "the published pre-migration snapshot, verified before it is used",
    (
        os.path.join("crates", "orxnud-store", "src", "backup.rs"),
        "&self.path",
    ): "the published pre-migration snapshot, verified before it is used",
    (
        os.path.join("crates", "orxnud-store", "src", "backup.rs"),
        "&staging",
    ): "the restore staging file, digest-compared against the snapshot",
}


#: The exemptions the last G17 run actually applied, one line each.
#:
#: An exemption that is not visible is an exemption nobody can review. The gate
#: prints these, so the omissions it makes are stated rather than implied.
_APPLIED_EXEMPTIONS: list[str] = []


def _open_path_expression(view: str, paren_idx: int) -> str | None:
    """The text passed to ``Connection::open(...)``, with whitespace collapsed.

    ``paren_idx`` is the index of the ``(`` that opens the argument list. ``None``
    means the argument list could not be delimited, which the caller treats as "not
    exempt": an exemption that cannot be matched exactly is not applied.
    """
    if paren_idx < 0 or paren_idx >= len(view) or view[paren_idx] != "(":
        return None
    code = rustscan.code_mask(view)
    matches = rustscan.delimiter_matches(view, code)
    close = matches.get(paren_idx)
    if close is None:
        return None
    return " ".join(view[paren_idx + 1 : close].split())


def unguarded_open_violations(root: str, sources: list[str]) -> list[Violation]:
    """Production opens of a file-backed database that bypass the ownership boundary.

    # Why this is needed at all

    `recovery::complete_outstanding_restore` runs inside
    `ownership::acquire_shared`/`acquire_exclusive`, so a database with an outstanding
    restore intent is never handed out usable. That guarantee is only as good as the
    claim that **every** production open goes through those two functions -- a claim that
    was found to be false once already, when `Store::open` was assumed to be the only
    route and `SqliteAuditJournal::open` and `SqliteApprovalLedger::open` turned out to
    open their own connections. A gate that cannot fail is not a gate, so this checks the
    claim rather than repeating it.

    # What it does and does not prove

    It proves that this workspace's production sources contain no file-backed SQLite open
    outside the two exempt modules. It does **not** prove runtime correctness of the
    recovery protocol; that is the protocol's own tests. This is defence in depth.
    """
    out: list[Violation] = []
    _APPLIED_EXEMPTIONS.clear()
    for path in sources:
        rel = os.path.relpath(path, root)
        if rel in OPEN_EXEMPT:
            continue
        text = open(path, encoding="utf-8").read()
        production = production_view(text)
        for m in _FILE_OPEN.finditer(production):
            line = rustscan.line_of(production, m.start())
            snippet = production.split("\n")[line - 1].strip()
            # `:memory:` is not a file; it has no path, no sidecars and nothing to recover.
            if "memory" in snippet:
                continue
            # A documented exemption for an open of a file that is not the database
            # the ownership boundary protects. Checked *before* the lease window, so
            # the exemption does not depend on how the open is spelled.
            expression = _open_path_expression(production, m.end() - 1)
            if expression is not None:
                reason = _DERIVED_OPEN_EXEMPT.get((rel, expression))
                if reason is not None:
                    _APPLIED_EXEMPTIONS.append(
                        f"{rel}:{rustscan.line_of(text, m.start())}: {expression} -- {reason}"
                    )
                    continue
            # The legitimate pattern: take the lease, then open. `Store::open` already
            # does both; a direct open is fine when a lease was taken just above it.
            window = "\n".join(production.split("\n")[max(0, line - 1 - _ACQUIRE_WINDOW) : line])
            if _ACQUIRE.search(window):
                continue
            out.append(
                Violation(
                    path,
                    line,
                    "production source opens a file-backed SQLite database directly. An "
                    "outstanding restore intent is only honoured because "
                    "`ownership::acquire_shared`/`acquire_exclusive` check for it, so an "
                    "open that skips ownership can serve a half-restored database. Take "
                    "the lease first (`Store::open`, or `acquire_shared` followed by "
                    "`Connection::open`).",
                )
            )
    return out


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))