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
# Reporting
# --------------------------------------------------------------------------


def report(name: str, violations: list[Violation], root: str) -> int:
    if violations:
        for v in violations:
            print(f"   {v.render(root)}")
        print(f"FAIL  {name}: {len(violations)} violation(s)", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("gate", choices=["g2d", "g3", "g3-platform-crates"])
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


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))