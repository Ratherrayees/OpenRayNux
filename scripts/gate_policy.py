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

# Crates allowed to reference the authority types at all.
#
# orxnud-domain *defines* them. orxnud-policy is the only authoriser by definition.
# Naming `CapabilityInvocation` as a parameter type is legitimate elsewhere -- a
# capability crate receives an invocation and cannot construct one -- so the invariant is
# about minting, which requires naming `PolicySeal`.
EXEMPT_CRATES = frozenset({"orxnud-domain", "orxnud-policy"})

# The authority surface, asserted rather than trusted. `check_authority_surface` verifies
# each of these against the domain source and fails if the domain has moved.
EXPECTED_SEAL_TYPE = "PolicySeal"
EXPECTED_SEAL_GATED = (
    ("AuthorisationProof", "issue"),
    ("CapabilityInvocation", "authorise"),
)
# Every public constructor the seal is allowed to have. More than one would be a second
# way to obtain authority from nothing.
EXPECTED_SEAL_CONSTRUCTORS = frozenset({"attest"})
# Identifiers that mint authority. `authorise` alone catches the method-call form,
# `Type::fn` and `use Type::fn; fn(..)`.
MINTING_VERBS = ("attest", "authorise", "issue")


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
            if ident == EXPECTED_SEAL_TYPE:
                out.append(
                    Violation(
                        path,
                        line,
                        f"references {EXPECTED_SEAL_TYPE}, the root of the authority "
                        f"chain: anything holding one can authorise a capability",
                    )
                )
            elif ident in MINTING_VERBS:
                out.append(
                    Violation(
                        path,
                        line,
                        f"calls `{ident}`, which mints authority or its proof",
                    )
                )
    return out


_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def check_authority_surface(root: str) -> list[str]:
    """Re-derive the authority chain from the domain source; report any drift.

    A gate whose forbidden list is a hand-maintained constant decays: someone adds a
    constructor, nobody edits the gate, and the gate keeps passing. So this derives the
    chain and asserts it.

    The derivation is the **closure of the seal**, not "anything that looks like
    authority". Starting from ``PolicySeal``, follow every public constructor in
    ``orxnud-domain`` that takes a type already in the set and returns a type; that type
    joins the set. Today the closure is exactly ``{PolicySeal, AuthorisationProof,
    CapabilityInvocation}``, which is the chain the gate forbids.

    Three things this asserts, and each fails loudly:

    1. the seal type exists and is public;
    2. every public constructor of the seal is an expected one -- so a second
       constructor *on the seal itself* is caught, since that would be a new way to
       obtain authority from nothing; and
    3. the closure is exactly the expected set -- so a new seal-gated path, at any
       depth, is caught.

    # What this deliberately cannot detect

    A *brand-new, unrelated* public type in ``orxnud-domain`` with a public constructor
    taking no seal at all. Nothing distinguishes that from an ordinary new domain type
    such as ``TaskId`` -- guessing would mean flagging every constructor in the crate,
    which is noise a reviewer learns to skip, and a gate that cries wolf is a gate that
    gets disabled. Introducing a new authority type is a design decision and is required
    to come through an ADR; this gate's job is to notice when the *existing* chain
    changes shape underneath it.
    """
    problems: list[str] = []
    domain = os.path.join(root, "crates", "orxnud-domain", "src")
    if not os.path.isdir(domain):
        return [f"orxnud-domain source not found at {domain}"]

    ctors: list[tuple[str, str, str, str]] = []  # (owner, fn, params, returns)
    structs: set[str] = set()
    for dirpath, _dirnames, filenames in os.walk(domain):
        for name in sorted(filenames):
            if not name.endswith(".rs"):
                continue
            code = _code_of(os.path.join(dirpath, name))
            structs |= set(re.findall(r"pub struct (\w+)", code))
            ctors.extend(_public_constructors(code))

    if EXPECTED_SEAL_TYPE not in structs:
        problems.append(
            f"orxnud-domain: `{EXPECTED_SEAL_TYPE}` is missing. The gate's entire "
            f"invariant rests on it being the root of the authority chain."
        )
        return problems

    # (2) The seal's own constructors.
    seal_ctors = sorted(fn for owner, fn, _p, _r in ctors if owner == EXPECTED_SEAL_TYPE)
    expected_seal_ctors = EXPECTED_SEAL_CONSTRUCTORS
    unexpected = [fn for fn in seal_ctors if fn not in expected_seal_ctors]
    if unexpected:
        problems.append(
            f"orxnud-domain: {EXPECTED_SEAL_TYPE} gained a public constructor "
            f"{unexpected}. A second way to obtain the seal is a second root of "
            f"authority, and the gate's whole model stops holding."
        )

    # (3) The closure.
    closure = {EXPECTED_SEAL_TYPE}
    changed = True
    while changed:
        changed = False
        for owner, _fn, params, ret in ctors:
            if owner in closure:
                continue
            takes_seal = any(f"&{t}" in params for t in closure)
            if takes_seal and ret:
                closure.add(ret)
                changed = True

    expected = {EXPECTED_SEAL_TYPE} | {t for t, _ in EXPECTED_SEAL_GATED}
    for extra in sorted(closure - expected):
        problems.append(
            f"orxnud-domain: `{extra}` is reachable from the seal and so is authority, "
            f"but the gate does not know about it. Either it is a new authority type and "
            f"the invariant needs restating, or it is not and the closure was followed "
            f"too far."
        )
    for missing in sorted(expected - closure):
        problems.append(
            f"orxnud-domain: `{missing}` was expected to be gated by "
            f"{EXPECTED_SEAL_TYPE} but no public constructor takes one. The chain has "
            f"been broken, which makes the type mintable from nothing."
        )
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
                "FAIL  G2d: the authority surface in orxnud-domain has changed. This is a "
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