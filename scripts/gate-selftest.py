#!/usr/bin/env python3
"""Self-tests for the G2d and G3 boundary gates.

# Why this drives the real gate

A self-test of a *copy* of the gate's logic proves only that the copy agrees with
itself. If the copy and the gate disagree, the copy is the thing that was tested. So
every case here builds a temporary fixture tree and runs the real
``scripts/ci-gates.sh G2d|G3`` over it, with ``ORXNUD_GATE_ROOT`` pointing at the
fixture. A case passes only when the actual gate accepts or rejects it.

The exit status is what CI reads. Nothing in this file is a stand-in.

# The three kinds of case

* **must fail** -- a fixture containing a real boundary crossing. If the gate passes it,
  the gate is broken.
* **must pass** -- legitimate code that must keep working. A gate that rejects these has
  become a gate people disable, which is how the original bypasses existed.
* **adversarial** -- semantically equivalent spellings of the same construct, which must
  all reach the same verdict. This is the class a regular expression gets wrong.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(REPO, "scripts", "ci-gates.sh")

# A minimal but *faithful* domain, so the G2d drift check has something real to verify.
# `PolicySeal::attest` is the ungated root; the other two take `&PolicySeal`, exactly as
# the real domain does. A fixture whose domain differed from the real shape would be
# testing a different invariant.
DOMAIN_SRC = """\
pub struct PolicySeal {
    issued_by: &'static str,
}

impl PolicySeal {
    pub fn attest(issued_by: &'static str) -> Self {
        Self { issued_by }
    }
    pub fn issued_by(&self) -> &'static str {
        self.issued_by
    }
}

pub struct AuthorisationProof {
    policy_version: String,
}

impl AuthorisationProof {
    pub fn issue(_seal: &PolicySeal, policy_version: impl Into<String>) -> Self {
        Self { policy_version: policy_version.into() }
    }
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }
}

pub struct CapabilityInvocation {
    step: u32,
}

impl CapabilityInvocation {
    pub fn authorise(_seal: &PolicySeal, step: u32) -> Self {
        Self { step }
    }
    pub fn step(&self) -> u32 {
        self.step
    }
}
"""


class Fixture:
    """A temporary repository-shaped tree the real gate can be pointed at."""

    def __init__(self, root: str) -> None:
        self.root = root
        for crate in ("orxnud-domain", "orxnud-policy", "orxnud-capability", "orxnud-task"):
            os.makedirs(os.path.join(root, "crates", crate, "src"), exist_ok=True)
        self.write("crates/orxnud-domain/src/invocation.rs", DOMAIN_SRC)
        for crate in ("orxnud-policy", "orxnud-capability", "orxnud-task"):
            self.write(f"crates/{crate}/src/lib.rs", "")

    def write(self, rel: str, text: str) -> None:
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def gate(self, which: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, ORXNUD_GATE_ROOT=self.root)
        return subprocess.run(
            ["bash", GATE, which],
            capture_output=True,
            text=True,
            env=env,
            cwd=REPO,
            check=False,
        )


# --------------------------------------------------------------------------
# Case table
# --------------------------------------------------------------------------

# (name, gate, relative path, source, expect_fail)
#
# `expect_fail` is the gate's own verdict: True means the gate must reject the fixture.
G2D_CASES: list[tuple[str, str, str, bool]] = [
    # ---- the three reproduced bypasses, each of which the old gate missed ----------
    (
        "bypass 1: a comment mentioning #[cfg(test)] must not switch the gate off",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        True,
    ),
    (
        "bypass 2: CapabilityInvocation::authorise in production code",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        True,
    ),
    (
        "bypass 3: the seal in examples/, which cargo compiles but the old find skipped",
        "G2d",
        "crates/orxnud-capability/examples/a.rs",
        True,
    ),
    # ---- equivalent spellings of minting -----------------------------------------
    ("a bare `authorise(..)` call", "G2d", "crates/orxnud-capability/src/a.rs", True),
    (
        "an imported associated function: use PolicySeal::attest;",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        True,
    ),
    (
        "a fully qualified path: orxnud_domain::PolicySeal::attest(..)",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        True,
    ),
    ("a type alias for the seal", "G2d", "crates/orxnud-capability/src/a.rs", True),
    (
        "AuthorisationProof::issue without a seal-derived value",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        True,
    ),
    (
        "benches/ is production-reachable code too",
        "G2d",
        "crates/orxnud-capability/benches/b.rs",
        True,
    ),
    # ---- legitimate code that must keep working -----------------------------------
    (
        "a real #[cfg(test)] module may mint a seal to build a fixture",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        False,
    ),
    (
        "a doc comment mentioning #[cfg(test)] is not an attribute",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        False,
    ),
    (
        "a string literal containing #[cfg(test)] is not an attribute",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        False,
    ),
    (
        "documentation naming cfg(target_os) and env::consts::OS is prose, not a branch",
        "G2d",
        "crates/orxnud-domain/src/platform.rs",
        False,
    ),
    (
        "a capability crate may take a CapabilityInvocation as an argument",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        False,
    ),
    (
        "a nested module inside a test module may mint a seal",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        False,
    ),
    (
        "#[cfg(all(test, unix))] is test-only",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        False,
    ),
]

# `#[cfg(any(test, unix))]` is *production* code that happens to run in tests. Treating
# it as test-only would silently exempt production code from the gate, so it is a
# must-fail case rather than a must-pass one.
G2D_ANY_TEST_CASES: list[tuple[str, str, str, bool]] = [
    (
        "#[cfg(any(test, unix))] is production code and must NOT be exempt",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        True,
    ),
]

G3_CASES: list[tuple[str, str, str, bool]] = [
    ("cfg(target_os = ...)", "G3", "crates/orxnud-task/src/a.rs", True),
    ("cfg(not(target_os = \"windows\"))", "G3", "crates/orxnud-task/src/a.rs", True),
    (
        "cfg(any(target_os = \"linux\", target_os = \"macos\"))",
        "G3",
        "crates/orxnud-task/src/a.rs",
        True,
    ),
    ("cfg(all(target_os = \"linux\", unix))", "G3", "crates/orxnud-task/src/a.rs", True),
    ("cfg(not(unix))", "G3", "crates/orxnud-task/src/a.rs", True),
    ("cfg(any(unix, target_os = \"windows\"))", "G3", "crates/orxnud-task/src/a.rs", True),
    ("cfg(not(any(target_os = \"windows\", unix)))", "G3", "crates/orxnud-task/src/a.rs", True),
    (
        "cfg(all(any(target_os = \"linux\"), not(unix)))",
        "G3",
        "crates/orxnud-task/src/a.rs",
        True,
    ),
    ("cfg_attr(not(unix), allow(unused))", "G3", "crates/orxnud-task/src/a.rs", True),
    (
        "cfg_attr(any(target_os = \"linux\"), path = \"...\")",
        "G3",
        "crates/orxnud-task/src/a.rs",
        True,
    ),
    ("cfg(target_family = \"wasm\")", "G3", "crates/orxnud-task/src/a.rs", True),
    ("cfg(target_arch = \"x86_64\")", "G3", "crates/orxnud-task/src/a.rs", True),
    ("env::consts::OS read in code", "G3", "crates/orxnud-task/src/a.rs", True),
    ("std::os::unix::fs in an import", "G3", "crates/orxnud-task/src/a.rs", True),
    ("std::os::windows::process in an import", "G3", "crates/orxnud-task/src/a.rs", True),
    # a predicate split across lines is the same predicate
    (
        "a predicate split across lines",
        "G3",
        "crates/orxnud-task/src/a.rs",
        True,
    ),
    # ---- must pass ---------------------------------------------------------------
    ("#[cfg(test)] is not a platform branch", "G3", "crates/orxnud-task/src/a.rs", False),
    (
        "#[cfg(feature = \"x\")] is not a platform branch",
        "G3",
        "crates/orxnud-task/src/a.rs",
        False,
    ),
    ("cfg(feature = \"extra\") is not a platform branch", "G3", "crates/orxnud-task/src/a.rs", False),
    ("#[cfg(debug_assertions)] is not a platform branch", "G3", "crates/orxnud-task/src/a.rs", False),
    (
        "documentation that names every platform form is prose",
        "G3",
        "crates/orxnud-task/src/a.rs",
        False,
    ),
    (
        "a string literal containing cfg(target_os = \"linux\")",
        "G3",
        "crates/orxnud-task/src/a.rs",
        False,
    ),
    (
        "a raw string containing a platform predicate",
        "G3",
        "crates/orxnud-task/src/a.rs",
        False,
    ),
    (
        "platform implementation inside a designated platform crate",
        "G3",
        "crates/orxnud-platform-fs/src/a.rs",
        False,
    ),
]


def source_for(name: str) -> str:
    """The fixture source for a named case."""
    table = {
        # --- G2d must-fail ---
        "bypass 1: a comment mentioning #[cfg(test)] must not switch the gate off": """
// The test module uses #[cfg(test)] later.
use orxnud_domain::PolicySeal;

fn production() {
    let _ = PolicySeal::attest("attacker");
}
""",
        "bypass 2: CapabilityInvocation::authorise in production code": """
use orxnud_domain::CapabilityInvocation;

fn production() {
    let _ = CapabilityInvocation::authorise(&(), 1);
}
""",
        "bypass 3: the seal in examples/, which cargo compiles but the old find skipped": """
use orxnud_domain::PolicySeal;

fn main() {
    let _ = PolicySeal::attest("attacker");
}
""",
        "a bare `authorise(..)` call": """
fn production() {
    let _ = authorise(&(), 1);
}
""",
        "an imported associated function: use PolicySeal::attest;": """
use orxnud_domain::PolicySeal::attest;

fn production() {
    let _ = attest("attacker");
}
""",
        "a fully qualified path: orxnud_domain::PolicySeal::attest(..)": """
fn production() {
    let _ = orxnud_domain::PolicySeal::attest("attacker");
}
""",
        "a type alias for the seal": """
use orxnud_domain::PolicySeal as Seal;

fn production() {
    let _ = Seal::attest("attacker");
}
""",
        "AuthorisationProof::issue without a seal-derived value": """
fn production() {
    let _ = orxnud_domain::AuthorisationProof::issue(&(), "v1");
}
""",
        "benches/ is production-reachable code too": """
fn bench() {
    let _ = orxnud_domain::PolicySeal::attest("attacker");
}
""",
        "#[cfg(any(test, unix))] is production code and must NOT be exempt": """
#[cfg(any(test, unix))]
fn production() {
    let _ = orxnud_domain::PolicySeal::attest("attacker");
}
""",
        # --- G2d must-pass ---
        "a real #[cfg(test)] module may mint a seal to build a fixture": """
#[cfg(test)]
mod tests {
    use orxnud_domain::PolicySeal;

    fn fixture() -> PolicySeal {
        PolicySeal::attest("test")
    }
}
""",
        "a doc comment mentioning #[cfg(test)] is not an attribute": """
/// This module documents its own shape and mentions #[cfg(test)] in passing.
pub fn production() {}
""",
        "a string literal containing #[cfg(test)] is not an attribute": """
const NOTE: &str = "#[cfg(test)] mod tests { }";

pub fn production() {}
""",
        "documentation naming cfg(target_os) and env::consts::OS is prose, not a branch": """
//! A portable core must not contain `cfg(target_os = "linux")`, nor `cfg(not(unix))`,
//! nor a read of `env::consts::OS`. Naming the rule here is not a violation of it.
pub fn production() {}
""",
        "a capability crate may take a CapabilityInvocation as an argument": """
use orxnud_domain::CapabilityInvocation;

/// Execute an invocation that policy has already authorised.
pub fn execute(invocation: &CapabilityInvocation) -> u32 {
    invocation.step()
}
""",
        "a nested module inside a test module may mint a seal": """
#[cfg(test)]
mod tests {
    mod deeper {
        use orxnud_domain::PolicySeal;

        pub fn fixture() -> PolicySeal {
            PolicySeal::attest("test")
        }
    }

    #[test]
    fn it_builds() {
        assert!(deeper::fixture().issued_by().len() > 0);
    }
}
""",
        "#[cfg(all(test, unix))] is test-only": """
#[cfg(all(test, unix))]
mod unix_only_tests {
    use orxnud_domain::PolicySeal;

    pub fn fixture() -> PolicySeal {
        PolicySeal::attest("test")
    }
}
""",
        # --- G3 must-fail ---
        "cfg(target_os = ...)": '#[cfg(target_os = "linux")]\npub fn f() {}\n',
        "cfg(not(target_os = \"windows\"))": '#[cfg(not(target_os = "windows"))]\npub fn f() {}\n',
        "cfg(any(target_os = \"linux\", target_os = \"macos\"))": (
            '#[cfg(any(target_os = "linux", target_os = "macos"))]\npub fn f() {}\n'
        ),
        "cfg(all(target_os = \"linux\", unix))": '#[cfg(all(target_os = "linux", unix))]\npub fn f() {}\n',
        "cfg(not(unix))": "#[cfg(not(unix))]\npub fn f() {}\n",
        "cfg(any(unix, target_os = \"windows\"))": '#[cfg(any(unix, target_os = "windows"))]\npub fn f() {}\n',
        "cfg(not(any(target_os = \"windows\", unix)))": (
            '#[cfg(not(any(target_os = "windows", unix)))]\npub fn f() {}\n'
        ),
        "cfg(all(any(target_os = \"linux\"), not(unix)))": (
            '#[cfg(all(any(target_os = "linux"), not(unix)))]\npub fn f() {}\n'
        ),
        "cfg_attr(not(unix), allow(unused))": (
            "#[cfg_attr(not(unix), allow(unused))]\npub fn f() {}\n"
        ),
        "cfg_attr(any(target_os = \"linux\"), path = \"...\")": (
            '#[cfg_attr(any(target_os = "linux"), path = "/x")]\npub fn f() {}\n'
        ),
        "cfg(target_family = \"wasm\")": '#[cfg(target_family = "wasm")]\npub fn f() {}\n',
        "cfg(target_arch = \"x86_64\")": '#[cfg(target_arch = "x86_64")]\npub fn f() {}\n',
        "env::consts::OS read in code": 'pub fn f() -> &\'static str {\n    std::env::consts::OS\n}\n',
        "std::os::unix::fs in an import": "use std::os::unix::fs::PermissionsExt;\n\npub fn f() {}\n",
        "std::os::windows::process in an import": (
            "use std::os::windows::process::CommandExt;\n\npub fn f() {}\n"
        ),
        "a predicate split across lines": (
            "#[cfg(all(\n    target_os = \"linux\",\n    unix,\n))]\npub fn f() {}\n"
        ),
        # --- G3 must-pass ---
        "#[cfg(test)] is not a platform branch": "#[cfg(test)]\nmod tests {\n    pub fn f() {}\n}\n",
        "#[cfg(feature = \"x\")] is not a platform branch": '#[cfg(feature = "x")]\npub fn f() {}\n',
        "cfg(feature = \"extra\") is not a platform branch": '#[cfg(feature = "extra")]\npub fn f() {}\n',
        "#[cfg(debug_assertions)] is not a platform branch": (
            "#[cfg(debug_assertions)]\npub fn f() {}\n"
        ),
        "documentation that names every platform form is prose": """
//! `cfg(target_os = "linux")`, `cfg(not(unix))`, `cfg(any(unix, windows))`,
//! `cfg(all(target_family = "wasm", target_arch = "x86_64"))`,
//! `env::consts::OS`, `std::os::unix::fs` -- all of these are prohibited here.
pub fn f() {}
""",
        "a string literal containing cfg(target_os = \"linux\")": (
            'pub const RULE: &str = "cfg(target_os = \\"linux\\")";\n\npub fn f() {}\n'
        ),
        "a raw string containing a platform predicate": """
pub const RULE: &str = r#"#[cfg(target_os = "linux")] fn f() {}"#;

pub fn f() {}
""",
        "platform implementation inside a designated platform crate": (
            '#[cfg(target_os = "linux")]\nuse std::os::unix::fs::PermissionsExt;\n\npub fn f() {}\n'
        ),
    }
    if name not in table:
        raise KeyError(f"no fixture source for case {name!r}")
    return table[name]


DRIFT_CASES: list[tuple[str, bool]] = [
    # Must be rejected: the chain changed shape underneath the gate.
    ("the seal gains a second public constructor", True),
    ("the domain gains a third seal-gated type", True),
    ("a type becomes gated transitively through an authority type", True),
    ("the seal type is renamed", True),
    # Must be accepted, and this one matters as much as the others: a *new ordinary*
    # domain type with a public constructor is not a finding. A check that flagged it
    # would flag every constructor in the crate, and nobody reads a gate that always
    # shouts.
    ("an ordinary new domain type with a public constructor", False),
    ("the domain is unchanged", False),
]


def mutated_domain(case: str) -> str:
    """A domain whose authority chain has been changed in one specific way."""
    if case.startswith("the seal gains a second public constructor"):
        return DOMAIN_SRC.replace(
            "    pub fn issued_by(&self) -> &'static str {",
            """    pub fn forge() -> Self {
        Self { issued_by: "forged" }
    }
    pub fn issued_by(&self) -> &'static str {""",
        )
    if case.startswith("the domain gains a third seal-gated type"):
        return (
            DOMAIN_SRC
            + """
/// A new authority type, gated by the seal like the existing two.
pub struct Escalation {
    approved: bool,
}

impl Escalation {
    pub fn approve(_seal: &PolicySeal, approved: bool) -> Self {
        Self { approved }
    }
}
"""
        )
    if case.startswith("a type becomes gated transitively"):
        return (
            DOMAIN_SRC
            + """
/// Gated through an authority type rather than through the seal directly, so it is only
/// findable by following the closure.
pub struct ExecutionGrant {
    granted: bool,
}

impl ExecutionGrant {
    pub fn grant(_proof: &AuthorisationProof, granted: bool) -> Self {
        Self { granted }
    }
}
"""
        )
    if case.startswith("the seal type is renamed"):
        return DOMAIN_SRC.replace("PolicySeal", "PolicySealV2")
    if case.startswith("an ordinary new domain type"):
        return (
            DOMAIN_SRC
            + """
/// Not authority: no seal, no relationship to one. Constructible, as any domain value is.
pub struct Cursor(pub u32);

impl Cursor {
    pub fn at(offset: u32) -> Self {
        Self(offset)
    }
}
"""
        )
    return DOMAIN_SRC


def run_case(
    tmp: str,
    name: str,
    gate: str,
    rel: str,
    expect_fail: bool,
    source: str,
) -> tuple[bool, str]:
    root = os.path.join(tmp, "case")
    shutil.rmtree(root, ignore_errors=True)
    fx = Fixture(root)
    fx.write(rel, source)
    result = fx.gate(gate)
    rejected = result.returncode != 0
    if rejected == expect_fail:
        return True, ""
    return (
        False,
        f"{name}\n     expected the gate to "
        f"{'REJECT' if expect_fail else 'ACCEPT'}, and it "
        f"{'rejected' if rejected else 'accepted'}\n"
        f"     gate output:\n{result.stdout}\n{result.stderr}",
    )


# --------------------------------------------------------------------------
# Adversarial transformations
# --------------------------------------------------------------------------
#
# Every fixture above is *authored*. These are the same violations, rewritten the way an
# ordinary refactor or a well-meaning contributor would rewrite them, with no intent to
# evade anything. Each must still be rejected: if a harmless edit can turn a violation
# into a pass, the gate is enforcing a spelling rather than a rule.
#
# The first group is G2d; the second is G3.

G2D_TRANSFORMS: list[tuple[str, str]] = [
    (
        "the comment that disables the gate, moved to the top of the file",
        """
// This crate deliberately mentions #[cfg(test)] in its documentation.
use orxnud_domain::PolicySeal;

fn production() {
    let _ = PolicySeal::attest("attacker");
}
""",
    ),
    (
        "the comment moved to the bottom, after the violation",
        """
use orxnud_domain::PolicySeal;

fn production() {
    let _ = PolicySeal::attest("attacker");
}

// see also #[cfg(test)] below
#[cfg(test)]
mod tests {}
""",
    ),
    (
        "the test module renamed, and the disabling comment kept",
        """
// The test module uses #[cfg(test)] later.
#[cfg(test)]
mod check_all_the_things {
    use orxnud_domain::PolicySeal;
    fn fixture() -> PolicySeal {
        PolicySeal::attest("t")
    }
}

fn production() {
    let _ = PolicySeal::attest("attacker");
}
""",
    ),
    (
        "the attribute reformatted across lines",
        """
#[cfg(
    test
)]
mod tests {
    fn f() {}
}

fn production() {
    let _ = orxnud_domain::PolicySeal::attest("attacker");
}
""",
    ),
    (
        "a fully qualified path, and the import removed",
        """
fn production() {
    let _ = ::orxnud_domain::invocation::PolicySeal::attest("attacker");
}
""",
    ),
    (
        "a re-exported alias",
        """
use orxnud_domain::PolicySeal as Gate;

fn production() {
    let _ = Gate::attest("attacker");
}
""",
    ),
    (
        "an associated-function import used bare",
        """
use orxnud_domain::PolicySeal::{self as S, attest};

fn production() {
    let _ = attest("attacker");
}
""",
    ),
    (
        "the minting call inside a nested production module",
        """
mod inner {
    pub mod deeper {
        use orxnud_domain::PolicySeal;
        pub fn forge() -> PolicySeal {
            PolicySeal::attest("attacker")
        }
    }
}
""",
    ),
]

G3_TRANSFORMS: list[tuple[str, str]] = [
    (
        "a predicate split one key per line",
        """
#[cfg(all(
    target_os = "linux",
    not(feature = "x"),
    unix,
))]
pub fn f() {}
""",
    ),
    (
        "a predicate nested three deep",
        """
#[cfg(not(all(any(target_os = "linux", target_os = "macos"), unix, not(feature = "y"))))]
pub fn f() {}
""",
    ),
    (
        "a predicate reformatted with extra spaces",
        """
#[cfg ( not ( target_os = \"windows\" ) )]
pub fn f() {}
""",
    ),
    (
        "a cfg_attr whose predicate is the whole trick",
        """
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    derive(Debug)
)]
pub struct S;
""",
    ),
    (
        "a fully qualified platform constant",
        """
pub fn f() -> &'static str {
    std::env::consts::OS
}
""",
    ),
    (
        "the predicate introduced inside an otherwise clean crate",
        """
// Portable core.
pub fn f() {}
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub fn g() {}
""",
    ),
]


# Rewrites of *legitimate* code that must keep being accepted. Without these, the
# adversarial group above is only half the story: a gate that flags a local variable
# called `target_os` is a gate that gets disabled, and the fix for that is not to weaken
# the gate but to notice it here.
G3_LEGITIMATE_TRANSFORMS: list[tuple[str, str]] = [
    (
        "a local variable that merely looks like a platform key",
        """
pub fn f() {
    let target_os = "linux";
    let unix = true;
    let _ = (target_os, unix);
}
""",
    ),
    (
        "a function parameter named windows",
        """
pub fn f(windows: bool) -> bool {
    windows
}
""",
    ),
    (
        "a struct field named target_arch, serialised as JSON",
        """
pub struct Build {
    pub target_arch: String,
}

pub fn render(b: &Build) -> String {
    format!("{:?}", b.target_arch)
}
""",
    ),
    (
        "prose in a block comment describing a platform predicate",
        """
/*
 * This crate must not branch on the platform: no `cfg(target_os = "linux")`,
 * no `cfg(not(unix))`, no read of `env::consts::OS`. Stating the rule is not
 * breaking it.
 */
pub fn f() {}
""",
    ),
]


def run_transform(
    tmp: str, gate: str, rel: str, name: str, source: str, expect_fail: bool = True
) -> str | None:
    """Return a failure description, or None when the gate reached the expected verdict."""
    root = os.path.join(tmp, "xform")
    shutil.rmtree(root, ignore_errors=True)
    fx = Fixture(root)
    fx.write(rel, source)
    result = fx.gate(gate)
    rejected = result.returncode != 0
    if rejected == expect_fail:
        return None
    if expect_fail:
        return (
            f"{name}\n     an ordinary refactor of a real violation turned it into a "
            f"PASS, so the gate enforces a spelling rather than a rule.\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return (
        f"{name}\n     legitimate code was REJECTED. A gate that flags this is a gate "
        f"people disable, which is how the original bypasses existed.\n"
        f"{result.stdout}\n{result.stderr}"
    )


def main() -> int:
    failures: list[str] = []
    total = 0

    with tempfile.TemporaryDirectory(prefix="orxnud-gate-selftest-") as tmp:
        for name, gate, rel, expect_fail in G2D_CASES + G2D_ANY_TEST_CASES + G3_CASES:
            total += 1
            ok, detail = run_case(tmp, name, gate, rel, expect_fail, source_for(name))
            if ok:
                print(f"  ok    {name}")
            else:
                print(f"  FAIL  {name}")
                failures.append(detail)

        # The authority-surface drift check: the gate must notice the domain changing,
        # because a forbidden list that silently goes stale is how the original bypasses
        # existed.
        for name, expect_fail in DRIFT_CASES:
            total += 1
            root = os.path.join(tmp, "drift")
            shutil.rmtree(root, ignore_errors=True)
            fx = Fixture(root)
            fx.write("crates/orxnud-domain/src/invocation.rs", mutated_domain(name))
            result = fx.gate("G2d")
            rejected = result.returncode != 0
            if rejected == expect_fail:
                print(f"  ok    {name}")
            else:
                print(f"  FAIL  {name}")
                failures.append(
                    f"{name}\n     expected the gate to "
                    f"{'REJECT' if expect_fail else 'ACCEPT'}\n{result.stdout}\n{result.stderr}"
                )

        for name, source in G2D_TRANSFORMS:
            total += 1
            detail = run_transform(tmp, "G2d", "crates/orxnud-capability/src/a.rs", name, source)
            if detail is None:
                print(f"  ok    G2d transform: {name}")
            else:
                print(f"  FAIL  G2d transform: {name}")
                failures.append(detail)

        for name, source in G3_TRANSFORMS:
            total += 1
            detail = run_transform(tmp, "G3", "crates/orxnud-task/src/a.rs", name, source)
            if detail is None:
                print(f"  ok    G3 transform: {name}")
            else:
                print(f"  FAIL  G3 transform: {name}")
                failures.append(detail)

        for name, source in G3_LEGITIMATE_TRANSFORMS:
            total += 1
            detail = run_transform(
                tmp, "G3", "crates/orxnud-task/src/a.rs", name, source, expect_fail=False
            )
            if detail is None:
                print(f"  ok    G3 legitimate: {name}")
            else:
                print(f"  FAIL  G3 legitimate: {name}")
                failures.append(detail)

    print()
    if failures:
        print(f"{len(failures)} of {total} boundary-gate self-tests failed:")
        for f in failures:
            print(f"\n   {f}")
        return 1
    print(f"all {total} boundary-gate self-tests pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())