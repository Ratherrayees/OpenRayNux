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

# Minimal but *faithful* copies of the two crates G2d now reads.
#
# Authority lives in orxnud-policy, beside the `pub(crate)` constructors that mint it,
# and the sealed capability traits live in orxnud-capability. A fixture whose shapes
# differed from the real ones would be testing a different invariant -- which is how a
# gate passes while meaning something else.
POLICY_SRC = """\
pub struct AuthorisationProof {
    policy_version: String,
}

impl AuthorisationProof {
    pub(crate) fn issue(policy_version: impl Into<String>) -> Self {
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
    pub(crate) fn authorise(_request: &(), step: u32) -> Self {
        Self { step }
    }
    pub fn step(&self) -> u32 {
        self.step
    }
}

pub struct DispatchView<'a> {
    step: u32,
    _p: &'a u32,
}
"""

CAPABILITY_SRC = """\
use orxnud_policy::CapabilityInvocation;

pub(crate) trait CapabilityAdapter {
    fn invoke(&self, view: &u32) -> Result<(), String>;
}

pub(crate) trait AdapterBundle {
    fn adapter(&self) -> &dyn CapabilityAdapter;
}

// Naming an authority type is legitimate: a capability crate receives an invocation
// and cannot construct one. The fixture needs one, or the must-pass cases would not
// show that the gate tells "names" apart from "mints".
pub fn execute(invocation: &CapabilityInvocation) -> u32 {
    invocation.step()
}
"""

# orxnud-domain must re-export nothing: everything depends on it, so a re-export there
# would put the minting constructor in reach of the whole workspace.
DOMAIN_SRC = """\
pub struct ActionRequest {
    pub step: u32,
}

impl ActionRequest {
    pub fn new(step: u32) -> Self {
        Self { step }
    }
}
"""


class Fixture:
    """A temporary repository-shaped tree the real gate can be pointed at."""

    def __init__(self, root: str) -> None:
        self.root = root
        for crate in ("orxnud-domain", "orxnud-policy", "orxnud-capability", "orxnud-task"):
            os.makedirs(os.path.join(root, "crates", crate, "src"), exist_ok=True)
        self.write("crates/orxnud-domain/src/lib.rs", DOMAIN_SRC)
        self.write("crates/orxnud-policy/src/authority.rs", POLICY_SRC)
        self.write("crates/orxnud-capability/src/dispatch.rs", CAPABILITY_SRC)
        self.write("crates/orxnud-task/src/lib.rs", "")

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
        "bypass 3: minting in examples/, which cargo compiles but the old find skipped",
        "G2d",
        "crates/orxnud-capability/examples/a.rs",
        True,
    ),
    # ---- equivalent spellings of minting -----------------------------------------
    ("a bare `authorise(..)` call", "G2d", "crates/orxnud-capability/src/a.rs", True),
    (
        "an imported associated function: use CapabilityInvocation::authorise;",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        True,
    ),
    (
        "a fully qualified path: orxnud_policy::CapabilityInvocation::authorise(..)",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        True,
    ),
    ("a type alias for the authority type", "G2d", "crates/orxnud-capability/src/a.rs", True),
    (
        "AuthorisationProof::issue from another crate",
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
        "a real #[cfg(test)] module may mint authority to build a fixture",
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
        "a nested module inside a test module may mint authority",
        "G2d",
        "crates/orxnud-capability/src/a.rs",
        False,
    ),
    (
        "a violation AFTER a nested block inside a test module is still test-only",
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
use orxnud_policy::CapabilityInvocation;

fn production() {
    let _ = CapabilityInvocation::authorise(&(), 1);
}
""",
        "bypass 2: CapabilityInvocation::authorise in production code": """
use orxnud_policy::CapabilityInvocation;

fn production() {
    let _ = CapabilityInvocation::authorise(&(), 1);
}
""",
        "bypass 3: minting in examples/, which cargo compiles but the old find skipped": """
use orxnud_policy::CapabilityInvocation;

fn main() {
    let _ = CapabilityInvocation::authorise(&(), 1);
}
""",
        "a bare `authorise(..)` call": """
fn production() {
    let _ = authorise(&(), 1);
}
""",
        "an imported associated function: use CapabilityInvocation::authorise;": """
use orxnud_policy::CapabilityInvocation::authorise;

fn production() {
    let _ = authorise(&(), 1);
}
""",
        "a fully qualified path: orxnud_policy::CapabilityInvocation::authorise(..)": """
fn production() {
    let _ = orxnud_policy::CapabilityInvocation::authorise(&(), 1);
}
""",
        "a type alias for the authority type": """
use orxnud_policy::CapabilityInvocation as Invocation;

fn production() {
    let _ = Invocation::authorise(&(), 1);
}
""",
        "AuthorisationProof::issue from another crate": """
fn production() {
    let _ = orxnud_policy::AuthorisationProof::issue("v1");
}
""",
        "benches/ is production-reachable code too": """
fn bench() {
    let _ = orxnud_policy::CapabilityInvocation::authorise(&(), 1);
}
""",
        "#[cfg(any(test, unix))] is production code and must NOT be exempt": """
#[cfg(any(test, unix))]
fn production() {
    let _ = orxnud_policy::CapabilityInvocation::authorise(&(), 1);
}
""",
        # --- G2d must-pass ---
        "a real #[cfg(test)] module may mint authority to build a fixture": """
#[cfg(test)]
mod tests {
    use orxnud_policy::CapabilityInvocation;

    fn fixture() -> CapabilityInvocation {
        CapabilityInvocation::authorise(&(), 1)
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
use orxnud_policy::CapabilityInvocation;

/// Execute an invocation that policy has already authorised.
pub fn execute(invocation: &CapabilityInvocation) -> u32 {
    invocation.step()
}
""",
        "a nested module inside a test module may mint authority": """
#[cfg(test)]
mod tests {
    mod deeper {
        use orxnud_policy::CapabilityInvocation;

        pub fn fixture() -> CapabilityInvocation {
            CapabilityInvocation::authorise(&(), 1)
        }
    }

    #[test]
    fn it_builds() {
        assert_eq!(deeper::fixture().step(), 1);
    }
}
""",
        "a violation AFTER a nested block inside a test module is still test-only": """
#[cfg(test)]
mod tests {
    // A nested block, so that a region matcher which ends at the first closing
    // brace would stop here -- before the violation below, and therefore expose it.
    mod deeper {
        pub fn helper() -> u32 {
            7
        }
    }

    use orxnud_policy::CapabilityInvocation;

    pub fn fixture() -> CapabilityInvocation {
        CapabilityInvocation::authorise(&(), 1)
    }
}
""",
        "#[cfg(all(test, unix))] is test-only": """
#[cfg(all(test, unix))]
mod unix_only_tests {
    use orxnud_policy::CapabilityInvocation;

    pub fn fixture() -> CapabilityInvocation {
        CapabilityInvocation::authorise(&(), 1)
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


# Each case mutates the authority surface in exactly one way and says whether the gate
# must reject it. The must-accept cases matter as much as the must-reject ones: a check
# that flagged an ordinary new public type would flag every constructor in the crate,
# and nobody reads a gate that always shouts.
DRIFT_CASES: list[tuple[str, str, bool]] = [
    # ---- must be rejected: the boundary has weakened --------------------------
    ("policy", "CapabilityInvocation::authorise is widened to `pub`", True),
    ("policy", "AuthorisationProof::issue is widened to `pub`", True),
    ("policy", "the minting constructor is renamed", True),
    ("policy", "the minting constructor is deleted", True),
    ("policy", "an authority type is renamed", True),
    ("policy", "an authority type is re-exported from orxnud-domain", True),
    ("capability", "CapabilityAdapter is widened to `pub`", True),
    ("capability", "AdapterBundle is widened to `pub`", True),
    ("capability", "a sealed trait is deleted", True),
    # ---- must be accepted ---------------------------------------------------
    ("policy", "an ordinary new public type with a public constructor", False),
    ("policy", "the authority surface is unchanged", False),
]


def drift_policy(case: str) -> str:
    """`orxnud-policy`'s source with its authority surface changed in one way."""
    if case.startswith("CapabilityInvocation::authorise is widened"):
        return POLICY_SRC.replace("pub(crate) fn authorise", "pub fn authorise")
    if case.startswith("AuthorisationProof::issue is widened"):
        return POLICY_SRC.replace("pub(crate) fn issue", "pub fn issue")
    if case.startswith("the minting constructor is renamed"):
        return POLICY_SRC.replace("fn authorise", "fn authorise_for_good_measure")
    if case.startswith("the minting constructor is deleted"):
        return POLICY_SRC.replace(
            """    pub(crate) fn authorise(_request: &(), step: u32) -> Self {
        Self { step }
    }
""",
            "",
        )
    if case.startswith("an authority type is renamed"):
        return POLICY_SRC.replace("CapabilityInvocation", "InvocationOfRecord")
    if case.startswith("an ordinary new public type"):
        return (
            POLICY_SRC
            + """
/// Not authority: it takes no authority type and returns none. Constructible, as any
/// ordinary public value in this crate is.
pub struct Cursor(pub u32);

impl Cursor {
    pub fn at(offset: u32) -> Self {
        Self(offset)
    }
}
"""
        )
    return POLICY_SRC


def drift_capability(case: str) -> str:
    """`orxnud-capability`'s source with its sealed traits changed in one way."""
    if case.startswith("CapabilityAdapter is widened"):
        return CAPABILITY_SRC.replace("pub(crate) trait CapabilityAdapter", "pub trait CapabilityAdapter")
    if case.startswith("AdapterBundle is widened"):
        return CAPABILITY_SRC.replace("pub(crate) trait AdapterBundle", "pub trait AdapterBundle")
    if case.startswith("a sealed trait is deleted"):
        return CAPABILITY_SRC.replace(
            """pub(crate) trait AdapterBundle {
    fn adapter(&self) -> &dyn CapabilityAdapter;
}
""",
            "",
        )
    return CAPABILITY_SRC


def mutated_domain(case: str) -> str:
    """`orxnud-domain` with authority leaking back into it."""
    if case.startswith("an authority type is re-exported"):
        return DOMAIN_SRC + (
            """
// Everything depends on orxnud-domain. A re-export here would put the minting
// constructor in reach of the whole workspace.
pub use orxnud_policy::{AuthorisationProof, CapabilityInvocation, DispatchView};
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
use orxnud_policy::CapabilityInvocation;

fn production() {
    let _ = CapabilityInvocation::authorise(&(), 1);
}
""",
    ),
    (
        "the comment moved to the bottom, after the violation",
        """
use orxnud_policy::CapabilityInvocation;

fn production() {
    let _ = CapabilityInvocation::authorise(&(), 1);
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
    use orxnud_policy::CapabilityInvocation;
    fn fixture() -> CapabilityInvocation {
        CapabilityInvocation::authorise(&(), 1)
    }
}

fn production() {
    let _ = CapabilityInvocation::authorise(&(), 1);
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
    let _ = orxnud_policy::CapabilityInvocation::authorise(&(), 1);
}
""",
    ),
    (
        "a fully qualified path, and the import removed",
        """
fn production() {
    let _ = ::orxnud_policy::authority::CapabilityInvocation::authorise(&(), 1);
}
""",
    ),
    (
        "a re-exported alias",
        """
use orxnud_policy::CapabilityInvocation as Gate;

fn production() {
    let _ = Gate::authorise(&(), 1);
}
""",
    ),
    (
        "an associated-function import used bare",
        """
use orxnud_policy::CapabilityInvocation::{self as S, authorise};

fn production() {
    let _ = authorise(&(), 1);
}
""",
    ),
    (
        "the minting call inside a nested production module",
        """
mod inner {
    pub mod deeper {
        use orxnud_policy::CapabilityInvocation;
        pub fn forge() -> CapabilityInvocation {
            CapabilityInvocation::authorise(&(), 1)
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

        # The authority-surface drift check. A forbidden list that silently goes stale is
        # how the original bypasses existed: G2d reported `ok` on a tree that forged
        # authority three ways, because the symbols it looked for were not the ones the
        # exploits used.
        for where, name, expect_fail in DRIFT_CASES:
            total += 1
            root = os.path.join(tmp, "drift")
            shutil.rmtree(root, ignore_errors=True)
            fx = Fixture(root)
            if where == "policy":
                fx.write("crates/orxnud-policy/src/authority.rs", drift_policy(name))
            elif where == "capability":
                fx.write("crates/orxnud-capability/src/dispatch.rs", drift_capability(name))
            fx.write("crates/orxnud-domain/src/lib.rs", mutated_domain(name))
            result = fx.gate("G2d")
            rejected = result.returncode != 0
            if rejected == expect_fail:
                print(f"  ok    {where}: {name}")
            else:
                print(f"  FAIL  {where}: {name}")
                failures.append(
                    f"{where}: {name}\n     expected the gate to "
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