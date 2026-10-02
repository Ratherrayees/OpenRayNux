//! Gate G2(b): the CLI may not become a second domain layer.
//!
//! # What this protects
//!
//! `orxnuctl` is the only user-facing interface, and the repository's claim is that
//! "business logic exists exactly once". A CLI that could import `orxnud-domain`,
//! `orxnud-store`, `orxnud-task`, `orxnud-policy` or `orxnud-daemon` could reimplement a
//! rule it can now see — and the failure is silent: the CLI would answer from its own
//! understanding while the daemon enforced a different one.
//!
//! # Why this test reads the real manifests
//!
//! It could restate the permitted list, and then the list would be a copy that drifts
//! from both the gate and the manifest, and the test would keep passing while the gate
//! had been amended. Instead it does three things, all against the shipped files:
//!
//! 1. derives the permitted set from the gate script itself, so gate and test cannot
//!    disagree about what is allowed;
//! 2. reads `orxnuctl`'s real manifest and asserts every internal dependency it names
//!    is in that set;
//! 3. asserts the current manifest is not *trivially* clean — that it does name the
//!    transport — so a future edit that quietly removes the check's subject fails too.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn script() -> PathBuf {
    repo_root().join("scripts/ci-gates.sh")
}

fn cli_manifest() -> PathBuf {
    repo_root().join("crates/orxnuctl/Cargo.toml")
}

/// The internal crates the gate permits, read out of the gate script.
///
/// Sourcing nothing and deciding nothing: the value is lifted from the shipped script,
/// so this test cannot claim a permission the gate does not grant, and amending the
/// gate without amending the intent shows up here as a failure.
fn permitted_internal_crates() -> BTreeSet<String> {
    let out = Command::new("sed")
        .arg("-n")
        .arg(r#"s/^  local CLI_ALLOWED_INTERNAL="\(.*\)"$/\1/p"#)
        .arg(script())
        .output()
        .expect("run sed");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.trim().is_empty(),
        "could not read CLI_ALLOWED_INTERNAL from {}; the gate's shape changed",
        script().display()
    );
    text.split_whitespace().map(str::to_owned).collect()
}

/// Every `orxnud-*` crate in `orxnuctl`'s `[dependencies]`.
fn internal_dependencies(manifest: &Path) -> BTreeSet<String> {
    let text = std::fs::read_to_string(manifest).expect("read the manifest");
    let mut deps = BTreeSet::new();
    let mut in_deps = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            in_deps = line == "[dependencies]";
            continue;
        }
        if !in_deps {
            continue;
        }
        let name = line.split('=').next().unwrap_or("").trim();
        if name.starts_with("orxnud-") {
            deps.insert(name.to_owned());
        }
    }
    deps
}

#[test]
fn the_permitted_set_is_the_transport_and_the_wire_vocabulary() {
    let permitted = permitted_internal_crates();
    assert!(
        permitted.contains("orxnud-protocol"),
        "the wire vocabulary is always permitted"
    );
    assert!(
        permitted.contains("orxnud-platform-ipc"),
        "opening the approved local socket is not a domain leak"
    );
    // And the crates whose types could carry a rule are absent. Named explicitly so
    // adding one is a deliberate edit to this test, not a silent widening.
    for forbidden in [
        "orxnud-domain",
        "orxnud-store",
        "orxnud-task",
        "orxnud-policy",
        "orxnud-capability",
        "orxnud-daemon",
    ] {
        assert!(
            !permitted.contains(forbidden),
            "{forbidden} must never be permitted for the CLI"
        );
    }
}

#[test]
fn the_cli_names_only_permitted_internal_crates() {
    let permitted = permitted_internal_crates();
    let actual = internal_dependencies(&cli_manifest());
    for dep in &actual {
        assert!(
            permitted.contains(dep),
            "orxnuctl depends on {dep}, which gate G2(b) does not permit"
        );
    }
}

#[test]
fn the_cli_actually_uses_the_transport() {
    // A guard on the guard: if the transport dependency were dropped, the check above
    // would still pass — vacuously, because there would be nothing to check. The
    // subject of this test has to be present for the test to mean anything.
    let actual = internal_dependencies(&cli_manifest());
    assert!(
        actual.contains("orxnud-platform-ipc"),
        "orxnuctl should name the transport; without it this file tests nothing"
    );
}

#[test]
fn no_internal_crate_is_a_dev_dependency_either() {
    // `G2(b)` reads `[dependencies]` only, so a dev-dependency on a domain crate would
    // let a CLI *test* reach into the engine — and a test that can do that is how an
    // end-to-end test quietly stops being end-to-end. Asserted here rather than in the
    // gate because the gate's own scope is the production graph.
    let text = std::fs::read_to_string(cli_manifest()).expect("read the manifest");
    let mut in_dev = false;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_dev = line == "[dev-dependencies]";
            continue;
        }
        if in_dev {
            let name = line.split('=').next().unwrap_or("").trim();
            assert!(
                !name.starts_with("orxnud-"),
                "orxnuctl has a dev-dependency on {name}; the end-to-end tests must go \
                 through the CLI and the socket, not into the engine"
            );
        }
    }
}
