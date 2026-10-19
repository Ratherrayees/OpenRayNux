//! `test-support` must never be part of a shipped build.
//!
//! # What it unlocks
//!
//! `orxnud_store::test_support::stage_schema` applies migrations 1..=N to a
//! connection. That is a schema change with **no pre-migration snapshot, no
//! verification and no recovery** — precisely F-26. It exists because integration
//! tests in other crates cannot see `#[cfg(test)]`, and because re-exporting the
//! DDL under a feature would put every `CREATE TABLE` string back into a build
//! that enabled it.
//!
//! So the exposure is bounded by the manifest, and the manifest is what this
//! reads. Same argument, same shape, as `fault_feature_is_not_shipped.rs`: a
//! `cfg`-only feature is invisible to `cargo tree -e features`, and the mistake
//! would be made in a manifest, so the check is a manifest check.

use std::path::{Path, PathBuf};

fn manifests() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let mut out = Vec::new();
    for dir in ["crates", "."] {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path().join("Cargo.toml");
            if p.is_file() {
                out.push(p);
            }
        }
    }
    out.sort();
    assert!(out.len() > 5, "did not find the workspace manifests");
    out
}

/// Only `orxnud-store` may enable it, and only from `[dev-dependencies]`.
#[test]
fn test_support_is_enabled_only_from_a_dev_dependency() {
    let mut offenders = Vec::new();
    for m in manifests() {
        let text = std::fs::read_to_string(&m).expect("read manifest");
        // Which dependency block are we in?
        let mut section = "";
        for (n, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.starts_with('[') {
                section = t;
            }
            if t.starts_with("default") && t.contains("test-support") {
                offenders.push(format!("{}:{} default: {line}", m.display(), n + 1));
            }
            if t.starts_with("features") && t.contains("test-support") {
                offenders.push(format!("{}:{} features: {line}", m.display(), n + 1));
            }
            if t.contains("test-support") && !t.starts_with("features") && !t.starts_with('#') {
                // A normal `[dependencies]` entry would ship it.
                let ok = section == "[dev-dependencies]"
                    || m.file_name().is_some_and(|f| f == "Cargo.toml")
                        && m.parent().is_some_and(|p| {
                            p.join("Cargo.toml").canonicalize().ok()
                                == Path::new(env!("CARGO_MANIFEST_DIR"))
                                    .join("Cargo.toml")
                                    .canonicalize()
                                    .ok()
                        })
                        && section == "[features]";
                if !ok {
                    offenders.push(format!("{}:{} in {section}: {line}", m.display(), n + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the test-support staging surface would ship in a normal build:\n  {}",
        offenders.join("\n  ")
    );
}

/// The feature must exist but enable nothing, so turning it on changes only `cfg`s.
#[test]
fn the_test_support_feature_is_empty() {
    let m = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(&m).expect("read manifest");
    assert!(
        text.contains("test-support = []"),
        "the feature declaration changed shape; re-check that it enables no dependency, \
         because a feature that pulls one in is no longer invisible to `cargo tree`"
    );
}

/// The staging helper itself must be behind the gate, not merely undocumented.
///
/// A manifest check proves nobody *enabled* the feature; this proves there is
/// nothing to reach when they have not. Without it, a later `pub fn` could be
/// added to the same module and the manifest test would still pass.
#[test]
fn the_staging_helper_is_not_present_without_the_feature() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    for entry in walk(&dir) {
        let src = std::fs::read_to_string(&entry).unwrap_or_default();
        for (n, line) in src.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("pub mod test_support") {
                // The gate must be on this line or the one above it.
                let gated = code.contains("cfg(test)")
                    || src
                        .lines()
                        .nth(n.saturating_sub(1))
                        .is_some_and(|l| l.contains("feature = \"test-support\""));
                if !gated {
                    offenders.push(format!("{}:{}", entry.display(), n + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "`pub mod test_support` is not behind a cfg gate: {}",
        offenders.join(", ")
    );
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}
