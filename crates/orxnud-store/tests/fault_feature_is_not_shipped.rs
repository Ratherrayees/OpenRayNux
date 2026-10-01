//! The `fault-injection` feature must never be part of a shipped build.
//!
//! The hook in `faults.rs` calls [`std::process::abort`]. That is correct for a
//! test and catastrophic in a release: any environment that happened to carry
//! `ORXNUD_FAULT=...` would kill the daemon mid-write. The risk is therefore not
//! the hook, it is the hook being *compiled into* something users run.
//!
//! # Why this is a manifest check and not `cargo tree`
//!
//! The first version of this test asked `cargo tree -e features` whether
//! `fault-injection` was enabled. It reported "off" even after the feature had
//! been added to `default = [...]`, because `fault-injection = []` enables no
//! optional *dependency*, so `cargo tree -e features` prints nothing for it at
//! all. A `cfg`-only feature is invisible to the dependency tree.
//!
//! So the check reads the manifests, which is also the layer where the mistake is
//! actually made. It is the same reasoning as gate G2: a manifest cannot prove
//! anything about runtime behaviour, but it can prove exactly what it is asked —
//! "nobody enabled this feature" — without pretending to.

use std::path::{Path, PathBuf};

fn manifests() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf();
    let mut out = Vec::new();
    for dir in ["crates", "."] {
        let d = root.join(dir);
        let Ok(entries) = std::fs::read_dir(&d) else {
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

/// `fault-injection` must not be a default feature of any crate.
#[test]
fn the_fault_injection_feature_is_not_a_default_anywhere() {
    let mut offenders = Vec::new();
    for m in manifests() {
        let text = std::fs::read_to_string(&m).expect("read manifest");
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            // `default = ["fault-injection"]` in any of its spellings.
            if line.starts_with("default") && line.contains("fault-injection") {
                offenders.push(format!("{}:{} default: {line}", m.display(), n + 1));
            }
            // `features = ["fault-injection"]` on a dependency of another crate.
            if line.starts_with("features") && line.contains("fault-injection") {
                offenders.push(format!("{}:{} features: {line}", m.display(), n + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the fault-injection hook would ship in a default build:\n  {}",
        offenders.join("\n  ")
    );
}

/// The feature must exist but be empty, so that turning it on changes nothing
/// except the `cfg` gates.
#[test]
fn the_fault_injection_feature_is_empty() {
    let m = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let text = std::fs::read_to_string(&m).expect("read manifest");
    assert!(
        text.contains("fault-injection = []"),
        "the feature declaration changed shape; re-check that it enables no dependency"
    );
}

/// Nothing outside `faults.rs` may abort the process.
///
/// The second exit. `maybe_crash` is the only intended one, and a second one would
/// let a crash escape from an ordinary error path.
#[test]
fn abort_is_reachable_only_through_the_gate() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut callers = Vec::new();
    for entry in walk(&dir) {
        let src = std::fs::read_to_string(&entry).unwrap_or_default();
        for (n, line) in src.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("process::abort") && !entry.ends_with("faults.rs") {
                callers.push(format!("{}:{}", entry.display(), n + 1));
            }
        }
    }
    assert!(
        callers.is_empty(),
        "process::abort is called outside faults.rs: {}",
        callers.join(", ")
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
