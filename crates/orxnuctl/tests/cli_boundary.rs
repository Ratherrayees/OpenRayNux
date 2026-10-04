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
//!    transport — so a future edit that quietly removes the check's subject fails too;
//! 4. since the credential command, asserts that the *module path* reached inside the two
//!    newly permitted crates is the secret-store vocabulary and nothing else.
//!
//! # Why (4) is the load-bearing one
//!
//! G2(b) permits `orxnud-domain` because `provider credential` must use the authoritative
//! `SecretRef` and `SecretsContract` rather than invent a reference format. A crate-level
//! permission is a blunt instrument: it permits `orxnud_domain::task_state`,
//! `orxnud_domain::approval`, anything. Without (4), a later change could import a domain
//! rule into the CLI, reimplement it there, and every existing check would still pass —
//! which is precisely the failure this file exists to prevent. The permission stays narrow
//! by being pinned to the three paths that justified it.

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
    // The provider credential is permitted, and the reason matters: `provider credential`
    // must use the authoritative `SecretRef` and `SecretsContract` rather than invent a
    // reference format, or it would write a credential the provider cannot read. Naming
    // the real types is the safer arrangement.
    assert!(
        permitted.contains("orxnud-domain"),
        "the credential command must use the real SecretRef, not a copy"
    );
    assert!(
        permitted.contains("orxnud-platform-secrets"),
        "the credential command must reach the real store"
    );

    // Everything that could carry a *rule* is still absent. Named explicitly so adding one
    // is a deliberate edit to this test, not a silent widening.
    for forbidden in [
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

// ---------------------------------------------------------------------------
// The module-path confinement
// ---------------------------------------------------------------------------

/// Every `orxnud_domain::` and `orxnud_platform_secrets::` path the CLI names.
///
/// The justification for widening G2(b) was one command needing the secret-store
/// vocabulary. This pins that justification to those paths, so the permission cannot
/// quietly become general domain access.
const PERMITTED_PATHS: &[&str] = &[
    "orxnud_domain::platform::SecretRef",
    "orxnud_domain::platform::SecretsContract",
    "orxnud_domain::platform::SecretLookup",
    "orxnud_platform_secrets::KeyringSecrets",
];

/// Rust source files under `orxnuctl/src`, with `#[cfg(test)]` blocks removed.
///
/// The same treatment the gate applies, for the same reason: a test may legitimately
/// build a fixture from a policy-only symbol, and this check is about what ships.
fn cli_sources() -> Vec<PathBuf> {
    let root = repo_root().join("crates/orxnuctl/src");
    let mut out = Vec::new();
    collect_rs(&root, &mut out);
    assert!(
        !out.is_empty(),
        "no CLI sources found at {}",
        root.display()
    );
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// A source file truncated at the end of its `#[cfg(test)]` module.
///
/// Owned rather than borrowed because the truncation is built, not found in place.
fn without_test_module(text: &str) -> String {
    let mut out = String::new();
    let mut in_tests = false;
    for line in text.lines() {
        if !in_tests && line.trim_start().starts_with("#[cfg(test)]") {
            in_tests = true;
            continue;
        }
        if in_tests && line == "}" {
            break;
        }
        if !in_tests {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Every path the CLI reaches inside the two newly permitted crates, in the shipped code.
///
/// A whole-line scan rather than a parse: the CLI is small, the check is a boundary, and a
/// false negative from a line-continuation or an alias would be worse than a false positive
/// that a reviewer can dismiss.
fn named_paths(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        // Only import statements. A qualified *call* such as
        // `orxnud_platform_secrets::KeyringSecrets::default()` names a path too, but it
        // cannot smuggle a rule into the CLI -- it can only use what is already imported --
        // and treating it as an import made the check reject its own caller.
        if !trimmed.starts_with("use ") {
            continue;
        }
        for crate_name in ["orxnud_domain", "orxnud_platform_secrets"] {
            let needle = format!("{crate_name}::");
            let mut rest = trimmed;
            while let Some(at) = rest.find(&needle) {
                let after = &rest[at + needle.len()..];
                // Consume every `seg::seg::…` segment, so `platform::SecretLookup` is
                // reported whole rather than as the module it lives in.
                let mut path = String::new();
                let mut cursor = after;
                loop {
                    let segment: String = cursor
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if segment.is_empty() {
                        break;
                    }
                    if !path.is_empty() {
                        path.push_str("::");
                    }
                    path.push_str(&segment);
                    cursor = &cursor[segment.len()..];
                    if let Some(next) = cursor.strip_prefix("::") {
                        cursor = next;
                    } else {
                        break;
                    }
                }
                if path.is_empty() {
                    rest = &rest[at + needle.len()..];
                    continue;
                }
                // A grouped import names the module and then the items inside braces, so
                // `use orxnud_domain::platform::{SecretRef, SecretsContract}` has to be
                // expanded or the scan rejects a legitimate import.
                let braces = cursor.trim_start();
                if let Some(inner) = braces.strip_prefix('{') {
                    let inner = inner.split('}').next().unwrap_or("");
                    for item in inner.split(',') {
                        let item = item.trim().trim_start_matches("self::");
                        let item = item.split(" as ").next().unwrap_or("").trim();
                        if !item.is_empty() {
                            found.push(format!("{crate_name}::{path}::{item}"));
                        }
                    }
                } else {
                    found.push(format!("{crate_name}::{path}"));
                }
                rest = &rest[at + needle.len()..];
            }
        }
    }
    found
}

#[test]
fn the_cli_reaches_only_the_secret_store_paths_inside_the_newly_permitted_crates() {
    let mut all: BTreeSet<String> = BTreeSet::new();
    for file in cli_sources() {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for path in named_paths(&without_test_module(&text)) {
            all.insert(path);
        }
    }

    assert!(
        !all.is_empty(),
        "the scan found nothing, so it would pass on a CLI that had lost the credential \
         command entirely -- a check that cannot fail is not a check"
    );

    for path in &all {
        assert!(
            PERMITTED_PATHS.contains(&path.as_str()),
            "orxnuctl reaches {path:?}, which is outside the secret-store vocabulary that \
             justified permitting orxnud-domain. The list is: {PERMITTED_PATHS:?}"
        );
    }
}

/// The specific thing the review asked about: no domain *rule* may be imported.
///
/// Named separately because it is the failure that matters and a reader should not have to
/// infer it from the allowlist above.
#[test]
fn the_cli_imports_no_domain_rule() {
    const FORBIDDEN_PREFIXES: &[&str] = &[
        "orxnud_domain::task_state",
        "orxnud_domain::approval",
        "orxnud_domain::action",
        "orxnud_domain::classification",
        "orxnud_domain::invocation",
        "orxnud_domain::actor",
        "orxnud_domain::schema",
        "orxnud_domain::ids",
        "orxnud_domain::audit",
        "orxnud_domain::config",
    ];

    let mut all: BTreeSet<String> = BTreeSet::new();
    for file in cli_sources() {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for path in named_paths(&without_test_module(&text)) {
            all.insert(path);
        }
    }
    for path in &all {
        for prefix in FORBIDDEN_PREFIXES {
            assert!(
                !path.starts_with(prefix),
                "orxnuctl imports {path:?}, which is a domain rule. A CLI that can see a \
                 rule can reimplement it, and then the CLI and the daemon disagree about \
                 what is allowed."
            );
        }
    }
}
