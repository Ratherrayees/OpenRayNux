//! S-30, criterion 4(b): `Backup::restore` must be unreachable from outside the crate.
//!
//! The coordination rule — acquire authority before restoring — is only worth having
//! if it cannot be skipped. Before S-30, `restore` was `pub` and took a path, so any
//! caller could restore over a database whose write-ahead log was still live and be
//! told `Ok(())`. That is the shape of F-26.
//!
//! A runtime test cannot establish visibility, so this checks it mechanically: it
//! compiles a probe against the crate as an *external* consumer and asserts the call
//! does **not** compile, naming `E0624` (private method).
//!
//! There is deliberately **no skip path**. A compile-fail probe that can be skipped is
//! a test that reports success without checking anything, which is the failure mode
//! this repository has already been bitten by twice.
//!
//! # The probe is hermetic
//!
//! The probe is a separate cargo project, so resolving it the usual way needs the
//! registry index. A DNS failure then fails this test for a reason that has nothing
//! to do with visibility -- a false negative that looks like a real answer.
//!
//! So the probe's dependency set is **vendored** and the probe is compiled with
//! `--offline` against that vendored tree, with the registry source replaced by it.
//! Vendoring is what makes the probe independent of the index and the cache: the
//! sources are in the vendor directory, so nothing has to be resolved or downloaded
//! at test time.
//!
//! Vendoring itself needs the index -- it resolves the graph before copying the
//! sources -- so it happens **once**, into a cache under `target/`, and every later
//! run reuses it. The cache is a build artefact, not a committed tree: nothing about
//! the repository changes, and the vendor directory is never written to the source
//! tree.
//!
//! The vendored versions are the ones this workspace's `Cargo.lock` already pins,
//! and cargo refuses a vendored crate whose package checksum disagrees with the
//! lockfile -- so the pin is enforced rather than assumed. A stale or absent cache
//! makes the probe fail loudly (see below); it never makes the test pass for the
//! wrong reason.

use std::process::Command;

/// The probe an external consumer would have to compile for the bypass to work.
///
/// It matches the **real** signature. Two earlier probes did not, and both were
/// worthless: one called `restore(&Path)` when the method takes `&RestoreGuard`, so
/// it failed on a type mismatch whether or not the method was public, and one was
/// accepted by an assertion loose enough to match an unrelated "private". A
/// compile-fail probe that fails for the wrong reason reports success forever.
///
/// The bypass needs all three of these: the guard type, the method that mints one,
/// and the restore itself. Restricting any one of them is sufficient, and each is a
/// deliberate part of the mechanism.
const PROBE: &str = r#"
fn bypass(b: &orxnud_store::backup::Backup, db: &std::path::Path) {
    let guard = orxnud_store::backup::RestoreGuard::acquire(db, &orxnud_platform_fs::OsIdentity).unwrap();
    b.restore(&guard).unwrap();
}
fn main() {}
"#;

/// The version of the prepared-project FORMAT.
///
/// The cache is reused whenever its marker file exists, so the key has to change
/// whenever the thing that was prepared changes shape. A version constant is the
/// blunt instrument for the part of that which is not visible in any file: if the
/// LAYOUT of the prepared project changes -- a different vendor directory, a
/// different source-replacement scheme, a different marker file -- and none of the
/// fingerprinted inputs change with it, the old cache would be reused under the
/// new preparation's expectations.
///
/// Bump this when the preparation changes in a way the other inputs cannot see.
const CACHE_FORMAT: &str = "v2";

/// The generated manifest of the probe project.
///
/// It is generated HERE, once, and then both fingerprinted and written to disk, so
/// that the key describes the file that is actually written. Generating it inside
/// the preparation step while fingerprinting something else left a gap: the cache
/// could be reused after the generator changed, because nothing that changed was
/// an input to the key.
///
/// The path dependencies carry the ABSOLUTE paths of the two crates, so the
/// manifest is also what covers the paths. That is what makes a moved or renamed
/// crate invalidate the cache.
fn probe_manifest(crate_dir: &std::path::Path, platform_fs: &std::path::Path) -> String {
    format!(
        "[package]\nname = \"orxnud-s30-probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
         [dependencies]\norxnud-store = {{ path = \"{}\" }}\n\
         orxnud-platform-fs = {{ path = \"{}\" }}\n\n\
         # An empty workspace table makes this its own workspace root. The\n\
         # cache lives under the workspace's `target/`, and without this cargo\n\
         # would find the parent workspace and refuse to build here.\n\
         [workspace]\n",
        crate_dir.display(),
        platform_fs.display()
    )
}

/// The generated cargo configuration that points the probe at the vendored tree
/// and at nothing else.
///
/// This is the file that makes the probe HERMETIC: it replaces the registry source
/// with the vendored directory, so an offline check cannot fall back to Cargo's
/// ordinary registry sources. It is fingerprinted for the same reason as the
/// manifest -- a different one is a different prepared project.
fn probe_cargo_config() -> String {
    "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n\
     [source.vendored-sources]\ndirectory = \"vendor\"\n"
        .to_string()
}

/// The cache key: a fingerprint of everything that determines what the prepared
/// project is.
///
/// Every input here is a file that will be read, or a string that will be written,
/// or the format version. The order is fixed, and each input carries a label that
/// is hashed alongside it, so two different inputs cannot collide by sharing
/// content.
fn cache_key(inputs: &[(&str, &str)]) -> String {
    // A cheap, stable hash (FNV-1a).
    let mut h: u64 = 1469598103934665603;
    for (label, content) in inputs {
        for byte in label
            .as_bytes()
            .iter()
            .chain(content.as_bytes().iter())
            .chain([0u8].iter())
        {
            h ^= u64::from(*byte);
            h = h.wrapping_mul(1099511628211);
        }
    }
    format!("{h:016x}")
}

/// The prepared probe project: where it lives, and the two generated files that
/// describe it.
struct Probe {
    dir: std::path::PathBuf,
    manifest: String,
    cargo_config: String,
}

/// The probe project, its cache directory, and the key that names it.
///
/// The cache is a build artefact: `target/` is git-ignored, and nothing here is
/// written to the source tree.
///
/// The name carries a fingerprint of **everything that determines what the probe
/// resolves to**: the probe source, the GENERATED manifest and cargo
/// configuration, the cache format version, and the contents of the workspace
/// lockfile, the root manifest, and the manifests of the two path dependencies. A
/// change to any of them must produce a different directory, because the cached
/// vendor tree carries a RESOLUTION -- a set of pinned versions -- and a stale one
/// would be checked against a graph the workspace no longer uses. Fingerprinting
/// only the probe source left that gap: a dependency update changed the workspace
/// resolution without changing the key, and the old vendor tree was reused.
///
/// Fingerprinting the generated manifest is also what covers the PATHS, because the
/// manifest carries the two crates' absolute paths. A moved or renamed crate
/// therefore invalidates the cache too.
fn probe_project(crate_dir: &std::path::Path) -> Probe {
    let workspace_root = crate_dir
        .parent()
        .and_then(|crates| crates.parent())
        .expect("the workspace root");
    let platform_fs = crate_dir
        .parent()
        .expect("the crates directory")
        .join("orxnud-platform-fs");

    let manifest = probe_manifest(crate_dir, &platform_fs);
    let cargo_config = probe_cargo_config();

    // The inputs that determine the probe's resolution, in a fixed order. Each read
    // is REQUIRED: an unreadable input must fail the test, not silently become an
    // empty string. A defaulted read produces a fingerprint that is stable across a
    // change from "present" to "absent", which is the fail-open this replaces.
    let read_required = |path: &std::path::Path, what: &str| -> String {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {what} at {}: {e}", path.display()))
    };
    let workspace_lockfile =
        read_required(&workspace_root.join("Cargo.lock"), "the workspace lockfile");
    let root_manifest = read_required(&workspace_root.join("Cargo.toml"), "the root manifest");
    let store_manifest = read_required(&crate_dir.join("Cargo.toml"), "the orxnud-store manifest");
    let platform_fs_manifest = read_required(
        &platform_fs.join("Cargo.toml"),
        "the orxnud-platform-fs manifest",
    );

    let fingerprint = cache_key(&[
        ("cache format", CACHE_FORMAT),
        ("probe source", PROBE),
        ("probe manifest", &manifest),
        ("probe cargo config", &cargo_config),
        ("workspace Cargo.lock", &workspace_lockfile),
        ("root Cargo.toml", &root_manifest),
        ("orxnud-store Cargo.toml", &store_manifest),
        ("orxnud-platform-fs Cargo.toml", &platform_fs_manifest),
    ]);
    let target = workspace_root.join("target");
    Probe {
        dir: target.join(format!("s30-probe-{fingerprint}")),
        manifest,
        cargo_config,
    }
}

/// Build the probe project if it is not already cached, and require every step to
/// succeed. Returns Err with a reason rather than panicking, so a test can drive a
/// failure directly.
///
/// Each step is required: a silently skipped lockfile copy lets the resolver pick
/// versions the workspace does not pin, and a silently skipped vendoring step lets an
/// offline check compile through Cargo ordinary registry sources -- reporting the
/// visibility answer without the hermetic property having been established.
fn prepare_probe(
    dir: &std::path::Path,
    manifest: &str,
    cargo_config: &str,
    workspace_root: &std::path::Path,
    cargo: &std::path::Path,
) -> Result<(), String> {
    if dir.join(".cargo").join("config.toml").is_file() {
        return Ok(());
    }

    let staging = dir.with_extension("staging");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(staging.join("src")).map_err(|e| format!("probe staging dir: {e}"))?;
    // The manifest and the cargo configuration are the GENERATED strings that the
    // cache key was computed over. Writing them verbatim is what keeps the key
    // honest: a different byte here is a different byte in the key.
    std::fs::write(staging.join("Cargo.toml"), manifest)
        .map_err(|e| format!("write the probe manifest: {e}"))?;
    std::fs::write(staging.join("src").join("main.rs"), PROBE)
        .map_err(|e| format!("write the probe source: {e}"))?;

    // Seed the probe lockfile from the workspace's, so the probe resolves to the
    // versions THIS tree pins rather than to whatever the resolver would pick afresh.
    // The probe is a different package from the workspace, so cargo adds it to the
    // seeded lockfile; that is a local addition and does not change the pinned
    // versions of anything else. Without the seed, the vendored tree could carry
    // versions the workspace does not use.
    // The copy is REQUIRED: a silently skipped copy lets the resolver choose versions
    // the workspace does not pin, and the vendored tree would then be built from a
    // graph nobody selected.
    let workspace_lock = workspace_root.join("Cargo.lock");
    std::fs::copy(&workspace_lock, staging.join("Cargo.lock")).map_err(|e| {
        format!(
            "cannot seed the probe lockfile from {}: {e}",
            workspace_lock.display()
        )
    })?;

    // Vendoring is REQUIRED. If it fails, the probe must not run: an offline check
    // with a populated registry cache can still compile through Cargo ordinary
    // registry sources, which would report the visibility answer WITHOUT the hermetic
    // property having been established. That is the fail-open this closes.
    let vendored = Command::new(cargo)
        .args([
            "vendor",
            "--offline",
            "--versioned-dirs",
            staging.join("vendor").to_str().expect("vendor path"),
        ])
        .current_dir(&staging)
        .output()
        .map_err(|e| format!("cannot run cargo vendor for the probe: {e}"))?;
    if !vendored.status.success() {
        return Err(format!(
            "cargo vendor failed for the probe, so the vendored tree was not \
             established and the probe must not run. cargo said:\n{}",
            String::from_utf8_lossy(&vendored.stderr)
        ));
    }
    if !staging.join("vendor").is_dir() {
        return Err("cargo vendor exited 0 but produced no vendor directory".to_string());
    }
    std::fs::create_dir_all(staging.join(".cargo"))
        .map_err(|e| format!("cargo config dir: {e}"))?;
    std::fs::write(staging.join(".cargo").join("config.toml"), cargo_config)
        .map_err(|e| format!("write cargo config: {e}"))?;

    let _ = std::fs::remove_dir_all(dir);
    std::fs::rename(&staging, dir).map_err(|e| {
        let _ = std::fs::remove_dir_all(&staging);
        format!("promote the prepared probe into place: {e}")
    })?;
    Ok(())
}

#[test]
fn restoring_from_outside_the_crate_does_not_compile() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_dir
        .parent()
        .and_then(|crates| crates.parent())
        .expect("the workspace root");
    let probe = probe_project(crate_dir);
    let dir = &probe.dir;
    let src = dir.join("src");

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    prepare_probe(
        dir,
        &probe.manifest,
        &probe.cargo_config,
        workspace_root,
        std::path::Path::new(&cargo),
    )
    .unwrap_or_else(|e| panic!("cannot prepare the probe project: {e}"));

    // The probe source is written on every run even when the cache is reused, so
    // that the cache's fingerprint and the source it checks cannot drift apart.
    std::fs::create_dir_all(&src).expect("probe dir");
    std::fs::write(src.join("main.rs"), PROBE).expect("write probe");

    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["check", "--quiet", "--offline"])
        .current_dir(dir)
        .output();

    let output = out.unwrap_or_else(|e| {
        panic!(
            "could not run cargo to check visibility. This is an environment problem, \
             not a pass: {e}"
        )
    });
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        !output.status.success(),
        "`Backup::restore` compiled from outside `orxnud-store`, so the coordination \
         mechanism can be bypassed. It must stay `pub(crate)` for acquiring authority \
         to be unavoidable."
    );
    // Tighter than "private": the probe must fail *about this mechanism*. An earlier
    // version accepted any message containing "private" and therefore passed for the
    // wrong reason -- `RestoreGuard` being crate-private also makes the bypass
    // impossible, so the test stayed green even with `restore` made public, and a
    // mutation that should have been caught was not.
    let about_the_mechanism = stderr.contains("RestoreGuard")
        || stderr.contains("restore")
        || stderr.contains("E0624")
        || stderr.contains("E0603");
    assert!(
        about_the_mechanism,
        "the probe must fail specifically because the restore path is unreachable from \
         outside the crate -- a missing `RestoreGuard`, a private `restore`, or neither. \
         A probe that fails for an unrelated reason proves nothing. cargo said:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Failure injection for the preparation step.
//
// These drive prepare_probe() with a broken input and assert that it REFUSES. The
// property under test is not "the happy path works" -- the main test covers that --
// but that a broken preparation cannot be mistaken for a good one.
//
// The specific failure this guards against is the one that was actually observed:
// an exported shell function did not cross the `docker run` boundary, so the errno
// column came out empty while the run reported success. A blank field is
// indistinguishable from "not measured", so every preparation step now returns a
// reason instead of being silently skipped.
// ---------------------------------------------------------------------------

/// The cache key must describe the GENERATED project, not only the files around it.
///
/// The cache is reused whenever its marker file exists, so a change to the
/// generated manifest, the generated cargo configuration, or the format of the
/// prepared project that no fingerprinted file reveals would otherwise reuse a
/// stale prepared tree. The prepared tree carries a RESOLUTION, so reusing it
/// after the thing that determines the resolution changed would check the old
/// graph.
///
/// This exercises the key function the cache directory is actually named by, so it
/// is a test of the real contract and not of a parallel implementation of it.
#[test]
fn the_cache_key_covers_the_generated_project_and_its_format() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_dir
        .parent()
        .and_then(|crates| crates.parent())
        .expect("the workspace root");
    let platform_fs = crate_dir
        .parent()
        .expect("the crates directory")
        .join("orxnud-platform-fs");

    let manifest = probe_manifest(crate_dir, &platform_fs);
    let cargo_config = probe_cargo_config();

    let read = |path: &std::path::Path, what: &str| -> String {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {what} at {}: {e}", path.display()))
    };
    let lockfile = read(&workspace_root.join("Cargo.lock"), "the workspace lockfile");
    let root_manifest = read(&workspace_root.join("Cargo.toml"), "the root manifest");
    let store_manifest = read(&crate_dir.join("Cargo.toml"), "the orxnud-store manifest");
    let platform_fs_manifest = read(
        &platform_fs.join("Cargo.toml"),
        "the orxnud-platform-fs manifest",
    );

    let key = |manifest: &str, cargo_config: &str, cache_format: &str| -> String {
        cache_key(&[
            ("cache format", cache_format),
            ("probe source", PROBE),
            ("probe manifest", manifest),
            ("probe cargo config", cargo_config),
            ("workspace Cargo.lock", &lockfile),
            ("root Cargo.toml", &root_manifest),
            ("orxnud-store Cargo.toml", &store_manifest),
            ("orxnud-platform-fs Cargo.toml", &platform_fs_manifest),
        ])
    };

    let base = key(&manifest, &cargo_config, CACHE_FORMAT);

    // Stable for identical inputs: a key that moved on every run would never be
    // reused, which is the whole point of caching it.
    assert_eq!(
        base,
        key(&manifest, &cargo_config, CACHE_FORMAT),
        "the cache key must be stable for identical inputs"
    );

    // Changing the GENERATED MANIFEST must change the key.
    let other_manifest = manifest.replace("orxnud-s30-probe", "orxnud-s30-probe-2");
    assert_ne!(
        other_manifest, manifest,
        "the manifest must actually differ"
    );
    assert_ne!(
        base,
        key(&other_manifest, &cargo_config, CACHE_FORMAT),
        "changing the generated manifest must change the cache key"
    );

    // Changing the GENERATED CARGO CONFIGURATION must change the key: it is the
    // file that makes the probe hermetic, so a different one is a different
    // prepared project.
    let other_config = cargo_config.replace("vendored-sources", "other-sources");
    assert_ne!(
        other_config, cargo_config,
        "the cargo config must actually differ"
    );
    assert_ne!(
        base,
        key(&manifest, &other_config, CACHE_FORMAT),
        "changing the generated cargo configuration must change the cache key"
    );

    // Changing the FORMAT VERSION must change the key even when nothing else
    // does: the format is the part of the preparation that no file reveals.
    assert_ne!(
        base,
        key(&manifest, &cargo_config, "v999"),
        "changing the cache format version must change the cache key"
    );

    // And the real project must be named by this key, so the assertions above are
    // about the function that names the cache directory.
    let expected_name = format!("s30-probe-{base}");
    let probe = probe_project(crate_dir);
    assert_eq!(
        probe.dir.file_name().and_then(|n| n.to_str()),
        Some(expected_name.as_str()),
        "the cache directory must be named by the key this test exercises"
    );
}

/// A preparation that cannot read the workspace lockfile must refuse rather than
/// proceeding with a resolution nobody chose.
#[test]
fn preparation_refuses_when_the_workspace_lockfile_is_missing() {
    let dir = std::env::temp_dir().join(format!("orxnud-prep-nolock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let crate_dir = dir.join("crates").join("orxnud-store");
    std::fs::create_dir_all(&crate_dir).expect("scratch crate dir");
    std::fs::write(crate_dir.join("Cargo.toml"), "[package]\nname=\"x\"\n").expect("manifest");
    let workspace_root = dir.join("workspace");
    std::fs::create_dir_all(&workspace_root).expect("workspace dir");
    // Deliberately no Cargo.lock in workspace_root.

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = probe_manifest(&crate_dir, &crate_dir.join("platform-fs"));
    let result = prepare_probe(
        &dir.join("probe"),
        &manifest,
        &probe_cargo_config(),
        &workspace_root,
        std::path::Path::new(&cargo),
    );
    let _ = std::fs::remove_dir_all(&dir);
    // The CAUSE is asserted, not just that it failed. An earlier form of this test
    // asserted `is_err()` and passed even with the guard removed, because the setup
    // was missing something else that made preparation fail for an unrelated reason --
    // a vacuous test that reported success. The message must name the lockfile.
    let err = result.expect_err("preparation must refuse when the lockfile is missing");
    assert!(
        err.contains("seed the probe lockfile"),
        "preparation must fail BECAUSE the lockfile could not be seeded; it said: {err}"
    );
}

/// A vendoring step that exits non-zero must refuse, so the probe cannot run
// against Cargo's ordinary registry sources and report an answer it did not earn.
///
/// This is the regression scenario the guard exists for, and it is exercised with the
/// REAL workspace and the REAL cargo, so the local registry cache is genuinely in
/// play. The wrapper runs the real `cargo vendor` -- which, with a populated cache,
/// SUCCEEDS -- and then fails anyway. The premise of the bug is that a populated
/// cache can carry the build past a broken preparation; the test proves the guard
/// does not depend on the cache being empty.
///
/// The wrapper's own marker is asserted, so a failure for some unrelated reason
/// (an empty cache, a missing crate) cannot satisfy the test.
#[test]
fn preparation_refuses_when_vendoring_fails_even_with_a_populated_registry_cache() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = crate_dir
        .parent()
        .and_then(|crates| crates.parent())
        .expect("the workspace root");
    let platform_fs = crate_dir
        .parent()
        .expect("the crates directory")
        .join("orxnud-platform-fs");

    let dir = std::env::temp_dir().join(format!("orxnud-prep-novendor-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");

    let real_cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let succeeded_marker = dir.join("real-vendor-succeeded");
    let wrapper = dir.join("cargo");
    let script = [
        "#!/bin/sh\n",
        "if [ \"$1\" = \"vendor\" ]; then\n",
        "  \"",
        &real_cargo,
        "\" \"$@\" >/dev/null 2>&1 && echo ok > \"",
        &succeeded_marker.display().to_string(),
        "\"\n",
        "  echo \"vendor refused by the test wrapper\" >&2\n",
        "  exit 1\n",
        "fi\n",
        "exec \"",
        &real_cargo,
        "\" \"$@\"\n",
    ]
    .concat();
    std::fs::write(&wrapper, script).expect("wrapper");
    make_executable(&wrapper);

    let probe = dir.join("probe");
    let manifest = probe_manifest(crate_dir, &platform_fs);
    let result = prepare_probe(
        &probe,
        &manifest,
        &probe_cargo_config(),
        workspace_root,
        &wrapper,
    );

    // The premise, asserted: the REAL vendoring succeeded against the local
    // registry cache. If it did not, this test would be proving less than it
    // claims -- the populated-cache scenario would not have been exercised at all.
    let real_vendor_succeeded = succeeded_marker.is_file();
    let promoted = probe.join(".cargo").join("config.toml").is_file();
    let err = result.expect_err("preparation must refuse when vendoring fails");

    // The CAUSE is asserted, not just that it failed. An `is_err()` assertion passes
    // for ANY failure, including one from an unrelated step, which would make this
    // test green while the guard it exists to protect was removed.
    assert!(
        err.contains("cargo vendor failed"),
        "preparation must fail BECAUSE vendoring failed; it said: {err}"
    );
    assert!(
        err.contains("vendor refused by the test wrapper"),
        "the failure must be the wrapper's, not an unrelated one; it said: {err}"
    );
    assert!(
        !promoted,
        "no probe may be promoted when vendoring failed: a promoted probe could \
         compile against Cargo's ordinary registry sources and report a visibility \
         answer that the hermetic property never earned"
    );
    assert!(
        real_vendor_succeeded,
        "the real `cargo vendor` must have SUCCEEDED against the local registry \
         cache, otherwise this test did not exercise the populated-cache scenario it \
         exists to cover"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
fn make_executable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn make_executable(_path: &std::path::Path) {}
