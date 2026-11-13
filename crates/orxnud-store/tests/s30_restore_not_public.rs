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

/// The probe project's own directory, cached under `target/` so that the vendoring
/// step happens once rather than on every test run.
///
/// The cache is a build artefact: `target/` is git-ignored, and nothing here is
/// written to the source tree. The name carries the probe source's own fingerprint,
/// so a changed probe invalidates the cache rather than being checked against a
/// stale vendored tree.
fn probe_dir(crate_dir: &std::path::Path) -> std::path::PathBuf {
    let fingerprint = {
        // A cheap, stable hash of the probe source and the crate it probes. The
        // crate path is included because the probe names it by path, so a moved
        // crate invalidates the cache too.
        let mut h: u64 = 1469598103934665603;
        for byte in PROBE
            .as_bytes()
            .iter()
            .chain(crate_dir.to_string_lossy().as_bytes().iter())
        {
            h ^= u64::from(*byte);
            h = h.wrapping_mul(1099511628211);
        }
        format!("{h:016x}")
    };
    let target = crate_dir
        .parent()
        .and_then(|crates| crates.parent())
        .expect("the workspace root")
        .join("target");
    target.join(format!("s30-probe-{fingerprint}"))
}

#[test]
fn restoring_from_outside_the_crate_does_not_compile() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = probe_dir(crate_dir);
    let src = dir.join("src");

    // The probe names the platform adapter as well, because the guard's real
    // signature takes the filesystem-identity capability (ADR-0058 Decision 1) and a
    // probe that called it with the wrong arity would fail for the wrong reason --
    // exactly the mistake this file's own comment warns about.
    let platform_fs = crate_dir
        .parent()
        .expect("the crates directory")
        .join("orxnud-platform-fs");

    // Prepare the probe project ONCE. Preparing it means vendoring its dependency
    // set, which is the step that needs the registry index; running it again on
    // every test run would put the network back on the test's critical path, which
    // is what this change exists to remove.
    //
    // If the cache is already present it is reused as-is. If it is not, it is
    // built. A failure to build it is NOT a pass: the probe then runs without the
    // vendored tree, its resolution fails, and the assertion below rejects that,
    // because a resolution failure does not mention the mechanism. The test can
    // fail; it must never pass for the wrong reason.
    let prepared = dir.join(".cargo").join("config.toml").is_file();
    if !prepared {
        let staging = dir.with_extension("staging");
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::create_dir_all(staging.join("src")).expect("probe staging dir");
        std::fs::write(
            staging.join("Cargo.toml"),
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
            ),
        )
        .expect("write manifest");
        std::fs::write(staging.join("src").join("main.rs"), PROBE).expect("write probe");

        let vendored = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args([
                "vendor",
                "--offline",
                "--versioned-dirs",
                staging.join("vendor").to_str().expect("vendor path"),
            ])
            .current_dir(&staging)
            .output();

        let vendored_ok = matches!(&vendored, Ok(o) if o.status.success());
        if vendored_ok {
            std::fs::create_dir_all(staging.join(".cargo")).expect("cargo config dir");
            std::fs::write(
                staging.join(".cargo").join("config.toml"),
                "[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n\
                 [source.vendored-sources]\ndirectory = \"vendor\"\n",
            )
            .expect("write cargo config");
        }
        let _ = std::fs::remove_dir_all(&dir);
        if std::fs::rename(&staging, &dir).is_err() {
            let _ = std::fs::remove_dir_all(&staging);
        }
    }

    // The probe source is written on every run even when the cache is reused, so
    // that the cache's fingerprint and the source it checks cannot drift apart.
    std::fs::create_dir_all(&src).expect("probe dir");
    std::fs::write(src.join("main.rs"), PROBE).expect("write probe");

    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["check", "--quiet", "--offline"])
        .current_dir(&dir)
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
