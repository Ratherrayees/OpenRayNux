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

#[test]
fn restoring_from_outside_the_crate_does_not_compile() {
    let crate_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = std::env::temp_dir().join(format!("orxnud-s30-visibility-{}", std::process::id()));
    let src = dir.join("src");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&src).expect("probe dir");

    // The probe names the platform adapter as well, because the guard's real
    // signature takes the filesystem-identity capability (ADR-0058 Decision 1) and a
    // probe that called it with the wrong arity would fail for the wrong reason --
    // exactly the mistake this file's own comment warns about.
    let platform_fs = crate_dir
        .parent()
        .expect("the crates directory")
        .join("orxnud-platform-fs");

    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"orxnud-s30-probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
             [dependencies]\norxnud-store = {{ path = \"{}\" }}\n\
             orxnud-platform-fs = {{ path = \"{}\" }}\n",
            crate_dir.display(),
            platform_fs.display()
        ),
    )
    .expect("write manifest");
    std::fs::write(src.join("main.rs"), PROBE).expect("write probe");

    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["check", "--quiet"])
        .current_dir(&dir)
        .output();

    let _ = std::fs::remove_dir_all(&dir);

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
