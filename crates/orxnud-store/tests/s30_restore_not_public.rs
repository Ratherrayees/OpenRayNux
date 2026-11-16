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
//!
//! **What needs the index, and what does not.** Preparing a cache needs the index,
//! because `cargo vendor` resolves the graph before it copies the sources. That is
//! a ONE-TIME step, and it is why the cache exists. So:
//!
//!   * the PROBE test -- the visibility assertion itself -- needs no index at all
//!     once a cache exists, and it demonstrates that by hiding the vendor tree and
//!     watching the build fail at the dependency source;
//!   * the cache-key test and the wrong-reason test are pure and need nothing;
//!   * the cache-validation test drives the preparation with a fake cargo, so it
//!     needs nothing either;
//!   * ONE test -- the one that asserts the guard holds against a POPULATED
//!     registry cache -- needs a populated registry by construction, because that
//!     is the scenario it exists to cover. It REFUSES when the registry is absent
//!     rather than passing for a weaker reason.

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
/// The probe project's own package name.
///
/// It is in the generated manifest, in the generated lockfile, and in the check
/// that compares the cached lockfile against the workspace's -- so it is named
/// once, here, rather than spelled in three places that could drift apart.
const PROBE_PACKAGE: &str = "orxnud-s30-probe";

fn probe_manifest(crate_dir: &std::path::Path, platform_fs: &std::path::Path) -> String {
    format!(
        "[package]\nname = \"{PROBE_PACKAGE}\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
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

/// One package a Cargo.lock names.
struct LockPin {
    name: String,
    version: String,
    /// Where the package comes from: the registry or git URL for a remote
    /// package, and absent for a local path dependency.
    ///
    /// This is the package's PROVENANCE, and it is COMPARED, not merely
    /// summarised as "remote": two packages of the same name and version from
    /// different registries are different packages, and a lockfile that swapped
    /// the source would otherwise pass the comparison.
    ///
    /// Its presence is also what makes a package remote, and that is what the
    /// vendored tree is built from: `cargo vendor` copies registry and git
    /// SOURCES, and leaves a path dependency where it is.
    source: Option<String>,
}

impl LockPin {
    /// Whether the package is one `cargo vendor` would have copied.
    fn is_remote(&self) -> bool {
        self.source.is_some()
    }
}

/// The packages a Cargo.lock names.
///
/// A Cargo.lock is a regular format: every package is a `[[package]]` block with
/// a `name` line and a `version` line, a `source` line when the package comes
/// from a registry or a git repository, and the workspace's own has nothing else.
/// Scanning for those keys is enough, and it keeps a TOML parser out of a test
/// that is about visibility.
///
/// A crate may appear at SEVERAL versions in one lockfile, so the pin -- name,
/// version and origin -- is the unit, not the name.
fn lockfile_pins(text: &str) -> Vec<LockPin> {
    let mut pins = Vec::new();
    for block in text.split("[[package]]").skip(1) {
        let field = |key: &str| -> Option<String> {
            let prefix = format!("{key} = \"");
            block.lines().map(str::trim).find_map(|line| {
                line.strip_prefix(&prefix)?
                    .strip_suffix('"')
                    .map(str::to_string)
            })
        };
        let (Some(name), Some(version)) = (field("name"), field("version")) else {
            continue;
        };
        pins.push(LockPin {
            name,
            version,
            source: field("source"),
        });
    }
    pins
}

/// Whether a prepared project's lockfile pins only versions the workspace pins.
///
/// The prepared lockfile is the workspace's, pruned to the probe's graph, plus
/// the probe's own package. Every other pin must be a pin the workspace
/// already has -- at the SAME version. Without this, a cache whose lockfile was
/// removed or altered would still be accepted, and cargo would resolve from
/// whatever the vendored tree happened to contain rather than from the pins the
/// workspace chose.
fn lockfile_is_workspace_pinned(
    cached: &std::path::Path,
    workspace_lock: &str,
    vendor_dir: &std::path::Path,
) -> bool {
    let Ok(text) = std::fs::read_to_string(cached) else {
        return false;
    };
    let cached_pins = lockfile_pins(&text);
    if cached_pins.is_empty() {
        return false;
    }
    let workspace_pins = lockfile_pins(workspace_lock);
    // Every pin the cache carries must be a pin the workspace has -- the SAME
    // name, the SAME version, and the SAME SOURCE -- the probe's own package
    // excepted. Comparing the source as well as the version is what stops a
    // lockfile that swapped a package for the same name and version from a
    // different registry.
    if !cached_pins.iter().all(|p| {
        p.name == PROBE_PACKAGE
            || workspace_pins
                .iter()
                .any(|w| w.name == p.name && w.version == p.version && w.source == p.source)
    }) {
        return false;
    }

    // The vendored tree must be COMPLETE for the remote dependency set, in BOTH
    // directions:
    //
    //   * every REMOTE pin -- a registry or git package -- must have its
    //     directory in the tree, because that is where its source lives. A pin
    //     with no directory is a source the build cannot use;
    //   * every directory in the tree must correspond to a pin, because a
    //     directory with no pin is a crate the build would resolve to a version
    //     nobody chose.
    //
    // A one-way check would miss both an EMPTY tree (every remote pin absent) and
    // a tree that has been partly deleted (the surviving directories all match).
    // Path dependencies are NOT vendored -- cargo leaves them where they are --
    // so they take no part in the first direction.
    let mut vendored: Vec<String> = Vec::new();
    let entries = match std::fs::read_dir(vendor_dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    for entry in entries {
        // An entry that cannot be read is a VALIDATION FAILURE, not a skipped
        // one: `flatten()` would drop the error and the tree would look smaller
        // than it is.
        let Ok(entry) = entry else {
            return false;
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => return false,
        };
        // A vendored crate is a DIRECTORY. `cargo vendor` copies the crate's
        // source into one, so a plain FILE or a SYMLINK with the right NAME is
        // not that source -- the build would fail on it later, when it wanted
        // the crate. `file_type()` does not follow symlinks, so a symlink is
        // rejected here too.
        if !file_type.is_dir() {
            return false;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            return false;
        };
        vendored.push(name);
    }
    for p in &cached_pins {
        if !p.is_remote() {
            continue;
        }
        // `--versioned-dirs` names each vendored crate `<name>-<version>`. The
        // crate's own name may contain dashes, so the directory is MATCHED
        // against the pins rather than split apart.
        if !vendored
            .iter()
            .any(|d| d == &format!("{}-{}", p.name, p.version))
        {
            return false;
        }
    }
    for d in &vendored {
        // Only a REMOTE package is vendored: `cargo vendor` copies registry and
        // git sources and leaves a path dependency where it is. A directory named
        // after a LOCAL package is not something cargo put there, so it does not
        // satisfy the check -- and it must not be able to stand in for a missing
        // remote package.
        if !cached_pins
            .iter()
            .any(|p| p.is_remote() && format!("{}-{}", p.name, p.version) == *d)
        {
            return false;
        }
    }
    true
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

/// Whether a prepared cache is the one this preparation would produce.
///
/// The cache is reused whenever its marker file exists, so a marker alone is NOT
/// evidence that the cache is usable. A damaged or edited cache can keep an empty
/// `.cargo/config.toml`, and cargo would then resolve the probe's dependencies
/// through Cargo's ordinary registry sources -- and the probe would STILL fail
/// with the privacy error, so the visibility test would pass having established
/// nothing about hermeticity.
///
/// That is measured, not hypothesised: with the local registry cache populated and
/// the configuration emptied, the probe fails with exactly the same E0603/E0624
/// privacy errors it produces when the vendored tree is used. The visibility
/// answer is identical; the guarantee behind it is not.
///
/// So the contents are compared with the generated strings byte for byte, the
/// vendor tree is required, and the prepared lockfile must pin only versions the
/// workspace pins. A cache that fails the comparison is not trusted: it is
/// rebuilt.
fn cache_is_valid(
    dir: &std::path::Path,
    manifest: &str,
    cargo_config: &str,
    workspace_lock: &str,
) -> bool {
    let read = |path: std::path::PathBuf| std::fs::read_to_string(path).ok();
    read(dir.join("Cargo.toml")).as_deref() == Some(manifest)
        && read(dir.join(".cargo").join("config.toml")).as_deref() == Some(cargo_config)
        && dir.join("vendor").is_dir()
        && lockfile_is_workspace_pinned(
            &dir.join("Cargo.lock"),
            workspace_lock,
            &dir.join("vendor"),
        )
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
    // A cache is reused only if it is the one this preparation would produce. A
    // damaged cache is REBUILT rather than accepted: the rebuild replaces the
    // directory wholesale, so nothing damaged can survive into the prepared tree.
    //
    // The workspace lockfile is needed to validate an existing cache and to seed
    // a new one. A lockfile that cannot be read cannot validate a cache, so the
    // cache is not reused; the seeding copy below then refuses with the reason,
    // rather than the failure being swallowed here.
    let workspace_lock = workspace_root.join("Cargo.lock");
    let workspace_lock_text = std::fs::read_to_string(&workspace_lock).ok();
    let cache_is_usable = workspace_lock_text
        .as_deref()
        .is_some_and(|text| cache_is_valid(dir, manifest, cargo_config, text));
    if cache_is_usable {
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

/// Whether the probe's failure was a PRIVACY diagnostic naming the mechanism this
/// test is about.
///
/// A bare error code is not enough, and a bare identifier is not enough either.
/// rustc's diagnostic for a type mismatch mentions `RestoreGuard` in the source
/// excerpt, and one for a wrong argument count mentions it in the note. Both are
/// E0308/E0061 failures, not privacy failures -- and both are what rustc would
/// say if `restore` were made PUBLIC with a changed signature, which is exactly
/// the regression this test exists to catch. A matcher that accepted any mention
/// of the name would report the mechanism as unreachable while it was reachable.
///
/// So the code must be one of rustc's two privacy codes AND the message must name
/// the item that has to stay unreachable: the `RestoreGuard` type, or the
/// `acquire`/`restore` method. Both must appear on the SAME diagnostic line, so
/// that an unrelated privacy error elsewhere in the output cannot be paired with
/// the name appearing in a source excerpt.
/// Strips the ANSI escape sequences a colourised diagnostic carries.
///
/// The CI workflow sets `CARGO_TERM_COLOR: always`, so rustc's diagnostics arrive
/// with the escape sequences in them, and the header is split across them:
///
/// ```text
/// ESC[1mESC[91merror[E0603]ESC[0mESC[1m: struct `RestoreGuard` is privateESC[0m
/// ```
///
/// The escapes are presentation, not content: the code and the item are still on the
/// SAME diagnostic line, which is the property the matcher is about. Matching the raw
/// line would therefore fail on CI while passing locally, and the test would have
/// proved nothing about the mechanism -- it would have proved that the host's colour
/// setting was off.
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            // CSI: ESC [ ... <final byte in @..~>
            Some('[') => {
                chars.next();
                for c in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&c) {
                        break;
                    }
                }
            }
            // OSC: ESC ] ... BEL, or ESC ] ... ESC \
            Some(']') => {
                chars.next();
                while let Some(c) = chars.next() {
                    if c == '\u{7}' {
                        break;
                    }
                    if c == '\u{1b}' {
                        chars.next();
                        break;
                    }
                }
            }
            // Any other two-byte escape.
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    out
}

fn privacy_failure(stderr: &str) -> bool {
    // The code and the item must be on the SAME diagnostic line. rustc prints the
    // item in the diagnostic's own header:
    //
    //   error[E0603]: struct `RestoreGuard` is private
    //   error[E0624]: method `restore` is private
    //
    // and the source excerpt that follows repeats the name. Searching the whole
    // stderr would therefore pair an unrelated E0603 -- on a DIFFERENT item --
    // with the name appearing in the excerpt, and accept the wrong failure.
    //
    // The colour escapes are stripped first: they are presentation, and they split
    // the header so that a plain prefix match would miss the very diagnostic it is
    // looking for on a host that colourises its output.
    stderr.lines().any(|line| {
        let line = strip_ansi(line);
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("error[E0603]:") {
            rest.contains("RestoreGuard")
        } else if let Some(rest) = line.strip_prefix("error[E0624]:") {
            rest.contains("`acquire`") || rest.contains("`restore`")
        } else {
            false
        }
    })
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
        .args(["check", "--quiet", "--offline", "--locked"])
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
    assert!(
        privacy_failure(&stderr),
        "the probe must fail specifically because the restore path is unreachable from \
         outside the crate -- a private `RestoreGuard`, a private `acquire` or \
         `restore`, or a combination. A probe that fails for an unrelated reason \
         proves nothing. cargo said:\n{stderr}"
    );

    // And the build must be PINNED to the lockfile. `--locked` means cargo may
    // not update it: with the lockfile removed, cargo would otherwise regenerate
    // the resolution from whatever the vendored tree happened to contain --
    // versions the workspace did not pin, and the very guarantee this probe
    // exists to check. So the build must fail, and it must fail on the
    // LOCKFILE rather than on the privacy diagnostic.
    let cached_lock = dir.join("Cargo.lock");
    let lock_backup = dir.join("Cargo.lock.probe-backup");
    std::fs::rename(&cached_lock, &lock_backup).expect("move the lockfile aside");
    let out = Command::new(&cargo)
        .args(["check", "--quiet", "--offline", "--locked"])
        .current_dir(dir)
        .output()
        .expect("run cargo check");
    std::fs::rename(&lock_backup, &cached_lock).expect("restore the lockfile");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert!(
        !out.status.success(),
        "with the lockfile removed the build must FAIL: cargo may not regenerate the \
         resolution from the vendored tree, because the workspace's pins are what \
         the probe is supposed to be checked against"
    );
    assert!(
        !privacy_failure(&stderr),
        "the failure must be the LOCKFILE, not the privacy diagnostic: if it is the \
         privacy error, cargo resolved the dependencies from somewhere other than \
         the lockfile. cargo said:\n{stderr}"
    );

    // And the probe must be BOUND to the vendored tree. With the vendor directory
    // hidden, the build must fail at the dependency source: source replacement is
    // exclusive, so cargo cannot fall back to the registry. If the build had
    // succeeded, the privacy error above would have come from a build that never
    // had the hermetic property -- it would have resolved the dependencies from
    // Cargo's ordinary registry sources instead.
    let vendor = dir.join("vendor");
    let hidden = dir.join("vendor.hidden");
    std::fs::rename(&vendor, &hidden).expect("hide the vendor tree");
    let out = Command::new(&cargo)
        .args(["check", "--quiet", "--offline", "--locked"])
        .current_dir(dir)
        .output()
        .expect("run cargo check");
    std::fs::rename(&hidden, &vendor).expect("restore the vendor tree");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    assert!(
        !out.status.success(),
        "with the vendor tree hidden the build must FAIL: if it succeeded, the probe \
         was compiled through Cargo's ordinary registry sources, and the privacy \
         error above proves nothing about hermeticity. cargo said:\n{stderr}"
    );
    assert!(
        !privacy_failure(&stderr),
        "the failure must be the dependency source, not the privacy diagnostic: if it \
         is the privacy error, the build reached type-checking, which means it \
         resolved the dependencies from somewhere other than the vendored tree. \
         cargo said:\n{stderr}"
    );
    assert!(
        stderr.contains("source") || stderr.contains("registry"),
        "the failure must name the dependency source it could not load. cargo said:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Failure injection for the preparation step.
//
// These drive prepare_probe() with a broken input and assert that it REFUSES. The
// property under test is not "the happy path works" -- the main test covers that --
// but that a broken preparation cannot be mistaken for a good one.
//
// The specific failure these guard against is the one this file already had: a
// preparation step that could be SKIPPED without anything saying so. A skipped
// step is indistinguishable from a successful one -- the probe then runs against
// Cargo's ordinary registry sources and reports the visibility answer without
// the hermetic property having been established -- so every preparation step
// returns a reason instead of being silently skipped.
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

/// A cache that has been damaged must not be silently trusted.
///
/// The cache is reused whenever its marker file exists, so the marker alone is not
/// evidence that the cache is usable. A damaged cache that keeps an EMPTY
/// `.cargo/config.toml` would let cargo resolve the probe's dependencies through
/// Cargo's ordinary registry sources -- and the probe would still fail with the
/// privacy error, so the visibility test would pass having established nothing
/// about hermeticity.
///
/// That is measured rather than hypothesised: with the local registry cache
/// populated and the configuration emptied, the probe fails with exactly the same
/// E0603/E0624 privacy errors it produces against the vendored tree. The
/// visibility ANSWER is identical; the guarantee behind it is not.
///
/// So the cache contents are compared with the generated strings byte for byte
/// and the vendor tree is required, and an invalid cache is rebuilt rather than
/// accepted.
#[test]
fn a_damaged_cache_is_rebuilt_rather_than_trusted() {
    // A SCRATCH workspace with a MINIMAL lockfile, because the vendored tree has
    // to correspond to the remote pins EXACTLY: the real workspace's lockfile
    // carries hundreds of remote pins, and no fixture tree can hold them all.
    //
    // The two remote pins below are real registry packages at real versions, and
    // the local one is a PATH dependency -- which `cargo vendor` does NOT copy,
    // because cargo leaves a path dependency where it is. The fixture therefore
    // has the shape a real vendored tree has, rather than one that vendors a
    // path dependency.
    let dir = std::env::temp_dir().join(format!("orxnud-s30-damaged-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");

    let crate_dir = dir.join("crates").join("orxnud-store");
    std::fs::create_dir_all(&crate_dir).expect("scratch crate dir");
    std::fs::write(crate_dir.join("Cargo.toml"), "[package]\nname=\"x\"\n").expect("manifest");
    let platform_fs = dir.join("crates").join("orxnud-platform-fs");
    let workspace_root = dir.join("workspace");
    std::fs::create_dir_all(&workspace_root).expect("scratch workspace dir");
    let workspace_lock_text = "version = 3\n\n\
        [[package]]\nname = \"bitflags\"\nversion = \"2.13.2\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
        [[package]]\nname = \"cfg-if\"\nversion = \"1.0.5\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
        [[package]]\nname = \"orxnud-store\"\nversion = \"0.1.0\"\n";
    std::fs::write(workspace_root.join("Cargo.lock"), workspace_lock_text).expect("lockfile");

    let manifest = probe_manifest(&crate_dir, &platform_fs);
    let cargo_config = probe_cargo_config();
    let probe = dir.join("probe");

    // A fake cargo whose `vendor` step creates the vendor directory and succeeds.
    // The property under test is the cache's VALIDATION, not the vendoring, so a
    // fake is what this test needs -- and it keeps the test independent of the
    // registry index. The counter records how many times the vendoring step ran,
    // which is how a REBUILD is distinguished from an ACCEPT.
    let calls = dir.join("vendor-calls");
    let fake_cargo = dir.join("cargo");
    let script = [
        "#!/bin/sh\n",
        "echo x >> \"",
        &calls.display().to_string(),
        "\"\n",
        "if [ \"$1\" = \"vendor\" ]; then\n",
        "  for last; do :; done\n",
        // The vendored crates, one directory per REMOTE pin -- a registry package
        // at its version, exactly as `cargo vendor --versioned-dirs` names them.
        // The local path dependency is deliberately NOT among them, because cargo
        // does not vendor a path dependency.
        "  mkdir -p \"$last/bitflags-2.13.2\" \"$last/cfg-if-1.0.5\"\n",
        "fi\n",
        "exit 0\n",
    ]
    .concat();
    std::fs::write(&fake_cargo, script).expect("fake cargo");
    make_executable(&fake_cargo);
    let vendor_calls = || -> usize {
        std::fs::read_to_string(&calls)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    };

    // A valid cache.
    prepare_probe(
        &probe,
        &manifest,
        &cargo_config,
        &workspace_root,
        &fake_cargo,
    )
    .expect("the first preparation must succeed");
    assert!(
        cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "a freshly prepared cache must be valid"
    );
    assert_eq!(vendor_calls(), 1, "the vendoring step must have run once");

    // Damage it: the marker file stays, but the configuration is emptied.
    std::fs::write(probe.join(".cargo").join("config.toml"), "").expect("damage the config");
    assert!(
        probe.join(".cargo").join("config.toml").is_file(),
        "the marker file must still be present: a damaged cache that LOOKS prepared \
         is the case under test"
    );
    assert!(
        !cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "a cache with an emptied configuration must not be valid"
    );

    // The retry must rebuild, not accept.
    prepare_probe(
        &probe,
        &manifest,
        &cargo_config,
        &workspace_root,
        &fake_cargo,
    )
    .expect("the retry must rebuild the damaged cache");
    assert!(
        cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "the damaged cache must have been rebuilt, not silently trusted: an accepted \
         damaged cache lets the probe compile through Cargo's ordinary registry \
         sources while still reporting the privacy error"
    );
    assert_eq!(
        vendor_calls(),
        2,
        "the vendoring step must have run a SECOND time: an accepted damaged cache \
         would not have been rebuilt, and the probe would then compile through \
         Cargo's ordinary registry sources"
    );
    assert_eq!(
        std::fs::read_to_string(probe.join(".cargo").join("config.toml")).ok(),
        Some(cargo_config.clone()),
        "the rebuilt cache must carry the generated configuration, not the damaged one"
    );
    assert!(
        lockfile_is_workspace_pinned(
            &probe.join("Cargo.lock"),
            workspace_lock_text,
            &probe.join("vendor"),
        ),
        "the rebuilt cache must carry a lockfile that pins only the workspace's \
         versions"
    );

    // Now the LOCKFILE, on its own. Everything else is intact, so this isolates
    // the lockfile check: a cache whose lockfile was removed would otherwise be
    // accepted, and cargo would resolve from whatever the vendored tree happened
    // to contain rather than from the workspace's pins. Damaged together with
    // the configuration, this assertion would pass for the wrong reason -- the
    // configuration mismatch alone would make the cache invalid.
    std::fs::remove_file(probe.join("Cargo.lock")).expect("remove the lockfile");
    assert!(
        !cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "a cache whose lockfile was removed must not be valid: with everything else \
         intact, only the lockfile check can reject it"
    );

    // And the retry rebuilds it.
    prepare_probe(
        &probe,
        &manifest,
        &cargo_config,
        &workspace_root,
        &fake_cargo,
    )
    .expect("the retry must rebuild the cache whose lockfile was removed");
    assert!(
        cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "the cache must have been rebuilt after its lockfile was removed"
    );
    assert!(
        lockfile_is_workspace_pinned(
            &probe.join("Cargo.lock"),
            workspace_lock_text,
            &probe.join("vendor"),
        ),
        "the rebuilt cache must carry a lockfile that pins only the workspace's \
         versions"
    );
    assert_eq!(
        vendor_calls(),
        3,
        "the vendoring step must have run a THIRD time: an accepted cache with a \
         missing lockfile would not have been rebuilt"
    );

    // And a TRUNCATED but still parseable lockfile. Every pin it still carries is
    // a workspace pin, so the subset check above accepts it -- but the vendored
    // tree holds a crate it no longer pins, so the cache is not complete for what
    // it will build. Without the completeness check this cache would be accepted
    // and the build would fail LATER, when cargo found the resolution
    // incomplete, rather than the cache being rebuilt.
    let lock_text = std::fs::read_to_string(probe.join("Cargo.lock")).expect("read lockfile");
    let truncated: String = lock_text
        .split_inclusive("[[package]]")
        .filter(|block| !block.contains("name = \"bitflags\""))
        .collect();
    assert_ne!(
        truncated, lock_text,
        "the truncation must have removed something"
    );
    assert!(
        !lockfile_pins(&truncated).is_empty(),
        "the truncated lockfile must still parse and still carry pins: it has to be a \
         lockfile that LOOKS usable, so that the completeness check is what rejects it"
    );
    std::fs::write(probe.join("Cargo.lock"), &truncated).expect("truncate the lockfile");
    assert!(
        !cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "a lockfile that no longer pins a vendored crate must not be valid: it is \
         incomplete for the tree it will build"
    );

    // And a lockfile that pins a version the WORKSPACE does not pin, for a crate
    // that is NOT in the vendor tree -- a path dependency. The completeness check
    // cannot see it: the crate is not vendored, so there is no directory to match
    // it against. The subset check is what rejects it, so this case is what keeps
    // that half of the guard from going untested.
    let bumped = lock_text.replace(
        "name = \"orxnud-store\"\nversion = \"0.1.0\"",
        "name = \"orxnud-store\"\nversion = \"9.9.9\"",
    );
    assert_ne!(
        bumped, lock_text,
        "the version bump must have changed something"
    );
    std::fs::write(probe.join("Cargo.lock"), &bumped).expect("bump the lockfile");
    assert!(
        !cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "a lockfile that pins a version the workspace does not pin must not be valid"
    );

    // Put the lockfile back, so the cases below test the VENDOR TREE and not the
    // lockfile damage that precedes them.
    std::fs::write(probe.join("Cargo.lock"), &lock_text).expect("restore the lockfile");
    assert!(
        cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "the cache must be valid again before the vendor-tree cases"
    );

    // An EMPTY vendor tree. Every remote pin is missing from it, so the tree
    // does not correspond to the lockfile -- but a one-way check, which only
    // asked whether each directory had a pin, would see an empty tree and pass.
    for entry in std::fs::read_dir(probe.join("vendor")).expect("vendor dir") {
        let entry = entry.expect("vendor entry");
        std::fs::remove_dir_all(entry.path()).expect("remove a vendored crate");
    }
    assert!(
        !cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "an EMPTY vendor tree must not be valid: every remote pin is missing from it"
    );

    // A PARTLY deleted vendor tree: one crate is gone and the rest survive. The
    // surviving directory still has a matching pin, so only the direction that
    // asks whether every remote pin has a directory can see this.
    std::fs::create_dir_all(probe.join("vendor").join("bitflags-2.13.2")).expect("restore one");
    assert!(
        !cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "a vendor tree missing a crate must not be valid, even when the crates that \
         remain all have matching pins"
    );

    // A directory in the tree that no pin accounts for: a crate the build would
    // resolve to a version nobody chose.
    std::fs::create_dir_all(probe.join("vendor").join("cfg-if-1.0.5")).expect("restore the other");
    std::fs::create_dir_all(probe.join("vendor").join("ghost-1.0.0")).expect("add a stray crate");
    assert!(
        !cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "a vendor directory that no lockfile pin accounts for must not be valid"
    );

    // And the whole tree back, so the cache is valid again.
    std::fs::remove_dir_all(probe.join("vendor").join("ghost-1.0.0")).expect("remove the stray");
    assert!(
        cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "the restored vendor tree must be valid again"
    );

    // A plain FILE where a package directory should be. The name matches the pin,
    // so a check on names alone would accept it -- but the source cargo would
    // load from it is not there.
    let crate_dir_path = probe.join("vendor").join("bitflags-2.13.2");
    std::fs::remove_dir_all(&crate_dir_path).expect("remove the crate directory");
    std::fs::write(&crate_dir_path, "not a crate\n").expect("replace it with a file");
    assert!(
        !cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "a regular file where a package directory should be must not be valid: the \
         name matches the pin, but the source is not there"
    );
    std::fs::remove_file(&crate_dir_path).expect("remove the file");
    std::fs::create_dir_all(&crate_dir_path).expect("restore the crate directory");

    // A directory named after a LOCAL path dependency. `cargo vendor` does not
    // vendor a path dependency, so nothing of that name belongs in the tree, and
    // it must not be able to stand in for a remote package either.
    std::fs::create_dir_all(probe.join("vendor").join("orxnud-store-0.1.0"))
        .expect("add a local crate");
    assert!(
        !cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "a directory matching a LOCAL path dependency must not be valid: cargo \
         does not vendor a path dependency"
    );
    std::fs::remove_dir_all(probe.join("vendor").join("orxnud-store-0.1.0")).expect("remove it");

    // The SAME name and version from a DIFFERENT source. The package is not the
    // one the workspace pins, and comparing only the name and the version would
    // not see the difference.
    let swapped = lock_text.replace(
        "source = \"registry+https://github.com/rust-lang/crates.io-index\"",
        "source = \"registry+https://example.invalid/other-index\"",
    );
    assert_ne!(
        swapped, lock_text,
        "the source swap must have changed something"
    );
    std::fs::write(probe.join("Cargo.lock"), &swapped).expect("swap the source");
    assert!(
        !cache_is_valid(&probe, &manifest, &cargo_config, workspace_lock_text),
        "a pin whose source is not the one the workspace pins must not be valid"
    );
    std::fs::write(probe.join("Cargo.lock"), &lock_text).expect("restore the lockfile");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A probe that failed for ANOTHER reason must not satisfy the visibility check.
///
/// A diagnostic that merely mentions `restore` or `RestoreGuard` is not evidence
/// that the access-control boundary was what stopped the probe. If `restore` were
/// made public with a changed signature, the probe would fail with a TYPE error
/// that names `RestoreGuard` -- and a matcher that accepted any mention of the
/// name would report the mechanism as unreachable while it was reachable.
///
/// The cases below are REAL rustc diagnostics, produced by compiling against a
/// throwaway crate whose `restore` is public, so they are what rustc actually
/// says rather than a hand-written approximation. The product crate is not
/// modified.
#[test]
fn a_failure_that_is_not_a_privacy_diagnostic_does_not_satisfy_the_visibility_check() {
    let dir = std::env::temp_dir().join(format!("orxnud-s30-wrongreason-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // A throwaway crate with the same SHAPE as the one under test, except that
    // `restore` and `RestoreGuard` are public -- which is what the bypass would
    // look like if the boundary were broken.
    let fake = dir.join("fake");
    std::fs::create_dir_all(fake.join("src")).expect("fake crate dir");
    std::fs::write(
        fake.join("Cargo.toml"),
        "[package]\nname = \"orxnud_store\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .expect("fake manifest");
    std::fs::write(
        fake.join("src").join("lib.rs"),
        "pub mod backup {\n    pub struct Backup;\n    pub struct RestoreGuard;\n    impl Backup {\n        pub fn restore(&self, _guard: &RestoreGuard) {}\n    }\n}\n\
         pub(crate) mod seams {}\n",
    )
    .expect("fake source");

    let probe = dir.join("probe");
    std::fs::create_dir_all(probe.join("src")).expect("probe dir");
    std::fs::write(
        probe.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
         [dependencies]\norxnud_store = { path = \"../fake\" }\n\n[workspace]\n",
    )
    .expect("probe manifest");

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let check = |source: &str| -> String {
        std::fs::write(probe.join("src").join("main.rs"), source).expect("write probe");
        let out = Command::new(&cargo)
            .args(["check", "--quiet", "--offline"])
            .current_dir(&probe)
            .output()
            .expect("run cargo check");
        assert!(
            !out.status.success(),
            "the probe must fail to compile, or the case under test proves nothing. \
             The source was:\n{source}"
        );
        String::from_utf8_lossy(&out.stderr).into_owned()
    };

    // The wrong ARGUMENT TYPE: rustc says E0308 and names `RestoreGuard` in the
    // expected/found types and in the source excerpt.
    let wrong_type = check(
        "fn bypass(b: &orxnud_store::backup::Backup, db: &std::path::Path) {\n    b.restore(db).unwrap();\n}\nfn main() {}\n",
    );
    assert!(
        wrong_type.contains("E0308"),
        "this case must be a type mismatch. cargo said:\n{wrong_type}"
    );
    assert!(
        wrong_type.contains("RestoreGuard"),
        "this case must mention `RestoreGuard`, which is what the permissive matcher \
         accepted. cargo said:\n{wrong_type}"
    );
    assert!(
        !privacy_failure(&wrong_type),
        "a type mismatch must NOT satisfy the visibility check: it is what rustc \
         reports if `restore` is made public with a changed signature. cargo said:\n{wrong_type}"
    );

    // The wrong ARITY: rustc says E0061 and mentions `RestoreGuard` in the note.
    let wrong_arity = check(
        "fn bypass(b: &orxnud_store::backup::Backup, g: &orxnud_store::backup::RestoreGuard) {\n    b.restore(g, g).unwrap();\n}\nfn main() {}\n",
    );
    assert!(
        wrong_arity.contains("E0061"),
        "this case must be an arity mismatch. cargo said:\n{wrong_arity}"
    );
    assert!(
        !privacy_failure(&wrong_arity),
        "an arity mismatch must NOT satisfy the visibility check. cargo said:\n{wrong_arity}"
    );

    // A SECOND privacy error, about a DIFFERENT item, with the target name
    // appearing only in the source excerpt. The throwaway crate carries a
    // crate-private MODULE, so naming it from outside is an E0603 of its own --
    // and the excerpt repeats the whole source line, which mentions `RestoreGuard`
    // in a string literal. The old matcher saw "E0603" and "RestoreGuard" somewhere
    // in stderr and accepted; the code and the item must be on the SAME line.
    let other_privacy = check(
        "fn bypass(b: &orxnud_store::backup::Backup, db: &std::path::Path) {\n    let _ = (orxnud_store::seams, \"RestoreGuard\");\n}\nfn main() {}\n",
    );
    assert!(
        other_privacy.contains("E0603"),
        "this case must be a privacy error. cargo said:\n{other_privacy}"
    );
    assert!(
        other_privacy.contains("RestoreGuard"),
        "this case must mention `RestoreGuard` somewhere in the output, which is \
         what the permissive matcher accepted. cargo said:\n{other_privacy}"
    );
    assert!(
        !privacy_failure(&other_privacy),
        "a privacy error about a DIFFERENT item must NOT satisfy the visibility \
         check, even when the target name appears elsewhere in the output. \
         cargo said:\n{other_privacy}"
    );

    // And the matcher must still ACCEPT the real thing.
    assert!(
        privacy_failure("error[E0603]: struct `RestoreGuard` is private"),
        "the matcher must accept the private-type diagnostic"
    );
    assert!(
        privacy_failure("error[E0624]: method `restore` is private"),
        "the matcher must accept the private-method diagnostic"
    );
    assert!(
        privacy_failure("error[E0624]: associated function `acquire` is private"),
        "the matcher must accept the private-associated-function diagnostic"
    );
    assert!(
        !privacy_failure("error[E0603]: struct `SomeOtherType` is private"),
        "a privacy diagnostic about a DIFFERENT item must not satisfy the check: the \
         mechanism under test is the restore path specifically"
    );

    // The SAME diagnostics as a colourised rustc emits them. The CI workflow sets
    // `CARGO_TERM_COLOR: always`, and the escape sequences split the header so that
    // a plain prefix match would miss it: this test failed on a hosted runner for
    // exactly that reason, while passing everywhere the colour setting was off.
    // The escapes are presentation; the code and the item are still on the same
    // diagnostic line, which is the property the matcher is about.
    assert!(
        privacy_failure(
            "\u{1b}[1m\u{1b}[91merror[E0603]\u{1b}[0m\u{1b}[1m: struct `RestoreGuard` is private\u{1b}[0m"
        ),
        "the matcher must accept the private-type diagnostic with rustc's colour escapes"
    );
    assert!(
        privacy_failure(
            "\u{1b}[1m\u{1b}[91merror[E0624]\u{1b}[0m\u{1b}[1m: method `restore` is private\u{1b}[0m"
        ),
        "the matcher must accept the private-method diagnostic with rustc's colour escapes"
    );
    assert!(
        privacy_failure(
            "\u{1b}[1m\u{1b}[91merror[E0624]\u{1b}[0m\u{1b}[1m: associated function `acquire` is private\u{1b}[0m"
        ),
        "the matcher must accept the private-associated-function diagnostic with rustc's \
         colour escapes"
    );
    // And the discipline still holds once the escapes are stripped: a privacy error
    // about a DIFFERENT item must not satisfy the check, coloured or not.
    assert!(
        !privacy_failure(
            "\u{1b}[1m\u{1b}[91merror[E0603]\u{1b}[0m\u{1b}[1m: struct `SomeOtherType` is private\u{1b}[0m"
        ),
        "a privacy diagnostic about a DIFFERENT item must not satisfy the check, and the \
         colour escapes must not change that"
    );

    let _ = std::fs::remove_dir_all(&dir);
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
         exists to cover. This test needs a POPULATED REGISTRY CACHE by \
         construction -- it is the scenario under test -- so when the registry is \
         unavailable this test refuses rather than passing for a weaker reason."
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
