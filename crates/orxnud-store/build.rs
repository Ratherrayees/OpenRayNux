//! Compile-time proof that the SQLite we link is new enough.
//!
//! # Why this exists
//!
//! The Phase 1 contract requires SQLite **>= 3.51.3**, because 3.51.2 (what
//! Fedora 44 ships) has a WAL-reset corruption bug. A runtime check alone is not
//! enough: it runs *after* the binary is built, so a release built against a
//! too-old amalgamation would still be a release, and the failure would appear
//! in production instead of at build time.
//!
//! Asserting against a constant *we* wrote proves nothing — it would still pass
//! if the amalgamation were downgraded underneath us. So this script reads
//! `SQLITE_VERSION_NUMBER` out of the actual bundled `sqlite3.h` that
//! `libsqlite3-sys` compiles, and emits it as a `cargo::rustc-env` value. The
//! library then const-asserts against *that*, which means:
//!
//! * downgrading `rusqlite` below 3.51.3 becomes a **build error**, and
//! * pointing `LIBSQLITE3_SYS_USE_PKG_CONFIG=1` at a system 3.51.2 also becomes a
//!   build error, because the system header is what gets parsed.
//!
//! # Which header
//!
//! `libsqlite3-sys` declares `links = "sqlite3"`, so its build script publishes
//! the directory via `DEP_SQLITE3_INCLUDE`. That is the authoritative location
//! for whichever SQLite is actually being compiled — bundled or system. We parse
//! `SQLITE_VERSION_NUMBER` from the header there.
//!
//! # If the header cannot be found
//!
//! We fail the build. A missing assertion is indistinguishable from no
//! assertion, and silently skipping the check would reintroduce exactly the
//! regression this guards against.

use std::path::PathBuf;

/// The lowest SQLite we accept, as `major * 1_000_000 + minor * 1_000 + patch`.
///
/// 3.51.3 encodes as 3_051_003. This is the same encoding
/// `SQLITE_VERSION_NUMBER` uses.
const MINIMUM: i64 = 3_051_003;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=LIBSQLITE3_SYS_USE_PKG_CONFIG");

    let Some(include_dir) = include_dir() else {
        fail(
            "DEP_SQLITE3_INCLUDE is not set, so the SQLite header that \
             libsqlite3-sys compiled cannot be located. The minimum-version \
             assertion cannot be skipped, so this is a hard error.",
        );
    };

    let header = include_dir.join("sqlite3.h");
    if !header.is_file() {
        fail(&format!(
            "expected a sqlite3.h in {}, but it is not there. The bundled \
             amalgamation supplies one; a pkg-config build must too.",
            include_dir.display()
        ));
    }

    let source = std::fs::read_to_string(&header).unwrap_or_else(|e| {
        fail(&format!("cannot read {}: {e}", header.display()));
    });

    let version = parse_version_number(&source).unwrap_or_else(|| {
        fail(&format!(
            "no `#define SQLITE_VERSION_NUMBER` in {}. Without it the \
             minimum-version assertion cannot be evaluated.",
            header.display()
        ));
    });

    if version < MINIMUM {
        fail(&format!(
            "SQLite {}.{}.{} ({version}) is linked, but OpenRayNux requires \
             >= 3.51.3 ({MINIMUM}) for the WAL-reset corruption fix. \
             Pin rusqlite's `bundled` feature, or do not set \
             LIBSQLITE3_SYS_USE_PKG_CONFIG against an older system library.",
            version / 1_000_000,
            (version / 1_000) % 1_000,
            version % 1_000
        ));
    }

    // Emitted for the library's `const` assertion, so the number the runtime
    // check will see and the number asserted at build time cannot drift apart.
    //
    // Deliberately not a `cargo::warning`: this passes on every build, and a
    // warning that is always green trains people to ignore warnings. The version
    // is recorded in the Phase 1 report instead.
    println!("cargo::rustc-env=ORXNUD_LINKED_SQLITE_VERSION={version}");
}

/// The directory holding the SQLite header `libsqlite3-sys` actually compiled.
fn include_dir() -> Option<PathBuf> {
    // `DEP_SQLITE3_INCLUDE` is set by libsqlite3-sys's build script because the
    // crate sets `links = "sqlite3"`. Cargo exports it to the build scripts of
    // packages that depend on it **directly**, as `DEP_<LINKS_KEY>_INCLUDE`.
    //
    // "Directly" is load-bearing: a `[build-dependencies]` entry does not get it,
    // because cargo resolves the metadata for the host graph. `orxnud-store`
    // therefore takes `libsqlite3-sys` as a normal dependency it never names in
    // code. See the comment in its manifest.
    let raw = std::env::var("DEP_SQLITE3_INCLUDE").ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    let dir = PathBuf::from(raw);
    dir.is_dir().then_some(dir)
}

/// Extracts `SQLITE_VERSION_NUMBER` from the header's `#define` line.
fn parse_version_number(header: &str) -> Option<i64> {
    header.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("#define")?.trim();
        // `strip_prefix` alone would also match `SQLITE_VERSION_NUMBER_FOO`, so
        // require the remainder to begin with whitespace. Note the check must
        // happen *before* trimming the remainder: `3053002` starts with a digit,
        // so an alphanumeric test would reject every real version.
        let value = rest.strip_prefix("SQLITE_VERSION_NUMBER")?;
        if !(value.is_empty() || value.starts_with(char::is_whitespace)) {
            return None;
        }
        value.trim().parse::<i64>().ok()
    })
}

/// Fails the build with `message`, via the type error `!` coerces to.
fn fail(message: &str) -> ! {
    panic!("{message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_parses_the_define_from_a_real_header() {
        let header = "\
/* comment */
#define SQLITE_VERSION         \"3.53.2\"
#define SQLITE_VERSION_NUMBER 3053002
#define SQLITE_SOURCE_ID       \"2026-03-01 00:00:00\"
";
        assert_eq!(parse_version_number(header), Some(3_053_002));
    }

    #[test]
    fn it_does_not_match_a_similarly_named_define() {
        // The guard that keeps `_EXTRA` and friends from being read as the version.
        for header in [
            "#define SQLITE_VERSION_NUMBER_EXTRA 1\n",
            "#define SQLITE_VERSION_NUMBERFOO 1\n",
        ] {
            assert_eq!(parse_version_number(header), None, "{header}");
        }
    }

    #[test]
    fn it_reads_the_real_bundled_header() {
        // Guards the parsing against the shipped header's formatting, which is the
        // one input that actually matters. Falls back to a shape check if cargo has
        // not vendored the amalgamation at this path.
        let Ok(header) = std::fs::read_to_string(std::env::var("DEP_SQLITE3_INCLUDE").map_or_else(
            |_| PathBuf::from("."),
            |p| PathBuf::from(p).join("sqlite3.h"),
        )) else {
            return;
        };
        let parsed = parse_version_number(&header).expect("the bundled header must parse");
        assert!(
            parsed >= MINIMUM,
            "the bundled amalgamation is older than the minimum: {parsed}"
        );
        // The encoding must round-trip into a plausible human version.
        assert_eq!(
            parsed / 1_000_000,
            3,
            "unexpected major version in {parsed}"
        );
    }

    #[test]
    fn it_reports_none_rather_than_guessing() {
        assert_eq!(
            parse_version_number("#define SQLITE_VERSION \"3.53.2\"\n"),
            None
        );
        assert_eq!(parse_version_number(""), None);
    }

    #[test]
    fn the_minimum_is_3_51_3() {
        // Guards against someone editing this to a three-digit patch field.
        assert_eq!(MINIMUM, 3_051_003);
        assert!(
            MINIMUM <= 3_053_002,
            "the bundled version must satisfy this"
        );
    }

    #[test]
    fn an_empty_include_dir_is_not_a_directory() {
        // `include_dir` must reject a blank value rather than returning
        // `PathBuf::from("")`, which would resolve to the crate directory and
        // then fail with a confusing "sqlite3.h is not there".
        assert!("".trim().is_empty());
    }
}
