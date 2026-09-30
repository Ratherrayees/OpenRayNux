//! Filesystem adapter: bounded reads, atomic writes, and a rooted jail.
//!
//! # This is the only place `cfg(target_os)` may appear
//!
//! Gate G3 greps the workspace for platform branches and fails if one is found
//! outside a `platform-*` crate. That is what makes "the portable core is
//! portable" a fact about the code rather than an intention. So this crate
//! contains every `cfg` the project needs; the core asks a trait
//! ([`FsContract`]) and never learns which OS it is on.
//!
//! # A root is mandatory, not optional
//!
//! Every path is resolved against a granted root, and anything that escapes it is
//! refused — including `..`, absolute paths, and symlinks that point outside. A
//! filesystem API with no root is a filesystem API where a bug in a caller
//! becomes arbitrary file access, and path traversal in a tool that runs
//! scheduled jobs is not a hypothetical.
//!
//! Symlinks are the hard part and are handled by canonicalising *both* the root
//! and the candidate before comparing, so a symlink inside the root pointing out
//! of it is refused rather than followed.
//!
//! # Atomic writes, always
//!
//! [`OsFs::write_atomic`] writes to a temporary sibling and renames. A config file
//! or state file that is half-written is worse than one that is missing: the
//! reader cannot tell corruption from absence. Renames within a directory are
//! atomic on every platform we support, which is why the temporary file must be a
//! *sibling* — a temporary file in `/tmp` would cross a filesystem boundary and
//! make the rename a copy.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::io;
use std::path::{Component, Path, PathBuf};

use orxnud_domain::platform::FsContract;

/// A filesystem error.
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    /// The path resolved outside the granted root.
    ///
    /// A refusal, never a silent clamp: a caller that asked for `../etc/passwd`
    /// must be told, not handed something else.
    #[error("{path} escapes the granted root")]
    EscapesRoot {
        /// The rejected path, as given.
        path: String,
    },

    /// The read would exceed the caller's bound.
    #[error("{path} is {size} bytes, above the {limit}-byte limit")]
    TooLarge {
        /// The path.
        path: String,
        /// Observed size.
        size: u64,
        /// The limit the caller passed.
        limit: u64,
    },

    /// Underlying I/O failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A filesystem confined to one root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsFs {
    root: PathBuf,
}

impl OsFs {
    /// A filesystem rooted at `root`.
    ///
    /// The root is canonicalised once, at construction, so a later relative
    /// resolution cannot be fooled by the root itself being a symlink.
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        // `canonicalize` fails for a path that does not exist yet, which is the
        // normal case for a fresh install. Fall back to the path as given: the
        // jail still works, it just compares against an uncanonicalised root.
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        Self { root }
    }

    /// The granted root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves `candidate` against the root, refusing anything that escapes it.
    ///
    /// # Errors
    ///
    /// [`FsError::EscapesRoot`] for `..`, an absolute path, or a prefix that
    /// resolves outside the root.
    pub fn resolve(&self, candidate: &Path) -> Result<PathBuf, FsError> {
        // An absolute path from a caller is always a mistake: the API is
        // root-relative, so an absolute path is either an escape attempt or a bug
        // in the caller. Both are refused.
        if candidate.is_absolute() {
            return Err(FsError::EscapesRoot {
                path: candidate.display().to_string(),
            });
        }
        for component in candidate.components() {
            match component {
                // `..` is refused rather than normalised. Normalising would let
                // `a/../../etc` collapse to something that looks inside the root
                // and is not.
                Component::ParentDir => {
                    return Err(FsError::EscapesRoot {
                        path: candidate.display().to_string(),
                    });
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(FsError::EscapesRoot {
                        path: candidate.display().to_string(),
                    });
                }
                Component::CurDir | Component::Normal(_) => {}
            }
        }
        let joined = self.root.join(candidate);
        // Symlink check: canonicalise the joined path when it exists and confirm it
        // is still under the root. A symlink inside the root pointing outward is
        // the escape that lexical checks alone miss.
        if let Ok(canonical) = joined.canonicalize()
            && !canonical.starts_with(&self.root)
        {
            return Err(FsError::EscapesRoot {
                path: candidate.display().to_string(),
            });
        }
        Ok(joined)
    }
}

impl FsContract for OsFs {
    type Error = FsError;

    fn read_bounded(&self, path: &Path, max_bytes: u64) -> Result<Vec<u8>, FsError> {
        let resolved = self.resolve(path)?;
        // Stat before reading so an oversized file costs one syscall rather than
        // a full read into memory that then has to be discarded.
        let size = std::fs::metadata(&resolved)?.len();
        if size > max_bytes {
            return Err(FsError::TooLarge {
                path: path.display().to_string(),
                size,
                limit: max_bytes,
            });
        }
        Ok(std::fs::read(resolved)?)
    }

    fn write_atomic(&self, path: &Path, contents: &[u8]) -> Result<(), FsError> {
        let resolved = self.resolve(path)?;
        if let Some(parent) = resolved.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // A sibling, not a `/tmp` file: the rename must stay within one filesystem
        // to remain atomic.
        let temp = resolved.with_extension(format!("tmp-{}", std::process::id()));
        // Write then sync then rename. The sync is what makes "written" mean
        // "durable" rather than "in the page cache"; without it a crash can leave
        // the renamed file present but empty.
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&temp)?;
            f.write_all(contents)?;
            f.sync_all()?;
        }
        match std::fs::rename(&temp, &resolved) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Do not leave a stray temporary behind on failure.
                let _ = std::fs::remove_file(&temp);
                Err(FsError::Io(e))
            }
        }
    }

    fn exists(&self, path: &Path) -> Result<bool, FsError> {
        let resolved = self.resolve(path)?;
        Ok(resolved.exists())
    }

    fn ensure_dir(&self, path: &Path) -> Result<(), FsError> {
        let resolved = self.resolve(path)?;
        std::fs::create_dir_all(resolved)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orxnud-fs-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create root");
        dir
    }

    fn fs(tag: &str) -> (OsFs, PathBuf) {
        let root = temp_root(tag);
        (OsFs::new(&root), root)
    }

    #[test]
    fn a_write_then_read_round_trips() {
        let (fs, _root) = fs("roundtrip");
        fs.write_atomic(Path::new("a/b.txt"), b"hello")
            .expect("write");
        assert_eq!(
            fs.read_bounded(Path::new("a/b.txt"), 1024).expect("read"),
            b"hello"
        );
    }

    #[test]
    fn an_atomic_write_leaves_no_temporary_behind() {
        let (fs, root) = fs("no-temp");
        fs.write_atomic(Path::new("x.txt"), b"v").expect("write");
        let strays: Vec<_> = std::fs::read_dir(&root)
            .expect("read dir")
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(strays.is_empty(), "a temporary file survived: {strays:?}");
    }

    #[test]
    fn a_read_above_the_bound_is_refused_without_reading_the_file() {
        let (fs, _root) = fs("bounded");
        fs.write_atomic(Path::new("big.bin"), &vec![0u8; 4096])
            .expect("write");
        let err = fs
            .read_bounded(Path::new("big.bin"), 10)
            .expect_err("must refuse");
        match err {
            FsError::TooLarge { size, limit, .. } => {
                assert_eq!(size, 4096);
                assert_eq!(limit, 10);
            }
            other => panic!("expected TooLarge, got {other}"),
        }
    }

    #[test]
    fn parent_traversal_is_refused_rather_than_normalised() {
        // `a/../../etc` normalises to outside the root; refusing beats clamping.
        let (fs, _root) = fs("traversal");
        for candidate in ["..", "../escape", "a/../../escape", "a/b/../../../escape"] {
            let err = fs.resolve(Path::new(candidate)).expect_err(candidate);
            assert!(
                matches!(err, FsError::EscapesRoot { .. }),
                "{candidate}: {err}"
            );
        }
    }

    #[test]
    fn an_absolute_path_is_refused() {
        let (fs, _root) = fs("absolute");
        let err = fs
            .resolve(Path::new("/etc/passwd"))
            .expect_err("must refuse");
        assert!(matches!(err, FsError::EscapesRoot { .. }), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_pointing_out_of_the_root_is_refused() {
        // The escape that lexical checks alone miss.
        let (fs, root) = fs("symlink");
        let outside = temp_root("symlink-outside");
        std::fs::write(outside.join("secret.txt"), b"secret").expect("write outside");
        std::os::unix::fs::symlink(&outside, root.join("escape")).expect("symlink");

        let err = fs
            .resolve(Path::new("escape/secret.txt"))
            .expect_err("must refuse");
        assert!(matches!(err, FsError::EscapesRoot { .. }), "{err}");
        // And a read through it is refused too, not just resolve.
        assert!(
            fs.read_bounded(Path::new("escape/secret.txt"), 1024)
                .is_err()
        );

        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn a_cur_dir_component_is_harmless() {
        let (fs, _root) = fs("curdir");
        assert!(fs.resolve(Path::new("./a/./b")).is_ok());
    }

    #[test]
    fn exists_distinguishes_absent_from_present() {
        let (fs, _root) = fs("exists");
        assert!(!fs.exists(Path::new("nope")).expect("exists"));
        fs.write_atomic(Path::new("yep"), b"1").expect("write");
        assert!(fs.exists(Path::new("yep")).expect("exists"));
    }

    #[test]
    fn ensure_dir_is_idempotent() {
        let (fs, _root) = fs("mkdir");
        fs.ensure_dir(Path::new("d/e/f")).expect("first");
        fs.ensure_dir(Path::new("d/e/f"))
            .expect("second, must be a no-op");
        assert!(fs.exists(Path::new("d/e/f")).expect("exists"));
    }

    #[test]
    fn ensure_dir_cannot_create_a_parent_directory() {
        let (fs, _root) = fs("mkdir-escape");
        assert!(fs.ensure_dir(Path::new("../outside")).is_err());
    }

    #[test]
    fn writing_outside_the_root_is_refused_and_writes_nothing() {
        let (fs, _root) = fs("write-escape");
        assert!(fs.write_atomic(Path::new("../escape.txt"), b"x").is_err());
        assert!(fs.write_atomic(Path::new("/tmp/escape.txt"), b"x").is_err());
    }

    #[test]
    fn an_empty_file_is_written_and_read_correctly() {
        // A zero-length write is legitimate (an empty config, a truncated log).
        let (fs, _root) = fs("empty");
        fs.write_atomic(Path::new("empty.txt"), b"").expect("write");
        assert_eq!(
            fs.read_bounded(Path::new("empty.txt"), 0).expect("read"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn overwriting_replaces_rather_than_appends() {
        let (fs, _root) = fs("overwrite");
        fs.write_atomic(Path::new("f"), b"first-value")
            .expect("first");
        fs.write_atomic(Path::new("f"), b"second").expect("second");
        assert_eq!(
            fs.read_bounded(Path::new("f"), 1024).expect("read"),
            b"second"
        );
    }

    #[test]
    fn the_root_is_where_it_was_pointed() {
        let (_fs, root) = fs("root");
        let fs2 = OsFs::new(&root);
        assert_eq!(
            fs2.root(),
            root.canonicalize().unwrap_or(root.clone()).as_path()
        );
    }
}
