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
//!
//! # The one exception to "no unsafe here", and why it is here
//!
//! `deny` rather than `forbid`, with a single Windows-only module: stable Rust
//! cannot report a file's 128-bit identity, its link count, or the native handle
//! behind an open SQLite main database, and the safe wrappers do not expose any
//! of them. ADR-0058's Windows disposition needs those three facts, so the
//! Windows-only `windows` module calls `CreateFileW`,
//! `GetFileInformationByHandleEx` and `sqlite3_file_control`. Every block has a
//! `SAFETY` comment, the module is compiled only on Windows, and nothing above
//! this crate can name a handle.

#![deny(unsafe_code)]
#![deny(missing_docs)]

#[cfg(windows)]
mod windows;

use std::io;
use std::path::{Component, Path, PathBuf};

use orxnud_domain::platform::{
    FileFacts, FilesystemIdentity, FsContract, SqliteMainDatabase, SqliteMainFacts,
};

/// The number of directory entries that name this inode, or `None` where the platform
/// does not expose the count.
///
/// # Why this is here and not in a caller
///
/// The portable core may not branch on the platform -- gate G3 enforces that, and this
/// crate is where every `cfg` the project needs lives. A caller that needs to know
/// whether a file is reachable under a second name asks this question here.
///
/// # The unsupported-platform case
///
/// `None` means **"not established"**, never "one". A caller that needs the count must
/// treat `None` as a refusal: reading a file whose link count was never checked is
/// reading a file whose containment was never checked. On Unix the count is
/// `st_nlink`; on Windows this helper cannot answer, because stable
/// `std::fs::Metadata` does not expose the count. That is a limit of *this helper*,
/// not of the platform adapter: [`OsIdentity::observe`] uses the native Windows
/// query and does report the count. A caller that reaches for this free function on
/// Windows is asking the wrong one.
///
/// # What a count of one does and does not mean
///
/// A count of exactly one means the inode has a single directory entry, so no second
/// name can reach it. It does not say the file is *inside* any particular directory --
/// that is a separate question, answered by the caller's own path rules.
#[must_use]
pub fn hard_link_count(meta: &std::fs::Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(meta.nlink())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        None
    }
}

/// The platform this build is running on, named for a refusal message.
///
/// Not a `cfg` and not a compile-time constant: it is the *runtime* target, which
/// is what an operator reading a refusal needs to see.
const PLATFORM: &str = std::env::consts::OS;

/// The filesystem-identity capability, implemented for this platform.
///
/// # What it answers
///
/// One observation, one resolution of the path: how many names reach the file,
/// and which file it is. On Unix both come from a single `stat`, so they cannot
/// describe two different files. On Windows both come from one handle opened by
/// `windows::observe` and queried for `FILE_ID_INFO` and `FILE_STANDARD_INFO`,
/// which is the native equivalent of the same single resolution.
///
/// # What it refuses to answer
///
/// Where the platform cannot establish the facts, it says so. That is not a
/// fallback to a permissive answer — it is the answer, and ADR-0058 Decision 2
/// requires the caller to refuse on it.
///
/// # Windows
///
/// Stable Rust's `MetadataExt::number_of_links`, `file_index` and
/// `volume_serial_number` are nightly-only (`windows_by_handle` #63010), so this
/// implementation does not use them. It calls `CreateFileW` with
/// `FILE_READ_ATTRIBUTES` and asks `GetFileInformationByHandleEx` for
/// `FileIdInfo` (the volume serial number and full 128-bit file identifier) and
/// `FileStandardInfo` (the link count). The handle is opened with read, write and
/// delete sharing and is closed before return; no handle outlives the call.
///
/// A path that does not exist is [`FileFacts::Absent`]. Every other failure —
/// access denied, an unsupported filesystem, a handle query that fails — is
/// [`FileFacts::Unknown`], which the store refuses. Windows was previously
/// unsupported on this path; that disposition is superseded by the native
/// implementation, not widened into a permissive default.
///
/// # The SQLite main-database handle
///
/// On Windows, [`FilesystemIdentity::observe_sqlite_main`] asks the connection for
/// the handle SQLite is actually using (`SQLITE_FCNTL_WIN32_GET_HANDLE`), queries
/// that handle for the same two facts, and never closes it. On platforms without
/// that API the answer is [`SqliteMainFacts::NotApplicable`], which leaves the
/// pathname observation as the only identity evidence and says so.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OsIdentity;

impl FilesystemIdentity for OsIdentity {
    fn observe(&self, path: &Path) -> FileFacts {
        // The absence check is portable: `ErrorKind::NotFound` is a portable
        // classification, so a database that does not exist yet is reported as
        // absent on every platform rather than as unknown. That distinction
        // matters — it is the difference between "nothing to check yet" and
        // "the platform cannot tell", and treating the second as the first would
        // refuse every fresh install.
        #[cfg(windows)]
        {
            windows::observe(path)
        }
        #[cfg(not(windows))]
        {
            let meta = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return FileFacts::Absent,
                Err(_) => return FileFacts::Unknown { platform: PLATFORM },
            };

            #[cfg(unix)]
            {
                use orxnud_domain::platform::FileId;
                use std::os::unix::fs::MetadataExt;
                // `hard_link_count` is the same helper the rest of the crate uses, so
                // the count has exactly one implementation.
                let Some(name_count) = hard_link_count(&meta) else {
                    return FileFacts::Unknown { platform: PLATFORM };
                };
                FileFacts::Known {
                    name_count,
                    identity: Some(FileId::Unix {
                        dev: meta.dev(),
                        ino: meta.ino(),
                    }),
                }
            }
            #[cfg(not(unix))]
            {
                // A target that is neither Unix nor Windows: the crate has no
                // native backend for it, and inventing one would be the
                // permissive default ADR-0058 forbids.
                let _ = meta;
                FileFacts::Unknown { platform: PLATFORM }
            }
        }
    }

    fn observe_sqlite_main(&self, connection: SqliteMainDatabase<'_>) -> SqliteMainFacts {
        #[cfg(windows)]
        {
            windows::observe_sqlite_main(connection)
        }
        #[cfg(not(windows))]
        {
            // There is no equivalent of `SQLITE_FCNTL_WIN32_GET_HANDLE` on these
            // targets, and the Unix VFS's own change detection is a warning, not
            // a refusal. Saying `NotApplicable` records that the path check is
            // the only identity evidence rather than pretending the handle was
            // verified.
            let _ = connection;
            SqliteMainFacts::NotApplicable
        }
    }
}

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

/// Finds an executable named `stem` beside the running program.
///
/// # Why this lives here
///
/// Two questions have to be answered together and neither is portable: what a
/// runnable file is *called* on this platform (`.exe` and friends), and whether a
/// given file is runnable *at all* (an execute permission bit, which Unix has and
/// Windows does not). Answering either in a portable crate would put an OS opinion
/// outside the boundary this crate exists to hold, which is what gate G3 checks.
///
/// # Why beside the current program
///
/// A capability that needs a helper must find the one that was built alongside it,
/// and the only reliable way to say "alongside" is relative to a known executable.
/// An environment variable would be the alternative and is deliberately not offered:
/// it would let whoever starts the process choose which program later runs, which is
/// a redirection of the capability rather than a convenience.
///
/// # The second candidate
///
/// Cargo writes a package's binaries to `target/<profile>/` and its test harnesses to
/// `target/<profile>/deps/` beneath it. So a production daemon looks beside itself,
/// and a test binary has to look one level up. Both are tried; a caller cannot tell
/// which situation it is in, and neither should have to.
///
/// # Nonexistence is not an error
///
/// A missing helper is reported as `None` so the caller can decide what it means.
/// For `filesystem/write-text` it means the capability is simply not registered, and
/// a dispatch names it as unimplemented — which is more useful than a sandbox failure
/// at execution time naming a path.
///
/// [`std::path::PathBuf`]: std::path::PathBuf
#[must_use]
pub fn sibling_executable(stem: &str) -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    // Both spellings, tried rather than chosen: asking the OS which suffix is
    // correct is a question with no portable answer, and a wrong guess here would
    // silently produce a capability that cannot run.
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    for dir in [dir.to_path_buf(), dir.parent()?.to_path_buf()] {
        for name in [stem.to_owned(), format!("{stem}.exe")] {
            candidates.push(dir.join(name));
        }
    }
    candidates.into_iter().find(|c| is_runnable(c))
}

/// Whether the kernel would execute this path.
///
/// Executability, not existence, and the distinction is load-bearing: a build directory
/// contains, beside each binary, a `.d` dep-info text file and an `.rmeta` metadata
/// file whose names share the binary's prefix. A name-based filter matches those too,
/// and the "executable" it returns is a few hundred bytes of text that cannot be run —
/// which surfaces much later as a sandbox refusing to exec it.
fn is_runnable(path: &std::path::Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Any execute bit, not the owner-only one: a binary built by another user and
        // made group-executable is runnable, and refusing it would be surprising.
        meta.permissions().mode() & 0o111 != 0
    }
    // Elsewhere, a regular file at a plausible path is the best answer available.
    // Windows has no execute bit; the loader decides, and it will say so itself.
    #[cfg(not(unix))]
    {
        true
    }
}

/// Restricts `dir` to its owner, as far as this platform can express that.
///
/// # Why it lives here
///
/// It was in `orxnud-daemon` as an unconditional `std::os::unix::fs::PermissionsExt`,
/// which is a mistake with two faces. Gate **G3** looked only for `cfg`, and this code
/// had none, so the gate passed -- while the MSVC build failed outright, because
/// `PermissionsExt` does not exist on Windows. V-29's "consequence of drift" predicted
/// exactly this: *G3 only greps for `cfg`, not for a Linux type name.* A platform API
/// used without a `cfg` is the same defect wearing a different hat, and G3 now detects
/// `std::os::{unix,windows}` paths directly, so this specific hole is closed.
///
/// So the branch lives here, where `cfg` is permitted, and the portable core asks for the
/// behaviour rather than reaching for the mechanism.
///
/// # What it does off Unix
///
/// Windows has no POSIX mode bits, and a portable owner-only spelling needs
/// `windows-sys` plus `unsafe` -- which gate **G4** forbids outside a platform crate that
/// has opted in, and this one has not. Rather than invent a weaker-looking call that reads
/// as though the restriction happened, this returns `Ok(())` and records the limit: a
/// directory created under a per-user state root already inherits a per-user ACL, so the
/// protection the caller wanted is present by a different mechanism. Windows sandbox
/// isolation as a whole remains **NOT_PROVEN** (ADR-0035, V-29); this says nothing about
/// it.
pub fn restrict_to_owner(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::hard_link_count;

    /// A freshly created file has exactly one name, and a hard link gives it a second.
    ///
    /// The count is what the helper's containment check asks, so the API it asks
    /// through is pinned here rather than only in a consumer. The hard-link case is
    /// Unix-only, which is a property of this crate -- the one place a platform branch
    /// is allowed to live.
    #[test]
    fn the_link_count_of_a_file_is_one_until_it_is_hard_linked() {
        let dir = std::env::temp_dir().join(format!(
            "orxnud-platfs-links-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("a.txt");
        std::fs::write(&file, b"one").expect("write");

        let meta = std::fs::metadata(&file).expect("stat");
        assert_eq!(
            hard_link_count(&meta),
            Some(1),
            "a file with a single name must report one link"
        );

        // Where the platform does not expose the count, `None` is the answer and the
        // test says so rather than asserting a number the platform cannot give.
        #[cfg(unix)]
        {
            let alias = dir.join("b.txt");
            std::fs::hard_link(&file, &alias).expect("hard link");
            let alias_meta = std::fs::metadata(&alias).expect("stat alias");
            assert_eq!(
                hard_link_count(&alias_meta),
                Some(2),
                "a hard-linked inode has two names and must report two links"
            );
        }
        #[cfg(not(unix))]
        {
            assert_eq!(
                hard_link_count(&meta),
                None,
                "a platform that cannot count links must answer None, never one"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

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

    /// **The filesystem-identity capability answers about real files.**
    ///
    /// Three facts, and the third is the one that must never be confused with
    /// the second:
    ///
    /// * a path that does not exist is **absent** — on every platform, because
    ///   both backends classify "not found" separately from "cannot tell";
    /// * a file with one name has one link and a stable identity;
    /// * a file with a second name has two links, and the identity is the same
    ///   file's.
    ///
    /// The Unix branch below exercises the POSIX backend. The Windows backend is
    /// exercised by [`windows_tests`], which asserts the native `FILE_ID_INFO`
    /// identity and the link count rather than a number the platform cannot give.
    /// A target with neither backend answers `Unknown`, and never `Absent` and
    /// never a safe-looking number. The caller refuses on `Unknown` (ADR-0058
    /// Decision 2), so this is the difference between "refused" and "silently
    /// unprotected".
    #[test]
    fn the_identity_capability_answers_about_real_files() {
        use orxnud_domain::platform::FilesystemIdentity as _;

        let dir = temp_root("identity");
        let file = dir.join("one.txt");
        std::fs::write(&file, b"one").expect("write");
        let missing = dir.join("not-there.txt");

        let identity = OsIdentity;

        // Absent, on every platform.
        assert_eq!(
            identity.observe(&missing),
            FileFacts::Absent,
            "a path that does not exist must be reported absent, not unknown: they \
             are different facts and conflating them would refuse every fresh install"
        );

        #[cfg(unix)]
        {
            match identity.observe(&file) {
                FileFacts::Known {
                    name_count,
                    identity: id,
                } => {
                    assert_eq!(name_count, 1, "a file with one name has one link");
                    assert!(
                        id.is_some(),
                        "a platform that can report an identity must report one; \
                         'no identity' would be a refusal the caller cannot act on"
                    );
                }
                other => panic!("expected known facts, got {other:?}"),
            }

            // The second name. This is the whole finding: the link count is a
            // property of the inode, so it goes up for *every* name.
            let alias = dir.join("two.txt");
            std::fs::hard_link(&file, &alias).expect("hard link");
            let before = identity.observe(&file);
            let after = identity.observe(&alias);
            match (before, after) {
                (
                    FileFacts::Known {
                        name_count: 2,
                        identity: a,
                    },
                    FileFacts::Known {
                        name_count: 2,
                        identity: b,
                    },
                ) => {
                    assert_eq!(
                        a, b,
                        "two names for one inode must report the same identity: the \
                         link count is a property of the inode, not of the name"
                    );
                }
                other => panic!("expected two links through both names, got {other:?}"),
            }
        }
        #[cfg(all(not(unix), not(windows)))]
        {
            assert_eq!(
                identity.observe(&file),
                FileFacts::Unknown {
                    platform: std::env::consts::OS
                },
                "a target with no native backend must answer Unknown, never Absent \
                 and never a number that reads as safe"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Windows-only tests: the native identity and the actual SQLite handle.
///
/// These run on the Windows CI job, not on a Linux host. They are unit tests of
/// this crate because the thing under test is the adapter's native path; the
/// store's Windows integration suite separately proves that a real `Store::open`
/// uses it.
#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use orxnud_domain::platform::{FileId, SqliteMainFacts};

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orxnud-fs-win-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create root");
        dir
    }

    fn known(facts: FileFacts) -> (u64, FileId) {
        match facts {
            FileFacts::Known {
                name_count,
                identity: Some(identity),
            } => (name_count, identity),
            other => panic!("expected known facts with an identity, got {other:?}"),
        }
    }

    #[test]
    fn the_native_identity_reports_a_file_and_its_hard_link() {
        let dir = temp_root("identity");
        let file = dir.join("one.txt");
        std::fs::write(&file, b"one").expect("write");

        let (name_count, identity) = known(OsIdentity.observe(&file));
        assert_eq!(name_count, 1, "a freshly created file has one name");
        assert!(
            matches!(identity, FileId::Windows { .. }),
            "the native backend must report the full Windows identity, got {identity:?}"
        );

        let alias = dir.join("two.txt");
        std::fs::hard_link(&file, &alias).expect(
            "the scratch filesystem must support hard links; if it does not, the \
             hard-link property cannot be established here and this test must fail \
             rather than pass without measuring it",
        );
        let (count_file, id_file) = known(OsIdentity.observe(&file));
        let (count_alias, id_alias) = known(OsIdentity.observe(&alias));
        assert_eq!(count_file, 2, "the link count is a property of the file");
        assert_eq!(count_alias, 2, "both names must report the same count");
        assert_eq!(
            id_file, id_alias,
            "both names must report the same volume serial number and 128-bit id"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_native_main_handle_check_agrees_with_the_path() {
        let dir = temp_root("main-handle");
        let db = dir.join("state.db");
        let conn = rusqlite::Connection::open(&db).expect("open the database");

        let (path_count, path_identity) = known(OsIdentity.observe(&db));
        match OsIdentity.observe_sqlite_main(SqliteMainDatabase::new(&conn)) {
            SqliteMainFacts::Known {
                name_count,
                identity,
            } => {
                assert_eq!(
                    name_count, path_count,
                    "the live connection and the path must report the same link count"
                );
                assert_eq!(
                    identity, path_identity,
                    "the live connection must hold the file the path names"
                );
            }
            other => panic!("expected the native handle to be known, got {other:?}"),
        }
        drop(conn);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_in_memory_connection_has_no_file_handle_to_check() {
        let conn = rusqlite::Connection::open_in_memory().expect("open in memory");
        assert_eq!(
            OsIdentity.observe_sqlite_main(SqliteMainDatabase::new(&conn)),
            SqliteMainFacts::Unknown {
                platform: "windows"
            },
            "an in-memory main database has no native file; the check must refuse \
             rather than report that there is nothing to check"
        );
    }
}
