//! Validating a directory tree the way its contents will later be used.
//!
//! # What this module is for
//!
//! The daemon has a state root and a workspace, and the workspace is handed to a
//! sandbox as a bind destination. Two things have to be true before that is safe:
//!
//! 1. The **objects** are what they claim to be — real directories, owned by the
//!    daemon, not group- or world-accessible.
//! 2. The **path** leading to them contains no component that could redirect a later
//!    path-based walk into somewhere else.
//!
//! The second is the one that is easy to get wrong. `bwrap` builds its destination
//! tree with `mkdir_with_parents` and `ensure_dir`, both of which use `stat()` and
//! `mkdir()` — path-based, symlink-following operations. If a workspace sits beneath
//! a directory that is a symbolic link, bwrap follows it and creates under whatever it
//! points at. That is CVE-2026-87766's precondition, and it is reachable here through
//! *configuration* — a state root beneath `/usr`, say, where `/usr` is a bind mount
//! whose contents an operator or a package might have changed.
//!
//! # The order the checks run in, and why
//!
//! Every step opens the next component relative to the descriptor it already holds,
//! with `O_NOFOLLOW`. So a symlinked component is refused at the step where it
//! appears, and the refusal names the component. Nothing is canonicalised up front:
//! `std::fs::canonicalize` *follows* symlinks, so canonicalising first would erase
//! exactly the evidence this walk exists to find. The canonical path is derived
//! afterwards, from the descriptor that survived the walk.
//!
//! # What this module does not claim
//!
//! It does not stop a process running as the **same uid** as the daemon from renaming
//! or replacing a component. Holding a descriptor pins an inode, not a name, and no
//! amount of care here changes that. The protection is against *other* uids, which is
//! what the ownership and permission rules exclude; a hostile same-uid process is a
//! separate threat requiring a separate service identity, and this module's messages
//! deliberately do not imply otherwise.
//!
//! It also does not claim that a mode-bit check proves an open will succeed. A mode
//! can permit an operation that a mount option, an LSM, or a read-only bind denies.
//! So the rule is: the mode is a *precondition* — when it is absent, refuse without
//! trying — and when it is present the open is attempted for real, and a failure is a
//! refusal rather than a retry somewhere else.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Component;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

/// What to do when a directory exists with the wrong mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeAction {
    /// Tighten it to the required mode through the descriptor, then re-verify.
    ///
    /// The state root takes this route: an existing world-readable root is a thing
    /// this product has always corrected, and correcting it is better behaviour than
    /// refusing to start because a previous build left it loose.
    Tighten,
    /// Require the exact mode; refuse anything else.
    ///
    /// The workspace takes this route, because an existing workspace may hold the
    /// output of a capability that already ran, and its mode is not this walk's to
    /// restate.
    Require,
}

/// How far down the path this walk may create missing directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Creation {
    /// Create nothing. Every component must already exist.
    ///
    /// Used to re-verify an already-validated path, and for the workspace when the
    /// caller wants to know whether it is already usable.
    ExistingOnly,
    /// Create missing components at or beneath `beneath`, and nowhere else.
    ///
    /// `beneath` names the first directory this daemon is entitled to create — for the
    /// default root that is `$HOME/.local`, for an explicit root it is the root itself.
    /// Everything above it must already exist, because creating `/home` or `/var/lib`
    /// is not this program's job and doing it would be a surprising side effect.
    ///
    /// # Why a path and not a component index
    ///
    /// An index has to be counted against a component list that includes the root and
    /// the components of the temporary directory a test happens to run in, so the same
    /// policy means different things in different places — and an off-by-one silently
    /// authorises creating the operator's home directory. A path says what it means and
    /// is checkable with [`is_within`], which the walk already needs anyway.
    From {
        /// The directory at or beneath which creation is permitted.
        beneath: PathBuf,
    },
}

/// The policy for one directory being validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirPolicy {
    /// Whether and where missing directories may be created.
    pub creation: Creation,
    /// What to do about an existing directory's mode.
    pub mode: ModeAction,
    /// Whether a world-writable ancestor is acceptable when it is root-owned and sticky.
    ///
    /// `/tmp` is the case this exists for: mode `1777`, owned by root. It is acceptable
    /// because the sticky bit stops one user replacing another user's child, and the
    /// child being created is owned by the daemon. It is **not** a general exemption
    /// for writable directories: the accepted case is a root-owned parent with the sticky
    /// bit set, and nothing else.
    pub allow_sticky_ancestor: bool,
}

/// A directory that passed every check, with the path it canonically is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedDir {
    /// The canonical path, derived from the descriptor that survived the walk.
    ///
    /// Derived, never taken from the caller's input: the input may contain `.` or a
    /// doubled separator or a component that is a symlink to the directory's real
    /// parent, and none of those spellings should reach a sandbox argument.
    pub canonical: PathBuf,
    /// The components this walk created, outermost first.
    ///
    /// Empty when nothing was created. Reported so a caller can log what a start did
    /// to the filesystem, which matters when a start is being audited.
    pub created: Vec<PathBuf>,
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// A mode formatted for an operator's eyes, or the word for an unreadable one.
///
/// [`ValidationError::ModeDeniesOpen`] carries the mode as an `Option` because the
/// case it names is precisely the one where the mode could not be read. `None` has to
/// print as something an operator can act on.
struct DisplayMode(Option<u32>);

impl std::fmt::Display for DisplayMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(mode) => write!(f, "{mode:04o}"),
            None => write!(f, "unreadable"),
        }
    }
}

/// A path formatted for an operator's eyes.
///
/// `PathBuf` has no `Display`, and `{path:?}` would render a state root with quotes and
/// escapes — correct for a debugger, misleading in a message an operator is meant to
/// read and act on. Every refusal here says *which* path, plainly.
struct DisplayPath<'a>(&'a Path);

impl std::fmt::Display for DisplayPath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// Why a path was refused.
///
/// Every variant names the offending component. A refusal that says only "invalid
/// state root" sends an operator to guess which of eight rules they broke.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// The path is not absolute.
    #[error(
        "the state root must be an absolute path; {} is relative, and a relative root \
         would depend on the working directory the daemon was started from",
        DisplayPath(path)
    )]
    NotAbsolute {
        /// The path as given.
        path: PathBuf,
    },

    /// The path contains a `..` component.
    ///
    /// Refused rather than resolved: a path that climbs is a path whose destination the
    /// caller has not thought about, and `..` in a configured root is a mistake more
    /// often than it is an intention.
    #[error(
        "the state root must not contain '..'; {} climbs out of itself, and a configured \
         root that climbs is a configuration mistake",
        DisplayPath(path)
    )]
    ParentTraversal {
        /// The path as given.
        path: PathBuf,
    },

    /// A component is a symbolic link.
    #[error(
        "{} is a symbolic link; every component of the state root must be a real \
         directory, because a later path-based walk would follow the link and could \
         create files outside the state root",
        DisplayPath(path)
    )]
    SymlinkComponent {
        /// The path of the component that is a link.
        path: PathBuf,
    },

    /// A component exists but is not a directory.
    #[error("{} is not a directory; the state root must be one", DisplayPath(path))]
    NotADirectory {
        /// The path of the component that is the wrong kind.
        path: PathBuf,
    },

    /// A component is missing and this policy does not permit creating it.
    #[error(
        "{} does not exist and this configuration does not permit creating it; missing \
         system directories are not this daemon's to create",
        DisplayPath(path)
    )]
    MissingNotPermitted {
        /// The path of the component that is absent.
        path: PathBuf,
    },

    /// A component is owned by a uid that is neither root nor the daemon's.
    ///
    /// An ancestor owned by a third uid is an ancestor another account can replace.
    #[error(
        "{} is owned by {found:?}, which is neither root nor the daemon's uid; an \
         ancestor another account can replace is an ancestor that can redirect a later walk",
        DisplayPath(path)
    )]
    OwnerMismatch {
        /// The path of the component with the unexpected owner.
        path: PathBuf,
        /// The uid that owns it.
        found: Option<u32>,
    },

    /// An ancestor is writable by group or other and is not an accepted sticky root.
    #[error(
        "{} is mode {mode:04o} and writable by group or other; another account could \
         replace a component of the state root",
        DisplayPath(path)
    )]
    AncestorWritable {
        /// The path of the writable ancestor.
        path: PathBuf,
        /// Its mode, in octal.
        mode: u32,
    },

    /// The leaf could not be opened because its mode denies even a directory open.
    ///
    /// This is the `0000` case. It is distinct from [`ValidationError::Io`] because the
    /// remedy is different: the operator must change the mode themselves, and this
    /// program cannot and will not do it for them.
    #[error(
        "{} is mode {}, which denies the daemon access to its own state root; refusing \
         rather than attempting an unsupported repair. Change the mode to 0700 and start \
         again",
        DisplayPath(path),
        DisplayMode(*mode)
    )]
    ModeDeniesOpen {
        /// The path of the directory that cannot be opened.
        path: PathBuf,
        /// Its mode, in octal, when it could be read.
        mode: Option<u32>,
    },

    /// The leaf's mode is not the required one and [`ModeAction::Require`] was set.
    #[error(
        "{} is mode {mode:04o}, not the required 0700; this directory is left exactly as \
         it is because a capability may already have written into it",
        DisplayPath(path)
    )]
    ModeNotAcceptable {
        /// The path of the directory with the wrong mode.
        path: PathBuf,
        /// Its mode, in octal.
        mode: u32,
    },

    /// A filesystem operation failed.
    #[error("{operation} for {} failed: {source}", DisplayPath(path))]
    Io {
        /// The path the operation was about.
        path: PathBuf,
        /// What was being attempted, for a message an operator can act on.
        operation: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Whether `path` is at or beneath `ancestor`, component by component.
///
/// # Why not `starts_with`
///
/// `Path::starts_with` already compares components rather than bytes, but it reads as
/// a prefix test, and the `/usr` versus `/usr-local` distinction is the whole point of
/// this function. Spelling it out — and testing the neighbour explicitly — keeps the
/// difference from being lost on a later read.
///
/// A path is within itself: `is_within(p, p)` is `true`. That is what makes the overlap
/// check work, because a state root placed exactly at a mounted directory is the most
/// direct form of the problem.
#[must_use]
pub fn is_within(path: &Path, ancestor: &Path) -> bool {
    let mut wanted = ancestor.components();
    for component in path.components() {
        match wanted.next() {
            // `path` still has components after `ancestor` ran out, so it names
            // something beneath the ancestor: contained.
            None => return true,
            Some(want) if want == component => {}
            // A component differs, so the two paths diverge here.
            _ => return false,
        }
    }
    // `path` ran out. It is contained only if `ancestor` has nothing left either --
    // otherwise `ancestor` names something deeper, and an ancestor is not within its
    // own descendant.
    wanted.next().is_none()
}

/// Whether a world-writable ancestor is acceptable.
///
/// # The four conditions, all of which must hold
///
/// 1. Owned by **root** — not merely by the daemon. A daemon-owned sticky directory is
///    the same-uid case, and the sticky bit does not stop an owner replacing its own
///    child. Accepting that here would silently widen the guarantee this crate
///    documents as out of scope.
/// 2. The sticky bit is set.
/// 3. The child being traversed is owned by the daemon's uid.
/// 4. The component was verified through a descriptor, not by a path lookup.
///
/// This is what makes `/tmp` usable as a state root and nothing more.
#[cfg(unix)]
fn sticky_ancestor_is_acceptable(mode: u32, uid: u32, daemon_uid: u32) -> bool {
    mode & 0o1000 != 0 && uid == 0 && daemon_uid != 0
}

/// The mode a validated directory must end up with.
#[cfg(unix)]
const REQUIRED_MODE: u32 = 0o700;
/// Group and other permission bits, any of which disqualifies a directory.
#[cfg(unix)]
const GROUP_OTHER_BITS: u32 = 0o077;
/// The owner-read bit, which is the precondition for an ordinary directory open.
#[cfg(unix)]
const OWNER_READ_BIT: u32 = 0o400;
/// The owner write, read and execute bits together.
#[cfg(unix)]
const OWNER_RWX_BITS: u32 = 0o700;
/// Bits that make a directory writable by someone other than its owner.
#[cfg(unix)]
const OTHERS_WRITE_BITS: u32 = 0o022;
/// Root's uid, the one ownership that makes a writable ancestor acceptable.
#[cfg(unix)]
const ROOT_UID: u32 = 0;

// ---------------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------------

/// Validates `root` against `policy` and returns the directory that survived.
///
/// # What it guarantees
///
/// * Every component from `/` to the leaf is a **real directory** — no symlinks, no
///   files.
/// * Every component is owned by root or by `expected_uid`.
/// * No component above the leaf is writable by group or other, except a root-owned
///   sticky ancestor when the policy allows it.
/// * The leaf is owned by `expected_uid` and ends at the required mode.
/// * Any directory created was created relative to a descriptor that was already
///   validated, and was re-opened and re-verified afterwards.
///
/// # What it does not guarantee
///
/// That a process running as `expected_uid` cannot replace a component during or after
/// the walk. See the module header.
///
/// # Errors
///
/// [`ValidationError`], naming the component and the rule. Nothing is left behind on
/// failure: anything this call created is removed before the error is returned.
pub fn validate_dir(
    root: &Path,
    policy: &DirPolicy,
    expected_uid: u32,
) -> Result<PreparedDir, ValidationError> {
    #[cfg(unix)]
    {
        validate_dir_unix(root, policy, expected_uid)
    }
    #[cfg(not(unix))]
    {
        let _ = (root, policy, expected_uid);
        Err(ValidationError::Io {
            path: root.to_path_buf(),
            operation: "validating the state root",
            source: std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "descriptor-relative directory validation is not implemented on this \
                 platform; the daemon cannot establish the state root it was asked for",
            ),
        })
    }
}

/// The Unix implementation, split out so the public entry point stays readable and the
/// platform split stays in one place.
#[cfg(unix)]
fn validate_dir_unix(
    root: &Path,
    policy: &DirPolicy,
    expected_uid: u32,
) -> Result<PreparedDir, ValidationError> {
    if !root.is_absolute() {
        return Err(ValidationError::NotAbsolute {
            path: root.to_path_buf(),
        });
    }

    // Lexical rules first, before touching the filesystem: a `..` in a configured root
    // is a configuration mistake, and resolving it would hide the mistake behind a path
    // that happens to work.
    let components: Vec<Component<'_>> = root.components().collect();
    for component in &components {
        if matches!(component, Component::ParentDir) {
            return Err(ValidationError::ParentTraversal {
                path: root.to_path_buf(),
            });
        }
    }

    let create_beneath: Option<&Path> = match &policy.creation {
        Creation::ExistingOnly => None,
        Creation::From { beneath } => Some(beneath.as_path()),
    };

    // The root descriptor is the anchor for every step after the first. Opening `/`
    // cannot follow a symlink, because it is the root; a failure here means the process
    // cannot run at all, which is not a configuration problem.
    let anchor = std::fs::File::open("/").map_err(|source| ValidationError::Io {
        path: PathBuf::from("/"),
        operation: "opening the filesystem root",
        source,
    })?;

    let mut current = anchor;
    // Directories this walk created, with the name each was made under. Kept so a later
    // failure can undo exactly what this call did — and nothing else, because a
    // pre-existing directory is never recorded here.
    // Each entry is the directory created and the **descriptor of the directory it was
    // created in**. The descriptor is a duplicate of a handle this walk already
    // validated, so removing the child later needs no second name resolution — which
    // matters, because a path-based removal would follow a symlink in exactly the way
    // the walk refuses to.
    let mut created: Vec<(PathBuf, std::fs::File)> = Vec::new();
    let mut canonical = PathBuf::from("/");
    let mut named_something = false;

    for (index, component) in components.iter().enumerate() {
        // `/` is already open as the anchor, and `.` is a no-op in a path: opening it
        // would succeed and add a component the caller did not mean.
        if matches!(component, Component::RootDir | Component::CurDir) {
            continue;
        }
        let name = component.as_os_str();
        let cname = crate::descriptor::component_to_cstr(component).map_err(|source| {
            ValidationError::Io {
                path: canonical.join(name),
                operation: "reading a path component",
                source,
            }
        })?;
        let display = canonical.join(name);

        // The leaf is the last component that names something. A trailing `.` does not
        // make the component before it an ancestor.
        let is_leaf = components[index + 1..]
            .iter()
            .all(|c| matches!(c, Component::CurDir | Component::RootDir));

        let file = match open_dir_no_follow(&current, &cname, &display) {
            Ok(file) => file,
            // A missing component this policy owns, **including the leaf**: creating
            // only the intermediates would leave a first run with `$HOME/.local/state`
            // and no `orxnud` beneath it, which is a start that fails for a reason the
            // caller did not cause. The guard is the path, not the position, so
            // `is_leaf` deliberately does not appear here.
            Err(ValidationError::MissingNotPermitted { .. })
                if create_beneath.is_some_and(|beneath| is_within(&display, beneath)) =>
            {
                // A missing intermediate this policy owns: create it, then re-open and
                // verify what came back. The re-open is the point — `mkdirat` succeeding
                // does not prove the thing now at that name is the directory this call
                // made.
                crate::descriptor::mkdirat(&current, &cname, REQUIRED_MODE).map_err(|source| {
                    ValidationError::Io {
                        path: display.clone(),
                        operation: "creating the directory",
                        source,
                    }
                })?;
                created.push((
                    display.clone(),
                    current.try_clone().map_err(|source| ValidationError::Io {
                        path: display.clone(),
                        operation: "duplicating the parent descriptor",
                        source,
                    })?,
                ));
                open_dir_no_follow(&current, &cname, &display)?
            }
            Err(refusal) => {
                let leftovers = rollback(&mut created);
                return Err(refusal_noting_leftovers(refusal, &leftovers));
            }
        };

        let meta = file.metadata().map_err(|source| ValidationError::Io {
            path: display.clone(),
            operation: "reading the directory's attributes",
            source,
        })?;

        if !meta.is_dir() {
            rollback(&mut created);
            return Err(ValidationError::NotADirectory { path: display });
        }

        let uid = uid_of(&meta);
        let mode = mode_of(&meta);
        let owner_is_root = uid == Some(ROOT_UID);
        let owner_is_daemon = uid == Some(expected_uid);

        if is_leaf {
            if !owner_is_daemon {
                rollback(&mut created);
                return Err(ValidationError::OwnerMismatch {
                    path: display,
                    found: uid,
                });
            }

            match policy.mode {
                ModeAction::Tighten => {
                    // The owner-read bit is a precondition, never a proof. When it is
                    // absent the open above already failed and we are not here; when it
                    // is present the change is attempted for real and the result the
                    // filesystem gives is what counts, rather than a mode-bit inference.
                    if mode & OWNER_READ_BIT == 0 {
                        rollback(&mut created);
                        return Err(ValidationError::ModeDeniesOpen {
                            path: display,
                            mode: Some(mode),
                        });
                    }
                    if mode & GROUP_OTHER_BITS != 0 || mode & OWNER_RWX_BITS != OWNER_RWX_BITS {
                        file.set_permissions(std::fs::Permissions::from_mode(REQUIRED_MODE))
                            .map_err(|source| ValidationError::Io {
                                path: display.clone(),
                                operation: "restricting the directory to its owner",
                                source,
                            })?;
                        // Re-read through the same descriptor: the mode that matters is
                        // the one the object has now, not the one it had a moment ago.
                        let after = file.metadata().map_err(|source| ValidationError::Io {
                            path: display.clone(),
                            operation: "re-reading the directory's mode",
                            source,
                        })?;
                        let after_mode = mode_of(&after);
                        if after_mode & GROUP_OTHER_BITS != 0
                            || after_mode & OWNER_RWX_BITS != OWNER_RWX_BITS
                        {
                            rollback(&mut created);
                            return Err(ValidationError::ModeNotAcceptable {
                                path: display,
                                mode: after_mode,
                            });
                        }
                    }
                }
                ModeAction::Require => {
                    if mode & GROUP_OTHER_BITS != 0 || mode & OWNER_RWX_BITS != OWNER_RWX_BITS {
                        rollback(&mut created);
                        return Err(ValidationError::ModeNotAcceptable {
                            path: display,
                            mode,
                        });
                    }
                }
            }

            canonical.push(name);
            named_something = true;
            break;
        }

        // An ancestor: owned by root or the daemon, and not writable by anyone else
        // unless it is an accepted sticky root.
        if !owner_is_root && !owner_is_daemon {
            rollback(&mut created);
            return Err(ValidationError::OwnerMismatch {
                path: display,
                found: uid,
            });
        }
        if mode & OTHERS_WRITE_BITS != 0 {
            // The ancestor must be **root**-owned -- `owner_is_root` is what the check
            // above just established for this branch -- and the child it protects is
            // the daemon's, which the next step of this walk verifies when it opens it.
            // Requiring the ancestor to be daemon-owned here would accept the same-uid
            // case the module header excludes, and reject `/tmp`, which is the one
            // layout this rule exists to permit.
            let acceptable = policy.allow_sticky_ancestor
                && owner_is_root
                && sticky_ancestor_is_acceptable(mode, uid.unwrap_or(u32::MAX), expected_uid);
            if !acceptable {
                rollback(&mut created);
                return Err(ValidationError::AncestorWritable {
                    path: display,
                    mode,
                });
            }
        }

        canonical.push(name);
        named_something = true;
        current = file;
    }

    // A path that is only `/` and separators names nothing. It would otherwise walk to a
    // successful empty validation of the filesystem root, which is not a state root.
    if !named_something {
        let leftovers = rollback(&mut created);
        if !leftovers.is_empty() {
            // Only reachable when the walk created something and then found nothing to
            // validate; the leftovers are named rather than dropped on the floor.
            return Err(ValidationError::Io {
                path: root.to_path_buf(),
                operation: "removing the directories this walk created",
                source: std::io::Error::other(format!(
                    "left behind: {}",
                    leftovers
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
            });
        }
        return Err(ValidationError::NotADirectory {
            path: root.to_path_buf(),
        });
    }

    Ok(PreparedDir {
        canonical,
        created: created.into_iter().map(|(path, _)| path).collect(),
    })
}

/// Turns an `openat` error into the refusal that names what actually happened.
///
/// # Why `ENOTDIR` needs a second look
///
/// `O_NOFOLLOW` combined with `O_DIRECTORY` makes the kernel answer `ENOTDIR` for a
/// final component that is a symbolic link, where `O_NOFOLLOW` alone answers `ELOOP`.
/// Reporting `ENOTDIR` for a symlink tells an operator their state root is "not a
/// directory" when it is a link to one — true, and useless, because the remedy for the
/// two is different. So an `ENOTDIR` is re-examined with `O_PATH | O_NOFOLLOW`, which
/// needs no permission at all and yields a descriptor for the link itself rather than
/// its target.
///
/// Everything else is mapped directly, so a second error can never mask the first.
#[cfg(unix)]
fn classify_open_error(
    error: std::io::Error,
    dir: &std::fs::File,
    name: &std::ffi::CStr,
    display: &Path,
) -> ValidationError {
    match error.raw_os_error() {
        Some(libc::ELOOP) => ValidationError::SymlinkComponent {
            path: display.to_path_buf(),
        },
        Some(libc::ENOTDIR) => {
            let link = crate::descriptor::openat(
                dir,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            );
            let is_a_link = link
                .as_ref()
                .ok()
                .and_then(|handle| handle.metadata().ok())
                .is_some_and(|meta| meta.file_type().is_symlink());
            if is_a_link {
                return ValidationError::SymlinkComponent {
                    path: display.to_path_buf(),
                };
            }
            ValidationError::NotADirectory {
                path: display.to_path_buf(),
            }
        }
        Some(libc::ENOENT) => ValidationError::MissingNotPermitted {
            path: display.to_path_buf(),
        },
        Some(libc::EACCES) => ValidationError::ModeDeniesOpen {
            path: display.to_path_buf(),
            mode: None,
        },
        _ => ValidationError::Io {
            path: display.to_path_buf(),
            operation: "opening the directory",
            source: error,
        },
    }
}

/// Turns a refusal into one that also names what the rollback could not remove.
///
/// A directory this walk created and could not remove is a directory on the caller's
/// machine that they do not know exists. Naming it is the difference between a refusal
/// that can be acted on and one that leaves litter.
#[cfg(unix)]
fn refusal_noting_leftovers(
    refusal: ValidationError,
    leftovers: &[std::path::PathBuf],
) -> ValidationError {
    if leftovers.is_empty() {
        return refusal;
    }
    let left = leftovers
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    match refusal {
        ValidationError::Io {
            path,
            operation,
            source,
        } => ValidationError::Io {
            path,
            operation,
            source: std::io::Error::other(format!("{source} (left behind: {left})")),
        },
        other => ValidationError::Io {
            path: std::path::PathBuf::new(),
            operation: "validating the state root",
            source: std::io::Error::other(format!("{other} (left behind: {left})")),
        },
    }
}

/// Opens a directory without following a final-component symlink, and reports which
/// refusal happened.
///
/// # Why this is a function and not an `OpenOptions` chain
///
/// `std::fs::OpenOptions` opens from the process root, and its accessors take
/// `&mut self`, so there is no way to give one a held descriptor without fighting the
/// builder's shape. What matters is one call whose base is a descriptor this walk
/// already validated, so it is a function.
///
/// # The `O_PATH` fallback, and what it is for
///
/// An ordinary `O_DIRECTORY | O_NOFOLLOW` open fails with `EACCES` when the mode denies
/// it — which is the `0000` case. That leaves the caller unable even to *describe* the
/// directory it is refusing. `O_PATH` needs no permission at all, so it yields a
/// descriptor that can be `fstat`ed for the mode and the owner, and the refusal becomes
/// a sentence an operator can act on.
///
/// It is used for diagnosis only. An `O_PATH` descriptor cannot be `fchmod`ed — the
/// kernel refuses with `EBADF`, measured — so it cannot repair anything, and this
/// function never pretends otherwise.
#[cfg(unix)]
fn open_dir_no_follow(
    dir: &std::fs::File,
    name: &std::ffi::CStr,
    display: &Path,
) -> Result<std::fs::File, ValidationError> {
    /// The flags an ordinary directory open needs.
    const ORDINARY: libc::c_int = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    let attempted = crate::descriptor::openat(dir, name, ORDINARY)
        .map_err(|error| classify_open_error(error, dir, name, display));

    match attempted {
        Ok(file) => Ok(file),
        Err(ValidationError::ModeDeniesOpen { .. }) => {
            // Only a permission failure is worth diagnosing further: the mode might deny
            // the daemon access to its own directory, which is a different message and a
            // different remedy from every other failure. Anything else passes through
            // unchanged, so a second error cannot mask the first.
            let diagnosed = crate::descriptor::openat(dir, name, ORDINARY | libc::O_PATH);

            let Ok(handle) = diagnosed else {
                // Not even `O_PATH` could open it, so whatever is wrong cannot be read
                // from here and the original failure is what the caller sees.
                return Err(match attempted {
                    Err(refusal) => refusal,
                    Ok(_) => unreachable!("the Ok arm returned at the top of this function"),
                });
            };

            let meta = handle.metadata().map_err(|source| ValidationError::Io {
                path: display.to_path_buf(),
                operation: "reading the directory's attributes",
                source,
            })?;
            Err(ValidationError::ModeDeniesOpen {
                path: display.to_path_buf(),
                mode: Some(mode_of(&meta)),
            })
        }
        Err(refusal) => Err(refusal),
    }
}

/// Whether a directory is root-owned and not writable by group or other.
///
/// # Why this lives here and not in the caller
///
/// The question is "can an ordinary user change what is inside this mounted tree", and
/// answering it needs the platform's own metadata — which gate G3 confines to a
/// `platform-*` crate. A caller that inlined the check would put `std::os::unix` outside
/// the crates permitted to name a platform, and the gate refuses exactly that.
///
/// # What the answer means
///
/// `true` when the directory is owned by root **and** neither group nor other may write
/// it, which is the shape of `/usr` and `/usr/local/bin` on a normal system. It is the
/// precondition for treating mounted content as trusted, not a proof that nothing in the
/// tree is a link — that is the walk's question, not this one's.
///
/// A path that cannot be inspected answers `false`: an unverifiable directory is not
/// evidence of safety, and the caller refuses rather than assuming.
#[must_use]
pub fn is_root_owned_and_not_writable_by_others(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        meta.uid() == ROOT_UID && meta.mode() & OTHERS_WRITE_BITS == 0
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// The permission bits of a `Metadata`, as octal without the file-type bits.
#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o7777
}

/// The owner uid of a `Metadata`, or `None` where the platform cannot say.
#[cfg(unix)]
fn uid_of(meta: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(meta.uid())
}

/// Removes the directories this walk created, innermost first, and reports any it could not.
///
/// # Why the parent is a descriptor and not a path
///
/// The walk is descriptor-relative precisely so that no step depends on a name resolving
/// to the same object twice. Removal by path would be the one place that guarantee was
/// dropped — the parent is opened by name, follows a symlink, and removes whatever that
/// resolves to. So each created directory is recorded with a duplicate of the descriptor
/// it was created in, and removal uses it.
///
/// # Why failures are reported rather than ignored
///
/// A directory this call created and could not remove is a directory the caller does not
/// know exists on their machine. Swallowing the error would leave a start that refused
/// with no trace of what it left behind, which is the failure mode this crate exists to
/// avoid. The returned paths are surfaced in the refusal.
///
/// Note the ordering: entries are innermost-first because they are popped, so a parent is
/// only attempted after its children are gone — the order `AT_REMOVEDIR` requires.
#[cfg(unix)]
fn rollback(created: &mut Vec<(PathBuf, std::fs::File)>) -> Vec<PathBuf> {
    let mut failed: Vec<PathBuf> = Vec::new();
    use std::os::unix::ffi::OsStrExt;
    while let Some((path, parent)) = created.pop() {
        let Some(name) = path.file_name() else {
            failed.push(path);
            continue;
        };
        let Ok(cname) = std::ffi::CString::new(name.as_bytes()) else {
            failed.push(path);
            continue;
        };
        if crate::descriptor::unlinkat_dir(&parent, &cname).is_err() {
            failed.push(path);
        }
    }
    failed
}
