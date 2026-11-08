//! Descriptor-relative directory operations, for facts stable `std` cannot express.
//!
//! # Why this module exists, and why it is allowed
//!
//! This crate is `deny(unsafe_code)` rather than `forbid`, and its own header says
//! why: stable Rust cannot report some facts, and the safe wrappers do not expose
//! them. The Windows `windows` module is that case — a 128-bit file identity, a link
//! count, and the native handle behind an open SQLite main database.
//!
//! `openat` is the same case on the other side: `std::fs` has no way to open a path
//! *relative to an open directory descriptor*. Every safe open takes a full path, so
//! the kernel resolves it from the process root — which means every component between
//! `/` and the target is a fresh lookup, and any of them can be swapped between the
//! moment it is checked and the moment it is used.
//!
//! That gap is not theoretical for this crate's caller. The daemon validates a state
//! root and its workspace and then hands the workspace to a sandbox as a bind
//! destination, where the parent components are walked again by a *different* process
//! (`bwrap`) using path-based, symlink-following operations. A walk that is not
//! descriptor-relative cannot promise the object it validated is the object the
//! sandbox mounts, and "the path looked right when we looked" is not a property.
//!
//! So this module contains the minimum surface that closes it: open a child relative
//! to a held descriptor, create a child relative to a held descriptor, and remove one.
//! Every function here is a thin wrapper whose entire body is one libc call — no
//! policy, no branching, no path construction. All of that lives in
//! [`crate::state_root`], which is safe code and is where the behaviour is tested.
//!
//! # What this does not claim
//!
//! Holding a descriptor pins an *inode*, not a *name*. A directory can still be
//! renamed or replaced, and a path derived from `/proc/self/fd` is a convenience for
//! messages, not an immutability guarantee. What these operations buy is that the
//! steps of one walk refer to the same object throughout the walk — which is the
//! window that matters, because the alternative is a name lookup between each step.
//!
//! # Invariants the caller must uphold
//!
//! * `name` must be a single path component with no `/` and no NUL. Callers pass
//!   components obtained from [`std::path::Component`], never a whole path.
//! * `dir` must be an open directory descriptor the caller owns.
//! * Errors are returned as [`std::io::Error`] with the raw errno preserved, so the
//!   caller can distinguish `ELOOP` (a symlink) from `ENOTDIR` (the wrong kind) from
//!   `EACCES` (a mode), which are three different rejections with three different
//!   operator remedies.

// The three wrappers below are the whole of this module's unsafe surface. `deny` at
// the crate level is deliberate and stays; this `allow` is scoped to exactly the
// module whose job is to call the C library for facts `std` does not expose, the same
// arrangement the `windows` module uses for its three.
#![allow(unsafe_code)]

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;

/// Opens `name` beneath `dir` and returns the descriptor.
///
/// # Errors
///
/// The underlying `openat` error, unmapped, so the caller sees the errno. `ELOOP`
/// means the final component is a symbolic link; `ENOTDIR` means it is not a
/// directory; `ENOENT` means it is absent; `EACCES` means the mode denies it.
///
/// # Safety
///
/// `openat` is called with a valid directory descriptor and a NUL-terminated name.
/// The returned descriptor is wrapped immediately in [`std::fs::File`], which owns
/// and closes it; no raw descriptor escapes this function. There is no pointer
/// arithmetic, no lifetime extension, and no transmute — the two pointers passed are
/// borrowed from values that outlive the call.
#[cfg(unix)]
pub fn openat(
    dir: &std::fs::File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> std::io::Result<std::fs::File> {
    // SAFETY: `dir` is a live directory descriptor borrowed for the duration of the
    // call; `name.as_ptr()` is a valid NUL-terminated string borrowed for the same
    // duration. The return value is either -1 (checked) or an owned descriptor, which
    // is moved into a `File` on the next line so it cannot leak or outlive its owner.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, exclusively-owned descriptor from the call above that
    // has not been handed to anything else. Wrapping it transfers that ownership to
    // the `File`, which closes it on drop.
    let file = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd) };
    Ok(file)
}

/// Creates the directory `name` beneath `dir`.
///
/// # Errors
///
/// The underlying `mkdirat` error. `EEXIST` means something already occupies the
/// name — the caller re-opens and re-verifies rather than assuming it created it, so
/// a concurrent creator is detected rather than trusted.
///
/// # Safety
///
/// As [`openat`]: a valid directory descriptor and a NUL-terminated name, both
/// borrowed for the duration of the call. `mkdirat` returns only a status, so there
/// is no descriptor to wrap and no ownership to transfer.
#[cfg(unix)]
pub fn mkdirat(
    dir: &std::fs::File,
    name: &std::ffi::CStr,
    mode: libc::mode_t,
) -> std::io::Result<()> {
    // SAFETY: `dir` is a live directory descriptor and `name.as_ptr()` a valid
    // NUL-terminated string, both borrowed for the duration of the call. The call
    // returns a status code only; it creates no descriptor and stores no pointer.
    let rc = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Removes the empty directory `name` beneath `dir`.
///
/// # Errors
///
/// The underlying `unlinkat` error. `ENOTEMPTY` and `EEXIST` mean the directory is
/// not empty, which the caller surfaces rather than forcing: a directory this walk
/// did not create is never removed.
///
/// # Safety
///
/// As [`openat`]. `AT_REMOVEDIR` is passed so the call refuses to remove anything
/// that is not an empty directory, which is what makes rollback safe to attempt.
#[cfg(unix)]
pub fn unlinkat_dir(dir: &std::fs::File, name: &std::ffi::CStr) -> std::io::Result<()> {
    // SAFETY: `dir` is a live directory descriptor and `name.as_ptr()` a valid
    // NUL-terminated string, both borrowed for the duration of the call. `AT_REMOVEDIR`
    // means the kernel refuses a non-directory or a non-empty directory, so the call
    // cannot remove a file the caller did not intend.
    let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// A path component turned into a NUL-terminated name, or a refusal.
///
/// A component containing a NUL byte cannot be passed to any of the calls above, and
/// a component containing `/` is not a component at all. Both are refused here rather
/// than sanitised, because a caller that reaches this with either is a bug and the
/// path must not be silently repaired into something else.
///
/// # Errors
///
/// [`std::io::ErrorKind::InvalidInput`] naming the component and which rule it broke.
#[cfg(unix)]
pub(crate) fn component_to_cstr(
    component: &std::path::Component<'_>,
) -> std::io::Result<std::ffi::CString> {
    let raw = component.as_os_str().as_bytes();
    if raw.contains(&b'/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "path component {:?} contains a separator; this is a bug, not a path",
                component.as_os_str()
            ),
        ));
    }
    std::ffi::CString::new(raw).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "path component {:?} contains a NUL byte and cannot be opened",
                component.as_os_str()
            ),
        )
    })
}
