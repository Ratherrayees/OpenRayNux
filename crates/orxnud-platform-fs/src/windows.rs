//! Native Windows file identity and SQLite main-database handle inspection.
//!
//! # Why this is unsafe code, and why it is confined here
//!
//! Stable Rust does not expose a file's 128-bit identifier, its link count, or
//! the native handle behind an open SQLite main database. The safe wrappers stop
//! at `std::fs::Metadata`, which carries none of them on stable Windows
//! (`windows_by_handle` #63010). ADR-0058's Windows disposition needs all three,
//! so this module calls the Win32 functions directly: `CreateFileW`,
//! `GetFileInformationByHandleEx` and `sqlite3_file_control`.
//!
//! Gate G4 permits `unsafe` in a `platform-*` crate; this crate uses `deny`
//! rather than `forbid` and allows it only in this module. Every block has a
//! `SAFETY` comment, and the only raw pointers that leave a block are the owned
//! handle wrapper and borrows whose owners outlive the call.
//!
//! # One resolution, two facts
//!
//! `observe` opens one handle and asks that handle for both the identity
//! (`FileIdInfo`) and the link count (`FileStandardInfo`). Asking the path twice
//! could describe two different files; asking one handle cannot.
//!
//! # What the handle is not
//!
//! The handle here is opened for attributes only. It is not the handle SQLite
//! uses, it is not retained, and it is closed before the function returns. The
//! handle inspected by `observe_sqlite_main` is SQLite's, is borrowed only for
//! the duration of the call, and is never closed here.

#![allow(unsafe_code)]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use orxnud_domain::platform::{FileFacts, FileId, SqliteMainDatabase, SqliteMainFacts};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
    FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx, OPEN_EXISTING,
};

/// An owned Win32 handle that is closed exactly once.
///
/// No handle opened by this module is returned to a caller; this wrapper exists
/// so the handle is closed even when a query below returns early. `Drop` is the
/// only place `CloseHandle` runs.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by a successful `CreateFileW`, is not
        // `INVALID_HANDLE_VALUE`, has not been closed, and `OwnedHandle` is its
        // only owner. `Drop` runs once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Why a path could not be opened for attributes.
enum OpenError {
    /// The path does not exist. This is a fact, not a failure.
    Absent,
    /// The platform could not establish the facts.
    Refused,
}

impl OpenError {
    /// Classifies the error the last Win32 call left behind.
    fn from_last_error() -> Self {
        match io::Error::last_os_error().raw_os_error() {
            Some(code)
                if code as u32 == ERROR_FILE_NOT_FOUND || code as u32 == ERROR_PATH_NOT_FOUND =>
            {
                Self::Absent
            }
            _ => Self::Refused,
        }
    }
}

/// Opens `path` for attribute queries.
///
/// The share mode is deliberately permissive. Bundled SQLite's `winOpen` opens
/// its database with `FILE_SHARE_READ | FILE_SHARE_WRITE` (no delete sharing),
/// unless the database URI sets `exclusive=1`, in which case it requests no
/// sharing. This observer additionally permits delete sharing; refusing to open a
/// file another process has open would make the observation fail for the
/// ordinary case. The flags let the same call observe a directory, matching Unix
/// `stat`.
fn open_for_attributes(path: &Path) -> Result<OwnedHandle, OpenError> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        // `CreateFileW` would silently stop at the NUL, observing a different
        // path than the caller named. Refusing is the only safe answer.
        return Err(OpenError::Refused);
    }
    wide.push(0);

    // SAFETY: `wide` is a live, NUL-terminated UTF-16 string for the duration of
    // the call. The security-attributes and template-handle arguments are null,
    // which `CreateFileW` documents as "no security attributes" and "no template".
    // The remaining arguments are plain flags and a valid creation disposition.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        Err(OpenError::from_last_error())
    } else {
        Ok(OwnedHandle(handle))
    }
}

/// Reads the identity and link count through an already-open handle.
///
/// The handle is only read from; ownership stays with the caller. On failure the
/// error carries the Win32 code so the caller can classify it, even though the
/// public contract currently maps every failure to `Unknown`.
fn query(handle: HANDLE) -> io::Result<(u64, FileId)> {
    // SAFETY: `FILE_ID_INFO` is a plain-old-data struct of an integer and a
    // 16-byte array, so an all-zero value is valid. `GetFileInformationByHandleEx`
    // writes exactly `size_of::<FILE_ID_INFO>()` bytes through the pointer on
    // success; the pointer refers to a live, correctly-aligned local for the whole
    // call, and the size is the one the API documents for `FileIdInfo`.
    let mut id: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: as above. `handle` is open for the duration of the call (either the
    // `OwnedHandle` in `observe` or SQLite's handle, which the connection owns).
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut id).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `FILE_STANDARD_INFO` is plain-old-data integers and booleans; an
    // all-zero value is valid. The same pointer/size contract as above applies,
    // with the size `FileStandardInfo` documents.
    let mut standard: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: as above; the handle is still open and the local is live.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&raw mut standard).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok((
        u64::from(standard.NumberOfLinks),
        FileId::Windows {
            volume_serial: id.VolumeSerialNumber,
            file_id: id.FileId.Identifier,
        },
    ))
}

/// Observes a path through one native handle.
pub(crate) fn observe(path: &Path) -> FileFacts {
    match open_for_attributes(path) {
        Err(OpenError::Absent) => FileFacts::Absent,
        Err(OpenError::Refused) => FileFacts::Unknown {
            platform: super::PLATFORM,
        },
        Ok(handle) => match query(handle.0) {
            Ok((name_count, identity)) => FileFacts::Known {
                name_count,
                identity: Some(identity),
            },
            Err(_) => FileFacts::Unknown {
                platform: super::PLATFORM,
            },
        },
    }
}

/// Observes the file behind SQLite's actual main-database handle.
///
/// # What is checked, and what is not
///
/// The connection must be a `rusqlite::Connection`; anything else is `Unknown`,
/// not `NotApplicable`, because this platform does have the API and simply could
/// not use it on that value. The `SQLITE_FCNTL_WIN32_GET_HANDLE` file-control
/// returns the `HANDLE` the Windows VFS opened. That handle is read for identity
/// and link count and is then left alone: SQLite owns it, and closing it here
/// would corrupt the connection.
///
/// An in-memory database, a connection whose main database has no file, or a
/// file-control that fails all answer `Unknown`. The store refuses on that
/// answer rather than falling back to the path check.
pub(crate) fn observe_sqlite_main(connection: SqliteMainDatabase<'_>) -> SqliteMainFacts {
    let Some(conn) = connection.downcast_ref::<rusqlite::Connection>() else {
        return SqliteMainFacts::Unknown {
            platform: super::PLATFORM,
        };
    };

    // SAFETY: `conn` is a live `rusqlite::Connection` borrowed for the duration
    // of this call. `handle()` returns the `sqlite3*` the connection owns; it is
    // valid until the connection is dropped, which cannot happen here because the
    // borrow is held.
    let db = unsafe { conn.handle() };
    if db.is_null() {
        return SqliteMainFacts::Unknown {
            platform: super::PLATFORM,
        };
    }

    // `INVALID_HANDLE_VALUE` is the sentinel; if the VFS writes a real handle it
    // replaces this value. Starting from the sentinel means a VFS that reports
    // success without writing cannot be mistaken for a usable handle.
    let mut raw: HANDLE = INVALID_HANDLE_VALUE;

    // SAFETY: `db` is a live SQLite connection handle as established above. The
    // database name is the NUL-terminated static string "main", which outlives the
    // call. `arg2` points to a live, correctly-aligned `HANDLE` local; SQLite's
    // file-control contract for this opcode is exactly "write the VFS handle
    // through this pointer". The call neither takes ownership of the connection
    // nor of the handle it reports.
    let rc = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            db,
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
            (&raw mut raw).cast(),
        )
    };

    if rc != rusqlite::ffi::SQLITE_OK || raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return SqliteMainFacts::Unknown {
            platform: super::PLATFORM,
        };
    }

    match query(raw) {
        Ok((name_count, identity)) => SqliteMainFacts::Known {
            name_count,
            identity,
        },
        Err(_) => SqliteMainFacts::Unknown {
            platform: super::PLATFORM,
        },
    }
}
