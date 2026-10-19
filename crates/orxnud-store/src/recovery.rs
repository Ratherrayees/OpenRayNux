//! Durable roll-forward recovery for a failed restore (F-26b).
//!
//! # The defect this closes
//!
//! `RestoreGuard` opens the live database and runs `wal_checkpoint(TRUNCATE)` *before* the
//! restore copy. Both mutate: SQLite may recover a stale `-wal` during the open, and the
//! checkpoint folds further frames into the main file. If the copy then fails, that
//! post-snapshot data is **absorbed** into the live database and the log is truncated, so
//! nothing can replay it away. The old code reported the failure honestly and rolled
//! nothing back.
//!
//! Rolling *back* is not available: removing the checkpoint would break S-30's criterion 4(a),
//! and replacing the file by rename would break the same-inode guarantee in 4(b). So this
//! rolls **forward** instead.
//!
//! # Why roll-forward fixes it
//!
//! The staged image — not the live database — is the authority. Absorption is allowed to
//! happen; what changes is that an unfinished restore is *detectably unfinished*, and is
//! retried until the staged content is installed and independently verified. An absorbed
//! state is therefore never observable as a served database: it is either overwritten, or
//! overwritten again by the retry.
//!
//! # The state machine
//!
//! Two artefacts on disk, and the pair distinguishes every crash window without trusting a
//! bare filename:
//!
//! | On disk | State | Action on next open |
//! |---|---|---|
//! | neither | [`RestoreState::Idle`] | nothing outstanding |
//! | staging only | [`RestoreState::Prepared`] | discard the staging file; the database was never touched |
//! | intent present | [`RestoreState::Outstanding`] | **roll forward**: install, checkpoint, verify, finalise |
//!
//! `Prepared` is reachable only by a crash between staging and publishing the intent, which
//! is why publishing is ordered last and made durable first. The invariant is:
//!
//! > **An intent file exists only if the staged image it names is complete, verified and
//! > durable.** Publishing is therefore the single commit point of the whole operation.
//!
//! Once published, every subsequent step is idempotent — installing the same staged image
//! twice yields the same bytes — so no other window needs its own recovery rule.
//!
//! # Durability
//!
//! Each step is flushed before the next begins, and directory entries are flushed after
//! renames and removals, because on Linux a rename is only durable once the *parent
//! directory entry* is written. See [`fsync_file`] and [`fsync_dir`] for the platform
//! position; **Windows does not currently get directory durability from `std`**, so
//! [`Durability::directory_flushed`] is false there and [`Durability::report`] says so.
//! That is a measured limitation, not an assumption, and it is why F-26b is not claimed
//! closed cross-platform.

use std::path::{Path, PathBuf};

use crate::backup::BackupError;

// --------------------------------------------------------------------------
// Test-only fault injection.
//
// The seams live here, at the operation boundaries the recovery protocol has, and they
// exist **only** under `#[cfg(test)]`. A production build does not contain the module,
// the arms, the flags, or the checks that consult them: there is no environment
// variable, no public entry point, and no way for another thread to reach them.
//
// Every seam is one-shot and per-thread, and every test that arms one must assert that
// it actually fired. A test that passes because the fault never triggered is worse
// than no test, because it looks like evidence.
// --------------------------------------------------------------------------
/// Test-only: a log of the durability operations performed, in order.
///
/// It exists so the *ordering* of the durability chain can be asserted rather than
/// inferred. A test that only checked "the restore succeeded" would not notice that
/// the parent directory was flushed after the intent was published.
#[cfg(test)]
pub(crate) mod record {
    use std::cell::RefCell;
    use std::path::Path;

    std::thread_local! {
        static LOG: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    pub(crate) fn note(op: &str, path: &Path) {
        LOG.with(|l| l.borrow_mut().push(format!("{op} {}", path.display())));
    }

    /// The operations recorded so far, in order.
    pub(crate) fn entries() -> Vec<String> {
        LOG.with(|l| l.borrow().clone())
    }

    pub(crate) fn clear() {
        LOG.with(|l| l.borrow_mut().clear());
    }
}

#[cfg(test)]
pub(crate) mod seams {
    use std::cell::RefCell;

    /// The points in the recovery protocol at which a test can inject a failure.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum Fault {
        /// Before the intent file is written. Nothing has been published.
        BeforeIntentPublish,
        /// After the intent is durable on disk, but before the caller learns it
        /// succeeded. This is the commit point: the intent *is* on disk.
        AfterIntentPublish,
        /// Part-way through the in-place copy, so the live database is genuinely
        /// partial.
        DuringCopy,
        /// After the copy has completed, before the write-ahead log is finalised.
        BeforeFinalize,
        /// At the post-copy verification, so the digest is never accepted.
        DuringVerification,
        /// After the data has been installed and verified, before the intent that
        /// authorises trusting it is cleared.
        BeforeClearIntent,
        /// A directory entry flush fails. The durability chain must stop here, and the
        /// live database must not be touched.
        DirectoryFlush,
    }

    std::thread_local! {
        static ARMED: RefCell<Option<Fault>> = const { RefCell::new(None) };
        static FIRED: RefCell<Vec<Fault>> = const { RefCell::new(Vec::new()) };
    }

    /// Arm `fault` for this thread. One-shot: consumed by the first matching check.
    pub(crate) fn arm(fault: Fault) {
        ARMED.with(|a| *a.borrow_mut() = Some(fault));
    }

    /// Whether `fault` has actually been reached on this thread.
    pub(crate) fn fired(fault: Fault) -> bool {
        FIRED.with(|f| f.borrow().contains(&fault))
    }

    /// Disarm and forget every recorded firing.
    pub(crate) fn reset() {
        ARMED.with(|a| *a.borrow_mut() = None);
        FIRED.with(|f| f.borrow_mut().clear());
    }

    /// Fail here if `fault` is armed, recording that it fired.
    pub(crate) fn check(fault: Fault) -> Result<(), String> {
        let armed = ARMED.with(|a| *a.borrow());
        if armed == Some(fault) {
            FIRED.with(|f| f.borrow_mut().push(fault));
            return Err(format!("injected fault at {fault:?}"));
        }
        Ok(())
    }
}

/// Format version written into every intent. A file this cannot parse is **not** ignored.
pub const INTENT_FORMAT: u32 = 1;

/// The staging file an intended restore is assembled in.
///
/// A **sibling** of the database: the staged image must be on the same filesystem so that
/// nothing here needs a cross-device copy, which cannot be atomic.
#[must_use]
pub fn staging_path_for(db_path: &Path) -> PathBuf {
    sibling(db_path, ".restore-staging")
}

/// The durable record that a restore is outstanding.
#[must_use]
pub fn intent_path_for(db_path: &Path) -> PathBuf {
    sibling(db_path, ".restore-intent")
}

fn sibling(db_path: &Path, suffix: &str) -> PathBuf {
    let mut name = db_path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    db_path.with_file_name(name)
}

/// What the on-disk pair says about a restore.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RestoreState {
    /// No staging file and no intent. Nothing is outstanding.
    Idle,
    /// A staged image with no intent: a crash before the commit point. The database was
    /// never touched, so the staging file is pure debris.
    Prepared,
    /// An intent is published. The restore must be driven to completion.
    Outstanding,
}

/// Reads the state from disk. Cheap enough to run on every open.
#[must_use]
pub fn restore_state(db_path: &Path) -> RestoreState {
    match (
        intent_path_for(db_path).exists(),
        staging_path_for(db_path).exists(),
    ) {
        (false, false) => RestoreState::Idle,
        (false, true) => RestoreState::Prepared,
        (true, _) => RestoreState::Outstanding,
    }
}

/// A published restore intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreIntent {
    /// Wire format, so a future layout cannot be misread as this one.
    pub format: u32,
    /// The database this intent restores.
    pub target: PathBuf,
    /// The staged image to install.
    pub staging: PathBuf,
    /// The logical digest the restored database must have.
    pub digest: String,
}

impl RestoreIntent {
    /// Serialises it in a fixed, line-oriented form.
    ///
    /// Paths may contain `=` or newlines on some platforms, so each field is on its own
    /// line and the path is the remainder of that line. A path containing a newline would
    /// be misparsed — recorded rather than defended against, because the value comes from
    /// `Backup::path_for`, not from user input.
    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "format={}\ntarget={}\nstaging={}\ndigest={}\n",
            self.format,
            self.target.display(),
            self.staging.display(),
            self.digest,
        )
    }

    /// Parses [`Self::to_text`].
    ///
    /// # Errors
    ///
    /// [`RecoveryError::Malformed`] if a field is missing, duplicated, or the format is
    /// not [`INTENT_FORMAT`]. An unreadable intent is **never** treated as "nothing to do":
    /// that would silently abandon an outstanding restore.
    pub fn parse(text: &str) -> Result<Self, RecoveryError> {
        let mut format = None;
        let mut target = None;
        let mut staging = None;
        let mut digest = None;
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let slot = match key {
                "format" => &mut format,
                "target" => &mut target,
                "staging" => &mut staging,
                "digest" => &mut digest,
                _ => continue,
            };
            if slot.is_some() {
                return Err(RecoveryError::Malformed(format!("duplicate `{key}`")));
            }
            *slot = Some(value.to_owned());
        }
        let format = format
            .ok_or_else(|| RecoveryError::Malformed("no `format` field".into()))?
            .parse::<u32>()
            .map_err(|_| RecoveryError::Malformed("`format` is not a number".into()))?;
        if format != INTENT_FORMAT {
            return Err(RecoveryError::Malformed(format!(
                "format {format} is not {INTENT_FORMAT}"
            )));
        }
        Ok(Self {
            format,
            target: PathBuf::from(
                target.ok_or_else(|| RecoveryError::Malformed("no `target` field".into()))?,
            ),
            staging: PathBuf::from(
                staging.ok_or_else(|| RecoveryError::Malformed("no `staging` field".into()))?,
            ),
            digest: digest.ok_or_else(|| RecoveryError::Malformed("no `digest` field".into()))?,
        })
    }
}

/// Why recovery could not complete. Every variant leaves the intent and staging file in
/// place, so a later open retries.
#[derive(Debug)]
pub enum RecoveryError {
    /// The intent file is unreadable or inconsistent. Treated as outstanding on purpose.
    Malformed(String),
    /// A filesystem operation failed.
    Io {
        /// What was being attempted.
        what: String,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The staged image is gone or does not match the intent.
    StagingUnavailable(String),
    /// The install completed but the main database does not yet hold the staged state.
    NotFinalised(String),
    /// The platform cannot establish the durability this protocol requires.
    DurabilityUnavailable(String),
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "the restore intent is malformed: {m}"),
            Self::Io { what, source } => write!(f, "restore recovery could not {what}: {source}"),
            Self::StagingUnavailable(m) => {
                write!(f, "the staged restore image is unusable: {m}")
            }
            Self::DurabilityUnavailable(m) => write!(
                f,
                "refusing to restore: the durability this protocol requires is unavailable \
                 and a restore would not survive a crash. {m}"
            ),
            Self::NotFinalised(m) => write!(
                f,
                "the restore could not be finalised, so the database is not yet the \
                 intended state: {m}"
            ),
        }
    }
}

impl std::error::Error for RecoveryError {}

impl From<RecoveryError> for BackupError {
    fn from(e: RecoveryError) -> Self {
        BackupError::Io {
            path: e.to_string(),
            source: std::io::Error::other(e.to_string()),
        }
    }
}

/// Whether the durability primitives this build has are sufficient for the intent.
///
/// Recorded rather than assumed: a build that cannot flush a directory cannot promise that
/// a published intent survives a crash, and the answer must be visible rather than inferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Durability {
    /// `File::sync_all` on the staging file and the intent file.
    pub file_flushed: bool,
    /// Directory entries flushed after rename and removal.
    pub directory_flushed: bool,
}

impl Durability {
    /// Refuses when the durability this protocol depends on is unavailable.
    ///
    /// # Why a refusal and not a warning
    ///
    /// The protocol's safety rests on one fact: **the published intent survives a crash.**
    /// A rename is only durable once the *parent directory entry* has been written, so
    /// without a directory flush the intent can be lost while the live database has already
    /// been modified — which is exactly the state F-26b exists to prevent, reintroduced by
    /// the mechanism meant to prevent it.
    ///
    /// `Durability::report()` saying "false" is a *report*, not a guarantee, and reporting it
    /// while proceeding anyway would make the check decorative. So this refuses, and it
    /// refuses **before** anything destructive: no staging, no intent, no copy.
    ///
    /// # Errors
    ///
    /// [`RecoveryError::DurabilityUnavailable`] naming what is missing and what it would
    /// take to fix it.
    pub fn require() -> Result<Self, RecoveryError> {
        let d = Self::report();
        if !d.file_flushed {
            return Err(RecoveryError::DurabilityUnavailable(
                "flushing a file is unavailable on this platform".into(),
            ));
        }
        if !d.directory_flushed {
            return Err(RecoveryError::DurabilityUnavailable(
                "directory entries cannot be flushed on this platform, so a published \
                 restore intent would not survive a crash. Windows `std::fs::File::open` \
                 rejects a directory; a native `FlushFileBuffers` on a directory handle \
                 opened with FILE_FLAG_BACKUP_SEMANTICS is required, and until that exists \
                 this platform refuses to restore rather than assume it is durable."
                    .into(),
            ));
        }
        Ok(d)
    }

    /// What this platform can currently guarantee.
    #[must_use]
    pub fn report() -> Self {
        Self {
            file_flushed: true,
            directory_flushed: crate::backup::directory_fsync_supported(),
        }
    }
}

/// Flushes a file's contents and metadata.
pub fn fsync_file(p: &Path) -> Result<(), RecoveryError> {
    #[cfg(test)]
    record::note("fsync_file", p);
    let f = std::fs::File::open(p).map_err(|source| RecoveryError::Io {
        what: format!("open {} to flush it", p.display()),
        source,
    })?;
    f.sync_all().map_err(|source| RecoveryError::Io {
        what: format!("flush {}", p.display()),
        source,
    })
}

/// Flushes a directory entry so a rename or removal inside it survives a crash.
///
/// # Platform position
///
/// Works on Linux (measured). **On Windows `std::fs::File::open` on a directory fails**, so
/// this is a no-op there and the intent's directory entry is **not** made durable by `std`.
/// That is a real limitation, not a silent one: [`Durability::report`] exposes it.
pub fn fsync_dir(dir: &Path) -> Result<(), RecoveryError> {
    #[cfg(test)]
    record::note("fsync_dir", dir);
    #[cfg(test)]
    seams::check(seams::Fault::DirectoryFlush).map_err(|what| RecoveryError::Io {
        what,
        source: std::io::Error::other("injected"),
    })?;
    if !crate::backup::directory_fsync_supported() {
        return Ok(());
    }
    let f = match std::fs::File::open(dir) {
        Ok(f) => f,
        Err(source) => {
            return Err(RecoveryError::Io {
                what: format!("open {} to flush the directory entry", dir.display()),
                source,
            });
        }
    };
    f.sync_all().map_err(|source| RecoveryError::Io {
        what: format!("flush directory {}", dir.display()),
        source,
    })
}

/// The directory whose entry makes `p`'s **name** durable.
///
/// Flushing the file itself is not enough: a file's name lives in its parent directory's
/// entry, and that entry is what a crash can lose. A restore that published an intent
/// naming a staged file whose directory entry was never flushed could find the intent
/// present and the image missing.
///
/// A path with no parent is an error rather than a silent skip: the flush is required,
/// and skipping it would make the durability claim false.
pub(crate) fn parent_dir_of(p: &Path) -> Result<PathBuf, RecoveryError> {
    p.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .ok_or_else(|| RecoveryError::Io {
            what: format!("{} has no parent directory to flush", p.display()),
            source: std::io::Error::other("no parent directory"),
        })
}

fn parent_of(p: &Path) -> PathBuf {
    p.parent()
        .filter(|d| !d.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Writes and durably publishes an intent.
///
/// The commit point of the whole protocol: everything before this is discardable, and
/// everything after it is idempotent. The staging file must already be flushed by the
/// caller, because **an intent naming an unsynced image would, after a crash, point at a
/// truncated file.**
pub(crate) fn publish_intent(intent: &RestoreIntent) -> Result<(), RecoveryError> {
    #[cfg(test)]
    record::note("publish_intent", &intent_path_for(&intent.target));
    // The commit point of the whole operation. Nothing before this line has told
    // anybody that a restore is outstanding, and everything after it has.
    #[cfg(test)]
    seams::check(seams::Fault::BeforeIntentPublish).map_err(|what| RecoveryError::Io {
        what,
        source: std::io::Error::other("injected"),
    })?;
    let path = intent_path_for(&intent.target);
    let tmp = sibling(&intent.target, ".restore-intent.tmp");
    std::fs::write(&tmp, intent.to_text()).map_err(|source| RecoveryError::Io {
        what: format!("write {}", tmp.display()),
        source,
    })?;
    fsync_file(&tmp)?;
    std::fs::rename(&tmp, &path).map_err(|source| RecoveryError::Io {
        what: format!("publish {}", path.display()),
        source,
    })?;
    fsync_dir(&parent_of(&path))?;
    // The intent is now durable. A failure *here* is the most interesting one in the
    // protocol: the file exists and is authoritative, but the caller was told the
    // operation failed. The next open must roll forward.
    #[cfg(test)]
    seams::check(seams::Fault::AfterIntentPublish).map_err(|what| RecoveryError::Io {
        what,
        source: std::io::Error::other("injected"),
    })?;
    Ok(())
}

/// Removes a published intent, durably.
///
/// Called **only** after the restored main database has been verified independently.
pub(crate) fn clear_intent(db_path: &Path) -> Result<(), RecoveryError> {
    let path = intent_path_for(db_path);
    match std::fs::remove_file(&path) {
        Ok(()) => fsync_dir(&parent_of(&path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(RecoveryError::Io {
            what: format!("remove {}", path.display()),
            source,
        }),
    }
}

/// Reads the published intent, or `None` when none is published.
///
/// # Errors
///
/// Propagates [`RecoveryError::Malformed`] rather than collapsing to `None`: an intent that
/// cannot be parsed is an outstanding restore, and treating it as absent would let a
/// half-restored database be served.
pub fn read_intent(db_path: &Path) -> Result<Option<RestoreIntent>, RecoveryError> {
    let path = intent_path_for(db_path);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(RecoveryError::Io {
                what: format!("read {}", path.display()),
                source,
            });
        }
    };
    RestoreIntent::parse(&text).map(Some)
}

/// Discards a staged image that was never published.
///
/// Called when the state is [`RestoreState::Prepared`]. The database was not touched, so
/// this loses nothing.
pub(crate) fn discard_prepared(db_path: &Path) -> Result<(), RecoveryError> {
    let staging = staging_path_for(db_path);
    match std::fs::remove_file(&staging) {
        Ok(()) => fsync_dir(&parent_of(&staging)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(RecoveryError::Io {
            what: format!("remove {}", staging.display()),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> PathBuf {
        std::env::temp_dir().join(format!("orxnud-recovery-{}", std::process::id()))
    }

    #[test]
    fn an_intent_round_trips_through_its_wire_format() {
        let i = RestoreIntent {
            format: INTENT_FORMAT,
            target: db().join("state.db"),
            staging: db().join("state.db.restore-staging"),
            digest: "0123456789abcdef".into(),
        };
        let back = RestoreIntent::parse(&i.to_text()).expect("round trip");
        assert_eq!(back, i);
    }

    #[test]
    fn a_malformed_intent_is_never_read_as_absent() {
        for bad in [
            "",
            "target=/x\n",
            "format=99\ntarget=/x\nstaging=/y\ndigest=z\n",
        ] {
            assert!(
                RestoreIntent::parse(bad).is_err(),
                "a malformed intent must be an error, not `None`: {bad:?}"
            );
        }
    }

    #[test]
    fn state_is_derived_from_the_pair_not_a_bare_filename() {
        let d = db();
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let target = d.join("state.db");
        assert_eq!(restore_state(&target), RestoreState::Idle);
        std::fs::write(staging_path_for(&target), b"x").unwrap();
        assert_eq!(restore_state(&target), RestoreState::Prepared);
        std::fs::write(intent_path_for(&target), b"format=1\n").unwrap();
        assert_eq!(
            restore_state(&target),
            RestoreState::Outstanding,
            "an intent dominates a stale staging file"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn durability_is_reported_rather_than_assumed() {
        let d = Durability::report();
        assert!(d.file_flushed, "flushing a file is portable and must work");
        assert!(
            d.directory_flushed,
            "this host measured directory fsync as supported; a failure here means the \
             platform position changed and the closure claim must be revisited"
        );
    }
}
/// Installs a staged image over the live database, **in place**, and finalises it.
///
/// # The finalization sequence, and why each step is where it is
///
/// Measured against this repository's pinned SQLite (3.53.2) before it was written; see
/// the validation pass. Two findings drive the order:
///
/// 1. `Backup::new` **preserves** the destination's `wal` journal mode, and while the
///    destination connection is open the restored content lives **only in the `-wal`** — a
///    read of the main file alone still returns the pre-restore rows.
/// 2. Removing `-wal`/`-shm` at that moment **destroys the restore and leaves the database
///    unreadable** (`disk I/O error`). That was the negative control.
///
/// So:
///
/// 1. install in place (writer open, WAL absorbs the writes — unavoidable and now harmless);
/// 2. **close the destination connection**, so SQLite's last-connection checkpoint runs;
/// 3. if a `-wal` still exists, open a fresh connection and `wal_checkpoint(TRUNCATE)`;
/// 4. close that connection;
/// 5. assert no WAL content remains — presence *or* absence is tested, never assumed;
/// 6. **only now** read the live database normally: with no log to mask it, that read is a
///    read of the main file, and it must equal the staged digest;
/// 7. remove leftover sidecars, flush the main file and its directory;
/// 8. clear the intent.
///
/// If step 5 or 6 fails, the intent **stays** and the caller must refuse. A live database
/// that does not yet equal the staged image is not a recoverable state to serve.
///
/// # Errors
///
/// [`RecoveryError`] in every failure case, with the intent and staging file left intact so
/// a later open retries. Nothing here ever reports success on a path that has not been
/// verified.
pub(crate) fn install_staged(
    target: &Path,
    staging: &Path,
    expected_digest: &str,
) -> Result<(), BackupError> {
    // Before anything destructive. A platform that cannot make an intent durable must not
    // install one, or must not act on one.
    Durability::require().map_err(|e| BackupError::Io {
        path: target.display().to_string(),
        source: std::io::Error::other(e),
    })?;
    if !staging.is_file() {
        return Err(BackupError::Missing(staging.to_path_buf()));
    }
    let w = |p: &Path, source: rusqlite::Error| BackupError::Write {
        path: p.display().to_string(),
        source,
    };

    // 0. Quiesce whatever log the live database already has, **before** installing.
    //
    //    This was found by `a_crash_after_the_intent_is_published_is_completed_by_the_next_open`,
    //    which is what the tests are for. The backup API writes the restored pages into the
    //    *main file*; if a `-wal` from before the restore still holds newer frames, SQLite
    //    replays them over those pages and the database ends up neither the pre-restore nor
    //    the restored state — `RestoreUnverified`, correctly, but a restore that cannot
    //    succeed.
    //
    //    Absorbing here is now **harmless**, which is the whole point of the roll-forward:
    //    the intent is already published and durable, so if this process dies the next one
    //    repeats the whole install. That is what it cost to get here, and it was worth it.
    quiesce_existing_log(target)?;

    // 1. Install in place. Never a rename: S-30 4(b) requires the same inode.
    {
        let src = rusqlite::Connection::open_with_flags(
            staging,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|source| w(staging, source))?;
        let mut dst = rusqlite::Connection::open(target).map_err(|source| w(target, source))?;
        // The copy is stepped explicitly rather than through `run_to_completion`, so
        // that a test can fail it *part-way through* and leave a genuinely partial live
        // database behind. The behaviour is the same as `run_to_completion`: the same
        // page count per step, the same pause, the same treatment of `Busy`/`Locked`.
        let backup =
            rusqlite::backup::Backup::new(&src, &mut dst).map_err(|source| w(target, source))?;
        loop {
            use rusqlite::backup::StepResult;
            let step = backup.step(64).map_err(|source| w(target, source))?;
            // The fault is checked between steps, so the live database holds some of
            // the restored pages and not all of them.
            #[cfg(test)]
            seams::check(seams::Fault::DuringCopy).map_err(|what| BackupError::Write {
                path: target.display().to_string(),
                source: rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(
                    what,
                ))),
            })?;
            match step {
                StepResult::Done => break,
                StepResult::More | StepResult::Busy | StepResult::Locked => {
                    std::thread::sleep(std::time::Duration::from_millis(0));
                }
                // `StepResult` is `#[non_exhaustive]`: an unknown variant is
                // treated as "more to do", exactly as `run_to_completion` does.
                _ => std::thread::sleep(std::time::Duration::from_millis(0)),
            }
        }
        // 2. Close. The step an earlier draft got wrong: the restored content lives in
        //    the -wal until the destination connection goes away.
    }

    // 3-4. If a log survives the last close, checkpoint it explicitly, then close again.
    //
    // The seam sits between the copy and the finalisation, because that is the window
    // in which the restored content may still be only in the write-ahead log.
    #[cfg(test)]
    seams::check(seams::Fault::BeforeFinalize).map_err(|what| BackupError::Write {
        path: target.display().to_string(),
        source: rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(what))),
    })?;
    finalize_log(target)?;

    // 5-6. With no log left, a normal read *is* a read of the main file.
    #[cfg(test)]
    seams::check(seams::Fault::DuringVerification).map_err(|what| BackupError::Write {
        path: target.display().to_string(),
        source: rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(what))),
    })?;
    let digest = live_digest(target)?;
    if digest != expected_digest {
        return Err(BackupError::RestoreUnverified {
            path: target.display().to_string(),
        });
    }

    // 7. Leftover sidecars are safe to drop now, and the main file must be durable before
    //    the intent that authorises trusting it is cleared.
    remove_sidecars(target).map_err(BackupError::from)?;
    fsync_file(target).map_err(BackupError::from)?;
    fsync_dir(&parent_of(target)).map_err(BackupError::from)
}

/// Checkpoints any surviving write-ahead log and closes the connection that did it.
///
/// Both the *existence* and the *absence* of a `-wal` are handled. The ADR's 2026-10-14
/// measurement recorded that `wal_checkpoint`'s counters are advisory — a truncate that
/// demonstrably ran once returned `log=0 ckpt=0` — so the result is judged by observing the
/// file, not by reading a number.
fn quiesce_existing_log(target: &Path) -> Result<(), BackupError> {
    finalize_log(target)
}

/// Checkpoints any surviving write-ahead log and closes the connection that did it.
fn finalize_log(target: &Path) -> Result<(), BackupError> {
    let wal = sidecar(target, "-wal");
    if !wal.exists() {
        // The last connection's checkpoint already absorbed it. Not an assumption about
        // size: the file is absent, so there is nothing to replay.
        return Ok(());
    }
    let conn =
        rusqlite::Connection::open_with_flags(target, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(|source| RecoveryError::Io {
                what: format!("open {} to checkpoint its log", target.display()),
                source: std::io::Error::other(source),
            })?;
    let busy: i64 = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |r| r.get(0))
        .map_err(|source| BackupError::Write {
            path: target.display().to_string(),
            source,
        })?;
    drop(conn);
    if busy != 0 {
        return Err(BackupError::Busy {
            path: target.display().to_string(),
            readers: busy,
        });
    }
    // Observed, not asserted from the pragma's counters.
    if wal.exists() && std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0) > 0 {
        return Err(BackupError::RestoreUnverified {
            path: wal.display().to_string(),
        });
    }
    Ok(())
}

fn sidecar(db_path: &Path, suffix: &str) -> PathBuf {
    let mut name = db_path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    db_path.with_file_name(name)
}

fn remove_sidecars(target: &Path) -> Result<(), RecoveryError> {
    for s in ["-wal", "-shm"] {
        let p = sidecar(target, s);
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(RecoveryError::Io {
                    what: format!("remove {}", p.display()),
                    source,
                });
            }
        }
    }
    Ok(())
}

/// The live database's logical digest, read through a **normal** connection.
///
/// Safe only because [`finalize_log`] has already established that no log can mask the
/// result. `immutable=1` is deliberately not used here: it is the wrong tool for a
/// *mutable* target, and after finalization it is unnecessary.
fn live_digest(target: &Path) -> Result<String, BackupError> {
    let c =
        rusqlite::Connection::open_with_flags(target, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|source| BackupError::Unreadable {
            path: target.display().to_string(),
            source,
        })?;
    crate::backup::logical_digest(&c).map_err(|source| BackupError::Unreadable {
        path: target.display().to_string(),
        source,
    })
}

/// Completes any outstanding restore, or does nothing when none is outstanding.
///
/// **The single enforcement point (F-26b).** Called from
/// `crate::ownership::acquire_shared` and `crate::ownership::acquire_exclusive`, which
/// every production live-database open passes through: `Store::open`,
/// `SqliteAuditJournal::open`, `SqliteApprovalLedger::open`, and `RestoreGuard::acquire_with`.
/// That is why it is here and not in `Store::open` — the audit establishing four routes is
/// in the verification register, and `Store::open` is only one of them.
///
/// # Rules this enforces
///
/// * A shared lease is never granted while an intent is outstanding, so a half-restored
///   database cannot become usable.
/// * Recovery takes the **exclusive** lease, through the `_unchecked` acquisition, so it
///   cannot recurse into the check that triggered it.
/// * A competitor holding the database makes the exclusive acquisition fail fast and typed;
///   it is never waited on and never bypassed.
/// * The check and the lease are not separated by a window in which the state could change:
///   the state is re-read *inside* the exclusive lease below.
///
/// # Errors
///
/// Propagated, so [`crate::ownership`] converts them into a refusal. The intent and staging
/// file are left in place on every failure path.
pub fn complete_outstanding_restore(db_path: &Path) -> Result<(), RecoveryError> {
    // Exclusive ownership for the whole of recovery. Taken without the check inside,
    // or recovery would require itself.
    let _lease =
        crate::ownership::acquire_exclusive_unchecked(db_path).map_err(|e| RecoveryError::Io {
            what: "take exclusive ownership to complete the restore".into(),
            source: std::io::Error::other(e),
        })?;
    complete_outstanding_restore_under_lease(db_path)
}

/// The body of [`complete_outstanding_restore`], for a caller that **already holds the
/// exclusive lease**.
///
/// Holding the exclusive lease is what makes the state read below trustworthy: a restore
/// publishes its intent under the exclusive lease, so no other process can publish one,
/// complete one, or remove one while the lease is held. The read here is therefore not
/// a stale observation that has to be re-taken later.
pub(crate) fn complete_outstanding_restore_under_lease(
    db_path: &Path,
) -> Result<(), RecoveryError> {
    match restore_state(db_path) {
        RestoreState::Idle => return Ok(()),
        // Never committed. The live database was not touched, so there is nothing to do
        // but drop the debris.
        RestoreState::Prepared => return discard_prepared(db_path),
        RestoreState::Outstanding => {}
    }

    // Re-read the state *under* the lease. Between the check above and this point another
    // process could have published an intent; this is the read that counts.
    let intent = match read_intent(db_path)? {
        Some(i) => i,
        // Cleared by whoever held the lease before us. Nothing outstanding now.
        None => return discard_prepared(db_path),
    };
    if intent.target != db_path {
        return Err(RecoveryError::Malformed(format!(
            "the intent names {} but this database is {}",
            intent.target.display(),
            db_path.display()
        )));
    }

    install_staged(db_path, &intent.staging, &intent.digest).map_err(|e| RecoveryError::Io {
        what: format!("install the staged image: {e}"),
        source: std::io::Error::other(e),
    })?;
    // The data is installed and verified, but the protocol is not complete until the
    // intent is gone. A failure here leaves a *contradictory* state if it were not
    // handled: the database holds the right content and the intent still says a
    // restore is outstanding.
    #[cfg(test)]
    seams::check(seams::Fault::BeforeClearIntent).map_err(|what| RecoveryError::Io {
        what,
        source: std::io::Error::other("injected"),
    })?;
    clear_intent(db_path)?;
    // The staged image has served its purpose and the intent is gone; drop it so a
    // later crash cannot mistake it for a prepared-but-uncommitted restore.
    discard_prepared(db_path)
}

#[cfg(test)]
mod rollforward {
    use super::*;
    use crate::pragma::Pragma;
    use rusqlite::{Connection, OpenFlags};

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("orxnud-rollf-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// A migrated database carrying `PRE-SNAPSHOT-ONLY`.
    fn base(d: &Path, name: &str) -> PathBuf {
        let p = d.join(name);
        let c = Connection::open(&p).expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        crate::migration::MigrationRunner::new(&c)
            .migrate(&p)
            .expect("migrate");
        c.execute_batch("CREATE TABLE IF NOT EXISTS audit_note (id INTEGER PRIMARY KEY, t TEXT);")
            .expect("table");
        c.execute("INSERT INTO audit_note VALUES (1,'PRE-SNAPSHOT-ONLY');", [])
            .expect("row");
        p
    }

    fn notes(p: &Path) -> String {
        Connection::open_with_flags(p, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open")
            .query_row(
                "SELECT COALESCE(group_concat(t),'') FROM audit_note;",
                [],
                |r| r.get::<_, String>(0),
            )
            .expect("read")
    }

    /// Staging + intent publication, without the install. This is the state a crash
    /// between steps 4 and 5 leaves behind, and it is produced here **directly** rather
    /// than by racing a kill, so the test is deterministic.
    fn stage_and_publish(db: &Path, staged: &Path) -> String {
        // The intent carries the **logical digest**, the same value
        // `install_staged` recomputes from the live main file. Storing anything else here
        // would make every restore fail verification -- which is the protocol working, and
        // is exactly what it did the first time this test was written.
        let digest = crate::backup::logical_digest(
            &Connection::open_with_flags(staged, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("open staged"),
        )
        .expect("digest");
        fsync_file(staged).expect("flush staged");
        publish_intent(&RestoreIntent {
            format: INTENT_FORMAT,
            target: db.to_path_buf(),
            staging: staged.to_path_buf(),
            digest: digest.clone(),
        })
        .expect("publish");
        digest
    }

    /// **A crash after the intent is published is recovered by rolling forward.**
    ///
    /// The live database here is in the pre-restore state with extra rows, exactly as it
    /// would be if the process died between publishing the intent and finishing. The
    /// recovery must leave it holding the staged content, and it must do so *without any
    /// human intervention* — the next open does it.
    #[test]
    fn a_crash_after_the_intent_is_published_is_completed_by_the_next_open() {
        let d = dir("rollf-crash");
        let db = base(&d, "state.db");
        // The staged image: the intended post-restore content.
        let staged = base(&d, "state.db.restore-staging");
        // The live database gains a post-snapshot row, then we "crash".
        let c = Connection::open(&db).expect("open");
        c.execute("INSERT INTO audit_note VALUES (2,'POST-SNAPSHOT');", [])
            .expect("post");
        drop(c);
        let before = notes(&db);
        stage_and_publish(&db, &staged);
        assert_eq!(restore_state(&db), RestoreState::Outstanding);

        // The next open. No explicit recovery call: this is what `acquire_shared` does.
        let _store = crate::sqlite::Store::open(&db, true).expect("open recovers");

        assert_eq!(
            notes(&db),
            "PRE-SNAPSHOT-ONLY",
            "the staged content must win"
        );
        assert_ne!(before, notes(&db), "precondition: the live state differed");
        assert_eq!(
            restore_state(&db),
            RestoreState::Idle,
            "a completed restore leaves nothing outstanding"
        );
        assert!(!intent_path_for(&db).exists(), "the intent must be cleared");
        assert!(
            !staging_path_for(&db).exists(),
            "the staged image must be dropped once it has served"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **An ordinary open refuses while recovery cannot complete, and says why.**
    ///
    /// The intent names a staging image that is not there, so the install cannot run. The
    /// requirement is that this is a typed refusal rather than a bypass: the database must
    /// not become usable, and the staged image (had it existed) must survive for a retry.
    #[test]
    fn an_open_refuses_while_an_outstanding_restore_cannot_be_completed() {
        let d = dir("rollf-refuse");
        let db = base(&d, "state.db");
        let staged = base(&d, "state.db.restore-staging");
        stage_and_publish(&db, &staged);
        // The staged image is lost -- the failure mode recovery exists for.
        std::fs::remove_file(staging_path_for(&db)).expect("lose the staged image");

        let err = crate::sqlite::Store::open(&db, true).expect_err("must refuse");
        let text = format!("{err:?}");
        assert!(
            text.contains("outstanding restore"),
            "the refusal must name recovery, or an operator reads it as lock contention: {text}"
        );
        assert_eq!(
            restore_state(&db),
            RestoreState::Outstanding,
            "the intent survives a failed recovery so the next attempt retries"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Recovery is idempotent: a second open changes nothing and still succeeds.**
    ///
    /// A crash between "the install verified" and "the intent was cleared" leaves exactly
    /// that state, and the next open must repeat the install rather than treat the already
    /// correct database as an error.
    #[test]
    fn recovery_repeated_over_an_already_restored_database_is_a_no_op() {
        let d = dir("rollf-idempotent");
        let db = base(&d, "state.db");
        let staged = base(&d, "state.db.restore-staging");
        let _ = staged;
        stage_and_publish(&db, &staging_path_for(&db));
        complete_outstanding_restore(&db).expect("first recovery");
        assert_eq!(notes(&db), "PRE-SNAPSHOT-ONLY", "restored");

        // Rebuild the staged image, exactly as a crash between "verified" and "intent
        // cleared" would leave it, and re-publish against **its own** digest. A freshly
        // migrated file records a new `schema_meta.applied_at`, so re-using the previous
        // digest would (correctly) fail verification -- the digest is over logical content,
        // and `applied_at` is part of it.
        let _ = base(&d, "state.db.restore-staging");
        stage_and_publish(&db, &staging_path_for(&db));
        complete_outstanding_restore(&db).expect("second recovery");
        assert_eq!(
            notes(&db),
            "PRE-SNAPSHOT-ONLY",
            "still the intended content"
        );
        assert_eq!(restore_state(&db), RestoreState::Idle);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Negative control: without the protocol, the pre-restore rows survive.**
    ///
    /// Shows what the tests above are actually detecting. Here the same "crash" is
    /// simulated with no intent and no staging file -- the pre-roll-forward world -- and the
    /// post-snapshot data is simply still there.
    #[test]
    fn without_a_published_intent_the_pre_restore_state_survives() {
        let d = dir("rollf-control");
        let db = base(&d, "state.db");
        let c = Connection::open(&db).expect("open");
        c.execute("INSERT INTO audit_note VALUES (2,'POST-SNAPSHOT');", [])
            .expect("post");
        drop(c);
        // Nothing published, so recovery has nothing to do.
        assert_eq!(restore_state(&db), RestoreState::Idle);
        complete_outstanding_restore(&db).expect("no-op");
        assert_eq!(
            notes(&db),
            "PRE-SNAPSHOT-ONLY,POST-SNAPSHOT",
            "the negative control: with no intent, nothing is rolled forward. This is the \
             behaviour the other three tests prove no longer happens on the restore path."
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The staged image survives a refused recovery, so a retry has something to install.
    #[test]
    fn a_failed_recovery_preserves_the_staged_image_for_a_retry() {
        let d = dir("rollf-preserve");
        let db = base(&d, "state.db");
        let staged = base(&d, "state.db.restore-staging");
        stage_and_publish(&db, &staged);
        // Corrupt the *live* target so verification cannot succeed, leaving the staging
        // image intact and the intent outstanding.
        let i = publish_intent(&RestoreIntent {
            format: INTENT_FORMAT,
            target: db.clone(),
            staging: staged.clone(),
            digest: "this-digest-does-not-match".into(),
        });
        assert!(i.is_ok());
        let err = complete_outstanding_restore(&db).expect_err("digest cannot match");
        assert!(matches!(err, RecoveryError::Io { .. }), "{err:?}");
        assert!(
            staged.exists(),
            "a failed recovery must keep the staged image: it is the only thing a retry has"
        );
        assert_eq!(
            restore_state(&db),
            RestoreState::Outstanding,
            "and must keep the intent, so the failure is visible rather than silent"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// The nine F-26b recovery scenarios.
///
/// Each test drives the **production** protocol: the same `publish_intent`,
/// `install_staged` and `complete_outstanding_restore` the runtime uses, reached
/// through the ordinary `Store::open` path wherever a restart is involved. The only
/// thing that is test-only is *where* a failure is injected, and every test asserts
/// that its injection actually fired.
///
/// # Restart discipline
///
/// A restart in this protocol means: every connection closed, every lease released, no
/// in-memory state carried across. The tests below do that explicitly -- they `drop`
/// their connections and let the `Store` go out of scope before reopening -- so that
/// whatever the next open observes, it observed from **disk**.
///
/// # Unique scratch directories
///
/// Every test gets its own directory, unique per *call* and not merely per tag. Two
/// tests sharing a directory is a defect that has already cost this repository one
/// intermittent failure: `durability.rs` had two tests using the same tag, so they
/// shared one database and one of them deleted it out from under the other.
#[cfg(test)]
mod scenarios {
    use super::*;
    use crate::pragma::Pragma;
    use rusqlite::{Connection, OpenFlags};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A scratch directory, unique per call.
    fn scratch(tag: &str) -> PathBuf {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("orxnud-f26b-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// A migrated database whose `audit_note` table holds `text`.
    fn db_with(d: &Path, name: &str, text: &str) -> PathBuf {
        let p = d.join(name);
        let c = Connection::open(&p).expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        crate::migration::MigrationRunner::new(&c)
            .migrate(&p)
            .expect("migrate");
        c.execute_batch("CREATE TABLE IF NOT EXISTS audit_note (id INTEGER PRIMARY KEY, t TEXT);")
            .expect("table");
        c.execute("INSERT INTO audit_note VALUES (1,?1);", [text])
            .expect("row");
        drop(c);
        p
    }

    /// The notes in a database, read through a normal connection.
    fn notes(p: &Path) -> String {
        Connection::open_with_flags(p, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open")
            .query_row(
                "SELECT COALESCE(group_concat(t),'') FROM audit_note;",
                [],
                |r| r.get::<_, String>(0),
            )
            .expect("read")
    }

    fn digest_of(p: &Path) -> String {
        crate::backup::logical_digest(
            &Connection::open_with_flags(p, OpenFlags::SQLITE_OPEN_READ_ONLY).expect("open"),
        )
        .expect("digest")
    }

    /// Stage an image and publish the intent, exactly as the production restore does.
    fn stage_and_publish(db: &Path, staged: &Path) -> String {
        let digest = digest_of(staged);
        fsync_file(staged).expect("flush staged");
        publish_intent(&RestoreIntent {
            format: INTENT_FORMAT,
            target: db.to_path_buf(),
            staging: staged.to_path_buf(),
            digest: digest.clone(),
        })
        .expect("publish");
        digest
    }

    /// Force the condition "a write-ahead log that is still on disk after the writing
    /// connection closed", and prove it.
    ///
    /// SQLite checkpoints and removes the log when the last connection closes, so the
    /// condition cannot simply be waited for. It is constructed instead, the way a
    /// crash would leave it: the log is copied aside *while the connection is open*,
    /// the connection is closed (which checkpoints and removes the log), and the
    /// pre-log image of the main file and the saved log are then put back. The result
    /// is exactly the pair a power cut leaves behind -- a main file without the
    /// committed row and a log that holds it -- and SQLite replays it on open.
    ///
    /// Returns nothing; the caller asserts the condition, because a test that assumes
    /// a log is there proves nothing about a log that is not.
    fn force_persisted_wal(db: &Path) {
        let main_before = db.with_extension("pre-log-main");
        let wal_saved = db.with_extension("saved-log");
        std::fs::copy(db, &main_before).expect("save the pre-log main file");
        {
            let c = Connection::open(db).expect("open");
            c.execute_batch("PRAGMA journal_mode=WAL;")
                .expect("wal mode");
            c.execute("INSERT INTO audit_note VALUES (7,'ONLY-IN-LOG');", [])
                .expect("row");
            // The row is in the log and the main file does not have it yet.
            let wal = sidecar(db, "-wal");
            assert!(
                wal.exists()
                    && std::fs::metadata(&wal)
                        .map(|m| m.len() > 0)
                        .unwrap_or(false),
                "precondition: the row must be in the log"
            );
            std::fs::copy(&wal, &wal_saved).expect("save the log");
            drop(c);
        }
        // The close checkpointed the row into the main file and removed the log.
        assert!(
            !sidecar(db, "-wal").exists(),
            "precondition: a clean close removes the log"
        );
        // Put the crash state back.
        std::fs::copy(&main_before, db).expect("restore the pre-log main file");
        std::fs::copy(&wal_saved, sidecar(db, "-wal")).expect("restore the log");
        let _ = std::fs::remove_file(sidecar(db, "-shm"));
        let _ = std::fs::remove_file(&main_before);
        let _ = std::fs::remove_file(&wal_saved);
    }

    /// The assertion every injected-failure test must make.
    fn assert_fired(fault: seams::Fault) {
        assert!(
            seams::fired(fault),
            "the injected fault {fault:?} was never reached: the test proved nothing"
        );
    }

    // ---------------------------------------------------------------- 1
    /// **Failure before the staged image becomes durable.**
    ///
    /// The staged image exists on disk but was never made durable, and the intent was
    /// never published. The protocol's invariant is that an intent exists *only* if the
    /// staged image it names is complete, verified and durable, so the absence of an
    /// intent is the proof that the live database was never touched.
    ///
    /// After a restart the state is `Prepared`: the staging file is pure debris, and
    /// the ordinary open must serve the untouched live database and discard the debris.
    #[test]
    fn a_failure_before_the_staged_image_is_durable_publishes_no_intent() {
        let d = scratch("before-durable");
        let db = db_with(&d, "state.db", "LIVE");
        let _staged = db_with(&d, "state.db.restore-staging", "STAGED");
        let live_digest_before = digest_of(&db);

        // The staged image exists but no intent was ever published: exactly the state a
        // crash between "write the staging file" and "publish the intent" leaves.
        assert_eq!(restore_state(&db), RestoreState::Prepared);
        assert!(
            !intent_path_for(&db).exists(),
            "an intent must exist only for a complete, durable staged image"
        );

        // Restart: everything is re-read from disk.
        let store = crate::sqlite::Store::open(&db, true).expect("open");
        drop(store);

        assert_eq!(
            notes(&db),
            "LIVE",
            "the live database was never touched, so it must be served unchanged"
        );
        assert_eq!(
            digest_of(&db),
            live_digest_before,
            "the live file is unchanged"
        );
        assert_eq!(
            restore_state(&db),
            RestoreState::Idle,
            "the abandoned staging file must be discarded, not left outstanding"
        );
        assert!(
            !staging_path_for(&db).exists(),
            "an abandoned staging file is debris and must be dropped"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---------------------------------------------------------------- 2
    /// **Failure immediately before the intent is published.**
    ///
    /// The staging file is complete and durable, but the intent never becomes
    /// authoritative. The live database must not have been destructively modified, and
    /// there must be no false indication that a recovery is outstanding.
    #[test]
    fn a_failure_immediately_before_publishing_the_intent_changes_nothing() {
        let d = scratch("before-publish");
        let db = db_with(&d, "state.db", "LIVE");
        let staged = db_with(&d, "state.db.restore-staging", "STAGED");
        let live_digest_before = digest_of(&db);

        seams::arm(seams::Fault::BeforeIntentPublish);
        let err = publish_intent(&RestoreIntent {
            format: INTENT_FORMAT,
            target: db.to_path_buf(),
            staging: staged.to_path_buf(),
            digest: digest_of(&staged),
        })
        .expect_err("the publication must fail");
        assert_fired(seams::Fault::BeforeIntentPublish);
        seams::reset();
        assert!(
            !intent_path_for(&db).exists(),
            "a failed publication must leave no intent: {err:?}"
        );
        assert_eq!(
            restore_state(&db),
            RestoreState::Prepared,
            "staging without an intent is not an outstanding recovery"
        );

        // The live database is untouched, and the ordinary path still serves it.
        let store = crate::sqlite::Store::open(&db, true).expect("open");
        drop(store);
        assert_eq!(notes(&db), "LIVE");
        assert_eq!(digest_of(&db), live_digest_before);
        assert_eq!(restore_state(&db), RestoreState::Idle);
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---------------------------------------------------------------- 3
    /// **Failure immediately after the intent is published.**
    ///
    /// This is the commit point. The intent is durable on disk, so the operation *is*
    /// outstanding even though the caller was told it failed. A restart through the
    /// ordinary open must recognise the intent and roll forward to the staged state.
    #[test]
    fn a_failure_immediately_after_publishing_the_intent_is_rolled_forward_on_the_next_open() {
        let d = scratch("after-publish");
        let db = db_with(&d, "state.db", "LIVE");
        let staged = db_with(&d, "state.db.restore-staging", "STAGED");
        let staged_digest = digest_of(&staged);

        seams::arm(seams::Fault::AfterIntentPublish);
        let err = publish_intent(&RestoreIntent {
            format: INTENT_FORMAT,
            target: db.to_path_buf(),
            staging: staged.to_path_buf(),
            digest: staged_digest.clone(),
        })
        .expect_err("the caller is told the publication failed");
        assert_fired(seams::Fault::AfterIntentPublish);
        seams::reset();

        // The intent is nevertheless on disk, and it is authoritative.
        assert!(
            intent_path_for(&db).exists(),
            "the intent is durable: {err:?}"
        );
        assert_eq!(restore_state(&db), RestoreState::Outstanding);
        let intent = read_intent(&db)
            .expect("read")
            .expect("an intent is published");
        assert_eq!(intent.digest, staged_digest);
        assert_eq!(intent.target, db);
        assert_eq!(intent.staging, staging_path_for(&db));

        // Restart through the ordinary path. Nothing in memory carries across.
        let store = crate::sqlite::Store::open(&db, true).expect("open rolls forward");
        drop(store);

        assert_eq!(notes(&db), "STAGED", "the staged content must win");
        assert_eq!(digest_of(&db), staged_digest);
        assert_eq!(restore_state(&db), RestoreState::Idle);
        assert!(!intent_path_for(&db).exists(), "the intent must be cleared");
        assert!(
            !staging_path_for(&db).exists(),
            "the staged image must be dropped"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---------------------------------------------------------------- 4
    /// **Failure during the in-place copy.**
    ///
    /// The live database is genuinely partial. The staged image and the intent must
    /// survive it, the partial database must not be served, and a later attempt must
    /// complete the restore.
    #[test]
    fn a_failure_during_the_in_place_copy_leaves_the_staged_authority_intact() {
        let d = scratch("during-copy");
        let db = db_with(&d, "state.db", "LIVE");
        let staged = db_with(&d, "state.db.restore-staging", "STAGED");
        let staged_digest = digest_of(&staged);
        stage_and_publish(&db, &staged);

        // Fail the copy part-way through.
        seams::arm(seams::Fault::DuringCopy);
        let err = install_staged(&db, &staging_path_for(&db), &staged_digest)
            .expect_err("the copy must fail");
        assert_fired(seams::Fault::DuringCopy);
        seams::reset();
        assert!(format!("{err:?}").contains("injected"), "{err:?}");

        // The authority survives the partial copy.
        assert!(
            staging_path_for(&db).exists(),
            "the staged image must survive a failed copy"
        );
        assert_eq!(
            digest_of(&staging_path_for(&db)),
            staged_digest,
            "the staged image must be undamaged"
        );
        assert!(
            intent_path_for(&db).exists(),
            "the intent must survive a failed copy"
        );
        assert_eq!(restore_state(&db), RestoreState::Outstanding);

        // The partial database must not be served: recovery is still outstanding, and
        // recovery cannot complete while the fault is still armed.
        seams::arm(seams::Fault::DuringCopy);
        let refused = crate::sqlite::Store::open(&db, true).expect_err("must refuse");
        assert_fired(seams::Fault::DuringCopy);
        seams::reset();
        assert!(
            format!("{refused:?}").contains("outstanding restore"),
            "the refusal must say the restore is outstanding: {refused:?}"
        );
        assert!(
            staging_path_for(&db).exists(),
            "a refused open must not lose the only recovery image"
        );
        assert!(intent_path_for(&db).exists());

        // The retry converges.
        let store = crate::sqlite::Store::open(&db, true).expect("the retry converges");
        drop(store);
        assert_eq!(notes(&db), "STAGED");
        assert_eq!(digest_of(&db), staged_digest);
        assert_eq!(restore_state(&db), RestoreState::Idle);
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---------------------------------------------------------------- 5
    /// **Restart after the copy but before the checkpoint/finalisation.**
    ///
    /// The main file may already hold the copied pages, so a naive "is the content
    /// right?" check would call the restore complete. It is not: the intent is still
    /// outstanding, and the recovery must be *retried*, not skipped.
    #[test]
    fn a_restart_after_the_copy_but_before_finalisation_retries_the_recovery() {
        let d = scratch("before-finalize");
        let db = db_with(&d, "state.db", "LIVE");
        let staged = db_with(&d, "state.db.restore-staging", "STAGED");
        let staged_digest = digest_of(&staged);
        stage_and_publish(&db, &staged);

        seams::arm(seams::Fault::BeforeFinalize);
        let err = install_staged(&db, &staging_path_for(&db), &staged_digest)
            .expect_err("the finalisation must fail");
        assert_fired(seams::Fault::BeforeFinalize);
        seams::reset();
        assert!(format!("{err:?}").contains("injected"), "{err:?}");

        // The intent is still outstanding, even though the copy already happened.
        assert_eq!(restore_state(&db), RestoreState::Outstanding);
        assert!(intent_path_for(&db).exists());
        assert!(staging_path_for(&db).exists());

        // The next open must *re-enter* the install rather than mistake the copied
        // main file for a completed restore. Arming the same fault proves it does:
        // if recovery skipped the install, the fault would never fire again.
        seams::arm(seams::Fault::BeforeFinalize);
        let refused = crate::sqlite::Store::open(&db, true).expect_err("must not be a no-op");
        assert_fired(seams::Fault::BeforeFinalize);
        seams::reset();
        assert!(
            format!("{refused:?}").contains("outstanding restore"),
            "{refused:?}"
        );

        // With the fault gone, the recovery completes.
        let store = crate::sqlite::Store::open(&db, true).expect("the retry converges");
        drop(store);
        assert_eq!(notes(&db), "STAGED");
        assert_eq!(digest_of(&db), staged_digest);
        assert_eq!(restore_state(&db), RestoreState::Idle);
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---------------------------------------------------------------- 6
    /// **A write-ahead log that persists after the connection closed.**
    ///
    /// The condition is *forced and verified*, not assumed. SQLite checkpoints and
    /// removes the log when the last connection closes, so the condition cannot simply
    /// be waited for; it is constructed the way a power cut would leave it, by
    /// `force_persisted_wal`. The test then asserts the log is there and non-empty and
    /// that the committed row is still replayable from it, so a pass cannot be
    /// explained by SQLite having checkpointed it away.
    ///
    /// The point of the test is that finalisation must fold the log into the main file
    /// *before* the sidecars are removed and the intent is cleared.
    #[test]
    fn a_log_that_survives_the_connection_close_is_folded_in_before_the_intent_is_cleared() {
        let d = scratch("wal-survives");
        let db = db_with(&d, "state.db", "LIVE");
        let staged = db_with(&d, "state.db.restore-staging", "STAGED");
        let staged_digest = digest_of(&staged);

        // Force a log that outlives the connection, and verify it.
        force_persisted_wal(&db);
        let wal = sidecar(&db, "-wal");
        assert!(
            wal.exists()
                && std::fs::metadata(&wal)
                    .map(|m| m.len() > 0)
                    .unwrap_or(false),
            "the condition must be forced and verified: a log must survive the close"
        );
        assert_eq!(
            notes(&db),
            "LIVE,ONLY-IN-LOG",
            "the committed row must still be replayable from the log"
        );

        stage_and_publish(&db, &staged);

        // Recovery: the log must be folded in, the sidecars removed, and only then
        // may the intent be cleared.
        let store = crate::sqlite::Store::open(&db, true).expect("open recovers");
        drop(store);

        // The sidecar state is read **before** any verification connection is opened.
        // Opening the database read-only recreates an empty log, because a read-only
        // connection cannot delete it on close; asserting afterwards would be
        // measuring the verifier rather than the recovery.
        assert!(
            !sidecar(&db, "-wal").exists(),
            "the log must be folded in and removed by the recovery"
        );
        assert!(
            !sidecar(&db, "-shm").exists(),
            "the shared-memory file must be removed too"
        );

        assert_eq!(
            notes(&db),
            "STAGED",
            "the staged content wins over the absorbed post-snapshot row"
        );
        assert_eq!(digest_of(&db), staged_digest);
        assert_eq!(restore_state(&db), RestoreState::Idle);
        assert!(!intent_path_for(&db).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---------------------------------------------------------------- 7
    /// **A competing reader makes the checkpoint report `SQLITE_BUSY`.**
    ///
    /// The competing reader is a real connection holding a real read transaction, so
    /// the checkpoint genuinely cannot complete. The result must be a refusal, the
    /// intent and the staged image must survive, and the retry must work once the
    /// contention ends.
    #[test]
    fn a_competing_reader_makes_recovery_refuse_and_leave_the_authority_intact() {
        let d = scratch("busy");
        let db = db_with(&d, "state.db", "LIVE");
        let staged = db_with(&d, "state.db.restore-staging", "STAGED");
        let staged_digest = digest_of(&staged);

        // A reader that holds the database open across the recovery attempt.
        let reader = Connection::open(&db).expect("reader");
        reader
            .execute_batch("BEGIN; SELECT * FROM audit_note;")
            .expect("hold");
        // Make sure there is a log for the checkpoint to contend with.
        {
            let w = Connection::open(&db).expect("writer");
            w.execute("INSERT INTO audit_note VALUES (3,'CONTENDED');", [])
                .expect("write");
            drop(w);
        }
        assert!(
            sidecar(&db, "-wal").exists(),
            "the contended database must have a log to checkpoint"
        );

        stage_and_publish(&db, &staged);

        let refused = crate::sqlite::Store::open(&db, true).expect_err("must refuse");
        let text = format!("{refused:?}");
        assert!(
            text.contains("outstanding restore"),
            "the refusal must be about the outstanding restore: {text}"
        );
        assert!(
            staging_path_for(&db).exists(),
            "a busy refusal must not lose the only recovery image"
        );
        assert!(
            intent_path_for(&db).exists(),
            "the intent must survive a busy refusal"
        );
        assert_eq!(restore_state(&db), RestoreState::Outstanding);

        // The contention ends, and the retry converges.
        reader.execute_batch("COMMIT;").expect("release");
        drop(reader);
        let store = crate::sqlite::Store::open(&db, true).expect("the retry converges");
        drop(store);
        assert_eq!(notes(&db), "STAGED");
        assert_eq!(digest_of(&db), staged_digest);
        assert_eq!(restore_state(&db), RestoreState::Idle);
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---------------------------------------------------------------- 8
    /// **Failure during the post-copy verification.**
    ///
    /// The verification is the only thing that decides whether the restored content may
    /// be trusted. If it fails, the intent must stay, the staged image must stay, and
    /// the database must not be served.
    #[test]
    fn a_failure_during_post_copy_verification_keeps_the_intent_and_refuses_service() {
        let d = scratch("verify-fail");
        let db = db_with(&d, "state.db", "LIVE");
        let staged = db_with(&d, "state.db.restore-staging", "STAGED");
        let staged_digest = digest_of(&staged);
        stage_and_publish(&db, &staged);

        seams::arm(seams::Fault::DuringVerification);
        let err = install_staged(&db, &staging_path_for(&db), &staged_digest)
            .expect_err("the verification must fail");
        assert_fired(seams::Fault::DuringVerification);
        seams::reset();
        assert!(format!("{err:?}").contains("injected"), "{err:?}");

        // Nothing was trusted, so nothing was cleared.
        assert!(intent_path_for(&db).exists(), "the intent must survive");
        assert!(
            staging_path_for(&db).exists(),
            "the staged image must survive"
        );
        assert_eq!(restore_state(&db), RestoreState::Outstanding);

        // The ordinary path refuses, because the recovery cannot complete.
        seams::arm(seams::Fault::DuringVerification);
        let refused = crate::sqlite::Store::open(&db, true).expect_err("must refuse");
        assert_fired(seams::Fault::DuringVerification);
        seams::reset();
        assert!(
            format!("{refused:?}").contains("outstanding restore"),
            "{refused:?}"
        );

        // With the conditions restored, the retry converges.
        let store = crate::sqlite::Store::open(&db, true).expect("the retry converges");
        drop(store);
        assert_eq!(notes(&db), "STAGED");
        assert_eq!(digest_of(&db), staged_digest);
        assert_eq!(restore_state(&db), RestoreState::Idle);
        let _ = std::fs::remove_dir_all(&d);
    }

    // ---------------------------------------------------------------- 9
    /// **Failure to clear the intent.**
    ///
    /// The data was installed and verified, but the protocol is not complete until the
    /// intent is gone. This is the case where "the database holds the right content"
    /// and "the restore is finished" come apart, and the requirement is that they must
    /// not be allowed to disagree: while the intent stands, the ordinary path must
    /// treat the restore as outstanding rather than serving the database as done.
    #[test]
    fn a_failure_to_clear_the_intent_leaves_the_restore_outstanding_not_finished() {
        let d = scratch("clear-fail");
        let db = db_with(&d, "state.db", "LIVE");
        let staged = db_with(&d, "state.db.restore-staging", "STAGED");
        let staged_digest = digest_of(&staged);
        stage_and_publish(&db, &staged);

        seams::arm(seams::Fault::BeforeClearIntent);
        let refused = crate::sqlite::Store::open(&db, true).expect_err("must refuse");
        assert_fired(seams::Fault::BeforeClearIntent);
        seams::reset();
        assert!(
            format!("{refused:?}").contains("outstanding restore"),
            "{refused:?}"
        );

        // The *data* was installed and verified -- the copy, the finalisation and the
        // digest check all succeeded. What failed is the completion of the protocol.
        assert_eq!(
            digest_of(&db),
            staged_digest,
            "the data installation itself succeeded"
        );
        assert!(
            intent_path_for(&db).exists(),
            "the intent stands: the restore is not finished"
        );
        assert_eq!(
            restore_state(&db),
            RestoreState::Outstanding,
            "installed data is not a finished restore"
        );

        // So the ordinary path must not treat this as complete: it must go through
        // recovery again rather than serve the database as though nothing were
        // outstanding.
        seams::arm(seams::Fault::BeforeClearIntent);
        let again = crate::sqlite::Store::open(&db, true).expect_err("must not be a no-op");
        assert_fired(seams::Fault::BeforeClearIntent);
        seams::reset();
        assert!(
            format!("{again:?}").contains("outstanding restore"),
            "{again:?}"
        );

        // And once the clearing works, the restore is genuinely finished.
        let store = crate::sqlite::Store::open(&db, true).expect("the retry converges");
        drop(store);
        assert_eq!(notes(&db), "STAGED");
        assert_eq!(restore_state(&db), RestoreState::Idle);
        assert!(!intent_path_for(&db).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    // ------------------------------------------------------- negative controls
    /// **Negative control: naively removing the log loses committed data.**
    ///
    /// This is the behaviour the protocol exists to prevent. If the `-wal` is deleted
    /// without being checkpointed, the committed rows in it are gone, and the database
    /// silently reverts. The protocol's ordering -- finalise, verify, *then* remove the
    /// sidecars -- is what makes that impossible.
    #[test]
    fn removing_the_log_without_checkpointing_it_loses_committed_rows() {
        let d = scratch("naive-sidecar");
        let db = db_with(&d, "state.db", "LIVE");
        force_persisted_wal(&db);
        let wal = sidecar(&db, "-wal");
        assert!(
            wal.exists()
                && std::fs::metadata(&wal)
                    .map(|m| m.len() > 0)
                    .unwrap_or(false),
            "precondition: the row must be only in the log"
        );
        assert_eq!(
            notes(&db),
            "LIVE,ONLY-IN-LOG",
            "precondition: the row is replayed from the log"
        );

        // The naive cleanup: delete the sidecars.
        std::fs::remove_file(&wal).expect("remove wal");
        let _ = std::fs::remove_file(sidecar(&db, "-shm"));

        assert_eq!(
            notes(&db),
            "LIVE",
            "the committed row was in the log and is now lost: this is why the \\
             sidecars are removed only after the log has been finalised"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **Negative control: an outstanding intent is never read as absent.**
    ///
    /// A malformed intent, and an intent whose staging image is gone, are both
    /// outstanding restores. Reading either as "no restore is outstanding" would let a
    /// half-restored database be served.
    #[test]
    fn an_outstanding_intent_is_never_read_as_absent() {
        let d = scratch("intent-not-absent");
        let db = db_with(&d, "state.db", "LIVE");

        // A malformed intent file.
        std::fs::write(intent_path_for(&db), b"this is not an intent\n").expect("write");
        assert_eq!(restore_state(&db), RestoreState::Outstanding);
        assert!(
            read_intent(&db).is_err(),
            "a malformed intent is an error, never None"
        );
        let refused = crate::sqlite::Store::open(&db, true).expect_err("must refuse");
        assert!(
            format!("{refused:?}").contains("outstanding restore"),
            "{refused:?}"
        );

        // An intent whose staging image is gone is still outstanding.
        std::fs::remove_file(intent_path_for(&db)).expect("remove");
        let _staged = db_with(&d, "state.db.restore-staging", "STAGED");
        stage_and_publish(&db, &_staged);
        std::fs::remove_file(staging_path_for(&db)).expect("lose the image");
        assert_eq!(restore_state(&db), RestoreState::Outstanding);
        let refused = crate::sqlite::Store::open(&db, true).expect_err("must refuse");
        assert!(
            format!("{refused:?}").contains("outstanding restore"),
            "{refused:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// The regression tests for the two defects the checkpoint review found.
///
/// They are separate from `scenarios` because they are about the *ordering* of two
/// mechanisms rather than about a crash window in the recovery protocol.
#[cfg(test)]
mod ordering {
    use super::*;
    use crate::pragma::Pragma;
    use rusqlite::Connection;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn scratch(tag: &str) -> PathBuf {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("orxnud-order-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    fn db_with(d: &Path, name: &str, text: &str) -> PathBuf {
        let p = d.join(name);
        let c = Connection::open(&p).expect("open");
        Pragma::critical().apply(&c).expect("pragmas");
        crate::migration::MigrationRunner::new(&c)
            .migrate(&p)
            .expect("migrate");
        c.execute_batch("CREATE TABLE IF NOT EXISTS audit_note (id INTEGER PRIMARY KEY, t TEXT);")
            .expect("table");
        c.execute("INSERT INTO audit_note VALUES (1,?1);", [text])
            .expect("row");
        drop(c);
        p
    }

    fn notes(p: &Path) -> String {
        Connection::open_with_flags(p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open")
            .query_row(
                "SELECT COALESCE(group_concat(t),'') FROM audit_note;",
                [],
                |r| r.get::<_, String>(0),
            )
            .expect("read")
    }

    /// **The shared lease is held before the recovery state is read.**
    ///
    /// A restore publishes its intent while holding the *exclusive* lease. If the
    /// shared lease were taken after the recovery state was read, a restore could
    /// publish an intent in between and crash, leaving this opener with a lease on a
    /// database whose restore was outstanding.
    ///
    /// The proof is structural rather than a comment: the hook fires with the lease
    /// held, and taking the exclusive lease from inside it must **fail**. It would
    /// succeed if the shared lease were not yet held.
    #[test]
    fn the_shared_lease_is_held_before_the_recovery_state_is_read() {
        let d = scratch("lease-order");
        let db = db_with(&d, "state.db", "LIVE");

        // `Rc`, not `Arc`: the seam's closure is not `Send`, and it is not required
        // to be -- it runs on the thread that takes the lease.
        let exclusive_was_refused = std::rc::Rc::new(Cell::new(false));
        let db = std::rc::Rc::new(db);
        {
            let db = db.clone();
            let flag = exclusive_was_refused.clone();
            crate::ownership::seams::after_shared_lease(move || {
                let taken = crate::ownership::acquire_exclusive_unchecked(db.as_path());
                flag.set(taken.is_err());
            });
        }

        let lease = crate::ownership::acquire_shared(db.as_path()).expect("acquire");
        drop(lease);

        assert!(
            exclusive_was_refused.get(),
            "the shared lease must be held before the recovery state is read: an \\
             exclusive acquisition from inside the hook must be refused"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **An intent left by an earlier interruption causes recovery, not a normal open.**
    ///
    /// The opener must not simply hand out a shared lease on a database whose restore
    /// is outstanding. This drives the ordinary shared acquisition and checks that the
    /// staged content won.
    #[test]
    fn an_outstanding_intent_causes_recovery_rather_than_a_normal_open() {
        let d = scratch("outstanding");
        let db = db_with(&d, "state.db", "LIVE");
        let staged = db_with(&d, "state.db.restore-staging", "STAGED");

        // A prior interruption: the intent is published, the install never happened.
        let digest = crate::backup::logical_digest(
            &Connection::open_with_flags(&staged, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("open staged"),
        )
        .expect("digest");
        fsync_file(&staged).expect("flush");
        publish_intent(&RestoreIntent {
            format: INTENT_FORMAT,
            target: db.clone(),
            staging: staging_path_for(&db),
            digest: digest.clone(),
        })
        .expect("publish");
        assert_eq!(restore_state(&db), RestoreState::Outstanding);

        // The ordinary shared acquisition. No explicit recovery call: this is the
        // path a production opener takes.
        let lease = crate::ownership::acquire_shared(&db).expect("acquire must recover");
        drop(lease);

        assert_eq!(notes(&db), "STAGED", "the staged content must win");
        assert_eq!(restore_state(&db), RestoreState::Idle);
        assert!(!intent_path_for(&db).exists(), "the intent must be cleared");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **The staged image's parent directory is flushed before the intent is published.**
    ///
    /// Flushing the staged *file* makes its contents durable; it does not make its
    /// *name* durable. The name lives in the parent directory's entry, and an intent
    /// that outlives a crash must not be able to name a staged file that the crash
    /// lost.
    #[test]
    fn the_staged_images_parent_directory_is_flushed_before_the_intent_is_published() {
        let d = scratch("staging-dir");
        let db = db_with(&d, "state.db", "LIVE");
        // The source of the restore: a separate database whose content is installed.
        let source = db_with(&d, "source.db", "RESTORED");

        // The snapshot the restore installs.
        let snapshot = {
            let c = Connection::open(&source).expect("open");
            crate::backup::Backup::take(&c, &source).expect("snapshot")
        };

        record::clear();
        let guard = crate::backup::RestoreGuard::acquire(&db).expect("guard");
        snapshot.restore(&guard).expect("restore");
        drop(guard);

        let log = record::entries();
        let staging_parent = d.clone();
        let flush = log
            .iter()
            .position(|e| e == &format!("fsync_dir {}", staging_parent.display()));
        let publish = log.iter().position(|e| e.starts_with("publish_intent "));
        assert!(
            flush.is_some(),
            "the directory containing the staged file must be flushed: {log:?}"
        );
        assert!(publish.is_some(), "the intent must be published: {log:?}");
        assert!(
            flush < publish,
            "the directory flush must precede the intent publication: {log:?}"
        );
        // The database file is not a directory, and flushing it would not make the
        // staged file's *name* durable.
        assert!(
            !log.iter()
                .any(|e| e == &format!("fsync_dir {}", db.display())),
            "the database file must not be flushed in place of its directory: {log:?}"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **A failed directory flush stops the restore before anything destructive.**
    ///
    /// The live database must not be modified, and no intent may be published, if the
    /// durability the protocol depends on could not be established.
    #[test]
    fn a_failed_directory_flush_prevents_progression_to_destructive_work() {
        let d = scratch("flush-fail");
        let db = db_with(&d, "state.db", "LIVE");
        let source = db_with(&d, "source.db", "RESTORED");
        let live_before = notes(&db);

        let snapshot = {
            let c = Connection::open(&source).expect("open");
            crate::backup::Backup::take(&c, &source).expect("snapshot")
        };

        seams::arm(seams::Fault::DirectoryFlush);
        let guard = crate::backup::RestoreGuard::acquire(&db).expect("guard");
        let err = snapshot.restore(&guard).expect_err("the flush must fail");
        seams::reset();
        assert!(format!("{err:?}").contains("injected"), "{err:?}");

        assert_eq!(
            notes(&db),
            live_before,
            "the live database must not be modified when the durability fails"
        );
        assert!(
            !intent_path_for(&db).exists(),
            "no intent may be published when the durability fails"
        );
        assert_eq!(
            restore_state(&db),
            RestoreState::Prepared,
            "the staged file is debris: it was never committed, so there is no \
             outstanding recovery -- only an abandoned staging file to discard"
        );
        assert_ne!(
            restore_state(&db),
            RestoreState::Outstanding,
            "a failed durability check must never leave an outstanding recovery"
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
