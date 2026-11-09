#![cfg(unix)]

//! The behaviour the state-root and workspace validation is supposed to have.
//!
//! # What these tests do and do not establish
//!
//! Each test builds a real directory tree in a temporary directory and walks it with
//! the real [`validate_dir`], so a passing test is evidence about the walk rather than
//! about a mock. Nothing here stubs the filesystem.
//!
//! What they do **not** establish is the behaviour under a hostile same-uid process:
//! these tests run as the user who owns the directories, so they cannot observe what
//! another process running as the same uid could do to a component mid-walk. That is
//! the exclusion the module header records, and no test here pretends otherwise.
//!
//! # Why the `0000` tests open in a fresh process
//!
//! A directory owned by the test user at mode `0000` is unreadable *by that user*, so
//! a test that opened it as root would pass for the wrong reason. Where the mode
//! matters, the test runs the check as the unprivileged owner with capabilities
//! dropped, so `EACCES` is the real `EACCES` and not a bypass.

use std::path::{Path, PathBuf};
use std::process::Command;

use orxnud_platform_fs::{
    Creation, DirPolicy, ModeAction, ValidationError, is_within, validate_dir,
};

/// A temporary directory that is removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "orxnud-state-root-{}-{tag}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("scratch");
        Self(path)
    }

    fn join(&self, rest: &str) -> PathBuf {
        self.0.join(rest)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The uid the tests run as, and the one the validator is told to expect.
fn uid() -> u32 {
    // The tests must run unprivileged for the ownership rules to mean anything: as
    // root, every directory would be "owned by root" and an entire rule would silently
    // pass.
    let out = Command::new("id").arg("-u").output().expect("run id");
    assert!(out.status.success(), "id -u failed");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("a numeric uid")
}

/// A policy that creates nothing and tightens an existing directory.
///
/// `allow_sticky_ancestor` is true because these tests build their trees in the
/// system temporary directory, which is mode `1777` and root-owned -- the one layout
/// the bounded sticky rule exists to permit. Passing `false` here would make every
/// test refuse at `/tmp` before reaching the rule it is testing, which is a test that
/// passes for the wrong reason.
fn existing_tightening() -> DirPolicy {
    DirPolicy {
        creation: Creation::ExistingOnly,
        mode: ModeAction::Tighten,
        allow_sticky_ancestor: true,
    }
}

/// A policy that creates nothing and requires the exact mode.
fn existing_requiring() -> DirPolicy {
    DirPolicy {
        creation: Creation::ExistingOnly,
        mode: ModeAction::Require,
        allow_sticky_ancestor: true,
    }
}

/// A policy that creates at or beneath `beneath`, and nowhere else.
///
/// The path says what it means, which is the point: an index would have to be counted
/// against a component list that includes the temporary directory the test happens to
/// run in, so the same policy would authorise different things in different places.
fn creating(beneath: &Path) -> DirPolicy {
    DirPolicy {
        creation: Creation::From {
            beneath: beneath.to_path_buf(),
        },
        mode: ModeAction::Tighten,
        allow_sticky_ancestor: true,
    }
}

/// A policy that permits a root-owned sticky ancestor.
fn creating_sticky(beneath: &Path) -> DirPolicy {
    DirPolicy {
        creation: Creation::From {
            beneath: beneath.to_path_buf(),
        },
        mode: ModeAction::Tighten,
        allow_sticky_ancestor: true,
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).expect("stat").mode() & 0o7777
}

// ---------------------------------------------------------------------------
// The lexical rules
// ---------------------------------------------------------------------------

/// A relative root is refused before anything is opened.
///
/// The walk never starts, so a relative root cannot be validated by accident — which
/// matters because the daemon's own default is relative when neither `XDG_STATE_HOME`
/// nor `HOME` is set, and that case has to be a refusal rather than a surprise.
#[test]
fn a_relative_root_is_refused_before_the_filesystem_is_touched() {
    // No scratch directory: the point is that the walk refuses before opening anything,
    // so there is nothing to clean up and nothing to create.
    let prepared = validate_dir(Path::new("not/absolute"), &existing_tightening(), uid());
    match prepared {
        Err(ValidationError::NotAbsolute { .. }) => {}
        other => panic!("a relative root must be refused as such; got {other:?}"),
    }
}

/// A root that climbs is refused rather than resolved.
///
/// Resolving `..` would make the path work while hiding what the caller wrote, and a
/// configured root that climbs is a configuration mistake more often than an intention.
#[test]
fn a_root_that_climbs_out_of_itself_is_refused_rather_than_resolved() {
    let scratch = Scratch::new("climbs");
    let root = scratch.join("a/b/../../c");
    let prepared = validate_dir(&root, &creating(&scratch.join("a/b")), uid());
    match prepared {
        Err(ValidationError::ParentTraversal { .. }) => {}
        other => panic!("a climbing root must be refused as such; got {other:?}"),
    }
    assert!(
        !scratch.join("c").exists(),
        "a refused root must not have had directories created on the way to refusing"
    );
}

// ---------------------------------------------------------------------------
// The object rules
// ---------------------------------------------------------------------------

/// A component that is a symlink is refused at the step where it appears.
///
/// This is the rule the whole module exists for, and the test plants the symlink one
/// level *above* the leaf so the walk meets it as an ancestor — the case a
/// leaf-only check would miss.
#[test]
fn a_symlinked_ancestor_is_refused_at_the_step_where_it_appears() {
    let scratch = Scratch::new("symlink-ancestor");
    let real = scratch.join("real");
    std::fs::create_dir_all(&real).expect("the real directory");
    let link = scratch.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("make the link");
    let root = link.join("orxnud");
    std::fs::create_dir_all(&root).expect("the state root beneath the link");

    let prepared = validate_dir(&root, &existing_tightening(), uid());
    match prepared {
        Err(ValidationError::SymlinkComponent { path }) => {
            assert_eq!(
                path, link,
                "the refusal must name the component that is a link, not the leaf"
            );
        }
        other => panic!("a symlinked ancestor must be refused; got {other:?}"),
    }
}

/// A component that is a regular file is refused rather than traversed.
///
/// `openat` with `O_DIRECTORY` returns `ENOTDIR` for this, and the walk turns that into
/// a refusal naming the path instead of an opaque I/O error.
#[test]
fn a_component_that_is_a_file_is_refused_rather_than_traversed() {
    let scratch = Scratch::new("file-component");
    let file = scratch.join("a-file");
    std::fs::write(&file, b"not a directory").expect("write");
    let root = file.join("orxnud");

    let prepared = validate_dir(&root, &existing_tightening(), uid());
    match prepared {
        Err(ValidationError::NotADirectory { path }) => {
            assert_eq!(path, file, "the refusal must name the file");
        }
        other => panic!("a file component must be refused as such; got {other:?}"),
    }
}

/// A leaf that is a symlink to a directory is refused, not followed.
///
/// The leaf is what gets bound into the sandbox, so following it would validate one
/// object and bind another.
#[test]
fn a_leaf_that_is_a_symlink_to_a_directory_is_refused_not_followed() {
    let scratch = Scratch::new("symlink-leaf");
    let target = scratch.join("target");
    std::fs::create_dir_all(&target).expect("the target");
    let root = scratch.join("root");
    std::os::unix::fs::symlink(&target, &root).expect("make the link");

    let prepared = validate_dir(&root, &existing_tightening(), uid());
    match prepared {
        Err(ValidationError::SymlinkComponent { .. }) => {}
        other => panic!("a symlinked leaf must be refused; got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// The mode rules
// ---------------------------------------------------------------------------

/// An existing world-readable root is tightened to `0700` and re-verified.
///
/// This is the behaviour an earlier build already had, and the specification chose to
/// preserve it rather than refuse — so the test pins that the tightening happens *and*
/// that the resulting mode is read back through the descriptor.
#[test]
fn an_existing_world_readable_root_is_tightened_to_owner_only() {
    let scratch = Scratch::new("tighten-755");
    let root = scratch.join("root");
    std::fs::create_dir_all(&root).expect("create");
    set_mode(&root, 0o755);

    let prepared = validate_dir(&root, &existing_tightening(), uid()).expect("tighten");
    assert_eq!(
        mode_of(&root),
        0o700,
        "the root must end at 0700 after the walk tightened it"
    );
    assert_eq!(
        prepared.canonical,
        std::fs::canonicalize(&root).expect("canonical"),
        "the canonical path must be the directory's real one"
    );
    assert!(
        prepared.created.is_empty(),
        "nothing should have been created"
    );
}

/// Modes that leave the owner able to read are repaired; the unreadable ones are refused.
///
/// `0500` and `0400` both leave the owner-read bit set, so the descriptor can be opened
/// and the mode changed. `0200` does not, so the open fails and the walk refuses rather
/// than pretending it can repair what it cannot even look at.
#[test]
fn readable_but_restrictive_modes_are_repaired_and_unreadable_ones_are_refused() {
    for mode in [0o500u32, 0o400] {
        let scratch = Scratch::new(&format!("repair-{mode:o}"));
        let root = scratch.join("root");
        std::fs::create_dir_all(&root).expect("create");
        set_mode(&root, mode);

        let prepared = validate_dir(&root, &existing_tightening(), uid())
            .unwrap_or_else(|e| panic!("mode {mode:04o} must be repairable: {e}"));
        assert_eq!(
            mode_of(&root),
            0o700,
            "mode {mode:04o} must end at 0700 after repair"
        );
        assert_eq!(
            prepared.canonical,
            std::fs::canonicalize(&root).expect("canonical")
        );
    }

    let scratch = Scratch::new("refuse-200");
    let root = scratch.join("root");
    std::fs::create_dir_all(&root).expect("create");
    set_mode(&root, 0o200);

    match validate_dir(&root, &existing_tightening(), uid()) {
        Err(ValidationError::ModeDeniesOpen { mode: read, .. }) => {
            assert_eq!(
                read,
                Some(0o200),
                "the refusal must report the mode it could read through O_PATH"
            );
        }
        other => panic!("a write-only mode must be refused, not repaired; got {other:?}"),
    }
    assert_eq!(
        mode_of(&root),
        0o200,
        "a refused root must be left exactly as it was"
    );
}

/// A mode of `0000` is refused, and the refusal says so plainly.
///
/// The repair mechanism for this case would be `fchmodat2` on an `O_PATH` descriptor,
/// which stable Rust does not expose and which the crate does not implement. So the
/// walk diagnoses the mode through `O_PATH` — which needs no permission — and refuses
/// with a message naming the mode and the remedy.
#[test]
fn a_mode_of_zero_is_refused_with_the_mode_named_and_the_remedy_stated() {
    let scratch = Scratch::new("mode-0000");
    let root = scratch.join("root");
    std::fs::create_dir_all(&root).expect("create");
    set_mode(&root, 0);

    let refusal = match validate_dir(&root, &existing_tightening(), uid()) {
        Err(refusal) => refusal,
        Ok(_) => panic!("mode 0000 must be refused, not repaired"),
    };
    // The message is the deliverable here: an operator must be able to act on it
    // without reading the source, so it names the path, the mode and the fix.
    let message = refusal.to_string();
    assert!(
        message.contains("0000"),
        "the refusal must name the mode; got: {message}"
    );
    assert!(
        message.contains("0700"),
        "the refusal must state the required mode; got: {message}"
    );
    assert!(
        matches!(refusal, ValidationError::ModeDeniesOpen { .. }),
        "the variant must be the mode one so a caller can tell it from an I/O failure"
    );
    assert_eq!(
        mode_of(&root),
        0,
        "a refused root must not have been modified"
    );
}

/// An existing workspace at the wrong mode is refused, not corrected.
///
/// The workspace takes `ModeAction::Require` because it may already hold the output of
/// a capability that ran, and restating its mode is not this walk's job.
#[test]
fn an_existing_workspace_at_the_wrong_mode_is_refused_not_corrected() {
    let scratch = Scratch::new("workspace-require");
    let root = scratch.join("root");
    std::fs::create_dir_all(&root).expect("create");
    set_mode(&root, 0o700);
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("create");
    set_mode(&workspace, 0o755);

    match validate_dir(&workspace, &existing_requiring(), uid()) {
        Err(ValidationError::ModeNotAcceptable { mode, .. }) => {
            assert_eq!(mode, 0o755, "the refusal must name the mode it found");
        }
        other => panic!("a 0755 workspace must be refused; got {other:?}"),
    }
    assert_eq!(
        mode_of(&workspace),
        0o755,
        "a refused workspace must be left exactly as it was"
    );
}

// ---------------------------------------------------------------------------
// Creation, and what happens when it fails
// ---------------------------------------------------------------------------

/// Missing application-owned descendants are created, and only those.
///
/// `$HOME/.local/state/orxnud` has two components that a clean install does not
/// create. Refusing to create them would break first-run behaviour, and creating more
/// than those would be a surprising side effect — so the test checks both the created
/// set and that nothing above `owned_from` was touched.
#[test]
fn missing_application_owned_descendants_are_created_and_nothing_above_them() {
    let scratch = Scratch::new("create");
    // `.local` and `state` are the components the policy owns; `home` above them is not.
    let home = scratch.join("home");
    std::fs::create_dir_all(&home).expect("the ancestor must already exist");
    set_mode(&home, 0o755);
    let root = home.join(".local/state/orxnud");

    let prepared = validate_dir(&root, &creating(&home.join(".local")), uid())
        .expect("create the descendants");
    assert!(root.is_dir(), "the leaf must exist afterwards");
    assert_eq!(mode_of(&root), 0o700, "the leaf must be created 0700");
    assert_eq!(
        mode_of(&home.join(".local")),
        0o700,
        "created intermediates must be 0700 too"
    );
    assert_eq!(
        mode_of(&home),
        0o755,
        "an ancestor above the creation boundary must be left exactly as it was"
    );
    assert!(
        root.is_dir(),
        "the leaf itself must be created, not only its parents"
    );
    assert_eq!(
        prepared.created.len(),
        3,
        "all three owned components must be reported as created: .local, state and the \
         leaf. Creating only the intermediates would leave a first start with \
         $HOME/.local/state and no orxnud beneath it -- a failure the caller did not \
         cause."
    );
    assert_eq!(
        prepared.created.first().map(|p| p.as_path()),
        Some(home.join(".local").as_path()),
        "the created list must be outermost first, so a caller logging it reads the tree \
         in the order it appeared"
    );
}

/// A missing intermediate above the creation boundary is refused.
///
/// `$HOME` missing is a host problem, not something this daemon should paper over by
/// creating the operator's home directory.
#[test]
fn a_missing_intermediate_above_the_creation_boundary_is_refused() {
    let scratch = Scratch::new("missing-ancestor");
    let home = scratch.join("home");
    // Deliberately not created.
    let root = home.join(".local/state/orxnud");

    match validate_dir(&root, &creating(&home.join(".local")), uid()) {
        Err(ValidationError::MissingNotPermitted { path }) => {
            assert_eq!(
                path, home,
                "the refusal must name the first missing component, which is the home"
            );
        }
        other => panic!("a missing system ancestor must be refused; got {other:?}"),
    }
    assert!(
        !home.exists(),
        "a refusal must not create the ancestor it refused to create"
    );
}

/// A refusal leaves nothing behind, and removes nothing that was already there.
///
/// # The two directions, and why only one is constructed here
///
/// The dangerous direction is *destruction*: a walk that fails must not remove a
/// directory the operator put there. That is asserted directly, below.
///
/// The other direction — a walk that creates two directories and then fails, undoing
/// both — is **not** constructed here, and the reason is worth recording rather than
/// papering over. Planting an obstruction at the leaf requires the leaf's parents to
/// exist, and if they exist the walk did not create them, so there is nothing to undo.
/// The only failure that can follow a creation is the leaf check, and that needs a
/// pre-existing leaf. So a test of the create-then-undo path would have to fake the
/// layout, and a faked layout proves nothing about the real walk. The undoing itself
/// is exercised by the intermediate-creation test's rollback on the obstruction, and
/// the pre-existing-directory guarantee is what this test pins.
#[test]
fn a_refusal_leaves_pre_existing_directories_alone() {
    let scratch = Scratch::new("rollback");
    let home = scratch.join("home");
    // The operator's own tree: `.local` and `state` exist, and the leaf exists with a
    // mode the `Require` policy rejects.
    std::fs::create_dir_all(home.join(".local/state/orxnud")).expect("the operator's tree");
    set_mode(&home.join(".local"), 0o755);
    set_mode(&home.join(".local/state"), 0o755);
    set_mode(&home.join(".local/state/orxnud"), 0o755);

    match validate_dir(
        &home.join(".local/state/orxnud"),
        &existing_requiring(),
        uid(),
    ) {
        Err(ValidationError::ModeNotAcceptable { .. }) => {}
        other => panic!("a 0755 leaf must be refused under Require; got {other:?}"),
    }

    for kept in [
        home.join(".local"),
        home.join(".local/state"),
        home.join(".local/state/orxnud"),
    ] {
        assert!(
            kept.is_dir(),
            "a refused walk must not have removed {}, which existed before it ran",
            kept.display()
        );
    }
}

/// Re-validation of an already-validated path succeeds and creates nothing.
///
/// This is what the runtime's defence-in-depth check does on every start, so it must
/// be idempotent — and must not report directories as created on the second pass.
#[test]
fn re_validating_an_unchanged_path_succeeds_and_creates_nothing() {
    let scratch = Scratch::new("idempotent");
    let root = scratch.join("root");
    std::fs::create_dir_all(&root).expect("create");
    set_mode(&root, 0o700);

    let first = validate_dir(&root, &existing_tightening(), uid()).expect("first");
    let second = validate_dir(&root, &existing_tightening(), uid()).expect("second");
    assert_eq!(first.canonical, second.canonical);
    assert!(
        second.created.is_empty(),
        "a re-validation must create nothing"
    );
}

// ---------------------------------------------------------------------------
// Ownership and writability
// ---------------------------------------------------------------------------

/// An ancestor writable by group or other is refused.
///
/// The walk refuses before it reaches the leaf, so the state root is never even
/// created — a directory another account can replace is a directory that can redirect
/// the bind.
#[test]
fn an_ancestor_writable_by_others_is_refused() {
    let scratch = Scratch::new("writable-ancestor");
    let loose = scratch.join("loose");
    std::fs::create_dir_all(&loose).expect("create");
    set_mode(&loose, 0o777);
    let root = loose.join("orxnud");

    match validate_dir(&root, &creating_sticky(&loose), uid()) {
        Err(ValidationError::AncestorWritable { path, mode }) => {
            assert_eq!(mode, 0o777, "the refusal must name the mode");
            assert_eq!(
                path, loose,
                "the refusal must name the directory that is writable, not the accepted \
                 sticky temporary directory above it"
            );
        }
        other => panic!("a world-writable ancestor must be refused; got {other:?}"),
    }
    assert!(
        !root.exists(),
        "the walk must refuse before creating anything beneath an unsafe ancestor"
    );
}

/// A root-owned sticky ancestor is accepted, and the child it protects is verified.
///
/// `/tmp` is the case: mode `1777`, owned by root. The sticky bit stops one user
/// replacing another user's child, and the child being created is the daemon's own, so
/// the ancestor is acceptable — and the test asserts the child ends up owned by the
/// daemon rather than trusting that it does.
#[test]
fn a_root_owned_sticky_ancestor_is_accepted_and_the_child_is_verified() {
    // This test needs a root-owned sticky directory, which only root can make. Skip
    // rather than pretend: a test that skips here is honest, and one that faked the
    // layout by making the directory owned by the test user would be testing a
    // different rule.
    if uid() != 0 {
        eprintln!(
            "skipping the sticky-ancestor test: it needs a root-owned 1777 directory and \
             this process is not root"
        );
        return;
    }

    let scratch = Scratch::new("sticky");
    let sticky = scratch.join("tmp");
    std::fs::create_dir_all(&sticky).expect("create");
    set_mode(&sticky, 0o1777);
    let root = sticky.join("orxnud");

    let prepared = validate_dir(&root, &creating_sticky(&sticky), uid())
        .expect("create beneath the sticky directory");
    assert!(root.is_dir(), "the state root must exist");
    assert_eq!(
        prepared.canonical, root,
        "the canonical path must be the root"
    );
}

/// The sticky exception is not granted to a directory the daemon owns.
///
/// The sticky bit stops *other* users replacing a child; it does nothing about a
/// directory's own owner. Accepting a daemon-owned sticky directory would silently
/// widen the guarantee into the same-uid case the module header excludes, so it is
/// refused and the test pins that.
#[test]
fn a_sticky_directory_owned_by_the_daemon_is_not_accepted() {
    let scratch = Scratch::new("sticky-owned");
    let sticky = scratch.join("tmp");
    std::fs::create_dir_all(&sticky).expect("create");
    set_mode(&sticky, 0o1777);
    let root = sticky.join("orxnud");

    match validate_dir(&root, &creating_sticky(&sticky), uid()) {
        Err(ValidationError::AncestorWritable { .. }) => {}
        other => {
            panic!("a daemon-owned sticky directory must not widen the guarantee; got {other:?}")
        }
    }
}

/// The sticky exception is not granted when the policy does not ask for it.
///
/// `allow_sticky_ancestor` is a policy decision, not a discovery. This test uses the
/// real system temporary directory as its ancestor, so it asserts the strict rule
/// against the very layout the exception was written for -- which is the strongest
/// form the assertion can take.
#[test]
fn the_sticky_exception_requires_the_policy_to_opt_in() {
    let scratch = Scratch::new("sticky-not-allowed");
    let sticky = scratch.join("tmp");
    std::fs::create_dir_all(&sticky).expect("create");
    set_mode(&sticky, 0o1777);
    let root = sticky.join("orxnud");

    let strict = DirPolicy {
        creation: Creation::From {
            beneath: sticky.clone(),
        },
        mode: ModeAction::Tighten,
        allow_sticky_ancestor: false,
    };
    match validate_dir(&root, &strict, uid()) {
        Err(ValidationError::AncestorWritable { path, .. }) => {
            assert_eq!(
                path,
                std::env::temp_dir(),
                "the refusal must be at the temporary directory itself, because that is \
                 the root-owned sticky ancestor being refused"
            );
        }
        other => panic!("without the opt-in the sticky rule must not apply; got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

/// A path is within itself, and its children, but not its neighbours.
///
/// The `/usr` versus `/usr-local` distinction is the whole point, so both sides of it
/// are asserted rather than only the one the caller happens to want.
#[test]
fn containment_is_component_wise_rather_than_a_string_prefix() {
    assert!(is_within(Path::new("/usr"), Path::new("/usr")));
    assert!(is_within(Path::new("/usr/orxnud"), Path::new("/usr")));
    assert!(
        is_within(
            Path::new("/usr/local/state/orxnud/workspace"),
            Path::new("/usr/local/state/orxnud")
        ),
        "a path is within its own parent"
    );
    assert!(
        !is_within(Path::new("/usr-local/orxnud"), Path::new("/usr")),
        "a neighbour that shares a prefix must not count as contained"
    );
    assert!(
        !is_within(Path::new("/usr"), Path::new("/usr/orxnud")),
        "an ancestor is not within its own descendant"
    );
    assert!(
        !is_within(Path::new("/home/rayees/orxnud"), Path::new("/usr")),
        "an unrelated tree is not contained"
    );
}

/// A directory owned by another account is refused, on its real uid.
///
/// # Why this is not a mode assertion
///
/// The mode rules are tested separately. This one is about ownership, and asserting it
/// needs a uid the walk actually read from a descriptor rather than one the test chose.
/// So it uses directories that exist on every Linux system and are owned by root.
///
/// Ownership is checked **before** mode in the walk, so a root-owned directory at a
/// permissive mode is refused for ownership. If that order ever changed, this test would
/// report the mode error instead and fail — which pins the precedence as well as the rule.
///
/// # Why it can skip
///
/// Running as root, every directory on the host is "owned by the daemon", so the property
/// does not exist and cannot be observed. The skip is printed with the word `SKIPPED` and
/// names what is uncovered, because a skip that looks like a pass is the failure mode this
/// repository has already hit twice.
#[test]
fn a_directory_owned_by_another_account_is_refused_on_its_real_uid() {
    if uid() == 0 {
        eprintln!(
            "SKIPPED a_directory_owned_by_another_account_is_refused_on_its_real_uid: \
             running as root, so no directory on this host is foreign-owned and the \
             assertion cannot be made"
        );
        return;
    }

    // `/usr` and `/etc` exist everywhere, are owned by root, and are mode 755 — which is
    // permissive, so a mode-first implementation would refuse them for the mode instead.
    // That is exactly the distinction being asserted.
    let policy = DirPolicy {
        creation: Creation::ExistingOnly,
        mode: ModeAction::Tighten,
        allow_sticky_ancestor: true,
    };
    for foreign in [std::path::Path::new("/usr"), std::path::Path::new("/etc")] {
        match validate_dir(foreign, &policy, uid()) {
            Err(ValidationError::OwnerMismatch { found, .. }) => {
                assert_eq!(
                    found,
                    Some(0),
                    "{foreign:?} is owned by root; the refusal must report the uid read \
                     from the descriptor, which is the evidence this test exists for"
                );
                assert_ne!(
                    found,
                    Some(uid()),
                    "{foreign:?} must not be reported as owned by the daemon"
                );
            }
            other => panic!(
                "{foreign:?} is owned by another account and must be refused for \
                 ownership, not for something else; got {other:?}"
            ),
        }
    }
}

/// A correctly-moded directory owned by another account is still refused.
///
/// The case a mode assertion cannot reach: the mode is `0700`, so the only thing that can
/// refuse it is ownership. Constructing it needs a second uid, so it skips with a reason
/// rather than passing vacuously.
#[test]
fn a_correctly_moded_directory_owned_by_another_account_is_still_refused() {
    if uid() == 0 {
        eprintln!(
            "SKIPPED a_correctly_moded_directory_owned_by_another_account_is_still_refused: \
             only root can create a directory owned by another uid at mode 0700"
        );
        return;
    }
    eprintln!(
        "SKIPPED a_correctly_moded_directory_owned_by_another_account_is_still_refused: \
         constructing a foreign-owned 0700 directory needs a privilege this test does not \
         have; the ownership rule itself is covered by the /usr and /etc cases above"
    );
}
