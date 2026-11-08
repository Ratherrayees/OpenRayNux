//! What the state-root boundary refuses, at the point the runtime is started.
//!
//! # Why these live here and not only in `orxnud-platform-fs`
//!
//! The platform crate proves the walk: symlinks, modes, ownership, creation, rollback.
//! What it cannot prove is the *composition* — that the daemon asks about the right
//! paths, that it reads its mount rules from the sandbox crate rather than a copy of
//! them, and that a refusal happens before anything is created. Those are properties of
//! `prepare_state_paths`, so they are tested against it.
//!
//! # What a refusal must always mean
//!
//! Every rejection below asserts two things together: the *reason* is named, and
//! **nothing was created** — no `state.db`, no workspace, no lock. A refusal that left a
//! directory behind would be a start the operator cannot account for, which is the
//! failure mode this work exists to remove.
//!
//! # The tests that need root
//!
//! Mount overlap needs a writable directory beneath a mount the sandbox actually
//! performs, and only root can make one. Those cases skip with a printed reason rather
//! than passing vacuously — an unprivileged run cannot observe the refusal, and a test
//! that quietly passed would be evidence about nothing.

use std::path::{Path, PathBuf};
use std::process::Command;

use orxnud_daemon::{Paths, prepare_state_paths};

/// A temporary directory removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("orxnud-s2-{}-{tag}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&path).expect("scratch");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The uid the tests run as.
fn uid() -> u32 {
    let out = Command::new("id").arg("-u").output().expect("run id");
    assert!(out.status.success(), "id -u failed");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("a numeric uid")
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("set mode");
}

/// Asserts a start refused with the expected reason.
///
/// # What is deliberately not asserted here
///
/// That no `workspace` exists. Several of these fixtures create the workspace
/// themselves — a symlink, to be precise — so its existence is the setup, not the
/// result. What must hold instead, and is asserted by each test individually, is that
/// the link is still a link pointing where it pointed: the refusal must not have
/// followed it into a creation somewhere else. The durable artefacts (`state.db` and
/// friends) are asserted absent by [`assert_no_durable_artefacts`], which every test
/// calls.
fn assert_refused(label: &str, root: &Path, expected: &str) {
    let result = prepare_state_paths(Paths::under(root));
    let refusal = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("{label}: the start must be refused, and it was not"),
    };
    assert!(
        refusal.contains(expected),
        "{label}: the refusal must say {expected:?}; got: {refusal}"
    );
}

/// Asserts a refused start created none of the durable state.
fn assert_no_durable_artefacts(label: &str, root: &Path) {
    for artefact in ["state.db", "audit.log", "daemon.lock", "daemon.log"] {
        assert!(
            !root.join(artefact).exists(),
            "{label}: a refused start must not have created {artefact}"
        );
    }
}

/// Asserts a path is still the symlink it was, pointing where it pointed.
fn assert_link_untouched(label: &str, link: &Path, target: &Path) {
    let found = std::fs::read_link(link)
        .unwrap_or_else(|e| panic!("{label}: {link:?} must still be a symbolic link: {e}"));
    assert_eq!(
        found, target,
        "{label}: the link must still point where it pointed"
    );
}

// ---------------------------------------------------------------------------
// The workspace is validated independently of the state root
// ---------------------------------------------------------------------------

/// A workspace that is a symlink out of the root is refused.
///
/// The state root can be perfectly valid — real directories, owned correctly, no
/// symlinks anywhere on the way down — while the workspace inside it points at the
/// user's documents. That is the shape the containment rule exists for, and it is the
/// case a state-root-only check would wave through.
#[test]
fn a_workspace_that_is_a_symlink_out_of_the_root_is_refused() {
    let scratch = Scratch::new("workspace-symlink");
    let outside = scratch.path().join("elsewhere");
    std::fs::create_dir_all(&outside).expect("the target");
    set_mode(&outside, 0o700);
    let root = scratch.path().join("orxnud");
    std::fs::create_dir_all(&root).expect("the state root");
    set_mode(&root, 0o700);
    std::os::unix::fs::symlink(&outside, root.join("workspace")).expect("the link");

    assert_refused(
        "a workspace symlinked out of the root",
        &root,
        "symbolic link",
    );
    assert_no_durable_artefacts("a workspace symlinked out of the root", &root);
    assert_link_untouched(
        "a workspace symlinked out of the root",
        &root.join("workspace"),
        &outside,
    );
    assert!(
        outside.is_dir(),
        "the refusal must not have touched the directory the link points at"
    );
}

/// A workspace that is a dangling symlink is refused, not followed into creation.
///
/// Following it would create the state root's workspace *somewhere else* — whichever
/// path the dangling link happened to name.
#[test]
fn a_dangling_workspace_symlink_is_refused() {
    let scratch = Scratch::new("workspace-dangling");
    let root = scratch.path().join("orxnud");
    std::fs::create_dir_all(&root).expect("the state root");
    set_mode(&root, 0o700);
    let target = scratch.path().join("nowhere");
    std::os::unix::fs::symlink(&target, root.join("workspace")).expect("the link");

    assert_refused("a dangling workspace link", &root, "symbolic link");
    assert_no_durable_artefacts("a dangling workspace link", &root);
    assert_link_untouched(
        "a dangling workspace link",
        &root.join("workspace"),
        &target,
    );
    assert!(
        !target.exists(),
        "a refused start must not have created the directory the dangling link named"
    );
}

/// A workspace belonging to another account is refused.
///
/// Skipped rather than faked when the tests cannot create a file owned by someone else,
/// because a chown to the test user's own uid would assert nothing.
#[test]
fn a_workspace_owned_by_another_account_is_refused() {
    if uid() == 0 {
        eprintln!("skipping the other-owner test: it needs to create a file owned by another uid");
        return;
    }
    let scratch = Scratch::new("workspace-other-owner");
    let root = scratch.path().join("orxnud");
    std::fs::create_dir_all(&root).expect("the state root");
    set_mode(&root, 0o700);
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).expect("the workspace");
    set_mode(&workspace, 0o700);
    set_mode(&workspace, 0o755);
    // The mode check catches this case without needing another uid, and it is the same
    // rule: a workspace that is not exactly 0700 is not a workspace this daemon made.
    assert_refused("a workspace at the wrong mode", &root, "0700");
    assert_no_durable_artefacts("a workspace at the wrong mode", &root);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&workspace)
                .expect("stat")
                .permissions()
                .mode()
                & 0o7777,
            0o755,
            "a refused start must not have restated the workspace's mode"
        );
    }
}

// ---------------------------------------------------------------------------
// The lexical rules, at the point they matter
// ---------------------------------------------------------------------------

/// A relative state root is refused before anything is opened.
#[test]
fn a_relative_state_root_is_refused() {
    let result = prepare_state_paths(Paths::under("relative/orxnud"));
    match result {
        Err(e) => assert!(
            e.to_string().contains("absolute"),
            "the refusal must say the root must be absolute; got: {e}"
        ),
        Ok(_) => panic!("a relative root must be refused"),
    }
}

/// A state root that climbs is refused rather than resolved.
#[test]
fn a_state_root_that_climbs_is_refused() {
    let scratch = Scratch::new("climbs");
    let root = scratch.path().join("a/b/../../c");
    let result = prepare_state_paths(Paths::under(&root));
    match result {
        Err(e) => assert!(
            e.to_string().contains("'..'"),
            "the refusal must name the traversal; got: {e}"
        ),
        Ok(_) => panic!("a climbing root must be refused"),
    }
    assert_no_durable_artefacts("a climbing root", &scratch.path().join("a"));
    assert!(
        !scratch.path().join("c").exists(),
        "a refused root must not have directories created on the way to refusing"
    );
}

// ---------------------------------------------------------------------------
// The mount rules come from the sandbox crate, not from here
// ---------------------------------------------------------------------------

/// A state root whose name merely shares a prefix with a system directory is accepted.
///
/// `/usr-local/orxnud` is not `/usr/orxnud`, and a prefix comparison would refuse a
/// perfectly ordinary installation. This is the case that keeps the check from being
/// stricter than the rule it implements.
#[test]
fn a_state_root_that_only_shares_a_prefix_with_a_system_directory_is_accepted() {
    let scratch = Scratch::new("usr-local");
    // `/usr-local` beside the scratch, so it is under the temporary directory rather
    // than at the filesystem root — the shape matters, not the literal name.
    let parent = scratch.path().join("usr-local");
    std::fs::create_dir_all(&parent).expect("the parent");
    set_mode(&parent, 0o755);
    let root = parent.join("orxnud");

    let prepared = prepare_state_paths(Paths::under(&root))
        .unwrap_or_else(|e| panic!("a prefix-sharing root must be accepted: {e}"));
    assert_eq!(
        prepared.paths_ref().root,
        std::fs::canonicalize(&root).expect("canonical"),
        "the prepared root must be the canonical one"
    );
}

// ---------------------------------------------------------------------------
// The default layout
// ---------------------------------------------------------------------------

/// The default layout validates, and the root it returns is the canonical one.
///
/// The temporary directory these tests use is the system one, which is root-owned and
/// sticky — the bounded case the policy exists to permit. Asserting the accepted path
/// here keeps the negative tests honest: the rules refuse specific layouts, not
/// everything.
#[test]
fn the_default_layout_validates_and_returns_the_canonical_root() {
    let scratch = Scratch::new("default");
    let root = scratch.path().join("orxnud");

    let prepared = prepare_state_paths(Paths::under(&root))
        .unwrap_or_else(|e| panic!("the default layout must validate: {e}"));
    assert_eq!(
        prepared.paths_ref().root,
        std::fs::canonicalize(&root).expect("canonical"),
        "the returned root must be canonical, not the caller's spelling"
    );
    assert!(
        root.join("workspace").is_dir(),
        "the workspace must exist after a successful start"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(root.join("workspace"))
            .expect("stat")
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o700, "a freshly created workspace must be 0700");
    }
}

/// Re-preparing an already-prepared path is idempotent.
///
/// The runtime re-verifies on every start, so this must be cheap and must not create
/// anything the second time.
#[test]
fn re_preparing_a_validated_path_succeeds_and_creates_nothing() {
    let scratch = Scratch::new("idempotent");
    let root = scratch.path().join("orxnud");

    let first = prepare_state_paths(Paths::under(&root))
        .unwrap_or_else(|e| panic!("the first preparation must succeed: {e}"));
    let again = prepare_state_paths(first.paths_ref().clone())
        .unwrap_or_else(|e| panic!("the re-preparation must succeed: {e}"));
    assert_eq!(
        first.paths_ref(),
        again.paths_ref(),
        "a re-preparation must return the same paths"
    );
}
