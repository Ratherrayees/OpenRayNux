//! The mutation harness must not be able to touch the developer's working tree.
//!
//! # Why this needs a test
//!
//! During V-89 a mutation runner did its work in the working tree, resetting each mutated
//! file with `git checkout` between mutations. That is a correct way to undo a mutation and
//! a catastrophic way to undo anything else: the same command discarded uncommitted work,
//! and the only reason it was noticed was that a test count had quietly dropped by two.
//! Nothing about the harness made that visible — it ran, printed results, and reported
//! success.
//!
//! A safety property that is enforced by whoever remembers it is not enforced. So the
//! guarantee is now in `scripts/mutate.sh`, and *this* test drives that script rather than
//! restating its logic — the failure mode this guards against is a test that reimplemented
//! the condition and therefore could not see the condition being removed.
//!
//! # What is actually asserted
//!
//! That a dirty tree is refused outright, and that uncommitted work survives the attempt.
//! The second half is the one that matters: a harness that refused but had already touched
//! something would pass a weaker test, and refusing is not difficult — deleting is.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn harness() -> PathBuf {
    repo_root().join("scripts/mutate.sh")
}

/// Runs the harness with a deliberately dirty tree and no mutations.
///
/// The target is a real test filter rather than a no-op so the refusal cannot be
/// mistaken for "nothing to do"; the harness must refuse *before* it considers work.
///
/// `tag` exists because cargo runs the tests in this file concurrently: a shared scratch
/// filename would have one test's cleanup delete the other test's evidence, which is a
/// failure of this test rather than of the harness.
fn run_against_dirty_tree(tag: &str) -> (std::process::Output, bool) {
    let root = repo_root();
    let scratch = root.join(format!(
        "crates/orxnud-store/tests/zz_mutation_harness_scratch_{tag}.rs"
    ));

    // An untracked file is the case that matters most: it is work with no git history to
    // notice its loss, and it is invisible to a naive `git diff`-only dirtiness check.
    std::fs::write(
        &scratch,
        "// deliberately uncommitted; the harness must leave this alone\n",
    )
    .expect("write scratch");

    let out = Command::new("bash")
        .arg(harness())
        .args(["-p", "orxnud-store", "--test", "ci_gates_are_strict"])
        .current_dir(&root)
        .output()
        .expect("the harness must be runnable");

    // Whether the file survived is observed *here*, before any cleanup: a helper that
    // deleted the evidence first would make the caller assert on a file it had just
    // removed, and the assertion would be about the test rather than the harness.
    let survived = scratch.exists();
    let _ = std::fs::remove_file(&scratch);
    (out, survived)
}

#[test]
fn a_dirty_working_tree_is_refused_rather_than_mutated() {
    let (out, _survived) = run_against_dirty_tree("exit");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "the harness must exit non-zero on a dirty tree. It succeeded, so it would have \
         run mutations here: {stderr}"
    );
    assert!(
        stderr.contains("dirty"),
        "the refusal must say *why* it refused, so a developer is not left guessing: {stderr}"
    );
}

#[test]
fn the_refusal_happens_before_any_work_is_touched() {
    let (_out, survived) = run_against_dirty_tree("survive");
    assert!(
        survived,
        "the harness deleted an uncommitted file while refusing to run. A refusal that \
         has already touched the tree is not a refusal."
    );
}

#[test]
fn the_harness_declares_the_two_guarantees_it_relies_on() {
    let script = std::fs::read_to_string(harness()).expect("read the harness");

    // A dirtiness check that ignores untracked files would let exactly the work that
    // cannot be recovered from `git checkout` through the guard. Asserted against the
    // script text because this is a property of the *command* it runs, not of any Rust
    // code, and the shell is what has to get it right.
    assert!(
        script.contains("--untracked-files=all") || script.contains("ls-files --others"),
        "the dirtiness check must include untracked files"
    );
    assert!(
        script.contains("git worktree"),
        "the harness must isolate its mutations in a worktree rather than running them \
         in the developer's checkout"
    );
}
