//! Compile-fail tests: assertions about what **cannot** be written.
//!
//! docs-13 §4.2 requires "a compile-fail test proves `Proposal` has no method
//! reaching an adapter". A positive test proves a thing works; a compile-fail
//! test proves an *absence*, which is otherwise only checkable by reading the
//! source. Security-relevant absences deserve the same rigour as features.
//!
//! Each `tests/compile_fail/*.rs` must **fail to compile**, and its recorded
//! `.stderr` pins *which* diagnostic is expected — so the test is sensitive to
//! the failure being for the right reason, not merely that one occurred. A file
//! that fails to compile because of a typo would otherwise pass a naive check
//! while proving nothing.
//!
//! Regenerate the recorded output with `TRYBUILD=overwrite` after an
//! intentional change, and **read the diff before committing it**.

#[test]
fn negative_space_is_enforced_by_the_compiler() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
