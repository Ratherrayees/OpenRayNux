//! Compile-fail assertions about the capability authority boundary.
//!
//! # Why these live here
//!
//! Because `CapabilityInvocation`, `AuthorisationProof` and `DispatchView` now live in
//! `orxnud-policy`, next to the `pub(crate)` constructors that are supposed to be their
//! only route. Proving an absence requires a crate that can *try* the forbidden thing,
//! and this crate is one: it already depends on `orxnud-policy`, and it is also the
//! crate whose execution surface is being sealed.
//!
//! `orxnud-domain` cannot host these fixtures. Adding `orxnud-policy` as a dependency
//! of `orxnud-domain` would invert the layer order that gate G2 enforces, and the right
//! fix for that is not a dev-dependency — it is the ownership change these fixtures
//! document.
//!
//! Each fixture must **fail to compile**, and its recorded `.stderr` pins which
//! diagnostic, so the test is sensitive to the failure being for the right reason. A
//! fixture that failed because of a typo would otherwise pass while proving nothing.
//!
//! Regenerate with `TRYBUILD=overwrite` after an intentional change, and read the diff.

#[test]
fn the_authority_boundary_is_enforced_by_the_compiler() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
