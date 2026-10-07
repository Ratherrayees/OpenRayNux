//! `PolicySeal` and `orxnud_policy::seal()` no longer exist.
//!
//! The seal was the enforcement story for ADR-0012 -- "it is not possible to do this
//! without going through policy" -- and it was worth nothing. `seal()` minted a token
//! for any string a caller supplied, nothing ever compared `issued_by` against a
//! principal, and holding one was enough to reach `AuthorisationProof::issue` and
//! `CapabilityInvocation::authorise`.
//!
//! So it is deleted rather than tightened. A checker that cannot fail is worse than no
//! checker, because it reports `ok` on the trees it was supposed to catch. This file
//! pins that the names stay gone, so re-adding a token no crate can obtain is a compile
//! error rather than a silent regression.

fn main() {
    let _seal = orxnud_policy::seal();
    let _seal = orxnud_domain::PolicySeal::attest("anything");
}
