//! `CapabilityAdapter` and `AdapterBundle` cannot be named from another crate.
//!
//! Both are whole `pub(crate)` traits. That shape matters: a `pub` trait whose methods
//! are `pub(crate)` would still let an outside crate *implement* it, and so register
//! an adapter of its own. Making the trait itself crate-private decides both halves at
//! once -- `invoke` cannot be called, and neither trait can be implemented, so no
//! external bundle can enter the registry even indirectly.
//!
//! Gate G2d reported `ok` on a tree that implemented `CapabilityAdapter` outside this
//! crate and called `invoke` with no policy, no approval, no budget charge and no
//! audit record, because such a file names none of `PolicySeal`, `attest`, `authorise`
//! or `issue`. The governed path was structurally optional and the gate could not see
//! it. This is the compiler saying what the gate should have said.

use orxnud_capability::{AdapterBundle, CapabilityAdapter};

fn main() {
    let _adapter: &dyn CapabilityAdapter = unimplemented!();
    let _bundle: &dyn AdapterBundle = unimplemented!();
}
