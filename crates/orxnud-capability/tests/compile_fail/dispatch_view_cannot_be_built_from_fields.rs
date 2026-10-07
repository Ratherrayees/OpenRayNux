//! A `DispatchView` cannot be written as a struct literal.
//!
//! `DispatchView` is the sole input every capability adapter takes, so forging one is
//! forging the capability call itself -- the caller picks `params` and asserts whatever
//! `data_class` it likes. Before this, a crate depending on `orxnud-capability` could
//! build one directly and hand it to `invoke`.
//!
//! This file is the struct literal alone. A companion file covers the `From`/`Into`
//! escapes; they are split because when several escapes share one fixture `rustc`
//! reports some diagnostics and silently drops others, so the recorded `.stderr` would
//// not mention this one at all.

use orxnud_domain::ids::CapabilityId;
use orxnud_domain::{DataClass, InvocationContext};
use orxnud_policy::authority::DispatchView;

fn main() {
    let params = orxnud_domain::json!({});
    let capability = CapabilityId::new("filesystem/write-text");
    let context = InvocationContext::new("k", 1, "c");

    let _view = DispatchView {
        step: 0,
        capability: &capability,
        params: &params,
        data_class: DataClass::Public,
        context: &context,
    };
}
