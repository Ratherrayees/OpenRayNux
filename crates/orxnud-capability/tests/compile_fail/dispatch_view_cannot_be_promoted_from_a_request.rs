//! An untrusted inbound request cannot be promoted into a `DispatchView`.
//!
//! `CapabilityRequest`/`ActionRequest` are deliberately `pub` with public fields: they
//! carry no authority, and a caller must be able to describe the action it wants. The
//! boundary is that a request cannot *become* the authorised thing. There is no
//! `From`/`Into`, and the only producer,
//! `CapabilityInvocation::dispatch_view`, is `pub(crate)` in `orxnud-policy`.

use orxnud_domain::ids::{CapabilityId, RunId, TaskId};
use orxnud_domain::{ActionRequest, DataClass};
use orxnud_policy::authority::DispatchView;

fn request() -> ActionRequest {
    ActionRequest::new(
        TaskId::new("t-1"),
        RunId::new("r-1"),
        0,
        CapabilityId::new("filesystem/write-text"),
        orxnud_domain::json!({"path": "~/.ssh/authorized_keys"}),
        DataClass::Public,
        DataClass::Public,
    )
}

fn main() {
    let _view: DispatchView<'_> = DispatchView::from(request());
    let _view: DispatchView<'_> = request().into();
    let _view: DispatchView<'_> = <ActionRequest as Into<DispatchView<'_>>>::into(request());
}
