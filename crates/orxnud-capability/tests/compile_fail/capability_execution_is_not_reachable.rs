//! The one shipped bundle cannot be executed directly.
//!
//! `orxnud_capability::text::WordCountBundle` is a real adapter for a real capability,
//! and before this change any crate depending on `orxnud-capability` could reach it
//! without going near policy:
//!
//! ```text
//! let bundle = WordCountBundle::default();
//! let view = DispatchView { step: 1, capability: &cap, params: &my_params,
//!                           data_class: DataClass::Public, context: &ctx };
//! bundle.adapter().invoke(&view, None)
//!     -> Ok(Succeeded { output: Some("{\"bytes\":43,...,\"words\":9}") })
//! ```
//!
//! No policy evaluation, no human approval, no approval digest, no budget charge, no
//! audit record -- and a `data_class` the caller asserted about itself.
//!
//! Gate G2d reported `ok` on a tree doing exactly this, because such a file names none
//! of `PolicySeal`, `attest`, `authorise` or `issue`. The governed path was
//! structurally optional and the gate could not see it.
//!
//! There are two links in the chain and both are cut. `bundle.adapter()` is
//! `AdapterBundle::adapter`, and that trait is `pub(crate)`, so the method does not
//! resolve at all -- the bundle is not an execution door from outside. And a
//! `DispatchView` can only be obtained from a `CapabilityInvocation`, which needs
//! `authorise`, also `pub(crate)`. Method resolution on a trait object does not require
//! the trait to be in scope, so these are independent refusals and the recorded
//! `.stderr` pins both.

use orxnud_domain::actor::{Actor, AuthChannel};
use orxnud_domain::enums::{RiskClass};
use orxnud_domain::ids::{CapabilityId, RunId, TaskId, UserId};
use orxnud_domain::{ActionRequest, InvocationContext};
use orxnud_capability::text::WordCountBundle;
use orxnud_policy::authority::{AuthorisationProof, CapabilityInvocation};

fn human() -> Actor {
    Actor::Human { user: UserId::new("u"), via: AuthChannel::LocalInteractive }
}

fn request() -> ActionRequest {
    ActionRequest::new(
        TaskId::new("t"),
        RunId::new("r"),
        0,
        CapabilityId::new("text/word-count"),
        orxnud_domain::json!({"text": "anything"}),
        orxnud_domain::DataClass::Public,
        orxnud_domain::DataClass::Public,
    )
}

fn main() {
    let bundle = WordCountBundle::default();

    // Link 1: obtaining an authorised invocation is refused.
    let invocation = CapabilityInvocation::authorise(
        request(),
        human(),
        InvocationContext::new("k", 1, "c"),
        AuthorisationProof::issue("v1", None, RiskClass::Low),
    );
    let view = invocation.dispatch_view();

    // Link 2: obtaining the adapter handle is refused.
    let adapter = bundle.adapter();
    let _out = adapter.invoke(&view, None);
}
