//! OpenRayNux local wire protocol.
//!
//! # What this crate is for
//!
//! The local transport is **JSON-RPC 2.0 over a Unix domain socket or a named
//! pipe** (ADR-0003). This crate defines the frames. It deliberately does *not*
//! contain the transport: no socket, no `tokio`, no I/O. It is a vocabulary, so
//! it stays inside the portable-core gate (G9).
//!
//! # Why JSON-RPC, and why that matters here
//!
//! JSON-RPC 2.0 is also MCP's wire format. Choosing it means the local client,
//! the MCP client, and the future remote API share framing, error codes, and
//! vocabulary — one implementation, one test suite, one debugging story
//! (ADR-0003).
//!
//! The local transport is **not** HTTP, for a reason worth restating: a socket
//! file has filesystem permissions, and that is the authorisation boundary,
//! enforced by the kernel. A loopback HTTP port has neither identity nor a
//! natural ACL.
//!
//! # Forward compatibility is a requirement, not a nicety
//!
//! The daemon and its clients are separately deployable. A client must tolerate
//! a daemon it does not fully understand. [`PROTOCOL_VERSION`] is negotiated at
//! connect time, unknown methods return a well-formed error rather than a
//! transport failure, and unknown fields are ignored on decode.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod frame;
pub mod method;
pub mod version;

pub use error::{ProtocolError, RpcError, RpcErrorCode};
pub use frame::{Notification, Request, Response, Success};
pub use method::Method;
pub use version::{negotiate, ProtocolVersion, PROTOCOL_VERSION};

/// The framing limits applied to every inbound message.
///
/// Bounds are parameters of the protocol rather than of an implementation, so a
/// client and a server cannot disagree about what "reasonable" means. They are
/// the deserialisation bound required by control S21.
pub mod limits {
    /// Maximum length of a serialised request frame, in bytes.
    ///
    /// Generous enough for a large document payload, small enough that a
    /// hostile peer cannot make the daemon allocate without bound.
    pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

    /// Maximum nesting depth accepted when decoding JSON.
    pub const MAX_JSON_DEPTH: usize = 64;
}
