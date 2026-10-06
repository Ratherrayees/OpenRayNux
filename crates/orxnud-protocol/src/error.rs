//! Protocol-level error codes and the error type.

use serde::{Deserialize, Serialize};

/// A JSON-RPC 2.0 error code, plus the OpenRayNux-reserved server range.
///
/// The standard codes keep the protocol recognisable as JSON-RPC (and therefore
/// compatible with MCP's framing); the reserved range is allocated so our
/// domain codes never collide with a peer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RpcErrorCode(i32);

impl RpcErrorCode {
    /// Invalid JSON was received.
    pub const PARSE_ERROR: Self = Self(-32700);
    /// The payload is not a valid Request object.
    pub const INVALID_REQUEST: Self = Self(-32600);
    /// The method does not exist.
    pub const METHOD_NOT_FOUND: Self = Self(-32601);
    /// Invalid method parameters.
    pub const INVALID_PARAMS: Self = Self(-32602);
    /// Internal error.
    pub const INTERNAL_ERROR: Self = Self(-32603);
    /// Version negotiation failed.
    pub const UNSUPPORTED_PROTOCOL_VERSION: Self = Self(-32022);

    // ---- The project-defined classes -------------------------------------
    //
    // JSON-RPC 2.0 defines five codes, and none of them says "the thing you named does
    // not exist" or "it exists but not in a state where that is legal". Reporting both as
    // `INVALID_REQUEST` tells a client to *fix its request*, which is the wrong instruction
    // for a task another worker just claimed; reporting them as `INTERNAL_ERROR` tells it to
    // file a bug, which is worse.
    //
    // These four live in the server-reserved band (`is_server_reserved`) so a client can
    // recognise "a code this server defines" without a registry, and they are spaced away
    // from `-32022` so nothing existing has to move. The codes are **not** the taxonomy:
    // `data.reason` carries the fine-grained, stable word (`proposal-already-decided`,
    // `approval-expired`, `not-at-boundary`, …) and a client that needs to branch on the
    // detail branches there. The code says which *kind* of recovery applies.

    /// The referenced resource does not exist.
    ///
    /// Distinct from `INVALID_REQUEST` because the request was well-formed: there is simply
    /// no such task or proposal. The recovery is to refresh the client's view, not to edit
    /// the request.
    pub const RESOURCE_NOT_FOUND: Self = Self(-32040);

    /// The request was valid, but the resource is not in a state where it is legal.
    ///
    /// Already decided, already completed, already cancelled, a stale or foreign lease,
    /// another worker winning a race, a continuation with no boundary to cross. One code for
    /// all of them because the recovery is the same in every case: **re-read the state and
    /// decide again**. `data.reason` separates them where it matters.
    pub const CONFLICT: Self = Self(-32041);

    /// Refused by policy or authority.
    ///
    /// No approval, a spent or expired one, a digest that no longer matches, a capability
    /// that is not granted. Retrying the identical request will fail identically; what is
    /// needed is a *new human decision*, which is why this is not `CONFLICT`.
    pub const FORBIDDEN: Self = Self(-32042);

    /// A dependency or the execution environment is unavailable.
    ///
    /// The provider could not be reached, a credential is missing, the sandbox guarantees
    /// could not be established, the platform has no backend. The operation itself is
    /// permitted; something it needs is not there. Distinct from `INTERNAL_ERROR` because
    /// the remedy is external — fix the configuration, add the credential, wait for the
    /// network — rather than report a defect.
    pub const ENVIRONMENT_UNAVAILABLE: Self = Self(-32043);

    /// The numeric code.
    #[must_use]
    pub const fn code(self) -> i32 {
        self.0
    }

    /// Whether this is one of the codes reserved for server use.
    #[must_use]
    pub fn is_server_reserved(self) -> bool {
        (-32099..=-32020).contains(&self.0)
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    /// The code.
    pub code: RpcErrorCode,
    /// A short, human-readable message. Never empty.
    pub message: String,
    /// Optional structured detail. Used for machine-readable context, never for
    /// secrets — redaction happens before this point (control S9).
    pub data: Option<serde_json::Value>,
}

impl RpcError {
    /// Builds an error with no structured data.
    #[must_use]
    pub fn new(code: RpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Attaches structured detail.
    ///
    /// For machine-readable context a caller can branch on. Never for secrets:
    /// redaction happens before this point (control S9), and this constructor takes
    /// whatever it is given.
    #[must_use]
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    /// The JSON-RPC method-not-found error, used for unknown methods.
    ///
    /// Forward compatibility in action: a newer client calling a method this
    /// daemon does not have gets a clean, well-formed answer rather than a
    /// dropped connection.
    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: RpcErrorCode::METHOD_NOT_FOUND,
            message: format!("unknown method: {method}"),
            data: Some(serde_json::json!({ "method": method })),
        }
    }

    /// The JSON-RPC internal error, used when the daemon refuses to proceed.
    ///
    /// Also the shape a **fails-closed** policy decision takes: the daemon
    /// returns an error rather than guessing, and never returns a partial or
    /// optimistic success.
    #[must_use]
    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            code: RpcErrorCode::INVALID_PARAMS,
            message: reason.into(),
            data: None,
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code.code(), self.message)
    }
}

impl std::error::Error for RpcError {}

/// A protocol-layer failure.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ProtocolError {
    /// A frame exceeded [`crate::limits::MAX_FRAME_BYTES`].
    #[error("frame too large: {size} bytes (limit {limit})")]
    FrameTooLarge {
        /// Observed size.
        size: usize,
        /// Configured limit.
        limit: usize,
    },

    /// A frame exceeded [`crate::limits::MAX_JSON_DEPTH`].
    #[error("JSON nesting too deep: {depth} (limit {limit})")]
    DepthExceeded {
        /// Observed depth.
        depth: usize,
        /// Configured limit.
        limit: usize,
    },

    /// The frame could not be parsed.
    #[error("malformed frame: {reason}")]
    Malformed {
        /// Parser's explanation.
        reason: String,
    },

    /// Version negotiation failed.
    #[error("protocol version mismatch: client accepts {client}, server accepts {server}")]
    VersionMismatch {
        /// The client's range.
        client: crate::version::VersionRange,
        /// The server's range.
        server: crate::version::VersionRange,
    },

    /// A version range was inverted.
    #[error("invalid version range: min {min} > max {max}")]
    InvalidVersionRange {
        /// Declared minimum.
        min: crate::version::ProtocolVersion,
        /// Declared maximum.
        max: crate::version::ProtocolVersion,
    },
}

impl std::fmt::Display for crate::version::VersionRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.min == self.max {
            write!(f, "{}", self.min)
        } else {
            write!(f, "{}..{}", self.min, self.max)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_codes_have_the_json_rpc_values() {
        assert_eq!(RpcErrorCode::PARSE_ERROR.code(), -32700);
        assert_eq!(RpcErrorCode::INVALID_REQUEST.code(), -32600);
        assert_eq!(RpcErrorCode::METHOD_NOT_FOUND.code(), -32601);
        assert_eq!(RpcErrorCode::INVALID_PARAMS.code(), -32602);
        assert_eq!(RpcErrorCode::INTERNAL_ERROR.code(), -32603);
    }

    #[test]
    fn our_server_code_sits_in_the_reserved_range() {
        assert!(RpcErrorCode::UNSUPPORTED_PROTOCOL_VERSION.is_server_reserved());
        assert!(!RpcErrorCode::INVALID_PARAMS.is_server_reserved());
    }

    #[test]
    fn unknown_method_is_a_clean_error_not_a_transport_failure() {
        let e = RpcError::method_not_found("does/not/exist");
        assert_eq!(e.code, RpcErrorCode::METHOD_NOT_FOUND);
        assert!(e.message.contains("does/not/exist"));
        assert!(e.data.is_some());
    }

    #[test]
    fn errors_always_carry_a_message() {
        // "Something went wrong" is a bug (docs-08 §9).
        for e in [
            RpcError::denied("x"),
            RpcError::method_not_found("m"),
            RpcError::new(RpcErrorCode::INTERNAL_ERROR, "y"),
        ] {
            assert!(!e.message.trim().is_empty());
        }
    }

    #[test]
    fn a_version_range_renders_readably_in_a_mismatch() {
        // `ProtocolError::VersionMismatch` interpolates these into its message,
        // so a range that cannot be displayed is a broken error, not a cosmetic
        // problem.
        use crate::version::{PROTOCOL_VERSION, ProtocolVersion, VersionRange};
        let exact = VersionRange::exact(PROTOCOL_VERSION);
        assert_eq!(exact.to_string(), PROTOCOL_VERSION.to_string());
        let span = VersionRange {
            min: ProtocolVersion(1),
            max: ProtocolVersion(3),
        };
        assert_eq!(span.to_string(), "1..3");

        let err = ProtocolError::VersionMismatch {
            client: span.clone(),
            server: exact.clone(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("1..3"), "{rendered}");
        assert!(rendered.contains(&exact.to_string()), "{rendered}");
    }

    #[test]
    fn display_includes_code_and_message() {
        let e = RpcError::denied("policy denied");
        let s = e.to_string();
        assert!(s.contains("-32602"));
        assert!(s.contains("policy denied"));
    }
}
