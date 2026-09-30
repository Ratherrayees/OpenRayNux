//! Protocol version negotiation.
//!
//! The daemon and its clients are separately deployable, so the version is
//! *negotiated*, not assumed. A client declares the range it supports; the
//! daemon replies with what it will speak. Neither side can be surprised.

use serde::{Deserialize, Serialize};

use crate::error::{ProtocolError, RpcError, RpcErrorCode};

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(1);

/// A protocol version number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolVersion(pub u16);

impl ProtocolVersion {
    /// The number, as the wire represents it.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// What a client says it can speak, on connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    /// Lowest version the client accepts.
    pub min: ProtocolVersion,
    /// Highest version the client accepts.
    pub max: ProtocolVersion,
}

impl VersionRange {
    /// A range that accepts exactly one version.
    #[must_use]
    pub fn exact(v: ProtocolVersion) -> Self {
        Self { min: v, max: v }
    }

    /// Whether this range accepts `v`.
    #[must_use]
    pub fn accepts(&self, v: ProtocolVersion) -> bool {
        self.min <= v && v <= self.max
    }
}

impl Default for VersionRange {
    fn default() -> Self {
        Self {
            min: PROTOCOL_VERSION,
            max: PROTOCOL_VERSION,
        }
    }
}

/// Negotiates a version.
///
/// # Errors
///
/// Returns [`ProtocolError::VersionMismatch`] when the ranges do not overlap.
/// A mismatch is reported as a *well-formed JSON-RPC error*, not a transport
/// failure, so a client learns why rather than seeing the socket close.
pub fn negotiate(
    client: &VersionRange,
    server: &VersionRange,
) -> Result<ProtocolVersion, ProtocolError> {
    if client.min > client.max {
        return Err(ProtocolError::InvalidVersionRange {
            min: client.min,
            max: client.max,
        });
    }
    if server.min > server.max {
        return Err(ProtocolError::InvalidVersionRange {
            min: server.min,
            max: server.max,
        });
    }
    let low = client.min.max(server.min);
    let high = client.max.min(server.max);
    if low > high {
        return Err(ProtocolError::VersionMismatch {
            client: client.clone(),
            server: server.clone(),
        });
    }
    // Prefer the highest mutually acceptable version, so a newer client is not
    // silently downgraded when the daemon could speak more.
    Ok(high)
}

impl ProtocolError {
    /// Renders this error as a JSON-RPC error object, for the wire.
    #[must_use]
    pub fn to_rpc(&self) -> RpcError {
        match self {
            Self::VersionMismatch { .. } | Self::InvalidVersionRange { .. } => RpcError {
                code: RpcErrorCode::UNSUPPORTED_PROTOCOL_VERSION,
                message: self.to_string(),
                data: None,
            },
            Self::FrameTooLarge { size, limit } => RpcError {
                code: RpcErrorCode::INVALID_REQUEST,
                message: self.to_string(),
                data: Some(serde_json::json!({ "size": size, "limit": limit })),
            },
            Self::DepthExceeded { depth, limit } => RpcError {
                code: RpcErrorCode::INVALID_REQUEST,
                message: self.to_string(),
                data: Some(serde_json::json!({ "depth": depth, "limit": limit })),
            },
            Self::Malformed { reason } => RpcError {
                code: RpcErrorCode::PARSE_ERROR,
                message: self.to_string(),
                data: Some(serde_json::json!({ "reason": reason })),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u16) -> ProtocolVersion {
        ProtocolVersion(n)
    }

    #[test]
    fn identical_ranges_negotiate_to_that_version() {
        let r = VersionRange::exact(v(1));
        assert_eq!(negotiate(&r, &r), Ok(v(1)));
    }

    #[test]
    fn negotiation_prefers_the_highest_common_version() {
        let client = VersionRange {
            min: v(1),
            max: v(3),
        };
        let server = VersionRange {
            min: v(2),
            max: v(5),
        };
        assert_eq!(negotiate(&client, &server), Ok(v(3)));
    }

    #[test]
    fn disjoint_ranges_error_rather_than_downgrade_silently() {
        // Silently picking a version neither side wanted is how protocol bugs
        // become unreproducible.
        let client = VersionRange {
            min: v(1),
            max: v(1),
        };
        let server = VersionRange {
            min: v(2),
            max: v(2),
        };
        assert!(matches!(
            negotiate(&client, &server),
            Err(ProtocolError::VersionMismatch { .. })
        ));
    }

    #[test]
    fn inverted_range_is_rejected() {
        let bad = VersionRange {
            min: v(5),
            max: v(1),
        };
        assert!(matches!(
            negotiate(&bad, &VersionRange::default()),
            Err(ProtocolError::InvalidVersionRange { .. })
        ));
    }

    #[test]
    fn version_mismatch_renders_as_a_well_formed_rpc_error() {
        let client = VersionRange::exact(v(1));
        let server = VersionRange::exact(v(2));
        let err = negotiate(&client, &server).expect_err("should mismatch");
        let rpc = err.to_rpc();
        assert_eq!(rpc.code, RpcErrorCode::UNSUPPORTED_PROTOCOL_VERSION);
        assert!(!rpc.message.is_empty());
    }

    #[test]
    fn default_range_is_exactly_the_current_version() {
        let d = VersionRange::default();
        assert!(d.accepts(PROTOCOL_VERSION));
        assert!(!d.accepts(ProtocolVersion(PROTOCOL_VERSION.0 + 1)));
    }

    #[test]
    fn range_acceptance_is_inclusive_at_both_ends() {
        let r = VersionRange {
            min: v(2),
            max: v(4),
        };
        assert!(!r.accepts(v(1)));
        assert!(r.accepts(v(2)));
        assert!(r.accepts(v(4)));
        assert!(!r.accepts(v(5)));
    }
}
