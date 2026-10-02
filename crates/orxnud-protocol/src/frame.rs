//! JSON-RPC 2.0 frames.
//!
//! Standard shapes, with one OpenRayNux addition: every frame may carry
//! `_meta`, and it is the *only* place protocol and tracing metadata live. That
//! mirrors what MCP `2026-07-28` standardised, so the same transport can later
//! carry `traceparent` without a format change.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProtocolError;
use crate::limits;

/// A JSON-RPC request id.
///
/// A string or a number, per the specification. We always emit strings, because
/// a numeric id can collide with an integer-looking string id from another
/// client and correlation is worth more than brevity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// A string id. The only form this implementation emits.
    Text(String),
    /// A numeric id. Accepted for interoperability.
    Number(i64),
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(s) => f.write_str(s),
            Self::Number(n) => write!(f, "{n}"),
        }
    }
}

/// A JSON-RPC request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// Correlation id.
    pub id: RequestId,
    /// The method name.
    pub method: String,
    /// Parameters. Absent rather than null when there are none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Protocol and tracing metadata.
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

impl Request {
    /// Builds a request with no params and no metadata.
    pub fn new(id: RequestId, method: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            method: method.into(),
            params: None,
            meta: None,
        }
    }

    /// Attaches params.
    #[must_use]
    pub fn with_params(mut self, params: Value) -> Self {
        self.params = Some(params);
        self
    }

    /// Attaches metadata.
    #[must_use]
    pub fn with_meta(mut self, meta: Value) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Encodes to JSON, refusing frames over the size limit.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::FrameTooLarge`] when the encoded frame exceeds
    /// [`limits::MAX_FRAME_BYTES`]. Checked *before* it is handed to a socket,
    /// because a frame we cannot bound is a frame we cannot reason about.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let bytes = serde_json::to_vec(self).map_err(|e| ProtocolError::Malformed {
            reason: e.to_string(),
        })?;
        if bytes.len() > limits::MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge {
                size: bytes.len(),
                limit: limits::MAX_FRAME_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decodes a frame, enforcing the size bound first.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::FrameTooLarge`] or [`ProtocolError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        decode_frame(bytes)
    }

    /// Whether the `jsonrpc` field is the expected version string.
    #[must_use]
    pub fn has_valid_version(&self) -> bool {
        self.jsonrpc == "2.0"
    }
}

/// A shared decoder for a frame of either direction.
///
/// One function because a client and a server have to agree on what a well-formed
/// frame is, and two copies of that rule is one more thing to keep in step. The size
/// bound is checked before parsing so an oversized frame cannot make the decoder
/// allocate for it first.
fn decode_frame<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.len() > limits::MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge {
            size: bytes.len(),
            limit: limits::MAX_FRAME_BYTES,
        });
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|e| ProtocolError::Malformed {
        reason: e.to_string(),
    })?;
    check_depth(&value, 0)?;
    serde_json::from_value(value).map_err(|e| ProtocolError::Malformed {
        reason: e.to_string(),
    })
}

/// A JSON-RPC notification: a request with no id, expecting no response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notification {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The method name.
    pub method: String,
    /// Parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl Notification {
    /// Builds a notification.
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            method: method.into(),
            params,
        }
    }
}

/// A successful result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Success {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The id of the request this answers.
    pub id: RequestId,
    /// The result.
    pub result: Value,
}

impl Success {
    /// Builds a success response.
    pub fn new(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result,
        }
    }
}

/// A JSON-RPC response: exactly one of `result` or `error`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    /// Always `"2.0"`.
    pub jsonrpc: String,
    /// The id of the request this answers.
    pub id: RequestId,
    /// The result, when the call succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The error, when it did not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<crate::error::RpcError>,
}

impl Response {
    /// Builds a success response.
    #[must_use]
    pub fn ok(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Builds an error response.
    #[must_use]
    pub fn err(id: RequestId, error: crate::error::RpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Encodes the response, enforcing the same size bound as [`Request::encode`].
    ///
    /// A response that cannot be encoded must not be sent unbounded either, and the
    /// bound is the protocol's own so a client decodes one thing.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::Malformed`] if serialisation fails, or
    /// [`ProtocolError::FrameTooLarge`] if the response exceeds
    /// [`limits::MAX_FRAME_BYTES`].
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let bytes = serde_json::to_vec(self).map_err(|e| ProtocolError::Malformed {
            reason: e.to_string(),
        })?;
        if bytes.len() > limits::MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge {
                size: bytes.len(),
                limit: limits::MAX_FRAME_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decodes a response frame, enforcing the size bound first.
    ///
    /// The mirror of [`Request::decode`], and deliberately in this crate rather than
    /// in each client: what a well-formed frame is has to be one rule, or a client and
    /// a daemon can each believe the other's frames are fine.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::FrameTooLarge`], [`ProtocolError::DepthExceeded`] or
    /// [`ProtocolError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        decode_frame(bytes)
    }

    /// Whether this carries a result rather than an error.
    pub fn is_ok(&self) -> bool {
        self.error.is_none() && self.result.is_some()
    }

    /// The result, or the error this response carries.
    ///
    /// The one place a caller has to choose between "the answer" and "the refusal",
    /// so it lives here rather than in each client. A client that wants the error's
    /// structured fields gets the whole [`crate::error::RpcError`], not a string.
    ///
    /// # Errors
    ///
    /// The carried [`crate::error::RpcError`], when this is an error response.
    pub fn into_result(self) -> Result<Value, crate::error::RpcError> {
        match (self.result, self.error) {
            (_, Some(e)) => Err(e),
            (Some(v), None) => Ok(v),
            // Neither field: a frame that is not a response at all. Reported as a
            // malformed frame rather than as a successful call with no value.
            (None, None) => Err(crate::error::RpcError::new(
                crate::error::RpcErrorCode::PARSE_ERROR,
                "response carried neither a result nor an error",
            )),
        }
    }
}

/// Enforces the JSON nesting bound.
///
/// A hand-rolled walk rather than a deserialiser option, because
/// `serde_json`'s recursion limit is not configurable and we need the bound to
/// be an explicit protocol parameter (control S21).
fn check_depth(value: &Value, depth: usize) -> Result<(), ProtocolError> {
    if depth > limits::MAX_JSON_DEPTH {
        return Err(ProtocolError::DepthExceeded {
            depth,
            limit: limits::MAX_JSON_DEPTH,
        });
    }
    match value {
        Value::Array(items) => {
            for item in items {
                check_depth(item, depth + 1)?;
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                check_depth(item, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id() -> RequestId {
        RequestId::Text("r-1".into())
    }

    #[test]
    fn request_round_trips() {
        let r = Request::new(id(), "daemon/status").with_params(json!({"verbose": true}));
        let bytes = r.encode().expect("encode");
        let back = Request::decode(&bytes).expect("decode");
        assert_eq!(r, back);
        assert!(back.has_valid_version());
    }

    #[test]
    fn meta_survives_the_round_trip() {
        // `_meta` is where trace context will live; it must not be dropped.
        let r = Request::new(id(), "m").with_meta(json!({"traceparent": "00-abc-def-01"}));
        let back = Request::decode(&r.encode().expect("encode")).expect("decode");
        assert_eq!(back.meta, Some(json!({"traceparent": "00-abc-def-01"})));
    }

    #[test]
    fn absent_params_are_omitted_not_nulled() {
        let bytes = Request::new(id(), "m").encode().expect("encode");
        let v: Value = serde_json::from_slice(&bytes).expect("json");
        assert!(
            v.get("params").is_none(),
            "params should be omitted, not null"
        );
    }

    #[test]
    fn unknown_fields_are_ignored_on_decode() {
        // Forward compatibility: a newer client may send fields we do not know.
        let raw = json!({
            "jsonrpc": "2.0",
            "id": "r-1",
            "method": "m",
            "somethingNew": {"a": 1}
        });
        let bytes = serde_json::to_vec(&raw).expect("encode");
        let r = Request::decode(&bytes).expect("should decode despite unknown field");
        assert_eq!(r.method, "m");
    }

    #[test]
    fn oversized_frames_are_refused_before_encoding() {
        let big = "x".repeat(limits::MAX_FRAME_BYTES + 1);
        let r = Request::new(id(), "m").with_params(json!({ "blob": big }));
        assert!(matches!(
            r.encode(),
            Err(ProtocolError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn oversized_inbound_frames_are_refused_before_decoding() {
        let bytes = vec![b'x'; limits::MAX_FRAME_BYTES + 1];
        assert!(matches!(
            Request::decode(&bytes),
            Err(ProtocolError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn deeply_nested_json_is_refused() {
        // Built iteratively so the test itself does not blow the stack.
        let mut v = json!(1);
        for _ in 0..(limits::MAX_JSON_DEPTH + 5) {
            v = json!([v]);
        }
        let bytes = serde_json::to_vec(&v).expect("encode");
        // A bare value is not a Request, so the error is either depth or
        // malformed — but never a stack overflow or an unbounded allocation.
        assert!(Request::decode(&bytes).is_err());
    }

    #[test]
    fn moderately_nested_json_is_accepted() {
        let mut v = json!(1);
        for _ in 0..8 {
            v = json!({ "a": v });
        }
        let bytes = serde_json::to_vec(&v).expect("encode");
        // Decodes to a malformed-request error, not a depth error.
        match Request::decode(&bytes) {
            Err(ProtocolError::Malformed { .. }) => {}
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    #[test]
    fn response_carries_exactly_one_of_result_or_error() {
        let ok = Response::ok(id(), json!({"status": "idle"}));
        assert!(ok.is_ok());
        assert!(ok.error.is_none());
        let bad = Response::err(id(), crate::error::RpcError::denied("denied"));
        assert!(!bad.is_ok());
        assert!(bad.result.is_none());
    }

    #[test]
    fn request_id_accepts_both_spec_forms() {
        assert_eq!(
            serde_json::from_str::<RequestId>("\"abc\"").expect("string id"),
            RequestId::Text("abc".into())
        );
        assert_eq!(
            serde_json::from_str::<RequestId>("42").expect("number id"),
            RequestId::Number(42)
        );
    }

    #[test]
    fn malformed_json_is_a_clean_error() {
        assert!(matches!(
            Request::decode(b"{not json"),
            Err(ProtocolError::Malformed { .. })
        ));
    }
}
