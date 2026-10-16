//! The Tier-1 stdin transport's wire format (ADR-0054, Decision 4).
//!
//! # Why a frame at all
//!
//! On a bare stdin, "the caller sent an empty file" and "the caller sent nothing" are
//! the same bytes: zero of them. A receiver cannot tell them apart, so it would either
//! refuse every empty write or accept every truncated send. The frame carries explicit,
//! **non-sensitive** metadata that makes the difference decidable.
//!
//! ```text
//! ORXNUD-STDIN/1\n
//! contents-length: <decimal>\n
//! \n
//! <contents-length bytes of raw payload, nothing else>
//! ```
//!
//! # The four receiver rules
//!
//! * A declared length of **zero** is a valid, successful write of an empty file.
//! * **Missing or unparseable metadata is refused** — no magic, unknown version,
//!   missing or duplicated length, non-decimal, signed, padded, or over the header cap.
//! * **Unexpected EOF or a length mismatch must not produce a successful write.** Fewer
//!   bytes than declared is a refusal; the receiver does not pad and does not write what
//!   it managed to read.
//! * **The receiver does not silently truncate excess data.** After the declared bytes it
//!   reads to EOF and requires nothing further.
//!
//! # Why a raw length prefix and not JSON
//!
//! JSON makes "length" ambiguous between characters and serialised bytes — the exact
//! ambiguity Decision 2 rejects — and would require buffering the whole payload to
//! compute it. A declared byte count *is* the count.
//!
//! # Why the header is capped
//!
//! Without a cap, "framed" is still an unbounded read: a peer could send an endless
//! header and the receiver would grow a `String` until it died. The cap is what keeps
//! the frame from reintroducing the denial-of-service surface Decision 2 removes.
//!
//! # Non-sensitivity
//!
//! A version string and a decimal length disclose nothing about content, **because this
//! channel carries payloads the user has already handed the daemon**. The same frame
//! would not be non-sensitive for a credential, since the length alone leaks the
//! secret's size. That is a second, independent reason credential-bearing Tier-1
//! capabilities remain prohibited (ADR-0054, Decision 5).

use std::fmt;
use std::io::Read;

/// The protocol's identifying first line. An unknown value is refused, not tolerated.
pub const MAGIC: &str = "ORXNUD-STDIN/1";

/// The transport version, passed in `argv` so a helper can refuse before it reads.
///
/// Non-sensitive, which is why it may live in `argv` while the payload does not.
pub const VERSION_ARG: &str = "--stdin-transport=1";

/// The maximum payload, in **UTF-8 bytes of the normalised value** (Decision 2).
///
/// Not characters: `chars().count()` is smaller than `len()` for any non-ASCII text,
/// so a character-based bound would admit up to four times this in bytes. Not
/// serialised-envelope bytes: that drifts whenever the framing changes.
pub const MAX_PAYLOAD_BYTES: usize = 1_048_576;

/// The maximum header, in bytes. See the module docs for why this must exist.
pub const MAX_HEADER_BYTES: usize = 512;

/// Why a frame was refused.
///
/// Every variant is a refusal by name. There is no `Default`, no "best effort" variant,
/// and nothing that a caller could treat as an empty or partial success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The stream ended before a complete header arrived.
    HeaderTruncated {
        /// How many bytes were available.
        got: usize,
    },
    /// The header exceeded [`MAX_HEADER_BYTES`].
    HeaderTooLong {
        /// The cap that was exceeded.
        limit: usize,
    },
    /// The first line was not [`MAGIC`] — wrong protocol, or wrong version.
    UnknownMagic {
        /// What arrived instead, truncated for the message.
        got: String,
    },
    /// No `contents-length` header.
    MissingLength,
    /// More than one `contents-length` header.
    DuplicateLength,
    /// The length was not a bare run of decimal digits.
    MalformedLength {
        /// What arrived instead, truncated for the message.
        got: String,
    },
    /// The declared length exceeds [`MAX_PAYLOAD_BYTES`].
    LengthOverBound {
        /// What was declared.
        declared: u64,
        /// The cap it exceeds.
        limit: usize,
    },
    /// The stream ended before the declared number of bytes arrived.
    BodyTruncated {
        /// What was declared.
        declared: usize,
        /// How many actually arrived.
        got: usize,
    },
    /// Bytes remained after the declared payload.
    TrailingData {
        /// How many bytes came after.
        extra: usize,
    },
    /// The underlying stream failed.
    Io(String),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTruncated { got } => {
                write!(
                    f,
                    "the stdin header ended after {got} bytes, before it was complete"
                )
            }
            Self::HeaderTooLong { limit } => write!(
                f,
                "the stdin header exceeds the {limit}-byte cap; refusing rather than \
                 growing a buffer without bound"
            ),
            Self::UnknownMagic { got } => write!(
                f,
                "expected the first line to be {MAGIC:?}, got {got:?}; this helper does \
                 not speak that transport"
            ),
            Self::MissingLength => write!(f, "the stdin frame has no `contents-length` header"),
            Self::DuplicateLength => {
                write!(
                    f,
                    "the stdin frame has more than one `contents-length` header"
                )
            }
            Self::MalformedLength { got } => write!(
                f,
                "`contents-length` must be bare decimal digits, got {got:?}"
            ),
            Self::LengthOverBound { declared, limit } => write!(
                f,
                "the frame declares {declared} bytes, over the {limit}-byte bound"
            ),
            Self::BodyTruncated { declared, got } => write!(
                f,
                "the frame declares {declared} bytes but the stream ended after {got}; \
                 a partial payload is never written"
            ),
            Self::TrailingData { extra } => write!(
                f,
                "{extra} bytes arrived after the declared payload; the receiver does not \
                 truncate, so this is refused"
            ),
            Self::Io(e) => write!(f, "the stdin stream failed: {e}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Frames a payload for delivery.
///
/// Refuses rather than truncates (Decision 2): a payload over the bound produces no
/// frame at all, so nothing can be written from it.
pub fn encode(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(FrameError::LengthOverBound {
            declared: payload.len() as u64,
            limit: MAX_PAYLOAD_BYTES,
        });
    }
    let mut frame = Vec::with_capacity(payload.len() + 64);
    frame.extend_from_slice(MAGIC.as_bytes());
    frame.push(b'\n');
    frame.extend_from_slice(b"contents-length: ");
    frame.extend_from_slice(payload.len().to_string().as_bytes());
    frame.extend_from_slice(b"\n\n");
    frame.extend_from_slice(payload);
    debug_assert!(frame.len() <= MAX_HEADER_BYTES + MAX_PAYLOAD_BYTES);
    Ok(frame)
}

/// Reads one frame from `reader` and returns its payload.
///
/// Every rule in the module docs is enforced here. In particular this never returns a
/// payload it did not fully receive, and never silently accepts a short read as an
/// empty one.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    let header = read_header(reader)?;
    let declared = parse_length(&header)?;

    let mut payload = vec![0u8; declared];
    reader
        .read_exact(&mut payload)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::UnexpectedEof => FrameError::BodyTruncated { declared, got: 0 },
            _ => FrameError::Io(e.to_string()),
        })
        .inspect_err(|_| {
            // `read_exact` may have consumed a prefix. The count is not recoverable from
            // here, and reporting a wrong `got` would be worse than reporting none, so the
            // error carries the declared length and the reason.
        })?;

    // Rule 4: no trailing data. A receiver that stops reading at `declared` and reports
    // success is the same wrong-write defect as truncation, arriving from the other side.
    let mut extra = 0usize;
    let mut buf = [0u8; 256];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => extra += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FrameError::Io(e.to_string())),
        }
    }
    if extra > 0 {
        return Err(FrameError::TrailingData { extra });
    }
    Ok(payload)
}

/// Reads up to the blank line that ends the header, bounded by [`MAX_HEADER_BYTES`].
fn read_header<R: Read>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut header = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        if header.len() >= MAX_HEADER_BYTES {
            return Err(FrameError::HeaderTooLong {
                limit: MAX_HEADER_BYTES,
            });
        }
        match reader.read(&mut byte) {
            Ok(0) => {
                return Err(FrameError::HeaderTruncated { got: header.len() });
            }
            Ok(_) => header.push(byte[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(FrameError::Io(e.to_string())),
        }
        // A header ends at a blank line: `\n\n`.
        if header.ends_with(b"\n\n") {
            return Ok(header);
        }
    }
}

/// Validates the header and returns the declared payload length.
fn parse_length(header: &[u8]) -> Result<usize, FrameError> {
    let text = std::str::from_utf8(header).map_err(|e| FrameError::Io(e.to_string()))?;
    let mut lines = text.split('\n');

    let first = lines.next().unwrap_or_default();
    if first != MAGIC {
        return Err(FrameError::UnknownMagic {
            got: first.chars().take(32).collect(),
        });
    }

    let mut declared: Option<u64> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some(value) = line.strip_prefix("contents-length: ") else {
            // An unrecognised header line is not ignored. Forward compatibility would be
            // nice, but a receiver that skips what it does not understand cannot tell a
            // future field from a malformed one, and this channel carries user content.
            return Err(FrameError::MalformedLength {
                got: line.chars().take(48).collect(),
            });
        };
        if declared.is_some() {
            return Err(FrameError::DuplicateLength);
        }
        // Bare decimal digits only: no sign, no padding, no underscores, no exponent.
        // `u64::from_str` accepts a leading `+`, so the check is done first.
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(FrameError::MalformedLength {
                got: value.chars().take(32).collect(),
            });
        }
        declared = Some(
            value
                .parse::<u64>()
                .map_err(|_| FrameError::MalformedLength {
                    got: value.chars().take(32).collect(),
                })?,
        );
    }

    let declared = declared.ok_or(FrameError::MissingLength)?;
    if declared > MAX_PAYLOAD_BYTES as u64 {
        return Err(FrameError::LengthOverBound {
            declared,
            limit: MAX_PAYLOAD_BYTES,
        });
    }
    Ok(declared as usize)
}
