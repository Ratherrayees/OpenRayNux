//! The capability crate's own test suite, as unit tests rather than integration tests.
//!
//! # Why these live inside the crate
//!
//! Because `CapabilityAdapter` and `AdapterBundle` are `pub(crate)`. Sealing them is
//! what makes an adapter uncallable and unimplementable from another crate — the
//! capability execution boundary — and it necessarily also means a test *outside* the
//! crate cannot provide a fake adapter to test the dispatcher with.
//!
//! That is not a loss of coverage; it is a correction of where these tests were
//! standing. A test that reaches past the boundary to test what is inside it was
//! testing the boundary's absence. These now drive the same paths from the inside,
//! which is also the only place a `RegisterError`, a `ReentrancyGuard`, or an adapter's
//! panic path can be provoked without a public door to provoke it through.
//!
//! Migration was mechanical: `orxnud_capability::` became `crate::`.

pub(crate) mod support;

/// The dispatcher's adapter registry, aliased so every coercion site in this suite
/// reads as "and the registry these adapters live in".
pub(crate) type Registry = crate::dispatch::AdapterRegistry;

mod bypass;
mod concurrency;
mod contract;
mod dispatch_path;
mod durable_state;
mod governed_path;
mod read_text;
mod read_text_real;
mod settlement;
mod write_text;
