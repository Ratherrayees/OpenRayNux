//! `orxnu-tui` — a thin terminal surface over the governed daemon.
//!
//! # What this crate is
//!
//! A Ratatui front end that sends the same protocol methods as `orxnuctl` over the
//! same socket, and renders the daemon's answers. It owns **no** task, proposal,
//! approval, policy or storage rule: those types are not nameable here. A task's state
//! is a string the daemon chose; an execution verdict is a flag the daemon set. The
//! TUI puts both on screen without deciding what either means.
//!
//! # Why the client comes from `orxnuctl`
//!
//! `orxnuctl::client::Client` is the shipped CLI's transport. Reusing it means one
//! implementation of framing, version negotiation and the local socket. A second one
//! here would be a second answer to "where does a frame end", which is the bug class
//! this repository keeps paying for.
//!
//! # What the first slice does
//!
//! Daemon status, task listing, task inspection, a read-only proposal preview, an
//! approval action, and an execution action whose verdict is displayed exactly as the
//! daemon reported it — including `NeedsVerification`, which is neither success nor
//! failure and must never be rendered as either.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod app;

pub use app::{App, Input, Notice};
