//! OpenRayNux SQLite persistence.
//!
//! # Two hard requirements
//!
//! ## 1. The bundled SQLite is at least 3.51.3
//!
//! SQLite 3.51.3 (2026-03-13) fixed the **WAL-reset database corruption bug**,
//! documented as present in every version from 3.7.0 through 3.51.2. It
//! requires two or more connections writing and checkpointing concurrently with
//! tight timing — which is *precisely* the workload a durable task queue
//! creates.
//!
//! This is why we **bundle** SQLite (`libsqlite3-sys` with the `bundled`
//! feature) rather than linking the system library. The development machine
//! runs Fedora 44, which ships 3.51.2 — *below the fix*. Linking the system
//! library would mean shipping a data-corruption bug in the state most
//! developers, and many users, would run.
//!
//! The requirement is enforced **at compile time**: `build.rs` parses
//! `SQLITE_VERSION_NUMBER` out of the header `libsqlite3-sys` actually compiles,
//! and [`sqlite`] const-asserts on the result. Asserting against a constant we
//! wrote ourselves would prove nothing. See ADR-0006 and V-02.
//!
//! ## 2. `critical` state is written with `synchronous = FULL`
//!
//! `sqlite.org/wal.html` is explicit that in WAL mode `synchronous = NORMAL`
//! means *"syncing the content to the disk is not required, as long as the
//! application is willing to sacrifice durability following a power loss or
//! hard reboot."* OpenRayNux requires surviving power loss, so every connection
//! to critical state uses `FULL`.
//!
//! Pragmas are **verified by reading them back** ([`Pragma::verify`]), because a
//! pragma that silently failed to apply is indistinguishable from one that was
//! never set until the day the disk loses power.
//!
//! # What this crate owns
//!
//! `orxnud-store` is the **only** crate that speaks SQL (ADR-0006 decision 2).
//! Everything above it works in domain operations:
//!
//! * [`schema`] — the Phase 2 tables, and why each one is required.
//! * [`task_repo`] — tasks, leases, attempts, effects, approvals, events.
//! * [`schedule_repo`] — schedules and the fire ledger.
//! * [`migration`] — forward-only, transactional, snapshot-protected.
//! * [`backup`] — the online snapshot and restore that make a migration
//!   recoverable (ADR-0017).
//! * [`region`] — the declared state regions (ADR-0028).
//!
//! # The transaction discipline
//!
//! Every state transition is one `BEGIN IMMEDIATE` transaction. `IMMEDIATE`
//! rather than the default `DEFERRED` because `sqlite.org/lang_transaction.html`
//! says: *"If the BEGIN IMMEDIATE operation succeeds, then no subsequent
//! operations in that transaction will ever fail with a SQLITE_BUSY error."*
//! With `DEFERRED`, the lock is taken at the first read and a concurrent writer
//! can invalidate the plan, so the transition is retried — which for a state
//! transition means re-evaluating whether it is still legal.
//!
//! Every mutation here takes `&mut Connection`, so the compiler enforces that a
//! caller cannot hold a shared borrow across a transaction.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod backup;
pub mod faults;
pub mod migration;
pub mod pragma;
pub mod region;
pub mod repository;
pub mod schedule_repo;
pub mod schema;
pub mod sqlite;
pub mod task_repo;

pub use migration::{MIGRATIONS, Migration, MigrationError, MigrationRunner};
pub use pragma::{Pragma, PragmaError};
pub use region::{RegionRegistry, StateRegion, task_layer_regions};
pub use repository::{Repository, RepositoryError, SchemaMeta};
pub use sqlite::{
    MIN_SQLITE_VERSION, SqliteVersion, Store, StoreError, open, verify_sqlite_version,
};
