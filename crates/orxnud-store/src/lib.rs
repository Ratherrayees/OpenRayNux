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
//! The requirement is enforced **at compile time** by the assertion in
//! [`sqlite`], not by a comment. See ADR-0006 and the Verification Register's
//! V-02.
//!
//! ## 2. `critical` state is written with `synchronous = FULL`
//!
//! `sqlite.org/wal.html` is explicit that in WAL mode `synchronous = NORMAL`
//! means *"syncing the content to the disk is not required, as long as the
//! application is willing to sacrifice durability following a power loss or
//! hard reboot."* OpenRayNux requires surviving power loss, so the task
//! connection uses `FULL`.
//!
//! Pragmas are **verified by reading them back** ([`Pragma::verify`]), because
//! a pragma that silently failed to apply is indistinguishable from one that
//! was never set until the day the disk loses power.
//!
//! # Scope
//!
//! Phase 1 creates the mechanism: connections, pragmas, the migration runner,
//! the state-region registry, and the repository port. It creates **no
//! application tables** — only `schema_meta` — because docs-13 §8 forbids
//! inventing a schema ahead of the engine that uses it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod migration;
pub mod pragma;
pub mod region;
pub mod repository;
pub mod sqlite;

pub use migration::{MIGRATIONS, Migration, MigrationError, MigrationRunner};
pub use pragma::{Pragma, PragmaError};
pub use region::{RegionRegistry, StateRegion};
pub use repository::{Repository, RepositoryError, SchemaMeta};
pub use sqlite::{
    MIN_SQLITE_VERSION, SqliteVersion, Store, StoreError, open, verify_sqlite_version,
};
