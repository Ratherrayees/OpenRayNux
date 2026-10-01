//! Engine factories for the production conformance run.
//!
//! Split out so the test bodies stay about *what is being proved* rather than about
//! how a database is opened. Every factory returns a fresh engine on a fresh
//! **real file** — never `:memory:` — because an in-memory database has no WAL and
//! no crash recovery and therefore cannot exercise TP-1, TP-4 or TP-7
//! (docs-08 §4.4).

use std::path::PathBuf;

use orxnud_task::DurableEngine;
use orxnud_task::EngineLimits;
use orxnud_task::conformance::EngineFactory;
use orxnud_task::conformance::properties::TaskEngine;

use crate::{database_in, open_migrated, scratch};

/// A counter making each engine's database unique within one test binary.
///
/// Without it, two factories built in the same process would share a path and one
/// suite's rows would be visible to another's — which is exactly the
/// cross-property interference the engine-per-property design exists to prevent.
fn unique_path(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    database_in(scratch(&format!("{tag}-{n}")))
}

/// A production engine on a fresh migrated file.
pub fn production() -> EngineFactory {
    Box::new(|| {
        let path = unique_path("engine");
        let conn = open_migrated(&path);
        Box::new(DurableEngine::new(conn, EngineLimits::documented()).expect("engine"))
    })
}

/// An engine whose store rejects every task write.
///
/// Used to prove the suite has teeth against the production engine: if an engine
/// that cannot store anything still produced a clean report, the report would be
/// worth nothing.
pub fn production_broken() -> EngineFactory {
    Box::new(|| {
        // A real, migrated database, so the reads are honest; only the writes are
        // broken. An engine that failed at *everything* would prove less: the suite
        // must notice a store that accepts reads and refuses writes, which is the
        // state a full disk or a revoked permission actually produces.
        let conn = open_migrated(&unique_path("broken"));
        Box::new(BrokenEngine {
            inner: DurableEngine::new(conn, EngineLimits::documented()).expect("engine"),
        })
    })
}

/// Wraps a working engine so every operation fails, to prove the suite detects it.
#[derive(Debug)]
struct BrokenEngine {
    inner: DurableEngine,
}

impl TaskEngine for BrokenEngine {
    fn name(&self) -> &'static str {
        "sqlite-durable-broken"
    }

    fn enqueue(
        &mut self,
        _task: orxnud_task::conformance::properties::TaskRecord,
    ) -> Result<(), String> {
        Err("[storage] the store is unusable".to_owned())
    }

    fn claim(
        &mut self,
        _worker: &str,
        _now_ms: i64,
    ) -> Result<orxnud_task::conformance::properties::Claim, String> {
        Err("[storage] the store is unusable".to_owned())
    }

    fn complete(
        &mut self,
        _id: &orxnud_domain::TaskId,
        _worker: &str,
        _now_ms: i64,
        _state: orxnud_domain::TaskState,
        _effect_observed: bool,
        _error: Option<String>,
    ) -> Result<(), String> {
        Err("[storage] the store is unusable".to_owned())
    }

    fn request_cancel(&mut self, _id: &orxnud_domain::TaskId) -> Result<(), String> {
        Err("[storage] the store is unusable".to_owned())
    }

    fn recover(&mut self, _now_ms: i64) -> Result<(), String> {
        Err("[storage] the store is unusable".to_owned())
    }

    fn all(&self) -> Vec<orxnud_task::conformance::properties::TaskRecord> {
        self.inner.all()
    }

    fn get(
        &self,
        id: &orxnud_domain::TaskId,
    ) -> Option<orxnud_task::conformance::properties::TaskRecord> {
        self.inner.get(id)
    }
}
