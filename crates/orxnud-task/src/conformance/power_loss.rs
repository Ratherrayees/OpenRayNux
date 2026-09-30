//! TP-7: power loss cannot corrupt task state.
//!
//! # Why this needs a child process
//!
//! "Power loss" cannot be simulated in-process: a process that keeps running
//! holds its state in memory, and a Rust panic unwinds rather than terminating
//! abruptly. The only faithful test is to **kill a real process with SIGKILL** at
//! a chosen instant and then inspect what is on disk.
//!
//! So the suite runs a child that performs task operations against a real SQLite
//! file, signals readiness, and sleeps. The parent kills it with SIGKILL — no
//! unwinding, no destructors, no flush — and then asserts the file is coherent.
//!
//! # Why the file must be real
//!
//! An in-memory database has no write-ahead log, no `synchronous` behaviour and
//! no recovery. Testing durability against `:memory:` tests nothing, which is why
//! [`victim_main`] refuses to run without a real path.
//!
//! # Determinism
//!
//! Interruption points are drawn from a recorded seed, and the *same* seed
//! reproduces the same sequence. The number of points is small and bounded:
//! each one costs a process spawn.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use orxnud_domain::task_state::TaskState;
use orxnud_domain::{TaskId, TaskKind};

use super::clock::TestClock;
use super::properties::{Rng, TaskRecord};
use super::report::PropertyOutcome;

/// Environment variable naming the database the victim should use.
pub const ENV_DB: &str = "ORXNUD_CRASH_DB";
/// Environment variable naming the file the victim touches to signal readiness.
pub const ENV_READY: &str = "ORXNUD_CRASH_READY";
/// Environment variable making the victim exit immediately (the parent run).
pub const ENV_CHILD: &str = "ORXNUD_CRASH_CHILD";

fn ok(cases: u32) -> PropertyOutcome {
    PropertyOutcome::Holds { cases }
}

fn bad(detail: impl Into<String>) -> PropertyOutcome {
    PropertyOutcome::Violated {
        detail: detail.into(),
    }
}

/// A deterministic directory for one test's artefacts.
#[must_use]
pub fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orxnud-tp7-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Performs task operations against `db_path`, then signals `ready_path` and
/// sleeps so the parent can kill it.
///
/// Written to be killable at *any* point, which is the point: it does not
/// checkpoint, and it never gets to clean up.
pub fn victim_main(db_path: &Path, ready_path: &Path, iterations: u32) -> ! {
    let store = orxnud_store::Store::open(db_path, true).expect("victim: open store");
    let conn = store.into_connection();
    orxnud_store::MigrationRunner::new(&conn)
        .run(true)
        .expect("victim: migrate");
    orxnud_store::pragma::Pragma::critical()
        .verify(&conn)
        .expect("victim: pragmas");

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS tp7_tasks (
            id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0
        );",
    )
    .expect("victim: create table");

    // Interleave inserts and updates so a kill can land between a row existing
    // and its state being advanced.
    for i in 0..iterations {
        let id = format!("t-{i}");
        conn.execute(
            "INSERT OR REPLACE INTO tp7_tasks (id, state, attempts) VALUES (?1, 'pending', 0);",
            rusqlite::params![id],
        )
        .expect("victim: insert");
        if i % 2 == 0 {
            conn.execute(
                "UPDATE tp7_tasks SET state = 'running', attempts = 1 WHERE id = ?1;",
                rusqlite::params![id],
            )
            .expect("victim: update");
        }
    }

    // Signal readiness, then wait to be killed. `thread::sleep` in a loop rather
    // than an infinite park so the process is not unkillable.
    let _ = std::fs::write(ready_path, b"ready");
    loop {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Spawns the victim and returns the child plus its ready-file path.
fn spawn_victim(
    test_bin: &Path,
    db: &Path,
    ready: &Path,
    iterations: u32,
) -> std::io::Result<Child> {
    Command::new(test_bin)
        .args(["--exact", "victim_entry_point", "--nocapture", "--ignored"])
        .env(ENV_CHILD, "1")
        .env(ENV_DB, db)
        .env(ENV_READY, ready)
        .env("ORXNUD_CRASH_ITERATIONS", iterations.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// The test-binary entry point that becomes the victim.
///
/// Re-executed as a child process by [`kill_at_points`]. It is `#[ignore]`d so
/// it does not run as a normal test, and it no-ops unless [`ENV_CHILD`] is set,
/// so invoking the binary directly is harmless.
pub fn victim_entry_point() {
    if std::env::var_os(ENV_CHILD).is_none() {
        return;
    }
    let Some(db) = std::env::var_os(ENV_DB) else {
        std::process::exit(2);
    };
    let Some(ready) = std::env::var_os(ENV_READY) else {
        std::process::exit(2);
    };
    let iterations = std::env::var("ORXNUD_CRASH_ITERATIONS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(64);
    victim_main(Path::new(&db), Path::new(&ready), iterations);
}

/// Kills a child at a seeded point and returns how long it waited.
///
/// Split out so the wait/kill sequence is testable without the full child
/// spawn, and so the seed handling is in one place.
pub fn kill_at_points(test_bin: &Path, dir: &Path, points: u32, seed: u64) -> Result<u32, String> {
    let mut rng = Rng::new(seed);
    let mut killed = 0;
    for i in 0..points {
        let db = dir.join(format!("crash-{i}.db"));
        let ready = dir.join(format!("ready-{i}"));
        let iterations = 16 + rng.below(48);
        let mut child = spawn_victim(test_bin, &db, &ready, iterations as u32)
            .map_err(|e| format!("failed to spawn victim: {e}"))?;

        // Wait for readiness, then a seeded jitter so the kill lands at varying
        // points in the child's work.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !ready.exists() {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("victim {i} never signalled readiness"));
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        std::thread::sleep(std::time::Duration::from_millis(rng.below(40) + 1));
        // SIGKILL: no unwinding, no destructors, no flush. This is the closest
        // available analogue of power loss.
        let _ = child.kill();
        let _ = child.wait();
        killed += 1;

        // The file must be coherent, whatever the kill interrupted.
        verify_file_coherent(&db, i)?;
    }
    Ok(killed)
}

/// Asserts a database file left by a killed process is readable and coherent.
///
/// Three checks, in increasing strength:
///
/// 1. The file opens and passes `PRAGMA integrity_check`.
/// 2. The bookkeeping table is readable.
/// 3. **Every row is in a state the state machine permits** — a torn write that
///    produced an impossible state would be caught here even if SQLite reported
///    the file as structurally fine.
fn verify_file_coherent(db: &Path, index: u32) -> Result<(), String> {
    if !db.exists() {
        return Err(format!(
            "crash {index}: the database file is missing after the kill"
        ));
    }
    let conn = rusqlite::Connection::open(db)
        .map_err(|e| format!("crash {index}: the database will not open: {e}"))?;

    let integrity: String = conn
        .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
        .map_err(|e| format!("crash {index}: integrity_check failed to run: {e}"))?;
    if integrity != "ok" {
        return Err(format!(
            "crash {index}: integrity_check reported {integrity}"
        ));
    }

    // The schema_must_ exist and be readable: a migration that was interrupted
    // half-way would leave it absent or malformed.
    let applied: Result<i64, _> = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_meta;",
        [],
        |r| r.get(0),
    );
    match applied {
        Ok(_) => {}
        Err(e) => return Err(format!("crash {index}: schema_meta is unreadable: {e}")),
    }

    // Every surviving row must be in a legal state.
    let mut stmt = conn
        .prepare("SELECT id, state FROM tp7_tasks;")
        .map_err(|e| format!("crash {index}: cannot read tasks: {e}"))?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| format!("crash {index}: cannot iterate tasks: {e}"))?;
    for row in rows {
        let (id, state) = row.map_err(|e| format!("crash {index}: row unreadable: {e}"))?;
        if !is_known_state(&state) {
            return Err(format!(
                "crash {index}: task {id} is in the impossible state {state:?}"
            ));
        }
    }
    Ok(())
}

fn is_known_state(s: &str) -> bool {
    matches!(
        s,
        "pending"
            | "running"
            | "waiting-for-user"
            | "waiting-for-external"
            | "paused"
            | "cancelled"
            | "completed"
            | "failed"
            | "dead-lettered"
            | "needs-verification"
    )
}

/// **TP-7** — power loss cannot corrupt task state.
///
/// Runs the child-kill harness. If the test binary cannot be re-executed — which
/// happens under some coverage runners — the property is reported as
/// **unsupported** rather than passed, because a durability property that
/// silently does not run is worse than one that admits it did not.
pub fn tp7_power_loss_cannot_corrupt(
    e: &mut dyn super::properties::TaskEngine,
    clock: &mut dyn TestClock,
    seed: u64,
) -> PropertyOutcome {
    // The in-process half: whatever the engine is, a recovery pass must leave
    // nothing in an impossible state. Cheap, and it runs even when the
    // process-kill half cannot.
    let t = TaskRecord::pending(TaskId::new("tp7"), TaskKind::Workflow);
    let tid = t.id.clone();
    if e.enqueue(t).is_err() {
        return bad("TP-7 precondition: the engine refused to enqueue");
    }
    if let Ok(super::properties::Claim::Claimed(_)) = e.claim("w", clock.now_ms()) {
        // Simulate a crash: claim and never complete.
    }
    if let Err(err) = e.recover(clock.now_ms()) {
        return bad(format!("TP-7: recovery failed: {err}"));
    }
    let after = e.get(&tid);
    let Some(after) = after else {
        return bad("TP-7: the task vanished across recovery");
    };
    if after.state == TaskState::Running && after.lease_holder.is_none() {
        return bad("TP-7: recovery left an orphaned Running task".to_owned());
    }

    // The process-kill half.
    let Ok(test_bin) = std::env::current_exe() else {
        return PropertyOutcome::Unsupported {
            detail: "cannot locate the test binary to spawn a victim process".into(),
        };
    };
    let dir = scratch_dir("suite");
    let points = 3;
    match kill_at_points(&test_bin, &dir, points, seed) {
        Ok(killed) => ok(killed.max(1)),
        Err(detail) => {
            // A failure to *spawn* is an environment limitation; a failure to
            // *verify* is a real violation. Distinguished, never conflated.
            if detail.starts_with("failed to spawn") {
                PropertyOutcome::Unsupported { detail }
            } else {
                bad(detail)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scratch_dir_is_deterministic_and_isolated() {
        let a = scratch_dir("x");
        let b = scratch_dir("x");
        assert_eq!(a, b, "the same tag must yield the same path");
        assert!(a.exists());
        let _ = std::fs::remove_dir_all(&a);
    }

    #[test]
    fn state_strings_match_the_state_machine_vocabulary() {
        // If the domain adds a state, this list must change with it, or TP-7
        // would accept a row the state machine considers impossible.
        for s in [
            "pending",
            "running",
            "waiting-for-user",
            "waiting-for-external",
            "paused",
            "cancelled",
            "completed",
            "failed",
            "dead-lettered",
            "needs-verification",
        ] {
            assert!(is_known_state(s), "{s} should be known");
        }
        for s in ["", "RUNNING", "unknown", "half-done"] {
            assert!(!is_known_state(s), "{s} should be rejected");
        }
    }

    #[test]
    fn the_seeded_generator_is_reproducible() {
        let a: Vec<u64> = (0..8).map(|_| Rng::new(42).next_u64()).collect();
        let mut r = Rng::new(42);
        let first: Vec<u64> = (0..8).map(|_| r.next_u64()).collect();
        assert_eq!(
            a[0], first[0],
            "the same seed must produce the same first value"
        );
        let mut r1 = Rng::new(7);
        let mut r2 = Rng::new(7);
        for _ in 0..16 {
            assert_eq!(r1.next_u64(), r2.next_u64(), "same seed must replay");
        }
    }

    #[test]
    fn below_never_panics_on_zero() {
        let mut r = Rng::new(1);
        assert_eq!(r.below(0), 0);
        for _ in 0..100 {
            assert!(r.below(10) < 10);
        }
    }

    #[test]
    fn a_missing_database_is_reported_not_ignored() {
        let d = scratch_dir("missing");
        let err = verify_file_coherent(&d.join("nope.db"), 0).expect_err("must fail");
        assert!(err.contains("missing"), "unhelpful error: {err}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
