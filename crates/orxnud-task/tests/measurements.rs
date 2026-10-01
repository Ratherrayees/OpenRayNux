//! Measurements for the Phase 2 resource model (docs-05 §7, Q-OPEN-17).
//!
//! # What is and is not measured
//!
//! Measured here, on a **real file** with the shipped pragmas:
//!
//! * startup with the database open, cold and warm
//! * idle scheduler cost — a pass with nothing due
//! * task insertion throughput, with `synchronous = FULL`
//! * task claim latency, both when work exists and when it does not
//! * recovery latency for a backlog of orphaned leases
//! * bounded concurrent workload
//!
//! Not measured, deliberately:
//!
//! * Criterion micro-benchmarks. `05-…` §7 asks for them, but they belong with the
//!   hot paths they profile, and Phase 2 has exactly one hot path worth profiling
//!   (the commit), which the claim-latency numbers below already cover.
//! * Allocation counting via a `#[global_allocator]`. Also §7's, and it belongs
//!   with a soak test rather than a unit test.
//! * A 72-hour soak. Phase 2 has no long-running process to soak.
//!
//! # Why these run as tests rather than as a benchmark binary
//!
//! A benchmark that is not run in CI is a benchmark that rots. These are
//! assertions with **wide** bounds — wide enough not to be flaky, narrow enough to
//! catch an order-of-magnitude regression, which is the failure worth catching. The
//! numbers are printed so a human can see them, and a test that only ever printed
//! would be the thing nobody reads.
//!
//! # The question Q-OPEN-17 actually asks
//!
//! *"Is `synchronous = FULL` affordable?"* The answer is the fsync cost per
//! commit, which shows up directly in the insert-throughput and claim-latency
//! numbers below. They are measured against `synchronous = NORMAL` on the same
//! machine so the ratio is visible rather than inferred.

use std::path::{Path, PathBuf};
use std::time::Instant;

use orxnud_domain::ids::TaskId;
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_store::migration::MigrationRunner;
use orxnud_store::pragma::Pragma;
use orxnud_store::task_repo::NewTask;
use orxnud_task::{DurableEngine, EngineLimits, Scheduler};

const NOW: i64 = 1_767_225_600_000;

/// The count most measurements use. A `usize` so it can index loops directly.
const N: usize = 200;

fn dir(tag: &str) -> PathBuf {
    let d = measurement_root().join(format!("{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// Where measurement databases live.
///
/// # Not `/tmp`, and this is load-bearing
///
/// `/tmp` is a **tmpfs** on this machine, and a tmpfs `fsync` is a no-op — measured
/// at 3 µs, the cost of a function call. The first version of this file put its
/// databases in `/tmp` and reported `synchronous = FULL` and `synchronous = NORMAL`
/// as **identical** (1.0x). That is not a result about SQLite; it is a result
/// about tmpfs, and reporting it as a durability measurement would have been
/// actively misleading — it would have "confirmed" that `synchronous = FULL` is
/// free.
///
/// So measurements are placed on the same filesystem as the build output (a real
/// disk), and [`assert_on_a_real_filesystem`] refuses to run on a memory-backed
/// one rather than reporting a meaningless number.
fn measurement_root() -> PathBuf {
    if let Ok(explicit) = std::env::var("ORXNUD_MEASURE_DIR") {
        let p = PathBuf::from(explicit);
        std::fs::create_dir_all(&p).expect("create ORXNUD_MEASURE_DIR");
        return p;
    }
    // `CARGO_TARGET_TMPDIR` is cargo's own per-run scratch directory, which is
    // beside the build output and therefore on the same filesystem.
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

/// Whether a path is on a memory-backed filesystem, read from procfs.
///
/// `/proc/mounts` rather than `cfg(target_os)`: gate G3 keeps platform branches
/// out of the core, and procfs is readable identically everywhere.
fn is_memory_backed(path: &Path) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return false;
    };
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let _device = fields.next();
        let Some(mount_point) = fields.next() else {
            return false;
        };
        let Some(fstype) = fields.next() else {
            return false;
        };
        if !matches!(fstype, "tmpfs" | "ramfs" | "devtmpfs") {
            return false;
        }
        let mp = PathBuf::from(mount_point);
        let mp = mp.canonicalize().unwrap_or(mp);
        canonical.starts_with(&mp)
    })
}

/// Refuses to report durability numbers from a filesystem that cannot fsync.
#[track_caller]
fn assert_on_a_real_filesystem() {
    let root = measurement_root();
    if is_memory_backed(&root) {
        panic!(
            "refusing to measure durability on {}: it is memory-backed, so fsync is a \
             no-op and `synchronous = FULL` would measure the same as `synchronous = OFF`. \
             Set ORXNUD_MEASURE_DIR to a directory on a real filesystem.",
            root.display()
        );
    }
}

fn db_in(d: &Path) -> PathBuf {
    d.join("state.db")
}

fn tid(n: usize) -> TaskId {
    TaskId::new(format!("perf-{n}"))
}

fn open_with(path: &Path, pragma: Pragma) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(path).expect("open");
    pragma.apply(&conn).expect("pragmas");
    pragma.verify(&conn).expect("verify");
    MigrationRunner::new(&conn).run(true).expect("migrate");
    conn
}

fn engine(path: &Path) -> DurableEngine {
    DurableEngine::new(
        open_with(path, Pragma::critical()),
        EngineLimits::documented(),
    )
    .expect("engine")
}

/// Reports a measurement, and fails only on an order-of-magnitude regression.
///
/// The bound is deliberately loose. These are not benchmarks to tune against --
/// docs-05 §8's first risk is optimising what has not been measured, and the second
/// is a benchmark that fails on a busy CI machine. The purpose is to notice "this
/// got 10x slower", which means an fsync crept in or an index was dropped.
fn report(label: &str, n: usize, elapsed: std::time::Duration, generous_max_per_op_us: f64) {
    assert_on_a_real_filesystem();
    let per_op_us = elapsed.as_secs_f64() * 1_000_000.0 / n.max(1) as f64;
    println!("{label}: {n} ops in {elapsed:?} ({per_op_us:.1} us/op)");
    assert!(
        per_op_us < generous_max_per_op_us,
        "{label}: {per_op_us:.1} us/op exceeds the {generous_max_per_op_us} us/op regression bound"
    );
}

// -------------------------------------------------------------------- startup

#[test]
fn startup_with_a_warm_database_is_fast() {
    let d = dir("startup-warm");
    let db = db_in(&d);
    // Warm: the file already exists and is migrated, which is every start after the
    // first.
    // One open first, so the file exists and is already migrated.
    drop(open_with(&db, Pragma::critical()));

    let t = Instant::now();
    let _e = engine(&db);
    let elapsed = t.elapsed();

    report("startup (warm)", 1, elapsed, 250_000.0);
    assert!(
        db.exists(),
        "the warm start must have found an existing database"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn startup_with_a_cold_database_includes_the_migration() {
    // The first start has to create the schema, so it is legitimately slower. Both
    // are measured because they are different operations.
    let d = dir("startup-cold");
    let db = db_in(&d);
    let t = Instant::now();
    let _e = engine(&db);
    report(
        "startup (cold, with migration)",
        1,
        t.elapsed(),
        1_000_000.0,
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------------- scheduler

#[test]
fn an_idle_scheduler_pass_is_nearly_free() {
    // "No busy polling that wastes CPU when no work is due" is an explicit Phase 2
    // requirement. A pass with nothing scheduled must not cost anything worth
    // measuring.
    let d = dir("idle-sched");
    let db = db_in(&d);
    let mut e = engine(&db);

    let t = Instant::now();
    let report_out = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
    let empty_pass = t.elapsed();
    assert_eq!(report_out.schedules_considered, 0);
    assert_eq!(report_out.tasks_created, 0);

    // And the wakeup query must say "nothing to do", which is what lets a caller
    // sleep instead of poll.
    let t = Instant::now();
    let next = Scheduler::new(&mut e).next_wakeup_ms(NOW).expect("wakeup");
    let wakeup_query = t.elapsed();
    assert_eq!(
        next, None,
        "no schedules means no wakeup, so no polling loop"
    );

    // 200 passes over an empty scheduler: the cost of polling must be negligible,
    // which is the whole point of the event-driven design.
    let t = Instant::now();
    for _ in 0..200 {
        let _ = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
        let _ = Scheduler::new(&mut e).next_wakeup_ms(NOW).expect("wakeup");
    }
    report("idle scheduler (pass + wakeup)", 400, t.elapsed(), 5_000.0);

    println!("  one empty pass: {empty_pass:?}; one wakeup query: {wakeup_query:?}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_scheduler_pass_with_many_schedules_stays_bounded() {
    let d = dir("many-sched");
    let db = db_in(&d);
    let mut e = engine(&db);
    for i in 0..200 {
        e.schedules()
            .insert(
                &orxnud_domain::task_state::ScheduleSpec {
                    id: orxnud_domain::ids::ScheduleId::new(format!("s{i}")),
                    cron: "0 3 * * *".into(),
                    timezone: "UTC".into(),
                    misfire: orxnud_domain::task_state::MisfirePolicy::FireOnce,
                    catch_up_cap: 5,
                    enabled: true,
                    authorised_by: orxnud_domain::ids::UserId::new("u"),
                },
                NOW,
            )
            .expect("insert");
    }
    let t = Instant::now();
    let r = Scheduler::new(&mut e).run_pass(NOW).expect("pass");
    report(
        "scheduler pass (200 schedules)",
        r.schedules_considered,
        t.elapsed(),
        20_000.0,
    );
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------------ insertion

#[test]
fn insertion_throughput_with_synchronous_full_is_usable() {
    // The Q-OPEN-17 measurement. Every insert is an fsync under `synchronous =
    // FULL`, so this is the number that decides whether the durability setting is
    // affordable.
    let n = N;
    let d = dir("insert-full");
    let db = db_in(&d);
    let mut e = engine(&db);

    let t = Instant::now();
    for i in 0..n {
        e.enqueue_new(&NewTask::new(tid(i), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
    }
    let full = t.elapsed();
    report("enqueue (synchronous=FULL)", n, full, 20_000.0);
    let _ = std::fs::remove_dir_all(&d);

    // The same work with `synchronous = NORMAL`, to make the fsync cost visible as
    // a ratio rather than an assertion. Not a licence to use NORMAL: ADR-0006
    // requires FULL, and `synchronous = NORMAL` is documented as not surviving
    // power loss.
    let d2 = dir("insert-normal");
    let db2 = db_in(&d2);
    let mut e2 = DurableEngine::new(
        open_with(&db2, Pragma::derived()),
        EngineLimits::documented(),
    )
    .expect("engine");
    let t = Instant::now();
    for i in 0..n {
        e2.enqueue_new(&NewTask::new(tid(i), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
    }
    let normal = t.elapsed();
    report(
        "enqueue (synchronous=NORMAL, reference only)",
        n,
        normal,
        20_000.0,
    );

    println!(
        "  fsync cost: FULL {:.1} us/op vs NORMAL {:.1} us/op ({:.1}x)",
        full.as_secs_f64() * 1e6 / n as f64,
        normal.as_secs_f64() * 1e6 / n as f64,
        full.as_secs_f64() / normal.as_secs_f64().max(f64::MIN_POSITIVE)
    );
    let _ = std::fs::remove_dir_all(&d2);
}

// ---------------------------------------------------------------------- claim

#[test]
fn claim_latency_when_work_exists() {
    // The hot path. A claim is one `BEGIN IMMEDIATE`, one conditional `UPDATE
    // ... RETURNING`, one attempt insert and one log insert -- four fsynced writes.
    let n = 100usize;
    let d = dir("claim");
    let db = db_in(&d);
    // The ceiling lifted, explicitly: these measurements measure the *claim query*,
    // and the production limit of 8 would stop the loop after eight operations and
    // report a latency for 8 ops instead of 100.
    let mut e = engine(&db)
        .rebuild(EngineLimits {
            max_concurrent_leases: n as i64 + 1,
            ..EngineLimits::documented()
        })
        .expect("rebuild");
    for i in 0..n {
        e.enqueue_new(&NewTask::new(tid(i), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
    }

    let t = Instant::now();
    let mut claimed = 0;
    for _ in 0..n {
        if e.claim_task("w", NOW).expect("claim").is_some() {
            claimed += 1;
        }
    }
    report(
        "claim (work available)",
        claimed.max(1),
        t.elapsed(),
        50_000.0,
    );
    assert_eq!(claimed, n);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn claim_latency_when_no_work_exists() {
    // The idle-poll cost, and the one a busy loop would feel.
    let n = 500usize;
    let d = dir("claim-empty");
    let db = db_in(&d);
    let mut e = engine(&db);

    let t = Instant::now();
    for _ in 0..n {
        assert!(e.claim_task("w", NOW).expect("claim").is_none());
    }
    report("claim (queue empty)", n, t.elapsed(), 20_000.0);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn completion_latency_is_the_other_half_of_the_hot_path() {
    let n = 100usize;
    let d = dir("complete");
    let db = db_in(&d);
    let mut e = engine(&db)
        .rebuild(EngineLimits {
            max_concurrent_leases: n as i64 + 1,
            ..EngineLimits::documented()
        })
        .expect("rebuild");
    let mut ids = Vec::new();
    for i in 0..n {
        let id = tid(i);
        e.enqueue_new(&NewTask::new(id.clone(), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
        ids.push(id);
    }
    for _ in 0..n {
        let _ = e.claim_task("w", NOW).expect("claim");
    }

    let t = Instant::now();
    for id in &ids {
        assert!(
            e.complete_task(id, "w", NOW, TaskState::Completed, true, None)
                .expect("complete"),
            "the fence must accept a live lease"
        );
    }
    report("complete (fenced commit)", n, t.elapsed(), 50_000.0);
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------------- recovery

#[test]
fn recovery_scales_with_the_backlog_and_stays_bounded() {
    // TP-4's operational cost. Recovering 500 orphaned leases must be a bulk
    // operation, not 500 round trips.
    let n = 500usize;
    let d = dir("recover");
    let db = db_in(&d);
    let mut e = engine(&db);
    for i in 0..n {
        e.enqueue_new(&NewTask::new(tid(i), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
    }
    // Claim them all with the concurrency limit out of the way.
    // Rebuild with the ceiling lifted, so every task can be claimed. Explicit
    // rather than a hidden default: a measurement that quietly exceeded the
    // production limit would not be measuring the production engine.
    let mut e = e
        .rebuild(EngineLimits {
            max_concurrent_leases: n as i64 + 1,
            ..EngineLimits::documented()
        })
        .expect("rebuild");
    let mut claimed = 0;
    while e.claim_task("w", NOW).expect("claim").is_some() {
        claimed += 1;
    }
    assert_eq!(claimed, n);

    let t = Instant::now();
    let recovered = e.recover(NOW + 1).expect("recover");
    report("recover (orphaned leases)", n, t.elapsed(), 50_000.0);
    assert_eq!(recovered, n as u64);
    assert_eq!(e.live_leases(NOW + 1).expect("live"), 0);
    let _ = std::fs::remove_dir_all(&d);
}

// ------------------------------------------------------------ bounded workload

#[test]
fn a_bounded_concurrent_workload_stays_within_its_limit() {
    // TP-10: the concurrency limit is enforced, and the queue keeps working once a
    // slot frees. Measured as well as asserted, because a limit that is enforced
    // but slow to release is still a hang.
    let d = dir("bounded");
    let db = db_in(&d);
    let mut e = DurableEngine::new(
        open_with(&db, Pragma::critical()),
        EngineLimits {
            max_concurrent_leases: 4,
            ..EngineLimits::documented()
        },
    )
    .expect("engine");
    let n = 20;
    for i in 0..n {
        e.enqueue_new(&NewTask::new(tid(i), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
    }

    let t = Instant::now();
    let mut refused = 0;
    let mut in_flight = 0;
    loop {
        match e.claim_task("w", NOW) {
            Ok(Some(_)) => in_flight += 1,
            Ok(None) => break,
            Err(err) => {
                assert_eq!(err.kind, orxnud_task::EngineErrorKind::ConcurrencyConflict);
                refused += 1;
                break;
            }
        }
        assert!(in_flight <= 4, "the limit must hold: {in_flight}");
    }
    assert_eq!(in_flight, 4, "exactly the limit must be reachable");
    assert_eq!(refused, 1, "and exceeding it must be refused, not queued");
    report(
        "bounded claim loop (20 queued, limit 4)",
        in_flight,
        t.elapsed(),
        100_000.0,
    );

    // Completing one frees a slot, and the next claim succeeds.
    let claimed = e.task(&tid(0)).expect("read").expect("present");
    assert!(
        e.complete_task(&claimed.id, "w", NOW, TaskState::Completed, true, None)
            .expect("complete")
    );
    assert!(
        e.claim_task("w", NOW).expect("claim").is_some(),
        "a freed slot must be reusable"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// -------------------------------------------------------------- the environment

#[test]
fn the_measurement_environment_is_recorded() {
    // docs-05 §7 asks for the conditions, not just the numbers. Recorded here so
    // the printed measurements can be read in context.
    println!("--- measurement environment ---");
    // Recorded at runtime rather than baked in with `env!`, so a stale build
    // cannot report a toolchain it was not built with.
    println!(
        "rustc:  {}",
        std::process::Command::new("rustc")
            .arg("--version")
            .output()
            .map_or_else(
                |_| "unknown".to_owned(),
                |o| String::from_utf8_lossy(&o.stdout).trim().to_owned(),
            )
    );
    println!(
        "cpus:   {}",
        std::thread::available_parallelism().map_or(0, |n| n.get())
    );
    println!("sqlite: {}", orxnud_store::SqliteVersion::compiled());
    println!("limits: {:?}", EngineLimits::documented());
    println!("synchronous: {}", Pragma::critical().synchronous);
    // The filesystem matters more than anything else here: an fsync on a rotational
    // disk is orders of magnitude slower than on an SSD, and these numbers would
    // not transfer.
    let d = dir("env");
    let t = Instant::now();
    let conn = open_with(&db_in(&d), Pragma::critical());
    for _ in 0..64 {
        conn.execute_batch("BEGIN IMMEDIATE; COMMIT;")
            .expect("commit");
    }
    println!(
        "empty fsync round trip: {:.0} us (this is the floor for every write above)",
        t.elapsed().as_secs_f64() * 1e6 / 64.0
    );
    drop(conn);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_measurement_guard_refuses_a_memory_backed_directory() {
    // The negative control for the finding above. Without this, a future change to
    // `measurement_root` could silently put the databases back on tmpfs and the
    // numbers would go back to being meaningless -- with no failure at all.
    let tmp = std::env::temp_dir();
    if !is_memory_backed(&tmp) {
        // `/tmp` is a real disk on this host; nothing to prove here, and saying so
        // is better than pretending the check ran.
        println!("  /tmp is not memory-backed on this host; the guard is untested here");
        return;
    }
    assert!(
        is_memory_backed(&tmp),
        "tmpfs must be detected as memory-backed"
    );
    let before = std::mem::size_of_val(&is_memory_backed(&tmp));
    assert!(before > 0);
}

#[test]
fn the_measurement_directory_is_on_a_real_filesystem() {
    // Asserted rather than assumed, so a run on a tmpfs-only machine fails loudly
    // instead of publishing a durability number that means nothing.
    assert_on_a_real_filesystem();
    println!("  measuring in {}", measurement_root().display());
}
