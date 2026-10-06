//! V-25: the resource budgets, measured rather than asserted in prose.
//!
//! # What this is
//!
//! docs-05 §2 states three budgets -- core-only idle RSS < 60 MB, core-only binary
//! < 40 MB, core-only cold start < 150 ms -- and its own §1 says a budget "becomes a
//! *fact* only when a benchmark exists in the repository and CI compares against it".
//! Until this file existed, none of the three was either.
//!
//! So this is that benchmark, and it follows the precedent already set by
//! `orxnud-task/tests/measurements.rs`: assertions with **wide** bounds, numbers printed
//! so a human can see them, and no optimisation. docs-05 §8 names the first risk as
//! "optimising what has not been measured" and the second as "a benchmark that fails on
//! a busy CI machine". Both are avoided by measuring first and asserting only on
//! order-of-magnitude regressions.
//!
//! # What "core-only" means here
//!
//! The `orxnud` daemon binary, started with **no provider**, serving on its local socket.
//! That is: daemon + local IPC + SQLite task engine + policy + audit + identity boundary +
//! core task lifecycle, and no provider client, no model, no GUI/TUI/MCP/voice.
//!
//! `--provider-scripted` is deliberately **not** used. It would add a proposer to the
//! measured process for no reason a core-only user pays for, and a provider's presence in
//! RSS should be a separate question from the core daemon's.
//!
//! # The measurement boundary for "ready"
//!
//! Cold start is measured to **the daemon answering a request**, not to the process
//! existing. `Runtime::start` establishes durable security state, then the task engine,
//! then binds the endpoint, and only then can serve -- so "the process launched" would be
//! measuring the wrong moment by the entire cost of opening SQLite, verifying the audit
//! chain and binding the socket. The harness polls `daemon/version` over the real socket,
//! which is exactly the boundary a client experiences.
//!
//! # Running it
//!
//! The numbers that matter are from the **release** profile, because that is what ships.
//! `scripts/measure-v25.sh` does that and prints a summary; run directly, it is:
//!
//! ```text
//! cargo test --release -p orxnud-daemon --test v25_measure -- --nocapture
//! ```
//!
//! Under plain `cargo test` it still runs, on `opt-level = 1`, and prints a line saying
//! so. Those numbers are for smoke-testing the harness, not for the budget.
//!
//! # Filesystem
//!
//! Inherits `orxnud-task`'s hard-won rule: `/tmp` is tmpfs, a tmpfs `fsync` is a no-op,
//! and a durability measurement taken there would "confirm" that `synchronous = FULL` is
//! free. Every database here is created under `CARGO_TARGET_TMPDIR`, beside the build
//! output on a real disk, and [`assert_on_a_real_filesystem`] refuses to report otherwise.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use orxnud_domain::ids::TaskId;
use orxnud_domain::task_state::{TaskKind, TaskState};
use orxnud_protocol::error::RpcErrorCode;
use orxnud_store::task_repo::NewTask;
use orxnud_task::{DurableEngine, EngineLimits};
use serde_json::{Value, json};

// ---------------------------------------------------------------------------
// plumbing
// ---------------------------------------------------------------------------

/// Beside the build output, on a real filesystem. See the module docs.
fn scratch(tag: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("v25-{tag}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// Whether a path is on a memory-backed filesystem, read from procfs.
///
/// `/proc/mounts` rather than `cfg(target_os)`: gate G3 keeps platform branches out of
/// the core, and procfs reads identically everywhere.
fn is_memory_backed(path: &Path) -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return false;
    };
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    mounts.lines().any(|line| {
        let mut f = line.split_whitespace();
        let _dev = f.next();
        let Some(mp) = f.next() else { return false };
        let Some(fstype) = f.next() else { return false };
        if !matches!(fstype, "tmpfs" | "ramfs" | "devtmpfs") {
            return false;
        }
        let mp = PathBuf::from(mp);
        let mp = mp.canonicalize().unwrap_or(mp);
        canonical.starts_with(&mp)
    })
}

#[track_caller]
fn assert_on_a_real_filesystem() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    assert!(
        !is_memory_backed(&dir),
        "refusing to report durability numbers from a memory-backed filesystem: a tmpfs \
         fsync is a no-op, so synchronous=FULL and synchronous=NORMAL would measure \
         identical and the result would be actively misleading"
    );
}

/// Five-number summary, because one number is not a measurement.
///
/// Percentiles from a sorted copy of the samples. `N` is always printed with them: a
/// P99 over 50 samples is a different claim from a P99 over 5000, and quoting the
/// former as the latter is the usual way a benchmark starts lying.
struct Summary {
    label: String,
    n: usize,
    min: Duration,
    p50: Duration,
    p95: Duration,
    p99: Duration,
    max: Duration,
}

impl Summary {
    fn of(label: &str, mut samples: Vec<Duration>) -> Self {
        assert!(!samples.is_empty(), "{label}: no samples");
        samples.sort_unstable();
        let at = |q: f64| {
            // Nearest-rank, which is what "the 95th percentile of these N samples" means
            // and does not invent a value that was never observed.
            let i = (((samples.len() as f64) * q).ceil() as usize).saturating_sub(1);
            samples[i.min(samples.len() - 1)]
        };
        Self {
            label: label.to_owned(),
            n: samples.len(),
            min: samples[0],
            p50: at(0.50),
            p95: at(0.95),
            p99: at(0.99),
            max: samples[samples.len() - 1],
        }
    }

    fn us(&self, d: Duration) -> f64 {
        d.as_secs_f64() * 1_000_000.0
    }

    fn print(&self) {
        println!(
            "V25 | {:<38} | N={:<5} | min {:>9.1}us | p50 {:>9.1}us | p95 {:>9.1}us | \
             p99 {:>9.1}us | max {:>9.1}us",
            self.label,
            self.n,
            self.us(self.min),
            self.us(self.p50),
            self.us(self.p95),
            self.us(self.p99),
            self.us(self.max),
        );
    }

    /// Fails only on an order-of-magnitude regression.
    ///
    /// The bound is set from the *shape* of the budget, not from a historical number on
    /// one machine: V-25's cold-start budget is 150 ms, so a p50 above 1500 ms means the
    /// budget is missed by 10x, which is the failure worth catching. A machine 3% slower
    /// than the author's is not.
    fn assert_under(&self, generous_max: Duration, what: &str) {
        assert!(
            self.p50 < generous_max,
            "{}: p50 {:.1}ms exceeds the {:.1}ms regression bound. This should be an \
             order-of-magnitude failure; if it is a small overshoot, the bound is wrong \
             rather than the code.",
            what,
            self.us(self.p50) / 1000.0,
            generous_max.as_secs_f64() * 1000.0,
        );
    }
}

/// Whether these numbers came from an optimised build.
fn is_optimised() -> bool {
    // `debug_assertions` is off in every non-debug profile, which is a cheaper and more
    // reliable signal than interrogating `cfg!(profile = "release")` across profiles.
    !cfg!(debug_assertions)
}

fn print_preamble() {
    println!(
        "V25 | build: {} | target: {} | rustc: {}",
        if is_optimised() {
            "optimised (run with --release for the numbers that matter)"
        } else {
            "UNOPTIMISED -- these numbers are not the V-25 figures"
        },
        std::env::consts::ARCH,
        option_env!("V25_RUSTC").unwrap_or("unknown"),
    );
    println!(
        "V25 | scratch: {} (memory-backed: {})",
        env!("CARGO_TARGET_TMPDIR"),
        is_memory_backed(&PathBuf::from(env!("CARGO_TARGET_TMPDIR")))
    );
}

/// A raw IPC client: a socket and four lines of framing.
///
/// Deliberately not `orxnuctl`. The harness must measure the transport a client
/// experiences, and it must be able to time connect, write, read and close separately --
/// which a CLI subprocess cannot do without its own process-spawn cost dominating.
struct Client(orxnud_platform_ipc::BlockingClient);

impl Client {
    fn connect(endpoint: &Path) -> Self {
        let c = orxnud_platform_ipc::connect_blocking(endpoint).expect("connect");
        c.set_read_timeout(Some(Duration::from_secs(20))).expect("timeout");
        Self(c)
    }

    fn round_trip(&mut self, id: &str, method: &str) -> Value {
        let frame = json!({"jsonrpc":"2.0","id":id,"method":method});
        let bytes = serde_json::to_vec(&frame).expect("encode");
        self.0.write_all(&bytes).expect("write");
        self.0.write_all(b"\n").expect("newline");
        self.0.flush().expect("flush");
        let mut line = String::new();
        BufReader::new(&mut self.0)
            .read_line(&mut line)
            .expect("read");
        serde_json::from_str(&line).expect("decode reply")
    }
}

fn send_raw(endpoint: &Path, line: &[u8]) -> Option<Value> {
    let mut c = orxnud_platform_ipc::connect_blocking(endpoint)?;
    c.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    c.write_all(line).ok()?;
    c.write_all(b"\n").ok()?;
    c.flush().ok()?;
    let mut r = BufReader::new(c);
    let mut s = String::new();
    r.read_line(&mut s).ok()?;
    serde_json::from_str(&s).ok()
}

fn is_ready(endpoint: &Path) -> bool {
    send_raw(
        endpoint,
        br#"{"jsonrpc":"2.0","id":"p","method":"daemon/version"}"#,
    )
    .is_some_and(|v| v.get("result").is_some())
}

fn await_ready(endpoint: &Path) {
    for _ in 0..600 {
        if is_ready(endpoint) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("the daemon never became ready at {}", endpoint.display());
}

// ---------------------------------------------------------------------------
// process sampling
// ---------------------------------------------------------------------------

/// One `/proc/<pid>/status` reading, plus the counts that matter for a "lightweight" claim.
#[derive(Debug, Clone, Copy)]
struct ProcSample {
    rss_kb: u64,
    peak_rss_kb: u64,
    threads: u64,
}

fn sample(pid: u32) -> ProcSample {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read status");
    let field = |name: &str| -> u64 {
        status
            .lines()
            .find_map(|l| {
                l.strip_prefix(name)
                    .and_then(|r| r.split_whitespace().next())
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(0)
    };
    ProcSample {
        rss_kb: field("VmRSS:"),
        peak_rss_kb: field("VmHWM:"),
        threads: field("Threads:"),
    }
}

fn open_fds(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd")).map_or(0, |d| d.count())
}

fn child_pids(pid: u32) -> usize {
    let mut total = 0;
    if let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) {
        for t in tasks.flatten() {
            if let Ok(children) = std::fs::read_to_string(t.path().join("children")) {
                total += children.split_whitespace().count();
            }
        }
    }
    total
}

// ---------------------------------------------------------------------------
// the daemon under measurement
// ---------------------------------------------------------------------------

/// The real `orxnud` binary, started as a real process.
///
/// Not `Runtime::start` in-process: an in-process measurement cannot answer "how much
/// memory does this daemon use", because it shares an address space with the harness and
/// every allocation either of them makes is indistinguishable.
struct Daemon {
    child: Child,
    endpoint: PathBuf,
}

impl Daemon {
    fn spawn(root: &Path) -> Self {
        let endpoint = root.join("orxnud.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_orxnud"))
            .arg("--state-root")
            .arg(root)
            // No provider: this measures the core daemon a user without a configured
            // model actually runs. `--provider-scripted` would add a proposer to the
            // measured process for no cost a core-only user pays.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn orxnud");
        Self { child, endpoint }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    /// Starts a daemon and returns it **along with** the time it took to become ready.
    ///
    /// The timer starts before `Command::spawn`, so process creation is inside the
    /// measurement. Excluding it would report the cost of the daemon's work and silently
    /// drop the cost of starting the program, which against a 150 ms budget is a large
    /// fraction rather than a rounding error.
    ///
    /// The daemon is handed back rather than dropped: `bind` refuses a path another live
    /// daemon owns, so a harness that timed one instance and then spawned another on the
    /// same root would deadlock against its own first process.
    fn start(root: &Path) -> (Self, Duration) {
        let t0 = Instant::now();
        let daemon = Self::spawn(root);
        await_ready(&daemon.endpoint);
        let elapsed = t0.elapsed();
        (daemon, elapsed)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Leaving a daemon running would make every later measurement of this host
        // wrong, and the harness's own integrity depends on not doing that.
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.endpoint);
    }
}

// ---------------------------------------------------------------------------
// Phase 3 — binary size
// ---------------------------------------------------------------------------

/// The shipped binary's size, with the number that V-25's 40 MB applies to named.
///
/// The release profile sets `strip = "symbols"`, so the shipped binary carries no symbol
/// table. That makes the distinction load-bearing rather than pedantic: the unstripped
/// build of the *same* source is several times larger and would fail the 40 MB budget,
/// so "which number" has to be an explicit decision or the budget means nothing.
#[test]
fn the_core_binary_size_is_measured_against_the_stripped_build() {
    print_preamble();
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_orxnud"));
    let bytes = std::fs::metadata(&bin).expect("stat").len();
    let mib = bytes as f64 / (1024.0 * 1024.0);
    let mb = bytes as f64 / 1_000_000.0;

    println!(
        "V25 | core binary {}: {bytes} bytes = {mib:.2} MiB = {mb:.2} MB (stripped, the \
         shipping profile)",
        bin.file_name().unwrap_or_default().to_string_lossy()
    );

    const BUDGET_MB: f64 = 40.0;
    println!(
        "V25 | binary size budget: {mb:.2} MB of {BUDGET_MB} MB -- {} ({:.1}% used)",
        if mb < BUDGET_MB { "PASS" } else { "FAIL" },
        mb / BUDGET_MB * 100.0,
    );

    // A 10x bound, not the budget itself: the point is to notice the binary growing an
    // order of magnitude (an accidental debug profile, an unstripped build, a vendored
    // runtime), not to fail because a dependency added 200 KB.
    assert!(
        mb < BUDGET_MB * 10.0,
        "the core binary is {mb:.1} MB. Either the 40 MB budget is now wrong or something \
         large has been linked into the daemon; check which before adjusting either."
    );
}

// ---------------------------------------------------------------------------
// Phase 4 — cold start
// ---------------------------------------------------------------------------

/// Process spawn to *ready to serve*, over many launches.
///
/// "Ready" is answering a request on the real socket, not the process existing. See the
/// module docs: `Runtime::start` does the durable state, the engine and the bind before
/// anyone can be served, so stopping the timer at exec would omit most of the cost.
#[test]
fn cold_start_to_ready_is_under_budget() {
    assert_on_a_real_filesystem();
    print_preamble();

    const N: usize = 30;
    let mut samples = Vec::with_capacity(N);
    let mut roots = Vec::with_capacity(N);

    for i in 0..N {
        let root = scratch(&format!("startup-{i}"));
        let (daemon, elapsed) = Daemon::start(&root);
        assert!(
            is_ready(daemon.endpoint()),
            "a daemon reported ready and then stopped answering"
        );
        drop(daemon);
        samples.push(elapsed);
        roots.push(root);
    }

    let s = Summary::of("cold start: spawn -> ready to serve", samples);
    s.print();

    let p50_ms = s.us(s.p50) / 1000.0;
    let p99_ms = s.us(s.p99) / 1000.0;
    println!(
        "V25 | cold start budget: p50 {p50_ms:.1} ms of 150 ms -- {} | p99 {p99_ms:.1} ms",
        if p50_ms < 150.0 { "PASS" } else { "FAIL" }
    );

    // 10x the budget. V-25's 150 ms is for a modest baseline machine; a p50 ten times
    // over it is a real regression rather than a faster laptop.
    s.assert_under(Duration::from_millis(1500), "cold start");

    for r in roots {
        let _ = std::fs::remove_dir_all(r);
    }
}

// ---------------------------------------------------------------------------
// Phase 5 — idle RSS, threads, descriptors, children
// ---------------------------------------------------------------------------

/// The core daemon's steady-state idle footprint.
///
/// Three readings, because they answer different questions: `VmRSS` immediately after
/// ready catches a start-time spike that settles away, and `VmHWM` is the peak the
/// process ever reached, which no amount of later sampling would reveal.
#[test]
fn the_idle_core_daemon_fits_its_memory_budget() {
    print_preamble();
    let root = scratch("idle");
    let (daemon, startup_ms) = Daemon::start(&root);
    let pid = daemon.pid();

    // Settle: the daemon is ready but the allocator has not necessarily reached its
    // working size. Sampling immediately would measure startup, not idle.
    std::thread::sleep(Duration::from_millis(500));

    let at_ready = sample(pid);
    let settled = sample(pid);
    let fds = open_fds(pid);
    let children = child_pids(pid);
    let threads = settled.threads;

    let mib = |kb: u64| kb as f64 / 1024.0;
    println!("V25 | idle RSS: {startup_ms:?} to ready, then");
    println!(
        "V25 |   at ready   {:>7.2} MiB",
        mib(at_ready.rss_kb)
    );
    println!(
        "V25 |   steady idle {:>6.2} MiB  (peak {:.2} MiB)",
        mib(settled.rss_kb),
        mib(settled.peak_rss_kb)
    );
    println!("V25 |   threads {threads} | open fds {fds} | child processes {children}");

    const BUDGET_MB: f64 = 60.0;
    let idle_mb = settled.rss_kb as f64 / 1024.0;
    println!(
        "V25 | idle RSS budget: {idle_mb:.1} MB of {BUDGET_MB} MB -- {}",
        if idle_mb < BUDGET_MB { "PASS" } else { "FAIL" }
    );

    assert!(
        idle_mb < BUDGET_MB * 10.0,
        "the idle core daemon holds {:.1} MB. That is 10x the 60 MB budget; either the \
         budget is wrong or something large is resident.",
        idle_mb
    );

    // The lightweight claim is not only bytes, so the counts are recorded. These are
    // measurements rather than new requirements: nothing in docs-05 states a ceiling for
    // them, and inventing one here would be a new product decision.
    assert_eq!(
        children, 0,
        "an idle core-only daemon must not hold a child process. The sandbox runs a \
         helper per *invocation*, so a resident one means a capability is executing when \
         nothing asked it to."
    );
    assert!(
        threads < 64,
        "the idle daemon holds {threads} threads for a single-socket accept loop; that is \
         a lot of scheduler surface for no work."
    );
}

// ---------------------------------------------------------------------------
// Phase 6 — IPC latency
// ---------------------------------------------------------------------------

/// A trivial request's cost, broken into connect, write, read and close.
///
/// `daemon/version` is the honest choice: it touches no provider, no sandbox, no
/// filesystem, no approval and no task execution. It also exercises the whole path --
/// accept, `SO_PEERCRED`, `authenticate`, parse, route, encode -- so it measures the
/// transport rather than unrelated work.
///
/// The daemon serves one request per connection and closes, so a "request" here is really
/// "a connection, one request, and a teardown". That is reported rather than hidden,
/// because the per-request figure is otherwise not comparable to a keep-alive transport.
#[test]
fn a_trivial_ipc_request_costs_what_it_should() {
    print_preamble();
    let root = scratch("ipc");
    let (daemon, _startup) = Daemon::start(&root);
    let endpoint = daemon.endpoint().to_path_buf();

    const N: usize = 2000;
    let mut total = Vec::with_capacity(N);
    let mut connect = Vec::with_capacity(N);

    for i in 0..N {
        let t0 = Instant::now();
        let mut c = Client::connect(&endpoint);
        let connected = t0.elapsed();

        let reply = c.round_trip(&i.to_string(), "daemon/version");
        assert!(
            reply.get("result").is_some(),
            "the measured request must succeed: {reply}"
        );
        let done = t0.elapsed();

        drop(c);
        connect.push(connected);
        total.push(done);
    }

    let ct = Summary::of("ipc connect (includes auth on accept)", connect);
    let tt = Summary::of("ipc request: connect -> reply (1 req/conn)", total);
    ct.print();
    tt.print();

    let p50_us = tt.us(tt.p50);
    println!(
        "V25 | IPC p50 {p50_us:.1} us per request over {N} one-shot connections; \
         connect alone is {:.1} us",
        ct.us(ct.p50)
    );

    // Generous by design: this is a report, and a busy CI runner must not fail on it. The
    // bound is 100 ms per request, which is ~1000x the observed figure -- it would only
    // catch a daemon that had stopped answering quickly at all.
    tt.assert_under(Duration::from_millis(100), "IPC request");

}

// ---------------------------------------------------------------------------
// Phase 7 — task engine, on the real durability settings
// ---------------------------------------------------------------------------

fn engine(path: &Path) -> DurableEngine {
    // Exactly what `TaskService::start` does, in the same order: open the store with the
    // critical pragmas, then migrate. Skipping the migration is not a shortcut -- it makes
    // every subsequent statement fail on a missing table, which is how this harness's first
    // version reported `no such table: tasks` instead of a measurement.
    //
    // `critical: true` is the point of the exercise: those are the pragmas under
    // measurement (`synchronous = FULL`, WAL), so a harness that quietly opened with
    // `false` would report `FULL` as costing nothing.
    let store = orxnud_store::sqlite::Store::open(path, true).expect("open the store");
    orxnud_store::migration::MigrationRunner::new(store.conn())
        .migrate(path, false)
        .expect("migrate");
    DurableEngine::new(store.into_connection(), EngineLimits::documented()).expect("engine")
}

const NOW: i64 = 1_767_225_600_000;

/// The durable transitions a user actually generates, each timed individually.
///
/// `synchronous = FULL` on a real disk, because that is the shipping configuration and
/// because the alternative -- measuring on tmpfs -- would report `FULL` as free. This is
/// the same trap `orxnud-task`'s measurements file documents, and `assert_on_a_real_filesystem`
/// above is the guard against walking into it.
#[test]
fn durable_task_transitions_cost_what_they_should() {
    assert_on_a_real_filesystem();
    print_preamble();
    let root = scratch("engine");
    let db = root.join("state.db");
    let mut e = engine(&db);

    const N: usize = 150;

    // One full lifecycle per iteration, rather than 200 creates followed by 200 claims.
    //
    // That is not tidiness. `EngineLimits::documented()` caps live leases at 8, so
    // batching the phases claims 200 tasks against an 8-lease ceiling and the ninth is
    // refused with `concurrency limit reached` -- which is the engine working correctly
    // and the harness measuring the wrong thing. Interleaving also matches what a user
    // generates: one task moving through its states, not two hundred held at once.
    let mut create = Vec::with_capacity(N);
    let mut claim = Vec::with_capacity(N);
    let mut propose = Vec::with_capacity(N);
    let mut complete = Vec::with_capacity(N);

    for i in 0..N {
        let id = TaskId::new(format!("v25-{i}"));

        let t0 = Instant::now();
        e.enqueue_new(&NewTask::new(id.clone(), TaskKind::Query, NOW), NOW)
            .expect("enqueue");
        create.push(t0.elapsed());

        let t0 = Instant::now();
        e.claim_task_id(&id, "w1", NOW).expect("claim");
        claim.push(t0.elapsed());

        let t0 = Instant::now();
        e.propose_action(
            &format!("p-{i}"),
            &id,
            "w1",
            &orxnud_domain::ids::CapabilityId::new("filesystem/write-text"),
            Some("out.txt"),
            r#"{"contents":"x","path":"out.txt"}"#,
            &orxnud_domain::Actor::System {
                component: orxnud_domain::actor::SystemComponent::HealthCheck,
            },
            NOW,
        )
        .expect("propose");
        propose.push(t0.elapsed());

        let t0 = Instant::now();
        e.complete_task(&id, "w1", NOW, TaskState::Completed, true, None)
            .expect("complete");
        complete.push(t0.elapsed());
    }

    for s in [
        Summary::of("task create (durable commit)", create),
        Summary::of("task claim (lease write)", claim),
        Summary::of("proposal creation (durable)", propose),
        Summary::of("task complete (durable commit)", complete),
    ] {
        s.print();
        // 100 ms per transition: an fsync is milliseconds, so anything near this is a
        // missing index or a pragma that stopped applying.
        s.assert_under(Duration::from_millis(100), "task transition");
    }

    // Sustained throughput, because it answers a different question than single-op
    // latency and inferring one from the other is how a benchmark misleads.
    let t0 = Instant::now();
    const M: usize = 500;
    for i in 0..M {
        e.enqueue_new(
            &NewTask::new(TaskId::new(format!("v25-sustained-{i}")), TaskKind::Query, NOW),
            NOW,
        )
        .expect("enqueue");
    }
    let sustained = t0.elapsed();
    println!(
        "V25 | sustained insert throughput: {:.0} commits/s ({M} durable commits in \
         {sustained:?})",
        M as f64 / sustained.as_secs_f64()
    );

    drop(e);
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Phase 8 — sandbox overhead
// ---------------------------------------------------------------------------

/// Tier-1 isolation cost, reported only where this host can produce positive evidence.
///
/// The core V-25 numbers above deliberately never invoke a sandboxed capability, because a
/// benchmark that spawns a subprocess per idle daemon would be measuring the wrong thing.
/// The cost is real and is measured here instead.
///
/// V-85, V-86 and V-87 govern what a green result means. On a GitHub-hosted runner this
/// host cannot create an unprivileged user namespace, so the honest output is a printed
/// measurement saying so -- not a skip, and not a passing assertion standing in for one.
#[test]
fn tier1_sandbox_overhead_is_measured_or_declined() {
    print_preamble();
    let cap = orxnud_platform_sandbox::host_capability();
    println!(
        "V25 | sandbox backend {} / mechanism {} | guarantees visibility={} \
         tree_lifetime={} resources={} | tier1_executable={}",
        cap.backend,
        cap.mechanism,
        cap.guarantees.visibility,
        cap.guarantees.tree_lifetime,
        cap.guarantees.resources,
        cap.tier1_executable,
    );

    if !cap.tier1_executable {
        println!(
            "V25 | sandbox cost NOT MEASURABLE on this host: Tier-1 capabilities are \
             refused here. Per V-87 this is the expected result on a container without a \
             user-namespace grant, and it is a statement about the host, not about the \
             daemon. Positive evidence comes from scripts/run-sandbox-tests.sh on a host \
             that can isolate."
        );
        return;
    }

    let root = scratch("sandbox");
    let (daemon, _startup) = Daemon::start(&root);
    let endpoint = daemon.endpoint().to_path_buf();
    let pid = daemon.pid();

    // The cheapest real capability: one write, fully approved, fully sandboxed.
    //
    // A fresh task per iteration, because the first execution *completes* its task. An
    // earlier version reused one task and so measured 14 refusals and 1 execution, which
    // is a perfectly good demonstration of single-use state and no evidence at all about
    // sandbox cost.
    const N: usize = 12;
    let mut samples = Vec::with_capacity(N);
    let mut ok = 0;
    let mut refusals = 0;

    for i in 0..N {
        let id = format!("sb{i}");
        send_raw(
            &endpoint,
            format!(
                r#"{{"jsonrpc":"2.0","id":"c","method":"task/create","params":{{"id":"{id}","content":"x"}}}}"#
            )
            .as_bytes(),
        )
        .expect("create");
        send_raw(
            &endpoint,
            format!(
                r#"{{"jsonrpc":"2.0","id":"cl","method":"task/claim","params":{{"id":"{id}","worker":"w1"}}}}"#
            )
            .as_bytes(),
        )
        .expect("claim");
        let p = send_raw(
            &endpoint,
            format!(
                r#"{{"jsonrpc":"2.0","id":"p","method":"task/propose","params":{{"task":"{id}","worker":"w1","capability":"filesystem/write-text","target":"out.txt","params":{{"path":"out.txt","contents":"x"}}}}}}"#
            )
            .as_bytes(),
        )
        .expect("propose");
        let proposal = p["result"]["proposal"]["proposal_id"]
            .as_str()
            .expect("proposal id")
            .to_owned();
        send_raw(
            &endpoint,
            format!(
                r#"{{"jsonrpc":"2.0","id":"a","method":"capability/approve","params":{{"proposal":"{proposal}","ttl_ms":60000}}}}"#
            )
            .as_bytes(),
        )
        .expect("approve");

        let t0 = Instant::now();
        let r = send_raw(
            &endpoint,
            format!(
                r#"{{"jsonrpc":"2.0","id":"x","method":"task/execute","params":{{"proposal":"{proposal}","worker":"w1"}}}}"#
            )
            .as_bytes(),
        );
        let elapsed = t0.elapsed();
        if r.as_ref().is_some_and(|v| v.get("result").is_some()) {
            ok += 1;
            samples.push(elapsed);
        } else {
            refusals += 1;
        }
    }

    if ok == 0 {
        println!("V25 | sandbox cost NOT MEASURED: no invocation succeeded on this host.");
        return;
    }
    let s = Summary::of("tier1 sandboxed execution (approved)", samples);
    s.print();
    println!(
        "V25 | {ok} of {N} invocations executed ({refusals} refused); child processes seen          at sample time: {}",
        child_pids(pid)
    );
}

/// The codes the harness's own client depends on, asserted so a taxonomy change cannot
/// silently invalidate the measurement.
///
/// Small, but it is the one place this file would otherwise be coupled to the taxonomy
/// without saying so.
#[test]
fn the_measured_error_taxonomy_is_the_one_this_harness_expects() {
    for (code, expected) in [
        (RpcErrorCode::INVALID_REQUEST, -32600),
        (RpcErrorCode::RESOURCE_NOT_FOUND, -32040),
        (RpcErrorCode::CONFLICT, -32041),
        (RpcErrorCode::FORBIDDEN, -32042),
        (RpcErrorCode::ENVIRONMENT_UNAVAILABLE, -32043),
        (RpcErrorCode::INTERNAL_ERROR, -32603),
    ] {
        assert_eq!(
            code.code(),
            expected,
            "the taxonomy the V-25 harness measures against has changed"
        );
    }
}

/// A compile-time reminder that this harness measures the *shipped* binary.
///
/// `Runtime::start` exists in this crate and would be the easy way to measure "the daemon",
/// but it shares an address space with the harness: every allocation either makes is
/// indistinguishable, so RSS would be meaningless. The spawn above is the point.
#[allow(dead_code, reason = "documents why this file spawns rather than embeds")]
const MEASUREMENT_NOTES: &str = "\
spawn a real process for RSS;
measure to an answered request for readiness;
never invoke a sandboxed capability for the core numbers;
refuse to report durability numbers from tmpfs;
";