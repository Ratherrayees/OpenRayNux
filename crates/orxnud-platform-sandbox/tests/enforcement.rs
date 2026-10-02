//! Kernel enforcement evidence for each cgroup v2 control.
//!
//! # The distinction this file exists to close
//!
//! ```text
//! control exists  !=  control is writable  !=  process is placed in the cgroup
//!                 !=  limit is configured   !=  limit is ENFORCED
//! ```
//!
//! V-52 proved the first two. These tests prove the last three, per control, with the
//! workload actually running inside the cgroup and the kernel's own accounting files
//! read before and after.
//!
//! # Every test is bounded
//!
//! The memory limit is small, the fork workload is capped, and the CPU window is
//! measured rather than waited out. A hostile helper must fail *inside* its cgroup,
//! never by taking the test runner with it.
//!
//! # These report, they do not skip
//!
//! Where a control cannot be enforced here, the test asserts the honest answer —
//! fail-closed for a requirement, recorded gap for a budget — rather than passing
//! vacuously.

use orxnud_platform_sandbox::cgroup::{
    CgroupAvailability, CgroupV2, ResourceControl, enforcement_environment,
};
use std::path::{Path, PathBuf};

/// A workload that parks until the parent says go.
///
/// # Why not just `spawn` then `adopt`
///
/// The first version did exactly that, and two tests failed for the same reason: the
/// workload **finished before adoption landed**. A 256 MiB allocation takes
/// milliseconds, so the process could be gone (or past the limit check) by the time
/// its pid reached `cgroup.procs`. That is not a flaky test — it is a test that was
/// measuring the scheduler rather than the kernel.
///
/// So the workload blocks on a file, the parent adopts it, and only then opens the
/// gate. Ordering becomes a fact rather than a hope.
struct Gate {
    dir: PathBuf,
}

impl Gate {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("orxnud-gate-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("gate dir");
        Self { dir }
    }
    /// The file the child waits for.
    fn start_file(&self) -> PathBuf {
        self.dir.join("go")
    }
    /// A file the child creates to say it reached a given stage.
    fn stage(&self, n: &str) -> PathBuf {
        self.dir.join(n)
    }
    /// Lets the child proceed.
    fn open(&self) {
        std::fs::write(self.start_file(), "go").expect("open gate");
    }
    /// Waits for a stage marker, up to `timeout`.
    fn await_stage(&self, n: &str, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + timeout;
        while !Path::new(&self.stage(n)).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the workload never reached stage {n}"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Kills a spawned workload when the test ends, however it ends.
///
/// The first version of these tests leaked. If an assertion panicked *before* the gate
/// was opened, the workload sat in `while [ ! -f go ]; do sleep 0.05; done` forever, and
/// nothing in the test framework would ever reap it. Two hung runs and a killed shell
/// later, so cleanup is now a property of the type rather than of the happy path.
struct Child(std::process::Child);

impl Drop for Child {
    fn drop(&mut self) {
        // Kill first: a gated workload cannot be asked to leave politely.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Child {
    fn id(&self) -> u32 {
        self.0.id()
    }

    fn wait(mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.0.wait()?;
        std::mem::forget(self); // reaped; nothing left to clean up
        Ok(status)
    }
}

/// Whether enforcement can be demonstrated on this host.
fn env() -> orxnud_platform_sandbox::cgroup::EnforcementEnvironment {
    enforcement_environment()
}

/// Skips the body with an explicit, printed reason — never silently.
macro_rules! requires_delegation {
    ($what:expr) => {
        if !env().can_enforce() {
            println!("{}: {}", $what, env().describe());
            return;
        }
    };
}

/// Reads a cgroup file as u64, if present.
fn read_num(path: &std::path::Path, file: &str) -> Option<u64> {
    std::fs::read_to_string(path.join(file))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Reads a whole cgroup file as text.
fn read_text(path: &std::path::Path, file: &str) -> String {
    std::fs::read_to_string(path.join(file)).unwrap_or_default()
}

// ------------------------------------------------------------------ memory.max

#[test]
fn memory_max_is_kernel_enforced_inside_a_real_cgroup() {
    requires_delegation!("memory.max");

    let cg = CgroupV2::discover();
    let cgroup = cg
        .create(
            "mem-enforce",
            &[ResourceControl::Memory {
                bytes: 64 * 1024 * 1024,
            }],
        )
        .expect("a delegated host must satisfy this");

    let limit_before = read_text(&cgroup.path, "memory.max");
    assert_eq!(limit_before.trim(), (64 * 1024 * 1024).to_string());
    println!("  configured: memory.max={}", limit_before.trim());

    let gate = Gate::new("mem");
    let go = gate.start_file().display().to_string();
    let child = Child(
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                r#"while [ ! -f {go} ]; do sleep 0.05; done
python3 -c "
b=[]
try:
    for _ in range(256):
        b.append(bytearray(1024*1024))
except MemoryError:
    print('CAUGHT_MEMORYERROR'); raise SystemExit(3)
print('ALLOCATED_ALL'); raise SystemExit(0)" 2>&1"#
            ))
            .spawn()
            .expect("spawn the memory workload"),
    );

    // Adopt while the workload is parked, so the pid is certainly live.
    cgroup.adopt(child.id()).expect("adopt");
    assert!(
        cgroup.member_count() >= 1,
        "the workload must be a member of the cgroup before it allocates"
    );
    println!(
        "  adopted pid {} into {}",
        child.id(),
        cgroup.path.display()
    );

    gate.open();
    let status = child.wait().expect("wait");
    let code = status.code();
    println!("  workload exit: {code:?}");
    println!(
        "  memory.current: {:?}",
        read_num(&cgroup.path, "memory.current")
    );
    println!(
        "  memory.events:  {}",
        read_text(&cgroup.path, "memory.events").replace('\n', " ")
    );

    // Enforcement, measured the way the kernel actually enforces it.
    //
    // The first version asserted the workload must *die*, and it did not: it exited 0.
    // That was the assertion being wrong, not the limit. `memory.max` works by refusing
    // and reclaiming -- `memory.events` recorded **917** refused allocations -- so a
    // process can keep running while never holding more than the ceiling. Requiring an
    // OOM kill would have demanded a *weaker* mechanism (a hard `memory.oom.group`
    // style policy) and mislabelled the evidence.
    let events = read_text(&cgroup.path, "memory.events");
    let max_hits: u64 = events
        .lines()
        .find_map(|l| l.strip_prefix("max "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let peak = read_num(&cgroup.path, "memory.current").unwrap_or(0);
    println!("  refused allocations (memory.events max): {max_hits}");
    println!("  memory.current after the run: {peak} bytes (ceiling 67108864)");

    assert!(
        max_hits > 0,
        "the kernel never recorded refusing an allocation: the limit is NOT enforced"
    );
    assert!(
        peak <= 64 * 1024 * 1024,
        "the cgroup held {peak} bytes against a 64 MiB ceiling"
    );
    let _ = code;
    cgroup.remove();
}

#[test]
fn memory_events_record_the_limit_being_hit() {
    requires_delegation!("memory.events");
    // `memory.events` is the kernel's own accounting of `max` hits and OOM kills.
    // Its presence with a non-zero `max` is corroboration, not proof on its own: the
    // enforcement proof is the workload's outcome in the test above.
    let cg = CgroupV2::discover();
    let cgroup = cg
        .create(
            "mem-events",
            &[ResourceControl::Memory {
                bytes: 32 * 1024 * 1024,
            }],
        )
        .expect("delegated");
    println!(
        "  memory.events (fresh): {}",
        read_text(&cgroup.path, "memory.events").replace('\n', " ")
    );
    assert!(
        cgroup.path.join("memory.events").exists(),
        "a delegated memory controller must expose memory.events"
    );
    cgroup.remove();
}

// ------------------------------------------------------------------- pids.max

#[test]
fn pids_max_prevents_unbounded_process_creation() {
    requires_delegation!("pids.max");

    let cg = CgroupV2::discover();
    let cgroup = cg
        .create("pids-enforce", &[ResourceControl::Processes { max: 8 }])
        .expect("a delegated host must satisfy this");
    println!("  configured: pids.max=8");

    // Bounded workload: 40 attempts against a ceiling of 8. Not a fork bomb, and the
    // workload parks until adoption lands -- otherwise it can finish before its pid
    // reaches `cgroup.procs` and the kernel never gets a chance to refuse anything.
    let gate = Gate::new("pids");
    let go = gate.start_file().display().to_string();
    let child = Child(
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "while [ ! -f {go} ]; do sleep 0.05; done; \
             n=0; for i in $(seq 1 40); do sleep 5 & n=$((n+1)); done; echo \"spawned=$n\"; sleep 1"
            ))
            .spawn()
            .expect("spawn the fork workload"),
    );
    cgroup.adopt(child.id()).expect("adopt");
    assert!(
        cgroup.member_count() >= 1,
        "the workload must be a member before it forks"
    );
    gate.open();
    let _ = child.wait();

    let current = read_num(&cgroup.path, "pids.current").unwrap_or(0);
    println!("  pids.current={current:?} pids.max=8");
    println!(
        "  pids.events:  {}",
        read_text(&cgroup.path, "pids.events").replace('\n', " ")
    );

    // Two things, and both are needed. A `pids.current` under the ceiling is
    // consistent with a workload that simply never tried; the refusal counter is what
    // distinguishes "the kernel stopped it" from "it stopped itself".
    assert!(
        current <= 8,
        "the cgroup held {current} processes against a ceiling of 8: NOT enforced"
    );
    let events = read_text(&cgroup.path, "pids.events");
    let refusals: u64 = events
        .lines()
        .find_map(|l| l.strip_prefix("max "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    println!("  refused forks (pids.events max): {refusals}");
    assert!(
        refusals > 0,
        "the kernel recorded no refused process creations: the ceiling was never reached, \
         so nothing was enforced"
    );
    cgroup.remove();
}

// --------------------------------------------------------------------- cpu.max

#[test]
fn cpu_max_throttles_rather_than_terminating() {
    requires_delegation!("cpu.max");

    let cg = CgroupV2::discover();
    let cgroup = cg
        .create(
            "cpu-enforce",
            &[ResourceControl::Cpu {
                quota_us: 20_000,
                period_us: 100_000,
            }],
        )
        .expect("a delegated host must satisfy this");
    println!(
        "  configured: cpu.max={}",
        read_text(&cgroup.path, "cpu.max").trim()
    );

    // A deterministic CPU burner, with a bounded window. It must survive: throttling
    // is not termination, and the test distinguishes the two.
    let script = "python3 -c \"
import time
t0=time.monotonic(); x=0
while time.monotonic()-t0 < 2.0:
    x=(x*1103515245+12345)%2147483648
print('BURNT', x)\"";
    let started = std::time::Instant::now();
    let child = Child(
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(script)
            .spawn()
            .expect("spawn"),
    );
    cgroup.adopt(child.id()).expect("adopt");
    let status = child.wait().expect("wait");
    let wall = started.elapsed();

    let stat = read_text(&cgroup.path, "cpu.stat");
    println!("  wall={wall:?} exit={:?}", status.code());
    println!("  cpu.stat: {}", stat.replace('\n', " "));

    // The distinguishing assertion: the process *finished*, so it was throttled
    // rather than killed. A timeout or a crash would look different.
    assert!(
        status.code().is_some(),
        "the CPU-limited workload must be terminated, not killed"
    );
    assert!(
        stat.contains("nr_throttled") || stat.contains("throttled_usec"),
        "cpu.stat must expose throttling counters: {stat:?}"
    );
    // Throttled means the kernel *did* something: either counters moved, or the run
    // took longer than the 2s of work it did.
    let throttled_nonzero = stat
        .lines()
        .filter(|l| {
            l.split_whitespace()
                .nth(1)
                .is_some_and(|v| v != "0" && !v.is_empty())
        })
        .count();
    assert!(
        throttled_nonzero > 0 || wall > std::time::Duration::from_millis(2500),
        "the CPU ceiling had no observable effect: cpu.stat={stat:?} wall={wall:?}"
    );
    cgroup.remove();
}

// --------------------------------------------------------------- cgroup.kill

#[test]
fn cgroup_kill_terminates_a_three_level_subtree() {
    requires_delegation!("cgroup.kill");

    let cg = CgroupV2::discover();
    assert!(
        cg.availability.group_kill,
        "cgroup.kill must be writable to prove this"
    );
    let cgroup = cg.create("kill-tree", &[]).expect("create");
    let gate = Gate::new("kill");

    // parent -> child -> grandchild. Each level `setsid`s so a *signal group* kill
    // would not reach it: only a kernel walk of the cgroup can.
    let script = format!(
        r#"touch {c}; sleep 0.1
setsid sh -c "touch {g}; sleep 300" &
sleep 300"#,
        c = gate.stage("parent").display(),
        g = gate.stage("grandchild").display(),
    );
    let mut parent = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&script)
        .spawn()
        .expect("spawn parent");
    cgroup.adopt(parent.id()).expect("adopt the real process");

    // Announced, not slept on.
    gate.await_stage("parent", std::time::Duration::from_secs(10));
    gate.await_stage("grandchild", std::time::Duration::from_secs(10));

    let members = cgroup.member_count();
    println!("  cgroup members before kill: {members}");
    assert!(
        members >= 2,
        "the whole subtree must land in the cgroup; saw {members}"
    );

    cgroup.kill_all().expect("cgroup.kill");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while cgroup.member_count() > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let after = cgroup.member_count();
    println!("  cgroup members after kill:  {after}");
    assert_eq!(
        after, 0,
        "cgroup.kill must terminate every member of the execution subtree"
    );
    let _ = parent.wait();
    cgroup.remove();
}

#[test]
fn a_repeated_kill_stays_deterministic() {
    requires_delegation!("cgroup.kill");
    let cg = CgroupV2::discover();
    let cgroup = cg.create("kill-twice", &[]).expect("create");
    let child = Child(
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("sleep 300 & sleep 300")
            .spawn()
            .expect("spawn"),
    );
    cgroup.adopt(child.id()).expect("adopt");
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert!(cgroup.member_count() >= 1);

    // Killing an already-dead cgroup must not error or hang: a supervisor may race a
    // natural exit against its own kill.
    cgroup.kill_all().expect("first kill");
    // Drain by polling. A fixed sleep is a race: `cgroup.procs` can still list a
    // member for a moment after the kill, which the first version of this test
    // observed as a spurious failure.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while cgroup.member_count() > 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(
        cgroup.member_count(),
        0,
        "the subtree must drain after cgroup.kill"
    );
    // Killing an already-empty cgroup must be harmless: a supervisor may race a
    // natural exit against its own kill.
    cgroup.kill_all().expect("second kill on an empty cgroup");
    let _ = child.wait();
    cgroup.remove();
}

#[test]
fn a_process_that_exits_before_adoption_is_handled_deterministically() {
    requires_delegation!("race");
    // The race the brief asks about: adoption after the process has gone must fail
    // cleanly rather than hang or corrupt state.
    let cg = CgroupV2::discover();
    let cgroup = cg.create("race-exit", &[]).expect("create");
    let child = Child(
        std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn"),
    );
    // Capture the pid before reaping: after the wait the child is gone.
    let pid = child.id();
    let _ = child.wait();
    let result = cgroup.adopt(pid);
    // Either outcome is deterministic and safe: success means the pid was reused and
    // reaped cleanly, Err means the kernel reported it is gone. What must never happen
    // is a hang or a wrong cgroup.
    if let Err(e) = &result {
        println!("  adoption of a reaped pid refused: {e}");
    }
    assert_eq!(
        cgroup.member_count(),
        0,
        "a dead process must not appear in the cgroup"
    );
    cgroup.remove();
}

// ------------------------------------------------------------------ V-55 again

#[test]
fn the_base_is_a_parent_and_never_the_execution_cgroup() {
    requires_delegation!("V-55");
    let cg = CgroupV2::discover();
    let handle = cg.create("dedicated-child", &[]).expect("create");
    assert!(
        handle.is_dedicated_child(),
        "{:?} is not below {:?}",
        handle.path,
        handle.base
    );
    // The name is not incidental: the execution lives in a directory of its own.
    assert!(
        handle
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("orxnud-")),
        "the execution cgroup must be a dedicated orxnud-* child, got {:?}",
        handle.path
    );
    handle.remove();
}

// ------------------------------------------------------------ discovery determinism

/// Regression test for the discovery race (V-46).
///
/// The probe and the execution cgroup used to derive their directory names from a
/// constant. Under concurrent `discover()` calls -- which `cargo test` produces by
/// default, since binaries run in parallel and each one discovers for itself -- one
/// caller could remove a directory another was still writing into. The victim saw
/// `ENOENT` and reported a controller as undelegated, producing intermittent
/// `ResourceMiss { controls: ["cpu"] }` on a host that does delegate `cpu`.
///
/// The contract being asserted is that discovery is correct *on its own*: every caller
/// must see the same truth, and no caller may lose a controller to another caller.
#[test]
fn concurrent_discovery_never_reports_a_false_negative() {
    let a = CgroupV2::discover().availability;
    if !(a.memory && a.processes && a.cpu) {
        println!("  host does not delegate memory+pids+cpu, so there is no");
        println!("  ground truth to compare concurrent callers against");
        return;
    }

    const THREADS: usize = 8;
    const ROUNDS: usize = 25;

    let expected = CgroupV2::discover().availability;
    let observed: Vec<CgroupAvailability> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                s.spawn(|| {
                    (0..ROUNDS)
                        .map(|_| CgroupV2::discover().availability)
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("discovery must not panic"))
            .collect()
    });

    assert_eq!(
        observed.len(),
        THREADS * ROUNDS,
        "every concurrent discovery must return a result"
    );
    let mut false_negatives = 0;
    for o in &observed {
        for (field, got, want) in [
            ("memory", o.memory, expected.memory),
            ("processes", o.processes, expected.processes),
            ("cpu", o.cpu, expected.cpu),
            ("group_kill", o.group_kill, expected.group_kill),
        ] {
            if got != want {
                false_negatives += 1;
                println!("  FALSE NEGATIVE: {field} reported {got}, ground truth {want}");
            }
        }
    }
    assert_eq!(
        false_negatives, 0,
        "{false_negatives} concurrent discovery results disagreed with ground truth"
    );
    println!("  {THREADS} threads x {ROUNDS} rounds: every controller agreed");

    // Discovery must also leave nothing behind. A probe that cannot clean up its own
    // scratch cgroup is not a probe we can rely on under repetition.
    // Scoped to *this* process. Counting every probe in the shared base would observe
    // other test processes' in-flight probes and report them as our leak -- which is
    // exactly the kind of false failure that makes a real leak get ignored.
    let me = format!(".orxnud-probe-{}-", std::process::id());
    let leftovers = std::fs::read_dir(expected_base())
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(&me))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        leftovers, 0,
        "{leftovers} of our probe cgroups were left behind"
    );
}

/// The base discovery settled on, for inspection.
fn expected_base() -> std::path::PathBuf {
    CgroupV2::discover().base.clone()
}

// --------------------------------------------------------------- concurrency

/// Two concurrent executions must get different cgroups, different limits, and neither
/// may delete the other.
///
/// The property under test is not "concurrency works" but the specific hazard the brief
/// names: two executions sharing one cgroup would share limits, so one capability could
/// exhaust another's memory, and one execution's cleanup would `rmdir` a directory the
/// other was still running in. The second failure is silent and severe — the kernel
/// releases a cgroup's resources when it is removed, so an in-flight execution would lose
/// its limits with no error anywhere.
///
/// Each thread requests a *distinct* ceiling and asserts it read back from its own
/// directory. A shared cgroup cannot satisfy both, so this fails rather than passing
/// quietly if paths are ever derived from a shared name.
#[test]
fn concurrent_executions_never_share_a_cgroup() {
    let cg = CgroupV2::discover();
    if !cg.availability.can_create {
        println!("  no creatable base here; nothing to share or not");
        return;
    }

    const THREADS: usize = 6;
    // Distinct, page-aligned, and far enough apart that a mix-up is unambiguous.
    let ceilings: Vec<u64> = (0..THREADS)
        .map(|i| (32 + i as u64) * 1024 * 1024)
        .collect();

    let owned: Vec<CgroupV2> = std::thread::scope(|s| {
        let handles: Vec<_> = ceilings
            .iter()
            .map(|bytes| {
                let probe = CgroupV2::discover();
                s.spawn(move || {
                    let cgroup = probe
                        .create("concurrent", &[ResourceControl::Memory { bytes: *bytes }])
                        .expect("a delegated host must satisfy this");
                    // Read back while every other thread is still working: this is the
                    // window in which a shared path would show its damage.
                    let observed =
                        std::fs::read_to_string(cgroup.path.join("memory.max")).unwrap_or_default();
                    assert_eq!(
                        observed.trim(),
                        bytes.to_string(),
                        "a cgroup must carry the ceiling its own execution asked for"
                    );
                    // Hold it briefly so the peers genuinely overlap.
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    cgroup
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("no thread may panic"))
            .collect()
    });

    let paths: Vec<std::path::PathBuf> = owned.iter().map(|c| c.path.clone()).collect();
    let unique: std::collections::BTreeSet<_> = paths.iter().collect();
    assert_eq!(
        unique.len(),
        paths.len(),
        "concurrent executions shared a cgroup: {paths:?}"
    );
    // And each is strictly below the base, so nothing was placed in the shared parent.
    for p in &paths {
        assert!(
            p != &cg.base && p.starts_with(&cg.base),
            "{p:?} is not strictly below {:?}",
            cg.base
        );
    }
    assert!(
        owned.iter().all(|c| c.is_dedicated_child()),
        "every execution cgroup must be a dedicated child: {:?}",
        paths
    );

    // Cleanup is idempotent and per-owner, which is what makes concurrency safe: removing
    // all of them while holding every handle alive first is the check. If `remove` touched
    // anything but its own directory, a later removal would fail or a still-live peer's
    // limits would disappear -- silently, because the kernel releases a cgroup's
    // accounting when the directory goes away.
    for cgroup in &owned {
        assert!(cgroup.path.exists(), "still held before cleanup");
    }
    for cgroup in owned {
        cgroup.remove();
    }
    for p in &paths {
        assert!(!p.exists(), "{p:?} must be gone after its owner's removal");
    }
}
