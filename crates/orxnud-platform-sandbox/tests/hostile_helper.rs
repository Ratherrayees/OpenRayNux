//! Hostile deterministic helpers: the adversarial side of Phase 4a.
//!
//! # These are attackers, not features
//!
//! Every helper tries to do something it must not be able to do: read a file it was
//! not granted, reach the network, find a credential, spawn a grandchild that
//! outlives it, print forever. They are the test suite's adversary, and they exist
//! because "the sandbox works" is otherwise unfalsifiable.
//!
//! # One binary, selected by argv
//!
//! A single helper binary re-executed by the runner, rather than a dozen binaries.
//! Each mode is deterministic, exits promptly unless it is explicitly a hang, and
//! prints a single-line JSON-ish result on stdout so the parent can assert on it.
//!
//! # Nothing here reads a real secret
//!
//! Synthetic markers only. The helper is given names like `ORXNUD_TEST_SECRET` that
//! the test places in the *parent's* environment, and its job is to report whether it
//! can see them. It never reads the user's real credential stores.

/// The environment variable carrying the helper's mode and parameters.
const HELPER_MODE_VAR: &str = "ORXNUD_HOSTILE_HELPER";

/// Where the descendant-spawning helper writes its heartbeat.
///
/// A parameter rather than a hard-coded `/tmp` path, because `/tmp` inside the sandbox
/// is a **private tmpfs**: a grandchild writing there is invisible to the host, so a
/// containment test that looks at `/tmp` would see nothing and conclude "contained"
/// for the wrong reason. The caller grants a host-visible directory and passes it here.
const MARKER_VAR: &str = "ORXNUD_DESCENDANT_MARKER";

/// What the helper reports back.
struct Report {
    ok: bool,
    detail: String,
}

impl Report {
    fn pass(detail: impl Into<String>) -> Self {
        Self {
            ok: true,
            detail: detail.into(),
        }
    }
    fn fail(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: detail.into(),
        }
    }
}

fn emit(r: &Report) {
    println!(
        "RESULT {}\t{}",
        if r.ok { "PASS" } else { "FAIL" },
        r.detail
    );
}

/// Re-executed by the sandbox runner as the hostile process.
///
/// A test binary rather than a shipped `bin`, so the adversary cannot become a
/// product artefact. The `--ignored` harness flags mean running the test normally does
/// nothing.
#[test]
#[ignore = "re-executed by isolation.rs as a hostile helper; not a test"]
fn hostile_helper_entry_point() {
    // Mode and parameters arrive via an explicitly granted environment variable, not
    // argv. libtest does not expose trailing arguments to a test's `env::args()` in a
    // way that survives `--exact ... -- <mode>`; the argv version silently ran `noop`,
    // so every output assertion in `isolation.rs` was testing the wrong thing.
    //
    // Using the environment is also the better shape for this particular test: the
    // whole point of Phase 4a is that a child sees only what it was granted, so
    // driving the helper through an explicit grant is self-consistent.
    let tail: Vec<String> = std::env::var(HELPER_MODE_VAR)
        .ok()
        .map(|m| m.split('\u{1}').map(str::to_owned).collect())
        .unwrap_or_default();
    let mode = tail.first().map_or("noop", String::as_str);
    let owned = |n: usize| -> String { tail.get(n).cloned().unwrap_or_default() };
    let report = match mode {
        // --- environment ---------------------------------------------------
        "env-dump" => env_dump(),
        "env-read" => env_read(&owned(1)),
        // --- filesystem ----------------------------------------------------
        "fs-read" => fs_read(&owned(1)),
        "fs-write" => fs_write(&owned(1)),
        "fs-list" => fs_list(&owned(1)),
        // --- network -------------------------------------------------------
        "net-connect" => net_connect(&owned(1)),
        "net-listen" => net_listen(),
        "net-resolve" => net_resolve(&owned(1)),
        // --- credentials ---------------------------------------------------
        "cred-env-probe" => cred_env_probe(),
        "cred-path-probe" => cred_path_probe(),
        // --- process -------------------------------------------------------
        "spawn-descendant" => spawn_descendant(),
        "descendant-hang" => {
            // A detached, signal-ignoring descendant plus a parent that never returns.
            // The combination is the only way to exercise a *timeout* while a descendant
            // is still alive: `spawn-descendant` returns immediately, so the sandbox exits
            // before any kill path is reached.
            let r = spawn_descendant();
            emit(&r);
            hang();
            unreachable!("hang never returns")
        }
        "hang" => {
            hang();
            unreachable!("hang never returns")
        }
        "flood" => flood(owned(1).parse().ok()),
        "exit-code" => {
            let code: i32 = owned(1).parse().unwrap_or(0);
            emit(&Report::pass(format!("exiting {code}")));
            std::process::exit(code);
        }
        "stderr-write" => {
            eprintln!("{}", "E".repeat(1000));
            Report::pass("stderr written")
        }
        "fd-scan" => fd_scan(),
        "mem-hog" => mem_hog(owned(1).parse().ok()),
        "fork-many" => fork_many(owned(1).parse().unwrap_or(8)),
        "malformed" => {
            // Not valid JSON, not the declared schema. A supervisor must classify this
            // as a bad result rather than parsing it into something plausible.
            println!("{{\"not\":\"the schema\"");
            Report::pass("malformed output emitted")
        }
        _ => Report::pass("noop"),
    };
    emit(&report);
}

// ---------------------------------------------------------------- environment

/// Reports every environment variable it can see.
///
/// The parent must pass an **explicit allowlist**, so a non-empty list here means the
/// environment was inherited. This is the single most important helper in the file.
fn env_dump() -> Report {
    let mut names: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    names.sort();
    emit(&Report::pass(format!("names={}", names.join(","))));
    Report::pass(format!("count={}", names.len()))
}

/// Whether a named variable is visible.
fn env_read(name: &str) -> Report {
    match std::env::var(name) {
        Ok(v) => Report::fail(format!("{name} is visible with value length {}", v.len())),
        Err(_) => Report::pass(format!("{name} is not visible")),
    }
}

// ---------------------------------------------------------------- filesystem

fn fs_read(path: &str) -> Report {
    match std::fs::read_to_string(path) {
        Ok(_) => Report::fail(format!("read {path}")),
        Err(e) => Report::pass(format!("{path} refused: {}", e.kind())),
    }
}

fn fs_write(path: &str) -> Report {
    match std::fs::write(path, b"hostile") {
        Ok(()) => Report::fail(format!("wrote {path}")),
        Err(e) => Report::pass(format!("{path} refused: {}", e.kind())),
    }
}

fn fs_list(path: &str) -> Report {
    match std::fs::read_dir(path) {
        Ok(_) => Report::fail(format!("listed {path}")),
        Err(e) => Report::pass(format!("{path} refused: {}", e.kind())),
    }
}

// ------------------------------------------------------------------- network

fn net_connect(addr: &str) -> Report {
    use std::net::TcpStream;
    match TcpStream::connect(addr) {
        Ok(_) => Report::fail(format!("connected to {addr}")),
        Err(e) => Report::pass(format!("{addr} refused: {e}")),
    }
}

fn net_listen() -> Report {
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(l) => Report::fail(format!(
            "bound a listening socket on port={}",
            l.local_addr().map_or(0, |a| a.port())
        )),
        Err(e) => Report::pass(format!("listen refused: {e}")),
    }
}

fn net_resolve(host: &str) -> Report {
    match std::net::ToSocketAddrs::to_socket_addrs(&(host, 80)) {
        Ok(_) => Report::fail(format!("resolved {host}")),
        Err(e) => Report::pass(format!("{host} did not resolve: {e}")),
    }
}

// --------------------------------------------------------------- credentials

/// The synthetic markers a parent places in its own environment.
///
/// If any of these reach the child, the environment boundary is broken. They are
/// names this test invented; none corresponds to a real provider or store.
const SYNTHETIC_MARKERS: &[&str] = &[
    "OPENRAYNUX_TEST_SECRET",
    "OPENRAYNUX_TEST_API_KEY",
    "OPENRAYNUX_TEST_CREDENTIAL",
    "AWS_SECRET_ACCESS_KEY",
    "ANTHROPIC_API_KEY",
];

fn cred_env_probe() -> Report {
    let mut found = Vec::new();
    for m in SYNTHETIC_MARKERS {
        if std::env::var(m).is_ok() {
            found.push(*m);
        }
    }
    // Also report the total variable count, so an empty marker list but a large count
    // is still caught: the point is that the environment is *closed*, not merely
    // free of these five names.
    let total = std::env::vars().count();
    if found.is_empty() {
        Report::pass(format!("no markers; total vars={total}"))
    } else {
        let leaked = found.join(",");
        Report::fail(format!("markers leaked: {leaked}; total vars={total}"))
    }
}

/// Attempts to reach credential locations by path.
fn cred_path_probe() -> Report {
    let candidates = [
        "/home/rayees/.ssh",
        "/home/rayees/.aws",
        "/home/rayees/.config/gcloud",
        "/run/user/1000/keyring",
    ];
    let mut reachable = Vec::new();
    for c in candidates {
        if std::fs::metadata(c).is_ok() {
            reachable.push(c);
        }
    }
    if reachable.is_empty() {
        Report::pass("no credential path reachable")
    } else {
        Report::fail(format!(
            "credential paths reachable: {}",
            reachable.join(",")
        ))
    }
}

// -------------------------------------------------------------------- process

/// Spawns a detached grandchild that ignores every termination signal.
///
/// The hostile shape for containment. `setsid` detaches it from our process group and
/// the `SIG_IGN`s make a graceful request pointless, so only kernel-level enforcement
/// can stop it.
fn spawn_descendant() -> Report {
    let marker =
        std::env::var(MARKER_VAR).unwrap_or_else(|_| "/tmp/orxnud-descendant-alive".into());
    // Injected as a literal in the child's source. Quoted, because it is a path the
    // caller chose and this helper is the adversary -- an unquoted path would be a
    // command-injection hole in the *test fixture*.
    let quoted = marker.replace('\\', "\\\\").replace('\'', "\\'");
    let script = r#"
import signal, time, os, sys
for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
    try: signal.signal(s, signal.SIG_IGN)
    except Exception: pass
path = sys.argv[1]
while True:
    with open(path, 'w') as f: f.write(str(os.getpid()))
    time.sleep(0.15)
"#;
    let mut cmd = std::process::Command::new("/usr/bin/python3");
    cmd.arg("-c").arg(script).arg(&quoted);
    match cmd.spawn() {
        Ok(_) => {
            // Wait for the grandchild to prove it is alive.
            //
            // Without this the helper returns immediately, the test binary exits, and
            // the namespace is torn down before the grandchild has written anything --
            // so a containment test sees no marker and concludes "contained" for the
            // wrong reason. The marker must exist *before* the parent dies, or the
            // test is measuring nothing.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !std::path::Path::new(&marker).exists() {
                if std::time::Instant::now() > deadline {
                    return Report::fail("the grandchild never established its marker");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Report::pass(format!("grandchild alive, marker={marker}"))
        }
        Err(e) => Report::fail(format!("could not spawn: {e}")),
    }
}

/// Counts the file descriptors this process was given.
///
/// The descriptor-hygiene check. A supervisor should hand the child exactly three --
/// stdin, stdout, stderr -- and nothing else: an inherited descriptor is an inherited
/// channel to whatever it was connected to.
fn fd_scan() -> Report {
    let mut extras = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Ok(n) = name.parse::<u32>()
                && n > 2
            {
                extras.push(n);
            }
        }
    }
    extras.sort_unstable();
    // Reports rather than judging. The property under test is not "exactly three" --
    // `bubblewrap` itself leaves an fd behind (`/proc/<ns-init>/fd`), so a sandboxed
    // helper legitimately sees one extra descriptor that has nothing to do with the
    // supervisor. What matters is that the supervisor *adds* nothing, which is a
    // comparison against an unsandboxed baseline and therefore lives in the parent.
    Report::pass(format!("extras={extras:?}"))
}

fn hang() -> Report {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

/// Allocates and *touches* memory until the kernel refuses.
///
/// The touching matters. `bytearray(n)` alone can be satisfied by untouched zero pages,
/// so a helper that only allocated would appear to succeed inside a ceiling that is
/// working perfectly. This one writes to every page, so `memory.max` produces a refusal
/// the helper can observe and report.
///
/// Reported, never panicked: a helper that is OOM-killed cannot report anything, and the
/// caller needs to distinguish "refused and stopped" from "ran unbounded".
///
/// # Hard host-side bound
///
/// `HARD_CAP_MIB` is not a politeness limit; it is what makes this helper safe to run.
///
/// The first version asked for 4096 MiB and stopped only when the allocator refused. That
/// is correct *while a ceiling is enforced* and catastrophic when one is not: a mutation
/// that removed the cgroup left this helper allocating against the whole machine, and the
/// test run drove the host into swap exhaustion and froze the system. An unbounded
/// adversary is only safe to run when the thing under test is what bounds it, which is
/// exactly the assumption a mutation invalidates.
///
/// So the helper bounds itself at the same 256 MiB the proven mechanism workload uses.
/// Against a 64 MiB ceiling the kernel kills it far below the
/// cap, so the enforcement evidence is unchanged; with no ceiling it stops at the cap and
/// reports, so a failed experiment costs a bounded amount of memory and says so.
const HARD_CAP_MIB: u64 = 256;

fn mem_hog(target_mib: Option<u64>) -> Report {
    let target = target_mib.unwrap_or(HARD_CAP_MIB).min(HARD_CAP_MIB) * 1024 * 1024;
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut refused = 0u64;
    while (held.len() as u64) * 1024 * 1024 < target {
        let mut page = vec![0u8; 1024 * 1024];
        // Touch every 4 KiB so the pages are actually resident and charged.
        for i in (0..page.len()).step_by(4096) {
            page[i] = (i % 251) as u8;
        }
        held.push(page);
    }
    // If we are still here, try until something refuses -- or until the hard cap, so an
    // unenforced run cannot run away.
    loop {
        if (held.len() as u64) * 8 * 1024 * 1024 >= HARD_CAP_MIB * 1024 * 1024 {
            refused = 0;
            break;
        }
        let mut page = match vec![0u8; 8 * 1024 * 1024].try_reserve_exact(1) {
            Ok(_) => vec![0u8; 8 * 1024 * 1024],
            Err(_) => {
                refused += 1;
                if refused > 64 {
                    break;
                }
                continue;
            }
        };
        for i in (0..page.len()).step_by(4096) {
            page[i] = 1;
        }
        held.push(page);
    }
    Report::pass(format!(
        "held {} MiB after {} refusals",
        (held.len() as u64) * 1024 * 1024 / (1024 * 1024),
        refused
    ))
}

/// Forks `count` children that outlive this process, bounded.
///
/// Used through the governed path to prove that a PID ceiling is enforced by the kernel
/// rather than by the helper's own restraint.
fn fork_many(count: u64) -> Report {
    let mut spawned = 0u64;
    for _ in 0..count {
        match std::process::Command::new("/bin/sleep")
            .arg("30")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(_) => spawned += 1,
            // The ceiling is enforced; further forks are refused.
            Err(_) => break,
        }
    }
    Report::pass(format!("spawned {spawned} of {count}"))
}

fn flood(bytes: Option<usize>) -> Report {
    let target = bytes.unwrap_or(usize::MAX);
    let line = "X".repeat(1023);
    let mut written = 0usize;
    while written < target {
        let chunk = (target - written).min(1024);
        println!("{}", &line[..chunk]);
        written += chunk;
    }
    Report::pass(format!("flooded {written} bytes"))
}
