//! Reports whether *this* machine can isolate a Tier-1 subprocess.
//!
//! # Why this exists
//!
//! "Can this host run a sandboxed capability?" is a runtime fact, and it has two failure
//! modes that look identical from the outside: the backend is not installed, or it is
//! installed and the kernel refuses to let it create a user namespace. The second is the
//! case a GitHub-hosted Linux runner is in — Ubuntu ships `bwrap`, so
//! [`orxnud_platform_sandbox::host_backend_name`] cheerfully answers `bwrap`, and every
//! Tier-1 dispatch is nevertheless refused. A build that only checked whether `bwrap` was
//! on disk would therefore report success on a host that can isolate nothing.
//!
//! So this reports the answer that decides whether work runs, using the *same* probe and
//! the same `AvailableGuarantees::check` the dispatcher uses. It cannot disagree with the
//! dispatch that refused a capability, because there is only one implementation of the
//! question.
//!
//! # What it prints, and why the last two lines matter
//!
//! Alongside the verdict it prints the uid map and effective capabilities of the process
//! it is running as. That is the *configuration* the answer was obtained in, and it is
//! what distinguishes the two environments this project has to tell apart:
//!
//! * **Production** — an unprivileged user (`uid != 0`, `CapEff == 0`) whose `bwrap` has
//!   to create a nested user namespace to gain any capability at all. `uid_map` is a
//!   single-entry map.
//! * **Not production** — a process that already holds `CAP_SYS_ADMIN`, or `uid == 0`
//!   with capabilities, where `bwrap` runs *without* nesting: the full identity map
//!   `0 0 4294967295`. A sandbox measured that way is not the sandbox users run, because
//!   the confinement path it exercises is not the one production depends on.
//!
//! Run it in CI before the suite, and the log states which of the two the run was.
//!
//! # Usage
//!
//! ```text
//! cargo run -p orxnud-platform-sandbox --example preflight
//! cargo run -p orxnud-platform-sandbox --example preflight -- --check
//! cargo run -p orxnud-platform-sandbox --example preflight -- --require
//! ```
//!
//! `--check` exits non-zero unless a Tier-1 capability can be sandboxed here. It is the
//! boolean a test scope decision needs: "may I run the sandbox-evidence suites on this
//! host?"
//!
//! `--require` is stricter and is for a lane whose entire purpose is to execute Tier-1
//! work: it also fails unless the observed sandbox identity is the nested,
//! unprivileged shape. That is what stops a container lane from passing quietly in a
//! configuration stronger than production. It must fail loudly rather than quietly run a
//! reduced suite and pass.

use std::process::ExitCode;

/// `/proc/self/uid_map`, one entry per line, or a note that it could not be read.
///
/// Read rather than inferred, because the inference is exactly the mistake this tool
/// exists to catch: a full identity map means no user namespace was created.
fn uid_map() -> String {
    match std::fs::read_to_string("/proc/self/uid_map") {
        Ok(text) => text
            .lines()
            .map(|l| format!("{l} "))
            .collect::<String>()
            .trim_end()
            .to_owned(),
        // Windows, and any host without procfs. Not an error: the *verdict* comes from
        // the sandbox crate's own probe, and this line is supporting evidence.
        Err(_) => "unavailable on this platform".to_owned(),
    }
}

/// This process's effective capability set, hex, or a note.
fn cap_eff() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("CapEff:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unavailable on this platform".to_owned())
}

fn main() -> ExitCode {
    let require = std::env::args().any(|a| a == "--require");
    // `--check` is the weaker, purely boolean question. Separate from `--require` because
    // a *host* may legitimately be unprivileged and still nest correctly, and a decision
    // about which suites to run must not depend on the container-lane identity check.
    let check = require || std::env::args().any(|a| a == "--check");

    println!("== OpenRayNux sandbox preflight ==");
    println!("   target os:   {}", std::env::consts::OS);
    println!("   uid / gid:   {} / {}", process_uid(), process_gid());

    // The configuration the answer below was obtained in. Printed before the verdict so
    // a reader has it in hand when they read the verdict.
    println!("   uid_map:     {}", uid_map());
    println!("   CapEff:      {}", cap_eff());

    let capability = orxnud_platform_sandbox::host_capability();
    println!("\n{}", capability.report());

    // The signature observed *inside* the probe sandbox. This, not the caller's own
    // uid_map, is what says whether `bwrap` had to nest a user namespace -- and that is
    // the difference between the production configuration and a merely-privileged one.
    //
    // Only `--require` enforces it. A developer host that can sandbox is not required to
    // be running as an unprivileged uid for its own tests to be meaningful.
    let mut nested_shape = false;
    match orxnud_platform_sandbox::linux::BwrapRunner::probe_identity() {
        Some((uid_map, cap_eff)) => {
            println!("\n== sandbox identity, observed inside the probe sandbox ==");
            println!("   uid_map:  {uid_map}");
            println!("   CapEff:   {cap_eff}");
            let nested = uid_map.split_whitespace().count() == 3
                && uid_map.split_whitespace().next() != Some("0")
                && !uid_map.contains("4294967295");
            nested_shape = nested;
            println!(
                "   shape:    {}",
                if nested {
                    "NESTED user namespace -- the production configuration: bwrap had to \
                     create one to gain any capability"
                } else {
                    "NO nested user namespace -- bwrap ran with the caller's own \
                     privileges. This is NOT the production configuration and a sandbox \
                     measured here is not evidence that the production path works."
                }
            );
        }
        None => {
            println!("\n== sandbox identity unavailable: the probe sandbox could not run here ==")
        }
    }

    if capability.tier1_executable {
        println!("\nRESULT: a Tier-1 capability can be sandboxed and executed here.");
        if require && !nested_shape {
            // The dangerous case, and the one that is easy to miss: the probe passed, so
            // every suite in this lane would have run green, but in a configuration no
            // user runs. Failing here is the difference between evidence and a
            // reassuring number.
            println!(
                "\n--require was given and a Tier-1 capability could run, but the sandbox \
                 identity is NOT the unprivileged nested shape. Refusing: a green run in \
                 this configuration is not evidence that the production path works."
            );
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    println!(
        "\nRESULT: a Tier-1 capability CANNOT be sandboxed here. Dispatching one is refused \
         by design (ADR-0035, V-49) -- an unsandboxed Tier-1 capability is worse than no \
         capability. This is a property of the host, not a defect in OpenRayNux."
    );
    if check {
        println!(
            "\n--check was given, so this is a failure for a caller deciding whether it may \
             run Tier-1 work on this host."
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// This process's real uid, read from `/proc/self/status` so no platform-specific API is
/// needed and the value comes from the same source as the capability set above.
#[must_use]
pub fn process_uid() -> String {
    proc_field("Uid:")
}

/// This process's real gid. See [`process_uid`].
#[must_use]
pub fn process_gid() -> String {
    proc_field("Gid:")
}

/// The second whitespace-separated field of the first `/proc/self/status` line starting
/// with `prefix`, or a note that procfs is unavailable.
fn proc_field(prefix: &str) -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(prefix))
                .and_then(|l| l.split_whitespace().nth(1))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unavailable on this platform".to_owned())
}
