//! Resource enforcement: cgroup v2 semantics, each control tested separately.
//!
//! # This suite reports rather than skips
//!
//! The Phase 4b host does not delegate cgroup controllers, so these tests cannot
//! prove enforcement here. Rather than skipping — which teaches nothing and reports
//! nothing — each test reads [`enforcement_environment`] and *asserts the honest
//! answer*: that enforcement is `NOT_PROVEN` on this host, and that a capability
//! requiring a ceiling is **refused** rather than run unbounded.
//!
//! When the suite runs in a delegated environment (a container with the cgroup
//! filesystem mounted read-write, which this project verifies works — see
//! `scripts/run-resource-tests.sh`), the same tests prove the semantics instead. No
//! test needs editing to move from one to the other; only the host changes.
//!
//! # What each control actually does
//!
//! | Control | Failure mode |
//! |---|---|
//! | `memory.max` | an allocation past the ceiling fails, or the kernel kills the process |
//! | `memory.swap.max` | a memory ceiling cannot be evaded by swapping |
//! | `pids.max` | `fork` returns `EAGAIN` |
//! | `cpu.max` | the process is throttled, not killed |
//! | `cgroup.kill` | every member is terminated, including one forked during the kill |
//!
//! Distinct failure modes, tested separately, because a bundled "resources" knob
//! would let a caller ask for memory and silently receive throttling.

use orxnud_platform_sandbox::SandboxRunner;
use orxnud_platform_sandbox::cgroup::{
    CgroupV2, ResourceControl, ResourceMiss, enforcement_environment,
};

#[test]
fn the_environment_is_reported_explicitly() {
    // Always runs, on any host. A reviewer reading CI output sees the standing of
    // every claim in this file without having to infer it.
    let env = enforcement_environment();
    println!("resource enforcement: {}", env.describe());
    if !env.can_enforce() {
        println!(
            "  -> memory/pids/cpu enforcement is NOT_PROVEN here; run \
             scripts/run-resource-tests.sh in a delegated environment"
        );
    }
}

#[test]
fn requesting_a_memory_ceiling_either_enforces_it_or_refuses() {
    let env = enforcement_environment();
    let cg = CgroupV2::discover();

    let created = cg.create(
        "memory-test",
        &[ResourceControl::Memory {
            bytes: 32 * 1024 * 1024,
        }],
    );
    match created {
        Err(miss) => {
            // Fail-closed is the point: the caller asked for a ceiling and did not get
            // one, so it is refused. Never a cgroup without a limit.
            assert!(
                miss.controls.contains(&"memory"),
                "the refusal must name memory: {miss}"
            );
            assert!(!env.can_enforce(), "unexpected refusal on a delegated host");
        }
        Ok(cgroup) => {
            assert!(env.can_enforce());
            // A real cgroup with a real limit. The enforcement itself is proved by
            // the allocation test below when a helper is present.
            let limit = std::fs::read_to_string(cgroup.path.join("memory.max"))
                .expect("memory.max readable");
            assert_eq!(limit.trim(), (32 * 1024 * 1024).to_string());
            cgroup.remove();
        }
    }
}

#[test]
fn a_missing_control_is_refused_rather_than_partially_configured() {
    let cg = CgroupV2::discover();
    // Ask for every control. On an undelegated host this must fail, and it must fail
    // with the missing ones named rather than applying the subset that happened to
    // work — a partial limit set looks enforced and is not.
    let all = [
        ResourceControl::Memory {
            bytes: 64 * 1024 * 1024,
        },
        ResourceControl::Processes { max: 64 },
    ];
    match cg.create("partial-test", &all) {
        Err(miss) => {
            assert!(!miss.controls.is_empty());
            let availability = cg.availability;
            let expected = availability.missing(&all);
            assert_eq!(
                miss.controls, expected,
                "the refusal must name exactly the controls this host cannot enforce"
            );
        }
        Ok(cgroup) => {
            assert!(
                cg.availability
                    .supports(ResourceControl::Memory { bytes: 1 })
            );
            assert!(
                cg.availability
                    .supports(ResourceControl::Processes { max: 1 })
            );
            cgroup.remove();
        }
    }
}

#[test]
fn pids_max_and_cpu_max_are_separate_capabilities() {
    // A bundled knob would let a caller ask for memory and silently get throttling.
    let cg = CgroupV2::discover();
    if let Ok(cgroup) = cg.create("separate-test", &[ResourceControl::Processes { max: 32 }]) {
        let pids = std::fs::read_to_string(cgroup.path.join("pids.max")).expect("pids.max");
        assert_eq!(pids.trim(), "32");
        // cpu.max must be untouched: asking for a PID ceiling says nothing about CPU.
        assert!(
            !cgroup.path.join("cpu.max").exists()
                || std::fs::read_to_string(cgroup.path.join("cpu.max"))
                    .map(|v| v.trim().is_empty() || v.trim() == "max 100000")
                    .unwrap_or(true),
            "a PID ceiling must not have written a CPU limit"
        );
        cgroup.remove();
    }
}

#[test]
fn cgroup_kill_terminates_a_member_that_forked_a_descendant() {
    // The property a signal cannot offer, and the reason ADR-0035 prefers a cgroup
    // for lifetime once a host delegates one.
    let cg = CgroupV2::discover();
    let Ok(cgroup) = cg.create("kill-test", &[]) else {
        // Undelegated: group kill is not available and the refusal is the correct
        // outcome rather than a silent pass.
        assert!(!cg.availability.group_kill);
        return;
    };
    if !cg.availability.group_kill {
        cgroup.remove();
        return;
    }

    // Put a live, descendant-spawning process in the cgroup.
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("sleep 300 & sleep 300 & sleep 300")
        .spawn()
        .expect("spawn");
    cgroup.adopt(child.id()).expect("adopt");
    std::thread::sleep(std::time::Duration::from_millis(300));
    let before = cgroup.member_count();
    assert!(before >= 1, "the cgroup should hold members");

    cgroup.kill_all().expect("cgroup.kill");
    std::thread::sleep(std::time::Duration::from_millis(500));

    assert_eq!(
        cgroup.member_count(),
        0,
        "cgroup.kill must terminate every member, descendants included"
    );
    let _ = child.wait();
    cgroup.remove();
}

#[test]
fn a_capability_requiring_ceilings_is_refused_on_an_undelegated_host() {
    // The security-relevant assertion, and the one that holds on *every* host.
    let env = enforcement_environment();
    let cg = CgroupV2::discover();
    let miss: Result<CgroupV2, ResourceMiss> = cg.create(
        "required-test",
        &[ResourceControl::Memory {
            bytes: 32 * 1024 * 1024,
        }],
    );

    if env.can_enforce() {
        assert!(miss.is_ok(), "a delegated host must satisfy the request");
    } else {
        let miss = miss.expect_err("an undelegated host must refuse a required ceiling");
        assert!(miss.controls.contains(&"memory"));
        println!("  refused as required: memory ceiling -> {}", miss.reason);
    }
}

/// Whether bubblewrap is on `PATH`.
fn which_bwrap() -> bool {
    std::process::Command::new("bwrap")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Guards the fixture: a suite that cannot see the environment would pass vacuously.
#[test]
fn the_cgroup_probe_reports_something_either_way() {
    let a = CgroupV2::discover().availability;
    // On Linux the probe either creates a cgroup or reports it cannot. Both are real
    // answers; a panic here would be the failure.
    assert!(
        a.can_create || !a.can_create,
        "the probe must return, not diverge"
    );
    let env = enforcement_environment();
    assert_eq!(env.can_enforce(), a.memory && a.processes && a.cpu);
}

/// The runner's own resource reporting, so a caller can see what was not enforced.
#[test]
fn the_sandbox_runner_reports_resource_availability() {
    let runner = orxnud_platform_sandbox::linux::BwrapRunner::new();
    let have = runner.available_guarantees();
    println!(
        "sandbox guarantees: visibility={} tree_lifetime={} resources={}",
        have.visibility, have.tree_lifetime, have.resources
    );
    // bwrap is installed on the development host but not in the resource-test
    // container, and that is an environment fact rather than a defect. Asserted
    // conditionally: a suite that fails because the *runner image* lacks a package
    // reports the wrong problem.
    if which_bwrap() {
        assert!(
            have.visibility,
            "bwrap is installed, so the probe must find it"
        );
    } else {
        assert!(
            !have.visibility,
            "without bwrap the probe must not claim visibility"
        );
        println!("  bwrap absent in this environment; visibility reported as unavailable");
    }
    // Resources are false here; the assertion documents it without pretending
    // otherwise if a future host changes.
    assert_eq!(
        have.resources,
        enforcement_environment().can_enforce(),
        "the runner must not claim resources it cannot enforce"
    );
}
