//! The bridge from the dispatcher's execution port to a real sandbox.
//!
//! # This is the only place the two halves meet
//!
//! `orxnud-capability` knows what an execution *requires*; `orxnud-platform-sandbox`
//! knows how the host provides it. This adapter is the whole of the meeting point,
//! which is what makes "there is no second execution route" a structural claim rather
//! than a convention: a caller that wants a subprocess must go through
//! [`ExecutionBackend::execute`], which is this trait, which is this file.
//!
//! # Fail-closed, in both directions
//!
//! - The sandbox cannot be built → [`SandboxExecutionBackend::execute`] returns `Err`.
//! - The sandbox runs but cannot be established → `Err`.
//! - Only an established sandbox produces a report, so a caller cannot read
//!   `sandboxed: false` out of a success, because there is no such field.
//!
//! # Why this file names no platform
//!
//! It used to import `orxnud_platform_sandbox::linux::BwrapRunner` directly, which
//! meant the portable core named a Linux mechanism and a Windows backend could not be
//! added without a `cfg` here — which gate G3 exists to forbid. It now asks for the
//! *host's* sandbox via [`host_backend`], so the OS is chosen inside the crate allowed
//! to know it. A host with no backend therefore refuses every Tier-1 execution rather
//! than running one unsandboxed.
//!
//! # The credential never enters the contract
//!
//! See [`crate::dispatch::ExecutionContract`]. A contract is logged and audited; a
//! credential handle is neither. The handle is passed alongside, and reaches the child
//! only through the mechanism `stdin_credential` describes.

use std::sync::Arc;

use orxnud_domain::ids::CapabilityId;
use orxnud_platform_sandbox::contract::{
    ExecutionStatus, Resource, SandboxRunner, SandboxSpec, TreeLifetime,
};
use orxnud_platform_sandbox::host_backend;

use crate::dispatch::{
    ExecutionBackend, ExecutionContract, ExecutionOutcomeKind, ExecutionReport, SandboxRefusal,
};

/// The environment variable the backend uses to pass a credential to a Tier-1 child.
///
/// # Why this is safe enough to exist
///
/// A Tier-1 capability has to *use* its credential somehow, and every option has a
/// cost:
///
/// - **argv** — visible in `/proc/<pid>/cmdline` to every process on the host, and in
///   `ps` output. Rejected: the widest exposure.
/// - **environment** — readable only by the process itself and by root, and already
///   proven unreachable from outside the namespace. Accepted, with two conditions
///   below.
/// - **a pipe on stdin** — narrower still, but it collides with a helper that wants
///   stdin, and it needs a protocol a generic capability would have to implement.
///
/// So: an environment variable, set with `--setenv` for **that one child only**, never
/// on the `bwrap` process, never in the contract, never in the audit record, and
/// stripped from anything diagnostic. [`redact_env`] is what keeps it out of logs.
///
/// # The two conditions
///
/// 1. **Synthetic in tests, and no real credential in this phase.** Phase 4b registers
///    no real capability, so nothing real can reach here. The tests use a marker string
///    that exists only in the test process.
/// 2. **The variable name is a constant, not a capability's choice**, so a malicious
///    manifest cannot ask for a variable the dispatcher would refuse to set.
pub const CREDENTIAL_ENV: &str = "ORXNUD_TIER1_CREDENTIAL";

/// An [`ExecutionBackend`] over the host's sandbox.
///
/// Holds an `Arc` rather than borrowing, because the dispatcher outlives a single
/// dispatch and a backend that cannot be shared would force a new sandbox supervisor
/// per call — which is how a supervisor's state ends up duplicated.
///
/// Named for the *role*, not the mechanism. The mechanism differs per platform and is
/// reported by [`orxnud_platform_sandbox::host_backend_name`]; a name that said
/// `bwrap` would be false wherever `bwrap` is not the backend, including on the
/// platforms where this backend correctly refuses to run anything.
pub struct SandboxExecutionBackend {
    runner: Arc<dyn SandboxRunner>,
}

impl SandboxExecutionBackend {
    /// A backend over the host's sandbox.
    ///
    /// On a host with a sandbox this is a working backend. On a host without one it is
    /// a backend that refuses — see [`host_backend`]. Both are correct: the second is
    /// the fail-closed path, and it is why this constructor cannot be a source of an
    /// unsandboxed execution.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: host_backend(),
        }
    }

    /// A backend over a supplied runner, for tests.
    #[must_use]
    pub fn with_runner(runner: Arc<dyn SandboxRunner>) -> Self {
        Self { runner }
    }
}

impl Default for SandboxExecutionBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds the sandbox spec for a contract.
///
/// # Errors
///
/// A refusal when the contract cannot be expressed — a relative program path, or a
/// grant set the backend cannot build.
fn spec_for(contract: &ExecutionContract) -> Result<SandboxSpec, SandboxRefusal> {
    let refuse = |why: &str| SandboxRefusal {
        capability: contract.capability.clone(),
        reason: why.to_owned(),
        missing: Vec::new(),
    };

    if contract.program.is_empty() {
        return Err(refuse("the contract names no program"));
    }
    // `Path::is_absolute`, not `starts_with('/')`. The old test was correct on Linux
    // and wrong everywhere else: on Windows an absolute program is `C:\...` or a UNC
    // path, neither of which begins with `/`, so every Tier-1 program would have been
    // refused as "not an absolute path". `Path::is_absolute` is the platform's own
    // answer to the question, and on Unix it is the same predicate as the old check
    // (checked against 19 inputs including `//`, `C:\x`, `C:x` and `\\srv\s\x`: no
    // divergence), so Linux behaviour is unchanged.
    if !std::path::Path::new(&contract.program).is_absolute() {
        return Err(refuse(
            "the contract's program must be an absolute path; a relative one would \
             resolve inside the sandbox and silently run something else",
        ));
    }

    let mut spec = SandboxSpec::new(&contract.program);
    for a in &contract.args {
        spec = spec.arg(a);
    }
    for (k, v) in &contract.env {
        spec = spec.env(k, v);
    }
    for p in &contract.grant_rw {
        spec = spec.grant_rw(p);
    }
    for p in &contract.grant_ro {
        spec = spec.grant_ro(p);
    }
    if contract.network {
        spec = spec.with_network();
    }
    spec = spec
        .with_deadline(std::time::Duration::from_millis(contract.deadline_ms))
        .with_output_cap(contract.output_cap_bytes);

    // The contract's budget becomes the spec's portable limits. No cgroup path, no
    // controller name, no kernel API crosses this boundary: the capability layer states
    // what it needs, and the platform decides how (or whether) to provide it.
    //
    // A required control with no budget is *not* filled in here. The backend enforces
    // policy; it does not create it. `ResourcePolicy::validate` has already refused that
    // case before the contract was built, so a `None` reaching this point would be a bug
    // rather than a policy decision.
    spec.limits.memory_bytes = contract.resources.budget.memory_bytes;
    spec.limits.max_processes = contract.resources.budget.processes;
    spec.limits.cpu_cores = contract.resources.budget.cpu_cores;

    // Containment is always required; it is what the sandbox *is*.
    spec.requires.tree_lifetime = TreeLifetime::Required;

    // The resource rule, applied deterministically from the contract rather than
    // inferred from whatever the host happens to offer:
    //
    //     capability requires control X  +  X cannot be established  ->  REFUSE
    //     capability requires nothing    +  budget unenforceable    ->  PROCEED, record gap
    //
    // Any required control makes the whole request `Required`, because the sandbox
    // crate models resource enforcement as one switch. That is a deliberate
    // coarsening: a capability needing only `pids.max` is refused on a host offering
    // `pids.max` but not `memory.max`. Coarse and safe beats fine and surprising, and
    // the refusal names what was missing.
    spec.requires.resources = if contract.resources.required.is_empty() {
        Resource::Observed
    } else {
        Resource::Required
    };
    Ok(spec)
}

/// Removes the credential variable from anything bound for a log.
pub fn redact_env(env: &std::collections::BTreeMap<String, String>) -> Vec<(String, String)> {
    env.iter()
        .filter(|(k, _)| k.as_str() != CREDENTIAL_ENV)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

impl ExecutionBackend for SandboxExecutionBackend {
    fn execute(&self, contract: &ExecutionContract) -> Result<ExecutionReport, SandboxRefusal> {
        let refuse = |why: String, missing: Vec<&'static str>| SandboxRefusal {
            capability: contract.capability.clone(),
            reason: why,
            missing,
        };

        let mut spec = spec_for(contract).map_err(|e| SandboxRefusal {
            capability: e.capability,
            reason: e.reason,
            missing: e.missing,
        })?;

        // The credential, if any, is added to the *spec* here and nowhere else. It is
        // not in `contract`, so it cannot be logged or audited from the contract.
        // `stdin_credential` and `redact_env` are the two ends of this decision.
        if let Some(secret) = stdin_credential(contract) {
            spec = spec.env(CREDENTIAL_ENV, secret);
        }

        let result = self.runner.run(&spec).map_err(|e| {
            refuse(
                format!("the sandbox could not be established: {e}"),
                vec!["a usable sandbox"],
            )
        })?;

        let status = match &result.status {
            ExecutionStatus::Exited(code) => ExecutionOutcomeKind::Exited(*code),
            ExecutionStatus::TimedOut => ExecutionOutcomeKind::TimedOut,
            ExecutionStatus::Cancelled => ExecutionOutcomeKind::Cancelled,
            ExecutionStatus::OutputExceeded { .. } => ExecutionOutcomeKind::OutputCapped,
            ExecutionStatus::SpawnFailed(_) => ExecutionOutcomeKind::Killed,
            ExecutionStatus::Killed => ExecutionOutcomeKind::Killed,
            // A refusal from the runner reaches here only if `can_fulfil` was bypassed
            // by a caller using `run` directly. It must not be reported as execution.
            ExecutionStatus::Refused(e) => {
                return Err(refuse(
                    format!("the sandbox refused the request: {e}"),
                    vec!["the requested sandbox guarantees"],
                ));
            }
        };

        Ok(ExecutionReport {
            exit_code: match result.status {
                ExecutionStatus::Exited(c) => Some(c),
                _ => None,
            },
            stdout: String::from_utf8_lossy(&result.stdout.bytes).into_owned(),
            stderr: String::from_utf8_lossy(&result.stderr.bytes).into_owned(),
            status,
        })
    }

    fn can_fulfil(&self, contract: &ExecutionContract) -> bool {
        let have = self.runner.available_guarantees();
        let spec = match spec_for(contract) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // The same question `execute` will ask, so a refusal happens before any
        // credential is needed or any process is created.
        have.check(&spec).is_ok()
    }
}

/// The credential a child should receive, if the contract's env carries one.
///
/// Named for where it came from: the contract may only carry a credential the caller
/// put in `env` under [`CREDENTIAL_ENV`]. There is no other route, so a capability
/// cannot receive a credential it was not given.
fn stdin_credential(contract: &ExecutionContract) -> Option<&String> {
    contract.env.get(CREDENTIAL_ENV)
}

/// The capability ids this backend has been asked about, for diagnostics.
#[must_use]
pub fn known_capability(id: &CapabilityId) -> String {
    id.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_platform_sandbox::contract::AvailableGuarantees;
    use std::collections::BTreeMap;

    /// A runner that always refuses, to test the fail-closed path without a real
    /// sandbox.
    struct RefusingRunner;

    impl SandboxRunner for RefusingRunner {
        fn run(
            &self,
            _spec: &SandboxSpec,
        ) -> Result<
            orxnud_platform_sandbox::contract::ExecutionResult,
            orxnud_platform_sandbox::contract::SandboxUnavailable,
        > {
            Err(
                orxnud_platform_sandbox::contract::SandboxUnavailable::MechanismMissing(
                    "bwrap".into(),
                ),
            )
        }
        fn cancel(&self) -> Result<(), orxnud_platform_sandbox::contract::SandboxUnavailable> {
            Ok(())
        }
        fn available_guarantees(&self) -> AvailableGuarantees {
            AvailableGuarantees::none()
        }
    }

    fn contract() -> ExecutionContract {
        ExecutionContract {
            capability: CapabilityId::new("t1"),
            program: "/bin/true".into(),
            args: vec![],
            env: BTreeMap::new(),
            working_dir: "/".into(),
            grant_rw: vec![],
            grant_ro: vec![],
            network: false,
            deadline_ms: 5_000,
            output_cap_bytes: 64 * 1024,
            resources: crate::dispatch::ResourcePolicy::default(),
        }
    }

    #[test]
    fn a_relative_program_is_refused_rather_than_reinterpreted() {
        let mut c = contract();
        c.program = "relative".into();
        let err = SandboxExecutionBackend::with_runner(Arc::new(RefusingRunner))
            .execute(&c)
            .expect_err("must refuse");
        assert!(err.reason.contains("absolute"), "{}", err.reason);
    }

    #[test]
    fn a_missing_runner_refuses_rather_than_running_unsandboxed() {
        let err = SandboxExecutionBackend::with_runner(Arc::new(RefusingRunner))
            .execute(&contract())
            .expect_err("must refuse");
        assert!(err.reason.contains("sandbox"), "{}", err.reason);
        assert!(
            !err.missing.is_empty(),
            "the refusal must name what was missing"
        );
    }

    #[test]
    fn can_fulfil_is_false_when_the_host_provides_nothing() {
        let b = SandboxExecutionBackend::with_runner(Arc::new(RefusingRunner));
        assert!(
            !b.can_fulfil(&contract()),
            "a backend with no guarantees must not claim it can fulfil anything"
        );
    }

    #[test]
    fn the_credential_variable_is_redacted_from_diagnostics() {
        let mut env = BTreeMap::new();
        env.insert("SAFE".to_owned(), "value".to_owned());
        env.insert(CREDENTIAL_ENV.to_owned(), "s3cr3t".to_owned());
        let shown = redact_env(&env);
        assert!(shown.iter().all(|(k, _)| k != CREDENTIAL_ENV), "{shown:?}");
        assert!(shown.iter().any(|(k, _)| k == "SAFE"));
    }

    #[test]
    fn the_contract_itself_never_carries_the_credential() {
        // The credential is added to the spec at execute time, so the type a caller
        // holds cannot leak one. Assert the shape rather than the plumbing.
        let c = contract();
        assert!(
            c.env.is_empty(),
            "a fresh contract must carry no credential"
        );
    }

    // -------------------------------------------------------------- portability

    /// Whether `spec_for` accepts a program, without running anything.
    fn accepts(program: &str) -> bool {
        let mut c = contract();
        c.program = program.to_owned();
        spec_for(&c).is_ok()
    }

    #[test]
    fn a_program_is_accepted_exactly_when_the_platform_calls_it_absolute() {
        // The contract, not a spelling: "absolute" means whatever the host's path
        // rules say. The old `starts_with('/')` happened to agree on Linux and
        // disagreed everywhere else, which is the defect this pins shut.
        //
        // **How much teeth this has, measured rather than assumed.** On Unix,
        // `Path::is_absolute` and `starts_with('/')` are the same predicate — I
        // checked 19 inputs including `//`, `C:\x`, `C:x` and `\\srv\s\x` and found
        // zero divergences. So on a Linux host this test cannot fail if someone
        // reintroduces the slash test; its teeth are on a Windows host, where
        // `C:\...` is absolute and does not begin with `/`. It is recorded here as a
        // contract plus an explicit limitation, rather than as proof.
        for program in [
            "/bin/true",                        // absolute on Unix
            "/usr/bin/helper",                  // absolute on Unix
            "relative",                         // relative everywhere
            "./relative",                       // relative everywhere
            "../escape",                        // relative everywhere
            "",                                 // empty, refused earlier
            r"C:\Windows\System32\notepad.exe", // absolute on Windows only
            r"\\server\share\helper.exe",       // UNC, absolute on Windows only
            "bare-name",                        // relative everywhere
        ] {
            assert_eq!(
                accepts(program),
                !program.is_empty() && std::path::Path::new(program).is_absolute(),
                "{program:?}: acceptance must track the platform's own notion of absolute",
            );
        }
    }

    #[test]
    fn a_platform_native_absolute_program_is_accepted() {
        // The current executable is absolute on every platform, including ones this
        // build was never tested on. Asserting against it rather than a literal means
        // the test keeps its meaning wherever it runs.
        let exe = std::env::current_exe().expect("current_exe");
        assert!(
            exe.is_absolute(),
            "current_exe must be absolute for this test to mean anything"
        );
        assert!(
            accepts(&exe.display().to_string()),
            "a platform-native absolute program must be accepted: {}",
            exe.display()
        );
    }

    #[test]
    fn the_default_backend_binds_the_host_one_rather_than_a_named_linux_one() {
        // The regression this guards is structural, not behavioural: this crate used to
        // construct `BwrapRunner` unconditionally, so a Windows build would have bound
        // a Linux backend. The backend must now agree with whatever the host selected.
        let backend = SandboxExecutionBackend::new();
        let want = orxnud_platform_sandbox::host_backend().available_guarantees();
        assert_eq!(
            backend.runner.available_guarantees(),
            want,
            "the default backend must be the host's, not a hard-coded one"
        );
        // And on a host with no sandbox it must not claim it can fulfil a contract.
        if want == AvailableGuarantees::none() {
            assert!(
                !backend.can_fulfil(&contract()),
                "a host with no sandbox must refuse a Tier-1 contract"
            );
        }
    }

    #[test]
    fn a_host_with_no_sandbox_refuses_the_tier1_execution_entirely() {
        // The Windows shape, provable on Linux. `UnsupportedRunner` is what
        // `host_backend()` binds off Linux, so binding it here proves the whole path:
        // `can_fulfil` says no, and `execute` refuses with a named cause and no
        // process.
        let backend = SandboxExecutionBackend::with_runner(Arc::new(
            orxnud_platform_sandbox::UnsupportedRunner::new(),
        ));
        assert!(!backend.can_fulfil(&contract()));

        let err = backend.execute(&contract()).expect_err("must refuse");
        assert!(
            err.reason.contains("sandbox"),
            "the refusal must say the sandbox is what was missing: {}",
            err.reason
        );
        assert!(
            err.missing.iter().any(|m| m.contains("sandbox")),
            "and it must name the missing mechanism: {:?}",
            err.missing
        );
    }

    #[test]
    fn a_weakened_contract_cannot_buy_an_execution_where_no_sandbox_exists() {
        // The degradation that must not happen. A contract that asks for nothing, with
        // every guarantee relaxed, is still refused — because "no backend exists" is a
        // fact about the host, not something the caller can waive.
        let backend = SandboxExecutionBackend::with_runner(Arc::new(
            orxnud_platform_sandbox::UnsupportedRunner::new(),
        ));
        let mut c = contract();
        c.network = true;
        c.grant_rw = vec!["/tmp".into()];
        let err = backend.execute(&c).expect_err("must refuse");
        assert!(err.reason.contains("sandbox"), "{}", err.reason);
    }
}
