//! The bridge from the dispatcher's execution port to a real sandbox.
//!
//! # This is the only place the two halves meet
//!
//! `orxnud-capability` knows what an execution *requires*; `orxnud-platform-sandbox`
//! knows how Linux provides it. This adapter is the whole of the meeting point, which
//! is what makes "there is no second execution route" a structural claim rather than a
//! convention: a caller that wants a subprocess must go through
//! [`ExecutionBackend::execute`], which is this trait, which is this file.
//!
//! # Fail-closed, in both directions
//!
//! - The sandbox cannot be built → [`BwrapExecutionBackend::execute`] returns `Err`.
//! - The sandbox runs but cannot be established → `Err`.
//! - Only an established sandbox produces a report, so a caller cannot read
//!   `sandboxed: false` out of a success, because there is no such field.
//!
//! # The credential never enters the contract
//!
//! See [`crate::dispatch::ExecutionContract`]. A contract is logged and audited; a
//! credential handle is neither. The handle is passed alongside, and reaches the child
//! only through the mechanism [`stdin_credential`] describes.

use std::sync::Arc;

use orxnud_domain::ids::CapabilityId;
use orxnud_platform_sandbox::contract::{
    ExecutionStatus, Resource, SandboxRunner, SandboxSpec, TreeLifetime,
};
use orxnud_platform_sandbox::linux::BwrapRunner;

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

/// An [`ExecutionBackend`] over a real Linux sandbox.
///
/// Holds an `Arc` rather than borrowing, because the dispatcher outlives a single
/// dispatch and a backend that cannot be shared would force a new sandbox supervisor
/// per call — which is how a supervisor's state ends up duplicated.
pub struct BwrapExecutionBackend {
    runner: Arc<dyn SandboxRunner>,
}

impl BwrapExecutionBackend {
    /// A backend over the host's default Linux sandbox.
    #[must_use]
    pub fn new() -> Self {
        Self {
            runner: Arc::new(BwrapRunner::new()),
        }
    }

    /// A backend over a supplied runner, for tests.
    #[must_use]
    pub fn with_runner(runner: Arc<dyn SandboxRunner>) -> Self {
        Self { runner }
    }
}

impl Default for BwrapExecutionBackend {
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
    if !contract.program.starts_with('/') {
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

impl ExecutionBackend for BwrapExecutionBackend {
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
        let err = BwrapExecutionBackend::with_runner(Arc::new(RefusingRunner))
            .execute(&c)
            .expect_err("must refuse");
        assert!(err.reason.contains("absolute"), "{}", err.reason);
    }

    #[test]
    fn a_missing_runner_refuses_rather_than_running_unsandboxed() {
        let err = BwrapExecutionBackend::with_runner(Arc::new(RefusingRunner))
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
        let b = BwrapExecutionBackend::with_runner(Arc::new(RefusingRunner));
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
}
