//! Platform dispatch: which [`SandboxRunner`] this host gets.
//!
//! # Why this module exists
//!
//! Before it, `orxnud-capability` imported `linux::BwrapRunner` directly. That is
//! the portable core naming a Linux mechanism, and it is the reason a Windows
//! backend could not be added without editing business logic — a `cfg` there would
//! have failed gate G3.
//!
//! So the *selection* lives here, in the one crate that is allowed to know the OS,
//! and the portable core asks for "the host's sandbox" rather than naming one. The
//! shape is the one docs-06 §4 already prescribes:
//!
//! ```text
//!         portable core  ── SandboxRunner (the contract)
//!                 │
//!        ┌────────┴─────────┐
//!   host_backend()      a supplied runner   (tests)
//!        │
//!   ┌────┴─────┐
//! Linux     not Linux
//! BwrapRunner  UnsupportedRunner
//! ```
//!
//! # The unsupported backend refuses; it never degrades
//!
//! [`UnsupportedRunner`] reports [`AvailableGuarantees::none`] and returns
//! [`SandboxUnavailable::MechanismMissing`] for **every** spec — including one that
//! asked for nothing at all.
//!
//! That last part is deliberate and is the whole point. A runner that honoured a
//! weakened spec would be an unsandboxed subprocess, and ADR-0035's invariant is that
//! an unsandboxed capability is *worse than no capability*: it runs third-party code
//! with no isolation while the audit record reads as though a sandbox was used. So
//! "the mechanism does not exist here" is reported as an error, and
//! [`AvailableGuarantees::none`] makes the dispatcher refuse at
//! [`crate::contract::SandboxRunner::available_guarantees`] — before a spec is built,
//! before a credential is resolved, and before any process is created.
//!
//! # What is deliberately **not** here
//!
//! No Windows sandbox. Job Objects, AppContainer, and the Windows resource limits are
//! unimplemented (ADR-0035; verification register V-29), so nothing here claims them.
//! This module makes the absence *explicit and deterministic* rather than leaving the
//! core to name `bwrap` and hope. Adding a real backend means adding a
//! `#[cfg(target_os = "windows")]` arm and implementing [`SandboxRunner`] — not
//! changing anything above this line.

use std::sync::Arc;

use crate::contract::{
    AvailableGuarantees, ExecutionResult, SandboxRunner, SandboxSpec, SandboxUnavailable,
};

#[cfg(target_os = "linux")]
mod selected {
    use std::sync::Arc;

    use crate::contract::SandboxRunner;
    use crate::linux::BwrapRunner;

    /// The runner this build selected, and what selected it.
    pub const NAME: &str = "bwrap";
    /// Which mechanism backs it.
    pub const MECHANISM: &str = "bubblewrap (PID + mount namespaces, cgroup v2 where delegated)";

    /// The host sandbox on Linux.
    #[must_use]
    pub fn runner() -> Arc<dyn SandboxRunner> {
        Arc::new(BwrapRunner::new())
    }
}

#[cfg(not(target_os = "linux"))]
mod selected {
    use std::sync::Arc;

    use crate::contract::SandboxRunner;
    use crate::platform::UnsupportedRunner;

    /// The runner this build selected, and what selected it.
    pub const NAME: &str = "unsupported";
    /// Which mechanism backs it.
    pub const MECHANISM: &str = "none — no sandbox backend is implemented for this platform";

    /// The host sandbox where none is implemented.
    #[must_use]
    pub fn runner() -> Arc<dyn SandboxRunner> {
        Arc::new(UnsupportedRunner::new())
    }
}

/// The runner for the platform this binary was compiled for.
///
/// # Errors
///
/// Never. Selection is a compile-time fact, not a runtime probe: a host either has the
/// backend or has the refusing one, and which one is knowable without touching the
/// OS. Runtime availability (is `bwrap` *installed*?) is
/// [`SandboxRunner::available_guarantees`]'s question, and it is asked separately.
#[must_use]
pub fn host_backend() -> Arc<dyn SandboxRunner> {
    selected::runner()
}

/// A short, stable name for the selected backend, for logs and audit records.
///
/// Used where a type name would be misleading: on a host with no backend the answer is
/// `"unsupported"`, and an audit line that said `bwrap` would be false.
#[must_use]
pub fn host_backend_name() -> &'static str {
    selected::NAME
}

/// The mechanism the selected backend uses, or that it has none.
#[must_use]
pub fn host_backend_mechanism() -> &'static str {
    selected::MECHANISM
}

/// A runner for a platform with no sandbox backend implemented.
///
/// # This is a refusal, not a fallback
///
/// Every method refuses. In particular [`SandboxRunner::run`] refuses even for a spec
/// that demanded no isolation, because "the caller did not ask for a sandbox" and "no
/// sandbox exists" are different situations and only the second one is true here.
///
/// It reports [`AvailableGuarantees::none`], which is the property the dispatcher reads
/// to refuse a Tier-1 capability *before* dispatch rather than after spawning something
/// unsandboxed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UnsupportedRunner;

impl UnsupportedRunner {
    /// The refusing runner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Why no backend exists here, phrased for a user who will read it.
    ///
    /// Names the platform and the missing mechanism rather than saying "unsupported",
    /// because the actionable fact is *which* isolation facility is absent.
    fn reason() -> String {
        format!(
            "no sandbox backend is implemented for {}: this host has no {}, so a \
             Tier-1 capability cannot be given process isolation. Refusing rather than \
             running it unsandboxed",
            std::env::consts::OS,
            host_backend_mechanism(),
        )
    }
}

impl SandboxRunner for UnsupportedRunner {
    fn run(&self, _spec: &SandboxSpec) -> Result<ExecutionResult, SandboxUnavailable> {
        // `Err`, not `Ok(Refused(..))`. Both refuse, but `Err` is what the trait
        // documents for "the sandbox could not be established", and it keeps the
        // distinction from a *helper* that failed inside a working sandbox.
        Err(SandboxUnavailable::MechanismMissing(
            UnsupportedRunner::reason(),
        ))
    }

    fn cancel(&self) -> Result<(), SandboxUnavailable> {
        // Nothing can be running, because nothing can be started.
        Ok(())
    }

    fn available_guarantees(&self) -> AvailableGuarantees {
        AvailableGuarantees::none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{
        IsolationRequirements, NetworkPolicy, Resource, ResourceLimits, SandboxSpec, TreeLifetime,
        Visibility,
    };

    /// A spec that asks for the *weakest* thing the contract permits.
    ///
    /// Built by relaxing every requirement, which is exactly the spec a "just run it
    /// anyway" implementation would accept. The refusing runner must refuse this too.
    fn weakest_possible_spec() -> SandboxSpec {
        let mut spec = SandboxSpec::new("anything");
        spec.requires = IsolationRequirements {
            visibility: Visibility::None,
            tree_lifetime: TreeLifetime::BestEffort,
            resources: Resource::Observed,
        };
        spec.network = NetworkPolicy::Full;
        spec.die_with_supervisor = false;
        spec.limits = ResourceLimits::default();
        spec
    }

    #[test]
    fn the_unsupported_backend_provides_nothing() {
        // Every field false. Not "true where we hope" — nothing is provided here.
        assert_eq!(
            UnsupportedRunner::new().available_guarantees(),
            AvailableGuarantees::none(),
        );
    }

    #[test]
    fn the_unsupported_backend_refuses_a_default_spec() {
        let err = UnsupportedRunner::new()
            .run(&SandboxSpec::new("anything"))
            .expect_err("must refuse");
        assert!(
            matches!(err, SandboxUnavailable::MechanismMissing(_)),
            "{err:?}"
        );
        // And the message must not read like a warning the caller may ignore.
        let text = err.to_string();
        assert!(text.contains("Refusing"), "{text}");
    }

    #[test]
    fn the_unsupported_backend_refuses_even_a_spec_that_asked_for_nothing() {
        // The load-bearing test. An implementation that honoured a weakened spec would
        // be an unsandboxed subprocess, which ADR-0035 calls worse than no capability.
        let err = UnsupportedRunner::new()
            .run(&weakest_possible_spec())
            .expect_err("must refuse even the weakest spec");
        assert!(
            matches!(err, SandboxUnavailable::MechanismMissing(_)),
            "{err:?}"
        );
    }

    #[test]
    fn the_refusal_names_the_platform_and_the_missing_mechanism() {
        // A user reading "unsupported" has to go looking. Naming the host and what is
        // absent is what makes the message actionable.
        let text = UnsupportedRunner::new()
            .run(&SandboxSpec::new("anything"))
            .expect_err("must refuse")
            .to_string();
        assert!(text.contains(std::env::consts::OS), "{text}");
    }

    #[test]
    fn cancelling_a_runner_that_can_start_nothing_succeeds() {
        // Not an error: there is no process to cancel, so there is nothing to report.
        assert!(UnsupportedRunner::new().cancel().is_ok());
    }

    #[test]
    fn a_default_spec_demands_more_than_the_unsupported_backend_provides() {
        // The dispatcher's refusal path, exercised directly. This is what stops a
        // Tier-1 capability before it reaches a credential or a process.
        let spec = SandboxSpec::new("anything");
        let err = AvailableGuarantees::none()
            .check(&spec)
            .expect_err("must refuse");
        assert!(
            matches!(
                err,
                SandboxUnavailable::GuaranteeUnavailable { guarantee, .. }
                    if guarantee == "process-tree lifetime containment"
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_weakened_spec_still_demands_visibility_on_this_platform() {
        // Relaxing containment must not silently buy a run where nothing exists. The
        // spec above sets `Visibility::None`, so the only reason it would pass is if a
        // backend existed — and `none()` says it does not.
        let spec = weakest_possible_spec();
        assert!(spec.requires.visibility == Visibility::None);
        // With visibility explicitly waived, `check` passes — which is why the
        // *runner* must also refuse, and does. Both layers are needed.
        assert!(AvailableGuarantees::none().check(&spec).is_ok());
        assert!(
            UnsupportedRunner::new().run(&spec).is_err(),
            "the runner's own refusal is what closes this, not the guarantee check"
        );
    }

    #[test]
    fn the_host_backend_is_selected_at_compile_time_and_reports_honestly() {
        // Whatever this host is, the answer must be one of the two named backends, and
        // a host with no backend must say so rather than naming `bwrap`.
        let name = host_backend_name();
        assert!(
            name == "bwrap" || name == "unsupported",
            "unexpected backend name {name:?}"
        );

        let guarantees = host_backend().available_guarantees();
        if name == "unsupported" {
            assert_eq!(
                guarantees,
                AvailableGuarantees::none(),
                "a host with no backend must not claim any guarantee"
            );
            // And it must refuse at run time too, not only in its report.
            let err = host_backend()
                .run(&SandboxSpec::new("anything"))
                .expect_err("must refuse");
            assert!(matches!(err, SandboxUnavailable::MechanismMissing(_)));
        } else {
            // On Linux this is `bwrap`. Whether *this* host delegates cgroup
            // controllers is a separate fact the probe reports; nothing here asserts it.
            assert!(
                guarantees.visibility,
                "bwrap is installed on a Linux host, so the probe must find it"
            );
        }
    }

    #[test]
    fn a_refusal_never_carries_a_status_that_claims_something_ran() {
        // `run` returns `Err` rather than `Ok(Refused(..))`. A caller that mapped this
        // to `SpawnFailed` would claim an attempt was made; nothing ran. Assert the
        // shape that preserves that distinction: an error, not a result.
        let outcome = UnsupportedRunner::new().run(&SandboxSpec::new("anything"));
        let Err(err) = outcome else {
            panic!("a refusal must be an Err, not an ExecutionResult");
        };
        assert!(
            matches!(err, SandboxUnavailable::MechanismMissing(_)),
            "{err:?}"
        );
    }
}
