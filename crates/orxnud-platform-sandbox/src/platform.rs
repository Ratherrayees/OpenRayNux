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

/// What this host can actually guarantee for a Tier-1 execution.
///
/// # Why this is a reported fact and not a probe of its own
///
/// It reads [`host_backend`]'s own [`SandboxRunner::available_guarantees`] and runs the
/// same [`AvailableGuarantees::check`] the dispatcher runs. It adds **no** second
/// probing path, which is the whole point: a diagnostic that re-derived the answer
/// could disagree with the dispatch that refused a capability, and then the log would
/// explain a refusal that happened for a different reason.
///
/// # Why `tier1_executable` is the field to read
///
/// [`host_backend_name`] is a *compile-time* fact. It answers "which backend did this
/// build select", so on Linux it says `bwrap` on a host where `bwrap` cannot create a
/// user namespace and every Tier-1 dispatch is refused. That gap is how a red CI run and
/// a `doctor` line reading `sandbox backend: bwrap` coexisted with zero sandboxed
/// execution. [`HostCapability::tier1_executable`] is the runtime answer, and it is the
/// one that decides whether work runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCapability {
    /// Which backend the build selected. Compile-time.
    pub backend: &'static str,
    /// Which mechanism backs it, or that it has none.
    pub mechanism: &'static str,
    /// What the host provides right now, as the runner itself reports it.
    pub guarantees: AvailableGuarantees,
    /// Whether a Tier-1 dispatch can be fulfilled on this host.
    ///
    /// [`AvailableGuarantees::check`] against the *default*
    /// [`crate::contract::IsolationRequirements`] — `Visibility::Namespaced` plus
    /// `TreeLifetime::Required`, which is what every Tier-1 contract asks for before a
    /// capability adds anything. So `false` means a Tier-1 capability is refused here,
    /// and that refusal is correct rather than a defect.
    pub tier1_executable: bool,
}

impl HostCapability {
    /// A one-block report for a log line, `doctor`, or a CI banner.
    ///
    /// States the verdict and the reason together, because "sandbox available: no"
    /// without the reason sends the reader to the wrong layer.
    #[must_use]
    pub fn report(&self) -> String {
        let verdict = if self.tier1_executable {
            "yes"
        } else {
            "no (Tier-1 capabilities are refused here; this is correct, not a fault)"
        };
        format!(
            "sandbox backend: {}\n\
             sandbox mechanism: {}\n\
             guarantees: visibility={} tree_lifetime={} resources={}\n\
             tier1_executable: {verdict}",
            self.backend,
            self.mechanism,
            self.guarantees.visibility,
            self.guarantees.tree_lifetime,
            self.guarantees.resources,
        )
    }
}

/// This host's sandbox capability, right now.
///
/// Cheap enough for a status path: one `bwrap --version`, one namespace probe, and one
/// cgroup discovery, which is exactly what the runner does on every dispatch anyway.
#[must_use]
pub fn host_capability() -> HostCapability {
    let guarantees = host_backend().available_guarantees();
    HostCapability {
        backend: selected::NAME,
        mechanism: selected::MECHANISM,
        tier1_executable: tier1_executable_for(guarantees),
        guarantees,
    }
}

/// Whether `guarantees` satisfy what a Tier-1 dispatch requires before a capability
/// adds anything to the request.
///
/// Split out from [`host_capability`] so both answers are testable on any host: the
/// negative state is the one that matters most, and on a developer machine with `bwrap`
/// working the negative state is otherwise unreachable.
fn tier1_executable_for(guarantees: AvailableGuarantees) -> bool {
    guarantees.check(&probe_spec()).is_ok()
}

/// The isolation a Tier-1 dispatch asks for, before a capability adds anything.
///
/// # Why this is spelled out rather than taken from `SandboxSpec::new`
///
/// A bare default spec asks for `Resource::Required`, and that would be wrong: it would
/// report Tier-1 as unavailable on any host without delegated cgroups even though every
/// shipped Tier-1 capability states a budget and requires no control, and would then run
/// there. So this mirrors what `orxnud-capability`'s `spec_for` actually produces:
///
/// * `Visibility::Namespaced` — the `SandboxSpec` default, unchanged by `spec_for`;
/// * `TreeLifetime::Required` — which `spec_for` sets unconditionally ("containment is
///   always required; it is what the sandbox *is*");
/// * `Resource::Observed` — which `spec_for` selects for a capability whose
///   `ResourcePolicy.required` is empty.
///
/// Stating it once, here, with the cross-reference, is what keeps it from drifting. The
/// three tests below pin each part, including that resources are deliberately *not* what
/// gates Tier-1 execution.
fn probe_spec() -> crate::contract::SandboxSpec {
    use crate::contract::{IsolationRequirements, Resource, TreeLifetime, Visibility};
    let mut spec = crate::contract::SandboxSpec::new("orxnud-capability-probe");
    // The program is never executed and never read: `check` consults only
    // `spec.requires`, so this asks the requirements question and nothing else.
    spec.requires = IsolationRequirements {
        visibility: Visibility::Namespaced,
        tree_lifetime: TreeLifetime::Required,
        resources: Resource::Observed,
    };
    spec
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

    /// A host that provides everything, for the positive half of the pair below.
    fn all_guarantees() -> AvailableGuarantees {
        AvailableGuarantees {
            visibility: true,
            tree_lifetime: true,
            resources: true,
        }
    }

    #[test]
    fn a_host_that_provides_nothing_reports_that_tier1_cannot_run() {
        // The negative state, asserted on any host. This is the state a GitHub-hosted
        // Linux runner is in: `bwrap` is installed, so the compile-time backend name is
        // still `bwrap`, and every Tier-1 dispatch is nevertheless refused.
        //
        // Pinned deliberately, because "Tier-1 is unavailable" must never be able to
        // drift into "so the tests may proceed" — the value is the only thing standing
        // between a missing guarantee and an unsandboxed subprocess.
        assert!(
            !tier1_executable_for(AvailableGuarantees::none()),
            "a host providing no guarantees must not claim a Tier-1 capability can run"
        );
    }

    #[test]
    fn a_host_that_provides_everything_reports_that_tier1_can_run() {
        // The positive half of the same pair, so the negative result above cannot be
        // satisfied by a predicate that always answers `false`.
        assert!(tier1_executable_for(all_guarantees()));
    }

    #[test]
    fn visibility_alone_is_not_enough_and_neither_is_tree_lifetime_alone() {
        // Each on its own leaves a required guarantee missing, so each must refuse.
        // Without these, a one-line change to `check` could quietly narrow the contract
        // and the pair above would still pass on an all-true input.
        for partial in [
            AvailableGuarantees {
                visibility: true,
                tree_lifetime: false,
                resources: true,
            },
            AvailableGuarantees {
                visibility: false,
                tree_lifetime: true,
                resources: true,
            },
        ] {
            assert!(
                !tier1_executable_for(partial),
                "{partial:?} leaves a required guarantee missing and must refuse"
            );
        }
    }

    #[test]
    fn resources_alone_never_decides_tier1_availability() {
        // Every shipped Tier-1 capability states a budget but requires no control, so
        // the resource switch must not be what gates execution. Pinned because getting
        // this wrong is silent and in the *permissive-looking* direction: a bare
        // `SandboxSpec::new()` asks for `Resource::Required`, so a definition that
        // skipped this would report Tier-1 unavailable on hosts where it runs fine --
        // and, once acted on, would be the shape of "no capability works here".
        assert!(tier1_executable_for(AvailableGuarantees {
            visibility: true,
            tree_lifetime: true,
            resources: false,
        }));
    }

    #[test]
    fn the_probe_spec_asks_for_exactly_what_a_tier1_dispatch_asks_for() {
        // Keeps `probe_spec` tied to the contract rather than to a guess. If `spec_for`
        // ever stops forcing `TreeLifetime::Required`, this is the test that says so.
        let spec = probe_spec();
        assert_eq!(spec.requires.visibility, Visibility::Namespaced);
        assert_eq!(spec.requires.tree_lifetime, TreeLifetime::Required);
        assert_eq!(spec.requires.resources, Resource::Observed);
    }

    #[test]
    fn the_reported_capability_is_the_runner_own_answer_and_not_a_second_probe() {
        // The load-bearing property of this whole type. If the report could disagree
        // with the runner, then a log line could explain a refusal that happened for a
        // different reason -- which is worse than no diagnostic.
        let reported = host_capability();
        assert_eq!(
            reported.guarantees,
            host_backend().available_guarantees(),
            "the report must read the runner's own answer, not re-derive one"
        );
        assert_eq!(reported.backend, host_backend_name());
        assert_eq!(reported.mechanism, host_backend_mechanism());
    }

    #[test]
    fn the_report_states_the_verdict_and_the_reason_together() {
        // "sandbox available: no" with no reason sends the reader to the wrong layer,
        // so the refusal has to say that it is correct rather than a fault.
        let report = host_capability().report();
        assert!(report.contains("tier1_executable:"), "{report}");
        assert!(report.contains("visibility="), "{report}");
        assert!(report.contains("tree_lifetime="), "{report}");
        assert!(report.contains("resources="), "{report}");

        // And the negative wording specifically, exercised directly so it is asserted
        // even on a developer host where the verdict happens to be positive.
        let refusing = HostCapability {
            backend: "bwrap",
            mechanism: "bubblewrap",
            guarantees: AvailableGuarantees::none(),
            tier1_executable: false,
        }
        .report();
        assert!(
            refusing.contains("this is correct, not a fault"),
            "{refusing}"
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
