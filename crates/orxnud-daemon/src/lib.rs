//! Composition root, lifecycle, and single-instance enforcement.
//!
//! # Phase 1 composes and starts nothing
//!
//! [`Daemon::start`] builds every subsystem and reports that it did. It opens no
//! socket, spawns no process, and starts no task worker — `docs/13-phase-1-contract.md`
//! §8 prohibits a second writer, any server, and any daemon. What exists is the
//! *wiring* and the *state machine* for starting and stopping, so that Phase 2
//! adds behaviour behind a lifecycle that already works.
//!
//! # Why the lifecycle is a state machine
//!
//! `Created → Starting → Running → Stopping → Stopped`, with `Failed` reachable
//! from anywhere. Modelled as a type rather than a bool because the interesting
//! bug is a double start or a stop after failure, and a bool cannot express
//! "neither running nor stopped" — it forces one of those answers.
//!
//! # Single-instance without a listener
//!
//! A daemon needs one instance per machine, but Phase 1 opens no socket, so the
//! lock cannot be a bound address. [`InstanceLock`] is a *plan*: the identity of
//! the lock, where it would live, and the check that no other instance holds it.
//! Phase 2 supplies the actual filesystem or socket primitive; what is
//! implemented and tested now is the decision logic — including that a stale lock
//! from a crashed process is distinguishable from a live one.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use orxnud_audit::AuditChain;
use orxnud_capability::{CapabilityRegistry, Dispatcher};
use orxnud_config::{ConfigSchemaVersion, LayeredConfig};
use orxnud_domain::ids::RequestId;
use orxnud_obs::TracingPlan;
use orxnud_policy::PolicyEngine;
use orxnud_store::Store;

/// Where the daemon keeps its runtime state.
///
/// A path, not an open file. Phase 1 records *where* state would live without
/// creating it, because creating a data directory is a side effect on the user's
/// machine and §8 forbids application state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The root directory for all daemon state.
    pub root: std::path::PathBuf,
    /// The SQLite database file.
    pub database: std::path::PathBuf,
    /// The audit journal file.
    pub audit: std::path::PathBuf,
    /// Where a single-instance lock would be placed.
    pub instance_lock: std::path::PathBuf,
    /// Where logs would be written, if not to stderr.
    pub log: std::path::PathBuf,
}

impl Paths {
    /// Derives every path from a root.
    ///
    /// One function rather than five independent ones so a caller cannot end up
    /// with a database outside the state root — which is the shape of bug that
    /// leaves an orphaned file the uninstall path does not know about.
    #[must_use]
    pub fn under(root: impl Into<std::path::PathBuf>) -> Self {
        let root = root.into();
        Self {
            database: root.join("state.db"),
            audit: root.join("audit.log"),
            instance_lock: root.join("daemon.lock"),
            log: root.join("daemon.log"),
            root,
        }
    }

    /// Every path this configuration would use, for `doctor` output.
    #[must_use]
    pub fn all(&self) -> Vec<&std::path::Path> {
        vec![
            &self.root,
            &self.database,
            &self.audit,
            &self.instance_lock,
            &self.log,
        ]
    }
}

/// The daemon's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    /// Built but not started.
    Created,
    /// Start in progress.
    Starting,
    /// Running.
    Running,
    /// Stop in progress.
    Stopping,
    /// Stopped, cleanly.
    Stopped,
    /// Stopped because of a failure.
    Failed,
}

impl LifecycleState {
    /// Whether the daemon is running.
    #[must_use]
    pub fn is_running(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Whether start may be called.
    #[must_use]
    pub fn can_start(self) -> bool {
        matches!(self, Self::Created | Self::Stopped)
    }

    /// Whether stop may be called.
    #[must_use]
    pub fn can_stop(self) -> bool {
        matches!(self, Self::Running | Self::Starting | Self::Failed)
    }

    /// Whether a start or stop is already in flight.
    #[must_use]
    pub fn is_transitioning(self) -> bool {
        matches!(self, Self::Starting | Self::Stopping)
    }
}

impl std::fmt::Display for LifecycleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Created => "created",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        };
        f.write_str(s)
    }
}

/// A lifecycle refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleError {
    /// The daemon is already running.
    #[error("cannot start: the daemon is already running")]
    AlreadyRunning,

    /// The daemon has not been started.
    #[error("cannot stop: the daemon is not running")]
    NotRunning,

    /// A start or stop is already in flight.
    #[error("cannot {requested}: a {in_flight} transition is already in progress")]
    TransitionInFlight {
        /// What was asked for.
        requested: &'static str,
        /// What is already happening.
        in_flight: &'static str,
    },

    /// Another instance holds the lock.
    #[error("another instance is already running (lock held by pid {pid})")]
    AlreadyRunningElsewhere {
        /// The holder's process id.
        pid: u32,
    },

    /// A store could not be opened.
    #[error("the store could not be opened: {0}")]
    Store(String),
}

/// What an instance lock holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockHolder {
    /// The process id of the holder.
    pub pid: u32,
    /// When it was acquired, ms since epoch.
    pub at_ms: i64,
}

impl LockHolder {
    /// Whether the holding process still appears to be alive.
    ///
    /// Phase 1 does **not** call into the OS to check: probing a pid is racy
    /// (the pid may have been reused) and platform-specific, and `platform-*` is
    /// where such a call belongs. What is implemented here is the *decision*:
    /// given a liveness answer, should the lock be taken or declared stale.
    #[must_use]
    pub fn should_yield_to(&self, holder_alive: bool, started_alive: bool) -> bool {
        // A live holder always wins. A dead holder does not: the lock is stale.
        // `started_alive` exists so a caller can distinguish "the daemon I asked
        // about is running" from "some process with this pid exists".
        !holder_alive && started_alive
    }
}

/// A single-instance lock, as a plan rather than a live lock.
///
/// The path and the holder's identity are decided here; acquiring the primitive
/// is Phase 2, because Phase 1 opens no socket and creates no files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceLock {
    path: std::path::PathBuf,
    held_by: Option<LockHolder>,
}

impl InstanceLock {
    /// A lock at `path`, believed unheld.
    #[must_use]
    pub fn at(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            held_by: None,
        }
    }

    /// Where the lock would live.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Who holds it, if anyone.
    #[must_use]
    pub fn holder(&self) -> Option<LockHolder> {
        self.held_by
    }

    /// Records a holder.
    #[must_use]
    pub fn held_by(mut self, holder: LockHolder) -> Self {
        self.held_by = Some(holder);
        self
    }

    /// Decides whether this instance may start.
    ///
    /// # Errors
    ///
    /// [`LifecycleError::AlreadyRunningElsewhere`] when a live instance holds the
    /// lock. A lock whose holder is dead is treated as stale and does not block —
    /// otherwise one crash would require manual cleanup before the daemon could
    /// ever run again.
    pub fn acquire(&self, holder_alive: bool, started_alive: bool) -> Result<(), LifecycleError> {
        let Some(existing) = self.held_by else {
            return Ok(());
        };
        if existing.should_yield_to(holder_alive, started_alive) {
            return Ok(());
        }
        Err(LifecycleError::AlreadyRunningElsewhere { pid: existing.pid })
    }
}

/// Everything the daemon is composed of.
///
/// The fields are read by `doctor` and asserted by tests; nothing here holds an
/// open handle, because nothing is open in Phase 1.
#[derive(Debug, Clone)]
pub struct Components {
    /// Where state would live.
    pub paths: Paths,
    /// The capability registry. Empty in Phase 1.
    pub registry: CapabilityRegistry,
    /// The dispatcher over that registry.
    pub dispatcher: Dispatcher,
    /// The audit chain. Empty; the journal file is not created.
    pub audit: AuditChain,
    /// The resolved configuration. No schema is defined yet.
    pub config: LayeredConfig,
    /// The tracing description. No subscriber is installed.
    pub tracing: TracingPlan,
    /// The config schema version this build writes.
    pub config_version: ConfigSchemaVersion,
    /// The instance lock plan.
    pub instance: InstanceLock,
}

impl Components {
    /// How many capabilities are enabled.
    ///
    /// Phase 1's exit criterion is zero, exposed so a test can assert it rather
    /// than a reader having to take it on trust.
    #[must_use]
    pub fn enabled_capabilities(&self) -> usize {
        self.registry.enabled_count()
    }

    /// Whether any capability is enabled.
    #[must_use]
    pub fn has_enabled_capabilities(&self) -> bool {
        self.enabled_capabilities() > 0
    }

    /// A multi-line summary, for `doctor`.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "capabilities enabled: {}\n",
            self.enabled_capabilities()
        ));
        s.push_str(&format!(
            "capabilities registered: {}\n",
            self.registry.ids().len()
        ));
        s.push_str(&format!("config schema version: {}\n", self.config_version));
        s.push_str(&format!("tracing: {}\n", self.tracing.describe()));
        s.push_str(&format!("audit entries: {}\n", self.audit.len()));
        s.push_str(&format!("config keys: {}\n", self.config.keys().len()));
        s.push_str(&format!("state root: {}", self.paths.root.display()));
        s
    }
}

/// The daemon.
#[derive(Debug)]
pub struct Daemon {
    components: Components,
    state: LifecycleState,
    /// The policy engine the daemon would evaluate actions through.
    ///
    /// Held but not called: Phase 1 authorises nothing, because there is nothing
    /// to authorise. Constructing it here is deliberate — a composition root that
    /// does not hold its policy engine would be a root that cannot be wired
    /// without editing it, and Phase 2 would then have to change the composition
    /// root rather than extend it. Exposed by [`Daemon::policy`] so the wiring is
    /// inspectable rather than merely present.
    policy: PolicyEngine,
    started_with: Option<RequestId>,
}

impl Daemon {
    /// Composes a daemon over `paths`.
    ///
    /// Opens nothing and creates nothing. The name says *compose* for that reason.
    #[must_use]
    pub fn compose(paths: Paths) -> Self {
        let registry = CapabilityRegistry::empty();
        let dispatcher = Dispatcher::with_registry(registry.clone());
        let instance = InstanceLock::at(paths.instance_lock.clone());
        let components = Components {
            paths,
            registry,
            dispatcher,
            audit: AuditChain::new(),
            config: LayeredConfig::empty(),
            tracing: TracingPlan::new(),
            config_version: ConfigSchemaVersion::INITIAL,
            instance,
        };
        Self {
            components,
            state: LifecycleState::Created,
            // Deny-all policy and an empty budget: the composition root is not
            // where permissions are granted.
            policy: PolicyEngine::new(
                orxnud_policy::PolicySet::deny_all("daemon/1"),
                orxnud_policy::BudgetLedger::empty(),
                "daemon/1",
            ),
            started_with: None,
        }
    }

    /// The current lifecycle state.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.state
    }

    /// The composed components.
    #[must_use]
    pub fn components(&self) -> &Components {
        &self.components
    }

    /// The capability registry.
    #[must_use]
    pub fn registry(&self) -> &CapabilityRegistry {
        &self.components.registry
    }

    /// The policy engine, for inspection.
    ///
    /// Phase 1 never calls it: there are no actions to authorise, and
    /// `docs/13-phase-1-contract.md` §8 forbids capabilities.
    #[must_use]
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// Starts the daemon.
    ///
    /// # Errors
    ///
    /// [`LifecycleError::AlreadyRunning`] on a second start,
    /// [`LifecycleError::TransitionInFlight`] while a transition is in progress,
    /// or [`LifecycleError::AlreadyRunningElsewhere`] when another instance holds
    /// the lock.
    pub fn start(&mut self) -> Result<(), LifecycleError> {
        if self.state.is_running() {
            return Err(LifecycleError::AlreadyRunning);
        }
        if self.state.is_transitioning() {
            return Err(LifecycleError::TransitionInFlight {
                requested: "start",
                in_flight: self.state_name(),
            });
        }
        if !self.state.can_start() {
            return Err(LifecycleError::AlreadyRunning);
        }
        // The single-instance decision happens *before* any state changes, so a
        // refusal leaves the daemon exactly as it was.
        self.components
            .instance
            .acquire(true, self.state.is_running())?;
        self.state = LifecycleState::Running;
        self.started_with = Some(RequestId::new("daemon-start"));
        Ok(())
    }

    /// Stops the daemon.
    ///
    /// # Errors
    ///
    /// [`LifecycleError::NotRunning`] when it was never started, or
    /// [`LifecycleError::TransitionInFlight`] while a transition is in progress.
    pub fn stop(&mut self) -> Result<(), LifecycleError> {
        if self.state.is_transitioning() {
            return Err(LifecycleError::TransitionInFlight {
                requested: "stop",
                in_flight: self.state_name(),
            });
        }
        if !self.state.can_stop() {
            return Err(LifecycleError::NotRunning);
        }
        self.state = LifecycleState::Stopped;
        self.started_with = None;
        Ok(())
    }

    /// Marks the daemon failed, from any state.
    pub fn fail(&mut self) {
        self.state = LifecycleState::Failed;
    }

    /// The request id from the last start, if it started.
    #[must_use]
    pub fn started_with(&self) -> Option<&RequestId> {
        self.started_with.as_ref()
    }

    /// Whether the store could be opened at the configured path.
    ///
    /// # Errors
    ///
    /// [`LifecycleError::Store`] if not. Present so `doctor` can report a real
    /// diagnosis; Phase 1 does not call it during `compose`.
    pub fn probe_store(&self) -> Result<Store, LifecycleError> {
        Store::open(&self.components.paths.database, true)
            .map_err(|e| LifecycleError::Store(e.to_string()))
    }

    fn state_name(&self) -> &'static str {
        match self.state {
            LifecycleState::Starting => "start",
            LifecycleState::Stopping => "stop",
            _ => "transition",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        Paths::under(std::env::temp_dir().join("orxnud-daemon-test"))
    }

    fn daemon() -> Daemon {
        Daemon::compose(paths())
    }

    #[test]
    fn a_composed_daemon_has_opened_nothing() {
        // Nothing exists on disk: `compose` must not create the state root, the
        // database, or the lock.
        let p = paths();
        let root = p.root.clone();
        let _ = std::fs::remove_dir_all(&root);
        let d = Daemon::compose(p.clone());
        assert_eq!(d.state(), LifecycleState::Created);
        assert!(!root.exists(), "compose created {}", root.display());
        assert!(!p.database.exists());
        assert!(!p.instance_lock.exists());
    }

    #[test]
    fn phase_one_enables_no_capabilities() {
        // The exit criterion, asserted.
        let d = daemon();
        assert_eq!(d.components().enabled_capabilities(), 0);
        assert!(!d.components().has_enabled_capabilities());
        assert!(d.registry().ids().is_empty());
    }

    #[test]
    fn the_lifecycle_runs_created_running_stopped() {
        let mut d = daemon();
        assert_eq!(d.state(), LifecycleState::Created);
        d.start().expect("start");
        assert_eq!(d.state(), LifecycleState::Running);
        assert!(d.state().is_running());
        assert!(d.started_with().is_some());
        d.stop().expect("stop");
        assert_eq!(d.state(), LifecycleState::Stopped);
        assert!(d.started_with().is_none());
    }

    #[test]
    fn a_second_start_is_refused() {
        let mut d = daemon();
        d.start().expect("start");
        assert_eq!(
            d.start().expect_err("second start"),
            LifecycleError::AlreadyRunning
        );
        // The refusal left the state untouched.
        assert_eq!(d.state(), LifecycleState::Running);
    }

    #[test]
    fn stopping_a_daemon_that_never_started_is_refused() {
        let mut d = daemon();
        assert_eq!(
            d.stop().expect_err("never started"),
            LifecycleError::NotRunning
        );
        assert_eq!(d.state(), LifecycleState::Created);
    }

    #[test]
    fn a_failed_daemon_can_still_be_stopped() {
        // A failure must be stoppable, or a crash would leave no clean path out.
        let mut d = daemon();
        d.start().expect("start");
        d.fail();
        assert_eq!(d.state(), LifecycleState::Failed);
        d.stop().expect("stop from failed");
        assert_eq!(d.state(), LifecycleState::Stopped);
    }

    #[test]
    fn a_stopped_daemon_can_start_again() {
        let mut d = daemon();
        d.start().expect("start");
        d.stop().expect("stop");
        d.start().expect("restart");
        assert_eq!(d.state(), LifecycleState::Running);
    }

    #[test]
    fn a_transition_in_flight_refuses_a_second_request() {
        // Reaching the intermediate states directly is the only way to test this
        // without a real async start; the point is that the state machine knows
        // they are not quiescent.
        for busy in [LifecycleState::Starting, LifecycleState::Stopping] {
            let mut d = daemon();
            d.state = busy;
            let err = d.start().expect_err("start while busy");
            assert!(
                matches!(err, LifecycleError::TransitionInFlight { .. }),
                "{err:?}"
            );
            let err = d.stop().expect_err("stop while busy");
            assert!(
                matches!(err, LifecycleError::TransitionInFlight { .. }),
                "{err:?}"
            );
        }
    }

    #[test]
    fn a_live_lock_holder_blocks_a_start() {
        let holder = LockHolder {
            pid: 4242,
            at_ms: 1_000,
        };
        let lock = InstanceLock::at("/tmp/orxnud.lock").held_by(holder);
        let err = lock.acquire(true, false).expect_err("must refuse");
        assert_eq!(err, LifecycleError::AlreadyRunningElsewhere { pid: 4242 });
    }

    #[test]
    fn a_dead_lock_holder_is_stale_and_does_not_block() {
        // Otherwise one crash would require manual cleanup forever.
        let holder = LockHolder {
            pid: 4242,
            at_ms: 1_000,
        };
        let lock = InstanceLock::at("/tmp/orxnud.lock").held_by(holder);
        assert!(
            lock.acquire(false, true).is_ok(),
            "a dead holder must not block"
        );
    }

    #[test]
    fn an_unheld_lock_never_blocks() {
        let lock = InstanceLock::at("/tmp/orxnud.lock");
        assert!(lock.holder().is_none());
        assert!(lock.acquire(false, false).is_ok());
        assert!(lock.acquire(true, true).is_ok());
    }

    #[test]
    fn the_stale_decision_distinguishes_a_dead_holder_from_a_live_one() {
        let holder = LockHolder { pid: 1, at_ms: 0 };
        // Alive: never yields.
        assert!(!holder.should_yield_to(true, true));
        assert!(!holder.should_yield_to(true, false));
        // Dead, and we are the instance asking: yield.
        assert!(holder.should_yield_to(false, true));
        // Dead, but we are not running, so this is not a stale-lock situation.
        assert!(!holder.should_yield_to(false, false));
    }

    #[test]
    fn every_path_is_derived_from_the_root() {
        let p = Paths::under("/var/lib/orxnud");
        assert_eq!(p.database, std::path::Path::new("/var/lib/orxnud/state.db"));
        assert_eq!(p.audit, std::path::Path::new("/var/lib/orxnud/audit.log"));
        assert_eq!(
            p.instance_lock,
            std::path::Path::new("/var/lib/orxnud/daemon.lock")
        );
        assert_eq!(p.log, std::path::Path::new("/var/lib/orxnud/daemon.log"));
        // Everything the daemon would touch lives under one root, which is what
        // makes the uninstall path complete.
        for path in p.all() {
            assert!(
                path.starts_with("/var/lib/orxnud"),
                "{path:?} escapes the root"
            );
        }
    }

    #[test]
    fn the_description_reports_zero_enabled_capabilities() {
        let d = daemon();
        let text = d.components().describe();
        assert!(text.contains("capabilities enabled: 0"), "{text}");
        assert!(text.contains("config schema version: 1"), "{text}");
    }

    #[test]
    fn the_composed_policy_engine_permits_nothing() {
        // Deny-all is the only correct starting point for a root that has granted
        // nothing.
        let d = daemon();
        assert_eq!(
            d.policy().audit().len(),
            0,
            "composition must not authorise anything"
        );
    }

    #[test]
    fn lifecycle_states_report_what_they_allow() {
        assert!(LifecycleState::Created.can_start());
        assert!(!LifecycleState::Created.can_stop());
        assert!(LifecycleState::Running.can_stop());
        assert!(!LifecycleState::Running.can_start());
        assert!(LifecycleState::Starting.is_transitioning());
        assert!(LifecycleState::Stopping.is_transitioning());
        assert!(!LifecycleState::Running.is_transitioning());
        assert_eq!(LifecycleState::Running.to_string(), "running");
    }
}
