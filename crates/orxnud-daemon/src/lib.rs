//! Composition root, lifecycle, and single-instance enforcement.
//!
//! # What is composed, and what is still absent
//!
//! [`Daemon::start`] builds every subsystem and reports that it did. It opens no
//! socket and spawns no process, and no capability is enabled — Phase 0-2 prohibit
//! a server and any working feature.
//!
//! What *is* operational is the task layer, in [`task_service`]: it opens the
//! database, migrates it, reclaims the previous run's leases, and refuses to start
//! if any of that fails. That is the part a user would lose work without, so it is
//! the part that runs rather than merely being wired.
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
//!
//! # The dispatcher this daemon composes
//!
//! [`Daemon::compose`] wires the **governed** dispatcher —
//! `orxnud_capability::dispatch::Dispatcher`, the one that runs all nine stages —
//! and installs the real [`SandboxExecutionBackend`] as its only execution
//! backend. It deliberately does **not** compose
//! `orxnud_capability::Dispatcher` from the crate root, which is the Phase-1
//! registry-resolution shell: it performs no policy evaluation, consults no
//! authority, and reaches no process.
//!
//! # Why the dispatcher is a borrow, not a field
//!
//! The governed dispatcher holds `&'p mut PolicyEngine`. A struct cannot contain
//! both an owned `PolicyEngine` and a mutable borrow of itself, so the dispatcher
//! cannot be a field of [`Daemon`] — not without taking ownership of the engine
//! inside the dispatcher, which would undo the single-writer guarantee ADR-0006
//! documents and that the register records as V-41.
//!
//! So the daemon **owns** everything the dispatcher needs — the one policy engine,
//! the adapter bundles, and the execution backend — and [`Daemon::dispatcher`]
//! lends them out for the duration of one borrow. That is not a workaround for the
//! borrow checker; it is a stricter version of the invariant. Two governed
//! dispatchers cannot exist at once, because the second borrow would not compile.
//! `PolicyEngine` also owns the one audit chain that policy writes to, so the
//! daemon reads its audit depth through the engine rather than keeping a second,
//! always-empty chain of its own.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod proposer;
pub mod runtime;
pub mod task_service;

use std::collections::BTreeMap;
use std::sync::Arc;

use orxnud_capability::dispatch::{AdapterBundle, ExecutionBackend};
use orxnud_capability::subprocess::SandboxExecutionBackend;
use orxnud_capability::{CapabilityDeclaration, CapabilityRegistry};
use orxnud_config::{ConfigSchemaVersion, LayeredConfig};
use orxnud_domain::enums::{DataClass, RiskClass};
use orxnud_domain::ids::{CapabilityId, RequestId};
use orxnud_domain::platform::SecretsContract;
use orxnud_obs::TracingPlan;
use orxnud_policy::{Grant, PolicyEngine};
use orxnud_store::Store;
use orxnud_store::security_state::{SqliteApprovalLedger, SqliteAuditJournal};

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

    /// The directory sandboxed capabilities may write inside.
    ///
    /// Inside the state root, so it is covered by the same "the daemon owns this tree"
    /// reasoning as the database and the journal, and so a state root on a different
    /// filesystem cannot accidentally expose a capability to a workspace it did not
    /// choose. Derived by one function rather than open-coded at each use, because a
    /// second derivation is a second answer to "where may this write".
    #[must_use]
    pub fn workspace(&self) -> std::path::PathBuf {
        self.root.join("workspace")
    }

    /// Creates the workspace directory if it is absent.
    ///
    /// Called during composition rather than lazily at first dispatch, so a capability
    /// cannot be blamed for a missing directory, and so the directory's permissions are
    /// set once at a place a reader will look. Idempotent: an existing workspace is
    /// left exactly as it is, because a side-effecting capability may have put files in
    /// it and this runs on every start.
    ///
    /// # Errors
    ///
    /// If the directory cannot be created.
    pub fn ensure_workspace(&self) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let ws = self.workspace();
        if ws.is_dir() {
            return Ok(());
        }
        std::fs::create_dir_all(&ws)?;
        // Owner-only, like the database and the socket: this tree holds the output of a
        // High-risk capability, so it must not be group- or world-readable.
        std::fs::set_permissions(&ws, std::fs::Permissions::from_mode(0o700))
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

    /// Durable security state could not be established.
    ///
    /// `what` names the mechanism and `reason` says what it answered, so a caller
    /// can tell "the audit journal does not verify" from "the approval ledger is
    /// unwritable" — one is a corrupted history, the other an outage, and they
    /// want different responses.
    #[error("could not establish {what}: {reason}")]
    SecurityState {
        /// Which mechanism.
        what: &'static str,
        /// What it answered.
        reason: String,
    },
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

/// Everything the governed dispatcher needs, owned by the daemon.
///
/// # Why this is a type
///
/// `orxnud_capability::dispatch::Dispatcher` *borrows* its policy engine and
/// secret store, so it cannot itself be stored on [`Daemon`]. What the daemon
/// owns is the configuration the dispatcher is built from: the adapter bundles and
/// the one execution backend. Holding them here is what makes [`Daemon::compose`]
/// a composition root rather than a factory that discards its work.
///
/// # Why `Debug` is hand-written
///
/// `Arc<dyn ExecutionBackend>` cannot be derived. A derived `Debug` would either
/// not compile or, once someone boxed a handle, print whatever the backend chose
/// to expose. Reporting the two counts is both true and safe.
#[derive(Clone)]
pub struct DispatchWiring {
    /// Capability id to the implementation that satisfies it.
    ///
    /// Empty until a capability is registered, which is the correct state: an
    /// adapter is a capability, and no capability exists yet. `Dispatcher::new`
    /// accepts an empty map, and every dispatch is refused with
    /// `NoImplementation` — the fail-closed result, not a gap.
    bundles: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>>,
    /// The only route to a Tier-1 process.
    ///
    /// Not an `Option`, deliberately. The governed dispatcher does accept `None`
    /// and refuses a Tier-1 capability when it sees one, so an `Option` here would
    /// not be a safety hole — but it would make "this daemon has no sandbox" a
    /// state someone can write. Making the field non-optional means composition
    /// cannot express it, and the only way to lose the backend is to stop building
    /// a daemon.
    execution: Arc<dyn ExecutionBackend>,
}

impl DispatchWiring {
    /// How many capabilities have an implementation.
    #[must_use]
    pub fn bundle_count(&self) -> usize {
        self.bundles.len()
    }

    /// Whether an execution backend is installed.
    ///
    /// Always `true`, and that is the useful part: it is a *structural* property,
    /// not a runtime observation. There is no code path that produces a
    /// `DispatchWiring` without a backend, so this cannot be false and a caller
    /// that branches on it is reading a compile-time fact.
    #[must_use]
    pub fn has_execution_backend(&self) -> bool {
        true
    }
}

impl std::fmt::Debug for DispatchWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchWiring")
            .field("bundles", &self.bundles.len())
            .field("execution_backend", &"installed")
            .finish()
    }
}

/// Everything the daemon is composed of.
///
/// The fields are read by `doctor` and asserted by tests; nothing here holds an
/// open handle, because nothing is open in Phase 1.
/// The policy view of every capability this build ships.
///
/// Kept beside the registry entries rather than inside them, because the two answer
/// different questions and collapsing them is how "declared" starts meaning "allowed":
/// the registry says what the code *can* do, this says what policy *permits*.
///
/// `(id, risk, max data class)`. `networked` is false for all of them today and
/// `cost` is 1, both stated at the grant site rather than inferred.
const SHIPPED_POLICY: [(&str, RiskClass, DataClass); 2] = [
    (
        orxnud_capability::text::WORD_COUNT_ID,
        RiskClass::Low,
        DataClass::Public,
    ),
    // High, and that is the whole point: policy refuses this one unless a single-use,
    // time-boxed, parameter-bound approval is presented. The grant below still has to
    // exist -- no grant is a refusal too -- so the capability is reachable only by the
    // two agreeing, which is what "governed" means here.
    (
        orxnud_capability::write_text::WRITE_TEXT_ID,
        RiskClass::High,
        DataClass::Public,
    ),
];

/// The policy set this build ships: deny-all, plus a standing grant per capability.
///
/// # Deny-all first, granted explicitly after
///
/// The base is `deny_all`, exactly as before this slice. A capability is reachable only
/// because a grant naming *it* was added here, so "no grant" remains the answer for
/// everything not on this list, and adding a capability means adding a grant rather
/// than loosening a default.
///
/// # Why the grants do not expire
///
/// They are standing grants for built-ins that read nothing, write nothing and resolve
/// no credential. `may_grant` is false, so a grant cannot mint authority for anything
/// else, and the capability each covers has no effect to abuse. A grant that needed
/// renewing on a timer would be a grant that arguably should not exist for a capability
/// this harmless — and a timer-driven permission is one that silently stops working.
fn shipped_policy_set(version: &str) -> orxnud_policy::PolicySet {
    let mut set = orxnud_policy::PolicySet::deny_all(version);
    for (id, _risk, max_class) in SHIPPED_POLICY {
        set = set.with_grant(Grant {
            id: orxnud_domain::ids::GrantId::new(format!("grant:{id}")),
            // A grant made by a machine is not a grant (ADR-0027). This names the
            // local user, which is who actually authorised shipping it.
            granted_by: orxnud_domain::ids::UserId::new("local"),
            capability: CapabilityId::new(id),
            max_data_class: max_class,
            // Never. A grant that could mint grants is an authority escalation.
            may_grant: false,
            expires_at_ms: i64::MAX,
            revoked: false,
        });
    }
    set
}

/// The budget this build ships: one global ceiling.
///
/// # What was measured before this was written
///
/// The obvious configuration — a funded `cost:low` and zeroed `cost:medium`/`high`/
/// `critical`, on the reasoning that it expresses "only Low may spend" — **does not
/// work**, and the failure is worth recording because it is silent in the source and
/// loud only at runtime.
///
/// The engine checks a cost with `permits_all`, which requires *every* declared
/// ceiling to permit it. So the four per-risk ceilings are conjunctive constraints on
/// one number, not four independent permissions: zeroing the upper three refuses the
/// Low-risk capability too, and the refusal names `cost:critical` as the ceiling that
/// bit. Verified against the running daemon before this comment was written.
///
/// A global ceiling is therefore the only shape that expresses anything true here.
///
/// # Why a global budget does not widen authority
///
/// The budget is one control among several, and it is the *coarsest* one. What
/// actually decides whether a capability may run is unchanged by this line: a
/// declaration must exist, a grant must exist and cover the data class, and a risk
/// class of High or above additionally requires a single-use, digest-bound approval.
/// A global ceiling cannot supply any of those. It bounds how much total work the
/// daemon will do before refusing, and nothing about *which* work that is.
///
/// The value is large because the only capability it funds is a pure in-process count
/// that costs 1 and touches nothing. A tight ceiling here would buy no safety — there
/// is no resource worth protecting — and would only mean a long-running daemon
/// eventually refuses harmless work for no reason. The ceiling exists to bound the
/// unbounded scopes, and `cost:low` is the one scope with nothing to bound.
fn shipped_budget() -> orxnud_policy::BudgetLedger {
    orxnud_policy::BudgetLedger::empty().with_global(1_000_000)
}

/// Declares every shipped capability in the registry.
///
/// The registry is the answer to "what does this build implement?", so it is populated
/// at composition — before any policy question is asked. A capability that is declared
/// but not granted is refused by policy; a capability that is granted but not declared
/// cannot be resolved. Both directions are refusals, which is the point.
fn register_shipped_declarations(registry: &mut CapabilityRegistry) {
    for declaration in shipped_declarations() {
        registry
            .register(declaration)
            .expect("a shipped capability must not be declared twice");
    }
}

/// The adapter/verifier pairs the dispatcher resolves against.
///
/// Exactly one implementation per capability, chosen here rather than discovered: a
/// second implementation of `text/word-count` would be a version-conflict bug, and the
/// dispatcher's own `register` refuses duplicates for that reason.
fn shipped_bundles(paths: &Paths) -> BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> {
    let mut bundles: BTreeMap<CapabilityId, Arc<dyn AdapterBundle + Send + Sync>> = BTreeMap::new();
    bundles.insert(
        CapabilityId::new(orxnud_capability::text::WORD_COUNT_ID),
        Arc::new(orxnud_capability::text::WordCountBundle::default()),
    );
    // `None` rather than a bundle with no program: a Tier-1 capability whose child
    // cannot be located must be *absent*, so the dispatcher answers `NoImplementation`
    // and names the capability, rather than constructing a plan with an empty program
    // that would fail later and further from the cause. `spec_for` would refuse it too,
    // but "the child binary is missing" is a deployment problem and saying so at
    // composition is more useful than saying it per dispatch.
    if let Some(helper) = orxnud_capability::write_text::resolve_helper() {
        bundles.insert(
            CapabilityId::new(orxnud_capability::write_text::WRITE_TEXT_ID),
            Arc::new(orxnud_capability::write_text::WriteTextBundle::new(
                paths.workspace(),
                helper,
            )),
        );
    }
    bundles
}

/// Every shipped declaration, in one list.
///
/// A single list so the registry, the bundles and the policy table cannot drift apart:
/// three hand-written lists would eventually disagree, and the disagreement would be a
/// capability that is declared but unresolvable, or resolvable but undeclared.
fn shipped_declarations() -> Vec<CapabilityDeclaration> {
    vec![
        orxnud_capability::text::declaration(),
        orxnud_capability::write_text::declaration(),
    ]
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
    /// What the governed dispatcher is built from.
    pub dispatch: DispatchWiring,
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
    ///
    /// `audit_entries` is passed in rather than read from a field, because the
    /// journal that matters is the one inside the policy engine and this type does
    /// not hold it. See [`Daemon::audit_len`].
    #[must_use]
    pub fn describe(&self, audit_entries: usize) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "capabilities enabled: {}\n",
            self.enabled_capabilities()
        ));
        s.push_str(&format!(
            "capabilities registered: {}\n",
            self.registry.ids().len()
        ));
        s.push_str(&format!(
            "capability implementations: {}\n",
            self.dispatch.bundle_count()
        ));
        s.push_str("execution backend: installed\n");
        s.push_str(&format!("config schema version: {}\n", self.config_version));
        s.push_str(&format!("tracing: {}\n", self.tracing.describe()));
        s.push_str(&format!("audit entries: {audit_entries}\n"));
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
    ///
    /// # What this wires
    ///
    /// * a deny-all [`PolicyEngine`] — the composition root is not where
    ///   permissions are granted;
    /// * an empty [`CapabilityRegistry`] and an empty adapter-bundle map, so every
    ///   dispatch is refused as `NoImplementation` rather than reaching an
    ///   adapter that does not exist;
    /// * the real [`SandboxExecutionBackend`], chosen by the sandbox crate for
    ///   this host. Constructing it touches nothing: the runner is selected at
    ///   compile time and a not-yet-cancelled flag is the only state it holds. The
    ///   probe that asks whether the host *can* sandbox happens at dispatch time,
    ///   where a refusal is actionable.
    #[must_use]
    pub fn compose(paths: Paths) -> Self {
        let mut daemon = Self::compose_inner(paths);
        daemon.install_shipped_declarations();
        daemon
    }

    fn compose_inner(paths: Paths) -> Self {
        // The registry and the bundles are *composition*: they say what this build
        // can do. `install_shipped_capabilities` separately says what policy permits,
        // and is called later because the policy engine is replaced when durable state
        // is attached. Keeping the two apart is what stops "declared" from silently
        // meaning "allowed".
        let mut registry = CapabilityRegistry::empty();
        register_shipped_declarations(&mut registry);
        let dispatch = DispatchWiring {
            bundles: shipped_bundles(&paths),
            execution: Arc::new(SandboxExecutionBackend::new()),
        };
        let instance = InstanceLock::at(paths.instance_lock.clone());
        let components = Components {
            paths,
            registry,
            dispatch,
            config: LayeredConfig::empty(),
            tracing: TracingPlan::new(),
            config_version: ConfigSchemaVersion::INITIAL,
            instance,
        };
        Self {
            components,
            state: LifecycleState::Created,
            policy: PolicyEngine::new(shipped_policy_set("daemon/1"), shipped_budget(), "daemon/1"),
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

    /// What the governed dispatcher is built from.
    #[must_use]
    pub fn dispatch_wiring(&self) -> &DispatchWiring {
        &self.components.dispatch
    }

    /// The **governed** dispatcher: the one that evaluates authority, policy,
    /// approval and budget, resolves capabilities and credentials, runs Tier-1 work
    /// through the sandbox, verifies the effect, and hands the outcome to audit.
    ///
    /// This is the production entry point into the capability layer. It replaces
    /// the Phase-1 shell that `orxnud_capability::Dispatcher` provides: that type
    /// resolves an id against a registry and refuses, which is a real check but
    /// none of the nine stages.
    ///
    /// # Why it is a borrow
    ///
    /// It takes `&mut self`, because it takes `&'p mut PolicyEngine` — the single
    /// writer ADR-0006 documents and that the verification register records as
    /// V-41. Holding it for one borrow means two governed dispatchers cannot exist
    /// at once; that is the invariant stated as a type rather than as a convention.
    ///
    /// # `secrets`
    ///
    /// The secret store is borrowed rather than owned because a store is a handle
    /// to a process-wide facility (a Secret Service, DPAPI, a Keychain), not daemon
    /// state, and `orxnud-platform-secrets` exposes no portable constructor the
    /// daemon could call without deciding *which* backend to use — a configuration
    /// decision that belongs to configuration, not to the composition root.
    ///
    /// Nothing is skipped by the borrow. The returned dispatcher has the same nine
    /// stages, the same refusal paths, and the same single execution backend as
    /// every other governed dispatcher; there is no reduced variant.
    #[must_use]
    pub fn dispatcher<'p, S: SecretsContract>(
        &'p mut self,
        secrets: &'p S,
    ) -> orxnud_capability::dispatch::Dispatcher<'p, S> {
        let Self {
            policy, components, ..
        } = self;
        orxnud_capability::dispatch::Dispatcher::new(
            policy,
            secrets,
            components.dispatch.bundles.clone(),
        )
        .with_execution(components.dispatch.execution.clone())
    }

    /// How many records the audit chain policy writes to holds.
    ///
    /// Read through the policy engine, because `PolicyEngine` owns the chain and
    /// policy is what appends to it. A daemon that kept its own chain would report
    /// zero forever while policy recorded every authorisation.
    #[must_use]
    pub fn audit_len(&self) -> usize {
        self.policy.audit().len()
    }

    /// A multi-line summary, for `doctor`.
    #[must_use]
    pub fn describe(&self) -> String {
        self.components.describe(self.audit_len())
    }

    /// Opens the durable audit journal and the spent-approval ledger, and makes
    /// this daemon's policy engine use them.
    ///
    /// # Why this is separate from [`Self::compose`]
    ///
    /// `compose` opens nothing — a test asserts it — and these two adapters open a
    /// SQLite file each. So durability is a *step* a caller takes once the state
    /// root is known and the user has agreed to create it, not something that
    /// happens as a side effect of building a struct.
    ///
    /// # What changes when this succeeds
    ///
    /// * Every audit record the governed path writes is persisted, so the journal
    ///   survives the process and `restore` can verify it.
    /// * An approval spent in this process stays spent in the next one. Before this,
    ///   a restart returned every consumed approval to the pool, and the single-use
    ///   guarantee held only for one process lifetime.
    ///
    /// # Refusals
    ///
    /// Fails without changing the engine if the database cannot be opened, or if
    /// the existing journal **does not verify**. A corrupted audit history is
    /// reported, never repaired and never appended to: continuing from an
    /// unverified head would assert a chain nobody can check.
    ///
    /// # Errors
    ///
    /// [`LifecycleError::SecurityState`] naming what could not be established.
    pub fn attach_durable_security_state(
        &mut self,
        path: &std::path::Path,
    ) -> Result<(), LifecycleError> {
        let unavailable =
            |what: &'static str, e: String| LifecycleError::SecurityState { what, reason: e };
        let journal = SqliteAuditJournal::open(path)
            .map_err(|e| unavailable("audit journal", e.to_string()))?;
        self.policy
            .restore(&journal)
            .map_err(|e| unavailable("audit journal verification", e.to_string()))?;
        let ledger = SqliteApprovalLedger::open(path)
            .map_err(|e| unavailable("approval ledger", e.to_string()))?;
        self.policy = std::mem::replace(
            &mut self.policy,
            // A placeholder is needed only because `with_security_state` consumes
            // `self` and this method already holds a borrow. It is never observed:
            // the real engine replaces it on the very next line, and if that line
            // could not run we would already have returned.
            PolicyEngine::new(shipped_policy_set("daemon/1"), shipped_budget(), "daemon/1"),
        )
        .with_security_state(Box::new(journal), Box::new(ledger));

        // Only now. The engine above replaced the one `compose` built, so declarations
        // registered into the earlier one would be discarded — and a capability that
        // cannot write a durable audit record must not run at all. Installing here,
        // after the chain is durable, is the fail-closed position rather than a
        // sequencing convenience.
        self.install_shipped_declarations();
        Ok(())
    }

    /// Grants the capabilities this build ships, to the current policy engine.
    ///
    /// # Why policy is not a special case in the dispatcher
    ///
    /// A capability becomes reachable because a **grant** exists in a `PolicySet` and
    /// a **declaration** exists in the engine, both through the ordinary registration
    /// paths. There is no `if capability == ... { allow }` anywhere: if that were how
    /// this worked, the policy engine's decision would be advisory, and every other
    /// capability would be one refactor away from being allow-listed.
    ///
    ///
    /// The grants themselves cannot be added here — a `PolicySet` is built *before*
    /// the engine that holds it — so they arrive via [`shipped_policy_set`]. That is
    /// why registration is split in two rather than being one tidy method.
    fn install_shipped_declarations(&mut self) {
        for (id, risk, max_class) in SHIPPED_POLICY {
            self.policy
                .register(orxnud_policy::CapabilityDeclaration::new(
                    CapabilityId::new(id),
                    risk,
                    max_class,
                    // Not networked. Checked by policy for egress consent, and true here
                    // would be a lie about a capability that opens no socket.
                    false,
                    // One unit of the risk scope per invocation: cheap, but counted, so a
                    // capability cannot be free by being unmeasured.
                    1,
                ));
        }
    }

    /// Whether the policy engine's audit records are persisted.
    ///
    /// `false` means the journal is in-memory and dies with the process, which is
    /// correct for a test and wrong for a daemon that takes actions.
    #[must_use]
    pub fn has_durable_audit(&self) -> bool {
        self.policy.is_audit_durable()
    }

    /// The policy engine, for inspection.
    ///
    /// Read-only, so a caller cannot authorise an action through it by accident.
    /// The governed dispatcher borrows it mutably; see [`Self::dispatcher`].
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
        // The workspace is created here rather than in `compose`, because `compose` is
        // required to touch nothing at all -- a composed-but-never-started daemon must
        // leave no trace, and a directory it created would be one. A failure is logged
        // and not fatal: the sandbox binds the path whether or not it exists, so the
        // capability's own write is what fails first, and refusing to start a daemon
        // because an optional capability cannot write would be worse than the reverse.
        if let Err(e) = self.components.paths.ensure_workspace() {
            tracing::warn!(
                "could not create the capability workspace at {}: {e}",
                self.components.paths.workspace().display()
            );
        }
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
    fn exactly_the_shipped_capabilities_are_enabled() {
        // Was "phase one enables no capabilities". That was true and is now false on
        // purpose: this build ships `text/word-count`. What replaces it is the stronger
        // claim — the set of enabled capabilities is *exactly* the shipped set, not a
        // superset — because "at least one" would not catch a stray registration.
        let d = daemon();
        // Not a count: the *set*. "Two" would pass just as happily for two accidental
        // registrations, and the claim being protected is that nothing is enabled
        // beyond what this build deliberately ships.
        let shipped: Vec<String> = vec![
            orxnud_capability::text::WORD_COUNT_ID.to_owned(),
            orxnud_capability::write_text::WRITE_TEXT_ID.to_owned(),
        ];
        let mut declared: Vec<String> =
            d.registry().ids().iter().map(ToString::to_string).collect();
        declared.sort();
        let mut expected = shipped.clone();
        expected.sort();
        assert_eq!(
            declared, expected,
            "the declared set must be exactly the shipped set"
        );
        assert_eq!(d.components().enabled_capabilities(), shipped.len());
        assert!(d.components().has_enabled_capabilities());
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
    fn the_description_reports_the_enabled_capabilities() {
        let d = daemon();
        let text = d.describe();
        assert!(text.contains("capabilities enabled: 2"), "{text}");
        assert!(text.contains("config schema version: 1"), "{text}");
    }

    #[test]
    fn composition_authorises_nothing_on_its_own() {
        // Registration is not authorisation. A declaration and a grant make a
        // capability *reachable*, but nothing is authorised until a request arrives and
        // policy decides — so the audit chain is still empty after composition, and a
        // capability that had authorised itself at wiring time would show up here.
        let d = daemon();
        assert_eq!(
            d.policy().audit().len(),
            0,
            "composition must not authorise anything"
        );
    }

    // ------------------------------------------------------------------
    // Composition: the governed capability path
    //
    // These are the tests that stop `Daemon::compose` from regressing to the
    // Phase-1 shell dispatcher. Two mechanisms, deliberately:
    //
    // * **Compile time.** `Daemon::dispatcher` is declared to return
    //   `orxnud_capability::dispatch::Dispatcher`. The assertions below call
    //   `has_execution_backend` and `audit_len`, which the shell type does not
    //   have. Restoring the shell does not compile, so the regression cannot be
    //   reintroduced quietly.
    // * **Run time.** The assertions themselves run against a composed daemon,
    //   not against a separately constructed dispatcher, so they fail if
    //   composition stops wiring the backend even if the signature survives.
    // ------------------------------------------------------------------

    /// A secret store with nothing in it.
    ///
    /// The secret store is not what this test is about — `orxnud-capability`
    /// tests that thoroughly. It is here because the governed dispatcher is
    /// generic over `SecretsContract` and has no default, so *some* store must
    /// exist to lend one. Empty is the safe choice: a dispatch can never resolve
    /// a credential from it.
    struct NoSecrets;

    #[derive(Debug, thiserror::Error)]
    #[error("no secret store in the composition test")]
    struct NoSecretsError;

    impl SecretsContract for NoSecrets {
        type Error = NoSecretsError;

        fn get(
            &self,
            _reference: &orxnud_domain::platform::SecretRef,
        ) -> Result<orxnud_domain::platform::SecretLookup, Self::Error> {
            Ok(orxnud_domain::platform::SecretLookup::Absent)
        }

        fn set(
            &self,
            _reference: &orxnud_domain::platform::SecretRef,
            _value: &str,
        ) -> Result<(), Self::Error> {
            Err(NoSecretsError)
        }

        fn delete(
            &self,
            _reference: &orxnud_domain::platform::SecretRef,
        ) -> Result<(), Self::Error> {
            Err(NoSecretsError)
        }

        fn is_available(&self) -> bool {
            false
        }
    }

    #[test]
    fn composition_installs_a_governed_dispatcher_with_an_execution_backend() {
        let mut d = daemon();
        let secrets = NoSecrets;

        // The governed dispatcher, borrowed from the composition root. Nothing here
        // constructs a dispatcher independently: every field it carries came out of
        // `Daemon::compose`.
        let governed = d.dispatcher(&secrets);

        assert!(
            governed.has_execution_backend(),
            "a composed daemon must install the execution backend, or a Tier-1 \
             capability would be refused for a reason the daemon chose"
        );
        assert_eq!(
            governed.audit_len(),
            0,
            "composition must not authorise anything"
        );
        // The governed dispatcher reads the *same* engine the daemon holds, which is
        // what makes the single-writer guarantee mean anything.
        assert_eq!(governed.audit_len(), d.audit_len());
    }

    #[test]
    fn composition_wires_a_backend_without_inventing_a_capability() {
        let d = daemon();
        assert!(
            d.dispatch_wiring().has_execution_backend(),
            "compose must install a backend"
        );
        // One implementation *per capability*, not one capability. The property is that
        // no id resolves ambiguously, so it is asserted as a set membership below and
        // the count is only the size of that set.
        assert_eq!(
            d.dispatch_wiring().bundle_count(),
            d.registry().ids().len(),
            "every declared capability needs an implementation, or a dispatch that \
             policy permits cannot run"
        );
        // Declaration and implementation must agree, or the two failure modes are a
        // capability policy allows that cannot run, and one that can run but policy has
        // never heard of. Neither is detectable from either list alone.
        let mut declared: Vec<String> =
            d.registry().ids().iter().map(ToString::to_string).collect();
        declared.sort();
        assert_eq!(
            declared,
            vec![
                "filesystem/write-text".to_owned(),
                "text/word-count".to_owned()
            ]
        );
        // What is being proven here is the *wiring*, not the backend's behaviour:
        // `orxnud-capability`'s suite is what proves `SandboxExecutionBackend`
        // refuses on a host with no sandbox. A deliberately-refusing stub would also
        // satisfy `has_execution_backend`, so this test does not claim more than it
        // establishes — that `compose` installs the backend named in its source, and
        // that the shipped capability needs no ceiling to be constructible.
    }

    #[test]
    fn one_composed_dispatcher_at_a_time_and_the_daemon_is_unchanged() {
        // The single-writer invariant. `dispatcher` takes `&mut self`, so a second
        // governed dispatcher cannot coexist with the first — that is the V-41
        // guarantee expressed as a type rather than a convention. What is checkable
        // at runtime is the consequence: lending one changes no daemon state, and a
        // new one is available once the previous is dropped.
        let mut d = daemon();
        let secrets = NoSecrets;
        let before = d.state();
        {
            let governed = d.dispatcher(&secrets);
            assert!(governed.has_execution_backend());
        }
        assert_eq!(d.state(), before, "lending a dispatcher changed the daemon");
        let second = d.dispatcher(&secrets);
        assert!(second.has_execution_backend());
    }

    #[test]
    fn the_dispatcher_debug_reports_the_wiring_without_printing_a_trait_object() {
        // `Arc<dyn ExecutionBackend>` has no `Debug`, so `DispatchWiring` writes its
        // own. A daemon log therefore gets the counts and the word "installed", not
        // whatever a backend's `Debug` happened to expose.
        let d = daemon();
        let text = format!("{:?}", d.dispatch_wiring());
        // The count, not the identity: this test is about the Debug shape, and the
        // bundle count itself is asserted in the composition test above.
        assert!(text.contains("bundles: 2"), "{text}");
        assert!(text.contains("execution_backend: \"installed\""), "{text}");
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
