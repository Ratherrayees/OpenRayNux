//! The serving loop: bounded admission, bounded per-request time, and the scheduler timer.
//!
//! # What this module is
//!
//! The transport lifecycle, extracted from `runtime.rs` because it is now the part with
//! its own invariants and its own failure modes, and because a 6,000-line module in which
//! `serve`, `authenticate` and the provider call sit together is a module in which those
//! invariants are hard to see. Nothing here decides anything: `runtime` still routes,
//! policy still decides, the dispatcher still orchestrates. What lives here is *when* a
//! connection is admitted, *how long* it may take, and *what the daemon does while it
//! waits*.
//!
//! # The bounds, and why each exists
//!
//! Before this module, `serve` awaited `handle_connection` **inline** in the accept loop
//! with no deadline on the frame read. Two consequences, both reachable by any process
//! running as the daemon's own user, and both now tested in
//! `tests/serve_lifecycle.rs`:
//!
//! 1. **Time was unbounded.** A peer that opened a socket and never finished a frame held
//!    the *only* serving path, so no other client was served — for as long as it chose.
//! 2. **Admission was unbounded.** Every accepted connection became an inline await, so
//!    "how many connections" had no answer: the ceiling was one, but expressed as
//!    "the rest of time".
//!
//! The fixes are `ServeLimits`: a **time** bound per phase and a
//! **count** bound on in-flight connections.
//!
//! # What is deliberately *not* changed
//!
//! * **Authentication still precedes a single byte of request.** The identity comparison
//!   happens in the accept loop, before a task is spawned and before any read. Serving
//!   connections concurrently must not become a way to be handed an unparsed frame
//!   earlier, and `tests/identity.rs` pins the refusal paths that would catch it if it did.
//! * **The governed mutex is still the single-writer guarantee** (ADR-0006, V-41). Making
//!   connections concurrent does not make `DurableEngine` shareable, and this module does
//!   not pretend otherwise — see `runtime` for where that lock is and is not held.
//! * **A Tier-1 dispatch still holds that mutex across the sandbox execution.** That is a
//!   real residual, recorded rather than hidden: the dispatcher is a synchronous function
//!   borrowing `&mut Daemon`, so there is no seam at which the lock could be released
//!   mid-effect without breaking the audit obligation the dispatcher settles internally.
//!   Bounding it is a change to the dispatcher, not to the transport. What *is* fixed here
//!   is that a health probe no longer queues behind it — see
//!   `StatusSnapshot`, which holds the values `daemon/status` reports.

use std::sync::Arc;
use std::time::Duration;

use orxnud_domain::platform::SecretsContract;
use orxnud_platform_ipc::{IpcError, Listener};
use orxnud_protocol::frame::{RequestId, Response};

use crate::Daemon;
use crate::runtime::{
    ArgvPayloadDisclosure, AuthenticatedPrincipal, InstallationIdentity, RequestError,
    argv_payload_disclosure, authenticate,
};
use crate::task_service::TaskService;

/// The governed triple: the daemon, its secret store, and the single task engine.
pub(crate) type Governed<S> = (Daemon, S, TaskService);

/// How long a connection may take, and how many may be in flight at once.
///
/// Every field is a bound rather than a policy: the point is that none of them is
/// unbounded, and that the values sit in one place a test can assert about instead of
/// being scattered across call sites as literals.
///
/// # The numbers, and what each is measured against
///
/// * `frame_read` bounds **the time to finish sending one request line**. It must exceed
///   the slowest legitimate client by a wide margin. 30 s is roughly four thousand times a
///   measured 8 ms request and leaves room for a slow pipe or a loaded machine.
/// * `request` bounds **the whole request**, execution included. It must exceed the
///   longest thing a single request can legitimately do: a Tier-1 dispatch is capped by
///   the sandbox contract at 10 s, and a provider call by the HTTP provider's 60 s.
///   **120 s** is chosen to exceed both with margin, not to be tight — a deadline that cut
///   a legitimate 60-second model call would be a correctness bug dressed as a latency
///   feature.
/// * `max_connections` bounds **in-flight connections**. 64 is far above what one person
///   and their scripts generate, and low enough that a stuck-peer loop cannot exhaust file
///   descriptors — each admitted connection costs one, and a refused one costs one only
///   transiently.
/// * `shutdown_drain` bounds how long shutdown waits for in-flight tasks. It is a
///   backstop, not a courtesy: after it, tasks are cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeLimits {
    /// How long one client may take to finish sending its request line.
    pub frame_read: Duration,
    /// How long the whole of one request may take, execution included.
    pub request: Duration,
    /// How many connections may be served at once.
    pub max_connections: usize,
    /// How long shutdown waits for in-flight connection tasks before cutting them.
    pub shutdown_drain: Duration,
}

impl Default for ServeLimits {
    /// The production values. Every number is justified in the type's documentation.
    fn default() -> Self {
        Self {
            frame_read: Duration::from_secs(30),
            request: Duration::from_secs(120),
            max_connections: 64,
            shutdown_drain: Duration::from_secs(5),
        }
    }
}

impl ServeLimits {
    /// The refusal an over-ceiling peer is answered with.
    ///
    /// Written here rather than at the call site so the machine-readable reason and the
    /// limit that produced it cannot drift apart.
    fn overload_refusal(&self) -> RequestError {
        RequestError::Unavailable {
            reason: "too-many-connections".to_owned(),
            detail: Some(format!(
                "this daemon is already serving its limit of {} connections; retry shortly",
                self.max_connections
            )),
        }
    }
}

/// What the daemon answers `daemon/status` with, captured once at startup.
///
/// # Why this exists
///
/// The `runtime` module documentation claimed that "status requests do not take [the
/// governed] lock". They did: `daemon/status` and `capability/list` both called
/// `governed.lock().await` to read fields that are **composition state, immutable while
/// serving** — the registry, the enabled count, whether durable security state is
/// attached, and the argv-payload disclosure.
///
/// Reading immutable state through the single-writer mutex is not a safety property; it
/// is a health check queued behind whatever the daemon happens to be doing. With a
/// 60-second provider wait or a 10-second sandboxed write in flight, that turns
/// `orxnud doctor` — the command a person runs when they think something is wrong — into
/// the command that hangs when something is wrong.
///
/// So the values are captured once, at composition, and served without a lock. That is
/// not a snapshot going stale: every field here is fixed before the endpoint is bound, and
/// nothing served after startup changes any of them.
///
/// The runtime sandbox capability is deliberately **not** here. It is a property of the
/// host rather than of the composition, it is what the dispatcher consults at dispatch
/// time, and caching it would make `doctor` report a stale answer about the one thing a
/// reader most needs to be current. It is still a cheap probe that takes no lock.
#[derive(Debug, Clone)]
pub(crate) struct StatusSnapshot {
    durable_audit: bool,
    enabled_capabilities: usize,
    argv_payload: Option<Arc<ArgvPayloadDisclosure>>,
}

impl StatusSnapshot {
    /// Reads every locked field once, while nothing else can hold the mutex.
    ///
    /// Called from `Runtime::finish` after `attach_durable_security_state` and before the
    /// endpoint is bound, so the values cannot be stale even in principle.
    pub(crate) fn capture<S: SecretsContract>(governed: &Governed<S>) -> Self {
        Self {
            durable_audit: governed.0.has_durable_audit(),
            enabled_capabilities: governed.0.components().enabled_capabilities(),
            argv_payload: argv_payload_disclosure(governed).map(Arc::new),
        }
    }

    pub(crate) fn durable_audit(&self) -> bool {
        self.durable_audit
    }

    pub(crate) fn enabled_capabilities(&self) -> usize {
        self.enabled_capabilities
    }

    pub(crate) fn argv_payload(&self) -> Option<&ArgvPayloadDisclosure> {
        self.argv_payload.as_deref()
    }
}

/// Closes the listener and removes the endpoint this runtime created.
///
/// Held for the duration of the serve loop so the endpoint cannot outlive the runtime on
/// any path, including an early return on a genuine transport error.
///
/// # Why the removal is still safe
///
/// The path here is not arbitrary: it is the endpoint `Runtime::start` successfully bound,
/// and `orxnud_platform_ipc::bind` **refuses** a path another live daemon is listening on
/// rather than unlinking it. So by the time a guard exists, the socket file is this
/// runtime's own. Removing a file that has since been replaced by something else is the
/// one case worth guarding against, and the check below does exactly that — it unlinks
/// only a socket file, and only at the recorded path.
///
/// A failure to remove is ignored on purpose: it is not the error the caller asked about,
/// and inventing a second failure here would replace a real diagnosis with a cosmetic one.
pub(crate) struct EndpointRelease {
    listener: Arc<Listener>,
    path: Option<std::path::PathBuf>,
}

impl EndpointRelease {
    pub(crate) fn new(listener: Arc<Listener>, path: Option<std::path::PathBuf>) -> Self {
        Self { listener, path }
    }
}

impl Drop for EndpointRelease {
    fn drop(&mut self) {
        // Stop accepting before the path goes away, so a client that connected before
        // shutdown is never refused by a vanished endpoint.
        self.listener.close();
        if let Some(path) = self.path.take() {
            // The platform crate owns both the platform knowledge this needs and the
            // ownership rule: it bound the path, and it is the only place that may unlink
            // a socket file.
            orxnud_platform_ipc::release_endpoint(&path);
        }
    }
}

/// Everything the loop needs, already `Arc`-wrapped so a connection task can outlive the
/// accept arm that spawned it.
///
/// The `Arc`s are taken by [`Runtime::serve`](crate::runtime::Runtime::serve) rather than
/// borrowed, which is what lets each connection be its own task without a `'static`
/// transmute or a leaked borrow. `Governed` is an `Arc<Mutex<…>>`, not a bare `Mutex`:
/// a bare one cannot cross a task boundary at all, and pretending otherwise is how a
/// serving loop ends up with a `&'static Mutex` it should never have had.
pub(crate) struct Serving<S: SecretsContract + Send + Sync + 'static> {
    pub(crate) listener: Arc<Listener>,
    pub(crate) governed: Arc<tokio::sync::Mutex<Governed<S>>>,
    pub(crate) proposer: Option<Arc<dyn crate::proposer::ProposalProvider>>,
    pub(crate) observations: Arc<std::sync::Mutex<crate::observation::ObservationStore>>,
    pub(crate) installation: InstallationIdentity,
    pub(crate) status: Arc<StatusSnapshot>,
}

/// Serves until `shutdown` resolves.
///
/// Four bounded things happen here, and each bound is stated in [`ServeLimits`]: admission,
/// the frame read, the whole request, and the shutdown drain.
///
/// # The three `select!` arms, and why the ordering is what it is
///
/// `biased` with shutdown first, then the scheduler timer, then task reaping, then
/// `accept`. Each position is load-bearing:
///
/// * **shutdown first** so a signal is observed even while connections are in flight.
/// * **the scheduler timer next** so a due occurrence is not delayed behind a burst of
///   accepted sockets — a tick that is late is a missed occurrence, and misfire policy
///   exists to record those rather than hide them.
/// * **reaping before `accept`** so a finished connection task is collected promptly. Its
///   position above `accept` is what keeps the `JoinSet` from growing without bound when
///   connections are short-lived and arrivals are fast.
///
/// # The scheduler
///
/// The timer arm is driven by `TaskService::next_wakeup_ms` — the engine's actual next
/// occurrence, not a fixed poll interval. Three consequences worth stating:
///
/// * **No busy-spin.** With no schedules `next_wakeup_ms` is `None`, the arm is disabled by
///   its `if` guard, and `select!` never polls it at all.
/// * **A distant wakeup cannot starve a new schedule.** The deadline is re-read on every
///   pass of the loop, so a schedule created while the loop was parked arms a sooner
///   deadline on the next turn — and creating one is itself a request, which wakes the
///   loop through `accept`.
/// * **A tick failure is surfaced, not swallowed.** The pass is bounded by
///   `EngineLimits::max_schedules_per_pass` and `catch_up_cap`, so it cannot run away, but
///   a storage fault in it would otherwise be a silent no-op until someone noticed a task
///   that never appeared.
pub(crate) async fn serve<S: SecretsContract + Send + Sync + 'static>(
    serving: Serving<S>,
    limits: ServeLimits,
    cleanup: Option<std::path::PathBuf>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), IpcError> {
    // Taken before the loop and released on every exit, including the `?`s below, so
    // "the endpoint outlives the runtime" is an invariant of the structure rather than a
    // property of control flow. See `EndpointRelease`.
    let _release = EndpointRelease::new(Arc::clone(&serving.listener), cleanup);
    let Serving {
        listener,
        governed,
        proposer,
        observations,
        installation,
        status,
    } = serving;

    tokio::pin!(shutdown);

    // The admission ceiling. One permit per admitted connection, held for the life of its
    // task, so the ceiling is a real bound rather than a counter that drifts upward.
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    // The live connection tasks, owned by the loop. `JoinSet` aborts whatever it still
    // holds when it is dropped, so even the early-return path below cannot leak a task —
    // and the explicit drain on the shutdown path is about *ordering*, not about cleanup.
    let mut live: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    loop {
        // When the next scheduled occurrence is due. Read fresh on every pass, so a
        // schedule created while the loop was parked arms a sooner deadline on the next
        // turn rather than waiting out the old one.
        let delay = next_wakeup(&governed).map(|(now, at)| {
            Duration::from_millis(u64::try_from(at.saturating_sub(now)).unwrap_or(u64::MAX))
        });

        tokio::select! {
            biased;

            () = &mut shutdown => {
                drain_connections(&mut live, limits.shutdown_drain).await;
                break;
            }

            _ = sleep_for(delay), if delay.is_some() => {
                run_scheduler_pass(&governed).await;
            }

            Some(joined) = live.join_next(), if !live.is_empty() => {
                if let Err(join) = joined {
                    // A panicking connection task is reported rather than silently kept.
                    // It cannot take the daemon with it — it is one task — but a swallowed
                    // panic is how a bug becomes invisible.
                    tracing::warn!(error = ?join, "a connection task ended abnormally");
                }
            }

            accepted = listener.accept() => {
                let mut stream = match accepted {
                    Ok(s) => s,
                    // Closed during shutdown, or the socket went away. Either way there is
                    // nothing left to serve.
                    Err(IpcError::Disconnected) | Err(IpcError::Unsupported) => break,
                    Err(e) => return Err(e),
                };

                // The identity decision is made here, before a task is spawned and before
                // `handle_connection` reads a single byte. That ordering is the property:
                // no request is ever parsed, let alone routed, by a caller whose identity
                // is unknown or wrong — so there is no path from "connected" to "granted
                // authority" that skips this check, including the new one through a
                // spawned task.
                let authenticated = match authenticate(&stream, installation) {
                    Ok(principal) => principal,
                    Err(refusal) => {
                        // Answered and then dropped, so the peer learns *why* rather than
                        // seeing a connection reset. The connection ends either way: a
                        // refused caller gets no channel to speak on.
                        let response = Response::err(
                            RequestId::Text("unknown".to_owned()),
                            refusal.to_rpc(),
                        );
                        let _ = crate::runtime::write_response(&mut stream, &response).await;
                        continue;
                    }
                };

                // Admission. At the ceiling the peer is *answered* with a refusal naming
                // the limit — never queued silently, and never admitted and then starved.
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    let response = Response::err(
                        RequestId::Text("unknown".to_owned()),
                        limits.overload_refusal().to_rpc(),
                    );
                    let _ = crate::runtime::write_response(&mut stream, &response).await;
                    continue;
                };

                let governed = Arc::clone(&governed);
                let proposer = proposer.clone();
                let observations = Arc::clone(&observations);
                let status = Arc::clone(&status);
                live.spawn(async move {
                    // Held for the whole task, so the slot returns whether the connection
                    // ended normally, timed out, or panicked. This is what makes the
                    // ceiling a real bound rather than a counter that drifts upward.
                    let _slot = slot;
                    serve_one(
                        &mut stream,
                        authenticated,
                        &governed,
                        &proposer,
                        &observations,
                        &status,
                        limits,
                    )
                    .await;
                });
            }
        }
    }

    Ok(())
}

// --------------------------------------------------------------------------
// Scheduler
// --------------------------------------------------------------------------

/// The next occurrence the engine says is due, in wall-clock milliseconds.
///
/// Read through the governed mutex because it is durable state, but **without waiting** for
/// it: `try_lock`, not `lock`. A pass in progress is bounded by the sandbox deadline or the
/// provider timeout, and neither should stop the loop from accepting connections in the
/// meantime — so a contended read yields the timer arm and lets the next turn read it
/// again, rather than parking the accept arm behind a dispatch.
///
/// Returning `None` on contention is not a claim that nothing is scheduled; it is a claim
/// that *this turn* has no deadline to arm. The next turn corrects it, and no occurrence is
/// lost because a tick re-derives everything from durable state.
fn next_wakeup<S: SecretsContract + Send + Sync + 'static>(
    governed: &Arc<tokio::sync::Mutex<Governed<S>>>,
) -> Option<(i64, i64)> {
    let Ok(mut g) = governed.try_lock() else {
        return None;
    };
    let now = g.2.clock_now_ms();
    // The delay rather than the absolute instant, and deliberately: converting a wall
    // clock millisecond into a monotonic `tokio::time::Instant` has no total function
    // (`Instant` has no `From<SystemTime>`), and every workaround for it — re-anchoring,
    // guessing an epoch — is a way to turn one clock into two. `now` and the wake-up come
    // from the same clock in the same read, so their difference is meaningful by
    // construction.
    g.2.next_wakeup_ms(now).ok().flatten().map(|at| (now, at))
}

/// Sleeps until a wall-clock millisecond instant, or forever when there is none.
///
/// `None` must not become `sleep(ZERO)`: that is a busy-spin, and an idle daemon must cost
/// nothing. `pending()` is the honest expression of "there is no deadline".
async fn sleep_for(delay: Option<Duration>) {
    let Some(delay) = delay else {
        std::future::pending::<()>().await;
        return;
    };
    // `sleep` of zero would be a busy-spin, so an already-due occurrence is still given a
    // tick of the runtime to reach the next pass. One millisecond is the smallest bound
    // that is not "yield and hope", and it is bounded rather than unbounded, which is the
    // property that matters: a schedule whose occurrence is in the past produces at most
    // one pass per millisecond, and each pass is itself capped by the engine's limits.
    tokio::time::sleep(delay.max(Duration::from_millis(1))).await;
}

/// Runs one bounded scheduler pass.
///
/// # Failures are logged and the loop continues
///
/// A pass that cannot run is a storage fault, and the existing semantics for that are
/// already conservative: the occurrence is not marked fired, so a later pass either fires
/// it or records it as a misfire under the schedule's own policy. What must not happen is
/// a silent no-op, so this logs at `error`.
///
/// The pass is bounded by `EngineLimits::max_schedules_per_pass` and `catch_up_cap` inside
/// the engine, so a slow pass cannot monopolise the loop; nothing here adds unbounded work.
async fn run_scheduler_pass<S: SecretsContract + Send + Sync + 'static>(
    governed: &Arc<tokio::sync::Mutex<Governed<S>>>,
) {
    let mut g = governed.lock().await;
    let now = g.2.clock_now_ms();
    match g.2.tick(now) {
        Ok(report) => {
            if report.tasks_created > 0 || report.dropped > 0 {
                tracing::info!(
                    considered = report.schedules_considered,
                    created = report.tasks_created,
                    dropped = report.dropped,
                    already_present = report.fires_already_present,
                    "scheduler pass"
                );
            }
        }
        Err(e) => {
            // Surfaced rather than swallowed: this is the only place a scheduler fault
            // would otherwise be invisible until a task simply never appeared.
            tracing::error!(
                error = ?e,
                "scheduler pass failed; the occurrence is not recorded as fired"
            );
        }
    }
}

// --------------------------------------------------------------------------
// One connection
// --------------------------------------------------------------------------

/// Serves one authenticated connection, within both deadlines.
///
/// The two bounds are separate because they bound different things. A peer that will not
/// finish sending is not holding a governed resource, and cutting it early is free. A
/// request that is executing a sandboxed capability *is* holding durable state, and cutting
/// it is not free — so the request deadline is deliberately the looser of the two and is
/// set above every bounded operation a single request can contain.
///
/// # A timeout cannot cancel an effect, and the reason is structural
///
/// The request deadline is a `tokio::time::timeout` around the whole of
/// `handle_connection`. Such a timeout can only fire when its future is polled, and a
/// future is only polled at an `.await`.
///
/// `execute_proposal` has exactly **one** `.await`, and it is the `governed.lock()` that
/// *precedes* the effect reservation. Everything from spending the approval, through
/// `reserve_effect`, through the sandboxed `dispatch`, to `resolve_effect`, runs without a
/// single suspension point.
///
/// So the deadline has exactly two places it can land:
///
/// * **before** the reservation — nothing was written, nothing needs recovering; or
/// * **after** settlement — the effect is resolved and the state is consistent.
///
/// There is no third case in which it interrupts a reserved-but-unsettled effect, which is
/// what makes "a timeout cannot turn a possibly-completed non-idempotent effect into a
/// retryable one" true by construction rather than by luck. The conservative
/// `needs-verification` path is still reachable — by a genuine crash or a genuine kill —
/// and is unchanged.
///
/// **This is a property of the shape of `execute_proposal`, not of this function**, so it
/// is pinned where it can be seen: see
/// `crate::runtime::tests::the_effect_critical_section_never_suspends`. Adding an `.await`
/// between the reservation and its settlement would break it silently, and that check is
/// what makes the break loud.
async fn serve_one<S: SecretsContract + Send + Sync + 'static>(
    stream: &mut orxnud_platform_ipc::LocalStream,
    authenticated: AuthenticatedPrincipal,
    governed: &Arc<tokio::sync::Mutex<Governed<S>>>,
    provider: &Option<Arc<dyn crate::proposer::ProposalProvider>>,
    observations: &Arc<std::sync::Mutex<crate::observation::ObservationStore>>,
    status: &StatusSnapshot,
    limits: ServeLimits,
) {
    let outcome = tokio::time::timeout(
        limits.request,
        crate::runtime::handle_connection(
            stream,
            authenticated,
            governed,
            provider,
            observations,
            status,
            limits.frame_read,
        ),
    )
    .await;

    match outcome {
        Ok(Ok(())) | Ok(Err(IpcError::Disconnected)) => {}
        Ok(Err(e)) => {
            // Transport faults are ordinary: a client that sent a request and closed
            // without reading is normal behaviour, not an attack.
            tracing::debug!(error = ?e, "connection ended with a transport fault");
        }
        Err(_) => {
            // Classified as a deadline, not a disconnect and not an internal fault: the
            // daemon is healthy and the client was too slow, so the recovery is external.
            tracing::warn!(
                budget_ms = limits.request.as_millis() as u64,
                "request exceeded its deadline; the connection was closed"
            );
        }
    }
}

/// Waits for in-flight connection tasks, then cuts whatever is left.
///
/// # The policy, stated
///
/// On shutdown, in-flight connections are given [`ServeLimits::shutdown_drain`] to finish
/// and are then cut. That is deliberately not "wait forever": a peer holding a connection
/// open must not be able to delay shutdown indefinitely, which is the same unbounded-time
/// defect as the original one, relocated to a different moment.
///
/// The cut is safe for durable state because it is the same cut a timeout performs. A
/// governed request that has reserved an effect has already written that reservation, so
/// recovery finds it on the next start. A request cut *before* it reserved anything wrote
/// nothing, so there is nothing to reconcile.
async fn drain_connections(live: &mut tokio::task::JoinSet<()>, budget: Duration) {
    let finished = tokio::time::timeout(budget, async {
        while let Some(joined) = live.join_next().await {
            if let Err(join) = joined {
                tracing::warn!(error = ?join, "a connection task ended abnormally during shutdown");
            }
        }
    })
    .await;
    if finished.is_err() {
        // `shutdown` aborts every task the set still holds and reaps them, so this is a
        // cut rather than a leak: after it returns, no task this runtime spawned is alive.
        live.shutdown().await;
        tracing::warn!(
            budget_ms = budget.as_millis() as u64,
            "in-flight connections did not finish within the shutdown drain budget; they were cut"
        );
    }
}
