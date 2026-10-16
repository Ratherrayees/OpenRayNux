//! The serving loop's lifecycle: admission, deadlines, isolation and drain.
//!
//! # Why this file exists
//!
//! The daemon used to await every connection to completion **inside** the listener's
//! accept loop, with no deadline around the frame read. Two consequences, both reachable
//! by any process running as the daemon's own user, and both reproduced before the fix:
//!
//! 1. a peer that opened a socket and never finished its frame stopped every other
//!    client being served, for as long as it held the socket — indefinitely;
//! 2. connection admission had no bound at all, expressed as "the rest of time" rather
//!    than as a number.
//!
//! Every test here reaches the daemon through a **real** Unix domain socket against a
//! **real** `Runtime` serving on a real task. A mock around `handle_connection` would not
//! exercise the accept loop, the read deadline or the connection ceiling, which are the
//! three things that changed.
//!
//! # Platform
//!
//! Every test here reaches the daemon through a Unix domain socket, which has no Windows
//! equivalent: the local IPC transport *refuses* there rather than binding a named pipe
//! (`crates/orxnud-platform-ipc`, ADR-0003/0035). Each test therefore carries
//! `#[cfg_attr(not(target_os = "linux"), ignore = ...)]` naming that reason, and the file
//! still *compiles* for MSVC — which is what the `windows-check` lane's `--all-targets`
//! proves. What these tests prove is Linux evidence, either way. V-29.
//!
//! # Time discipline
//!
//! Every time-based assertion has a **reasoned** bound rather than a sleep that happens to
//! pass on a fast machine:
//!
//! * `PROBE_BUDGET` is the ceiling for "an unrelated safe operation still answers". It is
//!   generous (2 s) because it must absorb a loaded CI runner, and it is only meaningful
//!   because the *defect* it guards against is unbounded — a stalled frame never produces
//!   an answer at any budget.
//! * `RELEASE_BUDGET` is the ceiling for "the daemon gave up on that peer". It must exceed
//!   the frame deadline the test configures.
//! * `DRAIN_BUDGET` is the ceiling for shutdown, and must exceed the frame deadline so a
//!   peer-held connection is expected to be *cut* rather than waited for.
//!
//! Where a test needs a peer to *hold* something it does so by not closing the socket and
//! by waiting on a condition — never by sleeping "long enough to probably still be
//! holding".

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use orxnud_daemon::Paths;
use orxnud_daemon::runtime::Runtime;
use orxnud_daemon::serve::ServeLimits;
use orxnud_domain::platform::{SecretLookup, SecretRef, SecretsContract};
use orxnud_platform_ipc::BlockingClient;
use orxnud_protocol::method::Method;
use serde_json::{Value, json};

/// The ceiling for "an unrelated safe operation still answers while something else is
/// stuck". Generous on purpose: it distinguishes "answered" from "never answered", and
/// only the second is the defect.
const PROBE_BUDGET: Duration = Duration::from_secs(2);

/// The ceiling for "the daemon released a peer that would not finish a frame".
const RELEASE_BUDGET: Duration = Duration::from_secs(5);

/// The ceiling for shutdown once signalled.
const DRAIN_BUDGET: Duration = Duration::from_secs(10);

// --------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------

/// A secret store with nothing in it, so a dispatch can never resolve a credential.
///
/// Keeps this suite off the real keyring, which is the point: a test that reached a
/// user's Secret Service would be testing the wrong thing.
struct NoSecrets;

#[derive(Debug, thiserror::Error)]
#[error("no secret store in the serving-lifecycle suite")]
struct NoSecretsError;

impl SecretsContract for NoSecrets {
    type Error = NoSecretsError;
    fn get(&self, _r: &SecretRef) -> Result<SecretLookup, Self::Error> {
        Ok(SecretLookup::Absent)
    }
    fn set(&self, _r: &SecretRef, _v: &str) -> Result<(), Self::Error> {
        Err(NoSecretsError)
    }
    fn delete(&self, _r: &SecretRef) -> Result<(), Self::Error> {
        Err(NoSecretsError)
    }
    fn is_available(&self) -> bool {
        false
    }
}

/// Unique per call, so two tests that both hold a directory cannot collide.
fn dir(tag: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("orxnud-serve-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// Multi-threaded on purpose.
///
/// These tests drive a real socket from a *blocking* client while the runtime serves on
/// another thread. A current-thread runtime would deadlock: the blocking read would
/// starve the accept loop that has to answer it.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

/// A running daemon, its endpoint, and a handle that stops it.
struct Harness {
    endpoint: PathBuf,
    stop: tokio::sync::oneshot::Sender<()>,
    serving: tokio::task::JoinHandle<Result<(), orxnud_platform_ipc::IpcError>>,
    root: PathBuf,
}

impl Harness {
    async fn start(tag: &str, limits: ServeLimits) -> Self {
        let root = dir(tag);
        let runtime = Runtime::start(Paths::under(&root), NoSecrets)
            .await
            .expect("start")
            .with_limits(limits);
        let endpoint = runtime.endpoint().to_path_buf();
        let (stop, rx) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(runtime.serve(async move {
            let _ = rx.await;
        }));
        Self {
            endpoint,
            stop,
            serving,
            root,
        }
    }

    /// Signals shutdown and waits, within a bounded budget, for `serve` to return.
    ///
    /// The budget is the assertion as much as the wait: a `serve` that cannot be stopped
    /// is a defect, so this panics with the elapsed time rather than hanging the suite.
    async fn stop_bounded(self) -> Duration {
        let Self {
            stop,
            serving,
            root,
            ..
        } = self;
        let _ = stop.send(());
        let started = Instant::now();
        match tokio::time::timeout(DRAIN_BUDGET, serving).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => panic!("serve reported a transport failure: {e}"),
            Ok(Err(join)) => panic!("the serve task panicked: {join}"),
            Err(_) => panic!(
                "serve did not return within {DRAIN_BUDGET:?} of shutdown being signalled; \
                 in-flight connection tasks are not being cut"
            ),
        }
        let _ = std::fs::remove_dir_all(&root);
        started.elapsed()
    }
}

fn connect(endpoint: &Path) -> Option<BlockingClient> {
    orxnud_platform_ipc::connect_blocking(endpoint)
}

/// One complete request over a real connection, measured.
///
/// `None` on any failure, including a read timeout — so a caller can tell "refused" from
/// "never answered", which is the distinction every test here turns on.
fn call(endpoint: &Path, line: &[u8], budget: Duration) -> Option<(Value, Duration)> {
    let started = Instant::now();
    let mut s = connect(endpoint)?;
    s.set_read_timeout(Some(budget)).ok()?;
    let _ = s.write_all(line);
    let _ = s.write_all(b"\n");
    let _ = s.flush();
    let mut reply = String::new();
    BufReader::new(s).read_line(&mut reply).ok()?;
    let value = serde_json::from_str(&reply).ok()?;
    Some((value, started.elapsed()))
}

/// A safe, read-only probe: `daemon/status` answers from composition state and performs no
/// side effect, so it is the right thing to assert is still reachable.
fn status_probe(endpoint: &Path, budget: Duration) -> Option<(Value, Duration)> {
    let line = serde_json::to_vec(
        &json!({"jsonrpc": "2.0", "id": 1, "method": Method::DaemonStatus.as_str()}),
    )
    .expect("frame");
    call(endpoint, &line, budget)
}

/// The `daemon/status` frame, as one line.
fn status_frame() -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": Method::DaemonStatus.as_str()}))
        .expect("frame")
}

/// The machine-readable reason on a refusal, or `None` if the reply is not a refusal.
fn refusal_reason(reply: &Value) -> Option<&str> {
    reply.get("error")?.get("data")?.get("reason")?.as_str()
}

/// Waits for `f` to hold, rather than assuming it does.
///
/// Used wherever a test needs "the first peer is now inside the read". A bare sleep makes
/// the test pass or fail depending on machine speed, which is the difference between a
/// regression test and a coin flip.
async fn eventually<F: FnMut() -> bool>(budget: Duration, mut f: F) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Opens a connection and starts a frame it will never finish.
///
/// Returns the open peer. A frame is one newline-terminated line, so sending bytes with no
/// trailing newline is a genuine partial frame: the runtime has committed to reading it and
/// has no reason to stop short of its deadline.
fn start_stalled_frame(endpoint: &Path) -> BlockingClient {
    let mut s = connect(endpoint).expect("stalling peer connects");
    s.write_all(br#"{"jsonrpc":"2.0","id":1,"method":"daemon/status""#)
        .expect("partial frame");
    s.flush().expect("flush");
    s
}

// --------------------------------------------------------------------------
// 1. Incomplete-frame isolation
// --------------------------------------------------------------------------

/// A peer holding an unfinished frame must not stop any other client being served.
///
/// This is the regression the whole package exists for. Before the fix the accept loop
/// awaited `handle_connection` inline, so the first peer's open read was the *only* serving
/// path and this assertion could never pass at any budget: the answer came only when the
/// stalling peer closed, which this test deliberately never does until after the probe has
/// been measured.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "real Unix socket required; see file header"
)]
fn an_incomplete_frame_does_not_stop_another_client_being_served() {
    rt().block_on(async {
        let harness = Harness::start("incomplete-frame", ServeLimits::default()).await;

        let stall = start_stalled_frame(&harness.endpoint);

        // The probe must answer while `stall` is still open.
        let (reply, elapsed) = status_probe(&harness.endpoint, PROBE_BUDGET).unwrap_or_else(|| {
            panic!(
                "a second client received no answer to daemon/status within {PROBE_BUDGET:?} \
                 while an authenticated peer held an incomplete frame; the stalling peer is \
                 still open, so the serving path was blocked rather than the client being slow"
            )
        });
        assert!(
            reply
                .get("result")
                .and_then(|r| r.get("status"))
                .is_some_and(|s| s == "running"),
            "the probe must be answered by the daemon, not refused: {reply}"
        );
        assert!(
            elapsed < PROBE_BUDGET,
            "the probe took {elapsed:?}, which is not a useful bound"
        );

        // The stalling peer is still connected: the probe did not succeed because the
        // stall ended.
        drop(stall);
        harness.stop_bounded().await;
    });
}

/// A peer that never finishes a frame is eventually given up, and the daemon survives.
///
/// The second half of the deadline requirement: bounding a read is only useful if the
/// connection is actually released. This asserts the *daemon* is still serving afterwards,
/// which is the property that matters — a timeout that killed the process would satisfy a
/// naive "did it stop blocking" check.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "real Unix socket required; see file header"
)]
fn a_peer_that_never_finishes_a_frame_is_eventually_released_and_the_daemon_survives() {
    rt().block_on(async {
        // A deliberately tiny deadline so this asserts the mechanism rather than waiting
        // out the production value. The production value is separately pinned by
        // `the_serve_limits_are_bounded`.
        let limits = ServeLimits {
            frame_read: Duration::from_millis(250),
            request: Duration::from_secs(10),
            max_connections: 8,
            shutdown_drain: Duration::from_secs(5),
        };
        let harness = Harness::start("frame-deadline", limits).await;

        let stall = start_stalled_frame(&harness.endpoint);

        // A well-formed client arriving after the stalling peer must be served. It may
        // arrive before the deadline expires — both outcomes are correct — so this only
        // requires that the daemon never stops answering.
        assert!(
            eventually(PROBE_BUDGET, || {
                status_probe(&harness.endpoint, Duration::from_millis(500)).is_some()
            })
            .await,
            "the daemon stopped answering within {PROBE_BUDGET:?} of a peer opening an \
             unfinished frame"
        );

        // And the stalling peer is eventually let go. The daemon closing its end of the
        // socket makes the reader here see EOF, which is how a released connection is
        // observed from the client side without guessing about signals.
        let mut reader = stall.try_clone().expect("clone for reading");
        reader.set_read_timeout(Some(RELEASE_BUDGET)).ok();
        let mut buf = [0u8; 1];
        let give_up_at = Instant::now() + RELEASE_BUDGET;
        let released = loop {
            if Instant::now() >= give_up_at {
                break false;
            }
            match reader.read(&mut buf) {
                // EOF: the daemon closed its end, which is the release.
                Ok(0) => break true,
                // A refusal followed by a close is the deadline having been reported.
                Ok(_) => continue,
                // Timed out again: still holding.
                Err(_) => continue,
            }
        };
        assert!(
            released,
            "the peer that never finished a frame was still connected after {RELEASE_BUDGET:?}, \
             so the frame-read deadline is not being enforced"
        );

        // The daemon is still serving after having released that connection.
        assert!(
            status_probe(&harness.endpoint, PROBE_BUDGET).is_some(),
            "the daemon did not answer after releasing a peer that exceeded its frame deadline"
        );

        drop(stall);
        harness.stop_bounded().await;
    });
}

/// An over-limit peer is *told* it is over the limit, and the daemon keeps serving.
///
/// Before the fix there was no ceiling to cross — every accepted connection became an
/// inline await — so the only way to observe connection pressure was to watch the daemon
/// stop answering.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "real Unix socket required; see file header"
)]
fn connection_pressure_is_refused_with_a_typed_reason_rather_than_queued() {
    rt().block_on(async {
        let limits = ServeLimits {
            // Long enough that the frame deadlines do not fire during this test: the thing
            // under test is admission, not expiry.
            frame_read: Duration::from_secs(30),
            request: Duration::from_secs(60),
            max_connections: 3,
            shutdown_drain: Duration::from_secs(5),
        };
        let harness = Harness::start("admission", limits).await;

        // Fill the ceiling with peers that never finish a frame.
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(start_stalled_frame(&harness.endpoint));
        }
        // The admits are asynchronous, so give the loop a moment to take them. The
        // condition, not a sleep: an over-limit refusal is itself the proof that the
        // admits landed, so the loop below converges on its own.
        let mut refused_at: Option<(Value, Duration)> = None;
        let deadline = Instant::now() + PROBE_BUDGET;
        while Instant::now() < deadline {
            if let Some((reply, elapsed)) = call(
                &harness.endpoint,
                &status_frame(),
                Duration::from_millis(500),
            ) && refusal_reason(&reply) == Some("too-many-connections")
            {
                refused_at = Some((reply, elapsed));
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let (refusal, elapsed) = refused_at.unwrap_or_else(|| {
            panic!(
                "with 3 peers holding open frames and a ceiling of 3, the next client was \
                 never told it was over the limit within {PROBE_BUDGET:?}; it must be \
                 refused with a typed reason, not queued or served"
            )
        });
        assert!(
            elapsed < PROBE_BUDGET,
            "the refusal took {elapsed:?}, which is not a useful bound"
        );
        assert_eq!(
            refusal_reason(&refusal),
            Some("too-many-connections"),
            "the refusal must name its own reason so a client can tell capacity from a fault"
        );
        // And it is the recovery-is-external bucket, not an internal fault: a client told
        // "your daemon is broken" would file a bug report instead of retrying.
        let code = refusal
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_i64);
        assert_ne!(
            code,
            Some(-32603),
            "a capacity refusal must not be reported as an internal error: {refusal}"
        );

        // Capacity frees as peers disconnect, and the daemon resumes serving.
        drop(held);
        assert!(
            eventually(PROBE_BUDGET, || {
                status_probe(&harness.endpoint, Duration::from_millis(300))
                    .is_some_and(|(v, _)| v.get("result").is_some())
            })
            .await,
            "the daemon did not resume serving after its in-flight peers disconnected"
        );

        harness.stop_bounded().await;
    });
}

/// The size bound and the time bound both exist, and neither has drifted away.
///
/// The time bound is new; the size bound (`MAX_REQUEST_BYTES`) is pre-existing. They bound
/// different things — *how much* a peer may send and *how long* it may take — and a
/// framework with only one of them still lets a peer occupy a connection indefinitely.
#[test]
fn the_serve_limits_are_bounded() {
    let d = ServeLimits::default();
    assert!(
        d.frame_read > Duration::ZERO && d.frame_read <= Duration::from_secs(60),
        "the frame-read deadline must be finite and short enough to bound a peer: {:?}",
        d.frame_read
    );
    assert!(
        d.request > d.frame_read,
        "the whole-request deadline must exceed the frame-read deadline, or a legitimate \
         slow request would be cut before it finished sending: {:?} vs {:?}",
        d.request,
        d.frame_read
    );
    // The request deadline must exceed the longest bounded thing a request contains: a
    // provider call (60 s) or a Tier-1 dispatch (10 s). Cutting either would be a
    // correctness bug wearing a latency feature's clothes.
    assert!(
        d.request >= Duration::from_secs(60),
        "the request deadline must not be tighter than the provider call it has to contain: {:?}",
        d.request
    );
    assert!(
        d.request <= Duration::from_secs(300),
        "the request deadline must itself be bounded: {:?}",
        d.request
    );
    assert!(
        d.max_connections > 0 && d.max_connections <= 4096,
        "the connection ceiling must be finite and non-zero: {}",
        d.max_connections
    );
    assert!(
        d.shutdown_drain > Duration::ZERO && d.shutdown_drain <= d.frame_read,
        "the shutdown drain budget must be finite and must not exceed the frame deadline, \
         since a peer-held connection is expected to be cut rather than waited for: {:?} vs {:?}",
        d.shutdown_drain,
        d.frame_read
    );
}

// --------------------------------------------------------------------------
// 2. Autonomous schedule execution
// --------------------------------------------------------------------------

/// A due occurrence is persisted without any request arriving.
///
/// The scheduler existed and had twelve conformance properties before this; what it did
/// not have was a caller. `TaskService::tick` had no production call site, so a schedule
/// never fired no matter how long the daemon ran. This asserts the timer does its job:
/// a schedule is created through the real RPC, then the test sends **nothing** at all and
/// waits for the task to exist.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "real Unix socket required; see file header"
)]
fn a_due_schedule_occurrence_is_created_without_any_request_arriving() {
    rt().block_on(async {
        let harness = Harness::start("scheduler-autonomous", ServeLimits::default()).await;

        // A schedule that fires every second, so the test does not have to wait a minute
        // to observe the property it is testing.
        let created = call(
            &harness.endpoint,
            &serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "schedule/create",
                "params": { "id": "every-second", "cron": "* * * * * *" },
            }))
            .expect("frame"),
            PROBE_BUDGET,
        )
        .expect("schedule/create is answered");
        assert_eq!(
            created
                .0
                .get("result")
                .and_then(|r| r.get("schedule"))
                .and_then(Value::as_str),
            Some("every-second"),
            "schedule/create must confirm the schedule it stored: {}",
            created.0
        );

        // No further request. The daemon's own timer has to do this.
        let appeared = eventually(Duration::from_secs(20), || {
            let Some((reply, _)) = task_list(&harness.endpoint) else {
                return false;
            };
            reply
                .get("result")
                .and_then(|r| r.get("tasks"))
                .and_then(Value::as_array)
                .is_some_and(|tasks| {
                    tasks.iter().any(|t| {
                        t.get("id")
                            .and_then(Value::as_str)
                            .is_some_and(|id| id.starts_with("sched-every-second-"))
                    })
                })
        })
        .await;
        assert!(
            appeared,
            "no task derived from the schedule appeared within 20s and without any request \
             arriving; the scheduler timer is not running"
        );

        harness.stop_bounded().await;
    });
}

/// Changing the next wakeup after the timer has been armed takes effect promptly.
///
/// The regression this pins: a timer computed once at startup would be a distant deadline
/// that a newly created, sooner schedule could not shorten, so the new schedule would wait
/// for the old one to expire. Here a *minute*-later schedule is created first (arming a
/// distant deadline), then a *second*-later one, and the second must fire long before the
/// first could have.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "real Unix socket required; see file header"
)]
fn a_schedule_created_after_the_timer_was_armed_shortens_it() {
    rt().block_on(async {
        let harness = Harness::start("scheduler-refresh", ServeLimits::default()).await;

        // Arm a distant deadline: hourly.
        call(
            &harness.endpoint,
            &serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "schedule/create",
                "params": { "id": "hourly", "cron": "0 * * * * *" },
            }))
            .expect("frame"),
            PROBE_BUDGET,
        )
        .expect("hourly schedule accepted");

        // Let the loop arm its timer on the hourly deadline.
        assert!(
            eventually(PROBE_BUDGET, || {
                status_probe(&harness.endpoint, Duration::from_millis(300)).is_some()
            })
            .await,
            "the daemon did not answer after a schedule was created"
        );

        // Now create a per-second schedule. If the armed deadline were not refreshed, this
        // task would not appear for up to an hour.
        let started = Instant::now();
        call(
            &harness.endpoint,
            &serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "id": 2, "method": "schedule/create",
                "params": { "id": "soon", "cron": "* * * * * *" },
            }))
            .expect("frame"),
            PROBE_BUDGET,
        )
        .expect("soon schedule accepted");

        let appeared = eventually(Duration::from_secs(20), || {
            let Some((reply, _)) = task_list(&harness.endpoint) else {
                return false;
            };
            reply
                .get("result")
                .and_then(|r| r.get("tasks"))
                .and_then(Value::as_array)
                .is_some_and(|tasks| {
                    tasks.iter().any(|t| {
                        t.get("id")
                            .and_then(Value::as_str)
                            .is_some_and(|id| id.starts_with("sched-soon-"))
                    })
                })
        })
        .await;
        assert!(
            appeared,
            "the sooner schedule never fired, in {}s, while an hourly schedule held the timer; \
             the armed deadline is not being refreshed when a schedule is created",
            started.elapsed().as_secs()
        );

        harness.stop_bounded().await;
    });
}

/// Shutdown returns within its budget even with a peer holding a connection open.
///
/// Without this, "drain in-flight connections" and "a peer can delay shutdown forever"
/// are the same policy, and the second is the defect this package exists to remove.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "real Unix socket required; see file header"
)]
fn shutdown_cuts_a_peer_held_connection_rather_than_waiting_for_it() {
    rt().block_on(async {
        let limits = ServeLimits {
            frame_read: Duration::from_secs(30),
            request: Duration::from_secs(60),
            max_connections: 8,
            shutdown_drain: Duration::from_millis(500),
        };
        let harness = Harness::start("shutdown-drain", limits).await;
        let stall = start_stalled_frame(&harness.endpoint);

        // The drain budget is 500 ms while the frame deadline is 30 s: only a cut can make
        // this return inside `DRAIN_BUDGET`.
        let elapsed = harness.stop_bounded().await;
        assert!(
            elapsed < DRAIN_BUDGET,
            "shutdown took {elapsed:?}, which is longer than the drain budget; in-flight \
             connections were waited for rather than cut"
        );
        drop(stall);
    });
}

/// `task/list` over a real socket, with a short budget: used by the scheduler tests to
/// observe persisted state without asserting anything about the daemon's internals.
fn task_list(endpoint: &Path) -> Option<(Value, Duration)> {
    call(
        endpoint,
        &serde_json::to_vec(
            &json!({"jsonrpc": "2.0", "id": 9, "method": Method::TaskList.as_str()}),
        )
        .expect("frame"),
        Duration::from_millis(500),
    )
}
// --------------------------------------------------------------------------
// 3. Slow-provider isolation
// --------------------------------------------------------------------------

/// A provider that blocks until the test releases it, and records that it was entered.
///
/// # Why a latch rather than a sleep
///
/// The test needs to assert something about a state where the provider is *definitely*
/// mid-call. A sleep races that: on a loaded machine the call may not have started, and the
/// test would pass for the wrong reason. The latch makes "the provider is now inside the
/// call" an observable fact the test waits for, so a failure means the property is absent
/// rather than that a machine was busy.
struct BlockedProvider {
    entered: std::sync::mpsc::Sender<()>,
    release: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
}

impl BlockedProvider {
    fn new() -> (
        Arc<Self>,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let p = Arc::new(Self {
            entered: entered_tx,
            release: Arc::new(std::sync::Mutex::new(release_rx)),
        });
        (p, entered_rx, release_tx)
    }
}

impl orxnud_daemon::proposer::ProposalProvider for BlockedProvider {
    fn model_id(&self) -> &str {
        "test/blocked"
    }

    fn complete(
        &self,
        _ctx: &orxnud_daemon::proposer::ProposalContext,
    ) -> Result<String, orxnud_daemon::proposer::ProviderError> {
        // Announce first, then block. The order matters: a provider that blocked before
        // announcing would leave the test unable to tell "not started" from "started and
        // stuck".
        let _ = self.entered.send(());
        if let Ok(release) = self.release.lock() {
            // A closed channel is how the harness tears the provider down at the end of a
            // failing run, so it must not hang here.
            let _ = release.recv();
        }
        // A syntactically valid answer, so a released provider still produces an
        // ordinary outcome rather than a refusal this test would have to interpret.
        Ok("{\"done\": true, \"summary\": \"released\"}".to_owned())
    }
}

/// A blocked provider must not stop unrelated requests from being served.
///
/// This is the test concurrency-at-the-transport cannot pass on its own, and the reason
/// the provider call was split out of the governed lock rather than merely spawned.
///
/// Before the split, `ai_propose` held `governed.lock().await` across the provider's
/// round trip. So a model that took any length of time blocked *every* other request,
/// including `daemon/status` — and spawning the connection would have changed nothing,
/// because the task would still queue on the mutex.
///
/// The assertion is deliberately about a **different, safe** operation: if the daemon can
/// still answer `daemon/status` while a model is mid-call, the lock is demonstrably not
/// held across the network wait.
#[test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "real Unix socket required; see file header"
)]
fn a_blocked_provider_does_not_stop_unrelated_requests() {
    rt().block_on(async {
        let (provider, entered, release) = BlockedProvider::new();
        let root = dir("slow-provider");
        let runtime = Runtime::start_with(Paths::under(&root), NoSecrets, provider)
            .await
            .expect("start")
            .with_limits(ServeLimits::default());
        let endpoint = runtime.endpoint().to_path_buf();
        let (stop, rx) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(runtime.serve(async move {
            let _ = rx.await;
        }));

        // A task to ask about, claimed so a proposal is legal.
        let task_id = "slow-1";
        assert!(
            call(
                &endpoint,
                &frame("task/create", json!({"id": task_id, "content": "hello"})),
                PROBE_BUDGET
            )
            .expect("task/create")
            .0
            .get("result")
            .is_some()
        );
        assert!(
            call(
                &endpoint,
                &frame("task/claim", json!({"id": task_id, "worker": "w"})),
                PROBE_BUDGET
            )
            .expect("task/claim")
            .0
            .get("result")
            .is_some()
        );

        // Start the model call. It runs on its own connection task and blocks in the
        // provider.
        let asking_endpoint = endpoint.clone();
        let asking = tokio::spawn(async move {
            call(
                &asking_endpoint,
                &frame("task/ai-propose", json!({"task": task_id, "worker": "w"})),
                Duration::from_secs(60),
            )
        });

        // Wait for the provider to be *definitely* inside the call, not merely scheduled.
        let entered = tokio::task::spawn_blocking(move || entered.recv());
        let ok = tokio::time::timeout(PROBE_BUDGET, entered)
            .await
            .expect("the provider was never entered within the probe budget")
            .expect("waiter task")
            .is_ok();
        assert!(ok, "the provider was never entered");

        // The daemon is now, by construction, inside a provider network wait.
        //
        // **Two probes, because they test two different things and only one of them can
        // detect this defect.** `task/list` reads durable state, so it needs the governed
        // lock: if that lock is held across the network wait, this probe times out. A
        // `daemon/status` probe would *not* catch it, because `daemon/status` answers from a
        // snapshot taken at composition and takes no lock at all -- so it would pass
        // whether or not the fix is present. Probing only with the lock-free method would
        // have made this test green against the exact defect it exists to catch.
        let (reply, elapsed) = call(
            &endpoint,
            &frame("task/list", serde_json::Value::Null),
            PROBE_BUDGET,
        )
        .unwrap_or_else(|| {
            panic!(
                "task/list received no answer within {PROBE_BUDGET:?} while a provider was \
                 blocked mid-call; the governed lock is being held across the network wait, \
                 so transport concurrency alone did not fix this"
            )
        });
        assert!(
            reply.get("result").is_some(),
            "the probe must be answered by the daemon, not refused: {reply}"
        );
        assert!(
            elapsed < PROBE_BUDGET,
            "the probe took {elapsed:?} while a provider was blocked, which is not a useful bound"
        );

        // And the lock-free health probe answers too -- which is the property that makes
        // `orxnud doctor` usable while the daemon is busy, and is worth asserting
        // separately because it is a different mechanism.
        let (status, status_elapsed) = status_probe(&endpoint, PROBE_BUDGET).unwrap_or_else(|| {
            panic!(
                "daemon/status received no answer within {PROBE_BUDGET:?} while a provider \
                 was blocked mid-call; the health probe must not depend on the governed lock"
            )
        });
        assert!(
            status
                .get("result")
                .and_then(|r| r.get("status"))
                .is_some_and(|s| s == "running"),
            "the health probe must be answered by the daemon: {status}"
        );
        assert!(
            status_elapsed < PROBE_BUDGET,
            "the health probe took {status_elapsed:?}, which is not a useful bound"
        );

        // Let the model answer and the request finish, then confirm the daemon is still
        // healthy — a blocked-then-released provider must not have left anything wedged.
        drop(release);
        let asked = tokio::time::timeout(Duration::from_secs(20), asking)
            .await
            .expect("the ai-propose request did not finish after the provider was released")
            .expect("ask task");
        assert!(
            asked.is_some(),
            "the released provider's request produced no answer at all"
        );

        assert!(
            status_probe(&endpoint, PROBE_BUDGET).is_some(),
            "the daemon did not answer after a blocked provider was released"
        );

        let _ = stop.send(());
        let _ = tokio::time::timeout(DRAIN_BUDGET, serving).await;
        let _ = std::fs::remove_dir_all(&root);
    });
}

/// A frame for one method, as the protocol crate would build it.
fn frame(method: &str, params: serde_json::Value) -> Vec<u8> {
    let mut v =
        serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": method})).expect("frame");
    if !params.is_null() {
        // Inlined rather than built with `json!` on the whole object so `params` can be a
        // runtime value, and appended as its own member to keep the line one line.
        v.pop();
        v.extend_from_slice(b", \"params\": ");
        v.extend_from_slice(&serde_json::to_vec(&params).expect("params"));
        v.push(b'}');
    }
    v
}
