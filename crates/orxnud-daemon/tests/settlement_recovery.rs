//! Production reports an unsettled authorisation at startup.
//!
//! # Why this is a binary-level test
//!
//! Because the finding was that the check did not exist in production at all.
//! `unresolved_authorisations` was reachable only from `#[cfg(test)]`, so the assembled
//! daemon started, served, and said nothing about a journal carrying an authorisation
//! that no terminal record named. A unit test of the detector function proves the
//! function is correct; it cannot prove anything is *calling* it.
//!
//! So this drives the real `orxnud` process: it starts one, lets it write a clean
//! journal, stops it, plants an orphan the way a process killed between its two audit
//! writes would, restarts, and reads the startup banner.
//!
//! # How the orphan is planted, and why through the real chain
//!
//! It cannot be produced by dispatching: every exit now settles its authorisation by
//! construction, so the states this detection exists for are unreachable from production
//! code *on purpose*. They are what an older build's journal, or a killed process, looks
//! like. The record is appended through `AuditChain::record` and a real SQLite journal so
//! it is correctly hash-chained — a hand-written row would fail `restore` on the hash
//! check and the daemon would refuse to start for an unrelated reason, which would make
//! this test pass without ever reaching the settlement report.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};

/// A spawned daemon, killed on drop so a failing assertion cannot leave one running.
struct Daemon {
    child: Child,
    endpoint: PathBuf,
    /// Where stderr is being written.
    ///
    /// A file rather than a pipe. The banner is read while the daemon is still running,
    /// and a pipe would need a non-blocking read plus a shared handle to work at all; a
    /// file can simply be re-read, and cannot fill.
    stderr_path: PathBuf,
}

impl Daemon {
    /// Starts the daemon and waits until it is serving.
    fn start(root: &Path) -> Self {
        let endpoint = root.join("orxnud.sock");
        // Unique per start: several tests start more than one daemon on one root, and a
        // shared name would have the second overwrite the first's banner.
        let stderr_path = root.join(format!(
            "daemon-stderr-{}-{}.log",
            std::process::id(),
            next_start()
        ));
        let file = std::fs::File::create(&stderr_path).expect("create stderr log");
        let child = Command::new(env!("CARGO_BIN_EXE_orxnud"))
            .arg("--state-root")
            .arg(root)
            .stdout(Stdio::null())
            // Not null: the startup banner is what is under test.
            .stderr(Stdio::from(file))
            .spawn()
            .expect("spawn orxnud");
        let me = Self {
            child,
            endpoint,
            stderr_path,
        };
        me.await_ready();
        me
    }

    fn await_ready(&self) {
        for _ in 0..1200 {
            if send(&self.endpoint, "daemon/version").is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "the daemon never became ready at {}",
            self.endpoint.display()
        );
    }

    /// Everything the daemon has written to stderr so far.
    fn stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One request, tolerating a refused connection the way a readiness loop must.
fn send(endpoint: &Path, method: &str) -> Option<Value> {
    use std::io::{Read as _, Write as _};
    let mut stream = std::os::unix::net::UnixStream::connect(endpoint).ok()?;
    let frame = format!(
        "{}\n",
        json!({"jsonrpc": "2.0", "id": "1", "method": method})
    );
    stream.write_all(frame.as_bytes()).ok()?;
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).ok()?;
    serde_json::from_slice(&buf[..n]).ok()
}

/// A monotonic counter, so each spawned daemon logs to its own file.
fn next_start() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::SeqCst)
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "orxnud-settle-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// Appends an authorisation with nothing closing it, through the real chain.
fn plant_orphan(db: &Path) -> u64 {
    use orxnud_audit::{AuditRecord, OutcomeKind};
    use orxnud_domain::ids::{RequestId, TaskId, UserId};
    use orxnud_domain::{Actor, AuthChannel, DataClass, RiskClass};

    let journal = orxnud_store::SqliteAuditJournal::open(db).expect("open the journal");
    let mut chain = orxnud_audit::AuditChain::restore(&journal).expect("the journal must load");

    let orphan = AuditRecord::authorised(
        Actor::Human {
            user: UserId::new("local"),
            via: AuthChannel::LocalInteractive,
        },
        "filesystem/write-text",
        None,
        DataClass::Public,
        RiskClass::High,
        "v1",
        None,
        None,
        Some(TaskId::new("ipc")),
        // The constant socket label, so this is indistinguishable from a real dispatch
        // by anything that reads labels.
        Some(RequestId::new("ipc#0")),
        1_767_225_600_000,
    );
    let seq = chain
        .record(orphan, &journal)
        .expect("append must be durable");
    assert!(
        matches!(
            chain.records().last().map(|r| &r.outcome),
            Some(&orxnud_audit::AuditOutcome::Authorised { .. })
        ),
        "the planted record must be an authorisation"
    );
    assert!(
        chain.verify().is_ok(),
        "the planted record must be correctly hash-chained, or restore would refuse to \
         start for an unrelated reason"
    );
    let _ = OutcomeKind::Completed;
    seq
}

/// A clean journal reports settled, and the banner says so.
///
/// The negative case, and the one that matters for trust: a check that always fires is a
/// check nobody reads. Without this, the warning test below would pass against a daemon
/// that printed WARNING unconditionally.
#[test]
fn a_clean_journal_is_reported_settled_at_startup() {
    let root = scratch("clean");
    let db = root.join("state.db");

    // Two lifetimes, so the second restores a journal the first wrote.
    let first = Daemon::start(&root);
    assert!(
        send(&first.endpoint, "task/list").is_some(),
        "the daemon must serve"
    );
    first.stop();

    let second = Daemon::start(&root);
    let banner = second.stderr();
    second.stop();

    assert!(
        banner.contains("fully settled"),
        "a clean journal must be reported settled; banner was:\n{banner}"
    );
    assert!(
        !banner.contains("unsettled"),
        "a clean journal must not produce an unsettled warning; banner was:\n{banner}"
    );

    let _ = std::fs::remove_dir_all(&root);
    let _ = db;
}

/// A journal carrying an unsettled authorisation is reported at startup, by sequence.
///
/// This is the finding reproduced against the assembled binary. Before the repair, this
/// daemon started and printed nothing: the detector existed, was correct, and was called
/// from nothing outside tests.
#[test]
fn an_unsettled_authorisation_is_reported_at_startup_with_its_sequence() {
    let root = scratch("orphan");
    let db = root.join("state.db");

    // A first lifetime, so there is a real journal to corrupt.
    let first = Daemon::start(&root);
    assert!(send(&first.endpoint, "task/list").is_some(), "must serve");
    first.stop();

    let orphan_seq = plant_orphan(&db);

    let second = Daemon::start(&root);
    let banner = second.stderr();
    // It must still serve: an unsettled authorisation is a reportable fact about the
    // world, not a reason to refuse to start. Refusing would turn a reportable unknown
    // into an outage no restart could clear.
    assert!(
        send(&second.endpoint, "task/list").is_some(),
        "the daemon must still serve with an unsettled authorisation in its journal"
    );
    second.stop();

    assert!(
        banner.contains("unsettled authorisation"),
        "startup must report the unsettled authorisation; banner was:\n{banner}"
    );
    assert!(
        banner.contains(&orphan_seq.to_string()),
        "the report must name the sequence so an operator can read it out of \
         audit_log; expected seq {orphan_seq}, banner was:\n{banner}"
    );
    assert!(
        !banner.contains("fully settled"),
        "a journal with an orphan must not also claim to be settled; banner was:\n{banner}"
    );
    assert!(
        !banner.contains("WARNING: audit journal restored with 0 unsettled"),
        "the count must be the real one"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// After the orphan is settled, startup reports settled again.
///
/// The check has to be able to come back clean, or an operator who deals with the
/// finding has no way to confirm they dealt with it. Closing the authorisation through
/// the chain is what a repaired journal looks like.
#[test]
fn settling_the_authorisation_clears_the_startup_report() {
    let root = scratch("cleared");
    let db = root.join("state.db");

    let first = Daemon::start(&root);
    assert!(send(&first.endpoint, "task/list").is_some(), "must serve");
    first.stop();

    let orphan_seq = plant_orphan(&db);

    // Close it, exactly as `record_terminal` does in production.
    {
        use orxnud_audit::{AuditRecord, OutcomeKind};
        use orxnud_domain::ids::{RequestId, TaskId, UserId};
        use orxnud_domain::{Actor, AuthChannel, DataClass, RiskClass};
        let journal = orxnud_store::SqliteAuditJournal::open(&db).expect("open");
        let mut chain = orxnud_audit::AuditChain::restore(&journal).expect("load");
        let closing = AuditRecord::authorised(
            Actor::Human {
                user: UserId::new("local"),
                via: AuthChannel::LocalInteractive,
            },
            "filesystem/write-text",
            None,
            DataClass::Public,
            RiskClass::High,
            "v1",
            None,
            None,
            Some(TaskId::new("ipc")),
            Some(RequestId::new("ipc#0")),
            1_767_225_600_100,
        )
        .finished(
            OutcomeKind::Uncertain,
            1_767_225_600_100,
            Some("settled by a test".into()),
        )
        .settling(orphan_seq);
        chain.record(closing, &journal).expect("append");
        assert!(chain.verify().is_ok(), "the chain must still verify");
        assert!(
            chain.unresolved_authorisations().is_empty(),
            "closing the orphan must settle it"
        );
    }

    let second = Daemon::start(&root);
    let banner = second.stderr();
    second.stop();

    assert!(
        banner.contains("fully settled"),
        "once settled, startup must report settled again; banner was:\n{banner}"
    );

    let _ = std::fs::remove_dir_all(&root);
}
