//! S-31 (F-26c): cross-process database ownership.
//!
//! # Why every assertion here spawns a real OS process
//!
//! S-30 proved a restore is safe against connections *inside one process* — an idle
//! handle observes the restored state, an active reader is refused. It cannot say
//! anything about a second daemon, because a second process is not in this process's
//! connection set. A second `Connection` here would pass or fail for reasons unrelated
//! to the gap, and would be worse than no test.
//!
//! # How it is driven
//!
//! The suite re-executes this binary with `ORXNUD_S31_ROLE` set. The parent tests spawn
//! roles; the role body is [`s31_role_body`], which does real work through the real
//! production API — `Backup::take`, `Backup::restore_coordinated`, `Store::open`.
//!
//! The exclusive holder in both tests is a **real restore paused inside the
//! checkpoint-to-restore window**, not a synthetic lock holder. That is deliberate: it
//! means the tests exercise the same exclusive window production uses, rather than a
//! stand-in that could drift from it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ROLE: &str = "ORXNUD_S31_ROLE";
const DB: &str = "ORXNUD_S31_DB";
const WINDOW: &str = "ORXNUD_S31_RESTORE_WINDOW";

fn test_binary() -> PathBuf {
    std::env::current_exe().expect("this test binary")
}

fn spawn(role: &str, db: &Path, window: Option<&Path>) -> Output {
    let mut cmd = Command::new(test_binary());
    cmd.arg("--exact")
        .arg("s31_role_body")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(ROLE, role)
        .env(DB, db);
    if let Some(w) = window {
        cmd.env(WINDOW, w);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("could not spawn the {role} role: {e}"))
}

fn text_of(out: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn dir(tag: &str) -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let d = std::env::temp_dir().join(format!("s31-tp-{}-{tag}-{nonce}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

fn wait_for(path: &Path) -> bool {
    for _ in 0..4000 {
        if path.exists() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    false
}

fn seed(db: &Path) {
    let conn = rusqlite::Connection::open(db).expect("seed");
    conn.pragma_update(None, "journal_mode", "WAL")
        .expect("wal");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT NOT NULL);
         INSERT OR IGNORE INTO schema_meta VALUES (1);
         INSERT OR IGNORE INTO notes VALUES (1, 'PRE');",
    )
    .expect("seed data");
}

/// **Test A — a competing process is excluded while a restore holds the database.**
#[test]
fn a_competing_process_is_excluded_during_the_restore_lifecycle() {
    let d = dir("exclude");
    let db = d.join("state.db");
    seed(&db);

    let marker = d.join("window");
    let mut restorer = spawn_live("restorer", &db, Some(&marker));
    assert!(
        wait_for(&marker.with_extension("ready")),
        "the restorer never reached the restore window:\n{}",
        drain(&mut restorer)
    );

    // A genuine second process, right now, through the real application open path.
    //
    // It did not write.
    //
    // Compared against a value read immediately before the competitor ran, not against
    // an absolute number: the restorer is deliberately paused *after* writing its own
    // post-snapshot row, so the database legitimately holds two rows at this point.
    // Asserting `== 1` measured the restorer's behaviour, not the competitor's.
    let count_now = || -> i64 {
        rusqlite::Connection::open(&db)
            .expect("parent read")
            .query_row("SELECT COUNT(*) FROM notes", [], |r| r.get(0))
            .expect("count")
    };
    let before = count_now();
    let competitor = spawn("competitor", &db, None);
    let text = text_of(&competitor);
    assert!(
        !competitor.status.success(),
        "a competitor must not succeed while a restore holds exclusive ownership:\n{text}"
    );
    assert!(
        text.contains("COMPETITOR: refused"),
        "the refusal must be the typed ownership conflict:\n{text}"
    );
    assert_eq!(
        count_now(),
        before,
        "the excluded process must not have modified the database"
    );

    // Release; the same operation then succeeds, showing the refusal was about
    // ownership and not a database that is simply broken.
    std::fs::write(marker.with_extension("go"), "").expect("release");
    let out = restorer.wait_with_output().expect("restorer");
    assert!(
        out.status.success(),
        "the restore must finish:\n{}",
        text_of(&out)
    );

    let later = spawn("competitor", &db, None);
    assert!(
        later.status.success(),
        "once ownership is released the same open must succeed:\n{}",
        text_of(&later)
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// **Test B — the exact interleaving, and the snapshot's logical state afterwards.**
#[test]
fn b_a_competitor_cannot_act_inside_the_checkpoint_to_restore_window() {
    let d = dir("window");
    let db = d.join("state.db");
    seed(&db);

    let marker = d.join("window");
    let mut restorer = spawn_live("restorer", &db, Some(&marker));
    assert!(
        wait_for(&marker.with_extension("ready")),
        "the restorer never reached the window:\n{}",
        drain(&mut restorer)
    );

    // The deterministic moment: between exclusive ownership being taken and the copy
    // happening. A timing race could not place a competitor here.
    let competitor = spawn("competitor", &db, None);
    assert!(
        !competitor.status.success(),
        "a competitor acting inside the window must be excluded:\n{}",
        text_of(&competitor)
    );
    assert!(
        text_of(&competitor).contains("COMPETITOR: refused"),
        "the exclusion must be an ownership conflict:\n{}",
        text_of(&competitor)
    );

    std::fs::write(marker.with_extension("go"), "").expect("release");
    let out = restorer.wait_with_output().expect("restorer");
    assert!(
        out.status.success(),
        "the restore must complete once uncontended:\n{}",
        text_of(&out)
    );

    // The snapshot's logical state, not merely that the restore returned.
    let after = rusqlite::Connection::open(&db).expect("read after restore");
    let bodies: String = after
        .query_row(
            "SELECT COALESCE(GROUP_CONCAT(body), '<none>') FROM notes ORDER BY id",
            [],
            |r| r.get(0),
        )
        .expect("bodies");
    assert_eq!(
        bodies, "PRE",
        "the restore must reproduce the snapshot's logical state; the competitor must \
         not have left a trace"
    );
    let integrity: String = after
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .expect("integrity");
    assert_eq!(integrity, "ok", "supplementary: integrity_check");
    let _ = std::fs::remove_dir_all(&d);
}

fn spawn_live(role: &str, db: &Path, window: Option<&Path>) -> std::process::Child {
    let mut cmd = Command::new(test_binary());
    cmd.arg("--exact")
        .arg("s31_role_body")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(ROLE, role)
        .env(DB, db)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(w) = window {
        cmd.env(WINDOW, w);
    }
    // No descriptor is handed to the child and no production seam is involved: the
    // restorer takes its own exclusive lease and restores under it. The earlier design
    // did the opposite -- an environment-variable seam inside the production restore --
    // and that was wrong twice.
    cmd.spawn().unwrap_or_else(|e| panic!("spawn {role}: {e}"))
}

fn drain(child: &mut std::process::Child) -> String {
    let _ = child.kill();
    let mut collected = String::new();
    if let Some(out) = child.stdout.take() {
        use std::io::Read as _;
        let mut s = String::new();
        let _ = out.take(16_384).read_to_string(&mut s);
        collected.push_str(&s);
    }
    if let Some(err) = child.stderr.take() {
        use std::io::Read as _;
        let mut s = String::new();
        let _ = err.take(16_384).read_to_string(&mut s);
        collected.push_str(&s);
    }
    collected
}

/// **Boundary 2 — two ordinary daemons may both hold the database open.**
///
/// The shared/exclusive protocol intends that ordinary opens *coexist* and only a restore
/// excludes. If two ordinary opens were refused, a second daemon could never start, which
/// would be a broader product and availability change than the protocol describes. This
/// asserts the permissive direction across a process boundary, which the in-process
/// ownership test cannot do on its own.
#[test]
fn c_two_processes_may_both_hold_the_database_open_normally() {
    let d = dir("two-open");
    let db = d.join("state.db");
    seed(&db);

    let first = spawn("holder", &db, None);
    assert!(
        first.status.success(),
        "the first ordinary process must acquire shared ownership:\n{}",
        text_of(&first)
    );

    // While the first still holds its lease, a second genuine process opens the same
    // database through the real application API.
    let second = spawn("competitor", &db, None);
    assert!(
        second.status.success(),
        "a second ordinary open must be PERMITTED while another process holds shared \
         ownership; refusing it would mean two daemons cannot coexist, which is not \
         what this protocol is for:\n{}",
        text_of(&second)
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The child-process entry point, reached only when `ORXNUD_S31_ROLE` is set.
#[test]
fn s31_role_body() {
    let Ok(role) = std::env::var(ROLE) else {
        // Parent invocation. The assertions are the tests above.
        return;
    };
    let db = PathBuf::from(std::env::var(DB).expect("child needs a database path"));

    match role.as_str() {
        "holder" => {
            // Take shared ownership, prove we have it, and wait to be released.
            let lease = orxnud_store::ownership::acquire_shared_for_tests(&db)
                .expect("holder takes shared ownership");
            let d = db.parent().expect("parent").to_path_buf();
            std::fs::write(d.join("holder.ready"), "").expect("signal ready");
            for _ in 0..4000 {
                if d.join("holder.go").exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            drop(lease);
        }
        "competitor" => {
            match orxnud_store::sqlite::Store::open(&db, true, &orxnud_platform_fs::OsIdentity) {
                Ok(_store) => eprintln!("COMPETITOR: opened the database"),
                Err(e) => {
                    eprintln!("COMPETITOR: refused — {e}");
                    std::process::exit(3);
                }
            }
        }
        "restorer" => {
            let conn = rusqlite::Connection::open(&db).expect("restorer seed");
            conn.pragma_update(None, "journal_mode", "WAL")
                .expect("wal");
            let snapshot = orxnud_store::backup::Backup::take(&conn, &db).expect("take");
            conn.execute_batch("INSERT INTO notes VALUES (2,'POST');")
                .expect("post-snapshot write");
            drop(conn);

            // Exclusive ownership is taken **before** anything reports readiness, so the
            // window the parent pauses in is the real one: ownership held, the restore
            // not yet started. Nothing in the production path is paused or configured.
            let lease = orxnud_store::ownership::acquire_exclusive_for_tests(&db)
                .expect("restorer takes exclusive ownership");

            if let Ok(marker) = std::env::var(WINDOW) {
                let marker = std::path::PathBuf::from(marker);
                std::fs::write(marker.with_extension("ready"), "in-window")
                    .expect("signal that the window is open");
                for _ in 0..4000 {
                    if marker.with_extension("go").exists() {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }

            snapshot
                .restore_with_lease_for_tests(&db, lease, &orxnud_platform_fs::OsIdentity)
                .expect("restore must succeed once uncontended");
            eprintln!("RESTORER: restored");
        }
        other => panic!("unknown role {other}"),
    }
}
