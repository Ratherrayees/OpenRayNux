//! F-26c / ADR-0058: the composition root supplies the filesystem-identity
//! capability, and a database reachable through two names is refused at the
//! daemon's own boundary.
//!
//! # Why this suite is here and not only in the store's
//!
//! The store's own suite proves that `Store::open` refuses an aliased database
//! when it is handed a capability that answers. That is the *mechanism*. It
//! does not prove that the **composition root** hands it one — and a
//! composition root that forgot to would leave every production open
//! unguarded while the store's tests stayed green.
//!
//! So this suite drives the daemon's own entry point,
//! [`Daemon::attach_durable_security_state`], which is what a real daemon calls
//! on start-up, and asserts that a database with a second name is refused there.
//!
//! # What it does not prove
//!
//! The observations are of a **path**; SQLite opens by filename. This proves the
//! bypass is rejected, not that the connection is bound to the inode that was
//! checked (ADR-0058 Decision 2).

use std::path::PathBuf;

use orxnud_daemon::{Daemon, Paths};

/// A state root unique to this process and this call.
fn root(tag: &str) -> PathBuf {
    use std::sync::atomic::AtomicU32;
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "orxnud-daemon-alias-{}-{tag}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("state root");
    dir
}

/// **The daemon's own start-up path refuses a database with a second name.**
#[test]
fn the_daemon_refuses_a_database_reachable_through_two_names() {
    let root = root("two-names");
    let paths = Paths::under(&root);

    // The ordinary path: the daemon attaches its durable security state, which
    // creates and migrates the database.
    {
        let mut daemon = Daemon::compose(paths.clone());
        daemon
            .attach_durable_security_state(&paths.database)
            .expect("the first attach must succeed");
    }
    assert!(
        paths.database.exists(),
        "the attach must have created the database"
    );

    // A second name for the same inode.
    let alias = root.join("alias.db");
    std::fs::hard_link(&paths.database, &alias).expect("hard link the database");

    // The daemon's own boundary must refuse it.
    let mut daemon = Daemon::compose(paths.clone());
    let err = daemon
        .attach_durable_security_state(&paths.database)
        .expect_err("a database reachable through two names must be refused at startup");
    let text = err.to_string();
    assert!(
        text.contains("names") || text.contains("alias") || text.contains("ownership"),
        "the refusal must say why the database was not safe to open; got: {text}"
    );

    // And it must not be a *silent* success: the daemon did not start.
    assert_eq!(
        daemon.state(),
        orxnud_daemon::LifecycleState::Created,
        "a refused attach must leave the daemon unstarted"
    );

    // Once the second name is gone, the same daemon path works again — so the
    // refusal released the lease rather than wedging the database.
    std::fs::remove_file(&alias).expect("remove the alias");
    let mut daemon = Daemon::compose(paths.clone());
    daemon
        .attach_durable_security_state(&paths.database)
        .expect("the refusal must have released the lease");

    let _ = std::fs::remove_dir_all(&root);
}
