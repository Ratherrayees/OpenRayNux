//! What this host's `/proc` permits, measured.
//!
//! # Why this lives here
//!
//! Reading a file's mode needs `std::os::unix::fs::PermissionsExt`, and gate G3 refuses a
//! platform-only module path in portable core — correctly, because it is exactly the kind
//! of Linux assumption that must not reach code claiming to be portable. This crate is
//! `orxnud-platform-sandbox`, which already owns `/proc` handling, so the measurement
//! belongs to it.
//!
//! # Why measure rather than assert
//!
//! The modes are stable Linux facts, but the *cross-uid* consequence of them is a property
//! of the mount's `hidepid` option and of ptrace hardening, which vary by host. V-67
//! records what was observed; a test that demanded a particular `hidepid` would fail on a
//! correctly-configured host for having been configured correctly. So the values are
//! asserted where they are invariant (the modes) and reported where they are not (the
//! mount options).

use std::os::unix::fs::PermissionsExt;

/// The mode of `/proc/<pid>/<file>`, in octal.
fn mode(path: &str) -> String {
    std::fs::metadata(path)
        .map(|m| format!("{:o}", m.permissions().mode() & 0o777))
        .unwrap_or_else(|e| format!("unreadable: {e}"))
}

/// The `/proc` mount options this evidence was gathered under.
fn proc_mount_options() -> String {
    std::fs::read_to_string("/proc/mounts")
        .ok()
        .and_then(|m| {
            m.lines()
                .find(|l| l.split_whitespace().nth(1) == Some("/proc"))
                .and_then(|l| l.split_whitespace().nth(3))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unreadable".to_owned())
}

/// `cmdline` is world-readable and `environ` is owner-only.
///
/// This is the asymmetry the whole S-17 design rests on: it is why a payload in `argv`
/// leaks to any local uid, and why a credential in the real `environ` would not. The
/// *credential* half is still argv-exposed because `spec.env` renders as `--setenv`, which
/// is a command line — that remains open (ADR-0054, Decision 5).
#[test]
fn the_proc_file_modes_are_as_the_design_assumes() {
    assert_eq!(
        mode("/proc/self/cmdline"),
        "444",
        "cmdline must be world-readable; if this host differs, the exposure this design \
         removes was already weaker here, and the evidence must be reported with that noted"
    );
    assert_eq!(
        mode("/proc/self/environ"),
        "400",
        "environ must be owner-only; a different mode would change what the credential \
         channel can establish on this host"
    );
}

/// Reported, not enforced: whether cross-uid reads are possible depends on this mount.
#[test]
fn the_proc_mount_configuration_is_reported() {
    let opts = proc_mount_options();
    eprintln!("host /proc mount options: {opts:?}");
    assert!(
        !opts.starts_with("unreadable"),
        "/proc/mounts must be readable for this evidence to be interpretable; got {opts:?}"
    );
}
