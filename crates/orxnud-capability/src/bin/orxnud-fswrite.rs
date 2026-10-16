//! The Tier-1 child for `filesystem/write-text`.
//!
//! # Why a separate program rather than a shell
//!
//! The sandbox gives a capability exactly one thing: a program, an argument vector,
//! an environment, and a set of filesystem grants. It does not give it a shell, and
//! this binary deliberately does not accept one. `orxnud-fswrite --path X --contents Y`
//! writes those bytes to that path and exits. There is no command to interpret, no
//! redirection to expand, and no way to express "also delete that" — the argv space is
//! the whole vocabulary.
//!
//! That matters because a shell would turn a narrowly-scoped capability into an
//! arbitrary one. `contents` is written with `fs::write`, never passed to a shell, so a
//! value containing `;`, `$(...)`, backticks or newlines is inert data rather than
//! syntax.
//!
//! # What this binary does NOT defend against
//!
//! It does not decide *where* it may write. It is the sandbox that enforces that,
//! by not binding anything outside the granted workspace: an escaping path resolves
//! to a location that does not exist inside the tmpfs root, so the write fails
//! because the filesystem refuses it rather than because this program checked a
//! string. That is the difference between a boundary and a validation, and it is why
//! the escape test asserts on the *effect* — the file does not appear outside —
//! rather than on this program's exit code.
//!
//! # Why the contents travel on stdin, not in argv
//!
//! `SandboxSpec` gained a stdin channel (ADR-0054). The contents used to be passed as
//! `--contents <text>` in `argv`, and `argv` is the host process table: `bwrap` is
//! executed with it, stays in the host PID namespace, and `/proc/<pid>/cmdline` is mode
//! `0444`, so any local uid could read the user's file for the life of the execution
//! (V-67). On the cgroup branch the joiner shell carried the same vector before it
//! `exec`ed `bwrap`, so there were two surfaces and fixing one would have fixed neither.
//!
//! The transport is framed, and that is not decoration: on a bare stdin "the caller sent
//! an empty file" and "the caller sent nothing" are the same zero bytes. The frame's
//! declared length makes them decidable, and every deviation from it is a refusal --
//! see `crate::stdin_frame`.
//!
//! # The version handshake
//!
//! `--stdin-transport=1` is **required**. This program refuses without it, and so does
//! an older helper that finds no `--contents` (ADR-0054, Decision 6). Both directions
//! fail closed by name rather than one silently misreading the other.

use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

fn main() {
    match run() {
        Ok(()) => {}
        Err(why) => {
            // stderr, not stdout: stdout is the capability's result channel and the
            // dispatcher parses it, so a diagnostic there could be mistaken for a
            // successful write by anything reading the child's output.
            eprintln!("orxnud-fswrite: {why}");
            std::process::exit(1);
        }
    }
}

/// Runs the write.
///
/// Errors rather than exiting on its own so the exit code has exactly one source.
fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "usage: orxnud-fswrite --path <path> {}\n\n\
             The file body is read from stdin as a framed payload; see \
             `orxnud_capability::stdin_frame`.",
            orxnud_capability::stdin_frame::VERSION_ARG
        );
        return Ok(());
    }

    // ADR-0054 Decision 6. Checked first and by exact match, so an incompatible pair
    // fails here rather than at some later point where the failure would look like a
    // corrupt payload.
    let transport =
        flag(&args, "--stdin-transport").or_else(|_| single(&args, "--stdin-transport"))?;
    if transport != "1" {
        return Err(format!(
            "unsupported stdin transport {transport:?}; this helper speaks \
             transport 1 ({}), and refuses rather than guessing",
            orxnud_capability::stdin_frame::VERSION_ARG
        ));
    }

    let path = flag(&args, "--path")?;

    // The frame decides what the body is. A declared zero is a valid empty write; a
    // short stream, a malformed header or trailing bytes are refusals, and none of them
    // may produce a file -- an empty file written from an empty stream is exactly the
    // "silently wrote something other than what was asked for" this refuses.
    let mut stdin = std::io::stdin().lock();
    let contents = orxnud_capability::stdin_frame::read_frame(&mut stdin)
        .map_err(|e| format!("refusing the stdin frame: {e}"))?;

    // Absolute only. A relative path would resolve against `working_dir`, which the
    // sandbox sets inside its own tree — correct, but it makes the write depend on a
    // directory this program cannot see, so it is refused instead.
    let target = Path::new(&path);
    if !target.is_absolute() {
        return Err(format!("--path must be absolute, got {path:?}"));
    }
    // Lexical normalisation, so `a/../b` is understood here rather than by the kernel.
    // This is *not* the security boundary -- the sandbox is -- but rejecting a path
    // that tries to climb keeps the failure legible instead of incidental.
    let mut normalised = PathBuf::new();
    for component in target.components() {
        match component {
            Component::ParentDir => {
                if !normalised.pop() {
                    return Err(format!("--path escapes its root: {path:?}"));
                }
            }
            Component::CurDir => {}
            other => normalised.push(other.as_os_str()),
        }
    }

    // Everything above this line can refuse with nothing written. The write itself is
    // last, so there is no path that creates a file and then decides it had the wrong
    // input.
    let mut file = std::fs::File::create(&normalised)
        .map_err(|e| format!("could not create {}: {e}", normalised.display()))?;
    file.write_all(&contents)
        .map_err(|e| format!("could not write {}: {e}", normalised.display()))?;
    file.flush()
        .map_err(|e| format!("could not flush {}: {e}", normalised.display()))?;
    // No "created N bytes" on stdout: the verifier re-reads the file rather than
    // believing a number the writer produced.
    Ok(())
}

/// Reads `--flag=value` for a flag written in that form.
///
/// `flag` handles the two-argument form; the transport version is conventionally
/// single-token so it is unmistakably metadata rather than a value that could be
/// confused with user content.
fn single(args: &[String], name: &str) -> Result<String, String> {
    let prefix = format!("{name}=");
    args.iter()
        .find_map(|a| a.strip_prefix(&prefix))
        .map(str::to_owned)
        .ok_or_else(|| format!("{name} is required"))
}

/// Reads `--flag value`.
///
/// A missing flag and a missing value are different mistakes and are reported as
/// such, so a truncated invocation cannot silently write an empty file.
fn flag(args: &[String], name: &str) -> Result<String, String> {
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == name {
            return it
                .next()
                .cloned()
                .ok_or_else(|| format!("{name} was given without a value"));
        }
        if let Some(rest) = arg.strip_prefix(&format!("{name}=")) {
            return Ok(rest.to_owned());
        }
    }
    Err(format!("{name} is required"))
}
