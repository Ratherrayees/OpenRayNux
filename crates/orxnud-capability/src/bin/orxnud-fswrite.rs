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
//! # Why the contents travel in argv
//!
//! `SandboxSpec` has no stdin channel, and adding one would mean changing the sandbox
//! contract, which this slice does not do. So the bytes are arguments. That makes
//! them visible to anything that can read the host process table for the duration of
//! the call, which is a real limitation of the existing contract rather than a
//! property of this program. It is acceptable for a workspace-scoped text write and
//! is recorded as such; it would not be acceptable for a credential.

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
        println!("usage: orxnud-fswrite --path <path> --contents <text>");
        return Ok(());
    }

    let path = flag(&args, "--path")?;
    let contents = flag(&args, "--contents")?;

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

    let mut file = std::fs::File::create(&normalised)
        .map_err(|e| format!("could not create {}: {e}", normalised.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|e| format!("could not write {}: {e}", normalised.display()))?;
    file.flush()
        .map_err(|e| format!("could not flush {}: {e}", normalised.display()))?;
    // No "created N bytes" on stdout: the verifier re-reads the file rather than
    // believing a number the writer produced.
    Ok(())
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
