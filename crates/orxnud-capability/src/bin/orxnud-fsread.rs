//! The Tier-1 child for `filesystem/read-text`.
//!
//! # Why a separate program rather than a shell
//!
//! The sandbox gives a capability exactly one thing: a program, an argument vector, an
//! environment, and a set of filesystem grants. It does not give it a shell, and this
//! binary deliberately does not accept one. `orxnud-fsread --path X` reads that one file
//! and exits. There is no command to interpret, no redirection to expand, and no way to
//! express "also list the directory" -- the argv space is the whole vocabulary.
//!
//! # What this binary does NOT defend against
//!
//! It does not decide *where* it may read. It is the sandbox that enforces that, by binding
//! nothing outside the granted workspace: an escaping path resolves to a location that does
//! not exist inside the tmpfs root, so the read fails because the filesystem refuses it
//! rather than because this program checked a string. That is the difference between a
//! boundary and a validation, and it is why the escape test asserts on the *effect* -- the
//! bytes never arrive -- rather than on this program's exit code.
//!
//! The lexical checks below exist to make a refusal legible, not to be the boundary. An
//! earlier layer refuses the same paths; this one exists so that if it were somehow reached
//! with a traversing path, the failure says why instead of surfacing as a bare `ENOENT`.
//!
//! # Content on stdout, and only on stdout
//!
//! The file's bytes go to stdout because that is the only channel the sandbox contract
//! offers for a result -- there is no stdin and no side-channel. Diagnostics go to stderr,
//! so a diagnostic can never be mistaken for content by anything reading stdout.
//!
//! Nothing here prints content to stderr, and no error message includes any. An error names
//! the path and the reason, never the bytes: stderr reaches logs.
//!
//! # The size limit
//!
//! 64 KiB, refused rather than truncated. A truncated read reported as a whole file is the
//! one outcome the model cannot detect, because it has no way to know a limit was applied.

use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};

/// Must match `read_text::MAX_READ_BYTES`. The verifier applies the same ceiling, so the two
/// halves of one read agree on what "too big" means.
const MAX_READ_BYTES: u64 = 64 * 1024;

fn main() {
    match run() {
        Ok(()) => {}
        Err(why) => {
            // stderr, not stdout: stdout is the capability's result channel and the
            // dispatcher parses it, so a diagnostic there could be mistaken for file content.
            eprintln!("orxnud-fsread: {why}");
            std::process::exit(1);
        }
    }
}

/// Runs the read.
///
/// Errors rather than exiting on its own so the exit code has exactly one source.
fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("usage: orxnud-fsread --path <path>");
        return Ok(());
    }

    let path = flag(&args, "--path")?;

    // Absolute only. A relative path would resolve against `working_dir`, which the sandbox
    // sets inside its own tree -- correct, but it makes the read depend on a directory this
    // program cannot see, so it is refused instead.
    let target = Path::new(&path);
    if !target.is_absolute() {
        return Err(format!("--path must be absolute, got {path:?}"));
    }

    // Lexical normalisation, so `a/../b` is understood here rather than by the kernel.
    // Not the security boundary -- the sandbox is -- but refusing a climbing path keeps the
    // failure legible instead of incidental.
    let normalised = normalise(target)?;

    let meta = std::fs::metadata(&normalised)
        .map_err(|e| format!("could not stat {}: {e}", normalised.display()))?;

    // A directory is refused rather than read, and refused *specially*: reading one would
    // either fail with EISDIR or, on some systems, produce a listing. Neither is a file
    // read, and a capability named `read-text` must not have a mode that returns names.
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", normalised.display()));
    }

    // Refused, not truncated. Checked before reading, so an oversized file is never loaded.
    if meta.len() > MAX_READ_BYTES {
        return Err(format!(
            "{} is {} bytes, over the {MAX_READ_BYTES}-byte read limit",
            normalised.display(),
            meta.len()
        ));
    }

    // The read is **bounded**, not merely measured afterwards.
    //
    // A metadata check followed by `read_to_end` is not a size limit: a file that grows
    // between the two observations would be read in full, and the check would then be
    // reporting on a file this process no longer matches. So this asks for at most
    // `MAX_READ_BYTES + 1` bytes: one byte past the limit is enough to prove the file is
    // over it, and nothing beyond that is ever materialised in this process.
    //
    // `take` is what makes the bound real -- it stops reading rather than reading and then
    // discarding, so peak memory is the limit and not the file's size.
    let file = std::fs::File::open(&normalised)
        .map_err(|e| format!("could not open {}: {e}", normalised.display()))?;
    let mut bytes = Vec::with_capacity(meta.len() as usize + 1);
    file.take(MAX_READ_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("could not read {}: {e}", normalised.display()))?;

    if bytes.len() as u64 > MAX_READ_BYTES {
        return Err(format!(
            "{} is over the {MAX_READ_BYTES}-byte read limit",
            normalised.display()
        ));
    }

    // The content, and nothing else, on stdout. No "read N bytes" preamble: a verifier
    // comparing bytes would have to skip it, and anything else reading stdout would have to
    // know to strip it.
    let mut out = std::io::stdout().lock();
    out.write_all(&bytes)
        .map_err(|e| format!("could not write the result: {e}"))?;
    out.flush()
        .map_err(|e| format!("could not flush the result: {e}"))?;
    Ok(())
}

/// Lexically normalises an absolute path, refusing anything that climbs out of its root.
fn normalise(target: &Path) -> Result<PathBuf, String> {
    let mut normalised = PathBuf::new();
    for component in target.components() {
        match component {
            Component::ParentDir => {
                if !normalised.pop() {
                    return Err(format!("--path escapes its root: {target:?}"));
                }
            }
            Component::CurDir => {}
            other => normalised.push(other.as_os_str()),
        }
    }
    Ok(normalised)
}

/// Reads `--flag value`.
///
/// A missing flag and a missing value are different mistakes and are reported as such, so a
/// truncated invocation cannot silently read nothing and report success.
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
