//! The daemon executable: the one canonical long-lived process.
//!
//! # Lifecycle
//!
//! ```text
//! parse arguments -> start the runtime (durable state, then endpoint) -> serve
//!   -> SIGINT / SIGTERM -> stop accepting, remove the endpoint, exit 0
//! ```
//!
//! Deliberately minimal. There is no CLI product surface here: `orxnuctl` is the
//! command-line client and depends only on `orxnud-protocol`, so the two never
//! compete. This binary's whole job is to *be* the process an interface connects
//! to.
//!
//! # Exit codes
//!
//! | code | meaning |
//! |------|---------|
//! | 0 | clean shutdown, or `--version` / `--doctor` |
//! | 1 | could not start, or failed while serving |
//! | 2 | bad arguments |
//!
//! A failure to start is a refusal to serve, not a degraded start: if durable
//! security state cannot be established, nothing binds and this exits 1.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use orxnud_daemon::Paths;
use orxnud_daemon::runtime::Runtime;
use orxnud_platform_secrets::KeyringSecrets;

const USAGE: &str = "\
orxnud -- the OpenRayNux daemon

USAGE:
    orxnud [--state-root <DIR>]

OPTIONS:
    --state-root <DIR>   Where state lives. Defaults to $XDG_STATE_HOME/orxnud,
                         or ~/.local/state/orxnud.
    --version            Print the version and exit.
    --doctor             Print a diagnosis of the configured paths and exit.
    --help               Print this and exit.

The daemon serves a local endpoint only. It never opens a network socket.
";

/// Argument parsing, hand-written.
///
/// The verb set is closed and tiny, and refusing an unexpected argument is a rule
/// worth writing by hand -- the same reasoning `orxnuctl` records for not taking
/// `clap`.
fn parse_args() -> Result<Action, String> {
    let mut root: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" | "-V" => return Ok(Action::Version),
            "--help" | "-h" => return Ok(Action::Help),
            "--doctor" => return Ok(Action::Doctor),
            "--state-root" => {
                root = Some(
                    args.next()
                        .ok_or_else(|| "--state-root needs a directory".to_owned())?,
                );
            }
            other if other.starts_with("--state-root=") => {
                root = Some(other["--state-root=".len()..].to_owned());
            }
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }
    Ok(Action::Serve(root.map_or_else(default_root, |r| {
        std::path::PathBuf::from(r)
    })))
}

enum Action {
    Version,
    Help,
    Doctor,
    Serve(std::path::PathBuf),
}

/// The state root, following the XDG convention `directories` would give.
///
/// Spelled out rather than pulled in as a dependency for one call: the rule is two
/// environment lookups, and a personal install not being relocatable is a worse
/// problem than a hand-written default.
fn default_root() -> std::path::PathBuf {
    if let Some(base) = std::env::var_os("XDG_STATE_HOME")
        && !base.is_empty()
    {
        return std::path::PathBuf::from(base).join("orxnud");
    }
    let home = std::env::var_os("HOME").map_or_else(
        || std::path::PathBuf::from(".orxnud"),
        std::path::PathBuf::from,
    );
    home.join(".local").join("state").join("orxnud")
}

fn main() -> ExitCode {
    let action = match parse_args() {
        Ok(a) => a,
        Err(why) => {
            eprintln!("orxnud: {why}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let root = match &action {
        Action::Version => {
            println!("orxnud {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Action::Help => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Action::Doctor => {
            doctor(&Paths::under(default_root()));
            return ExitCode::SUCCESS;
        }
        Action::Serve(root) => root.clone(),
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("orxnud: could not start a runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    runtime.block_on(async move { serve(Paths::under(&root)).await })
}

async fn serve(paths: Paths) -> ExitCode {
    // The ordering that matters is inside `Runtime::start`: durable security state is
    // attached before the endpoint exists. If it fails here, nothing was bound.
    let runtime = match Runtime::start(paths.clone(), KeyringSecrets::default()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("orxnud: refusing to start: {e}");
            return ExitCode::FAILURE;
        }
    };

    let endpoint = runtime.endpoint().to_path_buf();
    eprintln!(
        "orxnud: serving {} on {} (durable audit: {})",
        runtime.backend(),
        endpoint.display(),
        runtime.is_durable().await
    );

    match runtime.serve(orxnud_platform_ipc::shutdown_signal()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("orxnud: transport failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn doctor(paths: &Paths) {
    println!("orxnud {}", env!("CARGO_PKG_VERSION"));
    println!("state root: {}", paths.root.display());
    for p in paths.all() {
        println!("  {}", p.display());
    }
    println!("ipc backend: {}", orxnud_platform_ipc::backend_name());
    println!(
        "ipc endpoint: {}",
        orxnud_platform_ipc::endpoint_for(&paths.root).display()
    );
    println!(
        "sandbox backend: {}",
        orxnud_platform_sandbox::host_backend_name()
    );
    println!("durable security state: attach_durable_security_state on start");
    println!("(no paths were created; --doctor only reports)");
}
