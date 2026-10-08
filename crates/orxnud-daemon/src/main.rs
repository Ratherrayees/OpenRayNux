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
    orxnud [--state-root <DIR>] [--provider-base-url <URL> --provider-model <NAME>]

OPTIONS:
    --state-root <DIR>          Where state lives. Defaults to
                                $XDG_STATE_HOME/orxnud, or ~/.local/state/orxnud.
    --provider-base-url <URL>   An OpenAI-compatible base URL, e.g.
                                https://api.openai.com/v1. Both provider options must
                                be given together; with neither, `task/ai-propose`
                                answers `provider-not-configured`. https is the only
                                scheme that may carry a credential: a plaintext endpoint
                                is refused rather than used.
    --provider-model <NAME>     The model to ask for, e.g. gpt-4o-mini.
    --provider-scripted         Use the built-in non-model script instead of a real
                                provider. For deterministic testing on a host with no
                                credentials; it answers one fixed proposal and records
                                scripted/none in the audit record. Cannot be combined with
                                the two options above.
    --version                   Print the version and exit.
    --doctor                    Print a diagnosis of the configured paths and exit.
    --help                      Print this and exit.

PROVIDER CREDENTIAL:
    Read from the platform credential store, never from the command line or the
    environment: key `provider-api-key`, account `local`. An argument or an
    environment variable is visible to every process of the same user and ends up in
    `ps` output and crash dumps, so neither is accepted for a secret here. Store one with

        orxnuctl provider credential set < key.txt

    Until a key is stored, a configured provider answers `provider-credential-absent`.

PROVIDER SELECTION:
    Manual, and authoritative. The provider and model given here are exactly what the
    runtime uses. If they fail, the failure is reported: there is no automatic retry,
    no second provider, and no fallback to the scripted one. A provider outage is an
    outage, and a task's text may be private, so it is not permission to send the same
    context somewhere else.

The daemon serves a local endpoint only. Its single outbound connection is the
provider request above, and nothing else.
";

/// Argument parsing, hand-written.
///
/// The verb set is closed and tiny, and refusing an unexpected argument is a rule
/// worth writing by hand -- the same reasoning `orxnuctl` records for not taking
/// `clap`.
fn parse_args() -> Result<Action, String> {
    let mut root: Option<String> = None;
    // Non-secret provider settings. The credential is *not* here and cannot be: it is
    // read from the platform secret store by reference, because an argument is visible
    // in `ps` output and in the shell history.
    let mut base_url: Option<String> = None;
    let mut model: Option<String> = None;
    let mut scripted = false;
    let mut doctor = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--version" | "-V" => return Ok(Action::Version),
            "--help" | "-h" => return Ok(Action::Help),
            // Deferred to the end of parsing, not returned here.
            //
            // `--doctor` used to `return Ok(Action::Doctor)` inside this loop, which
            // meant (a) `--state-root` had to appear *before* `--doctor` to be seen at
            // all, and (b) even when it was seen, the `Action::Doctor` variant carried
            // no root, so the value was dropped and `doctor` reported the default
            // root's paths. The flag was accepted, validated, and ignored — worse than
            // rejecting it, because the output looked like a real diagnosis of the
            // root the operator asked about.
            "--doctor" => doctor = true,
            "--state-root" => {
                root = Some(
                    args.next()
                        .ok_or_else(|| "--state-root needs a directory".to_owned())?,
                );
            }
            other if other.starts_with("--state-root=") => {
                root = Some(other["--state-root=".len()..].to_owned());
            }
            "--provider-base-url" => {
                base_url = Some(
                    args.next()
                        .ok_or_else(|| "--provider-base-url needs a URL".to_owned())?,
                );
            }
            other if other.starts_with("--provider-base-url=") => {
                base_url = Some(other["--provider-base-url=".len()..].to_owned());
            }
            "--provider-scripted" => {
                scripted = true;
            }
            "--provider-model" => {
                model = Some(
                    args.next()
                        .ok_or_else(|| "--provider-model needs a model name".to_owned())?,
                );
            }
            other if other.starts_with("--provider-model=") => {
                model = Some(other["--provider-model=".len()..].to_owned());
            }
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }
    // Resolved once, for every verb that has a state root.
    let root = root.map_or_else(
        orxnud_platform_ipc::default_state_root,
        std::path::PathBuf::from,
    );
    if doctor {
        return Ok(Action::Doctor { root });
    }
    Ok(Action::Serve {
        root,
        provider: ProviderChoice::new(base_url, model, scripted),
    })
}

/// What the process was asked to do.
enum Action {
    /// Print the version and exit.
    Version,
    /// Print usage and exit.
    Help,
    /// Print the state layout and exit.
    Doctor {
        /// The root to report on. Carried rather than re-derived, because re-deriving
        /// it from the environment is how `--state-root` came to be ignored.
        root: std::path::PathBuf,
    },
    /// Serve, optionally with a proposal provider configured.
    Serve {
        /// Durable state root.
        root: std::path::PathBuf,
        /// Which provider, if any.
        provider: ProviderChoice,
    },
}

/// Which proposal provider a daemon was asked to use.
///
/// Three states and no default, because every default here is a way to be wrong
/// unnoticeably: a missing model name would be substituted, or a missing provider would be
/// filled with a script that answers a fixed string.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProviderChoice {
    /// Nothing configured. `task/ai-propose` answers `provider-not-configured`.
    None,
    /// A fixed, non-model provider, for deterministic testing without credentials.
    Scripted,
    /// An OpenAI-compatible endpoint.
    Remote {
        /// The base URL.
        base_url: String,
        /// The model to ask for.
        model: String,
    },
    /// `--provider-scripted` together with a real endpoint: contradictory.
    Conflicted,
    /// One of the two remote settings without the other.
    Incomplete,
}

impl ProviderChoice {
    fn new(base_url: Option<String>, model: Option<String>, scripted: bool) -> Self {
        match (base_url, model, scripted) {
            (None, None, false) => Self::None,
            (None, None, true) => Self::Scripted,
            (Some(base_url), Some(model), false) => Self::Remote { base_url, model },
            (_, _, true) => Self::Conflicted,
            _ => Self::Incomplete,
        }
    }
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
        Action::Serve { root, .. } => root.clone(),
        Action::Doctor { root } => root.clone(),
        Action::Version | Action::Help => orxnud_platform_ipc::default_state_root(),
    };
    let provider = match &action {
        Action::Version => {
            println!("orxnud {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Action::Help => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Action::Doctor { .. } => {
            // Honour `--state-root`.
            //
            // This used to call `default_state_root()` unconditionally, so
            // `orxnud --doctor --state-root /somewhere/else` printed a confident
            // diagnosis of the *default* root and said nothing about the one asked
            // for. An operator auditing a specific state root — after an incident, or
            // when several instances exist on one host — was therefore reading a
            // report about a different installation's paths. Silently ignoring an
            // argument is worse than refusing it, and this now simply answers the
            // question that was asked.
            doctor(&Paths::under(&root));
            return ExitCode::SUCCESS;
        }
        Action::Serve { provider, .. } => provider.clone(),
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

    runtime.block_on(async move { serve(Paths::under(&root), provider).await })
}

/// Serves, with a proposal provider when one was chosen.
///
/// A provider is built only from a complete, unambiguous choice. Half a configuration is a
/// refusal at startup rather than a guess here, because a default model name silently
/// substituted for a missing one is a daemon that reports proposals from a model nobody
/// chose.
async fn serve(paths: Paths, choice: ProviderChoice) -> ExitCode {
    let provider: Option<std::sync::Arc<dyn orxnud_daemon::proposer::ProposalProvider>> =
        match choice {
            ProviderChoice::None => {
                eprintln!(
                    "orxnud: no proposal provider configured; task/ai-propose will answer \
                     provider-not-configured"
                );
                None
            }
            ProviderChoice::Scripted => {
                eprintln!(
                    "orxnud: proposal provider is the built-in SCRIPT (not a model); it will \
                     answer one fixed proposal and record scripted/none in the audit record"
                );
                Some(orxnud_daemon::runtime::scripted_proposer())
            }
            ProviderChoice::Conflicted => {
                eprintln!(
                    "orxnud: --provider-scripted cannot be combined with \
                     --provider-base-url or --provider-model"
                );
                return ExitCode::FAILURE;
            }
            ProviderChoice::Incomplete => {
                eprintln!(
                    "orxnud: --provider-base-url and --provider-model must be given together"
                );
                return ExitCode::FAILURE;
            }
            ProviderChoice::Remote { base_url, model } => {
                match orxnud_daemon::http_provider::provider_from_settings(
                    Some(&base_url),
                    Some(&model),
                    KeyringSecrets::new(),
                ) {
                    Ok(p) => {
                        eprintln!(
                            "orxnud: proposal provider configured ({} model {})",
                            p.config().base_url,
                            p.config().model
                        );
                        Some(std::sync::Arc::new(p))
                    }
                    Err(e) => {
                        eprintln!("orxnud: proposal provider not usable: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        };

    // One store instance for both the startup report and the runtime, so the availability
    // reported cannot come from a different probe than the one that is used.
    let secrets = KeyringSecrets::new();

    // The ordering that matters is inside `Runtime::start`: durable security state is
    // attached before the endpoint exists. If it fails here, nothing was bound.
    let mut runtime = match Runtime::start_unconfigured(paths.clone(), secrets.clone()).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("orxnud: refusing to start: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(provider) = provider {
        runtime = runtime.with_proposer(provider);
    }

    if let Some(why) = secrets.stale_probe_entry() {
        eprintln!("orxnud: warning: {why}");
    }

    let endpoint = runtime.endpoint().to_path_buf();
    eprintln!(
        "orxnud: serving {} on {} (durable audit: {})",
        runtime.backend(),
        endpoint.display(),
        runtime.is_durable().await
    );

    // What the previous process left unsettled, reported before the first request is
    // accepted rather than on demand.
    //
    // The dispatcher settles every authorisation it creates, so this is normally
    // empty and stays that way. A non-empty report is the one case the journal cannot
    // resolve by itself: an authorisation that no terminal record names. Serving
    // continues — refusing to start would turn a reportable unknown into an outage no
    // restart could clear — but an operator reading the startup banner now learns
    // about it, instead of the information existing only in a function called from
    // tests.
    let settlement = runtime.restored_settlement().await;
    if settlement.is_settled() {
        eprintln!("orxnud: audit journal restored, fully settled");
    } else {
        eprintln!(
            "orxnud: WARNING: audit journal restored with {} unsettled authorisation(s): \
             {:?}",
            settlement.unresolved_authorisations.len(),
            settlement.unresolved_authorisations
        );
        if !settlement.dangling_settlements.is_empty() {
            eprintln!(
                "orxnud: WARNING: {} terminal record(s) name an authorisation that does \
                 not exist (terminal_seq, claimed_seq): {:?}",
                settlement.dangling_settlements.len(),
                settlement.dangling_settlements
            );
        }
        eprintln!(
            "orxnud: each listed seq is readable from the audit_log table; the action it \
             authorised has no recorded disposition"
        );
    }

    match runtime.serve(orxnud_platform_ipc::shutdown_signal()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("orxnud: transport failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Prints a diagnosis of the configured paths. Creates nothing.
///
/// # Why the list is annotated rather than bare
///
/// This used to print `paths.all()` — five paths — with no indication of which
/// existed. Three of the five are never created by anything: there is no `audit.log`
/// (the journal is the `audit_log` **table** inside `state.db`), no `daemon.lock`
/// (`InstanceLock` is an in-memory record; the single-instance rule is enforced by the
/// endpoint refusing to be replaced), and no `daemon.log` (logs go to stderr). An
/// operator reading a bare list has no way to tell "this file exists" from "this file
/// is a name this daemon has always had", and the first thing anyone does with a
/// diagnosis is go and look at the paths in it.
///
/// So each entry states whether it is present, and the two facts an operator cannot
/// otherwise infer — where the audit records actually live, and what actually enforces
/// one-instance-per-root — are stated outright.
fn doctor(paths: &Paths) {
    let present = |p: &std::path::Path| {
        if p.exists() { "present" } else { "absent" }
    };
    let endpoint = orxnud_platform_ipc::endpoint_for(&paths.root);
    let socket_present = endpoint.exists();

    println!("orxnud {}", env!("CARGO_PKG_VERSION"));
    println!(
        "state root: {} ({})",
        paths.root.display(),
        present(&paths.root)
    );
    println!("  {}", paths.database.display());
    println!("    present: {}", present(&paths.database));
    println!("  {}", endpoint.display());
    println!("    present: {}", present(&endpoint));
    println!("  {}", paths.root.join("workspace").display());
    println!("    present: {}", present(&paths.root.join("workspace")));
    println!(
        "durable audit: the audit_log table inside {}",
        paths.database.display()
    );
    println!("  (there is no separate audit.log file; the journal is SQLite, hash-chained)");
    println!("single instance: enforced by the endpoint above, not by a lock file");
    println!("  (no daemon.lock is created; a live endpoint refuses a second daemon)");
    println!("logs: stderr");
    println!("  (no daemon.log is created)");
    println!("ipc backend: {}", orxnud_platform_ipc::backend_name());
    if !socket_present {
        println!(
            "ipc endpoint: {} (not currently bound — no daemon is serving this root)",
            endpoint.display()
        );
    }
    // The backend *name* is a compile-time fact and says nothing about whether this host
    // can actually isolate anything: it reads `bwrap` on a machine where `bwrap` cannot
    // create a user namespace and every Tier-1 capability is refused. So the guarantees
    // are printed too, and the verdict says whether a Tier-1 capability can run here.
    print!("{}", orxnud_platform_sandbox::host_capability().report());
    println!("durable security state: the audit_log and spent_approvals tables inside");
    println!("  {}", paths.database.display());
    println!("  both are attached and verified before the endpoint is bound");
    println!("(no paths were created; --doctor only reports)");
}
