//! The `orxnuctl` binary.
//!
//! Thin by design: argument parsing, printing, exit code. All of it lives in the
//! library so it can be tested without spawning a process, and so a subcommand is a
//! library change with tests rather than a `main.rs` edit.
//!
//! # Exit status
//!
//! `0` when the command succeeded, non-zero when it did not — whether the failure was
//! a typo, an unreachable daemon, or a refusal. Nothing is encoded in the exit *value*
//! beyond success/failure: task state belongs to the daemon, and a shell that had to
//! understand exit code 3 to mean "already completed" would be a second copy of the
//! state machine in the worst possible place.

use std::process::ExitCode;

use orxnuctl::CliError;
use orxnuctl::client::Client;
use orxnuctl::{Command, ProviderCommand, help, parse, provider, task, version_line};

/// The one place the endpoint is decided, so no command body can forget the override.
///
/// `None` means the daemon's own default derivation, computed by the same function it
/// uses — so a client cannot end up looking somewhere the daemon is not.
fn client_for(endpoint: &Option<std::path::PathBuf>) -> Client {
    match endpoint {
        Some(path) => Client::new(path.clone()),
        None => Client::with_default_endpoint(),
    }
}

fn main() -> ExitCode {
    match parse(std::env::args().skip(1)) {
        Ok(invocation) => match invocation.command {
            Command::Version => {
                println!("{}", version_line());
                ExitCode::SUCCESS
            }
            Command::Doctor => {
                // Ask a daemon if one answers, and say so plainly if not. Starting one
                // to find out would be absurd, so `doctor` never spawns.
                let client = client_for(&invocation.endpoint);
                // One call, two observations. `daemon/status` is the answer that
                // matters here: the sandbox capability is a property of the *host the
                // daemon dispatches on*, and asking a second endpoint would risk
                // observing a different one.
                let observed = client.call("daemon/status", serde_json::json!({})).ok();
                print!("{}", orxnuctl::doctor_with(observed.as_ref()).render());
                ExitCode::SUCCESS
            }
            Command::Capability(ref capability) => {
                let client = client_for(&invocation.endpoint);
                match capability {
                    orxnuctl::CapabilityCommand::Run {
                        capability,
                        params,
                        target,
                        approval,
                    } => {
                        match task::run_capability(
                            capability,
                            params,
                            target.as_deref(),
                            approval.as_deref(),
                            &client,
                        ) {
                            Ok((output, succeeded)) => {
                                print!("{output}");
                                if succeeded {
                                    ExitCode::SUCCESS
                                } else {
                                    ExitCode::FAILURE
                                }
                            }
                            Err(e) => {
                                eprintln!("{}", task::describe_refusal(&e));
                                ExitCode::FAILURE
                            }
                        }
                    }
                    orxnuctl::CapabilityCommand::Approve {
                        capability,
                        params,
                        proposal,
                        target,
                        ttl_ms,
                    } => match task::approve_capability(
                        capability.as_deref(),
                        params.as_deref(),
                        proposal.as_deref(),
                        target.as_deref(),
                        *ttl_ms,
                        &client,
                    ) {
                        Ok(text) => {
                            // To stdout and nothing else: the output is an artefact meant
                            // for another command's `--approval`, so any commentary here
                            // would have to be stripped by the next shell.
                            println!("{text}");
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            eprintln!("{}", task::describe_refusal(&e));
                            ExitCode::FAILURE
                        }
                    },
                }
            }
            Command::Provider(ProviderCommand::Credential(ref verb)) => {
                // The only command that touches a secret store, and the only one that
                // reads stdin. It reaches the platform store directly rather than through
                // the daemon: a credential has no business crossing an IPC socket, and
                // asking the daemon to hold one would put it in a process that does not
                // need it.
                let secrets = orxnud_platform_secrets::KeyringSecrets::new();
                match provider::run(verb, &secrets) {
                    Ok(output) => {
                        println!("{output}");
                        ExitCode::SUCCESS
                    }
                    Err(why) => {
                        eprintln!("error: {why}");
                        ExitCode::FAILURE
                    }
                }
            }
            Command::Task(ref verb) => {
                // The one place the endpoint is decided, so no command body can
                // forget the override. `None` means the daemon's own default
                // derivation, computed by the same function it uses.
                let client = client_for(&invocation.endpoint);
                match task::run(verb, &client) {
                    Ok(output) => {
                        print!("{output}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("{}", task::describe_refusal(&e));
                        ExitCode::FAILURE
                    }
                }
            }
        },
        Err(CliError::MissingCommand(_)) => {
            print!("{}", help());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            eprintln!("try `orxnuctl --help`");
            ExitCode::FAILURE
        }
    }
}
