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
use orxnuctl::{Command, help, parse, task, version_line};

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
                let observed = client
                    .call("capability/list", serde_json::json!({}))
                    .ok()
                    .and_then(|r| r.get("enabled").and_then(serde_json::Value::as_u64))
                    .and_then(|n| usize::try_from(n).ok());
                print!("{}", orxnuctl::doctor_with(observed).render());
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
                        target,
                        ttl_ms,
                    } => match task::approve_capability(
                        capability,
                        params,
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
