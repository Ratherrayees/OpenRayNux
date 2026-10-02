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
use orxnuctl::{Command, doctor, help, parse, task, version_line};

fn main() -> ExitCode {
    match parse(std::env::args().skip(1)) {
        Ok(invocation) => match invocation.command {
            Command::Version => {
                println!("{}", version_line());
                ExitCode::SUCCESS
            }
            Command::Doctor => {
                print!("{}", doctor().render());
                ExitCode::SUCCESS
            }
            Command::Task(ref verb) => {
                // The one place the endpoint is decided, so no command body can
                // forget the override. `None` means the daemon's own default
                // derivation, computed by the same function it uses.
                let client = match invocation.endpoint {
                    Some(path) => Client::new(path),
                    None => Client::with_default_endpoint(),
                };
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
