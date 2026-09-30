//! The `orxnuctl` binary.
//!
//! Thin by design: argument parsing, printing, exit code. All of it lives in the
//! library so it can be tested without spawning a process, and so a future
//! subcommand is a library change with tests rather than a `main.rs` edit.

use std::process::ExitCode;

use orxnuctl::{CliError, doctor, help, parse, version_line};

fn main() -> ExitCode {
    match parse(std::env::args().skip(1)) {
        Ok(invocation) => {
            match invocation.command {
                orxnuctl::Command::Version => println!("{}", version_line()),
                orxnuctl::Command::Doctor => print!("{}", doctor().render()),
            }
            ExitCode::SUCCESS
        }
        Err(CliError::MissingCommand(_)) => {
            print!("{}", help());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
