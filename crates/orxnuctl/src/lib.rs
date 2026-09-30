//! `orxnuctl` — the CLI. Two subcommands, and that is the whole of it.
//!
//! # Why this is so small
//!
//! `docs/13-phase-1-contract.md` §8 permits `--version` and `doctor` and nothing
//! else. Every real command arrives in Phase 6, when there are interfaces to
//! drive. A CLI with placeholder verbs — `run`, `list`, `stop` that print "not
//! implemented" — teaches users that commands exist before they do, and the
//! commands then have to be designed around expectations set by stubs.
//!
//! So the argument parser is *closed*: an unknown subcommand is an error listing
//! what exists, rather than a hint that something is coming.
//!
//! # Depends on `orxnud-protocol` only
//!
//! The contract's rule for interfaces is that they may depend on
//! `orxnud-protocol` and nothing else internal (docs-03 §2, IR-2). That is what
//! makes "business logic exists exactly once" true: a CLI cannot reimplement a
//! rule it cannot see. Gate G2 enforces it mechanically — `orxnuctl`'s manifest
//! is the check.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

use orxnud_protocol::{PROTOCOL_VERSION, RpcErrorCode};

/// The CLI's own version, from the crate metadata.
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name used in help output and error messages.
pub const PROGRAM: &str = "orxnuctl";

/// The subcommands that exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Print the version and exit.
    Version,
    /// Report what this build is and what it can currently do.
    Doctor,
}

/// Why a command line could not be understood.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CliError {
    /// A subcommand that does not exist.
    #[error("unknown command {0:?}")]
    UnknownCommand(String),

    /// A known subcommand given an argument it does not take.
    ///
    /// Refused rather than ignored: silently dropping an argument a user typed is
    /// how `--porfile` becomes a mystery.
    #[error("{command} takes no arguments, but {extra:?} was given")]
    UnexpectedArgument {
        /// The subcommand.
        command: &'static str,
        /// What was supplied.
        extra: String,
    },

    /// A global flag with no subcommand.
    #[error("{0} requires a subcommand; try `{PROGRAM} --help`")]
    MissingCommand(String),
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Version => "version",
            Self::Doctor => "doctor",
        };
        f.write_str(s)
    }
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// What to do.
    pub command: Command,
}

/// The help text.
#[must_use]
pub fn help() -> String {
    format!(
        "{PROGRAM} {CLI_VERSION}\n\
         \n\
         Usage:\n  \
           {PROGRAM} --version\n  \
           {PROGRAM} doctor\n  \
           {PROGRAM} --help\n\
         \n\
         Commands:\n  \
           version   Print the version and exit\n  \
           doctor    Report this build: capabilities, config, storage\n\
         \n\
         This build speaks local protocol version {PROTOCOL_VERSION}.\n\
         There are no other commands yet."
    )
}

/// The version line.
#[must_use]
pub fn version_line() -> String {
    format!("{PROGRAM} {CLI_VERSION} (protocol {PROTOCOL_VERSION})")
}

/// Parses arguments, excluding `argv[0]`.
///
/// # Errors
///
/// [`CliError`] for an unknown command, an unexpected argument, or a flag with no
/// subcommand.
pub fn parse<I, S>(args: I) -> Result<Invocation, CliError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|s| s.as_ref().to_owned()).collect();

    match args.split_first() {
        None => Err(CliError::MissingCommand("--help".to_owned())),
        Some((first, rest)) => match first.as_str() {
            "--version" | "-V" | "version" => {
                reject_extra("version", rest)?;
                Ok(Invocation {
                    command: Command::Version,
                })
            }
            "doctor" => {
                reject_extra("doctor", rest)?;
                Ok(Invocation {
                    command: Command::Doctor,
                })
            }
            "--help" | "-h" | "help" => Err(CliError::MissingCommand("--help".to_owned())),
            other => Err(CliError::UnknownCommand(other.to_owned())),
        },
    }
}

fn reject_extra(command: &'static str, rest: &[String]) -> Result<(), CliError> {
    match rest.first() {
        None => Ok(()),
        Some(extra) => Err(CliError::UnexpectedArgument {
            command,
            extra: extra.clone(),
        }),
    }
}

/// What `doctor` reports about this build.
///
/// A struct rather than a formatted string so a test can assert on the parts and
/// a caller can render them however it likes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// The CLI version.
    pub cli_version: &'static str,
    /// The local protocol version this build speaks.
    pub protocol_version: u16,
    /// How many capabilities are enabled. Always zero in Phase 1.
    pub enabled_capabilities: usize,
    /// Whether the audit chain is wired.
    pub audit_wired: bool,
    /// Whether the store is wired.
    pub store_wired: bool,
    /// A note that no other commands exist, so a user is not left guessing.
    pub commands: Vec<&'static str>,
}

impl DoctorReport {
    /// Renders the report.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("{} {}\n", PROGRAM, self.cli_version));
        s.push_str(&format!("local protocol: {}\n", self.protocol_version));
        s.push_str(&format!(
            "capabilities enabled: {}\n",
            self.enabled_capabilities
        ));
        s.push_str(&format!("store wired: {}\n", self.store_wired));
        s.push_str(&format!("audit wired: {}\n", self.audit_wired));
        s.push_str(&format!("commands: {}\n", self.commands.join(", ")));
        s.push_str("\nNo capability is enabled. This is the expected Phase 1 state.\n");
        s
    }
}

/// The report for this build.
///
/// Reports from the CLI's own knowledge, not by starting a daemon: `doctor` must
/// work when nothing is running, which is exactly when a user runs it.
#[must_use]
pub fn doctor() -> DoctorReport {
    DoctorReport {
        cli_version: CLI_VERSION,
        protocol_version: PROTOCOL_VERSION.as_u16(),
        enabled_capabilities: 0,
        audit_wired: true,
        store_wired: true,
        commands: vec!["version", "doctor"],
    }
}

/// The JSON-RPC code a CLI failure maps to.
///
/// Not a mapping the CLI needs yet — there is no transport — but recording it
/// keeps the vocabulary honest: a CLI failure will eventually cross the wire, and
/// choosing the code then would be an unreviewed decision.
#[must_use]
pub const fn error_code_for(_error: &CliError) -> RpcErrorCode {
    // Invalid params, not method-not-found: the CLI has no methods to speak of,
    // and "method not found" would suggest a protocol problem where the user made
    // a CLI mistake.
    RpcErrorCode::INVALID_PARAMS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_doctor_are_the_whole_interface() {
        for args in [vec!["--version"], vec!["version"], vec!["-V"]] {
            assert_eq!(
                parse(args.clone()).expect("parses"),
                Invocation {
                    command: Command::Version
                },
                "{args:?}"
            );
        }
        assert_eq!(
            parse(vec!["doctor"]).expect("parses"),
            Invocation {
                command: Command::Doctor
            }
        );
    }

    #[test]
    fn an_unknown_command_is_an_error_listing_what_exists() {
        // Not a "coming soon" hint: a placeholder verb would create an
        // expectation the implementation then has to honour.
        let err = parse(vec!["run"]).expect_err("must refuse");
        assert_eq!(err, CliError::UnknownCommand("run".to_owned()));
        assert!(
            help().contains("version"),
            "help should list what does exist"
        );
    }

    #[test]
    fn an_unexpected_argument_is_refused_not_ignored() {
        let err = parse(vec!["doctor", "--verbose"]).expect_err("must refuse");
        assert_eq!(
            err,
            CliError::UnexpectedArgument {
                command: "doctor",
                extra: "--verbose".to_owned()
            }
        );
    }

    #[test]
    fn help_alone_is_reported_as_a_missing_command() {
        // `run` returns the help text; it is not an error to *ask* for help.
        for args in [vec!["--help"], vec!["-h"], vec!["help"]] {
            assert_eq!(
                parse(args.clone()).expect_err("handled by main"),
                CliError::MissingCommand("--help".to_owned()),
                "{args:?}"
            );
        }
    }

    #[test]
    fn no_arguments_is_also_a_missing_command() {
        assert_eq!(
            parse(Vec::<String>::new()).expect_err("needs a command"),
            CliError::MissingCommand("--help".to_owned())
        );
    }

    #[test]
    fn the_version_line_states_the_protocol_version() {
        let line = version_line();
        assert!(line.contains(CLI_VERSION));
        assert!(line.contains(&PROTOCOL_VERSION.as_u16().to_string()));
    }

    #[test]
    fn doctor_reports_zero_enabled_capabilities() {
        let r = doctor();
        assert_eq!(r.enabled_capabilities, 0);
        assert!(r.render().contains("capabilities enabled: 0"));
        assert!(r.render().contains("expected Phase 1 state"));
    }

    #[test]
    fn doctor_lists_exactly_the_commands_that_exist() {
        let r = doctor();
        assert_eq!(r.commands, vec!["version", "doctor"]);
        // And nothing in the output implies a capability exists.
        assert!(
            !r.render().contains("asr") && !r.render().contains("llm"),
            "doctor must not imply capabilities exist: {}",
            r.render()
        );
    }

    #[test]
    fn a_cli_error_maps_to_invalid_params() {
        let e = CliError::UnknownCommand("x".into());
        assert_eq!(
            error_code_for(&e).code(),
            RpcErrorCode::INVALID_PARAMS.code()
        );
    }

    #[test]
    fn the_parser_accepts_owned_and_borrowed_arguments() {
        // `parse` is generic so both `env::args()` and a test's `Vec<&str>` work.
        assert!(parse(vec!["doctor"]).is_ok());
        assert!(parse(vec![String::from("doctor")]).is_ok());
    }
}
