//! `orxnuctl` — the CLI.
//!
//! # What it does now
//!
//! `version`, `doctor`, and `task {create,list,claim,complete}`.
//!
//! # Why the parser is hand-written
//!
//! The command set is closed and small. `clap` is a larger dependency for the same
//! result, and one of its behaviours is actively wrong for this CLI: deriving the
//! parser means an unrecognised flag is often *ignored*. Refusing an unexpected
//! argument is a rule worth writing by hand — silently dropping what a user typed is
//! how `--porfile` becomes a mystery.
//!
//! # Depends on the wire vocabulary and the transport, and nothing else internal
//!
//! `orxnud-protocol` for frames, `orxnud-platform-ipc` for the socket. Everything that
//! could carry a domain rule — domain, store, task engine, policy, capability,
//! daemon — is absent, so "business logic exists exactly once" stays true: the CLI
//! cannot reimplement a rule it cannot see. Gate G2(b) checks the manifest
//! mechanically.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

pub mod client;
pub mod provider;
pub mod task;

use orxnud_protocol::{PROTOCOL_VERSION, RpcErrorCode};
use task::TaskCommand;

/// The CLI's own version, from the crate metadata.
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The name used in help output and error messages.
pub const PROGRAM: &str = "orxnuctl";

/// The `capability` subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityCommand {
    /// Invoke a capability through the governed dispatcher.
    ///
    /// Carries the capability id and its parameters as **untrusted input**, and
    /// deliberately nothing else: no assessed risk, no policy version, no approval, no
    /// credential and no authorisation proof. Those are the daemon's to decide, and a
    /// client able to assert them would be asserting authority it was never granted — so
    /// their absence here is the anti-forgery property, not an omission.
    Run {
        /// Which capability to invoke.
        capability: String,
        /// The capability's parameters, verbatim JSON.
        params: String,
        /// The human-readable target the operation concerns, if any.
        ///
        /// Part of the tuple an approval commits to, so it cannot be defaulted past:
        /// an approval issued for one target does not carry to another.
        target: Option<String>,
        /// An approval obtained from [`Self::Approve`], as JSON.
        ///
        /// Carried verbatim and untrusted. The daemon recomputes the digest from the
        /// parameters it is actually about to run and compares, so an approval that has
        /// been edited here is refused rather than believed — which is what makes it
        /// safe for the client to hold this at all.
        approval: Option<String>,
    },
    /// Ask the daemon for an approval of one proposed operation.
    ///
    /// Separate from [`Self::Run`] because approving and performing are different acts:
    /// this one produces the canonical tuple and its digest, and can be refused on its
    /// own terms, whereas a run either happens or does not.
    Approve {
        /// Which capability the approval would be for.
        capability: Option<String>,
        /// The parameters the approval would commit to, verbatim JSON.
        params: Option<String>,
        /// Approve a durable proposal instead of an ad-hoc action.
        ///
        /// The stronger form, and the one the governed task path uses: naming a proposal
        /// means the action comes from storage, so a caller cannot approve one thing and
        /// cause another. Exactly one of `proposal` or `capability` is required.
        proposal: Option<String>,
        /// The human-readable target, if any.
        target: Option<String>,
        /// How long the approval should live, in milliseconds.
        ///
        /// `0` produces an approval that has already expired, which is how the expiry
        /// behaviour is demonstrated without waiting for a clock.
        ttl_ms: Option<i64>,
    },
}

/// The `capability` subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderCommand {
    /// Store, remove or inspect the provider credential.
    Credential(provider::CredentialCommand),
}

/// Whether a provider credential subcommand was recognised.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnknownProviderCommand {
    /// The subcommand word was not one of the three.
    #[error("unknown provider command: {0}")]
    Command(String),
}

/// The subcommands that exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print the version and exit.
    Version,
    /// Report what this build is and what it can currently do.
    Doctor,
    /// Manage tasks, through the local daemon.
    Task(TaskCommand),
    /// Invoke capabilities, through the local daemon.
    Capability(CapabilityCommand),
    /// Manage the proposal provider's credential, in the platform secret store.
    Provider(ProviderCommand),
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

    /// The arguments were not a command this program accepts.
    #[error("{0}")]
    BadArgument(String),

    /// A required flag was not supplied.
    #[error("{command} needs {flag}")]
    MissingFlag {
        /// The subcommand.
        command: &'static str,
        /// The flag, spelled as the user should type it.
        flag: &'static str,
    },

    /// A flag that takes a value did not get one.
    #[error("{flag} needs a value")]
    MissingValue {
        /// The flag, spelled as the user should type it.
        flag: &'static str,
    },

    /// A flag that this command does not accept.
    #[error("{command} does not take {flag}")]
    UnknownFlag {
        /// The subcommand.
        command: &'static str,
        /// The flag that was supplied.
        flag: String,
    },

    /// A flag given more than once.
    #[error("{flag} was given more than once")]
    RepeatedFlag {
        /// The flag, spelled as the user should type it.
        flag: &'static str,
    },

    /// A `task` verb that does not exist.
    #[error(
        "unknown task command {0:?}; expected create, list, claim, complete, cancel, propose, execute, ai-propose or continue"
    )]
    UnknownTaskCommand(String),

    /// A `capability` verb that does not exist.
    #[error("unknown capability command {0:?}; expected run or approve")]
    UnknownCapabilityCommand(String),

    /// A flag whose value could not be used.
    ///
    /// Says what was wrong with the value rather than only that it was rejected, so a
    /// mistyped duration does not read as a mysterious refusal.
    #[error("{flag}={value:?} is not usable: {why}")]
    UnusableFlagValue {
        /// The flag, spelled as the user should type it.
        flag: &'static str,
        /// What was supplied.
        value: String,
        /// Why it could not be used.
        why: String,
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
            Self::Task(_) => "task",
            Self::Capability(_) => "capability",
            Self::Provider(_) => "provider",
        };
        f.write_str(s)
    }
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// What to do.
    pub command: Command,
    /// An endpoint override, when the user gave `--endpoint`.
    ///
    /// The daemon has `--state-root`, so a client needs the matching lever or a
    /// non-default daemon is unreachable. `None` means "use the default derivation",
    /// which is the same function the daemon uses.
    pub endpoint: Option<std::path::PathBuf>,
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
           {PROGRAM} task list\n  \
           {PROGRAM} task create --id <ID> [--kind <KIND>] <CONTENT>\n  \
           {PROGRAM} task claim --id <ID> --worker <WORKER>\n  \
           {PROGRAM} task complete --id <ID> --worker <WORKER>\n  \
           {PROGRAM} --help\n\
         \n\
         Commands:\n  \
           version   Print the version and exit\n  \
           doctor    Report this build: capabilities, config, storage\n  \
           task      Manage tasks through the local daemon\n  \
           capability\n             Invoke a capability through the governed dispatcher\n  \
           provider    Manage the proposal provider's credential\n\
         \n\
         Provider credential:\n\
           orxnuctl provider credential set < key.txt   Store it in the platform secret store\n\
           orxnuctl provider credential status           Report present/absent, never the value\n\
           orxnuctl provider credential delete           Remove it\n\
           The value is read from stdin, never from an argument: an argument is visible\n\
           in `ps` output and in shell history. Nothing echoes it back, not even a prefix.\n\
         \n\
         Capability verbs:\n\
           run     --capability <ID> [--params <JSON>] [--target <T>] [--approval <JSON>]\n\
           approve --capability <ID> [--params <JSON>] [--target <T>] [--ttl-ms <N>]\n\
         \n\
         A High-risk capability needs an approval for its exact parameters:\n\
           APPROVAL=$(orxnuctl capability approve --capability <ID> --params <JSON>)\n\
           orxnuctl capability run --capability <ID> --params <JSON> --approval \"$APPROVAL\"\n\
         \n\
         Task commands accept --endpoint <PATH> to reach a daemon that is not\n\
         on the default state root.\n\
         \n\
         Task state is owned by the daemon: this client sends the request and shows\n\
         the answer, and decides nothing about whether a task may be claimed or\n\
         completed.\n\
         \n\
         This build speaks local protocol version {PROTOCOL_VERSION}."
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
/// [`CliError`] for an unknown command, a missing or repeated flag, an unexpected
/// argument, or a flag with no subcommand.
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
                    endpoint: None,
                })
            }
            "doctor" => {
                // `--endpoint` is lifted here for the same reason as for `task` and
                // `capability`: `doctor` asks a *running* daemon what this host can do,
                // so a user with a non-default state root has to be able to name the
                // daemon they meant. `main` has always read `invocation.endpoint` on this
                // path, so refusing the flag here made that read dead and `doctor` could
                // only ever observe the default endpoint.
                let (endpoint, rest) = lift_endpoint(args_after(&args, 1))?;
                reject_extra("doctor", &rest)?;
                Ok(Invocation {
                    command: Command::Doctor,
                    endpoint: endpoint.map(Into::into),
                })
            }
            "task" => {
                let (command, endpoint) = parse_task(rest)?;
                Ok(Invocation {
                    command: Command::Task(command),
                    endpoint: endpoint.map(Into::into),
                })
            }
            "capability" => {
                let (command, endpoint) = parse_capability(rest)?;
                Ok(Invocation {
                    command: Command::Capability(command),
                    endpoint: endpoint.map(Into::into),
                })
            }
            "provider" => {
                // No endpoint: this command talks to the platform credential store, not to
                // a daemon, so there is no socket for `--endpoint` to name.
                let Some((verb, rest)) = rest.split_first() else {
                    return Err(CliError::MissingFlag {
                        command: "provider",
                        flag: "a command: credential",
                    });
                };
                if verb != "credential" {
                    return Err(CliError::UnknownCommand(format!("provider {verb}")));
                }
                let Some((action, rest)) = rest.split_first() else {
                    return Err(CliError::MissingFlag {
                        command: "provider credential",
                        flag: "one of: set, delete, status",
                    });
                };
                let action = action.clone();
                let inner = provider::parse(std::slice::from_ref(&action))
                    .map_err(CliError::BadArgument)
                    .and_then(|c| {
                        if rest.is_empty() {
                            Ok(c)
                        } else {
                            // Anything after the verb is refused rather than ignored: a
                            // silently-dropped `--api-key` is exactly the mistake this
                            // command exists to make impossible.
                            Err(CliError::BadArgument(format!(
                                "unexpected argument {:?}; the credential is read from \
                                 stdin, never from an argument",
                                rest[0]
                            )))
                        }
                    })?;
                Ok(Invocation {
                    command: Command::Provider(ProviderCommand::Credential(inner)),
                    endpoint: None,
                })
            }
            "--help" | "-h" | "help" => Err(CliError::MissingCommand("--help".to_owned())),
            other => Err(CliError::UnknownCommand(other.to_owned())),
        },
    }
}

/// Parses the arguments after `task`, yielding the command and any endpoint override.
///
/// The endpoint is lifted out **before** the verb is read, so it is accepted in either
/// position. `orxnuctl task --endpoint X list` and `orxnuctl task list --endpoint X`
/// are both spellings a user will type, and a flag that works in only one of them is a
/// papercut that produces a baffling error — which is exactly what it did before this
/// was hoisted.
fn parse_task(args: &[String]) -> Result<(TaskCommand, Option<String>), CliError> {
    let (endpoint, rest) = lift_endpoint(args)?;

    let Some((verb, rest)) = rest.split_first() else {
        return Err(CliError::MissingFlag {
            command: "task",
            flag: "a command: create, list, claim, complete or cancel",
        });
    };
    let mut flags = Flags::parse(verb, rest)?;
    if endpoint.is_some() && flags.take_optional("--endpoint").is_some() {
        return Err(CliError::RepeatedFlag { flag: "--endpoint" });
    }
    let command = match verb.as_str() {
        "create" => {
            let id = flags.take("create", "--id")?;
            let kind = flags.take_optional("--kind");
            let max_steps = flags
                .take_optional("--max-steps")
                .map(|raw| {
                    raw.parse::<u32>().map_err(|_| {
                        CliError::BadArgument(format!(
                            "--max-steps must be a whole number, not {raw:?}"
                        ))
                    })
                })
                .transpose()?;
            let content = flags.into_content();
            // Sent as a JSON number, not as the string the user typed. The wire stays
            // strict -- one spelling of a number, decided by the daemon -- while this is
            // only about accepting what a person types. The *bounds* are not duplicated
            // here: `0` and `1000` are sent on and refused by the daemon, which owns the
            // invariant, so the CLI and the daemon cannot disagree about what is legal.
            TaskCommand::Create {
                id,
                kind,
                content,
                max_steps,
            }
        }
        "list" => {
            flags.reject_all("list")?;
            TaskCommand::List
        }
        "claim" => {
            let id = flags.take("claim", "--id")?;
            let worker = flags.take("claim", "--worker")?;
            flags.reject_all("claim")?;
            TaskCommand::Claim { id, worker }
        }
        "complete" => {
            let id = flags.take("complete", "--id")?;
            let worker = flags.take("complete", "--worker")?;
            flags.reject_all("complete")?;
            TaskCommand::Complete { id, worker }
        }
        "propose" => {
            let task = flags.take("propose", "--task")?;
            let worker = flags.take("propose", "--worker")?;
            let capability = flags.take("propose", "--capability")?;
            let params = flags.take("propose", "--params")?;
            let target = flags.take_optional("--target");
            flags.reject_all("propose")?;
            TaskCommand::Propose {
                task,
                worker,
                capability,
                params,
                target,
            }
        }
        "ai-propose" => {
            let task = flags.take("ai-propose", "--task")?;
            let worker = flags.take("ai-propose", "--worker")?;
            flags.reject_all("ai-propose")?;
            TaskCommand::AiPropose { task, worker }
        }
        "continue" => {
            let task = flags.take("continue", "--task")?;
            let worker = flags.take("continue", "--worker")?;
            flags.reject_all("continue")?;
            TaskCommand::Continue { task, worker }
        }
        "execute" => {
            let proposal = flags.take("execute", "--proposal")?;
            let worker = flags.take("execute", "--worker")?;
            flags.reject_all("execute")?;
            TaskCommand::Execute { proposal, worker }
        }
        "cancel" => {
            // No `--worker`: cancellation is the engine's decision about a task, and
            // requiring an identity here would make an unclaimed task uncancellable.
            let id = flags.take("cancel", "--id")?;
            flags.reject_all("cancel")?;
            TaskCommand::Cancel { id }
        }

        other => return Err(CliError::UnknownTaskCommand(other.to_owned())),
    };
    Ok((command, endpoint))
}

/// Parses the arguments after `capability`.
fn parse_capability(args: &[String]) -> Result<(CapabilityCommand, Option<String>), CliError> {
    let (endpoint, rest) = lift_endpoint(args)?;
    let Some((verb, rest)) = rest.split_first() else {
        return Err(CliError::MissingFlag {
            command: "capability",
            flag: "a command: run",
        });
    };
    let mut flags = Flags::parse(verb, rest)?;
    if endpoint.is_some() && flags.take_optional("--endpoint").is_some() {
        return Err(CliError::RepeatedFlag { flag: "--endpoint" });
    }
    match verb.as_str() {
        "run" => {
            // Generic on purpose: the CLI names no capability and holds no parameter
            // schema, so adding a capability needs no change here — and cannot, since
            // holding a schema would make this a second definition of what a capability
            // accepts. The daemon validates.
            let capability = flags.take("run", "--capability")?;
            let params = flags.take("run", "--params")?;
            let target = flags.take_optional("--target");
            let approval = flags.take_optional("--approval");
            flags.reject_all("run")?;
            Ok((
                CapabilityCommand::Run {
                    capability,
                    params,
                    target,
                    approval,
                },
                endpoint,
            ))
        }
        "approve" => {
            let capability = flags.take_optional("--capability");
            let params = flags.take_optional("--params");
            let proposal = flags.take_optional("--proposal");
            let target = flags.take_optional("--target");
            let ttl_ms = match flags.take_optional("--ttl-ms") {
                None => None,
                Some(text) => {
                    Some(
                        text.parse::<i64>()
                            .map_err(|_| CliError::UnusableFlagValue {
                                flag: "--ttl-ms",
                                value: text,
                                why: "must be a whole number of milliseconds".to_owned(),
                            })?,
                    )
                }
            };
            flags.reject_all("approve")?;
            // Exactly one form. Approving a proposal and approving an ad-hoc action are
            // different acts; accepting both at once would leave which one was meant to
            // the daemon's guess.
            match (proposal.is_some(), capability.is_some()) {
                (true, false) => {}
                (false, true) => {
                    if params.is_none() {
                        return Err(CliError::MissingFlag {
                            command: "approve",
                            flag: "--params",
                        });
                    }
                }
                _ => {
                    return Err(CliError::MissingFlag {
                        command: "approve",
                        flag: "exactly one of --proposal or --capability",
                    });
                }
            }
            Ok((
                CapabilityCommand::Approve {
                    capability,
                    params,
                    proposal,
                    target,
                    ttl_ms,
                },
                endpoint,
            ))
        }
        other => Err(CliError::UnknownCapabilityCommand(other.to_owned())),
    }
}

/// `args` from index `from` onwards.
fn args_after(args: &[String], from: usize) -> &[String] {
    args.get(from..).unwrap_or(&[])
}

/// Removes every `--endpoint` from `args`, returning it and what is left.
///
/// A value-taking flag read out of band, because it may appear before the verb and the
/// verb is what says which other flags are legal.
fn lift_endpoint(args: &[String]) -> Result<(Option<String>, Vec<String>), CliError> {
    let mut endpoint: Option<String> = None;
    let mut rest: Vec<String> = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--endpoint" || arg.starts_with("--endpoint=") {
            if endpoint.is_some() {
                return Err(CliError::RepeatedFlag { flag: "--endpoint" });
            }
            let value = match arg.strip_prefix("--endpoint=") {
                Some(v) => v.to_owned(),
                None => {
                    i += 1;
                    args.get(i)
                        .cloned()
                        .ok_or(CliError::MissingValue { flag: "--endpoint" })?
                }
            };
            endpoint = Some(value);
        } else {
            rest.push(arg.to_owned());
        }
        i += 1;
    }
    Ok((endpoint, rest))
}

/// The `--flag value` pairs of one `task` invocation, plus any bare words.
///
/// Split out from [`parse_task`] so each verb reads as "take these flags, then insist
/// nothing else was passed" — which is what makes an unexpected argument an error
/// rather than a shrug.
struct Flags {
    values: Vec<(&'static str, String)>,
    bare: Vec<String>,
}

impl Flags {
    /// Reads `--flag value` and bare words. Anything else is refused immediately.
    ///
    /// Both `--flag value` and `--flag=value` are accepted, because both are what
    /// people type and the cost of accepting one of them is a shell-quoting mistake.
    fn parse(verb: &str, args: &[String]) -> Result<Self, CliError> {
        // `--endpoint` is absent on purpose: `lift_endpoint` has already removed it,
        // so seeing one here would mean the same flag was accepted twice.
        // The CLI's entire flag vocabulary, in one place so "which flags exist at all"
        // has a single answer. Which of them any given verb accepts is a separate
        // question, answered by what that verb `take`s and by `reject_all` refusing
        // whatever is left -- so `task create --target x` parses here and is then
        // refused by the verb, rather than being invisible to the task parser.
        const KNOWN: [&str; 11] = [
            "--id",
            "--kind",
            // How many logical steps a task may have. Optional, and defaulted by the
            // daemon to one, so a task that does not need continuation stays a short
            // command.
            "--max-steps",
            "--worker",
            "--capability",
            "--params",
            // Task verbs: which task a proposal is for, and which proposal to execute.
            "--task",
            "--proposal",
            // Part of the tuple an approval commits to, so it is carried rather than
            // derived: an approval for one target must not carry to another.
            "--target",
            // An approval produced by `capability approve`, carried verbatim. The daemon
            // recomputes its digest, so holding one grants nothing by itself.
            "--approval",
            "--ttl-ms",
        ];

        let mut values: Vec<(&'static str, String)> = Vec::new();
        let mut bare: Vec<String> = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            if let Some(name) = arg.strip_prefix("--") {
                let (name, inline) = match name.split_once('=') {
                    Some((n, v)) => (n, Some(v.to_owned())),
                    None => (name, None),
                };
                let flag = KNOWN
                    .iter()
                    .copied()
                    .find(|k| k.trim_start_matches('-') == name)
                    .ok_or_else(|| CliError::UnknownFlag {
                        command: leak_verb(verb),
                        flag: arg.to_owned(),
                    })?;
                let value = match inline {
                    Some(v) => v,
                    None => {
                        i += 1;
                        args.get(i)
                            .cloned()
                            .ok_or(CliError::MissingValue { flag })?
                    }
                };
                if values.iter().any(|(k, _)| *k == flag) {
                    return Err(CliError::RepeatedFlag { flag });
                }
                values.push((flag, value));
            } else {
                bare.push(arg.to_owned());
            }
            i += 1;
        }
        Ok(Self { values, bare })
    }

    /// The value of a required flag.
    ///
    /// # Errors
    ///
    /// [`CliError::MissingFlag`] if absent.
    ///
    /// **Removes** the flag it reads, which is what makes [`Self::reject_all`]
    /// meaningful: a leftover is then exactly a flag this verb did not ask for, rather
    /// than every flag including the ones just consumed.
    fn take(&mut self, verb: &'static str, flag: &'static str) -> Result<String, CliError> {
        self.take_optional(flag).ok_or(CliError::MissingFlag {
            command: verb,
            flag,
        })
    }

    /// The value of an optional flag, removing it.
    fn take_optional(&mut self, flag: &'static str) -> Option<String> {
        let at = self.values.iter().position(|(k, _)| *k == flag)?;
        Some(self.values.remove(at).1)
    }

    /// The trailing words, joined — a task's content.
    fn into_content(mut self) -> Option<String> {
        let content = std::mem::take(&mut self.bare).join(" ");
        if content.is_empty() {
            None
        } else {
            Some(content)
        }
    }

    /// Refuses anything not already consumed.
    ///
    /// A leftover here is a flag this verb never asked for, which is the whole point:
    /// `--kind` is create's, and `claim` must not quietly accept it.
    ///
    /// # Errors
    ///
    /// [`CliError::UnknownFlag`] for a leftover flag.
    fn reject_all(&self, verb: &'static str) -> Result<(), CliError> {
        if let Some((flag, _)) = self.values.first() {
            return Err(CliError::UnknownFlag {
                command: verb,
                flag: (*flag).to_owned(),
            });
        }
        if let Some(extra) = self.bare.first() {
            return Err(CliError::UnexpectedArgument {
                command: verb,
                extra: extra.clone(),
            });
        }
        Ok(())
    }
}

/// The verb a flag error should name.
///
/// `parse` learns the verb from a borrowed `&str`, but a `CliError` has to own it to
/// outlive the call. The set is closed and tiny, so interning is a lookup rather than
/// an allocation on a path that runs once per process.
fn leak_verb(verb: &str) -> &'static str {
    match verb {
        "create" => "create",
        "list" => "list",
        "claim" => "claim",
        "complete" => "complete",
        _ => "task",
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
    /// How many capabilities the daemon reports as enabled.
    ///
    /// `None` when no daemon was reachable. This used to be a hard-coded `0`, which was
    /// true while the build shipped nothing and became a lie the moment it shipped
    /// something — a `doctor` that reports a number it cannot observe is worse than one
    /// that admits it does not know.
    pub enabled_capabilities: Option<usize>,
    /// Whether the audit chain is wired.
    pub audit_wired: bool,
    /// Whether the store is wired.
    pub store_wired: bool,
    /// What the daemon reports this host can guarantee for a Tier-1 capability.
    ///
    /// `None` when no daemon was reachable, which is not the same as `false`. A
    /// `doctor` that cannot ask must say it does not know rather than imply the host
    /// cannot sandbox: "unknown" and "no" send an operator to different places.
    pub sandbox: Option<SandboxCapability>,
    /// A note that no other commands exist, so a user is not left guessing.
    pub commands: Vec<&'static str>,
}

/// The daemon's report of this host's sandbox capability.
///
/// Mirrors `daemon/status`'s `sandbox` object. Kept as named fields rather than a raw
/// `serde_json::Value` so `doctor` cannot render a half-understood shape, and so a
/// daemon that answers with something unexpected is visibly *absent* rather than
/// silently rendered as `false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCapability {
    /// Which backend the daemon's build selected. Compile-time.
    pub backend: String,
    /// Whether PID/mount namespaces are available here.
    pub visibility: bool,
    /// Whether a detached descendant can be contained here.
    pub tree_lifetime: bool,
    /// Whether OS-enforced resource ceilings are available here.
    pub resources: bool,
    /// Whether a Tier-1 capability can run here at all.
    pub tier1_executable: bool,
}

impl SandboxCapability {
    /// Reads the `sandbox` object out of a `daemon/status` response.
    ///
    /// Returns `None` when the field is absent or any field has the wrong type, so a
    /// protocol change degrades to "unknown" instead of to a wrong `false` — and a
    /// wrong `false` here would claim this host cannot isolate anything.
    #[must_use]
    pub fn from_status(value: &serde_json::Value) -> Option<Self> {
        let s = value.get("sandbox")?;
        Some(Self {
            backend: s.get("backend")?.as_str()?.to_owned(),
            visibility: s.get("visibility")?.as_bool()?,
            tree_lifetime: s.get("tree_lifetime")?.as_bool()?,
            resources: s.get("resources")?.as_bool()?,
            tier1_executable: s.get("tier1_executable")?.as_bool()?,
        })
    }

    /// The lines `render` prints for this capability.
    #[must_use]
    fn render(&self) -> String {
        let verdict = if self.tier1_executable {
            "yes"
        } else {
            "no — Tier-1 capabilities are refused here, which is correct"
        };
        format!(
            "sandbox backend: {}\n\
             sandbox guarantees: visibility={} tree_lifetime={} resources={}\n\
             tier1 executable: {verdict}\n",
            self.backend, self.visibility, self.tree_lifetime, self.resources,
        )
    }
}

impl DoctorReport {
    /// Renders the report.
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("{} {}\n", PROGRAM, self.cli_version));
        s.push_str(&format!("local protocol: {}\n", self.protocol_version));
        match self.enabled_capabilities {
            Some(n) => s.push_str(&format!("capabilities enabled: {n}\n")),
            None => s.push_str("capabilities enabled: unknown (no daemon reachable)\n"),
        }
        s.push_str(&format!("store wired: {}\n", self.store_wired));
        s.push_str(&format!("audit wired: {}\n", self.audit_wired));
        // The sandbox capability, when a daemon could be asked. It is absent here rather
        // than guessed at: this process cannot know what the *host* can isolate, only
        // the daemon that will actually dispatch on it can.
        match &self.sandbox {
            Some(cap) => s.push_str(&cap.render()),
            None => s.push_str(
                "sandbox capability: unknown (no daemon reachable, so it cannot be \
                 observed)\n",
            ),
        }
        s.push_str(&format!("commands: {}\n", self.commands.join(", ")));
        s.push_str(
            "\nCapability state is the daemon's to report; this build asks it when one \
             is running.\n",
        );
        s
    }
}

/// The report for this build, with no daemon observation.
///
/// Reports from the CLI's own knowledge and never starts a daemon: `doctor` must work
/// when nothing is running, which is exactly when a user runs it. `main` fills in
/// [`DoctorReport::enabled_capabilities`] when a daemon does answer.
#[must_use]
pub fn doctor() -> DoctorReport {
    doctor_with(None)
}

/// [`doctor`], with what a running daemon reported.
///
/// Both observations come from the same round trip conceptually and are passed together
/// so `doctor` has one place to learn what it could not observe.
#[must_use]
pub fn doctor_with(observed: Option<&serde_json::Value>) -> DoctorReport {
    DoctorReport {
        cli_version: CLI_VERSION,
        protocol_version: PROTOCOL_VERSION.as_u16(),
        enabled_capabilities: observed
            // `daemon/status` names it `capabilities_enabled`; `capability/list` names it
            // `enabled`. Both are read so a `doctor` still works against either shape,
            // and a response carrying neither degrades to "unknown" rather than to 0.
            .and_then(|r| r.get("capabilities_enabled").or_else(|| r.get("enabled")))
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| usize::try_from(n).ok()),
        audit_wired: true,
        store_wired: true,
        sandbox: observed.and_then(SandboxCapability::from_status),
        commands: vec![
            "version",
            "doctor",
            "task create",
            "task list",
            "task claim",
            "task complete",
            "task cancel",
            "capability run",
        ],
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
    fn version_and_doctor_parse_without_a_subcommand() {
        for args in [vec!["--version"], vec!["version"], vec!["-V"]] {
            assert_eq!(
                parse(args.clone()).expect("parses"),
                Invocation {
                    command: Command::Version,
                    endpoint: None,
                },
                "{args:?}"
            );
        }
        assert_eq!(
            parse(vec!["doctor"]).expect("parses"),
            Invocation {
                command: Command::Doctor,
                endpoint: None,
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
    fn doctor_admits_when_it_cannot_see_the_daemon() {
        // Was `capabilities enabled: 0`, asserted as a fact. It was true while nothing
        // shipped and became false the moment something did, which is exactly the kind
        // of stale claim `doctor` is run to disprove.
        let r = doctor();
        assert_eq!(r.enabled_capabilities, None);
        assert!(
            r.render().contains("unknown (no daemon reachable)"),
            "{}",
            r.render()
        );
        assert!(
            !r.render().contains("No capability is enabled"),
            "a stale Phase-1 claim must not survive: {}",
            r.render()
        );
    }

    #[test]
    fn doctor_reports_the_count_a_daemon_gave_it() {
        let status = serde_json::json!({
            "status": "running",
            "capabilities_enabled": 3,
            "sandbox": {
                "backend": "bwrap",
                "visibility": true,
                "tree_lifetime": true,
                "resources": true,
                "tier1_executable": true,
            },
        });
        let r = doctor_with(Some(&status));
        assert!(
            r.render().contains("capabilities enabled: 3"),
            "{}",
            r.render()
        );
    }

    /// The capability count came from `capability/list` before and comes from
    /// `daemon/status` now, so both spellings must still be understood.
    #[test]
    fn the_capability_count_is_read_from_either_daemon_spelling() {
        let legacy = serde_json::json!({ "enabled": 2 });
        let current = serde_json::json!({ "capabilities_enabled": 2 });
        assert_eq!(
            doctor_with(Some(&legacy)).enabled_capabilities,
            Some(2),
            "`enabled` must keep working so an older daemon is still readable"
        );
        assert_eq!(doctor_with(Some(&current)).enabled_capabilities, Some(2));
    }

    /// `doctor` reports the host's real Tier-1 capability, in both states.
    ///
    /// The pair matters more than either half. A `doctor` that only ever printed
    /// `tier1_executable: yes` would pass the positive test and be useless, and one that
    /// only printed the refusal would make a capable host look broken.
    #[test]
    fn doctor_reports_that_a_tier1_capability_can_run_when_the_host_allows_it() {
        let status = serde_json::json!({
            "sandbox": {
                "backend": "bwrap",
                "visibility": true,
                "tree_lifetime": true,
                "resources": true,
                "tier1_executable": true,
            },
        });
        let out = doctor_with(Some(&status)).render();
        assert!(out.contains("sandbox backend: bwrap"), "{out}");
        assert!(out.contains("tier1 executable: yes"), "{out}");
    }

    #[test]
    fn doctor_reports_the_refusal_when_the_host_cannot_isolate() {
        // The state a GitHub-hosted Linux runner is in: the backend is still named, and
        // every Tier-1 capability is refused anyway. The wording has to say the refusal
        // is correct, or an operator reads it as a fault and starts "fixing" the host.
        let status = serde_json::json!({
            "sandbox": {
                "backend": "bwrap",
                "visibility": false,
                "tree_lifetime": false,
                "resources": false,
                "tier1_executable": false,
            },
        });
        let out = doctor_with(Some(&status)).render();
        assert!(out.contains("tier1 executable: no"), "{out}");
        assert!(out.contains("which is correct"), "{out}");
    }

    #[test]
    fn doctor_says_unknown_rather_than_claiming_a_host_cannot_sandbox() {
        // No daemon, and a daemon that answers with an unexpected shape, must both
        // degrade to "unknown". Collapsing either into `false` would assert that this
        // host cannot isolate anything, which is a security claim nobody observed.
        let silent = doctor().render();
        assert!(silent.contains("sandbox capability: unknown"), "{silent}");
        assert!(!silent.contains("tier1 executable: no"), "{silent}");

        for malformed in [
            serde_json::json!({}),
            serde_json::json!({ "sandbox": null }),
            serde_json::json!({ "sandbox": { "backend": "bwrap" } }),
            serde_json::json!({ "sandbox": {
                "backend": "bwrap",
                "visibility": "yes",
                "tree_lifetime": true,
                "resources": true,
                "tier1_executable": true,
            } }),
            serde_json::json!({ "sandbox": {
                "backend": 7,
                "visibility": true,
                "tree_lifetime": true,
                "resources": true,
                "tier1_executable": true,
            } }),
        ] {
            let out = doctor_with(Some(&malformed)).render();
            assert!(
                out.contains("sandbox capability: unknown"),
                "a malformed status must not be rendered as a capability verdict: {out}"
            );
            assert!(
                !out.contains("tier1 executable: no"),
                "unknown must never render as a refusal: {out}"
            );
        }
    }

    #[test]
    fn doctor_lists_exactly_the_commands_that_exist() {
        let r = doctor();
        assert_eq!(
            r.commands,
            vec![
                "version",
                "doctor",
                "task create",
                "task list",
                "task claim",
                "task complete",
                "task cancel",
                "capability run",
            ],
            "doctor must not list a command that does not parse"
        );
        // And nothing in the output implies a capability exists.
        assert!(
            !r.render().contains("asr") && !r.render().contains("llm"),
            "doctor must not imply capabilities exist: {}",
            r.render()
        );
    }

    /// Every command `doctor` advertises must actually parse.
    ///
    /// The list in [`doctor`] and the parser are written separately, so they can
    /// disagree — and a user who is told a command exists and then finds it does not is
    /// worse off than one never told. This walks the advertised list through the real
    /// parser, with the minimum arguments each verb needs.
    #[test]
    fn every_advertised_command_actually_parses() {
        let invocations: Vec<Vec<&str>> = vec![
            vec!["version"],
            vec!["doctor"],
            vec!["task", "create", "--id", "x", "c"],
            vec!["task", "list"],
            vec!["task", "claim", "--id", "x", "--worker", "w"],
            vec!["task", "complete", "--id", "x", "--worker", "w"],
            vec!["task", "cancel", "--id", "x"],
            vec!["capability", "run", "--capability", "x", "--params", "{}"],
        ];
        assert_eq!(
            invocations.len(),
            doctor().commands.len(),
            "the invocation list and the advertised list must be the same length"
        );
        for (args, advertised) in invocations.iter().zip(doctor().commands.iter()) {
            assert!(
                parse(args.clone()).is_ok(),
                "`orxnuctl {}` is advertised as `{advertised}` but does not parse",
                args.join(" ")
            );
        }
    }

    // ------------------------------------------------------------ task parsing

    #[test]
    fn every_task_verb_parses_into_its_command() {
        assert_eq!(
            parse(["task", "list"]).expect("parses").command,
            Command::Task(TaskCommand::List)
        );
        assert_eq!(
            parse(["task", "create", "--id", "t1", "buy", "milk"])
                .expect("parses")
                .command,
            Command::Task(TaskCommand::Create {
                id: "t1".to_owned(),
                kind: None,
                content: Some("buy milk".to_owned()),
                max_steps: None,
            }),
            "bare words join into the content"
        );
        assert_eq!(
            parse(["task", "create", "--id", "t1", "--kind", "workflow", "ship"])
                .expect("parses")
                .command,
            Command::Task(TaskCommand::Create {
                id: "t1".to_owned(),
                kind: Some("workflow".to_owned()),
                content: Some("ship".to_owned()),
                max_steps: None,
            })
        );
        assert_eq!(
            parse(["task", "claim", "--id", "t1", "--worker", "w1"])
                .expect("parses")
                .command,
            Command::Task(TaskCommand::Claim {
                id: "t1".to_owned(),
                worker: "w1".to_owned(),
            })
        );
        assert_eq!(
            parse(["task", "complete", "--id", "t1", "--worker", "w1"])
                .expect("parses")
                .command,
            Command::Task(TaskCommand::Complete {
                id: "t1".to_owned(),
                worker: "w1".to_owned(),
            })
        );
        assert_eq!(
            parse(["task", "cancel", "--id", "t1"])
                .expect("parses")
                .command,
            Command::Task(TaskCommand::Cancel {
                id: "t1".to_owned(),
            }),
            "cancel takes no worker: the engine does not want one"
        );
    }

    #[test]
    fn cancel_does_not_accept_a_worker() {
        // The asymmetry with `complete` is deliberate. Cancellation decides about the
        // task and clears its lease; completion reports from a lease holder and is
        // fenced by it. Accepting a worker here would suggest cancel is fenced too.
        let err =
            parse(["task", "cancel", "--id", "t1", "--worker", "w"]).expect_err("must refuse");
        assert!(
            matches!(&err, CliError::UnknownFlag { flag, .. } if flag == "--worker"),
            "{err:?}"
        );
    }

    #[test]
    fn flags_accept_both_spellings() {
        // People type both; refusing one is a shell-quoting mistake, not a rule.
        let spellings: [&[&str]; 2] = [
            &["task", "claim", "--id", "t1", "--worker", "w1"],
            &["task", "claim", "--id=t1", "--worker=w1"],
        ];
        for args in spellings {
            assert_eq!(
                parse(args).expect("parses").command,
                Command::Task(TaskCommand::Claim {
                    id: "t1".to_owned(),
                    worker: "w1".to_owned(),
                }),
                "{args:?}"
            );
        }
    }

    #[test]
    fn a_missing_required_flag_is_refused_by_name() {
        for (args, flag) in [
            (["task", "create"].as_slice(), "--id"),
            (["task", "claim", "--id", "t"].as_slice(), "--worker"),
            (["task", "claim", "--worker", "w"].as_slice(), "--id"),
            (["task", "complete", "--id", "t"].as_slice(), "--worker"),
            (["task", "cancel"].as_slice(), "--id"),
        ] {
            let err = parse(args.to_vec()).expect_err("must refuse");
            assert!(
                matches!(&err, CliError::MissingFlag { flag: f, .. } if *f == flag),
                "{args:?} should need {flag}, got {err:?}"
            );
        }
    }

    #[test]
    fn a_flag_with_no_value_is_refused_rather_than_swallowed() {
        let err = parse(["task", "create", "--id"]).expect_err("must refuse");
        assert!(
            matches!(err, CliError::MissingValue { flag: "--id" }),
            "{err:?}"
        );
    }

    #[test]
    fn an_unexpected_flag_is_refused_rather_than_ignored() {
        // The behaviour a derive-based parser would get wrong: `--id` and `--ids` are
        // not the same flag, and a typo must not become a silent default.
        let err = parse(["task", "list", "--json"]).expect_err("must refuse");
        assert!(
            matches!(&err, CliError::UnknownFlag { flag, .. } if flag == "--json"),
            "{err:?}"
        );
        let err = parse(["task", "create", "--id", "t1", "--ids", "t2"]).expect_err("must refuse");
        assert!(
            matches!(&err, CliError::UnknownFlag { flag, .. } if flag == "--ids"),
            "{err:?}"
        );
    }

    #[test]
    fn a_repeated_flag_is_refused_rather_than_last_one_wins() {
        let err = parse(["task", "claim", "--id", "a", "--id", "b", "--worker", "w"])
            .expect_err("must refuse");
        assert!(
            matches!(err, CliError::RepeatedFlag { flag: "--id" }),
            "{err:?}"
        );
    }

    #[test]
    fn an_unknown_task_verb_lists_the_ones_that_exist() {
        let err = parse(["task", "teleport"]).expect_err("must refuse");
        assert!(
            matches!(&err, CliError::UnknownTaskCommand(v) if v == "teleport"),
            "{err:?}"
        );
        let rendered = err.to_string();
        for expected in ["create", "list", "claim", "complete", "cancel"] {
            assert!(
                rendered.contains(expected),
                "the refusal must say what exists: {rendered}"
            );
        }
    }

    #[test]
    fn task_with_no_verb_is_refused() {
        assert!(parse(["task"]).is_err());
    }

    #[test]
    fn a_verb_does_not_borrow_another_verbs_flags() {
        // `--kind` is create's; claim must not silently accept it.
        let err = parse([
            "task", "claim", "--id", "t", "--worker", "w", "--kind", "query",
        ])
        .expect_err("must refuse");
        assert!(
            matches!(&err, CliError::UnknownFlag { flag, .. } if flag == "--kind"),
            "{err:?}"
        );
    }

    #[test]
    fn the_endpoint_override_is_lifted_out_of_every_verb() {
        // Including `list`, which takes no other flags: without the exemption the
        // override would read as an unknown flag there and nowhere else.
        for args in [
            ["task", "list", "--endpoint", "/tmp/x.sock"].as_slice(),
            ["task", "create", "--id", "t", "--endpoint", "/tmp/x.sock"].as_slice(),
            [
                "task",
                "claim",
                "--id",
                "t",
                "--worker",
                "w",
                "--endpoint",
                "/tmp/x.sock",
            ]
            .as_slice(),
        ] {
            let got = parse(args.to_vec()).expect("parses").endpoint;
            assert_eq!(
                got.as_deref(),
                Some(std::path::Path::new("/tmp/x.sock")),
                "{args:?}"
            );
        }
        assert_eq!(parse(["task", "list"]).expect("parses").endpoint, None);
    }

    #[test]
    fn the_endpoint_override_works_before_the_verb_too() {
        // Both spellings are ones a user types. Before this was hoisted, the
        // flag-first form produced "unknown task command \"--endpoint\"", which is a
        // baffling answer to a reasonable command line.
        let cases: [&[&str]; 4] = [
            &["task", "--endpoint", "/tmp/x.sock", "list"],
            &["task", "--endpoint=/tmp/x.sock", "list"],
            &[
                "task",
                "--endpoint",
                "/tmp/x.sock",
                "create",
                "--id",
                "t",
                "c",
            ],
            &[
                "task",
                "--endpoint=/tmp/x.sock",
                "claim",
                "--id",
                "t",
                "--worker",
                "w",
            ],
        ];
        for args in cases {
            let got = parse(args.to_vec())
                .unwrap_or_else(|e| panic!("{args:?} should parse: {e:?}"))
                .endpoint;
            assert_eq!(
                got.as_deref(),
                Some(std::path::Path::new("/tmp/x.sock")),
                "{args:?}"
            );
        }
    }

    #[test]
    fn a_repeated_or_valueless_endpoint_is_refused() {
        let err = parse(["task", "--endpoint", "/a", "--endpoint", "/b", "list"])
            .expect_err("must refuse");
        assert!(
            matches!(err, CliError::RepeatedFlag { flag: "--endpoint" }),
            "{err:?}"
        );
        let err = parse(["task", "list", "--endpoint"]).expect_err("must refuse");
        assert!(
            matches!(err, CliError::MissingValue { flag: "--endpoint" }),
            "{err:?}"
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
