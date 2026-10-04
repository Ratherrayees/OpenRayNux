//! Storing and removing the provider's API credential.
//!
//! # Why this exists
//!
//! The provider adapter has read `SecretRef(provider-api-key, local)` through
//! [`SecretsContract`] since the day it was written, and there was no supported way for a
//! person to put a value there. V-78: the feature was complete and unreachable.
//!
//! # Why the value never appears in an argument
//!
//! `orxnuctl provider credential set --api-key …` would put the key in `ps` output, in the
//! shell history, and in the transcript of any screen share. So the value is read from
//! **stdin**, and the command takes no flag that could carry one. The set of flags is
//! checked rather than documented: a future `--api-key` would be a regression someone
//! could add without reading this, so [`parse`] refuses any argument it does not know and
//! the test suite asserts the absence.
//!
//! # Why nothing echoes
//!
//! There is no confirmation message containing the value, no length, no prefix and no
//! fingerprint. "Stored" is the whole report. A prefix is the reflex — it helps a person
//! recognise which key they stored — and it is also four characters of a credential in
//! every terminal scrollback and CI log, so it is not offered.
//!
//! # What is never written
//!
//! Not to SQLite, not to a config file, not to a task row, not to the audit record. The
//! platform credential store is the only destination, and it is reached through the same
//! [`SecretsContract::set`] the rest of the product uses. There is no second store here.

use std::io::Read as _;

use orxnud_domain::platform::{SecretRef, SecretsContract};
use zeroize::Zeroizing;

/// The one reference the provider reads.
///
/// Named here as well as in `http_provider` because the *name* is part of the contract
/// between this command and that adapter, and a change to one that missed the other would
/// leave a user with a stored key nothing reads.
#[must_use]
pub fn provider_key_ref() -> SecretRef {
    SecretRef::new("provider-api-key", "local")
}

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialCommand {
    /// Store a value read from stdin.
    Set,
    /// Remove the stored value.
    Delete,
    /// Report whether a value is stored, without revealing it.
    Status,
}

/// # Errors
///
/// A message for the user. Never contains the value, and never echoes stdin.
pub fn parse(args: &[String]) -> Result<CredentialCommand, String> {
    // Every refusal that carries an extra word says the same thing, whatever that word was.
    // A caller who typed `set sk-live-…` and one who typed `set --api-key sk-live-…` are
    // making the same mistake, and both must be told where the value belongs instead.
    let extra = || {
        "unexpected argument; the credential is read from stdin, never from an argument, \
         because an argument is visible in `ps` output and shell history"
    };
    let [verb, rest @ ..] = args else {
        return Err("expected one of: set, delete, status".to_owned());
    };
    if !rest.is_empty() {
        return Err(extra().to_owned());
    }
    match verb.as_str() {
        "set" => Ok(CredentialCommand::Set),
        "delete" => Ok(CredentialCommand::Delete),
        "status" => Ok(CredentialCommand::Status),
        other => Err(format!(
            "unknown provider credential command {other:?}; expected one of: set, delete, \
             status"
        )),
    }
}

/// Reads a credential from stdin.
///
/// Trimmed of the trailing newline a terminal and a pipe both add, and nothing else: no
/// case folding, no separator stripping, no "helpful" normalisation of a key that might have
/// different whitespace in it. An empty result is refused rather than stored, because an
/// empty credential that exists is worse than one that does not — the provider would send
/// `Bearer ` and the failure would look like a rejected key rather than a missing one.
///
/// # Errors
///
/// A message for the user. Never contains the value.
pub fn read_from_stdin() -> Result<Zeroizing<String>, String> {
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| format!("could not read the credential from stdin: {e}"))?;
    let value = buffer.trim();
    if value.is_empty() {
        return Err("the credential read from stdin was empty".to_owned());
    }
    if value.len() > MAX_CREDENTIAL_BYTES {
        return Err(format!(
            "the credential is {} bytes, over the {MAX_CREDENTIAL_BYTES}-byte limit",
            value.len()
        ));
    }
    if value.chars().any(char::is_control) {
        return Err("the credential contains a control character".to_owned());
    }
    Ok(Zeroizing::new(value.to_owned()))
}

/// A ceiling on a stored credential, so a paste accident cannot fill a keyring entry.
pub const MAX_CREDENTIAL_BYTES: usize = 4096;

/// Renders a secret-store error without letting it quote the value it failed on.
///
/// A store that fails while including the credential in its message must not launder it
/// into a terminal, a log or a CI transcript through us. Redacting the whole message is
/// the blunt version and is right here: a user whose platform store is broken needs a
/// working keyring, not a precise diagnosis of it.
fn redact_store_error(error: &dyn std::fmt::Display) -> String {
    let rendered = error.to_string();
    let lower = rendered.to_ascii_lowercase();
    if ["bearer", "sk-", "api_key", "apikey", "token=", "password"]
        .iter()
        .any(|needle| lower.contains(needle))
    {
        "<redacted: the store's own error may have contained the credential>".to_owned()
    } else {
        rendered
    }
}

/// Runs the command.
///
/// # Errors
///
/// A message safe to print. It never contains the credential, in whole or in part.
pub fn run<S: SecretsContract>(command: &CredentialCommand, secrets: &S) -> Result<String, String> {
    let reference = provider_key_ref();
    match command {
        CredentialCommand::Set => {
            let value = read_from_stdin()?;
            secrets.set(&reference, &value).map_err(|e| {
                format!(
                    "the credential store refused to save it: {}",
                    redact_store_error(&e)
                )
            })?;
            // The value is dropped (and zeroed) here. Nothing above this line returns it.
            Ok("stored".to_owned())
        }
        CredentialCommand::Delete => match secrets.delete(&reference) {
            Ok(()) => Ok("removed".to_owned()),
            Err(e) => Err(format!(
                "the credential store refused to remove it: {}",
                redact_store_error(&e)
            )),
        },
        CredentialCommand::Status => {
            use orxnud_domain::platform::SecretLookup;
            match secrets.get(&reference) {
                Ok(SecretLookup::Found(_)) => Ok("present".to_owned()),
                Ok(SecretLookup::Absent) => Ok("absent".to_owned()),
                Ok(SecretLookup::Unavailable(_)) => {
                    Ok("unavailable: this host has no usable credential store".to_owned())
                }
                Err(e) => Err(format!(
                    "the credential store could not be read: {}",
                    redact_store_error(&e)
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_three_subcommands_parse() {
        assert_eq!(parse(&args(&["set"])).expect("set"), CredentialCommand::Set);
        assert_eq!(
            parse(&args(&["delete"])).expect("delete"),
            CredentialCommand::Delete
        );
        assert_eq!(
            parse(&args(&["status"])).expect("status"),
            CredentialCommand::Status
        );
    }

    /// The load-bearing test of this module: there is no spelling of this command that
    /// takes a credential as an argument.
    #[test]
    fn no_spelling_of_the_command_accepts_a_credential_as_an_argument() {
        for attempt in [
            vec!["set", "--api-key", "sk-live-x"],
            vec!["set", "sk-live-x"],
            vec!["set", "--key=sk-live-x"],
            vec!["--api-key", "sk-live-x", "set"],
            vec!["set", "--api-key-file", "/tmp/x"],
        ] {
            let err = parse(&args(&attempt)).expect_err("must refuse");
            assert!(
                !err.contains("sk-live"),
                "the refusal quoted the value: {err}"
            );
            assert!(
                err.contains("stdin"),
                "the refusal must say where the value does belong: {err}"
            );
        }
    }

    #[test]
    fn an_unknown_subcommand_is_refused() {
        assert!(parse(&args(&["list"])).is_err());
        assert!(parse(&[]).is_err());
    }

    /// The reference is part of the contract with the adapter; a silent divergence would
    /// leave a stored credential nothing reads.
    #[test]
    fn the_reference_matches_what_the_provider_asks_for() {
        let r = provider_key_ref();
        assert_eq!(r.name, "provider-api-key");
        assert_eq!(r.account, "local");
    }

    #[test]
    fn the_limit_is_generous_but_finite() {
        const { assert!(MAX_CREDENTIAL_BYTES >= 64) };
        const { assert!(MAX_CREDENTIAL_BYTES <= 64 * 1024) };
    }
}
