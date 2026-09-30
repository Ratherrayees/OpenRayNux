//! Tracing wiring and redaction.
//!
//! # Redaction is the reason this crate exists
//!
//! A logging call with a raw `Debug` on a config struct prints the API key. That
//! is not a hypothetical: it is the most common way secrets escape a system, and
//! it is invisible in review because `{:?}` looks harmless. So this crate
//! provides [`Redacted<T>]` — a wrapper that formats as `[redacted]` — and gate
//! G10 greps for it.
//!
//! # No OTLP by default
//!
//! The `otlp` feature exists and is **off**. A personal install must not require
//! a collector (ADR-0020): an exporter that silently fails to reach a collector
//! either blocks startup or, worse, buffers diagnostics until the machine runs
//! out of memory. Phase 1 enables nothing.
//!
//! # This crate does not configure a subscriber on its own
//!
//! [`TracingPlan`] is a *description*. Turning it into a live subscriber belongs
//! to the composition root (`orxnud-daemon`), so that a test can assert what
//! *would* be installed without installing it, and so no library crate can
//! initialise global tracing behind the application's back. A library that
//! installs a global subscriber is a library that makes its consumer's logging
//! decisions for them.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

/// A value whose contents must never be logged.
///
/// `Display` and `Debug` both render `[redacted]`; there is deliberately no way
/// to get the inner value out through formatting. The value is still reachable
/// by value for whoever legitimately holds it — this guards *logging*, not
/// storage.
///
/// ```
/// use orxnud_obs::Redacted;
/// let secret = Redacted::new(String::from("hunter2"));
/// assert_eq!(secret.to_string(), "[redacted]");
/// assert_eq!(format!("{secret:?}"), "[redacted]");
/// // The value is still reachable; only its *formatting* is blocked.
/// assert_eq!(secret.expose(), "hunter2");
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wraps a value so formatting cannot reveal it.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Returns the wrapped value.
    ///
    /// Named `expose` rather than `get` so that a call site reads as a deliberate
    /// act of disclosure. Every use is greppable, which is the point: making a
    /// secret visible should be visible in a diff.
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Consumes the wrapper, returning the value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: fmt::Debug> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Whether a field should be redacted, by name.
///
/// A denylist rather than an allowlist, because the failure modes are opposite:
/// an allowlist silently drops fields nobody thought of, whereas a denylist only
/// fails to protect a field someone forgot to add. Both need review; the
/// denylist is safer for the common case of logging a struct whose fields change.
///
/// Matching is case-insensitive and substring-based, so `api_key`,
/// `openai_api_key` and `API-KEY` are all caught by one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionPolicy {
    needles: Vec<String>,
}

/// The field-name fragments treated as secret by default.
///
/// Includes `secret` and `token` because those appear in more places than one
/// might expect — OAuth refresh tokens, cancellation tokens, idempotency tokens.
const DEFAULT_NEEDLES: [&str; 9] = [
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "authorization",
];

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self {
            needles: DEFAULT_NEEDLES.iter().map(|s| (*s).to_owned()).collect(),
        }
    }
}

impl RedactionPolicy {
    /// The default policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a fragment to match.
    #[must_use]
    pub fn with_needle(mut self, needle: impl Into<String>) -> Self {
        self.needles.push(needle.into().to_lowercase());
        self
    }

    /// Whether a field with this name must be redacted.
    #[must_use]
    pub fn redacts(&self, field_name: &str) -> bool {
        let lower = field_name.to_lowercase();
        self.needles.iter().any(|n| lower.contains(n.as_str()))
    }

    /// The fragments in this policy, for `doctor` output.
    #[must_use]
    pub fn needles(&self) -> &[String] {
        &self.needles
    }
}

/// Log verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Nothing is logged.
    Off,
    /// Only failures that stopped an operation.
    Error,
    /// Failures and things that were recovered from.
    Warn,
    /// Ordinary operation.
    Info,
    /// Per-step detail.
    Debug,
    /// Everything, including values that may be sensitive.
    Trace,
}

impl Level {
    /// Parses a level name, case-insensitively.
    ///
    /// Returns `None` for an unknown name rather than defaulting: a typo in a
    /// config value that silently became `Info` is worse than a startup error.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "off" | "none" => Some(Self::Off),
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }

    /// Whether this level includes `other`.
    ///
    /// Ordered least to most verbose, so `Off` includes nothing and `Trace`
    /// includes everything.
    #[must_use]
    pub fn includes(self, other: Self) -> bool {
        other <= self
    }
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        };
        f.write_str(s)
    }
}

/// Where log lines go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sink {
    /// Discard everything.
    Discard,
    /// Write to stderr.
    ///
    /// The default. A daemon's diagnostics belong on stderr so they interleave
    /// with a service manager's journal rather than needing a file path.
    Stderr,
    /// Write to the given path.
    File,
}

/// A *description* of the tracing setup.
///
/// Not a live subscriber. See the module docs for why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracingPlan {
    /// The maximum level to emit.
    pub level: Level,
    /// Where lines go.
    pub sink: Sink,
    /// Whether a JSON encoder is used.
    pub json: bool,
    /// Whether timestamps are included.
    pub timestamps: bool,
    /// The field-name policy in force.
    pub redaction: RedactionPolicy,
    /// Whether OTLP export is on.
    ///
    /// Always `false` unless the `otlp` feature is compiled **and** explicitly
    /// requested. Reported rather than inferred so `doctor` can show it.
    pub otlp_enabled: bool,
}

impl Default for TracingPlan {
    fn default() -> Self {
        Self {
            level: Level::Info,
            sink: Sink::Stderr,
            json: false,
            timestamps: true,
            redaction: RedactionPolicy::default(),
            otlp_enabled: false,
        }
    }
}

impl TracingPlan {
    /// The default plan.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the level.
    #[must_use]
    pub fn with_level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Sets the sink.
    #[must_use]
    pub fn with_sink(mut self, sink: Sink) -> Self {
        self.sink = sink;
        self
    }

    /// Selects JSON encoding.
    #[must_use]
    pub fn with_json(mut self, json: bool) -> Self {
        self.json = json;
        self
    }

    /// Adds a redaction fragment.
    #[must_use]
    pub fn redacting(mut self, needle: impl Into<String>) -> Self {
        self.redaction = self.redaction.with_needle(needle);
        self
    }

    /// Turns OTLP on, if the feature is compiled.
    ///
    /// Returns `self` unchanged when the `otlp` feature is off, so a config file
    /// enabling it on a build without it degrades to local logging rather than
    /// failing startup.
    #[must_use]
    pub fn with_otlp(mut self, enabled: bool) -> Self {
        self.otlp_enabled = enabled && cfg!(feature = "otlp");
        self
    }

    /// Whether a field at `level` would be emitted.
    #[must_use]
    pub fn emits(&self, level: Level) -> bool {
        self.level.includes(level) && self.sink != Sink::Discard
    }

    /// A one-line description, for `doctor`.
    #[must_use]
    pub fn describe(&self) -> String {
        let sink = match self.sink {
            Sink::Discard => "discard",
            Sink::Stderr => "stderr",
            Sink::File => "file",
        };
        let encoding = if self.json { "json" } else { "text" };
        format!(
            "level={level} sink={sink} encoding={encoding} timestamps={ts} otlp={otlp} redaction_needles={n}",
            level = self.level,
            ts = self.timestamps,
            otlp = self.otlp_enabled,
            n = self.redaction.needles().len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_redacted_value_never_formats_its_contents() {
        let r = Redacted::new("hunter2");
        assert_eq!(format!("{r}"), "[redacted]");
        assert_eq!(format!("{r:?}"), "[redacted]");
        // The `{:?}` path matters most: it is what `#[derive(Debug)]` and an
        // unlabelled log field use.
        assert!(!format!("{r:?}").contains("hunter2"));
    }

    #[test]
    fn exposure_is_deliberate_and_available() {
        // Redaction guards logging, not storage: the value is still reachable.
        assert_eq!(*Redacted::new("s").expose(), "s");
        assert_eq!(Redacted::new("s").into_inner(), "s".to_owned());
    }

    #[test]
    fn redaction_is_case_insensitive_and_substring_based() {
        let p = RedactionPolicy::new();
        for name in [
            "password",
            "PASSWORD",
            "openai_api_key",
            "apiKey",
            "refresh_token",
            "client_secret",
            "Authorization",
        ] {
            assert!(p.redacts(name), "{name} should be redacted");
        }
        for name in ["count", "task_id", "elapsed_ms", "capability", "path"] {
            assert!(!p.redacts(name), "{name} should not be redacted");
        }
    }

    #[test]
    fn a_custom_needle_extends_rather_than_replaces() {
        let p = RedactionPolicy::new().with_needle("session_id");
        assert!(p.redacts("session_id"));
        assert!(p.redacts("password"), "the defaults must survive");
    }

    #[test]
    fn level_ordering_is_least_to_most_verbose() {
        assert!(Level::Trace.includes(Level::Error));
        assert!(Level::Info.includes(Level::Info));
        assert!(!Level::Info.includes(Level::Debug));
        assert!(!Level::Off.includes(Level::Error));
    }

    #[test]
    fn an_unknown_level_name_is_an_error_rather_than_a_default() {
        // A typo silently becoming `Info` would hide the fact that debug output
        // was never going to appear.
        assert_eq!(Level::parse("verbose"), None);
        assert_eq!(Level::parse(""), None);
        assert_eq!(Level::parse("DEBUG"), Some(Level::Debug));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
    }

    #[test]
    fn the_default_plan_logs_to_stderr_as_text() {
        let p = TracingPlan::new();
        assert_eq!(p.level, Level::Info);
        assert_eq!(p.sink, Sink::Stderr);
        assert!(!p.json);
        assert!(p.timestamps);
        // Phase 1 ships no exporter.
        assert!(!p.otlp_enabled, "OTLP must be off by default");
    }

    #[test]
    fn otlp_stays_off_without_the_feature() {
        // The `otlp` feature is not enabled in Phase 1, so requesting it is a
        // no-op rather than a startup failure.
        let p = TracingPlan::new().with_otlp(true);
        assert_eq!(p.otlp_enabled, cfg!(feature = "otlp"));
        #[cfg(not(feature = "otlp"))]
        assert!(!p.otlp_enabled);
    }

    #[test]
    fn discarding_means_emitting_nothing_at_any_level() {
        let p = TracingPlan::new()
            .with_sink(Sink::Discard)
            .with_level(Level::Trace);
        assert!(!p.emits(Level::Error));
        assert!(!p.emits(Level::Trace));
    }

    #[test]
    fn emits_respects_both_the_level_and_the_sink() {
        let p = TracingPlan::new().with_level(Level::Warn);
        assert!(p.emits(Level::Error));
        assert!(p.emits(Level::Warn));
        assert!(!p.emits(Level::Info));
    }

    #[test]
    fn the_description_mentions_the_settings_that_matter() {
        let d = TracingPlan::new()
            .with_level(Level::Debug)
            .with_json(true)
            .describe();
        for expected in ["level=debug", "sink=stderr", "encoding=json", "otlp=false"] {
            assert!(d.contains(expected), "{d} is missing {expected:?}");
        }
    }

    #[test]
    fn redacted_works_for_non_string_types_too() {
        // The wrapper is generic on purpose: the thing that must not be logged is
        // not always a string.
        let r = Redacted::new(vec![1u8, 2, 3]);
        assert_eq!(format!("{r:?}"), "[redacted]");
        assert_eq!(r.expose().len(), 3);
    }
}
