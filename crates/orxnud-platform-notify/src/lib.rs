//! Desktop notification adapter.
//!
//! # Phase 1 delivers nothing, deliberately
//!
//! There is no interface in Phase 1 (docs-13 §8), so there is no notification to
//! deliver and no user who has asked for one. [`NullNotifier`] is the honest
//! implementation: it reports that no transport exists and refuses to pretend
//! otherwise.
//!
//! The refusal is the useful part. A notifier that silently succeeds teaches
//! every caller that "the user was told" is a thing that happens, and the caller
//! stops checking. Then a real notifier is added, it fails for a reason nobody
//! expected, and the caller has been treating silence as consent.
//!
//! # Why the title and body are validated
//!
//! A desktop notification is the most leak-prone output the system has: it
//! appears on a screen anyone can see, it lands in a notification history that
//! outlives the app, and on some platforms it is mirrored to a server. So the
//! *title* must be non-empty — a notification with no title is unreadable — and
//! both fields are length-bounded, because a caller streaming a log line into a
//! title produces something no user can act on.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use orxnud_domain::platform::{NotificationRequest, NotifyContract};

/// A notification-delivery failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotifyError {
    /// No transport exists on this host.
    ///
    /// The Phase 1 answer, and a legitimate one. Distinct from a transport that
    /// exists and failed, because "we have no notifier" and "the notifier broke"
    /// call for different responses.
    #[error("no notification transport is available on this host")]
    NoTransport,

    /// The notification was rejected before delivery was attempted.
    #[error("invalid notification: {reason}")]
    Invalid {
        /// Why it was rejected.
        reason: String,
    },

    /// The transport exists but delivery failed.
    #[error("notification delivery failed: {0}")]
    DeliveryFailed(String),
}

/// A notifier with no transport.
///
/// Reports availability as `false` and refuses to deliver. See the module docs
/// for why the refusal is the feature.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullNotifier;

impl NullNotifier {
    /// The notifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl NotifyContract for NullNotifier {
    type Error = NotifyError;

    fn deliver(&self, request: &NotificationRequest) -> Result<(), NotifyError> {
        validate(request)?;
        Err(NotifyError::NoTransport)
    }

    fn is_available(&self) -> bool {
        false
    }
}

/// The longest permitted title or body, in characters.
const MAX_TITLE: usize = 200;
const MAX_BODY: usize = 1000;

/// Whether a request is well-formed enough to attempt delivery.
///
/// Checked before the transport is consulted so an invalid notification reports
/// *its* problem rather than "no transport", which would send the caller looking
/// in the wrong place. The body may be empty — a title-only notification is
/// legitimate — but it is still bounded, because an unbounded body is how a log
/// line ends up on someone's screen.
///
/// # Errors
///
/// [`NotifyError::Invalid`] for an empty title, or a title or body above its
/// limit.
pub fn validate(request: &NotificationRequest) -> Result<(), NotifyError> {
    let title = request.title.trim();
    if title.is_empty() {
        return Err(NotifyError::Invalid {
            reason: "the title is empty".into(),
        });
    }
    if title.chars().count() > MAX_TITLE {
        return Err(NotifyError::Invalid {
            reason: format!(
                "the title is {} characters, above the {MAX_TITLE}-character limit",
                title.chars().count()
            ),
        });
    }
    if request.body.chars().count() > MAX_BODY {
        return Err(NotifyError::Invalid {
            reason: format!(
                "the body is {} characters, above the {MAX_BODY}-character limit",
                request.body.chars().count()
            ),
        });
    }
    Ok(())
}

/// A recording notifier, for tests.
///
/// Captures what *would* have been delivered so a test can assert the request
/// shape without a notification daemon. Test-only by intent: it implements the
/// same trait as the real thing, so a caller cannot tell the difference, which is
/// exactly why it must not be reachable from production wiring.
#[derive(Debug, Default)]
pub struct RecordingNotifier {
    // `&self` is what the trait gives, so the record of what was delivered needs
    // interior mutability. `Mutex` rather than `RefCell` because a notifier may be
    // shared across tasks and `RefCell` would not be `Sync`.
    delivered: std::sync::Mutex<Vec<NotificationRequest>>,
    fail_with: Option<String>,
}

impl RecordingNotifier {
    /// A notifier that succeeds and records.
    #[must_use]
    pub fn new() -> Self {
        Self {
            delivered: std::sync::Mutex::new(Vec::new()),
            fail_with: None,
        }
    }

    /// A notifier that always fails, for the failure path.
    #[must_use]
    pub fn failing(reason: impl Into<String>) -> Self {
        Self {
            delivered: std::sync::Mutex::new(Vec::new()),
            fail_with: Some(reason.into()),
        }
    }

    /// What was delivered, in order.
    #[must_use]
    pub fn delivered(&self) -> Vec<NotificationRequest> {
        self.delivered.lock().map_or_else(
            // A poisoned lock means a test panicked while holding it. Returning
            // what is there beats a second panic hiding the first.
            |e| e.into_inner().clone(),
            |g| g.clone(),
        )
    }
}

impl NotifyContract for RecordingNotifier {
    type Error = NotifyError;

    fn deliver(&self, request: &NotificationRequest) -> Result<(), NotifyError> {
        validate(request)?;
        if let Some(reason) = &self.fail_with {
            return Err(NotifyError::DeliveryFailed(reason.clone()));
        }
        match self.delivered.lock() {
            Ok(mut g) => g.push(request.clone()),
            Err(e) => e.into_inner().push(request.clone()),
        }
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }
}

/// Counts delivery attempts.
///
/// Exists so a caller can prove "the user was told once" without keeping the
/// notifications themselves — the notifications may be sensitive enough that
/// retaining them is the thing to avoid.
#[derive(Debug, Default)]
pub struct DeliveryCounter {
    delivered: AtomicU64,
}

impl DeliveryCounter {
    /// A zeroed counter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            delivered: AtomicU64::new(0),
        }
    }

    /// Records one delivery.
    pub fn record(&self) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
    }

    /// How many deliveries were recorded.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.delivered.load(Ordering::Relaxed)
    }
}

/// Notification summaries by capability, for `doctor`.
///
/// A `BTreeMap` so the output is stable, and a *count* per key rather than the
/// bodies: `doctor` should report that two notifications happened, not what they
/// said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryLog {
    counts: BTreeMap<String, u64>,
}

impl DeliveryLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a delivery against a capability.
    pub fn record(&mut self, capability: &str) {
        *self.counts.entry(capability.to_owned()).or_insert(0) += 1;
    }

    /// The count for one capability.
    #[must_use]
    pub fn count_for(&self, capability: &str) -> u64 {
        self.counts.get(capability).copied().unwrap_or(0)
    }

    /// The total across all capabilities.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }

    /// The capabilities seen, in stable order.
    #[must_use]
    pub fn capabilities(&self) -> Vec<&str> {
        self.counts.keys().map(String::as_str).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_domain::platform::Urgency;

    fn request(title: &str) -> NotificationRequest {
        NotificationRequest {
            title: title.to_owned(),
            body: String::new(),
            preferred_channel: None,
            urgency: Urgency::Normal,
        }
    }

    fn request_with_body(title: &str, body: &str) -> NotificationRequest {
        NotificationRequest {
            title: title.to_owned(),
            body: body.to_owned(),
            preferred_channel: None,
            urgency: Urgency::Normal,
        }
    }

    #[test]
    fn phase_one_has_no_transport() {
        let n = NullNotifier::new();
        assert!(!n.is_available());
        assert!(matches!(
            n.deliver(&request("done")),
            Err(NotifyError::NoTransport)
        ));
    }

    #[test]
    fn an_empty_title_is_rejected_before_the_transport_is_consulted() {
        // Otherwise the caller sees "no transport" for what is actually a bug in
        // the caller, and goes looking in the wrong place.
        for title in ["", "   ", "\t\n"] {
            let err = NullNotifier::new()
                .deliver(&request(title))
                .expect_err("must refuse");
            assert!(
                matches!(err, NotifyError::Invalid { .. }),
                "{title:?}: {err}"
            );
        }
    }

    #[test]
    fn an_over_long_title_or_body_is_rejected() {
        // A notification is a line on a screen, not a log file.
        let err = NullNotifier::new()
            .deliver(&request(&"a".repeat(MAX_TITLE + 1)))
            .expect_err("must refuse");
        assert!(matches!(err, NotifyError::Invalid { .. }), "{err}");
        assert!(validate(&request(&"a".repeat(MAX_TITLE))).is_ok());

        let err = NullNotifier::new()
            .deliver(&request_with_body("t", &"b".repeat(MAX_BODY + 1)))
            .expect_err("must refuse");
        assert!(matches!(err, NotifyError::Invalid { .. }), "{err}");
    }

    #[test]
    fn an_empty_body_is_allowed() {
        // A title-only notification is legitimate; only a missing title is not.
        assert!(validate(&request("just a title")).is_ok());
        assert!(validate(&request_with_body("title", "")).is_ok());
    }

    #[test]
    fn validation_is_independent_of_the_transport() {
        // A recording transport must not accept what the null one rejects, or the
        // rules would be a property of the implementation rather than of the
        // request.
        assert!(validate(&request("")).is_err());
        assert!(RecordingNotifier::new().deliver(&request("")).is_err());
    }

    #[test]
    fn a_recording_notifier_captures_deliveries() {
        let n = RecordingNotifier::new();
        assert!(n.is_available());
        assert!(n.deliver(&request("one")).is_ok());
        assert!(n.deliver(&request_with_body("two", "body")).is_ok());
        let delivered = n.delivered();
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0].title, "one");
        assert_eq!(delivered[1].body, "body");
    }

    #[test]
    fn a_failing_notifier_reports_delivery_failure_not_absence() {
        // The two are different problems and a caller must be able to tell them
        // apart.
        let n = RecordingNotifier::failing("dbus went away");
        let err = n.deliver(&request("one")).expect_err("must fail");
        assert_eq!(err, NotifyError::DeliveryFailed("dbus went away".into()));
        assert!(n.delivered().is_empty());
    }

    #[test]
    fn the_counter_tallies_deliveries() {
        let c = DeliveryCounter::new();
        assert_eq!(c.count(), 0);
        c.record();
        c.record();
        assert_eq!(c.count(), 2);
    }

    #[test]
    fn the_log_counts_by_capability_without_retaining_bodies() {
        let mut log = DeliveryLog::new();
        assert_eq!(log.total(), 0);
        log.record("a");
        log.record("a");
        log.record("b");
        assert_eq!(log.count_for("a"), 2);
        assert_eq!(log.count_for("b"), 1);
        assert_eq!(log.count_for("never-seen"), 0);
        assert_eq!(log.total(), 3);
        // Stable order, so `doctor` output is comparable between runs.
        assert_eq!(log.capabilities(), vec!["a", "b"]);
    }
}
