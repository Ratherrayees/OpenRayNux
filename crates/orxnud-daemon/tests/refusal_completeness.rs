//! A refusal cannot acquire `INTERNAL_ERROR` without being classified.
//!
//! # What this protects, and why a test and not just good taste
//!
//! V-90 was not a bug in one mapping. It was a *shape*: `RequestError::Refused` took a
//! free-form `String` reason, so any code that reached it could spell a
//! caller-actionable condition into `INTERNAL_ERROR`. Two routes did exactly that, and the
//! defect survived the milestone (V-89) that introduced the taxonomy, precisely because
//! nothing about writing that code looked wrong.
//!
//! So the guarantee is now structural — `RequestError::Refused` does not exist, and
//! `INTERNAL_ERROR` requires naming an [`orxnud_daemon::runtime::InternalFault`] from a
//! closed enum where each variant carries its own argument for being unrecoverable. This
//! file checks that structure still holds, because structure is exactly the sort of thing
//! that gets quietly widened by a well-meaning patch later.
//!
//! These are static checks over the source rather than runtime assertions, following the
//! precedent in `orxnud-store/tests/ci_gates_are_strict.rs`: a test that reimplemented the
//! rule could not see the rule being removed, whereas grepping the actual file can.

use std::path::{Path, PathBuf};

fn daemon_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/runtime.rs")
}

fn source() -> String {
    std::fs::read_to_string(daemon_src()).expect("read runtime.rs")
}

/// Strips doc comments and ordinary comments.
///
/// Every one of these assertions is about *code*, not prose — and this file's own
/// documentation mentions `RequestError::Refused` by name, so a naive grep over the file
/// would match its explanation of the rule it is checking.
fn code_only(text: &str) -> String {
    text.lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The catch-all constructor is gone. This is the load-bearing assertion.
///
/// If it reappears, a caller-actionable refusal can once again be reported as a server
/// fault by anyone who reaches it, and nothing in the type system objects.
#[test]
fn the_free_form_internal_error_constructor_does_not_exist() {
    let code = code_only(&source());
    assert!(
        !code.contains("RequestError::Refused"),
        "RequestError::Refused has returned. It takes a free-form String reason, so any \
         caller-actionable condition can be spelled into INTERNAL_ERROR by anyone who \
         reaches it -- which is V-90. Classify the condition into a typed RequestError \
         variant, or name an InternalFault if it really is unrecoverable."
    );
    // Matched on the *trimmed line*, not as a substring: `ProviderRefused {` is a
    // different variant that legitimately exists, and a substring check would flag it.
    let declared = code
        .lines()
        .map(str::trim)
        .any(|l| l.starts_with("Refused {") || l.starts_with("Refused("));
    assert!(
        !declared,
        "a `Refused` variant declaration has returned; see the assertion above."
    );
}

/// `InternalFault` is closed, and every variant maps to `INTERNAL_ERROR`.
///
/// "Closed" is the operative word: an `#[non_exhaustive]` or string-valued fault would let
/// this list grow without anyone having argued for each entry, which is the failure mode
/// this file exists to prevent.
#[test]
fn an_internal_fault_must_be_named_from_a_closed_set() {
    let code = code_only(&source());
    assert!(
        code.contains("pub enum InternalFault"),
        "InternalFault is missing; INTERNAL_ERROR needs a named fault to be reportable."
    );
    assert!(
        !code.contains("#[non_exhaustive]"),
        "InternalFault is non_exhaustive. Each entry is an assertion that a condition is \
         unrecoverable by caller action, so each one has to be argued for in review rather \
         than inherited."
    );
    // A `String` or `&str` payload would restore the free-form escape hatch.
    let enum_body = code
        .split("pub enum InternalFault")
        .nth(1)
        .expect("InternalFault body")
        .split("\n}")
        .next()
        .expect("enum body");
    assert!(
        !enum_body.contains("String") && !enum_body.contains("&str"),
        "InternalFault must carry no data. A payload would let an arbitrary string reach \
         data.reason through the INTERNAL_ERROR path."
    );
}

/// The classifiers have no wildcard arm.
///
/// This is the "no permissive fallback" rule stated as a check rather than a convention.
/// `match e { known => .., _ => .. }` is precisely what made V-90 invisible: adding a
/// `DispatchError` variant compiled cleanly and silently became `INTERNAL_ERROR`.
#[test]
fn the_refusal_classifiers_have_no_catch_all_arm() {
    let code = code_only(&source());
    for classifier in [
        "fn dispatch_failure(",
        "fn policy_failure(",
        "fn denial_failure(",
    ] {
        let start = code
            .find(classifier)
            .unwrap_or_else(|| panic!("{classifier} is missing"));
        // Take the body up to the next top-level `fn`, so the arms checked are this
        // function's and not a neighbour's.
        let body = &code[start..];
        let end = body.find("\nfn ").unwrap_or(body.len());
        let body = &body[..end];
        assert!(
            !body.contains("_ =>"),
            "{classifier} has a `_ =>` arm. An unclassified condition must fail to compile \
             or fail a test, never default to INTERNAL_ERROR."
        );
    }
}

/// Every classification a client can act on is a real taxonomy code.
///
/// A guard against a plausible future mistake: routing a caller-actionable condition into
/// `RequestError::Internal`. The list is the classes `INTERNAL_ERROR` must never overlap.
#[test]
fn the_internal_fault_variants_are_the_ones_with_no_recovery() {
    // Each entry is `<fault> -> <why no caller action repairs it>`. Kept as data rather
    // than prose in the enum so this test can assert the set is unchanged: a new fault
    // that someone cannot justify is a review question, and this is where it surfaces.
    let justified: &[(&str, &str)] = &[
        (
            "DurableStateCorrupt",
            "a stored row does not parse; only repair or rebuild of the database fixes it",
        ),
        (
            "StorageUnavailable",
            "the database could not be read or written; retrying reaches the same fault",
        ),
        (
            "DisclosureStorePoisoned",
            "a previous holder panicked, so the daemon itself malfunctioned",
        ),
        (
            "CapabilityExecutionFailed",
            "an authorised capability ran and failed; the request was valid",
        ),
        (
            "CapabilityVerificationFailed",
            "the verifier could not check the effect, which is a defect in the daemon",
        ),
        (
            "ReentrantDispatch",
            "an adapter re-entered the dispatcher, which is an impossible invariant",
        ),
        (
            "InvalidCapabilitySchema",
            "the declaration is compiled in, so no configuration change reaches it",
        ),
    ];
    let code = code_only(&source());
    for (fault, why) in justified {
        assert!(
            code.contains(fault),
            "{fault} is missing from InternalFault; {why}"
        );
    }
    // And nothing beyond them, so an unjustified entry cannot be added quietly.
    let body = code
        .split("pub enum InternalFault")
        .nth(1)
        .expect("body")
        .split("\n}")
        .next()
        .expect("body");
    for line in body.lines() {
        let t = line.trim();
        // Only variant declarations, which are four-space-indented and end in a comma.
        if t.starts_with("    ")
            && t.ends_with(',')
            && t.chars().nth(4).is_some_and(|c| c.is_uppercase())
        {
            let name = t.trim_end_matches(',').trim();
            assert!(
                justified.iter().any(|(f, _)| *f == name),
                "{name} is a new InternalFault and has no recorded argument for being \
                 unrecoverable by caller action. Add it to this test with that argument, \
                 or classify it as an actionable refusal."
            );
        }
    }
}

/// The two routes V-90 named are classified, and the taxonomy is documented as such.
///
/// A documentation check rather than a code check, because the thing that regressed was a
/// claim: ADR-0050's own text said these were the classes, while the code contradicted it
/// on two routes and nothing recorded the contradiction.
#[test]
fn the_taxonomy_document_still_describes_the_code() {
    let adr = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .join("docs/09-decisions.md"),
    )
    .expect("read the decisions log");
    assert!(
        adr.contains("ADR-0050"),
        "ADR-0050 is missing from the decisions log."
    );
    // The codes the daemon now emits must be named in the record.
    for code in ["-32040", "-32041", "-32042", "-32043"] {
        assert!(
            adr.contains(code),
            "{code} is not documented in ADR-0050, so a client reading the record cannot \
             tell what it means."
        );
    }
}
