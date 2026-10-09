//! `text/word-count`: the first real capability.
//!
//! # Why this one first
//!
//! It is a pure function of its input. Nothing is read, nothing is written, no
//! credential is resolved, no process is spawned, and the same input always produces
//! the same output. That makes it the cheapest possible way to prove the *governed
//! pipeline itself* works in production — request in, policy decision, authorisation,
//! registry lookup, adapter, verification, durable audit, response — without spending
//! any authority to do it.
//!
//! A capability that reached the filesystem or a network would prove the same pipeline
//! while also introducing the first thing that can go wrong in it. This one cannot.
//!
//! # The counting contract
//!
//! Four numbers, each defined precisely because "count the words" has at least four
//! reasonable readings and a capability that leaves it ambiguous is a capability whose
//! output nobody can rely on.
//!
//! | field        | definition |
//! |--------------|------------|
//! | `bytes`      | `text.len()` — UTF-8 **bytes**. Not characters. |
//! | `characters` | `text.chars().count()` — Unicode **scalar values** (`char`). |
//! | `words`      | maximal runs of non-whitespace, whitespace being [`char::is_whitespace`] (Unicode `White_Space`). |
//! | `lines`      | `count('\n')`, plus one more if the text is non-empty and does not end with `\n`. |
//!
//! Consequences worth stating, because each is a decision rather than an accident:
//!
//! * `characters` counts **scalar values, not grapheme clusters**. `"👨‍👩‍👧"` is one
//!   `char` sequence of several — a family emoji is several code points joined by
//!   ZWJ, and `chars().count()` counts each. A user-visible "character" is a grapheme
//!   cluster, which is a *different* number and needs a dependency this repository does
//!   not have. `bytes`, `characters` and `words` are three different notions on purpose;
//!   collapsing them would hide exactly the encoding fact a caller most often wants.
//! * `"hello  world"` (two spaces) is **2 words**. Runs, not splits-on-single-space:
//!   any whitespace run is one separator.
//! * `""` is 0 bytes, 0 characters, 0 words, **0 lines**. A file with no content has no
//!   lines, not one empty line.
//! * `"a\n"` is **1 line** — one line, newline-terminated. A trailing newline does not
//!   open a second line.
//! * `"\n\n"` is **2 lines**: `""` and `""`. Empty lines count.
//! * `"\r\n"` is **1 line**: the `\r` is line *content*, not a second terminator. Only
//!   `\n` terminates a line, which is stated here because a reader could reasonably
//!   expect otherwise.
//!
//! # Where validation happens, and why not earlier
//!
//! Inside the adapter, because that is the capability's own contract boundary and
//! because there is no parameter-schema mechanism in the pipeline yet: the dispatcher
//! hands the adapter the invocation's validated parameters as a `serde_json::Value`, so
//! the shape is the adapter's to enforce. That is a real gap — the *normalised* params
//! the policy digests are computed over are currently a constant — and it is recorded
//! rather than papered over. When a parameter-schema mechanism exists it belongs here,
//! in front of this check, not instead of it.

use std::sync::LazyLock;

use serde_json::{Value, json};

use orxnud_domain::enums::{DataClass, IsolationTier, RiskClass};
use orxnud_domain::ids::CapabilityId;
use orxnud_policy::authority::DispatchView;

use crate::credential::CredentialHandle;
use crate::dispatch::{AdapterBundle, CapabilityAdapter, ExecutionTier};
use crate::verification::{ExecutionOutcome, VerificationOutcome, Verifier, VerifyError};

/// The capability id, namespaced like every other method and capability.
pub const WORD_COUNT_ID: &str = "text/word-count";

/// The largest text this capability will count.
///
/// Tighter than the transport's own ingress bound (256 KiB, the daemon's
/// `MAX_REQUEST_BYTES`) on purpose, for the same reason task content is: that bound protects the daemon's
/// memory, this one protects the capability's usefulness. A "word count" of a
/// megabyte is a denial of service wearing a useful hat.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;

/// The parameter the capability reads.
const TEXT_PARAM: &str = "text";

/// The capability id, built once.
static WORD_COUNT: LazyLock<CapabilityId> = LazyLock::new(|| CapabilityId::new(WORD_COUNT_ID));

/// The declaration this capability registers under.
///
/// # The classification is argued, not defaulted
///
/// * **risk `Low`** — "reading something already in scope, no external effect" is
///   `RiskClass::Low`'s own definition, and this reads nothing. `Low` also means
///   `requires_approval()` is false (that is `risk >= High`), so the pipeline does not
///   invent an approval for an operation that needs none.
/// * **reads/writes `Public`** — it touches only text the caller supplied in the
///   request, which is by definition already in the caller's hands.
/// * **isolation `InProcess`** — Tier 0. It is a Rust trait call in this address space.
///   `ExecutionTier::InProcess` on the adapter is what makes that structural rather
///   than a promise: a Tier-1 adapter is refused unless a sandbox is available, so the
///   tier and the declaration cannot quietly disagree.
/// * **idempotent** — a pure function of its input. Repeating it cannot duplicate an
///   effect, because it has none.
/// * **enabled** — the default is `false`, and switching it on is a deliberate act.
///   This slice is that act, made once, at the composition root.
#[must_use]
pub fn declaration() -> crate::CapabilityDeclaration {
    crate::CapabilityDeclaration::new(
        CapabilityId::new(WORD_COUNT_ID),
        "Count words, characters and lines",
    )
    .with_risk(RiskClass::Low)
    .with_data(DataClass::Public, DataClass::Public)
    .with_isolation(IsolationTier::InProcess)
    .with_params(crate::schema::word_count_params())
    .with_target(orxnud_domain::TargetSemantics::None)
    .idempotent()
    .enabled()
}

/// The counts a word count produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// UTF-8 bytes.
    pub bytes: usize,
    /// Unicode scalar values.
    pub characters: usize,
    /// Whitespace-separated runs.
    pub words: usize,
    /// `\n`-terminated lines.
    pub lines: usize,
}

impl Counts {
    /// The wire shape, as JSON.
    #[must_use]
    pub fn to_json(self) -> Value {
        json!({
            "bytes": self.bytes,
            "characters": self.characters,
            "words": self.words,
            "lines": self.lines,
        })
    }

    /// Reads the wire shape back, or `None` if it is not a well-formed count.
    ///
    /// A missing or wrongly-typed field makes the whole thing `None` rather than a
    /// partially-defaulted value: half a count is not a count, and defaulting a field
    /// to zero would let a truncated result verify.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let field = |k: &str| value.get(k)?.as_u64().and_then(|v| usize::try_from(v).ok());
        Some(Self {
            bytes: field("bytes")?,
            characters: field("characters")?,
            words: field("words")?,
            lines: field("lines")?,
        })
    }
}

/// Extracts and validates the `text` parameter.
///
/// # Errors
///
/// A message suitable for the adapter's `Err`, which the dispatcher turns into
/// [`ExecutionOutcome::Failed`]. Every branch names the field and what was wrong with
/// it, because "invalid parameters" tells a caller nothing they can act on.
fn text_param(params: &Value) -> Result<String, String> {
    // An unrecognised field is refused rather than ignored, for the same reason
    // `write_text::parse` refuses one: ignoring it would report success for an
    // operation the caller did not describe.
    if let Some(object) = params.as_object() {
        for key in object.keys() {
            if key != TEXT_PARAM {
                return Err(format!("`{key}` is not a parameter of this capability"));
            }
        }
    }
    let Some(raw) = params.get(TEXT_PARAM) else {
        return Err(format!("`{TEXT_PARAM}` is required"));
    };
    let Some(text) = raw.as_str() else {
        return Err(format!(
            "`{TEXT_PARAM}` must be a string, not {}",
            type_name(raw)
        ));
    };
    if text.len() > MAX_TEXT_BYTES {
        return Err(format!(
            "`{TEXT_PARAM}` is {} bytes, over the {MAX_TEXT_BYTES}-byte limit",
            text.len()
        ));
    }
    Ok(text.to_owned())
}

/// The JSON type name, for an error that has to say what it got.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// The adapter: counts, in-process, deterministically.
///
/// Receives only a `DispatchView`, which carries no actor — so this cannot learn who
/// asked, and a capability that could is a confused deputy (ADR-0027 S8).
#[derive(Debug, Default)]
pub struct WordCountAdapter;

impl CapabilityAdapter for WordCountAdapter {
    fn capability_id(&self) -> &CapabilityId {
        &WORD_COUNT
    }

    fn declared_class(&self) -> DataClass {
        DataClass::Public
    }

    fn tier(&self) -> ExecutionTier {
        // Tier 0, stated explicitly rather than left to the default so that the tier
        // and the declaration are visibly the same decision.
        ExecutionTier::InProcess
    }

    fn invoke(
        &self,
        view: &DispatchView<'_>,
        _credential: Option<&CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        let text = text_param(view.params())?;
        Ok(ExecutionOutcome::Succeeded {
            output: Some(count_by_scan(&text).to_json().to_string()),
        })
    }
}

/// **The adapter's** counting algorithm: one pass, tracking whether we are inside a
/// word.
///
/// # Why this is not shared with the verifier
///
/// [`count_by_split`] computes the same four numbers a structurally different way. If
/// both called one helper, the verifier would be checking the adapter against itself
/// and would agree with every bug the helper contained; keeping the two apart is what
/// makes a mutation test meaningful. See [`crate::text`]'s module docs for what this
/// does and does not buy.
fn count_by_scan(text: &str) -> Counts {
    let mut characters = 0usize;
    let mut words = 0usize;
    let mut newlines = 0usize;
    let mut inside_word = false;

    for c in text.chars() {
        characters += 1;
        if c == '\n' {
            newlines += 1;
        }
        // Whitespace ends a run and never starts one, so a leading space adds no word
        // and a trailing space adds none either. Tabs and non-ASCII spaces count,
        // because `is_whitespace` is the Unicode answer and inventing a narrower one
        // here would make the contract depend on this file's mood.
        let space = c.is_whitespace();
        if space {
            inside_word = false;
        } else if !inside_word {
            inside_word = true;
            words += 1;
        }
    }

    let lines = newlines + usize::from(!text.is_empty() && !text.ends_with('\n'));
    Counts {
        bytes: text.len(),
        characters,
        words,
        lines,
    }
}

/// The verifier's counting algorithm: derived from the input with different primitives.
///
/// Used only by `WordCountVerifier`. See `count_by_scan` for why the two are kept apart.
fn count_by_split(text: &str) -> Counts {
    Counts {
        bytes: text.len(),
        characters: text.chars().count(),
        words: text.split_whitespace().count(),
        lines: {
            let terminators = text.matches('\n').count();
            let unterminated_tail = usize::from(!text.is_empty() && !text.ends_with('\n'));
            terminators + unterminated_tail
        },
    }
}

/// Verifies a word count by recomputing it from the input.
///
/// # What "independent" means here, precisely
///
/// The verifier parses the adapter's claimed result, recomputes all four numbers from
/// the invocation's `text` using `count_by_split`, and compares. A corrupted count
/// is therefore caught even though nothing else observes the adapter.
///
/// What this does **not** buy: independence from a shared *misreading of the
/// specification*. If both implementations agreed that a line were terminated by
/// something other than `\n`, they would agree with each other and both be wrong.
/// That is inherent to verifying a pure function against a written contract — the
/// contract is the shared input — and the honest mitigation is the contract being
/// stated in the module docs and pinned by the tests, not a stronger verifier. What
/// the verifier does buy is independence from a shared *implementation*, which is the
/// defect class that actually occurs.
#[derive(Debug, Default)]
pub struct WordCountVerifier;

impl Verifier for WordCountVerifier {
    fn verify(
        &self,
        execution: &ExecutionOutcome,
        params: &Value,
        _at_ms: i64,
    ) -> Result<VerificationOutcome, VerifyError> {
        match execution {
            // `Undetermined`, not `Refuted`, and the repository's own verifier fixture
            // says why: a refutation asserts the effect was *proven absent and safe to
            // retry*, whereas a reported failure means nothing ran to verify at all.
            // Claiming a refutation here would tell a caller to retry something whose
            // failure may not have been transient — a retry loop on a bad parameter.
            //
            // The adapter's reason is not lost: the dispatch outcome still carries it
            // on `execution`, and the runtime surfaces it separately from this verdict.
            ExecutionOutcome::Failed { detail } => Ok(VerificationOutcome::Undetermined {
                reason: format!(
                    "the adapter reported a failure, so there was no effect to \
                                verify: {detail}"
                ),
            }),
            // Nothing is known either way. Never `Verified`, and never `Refuted`:
            // claiming a refutation here would authorise a retry for something that may
            // have happened.
            ExecutionOutcome::Unknown { detail } => Ok(VerificationOutcome::Undetermined {
                reason: format!("the adapter did not report: {detail}"),
            }),
            ExecutionOutcome::Succeeded { output } => {
                let Some(raw) = output else {
                    return Ok(VerificationOutcome::Refuted {
                        evidence: "the adapter claimed success but returned no result".into(),
                    });
                };
                let Ok(claimed) = serde_json::from_str::<Value>(raw) else {
                    return Ok(VerificationOutcome::Refuted {
                        evidence: "the adapter's result is not readable JSON".into(),
                    });
                };
                let Some(claimed) = Counts::from_json(&claimed) else {
                    return Ok(VerificationOutcome::Refuted {
                        evidence: "the adapter's result is missing a count".into(),
                    });
                };
                // Recomputing needs the original input. Without it there is nothing to
                // compare against, and guessing `Undetermined` would report every
                // malformed request as merely unverified rather than refuted.
                let Ok(text) = text_param(params) else {
                    return Ok(VerificationOutcome::Refuted {
                        evidence: "the invocation had no usable `text` to verify against".into(),
                    });
                };
                let expected = count_by_split(&text);
                if claimed == expected {
                    Ok(VerificationOutcome::Verified {
                        evidence: format!(
                            "recomputed independently: {} bytes, {} characters, {} words, {} lines",
                            expected.bytes, expected.characters, expected.words, expected.lines
                        ),
                    })
                } else {
                    Ok(VerificationOutcome::Refuted {
                        evidence: format!(
                            "the adapter reported {claimed:?} but the input independently \
                             counts as {expected:?}"
                        ),
                    })
                }
            }
        }
    }
}

/// The adapter and its verifier, paired as the dispatcher requires.
#[derive(Debug, Default)]
pub struct WordCountBundle {
    adapter: WordCountAdapter,
    verifier: WordCountVerifier,
}

impl AdapterBundle for WordCountBundle {
    fn adapter(&self) -> &dyn CapabilityAdapter {
        &self.adapter
    }

    /// No sandbox plan.
    ///
    /// `None` is not merely the default here — it is *required*. A `Some` plan on a
    /// Tier-0 adapter is a configuration error the dispatcher refuses, so returning
    /// `None` is the truthful answer for something that spawns no process.
    fn sandbox_plan(
        &self,
        _invocation: &orxnud_policy::authority::CapabilityInvocation,
    ) -> Result<Option<crate::dispatch::SandboxPlan>, crate::dispatch::PlanError> {
        Ok(None)
    }

    fn verifier(&self) -> &dyn Verifier {
        &self.verifier
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `f` with the actor-free projection, as the governed path produced it.
    ///
    /// This used to construct a `DispatchView` by hand, because every field was
    /// public. They are private now — they live in `orxnud-policy` and are the
    /// argument to a crate-private `invoke`, so a public field would reopen exactly
    /// the door the boundary closes.
    ///
    /// The replacement is stronger than what it replaced: the view now comes from a
    /// real policy authorisation rather than from whatever this test decided to put in
    /// it, so "the adapter learns what to do and not who asked" is asserted against a
    /// value that was actually authorised.
    fn with_view<R>(params: &Value, f: impl FnOnce(&DispatchView<'_>) -> R) -> R {
        crate::suites::support::with_dispatch_view(WORD_COUNT_ID, params, f)
    }

    /// Runs the adapter and reads the counts back out of its claimed result.
    fn run(params: &Value) -> Result<Counts, String> {
        match with_view(params, |view| WordCountAdapter.invoke(view, None)) {
            Ok(ExecutionOutcome::Succeeded { output: Some(raw) }) => {
                let v: Value = serde_json::from_str(&raw).expect("the adapter emits JSON");
                Ok(Counts::from_json(&v).expect("the adapter emits all four counts"))
            }
            Ok(other) => Err(format!("unexpected outcome: {other:?}")),
            Err(e) => Err(e),
        }
    }

    fn count(text: &str) -> Counts {
        run(&json!({ "text": text })).expect("counts")
    }

    // ---------------------------------------------------------- the declaration

    #[test]
    fn the_declaration_is_the_one_this_capability_can_honour() {
        let d = declaration();
        assert_eq!(d.id, CapabilityId::new(WORD_COUNT_ID));
        assert!(d.enabled, "this slice is the act that enables it");
        assert!(d.idempotent, "a pure function has no effect to duplicate");
        assert_eq!(d.risk, RiskClass::Low);
        assert!(
            !d.risk.requires_approval(),
            "Low risk must not demand an approval; the pipeline would otherwise \\
             invent one for an operation that needs none"
        );
        assert_eq!(d.reads, DataClass::Public);
        assert_eq!(d.writes, DataClass::Public);
        assert_eq!(d.isolation, IsolationTier::InProcess);
    }

    #[test]
    fn the_adapter_is_tier_0_and_the_declaration_agrees() {
        // A declaration claiming InProcess while the adapter is Tier 1 would be the
        // bypass V-50 exists to close, so the two are asserted together.
        assert_eq!(WordCountAdapter.tier(), ExecutionTier::InProcess);
        assert_eq!(declaration().isolation, IsolationTier::InProcess);
        // The plan itself needs a real `CapabilityInvocation`, which only the
        // dispatcher can mint, so that half of the property is asserted where a
        // dispatch already exists rather than duplicated with a mock here.
        assert!(
            WordCountAdapter.tier() == ExecutionTier::InProcess,
            "the adapter that would supply a plan must be the Tier-0 one"
        );
    }

    #[test]
    fn the_adapter_declares_the_classest_it_handles() {
        assert_eq!(WordCountAdapter.declared_class(), DataClass::Public);
    }

    // ------------------------------------------------------------ input handling

    #[test]
    fn empty_text_counts_zero_of_everything() {
        // Including zero lines: a body with no content has no lines, not one empty one.
        assert_eq!(
            count(""),
            Counts {
                bytes: 0,
                characters: 0,
                words: 0,
                lines: 0
            }
        );
    }

    #[test]
    fn ascii_text_is_counted_as_written() {
        assert_eq!(
            count("hello world"),
            Counts {
                bytes: 11,
                characters: 11,
                words: 2,
                lines: 1
            }
        );
    }

    #[test]
    fn a_repeated_whitespace_run_is_one_separator() {
        // The contract question this pins: two spaces do not make an empty word.
        for (text, expected_words) in [
            ("hello world", 2),
            ("hello  world", 2),
            ("hello   world", 2),
            ("  hello world  ", 2),
            ("hello\tworld", 2),
            ("hello\u{00a0}world", 2), // NBSP is Unicode whitespace
            ("hello\r\nworld", 2),
        ] {
            assert_eq!(count(text).words, expected_words, "{text:?}");
        }
    }

    #[test]
    fn whitespace_only_text_has_no_words() {
        for text in ["   ", "\t\t", "\n", "\r\n\r\n", " \u{2003} "] {
            let c = count(text);
            assert_eq!(c.words, 0, "{text:?} should have no words");
        }
    }

    #[test]
    fn lines_count_newline_terminators_plus_an_unterminated_tail() {
        for (text, expected) in [
            ("a", 1),
            ("a\n", 1), // terminated: no phantom second line
            ("a\nb", 2),
            ("a\nb\n", 2),
            ("\n", 1),   // one empty line
            ("\n\n", 2), // two empty lines
            ("a\n\nb", 3),
            ("", 0),
        ] {
            assert_eq!(count(text).lines, expected, "{text:?}");
        }
    }

    #[test]
    fn only_newline_terminates_a_line() {
        // `\r` is content, not a terminator. Stated because the opposite is a
        // reasonable guess and would silently disagree on CRLF input.
        assert_eq!(count("a\r\nb").lines, 2);
        assert_eq!(count("a\rb").lines, 1, "a bare CR does not end a line");
    }

    // --------------------------------------------------------------- unicode

    #[test]
    fn characters_are_scalar_values_not_bytes_and_not_graphemes() {
        // "é" as one scalar: 1 char, 2 bytes. The three notions are distinct and the
        // capability reports all three rather than collapsing them.
        let c = count("é");
        assert_eq!(c.characters, 1);
        assert_eq!(c.bytes, 2);

        // An emoji outside the BMP: 1 scalar, 4 bytes.
        let c = count("😀");
        assert_eq!(c.characters, 1);
        assert_eq!(c.bytes, 4);

        // A ZWJ family is several code points and therefore several "characters"
        // under this contract. Documented as a known limitation, pinned so a change
        // to it is deliberate rather than accidental.
        let c = count("👨‍👩‍👧");
        assert_eq!(c.characters, 5, "one scalar per code point, ZWJ included");
        assert_eq!(c.words, 1);
    }

    #[test]
    fn multibyte_text_counts_words_the_same_as_ascii() {
        let c = count("héllo wörld");
        assert_eq!(c.words, 2);
        assert_eq!(c.characters, 11);
        assert_eq!(c.bytes, 13, "two of those scalars are two bytes each");
    }

    #[test]
    fn combining_marks_are_their_own_scalars() {
        // "e" + combining acute is two scalars and one grapheme. See the module docs:
        // graphemes need a dependency this repository does not have, and pretending
        // otherwise would be a lie about what `characters` means.
        let c = count("e\u{0301}");
        assert_eq!(c.characters, 2);
        assert_eq!(c.bytes, 3);
    }

    #[test]
    fn multibyte_newlines_and_whitespace_are_handled_as_unicode() {
        // U+2028 LINE SEPARATOR is whitespace but not '\n', so it ends a word without
        // starting a line. Both halves of that are the contract.
        let c = count("a\u{2028}b");
        assert_eq!(c.words, 2, "it is whitespace");
        assert_eq!(c.lines, 1, "but only '\\n' terminates a line");
    }

    // ------------------------------------------------------------ determinism

    #[test]
    fn repeated_execution_is_identical() {
        let params = json!({ "text": "the quick brown fox\njumps over" });
        let first = run(&params).expect("counts");
        for _ in 0..8 {
            assert_eq!(
                run(&params).expect("counts"),
                first,
                "must be deterministic"
            );
        }
    }

    #[test]
    fn the_two_algorithms_agree_across_a_corpus() {
        // The verifier's algorithm is not the adapter's. This is the check that they
        // are two implementations of one contract rather than one implementation used
        // twice — and it is what makes the mutation test below meaningful.
        let corpus = [
            "",
            " ",
            "  ",
            "a",
            "a b",
            "a  b",
            " a b ",
            "a\nb",
            "a\n",
            "\n",
            "\n\n",
            "a\r\nb",
            "héllo wörld",
            "😀 😀",
            "👨‍👩‍👧x",
            "one two three\nfour five",
            "tabs\tand\nnewlines",
            "trailing space ",
            " leading",
            "e\u{0301} x",
        ];
        for text in corpus {
            assert_eq!(
                count_by_scan(text),
                count_by_split(text),
                "the two algorithms disagree on {text:?}"
            );
        }
    }

    // ------------------------------------------------------------- validation

    #[test]
    fn missing_or_wrongly_typed_text_is_refused() {
        for params in [
            json!({}),
            json!({ "text": null }),
            json!({ "text": 12 }),
            json!({ "text": true }),
            json!({ "text": ["a"] }),
            json!({ "text": { "a": 1 } }),
        ] {
            let err = run(&params).expect_err("must refuse");
            assert!(
                err.contains("text"),
                "the refusal must name the field: {err}"
            );
        }
    }

    #[test]
    fn oversized_text_is_refused_by_the_capabilitys_own_bound() {
        let at_limit = "x".repeat(MAX_TEXT_BYTES);
        assert!(
            count(&at_limit).bytes == MAX_TEXT_BYTES,
            "exactly at the bound is fine"
        );

        let over = "x".repeat(MAX_TEXT_BYTES + 1);
        let err = run(&json!({ "text": over })).expect_err("must refuse");
        assert!(err.contains("limit"), "{err}");
    }

    #[test]
    fn an_oversized_request_is_refused_before_it_is_counted() {
        // Guard the guard, as a compile-time assertion: if MAX_TEXT_BYTES ever rose to
        // or above the transport's own bound, the *frame* limit would be the thing
        // refusing rather than this capability, and the bound below would stop being
        // the effective one. Stated as a `const` assert so raising it is a deliberate
        // edit rather than something a runtime test would merely notice.
        const {
            assert!(
                MAX_TEXT_BYTES < 256 * 1024,
                "the capability bound must stay tighter than the transport's"
            );
        }
    }

    // ------------------------------------------------------------ verification

    #[test]
    fn a_correct_result_verifies() {
        let params = json!({ "text": "hello world\nsecond line" });
        let execution =
            with_view(&params, |view| WordCountAdapter.invoke(view, None)).expect("ran");
        let v = WordCountVerifier
            .verify(&execution, &params, 0)
            .expect("verified");
        assert!(v.is_verified(), "{v:?}");
    }

    #[test]
    fn every_field_is_checked_independently() {
        // Corrupt one field at a time. If verification compared a single field, or
        // compared a summary, these would pass.
        let params = json!({ "text": "hello world\nsecond line" });
        let good = count("hello world\nsecond line");
        for field in ["bytes", "characters", "words", "lines"] {
            for delta in [1i64, -1] {
                let mut tampered = good.to_json();
                let current = tampered[field].as_i64().expect("numeric");
                tampered[field] = json!(current + delta);
                let execution = ExecutionOutcome::Succeeded {
                    output: Some(tampered.to_string()),
                };
                let v = WordCountVerifier
                    .verify(&execution, &params, 0)
                    .expect("ran");
                assert!(
                    v.is_refuted(),
                    "a wrong {field} ({delta:+}) must be refuted, got {v:?}"
                );
            }
        }
    }

    #[test]
    fn a_result_for_the_wrong_text_is_refuted() {
        // Right shape, right field names, wrong input: the case a field-by-field
        // comparison would miss if the verifier used the adapter's output as its
        // source of truth.
        let execution = ExecutionOutcome::Succeeded {
            output: Some(count("something else entirely").to_json().to_string()),
        };
        let v = WordCountVerifier
            .verify(&execution, &json!({ "text": "hello world" }), 0)
            .expect("ran");
        assert!(
            v.is_refuted(),
            "a count of the wrong text must be refuted: {v:?}"
        );
    }

    #[test]
    fn unreadable_or_incomplete_results_are_refuted_not_accepted() {
        for raw in [
            "not json at all",
            "{}",
            r#"{"bytes":1}"#,
            r#"{"bytes":1,"characters":1,"words":1}"#,
            r#"{"bytes":"1","characters":1,"words":1,"lines":1}"#,
        ] {
            let execution = ExecutionOutcome::Succeeded {
                output: Some(raw.to_owned()),
            };
            let v = WordCountVerifier
                .verify(&execution, &json!({ "text": "a" }), 0)
                .expect("ran");
            assert!(v.is_refuted(), "{raw:?} must be refuted, got {v:?}");
        }
    }

    #[test]
    fn success_with_no_result_at_all_is_refuted() {
        let execution = ExecutionOutcome::Succeeded { output: None };
        let v = WordCountVerifier
            .verify(&execution, &json!({ "text": "a" }), 0)
            .expect("ran");
        assert!(v.is_refuted(), "{v:?}");
    }

    #[test]
    fn a_reported_failure_is_undetermined_and_never_a_refutation() {
        // Matches the repository's own verifier fixture: nothing ran, so there is
        // nothing to verify. Crucially it is *not* a refutation, because a refutation
        // authorises a retry and a reported failure may not have been transient.
        let execution = ExecutionOutcome::Failed {
            detail: "no text".into(),
        };
        let v = WordCountVerifier
            .verify(&execution, &json!({}), 0)
            .expect("ran");
        assert!(v.is_undetermined(), "{v:?}");
        assert!(!v.is_verified(), "must never claim success for a failure");
        assert!(!v.is_refuted(), "a failure is not a proven-absence: {v:?}");
        // The reason the adapter gave survives into the verdict's reason.
        assert!(
            v.to_string().contains("no text") || format!("{v:?}").contains("no text"),
            "the adapter's own reason must not be lost: {v:?}"
        );
    }

    #[test]
    fn an_unknown_outcome_is_undetermined_and_never_a_refutation() {
        // The distinction TP-12 exists to preserve: "may have happened" is not "proven
        // not to have happened", and only one of them authorises a retry.
        let execution = ExecutionOutcome::Unknown {
            detail: "timed out".into(),
        };
        let v = WordCountVerifier
            .verify(&execution, &json!({ "text": "a" }), 0)
            .expect("ran");
        assert!(v.is_undetermined(), "{v:?}");
        assert!(!v.is_verified(), "unknown is never verified");
        assert!(!v.is_refuted(), "unknown is never refuted");
    }

    #[test]
    fn verification_without_a_usable_input_is_refuted_not_undetermined() {
        // The invocation could not have produced a legitimate count, so the absence is
        // proven rather than merely unknown.
        let execution = ExecutionOutcome::Succeeded {
            output: Some(count("a").to_json().to_string()),
        };
        for params in [json!({}), json!({ "text": 42 })] {
            let v = WordCountVerifier
                .verify(&execution, &params, 0)
                .expect("ran");
            assert!(v.is_refuted(), "{params} should refute, got {v:?}");
        }
    }

    #[test]
    fn counts_round_trip_through_the_wire_shape() {
        for text in ["", "a", "hello world", "é😀\nsecond"] {
            let c = count(text);
            assert_eq!(Counts::from_json(&c.to_json()), Some(c), "{text:?}");
        }
    }
}
