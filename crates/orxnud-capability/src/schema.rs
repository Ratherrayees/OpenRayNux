//! The parameter shapes the shipped capabilities declare.
//!
//! One file, both schemas, so the set of things OpenRayNux can be asked to do is
//! readable in one place rather than assembled from per-capability modules. Each entry
//! sits directly beside the capability's own parser, and `text`/`write_text` assert
//! that the shape and the parser agree — the shape must never be the stricter of the
//! two, or a valid request would be refused before the capability saw it.

use orxnud_domain::ParamField;
use orxnud_domain::ParamKind;
use orxnud_domain::ParamSchema;
use orxnud_domain::ParamSpec;

/// `text/word-count`: the text to measure.
#[must_use]
pub fn word_count_params() -> ParamSpec {
    ParamSpec::new(
        "The text to count words, characters and lines in.",
        ParamSchema::new(vec![ParamField::required(
            "text",
            ParamKind::String,
            "The text to measure.",
        )]),
    )
}

/// `filesystem/write-text`: where to write, and what.
///
/// Shape only. Whether the path stays inside the workspace, names a single file and is
/// not absolute is `write_text::parse`'s business, and duplicating those rules here
/// would create two implementations that could disagree.
#[must_use]
pub fn write_text_params() -> ParamSpec {
    ParamSpec::new(
        "Write one text file into the sandbox workspace.",
        ParamSchema::new(vec![
            ParamField::required(
                "path",
                ParamKind::String,
                "File name, in the workspace root.",
            ),
            ParamField::required("contents", ParamKind::String, "The exact text to write."),
        ]),
    )
}

/// `filesystem/read-text`: which workspace file to read.
///
/// Shape only, and deliberately the narrowest schema in the crate: **one** required
/// string. There is no offset, no length, no encoding and no glob, because each of those
/// would be a way to ask for something other than "this file, in full". The 64 KiB ceiling
/// is not expressible here either -- it depends on the file, not on the request -- so it is
/// enforced where the file is actually read.
///
/// Path safety is not here on purpose: it belongs to `read_text::resolve`, and duplicating
/// those rules would create two implementations that could disagree about what "inside the
/// workspace" means.
#[must_use]
pub fn read_text_params() -> ParamSpec {
    ParamSpec::new(
        "Read one text file from the sandbox workspace.",
        ParamSchema::new(vec![ParamField::required(
            "path",
            ParamKind::String,
            "Path to the file, relative to the workspace root.",
        )]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The schema is a *shape*, so everything the capability's own parser accepts must
    /// satisfy it. If this ever fails, a valid request would be refused by the proposer
    /// before the capability had a chance to interpret it.
    #[test]
    fn the_shape_is_never_stricter_than_the_capabilitys_own_parser() {
        for params in [
            json!({"path": "a.txt", "contents": ""}),
            json!({"path": "a.txt", "contents": "hello"}),
            json!({"path": "a.txt", "contents": "line\nbreak é"}),
            // Values the parser refuses for *semantic* reasons still satisfy the shape,
            // and that is correct: the shape is not where those rules live.
            json!({"path": "../escape.txt", "contents": "x"}),
            json!({"path": "/etc/passwd", "contents": "x"}),
            json!({"path": "nested/a.txt", "contents": "x"}),
        ] {
            write_text_params()
                .schema
                .validate(&params)
                .unwrap_or_else(|p| panic!("{params} should satisfy the shape: {p:?}"));
        }

        for params in [
            json!({"text": "hello"}),
            json!({"text": ""}),
            json!({"text": "a\nb é"}),
        ] {
            word_count_params()
                .schema
                .validate(&params)
                .unwrap_or_else(|p| panic!("{params} should satisfy the shape: {p:?}"));
        }
    }

    /// And the shape *is* stricter than nothing: a malformed request is caught here
    /// rather than reaching the sandbox.
    #[test]
    fn the_shape_refuses_what_the_parser_would_also_refuse() {
        for params in [
            json!({}),
            json!({"path": "a.txt"}),
            json!({"path": "a.txt", "contents": 1}),
            json!({"path": "a.txt", "contents": "x", "extra": true}),
        ] {
            assert!(
                write_text_params().schema.validate(&params).is_err(),
                "{params} must not satisfy the shape"
            );
            assert!(
                crate::write_text::parse(&params).is_err(),
                "{params} must also be refused by the parser"
            );
        }
    }
}
