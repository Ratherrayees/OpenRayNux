//! What a capability accepts, in a form both the capability and its callers can read.
//!
//! # Why this is not a validation framework
//!
//! It is a *shape* description and nothing more: which fields exist, what type each is,
//! which are required, and what a nested object contains. It answers "is this the right
//! shape?" and never "is this value allowed?".
//!
//! That boundary is deliberate, and it is the whole reason a schema can sit in the
//! domain layer and be shared. Value rules — a path must stay inside the workspace, a
//! TTL must be positive, a recipient must look like an address — are decisions about the
//! world, and they belong next to the capability that understands the world. A schema
//! that tried to express them would either become a second implementation of the
//! capability's own checks or a constraint language nobody could read.
//!
//! So a capability declares its shape here and keeps its semantics in its own
//! [`crate`] code, and the two are asserted to agree rather than merged:
//! `orxnud-capability`'s tests check that every parameter set the parser accepts also
//! satisfies the schema, so the schema can never quietly become the stricter of the two.
//!
//! # What it is for
//!
//! Three consumers, one source:
//!
//! * the capability, to describe itself;
//! * the AI proposer, to learn what a well-formed request looks like and to reject
//!   malformed output **before** it becomes a durable proposal;
//! * eventually an approval prompt, which should show a human the same fields the
//!   capability will act on rather than a rendering of whatever JSON it was handed.

use serde_json::Value;

/// The type of one parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ParamKind {
    /// Text.
    String,
    /// A number, integral or not.
    Number,
    /// A boolean.
    Boolean,
    /// A nested object, described by the field's own `fields`.
    Object,
    /// An array. Element type is not described: no shipped capability takes one, and
    /// guessing at it now would be a schema feature with no user. An unconstrained array
    /// is honest about that; a wrong element type would not be.
    Array,
    /// Anything, including null. For a capability whose parameter is genuinely opaque.
    Any,
}

impl ParamKind {
    /// Whether a JSON value has this type.
    #[must_use]
    pub fn accepts(self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Number => value.is_number(),
            Self::Boolean => value.is_boolean(),
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
            Self::Any => true,
        }
    }

    /// A stable word for a refusal message.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Object => "object",
            Self::Array => "array",
            Self::Any => "any",
        }
    }
}

/// One field of a parameter object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParamField {
    /// The field name.
    pub name: String,
    /// What type it must be.
    pub kind: ParamKind,
    /// Whether its absence is a refusal.
    pub required: bool,
    /// Prose for a model or an approval prompt.
    pub description: String,
    /// For [`ParamKind::Object`], the nested fields.
    pub fields: Vec<ParamField>,
}

impl ParamField {
    /// A required field.
    #[must_use]
    pub fn required(
        name: impl Into<String>,
        kind: ParamKind,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            kind,
            required: true,
            description: description.into(),
            fields: Vec::new(),
        }
    }

    /// The same field, optional.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    /// The nested fields, for an object-typed field.
    #[must_use]
    pub fn with_fields(mut self, fields: Vec<ParamField>) -> Self {
        self.fields = fields;
        self
    }
}

/// The parameters a capability accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParamSchema {
    fields: Vec<ParamField>,
}

impl ParamSchema {
    /// A schema over these fields.
    #[must_use]
    pub fn new(fields: Vec<ParamField>) -> Self {
        Self { fields }
    }

    /// No parameters at all.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// The declared fields.
    #[must_use]
    pub fn fields(&self) -> &[ParamField] {
        &self.fields
    }

    /// The field names, in declaration order — what a model is told.
    #[must_use]
    pub fn field_names(&self) -> Vec<&str> {
        self.fields.iter().map(|f| f.name.as_str()).collect()
    }

    /// Checks a value against this shape.
    ///
    /// Returns every problem found rather than the first, because a model that has got
    /// the shape wrong usually got it wrong in more than one place, and reporting them
    /// all is what lets it try again correctly.
    ///
    /// # Errors
    ///
    /// Returns every problem found, or `Ok(())` when the value matches the shape.
    ///
    /// # Errors
    ///
    /// Returns every problem found rather than the first, or `Ok(())` when the value
    /// matches. Unknown fields are refused: that is the strict choice and it is the one
    /// that matters here, because a caller — especially a model — that sends a field the
    /// capability does not read has misunderstood the request, and ignoring the field
    /// would perform a *different* operation from the one that was described.
    pub fn validate(&self, value: &Value) -> Result<(), Vec<String>> {
        let Some(object) = value.as_object() else {
            return Err(vec![format!(
                "parameters must be an object, not {}",
                kind_of(value)
            )]);
        };
        let mut problems = Vec::new();

        for field in &self.fields {
            match object.get(&field.name) {
                None | Some(Value::Null) if field.required => {
                    problems.push(format!("`{}` is required", field.name));
                }
                // Null and absent are the same thing for an optional field: a caller
                // that sent `"x": null` has not supplied a value.
                None | Some(Value::Null) => {}
                Some(v) => {
                    if !field.kind.accepts(v) {
                        problems.push(format!(
                            "`{}` must be {}, not {}",
                            field.name,
                            field.kind.label(),
                            kind_of(v)
                        ));
                        continue;
                    }
                    if field.kind == ParamKind::Object
                        && !field.fields.is_empty()
                        && let Err(nested) = ParamSchema::new(field.fields.clone()).validate(v)
                    {
                        // Backticks stripped so a nested problem reads
                        // `config.mode must be string` rather than `config.`mode` must be
                        // string`, which is unreadable and gets copied into a prompt.
                        problems.extend(
                            nested
                                .into_iter()
                                .map(|p| format!("{}.{}", field.name, p.replace('`', ""))),
                        );
                    }
                }
            }
        }

        for key in object.keys() {
            if !self.fields.iter().any(|f| &f.name == key) {
                problems.push(format!("`{key}` is not a parameter of this capability"));
            }
        }

        if problems.is_empty() {
            Ok(())
        } else {
            problems.sort();
            Err(problems)
        }
    }
}

/// A capability's parameters as prose plus a machine-checkable shape.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParamSpec {
    /// What the parameters are for, shown to a model or an approver.
    pub description: String,
    /// The shape.
    pub schema: ParamSchema,
}

impl ParamSpec {
    /// A described schema.
    #[must_use]
    pub fn new(description: impl Into<String>, schema: ParamSchema) -> Self {
        Self {
            description: description.into(),
            schema,
        }
    }
}

/// Whether a capability names a target, and whether it must.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum TargetSemantics {
    /// The capability does not act on a named target.
    #[default]
    None,
    /// It may act without one.
    Optional,
    /// It acts on a target, and cannot be asked to act without one.
    Required,
}

impl TargetSemantics {
    /// A stable word for a refusal message.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }

    /// Whether a target was supplied where one is needed.
    ///
    /// `None` and `Optional` are both satisfied by nothing: a capability that does not
    /// act on a target must not have one demanded of it, and one that merely tolerates a
    /// target must not require one. Only `Required` can refuse.
    #[must_use]
    pub const fn satisfied_by(self, present: bool) -> bool {
        match self {
            Self::None | Self::Optional => true,
            Self::Required => present,
        }
    }
}

/// The JSON type name of a value, for a refusal message.
fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema() -> ParamSchema {
        ParamSchema::new(vec![
            ParamField::required("path", ParamKind::String, "where to write"),
            ParamField::required("contents", ParamKind::String, "what to write"),
        ])
    }

    #[test]
    fn a_well_formed_object_validates() {
        assert!(
            schema()
                .validate(&json!({"path": "a.txt", "contents": "x"}))
                .is_ok()
        );
    }

    /// Every refusal a proposer can hit, and each one names the field and what was
    /// wrong with it — a model cannot correct itself from "invalid parameters".
    #[test]
    fn structural_problems_are_named() {
        let cases: Vec<(Value, &str)> = vec![
            (json!("not an object"), "must be an object"),
            (json!({"path": "a.txt"}), "`contents` is required"),
            (
                json!({"path": 1, "contents": "x"}),
                "`path` must be string, not number",
            ),
            (
                json!({"path": "a.txt", "contents": "x", "sudo": true}),
                "`sudo` is not a parameter",
            ),
        ];
        for (value, expected) in cases {
            let problems = schema()
                .validate(&value)
                .expect_err(&format!("{value} must be refused"));
            assert!(
                problems.iter().any(|p| p.contains(expected)),
                "{value}: {problems:?} does not mention {expected:?}"
            );
        }
    }

    /// Null is treated as absent for a required field, because a model emitting
    /// `"path": null` has not supplied a path.
    #[test]
    fn a_null_required_field_is_a_refusal_not_a_pass() {
        let problems = schema()
            .validate(&json!({"path": null, "contents": "x"}))
            .expect_err("null is not a path");
        assert!(problems.iter().any(|p| p.contains("`path` is required")));
    }

    #[test]
    fn nested_objects_are_checked_recursively() {
        let nested = ParamSchema::new(vec![
            ParamField::required("config", ParamKind::Object, "nested").with_fields(vec![
                ParamField::required("mode", ParamKind::String, "a mode"),
            ]),
        ]);
        assert!(
            nested
                .validate(&json!({"config": {"mode": "fast"}}))
                .is_ok()
        );
        let problems = nested
            .validate(&json!({"config": {"mode": 7}}))
            .expect_err("wrong nested type");
        assert!(
            problems
                .iter()
                .any(|p| p.contains("config.mode must be string")),
            "the problem must name the nested field: {problems:?}"
        );
    }

    #[test]
    fn an_empty_schema_accepts_only_an_empty_object() {
        assert!(ParamSchema::empty().validate(&json!({})).is_ok());
        assert!(ParamSchema::empty().validate(&json!({"x": 1})).is_err());
    }

    #[test]
    fn optional_fields_may_be_absent() {
        let s = ParamSchema::new(vec![
            ParamField::required("path", ParamKind::String, "where").optional(),
        ]);
        assert!(s.validate(&json!({})).is_ok());
        assert!(s.validate(&json!({"path": "a"})).is_ok());
    }

    #[test]
    fn target_semantics_answer_the_only_question_asked_of_them() {
        assert!(TargetSemantics::None.satisfied_by(false));
        assert!(TargetSemantics::Optional.satisfied_by(false));
        assert!(TargetSemantics::Optional.satisfied_by(true));
        assert!(!TargetSemantics::Required.satisfied_by(false));
        assert!(TargetSemantics::Required.satisfied_by(true));
    }
}
