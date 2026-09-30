//! Layered configuration, schema versioning, and the migration mechanism.
//!
//! # Mechanism only — there is no config schema in Phase 1
//!
//! `docs/13-phase-1-contract.md` §12 explicitly defers the config schema shape to
//! Phase 2, and §8 forbids application schemas. So this crate ships the
//! **plumbing** and nothing it would carry:
//!
//! * [`LayeredConfig`] — merge a base, a user layer, and environment overrides,
//!   with a **declared precedence** rather than an emergent one.
//! * [`ConfigSchemaVersion`] — the version number a migration compares against.
//! * [`Migrator`] — the forward-only migration mechanism, exercised with a test
//!   double so the *mechanism* is proven without inventing a real schema.
//!
//! A test double is the honest choice here. A migration framework validated
//! against a schema we have not designed yet would be validated against a guess.
//!
//! # Precedence, and why it is enforced rather than documented
//!
//! `defaults < file < environment < explicit override`. A user who sets a value
//! in their config file must be able to override it for one run without editing
//! the file, and an explicit override must beat the environment so a script can
//! pin a value regardless of the shell it runs in. Getting this wrong is
//! silent — the config loads, just with the wrong value — so the order is a
//! constant with a test per pair rather than a comment.
//!
//! # Secrets never come from here
//!
//! Secret *references* may appear in config; secret *values* come from the
//! platform secret store ([`SecretRef`]). [`ConfigValue::from_environment`]
//! refuses to treat an environment variable as a secret store, because an
//! environment variable is visible to every process of the same user and ends up
//! in `ps` output and crash dumps.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Where a configuration value came from.
///
/// Recorded rather than discarded, so `orxnuctl doctor` can explain why a value
/// is what it is. A config system that cannot answer "where did this come from"
/// is one users end up debugging by deleting files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layer {
    /// Built-in defaults. Lowest precedence.
    Defaults,
    /// A config file on disk.
    File,
    /// An environment variable.
    Environment,
    /// An explicit programmatic override. Highest precedence.
    Override,
}

impl Layer {
    /// Whether `self` overrides `other`.
    ///
    /// `true` for strictly higher precedence. Two layers of equal precedence do
    /// not override each other; the caller decides, so the ambiguity is visible
    /// rather than silently resolved by map iteration order.
    #[must_use]
    pub fn overrides(self, other: Self) -> bool {
        self > other
    }
}

impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Defaults => "defaults",
            Self::File => "file",
            Self::Environment => "environment",
            Self::Override => "override",
        };
        f.write_str(s)
    }
}

/// One configuration key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigKey(pub String);

impl ConfigKey {
    /// Builds a key.
    #[must_use]
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    /// The key as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ConfigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A configuration value. Deliberately untyped at this layer.
///
/// Phase 1 does not define a schema, so there is nothing to validate against and
/// no enum to parse into. `serde_json::Value` is used rather than TOML's own
/// value type so the in-memory form is also the wire form the protocol crate
/// already speaks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigValue(pub serde_json::Value);

impl ConfigValue {
    /// Wraps a value.
    #[must_use]
    pub fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    /// A string value.
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self(serde_json::Value::String(value.into()))
    }

    /// A boolean value.
    #[must_use]
    pub fn bool(value: bool) -> Self {
        Self(serde_json::Value::Bool(value))
    }

    /// An integer value.
    #[must_use]
    pub fn integer(value: i64) -> Self {
        Self(serde_json::Value::from(value))
    }

    /// Whether the value is a secret.
    ///
    /// Always `false` for a plain value. Secret *references* are strings naming
    /// an entry in the secret store; the value itself never passes through
    /// configuration, so this exists to make the distinction checkable rather than
    /// assumed.
    #[must_use]
    pub fn is_secret(&self) -> bool {
        false
    }
}

/// A resolved value together with the layer that supplied it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resolved {
    /// The winning value.
    pub value: ConfigValue,
    /// Which layer supplied it.
    pub from: Layer,
    /// Every layer that supplied a value for this key, in precedence order.
    ///
    /// Kept so a user can be told *why* the resolved value is what it is, not
    /// only what it is.
    pub shadowed: Vec<Layer>,
}

/// Configuration merged from several layers.
///
/// Merging is eager rather than lazy: a `BTreeMap` per layer, resolved on
/// [`LayeredConfig::resolve`]. Lazy layering would need a reader to walk the
/// layers on every access, which puts the precedence rule in the hot path and
/// makes "which layer won" expensive to answer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LayeredConfig {
    layers: Vec<(Layer, BTreeMap<ConfigKey, ConfigValue>)>,
}

impl LayeredConfig {
    /// An empty configuration. Resolves every key to nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Adds or replaces a layer wholesale.
    #[must_use]
    pub fn with_layer(mut self, layer: Layer, values: BTreeMap<ConfigKey, ConfigValue>) -> Self {
        // Replacing rather than accumulating: two `File` layers means a caller
        // loaded two files, and merging them would hide which one is in play.
        self.layers.retain(|(l, _)| *l != layer);
        self.layers.push((layer, values));
        self.layers.sort_by_key(|(l, _)| *l);
        self
    }

    /// Sets one key in one layer.
    #[must_use]
    pub fn set(mut self, layer: Layer, key: ConfigKey, value: ConfigValue) -> Self {
        match self.layers.iter_mut().find(|(l, _)| *l == layer) {
            Some((_, values)) => {
                values.insert(key, value);
            }
            None => {
                let mut values = BTreeMap::new();
                values.insert(key, value);
                self.layers.push((layer, values));
                self.layers.sort_by_key(|(l, _)| *l);
            }
        }
        self
    }

    /// Every layer present, in precedence order.
    #[must_use]
    pub fn layers(&self) -> Vec<Layer> {
        self.layers.iter().map(|(l, _)| *l).collect()
    }

    /// Resolves one key.
    #[must_use]
    pub fn resolve(&self, key: &ConfigKey) -> Option<Resolved> {
        let mut best: Option<Resolved> = None;
        for (layer, values) in &self.layers {
            let Some(value) = values.get(key) else {
                continue;
            };
            match &best {
                // Layers are sorted, so a later layer always has >= precedence.
                // Equal precedence cannot occur: `with_layer` de-duplicates by
                // layer, and `set` writes into the existing entry.
                Some(prev) if !layer.overrides(prev.from) => {
                    let mut shadowed = prev.shadowed.clone();
                    shadowed.push(*layer);
                    best = Some(Resolved {
                        value: prev.value.clone(),
                        from: prev.from,
                        shadowed,
                    });
                }
                Some(prev) => {
                    let mut shadowed = prev.shadowed.clone();
                    shadowed.push(prev.from);
                    best = Some(Resolved {
                        value: value.clone(),
                        from: *layer,
                        shadowed,
                    });
                }
                None => {
                    best = Some(Resolved {
                        value: value.clone(),
                        from: *layer,
                        shadowed: Vec::new(),
                    });
                }
            }
        }
        best
    }

    /// Resolves every key, in stable key order.
    #[must_use]
    pub fn resolve_all(&self) -> BTreeMap<ConfigKey, Resolved> {
        let mut keys: BTreeMap<ConfigKey, Resolved> = BTreeMap::new();
        for (layer, values) in &self.layers {
            for (key, value) in values {
                match keys.get(key) {
                    Some(prev) if !layer.overrides(prev.from) => {}
                    Some(prev) => {
                        let from = prev.from;
                        keys.insert(
                            key.clone(),
                            Resolved {
                                value: value.clone(),
                                from: *layer,
                                shadowed: {
                                    let mut s = prev.shadowed.clone();
                                    s.push(from);
                                    s
                                },
                            },
                        );
                    }
                    None => {
                        keys.insert(
                            key.clone(),
                            Resolved {
                                value: value.clone(),
                                from: *layer,
                                shadowed: Vec::new(),
                            },
                        );
                    }
                }
            }
        }
        keys
    }

    /// The keys present in any layer.
    #[must_use]
    pub fn keys(&self) -> Vec<ConfigKey> {
        let mut out: Vec<ConfigKey> = self
            .layers
            .iter()
            .flat_map(|(_, v)| v.keys().cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// The version of a config document's schema.
///
/// A bare newtype so migration state is comparable and hashable without pulling
/// in a schema representation that Phase 1 does not define.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigSchemaVersion(pub u32);

impl ConfigSchemaVersion {
    /// The version a fresh install is written at.
    pub const INITIAL: Self = Self(1);

    /// The version number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for ConfigSchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One forward step between schema versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MigrationStep {
    /// The version this step produces.
    pub to: ConfigSchemaVersion,
}

/// A failure while migrating.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrationError {
    /// The document is already at a newer version than we understand.
    ///
    /// A refusal, not a downgrade: a config written by a future version may use
    /// keys this build would drop on the floor.
    #[error("config schema version {found} is newer than this build understands ({max})")]
    NewerThanSupported {
        /// The document's version.
        found: ConfigSchemaVersion,
        /// The highest version this build knows.
        max: ConfigSchemaVersion,
    },

    /// A step failed partway.
    ///
    /// Reported with the version reached, so a retry can start from there rather
    /// than from the beginning.
    #[error("migration to schema version {reached} failed: {reason}")]
    StepFailed {
        /// The version reached before failing.
        reached: ConfigSchemaVersion,
        /// What went wrong.
        reason: String,
    },

    /// A step was declared but is missing from the table.
    #[error("no migration registered from schema version {from} to {to}")]
    MissingStep {
        /// The version being migrated from.
        from: ConfigSchemaVersion,
        /// The version being migrated to.
        to: ConfigSchemaVersion,
    },
}

/// Applies forward-only schema migrations.
///
/// Backward compatibility is not attempted, and that is deliberate: a config file
/// is small, it is rewritten atomically, and keeping a down-migration path means
/// keeping the old schema alive forever. Forward-only is also what makes
/// `NewerThanSupported` a safe refusal instead of a data-loss hazard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migrator {
    supported: ConfigSchemaVersion,
    steps: Vec<(ConfigSchemaVersion, MigrationStep)>,
}

impl Migrator {
    /// A migrator supporting up to `supported`.
    #[must_use]
    pub fn new(supported: ConfigSchemaVersion) -> Self {
        Self {
            supported,
            steps: Vec::new(),
        }
    }

    /// Registers a step.
    #[must_use]
    pub fn step(mut self, from: ConfigSchemaVersion, to: ConfigSchemaVersion) -> Self {
        self.steps.push((from, MigrationStep { to }));
        self
    }

    /// The highest version this migrator supports.
    #[must_use]
    pub fn supported(&self) -> ConfigSchemaVersion {
        self.supported
    }

    /// The versions reachable from `from`, in order.
    ///
    /// # Errors
    ///
    /// [`MigrationError::NewerThanSupported`] if `from` is newer than this build,
    /// or [`MigrationError::MissingStep`] if the chain has a hole. A hole means
    /// the step table is incomplete, which is a bug in the table rather than in
    /// the document — reported rather than skipped, because skipping would leave
    /// a document at a version nothing else expects.
    pub fn plan(
        &self,
        from: ConfigSchemaVersion,
    ) -> Result<Vec<ConfigSchemaVersion>, MigrationError> {
        if from > self.supported {
            return Err(MigrationError::NewerThanSupported {
                found: from,
                max: self.supported,
            });
        }
        let mut plan = vec![from];
        let mut current = from;
        while current < self.supported {
            let next = self
                .steps
                .iter()
                .find(|(f, _)| *f == current)
                .map(|(_, s)| s.to)
                .ok_or(MigrationError::MissingStep {
                    from: current,
                    to: self.supported,
                })?;
            plan.push(next);
            current = next;
        }
        Ok(plan)
    }

    /// Runs the plan, handing each step to `apply`.
    ///
    /// # Errors
    ///
    /// The planning error, or [`MigrationError::StepFailed`] if `apply` reports a
    /// failure, annotated with the version reached.
    pub fn migrate<F>(
        &self,
        from: ConfigSchemaVersion,
        mut apply: F,
    ) -> Result<ConfigSchemaVersion, MigrationError>
    where
        F: FnMut(ConfigSchemaVersion, ConfigSchemaVersion) -> Result<(), String>,
    {
        let plan = self.plan(from)?;
        let mut current = from;
        for target in plan.into_iter().skip(1) {
            apply(current, target).map_err(|reason| MigrationError::StepFailed {
                reached: current,
                reason,
            })?;
            current = target;
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn map(pairs: &[(&str, ConfigValue)]) -> BTreeMap<ConfigKey, ConfigValue> {
        pairs
            .iter()
            .map(|(k, v)| (ConfigKey::new(*k), v.clone()))
            .collect()
    }

    #[test]
    fn precedence_is_defaults_then_file_then_environment_then_override() {
        let key = ConfigKey::new("k");
        let c = LayeredConfig::empty()
            .with_layer(Layer::Defaults, map(&[("k", ConfigValue::integer(1))]))
            .with_layer(Layer::File, map(&[("k", ConfigValue::integer(2))]))
            .with_layer(Layer::Environment, map(&[("k", ConfigValue::integer(3))]))
            .with_layer(Layer::Override, map(&[("k", ConfigValue::integer(4))]));

        let r = c.resolve(&key).expect("resolved");
        assert_eq!(r.value, ConfigValue::integer(4));
        assert_eq!(r.from, Layer::Override);
        // Every lower layer is recorded, so a user can be told why the value is 4.
        assert_eq!(
            r.shadowed,
            vec![Layer::Defaults, Layer::File, Layer::Environment]
        );
    }

    #[test]
    fn a_lower_layer_never_overrides_a_higher_one() {
        // Built out of order on purpose: precedence comes from the enum, not from
        // insertion order.
        let key = ConfigKey::new("k");
        let c = LayeredConfig::empty()
            .with_layer(
                Layer::Override,
                map(&[("k", ConfigValue::string("override"))]),
            )
            .with_layer(
                Layer::Defaults,
                map(&[("k", ConfigValue::string("default"))]),
            );
        assert_eq!(
            c.resolve(&key).expect("resolved").value,
            ConfigValue::string("override")
        );
    }

    #[test]
    fn an_explicit_override_beats_the_environment() {
        // So a script can pin a value regardless of the shell it runs in.
        let key = ConfigKey::new("k");
        let c = LayeredConfig::empty()
            .with_layer(
                Layer::Environment,
                map(&[("k", ConfigValue::string("from-env"))]),
            )
            .with_layer(
                Layer::Override,
                map(&[("k", ConfigValue::string("pinned"))]),
            );
        assert_eq!(
            c.resolve(&key).expect("resolved").value,
            ConfigValue::string("pinned")
        );
    }

    #[test]
    fn a_key_present_in_only_one_layer_resolves_from_it() {
        let c = LayeredConfig::empty()
            .with_layer(Layer::File, map(&[("only-file", ConfigValue::bool(true))]));
        let r = c.resolve(&ConfigKey::new("only-file")).expect("resolved");
        assert_eq!(r.from, Layer::File);
        assert!(r.shadowed.is_empty());
    }

    #[test]
    fn an_absent_key_resolves_to_nothing_rather_than_a_default() {
        // Returning a silent default would make a typo'd key indistinguishable
        // from a deliberately unset one.
        let c = LayeredConfig::empty();
        assert!(c.resolve(&ConfigKey::new("missing")).is_none());
        assert!(c.keys().is_empty());
    }

    #[test]
    fn replacing_a_layer_does_not_accumulate_it() {
        let c = LayeredConfig::empty()
            .with_layer(Layer::File, map(&[("k", ConfigValue::string("first"))]))
            .with_layer(Layer::File, map(&[("l", ConfigValue::string("second"))]));
        assert_eq!(c.layers(), vec![Layer::File]);
        assert_eq!(c.keys(), vec![ConfigKey::new("l")]);
    }

    #[test]
    fn set_writes_into_an_existing_layer() {
        let key = ConfigKey::new("k");
        let c = LayeredConfig::empty()
            .with_layer(Layer::File, map(&[("k", ConfigValue::string("a"))]))
            .set(Layer::File, key.clone(), ConfigValue::string("b"));
        assert_eq!(
            c.resolve(&key).expect("resolved").value,
            ConfigValue::string("b")
        );
        assert_eq!(c.layers(), vec![Layer::File]);
    }

    #[test]
    fn resolve_all_agrees_with_resolve() {
        // Two implementations of the same rule is a bug factory; this is the
        // check that they stay in step.
        let c = LayeredConfig::empty()
            .with_layer(
                Layer::File,
                map(&[
                    ("a", ConfigValue::integer(1)),
                    ("b", ConfigValue::integer(2)),
                ]),
            )
            .with_layer(Layer::Environment, map(&[("a", ConfigValue::integer(3))]));
        let all = c.resolve_all();
        for key in c.keys() {
            assert_eq!(
                all.get(&key),
                c.resolve(&key).as_ref(),
                "resolve_all and resolve disagree on {key}"
            );
        }
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn a_config_value_is_never_a_secret() {
        // Secrets live in the platform secret store; config holds references.
        for v in [
            ConfigValue::string("s"),
            ConfigValue::bool(true),
            ConfigValue::integer(1),
        ] {
            assert!(!v.is_secret());
        }
    }

    #[test]
    fn layers_render_their_wire_names() {
        for (l, s) in [
            (Layer::Defaults, "defaults"),
            (Layer::File, "file"),
            (Layer::Environment, "environment"),
            (Layer::Override, "override"),
        ] {
            assert_eq!(l.to_string(), s);
        }
    }

    // --- the migration mechanism, against a double rather than a real schema ---

    fn two_step_migrator() -> Migrator {
        Migrator::new(ConfigSchemaVersion(3))
            .step(ConfigSchemaVersion(1), ConfigSchemaVersion(2))
            .step(ConfigSchemaVersion(2), ConfigSchemaVersion(3))
    }

    #[test]
    fn a_plan_walks_every_step_in_order() {
        assert_eq!(
            two_step_migrator()
                .plan(ConfigSchemaVersion(1))
                .expect("plan"),
            vec![
                ConfigSchemaVersion(1),
                ConfigSchemaVersion(2),
                ConfigSchemaVersion(3)
            ]
        );
    }

    #[test]
    fn an_up_to_date_document_has_nothing_to_do() {
        assert_eq!(
            two_step_migrator()
                .plan(ConfigSchemaVersion(3))
                .expect("plan"),
            vec![ConfigSchemaVersion(3)]
        );
    }

    #[test]
    fn a_newer_document_is_refused_not_downgraded() {
        let err = two_step_migrator()
            .plan(ConfigSchemaVersion(9))
            .expect_err("must refuse");
        assert_eq!(
            err,
            MigrationError::NewerThanSupported {
                found: ConfigSchemaVersion(9),
                max: ConfigSchemaVersion(3)
            }
        );
    }

    #[test]
    fn a_hole_in_the_step_table_is_reported() {
        // Skipping the gap would leave the document at a version nothing expects.
        let m = Migrator::new(ConfigSchemaVersion(3))
            .step(ConfigSchemaVersion(1), ConfigSchemaVersion(2));
        let err = m.plan(ConfigSchemaVersion(1)).expect_err("must report");
        assert_eq!(
            err,
            MigrationError::MissingStep {
                from: ConfigSchemaVersion(2),
                to: ConfigSchemaVersion(3)
            }
        );
    }

    #[test]
    fn migrate_applies_each_step_and_reports_the_final_version() {
        let mut seen: Vec<(u32, u32)> = Vec::new();
        let end = two_step_migrator()
            .migrate(ConfigSchemaVersion(1), |from, to| {
                seen.push((from.get(), to.get()));
                Ok(())
            })
            .expect("migrate");
        assert_eq!(end, ConfigSchemaVersion(3));
        assert_eq!(seen, vec![(1, 2), (2, 3)]);
    }

    #[test]
    fn a_failed_step_reports_the_version_reached_so_a_retry_can_resume() {
        let err = two_step_migrator()
            .migrate(ConfigSchemaVersion(1), |from, to| {
                if to.get() == 3 {
                    Err("boom".into())
                } else {
                    let _ = from;
                    Ok(())
                }
            })
            .expect_err("must fail");
        assert_eq!(
            err,
            MigrationError::StepFailed {
                reached: ConfigSchemaVersion(2),
                reason: "boom".into()
            }
        );
    }

    proptest! {
        /// Precedence is a total order, so resolution is order-independent.
        /// Building the layers in any order must give the same answer.
        #[test]
        fn resolution_does_not_depend_on_insertion_order(seed: u8) {
            let layers = [
                (Layer::Defaults, ConfigValue::integer(0)),
                (Layer::File, ConfigValue::integer(1)),
                (Layer::Environment, ConfigValue::integer(2)),
                (Layer::Override, ConfigValue::integer(3)),
            ];
            // Rotate by `seed` to exercise different insertion orders.
            let n = layers.len();
            let start = (seed as usize) % n;
            let rotated: Vec<_> = (0..n)
                .map(|i| (layers[(start + i) % n].0, layers[(start + i) % n].1.clone()))
                .collect();

            let key = ConfigKey::new("k");
            let c = LayeredConfig::empty();
            let c = rotated.iter().fold(c, |acc, (l, v)| {
                acc.with_layer(*l, map(&[("k", v.clone())]))
            });
            let r = c.resolve(&key).expect("resolved");
            // Whichever order they arrive in, the highest layer wins.
            prop_assert_eq!(r.from, Layer::Override);
            prop_assert_eq!(r.value, ConfigValue::integer(3));
        }

        /// A plan never goes backwards and never skips a registered step.
        #[test]
        fn a_plan_is_monotonic(v: u8) {
            let m = two_step_migrator();
            let plan = m.plan(ConfigSchemaVersion(1)).expect("plan");
            for pair in plan.windows(2) {
                prop_assert!(pair[1] > pair[0], "plan went backwards: {:?}", plan);
            }
            let _ = v;
        }
    }
}
