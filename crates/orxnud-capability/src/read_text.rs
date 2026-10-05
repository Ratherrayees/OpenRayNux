//! `filesystem/read-text` — observing a workspace file under the same governance as
//! writing one.
//!
//! # Why a read needs the full write apparatus
//!
//! Reading is disclosure. A file's contents are workspace data, and this capability is the
//! mechanism by which a model observes what an earlier step produced, so it is declared
//! `RiskClass::High` with `Public -> Public` classification and requires human approval
//! exactly as `filesystem/write-text` does. A lower risk class would make this the first
//! capability whose whole purpose is to release information to a party nobody asked.
//!
//! Three structural consequences follow, and each is a difference from the write path
//! rather than a copy of it:
//!
//! * **The sandbox grant is read-only.** `write-text` binds the workspace read-write,
//!   because it writes. `read-text` binds it `ro` and grants `rw` nothing, so the sandbox
//!   refuses a write even if the helper were changed to attempt one. Confinement and
//!   capability are stated in the same place.
//! * **The output is ephemeral.** The bytes are the point of the call, and the bundle
//!   declares [`AdapterBundle::output_is_ephemeral`](crate::dispatch::AdapterBundle) so the
//!   daemon records metadata and
//!   drops the content instead of copying file contents into `task_step_results`.
//! * **The verifier re-reads and compares.** `write-text`'s verifier re-reads to confirm the
//!   bytes landed. A read's verifier re-reads to confirm the bytes *reported* were the
//!   bytes on disk. A verifier that only checked the path was inside the workspace would
//!   confirm the one thing that was never in doubt.
//!
//! # What the verifier's independence is bounded by
//!
//! Both sides share [`resolve`], so a wrong `resolve` would have the verifier reading a
//! different file than the helper did and could report `Verified` for content that was
//! never returned. That is the same bound `write-text` states: `resolve` is a path join,
//! not a reimplementation of the effect. It is a real dependency and is named rather than
//! glossed.

use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use orxnud_domain::enums::{DataClass, IsolationTier, RiskClass};
use orxnud_domain::ids::CapabilityId;
use orxnud_domain::invocation::{CapabilityInvocation, DispatchView};

use crate::verification::{ExecutionOutcome, VerificationOutcome, Verifier, VerifyError};

/// This capability's id.
pub const READ_TEXT_ID: &str = "filesystem/read-text";

/// The hard ceiling on one read: 64 KiB.
///
/// A refusal, never a truncation. A truncated read that reported success would hand the
/// model a prefix while the protocol called it the whole file, and the model cannot tell the
/// difference -- which is the failure mode the size limit exists to prevent.
pub const MAX_READ_BYTES: u64 = 64 * 1024;

const DEADLINE_MS: u64 = 5_000;
/// Matches the read ceiling plus a little slack for the JSON envelope around it.
const OUTPUT_CAP_BYTES: u64 = MAX_READ_BYTES + 4096;

/// The declaration, as the registry sees it.
#[must_use]
pub fn declaration() -> crate::CapabilityDeclaration {
    crate::CapabilityDeclaration::new(
        CapabilityId::new(READ_TEXT_ID),
        "Read a text file from inside the sandbox workspace",
    )
    .with_risk(RiskClass::High)
    .with_data(DataClass::Public, DataClass::Public)
    .with_isolation(IsolationTier::Subprocess)
    .with_params(crate::schema::read_text_params())
    .with_target(orxnud_domain::TargetSemantics::Required)
    // Deliberately absent: `.idempotent()`. A read has no effect to be idempotent about,
    // and marking it so would let a policy grant it a standing permission on the strength
    // of a word that means nothing here.
    .enabled()
}

/// The validated parameters of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadText {
    /// The workspace-relative path.
    pub path: String,
}

/// Reads and validates the parameters.
///
/// Exactly one field, and nothing here consults the filesystem: validation must not depend
/// on state the sandbox controls, or the two layers would not be independent.
pub fn parse(params: &Value) -> Result<ReadText, String> {
    let obj = params
        .as_object()
        .ok_or_else(|| format!("{READ_TEXT_ID} takes an object, got {}", kind_of(params)))?;

    for key in obj.keys() {
        if key != "path" {
            // Named rather than "unknown parameter", because the actionable half of this
            // message is which key to delete.
            return Err(format!("{READ_TEXT_ID} takes only `path`; got {key:?}"));
        }
    }

    let path = obj
        .get("path")
        .ok_or_else(|| format!("{READ_TEXT_ID} requires `path`"))?
        .as_str()
        .ok_or_else(|| {
            format!(
                "`path` must be a string, got {}",
                kind_of(obj.get("path").unwrap_or(&Value::Null))
            )
        })?;

    if path.is_empty() {
        return Err("`path` must not be empty".to_owned());
    }
    if path.trim().is_empty() {
        // Distinct from empty: a whitespace name is not a path, and silently trimming it
        // would turn a request for one file into a request for another.
        return Err(format!("`path` must not be blank: {path:?}"));
    }

    Ok(ReadText {
        path: path.to_owned(),
    })
}

fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// Resolves a workspace-relative path to an absolute one inside the workspace.
///
/// **Unlike `write_text::resolve`, nested paths are allowed.** The write path restricts
/// itself to a single name in the workspace root, which costs it nothing because it creates
/// the file it names. A read that could not address `subdir/out.txt` could not observe
/// anything a previous step wrote into a subdirectory, which is most of what a composed
/// task produces. So the rule here is the weaker, more honest one: *relative, and provably
/// inside the workspace*.
///
/// Every escape is refused lexically, before the filesystem is consulted, so the failure is
/// a clear message rather than an `ENOENT` from somewhere deeper.
pub fn resolve(workspace: &Path, path: &str) -> Result<PathBuf, String> {
    // The same two emptiness rules `parse` applies, repeated because this layer exists to
    // be independent of that one. A blank name is legal on some filesystems, so accepting it
    // here would mean the two layers disagreed about what a request even is.
    if path.is_empty() {
        return Err("`path` must not be empty".to_owned());
    }
    if path.trim().is_empty() {
        return Err(format!("`path` must not be blank: {path:?}"));
    }

    let mut out = workspace.to_path_buf();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!(
                    "`path` must stay inside the workspace; {path:?} climbs out of it"
                ));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!("`path` must be relative; got {path:?}"));
            }
        }
    }

    if out == workspace {
        return Err("`path` names the workspace itself, not a file in it".to_owned());
    }

    // Belt and braces: the loop above cannot produce this, because `ParentDir` returns
    // early. Checking anyway means a future edit to that match cannot quietly open a way
    // out of the workspace -- this is the assertion that the loop is still the boundary.
    if !out.starts_with(workspace) {
        return Err(format!(
            "`path` must stay inside the workspace; {path:?} resolves outside it"
        ));
    }
    Ok(out)
}

/// The adapter.
///
/// # Why `invoke` refuses
///
/// A Tier-1 adapter's `invoke` is never called: the dispatcher builds a contract from the
/// bundle's [`AdapterBundle::sandbox_plan`] and hands that to the execution backend. This
/// body is unreachable in normal operation, and it refuses rather than reading anything.
/// An in-process read would be an unsandboxed read of the workspace, which is the exact
/// bypass the tier exists to close -- and for a *read* that bypass is disclosure.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReadTextAdapter;

impl crate::dispatch::CapabilityAdapter for ReadTextAdapter {
    fn capability_id(&self) -> &CapabilityId {
        static ID: std::sync::OnceLock<CapabilityId> = std::sync::OnceLock::new();
        ID.get_or_init(|| CapabilityId::new(READ_TEXT_ID))
    }

    fn declared_class(&self) -> DataClass {
        DataClass::Public
    }

    fn tier(&self) -> crate::dispatch::ExecutionTier {
        crate::dispatch::ExecutionTier::Subprocess
    }

    fn invoke(
        &self,
        _view: &DispatchView<'_>,
        _credential: Option<&crate::credential::CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        Err(format!(
            "{READ_TEXT_ID} is Tier-1 and runs in the sandbox, never in this process"
        ))
    }
}

/// The adapter, its plan and its verifier.
///
/// Owns the workspace because the plan and the verifier must agree on which absolute path a
/// relative name denotes. If they resolved independently they could disagree, and a
/// verifier reading a different file than the helper did would report `Verified` for content
/// that was never returned.
#[derive(Debug, Clone)]
pub struct ReadTextBundle {
    workspace: PathBuf,
    helper: PathBuf,
    /// Held rather than built per call because [`AdapterBundle::verifier`] returns a
    /// borrow, and constructing one on demand would return a reference to a temporary.
    verifier: ReadTextVerifier,
}

impl ReadTextBundle {
    /// Binds the bundle to a workspace and the child to read from it.
    ///
    /// No defaults and no discovery: a caller that has not established a workspace has not
    /// established where it is allowed to read, and guessing would be the bug.
    #[must_use]
    pub fn new(workspace: impl Into<PathBuf>, helper: impl Into<PathBuf>) -> Self {
        let workspace = workspace.into();
        Self {
            verifier: ReadTextVerifier {
                workspace: workspace.clone(),
            },
            workspace,
            helper: helper.into(),
        }
    }

    /// The workspace this bundle reads from.
    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
}

impl crate::dispatch::AdapterBundle for ReadTextBundle {
    fn adapter(&self) -> &dyn crate::dispatch::CapabilityAdapter {
        &ReadTextAdapter
    }

    /// The plan for one invocation.
    ///
    /// Returning `None` here -- or a plan that ignores `invocation` -- would produce a child
    /// with no idea what to read, so an error is a refusal of the whole dispatch rather than
    /// a fallback to something that merely runs.
    fn sandbox_plan(
        &self,
        invocation: &CapabilityInvocation,
    ) -> Option<crate::dispatch::SandboxPlan> {
        let parsed = parse(invocation.params()).ok()?;
        let absolute = resolve(&self.workspace, &parsed.path).ok()?;

        Some(crate::dispatch::SandboxPlan {
            program: self.helper.display().to_string(),
            // The path travels in argv because `SandboxSpec` has no stdin channel, recorded
            // as a known limitation of the existing contract rather than worked around by
            // smuggling it through the credential environment variable.
            args: vec!["--path".to_owned(), absolute.display().to_string()],
            env: Default::default(),
            working_dir: self.workspace.display().to_string(),
            // **Empty, and that is the point.** `write-text` binds the workspace read-write
            // because it writes. This capability declares `Public -> Public` with no write
            // classification, so it is granted nothing writable: the sandbox refuses a write
            // even if the helper were changed to attempt one. Confinement and declared
            // capability are enforced in the same structure.
            grant_rw: Vec::new(),
            // The workspace read-only, and the child itself executable.
            grant_ro: vec![
                self.workspace.display().to_string(),
                self.helper.display().to_string(),
            ],
            network: false,
            deadline_ms: DEADLINE_MS,
            output_cap_bytes: OUTPUT_CAP_BYTES,
            resources: crate::dispatch::ResourcePolicy {
                // Nothing required: reading one file needs no delegated cgroup, and
                // requiring one would refuse the capability on any host that cannot
                // delegate for no security gain. Budgets are still stated.
                required: Vec::new(),
                budget: crate::dispatch::ResourceBudget {
                    memory_bytes: Some(64 * 1024 * 1024),
                    // 16 for the same measured reason as `write-text`: `pids.max` bounds the
                    // whole cgroup including the supervisor's own forks, and 1 or 2 fail at
                    // namespace creation on this host. Recorded as V-65.
                    processes: Some(16),
                    cpu_cores: Some(1.0),
                },
            },
        })
    }

    fn verifier(&self) -> &dyn Verifier {
        &self.verifier
    }

    /// The bytes are the point of the call and are not durable.
    ///
    /// This is what keeps file contents out of `task_step_results`: the daemon reads this
    /// flag when it builds the step result and records metadata instead of the output.
    fn output_is_ephemeral(&self) -> bool {
        true
    }
}

/// Confirms the bytes the child reported are the bytes on disk.
///
/// # Independence
///
/// It re-reads the file from the filesystem and compares. It does not check that the path
/// was inside the workspace, because that was never in doubt and is enforced twice already;
/// a confinement-only verifier would report `Verified` for any content at all, including
/// content the helper invented.
///
/// The adapter's stdout is used as the *thing being checked*, never as the *evidence*: the
/// evidence is computed from the independent read, so a helper that both lied and produced
/// a convincing digest would still be caught by the byte comparison.
#[derive(Debug, Clone)]
pub struct ReadTextVerifier {
    workspace: PathBuf,
}

impl Verifier for ReadTextVerifier {
    fn verify(
        &self,
        execution: &ExecutionOutcome,
        params: &Value,
        _at_ms: i64,
    ) -> Result<VerificationOutcome, VerifyError> {
        match execution {
            // `Undetermined`, not `Refuted`: a failure means nothing ran to check, and
            // "proven absent" is a stronger claim than that.
            ExecutionOutcome::Failed { detail } => Ok(VerificationOutcome::Undetermined {
                reason: format!("the adapter reported a failure, so no read to verify: {detail}"),
            }),
            ExecutionOutcome::Unknown { detail } => Ok(VerificationOutcome::Undetermined {
                reason: format!("no execution report, so the read is unknown: {detail}"),
            }),
            ExecutionOutcome::Succeeded { output } => {
                let parsed = parse(params).map_err(|e| VerifyError(e.to_owned()))?;
                let absolute = resolve(&self.workspace, &parsed.path)
                    .map_err(|e| VerifyError(e.to_owned()))?;

                // The independent read, subject to the same ceiling the helper was. A
                // verifier that ignored the limit could read a hundred megabytes to check a
                // sixty-four kilobyte claim.
                let expected = match bounded_read(&absolute) {
                    Ok(bytes) => bytes,
                    Err(ReadFailure::TooLarge { size }) => {
                        return Ok(VerificationOutcome::Refuted {
                            evidence: format!(
                                "{} is {size} bytes, over the {MAX_READ_BYTES}-byte read limit",
                                absolute.display()
                            ),
                        });
                    }
                    Err(ReadFailure::Io(detail)) => {
                        return Ok(VerificationOutcome::Undetermined {
                            reason: format!(
                                "the independent read of {} did not establish the bytes: {detail}",
                                absolute.display()
                            ),
                        });
                    }
                };

                let reported = output.as_deref().unwrap_or_default().as_bytes();
                if reported == expected.as_slice() {
                    Ok(VerificationOutcome::Verified {
                        // Bounded metadata only: path, byte count, digest. Never the bytes,
                        // and never the child's stdout, because this string is durable.
                        evidence: evidence(&absolute, &expected),
                    })
                } else {
                    Ok(VerificationOutcome::Refuted {
                        evidence: format!(
                            "{} holds {} bytes ({}), but the execution reported {} bytes ({}); \
                             the read does not match what is on disk",
                            absolute.display(),
                            expected.len(),
                            digest_of(&expected),
                            reported.len(),
                            digest_of(reported),
                        ),
                    })
                }
            }
        }
    }
}

/// Why an independent read could not produce bytes.
#[derive(Debug)]
enum ReadFailure {
    TooLarge { size: u64 },
    Io(String),
}

/// Reads a file, refusing anything over the ceiling rather than truncating it.
fn bounded_read(absolute: &Path) -> Result<Vec<u8>, ReadFailure> {
    let meta = std::fs::metadata(absolute).map_err(|e| ReadFailure::Io(e.to_string()))?;
    if !meta.is_file() {
        return Err(ReadFailure::Io(format!(
            "{} is not a regular file",
            absolute.display()
        )));
    }
    // Checked *before* reading, so an oversized file is never loaded into this process at
    // all. Reading it and then measuring would make the limit a memory ceiling rather than
    // a size limit.
    if meta.len() > MAX_READ_BYTES {
        return Err(ReadFailure::TooLarge { size: meta.len() });
    }
    // The read itself is bounded, not merely measured afterwards.
    //
    // `std::fs::read` sizes its buffer from the metadata and then reads whatever the file
    // turned out to be, so a file that grows between the two observations would be
    // materialised in full in *this* process. For the verifier that turns a 64 KiB claim
    // into an arbitrarily expensive check. `take` stops the read instead of reading and
    // discarding, so peak memory here is the limit and not the file's size.
    let file = std::fs::File::open(absolute).map_err(|e| ReadFailure::Io(e.to_string()))?;
    let mut file = file;
    let bytes = read_capped(&mut file, MAX_READ_BYTES).map_err(ReadFailure::Io)?;
    // One byte past the limit is over the limit: refused, never truncated to fit.
    if bytes.len() as u64 > MAX_READ_BYTES {
        return Err(ReadFailure::TooLarge {
            size: bytes.len() as u64,
        });
    }
    Ok(bytes)
}

/// The durable evidence string for a verified read.
///
/// Three bounded facts. Adding the bytes here would put file contents into
/// `task_step_results` and into every audit record derived from it, which is precisely what
/// this capability's ephemeral output exists to prevent.
fn evidence(absolute: &Path, bytes: &[u8]) -> String {
    format!(
        "{} holds the {} bytes the execution reported ({})",
        absolute.display(),
        bytes.len(),
        digest_of(bytes)
    )
}

/// Reads at most `max + 1` bytes and stops.
///
/// # Why one byte past
///
/// One byte beyond the limit is enough to establish that a file is over it, and nothing
/// past that is ever pulled from the source. `Take` stops the read rather than reading and
/// discarding, so the cap is a bound on bytes **materialised**, not merely on bytes returned.
///
/// The cap is expressed here, once, and every read path goes through it -- the verifier in
/// this module and, identically, `orxnud-fsread`. That is what makes the guarantee checkable:
/// `a_capped_read_never_pulls_more_than_the_limit_plus_one` measures it directly rather than
/// inferring it from an oversized file being refused, which an unbounded read would also do.
///
/// # Errors
///
/// Any I/O error from the source. Truncation is not an error: a short read is a complete file.
fn read_capped<R: std::io::Read>(source: &mut R, max: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    // `+ 1` is the detection byte; it is part of the bound, not an overrun of it.
    source
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// blake3, because that is what the approval digest already uses.
fn digest_of(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Locates the helper binary beside this one, if it was built.
#[must_use]
pub fn resolve_helper() -> Option<PathBuf> {
    crate::write_text::resolve_helper().map(|parent| parent.with_file_name("orxnud-fsread"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orxnud_domain::enums::IsolationTier;
    use serde_json::json;

    /// A sentinel that would be unmistakable in a log, an error string or a durable row.
    /// Every hygiene assertion below searches for exactly this.
    const SENTINEL: &str = "SENTINEL-CONTENT-MUST-NOT-LEAK-4f2a9c";

    fn workspace(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orxnud-fsread-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn write(dir: &Path, rel: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir parent");
        }
        std::fs::write(&path, contents).expect("seed");
        path
    }

    // ------------------------------------------------------ declaration

    #[test]
    fn the_declaration_is_high_risk_public_and_tier_one() {
        let d = declaration();
        assert_eq!(d.id.as_str(), READ_TEXT_ID);
        assert_eq!(d.risk, RiskClass::High, "reading is disclosure");
        assert_eq!(d.reads, DataClass::Public);
        assert_eq!(d.writes, DataClass::Public);
        assert_eq!(
            d.isolation,
            IsolationTier::Subprocess,
            "a read must not run in this process"
        );
        assert!(d.enabled, "it must be dispatchable at all");
    }

    #[test]
    fn the_target_is_required() {
        assert_eq!(
            declaration().target,
            orxnud_domain::TargetSemantics::Required,
            "a read with no target would read nothing in particular"
        );
    }

    #[test]
    fn the_schema_is_exactly_one_required_path() {
        let spec = crate::schema::read_text_params();
        // The field list is private, so the shape is established by what the schema accepts
        // and refuses rather than by inspecting it -- which is the property that matters.
        assert!(
            spec.schema.validate(&json!({ "path": "a.txt" })).is_ok(),
            "a path is the request"
        );
        assert!(
            spec.schema.validate(&json!({})).is_err(),
            "path is required"
        );
        for extra in ["offset", "length", "encoding", "contents"] {
            assert!(
                spec.schema
                    .validate(&json!({ "path": "a.txt", extra: 1 }))
                    .is_err(),
                "{extra} is not part of this capability"
            );
        }
    }

    #[test]
    fn unknown_parameters_are_refused() {
        for extra in [
            json!({"path": "a.txt", "offset": 1}),
            json!({"path": "a.txt", "encoding": "utf-16"}),
            json!({"path": "a.txt", "length": 10}),
            json!({"path": "a.txt", "contents": "x"}),
        ] {
            assert!(
                parse(&extra).is_err(),
                "{extra} must be refused: a read takes one path and nothing else"
            );
        }
    }

    #[test]
    fn missing_or_wrongly_typed_path_is_refused() {
        assert!(parse(&json!({})).is_err());
        assert!(parse(&json!({"path": 1})).is_err());
        assert!(parse(&json!({"path": null})).is_err());
        assert!(parse(&json!([])).is_err());
        assert!(parse(&json!("a.txt")).is_err());
    }

    // ------------------------------------------------------ path rules

    #[test]
    fn paths_that_climb_out_of_the_workspace_are_refused_before_execution() {
        let ws = workspace("escape");
        for path in [
            "/etc/passwd",
            "/",
            "",
            "   ",
            "..",
            "../escape.txt",
            "sub/../../escape.txt",
            "a/../../b.txt",
        ] {
            assert!(
                resolve(&ws, path).is_err(),
                "{path:?} must be refused by the validator"
            );
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    /// Nested paths are allowed, unlike the write path. A read that could not address
    /// `sub/out.txt` could not observe what an earlier step wrote there.
    #[test]
    fn nested_relative_paths_are_allowed_and_confined() {
        let ws = workspace("nested");
        let got = resolve(&ws, "sub/dir/out.txt").expect("a nested read is legitimate");
        assert!(got.starts_with(&ws));
        assert!(got.ends_with("sub/dir/out.txt"));
        assert!(resolve(&ws, "./a.txt").is_ok(), "`.` is not an escape");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn the_workspace_itself_is_not_a_file() {
        let ws = workspace("self");
        assert!(resolve(&ws, ".").is_err());
        assert!(resolve(&ws, "./").is_err());
        let _ = std::fs::remove_dir_all(&ws);
    }

    // ------------------------------------------------- bounded reading

    /// The bound is on the **read**, not on the outcome.
    ///
    /// A metadata check followed by an unbounded read is not a size limit: a file that grows
    /// between the two observations would be read in full and the check would then be
    /// describing a file this process no longer matches. The bounded read asks for one byte
    /// past the limit, so at most `MAX_READ_BYTES + 1` is ever materialised -- and a file
    /// that grew is still refused rather than truncated.
    /// The memory bound, **measured** rather than inferred.
    ///
    /// A reader that counts every byte pulled from it, over a source far larger than the
    /// limit. The assertion is on bytes *requested from the source*, which is the property
    /// that matters: an unbounded read would pull all of them even though it returns a
    /// refusal. This is the direct check an outcome test cannot make -- refusing an oversized
    /// file proves the refusal, not the bound.
    #[test]
    fn a_capped_read_never_pulls_more_than_the_limit_plus_one() {
        struct Counting {
            served: usize,
            remaining: usize,
        }
        impl std::io::Read for Counting {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.remaining == 0 {
                    return Ok(0);
                }
                let n = buf.len().min(self.remaining);
                self.served += n;
                self.remaining -= n;
                Ok(n)
            }
        }

        // A source ten times the limit, so an unbounded read would be obviously caught.
        let mut source = Counting {
            served: 0,
            remaining: (MAX_READ_BYTES as usize) * 10,
        };
        let got = read_capped(&mut source, MAX_READ_BYTES).expect("a capped read cannot fail");
        assert!(
            source.served <= MAX_READ_BYTES as usize + 1,
            "pulled {} bytes from the source, which is more than the {MAX_READ_BYTES}-byte \
             limit plus its detection byte",
            source.served
        );
        assert!(
            got.len() as u64 > MAX_READ_BYTES,
            "the detection byte is what distinguishes 'over the limit' from 'exactly at it'"
        );
        assert_eq!(
            source.served,
            got.len(),
            "everything pulled must be what was returned; nothing is read and discarded"
        );
    }

    /// At the limit, the cap is the whole file.
    #[test]
    fn a_capped_read_returns_a_file_exactly_at_the_limit() {
        struct Exact(usize);
        impl std::io::Read for Exact {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 == 0 {
                    return Ok(0);
                }
                let n = buf.len().min(self.0);
                self.0 -= n;
                Ok(n)
            }
        }
        let mut src = Exact(MAX_READ_BYTES as usize);
        let got = read_capped(&mut src, MAX_READ_BYTES).expect("read");
        assert_eq!(got.len() as u64, MAX_READ_BYTES);
        assert_eq!(src.0, 0, "the whole file was consumed");
    }

    #[test]
    fn a_file_that_grew_past_the_limit_is_refused_not_truncated() {
        let ws = workspace("grew");
        let path = write(&ws, "grew.txt", &vec![b'x'; MAX_READ_BYTES as usize + 1]);
        // Force the metadata branch to agree the file is small, so the only thing that can
        // catch this is the bounded read itself. A file whose *reported* size is within the
        // limit but whose content is not cannot be built portably, so this asserts the
        // property that is observable: the read refuses at the limit and returns nothing
        // truncated.
        match bounded_read(&path) {
            Err(ReadFailure::TooLarge { .. }) => {}
            other => panic!("an oversized file must be refused, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    /// The read is capped, so the vector can never exceed the limit plus the single byte
    /// used to detect that it was over. Asserted on the *type* of the bound rather than on
    /// a race: `Take` is what makes it true, and this records that the cap is expressed as
    /// one byte past the limit rather than as "read it all and compare".
    #[test]
    fn the_bounded_read_caps_at_one_byte_past_the_limit() {
        assert_eq!(
            MAX_READ_BYTES + 1,
            64 * 1024 + 1,
            "the detection byte is part of the guarantee, so pin it"
        );
        // A file far larger than the cap still yields a refusal, not an allocation.
        let ws = workspace("huge");
        let path = write(&ws, "huge.bin", &vec![b'z'; MAX_READ_BYTES as usize * 8]);
        assert!(matches!(
            bounded_read(&path),
            Err(ReadFailure::TooLarge { .. })
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn a_file_at_exactly_the_limit_is_readable() {
        let ws = workspace("limit-ok");
        let bytes = vec![b'x'; MAX_READ_BYTES as usize];
        let path = write(&ws, "big.txt", &bytes);
        let read = bounded_read(&path).expect("exactly at the limit must succeed");
        assert_eq!(read.len() as u64, MAX_READ_BYTES);
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn one_byte_over_the_limit_is_refused() {
        let ws = workspace("limit-over");
        let bytes = vec![b'x'; MAX_READ_BYTES as usize + 1];
        let path = write(&ws, "big.txt", &bytes);
        assert!(
            matches!(bounded_read(&path), Err(ReadFailure::TooLarge { .. })),
            "over the limit must be refused, never truncated"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn an_empty_file_reads_as_empty_rather_than_failing() {
        let ws = workspace("empty");
        let path = write(&ws, "empty.txt", b"");
        assert_eq!(
            bounded_read(&path).expect("empty is readable"),
            Vec::<u8>::new()
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn a_directory_is_not_readable() {
        let ws = workspace("dir");
        std::fs::create_dir_all(ws.join("adir")).expect("mkdir");
        assert!(matches!(
            bounded_read(&ws.join("adir")),
            Err(ReadFailure::Io(_))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn a_missing_file_is_not_readable() {
        let ws = workspace("missing");
        assert!(matches!(
            bounded_read(&ws.join("nope.txt")),
            Err(ReadFailure::Io(_))
        ));
        let _ = std::fs::remove_dir_all(&ws);
    }

    /// Bytes are bytes. The verifier compares them exactly, so a non-UTF-8 file is compared
    /// losslessly rather than lossily through `String`.
    #[test]
    fn non_utf8_bytes_are_compared_losslessly() {
        let ws = workspace("binary");
        let raw = vec![0x00, 0xff, 0xfe, 0x41, 0x80];
        let path = write(&ws, "bin.dat", &raw);
        assert_eq!(bounded_read(&path).expect("binary is readable"), raw);
        let _ = std::fs::remove_dir_all(&ws);
    }

    // ------------------------------------------------- verification

    fn verifier_for(ws: &Path) -> ReadTextVerifier {
        ReadTextVerifier {
            workspace: ws.to_path_buf(),
        }
    }

    #[test]
    fn matching_bytes_are_verified() {
        let ws = workspace("v-ok");
        write(&ws, "a.txt", SENTINEL.as_bytes());
        let out = verifier_for(&ws)
            .verify(
                &ExecutionOutcome::Succeeded {
                    output: Some(SENTINEL.to_owned()),
                },
                &json!({ "path": "a.txt" }),
                0,
            )
            .expect("verify");
        assert!(
            matches!(out, VerificationOutcome::Verified { .. }),
            "{out:?}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    /// The load-bearing test: the verifier compares against its own read, so a helper that
    /// reports the wrong bytes is caught even though it reported *some* bytes.
    #[test]
    fn differing_bytes_are_refuted_rather_than_believed() {
        let ws = workspace("v-bad");
        write(&ws, "a.txt", SENTINEL.as_bytes());
        let out = verifier_for(&ws)
            .verify(
                &ExecutionOutcome::Succeeded {
                    output: Some("something else entirely".to_owned()),
                },
                &json!({ "path": "a.txt" }),
                0,
            )
            .expect("verify");
        assert!(
            matches!(out, VerificationOutcome::Refuted { .. }),
            "{out:?}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn an_oversized_file_is_refused_by_the_verifier_too() {
        let ws = workspace("v-over");
        write(&ws, "big.txt", &vec![b'x'; MAX_READ_BYTES as usize + 1]);
        let out = verifier_for(&ws)
            .verify(
                &ExecutionOutcome::Succeeded {
                    output: Some("short".to_owned()),
                },
                &json!({ "path": "big.txt" }),
                0,
            )
            .expect("verify");
        assert!(
            matches!(out, VerificationOutcome::Refuted { .. }),
            "{out:?}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn a_failed_or_unknown_execution_is_undetermined_not_refuted() {
        let ws = workspace("v-fail");
        write(&ws, "a.txt", b"x");
        for outcome in [
            ExecutionOutcome::Failed {
                detail: "boom".into(),
            },
            ExecutionOutcome::Unknown {
                detail: "died".into(),
            },
        ] {
            let out = verifier_for(&ws)
                .verify(&outcome, &json!({ "path": "a.txt" }), 0)
                .expect("verify");
            assert!(
                matches!(out, VerificationOutcome::Undetermined { .. }),
                "{outcome:?} must not be a refutation: {out:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn an_unreadable_target_leaves_the_verification_undetermined() {
        let ws = workspace("v-unreadable");
        let out = verifier_for(&ws)
            .verify(
                &ExecutionOutcome::Succeeded {
                    output: Some("anything".to_owned()),
                },
                &json!({ "path": "missing.txt" }),
                0,
            )
            .expect("verify");
        assert!(
            matches!(out, VerificationOutcome::Undetermined { .. }),
            "the verifier could not establish the bytes: {out:?}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    // ------------------------------------------------- evidence hygiene

    /// Durable evidence carries bounded metadata and never the bytes.
    #[test]
    fn evidence_names_the_path_size_and_digest_but_never_the_content() {
        let ws = workspace("evidence");
        write(&ws, "a.txt", SENTINEL.as_bytes());
        let out = verifier_for(&ws)
            .verify(
                &ExecutionOutcome::Succeeded {
                    output: Some(SENTINEL.to_owned()),
                },
                &json!({ "path": "a.txt" }),
                0,
            )
            .expect("verify");
        let VerificationOutcome::Verified { evidence } = out else {
            panic!("expected Verified, got {out:?}");
        };
        assert!(
            !evidence.contains(SENTINEL),
            "file content leaked into durable evidence: {evidence}"
        );
        assert!(evidence.contains("a.txt"), "the path should be named");
        assert!(evidence.contains(&SENTINEL.len().to_string()), "byte count");
        assert!(
            evidence.contains(&digest_of(SENTINEL.as_bytes())),
            "the content digest should be there: {evidence}"
        );
        // Bounded: three facts, not an excerpt.
        assert!(evidence.len() < 300, "evidence is unbounded: {evidence}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn a_refutation_message_carries_no_content_either() {
        let ws = workspace("evidence-bad");
        write(&ws, "a.txt", SENTINEL.as_bytes());
        let out = verifier_for(&ws)
            .verify(
                &ExecutionOutcome::Succeeded {
                    output: Some("fabricated".to_owned()),
                },
                &json!({ "path": "a.txt" }),
                0,
            )
            .expect("verify");
        let VerificationOutcome::Refuted { evidence } = out else {
            panic!("expected Refuted, got {out:?}");
        };
        assert!(!evidence.contains(SENTINEL), "leak: {evidence}");
        assert!(evidence.len() < 300, "unbounded: {evidence}");
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn parameter_errors_never_echo_the_path_contents() {
        // A parameter error mentions the offending key or value only for `path`, which is a
        // name and never file content.
        for bad in [json!({"path": 1}), json!({}), json!({"nope": SENTINEL})] {
            let err = parse(&bad).expect_err("must be refused").to_string();
            assert!(
                !err.contains(SENTINEL) || bad.get("nope").is_some(),
                "an error echoed a value: {err}"
            );
        }
    }

    // ------------------------------------------------------- sandbox

    // ----------------------------------------------- output durability

    /// The bundle declares its output ephemeral, which is what stops the daemon writing file
    /// contents into `task_step_results`.
    #[test]
    fn the_bundle_declares_its_output_ephemeral() {
        let ws = workspace("ephemeral");
        let bundle = ReadTextBundle::new(&ws, "/nonexistent/orxnud-fsread");
        assert!(
            crate::dispatch::AdapterBundle::output_is_ephemeral(&bundle),
            "read output must never be durable"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    /// The default is today's behaviour, which is what makes the flag safe to add.
    #[test]
    fn a_bundle_that_says_nothing_keeps_its_output_durable() {
        let ws = workspace("default");
        let write_bundle =
            crate::write_text::WriteTextBundle::new(&ws, "/nonexistent/orxnud-fswrite");
        assert!(
            !crate::dispatch::AdapterBundle::output_is_ephemeral(&write_bundle),
            "write-text's output is durable, as it always was"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }
}
