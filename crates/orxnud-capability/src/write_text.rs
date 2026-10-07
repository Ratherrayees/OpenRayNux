//! `filesystem/write-text` — the first capability with a real side effect.
//!
//! # Why this capability exists
//!
//! `text/word-count` proved the governed path *reaches* an adapter. It could not prove
//! the path *governs* anything, because counting words has no world to govern: it
//! cannot be refused after the fact, it leaves nothing behind, and a bug in it is a
//! wrong number rather than a changed system. This one writes a file. Everything the
//! architecture claims about itself becomes observable here or nowhere:
//!
//! ```text
//! policy -> approval -> parameter-bound authorisation
//!        -> Tier-1 sandbox execution -> independent verification -> durable audit
//! ```
//!
//! # The contract
//!
//! Input:
//!
//! ```json
//! { "path": "notes/today.txt", "contents": "hello" }
//! ```
//!
//! `path` is a **single file name inside the sandbox-controlled workspace**, never a
//! path. That is a deliberate narrowing on two counts. An absolute path is a request to
//! name a location, and naming locations outside the workspace is precisely what this
//! capability must not be able to ask for. A *relative* path with a separator is a
//! request to create directories, which is a second capability wearing a first one's
//! name -- and this one does not create directories, so honouring such a path would
//! mean `resolve` promising a file the execution cannot deliver.
//!
//! There is no flag, option or parameter that widens either, because a capability whose
//! escape is available behind a flag is a capability with an escape.
//!
//! `contents` is the exact text to write. It is written as bytes and never interpreted:
//! no shell, no redirection, no expansion. See `src/bin/orxnud-fswrite.rs`.
//!
//! # Why High risk
//!
//! Because it changes the world outside the process. `RiskClass::High` means policy
//! refuses the call unless a single-use, time-boxed, parameter-bound approval is
//! presented — so reaching the sandbox at all requires an approval that was issued for
//! *these* parameters. That is the property this capability exists to demonstrate, and
//! it is why this module is deliberately the narrowest possible side effect: one file,
//! inside a directory the daemon owns, with no deletion, no copy, no permission change
//! and no directory traversal.
//!
//! # Where the boundary actually is
//!
//! Two independent layers, and the distinction matters:
//!
//! * **Validation** ([`resolve`]) rejects a path that climbs out of the workspace as a
//!   *lexical* matter, before anything runs. It is there so the refusal is legible.
//! * **The sandbox** is what makes the boundary real. It gives the child a tmpfs root
//!   and binds only the workspace read-write, so a path that escaped anyway would
//!   resolve to a location that does not exist inside the sandbox. The escape test
//!   therefore asserts that the file does not appear outside the workspace, which is a
//!   property of the sandbox and not of this function.
//!
//! # Idempotence
//!
//! Declared **not** idempotent. Writing the same contents to the same path twice
//! happens to leave the same bytes, but the capability offers no compare-before-write
//! and no way to promise the second call was a no-op, so an uncertain outcome must be
//! treated as uncertain rather than retried blindly.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use orxnud_domain::enums::{DataClass, IsolationTier, RiskClass};
use orxnud_domain::ids::CapabilityId;
use orxnud_policy::authority::{CapabilityInvocation, DispatchView};

use crate::dispatch::{
    AdapterBundle, CapabilityAdapter, ExecutionTier, ResourceBudget, ResourcePolicy, SandboxPlan,
};
use crate::verification::{ExecutionOutcome, VerificationOutcome, Verifier, VerifyError};

/// The id this capability is registered under.
pub const WRITE_TEXT_ID: &str = "filesystem/write-text";

/// How long the sandboxed child may run.
///
/// Generous for writing one file, and still bounded: an unbounded deadline would let a
/// wedged child hold the dispatch lock, and the lock is the daemon's single writer.
const DEADLINE_MS: u64 = 10_000;

/// The child's stdout/stderr cap, per stream.
///
/// The child writes nothing to stdout by design, so this is a backstop rather than a
/// budget it expects to use.
const OUTPUT_CAP_BYTES: u64 = 64 * 1024;

/// The declaration.
#[must_use]
pub fn declaration() -> crate::CapabilityDeclaration {
    crate::CapabilityDeclaration::new(
        CapabilityId::new(WRITE_TEXT_ID),
        "Write a text file inside the sandbox workspace",
    )
    .with_risk(RiskClass::High)
    .with_data(DataClass::Public, DataClass::Public)
    .with_isolation(IsolationTier::Subprocess)
    .with_params(crate::schema::write_text_params())
    .with_target(orxnud_domain::TargetSemantics::Required)
    // Deliberately absent: `.idempotent()`. See the module docs.
    .enabled()
}

/// The validated parameters of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteText {
    /// The workspace-relative path.
    pub path: String,
    /// The exact text to write.
    pub contents: String,
}

/// Reads and validates the parameters.
///
/// Errors are specific about *which* field was wrong, because "invalid params" on a
/// capability whose whole job is writing a file is useless to whoever has to fix the
/// call. Nothing here consults the filesystem: validation must not depend on state the
/// sandbox controls, or the two layers would not be independent.
pub fn parse(params: &Value) -> Result<WriteText, String> {
    let object = params
        .as_object()
        .ok_or_else(|| "params must be a JSON object".to_owned())?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| "`path` must be a string".to_owned())?;
    let contents = object
        .get("contents")
        .and_then(Value::as_str)
        .ok_or_else(|| "`contents` must be a string".to_owned())?;
    // An unrecognised field is refused rather than ignored. A caller that sends a field
    // this capability does not read has misunderstood the request, and ignoring it would
    // perform a *different* operation from the one described -- the shape check in
    // `schema.rs` refuses it too, and this is the layer that still holds when a proposal
    // reaches execution without passing through the proposer.
    for key in object.keys() {
        if key != "path" && key != "contents" {
            return Err(format!("`{key}` is not a parameter of this capability"));
        }
    }
    if path.is_empty() {
        return Err("`path` must not be empty".to_owned());
    }
    // An absolute path is refused rather than reinterpreted as workspace-relative.
    // Silently turning `/etc/passwd` into `workspace/etc/passwd` would report success
    // for an operation the caller did not ask for, which is worse than refusing.
    if Path::new(path).is_absolute() {
        return Err(format!(
            "`path` must be relative to the workspace; an absolute path ({path:?}) \
             names a location this capability cannot write"
        ));
    }
    // One file name, no directories. Checked on the components rather than on the
    // string so `a/b.txt`, `./a.txt` and a trailing slash are all caught the same way,
    // and so a Windows separator is caught on Windows rather than being smuggled
    // through as a literal character in a file name.
    let components: Vec<_> = Path::new(path).components().collect();
    if components.len() != 1 {
        return Err(format!(
            "`path` must be a single file name in the workspace root, not a path: \
             {path:?}. This capability writes one file and creates no directories"
        ));
    }
    if !matches!(components[0], Component::Normal(_)) {
        return Err(format!("`path` must name a file, got {path:?}"));
    }
    Ok(WriteText {
        path: path.to_owned(),
        contents: contents.to_owned(),
    })
}

/// Resolves a workspace-relative path to an absolute one inside `workspace`.
///
/// The lexical part of the boundary. A `..` that would leave the workspace is refused
/// here so the caller gets a reason; the sandbox is what would stop it regardless.
pub fn resolve(workspace: &Path, path: &str) -> Result<PathBuf, String> {
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
    // A resolved path with more than the workspace's own name appended would mean a
    // separator survived `parse`. Reaching here is a bug rather than a request, so it
    // is refused loudly instead of quietly writing somewhere deeper than promised.
    if out
        .strip_prefix(workspace)
        .map_or(true, |rest| rest.components().count() != 1)
    {
        return Err(format!(
            "`path` must be a single file name in the workspace root, not a path: {path:?}"
        ));
    }
    Ok(out)
}

/// The adapter.
///
/// # Why `invoke` refuses
///
/// A Tier-1 adapter's `invoke` is never called: the dispatcher builds a contract from
/// the bundle's [`AdapterBundle::sandbox_plan`] and hands that to the execution
/// backend. So this body is unreachable in normal operation, and it refuses rather
/// than writing anything for two reasons. If it wrote the file it would be a working
/// in-process implementation of a Tier-1 capability, which is the exact bypass the
/// tier exists to close — and the refusal means that if some future change ever routed
/// a Subprocess adapter here, the result is a refusal rather than an unsandboxed write.
#[derive(Debug, Default, Clone, Copy)]
pub struct WriteTextAdapter;

impl CapabilityAdapter for WriteTextAdapter {
    fn capability_id(&self) -> &CapabilityId {
        // A const promotion, so the bundle can hand out a `&'static` id without
        // owning one per call.
        static ID: std::sync::OnceLock<CapabilityId> = std::sync::OnceLock::new();
        ID.get_or_init(|| CapabilityId::new(WRITE_TEXT_ID))
    }

    fn declared_class(&self) -> DataClass {
        DataClass::Public
    }

    fn tier(&self) -> ExecutionTier {
        ExecutionTier::Subprocess
    }

    fn invoke(
        &self,
        _view: &DispatchView<'_>,
        _credential: Option<&crate::credential::CredentialHandle>,
    ) -> Result<ExecutionOutcome, String> {
        Err(format!(
            "{WRITE_TEXT_ID} is Tier-1 and runs in the sandbox, never in this process"
        ))
    }
}

/// The adapter, its plan and its verifier.
///
/// Owns the workspace because both the plan and the verifier need it, and because the
/// two must agree on *which* absolute path a relative parameter denotes. If they
/// resolved independently they could disagree, and a verifier reading a different file
/// than the writer wrote would report `Refuted` for a correct write — or worse, read a
/// file the write never touched and call it `Verified`.
#[derive(Debug, Clone)]
pub struct WriteTextBundle {
    workspace: PathBuf,
    helper: PathBuf,
    /// Held rather than built per call because [`AdapterBundle::verifier`] returns a
    /// borrow, and constructing one on demand would return a reference to a temporary.
    /// It shares `workspace` by clone, so it cannot drift from what the plan granted.
    verifier: WriteTextVerifier,
}

impl WriteTextBundle {
    /// Binds the bundle to a workspace and the child to run in it.
    ///
    /// No defaults and no discovery: a caller that has not established a workspace has
    /// not established where it is allowed to write, and guessing would be the bug.
    #[must_use]
    pub fn new(workspace: impl Into<PathBuf>, helper: impl Into<PathBuf>) -> Self {
        let workspace = workspace.into();
        Self {
            verifier: WriteTextVerifier {
                workspace: workspace.clone(),
            },
            workspace,
            helper: helper.into(),
        }
    }

    /// The workspace this bundle writes into.
    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
}

impl AdapterBundle for WriteTextBundle {
    fn adapter(&self) -> &dyn CapabilityAdapter {
        &WriteTextAdapter
    }

    /// The plan for one invocation.
    ///
    /// This is the only route by which the parameters reach the sandboxed child,
    /// because a Tier-1 adapter's `invoke` is not called. Returning `None` here — or a
    /// plan that ignores `invocation` — would produce a child with no idea what to
    /// write, so an error here is a refusal of the whole dispatch rather than a
    /// fallback to something that merely runs.
    fn sandbox_plan(&self, invocation: &CapabilityInvocation) -> Option<SandboxPlan> {
        let parsed = parse(invocation.params()).ok()?;
        let absolute = resolve(&self.workspace, &parsed.path).ok()?;

        Some(SandboxPlan {
            program: self.helper.display().to_string(),
            // The contents travel in argv because `SandboxSpec` has no stdin channel.
            // Recorded as a known limitation rather than worked around by smuggling
            // data through the credential environment variable, which is redacted for
            // credentials and would be a far worse place to put a payload.
            args: vec![
                "--path".to_owned(),
                absolute.display().to_string(),
                "--contents".to_owned(),
                parsed.contents,
            ],
            // Empty on purpose: a child that needs nothing from the environment should
            // not be offered any.
            env: Default::default(),
            working_dir: self.workspace.display().to_string(),
            // The whole workspace, read-write. Not the single target file: the sandbox
            // binds directories, and granting only the file would not stop a child
            // creating siblings.
            grant_rw: vec![self.workspace.display().to_string()],
            // The child must be executable inside the sandbox, and the sandbox root is a
            // tmpfs that hides everything not bound. Without this the exec fails and the
            // capability is unrunnable rather than unsafe.
            grant_ro: vec![self.helper.display().to_string()],
            network: false,
            deadline_ms: DEADLINE_MS,
            output_cap_bytes: OUTPUT_CAP_BYTES,
            resources: ResourcePolicy {
                // Nothing is *required*: this capability needs no delegated cgroup to
                // write one file, and requiring one would refuse the capability on any
                // host that cannot delegate, for no security gain. Budgets are still
                // stated, so a host that offers the controls has them bounded.
                required: Vec::new(),
                budget: ResourceBudget {
                    memory_bytes: Some(64 * 1024 * 1024),
                    // 16, not 1, and the number is worth understanding.
                    //
                    // `pids.max` bounds the whole cgroup, and the cgroup holds the
                    // sandbox supervisor's own process tree as well as the payload:
                    // bwrap forks to set up namespaces, then forks again for pid 1.
                    // Measured on this host, `pids.max = 1` fails at namespace creation
                    // with EAGAIN and `= 2` fails at "Can't fork for pid 1"; 4 is the
                    // floor and anything at or above it runs.
                    //
                    // So this ceiling is "processes this invocation may use", where
                    // "this invocation" includes the machinery that runs it. 1 would be
                    // the tidier-looking number and is the one that does not work. 16
                    // keeps a runaway fork loop bounded to almost nothing while leaving
                    // headroom for a supervisor that grows a task or two -- a ceiling set
                    // exactly at the floor turns a future sandbox change into an opaque
                    // capability failure. Recorded as V-65.
                    processes: Some(16),
                    cpu_cores: Some(1.0),
                },
            },
        })
    }

    fn verifier(&self) -> &dyn Verifier {
        &self.verifier
    }
}

/// Confirms the file exists with exactly the requested contents.
///
/// # Independence
///
/// It re-reads the file from the filesystem. It does not parse the child's stdout, not
/// because the child avoids printing (it does) but because a writer reporting what it
/// wrote is the writer marking its own homework — the same defect V-60 describes for
/// the in-process verifier. The independent route here is the only one that exists for
/// a filesystem effect: read the filesystem again.
///
/// The bound on that independence is the shared [`resolve`]. Both sides must agree on
/// which absolute path a relative name denotes, so a wrong `resolve` would make the
/// verifier read the wrong file and could report `Verified` for a write that landed
/// elsewhere. That is a narrower risk than a shared algorithm — `resolve` is a path
/// join, not a reimplementation of the effect — but it is a real one and is stated
/// rather than glossed.
#[derive(Debug, Clone)]
pub struct WriteTextVerifier {
    workspace: PathBuf,
}

impl Verifier for WriteTextVerifier {
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
                reason: format!("the adapter reported a failure, so no write to verify: {detail}"),
            }),
            // Same reasoning for an unknown outcome, and it is the more important of the
            // two here: a subprocess can die *after* writing, so this genuinely may have
            // happened.
            ExecutionOutcome::Unknown { detail } => Ok(VerificationOutcome::Undetermined {
                reason: format!("no execution report, so the write is unknown: {detail}"),
            }),
            ExecutionOutcome::Succeeded { .. } => {
                let parsed = parse(params).map_err(|e| VerifyError(e.to_owned()))?;
                let absolute = resolve(&self.workspace, &parsed.path)
                    .map_err(|e| VerifyError(e.to_owned()))?;

                // Read the bytes rather than asking whether a write happened. A missing
                // file is `Refuted` — proven absent — which is the state that makes a
                // retry safe, and only `Refuted` makes it safe.
                match std::fs::read(&absolute) {
                    Ok(bytes) => {
                        if bytes == parsed.contents.as_bytes() {
                            Ok(VerificationOutcome::Verified {
                                evidence: format!(
                                    "{} holds the {} requested bytes",
                                    absolute.display(),
                                    bytes.len()
                                ),
                            })
                        } else {
                            Ok(VerificationOutcome::Refuted {
                                evidence: format!(
                                    "{} exists but holds {} bytes, not the {} requested",
                                    absolute.display(),
                                    bytes.len(),
                                    parsed.contents.len()
                                ),
                            })
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        Ok(VerificationOutcome::Refuted {
                            evidence: format!("{} does not exist", absolute.display()),
                        })
                    }
                    Err(e) => {
                        // A file that exists but cannot be read is *unknown*, not absent:
                        // claiming it was never written would invite a retry onto a path
                        // that may already hold the effect.
                        Ok(VerificationOutcome::Undetermined {
                            reason: format!("{} could not be read: {e}", absolute.display()),
                        })
                    }
                }
            }
        }
    }
}

/// Finds the Tier-1 child next to a running executable.
///
/// A one-line delegation on purpose. The two questions this needs answered -- what a
/// runnable file is called here, and whether a file is runnable at all -- are OS
/// questions, and `orxnud-platform-fs` is the crate whose entire purpose is to answer
/// them in one place. Reimplementing either here would put an OS opinion in a portable
/// crate, which is precisely what gate G3 exists to prevent.
///
/// No environment override, deliberately: see `orxnud_platform_fs::sibling_executable`,
/// which explains
/// why a variable naming the child would be a redirection of the capability rather than
/// a convenience.
#[must_use]
pub fn resolve_helper() -> Option<PathBuf> {
    orxnud_platform_fs::sibling_executable("orxnud-fswrite")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declaration_is_high_risk_subprocess_and_not_idempotent() {
        let d = declaration();
        assert_eq!(d.risk, RiskClass::High);
        assert!(
            d.risk.requires_approval(),
            "High risk must demand an approval"
        );
        assert_eq!(d.isolation, IsolationTier::Subprocess);
        assert_eq!(WriteTextAdapter.tier(), ExecutionTier::Subprocess);
        assert!(
            !d.idempotent,
            "an uncertain write must not be declared safe to retry"
        );
        assert!(d.enabled);
    }

    #[test]
    fn the_adapter_refuses_to_run_in_process() {
        let params = serde_json::json!({"path": "a.txt", "contents": "x"});
        // The view now comes from a real policy authorisation rather than a literal:
        // `DispatchView`'s fields are private because they are the argument to
        // capability execution, and a hand-built one would reopen that door.
        let outcome = crate::suites::support::with_dispatch_view(WRITE_TEXT_ID, &params, |view| {
            WriteTextAdapter.invoke(view, None)
        });
        assert!(
            outcome.is_err(),
            "an in-process write would be the tier bypass; it must refuse"
        );
    }

    #[test]
    fn parameters_are_validated_by_field() {
        let ok = parse(&serde_json::json!({"path": "a.txt", "contents": "x"})).expect("valid");
        assert_eq!(
            ok,
            WriteText {
                path: "a.txt".to_owned(),
                contents: "x".to_owned()
            }
        );

        for (params, why) in [
            (serde_json::json!({}), "missing both fields"),
            (serde_json::json!({"path": "a.txt"}), "missing contents"),
            (serde_json::json!({"contents": "x"}), "missing path"),
            (
                serde_json::json!({"path": 1, "contents": "x"}),
                "path not a string",
            ),
            (
                serde_json::json!({"path": "a.txt", "contents": 2}),
                "contents not a string",
            ),
            (
                serde_json::json!({"path": "", "contents": "x"}),
                "empty path",
            ),
            (serde_json::json!("not an object"), "params not an object"),
            (serde_json::json!([1, 2]), "params an array"),
        ] {
            assert!(parse(&params).is_err(), "{why} must be refused");
        }
    }

    #[test]
    fn an_absolute_path_is_refused_rather_than_reinterpreted() {
        // The important half: not "silently made workspace-relative", which would
        // report success for an operation the caller did not ask for.
        assert!(parse(&serde_json::json!({"path": "/etc/passwd", "contents": "x"})).is_err());
        assert!(parse(&serde_json::json!({"path": "/tmp/x", "contents": "x"})).is_err());
    }

    #[test]
    fn resolution_stays_inside_the_workspace() {
        let ws = Path::new("/w");
        assert_eq!(
            resolve(ws, "a.txt").expect("plain"),
            PathBuf::from("/w/a.txt")
        );
        assert_eq!(
            resolve(ws, "./a.txt").expect("curdir is a no-op"),
            PathBuf::from("/w/a.txt")
        );

        // A separator is refused by `parse`, and `resolve` refuses it independently, so
        // neither layer depends on the other having run.
        // A trailing slash is not a directory request: `Path` normalises `a/` to the
        // single name `a`, so it names a file called `a`. Worth stating because it looks
        // like the opposite and a future reader would reasonably assume otherwise.
        assert_eq!(
            resolve(ws, "a/").expect("trailing slash"),
            PathBuf::from("/w/a")
        );
        for nested in ["nested/a.txt", "a/b.txt"] {
            assert!(
                resolve(ws, nested).is_err(),
                "{nested:?} is a directory request, not a file name"
            );
        }
        for escape in ["../outside.txt", "a/../../outside.txt", "..", "a/../.."] {
            assert!(
                resolve(ws, escape).is_err(),
                "{escape:?} must not resolve inside the workspace"
            );
        }
        assert!(
            resolve(ws, "").is_err(),
            "the workspace itself is not a file"
        );
    }

    #[test]
    fn contents_are_never_interpreted() {
        // Whatever a caller puts in `contents` is data. If any of this were ever
        // expanded, the capability would be a shell.
        let nasty = "$(touch /tmp/pwned); `id` && rm -rf / | tee\nnewline";
        let parsed = parse(&serde_json::json!({"path": "a.txt", "contents": nasty}))
            .expect("shell metacharacters are not a validation error");
        assert_eq!(parsed.contents, nasty);
    }
}
