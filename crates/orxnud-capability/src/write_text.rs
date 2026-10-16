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

use crate::dispatch::PlanError;
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
/// the bundle's `AdapterBundle::sandbox_plan` and hands that to the execution
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
    /// Still [`crate::dispatch::ArgvPayload::Content`] — and **no longer because of
    /// `argv`**.
    ///
    /// This declaration used to describe a mechanism: `sandbox_plan` put the file's
    /// contents in `args` (`--contents <text>`), those arguments reached `bwrap`'s
    /// command line, and `/proc/<pid>/cmdline` is mode `0444` (V-67, measured
    /// 2026-10-10). ADR-0054 removed that mechanism — the body now travels as a framed
    /// payload on the child's stdin, and `args` carries only `--path` and the transport
    /// version — so the honest description of *this function* is `None`.
    ///
    /// It stays `Content` anyway, deliberately, and the reason is a governance one rather
    /// than a descriptive one: **ADR-0054 Decision 7 keeps the refusal until all four of
    /// R-1's evidence conditions pass**, and one of them — the credential sentinel — is
    /// still unreachable while credential-bearing Tier-1 capabilities remain prohibited
    /// (Decision 5). Answering `None` here would silently re-enable `write-text` on the
    /// default posture, and the interim control would disappear as a side effect of the
    /// fix rather than by a decision anyone made.
    ///
    /// **So this answer is a switch that is held on, and it should say so loudly.** It
    /// stops being `Content` the moment Decision 7's conditions are met — and it stops
    /// being right the moment a future change puts user content back into `args`, which
    /// is the failure it would then correctly catch.
    ///
    /// **No bound is claimed**, because the payload no longer passes through here at
    /// all: the bound is `stdin_frame::MAX_PAYLOAD_BYTES` (1 MiB), enforced in
    /// `sandbox_plan` before this bundle produces a plan, and it is counted in UTF-8
    /// bytes of the normalised `contents`.
    ///
    /// The historical `MAX_ARG_STRLEN` figure no longer applies to this capability: that
    /// was the host kernel's ceiling on a single `argv` string (131072 on a 4 KiB page,
    /// 2097152 on a 64 KiB one) and nothing here is an `argv` string any more.
    fn argv_payload(&self) -> crate::dispatch::ArgvPayload {
        crate::dispatch::ArgvPayload::Content {
            implementation_bound: None,
        }
    }
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
    fn sandbox_plan(
        &self,
        invocation: &CapabilityInvocation,
    ) -> Result<Option<SandboxPlan>, PlanError> {
        // Both refusals are the caller's parameters, and both already carry a precise
        // reason from `parse`/`resolve`.
        //
        // These were `.ok()?`, which discarded those reasons and reported a bare `None`.
        // The dispatcher read `None` as "this adapter declares no sandbox plan", so a
        // traversing or absolute path — refused correctly, with nothing written — was
        // reported to the operator as *"the execution backend cannot establish the
        // required sandbox guarantees (missing: a sandbox plan)"*. That is false on any
        // host where the sandbox is working, which this one demonstrably was: a
        // `write-text` had completed seconds earlier. It also sent the reader to the
        // wrong layer entirely, checking bubblewrap and user namespaces for what was a
        // malformed argument.
        let parsed = parse(invocation.params()).map_err(PlanError::InvalidParams)?;
        let absolute = resolve(&self.workspace, &parsed.path).map_err(PlanError::InvalidParams)?;

        // ADR-0054 Decision 2: the bound is checked **here**, before a `SandboxPlan`
        // exists and therefore before any process does. Checking it at the transport
        // would mean the refusal came after a spawn that had to be cleaned up.
        //
        // `contents.len()` is UTF-8 **bytes**, which is what Decision 2 specifies. A
        // character count would admit up to four times this for non-ASCII text.
        if parsed.contents.len() > crate::stdin_frame::MAX_PAYLOAD_BYTES {
            return Err(PlanError::InvalidParams(format!(
                "`contents` is {} bytes, over the {} byte limit; refusing rather than \
                 truncating, because a shortened body would be a different write than the \
                 one that was asked for",
                parsed.contents.len(),
                crate::stdin_frame::MAX_PAYLOAD_BYTES,
            )));
        }

        // The frame is built here so a payload that cannot be framed never reaches the
        // sandbox at all. `encode` re-checks the bound; this is belt and braces, and it
        // is the same limit rather than a second one.
        let frame = crate::stdin_frame::encode(parsed.contents.as_bytes())
            .map_err(|e| PlanError::InvalidParams(format!("could not frame the payload: {e}")))?;

        Ok(Some(SandboxPlan {
            program: self.helper.display().to_string(),
            // ADR-0054 Decision 1: the payload is **not** here. `argv` reaches the host
            // process table -- `bwrap` is executed with it, stays in the host PID
            // namespace, and `/proc/<pid>/cmdline` is mode `0444` -- and on the cgroup
            // branch the joiner shell carries the same vector before it `exec`s `bwrap`.
            // Only `--path` and the transport version remain, and neither is user content.
            args: vec![
                "--path".to_owned(),
                absolute.display().to_string(),
                // ADR-0054 Decision 6: the version travels in argv so an incompatible
                // helper can refuse by name instead of silently mismatching. It is
                // non-sensitive, which is exactly why the payload may not join it.
                crate::stdin_frame::VERSION_ARG.to_owned(),
            ],
            // Decision 4: an empty payload is a *declared* zero, framed here rather than
            // inferred by the receiver from a stream that happened to be empty.
            stdin_payload: Some(frame),
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
        }))
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

    // ---------------------------------------------------------------- F-17 (S-03)
    //
    // F-17: `Refuted` is the only verification finding that becomes
    // `EffectStatus::NotPerformed`, and `not-performed` is the one status `recover()`
    // treats as "a repeat cannot duplicate anything" -- i.e. a retry permission.
    //
    // So every `Refuted` is a licence to re-run a possibly-performed non-idempotent
    // write. This test pins the case where the write DID occur and a later actor
    // changed the file. `WriteTextVerifier` re-reads the filesystem, so it cannot
    // distinguish "never written" from "written, then overwritten" -- and it answers
    // the second exactly as the first.
    //
    // The assertion below is the SAFE outcome, so it FAILS on the current code. That
    // failure is the evidence; a version of this test that asserted `Refuted` would
    // pass and would document the defect as though it were the contract.
    fn verifier_for(ws: &Path) -> WriteTextVerifier {
        WriteTextVerifier {
            workspace: ws.to_path_buf(),
        }
    }

    // The capability layer's half of the F-17 regression. It asserts what this crate is
    // responsible for -- the verdict is accurate, and it passes through the real admission
    // table unchanged -- and deliberately stops there.
    //
    // It originally asserted that this verdict must NOT be `Refuted`, which put the fix in
    // the wrong crate. ADR-0056 put it in the consumer: a verifier cannot tell a genuine
    // write-then-overwrite from a write that never ran, so downgrading the verdict here
    // would have destroyed a true observation without closing the hole. The property that
    // actually matters -- that the verdict does not authorise a retry -- is asserted in
    // `orxnud-daemon`, where `certainty_of`, the effect ledger and `recover()` live, in
    // `a_refuted_write_text_does_not_authorise_a_retry_after_a_possible_execution`.
    //
    // Both halves are needed. This one stops anyone "fixing" F-17 by making the verifier
    // stop reporting a true postcondition.
    #[test]
    fn a_write_that_occurred_and_was_later_overwritten_is_refuted_and_survives_admission() {
        let ws = std::env::temp_dir().join(format!("f17-verdict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(&ws).expect("mkdir");

        // The capability was asked to write "wanted".
        let requested = "wanted";
        // The write genuinely happened -- the file holds exactly what was asked for.
        std::fs::write(ws.join("f.txt"), requested).expect("the write occurs");

        // ... and then a second task, an editor, or a concurrent governed run changed
        // the same path before verification re-read it.
        let later = "somebody else wrote this";
        std::fs::write(ws.join("f.txt"), later).expect("the later write occurs");

        let params = serde_json::json!({ "path": "f.txt", "contents": requested });
        let execution = ExecutionOutcome::Succeeded {
            output: Some(String::new()),
        };
        let out = verifier_for(&ws)
            .verify(&execution, &params, 0)
            .expect("verification runs");

        // The postcondition genuinely does not hold, so the verifier must say so. This
        // observation is TRUE and stays available to the consumer, which is what lets the
        // consumer record an uncertainty instead of guessing.
        assert!(
            matches!(out, VerificationOutcome::Refuted { .. }),
            "the file does not hold the requested bytes, so `Refuted` is the accurate \
             observation; suppressing it here would hide a true fact and still not prove \
             anything about execution. Observed verdict: {out:?}"
        );

        // And the real admission table lets it through unchanged -- `(Succeeded, Refuted)`
        // is admissible. That is not the defect and must not be "fixed" either: refusing it
        // here would hide a true observation for the same reason, and ADR-0056 places the
        // boundary one layer up where the retry permission is actually issued.
        let admitted = crate::dispatch::admit_verification(&execution, out.clone());
        assert!(
            matches!(admitted, VerificationOutcome::Refuted { .. }),
            "admission is a no-op on a refuted postcondition after a successful execution, \
             and must stay one; the consumption of this answer is what ADR-0056 changed. \
             Got: {admitted:?}"
        );

        let _ = std::fs::remove_dir_all(&ws);
    }

    /// ADR-0056 Decision 7. **This test was inverted on purpose and the old assertion was
    /// the defect.**
    ///
    /// It previously read `Refuted` and justified it as "a genuinely absent file IS proven
    /// not to have been written". It is not proven, and that sentence is the same error as
    /// the one above it: a file's absence is a postcondition, and a write that happened
    /// whose output was subsequently deleted is indistinguishable from one that never ran.
    ///
    /// Note what is *not* being decided here. The retry permission is not being taken away
    /// from every absence — it was never held on evidence this strong. Genuine
    /// non-execution is still warrantable, and it is warrantable from a refusal decided
    /// before a process exists (`ExecutionCertainty::NothingAttempted`), which never reaches
    /// this function at all. Three tests in `orxnud-daemon` and one in `settlement.rs` cover
    /// that path and are unaffected by this change.
    ///
    /// So the verifier's answer is still `Refuted` — the postcondition genuinely does not
    /// hold, and saying so is accurate. What ADR-0056 changed is what the daemon is allowed
    /// to *do* with that answer, and that is `certainty_of`, not this function.
    #[test]
    fn an_absent_file_is_still_refuted_but_refutes_nothing_about_execution() {
        let ws = std::env::temp_dir().join(format!("f17-control-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ws);
        std::fs::create_dir_all(&ws).expect("mkdir");

        let params = serde_json::json!({ "path": "missing.txt", "contents": "wanted" });
        let out = verifier_for(&ws)
            .verify(
                &ExecutionOutcome::Succeeded {
                    output: Some(String::new()),
                },
                &params,
                0,
            )
            .expect("verification runs");

        assert!(
            matches!(out, VerificationOutcome::Refuted { .. }),
            "the postcondition genuinely does not hold, so the verifier must keep reporting \
             that accurately -- downgrading it here would destroy a true observation and fix \
             nothing, because the fix belongs in how the answer is consumed. Observed \
             verdict: {out:?}"
        );

        let _ = std::fs::remove_dir_all(&ws);
    }

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
