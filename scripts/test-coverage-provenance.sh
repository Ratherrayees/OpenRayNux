#!/usr/bin/env bash
#
# TEST-001 producer-provenance regression.
#
# G9's JSONL artifact proves that an ID appeared, not that the named test produced it.
# This script runs the real nextest harness and the real coverage producer, not a
# synthetic artifact:
#
#   1. Run the five required producer-rejection tests by exact identity and prove from
#      the runner's output that each ran exactly once and passed. One of them is the
#      named worker that calls `scope` and tries to mint another tracked test's record.
#   2. Run only the payload test. It must produce exactly its own record. The enforced
#      memory test must be absent, and the checker must classify it as missing.
#   3. Run both governed tests. Each must produce its own record, with no cross-claim.
#
# The payload test's outcome may be `verified` on a capable host or `reduced` where the
# cgroup controls are unavailable. This check is about identity attribution, not about
# proving kernel enforcement, so it does not require a privileged runner.
#
# This lives beside G9 rather than inside scripts/gate-selftest.py because it invokes
# cargo/nextest; putting it in gate-selftest.py would recursively run the build while the
# gate self-tests are already inside a workspace test run. G9 invokes it once, before the
# full suite, and fails closed if it does not pass.

set -euo pipefail

cd "$(dirname "$0")/.."

PAYLOAD="orxnud-capability::suites::governed_path::the_payload_is_constrained_before_it_executes_work"
ENFORCED="orxnud-capability::suites::governed_path::a_required_memory_ceiling_is_enforced_by_the_kernel_not_merely_written"
ARTIFACT="$PWD/target/test-coverage-provenance-$$-$RANDOM.jsonl"
CHECK_LOG="$ARTIFACT.check.log"
FOCUSED_LOG="$ARTIFACT.focused.log"
FOCUSED_JSON="$ARTIFACT.focused.json"
mkdir -p "$(dirname "$ARTIFACT")"
RUN=""

new_run() {
  RUN="coverage-provenance-$$-$(date +%s%N)-${RANDOM}"
}

cleanup() {
  rm -f "$ARTIFACT" "$CHECK_LOG" "$FOCUSED_LOG" "$FOCUSED_JSON"
}
trap cleanup EXIT INT TERM

fresh_artifact() {
  rm -f "$ARTIFACT"
}

have_nextest() {
  command -v cargo-nextest >/dev/null 2>&1
}

# G9 falls back to `cargo test` when nextest is unavailable. This regression follows the
# same rule with one extra constraint: `cargo test` does not supply nextest's identity
# variables, so the fallback runs one exact test per process and supplies the
# runner-controlled identity itself. It never falls back to the test thread's name.
run_focused() {
  local filter="$1"
  shift
  if have_nextest; then
    cargo nextest run -p orxnud-capability -E "$filter" --no-fail-fast
  else
    local test
    for test in "$@"; do
      NEXTEST_BINARY_ID=orxnud-capability NEXTEST_TEST_NAME="$test" \
        cargo test -p orxnud-capability --lib -- --exact "$test"
    done
  fi
}

# Run one required producer test by exact identity and prove from the runner's own
# output that exactly that test passed. A substring filter, an empty run, or a renamed
# test is not enough: the point of this step is that every required test executed.
run_required() {
  local test="$1"
  if have_nextest; then
    NEXTEST_EXPERIMENTAL_LIBTEST_JSON=1 \
      ORXNUD_TEST_COVERAGE="$ARTIFACT" ORXNUD_COVERAGE_RUN="$RUN" \
      cargo nextest run -p orxnud-capability -E "test(=$test)" \
      --no-fail-fast --message-format libtest-json \
      >"$FOCUSED_JSON" 2>"$FOCUSED_LOG" || {
        cat "$FOCUSED_LOG" >&2
        return 1
      }
    python3 - "$FOCUSED_JSON" "$test" <<'PY'
import json
import sys
from pathlib import Path

path, test = sys.argv[1:]
records = []
for line in Path(path).read_text(encoding="utf-8").splitlines():
    if line.strip():
        records.append(json.loads(line))
tests = [record for record in records if record.get("type") == "test"]
passed = [record for record in tests if record.get("event") == "ok"]
started = [record for record in tests if record.get("event") == "started"]
if len(passed) != 1 or len(started) != 1:
    raise SystemExit(f"required producer test {test!r} did not run exactly once and pass: {tests!r}")
name = passed[0].get("name", "")
if name.rsplit("$", 1)[-1] != test:
    raise SystemExit(f"required producer test {test!r} ran as {name!r}")
summary = [
    record
    for record in records
    if record.get("type") == "suite" and record.get("event") == "ok"
]
if not any(record.get("passed") == 1 and record.get("failed") == 0 for record in summary):
    raise SystemExit(f"required producer test {test!r} has no one-pass suite summary: {summary!r}")
PY
  else
    NEXTEST_BINARY_ID=orxnud-capability NEXTEST_TEST_NAME="$test" \
      ORXNUD_TEST_COVERAGE="$ARTIFACT" ORXNUD_COVERAGE_RUN="$RUN" \
      cargo test -p orxnud-capability --lib -- --exact "$test" \
      >"$FOCUSED_LOG" 2>&1 || {
        cat "$FOCUSED_LOG" >&2
        return 1
      }
    python3 - "$FOCUSED_LOG" "$test" <<'PY'
import sys
from pathlib import Path

path, test = sys.argv[1:]
output = Path(path).read_text(encoding="utf-8")
passed_line = f"test {test} ... ok"
should_panic_line = f"test {test} - should panic ... ok"
if passed_line not in output and should_panic_line not in output:
    raise SystemExit(f"required producer test {test!r} did not report an exact pass")
if "1 passed; 0 failed" not in output:
    raise SystemExit(f"required producer test {test!r} did not run exactly one passing test")
PY
  fi
}

check_records() {
  local expected_mode="$1"
  python3 - "$ARTIFACT" "$RUN" "$expected_mode" "$PAYLOAD" "$ENFORCED" <<'PY'
import json
import sys
from pathlib import Path

artifact, run, mode, payload, enforced = sys.argv[1:]
path = Path(artifact)
if not path.is_file():
    raise SystemExit(f"coverage producer wrote no artifact: {artifact}")

records = []
for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
    if not line.strip():
        continue
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{artifact}:{line_no}: malformed JSON: {exc}")
    if record.get("run") != run:
        raise SystemExit(f"{artifact}:{line_no}: wrong run token: {record.get('run')!r}")
    if record.get("outcome") not in {"verified", "reduced"}:
        raise SystemExit(f"{artifact}:{line_no}: invalid outcome: {record.get('outcome')!r}")
    records.append(record)

ids = [record.get("test") for record in records]
if mode == "payload-only":
    if ids != [payload]:
        raise SystemExit(f"payload-only run produced {ids!r}, expected exactly [{payload!r}]")
elif mode == "both":
    if sorted(ids) != sorted([payload, enforced]):
        raise SystemExit(f"complete run produced {ids!r}, expected [{payload!r}, {enforced!r}]")
else:
    raise SystemExit(f"unknown mode: {mode}")

if enforced in ids and mode == "payload-only":
    raise SystemExit("payload-only run incorrectly claims the enforced-memory path")
print("coverage provenance: " + ", ".join(f"{record['test'].rsplit('::', 1)[-1]}={record['outcome']}" for record in records))
PY
}

# 0. The real producer must reject a cross-test claim, an out-of-binary suite and a
# malformed ID before it appends anything. Each test is selected by its exact full path
# and its own runner output is checked, so a renamed, removed, filtered-out, or ignored
# test cannot silently shrink this regression.
fresh_artifact
new_run
required_tests=(
  "suites::governed_path::a_named_worker_with_a_scope_cannot_emit_another_tests_record"
  "suites::governed_path::a_verified_record_cannot_claim_another_tests_identity"
  "suites::governed_path::a_reduced_record_cannot_claim_another_tests_identity"
  "suites::governed_path::a_record_cannot_claim_a_suite_outside_this_binary"
  "suites::governed_path::a_record_cannot_use_a_malformed_identity"
)
for test in "${required_tests[@]}"; do
  run_required "$test"
  echo "coverage provenance: required producer test ran: ${test##*::}"
done
if [ -s "$ARTIFACT" ]; then
  echo "coverage provenance: a cross-test claim wrote an artifact instead of failing" >&2
  cat "$ARTIFACT" >&2
  exit 1
fi

# 1. Run only the payload test. It must not claim the enforced-memory path.
fresh_artifact
new_run
ORXNUD_TEST_COVERAGE="$ARTIFACT" ORXNUD_COVERAGE_RUN="$RUN" \
  run_focused "test(the_payload_is_constrained_before_it_executes_work)" \
    "suites::governed_path::v46::the_payload_is_constrained_before_it_executes_work"
check_records payload-only

# The checker must not fill the missing enforced path from the payload record. It exits
# non-zero for the incomplete suite, and its output names the enforced path as missing.
if python3 scripts/test-coverage.py check \
    --artifact "$ARTIFACT" --run "$RUN" \
    --suite orxnud-capability::suites::governed_path >"$CHECK_LOG" 2>&1; then
  echo "coverage provenance: checker accepted an incomplete governed_path suite" >&2
  exit 1
fi
if ! grep -F "MISSING       $ENFORCED" "$CHECK_LOG" >/dev/null; then
  echo "coverage provenance: checker did not report the enforced-memory path as missing" >&2
  cat "$CHECK_LOG" >&2
  exit 1
fi
echo "coverage provenance: checker correctly reported the enforced-memory path as missing"

# 2. A complete, non-excluded governed-path run must have both identities. This is still
# bounded to two tests and does not run the rest of the workspace.
fresh_artifact
new_run
ORXNUD_TEST_COVERAGE="$ARTIFACT" ORXNUD_COVERAGE_RUN="$RUN" \
  run_focused \
    "test(the_payload_is_constrained_before_it_executes_work) | test(a_required_memory_ceiling_is_enforced_by_the_kernel_not_merely_written)" \
    "suites::governed_path::v46::the_payload_is_constrained_before_it_executes_work" \
    "suites::governed_path::v46::a_required_memory_ceiling_is_enforced_by_the_kernel_not_merely_written"
check_records both

echo "coverage provenance: payload-only and complete governed runs are correctly attributed"
