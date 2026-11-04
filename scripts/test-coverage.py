#!/usr/bin/env python3
"""Validate TEST-001 test-coverage records and the shapes that can fake them.

G9 sets ``ORXNUD_TEST_COVERAGE`` to a fresh file and ``ORXNUD_COVERAGE_RUN`` to a
per-run token. Tests append one JSON object per exercised path: ``verified`` when the
intended assertion path ran, ``reduced`` when a platform capability was unavailable.
The gate must not read a green test exit as "the guarded body ran".

The scanner is deliberately narrow. It checks the expected tests for two shapes that
have already produced false green in this repository: a successful ``return`` before
any coverage decision, and a tautology such as ``a.can_create || !a.can_create``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass

SUITES: dict[str, list[str]] = {
    "orxnud-capability::suites::write_text": [
        "an_approved_write_reaches_the_sandbox_and_verifies_from_the_filesystem",
        "bytes_arrive_exactly_with_nothing_interpreted",
        "an_empty_file_is_the_requested_effect_not_a_missing_one",
        "an_escaping_path_cannot_reach_the_host_filesystem",
        "an_approval_for_one_parameter_set_does_not_authorise_another",
        "object_key_order_does_not_change_what_an_approval_authorises",
        "an_expired_approval_is_refused_and_nothing_is_written",
        "an_approval_succeeds_once_and_is_refused_the_second_time",
    ],
    "orxnud-capability::suites::governed_path": [
        "a_required_memory_ceiling_is_applied_by_the_governed_path",
        "a_governed_timeout_terminates_a_detached_descendant_and_reaps_its_cgroup",
        "a_required_memory_ceiling_is_enforced_by_the_kernel_not_merely_written",
        "the_payload_is_constrained_before_it_executes_work",
    ],
    "orxnud-daemon::uncertain_outcome": [
        "an_uncertain_non_idempotent_effect_stops_the_task_and_stays_stopped",
        "an_uncertain_task_offers_no_shortcut_back_to_running",
        "a_verified_effect_still_completes_normally",
        "the_audit_records_the_uncertainty_rather_than_a_completion",
        "a_crash_inside_the_uncertainty_transition_leaves_no_retryable_task",
        "the_durable_record_explains_the_uncertainty_without_carrying_content",
        "a_worker_whose_lease_ended_cannot_settle_the_outcome",
        "the_production_dispatch_path_records_a_non_repeatable_effect_before_it_runs",
        "the_production_dispatch_path_records_a_repeatable_effect_for_an_idempotent_capability",
    ],
    "orxnud-platform-sandbox::enforcement": [
        "memory_max_is_kernel_enforced_inside_a_real_cgroup",
        "memory_events_record_the_limit_being_hit",
        "pids_max_prevents_unbounded_process_creation",
        "cpu_max_throttles_rather_than_terminating",
        "cgroup_kill_terminates_a_three_level_subtree",
        "a_repeated_kill_stays_deterministic",
        "a_process_that_exits_before_adoption_is_handled_deterministically",
        "the_base_is_a_parent_and_never_the_execution_cgroup",
        "concurrent_discovery_never_reports_a_false_negative",
        "concurrent_executions_never_share_a_cgroup",
    ],
    "orxnud-platform-sandbox::resources": [
        "pids_max_and_cpu_max_are_separate_capabilities",
        "cgroup_kill_terminates_a_member_that_forked_a_descendant",
        "an_execution_lands_in_a_dedicated_child_cgroup",
        "the_cgroup_probe_reports_something_either_way",
    ],
    "orxnud-platform-sandbox::isolation": [
        "a_socket_bound_in_the_namespace_is_unreachable_from_the_host",
    ],
}

EXPECTED: dict[str, str] = {
    f"{suite}::{test}": suite for suite, tests in SUITES.items() for test in tests
}

TAUTOLOGY = re.compile(
    r"assert!\s*\(\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\|\|\s*!\s*\1\s*[,)]"
)
RETURN = re.compile(r"\breturn\s*;")
COVERAGE_GUARD = re.compile(
    r"coverage::reduced\s*\(|require_sandbox\s*\(|ready_on\s*\(|available\s*\("
)


@dataclass
class Record:
    test: str
    outcome: str
    reason: str | None


def fail(message: str) -> int:
    print(f"coverage: {message}", file=sys.stderr)
    return 1


def check(args: argparse.Namespace) -> int:
    if args.run_status != 0:
        return fail(
            f"the test command exited {args.run_status}; coverage records cannot downgrade a failure"
        )

    records: dict[str, Record] = {}
    try:
        with open(args.artifact, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    return fail(f"{args.artifact}:{line_no}: malformed JSON: {exc}")
                if not isinstance(raw, dict):
                    return fail(f"{args.artifact}:{line_no}: record is not an object")
                if set(raw) - {"run", "test", "outcome", "reason"}:
                    return fail(f"{args.artifact}:{line_no}: unknown record field")
                if raw.get("run") != args.run:
                    return fail(
                        f"{args.artifact}:{line_no}: record belongs to run "
                        f"{raw.get('run')!r}, not this run {args.run!r}"
                    )
                test = raw.get("test")
                outcome = raw.get("outcome")
                reason = raw.get("reason")
                if not isinstance(test, str) or test not in EXPECTED:
                    return fail(f"{args.artifact}:{line_no}: unknown test {test!r}")
                if outcome not in {"verified", "reduced"}:
                    return fail(f"{args.artifact}:{line_no}: invalid outcome {outcome!r}")
                if outcome == "reduced" and not (isinstance(reason, str) and reason.strip()):
                    return fail(f"{args.artifact}:{line_no}: reduced coverage needs a reason")
                if test in records:
                    return fail(f"{args.artifact}:{line_no}: duplicate record for {test}")
                records[test] = Record(test, outcome, reason)
    except FileNotFoundError:
        if not args.excluded_suite:
            return fail(f"coverage artifact {args.artifact} is missing")
    except OSError as exc:
        return fail(f"cannot read coverage artifact {args.artifact}: {exc}")

    if args.require_verified and args.excluded_suite:
        return fail("--require-verified cannot be combined with --excluded-suite")

    expected = {
        test: suite
        for test, suite in EXPECTED.items()
        if not args.suite or suite in args.suite
    }
    unknown_suites = set(args.suite) - set(SUITES)
    if unknown_suites:
        return fail(f"unknown suite(s): {', '.join(sorted(unknown_suites))}")
    if not expected:
        return fail("no expected test path matched this suite selection")

    verified: list[str] = []
    reduced: list[Record] = []
    not_exercised: list[str] = []
    missing: list[str] = []

    for test, suite in expected.items():
        record = records.get(test)
        if record is None:
            if suite in args.excluded_suite:
                not_exercised.append(test)
            else:
                missing.append(test)
        elif record.outcome == "verified":
            verified.append(test)
        else:
            reduced.append(record)

    for record in reduced:
        print(f"  reduced       {record.test}: {record.reason}")
    for test in not_exercised:
        print(f"  not exercised {test}: suite excluded by the gate on this host")
    for test in missing:
        print(f"  MISSING       {test}: the suite ran but recorded no outcome")

    print(
        "SUMMARY "
        f"verified={len(verified)} reduced={len(reduced)} "
        f"not-exercised={len(not_exercised)} missing={len(missing)}"
    )
    if missing:
        return fail(f"{len(missing)} expected test path(s) recorded no coverage outcome")
    if reduced or not_exercised:
        print(
            f"coverage: reduced coverage: {len(reduced)} reduced, "
            f"{len(not_exercised)} not exercised"
        )
    else:
        print(f"coverage: all {len(verified)} expected paths verified")
    if args.require_verified and (reduced or not_exercised):
        return fail("coverage was reduced but this invocation requires every path verified")
    return 0


def scan_file(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return [f"{path}: cannot read: {exc}"]

    errors: list[str] = []
    text = "".join(lines)
    for suite, tests in SUITES.items():
        for test in tests:
            full = f"{suite}::{test}"
            match = re.search(rf"\bfn\s+{re.escape(test)}\s*\(", text)
            if match is None:
                continue
            start = match.start()
            try:
                end = text.index("\n}", start)
            except ValueError:
                end = len(text)
            body = text[start:end]
            body_start = text[:start].count("\n") + 1
            if TAUTOLOGY.search(body):
                errors.append(f"{path}:{body_start}: {full}: tautology-shaped assertion")
            for ret in RETURN.finditer(body):
                before = body[max(0, ret.start() - 400) : ret.start()]
                if not COVERAGE_GUARD.search(before):
                    line = body_start + body[: ret.start()].count("\n")
                    errors.append(
                        f"{path}:{line}: {full}: return with no coverage decision before it"
                    )
    return errors


def scan(args: argparse.Namespace) -> int:
    errors: list[str] = []
    for path in args.file:
        errors.extend(scan_file(path))
    if errors:
        for error in errors:
            print(f"coverage: {error}", file=sys.stderr)
        return 1
    print(f"coverage: scanned {len(args.file)} test source file(s)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    check_parser = sub.add_parser("check")
    check_parser.add_argument("--artifact", required=True)
    check_parser.add_argument("--run", required=True)
    check_parser.add_argument("--run-status", type=int, default=0)
    check_parser.add_argument("--excluded-suite", action="append", default=[])
    check_parser.add_argument("--suite", action="append", default=[])
    check_parser.add_argument("--require-verified", action="store_true")
    check_parser.set_defaults(func=check)

    scan_parser = sub.add_parser("scan")
    scan_parser.add_argument("--file", action="append", required=True)
    scan_parser.set_defaults(func=scan)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
