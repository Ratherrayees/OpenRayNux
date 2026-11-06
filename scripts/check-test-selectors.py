#!/usr/bin/env python3
"""Validate developer-lane selectors against nextest's machine-readable listing.

The previous checker matched human-readable listing output with `grep -qxF`.
That output is presentation, and nextest colours it when `CARGO_TERM_COLOR=always`
is set (the CI environment does exactly that), so the exact match failed even
though every target existed. This helper reads the JSON listing instead and
validates the structure and semantic fields.

Filter validation is deliberately narrower than nextest's filter expression
language. The developer lanes use only ``test(<substring>)``. Nextest 0.9.146
does not apply ``-E`` to the JSON listing, so the selected testcases are found
by matching that substring against the JSON testcase names. Any other filter
form fails closed rather than being accepted without being understood.

Only the Python standard library is used.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

# The lane scripts use this form only. Keeping the parser strict means a future
# lane that uses a richer filter cannot pass without this checker being taught
# the new form deliberately.
_TEST_FILTER = re.compile(r"test\(([^()]+)\)")

# Diagnostics from a failing cargo/nextest invocation can be long; keep the
# useful tail rather than dumping a whole build log, and never include the
# environment.
_MAX_DIAGNOSTIC = 4000


class SelectorError(Exception):
    """A selector could not be established to be valid."""


def run_command(cmd: list[str], source: str) -> str:
    """Run a command and return stdout, or raise with the useful stderr."""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        if len(detail) > _MAX_DIAGNOSTIC:
            detail = detail[-_MAX_DIAGNOSTIC:]
        message = f"{source}: command failed: {' '.join(cmd)}"
        if detail:
            message += f"\n{detail}"
        raise SelectorError(message)
    return proc.stdout


def load_json(text: str, source: str) -> dict:
    """Parse a JSON object, failing closed on anything else."""
    if not text.strip():
        raise SelectorError(f"{source}: nextest produced no JSON output")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise SelectorError(f"{source}: nextest produced malformed JSON: {error}") from error
    if not isinstance(data, dict):
        raise SelectorError(
            f"{source}: unexpected JSON top level: {type(data).__name__}"
        )
    return data


def package_ids() -> dict[str, str]:
    """Map workspace package names to the ids used in nextest's JSON."""
    data = load_json(
        run_command(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            "cargo metadata",
        ),
        "cargo metadata",
    )
    packages = data.get("packages")
    if not isinstance(packages, list):
        raise SelectorError("cargo metadata: no packages array")
    mapping: dict[str, str] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise SelectorError("cargo metadata: a package is not an object")
        name = package.get("name")
        package_id = package.get("id")
        if not isinstance(name, str) or not isinstance(package_id, str):
            raise SelectorError("cargo metadata: a package has no name or id")
        mapping[name] = package_id
    return mapping


def package_id_for(pkg: str) -> str:
    """Return the Cargo package id for a package name, or fail."""
    ids = package_ids()
    try:
        return ids[pkg]
    except KeyError as error:
        raise SelectorError(f"package {pkg} is not in the workspace") from error


def validate_binaries(
    data: dict, pkg: str, target: str, package_id: str, source: str
) -> None:
    """Validate one ``--test target`` against the binaries-only JSON."""
    binaries = data.get("rust-binaries")
    if not isinstance(binaries, dict):
        raise SelectorError(f"{source}: JSON has no rust-binaries object")

    wanted = f"{pkg}::{target}"
    matches = []
    for key, entry in binaries.items():
        if not isinstance(entry, dict):
            raise SelectorError(f"{source}: binary entry {key!r} is not an object")
        for field in ("binary-id", "binary-name", "package-id", "kind"):
            if not isinstance(entry.get(field), str):
                raise SelectorError(
                    f"{source}: binary entry {key!r} has no string {field}"
                )
        if entry["binary-id"] == wanted:
            matches.append(entry)

    if not matches:
        raise SelectorError(f"{source}: {pkg} has no --test target {target}")

    for entry in matches:
        if entry["package-id"] != package_id:
            raise SelectorError(
                f"{source}: {wanted} belongs to package-id "
                f"{entry['package-id']}, not {package_id}"
            )
        if entry["kind"] != "test":
            raise SelectorError(
                f"{source}: {wanted} has kind {entry['kind']}, not test"
            )
        if entry["binary-name"] != target:
            raise SelectorError(
                f"{source}: {wanted} has binary-name "
                f"{entry['binary-name']}, not {target}"
            )


def parse_test_filter(filter_expr: str, source: str) -> str:
    """Extract the substring from the only filter form the lanes use."""
    match = _TEST_FILTER.fullmatch(filter_expr.strip())
    if match is None:
        raise SelectorError(
            f"{source}: unsupported filter form {filter_expr!r}; "
            "only test(<substring>) is validated"
        )
    return match.group(1)


def validate_filter(
    data: dict, pkg: str, filter_expr: str, package_id: str, source: str
) -> int:
    """Validate that ``test(<substring>)`` selects at least one package testcase."""
    pattern = parse_test_filter(filter_expr, source)
    suites = data.get("rust-suites")
    if not isinstance(suites, dict):
        raise SelectorError(f"{source}: JSON has no rust-suites object")

    matched = 0
    for suite_name, suite in suites.items():
        if not isinstance(suite, dict):
            raise SelectorError(f"{source}: suite {suite_name!r} is not an object")
        suite_package = suite.get("package-id")
        testcases = suite.get("testcases")
        if not isinstance(suite_package, str):
            raise SelectorError(
                f"{source}: suite {suite_name!r} has no string package-id"
            )
        if not isinstance(testcases, dict):
            raise SelectorError(
                f"{source}: suite {suite_name!r} has no testcases object"
            )
        if suite_package != package_id:
            continue
        for name in testcases:
            if not isinstance(name, str):
                raise SelectorError(
                    f"{source}: suite {suite_name!r} has a non-string testcase"
                )
            if pattern in name:
                matched += 1

    if matched == 0:
        raise SelectorError(
            f"{source}: filter selects no tests in {pkg}: {filter_expr}"
        )
    return matched


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: check-test-selectors.py <target|filter> <package> "
            "<value> <source>",
            file=sys.stderr,
        )
        return 2

    mode, pkg, value, source = argv
    try:
        package_id = package_id_for(pkg)
        if mode == "target":
            data = load_json(
                run_command(
                    [
                        "cargo",
                        "nextest",
                        "list",
                        "-p",
                        pkg,
                        "--list-type",
                        "binaries-only",
                        "--message-format",
                        "json",
                    ],
                    source,
                ),
                source,
            )
            validate_binaries(data, pkg, value, package_id, source)
        elif mode == "filter":
            data = load_json(
                run_command(
                    [
                        "cargo",
                        "nextest",
                        "list",
                        "-p",
                        pkg,
                        "-E",
                        value,
                        "--message-format",
                        "json",
                    ],
                    source,
                ),
                source,
            )
            validate_filter(data, pkg, value, package_id, source)
        else:
            print(f"unknown mode {mode!r}", file=sys.stderr)
            return 2
    except SelectorError as error:
        print(f"selector error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
