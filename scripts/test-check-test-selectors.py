#!/usr/bin/env python3
"""Regression tests for check-test-selectors.py.

The parser is tested against JSON shapes captured from nextest 0.9.146. The
shell integration with the real pinned nextest and CARGO_TERM_COLOR=always is
exercised separately by the gate and by the remediation validation.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "check_test_selectors", Path(__file__).with_name("check-test-selectors.py")
)
cts = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cts)

PKG = "orxnud-platform-sandbox"
PKG_ID = "path+file:///tmp/OpenRayNux/crates/orxnud-platform-sandbox#0.1.0"
SOURCE = "scripts/run-sandbox-tests.sh:104"


def binary_entry(
    target: str,
    *,
    package_id: str = PKG_ID,
    kind: str = "test",
    binary_name: str | None = None,
) -> dict:
    return {
        "binary-id": f"{PKG}::{target}",
        "binary-name": binary_name or target,
        "package-id": package_id,
        "kind": kind,
    }


def binaries(entries: list[dict]) -> dict:
    return {
        "rust-build-meta": {},
        "rust-binaries": {
            entry["binary-id"]: entry for entry in entries
        },
    }


def suites(entries: list[dict]) -> dict:
    return {
        "rust-build-meta": {},
        "test-count": 0,
        "rust-suites": {
            entry["suite"]: {
                "package-id": entry["package_id"],
                "testcases": entry["testcases"],
            }
            for entry in entries
        },
    }


def suite_entry(
    suite: str,
    testcases: list[str],
    *,
    package_id: str = PKG_ID,
) -> dict:
    return {
        "suite": suite,
        "package_id": package_id,
        "testcases": {name: {} for name in testcases},
    }


class BinaryValidationTests(unittest.TestCase):
    def test_exact_package_and_target_is_valid(self) -> None:
        data = binaries([binary_entry("isolation")])
        cts.validate_binaries(data, PKG, "isolation", PKG_ID, SOURCE)

    def test_absent_target_is_refused(self) -> None:
        data = binaries([binary_entry("resources")])
        with self.assertRaises(cts.SelectorError):
            cts.validate_binaries(data, PKG, "isolation", PKG_ID, SOURCE)

    def test_target_with_the_wrong_package_id_is_refused(self) -> None:
        data = binaries([binary_entry("isolation", package_id="path+file:///other#0.1.0")])
        with self.assertRaises(cts.SelectorError):
            cts.validate_binaries(data, PKG, "isolation", PKG_ID, SOURCE)

    def test_target_with_the_wrong_kind_is_refused(self) -> None:
        data = binaries([binary_entry("isolation", kind="bin")])
        with self.assertRaises(cts.SelectorError):
            cts.validate_binaries(data, PKG, "isolation", PKG_ID, SOURCE)

    def test_target_with_the_wrong_binary_name_is_refused(self) -> None:
        data = binaries([binary_entry("isolation", binary_name="other")])
        with self.assertRaises(cts.SelectorError):
            cts.validate_binaries(data, PKG, "isolation", PKG_ID, SOURCE)

    def test_missing_required_field_is_refused(self) -> None:
        entry = binary_entry("isolation")
        del entry["package-id"]
        data = binaries([entry])
        with self.assertRaises(cts.SelectorError):
            cts.validate_binaries(data, PKG, "isolation", PKG_ID, SOURCE)

    def test_missing_rust_binaries_object_is_refused(self) -> None:
        with self.assertRaises(cts.SelectorError):
            cts.validate_binaries(
                {"rust-build-meta": {}}, PKG, "isolation", PKG_ID, SOURCE
            )


class FilterValidationTests(unittest.TestCase):
    def test_matching_testcase_is_valid(self) -> None:
        data = suites(
            [
                suite_entry(
                    "orxnud-capability",
                    ["suites::governed_path::a", "suites::other::b"],
                )
            ]
        )
        matched = cts.validate_filter(
            data, "orxnud-capability", "test(suites::governed_path)", PKG_ID, SOURCE
        )
        self.assertEqual(matched, 1)

    def test_zero_matching_testcases_is_refused(self) -> None:
        data = suites([suite_entry("orxnud-capability", ["suites::other::b"])])
        with self.assertRaises(cts.SelectorError):
            cts.validate_filter(
                data,
                "orxnud-capability",
                "test(suites::governed_path)",
                PKG_ID,
                SOURCE,
            )

    def test_match_in_another_package_is_refused(self) -> None:
        data = suites(
            [
                suite_entry(
                    "orxnud-capability",
                    ["suites::governed_path::a"],
                    package_id="path+file:///other#0.1.0",
                )
            ]
        )
        with self.assertRaises(cts.SelectorError):
            cts.validate_filter(
                data,
                "orxnud-capability",
                "test(suites::governed_path)",
                PKG_ID,
                SOURCE,
            )

    def test_unsupported_filter_form_is_refused(self) -> None:
        with self.assertRaises(cts.SelectorError):
            cts.parse_test_filter("package(orxnud-capability)", SOURCE)

    def test_conjoined_filter_form_is_refused(self) -> None:
        with self.assertRaises(cts.SelectorError):
            cts.parse_test_filter("test(a) or test(b)", SOURCE)

    def test_missing_rust_suites_object_is_refused(self) -> None:
        with self.assertRaises(cts.SelectorError):
            cts.validate_filter(
                {"rust-build-meta": {}},
                "orxnud-capability",
                "test(suites::governed_path)",
                PKG_ID,
                SOURCE,
            )

    def test_non_object_testcases_is_refused(self) -> None:
        data = {
            "rust-suites": {
                "orxnud-capability": {
                    "package-id": PKG_ID,
                    "testcases": ["not", "an", "object"],
                }
            }
        }
        with self.assertRaises(cts.SelectorError):
            cts.validate_filter(
                data,
                "orxnud-capability",
                "test(suites::governed_path)",
                PKG_ID,
                SOURCE,
            )


class JsonAndCommandTests(unittest.TestCase):
    def test_empty_output_is_refused(self) -> None:
        with self.assertRaises(cts.SelectorError):
            cts.load_json("", SOURCE)

    def test_malformed_json_is_refused(self) -> None:
        with self.assertRaises(cts.SelectorError):
            cts.load_json("{not json", SOURCE)

    def test_non_object_json_is_refused(self) -> None:
        with self.assertRaises(cts.SelectorError):
            cts.load_json(json.dumps([]), SOURCE)

    def test_command_failure_carries_useful_stderr(self) -> None:
        fake = SimpleNamespace(returncode=1, stdout="", stderr="the real failure")
        with mock.patch.object(cts.subprocess, "run", return_value=fake):
            with self.assertRaises(cts.SelectorError) as raised:
                cts.run_command(["cargo", "nextest", "list"], SOURCE)
        message = str(raised.exception)
        self.assertIn("command failed", message)
        self.assertIn("the real failure", message)


if __name__ == "__main__":
    unittest.main()
