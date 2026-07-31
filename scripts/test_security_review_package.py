#!/usr/bin/env python3
"""Regression tests for the deterministic security-review package builder."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("security_review_package.py")
SPEC = importlib.util.spec_from_file_location("security_review_package", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load security-review package builder")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PackageBuilderTests(unittest.TestCase):
    def policy(self) -> dict[str, object]:
        return {
            "schema": "komms-security-review-package/v1",
            "package_version": "1.0.0",
            "protocol_profile": "komms-stable-v1",
            "review_status": "prepared-awaiting-external-reviewer",
            "archive_prefix": "review",
            "max_source_files": 8,
            "max_source_bytes": 4096,
            "max_tar_bytes": 32768,
            "max_archive_bytes": 32768,
            "required_paths": ["README.md"],
            "required_prefixes": ["src/"],
        }

    def repository(self, *, symlink: bool = False) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root / "README.md").write_text("review target\n", encoding="utf-8")
        (root / "src").mkdir()
        (root / "src/lib.rs").write_text("pub fn value() -> u8 { 1 }\n", encoding="utf-8")
        if symlink:
            (root / "src/link").symlink_to("lib.rs")
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "user.name=Test Maintainer",
                "-c",
                "user.email=maintainer@example.invalid",
                "commit",
                "-q",
                "-m",
                "Create review target",
            ],
            check=True,
            env={
                "PATH": __import__("os").environ["PATH"],
                "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
            },
        )
        return temporary, root

    def test_exact_revision_build_is_reproducible(self) -> None:
        temporary, root = self.repository()
        self.addCleanup(temporary.cleanup)
        first = MODULE.build_package(root, self.policy(), "HEAD")
        second = MODULE.build_package(root, self.policy(), "HEAD")
        self.assertEqual(first.archive_bytes, second.archive_bytes)
        self.assertEqual(first.report_bytes, second.report_bytes)
        self.assertEqual(
            first.report["archive_sha256"],
            MODULE.sha256(first.archive_bytes),
        )
        self.assertFalse(first.report["independent_security_review_claimed"])

    def test_tracked_symlink_is_rejected(self) -> None:
        temporary, root = self.repository(symlink=True)
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(MODULE.PackageError, "symlinks"):
            MODULE.build_package(root, self.policy(), "HEAD")

    def test_required_source_is_enforced(self) -> None:
        temporary, root = self.repository()
        self.addCleanup(temporary.cleanup)
        policy = self.policy()
        policy["required_paths"] = ["MISSING.md"]
        with self.assertRaisesRegex(MODULE.PackageError, "missing required paths"):
            MODULE.build_package(root, policy, "HEAD")

    def test_report_verification_rejects_changed_archive(self) -> None:
        temporary, root = self.repository()
        self.addCleanup(temporary.cleanup)
        built = MODULE.build_package(root, self.policy(), "HEAD")
        output = root / "out"
        output.mkdir()
        report = output / built.report_name
        archive = output / built.archive_name
        report.write_bytes(built.report_bytes)
        archive.write_bytes(built.archive_bytes + b"changed")
        with self.assertRaisesRegex(MODULE.PackageError, "size"):
            MODULE.verify_report(report, archive)

    def test_canonical_report_has_one_trailing_newline(self) -> None:
        encoded = MODULE.canonical_json({"z": 1, "a": 2})
        self.assertEqual(encoded, b'{"a":2,"z":1}\n')
        self.assertEqual(json.loads(encoded), {"a": 2, "z": 1})

    def test_unsafe_paths_are_rejected(self) -> None:
        for value in ("../escape", "/absolute", "./relative", "bad\nname", r"a\b"):
            with self.subTest(value=value):
                with self.assertRaises(MODULE.PackageError):
                    MODULE.safe_repo_path(value)


if __name__ == "__main__":
    unittest.main()
