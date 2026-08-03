#!/usr/bin/env python3
"""Regression tests for the bounded contributor profile runner."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "contributor-check.py"
SPEC = importlib.util.spec_from_file_location("contributor_check", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CONTRIBUTOR_CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRIBUTOR_CHECK)


class ContributorCheckTests(unittest.TestCase):
    def test_checked_in_profiles_are_valid(self) -> None:
        profiles = CONTRIBUTOR_CHECK.load_profiles()
        self.assertIn("protocol", profiles)
        self.assertIn("desktop", profiles)
        self.assertIn("android-core", profiles)
        self.assertIn("ios-core", profiles)
        self.assertIn("documentation", profiles)

    def test_every_profile_dry_runs_without_credentials(self) -> None:
        profiles = CONTRIBUTOR_CHECK.load_profiles()
        for profile in profiles:
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--dry-run", profile],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("No publication", completed.stdout)

    def test_unknown_profile_fails_closed(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "does-not-exist"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)

    def test_history_changing_git_command_is_rejected(self) -> None:
        self.assert_rejected(["git", "push"], "changes project history")

    def test_registry_changing_cargo_command_is_rejected(self) -> None:
        self.assert_rejected(["cargo", "publish"], "external registry")

    def test_remote_executable_is_rejected(self) -> None:
        self.assert_rejected(["ssh", "example.invalid"], "not allowed")

    def test_repository_escape_is_rejected(self) -> None:
        document = self.document(["python3", "scripts/check-docs.py"])
        document["profiles"]["test"]["commands"][0]["cwd"] = "../outside"
        with self.temporary_profiles(document) as path:
            with self.assertRaisesRegex(
                CONTRIBUTOR_CHECK.ProfileError,
                "escapes repository",
            ):
                CONTRIBUTOR_CHECK.load_profiles(path)

    def assert_rejected(self, argv: list[str], message: str) -> None:
        with self.temporary_profiles(self.document(argv)) as path:
            with self.assertRaisesRegex(CONTRIBUTOR_CHECK.ProfileError, message):
                CONTRIBUTOR_CHECK.load_profiles(path)

    @staticmethod
    def document(argv: list[str]) -> dict[str, object]:
        return {
            "schema": CONTRIBUTOR_CHECK.SCHEMA,
            "profiles": {
                "test": {
                    "description": "test",
                    "paths": ["docs"],
                    "commands": [{"cwd": ".", "argv": argv}],
                }
            },
        }

    @staticmethod
    def temporary_profiles(document: dict[str, object]):
        class ProfilesContext:
            def __enter__(self) -> Path:
                self.directory = tempfile.TemporaryDirectory()
                path = Path(self.directory.name) / "profiles.json"
                path.write_text(
                    json.dumps(document, sort_keys=True),
                    encoding="utf-8",
                )
                return path

            def __exit__(self, *_: object) -> None:
                self.directory.cleanup()

        return ProfilesContext()


if __name__ == "__main__":
    unittest.main()
