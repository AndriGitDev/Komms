#!/usr/bin/env python3
"""Regression tests for Android declared-license evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "scripts/android-license-evidence.py"
REVISION = "6" * 40


def run(*arguments: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(COMMAND), *arguments],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"returned {result.returncode}, expected {expected}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def fixture(
    root: Path,
    license_name: str,
    license_url: str = "https://www.apache.org/licenses/LICENSE-2.0.txt",
    policy_expression: str | None = "Apache-2.0",
) -> tuple[Path, Path, Path]:
    repository = root / "repository"
    lock = repository / "apps/android/app/gradle.lockfile"
    lock.parent.mkdir(parents=True)
    lock.write_text("example:library:1.0=runtimeClasspath\n", encoding="utf-8")
    metadata = repository / "apps/android/gradle/verification-metadata.xml"
    metadata.parent.mkdir(parents=True)
    cache = root / "cache"
    pom = cache / "example/library/1.0/hash/library-1.0.pom"
    pom.parent.mkdir(parents=True)
    pom.write_text(
        (
            "<project><licenses><license>"
            f"<name>{license_name}</name>"
            f"<url>{license_url}</url>"
            "</license></licenses></project>"
        ),
        encoding="utf-8",
    )
    pom_digest = hashlib.sha256(pom.read_bytes()).hexdigest()
    metadata.write_text(
        (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">'
            "<components><component group=\"example\" name=\"library\" version=\"1.0\">"
            '<artifact name="library-1.0.pom">'
            f'<sha256 value="{pom_digest}"/>'
            "</artifact></component></components></verification-metadata>"
        ),
        encoding="utf-8",
    )
    policy = repository / "release/android-license-policy-v1.json"
    policy.parent.mkdir(parents=True)
    rules = (
        [{"group_prefix": "example", "spdx": policy_expression}]
        if policy_expression
        else [{"group_prefix": "different", "spdx": "Apache-2.0"}]
    )
    policy.write_text(
        json.dumps(
            {
                "schema": "komms-android-license-policy/v1",
                "review_status": "declared-license-inventory-not-legal-opinion",
                "group_prefixes": rules,
                "exact_overrides": [],
                "custom_licenses": [],
                "claim": "fixture",
            }
        ),
        encoding="utf-8",
    )
    return repository, cache, policy


class AndroidLicenseEvidenceTests(unittest.TestCase):
    def test_verified_apache_declaration_is_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, cache, policy = fixture(
                root, "The Apache License, Version 2.0"
            )
            record = root / "licenses.json"
            run(
                "inventory",
                "--repository",
                str(repository),
                "--gradle-cache",
                str(cache),
                "--policy",
                str(policy),
                "--revision",
                REVISION,
                "--output",
                str(record),
            )
            result = run(
                "validate",
                "--repository",
                str(repository),
                "--record",
                str(record),
                "--policy",
                str(policy),
                "--expected-revision",
                REVISION,
                "--require-complete",
            )
            self.assertIn("declared=1", result.stdout)

    def test_unknown_declaration_blocks_complete_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, cache, policy = fixture(
                root,
                "Unclassified license",
                "https://example.invalid/unknown",
                policy_expression=None,
            )
            record = root / "licenses.json"
            run(
                "inventory",
                "--repository",
                str(repository),
                "--gradle-cache",
                str(cache),
                "--policy",
                str(policy),
                "--revision",
                REVISION,
                "--output",
                str(record),
            )
            run(
                "validate",
                "--repository",
                str(repository),
                "--record",
                str(record),
                "--policy",
                str(policy),
                "--require-complete",
                expected=2,
            )

    def test_policy_inventory_does_not_require_a_gradle_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _, policy = fixture(
                root, "The Apache License, Version 2.0"
            )
            record = root / "licenses.json"
            run(
                "inventory",
                "--repository",
                str(repository),
                "--policy",
                str(policy),
                "--revision",
                REVISION,
                "--output",
                str(record),
            )
            result = run(
                "validate",
                "--repository",
                str(repository),
                "--policy",
                str(policy),
                "--record",
                str(record),
                "--require-complete",
            )
            self.assertIn("policy_bound_without_pom=1", result.stdout)

    def test_pom_policy_mismatch_blocks_complete_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, cache, policy = fixture(
                root,
                "The MIT License",
                "https://opensource.org/licenses/MIT",
                policy_expression="Apache-2.0",
            )
            record = root / "licenses.json"
            run(
                "inventory",
                "--repository",
                str(repository),
                "--gradle-cache",
                str(cache),
                "--policy",
                str(policy),
                "--revision",
                REVISION,
                "--output",
                str(record),
            )
            run(
                "validate",
                "--repository",
                str(repository),
                "--policy",
                str(policy),
                "--record",
                str(record),
                "--require-complete",
                expected=2,
            )

    def test_unrecognized_pom_declaration_cannot_hide_behind_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, cache, policy = fixture(
                root,
                "Unclassified license",
                "https://example.invalid/unknown",
                policy_expression="Apache-2.0",
            )
            record = root / "licenses.json"
            run(
                "inventory",
                "--repository",
                str(repository),
                "--gradle-cache",
                str(cache),
                "--policy",
                str(policy),
                "--revision",
                REVISION,
                "--output",
                str(record),
            )
            run(
                "validate",
                "--repository",
                str(repository),
                "--policy",
                str(policy),
                "--record",
                str(record),
                "--require-complete",
                expected=2,
            )


if __name__ == "__main__":
    unittest.main()
