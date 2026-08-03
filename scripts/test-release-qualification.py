#!/usr/bin/env python3
"""Regression tests for release qualification evidence."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "scripts/release-qualification.py"
REVISION = "2" * 40
DIGEST = "3" * 64


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


class ReleaseQualificationTests(unittest.TestCase):
    def prepare(self, root: Path) -> tuple[Path, Path]:
        manifest = root / "artifacts.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": "komms-release-artifacts/v1",
                    "revision": REVISION,
                    "artifacts": [
                        {
                            "path": (
                                "artifacts/"
                                "Komms-0.4.0-windows-x86_64-test.msi"
                            ),
                            "sha256": DIGEST,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        output = root / "qualification.json"
        run(
            "prepare",
            "--revision",
            REVISION,
            "--version",
            "0.4.0",
            "--artifact-manifest",
            str(manifest),
            "--output",
            str(output),
        )
        return output, manifest

    def test_prepared_matrix_is_valid_and_entirely_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, manifest = self.prepare(Path(temporary))
            result = run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--expected-revision",
                REVISION,
            )
            self.assertIn("passed=0", result.stdout)
            parsed = json.loads(record.read_text(encoding="utf-8"))
            self.assertGreater(parsed["summary"]["open"], 0)
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                "--require-complete",
                expected=2,
            )

    def test_simulator_cannot_be_recorded_as_a_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, manifest = self.prepare(Path(temporary))
            parsed = json.loads(record.read_text(encoding="utf-8"))
            row = parsed["rows"][0]
            row["environment"] = {
                "kind": "simulator",
                "name": "generic",
                "os": "test",
                "architecture": "test",
                "supported_claim_cell": False,
            }
            case = row["cases"][0]
            case.update(
                {
                    "status": "passed",
                    "started_at": "2026-01-01T00:00:00Z",
                    "ended_at": "2026-01-01T00:01:00Z",
                    "artifact_after_sha256": DIGEST,
                    "steps": ["installed"],
                    "result": "launch observed",
                }
            )
            parsed["summary"]["open"] -= 1
            parsed["summary"]["passed"] += 1
            record.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                expected=2,
            )

    def test_record_rejects_a_different_artifact_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, manifest = self.prepare(Path(temporary))
            parsed = json.loads(manifest.read_text(encoding="utf-8"))
            parsed["artifacts"][0]["sha256"] = "9" * 64
            manifest.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                expected=2,
            )

    def test_record_cannot_omit_a_matrix_row_or_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, manifest = self.prepare(Path(temporary))
            parsed = json.loads(record.read_text(encoding="utf-8"))
            removed = parsed["rows"].pop()
            parsed["summary"]["open"] -= len(removed["cases"])
            record.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                expected=2,
            )

            record, manifest = self.prepare(Path(temporary))
            parsed = json.loads(record.read_text(encoding="utf-8"))
            parsed["rows"][0]["cases"].pop()
            parsed["summary"]["open"] -= 1
            record.write_text(json.dumps(parsed), encoding="utf-8")
            run(
                "validate",
                "--record",
                str(record),
                "--artifact-manifest",
                str(manifest),
                expected=2,
            )


if __name__ == "__main__":
    unittest.main()
