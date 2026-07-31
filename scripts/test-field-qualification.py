#!/usr/bin/env python3
"""Regression tests for field-qualification evidence boundaries."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMAND = ROOT / "scripts" / "field-qualification.py"
REVISION = "4" * 40


def run(*arguments: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(COMMAND), *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"returned {result.returncode}, expected {expected}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class FieldQualificationTests(unittest.TestCase):
    def prepare(self, root: Path, cell: str) -> tuple[Path, Path]:
        artifact = root / "Komms.test"
        artifact.write_bytes(b"revision-bound application")
        record = root / f"{cell}.json"
        run(
            "new",
            "--cell",
            cell,
            "--revision",
            REVISION,
            "--artifact",
            f"application={artifact}",
            "--output",
            str(record),
        )
        return record, artifact

    def complete_first(
        self, record: Path, artifact: Path, status: str
    ) -> dict:
        value = json.loads(record.read_text(encoding="utf-8"))
        evidence = record.parent / "redacted.txt"
        evidence.write_text("synthetic aggregate result\n", encoding="utf-8")
        row = value["rows"][0]
        row.update(
            {
                "status": status,
                "started_at": "2026-07-31T10:00:00Z",
                "ended_at": "2026-07-31T10:01:00Z",
                "artifact_sha256": [digest(artifact)],
                "observed": "Synthetic fixture completed.",
                "evidence": [
                    {
                        "path": evidence.name,
                        "bytes": evidence.stat().st_size,
                        "sha256": digest(evidence),
                        "description": "Synthetic redacted output.",
                    }
                ],
                "redaction_reviewed": True,
            }
        )
        for step in row["steps"]:
            step.update(
                {
                    "status": "pass",
                    "duration_ms": 1,
                    "observed": "Synthetic step completed.",
                }
            )
        value["summary"]["open"] -= 1
        value["summary"][status] += 1
        record.write_text(json.dumps(value), encoding="utf-8")
        return value

    def test_open_record_is_valid_but_not_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, _ = self.prepare(
                Path(temporary), "macbook-air-m1-macos-26-5-2"
            )
            result = run(
                "validate",
                "--record",
                str(record),
                "--expected-revision",
                REVISION,
            )
            self.assertIn("open=", result.stdout)
            run(
                "validate",
                "--record",
                str(record),
                "--require-qualified-complete",
                expected=2,
            )

    def test_simulator_cannot_be_recorded_as_physical_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, artifact = self.prepare(
                root, "android-api35-arm64-emulator"
            )
            self.complete_first(record, artifact, "pass")
            run("validate", "--record", str(record), expected=2)

    def test_simulator_pass_is_honest_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, artifact = self.prepare(
                root, "android-api35-arm64-emulator"
            )
            self.complete_first(record, artifact, "simulator-pass")
            run("validate", "--record", str(record))

    def test_non_applicable_simulator_scenario_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, artifact = self.prepare(
                root, "iphone-17-pro-ios-26-5-simulator"
            )
            value = self.complete_first(record, artifact, "simulator-pass")
            row = next(
                row
                for row in value["rows"]
                if row["id"] == "audio-call-direct-and-fallback"
            )
            source = value["rows"][0]
            row.update(
                {
                    key: source[key]
                    for key in (
                        "status",
                        "started_at",
                        "ended_at",
                        "artifact_sha256",
                        "observed",
                        "evidence",
                        "redaction_reviewed",
                    )
                }
            )
            for step in row["steps"]:
                step.update(
                    {
                        "status": "pass",
                        "duration_ms": 1,
                        "observed": "Synthetic step completed.",
                    }
                )
            value["summary"]["open"] -= 1
            value["summary"]["simulator-pass"] += 1
            record.write_text(json.dumps(value), encoding="utf-8")
            run("validate", "--record", str(record), expected=2)

    def test_missing_row_and_changed_evidence_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, artifact = self.prepare(
                root, "macbook-air-m1-macos-26-5-2"
            )
            value = self.complete_first(record, artifact, "pass")
            evidence = root / "redacted.txt"
            evidence.write_text("changed\n", encoding="utf-8")
            run("validate", "--record", str(record), expected=2)
            evidence.write_text("synthetic aggregate result\n", encoding="utf-8")
            value["rows"].pop()
            value["summary"]["open"] -= 1
            record.write_text(json.dumps(value), encoding="utf-8")
            run("validate", "--record", str(record), expected=2)

    def test_private_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, _ = self.prepare(
                Path(temporary), "macbook-air-m1-macos-26-5-2"
            )
            value = json.loads(record.read_text(encoding="utf-8"))
            value["provider_token"] = "not permitted"
            record.write_text(json.dumps(value), encoding="utf-8")
            run("validate", "--record", str(record), expected=2)

    def test_summary_does_not_promote_open_or_simulator_cells(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, _ = self.prepare(
                root, "android-api35-arm64-emulator"
            )
            output = root / "summary.json"
            run(
                "summarize",
                "--expected-revision",
                REVISION,
                "--record",
                str(record),
                "--output",
                str(output),
            )
            value = json.loads(output.read_text(encoding="utf-8"))
            emulator = next(
                target
                for target in value["targets"]
                if target["id"] == "android-api35-arm64-emulator"
            )
            self.assertFalse(emulator["qualified"])
            self.assertEqual(
                set(emulator["scenario_status"].values()), {"open"}
            )


if __name__ == "__main__":
    unittest.main()
