#!/usr/bin/env python3
"""Regression tests for stable-beta pilot, gate, and decision evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMMAND = ROOT / "scripts/stable-beta-readiness.py"
PLAN = ROOT / "release/stable-beta-plan-v1.json"
POLICY = ROOT / "release/policy-v1.json"
REVISION = "6" * 40
PILOT_REVISION = "5" * 40
ARTIFACT_DIGEST = "7" * 64
RECORD_DIGEST = "8" * 64


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


def evidence(kind: str) -> dict[str, Any]:
    independent = kind in {
        "accessibility-review",
        "continuity-acceptance",
        "independent-conformance",
        "independent-reproduction",
        "independent-review",
    }
    physical = kind in {
        "accessibility-review",
        "field-run",
        "physical-radio-run",
    }
    return {
        "kind": kind,
        "uri": f"evidence/{kind}.json",
        "sha256": RECORD_DIGEST,
        "revision": REVISION,
        "recorded_at": "2026-08-10T12:00:00Z",
        "producer": "External evaluator" if independent else "Komms project",
        "administrative_domain": "review.example" if independent else None,
        "environment": (
            "Named physical test environment"
            if physical
            else "Documented evidence environment"
        ),
        "independent": independent,
        "physical": physical,
    }


class StableBetaReadinessTests(unittest.TestCase):
    def prepare(self, root: Path) -> tuple[Path, Path, Path]:
        artifacts = root / "artifacts.json"
        artifacts.write_text(
            json.dumps(
                {
                    "schema": "komms-release-artifacts/v1",
                    "revision": REVISION,
                    "artifacts": [
                        {
                            "path": "artifacts/Komms-1.0.0-linux-x86_64-test.AppImage",
                            "sha256": ARTIFACT_DIGEST,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        notes = root / "release-notes.md"
        manifest_sha256 = hashlib.sha256(artifacts.read_bytes()).hexdigest()
        notes.write_text(
            (
                "# Stable-beta candidate\n\n"
                "Private messaging that keeps working.\n\n"
                f"Revision: {REVISION}\n\n"
                f"Artifact manifest SHA-256: {manifest_sha256}\n\n"
                "Queued means durable local custody. Delivered requires an "
                "authenticated end-to-end receipt.\n\n"
                "Not authorized for publication.\n"
            ),
            encoding="utf-8",
        )
        record = root / "stable-beta.json"
        run(
            "prepare",
            "--revision",
            REVISION,
            "--version",
            "1.0.0",
            "--artifact-manifest",
            str(artifacts),
            "--release-notes",
            str(notes),
            "--output",
            str(record),
        )
        return record, artifacts, notes

    def validate(
        self,
        record: Path,
        artifacts: Path,
        notes: Path,
        *,
        ready: bool = False,
        expected: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            "validate",
            "--record",
            str(record),
            "--artifact-manifest",
            str(artifacts),
            "--release-notes",
            str(notes),
            "--expected-revision",
            REVISION,
            "--expected-version",
            "1.0.0",
        ]
        if ready:
            arguments.append("--require-ready")
        return run(*arguments, expected=expected)

    def make_ready(self, record: Path) -> dict[str, Any]:
        value = json.loads(record.read_text(encoding="utf-8"))
        plan = json.loads(PLAN.read_text(encoding="utf-8"))
        pilot = value["pilot"]
        pilot.update(
            {
                "status": "completed",
                "pilot_revision": REVISION,
                "pilot_artifact_manifest_sha256": ARTIFACT_DIGEST,
                "signed_evidence_bundle_sha256": RECORD_DIGEST,
                "started_at": "2026-08-01T12:00:00Z",
                "ended_at": "2026-08-10T12:00:00Z",
                "consent": {
                    "version": "stable-v1-pilot-consent/v1",
                    "disclosures_confirmed": True,
                    "consented": 8,
                    "withdrawn": 0,
                    "completed": 8,
                },
                "aggregate_evidence": [evidence("release-bundle")],
                "outcome": "passed",
            }
        )
        for metric in pilot["metrics"]:
            metric["status"] = "measured"
            metric["result"] = "passed"
            if metric["kind"] == "rate":
                metric["successful"] = 8
                metric["samples"] = 8
            elif metric["kind"] == "count":
                metric["count"] = 0
            else:
                metric["total"] = 80
                metric["samples"] = 8

        for row, template in zip(
            value["candidate_matrix"], plan["candidate_matrix"], strict=True
        ):
            row.update(
                {
                    "status": "passed",
                    "evidence": [
                        evidence(kind)
                        for kind in template["required_evidence_kinds"]
                    ],
                    "result": "Final-candidate matrix row passed.",
                }
            )

        for row, template in zip(value["gate_audit"], plan["gates"], strict=True):
            row.update(
                {
                    "status": "closed",
                    "evidence": [
                        evidence(kind)
                        for kind in template["required_evidence_kinds"]
                    ],
                    "open_findings": [],
                    "closed_at": "2026-08-10T12:00:00Z",
                    "result": "Revision-bound gate evidence is complete.",
                }
            )

        value["support_update"].update(
            {
                "status": "approved",
                "starts_at": "2026-08-10T12:00:00Z",
                "ends_at": "2026-11-10T12:00:00Z",
                "contacts": [
                    {
                        "id": "general-support",
                        "status": "active",
                        "uri": "https://github.com/AndriGitDev/Komms/issues",
                    },
                    {
                        "id": "security",
                        "status": "active",
                        "uri": "SECURITY.md",
                    },
                ],
                "evidence": [evidence("decision-record")],
                "result": "Support and update window approved.",
            }
        )
        value["rollback"].update(
            {
                "status": "approved",
                "selected_action": "withdraw-and-clean-restore",
                "decided_at": "2026-08-10T12:00:00Z",
                "evidence": [
                    evidence("release-bundle"),
                    evidence("field-run"),
                ],
                "result": "Clean restore rollback path passed.",
            }
        )
        value["founder_decision"].update(
            {
                "decision": "go",
                "decided_by": "Andri",
                "decided_at": "2026-08-10T12:00:00Z",
                "evidence": [evidence("decision-record")],
                "result": "Stable-beta candidate preparation approved.",
            }
        )
        value["summary"] = {
            "pilot": "completed",
            "candidate_matrix_passed": len(value["candidate_matrix"]),
            "candidate_matrix_open": 0,
            "p0_closed": len(value["gate_audit"]),
            "p0_open": 0,
            "release_blocking_defects_open": 0,
            "decision": "go",
            "ready": True,
        }
        record.write_text(json.dumps(value), encoding="utf-8")
        return value

    def test_prepared_record_is_valid_but_not_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            result = self.validate(record, artifacts, notes)
            self.assertIn("ready=False", result.stdout)
            self.validate(record, artifacts, notes, ready=True, expected=2)

    def test_not_run_pilot_cannot_contain_measurements(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            value = json.loads(record.read_text(encoding="utf-8"))
            metric = value["pilot"]["metrics"][0]
            metric.update(
                {
                    "status": "measured",
                    "successful": 8,
                    "samples": 8,
                    "result": "passed",
                }
            )
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, expected=2)

    def test_complete_revision_bound_record_can_be_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            self.make_ready(record)
            result = self.validate(record, artifacts, notes, ready=True)
            self.assertIn("p0_closed=10", result.stdout)
            self.assertIn("ready=True", result.stdout)

    def test_independent_and_physical_evidence_cannot_be_relabelled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            value = self.make_ready(record)
            conformance = next(
                row
                for row in value["candidate_matrix"]
                if row["id"] == "conformance"
            )
            conformance["evidence"][0]["independent"] = False
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, ready=True, expected=2)

    def test_pilot_aggregate_may_precede_the_corrected_final_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            value = self.make_ready(record)
            value["pilot"]["pilot_revision"] = PILOT_REVISION
            for row in value["pilot"]["aggregate_evidence"]:
                row["revision"] = PILOT_REVISION
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, ready=True)

    def test_physical_evidence_cannot_be_relabelled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            value = self.make_ready(record)
            physical = next(
                row
                for row in value["candidate_matrix"]
                if row["id"] == "physical-radio"
            )
            physical["evidence"][0]["physical"] = False
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, ready=True, expected=2)

    def test_pilot_requires_release_bundle_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            value = self.make_ready(record)
            value["pilot"]["aggregate_evidence"] = [evidence("ci-run")]
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, ready=True, expected=2)

    def test_gate_cannot_close_without_every_required_evidence_kind(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            value = self.make_ready(record)
            gate = next(row for row in value["gate_audit"] if row["id"] == "P0-06")
            gate["evidence"] = [
                row
                for row in gate["evidence"]
                if row["kind"] != "independent-review"
            ]
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, ready=True, expected=2)

    def test_failed_metric_cannot_be_reported_as_a_passing_pilot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            value = self.make_ready(record)
            metric = next(
                row
                for row in value["pilot"]["metrics"]
                if row["id"] == "install-completion"
            )
            metric["successful"] = 1
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, ready=True, expected=2)

    def test_candidate_decision_cannot_authorize_publication_or_stability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            value = self.make_ready(record)
            value["founder_decision"]["publication_authorized"] = True
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, ready=True, expected=2)

    def test_extra_fields_cannot_smuggle_per_participant_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            value = json.loads(record.read_text(encoding="utf-8"))
            value["pilot"]["participant_ids"] = ["forbidden"]
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, expected=2)

    def test_ready_release_notes_must_be_bound_and_have_no_placeholders(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            self.make_ready(record)
            notes.write_text(
                "Private messaging that keeps working. [version]\n",
                encoding="utf-8",
            )
            value = json.loads(record.read_text(encoding="utf-8"))
            value["release_notes"]["sha256"] = hashlib.sha256(
                notes.read_bytes()
            ).hexdigest()
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, ready=True, expected=2)

            notes.write_text(
                (
                    "Private messaging that keeps working.\n"
                    f"Revision: {REVISION}\n"
                    f"Artifact manifest: {value['artifact_manifest']['sha256']}\n"
                    "Queued means durable local custody. Delivered requires "
                    "an authenticated end-to-end receipt.\n"
                    "Signature: [verification result and fingerprint]\n"
                ),
                encoding="utf-8",
            )
            value["release_notes"]["sha256"] = hashlib.sha256(
                notes.read_bytes()
            ).hexdigest()
            record.write_text(json.dumps(value), encoding="utf-8")
            self.validate(record, artifacts, notes, ready=True, expected=2)

    def test_malformed_scalar_fails_closed_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            record, artifacts, notes = self.prepare(Path(temporary))
            value = json.loads(record.read_text(encoding="utf-8"))
            value["support_update"]["eol_notice_days"] = "thirty"
            record.write_text(json.dumps(value), encoding="utf-8")
            result = self.validate(record, artifacts, notes, expected=2)
            self.assertNotIn("Traceback", result.stderr)
            self.assertIn("stable-beta readiness error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
