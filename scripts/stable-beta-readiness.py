#!/usr/bin/env python3
"""Prepare and validate the bounded stable-beta pilot and gate decision record."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "komms-stable-beta-readiness/v1"
PLAN_SCHEMA = "komms-stable-beta-plan/v1"
ARTIFACT_SCHEMA = "komms-release-artifacts/v1"
POLICY_SCHEMA = "komms-release-policy/v1"
REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
MAX_JSON_BYTES = 4 * 1024 * 1024
EVIDENCE_KINDS = {
    "accessibility-review",
    "asset-attestation",
    "ci-run",
    "conformance-run",
    "continuity-acceptance",
    "decision-record",
    "field-run",
    "incident-exercise",
    "independent-conformance",
    "independent-reproduction",
    "independent-review",
    "operator-run",
    "physical-radio-run",
    "public-copy-audit",
    "release-bundle",
}
INDEPENDENT_KINDS = {
    "accessibility-review",
    "continuity-acceptance",
    "independent-conformance",
    "independent-reproduction",
    "independent-review",
}
PHYSICAL_KINDS = {
    "accessibility-review",
    "field-run",
    "physical-radio-run",
}


class ReadinessError(ValueError):
    """A stable-beta readiness invariant was not met."""


def canonical(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def load(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise ReadinessError(f"{path}: expected a regular JSON file")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ReadinessError(f"{path}: JSON input exceeds {MAX_JSON_BYTES} bytes")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReadinessError(f"{path}: invalid JSON: {error}") from error


def digest(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ReadinessError(f"{path}: expected a regular file")
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def write_new(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(canonical(value))


def expect_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise ReadinessError(
            f"{label}: expected fields {sorted(keys)}, found {actual}"
        )
    return value


def timestamp(value: Any, label: str, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise ReadinessError(f"{label}: expected an RFC3339 UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ReadinessError(f"{label}: invalid timestamp") from error
    if parsed.year < 2026:
        raise ReadinessError(f"{label}: timestamp predates the stabilization program")
    return value


def bounded_text(value: Any, label: str, maximum: int = 2048) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > maximum
        or "\x00" in value
    ):
        raise ReadinessError(f"{label}: expected bounded non-empty text")
    return value


def public_uri(value: Any, label: str) -> str:
    uri = bounded_text(value, label, 1024)
    if uri.startswith("https://"):
        return uri
    pure = PurePosixPath(uri)
    if pure.is_absolute() or pure.as_posix() != uri or ".." in pure.parts:
        raise ReadinessError(f"{label}: expected HTTPS or safe repository-relative URI")
    return uri


def validated_plan(path: Path) -> dict[str, Any]:
    plan = load(path)
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise ReadinessError(f"{path}: expected {PLAN_SCHEMA}")
    if plan.get("plan_version") != 1 or plan.get("profile") != "stable-v1":
        raise ReadinessError("stable-beta plan version or profile is unsupported")
    pilot = plan.get("pilot")
    gates = plan.get("gates")
    matrix = plan.get("candidate_matrix")
    if not isinstance(pilot, dict) or not isinstance(gates, list) or not isinstance(
        matrix, list
    ):
        raise ReadinessError("stable-beta plan is incomplete")
    gate_ids = [row.get("id") for row in gates if isinstance(row, dict)]
    if gate_ids != [f"P0-{number:02d}" for number in range(1, 11)]:
        raise ReadinessError("stable-beta plan must contain P0-01 through P0-10")
    matrix_ids = [row.get("id") for row in matrix if isinstance(row, dict)]
    if len(matrix_ids) != 11 or len(set(matrix_ids)) != len(matrix_ids):
        raise ReadinessError("stable-beta plan has an incomplete candidate matrix")
    metrics = pilot.get("metrics")
    metric_ids = (
        [row.get("id") for row in metrics if isinstance(row, dict)]
        if isinstance(metrics, list)
        else []
    )
    if len(metric_ids) != 11 or len(set(metric_ids)) != len(metric_ids):
        raise ReadinessError("stable-beta plan has an incomplete pilot metric set")
    return plan


def artifact_contract(path: Path, revision: str) -> dict[str, Any]:
    manifest = load(path)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != ARTIFACT_SCHEMA
        or manifest.get("revision") != revision
        or not isinstance(manifest.get("artifacts"), list)
        or not manifest["artifacts"]
    ):
        raise ReadinessError("artifact manifest schema, revision, or inventory is invalid")
    seen: set[str] = set()
    for row in manifest["artifacts"]:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("path"), str)
            or not isinstance(row.get("sha256"), str)
            or not DIGEST_RE.fullmatch(row["sha256"])
            or row["path"] in seen
        ):
            raise ReadinessError("artifact manifest contains an invalid or duplicate row")
        seen.add(row["path"])
    return manifest


def binding(path: Path, logical_name: str) -> dict[str, Any]:
    return {"path": logical_name, "sha256": digest(path)}


def metric_template(template: dict[str, Any]) -> dict[str, Any]:
    common = {
        "id": template["id"],
        "kind": template["kind"],
        "status": "open",
        "result": "No aggregate pilot measurement has been recorded.",
    }
    if template["kind"] == "rate":
        return {**common, "successful": None, "samples": None}
    if template["kind"] == "count":
        return {**common, "count": None}
    if template["kind"] == "average":
        return {**common, "total": None, "samples": None}
    raise ReadinessError(f"{template.get('id')}: unknown pilot metric kind")


def prepare(args: argparse.Namespace) -> None:
    revision = args.revision.lower()
    if not REVISION_RE.fullmatch(revision):
        raise ReadinessError("revision must be a full lowercase source digest")
    if not VERSION_RE.fullmatch(args.version):
        raise ReadinessError("version must be a bounded semantic version")
    plan_path = Path(args.plan)
    policy_path = Path(args.policy)
    artifact_path = Path(args.artifact_manifest)
    notes_path = Path(args.release_notes)
    plan = validated_plan(plan_path)
    policy = load(policy_path)
    if not isinstance(policy, dict) or policy.get("schema") != POLICY_SCHEMA:
        raise ReadinessError("release policy has the wrong schema")
    artifact_contract(artifact_path, revision)
    if not notes_path.is_file() or notes_path.is_symlink():
        raise ReadinessError("release notes must be a regular file")
    pilot_plan = plan["pilot"]
    record = {
        "schema": SCHEMA,
        "revision": revision,
        "version": args.version,
        "profile": "stable-v1",
        "plan": binding(plan_path, plan_path.name),
        "policy": binding(policy_path, policy_path.name),
        "artifact_manifest": binding(artifact_path, "artifacts.json"),
        "release_notes": binding(notes_path, "release-notes.md"),
        "pilot": {
            "status": "not-run",
            "pilot_revision": None,
            "pilot_artifact_manifest_sha256": None,
            "signed_evidence_bundle_sha256": None,
            "started_at": None,
            "ended_at": None,
            "consent": {
                "version": "stable-v1-pilot-consent/v1",
                "disclosures_confirmed": False,
                "consented": 0,
                "withdrawn": 0,
                "completed": 0,
            },
            "privacy_contract": pilot_plan["privacy_contract"],
            "metrics": [
                metric_template(template) for template in pilot_plan["metrics"]
            ],
            "findings": [],
            "aggregate_evidence": [],
            "outcome": "pending",
        },
        "candidate_matrix": [
            {
                "id": template["id"],
                "status": "open",
                "evidence": [],
                "result": "No final-candidate run has been recorded.",
            }
            for template in plan["candidate_matrix"]
        ],
        "gate_audit": [
            {
                "id": template["id"],
                "owner": template["owner"],
                "status": "open",
                "evidence": [],
                "open_findings": [
                    "Closure evidence has not been supplied for this candidate."
                ],
                "closed_at": None,
                "result": "Open pending revision-bound closure evidence.",
            }
            for template in plan["gates"]
        ],
        "release_blocking_defects": [],
        "support_update": {
            "status": "draft",
            "owner": "Andri",
            "starts_at": None,
            "ends_at": None,
            "eol_notice_days": plan["support"]["minimum_eol_notice_days"],
            "contacts": [
                {
                    "id": "general-support",
                    "status": "prepared",
                    "uri": "https://github.com/AndriGitDev/Komms/issues",
                },
                {
                    "id": "security",
                    "status": "prepared",
                    "uri": "SECURITY.md",
                },
            ],
            "update_paths": [
                {
                    "artifact_class": row["id"],
                    "path": row["update_path"],
                }
                for row in policy.get("artifact_classes", [])
            ],
            "evidence": [],
            "result": "Support dates and exercised update evidence remain open.",
        },
        "rollback": {
            "status": "pending",
            "owner": "Andri",
            "triggers": plan["rollback"]["required_triggers"],
            "selected_action": None,
            "previous_artifact_manifest_sha256": None,
            "decided_at": None,
            "evidence": [],
            "result": "No candidate rollback decision has been approved.",
        },
        "founder_decision": {
            "decision": "pending",
            "scope": "stable-beta-candidate-preparation-only",
            "decided_by": None,
            "decided_at": None,
            "evidence": [],
            "merge_authorized": False,
            "publication_authorized": False,
            "stable_claim_authorized": False,
            "result": "No go/no-go decision has been recorded.",
        },
        "summary": {
            "pilot": "not-run",
            "candidate_matrix_passed": 0,
            "candidate_matrix_open": len(plan["candidate_matrix"]),
            "p0_closed": 0,
            "p0_open": len(plan["gates"]),
            "release_blocking_defects_open": 0,
            "decision": "pending",
            "ready": False,
        },
        "claim": (
            "Prepared evidence contract only. It authorizes no merge, publication, "
            "tag, stable claim, or release."
        ),
    }
    write_new(Path(args.output), record)


def validate_binding(
    value: Any, expected_path: str, expected_digest: str, label: str
) -> None:
    row = expect_keys(value, {"path", "sha256"}, label)
    if row != {"path": expected_path, "sha256": expected_digest}:
        raise ReadinessError(f"{label}: binding does not match the supplied file")


def validate_evidence(
    rows: Any, revision: str, label: str
) -> tuple[set[str], list[dict[str, Any]]]:
    if not isinstance(rows, list) or len(rows) > 128:
        raise ReadinessError(f"{label}: evidence must be a bounded list")
    kinds: set[str] = set()
    validated: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    expected_keys = {
        "kind",
        "uri",
        "sha256",
        "revision",
        "recorded_at",
        "producer",
        "administrative_domain",
        "environment",
        "independent",
        "physical",
    }
    for index, row_value in enumerate(rows):
        row = expect_keys(row_value, expected_keys, f"{label}[{index}]")
        kind = row["kind"]
        if kind not in EVIDENCE_KINDS:
            raise ReadinessError(f"{label}[{index}]: unknown evidence kind")
        uri = public_uri(row["uri"], f"{label}[{index}].uri")
        if (
            not isinstance(row["sha256"], str)
            or not DIGEST_RE.fullmatch(row["sha256"])
            or row["revision"] != revision
        ):
            raise ReadinessError(f"{label}[{index}]: digest or revision mismatch")
        timestamp(row["recorded_at"], f"{label}[{index}].recorded_at")
        producer = bounded_text(
            row["producer"], f"{label}[{index}].producer", 256
        )
        environment = bounded_text(
            row["environment"], f"{label}[{index}].environment", 512
        )
        domain = row["administrative_domain"]
        if domain is not None and (
            not isinstance(domain, str)
            or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", domain)
            or domain.startswith((".", "-"))
            or domain.endswith((".", "-"))
        ):
            raise ReadinessError(
                f"{label}[{index}]: malformed administrative domain"
            )
        if not isinstance(row["independent"], bool) or not isinstance(
            row["physical"], bool
        ):
            raise ReadinessError(f"{label}[{index}]: evidence flags must be boolean")
        if kind in INDEPENDENT_KINDS:
            if (
                row["independent"] is not True
                or domain is None
                or producer.casefold()
                in {
                    "andri",
                    "komms",
                    "komms project",
                    "implementation author",
                    "project-controlled",
                }
            ):
                raise ReadinessError(
                    f"{label}[{index}]: independent producer is not separately identified"
                )
        if kind in PHYSICAL_KINDS:
            if row["physical"] is not True or any(
                word in environment.casefold()
                for word in ("simulator", "emulator", "synthetic")
            ):
                raise ReadinessError(
                    f"{label}[{index}]: physical environment is mislabeled"
                )
        identity = (kind, uri)
        if identity in identities:
            raise ReadinessError(f"{label}[{index}]: duplicate evidence row")
        identities.add(identity)
        kinds.add(kind)
        validated.append(row)
    return kinds, validated


def rate_passes(template: dict[str, Any], successful: int, samples: int) -> bool:
    return (
        samples >= template["minimum_samples"]
        and 0 <= successful <= samples
        and successful * 100 >= template["minimum_percent"] * samples
    )


def validate_metrics(
    values: Any, templates: list[dict[str, Any]], complete: bool
) -> tuple[bool, int]:
    if not isinstance(values, list) or len(values) != len(templates):
        raise ReadinessError("pilot metrics do not match the canonical plan")
    all_passed = True
    measured = 0
    for value, template in zip(values, templates, strict=True):
        common = {"id", "kind", "status", "result"}
        kind = template["kind"]
        if kind == "rate":
            keys = common | {"successful", "samples"}
        elif kind == "count":
            keys = common | {"count"}
        elif kind == "average":
            keys = common | {"total", "samples"}
        else:
            raise ReadinessError(f"{template.get('id')}: unknown metric kind")
        row = expect_keys(value, keys, f"pilot metric {template['id']}")
        if row["id"] != template["id"] or row["kind"] != kind:
            raise ReadinessError(f"{template['id']}: metric differs from plan")
        if row["status"] not in {"open", "measured"}:
            raise ReadinessError(f"{template['id']}: invalid metric status")
        bounded_text(row["result"], f"{template['id']}.result")
        if row["status"] == "open":
            payload = [row[key] for key in keys - common]
            if any(value is not None for value in payload):
                raise ReadinessError(f"{template['id']}: open metric contains values")
            all_passed = False
            continue
        measured += 1
        if kind == "rate":
            successful = row["successful"]
            samples = row["samples"]
            if (
                isinstance(successful, bool)
                or not isinstance(successful, int)
                or isinstance(samples, bool)
                or not isinstance(samples, int)
            ):
                raise ReadinessError(f"{template['id']}: rate values must be integers")
            passed = rate_passes(template, successful, samples)
        elif kind == "count":
            count = row["count"]
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ReadinessError(f"{template['id']}: count must be non-negative")
            passed = count <= template["maximum_count"]
        else:
            total = row["total"]
            samples = row["samples"]
            if (
                isinstance(total, bool)
                or not isinstance(total, int)
                or total < 0
                or isinstance(samples, bool)
                or not isinstance(samples, int)
                or samples < template["minimum_samples"]
            ):
                raise ReadinessError(f"{template['id']}: average values are invalid")
            passed = total <= template["maximum_average"] * samples
        expected_result = "passed" if passed else "failed"
        if row["result"] != expected_result:
            raise ReadinessError(f"{template['id']}: result does not match aggregates")
        all_passed &= passed
    if complete and measured != len(templates):
        raise ReadinessError("completed pilot has unmeasured metrics")
    return all_passed, measured


def validate_findings(values: Any, label: str, require_resolved: bool) -> int:
    if not isinstance(values, list) or len(values) > 256:
        raise ReadinessError(f"{label}: findings must be a bounded list")
    identifiers: set[str] = set()
    open_blockers = 0
    keys = {
        "id",
        "severity",
        "status",
        "summary",
        "owner",
        "review_at",
        "evidence",
    }
    for index, value in enumerate(values):
        row = expect_keys(value, keys, f"{label}[{index}]")
        identifier = bounded_text(row["id"], f"{label}[{index}].id", 96)
        if identifier in identifiers:
            raise ReadinessError(f"{label}: duplicate finding id")
        identifiers.add(identifier)
        if row["severity"] not in {"critical", "high", "medium", "low", "info"}:
            raise ReadinessError(f"{identifier}: invalid severity")
        if row["status"] not in {"open", "fixed-verified", "accepted"}:
            raise ReadinessError(f"{identifier}: invalid status")
        bounded_text(row["summary"], f"{identifier}.summary")
        if not isinstance(row["owner"], str) or not row["owner"].strip():
            raise ReadinessError(f"{identifier}: owner is missing")
        timestamp(row["review_at"], f"{identifier}.review_at")
        evidence = row["evidence"]
        if not isinstance(evidence, list) or not evidence or not all(
            isinstance(item, str) and item.strip() for item in evidence
        ):
            raise ReadinessError(f"{identifier}: finding evidence is incomplete")
        if row["status"] == "open" and row["severity"] in {"critical", "high"}:
            open_blockers += 1
    if require_resolved and any(
        row["status"] != "fixed-verified" for row in values
    ):
        raise ReadinessError(f"{label}: release-blocking defect is not fixed and verified")
    return open_blockers


def validate_record(args: argparse.Namespace) -> None:
    record = load(Path(args.record))
    plan_path = Path(args.plan)
    policy_path = Path(args.policy)
    artifact_path = Path(args.artifact_manifest)
    notes_path = Path(args.release_notes)
    plan = validated_plan(plan_path)
    policy = load(policy_path)
    if not isinstance(policy, dict) or policy.get("schema") != POLICY_SCHEMA:
        raise ReadinessError("release policy has the wrong schema")
    top_keys = {
        "schema",
        "revision",
        "version",
        "profile",
        "plan",
        "policy",
        "artifact_manifest",
        "release_notes",
        "pilot",
        "candidate_matrix",
        "gate_audit",
        "release_blocking_defects",
        "support_update",
        "rollback",
        "founder_decision",
        "summary",
        "claim",
    }
    record = expect_keys(record, top_keys, "stable-beta record")
    if record["schema"] != SCHEMA or record["profile"] != "stable-v1":
        raise ReadinessError("stable-beta record has the wrong schema or profile")
    revision = record["revision"]
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise ReadinessError("stable-beta record has no full source revision")
    if args.expected_revision and revision != args.expected_revision.lower():
        raise ReadinessError("stable-beta revision does not match expected revision")
    version = record["version"]
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ReadinessError("stable-beta record has an invalid version")
    if args.expected_version and version != args.expected_version:
        raise ReadinessError("stable-beta version does not match expected version")
    artifact_contract(artifact_path, revision)
    validate_binding(record["plan"], plan_path.name, digest(plan_path), "plan")
    validate_binding(record["policy"], policy_path.name, digest(policy_path), "policy")
    validate_binding(
        record["artifact_manifest"],
        "artifacts.json",
        digest(artifact_path),
        "artifact_manifest",
    )
    validate_binding(
        record["release_notes"],
        "release-notes.md",
        digest(notes_path),
        "release_notes",
    )
    if notes_path.stat().st_size > 512 * 1024:
        raise ReadinessError("release notes exceed the 512 KiB public bound")
    try:
        release_notes = notes_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ReadinessError("release notes are not bounded UTF-8 text") from error
    bounded_text(record["claim"], "claim")

    pilot_keys = {
        "status",
        "pilot_revision",
        "pilot_artifact_manifest_sha256",
        "signed_evidence_bundle_sha256",
        "started_at",
        "ended_at",
        "consent",
        "privacy_contract",
        "metrics",
        "findings",
        "aggregate_evidence",
        "outcome",
    }
    pilot = expect_keys(record["pilot"], pilot_keys, "pilot")
    if pilot["status"] not in {"not-run", "in-progress", "completed"}:
        raise ReadinessError("pilot has an invalid status")
    if pilot["privacy_contract"] != plan["pilot"]["privacy_contract"]:
        raise ReadinessError("pilot privacy contract differs from the canonical plan")
    consent = expect_keys(
        pilot["consent"],
        {"version", "disclosures_confirmed", "consented", "withdrawn", "completed"},
        "pilot.consent",
    )
    if consent["version"] != "stable-v1-pilot-consent/v1":
        raise ReadinessError("pilot consent version is unsupported")
    for key in ("consented", "withdrawn", "completed"):
        if isinstance(consent[key], bool) or not isinstance(consent[key], int) or consent[key] < 0:
            raise ReadinessError(f"pilot consent {key} must be non-negative")
    if consent["withdrawn"] > consent["consented"] or consent["completed"] > (
        consent["consented"] - consent["withdrawn"]
    ):
        raise ReadinessError("pilot consent totals are inconsistent")
    if not isinstance(consent["disclosures_confirmed"], bool):
        raise ReadinessError("pilot disclosure state must be boolean")
    complete = pilot["status"] == "completed"
    metric_passed, _ = validate_metrics(
        pilot["metrics"], plan["pilot"]["metrics"], complete
    )
    pilot_open_blockers = validate_findings(pilot["findings"], "pilot.findings", False)
    if pilot["status"] == "not-run":
        _, aggregate_evidence = validate_evidence(
            pilot["aggregate_evidence"], revision, "pilot.aggregate_evidence"
        )
        if any(
            pilot[field] is not None
            for field in (
                "pilot_revision",
                "pilot_artifact_manifest_sha256",
                "signed_evidence_bundle_sha256",
                "started_at",
                "ended_at",
            )
        ):
            raise ReadinessError("not-run pilot contains run identity")
        if (
            consent
            != {
                "version": "stable-v1-pilot-consent/v1",
                "disclosures_confirmed": False,
                "consented": 0,
                "withdrawn": 0,
                "completed": 0,
            }
            or aggregate_evidence
            or pilot["findings"]
            or any(metric["status"] != "open" for metric in pilot["metrics"])
        ):
            raise ReadinessError("not-run pilot contains participation evidence")
        if pilot["outcome"] != "pending":
            raise ReadinessError("not-run pilot outcome must be pending")
    else:
        pilot_revision = pilot["pilot_revision"]
        if not isinstance(pilot_revision, str) or not REVISION_RE.fullmatch(
            pilot_revision
        ):
            raise ReadinessError("pilot run has no full artifact revision")
        for field in (
            "pilot_artifact_manifest_sha256",
            "signed_evidence_bundle_sha256",
        ):
            if not isinstance(pilot[field], str) or not DIGEST_RE.fullmatch(
                pilot[field]
            ):
                raise ReadinessError(f"pilot run has no valid {field}")
        aggregate_kinds, aggregate_evidence = validate_evidence(
            pilot["aggregate_evidence"],
            pilot_revision,
            "pilot.aggregate_evidence",
        )
        started = timestamp(pilot["started_at"], "pilot.started_at")
        ended = timestamp(pilot["ended_at"], "pilot.ended_at", optional=not complete)
        if ended is not None:
            start_value = datetime.strptime(started, "%Y-%m-%dT%H:%M:%SZ")
            end_value = datetime.strptime(ended, "%Y-%m-%dT%H:%M:%SZ")
            duration_seconds = (end_value - start_value).total_seconds()
            if (
                duration_seconds < 0
                or duration_seconds
                > plan["pilot"]["maximum_duration_days"] * 24 * 60 * 60
            ):
                raise ReadinessError("pilot duration is outside its bounded window")
        if not consent["disclosures_confirmed"]:
            raise ReadinessError("pilot disclosures were not confirmed")
        if consent["consented"] > plan["pilot"]["maximum_consented_participants"]:
            raise ReadinessError("pilot exceeds its participant cap")
        if "release-bundle" not in aggregate_kinds or not aggregate_evidence:
            raise ReadinessError("pilot run has no signed release-bundle evidence")
        if not complete and pilot["ended_at"] is not None:
            raise ReadinessError("in-progress pilot cannot have an end time")
        if complete:
            if consent["consented"] < plan["pilot"]["minimum_consented_participants"]:
                raise ReadinessError("completed pilot has too few consented participants")
            if consent["completed"] < plan["pilot"]["minimum_completed_participants"]:
                raise ReadinessError("completed pilot has too few completed participants")
            expected_outcome = (
                "passed"
                if metric_passed and pilot_open_blockers == 0
                else "failed"
            )
            if pilot["outcome"] != expected_outcome:
                raise ReadinessError("pilot outcome does not match aggregate evidence")
        elif pilot["outcome"] != "pending":
            raise ReadinessError("in-progress pilot outcome must be pending")

    matrix = record["candidate_matrix"]
    templates = plan["candidate_matrix"]
    if not isinstance(matrix, list) or len(matrix) != len(templates):
        raise ReadinessError("candidate matrix differs from the canonical plan")
    matrix_passed = 0
    matrix_open = 0
    for row_value, template in zip(matrix, templates, strict=True):
        row = expect_keys(
            row_value, {"id", "status", "evidence", "result"}, "candidate matrix row"
        )
        if row["id"] != template["id"] or row["status"] not in {
            "open",
            "blocked",
            "failed",
            "passed",
        }:
            raise ReadinessError(f"{template['id']}: invalid candidate matrix row")
        bounded_text(row["result"], f"{template['id']}.result")
        kinds, evidence = validate_evidence(
            row["evidence"], revision, f"candidate_matrix.{template['id']}"
        )
        if row["status"] == "passed":
            missing = set(template["required_evidence_kinds"]) - kinds
            if missing or not evidence:
                raise ReadinessError(
                    f"{template['id']}: passed row lacks {sorted(missing)}"
                )
            matrix_passed += 1
        else:
            matrix_open += 1

    audit = record["gate_audit"]
    gate_templates = plan["gates"]
    if not isinstance(audit, list) or len(audit) != len(gate_templates):
        raise ReadinessError("P0 audit differs from the canonical plan")
    p0_closed = 0
    p0_open = 0
    for row_value, template in zip(audit, gate_templates, strict=True):
        row = expect_keys(
            row_value,
            {
                "id",
                "owner",
                "status",
                "evidence",
                "open_findings",
                "closed_at",
                "result",
            },
            "gate audit row",
        )
        if (
            row["id"] != template["id"]
            or row["owner"] != template["owner"]
            or row["status"] not in {"open", "closed"}
        ):
            raise ReadinessError(f"{template['id']}: gate audit row differs from plan")
        bounded_text(row["result"], f"{template['id']}.result")
        if not isinstance(row["open_findings"], list) or not all(
            isinstance(item, str) and item.strip() for item in row["open_findings"]
        ):
            raise ReadinessError(f"{template['id']}: malformed open findings")
        kinds, evidence = validate_evidence(
            row["evidence"], revision, f"gate_audit.{template['id']}"
        )
        if row["status"] == "closed":
            missing = set(template["required_evidence_kinds"]) - kinds
            if missing or not evidence or row["open_findings"]:
                raise ReadinessError(
                    f"{template['id']}: closed gate lacks required evidence or has findings"
                )
            timestamp(row["closed_at"], f"{template['id']}.closed_at")
            p0_closed += 1
        else:
            if not row["open_findings"] or row["closed_at"] is not None:
                raise ReadinessError(f"{template['id']}: open gate status is inconsistent")
            p0_open += 1

    blocker_findings = validate_findings(
        record["release_blocking_defects"],
        "release_blocking_defects",
        args.require_ready,
    )
    open_defects = sum(
        1
        for row in record["release_blocking_defects"]
        if row["status"] != "fixed-verified"
    )

    support = expect_keys(
        record["support_update"],
        {
            "status",
            "owner",
            "starts_at",
            "ends_at",
            "eol_notice_days",
            "contacts",
            "update_paths",
            "evidence",
            "result",
        },
        "support_update",
    )
    if support["status"] not in {"draft", "approved"} or support["owner"] != "Andri":
        raise ReadinessError("support/update plan has an invalid status or owner")
    bounded_text(support["result"], "support_update.result")
    if (
        isinstance(support["eol_notice_days"], bool)
        or not isinstance(support["eol_notice_days"], int)
        or support["eol_notice_days"] < plan["support"]["minimum_eol_notice_days"]
    ):
        raise ReadinessError("support/update plan has insufficient EOL notice")
    expected_updates = [
        {"artifact_class": row["id"], "path": row["update_path"]}
        for row in policy.get("artifact_classes", [])
    ]
    if support["update_paths"] != expected_updates:
        raise ReadinessError("support/update paths differ from release policy")
    contacts = support["contacts"]
    if not isinstance(contacts, list) or [
        row.get("id") for row in contacts if isinstance(row, dict)
    ] != plan["support"]["required_contacts"]:
        raise ReadinessError("support/update contacts differ from plan")
    for row in contacts:
        expect_keys(row, {"id", "status", "uri"}, f"support contact {row.get('id')}")
        if row["status"] not in {"prepared", "active"}:
            raise ReadinessError(f"{row['id']}: invalid support contact status")
        public_uri(row["uri"], f"{row['id']}.uri")
    support_kinds, support_evidence = validate_evidence(
        support["evidence"], revision, "support_update.evidence"
    )
    if support["status"] == "approved":
        start = timestamp(support["starts_at"], "support_update.starts_at")
        end = timestamp(support["ends_at"], "support_update.ends_at")
        start_value = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
        end_value = datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ")
        if (end_value - start_value).days < plan["support"]["minimum_support_days"]:
            raise ReadinessError("support window is shorter than policy")
        if any(row["status"] != "active" for row in contacts):
            raise ReadinessError("approved support plan has an inactive contact")
        if "decision-record" not in support_kinds or not support_evidence:
            raise ReadinessError("approved support plan lacks decision evidence")
    elif support["starts_at"] is not None or support["ends_at"] is not None:
        raise ReadinessError("draft support plan must not claim a support window")

    rollback = expect_keys(
        record["rollback"],
        {
            "status",
            "owner",
            "triggers",
            "selected_action",
            "previous_artifact_manifest_sha256",
            "decided_at",
            "evidence",
            "result",
        },
        "rollback",
    )
    if rollback["status"] not in {"pending", "approved"} or rollback["owner"] != "Andri":
        raise ReadinessError("rollback decision has an invalid status or owner")
    if rollback["triggers"] != plan["rollback"]["required_triggers"]:
        raise ReadinessError("rollback triggers differ from the canonical plan")
    bounded_text(rollback["result"], "rollback.result")
    rollback_kinds, rollback_evidence = validate_evidence(
        rollback["evidence"], revision, "rollback.evidence"
    )
    if rollback["status"] == "approved":
        if rollback["selected_action"] not in {
            "restore-previous-compatible-artifacts",
            "withdraw-and-clean-restore",
        }:
            raise ReadinessError("rollback action is unsupported")
        if rollback["selected_action"] == "restore-previous-compatible-artifacts" and (
            not isinstance(rollback["previous_artifact_manifest_sha256"], str)
            or not DIGEST_RE.fullmatch(
                rollback["previous_artifact_manifest_sha256"]
            )
        ):
            raise ReadinessError("rollback decision lacks the prior artifact manifest")
        if rollback["selected_action"] == "withdraw-and-clean-restore" and rollback[
            "previous_artifact_manifest_sha256"
        ] is not None:
            raise ReadinessError("clean-restore rollback must not name prior artifacts")
        timestamp(rollback["decided_at"], "rollback.decided_at")
        if not {"release-bundle", "field-run"}.issubset(rollback_kinds) or not rollback_evidence:
            raise ReadinessError("approved rollback lacks release and field evidence")
    elif any(
        rollback[field] is not None
        for field in (
            "selected_action",
            "previous_artifact_manifest_sha256",
            "decided_at",
        )
    ) or rollback_evidence:
        raise ReadinessError("pending rollback contains an approval")

    decision = expect_keys(
        record["founder_decision"],
        {
            "decision",
            "scope",
            "decided_by",
            "decided_at",
            "evidence",
            "merge_authorized",
            "publication_authorized",
            "stable_claim_authorized",
            "result",
        },
        "founder_decision",
    )
    if decision["decision"] not in {"pending", "go", "no-go"}:
        raise ReadinessError("founder decision is invalid")
    if decision["scope"] != "stable-beta-candidate-preparation-only":
        raise ReadinessError("founder decision scope is too broad")
    if any(
        decision[field] is not False
        for field in (
            "merge_authorized",
            "publication_authorized",
            "stable_claim_authorized",
        )
    ):
        raise ReadinessError(
            "stable-beta decision cannot authorize merge, publication, or a stable claim"
        )
    bounded_text(decision["result"], "founder_decision.result")
    decision_kinds, decision_evidence = validate_evidence(
        decision["evidence"], revision, "founder_decision.evidence"
    )
    if decision["decision"] == "pending":
        if (
            decision["decided_by"] is not None
            or decision["decided_at"] is not None
            or decision_evidence
        ):
            raise ReadinessError("pending founder decision contains an authorization")
    else:
        if decision["decided_by"] != "Andri":
            raise ReadinessError("founder decision must retain accountable authorship")
        timestamp(decision["decided_at"], "founder_decision.decided_at")
        if "decision-record" not in decision_kinds or not decision_evidence:
            raise ReadinessError("founder decision lacks durable evidence")

    ready = (
        complete
        and pilot["outcome"] == "passed"
        and matrix_open == 0
        and p0_open == 0
        and open_defects == 0
        and blocker_findings == 0
        and support["status"] == "approved"
        and rollback["status"] == "approved"
        and decision["decision"] == "go"
    )
    if ready:
        unfilled = (
            "[version]",
            "[full revision]",
            "[digest]",
            "[verification result",
            "[supported cell",
            "[review/report",
            "[evidence",
            "[open or explicitly accepted risk",
        )
        if any(marker in release_notes for marker in unfilled):
            raise ReadinessError("ready candidate release notes contain placeholders")
        for required in (
            "Private messaging that keeps working",
            "Queued means",
            "Delivered requires",
            revision,
            record["artifact_manifest"]["sha256"],
        ):
            if required not in release_notes:
                raise ReadinessError(
                    f"ready candidate release notes omit required binding or limit: {required}"
                )
    expected_summary = {
        "pilot": pilot["status"],
        "candidate_matrix_passed": matrix_passed,
        "candidate_matrix_open": matrix_open,
        "p0_closed": p0_closed,
        "p0_open": p0_open,
        "release_blocking_defects_open": open_defects,
        "decision": decision["decision"],
        "ready": ready,
    }
    if record["summary"] != expected_summary:
        raise ReadinessError("stable-beta summary does not match its evidence")
    if args.require_ready and not ready:
        raise ReadinessError("stable-beta candidate is not ready")
    print(
        "stable-beta readiness valid: "
        + ", ".join(f"{key}={value}" for key, value in expected_summary.items())
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser("prepare")
    create.add_argument("--revision", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--artifact-manifest", required=True)
    create.add_argument("--release-notes", required=True)
    create.add_argument("--plan", default="release/stable-beta-plan-v1.json")
    create.add_argument("--policy", default="release/policy-v1.json")
    create.add_argument("--output", required=True)
    create.set_defaults(run=prepare)
    check = commands.add_parser("validate")
    check.add_argument("--record", required=True)
    check.add_argument("--artifact-manifest", required=True)
    check.add_argument("--release-notes", required=True)
    check.add_argument("--plan", default="release/stable-beta-plan-v1.json")
    check.add_argument("--policy", default="release/policy-v1.json")
    check.add_argument("--expected-revision")
    check.add_argument("--expected-version")
    check.add_argument("--require-ready", action="store_true")
    check.set_defaults(run=validate_record)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        args.run(args)
        return 0
    except ReadinessError as error:
        print(f"stable-beta readiness error: {error}", file=sys.stderr)
        return 2
    except (AttributeError, IndexError, KeyError, TypeError) as error:
        print(
            "stable-beta readiness error: malformed structured input "
            f"({type(error).__name__})",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
