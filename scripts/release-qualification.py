#!/usr/bin/env python3
"""Prepare and validate revision-bound install and update qualification records."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "komms-release-qualification/v1"
MATRIX_SCHEMA = "komms-release-qualification-matrix/v1"
ARTIFACT_SCHEMA = "komms-release-artifacts/v1"
REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
ALLOWED_STATUS = {"open", "observed", "passed", "failed", "blocked"}
FORBIDDEN_FIELDS = {
    "password",
    "token",
    "private_key",
    "credential",
    "message_content",
    "contact_graph",
    "safety_number",
}


class QualificationError(ValueError):
    """Qualification input does not satisfy the public evidence contract."""


def canonical(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def load(path: Path) -> Any:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
        raise QualificationError(f"{path}: expected a bounded regular file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"{path}: invalid JSON: {error}") from error


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def inspect_public(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise QualificationError(f"{path}: object key is not text")
            if key.lower() in FORBIDDEN_FIELDS:
                raise QualificationError(f"{path}.{key}: private data is forbidden")
            inspect_public(nested, f"{path}.{key}")
    elif isinstance(value, list):
        if len(value) > 2048:
            raise QualificationError(f"{path}: list is too large")
        for index, nested in enumerate(value):
            inspect_public(nested, f"{path}[{index}]")
    elif isinstance(value, str):
        if len(value.encode("utf-8")) > 64 * 1024:
            raise QualificationError(f"{path}: text is too large")
        if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
            raise QualificationError(f"{path}: private key material is forbidden")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise QualificationError(f"{path}: unsupported JSON value")


def matrix_contract(matrix: Any) -> list[dict[str, Any]]:
    if not isinstance(matrix, dict) or matrix.get("schema") != MATRIX_SCHEMA:
        raise QualificationError(f"matrix must use {MATRIX_SCHEMA}")
    version = matrix.get("matrix_version")
    rows = matrix.get("rows")
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version <= 0
        or not isinstance(rows, list)
        or not rows
        or len(rows) > 64
    ):
        raise QualificationError("qualification matrix header is malformed")
    identifiers: set[str] = set()
    result: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise QualificationError("malformed qualification matrix row")
        identifier = row.get("id")
        artifact_class = row.get("artifact_class")
        environment = row.get("environment")
        cases = row.get("required_cases")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in identifiers
            or not isinstance(artifact_class, str)
            or not artifact_class
            or not isinstance(environment, str)
            or not environment
            or not isinstance(cases, list)
            or not cases
            or len(cases) > 32
            or not all(isinstance(case, str) and case for case in cases)
            or len(cases) != len(set(cases))
        ):
            raise QualificationError("qualification matrix row is malformed")
        identifiers.add(identifier)
        result.append(
            {
                "id": identifier,
                "artifact_class": artifact_class,
                "environment": environment,
                "required_cases": cases,
            }
        )
    inspect_public(matrix)
    return result


def prepare(args: argparse.Namespace) -> None:
    matrix_path = Path(args.matrix)
    matrix = load(matrix_path)
    templates = matrix_contract(matrix)
    revision = args.revision.lower()
    if not REVISION_RE.fullmatch(revision):
        raise QualificationError("revision must be a full lowercase source digest")
    if not VERSION_RE.fullmatch(args.version):
        raise QualificationError("version must be a bounded semantic version")
    artifact_manifest = Path(args.artifact_manifest)
    manifest = load(artifact_manifest)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != ARTIFACT_SCHEMA
        or manifest.get("revision") != revision
        or not isinstance(manifest.get("artifacts"), list)
        or not manifest["artifacts"]
    ):
        raise QualificationError("artifact manifest schema or revision does not match")
    rows = []
    for template in templates:
        cases = template["required_cases"]
        rows.append(
            {
                "id": template.get("id"),
                "artifact_class": template.get("artifact_class"),
                "environment_contract": template.get("environment"),
                "environment": None,
                "cases": [
                    {
                        "id": case,
                        "status": "open",
                        "started_at": None,
                        "ended_at": None,
                        "artifact_before_sha256": None,
                        "artifact_after_sha256": None,
                        "steps": [],
                        "result": None,
                    }
                    for case in cases
                ],
            }
        )
    record = {
        "schema": SCHEMA,
        "revision": revision,
        "version": args.version,
        "matrix": {
            "path": PurePosixPath(matrix_path.name).as_posix(),
            "sha256": sha256(matrix_path),
            "matrix_version": matrix["matrix_version"],
        },
        "artifact_manifest": {
            "path": PurePosixPath(artifact_manifest.name).as_posix(),
            "sha256": sha256(artifact_manifest),
        },
        "rows": rows,
        "summary": {
            "passed": 0,
            "failed": 0,
            "blocked": 0,
            "observed": 0,
            "open": sum(len(row["cases"]) for row in rows),
        },
        "claim": "Prepared only; no case is qualified until a named supported environment records an actual run.",
    }
    inspect_public(record)
    Path(args.output).write_text(canonical(record), encoding="utf-8")


def validate_environment(environment: Any, row_id: str, passed: bool) -> None:
    if environment is None:
        if passed:
            raise QualificationError(f"{row_id}: a passed case requires an environment")
        return
    if not isinstance(environment, dict):
        raise QualificationError(f"{row_id}: environment must be an object")
    required = {"kind", "name", "os", "architecture", "supported_claim_cell"}
    if not required.issubset(environment):
        raise QualificationError(f"{row_id}: incomplete environment identity")
    if passed and (
        environment.get("kind") != "named-supported"
        or environment.get("supported_claim_cell") is not True
    ):
        raise QualificationError(
            f"{row_id}: simulator, emulator, generic host, or unsupported cells cannot pass"
        )


def validate(args: argparse.Namespace) -> None:
    record = load(Path(args.record))
    if not isinstance(record, dict) or record.get("schema") != SCHEMA:
        raise QualificationError(f"record must use {SCHEMA}")
    revision = record.get("revision")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise QualificationError("record has no full source revision")
    if args.expected_revision and revision != args.expected_revision.lower():
        raise QualificationError("record revision does not match expected revision")
    version = record.get("version")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise QualificationError("record has no bounded semantic version")
    if args.expected_version and version != args.expected_version:
        raise QualificationError("record version does not match expected version")
    matrix_path = Path(args.matrix)
    matrix = load(matrix_path)
    templates = matrix_contract(matrix)
    matrix_binding = record.get("matrix")
    if matrix_binding != {
        "path": matrix_path.name,
        "sha256": sha256(matrix_path),
        "matrix_version": matrix["matrix_version"],
    }:
        raise QualificationError(
            "qualification record is not bound to the supplied matrix"
        )
    manifest_path = Path(args.artifact_manifest)
    manifest = load(manifest_path)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != ARTIFACT_SCHEMA
        or manifest.get("revision") != revision
    ):
        raise QualificationError("artifact manifest schema or revision does not match")
    binding = record.get("artifact_manifest")
    if (
        not isinstance(binding, dict)
        or binding.get("path") != manifest_path.name
        or binding.get("sha256") != sha256(manifest_path)
    ):
        raise QualificationError(
            "qualification record is not bound to the supplied artifact manifest"
        )
    artifact_rows = manifest.get("artifacts")
    if not isinstance(artifact_rows, list) or not artifact_rows:
        raise QualificationError("artifact manifest has no artifact list")
    digests_by_class: dict[str, set[str]] = {}
    for artifact in artifact_rows:
        if not isinstance(artifact, dict):
            raise QualificationError("artifact manifest has a malformed row")
        path = artifact.get("path")
        digest = artifact.get("sha256")
        if (
            not isinstance(path, str)
            or not isinstance(digest, str)
            or not DIGEST_RE.fullmatch(digest)
        ):
            raise QualificationError("artifact manifest has an invalid row")
        for artifact_class in {
            row.get("artifact_class")
            for row in record.get("rows", [])
            if isinstance(row, dict) and isinstance(row.get("artifact_class"), str)
        }:
            if f"-{artifact_class}-" in PurePosixPath(path).name:
                digests_by_class.setdefault(artifact_class, set()).add(digest)
    inspect_public(record)
    rows = record.get("rows")
    if not isinstance(rows, list) or len(rows) != len(templates):
        raise QualificationError("record does not contain the complete qualification matrix")
    counts = {status: 0 for status in ALLOWED_STATUS}
    row_ids: set[str] = set()
    for row, template in zip(rows, templates, strict=True):
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            raise QualificationError("malformed qualification row")
        row_id = row["id"]
        if row_id in row_ids:
            raise QualificationError(f"{row_id}: duplicate row")
        row_ids.add(row_id)
        artifact_class = row.get("artifact_class")
        if (
            row_id != template["id"]
            or artifact_class != template["artifact_class"]
            or row.get("environment_contract") != template["environment"]
        ):
            raise QualificationError(f"{row_id}: row differs from the canonical matrix")
        cases = row.get("cases")
        expected_case_ids = template["required_cases"]
        if (
            not isinstance(cases, list)
            or [case.get("id") for case in cases if isinstance(case, dict)]
            != expected_case_ids
        ):
            raise QualificationError(f"{row_id}: cases differ from the canonical matrix")
        case_ids: set[str] = set()
        any_passed = any(
            isinstance(case, dict) and case.get("status") == "passed" for case in cases
        )
        validate_environment(row.get("environment"), row_id, any_passed)
        for case in cases:
            if not isinstance(case, dict) or not isinstance(case.get("id"), str):
                raise QualificationError(f"{row_id}: malformed case")
            case_id = case["id"]
            if case_id in case_ids:
                raise QualificationError(f"{row_id}/{case_id}: duplicate case")
            case_ids.add(case_id)
            status = case.get("status")
            if status not in ALLOWED_STATUS:
                raise QualificationError(f"{row_id}/{case_id}: invalid status")
            counts[status] += 1
            if status in {"passed", "failed", "observed"}:
                steps = case.get("steps")
                if (
                    not isinstance(steps, list)
                    or not steps
                    or len(steps) > 128
                    or not all(
                        isinstance(step, str) and step.strip() for step in steps
                    )
                ):
                    raise QualificationError(f"{row_id}/{case_id}: run has no steps")
                started = case.get("started_at")
                ended = case.get("ended_at")
                if (
                    not isinstance(started, str)
                    or not TIMESTAMP_RE.fullmatch(started)
                    or not isinstance(ended, str)
                    or not TIMESTAMP_RE.fullmatch(ended)
                    or ended < started
                    or not isinstance(case.get("result"), str)
                    or not case["result"].strip()
                ):
                    raise QualificationError(f"{row_id}/{case_id}: run is incomplete")
                after = case.get("artifact_after_sha256")
                if not isinstance(after, str) or not DIGEST_RE.fullmatch(after):
                    raise QualificationError(f"{row_id}/{case_id}: artifact digest is missing")
                if after not in digests_by_class.get(artifact_class, set()):
                    raise QualificationError(
                        f"{row_id}/{case_id}: result is not bound to its artifact class"
                    )
            if status == "passed":
                before = case.get("artifact_before_sha256")
                if case_id != "clean-install" and (
                    not isinstance(before, str) or not DIGEST_RE.fullmatch(before)
                ):
                    raise QualificationError(
                        f"{row_id}/{case_id}: transition has no prior artifact digest"
                    )
            if status == "blocked" and (
                not isinstance(case.get("result"), str)
                or not case["result"].strip()
            ):
                raise QualificationError(
                    f"{row_id}/{case_id}: blocked case has no stated blocker"
                )
    expected_summary = {
        "passed": counts["passed"],
        "failed": counts["failed"],
        "blocked": counts["blocked"],
        "observed": counts["observed"],
        "open": counts["open"],
    }
    if record.get("summary") != expected_summary:
        raise QualificationError("summary does not match case rows")
    if args.require_complete and (
        expected_summary["failed"]
        or expected_summary["blocked"]
        or expected_summary["observed"]
        or expected_summary["open"]
        or expected_summary["passed"] == 0
    ):
        raise QualificationError("stable qualification is not completely passed")
    print(
        "qualification record valid: "
        + ", ".join(f"{key}={value}" for key, value in expected_summary.items())
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser("prepare")
    create.add_argument("--matrix", default="release/qualification-matrix-v1.json")
    create.add_argument("--revision", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--artifact-manifest", required=True)
    create.add_argument("--output", required=True)
    create.set_defaults(run=prepare)
    check = commands.add_parser("validate")
    check.add_argument("--matrix", default="release/qualification-matrix-v1.json")
    check.add_argument("--record", required=True)
    check.add_argument("--artifact-manifest", required=True)
    check.add_argument("--expected-revision")
    check.add_argument("--expected-version")
    check.add_argument("--require-complete", action="store_true")
    check.set_defaults(run=validate)
    return root


def main() -> int:
    try:
        arguments = parser().parse_args()
        arguments.run(arguments)
        return 0
    except (QualificationError, OSError) as error:
        print(f"release qualification error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
