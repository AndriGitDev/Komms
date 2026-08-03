#!/usr/bin/env python3
"""Create, validate, and summarize revision-bound field-qualification runs."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MATRIX = ROOT / "field-qualification" / "v1" / "matrix.json"
MATRIX_SCHEMA = "komms-field-qualification-matrix/v1"
RUN_SCHEMA = "komms-field-qualification-run/v1"
SUMMARY_SCHEMA = "komms-field-qualification-summary/v1"
REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
STATUSES = {
    "open",
    "blocked",
    "observed",
    "simulator-pass",
    "pass",
    "fail",
}
EXECUTED = {"observed", "simulator-pass", "pass", "fail"}
ENVIRONMENT_KINDS = {
    "physical-host",
    "physical-device",
    "simulator",
    "network-pair",
    "hil-bench",
}
FORBIDDEN_FIELDS = {
    "password",
    "passphrase",
    "mnemonic",
    "token",
    "provider_token",
    "apns_token",
    "fcm_token",
    "wake_capability",
    "discovery_capability",
    "private_key",
    "secret_key",
    "message_content",
    "contact_graph",
    "safety_number",
    "device_serial",
    "subscriber_id",
}
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024


class FieldError(ValueError):
    """Field evidence does not satisfy the public qualification contract."""


def canonical(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def read_json(path: Path) -> Any:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size > MAX_JSON_BYTES
    ):
        raise FieldError(f"{path}: expected a bounded regular JSON file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FieldError(f"{path}: invalid JSON: {error}") from error


def write_new(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        output.write(canonical(value))


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def bounded_file(path: Path, maximum: int = MAX_EVIDENCE_BYTES) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > maximum:
        raise FieldError(f"{path}: expected a bounded regular file")


def inspect_public(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise FieldError(f"{path}: object key is not text")
            if key.casefold() in FORBIDDEN_FIELDS:
                raise FieldError(f"{path}.{key}: private data field is forbidden")
            inspect_public(nested, f"{path}.{key}")
    elif isinstance(value, list):
        if len(value) > 4096:
            raise FieldError(f"{path}: list is too large")
        for index, nested in enumerate(value):
            inspect_public(nested, f"{path}[{index}]")
    elif isinstance(value, str):
        if len(value.encode("utf-8")) > 64 * 1024:
            raise FieldError(f"{path}: text is too large")
        upper = value.upper()
        if "-----BEGIN " in upper and "PRIVATE KEY-----" in upper:
            raise FieldError(f"{path}: private key material is forbidden")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise FieldError(f"{path}: unsupported JSON value")


def relative_path(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise FieldError(f"{label}: relative path is missing")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise FieldError(f"{label}: path must be normalized and relative")
    return path


def matrix_contract(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    matrix = read_json(path)
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema") != MATRIX_SCHEMA
        or not isinstance(matrix.get("matrix_version"), int)
        or isinstance(matrix.get("matrix_version"), bool)
        or matrix["matrix_version"] <= 0
    ):
        raise FieldError(f"matrix must use {MATRIX_SCHEMA}")
    cells = matrix.get("target_cells")
    scenarios = matrix.get("scenarios")
    if (
        not isinstance(cells, list)
        or not cells
        or len(cells) > 128
        or not isinstance(scenarios, list)
        or not scenarios
        or len(scenarios) > 128
    ):
        raise FieldError("matrix target/scenario inventory is malformed")
    cell_ids: set[str] = set()
    platforms: set[str] = set()
    for cell in cells:
        if not isinstance(cell, dict):
            raise FieldError("matrix contains a malformed target cell")
        identifier = cell.get("id")
        platform = cell.get("platform")
        kind = cell.get("environment_kind")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in cell_ids
            or not isinstance(platform, str)
            or not platform
            or kind not in ENVIRONMENT_KINDS
            or not all(
                isinstance(cell.get(field), str) and cell[field].strip()
                for field in (
                    "device",
                    "os_version",
                    "architecture",
                    "availability",
                )
            )
            or not isinstance(cell.get("qualification_candidate"), bool)
        ):
            raise FieldError("matrix target cell is malformed")
        cell_ids.add(identifier)
        platforms.add(platform)
    scenario_ids: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise FieldError("matrix contains a malformed scenario")
        identifier = scenario.get("id")
        scenario_platforms = scenario.get("platforms")
        kinds = scenario.get("qualifying_environment_kinds")
        procedure = scenario.get("procedure")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in scenario_ids
            or not isinstance(scenario.get("category"), str)
            or not isinstance(scenario_platforms, list)
            or not scenario_platforms
            or not set(scenario_platforms).issubset(platforms)
            or len(scenario_platforms) != len(set(scenario_platforms))
            or not isinstance(kinds, list)
            or not kinds
            or not set(kinds).issubset(ENVIRONMENT_KINDS - {"simulator"})
            or len(kinds) != len(set(kinds))
            or not isinstance(scenario.get("simulator_applicable"), bool)
            or not isinstance(procedure, list)
            or not procedure
            or len(procedure) > 32
            or not isinstance(scenario.get("expected"), str)
            or not scenario["expected"].strip()
        ):
            raise FieldError("matrix scenario is malformed")
        step_ids: set[str] = set()
        for step in procedure:
            if (
                not isinstance(step, dict)
                or not isinstance(step.get("id"), str)
                or not step["id"]
                or step["id"] in step_ids
                or not isinstance(step.get("instruction"), str)
                or not step["instruction"].strip()
            ):
                raise FieldError(f"{identifier}: procedure step is malformed")
            step_ids.add(step["id"])
        scenario_ids.add(identifier)
    inspect_public(matrix)
    return matrix, cells, scenarios


def current_revision() -> str:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if dirty:
        raise FieldError("tracked worktree changes must be committed before a field run")
    return revision


def artifact_record(argument: str) -> dict[str, Any]:
    if "=" not in argument:
        raise FieldError("--artifact must use role=path")
    role, raw_path = argument.split("=", 1)
    if not role or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", role):
        raise FieldError("artifact role must be lowercase kebab-case")
    path = Path(raw_path).expanduser().resolve()
    bounded_file(path, 8 * 1024 * 1024 * 1024)
    return {
        "role": role,
        "name": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, int]:
    result = {status: 0 for status in sorted(STATUSES)}
    for row in rows:
        status = row.get("status")
        if status in result:
            result[status] += 1
    return result


def new_run(args: argparse.Namespace) -> None:
    matrix_path = Path(args.matrix).resolve()
    matrix, cells, scenarios = matrix_contract(matrix_path)
    matches = [cell for cell in cells if cell["id"] == args.cell]
    if len(matches) != 1:
        raise FieldError(f"unknown target cell: {args.cell}")
    cell = matches[0]
    revision = (args.revision or current_revision()).lower()
    if not REVISION_RE.fullmatch(revision):
        raise FieldError("revision must be one full lowercase source digest")
    artifacts = [artifact_record(argument) for argument in args.artifact]
    roles = [artifact["role"] for artifact in artifacts]
    if len(roles) != len(set(roles)):
        raise FieldError("artifact roles must be unique")
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    environment = {
        "cell_id": cell["id"],
        "platform": cell["platform"],
        "kind": cell["environment_kind"],
        "device": args.device or cell["device"],
        "os_version": args.os_version or cell["os_version"],
        "architecture": args.architecture or cell["architecture"],
        "network": args.network,
        "carrier": args.carrier,
        "qualification_candidate": cell["qualification_candidate"],
    }
    if not all(
        isinstance(environment[field], str) and environment[field].strip()
        for field in ("device", "os_version", "architecture")
    ):
        raise FieldError("device, OS version, and architecture must be exact")
    rows = []
    for scenario in scenarios:
        if cell["platform"] not in scenario["platforms"]:
            continue
        rows.append(
            {
                "id": scenario["id"],
                "category": scenario["category"],
                "expected": scenario["expected"],
                "status": "open",
                "started_at": None,
                "ended_at": None,
                "artifact_sha256": [],
                "steps": [
                    {
                        "id": step["id"],
                        "instruction": step["instruction"],
                        "status": "open",
                        "duration_ms": None,
                        "observed": "",
                    }
                    for step in scenario["procedure"]
                ],
                "observed": "",
                "evidence": [],
                "redaction_reviewed": False,
                "blocker": "",
                "retest_disposition": "",
            }
        )
    record = {
        "schema": RUN_SCHEMA,
        "revision": revision,
        "matrix": {
            "path": "field-qualification/v1/matrix.json",
            "version": matrix["matrix_version"],
            "sha256": sha256(matrix_path),
        },
        "artifacts": artifacts,
        "environment": environment,
        "operator_role": args.operator_role,
        "started_at": now,
        "completed_at": None,
        "limitations": [],
        "rows": rows,
        "summary": summarize_rows(rows),
        "claim": (
            "Prepared field record only. Simulator observations never qualify "
            "a physical target, and open or blocked rows remain unsupported."
        ),
    }
    inspect_public(record)
    write_new(Path(args.output), record)


def validate_artifacts(value: Any) -> set[str]:
    if not isinstance(value, list) or not value or len(value) > 32:
        raise FieldError("run has no bounded artifact inventory")
    roles: set[str] = set()
    digests: set[str] = set()
    for artifact in value:
        if (
            not isinstance(artifact, dict)
            or not isinstance(artifact.get("role"), str)
            or artifact["role"] in roles
            or not isinstance(artifact.get("name"), str)
            or PurePosixPath(artifact["name"]).name != artifact["name"]
            or isinstance(artifact.get("bytes"), bool)
            or not isinstance(artifact.get("bytes"), int)
            or artifact["bytes"] <= 0
            or not isinstance(artifact.get("sha256"), str)
            or not DIGEST_RE.fullmatch(artifact["sha256"])
        ):
            raise FieldError("run artifact inventory is malformed")
        roles.add(artifact["role"])
        digests.add(artifact["sha256"])
    return digests


def validate_evidence(
    evidence: Any, evidence_root: Path, label: str, verify_files: bool
) -> None:
    if not isinstance(evidence, list) or not evidence or len(evidence) > 32:
        raise FieldError(f"{label}: executed row needs bounded redacted evidence")
    for index, item in enumerate(evidence):
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("sha256"), str)
            or not DIGEST_RE.fullmatch(item["sha256"])
            or isinstance(item.get("bytes"), bool)
            or not isinstance(item.get("bytes"), int)
            or item["bytes"] <= 0
            or not isinstance(item.get("description"), str)
            or not item["description"].strip()
        ):
            raise FieldError(f"{label}: malformed evidence item {index}")
        relative = relative_path(item.get("path"), f"{label}/evidence[{index}]")
        if verify_files:
            root = evidence_root.resolve()
            path = evidence_root.joinpath(*relative.parts).resolve(strict=True)
            try:
                path.relative_to(root)
            except ValueError as error:
                raise FieldError(f"{label}: evidence path escapes its run directory") from error
            bounded_file(path)
            if path.stat().st_size != item["bytes"] or sha256(path) != item["sha256"]:
                raise FieldError(f"{label}: evidence bytes do not match {relative}")


def validate_run_value(
    record: Any,
    record_path: Path,
    matrix_path: Path,
    expected_revision: str | None,
    verify_files: bool,
) -> dict[str, int]:
    matrix, cells, scenarios = matrix_contract(matrix_path)
    if not isinstance(record, dict) or record.get("schema") != RUN_SCHEMA:
        raise FieldError(f"run must use {RUN_SCHEMA}")
    inspect_public(record)
    revision = record.get("revision")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise FieldError("run revision must be one full lowercase source digest")
    if expected_revision and revision != expected_revision.lower():
        raise FieldError("run revision does not match expected revision")
    if record.get("matrix") != {
        "path": "field-qualification/v1/matrix.json",
        "version": matrix["matrix_version"],
        "sha256": sha256(matrix_path),
    }:
        raise FieldError("run is not bound to the supplied canonical matrix")
    artifact_digests = validate_artifacts(record.get("artifacts"))
    if (
        not isinstance(record.get("operator_role"), str)
        or not record["operator_role"].strip()
        or not isinstance(record.get("started_at"), str)
        or not TIMESTAMP_RE.fullmatch(record["started_at"])
        or (
            record.get("completed_at") is not None
            and (
                not isinstance(record["completed_at"], str)
                or not TIMESTAMP_RE.fullmatch(record["completed_at"])
                or record["completed_at"] < record["started_at"]
            )
        )
        or not isinstance(record.get("limitations"), list)
        or len(record["limitations"]) > 128
        or not all(
            isinstance(limitation, str) and limitation.strip()
            for limitation in record["limitations"]
        )
    ):
        raise FieldError("run timing, role, or limitation header is malformed")
    environment = record.get("environment")
    if not isinstance(environment, dict):
        raise FieldError("run has no environment identity")
    cell_id = environment.get("cell_id")
    matches = [cell for cell in cells if cell["id"] == cell_id]
    if len(matches) != 1:
        raise FieldError("run names an unknown target cell")
    cell = matches[0]
    if (
        environment.get("platform") != cell["platform"]
        or environment.get("kind") != cell["environment_kind"]
        or environment.get("qualification_candidate")
        != cell["qualification_candidate"]
        or not all(
            isinstance(environment.get(field), str)
            and environment[field].strip()
            for field in ("device", "os_version", "architecture")
        )
        or not isinstance(environment.get("network"), str)
        or not isinstance(environment.get("carrier"), str)
    ):
        raise FieldError("run environment does not satisfy its target cell")
    rows = record.get("rows")
    relevant = [
        scenario for scenario in scenarios if cell["platform"] in scenario["platforms"]
    ]
    if (
        not isinstance(rows, list)
        or len(rows) != len(relevant)
        or [
            row.get("id") for row in rows if isinstance(row, dict)
        ]
        != [scenario["id"] for scenario in relevant]
    ):
        raise FieldError("run rows do not match the complete platform matrix")
    for row, scenario in zip(rows, relevant, strict=True):
        label = f"{cell_id}/{scenario['id']}"
        if (
            not isinstance(row, dict)
            or row.get("category") != scenario["category"]
            or row.get("expected") != scenario["expected"]
            or row.get("status") not in STATUSES
        ):
            raise FieldError(f"{label}: row contract differs from the matrix")
        status = row["status"]
        if status == "pass" and (
            not cell["qualification_candidate"]
            or cell["environment_kind"]
            not in scenario["qualifying_environment_kinds"]
        ):
            raise FieldError(
                f"{label}: simulator or non-qualifying environment cannot pass"
            )
        if status == "simulator-pass" and (
            cell["environment_kind"] != "simulator"
            or not scenario["simulator_applicable"]
        ):
            raise FieldError(f"{label}: simulator-pass is not permitted")
        steps = row.get("steps")
        if (
            not isinstance(steps, list)
            or len(steps) != len(scenario["procedure"])
            or [
                (step.get("id"), step.get("instruction"))
                for step in steps
                if isinstance(step, dict)
            ]
            != [
                (step["id"], step["instruction"])
                for step in scenario["procedure"]
            ]
        ):
            raise FieldError(f"{label}: steps differ from the canonical procedure")
        if status in EXECUTED:
            if scenario["category"] in {"real-network", "network-handoff"} and (
                not environment["network"].strip()
            ):
                raise FieldError(f"{label}: network conditions are missing")
            if scenario["id"] in {
                "cgnat-path",
                "mobile-wifi-cellular-handoff",
            } and not environment["carrier"].strip():
                raise FieldError(f"{label}: carrier is missing")
            if status == "pass" and cell["platform"] in {
                "network",
                "meshtastic",
            } and any(
                environment[field] == cell[field]
                for field in ("device", "os_version", "architecture")
            ):
                raise FieldError(
                    f"{label}: exact runtime endpoint/radio identity was not recorded"
                )
            if (
                not isinstance(row.get("started_at"), str)
                or not TIMESTAMP_RE.fullmatch(row["started_at"])
                or not isinstance(row.get("ended_at"), str)
                or not TIMESTAMP_RE.fullmatch(row["ended_at"])
                or row["ended_at"] < row["started_at"]
                or not isinstance(row.get("observed"), str)
                or not row["observed"].strip()
                or row.get("redaction_reviewed") is not True
            ):
                raise FieldError(f"{label}: executed result is incomplete")
            row_digests = row.get("artifact_sha256")
            if (
                not isinstance(row_digests, list)
                or not row_digests
                or not set(row_digests).issubset(artifact_digests)
                or len(row_digests) != len(set(row_digests))
            ):
                raise FieldError(f"{label}: result is not bound to an artifact")
            step_statuses = []
            for step in steps:
                if (
                    step.get("status") not in {"pass", "fail"}
                    or isinstance(step.get("duration_ms"), bool)
                    or not isinstance(step.get("duration_ms"), int)
                    or step["duration_ms"] < 0
                    or not isinstance(step.get("observed"), str)
                    or not step["observed"].strip()
                ):
                    raise FieldError(f"{label}/{step.get('id')}: step is incomplete")
                step_statuses.append(step["status"])
            if status in {"pass", "simulator-pass", "observed"} and set(
                step_statuses
            ) != {"pass"}:
                raise FieldError(f"{label}: successful/observed row has a failed step")
            if status == "fail" and "fail" not in step_statuses:
                raise FieldError(f"{label}: failed row has no failed step")
            validate_evidence(
                row.get("evidence"), record_path.parent, label, verify_files
            )
            if status == "fail" and (
                not isinstance(row.get("retest_disposition"), str)
                or not row["retest_disposition"].strip()
            ):
                raise FieldError(f"{label}: failure needs a retest disposition")
        elif status == "blocked":
            if (
                not isinstance(row.get("blocker"), str)
                or not row["blocker"].strip()
            ):
                raise FieldError(f"{label}: blocked row has no exact blocker")
            if (
                row.get("started_at") is not None
                or row.get("ended_at") is not None
                or row.get("artifact_sha256") != []
                or row.get("evidence") != []
                or row.get("redaction_reviewed") is not False
                or any(
                    step.get("status") != "open"
                    or step.get("duration_ms") is not None
                    or step.get("observed") != ""
                    for step in steps
                )
            ):
                raise FieldError(f"{label}: blocked row contains an unrecorded run")
        else:
            if status != "open":
                raise FieldError(f"{label}: unsupported non-executed state")
            if (
                row.get("started_at") is not None
                or row.get("ended_at") is not None
                or row.get("artifact_sha256") != []
                or row.get("observed") != ""
                or row.get("evidence") != []
                or row.get("redaction_reviewed") is not False
                or row.get("blocker") != ""
                or row.get("retest_disposition") != ""
                or any(
                    step.get("status") != "open"
                    or step.get("duration_ms") is not None
                    or step.get("observed") != ""
                    for step in steps
                )
            ):
                raise FieldError(f"{label}: open row contains an unrecorded result")
    counts = summarize_rows(rows)
    if record.get("summary") != counts:
        raise FieldError("run summary does not match its rows")
    return counts


def validate_run(args: argparse.Namespace) -> None:
    record_path = Path(args.record).resolve()
    counts = validate_run_value(
        read_json(record_path),
        record_path,
        Path(args.matrix).resolve(),
        args.expected_revision,
        not args.skip_evidence_files,
    )
    if args.require_qualified_complete and (
        counts["pass"] == 0
        or any(counts[status] for status in STATUSES - {"pass"})
    ):
        raise FieldError("run does not completely qualify this target cell")
    print(
        "valid field run: "
        + ", ".join(f"{status}={counts[status]}" for status in sorted(STATUSES))
    )


def summarize(args: argparse.Namespace) -> None:
    matrix_path = Path(args.matrix).resolve()
    matrix, cells, scenarios = matrix_contract(matrix_path)
    expected_revision = args.expected_revision.lower()
    if not REVISION_RE.fullmatch(expected_revision):
        raise FieldError("--expected-revision must be a full source digest")
    records = []
    cell_results: dict[str, dict[str, str]] = {}
    for raw_path in args.record:
        path = Path(raw_path).resolve()
        record = read_json(path)
        validate_run_value(
            record,
            path,
            matrix_path,
            expected_revision,
            not args.skip_evidence_files,
        )
        cell_id = record["environment"]["cell_id"]
        if cell_id in cell_results:
            raise FieldError(f"summary has duplicate target cell {cell_id}")
        cell_results[cell_id] = {
            row["id"]: row["status"] for row in record["rows"]
        }
        records.append(
            {
                "cell_id": cell_id,
                "path": Path(raw_path).name,
                "sha256": sha256(path),
            }
        )
    target_rows = []
    for cell in cells:
        relevant = [
            scenario["id"]
            for scenario in scenarios
            if cell["platform"] in scenario["platforms"]
        ]
        results = cell_results.get(cell["id"], {})
        statuses = {
            scenario_id: results.get(scenario_id, "open")
            for scenario_id in relevant
        }
        qualified = bool(statuses) and set(statuses.values()) == {"pass"}
        target_rows.append(
            {
                "id": cell["id"],
                "platform": cell["platform"],
                "environment_kind": cell["environment_kind"],
                "device": cell["device"],
                "os_version": cell["os_version"],
                "architecture": cell["architecture"],
                "availability": cell["availability"],
                "qualified": qualified,
                "scenario_status": statuses,
            }
        )
    summary = {
        "schema": SUMMARY_SCHEMA,
        "revision": expected_revision,
        "matrix": {
            "version": matrix["matrix_version"],
            "sha256": sha256(matrix_path),
        },
        "records": sorted(records, key=lambda item: item["cell_id"]),
        "targets": target_rows,
        "claim": (
            "Only targets whose every applicable scenario is pass are "
            "field-qualified. Simulator-pass and observed results remain "
            "development evidence; absent, blocked, or failed rows are unsupported."
        ),
    }
    inspect_public(summary)
    write_new(Path(args.output), summary)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser("new")
    create.add_argument("--matrix", default=str(DEFAULT_MATRIX))
    create.add_argument("--cell", required=True)
    create.add_argument("--revision")
    create.add_argument("--artifact", action="append", required=True)
    create.add_argument("--device")
    create.add_argument("--os-version")
    create.add_argument("--architecture")
    create.add_argument("--network", default="")
    create.add_argument("--carrier", default="")
    create.add_argument("--operator-role", default="maintainer")
    create.add_argument("--output", required=True)
    create.set_defaults(run=new_run)
    check = commands.add_parser("validate")
    check.add_argument("--matrix", default=str(DEFAULT_MATRIX))
    check.add_argument("--record", required=True)
    check.add_argument("--expected-revision")
    check.add_argument("--skip-evidence-files", action="store_true")
    check.add_argument("--require-qualified-complete", action="store_true")
    check.set_defaults(run=validate_run)
    combine = commands.add_parser("summarize")
    combine.add_argument("--matrix", default=str(DEFAULT_MATRIX))
    combine.add_argument("--expected-revision", required=True)
    combine.add_argument("--record", action="append", default=[])
    combine.add_argument("--skip-evidence-files", action="store_true")
    combine.add_argument("--output", required=True)
    combine.set_defaults(run=summarize)
    return root


def main() -> int:
    try:
        arguments = parser().parse_args()
        arguments.run(arguments)
        return 0
    except (
        FieldError,
        OSError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
    ) as error:
        print(f"field qualification error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
