#!/usr/bin/env python3
"""Create and validate secret-free native-wake physical-test evidence forms."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX = ROOT / "fixtures" / "native-wake-mobile-field-v1.json"
SCHEMA = "komms-native-wake-mobile-field-run-v1"
STATUSES = {"open", "pass", "fail", "blocked", "simulator-pass"}
FORBIDDEN_FIELDS = {
    "provider_token",
    "apns_token",
    "fcm_token",
    "wake_capability",
    "message_content",
    "contact_graph",
}


def digest(path: pathlib.Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def revision() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def load(path: pathlib.Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def write(path: pathlib.Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def new_run(args: argparse.Namespace) -> int:
    artifact = pathlib.Path(args.artifact).resolve()
    if not artifact.is_file():
        raise ValueError(f"artifact does not exist: {artifact}")
    matrix = load(MATRIX)
    rows = []
    for source in matrix["rows"]:
        if args.platform not in source["platforms"]:
            continue
        rows.append(
            {
                "id": source["id"],
                "requires_physical": source["requires_physical"],
                "status": "open",
                "expected": source["expected"],
                "observed": "",
                "observed_at": "",
                "redacted_evidence": [],
                "retest_disposition": "",
            }
        )
    value = {
        "schema": SCHEMA,
        "revision": revision(),
        "artifact": {
            "path": str(artifact),
            "sha256": digest(artifact),
        },
        "environment": {
            "platform": args.platform,
            "kind": args.environment,
            "device": args.device,
            "os_version": args.os_version,
            "network": args.network,
        },
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "completed_at": "",
        "operator": args.operator,
        "limitations": [],
        "rows": rows,
    }
    output = pathlib.Path(args.output).resolve()
    write(output, value)
    print(output)
    return 0


def field_names(value: object) -> set[str]:
    if isinstance(value, dict):
        names = set(value)
        for nested in value.values():
            names.update(field_names(nested))
        return names
    if isinstance(value, list):
        names: set[str] = set()
        for nested in value:
            names.update(field_names(nested))
        return names
    return set()


def validate_run(args: argparse.Namespace) -> int:
    path = pathlib.Path(args.evidence).resolve()
    value = load(path)
    errors: list[str] = []
    if value.get("schema") != SCHEMA:
        errors.append("schema is not the supported field-run version")
    rev = value.get("revision", "")
    if not re.fullmatch(r"[0-9a-f]{40}", rev):
        errors.append("revision must be one exact Git commit")
    environment = value.get("environment", {})
    platform = environment.get("platform")
    kind = environment.get("kind")
    if platform not in {"android", "ios"}:
        errors.append("platform must be android or ios")
    if kind not in {"physical", "simulator"}:
        errors.append("environment kind must be physical or simulator")
    if not environment.get("device") or not environment.get("os_version"):
        errors.append("device and OS version must be named")
    artifact = pathlib.Path(value.get("artifact", {}).get("path", ""))
    expected_digest = value.get("artifact", {}).get("sha256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        errors.append("artifact SHA-256 is missing or malformed")
    elif artifact.is_file() and digest(artifact) != expected_digest:
        errors.append("artifact bytes no longer match the recorded SHA-256")
    forbidden = field_names(value).intersection(FORBIDDEN_FIELDS)
    if forbidden:
        errors.append(
            "evidence contains forbidden secret/content fields: "
            + ", ".join(sorted(forbidden))
        )

    matrix_rows = {
        row["id"]
        for row in load(MATRIX)["rows"]
        if platform in row["platforms"]
    }
    rows = value.get("rows", [])
    ids = [row.get("id") for row in rows]
    if len(ids) != len(set(ids)):
        errors.append("scenario ids must be unique")
    if set(ids) != matrix_rows:
        errors.append("scenario rows do not match the canonical platform matrix")
    for row in rows:
        row_id = row.get("id", "<missing>")
        status = row.get("status")
        if status not in STATUSES:
            errors.append(f"{row_id}: unsupported status {status!r}")
            continue
        if status == "pass" and kind != "physical":
            errors.append(f"{row_id}: simulator evidence cannot be marked pass")
        if status == "simulator-pass" and kind != "simulator":
            errors.append(f"{row_id}: simulator-pass requires a simulator run")
        if status in {"pass", "fail", "simulator-pass"}:
            if not row.get("observed") or not row.get("observed_at"):
                errors.append(f"{row_id}: observed result and timestamp are required")
            if not row.get("redacted_evidence"):
                errors.append(f"{row_id}: at least one redacted evidence path is required")

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    counts = {status: 0 for status in STATUSES}
    for row in rows:
        counts[row["status"]] += 1
    print(
        f"valid {platform} {kind} evidence: "
        + ", ".join(f"{status}={counts[status]}" for status in sorted(counts))
    )
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser("new")
    create.add_argument("--platform", choices=("android", "ios"), required=True)
    create.add_argument(
        "--environment", choices=("physical", "simulator"), required=True
    )
    create.add_argument("--device", required=True)
    create.add_argument("--os-version", required=True)
    create.add_argument("--network", default="")
    create.add_argument("--operator", default="")
    create.add_argument("--artifact", required=True)
    create.add_argument("--output", required=True)
    create.set_defaults(run=new_run)
    validate = commands.add_parser("validate")
    validate.add_argument("evidence")
    validate.set_defaults(run=validate_run)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        return args.run(args)
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
