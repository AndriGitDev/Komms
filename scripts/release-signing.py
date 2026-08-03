#!/usr/bin/env python3
"""Prepare and validate public, revision-bound release-signing evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "komms-release-signing/v1"
POLICY_SCHEMA = "komms-release-policy/v1"
ARTIFACT_SCHEMA = "komms-release-artifacts/v1"
REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._+/=-]{7,255}$")
STATUS = {"open", "verified", "failed", "blocked"}
FORBIDDEN_PARTS = ("password", "private_key", "private-key", "credential", "token")


class SigningError(ValueError):
    """Signing evidence violated the public release contract."""


def canonical(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def load(path: Path) -> Any:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 8 * 1024 * 1024:
        raise SigningError(f"{path}: expected a bounded regular JSON file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SigningError(f"{path}: invalid JSON: {error}") from error


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def inspect_public(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise SigningError(f"{path}: object key is not text")
            lowered = key.lower()
            if any(part in lowered for part in FORBIDDEN_PARTS):
                raise SigningError(f"{path}.{key}: secret-bearing fields are forbidden")
            inspect_public(nested, f"{path}.{key}")
    elif isinstance(value, list):
        if len(value) > 1024:
            raise SigningError(f"{path}: list is too large")
        for index, nested in enumerate(value):
            inspect_public(nested, f"{path}[{index}]")
    elif isinstance(value, str):
        if len(value.encode("utf-8")) > 64 * 1024:
            raise SigningError(f"{path}: text is too large")
        if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
            raise SigningError(f"{path}: private key material is forbidden")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise SigningError(f"{path}: unsupported JSON value")


def policy_roles(
    policy: dict[str, Any],
) -> tuple[list[str], dict[str, set[str]], dict[str, dict[str, Any]]]:
    if policy.get("schema") != POLICY_SCHEMA:
        raise SigningError(f"policy must use {POLICY_SCHEMA}")
    roles = policy.get("signing_roles")
    channels = policy.get("channels")
    if not isinstance(roles, list) or not isinstance(channels, dict):
        raise SigningError("release policy is incomplete")
    role_ids = [row.get("id") for row in roles if isinstance(row, dict)]
    if (
        len(role_ids) != len(roles)
        or not all(isinstance(role, str) and role for role in role_ids)
        or len(set(role_ids)) != len(role_ids)
    ):
        raise SigningError("release policy has malformed signing roles")
    required: dict[str, set[str]] = {}
    for channel, configuration in channels.items():
        if not isinstance(channel, str) or not isinstance(configuration, dict):
            raise SigningError("release policy has malformed channels")
        values = configuration.get("required_signing_roles")
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise SigningError(f"{channel}: malformed required signing roles")
        if not set(values).issubset(set(role_ids)):
            raise SigningError(f"{channel}: unknown required signing role")
        required[channel] = set(values)
    artifact_classes = policy.get("artifact_classes")
    if not isinstance(artifact_classes, list) or not artifact_classes:
        raise SigningError("release policy has no artifact classes")
    classes: dict[str, dict[str, Any]] = {}
    for row in artifact_classes:
        if not isinstance(row, dict):
            raise SigningError("release policy has a malformed artifact class")
        identifier = row.get("id")
        signing_role = row.get("signing_role")
        formats = row.get("formats")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in classes
            or signing_role not in role_ids
            or not isinstance(formats, list)
            or not formats
            or not all(isinstance(value, str) and value for value in formats)
        ):
            raise SigningError("release policy has a malformed artifact class")
        classes[identifier] = {
            "signing_role": signing_role,
            "formats": tuple(formats),
        }
    return role_ids, required, classes


def classified_artifacts(
    manifest: dict[str, Any],
    revision: str,
    classes: dict[str, dict[str, Any]],
    strict: bool,
) -> tuple[set[str], dict[str, set[str]], set[str]]:
    if manifest.get("schema") != ARTIFACT_SCHEMA or manifest.get("revision") != revision:
        raise SigningError("artifact manifest schema or revision mismatch")
    artifact_rows = manifest.get("artifacts")
    if not isinstance(artifact_rows, list) or not artifact_rows:
        raise SigningError("artifact manifest has no artifact list")
    all_digests: set[str] = set()
    by_role: dict[str, set[str]] = {}
    covered_classes: set[str] = set()
    paths: set[str] = set()
    for row in artifact_rows:
        if not isinstance(row, dict):
            raise SigningError("artifact manifest has a malformed row")
        path = row.get("path")
        artifact_digest = row.get("sha256")
        if (
            not isinstance(path, str)
            or not isinstance(artifact_digest, str)
            or not DIGEST_RE.fullmatch(artifact_digest)
            or path in paths
        ):
            raise SigningError("artifact manifest has an invalid or duplicate artifact")
        pure = PurePosixPath(path)
        if (
            pure.is_absolute()
            or pure.as_posix() != path
            or len(pure.parts) < 2
            or pure.parts[0] != "artifacts"
            or ".." in pure.parts
        ):
            raise SigningError(f"{path}: unsafe artifact path")
        matches = [
            identifier
            for identifier in classes
            if f"-{identifier}-" in pure.name
        ]
        if len(matches) > 1 or (strict and len(matches) != 1):
            raise SigningError(f"{path}: artifact class is ambiguous or missing")
        if matches:
            artifact_class = matches[0]
            formats = classes[artifact_class]["formats"]
            if not any(pure.name.endswith(f".{suffix}") for suffix in formats):
                raise SigningError(f"{path}: artifact format is outside its class policy")
            role = classes[artifact_class]["signing_role"]
            by_role.setdefault(role, set()).add(artifact_digest)
            covered_classes.add(artifact_class)
        paths.add(path)
        all_digests.add(artifact_digest)
    return all_digests, by_role, covered_classes


def prepare(args: argparse.Namespace) -> None:
    revision = args.revision.lower()
    if not REVISION_RE.fullmatch(revision):
        raise SigningError("revision must be a full lowercase source digest")
    policy = load(Path(args.policy))
    manifest_path = Path(args.artifact_manifest)
    manifest = load(manifest_path)
    if not isinstance(policy, dict) or not isinstance(manifest, dict):
        raise SigningError("policy and artifact manifest must be objects")
    roles, _, classes = policy_roles(policy)
    classified_artifacts(manifest, revision, classes, strict=False)
    record = {
        "schema": SCHEMA,
        "revision": revision,
        "artifact_manifest": {
            "path": manifest_path.name,
            "sha256": digest(manifest_path),
        },
        "roles": [
            {
                "id": role,
                "status": "open",
                "public_fingerprint": None,
                "verified_at": None,
                "verifier": None,
                "artifact_sha256": [],
                "evidence": [],
                "result": "No signing-role enrollment or verification evidence has been supplied.",
            }
            for role in roles
        ],
        "summary": {"verified": 0, "failed": 0, "blocked": 0, "open": len(roles)},
        "claim": (
            "Prepared only. Platform roles require their exact class artifact set to "
            "pass the named verifier. The release-manifest role records enrollment "
            "and complete artifact coverage; publication separately verifies the "
            "completed detached bundle signature."
        ),
    }
    inspect_public(record)
    Path(args.output).write_text(canonical(record), encoding="utf-8")


def validate(args: argparse.Namespace) -> None:
    policy = load(Path(args.policy))
    record = load(Path(args.record))
    manifest = load(Path(args.artifact_manifest))
    if not isinstance(policy, dict) or not isinstance(record, dict) or not isinstance(manifest, dict):
        raise SigningError("policy, record, and artifact manifest must be objects")
    roles, required_by_channel, classes = policy_roles(policy)
    if record.get("schema") != SCHEMA:
        raise SigningError(f"record must use {SCHEMA}")
    revision = record.get("revision")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise SigningError("record has no full source revision")
    if args.expected_revision and revision != args.expected_revision.lower():
        raise SigningError("record revision does not match expected revision")
    binding = record.get("artifact_manifest")
    if (
        not isinstance(binding, dict)
        or binding.get("path") != Path(args.artifact_manifest).name
        or binding.get("sha256") != digest(Path(args.artifact_manifest))
    ):
        raise SigningError("signing record is not bound to the supplied artifact manifest")
    known_digests, digests_by_role, covered_classes = classified_artifacts(
        manifest,
        revision,
        classes,
        strict=args.channel != "validation",
    )
    if args.channel == "stable" and covered_classes != set(classes):
        missing_classes = sorted(set(classes) - covered_classes)
        raise SigningError(
            "stable artifact coverage is incomplete: " + ", ".join(missing_classes)
        )
    inspect_public(record)
    rows = record.get("roles")
    if not isinstance(rows, list) or [row.get("id") for row in rows if isinstance(row, dict)] != roles:
        raise SigningError("signing roles do not exactly match policy order")
    counts = {status: 0 for status in STATUS}
    verified_roles: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise SigningError("malformed signing role")
        role = row["id"]
        status = row.get("status")
        if status not in STATUS:
            raise SigningError(f"{role}: invalid status")
        counts[status] += 1
        if status == "verified":
            fingerprint = row.get("public_fingerprint")
            artifact_digests = row.get("artifact_sha256")
            evidence = row.get("evidence")
            if not isinstance(fingerprint, str) or not FINGERPRINT_RE.fullmatch(fingerprint):
                raise SigningError(f"{role}: invalid public fingerprint")
            expected_digests = (
                known_digests
                if role == "release-manifest"
                else digests_by_role.get(role, set())
            )
            if (
                not isinstance(artifact_digests, list)
                or not expected_digests
                or len(artifact_digests) != len(set(artifact_digests))
                or set(artifact_digests) != expected_digests
            ):
                raise SigningError(f"{role}: signed artifact digests are incomplete")
            if (
                not isinstance(evidence, list)
                or not evidence
                or not all(isinstance(value, str) and value for value in evidence)
                or not all(
                    isinstance(row.get(field), str) and row[field]
                    for field in ("verified_at", "verifier", "result")
                )
            ):
                raise SigningError(f"{role}: verification evidence is incomplete")
            verified_roles.add(role)
    expected_summary = {
        "verified": counts["verified"],
        "failed": counts["failed"],
        "blocked": counts["blocked"],
        "open": counts["open"],
    }
    if record.get("summary") != expected_summary:
        raise SigningError("summary does not match signing roles")
    required = required_by_channel.get(args.channel)
    if required is None:
        raise SigningError("unknown release channel")
    channels = policy.get("channels")
    channel_policy = channels.get(args.channel) if isinstance(channels, dict) else None
    if not isinstance(channel_policy, dict) or not isinstance(
        channel_policy.get("require_artifact_signing_roles"), bool
    ):
        raise SigningError("release channel has no artifact-signing policy")
    if channel_policy["require_artifact_signing_roles"]:
        required = required | set(digests_by_role)
    missing = sorted(required - verified_roles)
    if missing:
        raise SigningError(
            f"{args.channel} signing evidence is incomplete: " + ", ".join(missing)
        )
    print(
        f"{args.channel} signing evidence valid: "
        + ", ".join(f"{key}={value}" for key, value in expected_summary.items())
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser("prepare")
    create.add_argument("--policy", default="release/policy-v1.json")
    create.add_argument("--revision", required=True)
    create.add_argument("--artifact-manifest", required=True)
    create.add_argument("--output", required=True)
    create.set_defaults(run=prepare)
    check = commands.add_parser("validate")
    check.add_argument("--policy", default="release/policy-v1.json")
    check.add_argument("--record", required=True)
    check.add_argument("--artifact-manifest", required=True)
    check.add_argument("--expected-revision")
    check.add_argument("--channel", choices=("validation", "alpha", "stable"), required=True)
    check.set_defaults(run=validate)
    return root


def main() -> int:
    try:
        arguments = parser().parse_args()
        arguments.run(arguments)
        return 0
    except (OSError, SigningError) as error:
        print(f"release signing error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
