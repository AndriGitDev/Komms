#!/usr/bin/env python3
"""Create and verify bounded, revision-scoped Komms release evidence."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO


SCHEMA = "komms-release-evidence/v1"
BUILDER_SCHEMA = "komms-release-builder/v1"
SBOM_SCHEMA = "komms-release-sbom/v1"
COMPARISON_SCHEMA = "komms-reproducibility-comparison/v1"
ARTIFACT_SCHEMA = "komms-release-artifacts/v1"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_FILES = 512
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024
MAX_RELEASE_ASSET_FILES = MAX_ARTIFACT_FILES + 1
MAX_RELEASE_ASSET_BYTES = MAX_ARTIFACT_BYTES
MAX_ARCHIVE_MEMBERS = 1024
EVIDENCE_RECORD_NAMES = {
    "source.json",
    "builders.json",
    "artifacts.json",
    "komms.cdx.json",
    "android-licenses.json",
    "dependency-policy.json",
    "provenance.json",
    "reproducibility.json",
    "qualification.json",
    "signing.json",
    "residual-risks.json",
    "stable-beta.json",
    "release-notes.md",
}
EVIDENCE_CONTROL_NAMES = {
    "release-evidence.json",
    "SHA256SUMS",
    "SHA256SUMS.sig",
}
REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
BUILDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
SAFE_RELEASE_ASSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,191}$")
FORBIDDEN_FIELD_PARTS = (
    "password",
    "private_key",
    "private-key",
    "credential",
    "access_token",
    "refresh_token",
    "bearer",
)


class EvidenceError(ValueError):
    """A bounded input or evidence invariant failed."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(canonical_bytes(value))
    os.replace(temporary, path)


def load_json(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise EvidenceError(f"{path}: expected a regular JSON file")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise EvidenceError(f"{path}: JSON exceeds {MAX_JSON_BYTES} bytes")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{path}: invalid JSON: {error}") from error


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def validate_revision(revision: str) -> str:
    exact = revision.strip().lower()
    if not REVISION_RE.fullmatch(exact):
        raise EvidenceError("revision must be a complete 40- or 64-character lowercase digest")
    return exact


def validate_version(version: str) -> str:
    exact = version.strip()
    if not VERSION_RE.fullmatch(exact):
        raise EvidenceError("version must be a bounded semantic version")
    return exact


def validate_tag(tag: str, version: str) -> str:
    exact = tag.strip()
    if not TAG_RE.fullmatch(exact) or exact != f"v{version.split('+', 1)[0].split('-', 1)[0]}":
        raise EvidenceError("tag must be vMAJOR.MINOR.PATCH and match the application version")
    return exact


def validate_public_record(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise EvidenceError(f"{path}: object key is not text")
            lowered = key.lower()
            if any(part in lowered for part in FORBIDDEN_FIELD_PARTS):
                raise EvidenceError(f"{path}.{key}: secret-bearing fields are forbidden")
            validate_public_record(nested, f"{path}.{key}")
    elif isinstance(value, list):
        if len(value) > 4096:
            raise EvidenceError(f"{path}: list is too large")
        for index, nested in enumerate(value):
            validate_public_record(nested, f"{path}[{index}]")
    elif isinstance(value, str):
        if len(value.encode("utf-8")) > 64 * 1024:
            raise EvidenceError(f"{path}: text is too large")
        lowered = value.lower()
        if "-----begin " in lowered and "private key-----" in lowered:
            raise EvidenceError(f"{path}: private key material is forbidden")
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise EvidenceError(f"{path}: unsupported JSON value")


def safe_relative(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise EvidenceError(f"{path}: path escapes {root}") from error
    pure = PurePosixPath(relative.as_posix())
    if pure.is_absolute() or not pure.parts or any(part in ("", ".", "..") for part in pure.parts):
        raise EvidenceError(f"{path}: unsafe relative path")
    return pure.as_posix()


def iter_artifact_files(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        raise EvidenceError("artifact directory must be a real directory")
    files: list[Path] = []
    total = 0
    for candidate in sorted(root.rglob("*")):
        if candidate.is_symlink():
            raise EvidenceError(f"{candidate}: symlinks are forbidden")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise EvidenceError(f"{candidate}: unsupported filesystem entry")
        files.append(candidate)
        total += candidate.stat().st_size
        if len(files) > MAX_ARTIFACT_FILES:
            raise EvidenceError(f"artifact set exceeds {MAX_ARTIFACT_FILES} files")
        if total > MAX_ARTIFACT_BYTES:
            raise EvidenceError(f"artifact set exceeds {MAX_ARTIFACT_BYTES} bytes")
    if not files:
        raise EvidenceError("artifact directory is empty")
    return files


def update_framed_member(
    digests: tuple[Any, ...],
    prefix: bytes,
    source: BinaryIO,
    payload_size: int,
    archive_path: Path,
) -> None:
    if payload_size < 0:
        raise EvidenceError(f"{archive_path}: archive member has a negative size")
    frame_size = len(prefix) + payload_size
    for digest in digests:
        digest.update(frame_size.to_bytes(8, "big"))
        digest.update(prefix)
    remaining = payload_size
    while remaining:
        block = source.read(min(1024 * 1024, remaining))
        if not block:
            raise EvidenceError(f"{archive_path}: truncated archive member")
        remaining -= len(block)
        for digest in digests:
            digest.update(block)
    if source.read(1):
        raise EvidenceError(f"{archive_path}: archive member exceeds its declared size")


def normalized_zip_digest(path: Path) -> dict[str, str] | None:
    if path.suffix.lower() not in (".apk", ".aab", ".zip", ".ipa"):
        return None
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise EvidenceError(f"{path}: archive has too many members")
            expanded = sum(info.file_size for info in members if not info.is_dir())
            if expanded > MAX_ARTIFACT_BYTES:
                raise EvidenceError(f"{path}: expanded archive exceeds the byte bound")
            complete = hashlib.sha256()
            unsigned = hashlib.sha256()
            names: set[str] = set()
            for info in sorted(members, key=lambda row: row.filename):
                if info.is_dir():
                    continue
                name = PurePosixPath(info.filename).as_posix()
                pure = PurePosixPath(name)
                member_type = (info.external_attr >> 16) & 0o170000
                if (
                    pure.is_absolute()
                    or not pure.parts
                    or any(part in ("", ".", "..") for part in pure.parts)
                    or name in names
                    or member_type == stat.S_IFLNK
                    or info.flag_bits & 0x1
                ):
                    raise EvidenceError(f"{path}: unsafe archive member")
                names.add(name)
                prefix = name.encode() + b"\0"
                upper = name.upper()
                signature = upper.startswith("META-INF/") and upper.endswith(
                    (".RSA", ".DSA", ".EC", ".SF", ".MF")
                )
                digests = (complete,) if signature else (complete, unsigned)
                with archive.open(info, "r") as source:
                    update_framed_member(digests, prefix, source, info.file_size, path)
            return {
                "scheme": "zip-entry-content-v1",
                "sha256": complete.hexdigest(),
                "unsigned_payload_sha256": unsigned.hexdigest(),
            }
    except (RuntimeError, zipfile.BadZipFile) as error:
        raise EvidenceError(f"{path}: malformed ZIP-based artifact") from error


def normalized_tar_digest(path: Path) -> dict[str, str] | None:
    lowered = path.name.lower()
    if not lowered.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz")):
        return None
    try:
        with tarfile.open(path, "r:*") as archive:
            members = archive.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise EvidenceError(f"{path}: archive has too many members")
            expanded = sum(member.size for member in members if member.isfile())
            if expanded > MAX_ARTIFACT_BYTES:
                raise EvidenceError(f"{path}: expanded archive exceeds the byte bound")
            digest = hashlib.sha256()
            names: set[str] = set()
            for member in sorted(members, key=lambda row: row.name):
                name = PurePosixPath(member.name).as_posix()
                pure = PurePosixPath(name)
                if (
                    pure.is_absolute()
                    or not pure.parts
                    or any(part in ("", ".", "..") for part in pure.parts)
                    or name in names
                ):
                    raise EvidenceError(f"{path}: unsafe archive member")
                names.add(name)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise EvidenceError(f"{path}: non-regular archive member")
                source = archive.extractfile(member)
                if source is None:
                    raise EvidenceError(f"{path}: unreadable archive member")
                prefix = (
                    name.encode()
                    + b"\0"
                    + f"{member.mode & 0o777:o}".encode()
                    + b"\0"
                )
                with source:
                    update_framed_member((digest,), prefix, source, member.size, path)
            return {
                "scheme": "tar-entry-content-mode-v1",
                "sha256": digest.hexdigest(),
            }
    except tarfile.TarError as error:
        raise EvidenceError(f"{path}: malformed tar artifact") from error


def artifact_row(path: Path, relative: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "path": relative,
        "bytes": path.stat().st_size,
        "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}",
        "sha256": sha256_file(path),
    }
    normalized = normalized_zip_digest(path) or normalized_tar_digest(path)
    if normalized is not None:
        row["normalized"] = normalized
    return row


def copy_regular(source: Path, destination: Path) -> None:
    if not source.is_file() or source.is_symlink():
        raise EvidenceError(f"{source}: expected a regular file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    shutil.copy2(source, temporary)
    os.replace(temporary, destination)


def artifact_inventory(root: Path, revision: str) -> dict[str, Any]:
    artifacts = [
        artifact_row(source, f"artifacts/{safe_relative(source, root)}")
        for source in iter_artifact_files(root)
    ]
    return {
        "schema": ARTIFACT_SCHEMA,
        "revision": revision,
        "artifacts": artifacts,
    }


def validated_artifact_rows(
    manifest: Any, expected_revision: str | None = None
) -> tuple[str, dict[str, dict[str, Any]]]:
    if not isinstance(manifest, dict) or manifest.get("schema") != ARTIFACT_SCHEMA:
        raise EvidenceError(f"artifact inventory must use {ARTIFACT_SCHEMA}")
    revision = validate_revision(str(manifest.get("revision", "")))
    if expected_revision is not None and revision != validate_revision(expected_revision):
        raise EvidenceError("artifact inventory revision does not match the expected revision")
    validate_public_record(manifest)
    rows = manifest.get("artifacts")
    if not isinstance(rows, list) or not rows:
        raise EvidenceError("artifact inventory must contain at least one artifact")
    if len(rows) > MAX_ARTIFACT_FILES:
        raise EvidenceError(f"artifact inventory exceeds {MAX_ARTIFACT_FILES} files")
    result: dict[str, dict[str, Any]] = {}
    total = 0
    for row in rows:
        if not isinstance(row, dict):
            raise EvidenceError("malformed artifact inventory row")
        relative = row.get("path")
        if not isinstance(relative, str):
            raise EvidenceError("artifact inventory path is not text")
        pure = PurePosixPath(relative)
        if (
            pure.is_absolute()
            or pure.as_posix() != relative
            or len(pure.parts) < 2
            or pure.parts[0] != "artifacts"
            or any(part in ("", ".", "..") for part in pure.parts)
        ):
            raise EvidenceError(f"{relative}: unsafe artifact inventory path")
        size = row.get("bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise EvidenceError(f"{relative}: invalid artifact size")
        mode = row.get("mode")
        if not isinstance(mode, str) or not re.fullmatch(r"[0-7]{4}", mode):
            raise EvidenceError(f"{relative}: invalid artifact mode")
        digest = row.get("sha256")
        if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
            raise EvidenceError(f"{relative}: invalid artifact digest")
        if relative in result:
            raise EvidenceError(f"{relative}: duplicate artifact inventory path")
        result[relative] = row
        total += size
        if total > MAX_ARTIFACT_BYTES:
            raise EvidenceError(f"artifact inventory exceeds {MAX_ARTIFACT_BYTES} bytes")
    return revision, result


def make_inventory(args: argparse.Namespace) -> None:
    revision = validate_revision(args.revision)
    artifact_root = Path(args.artifact_dir).resolve()
    document = artifact_inventory(artifact_root, revision)
    validate_public_record(document)
    write_json(Path(args.output), document)


def command_metadata(manifest: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--format-version=1",
            "--manifest-path",
            str(manifest),
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
    )
    if completed.returncode != 0:
        reason = completed.stderr.strip().splitlines()[-1:] or ["unknown failure"]
        raise EvidenceError(f"cargo metadata failed for {manifest}: {reason[0]}")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise EvidenceError(f"cargo metadata returned invalid JSON for {manifest}") from error


def cargo_purl(name: str, version: str) -> str:
    return f"pkg:cargo/{urllib.parse.quote(name, safe='')}@{urllib.parse.quote(version, safe='.')}"


def maven_purl(group: str, name: str, version: str) -> str:
    namespace = urllib.parse.quote(group, safe=".")
    artifact = urllib.parse.quote(name, safe="")
    exact_version = urllib.parse.quote(version, safe=".-_")
    return f"pkg:maven/{namespace}/{artifact}@{exact_version}"


def cargo_components(
    metadata: dict[str, Any], workspace: str
) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]], set[str]]:
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    members = set(metadata.get("workspace_members", []))
    if not isinstance(packages, list) or not isinstance(resolve, dict):
        raise EvidenceError(f"{workspace}: incomplete cargo metadata")
    components: dict[str, dict[str, Any]] = {}
    package_refs: dict[str, str] = {}
    workspace_refs: set[str] = set()
    for package in packages:
        if not isinstance(package, dict):
            raise EvidenceError(f"{workspace}: malformed cargo package")
        package_id = package.get("id")
        name = package.get("name")
        version = package.get("version")
        if not all(isinstance(item, str) for item in (package_id, name, version)):
            raise EvidenceError(f"{workspace}: malformed cargo package identity")
        reference = cargo_purl(name, version)
        package_refs[package_id] = reference
        component: dict[str, Any] = {
            "type": "application" if package_id in members else "library",
            "bom-ref": reference,
            "name": name,
            "version": version,
            "purl": reference,
            "properties": [
                {"name": "komms:ecosystem", "value": "cargo"},
                {"name": "komms:workspace", "value": workspace},
            ],
        }
        license_expression = package.get("license")
        if isinstance(license_expression, str) and license_expression:
            component["licenses"] = [{"expression": license_expression}]
        source = package.get("source")
        if isinstance(source, str) and source:
            component["properties"].append({"name": "komms:source", "value": source})
        components.setdefault(reference, component)
        if package_id in members:
            workspace_refs.add(reference)
    dependencies: dict[str, set[str]] = {reference: set() for reference in components}
    for node in resolve.get("nodes", []):
        if not isinstance(node, dict):
            continue
        parent = package_refs.get(node.get("id"))
        if parent is None:
            continue
        for dependency in node.get("deps", []):
            if not isinstance(dependency, dict):
                continue
            child = package_refs.get(dependency.get("pkg"))
            if child is not None and child != parent:
                dependencies.setdefault(parent, set()).add(child)
    return components, dependencies, workspace_refs


def gradle_components(
    lockfiles: list[Path], repository: Path
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    components: dict[str, dict[str, Any]] = {}
    references: set[str] = set()
    for lockfile in lockfiles:
        for raw in lockfile.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            coordinate = line.split("=", 1)[0]
            parts = coordinate.split(":")
            if len(parts) != 3 or not all(parts):
                raise EvidenceError(f"{lockfile}: malformed locked coordinate")
            group, name, version = parts
            reference = maven_purl(group, name, version)
            references.add(reference)
            components.setdefault(
                reference,
                {
                    "type": "library",
                    "bom-ref": reference,
                    "group": group,
                    "name": name,
                    "version": version,
                    "purl": reference,
                    "properties": [
                        {"name": "komms:ecosystem", "value": "gradle"},
                        {
                            "name": "komms:lockfile",
                            "value": safe_relative(lockfile, repository),
                        },
                    ],
                },
            )
    return components, references


def gradle_lockfiles(repository: Path) -> list[Path]:
    return sorted((repository / "apps/android").glob("**/*gradle.lockfile"))


def load_release_toolchain(repository: Path) -> tuple[Path, dict[str, Any]]:
    path = repository / "release/toolchain-v1.json"
    policy = load_json(path)
    if (
        not isinstance(policy, dict)
        or policy.get("schema") != "komms-release-toolchain/v1"
    ):
        raise EvidenceError("release toolchain policy is missing or malformed")
    validate_public_record(policy)
    return path, policy


def make_builder_record(args: argparse.Namespace) -> None:
    revision = validate_revision(args.revision)
    builder_id = args.builder_id.strip()
    if not BUILDER_ID_RE.fullmatch(builder_id):
        raise EvidenceError("builder id must be a bounded public identifier")
    required = {
        "os": args.os,
        "architecture": args.architecture,
        "environment": args.environment,
        "runner_image": args.runner_image,
    }
    for name, value in required.items():
        if not value or len(value.encode("utf-8")) > 512:
            raise EvidenceError(f"{name} must be non-empty and at most 512 bytes")
    tools: dict[str, str] = {}
    for specification in args.tool:
        name, separator, version = specification.partition("=")
        name = name.strip()
        version = version.strip()
        if (
            separator != "="
            or not TOOL_NAME_RE.fullmatch(name)
            or not version
            or len(version.encode("utf-8")) > 512
            or name in tools
        ):
            raise EvidenceError("each tool must be a unique bounded NAME=VERSION pair")
        tools[name] = version
    if not tools:
        raise EvidenceError("at least one build tool version is required")
    record = {
        "schema": BUILDER_SCHEMA,
        "builder_id": builder_id,
        "revision": revision,
        "os": args.os,
        "architecture": args.architecture,
        "environment": args.environment,
        "runner_image": args.runner_image,
        "isolated": args.isolated,
        "tools": [{"name": name, "version": tools[name]} for name in sorted(tools)],
        "claim": (
            "Build-environment identity only; this record does not establish "
            "administrative independence."
        ),
    }
    validate_public_record(record)
    write_json(Path(args.output), record)


def make_sbom(args: argparse.Namespace) -> None:
    revision = validate_revision(args.revision)
    version = validate_version(args.version)
    repository = Path(args.repository).resolve()
    validate_android_license_record(
        repository, revision, Path(args.android_license_report)
    )
    manifests = [
        (repository / "Cargo.toml", "core"),
        (repository / "apps/desktop/src-tauri/Cargo.toml", "desktop"),
    ]
    components: dict[str, dict[str, Any]] = {}
    dependencies: dict[str, set[str]] = {}
    root_dependencies: set[str] = set()
    for manifest, workspace in manifests:
        metadata = command_metadata(manifest)
        found, relationships, workspace_refs = cargo_components(metadata, workspace)
        components.update(found)
        for parent, children in relationships.items():
            dependencies.setdefault(parent, set()).update(children)
        root_dependencies.update(workspace_refs)
    lockfiles = gradle_lockfiles(repository)
    gradle, gradle_refs = gradle_components(lockfiles, repository)
    android_licenses = load_json(Path(args.android_license_report))
    if (
        not isinstance(android_licenses, dict)
        or android_licenses.get("schema") != "komms-android-license-evidence/v1"
        or android_licenses.get("revision") != revision
    ):
        raise EvidenceError("Android license evidence schema or revision mismatch")
    for row in android_licenses.get("components", []):
        if not isinstance(row, dict) or row.get("status") != "declared":
            continue
        coordinate = row.get("coordinate")
        expression = row.get("spdx")
        if not isinstance(coordinate, str) or not isinstance(expression, str):
            raise EvidenceError("Android license evidence has a malformed declared row")
        parts = coordinate.split(":")
        if len(parts) != 3:
            raise EvidenceError("Android license evidence has a malformed coordinate")
        reference = maven_purl(*parts)
        if reference in gradle:
            gradle[reference]["licenses"] = [{"expression": expression}]
    components.update(gradle)
    root_dependencies.update(gradle_refs)
    root_ref = f"pkg:github/AndriGitDev/Komms@{revision}"
    lock_paths = [
        repository / "Cargo.lock",
        repository / "apps/desktop/src-tauri/Cargo.lock",
        *lockfiles,
    ]
    properties = [
        {"name": "komms:schema", "value": SBOM_SCHEMA},
        {"name": "komms:revision", "value": revision},
    ]
    for lockfile in lock_paths:
        relative = safe_relative(lockfile, repository)
        properties.append(
            {
                "name": f"komms:lock-sha256:{relative}",
                "value": sha256_file(lockfile),
            }
        )
    verification_metadata = repository / "apps/android/gradle/verification-metadata.xml"
    if not verification_metadata.is_file():
        raise EvidenceError("Android dependency verification metadata is missing")
    toolchain_path, _toolchain = load_release_toolchain(repository)
    properties.append(
        {
            "name": "komms:android-verification-metadata-sha256",
            "value": sha256_file(verification_metadata),
        }
    )
    properties.append(
        {
            "name": "komms:android-license-evidence-sha256",
            "value": sha256_file(Path(args.android_license_report)),
        }
    )
    properties.append(
        {
            "name": "komms:release-toolchain-sha256",
            "value": sha256_file(toolchain_path),
        }
    )
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:"
        + str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/AndriGitDev/Komms@{revision}")),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "Komms",
                "version": version,
                "purl": root_ref,
                "licenses": [{"expression": "AGPL-3.0-only"}],
                "externalReferences": [
                    {
                        "type": "vcs",
                        "url": f"https://github.com/AndriGitDev/Komms/tree/{revision}",
                    }
                ],
                "properties": properties,
            }
        },
        "components": [components[key] for key in sorted(components)],
        "dependencies": [
            {"ref": root_ref, "dependsOn": sorted(root_dependencies)},
            *[
                {"ref": key, "dependsOn": sorted(dependencies.get(key, set()))}
                for key in sorted(components)
            ],
        ],
    }
    validate_public_record(document)
    write_json(Path(args.output), document)


def make_dependency_record(args: argparse.Namespace) -> None:
    revision = validate_revision(args.revision)
    repository = Path(args.repository).resolve()
    validate_android_license_record(
        repository, revision, Path(args.android_license_report)
    )
    toolchain_path, toolchain = load_release_toolchain(repository)
    locks = [
        repository / "Cargo.lock",
        repository / "apps/desktop/src-tauri/Cargo.lock",
        *gradle_lockfiles(repository),
    ]
    verification_metadata = repository / "apps/android/gradle/verification-metadata.xml"
    if not verification_metadata.is_file():
        raise EvidenceError("Android dependency verification metadata is missing")
    android_licenses = load_json(Path(args.android_license_report))
    if (
        not isinstance(android_licenses, dict)
        or android_licenses.get("schema") != "komms-android-license-evidence/v1"
        or android_licenses.get("revision") != revision
    ):
        raise EvidenceError("Android license evidence schema or revision mismatch")
    license_summary = android_licenses.get("summary")
    if not isinstance(license_summary, dict) or license_summary.get("unknown") != 0:
        raise EvidenceError("Android license evidence has unresolved components")
    record = {
        "schema": "komms-dependency-policy/v1",
        "revision": revision,
        "results": {
            "root_cargo_deny": args.root_cargo_deny,
            "desktop_cargo_deny": args.desktop_cargo_deny,
            "android_dependency_locking": args.android_dependency_locking,
            "android_dependency_verification": args.android_dependency_verification,
            "android_declared_licenses": "passed",
            "swift_external_packages": "none",
        },
        "lockfiles": [
            {
                "path": safe_relative(path, repository),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in locks
        ],
        "integrity_files": [
            {
                "path": safe_relative(verification_metadata, repository),
                "bytes": verification_metadata.stat().st_size,
                "sha256": sha256_file(verification_metadata),
            }
        ],
        "android_license_evidence": {
            "path": "android-licenses.json",
            "bytes": Path(args.android_license_report).stat().st_size,
            "sha256": sha256_file(Path(args.android_license_report)),
            "summary": license_summary,
        },
        "release_toolchain": {
            "path": safe_relative(toolchain_path, repository),
            "bytes": toolchain_path.stat().st_size,
            "sha256": sha256_file(toolchain_path),
            "policy": toolchain,
        },
    }
    validate_public_record(record)
    write_json(Path(args.output), record)


def prepare_output(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise EvidenceError("output must be a real directory")
        if any(path.iterdir()):
            raise EvidenceError("output directory must be empty")
    else:
        path.mkdir(parents=True)


def validate_android_license_record(
    repository: Path, revision: str, record: Path
) -> None:
    run_evidence_check(
        [
            str(Path(__file__).with_name("android-license-evidence.py")),
            "validate",
            "--repository",
            str(repository),
            "--policy",
            str(repository / "release/android-license-policy-v1.json"),
            "--record",
            str(record),
            "--expected-revision",
            revision,
            "--require-complete",
        ]
    )


def load_build_records(directory: Path, revision: str) -> list[dict[str, Any]]:
    if not directory.is_dir() or directory.is_symlink():
        raise EvidenceError("build-record directory must be a real directory")
    paths = sorted(directory.rglob("*.json"))
    if not paths or len(paths) > 32:
        raise EvidenceError("build-record directory must contain 1 to 32 JSON records")
    records: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for path in paths:
        record = load_json(path)
        if not isinstance(record, dict) or record.get("schema") != BUILDER_SCHEMA:
            raise EvidenceError(f"{path}: invalid build record schema")
        if record.get("revision") != revision:
            raise EvidenceError(f"{path}: build record revision mismatch")
        identifier = record.get("builder_id")
        if not isinstance(identifier, str) or identifier in identifiers:
            raise EvidenceError(f"{path}: missing or duplicate builder id")
        identifiers.add(identifier)
        validate_public_record(record)
        records.append(record)
    return records


def make_bundle(args: argparse.Namespace) -> None:
    revision = validate_revision(args.revision)
    version = validate_version(args.version)
    tag = validate_tag(args.tag, version)
    artifact_root = Path(args.artifact_dir).resolve()
    output = Path(args.output_dir).resolve()
    if artifact_root == output or artifact_root in output.parents or output in artifact_root.parents:
        raise EvidenceError("artifact and evidence directories must not contain one another")
    builder = load_json(Path(args.builder))
    if not isinstance(builder, dict) or builder.get("schema") != BUILDER_SCHEMA:
        raise EvidenceError(f"builder record must use {BUILDER_SCHEMA}")
    if builder.get("revision") != revision:
        raise EvidenceError("builder record revision does not match the bundle")
    required_builder_fields = {
        "builder_id": str,
        "os": str,
        "architecture": str,
        "environment": str,
        "runner_image": str,
        "isolated": bool,
        "tools": list,
    }
    if any(not isinstance(builder.get(name), kind) for name, kind in required_builder_fields.items()):
        raise EvidenceError("builder record is incomplete")
    validate_public_record(builder)
    build_records = (
        load_build_records(Path(args.build_record_dir), revision)
        if args.build_record_dir is not None
        else [builder]
    )
    prepare_output(output)

    artifacts: list[dict[str, Any]] = []
    for source in iter_artifact_files(artifact_root):
        relative = safe_relative(source, artifact_root)
        destination = output / "artifacts" / relative
        copy_regular(source, destination)
        artifacts.append(artifact_row(destination, f"artifacts/{relative}"))

    source_record = {
        "schema": "komms-release-source/v1",
        "repository": "https://github.com/AndriGitDev/Komms",
        "revision": revision,
        "tag": tag,
        "version": version,
        "source_date_epoch": args.source_date_epoch,
        "builder": builder,
        "build_environments": build_records,
    }
    if not isinstance(args.source_date_epoch, int) or args.source_date_epoch <= 0:
        raise EvidenceError("source date epoch must be a positive integer")
    write_json(output / "source.json", source_record)
    write_json(
        output / "builders.json",
        {
            "schema": "komms-release-builders/v1",
            "revision": revision,
            "builders": build_records,
            "claim": (
                "Environment records identify build paths; they do not establish "
                "external independence."
            ),
        },
    )
    write_json(
        output / "artifacts.json",
        {
            "schema": "komms-release-artifacts/v1",
            "revision": revision,
            "artifacts": artifacts,
        },
    )

    optional_records = {
        "komms.cdx.json": args.sbom,
        "android-licenses.json": args.android_licenses,
        "dependency-policy.json": args.dependency_policy,
        "qualification.json": args.qualification,
        "reproducibility.json": args.reproducibility,
        "signing.json": args.signing,
        "residual-risks.json": args.residual_risks,
        "stable-beta.json": args.stable_beta,
        "release-notes.md": args.release_notes,
    }
    for name, supplied in optional_records.items():
        if supplied is not None:
            copy_regular(Path(supplied), output / name)

    provenance = {
        "schema": "komms-release-provenance/v1",
        "revision": revision,
        "tag": tag,
        "builder_id": builder.get("builder_id"),
        "statement": "This local record binds files and build facts but is not a hosted signed attestation.",
    }
    write_json(output / "provenance.json", provenance)

    records: list[dict[str, Any]] = []
    for path in sorted(output.iterdir()):
        if path.is_file():
            records.append(
                {
                    "path": path.name,
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    manifest = {
        "schema": SCHEMA,
        "revision": revision,
        "tag": tag,
        "version": version,
        "channel": args.channel,
        "artifact_count": len(artifacts),
        "artifact_bytes": sum(row["bytes"] for row in artifacts),
        "builder": builder,
        "build_environments": build_records,
        "artifacts": artifacts,
        "records": records,
        "claims": {
            "production_signed": False,
            "independently_reproduced": False,
            "qualified_for_stable": False,
        },
    }
    write_json(output / "release-evidence.json", manifest)

    checksum_rows: list[tuple[str, str]] = []
    for path in sorted(output.rglob("*")):
        if path.is_file():
            relative = safe_relative(path, output)
            if relative != "SHA256SUMS":
                checksum_rows.append((sha256_file(path), relative))
    checksums = "".join(f"{digest}  {name}\n" for digest, name in checksum_rows)
    (output / "SHA256SUMS").write_text(checksums, encoding="utf-8")

def parse_checksums(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw:
            continue
        if len(raw) < 67 or raw[64:66] != "  ":
            raise EvidenceError(f"{path}: malformed checksum row")
        digest = raw[:64]
        name = raw[66:]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise EvidenceError(f"{path}: malformed digest")
        pure = PurePosixPath(name)
        if pure.is_absolute() or not pure.parts or ".." in pure.parts or name in rows:
            raise EvidenceError(f"{path}: unsafe or duplicate checksum path")
        rows[name] = digest
    return rows


def validate_reproducibility_record(
    record: Any,
    revision: str,
    artifact_rows: dict[str, dict[str, Any]],
    require_independent: bool,
) -> bool:
    if not isinstance(record, dict) or record.get("schema") != COMPARISON_SCHEMA:
        raise EvidenceError(f"reproducibility record must use {COMPARISON_SCHEMA}")
    if record.get("revision") != revision:
        raise EvidenceError("reproducibility record revision mismatch")
    validate_public_record(record)
    rows = record.get("artifacts")
    if not isinstance(rows, list) or not rows:
        raise EvidenceError("reproducibility record has no artifact rows")
    counts = {
        "exact": 0,
        "normalized": 0,
        "explained": 0,
        "unexplained_or_missing": 0,
    }
    paths: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise EvidenceError("reproducibility record has a malformed artifact row")
        path = row.get("path")
        status = row.get("status")
        if not isinstance(path, str) or path in paths:
            raise EvidenceError("reproducibility record has an invalid or duplicate path")
        paths.add(path)
        expected = artifact_rows.get(path)
        if expected is None:
            raise EvidenceError(
                f"{path}: reproducibility row is not a release artifact"
            )
        if status == "exact":
            counts["exact"] += 1
            if row.get("sha256") != expected["sha256"]:
                raise EvidenceError(f"{path}: exact reproduction digest is not the release artifact")
        elif status == "normalized":
            counts["normalized"] += 1
            file_digests = {
                value
                for value in (
                    row.get("first_file_sha256"),
                    row.get("second_file_sha256"),
                )
                if isinstance(value, str) and DIGEST_RE.fullmatch(value)
            }
            if (
                expected["sha256"] not in file_digests
                or not isinstance(row.get("scheme"), str)
                or not row["scheme"]
                or row.get("field") not in {"sha256", "unsigned_payload_sha256"}
                or not isinstance(row.get("sha256"), str)
                or not DIGEST_RE.fullmatch(row["sha256"])
            ):
                raise EvidenceError(
                    f"{path}: normalized reproduction evidence is incomplete"
                )
        elif status == "explained":
            counts["explained"] += 1
            explanation = row.get("explanation")
            evidence = row.get("evidence")
            file_digests = {
                value
                for value in (
                    row.get("first_file_sha256"),
                    row.get("second_file_sha256"),
                )
                if isinstance(value, str) and DIGEST_RE.fullmatch(value)
            }
            if (
                not isinstance(explanation, str)
                or not explanation.strip()
                or not isinstance(evidence, list)
                or not evidence
                or not all(isinstance(value, str) and value.strip() for value in evidence)
                or expected["sha256"] not in file_digests
            ):
                raise EvidenceError(f"{path}: explained difference has incomplete evidence")
        elif status == "different":
            file_digests = {
                value
                for value in (
                    row.get("first_file_sha256"),
                    row.get("second_file_sha256"),
                )
                if isinstance(value, str) and DIGEST_RE.fullmatch(value)
            }
            if len(file_digests) != 2 or expected["sha256"] not in file_digests:
                raise EvidenceError(
                    f"{path}: different reproduction evidence is incomplete"
                )
            counts["unexplained_or_missing"] += 1
        elif status == "missing":
            if (
                not isinstance(row.get("first"), bool)
                or not isinstance(row.get("second"), bool)
                or row["first"] == row["second"]
                or row.get("present_file_sha256") != expected["sha256"]
            ):
                raise EvidenceError(
                    f"{path}: missing reproduction evidence is incomplete"
                )
            counts["unexplained_or_missing"] += 1
        else:
            raise EvidenceError(f"{path}: unknown reproduction status")
    summary = record.get("summary")
    expected_summary = {
        "compared": len(rows),
        **counts,
    }
    if summary != expected_summary:
        raise EvidenceError("reproducibility summary does not match artifact rows")

    independent = record.get("independently_verified") is True
    if independent:
        evidence = record.get("independent_evidence")
        report_uri = evidence.get("report_uri") if isinstance(evidence, dict) else None
        parsed_uri = urllib.parse.urlparse(report_uri) if isinstance(report_uri, str) else None
        if (
            not isinstance(evidence, dict)
            or evidence.get("separately_administered") is not True
            or not all(
                isinstance(evidence.get(field), str) and evidence[field].strip()
                for field in ("administrator", "environment", "executed_at")
            )
            or not isinstance(evidence.get("report_sha256"), str)
            or not DIGEST_RE.fullmatch(evidence["report_sha256"])
            or parsed_uri is None
            or parsed_uri.scheme != "https"
            or not parsed_uri.netloc
        ):
            raise EvidenceError("independent reproduction evidence is incomplete")
        first = record.get("first_builder")
        second = record.get("second_builder")
        first_id = first.get("builder_id") if isinstance(first, dict) else None
        second_id = second.get("builder_id") if isinstance(second, dict) else None
        if (
            not isinstance(first_id, str)
            or not isinstance(second_id, str)
            or first_id == second_id
        ):
            raise EvidenceError("independent reproduction requires distinct builders")
    if independent:
        if set(artifact_rows) != paths:
            raise EvidenceError(
                "independent reproduction must cover every release artifact exactly once"
            )
        if counts["unexplained_or_missing"] != 0:
            raise EvidenceError(
                "independent reproduction has unexplained or missing artifacts"
            )
    if require_independent and not independent:
        raise EvidenceError("stable evidence requires independent reproduction")
    return independent


def validate_residual_risk_record(
    record: Any, revision: str, require_authorized: bool
) -> None:
    if (
        not isinstance(record, dict)
        or record.get("schema") != "komms-release-residual-risks/v1"
        or record.get("profile") != "stable-v1"
    ):
        raise EvidenceError("residual-risk record has the wrong schema or profile")
    validate_public_record(record)
    risks = record.get("risks")
    if not isinstance(risks, list) or not risks:
        raise EvidenceError("residual-risk record has no risks")
    identifiers: set[str] = set()
    for risk in risks:
        if not isinstance(risk, dict):
            raise EvidenceError("residual-risk record has a malformed risk")
        identifier = risk.get("id")
        status = risk.get("status")
        statement = risk.get("statement")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in identifiers
            or status not in {"open", "closed", "accepted"}
            or not isinstance(statement, str)
            or not statement.strip()
        ):
            raise EvidenceError("residual-risk record has an invalid risk")
        identifiers.add(identifier)
    if require_authorized:
        evidence = record.get("authorization_evidence")
        if (
            record.get("revision") != revision
            or record.get("decision") != "authorized"
            or not isinstance(record.get("authorized_by"), str)
            or not record["authorized_by"].strip()
            or not isinstance(record.get("authorized_at"), str)
            or not record["authorized_at"].strip()
            or not isinstance(evidence, list)
            or not evidence
            or not all(isinstance(value, str) and value.strip() for value in evidence)
            or any(risk.get("status") == "open" for risk in risks)
        ):
            raise EvidenceError(
                "stable residual-risk decision lacks revision-bound authorization"
            )


def validate_reproducibility_command(args: argparse.Namespace) -> None:
    revision, artifacts = validated_artifact_rows(
        load_json(Path(args.artifact_manifest)),
        args.expected_revision,
    )
    independent = validate_reproducibility_record(
        load_json(Path(args.record)),
        revision,
        artifacts,
        require_independent=args.require_independent,
    )
    print(
        "reproducibility record valid: "
        + ("independently verified" if independent else "controlled measurement")
    )


def validate_residual_risks_command(args: argparse.Namespace) -> None:
    revision = validate_revision(args.expected_revision)
    validate_residual_risk_record(
        load_json(Path(args.record)),
        revision,
        require_authorized=args.require_authorized,
    )
    print(
        "residual-risk record valid: "
        + ("authorized" if args.require_authorized else "disposition recorded")
    )


def validate_dependency_policy_record(
    record: Any,
    bundle: Path,
    repository: Path,
    revision: str,
    publishable: bool,
) -> None:
    if (
        not isinstance(record, dict)
        or record.get("schema") != "komms-dependency-policy/v1"
        or record.get("revision") != revision
    ):
        raise EvidenceError("dependency policy record has the wrong schema or revision")
    validate_public_record(record)
    results = record.get("results")
    expected_result_keys = {
        "root_cargo_deny",
        "desktop_cargo_deny",
        "android_dependency_locking",
        "android_dependency_verification",
        "android_declared_licenses",
        "swift_external_packages",
    }
    if not isinstance(results, dict) or set(results) != expected_result_keys:
        raise EvidenceError("dependency policy result inventory is malformed")
    if results.get("android_declared_licenses") != "passed":
        raise EvidenceError("Android declared-license policy did not pass")
    if results.get("swift_external_packages") != "none":
        raise EvidenceError("unexpected external Swift packages are recorded")
    status_fields = expected_result_keys - {
        "android_declared_licenses",
        "swift_external_packages",
    }
    if any(results.get(name) not in {"passed", "failed", "not-run"} for name in status_fields):
        raise EvidenceError("dependency policy has an invalid result status")
    if publishable and any(results.get(name) != "passed" for name in status_fields):
        raise EvidenceError("publishable dependency policy has an incomplete gate")

    lock_paths = [
        repository / "Cargo.lock",
        repository / "apps/desktop/src-tauri/Cargo.lock",
        *gradle_lockfiles(repository),
    ]
    expected_locks = [
        {
            "path": safe_relative(path, repository),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in lock_paths
    ]
    if record.get("lockfiles") != expected_locks:
        raise EvidenceError("dependency policy lockfile evidence is stale")
    verification = repository / "apps/android/gradle/verification-metadata.xml"
    if record.get("integrity_files") != [
        {
            "path": safe_relative(verification, repository),
            "bytes": verification.stat().st_size,
            "sha256": sha256_file(verification),
        }
    ]:
        raise EvidenceError("dependency verification-metadata evidence is stale")

    licenses = bundle / "android-licenses.json"
    license_record = load_json(licenses)
    license_summary = (
        license_record.get("summary") if isinstance(license_record, dict) else None
    )
    if record.get("android_license_evidence") != {
        "path": "android-licenses.json",
        "bytes": licenses.stat().st_size,
        "sha256": sha256_file(licenses),
        "summary": license_summary,
    }:
        raise EvidenceError("dependency policy license evidence is stale")
    toolchain_path, toolchain = load_release_toolchain(repository)
    if record.get("release_toolchain") != {
        "path": safe_relative(toolchain_path, repository),
        "bytes": toolchain_path.stat().st_size,
        "sha256": sha256_file(toolchain_path),
        "policy": toolchain,
    }:
        raise EvidenceError("dependency policy toolchain evidence is stale")


def validate_sbom_record(
    record: Any,
    bundle: Path,
    repository: Path,
    revision: str,
    version: str,
) -> None:
    if (
        not isinstance(record, dict)
        or record.get("bomFormat") != "CycloneDX"
        or record.get("specVersion") != "1.5"
        or record.get("version") != 1
    ):
        raise EvidenceError("release SBOM has the wrong format")
    validate_public_record(record)
    metadata = record.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    properties = component.get("properties") if isinstance(component, dict) else None
    if (
        not isinstance(component, dict)
        or component.get("name") != "Komms"
        or component.get("version") != version
        or component.get("purl") != f"pkg:github/AndriGitDev/Komms@{revision}"
        or not isinstance(properties, list)
    ):
        raise EvidenceError("release SBOM root component is malformed")
    property_map: dict[str, str] = {}
    for row in properties:
        if (
            not isinstance(row, dict)
            or set(row) != {"name", "value"}
            or not isinstance(row.get("name"), str)
            or not isinstance(row.get("value"), str)
            or row["name"] in property_map
        ):
            raise EvidenceError("release SBOM has malformed root properties")
        property_map[row["name"]] = row["value"]
    expected_properties = {
        "komms:schema": SBOM_SCHEMA,
        "komms:revision": revision,
        "komms:android-verification-metadata-sha256": sha256_file(
            repository / "apps/android/gradle/verification-metadata.xml"
        ),
        "komms:android-license-evidence-sha256": sha256_file(
            bundle / "android-licenses.json"
        ),
        "komms:release-toolchain-sha256": sha256_file(
            repository / "release/toolchain-v1.json"
        ),
    }
    for lockfile in [
        repository / "Cargo.lock",
        repository / "apps/desktop/src-tauri/Cargo.lock",
        *gradle_lockfiles(repository),
    ]:
        relative = safe_relative(lockfile, repository)
        expected_properties[f"komms:lock-sha256:{relative}"] = sha256_file(lockfile)
    if property_map != expected_properties:
        raise EvidenceError("release SBOM build-input properties are stale")
    components = record.get("components")
    dependencies = record.get("dependencies")
    if (
        not isinstance(components, list)
        or not components
        or len(components) > 4096
        or not isinstance(dependencies, list)
        or not dependencies
        or len(dependencies) > 4097
    ):
        raise EvidenceError("release SBOM component graph is malformed")


def verify_bundle(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle_dir).resolve()
    if not bundle.is_dir() or bundle.is_symlink():
        raise EvidenceError("bundle must be a real directory")
    for path in sorted(bundle.iterdir()):
        if path.is_symlink():
            raise EvidenceError(f"{path}: top-level symlinks are forbidden")
        if path.is_dir():
            if path.name != "artifacts":
                raise EvidenceError(f"{path}: unexpected top-level directory")
        elif not path.is_file() or path.name not in (
            EVIDENCE_RECORD_NAMES | EVIDENCE_CONTROL_NAMES
        ):
            raise EvidenceError(f"{path}: unexpected top-level evidence record")
    manifest = load_json(bundle / "release-evidence.json")
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise EvidenceError(f"release evidence must use {SCHEMA}")
    revision = validate_revision(str(manifest.get("revision", "")))
    if args.expected_revision and revision != validate_revision(args.expected_revision):
        raise EvidenceError("release evidence revision does not match the expected revision")
    version = validate_version(str(manifest.get("version", "")))
    tag = validate_tag(str(manifest.get("tag", "")), version)
    validate_public_record(manifest)
    channel = manifest.get("channel")
    if channel not in {"validation", "alpha", "stable"}:
        raise EvidenceError("release evidence has an invalid channel")
    if channel in {"alpha", "stable"}:
        promotion = manifest.get("promotion")
        if (
            not isinstance(promotion, dict)
            or promotion.get("from") != "validation"
            or promotion.get("offline_manifest_signature_required") is not True
        ):
            raise EvidenceError("publishable evidence has no valid promotion record")
    elif "promotion" in manifest:
        raise EvidenceError("validation evidence must not claim promotion")
    expected_claims = {
        "production_signed": channel == "stable",
        "independently_reproduced": channel == "stable",
        "qualified_for_stable": channel == "stable",
    }
    if manifest.get("claims") != expected_claims:
        raise EvidenceError("release evidence channel claims are inconsistent")

    checksum_rows = parse_checksums(bundle / "SHA256SUMS")
    actual_paths: set[str] = set()
    for path in bundle.rglob("*"):
        if path.is_file():
            relative = safe_relative(path, bundle)
            if relative not in ("SHA256SUMS", "SHA256SUMS.sig"):
                actual_paths.add(relative)
    if set(checksum_rows) != actual_paths:
        raise EvidenceError("checksum inventory does not exactly match bundle files")
    for name, expected in checksum_rows.items():
        if sha256_file(bundle / name) != expected:
            raise EvidenceError(f"{name}: checksum mismatch")

    artifact_manifest = load_json(bundle / "artifacts.json")
    artifact_revision, rows = validated_artifact_rows(artifact_manifest, revision)
    if artifact_revision != revision:
        raise EvidenceError("artifact inventory revision mismatch")
    if len(rows) != manifest.get("artifact_count"):
        raise EvidenceError("artifact inventory count mismatch")
    if sum(row["bytes"] for row in rows.values()) != manifest.get("artifact_bytes"):
        raise EvidenceError("artifact inventory byte count mismatch")
    if manifest.get("artifacts") != list(rows.values()):
        raise EvidenceError("release evidence and artifact inventory disagree")
    expected_records = [
        {
            "path": path.name,
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(bundle.iterdir())
        if path.is_file() and path.name in EVIDENCE_RECORD_NAMES
    ]
    if manifest.get("records") != expected_records:
        raise EvidenceError("release evidence and top-level record inventory disagree")
    source_record = load_json(bundle / "source.json")
    builders_record = load_json(bundle / "builders.json")
    provenance_record = load_json(bundle / "provenance.json")
    if (
        not isinstance(source_record, dict)
        or source_record.get("schema") != "komms-release-source/v1"
        or source_record.get("repository") != "https://github.com/AndriGitDev/Komms"
        or source_record.get("revision") != revision
        or source_record.get("tag") != tag
        or source_record.get("version") != version
        or isinstance(source_record.get("source_date_epoch"), bool)
        or not isinstance(source_record.get("source_date_epoch"), int)
        or source_record["source_date_epoch"] <= 0
        or source_record.get("builder") != manifest.get("builder")
        or source_record.get("build_environments")
        != manifest.get("build_environments")
    ):
        raise EvidenceError("source record and release manifest disagree")
    build_environments = manifest.get("build_environments")
    if (
        not isinstance(builders_record, dict)
        or builders_record.get("schema") != "komms-release-builders/v1"
        or builders_record.get("revision") != revision
        or builders_record.get("builders") != build_environments
        or not isinstance(build_environments, list)
        or not build_environments
        or len(build_environments) > 32
    ):
        raise EvidenceError("builder records and release manifest disagree")
    collector = manifest.get("builder")
    for builder in [collector, *build_environments]:
        if (
            not isinstance(builder, dict)
            or builder.get("schema") != BUILDER_SCHEMA
            or builder.get("revision") != revision
            or not isinstance(builder.get("builder_id"), str)
            or not BUILDER_ID_RE.fullmatch(builder["builder_id"])
            or not isinstance(builder.get("os"), str)
            or not isinstance(builder.get("architecture"), str)
            or not isinstance(builder.get("environment"), str)
            or not isinstance(builder.get("runner_image"), str)
            or not isinstance(builder.get("isolated"), bool)
            or not isinstance(builder.get("tools"), list)
            or not builder["tools"]
        ):
            raise EvidenceError("release evidence has a malformed builder record")
        tool_names: set[str] = set()
        for tool in builder["tools"]:
            if (
                not isinstance(tool, dict)
                or not isinstance(tool.get("name"), str)
                or not TOOL_NAME_RE.fullmatch(tool["name"])
                or tool["name"] in tool_names
                or not isinstance(tool.get("version"), str)
                or not tool["version"]
            ):
                raise EvidenceError("release evidence has a malformed build tool record")
            tool_names.add(tool["name"])
    environment_ids = [builder["builder_id"] for builder in build_environments]
    if len(environment_ids) != len(set(environment_ids)):
        raise EvidenceError("release evidence has duplicate build-environment ids")
    if any(
        builder["builder_id"] == collector["builder_id"] and builder != collector
        for builder in build_environments
    ):
        raise EvidenceError("collector builder id has conflicting environment records")
    if (
        not isinstance(provenance_record, dict)
        or provenance_record.get("schema") != "komms-release-provenance/v1"
        or provenance_record.get("revision") != revision
        or provenance_record.get("tag") != tag
        or provenance_record.get("builder_id")
        != manifest["builder"]["builder_id"]
    ):
        raise EvidenceError("provenance record and release manifest disagree")
    repository = Path(args.repository).resolve()
    android_license_path = bundle / "android-licenses.json"
    dependency_policy_path = bundle / "dependency-policy.json"
    sbom_path = bundle / "komms.cdx.json"
    publishable = channel in {"alpha", "stable"}
    if android_license_path.is_file():
        validate_android_license_record(repository, revision, android_license_path)
    if dependency_policy_path.is_file():
        validate_dependency_policy_record(
            load_json(dependency_policy_path),
            bundle,
            repository,
            revision,
            publishable,
        )
    if sbom_path.is_file():
        validate_sbom_record(
            load_json(sbom_path),
            bundle,
            repository,
            revision,
            version,
        )
    if publishable and (
        not android_license_path.is_file()
        or not dependency_policy_path.is_file()
        or not sbom_path.is_file()
    ):
        raise EvidenceError("publishable evidence lacks dependency or SBOM records")
    artifact_manifest_digest = sha256_file(bundle / "artifacts.json")
    for record_name in ("qualification.json", "signing.json", "stable-beta.json"):
        record_path = bundle / record_name
        if not record_path.exists():
            continue
        record = load_json(record_path)
        binding = record.get("artifact_manifest") if isinstance(record, dict) else None
        if (
            not isinstance(binding, dict)
            or binding.get("path") != "artifacts.json"
            or binding.get("sha256") != artifact_manifest_digest
        ):
            raise EvidenceError(
                f"{record_name}: record is not bound to the bundled artifact manifest"
            )
    signing_path = bundle / "signing.json"
    qualification_path = bundle / "qualification.json"
    if channel in {"alpha", "stable"} and (
        not signing_path.is_file() or not qualification_path.is_file()
    ):
        raise EvidenceError("publishable evidence lacks signing or qualification records")
    if signing_path.is_file():
        run_evidence_check(
            [
                str(Path(__file__).with_name("release-signing.py")),
                "validate",
                "--policy",
                str(Path(args.policy)),
                "--record",
                str(signing_path),
                "--artifact-manifest",
                str(bundle / "artifacts.json"),
                "--expected-revision",
                revision,
                "--channel",
                channel,
            ]
        )
    if qualification_path.is_file():
        qualification_arguments = [
            str(Path(__file__).with_name("release-qualification.py")),
            "validate",
            "--matrix",
            str(Path(args.matrix)),
            "--record",
            str(qualification_path),
            "--artifact-manifest",
            str(bundle / "artifacts.json"),
            "--expected-revision",
            revision,
            "--expected-version",
            str(manifest["version"]),
        ]
        if channel == "stable":
            qualification_arguments.append("--require-complete")
        run_evidence_check(qualification_arguments)
    artifact_root = bundle / "artifacts"
    actual_artifacts = {
        f"artifacts/{safe_relative(path, artifact_root)}"
        for path in iter_artifact_files(artifact_root)
    }
    if actual_artifacts != set(rows):
        raise EvidenceError("artifact inventory does not exactly match bundled artifacts")
    for relative, row in rows.items():
        path = bundle / relative
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != row.get("bytes")
            or f"{stat.S_IMODE(path.stat().st_mode):04o}" != row.get("mode")
            or sha256_file(path) != row.get("sha256")
        ):
            raise EvidenceError(f"{relative}: artifact inventory mismatch")
    reproducibility_path = bundle / "reproducibility.json"
    residual_risks_path = bundle / "residual-risks.json"
    if channel == "stable" and (
        not reproducibility_path.is_file() or not residual_risks_path.is_file()
    ):
        raise EvidenceError("stable evidence lacks disposition records")
    if reproducibility_path.exists():
        validate_reproducibility_record(
            load_json(reproducibility_path),
            revision,
            rows,
            require_independent=channel == "stable",
        )
    if residual_risks_path.exists():
        validate_residual_risk_record(
            load_json(residual_risks_path),
            revision,
            require_authorized=channel == "stable",
        )
    stable_beta_path = bundle / "stable-beta.json"
    if stable_beta_path.exists():
        stable_beta_arguments = [
            str(Path(__file__).with_name("stable-beta-readiness.py")),
            "validate",
            "--record",
            str(stable_beta_path),
            "--artifact-manifest",
            str(bundle / "artifacts.json"),
            "--release-notes",
            str(bundle / "release-notes.md"),
            "--expected-revision",
            revision,
            "--expected-version",
            version,
        ]
        if channel == "stable":
            stable_beta_arguments.append("--require-ready")
        run_evidence_check(stable_beta_arguments)
    if channel == "stable":
        policy = load_json(Path(args.policy))
        required = (
            policy.get("stable_required_records")
            if isinstance(policy, dict)
            and policy.get("schema") == "komms-release-policy/v1"
            else None
        )
        if not isinstance(required, list) or not all(
            isinstance(name, str) for name in required
        ):
            raise EvidenceError("release policy has no stable required-record list")
        missing = [
            name
            for name in required
            if not (bundle / name).is_file() or (bundle / name).is_symlink()
        ]
        if missing:
            raise EvidenceError("stable evidence is missing: " + ", ".join(missing))
        claims = manifest.get("claims")
        if not isinstance(claims, dict) or not all(
            claims.get(name) is True
            for name in (
                "production_signed",
                "independently_reproduced",
                "qualified_for_stable",
            )
        ):
            raise EvidenceError("stable evidence claims are incomplete")
    print(f"verified {len(rows)} artifacts for {revision}")


def verify_published_artifacts(args: argparse.Namespace) -> None:
    artifact_root = Path(args.artifact_dir).resolve()
    manifest = load_json(Path(args.manifest))
    revision, rows = validated_artifact_rows(manifest, args.expected_revision)
    expected: dict[str, dict[str, Any]] = {}
    for relative, row in rows.items():
        pure = PurePosixPath(relative)
        if len(pure.parts) != 2:
            raise EvidenceError(
                f"{relative}: published release artifacts must have top-level names"
            )
        name = pure.name
        if not SAFE_RELEASE_ASSET_RE.fullmatch(name):
            raise EvidenceError(f"{relative}: unsafe published release artifact name")
        if name in expected:
            raise EvidenceError(f"{name}: duplicate published release artifact name")
        expected[name] = row

    if not artifact_root.is_dir() or artifact_root.is_symlink():
        raise EvidenceError("published artifact directory must be a real directory")
    actual: dict[str, Path] = {}
    total = 0
    for path in sorted(artifact_root.iterdir()):
        if path.is_symlink() or not path.is_file():
            raise EvidenceError(f"{path}: published release entries must be regular files")
        if not SAFE_RELEASE_ASSET_RE.fullmatch(path.name):
            raise EvidenceError(f"{path}: unsafe published release artifact name")
        actual[path.name] = path
        total += path.stat().st_size
        if len(actual) > MAX_ARTIFACT_FILES or total > MAX_ARTIFACT_BYTES:
            raise EvidenceError("published artifact set exceeds its resource bound")
    if set(actual) != set(expected):
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        raise EvidenceError(
            "published artifact set mismatch: "
            f"missing={missing or 'none'}, extra={extra or 'none'}"
        )
    for name, row in expected.items():
        path = actual[name]
        if path.stat().st_size != row["bytes"] or sha256_file(path) != row["sha256"]:
            raise EvidenceError(f"{name}: published artifact does not match signed evidence")
    print(f"verified {len(expected)} published artifacts for {revision}")


def preflight_release_assets(args: argparse.Namespace) -> None:
    metadata = load_json(Path(args.metadata))
    if not isinstance(metadata, dict) or metadata.get("isDraft") is not True:
        raise EvidenceError("publication target must be an existing draft release")
    version = validate_version(args.version)
    assets = metadata.get("assets")
    if not isinstance(assets, list):
        raise EvidenceError("release metadata has no asset list")
    if not 2 <= len(assets) <= MAX_RELEASE_ASSET_FILES:
        raise EvidenceError(
            f"draft must contain 2 to {MAX_RELEASE_ASSET_FILES} bounded assets"
        )
    expected_archive = f"Komms-{version}-release-evidence.tar.gz"
    names: set[str] = set()
    total = 0
    for asset in assets:
        if not isinstance(asset, dict):
            raise EvidenceError("release metadata contains a malformed asset")
        name = asset.get("name")
        size = asset.get("size")
        digest = asset.get("digest")
        if (
            not isinstance(name, str)
            or not SAFE_RELEASE_ASSET_RE.fullmatch(name)
            or name in names
        ):
            raise EvidenceError("release metadata contains an unsafe or duplicate asset name")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise EvidenceError(f"{name}: release asset has an invalid size")
        if (
            not isinstance(digest, str)
            or not digest.startswith("sha256:")
            or not DIGEST_RE.fullmatch(digest.removeprefix("sha256:"))
        ):
            raise EvidenceError(f"{name}: release asset has no valid SHA-256 digest")
        names.add(name)
        total += size
        if total > MAX_RELEASE_ASSET_BYTES:
            raise EvidenceError(
                f"release asset download exceeds {MAX_RELEASE_ASSET_BYTES} bytes"
            )
    evidence_archives = {
        name for name in names if name.endswith("-release-evidence.tar.gz")
    }
    if evidence_archives != {expected_archive}:
        raise EvidenceError(
            f"draft must contain exactly {expected_archive} as completed evidence"
        )
    print(f"draft preflight passed for {len(names)} assets ({total} bytes)")


def artifact_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("artifacts")
    if not isinstance(rows, list):
        raise EvidenceError("evidence has no artifact list")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise EvidenceError("malformed evidence artifact row")
        name = row["path"]
        if name in result:
            raise EvidenceError("duplicate evidence artifact path")
        result[name] = row
    return result


def compare_evidence(args: argparse.Namespace) -> None:
    first = load_json(Path(args.first))
    second = load_json(Path(args.second))
    if (
        not isinstance(first, dict)
        or not isinstance(second, dict)
        or first.get("schema") != SCHEMA
        or second.get("schema") != SCHEMA
    ):
        raise EvidenceError(f"both inputs must use {SCHEMA}")
    if first.get("revision") != second.get("revision"):
        raise EvidenceError("cannot compare evidence from different revisions")
    revision = validate_revision(str(first.get("revision", "")))
    validated_artifact_rows(
        {
            "schema": ARTIFACT_SCHEMA,
            "revision": revision,
            "artifacts": first.get("artifacts"),
        },
        revision,
    )
    validated_artifact_rows(
        {
            "schema": ARTIFACT_SCHEMA,
            "revision": revision,
            "artifacts": second.get("artifacts"),
        },
        revision,
    )
    left = artifact_map(first)
    right = artifact_map(second)
    names = sorted(set(left) | set(right))
    rows: list[dict[str, Any]] = []
    exact = 0
    normalized = 0
    for name in names:
        a = left.get(name)
        b = right.get(name)
        if a is None or b is None:
            present = a if a is not None else b
            rows.append(
                {
                    "path": name,
                    "status": "missing",
                    "first": a is not None,
                    "second": b is not None,
                    "present_file_sha256": present.get("sha256"),
                }
            )
            continue
        if a.get("sha256") == b.get("sha256"):
            exact += 1
            rows.append({"path": name, "status": "exact", "sha256": a.get("sha256")})
            continue
        a_normalized = a.get("normalized")
        b_normalized = b.get("normalized")
        common = None
        if isinstance(a_normalized, dict) and isinstance(b_normalized, dict):
            if a_normalized.get("scheme") == b_normalized.get("scheme"):
                for key in ("unsigned_payload_sha256", "sha256"):
                    if a_normalized.get(key) == b_normalized.get(key):
                        common = key
                        break
        if common is not None:
            normalized += 1
            rows.append(
                {
                    "path": name,
                    "status": "normalized",
                    "scheme": a_normalized.get("scheme"),
                    "field": common,
                    "sha256": a_normalized.get(common),
                    "first_file_sha256": a.get("sha256"),
                    "second_file_sha256": b.get("sha256"),
                }
            )
        else:
            rows.append(
                {
                    "path": name,
                    "status": "different",
                    "first_file_sha256": a.get("sha256"),
                    "second_file_sha256": b.get("sha256"),
                }
            )
    report = {
        "schema": COMPARISON_SCHEMA,
        "revision": first.get("revision"),
        "first_builder": first.get("builder"),
        "second_builder": second.get("builder"),
        "summary": {
            "compared": len(names),
            "exact": exact,
            "normalized": normalized,
            "explained": 0,
            "unexplained_or_missing": len(names) - exact - normalized,
        },
        "independently_verified": False,
        "artifacts": rows,
        "claim": "Measurement only; independence and platform-signing reproducibility require separate evidence.",
    }
    validate_public_record(report)
    write_json(Path(args.output), report)
    if args.require == "exact" and exact != len(names):
        raise EvidenceError("one or more artifacts were not byte-for-byte identical")
    if args.require == "normalized" and exact + normalized != len(names):
        raise EvidenceError("one or more artifacts differed after supported normalization")


def pack_bundle(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle_dir).resolve()
    output = Path(args.output).resolve()
    if bundle == output or bundle in output.parents:
        raise EvidenceError("evidence archive must be outside the source bundle")
    run_evidence_check(
        [
            "verify",
            "--bundle-dir",
            str(bundle),
            "--policy",
            str(Path(args.policy)),
            "--matrix",
            str(Path(args.matrix)),
            "--repository",
            str(Path(args.repository)),
        ]
    )
    manifest = load_json(bundle / "release-evidence.json")
    if (
        isinstance(manifest, dict)
        and manifest.get("channel") in {"alpha", "stable"}
        and (
            not (bundle / "SHA256SUMS.sig").is_file()
            or (bundle / "SHA256SUMS.sig").is_symlink()
        )
    ):
        raise EvidenceError(
            "publishable evidence must have a detached release-manifest signature"
        )
    source_record = load_json(bundle / "source.json")
    source_date_epoch = (
        source_record.get("source_date_epoch")
        if isinstance(source_record, dict)
        else None
    )
    if (
        isinstance(source_date_epoch, bool)
        or not isinstance(source_date_epoch, int)
        or source_date_epoch <= 0
    ):
        raise EvidenceError("source record has no positive source-date epoch")
    entries: list[tuple[str, Path]] = []
    total = 0
    for path in sorted(bundle.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise EvidenceError(f"{path}: bundle contains an unsupported entry")
        relative = safe_relative(path, bundle)
        entries.append((relative, path))
        if path.is_file():
            total += path.stat().st_size
            if total > MAX_ARTIFACT_BYTES:
                raise EvidenceError("bundle exceeds the archive byte bound")
    if len(entries) + 1 > MAX_ARCHIVE_MEMBERS:
        raise EvidenceError("bundle exceeds the archive member bound")
    if output.exists():
        raise EvidenceError("evidence archive output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise EvidenceError("evidence archive parent must be a real directory")
    temporary = output.with_name(f".{output.name}.tmp")
    try:
        with temporary.open("xb") as raw:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw,
                mtime=source_date_epoch,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as archive:
                    root_info = tarfile.TarInfo("release-evidence")
                    root_info.type = tarfile.DIRTYPE
                    root_info.mode = 0o755
                    root_info.mtime = source_date_epoch
                    root_info.uid = 0
                    root_info.gid = 0
                    archive.addfile(root_info)
                    for relative, path in entries:
                        info = tarfile.TarInfo(f"release-evidence/{relative}")
                        info.mtime = source_date_epoch
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        if path.is_dir():
                            info.type = tarfile.DIRTYPE
                            info.mode = 0o755
                            archive.addfile(info)
                            continue
                        info.size = path.stat().st_size
                        info.mode = stat.S_IMODE(path.stat().st_mode) & 0o777
                        with path.open("rb") as source:
                            archive.addfile(info, source)
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    print(f"packed deterministic evidence archive {output.name}: {sha256_file(output)}")


def unpack_bundle(args: argparse.Namespace) -> None:
    archive_path = Path(args.archive).resolve()
    output = Path(args.output_dir).resolve()
    if not archive_path.is_file() or archive_path.is_symlink():
        raise EvidenceError("archive must be a regular file")
    prepare_output(output)
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > MAX_ARCHIVE_MEMBERS:
                raise EvidenceError("archive has an invalid member count")
            total = 0
            destinations: set[Path] = set()
            for member in members:
                pure = PurePosixPath(member.name)
                if (
                    pure.is_absolute()
                    or not pure.parts
                    or any(part in ("", ".", "..") for part in pure.parts)
                ):
                    raise EvidenceError("archive contains an unsafe member path")
                if not (member.isdir() or member.isfile()):
                    raise EvidenceError("archive contains a non-regular member")
                total += member.size
                if total > MAX_ARTIFACT_BYTES:
                    raise EvidenceError("archive exceeds the extraction byte bound")
                destination = output.joinpath(*pure.parts)
                if destination in destinations:
                    raise EvidenceError("archive contains a duplicate member path")
                destinations.add(destination)
            for member in members:
                destination = output.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise EvidenceError("archive member could not be opened")
                temporary = destination.with_name(f".{destination.name}.tmp")
                with temporary.open("wb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                os.chmod(temporary, member.mode & 0o777)
                os.replace(temporary, destination)
    except tarfile.TarError as error:
        raise EvidenceError("malformed gzip tar evidence archive") from error


def run_evidence_check(arguments: list[str]) -> None:
    command = (
        [sys.executable, *arguments]
        if arguments and arguments[0].endswith(".py")
        else [sys.executable, str(Path(__file__).resolve()), *arguments]
    )
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=300,
    )
    if completed.returncode != 0:
        reason = completed.stderr.strip() or completed.stdout.strip() or "validation failed"
        raise EvidenceError(reason)


def promote_bundle(args: argparse.Namespace) -> None:
    source = Path(args.bundle_dir).resolve()
    output = Path(args.output_dir).resolve()
    if source == output or source in output.parents or output in source.parents:
        raise EvidenceError("source and promoted bundle must not contain one another")
    run_evidence_check(
        [
            "verify",
            "--bundle-dir",
            str(source),
            "--policy",
            str(Path(args.policy)),
            "--matrix",
            str(Path(args.matrix)),
            "--repository",
            str(Path(args.repository)),
        ]
    )
    manifest = load_json(source / "release-evidence.json")
    if not isinstance(manifest, dict):
        raise EvidenceError("source evidence manifest must be an object")
    if manifest.get("channel") != "validation":
        raise EvidenceError("only validation evidence may be promoted")
    revision = validate_revision(str(manifest.get("revision", "")))
    _, source_artifacts = validated_artifact_rows(
        load_json(source / "artifacts.json"), revision
    )

    policy = load_json(Path(args.policy))
    if not isinstance(policy, dict) or policy.get("schema") != "komms-release-policy/v1":
        raise EvidenceError("release policy has the wrong schema")
    replacement_paths = {
        "signing.json": Path(args.signing),
        "qualification.json": Path(args.qualification),
        "reproducibility.json": Path(args.reproducibility),
        "residual-risks.json": Path(args.residual_risks),
    }
    if args.stable_beta is not None:
        replacement_paths["stable-beta.json"] = Path(args.stable_beta)
    elif args.channel == "stable":
        raise EvidenceError("stable promotion requires a stable-beta readiness record")
    if args.release_notes is not None:
        replacement_paths["release-notes.md"] = Path(args.release_notes)
    for path in replacement_paths.values():
        if not path.is_file() or path.is_symlink():
            raise EvidenceError(f"{path}: promotion record must be a regular file")

    run_evidence_check(
        [
            str(Path(__file__).with_name("release-signing.py")),
            "validate",
            "--policy",
            str(Path(args.policy)),
            "--record",
            str(replacement_paths["signing.json"]),
            "--artifact-manifest",
            str(source / "artifacts.json"),
            "--expected-revision",
            revision,
            "--channel",
            args.channel,
        ]
    )
    qualification_arguments = [
        str(Path(__file__).with_name("release-qualification.py")),
        "validate",
        "--matrix",
        str(Path(args.matrix)),
        "--record",
        str(replacement_paths["qualification.json"]),
        "--artifact-manifest",
        str(source / "artifacts.json"),
        "--expected-revision",
        revision,
        "--expected-version",
        str(manifest["version"]),
    ]
    if args.channel == "stable":
        qualification_arguments.append("--require-complete")
    run_evidence_check(qualification_arguments)

    reproducibility = load_json(replacement_paths["reproducibility.json"])
    residual_risks = load_json(replacement_paths["residual-risks.json"])
    independent = validate_reproducibility_record(
        reproducibility,
        revision,
        source_artifacts,
        require_independent=args.channel == "stable",
    )
    validate_residual_risk_record(
        residual_risks,
        revision,
        require_authorized=args.channel == "stable",
    )
    if "stable-beta.json" in replacement_paths:
        stable_beta_arguments = [
            str(Path(__file__).with_name("stable-beta-readiness.py")),
            "validate",
            "--record",
            str(replacement_paths["stable-beta.json"]),
            "--artifact-manifest",
            str(source / "artifacts.json"),
            "--release-notes",
            str(replacement_paths["release-notes.md"]),
            "--expected-revision",
            revision,
            "--expected-version",
            str(manifest["version"]),
        ]
        if args.channel == "stable":
            stable_beta_arguments.append("--require-ready")
        run_evidence_check(stable_beta_arguments)

    prepare_output(output)
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise EvidenceError(f"{path}: symlinks are forbidden")
        if path.is_dir():
            continue
        relative = safe_relative(path, source)
        if relative in ("SHA256SUMS", "SHA256SUMS.sig"):
            continue
        if (
            relative == "stable-beta.json"
            and "stable-beta.json" not in replacement_paths
        ):
            continue
        copy_regular(path, output / relative)
    for name, path in replacement_paths.items():
        copy_regular(path, output / name)

    required = policy.get(
        "stable_required_records"
        if args.channel == "stable"
        else "publishable_required_records"
    )
    if not isinstance(required, list) or not all(
        isinstance(name, str) for name in required
    ):
        raise EvidenceError("publishable required-record policy is malformed")
    missing = [
        name
        for name in required
        if name != "SHA256SUMS" and not (output / name).is_file()
    ]
    if missing:
        raise EvidenceError(
            f"{args.channel} promotion is missing: " + ", ".join(missing)
        )
    records = []
    for path in sorted(output.iterdir()):
        if path.is_file() and path.name not in ("release-evidence.json", "SHA256SUMS"):
            records.append(
                {
                    "path": path.name,
                    "bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
            )
    manifest["channel"] = args.channel
    manifest["records"] = records
    manifest["claims"] = {
        "production_signed": args.channel == "stable",
        "independently_reproduced": args.channel == "stable" and independent,
        "qualified_for_stable": args.channel == "stable",
    }
    manifest["promotion"] = {
        "from": "validation",
        "offline_manifest_signature_required": True,
    }
    validate_public_record(manifest)
    write_json(output / "release-evidence.json", manifest)
    checksum_rows: list[tuple[str, str]] = []
    for path in sorted(output.rglob("*")):
        if path.is_file():
            relative = safe_relative(path, output)
            if relative not in ("SHA256SUMS", "SHA256SUMS.sig"):
                checksum_rows.append((sha256_file(path), relative))
    (output / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for digest, name in checksum_rows),
        encoding="utf-8",
    )
    run_evidence_check(
        [
            "verify",
            "--bundle-dir",
            str(output),
            "--expected-revision",
            revision,
            "--policy",
            str(Path(args.policy)),
            "--matrix",
            str(Path(args.matrix)),
            "--repository",
            str(Path(args.repository)),
        ]
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    sbom = commands.add_parser("sbom", help="create a deterministic aggregate CycloneDX SBOM")
    sbom.add_argument("--repository", default=".")
    sbom.add_argument("--revision", required=True)
    sbom.add_argument("--version", required=True)
    sbom.add_argument("--android-license-report", required=True)
    sbom.add_argument("--output", required=True)
    sbom.set_defaults(run=make_sbom)

    dependency = commands.add_parser("dependency-record", help="record lock and policy results")
    dependency.add_argument("--repository", default=".")
    dependency.add_argument("--revision", required=True)
    dependency.add_argument("--root-cargo-deny", choices=("passed", "failed", "not-run"), required=True)
    dependency.add_argument(
        "--desktop-cargo-deny", choices=("passed", "failed", "not-run"), required=True
    )
    dependency.add_argument("--android-license-report", required=True)
    dependency.add_argument(
        "--android-dependency-locking", choices=("passed", "failed", "not-run"), required=True
    )
    dependency.add_argument(
        "--android-dependency-verification",
        choices=("passed", "failed", "not-run"),
        required=True,
    )
    dependency.add_argument("--output", required=True)
    dependency.set_defaults(run=make_dependency_record)

    builder = commands.add_parser("builder-record", help="record a public build environment")
    builder.add_argument("--revision", required=True)
    builder.add_argument("--builder-id", required=True)
    builder.add_argument("--os", required=True)
    builder.add_argument("--architecture", required=True)
    builder.add_argument("--environment", required=True)
    builder.add_argument("--runner-image", required=True)
    builder.add_argument("--isolated", action=argparse.BooleanOptionalAction, default=False)
    builder.add_argument("--tool", action="append", default=[])
    builder.add_argument("--output", required=True)
    builder.set_defaults(run=make_builder_record)

    inventory = commands.add_parser("inventory", help="inventory a bounded artifact directory")
    inventory.add_argument("--artifact-dir", required=True)
    inventory.add_argument("--revision", required=True)
    inventory.add_argument("--output", required=True)
    inventory.set_defaults(run=make_inventory)

    bundle = commands.add_parser("bundle", help="copy artifacts into a bounded evidence bundle")
    bundle.add_argument("--artifact-dir", required=True)
    bundle.add_argument("--output-dir", required=True)
    bundle.add_argument("--revision", required=True)
    bundle.add_argument("--version", required=True)
    bundle.add_argument("--tag", required=True)
    bundle.add_argument("--source-date-epoch", required=True, type=int)
    bundle.add_argument("--builder", required=True)
    bundle.add_argument("--build-record-dir")
    bundle.add_argument("--channel", choices=("validation",), default="validation")
    bundle.add_argument("--sbom")
    bundle.add_argument("--android-licenses")
    bundle.add_argument("--dependency-policy")
    bundle.add_argument("--qualification")
    bundle.add_argument("--reproducibility")
    bundle.add_argument("--signing")
    bundle.add_argument("--residual-risks")
    bundle.add_argument("--stable-beta")
    bundle.add_argument("--release-notes")
    bundle.set_defaults(run=make_bundle)

    verify = commands.add_parser("verify", help="verify every bounded evidence record and artifact")
    verify.add_argument("--bundle-dir", required=True)
    verify.add_argument("--expected-revision")
    verify.add_argument("--repository", default=".")
    verify.add_argument("--policy", default="release/policy-v1.json")
    verify.add_argument("--matrix", default="release/qualification-matrix-v1.json")
    verify.set_defaults(run=verify_bundle)

    published = commands.add_parser(
        "verify-published-artifacts",
        help="require downloadable package bytes to match the signed artifact manifest",
    )
    published.add_argument("--artifact-dir", required=True)
    published.add_argument("--manifest", required=True)
    published.add_argument("--expected-revision")
    published.set_defaults(run=verify_published_artifacts)

    preflight = commands.add_parser(
        "preflight-release-assets",
        help="bound and validate draft-release asset metadata before download",
    )
    preflight.add_argument("--metadata", required=True)
    preflight.add_argument("--version", required=True)
    preflight.set_defaults(run=preflight_release_assets)

    reproduction = commands.add_parser(
        "validate-reproducibility",
        help="validate controlled or independently administered reproduction evidence",
    )
    reproduction.add_argument("--record", required=True)
    reproduction.add_argument("--artifact-manifest", required=True)
    reproduction.add_argument("--expected-revision", required=True)
    reproduction.add_argument("--require-independent", action="store_true")
    reproduction.set_defaults(run=validate_reproducibility_command)

    risks = commands.add_parser(
        "validate-residual-risks",
        help="validate open or revision-authorized residual-risk disposition",
    )
    risks.add_argument("--record", required=True)
    risks.add_argument("--expected-revision", required=True)
    risks.add_argument("--require-authorized", action="store_true")
    risks.set_defaults(run=validate_residual_risks_command)

    compare = commands.add_parser("compare", help="measure two clean-build evidence manifests")
    compare.add_argument("--first", required=True)
    compare.add_argument("--second", required=True)
    compare.add_argument("--output", required=True)
    compare.add_argument("--require", choices=("none", "exact", "normalized"), default="none")
    compare.set_defaults(run=compare_evidence)

    unpack = commands.add_parser("unpack", help="safely unpack a bounded evidence archive")
    unpack.add_argument("--archive", required=True)
    unpack.add_argument("--output-dir", required=True)
    unpack.set_defaults(run=unpack_bundle)

    pack = commands.add_parser(
        "pack", help="create a deterministic gzip tar archive from a verified bundle"
    )
    pack.add_argument("--bundle-dir", required=True)
    pack.add_argument("--output", required=True)
    pack.add_argument("--repository", default=".")
    pack.add_argument("--policy", default="release/policy-v1.json")
    pack.add_argument("--matrix", default="release/qualification-matrix-v1.json")
    pack.set_defaults(run=pack_bundle)

    promote = commands.add_parser(
        "promote", help="copy a validation bundle into a signable alpha or stable bundle"
    )
    promote.add_argument("--bundle-dir", required=True)
    promote.add_argument("--output-dir", required=True)
    promote.add_argument("--channel", choices=("alpha", "stable"), required=True)
    promote.add_argument("--repository", default=".")
    promote.add_argument("--policy", default="release/policy-v1.json")
    promote.add_argument("--matrix", default="release/qualification-matrix-v1.json")
    promote.add_argument("--signing", required=True)
    promote.add_argument("--qualification", required=True)
    promote.add_argument("--reproducibility", required=True)
    promote.add_argument("--residual-risks", required=True)
    promote.add_argument("--stable-beta")
    promote.add_argument("--release-notes", required=True)
    promote.set_defaults(run=promote_bundle)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        args.run(args)
        return 0
    except (EvidenceError, OSError, subprocess.SubprocessError) as error:
        print(f"release evidence error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
