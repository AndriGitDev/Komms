#!/usr/bin/env python3
"""Build and verify a bounded, deterministic security-review source archive."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "security-review/stable-v1/package.json"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TREE_RE = re.compile(r"^[0-9a-f]{40,64}$")
SAFE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


class PackageError(ValueError):
    """The requested review package violated its source or output contract."""


@dataclass(frozen=True)
class SourceEntry:
    mode: str
    object_id: str
    size: int
    path: str


@dataclass(frozen=True)
class BuiltPackage:
    archive_name: str
    archive_bytes: bytes
    report_name: str
    report_bytes: bytes
    report: dict[str, Any]


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_repo_path(value: str) -> str:
    if not value or "\\" in value or any(ord(character) < 0x20 for character in value):
        raise PackageError(f"unsafe repository path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or value.startswith("./") or any(part in {"", ".", ".."} for part in path.parts):
        raise PackageError(f"unsafe repository path: {value!r}")
    return path.as_posix()


def run_git(repo: Path, arguments: list[str], *, text: bool = False) -> bytes | str:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
        )
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() if isinstance(error.stderr, str) else error.stderr.decode("utf-8", "replace").strip()
        raise PackageError(f"git {' '.join(arguments)} failed: {detail}") from error
    return result.stdout


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PackageError(f"{path}: invalid package policy: {error}") from error
    if not isinstance(policy, dict) or policy.get("schema") != "komms-security-review-package/v1":
        raise PackageError("security-review package policy has the wrong schema")
    for key in (
        "max_source_files",
        "max_source_bytes",
        "max_tar_bytes",
        "max_archive_bytes",
    ):
        value = policy.get(key)
        if not isinstance(value, int) or value <= 0:
            raise PackageError(f"package policy {key} must be a positive integer")
    prefix = policy.get("archive_prefix")
    if not isinstance(prefix, str) or not SAFE_COMPONENT_RE.fullmatch(prefix):
        raise PackageError("package policy has an unsafe archive prefix")
    for key in ("required_paths", "required_prefixes"):
        values = policy.get(key)
        if not isinstance(values, list) or not values:
            raise PackageError(f"package policy {key} must be a non-empty list")
        normalized = [safe_repo_path(value) for value in values if isinstance(value, str)]
        if len(normalized) != len(values) or len(set(normalized)) != len(values):
            raise PackageError(f"package policy {key} is malformed or contains duplicates")
    return policy


def resolve_revision(repo: Path, revision: str) -> tuple[str, str, int]:
    if not revision or revision.startswith("-") or len(revision) > 128:
        raise PackageError("revision is missing or malformed")
    commit = str(run_git(repo, ["rev-parse", "--verify", f"{revision}^{{commit}}"], text=True)).strip()
    if not SHA_RE.fullmatch(commit):
        raise PackageError("git returned a malformed commit id")
    tree = str(run_git(repo, ["rev-parse", "--verify", f"{commit}^{{tree}}"], text=True)).strip()
    if not TREE_RE.fullmatch(tree):
        raise PackageError("git returned a malformed tree id")
    timestamp_text = str(run_git(repo, ["show", "-s", "--format=%ct", commit], text=True)).strip()
    try:
        timestamp = int(timestamp_text)
    except ValueError as error:
        raise PackageError("git returned a malformed commit timestamp") from error
    if timestamp < 0:
        raise PackageError("commit timestamp cannot be negative")
    return commit, tree, timestamp


def source_entries(repo: Path, commit: str, policy: dict[str, Any]) -> list[SourceEntry]:
    raw = bytes(run_git(repo, ["ls-tree", "-r", "-z", "--long", "--full-tree", commit]))
    entries: list[SourceEntry] = []
    seen: set[str] = set()
    total = 0
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, raw_object_id, raw_size = header.split()
            path = raw_path.decode("utf-8", "strict")
            object_id = raw_object_id.decode("ascii", "strict")
            size = int(raw_size)
        except (ValueError, UnicodeDecodeError) as error:
            raise PackageError("git tree contains a malformed entry") from error
        path = safe_repo_path(path)
        mode_text = mode.decode("ascii", "strict")
        if object_type != b"blob" or mode_text not in {"100644", "100755"}:
            raise PackageError(f"{path}: symlinks, submodules, and special entries are forbidden")
        if not TREE_RE.fullmatch(object_id) or size < 0:
            raise PackageError(f"{path}: malformed object metadata")
        if path in seen:
            raise PackageError(f"{path}: duplicate tree entry")
        seen.add(path)
        total += size
        entries.append(SourceEntry(mode_text, object_id, size, path))
        if len(entries) > policy["max_source_files"]:
            raise PackageError("source tree exceeds the file-count bound")
        if total > policy["max_source_bytes"]:
            raise PackageError("source tree exceeds the byte bound")
    if not entries:
        raise PackageError("source tree is empty")
    paths = {entry.path for entry in entries}
    missing = sorted(set(policy["required_paths"]) - paths)
    if missing:
        raise PackageError(f"source tree is missing required paths: {', '.join(missing)}")
    for prefix in policy["required_prefixes"]:
        if not any(path.startswith(prefix) for path in paths):
            raise PackageError(f"source tree is missing required prefix: {prefix}")
    return entries


def deterministic_gzip(data: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=output,
        mtime=0,
    ) as compressed:
        compressed.write(data)
    return output.getvalue()


def inspect_tar(data: bytes, archive_root: str, entries: list[SourceEntry]) -> None:
    expected = {f"{archive_root}/{entry.path}": entry.size for entry in entries}
    observed: dict[str, int] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                path = safe_repo_path(member.name.rstrip("/"))
                if not path.startswith(f"{archive_root}/") and path != archive_root:
                    raise PackageError(f"archive member escapes the package root: {path}")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise PackageError(f"archive contains a non-regular member: {path}")
                if path in observed:
                    raise PackageError(f"archive contains a duplicate member: {path}")
                observed[path] = member.size
    except (tarfile.TarError, OSError) as error:
        raise PackageError(f"generated tar is invalid: {error}") from error
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        extra = sorted(set(observed) - set(expected))
        wrong_size = sorted(
            path
            for path in set(expected) & set(observed)
            if expected[path] != observed[path]
        )
        raise PackageError(
            "generated tar does not match the source tree: "
            f"missing={missing[:4]} extra={extra[:4]} wrong_size={wrong_size[:4]}"
        )


def build_package(
    repo: Path,
    policy: dict[str, Any],
    revision: str,
) -> BuiltPackage:
    commit, tree, commit_timestamp = resolve_revision(repo, revision)
    entries = source_entries(repo, commit, policy)
    archive_root = f"{policy['archive_prefix']}-{commit[:12]}"
    tar_bytes = bytes(
        run_git(
            repo,
            [
                "archive",
                "--format=tar",
                f"--prefix={archive_root}/",
                commit,
            ],
        )
    )
    if len(tar_bytes) > policy["max_tar_bytes"]:
        raise PackageError("generated tar exceeds the byte bound")
    inspect_tar(tar_bytes, archive_root, entries)
    archive_bytes = deterministic_gzip(tar_bytes)
    if len(archive_bytes) > policy["max_archive_bytes"]:
        raise PackageError("compressed archive exceeds the byte bound")
    archive_name = f"{archive_root}.tar.gz"
    report_name = f"{archive_root}.json"
    report: dict[str, Any] = {
        "schema": "komms-security-review-package-report/v1",
        "package_version": policy["package_version"],
        "protocol_profile": policy["protocol_profile"],
        "source_revision": commit,
        "source_tree": tree,
        "source_commit_timestamp": commit_timestamp,
        "source_file_count": len(entries),
        "source_bytes": sum(entry.size for entry in entries),
        "archive_root": archive_root,
        "archive_name": archive_name,
        "archive_bytes": len(archive_bytes),
        "archive_sha256": sha256(archive_bytes),
        "archive_format": "git-archive-tar+gzip-mtime-zero",
        "required_paths": policy["required_paths"],
        "review_status": policy["review_status"],
        "reviewer": "unassigned",
        "findings_received": False,
        "independent_security_review_claimed": False,
        "rebuild_command": (
            "python3 scripts/security_review_package.py "
            f"--revision {commit} --output-dir security-review-artifacts"
        ),
    }
    return BuiltPackage(
        archive_name=archive_name,
        archive_bytes=archive_bytes,
        report_name=report_name,
        report_bytes=canonical_json(report),
        report=report,
    )


def write_exact(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise PackageError(f"{path.parent}: output directory must be a real directory")
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise PackageError(f"{path}: existing output is not a regular file")
        if path.read_bytes() == data:
            return
        raise PackageError(f"{path}: existing output differs; choose an empty directory")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def verify_report(report_path: Path, archive_path: Path) -> dict[str, Any]:
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        archive_bytes = archive_path.read_bytes()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PackageError(f"cannot read review package: {error}") from error
    if (
        not isinstance(report, dict)
        or report.get("schema") != "komms-security-review-package-report/v1"
    ):
        raise PackageError("review package report has the wrong schema")
    if archive_path.name != report.get("archive_name"):
        raise PackageError("archive filename does not match the report")
    if len(archive_bytes) != report.get("archive_bytes"):
        raise PackageError("archive size does not match the report")
    if sha256(archive_bytes) != report.get("archive_sha256"):
        raise PackageError("archive digest does not match the report")
    return report


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--revision", default="HEAD")
    root.add_argument("--output-dir")
    root.add_argument("--check", action="store_true")
    root.add_argument("--verify-report")
    root.add_argument("--archive")
    return root


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.verify_report or arguments.archive:
            if not arguments.verify_report or not arguments.archive:
                raise PackageError("--verify-report and --archive must be supplied together")
            report = verify_report(
                Path(arguments.verify_report).resolve(),
                Path(arguments.archive).resolve(),
            )
            print(
                "security-review archive verified: "
                f"{report['source_revision']} {report['archive_sha256']}"
            )
            return 0
        if arguments.check == bool(arguments.output_dir):
            raise PackageError("choose exactly one of --check or --output-dir")
        policy = load_policy()
        first = build_package(ROOT, policy, arguments.revision)
        if arguments.check:
            second = build_package(ROOT, policy, arguments.revision)
            if (
                first.archive_bytes != second.archive_bytes
                or first.report_bytes != second.report_bytes
            ):
                raise PackageError("two builds of the same revision were not identical")
            print(
                "security-review package is bounded and reproducible: "
                f"{first.report['source_revision']} "
                f"{first.report['archive_sha256']}"
            )
            return 0
        output_dir = Path(arguments.output_dir).resolve()
        write_exact(output_dir / first.archive_name, first.archive_bytes)
        write_exact(output_dir / first.report_name, first.report_bytes)
        print(output_dir / first.archive_name)
        print(output_dir / first.report_name)
        return 0
    except (OSError, PackageError) as error:
        print(f"security-review package error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
