#!/usr/bin/env python3
"""Inventory Android declared licenses from a revision-controlled policy."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


SCHEMA = "komms-android-license-evidence/v1"
POLICY_SCHEMA = "komms-android-license-policy/v1"
REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
LICENSE_RE = re.compile(r"^[A-Za-z0-9.+-]+(?: (?:AND|OR) [A-Za-z0-9.+-]+)*$")
GROUP_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
MAX_COMPONENTS = 1024
MAX_POM_BYTES = 4 * 1024 * 1024
MAX_POLICY_BYTES = 1024 * 1024
MAX_LOCKFILES = 16
MAX_LOCKFILE_BYTES = 16 * 1024 * 1024
MAX_VERIFICATION_BYTES = 32 * 1024 * 1024
MAX_POM_CANDIDATES = 64
MAX_LICENSE_DECLARATIONS = 64
MAX_LICENSE_TEXT_BYTES = 8192


class LicenseError(ValueError):
    """Android license evidence is incomplete or malformed."""


def canonical(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def locked_coordinates(repository: Path) -> tuple[set[tuple[str, str, str]], list[dict[str, Any]]]:
    coordinates: set[tuple[str, str, str]] = set()
    lock_rows: list[dict[str, Any]] = []
    paths = sorted((repository / "apps/android").glob("**/*gradle.lockfile"))
    if not paths or len(paths) > MAX_LOCKFILES:
        raise LicenseError("Android lockfile count is outside the bound")
    for path in paths:
        if (
            not path.is_file()
            or path.is_symlink()
            or path.stat().st_size > MAX_LOCKFILE_BYTES
        ):
            raise LicenseError(f"{path}: lockfile must be a bounded regular file")
        lock_rows.append(
            {
                "path": path.relative_to(repository).as_posix(),
                "sha256": digest(path),
            }
        )
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            parts = line.split("=", 1)[0].split(":")
            if len(parts) != 3 or not all(parts):
                raise LicenseError(f"{path}: malformed locked coordinate")
            coordinates.add((parts[0], parts[1], parts[2]))
    if not coordinates or len(coordinates) > MAX_COMPONENTS:
        raise LicenseError("locked Android component count is outside the bound")
    return coordinates, lock_rows


def verification_pom_hashes(repository: Path) -> dict[tuple[str, str, str], set[str]]:
    path = repository / "apps/android/gradle/verification-metadata.xml"
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size > MAX_VERIFICATION_BYTES
    ):
        raise LicenseError("Gradle verification metadata must be a bounded regular file")
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as error:
        raise LicenseError(f"invalid Gradle verification metadata: {error}") from error
    namespace = {"v": "https://schema.gradle.org/dependency-verification"}
    result: dict[tuple[str, str, str], set[str]] = {}
    for component in root.findall(".//v:component", namespace):
        coordinate = (
            component.attrib.get("group", ""),
            component.attrib.get("name", ""),
            component.attrib.get("version", ""),
        )
        if not all(coordinate):
            raise LicenseError("Gradle verification metadata has a malformed component")
        hashes = result.setdefault(coordinate, set())
        for artifact in component.findall("./v:artifact", namespace):
            if not artifact.attrib.get("name", "").endswith(".pom"):
                continue
            for checksum in artifact.findall("./v:sha256", namespace):
                value = checksum.attrib.get("value", "")
                if not DIGEST_RE.fullmatch(value):
                    raise LicenseError("Gradle verification metadata has a malformed SHA-256")
                hashes.add(value)
    return result


def read_json(path: Path, description: str, maximum: int) -> Any:
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size > maximum
    ):
        raise LicenseError(f"{description} must be a bounded regular file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LicenseError(f"invalid {description} JSON: {error}") from error


def license_expression(value: Any, description: str) -> str:
    if not isinstance(value, str) or not LICENSE_RE.fullmatch(value):
        raise LicenseError(f"{description} has an invalid license expression")
    return value


def load_policy(path: Path) -> tuple[dict[str, str], list[tuple[str, str]], dict[str, Any]]:
    policy = read_json(path, "Android license policy", MAX_POLICY_BYTES)
    if not isinstance(policy, dict) or policy.get("schema") != POLICY_SCHEMA:
        raise LicenseError(f"Android license policy must use {POLICY_SCHEMA}")
    if policy.get("review_status") != "declared-license-inventory-not-legal-opinion":
        raise LicenseError("Android license policy must state its review boundary")
    exact: dict[str, str] = {}
    for row in policy.get("exact_overrides", []):
        if not isinstance(row, dict):
            raise LicenseError("Android license policy has a malformed exact override")
        coordinate = row.get("coordinate")
        if (
            not isinstance(coordinate, str)
            or len(coordinate.split(":")) != 3
            or any(not part for part in coordinate.split(":"))
            or coordinate in exact
        ):
            raise LicenseError("Android license policy has an invalid exact coordinate")
        exact[coordinate] = license_expression(
            row.get("spdx"), f"{coordinate} policy override"
        )
    prefixes: list[tuple[str, str]] = []
    seen: set[str] = set()
    for row in policy.get("group_prefixes", []):
        if not isinstance(row, dict):
            raise LicenseError("Android license policy has a malformed group rule")
        prefix = row.get("group_prefix")
        if (
            not isinstance(prefix, str)
            or not GROUP_RE.fullmatch(prefix)
            or prefix in seen
        ):
            raise LicenseError("Android license policy has an invalid group prefix")
        seen.add(prefix)
        prefixes.append(
            (
                prefix,
                license_expression(row.get("spdx"), f"{prefix} policy rule"),
            )
        )
    if not prefixes:
        raise LicenseError("Android license policy has no group rules")
    custom_ids: set[str] = set()
    for row in policy.get("custom_licenses", []):
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("id"), str)
            or not row["id"].startswith("LicenseRef-")
            or not isinstance(row.get("description"), str)
            or not row["description"].strip()
            or row["id"] in custom_ids
        ):
            raise LicenseError("Android license policy has a malformed custom license")
        custom_ids.add(row["id"])
    expressions = [*exact.values(), *(expression for _, expression in prefixes)]
    referenced_custom = {
        token
        for expression in expressions
        for token in expression.split()
        if token.startswith("LicenseRef-")
    }
    if referenced_custom != custom_ids:
        raise LicenseError("Android license policy custom-license definitions are stale")
    return exact, sorted(prefixes, key=lambda row: (-len(row[0]), row[0])), policy


def policy_expression(
    coordinate: tuple[str, str, str],
    exact: dict[str, str],
    prefixes: list[tuple[str, str]],
) -> tuple[str | None, str | None]:
    joined = ":".join(coordinate)
    if joined in exact:
        return exact[joined], f"exact:{joined}"
    group = coordinate[0]
    for prefix, expression in prefixes:
        if group == prefix or group.startswith(prefix + "."):
            return expression, f"group-prefix:{prefix}"
    return None, None


def pom_path(
    cache: Path, coordinate: tuple[str, str, str]
) -> tuple[Path | None, str | None]:
    group, name, version = coordinate
    root = cache / group / name / version
    if not root.is_dir():
        return None, None
    candidates: list[Path] = []
    for path in root.glob("*/**/*.pom"):
        if path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size > MAX_POM_BYTES:
            raise LicenseError(f"{':'.join(coordinate)}: cached POM exceeds the byte bound")
        candidates.append(path)
        if len(candidates) > MAX_POM_CANDIDATES:
            raise LicenseError(f"{':'.join(coordinate)}: too many cached POM candidates")
    if not candidates:
        return None, None
    by_digest: dict[str, Path] = {}
    for path in candidates:
        by_digest.setdefault(digest(path), path)
    if len(by_digest) != 1:
        raise LicenseError(f"{':'.join(coordinate)}: conflicting cached POM files")
    pom_digest, path = next(iter(by_digest.items()))
    return path, pom_digest


def child_text(element: ET.Element, name: str) -> str | None:
    child = element.find(f"{{*}}{name}")
    if child is None or child.text is None:
        return None
    value = child.text.strip()
    if len(value.encode("utf-8")) > MAX_LICENSE_TEXT_BYTES:
        raise LicenseError("POM license text exceeds the byte bound")
    return value or None


def parse_pom(path: Path) -> tuple[list[dict[str, str]], tuple[str, str, str] | None]:
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as error:
        raise LicenseError(f"{path}: malformed POM XML") from error
    licenses: list[dict[str, str]] = []
    container = root.find("{*}licenses")
    if container is not None:
        for license_row in container.findall("{*}license"):
            name = child_text(license_row, "name") or ""
            url = child_text(license_row, "url") or ""
            if name or url:
                licenses.append({"name": name, "url": url})
                if len(licenses) > MAX_LICENSE_DECLARATIONS:
                    raise LicenseError(f"{path}: too many POM license declarations")
    parent = root.find("{*}parent")
    if parent is None:
        return licenses, None
    values = tuple(child_text(parent, name) or "" for name in ("groupId", "artifactId", "version"))
    if not all(values) or any("${" in value for value in values):
        return licenses, None
    return licenses, values  # type: ignore[return-value]


def normalize_license(name: str, url: str) -> str | None:
    value = f"{name} {url}".lower()
    rules = (
        ("apache", "2.0", "Apache-2.0"),
        ("eclipse public license", "2.0", "EPL-2.0"),
        ("eclipse public license", "1.0", "EPL-1.0"),
        ("mit", "", "MIT"),
        ("mozilla public license", "2.0", "MPL-2.0"),
        ("mozilla public license", "1.1", "MPL-1.1"),
        ("lesser general public license", "2.1", "LGPL-2.1-only"),
        ("lgpl-2.1-or-later", "", "LGPL-2.1-or-later"),
        ("cddl", "1.1", "CDDL-1.1"),
        ("cddl", "1.0", "CDDL-1.0"),
        ("common development and distribution license", "1.1", "CDDL-1.1"),
        ("common development and distribution license", "1.0", "CDDL-1.0"),
        ("bsd 3", "", "BSD-3-Clause"),
        ("new bsd", "", "BSD-3-Clause"),
        ("3-clause bsd", "", "BSD-3-Clause"),
        ("libyuv", "", "BSD-3-Clause"),
        ("android software development kit license", "", "LicenseRef-Android-SDK-Terms"),
        ("public domain", "", "LicenseRef-Public-Domain"),
        ("unicode license v3", "", "Unicode-3.0"),
    )
    for marker, version, expression in rules:
        if marker in value and (not version or version in value):
            return expression
    if "apache.org/licenses/license-2.0" in value:
        return "Apache-2.0"
    if "opensource.org/licenses/bsd-3-clause" in value:
        return "BSD-3-Clause"
    if "opensource.org/licenses/mit" in value:
        return "MIT"
    return None


def pom_evidence(
    coordinate: tuple[str, str, str],
    cache: Path,
    verified_hashes: dict[tuple[str, str, str], set[str]],
) -> dict[str, Any]:
    current = coordinate
    chain: list[dict[str, Any]] = []
    declared: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for _ in range(8):
        if current in seen:
            raise LicenseError(f"{':'.join(coordinate)}: POM parent cycle")
        seen.add(current)
        path, pom_digest = pom_path(cache, current)
        if path is None or pom_digest is None:
            break
        chain.append(
            {
                "coordinate": ":".join(current),
                "sha256": pom_digest,
                "gradle_verified": pom_digest in verified_hashes.get(current, set()),
            }
        )
        licenses, parent = parse_pom(path)
        if licenses:
            declared = licenses
            break
        if parent is None:
            break
        current = parent
    normalized = sorted(
        {
            expression
            for row in declared
            if (expression := normalize_license(row["name"], row["url"])) is not None
        }
    )
    unresolved = [
        row
        for row in declared
        if normalize_license(row["name"], row["url"]) is None
    ]
    return {
        "declared": declared,
        "pom_chain": chain,
        "pom_spdx": " OR ".join(normalized) if normalized and not unresolved else None,
        "pom_integrity": (
            "gradle-verified"
            if chain and all(row["gradle_verified"] for row in chain)
            else ("record-bound" if chain else "not-collected")
        ),
    }


def component_evidence(
    coordinate: tuple[str, str, str],
    exact: dict[str, str],
    prefixes: list[tuple[str, str]],
    cache: Path | None,
    verified_hashes: dict[tuple[str, str, str], set[str]],
) -> dict[str, Any]:
    expression, rule = policy_expression(coordinate, exact, prefixes)
    pom = (
        pom_evidence(coordinate, cache, verified_hashes)
        if cache is not None
        else {
            "declared": [],
            "pom_chain": [],
            "pom_spdx": None,
            "pom_integrity": "not-collected",
        }
    )
    pom_expression = pom["pom_spdx"]
    unresolved_declaration = bool(pom["declared"]) and pom_expression is None
    mismatch = (
        unresolved_declaration
        or (
            expression is not None
            and pom_expression is not None
            and set(expression.split(" OR ")) != set(pom_expression.split(" OR "))
        )
    )
    status = "declared" if expression is not None and not mismatch else "unknown"
    return {
        "coordinate": ":".join(coordinate),
        "status": status,
        "spdx": expression if status == "declared" else None,
        "policy_rule": rule,
        "policy_spdx": expression,
        "declared": pom["declared"],
        "pom_chain": pom["pom_chain"],
        "pom_spdx": pom_expression,
        "pom_integrity": pom["pom_integrity"],
        "pom_mismatch": mismatch,
    }


def create(args: argparse.Namespace) -> None:
    revision = args.revision.lower()
    if not REVISION_RE.fullmatch(revision):
        raise LicenseError("revision must be a full lowercase source digest")
    repository = Path(args.repository).resolve()
    policy_path = Path(args.policy).resolve()
    exact, prefixes, policy = load_policy(policy_path)
    cache = Path(args.gradle_cache).resolve() if args.gradle_cache else None
    if cache is not None and (not cache.is_dir() or cache.is_symlink()):
        raise LicenseError("Gradle module cache must be a real directory")
    coordinates, lockfiles = locked_coordinates(repository)
    hashes = verification_pom_hashes(repository)
    components = [
        component_evidence(coordinate, exact, prefixes, cache, hashes)
        for coordinate in sorted(coordinates)
    ]
    counts = {
        "declared": sum(row["status"] == "declared" for row in components),
        "unknown": sum(row["status"] == "unknown" for row in components),
        "policy_bound_without_pom": sum(
            row["status"] == "declared" and row["pom_integrity"] == "not-collected"
            for row in components
        ),
        "record_bound_pom_chains": sum(
            row["pom_integrity"] == "record-bound" for row in components
        ),
        "pom_mismatches": sum(row["pom_mismatch"] for row in components),
    }
    record = {
        "schema": SCHEMA,
        "revision": revision,
        "policy": {
            "path": policy_path.relative_to(repository).as_posix(),
            "sha256": digest(policy_path),
            "review_status": policy["review_status"],
        },
        "lockfiles": lockfiles,
        "verification_metadata": {
            "path": "apps/android/gradle/verification-metadata.xml",
            "sha256": digest(
                repository / "apps/android/gradle/verification-metadata.xml"
            ),
        },
        "components": components,
        "summary": counts,
        "claim": (
            "Declared license expressions are resolved from a revision-controlled "
            "policy for the exact lock graph. Optional POM declarations are "
            "cross-checked when collected. This is not a legal opinion; unknown "
            "or mismatched declarations remain release blockers."
        ),
    }
    Path(args.output).write_text(canonical(record), encoding="utf-8")


def validate(args: argparse.Namespace) -> None:
    repository = Path(args.repository).resolve()
    path = Path(args.record)
    record = read_json(path, "Android license record", 32 * 1024 * 1024)
    if not isinstance(record, dict) or record.get("schema") != SCHEMA:
        raise LicenseError(f"license record must use {SCHEMA}")
    revision = record.get("revision")
    if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
        raise LicenseError("license record has no full source revision")
    if args.expected_revision and revision != args.expected_revision.lower():
        raise LicenseError("license record revision mismatch")
    coordinates, lockfiles = locked_coordinates(repository)
    policy_path = Path(args.policy).resolve()
    exact, prefixes, policy = load_policy(policy_path)
    expected = {":".join(row) for row in coordinates}
    rows = record.get("components")
    if not isinstance(rows, list) or len(rows) > MAX_COMPONENTS:
        raise LicenseError("license record has an invalid component list")
    actual: set[str] = set()
    counts = {
        "declared": 0,
        "unknown": 0,
        "policy_bound_without_pom": 0,
        "record_bound_pom_chains": 0,
        "pom_mismatches": 0,
    }
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("coordinate"), str):
            raise LicenseError("license record has a malformed component")
        coordinate = row["coordinate"]
        if coordinate in actual:
            raise LicenseError(f"{coordinate}: duplicate license row")
        actual.add(coordinate)
        status = row.get("status")
        if status not in ("declared", "unknown"):
            raise LicenseError(f"{coordinate}: invalid license status")
        counts[status] += 1
        integrity = row.get("pom_integrity")
        if integrity not in ("gradle-verified", "record-bound", "not-collected"):
            raise LicenseError(f"{coordinate}: invalid POM integrity status")
        if integrity == "record-bound":
            counts["record_bound_pom_chains"] += 1
        if integrity == "not-collected" and status == "declared":
            counts["policy_bound_without_pom"] += 1
        mismatch = row.get("pom_mismatch")
        if not isinstance(mismatch, bool):
            raise LicenseError(f"{coordinate}: invalid POM mismatch status")
        if mismatch:
            counts["pom_mismatches"] += 1
        expression = row.get("spdx")
        if status == "declared" and (
            not isinstance(expression, str) or not LICENSE_RE.fullmatch(expression)
        ):
            raise LicenseError(f"{coordinate}: declared row has no SPDX expression")
        if status == "unknown" and expression is not None:
            raise LicenseError(f"{coordinate}: unknown row must not claim an SPDX expression")
        parts = tuple(coordinate.split(":"))
        if len(parts) != 3 or any(not part for part in parts):
            raise LicenseError(f"{coordinate}: malformed coordinate")
        expected_expression, expected_rule = policy_expression(
            parts, exact, prefixes  # type: ignore[arg-type]
        )
        declarations = row.get("declared")
        if (
            not isinstance(declarations, list)
            or len(declarations) > MAX_LICENSE_DECLARATIONS
            or not all(
                isinstance(declaration, dict)
                and set(declaration) == {"name", "url"}
                and isinstance(declaration["name"], str)
                and isinstance(declaration["url"], str)
                and len(declaration["name"].encode("utf-8"))
                <= MAX_LICENSE_TEXT_BYTES
                and len(declaration["url"].encode("utf-8"))
                <= MAX_LICENSE_TEXT_BYTES
                for declaration in declarations
            )
        ):
            raise LicenseError(f"{coordinate}: malformed POM declarations")
        expected_mismatch = bool(declarations) and row.get("pom_spdx") is None
        expected_mismatch = expected_mismatch or (
            expected_expression is not None
            and isinstance(row.get("pom_spdx"), str)
            and set(expected_expression.split(" OR "))
            != set(row["pom_spdx"].split(" OR "))
        )
        if (
            row.get("policy_spdx") != expected_expression
            or row.get("policy_rule") != expected_rule
            or (status == "declared" and expression != expected_expression)
            or mismatch != expected_mismatch
            or (expected_mismatch and status != "unknown")
        ):
            raise LicenseError(f"{coordinate}: license policy resolution mismatch")
        pom_expression = row.get("pom_spdx")
        if pom_expression is not None and (
            not isinstance(pom_expression, str)
            or not LICENSE_RE.fullmatch(pom_expression)
        ):
            raise LicenseError(f"{coordinate}: malformed POM license expression")
        pom_chain = row.get("pom_chain")
        if not isinstance(pom_chain, list) or len(pom_chain) > 8:
            raise LicenseError(f"{coordinate}: malformed POM chain")
        for pom in pom_chain:
            if (
                not isinstance(pom, dict)
                or not isinstance(pom.get("coordinate"), str)
                or not isinstance(pom.get("sha256"), str)
                or not DIGEST_RE.fullmatch(pom["sha256"])
                or not isinstance(pom.get("gradle_verified"), bool)
            ):
                raise LicenseError(f"{coordinate}: malformed POM evidence")
        expected_integrity = (
            "not-collected"
            if not pom_chain
            else (
                "gradle-verified"
                if all(pom["gradle_verified"] for pom in pom_chain)
                else "record-bound"
            )
        )
        if integrity != expected_integrity:
            raise LicenseError(f"{coordinate}: inconsistent POM integrity status")
    if actual != expected:
        raise LicenseError("license component inventory does not match lockfiles")
    if record.get("lockfiles") != lockfiles:
        raise LicenseError("license lockfile evidence is stale")
    metadata = repository / "apps/android/gradle/verification-metadata.xml"
    if record.get("verification_metadata") != {
        "path": "apps/android/gradle/verification-metadata.xml",
        "sha256": digest(metadata),
    }:
        raise LicenseError("license verification-metadata evidence is stale")
    if record.get("summary") != counts:
        raise LicenseError("license summary does not match component rows")
    expected_policy = {
        "path": policy_path.relative_to(repository).as_posix(),
        "sha256": digest(policy_path),
        "review_status": policy["review_status"],
    }
    if record.get("policy") != expected_policy:
        raise LicenseError("license policy evidence is stale")
    if args.require_complete and (counts["unknown"] or counts["pom_mismatches"]):
        raise LicenseError("Android license evidence has unresolved components")
    print(
        "Android license evidence valid: "
        + ", ".join(f"{name}={value}" for name, value in counts.items())
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--repository", default=".")
    inventory.add_argument(
        "--policy", default="release/android-license-policy-v1.json"
    )
    inventory.add_argument("--gradle-cache")
    inventory.add_argument("--revision", required=True)
    inventory.add_argument("--output", required=True)
    inventory.set_defaults(run=create)
    check = commands.add_parser("validate")
    check.add_argument("--repository", default=".")
    check.add_argument(
        "--policy", default="release/android-license-policy-v1.json"
    )
    check.add_argument("--record", required=True)
    check.add_argument("--expected-revision")
    check.add_argument("--require-complete", action="store_true")
    check.set_defaults(run=validate)
    return root


def main() -> int:
    try:
        arguments = parser().parse_args()
        arguments.run(arguments)
        return 0
    except (LicenseError, OSError) as error:
        print(f"Android license evidence error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
