#!/usr/bin/env python3
"""Validate source-controlled release policy, dependencies, and workflow controls."""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ACTION_REF_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*([^#\s]+)")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_CASES = {
    "clean-install",
    "authenticated-upgrade",
    "failed-upgrade-rollback",
    "old-version-compatibility",
    "signing-key-compromise-response",
}
PUBLISHABLE_RECORDS = {
    "source.json",
    "builders.json",
    "artifacts.json",
    "SHA256SUMS",
    "komms.cdx.json",
    "android-licenses.json",
    "dependency-policy.json",
    "provenance.json",
    "reproducibility.json",
    "qualification.json",
    "signing.json",
    "residual-risks.json",
    "release-notes.md",
}
STABLE_RECORDS = PUBLISHABLE_RECORDS | {"stable-beta.json"}
STABLE_BETA_MATRIX_IDS = [
    "clean-install",
    "distinct-nat",
    "optional-service-blackhole",
    "self-hosted-replacement",
    "mailbox-restart-overload",
    "backup-recovery",
    "signed-upgrade-rollback",
    "supported-device",
    "physical-radio",
    "accessibility",
    "conformance",
]
STABLE_BETA_METRIC_IDS = [
    "install-completion",
    "contact-establishment-success",
    "first-message-within-15-minutes",
    "offline-delivery-success",
    "fallback-success",
    "crash-or-recovery-success",
    "mode-comprehension",
    "expected-notification-behavior",
    "critical-accessibility-blockers",
    "privacy-boundary-incidents",
    "support-minutes",
]
RESIDUAL_RISK_IDS = {
    "consent-alpha-pilot",
    "distribution-credentials",
    "independent-conformance",
    "independent-reproduction",
    "independent-security-review",
    "install-upgrade-rollback",
    "legal-assets-and-continuity",
    "operator-qualification",
    "physical-field-qualification",
    "stable-beta-go-no-go",
}


def load_json(path: Path, errors: list[str]) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        errors.append(f"{path.relative_to(ROOT)}: invalid JSON: {error}")
        return None


def check_policy(errors: list[str]) -> tuple[set[str], set[str]]:
    policy = load_json(ROOT / "release/policy-v1.json", errors)
    if not isinstance(policy, dict) or policy.get("schema") != "komms-release-policy/v1":
        errors.append("release/policy-v1.json: wrong or missing policy schema")
        return set(), set()
    retention = policy.get("artifact_retention_days")
    if not isinstance(retention, int) or not 30 <= retention <= 400:
        errors.append("release policy retention must be between 30 and 400 days")
    channels = policy.get("channels")
    if not isinstance(channels, dict) or set(channels) != {"validation", "alpha", "stable"}:
        errors.append("release policy must define exactly validation, alpha, and stable")
        channels = {}
    roles = policy.get("signing_roles")
    role_ids = {
        row.get("id")
        for row in roles
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    } if isinstance(roles, list) else set()
    if not isinstance(roles, list) or len(role_ids) != len(roles):
        errors.append("release policy signing roles must be unique objects")
    for channel, configuration in channels.items():
        expected_publication = channel in {"alpha", "stable"}
        expected_stable_claim = channel == "stable"
        if (
            not isinstance(configuration, dict)
            or configuration.get("publication_allowed") is not expected_publication
            or configuration.get("stable_claim_allowed") is not expected_stable_claim
        ):
            errors.append(f"release policy channel {channel} has invalid claim authority")
        required = (
            configuration.get("required_signing_roles")
            if isinstance(configuration, dict)
            else None
        )
        if not isinstance(required, list) or not set(required).issubset(role_ids):
            errors.append(f"release policy channel {channel} has invalid signing roles")
        required_artifact_roles = (
            configuration.get("require_artifact_signing_roles")
            if isinstance(configuration, dict)
            else None
        )
        if (
            not isinstance(required_artifact_roles, bool)
            or required_artifact_roles != (channel in {"alpha", "stable"})
        ):
            errors.append(
                f"release policy channel {channel} has an invalid artifact-signing boundary"
            )
    artifacts = policy.get("artifact_classes")
    artifact_ids = {
        row.get("id")
        for row in artifacts
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    } if isinstance(artifacts, list) else set()
    if not isinstance(artifacts, list) or len(artifact_ids) != len(artifacts):
        errors.append("release policy artifact classes must be unique objects")
    for row in artifacts if isinstance(artifacts, list) else []:
        if row.get("signing_role") not in role_ids:
            errors.append(f"{row.get('id')}: artifact has no known signing role")
        if row.get("reproducibility") not in {
            "exact-or-explained",
            "measured-after-platform-signing",
        }:
            errors.append(f"{row.get('id')}: invalid reproducibility contract")
    if set(policy.get("publishable_required_records", [])) != PUBLISHABLE_RECORDS:
        errors.append("release policy publishable record inventory is incomplete or unexpected")
    if set(policy.get("stable_required_records", [])) != STABLE_RECORDS:
        errors.append("release policy stable record inventory is incomplete or unexpected")
    return role_ids, artifact_ids


def check_matrix(artifact_ids: set[str], errors: list[str]) -> None:
    matrix = load_json(ROOT / "release/qualification-matrix-v1.json", errors)
    if (
        not isinstance(matrix, dict)
        or matrix.get("schema") != "komms-release-qualification-matrix/v1"
    ):
        errors.append("release qualification matrix has the wrong schema")
        return
    rows = matrix.get("rows")
    if not isinstance(rows, list) or not rows:
        errors.append("release qualification matrix has no rows")
        return
    row_ids: set[str] = set()
    covered: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
            errors.append("release qualification matrix has a malformed row")
            continue
        row_id = row["id"]
        if row_id in row_ids:
            errors.append(f"{row_id}: duplicate qualification row")
        row_ids.add(row_id)
        artifact = row.get("artifact_class")
        if artifact not in artifact_ids:
            errors.append(f"{row_id}: unknown artifact class")
        else:
            covered.add(artifact)
        environment = row.get("environment")
        if not isinstance(environment, str) or len(environment) < 16:
            errors.append(f"{row_id}: environment contract is incomplete")
        cases = row.get("required_cases")
        if not isinstance(cases, list) or not REQUIRED_CASES.issubset(set(cases)):
            errors.append(f"{row_id}: required release-transition cases are incomplete")
        if not isinstance(cases, list) or not ({"manual-update", "store-update"} & set(cases)):
            errors.append(f"{row_id}: no bounded update path is qualified")
    if covered != artifact_ids:
        errors.append(
            "qualification matrix artifact coverage mismatch: "
            f"missing={sorted(artifact_ids - covered)}"
        )


def locked_coordinates(path: Path, errors: list[str]) -> set[tuple[str, str, str]]:
    coordinates: set[tuple[str, str, str]] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        errors.append(f"{path.relative_to(ROOT)}: unreadable: {error}")
        return coordinates
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        parts = line.split("=", 1)[0].split(":")
        if len(parts) != 3 or not all(parts):
            errors.append(f"{path.relative_to(ROOT)}: malformed locked coordinate")
            continue
        coordinates.add((parts[0], parts[1], parts[2]))
        if parts[0].startswith(("com.google.firebase", "com.google.android.gms")) and (
            "googleFree" in line
        ):
            errors.append(
                f"{path.relative_to(ROOT)}: Google dependency entered a Google-free graph"
            )
    return coordinates


def check_android_dependencies(errors: list[str]) -> None:
    build = (ROOT / "apps/android/app/build.gradle.kts").read_text(encoding="utf-8")
    if "dependencyLocking { lockAllConfigurations() }" not in build:
        errors.append("Android application does not lock every configuration")
    lockfiles = sorted((ROOT / "apps/android").glob("**/*gradle.lockfile"))
    required = {
        ROOT / "apps/android/app/gradle.lockfile",
        ROOT / "apps/android/core/gradle.lockfile",
        ROOT / "apps/android/settings-gradle.lockfile",
    }
    if not required.issubset(set(lockfiles)):
        errors.append("Android application, core, and settings lockfiles are required")
    locked: set[tuple[str, str, str]] = set()
    for path in lockfiles:
        locked.update(locked_coordinates(path, errors))
    if len(locked) < 100:
        errors.append("Android dependency lock inventory is unexpectedly small")

    verification_path = ROOT / "apps/android/gradle/verification-metadata.xml"
    try:
        root = ET.parse(verification_path).getroot()
    except (OSError, ET.ParseError) as error:
        errors.append(f"Android verification metadata is invalid: {error}")
        return
    namespace = {"v": "https://schema.gradle.org/dependency-verification"}
    verified: set[tuple[str, str, str]] = set()
    for component in root.findall(".//v:component", namespace):
        coordinate = (
            component.attrib.get("group", ""),
            component.attrib.get("name", ""),
            component.attrib.get("version", ""),
        )
        if not all(coordinate):
            errors.append("Android verification metadata has a malformed component")
            continue
        verified.add(coordinate)
        artifacts = component.findall("./v:artifact", namespace)
        if not artifacts:
            errors.append(f"{':'.join(coordinate)}: no verified artifact")
        for checksum in component.findall(".//v:sha256", namespace):
            if not DIGEST_RE.fullmatch(checksum.attrib.get("value", "")):
                errors.append(f"{':'.join(coordinate)}: malformed SHA-256")
    missing = locked - verified
    if missing:
        errors.append(
            "Android locked dependencies lack verification metadata: "
            + ", ".join(":".join(row) for row in sorted(missing)[:8])
        )

    policy = load_json(ROOT / "release/android-license-policy-v1.json", errors)
    if (
        not isinstance(policy, dict)
        or policy.get("schema") != "komms-android-license-policy/v1"
        or policy.get("review_status")
        != "declared-license-inventory-not-legal-opinion"
    ):
        errors.append("Android declared-license policy has the wrong schema or boundary")
        return
    exact = {
        row.get("coordinate"): row.get("spdx")
        for row in policy.get("exact_overrides", [])
        if isinstance(row, dict)
    }
    prefixes = [
        (row.get("group_prefix"), row.get("spdx"))
        for row in policy.get("group_prefixes", [])
        if isinstance(row, dict)
    ]
    unresolved: list[str] = []
    for coordinate in sorted(locked):
        joined = ":".join(coordinate)
        expression = exact.get(joined)
        if expression is None:
            matching = [
                (prefix, candidate)
                for prefix, candidate in prefixes
                if isinstance(prefix, str)
                and (
                    coordinate[0] == prefix
                    or coordinate[0].startswith(prefix + ".")
                )
            ]
            if matching:
                expression = max(matching, key=lambda row: len(row[0]))[1]
        if not isinstance(expression, str) or not expression:
            unresolved.append(joined)
    if unresolved:
        errors.append(
            "Android locked dependencies lack declared-license policy: "
            + ", ".join(unresolved[:8])
        )


def check_toolchain_policy(errors: list[str]) -> None:
    policy = load_json(ROOT / "release/toolchain-v1.json", errors)
    if (
        not isinstance(policy, dict)
        or policy.get("schema") != "komms-release-toolchain/v1"
    ):
        errors.append("release toolchain policy has the wrong schema")
        return
    expected = {
        ("rust", "release"): "1.88.0",
        ("rust", "msrv"): "1.88.0",
        ("android", "java"): "21",
        ("android", "gradle"): "8.14.3",
        ("android", "cargo_ndk"): "4.1.2",
        ("android", "compile_sdk"): 35,
        ("android", "build_tools"): "35.0.0",
        ("android", "ndk"): "27.2.12479018",
        ("apple", "xcode"): "16.4",
        ("apple", "xcode_build"): "16F6",
    }
    for path, value in expected.items():
        parent = policy.get(path[0])
        if not isinstance(parent, dict) or parent.get(path[1]) != value:
            errors.append(f"release toolchain policy has an unexpected {'.'.join(path)}")
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / ".github/workflows/ci.yml",
            ROOT / ".github/workflows/release.yml",
            ROOT / "apps/android/app/build.gradle.kts",
            ROOT / "scripts/install-xcodegen.sh",
            ROOT / "Dockerfile",
        )
    )
    required_literals = {
        "1.88.0",
        "8.14.3",
        "4.1.2",
        "35.0.0",
        "27.2.12479018",
        "Xcode 16.4",
        "Build version 16F6",
        "2.45.4",
        "090ec29491aad50aec10631bf6e62253fed733c50f3aab0f5ffc86bc170bdbef",
        "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
        "af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0",
        "7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818",
    }
    for literal in sorted(required_literals):
        if literal not in sources:
            errors.append(f"release toolchain pin is not enforced: {literal}")


def check_workflows(errors: list[str]) -> None:
    workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
    if not workflows:
        errors.append("no GitHub Actions workflows found")
        return
    combined_source = ""
    for workflow in workflows:
        source = workflow.read_text(encoding="utf-8")
        combined_source += source + "\n"
        if not re.search(r"(?m)^permissions:\n(?:  .+\n)*?  contents: read$", source):
            errors.append(f"{workflow.relative_to(ROOT)}: no top-level contents: read default")
        for number, line in enumerate(source.splitlines(), start=1):
            match = ACTION_REF_RE.match(line)
            if not match:
                continue
            action = match.group(1)
            if action.startswith("./"):
                continue
            if "@" not in action or not SHA_RE.fullmatch(action.rsplit("@", 1)[1]):
                errors.append(
                    f"{workflow.relative_to(ROOT)}:{number}: action is not pinned to a full SHA"
                )
    if "brew install xcodegen" in combined_source or "https://sh.rustup.rs" in combined_source:
        errors.append("workflow bootstrap tools must use checksum-pinned installers")
    for required_tool in (
        "cargo-fuzz --version 0.13.2",
        "cargo-ndk --version 4.1.2",
        "cargo-llvm-cov@0.8.7",
        "scripts/install-xcodegen.sh",
        "20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c",
        "swift:6.1-noble@sha256:e1cdaf7ddc9de37d8561da7a260535236694fca8c1b67d3129d47d8b180a9394",
    ):
        if required_tool not in combined_source:
            errors.append(f"workflow toolchain pin is missing: {required_tool}")

    release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    required_fragments = {
        "persist-credentials: false",
        "retention-days: 90",
        "artifact-metadata: write",
        "actions/attest@",
        "release-signing.py validate",
        "stable-beta-readiness.py validate",
        "--stable-beta target/stable-beta.json",
        "--require-complete",
        "environment: release-signing-enrollment",
        "environment: release-draft",
        "environment: release-publication",
        'DRAFT $RELEASE_TAG',
        'PUBLISH $RELEASE_TAG',
        "Release source must use an annotated tag.",
        "assets are never replaced",
        "preflight-release-assets",
        "verify-published-artifacts",
        "validation-evidence.tar.gz",
        "cmp -s draft-release.json current-release.json",
        "cmp -s visual-approval.json current-visual-approval.json",
        "release-visual-approval",
        "production_signed",
        "independently_reproduced",
        "qualified_for_stable",
    }
    for fragment in sorted(required_fragments):
        if fragment not in release:
            errors.append(f"release workflow is missing control: {fragment}")
    if "--clobber" in release:
        errors.append("release workflow must never replace a published or draft asset")
    if release.count("contents: write") != 2:
        errors.append("only draft creation and publication may request contents: write")
    create_position = release.find("  create-draft:")
    publish_position = release.find("  publish:")
    if 0 <= create_position < publish_position:
        create_block = release[create_position:publish_position]
        if "gh release upload" in create_block:
            errors.append("release draft creation must not attach validation artifacts")
    for position, name in ((create_position, "create-draft"), (publish_position, "publish")):
        if position < 0:
            errors.append(f"release workflow has no {name} job")
            continue
        block = release[position : position + 900]
        if "github.event_name == 'workflow_dispatch'" not in block:
            errors.append(f"release {name} job is not restricted to manual dispatch")

    dependabot = (ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
    if "package-ecosystem: github-actions" not in dependabot:
        errors.append("GitHub Action SHA updates are not configured")


def check_public_records(errors: list[str]) -> None:
    residual = load_json(ROOT / "release/residual-risks-v1.json", errors)
    if (
        not isinstance(residual, dict)
        or residual.get("schema") != "komms-release-residual-risks/v1"
        or residual.get("decision") != "not-authorized"
    ):
        errors.append("residual-risk template must visibly block stable authorization")
    else:
        risks = residual.get("risks")
        risk_keys = {
            "id",
            "status",
            "statement",
            "gate",
            "owner",
            "next_review",
            "required_action",
        }
        if (
            not isinstance(risks, list)
            or {row.get("id") for row in risks if isinstance(row, dict)}
            != RESIDUAL_RISK_IDS
            or len(risks) != len(RESIDUAL_RISK_IDS)
            or any(
                not isinstance(row, dict)
                or set(row) != risk_keys
                or row.get("status") != "open"
                or not all(
                    isinstance(row.get(field), str) and row[field].strip()
                    for field in (
                        "id",
                        "statement",
                        "gate",
                        "owner",
                        "next_review",
                        "required_action",
                    )
                )
                or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", row["next_review"])
                is None
                for row in risks
            )
        ):
            errors.append(
                "residual-risk template must retain every owner, date, gate, and action"
            )
    scripts = {
        "scripts/release-evidence.py",
        "scripts/android-license-evidence.py",
        "scripts/release-qualification.py",
        "scripts/release-signing.py",
        "scripts/stable-beta-readiness.py",
        "scripts/test-stable-beta-readiness.py",
        "scripts/stage-release-artifacts.py",
        "scripts/install-xcodegen.sh",
    }
    for relative in scripts:
        if not (ROOT / relative).is_file():
            errors.append(f"{relative}: required release control is missing")
    stable_beta = load_json(ROOT / "release/stable-beta-plan-v1.json", errors)
    stable_beta_gates = (
        stable_beta.get("gates", []) if isinstance(stable_beta, dict) else []
    )
    if not isinstance(stable_beta_gates, list):
        stable_beta_gates = []
    stable_beta_matrix = (
        stable_beta.get("candidate_matrix", [])
        if isinstance(stable_beta, dict)
        else []
    )
    if not isinstance(stable_beta_matrix, list):
        stable_beta_matrix = []
    stable_beta_pilot = (
        stable_beta.get("pilot", {}) if isinstance(stable_beta, dict) else {}
    )
    stable_beta_metrics = (
        stable_beta_pilot.get("metrics", [])
        if isinstance(stable_beta_pilot, dict)
        else []
    )
    if (
        not isinstance(stable_beta, dict)
        or stable_beta.get("schema") != "komms-stable-beta-plan/v1"
        or not all(isinstance(row, dict) for row in stable_beta_gates)
        or [row.get("id") for row in stable_beta_gates]
        != [f"P0-{number:02d}" for number in range(1, 11)]
        or not all(isinstance(row, dict) for row in stable_beta_matrix)
        or [row.get("id") for row in stable_beta_matrix]
        != STABLE_BETA_MATRIX_IDS
        or not isinstance(stable_beta_pilot, dict)
        or not isinstance(stable_beta_metrics, list)
        or not all(isinstance(row, dict) for row in stable_beta_metrics)
        or [row.get("id") for row in stable_beta_metrics]
        != STABLE_BETA_METRIC_IDS
    ):
        errors.append("stable-beta plan has incomplete pilot, matrix, or P0 coverage")
    for relative in (
        "Dockerfile",
        "deploy/reference-service/Dockerfile",
        "deploy/mailbox-service/Dockerfile",
        "deploy/wake-gateway/Dockerfile",
        "deploy/ohttp-relay/Dockerfile",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        if not source.startswith(
            "# syntax=docker/dockerfile:1.7@sha256:"
            "a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e\n"
        ):
            errors.append(f"{relative}: Dockerfile frontend must use the pinned digest")
        if source.count("@sha256:") < 3:
            errors.append(
                f"{relative}: frontend, builder, and runtime images must use immutable digests"
            )


def main() -> None:
    errors: list[str] = []
    _, artifact_ids = check_policy(errors)
    check_matrix(artifact_ids, errors)
    check_android_dependencies(errors)
    check_toolchain_policy(errors)
    check_workflows(errors)
    check_public_records(errors)
    if errors:
        for error in errors:
            print(f"release engineering check failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(
        "release policy, qualification coverage, dependency integrity, immutable "
        "workflow actions, and publication boundaries are valid"
    )


if __name__ == "__main__":
    main()
